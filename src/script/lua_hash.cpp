// hx.hash_algorithm: hash algorithms written in Lua (see the API comment in script_engine.h).
//   * registration + lookup in the shared state (hx.hash / doc:hash call them right there);
//   * LuaHasher: one run on a Lua stack, raising (shared state) or protected (a job's own state);
//   * custom_hashes(): factories for HashJob that rebuild an algorithm on the worker thread in a
//     fresh ScriptEngine which ran only the algorithm's script (like ParseJob does for parsers).
#include <atomic>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "script/lua_internal.h"

namespace hx {
namespace {

using Impl = ScriptEngine::Impl;

Impl& impl_here(lua_State* L) { return **static_cast<Impl**>(lua_getextraspace(L)); }

enum Step : int { kInit = 0, kUpdate = 1, kFinal = 2 };
const char* const kStepNames[] = {"init", "update", "final"};

// (spec, step, state, bytes?) -> the new state (init / update) or the normalized hex digest (final).
// Raw lookups: the spec's metatable (if any) is not involved.
int hash_step(lua_State* L) {
    const int which = int(lua_tointeger(L, 2));
    lua_pushstring(L, kStepNames[which]);
    if (lua_rawget(L, 1) != LUA_TFUNCTION) return luaL_error(L, "hash algorithm: '%s' is not a function", kStepNames[which]);
    int nargs = 0;
    if (which != kInit) {
        lua_pushvalue(L, 3);
        ++nargs;
    }
    if (which == kUpdate) {
        lua_pushvalue(L, 4);
        ++nargs;
    }
    lua_call(L, nargs, 1);
    if (which == kUpdate && lua_isnil(L, -1)) lua_pushvalue(L, 3);  // nil: the state was updated in place
    if (which == kFinal) {
        std::string hex;
        if (lua_type(L, -1) == LUA_TSTRING) hex = normalize_hex(lua_tostring(L, -1));
        if (hex.empty())
            return luaL_error(L, "hash algorithm: final() must return the digest as a hex string, got %s",
                              luaL_typename(L, -1));
        if (hex.size() % 2) hex.insert(hex.begin(), '0');
        lua_pushlstring(L, hex.data(), hex.size());
    }
    return 1;
}

int hex_digit(char c) { return c <= '9' ? c - '0' : c - 'a' + 10; }

}  // namespace

// ---- registration --------------------------------------------------------------------------------

int l_hash_algorithm(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    if (lua_getfield(L, 1, "name") != LUA_TSTRING) return luaL_error(L, "hx.hash_algorithm: 'name' (string) is required");
    for (const char* f : kStepNames)
        if (lua_getfield(L, 1, f) != LUA_TFUNCTION) return luaL_error(L, "hx.hash_algorithm: '%s' (function) is required", f);
    lua_settop(L, 1);
    Impl& im = impl_here(L);
    {
        ScriptHashInfo info;
        lua_getfield(L, 1, "name");
        info.name = lua_tostring(L, -1);
        lua_pop(L, 1);
        if (hash_name_key(info.name).empty())
            return luaL_error(L, "hx.hash_algorithm: the name needs letters or digits");
        if (info.name.find(',') != std::string::npos)
            return luaL_error(L, "hx.hash_algorithm: the name must not contain ','");
        if (find_hash_algorithm(info.name))
            return luaL_error(L, "hx.hash_algorithm: '%s' is a built-in algorithm (pick another name)", info.name.c_str());
        info.file = im.loading_file.empty() ? "<console>" : im.loading_file;
        // A copy of the spec without metatable: the steps below look its functions up raw.
        lua_createtable(L, 0, 4);
        lua_pushvalue(L, -2);
        lua_setfield(L, -2, "name");
        for (const char* f : kStepNames) {
            lua_getfield(L, 1, f);
            lua_setfield(L, -2, f);
        }
        im.register_hash(std::move(info), luaL_ref(L, LUA_REGISTRYINDEX));
    }
    return 0;
}

int find_lua_hash(const Impl& im, const std::string& name) {
    auto it = im.hash_refs.find(hash_name_key(name));
    return it == im.hash_refs.end() ? LUA_NOREF : it->second;
}

// ---- LuaHasher -----------------------------------------------------------------------------------

bool LuaHasher::step(int which, const uint8_t* data, size_t len) {
    lua_checkstack(L_, 6);
    lua_pushcfunction(L_, hash_step);
    lua_pushvalue(L_, base_);
    lua_pushinteger(L_, which);
    lua_pushvalue(L_, base_ + 1);
    int nargs = 3;
    if (which == kUpdate) {
        lua_pushlstring(L_, reinterpret_cast<const char*>(data), len);
        ++nargs;
    }
    if (!im_) {
        lua_call(L_, nargs, 1);
        return true;
    }
    std::string e;
    if (im_->pcall(nargs, 1, im_->script_limit_ms, &e)) return true;
    if (err_.empty()) err_ = e.empty() ? "error" : e;
    return false;
}

void LuaHasher::init() {
    if (base_) lua_settop(L_, base_ - 1);  // drop the previous run's spec + state
    lua_checkstack(L_, 4);
    base_ = lua_gettop(L_) + 1;
    lua_rawgeti(L_, LUA_REGISTRYINDEX, spec_ref_);
    lua_pushnil(L_);  // the state, set by the init step
    err_.clear();
    if (step(kInit, nullptr, 0)) lua_replace(L_, base_ + 1);
}

void LuaHasher::update(const uint8_t* data, size_t len) {
    if (!err_.empty() || !len) return;
    if (step(kUpdate, data, len)) lua_replace(L_, base_ + 1);
}

std::vector<uint8_t> LuaHasher::finish() {
    std::vector<uint8_t> out;
    if (!err_.empty() || !step(kFinal, nullptr, 0)) return out;
    size_t n = 0;
    const char* hex = lua_tolstring(L_, -1, &n);  // normalized by hash_step: lowercase, even length
    for (size_t i = 0; i + 1 < n; i += 2) out.push_back(uint8_t(hex_digit(hex[i]) * 16 + hex_digit(hex[i + 1])));
    lua_pop(L_, 1);
    return out;
}

// ---- background runs (HashJob) -------------------------------------------------------------------

namespace {

// A Lua algorithm in an engine of its own, made and used on the HashJob worker thread.
class JobHasher final : public Hasher {
public:
    std::unique_ptr<ScriptEngine> eng;  // before h: h's stack lives in eng
    std::unique_ptr<LuaHasher> h;
    std::string err;                    // could not be built

    void init() override {
        if (h) h->init();
    }
    void update(const uint8_t* data, size_t len) override {
        if (h) h->update(data, len);
    }
    std::vector<uint8_t> finish() override { return h ? h->finish() : std::vector<uint8_t>{}; }
    std::string error() const override { return h ? h->error() : err; }
};

}  // namespace

std::unique_ptr<Hasher> ScriptEngine::make_job_hasher(const std::vector<std::string>& dirs, const std::string& file,
                                                      const std::string& chunk, const std::string& text,
                                                      const std::string& name, const std::atomic<bool>* cancel) {
    auto out = std::make_unique<JobHasher>();
    if (text.empty() && chunk.empty()) {
        out->err = "defined in the console: only hx.hash / doc:hash can run it (define it in a script file)";
        return out;
    }
    out->eng = std::make_unique<ScriptEngine>(nullptr);
    ScriptEngine& e = *out->eng;
    if (!e.load_job_script(dirs, cancel, file, chunk, text)) {
        out->err = cancel && cancel->load() ? "cancelled"
                                            : "its script does not load on its own (does it use globals of another script?)";
        return out;
    }
    const int ref = find_lua_hash(*e.impl_, name);
    if (ref == LUA_NOREF) {
        out->err = "its script did not register it when loaded on its own";
        return out;
    }
    out->h = std::make_unique<LuaHasher>(e.impl_->L, e.impl_.get(), ref);
    return out;
}

std::vector<CustomHashAlgorithm> ScriptEngine::custom_hashes() const {
    struct Src {
        std::vector<std::string> dirs;
        std::string file, chunk, text, name;
    };
    std::vector<CustomHashAlgorithm> out;
    for (const ScriptHashInfo& h : hashes_) {
        auto src = std::make_shared<Src>();
        src->dirs = dirs_;
        src->file = h.file;
        src->name = h.name;
        if (auto it = impl_->sources.find(h.file); it != impl_->sources.end()) {
            src->chunk = it->second.chunk;
            src->text = it->second.text;
        }
        out.push_back({h.name, [src = std::shared_ptr<const Src>(std::move(src))](const std::atomic<bool>* cancel) {
                           return make_job_hasher(src->dirs, src->file, src->chunk, src->text, src->name, cancel);
                       }});
    }
    return out;
}

}  // namespace hx
