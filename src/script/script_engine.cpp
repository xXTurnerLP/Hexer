// ScriptEngine: Lua state lifetime, script loading + hot reload, console/REPL, parser/command
// dispatch, field editing. The Lua-facing API itself lives in lua_api.cpp.
#include "script/script_engine.h"

#include <algorithm>
#include <cctype>
#include <cfloat>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>

#include "core/os_file.h"
#include "script/lua_internal.h"

namespace hx {
namespace fs = std::filesystem;

namespace {

constexpr size_t kMaxConsoleLines = 5000;

fs::path to_path(const std::string& utf8) {
    return fs::path(std::u8string(utf8.begin(), utf8.end()));
}

std::string from_path(const fs::path& p) {
    std::u8string s = p.generic_u8string();
    return std::string(s.begin(), s.end());
}

struct ScriptFile {
    ScriptEngine::Impl::Watched w;
    std::string rel;  // path relative to its scripts dir ("examples/png.lua"), used as chunk name
    bool run = true;  // false for <dir>/lib/**: modules loaded with require(), watched but not run
};

// Every *.lua under each dir (recursive, hidden entries skipped), dirs in order, files sorted by
// relative path within a dir. Cheap: directory metadata only.
std::vector<ScriptFile> scan_scripts(const std::vector<std::string>& dirs) {
    std::vector<ScriptFile> all;
    for (const std::string& dir : dirs) {
        if (dir.empty()) continue;
        std::error_code ec;
        fs::path root = to_path(dir);
        if (!fs::is_directory(root, ec)) continue;
        std::vector<ScriptFile> here;
        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
        for (; !ec && it != end; it.increment(ec)) {
            const fs::directory_entry& e = *it;
            std::string name = from_path(e.path().filename());
            if (!name.empty() && name[0] == '.') {
                if (e.is_directory(ec)) it.disable_recursion_pending();
                continue;
            }
            if (e.is_directory(ec)) {
                if (it.depth() >= 4) it.disable_recursion_pending();
                continue;
            }
            if (!e.is_regular_file(ec)) continue;
            std::string ext = from_path(e.path().extension());
            for (char& c : ext) c = char(std::tolower((unsigned char)c));
            if (ext != ".lua") continue;
            ScriptFile f;
            f.w.path = from_path(e.path());
            f.rel = from_path(e.path().lexically_relative(root));
            f.w.size = e.file_size(ec);
            if (ec) f.w.size = 0;
            f.w.mtime = int64_t(e.last_write_time(ec).time_since_epoch().count());
            if (ec) f.w.mtime = 0;
            ec.clear();
            f.run = f.rel.compare(0, 4, "lib/") != 0;
            here.push_back(std::move(f));
        }
        std::sort(here.begin(), here.end(), [](const ScriptFile& a, const ScriptFile& b) { return a.rel < b.rel; });
        for (ScriptFile& f : here) all.push_back(std::move(f));
    }
    return all;
}

bool read_file(const std::string& path, std::string& out) {
    std::ifstream in(to_path(path), std::ios::binary);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    if (out.size() >= 3 && std::memcmp(out.data(), "\xEF\xBB\xBF", 3) == 0) out.erase(0, 3);  // UTF-8 BOM
    return true;
}

// Removes "[C]: in ?" noise lines from a REPL traceback.
std::string trim_traceback(const std::string& s) {
    std::string out;
    size_t pos = 0;
    while (pos <= s.size()) {
        size_t nl = s.find('\n', pos);
        std::string line = s.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        if (line != "\t[C]: in ?") {
            if (!out.empty()) out += '\n';
            out += line;
        }
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    if (out.size() >= 17 && out.compare(out.size() - 17, 17, "\nstack traceback:") == 0) out.resize(out.size() - 17);
    return out;
}

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace((unsigned char)s[b])) ++b;
    while (e > b && std::isspace((unsigned char)s[e - 1])) --e;
    return s.substr(b, e - b);
}

bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i])) return false;
    return true;
}

// "123", "-5", "0x1F", "0b101", "1_000" -> magnitude + sign (+ the base used). False on garbage /
// overflow.
bool parse_integer(const std::string& text, bool& negative, uint64_t& magnitude, int* base_out = nullptr) {
    std::string s;
    for (char c : text)
        if (c != '_' && c != '\'') s += c;
    size_t i = 0;
    negative = false;
    if (i < s.size() && (s[i] == '-' || s[i] == '+')) negative = s[i++] == '-';
    int base = 10;
    if (s.size() - i > 2 && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X')) base = 16, i += 2;
    else if (s.size() - i > 2 && s[i] == '0' && (s[i + 1] == 'b' || s[i + 1] == 'B')) base = 2, i += 2;
    else if (s.size() - i > 1 && (s.back() == 'h' || s.back() == 'H')) base = 16, s.pop_back();
    if (i >= s.size()) return false;
    if (base_out) *base_out = base;
    auto r = std::from_chars(s.data() + i, s.data() + s.size(), magnitude, base);
    return r.ec == std::errc() && r.ptr == s.data() + s.size();
}

// A quoted char literal as fmt="char" displays it: "'IHDR'" or "'IHDR' (1229472850)", with the
// escapes of the display (\n \r \t \0 \\ \" \xHH). False if `text` is not one.
bool parse_char_literal(const std::string& text, std::string& out) {
    if (text.size() < 2 || text[0] != '\'') return false;
    size_t end = text.back() == '\'' ? text.size() - 1 : text.rfind("' (");
    if (end == std::string::npos || end == 0 || (end != text.size() - 1 && text.back() != ')')) return false;
    out.clear();
    for (size_t i = 1; i < end; ++i) {
        char c = text[i];
        if (c != '\\') {
            out += c;
            continue;
        }
        if (++i >= end) return false;
        switch (text[i]) {
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case '0': out += '\0'; break;
        case '\\': case '"': case '\'': out += text[i]; break;
        case 'x': {
            unsigned v = 0;
            if (i + 2 >= end) return false;
            auto r = std::from_chars(text.data() + i + 1, text.data() + i + 3, v, 16);
            if (r.ec != std::errc() || r.ptr != text.data() + i + 3) return false;
            out += char(v);
            i += 2;
            break;
        }
        default: return false;
        }
    }
    return true;
}

}  // namespace

// ---- Impl ---------------------------------------------------------------------------------------

void ScriptEngine::Impl::drop_waiting() {
    if (L && waiting_ref != LUA_NOREF) luaL_unref(L, LUA_REGISTRYINDEX, waiting_ref);
    waiting = false;
    waiting_ref = LUA_NOREF;
    waiting_co = nullptr;
    waiting_doc = 0;
    prompt = {};
}

void ScriptEngine::Impl::close_state() {
    drop_waiting();
    if (L) lua_close(L);
    L = nullptr;
    cmd_thread = nullptr;
    inline_runs = 0;
    prompt_requested = false;
    parser_refs.clear();
    command_refs.clear();
    ref_pack = ref_unpack = ref_packsize = LUA_NOREF;
    deadline_on = false;
    timed_out = false;
    depth = 0;
    warn_buf.clear();
    logged_errors.clear();
}

void ScriptEngine::Impl::log_error_once(const std::string& text) {
    if (logged_errors.size() > 1000) logged_errors.clear();
    if (logged_errors.insert(text).second) eng.log(ConsoleLine::Error, text);
}

void ScriptEngine::Impl::new_state() {
    close_state();
    L = luaL_newstate();
    if (!L) {
        eng.log(ConsoleLine::Error, "Lua: could not create a state (out of memory)");
        return;
    }
    if (!install_api(*this)) eng.log(ConsoleLine::Error, "Lua: failed to initialise the hexer API");
}

bool ScriptEngine::Impl::pcall(int nargs, int nresults, int time_limit_ms, std::string* err) {
    int fn = lua_gettop(L) - nargs;
    lua_pushcfunction(L, lua_msg_handler);
    lua_insert(L, fn);

    // Nested calls (a host callback re-entering the engine) keep the earlier deadline.
    auto saved_deadline = deadline;
    bool saved_on = deadline_on;
    int saved_limit = limit_ms;
    auto mine = std::chrono::steady_clock::now() + std::chrono::milliseconds(time_limit_ms);
    if (!deadline_on || mine < deadline) {
        deadline = mine;
        limit_ms = time_limit_ms;
    }
    deadline_on = true;
    lua_sethook(L, lua_time_hook, LUA_MASKCOUNT, timed_out ? 1 : kHookCount);

    ++depth;
    int st = lua_pcall(L, nargs, nresults, fn);
    --depth;

    deadline = saved_deadline;
    deadline_on = saved_on;
    limit_ms = saved_limit;
    // The timeout stays sticky only while the (restored) outer deadline has passed too.
    if (timed_out && (!deadline_on || std::chrono::steady_clock::now() < deadline)) timed_out = false;
    if (!deadline_on) lua_sethook(L, nullptr, 0, 0);
    else if (!timed_out) lua_sethook(L, lua_time_hook, LUA_MASKCOUNT, kHookCount);

    bool ok = st == LUA_OK;
    if (!ok) {
        const char* msg = lua_tostring(L, -1);
        if (err) *err = msg ? msg : "(error)";
        lua_pop(L, 1);
    }
    lua_remove(L, fn);  // the handler (results, if any, sit above it)
    if (depth == 0) flush_highlights();
    return ok;
}

int ScriptEngine::Impl::resume(lua_State* co, int nargs, std::string* err) {
    // Same deadline bookkeeping as pcall: every resume is a fresh slice of script_limit_ms (the
    // time the user spends in a prompt does not count), nested ones keep an earlier deadline.
    auto saved_deadline = deadline;
    bool saved_on = deadline_on;
    int saved_limit = limit_ms;
    auto mine = std::chrono::steady_clock::now() + std::chrono::milliseconds(script_limit_ms);
    if (!deadline_on || mine < deadline) {
        deadline = mine;
        limit_ms = script_limit_ms;
    }
    deadline_on = true;
    lua_sethook(co, lua_time_hook, LUA_MASKCOUNT, timed_out ? 1 : kHookCount);
    lua_State* saved_thread = cmd_thread;
    cmd_thread = co;

    ++depth;
    int nres = 0;
    int st = lua_resume(co, L, nargs, &nres);
    --depth;

    cmd_thread = saved_thread;
    deadline = saved_deadline;
    deadline_on = saved_on;
    limit_ms = saved_limit;
    if (timed_out && (!deadline_on || std::chrono::steady_clock::now() < deadline)) timed_out = false;
    if (!deadline_on) lua_sethook(L, nullptr, 0, 0);
    else if (!timed_out) lua_sethook(L, lua_time_hook, LUA_MASKCOUNT, kHookCount);

    if (st == LUA_OK || st == LUA_YIELD) {
        lua_pop(co, nres);
    } else if (err) {
        // The dead coroutine keeps its stack, so the traceback can be taken after the fact.
        const char* msg = lua_tostring(co, -1);
        if (msg && std::strstr(msg, "\nstack traceback:")) {
            *err = msg;
        } else {
            if (!msg) msg = lua_pushfstring(L, "(error object is a %s value)", luaL_typename(co, -1));
            else lua_pushnil(L);  // keeps the pops below symmetric
            luaL_traceback(L, co, msg, 0);
            *err = lua_tostring(L, -1);
            lua_pop(L, 2);
        }
    }
    if (depth == 0) flush_highlights();
    return st;
}

void ScriptEngine::Impl::step_command(lua_State* co, int ref, const std::string& name, uint64_t doc_id, int nargs) {
    ScriptHost* host = eng.host_;
    Document* d = doc_id && host ? host->find_document(doc_id) : nullptr;
    if (d) d->begin_group("Script: " + name);  // the command (up to a prompt) is one undo step
    prompt_requested = false;
    std::string err;
    int st = resume(co, nargs, &err);
    if (d)
        if (Document* again = host->find_document(doc_id)) again->end_group();
    if (st == LUA_YIELD && prompt_requested && !waiting && L) {
        prompt_requested = false;
        prompt.command = name;
        waiting = true;
        waiting_ref = ref;
        waiting_co = co;
        waiting_doc = doc_id;
        return;
    }
    prompt_requested = false;
    if (st == LUA_YIELD) eng.log(ConsoleLine::Error, "Command '" + name + "': coroutine.yield() outside a coroutine");
    else if (st != LUA_OK) eng.log(ConsoleLine::Error, "Command '" + name + "': " + err);
    if (L) luaL_unref(L, LUA_REGISTRYINDEX, ref);
}

void ScriptEngine::Impl::register_parser(ParserInfo info, int ref) {
    auto it = parser_refs.find(info.name);
    if (it == parser_refs.end()) {
        parser_refs.emplace(info.name, ref);
        eng.parsers_.push_back(std::move(info));
        return;
    }
    luaL_unref(L, LUA_REGISTRYINDEX, it->second);
    it->second = ref;
    for (ParserInfo& p : eng.parsers_)
        if (p.name == info.name) {
            p = std::move(info);
            break;
        }
}

void ScriptEngine::Impl::register_command(ScriptCommand cmd, int ref) {
    auto it = command_refs.find(cmd.name);
    if (it == command_refs.end()) {
        command_refs.emplace(cmd.name, ref);
        eng.commands_.push_back(std::move(cmd));
        return;
    }
    luaL_unref(L, LUA_REGISTRYINDEX, it->second);
    it->second = ref;
    for (ScriptCommand& c : eng.commands_)
        if (c.name == cmd.name) {
            c = std::move(cmd);
            break;
        }
}

HighlightSet& ScriptEngine::Impl::script_hl(uint64_t doc_id) {
    hl_dirty.insert(doc_id);
    return eng.highlights_[doc_id];
}

void ScriptEngine::Impl::clear_script_hl(uint64_t doc_id) {
    eng.highlights_.erase(doc_id);
    hl_dirty.erase(doc_id);
}

void ScriptEngine::Impl::flush_highlights() {
    for (uint64_t id : hl_dirty) {
        auto it = eng.highlights_.find(id);
        if (it != eng.highlights_.end()) it->second.finalize();
    }
    hl_dirty.clear();
}

// ---- ScriptEngine ---------------------------------------------------------------------------------

ScriptEngine::ScriptEngine(ScriptHost* host) : host_(host), impl_(std::make_unique<Impl>(*this)) {
    impl_->new_state();  // usable (console, edit_field) even before the first reload()
}

ScriptEngine::~ScriptEngine() {
    impl_->close_state();  // finalizers may still log, so close while the console exists
}

void ScriptEngine::set_script_dirs(std::vector<std::string> dirs) { dirs_ = std::move(dirs); }

// require() looks in <dir>/lib of every scripts dir, later (user) dirs first.
void ScriptEngine::add_lib_paths() {
    lua_State* L = impl_->L;
    if (!L) return;
    std::string prefix;
    for (auto it = dirs_.rbegin(); it != dirs_.rend(); ++it) {
        if (it->empty()) continue;
        std::string d = from_path(to_path(*it));
        prefix += d + "/lib/?.lua;" + d + "/lib/?/init.lua;";
    }
    static const char* kCode = "package.path = ... .. package.path";
    if (luaL_loadbufferx(L, kCode, std::strlen(kCode), "=init", "t") != LUA_OK) {
        lua_pop(L, 1);
        return;
    }
    lua_pushlstring(L, prefix.data(), prefix.size());
    std::string err;
    if (!impl_->pcall(1, 0, impl_->script_limit_ms, &err)) log(ConsoleLine::Error, err);
}

void ScriptEngine::reload() {
    if (impl_->depth > 0) {
        log(ConsoleLine::Warn, "Script reload skipped: a script is running");
        return;
    }
    bool first = reload_count_ == 0;
    if (impl_->waiting)
        log(ConsoleLine::Warn, "Command '" + impl_->prompt.command + "' cancelled: scripts reloaded");
    parsers_.clear();
    commands_.clear();
    impl_->new_state();
    add_lib_paths();
    std::vector<ScriptFile> files = scan_scripts(dirs_);
    impl_->watched.clear();
    int failed = 0, ran = 0;
    for (const ScriptFile& f : files) {
        impl_->watched.push_back(f.w);
        if (!impl_->L) break;
        if (!f.run) continue;
        ++ran;
        std::string src;
        if (!read_file(f.w.path, src)) {
            log(ConsoleLine::Error, "Cannot read script " + f.w.path);
            ++failed;
            continue;
        }
        std::string chunk = "@" + f.rel;
        lua_State* L = impl_->L;
        if (luaL_loadbufferx(L, src.data(), src.size(), chunk.c_str(), "t") != LUA_OK) {
            log(ConsoleLine::Error, lua_tostring(L, -1) ? lua_tostring(L, -1) : "syntax error");
            lua_pop(L, 1);
            ++failed;
            continue;
        }
        impl_->loading_file = f.w.path;
        std::string err;
        if (!impl_->pcall(0, 0, impl_->script_limit_ms, &err)) {
            log(ConsoleLine::Error, err);
            ++failed;
        }
        impl_->loading_file.clear();
    }
    ++reload_count_;
    char buf[200];
    std::snprintf(buf, sizeof buf, "%s %d script%s (%d parser%s, %d command%s)%s%s",
                  first ? "Loaded" : "Reloaded", ran, ran == 1 ? "" : "s",
                  int(parsers_.size()), parsers_.size() == 1 ? "" : "s", int(commands_.size()),
                  commands_.size() == 1 ? "" : "s", failed ? " - errors in " : "",
                  failed ? (std::to_string(failed) + " file(s), see above").c_str() : "");
    log(failed ? ConsoleLine::Warn : ConsoleLine::Info, buf);
}

bool ScriptEngine::poll_hot_reload() {
    // Forget highlights of closed documents (cheap, piggybacks on the periodic poll).
    if (host_) {
        for (auto it = highlights_.begin(); it != highlights_.end();) {
            if (!host_->find_document(it->first)) it = highlights_.erase(it);
            else ++it;
        }
    }
    if (impl_->depth > 0) return false;
    std::vector<ScriptFile> files = scan_scripts(dirs_);
    bool same = files.size() == impl_->watched.size();
    for (size_t i = 0; same && i < files.size(); ++i) same = files[i].w == impl_->watched[i];
    if (same) return false;
    reload();
    return true;
}

// ---- console ------------------------------------------------------------------------------------

void ScriptEngine::log(ConsoleLine::Kind kind, const std::string& text) {
    size_t pos = 0;
    for (;;) {
        size_t nl = text.find('\n', pos);
        std::string line = text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        console_.push_back({kind, std::move(line)});
        ++console_gen_;
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    while (console_.size() > kMaxConsoleLines) console_.pop_front();
}

void ScriptEngine::clear_console() {
    console_.clear();
    ++console_gen_;
}

void ScriptEngine::exec(const std::string& code_in) {
    std::string code = trim(code_in);
    if (code.empty()) return;
    log(ConsoleLine::Input, code);
    lua_State* L = impl_->L;
    if (!L) return;

    // Predefined globals: doc, cur, sel (raw sets: no metamethods, cannot raise outside a pcall).
    Document* d = host_ ? host_->active_document() : nullptr;
    lua_pushglobaltable(L);
    lua_pushliteral(L, "doc");
    if (d) push_doc(L, d->id());
    else lua_pushnil(L);
    lua_rawset(L, -3);
    lua_pushliteral(L, "cur");
    if (d) lua_pushinteger(L, lua_Integer(d->view().cursor));
    else lua_pushnil(L);
    lua_rawset(L, -3);
    lua_pushliteral(L, "sel");
    if (d) {
        lua_createtable(L, 0, 2);
        lua_pushinteger(L, lua_Integer(d->view().sel_begin()));
        lua_setfield(L, -2, "start");
        lua_pushinteger(L, lua_Integer(d->view().sel_len()));
        lua_setfield(L, -2, "len");
    } else {
        lua_pushnil(L);
    }
    lua_rawset(L, -3);
    lua_pop(L, 1);

    int base = lua_gettop(L);
    std::string expr = "return " + code;
    if (luaL_loadbufferx(L, expr.data(), expr.size(), "=console", "t") != LUA_OK) {
        lua_pop(L, 1);
        if (luaL_loadbufferx(L, code.data(), code.size(), "=console", "t") != LUA_OK) {
            log(ConsoleLine::Error, lua_tostring(L, -1) ? lua_tostring(L, -1) : "syntax error");
            lua_settop(L, base);
            return;
        }
    }
    std::string err;
    if (!impl_->pcall(0, LUA_MULTRET, impl_->script_limit_ms, &err)) {
        log(ConsoleLine::Error, trim_traceback(err));
        lua_settop(L, base);
        return;
    }
    int n = lua_gettop(L) - base;
    for (int i = 1; i <= n; ++i) {
        int idx = base + i;
        if (lua_type(L, idx) == LUA_TNUMBER && lua_isinteger(L, idx) && lua_tointeger(L, idx) >= 10) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "%lld (0x%llX)", (long long)lua_tointeger(L, idx),
                          (unsigned long long)lua_tointeger(L, idx));
            log(ConsoleLine::Result, buf);
        } else {
            log(ConsoleLine::Result, lua_inspect(L, idx));
        }
    }
    lua_settop(L, base);
}

// ---- parsers ----------------------------------------------------------------------------------------

std::string ScriptEngine::detect_parser(Document& doc) {
    lua_State* L = impl_->L;
    if (!L) return {};
    std::vector<ParserInfo> list = parsers_;  // detect() may register parsers
    for (const ParserInfo& p : list) {
        auto it = impl_->parser_refs.find(p.name);
        if (it == impl_->parser_refs.end()) continue;
        int top = lua_gettop(L);
        lua_rawgeti(L, LUA_REGISTRYINDEX, it->second);
        lua_pushliteral(L, "detect");
        lua_rawget(L, -2);
        if (!lua_isfunction(L, -1)) {
            lua_settop(L, top);
            continue;
        }
        push_doc(L, doc.id());
        std::string err;
        bool hit = false;
        if (impl_->pcall(1, 1, kDetectTimeLimitMs, &err)) hit = lua_toboolean(L, -1);
        else impl_->log_error_once("Parser '" + p.name + "' detect: " + err);
        lua_settop(L, top);
        if (hit) return p.name;
    }
    std::string ext = path_extension(doc.has_path() ? doc.path() : doc.display_name());
    if (!ext.empty())
        for (const ParserInfo& p : list)
            for (const std::string& e : p.extensions)
                if (iequals(e, ext)) return p.name;
    return {};
}

ParseResult ScriptEngine::parse(Document& doc, const std::string& parser_name) {
    ParseResult r;
    r.parser = parser_name;
    r.doc_generation = doc.generation();
    auto t0 = std::chrono::steady_clock::now();
    auto it = impl_->parser_refs.find(parser_name);
    if (!impl_->L || it == impl_->parser_refs.end()) {
        r.error = "unknown parser '" + parser_name + "'";
    } else {
        int top = lua_gettop(impl_->L);
        run_parse(*impl_, doc, it->second, r);
        lua_settop(impl_->L, top);
    }
    r.ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    return r;
}

bool ScriptEngine::edit_field(Document& doc, const Field& field, const std::string& text_in, std::string* err) {
    auto fail = [&](const std::string& m) {
        if (err) *err = m;
        return false;
    };
    PackInfo pi;
    if (!field.editable() || !parse_pack_format(field.pack, pi)) return fail("field is not editable");
    if (doc.read_only()) return fail("document is read-only");
    if (doc.busy()) return fail("document is busy (saving)");
    if (field.offset > doc.size() || field.size > doc.size() - field.offset)
        return fail("field is outside the document (re-parse first)");
    lua_State* L = impl_->L;
    if (!L) return fail("scripting is not available");

    std::string text = trim(text_in);
    // Enum name (exact, then case-insensitive), or the display form "1 = NAME".
    bool have_int = false;
    int64_t iv = 0;
    if (field.enums) {
        for (int pass = 0; pass < 2 && !have_int; ++pass)
            for (const Field::EnumItem& e : *field.enums)
                if (pass == 0 ? e.name == text : iequals(e.name, text)) {
                    iv = e.value;
                    have_int = true;
                    break;
                }
    }
    // Char literal (fmt="char"): bytes, most significant first, like the display.
    std::string chars;
    if (!have_int && !pi.is_float && parse_char_literal(text, chars)) {
        if (chars.empty() || chars.size() > size_t(pi.size))
            return fail("char literal must have 1.." + std::to_string(pi.size) + " characters");
        uint64_t bits = 0;
        for (unsigned char ch : chars) bits = bits << 8 | ch;
        if (pi.is_signed && pi.size < 8 && ((bits >> (pi.size * 8 - 1)) & 1)) bits |= ~0ull << (pi.size * 8);
        iv = int64_t(bits);
        have_int = true;
    }
    if (!have_int) {
        size_t eq = text.find(" = ");
        if (eq != std::string::npos) text = trim(text.substr(0, eq));
        size_t paren = text.find(" (");  // "13 (0xD)"
        if (paren != std::string::npos) text = trim(text.substr(0, paren));
    }
    if (text.empty() && !have_int) return fail("empty value");

    lua_rawgeti(L, LUA_REGISTRYINDEX, impl_->ref_pack);
    lua_pushlstring(L, field.pack.data(), field.pack.size());
    if (pi.is_float) {
        double dv = 0;
        const char* b = text.data();
        auto r = std::from_chars(b, b + text.size(), dv);
        if (r.ec != std::errc() || r.ptr != b + text.size()) {
            lua_pop(L, 2);
            return fail("not a number: '" + text + "'");
        }
        if (pi.size == 4 && std::isfinite(dv) && std::fabs(dv) > double(FLT_MAX)) {  // inf / nan stay allowed
            lua_pop(L, 2);
            return fail("value out of range for f32 (max 3.4028235e38)");
        }
        lua_pushnumber(L, dv);
    } else {
        if (!have_int) {
            bool neg;
            uint64_t mag;
            int base = 10;
            if (!parse_integer(text, neg, mag, &base)) {
                lua_pop(L, 2);
                return fail("not a number or enum name: '" + text + "'");
            }
            // Range for the field's size/signedness.
            bool ok;
            if (pi.is_signed) {
                uint64_t lim = pi.size >= 8 ? (1ull << 63) : (1ull << (pi.size * 8 - 1));
                uint64_t umax = pi.size >= 8 ? ~0ull : (1ull << (pi.size * 8)) - 1;
                ok = neg ? mag <= lim : mag < lim;
                iv = neg ? int64_t(0 - mag) : int64_t(mag);
                if (!ok && !neg && base != 10 && mag <= umax) {  // hex/bin bit pattern, as fmt="hex"/"bin" shows it
                    ok = true;
                    iv = int64_t(pi.size >= 8 ? mag : mag | (~0ull << (pi.size * 8)));
                }
            } else {
                uint64_t max = pi.size >= 8 ? ~0ull : (1ull << (pi.size * 8)) - 1;
                ok = (!neg || mag == 0) && mag <= max;
                iv = int64_t(mag);
            }
            if (!ok) {
                lua_pop(L, 2);
                char buf[160];
                if (pi.is_signed)
                    std::snprintf(buf, sizeof buf, "value out of range for %d-byte signed field (%lld..%lld)", pi.size,
                                  pi.size >= 8 ? (long long)std::numeric_limits<int64_t>::min() : -(1ll << (pi.size * 8 - 1)),
                                  pi.size >= 8 ? (long long)std::numeric_limits<int64_t>::max() : (1ll << (pi.size * 8 - 1)) - 1);
                else
                    std::snprintf(buf, sizeof buf, "value out of range for %d-byte unsigned field (0..%llu)", pi.size,
                                  pi.size >= 8 ? ~0ull : (1ull << (pi.size * 8)) - 1);
                return fail(buf);
            }
        }
        lua_pushinteger(L, lua_Integer(iv));
    }
    std::string perr;
    if (!impl_->pcall(2, 1, impl_->script_limit_ms, &perr)) return fail("encode failed: " + error_head(perr));
    size_t n = 0;
    const char* bytes = lua_tolstring(L, -1, &n);
    std::string data(bytes ? bytes : "", n);
    lua_pop(L, 1);
    if (data.size() != field.size)
        return fail("encoded size " + std::to_string(data.size()) + " does not match field size " +
                    std::to_string(field.size));
    doc.begin_group("Edit field " + field.name);
    bool ok = doc.overwrite(field.offset, reinterpret_cast<const uint8_t*>(data.data()), data.size());
    doc.end_group();
    if (!ok) return fail("write failed");
    return true;
}

// ---- commands & highlights --------------------------------------------------------------------------

void ScriptEngine::run_command(const std::string& name_in) {
    // A copy: callers may pass a reference into command_refs, which the command itself can change
    // (hx.command re-registering, reload).
    const std::string name = name_in;
    lua_State* L = impl_->L;
    auto it = impl_->command_refs.find(name);
    if (!L || it == impl_->command_refs.end()) {
        log(ConsoleLine::Error, "Unknown command '" + name + "'");
        return;
    }
    if (impl_->waiting) {
        log(ConsoleLine::Error, "Command '" + name + "' not started: '" + impl_->prompt.command +
                                    "' is waiting for input");
        return;
    }
    Document* d = host_ ? host_->active_document() : nullptr;
    uint64_t id = d ? d->id() : 0;
    // A coroutine, so hx.prompt can suspend the command until the UI answers.
    lua_State* co = lua_newthread(L);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_rawgeti(co, LUA_REGISTRYINDEX, it->second);
    if (d) push_doc(co, id);
    else lua_pushnil(co);
    impl_->step_command(co, ref, name, id, 1);
}

const ScriptEngine::PendingPrompt* ScriptEngine::pending_prompt() const {
    return impl_->waiting ? &impl_->prompt : nullptr;
}

void ScriptEngine::answer_prompt(const std::string* text) {
    if (!impl_->waiting || impl_->depth > 0 || !impl_->L) return;
    lua_State* co = impl_->waiting_co;
    int ref = impl_->waiting_ref;
    uint64_t doc_id = impl_->waiting_doc;
    std::string name = impl_->prompt.command;
    impl_->waiting = false;  // the ref now belongs to step_command
    impl_->waiting_ref = LUA_NOREF;
    impl_->waiting_co = nullptr;
    impl_->waiting_doc = 0;
    impl_->prompt = {};
    if (text) lua_pushlstring(co, text->data(), text->size());
    else lua_pushnil(co);
    impl_->step_command(co, ref, name, doc_id, 1);
}

void ScriptEngine::set_script_time_limit_ms(int ms) { impl_->script_limit_ms = std::max(1, ms); }

const HighlightSet* ScriptEngine::script_highlights(uint64_t doc_id) const {
    auto it = highlights_.find(doc_id);
    return (it == highlights_.end() || it->second.empty()) ? nullptr : &it->second;
}

}  // namespace hx
