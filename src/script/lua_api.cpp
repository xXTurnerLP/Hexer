// The `hexer` / `hx` Lua API: hx.* functions, the Doc userdata, the parser context `p`, inspect.
// See the API contract at the top of script_engine.h and the error-handling rule in lua_internal.h.
#include "script/lua_internal.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <future>
#include <initializer_list>
#include <memory>

#include "core/devices.h"
#include "core/disasm.h"
#include "core/exe_map.h"
#include "core/hash.h"
#include "core/highlight.h"
#include "core/multisel.h"
#include "core/os_file.h"
#include "core/pcap.h"
#include "core/pcap_filter.h"
#include "core/search.h"
#include "core/symbols.h"
#include "core/util.h"
#include "core/xorscan.h"
#include "script/cexport.h"

#ifndef HEXER_VERSION
#define HEXER_VERSION "0.1.0"
#endif

namespace hx {
namespace {

constexpr const char* kDocMeta = "hexer.Doc";
constexpr const char* kParserMeta = "hexer.Parser";
constexpr uint64_t kMaxRead = 64ull << 20;        // doc:read / p:peekbytes cap
constexpr uint64_t kSmall = 64ull << 10;          // p:bytes returns data up to this size; cstr limit
constexpr uint64_t kMaxStr = 16ull << 20;         // p:str cap
constexpr uint64_t kMaxHash = 256ull << 20;       // doc:hash cap (it blocks the UI thread)
constexpr size_t kMaxScriptHighlights = 1000000;  // per document
constexpr const char* kEllipsis = "\xE2\x80\xA6";

using Impl = ScriptEngine::Impl;

Impl& impl_of(lua_State* L) { return **static_cast<Impl**>(lua_getextraspace(L)); }

// ---- small helpers -----------------------------------------------------------------------------

uint64_t check_u64(lua_State* L, int idx) {
    lua_Integer v = luaL_checkinteger(L, idx);
    luaL_argcheck(L, v >= 0, idx, "must be >= 0");
    return uint64_t(v);
}

// Pushes `field` of the table at `idx` without invoking metamethods (safe outside protected calls).
int raw_field(lua_State* L, int idx, const char* field) {
    idx = lua_absindex(L, idx);
    lua_pushstring(L, field);
    return lua_rawget(L, idx);
}

std::string escape_quoted(const char* s, size_t n, size_t max) {
    static const char* hexd = "0123456789ABCDEF";
    std::string out = "\"";
    size_t m = n < max ? n : max;
    for (size_t i = 0; i < m; ++i) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '\0': out += "\\0"; break;
        default:
            if (c < 0x20 || c >= 0x7F) {
                out += "\\x";
                out += hexd[c >> 4];
                out += hexd[c & 15];
            } else {
                out += char(c);
            }
        }
    }
    out += '"';
    if (n > m) out += kEllipsis;
    return out;
}

std::string hex_spaced(const uint8_t* p, size_t n) {
    static const char* hexd = "0123456789ABCDEF";
    std::string out;
    out.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) {
        if (i) out += ' ';
        out += hexd[p[i] >> 4];
        out += hexd[p[i] & 15];
    }
    return out;
}

// Color from a Lua value: "red" | "#rrggbb" | 0xRRGGBB | packed 0xAABBGGRR (as returned by hx.color).
bool to_color(lua_State* L, int idx, uint32_t& out) {
    int t = lua_type(L, idx);
    if (t == LUA_TNUMBER) {
        lua_Integer v = lua_tointeger(L, idx);
        if (v < 0 || v > 0xFFFFFFFFll) return false;
        out = v > 0xFFFFFF ? uint32_t(v) : from_rgb_int(uint32_t(v));
        return true;
    }
    if (t == LUA_TSTRING) return parse_color(lua_tostring(L, idx), out);
    return false;
}

// ---- number types shared by doc:uXX() and p:uXX() ------------------------------------------------

struct NumType {
    const char* name;  // Lua method name
    const char* base;  // type name without endianness ("u16")
    uint8_t size;
    bool is_signed;
    bool is_float;
    char endian;       // 0 = parser default, 'l', 'b'
};

const NumType kNumTypes[] = {
    {"u8", "u8", 1, false, false, 'l'},     {"i8", "i8", 1, true, false, 'l'},
    {"u16", "u16", 2, false, false, 0},     {"u16le", "u16", 2, false, false, 'l'},
    {"u16be", "u16", 2, false, false, 'b'}, {"i16", "i16", 2, true, false, 0},
    {"i16le", "i16", 2, true, false, 'l'},  {"i16be", "i16", 2, true, false, 'b'},
    {"u24", "u24", 3, false, false, 0},     {"u24le", "u24", 3, false, false, 'l'},
    {"u24be", "u24", 3, false, false, 'b'}, {"i24", "i24", 3, true, false, 0},
    {"i24le", "i24", 3, true, false, 'l'},  {"i24be", "i24", 3, true, false, 'b'},
    {"u32", "u32", 4, false, false, 0},     {"u32le", "u32", 4, false, false, 'l'},
    {"u32be", "u32", 4, false, false, 'b'}, {"i32", "i32", 4, true, false, 0},
    {"i32le", "i32", 4, true, false, 'l'},  {"i32be", "i32", 4, true, false, 'b'},
    {"u64", "u64", 8, false, false, 0},     {"u64le", "u64", 8, false, false, 'l'},
    {"u64be", "u64", 8, false, false, 'b'}, {"i64", "i64", 8, true, false, 0},
    {"i64le", "i64", 8, true, false, 'l'},  {"i64be", "i64", 8, true, false, 'b'},
    {"f32", "f32", 4, false, true, 0},      {"f32le", "f32", 4, false, true, 'l'},
    {"f32be", "f32", 4, false, true, 'b'},  {"f64", "f64", 8, false, true, 0},
    {"f64le", "f64", 8, false, true, 'l'},  {"f64be", "f64", 8, false, true, 'b'},
};
constexpr int kNumTypeCount = int(sizeof(kNumTypes) / sizeof(kNumTypes[0]));

struct NumValue {
    bool is_float = false;
    int64_t i = 0;
    double f = 0.0;
};

NumValue decode_num(const NumType& t, const uint8_t* b, bool be) {
    uint64_t v = 0;
    for (int k = 0; k < t.size; ++k) {
        int src = be ? k : t.size - 1 - k;
        v = (v << 8) | b[src];
    }
    NumValue out;
    if (t.is_float) {
        out.is_float = true;
        if (t.size == 4) {
            uint32_t u = uint32_t(v);
            float f;
            std::memcpy(&f, &u, 4);
            out.f = f;
        } else {
            std::memcpy(&out.f, &v, 8);
        }
        return out;
    }
    if (t.is_signed && t.size < 8) {
        int shift = 64 - 8 * t.size;
        out.i = int64_t(v << shift) >> shift;
    } else {
        out.i = int64_t(v);
    }
    return out;
}

void push_num(lua_State* L, const NumValue& v) {
    if (v.is_float) lua_pushnumber(L, v.f);
    else lua_pushinteger(L, lua_Integer(v.i));
}

std::string num_type_name(const NumType& t, bool be) {
    std::string s = t.base;
    if (t.size > 1) s += be ? "be" : "le";
    return s;
}

std::string num_pack(const NumType& t, bool be) {
    if (t.size == 1) return t.is_signed ? "b" : "B";
    std::string s = be ? ">" : "<";
    if (t.is_float) return s + (t.size == 4 ? "f" : "d");
    s += t.is_signed ? 'i' : 'I';
    s += char('0' + t.size);
    return s;
}

// ---- Doc userdata ----------------------------------------------------------------------------------

struct DocUd {
    uint64_t id;
};

Document* check_doc(lua_State* L, int idx) {
    auto* ud = static_cast<DocUd*>(luaL_checkudata(L, idx, kDocMeta));
    ScriptHost* host = impl_of(L).eng.host();
    Document* d = host ? host->find_document(ud->id) : nullptr;
    if (!d) luaL_error(L, "document closed");
    return d;
}

const char* edit_block_reason(const Document* d) {
    if (d->read_only()) return "document is read-only";
    if (d->busy()) return "document is busy (saving)";
    return nullptr;
}

int edit_failed(lua_State* L, const char* what, uint64_t off, uint64_t size) {
    char buf[160];
    std::snprintf(buf, sizeof buf, "%s failed at 0x%llX (document size 0x%llX)", what,
                  (unsigned long long)off, (unsigned long long)size);
    return luaL_error(L, "%s", buf);
}

int doc_size(lua_State* L) {
    lua_pushinteger(L, lua_Integer(check_doc(L, 1)->size()));
    return 1;
}

int doc_name(lua_State* L) {
    Document* d = check_doc(L, 1);
    lua_pushstring(L, d->display_name().c_str());
    return 1;
}

int doc_path(lua_State* L) {
    lua_pushstring(L, check_doc(L, 1)->path().c_str());
    return 1;
}

int doc_id(lua_State* L) {
    lua_pushinteger(L, lua_Integer(check_doc(L, 1)->id()));
    return 1;
}

// "file" (also untitled documents), "device" (raw disk / volume) or "process" (process memory).
int doc_target(lua_State* L) {
    const SourceKind k = check_doc(L, 1)->target();
    lua_pushstring(L, k == SourceKind::Process ? "process" : k == SourceKind::Device ? "device" : "file");
    return 1;
}

int doc_pid(lua_State* L) {
    const Document* d = check_doc(L, 1);
    if (d->target() == SourceKind::Process)
        lua_pushinteger(L, lua_Integer(d->process_id()));
    else
        lua_pushnil(L);
    return 1;
}

// doc:modules() -> list of {name=, base=, size=, path=} (process documents; {} otherwise), or nil, err.
int doc_modules(lua_State* L) {
    const Document* d = check_doc(L, 1);
    std::vector<ModuleInfo> mods;
    if (d->target() == SourceKind::Process) {
        std::string err;
        if (!process_modules(d->process_id(), mods, &err)) {
            lua_pushnil(L);
            lua_pushstring(L, err.c_str());
            return 2;
        }
    }
    lua_createtable(L, int(std::min<size_t>(mods.size(), INT32_MAX)), 0);
    for (size_t i = 0; i < mods.size(); ++i) {
        lua_createtable(L, 0, 4);
        lua_pushstring(L, mods[i].name.c_str());
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, lua_Integer(mods[i].base));
        lua_setfield(L, -2, "base");
        lua_pushinteger(L, lua_Integer(mods[i].size));
        lua_setfield(L, -2, "size");
        lua_pushstring(L, mods[i].path.c_str());
        lua_setfield(L, -2, "path");
        lua_rawseti(L, -2, lua_Integer(i + 1));
    }
    return 1;
}

int doc_read(lua_State* L) {
    Document* d = check_doc(L, 1);
    uint64_t off = check_u64(L, 2);
    uint64_t len = check_u64(L, 3);
    if (len > kMaxRead) return luaL_error(L, "doc:read: at most 64 MiB per call");
    uint64_t size = d->size();
    if (off >= size || len == 0) {
        lua_pushliteral(L, "");
        return 1;
    }
    len = std::min(len, size - off);
    luaL_Buffer b;
    char* p = luaL_buffinitsize(L, &b, size_t(len));
    size_t got = d->read(off, reinterpret_cast<uint8_t*>(p), size_t(len));
    luaL_pushresultsize(&b, got);
    return 1;
}

int doc_num(lua_State* L) {
    const NumType& t = kNumTypes[lua_tointeger(L, lua_upvalueindex(1))];
    Document* d = check_doc(L, 1);
    uint64_t off = check_u64(L, 2);
    uint8_t b[8];
    if (off >= d->size() || d->size() - off < t.size || d->read(off, b, t.size) != t.size) {
        lua_pushnil(L);
        return 1;
    }
    push_num(L, decode_num(t, b, t.endian == 'b'));
    return 1;
}

int doc_write(lua_State* L) {
    Document* d = check_doc(L, 1);
    uint64_t off = check_u64(L, 2);
    size_t n;
    const char* s = luaL_checklstring(L, 3, &n);
    if (const char* why = edit_block_reason(d)) return luaL_error(L, "%s", why);
    if (n && !d->overwrite(off, reinterpret_cast<const uint8_t*>(s), n))
        return edit_failed(L, "doc:write", off, d->size());
    return 0;
}

int doc_insert(lua_State* L) {
    Document* d = check_doc(L, 1);
    uint64_t off = check_u64(L, 2);
    size_t n;
    const char* s = luaL_checklstring(L, 3, &n);
    if (const char* why = edit_block_reason(d)) return luaL_error(L, "%s", why);
    if (n && !d->insert(off, reinterpret_cast<const uint8_t*>(s), n))
        return edit_failed(L, "doc:insert", off, d->size());
    return 0;
}

int doc_erase(lua_State* L) {
    Document* d = check_doc(L, 1);
    uint64_t off = check_u64(L, 2);
    uint64_t len = check_u64(L, 3);
    if (const char* why = edit_block_reason(d)) return luaL_error(L, "%s", why);
    if (len && !d->erase(off, len)) return edit_failed(L, "doc:erase", off, d->size());
    return 0;
}

int doc_replace(lua_State* L) {
    Document* d = check_doc(L, 1);
    uint64_t off = check_u64(L, 2);
    uint64_t len = check_u64(L, 3);
    size_t n;
    const char* s = luaL_checklstring(L, 4, &n);
    if (const char* why = edit_block_reason(d)) return luaL_error(L, "%s", why);
    if ((len || n) && !d->replace(off, len, reinterpret_cast<const uint8_t*>(s), n))
        return edit_failed(L, "doc:replace", off, d->size());
    return 0;
}

// Message handler for pcalls *inside* API functions (struct/array/transaction): appends a traceback
// to string errors once, so the deepest frames are kept when the error is re-raised; other error
// values pass through untouched.
int inner_msgh(lua_State* L) {
    if (lua_type(L, 1) == LUA_TSTRING && !std::strstr(lua_tostring(L, 1), "\nstack traceback:"))
        luaL_traceback(L, L, lua_tostring(L, 1), 1);
    else lua_settop(L, 1);
    return 1;
}

int doc_transaction(lua_State* L) {
    Document* d = check_doc(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    // Inside an open group (a command) an unlabelled transaction keeps that step's label.
    const char* label = luaL_optstring(L, 3, d->in_group() ? "" : "Script");
    uint64_t id = d->id();
    d->begin_group(label);
    lua_pushcfunction(L, inner_msgh);
    int base = lua_gettop(L);
    lua_pushvalue(L, 2);
    int st = lua_pcall(L, 0, LUA_MULTRET, base);
    ScriptHost* host = impl_of(L).eng.host();
    if (Document* again = host ? host->find_document(id) : nullptr) again->end_group();
    if (st != LUA_OK) return lua_error(L);
    return lua_gettop(L) - base;
}

int doc_cursor(lua_State* L) {
    lua_pushinteger(L, lua_Integer(check_doc(L, 1)->view().cursor));
    return 1;
}

int doc_selection(lua_State* L) {
    Document* d = check_doc(L, 1);
    lua_pushinteger(L, lua_Integer(d->view().sel_begin()));
    lua_pushinteger(L, lua_Integer(d->view().sel_len()));
    return 2;
}

void move_view(lua_State* L, Document* d, uint64_t off, uint64_t len) {
    uint64_t size = d->size();
    off = std::min(off, size);
    len = std::min(len, size - off);
    // The host first (the app's reveal_range: a Back / Forward history entry for the position
    // being left, select, scroll); then the selection itself where the host did not set it.
    if (ScriptHost* host = impl_of(L).eng.host()) host->reveal(*d, off, len);
    ViewState& v = d->view();
    if (v.sel_begin() != off || v.sel_len() != len) {
        v.anchor = off;
        v.cursor = off + len;
    }
    v.low_nibble = false;
    d->view_generation++;
}

int doc_select(lua_State* L) {
    Document* d = check_doc(L, 1);
    uint64_t off = check_u64(L, 2);
    uint64_t len = luaL_opt(L, check_u64, 3, 0);
    d->view().extra_sel.clear();  // one selection: no extra ranges
    move_view(L, d, off, len);
    return 0;
}

// doc:selections() -> { {offset=, length=}, ... }: every selected range (multi-selection), the one
// holding the primary selection first, the others in file order; {} when nothing is selected.
int doc_selections(lua_State* L) {
    Document* d = check_doc(L, 1);
    const std::vector<ByteRange> rs = selection_ranges_primary_first(d->view(), d->size());
    lua_createtable(L, int(rs.size()), 0);
    for (size_t i = 0; i < rs.size(); ++i) {
        lua_createtable(L, 0, 2);
        lua_pushinteger(L, lua_Integer(rs[i].begin));
        lua_setfield(L, -2, "offset");
        lua_pushinteger(L, lua_Integer(rs[i].len()));
        lua_setfield(L, -2, "length");
        lua_rawseti(L, -2, lua_Integer(i + 1));
    }
    return 1;
}

// One entry of doc:select_ranges: {offset=, length=} or {off, len}.
ByteRange check_range_entry(lua_State* L, int idx, lua_Integer n) {
    if (!lua_istable(L, idx)) luaL_error(L, "select_ranges: entry %d is not a table ({offset=, length=} or {off, len})", int(n));
    if (lua_getfield(L, idx, "offset") == LUA_TNIL) {
        lua_pop(L, 1);
        lua_rawgeti(L, idx, 1);
    }
    if (lua_getfield(L, idx, "length") == LUA_TNIL) {
        lua_pop(L, 1);
        lua_rawgeti(L, idx, 2);
    }
    // Numbers with an integer value (also 2.0, as luaL_checkinteger takes them for doc:select).
    int off_ok = 0, len_ok = lua_isnil(L, -1);
    const lua_Integer off_v = lua_type(L, -2) == LUA_TNUMBER ? lua_tointegerx(L, -2, &off_ok) : 0;
    const lua_Integer len_v = lua_type(L, -1) == LUA_TNUMBER ? lua_tointegerx(L, -1, &len_ok) : 0;
    if (!off_ok || !len_ok || off_v < 0 || len_v < 0)
        luaL_error(L, "select_ranges: entry %d needs a non-negative integer offset and length", int(n));
    const uint64_t off = uint64_t(off_v);
    const uint64_t len = uint64_t(len_v);
    lua_pop(L, 2);
    return {off, len > UINT64_MAX - off ? UINT64_MAX : off + len};
}

// doc:select_ranges{ {offset=, length=}, ... }: the first range becomes the primary selection (caret
// at its end, scrolled into view), the others the extra ranges of a multi-selection (merged when
// they touch). Clamped to the document; at most kMaxSelections ranges.
int doc_select_ranges(lua_State* L) {
    Document* d = check_doc(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);
    const lua_Integer n = luaL_len(L, 2);
    if (n < 0 || uint64_t(n) > kMaxSelections)
        luaL_error(L, "select_ranges: too many ranges (%d; at most %d)", int(n), int(kMaxSelections));
    std::vector<ByteRange> rs;
    rs.reserve(size_t(n));
    for (lua_Integer i = 1; i <= n; ++i) {
        lua_rawgeti(L, 2, i);
        rs.push_back(check_range_entry(L, lua_gettop(L), i));
        lua_pop(L, 1);
    }
    if (ScriptHost* host = impl_of(L).eng.host(); host && !rs.empty()) {
        // Revealed before the ranges are set, so the host records the jump from where it was.
        const uint64_t size = d->size(), b = std::min(rs[0].begin, size);
        host->reveal(*d, b, std::min(rs[0].end, size) - b);
    }
    set_selection_ranges(d->view(), rs, d->size());
    d->view_generation++;
    return 0;
}

int doc_goto(lua_State* L) {
    Document* d = check_doc(L, 1);
    move_view(L, d, check_u64(L, 2), 0);
    return 0;
}

// doc:hash(algo, off?, len?) -> lowercase hex digest of [off, off+len) (clamped to EOF; default
// the whole document). Blocking, so at most kMaxHash bytes per call.
int doc_hash(lua_State* L) {
    Document* d = check_doc(L, 1);
    const char* algo = luaL_checkstring(L, 2);
    const uint64_t size = d->size();
    const uint64_t off = std::min<uint64_t>(lua_isnoneornil(L, 3) ? 0 : check_u64(L, 3), size);
    const uint64_t len = std::min<uint64_t>(lua_isnoneornil(L, 4) ? size - off : check_u64(L, 4), size - off);
    if (len > kMaxHash)
        return luaL_error(L, "doc:hash: at most 256 MiB per call (the Hashes panel hashes any size in the background)");
    char err[256] = {};
    if (const int ref = find_hash_algorithm(algo) ? LUA_NOREF : find_lua_hash(impl_of(L), algo); ref != LUA_NOREF) {
        // A Lua algorithm runs right here (raising: its errors are this call's).
        std::shared_ptr<const Snapshot> snap = d->snapshot();
        LuaHasher h(L, nullptr, ref);
        uint64_t bad = UINT64_MAX;
        bool hole = false;
        if (hash_range(*snap, off, len, {&h}, nullptr, nullptr, &bad, &hole)) {
            const std::string hex = to_hex(h.finish());
            lua_pushlstring(L, hex.data(), hex.size());
            return 1;
        }
        std::snprintf(err, sizeof err, "doc:hash: %s",
                      (hole ? hash_hole_message(bad) : "read error at offset " + std::to_string(bad)).c_str());
    } else {
        std::string out, e;
        if (hash_snapshot_hex(*d->snapshot(), algo, off, len, out, &e))
            lua_pushlstring(L, out.data(), out.size());
        else
            std::snprintf(err, sizeof err, "doc:hash: %s", e.empty() ? "failed" : e.c_str());
    }
    if (err[0]) return luaL_error(L, "%s", err);
    return 1;
}

// ---- disassembly (hx.disasm / doc:disasm) ------------------------------------------------------
// Results are first copied into a Lua-owned array of plain structs, then into the result tables
// (a memory error while building them unwinds cleanly: see lua_internal.h).

constexpr size_t kMaxDisasm = 10000;  // instructions per call

struct LuaInsn {
    uint64_t offset, address, target;
    uint8_t length, flow;
    bool valid, readable, has_target;
    uint8_t bytes[Insn::kMaxLength];
    char text[256];
    char section[32];
};

// Argument `idx`: nil -> def, 64 / 32, or "x64" / "amd64" / "x86" / "64" / "32".
DisasmMode check_disasm_mode(lua_State* L, int idx, DisasmMode def) {
    if (lua_isnoneornil(L, idx)) return def;
    if (lua_type(L, idx) == LUA_TNUMBER) {
        const lua_Integer v = luaL_checkinteger(L, idx);
        if (v == 64) return DisasmMode::X64;
        if (v == 32) return DisasmMode::X86;
    } else if (const char* m = lua_tostring(L, idx)) {
        if (!std::strcmp(m, "64") || !std::strcmp(m, "x64") || !std::strcmp(m, "amd64") || !std::strcmp(m, "x86_64"))
            return DisasmMode::X64;
        if (!std::strcmp(m, "32") || !std::strcmp(m, "x86") || !std::strcmp(m, "i386")) return DisasmMode::X86;
    }
    luaL_argerror(L, idx, "mode must be 64 or 32");
    return def;
}

void to_lua_insn(const Insn& i, const std::string& section, LuaInsn& o) {
    o.offset = i.offset;
    o.address = i.address;
    o.target = i.target;
    o.length = i.length;
    o.flow = uint8_t(i.flow);
    o.valid = i.valid;
    o.readable = i.readable;
    o.has_target = i.has_target;
    std::memcpy(o.bytes, i.bytes, sizeof o.bytes);
    std::snprintf(o.text, sizeof o.text, "%s", i.text.c_str());
    std::snprintf(o.section, sizeof o.section, "%s", section.c_str());
}

// Replaces the array userdata at the top of the stack by the list of result tables.
void push_lua_insns(lua_State* L, const LuaInsn* v, size_t n) {
    lua_createtable(L, int(n), 0);
    for (size_t k = 0; k < n; ++k) {
        const LuaInsn& i = v[k];
        lua_createtable(L, 0, 9);
        lua_pushinteger(L, lua_Integer(i.address));
        lua_setfield(L, -2, "address");
        lua_pushinteger(L, lua_Integer(i.offset));
        lua_setfield(L, -2, "offset");
        lua_pushinteger(L, i.length);
        lua_setfield(L, -2, "length");
        lua_pushstring(L, i.text);
        lua_setfield(L, -2, "text");
        lua_pushlstring(L, reinterpret_cast<const char*>(i.bytes), std::min<size_t>(i.length, sizeof i.bytes));
        lua_setfield(L, -2, "bytes");
        lua_pushboolean(L, i.valid);
        lua_setfield(L, -2, "valid");
        if (i.has_target) {
            lua_pushinteger(L, lua_Integer(i.target));
            lua_setfield(L, -2, "target");
        }
        if (const char* f = insn_flow_name(Insn::Flow(i.flow)); f[0]) {
            lua_pushstring(L, f);
            lua_setfield(L, -2, "flow");
        }
        if (i.section[0]) {
            lua_pushstring(L, i.section);
            lua_setfield(L, -2, "section");
        }
        lua_rawseti(L, -2, lua_Integer(k + 1));
    }
    lua_remove(L, -2);  // the array userdata
}

// doc:disasm(off, count?, mode?) -> list of instructions (see the API comment). Addresses come
// from the document's address map (PE / ELF headers, process memory: identity, else offset).
int doc_disasm(lua_State* L) {
    Document* d = check_doc(L, 1);
    const uint64_t off = check_u64(L, 2);
    const lua_Integer cnt = luaL_optinteger(L, 3, 16);
    luaL_argcheck(L, cnt >= 0 && size_t(cnt) <= kMaxDisasm, 3, "count must be 0..10000");
    const bool has_mode = !lua_isnoneornil(L, 4);
    const DisasmMode forced = check_disasm_mode(L, 4, DisasmMode::X64);
    auto* arr = static_cast<LuaInsn*>(lua_newuserdatauv(L, sizeof(LuaInsn) * std::max<size_t>(size_t(cnt), 1), 0));
    size_t n = 0;
    {
        const AddressMap map = detect_address_map(*d);
        DisasmOptions opt;
        opt.mode = has_mode ? forced : (map.bits == 32 ? DisasmMode::X86 : DisasmMode::X64);
        std::vector<Insn> out;
        disasm_range(*d, off, size_t(cnt), map, opt, out);
        n = std::min(out.size(), size_t(cnt));
        for (size_t k = 0; k < n; ++k) to_lua_insn(out[k], map.section_at_offset(out[k].offset), arr[k]);
    }
    push_lua_insns(L, arr, n);
    return 1;
}

// ---- doc:symbols ---------------------------------------------------------------------------------
// The table is serialized into a malloc'ed blob owned by a userdata with __gc (a Lua error while
// the result tables are built frees it); the SymbolTable itself is gone by then.

struct SymRec {
    uint64_t address, offset;
    uint32_t name_off, name_len, mod_off, mod_len, fwd_off, fwd_len, ordinal;
    uint8_t kind;
    bool has_address, has_offset;
};
struct SymBlob {
    void* p;
    size_t n;
};
constexpr const char* kSymBlobMeta = "hexer.symblob";

int symblob_gc(lua_State* L) {
    auto* b = static_cast<SymBlob*>(luaL_checkudata(L, 1, kSymBlobMeta));
    std::free(b->p);
    b->p = nullptr;
    return 0;
}

// doc:symbols() -> list of {name=, address=, offset=, kind=, module=, ordinal=?, forward=?}
int doc_symbols(lua_State* L) {
    Document* d = check_doc(L, 1);
    auto* blob = static_cast<SymBlob*>(lua_newuserdatauv(L, sizeof(SymBlob), 0));
    blob->p = nullptr;
    blob->n = 0;
    if (luaL_newmetatable(L, kSymBlobMeta)) {
        lua_pushcfunction(L, symblob_gc);
        lua_setfield(L, -2, "__gc");
    }
    lua_setmetatable(L, -2);
    bool oom = false;
    {
        const AddressMap map = detect_address_map(*d);
        ScriptHost* host = impl_of(L).eng.host();
        std::shared_ptr<const SymbolTable> cached = host ? host->cached_symbols(*d) : nullptr;
        if (!cached) cached = std::make_shared<const SymbolTable>(build_symbols(*d->snapshot(), map));
        const SymbolTable& t = *cached;
        const size_t n = t.symbols.size() + t.forwarders.size();
        size_t pool = 0;
        for (const auto* v : {&t.symbols, &t.forwarders})
            for (const Symbol& s : *v) pool += s.name.size() + s.module.size() + s.forward.size();
        blob->p = std::malloc(std::max<size_t>(n * sizeof(SymRec) + pool, 1));
        if (!blob->p) {
            oom = true;
        } else {
            blob->n = n;
            auto* rec = static_cast<SymRec*>(blob->p);
            char* str = static_cast<char*>(blob->p) + n * sizeof(SymRec);
            uint32_t at = 0;
            auto put = [&](const std::string& s, uint32_t& off, uint32_t& len) {
                off = at;
                len = uint32_t(s.size());
                std::memcpy(str + at, s.data(), s.size());
                at += len;
            };
            size_t k = 0;
            for (const auto* v : {&t.symbols, &t.forwarders})
                for (const Symbol& s : *v) {
                    SymRec& r = rec[k++];
                    r.address = s.address;
                    r.has_address = s.forward.empty();
                    r.has_offset = r.has_address && map.va_to_offset(s.address, r.offset);
                    r.ordinal = s.ordinal;
                    r.kind = uint8_t(s.kind);
                    put(s.name, r.name_off, r.name_len);
                    put(s.module, r.mod_off, r.mod_len);
                    put(s.forward, r.fwd_off, r.fwd_len);
                }
        }
    }
    if (oom) return luaL_error(L, "doc:symbols: out of memory");
    const auto* rec = static_cast<const SymRec*>(blob->p);
    const char* str = static_cast<const char*>(blob->p) + blob->n * sizeof(SymRec);
    lua_createtable(L, int(std::min<size_t>(blob->n, INT32_MAX)), 0);
    for (size_t k = 0; k < blob->n; ++k) {
        const SymRec& r = rec[k];
        lua_createtable(L, 0, 6);
        lua_pushlstring(L, str + r.name_off, r.name_len);
        lua_setfield(L, -2, "name");
        if (r.has_address) {
            lua_pushinteger(L, lua_Integer(r.address));
            lua_setfield(L, -2, "address");
        }
        if (r.has_offset) {
            lua_pushinteger(L, lua_Integer(r.offset));
            lua_setfield(L, -2, "offset");
        }
        lua_pushstring(L, symbol_kind_name(Symbol::Kind(r.kind)));
        lua_setfield(L, -2, "kind");
        lua_pushlstring(L, str + r.mod_off, r.mod_len);
        lua_setfield(L, -2, "module");
        if (r.ordinal) {
            lua_pushinteger(L, lua_Integer(r.ordinal));
            lua_setfield(L, -2, "ordinal");
        }
        if (r.fwd_len) {
            lua_pushlstring(L, str + r.fwd_off, r.fwd_len);
            lua_setfield(L, -2, "forward");
        }
        lua_rawseti(L, -2, lua_Integer(k + 1));
    }
    lua_remove(L, -2);  // the blob (freed by its __gc)
    return 1;
}

int doc_find(lua_State* L) {
    Document* d = check_doc(L, 1);
    size_t n;
    const char* needle = luaL_checklstring(L, 2, &n);
    bool hex = false, backward = false;
    if (lua_istable(L, 4)) {
        lua_getfield(L, 4, "hex");
        hex = lua_toboolean(L, -1);
        lua_getfield(L, 4, "backward");
        backward = lua_toboolean(L, -1);
        lua_pop(L, 2);
    } else if (!lua_isnoneornil(L, 4)) {
        luaL_checktype(L, 4, LUA_TTABLE);
    }
    uint64_t size = d->size();
    uint64_t start = lua_isnoneornil(L, 3) ? (backward ? size : 0) : check_u64(L, 3);
    Impl& im = impl_of(L);
    char err[256] = "";
    bool found = false;
    uint64_t at = 0;
    {
        Pattern pat;
        std::string perr;
        if (hex) {
            if (!compile_pattern(SearchKind::Hex, std::string(needle, n), false, pat, &perr))
                std::snprintf(err, sizeof err, "doc:find: %s", perr.empty() ? "bad hex pattern" : perr.c_str());
        } else {
            pat.bytes.assign(needle, needle + n);
            pat.mask.assign(n, 0xFF);
        }
        if (!err[0] && pat.size() == 0) std::snprintf(err, sizeof err, "doc:find: empty pattern");
        if (!err[0]) {
            // Scan on a worker so a runaway search over a huge file can be cancelled at the
            // script's time limit (the instruction hook cannot interrupt C code).
            std::shared_ptr<const Snapshot> snap = d->snapshot();
            std::atomic<bool> cancel{false};
            bool forward = !backward;
            auto fut = std::async(std::launch::async, [&] {
                return find_in(*snap, pat, start, forward, &cancel);
            });
            auto until = im.deadline_on ? im.deadline
                                        : std::chrono::steady_clock::now() + std::chrono::seconds(10);
            if (fut.wait_until(until) != std::future_status::ready) {
                cancel = true;
                std::snprintf(err, sizeof err, "doc:find: time limit reached (use the Search panel for huge files)");
            }
            std::optional<uint64_t> r = fut.get();
            if (!err[0] && r) {
                found = true;
                at = *r;
            }
        }
    }
    if (err[0]) return luaL_error(L, "%s", err);
    if (found) lua_pushinteger(L, lua_Integer(at));
    else lua_pushnil(L);
    return 1;
}

// doc:view_range() -> first, last (inclusive) visible byte of the document's hex view, or nil.
int doc_view_range(lua_State* L) {
    Document* d = check_doc(L, 1);
    ScriptHost* host = impl_of(L).eng.host();
    uint64_t first = 0, last = 0;
    if (!host || !host->view_range(*d, first, last)) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushinteger(L, lua_Integer(first));
    lua_pushinteger(L, lua_Integer(last));
    return 2;
}

// ---- bookmarks (doc:bookmarks / doc:add_bookmark / doc:remove_bookmark; undoable via Document) ----

int doc_bookmarks(lua_State* L) {
    Document* d = check_doc(L, 1);
    const std::vector<Bookmark>& bms = d->view().bookmarks;  // a reference: nothing to destroy
    lua_createtable(L, int(bms.size()), 0);
    for (size_t i = 0; i < bms.size(); ++i) {
        const Bookmark& b = bms[i];
        lua_createtable(L, 0, 5);
        lua_pushinteger(L, lua_Integer(b.offset));
        lua_setfield(L, -2, "offset");
        lua_pushinteger(L, lua_Integer(b.length));
        lua_setfield(L, -2, "length");
        lua_pushlstring(L, b.name.data(), b.name.size());
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, lua_Integer(b.color));
        lua_setfield(L, -2, "color");
        lua_pushlstring(L, b.note.data(), b.note.size());
        lua_setfield(L, -2, "note");
        lua_rawseti(L, -2, lua_Integer(i + 1));
    }
    return 1;
}

bool add_bookmark_plain(Document& d, uint64_t off, uint64_t len, const char* name, size_t name_len, uint32_t color,
                        const char* note, size_t note_len) {
    Bookmark b;
    b.offset = off;
    b.length = len;
    b.name.assign(name, name_len);
    b.color = color;
    b.note.assign(note, note_len);
    return d.add_bookmark(b);
}

// doc:add_bookmark(off, len?, name?, color?, note?) -> 1-based index of the new bookmark.
int doc_add_bookmark(lua_State* L) {
    Document* d = check_doc(L, 1);
    const uint64_t off = check_u64(L, 2);
    const uint64_t len = luaL_opt(L, check_u64, 3, 1);
    size_t name_len = 0, note_len = 0;
    const char* name = luaL_optlstring(L, 4, "", &name_len);
    uint32_t color = 0;
    if (!lua_isnoneornil(L, 5) && !to_color(L, 5, color))
        return luaL_argerror(L, 5, "color expected (\"red\", \"#ff8800\", 0xff8800)");
    const char* note = luaL_optlstring(L, 6, "", &note_len);
    const uint64_t size = d->size();
    if (off >= size) return edit_failed(L, "doc:add_bookmark", off, size);
    const uint64_t blen = std::max<uint64_t>(1, std::min(len, size - off));
    if (!add_bookmark_plain(*d, off, blen, name, name_len, color, note, note_len))
        return luaL_error(L, "document is busy (saving)");
    lua_pushinteger(L, lua_Integer(d->view().bookmarks.size()));
    return 1;
}

int doc_remove_bookmark(lua_State* L) {
    Document* d = check_doc(L, 1);
    const lua_Integer i = luaL_checkinteger(L, 2);
    const size_t n = d->view().bookmarks.size();
    if (i < 1 || uint64_t(i) > n)
        return luaL_error(L, "doc:remove_bookmark: no bookmark #%I (the document has %I)", i, lua_Integer(n));
    if (!d->remove_bookmark(size_t(i - 1))) return luaL_error(L, "document is busy (saving)");
    return 0;
}

int doc_tostring(lua_State* L) {
    auto* ud = static_cast<DocUd*>(luaL_checkudata(L, 1, kDocMeta));
    ScriptHost* host = impl_of(L).eng.host();
    Document* d = host ? host->find_document(ud->id) : nullptr;
    if (d) {
        std::string name = d->display_name();
        lua_pushfstring(L, "Doc#%I \"%s\"", lua_Integer(ud->id), name.c_str());
    } else {
        lua_pushfstring(L, "Doc#%I (closed)", lua_Integer(ud->id));
    }
    return 1;
}

int doc_eq(lua_State* L) {
    auto* a = static_cast<DocUd*>(luaL_testudata(L, 1, kDocMeta));
    auto* b = static_cast<DocUd*>(luaL_testudata(L, 2, kDocMeta));
    lua_pushboolean(L, a && b && a->id == b->id);
    return 1;
}

int doc_apply_transform(lua_State* L);  // with the XOR search functions below

// ---- doc:packets ---------------------------------------------------------------------------------

lua_Integer opt_int(lua_State* L, int idx, const char* key, lua_Integer def);  // (XOR section below)
int opts_index(lua_State* L, int idx);

constexpr lua_Integer kMaxLuaPackets = 1000000;  // doc:packets entries per call
constexpr size_t kLuaPacketChunk = 65536;        // packets indexed at a time while collecting

struct LuaPacket {
    uint64_t number = 0;  // 1-based
    Packet p;
    PacketInfo pi;
};

// Blocking (run on a worker): the packets of `snap` from number `first` on matching `f`, at most
// `max`, into `out`; *next = the number to continue at (0 = the capture ended). The index grows in
// chunks (index_pcap_append), so a small page near the start never indexes the whole capture.
void collect_packets(const Snapshot& snap, const PacketFilter& f, uint64_t first, size_t max,
                     std::vector<LuaPacket>& out, uint64_t& next, bool& not_capture, const std::atomic<bool>& cancel) {
    next = 0;
    PcapIndexResult ix;
    const auto limit = [&](uint64_t n) { return size_t(std::min<uint64_t>(kPcapMaxPackets, n)); };
    index_pcap(snap, ix, limit(first - 1 + std::min<uint64_t>(max, kLuaPacketChunk)), &cancel);
    if (ix.format == CaptureFormat::None) {
        not_capture = true;
        return;
    }
    uint64_t i = first - 1;
    while (true) {
        for (; i < ix.packets.size(); ++i) {
            if ((i & 255) == 0 && cancel.load(std::memory_order_relaxed)) return;
            if (out.size() >= max) {
                next = i + 1;
                return;
            }
            LuaPacket lp;
            lp.number = i + 1;
            lp.p = ix.packets[size_t(i)];
            lp.pi = dissect_packet(snap, lp.p, kFilterRead);
            if (f.match(lp.p, lp.pi, lp.number)) out.push_back(std::move(lp));
        }
        if (!ix.truncated || ix.packets.size() >= kPcapMaxPackets || cancel.load()) return;
        index_pcap_append(snap, ix, limit(ix.packets.size() + kLuaPacketChunk), &cancel);
    }
}

void set_int(lua_State* L, const char* k, lua_Integer v) {
    lua_pushinteger(L, v);
    lua_setfield(L, -2, k);
}
void set_str(lua_State* L, const char* k, const std::string& v) {
    lua_pushlstring(L, v.data(), v.size());
    lua_setfield(L, -2, k);
}

// doc:packets(opts?) -> list, next | nil, err   (see the API comment)
int doc_packets(lua_State* L) {
    Document* d = check_doc(L, 1);
    const int ot = opts_index(L, 2);
    std::string ftext;
    if (ot) {
        lua_getfield(L, ot, "filter");
        if (!lua_isnil(L, -1)) {
            if (lua_type(L, -1) != LUA_TSTRING) return luaL_error(L, "doc:packets: option 'filter' must be a string");
            ftext = lua_tostring(L, -1);
        }
        lua_pop(L, 1);
    }
    const lua_Integer first = opt_int(L, ot, "first", 1);
    const lua_Integer max = opt_int(L, ot, "max", 10000);
    if (first < 1) return luaL_error(L, "doc:packets: first must be >= 1");
    if (max < 1 || max > kMaxLuaPackets) return luaL_error(L, "doc:packets: max must be 1..1000000");
    PacketFilter f;
    std::string ferr;
    size_t fpos = 0;
    if (!f.parse(ftext, &ferr, &fpos))
        return luaL_error(L, "doc:packets: filter: %s (column %d)", ferr.c_str(), int(fpos + 1));
    std::vector<LuaPacket> out;
    uint64_t next = 0;
    bool not_capture = false, timed_out = false;
    {
        // On a worker so the script time limit can stop a huge capture (the hook cannot interrupt C).
        std::shared_ptr<const Snapshot> snap = d->snapshot();
        std::atomic<bool> cancel{false};
        auto fut = std::async(std::launch::async, [&] {
            collect_packets(*snap, f, uint64_t(first), size_t(max), out, next, not_capture, cancel);
        });
        Impl& im = impl_of(L);
        const auto until = im.deadline_on ? im.deadline : std::chrono::steady_clock::now() + std::chrono::seconds(10);
        timed_out = fut.wait_until(until) != std::future_status::ready;
        if (timed_out) cancel = true;
        fut.get();
    }
    if (timed_out) return luaL_error(L, "doc:packets: time limit reached (page with first / max, or use the Packets panel)");
    if (not_capture) {
        lua_pushnil(L);
        lua_pushstring(L, "not a pcap / pcapng capture");
        return 2;
    }
    lua_createtable(L, int(out.size()), 0);
    for (size_t k = 0; k < out.size(); ++k) {
        const Packet& p = out[k].p;
        const PacketInfo& pi = out[k].pi;
        lua_createtable(L, 0, 24);
        set_int(L, "number", lua_Integer(out[k].number));
        set_int(L, "offset", lua_Integer(p.record_off));
        set_int(L, "data", lua_Integer(p.data_off));
        set_int(L, "length", lua_Integer(p.cap_len));
        set_int(L, "wire_length", lua_Integer(p.orig_len));
        const uint64_t pl = pi.payload_off < p.cap_len ? std::min<uint64_t>(pi.length, p.cap_len - pi.payload_off) : 0;
        set_int(L, "payload", lua_Integer(p.data_off + pi.payload_off));
        set_int(L, "payload_length", lua_Integer(pl));
        if (p.ts_ns != kNoTimestamp) {
            set_int(L, "time_ns", lua_Integer(p.ts_ns));
            lua_pushnumber(L, lua_Number(p.ts_ns) / 1e9);
            lua_setfield(L, -2, "time");
        }
        set_int(L, "interface", lua_Integer(p.iface));
        set_int(L, "linktype", lua_Integer(p.linktype));
        set_str(L, "proto", pi.proto);
        set_str(L, "src", pi.src);
        set_str(L, "dst", pi.dst);
        set_str(L, "info", pi.info);
        set_str(L, "summary", pi.summary);
        if (pi.vlan != 0xFFFF) set_int(L, "vlan", pi.vlan);
        if (pi.ip_version) {
            set_int(L, "ip_version", pi.ip_version);
            set_int(L, "ip_proto", pi.ip_proto);
        }
        if (pi.has_ports) {
            set_int(L, "src_port", pi.src_port);
            set_int(L, "dst_port", pi.dst_port);
        }
        if (pi.tcp_header) {
            set_int(L, "tcp_seq", lua_Integer(pi.tcp_seq));
            set_int(L, "tcp_ack", lua_Integer(pi.tcp_ack));
            set_int(L, "tcp_flags", pi.tcp_flags);
        }
        if (pi.fragment) {
            lua_pushboolean(L, 1);
            lua_setfield(L, -2, "fragment");
        }
        if (pi.malformed) {
            lua_pushboolean(L, 1);
            lua_setfield(L, -2, "malformed");
        }
        lua_rawseti(L, -2, lua_Integer(k + 1));
    }
    if (next) lua_pushinteger(L, lua_Integer(next));
    else lua_pushnil(L);
    return 2;
}

const luaL_Reg kDocMethods[] = {
    {"size", doc_size},       {"name", doc_name},          {"path", doc_path},
    {"id", doc_id},           {"read", doc_read},          {"write", doc_write},
    {"insert", doc_insert},   {"erase", doc_erase},        {"replace", doc_replace},
    {"transaction", doc_transaction},                      {"cursor", doc_cursor},
    {"selection", doc_selection},                          {"select", doc_select},
    {"selections", doc_selections},                        {"select_ranges", doc_select_ranges},
    {"goto", doc_goto},       {"jump", doc_goto},          {"find", doc_find},
    {"hash", doc_hash},       {"target", doc_target},      {"pid", doc_pid},
    {"disasm", doc_disasm},   {"symbols", doc_symbols},
    {"apply_transform", doc_apply_transform},
    {"modules", doc_modules},  {"packets", doc_packets},
    {"view_range", doc_view_range},                        {"bookmarks", doc_bookmarks},
    {"add_bookmark", doc_add_bookmark},                    {"remove_bookmark", doc_remove_bookmark},
    {nullptr, nullptr},
};

// ---- parser context ----------------------------------------------------------------------------------

using EnumList = std::vector<Field::EnumItem>;

struct ParseCtx {
    Document* doc = nullptr;
    ParseResult* out = nullptr;
    // Parse range [base, end) in document offsets (parse at offset). `pos` is absolute; p:tell /
    // p:seek / p:size / p:field offsets are relative to `base`, emitted fields are absolute.
    uint64_t base = 0;
    uint64_t end = UINT64_MAX;
    uint64_t pos = 0;
    bool big_endian = false;
    struct Open {
        int field = -1;
        bool is_array = false;
        int64_t elem = 0;
        bool elem_named = true;  // array: the current element already got its "name[i]"
    };
    std::vector<Open> open;
    int last = -1;                       // last emitted (or closed) field, target of p:note
    std::vector<uint8_t> explicit_color; // per field
    std::unordered_map<const void*, std::shared_ptr<const EnumList>> enums;
    std::unordered_map<const void*, std::shared_ptr<const std::vector<Field::FlagItem>>> flags;
    int ud_ref = LUA_NOREF;              // the `p` userdata (invalidated after the parse)
    int anchor_ref = LUA_NOREF;          // table keeping enum tables alive (stable cache keys)
    int parser_ref = LUA_NOREF;
};

struct ParserUd {
    ParseCtx* ctx;
};

ParseCtx* check_ctx(lua_State* L) {
    auto* ud = static_cast<ParserUd*>(luaL_checkudata(L, 1, kParserMeta));
    if (!ud->ctx) luaL_error(L, "parser context used after its parse finished");
    return ud->ctx;
}

// Absolute end of the parse range (clamped to the document).
uint64_t ctx_end(const ParseCtx* c) { return std::max(c->base, std::min(c->end, c->doc->size())); }
uint64_t ctx_size(const ParseCtx* c) { return ctx_end(c) - c->base; }  // range length
uint64_t ctx_remaining(const ParseCtx* c) {
    uint64_t e = ctx_end(c);
    return c->pos < e ? e - c->pos : 0;
}

// `off` is absolute; false if [off, off+n) leaves the parse range.
bool ctx_read(ParseCtx* c, uint64_t off, uint8_t* dst, size_t n) {
    uint64_t e = ctx_end(c);
    if (off < c->base || off > e || n > e - off) return false;
    return c->doc->read(off, dst, n) == n;
}

int eof_error(lua_State* L, uint64_t off, uint64_t need, uint64_t have) {
    char buf[160];
    std::snprintf(buf, sizeof buf, "read past end of data at 0x%llX (need %llu bytes, %llu left)",
                  (unsigned long long)off, (unsigned long long)need, (unsigned long long)have);
    return luaL_error(L, "%s", buf);
}

struct Opts {
    bool has_color = false;
    uint32_t color = 0;
    const char* comment = nullptr;  // kept alive on the Lua stack
    const char* fmt = "";           // "", "hex", "dec", "bin", "char" (static strings)
    int enum_idx = 0;               // absolute stack index of the enum table (0 = none)
    int flags_idx = 0;              // absolute stack index of the flags table (0 = none)
    Field::BitField bits;           // opts.bitfield
};

// opts.bitfield = {shift=, width=, be=?, signed=?} at `idx` (a table).
void read_bitfield(lua_State* L, int idx, Field::BitField& b) {
    luaL_checktype(L, idx, LUA_TTABLE);
    lua_getfield(L, idx, "shift");
    lua_getfield(L, idx, "width");
    lua_getfield(L, idx, "be");
    lua_getfield(L, idx, "signed");
    const lua_Integer shift = luaL_checkinteger(L, -4), width = luaL_checkinteger(L, -3);
    if (shift < 0 || width < 1 || shift + width > 64) luaL_error(L, "opts.bitfield: need 0 <= shift, 1 <= width, shift + width <= 64");
    b.shift = int(shift);
    b.width = int(width);
    b.big_endian = lua_toboolean(L, -2) != 0;
    b.is_signed = lua_toboolean(L, -1) != 0;
    lua_pop(L, 4);
}

// Reads the opts table at `idx`. Leaves comment/enum values on the stack (they must stay alive).
void read_opts(lua_State* L, int idx, Opts& o) {
    if (lua_isnoneornil(L, idx)) return;
    luaL_checktype(L, idx, LUA_TTABLE);
    idx = lua_absindex(L, idx);
    lua_getfield(L, idx, "color");
    if (!lua_isnil(L, -1)) {
        if (!to_color(L, -1, o.color)) luaL_error(L, "invalid color (use a name, \"#rrggbb\" or 0xRRGGBB)");
        o.has_color = true;
    }
    lua_pop(L, 1);
    lua_getfield(L, idx, "fmt");
    if (!lua_isnil(L, -1)) {
        const char* f = luaL_checkstring(L, -1);
        static const char* kFmts[] = {"hex", "dec", "bin", "char"};
        o.fmt = nullptr;
        for (const char* k : kFmts)
            if (std::strcmp(f, k) == 0) o.fmt = k;
        if (!o.fmt) luaL_error(L, "invalid fmt '%s' (hex, dec, bin or char)", f);
    }
    lua_pop(L, 1);
    lua_getfield(L, idx, "comment");
    if (lua_isnil(L, -1)) lua_pop(L, 1);
    else o.comment = luaL_checkstring(L, -1);
    lua_getfield(L, idx, "enum");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
    } else {
        luaL_checktype(L, -1, LUA_TTABLE);
        o.enum_idx = lua_gettop(L);
    }
    lua_getfield(L, idx, "flags");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
    } else {
        luaL_checktype(L, -1, LUA_TTABLE);
        o.flags_idx = lua_gettop(L);
    }
    lua_getfield(L, idx, "bitfield");
    if (!lua_isnil(L, -1)) read_bitfield(L, lua_gettop(L), o.bits);
    lua_pop(L, 1);
}

// Appends a field under the innermost open struct/array and returns its index. Raises the
// field-limit error (callers hold no C++ temporaries when calling this).
int emit(lua_State* L, ParseCtx* c, const char* name, const char* type, uint64_t off,
         uint64_t size, const Opts& o) {
    auto& F = c->out->fields;
    if (F.size() >= kMaxFields) {
        c->out->truncated = true;
        luaL_error(L, "field limit reached (%d fields); the tree is truncated", int(kMaxFields));
    }
    int idx = int(F.size());
    int parent = c->open.empty() ? -1 : c->open.back().field;
    F.emplace_back();
    Field& f = F.back();
    if (parent >= 0 && c->open.back().is_array && !c->open.back().elem_named) {
        f.name = F[parent].name + "[" + std::to_string(c->open.back().elem) + "]";
        c->open.back().elem_named = true;
    } else {
        f.name = name;
    }
    f.type = type;
    f.offset = off;
    f.size = size;
    f.parent = parent;
    f.depth = parent >= 0 ? F[parent].depth + 1 : 0;
    if (o.comment) f.comment = o.comment;
    f.bits = o.bits;
    f.fmt = o.fmt ? o.fmt : "";
    f.color = o.color;
    c->explicit_color.push_back(o.has_color ? 1 : 0);
    if (parent >= 0) F[parent].children.push_back(idx);
    c->last = idx;
    const Impl& im = impl_of(L);
    if (im.progress_fields) im.progress_fields->store(F.size(), std::memory_order_relaxed);
    if (im.progress_offset) im.progress_offset->store(off + size, std::memory_order_relaxed);
    return idx;
}

// Enum table -> shared sorted list (cached per table for the whole parse).
std::shared_ptr<const EnumList> get_enum(lua_State* L, ParseCtx* c, int tbl) {
    const void* key = lua_topointer(L, tbl);
    auto it = c->enums.find(key);
    if (it != c->enums.end()) return it->second;
    auto list = std::make_shared<EnumList>();
    lua_pushnil(L);
    while (lua_next(L, tbl)) {
        // value at -1, key at -2. Accept [number] = "NAME" and NAME = number.
        int kt = lua_type(L, -2), vt = lua_type(L, -1);
        if (kt == LUA_TNUMBER && lua_isinteger(L, -2) && vt == LUA_TSTRING)
            list->push_back({lua_tointeger(L, -2), lua_tostring(L, -1)});
        else if (kt == LUA_TSTRING && vt == LUA_TNUMBER && lua_isinteger(L, -1))
            list->push_back({lua_tointeger(L, -1), lua_tostring(L, -2)});
        lua_pop(L, 1);
    }
    std::sort(list->begin(), list->end(),
              [](const Field::EnumItem& a, const Field::EnumItem& b) { return a.value < b.value; });
    // Anchor the table so its address cannot be reused by another table during this parse.
    lua_rawgeti(L, LUA_REGISTRYINDEX, c->anchor_ref);
    lua_pushvalue(L, tbl);
    lua_pushboolean(L, 1);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    c->enums.emplace(key, list);
    return list;
}

// Flags table ({[0] = "READ"} or {READ = 0}) -> shared list sorted by bit (cached like enums).
std::shared_ptr<const std::vector<Field::FlagItem>> get_flags(lua_State* L, ParseCtx* c, int tbl) {
    const void* key = lua_topointer(L, tbl);
    auto it = c->flags.find(key);
    if (it != c->flags.end()) return it->second;
    auto list = std::make_shared<std::vector<Field::FlagItem>>();
    lua_pushnil(L);
    while (lua_next(L, tbl)) {
        int kt = lua_type(L, -2), vt = lua_type(L, -1);
        lua_Integer bit = -1;
        const char* name = nullptr;
        if (kt == LUA_TNUMBER && lua_isinteger(L, -2) && vt == LUA_TSTRING) {
            bit = lua_tointeger(L, -2);
            name = lua_tostring(L, -1);
        } else if (kt == LUA_TSTRING && vt == LUA_TNUMBER && lua_isinteger(L, -1)) {
            bit = lua_tointeger(L, -1);
            name = lua_tostring(L, -2);
        }
        if (!name || bit < 0 || bit > 63) {
            luaL_error(L, "opts.flags: use {[bit] = \"NAME\"} with bit numbers 0..63");
        }
        list->push_back({int(bit), name});
        lua_pop(L, 1);
    }
    std::sort(list->begin(), list->end(),
              [](const Field::FlagItem& a, const Field::FlagItem& b) { return a.bit < b.bit; });
    lua_rawgeti(L, LUA_REGISTRYINDEX, c->anchor_ref);
    lua_pushvalue(L, tbl);
    lua_pushboolean(L, 1);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    c->flags.emplace(key, list);
    return list;
}

const char* enum_name(const EnumList& list, int64_t v) {
    auto it = std::lower_bound(list.begin(), list.end(), v,
                               [](const Field::EnumItem& e, int64_t x) { return e.value < x; });
    return (it != list.end() && it->value == v) ? it->name.c_str() : nullptr;
}

// Sets the display text of an integer field (enum-aware).
void set_int_value(lua_State* L, ParseCtx* c, Field& f, int64_t v, bool is_unsigned, int size, const Opts& o) {
    if (o.enum_idx) {
        f.enums = get_enum(L, c, o.enum_idx);
        const char* name = enum_name(*f.enums, v);
        f.value = (is_unsigned ? std::to_string(uint64_t(v)) : std::to_string(v)) + " = " + (name ? name : "?");
    } else {
        f.value = format_int(v, is_unsigned, size, o.fmt);
        if (o.flags_idx) {
            f.flags = get_flags(L, c, o.flags_idx);
            const std::string names = format_flags(uint64_t(v), size, *f.flags);
            if (!names.empty()) f.value += " = " + names;
        }
    }
}

int p_typed(lua_State* L) {
    const NumType& t = kNumTypes[lua_tointeger(L, lua_upvalueindex(1))];
    ParseCtx* c = check_ctx(L);
    const char* name = luaL_checkstring(L, 2);
    Opts o;
    read_opts(L, 3, o);
    bool be = t.endian ? t.endian == 'b' : c->big_endian;
    uint8_t b[8];
    if (!ctx_read(c, c->pos, b, t.size)) return eof_error(L, c->pos, t.size, ctx_remaining(c));
    NumValue v = decode_num(t, b, be);
    int idx = emit(L, c, name, t.base, c->pos, t.size, o);
    {
        Field& f = c->out->fields[idx];
        f.type = num_type_name(t, be);
        f.pack = num_pack(t, be);
        if (v.is_float) f.value = format_float(v.f, t.size == 4);
        else set_int_value(L, c, f, v.i, !t.is_signed, t.size, o);
    }
    c->pos += t.size;
    push_num(L, v);
    return 1;
}

// Pushes `n` bytes at `off` as a Lua string (caller checked the range).
void push_bytes(lua_State* L, ParseCtx* c, uint64_t off, size_t n) {
    luaL_Buffer b;
    char* p = luaL_buffinitsize(L, &b, n);
    size_t got = c->doc->read(off, reinterpret_cast<uint8_t*>(p), n);
    luaL_pushresultsize(&b, got);
}

int p_bytes(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    const char* name = luaL_checkstring(L, 2);
    uint64_t n = check_u64(L, 3);
    Opts o;
    read_opts(L, 4, o);
    if (n > ctx_remaining(c)) return eof_error(L, c->pos, n, ctx_remaining(c));
    uint8_t head[16];
    size_t hn = size_t(std::min<uint64_t>(n, 16));
    c->doc->read(c->pos, head, hn);
    int idx = emit(L, c, name, "bytes", c->pos, n, o);
    c->out->fields[idx].value = hex_spaced(head, hn) + (n > 16 ? std::string(" ") + kEllipsis : std::string());
    uint64_t at = c->pos;
    c->pos += n;
    if (n <= kSmall) push_bytes(L, c, at, size_t(n));
    else lua_pushnil(L);
    return 1;
}

int p_str(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    const char* name = luaL_checkstring(L, 2);
    uint64_t n = check_u64(L, 3);
    Opts o;
    read_opts(L, 4, o);
    if (n > kMaxStr) return luaL_error(L, "p:str: string too long (max 16 MiB)");
    if (n > ctx_remaining(c)) return eof_error(L, c->pos, n, ctx_remaining(c));
    push_bytes(L, c, c->pos, size_t(n));
    int sidx = lua_gettop(L);
    int idx = emit(L, c, name, "str", c->pos, n, o);
    {
        size_t len;
        const char* s = lua_tolstring(L, sidx, &len);
        c->out->fields[idx].value = escape_quoted(s, len, 64);
    }
    c->pos += n;
    return 1;
}

int p_cstr(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    const char* name = luaL_checkstring(L, 2);
    Opts o;
    read_opts(L, 3, o);
    uint64_t rem = ctx_remaining(c);
    uint64_t limit = std::min<uint64_t>(rem, kSmall + 1);
    uint8_t chunk[4096];
    uint64_t len = 0;
    bool found = false;
    while (len < limit && !found) {
        size_t n = size_t(std::min<uint64_t>(sizeof chunk, limit - len));
        if (c->doc->read(c->pos + len, chunk, n) != n) break;
        const void* z = std::memchr(chunk, 0, n);
        if (z) {
            len += uint64_t(static_cast<const uint8_t*>(z) - chunk);
            found = true;
        } else {
            len += n;
        }
    }
    if (!found) {
        if (len > kSmall) {
            char buf[96];
            std::snprintf(buf, sizeof buf, "p:cstr: no NUL within 64 KiB at 0x%llX", (unsigned long long)c->pos);
            return luaL_error(L, "%s", buf);
        }
        return eof_error(L, c->pos, len + 1, rem);
    }
    push_bytes(L, c, c->pos, size_t(len));
    int sidx = lua_gettop(L);
    int idx = emit(L, c, name, "cstr", c->pos, len + 1, o);
    {
        size_t sl;
        const char* s = lua_tolstring(L, sidx, &sl);
        c->out->fields[idx].value = escape_quoted(s, sl, 64);
    }
    c->pos += len + 1;
    return 1;
}

int p_leb(lua_State* L, bool is_signed) {
    ParseCtx* c = check_ctx(L);
    const char* name = luaL_checkstring(L, 2);
    Opts o;
    read_opts(L, 3, o);
    uint64_t v = 0;
    int shift = 0;
    uint64_t n = 0;
    uint8_t byte = 0x80;
    while (byte & 0x80) {
        if (n == 10) return luaL_error(L, "LEB128 value longer than 10 bytes");
        if (!ctx_read(c, c->pos + n, &byte, 1)) return eof_error(L, c->pos + n, 1, 0);
        if (shift < 64) v |= uint64_t(byte & 0x7F) << shift;
        shift += 7;
        ++n;
    }
    if (is_signed && shift < 64 && (byte & 0x40)) v |= ~0ull << shift;
    int idx = emit(L, c, name, is_signed ? "sleb128" : "uleb128", c->pos, n, o);
    set_int_value(L, c, c->out->fields[idx], int64_t(v), !is_signed, 8, o);
    c->pos += n;
    lua_pushinteger(L, lua_Integer(v));
    return 1;
}
int p_uleb(lua_State* L) { return p_leb(L, false); }
int p_sleb(lua_State* L) { return p_leb(L, true); }

// Calls string.unpack(fmt, data) on bytes at the cursor. On success pushes the unpacked values and
// returns {count, bytes consumed}; raises on short data / bad formats.
struct Unpacked {
    int count;
    uint64_t consumed;
};
Unpacked unpack_at(lua_State* L, ParseCtx* c, int fmt_idx, const char* who) {
    Impl& im = impl_of(L);
    const char* fmt = lua_tostring(L, fmt_idx);
    uint64_t rem = ctx_remaining(c);
    // Fixed-size formats: exact size via string.packsize. Variable ones (s4, z, ...) get a 64 KiB
    // window first and, if their value is longer, one retry with up to kMaxStr bytes.
    lua_rawgeti(L, LUA_REGISTRYINDEX, im.ref_packsize);
    lua_pushvalue(L, fmt_idx);
    uint64_t need;
    bool fixed = lua_pcall(L, 1, 1, 0) == LUA_OK;
    if (fixed) need = uint64_t(lua_tointeger(L, -1));
    else need = std::min<uint64_t>(rem, kSmall);
    lua_pop(L, 1);
    if (need > rem) eof_error(L, c->pos, need, rem);
    for (;;) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, im.ref_unpack);
        lua_pushvalue(L, fmt_idx);
        push_bytes(L, c, c->pos, size_t(need));
        int base = lua_gettop(L) - 3;
        if (lua_pcall(L, 2, LUA_MULTRET, 0) == LUA_OK) {
            int n = lua_gettop(L) - base;  // values + next position
            Unpacked u{n - 1, uint64_t(lua_tointeger(L, -1) - 1)};
            lua_pop(L, 1);
            return u;
        }
        const char* msg = lua_tostring(L, -1);
        bool short_data = !fixed && msg && (std::strstr(msg, "too short") || std::strstr(msg, "unfinished string"));
        if (short_data && need < rem && need < kMaxStr) {  // the window was too small: widen it once
            lua_pop(L, 1);
            need = std::min<uint64_t>(rem, kMaxStr);
            continue;
        }
        if (short_data && need < rem)
            luaL_error(L, "%s('%s'): variable-length value larger than 16 MiB (use p:str / p:bytes)", who, fmt);
        if (short_data) eof_error(L, c->pos, need + 1, rem);
        luaL_error(L, "%s('%s'): %s", who, fmt, msg ? msg : "error");
    }
}

int p_read(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    luaL_checkstring(L, 2);
    const char* name = luaL_checkstring(L, 3);
    Opts o;
    read_opts(L, 4, o);
    Unpacked u = unpack_at(L, c, 2, "p:read");
    int first = lua_gettop(L) - u.count + 1;
    int idx = emit(L, c, name, "", c->pos, u.consumed, o);
    {
        Field& f = c->out->fields[idx];
        f.type = lua_tostring(L, 2);
        PackInfo pi;
        bool single = parse_pack_format(f.type, pi);
        for (int i = 0; i < u.count; ++i) {
            int vi = first + i;
            if (i) f.value += ", ";
            if (lua_type(L, vi) == LUA_TNUMBER && lua_isinteger(L, vi)) {
                if (u.count == 1) {
                    set_int_value(L, c, f, lua_tointeger(L, vi), single && !pi.is_signed, single ? pi.size : 8, o);
                } else {
                    f.value += format_int(lua_tointeger(L, vi), false, 8, o.fmt);
                }
            } else if (lua_type(L, vi) == LUA_TNUMBER) {
                f.value += format_float(lua_tonumber(L, vi), single && pi.size == 4);
            } else {
                size_t sl;
                const char* s = lua_tolstring(L, vi, &sl);
                f.value += escape_quoted(s, sl, 64);
            }
        }
        if (u.count == 1 && single && lua_type(L, first) == LUA_TNUMBER) f.pack = f.type;
    }
    c->pos += u.consumed;
    return u.count;
}

int p_peek(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    luaL_checkstring(L, 2);
    return unpack_at(L, c, 2, "p:peek").count;
}

int p_peekbytes(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    uint64_t n = std::min(check_u64(L, 2), std::min(ctx_remaining(c), kMaxRead));
    push_bytes(L, c, c->pos, size_t(n));
    return 1;
}

void close_open(ParseCtx* c) {
    ParseCtx::Open o = c->open.back();
    c->open.pop_back();
    auto& F = c->out->fields;
    Field& f = F[o.field];
    uint64_t end = std::max(c->pos, f.offset);
    for (int ch : f.children) end = std::max(end, F[ch].offset + F[ch].size);
    f.size = end - f.offset;
    c->last = o.field;
}

int p_struct(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    const char* name = luaL_checkstring(L, 2);
    luaL_checktype(L, 3, LUA_TFUNCTION);
    Opts o;
    read_opts(L, 4, o);
    int idx = emit(L, c, name, "struct", c->pos, 0, o);
    c->open.push_back({idx, false, 0, true});
    lua_pushcfunction(L, inner_msgh);
    int base = lua_gettop(L);
    lua_pushvalue(L, 3);
    lua_pushvalue(L, 1);
    int st = lua_pcall(L, 1, LUA_MULTRET, base);
    close_open(c);
    if (st != LUA_OK) return lua_error(L);
    return lua_gettop(L) - base;
}

int p_array(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    const char* name = luaL_checkstring(L, 2);
    uint64_t count = check_u64(L, 3);
    luaL_checktype(L, 4, LUA_TFUNCTION);
    Opts o;
    read_opts(L, 5, o);
    int idx = emit(L, c, name, "array", c->pos, 0, o);
    c->out->fields[idx].value = "[" + std::to_string(count) + "]";
    c->open.push_back({idx, true, 0, true});
    lua_createtable(L, int(std::min<uint64_t>(count, 1 << 16)), 0);
    int results = lua_gettop(L);
    lua_pushcfunction(L, inner_msgh);
    int msgh = lua_gettop(L);
    for (uint64_t i = 0; i < count; ++i) {
        c->open.back().elem = int64_t(i);
        c->open.back().elem_named = false;
        lua_pushvalue(L, 4);
        lua_pushinteger(L, lua_Integer(i));
        if (lua_pcall(L, 1, 1, msgh) != LUA_OK) {
            close_open(c);
            return lua_error(L);
        }
        lua_rawseti(L, results, lua_Integer(i + 1));
    }
    close_open(c);
    lua_settop(L, results);
    return 1;
}

int p_field(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    const char* name = luaL_checkstring(L, 2);
    uint64_t off = check_u64(L, 3);
    uint64_t size = check_u64(L, 4);
    const char* text = luaL_optstring(L, 5, "");
    Opts o;
    read_opts(L, 6, o);
    uint64_t total = ctx_size(c);
    if (off > total || size > total - off) return luaL_error(L, "p:field: range is beyond the end of the data");
    int idx = emit(L, c, name, "custom", c->base + off, size, o);
    c->out->fields[idx].value = text;
    return 0;
}

int p_label(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    const char* text = luaL_checkstring(L, 2);
    if (!c->open.empty()) c->out->fields[c->open.back().field].value = text;
    return 0;
}

int p_note(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    const char* text = luaL_checkstring(L, 2);
    if (c->last >= 0) {
        std::string& cm = c->out->fields[c->last].comment;
        if (!cm.empty()) cm += "; ";
        cm += text;
    }
    return 0;
}

int p_tell(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    lua_pushinteger(L, lua_Integer(c->pos - c->base));
    return 1;
}

int seek_to(lua_State* L, ParseCtx* c, int64_t target) {
    uint64_t size = ctx_size(c);
    if (target < 0 || uint64_t(target) > size) {
        char buf[128];
        std::snprintf(buf, sizeof buf, "seek out of range: %lld (data size 0x%llX)", (long long)target,
                      (unsigned long long)size);
        return luaL_error(L, "%s", buf);
    }
    c->pos = c->base + uint64_t(target);
    return 0;
}

int p_seek(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    return seek_to(L, c, luaL_checkinteger(L, 2));
}

int p_skip(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    return seek_to(L, c, int64_t(c->pos - c->base) + luaL_checkinteger(L, 2));
}

int p_base(lua_State* L) {
    lua_pushinteger(L, lua_Integer(check_ctx(L)->base));
    return 1;
}

int p_size(lua_State* L) {
    lua_pushinteger(L, lua_Integer(ctx_size(check_ctx(L))));
    return 1;
}

int p_remaining(lua_State* L) {
    lua_pushinteger(L, lua_Integer(ctx_remaining(check_ctx(L))));
    return 1;
}

int p_eof(lua_State* L) {
    lua_pushboolean(L, ctx_remaining(check_ctx(L)) == 0);
    return 1;
}

int p_endian(lua_State* L) {
    ParseCtx* c = check_ctx(L);
    if (!lua_isnoneornil(L, 2)) {
        const char* e = luaL_checkstring(L, 2);
        if (!std::strcmp(e, "le") || !std::strcmp(e, "little")) c->big_endian = false;
        else if (!std::strcmp(e, "be") || !std::strcmp(e, "big")) c->big_endian = true;
        else return luaL_error(L, "p:endian: expected \"le\" or \"be\", got \"%s\"", e);
    }
    lua_pushstring(L, c->big_endian ? "be" : "le");
    return 1;
}

int p_tostring(lua_State* L) {
    auto* ud = static_cast<ParserUd*>(luaL_checkudata(L, 1, kParserMeta));
    if (ud->ctx) lua_pushfstring(L, "Parser@%I", lua_Integer(ud->ctx->pos - ud->ctx->base));
    else lua_pushliteral(L, "Parser (finished)");
    return 1;
}

const luaL_Reg kParserMethods[] = {
    {"tell", p_tell},       {"seek", p_seek},     {"skip", p_skip},     {"size", p_size},
    {"remaining", p_remaining},                   {"eof", p_eof},       {"endian", p_endian},
    {"read", p_read},       {"bytes", p_bytes},   {"str", p_str},       {"cstr", p_cstr},
    {"uleb", p_uleb},       {"sleb", p_sleb},     {"struct", p_struct}, {"array", p_array},
    {"field", p_field},     {"label", p_label},   {"note", p_note},     {"peek", p_peek},
    {"peekbytes", p_peekbytes},                   {"base", p_base},
    {nullptr, nullptr},
};

// Protected body of run_parse: builds `p`, calls spec.parse(p, doc).
int parse_main(lua_State* L) {
    auto* c = static_cast<ParseCtx*>(lua_touserdata(L, 1));
    lua_newtable(L);
    c->anchor_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    auto* ud = static_cast<ParserUd*>(lua_newuserdatauv(L, sizeof(ParserUd), 0));
    ud->ctx = c;
    luaL_setmetatable(L, kParserMeta);
    int p = lua_gettop(L);
    lua_pushvalue(L, p);
    c->ud_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_rawgeti(L, LUA_REGISTRYINDEX, c->parser_ref);
    lua_getfield(L, -1, "parse");
    if (!lua_isfunction(L, -1)) return luaL_error(L, "parser has no parse function");
    lua_pushvalue(L, p);
    push_doc(L, c->doc->id());
    lua_call(L, 2, 0);
    return 0;
}

// ---- inspect -------------------------------------------------------------------------------------

std::string number_text(lua_State* L, int idx) {
    if (lua_isinteger(L, idx)) return std::to_string(lua_tointeger(L, idx));
    double d = lua_tonumber(L, idx);
    if (std::isnan(d)) return "nan";
    if (std::isinf(d)) return d > 0 ? "inf" : "-inf";
    char buf[64];
    std::snprintf(buf, sizeof buf, "%.14g", d);
    if (!std::strpbrk(buf, ".eEn")) std::strcat(buf, ".0");
    return buf;
}

bool is_identifier(const std::string& s) {
    static const char* kReserved[] = {"and", "break", "do", "else", "elseif", "end", "false", "for",
                                      "function", "global", "goto", "if", "in", "local", "nil", "not",
                                      "or", "repeat", "return", "then", "true", "until", "while"};
    if (s.empty() || std::isdigit((unsigned char)s[0])) return false;
    for (char ch : s)
        if (!(std::isalnum((unsigned char)ch) || ch == '_')) return false;
    for (const char* r : kReserved)
        if (s == r) return false;
    return true;
}

struct Inspector {
    lua_State* L;
    int max_depth;
    std::vector<const void*> path;
    size_t budget = 1u << 20;  // total key + scalar text; shared subtables can blow up exponentially
    static constexpr size_t kMaxEntries = 500;
    static constexpr int kMaxDepth = 64;  // the dump recurses in C++

    void charge(size_t n) { budget -= std::min(budget, n); }

    struct Entry {
        int rank = 0;           // 0 integer key, 1 float key, 2 string key, 3 other
        lua_Integer ik = 0;
        double nk = 0;
        std::string sk;
        std::string key, val;
    };

    std::string value(int idx, int depth, int indent) {
        idx = lua_absindex(L, idx);
        switch (lua_type(L, idx)) {
        case LUA_TNIL: return "nil";
        case LUA_TBOOLEAN: return lua_toboolean(L, idx) ? "true" : "false";
        case LUA_TNUMBER: return number_text(L, idx);
        case LUA_TSTRING: {
            size_t n;
            const char* s = lua_tolstring(L, idx, &n);
            std::string q = escape_quoted(s, n, 1024);
            if (n > 1024) q += " (" + std::to_string(n) + " bytes)";
            return q;
        }
        case LUA_TTABLE: return table(idx, depth, indent);
        case LUA_TUSERDATA:
            if (auto* d = static_cast<DocUd*>(luaL_testudata(L, idx, kDocMeta))) {
                ScriptHost* host = impl_of(L).eng.host();
                Document* doc = host ? host->find_document(d->id) : nullptr;
                if (!doc) return "Doc#" + std::to_string(d->id) + " (closed)";
                std::string name = doc->display_name();
                return "Doc#" + std::to_string(d->id) + " " + escape_quoted(name.data(), name.size(), 200);
            }
            [[fallthrough]];
        default: {
            char buf[64];
            std::snprintf(buf, sizeof buf, "%s: %p", lua_typename(L, lua_type(L, idx)), lua_topointer(L, idx));
            return buf;
        }
        }
    }

    std::string table(int t, int depth, int indent) {
        const void* p = lua_topointer(L, t);
        if (std::find(path.begin(), path.end(), p) != path.end()) return "<cycle>";
        if (depth >= max_depth || depth >= kMaxDepth || !budget || !lua_checkstack(L, 6)) return "{...}";
        path.push_back(p);
        std::vector<Entry> es;
        size_t total = 0;
        lua_pushnil(L);
        while (lua_next(L, t)) {
            ++total;
            if (es.size() < kMaxEntries && budget) {
                Entry e;
                int kt = lua_type(L, -2);
                if (kt == LUA_TNUMBER && lua_isinteger(L, -2)) {
                    e.rank = 0;
                    e.ik = lua_tointeger(L, -2);
                    e.key = "[" + std::to_string(e.ik) + "]";
                } else if (kt == LUA_TNUMBER) {
                    e.rank = 1;
                    e.nk = lua_tonumber(L, -2);
                    e.key = "[" + number_text(L, -2) + "]";
                } else if (kt == LUA_TSTRING) {
                    e.rank = 2;
                    size_t n;
                    const char* s = lua_tolstring(L, -2, &n);
                    e.sk.assign(s, n);
                    e.key = is_identifier(e.sk) ? e.sk : "[" + escape_quoted(s, n, 200) + "]";
                } else {
                    e.rank = 3;
                    e.key = "[" + value(lua_gettop(L) - 1, depth + 1, indent + 1) + "]";
                    e.sk = e.key;
                }
                e.val = value(lua_gettop(L), depth + 1, indent + 1);
                charge(e.key.size() + 4 + (lua_type(L, -1) == LUA_TTABLE ? 0 : e.val.size()));
                es.push_back(std::move(e));
            }
            lua_pop(L, 1);
        }
        path.pop_back();
        if (es.empty()) return "{}";
        std::sort(es.begin(), es.end(), [](const Entry& a, const Entry& b) {
            if (a.rank != b.rank) return a.rank < b.rank;
            if (a.rank == 0) return a.ik < b.ik;
            if (a.rank == 1) return a.nk < b.nk;
            return a.sk < b.sk;
        });
        bool is_array = es.size() == total;
        for (size_t i = 0; is_array && i < es.size(); ++i)
            is_array = es[i].rank == 0 && es[i].ik == lua_Integer(i + 1);
        size_t len = 0;
        bool multiline = false;
        for (const Entry& e : es) {
            len += e.val.size() + (is_array ? 2 : e.key.size() + 5);
            if (e.val.find('\n') != std::string::npos) multiline = true;
        }
        if (len + size_t(indent) * 2 > 76 || total > es.size()) multiline = true;
        std::string out;
        if (!multiline) {
            out = "{ ";
            for (size_t i = 0; i < es.size(); ++i) {
                if (i) out += ", ";
                out += is_array ? es[i].val : es[i].key + " = " + es[i].val;
            }
            return out + " }";
        }
        std::string pad(size_t(indent + 1) * 2, ' ');
        out = "{\n";
        for (const Entry& e : es) out += pad + (is_array ? e.val : e.key + " = " + e.val) + ",\n";
        if (total > es.size()) out += pad + "-- " + std::to_string(total - es.size()) + " more entries\n";
        return out + std::string(size_t(indent) * 2, ' ') + "}";
    }
};

// ---- hx.* functions ---------------------------------------------------------------------------------

// Concatenates all arguments like print (tables pretty-printed) and logs them.
int log_args(lua_State* L, ConsoleLine::Kind kind) {
    int n = lua_gettop(L);
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    for (int i = 1; i <= n; ++i) {
        if (i > 1) luaL_addchar(&b, '\t');
        if (lua_type(L, i) == LUA_TTABLE) {
            {
                std::string s = lua_inspect(L, i);
                lua_pushlstring(L, s.data(), s.size());
            }
            luaL_addvalue(&b);
        } else {
            luaL_tolstring(L, i, nullptr);
            luaL_addvalue(&b);
        }
    }
    luaL_pushresult(&b);
    size_t len;
    const char* s = lua_tolstring(L, -1, &len);
    impl_of(L).eng.log(kind, std::string(s, len));
    return 0;
}
int l_print(lua_State* L) { return log_args(L, ConsoleLine::Info); }
int l_warn(lua_State* L) { return log_args(L, ConsoleLine::Warn); }
int l_error(lua_State* L) { return log_args(L, ConsoleLine::Error); }

int l_no_exit(lua_State* L) { return luaL_error(L, "os.exit is disabled inside Hexer"); }
int l_no_stdin(lua_State* L) { return luaL_error(L, "io.read: there is no stdin inside Hexer (use io.open)"); }

int l_inspect(lua_State* L) {
    luaL_checkany(L, 1);
    lua_Integer depth = luaL_optinteger(L, 2, 6);
    depth = std::clamp<lua_Integer>(depth, 1, Inspector::kMaxDepth);
    {
        std::string s = lua_inspect(L, 1, int(depth));
        lua_pushlstring(L, s.data(), s.size());
    }
    return 1;
}

int l_clear_console(lua_State* L) {
    impl_of(L).eng.clear_console();
    return 0;
}

std::string opt_field_string(lua_State* L, int tbl, const char* key) {
    std::string s;
    if (raw_field(L, tbl, key) == LUA_TSTRING) s = lua_tostring(L, -1);
    lua_pop(L, 1);
    return s;
}

int l_parser(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    if (lua_getfield(L, 1, "name") != LUA_TSTRING) return luaL_error(L, "hx.parser: 'name' (string) is required");
    if (lua_getfield(L, 1, "parse") != LUA_TFUNCTION) return luaL_error(L, "hx.parser: 'parse' (function) is required");
    int dt = lua_getfield(L, 1, "detect");
    if (dt != LUA_TNIL && dt != LUA_TFUNCTION) return luaL_error(L, "hx.parser: 'detect' must be a function");
    int et = lua_getfield(L, 1, "extensions");
    if (et != LUA_TNIL && et != LUA_TTABLE) return luaL_error(L, "hx.parser: 'extensions' must be a table of strings");
    lua_settop(L, 1);
    Impl& im = impl_of(L);
    lua_pushvalue(L, 1);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    {
        ParserInfo info;
        info.name = opt_field_string(L, 1, "name");
        info.file = im.loading_file.empty() ? "<console>" : im.loading_file;
        if (et == LUA_TTABLE) {
            raw_field(L, 1, "extensions");
            lua_Integer n = lua_Integer(lua_rawlen(L, -1));
            for (lua_Integer i = 1; i <= n; ++i) {
                if (lua_rawgeti(L, -1, i) == LUA_TSTRING) {
                    std::string e = lua_tostring(L, -1);
                    if (!e.empty() && e[0] == '.') e.erase(0, 1);
                    for (char& ch : e) ch = char(std::tolower((unsigned char)ch));
                    info.extensions.push_back(e);
                }
                lua_pop(L, 1);
            }
            lua_pop(L, 1);
        }
        im.register_parser(std::move(info), ref);
    }
    return 0;
}

int l_command(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    if (lua_getfield(L, 1, "name") != LUA_TSTRING) return luaL_error(L, "hx.command: 'name' (string) is required");
    if (lua_getfield(L, 1, "run") != LUA_TFUNCTION) return luaL_error(L, "hx.command: 'run' (function) is required");
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);  // pops run
    lua_settop(L, 1);
    Impl& im = impl_of(L);
    {
        ScriptCommand cmd;
        cmd.name = opt_field_string(L, 1, "name");
        cmd.description = opt_field_string(L, 1, "description");
        cmd.file = im.loading_file.empty() ? "<console>" : im.loading_file;
        im.register_command(std::move(cmd), ref);
    }
    return 0;
}

int l_doc(lua_State* L) {
    ScriptHost* host = impl_of(L).eng.host();
    Document* d = host ? host->active_document() : nullptr;
    if (d) push_doc(L, d->id());
    else lua_pushnil(L);
    return 1;
}

int l_new_doc(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    size_t n;
    const char* bytes = luaL_optlstring(L, 2, "", &n);
    ScriptHost* host = impl_of(L).eng.host();
    Document* d = nullptr;
    if (host) {
        std::string nm = name;
        d = host->open_bytes(nm, reinterpret_cast<const uint8_t*>(bytes), n);
    }
    if (!d) return luaL_error(L, "hx.new_doc: could not open a new document");
    push_doc(L, d->id());
    return 1;
}

// hx.open_process(pid, {writable=false}?) -> doc | nil, err
int l_open_process(lua_State* L) {
    const lua_Integer pid = luaL_checkinteger(L, 1);
    luaL_argcheck(L, pid > 0 && pid <= lua_Integer(UINT32_MAX), 1, "not a process id");
    bool writable = false;
    if (!lua_isnoneornil(L, 2)) {
        luaL_checktype(L, 2, LUA_TTABLE);
        lua_getfield(L, 2, "writable");
        writable = lua_toboolean(L, -1) != 0;
        lua_pop(L, 1);
    }
    ScriptHost* host = impl_of(L).eng.host();
    std::string err = "no host";
    Document* d = host ? host->open_process(uint32_t(pid), writable, &err) : nullptr;
    if (!d) {
        lua_pushnil(L);
        lua_pushstring(L, err.c_str());
        return 2;
    }
    push_doc(L, d->id());
    return 1;
}

int l_highlight(lua_State* L) {
    Document* d = check_doc(L, 1);
    uint64_t off = check_u64(L, 2);
    uint64_t len = check_u64(L, 3);
    uint32_t color = 0;
    bool auto_color = lua_isnoneornil(L, 4);
    if (!auto_color && !to_color(L, 4, color)) return luaL_error(L, "hx.highlight: invalid color");
    const char* label = luaL_optstring(L, 5, "");
    Impl& im = impl_of(L);
    HighlightSet& set = im.script_hl(d->id());
    if (set.items.size() >= kMaxScriptHighlights) return luaL_error(L, "hx.highlight: too many highlights (max 1,000,000 per document)");
    Highlight h;
    h.offset = off;
    h.length = len;
    h.color = auto_color ? field_palette(int(set.items.size())) : color;
    h.label = label;
    set.add(std::move(h));
    return 0;
}

int l_clear_highlights(lua_State* L) {
    auto* ud = static_cast<DocUd*>(luaL_checkudata(L, 1, kDocMeta));
    impl_of(L).clear_script_hl(ud->id);
    return 0;
}

int l_color(lua_State* L) {
    uint32_t c;
    if (!to_color(L, 1, c)) return luaL_error(L, "hx.color: unknown color (use a name, \"#rrggbb\" or 0xRRGGBB)");
    lua_pushinteger(L, lua_Integer(c));
    return 1;
}

int l_hex(lua_State* L) {
    size_t n;
    const char* s = luaL_checklstring(L, 1, &n);
    {
        std::string h = hex_spaced(reinterpret_cast<const uint8_t*>(s), n);
        lua_pushlstring(L, h.data(), h.size());
    }
    return 1;
}

int l_unhex(lua_State* L) {
    const char* s = luaL_checkstring(L, 1);
    char err[200] = "";
    bool ok;
    {
        std::vector<uint8_t> out;
        std::string e;
        ok = parse_bytes(s, out, &e);
        if (ok) lua_pushlstring(L, reinterpret_cast<const char*>(out.data()), out.size());
        else std::snprintf(err, sizeof err, "hx.unhex: %s", e.empty() ? "not a byte string" : e.c_str());
    }
    if (!ok) return luaL_error(L, "%s", err);
    return 1;
}

// Standard CRC-32 (zlib / PNG / ZIP); `prev` continues an earlier result for chunked input.
struct Crc32Table {
    uint32_t v[256];
    Crc32Table() {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            v[i] = c;
        }
    }
};

int l_crc32(lua_State* L) {
    static const Crc32Table tbl;  // thread-safe init: background parses run in states of their own
    const uint32_t* table = tbl.v;
    size_t n;
    const auto* s = reinterpret_cast<const uint8_t*>(luaL_checklstring(L, 1, &n));
    uint32_t crc = ~uint32_t(luaL_optinteger(L, 2, 0));
    for (size_t i = 0; i < n; ++i) crc = table[(crc ^ s[i]) & 0xFF] ^ (crc >> 8);
    crc = ~crc;
    lua_pushinteger(L, lua_Integer(crc));
    return 1;
}

// hx.hash(algo, bytes) -> lowercase hex digest (core/hash.h; names ignore case and punctuation).
int l_hash(lua_State* L) {
    const char* algo = luaL_checkstring(L, 1);
    size_t n = 0;
    const char* data = luaL_checklstring(L, 2, &n);
    bool ok = false;
    if (const int ref = find_hash_algorithm(algo) ? LUA_NOREF : find_lua_hash(impl_of(L), algo); ref != LUA_NOREF) {
        LuaHasher h(L, nullptr, ref);  // a Lua algorithm: raising, in this state
        h.update(reinterpret_cast<const uint8_t*>(data), n);
        const std::string hex = to_hex(h.finish());
        lua_pushlstring(L, hex.data(), hex.size());
        return 1;
    }
    {
        std::string hex = hash_hex(algo, reinterpret_cast<const uint8_t*>(data), n);
        ok = !hex.empty();
        if (ok) lua_pushlstring(L, hex.data(), hex.size());
    }
    if (!ok) return luaL_error(L, "hx.hash: unknown algorithm '%s' (see hx.hash_algorithms())", algo);
    return 1;
}

// hx.disasm(bytes, address?, mode?) -> list of instructions decoded from a string (offset =
// position in `bytes`, 0-based; address = address + offset). At most kMaxDisasm instructions.
int l_disasm(lua_State* L) {
    size_t len = 0;
    const auto* data = reinterpret_cast<const uint8_t*>(luaL_checklstring(L, 1, &len));
    const lua_Integer base = luaL_optinteger(L, 2, 0);
    DisasmOptions opt;
    opt.mode = check_disasm_mode(L, 3, DisasmMode::X64);
    const size_t cap = std::min(len, kMaxDisasm);
    auto* arr = static_cast<LuaInsn*>(lua_newuserdatauv(L, sizeof(LuaInsn) * std::max<size_t>(cap, 1), 0));
    size_t n = 0;
    {
        const std::string none;
        for (size_t pos = 0; pos < len && n < cap;) {
            Insn i;
            disasm_one(data + pos, len - pos, uint64_t(base) + pos, opt, i);
            i.offset = pos;
            to_lua_insn(i, none, arr[n++]);
            pos += i.length ? i.length : 1;
        }
    }
    push_lua_insns(L, arr, n);
    return 1;
}

// ---- XOR search (hx.xor_scan / hx.xor_guess_key) -----------------------------------------------
// The scans run in helpers that fill Lua-owned arrays of plain structs.

constexpr uint64_t kMaxXorScan = 256ull << 20;   // hx.xor_scan range cap (it blocks)
constexpr uint64_t kMaxKeyGuess = 16ull << 20;   // hx.xor_guess_key range cap
constexpr lua_Integer kMaxXorHits = 100000;

struct LuaXorHit {
    uint64_t offset;
    uint32_t phase;
    uint8_t transform, key_len;
    uint8_t key[kXorMaxKeyLen];
    char text[192];
};

struct LuaKeyCand {
    uint8_t key[kXorMaxKeyLen];
    uint8_t len;
    double score;
};

// Optional fields of an options table at `idx` (absent / nil: the default; idx 0 = no table).
bool opt_bool(lua_State* L, int idx, const char* key, bool def) {
    if (!idx) return def;
    lua_getfield(L, idx, key);
    const bool v = lua_isnil(L, -1) ? def : lua_toboolean(L, -1) != 0;
    lua_pop(L, 1);
    return v;
}
lua_Integer opt_int(lua_State* L, int idx, const char* key, lua_Integer def) {
    if (!idx) return def;
    lua_getfield(L, idx, key);
    lua_Integer v = def;
    if (!lua_isnil(L, -1)) {
        int ok = 0;
        v = lua_tointegerx(L, -1, &ok);
        if (!ok) luaL_error(L, "option '%s' must be an integer", key);
    }
    lua_pop(L, 1);
    return v;
}
int opts_index(lua_State* L, int idx) {
    if (lua_isnoneornil(L, idx)) return 0;
    luaL_checktype(L, idx, LUA_TTABLE);
    return lua_absindex(L, idx);
}

const char* xor_transform_lua(XorTransform t) {
    switch (t) {
    case XorTransform::Xor: return "xor";
    case XorTransform::Add: return "add";
    case XorTransform::Rol: return "rol";
    case XorTransform::XorKey: return "xor_key";
    case XorTransform::AddKey: return "add_key";
    }
    return "?";
}

// Scans [start, start+len) of `d` on a worker (stopped at `until`); at most `max` hits into `arr`.
// Returns the hit count; *timed_out when the time limit stopped it.
size_t xor_scan_into(const Document& d, uint64_t start, uint64_t len, const char* pt, size_t pn,
                     const XorScanOptions& o, size_t max, std::chrono::steady_clock::time_point until,
                     LuaXorHit* arr, bool* timed_out) {
    const std::vector<uint8_t> plain(pt, pt + pn);
    std::shared_ptr<const Snapshot> snap = d.snapshot();
    XorScanResult res;
    std::atomic<bool> cancel{false};
    // On a worker so the script time limit can stop a long scan (the hook cannot interrupt C).
    auto fut = std::async(std::launch::async, [&] { scan_xor(*snap, start, start + len, plain, o, res, &cancel); });
    *timed_out = fut.wait_until(until) != std::future_status::ready;
    if (*timed_out) cancel = true;
    fut.get();
    if (*timed_out) return 0;
    const size_t n = std::min(res.hits.size(), max);
    for (size_t k = 0; k < n; ++k) {
        const XorHit& h = res.hits[k];
        LuaXorHit& out = arr[k];
        out.offset = h.offset;
        out.phase = h.phase;
        out.transform = uint8_t(h.transform);
        out.key_len = uint8_t(std::min<size_t>(h.key.size(), kXorMaxKeyLen));
        std::memcpy(out.key, h.key.data(), out.key_len);
        std::snprintf(out.text, sizeof out.text, "%s", describe_key(h.transform, h.key).c_str());
    }
    return n;
}

// key_guess over [off, off+len) of `d` into `arr` (kXorMaxKeyLen entries); returns the count.
size_t key_guess_into(const Document& d, uint64_t off, uint64_t len, uint8_t plain, uint32_t max_len, bool add,
                      LuaKeyCand* arr) {
    std::vector<uint8_t> buf(static_cast<size_t>(len));
    const size_t got = len ? d.read(off, buf.data(), buf.size()) : 0;
    const std::vector<KeyCandidate> c =
        key_guess(buf.data(), got, off, plain, max_len, add ? XorTransform::Add : XorTransform::Xor);
    const size_t n = std::min(c.size(), size_t(kXorMaxKeyLen));
    for (size_t k = 0; k < n; ++k) {
        arr[k].len = uint8_t(std::min<size_t>(c[k].key.size(), kXorMaxKeyLen));
        std::memcpy(arr[k].key, c[k].key.data(), arr[k].len);
        arr[k].score = c[k].score;
    }
    return n;
}

// hx.xor_scan(doc, plaintext, opts?) -> list of hits (see the API comment).
int l_xor_scan(lua_State* L) {
    Document* d = check_doc(L, 1);
    size_t pn = 0;
    const char* pt = luaL_checklstring(L, 2, &pn);
    const int ot = opts_index(L, 3);
    XorScanOptions o;  // plain data
    o.xor8 = opt_bool(L, ot, "xor", true);
    o.add8 = opt_bool(L, ot, "add", true);
    o.rol = opt_bool(L, ot, "rol", true);
    o.xor_multi = opt_bool(L, ot, "multi", false);
    o.add_multi = opt_bool(L, ot, "add_multi", false);
    const lua_Integer mk = opt_int(L, ot, "max_key_len", lua_Integer(kXorMaxKeyLen));
    const lua_Integer max = opt_int(L, ot, "max", 10000);
    const lua_Integer start_i = opt_int(L, ot, "start", 0);
    const lua_Integer length_i = opt_int(L, ot, "length", -1);
    if (!pn) return luaL_error(L, "hx.xor_scan: empty plaintext");
    if (mk < 2 || mk > lua_Integer(kXorMaxKeyLen)) return luaL_error(L, "hx.xor_scan: max_key_len must be 2..16");
    if (max < 1 || max > kMaxXorHits) return luaL_error(L, "hx.xor_scan: max must be 1..100000");
    if (start_i < 0) return luaL_error(L, "hx.xor_scan: start must be >= 0");
    o.max_key_len = uint32_t(mk);
    o.max_results = size_t(max);
    const uint64_t size = d->size();
    const uint64_t start = std::min(uint64_t(start_i), size);
    const uint64_t len = length_i < 0 ? size - start : std::min(uint64_t(length_i), size - start);
    if (len > kMaxXorScan)
        return luaL_error(L, "hx.xor_scan: at most 256 MiB per call (pass start / length, or use the XOR Search "
                             "panel, which scans any size in the background)");
    auto* arr = static_cast<LuaXorHit*>(lua_newuserdatauv(L, sizeof(LuaXorHit) * size_t(max), 0));
    Impl& im = impl_of(L);
    const auto until = im.deadline_on ? im.deadline : std::chrono::steady_clock::now() + std::chrono::seconds(10);
    bool timed_out = false;
    const size_t n = xor_scan_into(*d, start, len, pt, pn, o, size_t(max), until, arr, &timed_out);
    if (timed_out) return luaL_error(L, "hx.xor_scan: time limit reached (use the XOR Search panel for huge ranges)");
    lua_createtable(L, int(n), 0);
    for (size_t k = 0; k < n; ++k) {
        const LuaXorHit& h = arr[k];
        lua_createtable(L, 0, 5);
        lua_pushinteger(L, lua_Integer(h.offset));
        lua_setfield(L, -2, "offset");
        lua_pushstring(L, xor_transform_lua(XorTransform(h.transform)));
        lua_setfield(L, -2, "transform");
        lua_pushlstring(L, reinterpret_cast<const char*>(h.key), h.key_len);
        lua_setfield(L, -2, "key");
        lua_pushinteger(L, lua_Integer(h.phase));
        lua_setfield(L, -2, "phase");
        lua_pushstring(L, h.text);
        lua_setfield(L, -2, "text");
        lua_rawseti(L, -2, lua_Integer(k + 1));
    }
    return 1;
}

// hx.xor_guess_key(doc, off, len, opts?) -> list of { key=, score= }, best first.
int l_xor_guess_key(lua_State* L) {
    Document* d = check_doc(L, 1);
    uint64_t off = check_u64(L, 2);
    uint64_t len = check_u64(L, 3);
    const int ot = opts_index(L, 4);
    lua_Integer plain = 0;
    if (ot) {
        lua_getfield(L, ot, "plain");
        if (lua_type(L, -1) == LUA_TSTRING) {
            size_t sl = 0;
            const char* s = lua_tolstring(L, -1, &sl);
            plain = sl == 1 ? lua_Integer(uint8_t(s[0])) : -1;
        } else if (!lua_isnil(L, -1)) {
            int ok = 0;
            plain = lua_tointegerx(L, -1, &ok);
            if (!ok) plain = -1;
        }
        lua_pop(L, 1);
    }
    if (plain < 0 || plain > 255)
        return luaL_error(L, "hx.xor_guess_key: plain must be a byte value or a 1-character string");
    const lua_Integer max_len = opt_int(L, ot, "max_len", lua_Integer(kXorMaxKeyLen));
    if (max_len < 1 || max_len > lua_Integer(kXorMaxKeyLen)) return luaL_error(L, "hx.xor_guess_key: max_len must be 1..16");
    bool add = false;
    if (ot) {
        lua_getfield(L, ot, "op");
        const char* op = lua_type(L, -1) == LUA_TSTRING ? lua_tostring(L, -1) : nullptr;
        if (op && (!std::strcmp(op, "add") || !std::strcmp(op, "add_key"))) add = true;
        else if (!lua_isnil(L, -1) && !(op && (!std::strcmp(op, "xor") || !std::strcmp(op, "xor_key"))))
            return luaL_error(L, "hx.xor_guess_key: op must be \"xor\" or \"add\"");
        lua_pop(L, 1);
    }
    const uint64_t size = d->size();
    off = std::min(off, size);
    len = std::min(len, size - off);
    if (len > kMaxKeyGuess) return luaL_error(L, "hx.xor_guess_key: at most 16 MiB per call");
    auto* arr = static_cast<LuaKeyCand*>(lua_newuserdatauv(L, sizeof(LuaKeyCand) * kXorMaxKeyLen, 0));
    const size_t n = key_guess_into(*d, off, len, uint8_t(plain), uint32_t(max_len), add, arr);
    lua_createtable(L, int(n), 0);
    for (size_t k = 0; k < n; ++k) {
        lua_createtable(L, 0, 2);
        lua_pushlstring(L, reinterpret_cast<const char*>(arr[k].key), arr[k].len);
        lua_setfield(L, -2, "key");
        lua_pushnumber(L, arr[k].score);
        lua_setfield(L, -2, "score");
        lua_rawseti(L, -2, lua_Integer(k + 1));
    }
    return 1;
}

constexpr size_t kMaxTransformKey = 4096;  // doc:apply_transform key bytes

// doc:apply_transform{ op=, key=, start=?, length=?, phase=?, decode=?, label=? }: XOR / ADD / SUB /
// ROL / ROR a range in place as one undo step (core/xorscan.h apply_transform; see the API comment).
int doc_apply_transform(lua_State* L) {
    Document* d = check_doc(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);
    char err[320] = {};
    {
        lua_getfield(L, 2, "op");
        const char* op_s = lua_tostring(L, -1);
        const std::string op = op_s ? op_s : "";
        lua_pop(L, 1);
        bool decode = opt_bool(L, 2, "decode", false);
        // Applying = encoding (add adds, rol rotates left); sub / ror are the decodes, decode flips.
        const bool sum = op == "add" || op == "add_key" || op == "sub";
        const bool rot = op == "rol" || op == "ror";
        if (op == "sub" || op == "ror") decode = !decode;
        if (!sum && !rot && op != "xor" && op != "xor_key")
            return luaL_error(L, "doc:apply_transform: op must be \"xor\", \"add\", \"sub\", \"rol\" or \"ror\"");
        std::vector<uint8_t> key;
        lua_getfield(L, 2, "key");
        if (lua_type(L, -1) == LUA_TNUMBER) {
            int isnum = 0;
            const lua_Integer k = lua_tointegerx(L, -1, &isnum);
            if (!isnum || k < 0 || k > 255) return luaL_error(L, "doc:apply_transform: a numeric key must be 0..255");
            key.push_back(uint8_t(k));
        } else if (lua_type(L, -1) == LUA_TSTRING && (!rot || lua_rawlen(L, -1) == 1)) {  // rol: xor_scan's 1-byte key
            size_t kn = 0;
            const char* k = lua_tolstring(L, -1, &kn);
            key.assign(k, k + kn);
        } else {
            return luaL_error(L, rot ? "doc:apply_transform: rol / ror take key = the bit count (1..7)"
                                     : "doc:apply_transform: key (a string of key bytes or a byte value) is required");
        }
        lua_pop(L, 1);
        if (key.empty() || key.size() > kMaxTransformKey) return luaL_error(L, "doc:apply_transform: key must be 1..4096 bytes");
        if (rot && (key[0] < 1 || key[0] > 7)) return luaL_error(L, "doc:apply_transform: rol / ror key must be 1..7 bits");
        const XorTransform t = rot ? XorTransform::Rol : keyed_transform(key.size(), sum);
        // Range: start / length, else the selection.
        lua_getfield(L, 2, "start");
        lua_getfield(L, 2, "length");
        const bool has_len = !lua_isnil(L, -1), ranged = has_len || !lua_isnil(L, -2);
        lua_pop(L, 2);
        uint64_t start = 0, len = 0;
        if (ranged) {
            const lua_Integer s_i = opt_int(L, 2, "start", 0), l_i = opt_int(L, 2, "length", -1);
            if (s_i < 0) return luaL_error(L, "doc:apply_transform: start must be >= 0");
            if (has_len && l_i < 0) return luaL_error(L, "doc:apply_transform: length must be >= 0");
            start = uint64_t(s_i);
            len = l_i < 0 ? (start < d->size() ? d->size() - start : 0) : uint64_t(l_i);
        } else {
            const ViewState& v = d->view();
            if (!v.has_selection()) return luaL_error(L, "doc:apply_transform: nothing selected (pass start / length)");
            start = v.sel_begin();
            len = v.sel_len();
        }
        const lua_Integer ph = opt_int(L, 2, "phase", -1);
        lua_getfield(L, 2, "phase");
        if (!lua_isnil(L, -1) && ph < 0) return luaL_error(L, "doc:apply_transform: phase must be >= 0");
        lua_pop(L, 1);
        const uint64_t phase = ph < 0 ? start % key.size() : uint64_t(ph);
        lua_getfield(L, 2, "label");
        const std::string label = lua_type(L, -1) == LUA_TSTRING ? lua_tostring(L, -1) : "";
        lua_pop(L, 1);
        std::string e;
        if (!apply_transform(*d, start, len, t, key, phase, decode, &e, label))
            std::snprintf(err, sizeof err, "doc:apply_transform: %s", e.c_str());
    }
    if (err[0]) return luaL_error(L, "%s", err);
    return 0;
}

// hx.hash_algorithms() -> { "Sum-8", ..., "SHA-512", <Lua ones> } (display names, in display order)
int l_hash_algorithms(lua_State* L) {
    const auto& all = hash_algorithms();
    const auto& lua = impl_of(L).eng.hash_algorithms();
    lua_createtable(L, int(all.size() + lua.size()), 0);
    for (size_t i = 0; i < all.size(); ++i) {
        lua_pushstring(L, all[i].name);
        lua_rawseti(L, -2, lua_Integer(i + 1));
    }
    for (size_t i = 0; i < lua.size(); ++i) {
        lua_pushstring(L, lua[i].name.c_str());
        lua_rawseti(L, -2, lua_Integer(all.size() + i + 1));
    }
    return 1;
}

// Continuation of an inline hx.run (stack: name, message handler, [error]).
int run_inline_k(lua_State* L, int status, lua_KContext) {
    Impl& im = impl_of(L);
    --im.inline_runs;
    if (status != LUA_OK && status != LUA_YIELD) {
        {
            const char* msg = lua_tostring(L, -1);
            im.eng.log(ConsoleLine::Error, std::string("Command '") + lua_tostring(L, 1) + "': " + (msg ? msg : "(error)"));
        }
        lua_pop(L, 1);
    }
    return 0;
}

// hx.prompt(title, default?, {hint=}?) -> string | nil: suspends the running command's coroutine;
// the engine records the request, the UI asks the user, answer_prompt() resumes with the result.
int l_prompt(lua_State* L) {
    const char* title = luaL_checkstring(L, 1);
    const char* def = luaL_optstring(L, 2, "");
    const char* hint = "";
    if (lua_istable(L, 3)) {
        if (lua_getfield(L, 3, "hint") == LUA_TSTRING || lua_isnumber(L, -1)) hint = lua_tostring(L, -1);
        else if (!lua_isnil(L, -1)) return luaL_error(L, "hx.prompt: opts.hint must be a string");
    } else if (!lua_isnoneornil(L, 3)) {
        luaL_checktype(L, 3, LUA_TTABLE);
    }
    Impl& im = impl_of(L);
    if (L != im.cmd_thread) return luaL_error(L, "hx.prompt is only available inside commands");
    if (im.waiting) return luaL_error(L, "hx.prompt: another prompt is already open");
    if (!lua_isyieldable(L))
        return luaL_error(L, "hx.prompt: cannot ask here (not inside doc:transaction, metamethods or iterators)");
    im.prompt.title = title;
    im.prompt.default_text = def;
    im.prompt.hint = hint;
    im.prompt.command.clear();
    im.prompt_requested = true;
    return lua_yield(L, 0);  // resumed by answer_prompt with the text (or nil) as our result
}

// hx.run(name): run a registered command exactly like the palette does (one undo step on the
// active document). Lets automation (--exec) and other scripts chain commands.
int l_run(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    Impl& im = impl_of(L);
    bool known = false;
    {
        known = im.command_refs.count(std::string(name)) != 0;
    }
    if (!known) return luaL_error(L, "hx.run: unknown command '%s'", name);
    if (im.depth > 16 || im.inline_runs >= 16) return luaL_error(L, "hx.run: commands nested too deeply");
    if (L != im.cmd_thread) {
        im.eng.run_command(name);
        return 0;
    }
    // Inside a command: run it inline on the same coroutine, so an hx.prompt in it suspends the
    // whole chain; its edits join the caller's undo step. Errors are logged, not propagated.
    lua_settop(L, 1);
    lua_pushcfunction(L, lua_msg_handler);
    lua_rawgeti(L, LUA_REGISTRYINDEX, im.command_refs.find(name)->second);
    ScriptHost* host = im.eng.host();
    Document* d = host ? host->active_document() : nullptr;
    if (d) push_doc(L, d->id());
    else lua_pushnil(L);
    ++im.inline_runs;
    return run_inline_k(L, lua_pcallk(L, 1, 0, 2, 0, run_inline_k), 0);
}

const luaL_Reg kHexerFuncs[] = {
    {"parser", l_parser},     {"command", l_command},   {"log", l_print},
    {"warn", l_warn},         {"error", l_error},       {"inspect", l_inspect},
    {"clear_console", l_clear_console},                 {"doc", l_doc},
    {"new_doc", l_new_doc},   {"highlight", l_highlight},
    {"open_process", l_open_process},
    {"clear_highlights", l_clear_highlights},           {"color", l_color},
    {"hex", l_hex},           {"unhex", l_unhex},       {"crc32", l_crc32},
    {"hash", l_hash},         {"hash_algorithms", l_hash_algorithms},
    {"hash_algorithm", l_hash_algorithm},
    {"run", l_run},           {"prompt", l_prompt},     {"disasm", l_disasm},
    {"xor_scan", l_xor_scan}, {"xor_guess_key", l_xor_guess_key},
    {nullptr, nullptr},
};

void warn_fn(void* ud, const char* msg, int tocont) {
    auto* im = static_cast<Impl*>(ud);
    if (!tocont && im->warn_buf.empty() && msg[0] == '@') return;  // "@on"/"@off" control messages
    im->warn_buf += msg;
    if (!tocont) {
        im->eng.log(ConsoleLine::Warn, im->warn_buf);
        im->warn_buf.clear();
    }
}

// ---- sandbox: finalizers, stdin, UTF-8 file names ----------------------------------------------

// Lua runs __gc metamethods with debug hooks off, so the time limit could not stop a looping one
// (not even at reload / exit). setmetatable therefore swaps a metatable's __gc function for this
// runner (upvalue 1 = the original), which calls it on a fresh coroutine (hooks on) under a limit.
int gc_runner(lua_State* L) {
    Impl& im = impl_of(L);
    lua_State* co = lua_newthread(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_pushvalue(L, 1);
    lua_xmove(L, co, 2);
    auto saved_deadline = im.deadline;
    bool saved_on = im.deadline_on, saved_timed_out = im.timed_out;
    int saved_limit = im.limit_ms;
    auto mine = std::chrono::steady_clock::now() + std::chrono::milliseconds(kGcTimeLimitMs);
    if (!im.deadline_on || mine < im.deadline) {
        im.deadline = mine;
        im.limit_ms = kGcTimeLimitMs;
    }
    im.deadline_on = true;
    lua_sethook(co, lua_time_hook, LUA_MASKCOUNT, im.timed_out ? 1 : kHookCount);
    int nres = 0;
    int st = lua_resume(co, L, 1, &nres);
    im.deadline = saved_deadline;
    im.deadline_on = saved_on;
    im.timed_out = saved_timed_out;
    im.limit_ms = saved_limit;
    if (im.L) {  // a timeout inside re-armed the main thread's hook
        if (saved_on) lua_sethook(im.L, lua_time_hook, LUA_MASKCOUNT, saved_timed_out ? 1 : kHookCount);
        else lua_sethook(im.L, nullptr, 0, 0);
    }
    if (st != LUA_OK && st != LUA_YIELD) {
        lua_xmove(co, L, 1);
        return lua_error(L);  // Lua turns it into an "error in __gc" warning (console)
    }
    return 0;
}

// setmetatable / debug.setmetatable wrapper (upvalue 1 = the original).
int l_setmetatable(lua_State* L) {
    int n = std::min(lua_gettop(L), 2);
    lua_settop(L, n);
    if (lua_type(L, 2) == LUA_TTABLE) {
        lua_pushliteral(L, "__gc");
        if (lua_rawget(L, 2) == LUA_TFUNCTION && lua_tocfunction(L, -1) != gc_runner) {
            lua_pushcclosure(L, gc_runner, 1);
            lua_pushliteral(L, "__gc");
            lua_insert(L, -2);
            lua_rawset(L, 2);
        } else {
            lua_pop(L, 1);
        }
    }
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, n, 1);
    return 1;
}

void wrap_setmetatable(lua_State* L, int table_idx) {
    table_idx = lua_absindex(L, table_idx);
    lua_getfield(L, table_idx, "setmetatable");
    lua_pushcclosure(L, l_setmetatable, 1);
    lua_setfield(L, table_idx, "setmetatable");
}

#ifdef _WIN32
int io_fclose_utf8(lua_State* L) {
    auto* p = static_cast<luaL_Stream*>(luaL_checkudata(L, 1, LUA_FILEHANDLE));
    errno = 0;
    return luaL_fileresult(L, std::fclose(p->f) == 0, nullptr);
}

// io.open taking a UTF-8 file name (the CRT's fopen expects the ANSI code page on Windows).
int l_io_open_utf8(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    const char* mode = luaL_optstring(L, 2, "r");
    const char* m = mode;  // same check as liolib: [rwa]%+?b*
    bool valid = *m && std::strchr("rwa", *m++);
    if (valid && *m == '+') ++m;
    valid = valid && std::strspn(m, "b") == std::strlen(m);
    luaL_argcheck(L, valid, 2, "invalid mode");
    auto* p = static_cast<luaL_Stream*>(lua_newuserdatauv(L, sizeof(luaL_Stream), 0));
    p->f = nullptr;
    p->closef = nullptr;  // "closed" until opened
    luaL_setmetatable(L, LUA_FILEHANDLE);
    {
        std::wstring wname = utf8_to_wide(name), wmode = utf8_to_wide(mode);
        errno = 0;
        p->f = _wfopen(wname.c_str(), wmode.c_str());
    }
    if (!p->f) return luaL_fileresult(L, 0, name);
    p->closef = io_fclose_utf8;
    return 1;
}
#endif

// Runs once per state with one argument: a UTF-8 io.open (Windows) or nil. Closes the stdin holes
// left by liolib (loadfile()/dofile()/io.lines() without a name) and, on Windows, routes file names
// through the UTF-8 io.open: require's Lua searcher, loadfile, dofile, io.lines/input/output.
const char* kSandboxLua = R"LUA(
local wopen = ...
local io, package, load, error, type, tostring = io, package, load, error, type, tostring
local sub, gsub, gmatch, concat = string.sub, string.gsub, string.gmatch, table.concat
local no_stdin = "there is no stdin inside Hexer (use io.open)"
local open, lines, input, output, orig_loadfile = wopen or io.open, io.lines, io.input, io.output, loadfile

local function readall(path)
    local f, err = open(path, "rb")
    if not f then return nil, err end
    local s = f:read("a")
    f:close()
    if sub(s, 1, 3) == "\239\187\191" then s = sub(s, 4) end   -- UTF-8 BOM
    if sub(s, 1, 1) == "#" then s = gsub(s, "^#[^\n]*", "", 1) end  -- shebang; keeps line numbers
    return s
end

local function lfile(path, ...)
    if path == nil then return nil, "loadfile: " .. no_stdin end
    if not wopen then return orig_loadfile(path, ...) end
    local s, err = readall(path)
    if not s then return nil, "cannot open " .. tostring(err) end
    return load(s, "@" .. path, ...)
end
loadfile = lfile

function dofile(path)
    if path == nil then error("dofile: " .. no_stdin, 2) end
    local f, err = lfile(path)
    if not f then error(err, 0) end
    return f()
end

function io.lines(path, ...)
    if path == nil then error("io.lines: " .. no_stdin, 2) end
    if not wopen then return lines(path, ...) end
    local f, err = open(path, "r")
    if not f then error(err, 2) end
    return f:lines(...), nil, nil, f   -- f is closed by the generic for
end

if not wopen then return end
io.open = wopen

local function reopen(orig, mode)
    return function(f, ...)
        if type(f) == "string" then
            local h, err = open(f, mode)
            if not h then error("cannot open file '" .. f .. "' (" .. tostring(err) .. ")", 2) end
            f = h
        end
        return orig(f, ...)
    end
end
io.input, io.output = reopen(input, "r"), reopen(output, "w")

package.searchers[2] = function(name)
    local fname = gsub(gsub(name, "%.", "/"), "%%", "%%%%")
    local tried = {}
    for tpl in gmatch(package.path, "[^;]+") do
        local path = gsub(tpl, "%?", fname)
        local s = readall(path)
        if s then
            local fn, err = load(s, "@" .. path)
            if not fn then
                error("error loading module '" .. name .. "' from file '" .. path .. "':\n\t" .. err, 0)
            end
            return fn, path
        end
        tried[#tried + 1] = "no file '" .. path .. "'"
    end
    return concat(tried, "\n\t")
end
)LUA";

void install_sandbox(lua_State* L) {
    // __gc finalizers run under a time limit (see gc_runner).
    lua_pushglobaltable(L);
    wrap_setmetatable(L, -1);
    lua_pop(L, 1);
    lua_getglobal(L, "debug");
    wrap_setmetatable(L, -1);
    lua_pop(L, 1);

    // No stdin: io.stdin and the default input become a closed file handle, io.read an error.
    auto* p = static_cast<luaL_Stream*>(lua_newuserdatauv(L, sizeof(luaL_Stream), 0));
    p->f = nullptr;
    p->closef = nullptr;  // closed
    luaL_setmetatable(L, LUA_FILEHANDLE);
    lua_pushvalue(L, -1);
    lua_setfield(L, LUA_REGISTRYINDEX, "_IO_input");  // liolib's default-input key
    lua_getglobal(L, "io");
    lua_insert(L, -2);
    lua_setfield(L, -2, "stdin");
    lua_pushcfunction(L, l_no_stdin);
    lua_setfield(L, -2, "read");
    lua_pop(L, 1);

    if (luaL_loadbufferx(L, kSandboxLua, std::strlen(kSandboxLua), "=sandbox", "t") != LUA_OK) lua_error(L);
#ifdef _WIN32
    lua_pushcfunction(L, l_io_open_utf8);
#else
    lua_pushnil(L);
#endif
    lua_call(L, 1, 0);
}

int install_main(lua_State* L) {
    Impl& im = impl_of(L);
    luaL_openlibs(L);
    install_sandbox(L);

    // Doc metatable: methods + one closure per number type with explicit endianness.
    luaL_newmetatable(L, kDocMeta);
    lua_newtable(L);
    luaL_setfuncs(L, kDocMethods, 0);
    for (int i = 0; i < kNumTypeCount; ++i) {
        if (!kNumTypes[i].endian) continue;
        lua_pushinteger(L, i);
        lua_pushcclosure(L, doc_num, 1);
        lua_setfield(L, -2, kNumTypes[i].name);
    }
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, doc_tostring);
    lua_setfield(L, -2, "__tostring");
    lua_pushcfunction(L, doc_eq);
    lua_setfield(L, -2, "__eq");
    lua_pop(L, 1);

    // Parser context metatable.
    luaL_newmetatable(L, kParserMeta);
    lua_newtable(L);
    luaL_setfuncs(L, kParserMethods, 0);
    for (int i = 0; i < kNumTypeCount; ++i) {
        lua_pushinteger(L, i);
        lua_pushcclosure(L, p_typed, 1);
        lua_setfield(L, -2, kNumTypes[i].name);
    }
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, p_tostring);
    lua_setfield(L, -2, "__tostring");
    lua_pop(L, 1);

    // hexer / hx
    lua_newtable(L);
    luaL_setfuncs(L, kHexerFuncs, 0);
    lua_pushstring(L, HEXER_VERSION);
    lua_setfield(L, -2, "version");
    lua_pushvalue(L, -1);
    lua_setglobal(L, "hexer");
    lua_setglobal(L, "hx");

    lua_pushcfunction(L, l_print);
    lua_setglobal(L, "print");

    // A stray os.exit() in the console must not kill the editor (stdin: see install_sandbox).
    lua_getglobal(L, "os");
    lua_pushcfunction(L, l_no_exit);
    lua_setfield(L, -2, "exit");
    lua_pop(L, 1);

    // Keep the original string.pack/unpack/packsize for the engine's own use.
    lua_getglobal(L, "string");
    lua_getfield(L, -1, "pack");
    im.ref_pack = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_getfield(L, -1, "unpack");
    im.ref_unpack = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_getfield(L, -1, "packsize");
    im.ref_packsize = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pop(L, 1);
    return 0;
}

}  // namespace

// ---- exported glue ---------------------------------------------------------------------------------

int lua_msg_handler(lua_State* L) {
    const char* msg = lua_tostring(L, 1);
    if (!msg) {
        if (luaL_callmeta(L, 1, "__tostring") && lua_type(L, -1) == LUA_TSTRING) msg = lua_tostring(L, -1);
        else msg = lua_pushfstring(L, "(error object is a %s value)", luaL_typename(L, 1));
    }
    if (std::strstr(msg, "\nstack traceback:")) lua_pushstring(L, msg);  // already has one (re-raised)
    else luaL_traceback(L, L, msg, 1);
    return 1;
}

void lua_time_hook(lua_State* L, lua_Debug* ar) {
    Impl& im = impl_of(L);
    if (!im.deadline_on) return;
    const bool cancelled = im.cancel && im.cancel->load(std::memory_order_relaxed);  // ParseJob::cancel
    if (!cancelled && !im.timed_out && std::chrono::steady_clock::now() < im.deadline) {
        if (lua_gethookcount(L) != kHookCount) lua_sethook(L, lua_time_hook, LUA_MASKCOUNT, kHookCount);
        return;
    }
    // Sticky: from now on every instruction raises (on this thread and the main one), so code that
    // catches the error (pcall / xpcall / coroutine.resume in a loop) dies at its next instruction.
    im.timed_out = true;
    if (lua_gethookcount(L) != 1) lua_sethook(L, lua_time_hook, LUA_MASKCOUNT, 1);
    if (im.L && im.L != L && lua_gethookcount(im.L) != 1) lua_sethook(im.L, lua_time_hook, LUA_MASKCOUNT, 1);
    if (im.cmd_thread && im.cmd_thread != L && lua_gethookcount(im.cmd_thread) != 1)
        lua_sethook(im.cmd_thread, lua_time_hook, LUA_MASKCOUNT, 1);
    if (cancelled) lua_pushliteral(L, "parse cancelled");
    else if (lua_getinfo(L, "Sl", ar) && ar->currentline > 0)
        lua_pushfstring(L, "%s:%d: script time limit exceeded (%d ms)", ar->short_src, ar->currentline, im.limit_ms);
    else
        lua_pushfstring(L, "script time limit exceeded (%d ms)", im.limit_ms);
    lua_error(L);
}

bool install_api(Impl& im) {
    lua_State* L = im.L;
    *static_cast<Impl**>(lua_getextraspace(L)) = &im;
    lua_setwarnf(L, warn_fn, &im);
    lua_pushcfunction(L, install_main);
    if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
        lua_pop(L, 1);
        return false;
    }
    return true;
}

void push_doc(lua_State* L, uint64_t doc_id) {
    auto* ud = static_cast<DocUd*>(lua_newuserdatauv(L, sizeof(DocUd), 0));
    ud->id = doc_id;
    luaL_setmetatable(L, kDocMeta);
}

std::string lua_inspect(lua_State* L, int idx, int max_depth) {
    Inspector in{L, max_depth, {}};
    return in.value(idx, 0, 0);
}

void run_parse(Impl& im, Document& doc, int parser_ref, ParseResult& out, uint64_t base, uint64_t length) {
    lua_State* L = im.L;
    auto ctx = std::make_unique<ParseCtx>();
    ctx->doc = &doc;
    ctx->base = base;
    ctx->end = length > UINT64_MAX - base ? UINT64_MAX : base + length;
    ctx->pos = base;
    ctx->out = &out;
    ctx->parser_ref = parser_ref;
    lua_pushcfunction(L, parse_main);
    lua_pushlightuserdata(L, ctx.get());
    std::string err;
    bool ok = im.pcall(1, 0, kParseTimeLimitMs, &err);

    // Invalidate `p` (scripts may have stashed it) and release the anchors.
    if (ctx->ud_ref != LUA_NOREF) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->ud_ref);
        if (auto* ud = static_cast<ParserUd*>(lua_touserdata(L, -1))) ud->ctx = nullptr;
        lua_pop(L, 1);
        luaL_unref(L, LUA_REGISTRYINDEX, ctx->ud_ref);
    }
    if (ctx->anchor_ref != LUA_NOREF) luaL_unref(L, LUA_REGISTRYINDEX, ctx->anchor_ref);

    while (!ctx->open.empty()) close_open(ctx.get());
    if (!ok) {
        out.error = error_head(err);
        if (im.quiet_parse_errors) im.last_parse_error = err;  // a ParseJob reports it later
        else im.log_error_once("Parser '" + out.parser + "': " + err);
    }

    // Colors (explicit > inherited from a colored struct > palette by leaf order) and highlights.
    auto& F = out.fields;
    std::vector<uint8_t> inherit(F.size(), 0);
    std::vector<std::string> path(F.size());
    int leaf = 0;
    for (size_t i = 0; i < F.size(); ++i) {
        Field& f = F[i];
        bool leaf_field = f.children.empty();
        if (ctx->explicit_color[i]) {
            inherit[i] = 1;
        } else if (f.parent >= 0 && inherit[size_t(f.parent)]) {
            f.color = F[size_t(f.parent)].color;
            inherit[i] = 1;
        } else {
            f.color = field_palette(leaf);
            if (leaf_field) ++leaf;
        }
        if (f.parent < 0) {
            path[i] = f.name;
        } else {
            // Array elements are already named "items[3]": path "a.items[3]", not "a.items.items[3]".
            const Field& par = F[size_t(f.parent)];
            bool elem = par.type == "array" && f.name.size() > par.name.size() &&
                        f.name.compare(0, par.name.size(), par.name) == 0 && f.name[par.name.size()] == '[';
            path[i] = elem ? path[size_t(f.parent)] + f.name.substr(par.name.size())
                           : path[size_t(f.parent)] + "." + f.name;
        }
        if (leaf_field && f.size) {
            Highlight h;
            h.offset = f.offset;
            h.length = f.size;
            h.color = f.color;
            h.label = f.value.empty() ? path[i] : path[i] + " = " + f.value;
            h.field = int(i);
            out.highlights.add(std::move(h));
        }
    }
    out.highlights.finalize();
}

bool parse_pack_format(const std::string& fmt, PackInfo& out) {
    size_t i = 0;
    auto skip = [&] {
        while (i < fmt.size() && (fmt[i] == '<' || fmt[i] == '>' || fmt[i] == '=' || fmt[i] == ' ')) ++i;
    };
    skip();
    if (i >= fmt.size()) return false;
    char c = fmt[i++];
    PackInfo p;
    switch (c) {
    case 'b': p.size = 1; p.is_signed = true; break;
    case 'B': p.size = 1; break;
    case 'h': p.size = 2; p.is_signed = true; break;
    case 'H': p.size = 2; break;
    case 'l': p.size = int(sizeof(long)); p.is_signed = true; break;
    case 'L': p.size = int(sizeof(long)); break;
    case 'j': p.size = 8; p.is_signed = true; break;
    case 'J': p.size = 8; break;
    case 'T': p.size = int(sizeof(size_t)); break;
    case 'f': p.size = 4; p.is_float = true; break;
    case 'd': case 'n': p.size = 8; p.is_float = true; break;
    case 'i': case 'I': {
        int n = 0;
        while (i < fmt.size() && std::isdigit((unsigned char)fmt[i]) && n < 100) n = n * 10 + (fmt[i++] - '0');
        p.size = n ? n : 4;
        p.is_signed = c == 'i';
        break;
    }
    default: return false;
    }
    skip();
    if (i != fmt.size() || p.size < 1 || p.size > 8) return false;
    out = p;
    return true;
}

std::string format_int(int64_t v, bool is_unsigned, int size, const char* fmt) {
    if (size < 1) size = 1;
    if (size > 8) size = 8;
    uint64_t mask = size >= 8 ? ~0ull : ((1ull << (size * 8)) - 1);
    uint64_t bits = uint64_t(v) & mask;
    char buf[128];
    if (!fmt || !*fmt) {
        if (is_unsigned) {
            uint64_t u = uint64_t(v);
            if (u < 10) std::snprintf(buf, sizeof buf, "%llu", (unsigned long long)u);
            else std::snprintf(buf, sizeof buf, "%llu (0x%llX)", (unsigned long long)u, (unsigned long long)u);
        } else if (v >= 0 && v < 10) {
            std::snprintf(buf, sizeof buf, "%lld", (long long)v);
        } else {
            std::snprintf(buf, sizeof buf, "%lld (0x%llX)", (long long)v, (unsigned long long)bits);
        }
        return buf;
    }
    if (!std::strcmp(fmt, "hex")) {
        std::snprintf(buf, sizeof buf, "0x%0*llX", size * 2, (unsigned long long)bits);
        return buf;
    }
    if (!std::strcmp(fmt, "dec")) {
        if (is_unsigned) std::snprintf(buf, sizeof buf, "%llu", (unsigned long long)uint64_t(v));
        else std::snprintf(buf, sizeof buf, "%lld", (long long)v);
        return buf;
    }
    if (!std::strcmp(fmt, "bin")) {
        std::string s = "0b";
        for (int bit = size * 8 - 1; bit >= 0; --bit) {
            s += ((bits >> bit) & 1) ? '1' : '0';
            if (bit && bit % 8 == 0) s += '_';
        }
        return s;
    }
    // "char": the value's bytes, most significant first (like C multi-char constants 'IHDR').
    std::string chars;
    for (int k = size - 1; k >= 0; --k) chars += char((bits >> (k * 8)) & 0xFF);
    std::string q = escape_quoted(chars.data(), chars.size(), 16);
    q.front() = '\'';
    q.back() = '\'';
    return q + " (" + (is_unsigned ? std::to_string(uint64_t(v)) : std::to_string(v)) + ")";
}

std::string format_float(double v, bool is_f32) {
    if (std::isnan(v)) return "nan";
    if (std::isinf(v)) return v > 0 ? "inf" : "-inf";
    char buf[64];
    std::to_chars_result r = is_f32 ? std::to_chars(buf, buf + sizeof buf, float(v))
                                    : std::to_chars(buf, buf + sizeof buf, v);
    return std::string(buf, r.ptr);
}

std::string error_head(const std::string& full) {
    size_t p = full.find("\nstack traceback:");
    return p == std::string::npos ? full : full.substr(0, p);
}

}  // namespace hx
