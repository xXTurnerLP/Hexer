#pragma once
// Private glue shared by script_engine.cpp (engine orchestration) and lua_api.cpp (the `hexer` API).
//
// Error-handling rule for every lua_CFunction in this module: Lua errors are longjmp()s (Lua is
// built as C), which skip C++ destructors. So a C function must never raise a Lua error (luaL_check*,
// luaL_error, lua_call of user code, ...) while a local with a non-trivial destructor (std::string,
// std::vector, ...) is alive. Compute into such objects inside an inner scope / helper, keep the error
// text in a plain char buffer, and raise only after the scope ends. Safest: do the C++ work in a
// separate HX_NOINLINE helper (lua_api.cpp) - on MSVC (/EHsc) a Lua error raised BEFORE an inner
// scope of the same function was seen to crash while unwinding (hx.xor_scan).
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <lua.hpp>

#include "script/script_engine.h"

namespace hx {

constexpr int kParseTimeLimitMs = 2000;
constexpr int kDetectTimeLimitMs = 1000;
constexpr int kScriptTimeLimitMs = 10000;   // script load, commands, console
constexpr int kGcTimeLimitMs = 1000;        // each __gc finalizer (also at reload / exit)
constexpr int kHookCount = 4096;            // instructions between time checks
constexpr size_t kMaxFields = 200000;

struct ScriptEngine::Impl {
    explicit Impl(ScriptEngine& e) : eng(e) {}
    ~Impl() { close_state(); }

    ScriptEngine& eng;
    lua_State* L = nullptr;

    // Registry refs into the current state.
    std::unordered_map<std::string, int> parser_refs;   // parser name -> spec table
    std::unordered_map<std::string, int> command_refs;  // command name -> run function
    int ref_pack = LUA_NOREF;      // original string.pack / unpack / packsize (immune to user patching)
    int ref_unpack = LUA_NOREF;
    int ref_packsize = LUA_NOREF;

    std::string loading_file;      // script currently executed by reload() (for ParserInfo::file)

    struct Watched {
        std::string path;
        int64_t mtime = 0;
        uint64_t size = 0;
        bool operator==(const Watched&) const = default;
    };
    std::vector<Watched> watched;  // state of all *.lua files at the last reload

    // Time limit enforced by an instruction-count hook while Lua code runs.
    std::chrono::steady_clock::time_point deadline{};
    bool deadline_on = false;
    // Set once the deadline passed: the hook then fires on every instruction (sticky), so a
    // pcall / coroutine loop cannot swallow the error. Cleared when the timed-out call returns.
    bool timed_out = false;
    int limit_ms = 0;              // for the timeout message
    int depth = 0;                 // nesting of protected calls (callbacks may re-enter the engine)

    int script_limit_ms = kScriptTimeLimitMs;  // script load, commands, console

    // Commands run on a coroutine so hx.prompt can suspend them (see run_command / answer_prompt).
    lua_State* cmd_thread = nullptr;  // command coroutine running right now (hx.prompt yields it)
    int inline_runs = 0;              // hx.run nesting inside cmd_thread
    bool prompt_requested = false;    // set by hx.prompt right before it yields
    PendingPrompt prompt;             // its request; valid while waiting
    bool waiting = false;             // a command is suspended in hx.prompt
    int waiting_ref = LUA_NOREF;      // registry ref keeping its coroutine alive
    lua_State* waiting_co = nullptr;
    uint64_t waiting_doc = 0;         // document that gets the command's undo group (0 = none)
    void drop_waiting();              // forget the suspended command (state reset / reload)

    // Resumes `co` (nargs pushed) under the script time limit, as pcall does. Returns the
    // lua_resume status; on error sets *err to "msg\nstack traceback..". Yielded values are popped.
    int resume(lua_State* co, int nargs, std::string* err);
    // Resumes a command coroutine (ref = its registry ref) inside the command's undo group on
    // doc `doc_id`; records the prompt if it yields in hx.prompt, else logs errors and frees it.
    void step_command(lua_State* co, int ref, const std::string& name, uint64_t doc_id, int nargs);

    std::unordered_set<uint64_t> hl_dirty;  // doc ids whose script highlights need finalize()
    std::string warn_buf;          // pieces of a multi-part lua_warning message
    // The UI re-parses after every edit; identical parse/detect errors are logged once per reload.
    std::unordered_set<std::string> logged_errors;
    void log_error_once(const std::string& text);

    void new_state();              // close the old state, open a fresh one with the hexer API
    void close_state();

    // Pushes the traceback message handler, moves it below the function + nargs, calls, removes it.
    // Runs under a time limit (ms). On error returns false and sets *err to "msg\nstack traceback..".
    bool pcall(int nargs, int nresults, int time_limit_ms, std::string* err);

    // Registration from hx.parser / hx.command (a later one with the same name replaces it in place).
    void register_parser(ParserInfo info, int ref);
    void register_command(ScriptCommand cmd, int ref);
    HighlightSet& script_hl(uint64_t doc_id);  // marks it dirty; finalized when the script returns
    void clear_script_hl(uint64_t doc_id);
    void flush_highlights();
};

// Implemented in lua_api.cpp.
bool install_api(ScriptEngine::Impl& im);               // std libs, hexer/hx, metatables, print, warn
int lua_msg_handler(lua_State* L);                       // adds "stack traceback:" (once)
void lua_time_hook(lua_State* L, lua_Debug* ar);         // count hook enforcing Impl::deadline
void push_doc(lua_State* L, uint64_t doc_id);          // Doc userdata
std::string lua_inspect(lua_State* L, int idx, int max_depth = 6);
// Runs parser `ref` over `doc` range [base, base+length) (clamped to the document); fills `out`
// (fields with absolute offsets, highlights, error). Never throws/longjmps.
void run_parse(ScriptEngine::Impl& im, Document& doc, int parser_ref, ParseResult& out, uint64_t base = 0,
               uint64_t length = UINT64_MAX);

// Single numeric string.pack option ("<I2", ">i3", "B", "<d", ...): size and kind. False for
// anything else (multi-value, strings, padding-only formats).
struct PackInfo {
    int size = 0;
    bool is_signed = false;
    bool is_float = false;
};
bool parse_pack_format(const std::string& fmt, PackInfo& out);

// Display text for an integer field: "7", "13 (0xD)", "-1 (0xFF)"; `fmt`: "", "hex", "dec", "bin", "char".
std::string format_int(int64_t v, bool is_unsigned, int size, const char* fmt);
std::string format_float(double v, bool is_f32);

// Splits a pcall error ("file:line: msg\nstack traceback:...") into its first part.
std::string error_head(const std::string& full);

}  // namespace hx
