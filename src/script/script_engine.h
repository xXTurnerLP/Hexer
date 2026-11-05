#pragma once
// Lua 5.5 scripting: plugins, protocol/format parsers (deserializers) that build a structure tree +
// hex highlighting, field editing (serializers), commands, and an interactive console.
//
// =================================== Lua API (contract) ======================================
// Every *.lua file in the bundled scripts dir, then in the user scripts dir, is executed in one
// shared Lua state. Any change to any of those files triggers a full reload (fresh state).
// Subfolders are scanned too (sorted by relative path), except <dir>/lib/: files there are
// modules for require("name") (package.path includes <dir>/lib/?.lua) and are not run directly.
// os.exit and stdin are disabled (no killing the editor): io.read, io.lines(), io.stdin:read,
// io.input():read, loadfile() and dofile() without a file name raise. File names passed to
// io.open/io.lines/loadfile/dofile/require are UTF-8, also on Windows (hexer.exe's manifest
// selects the UTF-8 code page, so there os.rename/os.remove/package.loadlib are UTF-8 too).
// __gc finalizers set through setmetatable run under a 1 s limit each (also at reload / exit).
// Global table `hexer` (also aliased as `hx`):
//
//   hx.version                          "0.1.0"
//   hx.parser{ name=, extensions={"png",..}, detect=function(doc) -> bool, parse=function(p, doc) }
//   hx.command{ name=, description=, run=function(doc) }   -- shown in palette + Scripts menu
//   hx.run(name)                        -- run a registered command (as the palette does); inside
//                                          a command it runs inline, as part of the caller's step
//   hx.prompt(title, default?, {hint=}?) -> string | nil   -- ask the user for one line of text
//       (nil = cancelled). Only inside commands (else error "hx.prompt is only available inside
//       commands"): the command is suspended (a coroutine) while the dialog is open, the time limit
//       applies to each slice of Lua time separately, edits before and after the prompt are
//       separate undo steps, and a doc closed meanwhile raises "document closed" as usual. Not
//       inside doc:transaction (one undo step cannot span the dialog). One prompt at a time:
//       starting another command while one waits is refused; a script reload cancels it.
//         local key = hx.prompt("XOR key", "FF", { hint = "hex bytes" })
//         if not key then return end
//   print(...) / hx.log(...) / hx.warn(...) / hx.error(...)  -- to the console; tables pretty-printed
//   hx.inspect(v, depth?) -> string    -- pretty-printer used by print (depth 1..64, default 6;
//                                         output stops at ~1 MiB of keys/values)
//   hx.clear_console()
//   hx.doc() -> active Doc or nil
//   hx.new_doc(name, bytes) -> Doc     -- open bytes (e.g. a serialized packet) in a new tab
//   hx.highlight(doc, off, len, color, label?)  /  hx.clear_highlights(doc)
//   hx.color(c) -> packed int          -- c: "red"|"#ff8800"|0xff8800 (named: red, green, blue,
//                                         yellow, orange, purple, cyan, pink, gray, teal)
//   hx.hex(str) -> "DE AD BE EF"   hx.unhex("de ad be ef") -> str (lenient, like paste)
//   hx.crc32(str, prev?) -> int       -- zlib/PNG/ZIP CRC-32; pass `prev` to continue over chunks
//   hx.hash(algo, str) -> "cbf43926"   -- lowercase hex digest; algo: any of hx.hash_algorithms()
//                                         (case and punctuation ignored: "sha256", "CRC-32C", "md5")
//   hx.hash_algorithms() -> {"Sum-8", "XOR-8", "CRC-8", ..., "SHA-256", "SHA-512"}
//   hx.disasm(bytes, address?, mode?) -> list of instructions (x86-64, or mode 32 / "x86" for
//       32-bit code; address = of the first byte, default 0; at most 10000 per call), each
//       { address=, offset= (0-based in bytes), length=, text=, bytes=, valid=, target=?, flow=? }:
//         text   "mov rax, qword ptr [rip+0x2a]  ; 0x1031" (Intel, lowercase; RIP-relative
//                operands get the resolved address as a comment), "call 0x1105", "db 0x06" for
//                an invalid byte (valid = false, length 1)
//         target branch target or RIP-relative / absolute memory address (nil if none)
//         flow   "call" | "jmp" | "jcc" | "ret" | "int" (int / int3 / syscall) | nil
//   string.pack / string.unpack       -- standard Lua; the recommended way to serialize
//
// Doc (userdata; every call raises "document closed" if its tab was closed):
//   doc:size()  doc:name()  doc:path()  doc:id()
//   doc:target() -> "file" | "device" | "process"   doc:pid() -> process id (process memory) | nil
//       (process memory: offset = virtual address, unmapped pages read as 0; fixed size)
//   doc:read(off, len) -> string         (clamped to EOF; at most 64 MiB per call)
//   doc:u8(off) doc:i8(off) doc:u16le/u16be/i16le/i16be/u32le/u32be/i32le/i32be/
//       u64le/u64be/i64le/i64be/f32le/f32be/f64le/f64be(off)  -> number (nil past EOF)
//       (also u24le/u24be/i24le/i24be)
//   doc:write(off, bytes)   doc:insert(off, bytes)   doc:erase(off, len)   doc:replace(off, len, bytes)
//   doc:transaction(fn, label?)          -- all edits inside fn become ONE undo step; inside a
//                                           command (already one step) a label renames that step
//   doc:cursor() -> off     doc:selection() -> start, len     doc:select(off, len)     doc:jump(off) (alias doc["goto"])
//       (`goto` is a Lua keyword: write doc:jump(off), the same function, or doc["goto"](doc, off))
//   doc:find(needle, start?, {hex=bool, backward=bool}) -> off | nil   (hex=true: "DE ?? AD")
//   doc:hash(algo, off?, len?) -> hex   (default: the whole doc; clamped to EOF; at most 256 MiB per
//                                         call since it blocks - the Hashes panel does any size)
//   doc:disasm(off, count?, mode?) -> list of instructions like hx.disasm (count default 16, at
//       most 10000; stops at EOF). offset = file offset; address / target use the document's
//       address map (PE / ELF headers: virtual addresses, process memory: = offset, else = offset);
//       entries also get section= (".text") when the map names one. mode defaults to the
//       header's (PE32 / ELF32: 32), else 64. Unreadable bytes are 1-byte "??" entries.
//   All script edits are undoable and respect read-only mode (error "document is read-only").
//
// Parser context `p` (argument of parse; reads relative to the parse range, cursor starts at 0):
//   p:tell()  p:seek(off)  p:skip(n)  p:size()  p:remaining()  p:eof()
//   Parse at offset (ScriptEngine::parse with base/length, e.g. a PNG embedded in another file):
//   tell/seek/skip/size/remaining/eof/peek and p:field offsets are relative to the range start and
//   reads stop at the range end ("read past end of data"); emitted fields and highlights use
//   absolute document offsets; doc:* calls stay absolute. A whole-document parse has base 0.
//   p:base() -> absolute document offset of the range start: doc:read(p:base() + p:tell(), n).
//   p:endian("le"|"be")                 -- default endianness for u16/u32/... without suffix
//   Typed readers: read at tell(), advance, emit a field, return the value:
//     p:u8/i8/u16/i16/u24/i24/u32/i32/u64/i64/f32/f64(name, opts?)  (+ "le"/"be" suffixed variants,
//                                                                 e.g. p:u32be("length"))
//     p:read(fmt, name, opts?)          -- any string.unpack format, e.g. p:read(">I3", "len24")
//                                          (variable-length values such as s4 / z: up to 16 MiB)
//     p:bytes(name, n, opts?) -> string|nil  (returns the bytes when n <= 64 KiB, else nil)
//     p:str(name, n, opts?) -> string       p:cstr(name, opts?) -> string (NUL-terminated, max 64 KiB)
//     p:uleb(name, opts?) / p:sleb(name, opts?)  -- LEB128 varints
//   Structure:
//     p:struct(name, fn, opts?) -> fn's return value   (size = bytes consumed by fn)
//     p:array(name, count, fn(i), opts?)            (children labelled name[i], i from 0)
//                                                   -> table of fn's first return values
//     p:field(name, off, size, value_text, opts?)    (manual field, does not move the cursor)
//     p:label(text)                                 (display text of the innermost open struct)
//     p:note(text)                                  (comment on the last emitted field)
//   Non-emitting:  p:peek(fmt) -> values (string.unpack at tell()),  p:peekbytes(n) -> string
//   opts = { color=, comment=, enum={[1]="HELLO", ...}, fmt="hex"|"dec"|"bin"|"char" }
//          (enum may also be written name->value: {HELLO=1}; a struct's color is inherited by its
//           fields that have no color of their own)
//   Numeric fields (typed readers / p:read) are EDITABLE in the Structure panel: the new value is
//   range-checked, encoded with the field's own pack format and written back (enum names, char
//   literals like 'IHDR', and hex/bin bit patterns for signed fields accepted).
//   Limits: 200,000 fields; a parse is aborted after ~2 s (instruction-count hook) - the partial
//   tree is kept and the error (with script file:line) is shown in the console.
//
// Console REPL: input is first tried as `return <input>` (results printed), then as a statement.
// Predefined each time: `doc` (active Doc or nil), `cur` (cursor), `sel` = {start=, len=}.
// A command's edits to the active document form ONE undo step ("Script: <name>"). Script load,
// commands and console lines are stopped after 10 s, detect() after 1 s (same hook as parse).
// The time limit cannot be caught: once it fires, every further Lua instruction raises again.
// ===========================================================================================
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/document.h"
#include "core/highlight.h"

struct lua_State;

namespace hx {

struct ConsoleLine {
    enum Kind : uint8_t { Info, Warn, Error, Input, Result };
    Kind kind = Info;
    std::string text;
};

struct Field {
    std::string name;      // "length", "chunk[3]"
    std::string type;      // "u32be", "bytes", "str", "struct", "array", "custom", ">I3" ...
    std::string value;     // display text ("13 (0xD)", "IHDR", "89 50 4E 47 ...", enum name)
    std::string comment;
    uint64_t offset = 0;
    uint64_t size = 0;
    uint32_t color = 0;    // packed rgba (core/highlight.h); always set (auto palette if omitted)
    int parent = -1;
    int depth = 0;
    std::vector<int> children;
    std::string pack;      // string.pack format used to (re)encode; "" = not editable
    bool editable() const { return !pack.empty(); }
    // Enum names (sorted by value) when the field was read with opts.enum; null otherwise.
    // Shared by all fields that used the same enum table. Handy for a combo box in the UI.
    struct EnumItem {
        int64_t value = 0;
        std::string name;
    };
    std::shared_ptr<const std::vector<EnumItem>> enums;
};

struct ParseResult {
    std::string parser;              // parser name that produced this ("" = none)
    std::vector<Field> fields;       // flat, parents before children; roots have parent == -1
    HighlightSet highlights;         // leaf fields (no children) as colored ranges, finalized
    std::string error;               // "" on success
    bool truncated = false;          // hit the field limit
    double ms = 0.0;
    uint64_t doc_generation = 0;     // Document::generation() it was computed for
};

struct ParserInfo {
    std::string name;
    std::string file;                // script file path
    std::vector<std::string> extensions;
};

struct ScriptCommand {
    std::string name;
    std::string description;
    std::string file;
};

// Implemented by the application so scripts can reach documents and the UI.
class ScriptHost {
public:
    virtual ~ScriptHost() = default;
    virtual Document* active_document() = 0;
    virtual Document* find_document(uint64_t id) = 0;  // nullptr if closed
    virtual Document* open_bytes(const std::string& name, const uint8_t* data, size_t len) = 0;
    virtual void reveal(Document& doc, uint64_t offset, uint64_t len) = 0;  // select + scroll into view
};

class ScriptEngine {
public:
    explicit ScriptEngine(ScriptHost* host);
    ~ScriptEngine();
    ScriptEngine(const ScriptEngine&) = delete;
    ScriptEngine& operator=(const ScriptEngine&) = delete;

    // Directories scanned in order (later ones override parsers/commands with the same name).
    void set_script_dirs(std::vector<std::string> dirs);
    void reload();                 // fresh lua_State, run every script; errors go to the console
    bool poll_hot_reload();        // cheap mtime check (call ~once per second); true if reloaded
    uint64_t reload_count() const { return reload_count_; }
    // Runs `lua` in the current state as if it were one more script file named `chunk_name`
    // (hx.parser / hx.command register as usual, replacing same-named ones). Not persisted: the
    // next reload() forgets it. Used for one-off generated parsers (C struct -> "Apply at cursor").
    // Errors (syntax / runtime, with traceback) go to *err and the console.
    bool run_source(const std::string& lua, const std::string& chunk_name, std::string* err);

    // ---- console --------------------------------------------------------------------------
    void exec(const std::string& code);  // REPL line (echoed as Input)
    void log(ConsoleLine::Kind kind, const std::string& text);
    const std::deque<ConsoleLine>& console() const { return console_; }
    void clear_console();
    uint64_t console_generation() const { return console_gen_; }  // bumps on every new line

    // ---- parsers ---------------------------------------------------------------------------
    const std::vector<ParserInfo>& parsers() const { return parsers_; }
    // First parser whose detect(doc) returns true, else first whose extensions match the path, else "".
    std::string detect_parser(Document& doc);
    ParseResult parse(Document& doc, const std::string& parser_name);
    // Parse at offset: runs the parser over [base, base+length) (length UINT64_MAX = to EOF;
    // clamped to the document). The parser sees that range as its whole input (p:tell() == 0 at
    // `base`); Field::offset and highlights are absolute. detect() is not involved.
    ParseResult parse(Document& doc, const std::string& parser_name, uint64_t base, uint64_t length);
    // Serializer: encode `text` with the field's pack format (or enum name) and overwrite the
    // field's bytes in `doc` (one undo step).
    bool edit_field(Document& doc, const Field& field, const std::string& text, std::string* err);

    // ---- commands & highlights ---------------------------------------------------------------
    const std::vector<ScriptCommand>& commands() const { return commands_; }
    // Runs the command on a coroutine; refused (console error) while a prompt is pending.
    void run_command(const std::string& name);

    // ---- hx.prompt ---------------------------------------------------------------------------
    // A command waiting in hx.prompt. The UI shows a modal (title, hint, a text field preset with
    // default_text) while pending_prompt() is non-null and calls answer_prompt() once: the text on
    // OK/Enter, nullptr on Cancel/Escape. answer_prompt resumes the command synchronously (it may
    // prompt again, so re-check pending_prompt() afterwards); errors go to the console.
    struct PendingPrompt {
        std::string title, default_text, hint;
        std::string command;   // name of the waiting command
    };
    const PendingPrompt* pending_prompt() const;  // nullptr if none
    void answer_prompt(const std::string* text);  // no-op without a pending prompt

    // Time limit for script load, commands and console lines (default 10 s; tests lower it).
    void set_script_time_limit_ms(int ms);
    // Ranges created with hx.highlight(); app passes them to the hex view as a layer.
    const HighlightSet* script_highlights(uint64_t doc_id) const;  // nullptr if none

    ScriptHost* host() const { return host_; }
    struct Impl;  // private Lua glue (script/lua_api.cpp)

private:
    void add_lib_paths();

    ScriptHost* host_;
    std::unique_ptr<Impl> impl_;
    std::vector<std::string> dirs_;
    std::vector<ParserInfo> parsers_;
    std::vector<ScriptCommand> commands_;
    std::deque<ConsoleLine> console_;   // capped at 5000 lines
    uint64_t console_gen_ = 0;
    uint64_t reload_count_ = 0;
    std::unordered_map<uint64_t, HighlightSet> highlights_;
    friend struct Impl;
};

}  // namespace hx
