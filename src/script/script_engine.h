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
//   hx.version                          "1.1.0"
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
//   hx.open_process(pid, {writable=false}?) -> Doc | nil, err   -- the memory of process `pid` in a
//       tab (read-only unless writable; an open tab of that process is reused when it is writable
//       or writable was not asked for). nil + message when it cannot be opened (no such process,
//       access denied: needs administrator / ptrace rights)
//   hx.highlight(doc, off, len, color, label?)  /  hx.clear_highlights(doc)
//   hx.color(c) -> packed int          -- c: "red"|"#ff8800"|0xff8800 (named: red, green, blue,
//                                         yellow, orange, purple, cyan, pink, gray, teal)
//   hx.hex(str) -> "DE AD BE EF"   hx.unhex("de ad be ef") -> str (lenient, like paste)
//   hx.crc32(str, prev?) -> int       -- zlib/PNG/ZIP CRC-32; pass `prev` to continue over chunks
//   hx.hash(algo, str) -> "cbf43926"   -- lowercase hex digest; algo: any of hx.hash_algorithms()
//                                         (case and punctuation ignored: "sha256", "CRC-32C", "md5")
//   hx.hash_algorithms() -> {"Sum-8", "XOR-8", "CRC-8", ..., "SHA-256", "SHA-512", <Lua ones>}
//   hx.hash_algorithm{ name=, init=function() -> state, update=function(state, bytes) -> state?,
//       final=function(state) -> hex string }   -- a custom hash / checksum, usable everywhere a
//       built-in is: hx.hash, doc:hash, hx.hash_algorithms() and the Hashes panel. init() returns
//       the state for one run (any value: a table, an integer...); update(state, bytes) gets the
//       data in order, in chunks of any size (up to 4 MiB), and returns the new state (nil keeps
//       the old one: tables are updated in place); final(state) returns the digest as hex
//       (case, spaces, ':' / '-' and a leading 0x ignored; e.g. string.format("%08x", h)).
//       name: not a built-in's (after ignoring case and punctuation), no ','; a later
//       registration with the same name replaces it. The Hashes panel runs it on a worker
//       thread in a Lua state of its own that ran only its script file (as background parses
//       do: no globals of other scripts, print output is dropped; algorithms defined in the
//       console cannot run there), each update() under the script time limit; errors show in
//       the panel and once in the console. Plain Lua handles roughly 10-50 MB/s.
//         hx.hash_algorithm{ name = "Sum-16", init = function() return 0 end,
//           update = function(s, b) for i = 1, #b do s = s + b:byte(i) end return s & 0xFFFF end,
//           final = function(s) return string.format("%04x", s) end }
//   hx.disasm(bytes, address?, mode?) -> list of instructions (x86-64, or mode 32 / "x86" for
//       32-bit code; address = of the first byte, default 0; at most 10000 per call), each
//       { address=, offset= (0-based in bytes), length=, text=, bytes=, valid=, target=?, flow=? }:
//         text   "mov rax, qword ptr [rip+0x2a]  ; 0x1031" (Intel, lowercase; RIP-relative
//                operands get the resolved address as a comment), "call 0x1105", "db 0x06" for
//                an invalid byte (valid = false, length 1)
//         target branch target or RIP-relative / absolute memory address (nil if none)
//         flow   "call" | "jmp" | "jcc" | "ret" | "int" (int / int3 / syscall) | nil
//   hx.xor_scan(doc, plaintext, opts?) -> list of hits, by offset: where `plaintext` (raw bytes;
//       use hx.unhex for hex text) occurs XOR / ADD / ROL-encoded (core/xorscan.h), each
//       { offset=, transform="xor"|"add"|"rol"|"xor_key", key= (raw key bytes; rol: one byte = the
//       bit count), phase= (key index of `offset`), text= ("XOR 0x5A", "XOR key 53 45 ...") }.
//       opts = { start=0, length= (to EOF), xor=true, add=true, rol=true, multi=false (2..16 byte
//       XOR keys), add_multi=false (2..16 byte ADD keys: transform "add_key"), max_key_len=16,
//       max=10000 (hits) }. Blocking: at most 256 MiB per call (error
//       beyond; the XOR Search panel scans any size) and stopped at the script time limit.
//   hx.xor_guess_key(doc, off, len, opts?) -> list of { key=, score= (0..1) }, best first: XOR key
//       candidates for [off, off+len) assuming the plaintext is mostly `plain` bytes
//       (opts = { plain=0 (a byte value or a 1-char string, e.g. " " for text), max_len=16,
//       op="xor" | "add" (ADD keys: column byte minus plain) });
//       keys follow the absolute-offset convention of xor_scan. At most 16 MiB per call.
//   string.pack / string.unpack       -- standard Lua; the recommended way to serialize
//
// Doc (userdata; every call raises "document closed" if its tab was closed):
//   doc:size()  doc:name()  doc:path()  doc:id()
//   doc:target() -> "file" | "device" | "process"   doc:pid() -> process id (process memory) | nil
//       (process memory: offset = virtual address, unmapped pages read as 0; fixed size)
//   doc:modules() -> list of { name=, base=, size=, path= } by base: the loaded modules of a process
//       document ("KERNEL32.DLL", load address, image size, full path; Linux: file-backed mappings
//       with an executable part, base = lowest mapping); {} for files / devices; nil, err when the
//       process cannot be queried
//   doc:packets(opts?) -> list, next | nil, "not a pcap / pcapng capture"   -- the packets of a
//       capture (core/pcap.h index + dissector), in file order, each { number= (1-based), offset=
//       (record / block start), data= (first captured byte), length= (captured), wire_length=,
//       payload= (offset of the L7 payload), payload_length= (captured payload bytes), time= (s,
//       float), time_ns= (both nil for SPB), interface= (0-based), linktype=, proto=, src=, dst=,
//       info=, summary= (the Packets panel's columns), vlan=?, ip_version=?, ip_proto=?, src_port=?,
//       dst_port=?, tcp_seq=?, tcp_ack=?, tcp_flags=?, fragment=?, malformed=? } (? = only when the
//       layer was decoded). opts = { filter= (a Packets panel filter expression, core/pcap_filter.h;
//       a bad one raises "doc:packets: filter: <msg> (column N)"), first=1 (packet number to start
//       at), max=10000 (entries, 1..1000000) }. `next` = the number to pass as first for the next
//       page, nil when the capture ended. Not the panel's index: each call indexes the document as
//       it is now, synchronously, from the start up to where the page ends (in 64k-packet chunks),
//       stopped at the script time limit (error); a record cut short at the end ends the list.
//   doc:read(off, len) -> string         (clamped to EOF; at most 64 MiB per call)
//   doc:u8(off) doc:i8(off) doc:u16le/u16be/i16le/i16be/u32le/u32be/i32le/i32be/
//       u64le/u64be/i64le/i64be/f32le/f32be/f64le/f64be(off)  -> number (nil past EOF)
//       (also u24le/u24be/i24le/i24be)
//   doc:write(off, bytes)   doc:insert(off, bytes)   doc:erase(off, len)   doc:replace(off, len, bytes)
//   doc:transaction(fn, label?)          -- all edits inside fn become ONE undo step; inside a
//                                           command (already one step) a label renames that step
//   doc:cursor() -> off     doc:selection() -> start, len     doc:select(off, len)     doc:jump(off) (alias doc["goto"])
//       (`goto` is a Lua keyword: write doc:jump(off), the same function, or doc["goto"](doc, off))
//       doc:select also drops the extra ranges of a multi-selection. Both (and doc:select_ranges)
//       are Back / Forward jumps in the app: the position they leave goes into the tab's history.
//   doc:selections() -> { {offset=, length=}, ... }   -- multi-selection (core/multisel.h): every
//       selected range, the one holding the primary selection first, then the others in file
//       order (overlapping ones merged); {} when nothing is selected
//   doc:select_ranges{ {offset=, length=} | {off, len}, ... }   -- the first range becomes the
//       primary selection (scrolled into view), the others the extra ranges (clamped to the
//       document, merged when they touch); at most 100,000 ranges; {} leaves only the caret.
//       View state, not an undo step (like doc:select)
//   doc:find(needle, start?, {hex=bool, backward=bool}) -> off | nil   (hex=true: "DE ?? AD")
//   doc:hash(algo, off?, len?) -> hex   (default: the whole doc; clamped to EOF; at most 256 MiB per
//                                         call since it blocks - the Hashes panel does any size;
//                                         a Lua algorithm runs here, under the script time limit)
//   doc:apply_transform{ op=, key=, start=?, length=?, phase=?, decode=false, label=? }
//       XOR / ADD / SUB / ROL / ROR bytes in place as ONE undo step (XOR Search's "Decode
//       selection"; core/xorscan.h). op: "xor" | "add" | "sub" | "rol" | "ror" (also xor_scan's
//       "xor_key" / "add_key"); key: a string of key bytes (any length up to 4096: repeated) or a
//       byte value; rol / ror: key = the bit count 1..7 (a number, or xor_scan's 1-byte key
//       string). decode=true applies the inverse (sub for
//       add, ror for rol), so a hit h of hx.xor_scan decodes with { op = h.transform, key = h.key,
//       start = h.offset, length = n, decode = true }. Range: start / length (length default: to
//       EOF), neither given = the selection (error when nothing is selected); at most 256 MiB.
//       phase = key index of `start` (default start % #key: xor_scan's absolute convention). A
//       read-only document, an empty range or an unreadable byte raise; a failure partway changes
//       nothing (inside a command / transaction it rolls back that whole step). label default
//       "Encode <key>" / "Decode <key>" (inside a command or transaction: that step's label).
//   doc:disasm(off, count?, mode?) -> list of instructions like hx.disasm (count default 16, at
//       most 10000; stops at EOF). offset = file offset; address / target use the document's
//       address map (PE / ELF headers: virtual addresses, process memory: = offset, else = offset);
//       entries also get section= (".text") when the map names one. mode defaults to the
//       header's (PE32 / ELF32: 32), else 64. Unreadable bytes are 1-byte "??" entries.
//   doc:symbols() -> list of symbols (core/symbols.h), sorted by address, forwarded exports last:
//       { name=, address=, offset=, kind=, module=, ordinal=?, forward=? }
//         name     "CreateFileW", "#12" (by ordinal only), "puts@plt" / "puts@got" (ELF imports)
//         kind     "export" | "import" | "function" | "object"
//         module   PE: the export / import DLL ("KERNEL32.dll"); ELF: ""
//         address  virtual address (import: its IAT / GOT slot or PLT stub); nil for a forwarder
//         offset   file offset of address (nil when not backed by the file)
//         forward  forwarded export: "NTDLL.RtlAllocateHeap" (then no address)
//       Sources: PE export / import / delay-import directories, ELF .symtab / .dynsym FUNC and
//       OBJECT symbols, JUMP_SLOT / GLOB_DAT relocations; an entry point without a name of its
//       own is function "entry". Process memory: every loaded module's exports / imports from
//       its PE headers as mapped in memory (module = the DLL, e.g. "KERNEL32.dll!CreateFileW";
//       offset = address) plus "entry" per module (Windows; Linux processes: {}). Built
//       synchronously (capped at 1M symbols / ~3 s); {} for other files. Reuses the Disassembly
//       panel's table when it is up to date for the document (Auto map) instead of building.
//   doc:view_range() -> first, last   -- first and last byte visible in the document's hex view
//       (inclusive; as of the last drawn frame), nil when it has no drawn view (headless, empty doc)
//   doc:bookmarks() -> list of { offset=, length=, name=, color= (packed int, 0 = default), note= }
//   doc:add_bookmark(off, len?, name?, color?, note?) -> index   (len default 1, clamped to EOF;
//       color as hx.color takes it; index 1-based)   doc:remove_bookmark(i)  (1-based; error if
//       out of range). Both are undo steps ("Add bookmark" / "Remove bookmark"; inside a command
//       or doc:transaction part of its step) and also work on read-only documents.
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
//          flags = {[0]="READ", [1]="WRITE"}  (bit number -> name, also {READ=0}; integer fields:
//                  value shown as "3 = READ|WRITE", unnamed set bits as "bit9"; edits also take
//                  "READ|WRITE"; the C header export lists the names in a comment)
//          bitfield = {shift=, width=, be=?, signed=?}  (p:field over a bit-field storage unit:
//                  `width` bits from bit `shift` (0 = LSB) of the unit; be = big-endian unit
//                  (C bits allocated from the top). Only for the C header export, which declares
//                  it as `uint32_t name : width;`; C struct -> parser emits it)
//   Numeric fields (typed readers / p:read) are EDITABLE in the Structure panel: the new value is
//   range-checked, encoded with the field's own pack format and written back (enum names, char
//   literals like 'IHDR', and hex/bin bit patterns for signed fields accepted).
//   Limits: 200,000 fields; a parse is aborted after ~2 s (instruction-count hook) - the partial
//   tree is kept and the error (with script file:line) is shown in the console.
//   Background parses: the Structure panel runs parse() on a worker thread (script/parse_job.h),
//   each time in a Lua state of its own that ran only the script file the parser came from (as of
//   the last reload; require() works; it runs again for every parse, so keep its top-level code
//   cheap and free of side effects). So inside parse(): globals set by OTHER script files are
//   not visible (a script that needs one at load time is parsed on the UI thread instead, as are
//   parsers defined in the console); doc reads see the document as it was when the parse started;
//   the doc is read-only there (edits raise "document is read-only"; hx.highlight, doc:select /
//   doc:jump, bookmarks and hx.new_doc have no visible effect); print / hx.log output reaches the
//   console when the result arrives. detect() runs the same way (script/parse_job.h DetectJob:
//   a state per script, the document as of the start, output with the answer), so a slow
//   detect never blocks the UI; parsers that cannot be rebuilt alone detect in the shared
//   state, in their turn. The same rules hold inside detect() (no globals of other scripts).
//
// Console REPL: input is first tried as `return <input>` (results printed), then as a statement.
// Predefined each time: `doc` (active Doc or nil), `cur` (cursor), `sel` = {start=, len=}.
// A command's edits to the active document form ONE undo step ("Script: <name>"). Script load,
// commands and console lines are stopped after 10 s, detect() after 1 s (same hook as parse).
// The time limit cannot be caught: once it fires, every further Lua instruction raises again.
// ===========================================================================================
#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/document.h"
#include "core/hash.h"
#include "core/highlight.h"

struct lua_State;

namespace hx {

class ParseJob;
class DetectJob;
struct SymbolTable;

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
    const char* fmt = "";  // opts.fmt: "", "hex", "dec", "bin" or "char" (static strings)
    bool editable() const { return !pack.empty(); }
    // Enum names (sorted by value) when the field was read with opts.enum; null otherwise.
    // Shared by all fields that used the same enum table. Handy for a combo box in the UI.
    struct EnumItem {
        int64_t value = 0;
        std::string name;
    };
    std::shared_ptr<const std::vector<EnumItem>> enums;
    // Bit names (sorted by bit) when the field was read with opts.flags; null otherwise. The value
    // text then ends in " = READ|WRITE" (script/cexport.h format_flags).
    struct FlagItem {
        int bit = 0;  // 0 = least significant
        std::string name;
    };
    std::shared_ptr<const std::vector<FlagItem>> flags;
    // opts.bitfield: the field is `width` bits at bit `shift` of the integer its bytes hold (read
    // in `big_endian` order). Only used by the C header export (shift -1 = not a bit field).
    struct BitField {
        int shift = -1;
        int width = 0;
        bool big_endian = false;
        bool is_signed = false;
    } bits;
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

struct ScriptHashInfo {             // hx.hash_algorithm
    std::string name;
    std::string file;                // script file path ("<console>" when defined there)
};

// Implemented by the application so scripts can reach documents and the UI.
class ScriptHost {
public:
    virtual ~ScriptHost() = default;
    virtual Document* active_document() = 0;
    virtual Document* find_document(uint64_t id) = 0;  // nullptr if closed
    virtual Document* open_bytes(const std::string& name, const uint8_t* data, size_t len) = 0;
    virtual void reveal(Document& doc, uint64_t offset, uint64_t len) = 0;  // select + scroll into view
    // First and last (inclusive) byte visible in `doc`'s hex view as last drawn; false if it has
    // none (doc:view_range() returns nil). Default: no view (headless hosts).
    virtual bool view_range(Document& /*doc*/, uint64_t& /*first*/, uint64_t& /*last*/) { return false; }
    // A finished symbol table the host already holds for `doc` as it is now under its detected
    // map (the Disassembly panel's), so doc:symbols need not build one; nullptr: none (default).
    virtual std::shared_ptr<const SymbolTable> cached_symbols(Document& /*doc*/) { return nullptr; }
    // hx.open_process: the memory of process `pid` as a document (read-only unless `writable`),
    // e.g. a new tab; nullptr + *err on failure. Default: not supported (headless hosts).
    virtual Document* open_process(uint32_t /*pid*/, bool /*writable*/, std::string* err) {
        if (err) *err = "opening processes is not supported here";
        return nullptr;
    }
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

    // ---- hash algorithms (hx.hash_algorithm) ------------------------------------------------
    const std::vector<ScriptHashInfo>& hash_algorithms() const { return hashes_; }
    // Bumps on every reload and every registration (the Hashes panel refreshes its list).
    uint64_t hash_algorithms_generation() const { return hash_gen_; }
    // The registered algorithms for HashJob (script/lua_hash.cpp): each create() builds a Lua
    // state of its own on the worker that ran only the algorithm's script (as of the last reload /
    // run_source); one that cannot be rebuilt that way reports it through Hasher::error().
    std::vector<CustomHashAlgorithm> custom_hashes() const;

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
    // detect() of one parser on `doc`: 1 = true, 0 = false / no detect function / unknown parser,
    // -1 = error (*err, with traceback). 1 s limit.
    int run_detect(const std::string& parser, Document& doc, std::string* err);
    bool has_detect(const std::string& parser) const;  // the parser's spec has a detect function
    // detect_parser's fallback: the first parser in `list` with an extension of doc's path / name.
    static std::string extension_parser(const std::vector<ParserInfo>& list, const Document& doc);
    // Background jobs (script/parse_job.cpp): turns this fresh engine into a job's Lua state
    // (script dirs for require, `cancel` stops its Lua code, parse errors left to the job), then
    // runs one script as reload() would. False if it does not load on its own.
    bool load_job_script(const std::vector<std::string>& dirs, const std::atomic<bool>* cancel,
                         const std::string& file, const std::string& chunk, const std::string& text);

    ScriptHost* host_;
    std::unique_ptr<Impl> impl_;
    std::vector<std::string> dirs_;
    std::vector<ParserInfo> parsers_;
    std::vector<ScriptCommand> commands_;
    std::vector<ScriptHashInfo> hashes_;
    uint64_t hash_gen_ = 0;
    // custom_hashes()' create(): the algorithm `name` from one script, in a fresh engine.
    static std::unique_ptr<Hasher> make_job_hasher(const std::vector<std::string>& dirs, const std::string& file,
                                                   const std::string& chunk, const std::string& text,
                                                   const std::string& name, const std::atomic<bool>* cancel);
    std::deque<ConsoleLine> console_;   // capped at 5000 lines
    uint64_t console_gen_ = 0;
    uint64_t reload_count_ = 0;
    std::unordered_map<uint64_t, HighlightSet> highlights_;
    friend struct Impl;
    friend class ParseJob;  // script/parse_job.h: background parses in an engine of their own
    friend class DetectJob; // ... and background detect() calls
};

}  // namespace hx
