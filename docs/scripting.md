# Scripting Hexer with Lua

Hexer embeds **Lua 5.5**. Scripts can

* **parse** binary formats and protocols into a structure tree with colored hex highlights,
* **edit** parsed values in place (the parser doubles as a serializer),
* add **commands** to the command palette (Ctrl+Shift+P) and the Scripts menu,
* drive everything from an interactive **console** (REPL).

The bundled examples in `scripts/examples/` are the best reference. Start with
`tlv_protocol.lua`: it covers parsing and generating a custom protocol end to end.

---

## Where scripts live

| Location | What it is |
|---|---|
| `<hexer>/scripts/` | Bundled scripts (next to the executable; `scripts/` in the source tree for dev builds) |
| `<config>/scripts/` | **Your** scripts. `%APPDATA%\Hexer\scripts` on Windows, `~/.config/hexer/scripts` on Linux |

* Every `*.lua` file in those folders, subfolders included, runs at startup. Bundled scripts
  run first, then yours. Within a folder, files run sorted by relative path.
* If a parser or command has the **same name** as an earlier one, the later one replaces it. To
  override a bundled parser, register one with the same `name` in your own folder.
* Files under `<dir>/lib/` are **modules**. They don't run on their own; load them with
  `require("name")`, which finds `<dir>/lib/name.lua`. Put shared helpers there.
* **Hot reload:** saving, adding or removing any `.lua` file (lib modules too) reloads all
  scripts into a fresh Lua state within about a second. The console then says
  `Reloaded N scripts (...)`. Script errors are printed with `file:line` and a traceback.
  A broken script never stops the others from loading.

---

## Tutorial: a parser for a custom protocol in 20 lines

Say you captured messages that look like `AB 01 00 05 'h' 'e' 'l' 'l' 'o' 3C`: a magic byte,
a type, a big-endian length, the payload, and a checksum. Save this as
`<config>/scripts/myproto.lua`:

```lua
local TYPES = { [1] = "TEXT", [2] = "PING" }

hx.parser {
    name = "My protocol",
    extensions = { "myp" },                                  -- used when detect() says no
    detect = function(doc) return doc:u8(0) == 0xAB end,     -- cheap magic check
    parse = function(p, doc)
        p:endian("be")                                       -- default for u16/u32/...
        p:u8("magic", { fmt = "hex", color = "gray" })
        local t = p:u8("type", { enum = TYPES })
        local len = p:u16("length")
        if TYPES[t] == "TEXT" then p:str("text", len) else p:bytes("payload", len) end
        local sum = p:u8("checksum", { fmt = "hex" })
        local data = doc:read(0, 4 + len)
        local s = 0
        for i = 1, #data do s = s + data:byte(i) end
        p:note((s & 0xFF) == sum and "checksum OK" or "checksum BAD")
    end,
}
```

Save the file, open a capture, and the Structure panel fills in. Hover a byte to see its field
and click a field to select its bytes. Double-click the `type` value and type `PING` (or `2`) to
rewrite the byte; Ctrl+Z undoes it.

---

## Parser reference

```lua
hx.parser {
    name = "...",                    -- unique; shown in the parser picker
    extensions = { "png", ... },     -- optional, fallback when no detect() matches
    detect = function(doc) ... end,  -- optional, return true if this parser applies
    parse = function(p, doc) ... end,
}
```

Detection order: the first parser whose `detect(doc)` returns true, otherwise the first whose
extension matches the file name.

### The parser context `p`

The cursor starts at offset 0. Typed readers read at the cursor, advance it, **emit a field**
(tree entry + highlight) and **return the value**.

| Call | Notes |
|---|---|
| `p:tell()` `p:seek(off)` `p:skip(n)` | cursor; `skip` may be negative; seeking past the end is an error |
| `p:size()` `p:remaining()` `p:eof()` | |
| `p:endian("le"\|"be")` | default for readers without a suffix; returns the current one |
| `p:u8 i8 u16 i16 u24 i24 u32 i32 u64 i64 f32 f64 (name, opts?)` | default endianness |
| `p:u16le(name)`, `p:u32be(name)`, ... | explicit endianness (`le`/`be` suffix on every multi-byte type) |
| `p:read(fmt, name, opts?)` | any `string.unpack` format, e.g. `p:read(">I3", "len24")`; returns all values. Variable-length values (`s4`, `z`, ...) may be up to 16 MiB |
| `p:bytes(name, n, opts?)` | raw bytes; returns the string if `n` <= 64 KiB, else `nil` |
| `p:str(name, n, opts?)` | fixed-length string (max 16 MiB) |
| `p:cstr(name, opts?)` | NUL-terminated (max 64 KiB); the field includes the NUL |
| `p:uleb(name, opts?)` `p:sleb(name, opts?)` | LEB128 varints |
| `p:struct(name, fn, opts?)` | groups the fields `fn(p)` emits; size = bytes consumed; returns `fn`'s results |
| `p:array(name, count, fn, opts?)` | calls `fn(i)` for i = 0..count-1; the first field each call emits is named `name[i]`; returns a table of `fn`'s first results |
| `p:field(name, off, size, text, opts?)` | manual field anywhere; does not move the cursor |
| `p:label(text)` | display text of the innermost open struct/array |
| `p:note(text)` | adds a comment to the last emitted (or just closed) field |
| `p:peek(fmt)` | `string.unpack` at the cursor, no field, cursor unchanged |
| `p:peekbytes(n)` | bytes at the cursor (clamped to the end), no field |

`opts` (all optional):

| Key | Meaning |
|---|---|
| `color` | `"red"`, `"#ff8800"`, `0xff8800`, or a value from `hx.color`. Without one, fields get palette colors in order. A struct's color is inherited by its fields that don't set their own. |
| `comment` | shown next to the field |
| `enum` | `{ [1] = "HELLO", [2] = "BYE" }` (or `{ HELLO = 1 }`): value shown as `1 = HELLO` |
| `fmt` | integer display: `"hex"` (`0x0D`), `"dec"` (`13`), `"bin"` (`0b00001101`), `"char"` (`'A' (65)`) |

Default integer display is `13 (0xD)`; values below 10 show as plain `7`. u64 values are shown
unsigned. (In Lua they are plain integers, so values >= 2^63 come out negative.) Bytes show
the first 16 bytes in hex followed by `…`. Strings are shown quoted, with escapes.

### Editing (serializer for free)

Every field from a typed reader, or from `p:read` with a single numeric format, is **editable**
in the Structure panel. The new text is parsed as decimal, `0x` hex, `0b` binary, a float for
`f32`/`f64`, an enum name (case-insensitive), or a char literal such as `'IHDR'` (most
significant byte first, like `fmt = "char"` shows it). For signed fields, hex and binary also
take the bit pattern (`0xFF` in an `i8` is -1). The value is range-checked, encoded with the field's
`string.pack` format (`>I2`, `<i4`, `<d`, ...) and written over the field's bytes as one undo
step. Derived data such as checksums is *not* updated automatically. Re-parse and the parser's
check (see `png.lua`) shows the mismatch, or write a command that fixes it (see below).

### Limits and errors

* At most **200,000 fields** per parse. Past that, the tree is marked truncated and the parse
  stops.
* A parse is stopped after about **2 seconds** (detect: 1 s; scripts, commands, console: 10 s).
* Reading past the end raises `read past end of data at 0x...`.
* On any error **the partial tree is kept**: open structs are closed at the cursor. The error,
  with `file:line`, appears in the Structure panel and, with a traceback, in the console.
* Guard against damaged input instead of failing:
  `if len > p:remaining() then p:bytes("data (truncated)", p:remaining()) return end`.

---

## Doc API

`doc` objects are handles to open tabs. If the tab was closed, every call raises
`document closed`.

| Call | |
|---|---|
| `doc:size()` `doc:name()` `doc:path()` `doc:id()` | |
| `doc:read(off, len)` | string, clamped to the end; at most 64 MiB per call |
| `doc:u8(off)` `doc:i8(off)` `doc:u16le/u16be/i16le/i16be/u24le/u24be/u32le/u32be/i32le/i32be/u64le/u64be/i64le/i64be/f32le/f32be/f64le/f64be(off)` | number, or `nil` past the end |
| `doc:write(off, bytes)` | overwrite (may extend at the end) |
| `doc:insert(off, bytes)` `doc:erase(off, len)` `doc:replace(off, len, bytes)` | |
| `doc:transaction(fn, label?)` | every edit inside `fn` becomes **one** undo step, even if `fn` errors. Inside a command, which already is one step (`Script: <name>`), a label renames that step (the innermost label wins: Edit > Undo shows "Undo Append TLV") |
| `doc:cursor()` `doc:selection()` → start, len | |
| `doc:select(off, len)` `doc:jump(off)` | moves the selection/cursor and scrolls it into view (`doc:goto` also exists, but `goto` is a Lua keyword: call it as `doc["goto"](doc, off)`) |
| `doc:find(needle, start?, {hex=bool, backward=bool})` | offset or `nil`; `hex=true` takes patterns like `"DE ?? AD"` |

All edits are undoable. They fail with an error on read-only documents (`document is read-only`)
and while a save is running.

---

## The `hx` table (also `hexer`)

| Call | |
|---|---|
| `hx.version` | `"0.1.0"` |
| `hx.parser{...}` `hx.command{...}` | registration (see above / below) |
| `hx.run(name)` | runs a registered command exactly like the palette (one undo step on the active document); handy with `hexer --exec` |
| `print(...)` `hx.log(...)` `hx.warn(...)` `hx.error(...)` | console output; tables are pretty-printed. `hx.error` only logs, it does not raise. |
| `hx.inspect(v, depth?)` | readable dump: nested and sorted, cycle-safe, strings quoted. `depth` is 1..64 (default 6); output stops after about 1 MiB |
| `hx.clear_console()` | |
| `hx.doc()` | active document or `nil` |
| `hx.new_doc(name, bytes)` | opens the bytes in a new tab and returns its Doc |
| `hx.highlight(doc, off, len, color?, label?)` / `hx.clear_highlights(doc)` | extra colored ranges in the hex view |
| `hx.color(c)` | packed color from a name, `"#rrggbb"` or `0xRRGGBB`. Names: red green blue yellow orange purple cyan pink gray teal white |
| `hx.hex(s)` → `"DE AD"` / `hx.unhex("de:ad")` → bytes | `unhex` is as lenient as paste: `0x`, commas, `\x`, `b64:` |
| `hx.crc32(s, prev?)` | zlib/PNG/ZIP CRC-32; pass the previous result to continue over chunks |
| `string.pack` / `string.unpack` | standard Lua, the recommended way to (de)serialize |

`os.exit` and stdin are disabled: Hexer has no stdin (`io.read`, `io.lines()`, `io.stdin`,
`loadfile()` / `dofile()` without a file name raise), and a stray `os.exit()` must not close the
editor. File names are UTF-8 everywhere, also on Windows (`io.open`, `io.lines`, `loadfile`,
`dofile`, `require`; in hexer.exe, whose manifest selects the UTF-8 code page, also `os.rename`,
`os.remove` and `package.loadlib`). A `__gc` finalizer runs under a 1 s limit of its own.

---

## Commands and the serializer pattern

```lua
hx.command {
    name = "My protocol: build TEXT message",
    description = "shown in the palette",
    run = function(doc)                       -- active document or nil
        local text = my_text or "hello"       -- no prompts: use globals set from the console
        local body = string.pack(">BBs2", 0xAB, 1, text)   -- s2 = u16be length + bytes
        local sum = 0
        for i = 1, #body do sum = sum + body:byte(i) end
        hx.new_doc("message.myp", body .. string.char(sum & 0xFF))
    end,
}
```

* A command runs as **one undo step** on the active document.
* To patch a structure in place (insert a record, then fix the length and CRC), wrap the edits
  in `doc:transaction(function() ... end)`. See "HXP: append TLV record at cursor" in
  `tlv_protocol.lua`.
* Commands can't ask for input. Read a global with a default (`hx_xor_key = hx_xor_key or 0xFF`)
  and set it from the console (`hx_xor_key = 0x5A`).

---

## Console tips

* Type an expression and its value is printed: `doc:u32le(cur)` prints `305419896 (0x12345678)`.
  Statements work too: `for i = 0, 3 do print(doc:u8(i)) end`.
* Predefined before each line: `doc` (active document), `cur` (cursor offset),
  `sel` (`{start=, len=}`).
* `hx.hex(doc:read(sel.start, sel.len))` dumps the selection; `doc:find("IDAT")` finds bytes.
* Tables print readably: `{ a = 1, list = { 1, 2, 3 } }`.
* Prototype a parser in a file and keep it open in your editor: every save hot-reloads it.
* Commands and console code are stopped after 10 s, so an accidental infinite loop does not
  freeze Hexer. `pcall` cannot catch the time limit: once it fires, the script stops.

## Lua 5.5 notes

* `for` loop variables are read-only. Copy one to a local before changing it.
* `global` is a reserved word, so don't use it as a variable name.
* Integer division is `//`, bit operators are `& | ~ << >>`, and integers are 64-bit.
