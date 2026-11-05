# Hexer roadmap

## v1
- [x] Streaming file access (block cache), TB-file support, 64-bit virtual scrolling
- [x] Piece-table editing: overwrite / insert / delete / fill / paste, insert-overwrite toggle (Ins)
- [x] Full undo/redo history (Ctrl+Z / Ctrl+Y) for all content + bookmark changes; survives saves and restarts
      (typing, paste, cut, fill, inspector edits, structure field edits, script commands, bookmarks)
- [x] Save: fast in-place patching when size-preserving, otherwise temp-file + atomic rename; progress + cancel
- [x] Hot exit / crash recovery (Sublime-style session), restore tabs, cursor, scroll, bookmarks, history
- [x] External change detection (reload banner)
- [x] Single instance (Sublime-like): a second `hexer` hands its files to the running window (`--new-instance` opts out)
- [x] Dark theme, system fonts, zoom (Ctrl +/- / Ctrl+wheel), dockable panels
- [x] Tabs, drag & drop, recent files, command-line files, reopen closed tab (Ctrl+Shift+T)
- [x] Command palette (Ctrl+Shift+P) incl. script commands
- [x] Data inspector (LE/BE, ints, floats, LEB128/zigzag, time formats, GUID, chars), editable
- [x] Smart Goto (Ctrl+G): hex/dec, relative, %, end-N, expressions
- [x] Search (Ctrl+F, F3/Shift+F3): hex with `??`, text, UTF-16, case-insensitive; background; find-all list
- [x] Copy as (hex, C array, Python bytes, Base64, escaped); lenient paste parsing
- [x] Bookmarks with names and notes (Ctrl+B, F2 / Shift+F2), persisted; Bookmarks panel (this file /
      all open files, preview bytes), Bookmarks menu, Ctrl+Shift+B quick jump, scrollbar ticks
- [x] Backup of the original on the first save (`<file>.backup`, never overwritten; hard link / rename for rewrites, fast copy for in-place, size limit)
- [x] Settings window (Edit > Settings..., Ctrl+,): view, undo grouping, backups, session, fonts
- [x] Typing undo grouping limits (pause / bytes per step)
- [x] One selection convention: caret drawn inside the selection, Inspector/status at the first
      selected byte, inclusive ranges everywhere; headless UI tests for mouse/keyboard input
- [x] Script prompts (`hx.prompt`) with a modal dialog; XOR-with-key asks for the key
- [x] Lua scripting: parsers → structure tree + colored highlights, editable fields (serializer),
      commands, console REPL, hot reload, example scripts
- [x] Status bar: offset hex/dec, selection, size, INS/OVR, parser, save progress

### v1 still to verify by hand
Covered by unit tests and screenshot runs, but not yet exercised with real mouse/keyboard input:
- [ ] Keyboard shortcut routing while text fields have focus (Ctrl+Tab, Ins, F2/F3)
- [ ] Double-click editing in Inspector / Structure / Bookmarks, tab drag reordering, Ctrl+wheel zoom
- [ ] Native file dialogs, drag & drop, long saves with Cancel, the external-change banner
- [x] Linux build (CI compiles and tests linux-gcc + linux-clang on every push, 0 warnings)

### User feedback fixes
- [x] App icon consistent at every size (16/24/32 px hand-drawn pixel art of the same pointy-top
      hexagon and "101" as the large sizes; `tools/make_icon.py`)
- [x] Follow pointer type picked in the Inspector: clicking an integer row (int8..uint64, 24-bit
      too) sets width + signedness (byte order = LE/BE), the row is marked and its bytes are
      outlined in the hex view; signed and relative pointers; Structure fields follow as their own type

## Later
- [x] History panel (View > History: every undo state with its label and changed range; click to
      undo / redo to it; "saved" tag)
- [ ] History: relative time per entry (UndoEntry has no timestamp yet; needs the session format)
- [ ] Undo for the remaining view-level actions that benefit from it (read-only toggle, chosen parser)
- [x] Hashes & checksums of selection (Hashes panel: 16 CRCs/checksums/hashes, background, expected
      value match; `hx.hash` / `doc:hash`)
- [ ] Custom hash algorithms registered from Lua (`hx.hash_algorithm{...}`)
- [x] Entropy / byte-class minimap next to the scrollbar (View > Minimap: Off / Entropy / Byte Classes;
      background sampled scan, rescanned 1 s after edits; click / drag scrolls)
- [x] Minimap: rescan only the buckets an edit touched (`EntropyJob::rescan`: the piece lists of
      the last scan and the new snapshot are compared; overwrites rescan their buckets, an insert /
      delete rescans from the edit on, a new bucket layout / process memory / a save rescans all)
- [ ] Minimap: small regions inside huge sampled buckets can be missed (sampling); rescan
      process memory incrementally (its bytes change underneath, today it is always rescanned)
- [x] Structure → C header export (Structure panel "C Header" / row context menu: packed typedefs,
      deduped layouts, arrays, enums, bit fields, padding, static_asserts, `// @be`; converts back
      through C struct → parser to the same tree)
- [x] Bit-field / flags display in the Inspector (Bits row: a 0/1 toggle per bit at the selected
      integer row's width, undoable flips; Lua `opts.flags` names bits: "3 = READ|WRITE")
- [ ] C header export: emit `#define` masks for flags; char fields (`fmt = "char"`) as `char`;
      mixed-endianness structs (today: majority wins, the rest only get a BE comment)
- [x] Diff/compare two files with synced scrolling (File > Compare With: a Compare tab, F7 / Shift+F7,
      shift for inserted headers, "Align at Cursors")
- [x] Compare: keep the Compare tab (documents + shift) in the session
- [x] Compare: find the shift automatically ("Compare: Find Shift": a distinctive 64-byte block
      after the first difference, rolling-hash search within +-16 MiB, background job); compare a
      document with its version on disk (Compare With > File on Disk, reloads after saves; session)
- [ ] Compare: Find Shift for the next misalignment too (today it aligns at the first difference;
      a change followed by an insertion reports "no shift found")
- [x] Headless tests for DiffView / PacketsPanel / BitmapPanel (view_diff, panel_packets and
      panel_bitmap moved to hexer_ui_view; test_diffview, test_panels)
- [x] Open process memory and raw disks/devices (File > Open Process... / Open Disk..., Regions
      panel, read-only unless asked, in-place saves of overwrites, `doc:target()` / `doc:pid()`)
- [x] Process memory: Search / Strings / XOR search / minimap / Hash skip unreadable holes
      ("X unreadable skipped"); Inspector shows ?? for unreadable bytes
- [ ] Process memory: default the follow-pointer width to the process's pointer size; module
      list / jump to a module's base from the palette; Lua `hx.open_process(pid)`
- [x] Compile and test core/procmem.cpp + core/devices.cpp on Linux (/proc/PID/mem, /sys/block)
- [ ] Verify by hand: Open Process / Open Disk pickers, writable process save, the Regions click
      (screenshots only so far)
- [x] pcap/pcapng: Packets panel (index in the background, filter, "Parse with" a parser over each
      packet or its payload, Up / Down steps and re-parses); auto-shown for captures
- [ ] Packets: open a packet / TCP stream as its own tab, filter expressions (ip.src == ...)
- [x] Split view of the same document (View > Split View, Ctrl+\, F6; kept in the session)
- [ ] Multi-selection
- [x] C struct → parser: paste C definitions, get a Lua parser (apply at the cursor or save it)
- [x] Parse at offset (Structure panel "Parse at", e.g. a PNG inside a dump)
- [x] Remember the parse offset in the session (Parse at offset / range per tab)
- [x] Follow pointer: Ctrl+click / Ctrl+Enter, width + base + byte order settings, Inspector /
      Structure buttons; jump history (Alt+Left / Alt+Right, mouse back / forward)
- [x] Strings panel (ASCII / UTF-16, min length, background scan, click to jump, live filter)
- [x] Strings: deduplicate an ASCII-in-UTF-16 string found again shifted by one byte when both
      UTF-16LE and UTF-16BE are on (the shorter reading is dropped; equal length: LE is kept)
- [ ] Verify by hand: Ctrl+hover underline / tooltip and mouse X1/X2 (headless tests only)
- [x] Bitmap view: render bytes as pixels (adjustable width / pixel format) to spot tables & images
      (View > Bitmap; format / width / zoom remembered in settings.ini)
- [ ] Bitmap: zoom below 1x (downscale) for very wide images; remember the source mode
- [x] Byte-class coloring mode (zero / printable / whitespace / control / high bytes; View > Color
      Bytes by Class)
- [x] Disassembly at cursor: x86-64 / x86-32 (Zydis), Disassembly panel following the caret,
      PE / ELF / manual address maps, resolved branch + RIP-relative targets (follow = jump
      history), Go to Entry Point, backward scrolling (disasm_sync_back), `hx.disasm` / `doc:disasm`
- [x] Disassembly: symbol names (PE exports / imports / delay imports, ELF symtab / dynsym,
      @plt / @got from JUMP_SLOT relocations) as labels and for branch / call / IAT targets,
      nearest symbol + offset in the tooltip, Go to Symbol list, `doc:symbols()`; map choice / base /
      pinned start per tab in the session; panel options are real Settings members (checked
      against dumpbin on kernel32.dll: 1698 exports / 211 forwarded / 1292 imports, all equal)
- [ ] Disassembly: branch arrows; a "Find references to" scan; PDB / DWARF names; i386 PIC PLT
      (jmp [ebx+X]) @plt names; symbols for a Manual base over a PE / ELF image (today: none)
- [ ] Disassembly: other architectures (ARM / AArch64) only if asked (Zydis is x86 only)
- [x] Live tail mode for growing files (captures, logs): View > Live Tail, follows the end while the
      caret is there, a rewrite falls back to the "changed on disk" banner
- [x] Live tail: remember the toggle in the session
- [ ] Live tail: rescan the Packets index incrementally while a capture grows
- [x] XOR / rotate brute-force helpers to find simple obfuscation (XOR Search panel: known
      plaintext with 1-byte XOR / ADD / ROL and 2..16-byte XOR keys, key guess, undoable decode)
- [x] XOR search: Lua API (`hx.xor_scan(doc, plaintext, opts)` up to 256 MiB per call,
      `hx.xor_guess_key(doc, off, len, opts)` up to 16 MiB)
- [ ] XOR search: multi-byte ADD keys; a Lua binding for the undoable decode (`apply_transform`)
- [x] Script API: `doc:view_range()` (visible bytes); bookmark access from Lua (`doc:bookmarks()`,
      `doc:add_bookmark`, `doc:remove_bookmark`, undoable)
- [x] "Restore from .backup" (File menu, when `<file>.backup` exists): Compare with Backup side by
      side, Revert to Backup = one undoable edit referencing the backup file (nothing copied;
      disk untouched until Save; the .backup stays the original)
- [ ] Revert to Backup: hot exit keeps a revert only up to 16 MiB (the session format has no second
      file source; above that Hexer asks on exit) - store "whole file = <path>" pieces in the session
- [ ] Live font reload from the Settings window (font file / hinting changes need a restart now)
- [x] Settings: remember the Bookmarks panel's "All open files" toggle
- [ ] Headless App-level tests (session extras round trip of split / tail / parse at / Compare,
      the History and XOR panels' clicks): app.cpp is not linked by any test exe yet
- [x] Linux CI (linux-gcc + linux-clang build and test on every push, 0 warnings)
- [x] AppImage + Linux tar.gz; Windows portable zip (CI artifacts on every push, GitHub Release on
      `v*` tags; each package is smoke-tested with its own bundled scripts)
- [ ] Linux packages: AppStream metainfo in the AppImage; an aarch64 build
- [x] Compile the visual-analysis / compare / capture batch with GCC and Clang (-Wall -Wextra,
      green in CI)
- [ ] Run parsers on a worker thread over a Snapshot (a parse slower than ~50 ms is currently
      not re-run after edits; the Structure panel shows it as stale until F5)

## Known limitations / tech debt
- Each undo entry stores a full copy of the piece list; thousands of scattered edits combined with
  a long history use a lot of memory. Sharing piece vectors between entries would fix it.
- The session rewrites a document's whole `.hxs` file (including pasted bytes) on every change;
  an append-only chunk store would scale better for hundreds of MiB of pasted data.
- The hex view is replaced by a progress placeholder while that document is being saved.
- Script time limits only interrupt Lua code, not one long C call (e.g. `string.rep` of gigabytes).
- `__gc` assigned to a metatable after `setmetatable` runs without the script time limit.
- Single instance: bringing the running window to the front can be refused by Windows' foreground
  rules when the second `hexer` was not started from the foreground (the taskbar button flashes).
