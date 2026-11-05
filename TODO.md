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
- [x] Backup on the first save (`<file>.backup`; hard link / rename for rewrites, fast copy for in-place, size limit)
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
- [ ] Linux build (POSIX code paths are written but have never been compiled)

## Later
- [ ] History panel (click to jump to any undo state)
- [ ] Undo for the remaining view-level actions that benefit from it (read-only toggle, chosen parser)
- [ ] Hashes & checksums of selection (CRC32, MD5, SHA-1, SHA-256, Adler32; custom via Lua)
- [ ] Entropy / byte-class minimap next to the scrollbar
- [ ] Structure → C header export (turn a parsed tree into `struct` definitions)
- [ ] Bit-field / flags display in the Inspector (named bits, editable)
- [ ] Diff/compare two files with synced scrolling
- [ ] Open process memory and raw disks/devices
- [ ] pcap/pcapng import: one tab per packet, run protocol parsers on each
- [ ] Split view of the same document, multi-selection
- [ ] C struct → overlay: paste a C struct definition, get an instant parser/highlight (no Lua needed)
- [ ] Follow pointer: Ctrl+click a u32/u64 to jump to it as an offset; jump history (Alt+Left / Alt+Right)
- [ ] Strings panel (ASCII / UTF-16, min length, background scan, click to jump)
- [ ] Bitmap view: render bytes as pixels (adjustable width / pixel format) to spot tables & images
- [ ] Byte-class coloring mode (zero / printable / whitespace / control / high bytes)
- [ ] Disassembly at cursor (Capstone: x86/x64/ARM/AArch64/...)
- [ ] Live tail mode for growing files (captures, logs)
- [ ] XOR / rotate brute-force helpers to find simple obfuscation
- [ ] Script API: `doc:view_range()` (visible bytes); bookmark access from Lua
- [ ] "Restore from .backup" command (swap the file with its `.backup`, or open the backup side by side)
- [ ] Live font reload from the Settings window (font file / hinting changes need a restart now)
- [ ] Settings: remember the Bookmarks panel's "All open files" toggle
- [ ] Linux CI + AppImage; Windows portable zip
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
