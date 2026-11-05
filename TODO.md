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
- [ ] Linux build (POSIX code paths are written but have never been compiled)

## Later
- [ ] History panel (click to jump to any undo state)
- [ ] Undo for the remaining view-level actions that benefit from it (read-only toggle, chosen parser)
- [x] Hashes & checksums of selection (Hashes panel: 16 CRCs/checksums/hashes, background, expected
      value match; `hx.hash` / `doc:hash`)
- [ ] Custom hash algorithms registered from Lua (`hx.hash_algorithm{...}`)
- [x] Entropy / byte-class minimap next to the scrollbar (View > Minimap: Off / Entropy / Byte Classes;
      background sampled scan, rescanned 1 s after edits; click / drag scrolls)
- [ ] Minimap: rescan only the buckets an edit touched (today every edit rescans the whole map,
      bounded at 1024 x 256 KiB reads); small regions inside huge sampled buckets can be missed
- [ ] Structure → C header export (turn a parsed tree into `struct` definitions)
- [ ] Bit-field / flags display in the Inspector (named bits, editable)
- [x] Diff/compare two files with synced scrolling (File > Compare With: a Compare tab, F7 / Shift+F7,
      shift for inserted headers, "Align at Cursors")
- [ ] Compare: find the shift automatically (align on the first matching block); keep the Compare
      tab in the session; compare a document with its version on disk
- [ ] Headless tests for DiffView / PacketsPanel / BitmapPanel (view_diff.cpp etc. live in hexer_ui,
      which test_ui does not link; move them to hexer_ui_view or add a test exe)
- [ ] Open process memory and raw disks/devices
- [x] pcap/pcapng: Packets panel (index in the background, filter, "Parse with" a parser over each
      packet or its payload, Up / Down steps and re-parses); auto-shown for captures
- [ ] Packets: open a packet / TCP stream as its own tab, filter expressions (ip.src == ...)
- [ ] Split view of the same document, multi-selection
- [x] C struct → parser: paste C definitions, get a Lua parser (apply at the cursor or save it)
- [x] Parse at offset (Structure panel "Parse at", e.g. a PNG inside a dump)
- [ ] Remember the parse offset in the session (it is per tab and lost on restart now)
- [x] Follow pointer: Ctrl+click / Ctrl+Enter, width + base + byte order settings, Inspector /
      Structure buttons; jump history (Alt+Left / Alt+Right, mouse back / forward)
- [x] Strings panel (ASCII / UTF-16, min length, background scan, click to jump, live filter)
- [ ] Strings: deduplicate an ASCII-in-UTF-16 string found again shifted by one byte when both
      UTF-16LE and UTF-16BE are on
- [ ] Verify by hand: Ctrl+hover underline / tooltip and mouse X1/X2 (headless tests only)
- [x] Bitmap view: render bytes as pixels (adjustable width / pixel format) to spot tables & images
      (View > Bitmap; format / width / zoom remembered in settings.ini)
- [ ] Bitmap: zoom below 1x (downscale) for very wide images; remember the source mode
- [x] Byte-class coloring mode (zero / printable / whitespace / control / high bytes; View > Color
      Bytes by Class)
- [ ] Disassembly at cursor (Capstone: x86/x64/ARM/AArch64/...)
- [x] Live tail mode for growing files (captures, logs): View > Live Tail, follows the end while the
      caret is there, a rewrite falls back to the "changed on disk" banner
- [ ] Live tail: remember the toggle in the session (today it is off after a restart); rescan the
      Packets index incrementally while a capture grows
- [ ] XOR / rotate brute-force helpers to find simple obfuscation
- [ ] Script API: `doc:view_range()` (visible bytes); bookmark access from Lua
- [ ] "Restore from .backup" command (swap the file with its `.backup`, or open the backup side by side)
- [ ] Live font reload from the Settings window (font file / hinting changes need a restart now)
- [ ] Settings: remember the Bookmarks panel's "All open files" toggle
- [ ] Linux CI + AppImage; Windows portable zip
- [ ] Compile the visual-analysis / compare / capture batch with GCC and Clang (written for
      -Wall -Wextra but only built with MSVC so far)
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
