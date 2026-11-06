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
- [x] Keyboard shortcut routing while text fields have focus: one policy in `ui/input.h`
      (`global_shortcut` / `text_editing_chord`: Ctrl+Z/Y/A/C/V/X, Ins, Del, arrows, Home/End,
      Enter, Esc, Tab and typing keys stay in the field; Ctrl+Tab, F3, Ctrl+S, Ctrl+W... still
      fire; caret actions Ctrl+B, F2, Alt+arrows, Ctrl+Enter, F6 do not); headless test_ui cases
- [x] Double-click editing in Inspector / Structure / Bookmarks: one `InlineEdit` (ui/input.h,
      headless test_ui cases: double-click, Enter commits as one undo step, Esc cancels, a click
      elsewhere cancels byte edits / commits bookmark text, rejected values stay open); Enter
      edits the selected Structure field too; Bookmarks got a row context menu (Edit name / note,
      Select bytes, Copy offset, Delete)
- [x] Tab drag reordering (order kept in the session, test_session case), middle-click closes a
      tab (also the Compare tab), Ctrl+wheel zoom over the hex view / Compare tab with touchpad
      fractions summed into whole steps (`wheel_steps`)
- [x] Drag & drop (several files; folders skipped with a notification), long saves with Cancel
      (disabled past the point of no return), the external-change banner: Reload (drops edits and
      history: the file is the new original, bookmarks kept; test_core case) / Keep mine (Ignore
      when clean) / Compare (with the file on disk)
- [ ] Native file dialogs and OS drag & drop with a real mouse (not drivable headlessly)
- [x] Linux build (CI compiles and tests linux-gcc + linux-clang on every push, 0 warnings)

### User feedback fixes
- [x] App icon consistent at every size (16/24/32 px hand-drawn pixel art of the same pointy-top
      hexagon and "101" as the large sizes; `tools/make_icon.py`)
- [x] Follow pointer type picked in the Inspector: clicking an integer row (int8..uint64, 24-bit
      too) sets width + signedness (byte order = LE/BE), the row is marked and its bytes are
      outlined in the hex view; signed and relative pointers; Structure fields follow as their own type
- [x] Windows and options persist across restarts: which panels are open (a closed panel stays
      closed, an opened one stays open; Packets / Regions only auto-open for a newly opened capture /
      process), the OS window's size / position / maximized state (restored onto a connected
      monitor's work area, else centred on the primary), the Find bar kind + Ignore case, console
      Word wrap + Up/Down history (`console_history.txt`), Strings / XOR / Bitmap (Fit, Alpha,
      follow source) / Packets (Absolute time, Payload only) / Compare (Sync scroll / caret)
      options; per tab: insert mode, Back / Forward history, Packets filter + "Parse with"; per
      session: Find pattern, Bitmap fixed start, the C Struct to Parser draft (see CLAUDE.md
      "Persistence")
- [x] Script `doc:jump` / `doc:select` / `doc:select_ranges` record Back / Forward history (the
      host's reveal_range runs before the view moves, so Alt+Left returns); Reset Layout also closes
      the on-demand panels (Bitmap, Packets, Regions, Disassembly, History, XOR: Settings' panel_*
      defaults, settings.ini follows)
- [ ] Persistence follow-ups: Regions / Modules filters and in-panel tab choices (XOR, Regions)
      stay transient

## Later
- [x] History panel (View > History: every undo state with its label and changed range; click to
      undo / redo to it; "saved" tag)
- [x] History: relative time per entry ("just now", "5 min ago", "yesterday 14:03"; full date in
      the tooltip; UndoEntry::time_ms, kept in the session, a typing run has its last edit's time)
- [x] Undo for view-level actions: the read-only toggle, the chosen parser (Structure combo, palette,
      C struct) and Parse at are cheap view steps (no piece list copy; undo while read-only works);
      not scrolling, caret moves or the Packets panel's per-packet parse
- [x] History: view steps (parser, Parse at, read-only) keep the redo stack's content steps (undo a
      few edits, pick a parser: Redo re-applies the edits and keeps the parser); a new view step
      only replaces the undone view steps; no session format change
- [x] Hashes & checksums of selection (Hashes panel: 16 CRCs/checksums/hashes, background, expected
      value match; `hx.hash` / `doc:hash`)
- [x] Custom hash algorithms registered from Lua (`hx.hash_algorithm{name, init, update, final}`:
      Hashes panel (a Lua state of its own per run on the HashJob worker, cancel stops Lua at
      once, errors in the row + once in the console), `hx.hash` / `doc:hash` / `hx.hash_algorithms`;
      example Adler-32 (Lua) in scripts/examples/hashes.lua, checked against the built-in)
- [x] Entropy / byte-class minimap next to the scrollbar (View > Minimap: Off / Entropy / Byte Classes;
      background sampled scan, rescanned 1 s after edits; click / drag scrolls)
- [x] Minimap: rescan only the buckets an edit touched (`EntropyJob::rescan`: the piece lists of
      the last scan and the new snapshot are compared; overwrites rescan their buckets, an insert /
      delete rescans from the edit on, a new bucket layout / process memory / a save rescans all)
- [x] Minimap: small regions inside huge sampled buckets (sparse files: holes are known zeros via
      FSCTL_QUERY_ALLOCATED_RANGES / SEEK_DATA, only data ranges are read, each gets a chunk; a
      4 KiB block in a 1 TiB sparse file shows; `peak` / `nonzero`: a tick on the right edge marks a
      dense 4 KiB chunk or a lone non-zero byte the bucket average hides)
- [x] Minimap: fully allocated huge zero areas (disk images) no longer hide a small region between
      samples: once the scan is done, sampled all-zero buckets are refined while idle (one more
      4 KiB slot per gap and pass, bit-reversed order: midpoints first; a pass reads at most what
      the scan did, then pauses >= 3x its time; up to 64 passes in the app, cancelled by any new
      scan); process memory is refreshed incrementally (every 2 s the buckets around the visible
      bytes + a rotating 1/64 of the rest, `EntropyJob::refresh`)
- [ ] Minimap: refinement of buckets that are uniform but not zero (0xFF-erased flash dumps), and
      of the visible buckets first
- [x] Structure → C header export (Structure panel "C Header" / row context menu: packed typedefs,
      deduped layouts, arrays, enums, bit fields, padding, static_asserts, `// @be`; converts back
      through C struct → parser to the same tree)
- [x] Bit-field / flags display in the Inspector (Bits row: a 0/1 toggle per bit at the selected
      integer row's width, undoable flips; Lua `opts.flags` names bits: "3 = READ|WRITE")
- [x] C header export: `#define MEMBER_FLAG 0x...` masks for flags fields; 1-byte `fmt = "char"`
      fields as `char`; mixed byte order: the struct's majority annotation (`// @be` / `// @le`)
      plus `/* @le */` / `/* @be */` before each minority member, which C struct -> parser reads
      (an annotation comment on the member's own line), so the round trip keeps every byte order
- [x] Diff/compare two files with synced scrolling (File > Compare With: a Compare tab, F7 / Shift+F7,
      shift for inserted headers, "Align at Cursors")
- [x] Compare: keep the Compare tab (documents + shift) in the session
- [x] Compare: find the shift automatically ("Compare: Find Shift": a distinctive 64-byte block
      after the first difference, rolling-hash search within +-16 MiB, background job); compare a
      document with its version on disk (Compare With > File on Disk, reloads after saves; session)
- [x] Compare: Find Shift for the next misalignment too (from the A caret on, so after one Find
      Shift the next one continues behind the match; plain changes that realign within 4 KiB are
      passed over, so a change followed by an insertion finds the insertion)
- [x] Headless tests for DiffView / PacketsPanel / BitmapPanel (view_diff, panel_packets and
      panel_bitmap moved to hexer_ui_view; test_diffview, test_panels)
- [x] Open process memory and raw disks/devices (File > Open Process... / Open Disk..., Regions
      panel, read-only unless asked, in-place saves of overwrites, `doc:target()` / `doc:pid()`)
- [x] Process memory: Search / Strings / XOR search / minimap / Hash skip unreadable holes
      ("X unreadable skipped"); Inspector shows ?? for unreadable bytes
- [x] Process memory: default the follow-pointer width to the process's pointer size (until the
      user picks one; settings.ini keeps theirs); module list (Regions panel "Modules" tab, palette
      "Go to Module..."); module!export labels in the Disassembly from each module's in-memory PE
      headers (`detect_pe_image`); Lua `hx.open_process(pid, {writable})`, `doc:modules()`
- [ ] Process memory: symbols of Linux processes (ELF modules: PT_DYNAMIC .dynsym in memory, or
      the module's file on disk relocated to its base); the Disassembly's module symbols are only
      re-read on Refresh Memory / edits (a DLL loaded later has no labels until then)
- [x] Compile and test core/procmem.cpp + core/devices.cpp on Linux (/proc/PID/mem, /sys/block)
- [x] Process memory "all ??": a new process tab opened at address 0, inside the unmapped hole
      (reads were fine); it now starts at the main module (`process_start_address`), Search > Next /
      Previous Readable Region (`Alt+PgDn` / `Alt+PgUp`), a tab banner when the process exited or
      its memory reads are refused (`Document::target_read_denied`). Holes are not collapsed in the
      hex view (offset = address and the 64-bit row index stay linear); the minimap / scrollbar
      track and the Regions panel show them
- [x] Restart as Administrator (Windows; core/elevation): File menu / palette, both pickers, the
      access-denied banner; hot exit carries the session, process / disk targets go on the
      command line, the elevated instance waits for the old one (`--wait-pid`); "(Administrator)"
      in the title
- [ ] Restart as Administrator: verify the real UAC path by hand (automated runs use
      `HEXER_TEST_RESTART_VERB=open`); a writable process tab comes back read-only
- [ ] Verify by hand: Open Process / Open Disk pickers, writable process save, the Regions click
      (screenshots only so far)
- [x] pcap/pcapng: Packets panel (index in the background, filter, "Parse with" a parser over each
      packet or its payload, Up / Down steps and re-parses); auto-shown for captures
- [x] Packets: filter expressions (core/pcap_filter: ip.src/dst/addr incl. IPv6 + /prefix, tcp/udp
      ports, frame.len, eth.type, proto, "text"; and / or / not, parentheses; the error is marked
      inline and the previous filter stays; a worker above 100k packets)
- [x] Packets: Follow TCP Stream (core/pcap_stream: reassembly by sequence number with out-of-order,
      retransmitted / overlapping segments, wraparound, ACKed gaps, connection reuse; a read-only tab,
      sequential or interleaved, one bookmark per segment, 256 MiB cap; the list gets the conversation
      filter) and Open Packet / Payload as Tab
- [x] Packets: Follow UDP Stream (the datagrams of one 4-tuple, both directions, in capture order;
      same tab / bookmarks as TCP) and a "Stream" column (TCP / UDP conversation numbers, per
      protocol from 0, on a ConversationJob worker after each index)
- [ ] Packets: IPv4 / IPv6 fragment reassembly (fragments are skipped by Follow TCP / UDP Stream
      and the Stream column); a stream that starts without a SYN with an out-of-order first segment
      loses the bytes before it; split a Stream number at a port reuse (new SYN) like Wireshark;
      `tcp.stream` / `udp.stream` filter fields
- [x] Packets: Lua access (`doc:packets{ filter=, first=, max= }`: synchronous index + dissect,
      paged, time-limited; scripts/examples/packets.lua); filter on more fields (vlan, ip.proto,
      tcp.seq / tcp.ack, tcp.flags with names (`syn+ack`), tcp.flags.syn ..., frame.number)
- [x] Split view of the same document (View > Split View, Ctrl+\, F6; kept in the session)
- [x] Multi-selection (core/multisel.h): Alt+click / Alt+drag adds a range (Alt+click on a selected
      byte removes it), Add Selection (Ctrl+Shift+A), Select All Matches (Alt+F3 / Search Results
      "Select All", up to 100k); Copy / Copy As (one line per range), Cut, Delete, Fill, Paste (equal
      lengths) and Bookmark Selections as one undo step each (Document::fill_ranges: one pass);
      status bar "N selections, size"; `doc:selections()` / `doc:select_ranges{}`; transient
- [ ] Multi-selection: typing / Inspector edits into every range; scrollbar / minimap ticks for the
      extra ranges; Find inside the selected ranges; keep the extras in undo steps (an undo of a
      multi-range Delete restores only the primary selection today)
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
- [x] Bitmap: zoom below 1x (1/2x .. 1/16x: a screen pixel averages its block, at most kMaxBytes
      read per refresh; Fit picks a downscale for rows wider than the panel); the level and the
      follow source are remembered in settings.ini (Fixed offset: per session)
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
- [x] Symbols without stalls: SymbolJob restarts never block the UI (one worker per job, a request
      slot), the table is kept when an edit misses the bytes it was read from (SymbolTable::sources,
      compared piece by piece; size changes always rebuild), Go to Symbol filters a precomputed
      lowercase label text (1M symbols: ~10 ms per keystroke), doc:symbols reuses the panel's table
- [x] Symbols: keep the table across inserts / deletes after its sources (SymbolTable::size_min /
      size_max: each range check against the size is recorded; a Pe / Elf map's file_size is not
      compared, its regions are)
- [ ] Disassembly: branch arrows; a "Find references to" scan; PDB / DWARF names; i386 PIC PLT
      (jmp [ebx+X]) @plt names; symbols for a Manual base over a PE / ELF image (today: none)
- [ ] Disassembly: other architectures (ARM / AArch64) only if asked (Zydis is x86 only)
- [x] Live tail mode for growing files (captures, logs): View > Live Tail, follows the end while the
      caret is there, a rewrite falls back to the "changed on disk" banner
- [x] Live tail: remember the toggle in the session
- [x] Live tail: rescan the Packets index incrementally while a capture grows (index_pcap_append:
      only the records after the last one; a record cut short is read again; other bytes before
      the old end / a shrink / a cancelled index = a full rescan; filter + Stream numbers continue)
- [x] XOR / rotate brute-force helpers to find simple obfuscation (XOR Search panel: known
      plaintext with 1-byte XOR / ADD / ROL and 2..16-byte XOR keys, key guess, undoable decode)
- [x] XOR search: Lua API (`hx.xor_scan(doc, plaintext, opts)` up to 256 MiB per call,
      `hx.xor_guess_key(doc, off, len, opts)` up to 16 MiB)
- [x] XOR search: multi-byte ADD keys (scan "ADD key" + key guess XOR / ADD; `add_multi`,
      `op = "add"` in Lua) and `doc:apply_transform{op, key, start, length, phase, decode}` (the
      undoable decode as one step; a scan hit decodes with its own transform / key)
- [x] Script API: `doc:view_range()` (visible bytes); bookmark access from Lua (`doc:bookmarks()`,
      `doc:add_bookmark`, `doc:remove_bookmark`, undoable)
- [x] "Restore from .backup" (File menu, when `<file>.backup` exists): Compare with Backup side by
      side, Revert to Backup = one undoable edit referencing the backup file (nothing copied;
      disk untouched until Save; the .backup stays the original)
- [x] Revert to Backup across hot exit at any size: the session references the .backup by path
      (+ size / mtime; a changed or vanished backup drops the states that need it, the current one
      falls back to the file on disk, with a console line)
- [x] Live font reload from the Settings window (font files / hinting apply right away; a path is
      loaded when its field is left)
- [x] Settings: remember the Bookmarks panel's "All open files" toggle
- [x] Headless App-level tests (tests/test_app.cpp: the App without a window / GL through
      app_startup / app_frame / app_shutdown + run_named_action in ui/app_internal.h): session
      round trips of tab order / active tab / split view / live tail / Parse at / the Compare tab,
      History panel keys, XOR Search scan + key guess actions
- [ ] Headless App tests: clicks on panel rows inside the App (XOR results, History rows) need
      the rows' positions (no accessor inside app.cpp's panels; test_panels covers the panels alone)
- [x] Linux CI (linux-gcc + linux-clang build and test on every push, 0 warnings)
- [x] AppImage + Linux tar.gz; Windows portable zip (CI artifacts on every push, GitHub Release on
      `v*` tags; each package is smoke-tested with its own bundled scripts)
- [x] Linux packages: AppStream metainfo (assets/linux/io.github.xXTurnerLP.Hexer.metainfo.xml,
      installed by meson to share/metainfo, so the AppImage carries it; `appstreamcli validate`
      in CI, a warning only); an aarch64 leg of the package job (ubuntu-22.04-arm)
- [ ] Linux packages: drop `continue-on-error` from the aarch64 leg once it has passed on CI; a
      `<project_license>` in the metainfo once the project has a license; screenshots there once
      some are hosted at a stable URL
- [x] Compile the visual-analysis / compare / capture batch with GCC and Clang (-Wall -Wextra,
      green in CI)
- [x] Run parsers on a worker thread (script/parse_job.h: a Lua state of its own per parse over a
      read-only clone of the document; cancel, progress, stale results dropped; every parse is
      re-run after edits, debounced)
- [x] Background detect() (DetectJob: each parser's detect in a state of its own over a clone,
      "Detecting..." while slow, stale answers dropped; console / non-standalone parsers detect in
      the main engine in their turn)
- [x] Lua compiled as C++ (src/script/lua_onelua.cpp over the wrap's sources): a Lua error is a C++
      exception, destructors of live locals in our lua_CFunctions run (no more longjmp over C++
      frames, no HX_NOINLINE workaround); tested in debug / debugoptimized / release on MSVC

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
