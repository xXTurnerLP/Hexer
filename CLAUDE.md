# Hexer — project guide for Claude sessions

Modern, KISS, dark-mode hex editor for binary analysis (HxD alternative). C++20 + Dear ImGui (docking)
+ GLFW/OpenGL3 + Lua 5.5, built with Meson. Targets Windows (MSVC) and Linux (GCC/Clang).

## Non-negotiables
- **Never load a whole file.** All file access goes through `FileSource` (64 KiB block LRU cache) and
  the piece table. Anything O(file size) (search, save, hashing) runs on a worker thread over a
  `Snapshot`, with `Progress` + cancel. Must stay usable on multi-TB files and block devices.
- **Offsets are `uint64_t` everywhere** — never `int`, `size_t` for file positions, or `float`/ImGui scroll.
  The hex view scrolls by its own 64-bit row index with a custom scrollbar.
- **Full undo history** (Ctrl+Z / Ctrl+Y) for every content and bookmark change; it survives saves and
  restarts (session). New mutating features must go through `Document` so they are undoable.
- **Hot exit** (Sublime-style): no "save changes?" prompts on exit; unsaved edits + history + view
  state persist in the session dir and restore on launch. Only edits are stored, never the original file.
- **KISS**: plain structs, few abstractions, no new dependencies without a clear reason.
  Prefer one obvious way. UI is immediate-mode; keep state in `Document::view()` / small structs.
- UTF-8 strings/paths everywhere (`os_file` converts to UTF-16 on Windows).

## Layout
```
src/core/    no UI, no Lua — os_file, file_source (ByteBackend: file / device / process memory),
             procmem (process memory backend, "process://<pid>" URLs), devices (process / disk /
             memory region / module lists), piece_table, highlight, document (edits, undo, save, targets,
             extras), session (hot exit + per-doc / session extras), search, inspector, util (goto
             exprs, copy-as, paste parse), settings (+ paths), nav (PointerType, follow pointer +
             jump history), xorscan (XorScanJob, key_guess, undoable apply_transform),
             strings_scan (StringsJob), hash (16 algorithms + HashJob), cstruct (C struct
             definitions -> Lua parser source),
             entropy (ByteClass + EntropyJob: sampled per-bucket entropy for the minimap), bitmap
             (bytes -> pixels), diff (DiffJob: compare two Snapshots with a shift), pcap (pcap/pcapng
             PcapIndexJob + packet dissector), pcap_filter (PacketFilter expressions +
             PacketFilterJob), pcap_stream (TCP reassembly: follow_tcp_stream, TcpStreamJob),
             pcap_job.h (PcapWorker<R>: one background run, used by both); document also has
             refresh_appended() (live tail);
             exe_map (AddressMap: PE / ELF / manual file offset <-> VA, entry point, sections;
             detect_pe_image = a PE mapped by RVA in process memory; a Process map's `names` are
             the modules), nav also has AutoPointerWidth (process docs' pointer-size default);
             symbols (SymbolTable: PE exports / imports, ELF symtab / PLT / GOT names, bounded
             reads; SymbolJob builds it on a worker thread);
             disasm (x86-64 / x86 via Zydis, disasm_range / disasm_sync_back; its own static lib
             hexer_disasm so only its users link Zydis)
src/script/  script_engine.h (Lua API contract — the header comment is the API spec),
             script_engine.cpp, lua_api.cpp, lua_onelua.cpp (the wrap's Lua sources compiled as ONE
             C++ TU: Lua errors are C++ exceptions; include "lua.h" etc., never lua.hpp),
             cexport (parse tree -> C header, opts.flags names; no Lua, but on Field so it lives here), parse_job (ParseJob: one parse on a worker
             thread in a ScriptEngine of its own over Document::clone_readonly)
src/ui/      theme (dark theme, fonts, palette), hex_view (the widget), panels, app (main loop,
             menus, shortcuts, tabs, Compare tab, live tail, split view, minimap wiring, session
             extras, ScriptHost impl); self-contained feature UIs without App dependency:
             panel_strings, panel_hash, dialog_cstruct, panel_bitmap, panel_packets, panel_history,
             panel_xor, dialog_targets (Open Process / Open Disk + RegionsPanel) (App owns one of
             each), minimap (one per tab, in hexer_ui_view), view_diff (DiffView: two HexViews, App owns the one Compare),
             panel_disasm (Disassembly; in hexer_ui_view so test_disasm drives it headlessly);
             panel_bitmap, panel_packets and view_diff are in hexer_ui_view too (headless tests)
src/main.cpp
scripts/     bundled Lua scripts (examples/ parsers + commands); user scripts live in
             <config>/scripts and override bundled ones by name
tests/       doctest; one exe per module: test_core, test_util, test_script, test_search,
             test_ui (headless ImGui: drives HexView + Minimap with simulated mouse/keyboard),
             test_diffview (headless Compare view: next / prev, Find Shift, synced scroll),
             test_panels (headless Packets + Bitmap panels: row clicks / keys, decode, image clicks),
             test_nav, test_strings, test_hash, test_cstruct, test_entropy, test_bitmap,
             test_diff, test_pcap, test_pcapfilter, test_tcpstream (synthetic captures from
             pcap_fixture.h), test_tail (growing files), test_procmem (reads and writes the
             test process's own memory; its modules, their in-memory PE symbols, hx.open_process), test_history, test_xorscan, test_session,
             test_symbols (PE / ELF fixtures in symbol_fixture.h, malformed tables, kernel32.dll
             when present), test_disasm (encodings, sync_back, PE / ELF maps incl. malformed
             headers, Lua, headless panel incl. labels / Go to Symbol / session extras),
             test_cexport (C header export + round trip through cstruct, opts.flags, bit toggles),
             test_parsejob (background parses: cancel, stale reads, errors, sync fallback, holes)
tools/       meson.bat (MSVC env wrapper), ppm2png.py (screenshot conversion),
             make_icon.py (regenerates assets/icon/* + src/ui/icon_data.h; edit the design there),
             make_pcap.py (demo pcapng with HXP packets + an HTTP-over-TCP connection for the
             Packets panel / Follow TCP Stream)
assets/      app icon (PNG sizes + hexer.ico, embedded via src/hexer.rc), Linux .desktop file
.github/     CI (workflows/ci.yml): release builds + tests on GCC / Clang / MSVC; packages
             (Windows zip, Linux AppImage on ubuntu-22.04 + tar.gz) as 7-day artifacts, smoke-tested
             by ci/smoke-package.sh (source scripts/ moved away); `v*` tags publish a GitHub Release
```
Headers are the module contracts. Changing a public signature means updating every caller —
grep before you change one. Adding members is fine.

## Build & test
Windows (no MSVC on PATH by default; the wrapper loads vcvars via vswhere):
```
tools\meson.bat setup build            # once
tools\meson.bat compile -C build
tools\meson.bat test -C build --print-errorlogs
build\src\hexer.exe [files...]
```
From Git Bash use `cmd //c "tools\\meson.bat compile -C build"`.
Linux: `meson setup build && meson compile -C build && meson test -C build`
(needs X11/Wayland dev packages for GLFW, and GTK3 *or* dbus dev for native file dialogs).

Parallel sessions: use **your own build dir** (`build-<topic>`) to avoid ninja lock clashes.
Build a single target with `meson compile -C build-x hexer_core` / `test_core` etc.

Visual smoke test (no human needed):
```
build\src\hexer.exe --config-dir <tmp> --no-session --screenshot shot.ppm --frames 30 some.bin
python tools\ppm2png.py shot.ppm shot.png      # then view the PNG
```
Other app flags: `--exec "<lua>"` (run console code after startup), `--frames N`,
`--action "<name>"` (run a menu/palette action once the layout settled, e.g. `"Settings..."`,
`"Show All Bookmarks"`, `"Jump to Bookmark..."`, `"Strings: Scan File"`, `"Hash Selection"`,
`"New Parser from C Struct..."`, `"Follow Pointer at Cursor"`, `"Navigate Back"`, `"Minimap: Byte Classes"`,
`"Color Bytes by Class"`, `"Toggle Bitmap"`, `"Bitmap: Show at Cursor"`, `"Toggle Packets"`,
`"Packets: Follow TCP Stream"` / `"... (Interleaved)"`, `"Packets: Open Packet as Tab"`, `"Packets:
Open Payload as Tab"`, `"Packets: Filter Conversation"` (selected packet, else the one under the
caret: e.g. `--exec "local d=hx.doc(); d:jump(d:size()-20)"` picks the last packet; they wait
for the index),
`"Structure: Parse Selection"`, `"Structure: Copy as C Header"` (clipboard), `"Structure: Export C
Header..."` (native dialog), `"Toggle Live Tail"`, `"Compare with: <tab name>"`,
`"Compare: Align at Cursors"`, `"Compare: Find Shift"`, `"Compare with File on Disk"`, `"Compare with
Backup"`, `"Revert to Backup"` (the last two need `<file>.backup`), `"Show History"`, `"XOR: Scan File"`, `"XOR: Guess Key from
Selection"`, `"Open Process..."`, `"Open Disk..."`, `"Toggle Regions"`, `"Split Horizontally"`,
`"Split Vertically"`, `"Split View: Switch Pane"`, `"Undo"`, `"Toggle Disassembly"`, `"Go to Entry
Point"`, `"Disassemble at Cursor"`, `"Disassembly: Follow Target"`, `"Go to Symbol..."`, `"Go to Module..."` / `"Show Modules"` (process docs); any palette
label works too, e.g. `"Parser: PNG image"` then `"Structure: Parse at Cursor"`; repeatable; all
actions of one run execute in the same frame, so e.g. "Compare: Next Difference" right after
"Compare with: ..." finds no result yet). A process opens from the command line as
`"process://<pid>"` (read-only); `settings.ini` `pointer_width = 2` preselects the uint16 Inspector row.
Settings drive what actions cannot: put e.g. `bitmap_format = RGB 24-bit` or `minimap = classes`
in `<config-dir>/settings.ini` before a screenshot run. The real mouse cursor is not hidden: if it
sits over the window, its hover tooltip shows up in the screenshot.
Script commands can be driven from `--exec` with `hx.run("<command name>")`; a command that calls
`hx.prompt` leaves its modal open in the screenshot.

Headless UI tests (`tests/test_ui.cpp`, target `test_ui`): an ImGui context with no window/GL
(`io.DisplaySize` set by hand, `ImGuiBackendFlags_RendererHasTextures` so fonts bake without a
renderer). The `Ui` fixture owns a Document + HexView in a full-size host window; `ui.click(pos,
mods)`, `ui.drag(a, b)`, `ui.key(ImGuiKey_X, mods)`, `ui.type("ab")` queue io events one frame each,
and `ui.hex(off)` / `ui.txt(off)` give the screen position of a drawn byte (`HexView::cell_pos`).
Every change to input handling or hit testing in `ui/hex_view.cpp` gets a case there.
Use `Document::set_clock_for_tests` for undo-merge timing.

Structure panel parses: `update_structure()` (panels.cpp) starts a `ParseJob` (detect() stays on
the UI thread) and adopts its result when it is done and still matches the inputs (generation,
script reload, parser, Parse at range); a mismatching job is cancelled into `StructureState::retired`.
Don't call `ScriptEngine::parse` from the UI for the panel; it stays the synchronous API (tests).

Follow pointer type: `Settings::pointer_type()` (width / signed / relative / base + the Inspector's
LE/BE) is the one source; clicking an integer Inspector row sets it, `follow_pointer_as()`
(panels.h) follows it, `inspector_mark()` outlines the Inspector row's bytes in the hex view.
The Inspector's Bits row (after "binary") has the selected integer row's width, else 8 bits; a
click flips one bit through `inspector_toggle_bit()` (core/inspector.h, one undo step).

Session extras: per-tab view state (Parse at, live tail, split) goes to `Document::set_extra` in
`save_tab_extras()` (app.cpp) and comes back in `restore_tab_extras()`; state spanning tabs (the
Compare tab) goes to `Session::set_extra`. Process documents are not persistable: the session
skips them (hot exit drops them with a console line). The Disassembly panel keeps its per-doc
state ("disasm.map" / "disasm.base" / "disasm.top") itself: `DisasmPanel::save_extras` /
`restore_extras`, called next to the tab extras.

Jump history: `reveal_range()` (app_internal.h) is the one "big jump" helper: it pushes the
position it leaves onto the tab's `NavHistory`. Use it for new jump sources (not for caret moves).
Scroll-only sources (minimap click/drag, live tail follow) call `HexView::request_scroll_to`.

Compare tab: the DiffView sides draw the documents' own ViewState (caret, selection, top_row are
shared with their tabs; only one of them is drawn per frame). `top_row` is a row index, so
`Tab::top_bpr` records the row width it is expressed in and `adopt_top_units()` converts before a
view with another width draws. Jumps aimed at a tab's HexView while the Compare tab is shown are
handed over with `HexView::take_scroll_request()`. A B side that is not a tab (the file on disk,
the `.backup`) is `App::diff_aux` (a read-only Document; `compare_b()` finds either kind); Find
Shift is `core/diff.h find_shift` on DiffView's own `ShiftJob`.

Selection convention (one for the whole UI, see `ui/hex_view.h`): `ViewState` selection is
half-open `[sel_begin, sel_end)`; the caret is drawn on `caret_byte()` (inside the selection);
the Inspector/status bar/inspector edits use `focus_offset()` (selection start, else caret);
ranges are displayed with `fmt_range()` (inclusive end).

## Conventions
- namespace `hx`; 4-space indent; `snake_case` functions/vars, `PascalCase` types, `trailing_` members.
- Colors are packed `0xAABBGGRR` (IM_COL32 layout) — use `hx::rgba(r,g,b,a)`.
- Errors: return `bool` + `std::string* err` (nullable). No exceptions across module boundaries.
- Lua: API surface is documented in the comment block at the top of `src/script/script_engine.h`;
  keep it, `docs/scripting.md` and `scripts/examples/` in sync when changing the API.
  Lua is built as C++, so a lua_CFunction may raise (luaL_error / luaL_check*) with C++ locals
  alive; never `catch (...)` on a path called from Lua (it would swallow the error), no noexcept there.
- Tests: add doctest cases for any core/util/script behaviour you change. Use temp dirs, never the
  real user config dir (`paths::set_config_dir_override`).
- Commit messages: imperative, short subject; mention the module (`core:`, `ui:`, `script:`).
- Commit regularly at meaningful milestones (a feature or fix round lands, tests green, before a risky
  refactor) to keep a readable timeline — not every small edit. Only commit a building, test-passing
  tree; in parallel sessions commit only your own files (`git add <paths>`, never `git add -A` blindly).

## Roadmap
See `TODO.md`.
