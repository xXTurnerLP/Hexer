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
src/core/    no UI, no Lua — os_file, file_source, piece_table, highlight, document (edits, undo,
             save), session (hot exit), search, inspector, util (goto exprs, copy-as, paste parse),
             settings (+ paths), nav (follow pointer + jump history), strings_scan (StringsJob),
             hash (16 algorithms + HashJob), cstruct (C struct definitions -> Lua parser source)
src/script/  script_engine.h (Lua API contract — the header comment is the API spec),
             script_engine.cpp, lua_api.cpp
src/ui/      theme (dark theme, fonts, palette), hex_view (the widget), panels, app (main loop,
             menus, shortcuts, tabs, ScriptHost impl); self-contained feature UIs without App
             dependency: panel_strings, panel_hash, dialog_cstruct (App owns one of each)
src/main.cpp
scripts/     bundled Lua scripts (examples/ parsers + commands); user scripts live in
             <config>/scripts and override bundled ones by name
tests/       doctest; one exe per module: test_core, test_util, test_script, test_search,
             test_ui (headless ImGui: drives HexView with simulated mouse/keyboard), test_nav,
             test_strings, test_hash, test_cstruct
tools/       meson.bat (MSVC env wrapper), ppm2png.py (screenshot conversion),
             make_icon.py (regenerates assets/icon/* + src/ui/icon_data.h; edit the design there)
assets/      app icon (PNG sizes + hexer.ico, embedded via src/hexer.rc), Linux .desktop file
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
`"New Parser from C Struct..."`, `"Follow Pointer at Cursor"`, `"Navigate Back"`; any palette
label works too, e.g. `"Parser: PNG image"` then `"Structure: Parse at Cursor"`; repeatable).
Script commands can be driven from `--exec` with `hx.run("<command name>")`; a command that calls
`hx.prompt` leaves its modal open in the screenshot.

Headless UI tests (`tests/test_ui.cpp`, target `test_ui`): an ImGui context with no window/GL
(`io.DisplaySize` set by hand, `ImGuiBackendFlags_RendererHasTextures` so fonts bake without a
renderer). The `Ui` fixture owns a Document + HexView in a full-size host window; `ui.click(pos,
mods)`, `ui.drag(a, b)`, `ui.key(ImGuiKey_X, mods)`, `ui.type("ab")` queue io events one frame each,
and `ui.hex(off)` / `ui.txt(off)` give the screen position of a drawn byte (`HexView::cell_pos`).
Every change to input handling or hit testing in `ui/hex_view.cpp` gets a case there.
Use `Document::set_clock_for_tests` for undo-merge timing.

Jump history: `reveal_range()` (app_internal.h) is the one "big jump" helper: it pushes the
position it leaves onto the tab's `NavHistory`. Use it for new jump sources (not for caret moves).

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
- Tests: add doctest cases for any core/util/script behaviour you change. Use temp dirs, never the
  real user config dir (`paths::set_config_dir_override`).
- Commit messages: imperative, short subject; mention the module (`core:`, `ui:`, `script:`).
- Commit regularly at meaningful milestones (a feature or fix round lands, tests green, before a risky
  refactor) to keep a readable timeline — not every small edit. Only commit a building, test-passing
  tree; in parallel sessions commit only your own files (`git add <paths>`, never `git add -A` blindly).

## Roadmap
See `TODO.md`.
