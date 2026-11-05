# Hexer

A fast, dark-mode hex editor for reverse engineering binary files and protocols.

Hexer streams files straight from disk, so a 3 TiB disk image opens as fast as a 3 KiB packet
capture. Lua scripts turn raw bytes into a structure tree with colored highlights you can edit,
and every edit can be undone, even after a save or a restart.

Built with C++20, Dear ImGui (docking), GLFW, OpenGL 3 and Lua 5.5. It runs on Windows and Linux.

## Features

- **Huge files.** Files are read in 64 KiB blocks on demand and never loaded whole. Offsets are
  64-bit everywhere, and the hex view uses its own 64-bit scrollbar. Opening a 3 TiB sparse file
  takes no measurable time and adds about 6 MB of memory.
- **Editing.** Overwrite or insert (toggle with `Ins`), delete, fill a selection, cut, copy and
  paste. Paste is lenient: `DE AD BE EF`, `0xde,0xad`, `\xde\xad` and `b64:...` all work.
  Edited bytes are tinted amber.
- **Full undo history.** `Ctrl+Z` / `Ctrl+Y` covers every content and bookmark change: typing,
  paste, fill, inspector and structure edits, and script commands (one undo step each). The
  history survives saves and restarts. Typing is grouped into one step per run of keys: a pause
  of more than 500 ms, or more than 32 typed bytes, starts a new step (both in Settings).
- **Safe, fast saving.** If the size is unchanged, Hexer patches only the changed bytes in place.
  Otherwise it writes a temp file and renames it over the original. Saves run in the background
  with progress and Cancel (until the last step, when the dialog shows "Finishing..."). If another
  program changed the file since you opened it, saving asks first: Save As, **Overwrite anyway**,
  Reload or Cancel.
- **Backup of the original.** The first time Hexer writes over an existing file, the original
  contents are kept as `<file>.backup` next to it. An existing `.backup` is never replaced, so it
  always holds the file as it was before Hexer first saved it (delete it by hand to start over). A save that rewrites the file just gives the original that second
  name (a hard link, or a rename where links are unsupported), so this costs nothing; an in-place save copies the
  file first (fast OS copy, counted in the progress, cancellable), and skips files above the size
  limit (4 GiB by default; a notification says so). The status bar shows "Saved ... (backup:
  name.backup)". Files Hexer created itself and devices get no backup. Turn it off or change the
  limit in Edit > Settings > Saving.
- **Hot exit** (as in Sublime Text). Closing Hexer never asks "save changes?". Open tabs, unsaved
  edits, undo history, cursor, scroll position and bookmarks are restored on the next launch.
- **Selection.** Dragging over bytes a..b selects exactly those bytes; the caret is drawn on the
  last byte you dragged to (inside the selection). The Inspector, the status bar's Offset/Byte
  and inspector edits all work on the **first selected byte** (else the caret byte), and ranges
  are shown the same way everywhere, inclusive: `0x00000010-0x0000001F (16 bytes)`.
- **Data inspector.** Integers (8 to 64 bit, plus 24 bit), half/float/double, LEB128 and zigzag,
  binary, characters (ASCII, UTF-8, UTF-16), GUID, and Unix, FILETIME and DOS timestamps.
  Little or big endian. Double-click a value to edit it.
- **Structure panel.** Lua parsers decode the file into a tree. Each field is highlighted in the
  hex view in its own color. Double-click a value to edit it, and it is re-encoded in place.
  Bundled parsers: PNG, ZIP (including ZIP64) and an example TLV protocol ("HXP").
- **Parse at an offset.** The Structure panel's **Parse at** field (or **Cursor**, Scripts > Parse
  at Cursor) runs a parser from any offset, e.g. a PNG embedded in a firmware dump; fields are
  highlighted in place and the panel shows `PNG image @ 0x00001234`.
- **C struct to parser** (Scripts > New Parser from C Struct...). Paste C `struct`/`union`/`enum`
  definitions (bit fields, `#pragma pack`, arrays sized by earlier fields, `// @be`) and get a
  readable Lua parser live. Apply it at the cursor, or save it as a script.
- **Follow pointer and jump history.** Hold `Ctrl` over a byte to see where the 32-bit value
  there points (underlined, with a tooltip), `Ctrl+click` jumps there; `Ctrl+Enter` follows the
  value at the cursor. Width (8/16/32/64 bit), base address and byte order (the Inspector's LE/BE)
  are in Search > Follow Pointer Settings and the Settings window. The Inspector's uint32/uint64
  rows and the Structure panel's 32/64-bit integer fields have a `→` button. Every big jump (Go
  to, search hits, bookmarks, Structure / Strings rows, follow) is recorded: `Alt+Left` /
  `Alt+Right` or the mouse back / forward buttons walk the history.
- **Strings panel.** ASCII, UTF-16LE and UTF-16BE strings of the file or the selection, with a
  minimum length, scanned in the background (progress, Cancel), up to a million results with a
  live filter. Click a row to select the string.
- **Hashes panel.** CRC-8/16/32/32C, Adler-32, Fletcher-16, FNV-1a, Sum-8, XOR-8, MD5, SHA-1,
  SHA-256 and SHA-512 of the selection (or the whole file), computed in the background and
  automatically up to 64 MiB. Paste an expected value to highlight the matching row. Scripts get
  `hx.hash(algo, bytes)` and `doc:hash(algo, off, len)`.
- **Search.** Hex with wildcards (`DE ?? BE`, `4?`), text, UTF-16, optionally case-insensitive.
  Searches run in the background. Find All lists every match and highlights them.
- **Smart Go to.** `0x1F00`, `1F00h`, `#1234` (decimal), `+0x10` (relative), `end-0x100`, `50%`,
  `cur+4*0x10`.
- **Copy as** hex, C array, Python bytes, Base64 or an escaped string.
- **Bookmarks** with a name and a note, kept in the session and undoable. `Ctrl+B` toggles one on
  the selection or caret, `F2` / `Shift+F2` jump, `Ctrl+Shift+B` fuzzy-finds a bookmark in any open
  file. The Bookmarks panel (bottom dock) lists name, note, offset, length and the first bytes,
  for this file or **all open files**; double-click a name or note to edit it. The Bookmarks menu
  lists the active file's bookmarks. Bookmarks (and Find All hits) show as ticks on the scrollbar.
- **Settings window** (Edit > Settings..., `Ctrl+,`): bytes per row, grouping, font size, UI
  scale, undo grouping, backups, hot exit, autosave interval and fonts. Changes apply right away
  (fonts after a restart) and are saved to `settings.ini`.
- **Fonts** are rasterised with FreeType (hinted, pixel-snapped hex cells). `font_hinting`
  (`normal`, `light`, `none`, `mono`), `mono_font` and `ui_font` (file paths, empty = auto) are
  in the Settings window and `settings.ini`.
- **Command palette** (`Ctrl+Shift+P`) with fuzzy search over actions (e.g. *Strings: Scan File*,
  *Hash Selection*, *Structure: Parse at Cursor*), script commands, parsers and recent files.
- **Lua console** (REPL), script commands, and hot reload: save a `.lua` file and it reloads.
  Commands can ask for a value with `hx.prompt(title, default)` (a small dialog; Enter = OK,
  Esc = Cancel), e.g. *Selection: XOR with key* asks for the key.
- Tabs, drag and drop, recent files, reopen a closed tab with its edits (`Ctrl+Shift+T`), a
  banner when the file changes on disk, a read-only mode, and zoom (`Ctrl+=` / `Ctrl+-`, `Ctrl+wheel`).
- **One window** (as in Sublime Text). Opening files while Hexer runs (`hexer file.bin`, "Open
  with") adds them as tabs to the running window and brings it to the front. `--new-instance`
  opens a separate window instead.
- **Unreadable data** (bad sectors, a removed drive, a file truncated by another program) is shown
  as `??` and flagged with a red "I/O error" badge in the status bar; searches stop there and say
  where, instead of matching the zeros that stand in for it.

## Building

Meson downloads all dependencies (ImGui, GLFW, Lua, nativefiledialog-extended, doctest) on
first setup.

### Windows

You need Visual Studio 2022 or later with the C++ workload, Python, and `pip install meson ninja`.
`tools\meson.bat` finds Visual Studio and loads the MSVC environment for you:

```
tools\meson.bat setup build
tools\meson.bat compile -C build
tools\meson.bat test -C build
build\src\hexer.exe
```

From Git Bash, run `cmd //c "tools\\meson.bat compile -C build"`.

### Linux

Debian / Ubuntu:

```
sudo apt install build-essential meson ninja-build pkg-config \
    libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev libgl-dev \
    libgtk-3-dev
meson setup build
meson compile -C build
meson test -C build
./build/src/hexer
```

- **File dialogs:** these use GTK 3 when `libgtk-3-dev` is installed. To avoid GTK, install
  `libdbus-1-dev` instead and Hexer uses the xdg-desktop-portal dialogs:
  `meson setup build -Dnativefiledialog-extended:xdg-desktop-portal=enabled`.
- **Wayland:** the bundled GLFW builds its X11 backend, which runs on Wayland through XWayland.
  For a native Wayland window, either install your distribution's GLFW 3.4 (`libglfw3-dev`),
  which Meson then prefers, or build the bundled one with
  `-Dglfw:display-api=wayland` (this also needs `libwayland-dev libxkbcommon-dev wayland-protocols`).
- Fedora package names: `libX11-devel libXrandr-devel libXinerama-devel libXcursor-devel
  libXi-devel mesa-libGL-devel gtk3-devel`.

GCC 11 or newer (or a recent Clang with libc++) is needed for `std::from_chars` on floats.

> The Linux build has not been compiled yet; the code is written to be portable, but expect
> small fixes on the first build.

### Command line

```
hexer [options] [files...]
  --config-dir DIR     use DIR for settings, session and user scripts (portable mode)
  --no-session         do not restore or write the hot-exit session
  --new-instance       open a new window even if Hexer is already running
  --exec "LUA"         run Lua in the console after startup
  --action "NAME"      run a menu/palette action after startup, e.g. "Settings..." or
                       "Parser: PNG image" (repeatable)
  --screenshot OUT.ppm render, save the window as a PPM and exit
  --frames N           exit after N frames
```

## Keyboard shortcuts

| Keys | Action |
|---|---|
| `Ctrl+N` / `Ctrl+O` | New / open file |
| `Ctrl+S` / `Ctrl+Shift+S` | Save / save as |
| `Ctrl+W` / `Ctrl+Shift+T` | Close tab / reopen closed tab (with its edits) |
| `Ctrl+Tab` / `Ctrl+Shift+Tab` | Next / previous tab |
| `Ctrl+Z` | Undo |
| `Ctrl+Y` or `Ctrl+Shift+Z` | Redo |
| `Ctrl+X` / `Ctrl+C` / `Ctrl+V` | Cut / copy / paste (in overwrite mode a paste overwrites from the selection start and keeps the size) |
| `Ctrl+Shift+C` | Copy as (hex, C array, Python, Base64, escaped; `1`-`7` picks a format) |
| `Ctrl+A` | Select all |
| `Ins` | Toggle insert / overwrite |
| `Delete` / `Backspace` | Delete the selection, else the byte at / before the cursor (without a selection, `Backspace` only moves left in overwrite mode) |
| `Tab` | Switch between the hex and text columns |
| Arrows, `PgUp` / `PgDn` | Move the cursor (hold `Shift` to select; with a selection a plain arrow moves from the drawn caret and clears it) |
| `Home` / `End` | Start / end of the caret's row (`Shift+End` selects to the end of the row) |
| `Ctrl+Home` / `Ctrl+End` | Start / end of file |
| `Ctrl+Up` / `Ctrl+Down` | Scroll without moving the cursor |
| `Ctrl+F` | Find bar (`Enter` next, `Shift+Enter` previous, `Esc` closes) |
| `F3` / `Shift+F3` | Find next / previous |
| `Ctrl+G` | Go to offset (`Shift+Enter` selects from the cursor) |
| `Ctrl+B` | Toggle bookmark (on the selection, else the caret byte) |
| `F2` / `Shift+F2` | Next / previous bookmark |
| `Ctrl+Shift+B` | Jump to a bookmark in any open file (fuzzy search) |
| `Ctrl+click` / `Ctrl+Enter` | Follow the pointer under the mouse / at the cursor (`Ctrl+hover` previews the target) |
| `Alt+Left` / `Alt+Right`, mouse back / forward | Back / forward through the jump history |
| `Ctrl+,` | Settings |
| `Ctrl+Shift+P` | Command palette |
| `F5` | Re-parse structure |
| `Ctrl+=` or `Ctrl++` / `Ctrl+-` / `Ctrl+0`, `Ctrl+wheel` | Zoom in / out / reset |
| `Ctrl+L` (in the console) | Clear console |

Mouse: click and drag to select (bytes a..b inclusive; clicking the second hex digit puts the
caret on the low nibble; clicking below the last row puts it at the end of the file),
`Shift+click` extends the selection from its fixed end, double-click selects the field under the
mouse, `Ctrl+click` follows the pointer there, right-click opens the context menu.

## Hot exit

Hexer never asks whether to save when you close it. Instead it writes a session to
`<config>/session/`: the open tabs, each document's unsaved edits and full undo/redo history,
cursor, selection, scroll position and bookmarks. The session is also autosaved a few seconds
after each change, so a crash loses almost nothing. The next launch restores everything.

- Only your **edits** are stored, never a copy of the original file. A restored tab reads its
  original bytes from the file on disk.
- If a file changed on disk in the meantime, Hexer warns you. If a file is gone but the session
  still has every byte the document needs, it comes back as a "(recovered)" untitled tab.
- If the session cannot be written (e.g. the disk is full), quitting asks Save / Discard / Cancel
  for the unsaved documents instead of losing them. The same question comes up for a document
  whose unsaved state refers to a large part of a file version that a save replaced (undo past a
  save that rewrote the file): the session cannot keep it, so Hexer asks for just that document.
- A second `hexer` started while one runs hands its files to the running window and exits (with
  the same config directory; `--no-session`, `--new-instance` and `--exec` / `--screenshot` /
  `--frames` runs never do). Files sent to a Hexer that quit before taking them are opened by the
  next start.
- Closing a single **tab** with unsaved changes still asks Save / Discard / Cancel. A discarded
  tab can be brought back with `Ctrl+Shift+T` until you quit.
- `<config>` is `%APPDATA%\Hexer` on Windows and `~/.config/hexer` on Linux (or
  `$XDG_CONFIG_HOME/hexer`). Hot exit can be switched off in Edit > Settings (or with
  `restore_session = false` in `settings.ini`).

## Scripting quickstart

Put a `.lua` file in `<config>/scripts/` (Scripts > Open Scripts Folder). It loads at startup and
reloads every time you save it.

```lua
hx.parser {
    name = "My protocol",
    detect = function(doc) return doc:u8(0) == 0xAB end,
    parse = function(p, doc)
        p:endian("be")
        p:u8("magic", { fmt = "hex" })
        p:u8("type", { enum = { [1] = "TEXT", [2] = "PING" } })
        local len = p:u16("length")
        p:str("text", len)
    end,
}

hx.command {
    name = "My protocol: build a TEXT message",
    run = function(doc)
        hx.new_doc("message.myp", string.pack(">BBs2", 0xAB, 1, "hello"))
    end,
}
```

The console (bottom panel) is a Lua REPL: `doc`, `cur` and `sel` are predefined, so
`doc:read(cur, 16)`, `hx.hex(doc:read(sel.start, sel.len))` or `hx.run("HXP: build sample packet")`
work straight away.

See **[docs/scripting.md](docs/scripting.md)** for the full guide and API reference, and
`scripts/examples/` for complete parsers (PNG, ZIP, a TLV protocol) and commands.

## Project layout

`src/core` holds documents, streaming I/O, the piece table, undo, saving, the session, search,
the inspector, strings extraction, hashes, the C struct converter, the jump history and
utilities. `src/script` is the Lua engine. `src/ui` is the ImGui app. Tests
live in `tests/`, one executable per module; `tests/test_ui.cpp` drives the hex view headlessly
(simulated mouse and keyboard, no window). See `CLAUDE.md` for contributor notes and `TODO.md`
for the roadmap.
