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
  history survives saves and restarts.
- **Safe, fast saving.** If the size is unchanged, Hexer patches only the changed bytes in place.
  Otherwise it writes a temp file and renames it over the original. Saves run in the background
  with progress and Cancel.
- **Hot exit** (as in Sublime Text). Closing Hexer never asks "save changes?". Open tabs, unsaved
  edits, undo history, cursor, scroll position and bookmarks are restored on the next launch.
- **Data inspector.** Integers (8 to 64 bit, plus 24 bit), half/float/double, LEB128 and zigzag,
  binary, characters (ASCII, UTF-8, UTF-16), GUID, and Unix, FILETIME and DOS timestamps.
  Little or big endian. Double-click a value to edit it.
- **Structure panel.** Lua parsers decode the file into a tree. Each field is highlighted in the
  hex view in its own color. Double-click a value to edit it, and it is re-encoded in place.
  Bundled parsers: PNG, ZIP (including ZIP64) and an example TLV protocol ("HXP").
- **Search.** Hex with wildcards (`DE ?? BE`, `4?`), text, UTF-16, optionally case-insensitive.
  Searches run in the background. Find All lists every match and highlights them.
- **Smart Go to.** `0x1F00`, `1F00h`, `#1234` (decimal), `+0x10` (relative), `end-0x100`, `50%`,
  `cur+4*0x10`.
- **Copy as** hex, C array, Python bytes, Base64 or an escaped string.
- **Bookmarks** with names, kept in the session. `Ctrl+B` toggles one, `F2` / `Shift+F2` jump.
- **Command palette** (`Ctrl+Shift+P`) with fuzzy search over actions, script commands,
  parsers and recent files.
- **Lua console** (REPL), script commands, and hot reload: save a `.lua` file and it reloads.
- Tabs, drag and drop, recent files, reopen a closed tab with its edits (`Ctrl+Shift+T`), a
  banner when the file changes on disk, a read-only mode, and zoom (`Ctrl +/-`, `Ctrl+wheel`).

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
  --exec "LUA"         run Lua in the console after startup
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
| `Ctrl+X` / `Ctrl+C` / `Ctrl+V` | Cut / copy / paste |
| `Ctrl+Shift+C` | Copy as (hex, C array, Python, Base64, escaped) |
| `Ctrl+A` | Select all |
| `Ins` | Toggle insert / overwrite |
| `Delete` / `Backspace` | Delete the selection or byte (`Backspace` only moves left in overwrite mode) |
| `Tab` | Switch between the hex and text columns |
| Arrows, `PgUp` / `PgDn` | Move the cursor (hold `Shift` to select) |
| `Home` / `End` | Start / end of row |
| `Ctrl+Home` / `Ctrl+End` | Start / end of file |
| `Ctrl+Up` / `Ctrl+Down` | Scroll without moving the cursor |
| `Ctrl+F` | Find bar (`Enter` next, `Shift+Enter` previous, `Esc` closes) |
| `F3` / `Shift+F3` | Find next / previous |
| `Ctrl+G` | Go to offset (`Shift+Enter` selects from the cursor) |
| `Ctrl+B` | Toggle bookmark |
| `F2` / `Shift+F2` | Next / previous bookmark |
| `Ctrl+Shift+P` | Command palette |
| `F5` | Re-parse structure |
| `Ctrl+=` / `Ctrl+-` / `Ctrl+0`, `Ctrl+wheel` | Zoom in / out / reset |
| `Ctrl+L` (in the console) | Clear console |

Mouse: click and drag to select, `Shift+click` extends the selection, double-click selects the
field under the mouse, right-click opens the context menu.

## Hot exit

Hexer never asks whether to save when you close it. Instead it writes a session to
`<config>/session/`: the open tabs, each document's unsaved edits and full undo/redo history,
cursor, selection, scroll position and bookmarks. The session is also autosaved a few seconds
after each change, so a crash loses almost nothing. The next launch restores everything.

- Only your **edits** are stored, never a copy of the original file. A restored tab reads its
  original bytes from the file on disk.
- If a file changed on disk in the meantime, Hexer warns you. If a file is gone but the session
  still has every byte the document needs, it comes back as a "(recovered)" untitled tab.
- Closing a single **tab** with unsaved changes still asks Save / Discard / Cancel. A discarded
  tab can be brought back with `Ctrl+Shift+T` until you quit.
- `<config>` is `%APPDATA%\Hexer` on Windows and `~/.config/hexer` on Linux (or
  `$XDG_CONFIG_HOME/hexer`). Hot exit can be switched off with `restore_session = false` in
  `settings.ini`.

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
the inspector and utilities. `src/script` is the Lua engine. `src/ui` is the ImGui app. Tests
live in `tests/`, one executable per module. See `CLAUDE.md` for contributor notes and `TODO.md`
for the roadmap.
