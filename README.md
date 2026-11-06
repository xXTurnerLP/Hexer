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
- **Process memory and raw disks.** File > Open Process... lists the running processes (filter
  by name, pid or path) and opens one's address space as a document: offset = virtual address,
  unmapped pages show as `??`, the status bar says `process 1234 · 47-bit address space`, the view
  starts at the main module (its `MZ` header) instead of the empty address 0, Search > Next /
  Previous Readable Region (`Alt+PgDn` / `Alt+PgUp`) jumps over the holes, and the
  **Regions** panel (opens by itself) lists the memory map (base, size, protection, type, module);
  click a region to select it. Its **Modules** tab lists the loaded modules (base, size, path;
  also the 32-bit ones of a WOW64 process), and Search > Go to Module... jumps to one by name. The
  Disassembly panel labels module exports (`KERNEL32.dll!CreateFileW:`) from each module's PE
  headers in memory, and the follow-pointer width defaults to the process's pointer size (8, or 4
  for a 32-bit process) until you pick one. Lua: `hx.open_process(pid)`, `doc:modules()`.
  File > Open Disk... opens a physical disk or volume
  (`\\.\PhysicalDrive0`, `/dev/sda`). Both open **read-only** unless you tick Writable (or turn
  Edit > Read-only off later); they keep their size, so they stay in overwrite mode and a save
  writes just the changed bytes in place (no backup). `F5` / File > Refresh Memory re-reads a
  process's memory map (cached bytes also refresh every second). Reading another process usually
  needs administrator rights on Windows (ptrace rights on Linux): **File > Restart as
  Administrator** (also a button in both pickers and in a tab whose memory cannot be read) keeps
  the session, unsaved edits included, starts Hexer elevated (Windows asks first) with the process
  or disk you picked, and closes the old window; the title bar then says `(Administrator)`.
  Process tabs are not kept by hot exit; disks are, like files.
- **Editing.** Overwrite or insert (toggle with `Ins`), delete, fill a selection, cut, copy and
  paste. Paste is lenient: `DE AD BE EF`, `0xde,0xad`, `\xde\xad` and `b64:...` all work.
  Edited bytes are tinted amber.
- **Full undo history.** `Ctrl+Z` / `Ctrl+Y` covers every content and bookmark change: typing,
  paste, fill, inspector and structure edits, and script commands (one undo step each). The
  history survives saves and restarts. Typing is grouped into one step per run of keys: a pause
  of more than 500 ms, or more than 32 typed bytes, starts a new step (both in Settings).
  Edit > Read-only, the Structure panel's parser and Parse at are undo steps too (they change no
  byte; `Ctrl+Z` turns read-only off again, and picking a parser after a few undos keeps the
  edits redoable); moving the caret or scrolling is not.
- **History panel** (View > History): every state of the document, oldest first, with the
  action's name (Typing, Paste, Fill, Decode XOR 0x5A, Read-only on, Parser: PNG image, ...), the
  bytes it changed and when ("just now", "5 min ago", "yesterday 14:03"; hover for the full date).
  The current state is highlighted, redo states are greyed and the last saved one is tagged
  "saved". Click a row (or use `Up` / `Down` in the panel) to undo or redo to exactly that state.
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
  edits, undo history, cursor, scroll position and bookmarks are restored on the next launch,
  and so are a split view, live tail, the Structure panel's Parse at offset and the Compare tab.
- **Selection.** Dragging over bytes a..b selects exactly those bytes; the caret is drawn on the
  last byte you dragged to (inside the selection). The Inspector, the status bar's Offset/Byte
  and inspector edits all work on the **first selected byte** (else the caret byte), and ranges
  are shown the same way everywhere, inclusive: `0x00000010-0x0000001F (16 bytes)`.
- **Multi-selection.** `Alt+click` / `Alt+drag` adds a range (`Alt+click` on a selected byte removes
  its range), *Add Selection* (`Ctrl+Shift+A`) keeps the current selection and lets you select the
  next, and *Select All Matches* (`Alt+F3`, or "Select All" in Search Results) selects every Find
  All hit (up to 100,000). Copy / Copy As (one line per range), Cut, Delete, Fill, Paste (a value
  of every range's length) and *Bookmark Selections* act on all ranges as one undo step; Hash,
  Strings, Parse Selection and XOR use the primary selection. `Esc` or a plain click ends it; the
  extra ranges are not kept across restarts. Scripts: `doc:selections()` / `doc:select_ranges{}`.
- **Data inspector.** Integers (8 to 64 bit, plus 24 bit), half/float/double, LEB128 and zigzag,
  binary, characters (ASCII, UTF-8, UTF-16), GUID, and Unix, FILETIME and DOS timestamps.
  Little or big endian. Double-click a value to edit it.
- **Structure panel.** Lua parsers decode the file into a tree. Each field is highlighted in the
  hex view in its own color. Double-click a value to edit it, and it is re-encoded in place.
  Parsers run in the background and re-run after edits, so even a slow one never freezes the
  editor (the old tree stays shown until the new one is ready; a long parse can be cancelled).
  Bundled parsers: PNG, ZIP (including ZIP64) and an example TLV protocol ("HXP").
- **Parse at an offset.** The Structure panel's **Parse at** field (or **Cursor**, Scripts > Parse
  at Cursor) runs a parser from any offset, e.g. a PNG embedded in a firmware dump; fields are
  highlighted in place and the panel shows `PNG image @ 0x00001234`. *Structure: Parse
  Selection* parses just the selected bytes (e.g. one packet).
- **C struct to parser** (Scripts > New Parser from C Struct...). Paste C `struct`/`union`/`enum`
  definitions (bit fields, `#pragma pack`, arrays sized by earlier fields, `// @be`) and get a
  readable Lua parser live. Apply it at the cursor, or save it as a script.
- **Follow pointer and jump history.** Hold `Ctrl` over a byte to see where the value there
  points (underlined, with a tooltip such as `u16 LE → 0x1234`), `Ctrl+click` jumps there;
  `Ctrl+Enter` follows the value at the cursor. **Click an integer row in the Inspector** (int8 ..
  uint64, including 24-bit) to pick the pointer type: its width and signedness, with the
  Inspector's LE/BE as byte order. The chosen row is marked `→`, has a follow button, and the
  bytes it reads are outlined in the hex view. *Relative* (target = the pointer's own offset +
  value, e.g. rel32) and a base address (target = value - base) are in Search > Follow Pointer
  Settings and the Settings window. The Structure panel's integer fields follow with their own
  declared type. Every big jump (Go to, search hits, bookmarks, Structure / Strings / Packets
  rows, Bitmap clicks, follow, script `doc:jump` / `doc:select`) is recorded: `Alt+Left` /
  `Alt+Right` or the mouse back / forward buttons walk the history.
- **Strings panel.** ASCII, UTF-16LE and UTF-16BE strings of the file or the selection, with a
  minimum length, scanned in the background (progress, Cancel), up to a million results with a
  live filter (a UTF-16 string is listed once, not again as its one-byte-shifted reading in the
  other byte order). Click a row to select the string.
- **XOR / ADD / ROL search** (Search > XOR / ADD / ROL Search..., View > XOR Search): finds
  copies of a known plaintext (`This program`, `MZ`, `PE\0\0`, `http`, or your own text / hex)
  hidden by a 1-byte XOR, ADD/SUB or rotate, or by a repeating XOR or ADD key of 2..16 bytes, in the
  whole file or the selection, in the background. Each hit shows its transform, key and the decoded
  bytes; click it to select the match and choose its key. *Guess key* ranks likely XOR (or ADD) keys
  of a zero- or space-heavy selection. **Decode selection** applies the chosen key as one undo step.
  Scripts get the same with `hx.xor_scan` / `hx.xor_guess_key` / `doc:apply_transform`.
- **Minimap.** A strip right of the hex view shows the whole file top to bottom as an entropy
  heat map (dark = zeros, blue/teal = structured data and text, orange/red = compressed or
  random) or as the byte-class mix of each row (View > Minimap). It is scanned in the
  background (sampled, so a 3 TiB file takes seconds), rescanned a second after edits (only
  where the bytes changed); while idle it reads more between the samples of empty-looking areas,
  so a small region inside a huge zero-filled disk image shows up after a while (a tick on the
  right edge), and process memory is re-read around the visible bytes every 2 s. A
  click or drag scrolls there. Hover it for the range, entropy and class percentages.
- **Byte-class colors** (View > Color Bytes by Class): hex digits and text in the color of their
  class: zero, whitespace, printable, control, high (0x80-0xFE) and 0xFF.
- **Bitmap panel** (View > Bitmap): the bytes as pixels (gray 1/4/8-bit, RGB/BGR 24-bit,
  RGBA/BGRA/ARGB 32-bit, RGB565/555, byte classes) with an adjustable width, zoom (1/16x to
  16x: below 1x a screen pixel averages its block, for very wide images) and start
  (follow the hex view, follow the cursor, or a fixed offset; right-click > Show as Bitmap Here).
  Spot images, tables and padding at a glance; click a pixel to jump there, drag to select.
- **Disassembly panel** (View > Disassembly): an x86-64 listing (or 32-bit x86) at the caret,
  decoded by [Zydis](https://github.com/zyantific/zydis): address, bytes and Intel-syntax
  instruction, colored by control flow. Virtual addresses come from the PE (PE32 / PE32+) or ELF
  headers, a manual base address, or none (address = offset); process memory uses its own
  addresses. The listing follows the hex caret (or stays pinned: right-click > Disassemble Here),
  the caret's instruction is highlighted in both views, and a click selects an instruction's bytes.
  Branch and RIP-relative targets are resolved (`lea rcx, [rip+0x2f5c]  ; 0x140004000 <.rdata>`);
  double-click, `Ctrl+click` or `Enter` follows one (recorded in the jump history, `Alt+Left`
  returns). Search > Go to Entry Point jumps to the entry point. The wheel, arrows and
  PageUp / PageDown scroll, backwards too. Lua: `hx.disasm(bytes)`, `doc:disasm(off, n)`.
- **Compare** (File > Compare With...): two open files side by side in a Compare tab, with the
  differences highlighted (red = changed, blue = only in one file), synced scrolling and
  `F7` / `Shift+F7` for the next / previous difference. A **shift** lines up files where one has
  an extra header: put the caret on the same content in both and run *Compare: Align at Cursors*,
  or type it (`0x200`, `-16`). Runs in the background; edits recompare automatically.
  **Find Shift** finds it for you: after the first misalignment from the A caret on (plain
  changes are passed over) it looks for the next distinctive 64-byte block of either file within
  +-16 MiB of the other (padding is skipped), sets the shift and shows the match ("B has 512 bytes
  more at B 0x0"); run it again for the next insertion or deletion further on. Compare With > **File on Disk** compares
  the document with its saved file ("name (on disk)"): exactly your unsaved edits.
- **Restore from .backup** (File menu, when `<file>.backup` exists): *Compare with Backup* shows
  the original side by side; *Revert to Backup* replaces the content with the backup as one
  undoable edit (nothing is read into memory, the file on disk changes only when you save, and the
  `.backup` stays the original). Hot exit keeps a revert of any size: the session refers to the
  `.backup` by path; if it changed or vanished before the next start, the file on disk opens
  instead (the console says so).
- **Packets panel** for pcap / pcapng captures (opens by itself for a capture): every packet
  with time, length, protocol and a summary (Ethernet, VLAN, IPv4/IPv6, TCP, UDP, ICMP, ARP, ...),
  a live filter, and **Parse with**: pick a parser (e.g. your protocol's) and each packet you
  click, or step through with `Up` / `Down`, is parsed in the Structure panel (optionally just
  its payload). `python tools/make_pcap.py demo.pcapng` writes a demo capture.
  The filter is a small expression language: `ip.src == 10.0.0.1`, `ip.addr == 2001:db8::/32`,
  `tcp.port == 80 and not udp`, `frame.len > 1000 or (arp || icmp)`, `eth.type == 0x86dd`,
  `tcp.flags == syn+ack`, `tcp.flags.rst`, `vlan == 10`, `frame.number > 100`,
  `"text"` (fields: `ip.src/dst/addr`, `ip.proto`, `tcp.port/srcport/dstport`, `tcp.seq/ack`,
  `tcp.flags` (+ `.syn` / `.ack` / ...), `udp.port/srcport/dstport`, `frame.len`,
  `frame.number`, `eth.type`, `vlan`, `proto`; hover the box for the list); a mistake is marked
  in red where it is and the previous filter stays. A **Stream** column numbers the TCP / UDP
  conversations. **Follow TCP Stream** (right-click a TCP packet, or the toolbar's Follow
  Stream) reassembles the connection by sequence number (out-of-order, retransmitted and
  overlapping segments, sequence wraparound) into a new read-only tab, client -> server then
  server -> client or interleaved in arrival order, with a bookmark per segment ("#12 C>S")
  to find the packet again (up to 256 MiB per stream); **Follow UDP Stream** does the same with
  the datagrams of a UDP conversation. **Open Packet / Payload as Tab** does the same for a
  single packet. Under Live Tail a growing capture is indexed incrementally (only the new
  records). Scripts read the packets with `doc:packets{ filter = ... }`.
- **Live tail** (View > Live Tail) for growing files such as logs and captures: appended data
  shows up within half a second and the view follows it while the caret is at the end
  (`Ctrl+End`). Edits and undo keep working; a file that is rewritten instead of appended to
  turns tailing off and shows the usual "changed on disk" banner.
- **Split view** (View > Split View, `Ctrl+\`): two panes of the same file, top / bottom or side by
  side (*Split Horizontally* / *Split Vertically*), each with its own scroll position and
  minimap, e.g. the header in one while you edit the end in the other. Caret, selection,
  edits and highlights are shared; the pane you clicked last (or switched to with `F6`) is the
  active one that follows the caret and every jump (Go to, search, bookmarks, follow pointer,
  live tail). Drag the divider to resize it, double-click it for half / half. Side by side,
  the rows auto-fit the narrower panes. The split (orientation, divider, both scroll
  positions) is kept by hot exit.
- **Hashes panel.** CRC-8/16/32/32C, Adler-32, Fletcher-16, FNV-1a, Sum-8, XOR-8, MD5, SHA-1,
  SHA-256 and SHA-512 of the selection (or the whole file), computed in the background and
  automatically up to 64 MiB. Paste an expected value to highlight the matching row. Scripts get
  `hx.hash(algo, bytes)` and `doc:hash(algo, off, len)`, and can add algorithms of their own
  (`hx.hash_algorithm`, listed in the panel next to the built-ins).
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
  The "All open files" choice is remembered in `settings.ini`.
- **Settings window** (Edit > Settings..., `Ctrl+,`): bytes per row, grouping, font size, UI
  scale, undo grouping, backups, hot exit, autosave interval and fonts. Changes apply right away
  (a font file path once you leave its field) and are saved to `settings.ini`.
- **Fonts** are rasterised with FreeType (hinted, pixel-snapped hex cells). `font_hinting`
  (`normal`, `light`, `none`, `mono`), `mono_font` and `ui_font` (file paths, empty = auto) are
  in the Settings window and `settings.ini`.
- **Command palette** (`Ctrl+Shift+P`) with fuzzy search over actions (e.g. *Strings: Scan File*,
  *Hash Selection*, *Structure: Parse at Cursor*), script commands, parsers and recent files.
- **Lua console** (REPL), script commands, and hot reload: save a `.lua` file and it reloads.
  Commands can ask for a value with `hx.prompt(title, default)` (a small dialog; Enter = OK,
  Esc = Cancel), e.g. *Selection: XOR with key* asks for the key.
- Tabs (drag to reorder, the order is kept by hot exit; middle-click closes one), drag and drop
  of files (several at once), recent files, reopen a closed tab with its edits (`Ctrl+Shift+T`), a
  read-only mode, and zoom (`Ctrl+=` / `Ctrl+-`, `Ctrl+wheel`).
- **File changed on disk** banner: **Reload** (the file as it is now; edits and undo history are
  dropped, bookmarks kept), **Keep mine** (saving later asks before overwriting) or **Compare**
  (your version against the file on disk in a Compare tab).
- **Editing in panels:** double-click an Inspector value, a Structure field value or a bookmark's
  name / note (or press `Enter` on the selected Inspector / Structure row) to edit it in place;
  `Enter` applies it as one undo step, `Esc` cancels. While a text field has focus, its editing
  keys (`Ctrl+Z`, `Ctrl+A`, `Ins`, arrows...) stay in it, and global shortcuts such as
  `Ctrl+Tab`, `F3` and `Ctrl+S` still work.
- **One window** (as in Sublime Text). Opening files while Hexer runs (`hexer file.bin`, "Open
  with") adds them as tabs to the running window and brings it to the front. `--new-instance`
  opens a separate window instead.
- **Unreadable data** (bad sectors, a removed drive, a file truncated by another program) is shown
  as `??` and flagged with a red "I/O error" badge in the status bar; searches stop there and say
  where, instead of matching the zeros that stand in for it.

## Download

Tagged versions (`v*`) have ready-to-run packages on the GitHub Releases page; every CI run
also keeps them as build artifacts for 7 days.

- **Windows:** `hexer-windows-x64.zip`. Unzip it anywhere and run `hexer\hexer.exe`; it needs no
  installer and no Visual C++ runtime. Keep the `scripts` folder next to the exe.
- **Linux:** `hexer-x86_64.AppImage` (`chmod +x` it, then run it), or `hexer-linux-x86_64.tar.gz`
  (run `hexer-linux-x86_64/hexer`, with `scripts/` next to it); the AppImage carries AppStream
  metadata for software centers. CI also builds `aarch64` packages (experimental: not yet
  verified on hardware). Built on Ubuntu 22.04, so glibc
  2.35 or newer. File dialogs go through xdg-desktop-portal (GNOME, KDE and most desktops have it).

## Building

Meson downloads all dependencies (ImGui, GLFW, Lua, FreeType, nativefiledialog-extended, Zydis,
doctest) on first setup.

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
| `Alt+click` / `Alt+drag` | Add a range to the multi-selection (on a selected byte: remove its range); `Esc` clears the extra ranges |
| `Ctrl+Shift+A` / `Alt+F3` | Add Selection (keep it, select the next) / Select All Matches (every Find All hit) |
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
| `Alt+PgDn` / `Alt+PgUp` (process memory) | Next / previous readable region (skips unmapped holes) |
| `Ctrl+\` / `F6` | Split view on / off; switch to the other pane |
| `Ctrl+,` | Settings |
| `Ctrl+Shift+P` | Command palette |
| `F5` | Re-parse structure (and re-read a process's memory map) |
| `F7` / `Shift+F7` (Compare tab) | Next / previous difference |
| `Ctrl+=` or `Ctrl++` / `Ctrl+-` / `Ctrl+0`, `Ctrl+wheel` | Zoom in / out / reset |
| `Ctrl+L` (in the console) | Clear console |

Mouse: click and drag to select (bytes a..b inclusive; clicking the second hex digit puts the
caret on the low nibble; clicking below the last row puts it at the end of the file),
`Shift+click` extends the selection from its fixed end, double-click selects the field under the
mouse, `Ctrl+click` follows the pointer there, right-click opens the context menu.

## Hot exit

Hexer never asks whether to save when you close it. Instead it writes a session to
`<config>/session/`: the open tabs, each document's unsaved edits and full undo/redo history,
cursor, selection, scroll position and bookmarks, plus each tab's split view, live tail, Parse
at offset, insert mode, Back / Forward history, Packets filter and "Parse with" parser, and the
Compare tab, the Find bar's pattern, the Bitmap panel's fixed start and an unsaved C Struct to
Parser draft. The session is also autosaved a few seconds after each change, so a crash loses
almost nothing. The next launch restores everything.

Independent of hot exit, `settings.ini` remembers which panels are open (a panel you closed stays
closed), the window's size, position and maximized state (put back on a connected monitor, else
centred on the main one), and the panels' options (Find kind / Ignore case, Strings encodings and
minimum length, XOR transforms, Bitmap format / zoom / Fit / Alpha / source, Packets Absolute
time / Payload only, Compare Sync scroll / caret, Disassembly options, console Word wrap). The
console's Up / Down history is kept in `<config>/console_history.txt`. The dock layout itself is
in `<config>/layout.ini` (View > Reset Layout rebuilds it).

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
- **Process memory** tabs are not kept (a process id means nothing after a restart): quitting
  drops them without asking, unsaved edits included, and notes it in the console. Save them into
  the process first if you want to keep them. Disk / volume tabs are kept like files.
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

`src/core` holds documents, streaming I/O (files, disks and process memory), the piece table,
undo, saving, the session, search, the inspector, strings extraction, hashes, XOR search, the C
struct converter, the jump history, entropy, bitmap decoding, the compare engine, the pcap reader,
x86 disassembly with PE / ELF address maps and utilities. `src/script` is the Lua engine. `src/ui` is the ImGui app. Tests
live in `tests/`, one executable per module; `tests/test_ui.cpp` drives the hex view headlessly
(simulated mouse and keyboard, no window). See `CLAUDE.md` for contributor notes and `TODO.md`
for the roadmap.
