#pragma once
// User settings + per-OS directories. Settings are a plain "key = value" text file so they are
// easy to hand-edit; unknown keys are preserved-ignored, missing keys keep defaults.
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "core/nav.h"

namespace hx {

struct Settings {
    int bytes_per_row = 16;            // 0 = auto-fit to window width (multiple of 8)
    int group_size = 8;                // extra gap every N bytes (0 = none)
    bool uppercase_hex = true;
    bool show_ascii = true;
    bool insert_mode = false;          // default typing mode for new tabs
    bool big_endian_inspector = false;  // also the byte order of Follow pointer (Ctrl+click)
    // Follow pointer type (core/nav.h PointerType): a Ctrl+click reads a pointer_width-byte integer
    // (1, 2, 3, 4 or 8; signed if pointer_signed) at the byte and jumps to value - pointer_base
    // (e.g. a load address), or with pointer_relative to the byte's offset + value. Byte order is
    // big_endian_inspector. Picked in Settings, Search > Follow Pointer Settings or by clicking an
    // integer row in the Inspector.
    int pointer_width = 4;
    bool pointer_signed = false;
    bool pointer_relative = false;
    uint64_t pointer_base = 0;
    PointerType pointer_type() const {
        PointerType t;
        t.width = pointer_width;
        t.is_signed = pointer_signed;
        t.big_endian = big_endian_inspector;
        t.relative = pointer_relative;
        t.base = pointer_base;
        return t;
    }
    // Hashes panel: selected algorithms, comma-separated display names ("" = the defaults).
    std::string hash_algorithms;
    // Bookmarks panel: list the bookmarks of every open file, not just the active tab's.
    bool bookmarks_all_files = false;
    float font_size = 16.0f;           // monospace font pixel size (Ctrl +/- / Ctrl+wheel)
    // User zoom factor for the UI on top of the monitor's content scale (DPI), which is read at
    // startup and followed when the window moves to another monitor: 1.0 = native size everywhere.
    float ui_scale = 1.0f;
    bool restore_session = true;       // hot exit
    int session_autosave_seconds = 3;  // crash-safety interval while dirty
    bool goto_default_hex = true;
    bool highlight_modified = true;    // tint bytes that differ from disk
    // Hex digits / text glyphs colored by byte class (zero, whitespace, printable, control, high, 0xFF).
    bool byte_class_colors = false;
    // Strip right of the hex view: 0 = off, 1 = entropy heat map, 2 = byte classes (settings.ini:
    // minimap = off | entropy | classes).
    int minimap = 1;
    // Bitmap panel: pixel format (its display name, e.g. "RGB 24-bit"; "" = Gray 8-bit), width, zoom.
    std::string bitmap_format;
    int bitmap_width = 256;
    int bitmap_zoom = 2;
    // Disassembly panel: mode 0 = auto (the PE / ELF header's), 1 = 64-bit, 2 = 32-bit
    // (settings.ini: disasm_mode = auto | 64 | 32), AT&T syntax (disasm_syntax = intel | att),
    // uppercase, Follow cursor, bytes column. Per-tab map / base / pinned start: session extras.
    int disasm_mode = 0;
    bool disasm_att = false;
    bool disasm_uppercase = false;
    bool disasm_follow = true;
    bool disasm_bytes = true;
    // Typing-run undo coalescing: a pause longer than undo_merge_ms, or a run already covering
    // undo_merge_max_bytes bytes, starts a new undo step (0 = no limit). See Document::set_undo_merge.
    int undo_merge_ms = 500;
    int undo_merge_max_bytes = 32;
    // The first save over an existing file keeps the original as "<file>.backup" (never replaced
    // once it exists). In-place
    // saves of files larger than backup_max_bytes skip that copy (0 = no limit).
    bool backup_on_save = true;
    uint64_t backup_max_bytes = 4ull << 30;
    // ---- Fonts (read at startup) ----
    std::string mono_font;              // monospace font file path; "" = auto (Cascadia Mono, Consolas, JetBrains Mono, DejaVu Sans Mono...)
    std::string ui_font;                // UI font file path; "" = auto (Segoe UI, Inter, DejaVu Sans...)
    // FreeType hinting: "normal" (font's own hints, crispest) | "light" (vertical only, truer
    // shapes) | "none" (blurry, like stb_truetype) | "mono" (aliased); other values keep the default.
    std::string font_hinting = "normal";
    // ---- end fonts ----
    std::vector<std::string> recent_files;  // most recent first, max 20
    // Keys this version does not know (e.g. written by a newer Hexer); written back unchanged by save().
    std::vector<std::pair<std::string, std::string>> unknown_keys;

    // Set by load() for a file written before ui_scale became a factor (no "ui_scale_factor" key):
    // back then the first run stored the monitor scale itself in ui_scale. Not saved.
    bool legacy_ui_scale = false;

    bool load(const std::string& path);
    bool save(const std::string& path) const;
    void push_recent(const std::string& path);
    // One-time migration of a legacy file: a ui_scale equal to the current monitor scale (> 1) was
    // the old DPI-derived default, not a user choice, so it becomes 1.0 (else it would apply twice).
    // Clears legacy_ui_scale; returns true if ui_scale changed.
    bool migrate_ui_scale(float monitor_scale);
};

namespace paths {
void set_config_dir_override(const std::string& dir);  // --config-dir (tests, portable mode)
std::string config_dir();       // %APPDATA%\Hexer  |  $XDG_CONFIG_HOME/hexer (~/.config/hexer)
std::string session_dir();       // <config>/session
std::string user_scripts_dir();  // <config>/scripts  (created on first run)
std::string bundled_scripts_dir();  // <exe dir>/scripts, else HEXER_SOURCE_SCRIPTS_DIR (dev builds)
std::string settings_file();     // <config>/settings.ini
std::string imgui_ini_file();    // <config>/layout.ini
void ensure_dirs();              // create config/session/scripts dirs
}  // namespace paths

}  // namespace hx
