#pragma once
// User settings + per-OS directories. Settings are a plain "key = value" text file so they are
// easy to hand-edit; unknown keys are preserved-ignored, missing keys keep defaults.
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace hx {

struct Settings {
    int bytes_per_row = 16;            // 0 = auto-fit to window width (multiple of 8)
    int group_size = 8;                // extra gap every N bytes (0 = none)
    bool uppercase_hex = true;
    bool show_ascii = true;
    bool insert_mode = false;          // default typing mode for new tabs
    bool big_endian_inspector = false;
    float font_size = 16.0f;           // monospace font pixel size (Ctrl +/- / Ctrl+wheel)
    // User zoom factor for the UI on top of the monitor's content scale (DPI), which is read at
    // startup and followed when the window moves to another monitor: 1.0 = native size everywhere.
    float ui_scale = 1.0f;
    bool restore_session = true;       // hot exit
    int session_autosave_seconds = 3;  // crash-safety interval while dirty
    bool goto_default_hex = true;
    bool highlight_modified = true;    // tint bytes that differ from disk
    // Typing-run undo coalescing: a pause longer than undo_merge_ms, or a run already covering
    // undo_merge_max_bytes bytes, starts a new undo step (0 = no limit). See Document::set_undo_merge.
    int undo_merge_ms = 500;
    int undo_merge_max_bytes = 32;
    // First save over an existing file keeps the previous contents as "<file>.backup". In-place
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
