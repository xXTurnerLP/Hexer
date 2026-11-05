#include "core/settings.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdio>

#include "core/nav.h"
#include "core/os_file.h"

namespace hx {

namespace {

constexpr size_t kMaxRecent = 20;

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string lower(std::string s) {
    for (char& c : s) c = char(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool parse_bool(const std::string& v, bool& out) {
    std::string l = lower(v);
    if (l == "1" || l == "true" || l == "yes" || l == "on") out = true;
    else if (l == "0" || l == "false" || l == "no" || l == "off") out = false;
    else return false;
    return true;
}

bool parse_int(const std::string& v, int lo, int hi, int& out) {
    int x = 0;
    auto r = std::from_chars(v.data(), v.data() + v.size(), x);
    if (r.ec != std::errc() || r.ptr != v.data() + v.size()) return false;
    out = std::clamp(x, lo, hi);
    return true;
}

bool parse_u64(const std::string& v, uint64_t& out) {
    uint64_t x = 0;
    auto r = std::from_chars(v.data(), v.data() + v.size(), x);
    if (r.ec != std::errc() || r.ptr != v.data() + v.size()) return false;
    out = x;
    return true;
}

bool parse_float(const std::string& v, float lo, float hi, float& out) {
    float x = 0;
    auto r = std::from_chars(v.data(), v.data() + v.size(), x);
    if (r.ec != std::errc() || r.ptr != v.data() + v.size() || std::isnan(x)) return false;
    out = std::clamp(x, lo, hi);
    return true;
}

// A window size: 0 (= the default) or 200..32768 (smaller values grow to 200).
bool parse_size(const std::string& v, int& out) {
    int x = 0;
    if (!parse_int(v, 0, 32768, x)) return false;
    out = x == 0 ? 0 : std::max(x, 200);
    return true;
}

std::string fmt_float(float f) {
    char buf[32];
    auto r = std::to_chars(buf, buf + sizeof buf, f);
    return std::string(buf, r.ptr);
}

// Paths compare equal ignoring slash direction (and case on Windows).
bool same_path(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x == '\\') x = '/';
        if (y == '\\') y = '/';
#ifdef _WIN32
        x = char(std::tolower(static_cast<unsigned char>(x)));
        y = char(std::tolower(static_cast<unsigned char>(y)));
#endif
        if (x != y) return false;
    }
    return true;
}

}  // namespace

bool Settings::load(const std::string& path) {
    std::string text;
    if (!os_read_whole(path, text)) return false;
    std::vector<std::string> recent(kMaxRecent);
    unknown_keys.clear();
    bool saw_ui_scale = false, saw_factor = false, saw_x = false, saw_y = false;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) nl = text.size();
        std::string line = trim(text.substr(pos, nl - pos));
        pos = nl + 1;
        if (line.empty() || line[0] == '#' || line[0] == ';' || line[0] == '[') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(line.substr(0, eq)), v = trim(line.substr(eq + 1));
        // Malformed values keep the current/default value.
        if (key == "bytes_per_row") parse_int(v, 0, 256, bytes_per_row);
        else if (key == "group_size") parse_int(v, 0, 256, group_size);
        else if (key == "uppercase_hex") parse_bool(v, uppercase_hex);
        else if (key == "show_ascii") parse_bool(v, show_ascii);
        else if (key == "insert_mode") parse_bool(v, insert_mode);
        else if (key == "big_endian_inspector") parse_bool(v, big_endian_inspector);
        else if (key == "pointer_width") {
            int w = 0;
            if (parse_int(v, -1, 9, w) && valid_pointer_width(w)) pointer_width = w;
        }
        else if (key == "pointer_signed") parse_bool(v, pointer_signed);
        else if (key == "pointer_relative") parse_bool(v, pointer_relative);
        else if (key == "pointer_base") parse_u64(v, pointer_base);
        else if (key == "hash_algorithms") hash_algorithms = v;
        else if (key == "bookmarks_all_files") parse_bool(v, bookmarks_all_files);
        else if (key == "font_size") parse_float(v, 6.0f, 96.0f, font_size);
        else if (key == "ui_scale") saw_ui_scale = parse_float(v, 0.5f, 4.0f, ui_scale) || saw_ui_scale;
        else if (key == "ui_scale_factor") saw_factor = true;
        else if (key == "restore_session") parse_bool(v, restore_session);
        else if (key == "session_autosave_seconds") parse_int(v, 1, 3600, session_autosave_seconds);
        else if (key == "goto_default_hex") parse_bool(v, goto_default_hex);
        else if (key == "highlight_modified") parse_bool(v, highlight_modified);
        else if (key == "byte_class_colors") parse_bool(v, byte_class_colors);
        else if (key == "minimap") {
            const std::string m = lower(v);
            if (m == "off") minimap = 0;
            else if (m == "entropy") minimap = 1;
            else if (m == "classes") minimap = 2;
        }
        else if (key == "bitmap_format") bitmap_format = v;
        else if (key == "bitmap_width") parse_int(v, 1, 8192, bitmap_width);
        else if (key == "bitmap_zoom") parse_int(v, 1, 16, bitmap_zoom);
        else if (key == "disasm_mode") {
            const std::string m = lower(v);
            if (m == "auto") disasm_mode = 0;
            else if (m == "64") disasm_mode = 1;
            else if (m == "32") disasm_mode = 2;
        }
        else if (key == "disasm_syntax") {
            const std::string m = lower(v);
            if (m == "intel" || m == "att") disasm_att = m == "att";
        }
        else if (key == "disasm_uppercase") parse_bool(v, disasm_uppercase);
        else if (key == "disasm_follow") parse_bool(v, disasm_follow);
        else if (key == "disasm_bytes") parse_bool(v, disasm_bytes);
        else if (key == "undo_merge_ms") parse_int(v, 0, 600000, undo_merge_ms);
        else if (key == "undo_merge_max_bytes") parse_int(v, 0, 1 << 30, undo_merge_max_bytes);
        else if (key == "backup_on_save") parse_bool(v, backup_on_save);
        else if (key == "backup_max_bytes") parse_u64(v, backup_max_bytes);
        // fonts
        else if (key == "mono_font") mono_font = v;
        else if (key == "ui_font") ui_font = v;
        else if (key == "font_hinting") {
            const std::string h = lower(v);
            if (h == "none" || h == "light" || h == "normal" || h == "mono") font_hinting = h;
        }
        // main window
        else if (key == "window_w") parse_size(v, window_w);
        else if (key == "window_h") parse_size(v, window_h);
        else if (key == "window_x") saw_x = parse_int(v, -100000, 100000, window_x) || saw_x;
        else if (key == "window_y") saw_y = parse_int(v, -100000, 100000, window_y) || saw_y;
        else if (key == "window_maximized") parse_bool(v, window_maximized);
        // panel visibility
        else if (key == "panel_inspector") parse_bool(v, panel_inspector);
        else if (key == "panel_structure") parse_bool(v, panel_structure);
        else if (key == "panel_console") parse_bool(v, panel_console);
        else if (key == "panel_results") parse_bool(v, panel_results);
        else if (key == "panel_bookmarks") parse_bool(v, panel_bookmarks);
        else if (key == "panel_strings") parse_bool(v, panel_strings);
        else if (key == "panel_hashes") parse_bool(v, panel_hashes);
        else if (key == "panel_bitmap") parse_bool(v, panel_bitmap);
        else if (key == "panel_packets") parse_bool(v, panel_packets);
        else if (key == "panel_history") parse_bool(v, panel_history);
        else if (key == "panel_xor") parse_bool(v, panel_xor);
        else if (key == "panel_disasm") parse_bool(v, panel_disasm);
        else if (key == "panel_regions") parse_bool(v, panel_regions);
        // panel options
        else if (key == "find_kind") {
            const std::string m = lower(v);
            if (m == "hex") find_kind = 0;
            else if (m == "text") find_kind = 1;
            else if (m == "utf16") find_kind = 2;
        }
        else if (key == "find_ignore_case") parse_bool(v, find_ignore_case);
        else if (key == "console_wrap") parse_bool(v, console_wrap);
        else if (key == "strings_ascii") parse_bool(v, strings_ascii);
        else if (key == "strings_utf16le") parse_bool(v, strings_utf16le);
        else if (key == "strings_utf16be") parse_bool(v, strings_utf16be);
        else if (key == "strings_newlines") parse_bool(v, strings_newlines);
        else if (key == "strings_min_length") parse_int(v, 1, 4096, strings_min_length);
        else if (key == "xor_xor") parse_bool(v, xor_xor);
        else if (key == "xor_add") parse_bool(v, xor_add);
        else if (key == "xor_rol") parse_bool(v, xor_rol);
        else if (key == "xor_key") parse_bool(v, xor_key);
        else if (key == "xor_max_key_len") parse_int(v, 2, 16, xor_max_key_len);
        else if (key == "bitmap_fit") parse_bool(v, bitmap_fit);
        else if (key == "bitmap_alpha") parse_bool(v, bitmap_alpha);
        else if (key == "bitmap_source") {
            const std::string m = lower(v);
            if (m == "view") bitmap_source = 0;
            else if (m == "cursor") bitmap_source = 1;
        }
        else if (key == "packets_absolute_time") parse_bool(v, packets_absolute_time);
        else if (key == "packets_payload_only") parse_bool(v, packets_payload_only);
        else if (key == "packets_follow_interleaved") parse_bool(v, packets_follow_interleaved);
        else if (key == "compare_sync_scroll") parse_bool(v, compare_sync_scroll);
        else if (key == "compare_sync_caret") parse_bool(v, compare_sync_caret);
        else if (key.size() > 6 && key.compare(0, 6, "recent") == 0) {
            int idx = -1;
            if (parse_int(key.substr(6), -1, 1000, idx) && idx >= 0 && size_t(idx) < kMaxRecent) recent[size_t(idx)] = v;
            else unknown_keys.emplace_back(key, v);
        } else {
            unknown_keys.emplace_back(key, v);
        }
    }
    legacy_ui_scale = saw_ui_scale && !saw_factor;
    window_pos = saw_x && saw_y;
    recent_files.clear();
    for (auto& r : recent)
        if (!r.empty()) recent_files.push_back(std::move(r));
    return true;
}

bool Settings::save(const std::string& path) const {
    std::string s = "# Hexer settings (key = value). Unknown keys are kept.\n";
    auto put = [&](const char* k, const std::string& v) {
        s += k;
        s += " = ";
        s += v;
        s += '\n';
    };
    auto b = [](bool v) { return std::string(v ? "true" : "false"); };
    put("bytes_per_row", std::to_string(bytes_per_row));
    put("group_size", std::to_string(group_size));
    put("uppercase_hex", b(uppercase_hex));
    put("show_ascii", b(show_ascii));
    put("insert_mode", b(insert_mode));
    put("big_endian_inspector", b(big_endian_inspector));
    put("pointer_width", std::to_string(pointer_width));
    put("pointer_signed", b(pointer_signed));
    put("pointer_relative", b(pointer_relative));
    put("pointer_base", std::to_string(pointer_base));
    put("hash_algorithms", hash_algorithms);
    put("bookmarks_all_files", b(bookmarks_all_files));
    put("font_size", fmt_float(font_size));
    put("ui_scale", fmt_float(ui_scale));
    put("ui_scale_factor", "true");  // marks ui_scale as a user factor (see legacy_ui_scale)
    put("restore_session", b(restore_session));
    put("session_autosave_seconds", std::to_string(session_autosave_seconds));
    put("goto_default_hex", b(goto_default_hex));
    put("highlight_modified", b(highlight_modified));
    put("byte_class_colors", b(byte_class_colors));
    put("minimap", minimap == 0 ? "off" : minimap == 2 ? "classes" : "entropy");
    put("bitmap_format", bitmap_format);
    put("bitmap_width", std::to_string(bitmap_width));
    put("bitmap_zoom", std::to_string(bitmap_zoom));
    put("disasm_mode", disasm_mode == 1 ? "64" : disasm_mode == 2 ? "32" : "auto");
    put("disasm_syntax", disasm_att ? "att" : "intel");
    put("disasm_uppercase", b(disasm_uppercase));
    put("disasm_follow", b(disasm_follow));
    put("disasm_bytes", b(disasm_bytes));
    put("undo_merge_ms", std::to_string(undo_merge_ms));
    put("undo_merge_max_bytes", std::to_string(undo_merge_max_bytes));
    put("backup_on_save", b(backup_on_save));
    put("backup_max_bytes", std::to_string(backup_max_bytes));
    put("mono_font", mono_font);  // fonts
    put("ui_font", ui_font);
    put("font_hinting", font_hinting);
    put("window_w", std::to_string(window_w));
    put("window_h", std::to_string(window_h));
    if (window_pos) {
        put("window_x", std::to_string(window_x));
        put("window_y", std::to_string(window_y));
    }
    put("window_maximized", b(window_maximized));
    put("panel_inspector", b(panel_inspector));
    put("panel_structure", b(panel_structure));
    put("panel_console", b(panel_console));
    put("panel_results", b(panel_results));
    put("panel_bookmarks", b(panel_bookmarks));
    put("panel_strings", b(panel_strings));
    put("panel_hashes", b(panel_hashes));
    put("panel_bitmap", b(panel_bitmap));
    put("panel_packets", b(panel_packets));
    put("panel_history", b(panel_history));
    put("panel_xor", b(panel_xor));
    put("panel_disasm", b(panel_disasm));
    put("panel_regions", b(panel_regions));
    put("find_kind", find_kind == 1 ? "text" : find_kind == 2 ? "utf16" : "hex");
    put("find_ignore_case", b(find_ignore_case));
    put("console_wrap", b(console_wrap));
    put("strings_ascii", b(strings_ascii));
    put("strings_utf16le", b(strings_utf16le));
    put("strings_utf16be", b(strings_utf16be));
    put("strings_newlines", b(strings_newlines));
    put("strings_min_length", std::to_string(strings_min_length));
    put("xor_xor", b(xor_xor));
    put("xor_add", b(xor_add));
    put("xor_rol", b(xor_rol));
    put("xor_key", b(xor_key));
    put("xor_max_key_len", std::to_string(xor_max_key_len));
    put("bitmap_fit", b(bitmap_fit));
    put("bitmap_alpha", b(bitmap_alpha));
    put("bitmap_source", bitmap_source == 1 ? "cursor" : "view");
    put("packets_absolute_time", b(packets_absolute_time));
    put("packets_payload_only", b(packets_payload_only));
    put("packets_follow_interleaved", b(packets_follow_interleaved));
    put("compare_sync_scroll", b(compare_sync_scroll));
    put("compare_sync_caret", b(compare_sync_caret));
    for (size_t i = 0; i < recent_files.size() && i < kMaxRecent; ++i)
        put(("recent" + std::to_string(i)).c_str(), recent_files[i]);
    for (const auto& [k, v] : unknown_keys) put(k.c_str(), v);
    std::string dir = path_dirname(path);
    if (!dir.empty()) os_mkdirs(dir);
    return os_write_whole_atomic(path, s.data(), s.size());
}

bool Settings::migrate_ui_scale(float monitor_scale) {
    const bool legacy = legacy_ui_scale;
    legacy_ui_scale = false;
    if (!legacy || !(monitor_scale > 1.0f) || std::fabs(ui_scale - monitor_scale) > 0.005f) return false;
    ui_scale = 1.0f;
    return true;
}

void Settings::push_recent(const std::string& path) {
    if (path.empty()) return;
    recent_files.erase(std::remove_if(recent_files.begin(), recent_files.end(),
                                      [&](const std::string& r) { return same_path(r, path); }),
                       recent_files.end());
    recent_files.insert(recent_files.begin(), path);
    if (recent_files.size() > kMaxRecent) recent_files.resize(kMaxRecent);
}

// ---- console history ----------------------------------------------------------------------------

std::vector<std::string> load_history(const std::string& path) {
    std::vector<std::string> out;
    std::string text;
    if (!os_read_whole(path, text)) return out;
    std::string cur;
    for (size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '\n') {
            if (!cur.empty()) out.push_back(std::move(cur));
            cur.clear();
        } else if (c == '\r') {
            // CRLF (a hand-edited file): line breaks inside an entry are escaped, so this is noise
        } else if (c == '\\' && i + 1 < text.size()) {
            const char e = text[++i];
            cur += e == 'n' ? '\n' : e == 'r' ? '\r' : e;
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    return out;
}

bool save_history(const std::string& path, const std::vector<std::string>& entries, size_t max) {
    std::string s;
    const size_t first = entries.size() > max ? entries.size() - max : 0;
    for (size_t i = first; i < entries.size(); ++i) {
        for (char c : entries[i]) {
            if (c == '\\') s += "\\\\";
            else if (c == '\n') s += "\\n";
            else if (c == '\r') s += "\\r";
            else s += c;
        }
        s += '\n';
    }
    std::string dir = path_dirname(path);
    if (!dir.empty()) os_mkdirs(dir);
    return os_write_whole_atomic(path, s.data(), s.size());
}

// ---- window placement ---------------------------------------------------------------------------

int window_area(const WindowRect& r, const std::vector<WindowRect>& areas) {
    int best = -1;
    int64_t best_overlap = 0;
    for (size_t i = 0; i < areas.size(); ++i) {
        const WindowRect& a = areas[i];
        const int64_t w = std::min(int64_t(r.x) + r.w, int64_t(a.x) + a.w) - std::max<int64_t>(r.x, a.x);
        const int64_t h = std::min(int64_t(r.y) + r.h, int64_t(a.y) + a.h) - std::max<int64_t>(r.y, a.y);
        if (w <= 0 || h <= 0 || w * h <= best_overlap) continue;
        best_overlap = w * h;
        best = int(i);
    }
    return best;
}

WindowRect fit_window(WindowRect r, const WindowRect& area, bool center) {
    r.w = std::clamp(r.w, 1, std::max(1, area.w));
    r.h = std::clamp(r.h, 1, std::max(1, area.h));
    if (center) {
        r.x = area.x + (area.w - r.w) / 2;
        r.y = area.y + (area.h - r.h) / 2;
    } else {
        r.x = std::clamp(r.x, area.x, std::max(area.x, area.x + area.w - r.w));
        r.y = std::clamp(r.y, area.y, std::max(area.y, area.y + area.h - r.h));
    }
    return r;
}

// ---- paths --------------------------------------------------------------------------------------

namespace paths {

namespace {
std::string& override_dir() {
    static std::string dir;
    return dir;
}
}  // namespace

void set_config_dir_override(const std::string& dir) { override_dir() = dir; }

std::string config_dir() {
    if (!override_dir().empty()) return override_dir();
#ifdef _WIN32
    std::string base = os_env("APPDATA");
    if (base.empty()) {
        std::string profile = os_env("USERPROFILE");
        base = profile.empty() ? os_exe_dir() : path_join(path_join(profile, "AppData"), "Roaming");
    }
    return path_join(base, "Hexer");
#else
    std::string xdg = os_env("XDG_CONFIG_HOME");
    if (!xdg.empty() && xdg[0] == '/') return path_join(xdg, "hexer");  // spec: relative paths are invalid
    std::string home = os_env("HOME");
    if (home.empty()) return path_join(os_exe_dir(), ".hexer");
    return path_join(path_join(home, ".config"), "hexer");
#endif
}

std::string session_dir() { return path_join(config_dir(), "session"); }
std::string user_scripts_dir() { return path_join(config_dir(), "scripts"); }
std::string settings_file() { return path_join(config_dir(), "settings.ini"); }
std::string imgui_ini_file() { return path_join(config_dir(), "layout.ini"); }
std::string console_history_file() { return path_join(config_dir(), "console_history.txt"); }

std::string bundled_scripts_dir() {
    std::string exe_scripts = path_join(os_exe_dir(), "scripts");
    if (os_stat(exe_scripts).is_dir) return exe_scripts;
#ifdef HEXER_SOURCE_SCRIPTS_DIR
    return HEXER_SOURCE_SCRIPTS_DIR;
#else
    return exe_scripts;
#endif
}

void ensure_dirs() {
    os_mkdirs(config_dir());
    os_mkdirs(session_dir());
    os_mkdirs(user_scripts_dir());
}

}  // namespace paths

}  // namespace hx
