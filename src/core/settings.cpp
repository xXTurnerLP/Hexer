#include "core/settings.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdio>

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
    bool saw_ui_scale = false, saw_factor = false;
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
            if (parse_int(v, -1, 9, w) && (w == 1 || w == 2 || w == 4 || w == 8)) pointer_width = w;
        }
        else if (key == "pointer_base") parse_u64(v, pointer_base);
        else if (key == "hash_algorithms") hash_algorithms = v;
        else if (key == "font_size") parse_float(v, 6.0f, 96.0f, font_size);
        else if (key == "ui_scale") saw_ui_scale = parse_float(v, 0.5f, 4.0f, ui_scale) || saw_ui_scale;
        else if (key == "ui_scale_factor") saw_factor = true;
        else if (key == "restore_session") parse_bool(v, restore_session);
        else if (key == "session_autosave_seconds") parse_int(v, 1, 3600, session_autosave_seconds);
        else if (key == "goto_default_hex") parse_bool(v, goto_default_hex);
        else if (key == "highlight_modified") parse_bool(v, highlight_modified);
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
        else if (key.size() > 6 && key.compare(0, 6, "recent") == 0) {
            int idx = -1;
            if (parse_int(key.substr(6), -1, 1000, idx) && idx >= 0 && size_t(idx) < kMaxRecent) recent[size_t(idx)] = v;
            else unknown_keys.emplace_back(key, v);
        } else {
            unknown_keys.emplace_back(key, v);
        }
    }
    legacy_ui_scale = saw_ui_scale && !saw_factor;
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
    put("pointer_base", std::to_string(pointer_base));
    put("hash_algorithms", hash_algorithms);
    put("font_size", fmt_float(font_size));
    put("ui_scale", fmt_float(ui_scale));
    put("ui_scale_factor", "true");  // marks ui_scale as a user factor (see legacy_ui_scale)
    put("restore_session", b(restore_session));
    put("session_autosave_seconds", std::to_string(session_autosave_seconds));
    put("goto_default_hex", b(goto_default_hex));
    put("highlight_modified", b(highlight_modified));
    put("undo_merge_ms", std::to_string(undo_merge_ms));
    put("undo_merge_max_bytes", std::to_string(undo_merge_max_bytes));
    put("backup_on_save", b(backup_on_save));
    put("backup_max_bytes", std::to_string(backup_max_bytes));
    put("mono_font", mono_font);  // fonts
    put("ui_font", ui_font);
    put("font_hinting", font_hinting);
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
