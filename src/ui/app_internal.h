#pragma once
// Private to the UI module: the one App struct shared by app.cpp (main loop, menus, shortcuts,
// tabs, popups, ScriptHost) and panels.cpp (Inspector, Structure, Console, Search Results,
// Bookmarks, status bar). Plain data + a few helper functions; no class hierarchy.
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "core/document.h"
#include "core/search.h"
#include "core/session.h"
#include "core/settings.h"
#include "script/script_engine.h"
#include "ui/app.h"
#include "ui/hex_view.h"
#include "ui/theme.h"

struct GLFWwindow;

namespace hx {

// Dockable window names (also used by the default DockBuilder layout and the View menu).
inline constexpr const char* kWinEditor = "Editor";
inline constexpr const char* kWinInspector = "Inspector";
inline constexpr const char* kWinStructure = "Structure";
inline constexpr const char* kWinConsole = "Console";
inline constexpr const char* kWinResults = "Search Results";
inline constexpr const char* kWinBookmarks = "Bookmarks";

// ---- per-tab state -------------------------------------------------------------------------

// Structure panel state for one document (last parse result is kept per doc).
struct StructureState {
    ParseResult result;
    bool has_result = false;
    std::string used_parser;          // parser that produced `result` ("" = none found)
    // What the current result was computed for (re-parse when any of these change).
    uint64_t gen = UINT64_MAX;
    uint64_t reload = UINT64_MAX;
    std::string requested;            // doc.view().parser at parse time ("" = auto)
    // Debounce: a re-parse is scheduled for `due` once the inputs stop changing.
    uint64_t pending_gen = UINT64_MAX, pending_reload = UINT64_MAX;
    std::string pending_parser;
    double due = 0.0;                 // 0 = nothing scheduled
    // Tree view: expanded flag per field + flattened list of visible rows (rebuilt on change).
    std::vector<uint8_t> open;
    std::vector<int> rows;
    bool rows_dirty = true;
    int cursor_field = -1;            // field containing the caret (selected row)
    int scroll_to_field = -1;         // reveal this field's row on the next draw
};

struct SearchHits {
    std::vector<uint64_t> offsets;    // sorted ascending (as produced by a forward scan)
    HighlightSet layer;               // same ranges, for the hex view
    size_t len = 0;                   // pattern length
    bool truncated = false;
    uint64_t doc_gen = 0;             // document generation the hits were computed on
    std::string query;
};

struct Tab {
    std::unique_ptr<Document> doc;
    HexView view;
    std::string label;                // cached display name (the doc is not touched while busy)
    std::string path;                 // cached path (tooltip / title)
    unsigned int tab_id = 0;          // ImGuiID of the tab item (keeps app.tabs in visual order)
    bool insert_mode = false;
    HexViewEvents ev;                 // events of the last draw (hover offset for panels)
    uint64_t last_top_row = 0;

    // External change detection (polled for the active tab only).
    double next_disk_check = 0.0;
    bool disk_changed = false;
    bool ignore_valid = false;
    FileStat ignored_stat;            // "Ignore" pressed for this on-disk version

    // Highlight layers.
    HighlightSet bookmark_layer;
    uint64_t bookmark_sig = 0;
    SearchHits hits;
    StructureState st;
};

// ---- app-level state -----------------------------------------------------------------------

// Single-line in-place editor used by the Inspector, Structure and Bookmarks tables.
struct InlineEdit {
    int row = -1;                     // -1 = not editing
    uint64_t ctx = 0;                 // extra key (e.g. cursor offset / doc id) so edits cancel on change
    std::string buf;
    std::string error;
    int start_frame = 0;
    bool focus = false;
    bool active(int r, uint64_t c) const { return row == r && ctx == c; }
    void begin(int r, uint64_t c, std::string text);
    void end() { row = -1; }
};

struct FindState {
    bool open = false;
    bool focus = false;               // focus the input next frame
    int kind = 0;                     // SearchKind
    bool icase = false;
    std::string input;
    std::string error;
    SearchJob job;
    uint64_t job_doc = 0;             // doc id the running/last job searches
    uint64_t seen_gen = 0;            // job.generation() already handled
    size_t job_len = 0;
    std::string job_query;
};

enum class AfterSave { None, CloseTab, Quit };

struct SaveTask {
    std::thread thread;
    Progress progress;
    std::atomic<bool> finished{false};
    bool running = false;
    bool ok = false;                  // written by the worker before `finished`
    std::string err;                  // written by the worker before `finished`
    uint64_t doc_id = 0;
    std::string target;               // "" = save in place, else save-as path
    double started = 0.0;
    AfterSave after = AfterSave::None;
};

struct Notification {
    std::string text;
    bool error = false;
    double expires = 0.0;
    uint64_t id = 0;
};

struct MsgBox {
    std::string title;
    std::string text;
};

struct PaletteItem {
    std::string label;
    std::string hint;                 // shortcut text shown right-aligned
    int kind = 0;                     // 0 action, 1 script command, 2 parser, 3 recent file
    int index = 0;                    // action index
    std::string arg;                  // command / parser name / path
    bool enabled = true;
    int score = 0;
};

struct App final : ScriptHost {
    AppOptions opts;
    GLFWwindow* window = nullptr;
    Settings settings;
    double settings_dirty_at = -1.0;  // >= 0: save settings once this is ~1 s old
    Fonts fonts;
    float ui_scale = 1.0f;
    std::string ini_path;
    std::unique_ptr<ScriptEngine> engine;
    std::unique_ptr<Session> session; // null with --no-session
    bool hot_exit = false;            // session && settings.restore_session
    uint64_t session_sig = 0;
    double next_autosave = 0.0;
    std::string last_session_err;

    // Documents.
    std::vector<std::unique_ptr<Tab>> tabs;
    int active = -1;
    int select_request = -1;          // force-select this tab index next frame
    std::vector<std::unique_ptr<Tab>> closed;  // reopen with Ctrl+Shift+T (max 20)
    int untitled_counter = 0;
    std::vector<std::string> pending_open;     // drag & drop paths, processed next frame

    // Panels / layout.
    bool show_inspector = true, show_structure = true, show_console = true, show_results = true,
         show_bookmarks = true;
    bool build_layout = false;        // (re)build the default dock layout this frame
    int layout_focus_step = 0;        // after a layout build: front the Console tab, then the Editor
    bool focus_results = false;
    bool focus_console_input = false;

    FindState find;
    SaveTask save;

    // Popup requests (opened at the root ID stack in draw_popups()).
    bool req_goto = false, req_palette = false, req_fill = false, req_copy_as = false,
         req_about = false;
    uint64_t close_prompt_doc = 0;    // doc id awaiting Save/Discard/Cancel
    bool close_prompt_pending = false;
    bool quit_prompt_pending = false;
    std::vector<MsgBox> messages;

    // Goto popup.
    std::string goto_input;
    bool goto_select = false;
    // Fill popup.
    std::string fill_input = "00";
    // Command palette.
    std::string palette_query;
    std::string palette_last_query = "\x01";
    std::vector<PaletteItem> palette_all, palette_view;
    int palette_sel = 0;
    bool palette_scroll = false;

    // Console.
    std::string console_input;
    std::vector<std::string> console_history;  // last 100 lines
    int console_history_pos = -1;
    uint64_t console_seen_gen = 0;
    bool console_wrap = true;
    bool console_force_scroll = false;

    // Inline editors.
    InlineEdit insp_edit, st_edit, bm_edit;
    int insp_sel = -1;                // selected inspector row (Enter edits it)

    // Status bar / notifications.
    std::string status;
    double status_until = 0.0;
    std::vector<Notification> notifications;
    uint64_t next_notification_id = 1;

    // Quit flow.
    bool quit = false;                // leave the main loop
    bool quit_requested = false;      // window close / File > Exit (waits for running save)
    bool quitting_with_saves = false; // "Save all" chosen in the quit prompt
    std::vector<uint64_t> quit_queue; // doc ids still to save before quitting

    bool wants_poll = false;          // something animates/debounces: don't block in WaitEvents
    double next_script_poll = 0.0;
    std::string window_title;

    // ScriptHost
    Document* active_document() override;
    Document* find_document(uint64_t id) override;
    Document* open_bytes(const std::string& name, const uint8_t* data, size_t len) override;
    void reveal(Document& doc, uint64_t offset, uint64_t len) override;
};

// ---- helpers implemented in app.cpp, used by panels.cpp ------------------------------------
double now_s();
Tab* active_tab(App& app);
Tab* find_tab(App& app, uint64_t doc_id);
// Active tab's document if it may be touched right now (not saving), else nullptr.
Document* usable_doc(App& app);
// Select [offset, offset+len) with the caret at `offset`, scroll it into view, optionally focus.
void reveal_range(App& app, Tab& tab, uint64_t offset, uint64_t len, bool focus_view);
void set_status(App& app, const std::string& text, double seconds = 4.0);
void notify(App& app, const std::string& text, bool error);
void show_message(App& app, const std::string& title, const std::string& text);
bool open_path(App& app, const std::string& path);
void mark_settings_dirty(App& app);
// Status text for an edit call that returned false.
void report_edit_failure(App& app, const Document& doc);
std::string fmt_offset(uint64_t v);  // "0x0000001F" (at least 8 hex digits)

}  // namespace hx
