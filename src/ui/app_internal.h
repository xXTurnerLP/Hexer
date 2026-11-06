#pragma once
// Private to the UI module: the one App struct shared by app.cpp (main loop, menus, shortcuts,
// tabs, popups, ScriptHost) and panels.cpp (Inspector, Structure, Console, Search Results,
// Bookmarks, Strings, Hashes, Bitmap, Packets, History, XOR Search, Regions, status bar). Plain data + a few helper functions;
// no class hierarchy.
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "core/document.h"
#include "core/entropy.h"
#include "core/nav.h"
#include "core/search.h"
#include "core/session.h"
#include "core/settings.h"
#include "script/parse_job.h"
#include "script/script_engine.h"
#include "ui/app.h"
#include "ui/dialog_cstruct.h"
#include "ui/dialog_targets.h"
#include "ui/hex_view.h"
#include "ui/input.h"
#include "ui/minimap.h"
#include "ui/panel_bitmap.h"
#include "ui/panel_disasm.h"
#include "ui/panel_hash.h"
#include "ui/panel_history.h"
#include "ui/panel_packets.h"
#include "ui/panel_strings.h"
#include "ui/panel_xor.h"
#include "ui/theme.h"
#include "ui/view_diff.h"

struct GLFWwindow;

namespace hx {

// Dockable window names (also used by the default DockBuilder layout and the View menu).
inline constexpr const char* kWinEditor = "Editor";
inline constexpr const char* kWinInspector = "Inspector";
inline constexpr const char* kWinStructure = "Structure";
inline constexpr const char* kWinConsole = "Console";
inline constexpr const char* kWinResults = "Search Results";
inline constexpr const char* kWinBookmarks = "Bookmarks";
inline constexpr const char* kWinStrings = "Strings";
inline constexpr const char* kWinHashes = "Hashes";
inline constexpr const char* kWinCStruct = "C Struct to Parser";
inline constexpr const char* kWinBitmap = "Bitmap";
inline constexpr const char* kWinPackets = "Packets";
inline constexpr const char* kWinHistory = "History";
inline constexpr const char* kWinXor = "XOR Search";
inline constexpr const char* kWinRegions = "Regions";
inline constexpr const char* kWinDisasm = "Disassembly";

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
    // A clicked container row stays selected (and collapsed) while the caret stays where the
    // click put it, although the caret byte belongs to one of its children.
    int clicked_field = -1;
    uint64_t clicked_cursor = 0;
    // Parse at offset / range: the document's ViewState::parse_base / parse_length (undoable with
    // the parser, kept in the session; set_parse()). Needs a chosen parser (detect() looks at the
    // file start). A length comes from the Packets panel (one packet's bytes).
    uint64_t parsed_base = 0;         // base / length of `result`
    uint64_t parsed_length = UINT64_MAX;
    std::string base_input;           // the panel's "@" field
    uint64_t base_input_for = 0;      // the parse base base_input was last set from
    // Wall time of the last detect + parse (start of its job to its result).
    double last_parse_ms = 0.0;
    // The parse runs on a worker (script/parse_job.h); `result` stays shown (greyed after a
    // moment) until it finishes. job_reload / job_requested: what it was started for (with the
    // job's own generation / base / length). A job whose inputs changed is cancelled and parked
    // in `retired` until its worker has stopped (never joined on the UI thread while it runs).
    std::unique_ptr<ParseJob> job;
    uint64_t job_reload = UINT64_MAX;
    std::string job_requested;
    double job_t0 = 0.0;              // app clock at its start
    std::vector<std::unique_ptr<ParseJob>> retired;
    // Auto (no parser chosen): the parser is detected first, by a DetectJob on a worker; the
    // parse job starts once its answer arrives (still current; job_t0 = the detect's start).
    std::unique_ptr<DetectJob> detect;
    std::vector<std::unique_ptr<DetectJob>> retired_detect;
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
    bool io_warned = false;           // console warning about unreadable data already shown

    // Highlight layers.
    HighlightSet bookmark_layer;
    uint64_t bookmark_sig = 0;
    SearchHits hits;
    StructureState st;
    NavHistory nav;                   // Back / Forward over big jumps (Alt+Left / Alt+Right)

    // Entropy / byte-class minimap (scanned while the tab is shown; rescanned after edits, debounced).
    EntropyJob entropy;
    Minimap minimap;
    uint64_t entropy_gen = UINT64_MAX;          // document generation of the last started scan
    uint64_t entropy_pending_gen = UINT64_MAX;  // generation waiting for the debounce
    double entropy_first_change = 0.0, entropy_last_change = 0.0;
    uint64_t entropy_saved = 0;                 // saved_state_id() at the last scan (changed: full rescan)
    std::shared_ptr<const EntropyResult> entropy_shown;  // what the minimap draws (old map while rescanning)

    TailState tail;                   // View > Live Tail (session: doc extra tail.enabled)

    // doc.view().top_row is a row index; the tab's HexView and a Compare side may use different
    // bytes per row. top_bpr = the row width top_row is currently expressed in (0 = unknown).
    int top_bpr = 0;
    int compare_bpr = 0;              // bytes per row of this document's side in the Compare tab

    // View > Split View: the tab shows two panes of this document, each with its own scroll.
    // Caret and selection are shared (one ViewState). `view`, `minimap`, `ev` and
    // doc.view().top_row (rows of top_bpr bytes) always belong to the ACTIVE pane - the one
    // clicked last - so jumps, caret follow, live tail, panels and the session work on it
    // unchanged; the other pane keeps its scroll in split_top (rows of split_bpr bytes).
    // Activating the other pane swaps the two sets (activate_other_pane). Persisted as doc extras
    // split.on / split.vertical / split.ratio / split.active / split.top2 (see save_tab_extras).
    bool split = false;
    bool split_vertical = false;      // false: panes stacked top / bottom; true: side by side
    float split_ratio = 0.5f;         // share of the first (top / left) pane
    int split_active_pos = 0;         // where `view` is drawn: 0 = top / left, 1 = bottom / right
    HexView split_view;               // the inactive pane
    Minimap split_minimap;
    uint64_t split_top = 0;
    int split_bpr = 0;                // row width split_top is expressed in (0 = unknown)
    // Session restore: the inactive pane's first visible byte, applied once that pane has a layout
    // (its row width is only known then). UINT64_MAX = nothing pending.
    uint64_t split_restore = UINT64_MAX;
};

// ---- app-level state -----------------------------------------------------------------------

// Single-line in-place editor used by the Inspector, Structure and Bookmarks tables.
struct FindState {
    bool open = false;
    bool focus = false;               // focus the input next frame
    int kind = 0;                     // SearchKind
    bool icase = false;
    std::string input;
    std::string error;
    SearchJob job;
    uint64_t job_doc = 0;             // doc id the running/last job searches
    uint64_t job_doc_gen = 0;         // that document's generation when the job took its snapshot
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
    int kind = 0;                     // 0 action, 1 script command, 2 parser, 3 recent file, 4 bookmark,
                                      // 5 compare with document `doc`, 6 compare with a file (dialog)
    int index = 0;                    // action index / bookmark index
    std::string arg;                  // command / parser name / path
    bool enabled = true;
    int score = 0;
    uint64_t doc = 0;                 // bookmark: document id
};

struct App final : ScriptHost {
    AppOptions opts;
    GLFWwindow* window = nullptr;
    Settings settings;
    double settings_dirty_at = -1.0;  // >= 0: save settings once this is ~1 s old
    Fonts fonts;
    FontOptions fonts_loaded;         // what `fonts` came from; a Settings change reloads them
    float ui_scale = 1.0f;            // monitor content scale * settings.ui_scale
    float dpi_scale = 1.0f;           // monitor content scale (GLFW), followed at runtime
    float zoom_wheel = 0.0f;          // Ctrl+wheel delta not yet a whole zoom step (wheel_steps)
    bool dpi_changed = false;         // content-scale callback fired: re-apply before next frame
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
    bool restoring = false;           // restore_session is adding the session's tabs (no auto-show)

    // Panels / layout. The show_* flags are settings.ini panel_* (load_ui_settings /
    // store_ui_settings); Packets / Regions also open by themselves when a capture / process is
    // opened (not when the session restores one: then the saved visibility wins).
    bool show_inspector = true, show_structure = true, show_console = true, show_results = true,
         show_bookmarks = true, show_strings = true, show_hashes = true;
    bool show_bitmap = false, show_packets = false;  // opened on demand (Packets: for captures)
    bool show_history = false, show_xor = false;
    bool show_regions = false;        // auto-shown when a process document is opened
    bool show_disasm = false, focus_disasm = false;  // Disassembly panel (View > Disassembly)
    bool show_settings = false;       // Settings window (Edit > Settings..., Ctrl+,)
    bool focus_bookmarks = false;     // bring the Bookmarks panel to the front next frame
    bool build_layout = false;        // (re)build the default dock layout this frame
    int layout_focus_step = 0;        // after a layout build: front the Console tab, then the Editor
    bool focus_results = false;
    bool focus_console_input = false;
    bool focus_structure = false, focus_strings = false, focus_hashes = false;
    bool focus_bitmap = false, focus_packets = false;
    bool focus_history = false, focus_xor = false, focus_regions = false;

    // Feature panels (self-contained; App members so their worker threads are joined before exit).
    StringsPanel strings_panel;
    HashPanel hash_panel;
    CStructDialog cstruct_dlg;
    BitmapPanel bitmap_panel;
    PacketsPanel packets_panel;
    HistoryPanel history_panel;
    XorPanel xor_panel;
    TargetsDialog targets;            // File > Open Process... / Open Disk...
    RegionsPanel regions_panel;
    DisasmPanel disasm_panel;         // Disassembly (x86-64 / x86 listing at the caret)

    // Compare (File > Compare With...): a "Compare" tab in the editor's tab bar showing two open
    // documents side by side. Closing either document ends it.
    std::unique_ptr<DiffView> diff;
    uint64_t diff_a = 0, diff_b = 0;  // Document::id() of the two sides
    bool diff_select = false;         // select the Compare tab next frame
    bool diff_shown = false;          // the Compare tab was the selected tab last frame (session)
    // B side that is not an open tab (diff_b is its id): A's file as saved on disk ("Compare with
    // File on Disk": shows exactly the unsaved edits; reloaded when the file changes) or A's
    // "<file>.backup" ("Restore from .backup" > Compare with Backup). Read-only, owned here.
    std::unique_ptr<Tab> diff_aux;
    bool diff_aux_backup = false;     // diff_aux is the .backup (else the file on disk)

    FindState find;
    SaveTask save;

    // Popup requests (opened at the root ID stack in draw_popups()).
    bool req_goto = false, req_palette = false, req_fill = false, req_copy_as = false,
         req_about = false, req_bookmark_jump = false, req_compare = false;
    uint64_t close_prompt_doc = 0;    // doc id awaiting Save/Discard/Cancel
    bool close_prompt_pending = false;
    uint64_t reload_prompt_doc = 0;   // doc id awaiting "Reload from disk and discard edits?"
    bool reload_prompt_pending = false;
    uint64_t overwrite_prompt_doc = 0;  // doc id whose save waits for "file changed on disk" choice
    AfterSave overwrite_prompt_after = AfterSave::None;
    bool overwrite_prompt_pending = false;
    bool quit_prompt_pending = false;
    std::vector<uint64_t> quit_prompt_docs;  // docs the quit prompt asks about (empty = all dirty)
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
    bool palette_bookmarks = false;   // the palette lists bookmarks of all open files (Ctrl+Shift+B)
    bool palette_compare = false;     // the palette picks the document to compare with (Compare With...)
    // hx.prompt modal (a script command waits for an answer).
    std::string prompt_buf;

    // Console.
    std::string console_input;
    std::vector<std::string> console_history;  // last 100 lines
    int console_history_pos = -1;
    std::string console_draft;        // line being typed before browsing the history
    uint64_t console_seen_gen = 0;
    bool console_wrap = true;
    bool console_force_scroll = false;

    // Inline editors.
    InlineEdit insp_edit, st_edit, bm_edit;
    uint64_t edit_doc = 0;            // active doc id the inline edits belong to (ended on change)
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
    bool quit_skip_unsafe = false;    // hot exit: the !hot_exit_safe() docs were already decided

    // Single instance: this instance owns the main session dir and opens files other Hexer
    // processes forward to it (Session inbox).
    bool inbox = false;
    double next_inbox_poll = 0.0;

    bool wants_poll = false;          // something animates/debounces: don't block in WaitEvents
    double next_script_poll = 0.0;
    std::string window_title;

    // ScriptHost
    Document* active_document() override;
    Document* find_document(uint64_t id) override;
    Document* open_bytes(const std::string& name, const uint8_t* data, size_t len) override;
    void reveal(Document& doc, uint64_t offset, uint64_t len) override;
    bool view_range(Document& doc, uint64_t& first, uint64_t& last) override;
    std::shared_ptr<const SymbolTable> cached_symbols(Document& doc) override;
    Document* open_process(uint32_t pid, bool writable, std::string* err) override;

    // Follow-pointer width of process documents (core/nav.h AutoPointerWidth): the process's
    // pointer size while one is active, until the user picks a width (panels.cpp calls pick()).
    AutoPointerWidth auto_ptr;
    uint64_t auto_ptr_doc = UINT64_MAX;  // active doc id auto_ptr was last applied for
};

// ---- helpers implemented in app.cpp, used by panels.cpp ------------------------------------
double now_s();
Tab* active_tab(App& app);
Tab* find_tab(App& app, uint64_t doc_id);
// Active tab's document if it may be touched right now (not saving), else nullptr.
Document* usable_doc(App& app);
// Select [offset, offset+len) with the caret at `offset`, scroll it into view, optionally focus.
// A "big jump": the position it leaves is pushed onto the tab's NavHistory (Back returns to it).
void reveal_range(App& app, Tab& tab, uint64_t offset, uint64_t len, bool focus_view);
void set_status(App& app, const std::string& text, double seconds = 4.0);
void notify(App& app, const std::string& text, bool error);
void show_message(App& app, const std::string& title, const std::string& text);
bool open_path(App& app, const std::string& path);
// Native "Save as" dialog for a new file (e.g. an exported header) named `default_name`, in the
// active file's folder. False when cancelled (dialog errors are reported).
bool save_file_dialog(App& app, const std::string& default_name, std::string& out);
void mark_settings_dirty(App& app);
// Persistence of UI state (see CLAUDE.md "Persistence"): load_ui_settings copies settings.ini
// values into App / panel state at startup; store_ui_settings copies them back (every frame and
// before the final save) and marks the settings dirty when one changed.
void load_ui_settings(App& app);
void store_ui_settings(App& app);
// Status text for an edit call that returned false.
void report_edit_failure(App& app, const Document& doc);
std::string fmt_offset(uint64_t v);  // "0x0000001F" (at least 8 hex digits)

}  // namespace hx
