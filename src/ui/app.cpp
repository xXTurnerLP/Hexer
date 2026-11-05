// Application shell: window + GL + ImGui setup, main loop, tabs, menus, shortcuts, popups,
// saving (worker thread), search, hot-exit session, and the ScriptHost implementation.
// Panels live in ui/panels.cpp; shared state is the App struct in ui/app_internal.h.
#include "ui/app.h"

#include <algorithm>
#include <cfloat>
#include <chrono>
#include <climits>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include <GLFW/glfw3.h>

#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "misc/cpp/imgui_stdlib.h"
#include "nfd.h"

#include "core/highlight.h"
#include "core/os_file.h"
#include "core/util.h"
#include "ui/app_internal.h"
#include "ui/panels.h"
#ifndef _WIN32
#include "ui/icon_data.h"
#endif

namespace hx {

namespace {

constexpr size_t kMaxClosedTabs = 20;
constexpr uint64_t kMaxClipboardBytes = 64ull << 20;  // 64 MiB
constexpr float kMinFont = 8.0f, kMaxFont = 48.0f, kDefaultFont = 16.0f;
constexpr float kUiFontPx = 16.0f;
const char* const kEmDash = "\xE2\x80\x94";
const char* const kDirtyDot = "\xE2\x97\x8F";

// Popup identifiers (OpenPopup and BeginPopup* are both called at the root ID stack).
const char* const kPopGoto = "Go to offset###goto";
const char* const kPopPalette = "###palette";
const char* const kPopFill = "Fill selection###fill";
const char* const kPopCopyAs = "###copyas";
const char* const kPopClose = "Unsaved changes###closeprompt";
const char* const kPopQuit = "Unsaved changes###quitprompt";
const char* const kPopReload = "Reload from disk###reloadprompt";
const char* const kPopOverwrite = "File changed on disk###overwriteprompt";
const char* const kPopSaving = "Saving###saving";
const char* const kPopMessage = "###message";
const char* const kPopAbout = "About Hexer###about";
const char* const kPopPrompt = "###script_prompt";  // hx.prompt (title = the script's title)

std::vector<std::string> command_line_utf8(int argc, char** argv);  // bottom of file
void allow_foreground_handoff();                                    // bottom of file

const char* const kUsage =
    "usage: hexer [options] [files...]\n"
    "  --config-dir DIR     use DIR for settings, session and user scripts\n"
    "  --no-session         do not restore or write the hot-exit session\n"
    "  --new-instance       open a new window even if Hexer is already running\n"
    "  --screenshot OUT.ppm render, save the window as a binary PPM and exit\n"
    "  --frames N           exit after N frames (default 30 with --screenshot)\n"
    "  --exec \"LUA\"         run Lua in the console after startup\n"
    "  --action \"NAME\"      run a menu/palette action after startup, e.g. \"Settings...\" (repeatable)";

}  // namespace

// =============================================================================================
// Command line
// =============================================================================================

bool parse_args(int argc, char** argv, AppOptions& out, std::string* err) {
    auto fail = [&](const std::string& msg) {
        if (err) *err = msg;
        return false;
    };
    const std::vector<std::string> args = command_line_utf8(argc, argv);
    bool only_files = false;
    for (size_t i = 1; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (only_files || a.size() < 2 || a[0] != '-') {
            out.files.push_back(a);
            continue;
        }
        auto value = [&](std::string& dst) {
            if (i + 1 >= args.size()) return false;
            dst = args[++i];
            return true;
        };
        if (a == "--") {
            only_files = true;
        } else if (a == "--no-session") {
            out.no_session = true;
        } else if (a == "--new-instance") {
            out.new_instance = true;
        } else if (a == "--config-dir") {
            if (!value(out.config_dir) || out.config_dir.empty()) return fail("--config-dir needs a directory");
        } else if (a == "--screenshot") {
            if (!value(out.screenshot) || out.screenshot.empty()) return fail("--screenshot needs an output path");
        } else if (a == "--exec") {
            if (!value(out.run_lua)) return fail("--exec needs Lua code");
        } else if (a == "--action") {
            std::string v;
            if (!value(v) || v.empty()) return fail("--action needs an action name");
            out.actions.push_back(v);
        } else if (a == "--frames") {
            std::string v;
            if (!value(v)) return fail("--frames needs a number");
            char* end = nullptr;
            long n = std::strtol(v.c_str(), &end, 10);
            if (v.empty() || *end != '\0' || n <= 0 || n > 1000000) return fail("--frames: invalid count '" + v + "'");
            out.frames = int(n);
        } else if (a == "-h" || a == "--help") {
            return fail(kUsage);
        } else {
            return fail("unknown option '" + a + "'\n" + kUsage);
        }
    }
    if (!out.screenshot.empty() && out.frames <= 0) out.frames = 30;
    return true;
}

// =============================================================================================
// Small shared helpers (declared in app_internal.h)
// =============================================================================================

double now_s() { return glfwGetTime(); }

std::string fmt_offset(uint64_t v) { return "0x" + fmt_hex(v, 8); }

Tab* active_tab(App& app) {
    if (app.active < 0 || app.active >= int(app.tabs.size())) return nullptr;
    return app.tabs[size_t(app.active)].get();
}

Tab* find_tab(App& app, uint64_t doc_id) {
    for (auto& t : app.tabs)
        if (t->doc->id() == doc_id) return t.get();
    return nullptr;
}

static int tab_index(App& app, const Tab* tab) {
    for (size_t i = 0; i < app.tabs.size(); ++i)
        if (app.tabs[i].get() == tab) return int(i);
    return -1;
}

Document* usable_doc(App& app) {
    Tab* t = active_tab(app);
    return (t && !t->doc->busy()) ? t->doc.get() : nullptr;
}

void set_status(App& app, const std::string& text, double seconds) {
    app.status = text;
    app.status_until = now_s() + seconds;
}

void notify(App& app, const std::string& text, bool error) {
    Notification n;
    n.text = text;
    n.error = error;
    n.expires = now_s() + (error ? 15.0 : 7.0);
    n.id = app.next_notification_id++;
    app.notifications.push_back(std::move(n));
    if (app.notifications.size() > 5) app.notifications.erase(app.notifications.begin());
}

static void log_console(App& app, ConsoleLine::Kind kind, const std::string& text) {
    if (app.engine) app.engine->log(kind, text);
}

void show_message(App& app, const std::string& title, const std::string& text) {
    app.messages.push_back({title, text});
}

void mark_settings_dirty(App& app) {
    if (app.settings_dirty_at < 0.0) app.settings_dirty_at = now_s();
}

// Settings the core reads app-wide: typing-run undo merging and backups. Call after changes.
static void apply_core_settings(const Settings& s) {
    Document::set_undo_merge(s.undo_merge_ms, uint64_t(std::max(0, s.undo_merge_max_bytes)));
    Document::set_backup_policy(s.backup_on_save, s.backup_max_bytes);
}

void report_edit_failure(App& app, const Document& doc) {
    if (doc.busy())
        set_status(app, "Document is busy (saving)");
    else if (doc.read_only())
        set_status(app, "Document is read-only (Edit > Read-only to change)");
    else
        set_status(app, "Edit rejected (out of range)");
}

void reveal_range(App& app, Tab& tab, uint64_t offset, uint64_t len, bool focus_view) {
    Document& d = *tab.doc;
    if (d.busy()) return;
    const uint64_t size = d.size();
    offset = std::min(offset, size);
    uint64_t end = (len > size - offset) ? size : offset + len;
    ViewState& v = d.view();
    v.cursor = offset;  // caret at the start so the inspector shows the value there
    v.anchor = end;
    v.low_nibble = false;
    d.view_generation++;
    tab.view.request_scroll_to(offset, true);
    if (focus_view) tab.view.request_focus();
    int idx = tab_index(app, &tab);
    if (idx >= 0 && idx != app.active) app.select_request = idx;
}

void InlineEdit::begin(int r, uint64_t c, std::string text) {
    row = r;
    ctx = c;
    buf = std::move(text);
    error.clear();
    focus = true;
    start_frame = ImGui::GetFrameCount();
}

// =============================================================================================
// Tabs
// =============================================================================================

namespace {

void refresh_tab_cache(Tab& t) {
    if (t.doc->busy()) return;  // save_as may be changing the path on the worker thread
    t.label = t.doc->display_name();
    t.path = t.doc->path();
}

Tab& add_tab(App& app, std::unique_ptr<Document> doc) {
    auto t = std::make_unique<Tab>();
    t->doc = std::move(doc);
    t->insert_mode = app.settings.insert_mode;
    refresh_tab_cache(*t);
    app.tabs.push_back(std::move(t));
    app.active = int(app.tabs.size()) - 1;
    app.select_request = app.active;
    return *app.tabs.back();
}

std::string path_key(const std::string& p) {
    std::string k = p;
#ifdef _WIN32
    for (char& c : k) {
        if (c == '\\') c = '/';
        if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    }
#endif
    return k;
}

void new_document(App& app) {
    std::string name = "Untitled " + std::to_string(++app.untitled_counter);
    add_tab(app, Document::create_empty(name));
}

void close_tab_now(App& app, int index) {
    if (index < 0 || index >= int(app.tabs.size())) return;
    std::unique_ptr<Tab> t = std::move(app.tabs[size_t(index)]);
    app.tabs.erase(app.tabs.begin() + index);
    t->ev = HexViewEvents{};
    app.closed.push_back(std::move(t));  // keeps the Document: edits + history come back on reopen
    if (app.closed.size() > kMaxClosedTabs) app.closed.erase(app.closed.begin());
    app.insp_edit.end();
    app.st_edit.end();
    app.bm_edit.end();
    if (app.tabs.empty()) {
        app.active = -1;
        app.select_request = -1;
        return;
    }
    if (index < app.active) app.active--;
    app.active = std::clamp(app.active, 0, int(app.tabs.size()) - 1);
    app.select_request = app.active;
}

void request_close_tab(App& app, int index) {
    if (index < 0 || index >= int(app.tabs.size())) return;
    Tab& t = *app.tabs[size_t(index)];
    if (t.doc->busy()) {
        set_status(app, "Cannot close a document while it is being saved");
        return;
    }
    if (t.doc->dirty()) {
        app.close_prompt_doc = t.doc->id();
        app.close_prompt_pending = true;
        return;
    }
    close_tab_now(app, index);
}

// Index of the open tab showing `path` (same spelling, or the same file on disk), else -1.
int tab_for_path(App& app, const std::string& path) {
    if (path.empty()) return -1;
    const std::string key = path_key(path);
    for (size_t i = 0; i < app.tabs.size(); ++i) {
        const Tab& t = *app.tabs[i];
        if (t.path.empty()) continue;
        if (path_key(t.path) == key || os_same_file(t.path, path)) return int(i);
    }
    return -1;
}

void reopen_closed_tab(App& app) {
    if (app.closed.empty()) {
        set_status(app, "No closed tabs to reopen");
        return;
    }
    // Two Documents on one file would overwrite each other's bytes on save.
    if (int open = tab_for_path(app, app.closed.back()->path); open >= 0) {
        app.select_request = open;
        app.active = open;
        const std::string label = app.closed.back()->label;
        if (!app.closed.back()->doc->dirty()) {
            app.closed.pop_back();  // nothing unsaved in it: the open tab replaces it
            set_status(app, label + " is already open");
        } else {
            set_status(app, label + " is already open. Close that tab first to reopen the closed one with its edits.", 8.0);
        }
        return;
    }
    app.tabs.push_back(std::move(app.closed.back()));
    app.closed.pop_back();
    app.active = int(app.tabs.size()) - 1;
    app.select_request = app.active;
    set_status(app, "Reopened " + app.tabs.back()->label);
}

void switch_tab(App& app, int delta) {
    int n = int(app.tabs.size());
    if (n < 2) return;
    int cur = app.select_request >= 0 ? app.select_request : app.active;
    app.select_request = ((cur + delta) % n + n) % n;
    app.active = app.select_request;
}

bool any_dirty(App& app) {
    for (auto& t : app.tabs)
        if (t->doc->busy() || t->doc->dirty()) return true;
    return false;
}

bool any_busy(App& app) {
    for (auto& t : app.tabs)
        if (t->doc->busy()) return true;
    return false;
}

}  // namespace

bool open_path(App& app, const std::string& path) {
    if (path.empty()) return false;
    // Tab paths are absolute, so compare absolute paths (and file identity for links, 8.3 names).
    const std::string abs = os_absolute_path(path);
    if (int i = tab_for_path(app, abs); i >= 0) {
        app.select_request = i;
        app.active = i;
        return true;
    }
    std::string err;
    std::unique_ptr<Document> doc = Document::open_file(abs, &err);
    if (!doc) {
        std::string msg = "Cannot open " + path + (err.empty() ? "" : ": " + err);
        log_console(app, ConsoleLine::Error, msg);
        notify(app, msg, true);
        return false;
    }
    add_tab(app, std::move(doc));
    app.settings.push_recent(abs);
    mark_settings_dirty(app);
    return true;
}

// =============================================================================================
// Native file dialogs
// =============================================================================================

namespace {

std::string native_path(std::string p) {
#ifdef _WIN32
    for (char& c : p)
        if (c == '/') c = '\\';
#endif
    return p;
}

std::string dialog_dir(App& app) {
    if (Tab* t = active_tab(app); t && !t->path.empty()) return native_path(path_dirname(t->path));
    if (!app.settings.recent_files.empty()) return native_path(path_dirname(app.settings.recent_files.front()));
    return {};
}

void report_dialog_error(App& app) {
    const char* e = NFD_GetError();
    std::string msg = std::string("File dialog failed: ") + (e ? e : "unknown error");
    log_console(app, ConsoleLine::Error, msg);
    notify(app, msg, true);
    NFD_ClearError();
}

std::vector<std::string> open_dialog(App& app) {
    std::vector<std::string> out;
    const std::string dir = dialog_dir(app);
    const nfdpathset_t* set = nullptr;
    nfdresult_t r = NFD_OpenDialogMultipleU8(&set, nullptr, 0, dir.empty() ? nullptr : dir.c_str());
    if (r == NFD_OKAY && set) {
        nfdpathsetsize_t n = 0;
        if (NFD_PathSet_GetCount(set, &n) == NFD_OKAY) {
            for (nfdpathsetsize_t i = 0; i < n; ++i) {
                nfdu8char_t* p = nullptr;
                if (NFD_PathSet_GetPathU8(set, i, &p) == NFD_OKAY && p) {
                    out.emplace_back(p);
                    NFD_PathSet_FreePathU8(p);
                }
            }
        }
        NFD_PathSet_Free(set);
    } else if (r == NFD_ERROR) {
        report_dialog_error(app);
    }
    return out;
}

bool save_dialog(App& app, const Document& doc, std::string& out) {
    std::string dir = doc.has_path() ? native_path(path_dirname(doc.path())) : dialog_dir(app);
    std::string name = doc.has_path() ? path_filename(doc.path()) : doc.display_name();
    nfdu8char_t* p = nullptr;
    nfdresult_t r = NFD_SaveDialogU8(&p, nullptr, 0, dir.empty() ? nullptr : dir.c_str(), name.c_str());
    if (r == NFD_OKAY && p) {
        out = p;
        NFD_FreePathU8(p);
        return true;
    }
    if (r == NFD_ERROR) report_dialog_error(app);
    return false;
}

void open_with_dialog(App& app) {
    for (const std::string& p : open_dialog(app)) open_path(app, p);
}

}  // namespace

// =============================================================================================
// Saving (worker thread) and quitting
// =============================================================================================

namespace {

bool save_session(App& app, bool force, std::string* err_out = nullptr);  // per-frame section

// The on-disk version is one the user chose to ignore (banner "Ignore").
bool ignored_version(const Tab& t) {
    if (!t.ignore_valid) return false;
    const FileStat st = os_stat(t.path);
    return st.exists == t.ignored_stat.exists && st.size == t.ignored_stat.size &&
           st.mtime_ns == t.ignored_stat.mtime_ns;
}

// The file was changed by someone else since we opened / last saved it.
bool disk_conflict(const Tab& t) {
    return t.doc->has_path() && (t.disk_changed || t.doc->changed_on_disk()) && !ignored_version(t);
}

// Starts saving `tab` on a worker thread. Shows a Save As dialog for untitled docs / save_as.
// A save over a file that changed on disk first asks Overwrite / Save As / Reload / Cancel,
// unless `confirmed` (the user already chose Overwrite).
bool start_save(App& app, Tab& tab, bool save_as, AfterSave after, bool confirmed = false) {
    SaveTask& s = app.save;
    if (s.running) {
        set_status(app, "Another save is still in progress");
        return false;
    }
    Document& d = *tab.doc;
    if (d.busy()) return false;
    std::string target;
    if (save_as || !d.has_path()) {
        if (!save_dialog(app, d, target)) return false;
    } else if (!d.dirty() && after == AfterSave::None) {
        set_status(app, "No changes to save");
        return false;
    } else if (!confirmed && disk_conflict(tab)) {
        app.overwrite_prompt_doc = d.id();
        app.overwrite_prompt_after = after;
        app.overwrite_prompt_pending = true;
        return false;
    }
    s.progress.done = 0;
    s.progress.total = 0;
    s.progress.cancel = false;
    s.progress.committing = false;
    s.finished = false;
    s.ok = false;
    s.err.clear();
    s.doc_id = d.id();
    s.target = target;
    s.after = after;
    s.started = now_s();
    s.running = true;
    app.insp_edit.end();
    app.st_edit.end();
    app.bm_edit.end();
    SaveTask* task = &s;
    Document* doc = &d;
    // Overwrite confirmed: save over a file another program modified (Document::save refuses).
    const bool force = confirmed;
    s.thread = std::thread([task, doc, target, force] {
        std::string err;
        bool ok = target.empty() ? doc->save(&task->progress, &err, force)
                                 : doc->save_as(target, &task->progress, &err);
        task->ok = ok;
        task->err = std::move(err);
        task->finished.store(true);
    });
    return true;
}

void abort_quit(App& app) {
    app.quitting_with_saves = false;
    app.quit_queue.clear();
    app.quit_requested = false;
    app.quit_skip_unsafe = false;
}

// Asks Save / Discard / Cancel before quitting, for `docs` (empty = every dirty document).
void prompt_quit(App& app, std::vector<uint64_t> docs) {
    app.quit_prompt_docs = std::move(docs);
    app.quit_requested = false;  // the prompt decides
    app.quit_prompt_pending = true;
}

void poll_save(App& app) {
    SaveTask& s = app.save;
    if (!s.running || !s.finished.load()) return;
    s.thread.join();
    s.running = false;
    Tab* t = find_tab(app, s.doc_id);
    const double secs = now_s() - s.started;
    if (!t) return;
    refresh_tab_cache(*t);
    if (s.ok) {
        char buf[64];
        std::snprintf(buf, sizeof buf, " in %.1f s", secs);
        const SaveInfo info = t->doc->last_save_info();
        if (info.backup_created) {
            // First save over this file: the original is kept next to it.
            set_status(app, "Saved " + t->label + buf + " (backup: " + path_filename(info.backup_path) + ")", 10.0);
            log_console(app, ConsoleLine::Info, t->label + ": the original file was kept as " + info.backup_path);
        } else {
            set_status(app, "Saved " + t->label + buf);
        }
        if (info.backup_skipped && !info.note.empty()) {
            log_console(app, ConsoleLine::Warn, t->label + ": " + info.note);
            notify(app, info.note + "\nThe limit is in Edit > Settings > Saving.", false);
        }
        if (!s.err.empty()) {  // saved, but e.g. undo history before the save had to be dropped
            log_console(app, ConsoleLine::Warn, t->label + ": " + s.err);
            notify(app, t->label + ": " + s.err, false);
        }
        if (!s.target.empty()) {
            app.settings.push_recent(s.target);
            mark_settings_dirty(app);
        }
        t->disk_changed = false;
        t->ignore_valid = false;
        t->doc->view_generation++;
        if (s.after == AfterSave::CloseTab) close_tab_now(app, tab_index(app, t));
        // Write the session right away: until then it holds the pre-save pieces (a restore would
        // notice the stale state; this closes that window).
        save_session(app, true);
        return;
    }
    // Cancel can be pressed while an in-place write is already past the point of no return; only
    // a save that really stopped because of it is reported as cancelled, any other error is shown.
    if (s.progress.cancel.load() && s.err.find("cancelled") != std::string::npos) {
        set_status(app, "Save cancelled");
    } else if (s.target.empty() && t->doc->changed_on_disk() &&
               (s.err.find("modified on disk by another program since") != std::string::npos ||
                s.err.find("File size changed on disk") != std::string::npos)) {
        // Refused because another program modified the file (after "Ignore" on the banner, or it
        // changed just before the save): offer Overwrite anyway / Save As / Reload / Cancel.
        // Only for that refusal: a failed in-place write also changes the file's mtime, and its
        // error ("may be partially written") must be shown, not a prompt blaming another program.
        t->disk_changed = true;
        t->ignore_valid = false;
        app.overwrite_prompt_doc = t->doc->id();
        app.overwrite_prompt_after = s.after;
        app.overwrite_prompt_pending = true;
    } else {
        show_message(app, "Save failed", "Could not save " + t->label + ":\n" + s.err);
    }
    if (app.quitting_with_saves || s.after == AfterSave::Quit) abort_quit(app);
}

// Called every frame. Quits once nothing is running and every dirty doc is handled.
void process_quit(App& app) {
    if (!app.quit_requested || app.save.running) return;
    if (app.quitting_with_saves) {
        while (!app.quit_queue.empty()) {
            uint64_t id = app.quit_queue.front();
            app.quit_queue.erase(app.quit_queue.begin());
            Tab* t = find_tab(app, id);
            if (!t || !t->doc->dirty()) continue;
            if (!start_save(app, *t, false, AfterSave::Quit)) abort_quit(app);
            return;
        }
        // Everything chosen is saved. Continue below: other dirty docs may still hot-exit.
        app.quitting_with_saves = false;
        app.quit_skip_unsafe = true;
    }
    if (app.hot_exit) {
        // Documents whose unsaved state the session cannot hold (Document::hot_exit_safe) are not
        // hot-exited silently: ask for just those; the others hot-exit as usual.
        if (!app.quit_skip_unsafe) {
            std::vector<uint64_t> unsafe;
            for (auto& t : app.tabs)
                if (t->doc->dirty() && !t->doc->hot_exit_safe()) unsafe.push_back(t->doc->id());
            if (!unsafe.empty()) {
                prompt_quit(app, std::move(unsafe));
                return;
            }
        }
        // Quitting without a prompt is only safe once the session (the unsaved edits) is on disk.
        std::string err;
        if (save_session(app, true, &err) || !any_dirty(app)) {
            app.quit = true;
            return;
        }
        app.quit_skip_unsafe = false;
        show_message(app, "Session not saved",
                     "Hot exit could not write the session, so unsaved edits would be lost on quit:\n" + err +
                         "\n\nSave or discard them in the next dialog.");
        prompt_quit(app, {});
        return;
    }
    if (!any_dirty(app)) {
        app.quit = true;
        return;
    }
    prompt_quit(app, {});
}

}  // namespace

// =============================================================================================
// Editing commands
// =============================================================================================

namespace {

void after_edit(Tab& t) {
    t.doc->view_generation++;
    t.view.request_scroll_to(t.doc->view().cursor, false);
}

void do_undo(App& app, bool redo) {
    Tab* t = active_tab(app);
    Document* d = usable_doc(app);
    if (!d) return;
    const auto& stack = redo ? d->redo_stack() : d->undo_stack();
    std::string label = stack.empty() ? std::string() : stack.back().label;
    bool ok = redo ? d->redo() : d->undo();
    if (!ok) {
        set_status(app, redo ? "Nothing to redo" : "Nothing to undo");
        return;
    }
    d->view().low_nibble = false;  // the restored caret sits on a whole byte, not a half-typed one
    after_edit(*t);
    set_status(app, std::string(redo ? "Redo" : "Undo") + (label.empty() ? "" : ": " + label));
}

// Most bytes that may be copied as `fmt`: the clipboard text (not the raw bytes) is capped at
// kMaxClipboardBytes, and e.g. a C array needs ~6.25 characters per byte.
uint64_t copy_limit(CopyFormat fmt) {
    uint64_t chars_per_byte = 1;
    switch (fmt) {
        case CopyFormat::HexSpaced: chars_per_byte = 3; break;
        case CopyFormat::HexCompact: chars_per_byte = 2; break;
        case CopyFormat::CArray: chars_per_byte = 7; break;
        case CopyFormat::PythonBytes: chars_per_byte = 4; break;
        case CopyFormat::Base64: chars_per_byte = 2; break;
        case CopyFormat::EscapedString: chars_per_byte = 4; break;
        default: break;
    }
    return kMaxClipboardBytes / chars_per_byte;
}

CopyFormat default_copy_format(const Document& d) {
    return d.view().ascii_focus ? CopyFormat::Text : CopyFormat::HexSpaced;
}

// Returns true if the clipboard now holds the bytes.
bool copy_selection(App& app, CopyFormat fmt) {
    Document* d = usable_doc(app);
    if (!d) return false;
    const ViewState& v = d->view();
    uint64_t off = v.sel_begin(), len = v.sel_len();
    if (len == 0) {  // no selection: copy the byte under the caret
        if (v.cursor >= d->size()) {
            set_status(app, "Nothing to copy");
            return false;
        }
        off = v.cursor;
        len = 1;
    }
    if (len > copy_limit(fmt)) {
        show_message(app, "Copy", "The selection is " + fmt_size(len) + ". Copying more than " +
                                      fmt_size(copy_limit(fmt)) + " as " + copy_format_name(fmt) +
                                      " is not supported (the clipboard text is limited to 64 MiB).");
        return false;
    }
    std::vector<uint8_t> buf(static_cast<size_t>(len));
    size_t n = d->read(off, buf.data(), buf.size());
    std::string text = copy_as(buf.data(), n, fmt);
    ImGui::SetClipboardText(text.c_str());
    set_status(app, "Copied " + std::to_string(n) + (n == 1 ? " byte" : " bytes") + " as " +
                        copy_format_name(fmt));
    return true;
}

bool copy_default(App& app) {
    Document* d = usable_doc(app);
    if (!d) return false;
    return copy_selection(app, default_copy_format(*d));
}

void cut_selection(App& app) {
    Tab* t = active_tab(app);
    Document* d = usable_doc(app);
    if (!d) return;
    ViewState& v = d->view();
    if (!v.has_selection()) {
        set_status(app, "Select bytes to cut");
        return;
    }
    if (d->read_only()) {
        report_edit_failure(app, *d);
        return;
    }
    if (v.sel_len() > copy_limit(default_copy_format(*d))) {
        show_message(app, "Cut", "Cutting more than " + fmt_size(copy_limit(default_copy_format(*d))) +
                                     " to the clipboard is not supported.");
        return;
    }
    if (!copy_default(app)) return;  // never erase bytes that did not reach the clipboard
    uint64_t b = v.sel_begin(), len = v.sel_len();
    if (!d->erase(b, len)) {
        report_edit_failure(app, *d);
        return;
    }
    v.cursor = v.anchor = b;
    after_edit(*t);
    set_status(app, "Cut " + std::to_string(len) + " bytes");
}

void paste(App& app) {
    Tab* t = active_tab(app);
    Document* d = usable_doc(app);
    if (!d) return;
    const char* clip = ImGui::GetClipboardText();
    if (!clip || !*clip) {
        set_status(app, "Clipboard is empty");
        return;
    }
    std::string text = clip;
    ViewState& v = d->view();
    std::vector<uint8_t> bytes;
    bool parsed_hex = !v.ascii_focus && parse_bytes(text, bytes);
    if (!parsed_hex) bytes.assign(text.begin(), text.end());
    if (bytes.empty()) return;
    bool ok;
    const uint64_t at = v.has_selection() ? v.sel_begin() : v.cursor;
    const uint64_t sel_len = v.sel_len();
    // Insert mode replaces the selection; overwrite mode (size-preserving patching) overwrites
    // from the selection start, like typing does.
    if (v.has_selection() && t->insert_mode)
        ok = d->replace(at, sel_len, bytes.data(), bytes.size());
    else if (t->insert_mode)
        ok = d->insert(at, bytes.data(), bytes.size());
    else
        ok = d->overwrite(at, bytes.data(), bytes.size());
    if (!ok) {
        report_edit_failure(app, *d);
        return;
    }
    v.cursor = v.anchor = std::min<uint64_t>(at + bytes.size(), d->size());
    v.low_nibble = false;
    after_edit(*t);
    std::string msg = "Pasted " + std::to_string(bytes.size()) + " bytes" + (parsed_hex ? " (hex)" : " (text)");
    if (sel_len && !t->insert_mode && sel_len != bytes.size())
        msg += ", overwriting from the selection start (selection was " + std::to_string(sel_len) + " bytes)";
    set_status(app, msg, 6.0);
}

void select_all(App& app) {
    Tab* t = active_tab(app);
    Document* d = usable_doc(app);
    if (!d) return;
    d->view().anchor = 0;
    d->view().cursor = d->size();
    d->view_generation++;
    t->view.request_scroll_to(d->size(), false);
}

void toggle_insert_mode(App& app) {
    Tab* t = active_tab(app);
    if (!t) return;
    t->insert_mode = !t->insert_mode;
    app.settings.insert_mode = t->insert_mode;  // new tabs follow the last choice
    mark_settings_dirty(app);
    set_status(app, t->insert_mode ? "Insert mode" : "Overwrite mode");
}

void toggle_read_only(App& app) {
    Document* d = usable_doc(app);
    if (!d) return;
    d->set_read_only(!d->read_only());
    d->view_generation++;
    set_status(app, d->read_only() ? "Read-only" : "Writable");
}

void toggle_bookmark(App& app) {
    Document* d = usable_doc(app);
    if (!d) return;
    const ViewState& v = d->view();
    const uint64_t off = v.has_selection() ? v.sel_begin() : v.cursor;
    const uint64_t len = v.has_selection() ? v.sel_len() : 1;
    const auto& bms = v.bookmarks;
    for (size_t i = 0; i < bms.size(); ++i) {
        if (bms[i].offset == off) {
            std::string name = bms[i].name;
            if (d->remove_bookmark(i))
                set_status(app, "Removed bookmark " + name);
            else
                report_edit_failure(app, *d);
            return;
        }
    }
    if (d->size() == 0) {
        set_status(app, "Nothing to bookmark in an empty document");
        return;
    }
    Bookmark b;
    b.offset = std::min(off, d->size() - 1);
    b.length = std::max<uint64_t>(1, len);
    b.name = "Bookmark " + std::to_string(bms.size() + 1);
    if (d->add_bookmark(b))
        set_status(app, "Added " + b.name + " at " + fmt_range(b.offset, b.length));
    else
        report_edit_failure(app, *d);
}

void jump_bookmark(App& app, bool forward) {
    Tab* t = active_tab(app);
    Document* d = usable_doc(app);
    if (!d) return;
    const auto& bms = d->view().bookmarks;
    if (bms.empty()) {
        set_status(app, "No bookmarks (Ctrl+B adds one)");
        return;
    }
    const uint64_t cur = d->view().cursor;
    const Bookmark* best = nullptr;
    const Bookmark* wrap = nullptr;
    for (const Bookmark& b : bms) {
        if (forward) {
            if (b.offset > cur && (!best || b.offset < best->offset)) best = &b;
            if (!wrap || b.offset < wrap->offset) wrap = &b;
        } else {
            if (b.offset < cur && (!best || b.offset > best->offset)) best = &b;
            if (!wrap || b.offset > wrap->offset) wrap = &b;
        }
    }
    const Bookmark* target = best ? best : wrap;
    reveal_range(app, *t, target->offset, target->length, true);
    set_status(app, target->name + (best ? "" : " (wrapped)"));
}

void zoom(App& app, float delta) {
    float s = (delta == 0.0f) ? kDefaultFont : app.settings.font_size + delta;
    s = std::clamp(std::round(s), kMinFont, kMaxFont);
    if (s == app.settings.font_size) return;
    app.settings.font_size = s;
    mark_settings_dirty(app);
    set_status(app, "Font size " + std::to_string(int(s)) + " px", 1.5);
}

void reload_from_disk(App& app, Tab& t) {
    if (t.doc->busy()) return;
    std::string err;
    if (!t.doc->reload(&err)) {
        show_message(app, "Reload failed", "Could not reload " + t.label + ":\n" + err);
        return;
    }
    t.disk_changed = false;
    t.ignore_valid = false;
    t.hits = SearchHits{};
    t.doc->view_generation++;
    refresh_tab_cache(t);
    set_status(app, "Reloaded " + t.label + " from disk");
}

// File > Reload from Disk: reloading drops edits and the whole undo history and cannot be undone,
// so ask first when there is anything to lose. (The banner's "Reload (discard edits)" is explicit.)
void request_reload(App& app, Tab& t) {
    if (t.doc->busy()) return;
    if (t.doc->dirty() || t.doc->can_undo() || t.doc->can_redo()) {
        app.reload_prompt_doc = t.doc->id();
        app.reload_prompt_pending = true;
        return;
    }
    reload_from_disk(app, t);
}

void force_reparse(App& app) {
    Tab* t = active_tab(app);
    if (!t) return;
    t->st.gen = UINT64_MAX;
    t->st.pending_gen = UINT64_MAX - 1;
    set_status(app, "Re-parsing structure", 1.5);
}

// ---- search --------------------------------------------------------------------------------

void open_find_bar(App& app) {
    app.find.open = true;
    app.find.focus = true;
}

void find_start(App& app, SearchJob::Mode mode) {
    FindState& f = app.find;
    Document* d = usable_doc(app);
    if (!d) return;
    if (f.input.empty()) {
        open_find_bar(app);
        return;
    }
    Pattern pat;
    std::string err;
    if (!compile_pattern(SearchKind(f.kind), f.input, f.icase, pat, &err) || pat.size() == 0) {
        f.error = err.empty() ? "Invalid search pattern" : err;
        f.open = true;
        return;
    }
    f.error.clear();
    const ViewState& v = d->view();
    uint64_t from = 0;
    if (mode == SearchJob::Mode::Next)
        from = std::min(v.has_selection() ? v.sel_begin() + 1 : v.cursor, d->size());
    else if (mode == SearchJob::Mode::Prev)
        from = v.has_selection() ? v.sel_begin() : v.cursor;
    f.job_len = pat.size();
    f.job_doc = d->id();
    f.job_doc_gen = d->generation();
    f.job_query = f.input;
    f.job.start(d->snapshot(), std::move(pat), from, mode);
}

void poll_search(App& app) {
    FindState& f = app.find;
    const uint64_t g = f.job.generation();
    if (g == f.seen_gen) return;
    Tab* t = find_tab(app, f.job_doc);
    if (t && t->doc->busy()) return;  // apply the result once the save is done
    f.seen_gen = g;
    if (!t) return;
    SearchJob::Result r = f.job.result();
    if (r.cancelled) {
        set_status(app, "Search cancelled");
        return;
    }
    if (r.io_error) {  // the scan stopped there: no hits past it, not even in Find All
        const std::string msg = "Search stopped: unreadable data at " + fmt_offset(r.io_error_offset) + " in " + t->label;
        log_console(app, ConsoleLine::Warn, msg);
        notify(app, msg, true);
    }
    if (r.mode == SearchJob::Mode::All) {
        SearchHits& h = t->hits;
        h.offsets = std::move(r.hits);
        h.len = r.pattern_len ? r.pattern_len : f.job_len;
        h.truncated = r.truncated;
        h.doc_gen = f.job_doc_gen;  // edits made while the search ran mark the hits as stale
        h.query = f.job_query;
        h.layer.clear();
        const uint32_t color = hex_colors().search_hit;
        for (uint64_t off : h.offsets) h.layer.add({off, uint64_t(h.len), color, "Search hit", -1});
        h.layer.finalize();
        app.show_results = true;
        app.focus_results = true;
        set_status(app, std::to_string(h.offsets.size()) + (h.truncated ? "+" : "") + " hits for '" + h.query + "'");
        return;
    }
    if (r.hits.empty()) {
        set_status(app, "Not found: " + f.job_query);
        return;
    }
    reveal_range(app, *t, r.hits[0], r.pattern_len ? r.pattern_len : f.job_len, false);
    if (r.wrapped) set_status(app, "Search wrapped around");
}

}  // namespace

// =============================================================================================
// Action table: menus, shortcuts and the command palette all use it
// =============================================================================================

namespace {

struct Action {
    const char* name;
    ImGuiKeyChord keys[4];  // unused slots are 0
    void (*run)(App&);
    bool (*enabled)(App&);  // nullptr = always enabled
    bool in_text;           // also fires while a text field has keyboard focus
    bool repeat;
};

bool has_tab(App& a) { return active_tab(a) != nullptr; }
bool has_doc(App& a) { return usable_doc(a) != nullptr; }
bool has_selection(App& a) {
    Document* d = usable_doc(a);
    return d && d->view().has_selection();
}
bool can_undo(App& a) {
    Document* d = usable_doc(a);
    return d && d->can_undo();
}
bool can_redo(App& a) {
    Document* d = usable_doc(a);
    return d && d->can_redo();
}
bool has_file(App& a) {
    Document* d = usable_doc(a);
    return d && d->has_path();
}
bool idle(App& a) { return !a.save.running; }

constexpr ImGuiKeyChord C(ImGuiKeyChord k) { return ImGuiMod_Ctrl | k; }
constexpr ImGuiKeyChord CS(ImGuiKeyChord k) { return ImGuiMod_Ctrl | ImGuiMod_Shift | k; }
constexpr ImGuiKeyChord S(ImGuiKeyChord k) { return ImGuiMod_Shift | k; }

const Action kActions[] = {
    // File
    {"New", {C(ImGuiKey_N), 0}, [](App& a) { new_document(a); }, nullptr, true, false},
    {"Open...", {C(ImGuiKey_O), 0}, [](App& a) { open_with_dialog(a); }, nullptr, true, false},
    {"Save", {C(ImGuiKey_S), 0},
     [](App& a) { if (Tab* t = active_tab(a)) start_save(a, *t, false, AfterSave::None); }, has_doc, true, false},
    {"Save As...", {CS(ImGuiKey_S), 0},
     [](App& a) { if (Tab* t = active_tab(a)) start_save(a, *t, true, AfterSave::None); }, has_doc, true, false},
    {"Close Tab", {C(ImGuiKey_W), 0}, [](App& a) { request_close_tab(a, a.active); }, has_tab, true, false},
    {"Reopen Closed Tab", {CS(ImGuiKey_T), 0}, [](App& a) { reopen_closed_tab(a); },
     [](App& a) { return !a.closed.empty(); }, true, false},
    {"Reload from Disk", {0, 0}, [](App& a) { if (Tab* t = active_tab(a)) request_reload(a, *t); }, has_file, true, false},
    {"Exit", {0, 0}, [](App& a) { a.quit_requested = true; }, nullptr, true, false},
    // Edit
    {"Undo", {C(ImGuiKey_Z), 0}, [](App& a) { do_undo(a, false); }, can_undo, false, true},
    {"Redo", {C(ImGuiKey_Y), CS(ImGuiKey_Z)}, [](App& a) { do_undo(a, true); }, can_redo, false, true},
    {"Cut", {C(ImGuiKey_X), 0}, [](App& a) { cut_selection(a); }, has_selection, false, false},
    {"Copy", {C(ImGuiKey_C), 0}, [](App& a) { copy_default(a); }, has_doc, false, false},
    {"Copy As...", {CS(ImGuiKey_C), 0}, [](App& a) { a.req_copy_as = true; }, has_doc, false, false},
    {"Paste", {C(ImGuiKey_V), 0}, [](App& a) { paste(a); }, has_doc, false, false},
    {"Select All", {C(ImGuiKey_A), 0}, [](App& a) { select_all(a); }, has_doc, false, false},
    {"Fill Selection...", {0, 0}, [](App& a) { a.req_fill = true; }, has_selection, false, false},
    {"Toggle Insert / Overwrite", {ImGuiKey_Insert, 0}, [](App& a) { toggle_insert_mode(a); }, has_tab, false, false},
    {"Toggle Read-only", {0, 0}, [](App& a) { toggle_read_only(a); }, has_doc, false, false},
    {"Settings...", {C(ImGuiKey_Comma), 0}, [](App& a) { a.show_settings = !a.show_settings; }, nullptr, true, false},
    // Search & navigation
    {"Find...", {C(ImGuiKey_F), 0}, [](App& a) { open_find_bar(a); }, has_tab, true, false},
    {"Find Next", {ImGuiKey_F3, 0}, [](App& a) { find_start(a, SearchJob::Mode::Next); }, has_doc, true, true},
    {"Find Previous", {S(ImGuiKey_F3), 0}, [](App& a) { find_start(a, SearchJob::Mode::Prev); }, has_doc, true, true},
    {"Find All", {0, 0}, [](App& a) { find_start(a, SearchJob::Mode::All); }, has_doc, true, false},
    {"Go to Offset...", {C(ImGuiKey_G), 0}, [](App& a) { a.req_goto = true; }, has_doc, true, false},
    {"Toggle Bookmark", {C(ImGuiKey_B), 0}, [](App& a) { toggle_bookmark(a); }, has_doc, false, false},
    {"Next Bookmark", {ImGuiKey_F2, 0}, [](App& a) { jump_bookmark(a, true); }, has_doc, false, true},
    {"Previous Bookmark", {S(ImGuiKey_F2), 0}, [](App& a) { jump_bookmark(a, false); }, has_doc, false, true},
    {"Jump to Bookmark...", {CS(ImGuiKey_B), 0}, [](App& a) { a.req_bookmark_jump = true; }, nullptr, true, false},
    {"Show All Bookmarks", {0, 0}, [](App& a) {
         a.show_bookmarks = a.bm_all_files = a.focus_bookmarks = true;
     }, nullptr, true, false},
    {"Next Tab", {C(ImGuiKey_Tab), 0}, [](App& a) { switch_tab(a, +1); }, nullptr, true, true},
    {"Previous Tab", {CS(ImGuiKey_Tab), 0}, [](App& a) { switch_tab(a, -1); }, nullptr, true, true},
    // View
    // "+" is Shift+= on US layouts and keeps the US "]" key code on e.g. German ones (GLFW backend).
    {"Zoom In", {C(ImGuiKey_Equal), C(ImGuiKey_KeypadAdd), CS(ImGuiKey_Equal), C(ImGuiKey_RightBracket)}, [](App& a) { zoom(a, +1.0f); }, nullptr, true, true},
    {"Zoom Out", {C(ImGuiKey_Minus), C(ImGuiKey_KeypadSubtract)}, [](App& a) { zoom(a, -1.0f); }, nullptr, true, true},
    {"Reset Zoom", {C(ImGuiKey_0), C(ImGuiKey_Keypad0)}, [](App& a) { zoom(a, 0.0f); }, nullptr, true, false},
    {"Command Palette", {CS(ImGuiKey_P), 0}, [](App& a) { a.req_palette = true; }, nullptr, true, false},
    {"Toggle Inspector", {0, 0}, [](App& a) { a.show_inspector = !a.show_inspector; }, nullptr, true, false},
    {"Toggle Structure", {0, 0}, [](App& a) { a.show_structure = !a.show_structure; }, nullptr, true, false},
    {"Toggle Console", {0, 0}, [](App& a) { a.show_console = !a.show_console; }, nullptr, true, false},
    {"Toggle Search Results", {0, 0}, [](App& a) { a.show_results = !a.show_results; }, nullptr, true, false},
    {"Toggle Bookmarks", {0, 0}, [](App& a) { a.show_bookmarks = !a.show_bookmarks; }, nullptr, true, false},
    {"Reset Layout", {0, 0}, [](App& a) {
         a.build_layout = true;
         a.show_inspector = a.show_structure = a.show_console = a.show_results = a.show_bookmarks = true;
     }, nullptr, true, false},
    // Scripts
    {"Reparse Structure", {ImGuiKey_F5, 0}, [](App& a) { force_reparse(a); }, has_doc, true, false},
    {"Reload Scripts", {0, 0}, [](App& a) { a.engine->reload(); set_status(a, "Scripts reloaded"); }, idle, true, false},
    {"Open Scripts Folder", {0, 0}, [](App&) { os_reveal_in_file_manager(paths::user_scripts_dir()); }, nullptr, true, false},
    {"Clear Console", {0, 0}, [](App& a) { a.engine->clear_console(); }, nullptr, true, false},
    // Help
    {"About Hexer", {0, 0}, [](App& a) { a.req_about = true; }, nullptr, true, false},
};
constexpr int kActionCount = int(sizeof(kActions) / sizeof(kActions[0]));

const Action* find_action(const char* name) {
    for (const Action& a : kActions)
        if (std::string_view(a.name) == name) return &a;
    return nullptr;
}

std::string shortcut_text(const Action& a) {
    return a.keys[0] ? std::string(ImGui::GetKeyChordName(a.keys[0])) : std::string();
}

bool action_enabled(App& app, const Action& a) { return !a.enabled || a.enabled(app); }

// MenuItem bound to an action. `label` overrides the displayed text (e.g. "Undo Typing").
void menu_action(App& app, const char* name, const char* label = nullptr, bool checked = false) {
    const Action* a = find_action(name);
    if (!a) return;
    std::string sc = shortcut_text(*a);
    if (ImGui::MenuItem(label ? label : a->name, sc.empty() ? nullptr : sc.c_str(), checked,
                        action_enabled(app, *a)))
        a->run(app);
}

bool any_popup_open() {
    return ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel);
}

void handle_shortcuts(App& app) {
    if (any_popup_open()) return;
    const bool typing = ImGui::GetIO().WantTextInput;
    for (const Action& act : kActions) {
        for (ImGuiKeyChord k : act.keys) {
            if (!k) continue;
            ImGuiInputFlags fl = ImGuiInputFlags_RouteGlobal | (act.repeat ? ImGuiInputFlags_Repeat : 0);
            if (!ImGui::Shortcut(k, fl)) continue;
            if (typing && !act.in_text) continue;
            if (!action_enabled(app, act)) continue;
            act.run(app);
        }
    }
    // Esc closes the find bar when the hex view (not a text field) has focus.
    if (app.find.open && !typing && ImGui::Shortcut(ImGuiKey_Escape, ImGuiInputFlags_RouteGlobal)) {
        app.find.open = false;
        if (Tab* t = active_tab(app)) t->view.request_focus();
    }
}

}  // namespace

// =============================================================================================
// Main menu
// =============================================================================================

namespace {

void draw_recent_menu(App& app) {
    if (!ImGui::BeginMenu("Open Recent", !app.settings.recent_files.empty())) return;
    std::string open_me;
    for (const std::string& p : app.settings.recent_files)
        if (ImGui::MenuItem(p.c_str())) open_me = p;
    ImGui::Separator();
    if (ImGui::MenuItem("Clear Recent Files")) {
        app.settings.recent_files.clear();
        mark_settings_dirty(app);
    }
    ImGui::EndMenu();
    if (!open_me.empty()) open_path(app, open_me);
}

// `numbered`: show 1..N as shortcuts and accept those keys (the keyboard-opened Copy As popup).
void draw_copy_as_items(App& app, bool numbered = false) {
    for (int i = 0; i < int(CopyFormat::Count); ++i) {
        const std::string key = std::to_string(i + 1);
        const bool pressed = numbered && i < 9 && ImGui::IsKeyPressed(ImGuiKey(ImGuiKey_1 + i), false);
        if (ImGui::MenuItem(copy_format_name(CopyFormat(i)), numbered && i < 9 ? key.c_str() : nullptr, false,
                            has_doc(app)) ||
            (pressed && has_doc(app))) {
            copy_selection(app, CopyFormat(i));
            if (pressed) ImGui::CloseCurrentPopup();
        }
    }
}

// Popups close on Esc only with keyboard navigation enabled, which the hex view does not use.
void close_popup_on_escape() {
    if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) ImGui::CloseCurrentPopup();
}

void draw_edit_menu(App& app) {
    Document* d = usable_doc(app);
    std::string undo = "Undo", redo = "Redo";
    if (d && d->can_undo() && !d->undo_stack().back().label.empty()) undo += " " + d->undo_stack().back().label;
    if (d && d->can_redo() && !d->redo_stack().back().label.empty()) redo += " " + d->redo_stack().back().label;
    menu_action(app, "Undo", undo.c_str());
    menu_action(app, "Redo", redo.c_str());
    ImGui::Separator();
    menu_action(app, "Cut");
    menu_action(app, "Copy");
    if (ImGui::BeginMenu("Copy As", d != nullptr)) {
        draw_copy_as_items(app);
        ImGui::EndMenu();
    }
    menu_action(app, "Paste");
    ImGui::Separator();
    menu_action(app, "Select All");
    menu_action(app, "Fill Selection...");
    ImGui::Separator();
    Tab* t = active_tab(app);
    menu_action(app, "Toggle Insert / Overwrite", "Insert Mode", t && t->insert_mode);
    menu_action(app, "Toggle Read-only", "Read-only", d && d->read_only());
    ImGui::Separator();
    menu_action(app, "Settings...", nullptr, app.show_settings);
}

// The active document's bookmarks (first 30) plus the bookmark actions.
void draw_bookmarks_menu(App& app) {
    menu_action(app, "Toggle Bookmark", "Add / Remove Bookmark");
    menu_action(app, "Next Bookmark");
    menu_action(app, "Previous Bookmark");
    menu_action(app, "Jump to Bookmark...");
    menu_action(app, "Show All Bookmarks", "Show All Bookmarks...");
    Tab* t = active_tab(app);
    Document* d = usable_doc(app);
    if (!d) return;
    const auto& bms = d->view().bookmarks;
    ImGui::Separator();
    if (bms.empty()) {
        ImGui::TextDisabled("No bookmarks in %s", t->label.c_str());
        return;
    }
    constexpr size_t kMenuMax = 30;
    int jump = -1;
    for (size_t i = 0; i < bms.size() && i < kMenuMax; ++i) {
        const Bookmark& b = bms[i];
        ImGui::PushID(int(i));
        const std::string off = fmt_offset(b.offset);
        if (ImGui::MenuItem(b.name.empty() ? "(unnamed)" : b.name.c_str(), off.c_str())) jump = int(i);
        if (!b.note.empty()) ImGui::SetItemTooltip("%s", b.note.c_str());
        ImGui::PopID();
    }
    if (bms.size() > kMenuMax) {
        const std::string more = std::to_string(bms.size() - kMenuMax) + " more...";
        if (ImGui::MenuItem(more.c_str())) app.show_bookmarks = app.focus_bookmarks = true;
    }
    if (jump >= 0) reveal_range(app, *t, bms[size_t(jump)].offset, bms[size_t(jump)].length, true);
}

void draw_view_menu(App& app) {
    ImGui::MenuItem(kWinInspector, nullptr, &app.show_inspector);
    ImGui::MenuItem(kWinStructure, nullptr, &app.show_structure);
    ImGui::MenuItem(kWinConsole, nullptr, &app.show_console);
    ImGui::MenuItem(kWinResults, nullptr, &app.show_results);
    ImGui::MenuItem(kWinBookmarks, nullptr, &app.show_bookmarks);
    ImGui::Separator();
    menu_action(app, "Command Palette");
    ImGui::Separator();
    menu_action(app, "Zoom In");
    menu_action(app, "Zoom Out");
    menu_action(app, "Reset Zoom");
    ImGui::Separator();
    Settings& s = app.settings;
    if (ImGui::BeginMenu("Bytes per Row")) {
        for (int n : {0, 8, 16, 24, 32, 48, 64}) {
            std::string label = n == 0 ? std::string("Auto-fit") : std::to_string(n);
            if (ImGui::MenuItem(label.c_str(), nullptr, s.bytes_per_row == n)) {
                s.bytes_per_row = n;
                mark_settings_dirty(app);
            }
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Group Size")) {
        for (int n : {0, 2, 4, 8, 16}) {
            std::string label = n == 0 ? std::string("No grouping") : std::to_string(n);
            if (ImGui::MenuItem(label.c_str(), nullptr, s.group_size == n)) {
                s.group_size = n;
                mark_settings_dirty(app);
            }
        }
        ImGui::EndMenu();
    }
    bool changed = false;
    changed |= ImGui::MenuItem("Uppercase Hex", nullptr, &s.uppercase_hex);
    changed |= ImGui::MenuItem("Show Text Column", nullptr, &s.show_ascii);
    changed |= ImGui::MenuItem("Highlight Modified Bytes", nullptr, &s.highlight_modified);
    ImGui::Separator();
    if (ImGui::MenuItem("Hot Exit (restore session)", nullptr, &s.restore_session, app.session != nullptr)) {
        changed = true;
        app.hot_exit = app.session && s.restore_session;
    }
    if (changed) mark_settings_dirty(app);
    ImGui::Separator();
    menu_action(app, "Reset Layout");
}

void draw_scripts_menu(App& app) {
    menu_action(app, "Reparse Structure");
    menu_action(app, "Reload Scripts");
    menu_action(app, "Open Scripts Folder");
    const auto& cmds = app.engine->commands();
    if (!cmds.empty()) ImGui::Separator();
    // Run after the loop, with a copy of the name: a command may register commands, which
    // reallocates the engine's list this loop (and a reference into it) points into.
    std::string run;
    const bool can_run = idle(app) && !app.engine->pending_prompt();  // one command waits for input at a time
    for (const ScriptCommand& c : cmds) {
        if (ImGui::MenuItem(c.name.c_str(), nullptr, false, can_run)) run = c.name;
        if (!c.description.empty() && ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal))
            ImGui::SetTooltip("%s", c.description.c_str());
    }
    if (!run.empty()) app.engine->run_command(run);
}

void draw_main_menu(App& app) {
    if (!ImGui::BeginMainMenuBar()) return;
    if (ImGui::BeginMenu("File")) {
        menu_action(app, "New");
        menu_action(app, "Open...");
        draw_recent_menu(app);
        ImGui::Separator();
        menu_action(app, "Save");
        menu_action(app, "Save As...");
        menu_action(app, "Reload from Disk");
        ImGui::Separator();
        menu_action(app, "Close Tab");
        menu_action(app, "Reopen Closed Tab");
        ImGui::Separator();
        menu_action(app, "Exit");
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Edit")) {
        draw_edit_menu(app);
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Search")) {
        menu_action(app, "Find...");
        menu_action(app, "Find Next");
        menu_action(app, "Find Previous");
        menu_action(app, "Find All");
        ImGui::Separator();
        menu_action(app, "Go to Offset...");
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Bookmarks")) {
        draw_bookmarks_menu(app);
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("View")) {
        draw_view_menu(app);
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Scripts")) {
        draw_scripts_menu(app);
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Help")) {
        menu_action(app, "Command Palette");
        menu_action(app, "About Hexer");
        ImGui::EndMenu();
    }
    ImGui::EndMainMenuBar();
}

}  // namespace

// =============================================================================================
// Editor window: tabs, banners, find bar, hex view
// =============================================================================================

namespace {

ImVec4 col4(uint32_t c) { return ImGui::ColorConvertU32ToFloat4(c); }
const ImVec4 kWarnColor(1.0f, 0.78f, 0.35f, 1.0f);
const ImVec4 kErrorColor(1.0f, 0.42f, 0.42f, 1.0f);

void draw_empty_state(App& app) {
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const char* line = "Open a file (Ctrl+O)  \xC2\xB7  New (Ctrl+N)  \xC2\xB7  drop files here";
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + avail.y * 0.28f);
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 1.5f);
    float w = ImGui::CalcTextSize(line).x;
    ImGui::SetCursorPosX(std::max(0.0f, (avail.x - w) * 0.5f));
    ImGui::TextDisabled("%s", line);
    ImGui::PopFont();
    ImGui::Spacing();

    const float bw = ImGui::CalcTextSize("Open...").x + ImGui::CalcTextSize("New").x +
                     ImGui::GetStyle().FramePadding.x * 4 + ImGui::GetStyle().ItemSpacing.x;
    ImGui::SetCursorPosX(std::max(0.0f, (avail.x - bw) * 0.5f));
    if (ImGui::Button("Open...")) open_with_dialog(app);
    ImGui::SameLine();
    if (ImGui::Button("New")) new_document(app);

    const auto& recent = app.settings.recent_files;
    if (recent.empty()) return;
    ImGui::Spacing();
    ImGui::Spacing();
    const float lw = std::min(avail.x - 32.0f, 640.0f * app.ui_scale);
    const float x = std::max(0.0f, (avail.x - lw) * 0.5f);
    ImGui::SetCursorPosX(x);
    ImGui::TextDisabled("Recent files");
    std::string open_me;
    for (size_t i = 0; i < recent.size() && i < 10; ++i) {
        // File name first (what people scan for), then the folder dimmed; a long folder is cut
        // from the left so its most specific part stays visible. Full path in the tooltip.
        const std::string& path = recent[i];
        const std::string name = path_filename(path);
        std::string dir = path_dirname(path);
        ImGui::SetCursorPosX(x);
        ImGui::PushID(int(i));
        if (ImGui::Selectable("##recent", false, ImGuiSelectableFlags_AllowOverlap, ImVec2(lw, 0))) open_me = path;
        ImGui::SetItemTooltip("%s", path.c_str());
        ImGui::SameLine(x);
        ImGui::TextUnformatted(name.c_str());
        ImGui::SameLine();
        const float room = x + lw - ImGui::GetCursorPosX();
        const char* ell = "\xE2\x80\xA6";  // ellipsis
        if (ImGui::CalcTextSize(dir.c_str()).x > room) {
            size_t cut = 0;
            const float ell_w = ImGui::CalcTextSize(ell).x;
            while (cut < dir.size() && ImGui::CalcTextSize(dir.c_str() + cut).x + ell_w > room) ++cut;
            while (cut < dir.size() && (uint8_t(dir[cut]) & 0xC0) == 0x80) ++cut;  // UTF-8 boundary
            dir = std::string(ell) + dir.substr(cut);
        }
        ImGui::TextDisabled("%s", dir.c_str());
        ImGui::PopID();
    }
    if (!open_me.empty()) open_path(app, open_me);
}

void draw_disk_banner(App& app, Tab& t) {
    if (!t.disk_changed) return;
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(kWarnColor, "File changed on disk.");
    ImGui::SameLine();
    if (ImGui::SmallButton(t.doc->dirty() ? "Reload (discard edits)" : "Reload")) {
        reload_from_disk(app, t);
        return;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Ignore")) {
        t.disk_changed = false;
        t.ignore_valid = true;
        t.ignored_stat = os_stat(t.path);
    }
    ImGui::Separator();
}

void draw_read_only_badge(App& app, Tab& t) {
    if (!t.doc->read_only()) return;
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(kWarnColor, "READ-ONLY");
    ImGui::SameLine();
    if (ImGui::SmallButton("Make writable")) toggle_read_only(app);
}

void close_find_bar(App& app, Tab& t) {
    app.find.open = false;
    t.view.request_focus();
}

void draw_find_bar(App& app, Tab& t) {
    FindState& f = app.find;
    const float s = app.ui_scale;
    ImGui::PushID("findbar");
    static const char* kinds[] = {"Hex", "Text", "UTF-16"};
    ImGui::SetNextItemWidth(90.0f * s);
    if (ImGui::Combo("##kind", &f.kind, kinds, 3)) f.error.clear();
    ImGui::SameLine();
    ImGui::BeginDisabled(f.kind == int(SearchKind::Hex));
    ImGui::Checkbox("Ignore case", &f.icase);
    ImGui::EndDisabled();
    ImGui::SameLine();

    const bool running = f.job.running() && f.job_doc == t.doc->id();
    const float buttons = 220.0f * s + (running ? 200.0f * s : 0.0f);
    ImGui::SetNextItemWidth(std::max(140.0f * s, ImGui::GetContentRegionAvail().x - buttons));
    if (f.focus) {
        ImGui::SetKeyboardFocusHere();
        f.focus = false;
    }
    const char* hint = f.kind == int(SearchKind::Hex) ? "DE AD ?? EF" : "text to find";
    const std::string before = f.input;
    const bool enter = ImGui::InputTextWithHint("##find", hint, &f.input, ImGuiInputTextFlags_EnterReturnsTrue);
    if (ImGui::IsItemDeactivated() && ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
        f.input = before;  // ImGui reverts on Esc; keep what was typed
        close_find_bar(app, t);
        ImGui::PopID();
        return;
    }
    if (ImGui::IsItemEdited()) f.error.clear();
    if (enter) {
        find_start(app, ImGui::GetIO().KeyShift ? SearchJob::Mode::Prev : SearchJob::Mode::Next);
        ImGui::SetKeyboardFocusHere(-1);  // keep typing / pressing Enter
    }
    ImGui::SameLine();
    if (ImGui::Button("Prev")) find_start(app, SearchJob::Mode::Prev);
    ImGui::SameLine();
    if (ImGui::Button("Next")) find_start(app, SearchJob::Mode::Next);
    ImGui::SameLine();
    if (ImGui::Button("All")) find_start(app, SearchJob::Mode::All);
    if (running) {
        ImGui::SameLine();
        ImGui::ProgressBar(float(f.job.progress()), ImVec2(120.0f * s, 0.0f));
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) f.job.cancel();
    }
    ImGui::SameLine();
    if (ImGui::Button("x")) close_find_bar(app, t);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Close (Esc)");
    if (!f.error.empty()) ImGui::TextColored(kErrorColor, "%s", f.error.c_str());
    ImGui::PopID();
}

uint64_t bookmarks_signature(const std::vector<Bookmark>& bms) {
    uint64_t h = 1469598103934665603ull;
    auto mix = [&](uint64_t v) {
        h ^= v;
        h *= 1099511628211ull;
    };
    mix(bms.size());
    for (const Bookmark& b : bms) {
        mix(b.offset);
        mix(b.length);
        mix(b.color);
        for (char c : b.name) mix(uint8_t(c));
    }
    return h;
}

void update_bookmark_layer(Tab& t) {
    const auto& bms = t.doc->view().bookmarks;
    uint64_t sig = bookmarks_signature(bms);
    if (sig == t.bookmark_sig) return;
    t.bookmark_sig = sig;
    t.bookmark_layer.clear();
    for (const Bookmark& b : bms)
        t.bookmark_layer.add({b.offset, b.length, b.color ? b.color : hex_colors().bookmark, b.name, -1});
    t.bookmark_layer.finalize();
}

HexViewConfig make_view_config(App& app, const Tab& t) {
    HexViewConfig cfg;
    cfg.bytes_per_row = app.settings.bytes_per_row;
    cfg.group_size = app.settings.group_size;
    cfg.uppercase = app.settings.uppercase_hex;
    cfg.show_ascii = app.settings.show_ascii;
    cfg.insert_mode = t.insert_mode;
    cfg.highlight_modified = app.settings.highlight_modified;
    cfg.mono = app.fonts.mono;
    // Whole pixels: a fractional size (e.g. 16 px at 125 %) would rasterise blurrier glyphs.
    cfg.font_size = std::round(app.settings.font_size * app.ui_scale);
    if (!t.hits.offsets.empty()) cfg.tick_offsets = &t.hits.offsets;
    return cfg;
}

void draw_hex_context_menu(App& app) {
    if (!ImGui::BeginPopup("##hexctx")) return;
    menu_action(app, "Cut");
    menu_action(app, "Copy");
    if (ImGui::BeginMenu("Copy As", has_doc(app))) {
        draw_copy_as_items(app);
        ImGui::EndMenu();
    }
    menu_action(app, "Paste");
    ImGui::Separator();
    menu_action(app, "Select All");
    menu_action(app, "Fill Selection...");
    ImGui::Separator();
    menu_action(app, "Toggle Bookmark");
    menu_action(app, "Go to Offset...");
    menu_action(app, "Find...");
    close_popup_on_escape();
    ImGui::EndPopup();
}

void draw_hex_view(App& app, Tab& t) {
    Document& d = *t.doc;
    // Ctrl+wheel over the editor zooms the mono font (the hex view leaves Ctrl+wheel to us).
    ImGuiIO& io = ImGui::GetIO();
    if (io.KeyCtrl && io.MouseWheel != 0.0f && ImGui::IsWindowHovered(ImGuiHoveredFlags_ChildWindows))
        zoom(app, io.MouseWheel > 0.0f ? 1.0f : -1.0f);

    std::vector<const HighlightSet*> layers;
    if (t.st.has_result && !t.st.result.highlights.empty()) layers.push_back(&t.st.result.highlights);
    if (const HighlightSet* s = app.engine->script_highlights(d.id()); s && !s->empty()) layers.push_back(s);
    update_bookmark_layer(t);
    if (!t.bookmark_layer.empty()) layers.push_back(&t.bookmark_layer);
    if (!t.hits.layer.empty()) layers.push_back(&t.hits.layer);

    t.ev = HexViewEvents{};
    t.view.draw("##hex", d, layers, make_view_config(app, t), t.ev);
    if (t.ev.cursor_moved || d.view().top_row != t.last_top_row) {
        t.last_top_row = d.view().top_row;
        d.view_generation++;
    }
    if (t.ev.open_context_menu) ImGui::OpenPopup("##hexctx");
    draw_hex_context_menu(app);
}

void draw_tab_content(App& app, Tab& t) {
    if (t.doc->busy()) {
        // The worker thread owns the document while saving: do not read it from here.
        ImGui::Spacing();
        ImGui::TextDisabled("Saving %s...", t.label.c_str());
        ImGui::ProgressBar(float(app.save.progress.fraction()), ImVec2(320.0f * app.ui_scale, 0.0f));
        return;
    }
    draw_disk_banner(app, t);
    draw_read_only_badge(app, t);
    if (app.find.open) draw_find_bar(app, t);
    draw_hex_view(app, t);
}

// Keeps app.tabs in the visual order of the (reorderable) tab bar, so Ctrl+Tab, the session and
// the window title agree with what the user sees. Call inside BeginTabBar/EndTabBar.
void sync_tab_order(App& app) {
    ImGuiTabBar* bar = ImGui::GetCurrentTabBar();
    if (!bar || app.tabs.size() < 2) return;
    auto pos = [&](const Tab& t) {
        for (int k = 0; k < bar->Tabs.Size; ++k)
            if (bar->Tabs[k].ID == t.tab_id) return k;
        return INT_MAX;
    };
    bool sorted = true;
    for (size_t i = 1; i < app.tabs.size() && sorted; ++i)
        if (pos(*app.tabs[i]) < pos(*app.tabs[i - 1])) sorted = false;
    if (sorted) return;
    Tab* active = active_tab(app);
    Tab* requested = app.select_request >= 0 && app.select_request < int(app.tabs.size())
                         ? app.tabs[size_t(app.select_request)].get()
                         : nullptr;
    std::stable_sort(app.tabs.begin(), app.tabs.end(),
                     [&](const std::unique_ptr<Tab>& a, const std::unique_ptr<Tab>& b) { return pos(*a) < pos(*b); });
    app.active = active ? tab_index(app, active) : app.active;
    if (requested) app.select_request = tab_index(app, requested);
}

void draw_editor(App& app) {
    ImGuiWindowClass wc;
    // The editor has its own document tab bar: no dock tab bar (and no corner triangle) above it,
    // and panels may split its node but not become tabs next to it.
    wc.DockNodeFlagsOverrideSet = ImGuiDockNodeFlags_NoTabBar | ImGuiDockNodeFlags_NoDockingOverMe;
    ImGui::SetNextWindowClass(&wc);
    if (app.layout_focus_step == 1) ImGui::SetNextWindowFocus();  // ...then keyboard focus to the editor
    const bool visible = ImGui::Begin(kWinEditor, nullptr,
                                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
                                          ImGuiWindowFlags_NoCollapse);
    if (!visible) {
        ImGui::End();
        return;
    }
    if (app.tabs.empty()) {
        draw_empty_state(app);
        ImGui::End();
        return;
    }
    uint64_t close_id = 0;
    int shown = -1;
    const ImGuiTabBarFlags bar_flags = ImGuiTabBarFlags_Reorderable | ImGuiTabBarFlags_AutoSelectNewTabs |
                                       ImGuiTabBarFlags_TabListPopupButton | ImGuiTabBarFlags_FittingPolicyScroll |
                                       ImGuiTabBarFlags_DrawSelectedOverline;
    if (ImGui::BeginTabBar("##docs", bar_flags)) {
        for (size_t i = 0; i < app.tabs.size(); ++i) {
            Tab& t = *app.tabs[i];
            refresh_tab_cache(t);
            ImGuiTabItemFlags flags = 0;
            if (t.doc->busy() || t.doc->dirty()) flags |= ImGuiTabItemFlags_UnsavedDocument;
            if (int(i) == app.select_request) flags |= ImGuiTabItemFlags_SetSelected;
            std::string label = t.label + "###doc" + std::to_string(t.doc->id());
            bool open = true;
            const bool selected = ImGui::BeginTabItem(label.c_str(), &open, flags);
            t.tab_id = ImGui::GetItemID();
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal))
                ImGui::SetTooltip("%s", t.path.empty() ? "Untitled (not saved yet)" : t.path.c_str());
            if (selected) {
                shown = int(i);
                draw_tab_content(app, t);
                ImGui::EndTabItem();
            }
            if (!open) close_id = t.doc->id();
        }
        if (app.select_request >= 0) {
            app.active = app.select_request;  // takes visual effect next frame
            app.select_request = -1;
        } else if (shown >= 0) {
            app.active = shown;
        }
        sync_tab_order(app);
        ImGui::EndTabBar();
    }
    ImGui::End();
    if (close_id) request_close_tab(app, tab_index(app, find_tab(app, close_id)));
}

}  // namespace

// =============================================================================================
// Popups (all opened and drawn at the root ID stack)
// =============================================================================================

namespace {

bool center_next_window(App& app, float width, float y_frac = 0.25f) {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + vp->WorkSize.x * 0.5f, vp->WorkPos.y + vp->WorkSize.y * y_frac),
                            ImGuiCond_Appearing, ImVec2(0.5f, 0.0f));
    if (width > 0.0f) ImGui::SetNextWindowSize(ImVec2(width * app.ui_scale, 0.0f), ImGuiCond_Appearing);
    return true;
}

// ---- command palette ---------------------------------------------------------------------

// Ctrl+Shift+B: every bookmark of every open (not saving) document, the active one first.
void build_bookmark_palette(App& app) {
    std::vector<Tab*> order;
    if (Tab* t = active_tab(app)) order.push_back(t);
    for (auto& t : app.tabs)
        if (t.get() != active_tab(app)) order.push_back(t.get());
    for (Tab* t : order) {
        if (t->doc->busy()) continue;
        const auto& bms = t->doc->view().bookmarks;
        for (size_t i = 0; i < bms.size(); ++i) {
            const Bookmark& b = bms[i];
            PaletteItem it;
            it.label = (b.name.empty() ? std::string("(unnamed)") : b.name);
            if (!b.note.empty()) it.label += "  \xC2\xB7  " + b.note;
            it.label += "  \xC2\xB7  " + t->label;
            it.hint = fmt_offset(b.offset);
            it.kind = 4;
            it.index = int(i);
            it.doc = t->doc->id();
            app.palette_all.push_back(std::move(it));
        }
    }
}

void build_palette(App& app) {
    app.palette_all.clear();
    if (app.palette_bookmarks) {
        build_bookmark_palette(app);
        app.palette_last_query = "\x01";
        return;
    }
    for (int i = 0; i < kActionCount; ++i) {
        const Action& a = kActions[i];
        PaletteItem it;
        it.label = a.name;
        it.hint = shortcut_text(a);
        it.kind = 0;
        it.index = i;
        it.enabled = action_enabled(app, a);
        app.palette_all.push_back(std::move(it));
    }
    const bool can_run = idle(app) && !app.engine->pending_prompt();
    for (const ScriptCommand& c : app.engine->commands())
        app.palette_all.push_back({"Script: " + c.name, c.description, 1, 0, c.name, can_run, 0, 0});
    const bool doc = has_doc(app);
    app.palette_all.push_back({"Parser: Auto-detect", "", 2, 0, "", doc, 0, 0});
    for (const ParserInfo& p : app.engine->parsers())
        app.palette_all.push_back({"Parser: " + p.name, "", 2, 0, p.name, doc, 0, 0});
    for (const std::string& r : app.settings.recent_files)
        app.palette_all.push_back({"Open recent: " + r, "", 3, 0, r, true, 0, 0});
    app.palette_last_query = "\x01";  // force re-filter
}

void filter_palette(App& app) {
    if (app.palette_query == app.palette_last_query) return;
    app.palette_last_query = app.palette_query;
    app.palette_view.clear();
    for (const PaletteItem& it : app.palette_all) {
        int sc = app.palette_query.empty() ? 0 : fuzzy_score(app.palette_query, it.label);
        if (sc < 0) continue;
        PaletteItem copy = it;
        copy.score = sc;
        app.palette_view.push_back(std::move(copy));
    }
    std::stable_sort(app.palette_view.begin(), app.palette_view.end(),
                     [](const PaletteItem& a, const PaletteItem& b) { return a.score > b.score; });
    app.palette_sel = 0;
    app.palette_scroll = true;
}

void run_palette_item(App& app, const PaletteItem& it) {
    if (!it.enabled) return;
    switch (it.kind) {
        case 0: kActions[it.index].run(app); break;
        case 1: app.engine->run_command(it.arg); break;
        case 2:
            if (Document* d = usable_doc(app)) {
                d->view().parser = it.arg;
                d->view_generation++;
                app.show_structure = true;
            }
            break;
        case 3: open_path(app, it.arg); break;
        case 4:
            if (Tab* t = find_tab(app, it.doc); t && !t->doc->busy()) {
                const auto& bms = t->doc->view().bookmarks;
                if (size_t(it.index) < bms.size()) {
                    const Bookmark b = bms[size_t(it.index)];
                    reveal_range(app, *t, b.offset, b.length, true);
                    set_status(app, (b.name.empty() ? std::string("Bookmark") : b.name) + ": " +
                                        fmt_range(b.offset, b.length));
                }
            }
            break;
        default: break;
    }
}

void draw_palette(App& app) {
    center_next_window(app, 560.0f, 0.12f);
    if (!ImGui::BeginPopup(kPopPalette)) return;
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(-FLT_MIN);
    const char* hint = app.palette_bookmarks ? "Jump to a bookmark in any open file (name, note or file)..."
                                             : "Type a command, script, parser or recent file...";
    const bool enter = ImGui::InputTextWithHint("##q", hint, &app.palette_query, ImGuiInputTextFlags_EnterReturnsTrue);
    filter_palette(app);
    const int n = int(app.palette_view.size());
    if (n > 0) {
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) { app.palette_sel = (app.palette_sel + 1) % n; app.palette_scroll = true; }
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) { app.palette_sel = (app.palette_sel + n - 1) % n; app.palette_scroll = true; }
        if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) { app.palette_sel = std::min(n - 1, app.palette_sel + 10); app.palette_scroll = true; }
        if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) { app.palette_sel = std::max(0, app.palette_sel - 10); app.palette_scroll = true; }
    }
    int run = -1;
    if (enter && n > 0) run = app.palette_sel;
    // Enter deactivates the input; when it ran nothing (no match / disabled entry) keep typing.
    if (enter && (run < 0 || run >= n || !app.palette_view[size_t(run)].enabled)) ImGui::SetKeyboardFocusHere(-1);
    const float list_h = ImGui::GetTextLineHeightWithSpacing() * 14.0f;
    if (ImGui::BeginChild("##list", ImVec2(0.0f, list_h), ImGuiChildFlags_None)) {
        ImGuiListClipper clip;
        clip.Begin(n);
        if (app.palette_scroll && app.palette_sel < n) clip.IncludeItemByIndex(app.palette_sel);
        while (clip.Step()) {
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                const PaletteItem& it = app.palette_view[size_t(i)];
                ImGui::PushID(i);
                ImGui::BeginDisabled(!it.enabled);
                if (ImGui::Selectable(it.label.c_str(), i == app.palette_sel)) run = i;
                ImGui::EndDisabled();
                if (!it.hint.empty()) {
                    float hw = ImGui::CalcTextSize(it.hint.c_str()).x;
                    ImGui::SameLine(std::max(ImGui::GetContentRegionMax().x - hw, 0.0f));
                    ImGui::TextDisabled("%s", it.hint.c_str());
                }
                if (app.palette_scroll && i == app.palette_sel) {
                    ImGui::SetScrollHereY(0.5f);
                    app.palette_scroll = false;
                }
                ImGui::PopID();
            }
        }
        if (n == 0)
            ImGui::TextDisabled("%s", app.palette_bookmarks && app.palette_all.empty()
                                          ? "No bookmarks in the open files (Ctrl+B adds one at the cursor/selection)"
                                          : "No matches");
    }
    ImGui::EndChild();
    if (ImGui::IsKeyPressed(ImGuiKey_Escape)) ImGui::CloseCurrentPopup();
    PaletteItem chosen;
    bool do_run = false;
    if (run >= 0 && run < n && app.palette_view[size_t(run)].enabled) {
        chosen = app.palette_view[size_t(run)];
        do_run = true;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
    if (do_run) run_palette_item(app, chosen);
}

// ---- goto / fill / copy-as ---------------------------------------------------------------

void draw_goto(App& app) {
    center_next_window(app, 460.0f, 0.18f);
    if (!ImGui::BeginPopup(kPopGoto)) return;
    Tab* t = active_tab(app);
    Document* d = usable_doc(app);
    if (!d) {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    ImGui::TextUnformatted("Go to offset");
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(-FLT_MIN);
    const bool enter = ImGui::InputTextWithHint("##expr", "0x1F00   +0x10   end-0x100   50%   cur+4*0x10",
                                                &app.goto_input, ImGuiInputTextFlags_EnterReturnsTrue);
    uint64_t target = 0;
    std::string err;
    const ViewState& v = d->view();
    const bool ok = !app.goto_input.empty() &&
                    parse_offset(app.goto_input, v.cursor, d->size(), app.settings.goto_default_hex, target, &err);
    if (enter && !ok) ImGui::SetKeyboardFocusHere(-1);  // Enter deactivated the input: keep editing
    const bool shift = ImGui::GetIO().KeyShift;
    if (ImGui::Checkbox("Bare numbers are hex", &app.settings.goto_default_hex)) mark_settings_dirty(app);
    if (app.goto_input.empty())
        ImGui::TextDisabled("Size: %s (%s)", fmt_offset(d->size()).c_str(), fmt_size(d->size()).c_str());
    else if (ok)
        ImGui::Text("-> %s  (%llu)", fmt_offset(target).c_str(), static_cast<unsigned long long>(target));
    else
        ImGui::TextColored(kErrorColor, "%s", err.empty() ? "invalid expression" : err.c_str());
    ImGui::TextDisabled("Enter: go    Shift+Enter: select from cursor    Esc: close");
    if (enter && ok) {
        ViewState& vs = d->view();
        if (shift) {
            if (!vs.has_selection()) vs.anchor = vs.cursor;
            vs.cursor = target;
        } else {
            vs.cursor = vs.anchor = target;
        }
        vs.low_nibble = false;
        d->view_generation++;
        t->view.request_scroll_to(target, true);
        t->view.request_focus();
        ImGui::CloseCurrentPopup();
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Escape)) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void draw_fill(App& app) {
    center_next_window(app, 420.0f);
    if (!ImGui::BeginPopupModal(kPopFill, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    Tab* t = active_tab(app);
    Document* d = usable_doc(app);
    if (!d || !d->view().has_selection()) {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    const ViewState& v = d->view();
    ImGui::Text("Fill %s", fmt_range(v.sel_begin(), v.sel_len()).c_str());
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(360.0f * app.ui_scale);
    const bool enter = ImGui::InputTextWithHint("##pattern", "hex pattern, e.g. 00 or DE AD BE EF", &app.fill_input,
                                                ImGuiInputTextFlags_EnterReturnsTrue);
    std::vector<uint8_t> pat;
    std::string err;
    const bool ok = parse_bytes(app.fill_input, pat, &err) && !pat.empty();
    if (ok)
        ImGui::TextDisabled("%zu-byte pattern", pat.size());
    else
        ImGui::TextColored(kErrorColor, "%s", err.empty() ? "enter hex bytes" : err.c_str());
    ImGui::BeginDisabled(!ok);
    bool go = ImGui::Button("Fill") || (enter && ok);
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) ImGui::CloseCurrentPopup();
    if (go && ok) {
        if (d->fill(v.sel_begin(), v.sel_len(), pat.data(), pat.size())) {
            after_edit(*t);
            set_status(app, "Filled " + fmt_size(d->view().sel_len()));
        } else {
            report_edit_failure(app, *d);
        }
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void draw_copy_as_popup(App& app) {
    if (!ImGui::BeginPopup(kPopCopyAs)) return;
    ImGui::TextDisabled("Copy selection as");
    ImGui::Separator();
    draw_copy_as_items(app, true);
    if (ImGui::IsKeyPressed(ImGuiKey_Escape)) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

// ---- prompts / messages ------------------------------------------------------------------

void draw_close_prompt(App& app) {
    center_next_window(app, 0.0f, 0.3f);
    if (!ImGui::BeginPopupModal(kPopClose, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    Tab* t = find_tab(app, app.close_prompt_doc);
    if (!t) {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    ImGui::Text("Save changes to \"%s\" before closing?", t->label.c_str());
    ImGui::TextDisabled("Discarded tabs can still be reopened with Ctrl+Shift+T until Hexer exits.");
    ImGui::Spacing();
    if (ImGui::Button("Save") || ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
        ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false)) {
        ImGui::CloseCurrentPopup();
        start_save(app, *t, false, AfterSave::CloseTab);
    }
    ImGui::SetItemTooltip("Enter");
    ImGui::SameLine();
    if (ImGui::Button("Discard")) {
        ImGui::CloseCurrentPopup();
        close_tab_now(app, tab_index(app, t));
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void draw_reload_prompt(App& app) {
    center_next_window(app, 0.0f, 0.3f);
    if (!ImGui::BeginPopupModal(kPopReload, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    Tab* t = find_tab(app, app.reload_prompt_doc);
    if (!t || t->doc->busy()) {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    ImGui::Text("Reload \"%s\" from disk?", t->label.c_str());
    ImGui::TextDisabled(t->doc->dirty() ? "Unsaved changes and the undo history will be discarded. This cannot be undone."
                                        : "The undo history will be discarded. This cannot be undone.");
    ImGui::Spacing();
    if (ImGui::Button("Reload and discard")) {
        ImGui::CloseCurrentPopup();
        reload_from_disk(app, *t);
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

// Save over a file that another program changed since it was opened / last saved.
void draw_overwrite_prompt(App& app) {
    center_next_window(app, 0.0f, 0.3f);
    if (!ImGui::BeginPopupModal(kPopOverwrite, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    Tab* t = find_tab(app, app.overwrite_prompt_doc);
    if (!t || t->doc->busy()) {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    // A save started from the quit flow does not resume quitting; the user quits again.
    const AfterSave after = app.overwrite_prompt_after == AfterSave::Quit ? AfterSave::None : app.overwrite_prompt_after;
    ImGui::Text("\"%s\" was changed by another program.", t->label.c_str());
    ImGui::PushTextWrapPos(520.0f * app.ui_scale);
    ImGui::TextDisabled("Overwrite replaces the version on disk. Bytes you did not edit come partly from the file as "
                        "it was and partly as it is now, so the result can mix both versions. Save As keeps both.");
    ImGui::PopTextWrapPos();
    ImGui::Spacing();
    if (ImGui::Button("Save As...")) {
        ImGui::CloseCurrentPopup();
        start_save(app, *t, true, after);
    }
    ImGui::SameLine();
    if (ImGui::Button("Overwrite anyway")) {
        ImGui::CloseCurrentPopup();
        start_save(app, *t, false, after, true);
    }
    ImGui::SameLine();
    if (ImGui::Button(t->doc->dirty() ? "Reload (discard edits)" : "Reload")) {
        ImGui::CloseCurrentPopup();
        reload_from_disk(app, *t);
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void draw_quit_prompt(App& app) {
    center_next_window(app, 0.0f, 0.3f);
    if (!ImGui::BeginPopupModal(kPopQuit, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    // Scoped (hot exit keeps every other document): only the listed docs need a decision.
    const bool scoped = !app.quit_prompt_docs.empty();
    std::vector<Tab*> docs;
    for (auto& t : app.tabs) {
        const bool listed = std::find(app.quit_prompt_docs.begin(), app.quit_prompt_docs.end(), t->doc->id()) !=
                            app.quit_prompt_docs.end();
        if (t->doc->dirty() && (!scoped || listed)) docs.push_back(t.get());
    }
    if (scoped) {
        ImGui::TextUnformatted("Hot exit cannot keep the unsaved changes of:");
        for (Tab* t : docs) ImGui::BulletText("%s", t->label.c_str());
        ImGui::PushTextWrapPos(520.0f * app.ui_scale);
        ImGui::TextDisabled("They refer to a large part of a file version that a save replaced. Your other "
                            "documents are restored on the next start as usual.");
        ImGui::PopTextWrapPos();
    } else {
        ImGui::TextUnformatted("These documents have unsaved changes:");
        for (Tab* t : docs) ImGui::BulletText("%s", t->label.c_str());
    }
    ImGui::Spacing();
    if (ImGui::Button("Save All")) {
        app.quit_queue.clear();
        for (Tab* t : docs) app.quit_queue.push_back(t->doc->id());
        app.quitting_with_saves = true;
        app.quit_requested = true;
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Discard All")) {
        if (scoped) {  // the rest still goes through hot exit (and its session-save check)
            app.quit_skip_unsafe = true;
            app.quit_requested = true;
        } else {
            app.quit = true;
        }
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        abort_quit(app);
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void draw_saving(App& app) {
    center_next_window(app, 0.0f, 0.35f);
    if (!ImGui::BeginPopupModal(kPopSaving, nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove))
        return;
    if (!app.save.running) {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    Tab* t = find_tab(app, app.save.doc_id);
    const Progress& p = app.save.progress;
    ImGui::Text("Saving %s", t ? t->label.c_str() : "document");
    ImGui::ProgressBar(float(p.fraction()), ImVec2(360.0f * app.ui_scale, 0.0f));
    ImGui::TextDisabled("%s of %s", fmt_size(p.done.load()).c_str(), fmt_size(p.total.load()).c_str());
    // Past the point of no return (in-place writes / final rename) Cancel cannot stop the save.
    const bool committing = p.committing.load();
    ImGui::BeginDisabled(committing || p.cancel.load());
    if (ImGui::Button(committing ? "Finishing..." : p.cancel.load() ? "Cancelling..." : "Cancel"))
        app.save.progress.cancel = true;
    ImGui::EndDisabled();
    ImGui::EndPopup();
}

void draw_message(App& app) {
    if (app.messages.empty()) return;
    center_next_window(app, 0.0f, 0.3f);
    std::string id = app.messages.front().title + kPopMessage;
    if (!ImGui::BeginPopupModal(id.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    ImGui::PushTextWrapPos(520.0f * app.ui_scale);
    ImGui::TextUnformatted(app.messages.front().text.c_str());
    ImGui::PopTextWrapPos();
    ImGui::Spacing();
    if (ImGui::Button("OK") || ImGui::IsKeyPressed(ImGuiKey_Enter) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        app.messages.erase(app.messages.begin());
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void draw_about(App& app) {
    center_next_window(app, 0.0f, 0.3f);
    if (!ImGui::BeginPopupModal(kPopAbout, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    ImGui::Text("Hexer %s", HEXER_VERSION);
    ImGui::TextDisabled("Hex editor for binary and protocol analysis");
    ImGui::Separator();
    ImGui::Text("Config: %s", paths::config_dir().c_str());
    ImGui::Text("Scripts: %s", paths::user_scripts_dir().c_str());
    ImGui::Text("Dear ImGui %s", ImGui::GetVersion());
    ImGui::Spacing();
    ImGui::TextDisabled("Ctrl+Shift+P opens the command palette with every action.");
    if (ImGui::Button("Close") || ImGui::IsKeyPressed(ImGuiKey_Escape)) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

// hx.prompt: a script command waits for a value. Enter = OK, Esc = Cancel. While it is open the
// app's shortcuts are off (handle_shortcuts skips them while any popup is open).
void draw_script_prompt(App& app) {
    const ScriptEngine::PendingPrompt* p = app.engine->pending_prompt();
    center_next_window(app, 0.0f, 0.25f);
    const std::string id = (p && !p->title.empty() ? p->title : std::string("Script input")) + kPopPrompt;
    if (!ImGui::BeginPopupModal(id.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    if (!p) {  // cancelled by the engine (scripts reloaded): nothing to answer
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    const float w = 480.0f * app.ui_scale;
    ImGui::TextDisabled("Script command: %s", p->command.c_str());
    if (!p->hint.empty()) {
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + w);
        ImGui::TextUnformatted(p->hint.c_str());
        ImGui::PopTextWrapPos();
    }
    ImGui::Spacing();
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(w);
    const bool enter = ImGui::InputText("##answer", &app.prompt_buf,
                                        ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
    ImGui::Spacing();
    int answer = enter ? 1 : 0;  // 1 = OK, -1 = Cancel
    if (ImGui::Button("OK")) answer = 1;
    ImGui::SameLine();
    if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape, false)) answer = -1;
    ImGui::SameLine();
    ImGui::TextDisabled("Enter: OK    Esc: cancel");
    if (answer) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
    // Runs the command on (synchronously); it may ask again, which reopens the modal next frame.
    if (answer > 0) {
        const std::string text = app.prompt_buf;
        app.engine->answer_prompt(&text);
    } else if (answer < 0) {
        app.engine->answer_prompt(nullptr);
    }
}

// Opens at most one pending popup per frame, and only when no popup is open: OpenPopup at the
// same (root) level would otherwise replace the open one.
void open_pending_popup(App& app) {
    if (any_popup_open()) return;
    if (app.save.running && now_s() - app.save.started > 0.3) {
        ImGui::OpenPopup(kPopSaving);
        return;
    }
    if (!app.messages.empty()) {
        ImGui::OpenPopup((app.messages.front().title + kPopMessage).c_str());
        return;
    }
    if (app.close_prompt_pending) {
        app.close_prompt_pending = false;
        ImGui::OpenPopup(kPopClose);
        return;
    }
    if (app.quit_prompt_pending) {
        app.quit_prompt_pending = false;
        ImGui::OpenPopup(kPopQuit);
        return;
    }
    if (app.reload_prompt_pending) {
        app.reload_prompt_pending = false;
        ImGui::OpenPopup(kPopReload);
        return;
    }
    if (app.overwrite_prompt_pending) {
        app.overwrite_prompt_pending = false;
        ImGui::OpenPopup(kPopOverwrite);
        return;
    }
    if (const ScriptEngine::PendingPrompt* p = app.engine->pending_prompt()) {  // a script command asks for input
        app.prompt_buf = p->default_text;
        ImGui::OpenPopup(kPopPrompt);
        return;
    }
    if (app.req_palette || app.req_bookmark_jump) {
        app.palette_bookmarks = !app.req_palette;
        app.req_palette = app.req_bookmark_jump = false;
        app.palette_query.clear();
        build_palette(app);
        ImGui::OpenPopup(kPopPalette);
    } else if (app.req_goto) {
        app.req_goto = false;
        if (has_doc(app)) {
            app.goto_input.clear();
            ImGui::OpenPopup(kPopGoto);
        }
    } else if (app.req_fill) {
        app.req_fill = false;
        if (has_selection(app)) ImGui::OpenPopup(kPopFill);
    } else if (app.req_copy_as) {
        app.req_copy_as = false;
        if (has_doc(app)) ImGui::OpenPopup(kPopCopyAs);
    } else if (app.req_about) {
        app.req_about = false;
        ImGui::OpenPopup(kPopAbout);
    }
}

void draw_popups(App& app) {
    open_pending_popup(app);
    draw_saving(app);
    draw_message(app);
    draw_close_prompt(app);
    draw_quit_prompt(app);
    draw_reload_prompt(app);
    draw_overwrite_prompt(app);
    draw_palette(app);
    draw_goto(app);
    draw_fill(app);
    draw_copy_as_popup(app);
    draw_about(app);
    draw_script_prompt(app);
}

// ---- settings window ---------------------------------------------------------------------

bool combo_int(const char* label, int& value, std::initializer_list<int> options, const char* zero_label) {
    const std::string preview = value == 0 ? std::string(zero_label) : std::to_string(value);
    bool changed = false;
    if (ImGui::BeginCombo(label, preview.c_str())) {
        for (int n : options) {
            const std::string item = n == 0 ? std::string(zero_label) : std::to_string(n);
            if (ImGui::Selectable(item.c_str(), value == n)) {
                changed = value != n;
                value = n;
            }
        }
        ImGui::EndCombo();
    }
    return changed;
}

void help_marker(const char* text) {
    ImGui::SameLine();
    ImGui::TextDisabled("(?)");
    ImGui::SetItemTooltip("%s", text);
}

// One window, a few sections. Every change applies right away and is saved (settings.ini).
void draw_settings_window(App& app) {
    if (!app.show_settings) return;
    const float s = app.ui_scale;
    center_next_window(app, 0.0f, 0.12f);
    if (!ImGui::Begin("Settings###settings", &app.show_settings,
                      ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::End();
        return;
    }
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) && !ImGui::IsAnyItemActive() &&
        ImGui::IsKeyPressed(ImGuiKey_Escape, false))
        app.show_settings = false;
    Settings& st = app.settings;
    bool changed = false, core = false;
    ImGui::PushItemWidth(200.0f * s);

    ImGui::SeparatorText("Hex view");
    changed |= combo_int("Bytes per row", st.bytes_per_row, {0, 8, 16, 24, 32, 48, 64}, "Auto-fit");
    changed |= combo_int("Group size", st.group_size, {0, 2, 4, 8, 16}, "No grouping");
    changed |= ImGui::Checkbox("Uppercase hex", &st.uppercase_hex);
    ImGui::SameLine();
    changed |= ImGui::Checkbox("Text column", &st.show_ascii);
    ImGui::SameLine();
    changed |= ImGui::Checkbox("Tint modified bytes", &st.highlight_modified);
    int font_px = int(st.font_size);
    if (ImGui::SliderInt("Font size", &font_px, int(kMinFont), int(kMaxFont), "%d px")) {
        st.font_size = std::clamp(float(font_px), kMinFont, kMaxFont);
        changed = true;
    }
    help_marker("Hex view font (also Ctrl +/-, Ctrl+wheel, Ctrl+0).");
    ImGui::SliderFloat("UI scale", &st.ui_scale, 0.5f, 3.0f, "%.2fx");
    if (ImGui::IsItemDeactivatedAfterEdit()) {
        st.ui_scale = std::clamp(std::round(st.ui_scale * 20.0f) / 20.0f, 0.5f, 3.0f);
        app.dpi_changed = true;  // re-applied between frames
        changed = true;
    }
    help_marker("On top of the monitor's own scale (DPI).");

    ImGui::SeparatorText("Editing");
    changed |= ImGui::Checkbox("New tabs start in insert mode", &st.insert_mode);
    changed |= ImGui::Checkbox("Go to: bare numbers are hex", &st.goto_default_hex);
    if (ImGui::InputInt("Undo: typing pause (ms)", &st.undo_merge_ms, 50, 250)) {
        st.undo_merge_ms = std::clamp(st.undo_merge_ms, 0, 600000);
        changed = core = true;
    }
    help_marker("Typing becomes a new undo step after a pause longer than this (0 = never).");
    if (ImGui::InputInt("Undo: max bytes per step", &st.undo_merge_max_bytes, 8, 64)) {
        st.undo_merge_max_bytes = std::clamp(st.undo_merge_max_bytes, 0, 1 << 20);
        changed = core = true;
    }
    help_marker("A typing run longer than this many bytes starts a new undo step (0 = no limit).");

    ImGui::SeparatorText("Saving");
    if (ImGui::Checkbox("Keep the original as <file>.backup on the first save", &st.backup_on_save))
        changed = core = true;
    ImGui::BeginDisabled(!st.backup_on_save);
    int mib = int(std::min<uint64_t>(st.backup_max_bytes >> 20, uint64_t(INT_MAX)));
    if (ImGui::InputInt("Backup size limit (MiB)", &mib, 256, 1024)) {
        st.backup_max_bytes = uint64_t(std::max(0, mib)) << 20;
        changed = core = true;
    }
    ImGui::EndDisabled();
    help_marker("Saves that patch the file in place copy it first; files larger than this are not "
                "copied (0 = no limit). Saves that rewrite the file rename the original instead (free).");
    ImGui::BeginDisabled(app.session == nullptr);
    if (ImGui::Checkbox("Hot exit: restore tabs and unsaved edits on start", &st.restore_session)) {
        app.hot_exit = app.session && st.restore_session;
        changed = true;
    }
    ImGui::EndDisabled();
    if (ImGui::InputInt("Session autosave (s)", &st.session_autosave_seconds, 1, 10)) {
        st.session_autosave_seconds = std::clamp(st.session_autosave_seconds, 1, 3600);
        changed = true;
    }

    ImGui::SeparatorText("Fonts (restart Hexer to apply)");
    static const char* kHinting[] = {"normal", "light", "none", "mono"};
    if (ImGui::BeginCombo("Hinting", st.font_hinting.c_str())) {
        for (const char* h : kHinting)
            if (ImGui::Selectable(h, st.font_hinting == h)) {
                st.font_hinting = h;
                changed = true;
            }
        ImGui::EndCombo();
    }
    help_marker("normal: crispest (the font's own hints)  light: truer shapes  none: soft  mono: aliased");
    ImGui::PushItemWidth(360.0f * s);
    changed |= ImGui::InputTextWithHint("Hex font file", "auto (Cascadia Mono, Consolas, ...)", &st.mono_font);
    changed |= ImGui::InputTextWithHint("UI font file", "auto (Segoe UI, Inter, ...)", &st.ui_font);
    ImGui::PopItemWidth();
    ImGui::TextDisabled("Loaded: %s, %s (%s)", app.fonts.mono_path.empty() ? "built-in" : path_filename(app.fonts.mono_path).c_str(),
                        app.fonts.ui_path.empty() ? "built-in" : path_filename(app.fonts.ui_path).c_str(),
                        app.fonts.freetype ? "FreeType" : "stb_truetype");
    ImGui::PopItemWidth();
    ImGui::Spacing();
    ImGui::TextDisabled("Changes apply right away and are saved to settings.ini.");
    ImGui::SetItemTooltip("%s", paths::settings_file().c_str());
    if (changed) mark_settings_dirty(app);
    if (core) apply_core_settings(st);
    ImGui::End();
}

// ---- notifications (toasts, bottom-right) ------------------------------------------------

void draw_notifications(App& app) {
    const double t = now_s();
    auto& ns = app.notifications;
    ns.erase(std::remove_if(ns.begin(), ns.end(), [&](const Notification& n) { return n.expires <= t; }), ns.end());
    if (ns.empty()) return;
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    const float pad = 12.0f * app.ui_scale;
    float y = vp->WorkPos.y + vp->WorkSize.y - pad;
    uint64_t dismiss = 0;
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
                                   ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                                   ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoMove;
    for (size_t i = ns.size(); i-- > 0;) {
        const Notification& n = ns[i];
        ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + vp->WorkSize.x - pad, y), ImGuiCond_Always, ImVec2(1.0f, 1.0f));
        ImGui::SetNextWindowBgAlpha(0.96f);
        char name[48];
        std::snprintf(name, sizeof name, "##toast%llu", static_cast<unsigned long long>(n.id));
        if (ImGui::Begin(name, nullptr, flags)) {
            ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + 440.0f * app.ui_scale);
            ImGui::TextColored(n.error ? kErrorColor : ImGui::GetStyleColorVec4(ImGuiCol_Text), "%s", n.text.c_str());
            ImGui::PopTextWrapPos();
            ImGui::SameLine();
            if (ImGui::SmallButton("x")) dismiss = n.id;
            y -= ImGui::GetWindowHeight() + pad * 0.5f;
        }
        ImGui::End();
    }
    if (dismiss)
        ns.erase(std::remove_if(ns.begin(), ns.end(), [&](const Notification& n) { return n.id == dismiss; }), ns.end());
}

}  // namespace

// =============================================================================================
// ScriptHost
// =============================================================================================

Document* App::active_document() { return usable_doc(*this); }

Document* App::find_document(uint64_t id) {
    Tab* t = find_tab(*this, id);
    return t ? t->doc.get() : nullptr;
}

Document* App::open_bytes(const std::string& name, const uint8_t* data, size_t len) {
    std::unique_ptr<Document> d = Document::create_from_bytes(name.empty() ? "Script output" : name, data, len);
    if (!d) return nullptr;
    return add_tab(*this, std::move(d)).doc.get();
}

void App::reveal(Document& doc, uint64_t offset, uint64_t len) {
    if (Tab* t = find_tab(*this, doc.id())) reveal_range(*this, *t, offset, len, true);
}

// =============================================================================================
// Per-frame housekeeping: drops, disk changes, scripts, session, settings, title
// =============================================================================================

namespace {

void process_pending_opens(App& app) {
    if (app.pending_open.empty()) return;
    std::vector<std::string> paths;
    paths.swap(app.pending_open);
    for (const std::string& p : paths) {
        FileStat st = os_stat(p);
        if (st.exists && st.is_dir) {
            notify(app, "Cannot open a folder: " + p, true);
            continue;
        }
        open_path(app, p);
    }
}

void poll_disk_change(App& app) {
    Tab* t = active_tab(app);
    if (!t || t->doc->busy() || t->path.empty()) return;
    const double n = now_s();
    if (n < t->next_disk_check) return;
    t->next_disk_check = n + 2.0;
    t->disk_changed = t->doc->changed_on_disk() && !ignored_version(*t);
}

// Unreadable data (bad sector, removed drive, file truncated elsewhere): one console warning per
// document; the status bar shows an "I/O error" badge while it lasts.
void poll_io_errors(App& app) {
    for (auto& t : app.tabs) {
        if (t->io_warned || t->doc->busy() || !t->doc->io_error()) continue;
        t->io_warned = true;
        log_console(app, ConsoleLine::Warn,
                    t->label + ": I/O error while reading the file; unreadable bytes are shown as ?? and read as 0");
    }
}

void bring_to_front(GLFWwindow* w) {
    if (glfwGetWindowAttrib(w, GLFW_ICONIFIED)) glfwRestoreWindow(w);
    glfwFocusWindow(w);
    // The OS may refuse to steal the focus (Windows foreground rules): flash the taskbar instead.
    if (!glfwGetWindowAttrib(w, GLFW_FOCUSED)) glfwRequestWindowAttention(w);
}

// Single instance: open the files another Hexer process forwarded (see run_app) and come to the
// front. Also picks up messages left over from an instance that died before reading them.
void poll_inbox(App& app) {
    if (!app.inbox) return;
    const double n = now_s();
    if (n < app.next_inbox_poll) return;
    app.next_inbox_poll = n + 0.5;
    std::vector<std::vector<std::string>> msgs = inbox_take(app.session->dir());
    if (msgs.empty()) return;
    for (const auto& m : msgs)
        for (const std::string& p : m) app.pending_open.push_back(p);  // opened next frame, deduped
    bring_to_front(app.window);
}

void poll_scripts(App& app) {
    if (app.save.running) return;  // scripts may read documents
    const double n = now_s();
    if (n < app.next_script_poll) return;
    app.next_script_poll = n + 1.0;
    if (app.engine->poll_hot_reload()) set_status(app, "Scripts reloaded");
}

uint64_t session_signature(App& app) {
    uint64_t h = 1469598103934665603ull;
    auto mix = [&](uint64_t v) {
        h ^= v;
        h *= 1099511628211ull;
    };
    mix(app.tabs.size());
    mix(uint64_t(int64_t(app.active)));
    for (auto& t : app.tabs) {
        mix(t->doc->id());
        mix(t->doc->state_id());
        mix(t->doc->view_generation);
        mix(t->doc->read_only() ? 1 : 0);
    }
    return h;
}

// Returns false only if a session write was attempted (or impossible because a save is running)
// and failed; `err_out` gets the reason.
bool save_session(App& app, bool force, std::string* err_out) {
    if (!app.hot_exit || !app.session) return true;
    if (any_busy(app)) {
        if (err_out) *err_out = "a document is being saved";
        return false;
    }
    const uint64_t sig = session_signature(app);
    if (!force && sig == app.session_sig) return true;
    std::vector<Document*> docs;
    for (auto& t : app.tabs) docs.push_back(t->doc.get());
    std::string err;
    if (!app.session->save(docs, std::max(app.active, 0), &err)) {
        if (err != app.last_session_err) log_console(app, ConsoleLine::Warn, "Session save failed: " + err);
        app.last_session_err = err;
        if (err_out) *err_out = err.empty() ? std::string("unknown error") : err;
        return false;
    }
    app.session_sig = sig;
    app.last_session_err.clear();
    return true;
}

void autosave(App& app) {
    const double n = now_s();
    if (n >= app.next_autosave) {
        app.next_autosave = n + std::max(1, app.settings.session_autosave_seconds);
        save_session(app, false);
    }
    if (app.settings_dirty_at >= 0.0 && n - app.settings_dirty_at > 1.0) {
        app.settings_dirty_at = -1.0;
        app.settings.save(paths::settings_file());
    }
}

void update_title(App& app) {
    std::string title = "Hexer";
    if (Tab* t = active_tab(app)) {
        title += std::string(" ") + kEmDash + " " + t->label;
        if (t->doc->busy() || t->doc->dirty()) title += std::string(" ") + kDirtyDot;
    }
    if (title == app.window_title) return;
    app.window_title = title;
    glfwSetWindowTitle(app.window, title.c_str());
}

void build_default_layout(ImGuiID dock_id) {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::DockBuilderRemoveNode(dock_id);
    ImGui::DockBuilderAddNode(dock_id, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dock_id, vp->WorkSize);
    ImGuiID center = dock_id;
    ImGuiID right = ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.36f, nullptr, &center);
    ImGuiID bottom = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.28f, nullptr, &center);
    ImGuiID right_bottom = ImGui::DockBuilderSplitNode(right, ImGuiDir_Down, 0.58f, nullptr, &right);
    ImGui::DockBuilderDockWindow(kWinEditor, center);
    ImGui::DockBuilderDockWindow(kWinInspector, right);
    ImGui::DockBuilderDockWindow(kWinStructure, right_bottom);
    ImGui::DockBuilderDockWindow(kWinConsole, bottom);
    ImGui::DockBuilderDockWindow(kWinResults, bottom);
    ImGui::DockBuilderDockWindow(kWinBookmarks, bottom);
    ImGui::DockBuilderFinish(dock_id);
}

void draw_dockspace(App& app) {
    const ImGuiID dock_id = ImGui::GetID("HexerDockSpace");
    if (app.build_layout || !ImGui::DockBuilderGetNode(dock_id)) {
        build_default_layout(dock_id);
        app.build_layout = false;
        app.layout_focus_step = 4;  // windows get docked over the next frames; then front the tabs
    }
    ImGui::DockSpaceOverViewport(dock_id, ImGui::GetMainViewport());
}

void draw_panels(App& app) {
    // Inline edits are keyed by row / cursor within one document: end them when the active
    // document changes (Ctrl+Tab, new tab, script reveal...) so Enter cannot commit into another.
    const Tab* at = active_tab(app);
    const uint64_t doc_id = at ? at->doc->id() : 0;
    if (doc_id != app.edit_doc) {
        app.edit_doc = doc_id;
        app.insp_edit.end();
        app.st_edit.end();
        app.bm_edit.end();
    }
    if (app.show_inspector) draw_inspector_panel(app);
    if (app.show_structure) draw_structure_panel(app);
    if (app.show_console) {
        if (app.layout_focus_step == 2) ImGui::SetNextWindowFocus();  // fresh layout: Console in front
        draw_console_panel(app);
    }
    if (app.show_results) {
        if (app.focus_results) {
            ImGui::SetNextWindowFocus();
            app.focus_results = false;
        }
        draw_search_results_panel(app);
    }
    if (app.show_bookmarks) draw_bookmarks_panel(app);
    // New windows take focus when they first appear, so on the first frame the last panel drawn
    // (Bookmarks) would steal its dock node's selected tab from the one saved in the layout.
    if (ImGui::GetFrameCount() == 1) ImGui::SetWindowFocus(kWinEditor);
}

void frame(App& app) {
    app.wants_poll = false;
    // Inbox first: forwarded files are opened this frame, before process_quit can end the app
    // (the sender already exited, believing them delivered; open tabs go into the session).
    poll_inbox(app);
    process_pending_opens(app);
    poll_save(app);
    poll_search(app);
    poll_disk_change(app);
    poll_io_errors(app);
    poll_scripts(app);
    if (Tab* t = active_tab(app); t && !t->doc->busy()) update_structure(app, *t);

    draw_main_menu(app);
    draw_status_bar(app);  // side bar: must come before the dockspace
    draw_dockspace(app);
    draw_editor(app);
    draw_panels(app);
    draw_settings_window(app);
    draw_notifications(app);
    draw_popups(app);
    handle_shortcuts(app);

    process_quit(app);
    update_title(app);
    autosave(app);
    if (app.layout_focus_step > 0) app.layout_focus_step--;
    if (app.save.running || app.find.job.running() || app.layout_focus_step > 0) app.wants_poll = true;
}

// =============================================================================================
// Startup / shutdown
// =============================================================================================

void on_drop(GLFWwindow* w, int count, const char** paths) {
    App* app = static_cast<App*>(glfwGetWindowUserPointer(w));
    if (!app) return;
    for (int i = 0; i < count; ++i)
        if (paths[i]) app->pending_open.emplace_back(paths[i]);
}

// Scale for sizes in window coordinates. Where the framebuffer is denser than window coordinates
// (macOS Retina, Wayland) ImGui already rasterises fonts at framebuffer density, so only the rest
// of the monitor's content scale applies; on Windows/X11 (density 1) it is the content scale.
float ui_dpi_scale(GLFWwindow* w, float content_scale) {
    int ww = 0, wh = 0, fw = 0, fh = 0;
    glfwGetWindowSize(w, &ww, &wh);
    glfwGetFramebufferSize(w, &fw, &fh);
    const float density = (ww > 0 && fw > 0) ? float(fw) / float(ww) : 1.0f;
    return content_scale > 0.0f ? std::max(0.25f, content_scale / density) : 1.0f;
}

// Monitor DPI changed (window moved to another monitor, system scale changed).
void on_content_scale(GLFWwindow* w, float sx, float /*sy*/) {
    App* app = static_cast<App*>(glfwGetWindowUserPointer(w));
    if (!app || sx <= 0.0f) return;
    const float s = ui_dpi_scale(w, sx);
    if (s == app->dpi_scale) return;
    app->dpi_scale = s;
    app->dpi_changed = true;
}

// Re-applies ui_scale = monitor scale * settings.ui_scale (user factor). Between frames only.
void apply_ui_scale(App& app) {
    app.dpi_changed = false;
    const float s = std::clamp(app.dpi_scale * app.settings.ui_scale, 0.5f, 4.0f);
    if (s == app.ui_scale) return;
    app.ui_scale = s;
    ImGui::GetStyle().FontSizeBase = kUiFontPx * s;  // fonts are rasterised on demand at any size
    apply_dark_theme(s);
}

void on_glfw_error(int code, const char* desc) {
    std::fprintf(stderr, "hexer: GLFW error %d: %s\n", code, desc ? desc : "");
}

void restore_session(App& app) {
    Session::Restored r = app.session->load();
    const bool any = !r.docs.empty();
    for (auto& d : r.docs) {
        if (!d) continue;
        // Continue the "Untitled N" numbering after restored untitled tabs.
        const std::string name = d->display_name();
        if (!d->has_path() && name.rfind("Untitled ", 0) == 0) {
            const long n = std::strtol(name.c_str() + 9, nullptr, 10);
            if (n > app.untitled_counter && n < 1000000) app.untitled_counter = int(n);
        }
        Tab& t = add_tab(app, std::move(d));
        // top_row is a row index; with another bytes-per-row (auto-fit, window size) it would show
        // another region, so make sure the caret is on screen (no-op when it already is).
        t.view.request_scroll_to(t.doc->view().cursor, false);
    }
    if (any && !app.tabs.empty()) {
        app.active = std::clamp(r.active_index, 0, int(app.tabs.size()) - 1);
        app.select_request = app.active;
    }
    for (const std::string& w : r.warnings) log_console(app, ConsoleLine::Warn, "Session: " + w);
    if (r.warnings.size() == 1)
        notify(app, r.warnings.front(), false);
    else if (r.warnings.size() > 1)
        notify(app, "Session restored with " + std::to_string(r.warnings.size()) + " warnings (see Console)", false);
    for (auto& t : app.tabs) t->last_top_row = t->doc->view().top_row;
    app.session_sig = session_signature(app);
}

// Single instance (Sublime-like): when another Hexer owns this config dir's session, post our
// files to its inbox, wait until it has taken them and return true (the caller exits). Never for
// --no-session, --new-instance or automation runs (--exec, --screenshot, --frames); --config-dir
// scopes it to that directory, so test runs never reach the user's instance. If the running
// instance does not respond within a few seconds, the message is withdrawn and we start normally.
bool forward_to_running_instance(const AppOptions& opts) {
    if (opts.no_session || opts.new_instance || !opts.run_lua.empty() || !opts.actions.empty() || !opts.screenshot.empty() ||
        opts.frames > 0)
        return false;
    const std::string dir = paths::session_dir();
    if (!session_primary_running(dir)) return false;
    std::vector<std::string> files;
    for (const std::string& f : opts.files) files.push_back(os_absolute_path(f));
    std::string posted, err;
    if (!inbox_post(dir, files, &posted, &err)) {
        std::fprintf(stderr, "hexer: cannot reach the running instance (%s); opening a new window\n", err.c_str());
        return false;
    }
    allow_foreground_handoff();  // let the running instance take the focus from us
    for (int i = 0; i < 100; ++i) {  // it polls the inbox every 0.5 s
        if (!os_stat(posted).exists) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (!inbox_withdraw(posted)) return true;  // taken just now
    std::fprintf(stderr, "hexer: the running instance does not respond; opening a new window\n");
    return false;
}

void startup(App& app) {
    app.engine = std::make_unique<ScriptEngine>(&app);
    app.engine->set_script_dirs({paths::bundled_scripts_dir(), paths::user_scripts_dir()});
    app.engine->reload();
    if (!app.opts.no_session) app.session = std::make_unique<Session>(paths::session_dir());
    app.hot_exit = app.session && app.settings.restore_session;
    if (app.hot_exit) restore_session(app);
    app.inbox = app.session && app.session->primary();
    for (const std::string& f : app.opts.files) open_path(app, f);
    app.next_autosave = now_s() + std::max(1, app.settings.session_autosave_seconds);
}

void shutdown(App& app) {
    app.find.job.cancel();
    if (app.save.running) {
        app.save.thread.join();  // only reachable with --frames; normal exits wait for the save
        app.save.running = false;
    }
    if (app.hot_exit)
        save_session(app, true);
    else if (app.session && !app.settings.restore_session)
        app.session->clear();  // hot exit disabled: don't resurrect stale edits later
    app.settings.save(paths::settings_file());
    app.engine.reset();  // before documents: the Lua state may still reference them
    app.tabs.clear();
    app.closed.clear();
}

bool write_ppm(const std::string& path, int w, int h) {
    if (w <= 0 || h <= 0) return false;
    const size_t row = size_t(w) * 3;
    std::vector<uint8_t> px(row * size_t(h));
    glPixelStorei(GL_PACK_ALIGNMENT, 1);
    glReadBuffer(GL_BACK);
    glReadPixels(0, 0, w, h, GL_RGB, GL_UNSIGNED_BYTE, px.data());
    char header[64];
    int hn = std::snprintf(header, sizeof header, "P6\n%d %d\n255\n", w, h);
    std::string out(header, size_t(hn));
    out.reserve(out.size() + px.size());
    for (int y = h - 1; y >= 0; --y)  // GL origin is bottom-left; PPM is top-down
        out.append(reinterpret_cast<const char*>(px.data() + size_t(y) * row), row);
    std::string err;
    if (!os_write_whole_atomic(path, out.data(), out.size(), &err)) {
        std::fprintf(stderr, "hexer: cannot write screenshot %s: %s\n", path.c_str(), err.c_str());
        return false;
    }
    return true;
}

GLFWwindow* create_window() {
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
#ifdef __APPLE__
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#else
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
#endif
    glfwWindowHint(GLFW_SCALE_TO_MONITOR, GLFW_TRUE);
    return glfwCreateWindow(1440, 900, "Hexer", nullptr, nullptr);
}

// Window/taskbar icon. Windows: GLFW picks up the exe's GLFW_ICON resource (src/hexer.rc) by itself.
// X11: set from the embedded pixels. Wayland has no client-set icons (the .desktop file's Icon= is used).
void set_window_icon(GLFWwindow* w) {
#ifdef _WIN32
    (void)w;
#else
    if (glfwGetPlatform() == GLFW_PLATFORM_WAYLAND) return;
    auto px = [](const uint8_t* p) { return const_cast<unsigned char*>(p); };
    GLFWimage imgs[] = {
        {icon::k16Size, icon::k16Size, px(icon::k16)},
        {icon::k32Size, icon::k32Size, px(icon::k32)},
        {icon::k48Size, icon::k48Size, px(icon::k48)},
        {icon::k64Size, icon::k64Size, px(icon::k64)},
    };
    glfwSetWindowIcon(w, int(sizeof(imgs) / sizeof(imgs[0])), imgs);
#endif
}

}  // namespace

// =============================================================================================
// Entry
// =============================================================================================

int run_app(const AppOptions& opts) {
    App app;
    app.opts = opts;
    if (!opts.config_dir.empty()) paths::set_config_dir_override(opts.config_dir);
    paths::ensure_dirs();
    app.settings.load(paths::settings_file());
    if (forward_to_running_instance(opts)) return 0;
    apply_core_settings(app.settings);

    glfwSetErrorCallback(on_glfw_error);
    if (!glfwInit()) {
        std::fprintf(stderr, "hexer: cannot initialise GLFW\n");
        return 1;
    }
    app.window = create_window();
    if (!app.window) {
        std::fprintf(stderr, "hexer: cannot create an OpenGL 3.0 window\n");
        glfwTerminate();
        return 1;
    }
    set_window_icon(app.window);
    glfwMakeContextCurrent(app.window);
    glfwSwapInterval(1);
    glfwSetWindowUserPointer(app.window, &app);
    glfwSetDropCallback(app.window, on_drop);
    glfwSetWindowContentScaleCallback(app.window, on_content_scale);

    // settings.ui_scale is a user factor on top of the monitor's content scale, which is read on
    // every start and followed at runtime (on_content_scale).
    float sx = 1.0f, sy = 1.0f;
    glfwGetWindowContentScale(app.window, &sx, &sy);
    app.dpi_scale = ui_dpi_scale(app.window, sx);
    // Older versions stored the monitor scale itself as ui_scale on first run: make it 1.0 once.
    if (app.settings.migrate_ui_scale(sx > 0.0f ? sx : 1.0f)) app.settings.save(paths::settings_file());
    app.ui_scale = std::clamp(app.dpi_scale * app.settings.ui_scale, 0.5f, 4.0f);
    app.settings.font_size = std::clamp(app.settings.font_size, kMinFont, kMaxFont);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigWindowsMoveFromTitleBarOnly = true;
    app.ini_path = paths::imgui_ini_file();
    io.IniFilename = app.ini_path.c_str();
    app.build_layout = !os_stat(app.ini_path).exists;
    GImGui->ConfigNavWindowingKeyNext = 0;  // Ctrl+Tab switches document tabs instead
    GImGui->ConfigNavWindowingKeyPrev = 0;

    FontOptions font_opt;
    font_opt.ui_path = app.settings.ui_font;
    font_opt.mono_path = app.settings.mono_font;
    font_opt.hinting = app.settings.font_hinting;
    app.fonts = load_fonts(kUiFontPx * app.ui_scale, app.settings.font_size * app.ui_scale, font_opt);
    apply_dark_theme(app.ui_scale);
    ImGui_ImplGlfw_InitForOpenGL(app.window, true);
    ImGui_ImplOpenGL3_Init("#version 130");
    const bool nfd_ok = NFD_Init() == NFD_OKAY;

    startup(app);
    {
        char buf[64];
        std::snprintf(buf, sizeof buf, "%.2f", double(app.dpi_scale));
        log_console(app, ConsoleLine::Info,
                    std::string("Fonts: ") + (app.fonts.freetype ? "FreeType, hinting " + app.settings.font_hinting : "stb_truetype") +
                        ", monitor scale " + buf + ", mono " +
                        (app.fonts.mono_path.empty() ? "built-in" : app.fonts.mono_path) + ", ui " +
                        (app.fonts.ui_path.empty() ? "built-in" : app.fonts.ui_path));
    }

    int frame_no = 0, exit_code = 0, extra_frames = 2;
    bool actions_done = opts.actions.empty();
    const ImVec4 clear = col4(hex_colors().background);
    while (!app.quit) {
        if (opts.frames > 0 || app.wants_poll) {
            glfwPollEvents();
        } else if (extra_frames > 0) {  // let ImGui settle for a couple of frames after input
            --extra_frames;
            glfwPollEvents();
        } else {
            const double t0 = glfwGetTime();
            glfwWaitEventsTimeout(0.25);
            if (glfwGetTime() - t0 < 0.2) extra_frames = 2;  // woken by an event
        }
        if (glfwWindowShouldClose(app.window)) {
            glfwSetWindowShouldClose(app.window, GLFW_FALSE);
            app.quit_requested = true;  // the session makes this prompt-free (see process_quit)
        }
        if (app.dpi_changed) apply_ui_scale(app);

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        frame(app);
        ImGui::Render();

        int fw = 0, fh = 0;
        glfwGetFramebufferSize(app.window, &fw, &fh);
        glViewport(0, 0, fw, fh);
        glClearColor(clear.x, clear.y, clear.z, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        ++frame_no;
        if (frame_no == 1 && !opts.run_lua.empty()) app.engine->exec(opts.run_lua);
        // --action: once the first layout has settled (its focus changes would close popups).
        if (!actions_done && frame_no >= 2 && app.layout_focus_step == 0) {
            actions_done = true;
            for (const std::string& name : opts.actions) {
                const Action* a = find_action(name.c_str());
                if (!a)
                    std::fprintf(stderr, "hexer: --action: unknown action '%s'\n", name.c_str());
                else if (!action_enabled(app, *a))
                    std::fprintf(stderr, "hexer: --action: '%s' is not available now\n", name.c_str());
                else
                    a->run(app);
            }
        }
        if (opts.frames > 0 && frame_no >= opts.frames) {
            if (!opts.screenshot.empty() && !write_ppm(opts.screenshot, fw, fh)) exit_code = 1;
            app.quit = true;
        }
        glfwSwapBuffers(app.window);
    }

    shutdown(app);
    if (nfd_ok) NFD_Quit();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(app.window);
    glfwTerminate();
    return exit_code;
}

}  // namespace hx

// =============================================================================================
// UTF-8 command line (kept last: <windows.h> defines many macros)
// =============================================================================================
#ifdef _WIN32
#undef APIENTRY  // defined by glfw3.h for gl.h; <windows.h> defines it again
#include <windows.h>
#include <shellapi.h>

namespace hx {
namespace {
std::vector<std::string> command_line_utf8(int argc, char** argv) {
    std::vector<std::string> out;
    int n = 0;
    LPWSTR* w = CommandLineToArgvW(GetCommandLineW(), &n);
    if (w && n == argc) {
        for (int i = 0; i < n; ++i) out.push_back(wide_to_utf8(w[i]));
    } else {
        for (int i = 0; i < argc; ++i) out.emplace_back(argv[i] ? argv[i] : "");
    }
    if (w) LocalFree(w);
    return out;
}
void allow_foreground_handoff() { AllowSetForegroundWindow(ASFW_ANY); }
}  // namespace
}  // namespace hx
#else
namespace hx {
namespace {
std::vector<std::string> command_line_utf8(int argc, char** argv) {
    std::vector<std::string> out;
    for (int i = 0; i < argc; ++i) out.emplace_back(argv[i] ? argv[i] : "");
    return out;
}
void allow_foreground_handoff() {}
}  // namespace
}  // namespace hx
#endif
