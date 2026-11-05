#pragma once
// Non-file targets: the "Open Process..." and "Open Disk..." pickers and the Regions panel of a
// process document (core/devices.h, core/procmem.h).
//   * TargetsDialog: two independent windows. The process picker lists running processes
//     (filter by name / pid / path, Refresh, "Writable" checkbox); double-click or Open calls
//     cb.open_process(pid, writable). The disk picker lists disks and volumes with their sizes
//     (also accepts a typed device path), "Writable" with a warning; Open calls
//     cb.open_device(path, writable). A callback returning false keeps the window open and shows
//     its *err (e.g. "Access is denied (try running Hexer as administrator)").
//   * RegionsPanel: two tabs for the active process document. "Regions": table base | size |
//     prot | type | module, filter, Refresh (re-reads the region map and the document's cached
//     bytes); a click calls cb.jump(base, size). "Modules": the loaded modules (core/devices.h
//     process_modules) as base | size | name | path, filter, Refresh; a click calls
//     cb.jump(base, size). The region / module holding the caret is highlighted.
//     "Go to Module" (open_module_list + draw_module_list): a filterable popup of the modules;
//     Enter / click jumps to the module's base (cb.jump(base, size)).
// Self-contained: no App dependency. The app owns one TargetsDialog and one RegionsPanel, calls
// TargetsDialog::draw() every frame (it draws nothing while both windows are closed) and draws the
// RegionsPanel inside its own window (the caller owns Begin/End, like the other panels).
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/devices.h"

struct ImFont;

namespace hx {

class Document;

struct TargetsDialogCallbacks {
    // Open a process / device as a new tab. Return false and set *err to keep the picker open
    // with the error shown. Null = that picker's Open button is disabled.
    std::function<bool(uint32_t pid, bool writable, std::string* err)> open_process;
    std::function<bool(const std::string& path, bool writable, std::string* err)> open_device;
};

class TargetsDialog {
public:
    void open_process_picker();  // show + focus, re-list processes
    void open_disk_picker();     // show + focus, re-list devices
    bool process_picker_open() const { return proc_open_; }
    bool disk_picker_open() const { return disk_open_; }
    void close() { proc_open_ = disk_open_ = false; }

    // Draws whichever picker windows are open ("Open Process" / "Open Disk"; Begin/End inside).
    // `mono` = font for pids / paths / sizes (nullptr = current font).
    void draw(ImFont* mono, float ui_scale, const TargetsDialogCallbacks& cb);

    // Picker state (public for tests / persistence).
    std::string process_filter;
    bool process_writable = false;
    bool disk_writable = false;
    std::string disk_path;       // typed or selected device path

    // The process list after filtering by `filter` (case-insensitive substring of the name or the
    // path, or a pid prefix). Exposed for tests.
    static std::vector<const ProcessInfo*> filter_processes(const std::vector<ProcessInfo>& all,
                                                            const std::string& filter);

private:
    void draw_process_picker(ImFont* mono, float ui_scale, const TargetsDialogCallbacks& cb);
    void draw_disk_picker(ImFont* mono, float ui_scale, const TargetsDialogCallbacks& cb);

    bool proc_open_ = false, proc_focus_ = false;
    bool disk_open_ = false, disk_focus_ = false;
    std::vector<ProcessInfo> procs_;
    uint32_t proc_sel_ = UINT32_MAX;
    std::string proc_err_;
    std::vector<DeviceInfo> devs_;
    std::string disk_err_;
};

struct RegionsPanelCallbacks {
    std::function<void(uint64_t address, uint64_t size)> jump;  // select / reveal the region
    std::function<void(const std::string& msg)> notify;         // short status-bar message (optional)
};

struct RegionsPanel {
    ImFont* mono = nullptr;  // font for addresses (nullptr = current font)
    float ui_scale = 1.0f;

    // Draws the panel contents into the current window. `doc` may be null or a non-process
    // document (a hint is shown). The first draw for a document lists its regions; later lists
    // only on Refresh (they change while the process runs).
    void draw(Document* doc, const RegionsPanelCallbacks& cb);
    void forget(uint64_t doc_id);  // drop the cached list of a closed document
    void request_refresh() { refresh_requested_ = true; }
    void show_modules_tab() { select_modules_ = true; }  // the next draw() selects the Modules tab

    // "Go to Module": open_module_list() opens the popup (re-listing the modules) with the next
    // draw_module_list(), which the host calls every frame outside any panel window (it draws
    // nothing while the popup is closed, and closes it when `doc` is not a process document).
    void open_module_list() { open_modules_ = true; }
    bool module_list_open() const { return modules_open_; }
    void draw_module_list(Document* doc, const RegionsPanelCallbacks& cb);

    // Case-insensitive filter over name / type / prot and the hex base ("7ff", "0x7ff"). For tests.
    static bool region_matches(const MemRegion& r, const std::string& filter);
    // The same over a module's name / path and hex base.
    static bool module_matches(const ModuleInfo& m, const std::string& filter);

private:
    struct DocState {
        std::vector<MemRegion> regions;
        std::string error;
        std::string filter;
        bool listed = false;
        std::vector<ModuleInfo> modules;
        std::string mod_error;
        std::string mod_filter;
        bool mod_listed = false;
    };
    DocState& state(const Document& doc);
    void list_modules(const Document& doc, DocState& st);
    void draw_regions(Document& doc, DocState& st, const RegionsPanelCallbacks& cb);
    void draw_modules(Document& doc, DocState& st, const RegionsPanelCallbacks& cb);

    std::map<uint64_t, std::unique_ptr<DocState>> docs_;
    bool refresh_requested_ = false;
    bool select_modules_ = false;
    // Go to Module popup
    bool open_modules_ = false, modules_open_ = false, modules_focus_ = false, modules_scroll_ = false;
    std::string pick_filter_;
    int pick_sel_ = 0;
};

}  // namespace hx
