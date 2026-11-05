#pragma once
// Strings panel: extracts printable strings (ASCII / UTF-16LE / UTF-16BE) of the whole document or
// the selection on a worker thread (core/strings_scan.h) and lists them in a virtualised table with
// a live, incremental filter. Self-contained: it knows nothing about App; the host passes the active
// document and callbacks. Results are kept per document (by Document::id()), so switching tabs
// keeps them; call forget() when a document is closed.
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>

#include "core/strings_scan.h"

struct ImFont;

namespace hx {

class Document;
struct Settings;

struct StringsPanelCallbacks {
    std::function<void(uint64_t offset, uint64_t len)> jump;  // select [offset, offset+len) and reveal it
    std::function<void(const std::string& text)> copy;        // put text on the clipboard
    std::function<void(const std::string& msg)> notify;       // short status-bar message
};

struct StringsPanel {
    StringsPanel();
    ~StringsPanel();
    StringsPanel(const StringsPanel&) = delete;
    StringsPanel& operator=(const StringsPanel&) = delete;

    StringsOptions options;       // scan settings (shared by all documents)
    bool selection_only = false;  // scan the selection instead of the whole file
    ImFont* mono = nullptr;       // font for offsets and texts (nullptr = current font)
    float ui_scale = 1.0f;        // column widths

    // Options <-> settings.ini (Settings::strings_*): load_settings at startup; save_settings writes
    // them back and returns true when one changed (the host then saves settings.ini).
    void load_settings(const Settings& s);
    bool save_settings(Settings& s) const;

    // Draws the panel contents into the current window (the caller owns Begin/End). `doc` may be
    // null (no document open). Never mutates the document; a document being saved (busy) is shown
    // but cannot be rescanned until the save finishes.
    void draw(Document* doc, const StringsPanelCallbacks& cb);
    // Drops the results (and cancels the scan) of a closed document.
    void forget(uint64_t doc_id);
    // Start a scan (of the selection or the whole file) on the next draw(), as the Scan button
    // does (e.g. from a palette action).
    void request_scan(bool selection) {
        selection_only = selection;
        scan_requested_ = true;
    }
    // The last draw() had a scan running or a filter in progress: the host should keep drawing
    // frames (instead of waiting for input) so progress and results show up.
    bool wants_frames() const { return wants_frames_; }
    // Time the incremental filter may use per draw() (default 4 ms).
    double filter_budget_ms = 4.0;

private:
    struct DocState;
    DocState& state(uint64_t doc_id);
    std::map<uint64_t, std::unique_ptr<DocState>> docs_;
    bool scan_requested_ = false;
    bool wants_frames_ = false;
};

}  // namespace hx
