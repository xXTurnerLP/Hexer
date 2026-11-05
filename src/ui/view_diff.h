#pragma once
// Compare view: two documents side by side (two HexViews), differences highlighted, synced
// scrolling, Prev / Next difference (F7 / Shift+F7 while the view has focus). Self-contained (no
// App dependency): the host owns one DiffView per comparison and calls draw() every frame inside
// its own window (Begin/End are the caller's), e.g. a "Compare" dock window or tab.
//
//   * Both documents are normal open documents: their ViewState (caret, selection, top_row) is the
//     one their own tab uses, and edits made here go through Document (undoable as usual). Do not
//     draw a document's own tab in the same frame with a different bytes-per-row (both views share
//     top_row); a fixed HexViewConfig::bytes_per_row avoids that.
//   * The compare runs on a DiffJob worker over Snapshots (progress + Cancel). It starts on the
//     first draw, when the shift changes, on Recompare, and ~300 ms after either document's
//     generation stopped changing (only while the aligned overlap is <= kAutoLimit; bigger pairs
//     show "outdated - press Recompare" instead of re-reading terabytes after every edit).
//   * Highlights are built only for the visible window of each side (a few HighlightSet entries per
//     frame, never one per range); scrollbar ticks are subsampled to at most kMaxTicks per side.
//   * A side whose document is busy (being saved) shows a placeholder and is not read.
//   * Find Shift (toolbar / request_find_shift()) runs find_shift() on a ShiftJob worker
//     (progress + Cancel) and applies the proposed shift: both sides then show the matching block.
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "core/diff.h"
#include "core/highlight.h"
#include "ui/hex_view.h"

namespace hx {

class Document;
struct Settings;

struct DiffViewCallbacks {
    // Base config for both hex views (font, font_size, bytes_per_row, group_size, uppercase,
    // show_ascii, highlight_modified, pointer_*). tick_offsets / tick_color are set by the view.
    HexViewConfig config;
    // Per-document tweaks after `config` was copied (e.g. the tab's insert_mode). Optional.
    std::function<void(const Document& doc, HexViewConfig& cfg)> config_for;
    // Extra highlight layers drawn under the difference highlights (parser fields, bookmarks...).
    // Optional; the pointers must stay valid until draw() returns.
    std::function<void(const Document& doc, std::vector<const HighlightSet*>& layers)> layers;
    // Events of each side after its draw (context menu, follow pointer, nav back/forward). Optional.
    std::function<void(Document& doc, const HexViewEvents& ev)> on_events;
    // Short user-facing message ("No more differences"). Optional.
    std::function<void(const std::string& msg)> notify;
};

class DiffView {
public:
    static constexpr int kDebounceMs = 300;
    static constexpr size_t kMaxTicks = 4096;  // scrollbar tick marks per side
    static constexpr size_t kMaxRanges = 1000000;
    static constexpr uint64_t kAutoLimit = uint64_t(4) << 30;  // auto-recompare after edits up to this

    DiffView();
    ~DiffView();
    DiffView(const DiffView&) = delete;
    DiffView& operator=(const DiffView&) = delete;

    // Draws toolbar + both sides into the current window. Comparing another pair of documents
    // (by Document::id()) than in the last call starts a new compare.
    void draw(const char* id, Document& a, Document& b, const DiffViewCallbacks& cb);

    // Options (also edited by the toolbar).
    int64_t shift = 0;        // B offset = A offset + shift
    bool sync_scroll = true;
    bool sync_caret = false;  // moving the caret on one side moves the other (shift applied)

    // Sync scroll / Sync caret <-> settings.ini (Settings::compare_sync_*): the host applies them
    // to every new DiffView; save_settings returns true when one changed.
    void load_settings(const Settings& s);
    bool save_settings(Settings& s) const;

    // Actions (e.g. from the host's menu / palette). Jumps apply on the next draw().
    void request_next() { nav_request_ = 1; }
    void request_prev() { nav_request_ = -1; }
    void request_recompare() { recompare_requested_ = true; }
    void request_find_shift() { find_shift_requested_ = true; }
    void cancel() {
        job_.cancel();
        shift_job_.cancel();
    }

    // A compare / Find Shift is running or an automatic compare is pending: keep drawing frames.
    bool wants_frames() const {
        return job_.running() || shift_job_.running() || find_shift_requested_ || pending_since_ >= 0.0;
    }
    bool finding_shift() const { return shift_job_.running(); }
    // The last navigation / Find Shift note shown in the toolbar ("" = none).
    const std::string& note() const { return note_; }
    // The last finished compare (null before the first). May be stale (see stale()).
    std::shared_ptr<const DiffResult> result() const { return result_; }
    // The result does not match the documents' current contents / the current shift.
    bool stale() const { return stale_; }

private:
    struct Side {
        HexView view;
        HexViewEvents ev;
        HighlightSet layer;           // differences in the visible window
        uint64_t layer_begin = 1, layer_end = 0;  // window the layer was built for
        const DiffResult* layer_for = nullptr;
        std::vector<uint64_t> ticks;  // subsampled range starts (scrollbar)
        uint64_t last_top = 0;        // top_row after the previous frame
        int bpr = 16;                 // bytes per row of the last draw
        bool drawn = false;           // laid out at least once (bpr is real, not the guess)
    };
    void start_compare(Document& a, Document& b);
    void poll_job();
    void poll_shift(Document& a, Document& b, const DiffViewCallbacks& cb);
    void build_ticks();
    void update_layer(Side& s, const Document& d, bool side_b);
    void navigate(Document& a, Document& b, int dir, const DiffViewCallbacks& cb);
    void draw_toolbar(Document& a, Document& b);
    bool draw_side(Side& s, Document& d, bool side_b, float width, const DiffViewCallbacks& cb);
    uint64_t map_off(uint64_t off, bool a_to_b) const;
    uint64_t map_top(uint64_t top, const Side& from, const Side& to, uint64_t to_size, bool a_to_b) const;

    DiffJob job_;
    uint64_t job_gen_seen_ = 0;
    uint64_t running_run_ = 0;           // DiffJob run id of the last started compare
    std::shared_ptr<const DiffResult> result_;
    int64_t result_shift_ = 0;           // shift / generations the result was computed for
    uint64_t result_gen_a_ = 0, result_gen_b_ = 0;
    int64_t running_shift_ = 0;          // ... and of the last started compare
    uint64_t running_gen_a_ = 0, running_gen_b_ = 0;
    uint64_t seen_gen_a_ = 0, seen_gen_b_ = 0;  // generations seen by the last draw (debounce)
    uint64_t doc_a_ = 0, doc_b_ = 0;     // Document::id() of the pair compared
    bool stale_ = false;
    bool started_ = false;
    bool synced_once_ = false;
    double pending_since_ = -1.0;        // ImGui time of the last change awaiting a recompare
    bool recompare_requested_ = false;
    int nav_request_ = 0;
    size_t cur_ = kNoDiff;               // index of the difference last jumped to
    std::string shift_text_ = "0";
    int64_t shift_shown_ = 0;            // shift value shift_text_ was last synced with
    std::string shift_error_;
    std::string note_;                   // last navigation note ("No more differences")
    ShiftJob shift_job_;                 // Find Shift
    uint64_t shift_run_ = 0;             // ShiftJob run id of the last started search (0 = none)
    uint64_t shift_gen_seen_ = 0;
    bool find_shift_requested_ = false;
    Side a_, b_;
};

}  // namespace hx
