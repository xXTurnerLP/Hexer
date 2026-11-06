#pragma once
// History panel: the document's whole undo history as a list, oldest state at the top.
//
//   row 0           the oldest state ("Original"; "Oldest kept state" once kMaxUndo trimmed it)
//   row k (k >= 1)  the state after action k ("Typing", "Paste", "Fill", "Script: ...")
//   row current()   the document's current state (highlighted); rows below it are redo states
//                   (greyed). The row whose state is the last saved one is tagged "saved" (the
//                   first of a run: view steps after it have the same bytes).
//
// Clicking a row (or Up/Down/Home/End while the panel is focused) moves the document to that state
// with one Document::undo()/redo() per step, so it is exactly what repeated Ctrl+Z / Ctrl+Y do.
// The "Change" column is the byte range an action touched, found by comparing the piece lists of
// neighbouring states (bounded work, visible rows only, cached). View steps (read-only toggle,
// parser / Parse at: UndoEntry::view_only) change no byte. The "Time" column says when the action
// happened ("just now", "5 min ago", "yesterday 14:03"; the full date in a tooltip).
//
// Self-contained (no App dependency). The history_* helpers below are core-only (no ImGui) so
// tests/test_history.cpp can test them; HistoryPanel::draw() lives in panel_history.cpp.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "core/document.h"
#include "core/piece_table.h"

struct ImFont;

namespace hx {

// ---- history rows (UI thread, document not busy) -------------------------------------------------
inline size_t history_count(const Document& d) {
    return d.history_undo().size() + 1 + d.history_redo().size();
}
inline size_t history_current(const Document& d) { return d.history_undo().size(); }

// The stored entry of row `row`, or nullptr for the current state (its data is the live document).
inline const UndoEntry* history_entry(const Document& d, size_t row) {
    const auto& u = d.history_undo();
    const auto& r = d.history_redo();
    if (row < u.size()) return &u[row];
    if (row == u.size()) return nullptr;
    size_t j = row - u.size() - 1;  // 0 = the next redo
    return j < r.size() ? &r[r.size() - 1 - j] : nullptr;
}
inline uint64_t history_state_id(const Document& d, size_t row) {
    const UndoEntry* e = history_entry(d, row);
    return e ? e->state_id : d.state_id();
}
// The bytes of row `row`. A view step stores none: they are those of its neighbour toward the
// current row (see UndoEntry).
inline const std::vector<Piece>& history_pieces(const Document& d, size_t row) {
    const size_t cur = history_current(d);
    for (;;) {
        const UndoEntry* e = history_entry(d, row);
        if (!e) return d.table().pieces();
        if (!e->view_only) return e->pieces;
        row = row < cur ? row + 1 : row - 1;
    }
}
// Name of the action that led to row `row`.
inline std::string history_label(const Document& d, size_t row) {
    const auto& u = d.history_undo();
    const auto& r = d.history_redo();
    if (row == 0) return u.size() + r.size() >= Document::kMaxUndo ? "Oldest kept state" : "Original";
    const std::string* l = nullptr;
    if (row <= u.size()) {
        l = &u[row - 1].label;
    } else {
        size_t j = row - u.size() - 1;
        if (j < r.size()) l = &r[r.size() - 1 - j].label;
    }
    return l && !l->empty() ? *l : std::string("Edit");
}

// When the action that led to row `row` happened (UndoEntry::time_ms; 0 = unknown, and for row 0).
inline int64_t history_time(const Document& d, size_t row) {
    const auto& u = d.history_undo();
    const auto& r = d.history_redo();
    if (row == 0) return 0;
    if (row <= u.size()) return u[row - 1].time_ms;
    const size_t j = row - u.size() - 1;
    return j < r.size() ? r[r.size() - 1 - j].time_ms : 0;
}

// Local calendar time of `ms` (since the Unix epoch).
inline bool history_local_time(int64_t ms, std::tm& out) {
    const std::time_t t = std::time_t(ms / 1000);
#ifdef _WIN32
    return localtime_s(&out, &t) == 0;
#else
    return localtime_r(&t, &out) != nullptr;
#endif
}

// "just now" (under a minute, or a clock in the future), "N min ago" (under an hour), "today 14:03",
// "yesterday 14:03", "Mon 14:03" (the last week), else "2026-11-02 14:03". Local time; "" for 0.
inline std::string history_time_text(int64_t ms, int64_t now_ms) {
    if (ms <= 0) return {};
    if (now_ms - ms < 60000) return "just now";
    if (now_ms - ms < 3600000) return std::to_string((now_ms - ms) / 60000) + " min ago";
    std::tm t{}, n{};
    if (!history_local_time(ms, t) || !history_local_time(now_ms, n)) return {};
    // Whole calendar days between the two dates (noon avoids DST edges).
    std::tm a = t, b = n;
    a.tm_hour = b.tm_hour = 12;
    a.tm_min = b.tm_min = a.tm_sec = b.tm_sec = 0;
    a.tm_isdst = b.tm_isdst = -1;
    const double days = std::difftime(std::mktime(&b), std::mktime(&a)) / 86400.0;
    const int day = int(days + (days < 0 ? -0.5 : 0.5));
    char hm[16];
    std::snprintf(hm, sizeof hm, "%02d:%02d", t.tm_hour, t.tm_min);
    if (day == 0) return std::string("today ") + hm;
    if (day == 1) return std::string("yesterday ") + hm;
    if (day > 1 && day < 7) {
        static const char* kDays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
        return std::string(kDays[t.tm_wday % 7]) + " " + hm;
    }
    char buf[32];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02d %s", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, hm);
    return buf;
}

// "2026-11-06 14:03:12" (local time; "" for 0): the tooltip of the Time column.
inline std::string history_time_full(int64_t ms) {
    std::tm t{};
    if (ms <= 0 || !history_local_time(ms, t)) return {};
    char buf[40];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02d %02d:%02d:%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
                  t.tm_hour, t.tm_min, t.tm_sec);
    return buf;
}

// Moves `d` to row `row` with one undo()/redo() per step. False if a step was refused (busy,
// read-only, a group open) or `row` is out of range; the document then sits where it stopped.
inline bool history_jump(Document& d, size_t row) {
    if (row >= history_count(d)) return false;
    while (history_current(d) > row)
        if (!d.undo()) return false;
    while (history_current(d) < row)
        if (!d.redo()) return false;
    return true;
}

// What changed between two piece lists, in the coordinates of `after`: bytes [offset, offset +
// new_len) replace `old_len` bytes of `before`. Bytes count as equal when both lists reference the
// same stored bytes (same source, chunk and position), which is what an edit leaves untouched.
struct HistoryChange {
    bool known = false;      // false: the comparison gave up (more than max_steps pieces walked)
    bool same = false;       // no byte differs (e.g. a bookmark action)
    uint64_t offset = 0, old_len = 0, new_len = 0;
};

inline HistoryChange history_diff(const std::vector<Piece>& before, const std::vector<Piece>& after,
                                  size_t max_steps = size_t(1) << 15) {
    HistoryChange c;
    auto total = [](const std::vector<Piece>& v) {
        uint64_t n = 0;
        for (const Piece& p : v) n += p.len;
        return n;
    };
    const uint64_t sa = total(before), sb = total(after);
    // Common bytes walking from the front (fwd) or the back.
    auto common = [&](bool fwd, uint64_t limit, bool* ok) {
        size_t i = 0, j = 0, steps = 0;
        uint64_t oa = 0, ob = 0, n = 0;  // bytes consumed inside before[i] / after[j]
        while (i < before.size() && j < after.size() && n < limit) {
            if (++steps > max_steps) {
                *ok = false;
                return n;
            }
            const Piece& p = before[fwd ? i : before.size() - 1 - i];
            const Piece& q = after[fwd ? j : after.size() - 1 - j];
            if (p.src != q.src || p.chunk != q.chunk) break;
            // Positions of the next compared byte (fwd) / of the end of the remaining run (back).
            uint64_t pa = fwd ? p.start + oa : p.start + p.len - oa;
            uint64_t pb = fwd ? q.start + ob : q.start + q.len - ob;
            if (pa != pb) break;
            uint64_t k = std::min({p.len - oa, q.len - ob, limit - n});
            n += k;
            oa += k;
            ob += k;
            if (oa == p.len) {
                ++i;
                oa = 0;
            }
            if (ob == q.len) {
                ++j;
                ob = 0;
            }
        }
        return n;
    };
    bool ok = true;
    const uint64_t m = std::min(sa, sb);
    uint64_t pre = common(true, m, &ok);
    uint64_t suf = ok ? common(false, m - pre, &ok) : 0;
    if (!ok) return c;
    c.known = true;
    c.offset = pre;
    c.old_len = sa - pre - suf;
    c.new_len = sb - pre - suf;
    c.same = c.old_len == 0 && c.new_len == 0;
    return c;
}

// Change made by the action that led to row `row` (row 0: nothing).
inline HistoryChange history_row_change(const Document& d, size_t row) {
    if (row == 0 || row >= history_count(d)) {
        HistoryChange c;
        c.known = c.same = true;
        return c;
    }
    return history_diff(history_pieces(d, row - 1), history_pieces(d, row));
}

// ---- the panel ---------------------------------------------------------------------------------
struct HistoryPanelCallbacks {
    // The document moved to another history state (its caret/selection are already restored).
    // `offset` is where the bytes changed between the old and the new state (or the restored
    // caret when no byte did): scroll the hex view there without changing the selection.
    std::function<void(uint64_t offset)> moved;
    std::function<void(const std::string& msg)> notify;  // short status-bar message (optional)
};

struct HistoryPanel {
    ImFont* mono = nullptr;  // font for the Change column (nullptr = current font)
    float ui_scale = 1.0f;

    // Draws the panel contents into the current window (the caller owns Begin/End). `doc` may be
    // null. A busy (saving) document is not touched: the panel shows a note instead.
    void draw(Document* doc, const HistoryPanelCallbacks& cb);

private:
    struct Cached {
        uint64_t before_id = 0, after_id = 0;
        HistoryChange change;
    };
    const HistoryChange& change_of(const Document& d, size_t row);
    void jump(Document& d, size_t row, const HistoryPanelCallbacks& cb);

    uint64_t cache_doc_ = 0, cache_gen_ = UINT64_MAX;
    std::vector<Cached> cache_;          // by row; after_id == 0: not computed
    uint64_t shown_doc_ = 0, shown_state_ = 0;  // scroll the current row into view when it changes
};

}  // namespace hx
