#include "ui/view_diff.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "imgui.h"
#include "misc/cpp/imgui_stdlib.h"

#include "core/document.h"
#include "core/settings.h"
#include "core/util.h"

namespace hx {

namespace {

const ImVec4 kWarnColor(1.0f, 0.78f, 0.35f, 1.0f);
const ImVec4 kErrColor(1.0f, 0.42f, 0.42f, 1.0f);
const ImVec4 kOkColor(0.60f, 0.90f, 0.65f, 1.0f);
const uint32_t kChangedColor = rgba(240, 70, 70, 115);
const uint32_t kOnlyColor = rgba(70, 150, 245, 105);  // OnlyA / OnlyB
const uint32_t kTickColor = rgba(240, 90, 90);

// "1,234,567"
std::string fmt_count(uint64_t v) {
    std::string s = std::to_string(v), out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (i && (s.size() - i) % 3 == 0) out += ',';
        out += s[i];
    }
    return out;
}

// "[+|-]123" or "[+|-]0x1F" (spaces ignored). Accepts the full int64 range.
bool parse_shift(const std::string& text, int64_t& out) {
    std::string s;
    for (char c : text)
        if (c != ' ' && c != '\t' && c != '_') s += c;
    bool neg = false;
    size_t i = 0;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) neg = s[i++] == '-';
    int base = 10;
    if (i + 1 < s.size() && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
        base = 16;
        i += 2;
    }
    if (i >= s.size()) return false;
    uint64_t v = 0;
    const uint64_t limit = neg ? uint64_t(1) << 63 : (uint64_t(1) << 63) - 1;
    for (; i < s.size(); ++i) {
        char c = s[i];
        int d = c >= '0' && c <= '9' ? c - '0'
                : base == 16 && c >= 'a' && c <= 'f' ? c - 'a' + 10
                : base == 16 && c >= 'A' && c <= 'F' ? c - 'A' + 10
                                                     : -1;
        if (d < 0) return false;
        if (v > (limit - uint64_t(d)) / uint64_t(base)) return false;
        v = v * uint64_t(base) + uint64_t(d);
    }
    out = neg ? int64_t(uint64_t(0) - v) : int64_t(v);
    return true;
}

std::string fmt_shift(int64_t v) {
    if (v == 0) return "0";
    uint64_t m = v < 0 ? uint64_t(0) - uint64_t(v) : uint64_t(v);
    return std::string(v < 0 ? "-" : "") + "0x" + fmt_hex(m);
}

void select_range(Document& d, uint64_t off, uint64_t len) {
    ViewState& v = d.view();
    const uint64_t size = d.size();
    v.anchor = std::min(off, size);
    v.cursor = std::min(off + std::min(len, UINT64_MAX - off), size);
    v.low_nibble = false;
    ++d.view_generation;
}

const char* kind_name(uint8_t kind) {
    return kind == DiffRange::OnlyA ? "Only in A" : kind == DiffRange::OnlyB ? "Only in B" : "Changed";
}

std::string bytes_text(uint64_t n) { return fmt_count(n) + (n == 1 ? " byte" : " bytes"); }

// What Find Shift found, for the toolbar note / status bar.
std::string shift_message(const ShiftResult& r) {
    const std::string at_a = "A 0x" + fmt_hex(r.diff_a);
    switch (r.status) {
    case ShiftResult::Found:
        if (r.delta == 0)
            return "No shift needed: the bytes after the difference at " + at_a +
                   " already line up (changed, not inserted)";
        if (r.delta > 0)
            return "Shift " + fmt_shift(r.shift) + ": B has " + bytes_text(uint64_t(r.delta)) + " more at B 0x" +
                   fmt_hex(r.diff_b);
        return "Shift " + fmt_shift(r.shift) + ": A has " + bytes_text(uint64_t(0) - uint64_t(r.delta)) +
               " more at " + at_a;
    case ShiftResult::NoDifference: return "Nothing to align: no difference with the current shift";
    case ShiftResult::NoProbe:
        return "No distinctive bytes after the difference at " + at_a + " (only padding / repeats)";
    case ShiftResult::NoMatch:
        return "No shift found: nothing after the difference at " + at_a + " matches within +-" +
               fmt_size(ShiftOptions{}.window);
    case ShiftResult::IoError: return "Find Shift stopped: read error at " + at_a;
    default: return "Find Shift cancelled";
    }
}

}  // namespace

DiffView::DiffView() = default;
DiffView::~DiffView() = default;

void DiffView::load_settings(const Settings& s) {
    sync_scroll = s.compare_sync_scroll;
    sync_caret = s.compare_sync_caret;
}

bool DiffView::save_settings(Settings& s) const {
    if (s.compare_sync_scroll == sync_scroll && s.compare_sync_caret == sync_caret) return false;
    s.compare_sync_scroll = sync_scroll;
    s.compare_sync_caret = sync_caret;
    return true;
}

// Offset on the other side: A -> B adds the shift, B -> A subtracts it (saturating).
uint64_t DiffView::map_off(uint64_t off, bool a_to_b) const {
    const bool add = (shift >= 0) == a_to_b;
    const uint64_t m = shift >= 0 ? uint64_t(shift) : uint64_t(0) - uint64_t(shift);
    if (add) return off > UINT64_MAX - m ? UINT64_MAX : off + m;
    return off > m ? off - m : 0;
}

// First visible row of `from` mapped to the other side's row, clamped like the hex view does.
uint64_t DiffView::map_top(uint64_t top, const Side& from, const Side& to, uint64_t to_size, bool a_to_b) const {
    const uint64_t fb = uint64_t(std::max(1, from.bpr)), tb = uint64_t(std::max(1, to.bpr));
    const uint64_t first = top > UINT64_MAX / fb ? UINT64_MAX : top * fb;
    uint64_t row = map_off(first, a_to_b) / tb;
    if (to.ev.visible_rows > 0) {
        const uint64_t total = to_size / tb + 1, vis = uint64_t(to.ev.visible_rows);
        row = std::min(row, total > vis ? total - vis : 0);
    }
    return row;
}

void DiffView::start_compare(Document& a, Document& b) {
    running_run_ = job_.start(a.snapshot(), b.snapshot(), shift, kMaxRanges);
    running_gen_a_ = seen_gen_a_ = a.generation();
    running_gen_b_ = seen_gen_b_ = b.generation();
    running_shift_ = shift;
    started_ = true;
    pending_since_ = -1.0;
    recompare_requested_ = false;
}

// A finished Find Shift: apply the proposed shift and show the matching block on both sides.
void DiffView::poll_shift(Document& a, Document& b, const DiffViewCallbacks& cb) {
    const uint64_t g = shift_job_.generation();
    if (g == shift_gen_seen_) return;
    shift_gen_seen_ = g;
    auto r = shift_job_.result();
    if (!r || r->run != shift_run_) return;
    shift_run_ = 0;
    if (r->status == ShiftResult::Found) {
        shift = r->shift;  // the toolbar realigns the views and the compare restarts
        select_range(a, r->match_a, 0);
        select_range(b, r->match_b, 0);
        if (sync_scroll && a_.drawn) {
            // Center A on the match; B follows with the new shift (aligned rows, also near the start).
            const uint64_t bpr = uint64_t(std::max(1, a_.bpr)), vis = uint64_t(std::max(1, a_.ev.visible_rows));
            const uint64_t row = std::min(r->match_a, a.size()) / bpr;
            a.view().top_row = row > vis / 2 ? row - vis / 2 : 0;
            synced_once_ = false;
        } else {
            a_.view.request_scroll_to(std::min(r->match_a, a.size()), true);
            b_.view.request_scroll_to(std::min(r->match_b, b.size()), true);
        }
        cur_ = kNoDiff;
    }
    note_ = shift_message(*r);
    if (cb.notify) cb.notify(note_);
}

void DiffView::poll_job() {
    const uint64_t g = job_.generation();
    if (g == job_gen_seen_) return;
    job_gen_seen_ = g;
    auto r = job_.result();
    if (!r || r->run != running_run_) return;  // a run for another pair / shift
    result_ = std::move(r);
    result_gen_a_ = running_gen_a_;
    result_gen_b_ = running_gen_b_;
    result_shift_ = running_shift_;
    cur_ = kNoDiff;
    a_.layer_for = b_.layer_for = nullptr;
    build_ticks();
}

// One tick per bucket of size/kMaxTicks bytes that holds a difference (ranges are sorted).
void DiffView::build_ticks() {
    for (int side = 0; side < 2; ++side) {
        Side& s = side ? b_ : a_;
        s.ticks.clear();
        if (!result_) continue;
        const uint64_t size = side ? result_->b_size : result_->a_size;
        const uint64_t bucket_len = size / kMaxTicks + 1;
        uint64_t last = UINT64_MAX;
        for (const DiffRange& r : result_->ranges) {
            if ((side ? diff_len_b(r) : diff_len_a(r)) == 0) continue;
            const uint64_t off = side ? r.b_off : r.a_off;
            const uint64_t bucket = off / bucket_len;
            if (bucket == last) continue;
            last = bucket;
            s.ticks.push_back(off);
        }
    }
}

// Highlights for the visible window plus one screen above and below (so wheel / page scrolling
// shows highlights in the frame it happens).
void DiffView::update_layer(Side& s, const Document& d, bool side_b) {
    if (!result_) {
        if (!s.layer.empty()) s.layer.clear();
        s.layer_for = nullptr;
        return;
    }
    const uint64_t bpr = uint64_t(std::max(1, s.bpr));
    const uint64_t rows = uint64_t(std::max(s.ev.visible_rows, 64));
    const uint64_t top = d.view().top_row;
    const uint64_t r0 = top > rows ? top - rows : 0;
    const uint64_t r1 = top + 2 * rows + 2;
    const uint64_t begin = r0 > UINT64_MAX / bpr ? UINT64_MAX : r0 * bpr;
    const uint64_t end = r1 > UINT64_MAX / bpr ? UINT64_MAX : r1 * bpr;
    if (s.layer_for == result_.get() && begin >= s.layer_begin && end <= s.layer_end) return;
    // Build a wider window than needed so small scrolls reuse it.
    const uint64_t wb = begin > (end - begin) ? begin - (end - begin) : 0;
    const uint64_t we = end > UINT64_MAX - (end - begin) ? UINT64_MAX : end + (end - begin);
    s.layer.clear();
    const auto& v = result_->ranges;
    const auto span = ranges_in(v, wb, we, side_b);
    for (size_t i = span.first; i < span.second; ++i) {
        const DiffRange& r = v[i];
        const uint64_t len = side_b ? diff_len_b(r) : diff_len_a(r);
        if (!len) continue;
        const uint64_t off = side_b ? r.b_off : r.a_off, other = side_b ? r.a_off : r.b_off;
        std::string label = std::string(kind_name(r.kind)) + ": " + fmt_count(r.len) + (r.len == 1 ? " byte" : " bytes");
        if (r.kind == DiffRange::Changed) label += std::string(side_b ? " (A at 0x" : " (B at 0x") + fmt_hex(other) + ")";
        s.layer.add({off, len, r.kind == DiffRange::Changed ? kChangedColor : kOnlyColor, std::move(label), -1});
    }
    s.layer.finalize();
    s.layer_for = result_.get();
    s.layer_begin = wb;
    s.layer_end = we;
}

void DiffView::navigate(Document& a, Document& b, int dir, const DiffViewCallbacks& cb) {
    auto say = [&](std::string msg) {
        note_ = std::move(msg);
        if (cb.notify) cb.notify(note_);
    };
    if (!result_ || result_->ranges.empty()) {
        say(result_ ? "No differences" : "Not compared yet");
        return;
    }
    const auto& v = result_->ranges;
    const size_t n = v.size();
    const uint64_t pa = focus_offset(a.view()), pb = focus_offset(b.view());
    size_t idx;
    if (cur_ < n && pa == std::min(v[cur_].a_off, a.size()) && pb == std::min(v[cur_].b_off, b.size())) {
        // Still on the difference we jumped to: step (ties in one coordinate stay in order).
        idx = dir > 0 ? (cur_ + 1 < n ? cur_ + 1 : kNoDiff) : (cur_ > 0 ? cur_ - 1 : kNoDiff);
    } else {
        const bool on_b = b_.ev.focused && !a_.ev.focused;
        const uint64_t p = on_b ? pb : pa;
        idx = dir > 0 ? next_diff(v, p, on_b) : prev_diff(v, p, on_b);
    }
    if (idx == kNoDiff) {
        say(dir > 0 ? "No more differences after the caret" : "No differences before the caret");
        return;
    }
    const DiffRange& r = v[idx];
    select_range(a, r.a_off, diff_len_a(r));
    select_range(b, r.b_off, diff_len_b(r));
    a_.view.request_scroll_to(std::min(r.a_off, a.size()), true);
    b_.view.request_scroll_to(std::min(r.b_off, b.size()), true);
    cur_ = idx;
    say("Difference " + fmt_count(idx + 1) + " of " + fmt_count(n) + (result_->truncated ? "+" : "") + ": " +
        kind_name(r.kind) + ", " + fmt_count(r.len) + (r.len == 1 ? " byte" : " bytes"));
}

void DiffView::draw_toolbar(Document& a, Document& b) {
    const bool running = job_.running();
    if (ImGui::Button("< Prev")) nav_request_ = -1;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Previous difference (Shift+F7)");
    ImGui::SameLine();
    if (ImGui::Button("Next >")) nav_request_ = 1;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next difference (F7)");
    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Shift");
    ImGui::SameLine();
    if (shift != shift_shown_) {  // set from outside (or first draw): show the value
        if (started_) synced_once_ = false;  // a new shift from the host realigns the views too
        shift_text_ = fmt_shift(shift);
        shift_shown_ = shift;
        shift_error_.clear();
    }
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 9.0f);
    bool enter = ImGui::InputText("##shift", &shift_text_, ImGuiInputTextFlags_EnterReturnsTrue);
    if (enter || ImGui::IsItemDeactivatedAfterEdit()) {
        int64_t v = 0;
        if (parse_shift(shift_text_, v)) {
            shift_error_.clear();
            if (v != shift) synced_once_ = false;  // realign the views with the new shift
            shift = shift_shown_ = v;
        } else {
            shift_error_ = "Shift: a signed number, e.g. 16, -0x200";
        }
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("B offset = A offset + shift (signed, decimal or 0x hex),\n"
                          "e.g. 0x200 when B has an extra 512-byte header.");
    ImGui::SameLine();
    ImGui::BeginDisabled(shift_job_.running() || a.busy() || b.busy());
    if (ImGui::Button("Find Shift")) find_shift_requested_ = true;
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Find the shift that lines the documents up again after their first difference\n"
                          "(an inserted or deleted header / block, searched within +-%s).",
                          fmt_size(ShiftOptions{}.window).c_str());
    ImGui::SameLine();
    if (ImGui::Checkbox("Sync scroll", &sync_scroll) && sync_scroll) synced_once_ = false;
    ImGui::SameLine();
    ImGui::Checkbox("Sync caret", &sync_caret);
    ImGui::SameLine();
    if (ImGui::Button("Recompare")) recompare_requested_ = true;

    // Status line: progress or summary, staleness, last navigation note.
    if (shift_job_.running()) {
        ImGui::ProgressBar(float(shift_job_.progress()), ImVec2(ImGui::GetFontSize() * 14.0f, 0.0f));
        ImGui::SameLine();
        if (ImGui::Button("Cancel##shift")) shift_job_.cancel();
        ImGui::SameLine();
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("Finding the shift...");
    } else if (running) {
        ImGui::ProgressBar(float(job_.progress()), ImVec2(ImGui::GetFontSize() * 14.0f, 0.0f));
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) job_.cancel();
        ImGui::SameLine();
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("Comparing...");
    } else if (result_) {
        const DiffResult& r = *result_;
        ImGui::AlignTextToFramePadding();
        if (r.identical()) {
            ImGui::TextColored(kOkColor, "Identical (%s bytes)", fmt_count(r.a_size).c_str());
        } else {
            std::string s = fmt_count(r.range_count) + (r.range_count == 1 ? " range, " : " ranges, ") +
                            fmt_count(r.diff_bytes) + (r.diff_bytes == 1 ? " byte differs" : " bytes differ");
            ImGui::TextUnformatted(s.c_str());
        }
        if (r.truncated) {
            ImGui::SameLine();
            ImGui::TextColored(kWarnColor, "(first %s ranges shown)", fmt_count(r.ranges.size()).c_str());
        }
        if (r.cancelled) {
            ImGui::SameLine();
            ImGui::TextColored(kWarnColor, "Cancelled - partial result");
        }
        if (r.io_error) {
            ImGui::SameLine();
            ImGui::TextColored(kErrColor, "Read error at A 0x%s - stopped there", fmt_hex(r.io_error_offset).c_str());
        }
    } else {
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled(a.busy() || b.busy() ? "Waiting for the save to finish..." : "Not compared yet");
    }
    if (stale_ && result_) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, running || pending_since_ >= 0.0 ? "(outdated - recomparing...)"
                                                                        : "(outdated - press Recompare)");
    }
    if (!shift_error_.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(kErrColor, "%s", shift_error_.c_str());
    } else if (!note_.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("|  %s", note_.c_str());
    }
}

// Returns true when the user interacts with this side (hovered or keyboard focus).
bool DiffView::draw_side(Side& s, Document& d, bool side_b, float width, const DiffViewCallbacks& cb) {
    ImGui::BeginChild(side_b ? "##side_b" : "##side_a", ImVec2(width, 0.0f), ImGuiChildFlags_None,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    const std::string head = std::string(side_b ? "B: " : "A: ") + d.display_name() + (d.dirty() ? " *" : "");
    ImGui::TextUnformatted(head.c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("%s (%s bytes)", fmt_size(d.size()).c_str(), fmt_count(d.size()).c_str());
    if (!d.path().empty() && ImGui::IsItemHovered()) ImGui::SetTooltip("%s", d.path().c_str());
    if (d.busy()) {  // the save worker owns the document: do not read it
        ImGui::TextDisabled("Saving...");
        ImGui::EndChild();
        return false;
    }
    update_layer(s, d, side_b);
    std::vector<const HighlightSet*> layers;
    if (cb.layers) cb.layers(d, layers);
    if (!s.layer.empty()) layers.push_back(&s.layer);
    HexViewConfig cfg = cb.config;
    if (cb.config_for) cb.config_for(d, cfg);
    cfg.tick_offsets = s.ticks.empty() ? nullptr : &s.ticks;
    cfg.tick_color = kTickColor;
    s.view.draw("##hex", d, layers, cfg, s.ev);
    s.bpr = s.ev.bytes_per_row;
    s.drawn = true;
    const bool interacting = s.ev.focused || ImGui::IsWindowHovered(ImGuiHoveredFlags_ChildWindows);
    if (cb.on_events) cb.on_events(d, s.ev);
    ImGui::EndChild();
    return interacting;
}

void DiffView::draw(const char* id, Document& a, Document& b, const DiffViewCallbacks& cb) {
    ImGui::PushID(id);
    if (a.id() != doc_a_ || b.id() != doc_b_) {  // another pair: start over
        job_.cancel();
        running_run_ = 0;  // ignore whatever the old pair's run still publishes
        doc_a_ = a.id();
        doc_b_ = b.id();
        result_.reset();
        a_.ticks.clear();
        b_.ticks.clear();
        a_.layer_for = b_.layer_for = nullptr;
        cur_ = kNoDiff;
        shift_job_.cancel();
        shift_run_ = 0;
        started_ = false;
        synced_once_ = false;
        note_.clear();
    }
    poll_job();
    if (find_shift_requested_ && !a.busy() && !b.busy()) {
        find_shift_requested_ = false;
        note_.clear();
        shift_run_ = shift_job_.start(a.snapshot(), b.snapshot(), shift);
    }
    poll_shift(a, b, cb);

    // Recompare: immediately when asked / first time / shift changed, debounced after edits.
    const double now = ImGui::GetTime();
    if (a.generation() != seen_gen_a_ || b.generation() != seen_gen_b_) {
        seen_gen_a_ = a.generation();
        seen_gen_b_ = b.generation();
        if (started_) pending_since_ = now;
    }
    bool want = recompare_requested_ || !started_ || shift != running_shift_;
    if (pending_since_ >= 0.0 && now - pending_since_ >= kDebounceMs / 1000.0) {
        if (diff_work(a.size(), b.size(), shift) <= kAutoLimit) want = true;
        else pending_since_ = -1.0;  // too big to redo after every edit: wait for Recompare
    }
    if (want && !a.busy() && !b.busy()) start_compare(a, b);
    stale_ = result_ && (result_gen_a_ != a.generation() || result_gen_b_ != b.generation() || result_shift_ != shift);

    // F7 / Shift+F7 while this view (any child) has keyboard focus.
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) && ImGui::IsKeyPressed(ImGuiKey_F7, false))
        nav_request_ = ImGui::GetIO().KeyShift ? -1 : 1;

    draw_toolbar(a, b);
    if (nav_request_) {
        navigate(a, b, nav_request_, cb);
        nav_request_ = 0;
    }

    ViewState& va = a.view();
    ViewState& vb = b.view();
    // Synced scrolling, part 1: changes made outside the view since the last frame (goto in the
    // document's tab, first frame, new shift) - the side that moved wins.
    if (sync_scroll) {
        if (!synced_once_) {
            vb.top_row = map_top(va.top_row, a_, b_, b.size(), true);
            // Bytes per row are only known after both sides were laid out (auto-fit): until
            // then map_top guessed them, so align again on the next frame.
            synced_once_ = a_.drawn && b_.drawn;
        } else if (va.top_row != a_.last_top) {
            vb.top_row = map_top(va.top_row, a_, b_, b.size(), true);
        } else if (vb.top_row != b_.last_top) {
            va.top_row = map_top(vb.top_row, b_, a_, a.size(), false);
        }
    }

    const float spacing = ImGui::GetStyle().ItemSpacing.x;
    const float half = std::max(1.0f, std::floor((ImGui::GetContentRegionAvail().x - spacing) * 0.5f));

    // Part 2: the side the user scrolls (hovered / focused) drives the other one. Changes the
    // hex view made by itself (clamping) do not propagate.
    const uint64_t a_before = va.top_row;
    const bool a_user = draw_side(a_, a, false, half, cb);
    const bool a_drive = va.top_row != a_before && a_user;
    if (sync_scroll && a_drive) vb.top_row = map_top(va.top_row, a_, b_, b.size(), true);
    if (sync_caret && a_.ev.cursor_moved) {
        vb.anchor = std::min(map_off(va.anchor, true), b.size());
        vb.cursor = std::min(map_off(va.cursor, true), b.size());
        vb.ascii_focus = va.ascii_focus;
        vb.low_nibble = false;
        ++b.view_generation;
        b_.view.request_scroll_to(caret_byte(vb), false);
    }

    ImGui::SameLine();
    const uint64_t b_before = vb.top_row;
    const bool b_user = draw_side(b_, b, true, 0.0f, cb);
    const bool b_drive = vb.top_row != b_before && b_user;
    if (sync_scroll && b_drive && !a_drive) va.top_row = map_top(vb.top_row, b_, a_, a.size(), false);
    if (sync_caret && b_.ev.cursor_moved && !a_.ev.cursor_moved) {
        va.anchor = std::min(map_off(vb.anchor, false), a.size());
        va.cursor = std::min(map_off(vb.cursor, false), a.size());
        va.ascii_focus = vb.ascii_focus;
        va.low_nibble = false;
        ++a.view_generation;
        a_.view.request_scroll_to(caret_byte(va), false);
    }
    a_.last_top = va.top_row;
    b_.last_top = vb.top_row;
    ImGui::PopID();
}

}  // namespace hx
