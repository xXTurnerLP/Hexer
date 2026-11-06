#include "ui/panel_history.h"

#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "imgui.h"

#include "core/document.h"
#include "core/util.h"
#include "ui/hex_view.h"

namespace hx {

namespace {

const ImVec4 kSavedColor(0.45f, 0.85f, 0.55f, 1.0f);

std::string change_text(const HistoryChange& c) {
    if (!c.known) return "?";
    if (c.same) return {};
    std::string s = c.new_len ? fmt_range(c.offset, c.new_len) : "0x" + fmt_hex(c.offset, 8);
    if (c.old_len != c.new_len) {
        const bool grew = c.new_len > c.old_len;
        s += grew ? "  +" : "  -";
        s += std::to_string(grew ? c.new_len - c.old_len : c.old_len - c.new_len);
    }
    return s;
}

}  // namespace

const HistoryChange& HistoryPanel::change_of(const Document& d, size_t row) {
    if (cache_.size() <= row) cache_.resize(row + 1);
    Cached& c = cache_[row];
    const uint64_t before = row ? history_state_id(d, row - 1) : 0;
    const uint64_t after = history_state_id(d, row);
    if (c.after_id != after || c.before_id != before || c.after_id == 0) {
        c.before_id = before;
        c.after_id = after;
        c.change = history_row_change(d, row);
    }
    return c.change;
}

void HistoryPanel::jump(Document& d, size_t row, const HistoryPanelCallbacks& cb) {
    const size_t from = history_current(d);
    if (row == from) return;
    // Compare before moving: the stacks are rewritten by every step.
    const HistoryChange c = history_diff(history_pieces(d, from), history_pieces(d, row));
    const bool ok = history_jump(d, row);
    const size_t now = history_current(d);
    if (now != from && cb.moved) cb.moved(c.known && !c.same ? c.offset : d.view().cursor);
    if (!cb.notify) return;
    if (!ok) {
        cb.notify(d.read_only() ? "History: the document is read-only"
                                : "History: cannot move while an action is running");
    } else {
        const size_t steps = now > from ? now - from : from - now;
        cb.notify(std::string(now > from ? "Redo" : "Undo") + " " + std::to_string(steps) +
                  (steps == 1 ? " step" : " steps") + ": " + history_label(d, now));
    }
}

void HistoryPanel::draw(Document* doc, const HistoryPanelCallbacks& cb) {
    if (!doc) {
        ImGui::TextDisabled("No document open.");
        return;
    }
    if (doc->busy()) {
        ImGui::TextDisabled("Saving... the history is shown again when the save finishes.");
        return;
    }
    const float s = ui_scale;
    if (cache_doc_ != doc->id() || cache_gen_ != doc->persist_generation()) {
        cache_doc_ = doc->id();
        cache_gen_ = doc->persist_generation();
        cache_.clear();
    }

    const size_t n = history_count(*doc);
    const size_t cur = history_current(*doc);
    const uint64_t saved = doc->saved_state_id();
    ImGui::Text("%zu undo, %zu redo", cur, n - 1 - cur);
    if (doc->read_only()) {
        ImGui::SameLine();
        ImGui::TextDisabled("(read-only)");
    }

    // ---- keyboard: Up = one step back (undo), Down = one step forward (redo) ----
    size_t target = SIZE_MAX;
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput) {
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow) && cur > 0) target = cur - 1;
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow) && cur + 1 < n) target = cur + 1;
        if (ImGui::IsKeyPressed(ImGuiKey_Home, false)) target = 0;
        if (ImGui::IsKeyPressed(ImGuiKey_End, false)) target = n - 1;
    }

    const bool scroll_to_cur = shown_doc_ != doc->id() || shown_state_ != doc->state_id();
    shown_doc_ = doc->id();
    shown_state_ = doc->state_id();

    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                  ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;
    const int64_t now_ms = Document::now_ms();
    if (ImGui::BeginTable("##history", 4, flags)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 44.0f * s);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Change", ImGuiTableColumnFlags_WidthStretch, 1.4f);
        ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 110.0f * s);
        ImGui::TableHeadersRow();
        ImGuiListClipper clip;
        clip.Begin(int(std::min<size_t>(n, size_t(INT_MAX))));
        if (scroll_to_cur && cur < size_t(INT_MAX)) clip.IncludeItemByIndex(int(cur));
        const ImVec4 dim = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
        while (clip.Step()) {
            for (int r = clip.DisplayStart; r < clip.DisplayEnd; ++r) {
                const size_t row = size_t(r);
                const bool is_redo = row > cur;
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(r);
                if (is_redo) ImGui::PushStyleColor(ImGuiCol_Text, dim);
                const std::string num = std::to_string(row);
                if (ImGui::Selectable(num.c_str(), row == cur, ImGuiSelectableFlags_SpanAllColumns))
                    target = row;
                if (row == cur && scroll_to_cur && !ImGui::IsItemVisible()) ImGui::SetScrollHereY(0.5f);
                if (ImGui::IsItemHovered() && row != cur) {
                    const size_t steps = row > cur ? row - cur : cur - row;
                    ImGui::SetTooltip("%s %zu step%s to this state", row > cur ? "Redo" : "Undo", steps,
                                      steps == 1 ? "" : "s");
                }
                ImGui::PopID();
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(history_label(*doc, row).c_str());
                // View steps keep the bytes (and state id): tag only the first row of such a run.
                if (saved && history_state_id(*doc, row) == saved &&
                    (row == 0 || history_state_id(*doc, row - 1) != saved)) {
                    ImGui::SameLine();
                    ImGui::TextColored(kSavedColor, "saved");
                }
                ImGui::TableSetColumnIndex(2);
                const HistoryChange& c = change_of(*doc, row);
                const std::string text = change_text(c);
                if (mono) ImGui::PushFont(mono, 0.0f);
                ImGui::TextUnformatted(text.c_str());
                if (mono) ImGui::PopFont();
                if (!c.known && ImGui::IsItemHovered())
                    ImGui::SetTooltip("Too many edits in this state to compare cheaply");
                ImGui::TableSetColumnIndex(3);
                const int64_t when = history_time(*doc, row);
                ImGui::TextUnformatted(history_time_text(when, now_ms).c_str());
                if (when > 0 && ImGui::IsItemHovered()) ImGui::SetTooltip("%s", history_time_full(when).c_str());
                if (is_redo) ImGui::PopStyleColor();
            }
        }
        ImGui::EndTable();
    }

    if (target != SIZE_MAX && target < n) jump(*doc, target, cb);
}

}  // namespace hx
