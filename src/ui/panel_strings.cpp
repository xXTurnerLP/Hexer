#include "ui/panel_strings.h"

#include <algorithm>
#include <cfloat>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "imgui.h"
#include "misc/cpp/imgui_stdlib.h"

#include "core/document.h"
#include "core/settings.h"
#include "core/util.h"
#include "ui/hex_view.h"

namespace hx {

namespace {

const ImVec4 kWarnColor(1.0f, 0.78f, 0.35f, 1.0f);
const ImVec4 kErrColor(1.0f, 0.42f, 0.42f, 1.0f);
constexpr size_t kDisplayChars = 256;     // text column / filter
constexpr size_t kCopyChars = 1u << 20;   // "Copy text" limit

std::string fmt_off(uint64_t v) { return "0x" + fmt_hex(v, 8); }

// 1234567 -> "1,234,567"
std::string fmt_count(uint64_t v) {
    std::string s = std::to_string(v);
    for (int i = int(s.size()) - 3; i > 0; i -= 3) s.insert(size_t(i), ",");
    return s;
}

}  // namespace

struct StringsPanel::DocState {
    StringsJob job;
    uint64_t seen_gen = 0;                       // job generation already picked up
    uint64_t pending_doc_gen = 0;                // document generation when the running scan started
    std::shared_ptr<const StringsJob::Result> res;
    uint64_t res_doc_gen = 0;                    // document generation the result was taken from
    std::string filter_text;
    StringsFilter filter;
    size_t selected = SIZE_MAX;                  // index into res->scan.hits
};

StringsPanel::StringsPanel() = default;
StringsPanel::~StringsPanel() = default;

void StringsPanel::load_settings(const Settings& s) {
    options.ascii = s.strings_ascii;
    options.utf16le = s.strings_utf16le;
    options.utf16be = s.strings_utf16be;
    options.include_newlines = s.strings_newlines;
    options.min_length = uint32_t(std::clamp(s.strings_min_length, 1, 4096));
}

bool StringsPanel::save_settings(Settings& s) const {
    const int min_len = int(std::clamp<uint32_t>(options.min_length, 1, 4096));
    if (s.strings_ascii == options.ascii && s.strings_utf16le == options.utf16le && s.strings_utf16be == options.utf16be &&
        s.strings_newlines == options.include_newlines && s.strings_min_length == min_len)
        return false;
    s.strings_ascii = options.ascii;
    s.strings_utf16le = options.utf16le;
    s.strings_utf16be = options.utf16be;
    s.strings_newlines = options.include_newlines;
    s.strings_min_length = min_len;
    return true;
}

StringsPanel::DocState& StringsPanel::state(uint64_t doc_id) {
    auto& p = docs_[doc_id];
    if (!p) p = std::make_unique<DocState>();
    return *p;
}

void StringsPanel::forget(uint64_t doc_id) {
    auto it = docs_.find(doc_id);
    if (it == docs_.end()) return;
    it->second->job.cancel();
    docs_.erase(it);  // the job's destructor joins its worker (it stops at the next block)
}

void StringsPanel::draw(Document* doc, const StringsPanelCallbacks& cb) {
    wants_frames_ = false;
    if (!doc) {
        scan_requested_ = false;
        ImGui::TextDisabled("No document open.");
        return;
    }
    DocState& st = state(doc->id());
    const float s = ui_scale;

    // ---- pick up a finished scan ----
    if (st.job.generation() != st.seen_gen) {
        st.seen_gen = st.job.generation();
        st.res = st.job.result();
        st.res_doc_gen = st.pending_doc_gen;
        st.selected = SIZE_MAX;
        st.filter.reset(st.filter_text);
        if (st.res && cb.notify) {
            const auto& sc = st.res->scan;
            std::string msg = "Strings: " + fmt_count(sc.hits.size()) + (sc.truncated ? "+" : "") + " found";
            if (sc.cancelled) msg += " (cancelled)";
            if (sc.io_error) msg += " (read error at " + fmt_off(sc.io_error_offset) + ")";
            if (sc.skipped) msg += " (" + fmt_size(sc.skipped) + " unreadable skipped)";
            cb.notify(msg);
        }
    }

    // ---- scan controls ----
    const bool running = st.job.running();
    const ViewState& v = doc->view();
    const bool sel_ok = v.has_selection();
    const bool use_sel = selection_only && sel_ok;
    const bool any_enc = options.ascii || options.utf16le || options.utf16be;
    ImGui::BeginDisabled(doc->busy() || !any_enc);
    const bool requested = scan_requested_ && !doc->busy() && any_enc;
    scan_requested_ = false;
    if (ImGui::Button(running ? "Rescan###scan" : "Scan###scan") || requested) {
        const uint64_t b = use_sel ? v.sel_begin() : 0;
        const uint64_t e = use_sel ? v.sel_end() : UINT64_MAX;
        st.pending_doc_gen = doc->generation();
        st.job.start(doc->snapshot(), b, e, options);
    }
    ImGui::EndDisabled();
    if (doc->busy() && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Document is being saved...");
    ImGui::SameLine();
    if (ImGui::RadioButton("Whole file", !use_sel)) selection_only = false;
    ImGui::SameLine();
    ImGui::BeginDisabled(!sel_ok);
    if (ImGui::RadioButton("Selection", use_sel)) selection_only = true;
    ImGui::EndDisabled();
    if (!sel_ok && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Select a range in the hex view first");

    ImGui::Checkbox("ASCII", &options.ascii);
    ImGui::SameLine();
    ImGui::Checkbox("UTF-16LE", &options.utf16le);
    ImGui::SameLine();
    ImGui::Checkbox("UTF-16BE", &options.utf16be);
    ImGui::SameLine();
    ImGui::Checkbox("\\r\\n", &options.include_newlines);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Line breaks are part of a string (else they end it)");
    ImGui::SameLine();
    int min_len = int(options.min_length);
    ImGui::SetNextItemWidth(90.0f * s);
    if (ImGui::InputInt("Min length", &min_len)) options.min_length = uint32_t(std::clamp(min_len, 1, 4096));

    if (running) {
        wants_frames_ = true;
        char pct[32];
        std::snprintf(pct, sizeof pct, "Scanning %.0f%%", st.job.progress() * 100.0);
        ImGui::ProgressBar(float(st.job.progress()), ImVec2(-80.0f * s, 0.0f), pct);
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) st.job.cancel();
    }

    if (!st.res) {
        if (!running) ImGui::TextDisabled("Press Scan to list the strings of this document.");
        return;
    }
    const StringsJob::Result& res = *st.res;
    const std::vector<StringHit>& hits = res.scan.hits;

    // ---- filter ----
    ImGui::SetNextItemWidth(-FLT_MIN);
    if (ImGui::InputTextWithHint("##filter", "Filter (case-insensitive substring)", &st.filter_text))
        st.filter.reset(st.filter_text);
    const bool filtered = !st.filter.needle().empty();
    if (filtered && !st.filter.done(hits.size())) {
        wants_frames_ = true;
        // A slice per frame: a million hits never freeze the UI.
        const auto t0 = std::chrono::steady_clock::now();
        while (!st.filter.step(*res.snap, hits, 512)) {
            const std::chrono::duration<double, std::milli> el = std::chrono::steady_clock::now() - t0;
            if (el.count() >= filter_budget_ms) break;
        }
    }

    // ---- summary ----
    const auto& sc = res.scan;
    std::string line = fmt_count(hits.size()) + (sc.truncated ? "+" : "") + " strings";
    if (filtered) line = fmt_count(st.filter.matches().size()) + " of " + line;
    if (sc.begin != 0 || sc.end != res.snap->size()) line += " in " + fmt_range(sc.begin, sc.end - sc.begin);
    ImGui::TextUnformatted(line.c_str());
    if (filtered && !st.filter.done(hits.size())) {
        ImGui::SameLine();
        ImGui::TextDisabled("(filtering %.0f%%)", 100.0 * double(st.filter.tested()) / double(hits.size()));
    }
    if (sc.truncated) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(stopped at %s results)", fmt_count(res.options.max_results).c_str());
    }
    if (sc.cancelled) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(cancelled)");
    }
    if (sc.io_error) {
        ImGui::SameLine();
        ImGui::TextColored(kErrColor, "(read error at %s)", fmt_off(sc.io_error_offset).c_str());
    }
    if (sc.skipped) {  // holes of process memory: not errors
        ImGui::SameLine();
        ImGui::TextDisabled("(%s unreadable skipped)", fmt_size(sc.skipped).c_str());
    }
    if (st.res_doc_gen != doc->generation()) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(document changed since the scan)");
    }

    // ---- table ----
    const size_t rows = filtered ? st.filter.matches().size() : hits.size();
    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_Resizable;
    if (!ImGui::BeginTable("##strings", 4, flags)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 130.0f * s);
    ImGui::TableSetupColumn("Enc", ImGuiTableColumnFlags_WidthFixed, 70.0f * s);
    ImGui::TableSetupColumn("Len", ImGuiTableColumnFlags_WidthFixed, 60.0f * s);
    ImGui::TableSetupColumn("Text", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    ImGuiListClipper clip;
    clip.Begin(int(std::min<size_t>(rows, size_t(INT_MAX))));
    while (clip.Step()) {
        for (int row = clip.DisplayStart; row < clip.DisplayEnd; ++row) {
            const size_t i = filtered ? st.filter.matches()[size_t(row)] : size_t(row);
            const StringHit& h = hits[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(row);
            if (mono) ImGui::PushFont(mono, 0.0f);
            const std::string off = fmt_off(h.offset);
            if (ImGui::Selectable(off.c_str(), st.selected == i, ImGuiSelectableFlags_SpanAllColumns)) {
                st.selected = i;
                if (cb.jump) cb.jump(h.offset, h.byte_length);
            }
            if (mono) ImGui::PopFont();
            if (ImGui::BeginPopupContextItem("##ctx")) {
                st.selected = i;
                if (ImGui::MenuItem("Copy text") && cb.copy) {
                    cb.copy(string_hit_text(*res.snap, h, kCopyChars));
                    if (cb.notify && h.char_count > kCopyChars)
                        cb.notify("Copied the first " + fmt_count(kCopyChars) + " characters");
                }
                if (ImGui::MenuItem("Copy offset") && cb.copy) cb.copy(off);
                if (ImGui::MenuItem("Select") && cb.jump) cb.jump(h.offset, h.byte_length);
                ImGui::EndPopup();
            }
            ImGui::PopID();
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(encoding_name(h.encoding));
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(fmt_count(h.char_count).c_str());
            ImGui::TableSetColumnIndex(3);
            if (mono) ImGui::PushFont(mono, 0.0f);
            std::string text = escape_string_text(string_hit_text(*res.snap, h, kDisplayChars));
            if (h.char_count > kDisplayChars) text += "...";
            ImGui::TextUnformatted(text.c_str());
            if (mono) ImGui::PopFont();
        }
    }
    ImGui::EndTable();
}

}  // namespace hx
