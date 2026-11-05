#include "ui/panel_hash.h"

#include <cfloat>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"
#include "misc/cpp/imgui_stdlib.h"

#include "core/document.h"
#include "core/util.h"
#include "ui/hex_view.h"

namespace hx {

namespace {

const ImVec4 kWarnColor(1.0f, 0.78f, 0.35f, 1.0f);
const ImVec4 kErrColor(1.0f, 0.42f, 0.42f, 1.0f);
const ImVec4 kMatchText(0.60f, 0.90f, 0.65f, 1.0f);
const ImU32 kMatchRow = IM_COL32(40, 120, 60, 150);
constexpr double kDebounceSec = 0.15;

uint32_t default_algos() {
    uint32_t m = 0;
    const auto& all = hash_algorithms();
    for (size_t i = 0; i < all.size(); ++i)
        if (all[i].is_default) m |= uint32_t(1) << i;
    return m;
}

int count_bits(uint32_t m) {
    int n = 0;
    for (; m; m &= m - 1) ++n;
    return n;
}

std::string upper(std::string s) {
    for (char& c : s)
        if (c >= 'a' && c <= 'f') c = char(c - 'a' + 'A');
    return s;
}

}  // namespace

HashPanel::HashPanel() : algos_(default_algos()) {}

std::vector<std::string> HashPanel::selected() const {
    std::vector<std::string> out;
    const auto& all = hash_algorithms();
    for (size_t i = 0; i < all.size(); ++i)
        if (algos_ & (uint32_t(1) << i)) out.push_back(all[i].name);
    return out;
}

void HashPanel::set_selected(const std::vector<std::string>& names) {
    const auto& all = hash_algorithms();
    uint32_t m = 0;
    for (const auto& n : names)
        if (const HashAlgorithm* a = find_hash_algorithm(n)) m |= uint32_t(1) << size_t(a - all.data());
    algos_ = m;
}

void HashPanel::start(const Document& doc, const Key& k) {
    std::vector<std::string> names;
    const auto& all = hash_algorithms();
    for (size_t i = 0; i < all.size(); ++i)
        if (k.algos & (uint32_t(1) << i)) names.push_back(all[i].name);
    job_.start(doc.snapshot(), k.offset, k.length, std::move(names));
    // A previous run may have published after this frame's pickup in draw(); its result belongs to
    // the old key, not to `k`. From here on only the new run can publish (HashJob::start).
    seen_gen_ = job_.generation();
    job_key_ = k;
    have_no_auto_ = false;
}

void HashPanel::draw_algorithm_popup() {
    if (!ImGui::BeginPopup("##hash_algos")) return;
    const auto& all = hash_algorithms();
    if (ImGui::SmallButton("Defaults")) algos_ = default_algos();
    ImGui::SameLine();
    if (ImGui::SmallButton("All")) algos_ = (uint32_t(1) << all.size()) - 1;
    ImGui::SameLine();
    if (ImGui::SmallButton("None")) algos_ = 0;
    ImGui::Separator();
    for (size_t i = 0; i < all.size(); ++i) {
        if (i > 0 && all[i].digest_size >= 16 && all[i - 1].digest_size < 16) ImGui::Separator();  // MD5/SHA
        bool on = (algos_ >> i) & 1;
        if (ImGui::Checkbox(all[i].name, &on)) algos_ = on ? algos_ | (uint32_t(1) << i) : algos_ & ~(uint32_t(1) << i);
    }
    ImGui::EndPopup();
}

void HashPanel::draw_results(ImFont* mono, float ui_scale, const HashPanelCallbacks& cb) {
    auto copy = [&](const std::string& text, const std::string& what) {
        if (cb.copy) cb.copy(text);
        else ImGui::SetClipboardText(text.c_str());
        if (cb.status) cb.status("Copied " + what);
    };
    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollX |
                                  ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;
    if (!ImGui::BeginTable("##hashes", 2, flags)) return;
    ImGui::TableSetupScrollFreeze(1, 1);
    ImGui::TableSetupColumn("Algorithm", ImGuiTableColumnFlags_WidthFixed, 150.0f * ui_scale);
    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed);
    ImGui::TableHeadersRow();
    const auto& values = result_.values;
    for (size_t i = 0; i < values.size(); ++i) {
        const auto& v = values[i];
        const bool match = hex_matches(expected, v.hex);
        ImGui::TableNextRow();
        if (match) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, kMatchRow);
        ImGui::TableSetColumnIndex(0);
        ImGui::PushID(int(i));
        if (ImGui::Selectable(v.algo.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) copy(v.hex, v.algo);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Click to copy, right-click for more");
        if (ImGui::BeginPopupContextItem("##row")) {
            if (ImGui::MenuItem("Copy")) copy(v.hex, v.algo);
            if (ImGui::MenuItem("Copy as 0x...")) copy("0x" + v.hex, v.algo);
            if (ImGui::MenuItem("Copy uppercase")) copy(upper(v.hex), v.algo);
            ImGui::Separator();
            if (ImGui::MenuItem("Copy all")) {
                std::string all;
                for (const auto& w : values) all += w.algo + ": " + w.hex + "\n";
                copy(all, "all hashes");
            }
            ImGui::EndPopup();
        }
        ImGui::PopID();
        ImGui::TableSetColumnIndex(1);
        if (mono) ImGui::PushFont(mono, 0.0f);
        if (match) ImGui::TextColored(kMatchText, "%s", v.hex.c_str());
        else ImGui::TextUnformatted(v.hex.c_str());
        if (mono) ImGui::PopFont();
    }
    ImGui::EndTable();
}

void HashPanel::draw(const char* title, bool* open, const Document* doc, ImFont* mono, float ui_scale,
                     const HashPanelCallbacks& cb) {
    // Consume a finished run (only the newest run publishes; job_key_ describes it).
    if (job_.generation() != seen_gen_) {
        seen_gen_ = job_.generation();
        HashJob::Result r = job_.result();
        if (!r.cancelled) {
            result_ = std::move(r);
            result_key_ = job_key_;
            have_result_ = true;
        }
    }

    ImGuiWindowClass wc;  // like the other panels: the dock tab has its own close button
    wc.DockNodeFlagsOverrideSet = ImGuiDockNodeFlags_NoCloseButton;
    ImGui::SetNextWindowClass(&wc);
    ImGui::SetNextWindowSize(ImVec2(560.0f * ui_scale, 340.0f * ui_scale), ImGuiCond_FirstUseEver);  // when floating
    if (!ImGui::Begin(title, open)) {
        pending_since_ = -1.0;  // hidden (e.g. behind another dock tab): no auto compute
        ImGui::End();
        return;
    }
    if (!doc || doc->busy()) {
        pending_since_ = -1.0;
        ImGui::TextDisabled("%s", doc ? "Document is being saved..." : "Open a file to hash its bytes.");
        ImGui::End();
        return;
    }

    // ---- current range + key ----
    const ViewState& v = doc->view();
    const bool use_sel = v.has_selection() && !whole_file;
    Key cur;
    cur.doc_id = doc->id();
    cur.gen = doc->generation();
    cur.offset = use_sel ? v.sel_begin() : 0;
    cur.length = use_sel ? v.sel_len() : doc->size();
    cur.algos = algos_;
    const bool running = job_.running();
    const bool running_cur = running && job_key_ == cur;
    const bool fresh = have_result_ && result_key_ == cur;
    const bool small = cur.length <= kAutoLimit;
    const bool auto_ok = small && cur.algos != 0 && !(have_no_auto_ && no_auto_key_ == cur);

    // ---- auto compute (debounced) / manual request ----
    const double now = ImGui::GetTime();
    if (compute_requested_ && cur.algos) {
        start(*doc, cur);
    } else if (!fresh && !running_cur && auto_ok) {
        if (pending_since_ < 0 || !(pending_key_ == cur)) {
            pending_key_ = cur;
            pending_since_ = now;
        } else if (now - pending_since_ >= kDebounceSec) {
            start(*doc, cur);
            pending_since_ = -1.0;
        }
    }
    compute_requested_ = false;

    // ---- header: range, whole-file toggle, algorithms, compute / progress ----
    ImGui::TextUnformatted(use_sel ? "Selection" : "File");
    ImGui::SameLine();
    ImGui::TextDisabled("%s", fmt_range(cur.offset, cur.length).c_str());
    ImGui::SameLine();
    ImGui::BeginDisabled(!v.has_selection());
    ImGui::Checkbox("Whole file", &whole_file);
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Hash the whole file even when bytes are selected");

    char label[48];
    std::snprintf(label, sizeof label, "Algorithms (%d)...", count_bits(algos_));
    if (ImGui::Button(label)) ImGui::OpenPopup("##hash_algos");
    draw_algorithm_popup();
    ImGui::SameLine();
    ImGui::BeginDisabled(algos_ == 0);
    if (ImGui::Button(fresh ? "Recompute" : "Compute")) start(*doc, cur);
    ImGui::EndDisabled();
    if (job_.running()) {
        ImGui::SameLine();
        ImGui::ProgressBar(float(job_.progress()), ImVec2(140.0f * ui_scale, 0.0f));
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            job_.cancel();
            no_auto_key_ = job_key_;
            have_no_auto_ = true;
        }
    }

    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("##expected", "Expected value (hex, 0x optional) - a matching row turns green",
                             &expected);

    // ---- state line ----
    if (algos_ == 0) {
        ImGui::TextDisabled("No algorithm selected.");
    } else if (!fresh) {
        if (running_cur || (auto_ok && !running)) {
            ImGui::TextDisabled("Computing...");
        } else if (have_no_auto_ && no_auto_key_ == cur) {
            ImGui::TextDisabled("Cancelled. Press Compute to hash %s.", fmt_size(cur.length).c_str());
        } else if (!small) {
            ImGui::TextDisabled("%s is above the %s auto limit: press Compute.", fmt_size(cur.length).c_str(),
                                fmt_size(kAutoLimit).c_str());
        }
        if (have_result_ && !running_cur) {
            const char* why = result_key_.doc_id != cur.doc_id ? "another document"
                              : result_key_.gen != cur.gen     ? "document changed"
                              : result_key_.offset != cur.offset || result_key_.length != cur.length
                                  ? "range changed"
                                  : "algorithms changed";
            ImGui::TextColored(kWarnColor, "Stale (%s)", why);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Values below are for %s",
                                  fmt_range(result_key_.offset, result_key_.length).c_str());
        }
    }
    if (have_result_ && result_.io_error)
        ImGui::TextColored(kErrColor, "Read error at 0x%llX: no values.",
                           static_cast<unsigned long long>(result_.io_error_offset));
    if (have_result_ && !normalize_hex(expected).empty() && !result_.values.empty()) {
        std::string hit;
        for (const auto& r : result_.values)
            if (hex_matches(expected, r.hex)) hit += (hit.empty() ? "" : ", ") + r.algo;
        if (hit.empty()) ImGui::TextColored(kErrColor, "Expected value: no match");
        else ImGui::TextColored(kMatchText, "Expected value matches %s", hit.c_str());
    } else if (!expected.empty() && normalize_hex(expected).empty()) {
        ImGui::TextColored(kErrColor, "Expected value is not hex");
    }

    if (have_result_) draw_results(mono, ui_scale, cb);
    ImGui::End();
}

}  // namespace hx
