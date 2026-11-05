#include "ui/panel_packets.h"

#include <algorithm>
#include <cfloat>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

#include "imgui.h"
#include "misc/cpp/imgui_stdlib.h"

#include "core/document.h"
#include "core/util.h"

namespace hx {

namespace {

const ImVec4 kWarnColor(1.0f, 0.78f, 0.35f, 1.0f);
const ImVec4 kErrColor(1.0f, 0.42f, 0.42f, 1.0f);
constexpr size_t kSummaryRead = 2048;       // bytes dissected for a table row / the filter
constexpr size_t kPayloadRead = 1u << 20;   // bytes dissected to locate a payload
constexpr size_t kCacheMax = 4096;          // dissected rows kept

std::string fmt_off(uint64_t v) { return "0x" + fmt_hex(v, 8); }

std::string fmt_count(uint64_t v) {
    std::string s = std::to_string(v);
    for (int i = int(s.size()) - 3; i > 0; i -= 3) s.insert(size_t(i), ",");
    return s;
}

std::string lower(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    return s;
}

ImVec4 proto_color(const std::string& p) {
    if (p == "TCP") return ImVec4(0.55f, 0.75f, 1.0f, 1.0f);
    if (p == "UDP") return ImVec4(0.55f, 0.9f, 0.6f, 1.0f);
    if (p == "ICMP" || p == "ICMPv6") return ImVec4(0.95f, 0.7f, 1.0f, 1.0f);
    if (p == "ARP") return ImVec4(1.0f, 0.85f, 0.5f, 1.0f);
    return ImGui::GetStyleColorVec4(ImGuiCol_Text);
}

}  // namespace

struct PacketsPanel::DocState {
    PcapIndexJob job;
    uint64_t seen_gen = 0;
    uint64_t pending_doc_gen = 0;                 // document generation when the running index started
    std::shared_ptr<const PcapIndexJob::Result> res;
    uint64_t res_doc_gen = 0;
    bool auto_started = false;
    int64_t first_ts = 0;                         // time base of the "relative" column
    // Filter (incremental): needle is lower-cased; matches are packet indices, ascending.
    std::string filter_text, needle;
    size_t tested = 0;
    std::vector<uint32_t> matches;
    std::unordered_map<size_t, PacketInfo> cache;  // visible rows
    size_t selected = SIZE_MAX;                   // packet index
    size_t scroll_to = SIZE_MAX;                  // row to bring into view on this draw
    bool absolute_time = false;
    bool payload_only = false;
    std::string parser;                           // "" = none (select only)

    void reset_filter() {
        needle = lower(filter_text);
        tested = 0;
        matches.clear();
    }
    bool filtered() const { return !needle.empty(); }
    size_t packet_count() const { return res ? res->index.packets.size() : 0; }
    size_t rows() const { return filtered() ? matches.size() : packet_count(); }
    size_t packet_at(size_t row) const { return filtered() ? matches[row] : row; }
    // Row showing packet `idx`, or SIZE_MAX when filtered out.
    size_t row_of(size_t idx) const {
        if (!filtered()) return idx < packet_count() ? idx : SIZE_MAX;
        auto it = std::lower_bound(matches.begin(), matches.end(), uint32_t(std::min<size_t>(idx, UINT32_MAX)));
        return it != matches.end() && *it == idx ? size_t(it - matches.begin()) : SIZE_MAX;
    }
    const PacketInfo& info(size_t idx) {
        auto it = cache.find(idx);
        if (it != cache.end()) return it->second;
        if (cache.size() >= kCacheMax) cache.clear();
        return cache.emplace(idx, dissect_packet(*res->snap, res->index.packets[idx], kSummaryRead)).first->second;
    }
};

PacketsPanel::PacketsPanel() = default;
PacketsPanel::~PacketsPanel() = default;

bool PacketsPanel::is_capture(const Document& doc) { return pcap_detect(doc) != CaptureFormat::None; }

PacketsPanel::DocState& PacketsPanel::state(uint64_t doc_id) {
    auto& p = docs_[doc_id];
    if (!p) p = std::make_unique<DocState>();
    return *p;
}

void PacketsPanel::forget(uint64_t doc_id) {
    auto it = docs_.find(doc_id);
    if (it == docs_.end()) return;
    it->second->job.cancel();
    docs_.erase(it);  // the job's destructor joins its worker (it stops at the next record)
}

namespace {

// Selects (and optionally parses) packet `idx`: its captured bytes, or only the L7 payload.
void activate(const PcapIndexJob::Result& res, size_t idx, bool payload_only, const std::string& parser,
              const PacketsPanelCallbacks& cb) {
    const Packet& p = res.index.packets[idx];
    uint64_t off = p.data_off, len = p.cap_len;
    if (payload_only) {
        const PacketInfo pi = dissect_packet(*res.snap, p, kPayloadRead);
        off = p.data_off + pi.payload_off;
        len = pi.payload_len;
        if (p.cap_len > kPayloadRead)  // only the first kPayloadRead bytes were looked at
            len = std::min<uint64_t>(pi.length, p.cap_len - pi.payload_off);
    }
    if (cb.select) cb.select(off, len);
    if (parser.empty() || !cb.parse) return;
    if (len == 0) {
        if (cb.notify) cb.notify("Packet #" + std::to_string(idx + 1) + " has no payload to parse");
        return;
    }
    cb.parse(parser, off, len);
}

}  // namespace

bool PacketsPanel::row_pos(size_t row, float& x, float& y) const {
    for (const DrawnRow& r : drawn_)
        if (r.row == row) {
            x = r.x;
            y = r.y;
            return true;
        }
    return false;
}

size_t PacketsPanel::selected_packet(uint64_t doc_id) const {
    auto it = docs_.find(doc_id);
    return it == docs_.end() ? SIZE_MAX : it->second->selected;
}

void PacketsPanel::draw(Document* doc, const std::vector<std::string>& parser_names, const PacketsPanelCallbacks& cb) {
    wants_frames_ = false;
    drawn_.clear();
    if (!doc) {
        index_requested_ = false;
        ImGui::TextDisabled("No document open.");
        return;
    }
    DocState& st = state(doc->id());
    const float s = ui_scale;
    const bool capture = is_capture(*doc);

    // ---- pick up a finished index ----
    if (st.job.generation() != st.seen_gen) {
        st.seen_gen = st.job.generation();
        st.res = st.job.result();
        st.res_doc_gen = st.pending_doc_gen;
        st.selected = SIZE_MAX;
        st.cache.clear();
        st.reset_filter();
        st.first_ts = 0;
        if (st.res) {
            for (const Packet& p : st.res->index.packets)
                if (p.ts_ns != kNoTimestamp) {
                    st.first_ts = p.ts_ns;
                    break;
                }
            if (cb.notify) {
                const auto& ix = st.res->index;
                std::string msg = "Packets: " + fmt_count(ix.packets.size()) + (ix.truncated ? "+" : "") + " indexed";
                if (ix.cancelled) msg += " (cancelled)";
                if (ix.error) msg += " (" + ix.error_msg + " at " + fmt_off(ix.error_offset) + ")";
                cb.notify(msg);
            }
        }
    }

    // ---- index controls ----
    bool start = index_requested_ && capture && !doc->busy();
    index_requested_ = false;
    if (!st.auto_started && capture && !doc->busy() && !st.res && !st.job.running()) start = true;
    const bool running = st.job.running();
    ImGui::BeginDisabled(doc->busy() || !capture);
    if (ImGui::Button(running ? "Re-index###index" : "Index###index")) start = true;
    ImGui::EndDisabled();
    if (doc->busy() && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Document is being saved...");
    if (start) {
        st.auto_started = true;
        st.pending_doc_gen = doc->generation();
        st.job.start(doc->snapshot(), max_packets);
    }
    ImGui::SameLine();
    ImGui::Checkbox("Absolute time", &st.absolute_time);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("UTC time of day instead of seconds since the first packet (hover a row for the date)");
    ImGui::SameLine();
    ImGui::Checkbox("Payload only", &st.payload_only);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Select / parse only the L7 payload (after the TCP / UDP / ... header)");

    // ---- parser (same row when the panel is wide enough, e.g. docked at the bottom) ----
    ImGui::SameLine();
    if (ImGui::GetContentRegionAvail().x >= 400.0f * s) {
        ImGui::TextDisabled("|");
        ImGui::SameLine();
    } else {
        ImGui::NewLine();
    }
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Parse with");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200.0f * s);
    if (ImGui::BeginCombo("##parser", st.parser.empty() ? "(none: select only)" : st.parser.c_str())) {
        if (ImGui::Selectable("(none: select only)", st.parser.empty())) st.parser.clear();
        for (const std::string& n : parser_names)
            if (ImGui::Selectable(n.c_str(), st.parser == n)) st.parser = n;
        ImGui::EndCombo();
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Clicking a packet (or Up / Down) also runs this parser over its bytes");
    ImGui::SameLine();
    const bool can_parse = st.res && st.selected < st.packet_count() && !st.parser.empty();
    ImGui::BeginDisabled(!can_parse);
    if (ImGui::Button("Parse") && can_parse) activate(*st.res, st.selected, st.payload_only, st.parser, cb);
    ImGui::EndDisabled();

    if (running) {
        wants_frames_ = true;
        char pct[32];
        std::snprintf(pct, sizeof pct, "Indexing %.0f%%", st.job.progress() * 100.0);
        ImGui::ProgressBar(float(st.job.progress()), ImVec2(-80.0f * s, 0.0f), pct);
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) st.job.cancel();
    }

    if (!st.res) {
        if (!capture) ImGui::TextDisabled("This document is not a pcap / pcapng capture.");
        else if (!running) ImGui::TextDisabled("Press Index to list the packets.");
        return;
    }
    const PcapIndexJob::Result& res = *st.res;
    const PcapIndexResult& ix = res.index;
    const std::vector<Packet>& packets = ix.packets;

    // ---- filter ----
    ImGui::SetNextItemWidth(-FLT_MIN);
    if (ImGui::InputTextWithHint("##filter", "Filter: protocol or summary (case-insensitive substring)", &st.filter_text))
        st.reset_filter();
    if (st.filtered() && st.tested < packets.size()) {
        wants_frames_ = true;
        const auto t0 = std::chrono::steady_clock::now();
        while (st.tested < packets.size()) {
            for (int k = 0; k < 256 && st.tested < packets.size(); ++k, ++st.tested) {
                const PacketInfo pi = dissect_packet(*res.snap, packets[st.tested], kSummaryRead);
                if (lower(pi.proto).find(st.needle) != std::string::npos ||
                    lower(pi.summary).find(st.needle) != std::string::npos)
                    st.matches.push_back(uint32_t(st.tested));
            }
            const std::chrono::duration<double, std::milli> el = std::chrono::steady_clock::now() - t0;
            if (el.count() >= filter_budget_ms) break;
        }
    }

    // ---- summary ----
    std::string line = std::string(capture_format_name(ix.format)) + ": " +
                       (st.filtered() ? fmt_count(st.matches.size()) + " of " : std::string()) +
                       fmt_count(packets.size()) + (ix.truncated ? "+" : "") + " packets";
    if (ix.interfaces.size() == 1) {
        const char* ln = linktype_name(ix.interfaces[0].linktype);
        line += *ln ? std::string(", ") + ln : ", link type " + std::to_string(ix.interfaces[0].linktype);
    } else if (ix.interfaces.size() > 1) {
        line += ", " + std::to_string(ix.interfaces.size()) + " interfaces";
    }
    ImGui::TextUnformatted(line.c_str());
    if (st.filtered() && st.tested < packets.size()) {
        ImGui::SameLine();
        ImGui::TextDisabled("(filtering %.0f%%)", 100.0 * double(st.tested) / double(packets.size()));
    }
    if (ix.truncated) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(stopped at %s packets)", fmt_count(max_packets).c_str());
    }
    if (ix.cancelled) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(cancelled)");
    }
    if (ix.error) {
        ImGui::SameLine();
        ImGui::TextColored(kErrColor, "(%s at %s)", ix.error_msg.c_str(), fmt_off(ix.error_offset).c_str());
        ImGui::SameLine();
        if (ImGui::SmallButton("Show") && cb.select) cb.select(ix.error_offset, 0);
    }
    if (st.res_doc_gen != doc->generation()) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(document changed since indexing)");
    }

    // ---- keyboard: step through the (filtered) packets ----
    const size_t rows = st.rows();
    if (rows > 0 && ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput) {
        const size_t cur = st.selected == SIZE_MAX ? SIZE_MAX : st.row_of(st.selected);
        const size_t page = size_t(std::max(1.0f, rows_per_page_ - 1.0f));
        size_t next = SIZE_MAX;
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) next = cur == SIZE_MAX ? 0 : std::min(cur + 1, rows - 1);
        else if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) next = cur == SIZE_MAX ? 0 : (cur ? cur - 1 : 0);
        else if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) next = cur == SIZE_MAX ? 0 : std::min(cur + page, rows - 1);
        else if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) next = cur == SIZE_MAX ? 0 : (cur > page ? cur - page : 0);
        else if (ImGui::IsKeyPressed(ImGuiKey_Home, false)) next = 0;
        else if (ImGui::IsKeyPressed(ImGuiKey_End, false)) next = rows - 1;
        if (next != SIZE_MAX && next != cur) {
            st.selected = st.packet_at(next);
            st.scroll_to = next;
            activate(res, st.selected, st.payload_only, st.parser, cb);
        }
    }

    // ---- table ----
    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_Resizable;
    if (!ImGui::BeginTable("##packets", 6, flags)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 70.0f * s);
    ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 110.0f * s);
    ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 160.0f * s);
    ImGui::TableSetupColumn("Len", ImGuiTableColumnFlags_WidthFixed, 70.0f * s);
    ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 70.0f * s);
    ImGui::TableSetupColumn("Summary", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    ImGuiListClipper clip;
    clip.Begin(int(std::min<size_t>(rows, size_t(INT_MAX))));
    if (st.scroll_to < rows) clip.IncludeItemByIndex(int(st.scroll_to));
    char buf[64];
    while (clip.Step()) {
        for (int row = clip.DisplayStart; row < clip.DisplayEnd; ++row) {
            const size_t i = st.packet_at(size_t(row));
            const Packet& p = packets[i];
            const PacketInfo& pi = st.info(i);
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(row);
            std::snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(i + 1));
            if (ImGui::Selectable(buf, st.selected == i, ImGuiSelectableFlags_SpanAllColumns)) {
                st.selected = i;
                activate(res, i, st.payload_only, st.parser, cb);
            }
            {
                const ImVec2 r0 = ImGui::GetItemRectMin(), r1 = ImGui::GetItemRectMax();
                drawn_.push_back(DrawnRow{size_t(row), r0.x + 10.0f * s, (r0.y + r1.y) * 0.5f});
            }
            if (ImGui::IsItemHovered() && ImGui::BeginTooltip()) {
                ImGui::Text("Record at %s, data at %s", fmt_off(p.record_off).c_str(), fmt_off(p.data_off).c_str());
                ImGui::Text("Captured %u of %u bytes", p.cap_len, p.orig_len);
                if (p.ts_ns != kNoTimestamp) ImGui::Text("%s UTC", fmt_pcap_abstime(p.ts_ns, ix.time_decimals).c_str());
                if (p.iface < ix.interfaces.size()) {
                    const CaptureInterface& ifc = ix.interfaces[p.iface];
                    const char* ln = linktype_name(ifc.linktype);
                    ImGui::Text("Interface %u%s%s (%s)", ifc.local_id, ifc.name.empty() ? "" : ": ", ifc.name.c_str(),
                                *ln ? ln : ("link type " + std::to_string(ifc.linktype)).c_str());
                }
                if (pi.length || pi.payload_len)
                    ImGui::Text("Payload at +%llu, %llu bytes", static_cast<unsigned long long>(pi.payload_off),
                                static_cast<unsigned long long>(pi.length));
                ImGui::EndTooltip();
            }
            ImGui::PopID();
            ImGui::TableSetColumnIndex(1);
            if (mono) ImGui::PushFont(mono, 0.0f);
            ImGui::TextUnformatted(fmt_off(p.record_off).c_str());
            ImGui::TableSetColumnIndex(2);
            if (p.ts_ns == kNoTimestamp) ImGui::TextDisabled("-");
            else if (st.absolute_time) ImGui::TextUnformatted(fmt_pcap_abstime(p.ts_ns, ix.time_decimals).substr(11).c_str());
            else ImGui::TextUnformatted(fmt_pcap_reltime(int64_t(uint64_t(p.ts_ns) - uint64_t(st.first_ts)), ix.time_decimals).c_str());
            if (mono) ImGui::PopFont();
            ImGui::TableSetColumnIndex(3);
            if (p.cap_len == p.orig_len) std::snprintf(buf, sizeof buf, "%u", p.cap_len);
            else std::snprintf(buf, sizeof buf, "%u/%u", p.cap_len, p.orig_len);
            ImGui::TextUnformatted(buf);
            ImGui::TableSetColumnIndex(4);
            ImGui::TextColored(proto_color(pi.proto), "%s", pi.proto.c_str());
            ImGui::TableSetColumnIndex(5);
            if (mono) ImGui::PushFont(mono, 0.0f);
            if (pi.malformed) ImGui::TextColored(kErrColor, "%s", pi.summary.c_str());
            else ImGui::TextUnformatted(pi.summary.c_str());
            if (mono) ImGui::PopFont();
        }
    }
    // Keep the row picked by the keyboard in view (frozen header row ~ one row high).
    const float h = clip.ItemsHeight;
    if (h > 0.0f) {
        const float view_h = ImGui::GetWindowHeight();
        rows_per_page_ = std::max(1.0f, view_h / h - 1.0f);
        if (st.scroll_to < rows) {
            const float top = float(double(st.scroll_to) * double(h));
            const float y = ImGui::GetScrollY();
            if (y > top) ImGui::SetScrollY(top);
            else if (y < top + 2.0f * h - view_h) ImGui::SetScrollY(top + 2.0f * h - view_h);
        }
    }
    st.scroll_to = SIZE_MAX;
    ImGui::EndTable();
}

}  // namespace hx
