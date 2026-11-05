#include "ui/panel_packets.h"

#include <algorithm>
#include <cfloat>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
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
constexpr size_t kSummaryRead = kFilterRead;  // bytes dissected for a table row / the filter
constexpr size_t kPayloadRead = 1u << 20;   // bytes dissected to locate a payload
constexpr size_t kCacheMax = 4096;          // dissected rows kept

std::string fmt_off(uint64_t v) { return "0x" + fmt_hex(v, 8); }

std::string fmt_count(uint64_t v) {
    std::string s = std::to_string(v);
    for (int i = int(s.size()) - 3; i > 0; i -= 3) s.insert(size_t(i), ",");
    return s;
}

const char* kFilterHelp =
    "Filter expression, e.g.  tcp.port == 80 and not ip.src == 10.0.0.0/8\n\n"
    "Fields: ip.src  ip.dst  ip.addr (IPv4 / IPv6, optional /prefix)\n"
    "        tcp.port  tcp.srcport  tcp.dstport  udp.port  udp.srcport  udp.dstport\n"
    "        frame.len  eth.type  proto (== tcp | udp | icmp | icmpv6 | arp | ip | ipv6)\n"
    "Operators: == != < > <= >=   and or not (&& || !)   ( )\n"
    "A protocol alone (tcp, not arp) and \"text\" (Proto / Summary substring) work too.\n"
    "ip.addr / tcp.port / udp.port mean either end (!= : neither end).";

// Wireshark-style conversation filter of a packet ("" = no IP addresses).
std::string conversation_filter(const PacketInfo& pi) {
    if (pi.ip_version == 0) return {};
    auto addr = [&](const uint8_t* a) { return pi.ip_version == 4 ? fmt_ipv4(a) : fmt_ipv6(a); };
    std::string f = "ip.addr == " + addr(pi.ip_src) + " and ip.addr == " + addr(pi.ip_dst);
    if (pi.has_ports && (pi.proto == "TCP" || pi.proto == "UDP")) {
        const std::string l = pi.proto == "TCP" ? "tcp" : "udp";
        f += " and " + l + ".port == " + std::to_string(pi.src_port) + " and " + l + ".port == " +
             std::to_string(pi.dst_port);
    }
    return f;
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
    // Filter: `filter` is the applied expression, filter_text the box (may hold an invalid one:
    // filter_err / filter_err_pos). matches are packet indices, ascending; filled incrementally on
    // the UI thread (tested = packets looked at) or all at once by filter_job (filter_async).
    std::string filter_text;
    PacketFilter filter;
    std::string filter_err;
    size_t filter_err_pos = 0;
    size_t tested = 0;
    std::vector<uint32_t> matches;
    bool filter_async = false;
    bool filter_done = true;
    PacketFilterJob filter_job;
    uint64_t filter_seen_gen = 0;
    bool reveal_selected = false;                 // scroll to the selected packet once filtered
    std::unordered_map<size_t, PacketInfo> cache;  // visible rows
    size_t selected = SIZE_MAX;                   // packet index
    size_t scroll_to = SIZE_MAX;                  // row to bring into view on this draw
    std::string parser;                           // "" = none (select only)

    void reset_filter(size_t sync_max) {
        tested = 0;
        matches.clear();
        filter_async = res && filtered() && packet_count() > sync_max;
        filter_done = !filtered() || !res;
        if (filter_async) filter_job.start(res, filter);
        else filter_job.cancel();
    }
    // The box changed: apply it if it parses, else keep the previous filter and remember the error.
    void set_filter_text(size_t sync_max) {
        PacketFilter f;
        if (!f.parse(filter_text, &filter_err, &filter_err_pos)) return;
        filter_err.clear();
        if (f.text() == filter.text() && f.empty() == filter.empty()) return;
        filter = std::move(f);
        reset_filter(sync_max);
    }
    bool filtered() const { return !filter.empty(); }
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
    // The selected packet, else the one whose record holds the document's caret; SIZE_MAX if none.
    size_t target_packet(const Document& doc) const {
        if (selected < packet_count()) return selected;
        if (!res) return SIZE_MAX;
        const ViewState& v = doc.view();
        const uint64_t off = v.has_selection() ? v.sel_begin() : v.cursor;
        const std::vector<Packet>& ps = res->index.packets;
        auto it = std::upper_bound(ps.begin(), ps.end(), off,
                                   [](uint64_t o, const Packet& p) { return o < p.record_off; });
        if (it == ps.begin()) return SIZE_MAX;
        --it;
        return off < it->data_off + it->cap_len ? size_t(it - ps.begin()) : SIZE_MAX;
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

void PacketsPanel::load_settings(const Settings& s) {
    absolute_time = s.packets_absolute_time;
    payload_only = s.packets_payload_only;
    follow_interleaved = s.packets_follow_interleaved;
}

bool PacketsPanel::save_settings(Settings& s) const {
    if (s.packets_absolute_time == absolute_time && s.packets_payload_only == payload_only &&
        s.packets_follow_interleaved == follow_interleaved)
        return false;
    s.packets_absolute_time = absolute_time;
    s.packets_payload_only = payload_only;
    s.packets_follow_interleaved = follow_interleaved;
    return true;
}

void PacketsPanel::save_extras(Document& doc) const {
    auto it = docs_.find(doc.id());
    const DocState* st = it != docs_.end() ? it->second.get() : nullptr;
    doc.set_extra("packets.filter", st ? st->filter_text : std::string());
    doc.set_extra("packets.parser", st ? st->parser : std::string());
}

void PacketsPanel::restore_extras(const Document& doc) {
    const std::string f = doc.extra("packets.filter"), parser = doc.extra("packets.parser");
    if (f.empty() && parser.empty()) return;
    DocState& st = state(doc.id());
    st.parser = parser;
    st.filter_text = f;
    st.set_filter_text(filter_sync_max);  // applied once the index is there (an invalid one shows its error)
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

bool PacketsPanel::filter_box_pos(float& x, float& y) const {
    if (filter_x_ < 0.0f) return false;
    x = filter_x_;
    y = filter_y_;
    return true;
}

std::string PacketsPanel::applied_filter(uint64_t doc_id) const {
    auto it = docs_.find(doc_id);
    return it == docs_.end() ? std::string() : it->second->filter.text();
}

std::string PacketsPanel::filter_error(uint64_t doc_id, size_t* pos) const {
    auto it = docs_.find(doc_id);
    if (it == docs_.end()) return {};
    if (pos) *pos = it->second->filter_err_pos;
    return it->second->filter_err;
}

size_t PacketsPanel::shown_rows(uint64_t doc_id) const {
    auto it = docs_.find(doc_id);
    if (it == docs_.end()) return 0;
    return it->second->filter_done ? it->second->rows() : SIZE_MAX;
}

void PacketsPanel::run_pending(Pending what, DocState& st, Document& doc, size_t pk, const PacketsPanelCallbacks& cb) {
    auto note = [&](const std::string& m) {
        if (cb.notify) cb.notify(m);
    };
    if (pk == SIZE_MAX) return note("Packets: select a packet first (or put the caret inside one)");
    const PcapIndexJob::Result& res = *st.res;
    const Packet& p = res.index.packets[pk];
    const std::string num = "#" + std::to_string(pk + 1);
    st.selected = pk;
    st.reveal_selected = true;
    const PacketInfo pi = dissect_packet(*res.snap, p, kPayloadRead);
    auto filter_conversation = [&]() {
        const std::string f = conversation_filter(pi);
        if (f.empty()) return false;
        st.filter_text = f;
        st.set_filter_text(filter_sync_max);
        return true;
    };
    switch (what) {
    case Pending::Follow:
        if (!pi.tcp_header || pi.fragment) return note("Follow TCP Stream: packet " + num + " is not a TCP packet");
        stream_job_.start(st.res, pk, follow_interleaved, stream_max);
        filter_conversation();
        return note("Following the TCP stream of packet " + num + "...");
    case Pending::Conversation:
        if (!filter_conversation()) note("Packet " + num + " has no IP addresses to filter on");
        return;
    case Pending::OpenPacket:
    case Pending::OpenPayload: {
        const bool payload = what == Pending::OpenPayload;
        const uint64_t pl = pi.payload_off < p.cap_len ? std::min<uint64_t>(pi.length, p.cap_len - pi.payload_off) : 0;
        const uint64_t off = payload ? p.data_off + pi.payload_off : p.data_off;
        const uint64_t len = payload ? pl : p.cap_len;
        if (len == 0) return note("Packet " + num + (payload ? " has no payload" : " has no captured bytes"));
        std::vector<Bookmark> marks;
        if (!payload && pl) {
            Bookmark b;
            b.offset = pi.payload_off;
            b.length = pl;
            b.name = pi.proto + " payload";
            marks.push_back(std::move(b));
        }
        std::vector<uint8_t> bytes(static_cast<size_t>(len));  // one packet: at most kPcapMaxRecord
        bytes.resize(res.snap->read(off, bytes.data(), bytes.size()));
        if (cb.open_tab) cb.open_tab(doc.display_name() + " " + num + (payload ? " payload" : ""), bytes, marks);
        return note("Packet " + num + (payload ? " payload" : "") + " opened as a read-only tab (" +
                    fmt_count(bytes.size()) + " bytes)");
    }
    case Pending::None: break;
    }
}

void PacketsPanel::draw(Document* doc, const std::vector<std::string>& parser_names, const PacketsPanelCallbacks& cb) {
    wants_frames_ = false;
    drawn_.clear();
    filter_x_ = filter_y_ = -1.0f;
    // ---- a followed TCP stream is ready: hand it over as a new tab ----
    if (stream_job_.generation() != stream_seen_gen_) {
        stream_seen_gen_ = stream_job_.generation();
        if (auto r = stream_job_.result()) {
            const std::string num = "#" + std::to_string(r->packet + 1);
            std::string msg;
            if (r->stream.cancelled) {
                msg = "Follow TCP Stream cancelled";
            } else if (!r->stream.error.empty()) {
                msg = "Follow TCP Stream: " + r->stream.error;
            } else if (r->doc.bytes.empty()) {
                msg = "The TCP stream of packet " + num + " has no payload (" + tcp_stream_summary(r->stream) + ")";
            } else {
                if (cb.open_tab) cb.open_tab(r->doc.name, r->doc.bytes, r->doc.bookmarks);
                msg = "TCP stream: " + tcp_stream_summary(r->stream);
                if (r->doc.bookmarks_capped)
                    msg += "; bookmarks for the first " + fmt_count(r->doc.bookmarks.size()) + " segments only";
            }
            if (cb.notify) cb.notify(msg);
        }
        stream_job_.clear_result();  // the bytes live in the new document now
    }
    if (stream_job_.running()) wants_frames_ = true;
    if (!doc) {
        pending_ = Pending::None;
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
        st.reset_filter(filter_sync_max);
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
    // ---- a requested action (palette / menus / buttons): needs the index ----
    if (pending_ != Pending::None) {
        if (!capture) {
            pending_ = Pending::None;
            if (cb.notify) cb.notify("Packets: this document is not a pcap / pcapng capture");
        } else if (st.res && !st.job.running()) {
            const Pending what = pending_;
            pending_ = Pending::None;
            run_pending(what, st, *doc, st.target_packet(*doc), cb);
        } else if (!st.job.running()) {
            pending_ = Pending::None;  // no index and none coming (e.g. the document is being saved)
        }
    }
    ImGui::SameLine();
    ImGui::Checkbox("Absolute time", &absolute_time);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("UTC time of day instead of seconds since the first packet (hover a row for the date)");
    ImGui::SameLine();
    ImGui::Checkbox("Payload only", &payload_only);
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
    if (ImGui::Button("Parse") && can_parse) activate(*st.res, st.selected, payload_only, st.parser, cb);
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::GetContentRegionAvail().x >= 260.0f * s) {
        ImGui::TextDisabled("|");
        ImGui::SameLine();
    } else {
        ImGui::NewLine();
    }
    const bool have_index = st.res && !running;
    ImGui::BeginDisabled(!have_index || stream_job_.running());
    if (ImGui::Button("Follow TCP Stream")) ImGui::OpenPopup("##follow");
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Reassemble the selected packet's TCP connection into a new tab\n"
                          "(one bookmark per segment: packet number and direction)");
    if (ImGui::BeginPopup("##follow")) {
        if (ImGui::MenuItem("Client -> server, then server -> client")) request_follow_stream(false);
        if (ImGui::MenuItem("Interleaved (in arrival order)")) request_follow_stream(true);
        ImGui::EndPopup();
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(!have_index);
    if (ImGui::Button("Open as Tab")) ImGui::OpenPopup("##open");
    ImGui::EndDisabled();
    if (ImGui::BeginPopup("##open")) {
        if (ImGui::MenuItem("Packet (frame bytes)")) request_open_packet(false);
        if (ImGui::MenuItem("Payload only")) request_open_packet(true);
        ImGui::Separator();
        if (ImGui::MenuItem("Filter this conversation")) request_conversation_filter();
        ImGui::EndPopup();
    }
    if (pending_ != Pending::None) wants_frames_ = true;  // runs on the next draw

    if (running) {
        wants_frames_ = true;
        char pct[32];
        std::snprintf(pct, sizeof pct, "Indexing %.0f%%", st.job.progress() * 100.0);
        ImGui::ProgressBar(float(st.job.progress()), ImVec2(-80.0f * s, 0.0f), pct);
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) st.job.cancel();
    }
    if (stream_job_.running()) {
        char pct[48];
        std::snprintf(pct, sizeof pct, "Following TCP stream %.0f%%", stream_job_.progress() * 100.0);
        ImGui::ProgressBar(float(stream_job_.progress()), ImVec2(-80.0f * s, 0.0f), pct);
        ImGui::SameLine();
        if (ImGui::Button("Cancel##stream")) stream_job_.cancel();
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
    if (ImGui::InputTextWithHint("##filter", "Filter: tcp.port == 80, ip.addr == 10.0.0.1 and not arp, \"text\" (hover: fields)",
                                 &st.filter_text))
        st.set_filter_text(filter_sync_max);
    {
        const ImVec2 r0 = ImGui::GetItemRectMin(), r1 = ImGui::GetItemRectMax();
        filter_x_ = (r0.x + r1.x) * 0.5f;
        filter_y_ = (r0.y + r1.y) * 0.5f;
        if (ImGui::IsItemHovered() && !ImGui::IsItemActive()) ImGui::SetTooltip("%s", kFilterHelp);
        if (!st.filter_err.empty()) {
            // Red frame + a red mark under the character the error points at.
            ImDrawList* dl = ImGui::GetWindowDrawList();
            const ImU32 red = ImGui::GetColorU32(kErrColor);
            dl->AddRect(r0, r1, red, ImGui::GetStyle().FrameRounding, 0, 1.0f);
            const std::string& t = st.filter_text;
            const size_t pos = std::min(st.filter_err_pos, t.size());
            const float x = r0.x + ImGui::GetStyle().FramePadding.x + ImGui::CalcTextSize(t.c_str(), t.c_str() + pos).x;
            const float w = pos < t.size() ? ImGui::CalcTextSize(t.c_str() + pos, t.c_str() + pos + 1).x : 0.0f;
            if (x < r1.x)
                dl->AddRectFilled(ImVec2(x, r1.y - 3.0f * s), ImVec2(std::min(r1.x, x + std::max(w, 6.0f * s)), r1.y), red);
            const std::string still = st.filtered() ? "; still showing: " + st.filter.text() : std::string();
            ImGui::TextColored(kErrColor, "%s (column %zu)%s", st.filter_err.c_str(), pos + 1, still.c_str());
        }
    }
    if (st.filter_async && !st.filter_done) {
        wants_frames_ = true;
        if (st.filter_job.generation() != st.filter_seen_gen) {
            st.filter_seen_gen = st.filter_job.generation();
            auto r = st.filter_job.result();
            // Only a run for this filter over this index (a finished run of the same filter over
            // the previous index may not have been seen before a re-index restarted it).
            if (r && !r->cancelled && r->text == st.filter.text() && r->index == st.res) {
                st.matches = r->matches;
                st.filter_done = true;
            }
        }
    } else if (st.filtered() && !st.filter_done) {
        wants_frames_ = true;
        const auto t0 = std::chrono::steady_clock::now();
        while (st.tested < packets.size()) {
            const size_t end = std::min(packets.size(), st.tested + 256);
            filter_packets(*res.snap, packets, st.filter, st.tested, end, st.matches);
            st.tested = end;
            const std::chrono::duration<double, std::milli> el = std::chrono::steady_clock::now() - t0;
            if (el.count() >= filter_budget_ms) break;
        }
        if (st.tested >= packets.size()) st.filter_done = true;
    }
    if (st.reveal_selected && st.filter_done) {
        st.reveal_selected = false;
        st.scroll_to = st.selected == SIZE_MAX ? SIZE_MAX : st.row_of(st.selected);
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
    if (!st.filter_done) {
        const double f = st.filter_async ? st.filter_job.progress()
                                         : double(st.tested) / double(std::max<size_t>(1, packets.size()));
        ImGui::SameLine();
        ImGui::TextDisabled("(filtering %.0f%%)", 100.0 * f);
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
            activate(res, st.selected, payload_only, st.parser, cb);
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
                activate(res, i, payload_only, st.parser, cb);
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
            if (ImGui::BeginPopupContextItem("##row")) {
                st.selected = i;  // the actions below run on the next draw (they may change the rows)
                const bool tcp = pi.tcp_header && !pi.fragment;
                if (ImGui::MenuItem("Follow TCP Stream", nullptr, false, tcp)) request_follow_stream(false);
                if (ImGui::MenuItem("Follow TCP Stream (interleaved)", nullptr, false, tcp)) request_follow_stream(true);
                ImGui::Separator();
                if (ImGui::MenuItem("Open Packet as Tab")) request_open_packet(false);
                if (ImGui::MenuItem("Open Payload as Tab", nullptr, false, pi.length > 0)) request_open_packet(true);
                if (ImGui::MenuItem("Filter Conversation", nullptr, false, pi.ip_version != 0))
                    request_conversation_filter();
                ImGui::EndPopup();
            }
            ImGui::PopID();
            ImGui::TableSetColumnIndex(1);
            if (mono) ImGui::PushFont(mono, 0.0f);
            ImGui::TextUnformatted(fmt_off(p.record_off).c_str());
            ImGui::TableSetColumnIndex(2);
            if (p.ts_ns == kNoTimestamp) ImGui::TextDisabled("-");
            else if (absolute_time) ImGui::TextUnformatted(fmt_pcap_abstime(p.ts_ns, ix.time_decimals).substr(11).c_str());
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
