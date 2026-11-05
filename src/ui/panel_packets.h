#pragma once
// "Packets" panel: the packet list of a pcap / pcapng document (core/pcap.h). Self-contained: it
// knows nothing about App; the host passes the active document, the parser names and callbacks.
//
//   * Indexing runs on a PcapIndexJob worker over a Snapshot (progress + Cancel). It starts by
//     itself the first time a document detected as a capture is drawn; "Index" re-runs it.
//   * Table # | Offset | Time | Len | Proto | Summary, virtualised with ImGuiListClipper; only the
//     visible rows are dissected (small cache). Time is relative to the first packet, or the UTC
//     time of day with "Absolute time" (the row tooltip has the date).
//   * Filter: an expression (core/pcap_filter.h: ip.src == 10.0.0.1 and not tcp.port == 22, "text",
//     ...), re-applied on every edit. An invalid one is marked in red at its error position and the
//     previous filter stays. Up to filter_sync_max packets it runs on the UI thread under a
//     per-frame time budget, above on a PacketFilterJob worker (millions never freeze the UI).
//   * Follow TCP Stream (toolbar, row context menu, request_follow_stream): reassembles the selected
//     packet's connection on a TcpStreamJob worker (core/pcap_stream.h) and hands the bytes (client
//     -> server then server -> client, or interleaved) with one bookmark per segment to
//     cb.open_tab; the capture's list is filtered to that conversation. Open Packet / Payload as Tab
//     hands one packet's bytes over the same way. Actions without a selected row use the packet
//     under the document's caret, and wait for the index if it is still running.
//   * Row click (or Up / Down / Home / End / PageUp / PageDown while the panel is focused) selects
//     the packet's captured bytes in the hex view, or only its L7 payload with "Payload only". With
//     a parser chosen in "Parse with", the same range is also handed to cb.parse: stepping through
//     packets re-parses each one (the protocol-analysis loop).
// State (index, filter, selection, parser choice) is kept per document (by Document::id()); call
// forget() when a document is closed. Absolute time / Payload only apply to every document.
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/pcap.h"
#include "core/pcap_filter.h"
#include "core/pcap_stream.h"

struct ImFont;

namespace hx {

class Document;
struct Settings;

struct PacketsPanelCallbacks {
    std::function<void(uint64_t offset, uint64_t len)> select;  // select [offset, offset+len) and reveal it
    // Run `parser` over [offset, offset+len) (e.g. the Structure panel's parse-at-offset).
    std::function<void(const std::string& parser, uint64_t offset, uint64_t len)> parse;
    std::function<void(const std::string& msg)> notify;         // short status-bar message
    // Open `bytes` as a new read-only tab named `name` with these bookmarks (its initial state).
    std::function<void(const std::string& name, const std::vector<uint8_t>& bytes,
                       const std::vector<Bookmark>& bookmarks)> open_tab;
};

struct PacketsPanel {
    PacketsPanel();
    ~PacketsPanel();
    PacketsPanel(const PacketsPanel&) = delete;
    PacketsPanel& operator=(const PacketsPanel&) = delete;

    ImFont* mono = nullptr;       // font for offsets / addresses (nullptr = current font)
    float ui_scale = 1.0f;        // column widths
    double filter_budget_ms = 4.0;  // time the incremental filter may use per draw()
    size_t max_packets = kPcapMaxPackets;
    size_t filter_sync_max = kFilterSyncMax;  // more packets than this: the filter runs on a worker
    uint64_t stream_max = kTcpStreamMax;      // bytes of a followed TCP stream
    bool follow_interleaved = false;          // the last Follow TCP Stream choice (palette actions)
    bool absolute_time = false;               // Time column: UTC time of day (else relative)
    bool payload_only = false;                // a row selects / parses only its L7 payload

    // Absolute time / Payload only / follow_interleaved <-> settings.ini (Settings::packets_*):
    // load_settings at startup; save_settings writes them back, true when one changed.
    void load_settings(const Settings& s);
    bool save_settings(Settings& s) const;
    // Per-document choices <-> Document extras (hot exit): "packets.filter" = the filter box,
    // "packets.parser" = the "Parse with" parser ("" erases). restore_extras applies the filter
    // as typed (it filters once the capture is indexed); a no-op for a document without them.
    void save_extras(Document& doc) const;
    void restore_extras(const Document& doc);

    // Draws the panel contents into the current window (the caller owns Begin/End). `doc` may be
    // null. Never mutates the document. `parser_names` fills the "Parse with" combo.
    void draw(Document* doc, const std::vector<std::string>& parser_names, const PacketsPanelCallbacks& cb);
    // Drops the state (and cancels the index) of a closed document.
    void forget(uint64_t doc_id);
    // (Re-)index the active document on the next draw() (e.g. from a palette action).
    void request_index() { index_requested_ = true; }
    // Act on the selected packet (else the one under the caret) of the active document on the next
    // draw that has its index.
    void request_follow_stream(bool interleaved) {
        pending_ = Pending::Follow;
        follow_interleaved = interleaved;
    }
    void request_open_packet(bool payload) { pending_ = payload ? Pending::OpenPayload : Pending::OpenPacket; }
    void request_conversation_filter() { pending_ = Pending::Conversation; }
    // The last draw() had an index running or a filter in progress: keep drawing frames.
    bool wants_frames() const { return wants_frames_; }

    // True if `doc` looks like a capture (host: auto-show the panel for such documents).
    static bool is_capture(const Document& doc);

    // The last draw (for headless tests, tests/test_panels.cpp): screen position of the centre of
    // table row `row`'s "#" cell; false if that row was not drawn. The selected packet (0-based
    // index, SIZE_MAX = none) of document `doc_id`.
    bool row_pos(size_t row, float& x, float& y) const;
    size_t selected_packet(uint64_t doc_id) const;
    // Centre of the filter box; the applied filter, the error of the text in the box ("" = none) and
    // its byte position; the table's rows (SIZE_MAX while the filter is still running).
    bool filter_box_pos(float& x, float& y) const;
    std::string applied_filter(uint64_t doc_id) const;
    std::string filter_error(uint64_t doc_id, size_t* pos = nullptr) const;
    size_t shown_rows(uint64_t doc_id) const;
    bool stream_running() const { return stream_job_.running(); }

private:
    struct DocState;
    DocState& state(uint64_t doc_id);
    std::map<uint64_t, std::unique_ptr<DocState>> docs_;
    bool index_requested_ = false;
    enum class Pending : uint8_t { None, Follow, OpenPacket, OpenPayload, Conversation };
    Pending pending_ = Pending::None;
    void run_pending(Pending what, DocState& st, Document& doc, size_t packet, const PacketsPanelCallbacks& cb);
    TcpStreamJob stream_job_;
    uint64_t stream_seen_gen_ = 0;
    float filter_x_ = -1.0f, filter_y_ = -1.0f;
    bool wants_frames_ = false;
    float rows_per_page_ = 20.0f;  // from the last table draw (PageUp / PageDown)
    struct DrawnRow {
        size_t row;
        float x, y;
    };
    std::vector<DrawnRow> drawn_;  // rows of the last table draw (row_pos)
};

}  // namespace hx
