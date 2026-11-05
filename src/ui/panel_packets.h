#pragma once
// "Packets" panel: the packet list of a pcap / pcapng document (core/pcap.h). Self-contained: it
// knows nothing about App; the host passes the active document, the parser names and callbacks.
//
//   * Indexing runs on a PcapIndexJob worker over a Snapshot (progress + Cancel). It starts by
//     itself the first time a document detected as a capture is drawn; "Index" re-runs it.
//   * Table # | Offset | Time | Len | Proto | Summary, virtualised with ImGuiListClipper; only the
//     visible rows are dissected (small cache). Time is relative to the first packet, or the UTC
//     time of day with "Absolute time" (the row tooltip has the date).
//   * Filter: case-insensitive substring of Proto / Summary, applied incrementally under a per-frame
//     time budget (millions of packets never freeze the UI).
//   * Row click (or Up / Down / Home / End / PageUp / PageDown while the panel is focused) selects
//     the packet's captured bytes in the hex view, or only its L7 payload with "Payload only". With
//     a parser chosen in "Parse with", the same range is also handed to cb.parse: stepping through
//     packets re-parses each one (the protocol-analysis loop).
// State (index, filter, selection, parser choice) is kept per document (by Document::id()); call
// forget() when a document is closed.
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/pcap.h"

struct ImFont;

namespace hx {

class Document;

struct PacketsPanelCallbacks {
    std::function<void(uint64_t offset, uint64_t len)> select;  // select [offset, offset+len) and reveal it
    // Run `parser` over [offset, offset+len) (e.g. the Structure panel's parse-at-offset).
    std::function<void(const std::string& parser, uint64_t offset, uint64_t len)> parse;
    std::function<void(const std::string& msg)> notify;         // short status-bar message
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

    // Draws the panel contents into the current window (the caller owns Begin/End). `doc` may be
    // null. Never mutates the document. `parser_names` fills the "Parse with" combo.
    void draw(Document* doc, const std::vector<std::string>& parser_names, const PacketsPanelCallbacks& cb);
    // Drops the state (and cancels the index) of a closed document.
    void forget(uint64_t doc_id);
    // (Re-)index the active document on the next draw() (e.g. from a palette action).
    void request_index() { index_requested_ = true; }
    // The last draw() had an index running or a filter in progress: keep drawing frames.
    bool wants_frames() const { return wants_frames_; }

    // True if `doc` looks like a capture (host: auto-show the panel for such documents).
    static bool is_capture(const Document& doc);

    // The last draw (for headless tests, tests/test_panels.cpp): screen position of the centre of
    // table row `row`'s "#" cell; false if that row was not drawn. The selected packet (0-based
    // index, SIZE_MAX = none) of document `doc_id`.
    bool row_pos(size_t row, float& x, float& y) const;
    size_t selected_packet(uint64_t doc_id) const;

private:
    struct DocState;
    DocState& state(uint64_t doc_id);
    std::map<uint64_t, std::unique_ptr<DocState>> docs_;
    bool index_requested_ = false;
    bool wants_frames_ = false;
    float rows_per_page_ = 20.0f;  // from the last table draw (PageUp / PageDown)
    struct DrawnRow {
        size_t row;
        float x, y;
    };
    std::vector<DrawnRow> drawn_;  // rows of the last table draw (row_pos)
};

}  // namespace hx
