#pragma once
// TCP stream reassembly over a packet index (core/pcap.h): "Follow TCP Stream" of the Packets panel.
//
// The connection is the 4-tuple of the chosen packet (both directions; VLAN tags ignored). Every
// packet of it is processed in capture order like a receiver would: per direction the next expected
// sequence number (32-bit sequence numbers are unwrapped to 64 bits, so a wraparound is seamless),
// bytes already delivered are dropped (retransmissions, overlaps), segments ahead of a gap wait in
// an out-of-order queue and are delivered once the gap closes. A gap the capture never fills is
// skipped when the peer acknowledges past it, else at the end of the capture (TcpStreamSegment::
// gap_before counts the missing bytes). SYN and FIN take one sequence number each; a SYN's data
// (TCP Fast Open) starts after it. RST only ends the connection. No window / urgent handling, no
// checksum checks. A new SYN after the connection closed starts the next connection on the same
// ports: before the chosen packet it resets the reassembly, after it ends it.
// The client is the side that sent the SYN (or got the SYN+ACK), else the sender of the first
// packet seen. Only references into the capture are kept while scanning; the bytes are read when
// the document is built, capped at max_bytes (TcpStream::truncated).
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "core/document.h"
#include "core/pcap.h"
#include "core/pcap_job.h"

namespace hx {

struct TcpEndpoint {
    uint8_t ip_version = 0;  // 4 / 6
    uint8_t addr[16] = {};   // IPv4: the first 4 bytes
    uint16_t port = 0;
    bool operator==(const TcpEndpoint& o) const;
};
std::string fmt_endpoint(const TcpEndpoint& e);  // "10.0.0.1:80", "[2001:db8::1]:443"

struct TcpStreamSegment {
    size_t packet = 0;       // index into the capture's packets
    uint8_t dir = 0;         // 0 = client -> server, 1 = server -> client
    uint64_t data_off = 0;   // capture offset of the delivered bytes
    uint64_t len = 0;
    uint64_t stream_off = 0; // offset in its direction's byte stream (0 = first byte after the SYN)
    uint64_t gap_before = 0; // bytes missing from the capture right before this segment
};

constexpr uint64_t kTcpStreamMax = 256ull << 20;  // bytes of a followed stream (both directions)

struct TcpStream {
    TcpEndpoint client, server;
    std::vector<TcpStreamSegment> segments;  // delivery order = the interleaved order
    uint64_t bytes[2] = {};       // delivered per direction
    uint64_t missing[2] = {};     // never captured (skipped gaps)
    size_t packets = 0;           // packets of the connection
    size_t retransmitted = 0;     // segments that brought no new bytes
    size_t out_of_order = 0;      // segments that arrived ahead of a gap
    bool syn[2] = {}, fin[2] = {}, rst = false;
    bool truncated = false;       // stopped at max_bytes
    bool cancelled = false;
    std::string error;            // "" = ok
};

// Blocking. Reassembles the connection of packets[packet] (which must be a TCP packet).
// `done` (if non-null) counts the packets processed.
bool follow_tcp_stream(const Snapshot& snap, const std::vector<Packet>& packets, size_t packet, TcpStream& out,
                       uint64_t max_bytes = kTcpStreamMax, const std::atomic<bool>* cancel = nullptr,
                       std::atomic<uint64_t>* done = nullptr);

// The bytes of a followed stream for a new document, with one bookmark per segment ("#12 C>S",
// note: packet, direction, endpoints, stream offset, gap) coloured by direction.
//   interleaved = false: client -> server bytes, then server -> client
//   interleaved = true:  both directions in delivery order (the bookmarks mark the direction)
constexpr size_t kTcpStreamMaxBookmarks = 10000;
struct TcpStreamDoc {
    std::string name;             // "TCP 10.0.0.1:51000 > 10.0.0.2:80" (+ " interleaved")
    std::vector<uint8_t> bytes;
    std::vector<Bookmark> bookmarks;
    bool bookmarks_capped = false;  // more than max_bookmarks segments: the rest have none
};
void build_tcp_stream_doc(const Snapshot& snap, const TcpStream& s, bool interleaved, TcpStreamDoc& out,
                          size_t max_bookmarks = kTcpStreamMaxBookmarks);
// "1,234 B client -> server, 56 B back, 12 segments, 1 retransmitted ..." (status line).
std::string tcp_stream_summary(const TcpStream& s);

// Background follow + build (the Packets panel).
struct TcpStreamJobResult {
    TcpStream stream;
    TcpStreamDoc doc;
    size_t packet = 0;
    bool interleaved = false;
};
class TcpStreamJob {
public:
    void start(std::shared_ptr<const PcapIndexJob::Result> index, size_t packet, bool interleaved,
               uint64_t max_bytes = kTcpStreamMax);
    void cancel() { w_.cancel(); }
    bool running() const { return w_.running(); }
    double progress() const { return w_.progress(); }
    uint64_t generation() const { return w_.generation(); }
    std::shared_ptr<const TcpStreamJobResult> result() const { return w_.result(); }
    void clear_result() { w_.clear_result(); }

private:
    PcapWorker<TcpStreamJobResult> w_;
};

}  // namespace hx
