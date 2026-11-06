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
//
// Follow UDP Stream: the datagrams of the chosen packet's 4-tuple (both directions), each one a
// segment in capture order (no reassembly, no sequence numbers); the client is the sender of the
// first datagram. Same TcpStream / document / job types (TcpStream::udp). IP fragments are skipped
// by both (no fragment reassembly).
//
// Conversations ("Stream" column of the Packets panel): TCP and UDP packets with the same address /
// port pair (both directions, VLAN ignored) get one number, per protocol in order of first
// appearance from 0 (like Wireshark's tcp.stream / udp.stream, without its split at a port reuse).
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
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
    bool udp = false;             // follow_udp_stream: one segment per datagram
    std::string error;            // "" = ok
};

// Blocking. Reassembles the connection of packets[packet] (which must be a TCP packet).
// `done` (if non-null) counts the packets processed.
bool follow_tcp_stream(const Snapshot& snap, const std::vector<Packet>& packets, size_t packet, TcpStream& out,
                       uint64_t max_bytes = kTcpStreamMax, const std::atomic<bool>* cancel = nullptr,
                       std::atomic<uint64_t>* done = nullptr);
// Blocking. The datagrams of packets[packet]'s UDP conversation (it must be a UDP packet that is
// not an IP fragment), both directions in capture order; empty datagrams count as packets only.
bool follow_udp_stream(const Snapshot& snap, const std::vector<Packet>& packets, size_t packet, TcpStream& out,
                       uint64_t max_bytes = kTcpStreamMax, const std::atomic<bool>* cancel = nullptr,
                       std::atomic<uint64_t>* done = nullptr);

// The bytes of a followed stream for a new document, with one bookmark per segment ("#12 C>S",
// note: packet, direction, endpoints, stream offset, gap) coloured by direction.
//   interleaved = false: client -> server bytes, then server -> client
//   interleaved = true:  both directions in delivery order (the bookmarks mark the direction)
constexpr size_t kTcpStreamMaxBookmarks = 10000;
struct TcpStreamDoc {
    std::string name;             // "TCP 10.0.0.1:51000 > 10.0.0.2:80" (+ " (interleaved)"; "UDP ...")
    std::vector<uint8_t> bytes;
    std::vector<Bookmark> bookmarks;
    bool bookmarks_capped = false;  // more than max_bookmarks segments: the rest have none
};
void build_tcp_stream_doc(const Snapshot& snap, const TcpStream& s, bool interleaved, TcpStreamDoc& out,
                          size_t max_bookmarks = kTcpStreamMaxBookmarks);
// "1,234 bytes client -> server, 56 bytes server -> client, 12 segments of 15 packets, 1
// retransmitted ..." (status line); UDP: "..., 7 datagrams".
std::string tcp_stream_summary(const TcpStream& s);

// Background follow + build (the Packets panel); `udp`: follow_udp_stream instead.
struct TcpStreamJobResult {
    TcpStream stream;
    TcpStreamDoc doc;
    size_t packet = 0;
    bool interleaved = false;
};
class TcpStreamJob {
public:
    void start(std::shared_ptr<const PcapIndexJob::Result> index, size_t packet, bool interleaved,
               uint64_t max_bytes = kTcpStreamMax, bool udp = false);
    void cancel() { w_.cancel(); }
    bool running() const { return w_.running(); }
    double progress() const { return w_.progress(); }
    uint64_t generation() const { return w_.generation(); }
    std::shared_ptr<const TcpStreamJobResult> result() const { return w_.result(); }
    void clear_result() { w_.clear_result(); }

private:
    PcapWorker<TcpStreamJobResult> w_;
};

// ---- conversations ("Stream" column) --------------------------------------------------------------
constexpr uint32_t kNoStream = UINT32_MAX;
struct Conversations {
    std::vector<uint32_t> stream;  // per packet: its number within TCP / UDP, kNoStream = neither
    std::vector<uint8_t> is_udp;   // per packet: 1 = stream counts UDP conversations
    uint32_t count[2] = {};        // TCP, UDP conversations numbered so far
    std::unordered_map<std::string, uint32_t> ids;  // conversation key -> number (to continue)
};
// Blocking. Numbers packets[t.stream.size() ..) (so a live tail continues where `t` stopped).
// `done` counts the packets processed in this call.
void number_conversations(const Snapshot& snap, const std::vector<Packet>& packets, Conversations& t,
                          const std::atomic<bool>* cancel = nullptr, std::atomic<uint64_t>* done = nullptr);

struct ConversationJobResult {
    Conversations conv;
    std::shared_ptr<const PcapIndexJob::Result> index;  // the index the numbers belong to
    bool cancelled = false;
};
class ConversationJob {
public:
    // Numbers `index`'s packets; with `prev` (numbers of the first packets of the same capture, an
    // earlier result before a live-tail append) only the packets after them.
    void start(std::shared_ptr<const PcapIndexJob::Result> index,
               std::shared_ptr<const ConversationJobResult> prev = nullptr);
    void cancel() { w_.cancel(); }
    bool running() const { return w_.running(); }
    uint64_t generation() const { return w_.generation(); }
    std::shared_ptr<const ConversationJobResult> result() const { return w_.result(); }

private:
    PcapWorker<ConversationJobResult> w_;
};

}  // namespace hx
