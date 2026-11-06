#pragma once
// Packet filter expressions for the Packets panel: a tiny Wireshark-like language over the
// dissector's fields (core/pcap.h). Pure core: parse once, then match(packet, dissected info).
//
//   expr       := or
//   or         := and { ("or" | "||") and }
//   and        := not { ("and" | "&&") not }
//   not        := ("not" | "!") not | "(" expr ")" | comparison | protocol | "text"
//   comparison := field op value          op: == != < > <= >=
//
// Fields (a comparison with a field the packet does not have is false, for every operator):
//   ip.src ip.dst ip.addr      IPv4 "10.0.0.1" or IPv6 "2001:db8::1" / "::ffff:1.2.3.4", with an
//                              optional "/prefix" (== and != only); an IPv4 value never matches an
//                              IPv6 packet and vice versa; < > compare addresses byte by byte
//   tcp.port tcp.srcport tcp.dstport  udp.port udp.srcport udp.dstport   0..65535
//   frame.len                  length on the wire (Packet::orig_len)
//   frame.number               1-based packet number (filter_packets passes it; 0 = unknown: false)
//   eth.type                   EtherType after VLAN tags (0x0800, 0x86dd, 2054); Ethernet / SLL only
//   vlan (= vlan.id)           outermost 802.1Q / 802.1ad VLAN id, 0..4095 (false without a tag)
//   ip.proto                   IP protocol / IPv6 next header of the L4: 6 = TCP, 17 = UDP, ...
//   tcp.seq tcp.ack            raw 32-bit sequence / acknowledgment numbers
//   tcp.flags                  the flags byte: a number (0x12) or flag names joined by '+'
//                              (syn+ack = exactly SYN and ACK); names fin syn rst psh ack urg ece cwr
//   tcp.flags.syn (.fin .rst .psh .ack .urg .ece .cwr)   1 when set, 0 when not; alone = "is set"
//   proto                      == / != one of tcp udp icmp icmpv6 arp ip (= ipv4) ipv6 ("has this layer")
// ip.addr / tcp.port / udp.port stand for both ends: == (and < ...) is true when either end matches,
// != when neither does. A protocol name alone ("tcp", "not arp") is proto == name; a quoted
// "text" matches the Proto / Summary columns (case-insensitive substring, like the old filter).
// TCP fields (ports, seq, ack, flags) need a decoded TCP header, UDP ports a UDP header.
// Numbers are decimal or 0x hex. Keywords and field names are case-insensitive. Nesting is limited
// to 64 levels and a filter to about 1000 terms (an error beyond: match() recurses).
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

class PacketFilter {
public:
    // Parses `text`; whitespace only = no filter (matches everything). On an error *this is left
    // unchanged, *err gets the message and *err_pos the byte offset in `text` it refers to.
    bool parse(const std::string& text, std::string* err = nullptr, size_t* err_pos = nullptr);
    bool empty() const { return nodes_.empty(); }
    const std::string& text() const { return text_; }  // as last parsed successfully
    // `number` = the packet's 1-based frame number (frame.number; 0 = unknown).
    bool match(const Packet& p, const PacketInfo& pi, uint64_t number = 0) const;

    enum class Field : uint8_t { IpSrc, IpDst, IpAddr, TcpPort, TcpSrcPort, TcpDstPort, UdpPort, UdpSrcPort,
                                 UdpDstPort, FrameLen, EthType, Proto, FrameNumber, Vlan, IpProto, TcpSeq,
                                 TcpAck, TcpFlags, TcpFlag };
    enum class Op : uint8_t { Eq, Ne, Lt, Gt, Le, Ge };
    enum class Kind : uint8_t { And, Or, Not, Compare, Text };
    struct Node {
        Kind kind = Kind::Compare;
        int a = -1, b = -1;        // children (And / Or: both, Not: a)
        Field field = Field::Proto;
        Op op = Op::Eq;
        uint64_t num = 0;          // ports, lengths, EtherType, protocol id
        uint8_t ip_version = 0;    // address values: 4 / 6
        uint8_t prefix = 0;        // address prefix length (32 / 128 = the whole address)
        uint8_t addr[16] = {};
        uint8_t mask = 0;          // TcpFlag: the flag bit
        std::string text;          // Kind::Text: lower-cased needle
    };

private:
    bool eval(int n, const Packet& p, const PacketInfo& pi, uint64_t number) const;
    std::vector<Node> nodes_;
    int root_ = -1;
    std::string text_;
};

// Parses an IPv4 / IPv6 literal (no prefix): fills addr (IPv4 in the first 4 bytes), version 4 / 6.
bool parse_ip_literal(const std::string& s, uint8_t addr[16], uint8_t& version);

constexpr size_t kFilterRead = 2048;  // bytes dissected per packet for filtering (= the table rows)

// Blocking: indices of the packets in [begin, end) matching `f`, ascending, appended to `out`
// (frame.number = index + 1).
// `done` (if non-null) counts the packets tested.
void filter_packets(const Snapshot& snap, const std::vector<Packet>& packets, const PacketFilter& f, size_t begin,
                    size_t end, std::vector<uint32_t>& out, const std::atomic<bool>* cancel = nullptr,
                    std::atomic<uint64_t>* done = nullptr);

// Background filter over a finished index (the Packets panel uses it above kFilterSyncMax packets).
// `begin` / `prefix` (live tail): only packets from `begin` on are tested and the matches start
// with `prefix` (the matches below `begin` of an earlier run over the same packets).
constexpr size_t kFilterSyncMax = 100000;
struct PacketFilterResult {
    std::vector<uint32_t> matches;
    std::string text;      // the filter that produced them
    std::shared_ptr<const PcapIndexJob::Result> index;  // the index they number (a re-index makes them stale)
    bool cancelled = false;
};
class PacketFilterJob {
public:
    void start(std::shared_ptr<const PcapIndexJob::Result> index, const PacketFilter& f, size_t begin = 0,
               std::vector<uint32_t> prefix = {});
    void cancel() { w_.cancel(); }
    bool running() const { return w_.running(); }
    double progress() const { return w_.progress(); }
    uint64_t generation() const { return w_.generation(); }
    std::shared_ptr<const PacketFilterResult> result() const { return w_.result(); }

private:
    PcapWorker<PacketFilterResult> w_;
};

}  // namespace hx
