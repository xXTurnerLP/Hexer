#pragma once
// Packet captures: detect pcap / pcapng, index their packet records on a worker thread (never loads
// the file: sequential header reads through a small bounded buffer, packet data is skipped), and a
// quick, bounds-paranoid dissector for the summary line + the L7 payload location.
//
// Containers:
//   pcap    classic libpcap: magic a1b2c3d4 (us) / a1b23c4d (ns), either byte order; one link type
//           (global header) for the whole file.
//   pcapng  blocks; every Section Header Block starts a section with its own byte order and its own
//           interfaces (IDB: link type, snaplen, if_tsresol 10^-n or 2^-n, if_tsoffset). Packets
//           come from EPB, SPB (cap_len from the IDB snaplen) and the obsolete OPB; every other
//           block type is skipped by its length.
// A truncated or corrupt record stops the index cleanly: the packets before it are kept and the
// result names the problem and its offset.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "core/document.h"

namespace hx {

enum class CaptureFormat : uint8_t { None, Pcap, PcapNg };
const char* capture_format_name(CaptureFormat f);  // "", "pcap", "pcapng"

// Looks at the first bytes only (classic magics, or an SHB with a valid byte-order magic).
CaptureFormat pcap_detect(const Snapshot& snap);
CaptureFormat pcap_detect(const Document& doc);

// Common link types (LINKTYPE_*).
constexpr uint16_t kLinkNull = 0;       // BSD loopback: 4-byte address family, host byte order
constexpr uint16_t kLinkEthernet = 1;
constexpr uint16_t kLinkRaw = 101;      // raw IPv4 / IPv6 (version nibble)
constexpr uint16_t kLinkLoop = 108;     // OpenBSD loopback: like Null, family big-endian
constexpr uint16_t kLinkSll = 113;      // Linux cooked v1
constexpr uint16_t kLinkIpv4 = 228;
constexpr uint16_t kLinkIpv6 = 229;
constexpr uint16_t kLinkSll2 = 276;     // Linux cooked v2
const char* linktype_name(uint16_t linktype);  // "Ethernet", "Linux SLL", ..., "" if unknown

constexpr int64_t kNoTimestamp = INT64_MIN;  // Simple Packet Blocks carry no time

struct Packet {
    uint64_t record_off = 0;  // record header (pcap) / block start (pcapng)
    uint64_t data_off = 0;    // first captured byte
    uint32_t cap_len = 0;     // captured bytes at data_off
    uint32_t orig_len = 0;    // length on the wire
    int64_t ts_ns = 0;        // ns since the Unix epoch (if_tsoffset applied); kNoTimestamp for SPB
    uint16_t linktype = 0;
    uint32_t iface = 0;       // index into PcapIndexResult::interfaces (0 for classic pcap)
};

struct CaptureInterface {
    uint16_t linktype = 0;
    uint32_t snaplen = 0;     // 0 = unlimited
    uint32_t section = 0;     // pcapng section (0-based)
    uint32_t local_id = 0;    // interface id inside its section
    uint8_t tsresol = 6;      // raw if_tsresol: bit 7 clear = 10^-n s, set = 2^-n s (classic: 6 or 9)
    int64_t tsoffset_s = 0;   // if_tsoffset
    std::string name;         // if_name ("" = none)
};

struct PcapIndexResult {
    CaptureFormat format = CaptureFormat::None;
    std::vector<Packet> packets;            // in file order
    std::vector<CaptureInterface> interfaces;
    int time_decimals = 6;                  // 6 (us) or up to 9 for finer interface resolutions
    bool truncated = false;                 // stopped after max_packets
    bool cancelled = false;
    bool error = false;                     // stopped at a truncated / corrupt record (or not a capture)
    std::string error_msg;
    uint64_t error_offset = 0;
    uint64_t scanned = 0;                   // offset the index reached
};

constexpr size_t kPcapMaxPackets = 5000000;
constexpr uint32_t kPcapMaxRecord = 64u << 20;  // a record claiming more captured bytes is corrupt

// Blocking primitive. `progress` (if non-null) gets the offset reached.
void index_pcap(const Snapshot& snap, PcapIndexResult& out, size_t max_packets = kPcapMaxPackets,
                const std::atomic<bool>* cancel = nullptr, std::atomic<uint64_t>* progress = nullptr);

// Background index, same model as SearchJob / StringsJob: one run at a time; start() cancels a
// previous run without waiting for it (it finishes in the background and publishes nothing).
class PcapIndexJob {
public:
    PcapIndexJob() = default;
    ~PcapIndexJob();
    PcapIndexJob(const PcapIndexJob&) = delete;
    PcapIndexJob& operator=(const PcapIndexJob&) = delete;

    void start(std::shared_ptr<const Snapshot> snap, size_t max_packets = kPcapMaxPackets);
    void cancel();                 // non-blocking request
    bool running() const;
    double progress() const;       // 0..1
    uint64_t generation() const;   // increments every time a run finishes

    struct Result {
        PcapIndexResult index;
        std::shared_ptr<const Snapshot> snap;  // what was indexed (read packet bytes from it)
    };
    std::shared_ptr<const Result> result() const;  // last finished run; null before the first

private:
    struct Run;
    std::shared_ptr<Run> current() const;
    std::shared_ptr<Run> run_;
    std::vector<std::pair<std::thread, std::shared_ptr<Run>>> threads_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> generation_{0};
    mutable std::mutex mu_;
    std::shared_ptr<const Result> result_;
};

// ---- dissector ------------------------------------------------------------------------------------
// Decodes link layer (Ethernet + 802.1Q/802.1ad VLAN tags, Linux SLL/SLL2, raw IP, BSD loopback),
// IPv4 (options, fragments), IPv6 (hop-by-hop / routing / fragment / destination / AH / mobility
// extension headers), TCP, UDP, ICMP, ICMPv6 and ARP. Never reads outside data[0, n). Lengths come
// from the headers (IPv4 total length, IPv6 payload length, UDP length) so Ethernet padding is not
// counted as payload; a header that claims more than was captured is clipped to n.
struct PacketInfo {
    std::string proto;        // highest decoded layer: "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "IPv4",
                              // "IPv6", "Ethernet", "LLC", "SLL", ... ("?" = nothing decoded)
    std::string src, dst;     // "10.0.0.1:1234", "[2001:db8::1]:53", "aa:bb:cc:dd:ee:ff"
    std::string info;         // "[SYN, ACK] seq=1 ack=1 win=512 len=0", "Echo request id=1 seq=2", ...
    std::string summary;      // "src -> dst  info" (what the Packets table shows)
    uint32_t length = 0;      // L7 payload length according to the headers (may exceed payload_len
                              // when the capture was cut by the snaplen)
    size_t payload_off = 0;   // L7 start within data (after the deepest decoded header)
    size_t payload_len = 0;   // captured payload bytes: payload_off + payload_len <= n
    uint16_t vlan = 0xFFFF;   // outermost VLAN id (0xFFFF = none)
    uint8_t ip_proto = 0xFF;  // IP protocol / IPv6 next header of the L4 (0xFF = no IP)
    bool fragment = false;    // IPv4 / IPv6 fragment (L4 decoded only for the first fragment)
    bool malformed = false;   // a header was cut short or had impossible lengths (noted in info)
};
PacketInfo dissect(const uint8_t* data, size_t n, uint16_t linktype);

// Reads min(cap_len, max_read) bytes of a packet from `snap` and dissects them.
PacketInfo dissect_packet(const Snapshot& snap, const Packet& p, size_t max_read = 4096);

// ---- formatting -----------------------------------------------------------------------------------
// Seconds with `decimals` (0..9) fraction digits: "0.000123", "-1.500000".
std::string fmt_pcap_reltime(int64_t ns, int decimals);
// UTC: "2026-01-01 00:00:00.123456" (decimals fraction digits; 0 = none).
std::string fmt_pcap_abstime(int64_t ns, int decimals);
std::string fmt_ipv4(const uint8_t* a);   // 4 bytes
std::string fmt_ipv6(const uint8_t* a);   // 16 bytes, RFC 5952 ("2001:db8::1", "fe80::1:2")
std::string fmt_mac(const uint8_t* a);    // 6 bytes "aa:bb:cc:dd:ee:ff"

}  // namespace hx
