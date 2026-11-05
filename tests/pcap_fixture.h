#pragma once
// Synthetic captures for the packet filter / TCP stream / Packets panel tests: Ethernet frames with
// IPv4 / IPv6, TCP (any seq / ack / flags), UDP, ICMP, ARP, written as classic pcap or pcapng
// (either byte order). Byte vectors are built with push_back loops (vector::insert of ranges /
// initializer lists trips GCC 13 false positives).
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "core/document.h"
#include "core/pcap.h"
#include "core/pcap_filter.h"

namespace pcapfx {

using Bytes = std::vector<uint8_t>;

inline void put(Bytes& b, const Bytes& c) {
    for (uint8_t v : c) b.push_back(v);
}
inline void be16(Bytes& b, uint32_t v) {
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v));
}
inline void be32(Bytes& b, uint32_t v) {
    be16(b, v >> 16);
    be16(b, v & 0xFFFF);
}
inline Bytes str(const std::string& s) { return Bytes(s.begin(), s.end()); }

// "10.0.0.1" -> 4 bytes, "2001:db8::1" -> 16 bytes.
inline Bytes addr(const std::string& s) {
    uint8_t a[16] = {};
    uint8_t ver = 0;
    if (!hx::parse_ip_literal(s, a, ver)) return {};
    return Bytes(a, a + (ver == 4 ? 4 : 16));
}

inline Bytes tcp(uint16_t sp, uint16_t dp, uint32_t seq, uint32_t ack, uint8_t flags, const Bytes& payload = {}) {
    Bytes b;
    be16(b, sp);
    be16(b, dp);
    be32(b, seq);
    be32(b, ack);
    b.push_back(5 << 4);
    b.push_back(flags);
    be16(b, 512);
    be16(b, 0);
    be16(b, 0);
    put(b, payload);
    return b;
}
inline Bytes udp(uint16_t sp, uint16_t dp, const Bytes& payload) {
    Bytes b;
    be16(b, sp);
    be16(b, dp);
    be16(b, uint32_t(8 + payload.size()));
    be16(b, 0);
    put(b, payload);
    return b;
}
inline Bytes icmp_echo() {
    Bytes b = {8, 0, 0, 0};
    be16(b, 1);
    be16(b, 1);
    put(b, str("ping"));
    return b;
}

// IPv4 or IPv6 packet (by the address literals) around an L4 body; returns {ethertype, bytes}.
inline Bytes ip(const std::string& src, const std::string& dst, uint8_t proto, const Bytes& body, uint16_t& ethertype) {
    const Bytes s = addr(src), d = addr(dst);
    Bytes b;
    if (s.size() == 4) {
        ethertype = 0x0800;
        b.push_back(0x45);
        b.push_back(0);
        be16(b, uint32_t(20 + body.size()));
        be16(b, 1);
        be16(b, 0x4000);
        b.push_back(64);
        b.push_back(proto);
        be16(b, 0);
    } else {
        ethertype = 0x86DD;
        b.push_back(0x60);
        b.push_back(0);
        b.push_back(0);
        b.push_back(0);
        be16(b, uint32_t(body.size()));
        b.push_back(proto);
        b.push_back(64);
    }
    put(b, s);
    put(b, d);
    put(b, body);
    return b;
}

inline Bytes eth(uint16_t ethertype, const Bytes& body, int vlan = -1) {
    Bytes b = {0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01};
    if (vlan >= 0) {
        be16(b, 0x8100);
        be16(b, uint32_t(vlan));
    }
    be16(b, ethertype);
    put(b, body);
    while (b.size() < 60) b.push_back(0);  // Ethernet minimum frame (padding)
    return b;
}

inline Bytes tcp_frame(const std::string& src, uint16_t sp, const std::string& dst, uint16_t dp, uint32_t seq,
                       uint32_t ack, uint8_t flags, const Bytes& payload = {}) {
    uint16_t et = 0;
    const Bytes p = ip(src, dst, 6, tcp(sp, dp, seq, ack, flags, payload), et);
    return eth(et, p);
}
inline Bytes udp_frame(const std::string& src, uint16_t sp, const std::string& dst, uint16_t dp, const Bytes& payload,
                       int vlan = -1) {
    uint16_t et = 0;
    const Bytes p = ip(src, dst, 17, udp(sp, dp, payload), et);
    return eth(et, p, vlan);
}
inline Bytes icmp_frame(const std::string& src, const std::string& dst) {
    uint16_t et = 0;
    const Bytes p = ip(src, dst, 1, icmp_echo(), et);
    return eth(et, p);
}
inline Bytes arp_frame() {
    Bytes b;
    be16(b, 1);
    be16(b, 0x0800);
    b.push_back(6);
    b.push_back(4);
    be16(b, 1);
    put(b, Bytes{0x02, 0, 0, 0, 0, 0x01});
    put(b, addr("10.0.0.1"));
    put(b, Bytes(6, 0));
    put(b, addr("10.0.0.2"));
    return eth(0x0806, b);
}

// TCP flags
constexpr uint8_t FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10;

// ---- containers ----
struct W {
    Bytes b;
    bool be = false;
    W& u8(uint32_t v) {
        b.push_back(uint8_t(v));
        return *this;
    }
    W& u16(uint32_t v) { return be ? u8(v >> 8).u8(v) : u8(v).u8(v >> 8); }
    W& u32(uint32_t v) { return be ? u16(v >> 16).u16(v & 0xFFFF) : u16(v & 0xFFFF).u16(v >> 16); }
};

inline Bytes pcap_file(const std::vector<Bytes>& frames) {
    W w;
    w.u32(0xA1B2C3D4).u16(2).u16(4).u32(0).u32(0).u32(65535).u32(1);
    for (size_t i = 0; i < frames.size(); ++i) {
        w.u32(uint32_t(1000 + i)).u32(0).u32(uint32_t(frames[i].size())).u32(uint32_t(frames[i].size()));
        put(w.b, frames[i]);
    }
    return w.b;
}

inline Bytes pcapng_file(const std::vector<Bytes>& frames, bool big_endian = false) {
    W w;
    w.be = big_endian;
    w.u32(0x0A0D0D0A).u32(28).u32(0x1A2B3C4D).u16(1).u16(0).u32(0xFFFFFFFF).u32(0xFFFFFFFF).u32(28);  // SHB
    w.u32(1).u32(20).u16(1).u16(0).u32(65535).u32(20);                                                // IDB
    for (size_t i = 0; i < frames.size(); ++i) {
        const size_t pad = (4 - frames[i].size() % 4) % 4;
        const uint32_t len = uint32_t(32 + frames[i].size() + pad);
        w.u32(6).u32(len).u32(0).u32(0).u32(uint32_t(i)).u32(uint32_t(frames[i].size())).u32(uint32_t(frames[i].size()));
        put(w.b, frames[i]);
        for (size_t k = 0; k < pad; ++k) w.b.push_back(0);
        w.u32(len);
    }
    return w.b;
}

// A document + its finished packet index (what the Packets panel's jobs work on).
struct Capture {
    std::unique_ptr<hx::Document> doc;
    std::shared_ptr<hx::PcapIndexJob::Result> res;
    explicit Capture(const Bytes& file) {
        doc = hx::Document::create_from_bytes("cap", file.data(), file.size());
        res = std::make_shared<hx::PcapIndexJob::Result>();
        res->snap = doc->snapshot();
        hx::index_pcap(*res->snap, res->index);
    }
    const std::vector<hx::Packet>& packets() const { return res->index.packets; }
};

}  // namespace pcapfx
