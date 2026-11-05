// Tests for core/pcap: detection, classic pcap + pcapng indexing (endians, resolutions, sections,
// unknown blocks, truncation / corruption), the background job, the dissector and formatting.
#include <doctest/doctest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "core/document.h"
#include "core/pcap.h"

using namespace hx;

namespace {

using Bytes = std::vector<uint8_t>;

struct W {
    Bytes b;
    bool be = false;
    W& u8(uint32_t v) { b.push_back(uint8_t(v)); return *this; }
    W& u16(uint32_t v) { return be ? u8(v >> 8).u8(v) : u8(v).u8(v >> 8); }
    W& u32(uint32_t v) { return be ? u16(v >> 16).u16(v & 0xFFFF) : u16(v & 0xFFFF).u16(v >> 16); }
    W& u64(uint64_t v) {
        return be ? u32(uint32_t(v >> 32)).u32(uint32_t(v)) : u32(uint32_t(v)).u32(uint32_t(v >> 32));
    }
    W& raw(const Bytes& d) { b.insert(b.end(), d.begin(), d.end()); return *this; }
    W& pad4() { while (b.size() % 4) b.push_back(0); return *this; }
};

// Big-endian byte helpers for packet construction.
void be16(Bytes& b, uint32_t v) { b.push_back(uint8_t(v >> 8)), b.push_back(uint8_t(v)); }
void be32(Bytes& b, uint32_t v) { be16(b, v >> 16), be16(b, v & 0xFFFF); }
Bytes cat(Bytes a, const Bytes& c) { a.insert(a.end(), c.begin(), c.end()); return a; }
Bytes str(const std::string& s) { return Bytes(s.begin(), s.end()); }

Bytes eth(uint16_t type, const Bytes& body) {
    Bytes b = {0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01};
    be16(b, type);
    return cat(b, body);
}
Bytes ipv4(uint8_t proto, const Bytes& body, uint16_t frag = 0, const Bytes& opts = {}) {
    Bytes b;
    b.push_back(uint8_t(0x40 | (5 + opts.size() / 4)));
    b.push_back(0);
    be16(b, uint32_t(20 + opts.size() + body.size()));
    be16(b, 1);
    be16(b, frag);
    b.push_back(64);
    b.push_back(proto);
    be16(b, 0);
    b = cat(b, {10, 0, 0, 1, 10, 0, 0, 2});  // (vector::insert(il) trips a GCC 13 -Warray-bounds false positive)
    return cat(cat(b, opts), body);
}
Bytes udp(uint16_t sp, uint16_t dp, const Bytes& payload) {
    Bytes b;
    be16(b, sp), be16(b, dp), be16(b, uint32_t(8 + payload.size())), be16(b, 0);
    return cat(b, payload);
}
Bytes tcp(uint16_t sp, uint16_t dp, uint8_t flags, const Bytes& opts, const Bytes& payload) {
    Bytes b;
    be16(b, sp), be16(b, dp), be32(b, 1000), be32(b, 2000);
    b.push_back(uint8_t((5 + opts.size() / 4) << 4));
    b.push_back(flags);
    be16(b, 512), be16(b, 0), be16(b, 0);
    return cat(cat(b, opts), payload);
}
Bytes ipv6(uint8_t nh, const Bytes& body) {
    Bytes b = {0x60, 0, 0, 0};
    be16(b, uint32_t(body.size()));
    b.push_back(nh);
    b.push_back(64);
    Bytes src(16, 0), dst(16, 0);
    src[0] = 0x20, src[1] = 0x01, src[2] = 0x0d, src[3] = 0xb8, src[15] = 1;
    dst[0] = 0xfe, dst[1] = 0x80, dst[13] = 1, dst[15] = 2;
    return cat(cat(cat(b, src), dst), body);
}

std::shared_ptr<const Snapshot> snap_of(const Bytes& b) {
    auto doc = Document::create_from_bytes("test", b.data(), b.size());
    REQUIRE(doc);
    return doc->snapshot();
}

PcapIndexResult index_of(const Bytes& b, size_t max = kPcapMaxPackets) {
    PcapIndexResult r;
    index_pcap(*snap_of(b), r, max);
    return r;
}

// ---- classic pcap ----
W pcap_header(bool be, bool ns, uint32_t linktype = 1, uint32_t snaplen = 65535) {
    W w;
    w.be = be;
    w.u32(ns ? 0xA1B23C4D : 0xA1B2C3D4).u16(2).u16(4).u32(0).u32(0).u32(snaplen).u32(linktype);
    return w;
}
void pcap_rec(W& w, uint32_t sec, uint32_t frac, const Bytes& data, uint32_t orig = 0) {
    w.u32(sec).u32(frac).u32(uint32_t(data.size())).u32(orig ? orig : uint32_t(data.size())).raw(data);
}

// ---- pcapng ----
void ng_block(W& w, uint32_t type, const Bytes& body) {
    W tmp;
    tmp.be = w.be;
    tmp.raw(body).pad4();
    const uint32_t len = uint32_t(12 + tmp.b.size());
    w.u32(type).u32(len).raw(tmp.b).u32(len);
}
void ng_shb(W& w) {
    W b;
    b.be = w.be;
    b.u32(0x1A2B3C4D).u16(1).u16(0).u64(~uint64_t(0));
    ng_block(w, 0x0A0D0D0A, b.b);
}
void ng_idb(W& w, uint16_t linktype, uint32_t snaplen, int tsresol = -1, int64_t tsoffset = 0,
            const std::string& name = "") {
    W b;
    b.be = w.be;
    b.u16(linktype).u16(0).u32(snaplen);
    if (!name.empty()) b.u16(2).u16(uint16_t(name.size())).raw(str(name)).pad4();
    if (tsresol >= 0) b.u16(9).u16(1).u8(uint32_t(tsresol)).pad4();
    if (tsoffset) b.u16(14).u16(8).u64(uint64_t(tsoffset));
    if (b.b.size() > 8) b.u16(0).u16(0);
    ng_block(w, 1, b.b);
}
void ng_epb(W& w, uint32_t iface, uint64_t ts, const Bytes& data, uint32_t orig = 0) {
    W b;
    b.be = w.be;
    b.u32(iface).u32(uint32_t(ts >> 32)).u32(uint32_t(ts)).u32(uint32_t(data.size()));
    b.u32(orig ? orig : uint32_t(data.size())).raw(data);
    ng_block(w, 6, b.b);
}
void ng_spb(W& w, uint32_t orig, const Bytes& data) {
    W b;
    b.be = w.be;
    b.u32(orig).raw(data);
    ng_block(w, 3, b.b);
}
void ng_opb(W& w, uint16_t iface, uint64_t ts, const Bytes& data) {
    W b;
    b.be = w.be;
    b.u16(iface).u16(0).u32(uint32_t(ts >> 32)).u32(uint32_t(ts)).u32(uint32_t(data.size()));
    b.u32(uint32_t(data.size())).raw(data);
    ng_block(w, 2, b.b);
}

Bytes pkt(size_t n, uint8_t fill) { return Bytes(n, fill); }

}  // namespace

TEST_CASE("pcap_detect recognises every container variant") {
    for (bool be : {false, true})
        for (bool ns : {false, true}) {
            W w = pcap_header(be, ns);
            CHECK(pcap_detect(*snap_of(w.b)) == CaptureFormat::Pcap);
        }
    for (bool be : {false, true}) {
        W w;
        w.be = be;
        ng_shb(w);
        CHECK(pcap_detect(*snap_of(w.b)) == CaptureFormat::PcapNg);
        auto doc = Document::create_from_bytes("x", w.b.data(), w.b.size());
        CHECK(pcap_detect(*doc) == CaptureFormat::PcapNg);
    }
    CHECK(pcap_detect(*snap_of(str("not a capture at all"))) == CaptureFormat::None);
    CHECK(pcap_detect(*snap_of(Bytes{0xD4, 0xC3, 0xB2, 0xA1})) == CaptureFormat::None);  // too short
    Bytes bad_bom = {0x0A, 0x0D, 0x0D, 0x0A, 28, 0, 0, 0, 1, 2, 3, 4};
    CHECK(pcap_detect(*snap_of(bad_bom)) == CaptureFormat::None);
    CHECK(std::string(capture_format_name(CaptureFormat::PcapNg)) == "pcapng");
}

TEST_CASE("classic pcap: both byte orders, us and ns") {
    for (bool be : {false, true})
        for (bool ns : {false, true}) {
            CAPTURE(be);
            CAPTURE(ns);
            W w = pcap_header(be, ns, 101, 1500);
            pcap_rec(w, 1700000000, 5, pkt(10, 0xAA));
            pcap_rec(w, 1700000001, 999, pkt(3, 0xBB), 60);
            pcap_rec(w, 1700000002, 0, {});
            auto r = index_of(w.b);
            CHECK(r.format == CaptureFormat::Pcap);
            CHECK_FALSE(r.error);
            REQUIRE(r.packets.size() == 3);
            CHECK(r.interfaces.size() == 1);
            CHECK(r.interfaces[0].snaplen == 1500);
            CHECK(r.time_decimals == (ns ? 9 : 6));
            CHECK(r.packets[0].record_off == 24);
            CHECK(r.packets[0].data_off == 40);
            CHECK(r.packets[0].cap_len == 10);
            CHECK(r.packets[0].linktype == 101);
            CHECK(r.packets[0].ts_ns == 1700000000ll * 1000000000ll + (ns ? 5 : 5000));
            CHECK(r.packets[1].record_off == 50);
            CHECK(r.packets[1].cap_len == 3);
            CHECK(r.packets[1].orig_len == 60);
            CHECK(r.packets[1].ts_ns == 1700000001ll * 1000000000ll + (ns ? 999 : 999000));
            CHECK(r.packets[2].cap_len == 0);
            CHECK(r.scanned == w.b.size());
        }
}

TEST_CASE("classic pcap: FCS bits of the link type field are ignored") {
    W w = pcap_header(false, false, 0x10000001u);
    pcap_rec(w, 1, 0, pkt(4, 1));
    auto r = index_of(w.b);
    REQUIRE(r.packets.size() == 1);
    CHECK(r.packets[0].linktype == 1);
}

TEST_CASE("classic pcap: truncated and corrupt records keep the packets before them") {
    W w = pcap_header(false, false);
    pcap_rec(w, 1, 0, pkt(20, 1));
    pcap_rec(w, 2, 0, pkt(20, 2));
    const uint64_t third = w.b.size();
    pcap_rec(w, 3, 0, pkt(20, 3));

    SUBCASE("data cut short") {
        Bytes b(w.b.begin(), w.b.end() - 5);
        auto r = index_of(b);
        CHECK(r.error);
        CHECK(r.error_offset == third);
        CHECK(r.error_msg.find("truncated") != std::string::npos);
        CHECK(r.packets.size() == 2);
    }
    SUBCASE("record header cut short") {
        Bytes b(w.b.begin(), w.b.begin() + std::ptrdiff_t(third + 7));
        auto r = index_of(b);
        CHECK(r.error);
        CHECK(r.error_offset == third);
        CHECK(r.packets.size() == 2);
    }
    SUBCASE("absurd captured length") {
        Bytes b = w.b;
        b[size_t(third + 8)] = 0xFF, b[size_t(third + 11)] = 0x7F;
        auto r = index_of(b);
        CHECK(r.error);
        CHECK(r.error_offset == third);
        CHECK(r.packets.size() == 2);
    }
    SUBCASE("header only") {
        Bytes b(w.b.begin(), w.b.begin() + 24);
        auto r = index_of(b);
        CHECK_FALSE(r.error);
        CHECK(r.packets.empty());
    }
}

TEST_CASE("classic pcap: max_packets caps the index") {
    W w = pcap_header(false, false);
    for (int i = 0; i < 10; ++i) pcap_rec(w, uint32_t(i), 0, pkt(1, uint8_t(i)));
    auto r = index_of(w.b, 4);
    CHECK(r.truncated);
    CHECK_FALSE(r.error);
    CHECK(r.packets.size() == 4);
}

TEST_CASE("pcapng: EPB, SPB, OPB, unknown blocks, both byte orders") {
    for (bool be : {false, true}) {
        CAPTURE(be);
        W w;
        w.be = be;
        ng_shb(w);
        ng_idb(w, 1, 64, -1, 0, "eth0");
        const uint64_t epb_off = w.b.size();
        ng_epb(w, 0, 1700000000000001ull, pkt(13, 0x11), 100);  // default resolution: us
        ng_block(w, 0x00000BAD, pkt(9, 0xEE));                    // unknown: skipped
        ng_block(w, 4, pkt(16, 0));                               // NRB: skipped
        const uint64_t spb_off = w.b.size();
        ng_spb(w, 100, pkt(64, 0x22));                            // cap from snaplen 64
        ng_opb(w, 0, 5000000, pkt(7, 0x33));
        auto r = index_of(w.b);
        CHECK(r.format == CaptureFormat::PcapNg);
        CHECK_FALSE(r.error);
        REQUIRE(r.packets.size() == 3);
        REQUIRE(r.interfaces.size() == 1);
        CHECK(r.interfaces[0].name == "eth0");
        CHECK(r.interfaces[0].linktype == 1);
        const Packet& e = r.packets[0];
        CHECK(e.record_off == epb_off);
        CHECK(e.data_off == epb_off + 28);
        CHECK(e.cap_len == 13);
        CHECK(e.orig_len == 100);
        CHECK(e.ts_ns == 1700000000000001000ll);
        CHECK(e.linktype == 1);
        const Packet& s = r.packets[1];
        CHECK(s.record_off == spb_off);
        CHECK(s.data_off == spb_off + 12);
        CHECK(s.cap_len == 64);
        CHECK(s.orig_len == 100);
        CHECK(s.ts_ns == kNoTimestamp);
        CHECK(r.packets[2].cap_len == 7);
        CHECK(r.packets[2].ts_ns == 5000000000ll);
        CHECK(r.scanned == w.b.size());
        // The data bytes are where the index says.
        auto sn = snap_of(w.b);
        uint8_t b0 = 0;
        sn->read(e.data_off, &b0, 1);
        CHECK(b0 == 0x11);
        sn->read(s.data_off, &b0, 1);
        CHECK(b0 == 0x22);
    }
}

TEST_CASE("pcapng: if_tsresol powers of 10 and 2, if_tsoffset") {
    W w;
    ng_shb(w);
    ng_idb(w, 1, 0, 9);            // ns
    ng_idb(w, 1, 0, 0x80 | 20);    // 2^-20 s
    ng_idb(w, 1, 0, 3, 100);       // ms, +100 s
    ng_idb(w, 1, 0, 0x80 | 40);    // 2^-40 s (needs the shifted path)
    ng_epb(w, 0, 1234567890123456789ull, pkt(1, 0));
    ng_epb(w, 1, (uint64_t(3) << 20) | (uint64_t(1) << 19), pkt(1, 0));  // 3.5 s
    ng_epb(w, 2, 1500, pkt(1, 0));                                       // 1.5 s + 100 s
    ng_epb(w, 3, (uint64_t(7) << 40) | (uint64_t(1) << 38), pkt(1, 0));  // 7.25 s
    auto r = index_of(w.b);
    REQUIRE(r.packets.size() == 4);
    CHECK(r.packets[0].ts_ns == 1234567890123456789ll);
    CHECK(r.packets[1].ts_ns == 3500000000ll);
    CHECK(r.packets[2].ts_ns == 101500000000ll);
    CHECK(r.packets[3].ts_ns == 7250000000ll);
    CHECK(r.packets[1].iface == 1);
    CHECK(r.time_decimals == 9);
}

TEST_CASE("pcapng: several sections with their own byte order and interfaces") {
    W a;
    ng_shb(a);
    ng_idb(a, 1, 0);
    ng_epb(a, 0, 1, pkt(4, 1));
    W b;
    b.be = true;
    ng_shb(b);
    ng_idb(b, 101, 0);
    ng_idb(b, 228, 0);
    ng_epb(b, 1, 2, pkt(5, 2));
    ng_epb(b, 0, 3, pkt(6, 3));
    Bytes all = cat(a.b, b.b);
    auto r = index_of(all);
    CHECK_FALSE(r.error);
    REQUIRE(r.packets.size() == 3);
    REQUIRE(r.interfaces.size() == 3);
    CHECK(r.interfaces[2].section == 1);
    CHECK(r.interfaces[2].local_id == 1);
    CHECK(r.packets[0].linktype == 1);
    CHECK(r.packets[1].linktype == 228);
    CHECK(r.packets[1].iface == 2);
    CHECK(r.packets[1].cap_len == 5);
    CHECK(r.packets[2].linktype == 101);
    CHECK(r.packets[2].iface == 1);
}

TEST_CASE("pcapng: corrupt and truncated blocks stop cleanly") {
    W w;
    ng_shb(w);
    ng_idb(w, 1, 0);
    ng_epb(w, 0, 1, pkt(10, 1));
    const uint64_t bad = w.b.size();
    ng_epb(w, 0, 2, pkt(10, 2));

    SUBCASE("truncated block") {
        Bytes b(w.b.begin(), w.b.end() - 1);
        auto r = index_of(b);
        CHECK(r.error);
        CHECK(r.error_offset == bad);
        CHECK(r.packets.size() == 1);
    }
    SUBCASE("trailer mismatch") {
        Bytes b = w.b;
        b[b.size() - 4] ^= 0x04;
        auto r = index_of(b);
        CHECK(r.error);
        CHECK(r.error_offset == bad);
        CHECK(r.packets.size() == 1);
    }
    SUBCASE("length not a multiple of 4 / too small") {
        for (uint8_t v : {uint8_t(13), uint8_t(8), uint8_t(0)}) {
            Bytes b = w.b;
            b[size_t(bad + 4)] = v, b[size_t(bad + 5)] = 0;
            auto r = index_of(b);
            CHECK(r.error);
            CHECK(r.error_offset == bad);
            CHECK(r.packets.size() == 1);
        }
    }
    SUBCASE("unknown interface") {
        Bytes b = w.b;
        b[size_t(bad + 8)] = 7;
        auto r = index_of(b);
        CHECK(r.error);
        CHECK(r.error_msg.find("interface") != std::string::npos);
        CHECK(r.packets.size() == 1);
    }
    SUBCASE("captured length larger than the block") {
        Bytes b = w.b;
        b[size_t(bad + 20)] = 200;
        auto r = index_of(b);
        CHECK(r.error);
        CHECK(r.packets.size() == 1);
    }
    SUBCASE("trailing garbage shorter than a block header") {
        Bytes b = cat(w.b, Bytes{1, 2, 3});
        auto r = index_of(b);
        CHECK(r.error);
        CHECK(r.error_offset == w.b.size());
        CHECK(r.packets.size() == 2);
    }
    SUBCASE("SPB before any interface") {
        W x;
        ng_shb(x);
        ng_spb(x, 4, pkt(4, 0));
        auto r = index_of(x.b);
        CHECK(r.error);
        CHECK(r.packets.empty());
    }
    SUBCASE("not a capture") {
        auto r = index_of(str("hello world, definitely not pcap"));
        CHECK(r.error);
        CHECK(r.format == CaptureFormat::None);
    }
}

TEST_CASE("pcapng: IDB options that overrun are ignored") {
    W w;
    ng_shb(w);
    W body;
    body.u16(1).u16(0).u32(0).u16(9).u16(200).u8(9).pad4();  // option claims 200 bytes
    ng_block(w, 1, body.b);
    ng_epb(w, 0, 5, pkt(2, 0));
    auto r = index_of(w.b);
    CHECK_FALSE(r.error);
    REQUIRE(r.packets.size() == 1);
    CHECK(r.interfaces[0].tsresol == 6);  // the bad option was not applied
    CHECK(r.packets[0].ts_ns == 5000);
}

TEST_CASE("PcapIndexJob indexes in the background and publishes a result") {
    W w = pcap_header(false, false);
    for (int i = 0; i < 1000; ++i) pcap_rec(w, uint32_t(i), 0, pkt(32, uint8_t(i)));
    auto sn = snap_of(w.b);
    PcapIndexJob job;
    CHECK(job.result() == nullptr);
    job.start(sn);
    const auto t0 = std::chrono::steady_clock::now();
    while (job.generation() == 0 && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(10))
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    REQUIRE(job.generation() == 1);
    CHECK_FALSE(job.running());
    auto res = job.result();
    REQUIRE(res);
    CHECK(res->snap == sn);
    CHECK(res->index.packets.size() == 1000);
    CHECK(job.progress() == doctest::Approx(1.0));
    // Restart + cancel: never blocks, and the job stays usable.
    job.start(sn);
    job.cancel();
    job.start(sn, 10);
    while (job.running() && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(10))
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    REQUIRE(job.result());
    CHECK(job.result()->index.packets.size() == 10);
    CHECK(job.result()->index.truncated);
}

// ---- dissector ----

TEST_CASE("dissect: Ethernet / IPv4 / UDP with Ethernet padding") {
    Bytes frame = eth(0x0800, ipv4(17, udp(1234, 47000, str("HXdata"))));
    const size_t real = frame.size();
    frame.resize(60, 0);  // padding must not count as payload
    PacketInfo pi = dissect(frame.data(), frame.size(), kLinkEthernet);
    CHECK(pi.proto == "UDP");
    CHECK(pi.src == "10.0.0.1:1234");
    CHECK(pi.dst == "10.0.0.2:47000");
    CHECK(pi.payload_off == 14 + 20 + 8);
    CHECK(pi.payload_len == 6);
    CHECK(pi.length == 6);
    CHECK(pi.payload_off + pi.payload_len == real);
    CHECK(pi.ip_proto == 17);
    CHECK_FALSE(pi.malformed);
    CHECK(pi.summary == "10.0.0.1:1234 -> 10.0.0.2:47000  len=6");
}

TEST_CASE("dissect: 802.1Q and QinQ VLAN tags") {
    Bytes inner = ipv4(17, udp(1, 2, str("abc")));
    Bytes tag1 = {0x00, 0x0A};  // VLAN 10
    be16(tag1, 0x0800);
    Bytes f1 = eth(0x8100, cat(tag1, inner));
    PacketInfo a = dissect(f1.data(), f1.size(), kLinkEthernet);
    CHECK(a.proto == "UDP");
    CHECK(a.vlan == 10);
    CHECK(a.payload_off == 14 + 4 + 28);
    CHECK(a.summary.find("(VLAN 10)") != std::string::npos);

    Bytes outer = {0x00, 0x64};  // S-tag 100
    be16(outer, 0x8100);
    Bytes ctag = {0x00, 0x05};
    be16(ctag, 0x0800);
    Bytes f2 = eth(0x88A8, cat(cat(outer, ctag), inner));
    PacketInfo b = dissect(f2.data(), f2.size(), kLinkEthernet);
    CHECK(b.proto == "UDP");
    CHECK(b.vlan == 100);
    CHECK(b.payload_off == 14 + 8 + 28);
    CHECK(b.payload_len == 3);
}

TEST_CASE("dissect: IPv6 with extension headers + UDP") {
    Bytes u = udp(5353, 53, str("dnsq"));
    Bytes hop = {17, 0, 1, 4, 0, 0, 0, 0};  // hop-by-hop, next = UDP, 8 bytes
    Bytes dst = {0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  // dest opts, next = hop-by-hop, 16 bytes
    Bytes f = eth(0x86DD, ipv6(60, cat(cat(dst, hop), u)));
    PacketInfo pi = dissect(f.data(), f.size(), kLinkEthernet);
    CHECK(pi.proto == "UDP");
    CHECK(pi.src == "[2001:db8::1]:5353");
    CHECK(pi.dst == "[fe80::1:2]:53");
    CHECK(pi.payload_off == 14 + 40 + 16 + 8 + 8);
    CHECK(pi.payload_len == 4);
    CHECK(pi.ip_proto == 17);

    // Fragment header with offset != 0: no L4 decode.
    Bytes frag = {17, 0, 0x00, 0x09, 0, 0, 0, 1};  // offset 1 (8 bytes), more
    Bytes g = ipv6(44, cat(frag, str("rest")));
    PacketInfo fi = dissect(g.data(), g.size(), kLinkIpv6);
    CHECK(fi.fragment);
    CHECK(fi.proto == "IPv6");
    CHECK(fi.payload_off == 48);
    CHECK(fi.payload_len == 4);
}

TEST_CASE("dissect: TCP with options and flags") {
    Bytes opts = {2, 4, 0x05, 0xB4, 1, 1, 4, 2, 1, 1, 1, 0};  // MSS, NOP, NOP, SACK-perm, pad -> 12 bytes
    Bytes f = eth(0x0800, ipv4(6, tcp(443, 50000, 0x12, opts, str("hello"))));
    PacketInfo pi = dissect(f.data(), f.size(), kLinkEthernet);
    CHECK(pi.proto == "TCP");
    CHECK(pi.payload_off == 14 + 20 + 32);
    CHECK(pi.payload_len == 5);
    CHECK(pi.info.find("[SYN, ACK]") == 0);
    CHECK(pi.info.find("seq=1000") != std::string::npos);
    CHECK(pi.info.find("ack=2000") != std::string::npos);
    CHECK(pi.info.find("len=5") != std::string::npos);
    // IPv4 options shift the TCP header.
    Bytes g = eth(0x0800, ipv4(6, tcp(1, 2, 0x02, {}, {}), 0, Bytes{1, 1, 1, 0}));
    PacketInfo gi = dissect(g.data(), g.size(), kLinkEthernet);
    CHECK(gi.proto == "TCP");
    CHECK(gi.payload_off == 14 + 24 + 20);
    CHECK(gi.payload_len == 0);
    CHECK(gi.info.find("ack=") == std::string::npos);  // no ACK flag
}

TEST_CASE("dissect: ICMP, ICMPv6, ARP") {
    Bytes echo = {8, 0, 0, 0, 0, 7, 0, 3, 'p', 'i', 'n', 'g'};
    Bytes f = eth(0x0800, ipv4(1, echo));
    PacketInfo pi = dissect(f.data(), f.size(), kLinkEthernet);
    CHECK(pi.proto == "ICMP");
    CHECK(pi.info == "Echo request id=7 seq=3");
    CHECK(pi.payload_len == 4);

    Bytes ns6 = {135, 0, 0, 0, 0, 0, 0, 0};
    Bytes g = ipv6(58, ns6);
    PacketInfo gi = dissect(g.data(), g.size(), kLinkIpv6);
    CHECK(gi.proto == "ICMPv6");
    CHECK(gi.info == "Neighbor solicitation");

    Bytes arp = {0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2};
    Bytes h = eth(0x0806, arp);
    PacketInfo ai = dissect(h.data(), h.size(), kLinkEthernet);
    CHECK(ai.proto == "ARP");
    CHECK(ai.info == "Who has 10.0.0.2? Tell 10.0.0.1");
    CHECK(ai.payload_off == 14);
    CHECK(ai.payload_len == 28);
}

TEST_CASE("dissect: Linux SLL / SLL2, raw IP, loopback") {
    Bytes ip = ipv4(17, udp(7, 9, str("xy")));
    Bytes sll = {0, 0, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0, 0x08, 0x00};
    Bytes a = cat(sll, ip);
    PacketInfo pa = dissect(a.data(), a.size(), kLinkSll);
    CHECK(pa.proto == "UDP");
    CHECK(pa.payload_off == 16 + 28);

    Bytes sll2 = {0x08, 0x00, 0, 0, 0, 0, 0, 2, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0};
    Bytes b = cat(sll2, ip);
    PacketInfo pb = dissect(b.data(), b.size(), kLinkSll2);
    CHECK(pb.proto == "UDP");
    CHECK(pb.payload_off == 20 + 28);

    for (uint16_t lt : {kLinkRaw, kLinkIpv4}) {
        PacketInfo pr = dissect(ip.data(), ip.size(), lt);
        CHECK(pr.proto == "UDP");
        CHECK(pr.payload_off == 28);
    }
    Bytes v6 = ipv6(17, udp(1, 2, str("z")));
    CHECK(dissect(v6.data(), v6.size(), kLinkRaw).proto == "UDP");

    Bytes le = cat(Bytes{2, 0, 0, 0}, ip), bef = cat(Bytes{0, 0, 0, 2}, ip), six = cat(Bytes{30, 0, 0, 0}, v6);
    CHECK(dissect(le.data(), le.size(), kLinkNull).proto == "UDP");
    CHECK(dissect(bef.data(), bef.size(), kLinkNull).proto == "UDP");
    CHECK(dissect(bef.data(), bef.size(), kLinkLoop).proto == "UDP");
    CHECK(dissect(six.data(), six.size(), kLinkNull).proto == "UDP");
    CHECK(dissect(ip.data(), ip.size(), 9999).proto == "Link 9999");
}

TEST_CASE("dissect: IPv4 fragments") {
    Bytes first = eth(0x0800, ipv4(17, udp(1, 2, str("abcd")), 0x2000));  // MF
    PacketInfo a = dissect(first.data(), first.size(), kLinkEthernet);
    CHECK(a.fragment);
    CHECK(a.proto == "UDP");
    Bytes later = eth(0x0800, ipv4(17, str("tail"), 0x0003));  // offset 24
    PacketInfo b = dissect(later.data(), later.size(), kLinkEthernet);
    CHECK(b.fragment);
    CHECK(b.proto == "IPv4");
    CHECK(b.info.find("fragment offset 24") == 0);
    CHECK(b.payload_off == 34);
    CHECK(b.payload_len == 4);
}

TEST_CASE("dissect: malformed lengths are clipped and flagged") {
    SUBCASE("IPv4 header length beyond the capture") {
        Bytes f = eth(0x0800, ipv4(17, {}));
        f[14] = 0x4F;  // ihl 60
        PacketInfo pi = dissect(f.data(), f.size(), kLinkEthernet);
        CHECK(pi.malformed);
        CHECK(pi.payload_off + pi.payload_len <= f.size());
        Bytes tiny = {1, 2, 3};
        CHECK(dissect(tiny.data(), tiny.size(), kLinkEthernet).malformed);
    }
    SUBCASE("IPv4 total length smaller than the header (offload)") {
        Bytes f = eth(0x0800, ipv4(17, udp(1, 2, str("ab"))));
        f[16] = 0, f[17] = 0;
        PacketInfo pi = dissect(f.data(), f.size(), kLinkEthernet);
        CHECK(pi.malformed);
        CHECK(pi.proto == "UDP");
        CHECK(pi.payload_len == 2);
    }
    SUBCASE("IPv4 total length larger than captured (snaplen)") {
        Bytes f = eth(0x0800, ipv4(17, udp(1, 2, Bytes(100, 'x'))));
        f.resize(14 + 28 + 10);
        PacketInfo pi = dissect(f.data(), f.size(), kLinkEthernet);
        CHECK(pi.proto == "UDP");
        CHECK(pi.length == 100);
        CHECK(pi.payload_len == 10);
        CHECK(pi.payload_off + pi.payload_len == f.size());
    }
    SUBCASE("UDP length bigger than the IP packet / smaller than 8") {
        Bytes f = eth(0x0800, ipv4(17, udp(1, 2, str("abc"))));
        f[14 + 20 + 5] = 200;
        PacketInfo pi = dissect(f.data(), f.size(), kLinkEthernet);
        CHECK(pi.malformed);
        CHECK(pi.payload_len == 3);
        f[14 + 20 + 5] = 3;
        PacketInfo pj = dissect(f.data(), f.size(), kLinkEthernet);
        CHECK(pj.malformed);
    }
    SUBCASE("TCP data offset past the segment") {
        Bytes f = eth(0x0800, ipv4(6, tcp(1, 2, 0x10, {}, str("x"))));
        f[14 + 20 + 12] = 0xF0;  // 60 bytes
        PacketInfo pi = dissect(f.data(), f.size(), kLinkEthernet);
        CHECK(pi.malformed);
        CHECK(pi.proto == "TCP");
        CHECK(pi.payload_off + pi.payload_len <= f.size());
    }
    SUBCASE("IPv6 extension header overruns") {
        Bytes hop = {17, 200, 0, 0, 0, 0, 0, 0};
        Bytes f = ipv6(0, hop);
        PacketInfo pi = dissect(f.data(), f.size(), kLinkIpv6);
        CHECK(pi.malformed);
    }
    SUBCASE("null / empty input") {
        PacketInfo pi = dissect(nullptr, 100, kLinkEthernet);
        CHECK(pi.info == "no captured bytes");
        CHECK(pi.payload_len == 0);
        CHECK(pi.summary == "no captured bytes");
        PacketInfo pj = dissect(nullptr, 0, kLinkRaw);
        CHECK(pj.payload_len == 0);
    }
}

TEST_CASE("dissect never reads outside the buffer (every prefix, random bytes)") {
    std::vector<std::pair<Bytes, uint16_t>> samples = {
        {eth(0x0800, ipv4(6, tcp(1, 2, 0x18, Bytes{1, 1, 1, 1}, str("data")))), kLinkEthernet},
        {eth(0x86DD, ipv6(0, cat(Bytes{17, 0, 0, 0, 0, 0, 0, 0}, udp(1, 2, str("q"))))), kLinkEthernet},
        {eth(0x0806, Bytes{0, 1, 8, 0, 6, 4, 0, 2, 1, 1, 1, 1, 1, 1, 9, 9, 9, 9, 2, 2, 2, 2, 2, 2, 8, 8, 8, 8}),
         kLinkEthernet},
        {ipv6(51, Bytes{58, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 0, 0, 0, 0, 1, 0, 1}), kLinkIpv6},
        {cat(Bytes{2, 0, 0, 0}, ipv4(1, Bytes{0, 0, 0, 0, 0, 1, 0, 2})), kLinkNull},
    };
    for (auto& [full, lt] : samples) {
        for (size_t n = 0; n <= full.size(); ++n) {
            std::unique_ptr<uint8_t[]> buf(new uint8_t[n ? n : 1]);
            if (n) std::memcpy(buf.get(), full.data(), n);
            PacketInfo pi = dissect(buf.get(), n, lt);
            CHECK(pi.payload_off <= n);
            CHECK(pi.payload_len <= n - pi.payload_off);
        }
    }
    std::mt19937 rng(42);
    const uint16_t lts[] = {kLinkEthernet, kLinkSll, kLinkSll2, kLinkRaw, kLinkIpv4, kLinkIpv6, kLinkNull, kLinkLoop};
    for (int iter = 0; iter < 20000; ++iter) {
        const size_t n = rng() % 96;
        std::unique_ptr<uint8_t[]> buf(new uint8_t[n ? n : 1]);
        for (size_t i = 0; i < n; ++i) buf[i] = uint8_t(rng());
        // Bias toward plausible headers so the deep paths run.
        if (n > 14 && iter % 2) buf[12] = 0x08, buf[13] = 0x00, buf[14] = uint8_t(0x40 | (buf[14] & 0x0F));
        PacketInfo pi = dissect(buf.get(), n, lts[size_t(iter) % 8]);
        REQUIRE(pi.payload_off <= n);
        REQUIRE(pi.payload_len <= n - pi.payload_off);
    }
}

TEST_CASE("dissect_packet reads the packet from a snapshot") {
    W w;
    ng_shb(w);
    ng_idb(w, 1, 0);
    Bytes frame = eth(0x0800, ipv4(17, udp(1, 47000, str("HX\x01\x02"))));
    ng_epb(w, 0, 1, frame);
    auto sn = snap_of(w.b);
    PcapIndexResult r;
    index_pcap(*sn, r);
    REQUIRE(r.packets.size() == 1);
    PacketInfo pi = dissect_packet(*sn, r.packets[0]);
    CHECK(pi.proto == "UDP");
    CHECK(pi.payload_len == 4);
    uint8_t h[2] = {};
    sn->read(r.packets[0].data_off + pi.payload_off, h, 2);
    CHECK(h[0] == 'H');
    CHECK(h[1] == 'X');
    // A read limit only clips what is looked at.
    PacketInfo clipped = dissect_packet(*sn, r.packets[0], 20);
    CHECK(clipped.payload_off + clipped.payload_len <= 20);
}

TEST_CASE("formatting helpers") {
    uint8_t a6[16] = {0x20, 0x01, 0x0d, 0xb8};
    a6[15] = 1;
    CHECK(fmt_ipv6(a6) == "2001:db8::1");
    uint8_t z[16] = {};
    CHECK(fmt_ipv6(z) == "::");
    uint8_t one[16] = {0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1};  // 1:0:0:1:0:0:0:1 -> longest run wins
    CHECK(fmt_ipv6(one) == "1:0:0:1::1");
    uint8_t single[16] = {0, 1, 0, 0, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7};  // a single 0 group is not compressed
    CHECK(fmt_ipv6(single) == "1:0:2:3:4:5:6:7");
    const uint8_t v4[4] = {192, 168, 0, 255};
    CHECK(fmt_ipv4(v4) == "192.168.0.255");
    const uint8_t mac[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
    CHECK(fmt_mac(mac) == "de:ad:be:ef:00:01");

    CHECK(fmt_pcap_reltime(1500000, 6) == "0.001500");
    CHECK(fmt_pcap_reltime(-1500000000, 3) == "-1.500");
    CHECK(fmt_pcap_reltime(2000000123, 9) == "2.000000123");
    CHECK(fmt_pcap_reltime(5000000000, 0) == "5");
    CHECK(fmt_pcap_abstime(1767225600ll * 1000000000ll + 123456789, 6) == "2026-01-01 00:00:00.123456");
    CHECK(fmt_pcap_abstime(0, 0) == "1970-01-01 00:00:00");
    CHECK(fmt_pcap_abstime(-1, 9) == "1969-12-31 23:59:59.999999999");
    CHECK(fmt_pcap_abstime(951782400ll * 1000000000ll, 0) == "2000-02-29 00:00:00");
}
