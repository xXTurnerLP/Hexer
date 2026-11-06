// Tests for core/pcap_filter: the filter expression language (every field, operators, precedence,
// IPv4 / IPv6 literals and prefixes, error positions) and filtering an index (sync + PacketFilterJob).
#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <thread>
#include <vector>

#include "core/pcap.h"
#include "core/pcap_filter.h"
#include "pcap_fixture.h"

using namespace hx;
using namespace pcapfx;

namespace {

// Does `expr` (which must parse) match `frame`?
bool m(const std::string& expr, const Bytes& frame, uint32_t orig_len = 0) {
    PacketFilter f;
    std::string err;
    size_t pos = 0;
    const bool ok = f.parse(expr, &err, &pos);
    INFO("expr: " << expr << "  error: " << err << " at " << pos);
    REQUIRE(ok);
    Packet p;
    p.cap_len = uint32_t(frame.size());
    p.orig_len = orig_len ? orig_len : uint32_t(frame.size());
    p.linktype = kLinkEthernet;
    return f.match(p, dissect(frame.data(), frame.size(), kLinkEthernet));
}

// `expr` must fail; returns the error position (and checks the message contains `msg`).
size_t err_at(const std::string& expr, const std::string& msg = "") {
    PacketFilter f;
    std::string err;
    size_t pos = SIZE_MAX;
    INFO("expr: " << expr);
    CHECK_FALSE(f.parse(expr, &err, &pos));
    CHECK_FALSE(err.empty());
    if (!msg.empty()) CHECK_MESSAGE(err.find(msg) != std::string::npos, err);
    return pos;
}

const Bytes kTcp = tcp_frame("10.0.0.1", 51000, "10.0.0.2", 80, 1, 1, ACK | PSH, str("GET / HTTP/1.1"));
const Bytes kUdp = udp_frame("192.168.1.5", 5353, "224.0.0.251", 53, str("query"));
const Bytes kUdp6 = udp_frame("2001:db8::1", 40000, "fe80::1:2", 47000, str("v6 data"));
const Bytes kIcmp = icmp_frame("10.0.0.1", "10.0.0.9");
const Bytes kArp = arp_frame();
const Bytes kVlan = udp_frame("10.1.1.1", 1, "10.1.1.2", 2, str("x"), 10);

}  // namespace

TEST_CASE("pcap filter: empty and whitespace match everything") {
    PacketFilter f;
    CHECK(f.parse(""));
    CHECK(f.empty());
    CHECK(f.parse("   \t "));
    CHECK(f.empty());
    CHECK(m("", kArp));
    CHECK(m(" ", kTcp));
}

TEST_CASE("pcap filter: ip.src / ip.dst / ip.addr with IPv4") {
    CHECK(m("ip.src == 10.0.0.1", kTcp));
    CHECK_FALSE(m("ip.src == 10.0.0.2", kTcp));
    CHECK(m("ip.dst == 10.0.0.2", kTcp));
    CHECK(m("ip.src != 10.0.0.2", kTcp));
    CHECK(m("ip.addr == 10.0.0.2", kTcp));
    CHECK(m("ip.addr == 10.0.0.1", kTcp));
    CHECK_FALSE(m("ip.addr == 10.0.0.3", kTcp));
    CHECK_FALSE(m("ip.addr != 10.0.0.1", kTcp));  // != : neither end
    CHECK(m("ip.addr != 10.0.0.3", kTcp));
    CHECK(m("ip.src < 10.0.0.2", kTcp));
    CHECK_FALSE(m("ip.src > 10.0.0.1", kTcp));
    CHECK(m("ip.src >= 10.0.0.1", kTcp));
    CHECK(m("ip.src <= 10.0.0.1", kTcp));
    CHECK(m("ip.dst > 10.0.0.1", kTcp));
    // Prefixes
    CHECK(m("ip.src == 10.0.0.0/8", kTcp));
    CHECK(m("ip.src == 10.0.0.0/31", kTcp));
    CHECK_FALSE(m("ip.src == 10.0.0.0/32", kTcp));
    CHECK(m("ip.addr == 192.168.0.0/16", kUdp));
    CHECK(m("ip.dst == 224.0.0.0/4", kUdp));
    CHECK(m("ip.src == 0.0.0.0/0", kUdp));
    CHECK(m("ip.src != 172.16.0.0/12", kUdp));
    CHECK_FALSE(m("ip.src != 192.168.1.0/24", kUdp));
    CHECK(m("ip.src == 192.168.1.4/31", kUdp));  // bits inside a byte
    CHECK_FALSE(m("ip.src == 192.168.1.6/31", kUdp));
    // Packets without IP: false for every operator
    CHECK_FALSE(m("ip.src == 10.0.0.1", kArp));
    CHECK_FALSE(m("ip.src != 10.0.0.1", kArp));
    CHECK_FALSE(m("ip.addr != 1.2.3.4", kArp));
    // An IPv4 value never matches an IPv6 packet
    CHECK_FALSE(m("ip.src != 10.0.0.1", kUdp6));
}

TEST_CASE("pcap filter: IPv6 addresses") {
    CHECK(m("ip.src == 2001:db8::1", kUdp6));
    CHECK(m("ip.src == 2001:0db8:0000:0000:0000:0000:0000:0001", kUdp6));
    CHECK(m("ip.dst == fe80::1:2", kUdp6));
    CHECK(m("ip.dst == FE80:0:0:0:0:0:1:2", kUdp6));
    CHECK(m("ip.addr == fe80::1:2", kUdp6));
    CHECK(m("ip.addr == 2001:db8::/32", kUdp6));
    CHECK(m("ip.dst == fe80::/10", kUdp6));
    CHECK_FALSE(m("ip.src == fe80::/10", kUdp6));
    CHECK(m("ip.src != ::1", kUdp6));
    CHECK(m("ip.src < 2001:db8::2", kUdp6));
    CHECK_FALSE(m("ip.src == ::1", kTcp));  // IPv6 value, IPv4 packet
    CHECK_FALSE(m("ip.src != ::1", kTcp));

    uint8_t a[16];
    uint8_t v = 0;
    REQUIRE(parse_ip_literal("::", a, v));
    CHECK(v == 6);
    for (uint8_t b : a) CHECK(b == 0);
    REQUIRE(parse_ip_literal("::1", a, v));
    CHECK(a[15] == 1);
    CHECK(a[14] == 0);
    REQUIRE(parse_ip_literal("1::", a, v));
    CHECK(a[1] == 1);
    CHECK(a[15] == 0);
    REQUIRE(parse_ip_literal("::ffff:1.2.3.4", a, v));
    CHECK(v == 6);
    CHECK(a[10] == 0xFF);
    CHECK(a[11] == 0xFF);
    CHECK(a[12] == 1);
    CHECK(a[15] == 4);
    REQUIRE(parse_ip_literal("1:2:3:4:5:6:7:8", a, v));
    CHECK(a[0] == 0);
    CHECK(a[1] == 1);
    CHECK(a[15] == 8);
    REQUIRE(parse_ip_literal("1:2:3:4:5:6:1.2.3.4", a, v));
    CHECK(a[12] == 1);
    REQUIRE(parse_ip_literal("255.0.10.1", a, v));
    CHECK(v == 4);
    CHECK(a[0] == 255);
    CHECK(a[2] == 10);
    for (const char* bad : {"1::2::3", ":::", "12345::", "1:2:3:4:5:6:7:8:9", "g::1", "1:2:3:4:5:6:7", ":1:2:3:4:5:6:7",
                            "1::2:3:4:5:6:7:8", "::1.2.3", "1.2.3.4::", "256.1.1.1", "1.2.3", "1.2.3.4.5", "01234.1.1.1",
                            "1..2.3", ""}) {
        INFO(bad);
        CHECK_FALSE(parse_ip_literal(bad, a, v));
    }
}

TEST_CASE("pcap filter: ports, frame.len, eth.type") {
    CHECK(m("tcp.port == 80", kTcp));
    CHECK(m("tcp.port == 51000", kTcp));
    CHECK_FALSE(m("tcp.port == 81", kTcp));
    CHECK(m("tcp.port != 81", kTcp));
    CHECK_FALSE(m("tcp.port != 80", kTcp));
    CHECK(m("tcp.srcport == 51000", kTcp));
    CHECK_FALSE(m("tcp.srcport == 80", kTcp));
    CHECK(m("tcp.dstport == 80", kTcp));
    CHECK(m("tcp.dstport < 1024", kTcp));
    CHECK(m("tcp.port < 1024", kTcp));     // either end
    CHECK(m("tcp.port > 50000", kTcp));
    CHECK_FALSE(m("tcp.port > 60000", kTcp));
    CHECK(m("tcp.port == 0x50", kTcp));
    // TCP fields on a UDP packet (and vice versa) are absent: false for every operator
    CHECK_FALSE(m("tcp.port == 53", kUdp));
    CHECK_FALSE(m("tcp.port != 53", kUdp));
    CHECK_FALSE(m("udp.port != 80", kTcp));
    CHECK(m("udp.port == 53", kUdp));
    CHECK(m("udp.port == 5353", kUdp));
    CHECK(m("udp.srcport == 5353", kUdp));
    CHECK(m("udp.dstport == 53", kUdp));
    CHECK_FALSE(m("udp.dstport == 5353", kUdp));
    CHECK(m("udp.srcport >= 5353", kUdp));
    CHECK(m("udp.dstport <= 53", kUdp));
    CHECK(m("udp.port == 47000", kUdp6));
    // frame.len is the length on the wire
    CHECK(m("frame.len == 1500", kTcp, 1500));
    CHECK(m("frame.len > 1000", kTcp, 1500));
    CHECK_FALSE(m("frame.len < 1000", kTcp, 1500));
    CHECK(m("frame.len == 60", kArp));
    CHECK(m("frame.len >= 60 and frame.len <= 60", kArp));
    // eth.type (after VLAN tags)
    CHECK(m("eth.type == 0x0800", kTcp));
    CHECK(m("eth.type == 2048", kTcp));
    CHECK(m("eth.type == 0x86dd", kUdp6));
    CHECK(m("eth.type == 0x0806", kArp));
    CHECK(m("eth.type == 0x0800", kVlan));
    CHECK(m("eth.type != 0x0806", kVlan));
    CHECK(m("eth.type < 0x0806", kVlan));
    // eth.type absent on a raw IP link
    PacketFilter f;
    REQUIRE(f.parse("eth.type != 1"));
    const Bytes raw(kTcp.begin() + 14, kTcp.begin() + 14 + 20 + 20);
    Packet p;
    CHECK_FALSE(f.match(p, dissect(raw.data(), raw.size(), kLinkRaw)));
    REQUIRE(f.parse("tcp.port == 80"));
    CHECK(f.match(p, dissect(raw.data(), raw.size(), kLinkRaw)));
}

TEST_CASE("pcap filter: proto and bare protocol names") {
    CHECK(m("proto == tcp", kTcp));
    CHECK(m("proto == ip", kTcp));
    CHECK(m("proto == ipv4", kTcp));
    CHECK_FALSE(m("proto == ipv6", kTcp));
    CHECK_FALSE(m("proto == udp", kTcp));
    CHECK(m("proto != udp", kTcp));
    CHECK(m("proto == udp", kUdp));
    CHECK(m("proto == ipv6", kUdp6));
    CHECK(m("proto == udp", kUdp6));
    CHECK_FALSE(m("proto == ip", kUdp6));
    CHECK(m("proto == icmp", kIcmp));
    CHECK_FALSE(m("proto == icmpv6", kIcmp));
    CHECK(m("proto == arp", kArp));
    CHECK_FALSE(m("proto == ip", kArp));
    CHECK(m("tcp", kTcp));
    CHECK(m("udp", kUdp));
    CHECK(m("icmp", kIcmp));
    CHECK(m("arp", kArp));
    CHECK(m("ipv6", kUdp6));
    CHECK(m("ip", kIcmp));
    CHECK(m("not arp", kTcp));
    CHECK_FALSE(m("not arp", kArp));
    CHECK(m("TCP.PORT == 80 AND Proto == TCP", kTcp));  // case-insensitive
}

TEST_CASE("pcap filter: \"text\" matches Proto / Summary") {
    CHECK(m("\"echo request\"", kIcmp));
    CHECK(m("\"ECHO\"", kIcmp));
    CHECK_FALSE(m("\"echo\"", kTcp));
    CHECK(m("\"arp\"", kArp));
    CHECK(m("\"who has 10.0.0.2\"", kArp));
    CHECK(m("\"10.0.0.2:80\"", kTcp));
    CHECK(m("\"a\\\"b\" or tcp", kTcp));  // escaped quote inside
}

TEST_CASE("pcap filter: and / or / not precedence and parentheses") {
    // not > and > or
    CHECK(m("udp or tcp and tcp.port == 81", kUdp));           // udp or (tcp and ...)
    CHECK_FALSE(m("(udp or tcp) and tcp.port == 81", kUdp));
    CHECK(m("tcp and tcp.port == 81 or udp", kUdp));
    CHECK_FALSE(m("tcp and (tcp.port == 81 or udp)", kUdp));
    CHECK(m("not tcp and udp", kUdp));                        // (not tcp) and udp
    CHECK_FALSE(m("not (tcp or udp)", kUdp));
    CHECK(m("not not udp", kUdp));
    CHECK(m("! tcp && udp", kUdp));
    CHECK(m("tcp || udp", kUdp));
    CHECK(m("!(tcp)", kUdp));
    CHECK(m("((((udp))))", kUdp));
    CHECK(m("ip.src == 10.0.0.1 and tcp.dstport == 80 and not tcp.srcport == 80", kTcp));
    CHECK(m("arp or icmp or ip.addr == 1.2.3.4", kIcmp));
    CHECK_FALSE(m("arp or icmp or ip.addr == 1.2.3.4", kTcp));
    CHECK(m("tcp.port==80&&ip.src==10.0.0.1", kTcp));  // no spaces
}

TEST_CASE("pcap filter: errors carry their position; a failed parse keeps the previous filter") {
    CHECK(err_at("ip.src = 1.2.3.4", "==") == 7);
    CHECK(err_at("ip.src ==", "value") == 9);
    CHECK(err_at("ip.src", "after 'ip.src'") == 6);
    CHECK(err_at("foo == 1", "unknown field 'foo'") == 0);
    CHECK(err_at("tcp.port == 70000", "range") == 12);
    CHECK(err_at("eth.type == 0x10000", "range") == 12);
    CHECK(err_at("frame.len == 99999999999", "range") == 13);
    CHECK(err_at("tcp.port == 99999999999999999999999", "number") == 12);
    CHECK(err_at("tcp.port == abc", "number") == 12);
    CHECK(err_at("(tcp", "')'") == 4);
    CHECK(err_at("tcp)", "unmatched") == 3);
    CHECK(err_at("tcp udp", "'and' / 'or'") == 4);
    CHECK(err_at("tcp and", "expected") == 7);
    CHECK(err_at("and tcp", "unexpected 'and'") == 0);
    CHECK(err_at("not", "expected") == 3);
    CHECK(err_at("()", "unexpected ')'") == 1);
    CHECK(err_at("ip.src == 1.2.3", "address") == 10);
    CHECK(err_at("ip.src == 1.2.3.4/33", "prefix") == 18);
    CHECK(err_at("ip.src == ::1/129", "prefix") == 14);
    CHECK(err_at("ip.src == 1.2.3.4/x", "prefix") == 18);
    CHECK(err_at("ip.src < 10.0.0.0/8", "/prefix") == 7);
    CHECK(err_at("proto < tcp", "proto") == 6);
    CHECK(err_at("proto == http", "unknown protocol") == 9);
    CHECK(err_at("tcp == 1", "unknown field 'tcp'") == 0);
    CHECK(err_at("\"abc", "unterminated") == 0);
    CHECK(err_at("udp and #", "unexpected '#'") == 8);
    CHECK(err_at("tcp.port == == 1", "value") == 12);
    // Deep nesting is an error, not a stack overflow
    std::string deep;
    for (int i = 0; i < 200; ++i) deep += "(";
    deep += "tcp";
    for (int i = 0; i < 200; ++i) deep += ")";
    err_at(deep, "nested");
    std::string nots;
    for (int i = 0; i < 200; ++i) nots += "not ";
    err_at(nots + "tcp", "nested");
    // A long flat chain is not nested, but match() recurses through its left-deep tree: a pasted
    // filter of 100k terms is an error too, not a stack overflow (one long chain still works).
    std::string chain = "udp", huge = "udp";
    for (int i = 0; i < 500; ++i) chain += " or udp";
    for (int i = 0; i < 100000; ++i) huge += i % 2 ? " and udp" : " or udp";
    CHECK(m(chain, kUdp));
    CHECK_FALSE(m(chain, kTcp));
    err_at(huge, "too long");

    PacketFilter f;
    REQUIRE(f.parse("udp"));
    std::string err;
    size_t pos = 0;
    CHECK_FALSE(f.parse("udp and", &err, &pos));
    CHECK(f.text() == "udp");
    Packet p;
    CHECK(f.match(p, dissect(kUdp.data(), kUdp.size(), kLinkEthernet)));
    CHECK_FALSE(f.match(p, dissect(kTcp.data(), kTcp.size(), kLinkEthernet)));
}

TEST_CASE("pcap filter: filter_packets and PacketFilterJob over an index") {
    std::vector<Bytes> frames;
    for (int i = 0; i < 300; ++i) {
        if (i % 3 == 0) frames.push_back(tcp_frame("10.0.0.1", uint16_t(1000 + i), "10.0.0.2", 80, 1, 1, ACK));
        else if (i % 3 == 1) frames.push_back(udp_frame("10.0.0.3", 53, "10.0.0.4", uint16_t(2000 + i), str("dns")));
        else frames.push_back(arp_frame());
    }
    for (bool ng : {false, true}) {
        Capture cap(ng ? pcapng_file(frames, true) : pcap_file(frames));
        REQUIRE(cap.packets().size() == 300);
        PacketFilter f;
        REQUIRE(f.parse("tcp.dstport == 80 or udp.dstport == 2004"));
        std::vector<uint32_t> out;
        std::atomic<uint64_t> done{0};
        filter_packets(*cap.res->snap, cap.packets(), f, 0, cap.packets().size(), out, nullptr, &done);
        REQUIRE(out.size() == 101);
        CHECK(out[0] == 0);
        CHECK(out[1] == 3);
        CHECK(out[2] == 4);  // the UDP packet to port 2004
        CHECK(out.back() == 297);
        CHECK(done.load() == 300);
        // A sub-range (the Packets panel filters in slices)
        std::vector<uint32_t> part;
        filter_packets(*cap.res->snap, cap.packets(), f, 4, 10, part);
        REQUIRE(part.size() == 3);
        CHECK(part[0] == 4);
        CHECK(part[1] == 6);
        CHECK(part[2] == 9);

        PacketFilterJob job;
        job.start(cap.res, f);
        const auto t0 = std::chrono::steady_clock::now();
        while (job.generation() == 0) {
            REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK_FALSE(job.running());
        auto r = job.result();
        REQUIRE(r);
        CHECK(r->matches == out);
        CHECK(r->text == f.text());
        CHECK_FALSE(r->cancelled);
        CHECK(job.progress() == 1.0);
    }
}

TEST_CASE("pcap filter: vlan, ip.proto, tcp.seq / tcp.ack, tcp.flags (numbers and names), tcp.flags.<bit>") {
    // vlan / vlan.id: the outermost tag; no tag = false for every operator
    CHECK(m("vlan == 10", kVlan));
    CHECK(m("vlan.id == 10", kVlan));
    CHECK(m("vlan < 11 and vlan > 9", kVlan));
    CHECK_FALSE(m("vlan != 10", kVlan));
    CHECK_FALSE(m("vlan == 10", kUdp));
    CHECK_FALSE(m("vlan != 10", kUdp));
    CHECK(m("not vlan == 10", kUdp));
    // ip.proto: IPv4 protocol / IPv6 next header; false without IP
    CHECK(m("ip.proto == 6", kTcp));
    CHECK(m("ip.proto == 17", kUdp));
    CHECK(m("ip.proto == 17", kUdp6));
    CHECK(m("ip.proto == 1", kIcmp));
    CHECK(m("ip.proto == 0x11", kVlan));
    CHECK_FALSE(m("ip.proto == 6", kUdp));
    CHECK_FALSE(m("ip.proto != 6", kArp));
    CHECK_FALSE(m("ip.proto < 255", kArp));
    // tcp.seq / tcp.ack: raw 32-bit numbers, TCP only
    const Bytes big = tcp_frame("10.0.0.1", 1, "10.0.0.2", 2, 0xFFFFFFF0u, 77, ACK);
    CHECK(m("tcp.seq == 4294967280", big));
    CHECK(m("tcp.seq == 0xFFFFFFF0", big));
    CHECK(m("tcp.seq > 100 and tcp.ack == 77", big));
    CHECK(m("tcp.ack <= 77", big));
    CHECK_FALSE(m("tcp.ack == 78", big));
    CHECK(m("tcp.seq == 1", kTcp));
    CHECK_FALSE(m("tcp.seq == 1", kUdp));
    CHECK_FALSE(m("tcp.seq != 1", kUdp));
    // tcp.flags: the byte (kTcp has ACK | PSH = 0x18)
    CHECK(m("tcp.flags == 0x18", kTcp));
    CHECK(m("tcp.flags == 24", kTcp));
    CHECK(m("tcp.flags == ack+psh", kTcp));
    CHECK(m("tcp.flags == PSH+ACK", kTcp));
    CHECK_FALSE(m("tcp.flags == ack", kTcp));  // exactly ACK: no
    CHECK(m("tcp.flags != syn", kTcp));
    CHECK(m("tcp.flags > 0x10", kTcp));
    const Bytes synack = tcp_frame("10.0.0.2", 80, "10.0.0.1", 51000, 9, 1, SYN | ACK);
    CHECK(m("tcp.flags == syn+ack", synack));
    CHECK(m("tcp.flags == 0x12", synack));
    CHECK_FALSE(m("tcp.flags == syn", synack));
    CHECK_FALSE(m("tcp.flags == 0x12", kUdp));
    // tcp.flags.<name>: alone = set, == 1 / == 0
    CHECK(m("tcp.flags.syn", synack));
    CHECK(m("tcp.flags.ack and tcp.flags.syn", synack));
    CHECK_FALSE(m("tcp.flags.fin", synack));
    CHECK(m("not tcp.flags.fin", synack));
    CHECK(m("tcp.flags.fin == 0", synack));
    CHECK(m("tcp.flags.SYN == 1", synack));
    CHECK(m("tcp.flags.psh and tcp.flags.ack", kTcp));
    CHECK_FALSE(m("tcp.flags.syn", kTcp));
    CHECK_FALSE(m("tcp.flags.syn", kUdp));
    CHECK_FALSE(m("tcp.flags.syn == 0", kUdp));  // no TCP header: false either way
    for (const char* name : {"fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"}) {
        const int bit = int(std::string("fin syn rst psh ack urg ece cwr").find(name) / 4);
        const Bytes f = tcp_frame("10.0.0.1", 1, "10.0.0.2", 2, 1, 1, uint8_t(1u << bit));
        INFO(name);
        CHECK(m(std::string("tcp.flags.") + name, f));
        CHECK(m(std::string("tcp.flags == ") + name, f));
        CHECK(m("tcp.flags == " + std::to_string(1u << bit), f));
    }
    // errors
    CHECK(err_at("vlan == 4096", "out of range (0..4095)") == 8);
    CHECK(err_at("ip.proto == 256", "0..255") == 12);
    CHECK(err_at("tcp.seq == 4294967296", "0..4294967295") == 11);
    CHECK(err_at("tcp.flags == 256", "0..255") == 13);
    CHECK(err_at("tcp.flags == syn+bogus", "flag names") == 13);
    CHECK(err_at("tcp.flags == syn+", "flag names") == 13);
    CHECK(err_at("tcp.flags.syn == 2", "0 or 1") == 17);
    CHECK(err_at("tcp.flags.nope", "unknown TCP flag 'nope'") == 10);
    CHECK(err_at("tcp.flags.syn > ", "value") == 16);
}

TEST_CASE("pcap filter: frame.number (1-based; from filter_packets, unknown = false)") {
    std::vector<Bytes> frames;
    for (int i = 0; i < 10; ++i) frames.push_back(udp_frame("10.0.0.1", uint16_t(100 + i), "10.0.0.2", 53, str("q")));
    Capture cap(pcap_file(frames));
    REQUIRE(cap.packets().size() == 10);
    auto run = [&](const std::string& expr) {
        PacketFilter f;
        REQUIRE(f.parse(expr));
        std::vector<uint32_t> out;
        filter_packets(*cap.res->snap, cap.packets(), f, 0, cap.packets().size(), out);
        return out;
    };
    CHECK(run("frame.number == 1") == std::vector<uint32_t>{0});
    CHECK(run("frame.number >= 9") == std::vector<uint32_t>{8, 9});
    CHECK(run("frame.number > 2 and frame.number < 5") == std::vector<uint32_t>{2, 3});
    CHECK(run("frame.number != 1 and frame.number <= 3") == std::vector<uint32_t>{1, 2});
    CHECK(run("frame.number == 0").empty());
    CHECK(run("frame.number == 18446744073709551615").empty());
    // A sub-range still numbers by index
    PacketFilter f;
    REQUIRE(f.parse("frame.number == 6"));
    std::vector<uint32_t> part;
    filter_packets(*cap.res->snap, cap.packets(), f, 4, 8, part);
    CHECK(part == std::vector<uint32_t>{5});
    // match() without a number: frame.number is false for every operator
    CHECK_FALSE(m("frame.number == 0", kUdp));
    CHECK_FALSE(m("frame.number != 5", kUdp));
    CHECK(m("not frame.number == 1", kUdp));
    Packet p;
    const PacketInfo pi = dissect(kUdp.data(), kUdp.size(), kLinkEthernet);
    CHECK(f.match(p, pi, 6));
    CHECK_FALSE(f.match(p, pi, 7));
    CHECK(err_at("frame.number == x", "expected a number") == 16);
}

TEST_CASE("pcap filter: PacketFilterJob continues from `begin` with a prefix (live tail)") {
    std::vector<Bytes> frames;
    for (int i = 0; i < 100; ++i)
        frames.push_back(i % 2 ? udp_frame("10.0.0.1", 1, "10.0.0.2", 2, str("u")) : arp_frame());
    Capture cap(pcap_file(frames));
    PacketFilter f;
    REQUIRE(f.parse("udp"));
    std::vector<uint32_t> all;
    filter_packets(*cap.res->snap, cap.packets(), f, 0, 100, all);
    REQUIRE(all.size() == 50);
    // The prefix is taken as is (here: a marker value nobody would match) and only [60, 100) is tested.
    PacketFilterJob job;
    job.start(cap.res, f, 60, std::vector<uint32_t>{7777});
    const auto t0 = std::chrono::steady_clock::now();
    while (job.generation() == 0) {
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    auto r = job.result();
    REQUIRE(r);
    REQUIRE(r->matches.size() == 21);
    CHECK(r->matches[0] == 7777);
    CHECK(r->matches[1] == 61);
    CHECK(r->matches.back() == 99);
    CHECK(job.progress() == 1.0);
}
