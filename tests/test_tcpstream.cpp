// Tests for core/pcap_stream: TCP stream reassembly over synthetic pcap / pcapng captures (handshake,
// both directions, out-of-order / retransmitted / overlapping segments, sequence wraparound, gaps,
// connection reuse, caps), the stream document (sequential / interleaved + bookmarks), the job.
#include <doctest/doctest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <thread>
#include <vector>

#include "core/pcap.h"
#include "core/pcap_stream.h"
#include "pcap_fixture.h"

using namespace hx;
using namespace pcapfx;

namespace {

// Client 10.0.0.1:51000 <-> server 10.0.0.2:80 (or the IPv6 pair).
struct Conv {
    std::string c = "10.0.0.1", s = "10.0.0.2";
    uint16_t cp = 51000, sp = 80;
    std::vector<Bytes> frames;
    size_t c2s(uint32_t seq, uint32_t ack, uint8_t fl, const std::string& data = "") {
        frames.push_back(tcp_frame(c, cp, s, sp, seq, ack, fl, str(data)));
        return frames.size() - 1;
    }
    size_t s2c(uint32_t seq, uint32_t ack, uint8_t fl, const std::string& data = "") {
        frames.push_back(tcp_frame(s, sp, c, cp, seq, ack, fl, str(data)));
        return frames.size() - 1;
    }
    size_t other(const Bytes& f) {
        frames.push_back(f);
        return frames.size() - 1;
    }
};

std::string text(const TcpStreamDoc& d) { return std::string(d.bytes.begin(), d.bytes.end()); }

// Follows `packet` and builds the document (sequential or interleaved).
struct Followed {
    TcpStream s;
    TcpStreamDoc seq, inter;
    bool ok = false;
};
Followed follow(const Bytes& file, size_t packet, uint64_t max = kTcpStreamMax) {
    Capture cap(file);
    Followed f;
    f.ok = follow_tcp_stream(*cap.res->snap, cap.packets(), packet, f.s, max);
    if (f.ok) {
        build_tcp_stream_doc(*cap.res->snap, f.s, false, f.seq);
        build_tcp_stream_doc(*cap.res->snap, f.s, true, f.inter);
    }
    return f;
}

// The bytes of direction `dir` in delivery order.
std::string dir_text(const Followed& f, uint8_t dir) {
    std::string out;
    size_t pos = 0;
    for (const TcpStreamSegment& sg : f.s.segments) {
        if (sg.dir == dir) out += std::string(f.inter.bytes.begin() + std::ptrdiff_t(pos),
                                              f.inter.bytes.begin() + std::ptrdiff_t(pos + sg.len));
        pos += size_t(sg.len);
    }
    return out;
}

}  // namespace

TEST_CASE("tcp stream: handshake, both directions, FIN; pcap and pcapng (both byte orders)") {
    Conv v;
    v.other(udp_frame("10.0.0.9", 53, "10.0.0.1", 4000, str("noise")));
    v.c2s(1000, 0, SYN);
    v.s2c(5000, 1001, SYN | ACK);
    v.c2s(1001, 5001, ACK);
    const size_t get = v.c2s(1001, 5001, PSH | ACK, "GET /");
    v.other(tcp_frame("10.0.0.1", 51001, "10.0.0.2", 80, 1, 1, PSH | ACK, str("other connection")));
    const size_t resp = v.s2c(5001, 1006, PSH | ACK, "HTTP/1.1 200");
    const size_t more = v.c2s(1006, 5013, PSH | ACK, " more");
    v.s2c(5013, 1011, FIN | ACK);
    v.c2s(1011, 5014, FIN | ACK);
    v.s2c(5014, 1012, ACK);

    const Bytes files[] = {pcap_file(v.frames), pcapng_file(v.frames), pcapng_file(v.frames, true)};
    for (const Bytes& file : files) {
        for (size_t start : {get, resp, size_t(1)}) {  // any packet of the connection
            const Followed f = follow(file, start);
            REQUIRE(f.ok);
            CHECK(f.s.error.empty());
            CHECK(fmt_endpoint(f.s.client) == "10.0.0.1:51000");
            CHECK(fmt_endpoint(f.s.server) == "10.0.0.2:80");
            CHECK(f.s.packets == 9);
            CHECK(f.s.bytes[0] == 10);
            CHECK(f.s.bytes[1] == 12);
            CHECK(f.s.syn[0]);
            CHECK(f.s.syn[1]);
            CHECK(f.s.fin[0]);
            CHECK(f.s.fin[1]);
            CHECK_FALSE(f.s.rst);
            CHECK(f.s.retransmitted == 0);
            CHECK(f.s.out_of_order == 0);
            CHECK_FALSE(f.s.truncated);
            REQUIRE(f.s.segments.size() == 3);
            CHECK(f.s.segments[0].packet == get);
            CHECK(f.s.segments[0].dir == 0);
            CHECK(f.s.segments[0].stream_off == 0);
            CHECK(f.s.segments[1].packet == resp);
            CHECK(f.s.segments[1].dir == 1);
            CHECK(f.s.segments[2].packet == more);
            CHECK(f.s.segments[2].stream_off == 5);

            CHECK(text(f.seq) == "GET / moreHTTP/1.1 200");
            CHECK(text(f.inter) == "GET /HTTP/1.1 200 more");
            CHECK(f.seq.name == "TCP 10.0.0.1:51000 > 10.0.0.2:80");
            CHECK(f.inter.name == "TCP 10.0.0.1:51000 > 10.0.0.2:80 (interleaved)");
            REQUIRE(f.seq.bookmarks.size() == 3);
            const std::string n_get = "#" + std::to_string(get + 1), n_more = "#" + std::to_string(more + 1),
                              n_resp = "#" + std::to_string(resp + 1);
            CHECK(f.seq.bookmarks[0].name == n_get + " C>S");
            CHECK(f.seq.bookmarks[0].offset == 0);
            CHECK(f.seq.bookmarks[0].length == 5);
            CHECK(f.seq.bookmarks[1].name == n_more + " C>S");
            CHECK(f.seq.bookmarks[1].offset == 5);
            CHECK(f.seq.bookmarks[2].name == n_resp + " S>C");
            CHECK(f.seq.bookmarks[2].offset == 10);
            CHECK(f.seq.bookmarks[2].length == 12);
            CHECK(f.seq.bookmarks[0].color != f.seq.bookmarks[2].color);
            CHECK(f.seq.bookmarks[0].color == f.seq.bookmarks[1].color);
            CHECK(f.seq.bookmarks[1].note.find("stream offset 5") != std::string::npos);
            CHECK(f.seq.bookmarks[2].note.find("10.0.0.2:80 -> 10.0.0.1:51000") != std::string::npos);
            REQUIRE(f.inter.bookmarks.size() == 3);
            CHECK(f.inter.bookmarks[1].name == n_resp + " S>C");
            CHECK(f.inter.bookmarks[1].offset == 5);
            CHECK(f.inter.bookmarks[2].offset == 17);
            CHECK_FALSE(f.seq.bookmarks_capped);
        }
    }
}

TEST_CASE("tcp stream: out-of-order and overlapping queued segments") {
    Conv v;
    v.c2s(1000, 0, SYN);
    v.s2c(7000, 1001, SYN | ACK);
    const size_t b = v.c2s(1005, 7001, ACK, "4567");  // ahead of a gap
    v.c2s(1003, 7001, ACK, "2345");                    // ahead too, overlaps the one above
    const size_t srv = v.s2c(7001, 1001, ACK, "srv");  // delivered on arrival
    const size_t a = v.c2s(1001, 7004, ACK, "01");     // closes the gap
    v.c2s(1009, 7004, ACK, "89");
    const Followed f = follow(pcap_file(v.frames), b);
    REQUIRE(f.ok);
    CHECK(dir_text(f, 0) == "0123456789");
    CHECK(dir_text(f, 1) == "srv");
    CHECK(f.s.out_of_order == 2);
    CHECK(f.s.retransmitted == 0);
    CHECK(f.s.missing[0] == 0);
    REQUIRE(f.s.segments.size() == 5);
    CHECK(f.s.segments[0].packet == srv);  // delivery order: the server bytes came first
    CHECK(f.s.segments[1].packet == a);
    CHECK(f.s.segments[2].stream_off == 2);
    CHECK(f.s.segments[3].packet == b);    // only "67" of it was new
    CHECK(f.s.segments[3].len == 2);
    CHECK(f.s.segments[3].stream_off == 6);
    CHECK(text(f.inter) == "srv0123456789");
    CHECK(text(f.seq) == "0123456789srv");
    // The trimmed segment's bookmark covers only its new bytes.
    CHECK(f.seq.bookmarks[2].name == "#" + std::to_string(b + 1) + " C>S");
    CHECK(f.seq.bookmarks[2].offset == 6);
    CHECK(f.seq.bookmarks[2].length == 2);
}

TEST_CASE("tcp stream: retransmissions and partial overlaps deliver each byte once") {
    Conv v;
    v.c2s(1000, 0, SYN);
    v.s2c(3000, 1001, SYN | ACK);
    v.c2s(1001, 3001, ACK, "0123");
    v.c2s(1001, 3001, ACK, "0123");    // retransmission
    v.c2s(1003, 3001, ACK, "234567");  // overlap: "4567" new
    v.c2s(999, 3001, ACK, "xy");       // entirely old (before the stream start)
    v.c2s(1007, 3001, ACK, "6789");    // "89" new
    v.s2c(3001, 1011, ACK, "ok");
    v.s2c(3001, 1011, ACK, "ok");      // retransmission the other way
    v.c2s(1000, 0, SYN);               // retransmitted SYN: no data, no reset
    const Followed f = follow(pcapng_file(v.frames), 2);
    REQUIRE(f.ok);
    CHECK(text(f.seq) == "0123456789ok");
    CHECK(f.s.retransmitted == 3);
    REQUIRE(f.s.segments.size() == 4);
    CHECK(f.s.segments[1].stream_off == 4);
    CHECK(f.s.segments[1].len == 4);
    CHECK(f.s.segments[2].stream_off == 8);
    CHECK(f.s.segments[2].len == 2);
    CHECK(tcp_stream_summary(f.s).find("3 retransmitted") != std::string::npos);
}

TEST_CASE("tcp stream: sequence numbers wrap around 2^32") {
    Conv v;
    v.c2s(0xFFFFFFF8u, 0, SYN);
    v.s2c(0xFFFFFFFEu, 0xFFFFFFF9u, SYN | ACK);  // server data starts at 0xFFFFFFFF
    v.c2s(0xFFFFFFF9u, 0xFFFFFFFFu, ACK, "abcdefg");  // up to 0xFFFFFFFF
    v.c2s(0x00000000u, 0xFFFFFFFFu, ACK, "hij");      // continues after the wrap
    v.s2c(0xFFFFFFFFu, 3, ACK, "XY");                 // wraps inside the segment
    v.c2s(0x00000006u, 1, ACK, "pq");                 // out of order after the wrap
    v.c2s(0x00000003u, 1, ACK, "klm");
    v.s2c(0x00000001u, 8, ACK, "Z");
    v.c2s(0xFFFFFFFAu, 2, ACK, "bc");                 // retransmission from before the wrap
    for (bool ng : {false, true}) {
        const Followed f = follow(ng ? pcapng_file(v.frames, true) : pcap_file(v.frames), 4);
        REQUIRE(f.ok);
        CHECK(dir_text(f, 0) == "abcdefghijklmpq");
        CHECK(dir_text(f, 1) == "XYZ");
        CHECK(f.s.retransmitted == 1);
        CHECK(f.s.out_of_order == 1);
        CHECK(f.s.missing[0] + f.s.missing[1] == 0);
        CHECK(text(f.seq) == "abcdefghijklmpqXYZ");
    }
}

TEST_CASE("tcp stream: a gap is skipped once the peer acknowledges past it, else at the end") {
    Conv v;
    v.c2s(1000, 0, SYN);
    v.s2c(2000, 1001, SYN | ACK);
    v.c2s(1001, 2001, ACK, "AAAA");
    // 1005 "BBBB" never captured
    const size_t c = v.c2s(1009, 2001, ACK, "CCCC");
    v.s2c(2001, 1013, ACK);           // acknowledges everything: the gap is gone for good
    v.s2c(2001, 1013, ACK, "srv");
    v.c2s(1013, 2004, ACK, "DD");
    const Followed f = follow(pcap_file(v.frames), c);
    REQUIRE(f.ok);
    CHECK(text(f.inter) == "AAAACCCCsrvDD");  // CCCC before the server's answer
    CHECK(f.s.missing[0] == 4);
    REQUIRE(f.s.segments.size() == 4);
    CHECK(f.s.segments[1].gap_before == 4);
    CHECK(f.s.segments[1].stream_off == 8);
    CHECK(f.inter.bookmarks[1].note.find("4 bytes missing") != std::string::npos);
    CHECK(tcp_stream_summary(f.s).find("4 bytes not captured") != std::string::npos);

    // Never acknowledged: delivered at the end of the capture.
    Conv w;
    w.c2s(1000, 0, SYN);
    w.c2s(1001, 0, ACK, "AA");
    w.c2s(1005, 0, ACK, "CC");
    w.s2c(5000, 1003, ACK, "srv");  // acks only what it got
    const Followed g = follow(pcap_file(w.frames), 1);
    REQUIRE(g.ok);
    CHECK(text(g.inter) == "AAsrvCC");
    CHECK(g.s.missing[0] == 2);
    CHECK(g.s.segments.back().gap_before == 2);
}

TEST_CASE("tcp stream: no SYN (capture started mid-connection): the first sender is the client") {
    Conv v;
    v.c2s(77777, 88888, ACK | PSH, "req");
    v.s2c(88888, 77780, ACK | PSH, "resp");
    v.c2s(77780, 88892, ACK | PSH, "req2");
    const Followed f = follow(pcap_file(v.frames), 1);  // a server packet: directions are flipped
    REQUIRE(f.ok);
    CHECK(fmt_endpoint(f.s.client) == "10.0.0.1:51000");
    CHECK(text(f.seq) == "reqreq2resp");
    CHECK(f.s.segments[0].dir == 0);
    CHECK(f.s.segments[1].dir == 1);
    CHECK(f.seq.bookmarks[2].name == "#2 S>C");
    CHECK(tcp_stream_summary(f.s).find("no SYN") != std::string::npos);
    // A SYN+ACK seen first names its receiver the client.
    Conv w;
    w.s2c(500, 101, SYN | ACK);
    w.c2s(101, 501, ACK, "hi");
    const Followed g = follow(pcap_file(w.frames), 0);
    REQUIRE(g.ok);
    CHECK(fmt_endpoint(g.s.client) == "10.0.0.1:51000");
    CHECK(g.s.bytes[0] == 2);
}

TEST_CASE("tcp stream: SYN data (Fast Open), RST, max_bytes cap, bookmark cap") {
    Conv v;
    v.c2s(1000, 0, SYN, "hello");
    v.s2c(9000, 1006, SYN | ACK);
    v.c2s(1006, 9001, ACK, "world");
    v.s2c(9001, 1011, RST | ACK, "ignored");
    const Followed f = follow(pcap_file(v.frames), 0);
    REQUIRE(f.ok);
    CHECK(text(f.seq) == "helloworld");
    CHECK(f.s.rst);
    CHECK(tcp_stream_summary(f.s).find("reset") != std::string::npos);

    const Followed cut = follow(pcap_file(v.frames), 0, 7);
    REQUIRE(cut.ok);
    CHECK(cut.s.truncated);
    CHECK(text(cut.seq) == "hellowo");
    CHECK(tcp_stream_summary(cut.s).find("cut at 7 bytes") != std::string::npos);

    Capture cap(pcap_file(v.frames));
    TcpStream s;
    REQUIRE(follow_tcp_stream(*cap.res->snap, cap.packets(), 0, s));
    TcpStreamDoc d;
    build_tcp_stream_doc(*cap.res->snap, s, false, d, 1);
    CHECK(d.bookmarks.size() == 1);
    CHECK(d.bookmarks_capped);
    CHECK(text(d) == "helloworld");
}

TEST_CASE("tcp stream: a new SYN after the close starts the next connection on the same ports") {
    Conv v;
    const size_t c1 = v.c2s(1000, 0, SYN);
    v.s2c(5000, 1001, SYN | ACK);
    v.c2s(1001, 5001, ACK, "one");
    v.c2s(1004, 5001, FIN | ACK);
    v.s2c(5001, 1005, FIN | ACK);
    v.c2s(1005, 5002, ACK);
    const size_t c2 = v.c2s(90000, 0, SYN);
    v.s2c(70000, 90001, SYN | ACK);
    const size_t d2 = v.c2s(90001, 70001, ACK, "two");
    v.s2c(70001, 90004, ACK, "2");
    for (size_t p : {c1, size_t(2), size_t(5)}) {
        const Followed f = follow(pcap_file(v.frames), p);
        REQUIRE(f.ok);
        CHECK(text(f.seq) == "one");
        CHECK(f.s.packets == 6);
    }
    for (size_t p : {c2, d2, v.frames.size() - 1}) {
        const Followed f = follow(pcap_file(v.frames), p);
        REQUIRE(f.ok);
        CHECK(text(f.seq) == "two2");
        CHECK(f.s.packets == 4);
        CHECK(f.seq.bookmarks[0].name == "#" + std::to_string(d2 + 1) + " C>S");
    }
}

TEST_CASE("tcp stream: IPv6 connection; errors for non-TCP packets") {
    Conv v;
    v.c = "2001:db8::1";
    v.s = "2001:db8::2";
    v.cp = 40000;
    v.sp = 443;
    v.c2s(1, 0, SYN);
    v.s2c(1, 2, SYN | ACK);
    v.c2s(2, 2, ACK, "hello v6");
    v.other(udp_frame("10.0.0.1", 1, "10.0.0.2", 2, str("udp")));
    const Followed f = follow(pcapng_file(v.frames), 2);
    REQUIRE(f.ok);
    CHECK(fmt_endpoint(f.s.client) == "[2001:db8::1]:40000");
    CHECK(f.seq.name == "TCP [2001:db8::1]:40000 > [2001:db8::2]:443");
    CHECK(text(f.seq) == "hello v6");

    Capture cap(pcapng_file(v.frames));
    TcpStream s;
    CHECK_FALSE(follow_tcp_stream(*cap.res->snap, cap.packets(), 3, s));
    CHECK(s.error == "packet #4 is not a TCP packet");
    CHECK_FALSE(follow_tcp_stream(*cap.res->snap, cap.packets(), 99, s));
    CHECK_FALSE(s.error.empty());
}

TEST_CASE("tcp stream: IPv6 payload length 0 (segmentation offload / jumbogram) takes the whole packet") {
    // An offloaded IPv6 segment bigger than the dissector's header window: the payload runs to the
    // end of the captured packet, not to the end of the window.
    Conv v;
    v.c = "2001:db8::1";
    v.s = "2001:db8::2";
    v.c2s(1, 0, SYN);
    v.s2c(1, 2, SYN | ACK);
    std::string big;
    for (int i = 0; i < 3000; ++i) big += char('a' + i % 26);
    const size_t data = v.c2s(2, 2, PSH | ACK, big);
    v.frames[data][14 + 4] = 0;  // IPv6 payload length
    v.frames[data][14 + 5] = 0;
    v.c2s(3002, 2, PSH | ACK, "tail");
    const Followed f = follow(pcap_file(v.frames), data);
    REQUIRE(f.ok);
    CHECK(f.s.bytes[0] == 3004);
    CHECK(f.s.missing[0] == 0);
    CHECK(text(f.seq) == big + "tail");
}

TEST_CASE("tcp stream: TcpStreamJob follows and builds in the background") {
    Conv v;
    v.c2s(10, 0, SYN);
    v.s2c(20, 11, SYN | ACK);
    for (int i = 0; i < 500; ++i) v.c2s(uint32_t(11 + 4 * i), 21, ACK, "abcd");
    Capture cap(pcapng_file(v.frames));
    TcpStreamJob job;
    job.start(cap.res, 5, true);
    const auto t0 = std::chrono::steady_clock::now();
    while (job.generation() == 0) {
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    auto r = job.result();
    REQUIRE(r);
    CHECK(r->interleaved);
    CHECK(r->packet == 5);
    CHECK(r->stream.error.empty());
    CHECK(r->doc.bytes.size() == 2000);
    CHECK(r->doc.bookmarks.size() == 500);
    CHECK(r->doc.name.find("(interleaved)") != std::string::npos);
    job.clear_result();
    CHECK_FALSE(job.result());

    job.start(cap.res, 0, false);  // the SYN: still the connection
    while (job.generation() == 1) {
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    REQUIRE(job.result());
    CHECK(job.result()->doc.bytes.size() == 2000);
}
