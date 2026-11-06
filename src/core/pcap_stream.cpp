#include "core/pcap_stream.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "core/highlight.h"

namespace hx {

bool TcpEndpoint::operator==(const TcpEndpoint& o) const {
    return ip_version == o.ip_version && port == o.port && std::memcmp(addr, o.addr, 16) == 0;
}

std::string fmt_endpoint(const TcpEndpoint& e) {
    if (e.ip_version == 6) return "[" + fmt_ipv6(e.addr) + "]:" + std::to_string(e.port);
    return fmt_ipv4(e.addr) + ":" + std::to_string(e.port);
}

namespace {

constexpr size_t kHeaderRead = 512;  // bytes dissected per packet to find its TCP header

std::string fmt_count(uint64_t v) {
    std::string s = std::to_string(v);
    for (int i = int(s.size()) - 3; i > 0; i -= 3) s.insert(size_t(i), ",");
    return s;
}

// Dissects the headers of `p`; `len` = captured L7 bytes (TCP payload) at p.data_off + payload_off.
PacketInfo headers(const Snapshot& snap, const Packet& p, uint64_t& len) {
    PacketInfo pi = dissect_packet(snap, p, kHeaderRead);
    // A bogus IPv4 total length or an IPv6 payload length of 0 (segmentation offload, jumbogram)
    // makes the payload end at the read window: look at the whole packet then.
    if ((pi.malformed || pi.payload_off + pi.length == kHeaderRead) && p.cap_len > kHeaderRead)
        pi = dissect_packet(snap, p, p.cap_len);
    len = pi.payload_off < p.cap_len ? std::min<uint64_t>(pi.length, p.cap_len - pi.payload_off) : 0;
    return pi;
}

TcpEndpoint endpoint(const PacketInfo& pi, bool src) {
    TcpEndpoint e;
    e.ip_version = pi.ip_version;
    std::memcpy(e.addr, src ? pi.ip_src : pi.ip_dst, 16);
    e.port = src ? pi.src_port : pi.dst_port;
    return e;
}

struct Seg {
    size_t packet = 0;
    uint64_t data_off = 0;
    uint64_t len = 0;
};

struct Dir {
    bool started = false;
    int64_t next = 0;   // next expected (unwrapped) sequence number
    int64_t base = 0;   // sequence number of the first data byte
    std::map<int64_t, Seg> ooo;  // segments ahead of a gap, by unwrapped sequence number
    // The 64-bit sequence number closest to `next` with these low 32 bits.
    int64_t unwrap(uint32_t s) const { return next + int64_t(int32_t(s - uint32_t(uint64_t(next)))); }
};

class Reassembler {
public:
    Reassembler(TcpStream& s, uint64_t max) : s_(s), max_(max) {}

    void reset() {
        d_[0] = Dir{};
        d_[1] = Dir{};
        total_ = 0;
        stop_ = false;
    }
    Dir& dir(int i) { return d_[i]; }
    bool stopped() const { return stop_; }

    // Segment [seq, seq + len) of direction `di`.
    void add(int di, int64_t seq, const Seg& sg) {
        Dir& d = d_[di];
        const int64_t end = seq + int64_t(sg.len);
        if (end <= d.next) {
            ++s_.retransmitted;
            return;
        }
        if (seq > d.next) {
            auto it = d.ooo.find(seq);
            if (it == d.ooo.end() || it->second.len < sg.len) d.ooo[seq] = sg;
            ++s_.out_of_order;
            return;
        }
        deliver(di, sg, uint64_t(d.next - seq), 0);
        flush(di, 0);
    }

    // Delivers queued segments below `limit`, skipping the gaps before them.
    void skip_gaps(int di, int64_t limit) {
        Dir& d = d_[di];
        while (!stop_ && !d.ooo.empty() && d.ooo.begin()->first < limit) {
            const int64_t st = d.ooo.begin()->first;
            uint64_t gap = 0;
            if (st > d.next) {
                gap = uint64_t(st - d.next);
                s_.missing[di] += gap;
                d.next = st;
            }
            flush(di, gap);
        }
    }

private:
    // Queued segments that now continue the stream.
    void flush(int di, uint64_t gap) {
        Dir& d = d_[di];
        while (!stop_ && !d.ooo.empty() && d.ooo.begin()->first <= d.next) {
            const int64_t st = d.ooo.begin()->first;
            const Seg sg = d.ooo.begin()->second;
            d.ooo.erase(d.ooo.begin());
            if (st + int64_t(sg.len) <= d.next) continue;  // covered by what was delivered meanwhile
            deliver(di, sg, uint64_t(d.next - st), gap);
            gap = 0;
        }
    }
    // Bytes [skip, len) of `sg` continue direction `di` at d.next.
    void deliver(int di, const Seg& sg, uint64_t skip, uint64_t gap) {
        Dir& d = d_[di];
        uint64_t len = sg.len - skip;
        if (len > max_ - total_) {
            len = max_ - total_;
            s_.truncated = true;
            stop_ = true;
        }
        if (len == 0) return;
        TcpStreamSegment out;
        out.packet = sg.packet;
        out.dir = uint8_t(di);
        out.data_off = sg.data_off + skip;
        out.len = len;
        out.stream_off = uint64_t(d.next - d.base);
        out.gap_before = gap;
        s_.segments.push_back(out);
        d.next += int64_t(len);
        s_.bytes[di] += len;
        total_ += len;
    }

    TcpStream& s_;
    uint64_t max_;
    Dir d_[2];
    uint64_t total_ = 0;
    bool stop_ = false;
};

// Directions were counted from endpoint a; `client` (0 = a, 1 = b) becomes direction 0.
void orient(TcpStream& out, int client, const TcpEndpoint& a, const TcpEndpoint& b) {
    out.client = client == 0 ? a : b;
    out.server = client == 0 ? b : a;
    if (client != 1) return;
    for (TcpStreamSegment& sg : out.segments) sg.dir ^= 1;
    std::swap(out.bytes[0], out.bytes[1]);
    std::swap(out.missing[0], out.missing[1]);
    std::swap(out.syn[0], out.syn[1]);
    std::swap(out.fin[0], out.fin[1]);
}

// A UDP datagram with ports that is not an IP fragment.
bool is_udp(const PacketInfo& pi) { return pi.has_ports && pi.proto == "UDP" && !pi.fragment; }

}  // namespace

bool follow_tcp_stream(const Snapshot& snap, const std::vector<Packet>& packets, size_t packet, TcpStream& out,
                       uint64_t max_bytes, const std::atomic<bool>* cancel, std::atomic<uint64_t>* done) {
    out = TcpStream{};
    if (packet >= packets.size()) {
        out.error = "no such packet";
        return false;
    }
    uint64_t len0 = 0;
    const PacketInfo pi0 = headers(snap, packets[packet], len0);
    if (!pi0.tcp_header || pi0.fragment) {
        out.error = "packet #" + std::to_string(packet + 1) + " is not a TCP packet";
        return false;
    }
    const TcpEndpoint a = endpoint(pi0, true), b = endpoint(pi0, false);
    Reassembler re(out, max_bytes);
    int client = -1, first = -1;  // 0 = a, 1 = b
    for (size_t i = 0; i < packets.size(); ++i) {
        if ((i & 255) == 0) {
            if (cancel && cancel->load(std::memory_order_relaxed)) {
                out.cancelled = true;
                return false;
            }
            if (done) done->store(i, std::memory_order_relaxed);
        }
        uint64_t len = 0;
        const PacketInfo pi = headers(snap, packets[i], len);
        if (!pi.tcp_header || pi.fragment) continue;
        const TcpEndpoint src = endpoint(pi, true), dst = endpoint(pi, false);
        int di = -1;
        if (src == a && dst == b) di = 0;
        else if (src == b && dst == a) di = 1;
        if (di < 0) continue;
        const bool syn = (pi.tcp_flags & 0x02) != 0, ack = (pi.tcp_flags & 0x10) != 0,
                   fin = (pi.tcp_flags & 0x01) != 0, rst = (pi.tcp_flags & 0x04) != 0;
        if (syn && !ack && (out.fin[0] || out.fin[1] || out.rst)) {  // the next connection on these ports
            if (i > packet) break;
            out = TcpStream{};
            re.reset();
            client = first = -1;
        }
        ++out.packets;
        if (first < 0) first = di;
        if (client < 0 && syn) client = ack ? 1 - di : di;
        Dir& d = re.dir(di);
        if (syn) out.syn[di] = true;
        if (rst) out.rst = true;
        if (!d.started && (syn || (len > 0 && !rst))) {
            d.started = true;
            d.next = int64_t(pi.tcp_seq) + (syn ? 1 : 0);
            d.base = d.next;
        }
        if (d.started && len > 0 && !rst) {
            Seg sg;
            sg.packet = i;
            sg.data_off = packets[i].data_off + pi.payload_off;
            sg.len = len;
            re.add(di, d.unwrap(pi.tcp_seq) + (syn ? 1 : 0), sg);
        }
        if (fin) out.fin[di] = true;
        // The peer acknowledged bytes the capture never got: skip that gap.
        Dir& o = re.dir(1 - di);
        if (ack && o.started && !o.ooo.empty()) {
            const int64_t acked = o.unwrap(pi.tcp_ack);
            if (acked > o.next) re.skip_gaps(1 - di, acked);
        }
        if (re.stopped()) break;
    }
    re.skip_gaps(0, INT64_MAX);
    re.skip_gaps(1, INT64_MAX);
    if (done) done->store(packets.size(), std::memory_order_relaxed);
    if (client < 0) client = first < 0 ? 0 : first;
    orient(out, client, a, b);
    return true;
}

bool follow_udp_stream(const Snapshot& snap, const std::vector<Packet>& packets, size_t packet, TcpStream& out,
                       uint64_t max_bytes, const std::atomic<bool>* cancel, std::atomic<uint64_t>* done) {
    out = TcpStream{};
    out.udp = true;
    if (packet >= packets.size()) {
        out.error = "no such packet";
        return false;
    }
    uint64_t len0 = 0;
    const PacketInfo pi0 = headers(snap, packets[packet], len0);
    if (!is_udp(pi0)) {
        out.error = "packet #" + std::to_string(packet + 1) + " is not a UDP packet";
        return false;
    }
    const TcpEndpoint a = endpoint(pi0, true), b = endpoint(pi0, false);
    int client = -1;  // 0 = a, 1 = b
    uint64_t total = 0;
    for (size_t i = 0; i < packets.size(); ++i) {
        if ((i & 255) == 0) {
            if (cancel && cancel->load(std::memory_order_relaxed)) {
                out.cancelled = true;
                return false;
            }
            if (done) done->store(i, std::memory_order_relaxed);
        }
        uint64_t len = 0;
        const PacketInfo pi = headers(snap, packets[i], len);
        if (!is_udp(pi)) continue;
        const TcpEndpoint src = endpoint(pi, true), dst = endpoint(pi, false);
        int di = -1;
        if (src == a && dst == b) di = 0;
        else if (src == b && dst == a) di = 1;
        if (di < 0) continue;
        if (client < 0) client = di;
        ++out.packets;
        if (len > max_bytes - total) {
            len = max_bytes - total;
            out.truncated = true;
        }
        if (len) {
            TcpStreamSegment sg;
            sg.packet = i;
            sg.dir = uint8_t(di);
            sg.data_off = packets[i].data_off + pi.payload_off;
            sg.len = len;
            sg.stream_off = out.bytes[di];
            out.segments.push_back(sg);
            out.bytes[di] += len;
            total += len;
        }
        if (out.truncated) break;
    }
    if (done) done->store(packets.size(), std::memory_order_relaxed);
    orient(out, client < 0 ? 0 : client, a, b);
    return true;
}

void build_tcp_stream_doc(const Snapshot& snap, const TcpStream& s, bool interleaved, TcpStreamDoc& out,
                          size_t max_bookmarks) {
    out = TcpStreamDoc{};
    out.name = (s.udp ? "UDP " : "TCP ") + fmt_endpoint(s.client) + " > " + fmt_endpoint(s.server) + (interleaved ? " (interleaved)" : "");
    std::vector<const TcpStreamSegment*> order;
    order.reserve(s.segments.size());
    for (int pass = 0; pass < (interleaved ? 1 : 2); ++pass)
        for (const TcpStreamSegment& sg : s.segments)
            if (interleaved || sg.dir == pass) order.push_back(&sg);
    uint64_t total = 0;
    for (const TcpStreamSegment* sg : order) total += sg->len;
    out.bytes.resize(size_t(total));
    const std::string ends[2] = {fmt_endpoint(s.client) + " -> " + fmt_endpoint(s.server),
                                 fmt_endpoint(s.server) + " -> " + fmt_endpoint(s.client)};
    uint64_t pos = 0;
    for (const TcpStreamSegment* sg : order) {
        snap.read(sg->data_off, out.bytes.data() + pos, size_t(sg->len));
        if (out.bookmarks.size() < max_bookmarks) {
            Bookmark bm;
            bm.offset = pos;
            bm.length = sg->len;
            bm.name = "#" + std::to_string(sg->packet + 1) + (sg->dir == 0 ? " C>S" : " S>C");
            bm.color = sg->dir == 0 ? rgba(0xE8, 0x70, 0x70) : rgba(0x6A, 0xA8, 0xF0);
            bm.note = "packet " + std::to_string(sg->packet + 1) + ", " + (sg->dir == 0 ? "client" : "server") +
                      " (" + ends[sg->dir] + "), stream offset " + std::to_string(sg->stream_off) + ", " +
                      std::to_string(sg->len) + " bytes";
            if (sg->gap_before) bm.note += "; " + std::to_string(sg->gap_before) + " bytes missing before it";
            out.bookmarks.push_back(std::move(bm));
        } else {
            out.bookmarks_capped = true;
        }
        pos += sg->len;
    }
}

std::string tcp_stream_summary(const TcpStream& s) {
    std::string m = fmt_count(s.bytes[0]) + " bytes client -> server, " + fmt_count(s.bytes[1]) +
                    " bytes server -> client, ";
    if (s.udp) {
        m += fmt_count(s.packets) + " datagrams";
        if (s.truncated) m += "; cut at " + fmt_count(s.bytes[0] + s.bytes[1]) + " bytes (stream size limit)";
        return m;
    }
    m += fmt_count(s.segments.size()) + " segments of " + fmt_count(s.packets) + " packets";
    if (s.retransmitted) m += ", " + fmt_count(s.retransmitted) + " retransmitted";
    if (s.out_of_order) m += ", " + fmt_count(s.out_of_order) + " out of order";
    if (s.missing[0] + s.missing[1]) m += ", " + fmt_count(s.missing[0] + s.missing[1]) + " bytes not captured";
    if (!s.syn[0] && !s.syn[1]) m += ", no SYN (capture started mid-connection)";
    if (s.rst) m += ", reset";
    if (s.truncated) m += "; cut at " + fmt_count(s.bytes[0] + s.bytes[1]) + " bytes (stream size limit)";
    return m;
}

void TcpStreamJob::start(std::shared_ptr<const PcapIndexJob::Result> index, size_t packet, bool interleaved,
                         uint64_t max_bytes, bool udp) {
    const uint64_t total = index ? index->index.packets.size() : 0;
    w_.start(total, [index = std::move(index), packet, interleaved, max_bytes, udp](
                        TcpStreamJobResult& r, const std::atomic<bool>& cancel, std::atomic<uint64_t>& done) {
        r.packet = packet;
        r.interleaved = interleaved;
        r.stream.udp = udp;
        if (!index || !index->snap) {
            r.stream.error = "no packet index";
            return;
        }
        const Snapshot& snap = *index->snap;
        const std::vector<Packet>& ps = index->index.packets;
        if (udp ? follow_udp_stream(snap, ps, packet, r.stream, max_bytes, &cancel, &done)
                : follow_tcp_stream(snap, ps, packet, r.stream, max_bytes, &cancel, &done))
            build_tcp_stream_doc(snap, r.stream, interleaved, r.doc);
    });
}

// ---- conversations ------------------------------------------------------------------------------

void number_conversations(const Snapshot& snap, const std::vector<Packet>& packets, Conversations& t,
                          const std::atomic<bool>* cancel, std::atomic<uint64_t>* done) {
    const size_t begin = std::min(t.stream.size(), packets.size());
    t.stream.resize(begin);
    t.is_udp.resize(begin);
    t.stream.reserve(packets.size());
    t.is_udp.reserve(packets.size());
    std::string key;
    for (size_t i = begin; i < packets.size(); ++i) {
        if (((i - begin) & 255) == 0) {
            if (cancel && cancel->load(std::memory_order_relaxed)) return;
            if (done) done->store(i - begin, std::memory_order_relaxed);
        }
        const PacketInfo pi = dissect_packet(snap, packets[i], kHeaderRead);
        const bool tcp = pi.tcp_header && !pi.fragment, udp = is_udp(pi);
        uint32_t id = kNoStream;
        if (tcp || udp) {
            // proto + the two endpoints in a fixed order (both directions = one key)
            uint8_t e[2][19];
            for (int k = 0; k < 2; ++k) {
                e[k][0] = pi.ip_version;
                std::memcpy(e[k] + 1, k == 0 ? pi.ip_src : pi.ip_dst, 16);
                const uint16_t port = k == 0 ? pi.src_port : pi.dst_port;
                e[k][17] = uint8_t(port >> 8);
                e[k][18] = uint8_t(port);
            }
            const int lo = std::memcmp(e[0], e[1], 19) <= 0 ? 0 : 1;
            key.assign(1, udp ? 'u' : 't');
            key.append(reinterpret_cast<const char*>(e[lo]), 19);
            key.append(reinterpret_cast<const char*>(e[1 - lo]), 19);
            auto it = t.ids.find(key);
            if (it == t.ids.end()) it = t.ids.emplace(key, t.count[udp ? 1 : 0]++).first;
            id = it->second;
        }
        t.stream.push_back(id);
        t.is_udp.push_back(udp ? 1 : 0);
    }
    if (done) done->store(packets.size() - begin, std::memory_order_relaxed);
}

void ConversationJob::start(std::shared_ptr<const PcapIndexJob::Result> index,
                            std::shared_ptr<const ConversationJobResult> prev) {
    const size_t n = index ? index->index.packets.size() : 0;
    const size_t from = prev ? std::min(prev->conv.stream.size(), n) : 0;
    w_.start(n - from, [index = std::move(index), prev = std::move(prev)](
                           ConversationJobResult& r, const std::atomic<bool>& cancel, std::atomic<uint64_t>& done) {
        r.index = index;
        if (prev) r.conv = prev->conv;
        if (index && index->snap) number_conversations(*index->snap, index->index.packets, r.conv, &cancel, &done);
        r.cancelled = cancel.load();
    });
}

}  // namespace hx
