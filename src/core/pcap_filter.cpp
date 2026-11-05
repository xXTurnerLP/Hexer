#include "core/pcap_filter.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace hx {

namespace {

std::string lower(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    return s;
}

bool is_word_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' ||
           c == ':' || c == '/';
}

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Decimal or 0x hex, no sign; false on junk or overflow.
bool parse_uint(const std::string& s, uint64_t& v) {
    v = 0;
    if (s.empty()) return false;
    const bool hex = s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
    const unsigned base = hex ? 16 : 10;
    for (size_t i = hex ? 2 : 0; i < s.size(); ++i) {
        const int d = hex_digit(s[i]);
        if (d < 0 || unsigned(d) >= base) return false;
        if (v > (UINT64_MAX - uint64_t(d)) / base) return false;
        v = v * base + uint64_t(d);
    }
    return true;
}

bool parse_ipv4(const std::string& s, uint8_t* out) {
    size_t pos = 0;
    for (int i = 0; i < 4; ++i) {
        if (i && (pos >= s.size() || s[pos++] != '.')) return false;
        unsigned v = 0, digits = 0;
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9' && digits < 4) {
            v = v * 10 + unsigned(s[pos++] - '0');
            ++digits;
        }
        if (digits == 0 || digits > 3 || v > 255) return false;
        out[i] = uint8_t(v);
    }
    return pos == s.size();
}

// Groups of one side of "::" -> 16-bit words (an IPv4 tail counts as two). False on junk.
bool ipv6_groups(const std::string& s, std::vector<uint16_t>& out, bool allow_v4_tail) {
    if (s.empty()) return true;
    size_t pos = 0;
    while (true) {
        size_t end = s.find(':', pos);
        const std::string g = s.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
        if (end == std::string::npos && allow_v4_tail && g.find('.') != std::string::npos) {
            uint8_t v4[4];
            if (!parse_ipv4(g, v4)) return false;
            out.push_back(uint16_t(v4[0] << 8 | v4[1]));
            out.push_back(uint16_t(v4[2] << 8 | v4[3]));
            return true;
        }
        if (g.empty() || g.size() > 4) return false;
        unsigned v = 0;
        for (char c : g) {
            const int d = hex_digit(c);
            if (d < 0) return false;
            v = v * 16 + unsigned(d);
        }
        out.push_back(uint16_t(v));
        if (end == std::string::npos) return true;
        pos = end + 1;
    }
}

bool parse_ipv6(const std::string& s, uint8_t* out) {
    std::vector<uint16_t> head, tail;
    const size_t dc = s.find("::");
    if (dc != std::string::npos) {
        if (s.find("::", dc + 1) != std::string::npos) return false;
        if (!ipv6_groups(s.substr(0, dc), head, false) || !ipv6_groups(s.substr(dc + 2), tail, true)) return false;
        if (head.size() + tail.size() > 7) return false;
    } else {
        if (!ipv6_groups(s, head, true) || head.size() != 8) return false;
    }
    std::vector<uint16_t> words(8, 0);
    for (size_t i = 0; i < head.size(); ++i) words[i] = head[i];
    for (size_t i = 0; i < tail.size(); ++i) words[8 - tail.size() + i] = tail[i];
    for (size_t i = 0; i < 8; ++i) {
        out[2 * i] = uint8_t(words[i] >> 8);
        out[2 * i + 1] = uint8_t(words[i]);
    }
    return true;
}

// ---- tokens ----

enum class Tok : uint8_t { End, Word, Text, LParen, RParen, Op, And, Or, Not };

struct Token {
    Tok kind = Tok::End;
    size_t pos = 0;
    std::string text;  // as written (Text: unquoted)
    PacketFilter::Op op = PacketFilter::Op::Eq;
};

bool tokenize(const std::string& s, std::vector<Token>& out, std::string& err, size_t& err_pos) {
    size_t i = 0;
    while (true) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) ++i;
        Token t;
        t.pos = i;
        if (i >= s.size()) {
            out.push_back(t);
            return true;
        }
        const char c = s[i];
        const char n = i + 1 < s.size() ? s[i + 1] : '\0';
        using Op = PacketFilter::Op;
        auto op = [&](Op o, size_t len) {
            t.kind = Tok::Op;
            t.op = o;
            t.text = s.substr(i, len);
            i += len;
        };
        if (c == '(') t.kind = Tok::LParen, t.text = "(", ++i;
        else if (c == ')') t.kind = Tok::RParen, t.text = ")", ++i;
        else if (c == '=' && n == '=') op(Op::Eq, 2);
        else if (c == '!' && n == '=') op(Op::Ne, 2);
        else if (c == '<' && n == '=') op(Op::Le, 2);
        else if (c == '>' && n == '=') op(Op::Ge, 2);
        else if (c == '<') op(Op::Lt, 1);
        else if (c == '>') op(Op::Gt, 1);
        else if (c == '!') t.kind = Tok::Not, t.text = "!", ++i;
        else if (c == '&' && n == '&') t.kind = Tok::And, t.text = "&&", i += 2;
        else if (c == '|' && n == '|') t.kind = Tok::Or, t.text = "||", i += 2;
        else if (c == '=') {
            err = "use == to compare";
            err_pos = i;
            return false;
        } else if (c == '"') {
            size_t j = i + 1;
            std::string v;
            while (j < s.size() && s[j] != '"') {
                if (s[j] == '\\' && j + 1 < s.size()) ++j;
                v += s[j++];
            }
            if (j >= s.size()) {
                err = "unterminated \"text\"";
                err_pos = i;
                return false;
            }
            t.kind = Tok::Text;
            t.text = v;
            i = j + 1;
        } else if (is_word_char(c)) {
            size_t j = i;
            while (j < s.size() && is_word_char(s[j])) ++j;
            t.text = s.substr(i, j - i);
            const std::string w = lower(t.text);
            t.kind = w == "and" ? Tok::And : w == "or" ? Tok::Or : w == "not" ? Tok::Not : Tok::Word;
            i = j;
        } else {
            err = std::string("unexpected '") + c + "'";
            err_pos = i;
            return false;
        }
        out.push_back(std::move(t));
    }
}

// ---- parser ----

constexpr int kMaxDepth = 64;
// Nodes of one filter. match() recurses through the tree, and a flat "a or b or c ..." chain is a
// left-deep tree as deep as it is long: the cap keeps a pasted giant filter off the stack's end.
constexpr size_t kMaxNodes = 2000;

struct FieldName {
    const char* name;
    PacketFilter::Field field;
};
const FieldName kFields[] = {
    {"ip.src", PacketFilter::Field::IpSrc},         {"ip.dst", PacketFilter::Field::IpDst},
    {"ip.addr", PacketFilter::Field::IpAddr},       {"tcp.port", PacketFilter::Field::TcpPort},
    {"tcp.srcport", PacketFilter::Field::TcpSrcPort}, {"tcp.dstport", PacketFilter::Field::TcpDstPort},
    {"udp.port", PacketFilter::Field::UdpPort},     {"udp.srcport", PacketFilter::Field::UdpSrcPort},
    {"udp.dstport", PacketFilter::Field::UdpDstPort}, {"frame.len", PacketFilter::Field::FrameLen},
    {"eth.type", PacketFilter::Field::EthType},     {"proto", PacketFilter::Field::Proto},
};

// Protocol ids (Node::num of a Proto comparison).
enum ProtoId : uint64_t { kTcp, kUdp, kIcmp, kIcmpv6, kArp, kIp, kIpv6 };
bool proto_id(const std::string& w, uint64_t& id) {
    const std::string l = lower(w);
    if (l == "tcp") id = kTcp;
    else if (l == "udp") id = kUdp;
    else if (l == "icmp") id = kIcmp;
    else if (l == "icmpv6") id = kIcmpv6;
    else if (l == "arp") id = kArp;
    else if (l == "ip" || l == "ipv4") id = kIp;
    else if (l == "ipv6") id = kIpv6;
    else return false;
    return true;
}

class Parser {
public:
    Parser(const std::vector<Token>& t, std::vector<PacketFilter::Node>& nodes) : t_(t), nodes_(nodes) {}

    bool run(int& root) {
        root = or_expr(0);
        if (root < 0) return false;
        if (cur().kind != Tok::End) {
            if (cur().kind == Tok::RParen) return fail("unmatched ')'", cur().pos);
            return fail("expected 'and' / 'or' before '" + cur().text + "'", cur().pos);
        }
        return true;
    }
    std::string err;
    size_t err_pos = 0;

private:
    const Token& cur() const { return t_[i_]; }
    bool fail(const std::string& m, size_t pos) {
        if (err.empty()) {
            err = m;
            err_pos = pos;
        }
        return false;
    }
    int bad(const std::string& m, size_t pos) {
        fail(m, pos);
        return -1;
    }
    int add(PacketFilter::Node n) {
        if (nodes_.size() >= kMaxNodes) return bad("filter too long (at most 1000 terms)", cur().pos);
        nodes_.push_back(std::move(n));
        return int(nodes_.size()) - 1;
    }
    int binary(PacketFilter::Kind k, int a, int b) {
        PacketFilter::Node n;
        n.kind = k;
        n.a = a;
        n.b = b;
        return add(std::move(n));
    }

    int or_expr(int depth) {
        int a = and_expr(depth);
        while (a >= 0 && cur().kind == Tok::Or) {
            ++i_;
            const int b = and_expr(depth);
            if (b < 0) return -1;
            a = binary(PacketFilter::Kind::Or, a, b);
        }
        return a;
    }
    int and_expr(int depth) {
        int a = not_expr(depth);
        while (a >= 0 && cur().kind == Tok::And) {
            ++i_;
            const int b = not_expr(depth);
            if (b < 0) return -1;
            a = binary(PacketFilter::Kind::And, a, b);
        }
        return a;
    }
    int not_expr(int depth) {
        if (depth > kMaxDepth) return bad("expression nested too deeply", cur().pos);
        const Token& t = cur();
        switch (t.kind) {
        case Tok::Not: {
            ++i_;
            const int a = not_expr(depth + 1);
            return a < 0 ? -1 : binary(PacketFilter::Kind::Not, a, -1);
        }
        case Tok::LParen: {
            ++i_;
            const int a = or_expr(depth + 1);
            if (a < 0) return -1;
            if (cur().kind != Tok::RParen) return bad("expected ')'", cur().pos);
            ++i_;
            return a;
        }
        case Tok::Text: {
            ++i_;
            PacketFilter::Node n;
            n.kind = PacketFilter::Kind::Text;
            n.text = lower(t.text);
            return add(std::move(n));
        }
        case Tok::Word: return comparison();
        case Tok::End: return bad("expected a field, a protocol or \"text\"", t.pos);
        default: return bad("unexpected '" + t.text + "'", t.pos);
        }
    }

    int comparison() {
        const Token& name = cur();
        ++i_;
        const std::string w = lower(name.text);
        PacketFilter::Node n;
        n.kind = PacketFilter::Kind::Compare;
        bool known = false;
        for (const FieldName& f : kFields)
            if (w == f.name) {
                n.field = f.field;
                known = true;
            }
        if (!known) {  // a bare protocol name: proto == name
            if (proto_id(w, n.num) && cur().kind != Tok::Op) {
                n.field = PacketFilter::Field::Proto;
                return add(std::move(n));
            }
            return bad("unknown field '" + name.text + "'", name.pos);
        }
        if (cur().kind != Tok::Op) return bad("expected ==, !=, <, >, <= or >= after '" + name.text + "'", cur().pos);
        n.op = cur().op;
        const size_t op_pos = cur().pos;
        const std::string op_text = cur().text;
        ++i_;
        const Token& v = cur();
        if (v.kind != Tok::Word) return bad("expected a value after '" + op_text + "'", v.pos);
        ++i_;
        const bool ordering = n.op != PacketFilter::Op::Eq && n.op != PacketFilter::Op::Ne;
        switch (n.field) {
        case PacketFilter::Field::IpSrc:
        case PacketFilter::Field::IpDst:
        case PacketFilter::Field::IpAddr: {
            std::string a = v.text;
            const size_t slash = a.find('/');
            int prefix = -1;
            if (slash != std::string::npos) {
                uint64_t pv = 0;
                if (!parse_uint(a.substr(slash + 1), pv) || pv > 128)
                    return bad("bad prefix length", v.pos + slash + 1);
                prefix = int(pv);
                a = a.substr(0, slash);
            }
            if (!parse_ip_literal(a, n.addr, n.ip_version))
                return bad("expected an IPv4 or IPv6 address, got '" + a + "'", v.pos);
            const int bits = n.ip_version == 4 ? 32 : 128;
            if (prefix > bits) return bad("prefix longer than the address", v.pos + slash + 1);
            if (prefix >= 0 && ordering) return bad("a /prefix only works with == and !=", op_pos);
            n.prefix = uint8_t(prefix < 0 ? bits : prefix);
            break;
        }
        case PacketFilter::Field::Proto:
            if (ordering) return bad("proto only works with == and !=", op_pos);
            if (!proto_id(v.text, n.num))
                return bad("unknown protocol '" + v.text + "' (tcp, udp, icmp, icmpv6, arp, ip, ipv6)", v.pos);
            break;
        default: {
            if (!parse_uint(v.text, n.num)) return bad("expected a number, got '" + v.text + "'", v.pos);
            const bool port = n.field != PacketFilter::Field::FrameLen;  // ports and eth.type are 16-bit
            if (port && n.num > 0xFFFF) return bad("value out of range (0..65535)", v.pos);
            if (!port && n.num > UINT32_MAX) return bad("value out of range", v.pos);
            break;
        }
        }
        return add(std::move(n));
    }

    const std::vector<Token>& t_;
    std::vector<PacketFilter::Node>& nodes_;
    size_t i_ = 0;
};

template <class T>
bool cmp(PacketFilter::Op op, T a, T b) {
    switch (op) {
    case PacketFilter::Op::Eq: return a == b;
    case PacketFilter::Op::Ne: return a != b;
    case PacketFilter::Op::Lt: return a < b;
    case PacketFilter::Op::Gt: return a > b;
    case PacketFilter::Op::Le: return a <= b;
    case PacketFilter::Op::Ge: return a >= b;
    }
    return false;
}

// `addr` (16 bytes, ip_version family) against the node's value.
bool cmp_addr(const PacketFilter::Node& n, PacketFilter::Op op, const uint8_t* addr) {
    const size_t len = n.ip_version == 4 ? 4 : 16;
    if (n.prefix < len * 8) {  // prefix match (== / !=)
        bool eq = true;
        for (size_t bit = 0; bit < n.prefix && eq; bit += 8) {
            const unsigned keep = unsigned(std::min<size_t>(8, n.prefix - bit));
            const uint8_t mask = uint8_t(0xFFu << (8 - keep));
            eq = (addr[bit / 8] & mask) == (n.addr[bit / 8] & mask);
        }
        return op == PacketFilter::Op::Eq ? eq : !eq;
    }
    return cmp(op, std::memcmp(addr, n.addr, len), 0);
}

bool has_proto(const PacketInfo& pi, uint64_t id) {
    switch (id) {
    case kTcp: return pi.proto == "TCP";
    case kUdp: return pi.proto == "UDP";
    case kIcmp: return pi.proto == "ICMP";
    case kIcmpv6: return pi.proto == "ICMPv6";
    case kArp: return pi.proto == "ARP";
    case kIp: return pi.ip_version == 4;
    case kIpv6: return pi.ip_version == 6;
    default: return false;
    }
}

// Two-ended fields: == / < / ... = either end, != = neither end.
bool either(PacketFilter::Op op, bool (*test)(const PacketFilter::Node&, PacketFilter::Op, uint64_t),
            const PacketFilter::Node& n, uint64_t a, uint64_t b) {
    if (op == PacketFilter::Op::Ne) return !test(n, PacketFilter::Op::Eq, a) && !test(n, PacketFilter::Op::Eq, b);
    return test(n, op, a) || test(n, op, b);
}
bool test_num(const PacketFilter::Node& n, PacketFilter::Op op, uint64_t v) { return cmp(op, v, n.num); }

}  // namespace

bool parse_ip_literal(const std::string& s, uint8_t addr[16], uint8_t& version) {
    uint8_t tmp[16] = {};
    if (s.find(':') != std::string::npos) {
        if (!parse_ipv6(s, tmp)) return false;
        version = 6;
    } else {
        if (!parse_ipv4(s, tmp)) return false;
        version = 4;
    }
    std::memcpy(addr, tmp, 16);
    return true;
}

bool PacketFilter::parse(const std::string& text, std::string* err, size_t* err_pos) {
    std::vector<Token> toks;
    std::string e;
    size_t ep = 0;
    if (!tokenize(text, toks, e, ep)) {
        if (err) *err = e;
        if (err_pos) *err_pos = ep;
        return false;
    }
    std::vector<Node> nodes;
    int root = -1;
    if (toks.size() > 1) {  // more than End
        Parser p(toks, nodes);
        if (!p.run(root)) {
            if (err) *err = p.err;
            if (err_pos) *err_pos = p.err_pos;
            return false;
        }
    }
    nodes_ = std::move(nodes);
    root_ = root;
    text_ = text;
    if (err) err->clear();
    return true;
}

bool PacketFilter::match(const Packet& p, const PacketInfo& pi) const {
    return root_ < 0 || eval(root_, p, pi);
}

bool PacketFilter::eval(int i, const Packet& p, const PacketInfo& pi) const {
    const Node& n = nodes_[size_t(i)];
    switch (n.kind) {
    case Kind::And: return eval(n.a, p, pi) && eval(n.b, p, pi);
    case Kind::Or: return eval(n.a, p, pi) || eval(n.b, p, pi);
    case Kind::Not: return !eval(n.a, p, pi);
    case Kind::Text:
        return lower(pi.proto).find(n.text) != std::string::npos || lower(pi.summary).find(n.text) != std::string::npos;
    case Kind::Compare: break;
    }
    const bool tcp = pi.has_ports && pi.proto == "TCP", udp = pi.has_ports && pi.proto == "UDP";
    switch (n.field) {
    case Field::IpSrc:
    case Field::IpDst:
    case Field::IpAddr: {
        if (pi.ip_version == 0 || pi.ip_version != n.ip_version) return false;
        if (n.field == Field::IpSrc) return cmp_addr(n, n.op, pi.ip_src);
        if (n.field == Field::IpDst) return cmp_addr(n, n.op, pi.ip_dst);
        if (n.op == Op::Ne) return !cmp_addr(n, Op::Eq, pi.ip_src) && !cmp_addr(n, Op::Eq, pi.ip_dst);
        return cmp_addr(n, n.op, pi.ip_src) || cmp_addr(n, n.op, pi.ip_dst);
    }
    case Field::TcpPort: return tcp && either(n.op, test_num, n, pi.src_port, pi.dst_port);
    case Field::TcpSrcPort: return tcp && test_num(n, n.op, pi.src_port);
    case Field::TcpDstPort: return tcp && test_num(n, n.op, pi.dst_port);
    case Field::UdpPort: return udp && either(n.op, test_num, n, pi.src_port, pi.dst_port);
    case Field::UdpSrcPort: return udp && test_num(n, n.op, pi.src_port);
    case Field::UdpDstPort: return udp && test_num(n, n.op, pi.dst_port);
    case Field::FrameLen: return test_num(n, n.op, p.orig_len);
    case Field::EthType: return pi.eth_type != 0 && test_num(n, n.op, pi.eth_type);
    case Field::Proto: return has_proto(pi, n.num) == (n.op == Op::Eq);
    }
    return false;
}

void filter_packets(const Snapshot& snap, const std::vector<Packet>& packets, const PacketFilter& f, size_t begin,
                    size_t end, std::vector<uint32_t>& out, const std::atomic<bool>* cancel, std::atomic<uint64_t>* done) {
    end = std::min(end, packets.size());
    for (size_t i = begin; i < end; ++i) {
        if ((i & 255) == 0) {
            if (cancel && cancel->load(std::memory_order_relaxed)) return;
            if (done) done->store(i - begin, std::memory_order_relaxed);
        }
        if (f.match(packets[i], dissect_packet(snap, packets[i], kFilterRead))) out.push_back(uint32_t(i));
    }
    if (done) done->store(end > begin ? end - begin : 0, std::memory_order_relaxed);
}

void PacketFilterJob::start(std::shared_ptr<const PcapIndexJob::Result> index, const PacketFilter& f) {
    const uint64_t total = index ? index->index.packets.size() : 0;
    w_.start(total, [index = std::move(index), f](PacketFilterResult& r, const std::atomic<bool>& cancel,
                                                  std::atomic<uint64_t>& done) {
        r.text = f.text();
        r.index = index;
        if (index && index->snap)
            filter_packets(*index->snap, index->index.packets, f, 0, index->index.packets.size(), r.matches, &cancel,
                           &done);
        r.cancelled = cancel.load();
    });
}

}  // namespace hx
