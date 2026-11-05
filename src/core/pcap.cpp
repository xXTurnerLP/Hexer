#include "core/pcap.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace hx {

const char* capture_format_name(CaptureFormat f) {
    switch (f) {
    case CaptureFormat::Pcap: return "pcap";
    case CaptureFormat::PcapNg: return "pcapng";
    default: return "";
    }
}

const char* linktype_name(uint16_t linktype) {
    switch (linktype) {
    case kLinkNull: return "BSD loopback";
    case kLinkEthernet: return "Ethernet";
    case kLinkRaw: return "Raw IP";
    case kLinkLoop: return "OpenBSD loopback";
    case kLinkSll: return "Linux SLL";
    case kLinkIpv4: return "IPv4";
    case kLinkIpv6: return "IPv6";
    case kLinkSll2: return "Linux SLL2";
    case 105: return "802.11";
    case 127: return "802.11 radiotap";
    case 220: return "USB Linux mmapped";
    default: return "";
    }
}

namespace {

constexpr uint32_t kShb = 0x0A0D0D0A, kIdb = 1, kOpb = 2, kSpb = 3, kEpb = 6;
constexpr size_t kReadBuf = 256 * 1024;        // bounded read-ahead for record headers
constexpr size_t kMaxIdbOptions = 64 * 1024;   // option bytes of an IDB we look at

uint16_t rd16(const uint8_t* p, bool be) {
    return be ? uint16_t(p[0] << 8 | p[1]) : uint16_t(p[1] << 8 | p[0]);
}
uint32_t rd32(const uint8_t* p, bool be) {
    return be ? uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]
              : uint32_t(p[3]) << 24 | uint32_t(p[2]) << 16 | uint32_t(p[1]) << 8 | p[0];
}
uint64_t rd64(const uint8_t* p, bool be) {
    return be ? uint64_t(rd32(p, true)) << 32 | rd32(p + 4, true) : uint64_t(rd32(p + 4, false)) << 32 | rd32(p, false);
}

// Sequential reader over a Snapshot with one bounded read-ahead window.
class SeqReader {
public:
    explicit SeqReader(const Snapshot& s) : s_(s) {}
    uint64_t size() const { return s_.size(); }
    // Reads exactly n bytes at off. False on EOF or an unreadable byte (io() tells which).
    bool read(uint64_t off, uint8_t* dst, size_t n) {
        io_ = false;
        if (off > s_.size() || n > s_.size() - off) return false;
        if (n > kReadBuf) return direct(off, dst, n);
        if (off < buf_off_ || off - buf_off_ > buf_len_ || n > buf_len_ - (off - buf_off_)) {
            if (buf_.empty()) buf_.resize(kReadBuf);
            const size_t want = size_t(std::min<uint64_t>(kReadBuf, s_.size() - off));
            buf_off_ = off;
            buf_len_ = s_.read_valid(off, buf_.data(), want);
            if (buf_len_ < n) {
                io_ = true;
                return false;
            }
        }
        std::memcpy(dst, buf_.data() + (off - buf_off_), n);
        return true;
    }
    bool io() const { return io_; }

private:
    bool direct(uint64_t off, uint8_t* dst, size_t n) {
        if (s_.read_valid(off, dst, n) == n) return true;
        io_ = true;
        return false;
    }
    const Snapshot& s_;
    std::vector<uint8_t> buf_;
    uint64_t buf_off_ = 0;
    size_t buf_len_ = 0;
    bool io_ = false;
};

bool cancelled(const std::atomic<bool>* c) { return c && c->load(std::memory_order_relaxed); }

uint64_t pow10u(unsigned e) {
    uint64_t v = 1;
    while (e--) v *= 10;
    return v;
}

// Timestamp units -> ns, for a raw if_tsresol byte.
int64_t units_to_ns(uint64_t t, uint8_t res, int64_t offset_s) {
    uint64_t ns = 0;
    if (res & 0x80) {
        const unsigned n = res & 0x7F;
        const uint64_t sec = n < 64 ? t >> n : 0;
        const uint64_t frac = n < 64 ? t & ((uint64_t(1) << n) - 1) : t;
        uint64_t fns;
        if (n <= 34) fns = (frac * 1000000000ull) >> n;
        else if (n - 34 < 64) fns = ((frac >> (n - 34)) * 1000000000ull) >> 34;
        else fns = 0;
        ns = sec * 1000000000ull + fns;
    } else {
        const unsigned n = res;
        if (n <= 9) ns = t * pow10u(9 - n);
        else if (n - 9 <= 19) ns = t / pow10u(n - 9);
    }
    return int64_t(ns + uint64_t(offset_s) * 1000000000ull);  // wraps (no UB) for absurd values
}

int decimals_for(uint8_t res) {
    if (res & 0x80) return std::min(9, int(((res & 0x7F) * 30103 + 99999) / 100000));  // ceil(n log10 2)
    return std::min(9, int(res));
}

void fail(PcapIndexResult& out, uint64_t off, const std::string& msg) {
    out.error = true;
    out.error_offset = off;
    out.error_msg = msg;
}

void index_classic(SeqReader& rd, PcapIndexResult& out, size_t max_packets, const std::atomic<bool>* cancel,
                   std::atomic<uint64_t>* progress) {
    uint8_t gh[24];
    if (!rd.read(0, gh, 24)) return fail(out, 0, rd.io() ? "read error" : "file too short for a pcap header");
    const uint32_t m = rd32(gh, false);
    const bool be = m == 0xD4C3B2A1 || m == 0x4D3CB2A1;
    const bool ns = m == 0xA1B23C4D || m == 0x4D3CB2A1;
    CaptureInterface ifc;
    ifc.snaplen = rd32(gh + 16, be);
    ifc.linktype = uint16_t(rd32(gh + 20, be) & 0xFFFF);  // upper bits: FCS info
    ifc.tsresol = ns ? 9 : 6;
    out.interfaces.push_back(ifc);
    out.time_decimals = ns ? 9 : 6;
    const uint64_t size = rd.size();
    uint64_t off = 24;
    while (off < size) {
        if (cancelled(cancel)) {
            out.cancelled = true;
            break;
        }
        if (out.packets.size() >= max_packets) {
            out.truncated = true;
            break;
        }
        uint8_t h[16];
        if (!rd.read(off, h, 16)) {
            fail(out, off, rd.io() ? "read error in record header" : "truncated record header");
            break;
        }
        Packet p;
        p.record_off = off;
        p.data_off = off + 16;
        p.cap_len = rd32(h + 8, be);
        p.orig_len = rd32(h + 12, be);
        p.linktype = ifc.linktype;
        const uint64_t sec = rd32(h, be), frac = rd32(h + 4, be);
        p.ts_ns = int64_t(sec * 1000000000ull + (ns ? frac : frac * 1000ull));
        if (p.cap_len > kPcapMaxRecord) {
            fail(out, off, "corrupt record: captured length " + std::to_string(p.cap_len));
            break;
        }
        if (p.cap_len > size - p.data_off) {
            fail(out, off, "truncated packet data (" + std::to_string(p.cap_len) + " bytes claimed)");
            break;
        }
        out.packets.push_back(p);
        off = p.data_off + p.cap_len;
        if (progress) progress->store(off, std::memory_order_relaxed);
    }
    out.scanned = off;
}

struct Section {
    bool be = false;
    std::vector<uint32_t> ifaces;  // local id -> index into out.interfaces
};

void parse_idb_options(const uint8_t* o, size_t n, bool be, CaptureInterface& ifc) {
    size_t pos = 0;
    while (n - pos >= 4) {
        const uint16_t code = rd16(o + pos, be), len = rd16(o + pos + 2, be);
        if (code == 0) break;  // opt_endofopt
        if (len > n - pos - 4) break;  // malformed: ignore the rest
        const uint8_t* v = o + pos + 4;
        if (code == 9 && len >= 1) ifc.tsresol = v[0];
        else if (code == 14 && len >= 8) ifc.tsoffset_s = int64_t(rd64(v, be));
        else if (code == 2) {
            size_t l = std::min<size_t>(len, 256);
            while (l && v[l - 1] == 0) --l;
            ifc.name.assign(reinterpret_cast<const char*>(v), l);
        }
        pos += 4 + ((size_t(len) + 3) & ~size_t(3));
        if (pos > n) break;
    }
}

void index_ng(SeqReader& rd, PcapIndexResult& out, size_t max_packets, const std::atomic<bool>* cancel,
              std::atomic<uint64_t>* progress) {
    const uint64_t size = rd.size();
    uint64_t off = 0;
    Section sec;
    bool have_section = false;
    uint32_t section_no = 0;
    std::vector<uint8_t> opts;
    int decimals = 6;
    while (off < size) {
        if (cancelled(cancel)) {
            out.cancelled = true;
            break;
        }
        if (out.packets.size() >= max_packets) {
            out.truncated = true;
            break;
        }
        uint8_t h[28];
        if (!rd.read(off, h, 12)) {
            fail(out, off, rd.io() ? "read error in block header" : "truncated block header");
            break;
        }
        const bool is_shb = std::memcmp(h, "\x0A\x0D\x0D\x0A", 4) == 0;
        if (is_shb) {
            const uint32_t bom = rd32(h + 8, false);
            if (bom == 0x1A2B3C4D) sec.be = false;
            else if (bom == 0x4D3C2B1A) sec.be = true;
            else {
                fail(out, off, "bad byte-order magic in section header");
                break;
            }
        } else if (!have_section) {
            fail(out, off, "not a pcapng file (no section header block)");
            break;
        }
        const bool be = sec.be;
        const uint32_t type = rd32(h, be), len = rd32(h + 4, be);
        if (len < 12 || len % 4 != 0) {
            fail(out, off, "invalid block length " + std::to_string(len));
            break;
        }
        if (len > size - off) {
            fail(out, off, "truncated block (" + std::to_string(len) + " bytes claimed)");
            break;
        }
        uint8_t tr[4];
        if (!rd.read(off + len - 4, tr, 4)) {
            fail(out, off, "read error in block trailer");
            break;
        }
        if (rd32(tr, be) != len) {
            fail(out, off, "corrupt block: trailing length does not match");
            break;
        }
        auto need = [&](uint32_t min_len, size_t hdr) {
            if (len < min_len) {
                fail(out, off, "block too short for its type (" + std::to_string(len) + " bytes)");
                return false;
            }
            if (!rd.read(off, h, hdr)) {
                fail(out, off, "read error in block");
                return false;
            }
            return true;
        };
        auto lookup = [&](uint32_t id, uint32_t* global) {
            if (id >= sec.ifaces.size()) {
                fail(out, off, "packet refers to unknown interface " + std::to_string(id));
                return false;
            }
            *global = sec.ifaces[id];
            return true;
        };
        Packet p;
        bool is_packet = false;
        if (type == kShb) {
            if (!(need(28, 16))) break;
            if (rd16(h + 12, be) != 1) {
                fail(out, off, "unsupported pcapng version " + std::to_string(rd16(h + 12, be)));
                break;
            }
            if (have_section) ++section_no;
            have_section = true;
            sec.ifaces.clear();
        } else if (type == kIdb) {
            if (!(need(20, 16))) break;
            CaptureInterface ifc;
            ifc.linktype = rd16(h + 8, be);
            ifc.snaplen = rd32(h + 12, be);
            ifc.section = section_no;
            ifc.local_id = uint32_t(sec.ifaces.size());
            const size_t on = std::min<size_t>(len - 20, kMaxIdbOptions);
            opts.resize(on);
            if (on && !rd.read(off + 16, opts.data(), on)) {
                fail(out, off, "read error in interface options");
                break;
            }
            parse_idb_options(opts.data(), on, be, ifc);
            decimals = std::max(decimals, decimals_for(ifc.tsresol));
            sec.ifaces.push_back(uint32_t(out.interfaces.size()));
            out.interfaces.push_back(std::move(ifc));
        } else if (type == kEpb || type == kOpb) {
            if (!(need(32, 28))) break;
            const uint32_t id = type == kEpb ? rd32(h + 8, be) : rd16(h + 8, be);
            if (!(lookup(id, &p.iface))) break;
            const uint64_t ts = uint64_t(rd32(h + 12, be)) << 32 | rd32(h + 16, be);
            p.cap_len = rd32(h + 20, be);
            p.orig_len = rd32(h + 24, be);
            if (p.cap_len > len - 32) {
                fail(out, off, "corrupt packet block: captured length " + std::to_string(p.cap_len) +
                                   " exceeds the block");
                break;
            }
            const CaptureInterface& ifc = out.interfaces[p.iface];
            p.ts_ns = units_to_ns(ts, ifc.tsresol, ifc.tsoffset_s);
            p.data_off = off + 28;
            is_packet = true;
        } else if (type == kSpb) {
            if (!(need(16, 12))) break;
            if (!(lookup(0, &p.iface))) break;
            p.orig_len = rd32(h + 8, be);
            const uint32_t snap = out.interfaces[p.iface].snaplen;
            p.cap_len = std::min(p.orig_len, len - 16);
            if (snap) p.cap_len = std::min(p.cap_len, snap);
            p.ts_ns = kNoTimestamp;
            p.data_off = off + 12;
            is_packet = true;
        }
        // Any other block type (NRB, ISB, DSB, custom, ...) is skipped by its length.
        if (is_packet) {
            p.record_off = off;
            p.linktype = out.interfaces[p.iface].linktype;
            out.packets.push_back(p);
        }
        off += len;
        if (progress) progress->store(off, std::memory_order_relaxed);
    }
    out.time_decimals = std::min(9, decimals);
    out.scanned = off;
}

CaptureFormat detect_header(const uint8_t* h, uint64_t size) {
    const uint32_t m = rd32(h, false);
    if (size >= 24 && (m == 0xA1B2C3D4 || m == 0xD4C3B2A1 || m == 0xA1B23C4D || m == 0x4D3CB2A1))
        return CaptureFormat::Pcap;
    if (std::memcmp(h, "\x0A\x0D\x0D\x0A", 4) == 0) {
        const uint32_t bom = rd32(h + 8, false);
        if (bom == 0x1A2B3C4D || bom == 0x4D3C2B1A) return CaptureFormat::PcapNg;
    }
    return CaptureFormat::None;
}

}  // namespace

CaptureFormat pcap_detect(const Snapshot& snap) {
    uint8_t h[12];
    if (snap.size() < 12 || snap.read_valid(0, h, 12) != 12) return CaptureFormat::None;
    return detect_header(h, snap.size());
}

CaptureFormat pcap_detect(const Document& doc) {
    uint8_t h[12];
    if (doc.size() < 12 || doc.read(0, h, 12) != 12) return CaptureFormat::None;
    return detect_header(h, doc.size());
}

void index_pcap(const Snapshot& snap, PcapIndexResult& out, size_t max_packets, const std::atomic<bool>* cancel,
                std::atomic<uint64_t>* progress) {
    out = PcapIndexResult{};
    out.format = pcap_detect(snap);
    SeqReader rd(snap);
    if (out.format == CaptureFormat::Pcap) index_classic(rd, out, max_packets, cancel, progress);
    else if (out.format == CaptureFormat::PcapNg) index_ng(rd, out, max_packets, cancel, progress);
    else fail(out, 0, "not a pcap / pcapng capture");
}

// ---- background job -----------------------------------------------------------------------------

struct PcapIndexJob::Run {
    std::atomic<bool> cancel{false};
    std::atomic<bool> finished{false};
    std::atomic<uint64_t> done{0};
    uint64_t total = 0;
};

PcapIndexJob::~PcapIndexJob() {
    for (auto& t : threads_) t.second->cancel = true;
    for (auto& t : threads_) t.first.join();
}

std::shared_ptr<PcapIndexJob::Run> PcapIndexJob::current() const {
    std::lock_guard<std::mutex> lock(mu_);
    return run_;
}

void PcapIndexJob::cancel() {
    if (auto r = current()) r->cancel = true;
}

bool PcapIndexJob::running() const { return running_.load(); }

double PcapIndexJob::progress() const {
    auto r = current();
    const uint64_t t = r ? r->total : 0, d = r ? r->done.load() : 0;
    if (!t) return running_.load() ? 0.0 : 1.0;
    return d >= t ? 1.0 : double(d) / double(t);
}

uint64_t PcapIndexJob::generation() const { return generation_.load(); }

std::shared_ptr<const PcapIndexJob::Result> PcapIndexJob::result() const {
    std::lock_guard<std::mutex> lock(mu_);
    return result_;
}

void PcapIndexJob::start(std::shared_ptr<const Snapshot> snap, size_t max_packets) {
    auto run = std::make_shared<Run>();
    run->total = snap ? snap->size() : 0;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (run_) run_->cancel = true;
        run_ = run;
    }
    for (auto it = threads_.begin(); it != threads_.end();) {
        if (it->second->finished) {
            it->first.join();
            it = threads_.erase(it);
        } else {
            ++it;
        }
    }
    running_ = true;
    std::thread th([this, run, snap = std::move(snap), max_packets]() {
        auto r = std::make_shared<Result>();
        r->snap = snap;
        if (snap) index_pcap(*snap, r->index, max_packets, &run->cancel, &run->done);
        else r->index.cancelled = run->cancel.load();
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (run_ == run) {  // superseded runs publish nothing
                result_ = std::move(r);
                run->done = run->total;
                running_ = false;
                generation_.fetch_add(1);
            }
        }
        run->finished = true;
    });
    threads_.emplace_back(std::move(th), std::move(run));
}

// ---- formatting -----------------------------------------------------------------------------------

std::string fmt_ipv4(const uint8_t* a) {
    char b[48];
    std::snprintf(b, sizeof b, "%u.%u.%u.%u", unsigned(a[0]), unsigned(a[1]), unsigned(a[2]), unsigned(a[3]));
    return b;
}

std::string fmt_ipv6(const uint8_t* a) {
    uint16_t g[8];
    for (int i = 0; i < 8; ++i) g[i] = uint16_t(a[2 * i] << 8 | a[2 * i + 1]);
    int best = -1, best_len = 0;
    for (int i = 0; i < 8;) {
        if (g[i] != 0) {
            ++i;
            continue;
        }
        int j = i;
        while (j < 8 && g[j] == 0) ++j;
        if (j - i > best_len && j - i >= 2) best = i, best_len = j - i;
        i = j;
    }
    std::string s;
    char b[16];
    for (int i = 0; i < 8; ++i) {
        if (i == best) {
            s += "::";
            i += best_len - 1;
            continue;
        }
        if (!s.empty() && s.back() != ':') s += ':';
        std::snprintf(b, sizeof b, "%x", unsigned(g[i]));
        s += b;
    }
    return s;
}

std::string fmt_mac(const uint8_t* a) {
    char b[48];
    std::snprintf(b, sizeof b, "%02x:%02x:%02x:%02x:%02x:%02x", unsigned(a[0]), unsigned(a[1]), unsigned(a[2]),
                  unsigned(a[3]), unsigned(a[4]), unsigned(a[5]));
    return b;
}

namespace {

std::string fmt_frac(uint64_t frac_ns, int decimals) {
    if (decimals <= 0) return {};
    decimals = std::min(decimals, 9);
    char b[32];
    std::snprintf(b, sizeof b, ".%0*llu", decimals,
                  static_cast<unsigned long long>(frac_ns / pow10u(unsigned(9 - decimals))));
    return b;
}

}  // namespace

std::string fmt_pcap_reltime(int64_t ns, int decimals) {
    const bool neg = ns < 0;
    const uint64_t a = neg ? uint64_t(-(ns + 1)) + 1 : uint64_t(ns);
    return (neg ? "-" : "") + std::to_string(a / 1000000000ull) + fmt_frac(a % 1000000000ull, decimals);
}

std::string fmt_pcap_abstime(int64_t ns, int decimals) {
    int64_t sec = ns / 1000000000;
    int64_t frac = ns % 1000000000;
    if (frac < 0) frac += 1000000000, --sec;
    int64_t days = sec / 86400, rem = sec % 86400;
    if (rem < 0) rem += 86400, --days;
    // civil_from_days (H. Hinnant)
    const int64_t z = days + 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const int64_t doe = z - era * 146097;
    const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t y = yoe + era * 400;
    const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const int64_t mp = (5 * doy + 2) / 153;
    const int64_t d = doy - (153 * mp + 2) / 5 + 1;
    const int64_t m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) ++y;
    char b[160];
    std::snprintf(b, sizeof b, "%04lld-%02lld-%02lld %02lld:%02lld:%02lld", static_cast<long long>(y),
                  static_cast<long long>(m), static_cast<long long>(d), static_cast<long long>(rem / 3600),
                  static_cast<long long>(rem / 60 % 60), static_cast<long long>(rem % 60));
    return b + fmt_frac(uint64_t(frac), decimals);
}

// ---- dissector ------------------------------------------------------------------------------------

namespace {

class Dissector {
public:
    Dissector(const uint8_t* p, size_t n) : p_(p), n_(p ? n : 0) {}

    PacketInfo run(uint16_t linktype) {
        pi_.proto = "?";
        if (n_ == 0) pi_.info = "no captured bytes";
        else link(linktype);
        if (pi_.vlan != 0xFFFF) pi_.info += (pi_.info.empty() ? "" : " ") + std::string("(VLAN ") + std::to_string(pi_.vlan) + ")";
        if (pi_.src.empty() && pi_.dst.empty()) pi_.summary = pi_.info;
        else pi_.summary = pi_.src + " -> " + pi_.dst + (pi_.info.empty() ? "" : "  " + pi_.info);
        return pi_;
    }

private:
    bool has(size_t off, size_t len) const { return off <= n_ && len <= n_ - off; }
    uint8_t u8(size_t o) const { return o < n_ ? p_[o] : 0; }
    uint16_t be16(size_t o) const { return has(o, 2) ? uint16_t(p_[o] << 8 | p_[o + 1]) : 0; }
    uint32_t be32(size_t o) const { return has(o, 4) ? uint32_t(be16(o)) << 16 | be16(o + 2) : 0; }
    uint32_t le32(size_t o) const {
        return has(o, 4) ? uint32_t(p_[o]) | uint32_t(p_[o + 1]) << 8 | uint32_t(p_[o + 2]) << 16 | uint32_t(p_[o + 3]) << 24 : 0;
    }

    // Payload [off, end) clipped to the captured bytes; `length` = declared size.
    void payload(size_t off, size_t end) {
        if (end < off) end = off;
        const uint64_t declared = end - off;
        pi_.length = declared > UINT32_MAX ? UINT32_MAX : uint32_t(declared);
        pi_.payload_off = std::min(off, n_);
        pi_.payload_len = std::min(end, n_) - pi_.payload_off;
    }
    void bad(const char* what, size_t off, size_t end) {
        pi_.malformed = true;
        pi_.info = std::string("malformed: ") + what;
        payload(off, end);
    }

    void link(uint16_t lt) {
        switch (lt) {
        case kLinkEthernet: {
            pi_.proto = "Ethernet";
            if (!has(0, 14)) return bad("short Ethernet header", 0, n_);
            pi_.dst = fmt_mac(p_);
            pi_.src = fmt_mac(p_ + 6);
            uint16_t et = be16(12);
            size_t off = 14;
            for (int tags = 0; tags < 4 && (et == 0x8100 || et == 0x88A8 || et == 0x9100); ++tags) {
                if (!has(off, 4)) return bad("short VLAN tag", off, n_);
                if (pi_.vlan == 0xFFFF) pi_.vlan = be16(off) & 0x0FFF;
                et = be16(off + 2);
                off += 4;
            }
            if (et < 0x0600) {  // 802.3 length field: LLC follows
                pi_.proto = "LLC";
                pi_.info = "802.3 length " + std::to_string(et);
                return payload(off, off + et);
            }
            return ethertype(et, off);
        }
        case kLinkSll: {
            pi_.proto = "SLL";
            if (!has(0, 16)) return bad("short Linux SLL header", 0, n_);
            if (be16(4) == 6) pi_.src = fmt_mac(p_ + 6);
            return ethertype(be16(14), 16);
        }
        case kLinkSll2: {
            pi_.proto = "SLL2";
            if (!has(0, 20)) return bad("short Linux SLL2 header", 0, n_);
            if (u8(11) == 6) pi_.src = fmt_mac(p_ + 12);
            return ethertype(be16(0), 20);
        }
        case kLinkNull:
        case kLinkLoop: {
            pi_.proto = "Loopback";
            if (!has(0, 4)) return bad("short loopback header", 0, n_);
            uint32_t fam = lt == kLinkLoop ? be32(0) : le32(0);
            if (lt == kLinkNull && (fam & 0xFFFF) == 0) fam = be32(0);  // written on a big-endian host
            if (fam == 2) return ipv4(4);
            if (fam == 24 || fam == 28 || fam == 30) return ipv6(4);
            pi_.info = "address family " + std::to_string(fam);
            return payload(4, n_);
        }
        case kLinkRaw: {
            const uint8_t v = u8(0) >> 4;
            if (v == 4) return ipv4(0);
            if (v == 6) return ipv6(0);
            pi_.proto = "Raw IP";
            return bad("unknown IP version", 0, n_);
        }
        case kLinkIpv4: return ipv4(0);
        case kLinkIpv6: return ipv6(0);
        default: {
            const char* name = linktype_name(lt);
            pi_.proto = *name ? name : "Link " + std::to_string(lt);
            pi_.info = "link type " + std::to_string(lt);
            return payload(0, n_);
        }
        }
    }

    void ethertype(uint16_t et, size_t off) {
        switch (et) {
        case 0x0800: return ipv4(off);
        case 0x86DD: return ipv6(off);
        case 0x0806: return arp(off);
        default: {
            char b[32];
            std::snprintf(b, sizeof b, "EtherType 0x%04X", unsigned(et));
            pi_.info = b;
            return payload(off, n_);
        }
        }
    }

    void arp(size_t off) {
        pi_.proto = "ARP";
        if (!has(off, 8)) return bad("short ARP header", off, n_);
        const uint16_t ptype = be16(off + 2), op = be16(off + 6);
        const size_t hl = u8(off + 4), pl = u8(off + 5);
        const size_t body = 8 + 2 * hl + 2 * pl;
        if (!has(off, body)) return bad("short ARP body", off, off + body);
        payload(off, off + body);
        if (hl == 6 && pl == 4 && ptype == 0x0800) {
            const std::string spa = fmt_ipv4(p_ + off + 14), tpa = fmt_ipv4(p_ + off + 24);
            if (op == 1) pi_.info = "Who has " + tpa + "? Tell " + spa;
            else if (op == 2) pi_.info = spa + " is at " + fmt_mac(p_ + off + 8);
            else pi_.info = "opcode " + std::to_string(op);
        } else {
            pi_.info = "opcode " + std::to_string(op);
        }
    }

    void ipv4(size_t off) {
        pi_.proto = "IPv4";
        if (!has(off, 20)) return bad("short IPv4 header", off, n_);
        const uint8_t vihl = u8(off);
        if (vihl >> 4 != 4) return bad("IPv4 version field is not 4", off, n_);
        const size_t ihl = size_t(vihl & 0x0F) * 4;
        if (ihl < 20 || !has(off, ihl)) return bad("bad IPv4 header length", off, n_);
        pi_.src = fmt_ipv4(p_ + off + 12);
        pi_.dst = fmt_ipv4(p_ + off + 16);
        const size_t total = be16(off + 2);
        size_t end = off + total;
        bool bogus_len = false;
        if (total < ihl) {  // 0 with TCP segmentation offload; use what was captured
            end = n_;
            bogus_len = true;
        }
        const uint16_t frag = be16(off + 6);
        const bool mf = (frag & 0x2000) != 0;
        const size_t fo = size_t(frag & 0x1FFF) * 8;
        pi_.fragment = mf || fo != 0;
        pi_.ip_proto = u8(off + 9);
        if (fo != 0) {
            pi_.info = "fragment offset " + std::to_string(fo) + (mf ? " (more)" : "") + ", protocol " +
                       std::to_string(pi_.ip_proto);
            return payload(off + ihl, end);
        }
        l4(pi_.ip_proto, off + ihl, end, false);
        if (mf) pi_.info += " [first fragment]";
        if (bogus_len) {
            pi_.malformed = true;
            pi_.info += " [bad IPv4 total length " + std::to_string(total) + "]";
        }
    }

    void ipv6(size_t off) {
        pi_.proto = "IPv6";
        if (!has(off, 40)) return bad("short IPv6 header", off, n_);
        if (u8(off) >> 4 != 6) return bad("IPv6 version field is not 6", off, n_);
        pi_.src = fmt_ipv6(p_ + off + 8);
        pi_.dst = fmt_ipv6(p_ + off + 24);
        const size_t plen = be16(off + 4);
        const size_t end = plen ? off + 40 + plen : n_;  // 0: jumbogram / offload
        uint8_t nh = u8(off + 6);
        size_t pos = off + 40;
        for (int i = 0; i < 8; ++i) {
            size_t hl = 0;
            if (nh == 0 || nh == 43 || nh == 60 || nh == 135 || nh == 139 || nh == 140) {
                if (!has(pos, 2)) return bad("short IPv6 extension header", pos, end);
                hl = (size_t(u8(pos + 1)) + 1) * 8;
            } else if (nh == 51) {  // AH: length in 4-octet units minus 2
                if (!has(pos, 2)) return bad("short IPv6 AH header", pos, end);
                hl = (size_t(u8(pos + 1)) + 2) * 4;
            } else if (nh == 44) {
                if (!has(pos, 8)) return bad("short IPv6 fragment header", pos, end);
                const uint16_t f = be16(pos + 2);
                pi_.fragment = true;
                const uint8_t next = u8(pos);
                pos += 8;
                if ((f >> 3) != 0) {
                    pi_.ip_proto = next;
                    pi_.info = "fragment offset " + std::to_string(size_t(f >> 3) * 8) + ((f & 1) ? " (more)" : "") +
                               ", next header " + std::to_string(next);
                    return payload(pos, end);
                }
                nh = next;
                continue;
            } else {
                break;
            }
            if (!has(pos, hl) || pos + hl > end) return bad("IPv6 extension header overruns the packet", pos, end);
            nh = u8(pos);
            pos += hl;
        }
        pi_.ip_proto = nh;
        l4(nh, pos, end, true);
        if (pi_.fragment) pi_.info += " [first fragment]";
    }

    std::string ep(const std::string& addr, uint16_t port, bool v6) const {
        return (v6 ? "[" + addr + "]" : addr) + ":" + std::to_string(port);
    }

    void l4(uint8_t proto, size_t off, size_t end, bool v6) {
        if (off > end) return bad("IP header longer than the packet", off, off);
        switch (proto) {
        case 6: return tcp(off, end, v6);
        case 17: return udp(off, end, v6);
        case 1: return icmp(off, end, false);
        case 58: return icmp(off, end, true);
        default: {
            const char* name = nullptr;
            switch (proto) {
            case 2: name = "IGMP"; break;
            case 4: name = "IPIP"; break;
            case 41: name = "IPv6-in-IP"; break;
            case 47: name = "GRE"; break;
            case 50: name = "ESP"; break;
            case 51: name = "AH"; break;
            case 89: name = "OSPF"; break;
            case 132: name = "SCTP"; break;
            default: break;
            }
            if (name) pi_.proto = name;
            pi_.info = proto == 59 ? "no next header" : "protocol " + std::to_string(proto);
            return payload(off, end);
        }
        }
    }

    void tcp(size_t off, size_t end, bool v6) {
        pi_.proto = "TCP";
        if (!has(off, 20) || end - off < 20) return bad("short TCP header", off, end);
        const uint16_t sp = be16(off), dp = be16(off + 2);
        const uint32_t seq = be32(off + 4), ack = be32(off + 8);
        const size_t doff = size_t(u8(off + 12) >> 4) * 4;
        const unsigned flags = u8(off + 13);
        const uint16_t win = be16(off + 14);
        pi_.src = ep(pi_.src, sp, v6);
        pi_.dst = ep(pi_.dst, dp, v6);
        if (doff < 20 || doff > end - off) return bad("bad TCP header length", off + 20, end);
        static const char* kNames[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
        std::string f;
        for (int i = 0; i < 8; ++i)
            if (flags & (1u << i)) f += (f.empty() ? "" : ", ") + std::string(kNames[i]);
        payload(off + doff, end);
        pi_.info = "[" + f + "] seq=" + std::to_string(seq);
        if (flags & 0x10) pi_.info += " ack=" + std::to_string(ack);
        pi_.info += " win=" + std::to_string(win) + " len=" + std::to_string(pi_.length);
    }

    void udp(size_t off, size_t end, bool v6) {
        pi_.proto = "UDP";
        if (!has(off, 8) || end - off < 8) return bad("short UDP header", off, end);
        pi_.src = ep(pi_.src, be16(off), v6);
        pi_.dst = ep(pi_.dst, be16(off + 2), v6);
        const size_t ulen = be16(off + 4);
        if (ulen < 8) return bad("bad UDP length", off + 8, end);
        if (ulen > end - off) {
            payload(off + 8, end);
            pi_.malformed = true;
            pi_.info = "len=" + std::to_string(ulen - 8) + " [UDP length exceeds the IP packet]";
            return;
        }
        payload(off + 8, off + ulen);
        pi_.info = "len=" + std::to_string(pi_.length);
    }

    void icmp(size_t off, size_t end, bool v6) {
        pi_.proto = v6 ? "ICMPv6" : "ICMP";
        if (!has(off, 4) || end - off < 4) return bad("short ICMP header", off, end);
        const uint8_t type = u8(off), code = u8(off + 1);
        const char* name = nullptr;
        bool echo = false;
        if (!v6) {
            switch (type) {
            case 0: name = "Echo reply"; echo = true; break;
            case 3: name = "Destination unreachable"; break;
            case 5: name = "Redirect"; break;
            case 8: name = "Echo request"; echo = true; break;
            case 11: name = "Time exceeded"; break;
            default: break;
            }
        } else {
            switch (type) {
            case 1: name = "Destination unreachable"; break;
            case 2: name = "Packet too big"; break;
            case 3: name = "Time exceeded"; break;
            case 128: name = "Echo request"; echo = true; break;
            case 129: name = "Echo reply"; echo = true; break;
            case 133: name = "Router solicitation"; break;
            case 134: name = "Router advertisement"; break;
            case 135: name = "Neighbor solicitation"; break;
            case 136: name = "Neighbor advertisement"; break;
            default: break;
            }
        }
        pi_.info = name ? name : "type " + std::to_string(type);
        if (code) pi_.info += " code=" + std::to_string(code);
        if (echo && has(off, 8) && end - off >= 8)
            pi_.info += " id=" + std::to_string(be16(off + 4)) + " seq=" + std::to_string(be16(off + 6));
        payload(end - off >= 8 ? off + 8 : end, end);
    }

    const uint8_t* p_;
    size_t n_;
    PacketInfo pi_;
};

}  // namespace

PacketInfo dissect(const uint8_t* data, size_t n, uint16_t linktype) { return Dissector(data, n).run(linktype); }

PacketInfo dissect_packet(const Snapshot& snap, const Packet& p, size_t max_read) {
    const size_t n = std::min<size_t>(p.cap_len, max_read);
    std::vector<uint8_t> buf(n);
    const size_t got = n ? snap.read_valid(p.data_off, buf.data(), n) : 0;
    return dissect(buf.data(), got, p.linktype);
}

}  // namespace hx
