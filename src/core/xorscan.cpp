#include "core/xorscan.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "core/util.h"

namespace hx {

const char* transform_name(XorTransform t) {
    switch (t) {
    case XorTransform::Xor: return "XOR";
    case XorTransform::Add: return "ADD";
    case XorTransform::Rol: return "ROL";
    case XorTransform::XorKey: return "XOR key";
    }
    return "?";
}

namespace {

uint8_t rotl8(uint8_t v, unsigned r) {
    r &= 7;
    return r ? uint8_t((v << r) | (v >> (8 - r))) : v;
}

bool cancelled(const std::atomic<bool>* c) { return c && c->load(std::memory_order_relaxed); }

// True if the cyclic key k[0..L) equals itself rotated by a proper divisor of L.
bool has_shorter_period(const uint8_t* k, size_t L) {
    for (size_t p = 1; p < L; ++p) {
        if (L % p) continue;
        bool same = true;
        for (size_t j = p; j < L && same; ++j) same = k[j] == k[j - p];
        if (same) return true;
    }
    return false;
}

std::string hex2(uint8_t v) {
    char b[8];
    std::snprintf(b, sizeof b, "0x%02X", unsigned(v));
    return b;
}

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Scans the start offsets [0, starts) of buf (which holds at least starts + n - 1 bytes); `base` is
// the absolute offset of buf[0]. Returns false once max_results is exceeded (out.truncated set).
struct Matcher {
    Matcher(const std::vector<uint8_t>& plain, const XorScanOptions& o, XorScanResult& res)
        : p(plain), opt(o), out(res), n(plain.size()) {
        if (opt.rol && n) {
            for (unsigned r = 1; r < 8; ++r) {
                std::vector<uint8_t>& t = rol_pat[r];
                t.resize(n);
                for (size_t i = 0; i < n; ++i) t[i] = rotl8(p[i], r);
                if (t == p) continue;  // the identity on this plaintext (e.g. 0x00 / 0xFF / 0x55)
                rol_first[t[0]] = uint8_t(rol_first[t[0]] | (1u << r));
            }
        }
        if (opt.xor_multi) {
            const size_t max_len = std::clamp<size_t>(opt.max_key_len, 2, kXorMaxKeyLen);
            for (size_t L = 2; L <= max_len; ++L)
                if (n >= 2 * L && n >= L + 4) lens.push_back(L);
        }
    }

    bool add(uint64_t off, XorTransform t, std::vector<uint8_t> key, uint32_t phase) {
        if (out.hits.size() >= opt.max_results) {
            out.truncated = true;
            return false;
        }
        out.hits.push_back(XorHit{off, t, std::move(key), phase});
        return true;
    }

    bool scan(const uint8_t* buf, size_t starts, uint64_t base) {
        for (size_t i = 0; i < starts; ++i) {
            const uint8_t* d = buf + i;
            const uint64_t off = base + i;
            if (opt.xor8) {
                const uint8_t k = uint8_t(d[0] ^ p[0]);
                if (k) {
                    size_t j = 1;
                    while (j < n && uint8_t(d[j] ^ p[j]) == k) ++j;
                    if (j == n && !add(off, XorTransform::Xor, {k}, 0)) return false;
                }
            }
            if (opt.add8) {
                const uint8_t k = uint8_t(d[0] - p[0]);
                if (k) {
                    size_t j = 1;
                    while (j < n && uint8_t(d[j] - p[j]) == k) ++j;
                    if (j == n && !add(off, XorTransform::Add, {k}, 0)) return false;
                }
            }
            if (const unsigned mask = rol_first[d[0]]) {
                for (unsigned r = 1; r < 8; ++r) {
                    if (!(mask & (1u << r))) continue;
                    if (std::memcmp(d, rol_pat[r].data(), n) == 0 &&
                        !add(off, XorTransform::Rol, {uint8_t(r)}, 0))
                        return false;
                }
            }
            for (size_t L : lens) {
                // Key-independent pre-check: the key byte at distance L repeats.
                if (uint8_t(d[L] ^ p[L]) != uint8_t(d[0] ^ p[0])) continue;
                uint8_t kr[kXorMaxKeyLen] = {};
                for (size_t j = 0; j < L; ++j) kr[j] = uint8_t(d[j] ^ p[j]);
                size_t j = L + 1;
                while (j < n && uint8_t(d[j] ^ p[j]) == kr[j % L]) ++j;
                if (j < n || has_shorter_period(kr, L)) continue;  // constant keys have period 1
                std::vector<uint8_t> key(L);
                const uint32_t phase = uint32_t(off % L);
                for (size_t q = 0; q < L; ++q) key[(phase + q) % L] = kr[q];
                if (!add(off, XorTransform::XorKey, std::move(key), phase)) return false;
            }
        }
        return true;
    }

    const std::vector<uint8_t>& p;
    const XorScanOptions& opt;
    XorScanResult& out;
    size_t n;
    std::vector<uint8_t> rol_pat[8];
    uint8_t rol_first[256] = {};  // bit r: ROL r of the plaintext starts with this byte
    std::vector<size_t> lens;     // multi-byte key lengths to try
};

}  // namespace

std::string describe_key(XorTransform t, const std::vector<uint8_t>& key) {
    if (key.empty()) return transform_name(t);
    const uint8_t k = key[0];
    switch (t) {
    case XorTransform::Xor: return "XOR " + hex2(k);
    case XorTransform::Add: return "ADD " + hex2(k) + " (SUB " + hex2(uint8_t(256 - k)) + ")";
    case XorTransform::Rol: {
        const unsigned r = k & 7u;
        return "ROL " + std::to_string(r) + " (ROR " + std::to_string((8 - r) & 7u) + ")";
    }
    case XorTransform::XorKey: break;
    }
    std::string s = "XOR key";
    bool printable = true;
    for (uint8_t b : key) {
        s += " " + fmt_hex(b, 2);
        printable = printable && b >= 0x20 && b < 0x7F;
    }
    if (printable) s += " \"" + std::string(key.begin(), key.end()) + "\"";
    return s;
}

void apply_transform(uint8_t* data, size_t n, XorTransform t, const std::vector<uint8_t>& key,
                     uint64_t phase, bool decode) {
    if (key.empty() || !data) return;
    const uint8_t k = key[0];
    switch (t) {
    case XorTransform::Xor:
        for (size_t i = 0; i < n; ++i) data[i] ^= k;
        break;
    case XorTransform::Add:
        for (size_t i = 0; i < n; ++i) data[i] = uint8_t(decode ? data[i] - k : data[i] + k);
        break;
    case XorTransform::Rol: {
        const unsigned r = decode ? (8 - (k & 7u)) & 7u : k & 7u;
        for (size_t i = 0; i < n; ++i) data[i] = rotl8(data[i], r);
        break;
    }
    case XorTransform::XorKey: {
        const size_t L = key.size();
        size_t ki = size_t(phase % L);
        for (size_t i = 0; i < n; ++i) {
            data[i] ^= key[ki];
            if (++ki == L) ki = 0;
        }
        break;
    }
    }
}

std::vector<uint8_t> apply_transform(std::vector<uint8_t> data, XorTransform t, const std::vector<uint8_t>& key,
                                     uint64_t phase, bool decode) {
    apply_transform(data.data(), data.size(), t, key, phase, decode);
    return data;
}

bool apply_transform(Document& doc, uint64_t begin, uint64_t len, XorTransform t, const std::vector<uint8_t>& key,
                     uint64_t phase, bool decode, std::string* err, const std::string& label, uint64_t max_len) {
    auto fail = [err](const std::string& m) {
        if (err) *err = m;
        return false;
    };
    if (doc.busy()) return fail("the document is being saved");
    if (doc.read_only()) return fail("the document is read-only");
    if (key.empty()) return fail("the key is empty");
    if (begin >= doc.size() || len == 0) return fail("nothing selected");
    len = std::min(len, doc.size() - begin);
    if (len > max_len) return fail("the range is " + fmt_size(len) + "; at most " + fmt_size(max_len) + " can be changed at once");

    constexpr size_t kChunk = size_t(1) << 20;
    std::vector<uint8_t> buf(size_t(std::min<uint64_t>(len, kChunk)));
    std::vector<uint8_t> bad(buf.size());
    doc.begin_group(label.empty() ? std::string(decode ? "Decode " : "Encode ") + describe_key(t, key) : label);
    std::string why;
    uint64_t done = 0;
    while (done < len) {
        const size_t n = size_t(std::min<uint64_t>(kChunk, len - done));
        const size_t got = doc.read(begin + done, buf.data(), n, bad.data());
        const auto first_bad = std::find(bad.begin(), bad.begin() + ptrdiff_t(got), uint8_t(1));
        if (got != n || first_bad != bad.begin() + ptrdiff_t(got)) {
            why = "unreadable byte at 0x" + fmt_hex(begin + done + uint64_t(first_bad - bad.begin())) +
                  "; nothing was changed";
            break;
        }
        apply_transform(buf.data(), n, t, key, phase + done, decode);
        if (!doc.overwrite(begin + done, buf.data(), n)) {
            why = "the edit was rejected; nothing was changed";
            break;
        }
        done += n;
    }
    // A failure partway rolls the chunks already written back: no undo step, no redo step.
    if (why.empty()) doc.end_group();
    else doc.abort_group();
    return why.empty() ? true : fail(why);
}

bool parse_plaintext(const std::string& text, bool hex, std::vector<uint8_t>& out, std::string* err) {
    out.clear();
    if (hex) return parse_bytes(text, out, err);
    auto fail = [err](const std::string& m) {
        if (err) *err = m;
        return false;
    };
    for (size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c != '\\') {
            out.push_back(uint8_t(c));
            continue;
        }
        if (++i >= text.size()) return fail("trailing backslash");
        switch (text[i]) {
        case '0': out.push_back(0); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case '\\': out.push_back('\\'); break;
        case '"': out.push_back('"'); break;
        case '\'': out.push_back('\''); break;
        case 'x': {
            int v = 0, digits = 0;
            while (digits < 2 && i + 1 < text.size() && hex_digit(text[i + 1]) >= 0) {
                v = v * 16 + hex_digit(text[++i]);
                ++digits;
            }
            if (!digits) return fail("\\x needs hex digits");
            out.push_back(uint8_t(v));
            break;
        }
        default: return fail(std::string("unknown escape \\") + text[i]);
        }
    }
    return true;
}

void scan_xor(const Snapshot& snap, uint64_t begin, uint64_t end, const std::vector<uint8_t>& plaintext,
              const XorScanOptions& opt, XorScanResult& out, const std::atomic<bool>* cancel,
              std::atomic<uint64_t>* progress) {
    out = XorScanResult{};
    end = std::min(end, snap.size());
    begin = std::min(begin, end);
    out.begin = begin;
    out.end = end;
    const size_t n = plaintext.size();
    out.plaintext_len = n;
    if (n == 0) return;
    Matcher m(plaintext, opt, out);
    std::vector<uint8_t> buf;
    uint64_t pos = begin;
    while (pos < end) {
        if (cancelled(cancel)) {
            out.cancelled = true;
            break;
        }
        const uint64_t remain = end - pos;
        if (remain < n) break;  // no room for another match
        const size_t blk = size_t(std::min<uint64_t>(kXorBlock, remain - n + 1));  // start offsets
        const size_t want = blk + n - 1;  // + the overlap a match starting near the edge needs
        if (buf.size() < want) buf.resize(want);
        const size_t got = snap.read_valid(pos, buf.data(), want);
        const size_t starts = got >= n ? std::min(blk, got - n + 1) : 0;
        const bool more = m.scan(buf.data(), starts, pos);
        if (!more) break;  // truncated
        if (got < want) {
            const uint64_t at = pos + got;
            const uint64_t resume = snap.next_readable(at);
            if (resume <= at) {  // unreadable byte (I/O error): the data ends here
                if (progress) progress->fetch_add(blk, std::memory_order_relaxed);
                out.io_error = true;
                out.io_error_offset = at;
                break;
            }
            // A hole of a sparse source: every start in [pos + starts, resume) spans it.
            const uint64_t to = std::min(resume, end);
            out.skipped += to - at;
            if (progress) progress->fetch_add(to - pos, std::memory_order_relaxed);
            pos = to;
            continue;
        }
        if (progress) progress->fetch_add(blk, std::memory_order_relaxed);
        pos += blk;
    }
}

std::vector<KeyCandidate> key_guess(const uint8_t* data, size_t n, uint64_t base_offset, uint8_t plain_byte,
                                    uint32_t max_len) {
    std::vector<KeyCandidate> out;
    if (!data) return out;
    std::vector<uint32_t> counts;
    for (size_t L = 1; L <= std::max<uint32_t>(max_len, 1) && n >= 2 * L; ++L) {
        counts.assign(L * 256, 0);
        size_t c = 0;
        for (size_t i = 0; i < n; ++i) {
            ++counts[c * 256 + data[i]];
            if (++c == L) c = 0;
        }
        std::vector<uint8_t> rel(L);
        uint64_t matched = 0;
        for (size_t col = 0; col < L; ++col) {
            const uint32_t* row = &counts[col * 256];
            const size_t best = size_t(std::max_element(row, row + 256) - row);  // first max = lowest byte
            matched += row[best];
            rel[col] = uint8_t(best ^ plain_byte);
        }
        if (has_shorter_period(rel.data(), L)) continue;
        KeyCandidate k;
        k.key.resize(L);
        for (size_t col = 0; col < L; ++col) k.key[size_t((base_offset + col) % L)] = rel[col];
        k.score = double(matched) / double(n) - 0.001 * double(L);
        out.push_back(std::move(k));
    }
    std::stable_sort(out.begin(), out.end(),
                     [](const KeyCandidate& a, const KeyCandidate& b) { return a.score > b.score; });
    return out;
}

// ---- background job -----------------------------------------------------------------------------

struct XorScanJob::Run {
    std::atomic<bool> cancel{false};
    std::atomic<bool> finished{false};  // worker is about to exit: joining it does not block
    std::atomic<uint64_t> done{0};
    uint64_t total = 0;
};

XorScanJob::~XorScanJob() {
    for (auto& t : threads_) t.second->cancel = true;
    for (auto& t : threads_) t.first.join();
}

std::shared_ptr<XorScanJob::Run> XorScanJob::current() const {
    std::lock_guard<std::mutex> lock(mu_);
    return run_;
}

void XorScanJob::cancel() {
    if (auto r = current()) r->cancel = true;
}

bool XorScanJob::running() const { return running_.load(); }

double XorScanJob::progress() const {
    auto r = current();
    const uint64_t t = r ? r->total : 0, d = r ? r->done.load() : 0;
    if (!t) return running_.load() ? 0.0 : 1.0;
    return d >= t ? 1.0 : double(d) / double(t);
}

uint64_t XorScanJob::generation() const { return generation_.load(); }

std::shared_ptr<const XorScanJob::Result> XorScanJob::result() const {
    std::lock_guard<std::mutex> lock(mu_);
    return result_;
}

void XorScanJob::start(std::shared_ptr<const Snapshot> snap, uint64_t begin, uint64_t end,
                       std::vector<uint8_t> plaintext, XorScanOptions opt) {
    auto run = std::make_shared<Run>();
    if (snap) {
        const uint64_t e = std::min(end, snap->size());
        run->total = e > begin ? e - begin : 0;
    }
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
    std::thread th([this, run, snap = std::move(snap), begin, end, plain = std::move(plaintext), opt]() {
        auto r = std::make_shared<Result>();
        r->options = opt;
        r->snap = snap;
        r->plaintext = plain;
        if (snap) scan_xor(*snap, begin, end, plain, opt, r->scan, &run->cancel, &run->done);
        else r->scan.cancelled = run->cancel.load();
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

}  // namespace hx
