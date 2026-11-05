#include "core/search.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <iterator>

#include "core/hex_tokens.h"

namespace hx {

// ---- pattern compilation ------------------------------------------------------------------------
// Case-insensitivity is baked into the mask: an ASCII letter gets mask 0xDF (ignores the 0x20 case
// bit), and since only letters get that mask, (b & 0xDF) == (p & 0xDF) matches exactly {upper, lower}.
// find_in() therefore only looks at bytes/mask; Pattern::icase is informational.

namespace {

bool is_ascii_letter(uint8_t b) { return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z'); }

// UTF-8 -> UTF-16LE. False on malformed UTF-8.
bool utf8_to_utf16le(const std::string& s, std::vector<uint8_t>& out) {
    out.clear();
    const auto* p = reinterpret_cast<const uint8_t*>(s.data());
    size_t n = s.size(), i = 0;
    while (i < n) {
        uint32_t cp;
        size_t len;
        uint8_t b = p[i];
        if (b < 0x80) cp = b, len = 1;
        else if ((b & 0xE0) == 0xC0) cp = b & 0x1F, len = 2;
        else if ((b & 0xF0) == 0xE0) cp = b & 0x0F, len = 3;
        else if ((b & 0xF8) == 0xF0) cp = b & 0x07, len = 4;
        else return false;
        if (i + len > n) return false;
        for (size_t k = 1; k < len; ++k) {
            if ((p[i + k] & 0xC0) != 0x80) return false;
            cp = cp << 6 | (p[i + k] & 0x3F);
        }
        static const uint32_t min_cp[] = {0, 0, 0x80, 0x800, 0x10000};
        if (cp < min_cp[len] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += len;
        auto put = [&](uint32_t u) {
            out.push_back(uint8_t(u));
            out.push_back(uint8_t(u >> 8));
        };
        if (cp >= 0x10000) {
            cp -= 0x10000;
            put(0xD800 + (cp >> 10));
            put(0xDC00 + (cp & 0x3FF));
        } else {
            put(cp);
        }
    }
    return true;
}

}  // namespace

bool compile_pattern(SearchKind kind, const std::string& input, bool icase, Pattern& out, std::string* err) {
    out = Pattern{};
    switch (kind) {
    case SearchKind::Hex:
        if (!detail::parse_hex_tokens(input, true, out.bytes, out.mask, err)) {
            out = Pattern{};
            return false;
        }
        return true;  // icase is meaningless for hex
    case SearchKind::Text:
        out.bytes.assign(input.begin(), input.end());
        break;
    case SearchKind::Utf16:
        if (!utf8_to_utf16le(input, out.bytes)) {
            if (err) *err = "invalid UTF-8 text";
            return false;
        }
        break;
    }
    if (out.bytes.empty()) {
        if (err) *err = "empty pattern";
        out = Pattern{};
        return false;
    }
    out.mask.assign(out.bytes.size(), 0xFF);
    out.icase = icase;
    if (icase) {
        for (size_t i = 0; i < out.bytes.size(); ++i) {
            // UTF-16LE: only fold the low byte of a code unit whose high byte is 0 (a real ASCII char).
            if (kind == SearchKind::Utf16 && (i % 2 != 0 || i + 1 >= out.bytes.size() || out.bytes[i + 1] != 0))
                continue;
            if (is_ascii_letter(out.bytes[i])) out.mask[i] = 0xDF;
        }
    }
    for (size_t i = 0; i < out.bytes.size(); ++i) out.bytes[i] &= out.mask[i];
    return true;
}

// ---- matching -----------------------------------------------------------------------------------

namespace {

constexpr size_t kBlock = size_t(4) << 20;  // 4 MiB of match starts per read

// Finds matches of one pattern inside memory buffers. Construct once per search (BMH tables).
class Matcher {
public:
    Matcher(const Matcher&) = delete;  // the BMH searchers point into pat_
    Matcher& operator=(const Matcher&) = delete;
    explicit Matcher(const Pattern& p) : pat_(p.bytes), mask_(p.mask), m_(p.bytes.size()) {
        exact_ = std::all_of(mask_.begin(), mask_.end(), [](uint8_t v) { return v == 0xFF; });
        for (size_t i = 0; i < m_; ++i) {
            if (mask_[i] == 0xFF) {
                anchor_ = i;
                has_anchor_ = true;
                break;
            }
        }
        if (exact_ && m_ > kBmhMin) {
            fwd_.emplace(pat_.begin(), pat_.end());
            bwd_.emplace(pat_.rbegin(), pat_.rend());
        }
    }

    size_t size() const { return m_; }

    // First match with start in [lo, hi) of buf (buf holds at least hi + m - 1 bytes), or SIZE_MAX.
    size_t first(const uint8_t* buf, size_t lo, size_t hi) const {
        if (lo >= hi) return SIZE_MAX;
        const uint8_t* end = buf + hi + m_ - 1;
        if (fwd_) {
            auto r = (*fwd_)(buf + lo, end);
            return r.first == end ? SIZE_MAX : size_t(r.first - buf);
        }
        if (has_anchor_) {
            const uint8_t a = pat_[anchor_];
            size_t i = lo;
            while (i < hi) {
                const void* f = std::memchr(buf + i + anchor_, a, hi - i);
                if (!f) return SIZE_MAX;
                size_t s = size_t(static_cast<const uint8_t*>(f) - buf) - anchor_;
                if (equal_at(buf + s)) return s;
                i = s + 1;
            }
            return SIZE_MAX;
        }
        for (size_t i = lo; i < hi; ++i)
            if (equal_at(buf + i)) return i;
        return SIZE_MAX;
    }

    // Last match with start in [lo, hi), or SIZE_MAX.
    size_t last(const uint8_t* buf, size_t lo, size_t hi) const {
        if (lo >= hi) return SIZE_MAX;
        if (bwd_) {
            using RI = std::reverse_iterator<const uint8_t*>;
            RI rb(buf + hi + m_ - 1), re(buf + lo);
            auto r = (*bwd_)(rb, re);
            if (r.first == re) return SIZE_MAX;
            return size_t(r.second.base() - buf);  // reversed match end == forward match start
        }
        const uint8_t a = has_anchor_ ? pat_[anchor_] : 0;
        for (size_t i = hi; i-- > lo;) {
            if (has_anchor_ && buf[i + anchor_] != a) continue;
            if (equal_at(buf + i)) return i;
        }
        return SIZE_MAX;
    }

private:
    static constexpr size_t kBmhMin = 4;  // memchr+compare beats BMH for tiny patterns

    bool equal_at(const uint8_t* p) const {
        if (exact_) return std::memcmp(p, pat_.data(), m_) == 0;
        for (size_t k = 0; k < m_; ++k)
            if ((p[k] & mask_[k]) != pat_[k]) return false;
        return true;
    }

    std::vector<uint8_t> pat_, mask_;
    size_t m_;
    bool exact_ = true;
    bool has_anchor_ = false;
    size_t anchor_ = 0;
    std::optional<std::boyer_moore_horspool_searcher<std::vector<uint8_t>::const_iterator>> fwd_;
    std::optional<std::boyer_moore_horspool_searcher<std::vector<uint8_t>::const_reverse_iterator>> bwd_;
};

bool cancelled(const std::atomic<bool>* c) { return c && c->load(std::memory_order_relaxed); }

// Reads match starts [lo, lo+count) plus the m-1 byte tail into buf. Returns how many starts are
// fully readable (callers never ask past EOF, so short only before an unreadable byte).
size_t read_window(const Snapshot& snap, uint64_t lo, size_t count, size_t m, std::vector<uint8_t>& buf) {
    size_t want = count + m - 1;
    if (buf.size() < want) buf.resize(want);
    size_t got = snap.read_valid(lo, buf.data(), want);
    return got >= m ? std::min(count, got - m + 1) : 0;
}

// Forward scan over match starts in [lo, hi). `on_hit(offset)` returns the next allowed start
// (> offset) to continue, or UINT64_MAX to stop. Returns false if cancelled.
bool scan_forward(const Snapshot& snap, const Matcher& mt, uint64_t lo, uint64_t hi,
                  const std::atomic<bool>* cancel, std::atomic<uint64_t>* progress, bool* io_err,
                  const std::function<uint64_t(uint64_t)>& on_hit) {
    std::vector<uint8_t> buf;
    uint64_t pos = lo;
    while (pos < hi) {
        if (cancelled(cancel)) return false;
        size_t count = size_t(std::min<uint64_t>(kBlock, hi - pos));
        size_t n = read_window(snap, pos, count, mt.size(), buf);
        uint64_t next_pos = pos + count;
        size_t i = 0;
        while (i < n) {
            size_t k = mt.first(buf.data(), i, n);
            if (k == SIZE_MAX) break;
            uint64_t next = on_hit(pos + k);
            if (next == UINT64_MAX) {
                if (progress) progress->fetch_add(k + 1, std::memory_order_relaxed);
                return true;
            }
            if (next >= pos + n) {  // next allowed start lies in a later block
                next_pos = std::max(next_pos, next);
                break;
            }
            i = size_t(next - pos);
        }
        if (progress) progress->fetch_add(count, std::memory_order_relaxed);
        if (n < count) {  // read error: treat as end of data
            if (io_err) *io_err = true;
            return true;
        }
        pos = next_pos;
    }
    return true;
}

// Backward scan for the last match with start in [lo, hi).
std::optional<uint64_t> scan_backward(const Snapshot& snap, const Matcher& mt, uint64_t lo, uint64_t hi,
                                      const std::atomic<bool>* cancel, std::atomic<uint64_t>* progress,
                                      bool* io_err) {
    std::vector<uint8_t> buf;
    while (hi > lo) {
        if (cancelled(cancel)) return std::nullopt;
        size_t count = size_t(std::min<uint64_t>(kBlock, hi - lo));
        uint64_t start = hi - count;
        size_t n = read_window(snap, start, count, mt.size(), buf);
        if (n < count && io_err) *io_err = true;  // later matches in this window may be hidden
        size_t k = mt.last(buf.data(), 0, n);
        if (progress) progress->fetch_add(count, std::memory_order_relaxed);
        if (k != SIZE_MAX) return start + k;
        if (n < count) return std::nullopt;  // read error: stop
        hi = start;
    }
    return std::nullopt;
}

// Valid match starts are [0, size - m] -> exclusive bound size - m + 1 (0 if pattern too long).
uint64_t start_limit(const Snapshot& snap, size_t m) {
    return snap.size() >= m ? snap.size() - m + 1 : 0;
}

std::optional<uint64_t> find_range(const Snapshot& snap, const Matcher& mt, uint64_t lo, uint64_t hi, bool forward,
                                   const std::atomic<bool>* cancel, std::atomic<uint64_t>* progress,
                                   bool* io_err) {
    hi = std::min(hi, start_limit(snap, mt.size()));
    if (lo >= hi) return std::nullopt;
    if (!forward) return scan_backward(snap, mt, lo, hi, cancel, progress, io_err);
    std::optional<uint64_t> found;
    scan_forward(snap, mt, lo, hi, cancel, progress, io_err, [&](uint64_t off) {
        found = off;
        return UINT64_MAX;
    });
    return found;
}

}  // namespace

std::optional<uint64_t> find_in(const Snapshot& snap, const Pattern& pat, uint64_t from, bool forward,
                                const std::atomic<bool>* cancel, std::atomic<uint64_t>* progress,
                                bool* io_error) {
    if (io_error) *io_error = false;
    if (pat.size() == 0 || pat.mask.size() != pat.bytes.size()) return std::nullopt;
    Matcher mt(pat);
    if (forward) return find_range(snap, mt, from, UINT64_MAX, true, cancel, progress, io_error);
    return find_range(snap, mt, 0, from, false, cancel, progress, io_error);
}

// ---- background job -----------------------------------------------------------------------------

struct SearchJob::Run {
    std::atomic<bool> cancel{false};
    std::atomic<bool> finished{false};  // worker is about to exit: joining it does not block
    std::atomic<uint64_t> done{0};
    uint64_t total = 0;
};

SearchJob::~SearchJob() {
    for (auto& t : threads_) t.second->cancel = true;
    for (auto& t : threads_) t.first.join();
}

std::shared_ptr<SearchJob::Run> SearchJob::current() const {
    std::lock_guard<std::mutex> lock(mu_);
    return run_;
}

void SearchJob::cancel() {
    if (auto r = current()) r->cancel = true;
}

bool SearchJob::running() const { return running_.load(); }

double SearchJob::progress() const {
    auto r = current();
    uint64_t t = r ? r->total : 0, d = r ? r->done.load() : 0;
    if (!t) return running_.load() ? 0.0 : 1.0;
    return d >= t ? 1.0 : double(d) / double(t);
}

uint64_t SearchJob::generation() const { return generation_.load(); }

SearchJob::Result SearchJob::result() const {
    std::lock_guard<std::mutex> lock(mu_);
    return result_;
}

void SearchJob::start(std::shared_ptr<const Snapshot> snap, Pattern pat, uint64_t from, Mode mode,
                      size_t max_results) {
    // Never block the UI thread on the previous run (it may sit in one slow read): cancel it, let it
    // finish in the background (it no longer publishes anything) and join it once it has exited.
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
    std::thread th([this, run, snap = std::move(snap), pat = std::move(pat), from, mode, max_results]() {
        std::atomic<bool>& cancel_ = run->cancel;
        std::atomic<uint64_t>& done_ = run->done;
        bool io = false;
        Result r;
        r.mode = mode;
        r.pattern_len = pat.size();
        if (snap && pat.size() > 0 && pat.mask.size() == pat.bytes.size()) {
            const Snapshot& s = *snap;
            Matcher mt(pat);
            const uint64_t size = s.size();
            const uint64_t f = std::min(from, size);
            std::optional<uint64_t> hit;
            if (mode == Mode::Next) {
                hit = find_range(s, mt, f, UINT64_MAX, true, &cancel_, &done_, &io);
                if (!hit && !cancel_ && f > 0) {  // wrap: starts in [0, from)
                    hit = find_range(s, mt, 0, f, true, &cancel_, &done_, &io);
                    r.wrapped = hit.has_value();
                }
            } else if (mode == Mode::Prev) {
                hit = find_range(s, mt, 0, f, false, &cancel_, &done_, &io);
                if (!hit && !cancel_) {  // wrap: last match at or after `from`
                    hit = find_range(s, mt, f, UINT64_MAX, false, &cancel_, &done_, &io);
                    r.wrapped = hit.has_value();
                }
            } else {
                // All: non-overlapping matches from `from` to EOF.
                uint64_t hi = start_limit(s, mt.size());
                const size_t m = mt.size();
                scan_forward(s, mt, f, hi, &cancel_, &done_, &io, [&](uint64_t off) -> uint64_t {
                    if (r.hits.size() >= max_results) {
                        r.truncated = true;
                        return UINT64_MAX;
                    }
                    r.hits.push_back(off);
                    return off + m;
                });
            }
            if (hit) r.hits.push_back(*hit);
        }
        r.cancelled = cancel_.load();
        r.io_error = io;
        if (r.cancelled && mode != Mode::All) r.hits.clear();
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (run_ == run) {  // superseded runs publish nothing
                result_ = std::move(r);
                done_ = run->total;
                running_ = false;
                generation_.fetch_add(1);
            }
        }
        run->finished = true;
    });
    threads_.emplace_back(std::move(th), std::move(run));
}

}  // namespace hx
