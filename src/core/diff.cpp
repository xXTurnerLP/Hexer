#include "core/diff.h"

#include <algorithm>
#include <cstring>

namespace hx {

namespace {

constexpr size_t kBlock = size_t(4) << 20;  // compare granularity (4 MiB per side)
constexpr size_t kSub = 4096;               // memcmp sub-block inside a differing block

uint64_t load64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}

// True when no byte of x is zero (x = a ^ b: all 8 byte pairs differ).
bool no_zero_byte(uint64_t x) {
    return ((x - 0x0101010101010101ull) & ~x & 0x8080808080808080ull) == 0;
}

// Collects ranges: merges a range into the open one when it continues it (same kind, contiguous
// on both sides), stores at most `max` and keeps counting past the cap.
struct Emitter {
    Emitter(DiffResult& result, size_t max_ranges) : r(result), max(max_ranges) {}
    DiffResult& r;
    size_t max;
    bool open = false;
    DiffRange cur;

    void add(uint8_t kind, uint64_t a, uint64_t b, uint64_t len) {
        if (len == 0) return;
        r.diff_bytes += len;
        if (open && cur.kind == kind && cur.a_off + diff_len_a(cur) == a && cur.b_off + diff_len_b(cur) == b) {
            cur.len += len;
            return;
        }
        flush();
        cur = DiffRange{a, b, len, kind};
        open = true;
    }
    void flush() {
        if (!open) return;
        open = false;
        ++r.range_count;
        if (r.ranges.size() < max) r.ranges.push_back(cur);
        else r.truncated = true;
    }
};

// Differing runs of pa[0, n) vs pb[0, n), reported at A offset base_a / B offset base_b.
void compare_block(const uint8_t* pa, const uint8_t* pb, size_t n, uint64_t base_a, uint64_t base_b,
                   Emitter& em) {
    if (std::memcmp(pa, pb, n) == 0) return;
    size_t i = 0;
    while (i < n) {
        // Skip equal bytes: 4 KiB memcmp steps, then words, then bytes.
        while (i + kSub <= n && std::memcmp(pa + i, pb + i, kSub) == 0) i += kSub;
        while (i + 8 <= n && load64(pa + i) == load64(pb + i)) i += 8;
        while (i < n && pa[i] == pb[i]) ++i;
        if (i >= n) break;
        // A run of differing bytes: whole words where all 8 bytes differ, then bytes.
        const size_t s = i;
        while (i + 8 <= n && no_zero_byte(load64(pa + i) ^ load64(pb + i))) i += 8;
        while (i < n && pa[i] != pb[i]) ++i;
        em.add(DiffRange::Changed, base_a + s, base_b + s, i - s);
    }
}

// Aligned overlap: A[a_lo, a_lo + common) vs B[b_lo, b_lo + common). b_lo is not clamped here
// (it may exceed b_size when shift > b_size; common is 0 then).
struct Overlap {
    uint64_t a_lo = 0, b_lo = 0, common = 0;
};

Overlap overlap(uint64_t a_size, uint64_t b_size, int64_t shift) {
    Overlap o;
    if (shift >= 0) o.b_lo = uint64_t(shift);
    else o.a_lo = uint64_t(0) - uint64_t(shift);  // well-defined for INT64_MIN too
    if (o.a_lo < a_size && o.b_lo < b_size) o.common = std::min(a_size - o.a_lo, b_size - o.b_lo);
    return o;
}

}  // namespace

uint64_t diff_work(uint64_t a_size, uint64_t b_size, int64_t shift) {
    return overlap(a_size, b_size, shift).common;
}

DiffResult diff_snapshots(const Snapshot& a, const Snapshot& b, int64_t shift, size_t max_ranges,
                          const std::atomic<bool>* cancel, std::atomic<uint64_t>* progress) {
    DiffResult r;
    r.a_size = a.size();
    r.b_size = b.size();
    r.shift = shift;
    Emitter em(r, max_ranges);
    const Overlap o = overlap(r.a_size, r.b_size, shift);

    // Unaligned head: the side that starts later in the other one's coordinates.
    if (o.a_lo) em.add(DiffRange::OnlyA, 0, 0, std::min(o.a_lo, r.a_size));
    if (o.b_lo) em.add(DiffRange::OnlyB, 0, 0, std::min(o.b_lo, r.b_size));

    std::vector<uint8_t> ba, bb;
    if (o.common) {
        ba.resize(size_t(std::min<uint64_t>(kBlock, o.common)));
        bb.resize(ba.size());
    }
    for (uint64_t pos = 0; pos < o.common;) {
        if (cancel && cancel->load(std::memory_order_relaxed)) {
            r.cancelled = true;
            break;
        }
        const size_t n = size_t(std::min<uint64_t>(kBlock, o.common - pos));
        const size_t na = a.read_valid(o.a_lo + pos, ba.data(), n);
        const size_t nb = b.read_valid(o.b_lo + pos, bb.data(), n);
        const size_t m = std::min(na, nb);
        compare_block(ba.data(), bb.data(), m, o.a_lo + pos, o.b_lo + pos, em);
        if (progress) progress->fetch_add(n, std::memory_order_relaxed);
        if (m < n) {  // unreadable byte on either side: stop there (zeros would be false matches)
            r.io_error = true;
            r.io_error_offset = o.a_lo + pos + m;
            break;
        }
        pos += n;
    }

    // Tail of the longer side (only when the whole overlap was compared).
    if (!r.cancelled && !r.io_error) {
        const uint64_t a_end = std::min(o.a_lo + o.common, r.a_size);
        const uint64_t b_end = std::min(o.b_lo + o.common, r.b_size);
        if (a_end < r.a_size) em.add(DiffRange::OnlyA, a_end, b_end, r.a_size - a_end);
        if (b_end < r.b_size) em.add(DiffRange::OnlyB, a_end, b_end, r.b_size - b_end);
    }
    em.flush();
    return r;
}

// ---- lookups ------------------------------------------------------------------------------------

size_t next_diff(const std::vector<DiffRange>& ranges, uint64_t a_off, bool side_b) {
    auto it = std::partition_point(ranges.begin(), ranges.end(),
                                   [&](const DiffRange& r) { return (side_b ? r.b_off : r.a_off) <= a_off; });
    return it == ranges.end() ? kNoDiff : size_t(it - ranges.begin());
}

size_t prev_diff(const std::vector<DiffRange>& ranges, uint64_t a_off, bool side_b) {
    auto it = std::partition_point(ranges.begin(), ranges.end(),
                                   [&](const DiffRange& r) { return (side_b ? r.b_off : r.a_off) < a_off; });
    return it == ranges.begin() ? kNoDiff : size_t(it - ranges.begin()) - 1;
}

std::pair<size_t, size_t> ranges_in(const std::vector<DiffRange>& ranges, uint64_t begin, uint64_t end,
                                    bool side_b) {
    auto off = [side_b](const DiffRange& r) { return side_b ? r.b_off : r.a_off; };
    auto len = [side_b](const DiffRange& r) { return side_b ? diff_len_b(r) : diff_len_a(r); };
    // Range ends are non-decreasing on both sides (ranges never overlap and are sorted).
    auto lo = std::partition_point(ranges.begin(), ranges.end(),
                                   [&](const DiffRange& r) { return off(r) + len(r) <= begin; });
    auto hi = std::partition_point(lo, ranges.end(), [&](const DiffRange& r) { return off(r) < end; });
    return {size_t(lo - ranges.begin()), size_t(hi - ranges.begin())};
}

// ---- background job -----------------------------------------------------------------------------

struct DiffJob::Run {
    std::atomic<bool> cancel{false};
    std::atomic<bool> finished{false};  // worker is about to exit: joining it does not block
    std::atomic<uint64_t> done{0};
    uint64_t total = 0;
    uint64_t id = 0;
};

DiffJob::~DiffJob() {
    for (auto& t : threads_) t.second->cancel = true;
    for (auto& t : threads_) t.first.join();
}

std::shared_ptr<DiffJob::Run> DiffJob::current() const {
    std::lock_guard<std::mutex> lock(mu_);
    return run_;
}

void DiffJob::cancel() {
    if (auto r = current()) r->cancel = true;
}

bool DiffJob::running() const { return running_.load(); }

double DiffJob::progress() const {
    auto r = current();
    uint64_t t = r ? r->total : 0, d = r ? r->done.load() : 0;
    if (!t) return running_.load() ? 0.0 : 1.0;
    return d >= t ? 1.0 : double(d) / double(t);
}

uint64_t DiffJob::generation() const { return generation_.load(); }

std::shared_ptr<const DiffResult> DiffJob::result() const {
    std::lock_guard<std::mutex> lock(mu_);
    return result_;
}

uint64_t DiffJob::start(std::shared_ptr<const Snapshot> a, std::shared_ptr<const Snapshot> b, int64_t shift,
                        size_t max_ranges) {
    auto run = std::make_shared<Run>();
    run->id = ++next_run_;
    const uint64_t id = run->id;
    run->total = a && b ? diff_work(a->size(), b->size(), shift) : 0;
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
    std::thread th([this, run, a = std::move(a), b = std::move(b), shift, max_ranges]() {
        auto r = std::make_shared<DiffResult>();
        if (a && b) *r = diff_snapshots(*a, *b, shift, max_ranges, &run->cancel, &run->done);
        else r->cancelled = true;
        r->run = run->id;
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
    return id;
}

// ---- find shift ---------------------------------------------------------------------------------

namespace {

constexpr uint64_t kHashMul = 0x100000001B3ull;  // rolling hash base (odd: arithmetic mod 2^64)

uint64_t block_hash(const uint8_t* p, size_t n) {
    uint64_t h = 0;
    for (size_t i = 0; i < n; ++i) h = h * kHashMul + p[i];
    return h;
}

// x + d, clamped to [0, UINT64_MAX].
uint64_t offset_add(uint64_t x, int64_t d) {
    if (d >= 0) return x > UINT64_MAX - uint64_t(d) ? UINT64_MAX : x + uint64_t(d);
    const uint64_t m = uint64_t(0) - uint64_t(d);
    return x > m ? x - m : 0;
}

// a + b without signed overflow (saturating).
int64_t sat_add(int64_t a, int64_t b) {
    if (b > 0 && a > INT64_MAX - b) return INT64_MAX;
    if (b < 0 && a < INT64_MIN - b) return INT64_MIN;
    return a + b;
}

int64_t sat_neg(int64_t a) { return a == INT64_MIN ? INT64_MAX : -a; }

// x - y as a signed distance (exact while |x - y| < 2^63).
int64_t signed_diff(uint64_t x, uint64_t y) { return int64_t(x - y); }

// |s - shift| without overflow.
uint64_t shift_dist(int64_t s, int64_t shift) {
    return s >= shift ? uint64_t(s) - uint64_t(shift) : uint64_t(shift) - uint64_t(s);
}

// A distinctive block of one side and its nearest occurrence on the other side.
struct Probe {
    uint64_t at = 0;              // offset on its own side
    uint64_t hash = 0;
    std::vector<uint8_t> bytes;
    bool found = false;
    uint64_t match = 0;           // offset of the nearest occurrence on the other side
    uint64_t dist = UINT64_MAX;   // |match - (at + d)|
};

// Up to opt.probes distinctive (>= opt.min_distinct different byte values), non-overlapping
// blocks starting in [from, from + opt.probe_scan] of s, in offset order.
std::vector<Probe> find_probes(const Snapshot& s, uint64_t from, const ShiftOptions& opt,
                               std::atomic<uint64_t>* progress) {
    std::vector<Probe> out;
    const size_t k = opt.block;
    if (k == 0 || opt.probes == 0 || from >= s.size() || s.size() - from < k) return out;
    const uint64_t scan = std::min<uint64_t>(opt.probe_scan, uint64_t(1) << 40);
    const size_t n = size_t(std::min<uint64_t>(s.size() - from, scan + uint64_t(k)));
    std::vector<uint8_t> buf(n);
    const size_t got = s.read_valid(from, buf.data(), n);
    if (progress) progress->fetch_add(n, std::memory_order_relaxed);
    size_t start = 0;  // the next probe starts here or later
    while (out.size() < opt.probes && start + k <= got) {
        uint32_t count[256] = {};
        uint32_t distinct = 0;
        size_t first = SIZE_MAX;
        for (size_t i = start; i < got; ++i) {
            if (count[buf[i]]++ == 0) ++distinct;
            if (i >= start + k && --count[buf[i - k]] == 0) --distinct;
            if (i + 1 >= start + k && distinct >= opt.min_distinct) {
                first = i + 1 - k;
                break;
            }
        }
        if (first == SIZE_MAX) break;
        Probe p;
        p.at = from + first;
        p.bytes.assign(buf.begin() + std::ptrdiff_t(first), buf.begin() + std::ptrdiff_t(first + k));
        p.hash = block_hash(p.bytes.data(), k);
        out.push_back(std::move(p));
        start = first + k;
    }
    return out;
}

// For every probe: its occurrence in s nearest to at + d, at most w away (rolling hash over 4 MiB
// reads of the window around all probes, one pass; hits verified by memcmp). Unreadable bytes read
// as zero (a distinctive probe never matches them).
void search_probes(const Snapshot& s, std::vector<Probe>& probes, int64_t d, int64_t w,
                   const std::atomic<bool>* cancel, std::atomic<uint64_t>* progress, bool& cancelled) {
    if (probes.empty()) return;
    const size_t k = probes.front().bytes.size();
    if (s.size() < k) return;
    const uint64_t lo = offset_add(probes.front().at, sat_add(d, -w));
    const uint64_t hi = std::min<uint64_t>(offset_add(probes.back().at, sat_add(d, w)), s.size() - k);
    if (lo > hi) return;
    uint64_t top = 1;  // kHashMul^(k-1): weight of the byte leaving the window
    for (size_t i = 1; i < k; ++i) top *= kHashMul;
    uint64_t bloom[64] = {};  // 4096-bit filter on the top hash bits: most positions skip the probe loop
    for (const Probe& p : probes) bloom[p.hash >> 58] |= uint64_t(1) << ((p.hash >> 52) & 63);
    std::vector<uint8_t> buf(size_t(std::min<uint64_t>(kBlock, hi - lo + 1)) + k - 1);
    for (uint64_t pos = lo; pos <= hi;) {
        if (cancel && cancel->load(std::memory_order_relaxed)) {
            cancelled = true;
            return;
        }
        const uint64_t cnt = std::min<uint64_t>(kBlock, hi - pos + 1);  // match starts in this read
        const size_t n = size_t(cnt) + k - 1;
        s.read(pos, buf.data(), n);
        if (progress) progress->fetch_add(n, std::memory_order_relaxed);
        uint64_t h = block_hash(buf.data(), k);
        for (size_t i = 0;; ++i) {
            if (bloom[h >> 58] & (uint64_t(1) << ((h >> 52) & 63))) {
                for (Probe& p : probes) {
                    if (p.hash != h || std::memcmp(buf.data() + i, p.bytes.data(), k) != 0) continue;
                    const uint64_t m = pos + i, target = offset_add(p.at, d);
                    const uint64_t dist = m > target ? m - target : target - m;
                    if (dist <= uint64_t(w) && dist < p.dist) {
                        p.found = true;
                        p.match = m;
                        p.dist = dist;
                    }
                }
            }
            if (i + 1 >= cnt) break;
            h = (h - buf[i] * top) * kHashMul + buf[i + k];
        }
        pos += cnt;
    }
}

// The first probe (nearest to the difference) that was found, or null.
const Probe* first_found(const std::vector<Probe>& probes) {
    for (const Probe& p : probes)
        if (p.found) return &p;
    return nullptr;
}

// The first distinctive block starting in [pa, pa + opt.probe_scan] that A and B hold at the same
// aligned position (A[at, +block) == B[at - pa + pb, +block)): the difference at pa is a change,
// not an insertion. Returns its A offset in `at`.
bool aligned_match(const Snapshot& a, const Snapshot& b, uint64_t pa, uint64_t pb, const ShiftOptions& opt,
                   uint64_t& at, std::atomic<uint64_t>* progress) {
    const size_t k = opt.block;
    if (k == 0 || pa >= a.size() || pb >= b.size()) return false;
    const uint64_t scan = std::min<uint64_t>(opt.probe_scan, uint64_t(1) << 40);
    const size_t n = size_t(std::min<uint64_t>({a.size() - pa, b.size() - pb, scan + uint64_t(k)}));
    std::vector<uint8_t> ba(n), bb(n);
    const size_t got = std::min(a.read_valid(pa, ba.data(), n), b.read_valid(pb, bb.data(), n));
    if (progress) progress->fetch_add(2 * uint64_t(n), std::memory_order_relaxed);
    uint32_t count[256] = {};
    uint32_t distinct = 0;
    size_t equal_run = 0;
    for (size_t i = 0; i < got; ++i) {
        equal_run = ba[i] == bb[i] ? equal_run + 1 : 0;
        if (count[ba[i]]++ == 0) ++distinct;
        if (i >= k && --count[ba[i - k]] == 0) --distinct;
        if (equal_run >= k && distinct >= opt.min_distinct) {
            at = pa + i + 1 - k;
            return true;
        }
    }
    return false;
}

int64_t window_of(const ShiftOptions& opt) { return int64_t(std::min<uint64_t>(opt.window, uint64_t(1) << 62)); }

}  // namespace

uint64_t shift_work(uint64_t a_size, uint64_t b_size, int64_t shift, const ShiftOptions& opt) {
    const uint64_t w = uint64_t(window_of(opt));
    const uint64_t scan = std::min<uint64_t>(opt.probe_scan, uint64_t(1) << 40) + uint64_t(opt.block);
    // for each side: its probes, their window, aligned_match
    return diff_work(a_size, b_size, shift) + 2 * (scan + (2 * w + scan) + scan);
}

ShiftResult find_shift(const Snapshot& a, const Snapshot& b, int64_t shift, const ShiftOptions& opt,
                       const std::atomic<bool>* cancel, std::atomic<uint64_t>* progress) {
    ShiftResult r;
    r.shift = shift;
    const Overlap o = overlap(a.size(), b.size(), shift);
    r.diff_a = o.a_lo;
    r.diff_b = o.b_lo;
    if (o.common == 0 && (a.size() == 0 || b.size() == 0)) return r;  // NoDifference: nothing to align

    // 1. The first differing aligned byte (no overlap at all: its start counts as the difference).
    if (o.common) {
        bool differs = false;
        std::vector<uint8_t> ba(size_t(std::min<uint64_t>(kBlock, o.common))), bb(ba.size());
        for (uint64_t pos = 0; pos < o.common && !differs;) {
            if (cancel && cancel->load(std::memory_order_relaxed)) {
                r.status = ShiftResult::Cancelled;
                return r;
            }
            const size_t n = size_t(std::min<uint64_t>(kBlock, o.common - pos));
            const size_t m =
                std::min(a.read_valid(o.a_lo + pos, ba.data(), n), b.read_valid(o.b_lo + pos, bb.data(), n));
            if (progress) progress->fetch_add(n, std::memory_order_relaxed);
            size_t i = n;
            if (std::memcmp(ba.data(), bb.data(), m) != 0) {
                i = 0;
                while (i + kSub <= m && std::memcmp(ba.data() + i, bb.data() + i, kSub) == 0) i += kSub;
                while (ba[i] == bb[i]) ++i;  // a differing byte lies before m
                differs = true;
            } else if (m < n) {
                r.status = ShiftResult::IoError;
                r.diff_a = o.a_lo + pos + m;
                r.diff_b = o.b_lo + pos + m;
                return r;
            }
            r.diff_a = o.a_lo + pos + i;
            r.diff_b = o.b_lo + pos + i;
            pos += i;
        }
        if (!differs) return r;  // NoDifference
    }

    // 2. Probes of each side (the first distinctive blocks after the difference: an edit inside one
    // only costs that probe), searched near their aligned position on the other side.
    const int64_t w = window_of(opt);
    bool cancelled = false;
    std::vector<Probe> pa = find_probes(a, r.diff_a, opt, progress);  // A blocks: in B at +shift
    search_probes(b, pa, shift, w, cancel, progress, cancelled);
    std::vector<Probe> pb;
    if (!cancelled) {
        pb = find_probes(b, r.diff_b, opt, progress);  // B blocks: in A at -shift
        search_probes(a, pb, sat_neg(shift), w, cancel, progress, cancelled);
    }
    if (cancelled) {
        r.status = ShiftResult::Cancelled;
        return r;
    }
    const bool any_probe = !pa.empty() || !pb.empty();
    bool found = false;
    if (const Probe* p = first_found(pa)) {
        found = true;
        r.shift = signed_diff(p->match, p->at);
        r.match_a = p->at;
        r.match_b = p->match;
    }
    if (const Probe* p = first_found(pb)) {
        const int64_t s2 = signed_diff(p->at, p->match);
        if (!found || shift_dist(s2, shift) < shift_dist(r.shift, shift)) {
            r.shift = s2;
            r.match_a = p->match;
            r.match_b = p->at;
        }
        found = true;
    }
    uint64_t q = 0;
    // 3. Neither probe found (the bytes at the difference were changed): do A and B line up
    // again shortly after it with the current shift?
    if (!found && any_probe && aligned_match(a, b, r.diff_a, r.diff_b, opt, q, progress)) {
        found = true;
        r.match_a = q;
        r.match_b = offset_add(q, shift);
    }
    if (!found) {
        r.status = any_probe ? ShiftResult::NoMatch : ShiftResult::NoProbe;
        return r;
    }
    r.status = ShiftResult::Found;
    r.delta = int64_t(uint64_t(r.shift) - uint64_t(shift));
    return r;
}

struct ShiftJob::Run {
    std::atomic<bool> cancel{false};
    std::atomic<bool> finished{false};  // worker is about to exit: joining it does not block
    std::atomic<uint64_t> done{0};
    uint64_t total = 0;
    uint64_t id = 0;
};

ShiftJob::~ShiftJob() {
    for (auto& t : threads_) t.second->cancel = true;
    for (auto& t : threads_) t.first.join();
}

std::shared_ptr<ShiftJob::Run> ShiftJob::current() const {
    std::lock_guard<std::mutex> lock(mu_);
    return run_;
}

void ShiftJob::cancel() {
    if (auto r = current()) r->cancel = true;
}

bool ShiftJob::running() const { return running_.load(); }

double ShiftJob::progress() const {
    auto r = current();
    uint64_t t = r ? r->total : 0, d = r ? r->done.load() : 0;
    if (!t) return running_.load() ? 0.0 : 1.0;
    return d >= t ? 1.0 : double(d) / double(t);
}

uint64_t ShiftJob::generation() const { return generation_.load(); }

std::shared_ptr<const ShiftResult> ShiftJob::result() const {
    std::lock_guard<std::mutex> lock(mu_);
    return result_;
}

uint64_t ShiftJob::start(std::shared_ptr<const Snapshot> a, std::shared_ptr<const Snapshot> b, int64_t shift,
                         const ShiftOptions& opt) {
    auto run = std::make_shared<Run>();
    run->id = ++next_run_;
    const uint64_t id = run->id;
    run->total = a && b ? shift_work(a->size(), b->size(), shift, opt) : 0;
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
    std::thread th([this, run, a = std::move(a), b = std::move(b), shift, opt]() {
        auto r = std::make_shared<ShiftResult>();
        if (a && b) *r = find_shift(*a, *b, shift, opt, &run->cancel, &run->done);
        else r->status = ShiftResult::Cancelled;
        r->run = run->id;
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
    return id;
}

}  // namespace hx
