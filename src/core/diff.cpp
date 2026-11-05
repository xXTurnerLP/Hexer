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

}  // namespace hx
