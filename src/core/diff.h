#pragma once
// Byte-wise compare of two documents (Snapshots A and B) on a worker thread.
//
// Alignment: byte A[i] is compared with B[i + shift] (`shift` is signed, so B may start with an
// extra header of `shift` bytes, or A with one of -shift bytes). Bytes that have no counterpart are
// reported as OnlyA / OnlyB ranges (the unaligned head of the longer-starting side and the tail of
// the longer side). Compared in 4 MiB blocks: memcmp fast path, then a word-at-a-time scan.
//
// Ranges are sorted and merged (adjacent differing bytes form one range, also across blocks) and
// are monotonic in BOTH coordinates: for i < j, ranges[i] ends at or before ranges[j] in A and in B.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include "core/document.h"

namespace hx {

struct DiffRange {
    enum Kind : uint8_t {
        Changed = 0,  // A[a_off, +len) differs from B[b_off, +len) (b_off == a_off + shift)
        OnlyA = 1,    // A[a_off, +len) has no counterpart in B (b_off = where it would be in B)
        OnlyB = 2,    // B[b_off, +len) has no counterpart in A (a_off = where it would be in A)
    };
    uint64_t a_off = 0, b_off = 0, len = 0;
    uint8_t kind = Changed;
    bool operator==(const DiffRange&) const = default;
};

// Bytes a range covers on side A (0 for OnlyB) / on side B (0 for OnlyA).
inline uint64_t diff_len_a(const DiffRange& r) { return r.kind == DiffRange::OnlyB ? 0 : r.len; }
inline uint64_t diff_len_b(const DiffRange& r) { return r.kind == DiffRange::OnlyA ? 0 : r.len; }

struct DiffResult {
    std::vector<DiffRange> ranges;  // at most max_ranges (sorted, merged)
    uint64_t range_count = 0;       // all ranges found, also past the cap
    uint64_t diff_bytes = 0;        // all differing bytes (sum of len over every range), also past the cap
    bool truncated = false;         // range_count > ranges.size()
    bool cancelled = false;         // partial: the scan stopped early (counts cover the scanned part)
    bool io_error = false;          // a read failed; the scan stopped at A offset io_error_offset
    uint64_t io_error_offset = 0;
    uint64_t a_size = 0, b_size = 0;
    int64_t shift = 0;
    uint64_t run = 0;               // DiffJob: id of the start() call that produced it (0 = blocking call)
    bool identical() const { return range_count == 0 && !cancelled && !io_error; }
};

// Blocking primitive (the job runs it on its thread). `progress` (if non-null) counts compared
// bytes of the aligned overlap; that overlap's length is diff_work(a, b, shift).
DiffResult diff_snapshots(const Snapshot& a, const Snapshot& b, int64_t shift, size_t max_ranges = 1000000,
                          const std::atomic<bool>* cancel = nullptr, std::atomic<uint64_t>* progress = nullptr);
uint64_t diff_work(uint64_t a_size, uint64_t b_size, int64_t shift);

// ---- lookups over a result's ranges (binary search, O(log n)) ----------------------------------
constexpr size_t kNoDiff = SIZE_MAX;
// Index of the first range starting after `a_off` in A (range.a_off > a_off), or kNoDiff.
// side_b: the same in B coordinates (range.b_off > offset).
size_t next_diff(const std::vector<DiffRange>& ranges, uint64_t a_off, bool side_b = false);
// Index of the last range starting before `a_off` in A (or B with side_b), or kNoDiff.
size_t prev_diff(const std::vector<DiffRange>& ranges, uint64_t a_off, bool side_b = false);
// Index span [first, second) of the ranges that may intersect [begin, end) on side A (or B with
// side_b). Every range that covers a byte of the window is inside; the span may also hold
// zero-width ranges of the other side (OnlyB for side A) located inside the window.
std::pair<size_t, size_t> ranges_in(const std::vector<DiffRange>& ranges, uint64_t begin, uint64_t end,
                                    bool side_b = false);

// ---- automatic shift (Compare: Find Shift) -------------------------------------------------------
// Finds the shift that lines A and B up again after their first difference under `shift` (an
// insertion or deletion such as an extra header): from the first differing position (scanned like
// diff_snapshots), the first `probes` distinctive `block`-byte blocks of EACH side (at least
// `min_distinct` different byte values, so all-zero padding and short repeats are skipped; not
// overlapping; starting at most `probe_scan` bytes past the difference) are searched within
// +-`window` bytes of their aligned position on the other side, all in one rolling-hash pass per
// side, every hash hit verified by memcmp. Per side the first probe that is found counts (an edit
// inside the first block only costs that probe) with its nearest match; of the two sides the
// smaller change of the shift wins. When no probe is found (the bytes at the difference were
// changed, not inserted), a distinctive block equal on both sides at the current shift within
// probe_scan bytes reports Found with delta 0. Bounded work after the first difference: about
// 2 * (2 * window + 4 * probe_scan) bytes read, whatever the file sizes.
struct ShiftOptions {
    uint64_t window = uint64_t(16) << 20;     // +-16 MiB around the aligned position
    uint32_t block = 64;                      // probe length (bytes)
    uint32_t min_distinct = 8;                // distinct byte values a probe needs
    uint64_t probe_scan = uint64_t(1) << 20;  // how far past the difference a probe may start
    uint32_t probes = 16;                     // probes per side
};

struct ShiftResult {
    enum Status : uint8_t {
        Found,         // shift / delta / match_* are set (delta 0: the bytes after the difference
                       // already line up - a change, not an insertion)
        NoDifference,  // the aligned overlap is identical: nothing to align
        NoProbe,       // no distinctive block after the difference on either side
        NoMatch,       // no probe found within the window of the other side
        Cancelled,
        IoError,       // a read failed while looking for the first difference (at A diff_a)
    };
    uint8_t status = NoDifference;
    int64_t shift = 0;          // Found: the new total shift; else the input shift
    int64_t delta = 0;          // shift - input shift: > 0 B has delta extra bytes there (inserted
                                // in B), < 0 A has -delta extra bytes (deleted in B)
    uint64_t diff_a = 0, diff_b = 0;    // first difference under the input shift (A / B offset)
    uint64_t match_a = 0, match_b = 0;  // Found: A[match_a, +block) == B[match_b, +block)
    uint64_t run = 0;           // ShiftJob: id of the start() call (0 = blocking call)
};

// Blocking primitive (ShiftJob runs it on its thread). `progress` counts bytes read; the total is
// shift_work(a.size(), b.size(), shift, opt) (an upper bound: done jumps to it at the end).
ShiftResult find_shift(const Snapshot& a, const Snapshot& b, int64_t shift, const ShiftOptions& opt = {},
                       const std::atomic<bool>* cancel = nullptr, std::atomic<uint64_t>* progress = nullptr);
uint64_t shift_work(uint64_t a_size, uint64_t b_size, int64_t shift, const ShiftOptions& opt = {});

// Background find_shift(); same run model as DiffJob (start() supersedes without waiting).
class ShiftJob {
public:
    ~ShiftJob();
    uint64_t start(std::shared_ptr<const Snapshot> a, std::shared_ptr<const Snapshot> b, int64_t shift,
                   const ShiftOptions& opt = {});
    void cancel();
    bool running() const;
    double progress() const;      // 0..1
    uint64_t generation() const;  // increments every time a run finishes
    std::shared_ptr<const ShiftResult> result() const;  // the last finished run (null before)

private:
    struct Run;
    std::shared_ptr<Run> current() const;
    std::shared_ptr<Run> run_;    // guarded by mu_
    std::vector<std::pair<std::thread, std::shared_ptr<Run>>> threads_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> generation_{0};
    uint64_t next_run_ = 0;
    mutable std::mutex mu_;
    std::shared_ptr<const ShiftResult> result_;
};

// Background compare. One run at a time; start() cancels a previous run without waiting for it
// (it finishes in the background and its result is discarded), like SearchJob.
class DiffJob {
public:
    ~DiffJob();
    // Returns the run's id (1, 2, ...), also stored in its DiffResult::run.
    uint64_t start(std::shared_ptr<const Snapshot> a, std::shared_ptr<const Snapshot> b, int64_t shift,
                   size_t max_ranges = 1000000);
    void cancel();                // non-blocking request
    bool running() const;
    double progress() const;      // 0..1
    uint64_t generation() const;  // increments every time a run finishes (poll to detect completion)
    // The last finished run (null before the first one). Shared, so polling never copies ranges.
    std::shared_ptr<const DiffResult> result() const;

private:
    struct Run;
    std::shared_ptr<Run> current() const;
    std::shared_ptr<Run> run_;    // guarded by mu_
    std::vector<std::pair<std::thread, std::shared_ptr<Run>>> threads_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> generation_{0};
    uint64_t next_run_ = 0;
    mutable std::mutex mu_;
    std::shared_ptr<const DiffResult> result_;
};

}  // namespace hx
