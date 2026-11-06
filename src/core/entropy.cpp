#include "core/entropy.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>

#include "core/highlight.h"  // rgba()

namespace hx {

const char* byte_class_name(ByteClass c) {
    switch (c) {
    case ByteClass::Zero: return "zero";
    case ByteClass::Whitespace: return "whitespace";
    case ByteClass::Printable: return "printable";
    case ByteClass::Control: return "control";
    case ByteClass::High: return "high";
    case ByteClass::Full: return "0xFF";
    }
    return "?";
}

// ---- pure helpers -------------------------------------------------------------------------------

float shannon_entropy(const uint64_t counts[256]) {
    uint64_t total = 0;
    for (int i = 0; i < 256; ++i) total += counts[i];
    if (!total) return 0.0f;
    double h = 0.0;
    const double inv = 1.0 / double(total);
    for (int i = 0; i < 256; ++i) {
        if (!counts[i]) continue;
        const double p = double(counts[i]) * inv;
        h -= p * std::log2(p);
    }
    return float(std::clamp(h, 0.0, 8.0));
}

uint32_t entropy_color(float bits) {
    struct Stop {
        float at;
        uint8_t r, g, b;
    };
    static const Stop stops[] = {
        {0.0f, 0x26, 0x2b, 0x36},  // empty / constant: dark blue-gray
        {2.5f, 0x2c, 0x4a, 0x7a},  // structured: blue
        {4.5f, 0x22, 0x84, 0x8e},  // text / code: teal
        {6.2f, 0x4c, 0xa8, 0x5a},  // dense data: green
        {7.2f, 0xd8, 0xb4, 0x3c},  // threshold: yellow
        {7.7f, 0xec, 0x7c, 0x2c},  // compressed: orange
        {8.0f, 0xe4, 0x3e, 0x3a},  // encrypted / random: red
    };
    constexpr int n = int(sizeof(stops) / sizeof(stops[0]));
    if (!(bits > 0.0f)) bits = 0.0f;  // also NaN
    if (bits > 8.0f) bits = 8.0f;
    int i = 0;
    while (i + 2 < n && bits > stops[i + 1].at) ++i;
    const Stop &a = stops[i], &b = stops[i + 1];
    const float t = std::clamp((bits - a.at) / (b.at - a.at), 0.0f, 1.0f);
    auto mix = [t](uint8_t x, uint8_t y) { return uint8_t(std::lround(float(x) + (float(y) - float(x)) * t)); };
    return rgba(mix(a.r, b.r), mix(a.g, b.g), mix(a.b, b.b));
}

size_t EntropyResult::bucket_of(uint64_t offset) const {
    if (buckets.empty() || !bucket_size) return 0;
    return size_t(std::min<uint64_t>(offset / bucket_size, uint64_t(buckets.size() - 1)));
}

EntropyResult entropy_layout(uint64_t size, uint32_t buckets) {
    EntropyResult r;
    r.doc_size = size;
    r.bucket_size = 1;
    if (!size) return r;
    const uint64_t want = std::min<uint64_t>(std::max<uint32_t>(buckets, 1), size);
    const uint64_t bs = (size - 1) / want + 1;  // ceil(size / want) without overflow
    const uint64_t n = (size - 1) / bs + 1;
    r.bucket_size = bs;
    r.buckets.resize(size_t(n));
    for (uint64_t i = 0; i < n; ++i) {
        EntropyBucket& b = r.buckets[size_t(i)];
        b.offset = i * bs;
        b.length = std::min(bs, size - b.offset);
    }
    return r;
}

EntropyBucket entropy_aggregate(const EntropyResult& r, uint64_t begin, uint64_t end) {
    EntropyBucket out;
    if (r.buckets.empty()) return out;
    const size_t b0 = r.bucket_of(begin);
    const size_t b1 = end > begin ? std::max(b0, r.bucket_of(end - 1)) : b0;
    out.offset = r.buckets[b0].offset;
    out.length = r.buckets[b1].offset + r.buckets[b1].length - out.offset;
    double w = 0.0, h = 0.0, cls[kByteClassCount] = {};
    for (size_t i = b0; i <= b1; ++i) {
        const EntropyBucket& b = r.buckets[i];
        if (!b.done) continue;
        out.done = true;
        out.sampled |= b.sampled;
        out.unreadable |= b.unreadable;
        out.nonzero |= b.nonzero;
        out.peak = std::max(out.peak, b.peak);
        out.bytes_read += b.bytes_read;
        out.hole_bytes += b.hole_bytes;
        if (!b.bytes_read && !b.hole_bytes) continue;  // unreadable from its first byte: no data
        const double bw = double(b.length);
        w += bw;
        h += bw * double(b.entropy);
        for (int c = 0; c < kByteClassCount; ++c) cls[c] += bw * double(b.class_frac[c]);
    }
    if (w > 0.0) {
        out.entropy = float(h / w);
        for (int c = 0; c < kByteClassCount; ++c) out.class_frac[c] = float(cls[c] / w);
    }
    return out;
}

bool entropy_spot(const EntropyBucket& b) {
    if (!b.done) return false;
    if (b.peak >= b.entropy + kEntropySpotBits) return true;
    return b.nonzero && b.class_frac[int(ByteClass::Zero)] >= 0.999f;
}

std::vector<std::pair<uint64_t, uint64_t>> snapshot_data_ranges(const Snapshot& snap, uint64_t lo, uint64_t hi,
                                                                size_t max_ranges) {
    std::vector<std::pair<uint64_t, uint64_t>> out;
    hi = std::min(hi, snap.size());
    if (lo >= hi || snap.pieces.empty() || snap.starts.size() != snap.pieces.size()) {
        if (lo < hi) out.emplace_back(lo, hi);
        return out;
    }
    auto add = [&out](uint64_t from, uint64_t to) {
        if (from >= to) return;
        if (!out.empty() && out.back().second == from) out.back().second = to;
        else out.emplace_back(from, to);
    };
    size_t i = size_t(std::upper_bound(snap.starts.begin(), snap.starts.end(), lo) - snap.starts.begin()) - 1;
    for (; i < snap.pieces.size() && snap.starts[i] < hi; ++i) {
        const Piece& p = snap.pieces[i];
        const uint64_t ps = snap.starts[i];
        const uint64_t a = std::max(lo, ps), b = std::min(hi, ps + p.len);
        const FileSource* src =
            p.src == Piece::Original && p.chunk < snap.sources.size() ? snap.sources[p.chunk].get() : nullptr;
        for (uint64_t pos = a; pos < b;) {
            uint64_t db = 0, de = 0;
            if (out.size() >= max_ranges) {  // enough: the rest counts as data
                add(pos, hi);
                return out;
            }
            const uint64_t off = p.start + (pos - ps);  // in the source
            if (!src || !src->data_range(off, db, de) || db < off) {  // unknown: all data
                add(pos, b);
                break;
            }
            if (db >= de || db - p.start >= b - ps) break;  // only a hole up to b
            const uint64_t lb = ps + (db - p.start);
            const uint64_t le = std::min(b, ps + (std::min(de, p.start + p.len) - p.start));
            add(lb, le);
            pos = le;
        }
    }
    return out;
}

// ---- snapshot comparison -------------------------------------------------------------------------

namespace {

// The object holding a piece's bytes (file version / add chunk); null if the index is unknown.
const void* piece_store(const Snapshot& s, const Piece& p) {
    if (p.src == Piece::Original)
        return p.chunk < s.sources.size() ? static_cast<const void*>(s.sources[p.chunk].get()) : nullptr;
    return p.chunk < s.chunks.size() ? static_cast<const void*>(s.chunks[p.chunk].get()) : nullptr;
}

// Same bytes (same storage, same position)?
bool same_store(const Snapshot& a, const Piece& p, uint64_t oa, const Snapshot& b, const Piece& q, uint64_t ob) {
    const void* store = piece_store(a, p);
    return store && p.src == q.src && store == piece_store(b, q) && p.start + oa == q.start + ob;
}

bool has_process_source(const Snapshot& s) {
    for (const auto& src : s.sources)
        if (src && src->kind() == SourceKind::Process) return true;
    return false;
}

}  // namespace

std::vector<std::pair<uint64_t, uint64_t>> snapshot_changes(const Snapshot& before, const Snapshot& after) {
    std::vector<std::pair<uint64_t, uint64_t>> out;
    auto add = [&out](uint64_t from, uint64_t to) {
        if (from >= to) return;
        if (!out.empty() && out.back().second == from) out.back().second = to;
        else out.emplace_back(from, to);
    };
    const bool same_size = before.size() == after.size();
    // Walk both piece lists in step (logical offset `pos`); `oa` / `ob` = bytes consumed inside
    // the current piece of before / after. Other sizes stop at the first difference.
    const size_t na = before.pieces.size(), nb = after.pieces.size();
    size_t i = 0, j = 0;
    uint64_t oa = 0, ob = 0, pos = 0;
    while (i < na && j < nb) {
        const Piece& p = before.pieces[i];
        const Piece& q = after.pieces[j];
        const uint64_t k = std::min(p.len - oa, q.len - ob);
        if (!same_store(before, p, oa, after, q, ob)) {
            if (!same_size) break;
            add(pos, pos + k);
        }
        pos += k;
        oa += k;
        ob += k;
        if (oa >= p.len) {
            ++i;
            oa = 0;
        }
        if (ob >= q.len) {
            ++j;
            ob = 0;
        }
    }
    add(std::min(pos, after.size()), after.size());  // shifted (other size) or past the shorter list
    return out;
}

// ---- background job -----------------------------------------------------------------------------

namespace {

constexpr size_t kSampleChunk = 4096;      // sampled buckets read chunks of this size
constexpr size_t kReadBlock = size_t(1) << 20;  // full buckets are read in blocks of this size
constexpr size_t kMaxDataRanges = 64;      // data ranges of a sparse file sampled per bucket (each
                                           // gets >= 1 chunk: at most 256 KiB over the budget)

std::atomic<void (*)(uint32_t)> g_bucket_hook{nullptr};

// Computes one bucket. Returns false if cancelled before it was finished (bucket stays pending).
bool compute_bucket(const Snapshot& snap, EntropyBucket& b, const EntropyOptions& opts,
                    const std::atomic<bool>& cancel, std::vector<uint8_t>& buf, uint64_t& io_at) {
    uint64_t counts[256] = {};
    const uint64_t end = b.offset + b.length;
    // Counts the bytes, 4 KiB chunk by chunk (peak / nonzero).
    auto count = [&](const uint8_t* p, size_t n) {
        for (size_t q = 0; q < n; q += kSampleChunk) {
            const size_t m = std::min(kSampleChunk, n - q);
            uint64_t c[256] = {};
            for (size_t i = 0; i < m; ++i) ++c[p[q + i]];
            for (int v = 0; v < 256; ++v) counts[v] += c[v];
            if (c[0] == m) continue;
            b.nonzero = true;
            b.peak = std::max(b.peak, shannon_entropy(c));
        }
    };
    // Reads the readable bytes of [off, off + len), skipping holes of a sparse source (they mark
    // the bucket unreadable). False (and marks the bucket) at a genuine I/O error.
    auto take = [&](uint64_t off, size_t len) {
        if (buf.size() < len) buf.resize(len);
        const uint64_t stop = off + len;
        while (off < stop) {
            const size_t want = size_t(stop - off);
            const size_t got = snap.read_valid(off, buf.data(), want);
            count(buf.data(), got);
            b.bytes_read += got;
            if (got == want) break;
            b.unreadable = true;
            const uint64_t at = off + got;
            const uint64_t resume = snap.next_readable(at);
            if (resume <= at) {
                io_at = std::min(io_at, at);
                return false;
            }
            off = resume;
        }
        return true;
    };
    // One chunk at `at` (at most up to `limit`, the next chunk's position, and `rend`, the end of
    // its data range). A chunk that starts in a hole of process memory moves to the next readable
    // byte unless that is past `limit`. False at an I/O error.
    auto chunk_at = [&](uint64_t at, uint64_t limit, uint64_t rend, uint64_t len) {
        const uint64_t s = snap.next_readable(at);
        if (s >= limit) {
            b.unreadable = true;
            return true;
        }
        if (s > at) b.unreadable = true;
        return take(s, size_t(std::min(len, rend - s)));
    };

    // Fully inside a hole (unmapped process memory): unreadable, nothing to read.
    if (snap.next_readable(b.offset) >= end) {
        b.unreadable = true;
        b.done = true;
        return true;
    }

    // Holes of a sparse file are zeros: only the data ranges are read.
    const auto data = snapshot_data_ranges(snap, b.offset, end, kMaxDataRanges);
    uint64_t dlen = 0;
    for (const auto& r : data) dlen += r.second - r.first;
    b.hole_bytes = b.length - dlen;

    const uint64_t sample = opts.sample_per_bucket;
    if (sample && dlen > sample) {
        // Evenly spaced chunks over the data (holes left out); the first starts at the first data
        // byte, the last ends at the last one. A data range no chunk landed in gets one chunk at
        // its start, so a small region of a sparse file is never skipped.
        b.sampled = true;
        const uint64_t chunk = std::min<uint64_t>(kSampleChunk, sample);
        const uint64_t n = std::max<uint64_t>(1, sample / chunk);
        const uint64_t stride = n > 1 ? (dlen - chunk) / (n - 1) : 0;
        std::vector<uint8_t> hit(data.size(), 0);
        size_t ri = 0;
        uint64_t rbase = 0;  // data position of data[ri].first
        bool ok = true;
        for (uint64_t k = 0; k < n && ok; ++k) {
            if (cancel.load(std::memory_order_relaxed)) return false;
            const uint64_t dpos = k * stride;
            while (ri + 1 < data.size() && dpos >= rbase + (data[ri].second - data[ri].first)) {
                rbase += data[ri].second - data[ri].first;
                ++ri;
            }
            const uint64_t rend = data[ri].second;
            uint64_t at = data[ri].first + (dpos - rbase);
            if (rend - data[ri].first >= chunk) at = std::min(at, rend - chunk);  // a whole chunk
            const uint64_t limit = k + 1 < n && stride ? std::min(rend, at + stride) : rend;
            hit[ri] = 1;
            ok = chunk_at(at, limit, rend, chunk);
        }
        for (size_t i = 0; i < data.size() && ok; ++i) {
            if (cancel.load(std::memory_order_relaxed)) return false;
            if (!hit[i]) ok = chunk_at(data[i].first, data[i].second, data[i].second, chunk);
        }
        // The chunks stand for all `dlen` data bytes; the holes add their zeros.
        if (b.hole_bytes && b.bytes_read) {
            const double scale = double(dlen) / double(b.bytes_read);
            for (uint64_t& c : counts) c = uint64_t(std::llround(double(c) * scale));
        }
    } else {
        for (const auto& r : data) {
            bool ok = true;
            for (uint64_t pos = r.first; pos < r.second && ok;) {
                if (cancel.load(std::memory_order_relaxed)) return false;
                const uint64_t s = snap.next_readable(pos);
                if (s >= r.second) {
                    b.unreadable = true;
                    break;
                }
                if (s > pos) b.unreadable = true;
                const size_t len = size_t(std::min<uint64_t>(kReadBlock, r.second - s));
                ok = take(s, len);
                pos = s + len;
            }
            if (!ok) break;
        }
    }
    counts[0] += b.hole_bytes;

    b.entropy = shannon_entropy(counts);
    uint64_t cls[kByteClassCount] = {}, total = 0;
    for (int v = 0; v < 256; ++v) {
        cls[int(byte_class(uint8_t(v)))] += counts[v];
        total += counts[v];
    }
    for (int c = 0; c < kByteClassCount; ++c) b.class_frac[c] = total ? float(double(cls[c]) / double(total)) : 0.0f;
    b.done = true;
    return true;
}

}  // namespace

struct EntropyJob::Run {
    std::atomic<bool> cancel{false};
    std::atomic<bool> finished{false};  // worker is about to exit: joining it does not block
    std::atomic<uint32_t> done{0};
    uint32_t total = 0;
};

void EntropyJob::set_bucket_hook_for_tests(void (*hook)(uint32_t done)) { g_bucket_hook = hook; }

EntropyJob::~EntropyJob() {
    for (auto& t : threads_) t.second->cancel = true;
    for (auto& t : threads_) t.first.join();
}

std::shared_ptr<EntropyJob::Run> EntropyJob::current() const {
    std::lock_guard<std::mutex> lock(mu_);
    return run_;
}

void EntropyJob::cancel() {
    if (auto r = current()) r->cancel = true;
}

bool EntropyJob::running() const { return running_.load(); }

double EntropyJob::progress() const {
    auto r = current();
    const uint32_t t = r ? r->total : 0, d = r ? r->done.load() : 0;
    if (!t) return running_.load() ? 0.0 : 1.0;
    return d >= t ? 1.0 : double(d) / double(t);
}

uint64_t EntropyJob::generation() const { return generation_.load(); }

std::shared_ptr<const EntropyResult> EntropyJob::result() const {
    std::lock_guard<std::mutex> lock(mu_);
    return result_;
}

void EntropyJob::start(std::shared_ptr<const Snapshot> snap, EntropyOptions opts) {
    launch(std::move(snap), opts, false);
}

void EntropyJob::rescan(std::shared_ptr<const Snapshot> snap, EntropyOptions opts) {
    launch(std::move(snap), opts, true);
}

void EntropyJob::launch(std::shared_ptr<const Snapshot> snap, EntropyOptions opts, bool incremental) {
    // Never block the UI thread on the previous run (it may sit in one slow read): cancel it, let it
    // finish in the background (it no longer publishes anything) and join it once it has exited.
    auto run = std::make_shared<Run>();
    EntropyResult layout = entropy_layout(snap ? snap->size() : 0, opts.buckets);
    run->total = uint32_t(layout.buckets.size());
    std::shared_ptr<const EntropyResult> base;  // rescan: the latest published result ...
    std::shared_ptr<const Snapshot> base_snap;  // ... and what it was computed from
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (run_) run_->cancel = true;
        run_ = run;
        if (incremental && result_snap_ && result_opts_.sample_per_bucket == opts.sample_per_bucket) {
            base = result_;
            base_snap = result_snap_;
        }
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
    std::thread th([this, run, snap = std::move(snap), opts, r = std::move(layout), base = std::move(base),
                    base_snap = std::move(base_snap)]() mutable {
        using clock = std::chrono::steady_clock;
        uint64_t io_at = UINT64_MAX;
        std::vector<uint8_t> buf;
        auto last_pub = clock::now();
        // Publishes a copy of r; superseded runs publish nothing. Returns false if superseded.
        auto publish = [&](bool final) {
            r.io_error = io_at != UINT64_MAX;
            r.io_error_offset = r.io_error ? io_at : 0;
            auto copy = std::make_shared<const EntropyResult>(r);
            std::lock_guard<std::mutex> lock(mu_);
            if (run_ != run) return false;
            result_ = std::move(copy);
            result_snap_ = snap;
            result_opts_ = opts;
            if (final) {
                running_ = false;
                generation_.fetch_add(1);
            }
            return true;
        };
        // Rescan: copy the computed buckets no changed range touches. Same layout only (then bucket
        // i covers the same offsets in both; a shorter / longer last bucket is recomputed).
        if (base && base_snap && snap && !has_process_source(*snap) && base->bucket_size == r.bucket_size &&
            base->buckets.size() == r.buckets.size()) {
            const auto changes = snapshot_changes(*base_snap, *snap);
            size_t ci = 0;  // first change that ends after the current bucket's start
            for (size_t i = 0; i < r.buckets.size(); ++i) {
                EntropyBucket& b = r.buckets[i];
                const EntropyBucket& old = base->buckets[i];
                while (ci < changes.size() && changes[ci].second <= b.offset) ++ci;
                if (!old.done || old.offset != b.offset || old.length != b.length) continue;
                if (ci < changes.size() && changes[ci].first < b.offset + b.length) continue;  // touched
                b = old;
                ++r.reused;
                if (base->io_error && base->io_error_offset >= b.offset && base->io_error_offset - b.offset < b.length)
                    io_at = std::min(io_at, base->io_error_offset);
            }
            if (r.reused && r.reused < r.buckets.size()) publish(false);  // paint the kept buckets now
        }
        for (size_t i = 0; i < r.buckets.size(); ++i) {
            if (run->cancel.load() || !snap) break;
            EntropyBucket& b = r.buckets[i];
            if (b.done) {  // reused
                r.done = uint32_t(i + 1);
                run->done = r.done;
                continue;
            }
            if (!compute_bucket(*snap, b, opts, run->cancel, buf, io_at)) break;
            r.bytes_read += b.bytes_read;
            r.done = uint32_t(i + 1);
            run->done = r.done;
            const auto now = clock::now();
            const bool last = i + 1 == r.buckets.size();
            if (!last && (opts.publish_ms <= 0 || now - last_pub >= std::chrono::milliseconds(opts.publish_ms))) {
                last_pub = now;
                if (!publish(false)) break;
            }
            if (auto hook = g_bucket_hook.load()) hook(r.done);
        }
        r.cancelled = run->cancel.load();
        r.finished = true;
        publish(true);
        run->finished = true;
    });
    threads_.emplace_back(std::move(th), std::move(run));
}

}  // namespace hx
