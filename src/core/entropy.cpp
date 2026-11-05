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
        out.bytes_read += b.bytes_read;
        if (!b.bytes_read) continue;  // unreadable from its first byte: no data to average
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

// ---- background job -----------------------------------------------------------------------------

namespace {

constexpr size_t kSampleChunk = 4096;      // sampled buckets read chunks of this size
constexpr size_t kReadBlock = size_t(1) << 20;  // full buckets are read in blocks of this size

std::atomic<void (*)(uint32_t)> g_bucket_hook{nullptr};

// Computes one bucket. Returns false if cancelled before it was finished (bucket stays pending).
bool compute_bucket(const Snapshot& snap, EntropyBucket& b, const EntropyOptions& opts,
                    const std::atomic<bool>& cancel, std::vector<uint8_t>& buf, uint64_t& io_at) {
    uint64_t counts[256] = {};
    // Reads [off, off + len); false (and marks the bucket) at the first unreadable byte.
    auto take = [&](uint64_t off, size_t len) {
        if (buf.size() < len) buf.resize(len);
        const size_t got = snap.read_valid(off, buf.data(), len);
        const uint8_t* p = buf.data();
        for (size_t i = 0; i < got; ++i) ++counts[p[i]];
        b.bytes_read += got;
        if (got < len) {
            b.unreadable = true;
            io_at = std::min(io_at, off + got);
            return false;
        }
        return true;
    };

    const uint64_t sample = opts.sample_per_bucket;
    if (sample && b.length > sample) {
        // Evenly spaced chunks; the first starts at the bucket start, the last ends at its end.
        b.sampled = true;
        const uint64_t chunk = std::min<uint64_t>(kSampleChunk, sample);
        const uint64_t n = std::max<uint64_t>(1, sample / chunk);
        const uint64_t stride = n > 1 ? (b.length - chunk) / (n - 1) : 0;
        for (uint64_t k = 0; k < n; ++k) {
            if (cancel.load(std::memory_order_relaxed)) return false;
            if (!take(b.offset + k * stride, size_t(chunk))) break;
        }
    } else {
        for (uint64_t pos = 0; pos < b.length;) {
            if (cancel.load(std::memory_order_relaxed)) return false;
            const size_t len = size_t(std::min<uint64_t>(kReadBlock, b.length - pos));
            if (!take(b.offset + pos, len)) break;
            pos += len;
        }
    }

    b.entropy = shannon_entropy(counts);
    uint64_t cls[kByteClassCount] = {};
    for (int v = 0; v < 256; ++v) cls[int(byte_class(uint8_t(v)))] += counts[v];
    for (int c = 0; c < kByteClassCount; ++c)
        b.class_frac[c] = b.bytes_read ? float(double(cls[c]) / double(b.bytes_read)) : 0.0f;
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
    // Never block the UI thread on the previous run (it may sit in one slow read): cancel it, let it
    // finish in the background (it no longer publishes anything) and join it once it has exited.
    auto run = std::make_shared<Run>();
    EntropyResult layout = entropy_layout(snap ? snap->size() : 0, opts.buckets);
    run->total = uint32_t(layout.buckets.size());
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
    std::thread th([this, run, snap = std::move(snap), opts, r = std::move(layout)]() mutable {
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
            if (final) {
                running_ = false;
                generation_.fetch_add(1);
            }
            return true;
        };
        for (size_t i = 0; i < r.buckets.size(); ++i) {
            if (run->cancel.load() || !snap) break;
            EntropyBucket& b = r.buckets[i];
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
