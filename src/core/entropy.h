#pragma once
// Byte classes (shared by the hex view's byte-class coloring and the minimap) + file entropy overview.
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include "core/document.h"

namespace hx {

// FROZEN contract (used by several modules): classification of a single byte value.
enum class ByteClass : uint8_t {
    Zero,        // 0x00
    Whitespace,  // \t \n \v \f \r and space (0x09-0x0D, 0x20)
    Printable,   // 0x21-0x7E
    Control,     // 0x01-0x08, 0x0E-0x1F, 0x7F
    High,        // 0x80-0xFE
    Full,        // 0xFF
};
constexpr int kByteClassCount = 6;
constexpr ByteClass byte_class(uint8_t b) {
    return b == 0x00 ? ByteClass::Zero
         : b == 0xFF ? ByteClass::Full
         : (b >= 0x09 && b <= 0x0D) || b == 0x20 ? ByteClass::Whitespace
         : b >= 0x21 && b <= 0x7E ? ByteClass::Printable
         : b >= 0x80 ? ByteClass::High
         : ByteClass::Control;
}
const char* byte_class_name(ByteClass c);

// ---- entropy overview ---------------------------------------------------------------------------

// Shannon entropy of a byte histogram (256 counts) in bits per byte, 0..8. 0 for an empty histogram.
float shannon_entropy(const uint64_t counts[256]);

// Dark-mode heat ramp for an entropy value (0..8 bits/byte, clamped), packed 0xAABBGGRR:
// ~0 dark blue-gray, ~2-4 blue/teal, ~6 green, >7.2 (compressed / encrypted) orange to red.
uint32_t entropy_color(float bits);

struct EntropyOptions {
    uint32_t buckets = 1024;                   // at most this many (fewer for files smaller than this)
    uint64_t sample_per_bucket = 256 << 10;    // bigger buckets are sampled: this many bytes at most,
                                               // read as evenly spaced 4 KiB chunks (0 = read all)
    int publish_ms = 30;                       // publish partial results at most this often (0 = per bucket)
};

struct EntropyBucket {
    uint64_t offset = 0, length = 0;           // the bytes this bucket stands for
    float entropy = 0.0f;                      // bits/byte (0..8) of the bytes read
    float class_frac[kByteClassCount] = {};    // fraction of the bytes read in each ByteClass (sum 1)
    uint64_t bytes_read = 0;                   // < length when sampled or unreadable
    bool done = false;                         // computed (false = pending: draw neutral)
    bool sampled = false;                      // only part of the bucket was read
    bool unreadable = false;                   // an I/O error stopped reading this bucket, or it
                                               // has holes (sparse source: unmapped process
                                               // memory; skipped via Snapshot::next_readable, a
                                               // bucket fully inside one is done with nothing read)
};

struct EntropyResult {
    uint64_t doc_size = 0;                     // size of the snapshot scanned
    uint64_t bucket_size = 0;                  // every bucket but the last is this long (>= 1)
    std::vector<EntropyBucket> buckets;        // offsets/lengths set for all; computed in order
    uint32_t done = 0;                         // buckets[0, done) are computed
    bool finished = false;                     // the run ended (completed or cancelled)
    bool cancelled = false;
    bool io_error = false;                     // an I/O error made at least one bucket unreadable
    uint64_t io_error_offset = 0;              // with io_error: the first unreadable byte met
                                               // (holes of a sparse source are not I/O errors)
    uint64_t bytes_read = 0;                   // total bytes read so far (bounded by sampling)

    // Index of the bucket holding `offset` (clamped to the last bucket; 0 if there are none).
    size_t bucket_of(uint64_t offset) const;
};

// Bucket layout without computing anything: bucket_size = ceil(size / min(buckets, size)), every
// bucket that long except a shorter last one. Empty for size 0.
EntropyResult entropy_layout(uint64_t size, uint32_t buckets);

// Combines the computed buckets overlapping [begin, end) into one (weighted by length; an empty
// range uses the bucket holding `begin`). Pending buckets are ignored; done == false if none of
// them is computed yet. sampled / unreadable are or-ed. offset/length span the buckets used.
EntropyBucket entropy_aggregate(const EntropyResult& r, uint64_t begin, uint64_t end);

// Background entropy scan (SearchJob pattern). start() cancels any previous run without waiting for
// it; that run finishes in the background and publishes nothing more. Results are published
// progressively: result() returns the buckets computed so far, so a minimap can paint while the
// scan runs. Bounded work: at most buckets * sample_per_bucket bytes are read.
class EntropyJob {
public:
    ~EntropyJob();

    void start(std::shared_ptr<const Snapshot> snap, EntropyOptions opts = {});
    void cancel();                 // non-blocking request
    bool running() const;
    double progress() const;       // 0..1 (buckets done)
    uint64_t generation() const;   // increments every time a run finishes (poll to detect completion)
    // Latest published state of the current run (null before the first publication). Cheap: the
    // pointer is shared, never modified after publication.
    std::shared_ptr<const EntropyResult> result() const;

    // Test hook: called on the worker thread after each bucket is published (null = none).
    static void set_bucket_hook_for_tests(void (*hook)(uint32_t done));

private:
    struct Run;
    std::shared_ptr<Run> current() const;
    std::shared_ptr<Run> run_;     // guarded by mu_
    std::vector<std::pair<std::thread, std::shared_ptr<Run>>> threads_;  // current + superseded runs
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> generation_{0};
    mutable std::mutex mu_;
    std::shared_ptr<const EntropyResult> result_;
};

}  // namespace hx
