#pragma once
// XOR / ADD / ROL brute force: find simply obfuscated copies of a known plaintext, guess XOR keys,
// decode bytes for previews or (through Document, undoable) in place.
//
// Transforms (the "encoding" that turned plaintext p into the data d):
//   Xor     d = p ^ k                  1-byte key, k = 1..255
//   Add     d = p + k  (mod 256)       1-byte key, k = 1..255 (SUB k is ADD 256-k)
//   Rol     d = rotl(p, k)             k = 1..7 bits (ROR k is ROL 8-k)
//   XorKey  d[x] = p[x] ^ key[x % L]   multi-byte key, L = 2..16
//
// Key convention (one for scan hits, key_guess and the apply helpers): the key byte that applies to
// the byte at ABSOLUTE offset x is key[x % L]. A file XORed with "SECRET" from offset 0 reports the
// key "SECRET" wherever the plaintext is found. `phase` = key index of a range's first byte
// (= offset % L); 1-byte transforms have L = 1, phase 0.
//
// Scan (scan_xor / XorScanJob): every offset o where data[o, o+n) == encode(plaintext, key) for
// some key, all keys at once. The first byte determines the candidate key (k = d[o] ^ p[0],
// d[o] - p[0], ...), the rest verifies it - key-independent, O(1) per offset on average. Streaming
// in 4 MiB blocks with an n-1 byte overlap, so a match across a block edge is reported once.
// Holes of a sparse source (unmapped process memory) are skipped cheaply via
// Snapshot::next_readable (no match spans one; XorScanResult::skipped counts them); a genuine I/O
// error stops the scan.
// Not reported: the identity (key 0, a ROL that leaves this plaintext unchanged), multi-byte keys
// that are constant (a 1-byte XOR hit) or repeat a shorter key (reported at the shorter length).
// A multi-byte key of length L needs n >= 2*L and n >= L+4 plaintext bytes (the bytes past the
// first L verify the key; fewer would make random data match). False positives on random data:
// a 1-byte transform with an n-byte plaintext matches by chance with p ~ 2^(-8*(n-1)) per offset,
// so use at least 4 plaintext bytes on large files ("MZ" alone matches 1/256 of all offsets).
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "core/document.h"

namespace hx {

enum class XorTransform : uint8_t { Xor, Add, Rol, XorKey };
const char* transform_name(XorTransform t);  // "XOR", "ADD", "ROL", "XOR key"

constexpr uint32_t kXorMaxKeyLen = 16;
constexpr size_t kXorBlock = size_t(4) << 20;  // bytes per read

struct XorScanOptions {
    bool xor8 = true;            // XOR with a 1-byte key
    bool add8 = true;            // ADD / SUB with a 1-byte key
    bool rol = true;             // ROL / ROR 1..7 bits
    bool xor_multi = false;      // XOR with a 2..max_key_len byte key
    uint32_t max_key_len = kXorMaxKeyLen;  // clamped to 2..kXorMaxKeyLen
    size_t max_results = 100000;
};

struct XorHit {
    uint64_t offset = 0;
    XorTransform transform = XorTransform::Xor;
    std::vector<uint8_t> key;    // 1 byte for Xor / Add / Rol (Rol: the bit count), L for XorKey
    uint32_t phase = 0;          // key index of `offset` (= offset % L); 0 for 1-byte transforms
};

struct XorScanResult {
    std::vector<XorHit> hits;    // by offset, then transform
    uint64_t begin = 0, end = 0; // the range actually scanned (end clamped to the snapshot size)
    size_t plaintext_len = 0;
    bool truncated = false;      // stopped after max_results hits
    bool cancelled = false;      // hits found before the cancel are kept
    bool io_error = false;       // stopped at an unreadable byte (hits before it are kept)
    uint64_t io_error_offset = 0;
    uint64_t skipped = 0;        // bytes in holes of a sparse source passed over (not errors)
};

// "XOR 0x5A", "ADD 0x03 (SUB 0xFD)", "ROL 3 (ROR 5)", "XOR key 53 45 43 52 45 54 \"SECRET\"".
std::string describe_key(XorTransform t, const std::vector<uint8_t>& key);

// Encodes (decode=false: p -> d) or decodes (decode=true: d -> p) `n` bytes in place. Byte i uses
// key[(phase + i) % key.size()] (XorKey; the other transforms use key[0]). An empty key is a no-op.
void apply_transform(uint8_t* data, size_t n, XorTransform t, const std::vector<uint8_t>& key,
                     uint64_t phase, bool decode);
std::vector<uint8_t> apply_transform(std::vector<uint8_t> data, XorTransform t,
                                     const std::vector<uint8_t>& key, uint64_t phase, bool decode);

// Decodes (or encodes) [begin, begin+len) of `doc` in place as ONE undo step labelled `label`
// (default "<transform> selection"), in 1 MiB chunks; key index of `begin` = `phase`. Runs on the
// caller's (UI) thread, so it refuses ranges above `max_len` (default 256 MiB, like the
// "Selection: XOR with key" script command). False + *err when rejected (busy, read-only, empty
// key, too large, an unreadable byte in the range); a failure partway leaves the document and its
// history (undo AND redo stack) as they were (Document::abort_group).
constexpr uint64_t kXorApplyMax = uint64_t(256) << 20;
bool apply_transform(Document& doc, uint64_t begin, uint64_t len, XorTransform t,
                     const std::vector<uint8_t>& key, uint64_t phase, bool decode,
                     std::string* err = nullptr, const std::string& label = {},
                     uint64_t max_len = kXorApplyMax);

// Known-plaintext input of the UI. hex=true: anything parse_bytes() accepts ("4D 5A", "0x4d,0x5a").
// hex=false: UTF-8 text with C escapes \0 \n \r \t \\ \" \xHH (e.g. "PE\0\0", "\x89PNG").
bool parse_plaintext(const std::string& text, bool hex, std::vector<uint8_t>& out, std::string* err = nullptr);

// Blocking primitive: scans [begin, end) of `snap`. `progress` (if non-null) gets bytes scanned.
void scan_xor(const Snapshot& snap, uint64_t begin, uint64_t end, const std::vector<uint8_t>& plaintext,
              const XorScanOptions& opt, XorScanResult& out, const std::atomic<bool>* cancel = nullptr,
              std::atomic<uint64_t>* progress = nullptr);

// ---- key guessing --------------------------------------------------------------------------------
// For XOR-obfuscated data whose plaintext is dominated by one byte value (zeros in executables and
// tables; pass ' ' for text): for every key length L = 1..max_len (with at least 2 bytes per
// column), key[c] = the most common byte of column c (the bytes at i % L == c). score = fraction
// of the bytes that decode to `plain_byte` with that key, minus 0.001 per key byte (ties go to the
// shorter key). Keys that repeat a shorter key are dropped (that one is listed). Ranked best first.
// `base_offset` = absolute offset of data[0]: keys follow the absolute convention above.
struct KeyCandidate {
    std::vector<uint8_t> key;
    double score = 0;            // 0..1
};
std::vector<KeyCandidate> key_guess(const uint8_t* data, size_t n, uint64_t base_offset = 0,
                                    uint8_t plain_byte = 0, uint32_t max_len = kXorMaxKeyLen);

// ---- background job --------------------------------------------------------------------------------
// Same model as SearchJob / StringsJob: one run at a time; start() cancels a previous run without
// waiting for it (it finishes in the background and publishes nothing).
class XorScanJob {
public:
    XorScanJob() = default;
    ~XorScanJob();
    XorScanJob(const XorScanJob&) = delete;
    XorScanJob& operator=(const XorScanJob&) = delete;

    void start(std::shared_ptr<const Snapshot> snap, uint64_t begin, uint64_t end,
               std::vector<uint8_t> plaintext, XorScanOptions opt);
    void cancel();                 // non-blocking request
    bool running() const;
    double progress() const;       // 0..1
    uint64_t generation() const;   // increments every time a run finishes (poll to detect completion)

    struct Result {
        XorScanResult scan;
        std::vector<uint8_t> plaintext;
        XorScanOptions options;
        std::shared_ptr<const Snapshot> snap;  // what was scanned
    };
    // The last finished run (never modified after publishing); null before the first one.
    std::shared_ptr<const Result> result() const;

private:
    struct Run;
    std::shared_ptr<Run> current() const;
    std::shared_ptr<Run> run_;
    std::vector<std::pair<std::thread, std::shared_ptr<Run>>> threads_;  // current + superseded runs
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> generation_{0};
    mutable std::mutex mu_;
    std::shared_ptr<const Result> result_;
};

}  // namespace hx
