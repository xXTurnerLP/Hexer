#pragma once
// Checksums and cryptographic hashes, implemented from scratch (no dependencies).
//
//   * Hasher: incremental interface (init / update / finish). make_hasher() returns one that is
//     already initialised; init() resets it for reuse after finish().
//   * Registry: hash_algorithms() lists every algorithm in display order. Lookup by name is
//     forgiving: case-insensitive and ignoring everything but letters and digits, so "CRC-32",
//     "crc32" and "Crc_32" are the same; a few aliases exist ("crc32c" = "castagnoli" = "iscsi",
//     "crc16ccitt" / "ibm3740" = CRC-16/CCITT-FALSE, "crc8smbus" = CRC-8, ...).
//   * Digests are bytes in the conventional display order: checksums/CRCs as a big-endian integer
//     of their width (CRC-32 of "123456789" -> CB F4 39 26), MD5/SHA as their byte string.
//   * HashJob: several algorithms over a Snapshot range in one pass on a worker thread (4 MiB
//     reads), with progress / cancel / generation like SearchJob. Never loads the whole range.
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

class Hasher {
public:
    virtual ~Hasher() = default;
    virtual void init() = 0;                                  // back to the empty-input state
    virtual void update(const uint8_t* data, size_t len) = 0;
    virtual std::vector<uint8_t> finish() = 0;                // digest; call init() before reusing
};

struct HashAlgorithm {
    const char* name;           // display name: "CRC-32", "CRC-16/MODBUS", "SHA-256", "FNV-1a/64"
    size_t digest_size;         // bytes
    bool is_default;            // checked by default in the Hashes panel (CRC-32, MD5, SHA-1, SHA-256)
    std::unique_ptr<Hasher> (*create)();
};

// sum8, xor8, CRC-8 (SMBus), CRC-16/CCITT-FALSE, CRC-16/MODBUS, CRC-16/XMODEM, CRC-32 (ISO-HDLC),
// CRC-32C (Castagnoli), Adler-32, Fletcher-16, FNV-1a/32, FNV-1a/64, MD5, SHA-1, SHA-256, SHA-512.
const std::vector<HashAlgorithm>& hash_algorithms();
const HashAlgorithm* find_hash_algorithm(const std::string& name);  // nullptr if unknown
std::unique_ptr<Hasher> make_hasher(const std::string& name);       // nullptr if unknown

std::string to_hex(const std::vector<uint8_t>& bytes, bool uppercase = false);

// One-shot helper (scripts: hx.hash(algo, bytes)). Lowercase hex digest; "" if `algo` is unknown.
std::string hash_hex(const std::string& algo, const uint8_t* data, size_t len);

// For comparing a user-typed expected value with a digest: strips whitespace, ':' and '-',
// one leading "0x"/"0X", and lowercases. Returns "" if anything else than hex digits remains.
std::string normalize_hex(const std::string& s);
// normalize_hex(expected) is non-empty and equals normalize_hex(digest_hex).
bool hex_matches(const std::string& expected, const std::string& digest_hex);

// Blocking primitive: feeds [offset, offset + length) of `snap` (clamped to its size) to every
// hasher in 4 MiB blocks (hashers are not init()ed or finished here). Returns false if cancelled or
// if a byte could not be read (then *io_error_offset = the first unreadable byte, else UINT64_MAX).
// `progress` (bytes fed) may be null.
bool hash_range(const Snapshot& snap, uint64_t offset, uint64_t length, const std::vector<Hasher*>& hashers,
                const std::atomic<bool>* cancel = nullptr, std::atomic<uint64_t>* progress = nullptr,
                uint64_t* io_error_offset = nullptr);
// One algorithm over a snapshot range (scripts: doc:hash(algo, off, len)); lowercase hex in `out`.
// False with *err on an unknown algorithm or an I/O error.
bool hash_snapshot_hex(const Snapshot& snap, const std::string& algo, uint64_t offset, uint64_t length,
                       std::string& out, std::string* err = nullptr);

// Background hashing. One run at a time; start() cancels any previous run without waiting for it
// (that run finishes in the background and its result is discarded).
class HashJob {
public:
    ~HashJob();

    // Hashes [offset, offset + length) (clamped to the snapshot) with every named algorithm in one
    // pass. Unknown names are skipped.
    void start(std::shared_ptr<const Snapshot> snap, uint64_t offset, uint64_t length,
               std::vector<std::string> algos);
    void cancel();                 // non-blocking request
    bool running() const;
    double progress() const;       // 0..1
    uint64_t generation() const;   // increments every time a run finishes (poll to detect completion)

    struct Value {
        std::string algo;          // display name (HashAlgorithm::name)
        std::string hex;           // lowercase digest
    };
    struct Result {
        uint64_t offset = 0, length = 0;  // the range actually hashed (after clamping)
        std::vector<Value> values;        // in the order requested; empty if cancelled / io_error
        bool cancelled = false;
        bool io_error = false;            // a byte could not be read; no values
        uint64_t io_error_offset = 0;
    };
    Result result() const;         // copy of the last finished run

private:
    struct Run;
    std::shared_ptr<Run> current() const;
    std::shared_ptr<Run> run_;     // guarded by mu_
    std::vector<std::pair<std::thread, std::shared_ptr<Run>>> threads_;  // current + superseded runs
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> generation_{0};
    mutable std::mutex mu_;
    Result result_;
};

}  // namespace hx
