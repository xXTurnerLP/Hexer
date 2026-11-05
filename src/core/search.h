#pragma once
// Streaming pattern search over a Snapshot (works on files of any size, runs off the UI thread).
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "core/document.h"

namespace hx {

enum class SearchKind {
    Hex,    // "DE AD ?? EF", "deadbeef", "0xDE,0xAD" ; "??" = any byte
    Text,   // UTF-8 bytes of the input
    Utf16,  // UTF-16LE encoding of the input
};

struct Pattern {
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;   // 0xFF = must match, 0x00 = wildcard (same length as bytes)
    bool icase = false;          // ASCII case-insensitive (Text/Utf16 only)
    size_t size() const { return bytes.size(); }
};

bool compile_pattern(SearchKind kind, const std::string& input, bool icase, Pattern& out,
                     std::string* err = nullptr);

// Blocking primitive. Searches forward from `from` (inclusive) or backward from `from` (match must
// start at < from). No wrap-around. Updates `progress` (bytes scanned) if non-null; returns
// nullopt if not found or cancelled. Reads in large blocks with overlap; never loads the file.
std::optional<uint64_t> find_in(const Snapshot& snap, const Pattern& pat, uint64_t from, bool forward,
                                const std::atomic<bool>* cancel = nullptr,
                                std::atomic<uint64_t>* progress = nullptr);

// Background search job. One job at a time; start() cancels and joins any previous run.
class SearchJob {
public:
    enum class Mode { Next, Prev, All };
    ~SearchJob();

    // Next/Prev wrap around once (reporting `wrapped`). All collects up to `max_results` offsets.
    void start(std::shared_ptr<const Snapshot> snap, Pattern pat, uint64_t from, Mode mode,
               size_t max_results = 100000);
    void cancel();                 // non-blocking request
    bool running() const;
    double progress() const;       // 0..1
    uint64_t generation() const;   // increments every time a run finishes (poll to detect completion)

    struct Result {
        Mode mode = Mode::Next;
        std::vector<uint64_t> hits;  // Next/Prev: 0 or 1 entry
        size_t pattern_len = 0;
        bool wrapped = false;
        bool truncated = false;      // All: hit max_results
        bool cancelled = false;
    };
    Result result() const;         // copy of the last finished run

private:
    void join();
    std::thread thread_;
    std::atomic<bool> cancel_{false};
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> done_{0};
    std::atomic<uint64_t> total_{0};
    std::atomic<uint64_t> generation_{0};
    mutable std::mutex mu_;
    Result result_;
};

}  // namespace hx
