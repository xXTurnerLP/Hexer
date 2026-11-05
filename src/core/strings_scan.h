#pragma once
// Strings extraction ("strings" tool): finds runs of printable characters in a Snapshot range on a
// worker thread. Hits store only where a string is, never its text (a scan can report a million
// strings of a multi-TB file); string_hit_text() reads the text of one hit on demand.
//
// Characters: printable ASCII 0x20-0x7E and \t, plus \r and \n with include_newlines.
//   ASCII     one byte per character.
//   UTF-16LE  two bytes per character, a code unit holding one of the characters above
//   UTF-16BE  (0x0041 = 'A'); runs are found at even and at odd offsets.
// A run is reported when it has at least min_length characters. The scan is streaming (runs are
// carried across the 4 MiB read blocks), so a string crossing a block edge is reported once, whole.
// Strings are clipped to the scanned range [begin, end).
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

enum class StringEncoding : uint8_t { Ascii, Utf16LE, Utf16BE };
const char* encoding_name(StringEncoding e);  // "ASCII", "UTF-16LE", "UTF-16BE"

struct StringHit {
    uint64_t offset = 0;       // first byte
    uint64_t byte_length = 0;  // bytes covered (char_count * 2 for UTF-16)
    uint64_t char_count = 0;
    StringEncoding encoding = StringEncoding::Ascii;
};

struct StringsOptions {
    bool ascii = true;
    bool utf16le = true;
    bool utf16be = false;
    bool include_newlines = false;  // \r and \n are string characters (else they end a string)
    uint32_t min_length = 5;        // characters (values < 1 count as 1)
    size_t max_results = 1000000;
};

struct StringsScanResult {
    std::vector<StringHit> hits;  // sorted by offset, then encoding
    uint64_t begin = 0, end = 0;  // the range actually scanned (end clamped to the snapshot size)
    bool truncated = false;       // stopped after max_results hits
    bool cancelled = false;       // hits found before the cancel are kept
    bool io_error = false;        // stopped at an unreadable byte (strings before it are kept)
    uint64_t io_error_offset = 0;
};

constexpr size_t kStringsBlock = size_t(4) << 20;  // bytes per read

// Blocking primitive: scans [begin, end) of `snap`. `progress` (if non-null) gets bytes scanned.
void scan_strings(const Snapshot& snap, uint64_t begin, uint64_t end, const StringsOptions& opt,
                  StringsScanResult& out, const std::atomic<bool>* cancel = nullptr,
                  std::atomic<uint64_t>* progress = nullptr);

// Text of one hit: its characters (UTF-16 code units narrowed to ASCII), at most max_chars of them.
// Reads at most max_chars * 2 bytes. Unreadable bytes read as 0 (shown as "\0" by escape_string_text).
std::string string_hit_text(const Snapshot& snap, const StringHit& hit, size_t max_chars = 256);
std::string string_hit_text(const Document& doc, const StringHit& hit, size_t max_chars = 256);
// Display form: \t \r \n and other control bytes as C escapes ("\t", "\x00").
std::string escape_string_text(const std::string& text);

// Background scan, same model as SearchJob: one run at a time; start() cancels a previous run
// without waiting for it (it finishes in the background and publishes nothing).
class StringsJob {
public:
    ~StringsJob();
    StringsJob() = default;
    StringsJob(const StringsJob&) = delete;
    StringsJob& operator=(const StringsJob&) = delete;

    void start(std::shared_ptr<const Snapshot> snap, uint64_t begin, uint64_t end, StringsOptions opt);
    void cancel();                 // non-blocking request
    bool running() const;
    double progress() const;       // 0..1
    uint64_t generation() const;   // increments every time a run finishes (poll to detect completion)

    struct Result {
        StringsScanResult scan;
        StringsOptions options;
        std::shared_ptr<const Snapshot> snap;  // what was scanned (read hit texts from it)
    };
    // The last finished run (shared, never modified after publishing); null before the first one.
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

// Incremental case-insensitive (ASCII) substring filter over the text of hits, so a million hits
// can be filtered a slice per frame without freezing the UI. Texts are string_hit_text(..., 256).
class StringsFilter {
public:
    void reset(const std::string& needle);  // starts over; "" matches everything
    // Tests up to `max_hits` more hits; returns true once every hit has been tested.
    bool step(const Snapshot& snap, const std::vector<StringHit>& hits, size_t max_hits);
    bool done(size_t hit_count) const { return tested_ >= hit_count; }
    size_t tested() const { return tested_; }
    const std::string& needle() const { return needle_; }       // lower-cased
    const std::vector<size_t>& matches() const { return matches_; }  // indices into hits, ascending

private:
    std::string needle_;
    size_t tested_ = 0;
    std::vector<size_t> matches_;
};

}  // namespace hx
