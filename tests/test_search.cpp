// Tests for core/search (over Document snapshots) and core/settings (+ paths) in a temp config dir.
#include <doctest/doctest.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "core/document.h"
#include "core/os_file.h"
#include "core/search.h"
#include "core/settings.h"
#include "holey_mem.h"

using namespace hx;

namespace {

using Bytes = std::vector<uint8_t>;
constexpr uint64_t kBlk = uint64_t(4) << 20;  // search block size (4 MiB)

std::shared_ptr<const Snapshot> snap_of(const Bytes& b) {
    auto doc = Document::create_from_bytes("test", b.data(), b.size());
    REQUIRE(doc);
    REQUIRE(doc->size() == b.size());
    return doc->snapshot();  // the snapshot keeps its data alive after the document is gone
}

Pattern pat(SearchKind k, const std::string& s, bool icase = false) {
    Pattern p;
    std::string err;
    bool ok = compile_pattern(k, s, icase, p, &err);
    INFO("pattern '" << s << "': " << err);
    REQUIRE(ok);
    return p;
}

bool match_at(const Bytes& d, const Pattern& p, uint64_t i) {
    if (i + p.size() > d.size()) return false;
    for (size_t k = 0; k < p.size(); ++k)
        if ((d[size_t(i) + k] & p.mask[k]) != (p.bytes[k] & p.mask[k])) return false;
    return true;
}

// Naive reference: every match start, ascending.
std::vector<uint64_t> ref_all(const Bytes& d, const Pattern& p) {
    std::vector<uint64_t> out;
    for (uint64_t i = 0; i + p.size() <= d.size(); ++i)
        if (match_at(d, p, i)) out.push_back(i);
    return out;
}

// find_in semantics on a precomputed match list.
std::optional<uint64_t> ref_find(const std::vector<uint64_t>& all, uint64_t from, bool forward) {
    auto it = std::lower_bound(all.begin(), all.end(), from);  // first start >= from
    if (forward) return it == all.end() ? std::nullopt : std::optional<uint64_t>(*it);
    return it == all.begin() ? std::nullopt : std::optional<uint64_t>(*(it - 1));
}

void wait_for(const SearchJob& job, uint64_t gen) {
    auto t0 = std::chrono::steady_clock::now();
    while (job.generation() == gen) {
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(60));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

SearchJob::Result run_job(SearchJob& job, std::shared_ptr<const Snapshot> s, const Pattern& p, uint64_t from,
                          SearchJob::Mode mode, size_t max_results = 100000) {
    uint64_t gen = job.generation();
    job.start(std::move(s), p, from, mode, max_results);
    wait_for(job, gen);
    CHECK_FALSE(job.running());
    return job.result();
}

void plant(Bytes& d, uint64_t at, const Bytes& what) {
    for (size_t i = 0; i < what.size() && at + i < d.size(); ++i) d[size_t(at + i)] = what[i];
}

struct TempDir {
    std::string path;
    TempDir() {
        std::error_code ec;
        std::string base = std::filesystem::temp_directory_path(ec).string();
        if (ec || base.empty()) base = ".";
        path = path_join(base, "hexer_test_" + std::to_string(std::random_device{}()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        REQUIRE(os_mkdirs(path));
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(std::filesystem::path(path), ec);
    }
};

}  // namespace

// ================================================================================================
// compile_pattern
// ================================================================================================

TEST_CASE("compile_pattern") {
    Pattern p = pat(SearchKind::Hex, "DE AD ?? EF");
    CHECK(p.bytes == Bytes{0xDE, 0xAD, 0x00, 0xEF});
    CHECK(p.mask == Bytes{0xFF, 0xFF, 0x00, 0xFF});
    p = pat(SearchKind::Hex, "0xDE,0xAD");
    CHECK(p.bytes == Bytes{0xDE, 0xAD});
    CHECK(p.mask == Bytes{0xFF, 0xFF});
    p = pat(SearchKind::Hex, "deadbeef");
    CHECK(p.size() == 4);
    p = pat(SearchKind::Hex, "4? ?F");  // nibble wildcards
    CHECK(p.bytes == Bytes{0x40, 0x0F});
    CHECK(p.mask == Bytes{0xF0, 0x0F});
    p = pat(SearchKind::Hex, "de:ad\t{be}");
    CHECK(p.bytes == Bytes{0xDE, 0xAD, 0xBE});

    p = pat(SearchKind::Text, "Hi!");
    CHECK(p.bytes == Bytes{'H', 'i', '!'});
    CHECK(p.mask == Bytes{0xFF, 0xFF, 0xFF});
    p = pat(SearchKind::Text, "Hi!", true);
    CHECK(p.icase);
    CHECK(p.mask == Bytes{0xDF, 0xDF, 0xFF});
    p = pat(SearchKind::Text, "\xC3\xA9");
    CHECK(p.bytes == Bytes{0xC3, 0xA9});

    p = pat(SearchKind::Utf16, "A\xE2\x82\xAC");  // "A€"
    CHECK(p.bytes == Bytes{0x41, 0x00, 0xAC, 0x20});
    p = pat(SearchKind::Utf16, "\xF0\x9F\x98\x80");
    CHECK(p.bytes == Bytes{0x3D, 0xD8, 0x00, 0xDE});
    p = pat(SearchKind::Utf16, "a", true);
    CHECK(p.mask == Bytes{0xDF, 0xFF});

    Pattern bad;
    std::string err;
    CHECK_FALSE(compile_pattern(SearchKind::Hex, "", false, bad, &err));
    CHECK_FALSE(compile_pattern(SearchKind::Hex, "DEA", false, bad, &err));
    CHECK_FALSE(compile_pattern(SearchKind::Hex, "DE AG", false, bad, &err));
    CHECK(!err.empty());
    CHECK_FALSE(compile_pattern(SearchKind::Text, "", false, bad, &err));
    CHECK_FALSE(compile_pattern(SearchKind::Utf16, "\xFF", false, bad, &err));
    CHECK_FALSE(compile_pattern(SearchKind::Utf16, "", false, bad, &err));
}

// ================================================================================================
// find_in
// ================================================================================================

TEST_CASE("find_in: small documents, both directions, EOF edges") {
    Bytes d = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', ' ', 'h', 'e', 'l', 'l', 'o'};
    auto s = snap_of(d);
    Pattern lo = pat(SearchKind::Text, "hello");
    CHECK(find_in(*s, lo, 0, true) == 12u);
    CHECK(find_in(*s, lo, 12, true) == 12u);   // inclusive start
    CHECK(find_in(*s, lo, 13, true) == std::nullopt);
    CHECK(find_in(*s, lo, 17, true) == std::nullopt);
    CHECK(find_in(*s, lo, 1000, true) == std::nullopt);
    CHECK(find_in(*s, lo, 17, false) == 12u);  // match ends exactly at EOF
    CHECK(find_in(*s, lo, 12, false) == std::nullopt);  // must start < from
    Pattern ic = pat(SearchKind::Text, "HELLO", true);
    CHECK(find_in(*s, ic, 0, true) == 0u);
    CHECK(find_in(*s, ic, 1, true) == 12u);
    CHECK(find_in(*s, ic, 12, false) == 0u);
    CHECK(find_in(*s, ic, UINT64_MAX, false) == 12u);
    Pattern cs = pat(SearchKind::Text, "HELLO");
    CHECK(find_in(*s, cs, 0, true) == std::nullopt);
    Pattern whole = pat(SearchKind::Text, std::string(d.begin(), d.end()));
    CHECK(find_in(*s, whole, 0, true) == 0u);
    CHECK(find_in(*s, whole, 1, true) == std::nullopt);
    CHECK(find_in(*s, whole, 17, false) == 0u);
    CHECK(find_in(*s, whole, 0, false) == std::nullopt);
    Pattern longer = pat(SearchKind::Text, std::string(d.begin(), d.end()) + "!");
    CHECK(find_in(*s, longer, 0, true) == std::nullopt);
    CHECK(find_in(*s, longer, 100, false) == std::nullopt);
    Pattern last = pat(SearchKind::Hex, "6F");  // 'o' last byte
    CHECK(find_in(*s, last, 16, true) == 16u);
    CHECK(find_in(*s, last, 17, false) == 16u);
    CHECK(find_in(*s, last, 16, false) == 7u);
    // icase must not fold non-letters: '@' (0x40) vs '`' (0x60)
    Bytes at = {'`'};
    CHECK(find_in(*snap_of(at), pat(SearchKind::Text, "@", true), 0, true) == std::nullopt);

    Pattern empty;
    CHECK(find_in(*s, empty, 0, true) == std::nullopt);

    auto e = snap_of(Bytes{});
    CHECK(find_in(*e, lo, 0, true) == std::nullopt);
    CHECK(find_in(*e, lo, 0, false) == std::nullopt);
}

TEST_CASE("find_in: UTF-16 and case folding") {
    Bytes d = {0x00, 'H', 0x00, 'i', 0x00, 0x2D, 0x6E, 'h', 0x00, 'I', 0x00};
    auto s = snap_of(d);
    // LE "Hi" at offset 1
    CHECK(find_in(*s, pat(SearchKind::Utf16, "Hi"), 0, true) == 1u);
    CHECK(find_in(*s, pat(SearchKind::Utf16, "hi"), 0, true) == std::nullopt);
    CHECK(find_in(*s, pat(SearchKind::Utf16, "hi", true), 0, true) == 1u);
    CHECK(find_in(*s, pat(SearchKind::Utf16, "hi", true), 2, true) == 7u);
    // U+4E2D (LE 2D 4E): its high byte 'N' must not be case-folded to 'n' (0x6E).
    CHECK(find_in(*s, pat(SearchKind::Utf16, "\xE4\xB8\xAD", true), 0, true) == std::nullopt);
    CHECK(find_in(*s, pat(SearchKind::Hex, "2D 6E"), 0, true) == 5u);
}

TEST_CASE("find_in: matches across 4 MiB block boundaries agree with a naive scan") {
    const uint64_t size = 2 * kBlk + 777;
    Bytes d(size_t(size), 0x00);
    const Bytes sig = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    const uint64_t spots[] = {0,         100,         kBlk - 5,    kBlk - 3, kBlk + 1, 2 * kBlk - 2,
                              2 * kBlk + 10, size - 6, size - 3};
    for (uint64_t at : spots) plant(d, at, sig);
    plant(d, kBlk + 300, Bytes{'H', 'e', 'L', 'l', 'O'});
    plant(d, size - 20, Bytes{'h', 'E', 'l', 'L', 'o'});
    plant(d, 2 * kBlk + 100, Bytes{'h', 'e', 'l', 'l', 'o'});
    auto s = snap_of(d);

    std::vector<Pattern> pats = {
        pat(SearchKind::Hex, "DE"),                 // 1 byte: memchr
        pat(SearchKind::Hex, "DE AD BE EF"),        // short exact
        pat(SearchKind::Hex, "DE AD BE EF CA FE"),  // BMH path
        pat(SearchKind::Hex, "AD BE EF CA FE 00"),  // BMH, needs trailing byte
        pat(SearchKind::Hex, "DE ?? BE"),           // wildcard with anchor
        pat(SearchKind::Hex, "?? AD"),              // anchor not first
        pat(SearchKind::Hex, "D? A?"),              // no full-byte anchor
        pat(SearchKind::Hex, "FE 00 00"),
        pat(SearchKind::Text, "hello", true),       // icase: all letters, no anchor
        pat(SearchKind::Text, "hello"),
        pat(SearchKind::Hex, "DE AD BE"),           // last one ends exactly at EOF
    };
    std::vector<uint64_t> froms = {0, 1, 2, 99, 100, 101, size - 1, size, size + 5};
    for (uint64_t base : {kBlk, 2 * kBlk, size - 6})
        for (int k = -8; k <= 8; ++k) froms.push_back(base + uint64_t(int64_t(k)));
    for (uint64_t at : spots)
        for (int k = -2; k <= 2; ++k) froms.push_back(at + uint64_t(int64_t(k)));
    // Backward search reads blocks ending at `from`; put block starts right at/around the matches.
    for (uint64_t at : spots)
        for (int k = -4; k <= 4; ++k) froms.push_back(at + kBlk + uint64_t(int64_t(k)));

    for (size_t pi = 0; pi < pats.size(); ++pi) {
        const std::vector<uint64_t> all = ref_all(d, pats[pi]);
        CHECK(!all.empty());
        for (uint64_t from : froms) {
            if (from > size + 100) continue;
            for (bool fwd : {true, false}) {
                INFO("pattern #" << pi << " from " << from << (fwd ? " forward" : " backward"));
                CHECK(find_in(*s, pats[pi], from, fwd) == ref_find(all, from, fwd));
            }
        }
    }
}

TEST_CASE("find_in: cancel and progress") {
    Bytes d(size_t(3 * kBlk), 0x11);
    auto s = snap_of(d);
    Pattern p = pat(SearchKind::Hex, "22 33");
    std::atomic<bool> cancel{true};
    std::atomic<uint64_t> progress{0};
    CHECK(find_in(*s, p, 0, true, &cancel, &progress) == std::nullopt);
    CHECK(progress.load() == 0);  // cancelled before the first block
    cancel = false;
    CHECK(find_in(*s, p, 0, true, &cancel, &progress) == std::nullopt);
    CHECK(progress.load() >= 3 * kBlk - 1);
    CHECK(progress.load() <= 3 * kBlk);
    progress = 0;
    CHECK(find_in(*s, p, s->size(), false, &cancel, &progress) == std::nullopt);
    CHECK(progress.load() >= 3 * kBlk - 1);
}

// ================================================================================================
// SearchJob
// ================================================================================================

TEST_CASE("SearchJob: next / prev wrap, all, no match") {
    Bytes d(5000, 0x00);
    plant(d, 10, {0xAB, 0xCD});
    plant(d, 2000, {0xAB, 0xCD});
    plant(d, 4998, {0xAB, 0xCD});
    auto s = snap_of(d);
    Pattern p = pat(SearchKind::Hex, "AB CD");
    SearchJob job;
    CHECK(job.generation() == 0);
    CHECK_FALSE(job.running());

    auto r = run_job(job, s, p, 0, SearchJob::Mode::Next);
    CHECK(job.generation() == 1);
    CHECK(r.mode == SearchJob::Mode::Next);
    CHECK(r.hits == std::vector<uint64_t>{10});
    CHECK_FALSE(r.wrapped);
    CHECK_FALSE(r.cancelled);
    CHECK(r.pattern_len == 2);
    CHECK(job.progress() == doctest::Approx(1.0));

    r = run_job(job, s, p, 11, SearchJob::Mode::Next);
    CHECK(r.hits == std::vector<uint64_t>{2000});
    r = run_job(job, s, p, 4999, SearchJob::Mode::Next);  // wraps to the start
    CHECK(r.hits == std::vector<uint64_t>{10});
    CHECK(r.wrapped);
    r = run_job(job, s, p, 4998, SearchJob::Mode::Next);
    CHECK(r.hits == std::vector<uint64_t>{4998});
    CHECK_FALSE(r.wrapped);

    r = run_job(job, s, p, 2000, SearchJob::Mode::Prev);
    CHECK(r.hits == std::vector<uint64_t>{10});
    CHECK_FALSE(r.wrapped);
    r = run_job(job, s, p, 10, SearchJob::Mode::Prev);  // wraps to the end
    CHECK(r.hits == std::vector<uint64_t>{4998});
    CHECK(r.wrapped);
    r = run_job(job, s, p, 0, SearchJob::Mode::Prev);
    CHECK(r.hits == std::vector<uint64_t>{4998});
    CHECK(r.wrapped);

    r = run_job(job, s, p, 0, SearchJob::Mode::All);
    CHECK(r.mode == SearchJob::Mode::All);
    CHECK(r.hits == std::vector<uint64_t>{10, 2000, 4998});
    CHECK_FALSE(r.truncated);
    r = run_job(job, s, p, 0, SearchJob::Mode::All, 2);
    CHECK(r.hits == std::vector<uint64_t>{10, 2000});
    CHECK(r.truncated);
    r = run_job(job, s, p, 11, SearchJob::Mode::All);
    CHECK(r.hits == std::vector<uint64_t>{2000, 4998});

    Pattern none = pat(SearchKind::Hex, "12 34 56");
    for (auto mode : {SearchJob::Mode::Next, SearchJob::Mode::Prev, SearchJob::Mode::All}) {
        r = run_job(job, s, none, 100, mode);
        CHECK(r.hits.empty());
        CHECK_FALSE(r.wrapped);
        CHECK_FALSE(r.cancelled);
    }
    CHECK(job.generation() == 13);
}

TEST_CASE("SearchJob: all is non-overlapping and spans blocks") {
    Bytes d(size_t(kBlk + 10), 'A');
    auto s = snap_of(d);
    SearchJob job;
    auto r = run_job(job, s, pat(SearchKind::Text, "AA"), 0, SearchJob::Mode::All, 10000000);
    REQUIRE(r.hits.size() == size_t((kBlk + 10) / 2));
    for (size_t i = 0; i < r.hits.size(); ++i) REQUIRE(r.hits[i] == 2 * i);
    r = run_job(job, s, pat(SearchKind::Text, "AAA"), 0, SearchJob::Mode::All, 10000000);
    CHECK(r.hits.size() == size_t((kBlk + 10) / 3));
    CHECK(r.hits.back() == (r.hits.size() - 1) * 3);

    Bytes x(size_t(2 * kBlk + 50), 0);
    std::vector<uint64_t> want;
    for (uint64_t at = 7; at + 3 <= x.size(); at += 999983) {  // straddles both boundaries eventually
        plant(x, at, {1, 2, 3});
        want.push_back(at);
    }
    plant(x, kBlk - 1, {1, 2, 3});
    plant(x, 2 * kBlk - 2, {1, 2, 3});
    want.push_back(kBlk - 1);
    want.push_back(2 * kBlk - 2);
    std::sort(want.begin(), want.end());
    r = run_job(job, snap_of(x), pat(SearchKind::Hex, "01 02 03"), 0, SearchJob::Mode::All);
    CHECK(r.hits == want);
}

TEST_CASE("SearchJob: cancel, restart while running, destroy while running") {
    Bytes d(size_t(32) << 20, 0x5A);
    auto s = snap_of(d);
    Pattern p = pat(SearchKind::Text, "ZZZZY");  // never matches, BMH must scan everything
    {
        SearchJob job;
        uint64_t gen = job.generation();
        job.start(s, p, 0, SearchJob::Mode::All);
        job.cancel();
        wait_for(job, gen);
        auto r = job.result();
        CHECK(r.hits.empty());
        CHECK_FALSE(job.running());
        double pr = job.progress();
        CHECK(pr >= 0.0);
        CHECK(pr <= 1.0);
    }
    {
        SearchJob job;
        job.start(s, p, 0, SearchJob::Mode::All);
        // Restart immediately: previous run is cancelled (not waited for, and it publishes nothing),
        // the new one completes.
        Pattern q = pat(SearchKind::Text, "ZZ");
        job.start(s, q, 0, SearchJob::Mode::Next);
        wait_for(job, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        CHECK(job.generation() == 1);  // only the current run counts
        auto r = job.result();
        CHECK(r.mode == SearchJob::Mode::Next);
        CHECK_FALSE(r.cancelled);
        CHECK(r.hits == std::vector<uint64_t>{0});
    }
    {
        SearchJob job;
        job.start(s, p, 0, SearchJob::Mode::Prev);
    }  // destructor cancels + joins
    CHECK(true);
}

TEST_CASE("search: unreadable bytes stop the scan instead of matching as zeros") {
    // Snapshot whose middle piece references a missing add chunk: those bytes read as 0x00 but are
    // reported as unreadable (same path as a FileSource I/O error).
    auto base = snap_of(Bytes(size_t(kBlk), 0x11));
    auto s = std::make_shared<Snapshot>(*base);
    const uint64_t good = 1000, bad = 5000;
    s->pieces = {Piece{Piece::Add, 0, 0, good}, Piece{Piece::Add, 99, 0, bad}, Piece{Piece::Add, 0, 0, 3000}};
    s->starts = {0, good, good + bad};
    s->size_ = good + bad + 3000;
    std::vector<uint8_t> buf(size_t(s->size()));
    CHECK(s->read(0, buf.data(), buf.size()) == buf.size());  // zero-filled as before
    CHECK(buf[size_t(good)] == 0);
    CHECK(s->read_valid(0, buf.data(), buf.size()) == good);
    CHECK(s->read_valid(10, buf.data(), 100) == 100);

    Pattern zeros = pat(SearchKind::Hex, "00 00");
    bool io = false;
    CHECK(find_in(*s, zeros, 0, true, nullptr, nullptr, &io) == std::nullopt);
    CHECK(io);
    CHECK(find_in(*s, pat(SearchKind::Hex, "11 11"), 500, true, nullptr, nullptr, &io) == 500u);
    CHECK_FALSE(io);

    SearchJob job;
    auto r = run_job(job, s, zeros, 0, SearchJob::Mode::All);
    CHECK(r.hits.empty());
    CHECK(r.io_error);
    CHECK(r.io_error_offset == good);  // first unreadable byte
    r = run_job(job, s, pat(SearchKind::Hex, "11 11"), 0, SearchJob::Mode::All);
    CHECK(r.hits.size() == good / 2);  // matches before the unreadable bytes are still found
    CHECK(r.io_error);
    CHECK(r.io_error_offset == good);
    r = run_job(job, s, zeros, good + bad, SearchJob::Mode::Prev);  // backward into the bad range
    CHECK(r.io_error);
    CHECK(r.io_error_offset >= good);
    CHECK(r.io_error_offset < good + bad);
    r = run_job(job, s, pat(SearchKind::Hex, "11"), 0, SearchJob::Mode::Next);
    CHECK(r.hits == std::vector<uint64_t>{0});
    CHECK_FALSE(r.io_error);
}

TEST_CASE("SearchJob: rapid restarts publish only the last run") {
    Bytes d(size_t(32) << 20, 0x5A);
    plant(d, 12345, {'Q'});
    auto s = snap_of(d);
    Pattern never = pat(SearchKind::Text, "ZZZZY");
    SearchJob job;
    for (int i = 0; i < 20; ++i) job.start(s, never, 0, SearchJob::Mode::All);  // never waits for a run
    job.start(s, pat(SearchKind::Text, "Q"), 0, SearchJob::Mode::Next);
    wait_for(job, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(job.generation() == 1);
    auto r = job.result();
    CHECK(r.mode == SearchJob::Mode::Next);
    CHECK_FALSE(r.cancelled);
    CHECK(r.hits == std::vector<uint64_t>{12345});
    CHECK(job.progress() == doctest::Approx(1.0));
}

TEST_CASE("SearchJob: next / prev wrap across 4 MiB blocks") {
    const uint64_t size = 3 * kBlk + 123;
    Bytes d(size_t(size), 0x00);
    const uint64_t a = kBlk - 2;  // straddles the first block boundary
    plant(d, a, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66});
    auto s = snap_of(d);
    SearchJob job;
    for (const char* text : {"11 22 33 44 55 66", "11 ?? 33", "11"}) {  // BMH, wildcard, memchr paths
        INFO("pattern " << text);
        Pattern p = pat(SearchKind::Hex, text);
        auto r = run_job(job, s, p, a, SearchJob::Mode::Next);  // match exactly at `from`
        CHECK(r.hits == std::vector<uint64_t>{a});
        CHECK_FALSE(r.wrapped);
        r = run_job(job, s, p, a + 1, SearchJob::Mode::Next);  // overlaps `from`: only found by wrapping
        CHECK(r.hits == std::vector<uint64_t>{a});
        CHECK(r.wrapped);
        r = run_job(job, s, p, 2 * kBlk + 5, SearchJob::Mode::Next);
        CHECK(r.hits == std::vector<uint64_t>{a});
        CHECK(r.wrapped);
        r = run_job(job, s, p, UINT64_MAX, SearchJob::Mode::Next);  // from past EOF
        CHECK(r.hits == std::vector<uint64_t>{a});
        CHECK(r.wrapped);
        r = run_job(job, s, p, 0, SearchJob::Mode::Next);
        CHECK(r.hits == std::vector<uint64_t>{a});
        CHECK_FALSE(r.wrapped);

        r = run_job(job, s, p, a + 1, SearchJob::Mode::Prev);
        CHECK(r.hits == std::vector<uint64_t>{a});
        CHECK_FALSE(r.wrapped);
        r = run_job(job, s, p, size, SearchJob::Mode::Prev);
        CHECK(r.hits == std::vector<uint64_t>{a});
        CHECK_FALSE(r.wrapped);
        r = run_job(job, s, p, a, SearchJob::Mode::Prev);  // must start < from: wraps to itself
        CHECK(r.hits == std::vector<uint64_t>{a});
        CHECK(r.wrapped);
        r = run_job(job, s, p, 0, SearchJob::Mode::Prev);
        CHECK(r.hits == std::vector<uint64_t>{a});
        CHECK(r.wrapped);
        CHECK(job.progress() == doctest::Approx(1.0));
        CHECK_FALSE(r.cancelled);
    }

    // Match ending exactly at EOF, reached by Prev from 0 (wrap) and Next from past it (wrap).
    Bytes e(size_t(2 * kBlk + 3), 0x00);
    plant(e, e.size() - 3, {0xAA, 0xBB, 0xCC});
    plant(e, 5, {0xAA, 0xBB, 0xCC});
    auto se = snap_of(e);
    Pattern p = pat(SearchKind::Hex, "AA BB CC");
    auto r = run_job(job, se, p, 0, SearchJob::Mode::Prev);
    CHECK(r.hits == std::vector<uint64_t>{e.size() - 3});
    CHECK(r.wrapped);
    r = run_job(job, se, p, e.size() - 2, SearchJob::Mode::Next);
    CHECK(r.hits == std::vector<uint64_t>{5});
    CHECK(r.wrapped);
    r = run_job(job, se, p, 6, SearchJob::Mode::Next);
    CHECK(r.hits == std::vector<uint64_t>{e.size() - 3});
    CHECK_FALSE(r.wrapped);

    // A null snapshot finishes immediately with no hits.
    uint64_t gen = job.generation();
    r = run_job(job, nullptr, p, 0, SearchJob::Mode::Next);
    CHECK(job.generation() == gen + 1);
    CHECK(r.hits.empty());
    CHECK_FALSE(r.cancelled);
}

TEST_CASE("SearchJob: cancel semantics") {
    Bytes d(size_t(32) << 20, 0x5A);
    auto s = snap_of(d);
    Pattern never = pat(SearchKind::Text, "ZZZZY");
    SearchJob job;

    // A cancel() while idle must not leak into the next run.
    job.cancel();
    auto r = run_job(job, s, pat(SearchKind::Text, "ZZ"), 7, SearchJob::Mode::Next);
    CHECK_FALSE(r.cancelled);
    CHECK(r.hits == std::vector<uint64_t>{7});

    // Cancelling a running Next/Prev never reports a hit or a wrap; a run either finishes or is
    // cancelled, and generation advances exactly once per run.
    for (auto mode : {SearchJob::Mode::Next, SearchJob::Mode::Prev, SearchJob::Mode::All}) {
        for (int i = 0; i < 3; ++i) {
            uint64_t gen = job.generation();
            job.start(s, never, uint64_t(i) * 1000, mode);
            job.cancel();
            wait_for(job, gen);
            CHECK(job.generation() == gen + 1);
            CHECK_FALSE(job.running());
            r = job.result();
            CHECK(r.mode == mode);
            CHECK(r.hits.empty());
            CHECK_FALSE(r.wrapped);
            CHECK(job.progress() == doctest::Approx(1.0));  // finished runs report 1.0
        }
    }

    // A run that completes after an earlier cancelled one is not marked cancelled.
    Bytes hit = d;
    plant(hit, d.size() - 5, {'Z', 'Z', 'Z', 'Z', 'Y'});
    r = run_job(job, snap_of(hit), never, 0, SearchJob::Mode::Next);
    CHECK_FALSE(r.cancelled);
    CHECK(r.hits == std::vector<uint64_t>{d.size() - 5});
}

// Search over a file-backed document with many edits: the snapshot is a mix of original-file
// pieces (64 KiB FileSource cache blocks) and add-buffer pieces, so matches straddle piece, cache
// block and 4 MiB search block boundaries. Checked against a naive scan for every mode.
TEST_CASE("search over an edited file-backed document agrees with a naive scan") {
    TempDir tmp;
    std::mt19937 rng(12345);
    const size_t base_size = size_t(2 * kBlk + 4321);
    Bytes ref(base_size);
    for (auto& b : ref) b = uint8_t(rng() % 3);  // tiny alphabet: plenty of matches everywhere
    std::string f = path_join(tmp.path, "data.bin");
    REQUIRE(os_write_whole_atomic(f, ref.data(), ref.size()));
    std::string err;
    auto doc = Document::open_file(f, &err);
    INFO(err);
    REQUIRE(doc);
    REQUIRE(doc->size() == ref.size());

    // Edits concentrated around the 64 KiB and 4 MiB boundaries, plus random ones.
    std::vector<uint64_t> spots;
    for (uint64_t k = 1; k <= 8; ++k) spots.push_back(k * 65536);
    spots.push_back(kBlk);
    spots.push_back(2 * kBlk);
    for (int i = 0; i < 300; ++i) {
        uint64_t at = (i % 3 == 0) ? uint64_t(int64_t(spots[size_t(rng() % spots.size())]) + int64_t(rng() % 9) - 4)
                                    : rng() % ref.size();
        at = std::min<uint64_t>(at, ref.size());
        Bytes data(1 + rng() % 7);
        for (auto& b : data) b = uint8_t(rng() % 3);
        switch (rng() % 3) {
        case 0:
            REQUIRE(doc->insert(at, data.data(), data.size()));
            ref.insert(ref.begin() + ptrdiff_t(at), data.begin(), data.end());
            break;
        case 1: {
            uint64_t n = std::min<uint64_t>(1 + rng() % 5, ref.size() - at);
            if (n == 0) break;
            REQUIRE(doc->erase(at, n));
            ref.erase(ref.begin() + ptrdiff_t(at), ref.begin() + ptrdiff_t(at + n));
            break;
        }
        default:
            REQUIRE(doc->overwrite(at, data.data(), data.size()));
            if (at + data.size() > ref.size()) ref.resize(size_t(at + data.size()));
            std::copy(data.begin(), data.end(), ref.begin() + ptrdiff_t(at));
            break;
        }
    }
    REQUIRE(doc->size() == ref.size());
    auto s = doc->snapshot();
    const uint64_t size = s->size();
    CHECK(s->pieces.size() > 100);  // really a patchwork of file and add-buffer pieces

    std::vector<Pattern> pats = {
        pat(SearchKind::Hex, "02 02 02 02 02 02 02 02 02 02 02 02"),  // BMH, rare
        pat(SearchKind::Hex, "00 01 02 00 01 02"),                    // BMH, ~1 per 729 bytes
        pat(SearchKind::Hex, "02 ?? 02 ?? 02 ?? 02"),                 // wildcard with anchor
        pat(SearchKind::Hex, "?? 01 ?? 01 ?? 01"),                    // anchor not first
        pat(SearchKind::Hex, "0? 0? 0? 0? 0? 0? 0? 0? 0? 0? 0? 0?"), // no anchor: matches everywhere
        pat(SearchKind::Hex, "01 01 01"),                             // short exact, overlapping hits
    };
    std::vector<uint64_t> froms = {0, 1, size / 2, size - 1, size, size + 1};
    for (uint64_t b : {uint64_t(65536), 3 * uint64_t(65536), kBlk, 2 * kBlk})
        for (int k = -3; k <= 3; ++k) froms.push_back(b + uint64_t(int64_t(k)));
    for (int i = 0; i < 20; ++i) froms.push_back(rng() % (size + 1));

    SearchJob job;
    for (size_t pi = 0; pi < pats.size(); ++pi) {
        const Pattern& p = pats[pi];
        const std::vector<uint64_t> all = ref_all(ref, p);
        INFO("pattern #" << pi << " (" << all.size() << " matches)");
        REQUIRE(!all.empty());
        for (uint64_t from : froms) {
            INFO("from " << from);
            CHECK(find_in(*s, p, from, true) == ref_find(all, from, true));
            CHECK(find_in(*s, p, from, false) == ref_find(all, from, false));
        }
        // Next / Prev with wrap on a few starting points.
        for (uint64_t from : {uint64_t(0), kBlk + 1, size}) {
            INFO("job from " << from);
            auto r = run_job(job, s, p, from, SearchJob::Mode::Next);
            auto fwd = ref_find(all, from, true);
            REQUIRE(r.hits.size() == 1);
            CHECK(r.hits[0] == (fwd ? *fwd : all.front()));
            CHECK(r.wrapped == !fwd.has_value());
            r = run_job(job, s, p, from, SearchJob::Mode::Prev);
            auto bwd = ref_find(all, from, false);
            REQUIRE(r.hits.size() == 1);
            CHECK(r.hits[0] == (bwd ? *bwd : all.back()));
            CHECK(r.wrapped == !bwd.has_value());
        }
        // All: greedy non-overlapping matches from `from`.
        for (uint64_t from : {uint64_t(0), kBlk - 1}) {
            std::vector<uint64_t> want;
            for (uint64_t at : all)
                if (at >= from && (want.empty() || at >= want.back() + p.size())) want.push_back(at);
            auto r = run_job(job, s, p, from, SearchJob::Mode::All, 10000000);
            CHECK_FALSE(r.truncated);
            CHECK(r.hits.size() == want.size());
            CHECK(r.hits == want);
        }
    }
}

// ================================================================================================
// Settings + paths
// ================================================================================================

TEST_CASE("paths with override + settings round trip") {
    TempDir tmp;
    paths::set_config_dir_override(tmp.path);
    CHECK(paths::config_dir() == tmp.path);
    CHECK(paths::settings_file() == path_join(tmp.path, "settings.ini"));
    CHECK(paths::imgui_ini_file() == path_join(tmp.path, "layout.ini"));
    CHECK(paths::session_dir() == path_join(tmp.path, "session"));
    CHECK(paths::user_scripts_dir() == path_join(tmp.path, "scripts"));
    CHECK_FALSE(paths::bundled_scripts_dir().empty());
    paths::ensure_dirs();
    CHECK(os_stat(paths::session_dir()).is_dir);
    CHECK(os_stat(paths::user_scripts_dir()).is_dir);

    Settings def;
    Settings missing;
    CHECK_FALSE(missing.load(path_join(tmp.path, "nope.ini")));
    CHECK(missing.bytes_per_row == def.bytes_per_row);

    Settings s;
    s.bytes_per_row = 32;
    s.group_size = 4;
    s.uppercase_hex = false;
    s.show_ascii = false;
    s.insert_mode = true;
    s.big_endian_inspector = true;
    s.font_size = 18.5f;
    s.ui_scale = 1.25f;
    s.restore_session = false;
    s.session_autosave_seconds = 10;
    s.goto_default_hex = false;
    s.highlight_modified = false;
    CHECK(s.undo_merge_ms == 500);
    CHECK(s.undo_merge_max_bytes == 32);
    CHECK(s.backup_on_save == true);
    CHECK(s.backup_max_bytes == (4ull << 30));
    s.undo_merge_ms = 750;
    s.undo_merge_max_bytes = 0;
    s.backup_on_save = false;
    s.backup_max_bytes = 123ull << 32;  // needs more than 32 bits
    for (int i = 0; i < 25; ++i) s.push_recent("C:/files/f" + std::to_string(i) + ".bin");
    REQUIRE(s.recent_files.size() == 20);
    CHECK(s.recent_files.front() == "C:/files/f24.bin");
    CHECK(s.recent_files.back() == "C:/files/f5.bin");
    s.push_recent("C:/files/f10.bin");  // dedupe: moves to front
    CHECK(s.recent_files.size() == 20);
    CHECK(s.recent_files.front() == "C:/files/f10.bin");
    CHECK(std::count(s.recent_files.begin(), s.recent_files.end(), "C:/files/f10.bin") == 1);
    s.push_recent("");
    CHECK(s.recent_files.front() == "C:/files/f10.bin");
    s.recent_files.push_back("D:/with spaces/= equals.bin");
    s.recent_files.erase(s.recent_files.begin() + 5);

    REQUIRE(s.save(paths::settings_file()));
    Settings t;
    REQUIRE(t.load(paths::settings_file()));
    CHECK(t.bytes_per_row == 32);
    CHECK(t.group_size == 4);
    CHECK(t.uppercase_hex == false);
    CHECK(t.show_ascii == false);
    CHECK(t.insert_mode == true);
    CHECK(t.big_endian_inspector == true);
    CHECK(t.font_size == 18.5f);
    CHECK(t.ui_scale == 1.25f);
    CHECK(t.restore_session == false);
    CHECK(t.session_autosave_seconds == 10);
    CHECK(t.goto_default_hex == false);
    CHECK(t.highlight_modified == false);
    CHECK(t.undo_merge_ms == 750);
    CHECK(t.undo_merge_max_bytes == 0);
    CHECK(t.backup_on_save == false);
    CHECK(t.backup_max_bytes == (123ull << 32));
    CHECK(t.recent_files == s.recent_files);
    CHECK(t.recent_files.back() == "D:/with spaces/= equals.bin");
}

TEST_CASE("settings: hand-edited file, unknown keys preserved, bad values ignored") {
    TempDir tmp;
    std::string f = path_join(tmp.path, "settings.ini");
    std::string text =
        "# comment\n"
        "; another\n"
        "\n"
        "  bytes_per_row   =  24  \r\n"
        "group_size = banana\n"
        "uppercase_hex = no\n"
        "font_size = 1000\n"          // clamped
        "undo_merge_ms = -5\n"        // clamped to 0 (no time limit)
        "backup_max_bytes = lots\n"   // malformed: default kept
        "backup_on_save = off\n"
        "future_option = 42\n"
        "no equals sign here\n"
        "recent3 = /tmp/c.bin\n"
        "recent0 = /tmp/a.bin\n"
        "recent99 = /tmp/zzz.bin\n";  // out of range index -> kept as unknown
    REQUIRE(os_write_whole_atomic(f, text.data(), text.size()));
    Settings s;
    REQUIRE(s.load(f));
    Settings def;
    CHECK(s.bytes_per_row == 24);
    CHECK(s.group_size == def.group_size);
    CHECK(s.uppercase_hex == false);
    CHECK(s.font_size <= 96.0f);
    CHECK(s.undo_merge_ms == 0);
    CHECK(s.backup_max_bytes == def.backup_max_bytes);
    CHECK(s.backup_on_save == false);
    CHECK(s.recent_files == std::vector<std::string>{"/tmp/a.bin", "/tmp/c.bin"});
    REQUIRE(s.save(f));
    std::string back;
    REQUIRE(os_read_whole(f, back));
    CHECK(back.find("future_option = 42") != std::string::npos);
    CHECK(back.find("recent99 = /tmp/zzz.bin") != std::string::npos);
    Settings t;
    REQUIRE(t.load(f));
    CHECK(t.recent_files == s.recent_files);
    CHECK(t.unknown_keys.size() == 2);
}

TEST_CASE("settings: font fields round trip, hinting is validated") {
    TempDir tmp;
    std::string f = path_join(tmp.path, "settings.ini");
    Settings def;
    CHECK(def.mono_font.empty());
    CHECK(def.ui_font.empty());
    CHECK(def.font_hinting == "normal");

    Settings s;
    s.mono_font = "C:/Fonts/My Mono = 1.ttf";  // spaces and '=' survive (split at the first '=')
    s.ui_font = "/usr/share/fonts/ui.ttf";
    s.font_hinting = "light";
    REQUIRE(s.save(f));
    Settings t;
    REQUIRE(t.load(f));
    CHECK(t.mono_font == s.mono_font);
    CHECK(t.ui_font == s.ui_font);
    CHECK(t.font_hinting == "light");

    for (const char* ok : {"none", "light", "normal", "mono"}) {
        std::string text = std::string("font_hinting = ") + ok + "\n";
        REQUIRE(os_write_whole_atomic(f, text.data(), text.size()));
        Settings u;
        REQUIRE(u.load(f));
        CHECK(u.font_hinting == ok);
    }
    std::string text = "font_hinting = SUPER\nmono_font =\n";  // unknown mode: default; empty = auto
    REQUIRE(os_write_whole_atomic(f, text.data(), text.size()));
    Settings u;
    u.mono_font = "x.ttf";
    REQUIRE(u.load(f));
    CHECK(u.font_hinting == "normal");
    CHECK(u.mono_font.empty());
    text = "font_hinting = Light\n";  // case-insensitive, stored lower-case
    REQUIRE(os_write_whole_atomic(f, text.data(), text.size()));
    REQUIRE(u.load(f));
    CHECK(u.font_hinting == "light");
}

TEST_CASE("settings: a DPI-derived ui_scale from an older version is reset to 1.0 once") {
    TempDir tmp;
    std::string f = path_join(tmp.path, "settings.ini");
    auto write = [&](const std::string& text) { REQUIRE(os_write_whole_atomic(f, text.data(), text.size())); };

    write("ui_scale = 1.5\nfont_size = 16\n");  // old file: first run stored the monitor scale
    Settings s;
    REQUIRE(s.load(f));
    CHECK(s.legacy_ui_scale);
    CHECK(s.migrate_ui_scale(1.5f));
    CHECK(s.ui_scale == 1.0f);
    CHECK_FALSE(s.legacy_ui_scale);
    CHECK_FALSE(s.migrate_ui_scale(1.5f));  // once
    REQUIRE(s.save(f));

    // Saved by this version: the value is a user factor and is kept, even if it equals the DPI.
    Settings t;
    REQUIRE(t.load(f));
    CHECK_FALSE(t.legacy_ui_scale);
    t.ui_scale = 1.5f;
    REQUIRE(t.save(f));
    REQUIRE(t.load(f));
    CHECK_FALSE(t.migrate_ui_scale(1.5f));
    CHECK(t.ui_scale == 1.5f);
    CHECK(t.unknown_keys.empty());  // the marker key is not an unknown key

    // Old files whose value does not look like the old default keep it.
    for (auto [text, monitor] : {std::pair<const char*, float>{"ui_scale = 1.25\n", 1.5f},
                                 {"ui_scale = 1\n", 1.0f}, {"ui_scale = 2\n", 1.0f}}) {
        write(text);
        Settings u;
        REQUIRE(u.load(f));
        const float before = u.ui_scale;
        CHECK_FALSE(u.migrate_ui_scale(monitor));
        CHECK(u.ui_scale == before);
    }
    write("font_size = 16\n");  // no ui_scale at all: nothing to migrate
    Settings v;
    REQUIRE(v.load(f));
    CHECK_FALSE(v.legacy_ui_scale);
}

#ifdef _WIN32
TEST_CASE("settings: recent dedupe ignores case and slash direction on Windows") {
    Settings s;
    s.push_recent("C:\\Data\\File.bin");
    s.push_recent("c:/data/file.BIN");
    CHECK(s.recent_files.size() == 1);
    CHECK(s.recent_files.front() == "c:/data/file.BIN");
}
#endif

TEST_CASE("settings: follow pointer and hash algorithm fields round trip, bad widths ignored") {
    TempDir tmp;
    std::string f = path_join(tmp.path, "settings.ini");
    Settings def;
    CHECK(def.pointer_width == 4);
    CHECK(def.pointer_base == 0);
    CHECK(def.hash_algorithms.empty());
    Settings s;
    s.pointer_width = 8;
    s.pointer_base = 0x140000000ull;
    s.hash_algorithms = "CRC-32,SHA-256";
    REQUIRE(s.save(f));
    Settings t;
    REQUIRE(t.load(f));
    CHECK(t.pointer_width == 8);
    CHECK(t.pointer_base == 0x140000000ull);
    CHECK(t.hash_algorithms == "CRC-32,SHA-256");
    for (const char* bad : {"5", "16", "0", "-4", "x"}) {
        std::string text = std::string("pointer_width = ") + bad + "\n";
        REQUIRE(os_write_whole_atomic(f, text.data(), text.size()));
        Settings u;
        REQUIRE(u.load(f));
        CHECK(u.pointer_width == 4);
    }
}

TEST_CASE("settings: minimap, byte-class colors and bitmap panel fields round trip, bad values ignored") {
    TempDir tmp;
    std::string f = path_join(tmp.path, "settings.ini");
    Settings def;
    CHECK(def.minimap == 1);  // entropy
    CHECK_FALSE(def.byte_class_colors);
    for (int mode : {0, 1, 2}) {
        Settings s;
        s.minimap = mode;
        s.byte_class_colors = mode != 1;
        REQUIRE(s.save(f));
        Settings t;
        REQUIRE(t.load(f));
        CHECK(t.minimap == mode);
        CHECK(t.byte_class_colors == (mode != 1));
        CHECK(t.unknown_keys.empty());
    }
    const std::string text = "minimap = Classes\nbyte_class_colors = yes\n";
    REQUIRE(os_write_whole_atomic(f, text.data(), text.size()));
    Settings u;
    REQUIRE(u.load(f));
    CHECK(u.minimap == 2);  // case-insensitive
    CHECK(u.bitmap_width == 256);
    CHECK(u.bitmap_zoom == 2);
    CHECK(u.bitmap_format.empty());
    {
        Settings b;
        b.bitmap_format = "RGB 24-bit";
        b.bitmap_width = 640;
        b.bitmap_zoom = 3;
        REQUIRE(b.save(f));
        Settings c;
        REQUIRE(c.load(f));
        CHECK(c.bitmap_format == "RGB 24-bit");
        CHECK(c.bitmap_width == 640);
        CHECK(c.bitmap_zoom == 3);
        const std::string bad = "bitmap_width = 0\nbitmap_zoom = 17\n";
        REQUIRE(os_write_whole_atomic(f, bad.data(), bad.size()));
        Settings e;
        REQUIRE(e.load(f));
        CHECK(e.bitmap_width == 1);  // out-of-range numbers are clamped, like every int setting
        CHECK(e.bitmap_zoom == 16);
    }
    for (const char* bad : {"2", "heat", ""}) {
        const std::string t2 = std::string("minimap = ") + bad + "\n";
        REQUIRE(os_write_whole_atomic(f, t2.data(), t2.size()));
        Settings w;
        REQUIRE(w.load(f));
        CHECK(w.minimap == 1);
    }
}

TEST_CASE("search: holes of process memory are skipped in both directions, never matched across") {
    hx_test::HoleyMem hm;  // readable page | hole page | readable page
    const uint64_t a = hm.addr(), pg = hm.pg;
    const Bytes needle = {0xC3, 0x5A, 0x17, 0xE8, 0x9B, 0x42, 0x6D, 0xF1, 0x08, 0xA4, 0x3E, 0x77};
    std::memcpy(hm.base + 20, needle.data(), needle.size());
    std::memcpy(hm.after_ptr() + 10, needle.data(), needle.size());
    auto doc = hx_test::open_self();
    auto snap = doc->snapshot();
    std::string hex;
    for (uint8_t b : needle) hex += "0123456789ABCDEF"[b >> 4], hex += "0123456789ABCDEF"[b & 15], hex += ' ';
    const Pattern p = pat(SearchKind::Hex, hex);

    bool io = true;
    uint64_t skipped = 0;
    CHECK(find_in(*snap, p, a, true, nullptr, nullptr, &io, &skipped) == a + 20);
    CHECK_FALSE(io);
    CHECK(find_in(*snap, p, a + 21, true, nullptr, nullptr, &io, &skipped) == a + 2 * pg + 10);  // across the hole
    CHECK_FALSE(io);
    CHECK(skipped == pg);
    CHECK(find_in(*snap, p, a + 2 * pg + 5, false, nullptr, nullptr, &io, &skipped) == a + 20);
    CHECK_FALSE(io);
    CHECK(skipped >= pg);
    CHECK(find_in(*snap, p, a + pg + 100, false, nullptr, nullptr, &io, &skipped) == a + 20);  // from inside the hole
    CHECK_FALSE(io);
    CHECK(skipped > 0);
    // From address 0 (the unmapped null page) on: found somewhere, not "unreadable at 0".
    auto first = find_in(*snap, p, 0, true, nullptr, nullptr, &io, &skipped);
    REQUIRE(first.has_value());
    CHECK(*first <= a + 20);
    CHECK_FALSE(io);
    CHECK(skipped > 0);

    // A match never spans a hole (the zeros standing in for it are no data).
    const Pattern any2 = pat(SearchKind::Hex, "?? ??");
    CHECK(find_in(*snap, any2, a + pg - 1, true) == a + 2 * pg);
    CHECK(find_in(*snap, any2, a + 2 * pg, false) == a + pg - 2);
    CHECK(find_in(*snap, any2, a + pg + 7, false) == a + pg - 2);

    SearchJob job;
    auto r = run_job(job, snap, p, a, SearchJob::Mode::All);
    CHECK_FALSE(r.io_error);
    CHECK(r.skipped >= pg);
    CHECK(std::find(r.hits.begin(), r.hits.end(), a + 20) != r.hits.end());
    CHECK(std::find(r.hits.begin(), r.hits.end(), a + 2 * pg + 10) != r.hits.end());
    r = run_job(job, snap, p, a + 21, SearchJob::Mode::Next);
    CHECK(r.hits == std::vector<uint64_t>{a + 2 * pg + 10});
    CHECK_FALSE(r.io_error);
    r = run_job(job, snap, p, a + 2 * pg + 5, SearchJob::Mode::Prev);
    CHECK(r.hits == std::vector<uint64_t>{a + 20});
    CHECK_FALSE(r.io_error);
    CHECK(r.skipped > 0);
}

TEST_CASE("search: Snapshot::readable_end finds the data before a hole") {
    hx_test::HoleyMem hm(2, 3, 1);
    const uint64_t a = hm.addr(), pg = hm.pg;
    auto doc = hx_test::open_self();
    auto snap = doc->snapshot();
    CHECK(snap->readable_end(a, hm.hole_begin() + 5) == hm.hole_begin());
    CHECK(snap->readable_end(a, hm.hole_end()) == hm.hole_begin());
    CHECK(snap->readable_end(a, hm.hole_end() + 1) == hm.hole_end() + 1);
    CHECK(snap->readable_end(hm.hole_begin(), hm.hole_end()) == hm.hole_begin());  // none: lo
    CHECK(snap->readable_end(a + pg, a + pg) == a + pg);
    CHECK(snap->readable_end(0, 4096) == 0);  // the null page
    const uint64_t e0 = snap->readable_end(0, a + 1);
    CHECK(e0 == a + 1);
    // Without holes: simply hi (clamped to the size).
    auto plain = snap_of(Bytes(100, 1));
    CHECK(plain->readable_end(10, 50) == 50);
    CHECK(plain->readable_end(10, 500) == 100);
    CHECK(plain->readable_end(60, 50) == 60);
}
