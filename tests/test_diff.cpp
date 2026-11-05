// Tests for core/diff: DiffJob / diff_snapshots over Document snapshots, range lookups.
#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "core/diff.h"
#include "core/document.h"
#include "core/os_file.h"

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#endif

using namespace hx;
namespace fs = std::filesystem;

namespace {

using Bytes = std::vector<uint8_t>;
constexpr uint64_t kMiB = uint64_t(1) << 20;
constexpr uint64_t kBlk = 4 * kMiB;  // diff block size

std::shared_ptr<const Snapshot> snap_of(const Bytes& b) {
    auto doc = Document::create_from_bytes("test", b.data(), b.size());
    REQUIRE(doc);
    return doc->snapshot();  // keeps its data alive after the document is gone
}

DiffResult diff(const Bytes& a, const Bytes& b, int64_t shift = 0, size_t max_ranges = 1000000) {
    return diff_snapshots(*snap_of(a), *snap_of(b), shift, max_ranges);
}

Bytes random_bytes(size_t n, uint64_t seed) {
    std::mt19937_64 rng(seed);
    Bytes b(n);
    for (auto& x : b) x = uint8_t(rng());
    return b;
}

DiffRange R(uint64_t a, uint64_t b, uint64_t len, uint8_t kind = DiffRange::Changed) {
    return DiffRange{a, b, len, kind};
}

// Reference implementation: one byte at a time.
std::vector<DiffRange> naive(const Bytes& a, const Bytes& b, int64_t shift) {
    std::vector<DiffRange> out;
    auto add = [&](uint8_t kind, uint64_t ao, uint64_t bo, uint64_t len) {
        if (!len) return;
        if (!out.empty()) {
            DiffRange& c = out.back();
            if (c.kind == kind && c.a_off + diff_len_a(c) == ao && c.b_off + diff_len_b(c) == bo) {
                c.len += len;
                return;
            }
        }
        out.push_back(R(ao, bo, len, kind));
    };
    const int64_t A = int64_t(a.size()), B = int64_t(b.size());
    if (shift < 0) add(DiffRange::OnlyA, 0, 0, uint64_t(std::min<int64_t>(-shift, A)));
    if (shift > 0) add(DiffRange::OnlyB, 0, 0, uint64_t(std::min<int64_t>(shift, B)));
    int64_t i = std::max<int64_t>(0, -shift);
    for (; i < A && i + shift < B; ++i)
        if (a[size_t(i)] != b[size_t(i + shift)]) add(DiffRange::Changed, uint64_t(i), uint64_t(i + shift), 1);
    const uint64_t ae = uint64_t(std::min(i, A)), be = uint64_t(std::min(std::max<int64_t>(i + shift, 0), B));
    add(DiffRange::OnlyA, ae, be, uint64_t(A) - ae);
    add(DiffRange::OnlyB, ae, be, uint64_t(B) - be);
    return out;
}

uint64_t sum_len(const std::vector<DiffRange>& v) {
    uint64_t n = 0;
    for (auto& r : v) n += r.len;
    return n;
}

bool wait_for(const DiffJob& job, uint64_t gen, int timeout_ms = 30000) {
    auto t0 = std::chrono::steady_clock::now();
    while (job.generation() <= gen) {
        if (std::chrono::steady_clock::now() - t0 > std::chrono::milliseconds(timeout_ms)) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return true;
}

[[maybe_unused]] fs::path from_u8(const std::string& s) { return fs::path(std::u8string(s.begin(), s.end())); }
std::string u8(const fs::path& p) {
    auto s = p.u8string();
    return std::string(s.begin(), s.end());
}

struct TempDir {
    fs::path dir;
    TempDir() {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("hexer-diff-test-" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(dir);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    std::string file(const std::string& name) const { return u8(dir / name); }
};

void make_sparse(const std::string& p, uint64_t size) {
#ifdef _WIN32
    HANDLE h = CreateFileW(utf8_to_wide(p).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    REQUIRE(h != INVALID_HANDLE_VALUE);
    DWORD got = 0;
    DeviceIoControl(h, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &got, nullptr);
    CloseHandle(h);
#else
    { std::ofstream f(from_u8(p), std::ios::binary | std::ios::trunc); }  // ReadWrite needs an existing file
#endif
    auto f = OsFile::open(p, OsFile::Mode::ReadWrite);
    REQUIRE(f);
    REQUIRE(f->truncate(size));
}

}  // namespace

TEST_CASE("diff: identical and empty") {
    Bytes a = random_bytes(10000, 1);
    DiffResult r = diff(a, a);
    CHECK(r.identical());
    CHECK(r.ranges.empty());
    CHECK(r.diff_bytes == 0);
    CHECK(r.a_size == 10000);
    CHECK(r.b_size == 10000);
    CHECK(diff({}, {}).identical());
}

TEST_CASE("diff: single byte, adjacent merge, separate ranges") {
    Bytes a = random_bytes(1000, 2), b = a;
    b[500] ^= 1;
    DiffResult r = diff(a, b);
    REQUIRE(r.ranges.size() == 1);
    CHECK(r.ranges[0] == R(500, 500, 1));
    CHECK(r.diff_bytes == 1);
    CHECK(r.range_count == 1);
    CHECK_FALSE(r.identical());

    b[501] ^= 0xFF;
    b[502] ^= 0x80;
    b[510] ^= 4;
    r = diff(a, b);
    REQUIRE(r.ranges.size() == 2);
    CHECK(r.ranges[0] == R(500, 500, 3));
    CHECK(r.ranges[1] == R(510, 510, 1));
    CHECK(r.diff_bytes == 4);

    // First and last byte.
    Bytes c = a;
    c.front() ^= 1;
    c.back() ^= 1;
    r = diff(a, c);
    REQUIRE(r.ranges.size() == 2);
    CHECK(r.ranges[0] == R(0, 0, 1));
    CHECK(r.ranges[1] == R(999, 999, 1));
}

TEST_CASE("diff: long run of differing words and bytes") {
    Bytes a(100000, 0x11), b = a;
    for (size_t i = 3; i < 90001; ++i) b[i] = 0x22;
    b[50000] = 0x11;  // one equal byte splits the run
    DiffResult r = diff(a, b);
    REQUIRE(r.ranges.size() == 2);
    CHECK(r.ranges[0] == R(3, 3, 50000 - 3));
    CHECK(r.ranges[1] == R(50001, 50001, 90001 - 50001));
}

TEST_CASE("diff: length mismatch tails both ways") {
    Bytes a = random_bytes(100, 3);
    Bytes shorter(a.begin(), a.begin() + 60);
    DiffResult r = diff(a, shorter);
    REQUIRE(r.ranges.size() == 1);
    CHECK(r.ranges[0] == R(60, 60, 40, DiffRange::OnlyA));
    CHECK(r.diff_bytes == 40);

    r = diff(shorter, a);
    REQUIRE(r.ranges.size() == 1);
    CHECK(r.ranges[0] == R(60, 60, 40, DiffRange::OnlyB));

    // A changed last common byte does not merge with the tail (different kind).
    shorter[59] ^= 1;
    r = diff(a, shorter);
    REQUIRE(r.ranges.size() == 2);
    CHECK(r.ranges[0] == R(59, 59, 1));
    CHECK(r.ranges[1] == R(60, 60, 40, DiffRange::OnlyA));

    // One side empty.
    r = diff(a, {});
    REQUIRE(r.ranges.size() == 1);
    CHECK(r.ranges[0] == R(0, 0, 100, DiffRange::OnlyA));
    r = diff({}, a);
    REQUIRE(r.ranges.size() == 1);
    CHECK(r.ranges[0] == R(0, 0, 100, DiffRange::OnlyB));
}

TEST_CASE("diff: shift positive and negative") {
    Bytes body = random_bytes(5000, 4);
    Bytes with_header = {0xDE, 0xAD, 0xBE, 0xEF};
    with_header.insert(with_header.end(), body.begin(), body.end());

    // B = header + A: shift 4 aligns them; only the header is reported.
    DiffResult r = diff(body, with_header, 4);
    REQUIRE(r.ranges.size() == 1);
    CHECK(r.ranges[0] == R(0, 0, 4, DiffRange::OnlyB));
    CHECK(r.shift == 4);
    // Without the shift nearly everything differs.
    CHECK(diff(body, with_header, 0).diff_bytes > 4000);

    // A = header + B: shift -4.
    r = diff(with_header, body, -4);
    REQUIRE(r.ranges.size() == 1);
    CHECK(r.ranges[0] == R(0, 0, 4, DiffRange::OnlyA));

    // A change in the aligned part is reported at both offsets.
    Bytes b2 = with_header;
    b2[4 + 1000] ^= 0x55;
    r = diff(body, b2, 4);
    REQUIRE(r.ranges.size() == 2);
    CHECK(r.ranges[1] == R(1000, 1004, 1));

    // Shift beyond the other side: nothing aligns.
    r = diff(body, with_header, 10000);
    REQUIRE(r.ranges.size() == 2);
    CHECK(r.ranges[0] == R(0, 0, with_header.size(), DiffRange::OnlyB));
    CHECK(r.ranges[1] == R(0, with_header.size(), body.size(), DiffRange::OnlyA));
    r = diff(body, with_header, -10000);
    REQUIRE(r.ranges.size() == 2);
    CHECK(r.ranges[0] == R(0, 0, body.size(), DiffRange::OnlyA));
    CHECK(r.ranges[1] == R(body.size(), 0, with_header.size(), DiffRange::OnlyB));
    CHECK(diff(body, body, INT64_MIN).diff_bytes == 2 * body.size());
    CHECK(diff(body, body, INT64_MAX).diff_bytes == 2 * body.size());
}

TEST_CASE("diff: ranges crossing 4 MiB block boundaries") {
    const size_t n = size_t(9 * kMiB + 123);
    Bytes a = random_bytes(n, 5), b = a;
    for (uint64_t i = kBlk - 3; i < kBlk + 5; ++i) b[size_t(i)] ^= 0xFF;
    b[size_t(2 * kBlk - 1)] ^= 1;
    b[size_t(2 * kBlk)] ^= 1;
    DiffResult r = diff(a, b);
    REQUIRE(r.ranges.size() == 2);
    CHECK(r.ranges[0] == R(kBlk - 3, kBlk - 3, 8));
    CHECK(r.ranges[1] == R(2 * kBlk - 1, 2 * kBlk - 1, 2));

    // With a shift the block boundaries of A and B differ; the result still merges.
    Bytes bs(7, 0x42);
    bs.insert(bs.end(), b.begin(), b.end());
    r = diff(a, bs, 7);
    REQUIRE(r.ranges.size() == 3);
    CHECK(r.ranges[0] == R(0, 0, 7, DiffRange::OnlyB));
    CHECK(r.ranges[1] == R(kBlk - 3, kBlk + 4, 8));
    CHECK(r.ranges[2] == R(2 * kBlk - 1, 2 * kBlk + 6, 2));
}

TEST_CASE("diff: matches a byte-by-byte reference on random edits") {
    std::mt19937_64 rng(77);
    for (int iter = 0; iter < 40; ++iter) {
        size_t na = size_t(rng() % 3000), nb = size_t(rng() % 3000);
        Bytes a = random_bytes(na, rng()), b(nb);
        for (size_t i = 0; i < nb; ++i) b[i] = i < na ? a[i] : uint8_t(rng());
        for (int k = int(rng() % 30); k > 0 && nb; --k) {  // runs of changes
            size_t at = size_t(rng() % nb), len = size_t(rng() % 40);
            for (size_t i = at; i < std::min(nb, at + len); ++i) b[i] = uint8_t(rng());
        }
        int64_t shift = int64_t(rng() % 21) - 10;
        INFO("iter " << iter << " shift " << shift);
        DiffResult r = diff(a, b, shift);
        std::vector<DiffRange> want = naive(a, b, shift);
        CHECK(r.ranges == want);
        CHECK(r.diff_bytes == sum_len(want));
        CHECK(r.range_count == want.size());
    }
}

TEST_CASE("diff: max_ranges cap keeps counting") {
    Bytes a(1000, 0), b = a;
    for (int i = 0; i < 10; ++i) b[size_t(i * 10)] = 1;
    DiffResult r = diff(a, b, 0, 3);
    CHECK(r.truncated);
    REQUIRE(r.ranges.size() == 3);
    CHECK(r.ranges[2] == R(20, 20, 1));
    CHECK(r.range_count == 10);
    CHECK(r.diff_bytes == 10);
    r = diff(a, b, 0, 10);
    CHECK_FALSE(r.truncated);
    CHECK(r.ranges.size() == 10);
}

TEST_CASE("diff: lookups next / prev / ranges_in") {
    // A head OnlyB (zero width in A), changes, an OnlyA tail (zero width in B).
    std::vector<DiffRange> v = {R(0, 0, 4, DiffRange::OnlyB), R(0, 4, 2), R(10, 14, 3), R(20, 24, 1),
                                R(30, 34, 5, DiffRange::OnlyA)};
    CHECK(next_diff(v, 0) == 2);
    CHECK(next_diff(v, 9) == 2);
    CHECK(next_diff(v, 10) == 3);
    CHECK(next_diff(v, 30) == kNoDiff);
    CHECK(prev_diff(v, 0) == kNoDiff);
    CHECK(prev_diff(v, 1) == 1);
    CHECK(prev_diff(v, 10) == 1);
    CHECK(prev_diff(v, 11) == 2);
    CHECK(prev_diff(v, 1000) == 4);
    CHECK(next_diff(v, 0, true) == 1);   // B coordinates
    CHECK(next_diff(v, 4, true) == 2);
    CHECK(prev_diff(v, 4, true) == 0);
    CHECK(prev_diff(v, 34, true) == 3);
    CHECK(prev_diff(v, 35, true) == 4);
    CHECK(next_diff({}, 0) == kNoDiff);
    CHECK(prev_diff({}, 5) == kNoDiff);

    auto span = [&](uint64_t b, uint64_t e, bool side_b) { return ranges_in(v, b, e, side_b); };
    CHECK(span(0, 1, false) == std::pair<size_t, size_t>(1, 2));    // the OnlyB head has no A bytes
    CHECK(span(2, 10, false) == std::pair<size_t, size_t>(2, 2));   // gap: empty
    CHECK(span(2, 11, false) == std::pair<size_t, size_t>(2, 3));
    CHECK(span(12, 31, false) == std::pair<size_t, size_t>(2, 5));
    CHECK(span(35, 100, false) == std::pair<size_t, size_t>(5, 5));
    CHECK(span(0, 4, true) == std::pair<size_t, size_t>(0, 1));     // the OnlyB head in B
    CHECK(span(0, 5, true) == std::pair<size_t, size_t>(0, 2));
    CHECK(span(16, 25, true) == std::pair<size_t, size_t>(2, 4));
    CHECK(span(25, 100, true) == std::pair<size_t, size_t>(4, 5));   // OnlyA tail: at b_off 34,
    CHECK(diff_len_b(v[4]) == 0);                                     // zero width in B
    CHECK(ranges_in({}, 0, 100) == std::pair<size_t, size_t>(0, 0));
}

TEST_CASE("diff: cancel") {
    Bytes a = random_bytes(1000, 9), b = a;
    b[10] ^= 1;
    std::atomic<bool> cancel{true};
    DiffResult r = diff_snapshots(*snap_of(a), *snap_of(b), 0, 100, &cancel);
    CHECK(r.cancelled);
    CHECK(r.ranges.empty());
    CHECK_FALSE(r.identical());

    // Job: 2 GiB in memory (filled docs share one chunk), cancelled right away.
    const uint8_t pa = 1, pb = 2;
    auto da = Document::create_empty("a"), db = Document::create_empty("b");
    REQUIRE(da->fill(0, 2048 * kMiB, &pa, 1));
    REQUIRE(db->fill(0, 2048 * kMiB, &pb, 1));
    DiffJob job;
    job.start(da->snapshot(), db->snapshot(), 0, 10);
    job.cancel();
    REQUIRE(wait_for(job, 0));
    CHECK_FALSE(job.running());
    auto res = job.result();
    REQUIRE(res);
    CHECK(res->cancelled);
    CHECK(res->diff_bytes < 2048 * kMiB);

    // A superseded run publishes nothing; the latest one does.
    Bytes x = random_bytes(5000, 10), y = x;
    y[4999] ^= 1;
    uint64_t g = job.generation();
    const uint64_t first = job.start(da->snapshot(), db->snapshot(), 0, 10);
    const uint64_t second = job.start(snap_of(x), snap_of(y), 0);
    CHECK(second == first + 1);
    REQUIRE(wait_for(job, g));
    res = job.result();
    REQUIRE(res);
    CHECK(res->run == second);
    CHECK_FALSE(res->cancelled);
    REQUIRE(res->ranges.size() == 1);
    CHECK(res->ranges[0] == R(4999, 4999, 1));
    CHECK(job.progress() == 1.0);
}

TEST_CASE("diff: job result and progress") {
    Bytes a = random_bytes(size_t(10 * kMiB), 11), b = a;
    b.resize(b.size() - 100);
    b[size_t(5 * kMiB)] ^= 1;
    DiffJob job;
    CHECK_FALSE(job.result());
    job.start(snap_of(a), snap_of(b), 0);
    REQUIRE(wait_for(job, 0));
    auto r = job.result();
    REQUIRE(r);
    REQUIRE(r->ranges.size() == 2);
    CHECK(r->ranges[0] == R(5 * kMiB, 5 * kMiB, 1));
    CHECK(r->ranges[1] == R(b.size(), b.size(), 100, DiffRange::OnlyA));
    CHECK(job.progress() == 1.0);
    CHECK(diff_work(a.size(), b.size(), 0) == b.size());
    CHECK(diff_work(100, 50, 60) == 0);
    CHECK(diff_work(100, 50, -60) == 40);
}

TEST_CASE("diff: >4 GiB sparse pair") {
    TempDir t;
    const uint64_t size = (uint64_t(4) << 30) + 2 * kMiB;
    const std::string pa = t.file("a.bin"), pb = t.file("b.bin");
    make_sparse(pa, size);
    make_sparse(pb, size - kMiB);
    auto da = Document::open_file(pa), db = Document::open_file(pb);
    REQUIRE(da);
    REQUIRE(db);
    const uint64_t at = (uint64_t(4) << 30) + 100;  // beyond 32-bit offsets
    const uint8_t tag[8] = {'B', 'I', 'G', 'D', 'I', 'F', 'F', '!'};
    REQUIRE(db->overwrite(at, tag, sizeof tag));

    auto t0 = std::chrono::steady_clock::now();
    DiffJob job;
    job.start(da->snapshot(), db->snapshot(), 0);
    REQUIRE(wait_for(job, 0, 120000));
    auto r = job.result();
    REQUIRE(r);
    MESSAGE("4 GiB sparse compare: "
            << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count()
            << " ms");
    CHECK_FALSE(r->io_error);
    REQUIRE(r->ranges.size() == 2);
    CHECK(r->ranges[0] == R(at, at, 8));
    CHECK(r->ranges[1] == R(size - kMiB, size - kMiB, kMiB, DiffRange::OnlyA));
    CHECK(r->diff_bytes == kMiB + 8);
    auto span = ranges_in(r->ranges, at - 16, at + 16);
    CHECK(span == std::pair<size_t, size_t>(0, 1));
    CHECK(next_diff(r->ranges, 0) == 0);
    CHECK(next_diff(r->ranges, at) == 1);
}
