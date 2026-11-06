// Tests for core/diff: DiffJob / diff_snapshots over Document snapshots, range lookups.
#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iterator>
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

// ---- find_shift / ShiftJob ----------------------------------------------------------------------

namespace {

Bytes cat(std::initializer_list<const Bytes*> parts) {
    Bytes out;
    for (const Bytes* p : parts) out.insert(out.end(), p->begin(), p->end());
    return out;
}

ShiftResult shift_of(const Bytes& a, const Bytes& b, int64_t shift = 0, const ShiftOptions& opt = {}) {
    return find_shift(*snap_of(a), *snap_of(b), shift, opt);
}

// The proposed shift really aligns the documents: only the header / the unaligned tails differ.
void check_aligned(const Bytes& a, const Bytes& b, int64_t shift) {
    const DiffResult d = diff(a, b, shift);
    for (const DiffRange& r : d.ranges) CHECK(r.kind != DiffRange::Changed);
}

}  // namespace

TEST_CASE("find_shift: header inserted in B / deleted from B, various sizes") {
    const Bytes body = random_bytes(256 * 1024, 21);
    for (size_t h : {size_t(1), size_t(7), size_t(64), size_t(513), size_t(4096), size_t(100000)}) {
        CAPTURE(h);
        Bytes head = random_bytes(h, 100 + h);
        head[0] = uint8_t(body[0] ^ 0x5A);  // the first byte differs (else the difference starts later)
        const Bytes with = cat({&head, &body});
        ShiftResult r = shift_of(body, with);  // B has an extra header
        REQUIRE(r.status == ShiftResult::Found);
        CHECK(r.shift == int64_t(h));
        CHECK(r.delta == int64_t(h));
        CHECK(r.diff_a == 0);
        CHECK(std::memcmp(body.data() + r.match_a, with.data() + r.match_b, 64) == 0);
        check_aligned(body, with, r.shift);

        r = shift_of(with, body);  // A has the extra header (deleted from B)
        REQUIRE(r.status == ShiftResult::Found);
        CHECK(r.shift == -int64_t(h));
        CHECK(r.delta == -int64_t(h));
        check_aligned(with, body, r.shift);
    }
}

TEST_CASE("find_shift: an edit inside the first block after the difference") {
    const Bytes body = random_bytes(64 * 1024, 25);
    Bytes head = random_bytes(200, 26);
    head[0] = uint8_t(body[0] ^ 1);
    const Bytes b = cat({&head, &body});
    Bytes a = body;  // A: the original with two edited bytes at 0x10 (what Compare with Backup shows)
    a[0x10] ^= 0xFF;
    a[0x11] ^= 0xFF;
    ShiftResult r = shift_of(a, b);
    REQUIRE(r.status == ShiftResult::Found);
    CHECK(r.shift == 200);
    CHECK(r.match_a >= 0x12);
    CHECK(std::memcmp(a.data() + r.match_a, b.data() + r.match_b, 64) == 0);
    ShiftOptions one;
    one.probes = 1;
    CHECK(shift_of(a, b, 0, one).status == ShiftResult::NoMatch);  // why several probes are kept
}

TEST_CASE("find_shift: insertion / deletion in the middle adds to the current shift") {
    const Bytes x = random_bytes(10000, 31), y = random_bytes(50000, 32), ins = random_bytes(300, 33);
    const Bytes hdr = random_bytes(100, 34);
    const Bytes a = cat({&x, &y});
    const Bytes b = cat({&hdr, &x, &ins, &y});  // B: a 100-byte header (known shift) + 300 inserted bytes
    ShiftResult r = shift_of(a, b, 100);
    REQUIRE(r.status == ShiftResult::Found);
    CHECK(r.diff_a == x.size());
    CHECK(r.diff_b == 100 + x.size());
    CHECK(r.shift == 400);
    CHECK(r.delta == 300);
    CHECK(r.match_a == x.size());
    CHECK(r.match_b == 400 + x.size());

    r = shift_of(b, a, -100);  // the same seen from the other side: a deletion
    REQUIRE(r.status == ShiftResult::Found);
    CHECK(r.shift == -400);
    CHECK(r.delta == -300);
}

TEST_CASE("find_shift: low-entropy runs are skipped") {
    const Bytes x = random_bytes(5000, 41), y = random_bytes(20000, 42), zeros(10000, 0), pad(7, 0xAB);
    // B: zero padding inserted after x. A's probe at the difference is the start of y.
    {
        const Bytes a = cat({&x, &y}), b = cat({&x, &zeros, &y});
        ShiftResult r = shift_of(a, b);
        REQUIRE(r.status == ShiftResult::Found);
        CHECK(r.shift == 10000);
        CHECK(r.match_a >= x.size());
    }
    // The difference sits right before an all-zero run on both sides: a probe made of zeros
    // would match anywhere, so the first distinctive block (in y) is used.
    {
        const Bytes a = cat({&x, &zeros, &y}), b = cat({&x, &pad, &zeros, &y});
        ShiftResult r = shift_of(a, b);
        REQUIRE(r.status == ShiftResult::Found);
        CHECK(r.diff_a == x.size());
        CHECK(r.shift == 7);
        CHECK(r.match_a > x.size());
        CHECK(std::memcmp(a.data() + r.match_a, b.data() + r.match_b, 64) == 0);
    }
    // Only low-entropy data after the difference: nothing to search with.
    {
        const Bytes a = cat({&x, &zeros}), b = cat({&x, &pad, &zeros});
        ShiftResult r = shift_of(a, b);
        CHECK(r.status == ShiftResult::NoProbe);
        CHECK(r.shift == 0);
        CHECK(r.diff_a == x.size());
    }
}

TEST_CASE("find_shift: identical, appended tail, plain change, no match, window bound") {
    const Bytes a = random_bytes(100000, 51);
    CHECK(shift_of(a, a).status == ShiftResult::NoDifference);
    CHECK(shift_of(Bytes{}, Bytes{}).status == ShiftResult::NoDifference);
    Bytes longer = a;
    longer.resize(a.size() + 500, 0x11);
    CHECK(shift_of(a, longer).status == ShiftResult::NoDifference);  // only an appended tail

    // 16 changed bytes: no shift; the bytes after the change already line up.
    Bytes changed = a;
    for (size_t i = 1000; i < 1016; ++i) changed[i] ^= 0xFF;
    ShiftResult r = shift_of(a, changed);
    REQUIRE(r.status == ShiftResult::Found);
    CHECK(r.diff_a == 1000);
    CHECK(r.delta == 0);
    CHECK(r.shift == 0);
    CHECK(r.match_a >= 1016);
    CHECK(r.match_b == r.match_a);
    ShiftOptions one;  // a single probe (spanning the change) fails: found by the aligned check
    one.probes = 1;
    r = shift_of(a, changed, 0, one);
    REQUIRE(r.status == ShiftResult::Found);
    CHECK(r.delta == 0);
    CHECK(r.match_a == 1016);

    // Unrelated contents.
    r = shift_of(a, random_bytes(100000, 52));
    CHECK(r.status == ShiftResult::NoMatch);
    CHECK(r.shift == 0);

    // A header longer than the window is not found; a wider window finds it.
    const Bytes head = random_bytes(5000, 53);
    const Bytes b = cat({&head, &a});
    ShiftOptions small;
    small.window = 4096;
    CHECK(shift_of(a, b, 0, small).status == ShiftResult::NoMatch);
    small.window = 5000;
    r = shift_of(a, b, 0, small);
    REQUIRE(r.status == ShiftResult::Found);
    CHECK(r.shift == 5000);
    // Nearest match wins: the probe occurs twice in B, at +5000 and at +5000 + 70000.
    Bytes twice = b;
    twice.insert(twice.begin() + 75000, a.begin(), a.begin() + 64);
    r = shift_of(a, twice);
    REQUIRE(r.status == ShiftResult::Found);
    CHECK(r.shift == 5000);
}

TEST_CASE("find_shift: a change followed by an insertion; the next misalignment from an offset") {
    const Bytes x = random_bytes(10000, 81), y = random_bytes(50000, 82), z = random_bytes(30000, 83);
    const Bytes w = random_bytes(20000, 84), ins = random_bytes(300, 85), ins2 = random_bytes(77, 86);
    Bytes xc = x;  // two plain changes before the insertion
    for (size_t i = 1000; i < 1016; ++i) xc[i] ^= 0xFF;
    xc[5000] ^= 1;
    const Bytes a = cat({&x, &y, &z, &w}), b = cat({&xc, &y, &ins, &z, &ins2, &w});
    ShiftResult r = shift_of(a, b);
    REQUIRE(r.status == ShiftResult::Found);
    CHECK(r.changes == 2);
    CHECK_FALSE(r.limit);
    CHECK(r.diff_a == x.size() + y.size());
    CHECK(r.delta == 300);
    CHECK(r.shift == 300);
    CHECK(r.match_a == x.size() + y.size());
    CHECK(std::memcmp(a.data() + r.match_a, b.data() + r.match_b, 64) == 0);
    // Without passing over changes the first one answers "no shift" (the old behaviour).
    ShiftOptions plain;
    plain.change_scan = 0;
    ShiftResult p = shift_of(a, b, 0, plain);
    REQUIRE(p.status == ShiftResult::Found);
    CHECK(p.delta == 0);
    CHECK(p.diff_a == 1000);
    // The next misalignment: from the match on, under the new shift, the second insertion.
    ShiftOptions next;
    next.from = r.match_a;
    ShiftResult r2 = shift_of(a, b, r.shift, next);
    REQUIRE(r2.status == ShiftResult::Found);
    CHECK(r2.changes == 0);
    CHECK(r2.diff_a == x.size() + y.size() + z.size());
    CHECK(r2.delta == 77);
    CHECK(r2.shift == 377);
    next.from = r2.match_a;
    ShiftResult r3 = shift_of(a, b, r2.shift, next);
    CHECK(r3.status == ShiftResult::NoDifference);
    // max_changes: stop after each change; searching again from the match goes on.
    ShiftOptions one;
    one.max_changes = 1;
    ShiftResult s = shift_of(a, b, 0, one);
    REQUIRE(s.status == ShiftResult::Found);
    CHECK(s.limit);
    CHECK(s.changes == 1);
    CHECK(s.delta == 0);
    CHECK(s.diff_a == 1000);
    CHECK(s.match_a == 1016);
    one.from = s.match_a;
    s = shift_of(a, b, 0, one);
    CHECK(s.limit);
    CHECK(s.diff_a == 5000);
    one.from = s.match_a;
    s = shift_of(a, b, 0, one);
    CHECK_FALSE(s.limit);
    CHECK(s.delta == 300);
    // Only changes after `from`: no shift needed, the first change and the last match reported.
    Bytes only = a;
    only[20000] ^= 1;
    only[40000] ^= 1;
    only[70000] ^= 1;
    s = shift_of(a, only);
    REQUIRE(s.status == ShiftResult::Found);
    CHECK(s.delta == 0);
    CHECK(s.changes == 3);
    CHECK(s.diff_a == 20000);
    CHECK(s.match_a > 70000);
    ShiftOptions late;
    late.from = 70001;
    CHECK(shift_of(a, only, 0, late).status == ShiftResult::NoDifference);
}

TEST_CASE("find_shift: no overlap under the current shift, huge shifts do not overflow") {
    const Bytes body = random_bytes(20000, 61), head = random_bytes(3000, 62);
    const Bytes b = cat({&head, &body});
    ShiftResult r = shift_of(body, b, 30000);  // B offset 30000 is past B's end: no overlap at all
    REQUIRE(r.status == ShiftResult::Found);
    CHECK(r.shift == 3000);
    CHECK(shift_of(body, b, INT64_MAX).status == ShiftResult::NoMatch);
    CHECK(shift_of(body, b, INT64_MIN).status == ShiftResult::NoMatch);
}

TEST_CASE("find_shift: job, progress, cancel") {
    const Bytes body = random_bytes(size_t(6 * kMiB), 71), head = random_bytes(777, 72);
    const Bytes b = cat({&head, &body});
    ShiftJob job;
    CHECK_FALSE(job.result());
    const uint64_t id = job.start(snap_of(body), snap_of(b), 0);
    auto t0 = std::chrono::steady_clock::now();
    while (job.generation() == 0 && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30))
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    auto r = job.result();
    REQUIRE(r);
    CHECK(r->run == id);
    CHECK(r->status == ShiftResult::Found);
    CHECK(r->shift == 777);
    CHECK(job.progress() == 1.0);
    CHECK_FALSE(job.running());

    // A cancelled scan of 2 GiB (filled documents share one chunk) stops early.
    auto da = Document::create_empty("a"), db = Document::create_empty("b");
    const uint8_t za = 0, zb = 0;
    REQUIRE(da->fill(0, 2048 * kMiB, &za, 1));
    REQUIRE(db->fill(0, 2048 * kMiB, &zb, 1));
    const uint8_t tag = 1;
    REQUIRE(db->overwrite(2048 * kMiB - 1, &tag, 1));
    std::atomic<bool> cancel{true};
    ShiftResult c = find_shift(*da->snapshot(), *db->snapshot(), 0, {}, &cancel);
    CHECK(c.status == ShiftResult::Cancelled);
    CHECK(c.shift == 0);
}

TEST_CASE("find_shift: >4 GiB sparse files, insertion past 4 GiB") {
    TempDir t;
    const uint64_t size = (uint64_t(4) << 30) + 2 * kMiB;
    const std::string p = t.file("a.bin");
    make_sparse(p, size);
    auto da = Document::open_file(p), db = Document::open_file(p);
    REQUIRE(da);
    REQUIRE(db);
    const uint64_t at = (uint64_t(4) << 30) + 100;  // beyond 32-bit offsets
    const Bytes data = random_bytes(4096, 81);
    Bytes ins = random_bytes(300, 82);
    ins[0] = uint8_t(data[0] ^ 1);  // the difference starts exactly at `at`
    REQUIRE(da->overwrite(at, data.data(), data.size()));
    REQUIRE(db->overwrite(at, data.data(), data.size()));
    REQUIRE(db->insert(at, ins.data(), ins.size()));
    auto t0 = std::chrono::steady_clock::now();
    ShiftResult r = find_shift(*da->snapshot(), *db->snapshot(), 0);
    MESSAGE("4 GiB sparse find_shift: "
            << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count()
            << " ms");
    REQUIRE(r.status == ShiftResult::Found);
    CHECK(r.diff_a == at);
    CHECK(r.shift == 300);
    CHECK(r.match_a == at);
    CHECK(r.match_b == at + 300);
}

// ---- Revert to Backup: Document::replace_with_file ----------------------------------------------

namespace {

void write_file(const std::string& p, const Bytes& b) {
    std::ofstream f(from_u8(p), std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(b.data()), std::streamsize(b.size()));
}

Bytes read_file(const std::string& p) {
    std::ifstream f(from_u8(p), std::ios::binary);
    return Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

Bytes doc_bytes(const Document& d) {
    Bytes b(size_t(d.size()));
    if (!b.empty()) REQUIRE(d.read(0, b.data(), b.size()) == b.size());
    return b;
}

}  // namespace

TEST_CASE("replace_with_file: one undo step, references the file, save keeps the .backup") {
    TempDir t;
    const std::string p = t.file("data.bin");
    const Bytes cur = random_bytes(300000, 91), orig = random_bytes(200000, 92);
    write_file(p, cur);
    const std::string bak = Document::backup_path_of(p);
    CHECK(bak == os_absolute_path(p) + ".backup");
    write_file(bak, orig);

    auto d = Document::open_file(p);
    REQUIRE(d);
    const uint8_t x = 0x42;
    REQUIRE(d->overwrite(10, &x, 1));
    const Bytes edited = doc_bytes(*d);
    const size_t chunks = d->add_buffer().chunks().size();
    const size_t undo = d->undo_stack().size();

    std::string err;
    REQUIRE(d->replace_with_file(bak, "Revert to Backup", &err));
    CHECK(err.empty());
    CHECK(doc_bytes(*d) == orig);
    CHECK(d->dirty());
    CHECK(d->undo_stack().size() == undo + 1);
    CHECK(d->undo_stack().back().label == "Revert to Backup");
    CHECK(d->add_buffer().chunks().size() == chunks);  // nothing copied into memory
    CHECK(d->table().pieces().size() == 1);
    CHECK(d->is_modified_range(0, 1));                 // reverted bytes are not the file on disk
    CHECK(read_file(p) == cur);                        // disk untouched until saved

    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == edited);
    CHECK_FALSE(d->is_modified_range(0, 1));           // the current file version again
    CHECK(d->is_modified_range(10, 1));
    REQUIRE(d->redo());
    CHECK(doc_bytes(*d) == orig);

    // Edits on top of the reverted content, then save: a rewrite of the file; the .backup stays.
    REQUIRE(d->overwrite(5, &x, 1));
    Bytes want = orig;
    want[5] = x;
    CHECK(doc_bytes(*d) == want);
    REQUIRE(d->save(nullptr, &err));
    CHECK(read_file(p) == want);
    CHECK(read_file(bak) == orig);
    CHECK_FALSE(d->last_save_info().backup_created);
    CHECK_FALSE(d->dirty());
    // History survives the save: back to before the revert.
    REQUIRE(d->undo());
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == edited);
}

TEST_CASE("replace_with_file: session export inlines small reverts, refusals") {
    TempDir t;
    const std::string p = t.file("small.bin");
    const Bytes cur = random_bytes(5000, 93), orig = random_bytes(7000, 94);
    write_file(p, cur);
    const std::string bak = Document::backup_path_of(p);
    write_file(bak, orig);

    auto d = Document::open_file(p);
    REQUIRE(d);
    std::string err;
    CHECK_FALSE(d->replace_with_file(p, "Revert", &err));  // its own file
    CHECK_FALSE(err.empty());
    CHECK_FALSE(d->replace_with_file(t.file("missing.bin"), "Revert", &err));
    d->set_read_only(true);
    CHECK_FALSE(d->replace_with_file(bak, "Revert", &err));
    d->set_read_only(false);
    CHECK(d->undo_stack().empty());
    CHECK(doc_bytes(*d) == cur);

    REQUIRE(d->replace_with_file(bak, "Revert to Backup", &err));
    CHECK(d->hot_exit_safe());  // 7000 bytes: inlined into the session
    PersistedDoc st = d->persist();
    CHECK_FALSE(st.edits_dropped);
    auto r = Document::restore(st, nullptr, &err);
    REQUIRE(r);
    CHECK(doc_bytes(*r) == orig);
    REQUIRE(r->undo());
    CHECK(doc_bytes(*r) == cur);

    // An empty file empties the document (still undoable).
    const std::string empty = t.file("empty.bin");
    write_file(empty, {});
    REQUIRE(d->replace_with_file(empty, "Revert", &err));
    CHECK(d->size() == 0);
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == orig);
}

TEST_CASE("replace_with_file: after an undo (redo states dropped) the file stays referenced") {
    // Regression: the new undo step drops the redo states, which prunes unused sources; the
    // just-inserted file source was pruned too and the reverted content read as nothing / zeros.
    TempDir t;
    const std::string p = t.file("redo.bin");
    const Bytes cur = random_bytes(4000, 95), orig = random_bytes(6000, 96);
    write_file(p, cur);
    const std::string bak = Document::backup_path_of(p);
    write_file(bak, orig);
    auto d = Document::open_file(p);
    REQUIRE(d);
    const uint8_t x = 0x42;
    REQUIRE(d->overwrite(10, &x, 1));
    REQUIRE(d->undo());
    REQUIRE_FALSE(d->redo_stack().empty());
    std::string err;
    REQUIRE(d->replace_with_file(bak, "Revert to Backup", &err));
    CHECK(d->redo_stack().empty());
    CHECK(doc_bytes(*d) == orig);
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == cur);
    REQUIRE(d->redo());
    CHECK(doc_bytes(*d) == orig);
}
