// Entropy overview: byte classes, Shannon entropy, bucket layout, sampling and the background job.
#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <initializer_list>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#endif

#include "core/document.h"
#include "core/entropy.h"
#include "core/os_file.h"
#include "holey_mem.h"

using namespace hx;

namespace {

using Bytes = std::vector<uint8_t>;

std::shared_ptr<const Snapshot> snap_of(const Bytes& b) {
    auto doc = Document::create_from_bytes("test", b.data(), b.size());
    REQUIRE(doc);
    return doc->snapshot();  // keeps its data alive after the document is gone
}

void wait_for(const EntropyJob& job, uint64_t gen) {
    auto t0 = std::chrono::steady_clock::now();
    while (job.generation() == gen) {
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(60));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

std::shared_ptr<const EntropyResult> run(EntropyJob& job, std::shared_ptr<const Snapshot> s, EntropyOptions o = {}) {
    const uint64_t gen = job.generation();
    job.start(std::move(s), o);
    wait_for(job, gen);
    CHECK_FALSE(job.running());
    auto r = job.result();
    REQUIRE(r);
    CHECK(r->finished);
    return r;
}

float entropy_of(const Bytes& b) {
    uint64_t counts[256] = {};
    for (uint8_t v : b) ++counts[v];
    return shannon_entropy(counts);
}

float frac(const EntropyBucket& b, ByteClass c) { return b.class_frac[int(c)]; }

struct TempDir {
    std::string path;
    TempDir() {
        std::error_code ec;
        std::string base = std::filesystem::temp_directory_path(ec).string();
        if (ec || base.empty()) base = ".";
        path = path_join(base, "hexer_entropy_" + std::to_string(std::random_device{}()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        REQUIRE(os_mkdirs(path));
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(std::filesystem::path(path), ec);
    }
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
    {
        auto f = OsFile::open(p, OsFile::Mode::CreateTruncate);
        REQUIRE(f);
    }
#endif
    auto f = OsFile::open(p, OsFile::Mode::ReadWrite);
    REQUIRE(f);
    REQUIRE(f->truncate(size));
}

// Gate for the bucket hook: the worker blocks after publishing bucket `n` until g_release >= n.
std::atomic<uint32_t> g_release{0};
void gate_hook(uint32_t done) {
    auto t0 = std::chrono::steady_clock::now();
    while (g_release.load() < done && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30))
        std::this_thread::yield();
}
struct HookGuard {
    explicit HookGuard(uint32_t release) {
        g_release = release;
        EntropyJob::set_bucket_hook_for_tests(gate_hook);
    }
    ~HookGuard() {
        g_release = UINT32_MAX;
        EntropyJob::set_bucket_hook_for_tests(nullptr);
    }
};

}  // namespace

TEST_CASE("entropy: byte classes") {
    CHECK(byte_class(0x00) == ByteClass::Zero);
    CHECK(byte_class(0xFF) == ByteClass::Full);
    CHECK(byte_class(' ') == ByteClass::Whitespace);
    CHECK(byte_class('\n') == ByteClass::Whitespace);
    CHECK(byte_class('A') == ByteClass::Printable);
    CHECK(byte_class(0x7F) == ByteClass::Control);
    CHECK(byte_class(0x80) == ByteClass::High);
    CHECK(std::string(byte_class_name(ByteClass::Full)) == "0xFF");
}

TEST_CASE("entropy: shannon entropy of known buffers") {
    CHECK(entropy_of(Bytes(4096, 0)) == doctest::Approx(0.0));
    CHECK(entropy_of(Bytes(4096, 0x41)) == doctest::Approx(0.0));
    Bytes all(256 * 16);
    for (size_t i = 0; i < all.size(); ++i) all[i] = uint8_t(i);
    CHECK(entropy_of(all) == doctest::Approx(8.0));
    Bytes two(1000);
    for (size_t i = 0; i < two.size(); ++i) two[i] = uint8_t(i % 2 ? 0xAA : 0x55);
    CHECK(entropy_of(two) == doctest::Approx(1.0));
    Bytes four(1000);
    for (size_t i = 0; i < four.size(); ++i) four[i] = uint8_t(i % 4);
    CHECK(entropy_of(four) == doctest::Approx(2.0));
    uint64_t none[256] = {};
    CHECK(shannon_entropy(none) == 0.0f);
}

TEST_CASE("entropy: color ramp") {
    auto r = [](uint32_t c) { return int(c & 0xFF); };
    auto b = [](uint32_t c) { return int((c >> 16) & 0xFF); };
    CHECK((entropy_color(0.0f) >> 24) == 0xFF);           // opaque
    CHECK(entropy_color(-1.0f) == entropy_color(0.0f));  // clamped
    CHECK(entropy_color(9.0f) == entropy_color(8.0f));
    CHECK(entropy_color(NAN) == entropy_color(0.0f));
    CHECK(b(entropy_color(1.0f)) > r(entropy_color(1.0f)));  // low: blue-ish
    CHECK(r(entropy_color(7.9f)) > b(entropy_color(7.9f)) + 100);  // high: red/orange
    CHECK(r(entropy_color(7.5f)) > 0xC0);
}

TEST_CASE("entropy: bucket layout") {
    SUBCASE("empty") {
        EntropyResult r = entropy_layout(0, 1024);
        CHECK(r.buckets.empty());
        CHECK(r.bucket_size >= 1);
        CHECK(r.bucket_of(5) == 0);
    }
    SUBCASE("tiny file: one byte per bucket") {
        EntropyResult r = entropy_layout(10, 1024);
        REQUIRE(r.buckets.size() == 10);
        CHECK(r.bucket_size == 1);
        CHECK(r.buckets[9].offset == 9);
        CHECK(r.buckets[9].length == 1);
    }
    SUBCASE("not divisible") {
        EntropyResult r = entropy_layout(1000, 7);  // ceil(1000/7) = 143 -> 7 buckets, last 142
        REQUIRE(r.buckets.size() == 7);
        CHECK(r.bucket_size == 143);
        CHECK(r.buckets[6].offset == 858);
        CHECK(r.buckets[6].length == 142);
        CHECK(r.bucket_of(857) == 5);
        CHECK(r.bucket_of(858) == 6);
        CHECK(r.bucket_of(999999) == 6);
        uint64_t sum = 0;
        for (const auto& b : r.buckets) {
            CHECK(b.offset == sum);
            CHECK(b.length >= 1);
            sum += b.length;
        }
        CHECK(sum == 1000);
    }
    SUBCASE("ceil can need fewer buckets") {
        EntropyResult r = entropy_layout(10, 4);  // 3,3,3,1
        REQUIRE(r.buckets.size() == 4);
        r = entropy_layout(1025, 1024);  // bucket size 2 -> 513 buckets
        CHECK(r.bucket_size == 2);
        CHECK(r.buckets.size() == 513);
        CHECK(r.buckets.back().length == 1);
    }
    SUBCASE("huge") {
        const uint64_t size = 3ull << 40;  // 3 TiB
        EntropyResult r = entropy_layout(size, 1024);
        REQUIRE(r.buckets.size() == 1024);
        CHECK(r.bucket_size == size / 1024);
        CHECK(r.buckets.back().offset + r.buckets.back().length == size);
        r = entropy_layout(UINT64_MAX, 1000);  // no overflow
        CHECK(r.buckets.size() == 1000);
        CHECK(r.buckets.back().offset + r.buckets.back().length == UINT64_MAX);
    }
}

TEST_CASE("entropy: job computes entropy and class fractions per bucket") {
    // 4 buckets of 1024: zeros, counting (uniform), text, two-symbol 0x80/0xFF.
    Bytes d(4096);
    for (size_t i = 0; i < 1024; ++i) {
        d[i] = 0;
        d[1024 + i] = uint8_t(i);
        d[2048 + i] = uint8_t(i % 4 == 3 ? ' ' : 'a' + int(i % 3));
        d[3072 + i] = uint8_t(i % 2 ? 0xFF : 0x80);
    }
    EntropyJob job;
    EntropyOptions o;
    o.buckets = 4;
    auto r = run(job, snap_of(d), o);
    REQUIRE(r->buckets.size() == 4);
    CHECK(r->done == 4);
    CHECK_FALSE(r->cancelled);
    CHECK_FALSE(r->io_error);
    CHECK(r->bytes_read == 4096);
    CHECK(job.progress() == 1.0);
    const auto& b = r->buckets;
    for (const auto& x : b) {
        CHECK(x.done);
        CHECK_FALSE(x.sampled);
        CHECK(x.bytes_read == 1024);
        float sum = 0;
        for (float f : x.class_frac) sum += f;
        CHECK(sum == doctest::Approx(1.0));
    }
    CHECK(b[0].entropy == doctest::Approx(0.0));
    CHECK(frac(b[0], ByteClass::Zero) == doctest::Approx(1.0));
    CHECK(b[1].entropy == doctest::Approx(8.0));
    CHECK(frac(b[1], ByteClass::Zero) == doctest::Approx(4.0 / 1024));
    CHECK(frac(b[1], ByteClass::Full) == doctest::Approx(4.0 / 1024));
    CHECK(frac(b[1], ByteClass::High) == doctest::Approx(127.0 * 4 / 1024));
    CHECK(frac(b[1], ByteClass::Printable) == doctest::Approx(94.0 * 4 / 1024));
    CHECK(frac(b[1], ByteClass::Whitespace) == doctest::Approx(6.0 * 4 / 1024));
    CHECK(frac(b[1], ByteClass::Control) == doctest::Approx(27.0 * 4 / 1024));
    CHECK(b[2].entropy == doctest::Approx(2.0));
    CHECK(frac(b[2], ByteClass::Whitespace) == doctest::Approx(0.25));
    CHECK(frac(b[2], ByteClass::Printable) == doctest::Approx(0.75));
    CHECK(b[3].entropy == doctest::Approx(1.0));
    CHECK(frac(b[3], ByteClass::High) == doctest::Approx(0.5));
    CHECK(frac(b[3], ByteClass::Full) == doctest::Approx(0.5));

    // Aggregation over two buckets (equal lengths -> plain mean).
    EntropyBucket a = entropy_aggregate(*r, 0, 2048);
    CHECK(a.done);
    CHECK(a.offset == 0);
    CHECK(a.length == 2048);
    CHECK(a.entropy == doctest::Approx(4.0));
    CHECK(frac(a, ByteClass::Zero) == doctest::Approx((1.0 + 4.0 / 1024) / 2));
    a = entropy_aggregate(*r, 3100, 3100);  // empty range -> the bucket holding begin
    CHECK(a.offset == 3072);
    CHECK(a.entropy == doctest::Approx(1.0));
    a = entropy_aggregate(*r, 1000, 1100);  // straddles buckets 0 and 1
    CHECK(a.offset == 0);
    CHECK(a.length == 2048);
}

TEST_CASE("entropy: tiny and empty documents") {
    EntropyJob job;
    auto r = run(job, snap_of(Bytes{1, 2, 3}));
    REQUIRE(r->buckets.size() == 3);
    CHECK(r->done == 3);
    for (const auto& b : r->buckets) CHECK(b.entropy == 0.0f);
    CHECK(frac(r->buckets[0], ByteClass::Control) == 1.0f);

    r = run(job, snap_of(Bytes{}));
    CHECK(r->buckets.empty());
    CHECK(r->done == 0);
    CHECK(entropy_aggregate(*r, 0, 10).done == false);

    r = run(job, nullptr);
    CHECK(r->buckets.empty());
}

TEST_CASE("entropy: big buckets are sampled with bounded reads") {
    // 1 MiB buckets, 64 KiB sample = 16 chunks of 4 KiB each.
    Bytes d(size_t(4) << 20);
    std::mt19937 rng(5);
    for (auto& v : d) v = uint8_t(rng());
    for (size_t i = 0; i < (size_t(1) << 20); ++i) d[i] = 0;  // bucket 0 all zeros
    EntropyJob job;
    EntropyOptions o;
    o.buckets = 4;
    o.sample_per_bucket = 64 << 10;
    auto r = run(job, snap_of(d), o);
    REQUIRE(r->buckets.size() == 4);
    for (const auto& b : r->buckets) {
        CHECK(b.sampled);
        CHECK(b.bytes_read == (64u << 10));
    }
    CHECK(r->bytes_read == 4u * (64u << 10));
    CHECK(r->buckets[0].entropy == 0.0f);
    CHECK(r->buckets[1].entropy > 7.9f);  // random data stays ~8 bits/byte when sampled
    CHECK(entropy_aggregate(*r, 0, 4u << 20).sampled);

    o.sample_per_bucket = 0;  // read everything
    r = run(job, snap_of(d), o);
    CHECK_FALSE(r->buckets[1].sampled);
    CHECK(r->bytes_read == d.size());
}

TEST_CASE("entropy: >4 GiB sparse file is sampled quickly") {
    TempDir t;
    const std::string p = path_join(t.path, "sparse.bin");
    const uint64_t size = 6ull << 30;
    make_sparse(p, size);
    auto doc = Document::open_file(p);
    REQUIRE(doc);
    REQUIRE(doc->size() == size);
    const uint64_t at = size / 256 * 200;  // start of bucket 200
    const char tag[] = "not zero";
    REQUIRE(doc->overwrite(at, reinterpret_cast<const uint8_t*>(tag), sizeof(tag)));

    EntropyJob job;
    EntropyOptions o;
    o.buckets = 256;               // 24 MiB buckets
    o.sample_per_bucket = 32 << 10;
    const auto t0 = std::chrono::steady_clock::now();
    auto r = run(job, doc->snapshot(), o);
    const auto secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    REQUIRE(r->buckets.size() == 256);
    CHECK(r->bucket_size == size / 256);
    CHECK(r->done == 256);
    CHECK(secs < 20.0);
    uint64_t db = 0, de = 0;
    const auto snap = doc->snapshot();  // keep it alive: snapshot() builds a new one per call
    const auto& src = snap->sources.at(0);
    if (src->data_range(0, db, de) && db == size) {  // the OS reports the holes: nothing is read
        CHECK(r->bytes_read == sizeof(tag));
        CHECK_FALSE(r->buckets[0].sampled);
        CHECK(r->buckets[0].hole_bytes == r->buckets[0].length);
    } else {
        CHECK(r->bytes_read == 256u * (32u << 10));  // bounded: 8 MiB of a 6 GiB file
        CHECK(r->buckets[0].sampled);
    }
    CHECK(r->buckets[0].entropy == 0.0f);
    CHECK(frac(r->buckets[0], ByteClass::Zero) == 1.0f);
    const size_t tagged = r->bucket_of(at);
    CHECK(tagged == 200);
    CHECK(r->buckets[tagged].offset == at);  // the first sample chunk covers the tag
    CHECK(r->buckets[tagged].entropy > 0.0f);
    CHECK(frac(r->buckets[tagged], ByteClass::Zero) < 1.0f);
}

TEST_CASE("entropy: unreadable regions mark buckets instead of aborting") {
    // Snapshot whose middle piece references a missing add chunk: those bytes read as unreadable.
    auto base = snap_of(Bytes(4000, 0x11));
    auto s = std::make_shared<Snapshot>(*base);
    s->pieces = {Piece{Piece::Add, 0, 0, 1000}, Piece{Piece::Add, 99, 0, 1500}, Piece{Piece::Add, 0, 0, 1500}};
    s->starts = {0, 1000, 2500};
    s->size_ = 4000;
    EntropyJob job;
    EntropyOptions o;
    o.buckets = 4;  // 1000 bytes each: good, bad, half bad, good
    auto r = run(job, s, o);
    REQUIRE(r->buckets.size() == 4);
    CHECK(r->done == 4);
    CHECK(r->io_error);
    CHECK(r->io_error_offset == 1000);
    CHECK_FALSE(r->buckets[0].unreadable);
    CHECK(r->buckets[1].unreadable);
    CHECK(r->buckets[1].bytes_read == 0);
    CHECK(r->buckets[2].unreadable);
    CHECK_FALSE(r->buckets[3].unreadable);
    CHECK(r->buckets[3].done);
    CHECK(frac(r->buckets[3], ByteClass::Control) == 1.0f);
    EntropyBucket a = entropy_aggregate(*r, 0, 4000);
    CHECK(a.unreadable);
    CHECK(a.entropy == 0.0f);
}

TEST_CASE("entropy: results are published progressively") {
    Bytes d(64 * 100);
    for (size_t i = 0; i < d.size(); ++i) d[i] = uint8_t(i * 7);
    HookGuard hook(0);  // the worker stops after publishing bucket 1
    EntropyJob job;
    EntropyOptions o;
    o.buckets = 64;
    o.publish_ms = 0;
    const uint64_t gen = job.generation();
    job.start(snap_of(d), o);
    std::shared_ptr<const EntropyResult> r;
    auto t0 = std::chrono::steady_clock::now();
    while (!(r = job.result()) || r->done < 1) {
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
        std::this_thread::yield();
    }
    CHECK(r->done == 1);
    CHECK_FALSE(r->finished);
    CHECK(job.running());
    CHECK(job.generation() == gen);
    CHECK(job.progress() > 0.0);
    CHECK(job.progress() < 1.0);
    REQUIRE(r->buckets.size() == 64);
    CHECK(r->buckets[0].done);
    CHECK_FALSE(r->buckets[1].done);     // pending
    CHECK(r->buckets[63].length == 100);  // layout is complete from the start
    CHECK(entropy_aggregate(*r, 200, 300).done == false);

    g_release = 31;  // ... and then after bucket 32
    while ((r = job.result())->done < 32) {
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
        std::this_thread::yield();
    }
    CHECK(r->done == 32);
    CHECK(r->buckets[31].done);
    CHECK_FALSE(r->buckets[32].done);
    g_release = UINT32_MAX;
    wait_for(job, gen);
    r = job.result();
    CHECK(r->finished);
    CHECK(r->done == 64);
}

TEST_CASE("entropy: cancel and restart") {
    Bytes d(64 * 100, 0x41);
    EntropyJob job;
    EntropyOptions o;
    o.buckets = 64;
    o.publish_ms = 0;
    {
        HookGuard hook(1);  // blocks after bucket 2
        const uint64_t gen = job.generation();
        job.start(snap_of(d), o);
        auto t0 = std::chrono::steady_clock::now();
        while (job.progress() < 2.0 / 64) {
            REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
            std::this_thread::yield();
        }
        job.cancel();
        g_release = UINT32_MAX;
        wait_for(job, gen);
        auto r = job.result();
        CHECK(r->finished);
        CHECK(r->cancelled);
        CHECK(r->done >= 2);
        CHECK(r->done < 64);
        CHECK_FALSE(job.running());
    }
    {
        // A new start supersedes a blocked run without waiting for it; only the new run publishes.
        HookGuard hook(0);  // blocks after bucket 1
        const uint64_t gen = job.generation();
        job.start(snap_of(d), o);
        auto t0 = std::chrono::steady_clock::now();
        while (job.progress() < 1.0 / 64) {
            REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
            std::this_thread::yield();
        }
        Bytes small(10, 0);
        job.start(snap_of(small), o);  // must not block on the gated run
        g_release = UINT32_MAX;
        wait_for(job, gen);
        auto r = job.result();
        CHECK(r->finished);
        CHECK_FALSE(r->cancelled);
        CHECK(r->doc_size == 10);
        CHECK(r->done == 10);
    }
    {
        EntropyJob other;  // destroyed while running: cancels + joins
        other.start(snap_of(Bytes(size_t(8) << 20, 0x5A)), o);
    }
}

TEST_CASE("entropy: a process address space skips holes; fully unmapped buckets stay unreadable") {
    hx_test::HoleyMem hm;
    for (size_t i = 0; i < hm.pg; ++i) hm.base[i] = uint8_t(i * 31 + 7);
    auto doc = hx_test::open_self();
    auto snap = doc->snapshot();
    EntropyJob job;
    const auto t0 = std::chrono::steady_clock::now();
    auto r = run(job, snap);  // 1024 sampled buckets over the whole address space
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
    REQUIRE(r->finished);
    CHECK(r->done == r->buckets.size());
    CHECK_FALSE(r->io_error);  // holes are not I/O errors
    CHECK(r->bytes_read <= uint64_t(r->buckets.size()) * EntropyOptions{}.sample_per_bucket);
    // The bucket holding our page samples its mapped part (it is not "unreadable from byte 0").
    const EntropyBucket& mine = r->buckets[r->bucket_of(hm.addr())];
    CHECK(mine.done);
    CHECK(mine.bytes_read > 0);
    CHECK(mine.unreadable);  // and it has holes
    // Bucket 0 holds the null page; some bucket of a 47-bit space is entirely unmapped.
    size_t empty = 0;
    for (const EntropyBucket& b : r->buckets)
        if (b.done && b.bytes_read == 0) {
            CHECK(b.unreadable);
            ++empty;
        }
    CHECK(empty > 0);
    CHECK(r->buckets[0].unreadable);
}

// ---- incremental rescan (EntropyJob::rescan) -----------------------------------------------------

namespace {

std::atomic<uint32_t> g_computed{0};
void count_hook(uint32_t) { g_computed.fetch_add(1); }
struct CountGuard {
    CountGuard() {
        g_computed = 0;
        EntropyJob::set_bucket_hook_for_tests(count_hook);
    }
    ~CountGuard() { EntropyJob::set_bucket_hook_for_tests(nullptr); }
};

std::shared_ptr<const EntropyResult> rerun(EntropyJob& job, std::shared_ptr<const Snapshot> s, EntropyOptions o) {
    const uint64_t gen = job.generation();
    job.rescan(std::move(s), o);
    wait_for(job, gen);
    auto r = job.result();
    REQUIRE(r);
    CHECK(r->finished);
    return r;
}

// Every bucket of `a` equals the one of a full scan `b`.
void check_same(const EntropyResult& a, const EntropyResult& b) {
    REQUIRE(a.buckets.size() == b.buckets.size());
    CHECK(a.done == b.done);
    for (size_t i = 0; i < a.buckets.size(); ++i) {
        CAPTURE(i);
        CHECK(a.buckets[i].offset == b.buckets[i].offset);
        CHECK(a.buckets[i].length == b.buckets[i].length);
        CHECK(a.buckets[i].done);
        CHECK(a.buckets[i].entropy == b.buckets[i].entropy);
        for (int c = 0; c < kByteClassCount; ++c) CHECK(a.buckets[i].class_frac[c] == b.buckets[i].class_frac[c]);
    }
}

}  // namespace

TEST_CASE("entropy: snapshot_changes compares stored bytes, not values") {
    using Ranges = std::vector<std::pair<uint64_t, uint64_t>>;
    Bytes d(1000);
    for (size_t i = 0; i < d.size(); ++i) d[i] = uint8_t(i * 13);
    auto doc = Document::create_from_bytes("a", d.data(), d.size());
    auto s0 = doc->snapshot();
    CHECK(snapshot_changes(*s0, *s0).empty());
    const uint8_t x[3] = {1, 2, 3};
    REQUIRE(doc->overwrite(400, x, 3));
    REQUIRE(doc->overwrite(403, x, 2));  // adjacent: merged
    REQUIRE(doc->overwrite(900, x, 1));
    CHECK(snapshot_changes(*s0, *doc->snapshot()) == Ranges{{400, 405}, {900, 901}});
    // Writing the same values again still counts (other storage): no byte is compared.
    REQUIRE(doc->overwrite(10, d.data() + 10, 1));
    CHECK(snapshot_changes(*s0, *doc->snapshot()) == Ranges{{10, 11}, {400, 405}, {900, 901}});
    REQUIRE(doc->insert(100, x, 2));  // other size: from the first change to the end
    CHECK(snapshot_changes(*s0, *doc->snapshot()) == Ranges{{10, 1002}});
    for (int k = 0; k < 5; ++k) REQUIRE(doc->undo());
    CHECK(snapshot_changes(*s0, *doc->snapshot()).empty());
    REQUIRE(doc->erase(990, 10));  // truncated: the remaining bytes are unchanged
    CHECK(snapshot_changes(*s0, *doc->snapshot()).empty());
    CHECK(snapshot_changes(*doc->snapshot(), *s0) == Ranges{{990, 1000}});
    // Same bytes in another document: everything differs.
    auto other = Document::create_from_bytes("b", d.data(), d.size());
    CHECK(snapshot_changes(*s0, *other->snapshot()) == Ranges{{0, 1000}});
}

TEST_CASE("entropy: rescan reads only the buckets an overwrite touched") {
    Bytes d(64 * 1000);
    std::mt19937 rng(11);
    for (auto& v : d) v = uint8_t(rng() % 7);
    auto doc = Document::create_from_bytes("t", d.data(), d.size());
    EntropyJob job;
    EntropyOptions o;
    o.buckets = 64;  // 1000 bytes each
    o.publish_ms = 0;
    CountGuard count;
    auto r = run(job, doc->snapshot(), o);
    CHECK(r->reused == 0);
    CHECK(g_computed.load() == 64);

    // Nothing changed: everything is reused, nothing is read.
    g_computed = 0;
    r = rerun(job, doc->snapshot(), o);
    CHECK(r->reused == 64);
    CHECK(r->done == 64);
    CHECK(g_computed.load() == 0);
    CHECK(r->bytes_read == 0);

    // Overwrite inside bucket 10 and across the bucket 20 / 21 edge.
    Bytes hi(300, 0xFF);
    REQUIRE(doc->overwrite(10100, hi.data(), 300));
    REQUIRE(doc->overwrite(20900, hi.data(), 200));
    g_computed = 0;
    r = rerun(job, doc->snapshot(), o);
    CHECK(r->reused == 61);  // buckets 10, 20, 21 (not the ones between the two edits)
    CHECK(g_computed.load() == 3);
    CHECK(r->bytes_read == 3000);
    CHECK(frac(r->buckets[10], ByteClass::Full) == doctest::Approx(0.3));
    CHECK(frac(r->buckets[21], ByteClass::Full) == doctest::Approx(0.1));
    EntropyJob fresh;
    check_same(*r, *run(fresh, doc->snapshot(), o));

    // Undo: the pieces of the first scan come back, but the base is now the edited scan.
    g_computed = 0;
    REQUIRE(doc->undo());
    r = rerun(job, doc->snapshot(), o);
    CHECK(g_computed.load() == 2);  // bucket 20 + 21
    check_same(*r, *run(fresh, doc->snapshot(), o));
}

TEST_CASE("entropy: rescan after an insert / delete rescans from the edit; a new layout rescans all") {
    Bytes d(63990);  // 64 buckets of 1000 bytes (the last one 990)
    for (size_t i = 0; i < d.size(); ++i) d[i] = uint8_t((i / 1000) * 3 + (i & 1));
    auto doc = Document::create_from_bytes("t", d.data(), d.size());
    EntropyJob job, fresh;
    EntropyOptions o;
    o.buckets = 64;
    CountGuard count;
    auto r = run(job, doc->snapshot(), o);
    REQUIRE(r->bucket_size == 1000);
    // The same bytes in another document (same layout): nothing is reused.
    auto copy = Document::create_from_bytes("c", d.data(), d.size());
    CHECK(rerun(job, copy->snapshot(), o)->reused == 0);
    CHECK(rerun(job, doc->snapshot(), o)->reused == 0);

    const uint8_t x[5] = {0x80, 0x81, 0x82, 0x83, 0x84};
    REQUIRE(doc->insert(30500, x, 5));  // 63995 bytes: same layout, buckets 30.. shifted
    g_computed = 0;
    r = rerun(job, doc->snapshot(), o);
    REQUIRE(r->bucket_size == 1000);
    CHECK(r->reused == 30);
    CHECK(g_computed.load() == 34);
    check_same(*r, *run(fresh, doc->snapshot(), o));

    REQUIRE(doc->erase(63000, 10));  // delete near the end: only the last bucket
    g_computed = 0;
    r = rerun(job, doc->snapshot(), o);
    CHECK(r->reused == 63);
    CHECK(g_computed.load() == 1);
    check_same(*r, *run(fresh, doc->snapshot(), o));

    Bytes more(5000, 0x41);
    REQUIRE(doc->insert(0, more.data(), more.size()));  // bucket size changes: everything again
    g_computed = 0;
    r = rerun(job, doc->snapshot(), o);
    CHECK(r->bucket_size != 1000);
    CHECK(r->reused == 0);
    CHECK(g_computed.load() == r->buckets.size());
    check_same(*r, *run(fresh, doc->snapshot(), o));

    // Other sampling options: nothing is reused.
    EntropyOptions o2 = o;
    o2.sample_per_bucket = 512;
    r = rerun(job, doc->snapshot(), o2);
    CHECK(r->reused == 0);
}

TEST_CASE("entropy: rescan of a partial (superseded) result reuses only its computed buckets") {
    Bytes d(64 * 100, 0x30);
    auto doc = Document::create_from_bytes("t", d.data(), d.size());
    EntropyJob job;
    EntropyOptions o;
    o.buckets = 64;
    o.publish_ms = 0;
    {
        HookGuard hook(4);  // blocks after bucket 5 (published)
        job.start(doc->snapshot(), o);
        auto t0 = std::chrono::steady_clock::now();
        std::shared_ptr<const EntropyResult> p;
        while (!(p = job.result()) || p->done < 5) {
            REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
            std::this_thread::yield();
        }
        const uint64_t gen = job.generation();
        job.rescan(doc->snapshot(), o);  // supersedes the blocked run
        g_release = UINT32_MAX;
        wait_for(job, gen);
    }
    auto r = job.result();
    REQUIRE(r->finished);
    CHECK(r->reused >= 5);
    CHECK(r->reused < 64);
    CHECK(r->done == 64);
    EntropyJob fresh;
    check_same(*r, *run(fresh, doc->snapshot(), o));
}

TEST_CASE("entropy: process memory is always rescanned in full") {
    hx_test::HoleyMem hm;
    auto doc = hx_test::open_self();
    EntropyJob job;
    EntropyOptions o;
    o.buckets = 16;
    o.sample_per_bucket = 4096;
    auto r = run(job, doc->snapshot(), o);
    REQUIRE(r->done == 16);
    r = rerun(job, doc->snapshot(), o);
    CHECK(r->reused == 0);
    CHECK(r->done == 16);
}

namespace {

// A sparse file of `size` bytes whose holes the OS reports (else false: the test is skipped).
bool make_reported_sparse(const std::string& p, uint64_t size) {
#ifdef _WIN32
    HANDLE h = CreateFileW(utf8_to_wide(p).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD got = 0;
    const bool sparse = DeviceIoControl(h, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &got, nullptr) != 0;
    CloseHandle(h);
    if (!sparse) return false;
    auto f = OsFile::open(p, OsFile::Mode::ReadWrite);
#else
    auto f = OsFile::open(p, OsFile::Mode::CreateTruncate);
#endif
    if (!f || !f->truncate(size)) return false;
    uint64_t b = 0, e = 0;
    return f->data_range(0, b, e) && b == size && e == size;
}

bool write_at(const std::string& p, uint64_t off, const Bytes& b) {
    auto f = OsFile::open(p, OsFile::Mode::ReadWrite);
    return f && f->write_at(off, b.data(), b.size());
}

Bytes random_bytes(size_t n, unsigned seed) {
    Bytes b(n);
    std::mt19937 rng(seed);
    for (auto& v : b) v = uint8_t(1 + rng() % 255);  // never 0
    return b;
}

}  // namespace

TEST_CASE("entropy: a 4 KiB block inside a 1 TiB sparse file shows up") {
    TempDir t;
    const std::string p = path_join(t.path, "huge.bin");
    const uint64_t size = 1ull << 40;
    if (!make_reported_sparse(p, size)) {
        MESSAGE("skipped: no sparse file support with reported holes here");
        return;
    }
    const uint64_t at = 777ull * (1ull << 30) + 123456;  // inside bucket 777 (1 GiB buckets)
    REQUIRE(write_at(p, at, random_bytes(4096, 9)));
    auto doc = Document::open_file(p);
    REQUIRE(doc);
    const auto snap = doc->snapshot();

    // The data ranges: just the block (the filesystem may allocate a little around it).
    const auto ranges = snapshot_data_ranges(*snap, 0, size);
    REQUIRE(ranges.size() == 1);
    CHECK(ranges[0].first <= at);
    CHECK(ranges[0].second >= at + 4096);
    CHECK(ranges[0].second - ranges[0].first <= (1u << 20));
    CHECK(snapshot_data_ranges(*snap, 0, at - (1u << 20)).empty());

    EntropyJob job;
    auto r = run(job, snap);  // default options: 1024 buckets, 256 KiB sample each
    REQUIRE(r->buckets.size() == 1024);
    const size_t k = r->bucket_of(at);
    REQUIRE(k == 777);
    const EntropyBucket& b = r->buckets[k];
    CHECK_FALSE(b.sampled);  // its data fits the budget: read in full
    CHECK(b.nonzero);
    CHECK(b.peak > 2.9f);    // the densest 4 KiB chunk holds random bytes
    CHECK(entropy_spot(b));
    CHECK(b.hole_bytes + b.bytes_read == b.length);
    CHECK(b.class_frac[int(ByteClass::Zero)] < 1.0f);
    CHECK(r->bytes_read <= (1u << 20));  // only the allocated range was read
    for (size_t i : {size_t(0), size_t(776), size_t(778), size_t(1023)}) {
        INFO(i);
        CHECK(r->buckets[i].done);
        CHECK(r->buckets[i].hole_bytes == r->buckets[i].length);
        CHECK(r->buckets[i].entropy == 0.0f);
        CHECK(r->buckets[i].class_frac[int(ByteClass::Zero)] == 1.0f);
        CHECK_FALSE(entropy_spot(r->buckets[i]));
    }
    // A minimap row spanning many buckets still sees it.
    const EntropyBucket a = entropy_aggregate(*r, 512ull << 30, 1024ull << 30);
    CHECK(entropy_spot(a));
    CHECK(a.hole_bytes > 0);
    CHECK(a.peak == b.peak);
}

TEST_CASE("entropy: sampling covers every data range of a sparse bucket") {
    TempDir t;
    const std::string p = path_join(t.path, "spots.bin");
    const uint64_t size = 64ull << 20;
    if (!make_reported_sparse(p, size)) {
        MESSAGE("skipped: no sparse file support with reported holes here");
        return;
    }
    // 40 blocks of 64 KiB, 1 MiB apart: 2.5 MiB of data in one 64 MiB bucket, more than the
    // budget. Evenly spaced chunks over the data alone would miss some blocks.
    for (uint64_t i = 0; i < 40; ++i)
        REQUIRE(write_at(p, i * (1u << 20) + (512u << 10), random_bytes(64u << 10, unsigned(i))));
    auto doc = Document::open_file(p);
    REQUIRE(doc);
    const auto snap = doc->snapshot();
    const auto ranges = snapshot_data_ranges(*snap, 0, size);
    REQUIRE(ranges.size() == 40);
    EntropyOptions o;
    o.buckets = 1;
    o.sample_per_bucket = 64 << 10;  // 16 chunks for 40 ranges: every range still gets one
    EntropyJob job;
    auto r = run(job, snap, o);
    REQUIRE(r->buckets.size() == 1);
    const EntropyBucket& b = r->buckets[0];
    CHECK(b.sampled);
    CHECK(b.bytes_read == 40u * 4096u);  // one chunk per range (16 spread + 24 more)
    CHECK(b.hole_bytes == size - 40u * (64u << 10));
    // The sampled data stands for 2.5 MiB, the holes for the rest: mostly zeros.
    CHECK(b.class_frac[int(ByteClass::Zero)] > 0.9f);
    CHECK(b.class_frac[int(ByteClass::Zero)] < 0.98f);
    CHECK(b.peak > 7.5f);

    // An edit inside a hole is data too (it lives in the add buffer, not the file).
    const uint8_t x = 0x55;
    REQUIRE(doc->overwrite(100, &x, 1));
    const auto edited = snapshot_data_ranges(*doc->snapshot(), 0, 2u << 20);
    REQUIRE(edited.size() == 3);
    CHECK(edited[0] == std::make_pair(uint64_t(100), uint64_t(101)));
    CHECK(edited[1].first <= (512u << 10));
    CHECK(edited[2].first >= (1u << 20));
    // The cap: the last of max_ranges ranges extends to the end (a superset).
    const auto capped = snapshot_data_ranges(*snap, 0, size, 4);
    REQUIRE(capped.size() == 4);
    CHECK(capped[2] == ranges[2]);
    CHECK(capped[3].first == ranges[3].first);
    CHECK(capped[3].second == size);
}

TEST_CASE("entropy: a small dense region in zeros is a spot (peak / nonzero), also without holes") {
    Bytes d(size_t(1) << 20, 0);
    const Bytes noise = random_bytes(4096, 3);
    std::copy(noise.begin(), noise.end(), d.begin() + (300 << 10));
    d[900 << 10] = 1;  // a lone byte far away
    EntropyOptions o;
    o.buckets = 4;  // 256 KiB buckets, read in full
    o.sample_per_bucket = 0;
    EntropyJob job;
    auto r = run(job, snap_of(d), o);
    REQUIRE(r->buckets.size() == 4);
    const EntropyBucket& dense = r->buckets[1];
    CHECK(dense.entropy < 1.0f);  // the average hides it
    CHECK(dense.peak > 7.5f);
    CHECK(entropy_spot(dense));
    CHECK_FALSE(entropy_spot(r->buckets[0]));  // all zero
    CHECK_FALSE(r->buckets[0].nonzero);
    CHECK(r->buckets[3].nonzero);  // the lone byte
    CHECK(entropy_spot(r->buckets[3]));
    CHECK(r->buckets[3].hole_bytes == 0);

    // Uniform data is no spot, whatever its entropy.
    const Bytes rnd = random_bytes(size_t(1) << 20, 4);
    r = run(job, snap_of(rnd), o);
    for (const EntropyBucket& b : r->buckets) {
        CHECK(b.peak > 7.9f);
        CHECK_FALSE(entropy_spot(b));
    }
}

// ---- refinement of all-zero sampled buckets, refresh ----------------------------------------------

namespace {

// Polls the job's latest result until `pred` holds (fails after 60 s).
template <class Pred>
std::shared_ptr<const EntropyResult> wait_result(const EntropyJob& job, Pred pred) {
    auto t0 = std::chrono::steady_clock::now();
    for (;;) {
        auto r = job.result();
        if (r && pred(*r)) return r;
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(60));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

// 4 MiB of zeros in 1 MiB buckets sampled 64 KiB each (16 chunks, stride 68 KiB = 17 slots of
// 4 KiB per gap) with 8 non-zero bytes in bucket 2, in a slot between two of the scan's chunks.
constexpr uint64_t kRefStride = ((1u << 20) - 4096) / 15;
constexpr uint64_t kRefSpot = (2u << 20) + 5 * kRefStride + 11 * 4096 + 100;
Bytes refine_data() {
    Bytes d(size_t(4) << 20, 0);
    for (size_t i = 0; i < 8; ++i) d[size_t(kRefSpot) + i] = uint8_t(0x5A + i);
    return d;
}
EntropyOptions refine_opts(uint32_t passes) {
    EntropyOptions o;
    o.buckets = 4;
    o.sample_per_bucket = 64 << 10;
    o.refine_passes = passes;
    o.refine_pause_ms = 0;
    return o;
}

}  // namespace

TEST_CASE("entropy: refinement finds a small region between the samples of an allocated zero area") {
    REQUIRE(kRefStride == 17u * 4096u);
    const auto snap = snap_of(refine_data());
    EntropyJob job;
    // Off (the default): the scan's samples miss the bytes, and nothing reads more.
    auto r = run(job, snap, refine_opts(0));
    REQUIRE(r->buckets.size() == 4);
    CHECK(r->buckets[2].sampled);
    CHECK_FALSE(r->buckets[2].nonzero);
    CHECK_FALSE(entropy_spot(r->buckets[2]));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(job.result()->refine_pass == 0);
    CHECK(job.result()->bytes_read == 4u * (64u << 10));

    // On: the gaps are read slot by slot until the bytes show.
    r = run(job, snap, refine_opts(1000));
    if (r->refine_pass == 0) {  // (refinement may have published its first pass already)
        CHECK_FALSE(r->buckets[2].nonzero);  // the scan itself is unchanged
        CHECK(r->bytes_read == 4u * (64u << 10));
    }
    r = wait_result(job, [](const EntropyResult& x) { return x.buckets[2].nonzero; });
    const EntropyBucket& b = r->buckets[2];
    CHECK(entropy_spot(b));
    CHECK(b.peak > 0.0f);
    CHECK(b.entropy > 0.0f);
    CHECK(frac(b, ByteClass::Zero) < 1.0f);
    CHECK(frac(b, ByteClass::Zero) > 0.99f);
    CHECK(b.refined > 0);
    CHECK(b.refined < 32);
    CHECK(b.bytes_read < b.length);
    CHECK(r->refine_pass >= 1);
    CHECK(entropy_spot(entropy_aggregate(*r, 0, 4u << 20)));  // a row of all buckets shows it
    // The all-zero buckets go on until every slot is read; the found one stops.
    r = wait_result(job, [](const EntropyResult& x) {
        return x.buckets[0].refined == UINT32_MAX && x.buckets[1].refined == UINT32_MAX &&
               x.buckets[3].refined == UINT32_MAX;
    });
    for (size_t i : {size_t(0), size_t(1), size_t(3)}) {
        INFO(i);
        const EntropyBucket& z = r->buckets[i];
        CHECK_FALSE(z.nonzero);
        CHECK(z.bytes_read <= z.length);
        CHECK(z.bytes_read >= z.length - 15);  // all but the scan grid's rounding remainder
        CHECK(z.entropy == 0.0f);
        CHECK(frac(z, ByteClass::Zero) == 1.0f);
    }
    CHECK(r->buckets[2].refined == b.refined);
    CHECK(r->bytes_read <= (4u << 20));
}

TEST_CASE("entropy: refinement pauses between passes and is cancelled by a new run / the destructor") {
    const auto snap = snap_of(refine_data());
    EntropyOptions o = refine_opts(1000);
    o.refine_pause_ms = 60000;
    const auto t0 = std::chrono::steady_clock::now();
    {
        EntropyJob job;
        run(job, snap, o);
        auto r = wait_result(job, [](const EntropyResult& x) { return x.refine_pass >= 1; });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        CHECK(job.result()->refine_pass == 1);  // pausing
        CHECK_FALSE(job.running());
        // A new run supersedes the paused one right away.
        Bytes small(64 * 1024, 7);
        r = run(job, snap_of(small), refine_opts(0));
        CHECK(r->doc_size == small.size());
        run(job, snap, o);
        wait_result(job, [](const EntropyResult& x) { return x.refine_pass >= 1; });
    }  // the destructor cancels the pause
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
}

TEST_CASE("entropy: rescans keep refined buckets; refresh recomputes the given ranges, also of process memory") {
    auto d = refine_data();
    auto doc = Document::create_from_bytes("z", d.data(), d.size());
    EntropyJob job;
    run(job, doc->snapshot(), refine_opts(1000));
    wait_result(job, [](const EntropyResult& x) { return x.buckets[2].nonzero; });
    const uint8_t x = 0;
    REQUIRE(doc->overwrite(10, &x, 1));  // bucket 0
    auto r = rerun(job, doc->snapshot(), refine_opts(0));  // no refinement racing the checks
    CHECK(r->reused == 3);
    CHECK(r->buckets[2].nonzero);  // kept, not sampled again
    CHECK(r->buckets[0].refined == 0);  // recomputed

    // Refresh of bucket 2's range: recomputed (without refinement the samples miss the bytes again).
    const uint64_t gen = job.generation();
    job.refresh(doc->snapshot(), {{kRefSpot, kRefSpot + 1}}, refine_opts(0));
    wait_for(job, gen);
    r = job.result();
    CHECK(r->reused == 3);
    CHECK_FALSE(r->buckets[2].nonzero);
    CHECK(r->buckets[2].refined == 0);

    // Process memory: a rescan reads everything, a refresh only the ranges given.
    hx_test::HoleyMem hm;
    auto self = hx_test::open_self();
    EntropyOptions o;
    o.buckets = 16;
    o.sample_per_bucket = 4096;
    r = run(job, self->snapshot(), o);
    REQUIRE(r->done == 16);
    const uint64_t g2 = job.generation();
    const EntropyBucket& b5 = r->buckets[5];
    job.refresh(self->snapshot(), {{b5.offset + 7, b5.offset + 8}, {r->buckets[9].offset, r->buckets[11].offset}}, o);
    wait_for(job, g2);
    r = job.result();
    CHECK(r->reused == 13);  // 5, 9, 10 recomputed
    CHECK(r->done == 16);
    CHECK(rerun(job, self->snapshot(), o)->reused == 0);
}
