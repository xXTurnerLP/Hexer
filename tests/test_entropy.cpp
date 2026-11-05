// Entropy overview: byte classes, Shannon entropy, bucket layout, sampling and the background job.
#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <filesystem>
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
    CHECK(r->bytes_read == 256u * (32u << 10));  // bounded: 8 MiB of a 6 GiB file
    CHECK(secs < 20.0);
    CHECK(r->buckets[0].sampled);
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
