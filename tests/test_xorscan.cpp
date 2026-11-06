// Tests for core/xorscan: transforms, known-plaintext scan (1-byte XOR / ADD / ROL, multi-byte XOR
// keys, block edges, EOF, false positives, limits), key guessing, the undoable apply, the job.
#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "core/document.h"
#include "core/util.h"
#include "core/xorscan.h"
#include "holey_mem.h"

using namespace hx;

namespace {

using Bytes = std::vector<uint8_t>;
constexpr uint64_t kBlk = kXorBlock;

Bytes bytes_of(const std::string& s) { return Bytes(s.begin(), s.end()); }

std::shared_ptr<const Snapshot> snap_of(const Bytes& b) {
    auto doc = Document::create_from_bytes("test", b.data(), b.size());
    REQUIRE(doc);
    return doc->snapshot();
}

Bytes random_bytes(size_t n, uint32_t seed) {
    std::mt19937 rng(seed);
    Bytes b(n);
    for (auto& v : b) v = uint8_t(rng());
    return b;
}

// Writes encode(plain, t, key) at `at`, keyed by absolute offset (the module's convention).
void plant(Bytes& d, uint64_t at, const Bytes& plain, XorTransform t, const Bytes& key) {
    Bytes enc = apply_transform(plain, t, key, at, false);
    std::memcpy(d.data() + at, enc.data(), enc.size());
}

XorScanResult scan(const Bytes& d, const Bytes& plain, XorScanOptions o = {}, uint64_t begin = 0,
                   uint64_t end = UINT64_MAX) {
    auto s = snap_of(d);
    XorScanResult r;
    scan_xor(*s, begin, end, plain, o, r);
    return r;
}

XorHit hit(uint64_t off, XorTransform t, Bytes key, uint32_t phase = 0) { return XorHit{off, t, std::move(key), phase}; }

void check_hits(const std::vector<XorHit>& got, const std::vector<XorHit>& want) {
    REQUIRE(got.size() == want.size());
    for (size_t i = 0; i < got.size(); ++i) {
        CAPTURE(i);
        CHECK(got[i].offset == want[i].offset);
        CHECK(int(got[i].transform) == int(want[i].transform));
        CHECK(got[i].key == want[i].key);
        CHECK(got[i].phase == want[i].phase);
    }
}

std::shared_ptr<const XorScanJob::Result> wait_for(XorScanJob& job, uint64_t gen) {
    for (int i = 0; i < 20000 && job.generation() == gen; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    REQUIRE(job.generation() > gen);
    return job.result();
}

}  // namespace

TEST_CASE("xorscan: transforms round-trip and describe") {
    const Bytes p = bytes_of("Hello, World! \x01\x80\xFF");
    struct Case {
        XorTransform t;
        Bytes key;
    };
    const Case cases[] = {{XorTransform::Xor, {0x5A}}, {XorTransform::Add, {0xFD}}, {XorTransform::Rol, {3}},
                          {XorTransform::XorKey, bytes_of("KEY")}};
    for (const Case& c : cases) {
        const XorTransform t = c.t;
        const Bytes& key = c.key;
        const std::string name = transform_name(t);
        CAPTURE(name);
        const Bytes e = apply_transform(p, t, key, 5, false);
        CHECK(e != p);
        CHECK(apply_transform(e, t, key, 5, true) == p);
    }
    CHECK(apply_transform(Bytes{0x10, 0xFF}, XorTransform::Add, {3}, 0, false) == Bytes{0x13, 0x02});
    CHECK(apply_transform(Bytes{0x81}, XorTransform::Rol, {1}, 0, false) == Bytes{0x03});
    CHECK(apply_transform(Bytes{0x03}, XorTransform::Rol, {1}, 0, true) == Bytes{0x81});
    // XorKey: byte i uses key[(phase + i) % L].
    CHECK(apply_transform(Bytes{0, 0, 0, 0}, XorTransform::XorKey, {1, 2, 3}, 2, false) == Bytes{3, 1, 2, 3});
    CHECK(apply_transform(Bytes{7}, XorTransform::Xor, {}, 0, false) == Bytes{7});  // empty key: no-op

    CHECK(describe_key(XorTransform::Xor, {0x5A}) == "XOR 0x5A");
    CHECK(describe_key(XorTransform::Add, {0x03}) == "ADD 0x03 (SUB 0xFD)");
    CHECK(describe_key(XorTransform::Rol, {3}) == "ROL 3 (ROR 5)");
    CHECK(describe_key(XorTransform::XorKey, bytes_of("KEY")) == "XOR key 4B 45 59 \"KEY\"");
    CHECK(describe_key(XorTransform::XorKey, {0x01, 0xAB}) == "XOR key 01 AB");
}

TEST_CASE("xorscan: parse_plaintext") {
    Bytes b;
    CHECK(parse_plaintext("PE\\0\\0", false, b));
    CHECK(b == Bytes{'P', 'E', 0, 0});
    CHECK(parse_plaintext("\\x89PNG\\r\\n", false, b));
    CHECK(b == Bytes{0x89, 'P', 'N', 'G', '\r', '\n'});
    CHECK(parse_plaintext("a\\\\b\\x4", false, b));
    CHECK(b == Bytes{'a', '\\', 'b', 4});
    CHECK(parse_plaintext("4D 5A 90", true, b));
    CHECK(b == Bytes{0x4D, 0x5A, 0x90});
    std::string err;
    CHECK_FALSE(parse_plaintext("bad\\q", false, b, &err));
    CHECK_FALSE(err.empty());
    CHECK_FALSE(parse_plaintext("trailing\\", false, b));
    CHECK_FALSE(parse_plaintext("\\xZZ", false, b));
    CHECK_FALSE(parse_plaintext("zz", true, b));
}

TEST_CASE("xorscan: planted copies at block edges and EOF are found once with their keys") {
    const Bytes plain = bytes_of("This program");  // 12 bytes: random matches are ~2^-88 per offset
    Bytes d = random_bytes(size_t(4 * kBlk + 4096), 7);
    const uint64_t eof = d.size() - plain.size();
    plant(d, 100, plain, XorTransform::Xor, {0x5A});
    plant(d, 5000, plain, XorTransform::XorKey, bytes_of("KEY"));
    plant(d, kBlk - 5, plain, XorTransform::Add, {0x03});           // crosses the first block edge
    plant(d, 2 * kBlk - 1, plain, XorTransform::Rol, {3});          // starts on the last byte of a block
    plant(d, 3 * kBlk - 6, plain, XorTransform::Xor, {0xFF});
    plant(d, 4 * kBlk - 7, plain, XorTransform::XorKey, bytes_of("Hexer!"));
    plant(d, eof, plain, XorTransform::Add, {0xFF});                // SUB 1, ends at EOF

    XorScanOptions o;
    o.xor_multi = true;
    auto r = scan(d, plain, o);
    CHECK_FALSE(r.truncated);
    CHECK_FALSE(r.cancelled);
    CHECK_FALSE(r.io_error);
    CHECK(r.end == d.size());
    CHECK(r.plaintext_len == plain.size());
    check_hits(r.hits, {
                           hit(100, XorTransform::Xor, {0x5A}),
                           hit(5000, XorTransform::XorKey, bytes_of("KEY"), uint32_t(5000 % 3)),
                           hit(kBlk - 5, XorTransform::Add, {0x03}),
                           hit(2 * kBlk - 1, XorTransform::Rol, {3}),
                           hit(3 * kBlk - 6, XorTransform::Xor, {0xFF}),
                           hit(4 * kBlk - 7, XorTransform::XorKey, bytes_of("Hexer!"), uint32_t((4 * kBlk - 7) % 6)),
                           hit(eof, XorTransform::Add, {0xFF}),
                       });

    // Options switch transforms off; a range clips matches (they must lie fully inside).
    o = {};
    o.add8 = o.rol = false;
    check_hits(scan(d, plain, o).hits, {hit(100, XorTransform::Xor, {0x5A}), hit(3 * kBlk - 6, XorTransform::Xor, {0xFF})});
    o = {};
    check_hits(scan(d, plain, o, kBlk - 5, kBlk + 7).hits, {hit(kBlk - 5, XorTransform::Add, {0x03})});
    CHECK(scan(d, plain, o, kBlk - 4, kBlk + 7).hits.empty());
    CHECK(scan(d, plain, o, kBlk - 5, kBlk + 6).hits.empty());
    // A multi-byte key needs n >= 2L and n >= L+4: with max_key_len 2 the 3- and 6-byte keys are not found.
    o.xor8 = o.add8 = o.rol = false;
    o.xor_multi = true;
    o.max_key_len = 2;
    CHECK(scan(d, plain, o).hits.empty());
}

TEST_CASE("xorscan: no false positives on random data") {
    XorScanOptions o;
    o.xor_multi = true;
    // 4 bytes: each 1-byte transform matches by chance with p = 2^-24 per offset.
    CHECK(scan(random_bytes(size_t(1) << 20, 11), bytes_of("MZ\x90\x01"), o).hits.empty());
    // 8 bytes (multi-byte keys up to 4 bytes) over more than two blocks.
    CHECK(scan(random_bytes(size_t(2 * kBlk + 12345), 12), bytes_of(std::string("PE\x00\x00L\x01\x03\x00", 8)), o).hits.empty());
}

TEST_CASE("xorscan: identities, ambiguities and limits") {
    XorScanOptions o;
    o.xor_multi = true;
    // Plain occurrences and identity transforms are not reported.
    Bytes d = bytes_of(std::string("....This program....", 20));
    CHECK(scan(d, bytes_of("This program"), o).hits.empty());
    Bytes z(64, 0);
    CHECK(scan(z, Bytes(8, 0), o).hits.empty());  // XOR 0, ROL of zeros, constant / zero keys
    // A 1-byte XOR copy is not reported again as a multi-byte key; XOR 0x80 == ADD 0x80.
    Bytes e(40, 0x11);
    plant(e, 10, bytes_of("This program"), XorTransform::Xor, {0x80});
    check_hits(scan(e, bytes_of("This program"), o).hits,
               {hit(10, XorTransform::Xor, {0x80}), hit(10, XorTransform::Add, {0x80})});
    // Short plaintexts match a lot: capped.
    o.max_results = 100;
    auto r = scan(random_bytes(size_t(1) << 20, 3), bytes_of("MZ"), o);
    CHECK(r.truncated);
    CHECK(r.hits.size() == 100);
    CHECK(scan(d, Bytes{}, o).hits.empty());
    CHECK(scan(Bytes{1, 2}, bytes_of("abc"), o).hits.empty());  // plaintext longer than the data
}

TEST_CASE("xorscan: multi-byte key recovery from a whole-file XOR") {
    const std::string stub = "This program cannot be run in DOS mode.";
    Bytes d = random_bytes(65536, 21);
    std::memcpy(d.data() + 777, stub.data(), stub.size());
    const Bytes key = bytes_of("SECRET");
    d = apply_transform(d, XorTransform::XorKey, key, 0, false);  // the whole buffer from offset 0
    XorScanOptions o;
    o.xor8 = o.add8 = o.rol = false;
    o.xor_multi = true;
    auto r = scan(d, bytes_of(stub), o);
    check_hits(r.hits, {hit(777, XorTransform::XorKey, key, uint32_t(777 % 6))});  // not again as a 12-byte key
    // Decoding the hit with its key and phase gives the plaintext back.
    Bytes at(d.begin() + 777, d.begin() + 777 + ptrdiff_t(stub.size()));
    CHECK(apply_transform(at, XorTransform::XorKey, r.hits[0].key, r.hits[0].phase, true) == bytes_of(stub));
    o.max_key_len = 5;
    CHECK(scan(d, bytes_of(stub), o).hits.empty());
}

TEST_CASE("xorscan: key_guess ranks the key of zero-heavy data first") {
    std::mt19937 rng(5);
    Bytes plain(8192, 0);
    for (auto& v : plain)
        if (rng() % 4 == 0) v = uint8_t(rng());  // ~75% zeros
    const Bytes key = bytes_of("SECRET");
    const Bytes d = apply_transform(plain, XorTransform::XorKey, key, 0, false);
    auto c = key_guess(d.data(), d.size());
    REQUIRE_FALSE(c.empty());
    CHECK(c[0].key == key);
    CHECK(c[0].score > 0.7);
    for (size_t i = 1; i < c.size(); ++i) {
        CHECK(c[i].score <= c[0].score);
        CHECK(c[i].key.size() != 12);  // "SECRETSECRET" repeats the 6-byte key: dropped
    }
    // A slice at an unaligned offset still reports the key in the absolute convention.
    c = key_guess(d.data() + 1001, d.size() - 1001, 1001);
    REQUIRE_FALSE(c.empty());
    CHECK(c[0].key == key);
    // 1-byte XOR, text-like plaintext with ' ' as the dominant byte.
    Bytes text = bytes_of(std::string(200, ' ') + "a few words between many spaces" + std::string(100, ' '));
    text = apply_transform(text, XorTransform::Xor, {0x42}, 0, false);
    c = key_guess(text.data(), text.size(), 0, ' ');
    REQUIRE_FALSE(c.empty());
    CHECK(c[0].key == Bytes{0x42});
    CHECK(key_guess(d.data(), 1).empty());  // needs 2 bytes per column
    CHECK(key_guess(d.data(), 5, 0, 0, 16).size() == 2);  // L = 1, 2
}

TEST_CASE("xorscan: apply to a document is one undo step") {
    const Bytes orig = bytes_of("0123456789abcdefghij");
    auto doc = Document::create_from_bytes("t", orig.data(), orig.size());
    REQUIRE(doc);
    const Bytes key = bytes_of("KEY");
    std::string err;
    REQUIRE(apply_transform(*doc, 4, 10, XorTransform::XorKey, key, 4 % 3, false, &err));
    Bytes got(orig.size());
    doc->read(0, got.data(), got.size());
    Bytes want = orig;
    for (size_t i = 4; i < 14; ++i) want[i] ^= key[i % 3];
    CHECK(got == want);
    CHECK(doc->undo_stack().size() == 1);
    CHECK(doc->undo_stack().back().label == "Encode XOR key 4B 45 59 \"KEY\"");
    // Decoding (ADD) and clamping at EOF.
    REQUIRE(apply_transform(*doc, 18, 100, XorTransform::Add, {1}, 0, true, &err, "Decode test"));
    doc->read(0, got.data(), got.size());
    CHECK(got[18] == uint8_t('i' - 1));
    CHECK(got[19] == uint8_t('j' - 1));
    CHECK(doc->undo_stack().back().label == "Decode test");
    REQUIRE(doc->undo());
    REQUIRE(doc->undo());
    doc->read(0, got.data(), got.size());
    CHECK(got == orig);
    // Rejections.
    CHECK_FALSE(apply_transform(*doc, 0, 0, XorTransform::Xor, {1}, 0, true, &err));
    CHECK_FALSE(apply_transform(*doc, 0, 4, XorTransform::Xor, {}, 0, true, &err));
    CHECK_FALSE(apply_transform(*doc, 0, 20, XorTransform::Xor, {1}, 0, true, &err, {}, 10));
    CHECK(err.find("at most") != std::string::npos);
    doc->set_read_only(true);
    CHECK_FALSE(apply_transform(*doc, 0, 4, XorTransform::Xor, {1}, 0, true, &err));
    CHECK(doc->undo_stack().empty());

    // Larger than one 1 MiB chunk: still one step, key phase continues across chunks.
    Bytes big = random_bytes((size_t(3) << 20) + 17, 9);
    auto d2 = Document::create_from_bytes("big", big.data(), big.size());
    REQUIRE(apply_transform(*d2, 5, big.size() - 5, XorTransform::XorKey, bytes_of("SECRET"), 5, true));
    CHECK(d2->undo_stack().size() == 1);
    Bytes back(big.size());
    d2->read(0, back.data(), back.size());
    Bytes want_big = apply_transform(big, XorTransform::XorKey, bytes_of("SECRET"), 0, true);
    std::memcpy(want_big.data(), big.data(), 5);  // before the range: unchanged
    CHECK(back == want_big);
}

TEST_CASE("xorscan: cancel and unreadable bytes") {
    Bytes d(1000, 0x11);
    plant(d, 10, bytes_of("abcdef"), XorTransform::Xor, {0x5A});
    auto s = snap_of(d);
    std::atomic<bool> cancel{true};
    XorScanResult r;
    scan_xor(*s, 0, UINT64_MAX, bytes_of("abcdef"), XorScanOptions{}, r, &cancel);
    CHECK(r.cancelled);
    CHECK(r.hits.empty());

    // Middle piece references a missing add chunk: its bytes are unreadable (like a bad sector).
    auto bad = std::make_shared<Snapshot>(*s);
    bad->pieces = {Piece{Piece::Add, 0, 0, 1000}, Piece{Piece::Add, 99, 0, 500}};
    bad->starts = {0, 1000};
    bad->size_ = 1500;
    scan_xor(*bad, 0, UINT64_MAX, bytes_of("abcdef"), XorScanOptions{}, r);
    CHECK(r.io_error);
    CHECK(r.io_error_offset == 1000);
    check_hits(r.hits, {hit(10, XorTransform::Xor, {0x5A})});
}

TEST_CASE("XorScanJob: results, restart, cancel") {
    const Bytes plain = bytes_of("known plaintext");
    Bytes d = random_bytes(size_t(3 * kBlk), 33);
    for (uint64_t at = 1000; at + 64 < d.size(); at += 1 << 20) plant(d, at, plain, XorTransform::Xor, {0x77});
    auto s = snap_of(d);
    XorScanJob job;
    CHECK(job.result() == nullptr);
    CHECK_FALSE(job.running());
    job.start(s, 0, UINT64_MAX, plain, XorScanOptions{});
    auto r = wait_for(job, 0);
    REQUIRE(r);
    CHECK_FALSE(job.running());
    CHECK(job.progress() == doctest::Approx(1.0));
    CHECK(r->snap == s);
    CHECK(r->plaintext == plain);
    REQUIRE(r->scan.hits.size() == d.size() >> 20);
    CHECK(r->scan.hits[1].offset == 1000 + (1 << 20));
    CHECK(r->scan.hits[1].key == Bytes{0x77});

    // Restart right away: only the last run publishes.
    job.start(s, 0, UINT64_MAX, plain, XorScanOptions{});
    job.start(s, 0, 2000, plain, XorScanOptions{});
    r = wait_for(job, 1);
    CHECK(job.generation() == 2);
    CHECK(r->scan.end == 2000);
    CHECK(r->scan.hits.size() == 1);

    // Cancel: the run finishes (cancelled, or complete if it was already done).
    const uint64_t g = job.generation();
    job.start(s, 0, UINT64_MAX, plain, XorScanOptions{});
    job.cancel();
    r = wait_for(job, g);
    CHECK((r->scan.cancelled || r->scan.hits.size() == d.size() >> 20));
}

TEST_CASE("xorscan: holes of process memory are skipped by the scan") {
    hx_test::HoleyMem hm;  // readable page | hole page | readable page
    const uint64_t a = hm.addr(), pg = hm.pg;
    const Bytes plain = bytes_of("SECRET!!");
    Bytes enc = apply_transform(plain, XorTransform::Xor, {0x5A}, 0, false);
    std::memcpy(hm.after_ptr() + 100, enc.data(), enc.size());
    std::memcpy(hm.base + pg - 4, enc.data(), 4);       // a copy cut by the hole: never a match
    std::memcpy(hm.after_ptr(), enc.data() + 4, 4);
    auto doc = hx_test::open_self();
    auto snap = doc->snapshot();
    XorScanOptions o;
    o.add8 = o.rol = false;
    XorScanResult r;
    scan_xor(*snap, a, hm.end(), plain, o, r);
    CHECK_FALSE(r.io_error);
    CHECK(r.skipped == pg);
    check_hits(r.hits, {hit(a + 2 * pg + 100, XorTransform::Xor, {0x5A})});
    scan_xor(*snap, hm.hole_begin() + 1, hm.end(), plain, o, r);  // starting inside the hole
    CHECK_FALSE(r.io_error);
    CHECK(r.skipped == pg - 1);
    check_hits(r.hits, {hit(a + 2 * pg + 100, XorTransform::Xor, {0x5A})});
}

TEST_CASE("xorscan: apply failing partway leaves the document and its undo / redo stacks as they were") {
    // More than one 1 MiB chunk of readable memory, then a hole: the first chunk is written before
    // the second one hits the hole.
    const size_t pg = hx_test::page_size();
    hx_test::HoleyMem hm((size_t(1) << 20) / pg + 1, 1, 1);
    const uint64_t a = hm.addr();
    auto doc = hx_test::open_self(true);
    REQUIRE_FALSE(doc->read_only());
    const uint8_t x = 0x42;
    REQUIRE(doc->overwrite(a + 10, &x, 1));
    REQUIRE(doc->overwrite(a + 11, &x, 1));
    REQUIRE(doc->undo());  // one undo step, one redo step
    REQUIRE(doc->undo_stack().size() == 1);
    REQUIRE(doc->redo_stack().size() == 1);
    const uint64_t gen = doc->generation();

    std::string err;
    CHECK_FALSE(apply_transform(*doc, a, hm.hole_begin() - a + 100, XorTransform::Xor, {0xFF}, 0, true, &err));
    CHECK(err.find("unreadable") != std::string::npos);
    CHECK(err.find(fmt_hex(hm.hole_begin())) != std::string::npos);
    CHECK(doc->undo_stack().size() == 1);
    CHECK(doc->redo_stack().size() == 1);  // the earlier redo step survives, no new one
    CHECK_FALSE(doc->in_group());
    CHECK(doc->generation() != gen);  // content changed and was rolled back
    uint8_t b[16] = {};
    doc->read(a, b, sizeof b);
    for (int i = 0; i < 16; ++i) CHECK(b[i] == (i == 10 ? 0x42 : 0));
    CHECK(doc->is_modified_range(a + 10, 1));
    CHECK_FALSE(doc->is_modified_range(a + 100, (size_t(1) << 20) - 200));
    REQUIRE(doc->redo());  // the redo stack still works
    doc->read(a, b, sizeof b);
    CHECK(b[11] == 0x42);

    // Failing on the very first chunk (nothing written yet) is just as clean.
    CHECK_FALSE(apply_transform(*doc, hm.hole_begin() - 10, 20, XorTransform::Xor, {1}, 0, true, &err));
    CHECK(doc->undo_stack().size() == 2);
    CHECK(doc->redo_stack().empty());
}

TEST_CASE("xorscan: multi-byte ADD keys: transform, scan, key guess, labels") {
    // AddKey: byte i gets + key[(phase + i) % L]; decoding subtracts.
    CHECK(apply_transform(Bytes{0, 0, 0, 0xFF}, XorTransform::AddKey, {1, 2, 3}, 2, false) == Bytes{3, 1, 2, 2});
    CHECK(apply_transform(Bytes{3, 1, 2, 2}, XorTransform::AddKey, {1, 2, 3}, 2, true) == Bytes{0, 0, 0, 0xFF});
    CHECK(describe_key(XorTransform::AddKey, bytes_of("KEY")) == "ADD key 4B 45 59 \"KEY\"");
    CHECK(describe_key(XorTransform::AddKey, {0x01, 0xAB}) == "ADD key 01 AB");
    CHECK(std::string(transform_name(XorTransform::AddKey)) == "ADD key");
    CHECK(int(keyed_transform(1, true)) == int(XorTransform::Add));
    CHECK(int(keyed_transform(3, true)) == int(XorTransform::AddKey));
    CHECK(int(keyed_transform(1, false)) == int(XorTransform::Xor));
    CHECK(int(keyed_transform(2, false)) == int(XorTransform::XorKey));

    // Planted ADD-key copies (also across a block edge) are found with their absolute keys; with
    // add_multi off they are not, and the XOR-key search does not report them either.
    const std::string stub = "This program cannot be run in DOS mode.";
    Bytes d = random_bytes(size_t(kBlk) + 4096, 33);
    plant(d, 1234, bytes_of(stub), XorTransform::AddKey, bytes_of("K3Y!"));
    plant(d, kBlk - 9, bytes_of(stub), XorTransform::AddKey, {0x10, 0xF0, 0x01});
    XorScanOptions o;
    o.xor8 = o.add8 = o.rol = false;
    o.xor_multi = true;
    CHECK(scan(d, bytes_of(stub), o).hits.empty());
    o.add_multi = true;
    auto r = scan(d, bytes_of(stub), o);
    check_hits(r.hits, {hit(1234, XorTransform::AddKey, bytes_of("K3Y!"), uint32_t(1234 % 4)),
                        hit(kBlk - 9, XorTransform::AddKey, {0x10, 0xF0, 0x01}, uint32_t((kBlk - 9) % 3))});
    Bytes at(d.begin() + 1234, d.begin() + 1234 + ptrdiff_t(stub.size()));
    CHECK(apply_transform(at, XorTransform::AddKey, r.hits[0].key, r.hits[0].phase, true) == bytes_of(stub));
    // A constant ADD key is the 1-byte ADD hit, a repeated key the shorter one.
    Bytes c = random_bytes(4096, 34);
    plant(c, 100, bytes_of(stub), XorTransform::AddKey, {7, 7, 7});
    plant(c, 1000, bytes_of(stub), XorTransform::AddKey, {1, 2, 1, 2});
    o.add8 = true;
    o.xor_multi = false;
    check_hits(scan(c, bytes_of(stub), o).hits,
               {hit(100, XorTransform::Add, {7}), hit(1000, XorTransform::AddKey, {1, 2}, uint32_t(1000 % 2))});
    o.add_multi = false;
    check_hits(scan(c, bytes_of(stub), o).hits, {hit(100, XorTransform::Add, {7})});
    // No false positives on random data.
    o.add_multi = true;
    CHECK(scan(random_bytes(size_t(1) << 20, 35), bytes_of("This program"), o).hits.empty());

    // Key guess for ADD-obfuscated text: XOR and ADD differ once the dominant byte is not 0.
    Bytes text = bytes_of(std::string(300, ' ') + "a few words between many spaces" + std::string(200, ' '));
    text = apply_transform(text, XorTransform::AddKey, {0x13, 0x37}, 0, false);
    auto g = key_guess(text.data(), text.size(), 0, ' ', 16, XorTransform::AddKey);
    REQUIRE_FALSE(g.empty());
    CHECK(g[0].key == Bytes{0x13, 0x37});
    g = key_guess(text.data() + 1, text.size() - 1, 1, ' ', 16, XorTransform::Add);  // absolute convention
    REQUIRE_FALSE(g.empty());
    CHECK(g[0].key == Bytes{0x13, 0x37});
    g = key_guess(text.data(), text.size(), 0, ' ');  // as XOR: another key
    REQUIRE_FALSE(g.empty());
    CHECK(g[0].key != Bytes{0x13, 0x37});

    // Undoable apply; inside an open group an unlabelled apply keeps the group's label.
    const Bytes orig = bytes_of("0123456789");
    auto doc = Document::create_from_bytes("t", orig.data(), orig.size());
    std::string err;
    REQUIRE(apply_transform(*doc, 1, 5, XorTransform::AddKey, {1, 2}, 1, false, &err));
    CHECK(doc->undo_stack().back().label == "Encode ADD key 01 02");
    Bytes got(orig.size());
    doc->read(0, got.data(), got.size());
    CHECK(got == bytes_of("0335576789"));
    doc->begin_group("Script: mine");
    REQUIRE(apply_transform(*doc, 0, 2, XorTransform::Xor, {1}, 0, true, &err));
    doc->end_group();
    CHECK(doc->undo_stack().size() == 2);
    CHECK(doc->undo_stack().back().label == "Script: mine");
}
