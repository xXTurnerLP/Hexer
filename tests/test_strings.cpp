// Tests for core/strings_scan: run detection, block edges, UTF-16 alignment, limits, the job, the filter.
#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include "core/document.h"
#include "core/strings_scan.h"
#include "holey_mem.h"

using namespace hx;

namespace {

using Bytes = std::vector<uint8_t>;
constexpr uint64_t kBlk = kStringsBlock;

std::shared_ptr<const Snapshot> snap_of(const Bytes& b) {
    auto doc = Document::create_from_bytes("test", b.data(), b.size());
    REQUIRE(doc);
    return doc->snapshot();
}

Bytes bytes_of(const std::string& s) { return Bytes(s.begin(), s.end()); }

void put(Bytes& d, uint64_t at, const std::string& s) { std::memcpy(d.data() + at, s.data(), s.size()); }

void put16(Bytes& d, uint64_t at, const std::string& s, bool be = false) {
    for (size_t i = 0; i < s.size(); ++i) {
        d[size_t(at + 2 * i + (be ? 1 : 0))] = uint8_t(s[i]);
        d[size_t(at + 2 * i + (be ? 0 : 1))] = 0;
    }
}

StringsScanResult scan(const Bytes& d, StringsOptions o = {}, uint64_t begin = 0, uint64_t end = UINT64_MAX) {
    auto s = snap_of(d);
    StringsScanResult r;
    scan_strings(*s, begin, end, o, r);
    return r;
}

bool same(const StringHit& a, const StringHit& b) {
    return a.offset == b.offset && a.byte_length == b.byte_length && a.char_count == b.char_count &&
           a.encoding == b.encoding;
}

StringHit hit(uint64_t off, uint64_t chars, StringEncoding e) {
    const uint64_t w = e == StringEncoding::Ascii ? 1 : 2;
    return StringHit{off, chars * w, chars, e};
}

void check_hits(const std::vector<StringHit>& got, const std::vector<StringHit>& want) {
    REQUIRE(got.size() == want.size());
    for (size_t i = 0; i < got.size(); ++i) {
        INFO("hit " << i << ": got off=" << got[i].offset << " chars=" << got[i].char_count << " enc="
                    << encoding_name(got[i].encoding) << ", want off=" << want[i].offset
                    << " chars=" << want[i].char_count << " enc=" << encoding_name(want[i].encoding));
        CHECK(same(got[i], want[i]));
    }
}

// Naive reference over the whole buffer (no blocks), same rules as the scanner.
std::vector<StringHit> reference(const Bytes& d, const StringsOptions& o) {
    auto pr = [&](uint8_t c) {
        return (c >= 0x20 && c <= 0x7E) || c == '\t' || (o.include_newlines && (c == '\r' || c == '\n'));
    };
    std::vector<StringHit> out;
    const uint64_t mn = std::max<uint32_t>(o.min_length, 1);
    if (o.ascii) {
        uint64_t i = 0;
        while (i < d.size()) {
            if (!pr(d[i])) { ++i; continue; }
            uint64_t j = i;
            while (j < d.size() && pr(d[j])) ++j;
            if (j - i >= mn) out.push_back(hit(i, j - i, StringEncoding::Ascii));
            i = j;
        }
    }
    for (int be = 0; be < 2; ++be) {
        if (be ? !o.utf16be : !o.utf16le) continue;
        const auto enc = be ? StringEncoding::Utf16BE : StringEncoding::Utf16LE;
        auto ok = [&](uint64_t u) {
            uint8_t lo = be ? d[u + 1] : d[u], hi = be ? d[u] : d[u + 1];
            return hi == 0 && pr(lo);
        };
        for (uint64_t ph = 0; ph < 2; ++ph) {
            uint64_t u = ph;
            while (u + 1 < d.size()) {
                if (!ok(u)) { u += 2; continue; }
                uint64_t v = u;
                while (v + 1 < d.size() && ok(v)) v += 2;
                if ((v - u) / 2 >= mn) out.push_back(hit(u, (v - u) / 2, enc));
                u = v;
            }
        }
    }
    std::sort(out.begin(), out.end(), [](const StringHit& a, const StringHit& b) {
        return std::tie(a.offset, a.encoding) < std::tie(b.offset, b.encoding);
    });
    if (o.utf16le && o.utf16be) {
        // Both byte orders: a string is not listed again as its one-byte-shifted echo in the other
        // order (not longer, ends at most one byte past it; equal length: LE is kept).
        auto echo = [](const StringHit& e, const StringHit& m) {
            const bool shifted = e.offset == m.offset + 1 || m.offset == e.offset + 1;
            const bool other = e.encoding != StringEncoding::Ascii && m.encoding != StringEncoding::Ascii &&
                               e.encoding != m.encoding;
            return other && shifted && e.offset + 2 * e.char_count <= m.offset + 2 * m.char_count + 1 &&
                   (e.char_count < m.char_count ||
                    (e.char_count == m.char_count && m.encoding == StringEncoding::Utf16LE));
        };
        std::map<uint64_t, std::vector<size_t>> at;  // offset -> UTF-16 hits there
        for (size_t i = 0; i < out.size(); ++i)
            if (out[i].encoding != StringEncoding::Ascii) at[out[i].offset].push_back(i);
        std::vector<StringHit> kept;
        for (const StringHit& h : out) {
            bool drop = false;
            for (uint64_t nb : {h.offset - 1, h.offset + 1}) {
                auto it = at.find(nb);
                if (it == at.end()) continue;
                for (size_t m : it->second) drop = drop || echo(h, out[m]);
            }
            if (!drop) kept.push_back(h);
        }
        out.swap(kept);
    }
    return out;
}

std::shared_ptr<const StringsJob::Result> wait_for(StringsJob& job, uint64_t gen) {
    for (int i = 0; i < 20000 && job.generation() == gen; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    REQUIRE(job.generation() > gen);
    return job.result();
}

}  // namespace

TEST_CASE("strings: ASCII runs and min length") {
    auto r = scan(bytes_of(std::string("\x01hello\x00" "abcd\x00" "world!!\xFF" "abcde", 25)));
    check_hits(r.hits, {hit(1, 5, StringEncoding::Ascii), hit(12, 7, StringEncoding::Ascii),
                        hit(20, 5, StringEncoding::Ascii)});  // "abcd" is too short; "abcde" ends at EOF
    CHECK_FALSE(r.truncated);
    CHECK_FALSE(r.cancelled);
    CHECK_FALSE(r.io_error);
    CHECK(r.begin == 0);
    CHECK(r.end == 25);

    StringsOptions o;
    o.min_length = 4;
    r = scan(bytes_of(std::string("abcd\x00" "abc", 8)), o);
    check_hits(r.hits, {hit(0, 4, StringEncoding::Ascii)});
    o.min_length = 0;  // treated as 1
    r = scan(bytes_of(std::string("a\x00" "b", 3)), o);
    check_hits(r.hits, {hit(0, 1, StringEncoding::Ascii), hit(0, 1, StringEncoding::Utf16LE),
                        hit(2, 1, StringEncoding::Ascii)});  // 'a' 00 is also UTF-16LE "a"

    CHECK(scan(Bytes{}).hits.empty());
    CHECK(scan(bytes_of("abcde")).hits.size() == 1);   // whole file is one string
    CHECK(scan(bytes_of("tab\there")).hits.size() == 1);  // \t is a string character
}

TEST_CASE("strings: newlines option") {
    Bytes d = bytes_of("line1\r\nline2\nx");
    StringsOptions o;
    o.utf16le = false;
    check_hits(scan(d, o).hits, {hit(0, 5, StringEncoding::Ascii), hit(7, 5, StringEncoding::Ascii)});
    o.include_newlines = true;
    check_hits(scan(d, o).hits, {hit(0, 14, StringEncoding::Ascii)});
}

TEST_CASE("strings: UTF-16 alignment") {
    // 00 'A' 00 'B' 00 'C' 00 'D' 00 'E' 00: UTF-16LE "ABCDE" at offset 1, UTF-16BE "ABCDE" at 0.
    Bytes d = {0, 'A', 0, 'B', 0, 'C', 0, 'D', 0, 'E', 0};
    StringsOptions o;
    check_hits(scan(d, o).hits, {hit(1, 5, StringEncoding::Utf16LE)});
    o.utf16be = true;  // both readings are equally long: only the LE one is listed (no shifted echo)
    check_hits(scan(d, o).hits, {hit(1, 5, StringEncoding::Utf16LE)});
    o.utf16le = false;
    check_hits(scan(d, o).hits, {hit(0, 5, StringEncoding::Utf16BE)});

    // Even offset; the ASCII scanner sees only single characters there.
    Bytes e(40, 0xFF);
    put16(e, 0, "Hello");
    put16(e, 20, "World", true);
    o = StringsOptions{};
    o.utf16be = true;
    check_hits(scan(e, o).hits, {hit(0, 5, StringEncoding::Utf16LE), hit(20, 5, StringEncoding::Utf16BE)});

    // A dangling last byte is not a code unit: "abcd" + 'e' without its high byte at EOF.
    Bytes f = {'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e'};
    CHECK(scan(f).hits.empty());
    o = StringsOptions{};
    o.min_length = 4;
    o.ascii = false;
    check_hits(scan(f, o).hits, {hit(0, 4, StringEncoding::Utf16LE)});

    // Non-ASCII code units end a run.
    Bytes g(20, 0);
    put16(g, 0, "abcdefgh");
    g[7] = 0x01;  // 'd' becomes U+0164
    o = StringsOptions{};
    o.min_length = 3;
    o.ascii = false;
    check_hits(scan(g, o).hits, {hit(0, 3, StringEncoding::Utf16LE), hit(8, 4, StringEncoding::Utf16LE)});
}

TEST_CASE("strings: runs crossing the 4 MiB block edge are reported once, whole") {
    Bytes d(size_t(2 * kBlk + 100), 0);
    const std::string a(100, 'x');
    put(d, kBlk - 50, a);                          // ASCII across the first edge
    put16(d, 2 * kBlk - 7, "crossing");            // UTF-16LE at an odd offset across the second edge
    put(d, d.size() - 9, "endoffile");             // ends exactly at EOF
    StringsOptions o;
    auto r = scan(d, o);
    check_hits(r.hits, {hit(kBlk - 50, 100, StringEncoding::Ascii), hit(2 * kBlk - 7, 8, StringEncoding::Utf16LE),
                        hit(d.size() - 9, 9, StringEncoding::Ascii)});

    // A code unit split by the edge: string starts at the last byte of block 0.
    Bytes e(size_t(kBlk + 64), 0xFF);
    put16(e, kBlk - 1, "split");
    check_hits(scan(e).hits, {hit(kBlk - 1, 5, StringEncoding::Utf16LE)});
    // A string that ends at the last byte of a block, and one that starts at the first byte of the next.
    Bytes f(size_t(kBlk + 64), 0);
    put(f, kBlk - 5, "aaaaa");
    put(f, kBlk + 1, "bbbbb");
    check_hits(scan(f).hits, {hit(kBlk - 5, 5, StringEncoding::Ascii), hit(kBlk + 1, 5, StringEncoding::Ascii)});
    f[size_t(kBlk)] = 'c';  // now one string of 11 across the edge
    check_hits(scan(f).hits, {hit(kBlk - 5, 11, StringEncoding::Ascii)});
}

TEST_CASE("strings: random data matches a naive reference across block edges") {
    std::mt19937 rng(1234);
    const uint8_t alphabet[] = {'a', 'Z', ' ', 0, 0, 0, '\n', '\r', '\t', 0x80, 0x01};
    Bytes d(size_t(2 * kBlk + 12345));
    for (auto& b : d) b = alphabet[rng() % sizeof alphabet];
    // Long runs around both block edges.
    for (uint64_t edge : {kBlk, 2 * kBlk}) {
        put(d, edge - 30, std::string(61, 'q'));
        put16(d, edge - 21, "utf16 run here");
    }
    for (int variant = 0; variant < 3; ++variant) {
        StringsOptions o;
        o.min_length = variant == 0 ? 3 : variant == 1 ? 1 : 6;
        o.utf16be = variant != 0;
        o.include_newlines = variant == 2;
        o.max_results = SIZE_MAX;
        INFO("variant " << variant);
        auto r = scan(d, o);
        auto ref = reference(d, o);
        CHECK(r.hits.size() == ref.size());
        bool all = r.hits.size() == ref.size();
        for (size_t i = 0; all && i < ref.size(); ++i) all = same(r.hits[i], ref[i]);
        CHECK(all);
    }
}

TEST_CASE("strings: range scan clips strings to the range") {
    Bytes d(300, 0);
    put(d, 10, "first string");
    put(d, 95, "0123456789");  // 95..104
    put(d, 120, "inside");
    put(d, 145, "0123456789");  // 145..154
    StringsOptions o;
    auto r = scan(d, o, 100, 150);
    CHECK(r.begin == 100);
    CHECK(r.end == 150);
    check_hits(r.hits, {hit(100, 5, StringEncoding::Ascii), hit(120, 6, StringEncoding::Ascii),
                        hit(145, 5, StringEncoding::Ascii)});
    r = scan(d, o, 250, 1000);  // end is clamped to the size
    CHECK(r.end == 300);
    CHECK(r.hits.empty());
    r = scan(d, o, 500, 1000);  // begin past EOF
    CHECK(r.hits.empty());
    CHECK(r.begin == 300);
}

TEST_CASE("strings: max_results truncation") {
    Bytes d;
    for (int i = 0; i < 10; ++i) {
        std::string s = "string" + std::to_string(i);
        d.insert(d.end(), s.begin(), s.end());
        d.push_back(0xFF);
    }
    StringsOptions o;
    o.max_results = 3;
    auto r = scan(d, o);
    CHECK(r.truncated);
    REQUIRE(r.hits.size() == 3);
    CHECK(r.hits[0].offset == 0);
    CHECK(r.hits[2].offset == 16);
    o.max_results = 10;
    r = scan(d, o);
    CHECK_FALSE(r.truncated);
    CHECK(r.hits.size() == 10);
    o.max_results = 0;
    r = scan(d, o);
    CHECK(r.truncated);
    CHECK(r.hits.empty());
}

TEST_CASE("strings: cancel and unreadable bytes") {
    Bytes d(1000, 0);
    put(d, 0, "hello world");
    auto s = snap_of(d);
    std::atomic<bool> cancel{true};
    StringsScanResult r;
    scan_strings(*s, 0, UINT64_MAX, StringsOptions{}, r, &cancel);
    CHECK(r.cancelled);
    CHECK(r.hits.empty());

    // Middle piece references a missing add chunk: its bytes are unreadable (like a bad sector).
    auto base = snap_of(bytes_of(std::string(4000, 'k')));
    auto bad = std::make_shared<Snapshot>(*base);
    bad->pieces = {Piece{Piece::Add, 0, 0, 1000}, Piece{Piece::Add, 99, 0, 500}, Piece{Piece::Add, 0, 0, 1000}};
    bad->starts = {0, 1000, 1500};
    bad->size_ = 2500;
    scan_strings(*bad, 0, UINT64_MAX, StringsOptions{}, r);
    CHECK(r.io_error);
    CHECK(r.io_error_offset == 1000);
    check_hits(r.hits, {hit(0, 1000, StringEncoding::Ascii)});  // strings before the error are kept
}

TEST_CASE("StringsJob: results, restart, cancel") {
    Bytes d(size_t(3 * kBlk), 0);
    for (uint64_t at = 0; at + 16 < d.size(); at += 4096) put(d, at, "marker string");
    auto s = snap_of(d);
    StringsJob job;
    CHECK(job.result() == nullptr);
    CHECK_FALSE(job.running());
    job.start(s, 0, UINT64_MAX, StringsOptions{});
    auto r = wait_for(job, 0);
    REQUIRE(r);
    CHECK_FALSE(job.running());
    CHECK(job.progress() == doctest::Approx(1.0));
    CHECK(r->snap == s);
    CHECK(r->scan.hits.size() == d.size() / 4096);
    CHECK(string_hit_text(*r->snap, r->scan.hits[1]) == "marker string");

    // Range + options are kept with the result.
    StringsOptions o;
    o.min_length = 20;
    job.start(s, 4096, 8192, o);
    r = wait_for(job, 1);
    CHECK(r->options.min_length == 20);
    CHECK(r->scan.hits.empty());
    CHECK(r->scan.begin == 4096);

    // Restart right away: only the last run publishes.
    job.start(s, 0, UINT64_MAX, StringsOptions{});
    job.start(s, 0, 4096, StringsOptions{});
    r = wait_for(job, 2);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(job.generation() == 3);
    CHECK(job.result()->scan.hits.size() == 1);

    // Cancel: the run finishes (cancelled, or complete if it was already done).
    job.start(s, 0, UINT64_MAX, StringsOptions{});
    job.cancel();
    r = wait_for(job, 3);
    CHECK((r->scan.cancelled || r->scan.hits.size() == d.size() / 4096));

    {
        StringsJob j2;
        j2.start(s, 0, UINT64_MAX, StringsOptions{});
    }  // destructor cancels + joins
    CHECK(true);
}

TEST_CASE("strings: hit text and escaping") {
    Bytes d(64, 0x01);
    put(d, 0, "Hello\tWorld");
    put16(d, 20, "wide!");
    put16(d, 40, "BigEnd", true);
    auto doc = Document::create_from_bytes("t", d.data(), d.size());
    auto s = doc->snapshot();
    CHECK(string_hit_text(*s, hit(0, 11, StringEncoding::Ascii)) == "Hello\tWorld");
    CHECK(string_hit_text(*s, hit(0, 11, StringEncoding::Ascii), 5) == "Hello");
    CHECK(string_hit_text(*s, hit(20, 5, StringEncoding::Utf16LE)) == "wide!");
    CHECK(string_hit_text(*s, hit(40, 6, StringEncoding::Utf16BE)) == "BigEnd");
    CHECK(string_hit_text(*s, hit(40, 6, StringEncoding::Utf16BE), 3) == "Big");
    CHECK(string_hit_text(*doc, hit(20, 5, StringEncoding::Utf16LE)) == "wide!");
    CHECK(string_hit_text(*s, hit(60, 10, StringEncoding::Ascii)) == "\x01\x01\x01\x01");  // clamped at EOF
    CHECK(string_hit_text(*s, hit(20, 5, StringEncoding::Utf16BE)) == "?????");  // mismatching units
    CHECK(escape_string_text(std::string("a\tb\r\nc\x00\x7F", 8)) == "a\\tb\\r\\nc\\x00\\x7F");
    CHECK(std::string(encoding_name(StringEncoding::Utf16LE)) == "UTF-16LE");
}

TEST_CASE("StringsFilter: incremental case-insensitive substring") {
    Bytes d(200, 0);
    put(d, 0, "Kernel32.dll");
    put(d, 20, "user32.DLL");
    put(d, 40, "nothing here");
    put16(d, 60, "SHELL32.dll");
    StringsOptions o;
    auto s = snap_of(d);
    StringsScanResult r;
    scan_strings(*s, 0, UINT64_MAX, o, r);
    REQUIRE(r.hits.size() == 4);

    StringsFilter f;
    f.reset(".Dll");
    CHECK(f.needle() == ".dll");
    CHECK_FALSE(f.step(*s, r.hits, 1));
    CHECK(f.tested() == 1);
    CHECK_FALSE(f.step(*s, r.hits, 2));
    CHECK(f.step(*s, r.hits, 100));
    CHECK(f.done(r.hits.size()));
    CHECK(f.matches() == std::vector<size_t>{0, 1, 3});

    f.reset("");
    CHECK(f.step(*s, r.hits, 100));
    CHECK(f.matches().size() == 4);
    f.reset("this needle is longer than any string");
    CHECK(f.step(*s, r.hits, 100));
    CHECK(f.matches().empty());
    f.reset("32");
    int calls = 1;
    while (!f.step(*s, r.hits, 0)) ++calls;  // 0 still makes progress: one hit per call
    CHECK(calls == 4);
    CHECK(f.matches() == std::vector<size_t>{0, 1, 3});
}

TEST_CASE("strings: holes of process memory end strings and are skipped, not errors") {
    hx_test::HoleyMem hm;  // readable page | hole page | readable page (zero-filled)
    const uint64_t a = hm.addr(), pg = hm.pg;
    std::memcpy(hm.base + pg - 11, "HELLO_WORLD", 11);  // touches the hole
    std::memcpy(hm.after_ptr(), "ABCDEFGH", 8);          // starts right after it
    std::memcpy(hm.base + 100, "inside page one", 15);
    auto doc = hx_test::open_self();
    auto snap = doc->snapshot();
    StringsOptions o;
    o.utf16le = false;
    o.min_length = 4;
    StringsScanResult r;
    scan_strings(*snap, a, hm.end(), o, r);
    CHECK_FALSE(r.io_error);
    CHECK(r.skipped == pg);
    REQUIRE(r.hits.size() == 3);
    CHECK(r.hits[0].offset == a + 100);
    CHECK(r.hits[1].offset == a + pg - 11);
    CHECK(r.hits[1].char_count == 11);  // ends at the hole
    CHECK(r.hits[2].offset == a + 2 * pg);
    CHECK(r.hits[2].char_count == 8);
    CHECK(string_hit_text(*snap, r.hits[2]) == "ABCDEFGH");

    // Starting inside the hole; and the job reports the same.
    scan_strings(*snap, a + pg + 5, hm.end(), o, r);
    CHECK_FALSE(r.io_error);
    CHECK(r.skipped == pg - 5);
    REQUIRE(r.hits.size() == 1);
    CHECK(r.hits[0].offset == a + 2 * pg);

    StringsJob job;
    const uint64_t gen = job.generation();
    job.start(snap, a, hm.end(), o);
    const auto t0 = std::chrono::steady_clock::now();
    while (job.generation() == gen) {
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    auto jr = job.result();
    REQUIRE(jr);
    CHECK(jr->scan.hits.size() == 3);
    CHECK(jr->scan.skipped == pg);
    CHECK_FALSE(jr->scan.io_error);
}

TEST_CASE("strings: an ASCII-in-UTF-16 string is not listed again shifted by one byte") {
    StringsOptions o;
    o.ascii = false;
    o.utf16be = true;
    o.min_length = 4;
    // UTF-16LE "Hello": read one byte later as UTF-16BE it is "ello" (00 'e' 00 'l' ...).
    Bytes d(40, 0xFF);
    put16(d, 0, "Hello");
    put16(d, 21, "World", true);  // UTF-16BE "World": LE one byte later reads "orld"
    check_hits(scan(d, o).hits, {hit(0, 5, StringEncoding::Utf16LE), hit(21, 5, StringEncoding::Utf16BE)});
    // Before the dedup the echoes were listed too.
    o.utf16be = false;
    check_hits(scan(d, o).hits, {hit(0, 5, StringEncoding::Utf16LE), hit(22, 4, StringEncoding::Utf16LE)});
    o.utf16be = true;
    o.utf16le = false;
    check_hits(scan(d, o).hits, {hit(1, 4, StringEncoding::Utf16BE), hit(21, 5, StringEncoding::Utf16BE)});

    // A real BE string right behind an LE one is kept (it is not their shifted reading).
    Bytes e(60, 0xFF);
    put16(e, 0, "First");
    put16(e, 10, "Second", true);  // directly behind it
    o.utf16le = true;
    check_hits(scan(e, o).hits, {hit(0, 5, StringEncoding::Utf16LE), hit(10, 6, StringEncoding::Utf16BE)});
}
