#include <doctest/doctest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#include "core/document.h"
#include "core/inspector.h"
#include "core/nav.h"
#include "core/settings.h"

using namespace hx;

namespace {

std::unique_ptr<Document> make_doc(const std::vector<uint8_t>& b) {
    return Document::create_from_bytes("nav", b.data(), b.size());
}

NavEntry at(uint64_t off, uint64_t len = 0) { return NavEntry{off, len}; }

}  // namespace

// =============================================================================================
// NavHistory
// =============================================================================================

TEST_CASE("nav: empty history") {
    NavHistory h;
    CHECK(!h.can_back());
    CHECK(!h.can_forward());
    CHECK(h.back(at(5)) == at(5));
    CHECK(h.forward(at(5)) == at(5));
    CHECK(!h.can_back());
    CHECK(!h.can_forward());
}

TEST_CASE("nav: back and forward walk the history like a browser") {
    NavHistory h;
    // 0 -> 100 -> 200 (with a selection at 100)
    h.push(at(0));
    h.push(at(100, 4));
    CHECK(h.can_back());
    CHECK(!h.can_forward());

    CHECK(h.back(at(200)) == at(100, 4));
    CHECK(h.can_forward());
    CHECK(h.back(at(100, 4)) == at(0));
    CHECK(!h.can_back());
    CHECK(h.back_stack().empty());
    REQUIRE(h.forward_stack().size() == 2);

    CHECK(h.forward(at(0)) == at(100, 4));
    CHECK(h.forward(at(100, 4)) == at(200));
    CHECK(!h.can_forward());
    CHECK(h.back_stack().size() == 2);

    h.clear();
    CHECK(!h.can_back());
    CHECK(!h.can_forward());
}

TEST_CASE("nav: push dedupes consecutive entries and clears forward") {
    NavHistory h;
    h.push(at(10));
    h.push(at(10));
    CHECK(h.back_stack().size() == 1);
    h.push(at(10, 2));  // same offset, other selection: a different entry
    CHECK(h.back_stack().size() == 2);
    h.push(at(10));
    CHECK(h.back_stack().size() == 3);  // only *consecutive* duplicates are dropped

    CHECK(h.back(at(50)) == at(10));
    CHECK(h.can_forward());
    h.push(at(77));  // a new jump forgets the forward branch
    CHECK(!h.can_forward());
    CHECK(h.back_stack().back() == at(77));

    // back/forward round trip keeps both stacks consistent
    NavHistory g;
    g.push(at(1));
    g.push(at(2));
    CHECK(g.back(at(3)) == at(2));
    CHECK(g.forward(at(2)) == at(3));  // 2 goes back onto the back stack
    CHECK(g.back_stack().size() == 2);
    CHECK(g.back(at(3)) == at(2));
    CHECK(g.forward_stack().size() == 1);
}

TEST_CASE("nav: stacks are capped at kMax, dropping the oldest") {
    NavHistory h;
    for (uint64_t i = 0; i < NavHistory::kMax + 50; ++i) h.push(at(i));
    REQUIRE(h.back_stack().size() == NavHistory::kMax);
    CHECK(h.back_stack().front() == at(50));
    CHECK(h.back_stack().back() == at(NavHistory::kMax + 49));

    // Walking all the way back fills the forward stack up to the cap as well.
    uint64_t cur = 100000;
    NavEntry e = at(cur);
    size_t n = 0;
    while (h.can_back()) {
        e = h.back(e);
        ++n;
    }
    CHECK(n == NavHistory::kMax);
    CHECK(e == at(50));
    CHECK(h.forward_stack().size() == NavHistory::kMax);
    CHECK(h.forward_stack().front() == at(cur));
}

// =============================================================================================
// decode_pointer
// =============================================================================================

TEST_CASE("nav: decode_pointer widths and endianness") {
    std::vector<uint8_t> b(64, 0);
    // at 0: 10 00 00 00 00 00 00 00
    b[0] = 0x10;
    // at 8: 00 00 00 20 (BE 0x20)
    b[11] = 0x20;
    auto doc = make_doc(b);
    uint64_t t = 0;

    CHECK(decode_pointer(*doc, 0, 1, false, 0, t));
    CHECK(t == 0x10);
    CHECK(decode_pointer(*doc, 0, 2, false, 0, t));
    CHECK(t == 0x10);
    CHECK(decode_pointer(*doc, 0, 4, false, 0, t));
    CHECK(t == 0x10);
    CHECK(decode_pointer(*doc, 0, 8, false, 0, t));
    CHECK(t == 0x10);
    // big-endian 0x10000000 is way past EOF
    CHECK(!decode_pointer(*doc, 0, 4, true, 0, t));
    CHECK(decode_pointer(*doc, 0, 4, true, 0x10000000, t));
    CHECK(t == 0);

    CHECK(decode_pointer(*doc, 8, 4, true, 0, t));
    CHECK(t == 0x20);
    CHECK(decode_pointer(*doc, 10, 2, true, 0, t));
    CHECK(t == 0x20);
    CHECK(!decode_pointer(*doc, 8, 4, false, 0, t));  // LE 0x20000000

    // invalid widths (3 is valid: u24)
    CHECK(!decode_pointer(*doc, 0, 0, false, 0, t));
    CHECK(!decode_pointer(*doc, 0, 5, false, 0, t));
    CHECK(!decode_pointer(*doc, 0, 16, false, 0, t));
    CHECK(decode_pointer(*doc, 0, 3, false, 0, t));
    CHECK(t == 0x10);
}

TEST_CASE("nav: decode_pointer multi-byte values are assembled in the right order") {
    std::vector<uint8_t> b(0x10000, 0);
    b[0] = 0x34;
    b[1] = 0x12;
    auto doc = make_doc(b);
    uint64_t t = 0;
    CHECK(decode_pointer(*doc, 0, 2, false, 0, t));
    CHECK(t == 0x1234);
    CHECK(decode_pointer(*doc, 0, 2, true, 0, t));
    CHECK(t == 0x3412);
    CHECK(decode_pointer(*doc, 0, 4, false, 0, t));
    CHECK(t == 0x1234);
}

TEST_CASE("nav: decode_pointer base, EOF and range checks") {
    std::vector<uint8_t> b(32, 0);
    b[0] = 0x20;  // == size: the EOF position, allowed
    b[4] = 0x21;  // size + 1: beyond EOF
    b[8] = 0x05;
    b[28] = 0x01;
    auto doc = make_doc(b);
    uint64_t t = 99;

    CHECK(decode_pointer(*doc, 0, 4, false, 0, t));
    CHECK(t == 32);
    t = 99;
    CHECK(!decode_pointer(*doc, 4, 4, false, 0, t));
    CHECK(t == 99);  // untouched on failure

    // base: value - base, underflow fails
    CHECK(decode_pointer(*doc, 4, 4, false, 0x10, t));
    CHECK(t == 0x11);
    CHECK(decode_pointer(*doc, 8, 4, false, 5, t));
    CHECK(t == 0);
    CHECK(!decode_pointer(*doc, 8, 4, false, 6, t));

    // the value must fit before EOF
    CHECK(decode_pointer(*doc, 28, 4, false, 0, t));
    CHECK(t == 1);
    CHECK(!decode_pointer(*doc, 29, 4, false, 0, t));
    CHECK(!decode_pointer(*doc, 32, 1, false, 0, t));
    CHECK(!decode_pointer(*doc, UINT64_MAX, 8, false, 0, t));
    CHECK(decode_pointer(*doc, 31, 1, false, 0, t));
    CHECK(t == 0);

    auto empty = make_doc({});
    CHECK(!decode_pointer(*empty, 0, 1, false, 0, t));
}

TEST_CASE("nav: decode_pointer reads edited bytes") {
    std::vector<uint8_t> b(16, 0);
    auto doc = make_doc(b);
    const uint8_t p[2] = {0x0C, 0x00};
    REQUIRE(doc->overwrite(2, p, 2));
    uint64_t t = 0;
    CHECK(decode_pointer(*doc, 2, 2, false, 0, t));
    CHECK(t == 12);
    const uint8_t ins = 0xFF;
    REQUIRE(doc->insert(0, &ins, 1));  // shifts the pointer to offset 3
    CHECK(decode_pointer(*doc, 3, 2, false, 0, t));
    CHECK(t == 12);
}

// =============================================================================================
// PointerType: width 3, signed, relative
// =============================================================================================

namespace {

PointerType ptype(int width, bool sgn = false, bool be = false, bool rel = false, uint64_t base = 0) {
    PointerType p;
    p.width = width;
    p.is_signed = sgn;
    p.big_endian = be;
    p.relative = rel;
    p.base = base;
    return p;
}

}  // namespace

TEST_CASE("nav: decode_pointer 24-bit, both byte orders") {
    std::vector<uint8_t> b(0x20000, 0);
    b[0] = 0x56;
    b[1] = 0x34;
    b[2] = 0x01;  // LE 0x013456, BE 0x563401 (beyond EOF)
    auto doc = make_doc(b);
    uint64_t t = 0;
    CHECK(decode_pointer(*doc, 0, ptype(3), t));
    CHECK(t == 0x013456);
    CHECK(!decode_pointer(*doc, 0, ptype(3, false, true), t));
    CHECK(decode_pointer(*doc, 0, ptype(3, false, true, false, 0x550000), t));
    CHECK(t == 0x013401);
    // the old overload accepts width 3 as well
    CHECK(decode_pointer(*doc, 0, 3, false, 0, t));
    CHECK(t == 0x013456);
    // needs 3 bytes before EOF
    CHECK(decode_pointer(*doc, b.size() - 3, ptype(3), t));
    CHECK(t == 0);
    CHECK(!decode_pointer(*doc, b.size() - 2, ptype(3), t));
}

TEST_CASE("nav: decode_pointer signed absolute values below 0 cannot be followed") {
    std::vector<uint8_t> b(64, 0);
    b[0] = 0xFF;  // s8 -1
    b[1] = 0x10;  // s8 +16
    b[4] = 0xFE;  // s24 LE -2, u24 0xFFFFFE
    b[5] = 0xFF;
    b[6] = 0xFF;
    b[8] = 0x7F;  // s8 +127 (beyond EOF)
    auto doc = make_doc(b);
    uint64_t t = 99;
    CHECK(!decode_pointer(*doc, 0, ptype(1, true), t));
    CHECK(t == 99);
    CHECK(decode_pointer(*doc, 1, ptype(1, true), t));
    CHECK(t == 16);
    CHECK(!decode_pointer(*doc, 4, ptype(3, true), t));
    CHECK(!decode_pointer(*doc, 4, ptype(3, false), t));  // unsigned: ~16 MiB, beyond EOF
    // an unsigned value minus a base still works; a negative signed one never does
    CHECK(decode_pointer(*doc, 4, ptype(3, false, false, false, 0xFFFFF0), t));
    CHECK(t == 0x0E);
    CHECK(!decode_pointer(*doc, 4, ptype(3, true, false, false, 0xFFFFF0), t));
    CHECK(!decode_pointer(*doc, 8, ptype(1, true), t));
    // s64 -1, s16 BE -1
    std::vector<uint8_t> m(16, 0xFF);
    auto dm = make_doc(m);
    CHECK(!decode_pointer(*dm, 0, ptype(8, true), t));
    CHECK(!decode_pointer(*dm, 0, ptype(2, true, true), t));
}

TEST_CASE("nav: decode_pointer relative pointers go forward and backward") {
    std::vector<uint8_t> b(256, 0);
    b[16] = 0x10;  // +16 -> 32
    b[40] = 0xF0;  // s8 -16 -> 24 ; u8 240 -> 280 (beyond EOF)
    b[64] = 0xC0;  // s32 LE -64 -> 0
    b[65] = 0xFF;
    b[66] = 0xFF;
    b[67] = 0xFF;
    b[80] = 0xAF;  // s32 LE -81 -> before 0
    b[81] = 0xFF;
    b[82] = 0xFF;
    b[83] = 0xFF;
    b[96] = 0xFF;  // s24 BE -96 -> 0
    b[97] = 0xFF;
    b[98] = 0xA0;
    b[120] = 0x88;  // u8 +136 -> 256 == EOF (allowed)
    b[121] = 0x88;  // +136 -> 257 beyond EOF
    b[150] = 0x00;  // s16 BE 0x0020 -> 182
    b[151] = 0x20;
    auto doc = make_doc(b);
    uint64_t t = 0;
    CHECK(decode_pointer(*doc, 16, ptype(1, false, false, true), t));
    CHECK(t == 32);
    CHECK(decode_pointer(*doc, 40, ptype(1, true, false, true), t));
    CHECK(t == 24);
    CHECK(!decode_pointer(*doc, 40, ptype(1, false, false, true), t));
    CHECK(decode_pointer(*doc, 64, ptype(4, true, false, true), t));
    CHECK(t == 0);
    t = 7;
    CHECK(!decode_pointer(*doc, 80, ptype(4, true, false, true), t));  // would be before offset 0
    CHECK(t == 7);
    CHECK(decode_pointer(*doc, 96, ptype(3, true, true, true), t));
    CHECK(t == 0);
    CHECK(!decode_pointer(*doc, 96, ptype(3, true, false, true), t));  // LE 0xA0FFFF: far forward
    CHECK(decode_pointer(*doc, 120, ptype(1, false, false, true), t));
    CHECK(t == 256);
    CHECK(!decode_pointer(*doc, 121, ptype(1, false, false, true), t));
    CHECK(decode_pointer(*doc, 150, ptype(2, true, true, true), t));
    CHECK(t == 182);
    CHECK(!decode_pointer(*doc, 150, ptype(2, true, false, true), t));  // LE 0x2000: beyond EOF
    // relative ignores the base
    CHECK(decode_pointer(*doc, 16, ptype(1, false, false, true, 0x1000), t));
    CHECK(t == 32);
    // a zero value points at the pointer itself
    CHECK(decode_pointer(*doc, 0, ptype(4, true, false, true), t));
    CHECK(t == 0);
}

TEST_CASE("nav: decode_pointer relative 64-bit overflow and underflow") {
    std::vector<uint8_t> b(32, 0);
    // at 8: u64 LE 0xFFFFFFFFFFFFFFFF: unsigned at + value passes 2^64, signed it is -1 -> 7
    for (size_t i = 8; i < 16; ++i) b[i] = 0xFF;
    // at 16: s64 LE INT64_MIN (0x8000000000000000): magnitude 2^63, far before 0
    b[23] = 0x80;
    auto doc = make_doc(b);
    uint64_t t = 0;
    CHECK(!decode_pointer(*doc, 8, ptype(8, false, false, true), t));
    CHECK(decode_pointer(*doc, 8, ptype(8, true, false, true), t));
    CHECK(t == 7);
    CHECK(!decode_pointer(*doc, 16, ptype(8, true, false, true), t));
    CHECK(!decode_pointer(*doc, 16, ptype(8, false, false, true), t));  // +2^63: beyond EOF
    CHECK(!decode_pointer(*doc, 16, ptype(8, true), t));                // negative absolute
    // big-endian -8 at 24 -> 16
    std::vector<uint8_t> c(32, 0);
    for (size_t i = 24; i < 31; ++i) c[i] = 0xFF;
    c[31] = 0xF8;
    auto dc = make_doc(c);
    CHECK(decode_pointer(*dc, 24, ptype(8, true, true, true), t));
    CHECK(t == 16);
}

TEST_CASE("nav: pointer_type_name and pointer_link_text") {
    CHECK(pointer_type_name(ptype(1)) == "u8");
    CHECK(pointer_type_name(ptype(1, true, true)) == "s8");
    CHECK(pointer_type_name(ptype(2)) == "u16 LE");
    CHECK(pointer_type_name(ptype(3, true, true)) == "s24 BE");
    CHECK(pointer_type_name(ptype(4, true, false, true)) == "s32 LE rel");
    CHECK(pointer_type_name(ptype(8, false, false, false, 0x140000000ull)) == "u64 LE, base 0x140000000");
    CHECK(pointer_type_name(ptype(8, false, false, false, 0xABCull), false) == "u64 LE, base 0xabc");
    CHECK(pointer_type_name(ptype(4, false, false, true, 0x1000)) == "u32 LE rel");  // base unused
    CHECK(pointer_link_text(ptype(2), true, 0x1234) == "u16 LE \xE2\x86\x92 0x1234");
    CHECK(pointer_link_text(ptype(2), true, 0xAB, false) == "u16 LE \xE2\x86\x92 0xab");
    CHECK(pointer_link_text(ptype(4, true), false, 0).rfind("s32 LE \xE2\x86\x92 nothing to follow", 0) == 0);
}

TEST_CASE("nav: valid_pointer_width") {
    for (int w : {1, 2, 3, 4, 8}) CHECK(valid_pointer_width(w));
    for (int w : {-1, 0, 5, 6, 7, 9, 16}) CHECK(!valid_pointer_width(w));
}

TEST_CASE("nav: Inspector integer rows map to pointer types") {
    int w = 0;
    bool s = false;
    CHECK(insp_int_type(InspType::U8, w, s));
    CHECK((w == 1 && !s));
    CHECK(insp_int_type(InspType::I24, w, s));
    CHECK((w == 3 && s));
    CHECK(insp_int_type(InspType::U64, w, s));
    CHECK((w == 8 && !s));
    for (InspType t : {InspType::Bin8, InspType::F32, InspType::Ascii, InspType::ULEB128, InspType::Unix32,
                       InspType::Guid})
        CHECK(!insp_int_type(t, w, s));
    int n = 0;
    for (int i = 0; i < int(InspType::Count); ++i) {
        if (!insp_int_type(InspType(i), w, s)) continue;
        ++n;
        CHECK(insp_type_of_int(w, s) == InspType(i));
    }
    CHECK(n == 10);
    CHECK(insp_type_of_int(5, false) == InspType::Count);
    CHECK(insp_type_of_int(2, true) == InspType::I16);
}

TEST_CASE("nav: settings follow pointer type round trip") {
    std::error_code ec;
    const std::filesystem::path dir =
        std::filesystem::temp_directory_path(ec) /
        ("hexer_nav_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    REQUIRE(std::filesystem::create_directories(dir, ec));
    const std::string f = (dir / "settings.ini").string();
    Settings def;
    CHECK(def.pointer_type() == PointerType{});
    Settings s;
    s.pointer_width = 3;
    s.pointer_signed = true;
    s.pointer_relative = true;
    s.big_endian_inspector = true;
    s.pointer_base = 0x400000;
    REQUIRE(s.save(f));
    Settings u;
    REQUIRE(u.load(f));
    CHECK(u.pointer_width == 3);
    CHECK(u.pointer_signed);
    CHECK(u.pointer_relative);
    CHECK(u.pointer_type() == ptype(3, true, true, true, 0x400000));
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("nav: Back / Forward stacks as session text (encode, decode, clamp, set_stacks)") {
    const std::vector<NavEntry> back = {{0, 0}, {0x1000, 16}, {123456789012ull, 4}};
    const std::string text = nav_encode(back);
    CHECK(text == "0:0 4096:16 123456789012:4");
    CHECK(nav_encode({}).empty());
    CHECK(nav_decode(text, UINT64_MAX) == back);
    CHECK(nav_decode("", 100).empty());
    // Clamped to the document (it may have shrunk since): offset <= size, offset + length <= size.
    CHECK(nav_decode(text, 4100) == std::vector<NavEntry>{{0, 0}, {4096, 4}, {4100, 0}});
    // Malformed entries are skipped, the rest kept.
    CHECK(nav_decode("5:1 x:2 7 :3 8: -1:0 9:9z  10:0", 100) == std::vector<NavEntry>{{5, 1}, {10, 0}});
    CHECK(nav_decode("99999999999999999999:0 3:0", 100) == std::vector<NavEntry>{{3, 0}});

    NavHistory h;
    std::vector<NavEntry> big;
    for (uint64_t i = 0; i < NavHistory::kMax + 10; ++i) big.push_back({i, 0});
    h.set_stacks(big, {{7, 1}});
    REQUIRE(h.back_stack().size() == NavHistory::kMax);
    CHECK(h.back_stack().front().offset == 10);  // the oldest entries are dropped
    CHECK(h.back_stack().back().offset == NavHistory::kMax + 9);
    REQUIRE(h.forward_stack().size() == 1);
    CHECK(h.forward(NavEntry{50, 0}) == NavEntry{7, 1});
    CHECK(h.back(NavEntry{7, 1}) == NavEntry{50, 0});
    h.set_stacks({}, {});
    CHECK_FALSE(h.can_back());
    CHECK_FALSE(h.can_forward());
}
