#include <doctest/doctest.h>

#include <cstdint>
#include <memory>
#include <vector>

#include "core/document.h"
#include "core/nav.h"

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

    // invalid widths
    CHECK(!decode_pointer(*doc, 0, 0, false, 0, t));
    CHECK(!decode_pointer(*doc, 0, 3, false, 0, t));
    CHECK(!decode_pointer(*doc, 0, 16, false, 0, t));
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
