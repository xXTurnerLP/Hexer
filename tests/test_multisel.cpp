// Multi-selection (core/multisel.h): range sets, the selection of a document and every operation on
// all ranges as one undo step (Document::fill_ranges).
#include "core/multisel.h"

#include <doctest/doctest.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "core/document.h"
#include "core/util.h"

using namespace hx;
using Bytes = std::vector<uint8_t>;
using Ranges = std::vector<ByteRange>;

namespace {

Bytes doc_bytes(const Document& d) {
    Bytes b(size_t(d.size()));
    if (!b.empty()) REQUIRE(d.read(0, b.data(), b.size()) == b.size());
    return b;
}

Bytes str_bytes(const char* s) { return Bytes(s, s + std::strlen(s)); }

std::unique_ptr<Document> make_doc(const char* s) {
    const Bytes b = str_bytes(s);
    return Document::create_from_bytes("t", b.data(), b.size());
}

// Primary [pb, pe) + extras.
void select(Document& d, uint64_t pb, uint64_t pe, Ranges extras) {
    d.view().anchor = pb;
    d.view().cursor = pe;
    d.view().extra_sel = range_normalize(std::move(extras));
}

}  // namespace

TEST_CASE("multisel: range_add merges touching and overlapping ranges") {
    Ranges s;
    range_add(s, {10, 20});
    range_add(s, {30, 40});
    CHECK(s == Ranges{{10, 20}, {30, 40}});
    range_add(s, {0, 5});
    range_add(s, {50, 60});
    CHECK(s == Ranges{{0, 5}, {10, 20}, {30, 40}, {50, 60}});
    range_add(s, {5, 5});  // empty: ignored
    CHECK(s.size() == 4);
    range_add(s, {5, 10});  // touches both neighbours: one range
    CHECK(s == Ranges{{0, 20}, {30, 40}, {50, 60}});
    range_add(s, {32, 35});  // inside
    CHECK(s == Ranges{{0, 20}, {30, 40}, {50, 60}});
    range_add(s, {25, 55});  // swallows one, overlaps the next
    CHECK(s == Ranges{{0, 20}, {25, 60}});
    range_add(s, {21, 22});
    CHECK(s == Ranges{{0, 20}, {21, 22}, {25, 60}});
    range_add(s, {0, 100});
    CHECK(s == Ranges{{0, 100}});
    range_add(s, {UINT64_MAX - 2, UINT64_MAX});  // 64-bit offsets
    CHECK(s == Ranges{{0, 100}, {UINT64_MAX - 2, UINT64_MAX}});
}

TEST_CASE("multisel: range_find, range_clamp, range_total, range_normalize") {
    Ranges s{{10, 20}, {30, 40}};
    CHECK(range_find(s, 9) == 2);
    CHECK(range_find(s, 10) == 0);
    CHECK(range_find(s, 19) == 0);
    CHECK(range_find(s, 20) == 2);
    CHECK(range_find(s, 35) == 1);
    CHECK(range_find(s, 40) == 2);
    CHECK(range_find({}, 0) == 0);
    CHECK(range_total(s) == 20);

    Ranges c = s;
    range_clamp(c, 35);
    CHECK(c == Ranges{{10, 20}, {30, 35}});
    range_clamp(c, 30);
    CHECK(c == Ranges{{10, 20}});
    range_clamp(c, 0);
    CHECK(c.empty());

    CHECK(range_normalize({{30, 40}, {5, 5}, {10, 20}, {15, 31}, {50, 51}, {51, 52}}) == Ranges{{10, 40}, {50, 52}});
    CHECK(range_normalize({}).empty());
}

TEST_CASE("multisel: selection ranges of a view (primary + extras)") {
    auto d = make_doc("0123456789abcdefghij");
    ViewState& v = d->view();
    select(*d, 2, 4, {});
    CHECK_FALSE(has_extra_selections(v));
    CHECK(selection_ranges(v, d->size()) == Ranges{{2, 4}});
    select(*d, 4, 4, {});
    CHECK(selection_ranges(v, d->size()).empty());

    select(*d, 12, 10, {{0, 2}, {15, 18}});  // backward primary
    CHECK(has_extra_selections(v));
    CHECK(selection_ranges(v, d->size()) == Ranges{{0, 2}, {10, 12}, {15, 18}});
    CHECK(selection_ranges_primary_first(v, d->size()) == Ranges{{10, 12}, {0, 2}, {15, 18}});
    select(*d, 1, 3, {{0, 2}, {15, 18}});    // overlapping the primary: one merged range
    CHECK(selection_ranges(v, d->size()) == Ranges{{0, 3}, {15, 18}});
    CHECK(selection_ranges_primary_first(v, d->size()) == Ranges{{0, 3}, {15, 18}});
    CHECK(selection_ranges(v, 16) == Ranges{{0, 3}, {15, 16}});  // clamped
    select(*d, 5, 5, {{0, 2}});              // empty primary: only the extras
    CHECK(selection_ranges(v, d->size()) == Ranges{{0, 2}});
    CHECK(selection_ranges_primary_first(v, d->size()) == Ranges{{0, 2}});

    // Add Selection: the primary joins the extras and collapses to the caret.
    select(*d, 6, 8, {{0, 2}});
    CHECK(add_primary_to_extras(v));
    CHECK(v.extra_sel == Ranges{{0, 2}, {6, 8}});
    CHECK_FALSE(v.has_selection());
    CHECK(v.cursor == 8);
    CHECK_FALSE(add_primary_to_extras(v));

    // set_selection_ranges: first = primary, rest = extras (clamped, merged, empty ones dropped).
    CHECK(set_selection_ranges(v, {{4, 6}, {10, 12}, {11, 14}, {1, 1}, {18, 99}}, d->size()));
    CHECK(v.anchor == 4);
    CHECK(v.cursor == 6);
    CHECK(v.extra_sel == Ranges{{10, 14}, {18, 20}});
    CHECK(set_selection_ranges(v, {}, d->size()));
    CHECK(v.extra_sel.empty());
    CHECK_FALSE(v.has_selection());
    std::string err;
    CHECK_FALSE(set_selection_ranges(v, Ranges(kMaxSelections + 1, ByteRange{0, 1}), d->size(), &err));
    CHECK(err.find("too many") != std::string::npos);
}

TEST_CASE("multisel: delete every range is one undo step") {
    auto d = make_doc("AAxxBBByyCCzz");
    select(*d, 2, 4, {{7, 9}, {11, 13}});
    const size_t steps = d->undo_stack().size();
    std::string err;
    REQUIRE(erase_selections(*d, &err));
    CHECK(doc_bytes(*d) == str_bytes("AABBBCC"));
    CHECK(d->undo_stack().size() == steps + 1);
    CHECK(d->undo_stack().back().label == "Delete 3 ranges");
    CHECK(d->view().cursor == 2);
    CHECK_FALSE(d->view().has_selection());
    CHECK(d->view().extra_sel.empty());
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == str_bytes("AAxxBBByyCCzz"));
    CHECK(d->view().sel_begin() == 2);  // the primary selection comes back
    CHECK(d->view().sel_end() == 4);
    REQUIRE(d->redo());
    CHECK(doc_bytes(*d) == str_bytes("AABBBCC"));
}

TEST_CASE("multisel: fill every range from the pattern start, one undo step") {
    auto d = make_doc("0123456789abcdefghij");
    select(*d, 10, 15, {{0, 3}, {18, 20}});
    const uint8_t pat[] = {'X', 'Y'};
    REQUIRE(fill_selections(*d, pat, 2));
    CHECK(doc_bytes(*d) == str_bytes("XYX3456789XYXYXfghXY"));
    CHECK(d->undo_stack().back().label == "Fill 3 ranges");
    CHECK(d->size() == 20);
    CHECK(d->view().extra_sel == Ranges{{0, 3}, {18, 20}});  // the selection stays
    CHECK(d->view().sel_begin() == 10);
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == str_bytes("0123456789abcdefghij"));
    std::string err;
    CHECK_FALSE(fill_selections(*d, pat, 0, &err));
}

TEST_CASE("multisel: fill of ranges larger than an add-buffer chunk keeps the pattern phase") {
    const uint64_t n = 3 * AddBuffer::kChunkSize + 7;
    Bytes zero(size_t(n + 100), 0);
    auto d = Document::create_from_bytes("big", zero.data(), zero.size());
    select(*d, 1, 1 + n, {{n + 50, n + 53}});
    const uint8_t pat[] = {1, 2, 3};
    REQUIRE(fill_selections(*d, pat, 3));
    const Bytes b = doc_bytes(*d);
    CHECK(b[0] == 0);
    bool ok = true;
    for (uint64_t i = 0; i < n && ok; ++i) ok = b[size_t(1 + i)] == pat[i % 3];
    CHECK(ok);
    CHECK(b[size_t(n + 1)] == 0);
    CHECK(b[size_t(n + 50)] == 1);
    CHECK(b[size_t(n + 52)] == 3);
    CHECK(b[size_t(n + 53)] == 0);
    CHECK(d->table().pieces().size() < 64);  // the block is referenced, not copied per range
}

TEST_CASE("multisel: paste into every range needs matching lengths") {
    auto d = make_doc("0123456789abcdef");
    select(*d, 4, 6, {{0, 2}, {10, 12}});
    const size_t steps = d->undo_stack().size();
    std::string err;
    const Bytes three = str_bytes("XYZ");
    CHECK_FALSE(paste_selections(*d, three.data(), three.size(), &err));
    CHECK(err.find("3 bytes") != std::string::npos);
    CHECK(d->undo_stack().size() == steps);  // refused: no step, nothing changed
    CHECK(doc_bytes(*d) == str_bytes("0123456789abcdef"));
    const Bytes two = str_bytes("--");
    REQUIRE(paste_selections(*d, two.data(), two.size(), &err));
    CHECK(doc_bytes(*d) == str_bytes("--23--6789--cdef"));
    CHECK(d->undo_stack().size() == steps + 1);
    CHECK(d->undo_stack().back().label == "Paste into 3 ranges");
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == str_bytes("0123456789abcdef"));
}

TEST_CASE("multisel: bookmark every range in one undo step") {
    auto d = make_doc("0123456789abcdef");
    Bookmark old;
    old.offset = 15;
    old.name = "old";
    REQUIRE(d->add_bookmark(old));
    select(*d, 4, 6, {{0, 2}, {10, 13}});
    const size_t steps = d->undo_stack().size();
    std::string err;
    CHECK(bookmark_selections(*d, &err) == 3);
    const auto& bms = d->view().bookmarks;
    REQUIRE(bms.size() == 4);
    CHECK(bms[1].offset == 0);
    CHECK(bms[1].length == 2);
    CHECK(bms[1].name == "Selection 2");
    CHECK(bms[2].offset == 4);
    CHECK(bms[3].offset == 10);
    CHECK(bms[3].length == 3);
    CHECK(bms[3].name == "Selection 4");
    CHECK(d->undo_stack().size() == steps + 1);
    CHECK(d->undo_stack().back().label == "Bookmark 3 selections");
    REQUIRE(d->undo());
    CHECK(d->view().bookmarks.size() == 1);

    // Too many: refused, nothing added.
    Ranges many;
    for (uint64_t i = 0; i <= kMaxSelectionBookmarks; ++i) many.push_back({i * 2, i * 2 + 1});
    Bytes big(size_t(kMaxSelectionBookmarks * 2 + 4), 0);
    auto b = Document::create_from_bytes("big", big.data(), big.size());
    select(*b, 0, 0, many);
    CHECK(bookmark_selections(*b, &err) == 0);
    CHECK(err.find("not supported") != std::string::npos);
    CHECK(b->view().bookmarks.empty());
    CHECK(b->undo_stack().empty());
}

TEST_CASE("multisel: copy joins the ranges by newline") {
    auto d = make_doc("ABCDEFGHIJ");
    select(*d, 4, 6, {{0, 2}, {8, 10}});
    std::string out, err;
    REQUIRE(copy_selections(*d, CopyFormat::Text, 1000, out, &err));
    CHECK(out == "AB\nEF\nIJ");
    REQUIRE(copy_selections(*d, CopyFormat::HexSpaced, 1000, out, &err));
    CHECK(out == "41 42\n45 46\n49 4A");
    CHECK_FALSE(copy_selections(*d, CopyFormat::Text, 5, out, &err));  // 6 bytes in all
    CHECK(err.find("Copying more than") != std::string::npos);
}

TEST_CASE("multisel: fill_ranges validates its input and respects read-only") {
    auto d = make_doc("0123456789");
    const uint8_t x = 'x';
    std::string err;
    CHECK_FALSE(d->fill_ranges({{4, 6}, {2, 3}}, &x, 1, "t", &err));  // unsorted
    CHECK_FALSE(d->fill_ranges({{2, 5}, {4, 6}}, &x, 1, "t", &err));  // overlapping
    CHECK_FALSE(d->fill_ranges({{2, 2}}, &x, 1, "t", &err));          // empty
    CHECK_FALSE(d->fill_ranges({{8, 11}}, &x, 1, "t", &err));         // past the end
    CHECK(d->undo_stack().empty());
    CHECK(d->fill_ranges({}, &x, 1, "t", &err));                      // nothing to do
    CHECK(d->undo_stack().empty());
    CHECK(d->fill_ranges({{2, 4}, {4, 5}}, &x, 1, "t", &err));        // touching is fine
    CHECK(doc_bytes(*d) == str_bytes("01xxx56789"));
    d->set_read_only(true);
    CHECK_FALSE(d->fill_ranges({{0, 1}}, nullptr, 0, "t", &err));
    CHECK(err.find("read-only") != std::string::npos);
    CHECK(doc_bytes(*d) == str_bytes("01xxx56789"));
}

TEST_CASE("multisel: 100k ranges over an edited document in one pass") {
    const size_t n = 400000;
    Bytes b(n);
    for (size_t i = 0; i < n; ++i) b[i] = uint8_t(i);
    auto d = Document::create_from_bytes("big", b.data(), b.size());
    const uint8_t one = 0xEE;
    REQUIRE(d->overwrite(1, &one, 1));  // a few pieces to split
    REQUIRE(d->overwrite(n - 2, &one, 1));
    Ranges rs;
    for (uint64_t i = 0; i < kMaxSelections; ++i) rs.push_back({i * 4, i * 4 + 2});  // delete bytes 0, 1 of every 4
    select(*d, 0, 0, rs);
    REQUIRE(erase_selections(*d));
    CHECK(d->size() == n / 2);
    const Bytes got = doc_bytes(*d);
    bool ok = true;
    for (size_t i = 0; i < got.size() && ok; ++i) {
        const size_t src = (i / 2) * 4 + 2 + i % 2;
        const uint8_t want = src == n - 2 ? one : uint8_t(src);
        ok = got[i] == want;
    }
    CHECK(ok);
    REQUIRE(d->undo());
    CHECK(d->size() == n);
}

TEST_CASE("multisel: a size change clamps the extra ranges; undo keeps them") {
    auto d = make_doc("0123456789");
    select(*d, 0, 0, {{2, 3}, {6, 9}});
    REQUIRE(d->erase(5, 5));
    CHECK(d->view().extra_sel == Ranges{{2, 3}});
    d->view().extra_sel = {{1, 2}};
    REQUIRE(d->undo());
    CHECK(d->view().extra_sel == Ranges{{1, 2}});  // transient view state, not in the history
}
