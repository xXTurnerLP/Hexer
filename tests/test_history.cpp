// Tests for the History panel's core helpers (ui/panel_history.h, no ImGui): rows, labels, the
// changed-range diff and history_jump() vs. repeated undo()/redo().
#include "ui/panel_history.h"

#include <doctest/doctest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "core/document.h"

using namespace hx;
namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

namespace {

std::string u8(const fs::path& p) {
    auto s = p.u8string();
    return std::string(s.begin(), s.end());
}

struct TempDir {
    fs::path dir;
    TempDir() {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("hexer-history-" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(dir);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    std::string file(const std::string& name) const { return u8(dir / name); }
};

void write_file(const std::string& path, const Bytes& b) {
    std::ofstream f(fs::path(std::u8string(path.begin(), path.end())), std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(b.data()), std::streamsize(b.size()));
}

Bytes doc_bytes(const Document& d) {
    Bytes b(size_t(d.size()));
    if (!b.empty()) REQUIRE(d.read(0, b.data(), b.size()) == b.size());
    return b;
}

Bytes str_bytes(const char* s) { return Bytes(s, s + std::strlen(s)); }

int64_t g_fake_ms = 0;
int64_t fake_clock() { return g_fake_ms; }
struct FakeClock {
    FakeClock() {
        g_fake_ms = 1000;
        Document::set_clock_for_tests(&fake_clock);
        Document::set_undo_merge(500, 32);
    }
    ~FakeClock() {
        Document::set_clock_for_tests(nullptr);
        Document::set_undo_merge(500, 32);
    }
};

// Everything a history step restores.
struct State {
    Bytes bytes;
    uint64_t cursor = 0, anchor = 0, state_id = 0;
    std::vector<std::string> bookmarks;  // "offset:length:name"
    bool operator==(const State&) const = default;
};

State state_of(const Document& d) {
    State s;
    s.bytes = doc_bytes(d);
    s.cursor = d.view().cursor;
    s.anchor = d.view().anchor;
    s.state_id = d.state_id();
    for (const Bookmark& b : d.view().bookmarks)
        s.bookmarks.push_back(std::to_string(b.offset) + ":" + std::to_string(b.length) + ":" + b.name);
    return s;
}

void set_caret(Document& d, uint64_t cursor, uint64_t anchor) {
    d.view().cursor = cursor;
    d.view().anchor = anchor;
}

// A deterministic mix of actions on `d`. states[k] = the state history row k stands for (recorded
// right before action k+1, i.e. including the caret moves made after action k).
std::vector<State> build_history(Document& d, std::vector<std::string>* labels) {
    FakeClock clock;
    std::vector<State> states;
    auto step = [&](const char* label) {
        states.push_back(state_of(d));
        if (labels) labels->push_back(label);
    };
    const uint8_t ab[] = {'A', 'B'};
    const uint8_t z = 0;
    set_caret(d, 2, 2);
    step("Original");
    REQUIRE(d.overwrite(2, ab, 2));
    set_caret(d, 5, 5);
    step("Overwrite");
    REQUIRE(d.insert(5, ab, 2));
    set_caret(d, 1, 3);
    step("Insert");
    REQUIRE(d.erase(1, 2));
    set_caret(d, 0, 4);
    step("Delete");
    REQUIRE(d.fill(0, 4, &z, 1));
    Bookmark b;
    b.offset = 3;
    b.name = "mark";
    step("Fill");
    REQUIRE(d.add_bookmark(b));
    set_caret(d, 6, 6);
    step("Add bookmark");
    // One coalesced typing run of 3 bytes, then (after a pause) another one.
    for (uint64_t i = 0; i < 3; ++i) {
        const uint8_t c = uint8_t('x' + i);
        REQUIRE(d.overwrite(6 + i, &c, 1, true));
        g_fake_ms += 100;
        set_caret(d, 7 + i, 7 + i);
    }
    step("Typing");
    g_fake_ms += 5000;
    for (uint64_t i = 0; i < 2; ++i) {
        const uint8_t c = uint8_t('q' + i);
        REQUIRE(d.insert(1 + i, &c, 1, true));
        g_fake_ms += 100;
    }
    set_caret(d, 3, 3);
    step("Typing");
    d.begin_group("Script: demo");
    REQUIRE(d.overwrite(0, ab, 2));
    REQUIRE(d.erase(d.size() - 1, 1));
    d.end_group();
    set_caret(d, 0, 0);
    step("Script: demo");
    return states;
}

std::unique_ptr<Document> open_sample(const TempDir& t, const char* name) {
    const std::string p = t.file(name);
    write_file(p, str_bytes("0123456789abcdefghij"));
    auto d = Document::open_file(p);
    REQUIRE(d);
    return d;
}

}  // namespace

TEST_CASE("history rows, labels and jumps match the recorded states") {
    TempDir t;
    auto d = open_sample(t, "a.bin");
    std::vector<std::string> labels;
    const std::vector<State> states = build_history(*d, &labels);
    const size_t n = states.size();
    REQUIRE(d->undo_stack().size() == n - 1);  // the two typing runs stayed two steps
    CHECK(history_count(*d) == n);
    CHECK(history_current(*d) == n - 1);
    for (size_t k = 0; k < n; ++k) CHECK(history_label(*d, k) == labels[k]);
    CHECK(history_state_id(*d, n - 1) == d->state_id());
    CHECK(history_entry(*d, n - 1) == nullptr);

    // Visit every row in a scrambled order; each lands exactly on the recorded state.
    const size_t order[] = {0, 8, 3, 3, 7, 1, 6, 2, 5, 4, 0, 8};
    for (size_t k : order) {
        if (k >= n) continue;
        CAPTURE(k);
        REQUIRE(history_jump(*d, k));
        CHECK(history_current(*d) == k);
        CHECK(history_count(*d) == n);  // moving never loses steps
        CHECK(d->undo_stack().size() == k);
        CHECK(d->redo_stack().size() == n - 1 - k);
        CHECK(state_of(*d) == states[k]);
        for (size_t r = 0; r < n; ++r) CHECK(history_label(*d, r) == labels[r]);
    }
    CHECK_FALSE(history_jump(*d, n));  // out of range
}

TEST_CASE("history_jump equals repeated Ctrl+Z / Ctrl+Y") {
    TempDir t;
    auto a = open_sample(t, "a.bin");
    auto b = open_sample(t, "b.bin");
    build_history(*a, nullptr);
    build_history(*b, nullptr);
    const size_t n = history_count(*a);
    std::mt19937 rng(7);
    for (int i = 0; i < 40; ++i) {
        const size_t target = rng() % n;
        CAPTURE(target);
        REQUIRE(history_jump(*a, target));
        while (b->undo_stack().size() > target) REQUIRE(b->undo());
        while (b->undo_stack().size() < target) REQUIRE(b->redo());
        State sa = state_of(*a), sb = state_of(*b);
        sa.state_id = sb.state_id = 0;  // ids differ between documents
        CHECK(sa == sb);
        CHECK(a->undo_stack().size() == b->undo_stack().size());
        CHECK(a->redo_stack().size() == b->redo_stack().size());
        CHECK(a->dirty() == b->dirty());
    }
}

TEST_CASE("history survives saves and marks the saved state") {
    TempDir t;
    for (bool rewrite : {false, true}) {
        CAPTURE(rewrite);
        auto d = open_sample(t, rewrite ? "rw.bin" : "ip.bin");
        const uint64_t opened = d->saved_state_id();
        CHECK(history_state_id(*d, 0) == opened);  // a fresh document: row 0 is the saved state
        FakeClock clock;
        const uint8_t ab[] = {'A', 'B'};
        std::vector<State> states{state_of(*d)};
        REQUIRE(d->overwrite(4, ab, 2));
        states.push_back(state_of(*d));
        if (rewrite) {
            REQUIRE(d->insert(0, ab, 2));  // forces the rewrite path
        } else {
            REQUIRE(d->overwrite(10, ab, 2));  // still in-place compatible
        }
        states.push_back(state_of(*d));
        std::string err;
        REQUIRE(d->save(nullptr, &err));
        CHECK_FALSE(d->dirty());
        const size_t saved_row = history_current(*d);
        CHECK(history_state_id(*d, saved_row) == d->saved_state_id());
        REQUIRE(d->overwrite(1, ab, 1));
        states.push_back(state_of(*d));
        REQUIRE(d->erase(0, 1));
        states.push_back(state_of(*d));
        const size_t n = states.size();
        REQUIRE(history_count(*d) == n);
        for (size_t k : {size_t(0), saved_row, size_t(1), n - 1, saved_row + 1, size_t(0), n - 1}) {
            CAPTURE(k);
            REQUIRE(history_jump(*d, k));
            CHECK(state_of(*d).bytes == states[k].bytes);
            CHECK(d->dirty() == (k != saved_row));
            // Exactly one row carries the saved state id.
            size_t marked = 0;
            for (size_t r = 0; r < history_count(*d); ++r) marked += history_state_id(*d, r) == d->saved_state_id();
            CHECK(marked == 1);
            CHECK(history_state_id(*d, saved_row) == d->saved_state_id());
        }
    }
}

TEST_CASE("history_diff finds the changed range") {
    TempDir t;
    auto d = open_sample(t, "a.bin");  // 20 bytes
    const uint8_t ab[] = {'A', 'B', 'C'};
    REQUIRE(d->overwrite(5, ab, 3));
    REQUIRE(d->insert(12, ab, 2));
    REQUIRE(d->erase(0, 2));
    Bookmark b;
    b.offset = 1;
    REQUIRE(d->add_bookmark(b));
    REQUIRE(d->overwrite(d->size(), ab, 1));  // append at EOF
    REQUIRE(history_count(*d) == 6);

    HistoryChange c = history_row_change(*d, 1);  // overwrite 3 at 5
    CHECK(c.known);
    CHECK_FALSE(c.same);
    CHECK(c.offset == 5);
    CHECK(c.old_len == 3);
    CHECK(c.new_len == 3);
    c = history_row_change(*d, 2);  // insert 2 at 12
    CHECK(c.offset == 12);
    CHECK(c.old_len == 0);
    CHECK(c.new_len == 2);
    c = history_row_change(*d, 3);  // erase 2 at 0
    CHECK(c.offset == 0);
    CHECK(c.old_len == 2);
    CHECK(c.new_len == 0);
    c = history_row_change(*d, 4);  // bookmark only
    CHECK(c.known);
    CHECK(c.same);
    c = history_row_change(*d, 5);  // append
    CHECK(c.offset == 20);
    CHECK(c.old_len == 0);
    CHECK(c.new_len == 1);
    CHECK(history_row_change(*d, 0).same);

    // Across several steps (what a click jumps over): first to last differing byte.
    c = history_diff(history_pieces(*d, 0), history_pieces(*d, 3));
    CHECK(c.offset == 0);
    CHECK(c.new_len == 12);  // bytes 0..11 of the new state differ (shifted by the erase)
    // Identical piece lists.
    c = history_diff(history_pieces(*d, 2), history_pieces(*d, 2));
    CHECK(c.same);
    // The comparison gives up instead of walking huge piece lists.
    std::vector<Piece> many(100), other(100);
    for (size_t i = 0; i < many.size(); ++i) {
        many[i] = Piece{Piece::Add, 0, i * 2, 1};
        other[i] = Piece{Piece::Add, 0, i * 2, 1};
    }
    other[50].start = 1001;
    c = history_diff(many, other, 10);
    CHECK_FALSE(c.known);
    c = history_diff(many, other);
    CHECK(c.known);
    CHECK(c.offset == 50);
    CHECK(c.old_len == 1);
    CHECK(c.new_len == 1);
}

TEST_CASE("history_jump is refused when undo is") {
    TempDir t;
    auto d = open_sample(t, "a.bin");
    const uint8_t ab[] = {'A', 'B'};
    REQUIRE(d->overwrite(0, ab, 2));
    REQUIRE(d->overwrite(4, ab, 2));
    d->set_read_only(true);
    CHECK_FALSE(history_jump(*d, 0));
    CHECK(history_current(*d) == 2);
    d->set_read_only(false);
    d->begin_group("x");
    CHECK_FALSE(history_jump(*d, 0));
    d->end_group();
    CHECK(history_jump(*d, 0));
    CHECK(history_jump(*d, 1));
    CHECK(history_current(*d) == 1);
}

TEST_CASE("history_jump over hundreds of steps is fast") {
    TempDir t;
    auto d = open_sample(t, "a.bin");
    const int kSteps = 1000;
    for (int i = 0; i < kSteps; ++i) {
        const uint8_t c = uint8_t(i);
        REQUIRE(d->insert(uint64_t(i) * 7919 % d->size(), &c, 1));  // scattered: the piece list grows
    }
    REQUIRE(history_count(*d) == size_t(kSteps) + 1);
    const Bytes last = doc_bytes(*d);
    const auto t0 = std::chrono::steady_clock::now();
    REQUIRE(history_jump(*d, 0));
    REQUIRE(history_jump(*d, size_t(kSteps)));
    const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    MESSAGE("2 x " << kSteps << " history steps (" << d->table().pieces().size() << " pieces): " << ms << " ms");
    CHECK(ms < 2000.0);
    CHECK(doc_bytes(*d) == last);
    CHECK(d->undo_stack().size() == size_t(kSteps));
    CHECK(d->redo_stack().empty());
}

TEST_CASE("history_jump and history_diff on random edit sequences") {
    TempDir t;
    FakeClock clock;
    for (uint32_t seed = 1; seed <= 12; ++seed) {
        CAPTURE(seed);
        Bytes init(300);
        for (size_t i = 0; i < init.size(); ++i) init[i] = uint8_t(i * 37 + seed);
        const std::string pa = t.file("ra" + std::to_string(seed)), pb = t.file("rb" + std::to_string(seed));
        write_file(pa, init);
        write_file(pb, init);
        auto a = Document::open_file(pa);
        auto b = Document::open_file(pb);
        REQUIRE(a);
        REQUIRE(b);
        std::mt19937 rng(seed);
        auto rnd = [&](uint64_t n) { return n ? uint64_t(rng() % n) : 0; };
        auto check_twins = [&]() {
            State sa = state_of(*a), sb = state_of(*b);
            sa.state_id = sb.state_id = 0;
            CHECK(sa == sb);
            CHECK(a->undo_stack().size() == b->undo_stack().size());
            CHECK(a->redo_stack().size() == b->redo_stack().size());
            CHECK(a->dirty() == b->dirty());
        };
        for (int op = 0; op < 120; ++op) {
            const uint64_t size = a->size();
            const int kind = int(rnd(10));
            uint8_t buf[8];
            for (auto& v : buf) v = uint8_t(rng());
            const size_t n = size_t(1 + rnd(sizeof buf));
            const uint64_t at = rnd(size + 1);
            const uint64_t cur = rnd(size + 1), anc = rnd(size + 1);
            set_caret(*a, cur, anc);
            set_caret(*b, cur, anc);
            bool ra = true, rb = true;
            switch (kind) {
            case 0: ra = a->overwrite(at, buf, n); rb = b->overwrite(at, buf, n); break;
            case 1: ra = a->insert(at, buf, n); rb = b->insert(at, buf, n); break;
            case 2:
                if (at < size) {
                    const uint64_t len = 1 + rnd(std::min<uint64_t>(size - at, 20));
                    ra = a->erase(at, len);
                    rb = b->erase(at, len);
                }
                break;
            case 3:
                if (at < size) {
                    const uint64_t len = 1 + rnd(std::min<uint64_t>(size - at, 40));
                    ra = a->fill(at, len, buf, n);
                    rb = b->fill(at, len, buf, n);
                }
                break;
            case 4: {
                Bookmark bm;
                bm.offset = at;
                bm.name = "m" + std::to_string(op);
                ra = a->add_bookmark(bm);
                rb = b->add_bookmark(bm);
                break;
            }
            case 5:  // a short typing run (coalesced into one step)
                for (size_t i = 0; i < n && at + i <= a->size(); ++i) {
                    ra = a->overwrite(at + i, buf + i, 1, true) && ra;
                    rb = b->overwrite(at + i, buf + i, 1, true) && rb;
                    g_fake_ms += 50;
                }
                g_fake_ms += 5000;
                break;
            case 6: {  // undo / redo a few steps by hand on both
                const int k = int(rnd(4));
                for (int i = 0; i < k; ++i) {
                    if (rng() & 1) {
                        ra = a->undo();
                        rb = b->undo();
                    } else {
                        ra = a->redo();
                        rb = b->redo();
                    }
                    CHECK(ra == rb);
                }
                ra = rb = true;
                break;
            }
            case 7:
                if (op % 3 == 0) {  // occasional save (in place or rewrite, synchronously)
                    std::string err;
                    ra = a->save(nullptr, &err);
                    rb = b->save(nullptr, &err);
                }
                break;
            default: {  // jump to a random row: equals repeated Ctrl+Z / Ctrl+Y on the twin
                const size_t rows = history_count(*a);
                const size_t from = history_current(*a), target = size_t(rnd(rows));
                CAPTURE(op);
                CAPTURE(target);
                const Bytes before = doc_bytes(*a);
                const HistoryChange c = history_diff(history_pieces(*a, from), history_pieces(*a, target));
                REQUIRE(history_jump(*a, target));
                CHECK(history_current(*a) == target);
                CHECK(history_count(*a) == rows);
                while (b->undo_stack().size() > target) REQUIRE(b->undo());
                while (b->undo_stack().size() < target) REQUIRE(b->redo());
                // The reported range covers every differing byte.
                const Bytes after = doc_bytes(*a);
                REQUIRE(c.known);
                REQUIRE(c.offset <= std::min(before.size(), after.size()));
                CHECK(before.size() - c.old_len == after.size() - c.new_len);
                CHECK(std::equal(before.begin(), before.begin() + ptrdiff_t(c.offset), after.begin()));
                const size_t suf = after.size() - size_t(c.offset + c.new_len);
                CHECK(std::equal(before.end() - ptrdiff_t(suf), before.end(), after.end() - ptrdiff_t(suf)));
                if (c.same) CHECK(before == after);
                break;
            }
            }
            CHECK(ra == rb);
            check_twins();
        }
    }
}
