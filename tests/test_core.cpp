// Tests for src/core: os_file, file_source, piece_table, highlight, document, session.
#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <thread>

#include "core/document.h"
#include "core/file_source.h"
#include "core/highlight.h"
#include "core/os_file.h"
#include "core/piece_table.h"
#include "core/session.h"

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#endif

using namespace hx;
namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

namespace {

fs::path from_u8(const std::string& s) { return fs::path(std::u8string(s.begin(), s.end())); }

std::string u8(const fs::path& p) {
    auto s = p.u8string();
    return std::string(s.begin(), s.end());
}

struct TempDir {
    fs::path dir;
    TempDir() {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("hexer-test-" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(dir);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    std::string file(const std::string& name) const { return u8(dir / name); }
};

Bytes random_bytes(size_t n, uint64_t seed) {
    std::mt19937_64 rng(seed);
    Bytes b(n);
    for (auto& x : b) x = uint8_t(rng());
    return b;
}

void write_file(const std::string& path, const Bytes& b) {
    std::ofstream f(from_u8(path), std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(b.data()), std::streamsize(b.size()));
}

Bytes read_file(const std::string& path) {
    std::ifstream f(from_u8(path), std::ios::binary);
    return Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

Bytes doc_bytes(const Document& d) {
    Bytes b(size_t(d.size()));
    if (!b.empty()) REQUIRE(d.read(0, b.data(), b.size()) == b.size());
    return b;
}

Bytes str_bytes(const char* s) { return Bytes(s, s + std::strlen(s)); }

bool tmp_left_over(const TempDir& t) {
    for (auto& e : fs::directory_iterator(t.dir))
        if (e.path().string().find(".hexer-tmp") != std::string::npos) return true;
    return false;
}

// Deterministic clock for typing-run coalescing; restores the real clock and default limits.
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

// Sets the app-wide backup policy for one test case; restores the defaults.
struct BackupPolicy {
    BackupPolicy(bool enabled, uint64_t max_bytes) { Document::set_backup_policy(enabled, max_bytes); }
    ~BackupPolicy() { Document::set_backup_policy(true, 4ull << 30); }
};

}  // namespace

// =============================================================================================
// os_file
// =============================================================================================
TEST_CASE("os_file: path helpers") {
    CHECK(path_filename("c:/x/y.bin") == "y.bin");
    CHECK(path_dirname("c:/x/y.bin") == "c:/x");
    CHECK(path_extension("y.BIN") == "bin");
    CHECK(path_extension("noext") == "");
    CHECK(path_extension(".bashrc") == "");
    CHECK(path_filename("/a/b") == "b");
    CHECK(path_dirname("/a") == "/");
    CHECK(path_dirname("plain") == "");
    CHECK(path_join("a", "b").size() == 3);
    CHECK(path_join("a/", "b") == "a/b");
    CHECK(path_join("", "b") == "b");
#ifdef _WIN32
    CHECK(path_filename("c:\\x\\y.bin") == "y.bin");
    CHECK(path_dirname("c:\\x\\y.bin") == "c:\\x");
    CHECK(path_dirname("c:\\y.bin") == "c:\\");
    CHECK(path_filename("c:y.bin") == "y.bin");
    CHECK(wide_to_utf8(utf8_to_wide("h\xC3\xA9llo \xE2\x82\xAC")) == "h\xC3\xA9llo \xE2\x82\xAC");
#endif
}

TEST_CASE("os_file: read/write/stat/replace/list") {
    TempDir t;
    std::string p = t.file("a.bin");
    {
        auto f = OsFile::open(p, OsFile::Mode::CreateTruncate);
        REQUIRE(f);
        Bytes b = random_bytes(100000, 1);
        CHECK(f->write_at(0, b.data(), b.size()));
        CHECK(f->size() == 100000);
        Bytes r(200000);
        CHECK(f->read_at(0, r.data(), r.size()) == 100000);  // short only at EOF
        CHECK(std::equal(b.begin(), b.end(), r.begin()));
        CHECK(f->read_at(200000, r.data(), 10) == 0);
        CHECK(f->truncate(10));
        CHECK(f->size() == 10);
        CHECK(f->flush());
    }
    FileStat st = os_stat(p);
    CHECK(st.exists);
    CHECK(!st.is_dir);
    CHECK(st.size == 10);
    CHECK(st.mtime_ns != 0);
    CHECK(os_stat(t.file("nope")).exists == false);
    CHECK(os_stat(u8(t.dir)).is_dir);
    std::string err;
    CHECK(!OsFile::open(t.file("nope"), OsFile::Mode::Read, &err));
    CHECK(!err.empty());

    // Replace a file that is held open for reading: the open handle keeps the old bytes.
    write_file(p, str_bytes("old contents"));
    auto held = OsFile::open(p, OsFile::Mode::Read);
    REQUIRE(held);
    std::string q = t.file("b.tmp");
    write_file(q, str_bytes("new!"));
    REQUIRE(os_replace_file(q, p, &err));
    CHECK(!os_stat(q).exists);
    CHECK(read_file(p) == str_bytes("new!"));
    char buf[16] = {};
    CHECK(held->read_at(0, buf, 3) == 3);  // NTFS POSIX semantics / POSIX rename
    CHECK(std::string(buf, 3) == "old");

    std::string unicode = t.file("\xC3\xA9t\xC3\xA9.lua");
    CHECK(os_write_whole_atomic(unicode, "x=1", 3));
    std::string got;
    CHECK(os_read_whole(unicode, got));
    CHECK(got == "x=1");
    CHECK(os_mkdirs(t.file("d1/d2/d3")));
    CHECK(os_stat(t.file("d1/d2/d3")).is_dir);
    write_file(t.file("z.LUA"), {});
    auto files = os_list_files(u8(t.dir), ".lua");
    REQUIRE(files.size() == 2);
    CHECK(path_filename(files[0]) == "z.LUA");  // sorted by byte value: 'z' < 0xC3
    CHECK(os_same_file(p, p));
    CHECK(!os_same_file(p, unicode));
    CHECK(os_remove(unicode));
    CHECK(!os_stat(unicode).exists);
    CHECK(os_remove(unicode));  // already gone is fine
    CHECK(!os_exe_dir().empty());
    CHECK(os_env("HEXER_SURELY_UNSET_VAR") == "");
}

// =============================================================================================
// file_source
// =============================================================================================
TEST_CASE("file_source: cached reads, EOF, concurrent readers") {
    TempDir t;
    std::string p = t.file("big.bin");
    const size_t n = 40u << 20;  // > cache size, forces eviction
    Bytes data = random_bytes(n, 7);
    write_file(p, data);
    auto src = FileSource::open(p);
    REQUIRE(src);
    CHECK(src->size() == n);
    CHECK(src->stat_at_open().size == n);
    uint8_t b[16];
    CHECK(src->read(n - 4, b, 16) == 4);
    CHECK(src->read(n, b, 1) == 0);
    CHECK(std::memcmp(b, &data[n - 4], 4) == 0);

    std::atomic<int> failures{0};
    std::vector<std::thread> threads;
    for (int ti = 0; ti < 4; ++ti) {
        threads.emplace_back([&, ti] {
            std::mt19937_64 rng(100 + ti);
            Bytes buf;
            for (int k = 0; k < 1500; ++k) {
                uint64_t off = rng() % n;
                size_t len = (k % 50 == 0) ? (1u << 20) + size_t(rng() % 100000) : size_t(rng() % 200000);
                buf.resize(len);
                size_t expect = size_t(std::min<uint64_t>(len, n - off));
                size_t got = src->read(off, buf.data(), len);
                if (got != expect || std::memcmp(buf.data(), &data[size_t(off)], got) != 0) failures++;
            }
        });
    }
    for (auto& th : threads) th.join();
    CHECK(failures.load() == 0);
    CHECK(!src->io_error());
    src->invalidate();
    CHECK(src->read(123, b, 8) == 8);
    CHECK(std::memcmp(b, &data[123], 8) == 0);
}

// =============================================================================================
// piece_table
// =============================================================================================
namespace {
Bytes materialize(const PieceTable& t, const Bytes& orig, const Bytes& add) {
    Bytes out;
    for (const Piece& p : t.pieces()) {
        const Bytes& src = p.src == Piece::Original ? orig : add;
        out.insert(out.end(), src.begin() + std::ptrdiff_t(p.start), src.begin() + std::ptrdiff_t(p.start + p.len));
    }
    return out;
}
}  // namespace

TEST_CASE("piece_table: basics") {
    PieceTable t;
    t.reset(0, 0);
    CHECK(t.size() == 0);
    CHECK(t.pieces().empty());
    CHECK(t.is_identity(0, 0));
    t.reset(0, 100);
    CHECK(t.is_identity(0, 100));
    CHECK(t.is_inplace_compatible(0, 100));
    // Typing: consecutive add bytes merge into one piece.
    for (uint64_t i = 0; i < 10; ++i) t.insert(50 + i, Piece{Piece::Add, 0, i, 1});
    CHECK(t.pieces().size() == 3);
    CHECK(t.size() == 110);
    CHECK(!t.is_inplace_compatible(0, 110));
    t.erase(50, 10);
    CHECK(t.pieces().size() == 1);  // the two original halves merge back
    CHECK(t.is_identity(0, 100));
    // Overwrite pattern keeps in-place compatibility.
    t.erase(10, 5);
    t.insert(10, Piece{Piece::Add, 0, 0, 5});
    CHECK(t.is_inplace_compatible(0, 100));
    CHECK(!t.is_inplace_compatible(1, 100));
    auto [i, off] = t.locate(12);
    CHECK(i == 1);
    CHECK(off == 2);
    CHECK(t.piece_start(2) == 15);
    t.assign({Piece{Piece::Original, 0, 0, 0}, Piece{Piece::Add, 0, 3, 4}, Piece{Piece::Add, 0, 7, 2}});
    CHECK(t.pieces().size() == 1);  // zero-length dropped, contiguous merged
    CHECK(t.size() == 6);
    t.erase(0, 1000);  // clamped
    CHECK(t.size() == 0);
}

TEST_CASE("piece_table: randomized against reference") {
    std::mt19937_64 rng(42);
    for (int round = 0; round < 5; ++round) {
        Bytes orig = random_bytes(1000 + size_t(round) * 300, 1000 + round);
        Bytes add;
        PieceTable t;
        t.reset(0, orig.size());
        Bytes ref = orig;
        for (int op = 0; op < 3000; ++op) {
            int kind = int(rng() % 10);
            if (kind < 5 || ref.empty()) {
                uint64_t pos = rng() % (ref.size() + 1);
                size_t len = 1 + size_t(rng() % 20);
                // Sometimes continue the last add run so merging is exercised.
                uint64_t start = add.size();
                for (size_t k = 0; k < len; ++k) add.push_back(uint8_t(rng()));
                t.insert(pos, Piece{Piece::Add, 0, start, len});
                ref.insert(ref.begin() + std::ptrdiff_t(pos), add.begin() + std::ptrdiff_t(start), add.end());
            } else if (kind < 9) {
                uint64_t pos = rng() % ref.size();
                uint64_t len = 1 + rng() % 40;
                t.erase(pos, len);
                uint64_t e = std::min<uint64_t>(ref.size(), pos + len);
                ref.erase(ref.begin() + std::ptrdiff_t(pos), ref.begin() + std::ptrdiff_t(e));
            } else {
                // Original bytes re-inserted elsewhere (cut & paste of a range of the file).
                uint64_t s = rng() % orig.size(), len = 1 + rng() % 30;
                len = std::min<uint64_t>(len, orig.size() - s);
                uint64_t pos = rng() % (ref.size() + 1);
                t.insert(pos, Piece{Piece::Original, 0, s, len});
                ref.insert(ref.begin() + std::ptrdiff_t(pos), orig.begin() + std::ptrdiff_t(s),
                           orig.begin() + std::ptrdiff_t(s + len));
            }
            REQUIRE(t.size() == ref.size());
            if (op % 25 == 0) {
                REQUIRE(materialize(t, orig, add) == ref);
                const auto& ps = t.pieces();
                for (size_t k = 0; k < ps.size(); ++k) {
                    REQUIRE(ps[k].len > 0);
                    if (k) {
                        bool contiguous = ps[k - 1].src == ps[k].src && ps[k - 1].chunk == ps[k].chunk &&
                                          ps[k - 1].start + ps[k - 1].len == ps[k].start;
                        REQUIRE(!contiguous);
                    }
                }
                for (int q = 0; q < 10 && !ref.empty(); ++q) {
                    uint64_t pos = rng() % ref.size();
                    auto [i, off] = t.locate(pos);
                    REQUIRE(t.piece_start(i) + off == pos);
                    REQUIRE(off < ps[i].len);
                }
            }
        }
        CHECK(materialize(t, orig, add) == ref);
    }
}

// =============================================================================================
// highlight
// =============================================================================================
TEST_CASE("highlight: colors") {
    uint32_t c = 0;
    CHECK(parse_color("#ff8800", c));
    CHECK(c == rgba(0xff, 0x88, 0x00));
    CHECK(parse_color("FF8800", c));
    CHECK(c == rgba(0xff, 0x88, 0x00));
    CHECK(parse_color("0x112233", c));
    CHECK(c == rgba(0x11, 0x22, 0x33));
    CHECK(parse_color("#11223344", c));
    CHECK(c == rgba(0x11, 0x22, 0x33, 0x44));
    for (const char* n : {"red", "green", "blue", "yellow", "orange", "purple", "cyan", "pink", "gray", "teal", "white", " Red "})
        CHECK(parse_color(n, c));
    CHECK(!parse_color("nope", c));
    CHECK(!parse_color("#12345", c));
    CHECK(!parse_color("#gg0000", c));
    CHECK(from_rgb_int(0x102030) == rgba(0x10, 0x20, 0x30));
    std::vector<uint32_t> seen;
    for (int i = 0; i < 16; ++i) seen.push_back(field_palette(i));
    std::sort(seen.begin(), seen.end());
    CHECK(std::unique(seen.begin(), seen.end()) == seen.end());
    CHECK(field_palette(16) == field_palette(0));
    CHECK(field_palette(-1) == field_palette(15));
}

TEST_CASE("highlight: nested lookups") {
    HighlightSet hs;
    hs.add({0, 100, 1, "outer"});
    hs.add({50, 10, 2, "sibling"});
    hs.add({10, 10, 3, "inner"});
    hs.add({15, 3, 4, "inner2"});
    hs.add({5, 0, 5, "empty"});  // ignored
    hs.finalize();
    REQUIRE(hs.items.size() == 4);
    CHECK(hs.items[0].label == "outer");
    CHECK(hs.at(16)->label == "inner2");
    CHECK(hs.at(12)->label == "inner");
    CHECK(hs.at(30)->label == "outer");
    CHECK(hs.at(55)->label == "sibling");
    CHECK(hs.at(100) == nullptr);
    std::vector<const Highlight*> out;
    hs.query(14, 52, out);
    REQUIRE(out.size() == 4);
    CHECK(out[0]->label == "outer");
    CHECK(out[3]->label == "sibling");
    out.clear();
    hs.query(100, 200, out);
    CHECK(out.empty());

    // Randomized against brute force, including a struct covering everything.
    std::mt19937_64 rng(5);
    HighlightSet r;
    r.add({0, 1u << 20, 0, "all"});
    for (int i = 0; i < 3000; ++i) r.add({rng() % (1u << 20), 1 + rng() % 500, 0, ""});
    r.finalize();
    for (int q = 0; q < 2000; ++q) {
        uint64_t off = rng() % ((1u << 20) + 10);
        const Highlight* best = nullptr;
        for (const auto& h : r.items)
            if (h.offset <= off && off < h.offset + h.length && (!best || h.length < best->length)) best = &h;
        const Highlight* got = r.at(off);
        REQUIRE(bool(got) == bool(best));
        if (got) REQUIRE(got->length == best->length);
        uint64_t b = rng() % (1u << 20), e = b + rng() % 2000;
        out.clear();
        r.query(b, e, out);
        size_t expect = 0;
        for (const auto& h : r.items)
            if (h.offset < e && h.offset + h.length > b) expect++;
        REQUIRE(out.size() == expect);
        REQUIRE(std::is_sorted(out.begin(), out.end(), [](auto x, auto y) { return x->offset < y->offset; }));
    }
}

// =============================================================================================
// document: editing + undo
// =============================================================================================
TEST_CASE("document: bytes shifted by an insert or erase are not marked modified") {
    TempDir t;
    std::string p = t.file("shift.bin");
    write_file(p, str_bytes("0123456789"));
    auto d = Document::open_file(p);
    REQUIRE(d);
    const uint8_t ab[] = {'a', 'b'};
    CHECK(d->insert(2, ab, 2));
    CHECK(doc_bytes(*d) == str_bytes("01ab23456789"));
    CHECK(d->is_modified_range(2, 2));
    CHECK(d->is_modified_range(0, 12));
    CHECK(!d->is_modified_range(0, 2));
    CHECK(!d->is_modified_range(4, 8));  // original "23456789", now at +2
    CHECK(d->erase(0, 3));
    CHECK(doc_bytes(*d) == str_bytes("b23456789"));
    CHECK(d->is_modified_range(0, 1));
    CHECK(!d->is_modified_range(1, 8));
    REQUIRE(d->undo());
    REQUIRE(d->undo());
    CHECK(!d->is_modified_range(0, 10));
}

TEST_CASE("document: basic edits and range checks") {
    TempDir t;
    std::string p = t.file("f.bin");
    write_file(p, str_bytes("0123456789"));
    auto d = Document::open_file(p);
    REQUIRE(d);
    CHECK(d->display_name() == "f.bin");
    CHECK(d->size() == 10);
    CHECK(!d->dirty());
    CHECK(!d->is_modified_range(0, 10));
    const uint8_t ab[] = {'a', 'b'};
    CHECK(d->overwrite(8, ab, 2));
    CHECK(doc_bytes(*d) == str_bytes("01234567ab"));
    CHECK(d->is_modified_range(8, 1));
    CHECK(d->is_modified_range(0, 100));
    CHECK(!d->is_modified_range(0, 8));
    CHECK(d->overwrite(9, ab, 2));  // extends past EOF
    CHECK(doc_bytes(*d) == str_bytes("01234567aab"));
    CHECK(d->overwrite(11, ab, 2));  // at EOF
    CHECK(d->size() == 13);
    CHECK(!d->overwrite(14, ab, 2));  // past EOF
    CHECK(!d->insert(14, ab, 2));
    CHECK(d->insert(0, ab, 2));
    CHECK(doc_bytes(*d) == str_bytes("ab01234567aabab"));
    CHECK(d->erase(13, 100));  // clamps
    CHECK(doc_bytes(*d) == str_bytes("ab01234567aab"));
    CHECK(!d->erase(13, 1));
    CHECK(d->replace(2, 3, ab, 1));
    CHECK(doc_bytes(*d) == str_bytes("aba34567aab"));
    const uint8_t pat[] = {'x', 'y', 'z'};
    CHECK(d->fill(9, 5, pat, 3));
    CHECK(doc_bytes(*d) == str_bytes("aba34567axyzxy"));
    CHECK(d->undo_stack().size() == 7);
    CHECK(d->undo_stack().back().label == "Fill");
    d->set_read_only(true);
    CHECK(!d->insert(0, ab, 1));
    CHECK(!d->undo());
    CHECK(d->add_bookmark(Bookmark{1, 1, "ro ok", 0, ""}));  // bookmarks allowed on read-only docs
    d->set_read_only(false);
    while (d->undo()) {
    }
    CHECK(doc_bytes(*d) == str_bytes("0123456789"));
    CHECK(!d->dirty());
    CHECK(d->view().bookmarks.empty());
}

TEST_CASE("document: randomized edits/undo/redo/saves against reference") {
    TempDir t;
    std::string p = t.file("rand.bin");
    Bytes orig = random_bytes(3000, 9);
    write_file(p, orig);
    auto d = Document::open_file(p);
    REQUIRE(d);
    std::mt19937_64 rng(77);
    Bytes cur = orig;
    std::vector<Bytes> undo, redo;
    std::vector<uint64_t> undo_ids, redo_ids;
    uint64_t id = 0, saved = 0, next_id = 1;
    int saves = 0, rewrites = 0;

    auto edit_done = [&](const Bytes& before) {
        undo.push_back(before);
        undo_ids.push_back(id);
        redo.clear();
        redo_ids.clear();
        id = next_id++;
    };
    for (int op = 0; op < 4000; ++op) {
        int kind = int(rng() % 100);
        Bytes before = cur;
        uint64_t size = cur.size();
        if (kind < 20) {  // overwrite (may extend)
            uint64_t off = rng() % (size + 1);
            Bytes data = random_bytes(1 + size_t(rng() % 16), rng());
            REQUIRE(d->overwrite(off, data.data(), data.size()));
            if (cur.size() < off + data.size()) cur.resize(size_t(off + data.size()));
            std::copy(data.begin(), data.end(), cur.begin() + std::ptrdiff_t(off));
            edit_done(before);
        } else if (kind < 35 && size < 6000) {  // insert
            uint64_t off = rng() % (size + 1);
            Bytes data = random_bytes(1 + size_t(rng() % 32), rng());
            REQUIRE(d->insert(off, data.data(), data.size()));
            cur.insert(cur.begin() + std::ptrdiff_t(off), data.begin(), data.end());
            edit_done(before);
        } else if (kind < 50 && size > 0) {  // erase
            uint64_t off = rng() % size, len = 1 + rng() % 64;
            REQUIRE(d->erase(off, len));
            cur.erase(cur.begin() + std::ptrdiff_t(off), cur.begin() + std::ptrdiff_t(std::min(size, off + len)));
            edit_done(before);
        } else if (kind < 58) {  // replace
            uint64_t off = rng() % (size + 1), old_len = rng() % 20;
            Bytes data = random_bytes(size_t(rng() % 20), rng());
            uint64_t ol = std::min(old_len, size - off);
            if (ol == 0 && data.empty()) continue;
            REQUIRE(d->replace(off, old_len, data.data(), data.size()));
            cur.erase(cur.begin() + std::ptrdiff_t(off), cur.begin() + std::ptrdiff_t(off + ol));
            cur.insert(cur.begin() + std::ptrdiff_t(off), data.begin(), data.end());
            edit_done(before);
        } else if (kind < 63) {  // fill
            uint64_t off = rng() % (size + 1), len = 1 + rng() % 100;
            Bytes pat = random_bytes(1 + size_t(rng() % 5), rng());
            REQUIRE(d->fill(off, len, pat.data(), pat.size()));
            if (cur.size() < off + len) cur.resize(size_t(off + len));
            for (uint64_t k = 0; k < len; ++k) cur[size_t(off + k)] = pat[size_t(k % pat.size())];
            edit_done(before);
        } else if (kind < 82) {  // undo
            bool ok = d->undo();
            REQUIRE(ok == !undo.empty());
            if (ok) {
                redo.push_back(cur);
                redo_ids.push_back(id);
                cur = undo.back();
                id = undo_ids.back();
                undo.pop_back();
                undo_ids.pop_back();
            }
        } else if (kind < 97) {  // redo
            bool ok = d->redo();
            REQUIRE(ok == !redo.empty());
            if (ok) {
                undo.push_back(cur);
                undo_ids.push_back(id);
                cur = redo.back();
                id = redo_ids.back();
                redo.pop_back();
                redo_ids.pop_back();
            }
        } else {  // save (in place or rewrite depending on the edit set)
            std::string err;
            uint32_t before_src = d->current_source();
            REQUIRE_MESSAGE(d->save(nullptr, &err), err);
            if (d->current_source() != before_src) rewrites++;
            saves++;
            saved = id;
            REQUIRE(read_file(p) == cur);
            REQUIRE(!tmp_left_over(t));
        }
        REQUIRE(d->size() == cur.size());
        REQUIRE(d->dirty() == (id != saved));
        if (op % 10 == 0) REQUIRE(doc_bytes(*d) == cur);
    }
    CHECK(doc_bytes(*d) == cur);
    CHECK(saves > 20);
    CHECK(rewrites > 0);
    CHECK(rewrites < saves);  // some saves were in place
    // Walk the whole history back and forth after all those saves.
    while (!undo.empty()) {
        REQUIRE(d->undo());
        cur = undo.back();
        undo.pop_back();
        REQUIRE(doc_bytes(*d) == cur);
    }
    CHECK(!d->undo());
}

TEST_CASE("document: typing coalescing") {
    FakeClock clk;
    auto d = Document::create_from_bytes("t", reinterpret_cast<const uint8_t*>("................"), 16);
    const uint8_t a = 'a', b = 'b', c = 'c';
    CHECK(d->insert(4, &a, 1, true));
    CHECK(d->insert(5, &b, 1, true));
    CHECK(d->overwrite(5, &c, 1, true));  // e.g. low nibble of the same byte
    CHECK(d->undo_stack().size() == 1);
    CHECK(d->undo_stack()[0].label == "Typing");
    CHECK(d->overwrite(6, &a, 1, true));  // continues the run in overwrite mode
    CHECK(d->undo_stack().size() == 1);
    CHECK(d->insert(12, &a, 1, true));  // cursor jumped: new step
    CHECK(d->undo_stack().size() == 2);
    CHECK(d->erase(0, 1));  // non-typing action breaks the run
    CHECK(d->insert(12, &b, 1, true));
    CHECK(d->undo_stack().size() == 4);
    CHECK(d->undo());
    CHECK(d->insert(12, &c, 1, true));  // after undo: new step, redo cleared
    CHECK(d->undo_stack().size() == 4);
    CHECK(!d->can_redo());
    d->begin_group("g");
    d->end_group();
    CHECK(d->insert(13, &c, 1, true));  // a group in between also breaks the run
    CHECK(d->undo_stack().size() == 5);
    while (d->undo()) {
    }
    Bytes dots(16, '.');
    CHECK(doc_bytes(*d) == dots);
}

TEST_CASE("document: typing runs break after a pause or at the byte limit") {
    FakeClock clk;
    Bytes dots(64, '.');
    auto d = Document::create_from_bytes("t", dots.data(), dots.size());
    const uint8_t a = 'a';
    // Fast typing (each key within the window of the previous one) is one step, even though the
    // run as a whole takes longer than the window.
    for (uint64_t i = 0; i < 8; ++i) {
        REQUIRE(d->insert(i, &a, 1, true));
        g_fake_ms += 400;
    }
    CHECK(d->undo_stack().size() == 1);
    // A pause longer than the window starts a new step at the same position.
    g_fake_ms += 101;  // 501 ms since the last key
    REQUIRE(d->insert(8, &a, 1, true));
    CHECK(d->undo_stack().size() == 2);
    g_fake_ms += 500;  // exactly the window: still merges
    REQUIRE(d->insert(9, &a, 1, true));
    CHECK(d->undo_stack().size() == 2);
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d).size() == 64 + 8);  // only the keys after the pause were undone
    REQUIRE(d->redo());

    // Insert-mode hex typing: high nibble inserts a byte, the low nibble overwrites it: one step.
    g_fake_ms += 1000;
    const uint8_t hi = 0x40, lo = 0x41;
    REQUIRE(d->insert(20, &hi, 1, true));
    g_fake_ms += 300;
    REQUIRE(d->overwrite(20, &lo, 1, true));
    CHECK(d->undo_stack().size() == 3);
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d).size() == 64 + 10);
    REQUIRE(d->redo());

    // Byte limit (no time limit): a run covering 4 bytes refuses to grow, but edits inside its
    // bytes (the low nibble of its last byte) still merge.
    Document::set_undo_merge(0, 4);
    const size_t base = d->undo_stack().size();
    g_fake_ms += 100000;
    for (uint64_t i = 30; i < 34; ++i) REQUIRE(d->insert(i, &hi, 1, true));
    CHECK(d->undo_stack().size() == base + 1);
    REQUIRE(d->overwrite(33, &lo, 1, true));
    CHECK(d->undo_stack().size() == base + 1);
    REQUIRE(d->insert(34, &hi, 1, true));
    CHECK(d->undo_stack().size() == base + 2);
    for (uint64_t i = 35; i < 38; ++i) REQUIRE(d->insert(i, &hi, 1, true));
    CHECK(d->undo_stack().size() == base + 2);
    REQUIRE(d->overwrite(36, &lo, 1, true));  // inside the run (overwrite mode, cursor went back)
    CHECK(d->undo_stack().size() == base + 2);

    // Overwrite-mode typing obeys the same limits.
    Document::set_undo_merge(500, 32);
    g_fake_ms += 1000;
    for (uint64_t i = 40; i < 40 + 40; ++i) REQUIRE(d->overwrite(i, &a, 1, true));
    CHECK(d->undo_stack().size() == base + 4);  // 32 + 8 bytes
    while (d->undo()) {
    }
    CHECK(doc_bytes(*d) == dots);
}

TEST_CASE("document: groups, bookmarks, cursor in history") {
    auto d = Document::create_empty("Untitled 1");
    CHECK(d->display_name() == "Untitled 1");
    CHECK(!d->dirty());
    Bytes x = str_bytes("hello world");
    d->view().cursor = 0;
    CHECK(d->insert(0, x.data(), x.size()));
    d->view().cursor = 5;
    d->view().anchor = 2;
    d->begin_group("Paste");
    d->begin_group("inner");
    CHECK(d->overwrite(0, x.data(), 2));
    CHECK(d->erase(3, 2));
    CHECK(d->add_bookmark(Bookmark{1, 2, "bm", rgba(1, 2, 3), ""}));
    d->end_group();
    CHECK(d->insert(0, x.data(), 1));
    d->end_group();
    REQUIRE(d->undo_stack().size() == 2);
    CHECK(d->undo_stack().back().label == "inner");  // innermost non-empty label wins
    CHECK(d->view().bookmarks.size() == 1);
    d->view().cursor = 9;
    CHECK(d->undo());
    CHECK(doc_bytes(*d) == x);
    CHECK(d->view().bookmarks.empty());
    CHECK(d->view().cursor == 5);
    CHECK(d->view().anchor == 2);
    CHECK(d->redo());
    CHECK(d->view().bookmarks.size() == 1);
    CHECK(d->view().cursor == 9);  // redo returns to the "after" state

    // Bookmark-only history.
    CHECK(d->update_bookmark(0, Bookmark{4, 1, "renamed", 0, "a note"}));
    CHECK(d->add_bookmark(Bookmark{7, 1, "second", 0, ""}));
    CHECK(d->remove_bookmark(0));
    CHECK(!d->remove_bookmark(5));
    REQUIRE(d->view().bookmarks.size() == 1);
    CHECK(d->view().bookmarks[0].name == "second");
    CHECK(d->undo());
    CHECK(d->view().bookmarks.size() == 2);
    CHECK(d->undo());
    CHECK(d->view().bookmarks.size() == 1);
    CHECK(d->view().bookmarks[0].name == "renamed");
    CHECK(d->view().bookmarks[0].note == "a note");
    CHECK(d->undo());
    CHECK(d->view().bookmarks[0].name == "bm");
    CHECK(d->undo_stack().back().label == "inner");
}

TEST_CASE("document: group labels - innermost non-empty label names the step") {
    auto d = Document::create_empty("Untitled 1");
    const uint8_t x[2] = {1, 2};
    CHECK_FALSE(d->in_group());
    // A labelled inner group opened after the outer group already pushed its step renames it.
    d->begin_group("Script: cmd");
    CHECK(d->in_group());
    REQUIRE(d->insert(0, x, 1));
    d->begin_group("Append TLV");
    REQUIRE(d->insert(1, x, 1));
    d->end_group();
    REQUIRE(d->insert(2, x, 1));
    d->end_group();
    CHECK_FALSE(d->in_group());
    REQUIRE(d->undo_stack().size() == 1);
    CHECK(d->undo_stack().back().label == "Append TLV");
    // An unlabelled inner group keeps the outer label.
    d->begin_group("Script: cmd");
    d->begin_group("");
    REQUIRE(d->insert(0, x, 2));
    d->end_group();
    d->end_group();
    REQUIRE(d->undo_stack().size() == 2);
    CHECK(d->undo_stack().back().label == "Script: cmd");
    // No label anywhere: the first edit's own label.
    d->begin_group();
    REQUIRE(d->fill(0, 2, x, 1));
    d->end_group();
    CHECK(d->undo_stack().back().label == "Fill");
    // The next group starts from its own label again.
    d->begin_group("Paste");
    REQUIRE(d->insert(0, x, 1));
    d->end_group();
    CHECK(d->undo_stack().back().label == "Paste");
}

TEST_CASE("document: dirty tracking, undo limit, fill without materializing") {
    TempDir t;
    std::string p = t.file("d.bin");
    write_file(p, random_bytes(1000, 3));
    auto d = Document::open_file(p);
    const uint8_t v = 0x55;
    CHECK(d->overwrite(1, &v, 1));
    CHECK(d->dirty());
    CHECK(d->undo());
    CHECK(!d->dirty());
    CHECK(d->redo());
    CHECK(d->dirty());
    REQUIRE(d->save(nullptr, nullptr));
    CHECK(!d->dirty());
    CHECK(d->undo());
    CHECK(d->dirty());
    CHECK(d->redo());
    CHECK(!d->dirty());

    uint64_t gen = d->generation();
    for (int i = 0; i < int(Document::kMaxUndo) + 25; ++i) {
        uint8_t b = uint8_t(i);
        REQUIRE(d->overwrite(0, &b, 1));
    }
    CHECK(d->undo_stack().size() == Document::kMaxUndo);
    CHECK(d->generation() > gen);

    auto e = Document::create_empty("fill");
    const uint64_t tb = 1ull << 40;
    const uint8_t pat[] = {1, 2, 3};
    REQUIRE(e->fill(0, tb, pat, 3));
    CHECK(e->size() == tb);
    CHECK(e->table().pieces().size() < 20000);
    std::mt19937_64 rng(1);
    for (int i = 0; i < 200; ++i) {
        uint64_t off = rng() % (tb - 8);
        uint8_t buf[8];
        REQUIRE(e->read(off, buf, 8) == 8);
        for (int k = 0; k < 8; ++k) REQUIRE(buf[k] == pat[(off + uint64_t(k)) % 3]);
    }
    uint8_t last[4];
    CHECK(e->read(tb - 2, last, 4) == 2);
    CHECK(last[1] == pat[(tb - 1) % 3]);
    CHECK(e->undo());
    CHECK(e->size() == 0);
}

TEST_CASE("document: snapshot isolation and threading") {
    TempDir t;
    std::string p = t.file("s.bin");
    Bytes orig = random_bytes(5000, 11);
    write_file(p, orig);
    auto d = Document::open_file(p);
    auto snap = d->snapshot();
    const uint8_t z[3] = {0, 0, 0};
    CHECK(d->insert(10, z, 3));
    CHECK(d->erase(0, 2));
    CHECK(snap->size() == 5000);
    Bytes s(5000);
    std::thread th([&] { CHECK(snap->read(0, s.data(), s.size()) == 5000); });
    th.join();
    CHECK(s == orig);
    CHECK(d->size() == 5001);
    CHECK(snap->read(4999, s.data(), 10) == 1);
}

// =============================================================================================
// document: saving
// =============================================================================================
TEST_CASE("document: in-place save keeps history") {
    TempDir t;
    std::string p = t.file("inplace.bin");
    Bytes orig = random_bytes(3 * 65536 + 17, 21);
    write_file(p, orig);
    auto d = Document::open_file(p);
    REQUIRE(d);
    Bytes xyz = str_bytes("XYZ");
    REQUIRE(d->overwrite(1000, xyz.data(), 3));
    REQUIRE(d->overwrite(100000, xyz.data(), 1));
    Bytes edited = orig;
    std::copy(xyz.begin(), xyz.end(), edited.begin() + 1000);
    edited[100000] = 'X';
    CHECK(doc_bytes(*d) == edited);

    Progress pr;
    std::string err;
    REQUIRE(d->save(&pr, &err));
    CHECK(err.empty());
    CHECK(d->current_source() == 0);  // no rewrite happened
    CHECK(d->table().is_identity(0, orig.size()));
    CHECK(read_file(p) == edited);
    CHECK(!d->dirty());
    CHECK(!d->changed_on_disk());
    CHECK(pr.done.load() == pr.total.load());
    CHECK(!tmp_left_over(t));

    // Undo after save restores the TRUE old bytes (copied before overwriting).
    REQUIRE(d->undo());
    Bytes one = orig;
    std::copy(xyz.begin(), xyz.end(), one.begin() + 1000);
    CHECK(doc_bytes(*d) == one);
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == orig);
    CHECK(d->dirty());
    CHECK(read_file(p) == edited);  // undo does not touch the disk
    CHECK(d->is_modified_range(1000, 3));

    // Save the undone state (again in place), then redo and save once more.
    REQUIRE(d->save(nullptr, &err));
    CHECK(read_file(p) == orig);
    CHECK(!d->dirty());
    REQUIRE(d->redo());
    REQUIRE(d->redo());
    CHECK(doc_bytes(*d) == edited);
    CHECK(d->dirty());
    REQUIRE(d->save(nullptr, &err));
    CHECK(read_file(p) == edited);
    CHECK(d->current_source() == 0);
    while (d->undo()) {
    }
    CHECK(doc_bytes(*d) == orig);
    CHECK(read_file(p) == edited);
}

TEST_CASE("document: rewrite save keeps history") {
    TempDir t;
    std::string p = t.file("rewrite.bin");
    Bytes orig = random_bytes(200000, 31);
    write_file(p, orig);
    auto d = Document::open_file(p);
    REQUIRE(d);
    auto old_snapshot = d->snapshot();
    Bytes hello = str_bytes("hello");
    REQUIRE(d->insert(10, hello.data(), hello.size()));
    Bytes s1 = orig;
    s1.insert(s1.begin() + 10, hello.begin(), hello.end());
    REQUIRE(d->erase(5000, 100));
    Bytes s2 = s1;
    s2.erase(s2.begin() + 5000, s2.begin() + 5100);

    Progress pr;
    std::string err;
    REQUIRE(d->save(&pr, &err));
    CHECK(err.empty());
    CHECK(d->current_source() == 1);
    CHECK(read_file(p) == s2);
    CHECK(!tmp_left_over(t));
    CHECK(!d->dirty());
    CHECK(!d->changed_on_disk());
    CHECK(pr.done.load() == s2.size());
    CHECK(!d->is_modified_range(0, d->size()));

    // Older version still readable: history and old snapshots work.
    Bytes os(orig.size());
    CHECK(old_snapshot->read(0, os.data(), os.size()) == orig.size());
    CHECK(os == orig);
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == s1);
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == orig);
    CHECK(d->dirty());
    REQUIRE(d->save(nullptr, &err));  // rewrite again (pieces reference the old version)
    CHECK(read_file(p) == orig);
    REQUIRE(d->redo());
    CHECK(doc_bytes(*d) == s1);
    REQUIRE(d->redo());
    CHECK(doc_bytes(*d) == s2);
    REQUIRE(d->save(nullptr, &err));
    CHECK(read_file(p) == s2);
    while (d->undo()) {
    }
    CHECK(doc_bytes(*d) == orig);
}

TEST_CASE("document: save_as and untitled") {
    TempDir t;
    std::string a = t.file("a.bin"), b = t.file("b.bin");
    Bytes orig = random_bytes(10000, 41);
    write_file(a, orig);
    auto d = Document::open_file(a);
    const uint8_t v[2] = {1, 2};
    REQUIRE(d->insert(3, v, 2));
    Bytes edited = orig;
    edited.insert(edited.begin() + 3, v, v + 2);
    std::string err;
    REQUIRE(d->save_as(b, nullptr, &err));
    CHECK(path_filename(d->path()) == "b.bin");
    CHECK(d->display_name() == "b.bin");
    CHECK(read_file(a) == orig);
    CHECK(read_file(b) == edited);
    CHECK(!d->dirty());
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == orig);
    REQUIRE(d->save(nullptr, &err));  // saves to b now
    CHECK(read_file(b) == orig);
    CHECK(read_file(a) == orig);
    REQUIRE(d->save_as(d->path(), nullptr, &err));  // same file -> plain save

    auto u = Document::create_empty("Untitled 2");
    Bytes data = str_bytes("fresh");
    REQUIRE(u->insert(0, data.data(), data.size()));
    CHECK(u->dirty());
    CHECK(u->is_modified_range(0, 5));
    CHECK(!u->save(nullptr, &err));
    CHECK(!err.empty());
    std::string c = t.file("sub_c.bin");
    REQUIRE(u->save_as(c, nullptr, &err));
    CHECK(read_file(c) == data);
    CHECK(u->display_name() == "sub_c.bin");
    CHECK(u->has_path());
    CHECK(!u->dirty());
    REQUIRE(u->overwrite(0, v, 1));
    REQUIRE(u->save(nullptr, &err));
    CHECK(read_file(c)[0] == 1);

    auto f = Document::create_from_bytes("gen", data.data(), data.size());
    CHECK(f->dirty());
    CHECK(!f->is_modified_range(0, 5));
}

TEST_CASE("document: cancelled and rejected saves leave everything untouched") {
    TempDir t;
    std::string p = t.file("c.bin");
    Bytes orig = random_bytes(300000, 51);
    write_file(p, orig);
    FileStat before = os_stat(p);
    auto d = Document::open_file(p);
    const uint8_t v[1] = {9};
    REQUIRE(d->insert(100, v, 1));  // rewrite path
    Bytes edited = doc_bytes(*d);
    Progress pr;
    pr.cancel = true;
    std::string err;
    CHECK(!d->save(&pr, &err));
    CHECK(!err.empty());
    CHECK(read_file(p) == orig);
    CHECK(os_stat(p).mtime_ns == before.mtime_ns);
    CHECK(!tmp_left_over(t));
    CHECK(d->dirty());
    CHECK(doc_bytes(*d) == edited);
    CHECK(!d->busy());

    REQUIRE(d->undo());
    REQUIRE(d->overwrite(100, v, 1));  // in-place path (history references overwritten bytes)
    edited = doc_bytes(*d);
    CHECK(!d->save(&pr, &err));
    CHECK(read_file(p) == orig);
    CHECK(doc_bytes(*d) == edited);
    CHECK(d->dirty());
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == orig);
    pr.cancel = false;
    REQUIRE(d->redo());
    REQUIRE(d->save(&pr, &err));
    CHECK(read_file(p) == edited);

    d->set_read_only(true);
    REQUIRE(!d->dirty());
    CHECK(!d->insert(0, v, 1));
}

TEST_CASE("document: save on a worker thread while the UI reads") {
    TempDir t;
    std::string p = t.file("w.bin");
    Bytes orig = random_bytes(24u << 20, 61);
    write_file(p, orig);
    auto d = Document::open_file(p);
    const uint8_t v[4] = {1, 2, 3, 4};
    REQUIRE(d->insert(1u << 20, v, 4));
    Bytes expect = orig;
    expect.insert(expect.begin() + (1 << 20), v, v + 4);
    Progress pr;
    std::string err;
    bool ok = false;
    std::atomic<bool> finished{false};
    std::thread worker([&] {
        ok = d->save(&pr, &err);
        finished = true;
    });
    int reads = 0, rejected = 0;
    std::mt19937_64 rng(3);
    uint8_t buf[4096];
    auto t0 = std::chrono::steady_clock::now();
    while (true) {
        bool busy = d->busy();
        uint64_t off = rng() % (expect.size() - sizeof(buf));
        REQUIRE(d->read(off, buf, sizeof(buf)) == sizeof(buf));
        REQUIRE(std::memcmp(buf, &expect[size_t(off)], sizeof(buf)) == 0);
        auto s = d->snapshot();
        REQUIRE(s->size() == expect.size());
        if (busy) {
            if (!d->insert(0, v, 1))
                rejected++;
            else
                REQUIRE(d->undo());  // the save finished in between: take the edit back
        }
        reads++;
        if (finished && !d->busy()) break;
        if (std::chrono::steady_clock::now() - t0 > std::chrono::seconds(60)) break;
    }
    worker.join();
    CHECK(ok);
    CHECK(reads > 0);
    CHECK(read_file(p) == expect);
    CHECK(rejected > 0);
    CHECK(!d->dirty());
    CHECK(d->current_source() == 1);
    CHECK(doc_bytes(*d) == expect);
}

TEST_CASE("document: changed on disk and reload") {
    TempDir t;
    std::string p = t.file("r.bin");
    write_file(p, str_bytes("abcdef"));
    auto d = Document::open_file(p);
    const uint8_t v = 'Z';
    REQUIRE(d->overwrite(0, &v, 1));
    CHECK(!d->changed_on_disk());
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    write_file(p, str_bytes("1234567"));
    CHECK(d->changed_on_disk());
    std::string err;
    REQUIRE(d->reload(&err));
    CHECK(doc_bytes(*d) == str_bytes("1234567"));
    CHECK(!d->can_undo());
    CHECK(!d->dirty());
    CHECK(!d->changed_on_disk());
}

TEST_CASE("document: >4 GiB sparse file") {
    TempDir t;
    std::string p = t.file("huge.bin");
    const uint64_t size = 5ull << 30;
    {
#ifdef _WIN32
        HANDLE h = CreateFileW(utf8_to_wide(p).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        REQUIRE(h != INVALID_HANDLE_VALUE);
        DWORD got = 0;
        DeviceIoControl(h, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &got, nullptr);
        CloseHandle(h);
#else
        write_file(p, {});  // ReadWrite opens an existing file only
#endif
        auto f = OsFile::open(p, OsFile::Mode::ReadWrite);
        REQUIRE(f);
        REQUIRE(f->truncate(size));
    }
    {
        auto d = Document::open_file(p);
        REQUIRE(d);
        CHECK(d->size() == size);
        const uint64_t at = (9ull << 30) / 2;  // 4.5 GiB
        Bytes tag = str_bytes("BIGFILE!");
        REQUIRE(d->overwrite(at, tag.data(), tag.size()));
        uint8_t buf[16];
        REQUIRE(d->read(at - 4, buf, 16) == 16);
        CHECK(buf[0] == 0);
        CHECK(std::memcmp(buf + 4, tag.data(), 8) == 0);
        CHECK(d->is_modified_range(at, 1));
        CHECK(!d->is_modified_range(at - 4, 4));
        std::string err;
        REQUIRE(d->save(nullptr, &err));
        CHECK(d->current_source() == 0);
        CHECK(d->last_save_info().backup_skipped);  // above the default 4 GiB backup limit
        CHECK_FALSE(os_stat(p + ".backup").exists);
        {
            auto f = OsFile::open(p, OsFile::Mode::Read);
            REQUIRE(f->size() == size);
            REQUIRE(f->read_at(at, buf, 8) == 8);
            CHECK(std::memcmp(buf, tag.data(), 8) == 0);
        }
        REQUIRE(d->undo());
        REQUIRE(d->read(at, buf, 8) == 8);
        CHECK(buf[0] == 0);
        // Structural edits far out do not touch the disk.
        REQUIRE(d->insert(size - 1, tag.data(), 2));
        CHECK(d->size() == size + 2);
        REQUIRE(d->read(size - 1, buf, 3) == 3);
        CHECK(buf[0] == 'B');
        CHECK(buf[2] == 0);
        REQUIRE(d->erase(at, 1ull << 30));
        CHECK(d->size() == at);  // erase clamps at EOF
    }
    os_remove(p);
}

// =============================================================================================
// session
// =============================================================================================
TEST_CASE("session: round trip, skip unchanged, warnings") {
    TempDir t;
    std::string sdir = t.file("session");
    std::string pa = t.file("a.bin"), pc = t.file("c.bin");
    Bytes a_orig = random_bytes(70000, 71), c_orig = random_bytes(100, 72);
    write_file(pa, a_orig);
    write_file(pc, c_orig);

    auto a = Document::open_file(pa);
    Bytes ins = str_bytes("INSERTED");
    REQUIRE(a->insert(500, ins.data(), ins.size()));
    REQUIRE(a->overwrite(60000, ins.data(), 3));
    REQUIRE(a->add_bookmark(Bookmark{42, 4, "magic", rgba(255, 0, 0), "PNG signature"}));
    REQUIRE(a->undo());  // leave something on the redo stack too
    a->view().cursor = 1234;
    a->view().anchor = 1200;
    a->view().top_row = 77;
    a->view().parser = "png";
    a->view().low_nibble = true;
    Bytes a_now = doc_bytes(*a);

    Bytes ub = str_bytes("untitled bytes");
    auto b = Document::create_from_bytes("Untitled 3", ub.data(), ub.size());
    auto c = Document::open_file(pc);
    c->set_read_only(true);

    std::string err;
    {
        Session s(sdir);
        REQUIRE(s.save({a.get(), b.get(), c.get()}, 1, &err));
        auto files = os_list_files(sdir, ".hxs");
        CHECK(files.size() == 3);
        std::vector<int64_t> mt;
        for (auto& f : files) mt.push_back(os_stat(f).mtime_ns);
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        REQUIRE(s.save({a.get(), b.get(), c.get()}, 1, &err));  // nothing changed: no rewrites
        for (size_t i = 0; i < files.size(); ++i) CHECK(os_stat(files[i]).mtime_ns == mt[i]);
        a->view_generation++;
        a->view().cursor = 1235;
        REQUIRE(s.save({a.get(), b.get(), c.get()}, 1, &err));
    }
    {
        Session s(sdir);
        auto r = s.load();
        CHECK(r.warnings.empty());
        REQUIRE(r.docs.size() == 3);
        CHECK(r.active_index == 1);
        Document& ra = *r.docs[0];
        CHECK(os_same_file(ra.path(), pa));
        CHECK(doc_bytes(ra) == a_now);
        CHECK(ra.dirty());
        CHECK(ra.view().cursor == 1235);
        CHECK(ra.view().anchor == 1200);
        CHECK(ra.view().top_row == 77);
        CHECK(ra.view().parser == "png");
        CHECK(ra.view().low_nibble);
        CHECK(ra.view().bookmarks.empty());
        CHECK(ra.undo_stack().size() == 2);
        CHECK(ra.redo_stack().size() == 1);
        REQUIRE(ra.redo());
        CHECK(ra.view().bookmarks.size() == 1);
        CHECK(ra.view().bookmarks[0].name == "magic");
        CHECK(ra.view().bookmarks[0].note == "PNG signature");
        CHECK(ra.view().bookmarks[0].color == rgba(255, 0, 0));
        REQUIRE(ra.undo());
        REQUIRE(ra.undo());
        REQUIRE(ra.undo());
        CHECK(doc_bytes(ra) == a_orig);
        CHECK(!ra.dirty());  // back at the saved state
        REQUIRE(ra.redo());
        CHECK(ra.dirty());

        Document& rb = *r.docs[1];
        CHECK(!rb.has_path());
        CHECK(rb.display_name() == "Untitled 3");
        CHECK(doc_bytes(rb) == ub);
        CHECK(rb.dirty());
        Document& rc = *r.docs[2];
        CHECK(doc_bytes(rc) == c_orig);
        CHECK(!rc.dirty());
        CHECK(rc.read_only());

        // Closing c removes its file; saving restored docs keeps the others.
        REQUIRE(s.save({&ra, &rb}, 0, &err));
        CHECK(os_list_files(sdir, ".hxs").size() == 2);
    }

    // External change to a.bin: edits restored on top, with a warning.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    Bytes a_new = a_orig;
    a_new.push_back(1);
    write_file(pa, a_new);
    {
        Session s(sdir);
        auto r = s.load();
        REQUIRE(r.docs.size() == 2);
        REQUIRE(r.warnings.size() == 1);
        CHECK(r.warnings[0].find("changed on disk") != std::string::npos);
        CHECK(r.docs[0]->dirty());
        CHECK(r.docs[0]->size() == a_orig.size() + 8);  // our pieces, clamped to the new file
        REQUIRE(s.save({r.docs[0].get(), r.docs[1].get()}, 0, &err));
        auto again = Session(sdir).load();
        CHECK(again.warnings.empty());  // not repeated once re-saved
    }

    // Missing file whose pieces reference it: skipped with a warning; untitled still restored.
    os_remove(pa);
    {
        Session s(sdir);
        auto r = s.load();
        REQUIRE(r.docs.size() == 1);
        CHECK(!r.docs[0]->has_path());
        REQUIRE(r.warnings.size() == 1);
        CHECK(r.warnings[0].find("a.bin") != std::string::npos);
        s.clear();
        CHECK(os_list_files(sdir, ".hxs").empty());
        CHECK(Session(sdir).load().docs.empty());
    }
}

TEST_CASE("session: history across rewrite saves and recovered docs") {
    TempDir t;
    std::string sdir = t.file("session");
    std::string p = t.file("x.bin");
    Bytes orig = random_bytes(1000, 81);
    write_file(p, orig);
    auto d = Document::open_file(p);
    Bytes v = str_bytes("abc");
    REQUIRE(d->insert(10, v.data(), 3));
    std::string err;
    REQUIRE(d->save(nullptr, &err));  // rewrite: old version only lives in this process
    REQUIRE(d->overwrite(0, v.data(), 1));
    REQUIRE(d->undo());
    REQUIRE(d->undo());  // current state references the old version: inlined into the session
    Bytes now = doc_bytes(*d);
    CHECK(now == orig);
    {
        Session s(sdir);
        REQUIRE(s.save({d.get()}, 0, &err));
    }
    {
        auto r = Session(sdir).load();
        REQUIRE(r.docs.size() == 1);
        CHECK(doc_bytes(*r.docs[0]) == now);
        CHECK(r.docs[0]->dirty());
        CHECK(r.docs[0]->undo_stack().empty());  // entry referencing the old version dropped
        REQUIRE(r.docs[0]->redo());
        CHECK(!r.docs[0]->dirty());
    }

    // A doc that replaced every original byte survives its file being deleted.
    auto e = Document::open_file(p);
    REQUIRE(e->replace(0, e->size(), v.data(), 3));
    {
        Session s(sdir);
        REQUIRE(s.save({e.get()}, 0, &err));
    }
    os_remove(p);
    auto r = Session(sdir).load();
    REQUIRE(r.docs.size() == 1);
    CHECK(doc_bytes(*r.docs[0]) == v);
    CHECK(!r.docs[0]->has_path());
    CHECK(r.docs[0]->display_name().find("(recovered)") != std::string::npos);
    CHECK(r.warnings.size() == 1);
}

TEST_CASE("session: corrupt and torn files are skipped") {
    TempDir t;
    std::string sdir = t.file("session");
    auto a = Document::create_from_bytes("A", reinterpret_cast<const uint8_t*>("aaaa"), 4);
    auto b = Document::create_from_bytes("B", reinterpret_cast<const uint8_t*>("bbbb"), 4);
    std::string err;
    {
        Session s(sdir);
        REQUIRE(s.save({a.get(), b.get()}, 1, &err));
    }
    auto files = os_list_files(sdir, ".hxs");
    REQUIRE(files.size() == 2);
    Bytes f0 = read_file(files[0]);
    f0[f0.size() / 2] ^= 0x40;  // bit flip
    write_file(files[0], f0);
    {
        auto r = Session(sdir).load();
        REQUIRE(r.docs.size() == 1);
        CHECK(r.docs[0]->display_name() == "B");
        CHECK(r.active_index == 0);
        REQUIRE(r.warnings.size() == 1);
        CHECK(r.warnings[0].find("corrupt") != std::string::npos);
    }
    Bytes f1 = read_file(files[1]);
    f1.resize(f1.size() - 7);  // torn write
    write_file(files[1], f1);
    write_file(files[0], {});
    {
        auto r = Session(sdir).load();
        CHECK(r.docs.empty());
        CHECK(r.warnings.size() == 2);
    }
    write_file(t.file("session/session.ini"), str_bytes("garbage\ndoc=../../evil.hxs\nactive=99\n"));
    auto r = Session(sdir).load();
    CHECK(r.docs.empty());
}

// =============================================================================================
// additional coverage
// =============================================================================================
namespace {
void make_sparse(const std::string& p, uint64_t size) {
#ifdef _WIN32
    HANDLE h = CreateFileW(utf8_to_wide(p).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    REQUIRE(h != INVALID_HANDLE_VALUE);
    DWORD got = 0;
    DeviceIoControl(h, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &got, nullptr);
    CloseHandle(h);
#else
    write_file(p, {});  // ReadWrite opens an existing file only
#endif
    auto f = OsFile::open(p, OsFile::Mode::ReadWrite);
    REQUIRE(f);
    REQUIRE(f->truncate(size));
}
}  // namespace

TEST_CASE("file_source: close and reopen handle") {
    TempDir t;
    std::string p = t.file("cr.bin");
    write_file(p, str_bytes("abcdefgh"));
    auto src = FileSource::open(p);
    REQUIRE(src);
    uint8_t b[8];
    CHECK(src->read(0, b, 8) == 8);
    src->close_file();
    CHECK(src->read(0, b, 8) == 0);  // cache dropped, handle gone
    CHECK(src->io_error());
    CHECK(src->reopen_file());
    CHECK(src->read(2, b, 3) == 3);
    CHECK(std::memcmp(b, "cde", 3) == 0);
}

TEST_CASE("document: randomized size-preserving edits always save in place") {
    TempDir t;
    std::string p = t.file("ip.bin");
    Bytes cur = random_bytes(4096, 91);
    write_file(p, cur);
    auto d = Document::open_file(p);
    std::mt19937_64 rng(92);
    std::vector<Bytes> undo, redo;
    int saves = 0;
    for (int op = 0; op < 3000; ++op) {
        int kind = int(rng() % 100);
        if (kind < 40) {
            Bytes data = random_bytes(1 + size_t(rng() % 300), rng());
            uint64_t off = rng() % (cur.size() - data.size());
            undo.push_back(cur);
            redo.clear();
            REQUIRE(d->overwrite(off, data.data(), data.size(), rng() % 2 == 0));
            std::copy(data.begin(), data.end(), cur.begin() + std::ptrdiff_t(off));
            // Coalescing may have merged it into the previous step: mirror that in the model.
            if (d->undo_stack().size() < undo.size()) undo.pop_back();
        } else if (kind < 50) {
            uint64_t len = 1 + rng() % 500, off = rng() % (cur.size() - len);
            uint8_t pat[2] = {uint8_t(rng()), uint8_t(rng())};
            undo.push_back(cur);
            redo.clear();
            REQUIRE(d->fill(off, len, pat, 2));
            for (uint64_t k = 0; k < len; ++k) cur[size_t(off + k)] = pat[k % 2];
        } else if (kind < 70) {
            REQUIRE(d->undo() == !undo.empty());
            if (!undo.empty()) {
                redo.push_back(cur);
                cur = undo.back();
                undo.pop_back();
            }
        } else if (kind < 88) {
            REQUIRE(d->redo() == !redo.empty());
            if (!redo.empty()) {
                undo.push_back(cur);
                cur = redo.back();
                redo.pop_back();
            }
        } else {
            std::string err;
            REQUIRE_MESSAGE(d->save(nullptr, &err), err);
            REQUIRE(err.empty());
            REQUIRE(d->current_source() == 0);
            REQUIRE(read_file(p) == cur);
            saves++;
        }
        REQUIRE(d->undo_stack().size() == undo.size());
        if (op % 7 == 0) REQUIRE(doc_bytes(*d) == cur);
    }
    CHECK(saves > 100);
    while (!undo.empty()) {
        REQUIRE(d->undo());
        cur = undo.back();
        undo.pop_back();
        REQUIRE(doc_bytes(*d) == cur);
    }
}

TEST_CASE("document: in-place save of a huge overwrite trims history instead of copying it") {
    TempDir t;
    std::string p = t.file("trim.bin");
    const uint64_t size = 520ull << 20;  // just above the preservation budget
    BackupPolicy no_backup(false, 0);    // not about backups: skip the 520 MiB copy
    make_sparse(p, size);
    auto d = Document::open_file(p);
    REQUIRE(d);
    const uint8_t q = 'Q', ab = 0xAB;
    REQUIRE(d->overwrite(10, &q, 1));
    REQUIRE(d->fill(0, size, &ab, 1));
    std::string err;
    REQUIRE(d->save(nullptr, &err));
    CHECK(err.find("dropped") != std::string::npos);
    CHECK(d->current_source() == 0);
    CHECK(!d->dirty());
    CHECK(!d->can_undo());  // both states referenced the overwritten bytes
    {
        auto f = OsFile::open(p, OsFile::Mode::Read);
        uint8_t b[4];
        for (uint64_t off : {uint64_t(0), uint64_t(10), size / 2, size - 4}) {
            REQUIRE(f->read_at(off, b, 4) == 4);
            CHECK(b[0] == 0xAB);
            CHECK(b[3] == 0xAB);
        }
    }
    uint8_t b = 0;
    CHECK(d->read(10, &b, 1) == 1);
    CHECK(b == 0xAB);
    d.reset();
    os_remove(p);
}

// =============================================================================================
// regression tests for the data-safety review
// =============================================================================================
namespace {
uint32_t test_crc32(const uint8_t* p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) {
        c ^= p[i];
        for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
    }
    return c ^ 0xFFFFFFFFu;
}

std::string read_text(const std::string& p) {
    Bytes b = read_file(p);
    return std::string(b.begin(), b.end());
}
}  // namespace

TEST_CASE("session: docs that cannot be restored now are kept, not deleted") {
    TempDir t;
    std::string sdir = t.file("session");
    std::string p = t.file("usb.bin"), away = t.file("usb.away");
    write_file(p, str_bytes("ABCDEFGH"));
    std::string err;
    {
        auto d = Document::open_file(p);
        const uint8_t x = 'X';
        REQUIRE(d->overwrite(1, &x, 1));
        Session s(sdir);
        REQUIRE(s.save({d.get()}, 0, &err));
    }
    REQUIRE(fs::exists(from_u8(sdir) / "doc-1.hxs"));
    fs::rename(from_u8(p), from_u8(away));  // drive unplugged
    {
        Session s(sdir);
        auto r = s.load();
        CHECK(r.docs.empty());
        REQUIRE(r.warnings.size() == 1);
        CHECK(r.warnings[0].find("kept") != std::string::npos);
        CHECK(s.kept() == std::vector<std::string>{"doc-1.hxs"});
        // A new doc must not take the kept file's name, and saving must not delete it.
        auto u = Document::create_from_bytes("U", reinterpret_cast<const uint8_t*>("u"), 1);
        REQUIRE(s.save({u.get()}, 0, &err));
        REQUIRE(s.save({}, 0, &err));
        CHECK(fs::exists(from_u8(sdir) / "doc-1.hxs"));
        CHECK(read_text(t.file("session/session.ini")).find("doc=doc-1.hxs") != std::string::npos);
    }
    fs::rename(from_u8(away), from_u8(p));  // drive back
    {
        Session s(sdir);
        auto r = s.load();
        CHECK(r.warnings.empty());
        REQUIRE(r.docs.size() == 1);
        CHECK(doc_bytes(*r.docs[0]) == str_bytes("AXCDEFGH"));
        CHECK(r.docs[0]->dirty());
        CHECK(s.kept().empty());
    }

    // A file written by another Hexer version (valid checksum, other format) is kept as well; only
    // integrity failures are dropped. discard_kept() gives up on it.
    std::string f = t.file("session/doc-1.hxs");
    Bytes b = read_file(f);
    REQUIRE(b.size() > 12);
    b[4] = 99;  // version
    uint32_t c = test_crc32(b.data(), b.size() - 4);
    for (int i = 0; i < 4; ++i) b[b.size() - 4 + size_t(i)] = uint8_t(c >> (8 * i));
    write_file(f, b);
    {
        Session s(sdir);
        auto r = s.load();
        CHECK(r.docs.empty());
        REQUIRE(r.warnings.size() == 1);
        CHECK(r.warnings[0].find("different Hexer version") != std::string::npos);
        REQUIRE(s.save({}, 0, &err));
        CHECK(fs::exists(from_u8(f)));
        s.discard_kept();
        REQUIRE(s.save({}, 0, &err));
        CHECK(!fs::exists(from_u8(f)));
    }
}

TEST_CASE("session: a second instance never touches the first one's session") {
    TempDir t;
    std::string sdir = t.file("session");
    auto a = Document::create_from_bytes("A", reinterpret_cast<const uint8_t*>("aaaa"), 4);
    auto b = Document::create_from_bytes("B", reinterpret_cast<const uint8_t*>("bbbb"), 4);
    std::string err;
    {
        Session first(sdir);
        CHECK(first.load().docs.empty());
        REQUIRE(first.save({a.get()}, 0, &err));
        {
            Session second(sdir);
            auto r = second.load();
            CHECK(r.docs.empty());  // does not restore the first instance's docs
            CHECK(second.secondary());
            CHECK_FALSE(first.secondary());
            REQUIRE(second.save({b.get()}, 0, &err));
            REQUIRE(first.save({a.get()}, 0, &err));  // does not delete the second one's file
            REQUIRE(second.save({b.get()}, 0, &err));
            CHECK(os_list_files(sdir, ".hxs").size() == 1);
        }
        REQUIRE(first.save({a.get()}, 0, &err));
    }
    // The next instance owning the main dir adopts what the second one left behind.
    {
        Session s(sdir);
        auto r = s.load();
        CHECK(r.warnings.empty());
        REQUIRE(r.docs.size() == 2);
        CHECK(r.docs[0]->display_name() == "A");
        CHECK(r.docs[1]->display_name() == "B");
        CHECK(doc_bytes(*r.docs[1]) == str_bytes("bbbb"));
        REQUIRE(s.save({r.docs[0].get(), r.docs[1].get()}, 1, &err));
        CHECK(os_list_files(sdir, ".hxs").size() == 2);
    }
    CHECK(os_list_files(t.file("session/instance-1"), ".hxs").empty());
    auto r = Session(sdir).load();
    REQUIRE(r.docs.size() == 2);  // adopted once, not twice
    CHECK(r.active_index == 1);
}

TEST_CASE("session: a save that finished just before exit is not replayed on top of itself") {
    TempDir t;
    std::string sdir = t.file("session");
    std::string p = t.file("s.bin");
    write_file(p, str_bytes("ABCDEF"));
    std::string err;
    {
        auto d = Document::open_file(p);
        const uint8_t x = 'X';
        REQUIRE(d->insert(0, &x, 1));
        Session s(sdir);
        REQUIRE(s.save({d.get()}, 0, &err));
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        REQUIRE(d->save(nullptr, &err));  // rewrite; then the process dies before the next autosave
    }
    CHECK(read_file(p) == str_bytes("XABCDEF"));
    {
        Session s(sdir);
        auto r = s.load();
        REQUIRE(r.docs.size() == 1);
        CHECK(doc_bytes(*r.docs[0]) == str_bytes("XABCDEF"));  // not "XXABCDE"
        CHECK_FALSE(r.docs[0]->dirty());
        REQUIRE(r.warnings.size() == 1);
        CHECK(r.warnings[0].find("saved just before") != std::string::npos);
        REQUIRE(s.save({r.docs[0].get()}, 0, &err));
    }
    CHECK(Session(sdir).load().warnings.empty());

    // In-place variant: content stays right and no undo entry reads the overwritten bytes.
    {
        auto d = Document::open_file(p);
        const uint8_t y = 'Y';
        REQUIRE(d->overwrite(3, &y, 1));
        Session s(sdir);
        REQUIRE(s.save({d.get()}, 0, &err));
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        REQUIRE(d->save(nullptr, &err));
        CHECK(d->current_source() == 0);  // in place
    }
    {
        auto r = Session(sdir).load();
        REQUIRE(r.docs.size() == 1);
        CHECK(doc_bytes(*r.docs[0]) == str_bytes("XABYDEF"));
        CHECK_FALSE(r.docs[0]->dirty());
        CHECK_FALSE(r.docs[0]->can_undo());
    }

    // If the session file cannot be rewritten after a save, the stale one is removed.
    {
        auto d = Document::open_file(p);
        const uint8_t z = 'Z';
        REQUIRE(d->insert(0, &z, 1));
        Session s(sdir);
        s.load();
        REQUIRE(s.save({d.get()}, 0, &err));
        auto files = os_list_files(sdir, ".hxs");
        REQUIRE(files.size() == 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        REQUIRE(d->save(nullptr, &err));
        d->view_generation++;
        fs::create_directories(from_u8(files[0] + ".tmp"));  // makes the atomic write fail
        CHECK_FALSE(s.save({d.get()}, 0, &err));
        CHECK(!fs::exists(from_u8(files[0])));
        fs::remove(from_u8(files[0] + ".tmp"));
    }
}

TEST_CASE("document: hot exit of a state referencing a large replaced file version is reported") {
    TempDir t;
    std::string sdir = t.file("session");
    std::string p = t.file("big.bin");
    Bytes orig = random_bytes(size_t(17) << 20, 5);
    write_file(p, orig);
    auto d = Document::open_file(p);
    const uint8_t x = 'X';
    REQUIRE(d->insert(0, &x, 1));
    std::string err;
    REQUIRE(d->save(nullptr, &err));  // rewrite
    CHECK(d->hot_exit_safe());
    REQUIRE(d->undo());  // back to the original content, which now only lives in the old version
    CHECK(d->dirty());
    CHECK_FALSE(d->hot_exit_safe());
    {
        Session s(sdir);
        REQUIRE(s.save({d.get()}, 0, &err));
    }
    d.reset();
    auto r = Session(sdir).load();
    REQUIRE(r.docs.size() == 1);
    REQUIRE(r.warnings.size() == 1);
    CHECK(r.warnings[0].find("too large to keep") != std::string::npos);
    CHECK(r.docs[0]->size() == orig.size() + 1);  // the saved version
}

TEST_CASE("document: save after the file was replaced or modified by another program") {
    TempDir t;
    std::string p = t.file("r.bin"), q = t.file("r2.bin");
    write_file(p, str_bytes("AAAAAAAA"));
    auto d = Document::open_file(p);
    write_file(q, str_bytes("BBBBBBBB"));
    fs::last_write_time(from_u8(q), fs::last_write_time(from_u8(p)));  // same size and mtime
    REQUIRE(os_replace_file(q, p));
    CHECK(d->changed_on_disk());  // different file identity
    const uint8_t x = 'X';
    REQUIRE(d->overwrite(0, &x, 1));
    std::string err;
    REQUIRE(d->save(nullptr, &err));  // rewrite from the still-open old version, not a patch
    CHECK(read_file(p) == str_bytes("XAAAAAAA"));
    CHECK(doc_bytes(*d) == str_bytes("XAAAAAAA"));
    CHECK_FALSE(d->dirty());
    CHECK_FALSE(d->changed_on_disk());

    // Modified in place: the cached and the re-read blocks would be a torn mix -> refuse.
    std::string m = t.file("m.bin");
    write_file(m, Bytes(256 * 1024, 'a'));
    auto e = Document::open_file(m);
    Bytes buf(65536);
    REQUIRE(e->read(0, buf.data(), buf.size()) == buf.size());  // cached
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    {
        auto f = OsFile::open(m, OsFile::Mode::ReadWrite);
        REQUIRE(f);
        Bytes bs(256 * 1024, 'b');
        REQUIRE(f->write_at(0, bs.data(), bs.size()));
    }
    REQUIRE(e->insert(e->size(), &x, 1));
    CHECK_FALSE(e->save(nullptr, &err));
    CHECK(err.find("modified on disk") != std::string::npos);
    CHECK(read_file(m) == Bytes(256 * 1024, 'b'));
    CHECK(e->dirty());
    REQUIRE(e->save(nullptr, &err, true));  // forced: consistent with the current disk contents
    Bytes want(256 * 1024, 'b');
    want.push_back('X');
    CHECK(read_file(m) == want);
}

TEST_CASE("document: saving through a symlink updates the target") {
    TempDir t;
    std::string real = t.file("real.bin"), link = t.file("link.bin");
    write_file(real, str_bytes("abcdef"));
    std::error_code ec;
    fs::create_symlink(from_u8(real), from_u8(link), ec);
    if (ec) {
        MESSAGE("symlinks unavailable here, skipped: " << ec.message());
        return;
    }
    CHECK(os_stat(link).size == 6);  // follows the link (Windows too)
    CHECK(os_resolve_symlinks(link) == u8(from_u8(real).lexically_normal()));
    CHECK(os_resolve_symlinks(real) == real);
    auto d = Document::open_file(link);
    REQUIRE(d);
    const uint8_t x = 'X';
    REQUIRE(d->insert(0, &x, 1));  // size change -> rewrite path
    std::string err;
    REQUIRE(d->save(nullptr, &err));
    CHECK(fs::is_symlink(from_u8(link)));
    CHECK(read_file(real) == str_bytes("Xabcdef"));
    CHECK(doc_bytes(*d) == str_bytes("Xabcdef"));
    REQUIRE(d->overwrite(1, &x, 1));  // in place through the link
    REQUIRE(d->save(nullptr, &err));
    CHECK(read_file(real) == str_bytes("XXbcdef"));
    CHECK(!tmp_left_over(t));
}

TEST_CASE("document: devices never take the rewrite path") {
#ifdef _WIN32
    const std::string dev = "\\\\.\\NUL";
#else
    const std::string dev = "/dev/null";
#endif
    FileStat st = os_stat(dev);
    REQUIRE(st.exists);
    CHECK(st.is_device);
    auto d = Document::open_file(dev);
    REQUIRE(d);
    CHECK_FALSE(d->changed_on_disk());
    const uint8_t x = 'X';
    REQUIRE(d->insert(0, &x, 1));
    std::string err;
    CHECK_FALSE(d->save(nullptr, &err));
    CHECK(err.find("device") != std::string::npos);
    CHECK_FALSE(os_stat(dev + ".hexer-tmp").exists);
    auto u = Document::create_from_bytes("U", &x, 1);
    CHECK_FALSE(u->save_as(dev, nullptr, &err));
    CHECK(err.find("device") != std::string::npos);
}

TEST_CASE("document: add-buffer chunks nothing references are released") {
    auto d = Document::create_empty("u");
    Bytes big(size_t(3) << 20, 0x11), big2(size_t(3) << 20, 0x22);
    REQUIRE(d->insert(0, big.data(), big.size()));
    auto snap = d->snapshot();  // a reader still using those bytes
    REQUIRE(d->undo());
    REQUIRE(d->insert(0, big2.data(), big2.size()));  // drops the redo state -> its chunk is unused
    size_t live = 0;
    uint64_t bytes = 0;
    for (const auto& c : d->add_buffer().chunks())
        if (c->capacity) {
            ++live;
            bytes += c->capacity;
        }
    CHECK(live == 1);
    CHECK(bytes == big2.size());
    CHECK(doc_bytes(*d) == big2);
    REQUIRE(d->undo());
    CHECK(d->size() == 0);
    REQUIRE(d->redo());
    CHECK(doc_bytes(*d) == big2);
    Bytes old(big.size());
    REQUIRE(snap->read(0, old.data(), old.size()) == old.size());
    CHECK(old == big);  // the snapshot keeps the released chunk alive
    // Fill + undo repeatedly does not accumulate pattern chunks.
    auto e = Document::create_from_bytes("f", big.data(), big.size());
    const uint8_t pat[2] = {1, 2};
    for (int i = 0; i < 10; ++i) {
        REQUIRE(e->fill(0, big.size(), pat, 2));
        REQUIRE(e->undo());
    }
    REQUIRE(e->fill(0, 8, pat, 2));
    uint64_t total = 0;
    for (const auto& c : e->add_buffer().chunks()) total += c->capacity;
    CHECK(total <= big.size() + 2 * AddBuffer::kChunkSize);
    REQUIRE(e->undo());
    CHECK(doc_bytes(*e) == big);
}

TEST_CASE("document: unreadable bytes are reported per byte and by io_error()") {
    TempDir t;
    std::string p = t.file("io.bin");
    write_file(p, str_bytes("abcdefgh"));
    auto d = Document::open_file(p);
    REQUIRE(d);
    const uint8_t z = 'Z';
    REQUIRE(d->overwrite(2, &z, 1));
    uint8_t buf[8], bad[8];
    std::memset(bad, 7, sizeof bad);
    REQUIRE(d->read(0, buf, 8, bad) == 8);
    for (uint8_t b : bad) CHECK(b == 0);
    CHECK_FALSE(d->io_error());

    d->original()->close_file();  // every read of the file fails from now on
    REQUIRE(d->read(0, buf, 8, bad) == 8);
    for (int i = 0; i < 8; ++i) {
        CHECK(bad[i] == (i == 2 ? 0 : 1));        // the edited byte lives in the add buffer
        CHECK(buf[i] == (i == 2 ? 'Z' : 0));      // unreadable bytes still read as 0
    }
    CHECK(d->io_error());
    REQUIRE(d->read(6, buf, 8, bad) == 2);  // clamped to the size like read()
    CHECK(bad[0] == 1);
    CHECK(bad[1] == 1);
    CHECK(d->original()->reopen_file());
    CHECK(d->io_error());  // sticky
}

TEST_CASE("document: Progress::committing is cleared after every save") {
    TempDir t;
    std::string p = t.file("commit.bin");
    write_file(p, random_bytes(1 << 20, 3));
    auto d = Document::open_file(p);
    const uint8_t v = 1;
    Progress pr;
    std::string err;
    for (int pass = 0; pass < 2; ++pass) {
        if (pass == 0) REQUIRE(d->overwrite(5, &v, 1));  // in place
        else REQUIRE(d->insert(5, &v, 1));               // rewrite
        CHECK_FALSE(pr.committing.load());
        REQUIRE(d->save(&pr, &err));
        CHECK_FALSE(pr.committing.load());
    }
    // A save cancelled before its point of no return never sets it.
    REQUIRE(d->insert(5, &v, 1));
    pr.cancel = true;
    CHECK_FALSE(d->save(&pr, &err));
    CHECK_FALSE(pr.committing.load());
}

// =============================================================================================
// document: .backup on the first save
// =============================================================================================
TEST_CASE("os_file: os_copy_file copies, reports progress, cancels cleanly") {
    TempDir t;
    std::string a = t.file("src.bin"), b = t.file("dst.bin");
    Bytes data = random_bytes((8 << 20) + 123, 77);
    write_file(a, data);
    write_file(b, str_bytes("stale"));
    uint64_t last_done = 0, last_total = 0;
    int calls = 0;
    std::string err;
    REQUIRE(os_copy_file(a, b, [&](uint64_t done, uint64_t total) {
        ++calls;
        CHECK(done >= last_done);
        last_done = done;
        last_total = total;
        return true;
    }, &err));
    CHECK(calls >= 1);
    CHECK(last_done == data.size());
    CHECK(last_total == data.size());
    CHECK(read_file(b) == data);
    REQUIRE(os_copy_file(a, b, {}, &err));  // no callback, replaces the existing copy
    CHECK(read_file(b) == data);

    std::string c = t.file("cancelled.bin");
    bool cancelled = false;
    CHECK_FALSE(os_copy_file(a, c, [](uint64_t, uint64_t) { return false; }, &err, &cancelled));
    CHECK(cancelled);
    CHECK_FALSE(os_stat(c).exists);
    cancelled = true;
    CHECK_FALSE(os_copy_file(t.file("missing.bin"), c, {}, &err, &cancelled));
    CHECK_FALSE(cancelled);
    CHECK_FALSE(err.empty());
    write_file(t.file("empty.bin"), {});
    REQUIRE(os_copy_file(t.file("empty.bin"), c, {}, &err));
    CHECK(os_stat(c).exists);
    CHECK(os_stat(c).size == 0);
}

TEST_CASE("os_file: os_hard_link gives a file a second name") {
    TempDir t;
    std::string a = t.file("a.bin"), b = t.file("b.bin");
    write_file(a, str_bytes("same file"));
    std::string err;
    REQUIRE(os_hard_link(a, b, &err));  // NTFS / ext4 / tmpfs all have hard links
    CHECK(read_file(b) == str_bytes("same file"));
    CHECK_FALSE(os_identity_differs(os_stat(a), os_stat(b)));
    CHECK_FALSE(os_hard_link(a, b, &err));  // the new name must not exist
    CHECK_FALSE(err.empty());
    REQUIRE(os_remove(a));
    CHECK(read_file(b) == str_bytes("same file"));
}

TEST_CASE("document: in-place save keeps the original as .backup, once") {
    BackupPolicy policy(true, 4ull << 30);
    TempDir t;
    std::string p = t.file("ip.bin"), bak = p + ".backup";
    Bytes orig = random_bytes(300000, 61);
    write_file(p, orig);
    write_file(bak + ".tmp", str_bytes("leftover of an interrupted copy"));  // replaced
    auto d = Document::open_file(p);
    REQUIRE(d);
    CHECK_FALSE(d->last_save_info().backup_created);
    const uint8_t v[3] = {1, 2, 3};
    REQUIRE(d->overwrite(1000, v, 3));
    Bytes s1 = doc_bytes(*d);
    Progress pr;
    std::string err;
    REQUIRE(d->save(&pr, &err));
    CHECK(d->current_source() == 0);  // in place
    SaveInfo info = d->last_save_info();
    CHECK(info.backup_created);
    CHECK_FALSE(info.backup_skipped);
    CHECK(read_file(info.backup_path) == orig);
    CHECK(read_file(bak) == orig);
    CHECK_FALSE(os_stat(bak + ".tmp").exists);
    CHECK(read_file(p) == s1);
    // Progress covers backup copy + preserved history bytes + written bytes.
    CHECK(pr.total.load() == orig.size() + 3 + 3);
    CHECK(pr.done.load() == pr.total.load());

    // Second save: the backup keeps the original.
    REQUIRE(d->overwrite(2000, v, 3));
    Bytes s2 = doc_bytes(*d);
    REQUIRE(d->save(&pr, &err));
    CHECK_FALSE(d->last_save_info().backup_created);
    CHECK(read_file(bak) == orig);
    CHECK(read_file(p) == s2);
    // A rewrite save later does not back up again either.
    REQUIRE(d->insert(0, v, 1));
    REQUIRE(d->save(&pr, &err));
    CHECK(d->current_source() == 1);
    CHECK_FALSE(d->last_save_info().backup_created);
    CHECK(read_file(bak) == orig);
    while (d->undo()) {
    }
    CHECK(doc_bytes(*d) == orig);

    // Reopening the file and saving again never replaces the original's backup.
    d.reset();
    auto d2 = Document::open_file(p);
    REQUIRE(d2->overwrite(5, v, 1));
    REQUIRE(d2->save(nullptr, &err));
    CHECK_FALSE(d2->last_save_info().backup_created);
    CHECK(read_file(bak) == orig);
    // Same for a rewrite save from a fresh document.
    auto d3 = Document::open_file(p);
    REQUIRE(d3->insert(0, v, 2));
    REQUIRE(d3->save(nullptr, &err));
    CHECK_FALSE(d3->last_save_info().backup_created);
    CHECK(read_file(bak) == orig);
    // Deleting the .backup by hand starts over: the next first save keeps the then-current file.
    REQUIRE(os_remove(bak));
    Bytes now = read_file(p);
    auto d4 = Document::open_file(p);
    REQUIRE(d4->overwrite(7, v, 1));
    REQUIRE(d4->save(nullptr, &err));
    CHECK(d4->last_save_info().backup_created);
    CHECK(read_file(bak) == now);
}

TEST_CASE("document: rewrite save keeps the original file as .backup and history still reads it") {
    BackupPolicy policy(true, 1000);  // the size limit only applies to in-place copies
    TempDir t;
    std::string p = t.file("rw.bin"), bak = p + ".backup";
    Bytes orig = random_bytes(200000, 62);
    write_file(p, orig);
    FileStat before = os_stat(p);
    auto d = Document::open_file(p);
    REQUIRE(d);
    auto old_snap = d->snapshot();
    Bytes hello = str_bytes("hello");
    REQUIRE(d->insert(10, hello.data(), hello.size()));
    Bytes s1 = doc_bytes(*d);
    Progress pr;
    std::string err;
    REQUIRE(d->save(&pr, &err));
    CHECK(err.empty());
    CHECK(d->current_source() == 1);
    SaveInfo info = d->last_save_info();
    CHECK(info.backup_created);
    CHECK(read_file(bak) == orig);
    CHECK(read_file(p) == s1);
    CHECK(pr.done.load() == s1.size());
    CHECK_FALSE(tmp_left_over(t));
    // The backup IS the old file (hard link or rename, not a copy).
    FileStat bst = os_stat(bak);
    CHECK_FALSE(os_identity_differs(bst, before));
    CHECK(bst.mtime_ns == before.mtime_ns);
    CHECK_FALSE(d->changed_on_disk());

    // Our handle on the old version (now named .backup) keeps reading it: undo + old snapshots.
    Bytes os(orig.size());
    REQUIRE(old_snap->read(0, os.data(), os.size()) == orig.size());
    CHECK(os == orig);
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == orig);
    REQUIRE(d->save(nullptr, &err));  // rewrite from the old version; no second backup
    CHECK_FALSE(d->last_save_info().backup_created);
    CHECK(read_file(p) == orig);
    CHECK(read_file(bak) == orig);
    REQUIRE(d->redo());
    CHECK(doc_bytes(*d) == s1);
    REQUIRE(d->save(nullptr, &err));
    CHECK(read_file(p) == s1);
    CHECK(read_file(bak) == orig);
}

TEST_CASE("document: a hot-exit restored document does not replace its .backup again") {
    BackupPolicy policy(true, 4ull << 30);
    TempDir t;
    std::string sdir = t.file("session"), p = t.file("hb.bin"), bak = p + ".backup";
    Bytes orig = random_bytes(5000, 63);
    write_file(p, orig);
    std::string err;
    {
        auto d = Document::open_file(p);
        REQUIRE(d);
        Bytes x = str_bytes("first");
        REQUIRE(d->insert(0, x.data(), x.size()));  // rewrite save
        REQUIRE(d->save(nullptr, &err));
        CHECK(d->last_save_info().backup_created);
        CHECK(read_file(bak) == orig);
        CHECK_FALSE(os_stat(bak + ".tmp").exists);
        REQUIRE(d->insert(0, x.data(), x.size()));  // unsaved edit for the session
        Session s(sdir);
        REQUIRE(s.save({d.get()}, 0, &err));
    }
    auto r = Session(sdir).load();
    REQUIRE(r.docs.size() == 1);
    Document& d2 = *r.docs[0];
    REQUIRE(d2.save(nullptr, &err));
    CHECK_FALSE(d2.last_save_info().backup_created);
    CHECK(read_file(bak) == orig);  // still the original
    // A document opened fresh keeps the existing original backup as well.
    auto d3 = Document::open_file(p);
    REQUIRE(d3);
    const uint8_t z = 0;
    REQUIRE(d3->overwrite(0, &z, 1));
    REQUIRE(d3->save(nullptr, &err));
    CHECK_FALSE(d3->last_save_info().backup_created);
    CHECK(read_file(bak) == orig);
}

TEST_CASE("document: save_as backs up an existing different target; new files get none") {
    BackupPolicy policy(true, 4ull << 30);
    TempDir t;
    std::string a = t.file("a.bin"), b = t.file("b.bin"), c = t.file("c.bin");
    Bytes ab = random_bytes(5000, 63), bb = random_bytes(7000, 64);
    write_file(a, ab);
    write_file(b, bb);
    auto d = Document::open_file(a);
    const uint8_t v = 7;
    REQUIRE(d->insert(0, &v, 1));
    std::string err;
    REQUIRE(d->save_as(b, nullptr, &err));
    CHECK(d->last_save_info().backup_created);
    CHECK(read_file(b + ".backup") == bb);
    CHECK_FALSE(os_stat(a + ".backup").exists);  // a was never written
    CHECK(read_file(a) == ab);
    Bytes first = read_file(b);
    REQUIRE(d->overwrite(0, &v, 1));
    REQUIRE(d->insert(0, &v, 1));
    REQUIRE(d->save(nullptr, &err));  // b again: already backed up
    CHECK_FALSE(d->last_save_info().backup_created);
    CHECK(read_file(b + ".backup") == bb);
    REQUIRE(d->save_as(a, nullptr, &err));  // back onto a: first write there
    CHECK(d->last_save_info().backup_created);
    CHECK(read_file(a + ".backup") == ab);

    // A target that did not exist gets no backup, now or on later saves.
    REQUIRE(d->save_as(c, nullptr, &err));
    CHECK_FALSE(d->last_save_info().backup_created);
    REQUIRE(d->insert(0, &v, 1));
    REQUIRE(d->save(nullptr, &err));
    REQUIRE(d->overwrite(0, &v, 1));
    REQUIRE(d->save(nullptr, &err));
    CHECK_FALSE(os_stat(c + ".backup").exists);
    auto u = Document::create_empty("Untitled 1");
    REQUIRE(u->insert(0, &v, 1));
    std::string n = t.file("new.bin");
    REQUIRE(u->save_as(n, nullptr, &err));
    REQUIRE(u->overwrite(0, &v, 1));
    REQUIRE(u->insert(0, &v, 1));
    REQUIRE(u->save(nullptr, &err));
    CHECK_FALSE(u->last_save_info().backup_created);
    CHECK_FALSE(os_stat(n + ".backup").exists);
}

TEST_CASE("document: backup size limit, disabled policy, cancel") {
    TempDir t;
    const uint8_t v = 9;
    std::string err;
    SUBCASE("files above the limit are saved in place without a backup, reported once") {
        BackupPolicy policy(true, 1000);
        std::string p = t.file("big.bin");
        Bytes orig = random_bytes(10000, 65);
        write_file(p, orig);
        auto d = Document::open_file(p);
        REQUIRE(d->overwrite(10, &v, 1));
        Progress pr;
        REQUIRE(d->save(&pr, &err));
        SaveInfo info = d->last_save_info();
        CHECK_FALSE(info.backup_created);
        CHECK(info.backup_skipped);
        CHECK(info.note.find("limit") != std::string::npos);
        CHECK_FALSE(os_stat(p + ".backup").exists);
        CHECK(pr.total.load() == 2);  // no backup bytes
        REQUIRE(d->overwrite(11, &v, 1));
        REQUIRE(d->save(&pr, &err));
        CHECK_FALSE(d->last_save_info().backup_skipped);
        CHECK_FALSE(os_stat(p + ".backup").exists);
    }
    SUBCASE("disabled: no backup; enabling later backs up on the next save") {
        BackupPolicy policy(false, 0);
        std::string p = t.file("off.bin");
        Bytes orig = random_bytes(10000, 66);
        write_file(p, orig);
        auto d = Document::open_file(p);
        REQUIRE(d->overwrite(10, &v, 1));
        REQUIRE(d->save(nullptr, &err));
        REQUIRE(d->insert(10, &v, 1));
        REQUIRE(d->save(nullptr, &err));
        CHECK_FALSE(d->last_save_info().backup_created);
        CHECK_FALSE(d->last_save_info().backup_skipped);
        CHECK_FALSE(os_stat(p + ".backup").exists);
        Document::set_backup_policy(true, 0);
        Bytes now = read_file(p);
        REQUIRE(d->overwrite(10, &v, 1));
        REQUIRE(d->overwrite(11, &v, 1));
        REQUIRE(d->save(nullptr, &err));
        CHECK(d->last_save_info().backup_created);
        CHECK(read_file(p + ".backup") == now);
    }
    SUBCASE("cancel before/while copying the backup leaves the file and no backup") {
        BackupPolicy policy(true, 0);
        std::string p = t.file("cancel.bin");
        Bytes orig = random_bytes(100000, 67);
        write_file(p, orig);
        auto d = Document::open_file(p);
        REQUIRE(d->overwrite(10, &v, 1));
        Progress pr;
        pr.cancel = true;
        CHECK_FALSE(d->save(&pr, &err));
        CHECK(err.find("cancel") != std::string::npos);
        CHECK_FALSE(pr.committing.load());
        CHECK_FALSE(os_stat(p + ".backup").exists);
        CHECK_FALSE(os_stat(p + ".backup.tmp").exists);
        CHECK(read_file(p) == orig);
        CHECK(d->dirty());
        CHECK_FALSE(d->last_save_info().backup_created);
        pr.cancel = false;
        REQUIRE(d->save(&pr, &err));  // the cancelled attempt did not count as the backup
        CHECK(d->last_save_info().backup_created);
        CHECK(read_file(p + ".backup") == orig);
    }
}

TEST_CASE("session: single-instance inbox (post, take, withdraw, leftovers)") {
    TempDir t;
    std::string sdir = t.file("session");
    REQUIRE(os_mkdirs(sdir));
    CHECK_FALSE(session_primary_running(sdir));
    {
        Session s(sdir);
        CHECK(s.primary());
        CHECK_FALSE(s.secondary());
        CHECK(session_primary_running(sdir));  // the main dir's lock is held
        Session second(sdir);
        CHECK_FALSE(second.primary());
        CHECK(second.secondary());
        CHECK(session_primary_running(sdir));
    }
    CHECK_FALSE(session_primary_running(sdir));  // released when the instance ends

    CHECK(inbox_take(sdir).empty());  // no inbox dir yet
    std::string a, b, c;
    const std::string uni = "C:/d\xC3\xBC/\xE2\x82\xAC.bin";  // UTF-8 survives unchanged
    REQUIRE(inbox_post(sdir, {"/x/one.bin", uni}, &a));
    REQUIRE(inbox_post(sdir, {}, &b));  // "come to the front" only
    CHECK(a != b);
    CHECK(os_stat(a).exists);
    auto msgs = inbox_take(sdir);
    REQUIRE(msgs.size() == 2);
    std::sort(msgs.begin(), msgs.end());  // name order is not chronological
    CHECK(msgs[0].empty());
    CHECK(msgs[1] == std::vector<std::string>{"/x/one.bin", uni});
    CHECK_FALSE(os_stat(a).exists);
    CHECK_FALSE(inbox_withdraw(a));  // already taken
    CHECK(inbox_take(sdir).empty());  // each message is delivered once
    CHECK(os_list_files(path_join(sdir, "inbox"), "").empty());

    // Withdrawn before the running instance took it: never delivered.
    REQUIRE(inbox_post(sdir, {"/y.bin"}, &c));
    CHECK(inbox_withdraw(c));
    CHECK(inbox_take(sdir).empty());

    // A claimed message that an instance died before reading is delivered at the next start;
    // so is one it never got to (stale .paths).
    REQUIRE(inbox_post(sdir, {"/claimed.bin"}, &a));
    REQUIRE(os_replace_file(a, a + ".taken"));
    REQUIRE(inbox_post(sdir, {"/stale.bin"}, &b));
    msgs = inbox_take(sdir);
    std::sort(msgs.begin(), msgs.end());
    REQUIRE(msgs.size() == 2);
    CHECK(msgs[0] == std::vector<std::string>{"/claimed.bin"});
    CHECK(msgs[1] == std::vector<std::string>{"/stale.bin"});
    CHECK(os_list_files(path_join(sdir, "inbox"), "").empty());
}

TEST_CASE("session: version 1 files (bookmarks without notes) still load") {
    TempDir t;
    std::string sdir = t.file("session");
    // Without bookmarks a version 1 file differs from a version 2 one only in the version field
    // and the tail (v2: edits_dropped u8 + backed-up target count u32; v1: nothing when false).
    auto a = Document::create_from_bytes("Old", reinterpret_cast<const uint8_t*>("old!"), 4);
    std::string err;
    {
        Session s(sdir);
        REQUIRE(s.save({a.get()}, 0, &err));
    }
    auto files = os_list_files(sdir, ".hxs");
    REQUIRE(files.size() == 1);
    Bytes f = read_file(files[0]);
    REQUIRE(f.size() > 12);
    CHECK(f[4] == 2);  // current version
    f[4] = 1;
    f.erase(f.end() - 4 - 5, f.end() - 4);
    const uint32_t crc = test_crc32(f.data(), f.size() - 4);
    for (int i = 0; i < 4; ++i) f[f.size() - 4 + size_t(i)] = uint8_t(crc >> (8 * i));
    write_file(files[0], f);
    auto r = Session(sdir).load();
    CHECK(r.warnings.empty());
    REQUIRE(r.docs.size() == 1);
    CHECK(doc_bytes(*r.docs[0]) == str_bytes("old!"));
    f[4] = 9;  // a newer, unknown version is not read
    const uint32_t crc9 = test_crc32(f.data(), f.size() - 4);
    for (int i = 0; i < 4; ++i) f[f.size() - 4 + size_t(i)] = uint8_t(crc9 >> (8 * i));
    write_file(files[0], f);
    auto r9 = Session(sdir).load();
    CHECK(r9.docs.empty());
}

TEST_CASE("document: abort_group rolls the group back and keeps the history as it was") {
    const Bytes orig = {1, 2, 3, 4, 5, 6, 7, 8};
    auto d = Document::create_from_bytes("t", orig.data(), orig.size());
    auto content = [&] {
        Bytes b(size_t(d->size()));
        d->read(0, b.data(), b.size());
        return b;
    };
    const uint8_t x = 0xAA, y = 0xBB;
    REQUIRE(d->overwrite(0, &x, 1));
    REQUIRE(d->overwrite(1, &x, 1));
    REQUIRE(d->undo());
    const Bytes before = content();
    REQUIRE(d->undo_stack().size() == 1);
    REQUIRE(d->redo_stack().size() == 1);
    d->view().cursor = d->view().anchor = 3;
    Bookmark bm;
    bm.offset = 2;

    // Several edits (and a bookmark) in one group, aborted: nothing happened.
    d->begin_group("Batch");
    REQUIRE(d->overwrite(4, &y, 1));
    REQUIRE(d->insert(0, &y, 1));
    REQUIRE(d->add_bookmark(bm));
    d->view().cursor = 7;
    CHECK(d->redo_stack().empty());  // set aside while the group is open
    d->abort_group();
    CHECK_FALSE(d->in_group());
    CHECK(content() == before);
    CHECK(d->undo_stack().size() == 1);
    REQUIRE(d->redo_stack().size() == 1);
    CHECK(d->view().bookmarks.empty());
    CHECK(d->view().cursor == 3);
    REQUIRE(d->redo());  // the earlier redo step still applies
    CHECK(content()[1] == 0xAA);
    REQUIRE(d->undo());

    // Nested: an inner abort fails the whole outer group (rolled back when it closes).
    d->begin_group("outer");
    REQUIRE(d->overwrite(5, &y, 1));
    d->begin_group("inner");
    REQUIRE(d->overwrite(6, &y, 1));
    d->abort_group();
    CHECK(d->in_group());
    REQUIRE(d->overwrite(7, &y, 1));
    d->end_group();
    CHECK(content() == before);
    CHECK(d->undo_stack().size() == 1);
    CHECK(d->redo_stack().size() == 1);

    // The bytes an aborted group appended are released at once (not kept until a later edit).
    {
        const Bytes big(size_t(3) << 20, 0x33);
        d->begin_group("big");
        REQUIRE(d->insert(0, big.data(), big.size()));
        d->abort_group();
        uint64_t live = 0;
        for (const auto& c : d->add_buffer().chunks()) live += c->capacity;
        CHECK(live < big.size());
        CHECK(content() == before);
        CHECK(d->redo_stack().size() == 1);
    }

    // Aborting a group without edits changes nothing; abort_group outside a group is a no-op.
    d->begin_group("empty");
    d->abort_group();
    d->abort_group();
    CHECK(d->redo_stack().size() == 1);

    // A group that ends normally is one step and discards the redo stack like any edit.
    d->begin_group("ok");
    REQUIRE(d->overwrite(5, &y, 1));
    REQUIRE(d->overwrite(6, &y, 1));
    d->end_group();
    CHECK(d->undo_stack().size() == 2);
    CHECK(d->redo_stack().empty());
    CHECK(d->undo_stack().back().label == "ok");
    REQUIRE(d->undo());
    CHECK(content() == before);
}

TEST_CASE("document: a device path denied access carries the administrator / root hint") {
#ifdef _WIN32
    const std::string dev = "\\\\.\\PhysicalDrive0";
#else
    const std::string dev = "/dev/sda";
#endif
    std::string err;
    auto d = Document::open_file(dev, &err);
    if (d || err.find("denied") == std::string::npos) return;  // elevated, or no such device here
    CHECK(err.find("administrator") != std::string::npos);
    std::string err2;
    CHECK_FALSE(Document::open_device(dev, false, &err2));
    CHECK(err2.find("administrator") != std::string::npos);
    CHECK(err2.find("administrator") == err2.rfind("administrator"));  // once, not twice
}
