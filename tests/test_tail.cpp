// Tests for live tail: FileSource::extend + Document::refresh_appended (files growing by appending).
#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "core/document.h"
#include "core/file_source.h"
#include "core/os_file.h"

using namespace hx;
namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

namespace {

fs::path from_u8(const std::string& s) { return fs::path(std::u8string(s.begin(), s.end())); }

struct TempDir {
    fs::path dir;
    TempDir() {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("hexer-tail-" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(dir);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    std::string file(const std::string& name) const {
        auto s = (dir / name).u8string();
        return std::string(s.begin(), s.end());
    }
};

Bytes random_bytes(size_t n, uint64_t seed) {
    std::mt19937_64 rng(seed);
    Bytes b(n);
    for (auto& x : b) x = uint8_t(rng());
    return b;
}

Bytes str_bytes(const char* s) { return Bytes(s, s + std::strlen(s)); }

void write_file(const std::string& path, const Bytes& b) {
    std::ofstream f(from_u8(path), std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(b.data()), std::streamsize(b.size()));
}

void append_file(const std::string& path, const Bytes& b) {
    std::ofstream f(from_u8(path), std::ios::binary | std::ios::app);
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

Bytes snap_bytes(const Snapshot& s) {
    Bytes b(size_t(s.size()));
    if (!b.empty()) REQUIRE(s.read(0, b.data(), b.size()) == b.size());
    return b;
}

Bytes cat(Bytes a, const Bytes& b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

void mtime_tick() { std::this_thread::sleep_for(std::chrono::milliseconds(20)); }

}  // namespace

TEST_CASE("tail: FileSource::extend only grows and drops the short last block") {
    TempDir t;
    const std::string p = t.file("a.bin");
    Bytes base = random_bytes(70000, 1);  // second 64 KiB block is partial
    write_file(p, base);
    auto src = FileSource::open(p);
    REQUIRE(src);
    uint8_t b[16];
    REQUIRE(src->read(69990, b, 16) == 10);  // caches the short block at EOF
    Bytes more = random_bytes(100000, 2);
    append_file(p, more);
    CHECK(src->size() == 70000);
    CHECK_FALSE(src->extend(100));
    CHECK(src->extend(70000));
    CHECK(src->extend(170000));
    CHECK(src->size() == 170000);
    Bytes all = cat(base, more);
    Bytes got(all.size());
    REQUIRE(src->read(0, got.data(), got.size()) == got.size());
    CHECK(got == all);
    REQUIRE(src->read(69990, b, 16) == 16);  // across the old end, through the cache
    CHECK(std::memcmp(b, all.data() + 69990, 16) == 0);
    CHECK_FALSE(src->io_error());
}

TEST_CASE("tail: no change, untitled") {
    TempDir t;
    const std::string p = t.file("a.log");
    write_file(p, str_bytes("hello"));
    auto d = Document::open_file(p);
    REQUIRE(d);
    uint64_t added = 99;
    CHECK(d->refresh_appended(&added) == GrowResult::Unchanged);
    CHECK(added == 0);
    CHECK(d->refresh_appended() == GrowResult::Unchanged);
    auto u = Document::create_empty("Untitled 1");
    CHECK(u->refresh_appended() == GrowResult::Unchanged);
    auto ub = Document::create_from_bytes("Untitled 2", reinterpret_cast<const uint8_t*>("xy"), 2);
    CHECK(ub->refresh_appended() == GrowResult::Unchanged);
}

TEST_CASE("tail: growth makes the new bytes readable") {
    TempDir t;
    const std::string p = t.file("a.log");
    Bytes base = random_bytes(5000, 3);
    write_file(p, base);
    auto d = Document::open_file(p);
    REQUIRE(d);
    uint8_t b[8];
    REQUIRE(d->read(4995, b, 8) == 5);  // cache the partial block
    const uint64_t gen = d->generation();
    Bytes more = random_bytes(3000, 4);
    append_file(p, more);
    CHECK(d->changed_on_disk());
    uint64_t added = 0;
    std::string err;
    CHECK(d->refresh_appended(&added, &err) == GrowResult::Grown);
    CHECK(added == 3000);
    CHECK(d->size() == 8000);
    CHECK(doc_bytes(*d) == cat(base, more));
    CHECK_FALSE(d->changed_on_disk());
    CHECK_FALSE(d->dirty());
    CHECK_FALSE(d->can_undo());  // not an undo step
    CHECK(d->generation() != gen);
    CHECK(d->table().pieces().size() == 1);
    CHECK_FALSE(d->is_modified_range(0, d->size()));
    CHECK(d->refresh_appended() == GrowResult::Unchanged);
}

TEST_CASE("tail: repeated small appends stay one piece") {
    TempDir t;
    const std::string p = t.file("a.log");
    Bytes all = str_bytes("start\n");
    write_file(p, all);
    auto d = Document::open_file(p);
    REQUIRE(d);
    for (int i = 0; i < 50; ++i) {
        Bytes line = str_bytes(("line " + std::to_string(i) + "\n").c_str());
        append_file(p, line);
        all = cat(all, line);
        uint64_t added = 0;
        REQUIRE(d->refresh_appended(&added) == GrowResult::Grown);
        CHECK(added == line.size());
        CHECK(d->refresh_appended() == GrowResult::Unchanged);
    }
    CHECK(doc_bytes(*d) == all);
    CHECK(d->table().pieces().size() == 1);
    CHECK_FALSE(d->dirty());
}

TEST_CASE("tail: edits and undo/redo history keep the tail") {
    TempDir t;
    const std::string p = t.file("a.log");
    const Bytes base = str_bytes("0123456789");
    write_file(p, base);
    auto d = Document::open_file(p);
    REQUIRE(d);
    REQUIRE(d->insert(5, reinterpret_cast<const uint8_t*>("AB"), 2));  // 01234AB56789
    REQUIRE(d->overwrite(0, reinterpret_cast<const uint8_t*>("Z"), 1));  // Z1234AB56789
    REQUIRE(d->erase(11, 1));                                           // Z1234AB5678
    REQUIRE(d->undo());                                                  // redo stack: the erase
    const Bytes s1 = str_bytes("01234AB56789"), s2 = str_bytes("Z1234AB56789"), s3 = str_bytes("Z1234AB5678");
    CHECK(doc_bytes(*d) == s2);

    const Bytes tail1 = str_bytes("+tail one");
    append_file(p, tail1);
    REQUIRE(d->refresh_appended() == GrowResult::Grown);
    CHECK(d->dirty());
    CHECK(doc_bytes(*d) == cat(s2, tail1));
    CHECK(d->is_modified_range(0, 1));
    CHECK_FALSE(d->is_modified_range(12, tail1.size()));

    REQUIRE(d->redo());
    CHECK(doc_bytes(*d) == cat(s3, tail1));  // the erased byte stays erased, the tail follows
    REQUIRE(d->undo());
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == cat(s1, tail1));

    const Bytes tail2 = str_bytes("+two");
    append_file(p, tail2);
    REQUIRE(d->refresh_appended() == GrowResult::Grown);
    CHECK(doc_bytes(*d) == cat(cat(s1, tail1), tail2));
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == cat(cat(base, tail1), tail2));
    CHECK_FALSE(d->dirty());  // back at the file contents
    CHECK_FALSE(d->can_undo());
    REQUIRE(d->redo());
    REQUIRE(d->redo());
    REQUIRE(d->redo());
    CHECK(doc_bytes(*d) == cat(cat(s3, tail1), tail2));
    CHECK_FALSE(d->can_redo());
    for (const UndoEntry& u : d->undo_stack()) CHECK(u.pieces.size() <= 4);  // tails merged, no piece growth
}

TEST_CASE("tail: save after growth (in place and rewrite), then keep tailing") {
    TempDir t;
    const std::string p = t.file("a.log");
    write_file(p, str_bytes("abcdef"));
    auto d = Document::open_file(p);
    REQUIRE(d);
    REQUIRE(d->overwrite(0, reinterpret_cast<const uint8_t*>("X"), 1));
    append_file(p, str_bytes("ghij"));
    REQUIRE(d->refresh_appended() == GrowResult::Grown);
    std::string err;
    REQUIRE(d->save(nullptr, &err));  // in place: size-preserving over the grown file
    CHECK(read_file(p) == str_bytes("Xbcdefghij"));
    CHECK_FALSE(d->changed_on_disk());

    REQUIRE(d->insert(1, reinterpret_cast<const uint8_t*>("--"), 2));
    REQUIRE(d->save(nullptr, &err));  // rewrite: a new file version
    CHECK(read_file(p) == str_bytes("X--bcdefghij"));
    mtime_tick();
    append_file(p, str_bytes("KL"));
    REQUIRE(d->refresh_appended() == GrowResult::Grown);
    CHECK(doc_bytes(*d) == str_bytes("X--bcdefghijKL"));
    CHECK_FALSE(d->dirty());
    REQUIRE(d->undo());  // undo the insert: older version + the tail of the current one
    CHECK(doc_bytes(*d) == str_bytes("XbcdefghijKL"));
    REQUIRE(d->undo());
    CHECK(doc_bytes(*d) == str_bytes("abcdefghijKL"));
}

TEST_CASE("tail: prefix rewrite, shrink, same-size rewrite, replace, delete -> NotAppend") {
    TempDir t;
    const std::string p = t.file("a.log");
    const Bytes base = random_bytes(10000, 5);

    SUBCASE("rewritten and longer") {
        write_file(p, base);
        auto d = Document::open_file(p);
        REQUIRE(d);
        CHECK(d->refresh_appended() == GrowResult::Unchanged);  // tail mode switched on
        Bytes other = base;
        other[9000] ^= 0xFF;  // inside the checked 4 KiB before the old end
        other = cat(other, str_bytes("more"));
        write_file(p, other);
        CHECK(d->refresh_appended() == GrowResult::NotAppend);
        CHECK(d->size() == base.size());
        CHECK(d->changed_on_disk());  // still reported for the reload flow
    }
    SUBCASE("rewritten small file") {
        write_file(p, str_bytes("abc"));
        auto d = Document::open_file(p);
        REQUIRE(d);
        CHECK(d->refresh_appended() == GrowResult::Unchanged);
        write_file(p, str_bytes("xbcdef"));
        CHECK(d->refresh_appended() == GrowResult::NotAppend);
    }
    SUBCASE("rewritten between two growths") {
        write_file(p, base);
        auto d = Document::open_file(p);
        REQUIRE(d);
        append_file(p, str_bytes("one"));
        REQUIRE(d->refresh_appended() == GrowResult::Grown);
        Bytes other = cat(base, str_bytes("ONE"));  // last bytes rewritten, then more appended
        write_file(p, cat(other, str_bytes("two")));
        CHECK(d->refresh_appended() == GrowResult::NotAppend);
        CHECK(d->size() == base.size() + 3);  // not extended (reload flow takes over)
    }
    SUBCASE("cached bytes differ (never polled before)") {
        write_file(p, base);
        auto d = Document::open_file(p);
        REQUIRE(d);
        uint8_t b[4];
        REQUIRE(d->read(base.size() - 4, b, 4) == 4);  // the view showed the end
        Bytes other = base;
        other.back() ^= 0x55;
        write_file(p, cat(other, str_bytes("more")));
        CHECK(d->refresh_appended() == GrowResult::NotAppend);
    }
    SUBCASE("shrunk") {
        write_file(p, base);
        auto d = Document::open_file(p);
        REQUIRE(d);
        write_file(p, Bytes(base.begin(), base.begin() + 100));
        CHECK(d->refresh_appended() == GrowResult::NotAppend);
        CHECK(d->size() == base.size());
    }
    SUBCASE("same size, modified") {
        write_file(p, base);
        auto d = Document::open_file(p);
        REQUIRE(d);
        mtime_tick();
        Bytes other = base;
        other[0] ^= 1;
        write_file(p, other);
        CHECK(d->refresh_appended() == GrowResult::NotAppend);
    }
    SUBCASE("replaced by another (longer) file") {
        write_file(p, base);
        auto d = Document::open_file(p);
        REQUIRE(d);
        const std::string q = t.file("new.log");
        write_file(q, cat(base, str_bytes("tail")));  // same prefix, but another file
        std::string err;
        REQUIRE(os_replace_file(q, p, &err));
        const FileStat known = d->disk_stat();
        const FileStat now = os_stat(p);
        if ((known.dev || known.ino) && (now.dev || now.ino)) CHECK(d->refresh_appended() == GrowResult::NotAppend);
    }
    SUBCASE("deleted") {
        write_file(p, base);
        auto d = Document::open_file(p);
        REQUIRE(d);
        std::error_code ec;
        fs::remove(from_u8(p), ec);
        if (!ec) CHECK(d->refresh_appended() == GrowResult::NotAppend);
    }
}

TEST_CASE("tail: snapshots taken before growth are unchanged") {
    TempDir t;
    const std::string p = t.file("a.log");
    const Bytes base = random_bytes(70000, 6);
    write_file(p, base);
    auto d = Document::open_file(p);
    REQUIRE(d);
    auto snap = d->snapshot();
    const Bytes more = random_bytes(200000, 7);
    append_file(p, more);
    REQUIRE(d->refresh_appended() == GrowResult::Grown);
    CHECK(snap->size() == base.size());
    CHECK(snap_bytes(*snap) == base);
    uint8_t b[16];
    CHECK(snap->read(69990, b, 16) == 10);
    auto snap2 = d->snapshot();
    CHECK(snap2->size() == base.size() + more.size());
    CHECK(snap_bytes(*snap2) == cat(base, more));
}

TEST_CASE("tail: concurrent snapshot readers while the file grows") {
    TempDir t;
    const std::string p = t.file("a.log");
    Bytes all = random_bytes(100000, 8);
    write_file(p, all);
    auto d = Document::open_file(p);
    REQUIRE(d);
    auto snap = d->snapshot();
    const Bytes expect = all;
    std::atomic<bool> stop{false}, bad{false};
    std::thread reader([&] {
        Bytes buf(expect.size());
        while (!stop) {
            if (snap->read(0, buf.data(), buf.size()) != buf.size() || buf != expect) bad = true;
            uint8_t b[64];
            if (snap->read(expect.size() - 32, b, 64) != 32) bad = true;
        }
    });
    for (int i = 0; i < 30; ++i) {
        Bytes more = random_bytes(777, 100 + uint64_t(i));
        append_file(p, more);
        all = cat(all, more);
        if (d->refresh_appended() != GrowResult::Grown) bad = true;
    }
    stop = true;
    reader.join();
    CHECK_FALSE(bad.load());
    CHECK(doc_bytes(*d) == all);
}

TEST_CASE("tail: persist and restore after growth") {
    TempDir t;
    const std::string p = t.file("a.log");
    write_file(p, str_bytes("hello world"));
    auto d = Document::open_file(p);
    REQUIRE(d);
    REQUIRE(d->overwrite(0, reinterpret_cast<const uint8_t*>("J"), 1));
    append_file(p, str_bytes(" and more"));
    REQUIRE(d->refresh_appended() == GrowResult::Grown);
    const Bytes expect = str_bytes("Jello world and more");
    REQUIRE(doc_bytes(*d) == expect);

    PersistedDoc pd = d->persist();
    d.reset();
    bool changed = true;
    std::string err;
    auto r = Document::restore(pd, &changed, &err);
    REQUIRE(r);
    CHECK_FALSE(changed);
    CHECK_FALSE(r->changed_on_disk());
    CHECK(r->dirty());
    CHECK(doc_bytes(*r) == expect);
    REQUIRE(r->undo());
    CHECK(doc_bytes(*r) == str_bytes("hello world and more"));
    CHECK_FALSE(r->dirty());
    REQUIRE(r->redo());

    append_file(p, str_bytes("!"));  // keeps tailing after a restore
    REQUIRE(r->refresh_appended() == GrowResult::Grown);
    CHECK(doc_bytes(*r) == str_bytes("Jello world and more!"));

    // Clean doc: persisted after growth, restored as the identity over the grown file.
    auto c = Document::open_file(p);
    REQUIRE(c);
    append_file(p, str_bytes("?"));
    REQUIRE(c->refresh_appended() == GrowResult::Grown);
    PersistedDoc pc = c->persist();
    auto rc = Document::restore(pc, &changed, &err);
    REQUIRE(rc);
    CHECK_FALSE(changed);
    CHECK_FALSE(rc->dirty());
    CHECK(doc_bytes(*rc) == str_bytes("hello world and more!?"));
}

TEST_CASE("tail: bytes appended while an in-place save runs are picked up afterwards") {
    // The save re-stats the file after writing, so disk_stat() already includes bytes an appender
    // added during the write; the next poll must still append them (stat equals disk_stat there).
    TempDir t;
    const std::string p = t.file("big.log");
    const Bytes base = random_bytes(size_t(24) << 20, 7);
    write_file(p, base);
    auto d = Document::open_file(p);
    REQUIRE(d);
    REQUIRE(d->refresh_appended() == GrowResult::Unchanged);
    const uint8_t pat = 0x5A;
    REQUIRE(d->fill(0, uint64_t(16) << 20, &pat, 1));
    const Bytes extra = str_bytes("appended during the save\n");
    Progress pr;
    std::atomic<bool> appended{false};
    std::thread appender([&] {
        while (!pr.committing.load() && !appended.load()) std::this_thread::yield();
        append_file(p, extra);
        appended = true;
    });
    std::string err;
    const bool ok = d->save(&pr, &err);
    appended = true;  // the save failed before committing: release the appender
    appender.join();
    REQUIRE_MESSAGE(ok, err);
    Bytes expect = base;
    std::fill(expect.begin(), expect.begin() + (16 << 20), pat);
    expect = cat(expect, extra);
    REQUIRE(read_file(p) == expect);
    GrowResult r = d->refresh_appended();
    CHECK((r == GrowResult::Grown || r == GrowResult::Unchanged));
    if (r == GrowResult::Unchanged) r = d->refresh_appended();  // (appended after the save's stat)
    CHECK(d->size() == expect.size());
    CHECK(doc_bytes(*d) == expect);
    CHECK_FALSE(d->dirty());
    CHECK_FALSE(d->changed_on_disk());
}
