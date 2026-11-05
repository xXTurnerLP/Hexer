// Tests for session extras: per-document (PersistedDoc::extras, session file v3) and session-level
// (Session::set_extra, stored in the index), backward compatibility with v2 session files, and the
// Bookmarks "all open files" setting.
#include <doctest/doctest.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "core/document.h"
#include "core/os_file.h"
#include "core/session.h"
#include "core/settings.h"

using namespace hx;
namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

namespace {

struct TempDir {
    fs::path dir;
    TempDir() {
        std::random_device rd;
        dir = fs::temp_directory_path() / ("hexer-test-session-" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(dir);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    std::string path() const {
        auto s = dir.u8string();
        return std::string(s.begin(), s.end());
    }
    std::string file(const std::string& name) const { return path_join(path(), name); }
};

Bytes read_file(const std::string& path) {
    std::ifstream f(fs::path(std::u8string(path.begin(), path.end())), std::ios::binary);
    return Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

void write_file(const std::string& path, const Bytes& b) {
    std::ofstream f(fs::path(std::u8string(path.begin(), path.end())), std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(b.data()), std::streamsize(b.size()));
}

Bytes doc_bytes(const Document& d) {
    Bytes b(size_t(d.size()));
    if (!b.empty()) REQUIRE(d.read(0, b.data(), b.size()) == b.size());
    return b;
}

std::unique_ptr<Document> make_doc(const char* name, const std::string& text) {
    return Document::create_from_bytes(name, reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

uint32_t le32(const Bytes& b, size_t at) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= uint32_t(b[at + size_t(i)]) << (8 * i);
    return v;
}

void put_le32(Bytes& b, size_t at, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[at + size_t(i)] = uint8_t(v >> (8 * i));
}

uint32_t crc32(const Bytes& b, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) {
        c ^= b[i];
        for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
    }
    return c ^ 0xFFFFFFFFu;
}

void fix_crc(Bytes& b) { put_le32(b, b.size() - 4, crc32(b, b.size() - 4)); }

std::string only_hxs(const std::string& dir) {
    auto files = os_list_files(dir, ".hxs");
    REQUIRE(files.size() == 1);
    return files[0];
}

// Written by the pre-extras build (session format v2): untitled "Untitled 7" with "hello\nfixture",
// overwrite(2, AB CD), insert(0, AB) undone (on the redo stack), a bookmark {3, 4, "bm",
// 0xFF00FF00, "note"} (top undo step; it cleared the redo stack), cursor 5, anchor 2, parser "png".
const uint8_t kV2Doc[] = {
    0x48, 0x58, 0x53, 0x31, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
    0x55, 0x6e, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x64, 0x20, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
    0x0a, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 0xab, 0xcd, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0x09, 0x00, 0x00, 0x00, 0x4f, 0x76, 0x65, 0x72, 0x77, 0x72, 0x69, 0x74, 0x65,
    0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0c,
    0x00, 0x00, 0x00, 0x41, 0x64, 0x64, 0x20, 0x62, 0x6f, 0x6f, 0x6b, 0x6d, 0x61, 0x72, 0x6b, 0x00,
    0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
    0x00, 0x70, 0x6e, 0x67, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x62, 0x6d, 0x00, 0xff,
    0x00, 0xff, 0x04, 0x00, 0x00, 0x00, 0x6e, 0x6f, 0x74, 0x65, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x26, 0x0e, 0xda, 0xc4
};
const char kV2Index[] = "version=1\nactive=0\ndoc=doc-1.hxs\n";

}  // namespace

TEST_CASE("document extras: set/erase/persist_generation") {
    auto d = make_doc("U", "abc");
    CHECK(d->extras().empty());
    CHECK(d->extra("split.on").empty());
    uint64_t g = d->persist_generation();
    d->set_extra("split.on", "1");
    CHECK(d->extra("split.on") == "1");
    CHECK(d->persist_generation() > g);
    g = d->persist_generation();
    d->set_extra("split.on", "1");  // unchanged: no rewrite needed
    CHECK(d->persist_generation() == g);
    d->set_extra("nope", "");  // erasing a missing key is a no-op
    CHECK(d->persist_generation() == g);
    d->set_extra("split.on", "");
    CHECK(d->extras().empty());
    CHECK(d->persist_generation() > g);
    // Not content: no undo step, not dirty-making.
    CHECK(!d->can_undo());
    CHECK(d->persist().extras.empty());
    d->set_extra("tail.enabled", "1");
    CHECK(d->persist().extras.at("tail.enabled") == "1");
}

TEST_CASE("session: document extras round trip (empty, many, binary-safe)") {
    TempDir t;
    const std::string bin("a\nb\0c\r\n\xff=%x", 11);
    std::map<std::string, std::string> many;
    for (int i = 0; i < 200; ++i) many["k." + std::to_string(i)] = std::string(size_t(i) + 1, char('a' + i % 26));
    many["split.ratio"] = "0.375";
    many[std::string("key\0with\nnul", 12)] = bin;

    auto plain = make_doc("Plain", "plain bytes");
    auto rich = make_doc("Rich", "rich bytes");
    for (const auto& [k, v] : many) rich->set_extra(k, v);
    auto one = make_doc("One", "x");
    one->set_extra("parse.parser", "PNG image");
    {
        Session s(t.path());
        REQUIRE(s.save({plain.get(), rich.get(), one.get()}, 0));
        // A doc without extras keeps the v2 layout (readable by older builds), others are v3.
        int v2 = 0, v3 = 0;
        for (const std::string& f : os_list_files(t.path(), ".hxs")) {
            Bytes b = read_file(f);
            REQUIRE(b.size() > 8);
            (le32(b, 4) == 2 ? v2 : v3)++;
            if (le32(b, 4) != 2) CHECK(le32(b, 4) == 3);
        }
        CHECK(v2 == 1);
        CHECK(v3 == 2);
    }
    {
        Session s(t.path());
        auto r = s.load();
        CHECK(r.warnings.empty());
        REQUIRE(r.docs.size() == 3);
        CHECK(r.docs[0]->extras().empty());
        CHECK(r.docs[1]->extras() == many);
        CHECK(r.docs[1]->extra(std::string("key\0with\nnul", 12)) == bin);
        CHECK(r.docs[2]->extra("parse.parser") == "PNG image");
        CHECK(r.docs[1]->display_name() == "Rich");
        // Changing only an extra rewrites that doc on the next save.
        r.docs[2]->set_extra("parse.parser", "");
        r.docs[0]->set_extra("split.top2", "123456789012");
        std::vector<Document*> docs;
        for (auto& d : r.docs) docs.push_back(d.get());
        REQUIRE(s.save(docs, 2));
    }
    auto r = Session(t.path()).load();
    REQUIRE(r.docs.size() == 3);
    CHECK(r.active_index == 2);
    CHECK(r.docs[0]->extras() == std::map<std::string, std::string>{{"split.top2", "123456789012"}});
    CHECK(r.docs[1]->extras() == many);
    CHECK(r.docs[2]->extras().empty());
}

TEST_CASE("session: session-level extras and saved doc ids") {
    TempDir t;
    auto a = make_doc("A", "aaaa");
    auto b = make_doc("B", "bbbb");
    const std::string compare = std::to_string(a->id()) + "|" + std::to_string(b->id()) + "|-16";
    const std::string weird("v a=l%u\ne\0\x01\x7f\xc3\xa4 ", 15);
    const std::string weird_key("k e=y%\n\0", 8);
    {
        Session s(t.path());
        CHECK(s.extras().empty());
        s.set_extra("compare.1", compare);
        s.set_extra("active", "compare.1");
        s.set_extra(weird_key, weird);
        s.set_extra("gone", "x");
        s.set_extra("gone", "");  // erased
        CHECK(s.extra("gone").empty());
        CHECK(s.extras().size() == 3);
        REQUIRE(s.save({a.get(), b.get()}, 1));
    }
    // The index stays line-based: no raw newline or NUL leaks into it.
    std::string ini;
    REQUIRE(os_read_whole(t.file("session.ini"), ini));
    CHECK(ini.find('\0') == std::string::npos);
    CHECK(ini.find("x.compare.1=" + compare + "\n") != std::string::npos);

    // (Only one Session may own the directory at a time: a second one would be a secondary instance.)
    auto s = std::make_unique<Session>(t.path());
    auto r = s->load();
    CHECK(r.warnings.empty());
    REQUIRE(r.docs.size() == 2);
    REQUIRE(r.saved_ids.size() == 2);
    CHECK(r.saved_ids[0] == a->id());
    CHECK(r.saved_ids[1] == b->id());
    CHECK(r.docs[0]->id() != a->id());  // restored docs get fresh ids
    CHECK(s->extra("compare.1") == compare);
    CHECK(s->extra("active") == "compare.1");
    CHECK(s->extra(weird_key) == weird);
    CHECK(s->extras().size() == 3);

    // The next save writes the restored docs' current ids; extras are kept as set.
    s->set_extra("active", "");
    std::vector<Document*> docs{r.docs[0].get(), r.docs[1].get()};
    REQUIRE(s->save(docs, 0));
    s.reset();
    s = std::make_unique<Session>(t.path());
    auto r2 = s->load();
    REQUIRE(r2.saved_ids.size() == 2);
    CHECK(r2.saved_ids[0] == r.docs[0]->id());
    CHECK(r2.saved_ids[1] == r.docs[1]->id());
    CHECK(s->extras().size() == 2);
    CHECK(s->extra("active").empty());

    // clear() drops them too.
    s->clear();
    CHECK(s->extras().empty());
    s.reset();
    CHECK(Session(t.path()).load().docs.empty());
}

TEST_CASE("session: unescaping tolerates hand-edited index lines") {
    TempDir t;
    auto a = make_doc("A", "aaaa");
    REQUIRE(Session(t.path()).save({a.get()}, 0));
    std::string ini;
    REQUIRE(os_read_whole(t.file("session.ini"), ini));
    ini += "x.bad=100%\nx.half=%4\nx.nonhex=%zz%41\nx.=empty key ignored? no: kept\ndocid=999\n";
    REQUIRE(os_write_whole_atomic(t.file("session.ini"), ini.data(), ini.size()));
    Session s(t.path());
    auto r = s.load();
    REQUIRE(r.docs.size() == 1);
    CHECK(r.saved_ids[0] == a->id());  // a docid line not right after its doc line is ignored
    CHECK(s.extra("bad") == "100%");
    CHECK(s.extra("half") == "%4");
    CHECK(s.extra("nonhex") == "%zzA");
}

TEST_CASE("session: v2 session file written before extras still loads") {
    TempDir t;
    write_file(t.file("doc-1.hxs"), Bytes(std::begin(kV2Doc), std::end(kV2Doc)));
    REQUIRE(os_write_whole_atomic(t.file("session.ini"), kV2Index, std::strlen(kV2Index)));
    const std::string want_s("he\xab\xcdo\nfixture", 13);
    const Bytes want(want_s.begin(), want_s.end());
    {
        Session s(t.path());
        auto r = s.load();
        CHECK(r.warnings.empty());
        REQUIRE(r.docs.size() == 1);
        REQUIRE(r.saved_ids.size() == 1);
        CHECK(r.saved_ids[0] == 0);  // old index: no ids
        CHECK(s.extras().empty());
        Document& d = *r.docs[0];
        CHECK(d.display_name() == "Untitled 7");
        CHECK(doc_bytes(d) == want);
        CHECK(d.extras().empty());
        CHECK(d.view().cursor == 5);
        CHECK(d.view().anchor == 2);
        CHECK(d.view().parser == "png");
        REQUIRE(d.view().bookmarks.size() == 1);
        CHECK(d.view().bookmarks[0].note == "note");
        CHECK(d.view().bookmarks[0].color == 0xFF00FF00u);
        REQUIRE(d.undo_stack().size() == 2);
        CHECK(d.undo_stack().back().label == "Add bookmark");
        CHECK(d.redo_stack().empty());
        // Upgrade: add an extra, the file becomes v3.
        d.set_extra("split.on", "1");
        REQUIRE(s.save({&d}, 0));
        CHECK(le32(read_file(only_hxs(t.path())), 4) == 3);
    }
    {
        Session s(t.path());
        auto r = s.load();
        CHECK(r.warnings.empty());
        REQUIRE(r.docs.size() == 1);
        Document& d = *r.docs[0];
        CHECK(doc_bytes(d) == want);
        CHECK(d.extra("split.on") == "1");
        REQUIRE(d.undo());  // the bookmark step
        CHECK(d.view().bookmarks.empty());
        REQUIRE(d.undo());  // the overwrite
        const std::string orig = "hello\nfixture";
        CHECK(doc_bytes(d) == Bytes(orig.begin(), orig.end()));
        // Downgrade direction: without extras the file is written as v2 again.
        d.set_extra("split.on", "");
        REQUIRE(s.save({&d}, 0));
        CHECK(le32(read_file(only_hxs(t.path())), 4) == 2);
    }
}

TEST_CASE("session: corrupt extension block drops the extras, not the document") {
    TempDir t;
    auto d = make_doc("Doc", "content");
    d->set_extra("k", "v");
    REQUIRE(Session(t.path()).save({d.get()}, 0));
    const std::string f = only_hxs(t.path());
    const Bytes good = read_file(f);
    // Tail: ... u32 block_len (14) | u32 count (1) | u32 1 'k' | u32 1 'v' | u32 crc
    const size_t block = good.size() - 4 - 14;
    REQUIRE(le32(good, block - 4) == 14);
    REQUIRE(le32(good, block) == 1);

    SUBCASE("inner string length past the block") {
        Bytes b = good;
        put_le32(b, block + 4, 100);
        fix_crc(b);
        write_file(f, b);
    }
    SUBCASE("inner count larger than the block holds") {
        Bytes b = good;
        put_le32(b, block, 2);
        fix_crc(b);
        write_file(f, b);
    }
    SUBCASE("block length leaves unparsed bytes") {
        Bytes b = good;
        put_le32(b, block + 4 + 5 + 0, 0);  // value length 0: 'v' left over
        fix_crc(b);
        write_file(f, b);
    }
    {
        Session s(t.path());
        auto r = s.load();
        REQUIRE(r.docs.size() == 1);
        CHECK(doc_bytes(*r.docs[0]) == Bytes{'c', 'o', 'n', 't', 'e', 'n', 't'});
        CHECK(r.docs[0]->extras().empty());
        REQUIRE(r.warnings.size() == 1);
        CHECK(r.warnings[0].find("view state") != std::string::npos);
        REQUIRE(s.save({r.docs[0].get()}, 0));  // rewritten: the warning is not repeated
    }
    auto r = Session(t.path()).load();
    REQUIRE(r.docs.size() == 1);
    CHECK(r.warnings.empty());
}

TEST_CASE("session: block length beyond the file is a different-version file, kept") {
    TempDir t;
    auto d = make_doc("Doc", "content");
    d->set_extra("k", "v");
    REQUIRE(Session(t.path()).save({d.get()}, 0));
    const std::string f = only_hxs(t.path());
    Bytes b = read_file(f);
    put_le32(b, b.size() - 4 - 14 - 4, 1000);
    fix_crc(b);
    write_file(f, b);
    Session s(t.path());
    auto r = s.load();
    CHECK(r.docs.empty());
    CHECK(s.kept().size() == 1);  // not deleted: never lose edits over a format question
}

TEST_CASE("settings: bookmarks_all_files round trip") {
    TempDir t;
    const std::string path = t.file("settings.ini");
    Settings def;
    CHECK(!def.bookmarks_all_files);
    Settings a;
    a.bookmarks_all_files = true;
    REQUIRE(a.save(path));
    Settings b;
    REQUIRE(b.load(path));
    CHECK(b.bookmarks_all_files);
    for (const auto& [text, want] : std::vector<std::pair<std::string, bool>>{
             {"bookmarks_all_files = off\n", false}, {"bookmarks_all_files = yes\n", true},
             {"bookmarks_all_files = maybe\n", false}}) {
        REQUIRE(os_write_whole_atomic(path, text.data(), text.size()));
        Settings c;
        REQUIRE(c.load(path));
        CHECK(c.bookmarks_all_files == want);
        CHECK(c.unknown_keys.empty());
    }
}
