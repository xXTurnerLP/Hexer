// Tests for session extras: per-document (PersistedDoc::extras, session file v3) and session-level
// (Session::set_extra, stored in the index), backward compatibility with v2 session files, and the
// Bookmarks "all open files" setting; the Restart as Administrator handover (core/elevation).
#include <doctest/doctest.h>

#include <algorithm>
#include <algorithm>
#include <chrono>
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
#include "core/elevation.h"
#include "core/nav.h"
#include "core/os_file.h"
#include "core/session.h"
#include "core/settings.h"

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

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
        // Every doc is written in the current format (v4: history times), extras or not.
        for (const std::string& f : os_list_files(t.path(), ".hxs")) {
            Bytes b = read_file(f);
            REQUIRE(b.size() > 8);
            CHECK(le32(b, 4) == 4);
        }
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
        // Upgrade: the next save writes the current format (v4).
        d.set_extra("split.on", "1");
        REQUIRE(s.save({&d}, 0));
        CHECK(le32(read_file(only_hxs(t.path())), 4) == 4);
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
        CHECK(d.undo_stack().empty());
        CHECK(d.redo_stack().size() == 2);
        // Steps from before timestamps have none (the History panel leaves the time empty).
        CHECK(d.redo_stack().back().time_ms == 0);
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

TEST_CASE("session: the app's per-tab and session-level persistence keys round trip") {
    TempDir t;
    auto a = make_doc("A", std::string(5000, 'a'));
    auto b = make_doc("B", "bbbb");
    const std::vector<NavEntry> back = {{0, 0}, {4096, 16}, {4999, 1}};
    const std::vector<NavEntry> fwd = {{100, 0}};
    // Per tab (App save_tab_extras / PacketsPanel::save_extras): insert mode, Back / Forward,
    // the Packets filter and parser.
    a->set_extra("edit.insert", "1");
    a->set_extra("nav.back", nav_encode(back));
    a->set_extra("nav.fwd", nav_encode(fwd));
    a->set_extra("packets.filter", "ip.src == 10.0.0.1 and \"GET /x=1%\"");
    a->set_extra("packets.parser", "My proto");
    b->set_extra("edit.insert", "0");
    // Session level (App save_session_extras): Find pattern, Bitmap fixed start, C struct draft.
    const std::string pattern("DE AD\n\0\xff", 8);
    const std::string draft = "struct hdr {\n\tuint32_t magic; // \"MZ\" = 0x5A4D\n\tchar name[8];\r\n};\n";
    {
        Session s(t.path());
        s.set_extra("find.pattern", pattern);
        s.set_extra("bitmap.fixed", "123456789012");
        s.set_extra("cstruct.open", "1");
        s.set_extra("cstruct.source", draft);
        s.set_extra("cstruct.name", "My hdr");
        s.set_extra("cstruct.root", "hdr");
        s.set_extra("cstruct.endian", "be");
        s.set_extra("cstruct.pack", "4");
        REQUIRE(s.save({a.get(), b.get()}, 0));
    }
    Session s(t.path());
    auto r = s.load();
    REQUIRE(r.docs.size() == 2);
    const Document& ra = *r.docs[0];
    CHECK(ra.extra("edit.insert") == "1");
    CHECK(nav_decode(ra.extra("nav.back"), ra.size()) == back);
    CHECK(nav_decode(ra.extra("nav.fwd"), ra.size()) == fwd);
    CHECK(ra.extra("packets.filter") == "ip.src == 10.0.0.1 and \"GET /x=1%\"");
    CHECK(ra.extra("packets.parser") == "My proto");
    CHECK(r.docs[1]->extra("edit.insert") == "0");
    CHECK(r.docs[1]->extra("nav.back").empty());
    CHECK(s.extra("find.pattern") == pattern);
    CHECK(s.extra("bitmap.fixed") == "123456789012");
    CHECK(s.extra("cstruct.open") == "1");
    CHECK(s.extra("cstruct.source") == draft);
    CHECK(s.extra("cstruct.name") == "My hdr");
    CHECK(s.extra("cstruct.root") == "hdr");
    CHECK(s.extra("cstruct.endian") == "be");
    CHECK(s.extra("cstruct.pack") == "4");
    s.clear();
}

// ---- Restart as Administrator (core/elevation.h) --------------------------------------------

TEST_CASE("elevation: Windows command-line quoting round-trips through CommandLineToArgvW") {
    CHECK(win_quote_arg("plain") == "plain");
    CHECK(win_quote_arg("") == "\"\"");
    CHECK(win_quote_arg("a b") == "\"a b\"");
    CHECK(win_quote_arg(R"(C:\dir\x.bin)") == R"(C:\dir\x.bin)");  // no blanks: as is, backslashes literal
    CHECK(win_quote_arg(R"(C:\Program Files\x\)") == R"("C:\Program Files\x\\")");  // doubled before the closing quote
    CHECK(win_quote_arg(R"(say "hi")") == R"("say \"hi\"")");
    CHECK(win_quote_arg(R"(a\"b)") == R"("a\\\"b")");  // backslashes before a quote: doubled, quote escaped
    CHECK(win_quote_arg(R"(\\.\PhysicalDrive0)") == R"(\\.\PhysicalDrive0)");
    const std::string jurgen = R"(C:\Users\J)" "\xC3\xBC" R"(rgen\my cfg)";
    CHECK(win_command_line({"--config-dir", jurgen}) == "--config-dir \"" + jurgen + "\"");

    const std::vector<std::string> args = {
        "--new-instance", "--wait-pid", "1234", "--config-dir",
        R"(C:\Users\J)" "\xC3\xBC" R"(rgen M)" "\xC3\xBC" R"(ller\AppData\Roaming\Hexer)",  // blanks + umlauts
        "--", "process://4242", R"(\\.\PhysicalDrive1)", R"(C:\with space\)", "", "tab\there",
        R"(quote"in)", R"(tail\\)", R"(a\\"b c)", "\xE6\x97\xA5\xE6\x9C\xAC \xE8\xAA\x9E.bin",  // CJK + a blank
    };
#ifdef _WIN32
    const std::wstring line = L"hexer.exe " + utf8_to_wide(win_command_line(args));
    int n = 0;
    LPWSTR* w = CommandLineToArgvW(line.c_str(), &n);
    REQUIRE(w);
    REQUIRE(n == int(args.size()) + 1);
    for (size_t i = 0; i < args.size(); ++i) CHECK(wide_to_utf8(w[i + 1]) == args[i]);
    LocalFree(w);
#else
    CHECK(win_command_line(args).find(" \"\" \"tab\there\" ") != std::string::npos);  // pure: same text everywhere
#endif
}

TEST_CASE("elevation: restart arguments of the elevated instance") {
    CHECK(restart_args(R"(C:\cfg dir)", 77, {"process://5", R"(\\.\PhysicalDrive0)"}) ==
          std::vector<std::string>{"--new-instance", "--wait-pid", "77", "--config-dir", R"(C:\cfg dir)", "--",
                                   "process://5", R"(\\.\PhysicalDrive0)"});
    CHECK(restart_args("", 9, {}) == std::vector<std::string>{"--new-instance", "--wait-pid", "9"});
    CHECK(restart_args("/x", 9, {"-starts-with-dash.bin"}).back() == "-starts-with-dash.bin");  // after "--"
    // An instance started with --no-session passes it on: the elevated one must not restore (and
    // then own) the hot-exit session the old one never touched.
    CHECK(restart_args("/x", 9, {"a.bin"}, true) ==
          std::vector<std::string>{"--new-instance", "--no-session", "--wait-pid", "9", "--config-dir", "/x", "--", "a.bin"});
    const std::vector<std::string> with_session = restart_args("/x", 9, {});
    CHECK(std::count(with_session.begin(), with_session.end(), "--no-session") == 0);
#ifndef _WIN32
    CHECK_FALSE(can_restart_elevated());
#endif
    // Never blocks on a pid that is gone; times out on one that runs (this process).
    CHECK_FALSE(wait_process_exit(os_process_id(), 30));
    CHECK(wait_process_exit(0, 30));
}

TEST_CASE("elevation: session handover to the elevated instance through an injected launcher") {
    TempDir td;
    const std::string sdir = td.file("session");
    REQUIRE(os_mkdirs(sdir));
    const std::string data = td.file("data.bin");
    write_file(data, Bytes(64, 0x11));

    std::vector<std::string> launched;
    bool deny = true;  // first: the user cancels the UAC prompt
    set_elevated_launcher([&](const std::vector<std::string>& args, std::string* err, bool* cancelled) {
        if (deny) {
            if (cancelled) *cancelled = true;
            if (err) *err = "cancelled";
            return false;
        }
        launched = args;
        return true;
    });

    auto old_session = std::make_unique<Session>(sdir);
    REQUIRE(old_session->primary());
    std::string err;
    auto doc = Document::open_file(data, &err);
    REQUIRE_MESSAGE(doc, err);
    const uint8_t x = 0xAB;
    REQUIRE(doc->overwrite(5, &x, 1));
    doc->view().cursor = 5;
    REQUIRE(old_session->save({doc.get()}, 0, &err));

    // The old instance holds the session: an instance started now would only get instance-1/,
    // without the edits. That is why the elevated one waits (--wait-pid) for the old one to exit.
    {
        Session early(sdir);
        CHECK(early.secondary());
        CHECK(early.load().docs.empty());
    }

    const auto args = restart_args(td.path(), os_process_id(), {"process://4242"});
    bool cancelled = false;
    CHECK_FALSE(launch_elevated(args, &err, &cancelled));
    CHECK(cancelled);
    CHECK(launched.empty());  // cancelled: nothing started, the old instance keeps running untouched

    deny = false;
    REQUIRE(launch_elevated(args, &err, &cancelled));
    CHECK_FALSE(cancelled);
    CHECK(launched == args);
    CHECK(std::find(launched.begin(), launched.end(), "--new-instance") != launched.end());
    CHECK(launched.back() == "process://4242");  // the process tab is not in the session: on the command line

    // The old instance quits (hot exit already written), then the elevated one starts.
    REQUIRE(old_session->save({doc.get()}, 0, &err));
    old_session.reset();
    doc.reset();
    Session fresh(sdir);
    CHECK(fresh.primary());
    auto r = fresh.load();
    REQUIRE(r.docs.size() == 1);  // exactly once: no duplicate, nothing lost
    uint8_t b = 0;
    REQUIRE(r.docs[0]->read(5, &b, 1) == 1);
    CHECK(b == 0xAB);
    CHECK(r.docs[0]->dirty());
    CHECK(r.docs[0]->view().cursor == 5);
    CHECK(r.docs[0]->can_undo());
    set_elevated_launcher(nullptr);
    fresh.clear();
}

// Tab drag reordering: App keeps app.tabs in the tab bar's visual order and saves them in that
// order (a reorder changes session_signature, so it is saved); the session restores that order.
TEST_CASE("session: documents restore in the order they were saved (reordered tabs)") {
    TempDir t;
    auto a = make_doc("A", "aaaa");
    auto b = make_doc("B", "bbbb");
    auto c = make_doc("C", "cccc");
    {
        Session s(t.path());
        REQUIRE(s.save({c.get(), a.get(), b.get()}, 1));
    }
    auto r = Session(t.path()).load();
    REQUIRE(r.docs.size() == 3);
    CHECK(r.docs[0]->display_name() == "C");
    CHECK(r.docs[1]->display_name() == "A");
    CHECK(r.docs[2]->display_name() == "B");
    CHECK(r.active_index == 1);
}

// ---- session format v4: history times, view steps, Parse at, files referenced by path --------

namespace {

void put_str(Bytes& b, const std::string& s) {
    const size_t at = b.size();
    b.resize(at + 4 + s.size());
    put_le32(b, at, uint32_t(s.size()));
    if (!s.empty()) std::memcpy(b.data() + at + 4, s.data(), s.size());
}

int64_t g_session_ms = 0;
int64_t session_clock() { return g_session_ms; }

}  // namespace

TEST_CASE("session: a v3 file (Parse at kept as extras) restores exactly and migrates") {
    // v3 = the v2 layout + the extension block: the kV2Doc fixture with version 3 and extras
    // "parse.base" = "5", "parse.length" = "3", "split.on" = "1", as the previous build wrote them.
    TempDir t;
    Bytes b(std::begin(kV2Doc), std::end(kV2Doc));
    b.resize(b.size() - 4);  // the CRC
    put_le32(b, 4, 3);
    Bytes block(4);
    put_le32(block, 0, 3);
    for (const char* kv : {"parse.base", "5", "parse.length", "3", "split.on", "1"}) put_str(block, kv);
    put_str(b, std::string(block.begin(), block.end()));
    b.resize(b.size() + 4);
    fix_crc(b);
    write_file(t.file("doc-1.hxs"), b);
    REQUIRE(os_write_whole_atomic(t.file("session.ini"), kV2Index, std::strlen(kV2Index)));
    const std::string want_s("he\xab\xcdo\nfixture", 13);
    const Bytes want(want_s.begin(), want_s.end());
    {
        Session s(t.path());
        auto r = s.load();
        CHECK(r.warnings.empty());
        REQUIRE(r.docs.size() == 1);
        Document& d = *r.docs[0];
        CHECK(doc_bytes(d) == want);
        CHECK(d.view().parser == "png");
        CHECK(d.view().parse_base == 5);  // moved out of the extras
        CHECK(d.view().parse_length == 3);
        CHECK(d.extras() == std::map<std::string, std::string>{{"split.on", "1"}});
        REQUIRE(d.undo_stack().size() == 2);
        CHECK(d.undo_stack().back().time_ms == 0);  // no times before v4
        CHECK_FALSE(d.undo_stack().back().view_only);
        d.view_generation++;  // a change: the next save writes the current format
        REQUIRE(s.save({&d}, 0));
        CHECK(le32(read_file(only_hxs(t.path())), 4) == 4);
    }
    Session s(t.path());
    auto r = s.load();
    CHECK(r.warnings.empty());
    REQUIRE(r.docs.size() == 1);
    Document& d = *r.docs[0];
    CHECK(doc_bytes(d) == want);
    CHECK(d.view().parse_base == 5);
    CHECK(d.view().parse_length == 3);
    CHECK(d.extra("parse.base").empty());
    REQUIRE(d.undo());
    REQUIRE(d.undo());
    const std::string orig = "hello\nfixture";
    CHECK(doc_bytes(d) == Bytes(orig.begin(), orig.end()));
}

TEST_CASE("session: v4 keeps history times, view steps and the Parse at range") {
    TempDir t;
    Document::set_clock_for_tests(&session_clock);
    g_session_ms = 1700000000123;
    auto d = make_doc("Doc", "0123456789");
    const uint8_t x = 'x';
    REQUIRE(d->overwrite(1, &x, 1));
    g_session_ms += 1000;
    ViewOptions o = d->view_options();
    o.parser = "PNG image";
    o.parse_base = 4;
    o.parse_length = 6;
    REQUIRE(d->set_view_options(o, "Parse 0x4..0x9 with PNG image"));
    g_session_ms += 1000;
    o.read_only = true;
    REQUIRE(d->set_view_options(o, "Read-only on"));
    Document::set_clock_for_tests(nullptr);
    {
        Session s(t.path());
        REQUIRE(s.save({d.get()}, 0));
    }
    auto s = std::make_unique<Session>(t.path());
    auto r = s->load();
    CHECK(r.warnings.empty());
    REQUIRE(r.docs.size() == 1);
    Document& e = *r.docs[0];
    CHECK(e.read_only());
    CHECK(e.view().parser == "PNG image");
    CHECK(e.view().parse_base == 4);
    CHECK(e.view().parse_length == 6);
    REQUIRE(e.undo_stack().size() == 3);
    CHECK(e.undo_stack()[0].time_ms == 1700000000123);
    CHECK(e.undo_stack()[1].time_ms == 1700000001123);
    CHECK(e.undo_stack()[2].time_ms == 1700000002123);
    CHECK(e.undo_stack()[1].view_only);
    CHECK(e.undo_stack()[1].pieces.empty());
    CHECK(e.undo_stack()[2].label == "Read-only on");
    CHECK(e.dirty());
    REQUIRE(e.undo());  // read-only off: allowed while read-only
    CHECK_FALSE(e.read_only());
    REQUIRE(e.undo());
    CHECK(e.view().parser.empty());
    CHECK(e.view().parse_base == 0);
    CHECK(e.view().parse_length == UINT64_MAX);
    CHECK(doc_bytes(e) == Bytes{'0', 'x', '2', '3', '4', '5', '6', '7', '8', '9'});
    REQUIRE(e.undo());
    CHECK(doc_bytes(e) == Bytes{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'});
    // The redo states (view steps among them) survive the next round trip too.
    REQUIRE(s->save({&e}, 0));
    s.reset();  // the next instance owns the session directory
    auto r2 = Session(t.path()).load();
    REQUIRE(r2.docs.size() == 1);
    Document& f = *r2.docs[0];
    REQUIRE(f.redo_stack().size() == 3);
    CHECK(f.redo_stack()[1].view_only);
    CHECK(f.redo_stack()[1].time_ms == 1700000001123);
    REQUIRE(f.redo());
    REQUIRE(f.redo());
    REQUIRE(f.redo());
    CHECK(f.read_only());
    CHECK(f.view().parse_base == 4);
    CHECK(doc_bytes(f) == Bytes{'0', 'x', '2', '3', '4', '5', '6', '7', '8', '9'});
}

TEST_CASE("session: a malformed view-step flag is a different-version file, kept") {
    TempDir t;
    auto d = make_doc("Doc", "abc");
    ViewOptions o = d->view_options();
    o.read_only = true;
    REQUIRE(d->set_view_options(o, "R"));
    REQUIRE(Session(t.path()).save({d.get()}, 0));
    const std::string f = only_hxs(t.path());
    Bytes b = read_file(f);
    // The entry's label "R" (u32 1, 'R') is followed by the time (u64) and the flags byte (3).
    const Bytes label = {1, 0, 0, 0, 'R'};
    auto it = std::search(b.begin(), b.end(), label.begin(), label.end());
    REQUIRE(it != b.end());
    const size_t flags = size_t(it - b.begin()) + 5 + 8;
    REQUIRE(b[flags] == 3);
    b[flags] = 1;  // a view step without its view options
    fix_crc(b);
    write_file(f, b);
    Session s(t.path());
    auto r = s.load();
    CHECK(r.docs.empty());
    CHECK(s.kept().size() == 1);
}

// Revert to Backup on a file whose backup is far above the 16 MiB the session could inline: the
// session references the .backup by path (+ size + mtime) instead of copying it.
TEST_CASE("session: Revert to Backup of a big sparse file survives hot exit without copying it") {
    TempDir t;
    const std::string sdir = t.file("session");
    const std::string p = t.file("big.bin");
    write_file(p, Bytes(4096, 0x11));
    const std::string bak = Document::backup_path_of(p);
    const uint64_t big = 256ull << 20;
    {
        std::ofstream f(fs::path(std::u8string(bak.begin(), bak.end())), std::ios::binary | std::ios::trunc);
        f.write("HEAD", 4);
    }
    fs::resize_file(fs::path(std::u8string(bak.begin(), bak.end())), big);  // sparse (zeros) up to 256 MiB
    {
        std::fstream f(fs::path(std::u8string(bak.begin(), bak.end())), std::ios::binary | std::ios::in | std::ios::out);
        f.seekp(std::streamoff(big - 4));
        f.write("TAIL", 4);
    }
    auto bytes_at = [](const Document& d, uint64_t off, size_t n) {
        Bytes b(n);
        REQUIRE(d.read(off, b.data(), n) == n);
        return b;
    };
    const Bytes head = {'H', 'E', 'A', 'D'}, tail = {'T', 'A', 'I', 'L'}, zeros(64, 0);

    auto d = Document::open_file(p);
    REQUIRE(d);
    const uint8_t x = 0x42;
    REQUIRE(d->overwrite(10, &x, 1));
    std::string err;
    REQUIRE(d->replace_with_file(bak, "Revert to Backup", &err));
    CHECK(d->size() == big);
    CHECK(d->hot_exit_safe());  // before: false above 16 MiB (Hexer asked on exit)
    const PersistedDoc pd = d->persist();
    REQUIRE(pd.ref_files.size() == 1);
    CHECK(pd.ref_files[0].path == os_absolute_path(bak));
    CHECK(pd.ref_files[0].stat.size == big);
    CHECK_FALSE(pd.edits_dropped);
    {
        Session s(sdir);
        REQUIRE(s.save({d.get()}, 0, &err));
    }
    CHECK(read_file(only_hxs(sdir)).size() < 4096);  // nothing of the backup was copied

    SUBCASE("restores the reverted content and its history") {
        auto r = Session(sdir).load();
        CHECK(r.warnings.empty());
        REQUIRE(r.docs.size() == 1);
        Document& e = *r.docs[0];
        CHECK(e.size() == big);
        CHECK(e.dirty());
        CHECK(bytes_at(e, 0, 4) == head);
        CHECK(bytes_at(e, big - 4, 4) == tail);
        CHECK(bytes_at(e, big / 2, 64) == zeros);
        CHECK(e.table().pieces().size() == 1);
        uint64_t held = 0;
        for (const auto& c : e.add_buffer().chunks()) held += c ? c->used : 0;
        CHECK(held < 4096);  // no materialization
        CHECK(e.hot_exit_safe());
        REQUIRE(e.undo());
        CHECK(e.size() == 4096);
        CHECK(bytes_at(e, 10, 1) == Bytes{0x42});
        REQUIRE(e.undo());
        CHECK(bytes_at(e, 10, 1) == Bytes{0x11});
        REQUIRE(e.redo());
        REQUIRE(e.redo());
        CHECK(e.size() == big);
        CHECK(bytes_at(e, big - 4, 4) == tail);
    }
    SUBCASE("a changed backup: the file on disk opens, with a warning") {
        d.reset();  // releases the backup (Windows)
        {
            std::ofstream f(fs::path(std::u8string(bak.begin(), bak.end())), std::ios::binary | std::ios::app);
            f.write("!", 1);
        }
        auto r = Session(sdir).load();
        REQUIRE(r.docs.size() == 1);
        REQUIRE(r.warnings.size() == 1);
        CHECK(r.warnings[0].find("big.bin.backup changed or is missing") != std::string::npos);
        Document& e = *r.docs[0];
        CHECK_FALSE(e.dirty());
        CHECK(e.size() == 4096);
        CHECK(bytes_at(e, 10, 1) == Bytes{0x11});
        REQUIRE(e.undo());  // the history before the revert is kept
        CHECK(bytes_at(e, 10, 1) == Bytes{0x42});
        CHECK(e.redo_stack().size() == 1);
    }
    SUBCASE("a deleted backup that only the redo history needs: those steps are dropped") {
        REQUIRE(d->undo());
        {
            Session s(sdir);
            REQUIRE(s.save({d.get()}, 0, &err));
        }
        d.reset();
        REQUIRE(os_remove(bak));
        auto r = Session(sdir).load();
        REQUIRE(r.docs.size() == 1);
        REQUIRE(r.warnings.size() == 1);
        CHECK(r.warnings[0].find("undo steps that needed big.bin.backup were dropped") != std::string::npos);
        Document& e = *r.docs[0];
        CHECK(e.dirty());
        CHECK(e.size() == 4096);
        CHECK(bytes_at(e, 10, 1) == Bytes{0x42});
        CHECK(e.redo_stack().empty());
        REQUIRE(e.undo());
        CHECK(bytes_at(e, 10, 1) == Bytes{0x11});
    }
}

TEST_CASE("session: an unsaved Revert to Backup is not taken for our own save when the file changed to its size") {
    TempDir t;
    const std::string sdir = t.file("session");
    const std::string p = t.file("f.bin");
    const std::string bak = Document::backup_path_of(p);
    write_file(p, Bytes(64, 0x11));
    write_file(bak, Bytes(64, 0x22));
    {
        auto d = Document::open_file(p);
        REQUIRE(d);
        std::string err;
        REQUIRE(d->replace_with_file(bak, "Revert to Backup", &err));
        Session s(sdir);
        REQUIRE(s.save({d.get()}, 0, &err));
    }
    // The file on disk changes behind our back, keeping its size (a newer mtime either way).
    auto rewrite = [&](uint8_t v) {
        const fs::path fp(std::u8string(p.begin(), p.end()));
        const auto before = fs::last_write_time(fp);
        write_file(p, Bytes(64, v));
        fs::last_write_time(fp, before + std::chrono::seconds(5));
    };
    auto said_saved = [](const Session::Restored& r) {
        for (const std::string& w : r.warnings)
            if (w.find("was saved just before") != std::string::npos) return true;
        return false;
    };
    SUBCASE("other bytes: the reverted content stays, unsaved") {
        rewrite(0x33);
        auto r = Session(sdir).load();
        REQUIRE(r.docs.size() == 1);
        CHECK_FALSE(said_saved(r));
        CHECK(r.docs[0]->dirty());
        CHECK(doc_bytes(*r.docs[0]) == Bytes(64, 0x22));
    }
    SUBCASE("the reverted bytes (our save completed): it opens clean from disk") {
        rewrite(0x22);
        auto r = Session(sdir).load();
        REQUIRE(r.docs.size() == 1);
        CHECK(said_saved(r));
        CHECK_FALSE(r.docs[0]->dirty());
        CHECK(doc_bytes(*r.docs[0]) == Bytes(64, 0x22));
    }
}
