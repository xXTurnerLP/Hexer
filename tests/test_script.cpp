// Script engine tests: parser API, field editing, Doc API, REPL, hot reload, bundled examples.
#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "core/document.h"
#include "core/hash.h"
#include "core/nav.h"
#include "core/pcap.h"
#include "core/os_file.h"
#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
#include "script/script_engine.h"
#include "pcap_fixture.h"

using namespace hx;
namespace fs = std::filesystem;

namespace {

struct FakeHost : ScriptHost {
    std::vector<std::unique_ptr<Document>> docs;
    Document* active = nullptr;
    int reveals = 0;

    Document* active_document() override { return active; }
    Document* find_document(uint64_t id) override {
        for (auto& d : docs)
            if (d->id() == id) return d.get();
        return nullptr;
    }
    Document* open_bytes(const std::string& name, const uint8_t* data, size_t len) override {
        docs.push_back(Document::create_from_bytes(name, data, len));
        active = docs.back().get();
        return active;
    }
    // Like the app's reveal_range when `app_like`: the position being left goes onto `nav`
    // (Back / Forward), then the range is selected with the caret at its start.
    bool app_like = false;
    NavHistory nav;
    void reveal(Document& d, uint64_t off, uint64_t len) override {
        ++reveals;
        if (!app_like) return;
        ViewState& v = d.view();
        const NavEntry from{v.sel_begin(), v.sel_len()};
        v.cursor = off;
        v.anchor = off + len;
        if (NavEntry{v.sel_begin(), v.sel_len()} != from) nav.push(from);
    }
    bool has_view = false;           // doc:view_range(): what the "hex view" shows
    uint64_t view_first = 0, view_last = 0;
    bool view_range(Document&, uint64_t& first, uint64_t& last) override {
        first = view_first;
        last = view_last;
        return has_view;
    }

    Document* add(const std::string& bytes, const std::string& name = "test.bin") {
        return open_bytes(name, reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
    }
    void close(Document* d) {
        if (active == d) active = nullptr;
        for (size_t i = 0; i < docs.size(); ++i)
            if (docs[i].get() == d) docs.erase(docs.begin() + long(i));
    }
};

struct TempDir {
    fs::path path;
    TempDir() {
        std::random_device rd;
        path = fs::temp_directory_path() / ("hexer_test_script_" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    std::string str() const {
        auto u = path.generic_u8string();
        return std::string(u.begin(), u.end());
    }
    void write(const std::string& name, const std::string& content) const {
        fs::create_directories((path / name).parent_path());
        std::ofstream out(path / name, std::ios::binary | std::ios::trunc);
        out << content;
    }
};

std::string bytes_of(const Document& d) {
    std::string s(size_t(d.size()), '\0');
    d.read(0, reinterpret_cast<uint8_t*>(s.data()), s.size());
    return s;
}

// Same path rule as the highlight labels: "a.b", array elements "items[2]".
std::string field_path(const ParseResult& r, int i) {
    const Field& f = r.fields[size_t(i)];
    if (f.parent < 0) return f.name;
    const Field& par = r.fields[size_t(f.parent)];
    if (par.type == "array" && f.name.rfind(par.name + "[", 0) == 0)
        return field_path(r, f.parent) + f.name.substr(par.name.size());
    return field_path(r, f.parent) + "." + f.name;
}

const Field* find_field(const ParseResult& r, const std::string& path) {
    for (size_t i = 0; i < r.fields.size(); ++i)
        if (field_path(r, int(i)) == path) return &r.fields[i];
    return nullptr;
}

// Never null: a missing path yields a field whose value/comment say so (keeps CHECKs readable).
const Field& fld(const ParseResult& r, const std::string& path) {
    static Field missing;
    if (const Field* f = find_field(r, path)) return *f;
    missing = Field{};
    missing.value = missing.comment = "<missing " + path + ">";
    return missing;
}

struct Fixture {
    FakeHost host;
    ScriptEngine eng{&host};
    TempDir dir;

    void load(const std::string& code, const std::string& file = "test.lua") {
        dir.write(file, code);
        eng.set_script_dirs({dir.str()});
        eng.reload();
    }
    bool console_has(const std::string& needle, int kind = -1) const {
        for (const ConsoleLine& l : eng.console())
            if ((kind < 0 || l.kind == kind) && l.text.find(needle) != std::string::npos) return true;
        return false;
    }
    int errors() const {
        int n = 0;
        for (const ConsoleLine& l : eng.console()) n += l.kind == ConsoleLine::Error;
        return n;
    }
    std::string last_result() const {
        for (auto it = eng.console().rbegin(); it != eng.console().rend(); ++it)
            if (it->kind == ConsoleLine::Result) return it->text;
        return "<none>";
    }
    std::string last_line() const { return eng.console().empty() ? "" : eng.console().back().text; }
};

uint32_t crc32(const std::string& s) {
    uint32_t crc = 0xFFFFFFFFu;
    for (unsigned char c : s) {
        crc ^= c;
        for (int k = 0; k < 8; ++k) crc = (crc & 1) ? 0xEDB88320u ^ (crc >> 1) : crc >> 1;
    }
    return ~crc;
}

std::string be32(uint32_t v) {
    std::string s(4, '\0');
    for (int i = 0; i < 4; ++i) s[size_t(i)] = char(v >> (24 - 8 * i));
    return s;
}

const char* kBasicParser = R"LUA(
hx.parser {
    name = "basic",
    extensions = { "bas" },
    detect = function(doc) return doc:u8(0) == 1 and doc:size() == 45 end,
    parse = function(p, doc)
        p:endian("be")
        p:u8("a")
        p:struct("hdr", function()
            p:u16("b")
            p:u8("kind", { enum = { [1] = "HELLO", [2] = "BYE" } })
            p:u8("small", { fmt = "hex" })
            p:label("header!")
        end)
        p:note("after hdr")
        p:u16le("le")
        p:u64("big")
        p:array("items", 3, function(i) return p:u8("item") end)
        p:bytes("blob", 20)
        p:str("text", 3, { color = "red", comment = "c" })
        p:f32("flt")
    end,
}
)LUA";

std::string basic_bytes() {
    std::string s;
    s += "\x01";                              // a
    s += std::string("\x01\x02", 2);          // b = 0x0102
    s += "\x02";                              // kind = BYE
    s += "\x0D";                              // small
    s += std::string("\x34\x12", 2);          // le = 0x1234
    s += std::string(8, '\xFF');              // big
    s += std::string("\x07\x08\x09", 3);      // items
    for (int i = 0; i < 20; ++i) s += char(i);  // blob
    s += "a\"b";                              // text
    s += std::string("\x3F\xC0\x00\x00", 4);  // flt = 1.5
    return s;
}

}  // namespace

TEST_CASE("parser: fields, offsets, sizes, values, structure") {
    Fixture fx;
    fx.load(kBasicParser);
    REQUIRE(fx.errors() == 0);
    REQUIRE(fx.eng.parsers().size() == 1);
    CHECK(fx.eng.parsers()[0].name == "basic");
    CHECK(fx.eng.parsers()[0].extensions == std::vector<std::string>{"bas"});

    Document* d = fx.host.add(basic_bytes());
    CHECK(fx.eng.detect_parser(*d) == "basic");
    ParseResult r = fx.eng.parse(*d, "basic");
    INFO(r.error);
    REQUIRE(r.error.empty());
    CHECK(r.parser == "basic");
    CHECK(r.doc_generation == d->generation());

    const Field* a = find_field(r, "a");
    REQUIRE(a);
    CHECK(a->value == "1");
    CHECK(a->type == "u8");
    CHECK(a->pack == "B");
    CHECK(a->offset == 0);
    CHECK(a->size == 1);

    const Field* hdr = find_field(r, "hdr");
    REQUIRE(hdr);
    CHECK(hdr->type == "struct");
    CHECK(hdr->offset == 1);
    CHECK(hdr->size == 4);
    CHECK(hdr->value == "header!");
    CHECK(hdr->comment == "after hdr");
    CHECK(hdr->children.size() == 3);
    CHECK_FALSE(hdr->editable());

    const Field* b = find_field(r, "hdr.b");
    REQUIRE(b);
    CHECK(b->value == "258 (0x102)");
    CHECK(b->type == "u16be");
    CHECK(b->pack == ">I2");
    CHECK(b->depth == 1);

    const Field* kind = find_field(r, "hdr.kind");
    REQUIRE(kind);
    CHECK(kind->value == "2 = BYE");
    REQUIRE(kind->enums);
    CHECK(kind->enums->size() == 2);

    CHECK(fld(r, "hdr.small").value == "0x0D");
    CHECK(fld(r, "le").value == "4660 (0x1234)");
    CHECK(fld(r, "le").pack == "<I2");
    CHECK(fld(r, "big").value == "18446744073709551615 (0xFFFFFFFFFFFFFFFF)");

    const Field* items = find_field(r, "items");
    REQUIRE(items);
    CHECK(items->type == "array");
    CHECK(items->size == 3);
    REQUIRE(items->children.size() == 3);
    CHECK(r.fields[size_t(items->children[2])].name == "items[2]");
    CHECK(fld(r, "items[1]").value == "8");

    const Field* blob = find_field(r, "blob");
    REQUIRE(blob);
    CHECK(blob->size == 20);
    CHECK(blob->value.rfind("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F", 0) == 0);
    CHECK(blob->value.find("\xE2\x80\xA6") != std::string::npos);
    CHECK_FALSE(blob->editable());

    const Field* text = find_field(r, "text");
    REQUIRE(text);
    CHECK(text->value == "\"a\\\"b\"");
    CHECK(text->comment == "c");
    uint32_t red = 0;
    REQUIRE(parse_color("red", red));
    CHECK(text->color == red);

    CHECK(fld(r, "flt").value == "1.5");
    CHECK(fld(r, "flt").pack == ">f");

    // Highlights: leaf fields only, labelled with their path, auto colors from the palette.
    for (const Highlight& h : r.highlights.items) {
        REQUIRE(h.field >= 0);
        CHECK(r.fields[size_t(h.field)].children.empty());
    }
    const Highlight* hb = r.highlights.at(1);
    REQUIRE(hb);
    CHECK(hb->label == "hdr.b = 258 (0x102)");
    CHECK(hb->color == field_palette(1));  // second leaf
    CHECK(fld(r, "a").color == field_palette(0));
    const Highlight* ht = r.highlights.at(text->offset);
    REQUIRE(ht);
    CHECK(ht->color == red);
}

TEST_CASE("parser: read past EOF keeps the partial tree and reports file:line") {
    Fixture fx;
    fx.load(R"LUA(
hx.parser { name = "eof", parse = function(p)
    p:u8("first")
    p:struct("s", function()
        p:u8("second")
        p:u32("too_big")
    end)
end }
)LUA");
    Document* d = fx.host.add(std::string("\x01\x02\x03", 3));
    ParseResult r = fx.eng.parse(*d, "eof");
    CHECK(r.error.find("read past end of data at 0x2") != std::string::npos);
    CHECK(r.error.find("test.lua:6:") != std::string::npos);
    CHECK(r.error.find("stack traceback") == std::string::npos);
    REQUIRE(r.fields.size() == 3);
    CHECK(find_field(r, "s.second"));
    CHECK(fld(r, "s").size == 1);
    CHECK_FALSE(r.highlights.empty());
    CHECK(fx.console_has("read past end", ConsoleLine::Error));
}

TEST_CASE("parser: field limit truncates") {
    Fixture fx;
    fx.load(R"LUA(
hx.parser { name = "many", parse = function(p)
    p:array("x", 300000, function() p:u8("b") end)
end }
)LUA");
    Document* d = fx.host.add(std::string(300000, '\x00'));
    ParseResult r = fx.eng.parse(*d, "many");
    CHECK(r.truncated);
    CHECK(r.fields.size() == 200000);
    CHECK(r.error.find("field limit") != std::string::npos);
    CHECK(fld(r, "x").size == 199999);
}

TEST_CASE("parser: infinite loop is stopped by the time limit") {
    Fixture fx;
    fx.load(R"LUA(
hx.parser { name = "loop", parse = function(p)
    p:u8("before")
    while true do end
end }
)LUA");
    Document* d = fx.host.add("abc");
    auto t0 = std::chrono::steady_clock::now();
    ParseResult r = fx.eng.parse(*d, "loop");
    double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    CHECK(s < 6.0);
    CHECK(r.error.find("time limit") != std::string::npos);
    CHECK(r.fields.size() == 1);
    // Engine still works afterwards (hook removed).
    fx.eng.exec("1 + 1");
    CHECK(fx.last_result() == "2");
}

TEST_CASE("parser: p:read formats, peek, cstr, leb128, manual fields") {
    Fixture fx;
    fx.load(R"LUA(
hx.parser { name = "misc", parse = function(p)
    local a, b = p:peek("BB")
    assert(a == 0x10 and b == 0x20 and p:tell() == 0)
    p:read(">I3", "len24")
    p:cstr("name")
    p:uleb("u")
    p:sleb("s")
    p:field("manual", 0, 2, "custom text")
    p:i8("neg")
    assert(p:eof())
end }
)LUA");
    std::string data = std::string("\x10\x20\x30", 3) + "hi" + std::string("\0", 1) +
                       std::string("\xE5\x8E\x26", 3) + std::string("\x7F", 1) + std::string("\xFF", 1);
    Document* d = fx.host.add(data);
    ParseResult r = fx.eng.parse(*d, "misc");
    INFO(r.error);
    REQUIRE(r.error.empty());
    CHECK(fld(r, "len24").value == "1056816 (0x102030)");
    CHECK(fld(r, "len24").pack == ">I3");
    CHECK(fld(r, "len24").type == ">I3");
    CHECK(fld(r, "name").value == "\"hi\"");
    CHECK(fld(r, "name").size == 3);
    CHECK(fld(r, "u").value == "624485 (0x98765)");
    CHECK(fld(r, "s").value == "-1 (0xFFFFFFFFFFFFFFFF)");
    CHECK(fld(r, "manual").value == "custom text");
    CHECK(fld(r, "manual").offset == 0);
    CHECK(fld(r, "neg").value == "-1 (0xFF)");
}

TEST_CASE("edit_field: encode, range checks, enum names, undo") {
    Fixture fx;
    fx.load(kBasicParser);
    Document* d = fx.host.add(basic_bytes());
    std::string original = bytes_of(*d);
    ParseResult r = fx.eng.parse(*d, "basic");
    REQUIRE(r.error.empty());

    const Field* b = find_field(r, "hdr.b");
    std::string err;
    REQUIRE(fx.eng.edit_field(*d, *b, "0x1234", &err));
    CHECK(bytes_of(*d).substr(1, 2) == "\x12\x34");
    ParseResult r2 = fx.eng.parse(*d, "basic");
    CHECK(fld(r2, "hdr.b").value == "4660 (0x1234)");
    CHECK(d->undo_stack().back().label == "Edit field b");

    CHECK_FALSE(fx.eng.edit_field(*d, *b, "70000", &err));
    CHECK(err.find("out of range") != std::string::npos);
    CHECK_FALSE(fx.eng.edit_field(*d, *b, "-1", &err));
    CHECK_FALSE(fx.eng.edit_field(*d, *b, "banana", &err));

    REQUIRE(fx.eng.edit_field(*d, fld(r, "hdr.kind"), "HELLO", &err));
    CHECK(bytes_of(*d)[3] == 1);
    REQUIRE(fx.eng.edit_field(*d, fld(r, "hdr.kind"), "bye", &err));  // case-insensitive
    CHECK(bytes_of(*d)[3] == 2);

    REQUIRE(fx.eng.edit_field(*d, fld(r, "flt"), "-2.25", &err));
    ParseResult r3 = fx.eng.parse(*d, "basic");
    CHECK(fld(r3, "flt").value == "-2.25");

    REQUIRE(fx.eng.edit_field(*d, fld(r, "big"), "1", &err));
    CHECK(bytes_of(*d).substr(7, 8) == std::string("\0\0\0\0\0\0\0\x01", 8));

    CHECK_FALSE(fx.eng.edit_field(*d, fld(r, "blob"), "1", &err));  // not editable

    while (d->can_undo()) d->undo();
    CHECK(bytes_of(*d) == original);

    d->set_read_only(true);
    CHECK_FALSE(fx.eng.edit_field(*d, *b, "1", &err));
    CHECK(err == "document is read-only");
}

TEST_CASE("Doc API: read, numbers, edits, transaction undo, find") {
    Fixture fx;
    fx.load("");
    Document* d = fx.host.add(std::string("\x78\x56\x34\x12", 4) + "hello world");
    fx.eng.exec("return doc:u32le(0)");
    CHECK(fx.last_result() == "305419896 (0x12345678)");
    fx.eng.exec("return doc:u32be(0) == 0x78563412, doc:u8(100), doc:size(), doc:name()");
    CHECK(fx.console_has("true", ConsoleLine::Result));
    CHECK(fx.console_has("nil", ConsoleLine::Result));
    CHECK(fx.console_has("\"test.bin\"", ConsoleLine::Result));
    fx.eng.exec("return doc:read(4, 5)");
    CHECK(fx.last_result() == "\"hello\"");
    fx.eng.exec("return doc:find('world')");
    CHECK(fx.last_result() == "10 (0xA)");
    fx.eng.exec("return doc:find('6F ?? 77', 0, {hex=true})");
    CHECK(fx.last_result() == "8");
    fx.eng.exec("return doc:find('o', nil, {backward=true})");
    CHECK(fx.last_result() == "11 (0xB)");
    fx.eng.exec("return doc:find('zzz')");
    CHECK(fx.last_result() == "nil");

    size_t undo_before = d->undo_stack().size();
    fx.eng.exec("doc:transaction(function() doc:write(0, 'AB') doc:insert(2, '--') doc:erase(0, 1) end)");
    CHECK(fx.errors() == 0);
    CHECK(bytes_of(*d).substr(0, 4) == "B--\x34");
    CHECK(d->undo_stack().size() == undo_before + 1);
    d->undo();
    CHECK(bytes_of(*d).substr(0, 4) == "\x78\x56\x34\x12");

    // A failing transaction still closes the group and propagates the error.
    fx.eng.exec("doc:transaction(function() doc:write(0, 'Z') error('nope') end)");
    CHECK(fx.console_has("nope", ConsoleLine::Error));
    CHECK(d->undo_stack().size() == undo_before + 1);
    d->undo();
    CHECK(bytes_of(*d)[0] == '\x78');

    fx.eng.exec("doc:select(4, 5)");
    CHECK(d->view().sel_begin() == 4);
    CHECK(d->view().sel_len() == 5);
    CHECK(fx.host.reveals >= 1);
    fx.eng.exec("return sel.start, sel.len, cur");
    CHECK(fx.console_has("5", ConsoleLine::Result));
    fx.eng.exec("doc:jump(2)");
    CHECK(d->view().cursor == 2);

    d->set_read_only(true);
    fx.eng.exec("doc:write(0, 'x')");
    CHECK(fx.console_has("document is read-only", ConsoleLine::Error));
}

TEST_CASE("Doc API: doc:jump / doc:select / doc:select_ranges reveal from the old position (Back works)") {
    Fixture fx;
    fx.load("");
    Document* d = fx.host.add(std::string(100, 'a'));
    fx.host.app_like = true;
    d->view().cursor = d->view().anchor = 5;
    fx.eng.exec("doc:jump(60)");
    CHECK(d->view().cursor == 60);
    REQUIRE(fx.host.nav.back_stack().size() == 1);
    CHECK(fx.host.nav.back_stack().back() == NavEntry{5, 0});  // the jump left 5: Back returns there
    fx.eng.exec("doc:select(10, 4)");
    CHECK(d->view().sel_begin() == 10);
    CHECK(d->view().sel_len() == 4);
    CHECK(d->view().cursor == 10);  // the host's selection stands (caret at the start, as in the app)
    REQUIRE(fx.host.nav.back_stack().size() == 2);
    CHECK(fx.host.nav.back_stack().back() == NavEntry{60, 0});
    fx.eng.exec("doc:select(10, 4)");  // no move: no entry
    CHECK(fx.host.nav.back_stack().size() == 2);
    fx.eng.exec("doc:select_ranges{ {offset=30, length=2}, {50, 1} }");
    REQUIRE(fx.host.nav.back_stack().size() == 3);
    CHECK(fx.host.nav.back_stack().back() == NavEntry{10, 4});
    CHECK(d->view().sel_begin() == 30);
    CHECK(d->view().extra_sel == std::vector<ByteRange>{{50, 51}});
    // Back restores the position before the script's last jump.
    const NavEntry back = fx.host.nav.back(NavEntry{d->view().sel_begin(), d->view().sel_len()});
    CHECK(back == NavEntry{10, 4});
    // Without an app (a host that does not select), the script still moves the view itself.
    fx.host.app_like = false;
    fx.eng.exec("doc:select(70, 3)");
    CHECK(d->view().anchor == 70);
    CHECK(d->view().cursor == 73);
}

TEST_CASE("Doc API: multi-selection with doc:selections / doc:select_ranges") {
    Fixture fx;
    fx.load("");
    Document* d = fx.host.add(std::string(100, 'a'));
    fx.eng.exec("return #doc:selections()");
    CHECK(fx.last_result() == "0");
    const int reveals = fx.host.reveals;
    fx.eng.exec("doc:select_ranges{ {offset=40, length=4}, {10, 2}, {offset=12, length=3}, {90, 50} }");
    CHECK(d->view().sel_begin() == 40);
    CHECK(d->view().sel_end() == 44);
    CHECK(d->view().extra_sel == std::vector<ByteRange>{{10, 15}, {90, 100}});  // merged, clamped
    CHECK(fx.host.reveals == reveals + 1);
    fx.eng.exec("local t = {} for _, r in ipairs(doc:selections()) do t[#t + 1] = r.offset .. '+' .. r.length end "
                "return table.concat(t, ' ')");
    CHECK(fx.last_result() == "\"40+4 10+5 90+10\"");

    // Bad entries raise and leave the selection as it was.
    fx.eng.exec("doc:select_ranges{ {1, 2}, 'x' }");
    CHECK(fx.console_has("entry 2 is not a table", ConsoleLine::Error));
    fx.eng.exec("doc:select_ranges{ {-1, 2} }");
    CHECK(fx.console_has("non-negative integer", ConsoleLine::Error));
    fx.eng.exec("local t = {} for i = 1, 100001 do t[i] = {i, 1} end doc:select_ranges(t)");
    CHECK(fx.console_has("too many ranges", ConsoleLine::Error));
    CHECK(d->view().extra_sel.size() == 2);
    // Integral floats are integers, as for doc:select (luaL_checkinteger); 1.5 is not.
    fx.eng.exec("doc:select_ranges{ {offset = 60 / 2, length = 4 / 2}, {20.0, 1} }");
    CHECK(d->view().sel_begin() == 30);
    CHECK(d->view().sel_end() == 32);
    CHECK(d->view().extra_sel == std::vector<ByteRange>{{20, 21}});
    fx.eng.exec("doc:select_ranges{ {1.5, 2} }");
    CHECK(fx.console_has("entry 1 needs a non-negative integer", ConsoleLine::Error));
    CHECK(d->view().sel_begin() == 30);

    // doc:select is one selection again; {} = only the caret.
    fx.eng.exec("doc:select(3, 1)");
    CHECK(d->view().extra_sel.empty());
    fx.eng.exec("doc:select_ranges{ {5, 1}, {7, 1} } doc:select_ranges{}");
    CHECK(d->view().extra_sel.empty());
    CHECK(!d->view().has_selection());
}

TEST_CASE("Doc API: target kind and pid") {
    Fixture fx;
    fx.load("");
    fx.host.add("abc");
    fx.eng.exec("return doc:target(), doc:pid()");
    CHECK(fx.console_has("\"file\"", ConsoleLine::Result));
    CHECK(fx.console_has("nil", ConsoleLine::Result));
    // This test process's own memory.
    std::string err;
    std::unique_ptr<Document> p = Document::open_process(uint32_t(os_process_id()), false, &err);
    REQUIRE_MESSAGE(p, err);
    fx.host.docs.push_back(std::move(p));
    fx.host.active = fx.host.docs.back().get();
    fx.eng.exec("return doc:target()");
    CHECK(fx.last_result() == "\"process\"");
    fx.eng.exec("return doc:pid() == " + std::to_string(uint32_t(os_process_id())));
    CHECK(fx.last_result() == "true");
    CHECK(fx.errors() == 0);
}

TEST_CASE("Doc API: closed document raises") {
    Fixture fx;
    fx.load("");
    Document* d = fx.host.add("abc");
    fx.eng.exec("keep = doc");
    fx.host.close(d);
    fx.eng.exec("return keep:size()");
    CHECK(fx.console_has("document closed", ConsoleLine::Error));
    fx.eng.exec("return tostring(keep)");
    CHECK(fx.last_result().find("(closed)") != std::string::npos);
}

TEST_CASE("REPL: expressions, statements, errors, inspect") {
    Fixture fx;
    fx.load("");
    fx.eng.exec("1 + 2");
    CHECK(fx.eng.console()[fx.eng.console().size() - 2].kind == ConsoleLine::Input);
    CHECK(fx.last_result() == "3");
    size_t n = fx.eng.console().size();
    fx.eng.exec("x = 41");
    CHECK(fx.eng.console().size() == n + 1);  // just the echo
    fx.eng.exec("x + 1");
    CHECK(fx.last_result() == "42 (0x2A)");
    fx.eng.exec("{ b = { 2, 3 }, a = 'q' }");
    CHECK(fx.last_result() == "{ a = \"q\", b = { 2, 3 } }");
    fx.eng.exec("local t = { name = 'x' } t.self = t return t");
    CHECK(fx.last_result().find("<cycle>") != std::string::npos);
    fx.eng.exec("print('hello', 1, { 1 })");
    CHECK(fx.last_line() == "hello\t1\t{ 1 }");
    fx.eng.exec("error('boom')");
    CHECK(fx.console_has("console:1: boom", ConsoleLine::Error));
    fx.eng.exec("this is not lua");
    CHECK(fx.eng.console().back().kind == ConsoleLine::Error);
    fx.eng.exec("hx.inspect({ [1] = 'a', [3] = 'c', ['key with space'] = true })");
    CHECK(fx.last_result().find("[\\\"key with space\\\"] = true") != std::string::npos);
    fx.eng.exec("hx.hex('\\1\\2\\255'), hx.unhex('de:ad') == '\\xde\\xad', hx.color('#ff8800') == hx.color(0xff8800)");
    CHECK(fx.console_has("\"01 02 FF\"", ConsoleLine::Result));
    fx.eng.exec("string.format('%08X', hx.crc32('123456789'))");
    CHECK(fx.last_result() == "\"CBF43926\"");

    uint64_t g = fx.eng.console_generation();
    fx.eng.clear_console();
    CHECK(fx.eng.console().empty());
    CHECK(fx.eng.console_generation() > g);
    for (int i = 0; i < 6000; ++i) fx.eng.log(ConsoleLine::Info, "line");
    CHECK(fx.eng.console().size() == 5000);
}

TEST_CASE("highlights from scripts") {
    Fixture fx;
    fx.load("");
    Document* d = fx.host.add(std::string(64, 'x'));
    CHECK(fx.eng.script_highlights(d->id()) == nullptr);
    fx.eng.exec("hx.highlight(doc, 10, 4, 'green', 'mark') hx.highlight(doc, 0, 2, 0x112233)");
    const HighlightSet* hs = fx.eng.script_highlights(d->id());
    REQUIRE(hs);
    REQUIRE(hs->items.size() == 2);
    CHECK(hs->items[0].offset == 0);  // finalized (sorted)
    CHECK(hs->items[0].color == from_rgb_int(0x112233));
    REQUIRE(hs->at(11));
    CHECK(hs->at(11)->label == "mark");
    fx.eng.exec("hx.clear_highlights(doc)");
    CHECK(fx.eng.script_highlights(d->id()) == nullptr);
}

TEST_CASE("reload: later definitions replace earlier ones, errors do not stop loading") {
    Fixture fx;
    fx.dir.write("a.lua", "hx.parser { name = 'X', parse = function(p) p:u8('from_a') end }\n"
                          "hx.command { name = 'C', run = function() end }");
    fx.dir.write("b.lua", "hx.parser { name = 'X', parse = function(p) p:u8('from_b') end }");
    fx.dir.write("c.lua", "local x = nil + 1");
    fx.dir.write("d.lua", "this is a syntax error");
    fx.eng.set_script_dirs({fx.dir.str()});
    fx.eng.reload();
    CHECK(fx.console_has("c.lua:1:", ConsoleLine::Error));
    CHECK(fx.console_has("d.lua:1:", ConsoleLine::Error));
    REQUIRE(fx.eng.parsers().size() == 1);
    CHECK(fx.eng.parsers()[0].file.find("b.lua") != std::string::npos);
    CHECK(fx.eng.commands().size() == 1);
    Document* d = fx.host.add("z");
    ParseResult r = fx.eng.parse(*d, "X");
    CHECK(find_field(r, "from_b"));
    CHECK(fx.eng.parse(*d, "nope").error.find("unknown parser") != std::string::npos);
}

TEST_CASE("reload: lib/ modules are require()-able, not run; os.exit is disabled") {
    Fixture fx;
    fx.dir.write("lib/mylib.lua", "ran_lib = (ran_lib or 0) + 1 return { twice = function(x) return 2 * x end }");
    fx.dir.write("sub/user.lua", "local m = require('mylib') answer = m.twice(21)");
    fx.eng.set_script_dirs({fx.dir.str()});
    fx.eng.reload();
    CHECK(fx.errors() == 0);
    CHECK(fx.console_has("Loaded 1 script"));
    fx.eng.exec("answer, ran_lib");
    CHECK(fx.console_has("42 (0x2A)", ConsoleLine::Result));
    CHECK(fx.last_result() == "1");  // required once, never executed as a script
    fx.eng.exec("os.exit(1)");
    CHECK(fx.console_has("os.exit is disabled", ConsoleLine::Error));
    // require never searches the current directory (planted ./x.lua / ./x.dll) or loads native code.
    fx.eng.exec("package.path:find('./', 1, true) == nil and package.path:find(string.char(46, 92), 1, true) == nil "
                "and package.cpath == ''");
    CHECK(fx.last_result() == "true");
    // Editing a lib module triggers a reload too.
    fx.dir.write("lib/mylib.lua", "return { twice = function(x) return 3 * x end }");
    CHECK(fx.eng.poll_hot_reload());
    fx.eng.exec("answer");
    CHECK(fx.last_result() == "63 (0x3F)");
}

TEST_CASE("hot reload detects modified, added and removed scripts") {
    Fixture fx;
    fx.load("hx.parser { name = 'one', parse = function(p) end }", "hot.lua");
    uint64_t count = fx.eng.reload_count();
    CHECK_FALSE(fx.eng.poll_hot_reload());
    fx.dir.write("hot.lua", "hx.parser { name = 'two', parse = function(p) end } -- longer now");
    CHECK(fx.eng.poll_hot_reload());
    CHECK(fx.eng.reload_count() == count + 1);
    CHECK(fx.console_has("Reloaded 1 script"));
    REQUIRE(fx.eng.parsers().size() == 1);
    CHECK(fx.eng.parsers()[0].name == "two");
    CHECK_FALSE(fx.eng.poll_hot_reload());
    fx.dir.write("new.lua", "hx.command { name = 'N', run = function() end }");
    CHECK(fx.eng.poll_hot_reload());
    CHECK(fx.eng.commands().size() == 1);
    fs::remove(fx.dir.path / "new.lua");
    CHECK(fx.eng.poll_hot_reload());
    CHECK(fx.eng.commands().empty());
}

TEST_CASE("commands run as one undo step") {
    Fixture fx;
    fx.load("hx.command { name = 'twice', run = function(doc) doc:write(0, 'A') doc:write(1, 'B') end }");
    Document* d = fx.host.add("xyz");
    size_t before = d->undo_stack().size();
    fx.eng.run_command("twice");
    CHECK(bytes_of(*d) == "ABz");
    CHECK(d->undo_stack().size() == before + 1);
    d->undo();
    CHECK(bytes_of(*d) == "xyz");
    fx.eng.run_command("missing");
    CHECK(fx.console_has("Unknown command", ConsoleLine::Error));
}

TEST_CASE("hx.run runs a command from Lua; unknown names and runaway recursion are errors") {
    Fixture fx;
    fx.load("hx.command { name = 'mark', run = function(doc) doc:write(0, 'M') end }\n"
            "hx.command { name = 'loop', run = function(doc) hx.run('loop') end }");
    Document* d = fx.host.add("xyz");
    size_t before = d->undo_stack().size();
    fx.eng.exec("hx.run('mark')");
    CHECK(bytes_of(*d) == "Myz");
    CHECK(d->undo_stack().size() == before + 1);
    fx.eng.exec("hx.run('nope')");
    CHECK(fx.console_has("unknown command 'nope'", ConsoleLine::Error));
    fx.eng.run_command("loop");
    CHECK(fx.console_has("nested too deeply", ConsoleLine::Error));
    fx.eng.exec("return 1 + 1");
    CHECK(fx.last_result() == "2");  // engine still usable
}

TEST_CASE("run_command: the name may refer into commands() although the command changes them") {
    Fixture fx;
    // Registering many commands reallocates the command list the caller's name points into; the
    // error message after the call must still carry the right name.
    fx.load("hx.command { name = 'grow', run = function(doc)\n"
            "  for i = 1, 200 do hx.command { name = 'c' .. i, run = function() end } end\n"
            "  error('boom')\n"
            "end }");
    fx.host.add("xyz");
    REQUIRE(!fx.eng.commands().empty());
    REQUIRE(fx.eng.commands()[0].name == "grow");
    fx.eng.run_command(fx.eng.commands()[0].name);
    CHECK(fx.console_has("Command 'grow': ", ConsoleLine::Error));
    CHECK(fx.console_has("boom", ConsoleLine::Error));
    CHECK(fx.eng.commands().size() == 201);
}

TEST_CASE("doc:transaction labels: inside a command the innermost label names the step") {
    Fixture fx;
    fx.load("hx.command { name = 'tlv', run = function(doc)\n"
            "  doc:write(0, 'A')\n"
            "  doc:transaction(function() doc:insert(1, 'BC') end, 'Append TLV')\n"
            "end }\n"
            "hx.command { name = 'plain', run = function(doc)\n"
            "  doc:transaction(function() doc:insert(0, 'Q') end)\n"
            "end }");
    Document* d = fx.host.add("xyz");
    fx.eng.run_command("tlv");
    CHECK(fx.errors() == 0);
    CHECK(bytes_of(*d) == "ABCyz");
    REQUIRE(d->undo_stack().size() == 1);
    CHECK(d->undo_stack().back().label == "Append TLV");
    fx.eng.run_command("plain");  // unlabelled: keeps the command's label
    REQUIRE(d->undo_stack().size() == 2);
    CHECK(d->undo_stack().back().label == "Script: plain");
    fx.eng.exec("doc:transaction(function() doc:write(0, 'z') end)");  // outside a command
    CHECK(d->undo_stack().back().label == "Script");
    fx.eng.exec("doc:transaction(function() doc:write(0, 'y') end, 'Mine')");
    CHECK(d->undo_stack().back().label == "Mine");
    CHECK(d->undo_stack().size() == 4);
}

// ---- hx.prompt -----------------------------------------------------------------------------------------

namespace {
const char* kAskScript = R"LUA(
hx.command { name = 'ask', run = function(doc)
    doc:write(0, 'A')
    local v = hx.prompt('Value?', 'def', { hint = 'one letter' })
    got = v == nil and 'cancelled' or v
    if v then doc:write(1, v) end
end }
hx.command { name = 'other', run = function(doc) doc:write(2, 'O') end }
hx.command { name = 'outer', run = function(doc) hx.run('ask') doc:write(2, '!') end }
hx.command { name = 'twice', run = function(doc)
    local a = hx.prompt('first')
    local b = hx.prompt('second', a)
    got = tostring(a) .. '+' .. tostring(b)
end }
hx.command { name = 'in transaction', run = function(doc)
    doc:transaction(function() hx.prompt('nope') end)
end }
hx.command { name = 'nested coroutine', run = function(doc)
    local ok, e = coroutine.resume(coroutine.create(function() return hx.prompt('nope') end))
    got = tostring(ok) .. ' ' .. tostring(e)
end }
hx.command { name = 'yield', run = function(doc) coroutine.yield() end }
hx.parser { name = 'asks', parse = function(p) hx.prompt('nope') end }
)LUA";
}  // namespace

TEST_CASE("hx.prompt: the command waits for answer_prompt; edits around it are separate steps") {
    Fixture fx;
    fx.load(kAskScript);
    Document* d = fx.host.add("xyz");
    fx.eng.run_command("ask");
    const ScriptEngine::PendingPrompt* pp = fx.eng.pending_prompt();
    REQUIRE(pp);
    CHECK(pp->title == "Value?");
    CHECK(pp->default_text == "def");
    CHECK(pp->hint == "one letter");
    CHECK(pp->command == "ask");
    CHECK(bytes_of(*d) == "Ayz");
    CHECK(d->undo_stack().size() == 1);
    CHECK(!d->in_group());  // no undo group stays open while the user types
    CHECK(d->can_undo());

    // Nothing else may start meanwhile (palette, hx.run from the console).
    fx.eng.run_command("other");
    CHECK(fx.console_has("Command 'other' not started: 'ask' is waiting for input", ConsoleLine::Error));
    fx.eng.exec("hx.run('other')");
    CHECK(bytes_of(*d) == "Ayz");
    fx.eng.exec("1 + 1");  // the console still works
    CHECK(fx.last_result() == "2");

    std::string q = "Q";
    fx.eng.answer_prompt(&q);
    CHECK(!fx.eng.pending_prompt());
    CHECK(bytes_of(*d) == "AQz");
    REQUIRE(d->undo_stack().size() == 2);
    CHECK(d->undo_stack().back().label == "Script: ask");
    fx.eng.exec("got");
    CHECK(fx.last_result() == "\"Q\"");
    fx.eng.answer_prompt(&q);  // no prompt pending: no-op
    CHECK(bytes_of(*d) == "AQz");

    // Cancel: hx.prompt returns nil.
    fx.eng.run_command("ask");
    fx.eng.answer_prompt(nullptr);
    fx.eng.exec("got");
    CHECK(fx.last_result() == "\"cancelled\"");
    CHECK(!fx.eng.pending_prompt());

    // Prompting twice; the second default comes from the first answer.
    fx.eng.run_command("twice");
    REQUIRE(fx.eng.pending_prompt());
    CHECK(fx.eng.pending_prompt()->default_text.empty());
    std::string one = "1";
    fx.eng.answer_prompt(&one);
    REQUIRE(fx.eng.pending_prompt());
    CHECK(fx.eng.pending_prompt()->title == "second");
    CHECK(fx.eng.pending_prompt()->default_text == "1");
    fx.eng.answer_prompt(nullptr);
    fx.eng.exec("got");
    CHECK(fx.last_result() == "\"1+nil\"");

    // hx.run inside a command runs inline: the prompt suspends the whole chain.
    fx.eng.run_command("outer");
    REQUIRE(fx.eng.pending_prompt());
    CHECK(fx.eng.pending_prompt()->command == "outer");
    std::string z = "Z";
    fx.eng.answer_prompt(&z);
    CHECK(bytes_of(*d) == "AZ!");
    CHECK(fx.errors() == 2);  // just the two refused starts
}

TEST_CASE("hx.prompt: only inside commands, never inside doc:transaction") {
    Fixture fx;
    fx.load(kAskScript);
    Document* d = fx.host.add("xyz");
    fx.eng.exec("hx.prompt('x')");
    CHECK(fx.console_has("hx.prompt is only available inside commands", ConsoleLine::Error));
    ParseResult r = fx.eng.parse(*d, "asks");
    CHECK(r.error.find("hx.prompt is only available inside commands") != std::string::npos);
    fx.eng.run_command("in transaction");
    CHECK(fx.console_has("hx.prompt: cannot ask here", ConsoleLine::Error));
    CHECK(!d->in_group());
    fx.eng.run_command("nested coroutine");  // a script's own coroutine is not the command
    fx.eng.exec("got");
    CHECK(fx.last_result() == "\"false test.lua:19: hx.prompt is only available inside commands\"");
    fx.eng.run_command("yield");
    CHECK(fx.console_has("Command 'yield': coroutine.yield() outside a coroutine", ConsoleLine::Error));
    CHECK(!fx.eng.pending_prompt());
    fx.eng.run_command("other");  // nothing is left waiting
    CHECK(bytes_of(*d) == "xyO");
}

TEST_CASE("hx.prompt: closed document, reload while pending, errors after the answer") {
    Fixture fx;
    fx.load(kAskScript + std::string("hx.command { name = 'boom', run = function() hx.prompt('x') error('after') end }"));
    Document* d = fx.host.add("xyz");
    fx.eng.run_command("ask");
    fx.host.close(d);
    std::string q = "Q";
    fx.eng.answer_prompt(&q);
    CHECK(fx.console_has("Command 'ask': ", ConsoleLine::Error));
    CHECK(fx.console_has("document closed", ConsoleLine::Error));
    CHECK(!fx.eng.pending_prompt());

    fx.eng.run_command("boom");
    fx.eng.answer_prompt(&q);
    CHECK(fx.console_has("Command 'boom': ", ConsoleLine::Error));
    CHECK(fx.console_has("after", ConsoleLine::Error));
    CHECK(fx.console_has("stack traceback:", ConsoleLine::Error));

    Document* e = fx.host.add("xyz");
    fx.eng.run_command("ask");
    REQUIRE(fx.eng.pending_prompt());
    fx.eng.reload();
    CHECK(!fx.eng.pending_prompt());
    CHECK(fx.console_has("Command 'ask' cancelled: scripts reloaded", ConsoleLine::Warn));
    fx.eng.answer_prompt(&q);  // no-op
    CHECK(bytes_of(*e) == "Ayz");
    CHECK(!e->in_group());
    fx.eng.run_command("other");
    CHECK(bytes_of(*e) == "AyO");
}

TEST_CASE("hx.prompt: the time limit applies per slice, not to the time spent in the dialog") {
    Fixture fx;
    fx.eng.set_script_time_limit_ms(400);
    fx.load("local function spin(s) local t = os.clock() while os.clock() - t < s do end end\n"
            "hx.command { name = 'slow', run = function() spin(0.25) hx.prompt('x') spin(0.25) done = true end }\n"
            "hx.command { name = 'too slow', run = function() spin(0.25) spin(0.25) spin(1) end }");
    fx.host.add("xyz");
    fx.eng.run_command("slow");
    REQUIRE(fx.eng.pending_prompt());
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    std::string a = "a";
    fx.eng.answer_prompt(&a);
    fx.eng.exec("done");
    CHECK(fx.last_result() == "true");
    CHECK(fx.errors() == 0);
    fx.eng.run_command("too slow");
    CHECK(fx.console_has("time limit exceeded (400 ms)", ConsoleLine::Error));
}

// ---- bundled example scripts -------------------------------------------------------------------------

struct Examples : Fixture {
    Examples() {
        eng.set_script_dirs({HEXER_SOURCE_SCRIPTS_DIR});
        eng.reload();
    }
    bool has_parser(const std::string& n) const {
        for (auto& p : eng.parsers())
            if (p.name == n) return true;
        return false;
    }
};

TEST_CASE("examples: load cleanly") {
    Examples fx;
    std::string all;
    for (const ConsoleLine& l : fx.eng.console()) all += l.text + "\n";
    INFO(all);
    CHECK(fx.errors() == 0);
    CHECK(fx.has_parser("PNG image"));
    CHECK(fx.has_parser("HXP packet"));
    CHECK(fx.has_parser("ZIP archive"));
    CHECK(fx.eng.commands().size() >= 7);
}

TEST_CASE("examples: PNG") {
    Examples fx;
    std::string ihdr = std::string("\0\0\0\x10\0\0\0\x08\x08\x02\0\0\0", 13);
    std::string png = std::string("\x89PNG\r\n\x1a\n", 8);
    png += be32(13) + "IHDR" + ihdr + be32(crc32("IHDR" + ihdr));
    png += be32(0) + "IEND" + be32(crc32("IEND"));
    Document* d = fx.host.add(png, "img.png");
    CHECK(fx.eng.detect_parser(*d) == "PNG image");
    ParseResult r = fx.eng.parse(*d, "PNG image");
    INFO(r.error);
    REQUIRE(r.error.empty());
    REQUIRE(find_field(r, "chunk[0].data.width"));
    CHECK(fld(r, "chunk[0].data.width").value == "16 (0x10)");
    CHECK(fld(r, "chunk[0].data.color_type").value == "2 = Truecolor (RGB)");
    CHECK(fld(r, "chunk[0].crc").comment == "CRC OK");
    CHECK(fld(r, "chunk[1].type").value == "\"IEND\"");
    CHECK_FALSE(find_field(r, "trailing data"));

    // Edit through the structure (serializer direction): width = 32, then the CRC no longer matches.
    std::string err;
    REQUIRE(fx.eng.edit_field(*d, fld(r, "chunk[0].data.width"), "32", &err));
    ParseResult r2 = fx.eng.parse(*d, "PNG image");
    CHECK(fld(r2, "chunk[0].crc").comment.find("MISMATCH") != std::string::npos);
}

TEST_CASE("examples: HXP build, parse, patch, undo") {
    Examples fx;
    fx.eng.run_command("HXP: build sample packet");
    CHECK(fx.errors() == 0);
    REQUIRE(fx.host.active);
    Document* d = fx.host.active;
    CHECK(fx.eng.detect_parser(*d) == "HXP packet");
    ParseResult r = fx.eng.parse(*d, "HXP packet");
    INFO(r.error);
    REQUIRE(r.error.empty());
    CHECK(fld(r, "packet[0].msg_type").value == "1 = HELLO");
    CHECK(fld(r, "packet[1].msg_type").value == "2 = DATA");
    CHECK(fld(r, "packet[0].crc").comment == "CRC OK");
    CHECK(fld(r, "packet[1].crc").comment == "CRC OK");
    CHECK(fld(r, "packet[0]").value == "HELLO");
    CHECK(fld(r, "packet[0].payload.record[1].name").value == "\"sensor-7\"");
    CHECK(fld(r, "packet[1].payload.record[1].celsius_x10").comment.find("23.5") != std::string::npos);
    CHECK(fld(r, "packet[0].payload.record[0]").value == "DEVICE_ID");

    std::string before = bytes_of(*d);
    d->view().cursor = d->view().anchor = 7;  // inside the first record of packet 0
    fx.eng.run_command("HXP: append TLV record at cursor");
    REQUIRE(fx.eng.pending_prompt());
    CHECK(fx.eng.pending_prompt()->title == "NAME record text");
    std::string text = fx.eng.pending_prompt()->default_text;
    CHECK(text == "added by hexer");
    fx.eng.answer_prompt(&text);
    CHECK(fx.errors() == 0);
    ParseResult r2 = fx.eng.parse(*d, "HXP packet");
    REQUIRE(r2.error.empty());
    CHECK(fld(r2, "packet[0].crc").comment == "CRC OK");
    CHECK(fld(r2, "packet[0].payload.record[1].name").value == "\"added by hexer\"");
    CHECK(fld(r2, "packet[0].payload.record[2].name").value == "\"sensor-7\"");
    CHECK(fld(r2, "packet[1].crc").comment == "CRC OK");
    d->undo();
    CHECK(bytes_of(*d) == before);

    fx.eng.run_command("HXP: print packet summary");
    CHECK(fx.console_has("HELLO"));
    CHECK(fx.console_has("2 packet(s)"));
}

TEST_CASE("examples: ZIP built with string.pack in the console") {
    Examples fx;
    fx.eng.exec(R"LUA(
local name, data = "a.txt", "hello"
local crc = hx.crc32(data)
local lfh = string.pack("<I4I2I2I2I2I2I4I4I4I2I2", 0x04034b50, 20, 0, 0, 0, 0x21, crc, #data, #data, #name, 0) .. name .. data
local cdh = string.pack("<I4BBI2I2I2I2I2I4I4I4I2I2I2I2I2I4I4", 0x02014b50, 20, 3, 20, 0, 0, 0, 0x21, crc, #data, #data, #name, 0, 0, 0, 0, 0, 0) .. name
local eocd = string.pack("<I4I2I2I2I2I4I4I2", 0x06054b50, 0, 0, 1, 1, #cdh, #lfh, 0)
hx.new_doc("t.zip", lfh .. cdh .. eocd)
)LUA");
    CHECK(fx.errors() == 0);
    Document* d = fx.host.active;
    REQUIRE(d);
    CHECK(fx.eng.detect_parser(*d) == "ZIP archive");
    ParseResult r = fx.eng.parse(*d, "ZIP archive");
    INFO(r.error);
    REQUIRE(r.error.empty());
    CHECK(fld(r, "file[0]").value == "a.txt");
    CHECK(fld(r, "file[0].data").size == 5);
    CHECK(fld(r, "file[0].mod_date").comment == "1980-01-01 00:00:00");
    CHECK(fld(r, "central[0].host_os").value == "3 = Unix");
    CHECK(fld(r, "end_of_central_directory").value == "1 entries");
    CHECK_FALSE(find_field(r, "unknown"));
}

TEST_CASE("examples: selection commands") {
    Examples fx;
    Document* d = fx.host.add("123456789");
    d->view().anchor = 0;
    d->view().cursor = 9;
    fx.eng.run_command("Selection: checksum (sum8/xor8/crc32)");
    CHECK(fx.console_has("crc32 = 0xCBF43926"));
    fx.eng.run_command("Selection: print as C array");
    CHECK(fx.console_has("0x31, 0x32, 0x33"));
    fx.eng.run_command("Selection: XOR with key");
    REQUIRE(fx.eng.pending_prompt());
    CHECK(fx.eng.pending_prompt()->default_text == "FF");
    std::string key = fx.eng.pending_prompt()->default_text;  // OK on the default
    fx.eng.answer_prompt(&key);
    CHECK(!fx.eng.pending_prompt());
    CHECK(bytes_of(*d)[0] == char(0x31 ^ 0xFF));
    CHECK(bytes_of(*d)[8] == char(0x39 ^ 0xFF));
    d->undo();
    CHECK(bytes_of(*d) == "123456789");
    fx.eng.run_command("Selection: XOR with key");
    key = "'ab'";
    fx.eng.answer_prompt(&key);
    CHECK(bytes_of(*d)[0] == char('1' ^ 'a'));
    CHECK(bytes_of(*d)[1] == char('2' ^ 'b'));
    CHECK(fx.errors() == 0);

    Document* z = fx.host.add(std::string(10, 'x') + std::string(20, '\0') + "y" + std::string(8, '\0') + "y" +
                              std::string(16, '\0'));
    z->view().anchor = z->view().cursor = 0;
    fx.eng.run_command("Highlight: all NUL runs >= 16 bytes in view range");
    const HighlightSet* hs = fx.eng.script_highlights(z->id());
    REQUIRE(hs);
    REQUIRE(hs->items.size() == 2);
    CHECK(hs->items[0].offset == 10);
    CHECK(hs->items[0].length == 20);
    CHECK(hs->items[1].offset == 40);
    CHECK(hs->items[1].length == 16);
}

TEST_CASE("examples: XOR with key prompts, remembers the key, is one undo step") {
    Examples fx;
    std::string orig;
    for (int i = 0; i < 300000; ++i) orig += char((i * 7 + i / 251) & 0xFF);
    Document* d = fx.host.add(orig);
    auto ref = [&](uint64_t start, uint64_t len, const std::string& key) {
        std::string s = orig;
        for (uint64_t i = 0; i < len; ++i)
            s[size_t(start + i)] = char(s[size_t(start + i)] ^ key[size_t(i % key.size())]);
        return s;
    };
    auto run = [&](uint64_t start, uint64_t len, const std::string& answer) {
        d->view().anchor = start;
        d->view().cursor = start + len;
        fx.eng.run_command("Selection: XOR with key");
        REQUIRE(fx.eng.pending_prompt());
        fx.eng.answer_prompt(&answer);
        CHECK(!fx.eng.pending_prompt());
    };
    size_t steps = d->undo_stack().size();
    run(3, 19, "DE AD BE EF");  // multi-byte key; 19 bytes = 2 words + a tail
    CHECK(bytes_of(*d) == ref(3, 19, "\xDE\xAD\xBE\xEF"));
    REQUIRE(d->undo_stack().size() == steps + 1);
    CHECK(d->undo_stack().back().label == "XOR selection");
    d->undo();
    CHECK(bytes_of(*d) == orig);

    // The last key is the next default.
    d->view().anchor = 0;
    d->view().cursor = 1;
    fx.eng.run_command("Selection: XOR with key");
    REQUIRE(fx.eng.pending_prompt());
    CHECK(fx.eng.pending_prompt()->default_text == "DE AD BE EF");
    CHECK(fx.eng.pending_prompt()->hint.find("quotes") != std::string::npos);
    fx.eng.answer_prompt(nullptr);  // cancel: nothing changes
    CHECK(bytes_of(*d) == orig);

    // Odd key lengths across chunk boundaries (the key stream repeats every lcm(len, 8) bytes).
    run(5, 299990, "\"abcde\"");
    CHECK(bytes_of(*d) == ref(5, 299990, "abcde"));
    d->undo();
    run(1, 200001, "0x01,0x02,0x03");
    CHECK(bytes_of(*d) == ref(1, 200001, "\x01\x02\x03"));
    d->undo();
    run(0, 7, "FF");
    CHECK(bytes_of(*d) == ref(0, 7, "\xFF"));
    d->undo();
    CHECK(bytes_of(*d) == orig);
    CHECK(fx.errors() == 0);

    // Bad keys and empty selections are refused with a message.
    run(0, 4, "XYZ");
    CHECK(fx.console_has("XOR: not hex bytes or a quoted text: XYZ", ConsoleLine::Error));
    run(0, 4, "\"\"");
    CHECK(fx.console_has("XOR: the key is empty", ConsoleLine::Error));
    CHECK(bytes_of(*d) == orig);
    d->view().anchor = d->view().cursor = 0;
    fx.eng.run_command("Selection: XOR with key");
    CHECK(!fx.eng.pending_prompt());
    CHECK(fx.console_has("select some bytes first", ConsoleLine::Warn));
}

// ---- bundled examples on realistic inputs ------------------------------------------------------------
//
// The PNG and ZIP samples were produced by real encoders (Python's zlib and zipfile modules), so the
// parsers are checked against the layouts real tools write, not just against layouts built here.

namespace {

std::string unhex(const char* h) {
    std::string out;
    auto nib = [](char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; };
    for (; h[0] && h[1]; h += 2) out += char(nib(h[0]) << 4 | nib(h[1]));
    return out;
}

std::string hex_of(const std::string& s) {
    static const char* kDigits = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        out += kDigits[c >> 4];
        out += kDigits[c & 15];
    }
    return out;
}

std::string le(uint64_t v, int n) {
    std::string s;
    for (int i = 0; i < n; ++i) s += char((v >> (8 * i)) & 0xFF);
    return s;
}

// 4x2 indexed PNG: IHDR gAMA PLTE tRNS pHYs tIME tEXt IDAT IDAT (zlib stream split in two) IEND.
const char* kPngHex =
    "89504E470D0A1A0A0000000D494844520000000400000002080300000048768D510000000467414D410000B18F0BFC61"
    "0500000009504C5445FF000000FF000000FF2D4ACD8A0000000274524E53FF80080FB36A000000097048597300000B13"
    "00000B1301009A9C180000000774494D4507EA0B050D2D0AF32273C50000001374455874536F66747761726500486578"
    "6572207465737478F4272D000000074944415478DA63606064622A3AE548000000084944415400614600002B0008204B"
    "D2940000000049454E44AE426082";

// zipfile: "dir/" (directory), "dir/hello.txt" (stored, entry comment), "data.bin" (deflate),
// archive comment.
const char* kZipRegularHex =
    "504B0304140000000000A56DB158000000000000000000000000040000006469722F504B0304140000000000A56DB158"
    "537424F40D0000000D0000000D0000006469722F68656C6C6F2E74787468656C6C6F2C20776F726C640A504B03041400"
    "000008008318225AFC2793AE460000000801000008000000646174612E62696E73741C1E808191899985958D9D83938B"
    "9B87978F5F4050485844544C5C42524A5A46564E5E4151495945554D5D43534B5B47574FDFC0D0C8D8C4D4CCDCC2D2CA"
    "DAC6D6CE1E00504B01021400140000000000A56DB158000000000000000000000000040000000000000000001000ED41"
    "000000006469722F504B01021400140000000000A56DB158537424F40D0000000D0000000D0000000D00000000000000"
    "8001220000006469722F68656C6C6F2E747874656E74727920636F6D6D656E74504B010214001400000008008318225A"
    "FC2793AE460000000801000008000000000000000000000080015A000000646174612E62696E504B0506000000000300"
    "0300B0000000C60000000F006172636869766520636F6D6D656E74";

// zipfile writing to a non-seekable stream: sizes are 0 in the local headers (flag 8) and follow
// the data in signed data descriptors. a.txt is deflated, b.txt stored.
const char* kZipStreamedHex =
    "504B03041400080008000000215800000000000000000000000005000000612E7478742B2E294A4DCC4D4D51281E3A0C"
    "00504B0708510717A10E000000B4000000504B0304140008000000000021580000000000000000000000000500000062"
    "2E7478747365636F6E64504B070869111FB60600000006000000504B0102140014000800080000002158510717A10E00"
    "0000B4000000050000000000000000000000800100000000612E747874504B010214001400080000000000215869111F"
    "B60600000006000000050000000000000000000000800141000000622E747874504B0506000000000200020066000000"
    "7A0000000000";

// zipfile with force_zip64=True: local sizes are 0xFFFFFFFF, real sizes in a ZIP64 extra record.
const char* kZip64Hex =
    "504B03042D0000000000000021580E5ADE2BFFFFFFFFFFFFFFFF070014006269672E7478740100100014000000000000"
    "00140000000000000070726574656E6420746869732069732068756765504B01022D002D0000000000000021580E5ADE"
    "2B14000000140000000700000000000000000000008001000000006269672E747874504B050600000000010001003500"
    "00004D0000000000";

// Leaf fields (no children, size > 0) must tile [0, size) exactly: no gaps, no overlaps.
// Returns "" when they do, else a description of the first problem.
std::string tiling_problem(const ParseResult& r, uint64_t size) {
    std::vector<const Field*> leaves;
    for (const Field& f : r.fields)
        if (f.children.empty() && f.size > 0) leaves.push_back(&f);
    std::stable_sort(leaves.begin(), leaves.end(),
                     [](const Field* a, const Field* b) { return a->offset < b->offset; });
    uint64_t at = 0;
    for (const Field* f : leaves) {
        if (f->offset != at)
            return (f->offset > at ? "gap before " : "overlap at ") + f->name + " @" + std::to_string(f->offset) +
                   " (expected " + std::to_string(at) + ")";
        at = f->offset + f->size;
    }
    if (at != size) return "leaves end at " + std::to_string(at) + ", size " + std::to_string(size);
    return "";
}

std::vector<std::string> root_names(const ParseResult& r) {
    std::vector<std::string> out;
    for (const Field& f : r.fields)
        if (f.parent < 0) out.push_back(f.name);
    return out;
}

std::string tree_dump(const ParseResult& r) {
    std::string s;
    for (size_t i = 0; i < r.fields.size(); ++i) {
        const Field& f = r.fields[i];
        s += std::string(size_t(f.depth) * 2, ' ') + f.name + " @" + std::to_string(f.offset) + "+" +
             std::to_string(f.size) + " = " + f.value + (f.comment.empty() ? "" : "  // " + f.comment) + "\n";
    }
    return s;
}

// A parse of damaged data may stop with an EOF error (the partial tree is kept), but must never fail
// with a script bug ("attempt to index a nil value", "bad argument", ...).
bool acceptable_damage_error(const std::string& e) {
    return e.empty() || e.find("read past end of data") != std::string::npos;
}

}  // namespace

TEST_CASE("examples: realistic PNG (palette, ancillary chunks, split IDAT)") {
    Examples fx;
    const std::string png = unhex(kPngHex);
    REQUIRE(png.size() == 206);
    Document* d = fx.host.add(png, "real.png");
    CHECK(fx.eng.detect_parser(*d) == "PNG image");
    ParseResult r = fx.eng.parse(*d, "PNG image");
    INFO(tree_dump(r));
    REQUIRE(r.error.empty());
    CHECK(tiling_problem(r, d->size()) == "");
    CHECK(fx.errors() == 0);

    std::vector<std::string> roots = root_names(r);
    REQUIRE(roots.size() == 11);
    CHECK(roots[0] == "signature");
    CHECK(roots[10] == "chunk[9]");
    const char* types[] = {"IHDR", "gAMA", "PLTE", "tRNS", "pHYs", "tIME", "tEXt", "IDAT", "IDAT", "IEND"};
    for (int i = 0; i < 10; ++i) {
        std::string c = "chunk[" + std::to_string(i) + "]";
        CHECK(fld(r, c + ".type").value == "\"" + std::string(types[i]) + "\"");
        CHECK(fld(r, c + ".crc").comment == "CRC OK");
    }

    CHECK(fld(r, "chunk[0]").value == "IHDR  (13 bytes)");
    CHECK(fld(r, "chunk[0].type").comment == "image header");
    CHECK(fld(r, "chunk[0].data.width").value == "4");
    CHECK(fld(r, "chunk[0].data.height").value == "2");
    CHECK(fld(r, "chunk[0].data.bit_depth").value == "8");
    CHECK(fld(r, "chunk[0].data.color_type").value == "3 = Indexed (palette)");
    CHECK(fld(r, "chunk[0].data.interlace").value == "0 = none");
    CHECK(fld(r, "chunk[1].data.gamma_x100000").comment == "gamma = 0.45455");

    const Field* entries = find_field(r, "chunk[2].data.entries");
    REQUIRE(entries);
    CHECK(entries->children.size() == 3);
    CHECK(fld(r, "chunk[2].data.entries[1]").value == "#00ff00");
    CHECK(fld(r, "chunk[2].data.entries[1].g").value == "0xFF");
    CHECK(fld(r, "chunk[2].data.entries[1].r").value == "0x00");
    uint32_t green = 0;
    REQUIRE(parse_color("#00ff00", green));
    CHECK(fld(r, "chunk[2].data.entries[1].b").color == green);  // inherited from the entry struct

    CHECK(fld(r, "chunk[3].data").value == "FF 80");
    CHECK(fld(r, "chunk[3].type").comment == "transparency");
    CHECK(fld(r, "chunk[4].data.pixels_per_unit_x").value == "2835 (0xB13)");
    CHECK(fld(r, "chunk[4].data.unit").value == "1 = meter");
    CHECK(fld(r, "chunk[5].data").value == "2026-11-05 13:45:10 UTC");
    CHECK(fld(r, "chunk[6].data").value == "Software: Hexer test");
    CHECK(fld(r, "chunk[6].data.keyword").value == "\"Software\"");
    CHECK(fld(r, "chunk[6].data.text").value == "\"Hexer test\"");
    CHECK(fld(r, "chunk[7].data").size == 7);
    CHECK(fld(r, "chunk[8].data").size == 8);
    CHECK(fld(r, "chunk[9]").value == "IEND  (0 bytes)");

    const Highlight* h = r.highlights.at(16);
    REQUIRE(h);
    CHECK(h->label == "chunk[0].data.width = 4");

    // Serializer direction: an enum edit by name breaks the IHDR CRC, nothing else.
    std::string err;
    REQUIRE(fx.eng.edit_field(*d, fld(r, "chunk[0].data.color_type"), "Truecolor (RGB)", &err));
    CHECK(bytes_of(*d)[25] == 2);
    ParseResult r2 = fx.eng.parse(*d, "PNG image");
    CHECK(fld(r2, "chunk[0].crc").comment.find("CRC MISMATCH") != std::string::npos);
    CHECK(fld(r2, "chunk[1].crc").comment == "CRC OK");
}

TEST_CASE("examples: PNG parser copes with damaged files") {
    Examples fx;
    const std::string png = unhex(kPngHex);

    SUBCASE("every truncation keeps a clean, complete tree") {
        for (size_t n = 8; n < png.size(); ++n) {
            Document* d = fx.host.add(png.substr(0, n), "cut.png");
            ParseResult r = fx.eng.parse(*d, "PNG image");
            INFO("prefix length ", n, "\n", tree_dump(r));
            CHECK(r.error.empty());
            CHECK(tiling_problem(r, n) == "");
            fx.host.close(d);
        }
        CHECK(fx.errors() == 0);
    }
    SUBCASE("length pointing past the end") {
        std::string bad = png;
        bad.replace(8, 4, be32(0xFFFFFF00u));
        Document* d = fx.host.add(bad, "bad.png");
        ParseResult r = fx.eng.parse(*d, "PNG image");
        INFO(tree_dump(r));
        CHECK(r.error.empty());
        CHECK(find_field(r, "chunk[0].data (truncated)"));
        CHECK(fld(r, "chunk[0].data (truncated)").comment == "length field points past the end of the file");
        CHECK(tiling_problem(r, bad.size()) == "");
    }
    SUBCASE("IHDR with the wrong length is shown raw") {
        std::string ihdr = std::string("\0\0\0\x10\0\0\0\x08\x08\x02\0\0\0\0", 14);  // 14 bytes instead of 13
        std::string bad = std::string("\x89PNG\r\n\x1a\n", 8) + be32(14) + "IHDR" + ihdr + be32(crc32("IHDR" + ihdr)) +
                          be32(0) + "IEND" + be32(crc32("IEND"));
        Document* d = fx.host.add(bad, "bad.png");
        ParseResult r = fx.eng.parse(*d, "PNG image");
        INFO(tree_dump(r));
        CHECK(r.error.empty());
        CHECK(fld(r, "chunk[0].data").type == "bytes");
        CHECK(fld(r, "chunk[0].crc").comment == "CRC OK");
        CHECK(fld(r, "chunk[1].type").value == "\"IEND\"");
        CHECK(tiling_problem(r, bad.size()) == "");
    }
    SUBCASE("tEXt without a NUL separator") {
        std::string text = "NoSeparatorHere";
        std::string bad = std::string("\x89PNG\r\n\x1a\n", 8) + be32(uint32_t(text.size())) + "tEXt" + text +
                          be32(crc32("tEXt" + text)) + be32(0) + "IEND" + be32(crc32("IEND")) + "junk";
        Document* d = fx.host.add(bad, "bad.png");
        ParseResult r = fx.eng.parse(*d, "PNG image");
        INFO(tree_dump(r));
        CHECK(r.error.empty());
        CHECK(fld(r, "chunk[0].data.text").value == "\"NoSeparatorHere\"");
        CHECK(fld(r, "chunk[0].data.text").comment == "no NUL after the keyword");
        CHECK(fld(r, "trailing data").value == "6A 75 6E 6B");
        CHECK(tiling_problem(r, bad.size()) == "");
    }
}

TEST_CASE("examples: realistic ZIP from Python zipfile") {
    Examples fx;
    const std::string zip = unhex(kZipRegularHex);
    REQUIRE(zip.size() == 411);
    Document* d = fx.host.add(zip, "real.zip");
    CHECK(fx.eng.detect_parser(*d) == "ZIP archive");
    ParseResult r = fx.eng.parse(*d, "ZIP archive");
    INFO(tree_dump(r));
    REQUIRE(r.error.empty());
    CHECK(tiling_problem(r, zip.size()) == "");
    CHECK(root_names(r) == std::vector<std::string>{"file[0]", "file[1]", "file[2]", "central[0]", "central[1]",
                                                   "central[2]", "end_of_central_directory"});
    CHECK(fld(r, "file[0]").value == "dir/");
    CHECK_FALSE(find_field(r, "file[0].data"));
    CHECK(fld(r, "file[1]").value == "dir/hello.txt");
    CHECK(fld(r, "file[1].method").value == "0 = stored");
    CHECK(fld(r, "file[1].mod_date").comment == "2024-05-17 13:45:10");
    CHECK(fld(r, "file[1].crc32").value == "0xF4247453");
    CHECK(fld(r, "file[1].data").size == 13);
    CHECK(fld(r, "file[1].data").offset == 0x4D);
    CHECK(fld(r, "file[2]").value == "data.bin");
    CHECK(fld(r, "file[2].method").value == "8 = deflate");
    CHECK(fld(r, "file[2].mod_date").comment == "2025-01-02 03:04:06");
    CHECK(fld(r, "file[2].uncompressed_size").value == "264 (0x108)");
    CHECK(fld(r, "file[2].data").size == 70);
    CHECK(fld(r, "central[0].external_attrs").value == "0x41ED0010");
    CHECK(fld(r, "central[1]").value == "dir/hello.txt");
    CHECK(fld(r, "central[1].comment").value == "\"entry comment\"");
    CHECK(fld(r, "central[1].local_header_offset").value == "0x00000022");
    CHECK(fld(r, "central[2].local_header_offset").value == "0x0000005A");
    CHECK(fld(r, "end_of_central_directory").value == "3 entries");
    CHECK(fld(r, "end_of_central_directory.cd_offset").value == "0x000000C6");
    CHECK(fld(r, "end_of_central_directory.comment").value == "\"archive comment\"");
    CHECK(fx.errors() == 0);
}

TEST_CASE("examples: streamed ZIP with data descriptors") {
    Examples fx;
    const std::string zip = unhex(kZipStreamedHex);
    Document* d = fx.host.add(zip, "streamed.zip");
    ParseResult r = fx.eng.parse(*d, "ZIP archive");
    INFO(tree_dump(r));
    REQUIRE(r.error.empty());
    CHECK(tiling_problem(r, zip.size()) == "");
    CHECK(root_names(r) == std::vector<std::string>{"file[0]", "data_descriptor", "file[1]", "data_descriptor",
                                                   "central[0]", "central[1]", "end_of_central_directory"});
    CHECK(fld(r, "file[0].flags").value == "0x0008 = DATA_DESCRIPTOR");  // opts.flags names the set bits
    CHECK(fld(r, "file[0].flags").flags != nullptr);
    CHECK(fld(r, "file[0].compressed_size").value == "0");
    CHECK(fld(r, "file[0].data").size == 14);  // found by resynchronising on the descriptor
    CHECK(fld(r, "file[1].data").size == 6);
    const Field* desc = find_field(r, "data_descriptor");
    REQUIRE(desc);
    CHECK(desc->offset == 0x31);
    CHECK(fld(r, "data_descriptor.crc32").value == "0xA1170751");
    CHECK(fld(r, "data_descriptor.compressed_size").value == "14 (0xE)");
    CHECK(fld(r, "data_descriptor.uncompressed_size").value == "180 (0xB4)");
    CHECK(fld(r, "central[0].compressed_size").value == "14 (0xE)");
    CHECK(fld(r, "end_of_central_directory").value == "2 entries");
    CHECK(fx.errors() == 0);
}

TEST_CASE("examples: ZIP64 extra fields and end records") {
    Examples fx;
    std::string zip = unhex(kZip64Hex);
    Document* d = fx.host.add(zip, "z64.zip");
    ParseResult r = fx.eng.parse(*d, "ZIP archive");
    INFO(tree_dump(r));
    REQUIRE(r.error.empty());
    CHECK(tiling_problem(r, zip.size()) == "");
    CHECK(fld(r, "file[0].compressed_size").value == "4294967295 (0xFFFFFFFF)");
    CHECK(fld(r, "file[0].extra.record[0]").value == "ZIP64");
    CHECK(fld(r, "file[0].extra.record[0].id").value == "1 = ZIP64");
    CHECK(fld(r, "file[0].extra.record[0].uncompressed_size").value == "20 (0x14)");
    CHECK(fld(r, "file[0].extra.record[0].compressed_size").value == "20 (0x14)");
    CHECK(fld(r, "file[0].data").size == 20);
    CHECK(fld(r, "central[0]").value == "big.txt");
    CHECK(fld(r, "end_of_central_directory").value == "1 entries");

    // Add the ZIP64 end record + locator in front of the classic EOCD, as large archives have them.
    const uint64_t cd_off = 0x4D, cd_size = 0x35, eocd_at = 0x82;
    std::string e64 = le(0x06064b50, 4) + le(44, 8) + le(45, 1) + le(3, 1) + le(45, 2) + le(0, 4) + le(0, 4) +
                      le(1, 8) + le(1, 8) + le(cd_size, 8) + le(cd_off, 8);
    std::string loc = le(0x07064b50, 4) + le(0, 4) + le(eocd_at, 8) + le(1, 4);
    std::string eocd = le(0x06054b50, 4) + le(0, 2) + le(0, 2) + le(0xFFFF, 2) + le(0xFFFF, 2) +
                       le(0xFFFFFFFF, 4) + le(0xFFFFFFFF, 4) + le(0, 2);
    std::string big = zip.substr(0, eocd_at) + e64 + loc + eocd;
    Document* d2 = fx.host.add(big, "z64b.zip");
    ParseResult r2 = fx.eng.parse(*d2, "ZIP archive");
    INFO(tree_dump(r2));
    REQUIRE(r2.error.empty());
    CHECK(tiling_problem(r2, big.size()) == "");
    CHECK(fld(r2, "zip64_end_of_central_directory").value == "1 entries");
    CHECK(fld(r2, "zip64_end_of_central_directory.record_size").value == "44 (0x2C)");
    CHECK(fld(r2, "zip64_end_of_central_directory.host_os").value == "3 = Unix");
    CHECK(fld(r2, "zip64_end_of_central_directory.cd_offset").value == "0x000000000000004D");
    CHECK_FALSE(find_field(r2, "zip64_end_of_central_directory.extensible_data"));
    CHECK(fld(r2, "zip64_eocd_locator.eocd64_offset").value == "0x0000000000000082");
    CHECK(fld(r2, "end_of_central_directory").value == "entries in ZIP64 record");
    CHECK(fx.errors() == 0);
}

TEST_CASE("examples: HXP packets built by the serializer command parse into a full tree") {
    Examples fx;
    fx.eng.run_command("HXP: build sample packet");
    REQUIRE(fx.host.active);
    Document* d = fx.host.active;
    CHECK(fx.console_has("Built 52 bytes"));
    ParseResult r = fx.eng.parse(*d, "HXP packet");
    INFO(tree_dump(r));
    REQUIRE(r.error.empty());
    CHECK(tiling_problem(r, d->size()) == "");
    CHECK(root_names(r) == std::vector<std::string>{"packet[0]", "packet[1]"});
    CHECK(fld(r, "packet[0].magic").value == "\"HX\"");
    CHECK(fld(r, "packet[0].version").value == "1");
    CHECK(fld(r, "packet[0].length").value == "16 (0x10)");
    CHECK(fld(r, "packet[0].payload.record[0].tag").value == "1 = DEVICE_ID");
    CHECK(fld(r, "packet[0].payload.record[0].len").value == "4");
    CHECK(fld(r, "packet[0].payload.record[0].device_id").value == "0xC0FFEE42");
    CHECK(fld(r, "packet[0].payload.record[1]").value == "NAME");
    CHECK(fld(r, "packet[1]").value == "DATA");
    CHECK(fld(r, "packet[1].payload.record[0].unix_time").value == "1767225600 (0x6955B900)");
    CHECK(fld(r, "packet[1].payload.record[0].unix_time").comment == "2026-01-01 00:00:00 UTC");
    CHECK(fld(r, "packet[1].payload.record[1].celsius_x10").value == "235 (0xEB)");
    CHECK(fld(r, "packet[1].payload.record[2]").value == "BLOB");
    CHECK(fld(r, "packet[1].payload.record[2].value").value == "DE AD BE EF");
    CHECK(fld(r, "packet[1].crc").comment == "CRC OK");
    uint32_t cyan = 0;
    REQUIRE(parse_color("cyan", cyan));
    CHECK(fld(r, "packet[0].payload.record[0].device_id").color == cyan);  // per-tag struct color

    // Serializer + parser together: append records to both packets, everything stays consistent.
    std::string kitchen = "kitchen";
    d->view().cursor = d->view().anchor = 49;  // inside the last record of packet[1]: append at its end
    fx.eng.run_command("HXP: append TLV record at cursor");
    fx.eng.answer_prompt(&kitchen);
    d->view().cursor = d->view().anchor = 0;
    fx.eng.run_command("HXP: append TLV record at cursor");
    REQUIRE(fx.eng.pending_prompt());
    CHECK(fx.eng.pending_prompt()->default_text == "kitchen");  // the last text is the default
    fx.eng.answer_prompt(&kitchen);
    CHECK(fx.errors() == 0);
    ParseResult r2 = fx.eng.parse(*d, "HXP packet");
    INFO(tree_dump(r2));
    REQUIRE(r2.error.empty());
    CHECK(tiling_problem(r2, d->size()) == "");
    CHECK(fld(r2, "packet[0].payload.record[0].name").value == "\"kitchen\"");
    CHECK(fld(r2, "packet[0].crc").comment == "CRC OK");
    CHECK(fld(r2, "packet[1].crc").comment == "CRC OK");
    CHECK(find_field(r2, "packet[1].payload.record[3]"));
    CHECK(fld(r2, "packet[1].payload.record[3].name").value == "\"kitchen\"");

    // Edit through the structure: the CRC check notices.
    std::string err;
    REQUIRE(fx.eng.edit_field(*d, fld(r2, "packet[1].msg_type"), "ack", &err));
    ParseResult r3 = fx.eng.parse(*d, "HXP packet");
    CHECK(fld(r3, "packet[1].msg_type").value == "3 = ACK");
    CHECK(fld(r3, "packet[1].crc").comment.find("CRC MISMATCH") != std::string::npos);
    CHECK(fld(r3, "packet[0].crc").comment == "CRC OK");
}

TEST_CASE("examples: HXP parser copes with damaged captures") {
    Examples fx;
    fx.eng.run_command("HXP: build sample packet");
    REQUIRE(fx.host.active);
    const std::string good = bytes_of(*fx.host.active);

    for (size_t n = 1; n < good.size(); ++n) {
        Document* d = fx.host.add(good.substr(0, n), "cut.hxp");
        ParseResult r = fx.eng.parse(*d, "HXP packet");
        INFO("prefix length ", n, "\n", tree_dump(r));
        CHECK(r.error.empty());
        CHECK(tiling_problem(r, n) == "");
        fx.host.close(d);
    }

    // Unknown tag, record overrunning the payload, garbage after the last packet.
    std::string odd = std::string("HX\x01\x03\x00\x05", 6) + std::string("\x42\x01\x99", 3) +
                      std::string("\x04\x07", 2) + "zz" + "tail";
    Document* d = fx.host.add(odd, "odd.hxp");
    ParseResult r = fx.eng.parse(*d, "HXP packet");
    INFO(tree_dump(r));
    CHECK(r.error.empty());
    CHECK(fld(r, "packet[0].payload.record[0]").value == "0x42");
    CHECK(fld(r, "packet[0].payload.record[0].tag").value == "66 = ?");
    CHECK(fld(r, "packet[0].payload.record[1].len").comment == "record overruns the payload");
    CHECK(fld(r, "packet[0].crc").comment.find("CRC MISMATCH") != std::string::npos);
    CHECK(fld(r, "unparsed").value == "74 61 69 6C");
    CHECK(tiling_problem(r, odd.size()) == "");
    CHECK(fx.errors() == 0);
}

TEST_CASE("examples: parsers survive random corruption without script errors") {
    Examples fx;
    fx.eng.run_command("HXP: build sample packet");
    REQUIRE(fx.host.active);
    struct Sample {
        std::string bytes, parser;
    };
    std::vector<Sample> samples = {
        {unhex(kPngHex), "PNG image"},           {unhex(kZipRegularHex), "ZIP archive"},
        {unhex(kZipStreamedHex), "ZIP archive"}, {unhex(kZip64Hex), "ZIP archive"},
        {bytes_of(*fx.host.active), "HXP packet"},
    };
    std::mt19937 rng(20261105);
    int eof_errors = 0, clean = 0;
    for (const Sample& s : samples) {
        for (int iter = 0; iter < 150; ++iter) {
            std::string data = s.bytes;
            int flips = 1 + int(rng() % 4);
            for (int k = 0; k < flips; ++k) {
                size_t at = rng() % data.size();
                // Mostly small/structural values (lengths, 0xFF runs), sometimes any byte.
                const unsigned char picks[] = {0x00, 0x01, 0x08, 0x7F, 0x80, 0xFF};
                data[at] = char(rng() % 3 ? picks[rng() % 6] : rng() % 256);
            }
            if (rng() % 4 == 0) data.resize(rng() % data.size() + 1);
            Document* d = fx.host.add(data, "fuzz.bin");
            fx.eng.detect_parser(*d);
            ParseResult r = fx.eng.parse(*d, s.parser);
            INFO(s.parser, " iteration ", iter, ": ", r.error, "\n", hex_of(data));
            CHECK(acceptable_damage_error(r.error));
            CHECK((!r.fields.empty() || !r.error.empty()));
            (r.error.empty() ? clean : eof_errors)++;
            fx.host.close(d);
        }
    }
    MESSAGE("random corruption: ", clean, " clean parses, ", eof_errors, " stopped at EOF with a partial tree");
    // Errors reach the console one line at a time (message, then traceback lines); none of them may
    // be a script bug.
    for (const ConsoleLine& l : fx.eng.console()) {
        if (l.kind != ConsoleLine::Error) continue;
        INFO(l.text);
        CHECK(l.text.find("attempt to") == std::string::npos);
        CHECK(l.text.find("bad argument") == std::string::npos);
    }
}

TEST_CASE("examples: detect() never errors on empty, tiny or random documents") {
    Examples fx;
    std::mt19937 rng(7);
    std::vector<std::string> inputs = {"", "P", "PK", "HX", "HX\x01", std::string("\x89PNG", 4)};
    for (int i = 0; i < 20; ++i) {
        std::string s(rng() % 64, '\0');
        for (char& c : s) c = char(rng());
        inputs.push_back(s);
    }
    for (const std::string& in : inputs) {
        Document* d = fx.host.add(in, "x.bin");
        std::string p = fx.eng.detect_parser(*d);
        CHECK(p == (in == "HX" ? "HXP packet" : ""));
        // Forcing a parser onto unrelated data still yields a tree or an EOF report.
        for (const char* name : {"PNG image", "ZIP archive", "HXP packet"}) {
            ParseResult r = fx.eng.parse(*d, name);
            INFO(name, " on ", in.size(), " bytes: ", r.error);
            CHECK(acceptable_damage_error(r.error));
        }
        fx.host.close(d);
    }
}

TEST_CASE("docs/scripting.md tutorial parser works") {
    Fixture fx;
    fx.load(R"LUA(
local TYPES = { [1] = "TEXT", [2] = "PING" }

hx.parser {
    name = "My protocol",
    extensions = { "myp" },
    detect = function(doc) return doc:u8(0) == 0xAB end,
    parse = function(p, doc)
        p:endian("be")
        p:u8("magic", { fmt = "hex", color = "gray" })
        local t = p:u8("type", { enum = TYPES })
        local len = p:u16("length")
        if TYPES[t] == "TEXT" then p:str("text", len) else p:bytes("payload", len) end
        local sum = p:u8("checksum", { fmt = "hex" })
        local data = doc:read(0, 4 + len)
        local s = 0
        for i = 1, #data do s = s + data:byte(i) end
        p:note((s & 0xFF) == sum and "checksum OK" or "checksum BAD")
    end,
}

hx.command {
    name = "My protocol: build TEXT message",
    run = function(doc)
        local text = my_text or "hello"
        local body = string.pack(">BBs2", 0xAB, 1, text)
        local sum = 0
        for i = 1, #body do sum = sum + body:byte(i) end
        hx.new_doc("message.myp", body .. string.char(sum & 0xFF))
    end,
}
)LUA");
    REQUIRE(fx.errors() == 0);
    fx.eng.run_command("My protocol: build TEXT message");
    REQUIRE(fx.host.active);
    Document* d = fx.host.active;
    CHECK(fx.eng.detect_parser(*d) == "My protocol");
    ParseResult r = fx.eng.parse(*d, "My protocol");
    INFO(r.error);
    REQUIRE(r.error.empty());
    CHECK(fld(r, "type").value == "1 = TEXT");
    CHECK(fld(r, "text").value == "\"hello\"");
    CHECK(fld(r, "checksum").comment == "checksum OK");
    std::string err;
    REQUIRE(fx.eng.edit_field(*d, fld(r, "type"), "PING", &err));
    CHECK(fld(fx.eng.parse(*d, "My protocol"), "checksum").comment == "checksum BAD");
}

TEST_CASE("identical parse errors are logged once until reload") {
    Fixture fx;
    fx.load("hx.parser { name = 'bad', parse = function(p) p:u32('x') end }");
    Document* d = fx.host.add("ab");
    fx.eng.parse(*d, "bad");
    int n = fx.errors();
    CHECK(n > 0);
    fx.eng.parse(*d, "bad");
    CHECK(fx.errors() == n);
    CHECK(fx.eng.parse(*d, "bad").error.find("read past end") != std::string::npos);
    fx.eng.reload();
    fx.eng.parse(*d, "bad");
    CHECK(fx.errors() > n);
}

TEST_CASE("time limit is sticky: pcall / coroutine loops cannot swallow it") {
    Fixture fx;
    fx.load(R"LUA(
hx.parser { name = "pcall loop", parse = function(p)
    p:u8("before")
    while true do pcall(function() while true do end end) end
end }
hx.parser { name = "xpcall loop", parse = function(p)
    while true do xpcall(function() while true do end end, function(e) return e end) end
end }
hx.parser { name = "coroutine loop", parse = function(p)
    while true do
        coroutine.resume(coroutine.create(function() while true do end end))
        pcall(coroutine.wrap(function() while true do end end))
    end
end }
)LUA");
    Document* d = fx.host.add("abc");
    for (const char* name : {"pcall loop", "xpcall loop", "coroutine loop"}) {
        INFO(name);
        auto t0 = std::chrono::steady_clock::now();
        ParseResult r = fx.eng.parse(*d, name);
        double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        CHECK(s < 6.0);
        CHECK(r.error.find("time limit") != std::string::npos);
    }
    // The flag is cleared afterwards: normal code (incl. pcall) runs to completion again.
    fx.eng.exec("local s = 0 for i = 1, 1000000 do s = s + i end return select(2, pcall(function() return s end))");
    CHECK(fx.last_result() == "500000500000 (0x746A5A2920)");
}

TEST_CASE("__gc finalizers run under a time limit (also when the state is closed)") {
    Fixture fx;
    fx.load("");
    fx.eng.exec("setmetatable({}, { __gc = function() gc_ran = (gc_ran or 0) + 1 end }) collectgarbage() collectgarbage()");
    fx.eng.exec("gc_ran");
    CHECK(fx.last_result() == "1");

    auto t0 = std::chrono::steady_clock::now();
    fx.eng.exec("setmetatable({}, { __gc = function() while true do end end }) collectgarbage() collectgarbage() return 7");
    double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    CHECK(s < 5.0);
    CHECK(fx.last_result() == "7");  // the console line itself was not timed out
    CHECK(fx.console_has("error in __gc", ConsoleLine::Warn));
    CHECK(fx.console_has("time limit", ConsoleLine::Warn));

    // A looping finalizer that is still pending when the state closes (reload / exit).
    fx.eng.exec("keep = debug.setmetatable({}, { __gc = function() while true do end end })");
    t0 = std::chrono::steady_clock::now();
    fx.eng.reload();
    s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    CHECK(s < 5.0);
    fx.eng.exec("1 + 1");
    CHECK(fx.last_result() == "2");
}

TEST_CASE("hx.inspect: depth is clamped and total output is bounded") {
    Fixture fx;
    fx.load("");
    // Deep chain with a huge depth: used to recurse until the C++ stack overflowed.
    fx.eng.exec("local t = {} local c = t for i = 1, 100000 do c.x = {} c = c.x end "
                "local s = hx.inspect(t, 1000000) return #s < 100000, s:find('{...}', 1, true) ~= nil");
    CHECK(fx.eng.console()[fx.eng.console().size() - 2].text == "true");
    CHECK(fx.last_result() == "true");
    CHECK(fx.errors() == 0);
    // Shared subtables (40^5 leaf entries when expanded): stops at the budget instead of running ~40 s.
    auto t0 = std::chrono::steady_clock::now();
    fx.eng.exec("local leaf = {} for i = 1, 40 do leaf[i] = i end local t = leaf "
                "for l = 1, 4 do local n = {} for i = 1, 40 do n[i] = t end t = n end "
                "local s = hx.inspect(t) return #s < 64 * 1024 * 1024, s:find('more entries', 1, true) ~= nil");
    double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    CHECK(s < 5.0);
    CHECK(fx.errors() == 0);
    CHECK(fx.eng.console()[fx.eng.console().size() - 2].text == "true");
    CHECK(fx.last_result() == "true");
}

TEST_CASE("stdin is unreachable: io.lines(), io.stdin, io.input(), loadfile(), dofile()") {
    Fixture fx;
    fx.load("");
    for (const char* code : {"io.read('l')", "io.lines()", "for l in io.lines() do end", "io.stdin:read('l')",
                             "io.input():read('l')", "dofile()", "assert(loadfile())"}) {
        INFO(code);
        int before = fx.errors();
        fx.eng.exec(code);
        CHECK(fx.errors() > before);
    }
    CHECK(fx.console_has("io.lines: there is no stdin", ConsoleLine::Error));
    CHECK(fx.console_has("loadfile: there is no stdin", ConsoleLine::Error));
    // Files still work.
    fx.dir.write("data.txt", "one\ntwo\n");
    fx.eng.exec("local n = 0 for l in io.lines(" + std::string("'") + fx.dir.str() + "/data.txt') do n = n + 1 end return n");
    CHECK(fx.last_result() == "2");
}

TEST_CASE("UTF-8 paths: require from a non-ASCII scripts dir, io.open, loadfile, dofile, io.lines") {
    Fixture fx;
    const std::string sub = "cfg\xC3\xA9";  // "cfgé" (UTF-8)
    fs::path root = fx.dir.path / fs::path(std::u8string(sub.begin(), sub.end()));
    fs::create_directories(root / "lib");
    {
        std::ofstream(root / "lib" / "mymod.lua", std::ios::binary) << "return { v = 42 }";
        std::ofstream(root / "main.lua", std::ios::binary) << "mod_v = require('mymod').v";
        std::ofstream(root / "chunk.txt", std::ios::binary) << "#!shebang\nreturn ...";
        std::ofstream(root / "lines.txt", std::ios::binary) << "a\nb\nc\n";
    }
    std::string rs = fx.dir.str() + "/" + sub;
    fx.eng.set_script_dirs({rs});
    fx.eng.reload();
    CHECK(fx.errors() == 0);
    fx.eng.exec("mod_v");
    CHECK(fx.last_result() == "42 (0x2A)");
    fx.eng.exec("root = '" + rs + "'");
    fx.eng.exec("assert(loadfile(root .. '/chunk.txt'))(5)");
    CHECK(fx.last_result() == "5");
    fx.eng.exec("dofile(root .. '/chunk.txt')");
    CHECK(fx.errors() == 0);
    fx.eng.exec("local n = 0 for l in io.lines(root .. '/lines.txt') do n = n + 1 end return n");
    CHECK(fx.last_result() == "3");
    fx.eng.exec("local f = assert(io.open(root .. '/out\xC3\xA9.txt', 'wb')) f:write('xyz') f:close() "
                "local g = assert(io.open(root .. '/out\xC3\xA9.txt', 'rb')) local s = g:read('a') g:close() return s");
    CHECK(fx.last_result() == "\"xyz\"");
    CHECK(fs::exists(root / fs::path(u8"outé.txt")));
    fx.eng.exec("select(2, pcall(require, 'nope'))");
    CHECK(fx.last_result().find("no file '") != std::string::npos);
    fx.eng.exec("(io.open(root .. '/missing.txt'))");
    CHECK(fx.last_result() == "nil");
    CHECK(fx.errors() == 0);
}

TEST_CASE("edit_field: every fmt round-trips its own display text; char literals; f32 range") {
    Fixture fx;
    fx.load(R"LUA(
hx.parser { name = "fmts", parse = function(p)
    p:endian("be")
    p:u32("plain")
    p:u32("hex", { fmt = "hex" })
    p:u32("dec", { fmt = "dec" })
    p:u32("bin", { fmt = "bin" })
    p:u32("tag", { fmt = "char" })
    p:u32("kind", { enum = { [3] = "THREE" } })
    p:i8("neg_hex", { fmt = "hex" })
    p:i16("neg_bin", { fmt = "bin" })
    p:i16("neg_char", { fmt = "char" })
    p:f32("flt")
end }
)LUA");
    std::string data = be32(13) + be32(0xDEADBEEF) + be32(7) + be32(5) + "IHDR" + be32(3) + "\xFF" +
                       std::string("\xFF\xFE", 2) + std::string("\xFF\x01", 2) + std::string("\x3F\xC0\x00\x00", 4);
    Document* d = fx.host.add(data);
    ParseResult r = fx.eng.parse(*d, "fmts");
    REQUIRE(r.error.empty());
    CHECK(fld(r, "tag").value == "'IHDR' (1229472850)");
    std::string err;
    for (const char* name : {"plain", "hex", "dec", "bin", "tag", "kind", "neg_hex", "neg_bin", "neg_char", "flt"}) {
        INFO(name, " = ", fld(r, name).value);
        CHECK(fx.eng.edit_field(*d, fld(r, name), fld(r, name).value, &err));
        INFO(err);
        CHECK(bytes_of(*d) == data);
    }
    REQUIRE(fx.eng.edit_field(*d, fld(r, "tag"), "'ABCD'", &err));
    CHECK(bytes_of(*d).substr(16, 4) == "ABCD");
    REQUIRE(fx.eng.edit_field(*d, fld(r, "tag"), "'\\x01\\n'", &err));  // short literal: low bytes
    CHECK(bytes_of(*d).substr(16, 4) == std::string("\0\0\x01\n", 4));
    CHECK_FALSE(fx.eng.edit_field(*d, fld(r, "tag"), "'ABCDE'", &err));
    CHECK(err.find("char literal") != std::string::npos);
    CHECK_FALSE(fx.eng.edit_field(*d, fld(r, "neg_hex"), "0x100", &err));  // still range-checked

    CHECK_FALSE(fx.eng.edit_field(*d, fld(r, "flt"), "1e39", &err));
    CHECK(err.find("out of range for f32") != std::string::npos);
    CHECK(fx.eng.edit_field(*d, fld(r, "flt"), "-3e38", &err));
    CHECK(fx.eng.edit_field(*d, fld(r, "flt"), "inf", &err));
    CHECK(fld(fx.eng.parse(*d, "fmts"), "flt").value == "inf");
}

TEST_CASE("p:read: variable-length formats longer than 64 KiB") {
    Fixture fx;
    fx.load(R"LUA(
hx.parser { name = "blob", parse = function(p)
    local s = p:read("<s4", "blob")
    blob_len = #s
    local z = p:read("z", "text")
    z_len = #z
    p:read("<s4", "short")
end }
)LUA");
    std::string data = std::string("\x70\x11\x01\x00", 4) + std::string(70000, 'a') + std::string(70000, 'b') +
                       std::string(1, '\0') + std::string("\x10\x00\x00\x00", 4) + "abc";
    Document* d = fx.host.add(data);
    ParseResult r = fx.eng.parse(*d, "blob");
    CHECK(fld(r, "blob").size == 70004);
    CHECK(fld(r, "text").size == 70001);
    fx.eng.exec("blob_len, z_len");
    CHECK(fx.console_has("70000 (0x11170)", ConsoleLine::Result));
    CHECK(r.error.find("read past end of data") != std::string::npos);  // a real EOF is still reported
}

TEST_CASE("parse at offset: relative cursor, absolute fields, range end is EOF") {
    Fixture fx;
    fx.load(R"LUA(
hx.parser { name = "rel", parse = function(p, doc)
    t0, sz, base = p:tell(), p:size(), p:base()
    p:u16le("a")
    p:u8("b")
    t1, rem = p:tell(), p:remaining()
    p:field("manual", 1, 2, "x")
    seek_err = select(2, pcall(p.seek, p, sz + 1))
    abs_byte = doc:u8(base + 1)
    p:u32le("past")
end }
)LUA");
    Document* d = fx.host.add(std::string("\xAA\xBB\x01\x02\x03\x04\x05\x06\x07\x08", 10));
    ParseResult r = fx.eng.parse(*d, "rel", 2, 5);  // bytes 01 02 03 04 05
    CHECK(fld(r, "a").offset == 2);
    CHECK(fld(r, "a").value == "513 (0x201)");
    CHECK(fld(r, "b").offset == 4);
    CHECK(fld(r, "b").value == "3");
    CHECK(fld(r, "manual").offset == 3);
    CHECK(r.highlights.at(2) != nullptr);
    CHECK(r.highlights.at(1) == nullptr);
    CHECK(r.error.find("read past end of data") != std::string::npos);  // 2 bytes left, needs 4
    CHECK_FALSE(find_field(r, "past"));
    fx.eng.exec("string.format('%d %d %d %d %d %d', t0, sz, base, t1, rem, abs_byte)");
    CHECK(fx.console_has("0 5 2 3 2 2", ConsoleLine::Result));
    fx.eng.exec("seek_err");
    CHECK(fx.console_has("seek out of range", ConsoleLine::Result));

    // Length to EOF and clamping past the document end.
    ParseResult all = fx.eng.parse(*d, "rel", 3, UINT64_MAX);
    CHECK(all.error.empty());
    CHECK(fld(all, "past").offset == 6);
    ParseResult beyond = fx.eng.parse(*d, "rel", 100, 4);
    CHECK(beyond.error.find("read past end of data") != std::string::npos);
    // The default overload still parses from 0.
    CHECK(fld(fx.eng.parse(*d, "rel"), "a").offset == 0);
}

TEST_CASE("parse at offset: PNG embedded in a larger buffer") {
    Examples fx;
    const std::string png = unhex(kPngHex);
    const uint64_t base = 1000;
    std::string blob = std::string(size_t(base), '\x55') + png + std::string(300, '\x66');
    Document* d = fx.host.add(blob, "container.bin");
    ParseResult whole = [&] {
        Document* only = fx.host.add(png, "real.png");
        return fx.eng.parse(*only, "PNG image");
    }();
    REQUIRE(whole.error.empty());

    ParseResult r = fx.eng.parse(*d, "PNG image", base, png.size());
    INFO(tree_dump(r));
    CHECK(r.error.empty());
    REQUIRE(r.fields.size() == whole.fields.size());
    for (size_t i = 0; i < r.fields.size(); ++i) {
        CHECK(r.fields[i].name == whole.fields[i].name);
        CHECK(r.fields[i].offset == whole.fields[i].offset + base);
        CHECK(r.fields[i].size == whole.fields[i].size);
        CHECK(r.fields[i].comment == whole.fields[i].comment);  // e.g. "CRC OK" (doc:read is absolute)
    }
    CHECK(fld(r, "chunk[0].crc").comment.find("CRC OK") != std::string::npos);
    CHECK(fld(r, "chunk[0].data.width").value == "4");
    CHECK(fld(r, "chunk[0].data.width").offset == base + 16);
    CHECK_FALSE(find_field(r, "trailing data"));  // the range ends at the PNG's end
    const Highlight* h = r.highlights.at(base + 16);
    REQUIRE(h);
    CHECK(h->label == "chunk[0].data.width = 4");

    // To EOF: the bytes after the PNG show up as trailing data at their absolute offset.
    ParseResult tail = fx.eng.parse(*d, "PNG image", base, UINT64_MAX);
    CHECK(fld(tail, "trailing data").offset == base + png.size());
    CHECK(fld(tail, "trailing data").size == 300);

    // Cut short: reads beyond the range raise the EOF error, the partial tree is kept.
    ParseResult cut = fx.eng.parse(*d, "PNG image", base, 30);
    CHECK(fld(cut, "signature").offset == base);
    CHECK(fld(cut, "chunk[0].data (truncated)").offset == base + 16);
}

TEST_CASE("run_source: one-off scripts register parsers until the next reload") {
    Fixture fx;
    fx.load("hx.parser { name = 'file', parse = function(p) p:u8('a') end }");
    std::string err;
    REQUIRE(fx.eng.run_source("hx.parser { name = 'once', parse = function(p) p:u16be('w') end }", "C struct", &err));
    bool found = false;
    for (const ParserInfo& p : fx.eng.parsers()) found |= p.name == "once" && p.file == "C struct";
    CHECK(found);
    Document* d = fx.host.add(std::string("\x00\x01\x02\x03", 4));
    ParseResult r = fx.eng.parse(*d, "once", 2, UINT64_MAX);
    CHECK(fld(r, "w").value == "515 (0x203)");
    CHECK(fld(r, "w").offset == 2);

    CHECK_FALSE(fx.eng.run_source("hx.parser {", "broken", &err));
    CHECK(err.find("broken") != std::string::npos);
    CHECK_FALSE(fx.eng.run_source("error('boom')", "boomer", &err));
    CHECK(err.find("boom") != std::string::npos);

    fx.eng.reload();
    for (const ParserInfo& p : fx.eng.parsers()) CHECK(p.name != "once");
}

TEST_CASE("hx.hash, hx.hash_algorithms, doc:hash") {
    Fixture fx;
    fx.load("");
    fx.eng.exec("hx.hash('crc32', '123456789')");
    CHECK(fx.last_result() == "\"cbf43926\"");
    fx.eng.exec("hx.hash('SHA-256', 'abc')");
    CHECK(fx.last_result() == "\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"");
    fx.eng.exec("hx.hash('md5', '')");
    CHECK(fx.last_result() == "\"d41d8cd98f00b204e9800998ecf8427e\"");
    fx.eng.exec("hx.hash('nope', 'x')");
    CHECK(fx.console_has("hx.hash: unknown algorithm 'nope'", ConsoleLine::Error));
    fx.eng.exec("local t = hx.hash_algorithms() return #t .. ' ' .. t[1] .. ' ' .. t[#t]");
    CHECK(fx.last_result() == "\"16 Sum-8 SHA-512\"");
    fx.eng.exec("local ok = true for _, n in ipairs(hx.hash_algorithms()) do ok = ok and #hx.hash(n, 'x') > 0 end return ok");
    CHECK(fx.last_result() == "true");

    fx.host.add("xx123456789yy");
    fx.eng.exec("doc:hash('CRC-32', 2, 9)");
    CHECK(fx.last_result() == "\"cbf43926\"");
    fx.eng.exec("doc:hash('crc32') == hx.hash('crc32', 'xx123456789yy')");  // default: whole doc
    CHECK(fx.last_result() == "true");
    fx.eng.exec("doc:hash('crc32', 2) == hx.hash('crc32', '123456789yy')");  // to EOF
    CHECK(fx.last_result() == "true");
    fx.eng.exec("doc:hash('crc32', 11, 100) == hx.hash('crc32', 'yy')");  // clamped
    CHECK(fx.last_result() == "true");
    fx.eng.exec("doc:hash('md5', 99, 5)");
    CHECK(fx.last_result() == "\"d41d8cd98f00b204e9800998ecf8427e\"");
    fx.eng.exec("doc:hash('bogus', 0, 1)");
    CHECK(fx.console_has("doc:hash:", ConsoleLine::Error));
    // Bounded: a long range is refused (it would block the UI thread).
    Document* big = fx.host.add(std::string(1, 'z'));
    std::vector<uint8_t> chunk(1 << 20, 0xAB);
    for (int i = 0; i < 257; ++i) REQUIRE(big->insert(big->size(), chunk.data(), chunk.size()));
    fx.eng.exec("doc:hash('crc32', 0, doc:size())");
    CHECK(fx.console_has("at most 256 MiB", ConsoleLine::Error));
    fx.eng.exec("#doc:hash('sha1', 0, 256 * 1024 * 1024)");
    CHECK(fx.last_result() == "40 (0x28)");
}

TEST_CASE("doc:view_range and bookmarks from Lua (undoable)") {
    Fixture fx;
    fx.load(R"LUA(
hx.command { name = "two marks", run = function(doc) doc:add_bookmark(1) doc:add_bookmark(2, 2, "b") end }
)LUA");
    Document* d = fx.host.add(std::string(100, 'a'));
    fx.eng.exec("doc:view_range() == nil");  // no drawn view (headless host)
    CHECK(fx.last_result() == "true");
    fx.host.has_view = true;
    fx.host.view_first = 16;
    fx.host.view_last = 79;
    fx.eng.exec("local a, b = doc:view_range() return a .. ' ' .. b");
    CHECK(fx.last_result() == "\"16 79\"");

    fx.eng.exec("doc:add_bookmark(10, 4, 'hdr', 'red', 'a note')");
    CHECK(fx.last_result() == "1");
    REQUIRE(d->view().bookmarks.size() == 1);
    CHECK(d->view().bookmarks[0].offset == 10);
    CHECK(d->view().bookmarks[0].length == 4);
    CHECK(d->view().bookmarks[0].name == "hdr");
    CHECK(d->view().bookmarks[0].note == "a note");
    CHECK(d->view().bookmarks[0].color != 0);
    fx.eng.exec("doc:add_bookmark(98, 50)");  // length clamped to EOF
    CHECK(fx.last_result() == "2");
    fx.eng.exec("local b = doc:bookmarks() return #b .. ' ' .. b[1].name .. ' ' .. b[1].offset .. ' ' .. b[1].length "
                ".. ' ' .. b[1].note .. ' ' .. b[2].length .. ' ' .. b[2].color .. '|' .. b[2].name .. '|'");
    CHECK(fx.last_result() == "\"2 hdr 10 4 a note 2 0||\"");
    fx.eng.exec("doc:add_bookmark(100)");
    CHECK(fx.console_has("doc:add_bookmark failed", ConsoleLine::Error));
    fx.eng.exec("doc:add_bookmark(0, 1, 'x', {})");
    CHECK(fx.console_has("color expected", ConsoleLine::Error));
    fx.eng.exec("doc:remove_bookmark(1)");
    REQUIRE(d->view().bookmarks.size() == 1);
    CHECK(d->view().bookmarks[0].offset == 98);
    fx.eng.exec("doc:remove_bookmark(5)");
    CHECK(fx.console_has("no bookmark #5", ConsoleLine::Error));
    CHECK(d->view().bookmarks.size() == 1);

    // Every change is an undo step.
    CHECK(d->undo());
    CHECK(d->view().bookmarks.size() == 2);
    CHECK(d->undo());
    CHECK(d->view().bookmarks.size() == 1);
    CHECK(d->undo());
    CHECK(d->view().bookmarks.empty());
    // A command's bookmarks are one step; read-only documents still take bookmarks.
    d->set_read_only(true);
    const int errors = fx.errors();
    fx.eng.run_command("two marks");
    CHECK(fx.errors() == errors);
    CHECK(d->view().bookmarks.size() == 2);
    d->set_read_only(false);  // (undo is refused while read-only)
    CHECK(d->undo());
    CHECK(d->view().bookmarks.empty());
}

TEST_CASE("hx.xor_scan and hx.xor_guess_key") {
    Fixture fx;
    fx.load("");
    std::string data(200, '\x11');
    const std::string secret = "SECRET!!", plain = "PLAINTEXT", text = "This is a test", key = "KEY";
    for (size_t i = 0; i < secret.size(); ++i) data[50 + i] = char(uint8_t(secret[i]) ^ 0x5A);
    for (size_t i = 0; i < plain.size(); ++i) data[120 + i] = char(uint8_t(plain[i]) + 3);
    for (size_t i = 0; i < text.size(); ++i) data[151 + i] = char(uint8_t(text[i]) ^ uint8_t(key[(151 + i) % 3]));
    fx.host.add(data);

    fx.eng.exec("local h = hx.xor_scan(doc, 'SECRET!!') return #h .. ' ' .. h[1].offset .. ' ' .. h[1].transform .. "
                "' ' .. hx.hex(h[1].key) .. ' ' .. h[1].phase .. ' ' .. h[1].text");
    CHECK(fx.last_result() == "\"1 50 xor 5A 0 XOR 0x5A\"");
    fx.eng.exec("local h = hx.xor_scan(doc, 'PLAINTEXT', { xor = false, rol = false }) "
                "return #h .. ' ' .. h[1].offset .. ' ' .. h[1].transform .. ' ' .. hx.hex(h[1].key)");
    CHECK(fx.last_result() == "\"1 120 add 03\"");
    fx.eng.exec("#hx.xor_scan(doc, 'PLAINTEXT', { start = 0, length = 125 })");  // range ends inside it
    CHECK(fx.last_result() == "0");
    fx.eng.exec("#hx.xor_scan(doc, 'PLAINTEXT', { add = false })");
    CHECK(fx.last_result() == "0");
    fx.eng.exec("local h = hx.xor_scan(doc, 'This is a test', { multi = true, xor = false, add = false, rol = false, "
                "max_key_len = 4 }) return #h .. ' ' .. h[1].offset .. ' ' .. h[1].transform .. ' ' .. h[1].key .. ' ' "
                ".. h[1].phase");
    CHECK(fx.last_result() == "\"1 151 xor_key KEY 1\"");
    CHECK(fx.errors() == 0);
    fx.eng.exec("(pcall(hx.xor_scan, doc, ''))");  // a Lua error raised before the scan
    CHECK(fx.last_result() == "false");
    fx.eng.exec("hx.xor_scan(doc, '')");
    CHECK(fx.console_has("hx.xor_scan: empty plaintext", ConsoleLine::Error));
    fx.eng.exec("hx.xor_scan(doc, 'abc', { max_key_len = 40 })");
    CHECK(fx.console_has("max_key_len must be 2..16", ConsoleLine::Error));

    // Key guess: zeros XORed with "AB" (absolute offsets: a range starting at an odd offset too).
    std::string ab(256, '\0');
    for (size_t i = 0; i < ab.size(); ++i) ab[i] = i % 2 ? 'B' : 'A';
    fx.host.add(ab);
    fx.eng.exec("local c = hx.xor_guess_key(doc, 0, doc:size()) return c[1].key .. ' ' .. string.format('%.3f', c[1].score)");
    CHECK(fx.last_result() == "\"AB 0.998\"");
    fx.eng.exec("hx.xor_guess_key(doc, 1, 100)[1].key");
    CHECK(fx.last_result() == "\"AB\"");
    fx.eng.exec("hx.xor_guess_key(doc, 0, 256, { plain = 'A', max_len = 1 })[1].key:byte()");  // 'A' ^ 'A' = 0
    CHECK(fx.last_result() == "0");
    fx.eng.exec("hx.xor_guess_key(doc, 0, 4, { plain = 'ab' })");
    CHECK(fx.console_has("plain must be a byte value", ConsoleLine::Error));

    // Bounded: a sparse 300 MiB file is refused as a whole, scanned in a range.
    const std::string big = path_join(fx.dir.str(), "big.bin");
    {
        auto f = OsFile::open(big, OsFile::Mode::CreateTruncate);
        REQUIRE(f);
        REQUIRE(f->truncate(300ull << 20));
    }
    fx.host.docs.push_back(Document::open_file(big));
    REQUIRE(fx.host.docs.back());
    fx.host.active = fx.host.docs.back().get();
    fx.eng.exec("hx.xor_scan(doc, 'MZ\\144\\0')");
    CHECK(fx.console_has("at most 256 MiB", ConsoleLine::Error));
    fx.eng.exec("#hx.xor_scan(doc, 'MZ\\144\\0', { start = 1024, length = 1 << 20 })");
    CHECK(fx.last_result() == "0");
    fx.eng.exec("hx.xor_guess_key(doc, 0, doc:size())");
    CHECK(fx.console_has("at most 16 MiB", ConsoleLine::Error));
}

// ---- Lua errors are C++ exceptions (Lua is compiled as C++, script/lua_onelua.cpp) -------------

namespace {

int g_dtors = 0;  // destructors run by the C functions below

struct DtorProbe {
    ~DtorProbe() { ++g_dtors; }
};

// Raises a Lua error while C++ objects with destructors are alive in this frame.
int raise_with_locals(lua_State* L) {
    DtorProbe probe;
    const std::string s(1000, 'x');
    const std::vector<int> v(1000, 7);
    const auto sp = std::make_shared<DtorProbe>();
    return luaL_error(L, "boom %d %d", int(s.size()), v[999]);
}

// Calls the Lua function at index 1 (it raises) while C++ objects are alive here.
int call_with_locals(lua_State* L) {
    DtorProbe probe;
    const std::vector<std::string> names(50, "name");
    lua_pushvalue(L, 1);
    lua_call(L, 0, 0);
    return 0;
}

}  // namespace

TEST_CASE("Lua errors unwind C++ frames: destructors of live locals run") {
    lua_State* L = luaL_newstate();
    REQUIRE(L);
    luaL_openlibs(L);
    g_dtors = 0;
    lua_pushcfunction(L, raise_with_locals);
    CHECK(lua_pcall(L, 0, 0, 0) == LUA_ERRRUN);
    CHECK(std::string(lua_tostring(L, -1)) == "boom 1000 7");
    lua_pop(L, 1);
    CHECK(g_dtors == 2);  // the probe and the shared_ptr's object

    // From Lua code through pcall, also when the error passes a C++ frame on its way out.
    lua_register(L, "raise_with_locals", raise_with_locals);
    lua_register(L, "call_with_locals", call_with_locals);
    g_dtors = 0;
    const char* code = R"LUA(
        local n = 0
        for i = 1, 200 do
            if not pcall(raise_with_locals) then n = n + 1 end
            if not pcall(call_with_locals, function() error("inner") end) then n = n + 1 end
            if not pcall(call_with_locals, raise_with_locals) then n = n + 1 end
        end
        return n
    )LUA";
    REQUIRE(luaL_loadstring(L, code) == LUA_OK);
    REQUIRE(lua_pcall(L, 0, 1, 0) == LUA_OK);
    CHECK(lua_tointeger(L, -1) == 600);
    CHECK(g_dtors == 200 * (2 + 1 + 3));
    lua_close(L);
}

TEST_CASE("Lua errors raised inside bindings: pcall catches them, the engine keeps working") {
    Fixture fx;
    fx.load(R"LUA(
hx.parser { name = "errs", parse = function(p)
    local bad = 0
    if not pcall(p.u8, p, "f", { flags = { [99] = "X" } }) then bad = bad + 1 end  -- opts.flags
    if not pcall(p.u32, p, "past_eof_" .. string.rep("x", 100)) then bad = bad + 1 end
    if not pcall(p.bytes, p, "huge", 1 << 40) then bad = bad + 1 end
    if not pcall(p.str, p, "long", 1 << 30) then bad = bad + 1 end
    if not pcall(p.field, p, "f", 0, 1 << 40) then bad = bad + 1 end
    if not pcall(p.u8, p, {}) then bad = bad + 1 end
    p:note("bad " .. bad)
    p:u8("ok")
end }
)LUA");
    std::string data;
    for (int i = 0; i < 64; ++i) data += char(i);
    data[0] = 1;
    data[1] = 2;
    fx.host.add(data.substr(0, 2));
    for (int round = 0; round < 3; ++round) {
        ParseResult r = fx.eng.parse(*fx.host.active, "errs");
        CHECK(r.error.empty());
        CHECK(find_field(r, "ok"));
        bool noted = false;
        for (const Field& f : r.fields) noted |= f.name.find("bad 6") != std::string::npos ||
                                                 f.value.find("bad 6") != std::string::npos ||
                                                 f.comment.find("bad 6") != std::string::npos;
        CHECK(noted);
    }

    fx.host.add(data);
    const char* code = R"LUA(
        local errs, n = {}, 0
        local function bad(f, ...)
            local ok, e = pcall(f, ...)
            if not ok then n = n + 1; errs[#errs + 1] = tostring(e) end
        end
        for i = 1, 100 do
            bad(doc.find, doc, "zz", 0, { hex = true })     -- not a hex pattern
            bad(doc.find, doc, "")                          -- empty pattern
            bad(doc.find, doc, "a", 0, 5)                   -- options not a table
            bad(doc.hash, doc, "no-such-hash")
            bad(doc.hash, doc, "sha256", -1)
            bad(hx.hash, "no-such-hash", "abc")
            bad(hx.disasm, "\x90\xC3", 0, "arm")
            bad(doc.disasm, doc, 0, 4, 16)
            bad(doc.disasm, doc, 0, 1 << 20)
            bad(hx.xor_scan, doc, "")
            bad(hx.xor_scan, doc, {})
            bad(hx.xor_scan, doc, "abc", { max_key_len = 99 })
            bad(hx.xor_guess_key, doc, 0, 4, { plain = "ab" })
            bad(hx.unhex, "zz")
            bad(doc.add_bookmark, doc, "x")
            bad(doc.symbols, 42)
        end
        return n .. " " .. #errs[1] .. " " .. #errs[16]
    )LUA";
    fx.eng.exec(code);
    const std::string res = fx.last_result();
    CHECK(res.rfind("\"1600 ", 0) == 0);
    CHECK(fx.errors() == 0);
    // Everything still works afterwards.
    fx.eng.exec("doc:find('\\5\\6\\7')");
    CHECK(fx.last_result() == "5");
    fx.eng.exec("doc:hash('crc32', 0, 4)");
    CHECK(fx.last_result().size() == 10);
    fx.eng.exec("#hx.disasm('\\x90\\xC3')");
    CHECK(fx.last_result() == "2");
    fx.eng.exec("#hx.xor_scan(doc, '\\5\\6\\7') > 0");
    CHECK(fx.last_result() == "true");
    // Unprotected errors go to the console with their message.
    fx.eng.exec("hx.disasm('\\x90', 0, 'arm')");
    CHECK(fx.console_has("mode must be 64 or 32", ConsoleLine::Error));
    fx.eng.exec("doc:hash('no-such-hash')");
    CHECK(fx.console_has("no-such-hash", ConsoleLine::Error));
    fx.eng.exec("1 + 1");
    CHECK(fx.last_result() == "2");
}

// ---- hx.hash_algorithm ----------------------------------------------------------------------------

namespace {

HashJob::Result run_hash_job(HashJob& job, std::shared_ptr<const Snapshot> snap, std::vector<std::string> algos,
                             std::vector<CustomHashAlgorithm> custom, uint64_t off = 0, uint64_t len = UINT64_MAX) {
    const uint64_t gen = job.generation();
    job.start(std::move(snap), off, len, std::move(algos), std::move(custom));
    const auto t0 = std::chrono::steady_clock::now();
    while (job.generation() == gen) {
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(60));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return job.result();
}

const char* const kHashScript = R"LUA(
hx.hash_algorithm{ name = "Sum-16", init = function() return 0 end,
  update = function(s, b) for i = 1, #b do s = s + b:byte(i) end return s & 0xFFFF end,
  final = function(s) return string.format("%04X", s) end }
-- state table changed in place (update returns nothing); final with 0x / odd length
hx.hash_algorithm{ name = "Count bytes", init = function() return { n = 0 } end,
  update = function(s, b) s.n = s.n + #b end,
  final = function(s) return string.format("0x%x", s.n) end }
hx.hash_algorithm{ name = "Broken final", init = function() return 0 end, update = function() end,
  final = function() return "not hex" end }
hx.hash_algorithm{ name = "Broken update", init = function() return 0 end,
  update = function(s, b) if #b > 3 then error("too much data") end return s end,
  final = function() return "00" end }
)LUA";

}  // namespace

TEST_CASE("hx.hash_algorithm: hx.hash, doc:hash, hx.hash_algorithms, errors") {
    Fixture fx;
    fx.load(kHashScript);
    REQUIRE(fx.errors() == 0);
    REQUIRE(fx.eng.hash_algorithms().size() == 4);
    CHECK(fx.eng.hash_algorithms()[0].name == "Sum-16");
    CHECK(fx.eng.hash_algorithms()[0].file.find("test.lua") != std::string::npos);
    std::string data(70000, '\0');
    for (size_t i = 0; i < data.size(); ++i) data[i] = char(i * 7 + 1);
    uint32_t sum = 0;
    for (unsigned char c : data) sum = (sum + c) & 0xFFFF;
    char want[16];
    std::snprintf(want, sizeof want, "\"%04x\"", unsigned(sum));
    fx.host.add(data);

    fx.eng.exec("hx.hash('sum16', doc:read(0, doc:size()))");  // case / punctuation ignored, lowercase result
    CHECK(fx.last_result() == want);
    fx.eng.exec("doc:hash('Sum-16')");
    CHECK(fx.last_result() == want);
    fx.eng.exec("doc:hash('Count bytes', 10, 5)");
    CHECK(fx.last_result() == "\"05\"");  // "0x5": odd length padded
    fx.eng.exec("local t = hx.hash_algorithms() return #t .. ' ' .. t[#t - 3] .. ' ' .. t[#t]");
    CHECK(fx.last_result() == "\"20 Sum-16 Broken update\"");
    CHECK(fx.errors() == 0);
    fx.eng.exec("doc:hash('Broken final')");
    CHECK(fx.console_has("final() must return the digest as a hex string", ConsoleLine::Error));
    fx.eng.exec("hx.hash('Broken update', 'abcd')");
    CHECK(fx.console_has("too much data", ConsoleLine::Error));
    fx.eng.exec("hx.hash('Broken update', 'abc')");
    CHECK(fx.last_result() == "\"00\"");

    // Registration errors; a later registration replaces the earlier one in place.
    const int before = fx.errors();
    fx.eng.exec("hx.hash_algorithm{ name = 'crc-32', init = print, update = print, final = print }");
    CHECK(fx.console_has("is a built-in algorithm", ConsoleLine::Error));
    fx.eng.exec("hx.hash_algorithm{ name = 'a,b', init = print, update = print, final = print }");
    CHECK(fx.console_has("must not contain ','", ConsoleLine::Error));
    fx.eng.exec("hx.hash_algorithm{ name = 'x', init = print, update = print }");
    CHECK(fx.console_has("'final' (function) is required", ConsoleLine::Error));
    CHECK(fx.errors() > before);
    const uint64_t g = fx.eng.hash_algorithms_generation();
    fx.eng.exec("hx.hash_algorithm{ name = 'SUM 16', init = function() return 1 end, update = function() end, "
                "final = function() return 'ab' end }");
    CHECK(fx.eng.hash_algorithms_generation() != g);
    CHECK(fx.eng.hash_algorithms().size() == 4);
    CHECK(fx.eng.hash_algorithms()[0].name == "SUM 16");
    CHECK(fx.eng.hash_algorithms()[0].file == "<console>");
    fx.eng.exec("hx.hash('Sum-16', 'xyz')");
    CHECK(fx.last_result() == "\"ab\"");
    // A reload forgets console definitions.
    fx.eng.reload();
    CHECK(fx.eng.hash_algorithms()[0].name == "Sum-16");
}

TEST_CASE("hx.hash_algorithm: HashJob runs script algorithms in Lua states of their own") {
    Fixture fx;
    fx.load(kHashScript);
    REQUIRE(fx.errors() == 0);
    std::string data((size_t(9) << 20) + 3, '\0');
    for (size_t i = 0; i < data.size(); ++i) data[i] = char((i * 131) >> 3);
    Document* d = fx.host.add(data);
    fx.eng.exec("doc:hash('Sum-16')");
    const std::string want = fx.last_result();
    fx.eng.exec("doc:hash('Count bytes', 1)");
    const std::string want_count = fx.last_result();
    fx.eng.exec("doc:hash('Sum-16', 1)");
    const std::string want_from1 = fx.last_result();

    std::vector<CustomHashAlgorithm> custom = fx.eng.custom_hashes();
    REQUIRE(custom.size() == 4);
    HashJob job;
    HashJob::Result r = run_hash_job(job, d->snapshot(), {"CRC-32"}, custom, 1);
    REQUIRE(r.values.size() == 5);
    CHECK(r.values[0].algo == "CRC-32");
    CHECK(r.values[1].algo == "Sum-16");
    CHECK("\"" + r.values[1].hex + "\"" == want_from1);
    CHECK("\"" + r.values[2].hex + "\"" == want_count);
    CHECK(r.values[3].hex.empty());
    CHECK(r.values[3].error.find("final() must return the digest") != std::string::npos);
    CHECK(r.values[4].hex.empty());
    CHECK(r.values[4].error.find("too much data") != std::string::npos);
    CHECK(r.values[4].error.find("test.lua") != std::string::npos);  // file:line of the script
    r = run_hash_job(job, d->snapshot(), {}, {custom[0]});
    REQUIRE(r.values.size() == 1);
    CHECK("\"" + r.values[0].hex + "\"" == want);

    // A console definition cannot be rebuilt on the worker: its value is an error.
    fx.eng.exec("hx.hash_algorithm{ name = 'Typed in', init = function() return 0 end, update = function() end, "
                "final = function() return '01' end }");
    custom = fx.eng.custom_hashes();
    REQUIRE(custom.size() == 5);
    r = run_hash_job(job, d->snapshot(), {}, {custom[4]});
    REQUIRE(r.values.size() == 1);
    CHECK(r.values[0].error.find("defined in the console") != std::string::npos);
    // A script that needs another script's global at load time does not load on its own.
    fx.dir.write("b.lua", "assert(hx_from_a) hx.hash_algorithm{ name = 'Needs A', init = function() return 0 end, "
                          "update = function() end, final = function() return '01' end }");
    fx.dir.write("a.lua", "hx_from_a = true");
    fx.eng.reload();
    REQUIRE(fx.errors() == 0);
    custom = fx.eng.custom_hashes();
    const CustomHashAlgorithm* needs = nullptr;
    for (const auto& c : custom)
        if (c.name == "Needs A") needs = &c;
    REQUIRE(needs);
    r = run_hash_job(job, d->snapshot(), {}, {*needs});
    REQUIRE(r.values.size() == 1);
    CHECK(r.values[0].error.find("does not load on its own") != std::string::npos);
}

TEST_CASE("hx.hash_algorithm: cancelling a slow Lua hash stops it inside update()") {
    Fixture fx;
    fx.load("hx.hash_algorithm{ name = 'Slow', init = function() return 0 end, "
            "update = function(s, b) while true do s = s + 1 end end, final = function() return '00' end }");
    REQUIRE(fx.errors() == 0);
    const std::string data(1000, 'x');
    Document* d = fx.host.add(data);
    HashJob job;
    const uint64_t gen = job.generation();
    job.start(d->snapshot(), 0, UINT64_MAX, {}, fx.eng.custom_hashes());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    CHECK(job.running());
    const auto t0 = std::chrono::steady_clock::now();
    job.cancel();
    while (job.generation() == gen) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(2));  // not the 10 s time limit
    CHECK(job.result().cancelled);
}

TEST_CASE("examples: Adler-32 (Lua) equals the built-in Adler-32") {
    Examples fx;
    REQUIRE(fx.errors() == 0);
    std::string data((size_t(5) << 20) + 999, '\0');
    std::mt19937 rng(3);
    for (char& c : data) c = char(rng());
    Document* d = fx.host.add(data);
    fx.eng.exec("hx.hash('Adler-32 (Lua)', '123456789') == hx.hash('adler32', '123456789') and "
                "hx.hash('Adler-32 (Lua)', '') == hx.hash('adler32', '')");
    CHECK(fx.last_result() == "true");
    fx.eng.exec("doc:hash('Adler-32 (Lua)', 100) == doc:hash('Adler-32', 100)");
    CHECK(fx.last_result() == "true");
    fx.eng.exec("hx.hash('Adler-32 (Lua)', '123456789')");
    CHECK(fx.last_result() == "\"091e01de\"");
    const CustomHashAlgorithm* adler = nullptr;
    const std::vector<CustomHashAlgorithm> custom = fx.eng.custom_hashes();
    for (const auto& c : custom)
        if (c.name == "Adler-32 (Lua)") adler = &c;
    REQUIRE(adler);
    HashJob job;
    const HashJob::Result r = run_hash_job(job, d->snapshot(), {"Adler-32"}, {*adler}, 7);
    REQUIRE(r.values.size() == 2);
    CHECK(r.values[1].error.empty());
    CHECK(r.values[0].hex == r.values[1].hex);
}

// ---- doc:apply_transform + multi-byte ADD keys --------------------------------------------------

TEST_CASE("doc:apply_transform: xor / add / sub / rol / ror, one undo step, range and errors") {
    Fixture fx;
    fx.load("");
    Document* d = fx.host.add("0123456789abcdef");
    fx.eng.exec("doc:apply_transform{ op = 'xor', key = 0x20, start = 10, length = 6 }");
    CHECK(bytes_of(*d) == "0123456789ABCDEF");
    CHECK(d->undo_stack().size() == 1);
    CHECK(d->undo_stack().back().label == "Encode XOR 0x20");
    // A multi-byte key follows the absolute convention: byte x gets key[x % #key].
    fx.eng.exec("doc:apply_transform{ op = 'add', key = '\\1\\2', start = 1, length = 3, label = 'Mine' }");
    CHECK(bytes_of(*d) == "0335456789ABCDEF");  // '1'+2, '2'+1, '3'+2
    CHECK(d->undo_stack().back().label == "Mine");
    fx.eng.exec("doc:apply_transform{ op = 'add_key', key = '\\1\\2', start = 1, length = 3, decode = true }");
    CHECK(bytes_of(*d) == "0123456789ABCDEF");
    CHECK(d->undo_stack().back().label == "Decode ADD key 01 02");
    // Without start / length: the selection. phase overrides the absolute convention.
    fx.eng.exec("doc:select(4, 6)");
    fx.eng.exec("doc:apply_transform{ op = 'sub', key = '\\1\\2', phase = 0 }");
    CHECK(bytes_of(*d) == "0123335577ABCDEF");
    fx.eng.exec("doc:apply_transform{ op = 'rol', key = 1, start = 0, length = 1 }");
    CHECK(uint8_t(bytes_of(*d)[0]) == uint8_t('0' << 1));
    fx.eng.exec("doc:apply_transform{ op = 'ror', key = 1, start = 0, length = 1 }");
    fx.eng.exec("doc:apply_transform{ op = 'rol', key = 1, start = 1, length = 1, decode = true }");  // = ror
    CHECK(uint8_t(bytes_of(*d)[0]) == uint8_t('0'));
    CHECK(uint8_t(bytes_of(*d)[1]) == uint8_t(0x98));  // '1' = 0x31 rotated right
    CHECK(fx.errors() == 0);
    const size_t steps = d->undo_stack().size();
    CHECK(steps == 7);
    // Inside a command the transform is part of the command's step, under its label.
    fx.load("hx.command{ name = 'twice', run = function(doc) "
            "doc:apply_transform{ op = 'xor', key = 'K', start = 0, length = 2 } "
            "doc:apply_transform{ op = 'xor', key = 'K', start = 0, length = 2 } end }");
    const std::string before = bytes_of(*d);
    fx.eng.run_command("twice");
    CHECK(fx.errors() == 0);
    CHECK(bytes_of(*d) == before);
    CHECK(d->undo_stack().size() == steps + 1);
    CHECK(d->undo_stack().back().label == "Script: twice");

    // Errors.
    fx.eng.exec("doc:select(0, 0)");
    const char* bad[][2] = {
        {"doc:apply_transform{ op = 'xor', key = 1 }", "nothing selected (pass start / length)"},
        {"doc:apply_transform{ op = 'nand', key = 1, start = 0 }", "op must be"},
        {"doc:apply_transform{ op = 'xor', start = 0 }", "key (a string of key bytes or a byte value) is required"},
        {"doc:apply_transform{ op = 'xor', key = '', start = 0 }", "key must be 1..4096 bytes"},
        {"doc:apply_transform{ op = 'add', key = 256, start = 0 }", "numeric key must be 0..255"},
        {"doc:apply_transform{ op = 'rol', key = 8, start = 0 }", "must be 1..7 bits"},
        {"doc:apply_transform{ op = 'rol', key = 'ab', start = 0 }", "bit count"},
        {"doc:apply_transform{ op = 'xor', key = 1, start = 100 }", "doc:apply_transform: nothing selected"},
        {"doc:apply_transform{ op = 'xor', key = 1, start = -1 }", "start must be >= 0"},
        {"doc:apply_transform{ op = 'xor', key = 1, start = 0, length = -5 }", "length must be >= 0"},
        {"doc:apply_transform{ op = 'xor', key = 'ab', start = 0, length = 2, phase = -1 }", "phase must be >= 0"},
    };
    for (const auto& b : bad) {
        INFO(b[0]);
        const int n = fx.errors();
        fx.eng.exec(b[0]);
        CHECK(fx.errors() > n);
        CHECK(fx.console_has(b[1], ConsoleLine::Error));
    }
    d->set_read_only(true);
    fx.eng.exec("doc:apply_transform{ op = 'xor', key = 1, start = 0 }");
    CHECK(fx.console_has("doc:apply_transform: the document is read-only", ConsoleLine::Error));
    CHECK(d->undo_stack().size() == steps + 1);
}

TEST_CASE("hx.xor_scan add_multi, hx.xor_guess_key op = add, decode a hit with doc:apply_transform") {
    Fixture fx;
    fx.load("");
    std::string data(300, '\x11');
    const std::string text = "This is a known plaintext", key = "K3y";
    for (size_t i = 0; i < text.size(); ++i) data[101 + i] = char(uint8_t(text[i]) + uint8_t(key[(101 + i) % 3]));
    Document* d = fx.host.add(data);
    fx.eng.exec("#hx.xor_scan(doc, 'This is a known', { xor = false, add = false, rol = false, multi = true })");
    CHECK(fx.last_result() == "0");
    fx.eng.exec("local h = hx.xor_scan(doc, 'This is a known', { xor = false, add = false, rol = false, "
                "add_multi = true }) return #h .. ' ' .. h[1].offset .. ' ' .. h[1].transform .. ' ' .. h[1].key .. "
                "' ' .. h[1].phase .. ' ' .. h[1].text");
    CHECK(fx.last_result() == R"("1 101 add_key K3y 2 ADD key 4B 33 79 \"K3y\"")");
    fx.eng.exec("local h = hx.xor_scan(doc, 'This is a known', { add_multi = true })[1] "
                "doc:apply_transform{ op = h.transform, key = h.key, start = h.offset, length = 25, decode = true }");
    CHECK(fx.errors() == 0);
    CHECK(bytes_of(*d).substr(101, text.size()) == text);
    CHECK(d->undo_stack().size() == 1);

    // Key guess: spaces ADDed with "ab" (with a carry, so the XOR guess is another key).
    std::string sp(256, ' ');
    for (size_t i = 0; i < sp.size(); ++i) sp[i] = char(' ' + (i % 2 ? 'b' : 'a'));
    fx.host.add(sp);
    fx.eng.exec("hx.xor_guess_key(doc, 1, 255, { plain = ' ', op = 'add' })[1].key");
    CHECK(fx.last_result() == "\"ab\"");
    fx.eng.exec("hx.xor_guess_key(doc, 1, 255, { plain = ' ' })[1].key == 'ab'");
    CHECK(fx.last_result() == "false");
    fx.eng.exec("hx.xor_guess_key(doc, 0, 4, { op = 'mul' })");
    CHECK(fx.console_has("op must be \"xor\" or \"add\"", ConsoleLine::Error));
}

TEST_CASE("doc:apply_transform decodes a ROL hit of hx.xor_scan with its key string (the bit count)") {
    Fixture fx;
    fx.load("");
    std::string data(64, '\0');
    const std::string text = "Rotated plaintext";
    for (size_t i = 0; i < text.size(); ++i) {
        const uint8_t c = uint8_t(text[i]);
        data[20 + i] = char(uint8_t((c << 3) | (c >> 5)));  // ROL 3
    }
    Document* d = fx.host.add(data);
    fx.eng.exec("local h = hx.xor_scan(doc, 'Rotated plain', { xor = false, add = false })[1] "
                "return h.transform .. ' ' .. #h.key .. ' ' .. h.key:byte()");
    CHECK(fx.last_result() == "\"rol 1 3\"");
    // The documented recipe: { op = h.transform, key = h.key, ... , decode = true }.
    fx.eng.exec("local h = hx.xor_scan(doc, 'Rotated plain', { xor = false, add = false })[1] "
                "doc:apply_transform{ op = h.transform, key = h.key, start = h.offset, length = 17, decode = true }");
    CHECK(fx.errors() == 0);
    CHECK(bytes_of(*d).substr(20, text.size()) == text);
    CHECK(d->undo_stack().size() == 1);
    // A longer string is still not a bit count.
    fx.eng.exec("doc:apply_transform{ op = 'ror', key = '\\3\\3', start = 0, length = 1 }");
    CHECK(fx.console_has("bit count", ConsoleLine::Error));
    CHECK(d->undo_stack().size() == 1);
}

TEST_CASE("doc:packets: index entries, filter, paging, not a capture, errors") {
    Fixture fx;
    fx.load("");
    std::vector<pcapfx::Bytes> f;
    f.push_back(pcapfx::udp_frame("10.0.0.5", 5353, "10.0.0.9", 53, pcapfx::str("ask"), 7));
    f.push_back(pcapfx::tcp_frame("10.0.0.1", 51000, "10.0.0.2", 80, 100, 0, pcapfx::SYN));
    f.push_back(pcapfx::tcp_frame("10.0.0.1", 51000, "10.0.0.2", 80, 101, 1, pcapfx::PSH | pcapfx::ACK,
                                  pcapfx::str("GET /")));
    f.push_back(pcapfx::arp_frame());
    for (int i = 0; i < 20; ++i) f.push_back(pcapfx::udp_frame("10.0.0.3", 4000, "10.0.0.4", 53, pcapfx::str("x")));
    const pcapfx::Bytes cap = pcapfx::pcapng_file(f);
    Document* d = fx.host.open_bytes("cap.pcapng", cap.data(), cap.size());
    PcapIndexResult ix;
    index_pcap(*d->snapshot(), ix);
    REQUIRE(ix.packets.size() == 24);
    auto run = [&](const std::string& lua) {
        fx.eng.exec(lua);
        return fx.last_result();
    };
    CHECK(run("local l, nx = doc:packets() return #l .. ' ' .. tostring(nx)") == "\"24 nil\"");
    // A UDP packet with a VLAN tag
    const Packet& p0 = ix.packets[0];
    CHECK(run("local p = doc:packets()[1] return p.number .. ' ' .. p.offset .. ' ' .. p.data .. ' ' .. p.length .. ' ' "
              ".. p.wire_length .. ' ' .. p.interface .. ' ' .. p.linktype") ==
          "\"1 " + std::to_string(p0.record_off) + " " + std::to_string(p0.data_off) + " " +
              std::to_string(p0.cap_len) + " " + std::to_string(p0.orig_len) + " 0 1\"");
    CHECK(run("local p = doc:packets()[1] return p.proto .. '|' .. p.src .. '|' .. p.dst .. '|' .. p.info") ==
          "\"UDP|10.0.0.5:5353|10.0.0.9:53|len=3 (VLAN 7)\"");
    CHECK(run("local p = doc:packets()[1] return p.vlan .. ' ' .. p.ip_version .. ' ' .. p.ip_proto .. ' ' .. "
              "p.src_port .. ' ' .. p.dst_port .. ' ' .. tostring(p.tcp_flags) .. ' ' .. tostring(p.fragment)") ==
          "\"7 4 17 5353 53 nil nil\"");
    CHECK(run("local p = doc:packets()[1] return doc:read(p.payload, p.payload_length)") == "\"ask\"");
    CHECK(run("local p = doc:packets()[1] return p.time_ns .. ' ' .. p.time") == "\"0 0.0\"");
    CHECK(run("return doc:packets()[1].summary") == "\"10.0.0.5:5353 -> 10.0.0.9:53  len=3 (VLAN 7)\"");
    // TCP fields
    CHECK(run("local p = doc:packets()[3] return p.tcp_seq .. ' ' .. p.tcp_ack .. ' ' .. p.tcp_flags .. ' ' .. "
              "doc:read(p.payload, p.payload_length)") == "\"101 1 24 GET /\"");
    CHECK(run("local p = doc:packets()[4] return p.proto .. ' ' .. tostring(p.ip_version) .. ' ' .. "
              "tostring(p.src_port) .. ' ' .. p.payload_length") == "\"ARP nil nil 28\"");
    // filter
    CHECK(run("local l = doc:packets{ filter = 'tcp' } return #l .. ' ' .. l[1].number .. ' ' .. l[2].number") ==
          "\"2 2 3\"");
    CHECK(run("local l = doc:packets{ filter = 'tcp.flags.syn or vlan == 7' } return #l .. ' ' .. l[1].number .. ' ' "
              ".. l[2].number") == "\"2 1 2\"");
    CHECK(run("return #doc:packets{ filter = 'udp.dstport == 53 and frame.number > 20' }") == "4");
    CHECK(run("return #doc:packets{ filter = '\"PSH\"' }") == "1");  // "text": Proto / Summary
    CHECK(run("return #doc:packets{ filter = 'icmp' }") == "0");
    // paging: first / max, the second result is where to continue
    CHECK(run("local l, nx = doc:packets{ max = 5 } return #l .. ' ' .. l[5].number .. ' ' .. nx") == "\"5 5 6\"");
    CHECK(run("local l, nx = doc:packets{ first = 6, max = 5 } return l[1].number .. ' ' .. nx") == "\"6 11\"");
    CHECK(run("local l, nx = doc:packets{ first = 20 } return #l .. ' ' .. tostring(nx)") == "\"5 nil\"");
    CHECK(run("local l, nx = doc:packets{ first = 24, max = 1 } return #l .. ' ' .. tostring(nx)") == "\"1 nil\"");
    CHECK(run("return #doc:packets{ first = 1000 }") == "0");
    CHECK(run("local l, nx = doc:packets{ filter = 'udp', max = 2 } return l[2].number .. ' ' .. nx") == "\"5 6\"");
    CHECK(run("local l, nx = doc:packets{ filter = 'udp', first = 6, max = 100 } return #l .. ' ' .. tostring(nx)") ==
          "\"19 nil\"");
    // errors
    fx.eng.exec("doc:packets{ filter = 'tcp.port ==' }");
    CHECK(fx.console_has("doc:packets: filter: expected a value after '==' (column 12)", ConsoleLine::Error));
    fx.eng.exec("doc:packets{ max = 0 }");
    CHECK(fx.console_has("max must be 1..1000000", ConsoleLine::Error));
    fx.eng.exec("doc:packets{ first = 0 }");
    CHECK(fx.console_has("first must be >= 1", ConsoleLine::Error));
    fx.eng.exec("doc:packets{ filter = 5 }");
    CHECK(fx.console_has("option 'filter' must be a string", ConsoleLine::Error));
    fx.eng.exec("doc:packets(3)");
    CHECK(fx.console_has("table expected", ConsoleLine::Error));
    // not a capture: nil + message
    fx.host.add("just some bytes, not a capture");
    CHECK(run("local l, e = doc:packets() return tostring(l) .. ' ' .. e") == "\"nil not a pcap / pcapng capture\"");
}

TEST_CASE("doc:packets: a capture bigger than one index chunk; a truncated last record") {
    Fixture fx;
    fx.load("");
    std::vector<pcapfx::Bytes> f;
    for (int i = 0; i < 70000; ++i)
        f.push_back(i % 7 ? pcapfx::arp_frame() : pcapfx::udp_frame("10.0.0.1", 1, "10.0.0.2", 2, pcapfx::str("u")));
    pcapfx::Bytes cap = pcapfx::pcap_file(f);
    cap.resize(cap.size() - 10);  // the last record is cut short: the packets before it count
    fx.host.open_bytes("big.pcap", cap.data(), cap.size());
    fx.eng.exec("local l, nx = doc:packets{ filter = 'frame.number >= 69990', max = 1000000 } "
                "return #l .. ' ' .. l[1].number .. ' ' .. tostring(nx)");
    CHECK(fx.last_result() == "\"10 69990 nil\"");
    fx.eng.exec("local l, nx = doc:packets{ filter = 'udp', max = 3, first = 65530 } return l[1].number .. ' ' .. "
                "l[3].number .. ' ' .. nx");
    CHECK(fx.last_result() == "\"65535 65549 65550\"");
}

TEST_CASE("examples: Capture commands (packets.lua)") {
    Examples fx;
    std::vector<pcapfx::Bytes> f;
    f.push_back(pcapfx::udp_frame("10.0.0.5", 5353, "10.0.0.9", 53, pcapfx::str("ask")));
    f.push_back(pcapfx::tcp_frame("10.0.0.1", 51000, "10.0.0.2", 80, 101, 1, pcapfx::PSH | pcapfx::ACK,
                                  pcapfx::str("GET /")));
    f.push_back(pcapfx::udp_frame("10.0.0.9", 53, "10.0.0.5", 5353, pcapfx::str("reply")));
    const pcapfx::Bytes cap = pcapfx::pcap_file(f);
    Document* d = fx.host.open_bytes("cap.pcap", cap.data(), cap.size());
    const int errors = fx.errors();
    fx.eng.run_command("Capture: Protocol Summary");
    CHECK(fx.errors() == errors);
    CHECK(fx.console_has("3 packets"));
    CHECK(fx.console_has("UDP        2"));
    fx.eng.run_command("Capture: Bookmark Matching Packets...");
    REQUIRE(fx.eng.pending_prompt());
    const std::string filter = "udp";
    fx.eng.answer_prompt(&filter);
    CHECK(fx.errors() == errors);
    REQUIRE(d->view().bookmarks.size() == 2);
    CHECK(d->view().bookmarks[0].name == "#1 UDP");
    CHECK(d->view().bookmarks[1].length == 5);
    CHECK(fx.console_has("2 bookmarks (2 packets matched)"));
    CHECK(d->undo());  // one step
    CHECK(d->view().bookmarks.empty());
    // A bad filter is a warning, not an error.
    fx.eng.run_command("Capture: Bookmark Matching Packets...");
    const std::string bad = "udp.port ==";
    fx.eng.answer_prompt(&bad);
    CHECK(fx.errors() == errors);
    CHECK(fx.console_has("doc:packets: filter: expected a value", ConsoleLine::Warn));
}
