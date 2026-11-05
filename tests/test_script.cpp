// Script engine tests: parser API, field editing, Doc API, REPL, hot reload, bundled examples.
#include <doctest/doctest.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "core/document.h"
#include "script/script_engine.h"

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
    void reveal(Document&, uint64_t, uint64_t) override { ++reveals; }

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
    CHECK(bytes_of(*d)[0] == char(0x31 ^ 0xFF));
    CHECK(bytes_of(*d)[8] == char(0x39 ^ 0xFF));
    d->undo();
    CHECK(bytes_of(*d) == "123456789");
    fx.eng.exec("hx_xor_key = 'ab'");
    fx.eng.run_command("Selection: XOR with key");
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
    CHECK(fld(r, "file[0].flags").value == "0b00000000_00001000");
    CHECK(fld(r, "file[0].flags").comment == "sizes in data descriptor");
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
    fx.eng.exec("hxp_record_text = 'kitchen'");
    d->view().cursor = d->view().anchor = 49;  // inside the last record of packet[1]: append at its end
    fx.eng.run_command("HXP: append TLV record at cursor");
    d->view().cursor = d->view().anchor = 0;
    fx.eng.run_command("HXP: append TLV record at cursor");
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
