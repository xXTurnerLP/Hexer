// Structure -> C header export (script/cexport.h), with a round trip through the C struct ->
// parser converter (core/cstruct.h); opts.flags / opts.bitfield in parsers; the Inspector's bit
// toggles (core/inspector.h).
#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "core/cstruct.h"
#include "core/document.h"
#include "core/inspector.h"
#include "script/cexport.h"
#include "script/script_engine.h"

using namespace hx;
namespace fs = std::filesystem;

namespace {

struct FakeHost : ScriptHost {
    std::vector<std::unique_ptr<Document>> docs;
    Document* active = nullptr;
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
    void reveal(Document&, uint64_t, uint64_t) override {}
};

struct TempDir {
    fs::path path;
    TempDir() {
        std::random_device rd;
        path = fs::temp_directory_path() / ("hexer_test_cexport_" + std::to_string(rd()) + std::to_string(rd()));
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
};

std::string bytes(std::initializer_list<int> b) {
    std::string s;
    for (int v : b) s += char(uint8_t(v));
    return s;
}

// A fresh engine with one script file; parses `data` with parser `name`.
struct Run {
    FakeHost host;
    ScriptEngine eng{&host};
    TempDir dir;
    std::string log;
    Document* doc = nullptr;

    ParseResult parse(const std::string& lua, const std::string& name, const std::string& data) {
        {
            std::ofstream out(dir.path / "gen.lua", std::ios::binary | std::ios::trunc);
            out << lua;
        }
        eng.set_script_dirs({dir.str()});
        eng.reload();
        int errors = 0;
        log.clear();
        for (const ConsoleLine& l : eng.console()) {
            log += l.text + "\n";
            if (l.kind == ConsoleLine::Error) ++errors;
        }
        INFO(log);
        INFO(lua);
        REQUIRE(errors == 0);
        doc = host.open_bytes("data.bin", reinterpret_cast<const uint8_t*>(data.data()), data.size());
        return eng.parse(*doc, name);
    }
};

std::string field_path(const ParseResult& r, int i) {
    const Field& f = r.fields[size_t(i)];
    return f.parent < 0 ? f.name : field_path(r, f.parent) + "." + f.name;
}

bool contains(const std::string& hay, const std::string& needle) { return hay.find(needle) != std::string::npos; }

size_t count(const std::string& hay, const std::string& needle) {
    size_t n = 0;
    for (size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1)) ++n;
    return n;
}

// "path @off+size = value" for every field, skipping the exporter's _padN members.
std::string tree(const ParseResult& r) {
    std::string s;
    for (size_t i = 0; i < r.fields.size(); ++i) {
        const Field& f = r.fields[i];
        if (f.name.rfind("_pad", 0) == 0) continue;
        s += field_path(r, int(i)) + " @" + std::to_string(f.offset) + "+" + std::to_string(f.size) + " = " +
             f.value + "\n";
    }
    return s;
}

// C -> parser -> parse -> C header -> parser -> parse: both trees must be the same.
void round_trip(const std::string& c, const std::string& data, const CStructOptions& opt, std::string* header_out = nullptr) {
    std::string lua1, lua2, err;
    REQUIRE_MESSAGE(cstruct_to_lua(c, opt, lua1, &err), err);
    Run a;
    const ParseResult r1 = a.parse(lua1, opt.name, data);
    REQUIRE_MESSAGE(r1.error.empty(), r1.error);
    const std::string header = fields_to_c_header(r1.fields, -1, opt.name);
    if (header_out) *header_out = header;
    INFO(header);
    CStructOptions opt2;  // the header carries packing and endianness itself
    opt2.name = "again";
    REQUIRE_MESSAGE(cstruct_to_lua(header, opt2, lua2, &err), err);
    Run b;
    const ParseResult r2 = b.parse(lua2, "again", data);
    REQUIRE_MESSAGE(r2.error.empty(), r2.error);
    CHECK(tree(r1) == tree(r2));
}

}  // namespace

TEST_CASE("cexport: flag names format and parse") {
    const std::vector<Field::FlagItem> fl = {{0, "READ"}, {1, "WRITE"}, {2, "EXEC"}, {15, "TOP"}};
    CHECK(format_flags(0, 2, fl) == "");
    CHECK(format_flags(5, 2, fl) == "READ|EXEC");
    CHECK(format_flags(0x8083, 2, fl) == "READ|WRITE|bit7|TOP");
    CHECK(format_flags(uint64_t(-1), 1, fl) == "READ|WRITE|EXEC|bit3|bit4|bit5|bit6|bit7");  // masked to 8 bits
    uint64_t v = 0;
    CHECK(parse_flags("READ|EXEC", fl, v));
    CHECK(v == 5);
    CHECK(parse_flags(" write | top ", fl, v));
    CHECK(v == 0x8002);
    CHECK(parse_flags("bit9|READ", fl, v));
    CHECK(v == 0x201);
    CHECK_FALSE(parse_flags("READ|NOPE", fl, v));
    CHECK_FALSE(parse_flags("", fl, v));
    CHECK_FALSE(parse_flags("READ||WRITE", fl, v));
    CHECK_FALSE(parse_flags("5", fl, v));
}

TEST_CASE("cexport: opts.flags shows set bit names; edits take names") {
    Run r;
    const char* lua = R"LUA(
        local PERM = { [0] = "READ", [1] = "WRITE", [2] = "EXEC" }
        hx.parser { name = "flags", parse = function(p)
            p:u8("perm", { flags = PERM })
            p:u16("mode", { flags = { READ = 0, WRITE = 1 }, fmt = "hex" })
            p:u8("none", { flags = PERM })
        end }
    )LUA";
    ParseResult res = r.parse(lua, "flags", bytes({0x85, 0x02, 0x00, 0x00}));
    REQUIRE(res.error.empty());
    REQUIRE(res.fields.size() == 3);
    CHECK(res.fields[0].value == "133 (0x85) = READ|EXEC|bit7");
    REQUIRE(res.fields[0].flags);
    CHECK(res.fields[0].flags->size() == 3);
    CHECK(res.fields[0].flags->at(2).name == "EXEC");
    CHECK(res.fields[1].value == "0x0002 = WRITE");
    CHECK(res.fields[2].value == "0");

    std::string err;
    CHECK(r.eng.edit_field(*r.doc, res.fields[0], "WRITE|EXEC", &err));
    uint8_t b = 0;
    r.doc->read(0, &b, 1);
    CHECK(b == 6);
    CHECK(r.eng.edit_field(*r.doc, res.fields[0], "7 = READ|WRITE|EXEC", &err));  // the display form
    r.doc->read(0, &b, 1);
    CHECK(b == 7);
    CHECK_FALSE(r.eng.edit_field(*r.doc, res.fields[0], "bit8", &err));
    CHECK(contains(err, "beyond"));
    CHECK_FALSE(r.eng.edit_field(*r.doc, res.fields[0], "READ|NOPE", &err));

    Run bad;
    ParseResult e = bad.parse(R"(hx.parser { name = "bad", parse = function(p) p:u8("x", { flags = { [64] = "X" } }) end })",
                              "bad", bytes({1}));
    CHECK(contains(e.error, "opts.flags"));
}

TEST_CASE("cexport: header layout - padding, dedupe, arrays, BE, flags, enums, overlaps") {
    Run r;
    const char* lua = R"LUA(
        local KIND = { [1] = "HELLO", [2] = "BYE" }
        local function point(p) p:i16le("x") p:i16le("y") end
        hx.parser { name = "demo file", parse = function(p)
            p:struct("Demo", function()
                p:u32be("magic", { fmt = "hex" })
                p:u8("kind", { enum = KIND })
                p:u8("ok", { enum = { [0] = "false", [1] = "true" } })
                p:skip(2)
                p:u16le("perm", { flags = { [0] = "READ", [3] = "EXEC" } })
                p:struct("a", point)
                p:struct("b", point)
                p:array("vals", 3, function() p:u16le("v") end)
                p:array("pts", 2, function() p:struct("pt", point) end)
                p:str("name", 4)
                p:bytes("blob", 3)
                p:array("mixed", 2, function(i) if i == 0 then p:u8("m") else p:u16le("m") end end)
                p:field("again", 0, 4, "magic again")
                p:u24le("u24")
                p:f32("ratio")
            end)
        end }
    )LUA";
    std::string data(4 + 1 + 1 + 2 + 2 + 4 + 4 + 6 + 8 + 4 + 3 + 3 + 3 + 4, '\0');
    ParseResult res = r.parse(lua, "demo file", data);
    REQUIRE_MESSAGE(res.error.empty(), res.error);
    const std::string h = fields_to_c_header(res.fields, -1, "demo file");
    INFO(h);
    CHECK(contains(h, "#pragma pack(push, 1)"));
    CHECK(contains(h, "#pragma pack(pop)"));
    CHECK(contains(h, "#include <stdbool.h>"));
    CHECK(contains(h, "typedef struct Demo {"));
    CHECK(contains(h, "static_assert(sizeof(Demo) == 49, \"Demo\");"));
    CHECK(contains(h, "uint32_t magic;"));
    CHECK(contains(h, "/* +0x0000, BE */"));
    CHECK(contains(h, "enum kind_e : uint8_t {"));
    CHECK(contains(h, "    HELLO = 1,"));
    CHECK(contains(h, "enum kind_e kind;"));
    CHECK(contains(h, "bool ok;"));
    CHECK(contains(h, "uint8_t _pad0[2];"));
    CHECK(contains(h, "uint16_t perm;"));
    CHECK(contains(h, "flags: READ = 0x1, EXEC = 0x8"));
    // a, b and the pts elements share one layout: one typedef, named after the first use
    CHECK(count(h, "typedef struct a_t {") == 1);
    CHECK(count(h, "typedef struct") == 2);
    CHECK(contains(h, "a_t a;"));
    CHECK(contains(h, "a_t b;"));
    CHECK(contains(h, "a_t pts[2];"));
    CHECK(contains(h, "static_assert(sizeof(a_t) == 4, \"a_t\");"));
    CHECK(h.find("typedef struct a_t") < h.find("typedef struct Demo"));  // dependencies first
    CHECK(contains(h, "uint16_t vals[3];"));
    CHECK(contains(h, "char name[4];"));
    CHECK(contains(h, "uint8_t blob[3];"));
    CHECK(contains(h, "uint8_t mixed[3];"));
    CHECK(contains(h, "array of 2 elements with different layouts"));
    CHECK(contains(h, "again (file offset 0x0, 4 bytes) overlaps an earlier member: not declared"));
    CHECK(contains(h, "uint8_t u24[3];"));
    CHECK(contains(h, "u24le"));
    CHECK(contains(h, "float ratio;"));
    CHECK(contains(h, "/* +0x002D */"));  // ratio: relative offset

    SUBCASE("a subtree: the selected struct only") {
        int a = -1;
        for (size_t i = 0; i < res.fields.size(); ++i)
            if (res.fields[i].name == "a") a = int(i);
        REQUIRE(a >= 0);
        const std::string hs = fields_to_c_header(res.fields, a, "a");
        INFO(hs);
        CHECK(contains(hs, "typedef struct a {"));
        CHECK(contains(hs, "int16_t x;"));
        CHECK_FALSE(contains(hs, "Demo"));
    }
}

TEST_CASE("cexport: enum constants outside the field's type are left out (the header compiles)") {
    // Regression: one enum table shared by fields of different sizes (or negative names on an
    // unsigned field) gave `enum x_e : uint8_t { BIG = 300 }`, which no C / C++ compiler accepts;
    // a uint64 constant >= 2^63 was written as a negative number.
    Run r;
    const char* lua = R"LUA(
        local E = { [-1] = "NEG", [1] = "ONE", [300] = "BIG" }
        hx.parser { name = "e", parse = function(p)
            p:u8("small", { enum = E })
            p:i16le("wide", { enum = E })
            p:u64le("all", { enum = { [-1] = "ALL", [2] = "TWO" } })
        end }
    )LUA";
    ParseResult res = r.parse(lua, "e", std::string(11, '\x01'));
    REQUIRE_MESSAGE(res.error.empty(), res.error);
    const std::string h = fields_to_c_header(res.fields, -1, "e");
    INFO(h);
    CHECK(contains(h, "    ONE = 1,\n    /* BIG = 300 does not fit uint8_t */\n};"));
    CHECK(contains(h, "NEG = -1 does not fit uint8_t"));
    CHECK(contains(h, "BIG = 300 does not fit uint8_t"));
    CHECK(contains(h, "enum wide_e : int16_t {\n    NEG = -1,\n    wide_e_ONE = 1,\n    BIG = 300,\n};"));
    CHECK(contains(h, "    ALL = 0xFFFFFFFFFFFFFFFF,"));
    CHECK(contains(h, "    TWO = 2,"));
}

TEST_CASE("cexport: several roots are wrapped; a mostly big-endian struct gets // @be") {
    Run r;
    ParseResult res = r.parse(R"(hx.parser { name = "two", parse = function(p)
        p:u16be("len") p:u32be("crc") p:u8("tag") end })",
                              "two", bytes({0, 1, 0, 0, 0, 2, 3}));
    REQUIRE(res.error.empty());
    const std::string h = fields_to_c_header(res.fields, -1, "two roots");
    INFO(h);
    CHECK(contains(h, "// @be\ntypedef struct two_roots {"));
    CHECK(contains(h, "static_assert(sizeof(two_roots) == 7"));
    CHECK(fields_to_c_header({}, -1, "x").empty());
}

TEST_CASE("cexport: round trip C -> parser -> C header -> parser keeps the tree") {
    SUBCASE("scalars, nested structs (deduped), arrays, strings, enums, bool, natural alignment") {
        const char* c = R"C(
            enum Kind : uint16_t { K_NONE = 0, K_ONE = 1, K_TWO = 2 };
            struct Point { int16_t x; int16_t y; };
            struct Rec {
                uint8_t tag;
                uint32_t id;          // 3 bytes of natural-alignment padding before it
                struct Point a;
                struct Point b;
                struct Point path[3];
                uint16_t grid[2][3];
                char name[6];
                char names[2][3];
                uint8_t raw[4];
                enum Kind kind;
                bool on;
                int64_t big;
                double d;
                float f;
                int8_t s8;
            };
        )C";
        std::string data;
        for (int i = 0; i < 128; ++i) data += char(uint8_t(i * 37 + 11));
        data[74] = 2;  // kind = K_TWO (after natural-alignment padding)
        data[75] = 0;
        CStructOptions o;
        o.name = "rec";
        o.pack = 0;
        std::string h;
        round_trip(c, data, o, &h);
        CHECK(contains(h, "uint8_t _pad0[3];"));
        CHECK(contains(h, "uint16_t grid[2][3];"));
        CHECK(contains(h, "char names[2][3];"));
        CHECK(contains(h, "a_t path[3];"));
        CHECK(contains(h, "enum kind_e : uint16_t"));
    }
    SUBCASE("big-endian structs") {
        const char* c = R"C(
            // @be
            struct Hdr { uint32_t magic; uint16_t len; int32_t delta; };
            struct File { struct Hdr h; uint16_t le_word; uint8_t body[4]; };
        )C";
        CStructOptions o;
        o.name = "file";
        std::string h;
        round_trip(c, bytes({0xDE, 0xAD, 0xBE, 0xEF, 0, 9, 0xFF, 0xFF, 0xFF, 0xFE, 0x34, 0x12, 1, 2, 3, 4}), o, &h);
        CHECK(contains(h, "// @be\ntypedef struct h_t {"));
        CHECK(contains(h, "/* +0x0000, BE */"));
    }
    SUBCASE("bit fields: little- and big-endian units, unnamed bits, adjacent units") {
        const char* c = R"C(
            struct Ip {
                uint8_t ihl : 4;
                uint8_t version : 4;
                uint16_t flags : 3;
                uint16_t : 2;
                uint16_t frag : 11;
                uint8_t lo : 3;
                uint8_t : 0;
                uint8_t hi : 2;
                uint32_t big;
            };
            // @be
            struct Be { uint8_t version : 4; uint8_t ihl : 4; uint16_t a : 4; uint16_t b : 12; };
            struct Both { struct Ip ip; struct Be be; };
        )C";
        CStructOptions o;
        o.name = "bits";
        std::string h;
        round_trip(c, bytes({0x45, 0x1D, 0x09, 0x05, 0x02, 7, 0, 0, 0, 0x45, 0x12, 0x34}), o, &h);
        CHECK(contains(h, "uint8_t ihl : 4;"));
        CHECK(contains(h, "uint16_t : 2;"));
        CHECK(contains(h, "uint8_t : 5;"));  // lo's unit is declared full instead of `: 0`
        CHECK_FALSE(contains(h, " : 0;"));
        CHECK(contains(h, "// @be\ntypedef struct be_t {"));
    }
    SUBCASE("bit-field units are declared full (GCC / Clang lay out pack(1) bits like MSVC)") {
        // Regression: a partly used multi-byte unit was declared with its used bits only, and a
        // `: 0` closed it; GCC / Clang then packed the bits (sizeof 2 instead of 5 for A) or
        // aligned the `: 0` to 4 bytes, failing the header's own static_assert.
        const char* c = R"C(
            struct A { uint8_t x; uint32_t a : 4; uint32_t : 0; uint32_t b : 4; uint8_t z; };
            // @be
            struct B { uint16_t a : 4; uint32_t b : 3; uint8_t z; };
            struct Both { struct A a; struct B b; uint64_t d : 9; };
        )C";
        CStructOptions o;
        o.name = "full";
        std::string data;
        for (int i = 0; i < 32; ++i) data += char(uint8_t(i * 29 + 3));
        std::string h;
        round_trip(c, data, o, &h);
        CHECK(contains(h, "uint32_t a : 4;"));
        CHECK(count(h, "uint32_t : 28;") == 2);  // a and b of A, each in its own full unit
        CHECK(contains(h, "uint16_t : 12;"));       // B.a (BE): the low 12 bits
        CHECK(contains(h, "uint32_t : 29;"));       // B.b (BE): the low 29 bits
        CHECK(contains(h, "uint64_t : 55;"));
        CHECK_FALSE(contains(h, " : 0;"));
    }
}

TEST_CASE("cexport: #define masks for flags, fmt = char as char, mixed byte order annotated") {
    Run r;
    const char* lua = R"LUA(
        local PERM = { [0] = "READ", [3] = "EXEC", [20] = "TOO_WIDE" }
        hx.parser { name = "mix", parse = function(p)
            p:struct("Mix", function()
                p:u32be("magic", { fmt = "hex" })
                p:u16le("len")
                p:i16be("delta")
                p:u32le("x")
                p:u16le("perm", { flags = PERM })
                p:u8("c", { fmt = "char" })
                p:u32le("tag", { fmt = "char" })
                p:f32be("ratio")
                p:struct("in", function() p:u8("PERM_READ") p:u16le("y") p:u16le("z") end)
            end)
        end }
    )LUA";
    ParseResult res = r.parse(lua, "mix", std::string(4 + 2 + 2 + 4 + 2 + 1 + 4 + 4 + 5, '\x41'));
    REQUIRE_MESSAGE(res.error.empty(), res.error);
    const std::string h = fields_to_c_header(res.fields, -1, "mix");
    INFO(h);
    // Flags: one mask per named bit that fits, before the struct; names unique in the header.
    // PERM_READ is a member's name (in_t): that mask gets a suffix.
    CHECK(contains(h, "// Mix.perm flags\n#define PERM_READ_2 0x1\n#define PERM_EXEC 0x8\n\n"));
    CHECK_FALSE(contains(h, "TOO_WIDE 0x"));
    CHECK(h.find("#define PERM_EXEC") < h.find("typedef struct Mix"));
    CHECK(contains(h, "flags: READ = 0x1, EXEC = 0x8"));
    // fmt = "char": a 1-byte one is a char, wider ones stay integers.
    CHECK(contains(h, "    char c;"));
    CHECK(contains(h, "uint32_t tag;"));
    CHECK(contains(h, "chars"));
    // 7 LE numbers vs 3 BE: the struct is @le, the BE members are annotated one by one.
    CHECK(contains(h, "// @le\ntypedef struct Mix {"));
    CHECK(contains(h, "    /* @be */ uint32_t magic;"));
    CHECK(contains(h, "    /* @be */ int16_t delta;"));
    CHECK(contains(h, "    /* @be */ float ratio;"));
    CHECK(contains(h, "    uint16_t len;"));
    CHECK(contains(h, "Mixed byte order"));
    // ... and C struct -> parser reads them back with the same byte orders.
    std::string lua2, err;
    CStructOptions o;
    o.name = "again";
    REQUIRE_MESSAGE(cstruct_to_lua(h, o, lua2, &err), err);
    CHECK(contains(lua2, "p:u32be(\"magic\""));
    CHECK(contains(lua2, "p:i16be(\"delta\""));
    CHECK(contains(lua2, "p:f32be(\"ratio\""));
    CHECK(contains(lua2, "p:u16le(\"len\""));
    CHECK(contains(lua2, "p:u8(\"c\", { fmt = \"char\" })"));
    Run b;
    const ParseResult r2 = b.parse(lua2, "again", std::string(4 + 2 + 2 + 4 + 2 + 1 + 4 + 4 + 5, '\x41'));
    REQUIRE_MESSAGE(r2.error.empty(), r2.error);
    auto leaves = [](const ParseResult& pr) {  // "name @offset type" of every leaf
        std::string out;
        for (const Field& f : pr.fields)
            if (f.children.empty()) out += f.name + " @" + std::to_string(f.offset) + " " + f.type + "\n";
        return out;
    };
    CHECK(leaves(r2) == leaves(res));  // the same byte orders (u32be / u16le ...) at the same offsets
    // No mixed struct: no per-member annotations.
    Run s;
    ParseResult plain = s.parse(R"(hx.parser { name = "le", parse = function(p) p:u16le("a") p:u8("b") end })", "le",
                                std::string(3, '\0'));
    REQUIRE(plain.error.empty());
    const std::string hp = fields_to_c_header(plain.fields, -1, "le");
    CHECK_FALSE(contains(hp, "@be"));
    CHECK_FALSE(contains(hp, "@le"));
    CHECK_FALSE(contains(hp, "Mixed byte order"));
}

TEST_CASE("cexport: mixed byte order round trip C -> parser -> C header -> parser") {
    const char* c = R"C(
        enum Kind : uint16_t { K_A = 1, K_B = 0x100 };
        // @be
        struct Net {
            uint32_t magic;
            uint16_t len;
            /* @le */ uint32_t host_order;
            /* @le */ enum Kind kind;
            /* @le */ uint16_t lo : 4;
            /* @le */ uint16_t hi : 12;
            int16_t delta;
            char c;
            uint32_t after; // @le: a trailing comment does not change the next member
            uint32_t next;
        };
    )C";
    CStructOptions o;
    o.name = "net";
    std::string lua, err;
    REQUIRE_MESSAGE(cstruct_to_lua(c, o, lua, &err), err);
    INFO(lua);
    CHECK(contains(lua, "p:u32le(\"host_order\""));
    CHECK(contains(lua, "p:u16le(\"kind\""));
    CHECK(contains(lua, "p:u32be(\"after\""));
    CHECK(contains(lua, "p:u32be(\"next\""));
    CHECK(contains(lua, "p:peek(\"<I2\")"));  // the bit-field unit is little-endian
    std::string data;
    for (int i = 0; i < 40; ++i) data += char(uint8_t(i * 13 + 5));
    std::string h;
    round_trip(c, data, o, &h);
    INFO(h);
    CHECK(contains(h, "// @be\ntypedef struct Net {"));
    CHECK(contains(h, "    /* @le */ uint32_t host_order;"));
    CHECK(contains(h, "    /* @le */ enum kind_e kind;"));
    CHECK(contains(h, "    /* @le */ uint16_t lo : 4;"));
    CHECK(contains(h, "    char c;"));
    CHECK(contains(h, "    uint32_t next;"));
}

TEST_CASE("inspector: bit locations and undoable bit toggles") {
    int bi = -1;
    uint8_t m = 0;
    CHECK(insp_bit_location(1, false, 7, bi, m));
    CHECK((bi == 0 && m == 0x80));
    CHECK(insp_bit_location(4, false, 9, bi, m));
    CHECK((bi == 1 && m == 0x02));
    CHECK(insp_bit_location(4, true, 9, bi, m));
    CHECK((bi == 2 && m == 0x02));
    CHECK(insp_bit_location(8, true, 63, bi, m));
    CHECK((bi == 0 && m == 0x80));
    CHECK_FALSE(insp_bit_location(2, false, 16, bi, m));
    CHECK_FALSE(insp_bit_location(9, false, 0, bi, m));

    const uint8_t init[] = {0x00, 0x10, 0x00, 0xFF};
    auto d = Document::create_from_bytes("bits.bin", init, sizeof init);
    std::string err;
    REQUIRE(inspector_toggle_bit(*d, 0, 2, false, 12, &err));  // LE: bit 12 lives in byte 1
    uint8_t b[4] = {};
    d->read(0, b, 4);
    CHECK(b[1] == 0x00);
    REQUIRE(inspector_toggle_bit(*d, 0, 2, true, 0, &err));    // BE: bit 0 lives in byte 1
    d->read(0, b, 4);
    CHECK(b[1] == 0x01);
    REQUIRE(d->undo_stack().size() == 2);
    CHECK(d->undo_stack().back().label == "Toggle bit 0");
    CHECK(d->undo());
    CHECK(d->undo());
    d->read(0, b, 4);
    CHECK(b[1] == 0x10);
    CHECK_FALSE(inspector_toggle_bit(*d, 2, 4, false, 0, &err));  // only 2 bytes left
    CHECK(contains(err, "not enough"));
    d->set_read_only(true);
    CHECK_FALSE(inspector_toggle_bit(*d, 0, 1, false, 0, &err));
    CHECK(contains(err, "read-only"));
}

