// C struct -> Lua parser: generate Lua for C definitions and RUN it through the script engine on
// crafted buffers (field names, offsets, sizes, values), plus error messages for bad input.
#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "core/cstruct.h"
#include "core/document.h"
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
        path = fs::temp_directory_path() / ("hexer_test_cstruct_" + std::to_string(rd()) + std::to_string(rd()));
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

const Field& fld(const ParseResult& r, const std::string& path) {
    static Field missing;
    if (const Field* f = find_field(r, path)) return *f;
    missing = Field{};
    missing.value = missing.comment = "<missing " + path + ">";
    missing.offset = missing.size = 0xDEAD;
    return missing;
}

std::string dump(const ParseResult& r) {
    std::string s;
    for (size_t i = 0; i < r.fields.size(); ++i) {
        const Field& f = r.fields[i];
        s += field_path(r, int(i)) + " @" + std::to_string(f.offset) + "+" + std::to_string(f.size) + " = " + f.value +
             (f.comment.empty() ? "" : "  // " + f.comment) + "\n";
    }
    return s;
}

std::string bytes(std::initializer_list<int> b) {
    std::string s;
    for (int v : b) s += char(uint8_t(v));
    return s;
}

// Generates the parser, loads it into a fresh engine and parses `data`.
struct Gen {
    FakeHost host;
    ScriptEngine eng{&host};
    TempDir dir;
    std::string lua, err, log;
    CStructInfo info;

    bool generate(const std::string& c, const CStructOptions& opt = {}) {
        return cstruct_to_lua(c, opt, lua, &err, &info);
    }

    ParseResult run(const std::string& c, const std::string& data, CStructOptions opt = {}, uint64_t base = 0,
                    uint64_t len = UINT64_MAX) {
        bool ok = generate(c, opt);
        INFO(err);
        REQUIRE(ok);
        {
            std::ofstream out(dir.path / "gen.lua", std::ios::binary | std::ios::trunc);
            out << lua;
        }
        eng.set_script_dirs({dir.str()});
        eng.reload();
        log.clear();
        int errors = 0;
        for (const ConsoleLine& l : eng.console()) {
            log += l.text + "\n";
            if (l.kind == ConsoleLine::Error) ++errors;
        }
        INFO(log);
        INFO(lua);
        REQUIRE(errors == 0);
        Document* d = host.open_bytes("data.bin", reinterpret_cast<const uint8_t*>(data.data()), data.size());
        return eng.parse(*d, opt.name, base, len);
    }
};

std::string gen_error(const std::string& c, const CStructOptions& opt = {}) {
    std::string lua, err;
    bool ok = cstruct_to_lua(c, opt, lua, &err);
    CHECK_FALSE(ok);
    CHECK(lua.empty());
    return err;
}

}  // namespace

TEST_CASE("cstruct: scalars, char arrays, byte arrays (packed, little-endian)") {
    Gen g;
    const char* c = R"C(
        // A simple header.
        struct Header {
            uint32_t magic;      /* 'HXR1' */
            uint16_t version;
            int8_t   delta;
            char     name[6];
            uint8_t  key[4];
            float    scale;
            double   ratio;
            bool     enabled;
            char     tag;
            int64_t  big;
        };
    )C";
    std::string data = bytes({0x31, 0x52, 0x58, 0x48, 0x02, 0x01, 0xFE}) + std::string("abc\0\0\0", 6) +
                       bytes({0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x80, 0x3F}) +
                       bytes({0, 0, 0, 0, 0, 0, 0xF8, 0x3F, 1, 'Z'}) + bytes({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    ParseResult r = g.run(c, data);
    INFO(g.lua);
    INFO(dump(r));
    CHECK(r.error.empty());
    CHECK(fld(r, "Header").size == data.size());
    CHECK(fld(r, "Header.magic").value == "1213747761 (0x48585231)");
    CHECK(fld(r, "Header.version").value == "258 (0x102)");
    CHECK(fld(r, "Header.version").offset == 4);
    CHECK(fld(r, "Header.delta").value == "-2 (0xFE)");
    CHECK(fld(r, "Header.name").type == "str");
    CHECK(fld(r, "Header.name").size == 6);
    CHECK(fld(r, "Header.name").value.rfind("\"abc", 0) == 0);
    CHECK(fld(r, "Header.key").type == "bytes");
    CHECK(fld(r, "Header.key").value == "DE AD BE EF");
    CHECK(fld(r, "Header.scale").value == "1");
    CHECK(fld(r, "Header.ratio").value == "1.5");
    CHECK(fld(r, "Header.enabled").value == "1 = true");
    CHECK(fld(r, "Header.tag").value.find("'Z'") != std::string::npos);
    CHECK(fld(r, "Header.big").value.rfind("-1", 0) == 0);
    CHECK(fld(r, "Header.big").offset == 31);
    CHECK(g.info.structs.size() == 1);
    CHECK(g.info.structs[0].name == "Header");
    CHECK(g.info.structs[0].size == 39);
    CHECK(g.info.root == "Header");
    // Readable output: one reader per line, explicit endianness, a struct function, the registration.
    CHECK(g.lua.find("local function parse_Header(p)") != std::string::npos);
    CHECK(g.lua.find("    p:u16le(\"version\")") != std::string::npos);
    CHECK(g.lua.find("p:str(\"name\", 6)") != std::string::npos);
    CHECK(g.lua.find("hx.parser {") != std::string::npos);
    CHECK(g.lua.find("detect =") == std::string::npos);
}

TEST_CASE("cstruct: multi-word C types and Windows names") {
    Gen g;
    ParseResult r = g.run(R"C(
        typedef struct {
            unsigned char a; signed char b; short c; unsigned short d; int e; unsigned f;
            long g; unsigned long long h; long long int i; BYTE j; WORD k; DWORD l; QWORD m;
            u8 n; s16 o; i32 q; _Bool t;
        } T;
    )C", std::string(64, '\x01'));
    INFO(g.lua);
    CHECK(g.info.structs.size() == 1);
    CHECK(g.info.structs[0].name == "T");
    CHECK(g.info.structs[0].size == 1 + 1 + 2 + 2 + 4 + 4 + 4 + 8 + 8 + 1 + 2 + 4 + 8 + 1 + 2 + 4 + 1);
    CHECK(fld(r, "T.c").type == "i16le");
    CHECK(fld(r, "T.h").type == "u64le");
    CHECK(fld(r, "T.i").offset == 26);
    CHECK(fld(r, "T.m").size == 8);
    CHECK(fld(r, "T.t").value == "1 = true");
}

TEST_CASE("cstruct: packing - natural alignment, #pragma pack, __attribute__((packed))") {
    const char* c = R"C(
        struct S { uint8_t a; uint32_t b; uint16_t c; };
    )C";
    std::string data = bytes({1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0});
    SUBCASE("natural") {
        Gen g;
        CStructOptions o;
        o.pack = 0;
        ParseResult r = g.run(c, data, o);
        INFO(g.lua);
        CHECK(r.error.empty());
        CHECK(fld(r, "S.b").offset == 4);
        CHECK(fld(r, "S.b").value == "2");
        CHECK(fld(r, "S.c").offset == 8);
        CHECK(fld(r, "S").size == 12);  // tail padding included
        CHECK(g.info.structs[0].size == 12);
        CHECK(g.lua.find("p:skip(3)  -- padding") != std::string::npos);
    }
    SUBCASE("packed default") {
        Gen g;
        ParseResult r = g.run(c, data);
        CHECK(fld(r, "S.b").offset == 1);
        CHECK(fld(r, "S.c").offset == 5);
        CHECK(g.info.structs[0].size == 7);
    }
    SUBCASE("pragma pack overrides the natural default") {
        Gen g;
        CStructOptions o;
        o.pack = 0;
        g.generate(R"C(
            #pragma pack(push, 1)
            struct P { uint8_t a; uint32_t b; };
            #pragma pack(pop)
            struct N { uint8_t a; uint32_t b; };
            #pragma pack(2)
            struct Two { uint8_t a; uint32_t b; };
            #pragma pack()
            struct Back { uint8_t a; uint64_t b; };
            struct __attribute__((packed)) A1 { uint8_t a; uint32_t b; };
            struct A2 { uint8_t a; uint32_t b; } __attribute__((__packed__));
            typedef struct { uint8_t a; uint16_t b; } __attribute__((packed)) A3;
        )C", o);
        INFO(g.err);
        REQUIRE(g.info.structs.size() == 7);
        CHECK(g.info.structs[0].size == 5);
        CHECK(g.info.structs[1].size == 8);
        CHECK(g.info.structs[2].size == 6);
        CHECK(g.info.structs[3].size == 16);
        CHECK(g.info.structs[4].size == 5);
        CHECK(g.info.structs[5].size == 5);
        CHECK(g.info.structs[6].name == "A3");
        CHECK(g.info.structs[6].size == 3);
    }
    SUBCASE("nested struct alignment and arrays") {
        Gen g;
        CStructOptions o;
        o.pack = 0;
        g.generate(R"C(
            struct In { uint8_t x; uint16_t y; };          // 4, align 2
            struct Out { uint8_t a; struct In in; uint8_t b; uint64_t c; uint8_t d[3]; };
        )C", o);
        INFO(g.err);
        REQUIRE(g.info.structs.size() == 2);
        CHECK(g.info.structs[0].size == 4);
        CHECK(g.info.structs[1].size == 1 + 1 + 4 + 1 + 1 + 8 + 3 + 5);  // 24
    }
}

TEST_CASE("cstruct: endianness - option, per-struct annotation, __be32") {
    const char* c = R"C(
        // @be
        struct Net { uint16_t port; uint32_t addr; };
        struct Host { uint16_t port; struct Net net; __be32 tagged; };
    )C";
    std::string data = bytes({0x01, 0x02, 0x01, 0x02, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05});
    Gen g;
    ParseResult r = g.run(c, data);
    INFO(g.lua);
    INFO(dump(r));
    CHECK(r.error.empty());
    CHECK(fld(r, "Host.port").value == "513 (0x201)");
    CHECK(fld(r, "Host.net.port").value == "258 (0x102)");
    CHECK(fld(r, "Host.net.addr").value == "167772161 (0xA000001)");
    CHECK(fld(r, "Host.tagged").value == "5");

    SUBCASE("big-endian default, @le annotation right after the brace") {
        Gen g2;
        CStructOptions o;
        o.big_endian = true;
        ParseResult r2 = g2.run(R"C(
            struct A { uint16_t x; };
            struct B { // @le
                uint16_t y; struct A a; struct { uint16_t z; } inner; };
        )C", bytes({0x01, 0x02, 0x01, 0x02, 0x01, 0x02}), o);
        INFO(g2.lua);
        CHECK(fld(r2, "B.y").value == "513 (0x201)");
        CHECK(fld(r2, "B.a.x").value == "258 (0x102)");      // A keeps its own (default) endianness
        CHECK(fld(r2, "B.inner.z").value == "513 (0x201)");  // unnamed nested struct inherits B's
    }
}

TEST_CASE("cstruct: nesting - named, inline, anonymous structs and unions") {
    Gen g;
    const char* c = R"C(
        typedef struct Point { int16_t x, y; } Point;
        union Value { uint32_t u; float f; uint8_t raw[2]; };
        struct Shape {
            uint8_t kind;
            Point origin;
            struct { uint8_t w; uint8_t h; } size;
            struct { uint8_t r, g, b; };        // anonymous: flattened
            union { uint16_t word; uint8_t lo; }; // anonymous union
            union Value v;
            Point pts[2];
        };
    )C";
    std::string data = bytes({7, 1, 0, 0xFF, 0xFF, 3, 4, 10, 20, 30, 0x34, 0x12, 0, 0, 0x80, 0x3F, 1, 0, 2, 0, 3, 0, 4, 0});
    ParseResult r = g.run(c, data);
    INFO(g.lua);
    INFO(dump(r));
    CHECK(r.error.empty());
    CHECK(fld(r, "Shape.origin.x").value == "1");
    CHECK(fld(r, "Shape.origin.y").value == "-1 (0xFFFF)");
    CHECK(fld(r, "Shape.origin").size == 4);
    CHECK(fld(r, "Shape.size.h").value == "4");
    CHECK(fld(r, "Shape.size.h").offset == 6);
    CHECK(fld(r, "Shape.g").value == "20 (0x14)");
    CHECK(fld(r, "Shape.word").value == "4660 (0x1234)");
    CHECK(fld(r, "Shape.word").offset == 10);
    CHECK(fld(r, "Shape.lo").offset == 10);
    CHECK(fld(r, "Shape.lo").value == "52 (0x34)");
    CHECK(fld(r, "Shape.v").offset == 12);
    CHECK(fld(r, "Shape.v").size == 4);
    CHECK(fld(r, "Shape.v.u").value == "1065353216 (0x3F800000)");
    CHECK(fld(r, "Shape.v.f").value == "1");
    CHECK(fld(r, "Shape.v.raw").offset == 12);
    CHECK(fld(r, "Shape.pts[1].y").value == "4");
    CHECK(fld(r, "Shape.pts[1].y").offset == 22);
    CHECK(fld(r, "Shape").size == 24);
    REQUIRE(g.info.structs.size() == 3);
    CHECK(g.info.structs[0].name == "Point");
    CHECK(g.info.structs[1].name == "Value");
    CHECK(g.info.structs[1].size == 4);
    CHECK(g.info.root == "Shape");

    SUBCASE("root option") {
        Gen g2;
        CStructOptions o;
        o.root = "Point";
        ParseResult r2 = g2.run(c, data, o);
        CHECK(fld(r2, "Point.x").value == "263 (0x107)");
        CHECK(fld(r2, "Point.y").value == "-256 (0xFF00)");
        CHECK_FALSE(find_field(r2, "Shape"));
        o.root = "Nope";
        CHECK(gen_error(c, o) == "root struct 'Nope' not found");
    }
}

TEST_CASE("cstruct: multi-dimensional arrays, struct arrays, string arrays") {
    Gen g;
    ParseResult r = g.run(R"C(
        struct Item { uint8_t id; char label[3]; };
        struct M {
            uint16_t m[2][3];
            char names[2][4];
            struct Item items[2];
            uint8_t grid[2][2];
        };
    )C", bytes({1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0}) + "abcdwxyz" + bytes({9, 'a', 'b', 0, 8, 'c', 'd', 0}) +
             bytes({1, 2, 3, 4}));
    INFO(g.lua);
    INFO(dump(r));
    CHECK(r.error.empty());
    CHECK(fld(r, "M.m").value == "[2]");
    CHECK(fld(r, "M.m[1]").value == "[3]");
    CHECK(fld(r, "M.m[1][2]").value == "6");
    CHECK(fld(r, "M.m[1][2]").offset == 10);
    CHECK(fld(r, "M.names[1]").value == "\"wxyz\"");
    CHECK(fld(r, "M.items[1].id").value == "8");
    CHECK(fld(r, "M.items[1].label").offset == 25);
    CHECK(fld(r, "M.grid[1]").value == "03 04");
}

TEST_CASE("cstruct: enums") {
    Gen g;
    ParseResult r = g.run(R"C(
        enum Kind : uint8_t { K_NONE, K_HELLO = 1, K_DATA, K_BYE = 0x10 };
        typedef enum { RED = -1, GREEN = 5, BLUE } Color;   // plain enum: 4 bytes, signed
        enum class Mode : uint16_t { Off = 0, On = 1 };
        struct E { enum Kind kind; Color color; Mode mode; Kind k2; uint8_t pad[K_DATA]; };
    )C", bytes({2, 0xFF, 0xFF, 0xFF, 0xFF, 1, 0, 0x10, 0xAA, 0xBB}));
    INFO(g.lua);
    INFO(dump(r));
    CHECK(r.error.empty());
    CHECK(fld(r, "E.kind").value == "2 = K_DATA");
    CHECK(fld(r, "E.color").value == "-1 = RED");
    CHECK(fld(r, "E.color").size == 4);
    CHECK(fld(r, "E.mode").value == "1 = On");
    CHECK(fld(r, "E.k2").value == "16 = K_BYE");
    CHECK(fld(r, "E.pad").size == 2);
    // Enum fields stay editable by name.
    CHECK(fld(r, "E.kind").editable());
    CHECK(g.lua.find("local Kind = { [0] = \"K_NONE\", [1] = \"K_HELLO\", [2] = \"K_DATA\", [16] = \"K_BYE\" }") !=
          std::string::npos);
}

TEST_CASE("cstruct: bit fields") {
    Gen g;
    const char* c = R"C(
        enum Prio : uint8_t { LOW, MID, HIGH };
        struct Ip {
            uint8_t ihl : 4;
            uint8_t version : 4;
            uint16_t flags : 3;
            uint16_t frag : 13;
            int8_t s : 3;
            int8_t : 2;          // unnamed: padding bits
            enum Prio prio : 2;
            bool on : 1;
            uint32_t big;
        };
    )C";
    // ihl=5, version=4 | flags=0b101, frag=0x123 -> unit = 0x123 << 3 | 5 = 0x091D | s=-3 (0b101), prio=2 at bits 5..6, on=1 at bit 7
    std::string data = bytes({0x45, 0x1D, 0x09, 0x05 | (2 << 5) | 0x80, 7, 0, 0, 0});
    ParseResult r = g.run(c, data);
    INFO(g.lua);
    INFO(dump(r));
    CHECK(r.error.empty());
    CHECK(fld(r, "Ip.ihl").value == "5");
    CHECK(fld(r, "Ip.ihl").comment == "bits 0..3");
    CHECK(fld(r, "Ip.version").value == "4");
    CHECK(fld(r, "Ip.version").offset == 0);
    CHECK(fld(r, "Ip.version").size == 1);
    CHECK(fld(r, "Ip.flags").value == "5");
    CHECK(fld(r, "Ip.frag").value == "291 (0x123)");
    CHECK(fld(r, "Ip.frag").offset == 1);
    CHECK(fld(r, "Ip.frag").size == 2);
    CHECK(fld(r, "Ip.s").value == "-3");
    CHECK(fld(r, "Ip.prio").value == "2 = HIGH");
    CHECK(fld(r, "Ip.on").value == "1 = true");
    CHECK(fld(r, "Ip.on").comment == "bit 7");
    CHECK(fld(r, "Ip.big").offset == 4);
    CHECK(fld(r, "Ip.big").value == "7");
    CHECK(g.info.structs[0].size == 8);

    SUBCASE("big-endian structs allocate from the most significant bit") {
        Gen g2;
        CStructOptions o;
        o.big_endian = true;
        ParseResult r2 = g2.run("struct H { uint8_t version : 4; uint8_t ihl : 4; uint16_t a : 4; uint16_t b : 12; };",
                                bytes({0x45, 0x12, 0x34}), o);
        INFO(g2.lua);
        CHECK(fld(r2, "H.version").value == "4");
        CHECK(fld(r2, "H.ihl").value == "5");
        CHECK(fld(r2, "H.a").value == "1");
        CHECK(fld(r2, "H.b").value == "564 (0x234)");
    }
    SUBCASE("new unit when the type size changes; ': 0' closes a unit; natural alignment") {
        Gen g3;
        CStructOptions o;
        o.pack = 0;
        g3.generate("struct B { uint8_t a : 3; uint32_t b : 3; uint32_t c : 2; uint32_t : 0; uint32_t d : 1; };", o);
        INFO(g3.err);
        REQUIRE(g3.info.structs.size() == 1);
        CHECK(g3.info.structs[0].size == 12);
    }
}

TEST_CASE("cstruct: dynamic arrays sized by earlier fields") {
    Gen g;
    const char* c = R"C(
        #define HDR_MAGIC_LEN 2
        struct Rec { uint8_t n; char text[n]; };
        struct Packet {
            char     magic[HDR_MAGIC_LEN];
            uint16_t len;
            uint8_t  data[len];
            uint8_t  count;
            uint16_t words[count * 2];
            struct Rec recs[count - 1];
            struct { uint8_t k; uint8_t v[k]; } kv;   // inner struct sees its own fields
            uint8_t  end;                             // Lua keyword as a field name
            uint8_t  tail[end];
            uint8_t  rest[];                          // the rest of the data
        };
    )C";
    std::string data = std::string("HX") + bytes({3, 0, 0xA, 0xB, 0xC, 2, 1, 0, 2, 0, 3, 0, 4, 0}) + bytes({2}) +
                       "hi" + bytes({1, 0x55, 2, 0x66, 0x77, 0xEE, 0xFF});
    ParseResult r = g.run(c, data);
    INFO(g.lua);
    INFO(dump(r));
    CHECK(r.error.empty());
    CHECK(fld(r, "Packet.data").offset == 4);
    CHECK(fld(r, "Packet.data").size == 3);
    CHECK(fld(r, "Packet.data").value == "0A 0B 0C");
    CHECK(fld(r, "Packet.words").value == "[4]");
    CHECK(fld(r, "Packet.words[3]").value == "4");
    CHECK(fld(r, "Packet.recs").value == "[1]");
    CHECK(fld(r, "Packet.recs[0].text").value == "\"hi\"");
    CHECK(fld(r, "Packet.kv.v").value == "55");
    CHECK(fld(r, "Packet.tail").value == "66 77");
    CHECK(fld(r, "Packet.rest").value == "EE FF");
    CHECK(fld(r, "Packet.rest").offset == data.size() - 2);
    CHECK(fld(r, "Packet").size == data.size());
    CHECK_FALSE(g.info.structs[1].fixed);
    CHECK(g.lua.find("local len = p:u16le(\"len\")") != std::string::npos);
    CHECK(g.lua.find("p:bytes(\"data\", len)") != std::string::npos);
    CHECK(g.lua.find("count * 2") != std::string::npos);
    CHECK(g.lua.find("local end_ = p:u8(\"end\")") != std::string::npos);
    CHECK(g.lua.find("local HDR_MAGIC_LEN = 2") != std::string::npos);
    CHECK(g.lua.find("p:str(\"magic\", HDR_MAGIC_LEN)") != std::string::npos);

    SUBCASE("a length past the data is the usual EOF error, the partial tree is kept") {
        Gen g2;
        ParseResult r2 = g2.run("struct P { uint8_t len; uint8_t data[len]; };", bytes({9, 1, 2}));
        CHECK(r2.error.find("read past end of data") != std::string::npos);
        CHECK(fld(r2, "P.len").value == "9");
    }
    SUBCASE("natural alignment after a dynamic member is computed at run time") {
        Gen g3;
        CStructOptions o;
        o.pack = 0;
        ParseResult r3 = g3.run("struct P { uint8_t n; uint8_t d[n]; uint32_t x; uint8_t y; };",
                                bytes({1, 0xAA, 0, 0, 7, 0, 0, 0, 9, 0, 0, 0}), o);
        INFO(g3.lua);
        CHECK(fld(r3, "P.x").offset == 4);
        CHECK(fld(r3, "P.x").value == "7");
        CHECK(fld(r3, "P").size == 12);
        CHECK(g3.lua.find("align(p, start, 4)") != std::string::npos);
    }
}

TEST_CASE("cstruct: #define constants, sizeof, comments, ignored preprocessor lines") {
    Gen g;
    ParseResult r = g.run(R"C(
        #pragma once
        #include <stdint.h>
        #ifndef X_H
        #define NAME_LEN   4
        #define TOTAL      (NAME_LEN * 2 + 1)   /* 9 */
        #define MAKE(x)    ((x) + 1)            // function-like: ignored
        #define MULTI \
            3
        #endif
        typedef uint8_t mac_t[3];
        struct Inner { uint16_t a; uint8_t b; };
        struct D {
            char name[TOTAL];
            uint8_t x[MULTI];
            uint8_t y[sizeof(struct Inner) - 1];
            mac_t mac;
            mac_t macs[2];
        };
    )C", std::string(9, 'n') + std::string(3, 'x') + std::string(2, 'y') + bytes({1, 2, 3, 4, 5, 6, 7, 8, 9}));
    INFO(g.lua);
    INFO(dump(r));
    CHECK(r.error.empty());
    CHECK(fld(r, "D.name").size == 9);
    CHECK(fld(r, "D.x").size == 3);
    CHECK(fld(r, "D.y").size == 2);
    CHECK(fld(r, "D.mac").value == "01 02 03");
    CHECK(fld(r, "D.macs[1]").value == "07 08 09");
    CHECK(g.lua.find("local TOTAL = 9") != std::string::npos);
    CHECK(g.lua.find("local NAME_LEN") == std::string::npos);  // only the names the code uses
}

TEST_CASE("cstruct: generated parser runs at an offset (Apply at cursor)") {
    Gen g;
    std::string data = std::string(5, '\0') + bytes({2, 0, 0xAB, 0xCD, 0xEE});
    ParseResult r = g.run("struct P { uint16_t len; uint8_t data[len]; uint8_t rest[]; };", data, {}, 5);
    INFO(dump(r));
    CHECK(r.error.empty());
    CHECK(fld(r, "P").offset == 5);
    CHECK(fld(r, "P.len").value == "2");
    CHECK(fld(r, "P.data").offset == 7);
    CHECK(fld(r, "P.rest").offset == 9);
    CHECK(fld(r, "P.rest").size == 1);
    ParseResult limited = g.eng.parse(*g.host.active, "C struct", 5, 3);
    CHECK(limited.error.find("read past end of data") != std::string::npos);
}

TEST_CASE("cstruct: errors carry line numbers") {
    CHECK(gen_error("struct A {\n  uint32_t a;\n  uint9_t b;\n};") == "line 3: unknown type 'uint9_t'");
    CHECK(gen_error("struct A {\n  uint8_t n;\n  uint8_t d[m];\n};").rfind("line 3: unknown identifier 'm'", 0) == 0);
    CHECK(gen_error("struct A {\n  uint8_t *p;\n};").rfind("line 2: pointers are not supported", 0) == 0);
    CHECK(gen_error("struct A {\n  uint8_t a;\n") == "line 1: missing '}'");
    CHECK(gen_error("struct A { uint8_t a }; ") == "line 1: expected ';' before '}'");
    CHECK(gen_error("struct A {\n uint8_t a[];\n uint8_t b;\n};") == "line 2: flexible array 'a' must be the last member");
    CHECK(gen_error("struct A { uint8_t a; uint8_t a; };") == "line 1: duplicate member 'a'");
    CHECK(gen_error("struct A { float f; uint8_t d[f]; };").find("cannot be used as an array size") != std::string::npos);
    CHECK(gen_error("struct A { uint8_t a : 9; };") == "line 1: bit field 'a': width 9 is out of range");
    CHECK(gen_error("struct B;\nstruct A { struct B b; };") == "line 2: 'B' is declared but not defined");
    CHECK(gen_error("struct A { struct A a; };") == "line 1: 'A' is declared but not defined");
    CHECK(gen_error("union U { uint8_t n; uint8_t d[n]; };").find("not supported in unions") != std::string::npos);
    CHECK(gen_error("\n\n#define X (1 +\nstruct A { uint8_t a[X]; };").rfind("line 3:", 0) == 0);
    CHECK(gen_error("/* unterminated\nstruct A {};") == "line 1: unterminated comment");
    CHECK(gen_error("") == "no struct found (define a struct or union)");
    CHECK(gen_error("struct A { long double x; };") == "line 1: long double is not supported");

    // The info list is filled as far as the source could be read.
    std::string lua, err;
    CStructInfo info;
    CHECK_FALSE(cstruct_to_lua("struct A { uint8_t a; };\nstruct B { foo x; };", {}, lua, &err, &info));
    CHECK(err == "line 2: unknown type 'foo'");
    REQUIRE(info.structs.size() == 1);
    CHECK(info.structs[0].name == "A");
}

TEST_CASE("cstruct: deeply nested input is an error, not a stack overflow") {
    const std::string deep = "nested too deeply";
    auto parens = [](int n) { return "struct A { uint8_t x[" + std::string(size_t(n), '(') + "2" + std::string(size_t(n), ')') + "]; };"; };
    auto nest = [](int n) {
        std::string s = "struct A { ";
        for (int i = 0; i < n; ++i) s += "struct { ";
        s += "uint8_t x; ";
        for (int i = 0; i < n; ++i) s += "}; ";
        return s + "};";
    };
    auto defines = [](int n) {
        std::string s;
        for (int i = 0; i < n; ++i) s += "#define D" + std::to_string(i) + " " + (i ? "D" + std::to_string(i - 1) : "2") + "\n";
        return s + "struct A { uint8_t x[D" + std::to_string(n - 1) + "]; };";
    };
    // Realistic depths work.
    for (const std::string& src : {parens(20), nest(20), defines(20)}) {
        std::string lua, err;
        CHECK(cstruct_to_lua(src, {}, lua, &err));
        CHECK(err == "");
    }
    // Pathological ones fail cleanly (these used to overflow the stack).
    CHECK(gen_error(parens(5000)).find(deep) != std::string::npos);
    CHECK(gen_error("struct A { uint8_t x[" + std::string(20000, '~') + "1]; };").find(deep) != std::string::npos);
    CHECK(gen_error(nest(3000)).find(deep) != std::string::npos);
    CHECK(gen_error(defines(5000)).find(deep) != std::string::npos);
}

TEST_CASE("cstruct: parser name is quoted; names never break the Lua") {
    Gen g;
    CStructOptions o;
    o.name = "My \"quoted\" \\ parser";
    ParseResult r = g.run("enum p : uint8_t { start, bits }; struct parse_X { uint8_t p; uint8_t start; enum p math; uint8_t d[start]; };",
                          bytes({1, 2, 1, 0xAA, 0xBB}), o);
    INFO(g.lua);
    INFO(dump(r));
    CHECK(r.parser == o.name);
    CHECK(r.error.empty());
    CHECK(fld(r, "parse_X.math").value == "1 = bits");
    CHECK(fld(r, "parse_X.d").value == "AA BB");
}

TEST_CASE("cstruct: the dialog's example (ui/dialog_cstruct.cpp) converts and parses") {
    Gen g;
    const char* example = R"C(
#define NAME_LEN 8

enum MsgType : uint8_t { HELLO = 1, DATA = 2, BYE = 3 };

struct Header {
    char     magic[4];
    uint8_t  version : 4;
    uint8_t  flags   : 4;
    enum MsgType type;
    uint16_t length;
};

struct Packet {
    struct Header hdr;
    char     name[NAME_LEN];
    uint16_t count;
    uint32_t values[count];
};
)C";
    std::string data = std::string("HXP1") + bytes({0x21, 2, 4, 0}) + "sensor-7" + bytes({2, 0, 1, 0, 0, 0, 2, 0, 0, 0});
    ParseResult r = g.run(example, data);
    INFO(g.lua);
    INFO(dump(r));
    CHECK(r.error.empty());
    CHECK(fld(r, "Packet.hdr.version").value == "1");
    CHECK(fld(r, "Packet.hdr.flags").value == "2");
    CHECK(fld(r, "Packet.hdr.type").value == "2 = DATA");
    CHECK(fld(r, "Packet.name").value == "\"sensor-7\"");
    CHECK(fld(r, "Packet.values[1]").value == "2");
    CHECK(fld(r, "Packet").size == data.size());
}
