// Tests for core/util and core/inspector. Must not need any other core symbols (no Document/os_file).
#include <doctest/doctest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "core/inspector.h"
#include "core/util.h"

using namespace hx;

namespace {

using Bytes = std::vector<uint8_t>;

std::string insp(InspType t, const Bytes& b, bool be = false) {
    auto rows = inspect(b.data(), b.size(), be);
    return rows[size_t(t)].value;
}
size_t insp_size(InspType t, const Bytes& b, bool be = false) {
    auto rows = inspect(b.data(), b.size(), be);
    return rows[size_t(t)].size;
}
Bytes enc(InspType t, const std::string& s, bool be = false) {
    Bytes out;
    std::string err;
    bool ok = inspector_encode(t, s, be, out, &err);
    INFO("encode '" << s << "': " << err);
    CHECK(ok);
    return out;
}
bool enc_fails(InspType t, const std::string& s, bool be = false) {
    Bytes out;
    std::string err;
    bool ok = inspector_encode(t, s, be, out, &err);
    if (!ok) CHECK(!err.empty());
    return !ok;
}

uint64_t off(const std::string& e, uint64_t cur = 0, uint64_t size = 0x1000, bool hex = true) {
    uint64_t v = 0;
    std::string err;
    bool ok = parse_offset(e, cur, size, hex, v, &err);
    INFO("expr '" << e << "': " << err);
    CHECK(ok);
    return v;
}
std::string off_err(const std::string& e, uint64_t cur = 0, uint64_t size = 0x1000, bool hex = true) {
    uint64_t v = 12345;
    std::string err;
    bool ok = parse_offset(e, cur, size, hex, v, &err);
    INFO("expr '" << e << "' unexpectedly gave " << v);
    CHECK_FALSE(ok);
    CHECK(v == 12345);  // output untouched on error
    CHECK(!err.empty());
    return err;
}

Bytes pb(const std::string& s) {
    Bytes out;
    std::string err;
    bool ok = parse_bytes(s, out, &err);
    INFO("parse_bytes '" << s << "': " << err);
    CHECK(ok);
    return out;
}

Bytes str_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

}  // namespace

// ================================================================================================
// fmt helpers
// ================================================================================================

TEST_CASE("fmt_hex / fmt_size") {
    CHECK(fmt_hex(0) == "0");
    CHECK(fmt_hex(0xAB, 4) == "00AB");
    CHECK(fmt_hex(0xAB, 0, false) == "ab");
    CHECK(fmt_hex(0x12345, 2) == "12345");
    CHECK(fmt_hex(UINT64_MAX) == "FFFFFFFFFFFFFFFF");
    CHECK(fmt_size(0) == "0 B");
    CHECK(fmt_size(512) == "512 B");
    CHECK(fmt_size(1023) == "1023 B");
    CHECK(fmt_size(1024) == "1.00 KiB");
    CHECK(fmt_size(1536) == "1.50 KiB");
    CHECK(fmt_size(uint64_t(5) << 20) == "5.00 MiB");
    CHECK(fmt_size(uint64_t(2) << 40) == "2.00 TiB");
    CHECK(fmt_size(UINT64_MAX) == "16.00 EiB");
}

// ================================================================================================
// parse_offset
// ================================================================================================

TEST_CASE("parse_offset: number syntaxes") {
    CHECK(off("0x100") == 0x100);
    CHECK(off("0X1f") == 0x1F);
    CHECK(off("100") == 0x100);                       // default hex
    CHECK(off("100", 0, 0x1000, false) == 100);       // default decimal
    CHECK(off("1F00h", 0, 0x2000) == 0x1F00);
    CHECK(off("1f00H", 0, 0x2000, false) == 0x1F00);  // suffix wins over default
    CHECK(off("$1F00", 0, 0x2000) == 0x1F00);
    CHECK(off("#4096") == 4096);
    CHECK(off("4096d") == 4096);                      // decimal suffix even with default hex
    CHECK(off("ad") == 0xAD);                         // hex digits, not a 'd' suffix
    CHECK(off("0") == 0);
    CHECK(off("  0x10  ") == 0x10);
}

TEST_CASE("parse_offset: keywords, percent, relative") {
    CHECK(off("end") == 0x1000);
    CHECK(off("EOF") == 0x1000);
    CHECK(off("end-0x100") == 0xF00);
    CHECK(off("cur", 0x123) == 0x123);
    CHECK(off(".", 0x123) == 0x123);
    CHECK(off(". + 1", 5) == 6);
    CHECK(off("cur+4*0x10", 0x10) == 0x50);
    CHECK(off("50%", 0, 1000) == 500);
    CHECK(off("100%", 0, 1000) == 1000);
    CHECK(off("0%", 0, 1000) == 0);
    CHECK(off("12.5%", 0, 1000) == 125);
    CHECK(off("33%", 0, 3) == 0);
    CHECK(off("50 %", 0, 1000) == 500);
    CHECK(off("50%+0x10", 0, 1000) == 516);
    // Relative to current.
    CHECK(off("+0x10", 0x100) == 0x110);
    CHECK(off("-#20", 100) == 80);
    CHECK(off("-0x10+4", 0x100) == 0xF4);  // cur - 0x10 + 4
    CHECK(off("+2*3", 10, 100, false) == 16);
    CHECK(off("-(4)", 10, 100, false) == 6);
    CHECK(off("-(-2)", 10, 100, false) == 12);
    // Huge files: exact 64-bit math.
    const uint64_t tb4 = uint64_t(4) << 40;
    CHECK(off("50%", 0, tb4) == tb4 / 2);
    CHECK(off("end-1", 0, tb4) == tb4 - 1);
    CHECK(off("0x30000000000", 0, tb4) == 0x30000000000ull);
    CHECK(off("+0x100", tb4 - 0x100, tb4) == tb4);
    CHECK(off("99.999999%", 0, tb4) == tb4 / 100000000 * 99999999 + tb4 % 100000000 * 99999999 / 100000000);
}

TEST_CASE("parse_offset: operators and precedence") {
    CHECK(off("(0x10+0x10)*2") == 0x40);
    CHECK(off("2*(3+4)", 0, 100, false) == 14);
    CHECK(off("2+3*4", 0, 100, false) == 14);
    CHECK(off("10-2-3", 0, 100, false) == 5);  // left associative
    CHECK(off("0x100/0x10") == 0x10);
    CHECK(off("100/3", 0, 100, false) == 33);
    CHECK(off("8/2/2", 0, 100, false) == 2);
    CHECK(off("end-0x10-0x10") == 0xFE0);
    CHECK(off("((1))") == 1);
    CHECK(off("2*-1+4", 0, 100, false) == 2);
    CHECK(off("0x10 - 0x20 + 0x20") == 0x10);  // negative intermediate is fine
}

TEST_CASE("parse_offset: errors") {
    CHECK(off_err("") == "empty expression");
    CHECK(off_err("   ") == "empty expression");
    CHECK(off_err("0x10/0") == "division by zero");
    off_err("0x");
    off_err("$");
    off_err("#");
    off_err("0x10)");
    CHECK(off_err("(0x10") == "missing ')'");
    off_err("zz");
    off_err("abc", 0, 0x1000, false);  // not decimal
    off_err("12h3");
    off_err("0x2000");                 // beyond size 0x1000
    off_err("end+1");
    off_err("-0x10", 0);               // before start
    off_err("0-1");
    off_err("FFFFFFFFFFFFFFFFF");      // overflow
    off_err("0xFFFFFFFFFFFFFFFF");     // > int64 max
    off_err("0x7FFFFFFFFFFFFFFF*2");
    off_err("0x10+");
    off_err("*2");
    off_err("50%%");
    off_err("0x10%");
    off_err("1.5");
    off_err("1 2");
    off_err(std::string("10\0" "5", 4));  // embedded NUL is not end of input
    off_err("101%", 0, 100);
    off_err("1.1234567%", 0, 100);
    std::string e = off_err("0x10 ? 4");
    CHECK(e.find("position 6") != std::string::npos);
}

// ================================================================================================
// copy_as / parse_bytes / base64
// ================================================================================================

TEST_CASE("copy_as formats") {
    const Bytes d = {0xDE, 0xAD, 0xBE, 0xEF};
    CHECK(copy_as(d.data(), d.size(), CopyFormat::HexSpaced) == "DE AD BE EF");
    CHECK(copy_as(d.data(), d.size(), CopyFormat::HexCompact) == "DEADBEEF");
    CHECK(copy_as(d.data(), d.size(), CopyFormat::CArray) == "{ 0xDE, 0xAD, 0xBE, 0xEF }");
    CHECK(copy_as(d.data(), d.size(), CopyFormat::PythonBytes) == "b\"\\xde\\xad\\xbe\\xef\"");
    CHECK(copy_as(d.data(), d.size(), CopyFormat::Base64) == "3q2+7w==");
    CHECK(copy_as(d.data(), d.size(), CopyFormat::EscapedString) == "\"\\xde\\xad\\xbe\\xef\"");
    CHECK(copy_as(d.data(), d.size(), CopyFormat::Text) == std::string("\xDE\xAD\xBE\xEF"));

    CHECK(copy_as(nullptr, 0, CopyFormat::HexSpaced).empty());
    CHECK(copy_as(nullptr, 0, CopyFormat::CArray) == "{ }");
    CHECK(copy_as(nullptr, 0, CopyFormat::PythonBytes) == "b\"\"");
    CHECK(copy_as(nullptr, 0, CopyFormat::Base64).empty());

    const Bytes py = {'a', '"', '\\', 0x00, ' ', '~', 0x7F};
    CHECK(copy_as(py.data(), py.size(), CopyFormat::PythonBytes) == "b\"a\\\"\\\\\\x00 ~\\x7f\"");

    const Bytes esc = {'A', 0x01, 'B', '\n', 0x01, 'g', '\t', '\r', '"', '\\', 0x00, '1'};
    CHECK(copy_as(esc.data(), esc.size(), CopyFormat::EscapedString) ==
          "\"A\\x01\\x42\\n\\x01g\\t\\r\\\"\\\\\\x00\\x31\"");

    const Bytes txt = {'h', 'i', 0x00, '!'};
    CHECK(copy_as(txt.data(), txt.size(), CopyFormat::Text) == "hi.!");

    Bytes seq(17);
    for (int i = 0; i < 17; ++i) seq[size_t(i)] = uint8_t(i);
    CHECK(copy_as(seq.data(), seq.size(), CopyFormat::CArray) ==
          "{\n    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,\n"
          "    0x10\n}");
    Bytes sixteen(seq.begin(), seq.begin() + 16);
    CHECK(copy_as(sixteen.data(), 16, CopyFormat::CArray).find('\n') == std::string::npos);
    Bytes thirtytwo(32, 0xAA);
    std::string c32 = copy_as(thirtytwo.data(), 32, CopyFormat::CArray);
    CHECK(c32.substr(c32.size() - 6) == "0xAA\n}");
    CHECK(c32.find("0xAA,\n    0xAA") != std::string::npos);

    for (int f = 0; f < int(CopyFormat::Count); ++f) {
        std::string n = copy_format_name(CopyFormat(f));
        CHECK(!n.empty());
        CHECK(n != "?");
    }
    CHECK(std::string(copy_format_name(CopyFormat::HexSpaced)) == "Hex (spaced)");
    CHECK(std::string(copy_format_name(CopyFormat::CArray)) == "C array");
}

TEST_CASE("parse_bytes lenient") {
    const Bytes dead = {0xDE, 0xAD};
    CHECK(pb("DE AD") == dead);
    CHECK(pb("dead") == dead);
    CHECK(pb("de:ad") == dead);
    CHECK(pb("de-ad") == dead);
    CHECK(pb("0xde,0xad") == dead);
    CHECK(pb("0xDE, 0xAD") == dead);
    CHECK(pb("\\xde\\xad") == dead);
    CHECK(pb("{ 0xDE, 0xAD }") == dead);
    CHECK(pb("[0xde;0xad]") == dead);
    CHECK(pb("  de\n\tad \r\n") == dead);
    CHECK(pb("{ 0x1, 0x2 }") == Bytes{0x01, 0x02});
    CHECK(pb("\\x5") == Bytes{0x05});
    CHECK(pb("DEADBEEF") == Bytes{0xDE, 0xAD, 0xBE, 0xEF});
    CHECK(pb("b64:3q2+7w==") == Bytes{0xDE, 0xAD, 0xBE, 0xEF});
    CHECK(pb("b64: 3q2+ 7w") == Bytes{0xDE, 0xAD, 0xBE, 0xEF});

    Bytes out;
    std::string err;
    CHECK_FALSE(parse_bytes("DEA", out, &err));
    CHECK(err.find("odd") != std::string::npos);
    CHECK_FALSE(parse_bytes("de a", out, &err));
    CHECK_FALSE(parse_bytes("xyz", out, &err));
    CHECK(err.find("position 1") != std::string::npos);
    CHECK_FALSE(parse_bytes("de ag", out, &err));
    CHECK_FALSE(parse_bytes("", out, &err));
    CHECK_FALSE(parse_bytes(" , ", out, &err));
    CHECK_FALSE(parse_bytes("b64:", out, &err));
    CHECK_FALSE(parse_bytes("b64:!!!!", out, &err));
    CHECK_FALSE(parse_bytes("de??", out, &err));  // wildcards are for search only
    CHECK(out.empty());
}

TEST_CASE("copy_as -> parse_bytes round trips") {
    std::mt19937 rng(1234);
    for (size_t len : {size_t(1), size_t(2), size_t(15), size_t(16), size_t(17), size_t(100), size_t(1000)}) {
        Bytes d(len);
        for (auto& b : d) b = uint8_t(rng());
        for (CopyFormat f : {CopyFormat::HexSpaced, CopyFormat::HexCompact, CopyFormat::CArray}) {
            INFO("format " << copy_format_name(f) << " len " << len);
            CHECK(pb(copy_as(d.data(), d.size(), f)) == d);
        }
        CHECK(pb("b64:" + copy_as(d.data(), d.size(), CopyFormat::Base64)) == d);
        // Python bytes / escaped strings of pure non-printables are \x sequences -> parseable too.
        Bytes hi(len, 0x80);
        std::string py = copy_as(hi.data(), hi.size(), CopyFormat::PythonBytes);
        CHECK(pb(py.substr(2, py.size() - 3)) == hi);
    }
}

TEST_CASE("base64 vectors (RFC 4648)") {
    const char* plain[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
    const char* coded[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
    for (int i = 0; i < 7; ++i) {
        Bytes p = str_bytes(plain[i]);
        CHECK(base64_encode(p.data(), p.size()) == coded[i]);
        Bytes back;
        CHECK(base64_decode(coded[i], back));
        CHECK(back == p);
    }
    Bytes out;
    CHECK(base64_decode("Zm9vYg", out));  // padding optional
    CHECK(out == str_bytes("foob"));
    CHECK(base64_decode("Zm9v\nYmFy", out));  // whitespace ignored
    CHECK(out == str_bytes("foobar"));
    CHECK(base64_decode("Zg=", out));
    CHECK(out == str_bytes("f"));
    CHECK_FALSE(base64_decode("Z", out));
    CHECK_FALSE(base64_decode("Zm9vY", out));
    CHECK_FALSE(base64_decode("Zm9v!", out));
    CHECK_FALSE(base64_decode("Zg==Zg==", out));
    Bytes std_alpha, url_alpha;
    CHECK(base64_decode("+/8=", std_alpha));
    CHECK(base64_decode("-_8=", url_alpha));
    CHECK(std_alpha == url_alpha);
    CHECK(std_alpha == Bytes{0xFB, 0xFF});
    Bytes all(256);
    for (int i = 0; i < 256; ++i) all[size_t(i)] = uint8_t(i);
    CHECK(base64_decode(base64_encode(all.data(), all.size()), out));
    CHECK(out == all);
}

// ================================================================================================
// fuzzy_score
// ================================================================================================

TEST_CASE("fuzzy_score") {
    CHECK(fuzzy_score("", "anything") == 0);
    CHECK(fuzzy_score("abc", "ab") == -1);
    CHECK(fuzzy_score("xyz", "Open File") == -1);
    CHECK(fuzzy_score("ba", "ab") == -1);  // order matters
    CHECK(fuzzy_score("OPEN", "open") >= 0);
    CHECK(fuzzy_score("open", "OPEN") >= 0);
    CHECK(fuzzy_score("of", "Open File") > fuzzy_score("of", "Goto offset"));
    CHECK(fuzzy_score("copy", "Copy as hex") > fuzzy_score("copy", "Close Other Pane Yes"));
    CHECK(fuzzy_score("save", "Save") > fuzzy_score("save", "Save As..."));
    CHECK(fuzzy_score("sa", "Save As") > fuzzy_score("sa", "Close all tabs"));
    CHECK(fuzzy_score("gt", "Go To") > fuzzy_score("gt", "Ignite"));
    CHECK(fuzzy_score("fn", "findNext") > fuzzy_score("fn", "fine"));  // camelCase word start
    CHECK(fuzzy_score("go", "Goto") > fuzzy_score("go", "Ago"));          // prefix bonus
    CHECK(fuzzy_score("ab", "a_b") > fuzzy_score("ab", "axxxxxxxxb"));   // gap penalty / word start
}

// ================================================================================================
// Inspector: decoding
// ================================================================================================

TEST_CASE("inspect: rows, order, empty input") {
    auto rows = inspect(nullptr, 0, false);
    REQUIRE(rows.size() == size_t(InspType::Count));
    for (size_t i = 0; i < rows.size(); ++i) {
        CHECK(rows[i].type == InspType(i));
        CHECK(rows[i].name != nullptr);
        CHECK(rows[i].size == 0);
        CHECK(rows[i].value.empty());
        CHECK(rows[i].editable);
    }
    Bytes one = {0x41};
    rows = inspect(one.data(), 1, false);
    CHECK(rows[size_t(InspType::U8)].value == "65");
    CHECK(rows[size_t(InspType::U16)].value.empty());
    CHECK(rows[size_t(InspType::U16)].size == 0);
    CHECK(std::string(rows[size_t(InspType::U32)].name) == "uint32");
}

TEST_CASE("inspect: 8-bit") {
    CHECK(insp(InspType::Bin8, {0x4D}) == "01001101");
    CHECK(insp(InspType::Bin8, {0x00}) == "00000000");
    CHECK(insp(InspType::Bin8, {0xFF}) == "11111111");
    CHECK(insp(InspType::I8, {0x4D}) == "77");
    CHECK(insp(InspType::I8, {0xFF}) == "-1");
    CHECK(insp(InspType::I8, {0x80}) == "-128");
    CHECK(insp(InspType::I8, {0x7F}) == "127");
    CHECK(insp(InspType::U8, {0xFF}) == "255");
    CHECK(insp_size(InspType::U8, {0xFF}) == 1);
    CHECK(insp(InspType::Ascii, {0x41}) == "A");
    CHECK(insp(InspType::Ascii, {0x7E}) == "~");
    CHECK(insp(InspType::Ascii, {0x0A}) == ". (0x0A)");
    CHECK(insp(InspType::Ascii, {0x20}) == ". (0x20)");
    CHECK(insp(InspType::Ascii, {0xFF}) == ". (0xFF)");
}

TEST_CASE("inspect: multi-byte ints, both endians") {
    CHECK(insp(InspType::U16, {0x34, 0x12}) == "4660");
    CHECK(insp(InspType::U16, {0x34, 0x12}, true) == "13330");
    CHECK(insp(InspType::I16, {0x00, 0x80}) == "-32768");
    CHECK(insp(InspType::U16, {0x00, 0x80}) == "32768");
    CHECK(insp(InspType::I16, {0x00, 0x80}, true) == "128");
    CHECK(insp(InspType::I16, {0xFF, 0x7F}) == "32767");

    CHECK(insp(InspType::I24, {0xFF, 0xFF, 0x7F}) == "8388607");
    CHECK(insp(InspType::I24, {0xFF, 0xFF, 0x7F}, true) == "-129");
    CHECK(insp(InspType::U24, {0xFF, 0xFF, 0x7F}, true) == "16777087");
    CHECK(insp(InspType::I24, {0x00, 0x00, 0x80}) == "-8388608");
    CHECK(insp(InspType::U24, {0xFF, 0xFF, 0xFF}) == "16777215");
    CHECK(insp_size(InspType::U24, {0xFF, 0xFF, 0xFF}) == 3);

    CHECK(insp(InspType::I32, {0, 0, 0, 0x80}) == "-2147483648");
    CHECK(insp(InspType::I32, {0, 0, 0, 0x80}, true) == "128");
    CHECK(insp(InspType::U32, {0x78, 0x56, 0x34, 0x12}) == "305419896");
    CHECK(insp(InspType::U32, {0x12, 0x34, 0x56, 0x78}, true) == "305419896");
    CHECK(insp(InspType::U32, {0xFF, 0xFF, 0xFF, 0xFF}) == "4294967295");

    Bytes ff(8, 0xFF);
    CHECK(insp(InspType::U64, ff) == "18446744073709551615");
    CHECK(insp(InspType::I64, ff) == "-1");
    Bytes min64 = {0, 0, 0, 0, 0, 0, 0, 0x80};
    CHECK(insp(InspType::I64, min64) == "-9223372036854775808");
    CHECK(insp(InspType::U64, min64) == "9223372036854775808");
    CHECK(insp(InspType::I64, min64, true) == "128");
    Bytes max64 = {0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    CHECK(insp(InspType::I64, max64, true) == "9223372036854775807");
    CHECK(insp_size(InspType::I64, max64) == 8);
    CHECK(insp(InspType::U64, {1, 2, 3, 4, 5, 6, 7}) == "");  // 7 bytes: not enough
}

TEST_CASE("inspect: floats") {
    CHECK(insp(InspType::F16, {0x00, 0x3C}) == "1");
    CHECK(insp(InspType::F16, {0x3C, 0x00}, true) == "1");
    CHECK(insp(InspType::F16, {0x00, 0xC0}) == "-2");
    CHECK(insp(InspType::F16, {0xFF, 0x7B}) == "65504");
    CHECK(insp(InspType::F16, {0x01, 0x00}) == "6e-08");  // smallest subnormal
    CHECK(insp(InspType::F16, {0x00, 0x04}) == "6.104e-05");  // smallest normal
    CHECK(insp(InspType::F16, {0x55, 0x35}) == "0.3333");
    CHECK(insp(InspType::F16, {0x66, 0x2E}) == "0.1");
    CHECK(insp(InspType::F16, {0x00, 0x5A}) == "192");
    CHECK(insp(InspType::F16, {0x00, 0x49}) == "10");
    CHECK(insp(InspType::F16, {0x00, 0x7C}) == "inf");
    CHECK(insp(InspType::F16, {0x00, 0xFC}) == "-inf");
    CHECK(insp(InspType::F16, {0x00, 0x7E}) == "nan");
    CHECK(insp(InspType::F16, {0x00, 0x80}) == "-0");
    CHECK(insp(InspType::F16, {0x00, 0x00}) == "0");

    CHECK(insp(InspType::F32, {0, 0, 0x80, 0x3F}) == "1");
    CHECK(insp(InspType::F32, {0x3F, 0x80, 0, 0}, true) == "1");
    CHECK(insp(InspType::F32, {0xCD, 0xCC, 0xCC, 0x3D}) == "0.1");
    CHECK(insp(InspType::F32, {0xFF, 0xFF, 0x7F, 0x7F}) == "3.4028235e+38");
    CHECK(insp(InspType::F32, {0x01, 0, 0, 0}) == "1e-45");
    CHECK(insp(InspType::F32, {0, 0, 0x80, 0xFF}) == "-inf");
    CHECK(insp(InspType::F32, {0, 0, 0xC0, 0x7F}) == "nan");

    CHECK(insp(InspType::F64, {0, 0, 0, 0, 0, 0, 0xF0, 0x3F}) == "1");
    CHECK(insp(InspType::F64, {0x3F, 0xF0, 0, 0, 0, 0, 0, 0}, true) == "1");
    CHECK(insp(InspType::F64, {0x9A, 0x99, 0x99, 0x99, 0x99, 0x99, 0xB9, 0x3F}) == "0.1");
    CHECK(insp(InspType::F64, {0, 0, 0, 0, 0, 0, 0, 0x80}) == "-0");
    CHECK(insp(InspType::F64, {0x18, 0x2D, 0x44, 0x54, 0xFB, 0x21, 0x09, 0x40}) == "3.141592653589793");
    CHECK(insp(InspType::F64, {0x01, 0, 0, 0, 0, 0, 0, 0}) == "5e-324");
}

TEST_CASE("inspect: UTF-8") {
    CHECK(insp(InspType::Utf8, {0x41}) == "U+0041 A");
    CHECK(insp(InspType::Utf8, {0x0A}) == "U+000A");
    CHECK(insp(InspType::Utf8, {0xC3, 0xA9}) == "U+00E9 \xC3\xA9");
    CHECK(insp_size(InspType::Utf8, {0xC3, 0xA9, 0x41}) == 2);
    CHECK(insp(InspType::Utf8, {0xE2, 0x82, 0xAC}) == "U+20AC \xE2\x82\xAC");
    CHECK(insp_size(InspType::Utf8, {0xE2, 0x82, 0xAC}) == 3);
    CHECK(insp(InspType::Utf8, {0xF0, 0x9F, 0x98, 0x80}) == "U+1F600 \xF0\x9F\x98\x80");
    CHECK(insp_size(InspType::Utf8, {0xF0, 0x9F, 0x98, 0x80}) == 4);
    CHECK(insp(InspType::Utf8, {0xC2, 0x85}) == "U+0085");  // C1 control
    // Invalid.
    CHECK(insp(InspType::Utf8, {0xC0, 0x80}) == "-");        // overlong
    CHECK(insp(InspType::Utf8, {0x80}) == "-");              // stray continuation
    CHECK(insp(InspType::Utf8, {0xED, 0xA0, 0x80}) == "-");  // surrogate
    CHECK(insp(InspType::Utf8, {0xF4, 0x90, 0x80, 0x80}) == "-");  // > U+10FFFF
    CHECK(insp(InspType::Utf8, {0xC3, 0x41}) == "-");        // bad continuation
    CHECK(insp(InspType::Utf8, {0xFF}) == "-");
    CHECK(insp_size(InspType::Utf8, {0xFF}) == 0);
    CHECK(insp(InspType::Utf8, {0xE2, 0x82}) == "");         // truncated: not enough bytes
}

TEST_CASE("inspect: UTF-16") {
    CHECK(insp(InspType::Utf16, {0x41, 0x00}) == "U+0041 A");
    CHECK(insp(InspType::Utf16, {0x00, 0x41}, true) == "U+0041 A");
    CHECK(insp_size(InspType::Utf16, {0x41, 0x00}) == 2);
    CHECK(insp(InspType::Utf16, {0xAC, 0x20}) == "U+20AC \xE2\x82\xAC");
    CHECK(insp(InspType::Utf16, {0x3D, 0xD8, 0x00, 0xDE}) == "U+1F600 \xF0\x9F\x98\x80");
    CHECK(insp(InspType::Utf16, {0xD8, 0x3D, 0xDE, 0x00}, true) == "U+1F600 \xF0\x9F\x98\x80");
    CHECK(insp_size(InspType::Utf16, {0x3D, 0xD8, 0x00, 0xDE}) == 4);
    CHECK(insp(InspType::Utf16, {0x00, 0xDC}) == "-");               // lone low surrogate
    CHECK(insp(InspType::Utf16, {0x3D, 0xD8, 0x41, 0x00}) == "-");   // high + non-low
    CHECK(insp(InspType::Utf16, {0x3D, 0xD8}) == "");                // high, truncated
    CHECK(insp(InspType::Utf16, {0x41}) == "");
}

TEST_CASE("inspect: LEB128 / ZigZag") {
    CHECK(insp(InspType::ULEB128, {0xE5, 0x8E, 0x26, 0xFF}) == "624485");
    CHECK(insp_size(InspType::ULEB128, {0xE5, 0x8E, 0x26, 0xFF}) == 3);
    CHECK(insp(InspType::ULEB128, {0x7F}) == "127");
    CHECK(insp(InspType::ULEB128, {0x00}) == "0");
    CHECK(insp(InspType::ULEB128, {0x80, 0x01}) == "128");
    Bytes max_u = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01};
    CHECK(insp(InspType::ULEB128, max_u) == "18446744073709551615");
    CHECK(insp_size(InspType::ULEB128, max_u) == 10);
    Bytes over = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02};
    CHECK(insp(InspType::ULEB128, over) == "-");
    CHECK(insp_size(InspType::ULEB128, over) == 0);
    Bytes eleven(11, 0xFF);
    CHECK(insp(InspType::ULEB128, eleven) == "-");
    CHECK(insp(InspType::ULEB128, {0x80, 0x80, 0x80}) == "");  // unterminated within avail

    CHECK(insp(InspType::SLEB128, {0xC0, 0xBB, 0x78}) == "-123456");
    CHECK(insp_size(InspType::SLEB128, {0xC0, 0xBB, 0x78}) == 3);
    CHECK(insp(InspType::SLEB128, {0x7F}) == "-1");
    CHECK(insp(InspType::SLEB128, {0x3F}) == "63");
    CHECK(insp(InspType::SLEB128, {0x40}) == "-64");
    CHECK(insp(InspType::SLEB128, {0xC0, 0x00}) == "64");
    Bytes min_s = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F};
    CHECK(insp(InspType::SLEB128, min_s) == "-9223372036854775808");
    CHECK(insp_size(InspType::SLEB128, min_s) == 10);
    Bytes max_s = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00};
    CHECK(insp(InspType::SLEB128, max_s) == "9223372036854775807");
    Bytes bad_s = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01};
    CHECK(insp(InspType::SLEB128, bad_s) == "-");

    CHECK(insp(InspType::ZigZag, {0x00}) == "0");
    CHECK(insp(InspType::ZigZag, {0x01}) == "-1");
    CHECK(insp(InspType::ZigZag, {0x02}) == "1");
    CHECK(insp(InspType::ZigZag, {0x03}) == "-2");
    CHECK(insp(InspType::ZigZag, {0xAC, 0x02}) == "150");
    CHECK(insp(InspType::ZigZag, max_u) == "-9223372036854775808");
    Bytes zz_max = {0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01};
    CHECK(insp(InspType::ZigZag, zz_max) == "9223372036854775807");
}

TEST_CASE("inspect: times") {
    CHECK(insp(InspType::Unix32, {0, 0, 0, 0}) == "1970-01-01 00:00:00 UTC");
    CHECK(insp(InspType::Unix32, {0xFF, 0xFF, 0xFF, 0x7F}) == "2038-01-19 03:14:07 UTC");
    CHECK(insp(InspType::Unix32, {0x7F, 0xFF, 0xFF, 0xFF}, true) == "2038-01-19 03:14:07 UTC");
    CHECK(insp(InspType::Unix32, {0, 0, 0, 0x80}) == "1901-12-13 20:45:52 UTC");
    CHECK(insp(InspType::Unix32, {0x00, 0xF1, 0x53, 0x65}) == "2023-11-14 22:13:20 UTC");
    CHECK(insp(InspType::Unix32, {0x65, 0x53, 0xF1, 0x00}, true) == "2023-11-14 22:13:20 UTC");
    CHECK(insp(InspType::Unix32, {0xFF, 0xFF, 0xFF, 0xFF}) == "1969-12-31 23:59:59 UTC");
    // 2000-02-29 (leap day) 12:00:00 = 951825600 = 0x38BBB4C0
    CHECK(insp(InspType::Unix32, {0xC0, 0xB4, 0xBB, 0x38}) == "2000-02-29 12:00:00 UTC");

    auto u64le = [](uint64_t v) {
        Bytes b(8);
        for (int i = 0; i < 8; ++i) b[size_t(i)] = uint8_t(v >> (8 * i));
        return b;
    };
    auto u64be = [](uint64_t v) {
        Bytes b(8);
        for (int i = 0; i < 8; ++i) b[size_t(7 - i)] = uint8_t(v >> (8 * i));
        return b;
    };
    CHECK(insp(InspType::Unix64, u64le(253402300799ull)) == "9999-12-31 23:59:59 UTC");
    CHECK(insp(InspType::Unix64, u64be(253402300799ull), true) == "9999-12-31 23:59:59 UTC");
    CHECK(insp(InspType::Unix64, u64le(253402300800ull)) == "-");
    CHECK(insp_size(InspType::Unix64, u64le(253402300800ull)) == 0);
    CHECK(insp(InspType::Unix64, u64le(uint64_t(-62167219200ll))) == "0000-01-01 00:00:00 UTC");
    CHECK(insp(InspType::Unix64, u64le(uint64_t(-62167219201ll))) == "-");
    CHECK(insp(InspType::Unix64, u64le(UINT64_MAX >> 1)) == "-");
    CHECK(insp(InspType::Unix64, u64le(uint64_t(INT64_MIN))) == "-");
    CHECK(insp(InspType::Unix64, u64le(uint64_t(-1))) == "1969-12-31 23:59:59 UTC");
    CHECK(insp(InspType::Unix64, u64le(1700000000)) == "2023-11-14 22:13:20 UTC");

    CHECK(insp(InspType::FileTime, u64le(116444736000000000ull)) == "1970-01-01 00:00:00 UTC");
    CHECK(insp(InspType::FileTime, u64be(116444736000000000ull), true) == "1970-01-01 00:00:00 UTC");
    CHECK(insp(InspType::FileTime, u64le(0)) == "1601-01-01 00:00:00 UTC");
    CHECK(insp(InspType::FileTime, u64le(116444736000000001ull)) == "1970-01-01 00:00:00.0000001 UTC");
    CHECK(insp(InspType::FileTime, u64le(133444736001234567ull)) == "2023-11-14 22:13:20.1234567 UTC");
    CHECK(insp(InspType::FileTime, u64le(UINT64_MAX)) == "-");  // year 60056

    // DOS: 2024-03-15 13:45:30 -> date 0x586F, time 0x6DAF
    CHECK(insp(InspType::DosDateTime, {0xAF, 0x6D, 0x6F, 0x58}) == "2024-03-15 13:45:30");
    CHECK(insp(InspType::DosDateTime, {0x58, 0x6F, 0x6D, 0xAF}, true) == "2024-03-15 13:45:30");
    CHECK(insp(InspType::DosDateTime, {0x00, 0x00, 0x21, 0x00}) == "1980-01-01 00:00:00");
    CHECK(insp(InspType::DosDateTime, {0, 0, 0, 0}) == "-");
    CHECK(insp(InspType::DosDateTime, {0x00, 0x00, 0x3E, 0x00}) == "1980-01-30 00:00:00");
    CHECK(insp(InspType::DosDateTime, {0x00, 0x00, 0x20, 0x00}) == "-");  // day 0
    CHECK(insp(InspType::DosDateTime, {0x00, 0x00, 0x5E, 0x00}) == "-");  // Feb 30
    CHECK(insp(InspType::DosDateTime, {0x00, 0xC0, 0x21, 0x00}) == "-");  // hour 24
    CHECK(insp(InspType::DosDateTime, {0x1E, 0x00, 0x21, 0x00}) == "-");  // second 60
    CHECK(insp_size(InspType::DosDateTime, {0, 0, 0, 0}) == 0);
}

TEST_CASE("inspect: GUID") {
    Bytes le = {0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    CHECK(insp(InspType::Guid, le) == "{00112233-4455-6677-8899-AABBCCDDEEFF}");
    Bytes be = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    CHECK(insp(InspType::Guid, be, true) == "{00112233-4455-6677-8899-AABBCCDDEEFF}");
    CHECK(insp_size(InspType::Guid, be) == 16);
    CHECK(insp(InspType::Guid, Bytes(15, 0)) == "");
}

// ================================================================================================
// Inspector: encoding
// ================================================================================================

TEST_CASE("inspector_encode: ints and range checks") {
    CHECK(enc(InspType::U8, "255") == Bytes{0xFF});
    CHECK(enc(InspType::U8, "0xff") == Bytes{0xFF});
    CHECK(enc(InspType::U8, " 7 ") == Bytes{0x07});
    CHECK(enc_fails(InspType::U8, "256"));
    CHECK(enc_fails(InspType::U8, "0x100"));
    CHECK(enc_fails(InspType::U8, "-1"));
    CHECK(enc(InspType::U8, "-0") == Bytes{0x00});
    CHECK(enc(InspType::I8, "-128") == Bytes{0x80});
    CHECK(enc(InspType::I8, "127") == Bytes{0x7F});
    CHECK(enc(InspType::I8, "0xFF") == Bytes{0xFF});  // hex = raw bit pattern
    CHECK(enc(InspType::I8, "-0x80") == Bytes{0x80});
    CHECK(enc_fails(InspType::I8, "128"));
    CHECK(enc_fails(InspType::I8, "-129"));
    CHECK(enc_fails(InspType::I8, "0x100"));
    CHECK(enc_fails(InspType::I8, "-0x81"));
    CHECK(enc_fails(InspType::I8, "abc"));
    CHECK(enc_fails(InspType::I8, ""));
    CHECK(enc_fails(InspType::I8, "1.5"));
    CHECK(enc_fails(InspType::I8, "0x"));

    CHECK(enc(InspType::U16, "0x1234") == Bytes{0x34, 0x12});
    CHECK(enc(InspType::U16, "0x1234", true) == Bytes{0x12, 0x34});
    CHECK(enc(InspType::I16, "-2") == Bytes{0xFE, 0xFF});
    CHECK(enc_fails(InspType::I16, "32768"));
    CHECK(enc(InspType::I24, "-8388608") == Bytes{0x00, 0x00, 0x80});
    CHECK(enc(InspType::U24, "16777215", true) == Bytes{0xFF, 0xFF, 0xFF});
    CHECK(enc_fails(InspType::U24, "16777216"));
    CHECK(enc_fails(InspType::I24, "8388608"));
    CHECK(enc(InspType::U32, "305419896", true) == Bytes{0x12, 0x34, 0x56, 0x78});
    CHECK(enc(InspType::I32, "-2147483648") == Bytes{0, 0, 0, 0x80});
    CHECK(enc_fails(InspType::U32, "4294967296"));
    CHECK(enc(InspType::U64, "18446744073709551615") == Bytes(8, 0xFF));
    CHECK(enc_fails(InspType::U64, "18446744073709551616"));
    CHECK(enc(InspType::I64, "-9223372036854775808") == Bytes{0, 0, 0, 0, 0, 0, 0, 0x80});
    CHECK(enc_fails(InspType::I64, "9223372036854775808"));
    CHECK(enc(InspType::I64, "0xFFFFFFFFFFFFFFFF") == Bytes(8, 0xFF));
    CHECK(enc_fails(InspType::I64, "-9223372036854775809"));
}

TEST_CASE("inspector_encode: other types") {
    CHECK(enc(InspType::Bin8, "01001101") == Bytes{0x4D});
    CHECK(enc(InspType::Bin8, "0b1") == Bytes{0x01});
    CHECK(enc(InspType::Bin8, "0100 1101") == Bytes{0x4D});
    CHECK(enc_fails(InspType::Bin8, "2"));
    CHECK(enc_fails(InspType::Bin8, "111111111"));
    CHECK(enc_fails(InspType::Bin8, ""));

    CHECK(enc(InspType::F16, "1") == Bytes{0x00, 0x3C});
    CHECK(enc(InspType::F16, "1", true) == Bytes{0x3C, 0x00});
    CHECK(enc(InspType::F16, "65504") == Bytes{0xFF, 0x7B});
    CHECK(enc(InspType::F16, "-2") == Bytes{0x00, 0xC0});
    CHECK(enc(InspType::F16, "inf") == Bytes{0x00, 0x7C});
    CHECK(enc(InspType::F16, "-inf") == Bytes{0x00, 0xFC});
    CHECK(enc(InspType::F16, "6e-8") == Bytes{0x01, 0x00});
    CHECK(enc(InspType::F16, "+0.5") == Bytes{0x00, 0x38});
    CHECK(enc(InspType::F16, "65519") == Bytes{0xFF, 0x7B});  // rounds down to max
    CHECK(enc_fails(InspType::F16, "65520"));
    CHECK(enc_fails(InspType::F16, "70000"));
    CHECK(enc_fails(InspType::F16, "x"));
    CHECK(enc(InspType::F32, "1") == Bytes{0, 0, 0x80, 0x3F});
    CHECK(enc(InspType::F32, "0.1", true) == Bytes{0x3D, 0xCC, 0xCC, 0xCD});
    CHECK(enc_fails(InspType::F32, "1e39"));
    CHECK(enc(InspType::F32, "inf") == Bytes{0, 0, 0x80, 0x7F});
    CHECK(enc(InspType::F64, "0.1") == Bytes{0x9A, 0x99, 0x99, 0x99, 0x99, 0x99, 0xB9, 0x3F});
    CHECK(enc_fails(InspType::F64, "1.0.0"));
    CHECK(enc_fails(InspType::F64, ""));

    CHECK(enc(InspType::Ascii, "A") == Bytes{0x41});
    CHECK(enc(InspType::Ascii, " ") == Bytes{0x20});
    CHECK(enc_fails(InspType::Ascii, "AB"));
    CHECK(enc_fails(InspType::Ascii, "\xC3\xA9"));
    CHECK(enc_fails(InspType::Ascii, ""));

    CHECK(enc(InspType::Utf8, "\xC3\xA9") == Bytes{0xC3, 0xA9});
    CHECK(enc(InspType::Utf8, "U+1F600") == Bytes{0xF0, 0x9F, 0x98, 0x80});
    CHECK(enc(InspType::Utf8, "u+41") == Bytes{0x41});
    CHECK(enc(InspType::Utf8, "U+00E9 \xC3\xA9") == Bytes{0xC3, 0xA9});  // the displayed form
    CHECK(enc_fails(InspType::Utf8, "U+D800"));
    CHECK(enc_fails(InspType::Utf8, "U+110000"));
    CHECK(enc_fails(InspType::Utf8, "ab"));
    CHECK(enc_fails(InspType::Utf8, "\xFF"));
    CHECK(enc(InspType::Utf16, "\xF0\x9F\x98\x80") == Bytes{0x3D, 0xD8, 0x00, 0xDE});
    CHECK(enc(InspType::Utf16, "\xF0\x9F\x98\x80", true) == Bytes{0xD8, 0x3D, 0xDE, 0x00});
    CHECK(enc(InspType::Utf16, "A") == Bytes{0x41, 0x00});
    CHECK(enc(InspType::Utf16, "A", true) == Bytes{0x00, 0x41});

    CHECK(enc(InspType::ULEB128, "624485") == Bytes{0xE5, 0x8E, 0x26});
    CHECK(enc(InspType::ULEB128, "0") == Bytes{0x00});
    CHECK(enc(InspType::ULEB128, "18446744073709551615") ==
          Bytes{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01});
    CHECK(enc_fails(InspType::ULEB128, "-1"));
    CHECK(enc(InspType::SLEB128, "-123456") == Bytes{0xC0, 0xBB, 0x78});
    CHECK(enc(InspType::SLEB128, "-1") == Bytes{0x7F});
    CHECK(enc(InspType::SLEB128, "63") == Bytes{0x3F});
    CHECK(enc(InspType::SLEB128, "64") == Bytes{0xC0, 0x00});
    CHECK(enc(InspType::SLEB128, "-64") == Bytes{0x40});
    CHECK(enc(InspType::SLEB128, "-9223372036854775808") ==
          Bytes{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F});
    CHECK(enc(InspType::ZigZag, "-1") == Bytes{0x01});
    CHECK(enc(InspType::ZigZag, "1") == Bytes{0x02});
    CHECK(enc(InspType::ZigZag, "150") == Bytes{0xAC, 0x02});
    CHECK(enc(InspType::ZigZag, "-9223372036854775808") ==
          Bytes{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01});

    CHECK(enc(InspType::Unix32, "2038-01-19 03:14:07 UTC") == Bytes{0xFF, 0xFF, 0xFF, 0x7F});
    CHECK(enc(InspType::Unix32, "2038-01-19 03:14:07", true) == Bytes{0x7F, 0xFF, 0xFF, 0xFF});
    CHECK(enc(InspType::Unix32, "1970-01-01") == Bytes{0, 0, 0, 0});
    CHECK(enc(InspType::Unix32, "2023-11-14T22:13:20Z") == Bytes{0x00, 0xF1, 0x53, 0x65});
    CHECK(enc(InspType::Unix32, "1969-12-31 23:59:59") == Bytes{0xFF, 0xFF, 0xFF, 0xFF});
    CHECK(enc(InspType::Unix32, "1901-12-13 20:45:52") == Bytes{0, 0, 0, 0x80});
    CHECK(enc_fails(InspType::Unix32, "2038-01-19 03:14:08"));
    CHECK(enc_fails(InspType::Unix32, "1901-12-13 20:45:51"));
    CHECK(enc_fails(InspType::Unix32, "2023-02-29"));     // not a leap year
    CHECK(enc_fails(InspType::Unix32, "2023-13-01"));
    CHECK(enc_fails(InspType::Unix32, "2023-01-01 24:00:00"));
    CHECK(enc_fails(InspType::Unix32, "2023-01-01 garbage"));
    CHECK(enc_fails(InspType::Unix32, "1700000000"));
    CHECK(enc(InspType::Unix32, "2024-02-29 00:00") == enc(InspType::Unix32, "2024-02-29 00:00:00"));
    CHECK(enc(InspType::Unix64, "9999-12-31 23:59:59") ==
          Bytes{0x7F, 0x41, 0xF4, 0xFF, 0x3A, 0x00, 0x00, 0x00});
    CHECK(enc(InspType::FileTime, "1601-01-01 00:00:00") == Bytes(8, 0));
    CHECK(enc_fails(InspType::FileTime, "1600-12-31 23:59:59"));
    CHECK(enc(InspType::DosDateTime, "2024-03-15 13:45:30") == Bytes{0xAF, 0x6D, 0x6F, 0x58});
    CHECK(enc(InspType::DosDateTime, "2024-03-15 13:45:30", true) == Bytes{0x58, 0x6F, 0x6D, 0xAF});
    CHECK(enc(InspType::DosDateTime, "2024-03-15 13:45:31") == Bytes{0xAF, 0x6D, 0x6F, 0x58});  // 2s units
    CHECK(enc_fails(InspType::DosDateTime, "1979-12-31 23:59:59"));
    CHECK(enc_fails(InspType::DosDateTime, "2108-01-01"));

    Bytes le = {0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    CHECK(enc(InspType::Guid, "{00112233-4455-6677-8899-AABBCCDDEEFF}") == le);
    CHECK(enc(InspType::Guid, "00112233445566778899aabbccddeeff") == le);
    Bytes be = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    CHECK(enc(InspType::Guid, "{00112233-4455-6677-8899-AABBCCDDEEFF}", true) == be);
    CHECK(enc_fails(InspType::Guid, "{0011}"));
    CHECK(enc_fails(InspType::Guid, "{00112233-4455-6677-8899-AABBCCDDEEFG}"));
    CHECK(enc_fails(InspType::Count, "1"));
}

TEST_CASE("inspector: decode -> encode round trips over random data, both endians") {
    std::mt19937 rng(42);
    int checked = 0;
    for (int iter = 0; iter < 3000; ++iter) {
        Bytes buf(16);
        for (auto& b : buf) b = uint8_t(rng());
        if (iter % 3 == 0) buf[3] = buf[7] = 0x00;  // make some time values plausible
        if (iter % 5 == 0) buf[1] &= 0x3F;           // valid-ish UTF-8 / small LEBs
        for (bool be : {false, true}) {
            auto rows = inspect(buf.data(), buf.size(), be);
            for (const InspRow& r : rows) {
                if (r.size == 0 || r.value == "-" || r.value == "nan") continue;
                if (r.type == InspType::Ascii && r.value.size() != 1) continue;  // ". (0xNN)"
                Bytes out;
                std::string err;
                INFO("type " << r.name << " value '" << r.value << "' be=" << be);
                REQUIRE(inspector_encode(r.type, r.value, be, out, &err));
                if (r.type == InspType::ULEB128 || r.type == InspType::SLEB128 || r.type == InspType::ZigZag) {
                    // Non-minimal encodings re-encode shorter; the value must match.
                    auto back = inspect(out.data(), out.size(), be);
                    CHECK(back[size_t(r.type)].value == r.value);
                    CHECK(out.size() <= r.size);
                } else if (r.type == InspType::DosDateTime) {
                    auto back = inspect(out.data(), out.size(), be);
                    CHECK(back[size_t(r.type)].value == r.value);
                } else {
                    CHECK(out == Bytes(buf.begin(), buf.begin() + std::ptrdiff_t(r.size)));
                }
                ++checked;
            }
        }
    }
    CHECK(checked > 50000);
}

TEST_CASE("inspector: float16 exhaustive round trip") {
    for (uint32_t h = 0; h < 0x10000; ++h) {
        Bytes b = {uint8_t(h), uint8_t(h >> 8)};
        std::string v = insp(InspType::F16, b);
        if (v == "nan") continue;
        Bytes out;
        INFO("half " << h << " '" << v << "'");
        REQUIRE(inspector_encode(InspType::F16, v, false, out));
        CHECK(out == b);
    }
}
