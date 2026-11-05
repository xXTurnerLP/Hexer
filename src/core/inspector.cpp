#include "core/inspector.h"

#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>

namespace hx {

namespace {

// ---- byte helpers -----------------------------------------------------------------------------

uint64_t load(const uint8_t* p, size_t n, bool be) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v |= uint64_t(p[be ? n - 1 - i : i]) << (8 * i);
    return v;
}

void store(std::vector<uint8_t>& out, uint64_t v, size_t n, bool be) {
    out.resize(n);
    for (size_t i = 0; i < n; ++i) out[be ? n - 1 - i : i] = uint8_t(v >> (8 * i));
}

int64_t sign_extend(uint64_t v, unsigned bits) {
    if (bits >= 64) return int64_t(v);
    uint64_t m = uint64_t(1) << (bits - 1);
    v &= (uint64_t(1) << bits) - 1;
    return int64_t((v ^ m) - m);
}

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

bool fail(std::string* err, const char* msg) {
    if (err) *err = msg;
    return false;
}

// ---- floats -----------------------------------------------------------------------------------

double half_to_double(uint16_t h) {
    int sign = h >> 15, exp = (h >> 10) & 0x1F, man = h & 0x3FF;
    double v;
    if (exp == 0) v = std::ldexp(double(man), -24);
    else if (exp == 31) v = man ? std::numeric_limits<double>::quiet_NaN() : std::numeric_limits<double>::infinity();
    else v = std::ldexp(double(man | 0x400), exp - 25);
    return sign ? -v : v;
}

// Round-to-nearest-even. Returns false if a finite value overflows the half range.
bool double_to_half(double x, uint16_t& out) {
    uint16_t sign = std::signbit(x) ? 0x8000 : 0;
    if (std::isnan(x)) {
        out = 0x7E00;
        return true;
    }
    double a = std::fabs(x);
    if (std::isinf(a)) {
        out = sign | 0x7C00;
        return true;
    }
    if (a >= 65520.0) return false;  // rounds to infinity
    if (a < std::ldexp(1.0, -14)) {  // subnormal (may round up to the smallest normal: 0x0400)
        out = sign | uint16_t(std::nearbyint(a * std::ldexp(1.0, 24)));
        return true;
    }
    int k;
    std::frexp(a, &k);       // a = f * 2^k, f in [0.5, 1)
    int e = k - 1;            // a in [2^e, 2^(e+1))
    double m = std::nearbyint((std::ldexp(a, -e) - 1.0) * 1024.0);
    if (m >= 1024.0) {
        m = 0;
        ++e;
    }
    out = uint16_t(sign | uint16_t((e + 15) << 10) | uint16_t(m));
    return true;
}

std::string fmt_special(double v) {
    if (std::isnan(v)) return "nan";
    return v < 0 ? "-inf" : "inf";
}

template <class F>
std::string fmt_shortest(F v) {
    if (!std::isfinite(v)) return fmt_special(double(v));
    char buf[64];
    auto r = std::to_chars(buf, buf + sizeof buf, v);
    return std::string(buf, r.ptr);
}

std::string fmt_half(uint16_t h) {
    double v = half_to_double(h);
    if (!std::isfinite(v)) return fmt_special(v);
    char buf[64];
    if (v == std::trunc(v)) {  // integers print plainly ("65504", not "6.55e+04"); |v| <= 65504
        auto r = std::to_chars(buf, buf + sizeof buf, int64_t(v));
        std::string s(buf, r.ptr);
        return std::signbit(v) && v == 0 ? "-0" : s;
    }
    for (int p = 1; p <= 5; ++p) {  // shortest text that round-trips to the same half
        auto r = std::to_chars(buf, buf + sizeof buf, v, std::chars_format::general, p);
        double back = 0;
        std::from_chars(buf, r.ptr, back);
        uint16_t hb;
        if (double_to_half(back, hb) && hb == h)
            return std::string(buf, r.ptr);
    }
    auto r = std::to_chars(buf, buf + sizeof buf, v);
    return std::string(buf, r.ptr);
}

bool parse_double(const std::string& text, double& out) {
    std::string t = trim(text);
    if (!t.empty() && t[0] == '+') t.erase(0, 1);
    if (t.empty()) return false;
    auto r = std::from_chars(t.data(), t.data() + t.size(), out);
    return r.ec == std::errc() && r.ptr == t.data() + t.size();
}

// ---- integers ---------------------------------------------------------------------------------

// Parses [+|-](decimal | 0x hex). Magnitude in `mag`.
bool parse_int(const std::string& text, bool& neg, bool& hex, uint64_t& mag) {
    std::string t = trim(text);
    neg = hex = false;
    size_t i = 0;
    if (i < t.size() && (t[i] == '+' || t[i] == '-')) neg = t[i++] == '-';
    if (i + 1 < t.size() && t[i] == '0' && (t[i + 1] == 'x' || t[i + 1] == 'X')) {
        hex = true;
        i += 2;
    }
    if (i >= t.size()) return false;
    const char* b = t.data() + i;
    const char* e = t.data() + t.size();
    auto r = std::from_chars(b, e, mag, hex ? 16 : 10);
    return r.ec == std::errc() && r.ptr == e;
}

// Unsigned value of `bits` width.
bool parse_uint_bits(const std::string& text, unsigned bits, uint64_t& out, std::string* err) {
    bool neg, hex;
    uint64_t mag;
    if (!parse_int(text, neg, hex, mag)) return fail(err, "not a number");
    uint64_t max = bits >= 64 ? ~uint64_t(0) : (uint64_t(1) << bits) - 1;
    if (neg && mag != 0) return fail(err, "must not be negative");
    if (mag > max) return fail(err, "out of range");
    out = mag;
    return true;
}

// Signed value of `bits` width; an unsigned hex literal may also give the raw bit pattern
// (e.g. 0xFF for int8 = -1). Result is the two's complement bit pattern.
bool parse_sint_bits(const std::string& text, unsigned bits, uint64_t& out, std::string* err) {
    bool neg, hex;
    uint64_t mag;
    if (!parse_int(text, neg, hex, mag)) return fail(err, "not a number");
    uint64_t umax = bits >= 64 ? ~uint64_t(0) : (uint64_t(1) << bits) - 1;
    uint64_t pos_max = umax >> 1;   // 2^(bits-1) - 1
    uint64_t neg_max = pos_max + 1; // magnitude of the minimum
    if (neg) {
        if (mag > neg_max) return fail(err, "out of range");
        out = (0 - mag) & umax;
    } else {
        if (mag > (hex ? umax : pos_max)) return fail(err, "out of range");
        out = mag;
    }
    return true;
}

// ---- LEB128 -----------------------------------------------------------------------------------

// Returns bytes consumed, 0 if not enough bytes, SIZE_MAX if malformed/overflowing.
size_t uleb_decode(const uint8_t* p, size_t avail, uint64_t& v) {
    v = 0;
    for (size_t i = 0; i < 10; ++i) {
        if (i >= avail) return 0;
        uint8_t b = p[i];
        if (i == 9 && (b & 0xFE)) return SIZE_MAX;  // > 64 bits or still continuing
        v |= uint64_t(b & 0x7F) << (7 * i);
        if (!(b & 0x80)) return i + 1;
    }
    return SIZE_MAX;
}

size_t sleb_decode(const uint8_t* p, size_t avail, int64_t& out) {
    uint64_t v = 0;
    for (size_t i = 0; i < 10; ++i) {
        if (i >= avail) return 0;
        uint8_t b = p[i];
        unsigned shift = unsigned(7 * i);
        if (i == 9) {  // only bit 63 left: the payload must be pure sign extension
            if ((b & 0x80) || ((b & 0x7F) != 0 && (b & 0x7F) != 0x7F)) return SIZE_MAX;
            v |= uint64_t(b & 1) << 63;
            out = int64_t(v);
            return 10;
        }
        v |= uint64_t(b & 0x7F) << shift;
        if (!(b & 0x80)) {
            shift += 7;
            if ((b & 0x40) && shift < 64) v |= ~uint64_t(0) << shift;
            out = int64_t(v);
            return i + 1;
        }
    }
    return SIZE_MAX;
}

void uleb_encode(uint64_t v, std::vector<uint8_t>& out) {
    out.clear();
    do {
        uint8_t b = v & 0x7F;
        v >>= 7;
        if (v) b |= 0x80;
        out.push_back(b);
    } while (v);
}

void sleb_encode(int64_t v, std::vector<uint8_t>& out) {
    out.clear();
    for (;;) {
        uint8_t b = uint8_t(v & 0x7F);
        v >>= 7;  // arithmetic shift (guaranteed since C++20)
        bool done = (v == 0 && !(b & 0x40)) || (v == -1 && (b & 0x40));
        if (!done) b |= 0x80;
        out.push_back(b);
        if (done) break;
    }
}

// ---- characters -------------------------------------------------------------------------------

void append_utf8(std::string& s, uint32_t cp) {
    if (cp < 0x80) {
        s += char(cp);
    } else if (cp < 0x800) {
        s += char(0xC0 | (cp >> 6));
        s += char(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        s += char(0xE0 | (cp >> 12));
        s += char(0x80 | ((cp >> 6) & 0x3F));
        s += char(0x80 | (cp & 0x3F));
    } else {
        s += char(0xF0 | (cp >> 18));
        s += char(0x80 | ((cp >> 12) & 0x3F));
        s += char(0x80 | ((cp >> 6) & 0x3F));
        s += char(0x80 | (cp & 0x3F));
    }
}

// Returns bytes consumed, 0 if not enough bytes, SIZE_MAX if invalid.
size_t utf8_decode(const uint8_t* p, size_t avail, uint32_t& cp) {
    if (avail == 0) return 0;
    uint8_t b = p[0];
    size_t n;
    uint32_t min;
    if (b < 0x80) {
        cp = b;
        return 1;
    } else if ((b & 0xE0) == 0xC0) {
        n = 2, cp = b & 0x1F, min = 0x80;
    } else if ((b & 0xF0) == 0xE0) {
        n = 3, cp = b & 0x0F, min = 0x800;
    } else if ((b & 0xF8) == 0xF0) {
        n = 4, cp = b & 0x07, min = 0x10000;
    } else {
        return SIZE_MAX;
    }
    for (size_t i = 1; i < n; ++i) {
        if (i >= avail) return 0;
        if ((p[i] & 0xC0) != 0x80) return SIZE_MAX;
        cp = (cp << 6) | (p[i] & 0x3F);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return SIZE_MAX;
    return n;
}

std::string fmt_codepoint(uint32_t cp) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "U+%04X", unsigned(cp));
    std::string s = buf;
    bool control = cp < 0x20 || (cp >= 0x7F && cp < 0xA0);
    if (!control) {
        s += ' ';
        append_utf8(s, cp);
    }
    return s;
}

// "U+XXXX[ anything]" or exactly one UTF-8 encoded code point.
bool parse_codepoint(const std::string& text, uint32_t& cp, std::string* err) {
    if (text.size() > 2 && (text[0] == 'U' || text[0] == 'u') && text[1] == '+') {
        const char* b = text.data() + 2;
        const char* e = text.data() + text.size();
        uint32_t v = 0;
        auto r = std::from_chars(b, e, v, 16);
        if (r.ec != std::errc() || (r.ptr != e && !std::isspace(static_cast<unsigned char>(*r.ptr))))
            return fail(err, "expected U+XXXX");
        if (v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) return fail(err, "invalid code point");
        cp = v;
        return true;
    }
    if (text.empty()) return fail(err, "expected one character");
    size_t n = utf8_decode(reinterpret_cast<const uint8_t*>(text.data()), text.size(), cp);
    if (n == 0 || n == SIZE_MAX) return fail(err, "invalid UTF-8");
    if (n != text.size()) return fail(err, "expected one character");
    return true;
}

// ---- dates (proleptic Gregorian, UTC; no dependency on gmtime) --------------------------------

constexpr int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = unsigned(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + int64_t(doe) - 719468;
}

void civil_from_days(int64_t z, int64_t& y, unsigned& m, unsigned& d) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = unsigned(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = int64_t(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y += m <= 2;
}

bool is_leap(int64_t y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

unsigned days_in_month(int64_t y, unsigned m) {
    static const unsigned dm[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return m == 2 && is_leap(y) ? 29 : dm[m - 1];
}

// Supported display range: years 0000..9999.
constexpr int64_t kMinSecs = days_from_civil(0, 1, 1) * 86400;
constexpr int64_t kMaxSecs = days_from_civil(9999, 12, 31) * 86400 + 86399;

std::string fmt_datetime(int64_t secs, uint32_t frac100ns, bool utc) {
    if (secs < kMinSecs || secs > kMaxSecs) return "-";
    int64_t days = secs >= 0 ? secs / 86400 : -((-secs + 86399) / 86400);
    int64_t rem = secs - days * 86400;
    int64_t y;
    unsigned m, d;
    civil_from_days(days, y, m, d);
    char buf[64];
    int n = std::snprintf(buf, sizeof buf, "%04d-%02u-%02u %02d:%02d:%02d", int(y), m, d, int(rem / 3600),
                          int(rem / 60 % 60), int(rem % 60));
    if (frac100ns) n += std::snprintf(buf + n, sizeof buf - size_t(n), ".%07u", unsigned(frac100ns));
    if (utc) std::snprintf(buf + n, sizeof buf - size_t(n), " UTC");
    return buf;
}

// "YYYY-MM-DD[( |T)hh:mm[:ss[.fffffff]]][ ][UTC|Z]" -> seconds since 1970 (+ 100ns fraction).
bool parse_datetime(const std::string& text, int64_t& secs, uint32_t& frac100ns, std::string* err) {
    std::string t = trim(text);
    size_t i = 0;
    auto num = [&](int min_digits, int max_digits, int64_t& v) {
        int n = 0;
        v = 0;
        while (i < t.size() && n < max_digits && std::isdigit(static_cast<unsigned char>(t[i]))) {
            v = v * 10 + (t[i++] - '0');
            ++n;
        }
        return n >= min_digits;
    };
    auto expect = [&](char c) {
        if (i < t.size() && t[i] == c) {
            ++i;
            return true;
        }
        return false;
    };
    int64_t y, mo, d, h = 0, mi = 0, s = 0;
    frac100ns = 0;
    if (!num(4, 4, y) || !expect('-') || !num(1, 2, mo) || !expect('-') || !num(1, 2, d))
        return fail(err, "expected YYYY-MM-DD hh:mm:ss");
    if (i < t.size() && (t[i] == ' ' || t[i] == 'T') && i + 1 < t.size() &&
        std::isdigit(static_cast<unsigned char>(t[i + 1]))) {
        ++i;
        if (!num(1, 2, h) || !expect(':') || !num(1, 2, mi)) return fail(err, "expected hh:mm:ss");
        if (expect(':')) {
            if (!num(1, 2, s)) return fail(err, "expected hh:mm:ss");
            if (expect('.')) {
                int n = 0;
                while (i < t.size() && std::isdigit(static_cast<unsigned char>(t[i]))) {
                    if (n < 7) frac100ns = frac100ns * 10 + uint32_t(t[i] - '0');
                    ++n;
                    ++i;
                }
                if (n == 0) return fail(err, "expected fraction digits");
                for (; n < 7; ++n) frac100ns *= 10;
            }
        }
    }
    while (i < t.size() && t[i] == ' ') ++i;
    std::string tail = t.substr(i);
    if (!(tail.empty() || tail == "Z" || tail == "UTC" || tail == "utc")) return fail(err, "unexpected text after date");
    if (mo < 1 || mo > 12 || d < 1 || d > days_in_month(y, unsigned(mo))) return fail(err, "invalid date");
    if (h > 23 || mi > 59 || s > 59) return fail(err, "invalid time");
    secs = days_from_civil(y, unsigned(mo), unsigned(d)) * 86400 + h * 3600 + mi * 60 + s;
    return true;
}

constexpr int64_t kFileTimeEpochDelta = 11644473600;  // seconds 1601-01-01 -> 1970-01-01

// DOS: time = hhhhhmmmmmmsssss (2s units), date = yyyyyyymmmmddddd (years since 1980).
std::string fmt_dos(uint32_t v) {
    unsigned time = v & 0xFFFF, date = v >> 16;
    unsigned sec = (time & 0x1F) * 2, min = (time >> 5) & 0x3F, hour = time >> 11;
    unsigned day = date & 0x1F, mon = (date >> 5) & 0xF, year = 1980 + (date >> 9);
    if (mon < 1 || mon > 12 || day < 1 || day > days_in_month(year, mon) || hour > 23 || min > 59 || sec > 59)
        return "-";
    char buf[32];
    std::snprintf(buf, sizeof buf, "%04u-%02u-%02u %02u:%02u:%02u", year, mon, day, hour, min, sec);
    return buf;
}

// ---- GUID -------------------------------------------------------------------------------------

std::string fmt_guid(const uint8_t* p, bool be) {
    char buf[48];
    std::snprintf(buf, sizeof buf, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", unsigned(load(p, 4, be)),
                  unsigned(load(p + 4, 2, be)), unsigned(load(p + 6, 2, be)), p[8], p[9], p[10], p[11], p[12],
                  p[13], p[14], p[15]);
    return buf;
}

bool parse_guid(const std::string& text, bool be, std::vector<uint8_t>& out, std::string* err) {
    std::string t = trim(text);
    if (t.size() >= 2 && t.front() == '{' && t.back() == '}') t = t.substr(1, t.size() - 2);
    std::string hex;
    for (char c : t) {
        if (c == '-') continue;
        if (!std::isxdigit(static_cast<unsigned char>(c))) return fail(err, "invalid GUID");
        hex += c;
    }
    if (hex.size() != 32) return fail(err, "GUID needs 32 hex digits");
    uint8_t raw[16];
    for (int i = 0; i < 16; ++i) {
        unsigned v = 0;
        std::from_chars(hex.data() + 2 * i, hex.data() + 2 * i + 2, v, 16);
        raw[i] = uint8_t(v);
    }
    // raw is the text order (big-endian fields); the first 3 fields are stored little-endian unless `be`.
    out.assign(raw, raw + 16);
    if (!be) {
        std::swap(out[0], out[3]);
        std::swap(out[1], out[2]);
        std::swap(out[4], out[5]);
        std::swap(out[6], out[7]);
    }
    return true;
}

const char* type_name(InspType t) {
    switch (t) {
    case InspType::Bin8: return "binary";
    case InspType::I8: return "int8";
    case InspType::U8: return "uint8";
    case InspType::I16: return "int16";
    case InspType::U16: return "uint16";
    case InspType::I24: return "int24";
    case InspType::U24: return "uint24";
    case InspType::I32: return "int32";
    case InspType::U32: return "uint32";
    case InspType::I64: return "int64";
    case InspType::U64: return "uint64";
    case InspType::F16: return "float16";
    case InspType::F32: return "float32";
    case InspType::F64: return "float64";
    case InspType::Ascii: return "ASCII";
    case InspType::Utf8: return "UTF-8";
    case InspType::Utf16: return "UTF-16";
    case InspType::ULEB128: return "ULEB128";
    case InspType::SLEB128: return "SLEB128";
    case InspType::ZigZag: return "ZigZag";
    case InspType::Unix32: return "Unix time32";
    case InspType::Unix64: return "Unix time64";
    case InspType::FileTime: return "FILETIME";
    case InspType::DosDateTime: return "DOS date/time";
    case InspType::Guid: return "GUID";
    default: return "?";
    }
}

struct IntInfo {
    size_t bytes;
    bool is_signed;
};

bool int_info(InspType t, IntInfo& info) {
    switch (t) {
    case InspType::I8: info = {1, true}; return true;
    case InspType::U8: info = {1, false}; return true;
    case InspType::I16: info = {2, true}; return true;
    case InspType::U16: info = {2, false}; return true;
    case InspType::I24: info = {3, true}; return true;
    case InspType::U24: info = {3, false}; return true;
    case InspType::I32: info = {4, true}; return true;
    case InspType::U32: info = {4, false}; return true;
    case InspType::I64: info = {8, true}; return true;
    case InspType::U64: info = {8, false}; return true;
    default: return false;
    }
}

InspRow inspect_one(InspType t, const uint8_t* p, size_t avail, bool be) {
    InspRow r{t, type_name(t), "", 0, true};
    auto need = [&](size_t n) { return avail >= n; };
    IntInfo ii;
    if (int_info(t, ii)) {
        if (!need(ii.bytes)) return r;
        uint64_t v = load(p, ii.bytes, be);
        r.value = ii.is_signed ? std::to_string(sign_extend(v, unsigned(ii.bytes * 8))) : std::to_string(v);
        r.size = ii.bytes;
        return r;
    }
    switch (t) {
    case InspType::Bin8:
        if (!need(1)) return r;
        for (int i = 7; i >= 0; --i) r.value += (p[0] >> i) & 1 ? '1' : '0';
        r.size = 1;
        break;
    case InspType::F16:
        if (!need(2)) return r;
        r.value = fmt_half(uint16_t(load(p, 2, be)));
        r.size = 2;
        break;
    case InspType::F32: {
        if (!need(4)) return r;
        uint32_t bits = uint32_t(load(p, 4, be));
        float f;
        std::memcpy(&f, &bits, 4);
        r.value = fmt_shortest(f);
        r.size = 4;
        break;
    }
    case InspType::F64: {
        if (!need(8)) return r;
        uint64_t bits = load(p, 8, be);
        double d;
        std::memcpy(&d, &bits, 8);
        r.value = fmt_shortest(d);
        r.size = 8;
        break;
    }
    case InspType::Ascii: {
        if (!need(1)) return r;
        uint8_t b = p[0];
        if (b > 0x20 && b < 0x7F) {
            r.value = std::string(1, char(b));
        } else {
            char buf[16];
            std::snprintf(buf, sizeof buf, ". (0x%02X)", b);
            r.value = buf;
        }
        r.size = 1;
        break;
    }
    case InspType::Utf8: {
        uint32_t cp;
        size_t n = utf8_decode(p, avail, cp);
        if (n == 0) return r;
        if (n == SIZE_MAX) {
            r.value = "-";
            return r;
        }
        r.value = fmt_codepoint(cp);
        r.size = n;
        break;
    }
    case InspType::Utf16: {
        if (!need(2)) return r;
        uint32_t u = uint32_t(load(p, 2, be));
        if (u >= 0xDC00 && u <= 0xDFFF) {
            r.value = "-";
            return r;
        }
        if (u >= 0xD800 && u <= 0xDBFF) {
            if (!need(4)) return r;
            uint32_t lo = uint32_t(load(p + 2, 2, be));
            if (lo < 0xDC00 || lo > 0xDFFF) {
                r.value = "-";
                return r;
            }
            r.value = fmt_codepoint(0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00));
            r.size = 4;
        } else {
            r.value = fmt_codepoint(u);
            r.size = 2;
        }
        break;
    }
    case InspType::ULEB128:
    case InspType::ZigZag: {
        uint64_t v;
        size_t n = uleb_decode(p, avail, v);
        if (n == 0) return r;
        if (n == SIZE_MAX) {
            r.value = "-";
            return r;
        }
        if (t == InspType::ULEB128) r.value = std::to_string(v);
        else r.value = std::to_string(int64_t(v >> 1) ^ -int64_t(v & 1));
        r.size = n;
        break;
    }
    case InspType::SLEB128: {
        int64_t v;
        size_t n = sleb_decode(p, avail, v);
        if (n == 0) return r;
        if (n == SIZE_MAX) {
            r.value = "-";
            return r;
        }
        r.value = std::to_string(v);
        r.size = n;
        break;
    }
    case InspType::Unix32:
        if (!need(4)) return r;
        r.value = fmt_datetime(sign_extend(load(p, 4, be), 32), 0, true);
        r.size = 4;
        break;
    case InspType::Unix64:
        if (!need(8)) return r;
        r.value = fmt_datetime(int64_t(load(p, 8, be)), 0, true);
        r.size = 8;
        break;
    case InspType::FileTime: {
        if (!need(8)) return r;
        uint64_t v = load(p, 8, be);
        r.value = fmt_datetime(int64_t(v / 10000000) - kFileTimeEpochDelta, uint32_t(v % 10000000), true);
        r.size = 8;
        break;
    }
    case InspType::DosDateTime:
        if (!need(4)) return r;
        r.value = fmt_dos(uint32_t(load(p, 4, be)));
        r.size = 4;
        break;
    case InspType::Guid:
        if (!need(16)) return r;
        r.value = fmt_guid(p, be);
        r.size = 16;
        break;
    default:
        r.editable = false;
        break;
    }
    if (r.value == "-") r.size = 0;  // decodable length but invalid value
    return r;
}

}  // namespace

std::vector<InspRow> inspect(const uint8_t* data, size_t avail, bool big_endian) {
    std::vector<InspRow> rows;
    rows.reserve(size_t(InspType::Count));
    if (!data) avail = 0;
    for (int i = 0; i < int(InspType::Count); ++i) rows.push_back(inspect_one(InspType(i), data, avail, big_endian));
    return rows;
}

bool inspector_encode(InspType type, const std::string& text, bool big_endian, std::vector<uint8_t>& out,
                      std::string* err) {
    out.clear();
    const bool be = big_endian;
    IntInfo ii;
    if (int_info(type, ii)) {
        uint64_t v;
        unsigned bits = unsigned(ii.bytes * 8);
        if (!(ii.is_signed ? parse_sint_bits(text, bits, v, err) : parse_uint_bits(text, bits, v, err))) return false;
        store(out, v, ii.bytes, be);
        return true;
    }
    switch (type) {
    case InspType::Bin8: {
        std::string t;
        for (char c : trim(text))
            if (c != ' ' && c != '_') t += c;
        if (t.size() > 2 && t[0] == '0' && (t[1] == 'b' || t[1] == 'B')) t.erase(0, 2);
        if (t.empty() || t.size() > 8) return fail(err, "expected up to 8 binary digits");
        unsigned v = 0;
        for (char c : t) {
            if (c != '0' && c != '1') return fail(err, "expected binary digits");
            v = v << 1 | unsigned(c - '0');
        }
        out.push_back(uint8_t(v));
        return true;
    }
    case InspType::F16: {
        double d;
        uint16_t h;
        if (!parse_double(text, d)) return fail(err, "not a number");
        if (!double_to_half(d, h)) return fail(err, "out of range for float16");
        store(out, h, 2, be);
        return true;
    }
    case InspType::F32: {
        // Parse as float directly (correct rounding; no double->float double rounding).
        std::string t = trim(text);
        if (!t.empty() && t[0] == '+') t.erase(0, 1);
        float f = 0;
        auto r = std::from_chars(t.data(), t.data() + t.size(), f);
        if (t.empty() || r.ptr != t.data() + t.size()) return fail(err, "not a number");
        if (r.ec == std::errc::result_out_of_range) {  // overflow is an error, underflow -> 0 / subnormal
            double d;
            if (!parse_double(t, d) || std::fabs(d) > double(std::numeric_limits<float>::max()))
                return fail(err, "out of range for float32");
            f = float(d);
        } else if (r.ec != std::errc()) {
            return fail(err, "not a number");
        }
        uint32_t bits;
        std::memcpy(&bits, &f, 4);
        store(out, bits, 4, be);
        return true;
    }
    case InspType::F64: {
        double d;
        if (!parse_double(text, d)) return fail(err, "not a number");
        uint64_t bits;
        std::memcpy(&bits, &d, 8);
        store(out, bits, 8, be);
        return true;
    }
    case InspType::Ascii:
        if (text.size() != 1 || static_cast<unsigned char>(text[0]) >= 0x80)
            return fail(err, "expected one ASCII character");
        out.push_back(uint8_t(text[0]));
        return true;
    case InspType::Utf8: {
        uint32_t cp;
        if (!parse_codepoint(text, cp, err)) return false;
        std::string s;
        append_utf8(s, cp);
        out.assign(s.begin(), s.end());
        return true;
    }
    case InspType::Utf16: {
        uint32_t cp;
        if (!parse_codepoint(text, cp, err)) return false;
        std::vector<uint8_t> unit;
        if (cp >= 0x10000) {
            cp -= 0x10000;
            store(out, 0xD800 + (cp >> 10), 2, be);
            store(unit, 0xDC00 + (cp & 0x3FF), 2, be);
            out.insert(out.end(), unit.begin(), unit.end());
        } else {
            store(out, cp, 2, be);
        }
        return true;
    }
    case InspType::ULEB128: {
        uint64_t v;
        if (!parse_uint_bits(text, 64, v, err)) return false;
        uleb_encode(v, out);
        return true;
    }
    case InspType::SLEB128:
    case InspType::ZigZag: {
        uint64_t bits;
        if (!parse_sint_bits(text, 64, bits, err)) return false;
        int64_t v = int64_t(bits);
        if (type == InspType::SLEB128) sleb_encode(v, out);
        else uleb_encode((uint64_t(v) << 1) ^ uint64_t(v >> 63), out);
        return true;
    }
    case InspType::Unix32:
    case InspType::Unix64:
    case InspType::FileTime:
    case InspType::DosDateTime: {
        int64_t secs;
        uint32_t frac;
        if (!parse_datetime(text, secs, frac, err)) return false;
        if (type == InspType::Unix32) {
            if (secs < INT32_MIN || secs > INT32_MAX) return fail(err, "out of range for 32-bit time");
            store(out, uint64_t(secs) & 0xFFFFFFFF, 4, be);
        } else if (type == InspType::Unix64) {
            store(out, uint64_t(secs), 8, be);
        } else if (type == InspType::FileTime) {
            if (secs < -kFileTimeEpochDelta) return fail(err, "FILETIME starts at 1601");
            uint64_t v = uint64_t(secs + kFileTimeEpochDelta) * 10000000 + frac;
            store(out, v, 8, be);
        } else {
            int64_t days = secs >= 0 ? secs / 86400 : -((-secs + 86399) / 86400);
            int64_t rem = secs - days * 86400, y;
            unsigned m, d;
            civil_from_days(days, y, m, d);
            if (y < 1980 || y > 2107) return fail(err, "DOS dates cover 1980..2107");
            uint32_t time = uint32_t((rem / 3600) << 11 | (rem / 60 % 60) << 5 | (rem % 60) / 2);
            uint32_t date = uint32_t((y - 1980) << 9 | int64_t(m) << 5 | int64_t(d));
            store(out, uint64_t(date) << 16 | time, 4, be);
        }
        return true;
    }
    case InspType::Guid:
        return parse_guid(text, be, out, err);
    default:
        return fail(err, "not editable");
    }
}

bool insp_int_type(InspType type, int& width, bool& is_signed) {
    IntInfo ii{};
    if (!int_info(type, ii)) return false;
    width = int(ii.bytes);
    is_signed = ii.is_signed;
    return true;
}

InspType insp_type_of_int(int width, bool is_signed) {
    for (int i = 0; i < int(InspType::Count); ++i) {
        int w = 0;
        bool s = false;
        if (insp_int_type(InspType(i), w, s) && w == width && s == is_signed) return InspType(i);
    }
    return InspType::Count;
}

}  // namespace hx
