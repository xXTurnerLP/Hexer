#include "core/util.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <limits>

#include "core/hex_tokens.h"

namespace hx {

// ---- formatting -------------------------------------------------------------------------------

std::string fmt_hex(uint64_t v, int min_digits, bool upper) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char buf[16];
    int n = 0;
    do {
        buf[n++] = digits[v & 0xF];
        v >>= 4;
    } while (v);
    std::string s;
    if (min_digits > n) s.assign(size_t(min_digits - n), '0');
    while (n) s += buf[--n];
    return s;
}

std::string fmt_size(uint64_t bytes) {
    if (bytes < 1024) return std::to_string(bytes) + " B";
    static const char* units[] = {"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    double v = double(bytes) / 1024.0;
    int u = 0;
    while (v >= 1024.0 && u < 5) {
        v /= 1024.0;
        ++u;
    }
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.2f %s", v, units[u]);
    return buf;
}

// ---- goto expressions -------------------------------------------------------------------------
// Grammar (whitespace allowed between tokens):
//   input   := [('+'|'-')] sum          leading sign => relative to `current`
//   sum     := product (('+'|'-') product)*
//   product := unary (('*'|'/') unary)*
//   unary   := ('+'|'-') unary | primary
//   primary := number ['%'] | 'end' | 'eof' | 'cur' | '.' | '(' sum ')'
// Evaluated in checked int64 arithmetic (file offsets never reach 2^63).

namespace {

struct ExprParser {
    ExprParser(const std::string& text, uint64_t cur, uint64_t sz, bool hex)
        : s(text), current(cur), size(sz), default_hex(hex) {}

    const std::string& s;
    uint64_t current, size;
    bool default_hex;
    size_t pos = 0;
    std::string error;

    static constexpr int64_t kMax = std::numeric_limits<int64_t>::max();
    static constexpr int64_t kMin = std::numeric_limits<int64_t>::min();

    bool fail(const std::string& msg) {
        if (error.empty()) error = msg;
        return false;
    }
    bool overflow() { return fail("value too large"); }

    void skip_ws() {
        while (pos < s.size() && std::isspace(static_cast<unsigned char>(s[pos]))) ++pos;
    }
    char peek() {
        skip_ws();
        return pos < s.size() ? s[pos] : '\0';
    }
    std::string here() const {
        std::string r = "'";
        r += s[pos];
        r += "' at position " + std::to_string(pos + 1);
        return r;
    }

    bool add(int64_t a, int64_t b, int64_t& r) {
        if ((b > 0 && a > kMax - b) || (b < 0 && a < kMin - b)) return overflow();
        r = a + b;
        return true;
    }
    bool sub(int64_t a, int64_t b, int64_t& r) {
        if ((b < 0 && a > kMax + b) || (b > 0 && a < kMin + b)) return overflow();
        r = a - b;
        return true;
    }
    bool mul(int64_t a, int64_t b, int64_t& r) {
        uint64_t ua = a < 0 ? 0 - uint64_t(a) : uint64_t(a);
        uint64_t ub = b < 0 ? 0 - uint64_t(b) : uint64_t(b);
        if (ub != 0 && ua > uint64_t(kMax) / ub) return overflow();
        r = a * b;  // |a*b| <= kMax, no overflow
        return true;
    }

    static int64_t clamp64(uint64_t v) { return v > uint64_t(kMax) ? kMax : int64_t(v); }

    // Parses a whole number token into `out` (and handles a trailing '%').
    bool number(int64_t& out) {
        size_t start = pos;
        int base = 0;  // 0 = decide from suffix / default
        bool prefixed = false;
        if (s[pos] == '$') {
            base = 16;
            prefixed = true;
            ++pos;
        } else if (s[pos] == '#') {
            base = 10;
            prefixed = true;
            ++pos;
        } else if (s[pos] == '0' && pos + 1 < s.size() && (s[pos + 1] == 'x' || s[pos + 1] == 'X')) {
            base = 16;
            prefixed = true;
            pos += 2;
        }
        size_t tok = pos;
        while (pos < s.size() && (std::isalnum(static_cast<unsigned char>(s[pos])) || s[pos] == '_')) ++pos;
        std::string body = s.substr(tok, pos - tok);
        // Percent: a decimal number (optionally fractional) followed by '%'.
        bool frac = false;
        std::string frac_digits;
        if (!prefixed && pos < s.size() && s[pos] == '.') {
            size_t p = pos + 1;
            while (p < s.size() && std::isdigit(static_cast<unsigned char>(s[p]))) ++p;
            size_t q = p;
            while (q < s.size() && std::isspace(static_cast<unsigned char>(s[q]))) ++q;
            if (q < s.size() && s[q] == '%') {
                frac = true;
                frac_digits = s.substr(pos + 1, p - pos - 1);
                pos = p;
            }
        }
        size_t after = pos;
        skip_ws();
        if (!prefixed && pos < s.size() && s[pos] == '%') {
            ++pos;
            return percent(body, frac_digits, start, out);
        }
        if (frac) return fail("invalid number at position " + std::to_string(start + 1));
        pos = after;

        if (base == 0 && body.size() > 1) {
            char last = body.back();
            std::string rest = body.substr(0, body.size() - 1);
            bool all_dec = std::all_of(rest.begin(), rest.end(),
                                       [](char c) { return c >= '0' && c <= '9'; });
            if (last == 'h' || last == 'H') {
                base = 16;
                body = rest;
            } else if ((last == 'd' || last == 'D') && all_dec) {
                base = 10;
                body = rest;
            }
        }
        if (base == 0) base = default_hex ? 16 : 10;
        if (body.empty())
            return fail("missing digits at position " + std::to_string(start + 1));
        uint64_t v = 0;
        for (char c : body) {
            int d = detail::hex_nibble(c);
            if (d < 0 || d >= base)
                return fail("invalid " + std::string(base == 16 ? "hex" : "decimal") + " number '" +
                            s.substr(start, pos - start) + "'");
            if (v > (uint64_t(kMax) - uint64_t(d)) / uint64_t(base)) return overflow();
            v = v * uint64_t(base) + uint64_t(d);
        }
        out = int64_t(v);
        return true;
    }

    // size * (int.frac) / 100, exact integer math.
    bool percent(const std::string& ip, const std::string& fp, size_t start, int64_t& out) {
        if (ip.empty() && fp.empty()) return fail("missing digits at position " + std::to_string(start + 1));
        if (fp.size() > 6) return fail("too many decimals in percentage");
        uint64_t num = 0, den = 100;
        for (char c : ip + fp) {
            if (c < '0' || c > '9') return fail("invalid percentage at position " + std::to_string(start + 1));
            num = num * 10 + uint64_t(c - '0');
            if (num > 1000000000000ull) return overflow();
        }
        for (size_t i = 0; i < fp.size(); ++i) den *= 10;
        uint64_t sz = uint64_t(clamp64(size));
        uint64_t q = sz / den, r = sz % den;  // size*num/den = q*num + r*num/den
        if (q && num > uint64_t(kMax) / q) return overflow();
        uint64_t a = q * num;
        uint64_t b = r * num / den;  // r < den <= 1e8, num <= 1e12 -> fits
        if (a > uint64_t(kMax) - b) return overflow();
        out = int64_t(a + b);
        return true;
    }

    bool primary(int64_t& out) {
        char c = peek();
        if (c == '\0') return fail("unexpected end of expression");
        if (c == '(') {
            ++pos;
            if (!sum(out)) return false;
            if (peek() != ')') return fail("missing ')'");
            ++pos;
            return true;
        }
        if (c == '.' && !(pos + 1 < s.size() && std::isdigit(static_cast<unsigned char>(s[pos + 1])))) {
            ++pos;
            out = clamp64(current);
            return true;
        }
        if (std::isalpha(static_cast<unsigned char>(c))) {
            size_t p = pos;
            while (p < s.size() && std::isalnum(static_cast<unsigned char>(s[p]))) ++p;
            std::string word = s.substr(pos, p - pos);
            std::transform(word.begin(), word.end(), word.begin(),
                           [](char ch) { return char(std::tolower(static_cast<unsigned char>(ch))); });
            if (word == "end" || word == "eof") {
                pos = p;
                out = clamp64(size);
                return true;
            }
            if (word == "cur") {
                pos = p;
                out = clamp64(current);
                return true;
            }
            // otherwise it may be a hex number like "ff" / "1F00h"; fall through
        }
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '$' || c == '#' || c == '.') return number(out);
        return fail("unexpected " + here());
    }

    bool unary(int64_t& out) {
        char c = peek();
        if (c == '+' || c == '-') {
            ++pos;
            int64_t v;
            if (!unary(v)) return false;
            if (c == '-') {
                if (v == kMin) return overflow();
                v = -v;
            }
            out = v;
            return true;
        }
        return primary(out);
    }

    bool product(int64_t& out) {
        if (!unary(out)) return false;
        for (;;) {
            char c = peek();
            if (c != '*' && c != '/') return true;
            ++pos;
            int64_t rhs;
            if (!unary(rhs)) return false;
            if (c == '*') {
                if (!mul(out, rhs, out)) return false;
            } else {
                if (rhs == 0) return fail("division by zero");
                if (out == kMin && rhs == -1) return overflow();
                out /= rhs;
            }
        }
    }

    // Continues a sum whose value so far is `acc`.
    bool sum_tail(int64_t& acc) {
        for (;;) {
            char c = peek();
            if (c != '+' && c != '-') return true;
            ++pos;
            int64_t rhs;
            if (!product(rhs)) return false;
            if (!(c == '+' ? add(acc, rhs, acc) : sub(acc, rhs, acc))) return false;
        }
    }

    bool sum(int64_t& out) { return product(out) && sum_tail(out); }

    bool top(int64_t& out) {
        if (peek() == '\0') return fail("empty expression");
        char c = peek();
        if (c == '+' || c == '-') {
            // Relative: "-0x10+4" == "cur - 0x10 + 4".
            out = clamp64(current);
            if (!sum_tail(out)) return false;
        } else if (!sum(out)) {
            return false;
        }
        skip_ws();
        if (pos != s.size()) return fail("unexpected " + here());
        return true;
    }
};

}  // namespace

bool parse_offset(const std::string& expr, uint64_t current, uint64_t size, bool default_hex,
                  uint64_t& out, std::string* err) {
    ExprParser p(expr, current, size, default_hex);
    int64_t v = 0;
    if (!p.top(v)) {
        if (err) *err = p.error;
        return false;
    }
    if (v < 0) {
        if (err) *err = "offset is before the start of the file";
        return false;
    }
    if (uint64_t(v) > size) {
        if (err) *err = "offset 0x" + fmt_hex(uint64_t(v)) + " is beyond the end (size 0x" + fmt_hex(size) + ")";
        return false;
    }
    out = uint64_t(v);
    return true;
}

// ---- copy as ----------------------------------------------------------------------------------

const char* copy_format_name(CopyFormat f) {
    switch (f) {
    case CopyFormat::HexSpaced: return "Hex (spaced)";
    case CopyFormat::HexCompact: return "Hex (compact)";
    case CopyFormat::CArray: return "C array";
    case CopyFormat::PythonBytes: return "Python bytes";
    case CopyFormat::Base64: return "Base64";
    case CopyFormat::EscapedString: return "Escaped string";
    case CopyFormat::Text: return "Text";
    default: return "?";
    }
}

namespace {
const char kHexUp[] = "0123456789ABCDEF";
const char kHexLo[] = "0123456789abcdef";

void put_hex(std::string& s, uint8_t b, const char* digits) {
    s += digits[b >> 4];
    s += digits[b & 0xF];
}
}  // namespace

std::string copy_as(const uint8_t* data, size_t len, CopyFormat f) {
    std::string s;
    switch (f) {
    case CopyFormat::HexSpaced:
        s.reserve(len * 3);
        for (size_t i = 0; i < len; ++i) {
            if (i) s += ' ';
            put_hex(s, data[i], kHexUp);
        }
        break;
    case CopyFormat::HexCompact:
        s.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) put_hex(s, data[i], kHexUp);
        break;
    case CopyFormat::CArray:
        if (len == 0) return "{ }";
        if (len <= 16) {
            s = "{ ";
            for (size_t i = 0; i < len; ++i) {
                if (i) s += ", ";
                s += "0x";
                put_hex(s, data[i], kHexUp);
            }
            s += " }";
        } else {
            s.reserve(len * 6 + len / 16 * 6 + 4);
            s = "{\n";
            for (size_t i = 0; i < len; ++i) {
                if (i % 16 == 0) s += "    ";
                s += "0x";
                put_hex(s, data[i], kHexUp);
                if (i + 1 < len) s += (i % 16 == 15) ? ",\n" : ", ";
            }
            s += "\n}";
        }
        break;
    case CopyFormat::PythonBytes:
        s = "b\"";
        for (size_t i = 0; i < len; ++i) {
            uint8_t b = data[i];
            if (b == '"' || b == '\\') {
                s += '\\';
                s += char(b);
            } else if (b >= 0x20 && b < 0x7F) {
                s += char(b);
            } else {
                s += "\\x";
                put_hex(s, b, kHexLo);
            }
        }
        s += '"';
        break;
    case CopyFormat::Base64:
        return base64_encode(data, len);
    case CopyFormat::EscapedString: {
        s = "\"";
        bool after_hex = false;  // C hex escapes are greedy: "\x41" + "B" would merge
        for (size_t i = 0; i < len; ++i) {
            uint8_t b = data[i];
            const char* esc = nullptr;
            switch (b) {
            case '\n': esc = "\\n"; break;
            case '\r': esc = "\\r"; break;
            case '\t': esc = "\\t"; break;
            case '\\': esc = "\\\\"; break;
            case '"': esc = "\\\""; break;
            default: break;
            }
            if (esc) {
                s += esc;
                after_hex = false;
            } else if (b >= 0x20 && b < 0x7F && !(after_hex && detail::hex_nibble(char(b)) >= 0)) {
                s += char(b);
                after_hex = false;
            } else {
                s += "\\x";
                put_hex(s, b, kHexLo);
                after_hex = true;
            }
        }
        s += '"';
        break;
    }
    case CopyFormat::Text:
        s.assign(reinterpret_cast<const char*>(data), len);
        std::replace(s.begin(), s.end(), '\0', '.');
        break;
    default:
        break;
    }
    return s;
}

// ---- base64 -----------------------------------------------------------------------------------

std::string base64_encode(const uint8_t* data, size_t len) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string s;
    s.reserve((len + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        uint32_t v = uint32_t(data[i]) << 16 | uint32_t(data[i + 1]) << 8 | data[i + 2];
        s += tbl[v >> 18];
        s += tbl[(v >> 12) & 63];
        s += tbl[(v >> 6) & 63];
        s += tbl[v & 63];
    }
    if (len - i == 1) {
        uint32_t v = uint32_t(data[i]) << 16;
        s += tbl[v >> 18];
        s += tbl[(v >> 12) & 63];
        s += "==";
    } else if (len - i == 2) {
        uint32_t v = uint32_t(data[i]) << 16 | uint32_t(data[i + 1]) << 8;
        s += tbl[v >> 18];
        s += tbl[(v >> 12) & 63];
        s += tbl[(v >> 6) & 63];
        s += '=';
    }
    return s;
}

// Accepts the standard and URL-safe alphabets, ignores whitespace, padding optional.
bool base64_decode(const std::string& in, std::vector<uint8_t>& out) {
    out.clear();
    uint32_t acc = 0;
    int bits = 0;
    size_t pad = 0;
    for (char c : in) {
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+' || c == '-') v = 62;
        else if (c == '/' || c == '_') v = 63;
        else if (c == '=') { ++pad; continue; }
        else if (std::isspace(static_cast<unsigned char>(c))) continue;
        else return false;
        if (pad) return false;  // data after padding
        acc = (acc << 6) | uint32_t(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(uint8_t(acc >> bits));
            acc &= (1u << bits) - 1;
        }
    }
    if (bits >= 6) return false;  // a single dangling character carries < 1 byte
    if (pad > 2) return false;
    return true;
}

// ---- lenient paste parsing --------------------------------------------------------------------

bool parse_bytes(const std::string& text, std::vector<uint8_t>& out, std::string* err) {
    size_t b = 0, e = text.size();
    while (b < e && std::isspace(static_cast<unsigned char>(text[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(text[e - 1]))) --e;
    std::string t = text.substr(b, e - b);
    if (t.size() >= 4 && (t[0] == 'b' || t[0] == 'B') && (t[1] == '6') && t[2] == '4' && t[3] == ':') {
        if (!base64_decode(t.substr(4), out) || out.empty()) {
            out.clear();
            if (err) *err = "invalid base64";
            return false;
        }
        return true;
    }
    std::vector<uint8_t> mask;
    if (!detail::parse_hex_tokens(t, false, out, mask, err)) {
        out.clear();
        return false;
    }
    return true;
}

// ---- fuzzy matching ---------------------------------------------------------------------------
// Best-alignment subsequence match (small DP; command names are short).

int fuzzy_score(const std::string& pattern, const std::string& text) {
    const size_t m = pattern.size(), n = text.size();
    if (m == 0) return 0;
    if (m > n) return -1;
    auto lower = [](char c) { return char(std::tolower(static_cast<unsigned char>(c))); };
    auto word_start = [&](size_t j) {
        if (j == 0) return true;
        char p = text[j - 1], c = text[j];
        if (p == ' ' || p == '_' || p == '-' || p == '.' || p == ':' || p == '/' || p == '\\' || p == '(')
            return true;
        return std::islower(static_cast<unsigned char>(p)) && std::isupper(static_cast<unsigned char>(c));
    };
    constexpr int kMatch = 10, kConsecutive = 20, kWordStart = 20, kPrefix = 15;
    constexpr int kNone = std::numeric_limits<int>::min() / 2;
    // prev[j] = best score with pattern[i-1] matched at text[j].
    std::vector<int> prev(n, kNone), cur(n, kNone);
    for (size_t i = 0; i < m; ++i) {
        const char pc = lower(pattern[i]);
        int run = kNone;  // max over k < j-1 of prev[k] + k  (for the gap penalty)
        for (size_t j = 0; j < n; ++j) {
            cur[j] = kNone;
            if (i > 0 && j >= 2 && prev[j - 2] > kNone) run = std::max(run, prev[j - 2] + int(j - 2));
            if (lower(text[j]) != pc) continue;
            int bonus = kMatch + (word_start(j) ? kWordStart : 0);
            if (i == 0) {
                cur[j] = bonus + (j == 0 ? kPrefix : 0) - int(std::min<size_t>(j, 20));
                continue;
            }
            int best = kNone;
            if (j >= 1 && prev[j - 1] > kNone) best = prev[j - 1] + kConsecutive;
            if (run > kNone) best = std::max(best, run - int(j - 1));  // gap of j-k-1 chars
            if (best > kNone) cur[j] = best + bonus;
        }
        std::swap(prev, cur);
    }
    int best = kNone;
    for (size_t j = 0; j < n; ++j) best = std::max(best, prev[j]);
    if (best == kNone) return -1;
    best -= int(std::min<size_t>(n - m, 30)) / 3;  // slight preference for shorter texts
    return std::max(best, 0);
}

}  // namespace hx
