// C struct definitions -> Lua parser source. Tokenizer (with #define / #pragma pack / @be-@le
// annotations), a recursive-descent parser building a small model, and a code generator that
// computes the layout (alignment, bit-field units, unions) while it writes the Lua.
#include "core/cstruct.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace hx {
namespace {

// ---- errors (internal only: cstruct_to_lua catches them) ------------------------------------------

struct CError {
    std::string msg;
};

[[noreturn]] void fail(int line, const std::string& msg) {
    throw CError{line > 0 ? "line " + std::to_string(line) + ": " + msg : msg};
}

// ---- tokens -----------------------------------------------------------------------------------------

enum class Tk : uint8_t { End, Ident, Number, Punct, Str, Pack, Define };

struct Token {
    Tk kind = Tk::End;
    std::string text;         // identifier / punctuator / define name / pack op
    uint64_t num = 0;         // number value; pack value (0 = none)
    int line = 0;
    char annot = 0;           // 'b' / 'l': a `@be` / `@le` comment right before this token
    bool annot_inline = false;  // ... and that comment ends on this token's line
    std::vector<Token> body;  // Define: replacement tokens (+ End)
};

bool ident_start(char c) { return std::isalpha(static_cast<unsigned char>(c)) || c == '_'; }
bool ident_char(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; }

// `@be` / `@le` as a word inside a comment.
char comment_annot(const std::string& s) {
    for (size_t i = 0; i + 2 < s.size(); ++i) {
        if (s[i] != '@') continue;
        bool word_end = i + 3 >= s.size() || !ident_char(s[i + 3]);
        if (!word_end) continue;
        if (s.compare(i + 1, 2, "be") == 0) return 'b';
        if (s.compare(i + 1, 2, "le") == 0) return 'l';
    }
    return 0;
}

class Lexer {
public:
    Lexer(const std::string& s, int line, bool directive) : s_(s), line_(line), directive_(directive) {}

    std::vector<Token> run() {
        std::vector<Token> out;
        bool line_start = true;
        char pending = 0;
        int pending_line = 0;
        while (i_ < s_.size()) {
            char c = s_[i_];
            if (c == '\n') {
                ++line_;
                ++i_;
                line_start = true;
                continue;
            }
            if (c == '\\' && (at(1) == '\n' || (at(1) == '\r' && at(2) == '\n'))) {  // line continuation
                i_ += at(1) == '\n' ? 2 : 3;
                ++line_;
                continue;
            }
            if (std::isspace(static_cast<unsigned char>(c))) {
                ++i_;
                continue;
            }
            if (c == '/' && at(1) == '/') {
                size_t e = s_.find('\n', i_);
                if (e == std::string::npos) e = s_.size();
                if (char a = comment_annot(s_.substr(i_, e - i_))) {
                    pending = a;
                    pending_line = line_;
                }
                i_ = e;
                continue;
            }
            if (c == '/' && at(1) == '*') {
                size_t e = s_.find("*/", i_ + 2);
                if (e == std::string::npos) fail(line_, "unterminated comment");
                std::string body = s_.substr(i_, e - i_);
                line_ += int(std::count(body.begin(), body.end(), '\n'));
                if (char a = comment_annot(body)) {
                    pending = a;
                    pending_line = line_;
                }
                i_ = e + 2;
                continue;
            }
            if (c == '#' && line_start && !directive_) {
                directive(out);
                continue;
            }
            line_start = false;
            Token t;
            t.line = line_;
            t.annot = pending;
            t.annot_inline = pending && pending_line == line_;
            pending = 0;
            if (ident_start(c)) {
                size_t b = i_;
                while (i_ < s_.size() && ident_char(s_[i_])) ++i_;
                t.kind = Tk::Ident;
                t.text = s_.substr(b, i_ - b);
            } else if (std::isdigit(static_cast<unsigned char>(c))) {
                t.kind = Tk::Number;
                t.num = number();
            } else if (c == '\'') {
                t.kind = Tk::Number;
                t.num = char_literal();
            } else if (c == '"') {
                t.kind = Tk::Str;
                ++i_;
                while (i_ < s_.size() && s_[i_] != '"' && s_[i_] != '\n') i_ += s_[i_] == '\\' ? 2 : 1;
                if (i_ >= s_.size() || s_[i_] != '"') fail(line_, "unterminated string");
                ++i_;
            } else {
                t.kind = Tk::Punct;
                static const char* kTwo[] = {"<<", ">>", "::"};
                for (const char* two : kTwo)
                    if (c == two[0] && at(1) == two[1]) t.text = two;
                if (t.text.empty()) {
                    if (!std::strchr("{}()[];,:=*+-/%&|^~<>!?.", c))
                        fail(line_, std::string("unexpected character '") + c + "'");
                    t.text = std::string(1, c);
                }
                i_ += t.text.size();
            }
            out.push_back(std::move(t));
        }
        Token end;
        end.line = line_;
        out.push_back(end);
        return out;
    }

private:
    char at(size_t k) const { return i_ + k < s_.size() ? s_[i_ + k] : '\0'; }

    uint64_t number() {
        int base = 10;
        if (at(0) == '0' && (at(1) == 'x' || at(1) == 'X')) base = 16, i_ += 2;
        else if (at(0) == '0' && (at(1) == 'b' || at(1) == 'B')) base = 2, i_ += 2;
        else if (at(0) == '0' && std::isdigit(static_cast<unsigned char>(at(1)))) base = 8, ++i_;
        uint64_t v = 0;
        bool any = false, overflow = false;
        for (;; ++i_) {
            char c = at(0);
            int d = std::isdigit(static_cast<unsigned char>(c)) ? c - '0'
                    : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                    : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                                             : 99;
            if (c == '\'' && any) continue;  // C++14 digit separator
            if (d >= base) break;
            if (v > (UINT64_MAX - uint64_t(d)) / uint64_t(base)) overflow = true;
            v = v * uint64_t(base) + uint64_t(d);
            any = true;
        }
        while (at(0) == 'u' || at(0) == 'U' || at(0) == 'l' || at(0) == 'L') ++i_;
        if (!any || overflow || ident_char(at(0)) || at(0) == '.') fail(line_, "invalid number");
        return v;
    }

    uint64_t char_literal() {
        ++i_;
        uint64_t v = 0;
        if (at(0) == '\\') {
            char e = at(1);
            i_ += 2;
            switch (e) {
                case 'n': v = '\n'; break;
                case 'r': v = '\r'; break;
                case 't': v = '\t'; break;
                case '0': v = 0; break;
                case '\\': v = '\\'; break;
                case '\'': v = '\''; break;
                default: fail(line_, "unsupported escape in character literal");
            }
        } else {
            v = static_cast<unsigned char>(at(0));
            ++i_;
        }
        if (at(0) != '\'') fail(line_, "invalid character literal");
        ++i_;
        return v;
    }

    // `#...` up to the end of the (logical) line: #define and #pragma pack become tokens.
    void directive(std::vector<Token>& out) {
        int line = line_;
        size_t b = ++i_;
        while (i_ < s_.size() && s_[i_] != '\n') {
            if (s_[i_] == '\\' && (at(1) == '\n' || (at(1) == '\r' && at(2) == '\n'))) {
                i_ += at(1) == '\n' ? 2 : 3;
                ++line_;
                continue;
            }
            if (s_[i_] == '/' && at(1) == '*') {  // a block comment may span lines
                size_t e = s_.find("*/", i_ + 2);
                if (e == std::string::npos) fail(line_, "unterminated comment");
                line_ += int(std::count(s_.begin() + long(i_), s_.begin() + long(e), '\n'));
                i_ = e + 2;
                continue;
            }
            ++i_;
        }
        std::string text = s_.substr(b, i_ - b);
        size_t k = 0;
        while (k < text.size() && std::isspace(static_cast<unsigned char>(text[k]))) ++k;
        size_t w = k;
        while (k < text.size() && ident_char(text[k])) ++k;
        std::string word = text.substr(w, k - w);
        std::string rest = text.substr(k);
        if (word == "define") {
            size_t n = 0;
            while (n < rest.size() && std::isspace(static_cast<unsigned char>(rest[n]))) ++n;
            size_t ne = n;
            while (ne < rest.size() && ident_char(rest[ne])) ++ne;
            if (ne == n) fail(line, "#define without a name");
            if (ne < rest.size() && rest[ne] == '(') return;  // function-like macro: ignored
            Token t;
            t.kind = Tk::Define;
            t.line = line;
            t.text = rest.substr(n, ne - n);
            t.body = Lexer(rest.substr(ne), line, true).run();
            out.push_back(std::move(t));
        } else if (word == "pragma") {
            std::vector<Token> p = Lexer(rest, line, true).run();
            if (p.empty() || p[0].kind != Tk::Ident || p[0].text != "pack") return;
            Token t;
            t.kind = Tk::Pack;
            t.line = line;
            t.text = "reset";
            if (p.size() < 3 || p[1].text != "(") fail(line, "expected '(' after #pragma pack");
            for (size_t j = 2; j < p.size() && p[j].text != ")"; ++j) {
                if (p[j].kind == Tk::Ident && (p[j].text == "push" || p[j].text == "pop")) t.text = p[j].text;
                else if (p[j].kind == Tk::Number) t.num = p[j].num;
            }
            if (t.text == "reset" && t.num) t.text = "set";
            if (t.num && t.num != 1 && t.num != 2 && t.num != 4 && t.num != 8 && t.num != 16)
                fail(line, "#pragma pack value must be 1, 2, 4, 8 or 16");
            out.push_back(std::move(t));
        }
        // #include, #if, #pragma once, ...: ignored
    }

    const std::string& s_;
    size_t i_ = 0;
    int line_;
    bool directive_;
};

// ---- model ------------------------------------------------------------------------------------------

struct Prim {
    enum Kind : uint8_t { Int, Float, Char, Bool };
    int size = 4;
    bool is_signed = true;
    Kind kind = Int;
    char endian = 0;  // 'l' / 'b' for __le16 / __be32 ...; 0 = the struct's
};

struct Expr {
    bool is_const = true;
    int64_t value = 0;
    std::string lua;                 // Lua text (symbolic: define names, field locals)
    int prec = 9;                    // C precedence of the top operator (9 = atomic)
    std::vector<std::string> defs;   // #define names the Lua text mentions
};

struct Dim {
    bool flexible = false;           // `[]` / `[0]`: the rest of the data
    Expr count;
};

struct TypeRef {
    enum Kind : uint8_t { Prim, Struct, Enum } kind = Prim;
    hx::Prim prim{};
    int idx = -1;                    // struct / enum index
    std::vector<Dim> dims;           // from an array typedef
};

struct Member {
    std::string name;                // "" = anonymous struct/union (flattened) or unnamed bit field
    TypeRef type;
    std::vector<Dim> dims;
    int bits = -1;                   // bit-field width; -1 = not a bit field
    int line = 0;
    std::string lua_local;           // set when a later array size refers to this field
};

struct StructDef {
    std::string tag, typedef_name;
    bool is_union = false;
    bool complete = false;
    bool is_inline = false;          // unnamed, defined inside a member declaration
    int scope_parent = -1;           // inline: struct whose earlier fields are visible
    char endian = 'l';
    int pack = 0;                    // max alignment; 0 = natural
    int line = 0;
    std::vector<Member> members;
    std::string display() const { return typedef_name.empty() ? tag : typedef_name; }
};

struct EnumDef {
    std::string name;                // C name ("" = anonymous)
    std::string lua;                 // Lua table name
    hx::Prim prim{};
    std::vector<std::pair<int64_t, std::string>> items;
    bool used = false;
};

struct Define {
    std::vector<Token> body;
    int line = 0;
    bool evaluating = false;
    bool done = false;
    int64_t value = 0;
    std::string lua;                 // Lua local name
    bool used = false;
};

const char* const kLuaKeywords[] = {"and", "break", "do", "else", "elseif", "end", "false", "for", "function",
                                    "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return",
                                    "then", "true", "until", "while"};

bool is_lua_keyword(const std::string& s) {
    for (const char* k : kLuaKeywords)
        if (s == k) return true;
    return false;
}

std::string lua_quote(const std::string& s) {
    std::string o = "\"";
    for (char c : s) {
        unsigned char u = static_cast<unsigned char>(c);
        if (c == '"' || c == '\\') o += '\\', o += c;
        else if (u < 0x20 || u == 0x7F) {
            char b[8];
            std::snprintf(b, sizeof b, "\\%03u", unsigned(u));
            o += b;
        } else o += c;
    }
    return o + "\"";
}

std::string S(uint64_t v) { return std::to_string(v); }
std::string S(int64_t v) { return std::to_string(v); }
std::string S(int v) { return std::to_string(v); }

// Names that generated code uses inside parse functions; a field local may not shadow them.
bool reserved_name(const std::string& n) {
    static const char* const kNames[] = {"p", "math", "string", "tostring", "hx", "align", "bitfield", "BOOL"};
    for (const char* k : kNames)
        if (n == k) return true;
    auto numbered = [&](const char* pre) {
        size_t l = std::strlen(pre);
        if (n.compare(0, l, pre) != 0) return false;
        for (size_t i = l; i < n.size(); ++i)
            if (!std::isdigit(static_cast<unsigned char>(n[i]))) return false;
        return true;
    };
    return numbered("start") || numbered("bits") || n.rfind("parse_", 0) == 0;
}

struct PrimName {
    const char* name;
    Prim prim;
};

constexpr Prim kU8{1, false, Prim::Int, 0}, kI8{1, true, Prim::Int, 0}, kU16{2, false, Prim::Int, 0},
    kI16{2, true, Prim::Int, 0}, kU32{4, false, Prim::Int, 0}, kI32{4, true, Prim::Int, 0},
    kU64{8, false, Prim::Int, 0}, kI64{8, true, Prim::Int, 0}, kF32{4, true, Prim::Float, 0},
    kF64{8, true, Prim::Float, 0}, kBool{1, false, Prim::Bool, 0}, kChar{1, false, Prim::Char, 0};

const PrimName kPrims[] = {
    {"uint8_t", kU8}, {"u8", kU8}, {"BYTE", kU8}, {"UINT8", kU8}, {"UCHAR", kU8}, {"__u8", kU8},
    {"u_int8_t", kU8}, {"uchar", kU8},
    {"int8_t", kI8}, {"i8", kI8}, {"s8", kI8}, {"INT8", kI8}, {"__s8", kI8}, {"__int8", kI8},
    {"CHAR", kChar},
    {"uint16_t", kU16}, {"u16", kU16}, {"WORD", kU16}, {"UINT16", kU16}, {"USHORT", kU16}, {"__u16", kU16},
    {"u_int16_t", kU16}, {"ushort", kU16}, {"char16_t", kU16}, {"wchar_t", kU16}, {"WCHAR", kU16},
    {"int16_t", kI16}, {"i16", kI16}, {"s16", kI16}, {"INT16", kI16}, {"SHORT", kI16}, {"__s16", kI16},
    {"__int16", kI16},
    {"uint32_t", kU32}, {"u32", kU32}, {"DWORD", kU32}, {"UINT32", kU32}, {"UINT", kU32}, {"ULONG", kU32},
    {"__u32", kU32}, {"u_int32_t", kU32}, {"uint", kU32}, {"char32_t", kU32},
    {"int32_t", kI32}, {"i32", kI32}, {"s32", kI32}, {"INT32", kI32}, {"INT", kI32}, {"LONG", kI32},
    {"BOOL", kI32}, {"__s32", kI32}, {"__int32", kI32},
    {"uint64_t", kU64}, {"u64", kU64}, {"QWORD", kU64}, {"UINT64", kU64}, {"ULONGLONG", kU64},
    {"DWORD64", kU64}, {"__u64", kU64}, {"u_int64_t", kU64},
    {"int64_t", kI64}, {"i64", kI64}, {"s64", kI64}, {"INT64", kI64}, {"LONGLONG", kI64}, {"__s64", kI64},
    {"__int64", kI64},
    {"float", kF32}, {"f32", kF32}, {"FLOAT", kF32}, {"double", kF64}, {"f64", kF64}, {"DOUBLE", kF64},
    {"bool", kBool}, {"_Bool", kBool}, {"BOOLEAN", kBool},
    {"__le16", {2, false, Prim::Int, 'l'}}, {"__be16", {2, false, Prim::Int, 'b'}},
    {"__le32", {4, false, Prim::Int, 'l'}}, {"__be32", {4, false, Prim::Int, 'b'}},
    {"__le64", {8, false, Prim::Int, 'l'}}, {"__be64", {8, false, Prim::Int, 'b'}},
};

bool is_qualifier(const std::string& s) {
    static const char* const kQ[] = {"const", "volatile", "register", "static", "extern", "mutable",
                                     "__unaligned", "__restrict", "restrict", "__extension__", "inline"};
    for (const char* q : kQ)
        if (s == q) return true;
    return false;
}

bool is_multiword(const std::string& s) {
    return s == "signed" || s == "unsigned" || s == "short" || s == "long" || s == "int" || s == "char" ||
           s == "__signed__";
}

const char* const kAlignHelper =
    "-- Skips the padding natural alignment puts before a member (n = its alignment).\n"
    "local function align(p, start, n)\n"
    "    local r = (p:tell() - start) % n\n"
    "    if r ~= 0 then p:skip(math.min(n - r, p:remaining())) end\n"
    "end\n\n";

const char* const kBitfieldHelper =
    "-- Bit field: `width` bits at bit `shift` of a storage unit (`unit` = its value, read with\n"
    "-- p:peek), shown as a field over the unit's `size` bytes (opts.bitfield tells the C header\n"
    "-- export which bits). Returns the value.\n"
    "local function bitfield(p, name, unit, size, shift, width, opts)\n"
    "    opts = opts or {}\n"
    "    local v = (unit >> shift) & ((1 << width) - 1)\n"
    "    if opts.signed and v >> (width - 1) == 1 then v = v - (1 << width) end\n"
    "    local text\n"
    "    if opts.enum then\n"
    "        text = string.format(\"%d = %s\", v, opts.enum[v] or \"?\")\n"
    "    elseif v < 10 then\n"
    "        text = tostring(v)\n"
    "    else\n"
    "        text = string.format(\"%d (0x%X)\", v, v)\n"
    "    end\n"
    "    local bits = width == 1 and string.format(\"bit %d\", shift)\n"
    "        or string.format(\"bits %d..%d\", shift, shift + width - 1)\n"
    "    p:field(name, p:tell(), size, text,\n"
    "        { comment = bits, bitfield = { shift = shift, width = width, be = opts.be, signed = opts.signed } })\n"
    "    return v\n"
    "end\n\n";

// Generated code for a struct body / member, plus its layout.
struct Body {
    std::vector<std::string> lines;  // relative indentation
    bool fixed = true;
    uint64_t size = 0;               // fixed: exact size; else the size of the fixed parts
    uint64_t align = 1;
};

// Per parse function: counters for generated locals.
struct Ctx {
    int starts = 0;
    int units = 0;
};

constexpr uint64_t kMaxSize = uint64_t(1) << 48;
// Nested structs / parentheses / unary operators / #define chains: well above real headers, and
// a small fraction of the UI thread's stack (32 levels + the error unwinding fit in 128 KB).
constexpr int kMaxNest = 32;

// Recursion guard: deeply nested input is an error instead of a stack overflow.
struct Nest {
    int& depth;
    Nest(int& d, int line) : depth(d) {
        if (++depth > kMaxNest) {
            --depth;
            fail(line, "nested too deeply (more than " + std::to_string(kMaxNest) + " levels)");
        }
    }
    ~Nest() { --depth; }
    Nest(const Nest&) = delete;
    Nest& operator=(const Nest&) = delete;
};

class Converter {
public:
    Converter(std::vector<Token> toks, const CStructOptions& opt) : t_(std::move(toks)), opt_(opt) {
        if (opt.pack != 0 && opt.pack != 1 && opt.pack != 2 && opt.pack != 4 && opt.pack != 8 && opt.pack != 16)
            fail(0, "packing must be 0 (natural), 1, 2, 4, 8 or 16");
        default_pack_ = opt.pack;
        pack_ = default_pack_;
        default_endian_ = opt.big_endian ? 'b' : 'l';
    }

    void parse_all() {
        while (peek().kind != Tk::End) {
            if (accept(";")) continue;
            const Token& k = peek();
            if (k.kind == Tk::Ident && k.text == "typedef") {
                parse_typedef();
                continue;
            }
            if (k.kind == Tk::Ident && (k.text == "static_assert" || k.text == "_Static_assert")) {
                skip_statement();
                continue;
            }
            if (k.kind != Tk::Ident) fail(k.line, "expected a struct, union, enum, typedef or #define" + found());
            int defined = -1;
            parse_type(-1, 0, &defined);
            bool packed = false;
            skip_attrs(packed);
            if (packed && defined >= 0) structs_[size_t(defined)]->pack = 1;
            if (accept(";")) continue;
            skip_statement();  // variable / function declarations: ignored
        }
    }

    void fill_info(CStructInfo& info, bool with_layout) {
        info.structs.clear();
        for (int si : order_) {
            CStructInfo::Item it;
            it.name = structs_[size_t(si)]->display();
            it.line = structs_[size_t(si)]->line;
            if (with_layout) {
                const Body& b = gen_named(si);
                it.fixed = b.fixed;
                it.size = b.size;
            }
            info.structs.push_back(std::move(it));
        }
    }

    int pick_root() {
        if (order_.empty()) fail(0, "no struct found (define a struct or union)");
        if (opt_.root.empty()) return order_.back();
        int idx = -1;
        auto td = typedefs_.find(opt_.root);
        if (td != typedefs_.end() && td->second.kind == TypeRef::Struct && td->second.dims.empty()) idx = td->second.idx;
        auto tg = tags_.find(opt_.root);
        if (idx < 0 && tg != tags_.end()) idx = tg->second;
        if (idx < 0 || !structs_[size_t(idx)]->complete || structs_[size_t(idx)]->is_inline)
            fail(0, "root struct '" + opt_.root + "' not found");
        return idx;
    }

    std::string generate(int root) {
        for (int si : order_) gen_named(si);  // sets the used flags below
        const StructDef& rs = *structs_[size_t(root)];
        std::string out;
        out += "-- Generated by Hexer from C struct definitions: a regular parser script, edit freely.\n";
        out += "-- Root: " + rs.display() + "   default endianness: " + (opt_.big_endian ? "big" : "little") +
               "   default packing: " +
               (opt_.pack == 0 ? std::string("natural alignment")
                               : opt_.pack == 1 ? std::string("packed") : "max " + S(opt_.pack) + " bytes") +
               "\n-- No detect(): pick it in the Structure panel's parser list.\n\n";
        bool any = false;
        for (const std::string& name : define_order_) {
            const Define& d = defines_[name];
            if (!d.used || d.lua.empty()) continue;
            out += "local " + d.lua + " = " + S(d.value) + "\n";
            any = true;
        }
        if (any) out += "\n";
        any = false;
        for (const EnumDef& e : enums_) {
            if (!e.used) continue;
            std::vector<std::string> items;
            std::set<int64_t> seen;
            for (const auto& [v, n] : e.items)
                if (seen.insert(v).second) items.push_back("[" + S(v) + "] = " + lua_quote(n));
            std::string one = "local " + e.lua + " = { ";
            size_t len = one.size();
            for (const std::string& it : items) len += it.size() + 2;
            if (len <= 100) {
                for (size_t i = 0; i < items.size(); ++i) one += (i ? ", " : "") + items[i];
                out += one + (items.empty() ? "}\n" : " }\n");
            } else {
                out += "local " + e.lua + " = {\n";
                for (const std::string& it : items) out += "    " + it + ",\n";
                out += "}\n";
            }
            any = true;
        }
        if (uses_bool_) out += "local BOOL = { [0] = \"false\", [1] = \"true\" }\n", any = true;
        if (any) out += "\n";
        if (uses_align_) out += kAlignHelper;
        if (uses_bitfield_) out += kBitfieldHelper;
        for (int si : order_) {
            const StructDef& s = *structs_[size_t(si)];
            const Body& b = gen_named(si);
            std::string bytes = S(b.size) + (b.size == 1 ? " byte" : " bytes");
            out += std::string("-- ") + (s.is_union ? "union " : "struct ") + s.display() + ": " +
                   (b.fixed ? bytes : "variable size (at least " + bytes + ")") + "\n";
            out += "local function " + fn_name(si) + "(p)\n";
            for (const std::string& l : b.lines) out += "    " + l + "\n";
            out += "end\n\n";
        }
        out += "hx.parser {\n";
        out += "    name = " + lua_quote(opt_.name.empty() ? std::string("C struct") : opt_.name) + ",\n";
        out += "    parse = function(p)\n";
        out += "        p:struct(" + lua_quote(rs.display()) + ", " + fn_name(root) + ")\n";
        out += "    end,\n";
        out += "}\n";
        return out;
    }

    std::string root_name(int root) const { return structs_[size_t(root)]->display(); }

private:
    // ---- token access ------------------------------------------------------------------------------
    const Token& peek() {
        for (;;) {
            const Token& k = t_[i_];
            if (k.kind == Tk::Pack) {
                apply_pack(k);
                ++i_;
            } else if (k.kind == Tk::Define) {
                if (!defines_.count(k.text)) define_order_.push_back(k.text);
                Define d;
                d.body = k.body;
                d.line = k.line;
                defines_[k.text] = std::move(d);
                ++i_;
            } else {
                return k;
            }
        }
    }
    Token take() {
        const Token& k = peek();
        Token r = k;
        if (k.kind != Tk::End) ++i_;
        return r;
    }
    bool is_p(const char* s) {
        const Token& k = peek();
        return k.kind == Tk::Punct && k.text == s;
    }
    bool is_id(const char* s) {
        const Token& k = peek();
        return k.kind == Tk::Ident && k.text == s;
    }
    bool accept(const char* s) {
        if (!is_p(s)) return false;
        take();
        return true;
    }
    std::string found() {
        const Token& k = peek();
        switch (k.kind) {
            case Tk::End: return " at the end of the input";
            case Tk::Number: return " before " + S(k.num);
            case Tk::Str: return " before a string";
            default: return " before '" + k.text + "'";
        }
    }
    void expect(const char* s) {
        if (!accept(s)) fail(peek().line, std::string("expected '") + s + "'" + found());
    }
    std::string expect_ident(const char* what) {
        if (peek().kind != Tk::Ident) fail(peek().line, std::string("expected ") + what + found());
        return take().text;
    }

    void apply_pack(const Token& k) {
        if (k.text == "push") {
            pack_stack_.push_back(pack_);
            if (k.num) pack_ = int(k.num);
        } else if (k.text == "pop") {
            if (!pack_stack_.empty()) {
                pack_ = pack_stack_.back();
                pack_stack_.pop_back();
            }
        } else if (k.text == "set") {
            pack_ = int(k.num);
        } else {
            pack_ = default_pack_;
        }
    }

    // Skips to the end of a declaration we do not model (`;` at depth 0, or a closing `}`).
    void skip_statement() {
        int depth = 0;
        for (;;) {
            Token k = take();
            if (k.kind == Tk::End) return;
            if (k.kind != Tk::Punct) continue;
            if (k.text == "(" || k.text == "[" || k.text == "{") {
                ++depth;
            } else if (k.text == ")" || k.text == "]" || k.text == "}") {
                if (--depth <= 0 && k.text == "}") {
                    accept(";");
                    return;
                }
            } else if (k.text == ";" && depth <= 0) {
                return;
            }
        }
    }

    void skip_parens(bool& packed) {
        int line = peek().line;
        expect("(");
        int depth = 1;
        while (depth) {
            Token k = take();
            if (k.kind == Tk::End) fail(line, "unbalanced parentheses");
            if (k.kind == Tk::Punct && k.text == "(") ++depth;
            else if (k.kind == Tk::Punct && k.text == ")") --depth;
            else if (k.kind == Tk::Ident && (k.text == "packed" || k.text == "__packed__")) packed = true;
        }
    }

    // __attribute__((...)), __declspec(...), alignas(...), __packed, [[...]]. Sets `packed`.
    bool skip_attrs(bool& packed) {
        bool any = false;
        for (;;) {
            const Token& k = peek();
            if (k.kind == Tk::Ident && (k.text == "__attribute__" || k.text == "__attribute" ||
                                        k.text == "__declspec" || k.text == "alignas" || k.text == "_Alignas")) {
                take();
                skip_parens(packed);
            } else if (k.kind == Tk::Ident && (k.text == "__packed" || k.text == "_Packed")) {
                take();
                packed = true;
            } else if (k.kind == Tk::Punct && k.text == "[" && t_[i_ + 1].kind == Tk::Punct &&
                       t_[i_ + 1].text == "[") {
                int line = k.line;
                take();
                take();
                for (;;) {
                    Token a = take();
                    if (a.kind == Tk::End) fail(line, "unterminated [[attribute]]");
                    if (a.kind == Tk::Ident && a.text == "packed") packed = true;
                    if (a.kind == Tk::Punct && a.text == "]" && is_p("]")) {
                        take();
                        break;
                    }
                }
            } else {
                return any;
            }
            any = true;
        }
    }

    // ---- types -------------------------------------------------------------------------------------
    TypeRef parse_type(int scope, char annot, int* defined) {
        bool packed = false;
        for (;;) {
            const Token& k = peek();
            if (k.kind == Tk::Ident && is_qualifier(k.text)) {
                if (k.annot) annot = k.annot;
                take();
            } else if (!skip_attrs(packed)) {
                break;
            }
        }
        const Token k = peek();
        if (k.kind != Tk::Ident) fail(k.line, "expected a type" + found());
        if (k.text == "struct" || k.text == "union") {
            int def = -1;
            TypeRef r = parse_struct_spec(scope, annot ? annot : k.annot, &def);
            if (packed && def >= 0) structs_[size_t(def)]->pack = 1;
            if (defined) *defined = def;
            return r;
        }
        if (k.text == "enum") return parse_enum_spec();
        TypeRef r;
        if (is_multiword(k.text)) {
            bool uns = false, sgn = false, ch = false;
            int shorts = 0, longs = 0;
            while (peek().kind == Tk::Ident && is_multiword(peek().text)) {
                std::string w = take().text;
                if (w == "unsigned") uns = true;
                else if (w == "signed" || w == "__signed__") sgn = true;
                else if (w == "short") ++shorts;
                else if (w == "long") ++longs;
                else if (w == "char") ch = true;
            }
            if (is_id("double")) fail(k.line, "long double is not supported");
            if (ch) r.prim = (uns || sgn) ? Prim{1, !uns, Prim::Int, 0} : kChar;
            else r.prim = Prim{shorts ? 2 : longs >= 2 ? 8 : 4, !uns, Prim::Int, 0};
            return r;
        }
        take();
        if (auto it = typedefs_.find(k.text); it != typedefs_.end()) return it->second;
        if (auto it = tags_.find(k.text); it != tags_.end()) {
            r.kind = TypeRef::Struct;
            r.idx = it->second;
            return r;
        }
        if (auto it = enum_tags_.find(k.text); it != enum_tags_.end()) {
            r.kind = TypeRef::Enum;
            r.idx = it->second;
            return r;
        }
        for (const PrimName& pn : kPrims)
            if (k.text == pn.name) {
                r.prim = pn.prim;
                return r;
            }
        fail(k.line, "unknown type '" + k.text + "'");
    }

    int tag_index(const std::string& tag, bool is_union, int line) {
        auto it = tags_.find(tag);
        if (it != tags_.end()) {
            if (structs_[size_t(it->second)]->is_union != is_union)
                fail(line, "'" + tag + "' was declared as a " + (is_union ? "struct" : "union"));
            return it->second;
        }
        int idx = new_struct();
        structs_[size_t(idx)]->tag = tag;
        structs_[size_t(idx)]->is_union = is_union;
        structs_[size_t(idx)]->line = line;
        tags_[tag] = idx;
        return idx;
    }
    int new_struct() {
        structs_.push_back(std::make_unique<StructDef>());
        return int(structs_.size() - 1);
    }

    TypeRef parse_struct_spec(int scope, char annot, int* defined) {
        Token kw = take();
        Nest nest(depth_, kw.line);
        bool is_union = kw.text == "union";
        bool packed = false;
        skip_attrs(packed);
        std::string tag;
        if (peek().kind == Tk::Ident) tag = take().text;
        skip_attrs(packed);
        TypeRef r;
        r.kind = TypeRef::Struct;
        if (!is_p("{")) {
            if (tag.empty())
                fail(peek().line, std::string("expected a ") + (is_union ? "union" : "struct") + " name or '{'" + found());
            r.idx = tag_index(tag, is_union, kw.line);
            return r;
        }
        take();
        int idx;
        if (!tag.empty()) {
            idx = tag_index(tag, is_union, kw.line);
            if (structs_[size_t(idx)]->complete) fail(kw.line, "'" + tag + "' is defined twice");
        } else {
            idx = new_struct();
        }
        StructDef& s = *structs_[size_t(idx)];
        s.is_union = is_union;
        s.line = kw.line;
        s.is_inline = tag.empty();
        s.scope_parent = tag.empty() ? scope : -1;
        char e = annot ? annot : peek().annot;  // `// @be` before the struct or right after its `{`
        if (!e) e = (tag.empty() && scope >= 0) ? structs_[size_t(scope)]->endian : default_endian_;
        s.endian = e;
        s.pack = pack_;
        parse_members(idx);
        skip_attrs(packed);
        if (packed) s.pack = 1;
        s.complete = true;
        if (!s.is_inline) order_.push_back(idx);
        if (defined) *defined = idx;
        r.idx = idx;
        return r;
    }

    TypeRef parse_enum_spec() {
        int line = take().line;
        if (is_id("class") || is_id("struct")) take();
        bool packed = false;
        skip_attrs(packed);
        std::string name;
        if (peek().kind == Tk::Ident) name = take().text;
        Prim prim = kI32;
        if (accept(":")) {
            TypeRef b = parse_type(-1, 0, nullptr);
            if (b.kind == TypeRef::Enum) prim = enums_[size_t(b.idx)].prim;
            else if (b.kind != TypeRef::Prim || b.prim.kind == Prim::Float || !b.dims.empty())
                fail(line, "the base type of an enum must be an integer type");
            else prim = b.prim;
            if (prim.kind == Prim::Char) prim.kind = Prim::Int;
        }
        TypeRef r;
        r.kind = TypeRef::Enum;
        if (!is_p("{")) {
            if (name.empty()) fail(peek().line, "expected an enum name or '{'" + found());
            auto it = enum_tags_.find(name);
            if (it == enum_tags_.end()) fail(line, "unknown enum '" + name + "'");
            r.idx = it->second;
            return r;
        }
        take();
        if (!name.empty() && enum_tags_.count(name)) fail(line, "enum '" + name + "' is defined twice");
        EnumDef e;
        e.name = name;
        e.prim = prim;
        if (!name.empty()) e.lua = claim(name);
        r.idx = int(enums_.size());
        enums_.push_back(std::move(e));
        if (!name.empty()) enum_tags_[name] = r.idx;
        int64_t next = 0;
        while (!accept("}")) {
            std::string item = expect_ident("an enumerator name");
            int64_t v = next;
            if (accept("=")) v = parse_expr(-1).value;
            enums_[size_t(r.idx)].items.push_back({v, item});
            enum_consts_[item] = v;
            next = int64_t(uint64_t(v) + 1);
            if (!accept(",")) {
                expect("}");
                break;
            }
        }
        return r;
    }

    void parse_typedef() {
        Token kw = take();
        int defined = -1;
        TypeRef base = parse_type(-1, kw.annot, &defined);
        bool packed = false;
        skip_attrs(packed);
        bool first = true;
        for (;;) {
            if (is_p("*")) fail(peek().line, "pointer typedefs are not supported");
            if (is_p("(")) fail(peek().line, "function typedefs are not supported");
            int line = peek().line;
            std::string name = expect_ident("a typedef name");
            skip_attrs(packed);
            std::vector<Dim> dims;
            parse_dims(-1, dims, line);
            for (const Dim& d : dims)
                if (d.flexible) fail(line, "typedef '" + name + "': arrays in typedefs need a size");
            TypeRef t = base;
            t.dims = dims;
            t.dims.insert(t.dims.end(), base.dims.begin(), base.dims.end());
            typedefs_[name] = t;
            if (first && base.kind == TypeRef::Struct && defined == base.idx) {
                StructDef& s = *structs_[size_t(base.idx)];
                if (s.typedef_name.empty()) s.typedef_name = name;
                if (s.is_inline) {
                    s.is_inline = false;
                    s.scope_parent = -1;
                    order_.push_back(base.idx);
                }
            }
            if (first && base.kind == TypeRef::Enum && enums_[size_t(base.idx)].lua.empty()) {
                enums_[size_t(base.idx)].name = name;
                enums_[size_t(base.idx)].lua = claim(name);
            }
            first = false;
            if (accept(",")) continue;
            skip_attrs(packed);
            expect(";");
            break;
        }
        if (packed && defined >= 0) structs_[size_t(defined)]->pack = 1;
    }

    void parse_dims(int scope, std::vector<Dim>& dims, int line) {
        while (accept("[")) {
            Dim d;
            if (!accept("]")) {
                d.count = parse_expr(scope);
                expect("]");
                if (d.count.is_const && d.count.value < 0) fail(line, "array size must not be negative");
                if (d.count.is_const && uint64_t(d.count.value) > kMaxSize) fail(line, "array is too large");
                if (d.count.is_const && d.count.value == 0) d.flexible = true;
            } else {
                d.flexible = true;
            }
            if (d.flexible && !dims.empty()) fail(line, "only the first array dimension may be empty");
            dims.push_back(std::move(d));
        }
    }

    static bool int_prim(const TypeRef& t, const std::vector<EnumDef>& enums, Prim& out) {
        if (!t.dims.empty()) return false;
        if (t.kind == TypeRef::Enum) {
            out = enums[size_t(t.idx)].prim;
            if (t.prim.endian) out.endian = t.prim.endian;  // a member's own byte order
            return true;
        }
        if (t.kind != TypeRef::Prim || t.prim.kind == Prim::Float) return false;
        out = t.prim;
        return true;
    }

    void parse_members(int si) {
        int open_line = structs_[size_t(si)]->line;
        int flexible_line = 0;
        std::string flexible_name;
        while (!accept("}")) {
            if (peek().kind == Tk::End) fail(open_line, "missing '}'");
            if (accept(";")) continue;
            if (is_id("static_assert") || is_id("_Static_assert")) {
                skip_statement();
                continue;
            }
            int line = peek().line;
            int defined = -1;
            // `/* @be */ int16_t x;` (the comment on the member's line): this member's byte order.
            const char member_endian = peek().annot_inline ? peek().annot : 0;
            TypeRef base = parse_type(si, 0, &defined);
            if (member_endian && (base.kind == TypeRef::Prim || base.kind == TypeRef::Enum)) base.prim.endian = member_endian;
            bool packed = false;
            skip_attrs(packed);
            if (packed && defined >= 0) structs_[size_t(defined)]->pack = 1;
            if (accept(";")) {
                if (base.kind == TypeRef::Struct && defined >= 0 && structs_[size_t(defined)]->is_inline) {
                    Member m;  // anonymous struct/union: its members are flattened into this one
                    m.type = base;
                    m.line = line;
                    add_member(si, std::move(m), flexible_line, flexible_name);
                    continue;
                }
                if (defined >= 0 || base.kind == TypeRef::Enum) continue;  // type declaration only
                fail(line, "expected a member name" + found());
            }
            for (;;) {
                if (is_p("*")) fail(peek().line, "pointers are not supported (use uint32_t / uint64_t for the value)");
                Member m;
                m.line = peek().line;
                m.type = base;
                if (!is_p(":")) m.name = expect_ident("a member name");
                skip_attrs(packed);
                parse_dims(si, m.dims, m.line);
                if (!base.dims.empty() && !m.dims.empty() && base.dims[0].flexible)
                    fail(m.line, "only the first array dimension may be empty");
                m.dims.insert(m.dims.end(), base.dims.begin(), base.dims.end());
                m.type.dims.clear();
                if (accept(":")) {
                    Expr w = parse_expr(-1);
                    Prim pr;
                    if (!int_prim(m.type, enums_, pr) || !m.dims.empty())
                        fail(m.line, "bit field '" + m.name + "' must have an integer type");
                    if (w.value < 0 || w.value > pr.size * 8)
                        fail(m.line, "bit field '" + m.name + "': width " + S(w.value) + " is out of range");
                    if (w.value == 0 && !m.name.empty()) fail(m.line, "bit field '" + m.name + "' has width 0");
                    m.bits = int(w.value);
                } else if (m.name.empty()) {
                    fail(m.line, "expected a member name" + found());
                }
                skip_attrs(packed);
                if (m.type.kind == TypeRef::Struct && !structs_[size_t(m.type.idx)]->complete)
                    fail(m.line, "'" + structs_[size_t(m.type.idx)]->tag + "' is declared but not defined");
                add_member(si, std::move(m), flexible_line, flexible_name);
                if (accept(",")) continue;
                expect(";");
                break;
            }
        }
    }

    void add_member(int si, Member m, int& flexible_line, std::string& flexible_name) {
        if (flexible_line) fail(flexible_line, "flexible array '" + flexible_name + "' must be the last member");
        if (!m.name.empty() && find_in(si, m.name)) fail(m.line, "duplicate member '" + m.name + "'");
        if (!m.dims.empty() && m.dims[0].flexible) {
            flexible_line = m.line;
            flexible_name = m.name;
        }
        structs_[size_t(si)]->members.push_back(std::move(m));
    }

    Member* find_in(int si, const std::string& name) {
        for (Member& m : structs_[size_t(si)]->members) {
            if (m.name == name) return &m;
            if (m.name.empty() && m.bits < 0 && m.type.kind == TypeRef::Struct &&
                structs_[size_t(m.type.idx)]->is_inline)
                if (Member* r = find_in(m.type.idx, name)) return r;
        }
        return nullptr;
    }
    // Earlier field visible from struct `scope` (its own, then the enclosing unnamed structs').
    Member* find_field(int scope, const std::string& name) {
        for (int s = scope; s >= 0; s = structs_[size_t(s)]->is_inline ? structs_[size_t(s)]->scope_parent : -1)
            if (Member* m = find_in(s, name)) return m;
        return nullptr;
    }

    // ---- expressions -------------------------------------------------------------------------------
    static int prec_of(const std::string& op) {
        if (op == "|") return 1;
        if (op == "^") return 2;
        if (op == "&") return 3;
        if (op == "<<" || op == ">>") return 4;
        if (op == "+" || op == "-") return 5;
        if (op == "*" || op == "/" || op == "%") return 6;
        return 0;
    }

    Expr parse_expr(int scope) { return binary(scope, 1); }

    Expr binary(int scope, int min_prec) {
        Expr lhs = unary(scope);
        for (;;) {
            const Token& k = peek();
            if (k.kind != Tk::Punct) break;
            int pr = prec_of(k.text);
            if (!pr || pr < min_prec) break;
            std::string op = k.text;
            int line = k.line;
            take();
            Expr rhs = binary(scope, pr + 1);
            lhs = combine(op, pr, lhs, rhs, line);
        }
        return lhs;
    }

    static std::string wrap(const Expr& e, int pr, bool right) {
        return (e.prec < pr || (right && e.prec == pr)) ? "(" + e.lua + ")" : e.lua;
    }

    Expr combine(const std::string& op, int pr, const Expr& a, const Expr& b, int line) {
        Expr r;
        r.is_const = a.is_const && b.is_const;
        if (r.is_const) {
            uint64_t x = uint64_t(a.value), y = uint64_t(b.value);
            if (op == "+") r.value = int64_t(x + y);
            else if (op == "-") r.value = int64_t(x - y);
            else if (op == "*") r.value = int64_t(x * y);
            else if (op == "/" || op == "%") {
                if (b.value == 0) fail(line, "division by zero");
                if (b.value == -1) r.value = op == "/" ? int64_t(0 - x) : 0;
                else r.value = op == "/" ? a.value / b.value : a.value % b.value;
            } else if (op == "<<" || op == ">>") {
                if (b.value < 0 || b.value > 63) fail(line, "shift count out of range");
                r.value = op == "<<" ? int64_t(x << y) : a.value >> b.value;
            } else if (op == "&") r.value = int64_t(x & y);
            else if (op == "|") r.value = int64_t(x | y);
            else r.value = int64_t(x ^ y);
        }
        r.defs = a.defs;
        r.defs.insert(r.defs.end(), b.defs.begin(), b.defs.end());
        if (r.is_const && r.defs.empty()) {
            r.lua = S(r.value);
            r.prec = r.value < 0 ? 8 : 9;
        } else {
            std::string lop = op == "/" ? "//" : op == "^" ? "~" : op;
            r.lua = wrap(a, pr, false) + " " + lop + " " + wrap(b, pr, true);
            r.prec = pr;
        }
        return r;
    }

    Expr unary(int scope) {
        const Token& k = peek();
        Nest nest(depth_, k.line);
        if (k.kind == Tk::Punct && (k.text == "-" || k.text == "~" || k.text == "+")) {
            std::string op = k.text;
            take();
            Expr e = unary(scope);
            if (op == "+") return e;
            Expr r;
            r.is_const = e.is_const;
            r.defs = e.defs;
            if (e.is_const) r.value = op == "-" ? int64_t(0 - uint64_t(e.value)) : ~e.value;
            if (r.is_const && r.defs.empty()) {
                r.lua = S(r.value);
                r.prec = r.value < 0 ? 8 : 9;
            } else {
                bool paren = e.prec < 8 || e.lua[0] == '-' || e.lua[0] == '~';  // "--" would be a Lua comment
                r.lua = op + (paren ? "(" + e.lua + ")" : e.lua);
                r.prec = 8;
            }
            return r;
        }
        return primary(scope);
    }

    Expr primary(int scope) {
        const Token k = peek();
        Expr e;
        if (k.kind == Tk::Number) {
            take();
            if (k.num > uint64_t(INT64_MAX)) fail(k.line, "number too large");
            e.value = int64_t(k.num);
            e.lua = S(e.value);
            return e;
        }
        if (accept("(")) {
            e = parse_expr(scope);
            expect(")");
            if (e.prec < 9) {
                e.lua = "(" + e.lua + ")";
                e.prec = 9;
            }
            return e;
        }
        if (k.kind != Tk::Ident) fail(k.line, "expected a number or a name" + found());
        take();
        if (k.text == "sizeof") {
            expect("(");
            TypeRef t = parse_type(-1, 0, nullptr);
            std::vector<Dim> dims;
            parse_dims(-1, dims, k.line);
            dims.insert(dims.end(), t.dims.begin(), t.dims.end());
            expect(")");
            e.value = int64_t(type_size(t, dims, k.line));
            e.lua = S(e.value);
            return e;
        }
        if (defines_.count(k.text)) {
            e.value = eval_define(k.text, k.line);
            e.lua = defines_[k.text].lua;
            e.defs.push_back(k.text);
            return e;
        }
        if (Member* m = find_field(scope, k.text)) {
            Prim pr;
            if (!m->dims.empty() || !int_prim(m->type, enums_, pr))
                fail(k.line, "'" + k.text + "' cannot be used as an array size (only earlier integer fields)");
            if (m->lua_local.empty()) m->lua_local = local_name(m->name);
            e.is_const = false;
            e.lua = m->lua_local;
            return e;
        }
        if (auto it = enum_consts_.find(k.text); it != enum_consts_.end()) {
            e.value = it->second;
            e.lua = S(e.value);
            e.prec = e.value < 0 ? 8 : 9;
            return e;
        }
        fail(k.line, "unknown identifier '" + k.text +
                         "' (use a number, a #define, an enum constant or an earlier integer field)");
    }

    int64_t eval_define(const std::string& name, int line) {
        Define& d = defines_[name];
        if (d.done) return d.value;
        if (d.evaluating) fail(line, "#define " + name + " refers to itself");
        d.evaluating = true;
        // Parse the body as the token stream, then restore it (also when an error unwinds: RAII
        // rather than catch + rethrow, which on MSVC keeps every level's frames on the stack).
        struct Restore {
            Converter& c;
            std::vector<Token> t;
            size_t i;
            ~Restore() {
                c.t_ = std::move(t);
                c.i_ = i;
            }
        } restore{*this, std::move(t_), i_};
        t_ = d.body;
        i_ = 0;
        Expr e = parse_expr(-1);
        if (peek().kind != Tk::End) fail(d.line, "#define " + name + ": unexpected" + found());
        d.evaluating = false;
        d.done = true;
        d.value = e.value;
        if (d.lua.empty()) d.lua = claim(name);
        return d.value;
    }

    uint64_t type_size(const TypeRef& t, const std::vector<Dim>& dims, int line) {
        uint64_t n = 0;
        if (t.kind == TypeRef::Prim) {
            n = uint64_t(t.prim.size);
        } else if (t.kind == TypeRef::Enum) {
            n = uint64_t(enums_[size_t(t.idx)].prim.size);
        } else {
            const StructDef& s = *structs_[size_t(t.idx)];
            if (!s.complete) fail(line, "sizeof: '" + s.tag + "' is not defined yet");
            Ctx c;
            Body b = gen_body(t.idx, c, "start");
            if (!b.fixed) fail(line, "sizeof: '" + s.display() + "' has a variable size");
            n = b.size;
        }
        for (const Dim& d : dims) {
            if (d.flexible || !d.count.is_const) fail(line, "sizeof: the array size is not constant");
            n = checked_mul(n, uint64_t(d.count.value), line);
        }
        return n;
    }

    static uint64_t checked_mul(uint64_t a, uint64_t b, int line) {
        if (a && b > kMaxSize / a) fail(line, "array is too large");
        return a * b;
    }

    // ---- Lua names ---------------------------------------------------------------------------------
    std::string claim(std::string want, bool check_reserved = true) {
        if (is_lua_keyword(want) || (check_reserved && reserved_name(want))) want += "_";
        std::string n = want;
        for (int k = 2; top_names_.count(n); ++k) n = want + "_" + S(k);
        top_names_.insert(n);
        return n;
    }
    std::string local_name(const std::string& name) {
        std::string n = name;
        while (is_lua_keyword(n) || reserved_name(n) || top_names_.count(n)) n += "_";
        return n;
    }
    std::string fn_name(int si) {
        auto it = fn_names_.find(si);
        if (it == fn_names_.end())
            it = fn_names_.emplace(si, claim("parse_" + structs_[size_t(si)]->display(), false)).first;
        return it->second;
    }

    // ---- code generation ---------------------------------------------------------------------------
    const Body& gen_named(int si) {
        auto it = named_.find(si);
        if (it != named_.end()) return it->second;
        Ctx c;
        Body b = gen_body(si, c, "start");
        return named_.emplace(si, std::move(b)).first->second;
    }

    std::string count_lua(const Dim& d) {
        for (const std::string& name : d.count.defs) defines_[name].used = true;
        return d.count.lua;
    }

    static std::string reader(const Prim& pr, char endian) {
        std::string r;
        if (pr.kind == Prim::Float) r = pr.size == 4 ? "f32" : "f64";
        else r = (pr.is_signed && pr.kind == Prim::Int ? "i" : "u") + S(pr.size * 8);
        if (pr.size > 1) r += endian == 'b' ? "be" : "le";
        return r;
    }

    std::string enum_lua(int idx) {
        EnumDef& e = enums_[size_t(idx)];
        if (e.lua.empty()) e.lua = claim("Enum");
        e.used = true;
        return e.lua;
    }

    Body gen_scalar(const TypeRef& t, const std::string& nq, const StructDef& parent, Ctx& ctx, const Member* m) {
        Body b;
        std::string local = (m && !m->lua_local.empty()) ? "local " + m->lua_local + " = " : "";
        if (t.kind == TypeRef::Prim || t.kind == TypeRef::Enum) {
            Prim pr = t.kind == TypeRef::Prim ? t.prim : enums_[size_t(t.idx)].prim;
            if (t.kind == TypeRef::Enum && t.prim.endian) pr.endian = t.prim.endian;  // a member's own order
            std::string opts;
            if (t.kind == TypeRef::Enum) {
                opts = ", { enum = " + enum_lua(t.idx) + " }";
            } else if (pr.kind == Prim::Char) {
                opts = ", { fmt = \"char\" }";
            } else if (pr.kind == Prim::Bool) {
                opts = ", { enum = BOOL }";
                uses_bool_ = true;
            }
            b.size = b.align = uint64_t(pr.size);
            b.lines.push_back(local + "p:" + reader(pr, pr.endian ? pr.endian : parent.endian) + "(" + nq + opts + ")");
            return b;
        }
        const StructDef& sd = *structs_[size_t(t.idx)];
        if (!sd.is_inline) {
            const Body& nb = gen_named(t.idx);
            b.fixed = nb.fixed;
            b.size = nb.size;
            b.align = nb.align;
            b.lines.push_back("p:struct(" + nq + ", " + fn_name(t.idx) + ")");
            return b;
        }
        if (m && m->name.empty()) {  // anonymous member: inline in the parent's scope
            ++ctx.starts;
            return gen_body(t.idx, ctx, "start" + S(ctx.starts + 1));
        }
        Ctx inner;  // a closure: fresh scope
        Body ib = gen_body(t.idx, inner, "start");
        b.fixed = ib.fixed;
        b.size = ib.size;
        b.align = ib.align;
        if (ib.lines.empty()) {
            b.lines.push_back("p:struct(" + nq + ", function() end)");
        } else {
            b.lines.push_back("p:struct(" + nq + ", function()");
            for (const std::string& l : ib.lines) b.lines.push_back("    " + l);
            b.lines.push_back("end)");
        }
        return b;
    }

    Body gen_member(const Member& m, const StructDef& parent, Ctx& ctx) {
        std::string nq = lua_quote(m.name);
        if (m.dims.empty()) return gen_scalar(m.type, nq, parent, ctx, &m);
        const TypeRef& t = m.type;
        size_t nd = m.dims.size(), wrap_dims = nd;
        bool is_char = t.kind == TypeRef::Prim && t.prim.kind == Prim::Char;
        bool is_byte = t.kind == TypeRef::Prim && t.prim.kind == Prim::Int && t.prim.size == 1;
        Body inner;
        if (is_char || is_byte) {  // innermost dimension: one string / bytes field
            const Dim& d = m.dims[nd - 1];
            std::string cnt = d.flexible ? "p:remaining()" : count_lua(d);
            inner.lines.push_back(std::string(is_char ? "p:str(" : "p:bytes(") + nq + ", " + cnt + ")");
            inner.fixed = !d.flexible && d.count.is_const;
            inner.size = inner.fixed ? uint64_t(d.count.value) : 0;
            wrap_dims = nd - 1;
        } else {
            inner = gen_scalar(t, nq, parent, ctx, nullptr);
        }
        for (size_t k = wrap_dims; k-- > 0;) {
            const Dim& d = m.dims[k];
            std::string cnt;
            if (d.flexible) {
                if (!inner.fixed || inner.size == 0)
                    fail(m.line, "flexible array '" + m.name + "' needs an element type of fixed size");
                cnt = "p:remaining() // " + S(inner.size);
            } else {
                cnt = count_lua(d);
            }
            std::vector<std::string> lines;
            std::string head = "p:array(" + nq + ", " + cnt + ", function()";
            if (inner.lines.size() == 1 && head.size() + inner.lines[0].size() < 90) {
                lines.push_back(head + " " + inner.lines[0] + " end)");
            } else {
                lines.push_back(head);
                for (const std::string& l : inner.lines) lines.push_back("    " + l);
                lines.push_back("end)");
            }
            inner.lines = std::move(lines);
            if (inner.fixed && !d.flexible && d.count.is_const) {
                inner.size = checked_mul(inner.size, uint64_t(d.count.value), m.line);
            } else {
                inner.fixed = false;
                inner.size = 0;
            }
        }
        return inner;
    }

    Body gen_union(int si, Ctx& ctx, const std::string& start_var) {
        const StructDef& s = *structs_[size_t(si)];
        uint64_t cap = uint64_t(s.pack);
        Body b;
        b.lines.push_back("local " + start_var + " = p:tell()");
        uint64_t last = 0;
        for (size_t k = 0; k < s.members.size(); ++k) {
            const Member& m = s.members[k];
            if (m.bits >= 0) fail(m.line, "bit fields in unions are not supported");
            Body mb = gen_member(m, s, ctx);
            if (!mb.fixed) fail(m.line, "members of variable size are not supported in unions");
            if (k) b.lines.push_back("p:seek(" + start_var + ")");
            b.lines.insert(b.lines.end(), mb.lines.begin(), mb.lines.end());
            b.size = std::max(b.size, mb.size);
            b.align = std::max(b.align, cap ? std::min(mb.align, cap) : mb.align);
            last = mb.size;
        }
        b.size = (b.size + b.align - 1) / b.align * b.align;
        if (b.size != last) b.lines.push_back("p:seek(" + start_var + " + " + S(b.size) + ")");
        return b;
    }

    Body gen_body(int si, Ctx& ctx, const std::string& start_var) {
        const StructDef& s = *structs_[size_t(si)];
        if (s.is_union) return gen_union(si, ctx, start_var);
        Body b;
        uint64_t cap = uint64_t(s.pack);
        auto eff = [&](uint64_t a) { return cap ? std::min(a, cap) : a; };
        bool known = true, uses_start = false;
        uint64_t off = 0;
        auto pad = [&](uint64_t a, bool tail) {
            if (a <= 1) return;
            if (known) {
                uint64_t n = (a - off % a) % a;
                if (!n) return;
                b.lines.push_back(tail ? "p:skip(math.min(" + S(n) + ", p:remaining()))  -- tail padding"
                                       : "p:skip(" + S(n) + ")  -- padding");
                off += n;
            } else {
                b.lines.push_back("align(p, " + start_var + ", " + S(a) + ")" + (tail ? "  -- tail padding" : ""));
                uses_start = uses_align_ = true;
            }
        };
        int unit = 0, used = 0;
        char unit_endian = 'l';
        std::string unit_var;
        auto close_unit = [&] {
            if (!unit) return;
            b.lines.push_back("p:skip(" + S(unit) + ")");
            off += uint64_t(unit);
            unit = 0;
        };
        for (const Member& m : s.members) {
            if (m.bits >= 0) {
                Prim pr;
                int_prim(m.type, enums_, pr);
                int sz = pr.size;
                uint64_t a = eff(uint64_t(sz));
                if (m.bits == 0 || unit != sz || used + m.bits > sz * 8) {
                    close_unit();
                    pad(a, false);
                    b.align = std::max(b.align, a);
                }
                if (m.bits == 0) continue;
                if (!unit) {
                    unit = sz;
                    used = 0;
                    ++ctx.units;
                    unit_var = ctx.units == 1 ? "bits" : "bits" + S(ctx.units);
                    unit_endian = pr.endian ? pr.endian : s.endian;
                    b.lines.push_back("local " + unit_var + " = p:peek(\"" + (unit_endian == 'b' ? ">" : "<") + "I" +
                                      S(sz) + "\")  -- " + S(sz * 8) + "-bit unit of bit fields");
                }
                int shift = unit_endian == 'b' ? sz * 8 - used - m.bits : used;
                used += m.bits;
                if (m.name.empty()) continue;  // unnamed padding bits
                std::string opts;
                if (m.type.kind == TypeRef::Enum) {
                    opts = "enum = " + enum_lua(m.type.idx);
                } else if (pr.kind == Prim::Bool) {
                    opts = "enum = BOOL";
                    uses_bool_ = true;
                }
                if (pr.is_signed && pr.kind == Prim::Int) opts += std::string(opts.empty() ? "" : ", ") + "signed = true";
                if (unit_endian == 'b') opts += std::string(opts.empty() ? "" : ", ") + "be = true";
                std::string call = "bitfield(p, " + lua_quote(m.name) + ", " + unit_var + ", " + S(sz) + ", " +
                                   S(shift) + ", " + S(m.bits) + (opts.empty() ? "" : ", { " + opts + " }") + ")";
                if (!m.lua_local.empty()) call = "local " + m.lua_local + " = " + call;
                b.lines.push_back(call);
                uses_bitfield_ = true;
                continue;
            }
            close_unit();
            Body mb = gen_member(m, s, ctx);
            uint64_t a = eff(mb.align);
            pad(a, false);
            b.align = std::max(b.align, a);
            b.lines.insert(b.lines.end(), mb.lines.begin(), mb.lines.end());
            off += mb.size;
            if (off > kMaxSize) fail(m.line, "struct is too large");
            if (!mb.fixed) known = false;
        }
        close_unit();
        pad(b.align, true);
        b.fixed = known;
        b.size = off;
        if (uses_start) b.lines.insert(b.lines.begin(), "local " + start_var + " = p:tell()");
        return b;
    }

    std::vector<Token> t_;
    size_t i_ = 0;
    int depth_ = 0;  // Nest guard
    CStructOptions opt_;
    int default_pack_ = 1, pack_ = 1;
    std::vector<int> pack_stack_;
    char default_endian_ = 'l';

    std::vector<std::unique_ptr<StructDef>> structs_;
    std::vector<int> order_;  // named structs in completion order
    std::map<std::string, int> tags_;
    std::map<std::string, TypeRef> typedefs_;
    std::vector<EnumDef> enums_;
    std::map<std::string, int> enum_tags_;
    std::map<std::string, int64_t> enum_consts_;
    std::map<std::string, Define> defines_;
    std::vector<std::string> define_order_;

    std::set<std::string> top_names_;
    std::map<int, std::string> fn_names_;
    std::map<int, Body> named_;
    bool uses_align_ = false, uses_bitfield_ = false, uses_bool_ = false;
};

}  // namespace

bool cstruct_to_lua(const std::string& c_source, const CStructOptions& opt, std::string& lua_out, std::string* err,
                    CStructInfo* info) {
    lua_out.clear();
    if (info) *info = CStructInfo{};
    std::unique_ptr<Converter> conv;
    try {
        conv = std::make_unique<Converter>(Lexer(c_source, 1, false).run(), opt);
        conv->parse_all();
        int root = conv->pick_root();
        lua_out = conv->generate(root);
        if (info) {
            conv->fill_info(*info, true);
            info->root = conv->root_name(root);
        }
        return true;
    } catch (const CError& e) {
        lua_out.clear();
        if (info && conv) {
            try {
                conv->fill_info(*info, false);
            } catch (const CError&) {
            }
        }
        if (err) *err = e.msg;
        return false;
    }
}

}  // namespace hx
