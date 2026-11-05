// Parse tree -> C header (see cexport.h) and the opts.flags name helpers.
#include "script/cexport.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace hx {

namespace {

bool iequal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    return true;
}

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string hex(uint64_t v, int digits = 0) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%0*llX", digits, static_cast<unsigned long long>(v));
    return b;
}

const char* const kReserved[] = {
    // C / C++ keywords a field name may collide with
    "auto", "bool", "break", "case", "char", "class", "const", "continue", "default", "delete", "do",
    "double", "else", "enum", "extern", "false", "float", "for", "goto", "if", "inline", "int", "long",
    "namespace", "new", "operator", "private", "protected", "public", "register", "restrict", "return",
    "short", "signed", "sizeof", "static", "struct", "switch", "template", "this", "true", "typedef",
    "typename", "union", "unsigned", "using", "virtual", "void", "volatile", "while", "_Bool",
    // the types the header itself uses
    "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "static_assert", "offsetof", "NULL",
};

bool reserved(const std::string& s) {
    for (const char* k : kReserved)
        if (s == k) return true;
    return false;
}

// Any text -> a C identifier: "chunk[3]" -> "chunk_3", "IHDR data" -> "IHDR_data", "2nd" -> "_2nd".
std::string c_ident(const std::string& s) {
    std::string o;
    bool gap = false;  // invalid characters since the last valid one: one '_' between words
    for (char ch : s) {
        if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '_') {
            if (gap && !o.empty()) o += '_';
            gap = false;
            o += ch;
        } else {
            gap = true;
        }
    }
    if (o.empty()) o = "field";
    if (std::isdigit(static_cast<unsigned char>(o[0]))) o = "_" + o;
    if (reserved(o)) o += '_';
    return o;
}

// Type name hint of a field: its name without an array index ("chunk[3]" -> "chunk").
std::string type_stem(const std::string& name) {
    std::string n = name;
    if (!n.empty() && n.back() == ']') {
        size_t lb = n.rfind('[');
        if (lb != std::string::npos && lb > 0) n.erase(lb);
    }
    return c_ident(n);
}

// A numeric pack format ("<I4", ">h", "B", "<d") of a field of `size` bytes.
struct Num {
    bool ok = false;
    bool is_float = false;
    bool is_signed = false;
    bool be = false;
};

Num pack_num(const std::string& p, uint64_t size) {
    Num n;
    size_t i = 0;
    if (i < p.size() && (p[i] == '<' || p[i] == '>' || p[i] == '=')) n.be = p[i++] == '>';
    if (i >= p.size()) return n;
    const char c = p[i++];
    uint64_t want = 0;
    switch (c) {
        case 'b': case 'B': want = 1; break;
        case 'h': case 'H': want = 2; break;
        case 'l': case 'L': case 'j': case 'J': want = size; break;  // native long: trust the size
        case 'f': want = 4; n.is_float = true; break;
        case 'd': case 'n': want = 8; n.is_float = true; break;
        case 'i': case 'I': {
            uint64_t w = 0;
            while (i < p.size() && std::isdigit(static_cast<unsigned char>(p[i])) && w < 100) w = w * 10 + uint64_t(p[i++] - '0');
            want = w ? w : 4;
            break;
        }
        default: return n;
    }
    if (i != p.size() || want != size) return n;
    if (!n.is_float && size != 1 && size != 2 && size != 4 && size != 8) return n;
    n.is_signed = n.is_float || (c >= 'a' && c <= 'z');
    n.ok = true;
    return n;
}

std::string int_type(uint64_t size, bool is_signed) {
    return std::string(is_signed ? "int" : "uint") + std::to_string(size * 8) + "_t";
}

bool is_bool_enum(const std::vector<Field::EnumItem>& e) {
    return e.size() == 2 && e[0].value == 0 && e[0].name == "false" && e[1].value == 1 && e[1].name == "true";
}

// A member's type: a builtin ("uint32_t", "char"), a struct typedef or an enum. Typedef and enum
// names are only given out when the header is written, so layouts that end up unused (array
// elements of differing layouts) take no names.
struct TypeName {
    std::string builtin;
    int type_ref = -1;              // struct typedef
    int enum_ref = -1;              // enum
    bool operator==(const TypeName& o) const {
        return builtin == o.builtin && type_ref == o.type_ref && enum_ref == o.enum_ref;
    }
};

// One member declaration.
struct Decl {
    TypeName type;
    std::vector<uint64_t> dims;
    std::string note;               // comment after the offset ("BE", "flags: ...")
    uint64_t size = 0;
    int be = 0, le = 0;             // multi-byte integers by byte order (for the @be annotation)
    bool skip = false;              // 0 bytes: nothing to declare

    bool same_layout(const Decl& o) const {
        return type == o.type && dims == o.dims && note == o.note && size == o.size && !skip && !o.skip;
    }
};

// One line of a struct body: a member (type + rest, e.g. " name[4];") or a comment (raw).
struct Line {
    TypeName type;
    std::string rest;
    uint64_t rel = 0;               // offset in the struct
    std::string note;
    std::string raw;                // non-empty: a comment line, written as is
};

struct TypeDef {
    std::string stem;               // name hint ("chunk" -> chunk_t)
    std::string name;               // given out by emit()
    std::vector<Line> lines;
    uint64_t size = 0;
    bool be = false;
    std::vector<int> types, enums;  // dependencies
};

struct EnumDef {
    std::string stem, name, base;
    const std::vector<Field::EnumItem>* items = nullptr;
    uint64_t bytes = 0;             // underlying type (base)
    bool is_signed = false;
};

// Does enum value v fit the underlying type? (Lua values are int64: a uint64 constant >= 2^63
// arrives negative.)
bool enum_fits(int64_t v, uint64_t bytes, bool is_signed) {
    if (bytes >= 8) return true;
    const int bits = int(bytes * 8);
    if (is_signed) return v >= -(int64_t(1) << (bits - 1)) && v < (int64_t(1) << (bits - 1));
    return v >= 0 && v < (int64_t(1) << bits);
}

// The constant as a C literal of the underlying type.
std::string enum_literal(int64_t v, uint64_t bytes, bool is_signed) {
    if (!is_signed && bytes >= 8 && v < 0) return hex(uint64_t(v));
    if (v == INT64_MIN) return "(-9223372036854775807 - 1)";
    return std::to_string(v);
}

class Exporter {
public:
    explicit Exporter(const std::vector<Field>& f) : F(f) {}

    std::string run(int root, const std::string& name) {
        std::vector<int> kids;
        uint64_t start = 0, end = 0;
        std::string root_name;
        auto add_range = [&](int i) {
            const Field& f = F[size_t(i)];
            if (kids.empty() || f.offset < start) start = f.offset;
            end = std::max(end, f.offset + f.size);
            kids.push_back(i);
        };
        if (root >= 0) {
            const Field& r = F[size_t(root)];
            if (r.type != "array" && !r.children.empty()) {
                kids = r.children;
                start = r.offset;
                end = r.offset + r.size;
                root_name = c_ident(r.name);
            } else {
                add_range(root);
                root_name = c_ident(name.empty() ? r.name : name);
            }
        } else {
            std::vector<int> roots;
            for (size_t i = 0; i < F.size(); ++i)
                if (F[i].parent < 0) roots.push_back(int(i));
            if (roots.size() == 1 && F[size_t(roots[0])].type != "array" && !F[size_t(roots[0])].children.empty())
                return run(roots[0], name);
            for (int i : roots) add_range(i);
            root_name = c_ident(name.empty() ? std::string("parsed") : name);
        }
        if (kids.empty()) return {};
        const int top = build_struct(kids, start, end - start, root_name, true);
        if (types_[size_t(top)].size == 0) return {};
        return emit(top, name.empty() ? root_name : name);
    }

private:
    const std::vector<Field>& F;
    std::vector<TypeDef> types_;
    std::unordered_map<std::string, int> by_sig_;
    std::vector<EnumDef> enums_;
    std::map<std::pair<const void*, std::string>, int> enum_by_key_;
    bool uses_bool_ = false;

    int enum_of(const Field& f, bool is_signed) {
        const std::string base = int_type(f.size, is_signed);
        const auto key = std::make_pair(static_cast<const void*>(f.enums.get()), base);
        auto it = enum_by_key_.find(key);
        if (it != enum_by_key_.end()) return it->second;
        EnumDef e;
        e.stem = type_stem(f.name);
        e.base = base;
        e.items = f.enums.get();
        e.bytes = f.size;
        e.is_signed = is_signed;
        enums_.push_back(std::move(e));
        const int idx = int(enums_.size() - 1);
        enum_by_key_.emplace(key, idx);
        return idx;
    }

    static Decl blob(uint64_t size, const std::string& note) {
        Decl d;
        d.type.builtin = "uint8_t";
        d.dims = {size};
        d.size = size;
        d.note = note;
        d.skip = size == 0;
        return d;
    }

    Decl make_decl(int fi) {
        const Field& f = F[size_t(fi)];
        Decl d;
        d.size = f.size;
        if (f.type == "array") {
            const std::vector<int> kids = sorted(f.children);
            if (kids.empty()) return blob(f.size, "");
            Decl el0;
            bool uniform = true;
            for (size_t i = 0; i < kids.size() && uniform; ++i) {
                const Decl el = make_decl(kids[i]);
                if (i == 0) el0 = el;
                const Field& c = F[size_t(kids[i])];
                uniform = el.same_layout(el0) && c.bits.shift < 0 && el0.size > 0 &&
                          c.offset == f.offset + uint64_t(i) * el0.size;
            }
            if (uniform && el0.size * kids.size() == f.size) {
                d = el0;
                d.dims.insert(d.dims.begin(), uint64_t(kids.size()));
                d.size = f.size;
                return d;
            }
            return blob(f.size, "array of " + std::to_string(kids.size()) + " elements with different layouts");
        }
        if (!f.children.empty() || f.type == "struct") {
            const int t = build_struct(f.children, f.offset, f.size, type_stem(f.name), false);
            d.type.type_ref = t;
            d.size = types_[size_t(t)].size;
            d.skip = d.size == 0;
            return d;
        }
        const Num n = pack_num(f.pack, f.size);
        if (n.ok) {
            if (n.is_float) {
                d.type.builtin = f.size == 4 ? "float" : "double";
            } else if (f.enums && f.size == 1 && is_bool_enum(*f.enums)) {
                d.type.builtin = "bool";
                uses_bool_ = true;
            } else if (f.enums && !f.enums->empty()) {
                d.type.enum_ref = enum_of(f, n.is_signed);
            } else {
                d.type.builtin = int_type(f.size, n.is_signed);
            }
            if (f.size > 1) (n.be ? d.be : d.le) = 1;
            if (n.be && f.size > 1) d.note = "BE";
            if (f.flags && !f.flags->empty()) {
                std::string fl;
                for (const Field::FlagItem& it : *f.flags) {
                    if (it.bit < 0 || uint64_t(it.bit) >= f.size * 8) continue;
                    fl += (fl.empty() ? "flags: " : ", ") + it.name + " = " + hex(uint64_t(1) << it.bit);
                }
                if (!fl.empty()) d.note += (d.note.empty() ? "" : ", ") + fl;
            }
            return d;
        }
        if (f.type == "str" || f.type == "cstr") {
            d.type.builtin = "char";
            d.dims = {f.size};
            d.skip = f.size == 0;
            if (f.type == "cstr") d.note = "NUL-terminated";
            return d;
        }
        if (f.type == "uleb128" || f.type == "sleb128") return blob(f.size, f.type == "uleb128" ? "ULEB128" : "SLEB128");
        if (f.type == "bytes" || f.type == "custom") return blob(f.size, "");
        return blob(f.size, f.type);
    }

    std::vector<int> sorted(std::vector<int> kids) const {
        std::stable_sort(kids.begin(), kids.end(),
                         [&](int a, int b) { return F[size_t(a)].offset < F[size_t(b)].offset; });
        return kids;
    }

    static bool unit_size(uint64_t s) { return s == 1 || s == 2 || s == 4 || s == 8; }
    static bool is_bits(const Field& f) {
        return f.bits.shift >= 0 && f.bits.width > 0 && unit_size(f.size) &&
               uint64_t(f.bits.shift) + uint64_t(f.bits.width) <= f.size * 8;
    }

    // Builds (or finds an identical) typedef for the members `kids_in` over [start, start + size).
    int build_struct(const std::vector<int>& kids_in, uint64_t start, uint64_t size, const std::string& stem,
                     bool is_root) {
        const std::vector<int> kids = sorted(kids_in);
        TypeDef t;
        t.stem = stem;
        std::set<std::string> names;
        auto member_name = [&](const std::string& raw) {
            const std::string base = c_ident(raw);
            std::string n = base;
            for (int k = 2; names.count(n); ++k) n = base + "_" + std::to_string(k);
            names.insert(n);
            return n;
        };
        uint64_t pos = start;
        int pads = 0, be = 0, le = 0;
        auto line = [&](const TypeName& type, const std::string& rest, uint64_t off, const std::string& note) {
            Line l;
            l.type = type;
            l.rest = rest;
            l.rel = off - start;
            l.note = note;
            t.lines.push_back(std::move(l));
        };
        auto builtin = [](const std::string& s) {
            TypeName tn;
            tn.builtin = s;
            return tn;
        };
        auto comment = [&](const std::string& text) {
            Line l;
            l.raw = "    /* " + text + " */";
            t.lines.push_back(std::move(l));
        };
        auto pad_to = [&](uint64_t off) {
            if (off <= pos) return;
            std::string n = "_pad" + std::to_string(pads++);
            while (names.count(n)) n = "_pad" + std::to_string(pads++);
            names.insert(n);
            line(builtin("uint8_t"), " " + n + "[" + std::to_string(off - pos) + "];", pos, "");
            pos = off;
        };
        auto overlap = [&](const Field& c) {
            comment(c_ident(c.name) + " (file offset " + hex(c.offset) + ", " + std::to_string(c.size) +
                    " bytes) overlaps an earlier member: not declared");
        };
        for (size_t i = 0; i < kids.size(); ++i) {
            const Field& c = F[size_t(kids[i])];
            if (is_bits(c)) {
                size_t j = i + 1;
                while (j < kids.size() && is_bits(F[size_t(kids[j])]) && F[size_t(kids[j])].offset == c.offset &&
                       F[size_t(kids[j])].size == c.size && F[size_t(kids[j])].bits.big_endian == c.bits.big_endian)
                    ++j;
                if (c.offset < pos) {
                    for (size_t k = i; k < j; ++k) overlap(F[size_t(kids[k])]);
                    i = j - 1;
                    continue;
                }
                pad_to(c.offset);
                // Every unit is declared full (see below), so the next one starts a new unit with
                // MSVC as well as GCC / Clang without a `: 0` (which GCC aligns even under pack(1)).
                const TypeName unit_t = builtin(int_type(c.size, false));
                std::vector<int> grp(kids.begin() + std::ptrdiff_t(i), kids.begin() + std::ptrdiff_t(j));
                const bool gbe = c.bits.big_endian;
                std::stable_sort(grp.begin(), grp.end(), [&](int a, int b) {
                    const Field::BitField& x = F[size_t(a)].bits;
                    const Field::BitField& y = F[size_t(b)].bits;
                    return gbe ? x.shift + x.width > y.shift + y.width : x.shift < y.shift;
                });
                int cur = gbe ? int(c.size * 8) : 0;  // next free bit (BE: allocated from the top)
                for (int gi : grp) {
                    const Field& m = F[size_t(gi)];
                    const int lo = m.bits.shift, hi = m.bits.shift + m.bits.width;  // [lo, hi)
                    if (gbe ? hi > cur : lo < cur) {
                        overlap(m);
                        continue;
                    }
                    const int gap = gbe ? cur - hi : lo - cur;
                    if (gap > 0) line(unit_t, " : " + std::to_string(gap) + ";", c.offset, "unused bits");
                    const std::string bits = m.bits.width == 1 ? "bit " + std::to_string(lo)
                                                               : "bits " + std::to_string(lo) + ".." + std::to_string(hi - 1);
                    line(builtin(int_type(c.size, m.bits.is_signed)),
                         " " + member_name(m.name) + " : " + std::to_string(m.bits.width) + ";", c.offset,
                         bits + (gbe && c.size > 1 ? ", BE" : ""));
                    cur = gbe ? lo : hi;
                }
                // Fill the unit: under pack(1) GCC / Clang allocate bit fields bit by bit, so a unit
                // whose last bits stay undeclared would be shorter there than with MSVC.
                const int rest = gbe ? cur : int(c.size * 8) - cur;
                if (rest > 0) line(unit_t, " : " + std::to_string(rest) + ";", c.offset, "unused bits");
                ++(gbe ? be : le);  // also 1-byte units: BE allocates from the top bit
                pos = c.offset + c.size;
                i = j - 1;
                continue;
            }
            if (c.offset < pos) {
                overlap(c);
                continue;
            }
            const Decl d = make_decl(kids[i]);
            if (d.skip) {
                comment(c_ident(c.name) + ": 0 bytes");
                continue;
            }
            pad_to(c.offset);
            std::string rest = " " + member_name(c.name);
            for (uint64_t n : d.dims) rest += "[" + std::to_string(n) + "]";
            line(d.type, rest + ";", c.offset, d.note);
            be += d.be;
            le += d.le;
            if (d.type.type_ref >= 0) t.types.push_back(d.type.type_ref);
            if (d.type.enum_ref >= 0) t.enums.push_back(d.type.enum_ref);
            pos = c.offset + d.size;
        }
        pad_to(start + size);
        t.size = pos - start;
        t.be = be > le;
        std::string sig = t.be ? "be\n" : "le\n";
        for (const Line& l : t.lines)
            sig += l.raw.empty() ? l.type.builtin + "#" + std::to_string(l.type.type_ref) + "#" +
                                       std::to_string(l.type.enum_ref) + l.rest + "@" + std::to_string(l.rel) + " " +
                                       l.note + "\n"
                                 : l.raw + "\n";
        if (is_root) t.name = stem;
        else if (auto it = by_sig_.find(sig); it != by_sig_.end()) return it->second;
        types_.push_back(std::move(t));
        const int idx = int(types_.size() - 1);
        if (!is_root) by_sig_.emplace(std::move(sig), idx);
        return idx;
    }

    std::string type_text(const TypeName& tn) const {
        if (tn.type_ref >= 0) return types_[size_t(tn.type_ref)].name;
        if (tn.enum_ref >= 0) return "enum " + enums_[size_t(tn.enum_ref)].name;
        return tn.builtin;
    }

    std::string emit(int top, const std::string& title) {
        // Dependencies first (post-order), each type once.
        std::vector<int> order, enum_order;
        std::vector<char> seen(types_.size(), 0), eseen(enums_.size(), 0);
        std::vector<std::pair<int, size_t>> stack{{top, 0}};
        seen[size_t(top)] = 1;
        while (!stack.empty()) {
            const int ti = stack.back().first;
            const TypeDef& t = types_[size_t(ti)];
            if (stack.back().second < t.types.size()) {
                const int dep = t.types[stack.back().second++];
                if (!seen[size_t(dep)]) {
                    seen[size_t(dep)] = 1;
                    stack.push_back({dep, 0});
                }
                continue;
            }
            for (int e : t.enums)
                if (!eseen[size_t(e)]) {
                    eseen[size_t(e)] = 1;
                    enum_order.push_back(e);
                }
            order.push_back(ti);
            stack.pop_back();
        }
        // Names: the root keeps its own; the others get <stem>_t / <stem>_e (+ _2, _3 on clashes).
        std::set<std::string> used{types_[size_t(top)].name};
        auto unique = [&](const std::string& stem, const char* suffix) {
            std::string n = stem + suffix;
            for (int k = 2; used.count(n) || reserved(n); ++k) n = stem + "_" + std::to_string(k) + suffix;
            used.insert(n);
            return n;
        };
        for (int ti : order)
            if (ti != top) types_[size_t(ti)].name = unique(types_[size_t(ti)].stem, "_t");
        for (int ei : enum_order) enums_[size_t(ei)].name = unique(enums_[size_t(ei)].stem, "_e");

        std::string o;
        o += "// Generated by Hexer from the parse tree of \"" + title + "\" (Structure > Copy as C Header).\n";
        o += "// The layout of this parsed instance: variable-size parts have the sizes parsed here.\n";
        o += "// Offsets (+0x...) are relative to the struct start; BE = big-endian.\n";
        o += "#pragma once\n#include <assert.h>\n#include <stdint.h>\n";
        if (uses_bool_) o += "#include <stdbool.h>\n";
        o += "\n#pragma pack(push, 1)\n\n";
        // Enum constants share one namespace in C: a clash gets the enum's name as a prefix.
        std::set<std::string> consts;
        for (int ei : enum_order) {
            const EnumDef& e = enums_[size_t(ei)];
            o += "enum " + e.name + " : " + e.base + " {\n";
            for (const Field::EnumItem& item : *e.items) {
                if (!enum_fits(item.value, e.bytes, e.is_signed)) {  // a compile error in C / C++
                    o += "    /* " + item.name + " = " + std::to_string(item.value) + " does not fit " + e.base + " */\n";
                    continue;
                }
                std::string c = c_ident(item.name);
                if (consts.count(c) || used.count(c)) c = e.name + "_" + c;
                for (int k = 2; consts.count(c); ++k) c = e.name + "_" + c_ident(item.name) + "_" + std::to_string(k);
                consts.insert(c);
                o += "    " + c + " = " + enum_literal(item.value, e.bytes, e.is_signed) + ",\n";
            }
            o += "};\n\n";
        }
        for (int ti : order) {
            const TypeDef& t = types_[size_t(ti)];
            if (t.be) o += "// @be\n";
            o += "typedef struct " + t.name + " {\n";
            for (const Line& l : t.lines) {
                if (!l.raw.empty()) {
                    o += l.raw + "\n";
                    continue;
                }
                std::string s = "    " + type_text(l.type) + l.rest;
                if (s.size() < 40) s.append(40 - s.size(), ' ');
                else s += ' ';
                o += s + "/* +" + hex(l.rel, 4) + (l.note.empty() ? "" : ", " + l.note) + " */\n";
            }
            o += "} " + t.name + ";\n";
            o += "static_assert(sizeof(" + t.name + ") == " + std::to_string(t.size) + ", \"" + t.name + "\");\n\n";
        }
        o += "#pragma pack(pop)\n";
        return o;
    }
};

}  // namespace

std::string format_flags(uint64_t v, int width, const std::vector<Field::FlagItem>& flags) {
    if (width > 0 && width < 8) v &= (uint64_t(1) << (width * 8)) - 1;
    std::string s;
    for (int bit = 0; bit < 64 && v; ++bit) {
        const uint64_t m = uint64_t(1) << bit;
        if (!(v & m)) continue;
        v &= ~m;
        std::string name = "bit" + std::to_string(bit);
        for (const Field::FlagItem& it : flags)
            if (it.bit == bit) {
                name = it.name;
                break;
            }
        s += (s.empty() ? "" : "|") + name;
    }
    return s;
}

bool parse_flags(const std::string& text, const std::vector<Field::FlagItem>& flags, uint64_t& out) {
    out = 0;
    size_t b = 0;
    bool any = false;
    while (b <= text.size()) {
        size_t e = text.find('|', b);
        if (e == std::string::npos) e = text.size();
        const std::string part = trim(text.substr(b, e - b));
        b = e + 1;
        if (part.empty()) return false;
        bool found = false;
        for (const Field::FlagItem& it : flags)
            if (iequal(it.name, part) && it.bit >= 0 && it.bit < 64) {
                out |= uint64_t(1) << it.bit;
                found = true;
                break;
            }
        if (!found && part.size() > 3 && iequal(part.substr(0, 3), "bit")) {
            int bit = 0;
            size_t k = 3;
            for (; k < part.size() && std::isdigit(static_cast<unsigned char>(part[k])) && bit < 64; ++k)
                bit = bit * 10 + (part[k] - '0');
            if (k == part.size() && bit < 64) {
                out |= uint64_t(1) << bit;
                found = true;
            }
        }
        if (!found) return false;
        any = true;
        if (e == text.size()) break;
    }
    return any;
}

std::string fields_to_c_header(const std::vector<Field>& fields, int root, const std::string& name) {
    if (fields.empty() || root >= int(fields.size())) return {};
    Exporter ex(fields);
    return ex.run(root, name);
}

}  // namespace hx
