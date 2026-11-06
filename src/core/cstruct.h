#pragma once
// C struct definitions -> Lua parser source (a regular hx.parser script, readable and meant to be
// edited further). No Lua dependency here: the result is plain text that the script engine runs.
//
// Supported C subset:
//   * struct / union definitions: `struct X {...};`, `typedef struct X {...} Y;`, nested named and
//     anonymous structs/unions (anonymous members are flattened, as in C11), references to earlier
//     struct types (`struct X x;` or just `X x;`), forward declarations, `typedef <type> Name;`
//     (also array typedefs such as `typedef uint8_t mac_t[6];`).
//   * types: uint8_t..uint64_t, int8_t..int64_t, u8..u64, i8..i64, s8..s64, BYTE/WORD/DWORD/QWORD
//     (+ a few more Windows names), char, signed/unsigned char/short/int/long/long long, float,
//     double, bool, _Bool, char16_t/char32_t. `long` is 32-bit (LLP64, like MSVC); use long long /
//     int64_t for 64-bit. const/volatile are ignored. Pointers are rejected.
//   * arrays (multi-dimensional): char arrays -> p:str, other 1-byte integer arrays -> p:bytes
//     (one field instead of one per byte), anything else -> p:array. Sizes are constant
//     expressions (numbers, #define constants, enum constants, sizeof(type), + - * / % << >> & | ^ ~)
//     or DYNAMIC: expressions over earlier integer fields of the same (or an enclosing unnamed)
//     struct, e.g. `uint8_t data[len];`, `uint16_t words[count * 2];`. `x[]` / `x[0]` as the last
//     member = "the rest of the data".
//   * enums: `enum Name : uint8_t { A = 1, B };` (underlying type) or plain enums (4 bytes, signed);
//     fields of an enum type are shown as `1 = A`.
//   * bit fields: consecutive bit fields share a storage unit of their declared type (MSVC rule: a
//     new unit starts when the type size changes or the bits do not fit; `: 0` closes the unit).
//     Bits are allocated from the least significant bit (big-endian structs: from the most
//     significant bit). Each bit field is shown as a field over its unit's bytes (not editable).
//   * packing: the default comes from CStructOptions::pack (1 = packed, 0 = natural alignment);
//     `#pragma pack(n)`, `#pragma pack(push, n)`, `#pragma pack(pop)`, `#pragma pack()` and
//     `__attribute__((packed))` override it. Natural alignment = the type size (8 for 64-bit types).
//   * endianness: CStructOptions::big_endian, overridden per struct by an annotation comment
//     `// @be` or `// @le` on the line(s) right before `struct` / `union` / `typedef`, or right
//     after the struct's `{`. Nested unnamed structs inherit the enclosing struct's endianness.
//     One member: an annotation comment on the member's own line before its type
//     (`/* @be */ int16_t x;`, also enum members and bit fields: a unit takes its first
//     member's) overrides the struct's for it; `__be32` / `__le16` ... types do the same.
//   * comments, `#define NAME <constant expression>`; other preprocessor lines are ignored.
#include <cstdint>
#include <string>
#include <vector>

namespace hx {

struct CStructOptions {
    std::string name = "C struct";  // parser name (hx.parser{name=...})
    std::string root;               // struct to parse (tag or typedef name); "" = last defined
    bool big_endian = false;        // default endianness
    int pack = 1;                   // default max alignment: 1 = packed, 0 = natural, 2/4/8 = cap
};

// What was found in the source (for the UI: root combo, size preview).
struct CStructInfo {
    struct Item {
        std::string name;           // typedef name if any, else the tag
        bool fixed = true;          // false: contains dynamic arrays (size below is the minimum)
        uint64_t size = 0;
        int line = 0;
    };
    std::vector<Item> structs;      // named structs/unions in definition order
    std::string root;               // the struct the parser starts with
};

// Generates the Lua parser. On error returns false and sets *err to e.g.
// "line 7: unknown type 'uint9_t'" (lua_out is cleared). `info` (optional) is filled as far as
// the source could be read, also on errors.
bool cstruct_to_lua(const std::string& c_source, const CStructOptions& opt, std::string& lua_out,
                    std::string* err, CStructInfo* info = nullptr);

}  // namespace hx
