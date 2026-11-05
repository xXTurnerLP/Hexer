#pragma once
// Parse tree (script_engine.h Field) helpers without Lua: flag names (opts.flags) and the
// Structure panel's "Copy as C Header" export.
//
// C header export: the layout of THIS parsed instance as packed C structs:
//   * every struct field becomes a named typedef (`<name>_t`, the root keeps its own name);
//     structs with identical layouts share one typedef; dependencies come first
//   * integers / floats from typed readers -> uint8_t..int64_t / float / double; other sizes
//     (u24, multi-value p:read) -> uint8_t name[N] with the type in a comment
//   * enums (opts.enum) -> `enum name_e : uint16_t { ... };` (the {false, true} enum -> bool;
//     constants the field's type cannot hold become comments)
//   * opts.flags -> the integer type with the bit names in a comment
//   * arrays whose elements share one layout -> T name[N] (nested arrays -> T name[N][M]);
//     other arrays, bytes, LEB128, p:field -> uint8_t name[N]; str -> char name[N]
//   * opts.bitfield fields -> `uint32_t name : width;` (unnamed `: k` for skipped and trailing
//     bits: every unit is declared full, so MSVC and GCC / Clang give the same layout)
//   * gaps -> uint8_t _padN[k]; members overlapping an earlier one (unions, re-reads) are left
//     out with a comment
//   * `#pragma pack(push, 1)`, a static_assert(sizeof) per struct, offset comments relative to
//     the struct start, big-endian fields marked BE; a struct whose integers are mostly
//     big-endian gets the `// @be` annotation core/cstruct.h understands, so the header
//     converts back into an equivalent parser (C struct -> parser).
#include <cstdint>
#include <string>
#include <vector>

#include "script/script_engine.h"

namespace hx {

// "READ|WRITE" for the set bits of `v` (`width` bytes); set bits without a name as "bit9".
// "" when no bit is set.
std::string format_flags(uint64_t v, int width, const std::vector<Field::FlagItem>& flags);
// Parses "READ|WRITE" / "READ | write" (names case-insensitive, "bit9" accepted) into a value.
// False if a part is not a flag name.
bool parse_flags(const std::string& text, const std::vector<Field::FlagItem>& flags, uint64_t& out);

// C header for the subtree of fields[root] (a struct or array field), or for the whole tree
// with root = -1: a single root struct is used as is, several roots are wrapped into a struct
// named after `name` (e.g. the parser name). Returns "" when there is nothing to export.
std::string fields_to_c_header(const std::vector<Field>& fields, int root, const std::string& name);

}  // namespace hx
