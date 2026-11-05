#pragma once
// Formatting / parsing helpers shared by UI and scripts.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hx {

std::string fmt_hex(uint64_t v, int min_digits = 0, bool upper = true);  // no prefix
std::string fmt_size(uint64_t bytes);  // "512 B", "1.50 KiB", "2.00 TiB"

// Goto / offset expressions. Terms joined by + or -:
//   0x1F00 | 1F00h | $1F00 -> hex ;  #4096 | 4096d -> decimal ; bare numbers use `default_hex`
//   50%      -> percent of size     ;  end / eof  -> size ;  cur / . -> current
//   leading +N / -N is relative to `current`. Result must be <= size (else error).
// Examples: "0x100", "+0x10", "-#20", "end-0x100", "50%", "cur+4*0x10" (also supports * and /).
bool parse_offset(const std::string& expr, uint64_t current, uint64_t size, bool default_hex,
                  uint64_t& out, std::string* err = nullptr);

enum class CopyFormat { HexSpaced, HexCompact, CArray, PythonBytes, Base64, EscapedString, Text, Count };
const char* copy_format_name(CopyFormat f);  // "Hex (spaced)", "C array", ...
std::string copy_as(const uint8_t* data, size_t len, CopyFormat f);

// Lenient byte parser for paste / scripts: hex with any separators ("DE AD", "de:ad", "0xde,0xad",
// "\xde\xad", "{ 0xDE, 0xAD }"), or base64 if prefixed "b64:". Returns false if not parseable.
bool parse_bytes(const std::string& text, std::vector<uint8_t>& out, std::string* err = nullptr);
bool base64_decode(const std::string& in, std::vector<uint8_t>& out);
std::string base64_encode(const uint8_t* data, size_t len);

// Case-insensitive ASCII fuzzy match for the command palette. Returns score (higher = better) or
// -1 if `pattern` chars do not appear in order in `text`.
int fuzzy_score(const std::string& pattern, const std::string& text);

}  // namespace hx
