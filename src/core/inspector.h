#pragma once
// Data inspector: interpret the bytes at the cursor as many types; encode edited values back.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hx {

enum class InspType {
    Bin8, I8, U8, I16, U16, I24, U24, I32, U32, I64, U64,
    F16, F32, F64,
    Ascii, Utf8, Utf16,      // single character / code point at cursor
    ULEB128, SLEB128,        // protobuf-style varints (also "varint")
    ZigZag,                  // zigzag-decoded LEB128 (protobuf sint)
    Unix32, Unix64,          // seconds since epoch, shown as UTC ISO-8601
    FileTime,                // Windows FILETIME (100ns since 1601), UTC
    DosDateTime,             // MS-DOS date+time (4 bytes: time lo word, date hi word)
    Guid,                    // 16 bytes, Microsoft mixed-endian text form {xxxxxxxx-...}
    Count
};

struct InspRow {
    InspType type;
    const char* name;      // "uint32", "float64", "ULEB128" ...
    std::string value;     // formatted; "" / "-" when not enough bytes or invalid
    size_t size = 0;       // bytes consumed (0 = not decodable here)
    bool editable = false;
};

// `avail` = bytes available at the cursor (pass up to 16+). `big_endian` affects multi-byte ints,
// floats, UTF-16, Unix/FileTime/DosDateTime. Rows are returned in InspType order.
std::vector<InspRow> inspect(const uint8_t* data, size_t avail, bool big_endian);

// Parse `text` for `type` and produce the bytes to overwrite at the cursor. Accepts decimal or
// 0x-hex for ints (range-checked), floats, single char for Ascii/Utf8/Utf16, ISO dates for time
// types, GUID text. Returns false with a short message on bad input / out of range.
bool inspector_encode(InspType type, const std::string& text, bool big_endian,
                      std::vector<uint8_t>& out, std::string* err = nullptr);

}  // namespace hx
