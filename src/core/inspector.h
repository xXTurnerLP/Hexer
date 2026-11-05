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
    bool unreadable = false;  // its bytes include an unreadable one: value "??", not editable
};

// `avail` = bytes available at the cursor (pass up to 16+). `big_endian` affects multi-byte ints,
// floats, UTF-16, Unix/FileTime/DosDateTime. Rows are returned in InspType order.
// `unreadable` (optional, avail flags as from Document::read(..., unreadable)): a row whose bytes
// include an unreadable one - every row when the first byte is - gets value "??", editable =
// false and unreadable = true (its size is kept, so the bytes it would decode can be outlined).
std::vector<InspRow> inspect(const uint8_t* data, size_t avail, bool big_endian,
                             const uint8_t* unreadable = nullptr);

// Parse `text` for `type` and produce the bytes to overwrite at the cursor. Accepts decimal or
// 0x-hex for ints (range-checked), floats, single char for Ascii/Utf8/Utf16, ISO dates for time
// types, GUID text. Returns false with a short message on bad input / out of range.
bool inspector_encode(InspType type, const std::string& text, bool big_endian,
                      std::vector<uint8_t>& out, std::string* err = nullptr);

// The integer rows (I8/U8 ... I64/U64) double as follow-pointer types (core/nav.h PointerType):
// their width (1, 2, 3, 4, 8) and signedness. False for every other row (Bin8, floats, text...).
bool insp_int_type(InspType type, int& width, bool& is_signed);
// The integer row of a width / signedness; InspType::Count if there is none.
InspType insp_type_of_int(int width, bool is_signed);

// ---- Bits grid (one toggle per bit of the integer at the focus offset) ----------------------
// Byte (0-based from the decode position) and mask of bit `bit` (0 = least significant) of a
// `width`-byte integer (1..8) in the given byte order. False if width or bit is out of range.
bool insp_bit_location(int width, bool big_endian, int bit, int& byte_index, uint8_t& mask);

class Document;
// Flips bit `bit` of the `width`-byte integer at `at` in `d`: one undoable overwrite of the byte
// holding it (undo label "Toggle bit N"). False with *err for a read-only / busy document, a bit
// outside the integer, a byte past the end or an unreadable byte (process memory holes).
bool inspector_toggle_bit(Document& d, uint64_t at, int width, bool big_endian, int bit, std::string* err = nullptr);

}  // namespace hx
