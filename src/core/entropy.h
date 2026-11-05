#pragma once
// Byte classes (shared by the hex view's byte-class coloring and the minimap) + file entropy overview.
#include <cstdint>

namespace hx {

// FROZEN contract (used by several modules): classification of a single byte value.
enum class ByteClass : uint8_t {
    Zero,        // 0x00
    Whitespace,  // \t \n \v \f \r and space (0x09-0x0D, 0x20)
    Printable,   // 0x21-0x7E
    Control,     // 0x01-0x08, 0x0E-0x1F, 0x7F
    High,        // 0x80-0xFE
    Full,        // 0xFF
};
constexpr int kByteClassCount = 6;
constexpr ByteClass byte_class(uint8_t b) {
    return b == 0x00 ? ByteClass::Zero
         : b == 0xFF ? ByteClass::Full
         : (b >= 0x09 && b <= 0x0D) || b == 0x20 ? ByteClass::Whitespace
         : b >= 0x21 && b <= 0x7E ? ByteClass::Printable
         : b >= 0x80 ? ByteClass::High
         : ByteClass::Control;
}
const char* byte_class_name(ByteClass c);

}  // namespace hx
