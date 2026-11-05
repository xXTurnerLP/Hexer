#include "core/entropy.h"

namespace hx {

const char* byte_class_name(ByteClass c) {
    switch (c) {
    case ByteClass::Zero: return "zero";
    case ByteClass::Whitespace: return "whitespace";
    case ByteClass::Printable: return "printable";
    case ByteClass::Control: return "control";
    case ByteClass::High: return "high";
    case ByteClass::Full: return "0xFF";
    }
    return "?";
}

}  // namespace hx
