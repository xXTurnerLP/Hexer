#pragma once
// Private helper shared by util.cpp (parse_bytes) and search.cpp (hex patterns): lenient hex text
// -> bytes (+ per-byte mask for wildcards). Not part of any public contract.
//
// Accepted: hex digit pairs with any of the separators  whitespace , ; : - { } [ ] ( )
// and the prefixes 0x / 0X (at the start of a token) and \x / \X (anywhere). A token is a run of
// digits between separators/prefixes; each token must have an even number of digits, except that a
// single digit after a prefix ("0x1", "\x5") means one byte (C arrays like "{ 0x1, 0x2 }").
// With `wildcards`, '?' is a wildcard nibble ("??" = any byte, "4?" = 0x40..0x4F).
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hx::detail {

inline int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline bool is_hex_separator(char c) {
    switch (c) {
    case ' ': case '\t': case '\r': case '\n': case '\v': case '\f':
    case ',': case ';': case ':': case '-': case '{': case '}': case '[': case ']': case '(': case ')':
        return true;
    default:
        return false;
    }
}

// Returns false (with a message) on an invalid character or an odd-length token.
inline bool parse_hex_tokens(const std::string& text, bool wildcards, std::vector<uint8_t>& bytes,
                             std::vector<uint8_t>& mask, std::string* err) {
    bytes.clear();
    mask.clear();
    // Digits of the current token: value nibble + mask nibble (0xF = fixed, 0x0 = wildcard).
    std::vector<uint8_t> nib, nib_mask;
    bool prefixed = false;
    auto flush = [&]() -> bool {
        if (nib.empty()) {
            prefixed = false;
            return true;
        }
        if (nib.size() == 1 && prefixed) {  // "0x1" -> 0x01
            nib.insert(nib.begin(), 0);
            nib_mask.insert(nib_mask.begin(), 0xF);
        }
        if (nib.size() % 2 != 0) {
            if (err) *err = "odd number of hex digits";
            return false;
        }
        for (size_t i = 0; i < nib.size(); i += 2) {
            bytes.push_back(uint8_t(nib[i] << 4 | nib[i + 1]));
            mask.push_back(uint8_t(nib_mask[i] << 4 | nib_mask[i + 1]));
        }
        nib.clear();
        nib_mask.clear();
        prefixed = false;
        return true;
    };
    for (size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        char next = i + 1 < text.size() ? text[i + 1] : '\0';
        if (is_hex_separator(c)) {
            if (!flush()) return false;
            continue;
        }
        if (c == '\\' && (next == 'x' || next == 'X')) {
            if (!flush()) return false;
            prefixed = true;
            ++i;
            continue;
        }
        if (c == '0' && (next == 'x' || next == 'X') && nib.empty()) {
            prefixed = true;
            ++i;
            continue;
        }
        int v = hex_nibble(c);
        if (v >= 0) {
            nib.push_back(uint8_t(v));
            nib_mask.push_back(0xF);
            continue;
        }
        if (wildcards && c == '?') {
            nib.push_back(0);
            nib_mask.push_back(0);
            continue;
        }
        if (err) {
            *err = "invalid character '";
            if (static_cast<unsigned char>(c) >= 0x20 && static_cast<unsigned char>(c) < 0x7F)
                *err += c;
            else
                *err += "?";
            *err += "' at position " + std::to_string(i + 1);
        }
        return false;
    }
    if (!flush()) return false;
    if (bytes.empty()) {
        if (err) *err = "no bytes";
        return false;
    }
    return true;
}

}  // namespace hx::detail
