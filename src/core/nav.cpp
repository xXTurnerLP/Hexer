#include "core/nav.h"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "core/document.h"
#include "core/util.h"

namespace hx {

namespace {

void push_capped(std::vector<NavEntry>& s, const NavEntry& e) {
    if (!s.empty() && s.back() == e) return;
    s.push_back(e);
    if (s.size() > NavHistory::kMax) s.erase(s.begin(), s.begin() + ptrdiff_t(s.size() - NavHistory::kMax));
}

}  // namespace

void NavHistory::push(const NavEntry& from) {
    push_capped(back_, from);
    fwd_.clear();
}

NavEntry NavHistory::back(const NavEntry& current) {
    if (back_.empty()) return current;
    NavEntry t = back_.back();
    back_.pop_back();
    push_capped(fwd_, current);
    return t;
}

NavEntry NavHistory::forward(const NavEntry& current) {
    if (fwd_.empty()) return current;
    NavEntry t = fwd_.back();
    fwd_.pop_back();
    push_capped(back_, current);
    return t;
}

void NavHistory::set_stacks(std::vector<NavEntry> back, std::vector<NavEntry> forward) {
    back_ = std::move(back);
    fwd_ = std::move(forward);
    if (back_.size() > kMax) back_.erase(back_.begin(), back_.begin() + ptrdiff_t(back_.size() - kMax));
    if (fwd_.size() > kMax) fwd_.erase(fwd_.begin(), fwd_.begin() + ptrdiff_t(fwd_.size() - kMax));
}

std::string nav_encode(const std::vector<NavEntry>& stack) {
    std::string s;
    for (const NavEntry& e : stack) {
        if (!s.empty()) s += ' ';
        s += std::to_string(e.offset) + ':' + std::to_string(e.length);
    }
    return s;
}

std::vector<NavEntry> nav_decode(const std::string& text, uint64_t size) {
    std::vector<NavEntry> out;
    auto num = [](const std::string& t, uint64_t& v) {
        auto r = std::from_chars(t.data(), t.data() + t.size(), v);
        return !t.empty() && r.ec == std::errc() && r.ptr == t.data() + t.size();
    };
    size_t pos = 0;
    while (pos < text.size()) {
        size_t end = text.find(' ', pos);
        if (end == std::string::npos) end = text.size();
        const std::string item = text.substr(pos, end - pos);
        pos = end + 1;
        const size_t colon = item.find(':');
        NavEntry e;
        if (colon == std::string::npos || !num(item.substr(0, colon), e.offset) || !num(item.substr(colon + 1), e.length))
            continue;
        e.offset = std::min(e.offset, size);
        e.length = std::min(e.length, size - e.offset);
        out.push_back(e);
    }
    return out;
}

void NavHistory::clear() {
    back_.clear();
    fwd_.clear();
}

bool valid_pointer_width(int width) {
    return width == 1 || width == 2 || width == 3 || width == 4 || width == 8;
}

bool decode_pointer(const Document& doc, uint64_t at, const PointerType& type, uint64_t& target) {
    const int width = type.width;
    if (!valid_pointer_width(width)) return false;
    const uint64_t size = doc.size();
    if (at >= size || size - at < uint64_t(width)) return false;
    uint8_t b[8] = {}, bad[8] = {};
    if (doc.read(at, b, size_t(width), bad) != size_t(width)) return false;
    uint64_t value = 0;
    for (int i = 0; i < width; ++i) {
        if (bad[i]) return false;
        const int k = type.big_endian ? i : width - 1 - i;  // most significant byte first
        value = (value << 8) | b[k];
    }
    const unsigned bits = unsigned(width) * 8u;
    const bool negative = type.is_signed && ((value >> (bits - 1)) & 1u);
    // Magnitude of a negative value: 2^bits - value (fits: at most 2^63 for 64-bit).
    const uint64_t mag = !negative ? 0 : bits == 64 ? ~value + 1 : (uint64_t(1) << bits) - value;
    uint64_t t = 0;
    if (type.relative) {
        if (negative) {
            if (mag > at) return false;      // before offset 0
            t = at - mag;
        } else {
            if (value > UINT64_MAX - at) return false;  // past 2^64
            t = at + value;
        }
    } else {
        if (negative || value < type.base) return false;
        t = value - type.base;
    }
    if (t > size) return false;
    target = t;
    return true;
}

bool decode_pointer(const Document& doc, uint64_t at, int width, bool big_endian, uint64_t base,
                    uint64_t& target) {
    PointerType pt;
    pt.width = width;
    pt.big_endian = big_endian;
    pt.base = base;
    return decode_pointer(doc, at, pt, target);
}

std::string pointer_type_name(const PointerType& type, bool uppercase) {
    std::string s = (type.is_signed ? "s" : "u") + std::to_string(type.width * 8);
    if (type.width > 1) s += type.big_endian ? " BE" : " LE";
    if (type.relative)
        s += " rel";
    else if (type.base)
        s += std::string(", base ") + "0x" + fmt_hex(type.base, 1, uppercase);
    return s;
}

std::string pointer_link_text(const PointerType& type, bool ok, uint64_t target, bool uppercase) {
    std::string s = pointer_type_name(type, uppercase) + " \xE2\x86\x92 ";  // U+2192
    if (ok) return s + "0x" + fmt_hex(target, 1, uppercase);
    return s + "nothing to follow (beyond EOF, negative or unreadable)";
}

}  // namespace hx
