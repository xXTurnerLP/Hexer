#include "core/nav.h"

#include <cstddef>
#include <cstdint>
#include <vector>

#include "core/document.h"

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

void NavHistory::clear() {
    back_.clear();
    fwd_.clear();
}

bool decode_pointer(const Document& doc, uint64_t at, int width, bool big_endian, uint64_t base,
                    uint64_t& target) {
    if (width != 1 && width != 2 && width != 4 && width != 8) return false;
    const uint64_t size = doc.size();
    if (at >= size || size - at < uint64_t(width)) return false;
    uint8_t b[8] = {}, bad[8] = {};
    if (doc.read(at, b, size_t(width), bad) != size_t(width)) return false;
    uint64_t value = 0;
    for (int i = 0; i < width; ++i) {
        if (bad[i]) return false;
        const int k = big_endian ? i : width - 1 - i;  // most significant byte first
        value = (value << 8) | b[k];
    }
    if (value < base) return false;
    value -= base;
    if (value > size) return false;
    target = value;
    return true;
}

}  // namespace hx
