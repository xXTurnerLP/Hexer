#include "core/highlight.h"

#include <algorithm>
#include <cctype>

namespace hx {

uint32_t field_palette(int index) {
    // Mid-saturation tints chosen to stay distinguishable from each other when drawn as translucent
    // backgrounds over a ~#1e1f22 editor background (neighbouring indices differ in hue a lot).
    static const uint32_t kPalette[16] = {
        rgba(86, 156, 214),   // blue
        rgba(214, 157, 86),   // amber
        rgba(78, 201, 176),   // teal
        rgba(197, 134, 192),  // orchid
        rgba(140, 200, 90),   // lime
        rgba(230, 110, 110),  // coral
        rgba(100, 200, 230),  // sky
        rgba(220, 200, 90),   // gold
        rgba(150, 130, 235),  // lavender
        rgba(235, 140, 70),   // orange
        rgba(90, 190, 130),   // green
        rgba(235, 125, 175),  // pink
        rgba(120, 150, 210),  // steel
        rgba(190, 160, 120),  // tan
        rgba(70, 175, 190),   // cyan
        rgba(205, 110, 145),  // rose
    };
    int i = index % 16;
    if (i < 0) i += 16;
    return kPalette[i];
}

bool parse_color(const std::string& in, uint32_t& out) {
    std::string s;
    for (char c : in)
        if (!std::isspace(static_cast<unsigned char>(c))) s += char(std::tolower(static_cast<unsigned char>(c)));
    struct Named {
        const char* name;
        uint32_t color;
    };
    static const Named kNamed[] = {
        {"red", rgba(230, 90, 90)},     {"green", rgba(110, 200, 110)}, {"blue", rgba(90, 150, 230)},
        {"yellow", rgba(230, 210, 90)}, {"orange", rgba(240, 150, 70)}, {"purple", rgba(170, 120, 230)},
        {"cyan", rgba(80, 200, 220)},   {"pink", rgba(235, 125, 180)},  {"gray", rgba(150, 150, 150)},
        {"grey", rgba(150, 150, 150)},  {"teal", rgba(70, 180, 160)},   {"white", rgba(235, 235, 235)},
    };
    for (const Named& n : kNamed)
        if (s == n.name) {
            out = n.color;
            return true;
        }
    if (!s.empty() && s[0] == '#')
        s.erase(0, 1);
    else if (s.size() > 2 && s[0] == '0' && s[1] == 'x')
        s.erase(0, 2);
    if (s.size() != 6 && s.size() != 8) return false;
    uint32_t v = 0;
    for (char c : s) {
        int d;
        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
        else
            return false;
        v = (v << 4) | uint32_t(d);
    }
    if (s.size() == 6)
        out = from_rgb_int(v);
    else  // RRGGBBAA
        out = rgba(uint8_t(v >> 24), uint8_t(v >> 16), uint8_t(v >> 8), uint8_t(v));
    return true;
}

// ---------------------------------------------------------------------------------------------
// HighlightSet
//
// items are sorted by offset. max_end_ is an implicit binary max-tree over items' end offsets
// (leaves at [cap, 2*cap)), so "all items with index < k whose end > x" is found by descending
// only into subtrees that contain such an item: O(log n) per reported item. This keeps nested
// highlights (a struct covering thousands of fields) fast, unlike a plain backwards scan.
// ---------------------------------------------------------------------------------------------
namespace {
uint64_t end_of(const Highlight& h) {
    uint64_t e = h.offset + h.length;
    return e < h.offset ? UINT64_MAX : e;
}

template <class F>
void collect(const std::vector<uint64_t>& tree, size_t node, size_t lo, size_t hi, size_t limit,
             uint64_t x, F&& f) {
    // node covers item indices [lo, hi); report items with index < limit and end > x, in order.
    if (lo >= limit || tree[node] <= x) return;
    if (hi - lo == 1) {
        f(lo);
        return;
    }
    size_t mid = (lo + hi) / 2;
    collect(tree, node * 2, lo, mid, limit, x, f);
    collect(tree, node * 2 + 1, mid, hi, limit, x, f);
}
}  // namespace

void HighlightSet::clear() {
    items.clear();
    max_end_.clear();
}

void HighlightSet::add(Highlight h) {
    if (h.length == 0) return;
    if (h.offset + h.length < h.offset) h.length = UINT64_MAX - h.offset;  // clamp overflow
    items.push_back(std::move(h));
}

void HighlightSet::finalize() {
    std::stable_sort(items.begin(), items.end(), [](const Highlight& a, const Highlight& b) {
        if (a.offset != b.offset) return a.offset < b.offset;
        return a.length > b.length;
    });
    size_t cap = 1;
    while (cap < items.size()) cap *= 2;
    max_end_.assign(cap * 2, 0);
    for (size_t i = 0; i < items.size(); ++i) max_end_[cap + i] = end_of(items[i]);
    for (size_t i = cap - 1; i >= 1; --i) max_end_[i] = std::max(max_end_[2 * i], max_end_[2 * i + 1]);
}

const Highlight* HighlightSet::at(uint64_t off) const {
    if (items.empty() || max_end_.empty()) return nullptr;
    // Items that start at or before `off`...
    auto it = std::upper_bound(items.begin(), items.end(), off,
                               [](uint64_t v, const Highlight& h) { return v < h.offset; });
    size_t limit = size_t(it - items.begin());
    if (limit == 0) return nullptr;
    size_t cap = max_end_.size() / 2;
    const Highlight* best = nullptr;
    // ...and end after it. Innermost = smallest; ties go to the later one (added deeper).
    collect(max_end_, 1, 0, cap, limit, off, [&](size_t i) {
        const Highlight& h = items[i];
        if (!best || h.length <= best->length) best = &h;
    });
    return best;
}

void HighlightSet::query(uint64_t begin, uint64_t end, std::vector<const Highlight*>& out) const {
    if (begin >= end || items.empty() || max_end_.empty()) return;
    auto it = std::lower_bound(items.begin(), items.end(), end,
                               [](const Highlight& h, uint64_t v) { return h.offset < v; });
    size_t limit = size_t(it - items.begin());
    size_t cap = max_end_.size() / 2;
    collect(max_end_, 1, 0, cap, limit, begin, [&](size_t i) { out.push_back(&items[i]); });
}

}  // namespace hx
