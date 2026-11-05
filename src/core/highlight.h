#pragma once
// Colored byte ranges drawn by the hex view (parser fields, search hits, script marks, bookmarks).
#include <cstdint>
#include <string>
#include <vector>

namespace hx {

// Colors are packed like ImGui's IM_COL32: 0xAABBGGRR (R in the low byte).
constexpr uint32_t rgba(uint8_t r, uint8_t g, uint8_t b, uint8_t a = 255) {
    return (uint32_t(a) << 24) | (uint32_t(b) << 16) | (uint32_t(g) << 8) | uint32_t(r);
}

// 16 distinct, dark-mode friendly tints used to auto-color parser fields (index wraps).
uint32_t field_palette(int index);
// Parses "red" | "#ff8800" | "ff8800" into a packed color; returns false if unknown.
// Named: red, green, blue, yellow, orange, purple, cyan, pink, gray, teal, white.
bool parse_color(const std::string& s, uint32_t& out);
// 0xRRGGBB integer (as written in Lua) -> packed color with alpha 255.
constexpr uint32_t from_rgb_int(uint32_t rrggbb) {
    return rgba(uint8_t(rrggbb >> 16), uint8_t(rrggbb >> 8), uint8_t(rrggbb));
}

struct Highlight {
    uint64_t offset = 0;
    uint64_t length = 0;
    uint32_t color = 0;   // background tint; the view applies its own alpha blending
    std::string label;    // shown in the hover tooltip (e.g. "chunk.length = 13")
    int field = -1;       // index into ParseResult::fields, or -1
};

class HighlightSet {
public:
    std::vector<Highlight> items;   // after finalize(): sorted by offset (ties: larger first)

    void clear();
    void add(Highlight h);          // zero-length entries ignored
    void finalize();                // sort + build lookup acceleration; call after adding

    // Innermost (smallest) highlight covering `off`, or nullptr. O(log n) + a short scan.
    // Overlap is allowed (nested structs) but typical sets are mostly non-overlapping.
    const Highlight* at(uint64_t off) const;
    // All highlights intersecting [begin, end).
    void query(uint64_t begin, uint64_t end, std::vector<const Highlight*>& out) const;
    bool empty() const { return items.empty(); }

private:
    std::vector<uint64_t> max_end_;  // prefix max of (offset+length), for overlap-aware lookups
};

}  // namespace hx
