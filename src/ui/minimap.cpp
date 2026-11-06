#include "ui/minimap.h"

#include <algorithm>
#include <cmath>
#include <vector>

#include "imgui.h"

#include "core/highlight.h"  // rgba()
#include "core/util.h"       // fmt_size()
#include "ui/hex_view.h"     // fmt_range()
#include "ui/theme.h"

namespace hx {

uint64_t minimap_row_offset(uint64_t row, uint64_t rows, uint64_t size) {
    if (!rows) return 0;
    if (row >= rows) return size;
    const uint64_t q = size / rows, rem = size % rows;  // row * size / rows without overflow
    return row * q + row * rem / rows;
}

uint64_t minimap_offset_row(uint64_t offset, uint64_t rows, uint64_t size) {
    if (!rows || !size) return 0;
    // Inverse of minimap_row_offset: the last row whose first byte is <= offset, i.e.
    // ceil((offset + 1) * rows / size) - 1.
    if (offset >= size) return rows - 1;
    const uint64_t row = offset + 1 <= UINT64_MAX / rows
                             ? ((offset + 1) * rows - 1) / size
                             : uint64_t(double(offset) / double(size) * double(rows));
    return std::min(row, rows - 1);
}

namespace {

constexpr uint32_t kBackground = rgba(0x1a, 0x1b, 0x1e);
constexpr uint32_t kPending = rgba(0x2b, 0x2d, 0x31);
constexpr uint32_t kViewFill = rgba(0xff, 0xff, 0xff, 38);
constexpr uint32_t kViewBorder = rgba(0xff, 0xff, 0xff, 150);
constexpr float kSpotMinBits = 6.2f;  // spot ticks are at least green (visible on dark rows)

// Pixel row y covers bytes [row_begin, row_end); an empty range (fewer bytes than rows) shows the
// bucket holding row_begin.
struct Row {
    uint64_t begin = 0, end = 0;
};
Row row_range(int y, int rows, uint64_t size) {
    return {minimap_row_offset(uint64_t(y), uint64_t(rows), size), minimap_row_offset(uint64_t(y) + 1, uint64_t(rows), size)};
}

void tooltip(const EntropyResult* r, uint64_t size, Row row) {
    ImGui::BeginTooltip();
    EntropyBucket a;
    if (r) a = entropy_aggregate(*r, row.begin, row.end);
    if (a.length) {
        ImGui::TextUnformatted(fmt_range(a.offset, a.length).c_str());
    } else {
        const uint64_t len = std::max<uint64_t>(1, row.end - row.begin);
        ImGui::TextUnformatted(fmt_range(row.begin, std::min(len, size - std::min(row.begin, size))).c_str());
    }
    if (!a.done) {
        ImGui::TextDisabled("%s", r && !r->finished ? "Scanning..." : "Not scanned");
    } else if (!a.bytes_read && !a.hole_bytes) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(hex_colors().unreadable_text), "Unreadable");
    } else {
        ImGui::Text("Entropy %.2f bits/byte", double(a.entropy));
        ImGui::Separator();
        const float sq = ImGui::GetTextLineHeight() * 0.7f;
        for (int c = 0; c < kByteClassCount; ++c) {
            const ImVec2 p = ImGui::GetCursorScreenPos();
            const float dy = (ImGui::GetTextLineHeight() - sq) * 0.5f;
            ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(p.x, p.y + dy), ImVec2(p.x + sq, p.y + dy + sq),
                                                      byte_class_color(ByteClass(c)), 2.0f);
            ImGui::Dummy(ImVec2(sq, sq));
            ImGui::SameLine();
            ImGui::TextUnformatted(byte_class_name(ByteClass(c)));
            ImGui::SameLine(ImGui::GetFontSize() * 7.0f);
            ImGui::Text("%5.1f%%", double(a.class_frac[c]) * 100.0);
        }
        if (a.sampled || a.unreadable || a.hole_bytes || entropy_spot(a)) ImGui::Separator();
        if (entropy_spot(a))  // the tick on the right edge
            ImGui::Text("Densest 4 KiB: %.2f bits/byte", double(a.peak));
        if (a.hole_bytes)
            ImGui::TextDisabled("sparse: %s of holes (zeros, not read)", fmt_size(a.hole_bytes).c_str());
        if (a.sampled)
            ImGui::TextDisabled("sampled (%s of %s read)", fmt_size(a.bytes_read).c_str(), fmt_size(a.length).c_str());
        if (a.unreadable)
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(hex_colors().unreadable_text), "partly unreadable");
    }
    ImGui::EndTooltip();
}

}  // namespace

void Minimap::draw(const char* id, float width, float height, const EntropyResult* r, uint64_t doc_size,
                   uint64_t view_begin, uint64_t view_end, MinimapMode mode, MinimapEvents& ev) {
    ev = MinimapEvents{};
    if (height <= 0.0f) height = ImGui::GetContentRegionAvail().y;
    width = std::max(1.0f, std::floor(width));
    height = std::max(1.0f, std::floor(height));
    const ImVec2 p0 = ImGui::GetCursorScreenPos();
    const ImVec2 p1(p0.x + width, p0.y + height);
    ImGui::InvisibleButton(id, ImVec2(width, height));
    const bool hovered = ImGui::IsItemHovered();
    const bool active = ImGui::IsItemActive();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const int rows = int(height);
    const uint64_t size = doc_size;

    dl->AddRectFilled(p0, p1, kBackground);
    if (size > 0) {
        // Entropy: merge runs of equal colors into one rect. ByteClass: stacked segments per row.
        int run_y = 0;
        uint32_t run_c = 0;
        auto flush = [&](int y_end) {
            if (y_end > run_y && run_c)
                dl->AddRectFilled(ImVec2(p0.x, p0.y + float(run_y)), ImVec2(p1.x, p0.y + float(y_end)), run_c);
        };
        const uint32_t bad = hex_colors().unreadable_text;
        struct Spot {
            int y;
            uint32_t color;
        };
        std::vector<Spot> spots;
        for (int y = 0; y < rows; ++y) {
            const Row row = row_range(y, rows, size);
            EntropyBucket a;
            if (r) a = entropy_aggregate(*r, row.begin, row.end);
            uint32_t c = kPending;
            const bool data = a.done && (a.bytes_read > 0 || a.hole_bytes > 0);
            if (a.done && !data) c = (bad & 0x00FFFFFFu) | 0x90000000u;  // unreadable only
            else if (data && mode == MinimapMode::Entropy) c = entropy_color(a.entropy);
            if (data && mode == MinimapMode::ByteClass) {
                flush(y);
                run_c = 0;
                run_y = y + 1;
                float x = p0.x, acc = 0.0f;
                for (int k = 0; k < kByteClassCount; ++k) {
                    acc += a.class_frac[k];
                    const float x1 = k + 1 == kByteClassCount ? p1.x : p0.x + std::round(acc * width);
                    if (x1 > x)
                        dl->AddRectFilled(ImVec2(x, p0.y + float(y)), ImVec2(x1, p0.y + float(y + 1)),
                                          byte_class_color(ByteClass(k)));
                    x = std::max(x, x1);
                }
            } else if (c != run_c) {
                flush(y);
                run_y = y;
                run_c = c;
            }
            if (data && a.unreadable)  // partly unreadable: red tick on the left edge
                dl->AddRectFilled(ImVec2(p0.x, p0.y + float(y)), ImVec2(p0.x + 2.0f, p0.y + float(y + 1)), bad);
            if (data && entropy_spot(a))  // a small dense region the average hides: tick on the right
                spots.push_back({y, entropy_color(std::max(a.peak, kSpotMinBits))});
        }
        flush(rows);
        // Spot ticks last (over the runs), at least 2 px tall so a single row stays visible.
        const float tick_w = std::max(2.0f, std::floor(width / 2.0f));
        for (const Spot& sp : spots) {
            const float y0 = std::min(p0.y + float(sp.y), p1.y - 2.0f);
            dl->AddRectFilled(ImVec2(p1.x - tick_w, y0), ImVec2(p1.x, y0 + 2.0f), sp.color);
        }

        // Viewport box.
        const uint64_t vb = std::min(view_begin, size), ve = std::clamp(view_end, vb, size);
        float y0 = p0.y + float(double(height) * (double(vb) / double(size)));
        float y1 = p0.y + float(double(height) * (double(ve) / double(size)));
        if (y1 - y0 < 3.0f) {
            const float mid = (y0 + y1) * 0.5f;
            y0 = std::max(p0.y, std::min(mid - 1.5f, p1.y - 3.0f));  // strips < 3 px: from the top
            y1 = y0 + 3.0f;
        }
        y0 = std::floor(y0);
        y1 = std::ceil(y1);
        dl->AddRectFilled(ImVec2(p0.x, y0), ImVec2(p1.x, y1), kViewFill);
        dl->AddRect(ImVec2(p0.x, y0), ImVec2(p1.x, y1), kViewBorder);
    }
    dl->AddLine(ImVec2(p0.x, p0.y), ImVec2(p0.x, p1.y), hex_colors().separator);

    const ImVec2 mouse = ImGui::GetIO().MousePos;
    // Clamp as float first: the mouse position is -FLT_MAX when there is no mouse (int overflow).
    const int my = int(std::clamp(std::floor(mouse.y - p0.y), 0.0f, float(rows - 1)));
    if (active && size > 0) {
        // Centre of the pixel row under the mouse (clamped while dragging past the ends).
        const Row row = row_range(my, rows, size);
        uint64_t off = row.begin + (row.end - row.begin) / 2;
        off = std::min(off, size - 1);
        if (ImGui::IsItemActivated() || off != last_jump_) {
            ev.jump_requested = true;
            ev.jump_offset = off;
            last_jump_ = off;
        }
    } else {
        last_jump_ = UINT64_MAX;
    }
    if (hovered && size > 0) {
        const Row row = row_range(my, rows, size);
        ev.hovered = true;
        ev.hover_offset = std::min(row.begin, size - 1);
        if (!active) tooltip(r, size, row);
    }
}

}  // namespace hx
