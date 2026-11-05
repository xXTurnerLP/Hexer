#pragma once
// Dark theme, fonts and the hex-view color palette.
#include <cstdint>

struct ImFont;

namespace hx {

struct Fonts {
    ImFont* ui = nullptr;    // proportional UI font (Segoe UI / DejaVu Sans / Inter..., fallback default)
    ImFont* mono = nullptr;  // monospace (Cascadia Mono / Consolas / JetBrains Mono / DejaVu Sans Mono..., fallback default)
};

// Must be called after ImGui::CreateContext() and before the first frame. Searches common system
// font paths on Windows and Linux; falls back to ImGui's built-in font if none found.
Fonts load_fonts(float ui_size_px, float mono_size_px);
void apply_dark_theme(float ui_scale);

// Colors used by the hex view (packed IM_COL32 / core rgba()).
struct HexColors {
    uint32_t background, row_alt, offset_text, header_text, hex_text, zero_text, ascii_text,
        nonprint_text, cursor, cursor_inactive, selection, modified_text, hover, separator,
        search_hit, bookmark;
};
const HexColors& hex_colors();

// Distinct, dark-mode friendly colors for auto-coloring parser fields (index wraps).
uint32_t palette_color(int index);

}  // namespace hx
