#pragma once
// Dark theme, fonts and the hex-view color palette.
#include <cstdint>
#include <string>

#include "core/entropy.h"  // ByteClass

struct ImFont;

namespace hx {

struct Fonts {
    ImFont* ui = nullptr;    // proportional UI font (Segoe UI / DejaVu Sans / Inter..., fallback default)
    ImFont* mono = nullptr;  // monospace (Cascadia Mono / Consolas / JetBrains Mono / DejaVu Sans Mono..., fallback default)
    bool freetype = false;   // rasterised by FreeType (hinted); false = stb_truetype fallback
    std::string ui_path, mono_path;  // files actually loaded ("" = ImGui's built-in font)
};

struct FontOptions {
    std::string ui_path, mono_path;  // font files; "" = auto-detect from the system font dirs
    std::string hinting = "normal";  // FreeType hinting: "none" | "light" | "normal" | "mono"
};

// Must be called after ImGui::CreateContext() and before the first frame. Uses FreeType (hinted,
// crisp at small sizes) and falls back to stb_truetype if FreeType cannot load the font. Missing or
// unreadable option paths fall back to auto-detection (common system font paths on Windows and
// Linux), then to ImGui's built-in font. The mono font's advances are snapped to whole pixels so
// cell-based layouts (hex view) land every glyph on the pixel grid.
Fonts load_fonts(float ui_size_px, float mono_size_px, const FontOptions& opt = {});
void apply_dark_theme(float ui_scale);

// Colors used by the hex view (packed IM_COL32 / core rgba()).
struct HexColors {
    uint32_t background, row_alt, offset_text, header_text, hex_text, zero_text, ascii_text,
        nonprint_text, cursor, cursor_inactive, selection, modified_text, hover, separator,
        search_hit, bookmark, unreadable_text;
    // Byte-class coloring (HexViewConfig::byte_class_colors, minimap), indexed by ByteClass:
    // zero dim, whitespace subtle, printable clear, control / high / 0xFF distinct. Orange stays
    // reserved for modified bytes and red for unreadable ones.
    uint32_t byte_class[kByteClassCount];
};
const HexColors& hex_colors();
uint32_t byte_class_color(ByteClass c);  // hex_colors().byte_class[c]

// Distinct, dark-mode friendly colors for auto-coloring parser fields (index wraps).
uint32_t palette_color(int index);

}  // namespace hx
