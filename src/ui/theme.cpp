// Dark theme, font loading and the hex-view palette.
#include "ui/theme.h"

#include <string>
#include <vector>

#include <ft2build.h>
#include FT_FREETYPE_H

#include "imgui.h"
#include "imgui_internal.h"  // ImFontAtlasGetFontLoaderForStbTruetype
#include "ui/third_party/imgui_freetype.h"

#include "core/highlight.h"
#include "core/os_file.h"

namespace hx {

namespace {

bool font_file_exists(const std::string& path) {
    FileStat st = os_stat(path);
    return st.exists && !st.is_dir && st.size > 0;
}

// First existing path of `names` inside any of `dirs` ("" if none).
std::string find_font(const std::vector<std::string>& dirs, const std::vector<const char*>& names) {
    for (const char* name : names)
        for (const std::string& dir : dirs) {
            std::string p = path_join(dir, name);
            if (font_file_exists(p)) return p;
        }
    return {};
}

std::vector<std::string> font_dirs() {
    std::vector<std::string> dirs;
#ifdef _WIN32
    std::string windir = os_env("WINDIR");
    if (!windir.empty()) dirs.push_back(path_join(windir, "Fonts"));
    dirs.push_back("C:/Windows/Fonts");
    std::string local = os_env("LOCALAPPDATA");  // per-user installed fonts
    if (!local.empty()) dirs.push_back(path_join(local, "Microsoft/Windows/Fonts"));
#else
    std::string home = os_env("HOME");
    if (!home.empty()) {
        dirs.push_back(path_join(home, ".local/share/fonts"));
        dirs.push_back(path_join(home, ".fonts"));
    }
    // Debian/Ubuntu, Arch, Fedora/openSUSE layouts.
    for (const char* d : {"/usr/share/fonts/truetype/jetbrains-mono", "/usr/share/fonts/TTF",
                          "/usr/share/fonts/jetbrains-mono", "/usr/share/fonts/jetbrains-mono-fonts",
                          "/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/dejavu",
                          "/usr/share/fonts/dejavu-sans-mono-fonts", "/usr/share/fonts/dejavu-sans-fonts",
                          "/usr/share/fonts/truetype/liberation", "/usr/share/fonts/liberation-mono",
                          "/usr/share/fonts/liberation", "/usr/share/fonts/truetype/noto",
                          "/usr/share/fonts/noto", "/usr/share/fonts/google-noto",
                          "/usr/share/fonts/truetype/ubuntu", "/usr/share/fonts/ubuntu",
                          "/usr/local/share/fonts"})
        dirs.push_back(d);
#endif
    return dirs;
}

// Light text on a dark background blended in gamma space looks thinner than the glyph coverage
// says; a mild coverage boost compensates (the theme is dark-only).
constexpr float kTextContrast = 1.2f;

// FreeType loader flags for a hinting mode (unknown modes = normal).
unsigned freetype_flags(const std::string& hinting) {
    if (hinting == "none") return ImGuiFreeTypeLoaderFlags_NoHinting;
    if (hinting == "light") return ImGuiFreeTypeLoaderFlags_LightHinting;  // vertical-only snapping
    if (hinting == "mono") return ImGuiFreeTypeLoaderFlags_MonoHinting | ImGuiFreeTypeLoaderFlags_Monochrome;
    return 0;  // normal: the font's own hinting (crisp stems), auto-hinter for unhinted fonts
}

// FT_Init_FreeType only fails when out of memory, but imgui_freetype does not survive a failed
// loader init, so probe first and stay on stb_truetype if it fails.
bool freetype_works() {
    FT_Library lib = nullptr;
    if (FT_Init_FreeType(&lib) != 0) return false;
    FT_Done_FreeType(lib);
    return true;
}

// Adds a font with the atlas loader (FreeType); a file FreeType rejects is retried with stb_truetype.
// `snap` rounds advances to whole pixels (monospace cell layouts).
ImFont* add_font_file(const std::string& path, float size_px, bool merge, bool snap = false) {
    ImFontAtlas* atlas = ImGui::GetIO().Fonts;
    ImFontConfig cfg;
    cfg.MergeMode = merge;
    cfg.PixelSnapH = snap;
    cfg.RasterizerMultiply = kTextContrast;
    if (ImFont* f = atlas->AddFontFromFileTTF(path.c_str(), size_px, &cfg)) return f;
    if (atlas->FontLoader == ImFontAtlasGetFontLoaderForStbTruetype()) return nullptr;
    cfg.FontLoader = ImFontAtlasGetFontLoaderForStbTruetype();
    return atlas->AddFontFromFileTTF(path.c_str(), size_px, &cfg);
}

// Merges a broad symbol font into the font added last, for glyphs (arrows, box drawing, ...) the
// primary font lacks. ImGui 1.92 loads glyphs on demand, so no glyph ranges are needed.
void merge_symbol_fallback(const std::vector<std::string>& dirs, const std::string& primary,
                           float size_px) {
#ifdef _WIN32
    std::string sym = find_font(dirs, {"seguisym.ttf"});
#else
    std::string sym = find_font(dirs, {"DejaVuSans.ttf", "NotoSansSymbols2-Regular.ttf",
                                       "NotoSansSymbols-Regular.ttf"});
#endif
    if (!sym.empty() && sym != primary) add_font_file(sym, size_px, true);
}

ImFont* add_default_font(float size_px) {
    ImFontConfig cfg;
    cfg.SizePixels = size_px;
    cfg.RasterizerMultiply = kTextContrast;
    return ImGui::GetIO().Fonts->AddFontDefaultVector(&cfg);
}

ImVec4 col(uint32_t c) { return ImGui::ColorConvertU32ToFloat4(c); }

}  // namespace

Fonts load_fonts(float ui_size_px, float mono_size_px, const FontOptions& opt) {
    if (ui_size_px <= 0.0f) ui_size_px = 16.0f;
    if (mono_size_px <= 0.0f) mono_size_px = 16.0f;
    const std::vector<std::string> dirs = font_dirs();

    Fonts f;
    ImFontAtlas* atlas = ImGui::GetIO().Fonts;
    f.freetype = freetype_works();
    if (f.freetype) {
        atlas->SetFontLoader(ImGuiFreeType::GetFontLoader());
        atlas->FontLoaderFlags = freetype_flags(opt.hinting);
    }

#ifdef _WIN32
    std::string ui_path = find_font(dirs, {"segoeui.ttf"});
    std::string mono_path = find_font(dirs, {"CascadiaMono.ttf", "CascadiaCode.ttf", "consola.ttf"});
#else
    std::string ui_path = find_font(dirs, {"Inter-Regular.ttf", "DejaVuSans.ttf",
                                           "NotoSans-Regular.ttf", "Ubuntu-R.ttf",
                                           "LiberationSans-Regular.ttf"});
    std::string mono_path = find_font(dirs, {"JetBrainsMono-Regular.ttf", "DejaVuSansMono.ttf",
                                             "LiberationMono-Regular.ttf", "NotoSansMono-Regular.ttf",
                                             "UbuntuMono-R.ttf"});
#endif
    if (!opt.ui_path.empty() && font_file_exists(opt.ui_path)) ui_path = opt.ui_path;
    if (!opt.mono_path.empty() && font_file_exists(opt.mono_path)) mono_path = opt.mono_path;

    // The UI font is added first so it becomes the default font (Fonts[0]).
    if (!ui_path.empty()) {
        f.ui = add_font_file(ui_path, ui_size_px, false);
        if (f.ui) {
            f.ui_path = ui_path;
            merge_symbol_fallback(dirs, ui_path, ui_size_px);
        }
    }
    const bool ui_is_default = !f.ui;
    if (!f.ui) f.ui = add_default_font(ui_size_px);

    if (!mono_path.empty()) {
        f.mono = add_font_file(mono_path, mono_size_px, false, true);
        if (f.mono) {
            f.mono_path = mono_path;
            merge_symbol_fallback(dirs, mono_path, mono_size_px);
        }
    }
    // ImGui's built-in ProggyForever is monospace, so a default UI font can double as mono.
    if (!f.mono) f.mono = ui_is_default ? f.ui : add_default_font(mono_size_px);

    ImGui::GetIO().FontDefault = f.ui;
    return f;
}

void apply_dark_theme(float ui_scale) {
    if (ui_scale <= 0.0f) ui_scale = 1.0f;
    ImGuiStyle& s = ImGui::GetStyle();
    // Start from defaults so repeated calls (ui scale changes) do not compound scaling; keep fonts.
    const float font_base = s.FontSizeBase, font_main = s.FontScaleMain, font_dpi = s.FontScaleDpi;
    s = ImGuiStyle();
    s.FontSizeBase = font_base;
    s.FontScaleMain = font_main;
    s.FontScaleDpi = font_dpi;

    s.WindowPadding = ImVec2(8, 8);
    s.FramePadding = ImVec2(8, 4);
    s.ItemSpacing = ImVec2(8, 6);
    s.ItemInnerSpacing = ImVec2(6, 4);
    s.CellPadding = ImVec2(6, 3);
    s.IndentSpacing = 18;
    s.ScrollbarSize = 12;
    s.GrabMinSize = 10;
    s.WindowRounding = 6;
    s.ChildRounding = 4;
    s.FrameRounding = 4;
    s.PopupRounding = 4;
    s.ScrollbarRounding = 6;
    s.GrabRounding = 4;
    s.TabRounding = 4;
    s.WindowBorderSize = 1;
    s.ChildBorderSize = 1;
    s.PopupBorderSize = 1;
    s.FrameBorderSize = 1;
    s.TabBorderSize = 0;
    s.TabBarBorderSize = 1;
    s.TabBarOverlineSize = 2;
    s.DockingSeparatorSize = 2;
    s.SeparatorTextBorderSize = 1;
    s.WindowTitleAlign = ImVec2(0.0f, 0.5f);
    s.WindowMenuButtonPosition = ImGuiDir_None;
    s.SelectableTextAlign = ImVec2(0.0f, 0.5f);
    s.ScaleAllSizes(ui_scale);

    const uint32_t bg = rgba(0x1e, 0x1f, 0x22);        // editor background
    const uint32_t panel = rgba(0x2b, 0x2d, 0x30);     // tool windows / menus
    const uint32_t raised = rgba(0x39, 0x3b, 0x40);    // buttons, hovered tabs
    const uint32_t raised_hi = rgba(0x43, 0x45, 0x4a);
    const uint32_t raised_hi2 = rgba(0x4e, 0x51, 0x57);
    const uint32_t border = rgba(0x39, 0x3b, 0x40);
    const uint32_t text = rgba(0xdf, 0xe1, 0xe5);
    const uint32_t text_dim = rgba(0x8c, 0x8f, 0x94);
    const uint32_t accent = rgba(0x35, 0x74, 0xf0);
    const uint32_t accent_hi = rgba(0x4a, 0x85, 0xf5);
    const uint32_t accent_lo = rgba(0x2e, 0x5f, 0xc4);

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text] = col(text);
    c[ImGuiCol_TextDisabled] = col(text_dim);
    c[ImGuiCol_WindowBg] = col(panel);
    c[ImGuiCol_ChildBg] = col(rgba(0, 0, 0, 0));
    c[ImGuiCol_PopupBg] = col(rgba(0x30, 0x32, 0x36, 250));
    c[ImGuiCol_Border] = col(border);
    c[ImGuiCol_BorderShadow] = col(rgba(0, 0, 0, 0));
    c[ImGuiCol_FrameBg] = col(bg);
    c[ImGuiCol_FrameBgHovered] = col(rgba(0x25, 0x27, 0x2b));
    c[ImGuiCol_FrameBgActive] = col(rgba(0x28, 0x2a, 0x2e));
    c[ImGuiCol_TitleBg] = col(panel);
    c[ImGuiCol_TitleBgActive] = col(panel);
    c[ImGuiCol_TitleBgCollapsed] = col(panel);
    c[ImGuiCol_MenuBarBg] = col(panel);
    c[ImGuiCol_ScrollbarBg] = col(rgba(0, 0, 0, 0));
    c[ImGuiCol_ScrollbarGrab] = col(rgba(0x4a, 0x4d, 0x52, 200));
    c[ImGuiCol_ScrollbarGrabHovered] = col(rgba(0x5a, 0x5d, 0x63, 230));
    c[ImGuiCol_ScrollbarGrabActive] = col(rgba(0x6b, 0x6e, 0x74));
    c[ImGuiCol_CheckMark] = col(rgba(0xff, 0xff, 0xff));
    c[ImGuiCol_CheckboxSelectedBg] = col(accent);
    c[ImGuiCol_SliderGrab] = col(accent);
    c[ImGuiCol_SliderGrabActive] = col(accent_hi);
    c[ImGuiCol_Button] = col(raised);
    c[ImGuiCol_ButtonHovered] = col(raised_hi);
    c[ImGuiCol_ButtonActive] = col(accent_lo);
    c[ImGuiCol_Header] = col(rgba(0x35, 0x74, 0xf0, 90));
    c[ImGuiCol_HeaderHovered] = col(rgba(0xff, 0xff, 0xff, 18));
    c[ImGuiCol_HeaderActive] = col(rgba(0x35, 0x74, 0xf0, 130));
    c[ImGuiCol_Separator] = col(border);
    c[ImGuiCol_SeparatorHovered] = col(accent_lo);
    c[ImGuiCol_SeparatorActive] = col(accent);
    c[ImGuiCol_ResizeGrip] = col(rgba(0, 0, 0, 0));
    c[ImGuiCol_ResizeGripHovered] = col(accent_lo);
    c[ImGuiCol_ResizeGripActive] = col(accent);
    c[ImGuiCol_InputTextCursor] = col(text);
    c[ImGuiCol_TabHovered] = col(raised_hi);
    c[ImGuiCol_Tab] = col(panel);
    c[ImGuiCol_TabSelected] = col(bg);
    c[ImGuiCol_TabSelectedOverline] = col(accent);
    c[ImGuiCol_TabDimmed] = col(panel);
    c[ImGuiCol_TabDimmedSelected] = col(rgba(0x25, 0x26, 0x29));
    c[ImGuiCol_TabDimmedSelectedOverline] = col(raised_hi2);
    c[ImGuiCol_DockingPreview] = col(rgba(0x35, 0x74, 0xf0, 110));
    c[ImGuiCol_DockingEmptyBg] = col(bg);
    c[ImGuiCol_PlotLines] = col(text_dim);
    c[ImGuiCol_PlotLinesHovered] = col(accent_hi);
    c[ImGuiCol_PlotHistogram] = col(accent);
    c[ImGuiCol_PlotHistogramHovered] = col(accent_hi);
    c[ImGuiCol_TableHeaderBg] = col(rgba(0x32, 0x34, 0x38));
    c[ImGuiCol_TableBorderStrong] = col(border);
    c[ImGuiCol_TableBorderLight] = col(rgba(0x33, 0x35, 0x39));
    c[ImGuiCol_TableRowBg] = col(rgba(0, 0, 0, 0));
    c[ImGuiCol_TableRowBgAlt] = col(rgba(0xff, 0xff, 0xff, 7));
    c[ImGuiCol_TextLink] = col(accent_hi);
    c[ImGuiCol_TextSelectedBg] = col(rgba(0x35, 0x74, 0xf0, 110));
    c[ImGuiCol_TreeLines] = col(raised_hi);
    c[ImGuiCol_DragDropTarget] = col(accent);
    c[ImGuiCol_DragDropTargetBg] = col(rgba(0x35, 0x74, 0xf0, 40));
    c[ImGuiCol_UnsavedMarker] = col(text);
    c[ImGuiCol_NavCursor] = col(accent);
    c[ImGuiCol_NavWindowingHighlight] = col(rgba(0xff, 0xff, 0xff, 180));
    c[ImGuiCol_NavWindowingDimBg] = col(rgba(0, 0, 0, 120));
    c[ImGuiCol_ModalWindowDimBg] = col(rgba(0, 0, 0, 140));
}

const HexColors& hex_colors() {
    static const HexColors c = {
        /* background      */ rgba(0x1e, 0x1f, 0x22),
        /* row_alt         */ rgba(0xff, 0xff, 0xff, 6),
        /* offset_text     */ rgba(0x6f, 0x86, 0xa6),
        /* header_text     */ rgba(0x8c, 0x8f, 0x94),
        /* hex_text        */ rgba(0xd5, 0xd8, 0xdd),
        /* zero_text       */ rgba(0x5a, 0x5e, 0x65),
        /* ascii_text      */ rgba(0xa9, 0xc4, 0x9f),
        /* nonprint_text   */ rgba(0x50, 0x54, 0x5a),
        /* cursor          */ rgba(0x35, 0x74, 0xf0),
        /* cursor_inactive */ rgba(0x7a, 0x7e, 0x86),
        /* selection       */ rgba(0x35, 0x74, 0xf0, 95),
        /* modified_text   */ rgba(0xf0, 0xa4, 0x3a),
        /* hover           */ rgba(0xff, 0xff, 0xff, 70),
        /* separator       */ rgba(0x39, 0x3b, 0x40),
        /* search_hit      */ rgba(0xf2, 0xc9, 0x3b, 110),
        /* bookmark        */ rgba(0xef, 0x5f, 0x6b),
        /* unreadable_text */ rgba(0xff, 0x6b, 0x6b),
    };
    return c;
}

uint32_t palette_color(int index) { return field_palette(index); }

}  // namespace hx
