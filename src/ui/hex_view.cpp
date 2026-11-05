// The hex editor widget. See hex_view.h for the behaviour contract.
//
// Structure of HexView::draw():
//   1. layout   - font metrics, bytes per row, column x positions, row counts (Layout)
//   2. input    - scrollbar, mouse wheel, mouse selection, keyboard navigation and typing
//   3. drawing  - one doc.read() of the visible rows, then backgrounds, text, caret, scrollbar
// All row/offset math is uint64_t; floats are only used for on-screen pixel positions.
#include "ui/hex_view.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <string>

#include "imgui.h"
#include "imgui_internal.h"  // ImGuiWindow::InnerRect (exact visible area of the child window)

#include "core/nav.h"
#include "core/util.h"
#include "ui/theme.h"

namespace hx {

uint64_t caret_byte(const ViewState& v) { return v.cursor > v.anchor ? v.cursor - 1 : v.cursor; }

uint64_t focus_offset(const ViewState& v) { return v.has_selection() ? v.sel_begin() : v.cursor; }

std::string fmt_range(uint64_t begin, uint64_t len) {
    std::string s = "0x" + fmt_hex(begin, 8);
    if (len > 1) s += "-0x" + fmt_hex(begin + len - 1, 8);
    s += " (";
    if (len >= 1024) s += fmt_size(len) + ", ";
    s += std::to_string(len) + (len == 1 ? " byte)" : " bytes)");
    return s;
}

uint32_t byte_text_color(uint8_t b, bool text, bool unreadable, bool modified, bool class_colors) {
    const HexColors& C = hex_colors();
    if (unreadable) return C.unreadable_text;
    if (modified) return C.modified_text;
    if (class_colors) return byte_class_color(byte_class(b));
    if (text) return b >= 0x20 && b < 0x7F ? C.ascii_text : C.nonprint_text;
    return b == 0 ? C.zero_text : C.hex_text;
}

namespace {

constexpr int kMaxBytesPerRow = 256;
constexpr int kMaxAutoBytesPerRow = 128;
constexpr int kWheelRows = 3;
constexpr int kMouseBack = 3, kMouseForward = 4;  // X1 / X2 (GLFW_MOUSE_BUTTON_4 / _5)

// ---- layout ------------------------------------------------------------------------------------

// Horizontal layout in character cells (monospace):
//   [pad][offset digits][gap][hex bytes "XX XX .. XX" + group gaps][gap][text column][pad]
// Each byte takes 3 cells in the hex column ("XX "), plus one extra cell after every group.
struct Layout {
    ImFont* font = nullptr;
    float font_px = 0, adv = 0, line_h = 0, text_dy = 0;
    int bpr = 16, group = 0, off_digits = 8;
    bool ascii = true;

    // Screen-space x positions (already shifted by the horizontal scroll).
    float base_x = 0, off_x = 0, sep1_x = 0, hex_x = 0, hex_end_x = 0, sep2_x = 0, text_x = 0,
          text_end_x = 0;
    // Visible area of the child window and its parts.
    ImVec2 inner_min, inner_max;
    float rows_y = 0;   // top of the first row (below the header)
    float data_x1 = 0;  // right edge of the data area == left edge of the scrollbar
    float sb_w = 0;
    int full_rows = 1;  // rows that fit entirely
    uint64_t total_rows = 1, max_top = 0;

    int cell(int i) const { return i * 3 + (group ? i / group : 0); }
    float hex_byte_x(int i) const { return hex_x + adv * float(cell(i)); }
    float text_byte_x(int i) const { return text_x + adv * float(i); }
    float row_y(uint64_t row, uint64_t top) const { return rows_y + line_h * float(row - top); }
};

int effective_group(int group, int bpr) { return (group <= 0 || group >= bpr) ? 0 : group; }

int hex_cells(int bpr, int group) { return (bpr - 1) * 3 + (group ? (bpr - 1) / group : 0) + 2; }

int total_cells(int bpr, int group, int off_digits, bool ascii) {
    return 1 + off_digits + 2 + hex_cells(bpr, group) + (ascii ? 2 + bpr : 0) + 1;
}

int hex_digits(uint64_t v) {
    int n = 0;
    do {
        ++n;
        v >>= 4;
    } while (v);
    return n;
}

int choose_bytes_per_row(const HexViewConfig& cfg, float avail_w, float adv, int off_digits) {
    if (cfg.bytes_per_row > 0) return std::min(cfg.bytes_per_row, kMaxBytesPerRow);
    int best = 8;
    for (int n = 16; n <= kMaxAutoBytesPerRow; n += 8) {
        float w = adv * float(total_cells(n, effective_group(cfg.group_size, n), off_digits, cfg.show_ascii));
        if (w > avail_w) break;
        best = n;
    }
    return best;
}

void set_row_counts(Layout& L, uint64_t size) {
    L.total_rows = size / uint64_t(L.bpr) + 1;  // +1: the row holding the EOF (append) position
    L.max_top = L.total_rows > uint64_t(L.full_rows) ? L.total_rows - uint64_t(L.full_rows) : 0;
}

// Places the columns at the child's (scrolled) origin.
void place_columns(Layout& L, float scroll_x) {
    // Whole pixels: with the mono font's whole-pixel advances every cell, separator and highlight
    // edge then lands on the pixel grid (no blurry glyphs or 2-pixel lines).
    L.base_x = std::floor(L.inner_min.x - scroll_x);
    const float a = L.adv;
    const int hc = hex_cells(L.bpr, L.group);
    L.off_x = L.base_x + a;
    L.sep1_x = L.off_x + a * float(L.off_digits + 1);
    L.hex_x = L.off_x + a * float(L.off_digits + 2);
    L.hex_end_x = L.hex_x + a * float(hc);
    L.sep2_x = L.hex_end_x + a;
    L.text_x = L.hex_end_x + a * 2;
    L.text_end_x = L.text_x + a * float(L.bpr);
}

uint64_t clamp_top(uint64_t top, const Layout& L) { return std::min(top, L.max_top); }

uint64_t scroll_rows(uint64_t top, int64_t delta, const Layout& L) {
    if (delta < 0) {
        uint64_t d = uint64_t(-delta);
        return top > d ? top - d : 0;
    }
    return clamp_top(top + uint64_t(delta), L);
}

uint64_t ensure_row_visible(uint64_t top, uint64_t row, const Layout& L) {
    if (row < top) top = row;
    else if (row >= top + uint64_t(L.full_rows)) top = row - uint64_t(L.full_rows) + 1;
    return clamp_top(top, L);
}

// ---- hit testing -------------------------------------------------------------------------------

struct Hit {
    uint64_t off = 0;     // clamped to [0, size]
    bool text = false;    // in the text column
    bool low = false;     // on the second hex digit
    bool on_byte = false; // really over an existing byte cell (for hover)
};

// Byte under screen point `p`. Rows above the first one map to it; below the last row (the one
// holding the EOF position) everything is EOF, so a click or drag into the empty area under the
// data reaches the end of the file.
Hit hit_test(const Layout& L, ImVec2 p, uint64_t top, uint64_t size) {
    Hit h;
    float rel_f = std::floor((p.y - L.rows_y) / L.line_h);
    int64_t rel = int64_t(std::clamp(rel_f, 0.0f, float(L.full_rows)));
    const bool below = top + uint64_t(rel) >= L.total_rows;
    bool row_inside = rel_f >= 0.0f && rel_f <= float(L.full_rows) && !below;
    uint64_t row = std::min(top + uint64_t(rel), L.total_rows - 1);
    if (below) {
        h.off = size;
        h.text = L.ascii && p.x >= L.sep2_x;
        return h;
    }

    int col = 0;
    bool col_inside = false;
    if (L.ascii && p.x >= L.sep2_x) {
        h.text = true;
        float c = std::floor((p.x - L.text_x) / L.adv);
        col = int(std::clamp(c, 0.0f, float(L.bpr - 1)));
        col_inside = p.x >= L.text_x && p.x < L.text_end_x;
    } else {
        // The gap between two bytes (one cell, or two at a group boundary) is split in the middle.
        for (int i = L.bpr - 1; i > 0; --i)
            if (p.x >= 0.5f * (L.hex_byte_x(i - 1) + 2.0f * L.adv + L.hex_byte_x(i))) {
                col = i;
                break;
            }
        h.low = p.x >= L.hex_byte_x(col) + L.adv;
        col_inside = p.x >= L.hex_x - 0.5f * L.adv && p.x < L.hex_end_x + 0.5f * L.adv;
    }
    uint64_t off = row * uint64_t(L.bpr) + uint64_t(col);
    if (off >= size) {
        off = size;
        h.low = false;
    }
    h.off = off;
    h.on_byte = row_inside && col_inside && off < size;
    return h;
}

// Innermost highlight at `off`; later layers win.
const Highlight* highlight_at(const std::vector<const HighlightSet*>& layers, uint64_t off) {
    for (size_t i = layers.size(); i-- > 0;)
        if (layers[i])
            if (const Highlight* h = layers[i]->at(off)) return h;
    return nullptr;
}

// ---- editing -----------------------------------------------------------------------------------

bool can_edit(const Document& doc) { return !doc.read_only() && !doc.busy(); }

int hex_value(unsigned c) {
    if (c >= '0' && c <= '9') return int(c - '0');
    if (c >= 'a' && c <= 'f') return int(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return int(c - 'A' + 10);
    return -1;
}

// Insert mode with a selection: the typed byte replaces the selection (one undo step).
bool replace_selection(Document& doc, uint8_t b, bool keep_on_byte) {
    ViewState& v = doc.view();
    uint64_t pos = v.sel_begin();
    if (!doc.replace(pos, v.sel_len(), &b, 1)) return false;
    v.cursor = v.anchor = keep_on_byte ? pos : pos + 1;
    v.low_nibble = keep_on_byte;
    return true;
}

bool type_nibble(Document& doc, const HexViewConfig& cfg, int digit) {
    ViewState& v = doc.view();
    if (v.has_selection()) {
        if (cfg.insert_mode) return replace_selection(doc, uint8_t(digit << 4), true);
        v.cursor = v.anchor = v.sel_begin();
        v.low_nibble = false;
    }
    const uint64_t pos = v.cursor;
    const bool low = v.low_nibble && pos < doc.size();
    uint8_t old = 0;
    if (pos < doc.size()) doc.read(pos, &old, 1);

    if (cfg.insert_mode && !low) {
        uint8_t b = uint8_t(digit << 4);  // new byte; the low nibble then overwrites it (coalesced)
        if (!doc.insert(pos, &b, 1, true)) return false;
        v.low_nibble = true;
    } else {
        uint8_t b = low ? uint8_t((old & 0xF0) | digit) : uint8_t((digit << 4) | (old & 0x0F));
        if (!doc.overwrite(pos, &b, 1, true)) return false;  // at EOF this appends a byte
        if (low) {
            v.cursor = pos + 1;
            v.low_nibble = false;
        } else {
            v.low_nibble = true;
        }
    }
    v.anchor = v.cursor;
    return true;
}

bool type_char(Document& doc, const HexViewConfig& cfg, uint8_t c) {
    ViewState& v = doc.view();
    if (v.has_selection()) {
        if (cfg.insert_mode) return replace_selection(doc, c, false);
        v.cursor = v.anchor = v.sel_begin();
    }
    const uint64_t pos = v.cursor;
    bool ok = cfg.insert_mode ? doc.insert(pos, &c, 1, true) : doc.overwrite(pos, &c, 1, true);
    if (!ok) return false;
    v.cursor = v.anchor = pos + 1;
    v.low_nibble = false;
    return true;
}

bool erase_selection(Document& doc) {
    ViewState& v = doc.view();
    uint64_t b = v.sel_begin();
    if (!doc.erase(b, v.sel_len())) return false;
    v.cursor = v.anchor = b;
    v.low_nibble = false;
    return true;
}

bool delete_forward(Document& doc) {
    ViewState& v = doc.view();
    if (v.has_selection()) return erase_selection(doc);
    if (v.cursor >= doc.size() || !doc.erase(v.cursor, 1)) return false;
    v.anchor = v.cursor;
    v.low_nibble = false;
    return true;
}

// Returns true if bytes were removed (otherwise it may still have moved the caret).
bool backspace(Document& doc, const HexViewConfig& cfg, bool editable) {
    ViewState& v = doc.view();
    if (editable && v.has_selection()) return erase_selection(doc);
    if (!cfg.insert_mode) {  // overwrite mode: just move left
        if (v.low_nibble && !v.ascii_focus) v.low_nibble = false;
        else if (v.cursor > 0) --v.cursor;
        v.low_nibble = false;
        v.anchor = v.cursor;
        return false;
    }
    if (!editable) return false;
    if (v.low_nibble && !v.ascii_focus && v.cursor < doc.size()) {
        // Half-typed inserted byte: remove it.
        if (!doc.erase(v.cursor, 1)) return false;
    } else {
        if (v.cursor == 0 || !doc.erase(v.cursor - 1, 1)) return false;
        --v.cursor;
    }
    v.anchor = v.cursor;
    v.low_nibble = false;
    return true;
}

// ---- drawing helpers ---------------------------------------------------------------------------

// Batches consecutive same-colored characters of one row into a single AddText call. Gaps between
// cells are padded with spaces (which produce no geometry), so x positions stay cell-exact.
struct TextRun {
    ImDrawList* dl;
    const Layout& L;
    float x0, y;
    char buf[1024];
    int len = 0, start = 0;
    uint32_t col = 0;

    TextRun(ImDrawList* d, const Layout& l, float x, float yy) : dl(d), L(l), x0(x), y(yy) {}
    ~TextRun() { flush(); }

    void put(int cell, const char* s, int n, uint32_t c) {
        if (len) {
            int gap = cell - (start + len);
            if (c != col || gap < 0 || gap > 8 || len + gap + n > int(sizeof(buf))) flush();
        }
        if (!len) {
            start = cell;
            col = c;
        }
        while (start + len < cell) buf[len++] = ' ';
        std::memcpy(buf + len, s, size_t(n));
        len += n;
    }
    void flush() {
        if (len) dl->AddText(L.font, L.font_px, ImVec2(x0 + L.adv * float(start), y), col, buf, buf + len);
        len = 0;
    }
};

constexpr uint32_t kLinkColor = IM_COL32(0x6c, 0xa4, 0xff, 0xff);  // follow-pointer underline

uint32_t with_alpha(uint32_t c, uint32_t a) { return (c & 0x00FFFFFFu) | (a << 24); }

// Highlight colors arrive opaque; the view tints them. Explicitly translucent colors are kept.
uint32_t highlight_fill(uint32_t c) {
    uint32_t a = c >> 24;
    return with_alpha(c, a == 255 ? 72u : a);
}

// Fills [begin, end) in the visible rows (hex and/or text column), one rounded rect per row piece.
void fill_range(ImDrawList* dl, const Layout& L, uint64_t top, uint64_t draw_rows, uint64_t begin,
                uint64_t end, uint32_t color, float rounding, bool hex, bool text) {
    if (end <= begin || draw_rows == 0) return;
    const uint64_t bpr = uint64_t(L.bpr);
    uint64_t first = std::max(begin / bpr, top);
    uint64_t last = std::min((end - 1) / bpr, top + draw_rows - 1);
    for (uint64_t row = first; row <= last; ++row) {
        uint64_t rs = row * bpr;
        int a = int(std::max(begin, rs) - rs);
        int b = int(std::min(end, rs + bpr) - rs);  // exclusive
        ImDrawFlags flags = 0;
        bool round_l = rs + uint64_t(a) == begin, round_r = rs + uint64_t(b) == end;
        if (round_l && round_r) flags = ImDrawFlags_RoundCornersAll;
        else if (round_l) flags = ImDrawFlags_RoundCornersLeft;
        else if (round_r) flags = ImDrawFlags_RoundCornersRight;
        else flags = ImDrawFlags_RoundCornersNone;
        float y0 = L.row_y(row, top) + 1.0f, y1 = y0 + L.line_h - 2.0f;
        if (hex) {
            float x0 = std::floor(L.hex_byte_x(a) - 0.5f * L.adv) + 1.0f;
            float x1 = std::floor(L.hex_byte_x(b - 1) + 2.5f * L.adv) - 1.0f;
            dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x1, y1), color, rounding, flags);
        }
        if (text && L.ascii)
            dl->AddRectFilled(ImVec2(L.text_byte_x(a), y0), ImVec2(L.text_byte_x(b), y1), color, rounding, flags);
    }
}

// Underlines [begin, end) in the visible rows, hex and text column (the follow-pointer link).
void underline_range(ImDrawList* dl, const Layout& L, uint64_t top, uint64_t draw_rows, uint64_t begin,
                     uint64_t end, uint32_t color) {
    if (end <= begin || draw_rows == 0) return;
    const uint64_t bpr = uint64_t(L.bpr);
    uint64_t first = std::max(begin / bpr, top);
    uint64_t last = std::min((end - 1) / bpr, top + draw_rows - 1);
    for (uint64_t row = first; row <= last; ++row) {
        uint64_t rs = row * bpr;
        int a = int(std::max(begin, rs) - rs);
        int b = int(std::min(end, rs + bpr) - rs);  // exclusive
        float y = std::floor(L.row_y(row, top) + L.text_dy + L.font_px) + 1.0f;
        const float t = std::max(1.0f, std::floor(L.font_px / 12.0f));
        dl->AddRectFilled(ImVec2(L.hex_byte_x(a), y), ImVec2(L.hex_byte_x(b - 1) + 2.0f * L.adv, y + t), color);
        if (L.ascii) dl->AddRectFilled(ImVec2(L.text_byte_x(a), y), ImVec2(L.text_byte_x(b), y + t), color);
    }
}

void format_hex(char* out, uint64_t v, int digits, const char* hexchars) {
    for (int i = digits - 1; i >= 0; --i) {
        out[i] = hexchars[v & 0xF];
        v >>= 4;
    }
}

}  // namespace

// ---- HexView -----------------------------------------------------------------------------------

ImVec2 HexView::cell_pos(uint64_t off, bool text, float fx) const {
    const HexViewGeometry& g = geo_;
    const uint64_t bpr = uint64_t(std::max(1, g.bpr));
    const int col = int(off % bpr);
    const uint64_t row = off / bpr;
    const float y = g.rows_y + g.line_h * (float(int64_t(row) - int64_t(g.top_row)) + 0.5f);
    if (text) return ImVec2(g.text_x + g.adv * (float(col) + fx), y);
    const int cell = col * 3 + (g.group ? col / g.group : 0);
    return ImVec2(g.hex_x + g.adv * (float(cell) + 2.0f * fx), y);
}

void HexView::request_scroll_to(uint64_t offset, bool center) {
    has_scroll_request_ = true;
    scroll_target_ = offset;
    scroll_center_ = center;
}

bool HexView::take_scroll_request(uint64_t& offset, bool& center) {
    if (!has_scroll_request_) return false;
    has_scroll_request_ = false;
    offset = scroll_target_;
    center = scroll_center_;
    return true;
}

void HexView::draw(const char* id, Document& doc, const std::vector<const HighlightSet*>& layers,
                   const HexViewConfig& cfg, HexViewEvents& ev) {
    ev = HexViewEvents{};
    ImGuiIO& io = ImGui::GetIO();
    const ImGuiStyle& style = ImGui::GetStyle();
    const HexColors& C = hex_colors();
    ViewState& v = doc.view();

    // Remember the UI font for the tooltip before switching to the monospace font.
    ImFont* ui_font = ImGui::GetFont();
    const float ui_font_size = style.FontSizeBase;
    ImFont* mono = cfg.mono ? cfg.mono : ui_font;
    const float mono_size = cfg.font_size > 0.0f ? cfg.font_size : (cfg.mono ? cfg.mono->LegacySize : ui_font_size);
    ImGui::PushFont(mono, mono_size);

    // ---- 1. layout -----------------------------------------------------------------------------
    Layout L;
    L.font = ImGui::GetFont();
    L.font_px = ImGui::GetFontSize();
    L.adv = L.font->CalcTextSizeA(L.font_px, FLT_MAX, 0.0f, "0").x;
    if (L.adv <= 0.0f) L.adv = L.font_px * 0.6f;
    L.line_h = std::floor(L.font_px * 1.3f + 0.5f);
    L.text_dy = std::floor((L.line_h - L.font_px) * 0.5f);
    L.ascii = cfg.show_ascii;
    L.sb_w = std::max(style.ScrollbarSize, 8.0f);

    uint64_t size = doc.size();
    L.off_digits = std::max(8, hex_digits(size));
    const float reserve = std::max(0.0f, cfg.reserve_right);
    ImVec2 avail = ImGui::GetContentRegionAvail();
    avail.x -= reserve;
    L.bpr = std::max(1, choose_bytes_per_row(cfg, avail.x - L.sb_w, L.adv, L.off_digits));
    L.group = effective_group(cfg.group_size, L.bpr);
    const float content_w = L.adv * float(total_cells(L.bpr, L.group, L.off_digits, L.ascii));

    // Content width is explicit (enables ImGui's horizontal scrollbar when a fixed row is too
    // wide); content height is 1 so ImGui never shows a vertical scrollbar - we draw our own.
    ImGui::SetNextWindowContentSize(ImVec2(content_w + L.sb_w, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, C.background);
    const bool visible = ImGui::BeginChild(id, ImVec2(reserve > 0.0f ? -reserve : 0.0f, 0), ImGuiChildFlags_None,
                                           ImGuiWindowFlags_HorizontalScrollbar |
                                               ImGuiWindowFlags_NoScrollWithMouse |
                                               ImGuiWindowFlags_NoNavInputs);
    ImGui::PopStyleColor();
    ImGuiWindow* win = ImGui::GetCurrentWindow();
    L.inner_min = win->InnerRect.Min;
    L.inner_max = win->InnerRect.Max;
    if (!visible || L.inner_max.x - L.inner_min.x < L.adv * 4 || L.inner_max.y - L.inner_min.y < L.line_h * 2) {
        ImGui::EndChild();
        ImGui::PopFont();
        ev.bytes_per_row = L.bpr;
        return;
    }
    // Take keyboard focus when asked, or when the host window itself got focused (e.g. its tab was
    // clicked) and nothing in it is being edited, so typing goes straight to the bytes.
    const bool parent_focused = win->ParentWindow && GImGui->NavWindow == win->ParentWindow;
    if (want_focus_ || (parent_focused && !ImGui::IsAnyItemActive())) {
        ImGui::SetWindowFocus();
        want_focus_ = false;
    }

    L.data_x1 = L.inner_max.x - L.sb_w;
    L.rows_y = L.inner_min.y + L.line_h + 2.0f;  // header row
    L.full_rows = std::max(1, int((L.inner_max.y - L.rows_y) / L.line_h));
    place_columns(L, ImGui::GetScrollX());
    set_row_counts(L, size);
    geo_.valid = true;
    geo_.hex_x = L.hex_x;
    geo_.text_x = L.text_x;
    geo_.adv = L.adv;
    geo_.rows_y = L.rows_y;
    geo_.line_h = L.line_h;
    geo_.bpr = L.bpr;
    geo_.group = L.group;
    geo_.full_rows = L.full_rows;
    geo_.ascii = L.ascii;

    // Keep the first visible byte stable when bytes/row changes (auto-fit while resizing).
    if (last_bpr_ > 0 && last_bpr_ != L.bpr) v.top_row = v.top_row * uint64_t(last_bpr_) / uint64_t(L.bpr);
    last_bpr_ = L.bpr;

    // Sanitize view state (document may have shrunk through undo / reload).
    v.cursor = std::min(v.cursor, size);
    v.anchor = std::min(v.anchor, size);
    if (!L.ascii) v.ascii_focus = false;
    if (v.ascii_focus || v.cursor >= size) v.low_nibble = false;

    if (has_scroll_request_) {
        uint64_t row = std::min(scroll_target_, size) / uint64_t(L.bpr);
        if (scroll_center_) {
            uint64_t half = uint64_t(L.full_rows / 2);
            v.top_row = row > half ? row - half : 0;
        } else {
            v.top_row = ensure_row_visible(v.top_row, row, L);
        }
        has_scroll_request_ = false;
    }
    v.top_row = clamp_top(v.top_row, L);

    const uint64_t old_cursor = v.cursor, old_anchor = v.anchor, old_top = v.top_row;
    const bool old_low = v.low_nibble, old_ascii = v.ascii_focus;
    bool keep_caret_visible = false;
    const bool focused = ImGui::IsWindowFocused();
    const ImVec2 mouse = io.MousePos;

    // ---- 2a. scrollbar -------------------------------------------------------------------------
    const float track_y0 = L.inner_min.y, track_y1 = L.inner_max.y, track_h = track_y1 - track_y0;
    auto thumb_metrics = [&](float& thumb_y, float& thumb_h) {
        double frac = double(L.full_rows) / double(L.total_rows);
        thumb_h = float(std::clamp(double(track_h) * frac, double(std::max(style.GrabMinSize, 20.0f)), double(track_h)));
        double pos = L.max_top ? double(v.top_row) / double(L.max_top) : 0.0;
        thumb_y = track_y0 + float(double(track_h - thumb_h) * pos);
    };

    ImGui::SetCursorScreenPos(ImVec2(L.data_x1, track_y0));
    ImGui::InvisibleButton("##vscroll", ImVec2(L.sb_w, track_h));
    const bool sb_hovered = ImGui::IsItemHovered();
    const bool sb_active = ImGui::IsItemActive();
    if (L.max_top > 0) {
        float thumb_y, thumb_h;
        thumb_metrics(thumb_y, thumb_h);
        if (ImGui::IsItemActivated() && mouse.y >= thumb_y && mouse.y < thumb_y + thumb_h) {
            dragging_scrollbar_ = true;
            scrollbar_grab_ = double(mouse.y - thumb_y);
        }
        if (!sb_active) dragging_scrollbar_ = false;
        if (dragging_scrollbar_) {
            double range = double(track_h - thumb_h);
            if (range > 0.0) {
                double t = std::clamp((double(mouse.y) - scrollbar_grab_ - double(track_y0)) / range, 0.0, 1.0);
                v.top_row = clamp_top(uint64_t(t * double(L.max_top) + 0.5), L);
            }
        } else if (sb_active && ImGui::IsMouseClicked(ImGuiMouseButton_Left, true)) {
            // Click on the track pages towards the mouse (repeats while held).
            if (mouse.y < thumb_y) v.top_row = scroll_rows(v.top_row, -int64_t(L.full_rows), L);
            else if (mouse.y >= thumb_y + thumb_h) v.top_row = scroll_rows(v.top_row, L.full_rows, L);
        }
    } else {
        dragging_scrollbar_ = false;
    }

    // ---- 2b. mouse wheel -----------------------------------------------------------------------
    if (ImGui::IsWindowHovered() && !io.KeyCtrl) {
        if (io.MouseWheel != 0.0f && io.KeyShift) {
            ImGui::SetScrollX(ImGui::GetScrollX() - io.MouseWheel * L.adv * 6.0f);
        } else if (io.MouseWheel != 0.0f) {
            wheel_accum_ -= io.MouseWheel * float(kWheelRows);
            float whole = std::trunc(wheel_accum_);
            wheel_accum_ -= whole;
            if (whole != 0.0f) v.top_row = scroll_rows(v.top_row, int64_t(whole), L);
        }
        if (io.MouseWheelH != 0.0f) ImGui::SetScrollX(ImGui::GetScrollX() - io.MouseWheelH * L.adv * 6.0f);
    }

    // ---- 2c. mouse in the data area ------------------------------------------------------------
    ImGui::SetCursorScreenPos(ImVec2(L.inner_min.x, L.rows_y));
    ImGui::InvisibleButton("##data", ImVec2(std::max(1.0f, L.data_x1 - L.inner_min.x), std::max(1.0f, L.inner_max.y - L.rows_y)),
                           ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight);
    const bool data_hovered = ImGui::IsItemHovered();
    const bool tooltip_hover = ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip);

    // Selection model: dragging from byte a over byte b selects [min(a,b), max(a,b)+1).
    auto select_span = [&](uint64_t a, uint64_t b) {
        if (b >= a) {
            v.anchor = a;
            v.cursor = std::min(b + 1, size);
        } else {
            v.anchor = std::min(a + 1, size);
            v.cursor = b;
        }
        v.low_nibble = false;
    };

    if (ImGui::IsWindowHovered()) {
        if (ImGui::IsMouseClicked(kMouseBack)) ev.nav_back = true;
        if (ImGui::IsMouseClicked(kMouseForward)) ev.nav_forward = true;
    }

    if (data_hovered) {
        Hit h = hit_test(L, mouse, v.top_row, size);
        if (io.KeyCtrl && !io.KeyShift && h.on_byte && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            // Follow pointer: the app jumps (and records history); the caret stays put.
            dragging_select_ = false;
            uint64_t t = 0;
            if (decode_pointer(doc, h.off, cfg.pointer_width, cfg.pointer_big_endian, cfg.pointer_base, t)) {
                ev.follow_requested = true;
                ev.follow_target = t;
                ev.follow_from = h.off;
            }
        } else if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
            dragging_select_ = false;
            if (const Highlight* hl = highlight_at(layers, h.off)) {
                uint64_t b = std::min(hl->offset, size);
                uint64_t e = hl->length > size - b ? size : b + hl->length;
                v.anchor = b;
                v.cursor = e;
                v.low_nibble = false;
            }
        } else if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            if (io.KeyShift) {
                // Extend from the fixed end of the current selection (the byte it started on).
                drag_origin_ = (v.has_selection() && v.cursor < v.anchor) ? v.anchor - 1 : v.anchor;
                select_span(drag_origin_, h.off);
            } else {
                drag_origin_ = h.off;
                v.cursor = v.anchor = h.off;
                v.low_nibble = !h.text && h.low;
            }
            v.ascii_focus = h.text;
            dragging_select_ = true;
        } else if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
            if (!(v.has_selection() && h.off >= v.sel_begin() && h.off < v.sel_end())) {
                v.cursor = v.anchor = h.off;
                v.low_nibble = false;
                v.ascii_focus = h.text;
            }
            ev.open_context_menu = true;
            ImGui::SetWindowFocus();
        }
    }
    if (dragging_select_) {
        if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            dragging_select_ = false;
        } else {
            // Auto-scroll when dragging above/below the rows, faster the further away.
            const float rows_bottom = L.rows_y + L.line_h * float(L.full_rows);
            if (mouse.y < L.rows_y)
                v.top_row = scroll_rows(v.top_row, -(1 + int64_t((L.rows_y - mouse.y) / L.line_h)), L);
            else if (mouse.y > rows_bottom)
                v.top_row = scroll_rows(v.top_row, 1 + int64_t((mouse.y - rows_bottom) / L.line_h), L);
            ImVec2 p = mouse;
            p.y = std::clamp(p.y, L.rows_y, rows_bottom - 1.0f);
            Hit h = hit_test(L, p, v.top_row, size);
            if (h.off != drag_origin_ || ImGui::IsMouseDragging(ImGuiMouseButton_Left)) select_span(drag_origin_, h.off);
        }
    }

    // ---- 2d. keyboard --------------------------------------------------------------------------
    if (focused) {
        const bool shift = io.KeyShift, ctrl = io.KeyCtrl;
        const bool editable = can_edit(doc);
        const uint64_t bpr = uint64_t(L.bpr);
        bool moved = false;

        auto move_rows = [&](int64_t d) {
            uint64_t row = v.cursor / bpr, col = v.cursor % bpr, last_row = size / bpr;
            uint64_t nr = d < 0 ? (row > uint64_t(-d) ? row - uint64_t(-d) : 0) : std::min(row + uint64_t(d), last_row);
            v.cursor = std::min(nr * bpr + col, size);
        };
        auto nav = [&](ImGuiKey key) { return ImGui::IsKeyPressed(key, true); };
        // A plain move with a selection starts from the caret as drawn (inside the selection) and
        // collapses it; Shift+moves keep the anchor and move the cursor boundary.
        const uint64_t cb = caret_byte(v);
        auto collapse = [&] {
            if (!shift && v.has_selection()) {
                v.cursor = v.anchor = cb;
                v.low_nibble = false;
            }
        };
        const uint64_t cb_row_start = cb - cb % bpr;

        if (!io.KeyAlt) {
            if (nav(ImGuiKey_LeftArrow)) {
                collapse();
                // On the low nibble, Left first goes back to the high nibble of the same byte.
                if (shift || !v.low_nibble || v.ascii_focus) v.cursor -= v.cursor > 0 ? 1 : 0;
                moved = true;
            }
            if (nav(ImGuiKey_RightArrow)) {
                collapse();
                v.cursor = std::min(v.cursor + 1, size);
                moved = true;
            }
            if (nav(ImGuiKey_UpArrow)) {
                if (ctrl) {
                    v.top_row = scroll_rows(v.top_row, -1, L);  // scroll without moving the caret
                } else {
                    collapse();
                    move_rows(-1);
                    moved = true;
                }
            }
            if (nav(ImGuiKey_DownArrow)) {
                if (ctrl) {
                    v.top_row = scroll_rows(v.top_row, 1, L);
                } else {
                    collapse();
                    move_rows(1);
                    moved = true;
                }
            }
            if (nav(ImGuiKey_PageUp)) {
                collapse();
                move_rows(-int64_t(L.full_rows));
                v.top_row = scroll_rows(v.top_row, -int64_t(L.full_rows), L);
                moved = true;
            }
            if (nav(ImGuiKey_PageDown)) {
                collapse();
                move_rows(L.full_rows);
                v.top_row = scroll_rows(v.top_row, L.full_rows, L);
                moved = true;
            }
            if (nav(ImGuiKey_Home)) {
                v.cursor = ctrl ? 0 : cb_row_start;  // row of the drawn caret
                moved = true;
            }
            if (nav(ImGuiKey_End)) {
                if (ctrl)
                    v.cursor = size;
                else if (shift)  // half-open selection: end after the row's last byte
                    v.cursor = std::min(cb_row_start + bpr, size);
                else             // caret on the row's last byte (stays put on an empty last row)
                    v.cursor = cb_row_start + bpr - 1 < size ? cb_row_start + bpr - 1
                                                             : (size > cb_row_start ? size - 1 : size);
                moved = true;
            }
        }
        if (moved) {
            v.low_nibble = false;  // every move lands on a byte's high nibble
            if (!shift) v.anchor = v.cursor;
            keep_caret_visible = true;
        }
        if (L.ascii && !ctrl && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_Tab, false)) {
            v.ascii_focus = !v.ascii_focus;
            v.low_nibble = false;
            keep_caret_visible = true;
        }

        if (!ctrl && !io.KeyAlt && nav(ImGuiKey_Delete) && editable && delete_forward(doc)) {
            ev.edited = true;
            keep_caret_visible = true;
        }
        if (!ctrl && !io.KeyAlt && nav(ImGuiKey_Backspace)) {
            if (backspace(doc, cfg, editable)) ev.edited = true;
            keep_caret_visible = true;
        }

        // Typed characters. Ctrl chords are shortcuts. AltGr types: it is Ctrl+Alt on Windows and
        // plain (Right) Alt on X11/Wayland; GLFW already drops characters of real Alt chords.
        const bool chord = (io.KeyCtrl && !io.KeyAlt) || io.KeySuper;
        if (!chord && editable) {
            for (ImWchar wc : io.InputQueueCharacters) {
                unsigned c = unsigned(wc);
                if (c < 0x20 || c > 0x7E) continue;  // printable ASCII only
                bool ok = false;
                if (v.ascii_focus) {
                    ok = type_char(doc, cfg, uint8_t(c));
                } else {
                    int d = hex_value(c);
                    if (d >= 0) ok = type_nibble(doc, cfg, d);
                }
                if (ok) {
                    ev.edited = true;
                    keep_caret_visible = true;
                }
            }
        }
    }

    // Edits change the size; refresh row metrics before scrolling/drawing.
    size = doc.size();
    set_row_counts(L, size);
    v.cursor = std::min(v.cursor, size);
    v.anchor = std::min(v.anchor, size);
    if (keep_caret_visible) {
        v.top_row = ensure_row_visible(v.top_row, caret_byte(v) / uint64_t(L.bpr), L);
        // Horizontal too, when a fixed-width row is wider than the view (applies next frame).
        if (ImGui::GetScrollMaxX() > 0.0f) {
            const int col = int(caret_byte(v) % uint64_t(L.bpr));
            const float cx = v.ascii_focus ? L.text_byte_x(col) : L.hex_byte_x(col);
            const float cw = v.ascii_focus ? L.adv : 2.0f * L.adv;
            const float x0 = L.inner_min.x + L.adv, x1 = L.data_x1 - L.adv;
            if (cx < x0) ImGui::SetScrollX(ImGui::GetScrollX() - (x0 - cx));
            else if (cx + cw > x1) ImGui::SetScrollX(ImGui::GetScrollX() + (cx + cw - x1));
        }
    }
    v.top_row = clamp_top(v.top_row, L);
    geo_.top_row = v.top_row;

    // ---- 3. drawing ----------------------------------------------------------------------------
    const uint64_t top = v.top_row;
    const uint64_t caret = caret_byte(v);  // the byte the caret is drawn on
    const uint64_t bpr = uint64_t(L.bpr);
    const uint64_t draw_rows = std::min(uint64_t(L.full_rows) + 1, L.total_rows - top);
    const uint64_t vis_begin = top * bpr;
    const uint64_t vis_end = std::min(size, (top + draw_rows) * bpr);
    buf_.resize(size_t(draw_rows * bpr));
    bad_.resize(buf_.size());
    const size_t got =
        vis_end > vis_begin ? doc.read(vis_begin, buf_.data(), size_t(vis_end - vis_begin), bad_.data()) : 0;
    const uint64_t data_end = vis_begin + got;  // bytes in [vis_begin, data_end) are available

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const char* hexchars = cfg.uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    const ImVec2 data_min(L.inner_min.x, L.rows_y), data_max(L.data_x1, L.inner_max.y);
    const float rounding = std::max(2.0f, L.font_px * 0.2f);

    dl->AddRectFilled(L.inner_min, L.inner_max, C.background);

    // Header row: column numbers (cursor column emphasised) and column titles.
    dl->PushClipRect(L.inner_min, ImVec2(L.data_x1, L.rows_y), true);
    {
        const float y = L.inner_min.y + L.text_dy;
        const uint64_t cur_col = caret % bpr;
        dl->AddText(L.font, L.font_px, ImVec2(L.off_x, y), C.header_text, "Offset");
        TextRun run(dl, L, L.hex_x, y);
        for (int i = 0; i < L.bpr; ++i) {
            char t[2];
            format_hex(t, uint64_t(i) & 0xFF, 2, hexchars);
            run.put(L.cell(i), t, 2, uint64_t(i) == cur_col ? C.cursor : C.header_text);
        }
        run.flush();
        if (L.ascii)
            dl->AddText(L.font, L.font_px, ImVec2(L.text_x, y), C.header_text, L.bpr >= 12 ? "Decoded text" : "Text");
        dl->AddLine(ImVec2(L.inner_min.x, L.rows_y - 1.0f), ImVec2(L.data_x1, L.rows_y - 1.0f), C.separator);
    }
    dl->PopClipRect();

    dl->PushClipRect(data_min, data_max, true);

    // Row tints, offsets column separators.
    for (uint64_t k = 0; k < draw_rows; ++k) {
        uint64_t row = top + k;
        if (row & 1) {
            float y = L.row_y(row, top);
            dl->AddRectFilled(ImVec2(L.inner_min.x, y), ImVec2(L.data_x1, y + L.line_h), C.row_alt);
        }
    }
    dl->AddLine(ImVec2(L.sep1_x, L.rows_y), ImVec2(L.sep1_x, L.inner_max.y), C.separator);
    if (L.ascii) dl->AddLine(ImVec2(L.sep2_x, L.rows_y), ImVec2(L.sep2_x, L.inner_max.y), C.separator);

    // Highlight layers (later layers on top), then the selection.
    for (const HighlightSet* layer : layers) {
        if (!layer || layer->empty() || vis_end <= vis_begin) continue;
        hl_tmp_.clear();
        layer->query(vis_begin, vis_end, hl_tmp_);
        for (const Highlight* h : hl_tmp_) {
            uint64_t e = h->length > size - std::min(h->offset, size) ? size : h->offset + h->length;
            fill_range(dl, L, top, draw_rows, h->offset, e, highlight_fill(h->color), rounding, true, true);
        }
    }
    if (v.has_selection())
        fill_range(dl, L, top, draw_rows, v.sel_begin(), v.sel_end(), C.selection, rounding, true, true);

    // Caret geometry. With a selection the caret is an outline on the selection's active end byte
    // (the selection fill stays visible); without one it is the solid nibble/char box.
    const bool sel_caret = v.has_selection();
    const uint64_t cur_row = caret / bpr;
    const bool caret_visible = cur_row >= top && cur_row < top + draw_rows;
    const int cur_col = int(caret % bpr);
    ImVec2 caret_hex_min, caret_hex_max, caret_txt_min, caret_txt_max;
    if (caret_visible) {
        float y0 = L.row_y(cur_row, top) + 1.0f, y1 = y0 + L.line_h - 2.0f;
        float hx0 = L.hex_byte_x(cur_col);
        caret_hex_min = ImVec2(hx0 - 2.0f, y0);
        caret_hex_max = ImVec2(hx0 + 2.0f * L.adv + 2.0f, y1);
        caret_txt_min = ImVec2(L.text_byte_x(cur_col), y0);
        caret_txt_max = ImVec2(L.text_byte_x(cur_col) + L.adv, y1);
        if (sel_caret) {
            // outline drawn after the bytes
        } else if (focused && !v.ascii_focus) {
            dl->AddRectFilled(caret_hex_min, caret_hex_max, with_alpha(C.cursor, 90), 2.0f);
            float nx = hx0 + (v.low_nibble ? L.adv : 0.0f);
            dl->AddRectFilled(ImVec2(nx - (v.low_nibble ? 0.0f : 2.0f), y0),
                              ImVec2(nx + L.adv + (v.low_nibble ? 2.0f : 0.0f), y1), C.cursor, 2.0f);
        } else if (focused && L.ascii) {
            dl->AddRectFilled(caret_txt_min, caret_txt_max, C.cursor, 2.0f);
        }
    }

    // Bytes: offsets, hex digits, text. Modified bytes are tinted when configured.
    const bool caret_solid_hex = focused && !v.ascii_focus && !sel_caret;
    const bool caret_solid_txt = focused && v.ascii_focus && !sel_caret;
    const uint32_t on_caret = rgba(0xff, 0xff, 0xff);
    for (uint64_t k = 0; k < draw_rows; ++k) {
        const uint64_t row = top + k;
        const uint64_t rs = row * bpr;
        const float y = L.row_y(row, top) + L.text_dy;

        char off_buf[20];
        format_hex(off_buf, rs, L.off_digits, hexchars);
        dl->AddText(L.font, L.font_px, ImVec2(L.off_x, y), row == cur_row ? C.hex_text : C.offset_text,
                    off_buf, off_buf + L.off_digits);

        const int row_len = rs < data_end ? int(std::min(bpr, data_end - rs)) : 0;
        if (row_len == 0) continue;
        const uint8_t* bytes = buf_.data() + (rs - vis_begin);
        const uint8_t* bad = bad_.data() + (rs - vis_begin);
        const bool row_modified = cfg.highlight_modified && doc.is_modified_range(rs, uint64_t(row_len));

        TextRun hex_run(dl, L, L.hex_x, y);
        TextRun txt_run(dl, L, L.text_x, y);
        for (int i = 0; i < row_len; ++i) {
            const uint8_t b = bytes[i];
            const bool modified = row_modified && doc.is_modified_range(rs + uint64_t(i), 1);
            const bool is_caret = caret_visible && row == cur_row && i == cur_col;
            const bool unreadable = bad[i] != 0;  // I/O error: not a real zero
            char t[2] = {hexchars[b >> 4], hexchars[b & 0xF]};
            if (unreadable) t[0] = t[1] = '?';
            uint32_t hc = byte_text_color(b, false, unreadable, modified, cfg.byte_class_colors);
            if (is_caret && caret_solid_hex) hc = on_caret;
            hex_run.put(L.cell(i), t, 2, hc);
            if (L.ascii) {
                const bool printable = !unreadable && b >= 0x20 && b < 0x7F;
                char ch = unreadable ? '?' : printable ? char(b) : '.';
                uint32_t tc = byte_text_color(b, true, unreadable, modified, cfg.byte_class_colors);
                if (is_caret && caret_solid_txt) tc = on_caret;
                txt_run.put(i, &ch, 1, tc);
            }
        }
    }

    // Caret outlines: inactive column (or both when the view is not focused); with a selection the
    // focused column gets a bright outline on the active end byte.
    if (caret_visible) {
        const bool hex_active = sel_caret && focused && !v.ascii_focus;
        const bool txt_active = sel_caret && focused && v.ascii_focus;
        if (!caret_solid_hex)
            dl->AddRect(caret_hex_min, caret_hex_max, hex_active ? C.cursor : C.cursor_inactive, 2.0f, 0,
                        hex_active ? 2.0f : 1.0f);
        if (L.ascii && !caret_solid_txt)
            dl->AddRect(caret_txt_min, caret_txt_max, txt_active ? C.cursor : C.cursor_inactive, 2.0f, 0,
                        txt_active ? 2.0f : 1.0f);
    }

    // Bookmark markers in the offset gutter.
    for (const Bookmark& bm : v.bookmarks) {
        uint64_t row = bm.offset / bpr;
        if (row < top || row >= top + draw_rows) continue;
        float y = L.row_y(row, top);
        float x = L.base_x + L.adv * 0.25f;
        dl->AddRectFilled(ImVec2(x, y + 3.0f), ImVec2(x + std::max(3.0f, L.adv * 0.35f), y + L.line_h - 3.0f),
                          bm.color ? bm.color : C.bookmark, 1.5f);
    }

    // Hover: subtle box around the byte under the mouse in both columns. With Ctrl held the
    // pointer starting there is underlined like a link (red when it cannot be followed).
    Hit hover;
    bool link = false, link_ok = false;
    uint64_t link_target = 0;
    if (data_hovered && !dragging_scrollbar_) {
        hover = hit_test(L, mouse, top, size);
        if (hover.on_byte) {
            ev.has_hover = true;
            ev.hover_offset = hover.off;
            uint64_t row = hover.off / bpr;
            int col = int(hover.off % bpr);
            float y0 = L.row_y(row, top) + 1.0f, y1 = y0 + L.line_h - 2.0f;
            float hx0 = L.hex_byte_x(col);
            dl->AddRect(ImVec2(hx0 - 2.0f, y0), ImVec2(hx0 + 2.0f * L.adv + 2.0f, y1), C.hover, 2.0f);
            if (L.ascii)
                dl->AddRect(ImVec2(L.text_byte_x(col), y0), ImVec2(L.text_byte_x(col) + L.adv, y1), C.hover, 2.0f);
            if (io.KeyCtrl && !io.KeyShift && !dragging_select_) {
                link = true;
                link_ok = decode_pointer(doc, hover.off, cfg.pointer_width, cfg.pointer_big_endian,
                                         cfg.pointer_base, link_target);
                const uint64_t w = uint64_t(std::clamp(cfg.pointer_width, 1, 8));
                const uint64_t end = w > size - hover.off ? size : hover.off + w;
                underline_range(dl, L, top, draw_rows, hover.off, end, link_ok ? kLinkColor : C.unreadable_text);
                if (link_ok) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            }
        }
    }
    dl->PopClipRect();

    // Scrollbar: track, caret/bookmark ticks, thumb.
    {
        const ImVec2 t0(L.data_x1, track_y0), t1(L.inner_max.x, track_y1);
        dl->AddRectFilled(t0, t1, rgba(0, 0, 0, 40));
        dl->AddLine(ImVec2(t0.x, t0.y), ImVec2(t0.x, t1.y), C.separator);
        auto tick_y = [&](uint64_t row) {
            return track_y0 + float(double(track_h) * (double(row) / double(L.total_rows)));
        };
        const float mid_x = std::floor((t0.x + t1.x) * 0.5f);
        // Search hits (right half): one binary search per pixel row of the track, so a million
        // hits cost no more than a few.
        if (cfg.tick_offsets && !cfg.tick_offsets->empty() && track_h > 0.0f) {
            const std::vector<uint64_t>& hits = *cfg.tick_offsets;
            const uint32_t hc = cfg.tick_color ? cfg.tick_color : C.search_hit;
            const int px = int(track_h);
            for (int y = 0; y < px; ++y) {
                const uint64_t r0 = uint64_t(double(y) / double(track_h) * double(L.total_rows));
                const uint64_t r1 = uint64_t(double(y + 1) / double(track_h) * double(L.total_rows));
                const uint64_t lo = r0 * bpr, hi = std::max(r1, r0 + 1) * bpr;
                auto it = std::lower_bound(hits.begin(), hits.end(), lo);
                if (it == hits.end()) break;
                if (*it >= hi) continue;
                const float yy = track_y0 + float(y);
                dl->AddRectFilled(ImVec2(mid_x, yy), ImVec2(t1.x, yy + 2.0f), with_alpha(hc, 230));
            }
        }
        // Bookmarks (left half, slightly taller).
        for (const Bookmark& bm : v.bookmarks) {
            float y = std::floor(tick_y(bm.offset / bpr));
            dl->AddRectFilled(ImVec2(t0.x + 1.0f, y - 1.0f), ImVec2(mid_x, y + 2.0f), bm.color ? bm.color : C.bookmark);
        }
        if (L.max_top > 0) {
            float thumb_y, thumb_h;
            thumb_metrics(thumb_y, thumb_h);
            ImGuiCol ci = dragging_scrollbar_ ? ImGuiCol_ScrollbarGrabActive
                          : sb_hovered        ? ImGuiCol_ScrollbarGrabHovered
                                              : ImGuiCol_ScrollbarGrab;
            float pad = std::max(2.0f, std::floor(L.sb_w * 0.2f));
            dl->AddRectFilled(ImVec2(t0.x + pad, thumb_y + 1.0f), ImVec2(t1.x - pad + 1.0f, thumb_y + thumb_h - 1.0f),
                              ImGui::GetColorU32(ci), (L.sb_w - 2.0f * pad) * 0.5f);
        }
        float cy = tick_y(cur_row);
        dl->AddRectFilled(ImVec2(t0.x + 1.0f, cy - 1.0f), ImVec2(t1.x, cy + 1.0f), C.cursor);
    }

    // Tooltip: the link target while Ctrl is held (no delay), else offset, innermost highlight
    // label, little-endian quick values.
    if (link && !ImGui::IsAnyMouseDown()) {
        ImGui::PushFont(ui_font, ui_font_size);
        ImGui::BeginTooltip();
        if (link_ok)
            ImGui::Text(cfg.uppercase ? "\xE2\x86\x92 0x%llX  (Ctrl+click to follow)"
                                      : "\xE2\x86\x92 0x%llx  (Ctrl+click to follow)",
                        (unsigned long long)link_target);
        else
            ImGui::TextUnformatted("\xE2\x86\x92 beyond EOF");  // U+2192
        std::string kind = "u" + std::to_string(std::clamp(cfg.pointer_width, 1, 8) * 8) +
                           (cfg.pointer_big_endian ? " big-endian" : " little-endian");
        if (cfg.pointer_base) kind += ", base 0x" + fmt_hex(cfg.pointer_base, 1, cfg.uppercase);
        ImGui::TextDisabled("%s", kind.c_str());
        ImGui::EndTooltip();
        ImGui::PopFont();
    } else if (tooltip_hover && ev.has_hover && !dragging_select_ && !dragging_scrollbar_ && !ImGui::IsAnyMouseDown()) {
        uint8_t q[4] = {0, 0, 0, 0};
        size_t n = doc.read(ev.hover_offset, q, 4);
        ImGui::PushFont(ui_font, ui_font_size);
        ImGui::BeginTooltip();
        ImGui::Text(cfg.uppercase ? "Offset 0x%llX  (%llu)" : "Offset 0x%llx  (%llu)",
                    (unsigned long long)ev.hover_offset, (unsigned long long)ev.hover_offset);
        if (const Highlight* hl = highlight_at(layers, ev.hover_offset))
            if (!hl->label.empty()) ImGui::TextUnformatted(hl->label.c_str());
        if (v.has_selection() && ev.hover_offset >= v.sel_begin() && ev.hover_offset < v.sel_end())
            ImGui::TextDisabled("Selection: %llu bytes", (unsigned long long)v.sel_len());
        ImGui::Separator();
        if (n >= 1) ImGui::Text("u8   %-11u i8   %d", unsigned(q[0]), int(int8_t(q[0])));
        if (n >= 2) {
            uint16_t u16 = uint16_t(q[0] | (q[1] << 8));
            ImGui::Text("u16  %-11u i16  %d", unsigned(u16), int(int16_t(u16)));
        }
        if (n >= 4) {
            uint32_t u32 = uint32_t(q[0]) | (uint32_t(q[1]) << 8) | (uint32_t(q[2]) << 16) | (uint32_t(q[3]) << 24);
            ImGui::Text("u32  %-11u i32  %d", unsigned(u32), int(int32_t(u32)));
        }
        ImGui::TextDisabled("little-endian");
        ImGui::EndTooltip();
        ImGui::PopFont();
    }

    ImGui::EndChild();
    ImGui::PopFont();

    // ---- events --------------------------------------------------------------------------------
    ev.focused = focused;
    ev.bytes_per_row = L.bpr;
    ev.visible_rows = L.full_rows;
    ev.cursor_moved = v.cursor != old_cursor || v.anchor != old_anchor || v.low_nibble != old_low ||
                      v.ascii_focus != old_ascii || ev.edited;
    if (ev.cursor_moved || v.top_row != old_top) ++doc.view_generation;
}

}  // namespace hx
