#pragma once
// The hex editor widget: offset column | hex bytes | text column, drawn with ImDrawList.
// Scrolling is virtual and 64-bit: the view keeps its own row index (doc.view().top_row) and draws
// a custom scrollbar, because ImGui's float scroll positions cannot address TB-sized files.
// Only the visible rows are read from the document each frame.
#include <cstdint>
#include <string>
#include <vector>

#include "core/document.h"
#include "core/highlight.h"
#include "core/nav.h"

struct ImFont;
struct ImVec2;

namespace hx {

// ---- the selection convention (used by the hex view and every panel) ---------------------------
// ViewState's selection is half-open: [sel_begin, sel_end), empty when anchor == cursor. Dragging
// from byte a over byte b selects a..b inclusive. The caret is drawn ON a byte: caret_byte() is the
// last selected byte of a forward selection (cursor - 1), the first one of a backward selection
// (cursor), or the cursor without a selection - so it is always inside what is highlighted.
uint64_t caret_byte(const ViewState& v);
// Where the Inspector, the status bar's "Byte" and inspector edits work: the selection's first
// byte, else the cursor.
uint64_t focus_offset(const ViewState& v);
// How a byte range is shown everywhere (inclusive end): "0x00000010-0x0000001F (16 bytes)";
// a single byte is "0x00000010 (1 byte)", an empty range "0x00000010 (0 bytes)".
std::string fmt_range(uint64_t begin, uint64_t len);

// Color of byte `b` in the hex column (text = false) or the text column. Precedence: unreadable
// (I/O error) > modified (only pass true when highlighting is on) > byte class (class_colors) >
// the plain scheme (hex: zero dim, others bright; text: printable vs non-printable).
uint32_t byte_text_color(uint8_t b, bool text, bool unreadable, bool modified, bool class_colors);

struct HexViewConfig {
    int bytes_per_row = 16;     // 0 = auto-fit to available width (multiple of 8, min 8)
    int group_size = 8;         // visual gap every N bytes (0 = none)
    bool uppercase = true;
    bool show_ascii = true;
    bool insert_mode = false;   // typing inserts instead of overwriting
    bool highlight_modified = true;
    // Hex digits and text glyphs take their color from the byte's class (core/entropy.h ByteClass,
    // theme HexColors::byte_class) instead of the plain zero / text colors. Layout is unchanged.
    bool byte_class_colors = false;
    // Pixels left free right of the view (e.g. for a Minimap strip drawn with SameLine(0, 0)
    // right after draw()); bytes-per-row auto-fit uses the narrower width. 0 = fill the region.
    float reserve_right = 0.0f;
    ImFont* mono = nullptr;     // font to use (nullptr = current)
    float font_size = 0.0f;     // 0 = font's default size
    // Extra scrollbar tick marks (e.g. Find All hits): sorted offsets, drawn at most one per pixel.
    const std::vector<uint64_t>* tick_offsets = nullptr;
    uint32_t tick_color = 0;
    // Follow pointer (Ctrl+hover / Ctrl+click): the hovered byte starts an integer of
    // pointer_width bytes (1, 2, 3, 4, 8), sign-extended if pointer_signed; the target offset is
    // value - pointer_base, or with pointer_relative the byte's offset + value (core/nav.h PointerType).
    int pointer_width = 4;
    bool pointer_big_endian = false;
    uint64_t pointer_base = 0;
    bool pointer_signed = false;
    bool pointer_relative = false;
    // Outlined bytes [mark_offset, mark_offset + mark_length) in both columns, e.g. what the
    // Inspector's hovered / selected type covers at its decode position. 0 length = none.
    uint64_t mark_offset = 0;
    uint64_t mark_length = 0;

    PointerType pointer_type() const {
        PointerType t;
        t.width = pointer_width;
        t.is_signed = pointer_signed;
        t.big_endian = pointer_big_endian;
        t.relative = pointer_relative;
        t.base = pointer_base;
        return t;
    }
    void set_pointer_type(const PointerType& t) {
        pointer_width = t.width;
        pointer_signed = t.is_signed;
        pointer_big_endian = t.big_endian;
        pointer_relative = t.relative;
        pointer_base = t.base;
    }
};

// Pixel geometry of the last draw() (screen coordinates), for tests and automation.
struct HexViewGeometry {
    bool valid = false;         // draw() laid out rows at least once
    float hex_x = 0, text_x = 0, adv = 0, rows_y = 0, line_h = 0;
    int bpr = 16, group = 0, full_rows = 0;
    bool ascii = true;
    uint64_t top_row = 0;
};

struct HexViewEvents {
    bool cursor_moved = false;      // caret or selection changed this frame
    bool edited = false;            // a byte was typed / deleted this frame
    bool open_context_menu = false; // right-click inside the view (app draws the popup)
    bool focused = false;           // view has keyboard focus
    bool has_hover = false;
    uint64_t hover_offset = 0;      // byte under the mouse when has_hover
    int bytes_per_row = 16;         // effective value after auto-fit
    int visible_rows = 0;
    // Ctrl+click on a byte whose pointer decodes inside the file (target <= size). The caret does
    // not move; the app jumps to follow_target and records follow_from in its NavHistory.
    bool follow_requested = false;
    uint64_t follow_target = 0;
    uint64_t follow_from = 0;       // the clicked byte (start of the pointer)
    bool nav_back = false;          // mouse X1 (back) pressed while the view is hovered
    bool nav_forward = false;       // mouse X2 (forward) pressed while the view is hovered
};

// One instance per open tab (keeps drag/scrollbar interaction state).
//
// Input handled by the view while focused (everything else - copy/paste/undo/find/goto - is the
// app's job): arrows, PgUp/PgDn, Home/End (row of the caret byte: End puts the caret on the row's
// last byte, Shift+End selects through it), Ctrl+Home/End (file), Shift+nav extends selection,
// a plain move with a selection starts from the drawn caret (caret_byte) and clears it,
// Tab switches hex/text column, typing 0-9a-f (hex column) or printable chars (text column) edits
// (overwrite or insert per config; read-only docs ignore typing), Delete removes the selection or
// the byte at the caret in both modes, Backspace removes the selection, else the previous byte in
// insert mode (in overwrite mode it only moves left), mouse click/drag selects (bytes a..b
// inclusive; a click on the second hex digit puts the caret on the low nibble; a click below the
// last row or past the last byte puts the caret at EOF), Shift+click extends from the selection's
// fixed end, double-click selects the highlight (field) under the mouse, multi-selection
// (core/multisel.h, ViewState::extra_sel; extra ranges drawn in a lighter selection tint): Alt+click
// / Alt+drag selects a new range (byte a..b) and the previous selection joins the extra ranges,
// Alt+click on a byte of an extra range removes that range (on the primary selection: collapses it
// to the caret there), a plain click or Esc (claimed only while extras exist) clears the extras,
// Delete / Backspace with extras delete every range (one undo step), Ctrl+hover underlines the
// pointer (cfg.pointer_type()) starting at the hovered byte with a tooltip of its type and target
// (pointer_link_text, e.g. "u16 LE -> 0x1234") and Ctrl+click
// on a byte reports ev.follow_requested instead of moving the caret (nothing for a pointer that is
// unreadable or points beyond EOF), mouse X1/X2 set ev.nav_back / nav_forward, wheel scrolls
// 3 rows (Ctrl+wheel is left to the app for zoom), dragging the custom scrollbar maps linearly to
// the 64-bit row range.
class HexView {
public:
    // `layers` are drawn in order (later layers paint on top). Fills the available content region.
    void draw(const char* id, Document& doc, const std::vector<const HighlightSet*>& layers,
              const HexViewConfig& cfg, HexViewEvents& ev);
    // Scroll so `offset` is visible (centered if `center`); applied during the next draw().
    void request_scroll_to(uint64_t offset, bool center = true);
    // Takes a pending request_scroll_to() back (it is not applied then), e.g. to hand it to another
    // view of the same document that is drawn instead of this one (the Compare tab). False if none.
    bool take_scroll_request(uint64_t& offset, bool& center);
    void request_focus() { want_focus_ = true; }
    const HexViewGeometry& geometry() const { return geo_; }
    // Screen position inside byte `off`'s cell (hex digits, or the text column) as laid out by the
    // last draw(): x at fraction `fx` of the cell width (hex cell = both digits), y mid-row.
    ImVec2 cell_pos(uint64_t off, bool text, float fx = 0.25f) const;

private:
    HexViewGeometry geo_;
    bool want_focus_ = false;
    bool has_scroll_request_ = false;
    bool scroll_center_ = true;
    uint64_t scroll_target_ = 0;
    bool dragging_select_ = false;
    bool dragging_scrollbar_ = false;
    double scrollbar_grab_ = 0.0;
    uint64_t drag_origin_ = 0;
    std::vector<uint8_t> buf_;  // visible bytes scratch
    std::vector<uint8_t> bad_;  // 1 per visible byte that could not be read (drawn as ??)
    std::vector<const Highlight*> hl_tmp_;  // per-frame highlight query scratch
    float wheel_accum_ = 0.0f;  // fractional wheel rows (touchpads)
    int last_bpr_ = 0;          // keeps the first visible byte stable when bytes/row changes
};

}  // namespace hx
