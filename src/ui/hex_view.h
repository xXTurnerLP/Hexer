#pragma once
// The hex editor widget: offset column | hex bytes | text column, drawn with ImDrawList.
// Scrolling is virtual and 64-bit: the view keeps its own row index (doc.view().top_row) and draws
// a custom scrollbar, because ImGui's float scroll positions cannot address TB-sized files.
// Only the visible rows are read from the document each frame.
#include <cstdint>
#include <vector>

#include "core/document.h"
#include "core/highlight.h"

struct ImFont;

namespace hx {

struct HexViewConfig {
    int bytes_per_row = 16;     // 0 = auto-fit to available width (multiple of 8, min 8)
    int group_size = 8;         // visual gap every N bytes (0 = none)
    bool uppercase = true;
    bool show_ascii = true;
    bool insert_mode = false;   // typing inserts instead of overwriting
    bool highlight_modified = true;
    ImFont* mono = nullptr;     // font to use (nullptr = current)
    float font_size = 0.0f;     // 0 = font's default size
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
};

// One instance per open tab (keeps drag/scrollbar interaction state).
//
// Input handled by the view while focused (everything else - copy/paste/undo/find/goto - is the
// app's job): arrows, PgUp/PgDn, Home/End (row), Ctrl+Home/End (file), Shift+nav extends selection,
// Tab switches hex/text column, typing 0-9a-f (hex column) or printable chars (text column) edits
// (overwrite or insert per config; read-only docs ignore typing), Backspace/Delete remove bytes
// (selection first) in insert mode and when a selection exists, mouse click/drag selects,
// Shift+click extends, double-click selects the highlight (field) under the mouse, wheel scrolls
// 3 rows (Ctrl+wheel is left to the app for zoom), dragging the custom scrollbar maps linearly to
// the 64-bit row range.
class HexView {
public:
    // `layers` are drawn in order (later layers paint on top). Fills the available content region.
    void draw(const char* id, Document& doc, const std::vector<const HighlightSet*>& layers,
              const HexViewConfig& cfg, HexViewEvents& ev);
    // Scroll so `offset` is visible (centered if `center`); applied during the next draw().
    void request_scroll_to(uint64_t offset, bool center = true);
    void request_focus() { want_focus_ = true; }

private:
    bool want_focus_ = false;
    bool has_scroll_request_ = false;
    bool scroll_center_ = true;
    uint64_t scroll_target_ = 0;
    bool dragging_select_ = false;
    bool dragging_scrollbar_ = false;
    double scrollbar_grab_ = 0.0;
    uint64_t drag_origin_ = 0;
    std::vector<uint8_t> buf_;  // visible bytes scratch
    std::vector<const Highlight*> hl_tmp_;  // per-frame highlight query scratch
    float wheel_accum_ = 0.0f;  // fractional wheel rows (touchpads)
    int last_bpr_ = 0;          // keeps the first visible byte stable when bytes/row changes
};

}  // namespace hx
