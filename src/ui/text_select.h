#pragma once
// Read-only text the user can select with the mouse and copy: the Console output, messages,
// error texts. No App dependency (tests/test_ui.cpp drives it headlessly).
//
// Interaction (the same everywhere): drag selects (dragging past the window's top / bottom
// scrolls it), Shift+click extends, double-click selects a word, triple-click a line. While the
// widget has keyboard focus (it was clicked last) Ctrl+C copies the selection and Ctrl+A selects
// everything; both are routed to the focused window only (ImGuiInputFlags_RouteFocused), so they
// win over the app's global Copy / Select All there and nowhere else. Ctrl+C without a selection
// stays the app's. The right-click menu is the caller's (copy() / select_all() / has_selection()),
// except for selectable_text(), which has its own.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "imgui.h"

namespace hx {

struct TextLine {
    std::string_view text;  // one line; a '\n' inside starts a new row (selection counts it as a byte)
    ImU32 color = 0;        // 0 = ImGuiCol_Text
};

struct TextPos {
    size_t line = 0;
    size_t col = 0;  // byte offset in the line (on a UTF-8 character boundary)
    bool operator==(const TextPos& o) const { return line == o.line && col == o.col; }
    bool operator!=(const TextPos& o) const { return !(*this == o); }
    bool operator<(const TextPos& o) const { return line != o.line ? line < o.line : col < o.col; }
};

class TextSelect {
public:
    // Draws `lines` at the cursor of the current window and handles the mouse / keys. `wrap_width`:
    // > 0 wraps at that width (px), 0 at the content region's width, < 0 never (one row per line,
    // as wide as the visible rows, for a window with a horizontal scrollbar). Rows are one text line
    // high; lines are ItemSpacing.y apart. Only the visible rows are drawn. `layout_gen` != 0 lets an
    // unchanged text (same generation, line count, width, font) reuse last frame's row layout.
    // Returns true on the frame the widget was clicked (it then has keyboard focus).
    bool draw(const char* id, const std::vector<TextLine>& lines, float wrap_width, uint64_t layout_gen = 0);

    bool has_selection() const { return anchor_ != caret_; }
    TextPos sel_begin() const { return anchor_ < caret_ ? anchor_ : caret_; }
    TextPos sel_end() const { return anchor_ < caret_ ? caret_ : anchor_; }
    std::string selected_text(const std::vector<TextLine>& lines) const;  // lines joined by '\n'
    void copy(const std::vector<TextLine>& lines) const;                  // nothing without a selection
    void select_all(const std::vector<TextLine>& lines);
    void select(TextPos anchor, TextPos caret) { anchor_ = anchor, caret_ = caret; }
    void clear() { anchor_ = caret_ = TextPos{}; }
    // `n` lines were removed from the front of the text (a capped log, a clear): positions move up.
    void drop_front(size_t n);

    // Screen position of `p` as laid out by the last draw() (tests); false when not on a drawn row.
    bool screen_pos(TextPos p, ImVec2* out) const;

private:
    struct Row {
        size_t line;
        uint32_t begin, end;  // bytes of the line on this row
        float y;              // top, relative to the widget's origin
    };
    void layout(const std::vector<TextLine>& lines, float wrap_w);
    TextPos hit(const std::vector<TextLine>& lines, ImVec2 mouse, bool nearest) const;
    float x_of(const std::vector<TextLine>& lines, const Row& r, size_t col) const;

    TextPos anchor_, caret_;
    std::vector<Row> rows_;
    float height_ = 0.0f;
    ImVec2 origin_{0.0f, 0.0f};
    // layout cache key
    uint64_t gen_ = 0;
    size_t nlines_ = 0;
    float wrap_w_ = -1.0f, font_size_ = 0.0f, gap_ = 0.0f;
    const ImFont* font_ = nullptr;
    const std::vector<TextLine>* drawn_ = nullptr;  // for screen_pos (tests): last draw's lines
    bool word_drag_ = false;                        // a double / triple click is held: no drag
};

// One selectable read-only text block (a message, an error) with its own right-click menu
// (Copy / Select All / Copy All). `text` may hold '\n'. `wrap_width` as in TextSelect::draw.
// Only one such block holds a selection at a time (the last one clicked), keyed by `id`.
void selectable_text(const char* id, std::string_view text, ImU32 color = 0, float wrap_width = 0.0f);

}  // namespace hx
