#include "ui/text_select.h"

#include <algorithm>
#include <cfloat>
#include <cstring>

#include "imgui_internal.h"

namespace hx {

namespace {

bool is_word_byte(unsigned char c) {
    return c >= 0x80 || c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
bool is_blank(unsigned char c) { return c == ' ' || c == '\t'; }

size_t char_len(std::string_view s, size_t at) {
    if (at >= s.size()) return 0;
    unsigned int c = 0;
    const int n = ImTextCharFromUtf8(&c, s.data() + at, s.data() + s.size());
    return n > 0 ? size_t(n) : 1;
}

TextPos clamp(const std::vector<TextLine>& lines, TextPos p) {
    if (lines.empty()) return {};
    if (p.line >= lines.size()) return {lines.size() - 1, lines.back().text.size()};
    p.col = std::min(p.col, lines[p.line].text.size());
    return p;
}

}  // namespace

void TextSelect::layout(const std::vector<TextLine>& lines, float wrap_w) {
    ImFont* font = ImGui::GetFont();
    const float size = ImGui::GetFontSize();
    const float gap = ImGui::GetStyle().ItemSpacing.y;
    rows_.clear();
    float y = 0.0f;
    const float lh = ImGui::GetTextLineHeight();
    for (size_t i = 0; i < lines.size(); ++i) {
        if (i) y += gap;
        const std::string_view t = lines[i].text;
        const char* base = t.data();
        const char* end = base + t.size();
        const char* s = base;
        for (;;) {
            const char* e;
            if (wrap_w > 0.0f) {
                e = s < end ? ImFontCalcWordWrapPositionEx(font, size, s, end, wrap_w) : end;
                if (e == s && s < end && *s != '\n') e = s + char_len(t, size_t(s - base));  // always progress
            } else {
                e = static_cast<const char*>(std::memchr(s, '\n', size_t(end - s)));
                if (!e) e = end;
            }
            rows_.push_back({i, uint32_t(s - base), uint32_t(e - base), y});
            y += lh;
            if (e >= end) break;
            // the next row: after the newline, or (wrapped) after the blanks ImGui skips there too
            const char* next = wrap_w > 0.0f ? ImTextCalcWordWrapNextLineStart(e, end) : e + 1;
            if (next >= end && !std::memchr(e, '\n', size_t(end - e))) break;  // only blanks were left
            s = next;
        }
    }
    height_ = rows_.empty() ? 0.0f : y;
}

float TextSelect::x_of(const std::vector<TextLine>& lines, const Row& r, size_t col) const {
    const std::string_view t = lines[r.line].text;
    col = std::clamp<size_t>(col, r.begin, r.end);
    if (col == r.begin) return 0.0f;
    return ImGui::GetFont()->CalcTextSizeA(ImGui::GetFontSize(), FLT_MAX, 0.0f, t.data() + r.begin, t.data() + col).x;
}

TextPos TextSelect::hit(const std::vector<TextLine>& lines, ImVec2 mouse, bool nearest) const {
    if (rows_.empty()) return {};
    const float y = mouse.y - origin_.y;
    if (y < 0.0f) return {rows_.front().line, rows_.front().begin};
    // the last row starting at or above y (the gap below a line belongs to its last row)
    auto it = std::upper_bound(rows_.begin(), rows_.end(), y, [](float v, const Row& r) { return v < r.y; });
    const Row& r = *(it == rows_.begin() ? it : it - 1);
    if (it == rows_.end() && y >= height_) return {r.line, r.end};
    const std::string_view t = lines[r.line].text;
    ImFont* font = ImGui::GetFont();
    const float size = ImGui::GetFontSize();
    const float x = mouse.x - origin_.x;
    float acc = 0.0f;
    for (size_t c = r.begin; c < r.end;) {
        const size_t n = char_len(t, c);
        const float w = font->CalcTextSizeA(size, FLT_MAX, 0.0f, t.data() + c, t.data() + c + n).x;
        if (x < acc + (nearest ? w * 0.5f : w)) return {r.line, c};
        acc += w;
        c += n;
    }
    return {r.line, r.end};
}

bool TextSelect::draw(const char* id, const std::vector<TextLine>& lines, float wrap_width, uint64_t layout_gen) {
    ImGuiWindow* win = ImGui::GetCurrentWindow();
    const float avail = std::max(1.0f, ImGui::GetContentRegionAvail().x);
    const float wrap_w = wrap_width > 0.0f ? wrap_width : wrap_width == 0.0f ? avail : -1.0f;
    const float gap = ImGui::GetStyle().ItemSpacing.y;
    if (layout_gen == 0 || layout_gen != gen_ || lines.size() != nlines_ || wrap_w != wrap_w_ ||
        ImGui::GetFontSize() != font_size_ || ImGui::GetFont() != font_ || gap != gap_) {
        layout(lines, wrap_w);
        gen_ = layout_gen, nlines_ = lines.size(), wrap_w_ = wrap_w;
        font_size_ = ImGui::GetFontSize(), font_ = ImGui::GetFont(), gap_ = gap;
    }
    drawn_ = &lines;
    origin_ = ImGui::GetCursorScreenPos();
    const float lh = ImGui::GetTextLineHeight();

    // visible rows
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const float top = dl->GetClipRectMin().y - origin_.y, bottom = dl->GetClipRectMax().y - origin_.y;
    auto first = std::upper_bound(rows_.begin(), rows_.end(), top - lh, [](float v, const Row& r) { return v < r.y; });
    size_t vis_begin = size_t(first - rows_.begin()), vis_end = vis_begin;
    float width = 0.0f;
    while (vis_end < rows_.size() && rows_[vis_end].y < bottom) {
        const Row& r = rows_[vis_end++];
        width = std::max(width, x_of(lines, r, r.end));
    }
    const float item_w = wrap_width > 0.0f ? std::max(width, 1.0f) : std::max(width, avail);

    // the item: one invisible button covering every row
    ImGui::InvisibleButton(id, ImVec2(item_w, std::max(height_, 1.0f)));
    const ImGuiID item_id = ImGui::GetItemID();
    const bool clicked = ImGui::IsItemActivated();
    const ImGuiIO& io = ImGui::GetIO();
    if (clicked) {
        const int count = ImGui::GetMouseClickedCount(ImGuiMouseButton_Left);
        word_drag_ = count >= 2;
        if (count >= 3) {  // the whole line (to the start of the next one, like a text editor)
            const TextPos p = hit(lines, io.MousePos, false);
            anchor_ = {p.line, 0};
            caret_ = p.line + 1 < lines.size() ? TextPos{p.line + 1, 0} : TextPos{p.line, lines[p.line].text.size()};
        } else if (count == 2) {  // a word, a run of blanks or one other character
            const TextPos p = hit(lines, io.MousePos, false);
            const std::string_view t = p.line < lines.size() ? lines[p.line].text : std::string_view();
            size_t b = p.col, e = p.col;
            if (p.col < t.size()) {
                const unsigned char c = static_cast<unsigned char>(t[p.col]);
                auto same = [&](unsigned char x) {
                    return is_word_byte(c) ? is_word_byte(x) : is_blank(c) ? is_blank(x) : false;
                };
                if (is_word_byte(c) || is_blank(c)) {
                    while (b > 0 && same(static_cast<unsigned char>(t[b - 1]))) --b;
                    while (e < t.size() && same(static_cast<unsigned char>(t[e]))) ++e;
                } else {
                    e = p.col + char_len(t, p.col);
                }
            }
            anchor_ = {p.line, b};
            caret_ = {p.line, e};
        } else {
            const TextPos p = hit(lines, io.MousePos, true);
            if (!io.KeyShift) anchor_ = p;
            caret_ = p;
        }
    } else if (ImGui::IsItemActive() && !word_drag_ && ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f)) {
        caret_ = hit(lines, io.MousePos, true);
        // dragging past the visible part scrolls the window
        const float cy0 = dl->GetClipRectMin().y, cy1 = dl->GetClipRectMax().y;
        const float over = io.MousePos.y < cy0 ? io.MousePos.y - cy0 : io.MousePos.y > cy1 ? io.MousePos.y - cy1 : 0.0f;
        if (over != 0.0f && win->ScrollMax.y > 0.0f)
            ImGui::SetScrollY(std::clamp(ImGui::GetScrollY() + over * std::min(1.0f, io.DeltaTime * 12.0f), 0.0f,
                                         win->ScrollMax.y));
    }

    // keys while focused
    if (ImGui::GetFocusID() == item_id && ImGui::IsWindowFocused()) {
        if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_A, ImGuiInputFlags_RouteFocused)) select_all(lines);
        if (has_selection() && ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_C, ImGuiInputFlags_RouteFocused))
            copy(lines);
        if (has_selection() && ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_Insert, ImGuiInputFlags_RouteFocused))
            copy(lines);
    }

    // draw: selection behind the text
    const TextPos sb = clamp(lines, sel_begin()), se = clamp(lines, sel_end());
    const bool sel = sb != se;
    const ImU32 sel_col = ImGui::GetColorU32(ImGuiCol_TextSelectedBg);
    const ImU32 text_col = ImGui::GetColorU32(ImGuiCol_Text);
    ImFont* font = ImGui::GetFont();
    const float size = ImGui::GetFontSize();
    const float nl_w = font->CalcTextSizeA(size, FLT_MAX, 0.0f, " ").x * 0.5f;  // a selected line end
    for (size_t k = vis_begin; k < vis_end; ++k) {
        const Row& r = rows_[k];
        const ImVec2 p(origin_.x, origin_.y + r.y);
        if (sel && r.line >= sb.line && r.line <= se.line) {
            const size_t from = r.line == sb.line ? sb.col : 0;
            const size_t to = r.line == se.line ? se.col : SIZE_MAX;
            // the selection goes on past the line's end: a small mark for the selected line break
            const bool last_row = k + 1 >= rows_.size() || rows_[k + 1].line != r.line;
            const bool past_end = last_row && to > r.end;
            if (from <= r.end && to >= r.begin && (from < to)) {
                const float x0 = x_of(lines, r, std::max<size_t>(from, r.begin));
                float x1 = x_of(lines, r, std::min<size_t>(to, r.end));
                if (past_end) x1 += nl_w;
                if (x1 > x0) dl->AddRectFilled(ImVec2(p.x + x0, p.y), ImVec2(p.x + x1, p.y + lh), sel_col);
            }
        }
        if (r.end > r.begin) {
            const std::string_view t = lines[r.line].text;
            dl->AddText(font, size, p, lines[r.line].color ? lines[r.line].color : text_col, t.data() + r.begin,
                        t.data() + r.end);
        }
    }
    return clicked;
}

std::string TextSelect::selected_text(const std::vector<TextLine>& lines) const {
    if (lines.empty() || !has_selection()) return {};
    const TextPos b = clamp(lines, sel_begin()), e = clamp(lines, sel_end());
    std::string out;
    for (size_t i = b.line; i <= e.line; ++i) {
        const std::string_view t = lines[i].text;
        const size_t from = i == b.line ? b.col : 0;
        const size_t to = i == e.line ? e.col : t.size();
        if (to > from) out.append(t.data() + from, to - from);
        if (i != e.line) out += '\n';
    }
    return out;
}

void TextSelect::copy(const std::vector<TextLine>& lines) const {
    if (has_selection()) ImGui::SetClipboardText(selected_text(lines).c_str());
}

void TextSelect::select_all(const std::vector<TextLine>& lines) {
    anchor_ = {};
    caret_ = lines.empty() ? TextPos{} : TextPos{lines.size() - 1, lines.back().text.size()};
}

void TextSelect::drop_front(size_t n) {
    if (n == 0) return;
    auto move = [n](TextPos& p) { p = p.line < n ? TextPos{} : TextPos{p.line - n, p.col}; };
    move(anchor_);
    move(caret_);
    gen_ = 0;  // the rows name line indexes
}

bool TextSelect::screen_pos(TextPos p, ImVec2* out) const {
    if (!drawn_ || !font_) return false;
    for (const Row& r : rows_) {
        if (r.line != p.line || p.col < r.begin || p.col > r.end) continue;
        const std::string_view t = (*drawn_)[r.line].text;
        const float x = p.col == r.begin ? 0.0f
                                         : const_cast<ImFont*>(font_)->CalcTextSizeA(font_size_, FLT_MAX, 0.0f,
                                                                                    t.data() + r.begin, t.data() + p.col)
                                               .x;
        *out = ImVec2(origin_.x + x, origin_.y + r.y + font_size_ * 0.5f);
        return true;
    }
    return false;
}

// ---- one block ----------------------------------------------------------------------------------

void selectable_text(const char* id, std::string_view text, ImU32 color, float wrap_width) {
    static TextSelect owned;       // the block clicked last
    static TextSelect other;       // any other block: drawn without a selection
    static ImGuiID owner = 0;
    std::vector<TextLine> lines;
    for (size_t pos = 0;;) {
        const size_t nl = text.find('\n', pos);
        lines.push_back({text.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos), color});
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    ImGui::PushID(id);
    const ImGuiID me = ImGui::GetID("##text");
    TextSelect& ts = owner == me ? owned : other;
    if (&ts == &other) other.clear();
    if (ts.draw("##text", lines, wrap_width) && owner != me) {
        owner = me;
        owned = other;
    }
    if (ImGui::BeginPopupContextItem("##ctx")) {
        TextSelect& cur = owner == me ? owned : other;
        if (ImGui::MenuItem("Copy", "Ctrl+C", false, owner == me && cur.has_selection())) cur.copy(lines);
        if (ImGui::MenuItem("Select All", "Ctrl+A")) {
            owner = me;
            owned.select_all(lines);
        }
        if (ImGui::MenuItem("Copy All")) ImGui::SetClipboardText(std::string(text).c_str());
        ImGui::EndPopup();
    }
    ImGui::PopID();
}

}  // namespace hx
