// Dockable panels: Inspector, Structure, Console, Search Results, Bookmarks, Strings, Hashes + the
// status bar.
// Each panel reads the active tab through App helpers and never touches a busy (saving) document.
#include "ui/panels.h"

#include <algorithm>
#include <cfloat>
#include <climits>
#include <cstdio>
#include <string>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"
#include "misc/cpp/imgui_stdlib.h"

#include "core/hash.h"
#include "core/highlight.h"
#include "core/inspector.h"
#include "core/nav.h"
#include "core/util.h"
#include "ui/app_internal.h"
#include "ui/hex_view.h"

namespace hx {

namespace {

const ImVec4 kErrColor(1.0f, 0.42f, 0.42f, 1.0f);
const ImVec4 kWarnColor(1.0f, 0.78f, 0.35f, 1.0f);
const ImVec4 kInputColor(0.55f, 0.75f, 1.0f, 1.0f);
const ImVec4 kResultColor(0.60f, 0.90f, 0.65f, 1.0f);

unsigned long long ull(uint64_t v) { return static_cast<unsigned long long>(v); }

// Begin a panel window; returns false (after End) when collapsed / hidden in a dock tab.
bool begin_panel(const char* name, bool* open) {
    // Each panel tab already has its own close button; drop the duplicate one at the node's right.
    ImGuiWindowClass wc;
    wc.DockNodeFlagsOverrideSet = ImGuiDockNodeFlags_NoCloseButton;
    ImGui::SetNextWindowClass(&wc);
    if (ImGui::Begin(name, open)) return true;
    ImGui::End();
    return false;
}

// Shown instead of panel contents when there is nothing to show.
void empty_note(App& app, const char* no_doc_text) {
    Tab* t = active_tab(app);
    ImGui::TextDisabled("%s", t ? "Document is being saved..." : no_doc_text);
}

// Single-line in-place editor. Returns +1 = commit, -1 = cancelled, 0 = still editing.
// With `commit_on_blur`, clicking elsewhere after an edit commits instead of cancelling.
int inline_edit_input(InlineEdit& e, bool commit_on_blur) {
    if (e.focus) {
        ImGui::SetKeyboardFocusHere();
        e.focus = false;
    }
    ImGui::SetNextItemWidth(-FLT_MIN);
    const bool enter = ImGui::InputText("##inline", &e.buf,
                                        ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
    if (!e.error.empty() && ImGui::IsItemActive()) ImGui::SetTooltip("%s", e.error.c_str());
    if (enter) return 1;
    if (ImGui::IsItemDeactivated() && ImGui::IsKeyPressed(ImGuiKey_Escape, false)) return -1;
    if (commit_on_blur && ImGui::IsItemDeactivatedAfterEdit()) return 1;
    if (!ImGui::IsItemActive() && ImGui::GetFrameCount() > e.start_frame + 2) return -1;
    return 0;
}

// Popups close on Esc only with keyboard navigation enabled, which the app does not use.
void close_popup_on_escape() {
    if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) ImGui::CloseCurrentPopup();
}

// Keep editing after a rejected value (error shown as tooltip + status).
void retry_edit(App& app, InlineEdit& e, const std::string& err) {
    e.error = err.empty() ? "invalid value" : err;
    e.focus = true;
    e.start_frame = ImGui::GetFrameCount();
    set_status(app, "Invalid value: " + e.error);
}

void draw_swatch(uint32_t color) {
    const float sz = ImGui::GetTextLineHeight() * 0.7f;
    ImVec2 p = ImGui::GetCursorScreenPos();
    const float pad = (ImGui::GetTextLineHeight() - sz) * 0.5f;
    ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(p.x, p.y + pad), ImVec2(p.x + sz, p.y + pad + sz),
                                              color | 0xFF000000u, 2.0f);
    ImGui::Dummy(ImVec2(sz, ImGui::GetTextLineHeight()));
    ImGui::SameLine();
}

// A small "->" button at the right end of the current table cell. Returns true when clicked.
bool follow_button(bool enabled, const std::string& tooltip) {
    const char* arrow = "\xE2\x86\x92";  // U+2192
    const float bw = ImGui::CalcTextSize(arrow).x + ImGui::GetStyle().FramePadding.x * 2.0f;
    ImGui::SameLine();
    const float avail = ImGui::GetContentRegionAvail().x;
    if (avail > bw) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + avail - bw);
    ImGui::BeginDisabled(!enabled);
    const bool clicked = ImGui::SmallButton(arrow);
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("%s", tooltip.c_str());
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) && !enabled) ImGui::SetTooltip("%s", tooltip.c_str());
    return clicked && enabled;
}

// Tooltip / target of following the `width`-byte pointer at `at`.
std::string follow_tip(App& app, const Document& d, uint64_t at, int width, bool be, bool& ok) {
    uint64_t target = 0;
    ok = decode_pointer(d, at, width, be, app.settings.pointer_base, target);
    std::string base = app.settings.pointer_base ? " - base " + fmt_offset(app.settings.pointer_base) : std::string();
    return ok ? "Follow pointer" + base + " \xE2\x86\x92 " + fmt_offset(target) + "  (Alt+Left goes back)"
              : "Cannot follow: the value" + base + " points beyond EOF";
}

std::string hex_preview(const uint8_t* data, size_t n) {
    std::string s;
    s.reserve(n * 3);
    static const char* digits = "0123456789ABCDEF";
    for (size_t i = 0; i < n; ++i) {
        if (i) s += ' ';
        s += digits[data[i] >> 4];
        s += digits[data[i] & 15];
    }
    return s;
}

}  // namespace

// =============================================================================================
// Inspector
// =============================================================================================

namespace {

void commit_inspector_edit(App& app, Document& d, const InspRow& r, bool be) {
    std::vector<uint8_t> out;
    std::string err;
    if (!inspector_encode(r.type, app.insp_edit.buf, be, out, &err)) {
        retry_edit(app, app.insp_edit, err);
        return;
    }
    const uint64_t at = focus_offset(d.view());
    // Same size: overwrite in place. Variable-length types (LEB128) may change the byte count.
    const bool ok = (r.size == 0 || out.size() == r.size) ? d.overwrite(at, out.data(), out.size())
                                                          : d.replace(at, r.size, out.data(), out.size());
    app.insp_edit.end();
    if (!ok) {
        report_edit_failure(app, d);
        return;
    }
    d.view_generation++;
    set_status(app, std::string("Wrote ") + r.name + " (" + std::to_string(out.size()) + " bytes) at " +
                        fmt_offset(at));
}

void draw_inspector_row(App& app, Tab& t, Document& d, const InspRow& r, int i, bool be) {
    const uint64_t cur = focus_offset(d.view());
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::PushID(i);
    const bool editing = app.insp_edit.active(i, cur);
    const char* value = r.value.empty() ? "-" : r.value.c_str();
    if (ImGui::Selectable(r.name, app.insp_sel == i,
                          ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick |
                              ImGuiSelectableFlags_AllowOverlap))
        app.insp_sel = i;
    const bool hovered = ImGui::IsItemHovered();
    if (hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && r.editable && !d.read_only())
        app.insp_edit.begin(i, cur, r.value);
    if (hovered && !editing && r.size)
        ImGui::SetItemTooltip("%s: %zu byte%s%s", r.name, r.size, r.size == 1 ? "" : "s",
                              r.editable ? "  (double-click or Enter to edit)" : "");
    if (ImGui::BeginPopupContextItem("##ctx")) {
        if (ImGui::MenuItem("Copy value")) ImGui::SetClipboardText(value);
        if (ImGui::MenuItem("Edit value", nullptr, false, r.editable && !d.read_only()))
            app.insp_edit.begin(i, cur, r.value);
        close_popup_on_escape();
        ImGui::EndPopup();
    }
    ImGui::TableSetColumnIndex(1);
    if (editing) {
        int res = inline_edit_input(app.insp_edit, false);
        if (res > 0) commit_inspector_edit(app, d, r, be);
        if (res < 0) app.insp_edit.end();
    } else {
        ImGui::PushFont(app.fonts.mono, 0.0f);
        if (r.size == 0)
            ImGui::TextDisabled("%s", value);
        else
            ImGui::TextUnformatted(value);
        ImGui::PopFont();
        const int width = r.type == InspType::U32 ? 4 : r.type == InspType::U64 ? 8 : 0;
        if (width && r.size) {
            bool ok = false;
            const std::string tip = follow_tip(app, d, cur, width, be, ok);
            if (follow_button(ok, tip)) follow_pointer(app, t, cur, width, be);
        }
    }
    ImGui::PopID();
}

void draw_selection_info(Document& d) {
    const ViewState& v = d.view();
    if (!v.has_selection()) {
        ImGui::TextDisabled("No selection  \xC2\xB7  caret %s of %s", fmt_offset(v.cursor).c_str(),
                            fmt_offset(d.size()).c_str());
        ImGui::TextDisabled("Values decode from the caret byte.");
        return;
    }
    ImGui::Text("Selection %s", fmt_range(v.sel_begin(), v.sel_len()).c_str());
    ImGui::TextDisabled("Values decode from the first selected byte.");
}

}  // namespace

void draw_inspector_panel(App& app) {
    if (!begin_panel(kWinInspector, &app.show_inspector)) return;
    Document* d = usable_doc(app);
    if (!d) {
        empty_note(app, "Open a file to inspect values at the cursor.");
        ImGui::End();
        return;
    }
    bool be = app.settings.big_endian_inspector;
    if (ImGui::RadioButton("Little endian", !be)) be = false;
    ImGui::SameLine();
    if (ImGui::RadioButton("Big endian", be)) be = true;
    if (be != app.settings.big_endian_inspector) {
        app.settings.big_endian_inspector = be;
        app.insp_edit.end();
        mark_settings_dirty(app);
    }
    ImGui::SameLine();
    const uint64_t at = focus_offset(d->view());  // selection start, else the caret byte
    ImGui::TextDisabled("@ %s", fmt_offset(at).c_str());

    uint8_t buf[16] = {};
    const size_t n = d->read(at, buf, sizeof buf);
    const std::vector<InspRow> rows = inspect(buf, n, be);
    if (app.insp_edit.row >= 0 && app.insp_edit.ctx != at) app.insp_edit.end();  // moved

    // Enter edits the selected row when the panel has focus (and no text field is active).
    if (app.insp_sel >= 0 && app.insp_sel < int(rows.size()) && app.insp_edit.row < 0 &&
        ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) && !ImGui::GetIO().WantTextInput &&
        !ImGui::GetIO().KeyCtrl &&  // Ctrl+Enter = Follow Pointer at Cursor
        (ImGui::IsKeyPressed(ImGuiKey_Enter) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter))) {
        const InspRow& r = rows[size_t(app.insp_sel)];
        if (r.editable && !d->read_only()) app.insp_edit.begin(app.insp_sel, at, r.value);
    }

    // Room for the separator (1 px + spacing) and the two selection-info lines, so the panel
    // itself never needs a scrollbar next to the table's.
    const float footer = ImGui::GetTextLineHeightWithSpacing() * 2.0f + ImGui::GetStyle().ItemSpacing.y * 2.0f + 2.0f;
    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable |
                                  ImGuiTableFlags_ScrollY;
    if (ImGui::BeginTable("##insp", 2, flags, ImVec2(0.0f, -footer))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 96.0f * app.ui_scale);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < rows.size(); ++i) draw_inspector_row(app, *active_tab(app), *d, rows[i], int(i), be);
        ImGui::EndTable();
    }
    ImGui::Separator();
    draw_selection_info(*d);
    ImGui::End();
}

// =============================================================================================
// Structure
// =============================================================================================

namespace {

// A parse slower than this (detect + parse, on the UI thread) is not re-run on every edit.
constexpr double kAutoParseBudgetMs = 50.0;

void run_parse(App& app, Tab& t) {
    StructureState& st = t.st;
    Document& d = *t.doc;
    const double t0 = now_s();
    const std::string requested = d.view().parser;
    const std::string name = requested.empty() ? app.engine->detect_parser(d) : requested;
    const size_t old_count = st.result.fields.size();
    if (name.empty()) {
        st.result = ParseResult{};
        st.has_result = false;
    } else {
        st.result = st.base ? app.engine->parse(d, name, st.base, UINT64_MAX) : app.engine->parse(d, name);
        st.has_result = true;
    }
    st.parsed_base = st.base;
    st.used_parser = name;
    st.last_parse_ms = (now_s() - t0) * 1000.0;
    st.slow = st.has_result && (st.last_parse_ms > kAutoParseBudgetMs || st.result.truncated);
    st.gen = d.generation();
    st.reload = app.engine->reload_count();
    st.requested = requested;
    st.due = 0.0;
    const auto& fields = st.result.fields;
    if (fields.size() != old_count || st.open.size() != fields.size()) {
        st.open.assign(fields.size(), 0);  // new shape: expand the roots only
        for (size_t i = 0; i < fields.size(); ++i)
            if (fields[i].parent < 0) st.open[i] = 1;
    }
    st.rows_dirty = true;
    st.cursor_field = -1;  // re-evaluated (and revealed) on the next draw
    st.scroll_to_field = -1;
    st.clicked_field = -1;
    if (app.st_edit.ctx == d.id()) app.st_edit.end();  // field indices may have changed
}

// Flattened list of visible rows (DFS honoring the expanded flags). Only rebuilt on change, so a
// 200k-field tree costs nothing per frame; drawing is virtualised with ImGuiListClipper.
void rebuild_rows(StructureState& st) {
    st.rows.clear();
    st.rows_dirty = false;
    const auto& fields = st.result.fields;
    std::vector<int> stack;
    for (size_t i = fields.size(); i-- > 0;)
        if (fields[i].parent < 0) stack.push_back(int(i));
    while (!stack.empty()) {
        int i = stack.back();
        stack.pop_back();
        st.rows.push_back(i);
        const Field& f = fields[size_t(i)];
        if (!st.open[size_t(i)]) continue;
        for (size_t c = f.children.size(); c-- > 0;) {
            int ch = f.children[c];
            if (ch >= 0 && ch < int(fields.size())) stack.push_back(ch);
        }
    }
}

int field_at(const StructureState& st, uint64_t off) {
    if (!st.has_result) return -1;
    const Highlight* h = st.result.highlights.at(off);
    if (!h || h->field < 0 || h->field >= int(st.result.fields.size())) return -1;
    return h->field;
}

void open_ancestors(StructureState& st, int fi) {
    const auto& fields = st.result.fields;
    for (int p = fields[size_t(fi)].parent; p >= 0 && p < int(fields.size()); p = fields[size_t(p)].parent) {
        if (!st.open[size_t(p)]) {
            st.open[size_t(p)] = 1;
            st.rows_dirty = true;
        }
    }
}

void draw_parser_combo(App& app, Tab& t, Document& d) {
    StructureState& st = t.st;
    std::string& forced = d.view().parser;
    std::string preview = forced.empty() ? "Auto (" + (st.used_parser.empty() ? std::string("none") : st.used_parser) + ")"
                                         : forced;
    std::string choose;
    bool chosen = false;
    ImGui::SetNextItemWidth(220.0f * app.ui_scale);
    if (ImGui::BeginCombo("##parser", preview.c_str())) {
        if (ImGui::Selectable("Auto-detect", forced.empty())) {
            chosen = true;
        }
        for (const ParserInfo& p : app.engine->parsers()) {
            if (ImGui::Selectable(p.name.c_str(), forced == p.name)) {
                choose = p.name;
                chosen = true;
            }
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal)) ImGui::SetTooltip("%s", p.file.c_str());
        }
        ImGui::EndCombo();
    }
    if (chosen && choose != forced) {
        forced = choose;
        d.view_generation++;
    }
    ImGui::SameLine();
    if (ImGui::Button("Reparse")) {
        st.gen = UINT64_MAX;
        st.pending_gen = UINT64_MAX - 1;
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Run the parser again (F5)");
}

// "Parse at [offset] [Cursor] [File start]": where the parser starts (e.g. a PNG inside a dump).
void draw_parse_base(App& app, Tab& t, Document& d) {
    StructureState& st = t.st;
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Parse at");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(150.0f * app.ui_scale);
    const bool enter = ImGui::InputTextWithHint("##base", "0 (file start)", &st.base_input,
                                                ImGuiInputTextFlags_EnterReturnsTrue);
    if (ImGui::IsItemDeactivated() && !enter) st.base_input = st.base ? fmt_offset(st.base) : std::string();
    ImGui::SetItemTooltip("Offset to parse from, like Go to: 0x1F00, #1234, cur, end-0x100 (Enter applies)");
    if (enter) {
        uint64_t v = 0;
        std::string err;
        if (st.base_input.empty())
            set_parse_base(app, t, 0);
        else if (parse_offset(st.base_input, d.view().cursor, d.size(), app.settings.goto_default_hex, v, &err))
            set_parse_base(app, t, v);
        else
            set_status(app, "Parse at: " + (err.empty() ? std::string("invalid offset") : err));
    }
    ImGui::SameLine();
    if (ImGui::Button("Cursor")) set_parse_base(app, t, focus_offset(d.view()));
    ImGui::SetItemTooltip("Parse from the cursor / selection start");
    ImGui::SameLine();
    ImGui::BeginDisabled(st.base == 0);
    if (ImGui::Button("File start")) set_parse_base(app, t, 0);
    ImGui::EndDisabled();
}

void draw_parse_info(App& app, StructureState& st, const Document& d) {
    if (!st.has_result) {
        if (st.gen == UINT64_MAX)
            ImGui::TextDisabled("Parsing...");
        else
            ImGui::TextDisabled("No parser matched this document.");
        ImGui::TextDisabled("Pick one above, or add a script (Scripts > Open Scripts Folder).");
        return;
    }
    const ParseResult& r = st.result;
    if (st.parsed_base)
        ImGui::TextDisabled("%s @ %s  \xC2\xB7  %zu fields  \xC2\xB7  %.1f ms", r.parser.c_str(),
                            fmt_offset(st.parsed_base).c_str(), r.fields.size(), r.ms);
    else
        ImGui::TextDisabled("%zu fields  \xC2\xB7  %.1f ms", r.fields.size(), r.ms);
    if (st.slow && st.gen != d.generation()) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(stale: press F5 to re-parse)");
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("This parser took %.0f ms, so it is not re-run automatically after edits.", st.last_parse_ms);
    }
    if (r.truncated) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(truncated: field limit reached)");
    }
    if (!r.error.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, kErrColor);
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextUnformatted(r.error.c_str());
        ImGui::PopTextWrapPos();
        ImGui::PopStyleColor();
    }
    (void)app;
}

bool commit_field_edit(App& app, Document& d, const Field& f) {
    std::string err;
    if (!app.engine->edit_field(d, f, app.st_edit.buf, &err)) {
        if (d.read_only() || d.busy()) {
            app.st_edit.end();
            report_edit_failure(app, d);
            return false;
        }
        retry_edit(app, app.st_edit, err);
        return false;
    }
    app.st_edit.end();
    d.view_generation++;
    set_status(app, "Set " + f.name + " = " + app.st_edit.buf);
    return true;
}

// Width (1, 2, 4, 8) and byte order of an integer field from its pack format ("<I4", ">H", "B"...);
// 0 for anything else (floats, strings, structs, 3-byte ints).
int int_field_width(const Field& f, bool& be) {
    const std::string& p = f.pack;
    size_t i = 0;
    be = false;
    if (i < p.size() && (p[i] == '<' || p[i] == '>' || p[i] == '=')) be = p[i++] == '>';
    if (i >= p.size()) return 0;
    int w = 0;
    switch (p[i++]) {
        case 'b': case 'B': w = 1; break;
        case 'h': case 'H': w = 2; break;
        case 'j': case 'J': w = 8; break;
        case 'i': case 'I':
            w = 0;
            while (i < p.size() && p[i] >= '0' && p[i] <= '9' && w < 100) w = w * 10 + (p[i++] - '0');
            if (w == 0) w = 4;
            break;
        default: return 0;
    }
    if (i != p.size() || uint64_t(w) != f.size || (w != 1 && w != 2 && w != 4 && w != 8)) return 0;
    return w;
}

// Returns whether the row is visible (taken from the name cell: the last cell may be in a hidden column).
bool draw_field_row(App& app, Tab& t, Document& d, int row, int hover_field) {
    StructureState& st = t.st;
    const int fi = st.rows[size_t(row)];
    const Field& f = st.result.fields[size_t(fi)];
    const bool leaf = f.children.empty();
    // A stale result (content changed, not re-parsed yet) has stale offsets: no field edits.
    const bool can_edit = f.editable() && !d.read_only() && st.gen == d.generation();
    bool ptr_be = false;
    const int ptr_w = int_field_width(f, ptr_be);
    ImGui::TableNextRow();
    if (fi == hover_field && fi != st.cursor_field)
        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, ImGui::GetColorU32(ImGuiCol_HeaderHovered, 0.45f));
    ImGui::PushID(fi);

    // Name (tree node; children are rows of their own, so no TreePush)
    ImGui::TableSetColumnIndex(0);
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + float(f.depth) * ImGui::GetStyle().IndentSpacing);
    ImGuiTreeNodeFlags fl = ImGuiTreeNodeFlags_SpanAllColumns | ImGuiTreeNodeFlags_AllowOverlap |
                            ImGuiTreeNodeFlags_NoTreePushOnOpen | ImGuiTreeNodeFlags_OpenOnArrow;
    if (leaf) fl |= ImGuiTreeNodeFlags_Leaf;
    if (fi == st.cursor_field) fl |= ImGuiTreeNodeFlags_Selected;
    if (!leaf) ImGui::SetNextItemOpen(st.open[size_t(fi)] != 0, ImGuiCond_Always);
    const bool is_open = ImGui::TreeNodeEx("##node", fl, "%s", f.name.c_str());
    const bool row_visible = ImGui::IsItemVisible();
    const bool toggled = ImGui::IsItemToggledOpen();
    if (!leaf && is_open != (st.open[size_t(fi)] != 0)) {
        st.open[size_t(fi)] = is_open ? 1 : 0;
        st.rows_dirty = true;  // applied next frame (never mutate rows while clipping them)
    }
    const bool hovered = ImGui::IsItemHovered();
    if (ImGui::IsItemClicked(ImGuiMouseButton_Left) && !toggled) {
        reveal_range(app, t, f.offset, f.size, false);
        st.cursor_field = fi;  // already visible: no auto-scroll
        st.clicked_field = leaf ? -1 : fi;
        st.clicked_cursor = d.view().cursor;
    }
    if (hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && can_edit)
        app.st_edit.begin(fi, d.id(), f.value);
    if (hovered && ImGui::BeginItemTooltip()) {  // full name + type (the Type column starts hidden)
        ImGui::Text("%s  :  %s", f.name.c_str(), f.type.c_str());
        if (!f.comment.empty()) ImGui::TextDisabled("%s", f.comment.c_str());
        ImGui::EndTooltip();
    }
    if (ImGui::BeginPopupContextItem("##ctx")) {
        if (ImGui::MenuItem("Select bytes")) reveal_range(app, t, f.offset, f.size, true);
        if (ImGui::MenuItem("Edit value", nullptr, false, can_edit))
            app.st_edit.begin(fi, d.id(), f.value);
        ImGui::Separator();
        if (ImGui::MenuItem("Copy value")) ImGui::SetClipboardText(f.value.c_str());
        if (ImGui::MenuItem("Copy name")) ImGui::SetClipboardText(f.name.c_str());
        if (ImGui::MenuItem("Copy offset")) ImGui::SetClipboardText(fmt_offset(f.offset).c_str());
        if (ptr_w) {
            ImGui::Separator();
            if (ImGui::MenuItem("Follow as pointer", nullptr, false, st.gen == d.generation()))
                follow_pointer(app, t, f.offset, ptr_w, ptr_be);
        }
        close_popup_on_escape();
        ImGui::EndPopup();
    }

    // Value (+ color swatch) or the in-place editor
    ImGui::TableSetColumnIndex(1);
    if (app.st_edit.active(fi, d.id())) {
        int res = inline_edit_input(app.st_edit, false);
        if (res > 0 && commit_field_edit(app, d, f)) {
            st.gen = UINT64_MAX;  // one explicit edit: re-parse even if auto-parse is off (slow parser)
            st.pending_gen = UINT64_MAX - 1;
        }
        if (res < 0) app.st_edit.end();
    } else {
        draw_swatch(f.color);
        ImGui::TextUnformatted(f.value.c_str());
        // 32/64-bit integers that point inside the file get a follow button (any width: context menu).
        if ((ptr_w == 4 || ptr_w == 8) && st.gen == d.generation()) {
            bool ok = false;
            const std::string tip = follow_tip(app, d, f.offset, ptr_w, ptr_be, ok);
            if (ok && follow_button(true, tip)) follow_pointer(app, t, f.offset, ptr_w, ptr_be);
        }
    }
    ImGui::PushFont(app.fonts.mono, 0.0f);
    ImGui::TableSetColumnIndex(2);
    ImGui::TextUnformatted(fmt_offset(f.offset).c_str());
    ImGui::TableSetColumnIndex(3);
    ImGui::Text("%llu", ull(f.size));
    ImGui::PopFont();
    ImGui::TableSetColumnIndex(4);
    ImGui::TextDisabled("%s", f.type.c_str());
    ImGui::PopID();
    return row_visible;
}

void draw_field_table(App& app, Tab& t, Document& d) {
    StructureState& st = t.st;
    const int hover_field = t.ev.has_hover ? field_at(st, t.ev.hover_offset) : -1;
    const uint64_t at = focus_offset(d.view());  // same byte as the Inspector
    int cur_field = at < d.size() ? field_at(st, at) : -1;
    // Highlights exist for leaves only: after clicking a container row, the caret byte maps to
    // its first leaf. Keep the container selected (and collapsed) until the caret moves.
    if (st.clicked_field >= 0) {
        bool inside = false;
        if (st.clicked_field < int(st.result.fields.size()) && d.view().cursor == st.clicked_cursor)
            for (int p = cur_field; p >= 0 && p < int(st.result.fields.size()); p = st.result.fields[size_t(p)].parent)
                if (p == st.clicked_field) {
                    inside = true;
                    break;
                }
        if (inside)
            cur_field = st.clicked_field;
        else
            st.clicked_field = -1;
    }
    if (cur_field != st.cursor_field) {
        st.cursor_field = cur_field;
        if (cur_field >= 0) {
            open_ancestors(st, cur_field);
            st.scroll_to_field = cur_field;
        }
    }
    if (app.st_edit.ctx == d.id() && app.st_edit.row >= 0 && st.gen != d.generation()) app.st_edit.end();
    if (st.rows_dirty) rebuild_rows(st);

    int scroll_row = -1;
    if (st.scroll_to_field >= 0) {
        auto it = std::find(st.rows.begin(), st.rows.end(), st.scroll_to_field);
        if (it != st.rows.end()) scroll_row = int(it - st.rows.begin());
        st.scroll_to_field = -1;
    }
    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable |
                                  ImGuiTableFlags_ScrollY | ImGuiTableFlags_Hideable;
    if (!ImGui::BeginTable("##fields", 5, flags)) return;
    const float s = app.ui_scale;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 0.5f);
    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 0.5f);
    ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 96.0f * s);
    ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 56.0f * s);
    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultHide, 64.0f * s);
    ImGui::TableHeadersRow();
    ImGuiListClipper clip;
    clip.Begin(int(st.rows.size()));
    if (scroll_row >= 0) clip.IncludeItemByIndex(scroll_row);
    while (clip.Step()) {
        for (int r = clip.DisplayStart; r < clip.DisplayEnd; ++r) {
            const bool row_visible = draw_field_row(app, t, d, r, hover_field);
            if (r == scroll_row && !row_visible) ImGui::SetScrollHereY(0.5f);
        }
    }
    ImGui::EndTable();
}

}  // namespace

void update_structure(App& app, Tab& t) {
    StructureState& st = t.st;
    Document& d = *t.doc;
    const uint64_t gen = d.generation();
    const uint64_t rel = app.engine->reload_count();
    const std::string& want = d.view().parser;
    if (gen == st.gen && rel == st.reload && want == st.requested && st.base == st.parsed_base) {
        st.due = 0.0;
        return;
    }
    // Only the content changed and the last parse was slow: don't freeze the UI after every
    // keystroke. The panel shows the result as stale; F5 / Reparse (st.gen = UINT64_MAX) runs it.
    if (st.slow && st.gen != UINT64_MAX && rel == st.reload && want == st.requested) {
        st.due = 0.0;
        return;
    }
    const double now = now_s();
    if (gen != st.pending_gen || rel != st.pending_reload || want != st.pending_parser) {
        st.pending_gen = gen;
        st.pending_reload = rel;
        st.pending_parser = want;
        const bool first = st.gen == UINT64_MAX && !st.has_result && st.reload == UINT64_MAX;
        st.due = now + (first ? 0.0 : 0.12);  // debounce while typing
    }
    app.wants_poll = true;
    if (now >= st.due) run_parse(app, t);
}

void set_parse_base(App& app, Tab& t, uint64_t base) {
    StructureState& st = t.st;
    Document& d = *t.doc;
    if (d.busy()) return;
    base = std::min(base, d.size());
    st.base = base;
    st.base_input = base ? fmt_offset(base) : std::string();
    // detect() looks at the file start: keep the parser that is shown now.
    if (base && d.view().parser.empty() && !st.used_parser.empty()) {
        d.view().parser = st.used_parser;
        d.view_generation++;
    }
    st.gen = UINT64_MAX;  // re-parse now
    st.pending_gen = UINT64_MAX - 1;
    if (base && d.view().parser.empty())
        set_status(app, "Parse at " + fmt_offset(base) + ": pick a parser in the Structure panel");
    else
        set_status(app, base ? "Parsing from " + fmt_offset(base) : std::string("Parsing from the file start"), 3.0);
}

void draw_structure_panel(App& app) {
    if (!begin_panel(kWinStructure, &app.show_structure)) return;
    Tab* t = active_tab(app);
    Document* d = usable_doc(app);
    if (!d) {
        empty_note(app, "Open a file to see its parsed structure.");
        ImGui::End();
        return;
    }
    draw_parser_combo(app, *t, *d);
    draw_parse_base(app, *t, *d);
    draw_parse_info(app, t->st, *d);
    if (t->st.has_result && !t->st.result.fields.empty()) draw_field_table(app, *t, *d);
    ImGui::End();
}

// =============================================================================================
// Console
// =============================================================================================

namespace {

ImVec4 console_color(ConsoleLine::Kind k) {
    switch (k) {
        case ConsoleLine::Warn: return kWarnColor;
        case ConsoleLine::Error: return kErrColor;
        case ConsoleLine::Input: return kInputColor;
        case ConsoleLine::Result: return kResultColor;
        default: return ImGui::GetStyleColorVec4(ImGuiCol_Text);
    }
}

void draw_console_line(const ConsoleLine& l) {
    ImGui::PushStyleColor(ImGuiCol_Text, console_color(l.kind));
    if (l.kind == ConsoleLine::Input) {
        std::string s = "> " + l.text;
        ImGui::TextUnformatted(s.c_str(), s.c_str() + s.size());
    } else {
        ImGui::TextUnformatted(l.text.c_str(), l.text.c_str() + l.text.size());
    }
    ImGui::PopStyleColor();
}

std::string console_text(const std::deque<ConsoleLine>& lines) {
    std::string all;
    for (const ConsoleLine& l : lines) {
        if (l.kind == ConsoleLine::Input) all += "> ";
        all += l.text;
        all += '\n';
    }
    return all;
}

int console_history_cb(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag != ImGuiInputTextFlags_CallbackHistory) return 0;
    App& app = *static_cast<App*>(data->UserData);
    const auto& h = app.console_history;
    if (h.empty()) return 0;
    int& pos = app.console_history_pos;
    if (data->EventKey == ImGuiKey_UpArrow) {
        if (pos < 0) app.console_draft.assign(data->Buf, size_t(data->BufTextLen));  // keep the typed line
        pos = pos < 0 ? int(h.size()) - 1 : std::max(0, pos - 1);
    } else if (data->EventKey == ImGuiKey_DownArrow) {
        if (pos < 0) return 0;
        if (++pos >= int(h.size())) pos = -1;
    }
    data->DeleteChars(0, data->BufTextLen);
    data->InsertChars(0, pos >= 0 ? h[size_t(pos)].c_str() : app.console_draft.c_str());
    return 0;
}

void run_console_input(App& app) {
    std::string code = app.console_input;
    app.console_input.clear();
    app.console_history_pos = -1;
    if (code.find_first_not_of(" \t") == std::string::npos) return;
    if (app.save.running) {
        set_status(app, "Wait for the save to finish before running scripts");
        app.console_input = code;
        return;
    }
    auto& h = app.console_history;
    if (h.empty() || h.back() != code) h.push_back(code);
    if (h.size() > 100) h.erase(h.begin());
    app.console_force_scroll = true;
    app.engine->exec(code);
}

void draw_console_output(App& app) {
    const auto& lines = app.engine->console();
    if (ImGui::BeginPopupContextWindow("##conctx")) {
        if (ImGui::MenuItem("Copy all")) ImGui::SetClipboardText(console_text(lines).c_str());
        if (ImGui::MenuItem("Clear", "Ctrl+L")) app.engine->clear_console();
        ImGui::MenuItem("Word wrap", nullptr, &app.console_wrap);
        close_popup_on_escape();
        ImGui::EndPopup();
    }
    const bool at_bottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 2.0f;
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(ImGui::GetStyle().ItemSpacing.x, 2.0f));
    if (app.console_wrap) {
        // Variable-height wrapped lines: no clipper. The console is capped at 5000 lines and
        // ImGui only measures (does not render) off-screen text.
        ImGui::PushTextWrapPos(0.0f);
        for (const ConsoleLine& l : lines) draw_console_line(l);
        ImGui::PopTextWrapPos();
    } else {
        ImGuiListClipper clip;
        clip.Begin(int(lines.size()));
        while (clip.Step())
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) draw_console_line(lines[size_t(i)]);
    }
    ImGui::PopStyleVar();
    const uint64_t gen = app.engine->console_generation();
    if (app.console_force_scroll || (gen != app.console_seen_gen && at_bottom)) ImGui::SetScrollHereY(1.0f);
    app.console_force_scroll = false;
    app.console_seen_gen = gen;
}

}  // namespace

void draw_console_panel(App& app) {
    if (!begin_panel(kWinConsole, &app.show_console)) return;
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_L, ImGuiInputFlags_RouteFocused)) app.engine->clear_console();
    const float input_h = ImGui::GetFrameHeightWithSpacing();
    const ImGuiWindowFlags out_flags = app.console_wrap ? 0 : ImGuiWindowFlags_HorizontalScrollbar;
    if (ImGui::BeginChild("##out", ImVec2(0.0f, -input_h), ImGuiChildFlags_None, out_flags)) draw_console_output(app);
    ImGui::EndChild();

    if (app.focus_console_input) {
        ImGui::SetKeyboardFocusHere();
        app.focus_console_input = false;
    }
    ImGui::SetNextItemWidth(-FLT_MIN);
    const bool enter = ImGui::InputTextWithHint("##in", "Lua  (Enter runs, Up/Down history; doc, cur, sel are predefined)",
                                                &app.console_input,
                                                ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackHistory,
                                                console_history_cb, &app);
    if (enter) {
        run_console_input(app);
        ImGui::SetKeyboardFocusHere(-1);
    }
    ImGui::End();
}

// =============================================================================================
// Search results
// =============================================================================================

void draw_search_results_panel(App& app) {
    if (!begin_panel(kWinResults, &app.show_results)) return;
    Tab* t = active_tab(app);
    Document* d = usable_doc(app);
    if (!d) {
        empty_note(app, "No document.");
        ImGui::End();
        return;
    }
    SearchHits& h = t->hits;
    if (h.offsets.empty()) {
        if (h.query.empty())
            ImGui::TextDisabled("No results yet. Ctrl+F, then \"All\" lists every match here.");
        else
            ImGui::TextDisabled("No hits for '%s'.", h.query.c_str());
        ImGui::End();
        return;
    }
    ImGui::Text("%zu%s hits for '%s'", h.offsets.size(), h.truncated ? "+" : "", h.query.c_str());
    if (h.doc_gen != d->generation()) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(document changed since the search)");
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Clear")) {
        h = SearchHits{};
        ImGui::End();
        return;
    }
    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##hits", 3, flags)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 56.0f * app.ui_scale);
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 150.0f * app.ui_scale);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        const uint64_t cur = focus_offset(d->view());
        ImGuiListClipper clip;
        clip.Begin(int(std::min<size_t>(h.offsets.size(), size_t(INT_MAX))));
        uint8_t buf[16];
        while (clip.Step()) {
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                const uint64_t off = h.offsets[size_t(i)];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(i);
                char idx[24];
                std::snprintf(idx, sizeof idx, "%d", i + 1);
                if (ImGui::Selectable(idx, off == cur, ImGuiSelectableFlags_SpanAllColumns))
                    reveal_range(app, *t, off, h.len, false);
                ImGui::PopID();
                ImGui::PushFont(app.fonts.mono, 0.0f);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(fmt_offset(off).c_str());
                ImGui::TableSetColumnIndex(2);
                const size_t n = d->read(off, buf, std::min<size_t>(sizeof buf, std::max<size_t>(h.len, 8)));
                ImGui::TextUnformatted(hex_preview(buf, n).c_str());
                ImGui::PopFont();
            }
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

// =============================================================================================
// Bookmarks
// =============================================================================================

namespace {

// One change requested while drawing the table, applied after it (the lists must not change
// while they are being iterated).
struct BookmarkChange {
    enum Kind { None, Name, Note, Remove } kind = None;
    uint64_t doc = 0;
    size_t index = 0;
    std::string text;
};

// The Name / Note cell: text (double-click edits) or the in-place editor. `field` 0 = name, 1 = note.
void bookmark_text_cell(App& app, Tab& t, const Bookmark& b, size_t i, int field, bool selected,
                        BookmarkChange& change) {
    Document& d = *t.doc;
    const int row = int(i) * 2 + field;
    if (app.bm_edit.active(row, d.id())) {
        const int res = inline_edit_input(app.bm_edit, true);
        if (res > 0) change = {field == 0 ? BookmarkChange::Name : BookmarkChange::Note, d.id(), i, app.bm_edit.buf};
        if (res != 0) app.bm_edit.end();
        return;
    }
    const std::string& text = field == 0 ? b.name : b.note;
    if (field == 0) {
        draw_swatch(b.color ? b.color : hex_colors().bookmark);
        ImGuiSelectableFlags fl = ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap |
                                  ImGuiSelectableFlags_AllowDoubleClick;
        if (ImGui::Selectable(text.empty() ? "(unnamed)" : text.c_str(), selected, fl)) {
            if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                app.bm_edit.begin(row, d.id(), b.name);
            else
                reveal_range(app, t, b.offset, b.length, false);
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal))
            ImGui::SetTooltip("%s\n%s", fmt_range(b.offset, b.length).c_str(),
                              "Click: select it  \xC2\xB7  double-click the name or note to edit");
        return;
    }
    // Note: plain text; a double-click anywhere in the cell edits it.
    ImGui::PushID("note");
    const float w = std::max(1.0f, ImGui::GetContentRegionAvail().x);
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("##hit", ImVec2(w, ImGui::GetTextLineHeight()), ImGuiButtonFlags_AllowOverlap);
    const bool dbl = ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
    if (ImGui::IsItemClicked() && !dbl) reveal_range(app, t, b.offset, b.length, false);
    ImGui::SetCursorScreenPos(p);
    if (text.empty())
        ImGui::TextDisabled("%s", dbl ? "" : "-");
    else
        ImGui::TextUnformatted(text.c_str());
    ImGui::PopID();
    if (dbl) app.bm_edit.begin(row, d.id(), b.note);
}

void draw_bookmark_rows(App& app, Tab& t, BookmarkChange& change) {
    Document& d = *t.doc;
    const std::vector<Bookmark>& bms = d.view().bookmarks;
    const uint64_t at = focus_offset(d.view());
    ImGuiListClipper clip;
    clip.Begin(int(bms.size()));
    uint8_t buf[8];
    while (clip.Step()) {
        for (int k = clip.DisplayStart; k < clip.DisplayEnd; ++k) {
            const size_t i = size_t(k);
            const Bookmark& b = bms[i];
            ImGui::TableNextRow();
            ImGui::PushID(k);
            const bool selected = &t == active_tab(app) && at >= b.offset && at - b.offset < std::max<uint64_t>(b.length, 1);
            ImGui::TableSetColumnIndex(0);
            bookmark_text_cell(app, t, b, i, 0, selected, change);
            ImGui::TableSetColumnIndex(1);
            bookmark_text_cell(app, t, b, i, 1, selected, change);
            ImGui::PushFont(app.fonts.mono, 0.0f);
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(fmt_offset(b.offset).c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%llu", ull(b.length));
            ImGui::TableSetColumnIndex(4);
            const size_t n = d.read(b.offset, buf, size_t(std::min<uint64_t>(b.length, sizeof buf)));
            std::string pv = hex_preview(buf, n);
            if (b.length > sizeof buf) pv += " \xE2\x80\xA6";
            ImGui::TextDisabled("%s", pv.c_str());
            ImGui::PopFont();
            ImGui::TableSetColumnIndex(5);
            if (ImGui::SmallButton("x")) change = {BookmarkChange::Remove, d.id(), i, {}};
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Delete bookmark (undoable)");
            ImGui::PopID();
        }
    }
}

void apply_bookmark_change(App& app, const BookmarkChange& c) {
    if (c.kind == BookmarkChange::None) return;
    Tab* t = find_tab(app, c.doc);
    if (!t || t->doc->busy()) return;
    Document& d = *t->doc;
    const auto& bms = d.view().bookmarks;
    if (c.index >= bms.size()) return;
    bool ok = true;
    if (c.kind == BookmarkChange::Remove) {
        ok = d.remove_bookmark(c.index);
    } else {
        Bookmark b = bms[c.index];
        std::string& field = c.kind == BookmarkChange::Name ? b.name : b.note;
        if (field == c.text) return;
        field = c.text;
        ok = d.update_bookmark(c.index, b);
    }
    if (!ok) report_edit_failure(app, d);
}

}  // namespace

void add_bookmark_here(App& app, Document& d) {
    const ViewState& v = d.view();
    if (d.size() == 0) {
        set_status(app, "Nothing to bookmark in an empty document");
        return;
    }
    Bookmark b;
    b.offset = std::min(v.has_selection() ? v.sel_begin() : v.cursor, d.size() - 1);
    b.length = v.has_selection() ? v.sel_len() : 1;
    b.name = "Bookmark " + std::to_string(v.bookmarks.size() + 1);
    if (d.add_bookmark(b))
        set_status(app, "Added " + b.name + " at " + fmt_range(b.offset, b.length));
    else
        report_edit_failure(app, d);
}

void draw_bookmarks_panel(App& app) {
    if (app.focus_bookmarks) {
        ImGui::SetNextWindowFocus();
        app.focus_bookmarks = false;
    }
    if (!begin_panel(kWinBookmarks, &app.show_bookmarks)) return;
    Tab* t = active_tab(app);
    Document* d = usable_doc(app);
    ImGui::BeginDisabled(!d);
    if (ImGui::SmallButton("Add") && d) add_bookmark_here(app, *d);
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("Bookmark the selection, or the byte at the caret (Ctrl+B)");
    ImGui::SameLine();
    ImGui::Checkbox("All open files", &app.bm_all_files);
    ImGui::SameLine();
    ImGui::TextDisabled("Ctrl+B toggle  \xC2\xB7  F2 / Shift+F2 next / previous  \xC2\xB7  Ctrl+Shift+B find  \xC2\xB7  "
                        "double-click name or note to edit");

    // The tabs to list: the active one, or every open (not saving) one.
    std::vector<Tab*> tabs;
    size_t total = 0;
    if (app.bm_all_files) {
        for (auto& tp : app.tabs)
            if (!tp->doc->busy() && !tp->doc->view().bookmarks.empty()) {
                tabs.push_back(tp.get());
                total += tp->doc->view().bookmarks.size();
            }
    } else if (d) {
        tabs.push_back(t);
        total = d->view().bookmarks.size();
    }
    if (total == 0) {
        ImGui::Spacing();
        if (!d && !app.bm_all_files)
            empty_note(app, "No document.");
        else
            ImGui::TextDisabled(app.bm_all_files ? "No bookmarks in the open files." : "No bookmarks in this file.");
        ImGui::TextDisabled("Ctrl+B adds a bookmark at the cursor/selection.");
        ImGui::End();
        return;
    }
    BookmarkChange change;
    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##bms", 6, flags)) {
        const float s = app.ui_scale;
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 0.35f);
        ImGui::TableSetupColumn("Note", ImGuiTableColumnFlags_WidthStretch, 0.65f);
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 96.0f * s);
        ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 64.0f * s);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 200.0f * s);
        ImGui::TableSetupColumn("##del", ImGuiTableColumnFlags_WidthFixed, 24.0f * s);
        ImGui::TableHeadersRow();
        for (Tab* tab : tabs) {
            ImGui::PushID(int(tab->doc->id()));
            if (app.bm_all_files) {  // file header row
                ImGui::TableNextRow(ImGuiTableRowFlags_None);
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImGuiCol_TableHeaderBg));
                ImGui::TableSetColumnIndex(0);
                const bool is_active = tab == t;
                ImGui::TextColored(is_active ? ImGui::GetStyleColorVec4(ImGuiCol_Text)
                                             : ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled),
                                   "%s", tab->label.c_str());
                if (ImGui::IsItemHovered() && !tab->path.empty()) ImGui::SetTooltip("%s", tab->path.c_str());
                ImGui::TableSetColumnIndex(1);
                const size_t n = tab->doc->view().bookmarks.size();
                ImGui::TextDisabled("%zu bookmark%s", n, n == 1 ? "" : "s");
            }
            draw_bookmark_rows(app, *tab, change);
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    apply_bookmark_change(app, change);
    ImGui::End();
}

// =============================================================================================
// Strings / Hashes (self-contained panels, ui/panel_strings.h / ui/panel_hash.h)
// =============================================================================================

namespace {

// A panel added after the user's layout.ini was written docks into `like`'s node on first use.
void dock_like(const char* like) {
    if (ImGuiWindow* w = ImGui::FindWindowByName(like); w && w->DockId)
        ImGui::SetNextWindowDockID(w->DockId, ImGuiCond_FirstUseEver);
}

}  // namespace

void draw_strings_panel(App& app) {
    dock_like(kWinConsole);
    if (!begin_panel(kWinStrings, &app.show_strings)) return;
    Tab* t = active_tab(app);
    StringsPanel& sp = app.strings_panel;
    sp.mono = app.fonts.mono;
    sp.ui_scale = app.ui_scale;
    StringsPanelCallbacks cb;
    const uint64_t doc_id = t ? t->doc->id() : 0;
    cb.jump = [&app, doc_id](uint64_t off, uint64_t len) {
        if (Tab* tab = find_tab(app, doc_id)) reveal_range(app, *tab, off, len, false);
    };
    cb.copy = [&app](const std::string& s) {
        ImGui::SetClipboardText(s.c_str());
        set_status(app, "Copied " + std::to_string(s.size()) + " characters");
    };
    cb.notify = [&app](const std::string& m) { set_status(app, m); };
    sp.draw(t ? t->doc.get() : nullptr, cb);  // a busy document is shown but not rescanned
    if (sp.wants_frames()) app.wants_poll = true;
    ImGui::End();
}

void draw_hash_panel(App& app) {
    dock_like(kWinInspector);
    HashPanelCallbacks cb;
    cb.status = [&app](const std::string& m) { set_status(app, m); };
    HashPanel& hp = app.hash_panel;
    hp.draw(kWinHashes, &app.show_hashes, usable_doc(app), app.fonts.mono, app.ui_scale, cb);
    if (hp.wants_frames()) app.wants_poll = true;
    // Remember the algorithm choice ("-" = none, "" = the defaults, so an untouched choice is not
    // written to settings.ini and follows future defaults).
    std::string names, defaults;
    for (const std::string& n : hp.selected()) names += (names.empty() ? "" : ",") + n;
    for (const HashAlgorithm& a : hash_algorithms())
        if (a.is_default) defaults += (defaults.empty() ? "" : ",") + std::string(a.name);
    if (names == defaults) names.clear();
    else if (names.empty()) names = "-";
    if (names != app.settings.hash_algorithms) {
        app.settings.hash_algorithms = names;
        mark_settings_dirty(app);
    }
}

// =============================================================================================
// Status bar
// =============================================================================================

namespace {

void status_sep() {
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
}

void draw_doc_status(App& app, Tab& t) {
    Document& d = *t.doc;
    const ViewState& v = d.view();
    // Offset and Byte describe the same byte as the Inspector: the selection start, else the caret.
    const uint64_t at = focus_offset(v);
    ImGui::Text("Offset %s (%llu)", fmt_offset(at).c_str(), ull(at));
    if (ImGui::IsItemClicked()) app.req_goto = true;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Go to offset (Ctrl+G)");
    status_sep();
    if (v.has_selection())
        ImGui::Text("Sel %s", fmt_range(v.sel_begin(), v.sel_len()).c_str());
    else
        ImGui::TextDisabled("No selection");
    status_sep();
    uint8_t b = 0, bad = 0;
    const bool have = at < d.size() && d.read(at, &b, 1, &bad) == 1;
    if (have && bad) {
        ImGui::TextColored(kErrColor, "Byte ??");
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("This byte could not be read from disk");
    } else if (have) {
        const char c = (b >= 0x20 && b < 0x7F) ? char(b) : '.';
        ImGui::Text("Byte 0x%02X  %u  '%c'", unsigned(b), unsigned(b), c);
    } else {
        ImGui::TextDisabled("EOF");
    }
    status_sep();
    ImGui::Text("Size %s", fmt_size(d.size()).c_str());
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%llu bytes", ull(d.size()));
    status_sep();
    ImGui::TextUnformatted(t.insert_mode ? "INS" : "OVR");
    if (ImGui::IsItemClicked()) {
        t.insert_mode = !t.insert_mode;
        app.settings.insert_mode = t.insert_mode;
        mark_settings_dirty(app);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Insert / overwrite (Insert key)");
    if (d.read_only()) {
        status_sep();
        ImGui::TextColored(kWarnColor, "RO");
    }
    if (d.io_error()) {
        status_sep();
        ImGui::TextColored(kErrColor, "I/O error");
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Part of the file could not be read (bad sector, removed drive, or truncated by\n"
                              "another program). Unreadable bytes are shown as ??. Searches stop at them and\n"
                              "saves that rewrite the file refuse; copies and scripts read them as 0.");
    }
    if (!t.st.used_parser.empty()) {
        status_sep();
        if (t.st.parsed_base)
            ImGui::Text("Parser: %s @ %s", t.st.used_parser.c_str(), fmt_offset(t.st.parsed_base).c_str());
        else
            ImGui::Text("Parser: %s", t.st.used_parser.c_str());
    }
}

}  // namespace

void draw_status_bar(App& app) {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings |
                                   ImGuiWindowFlags_MenuBar;
    if (ImGui::BeginViewportSideBar("##statusbar", vp, ImGuiDir_Down, ImGui::GetFrameHeight(), flags)) {
        if (ImGui::BeginMenuBar()) {
            Tab* t = active_tab(app);
            if (!t)
                ImGui::TextDisabled("No document");
            else if (t->doc->busy())
                ImGui::Text("Saving %s  %.0f%%", t->label.c_str(), app.save.progress.fraction() * 100.0);
            else
                draw_doc_status(app, *t);
            if (app.find.job.running()) {
                status_sep();
                ImGui::Text("Searching %.0f%%", app.find.job.progress() * 100.0);
            }
            if (app.save.running && !(t && t->doc->busy())) {
                status_sep();
                ImGui::Text("Saving %.0f%%", app.save.progress.fraction() * 100.0);
            }
            if (!app.status.empty() && now_s() < app.status_until) {
                status_sep();
                ImGui::TextUnformatted(app.status.c_str());
            }
            ImGui::EndMenuBar();
        }
    }
    ImGui::End();
}

}  // namespace hx
