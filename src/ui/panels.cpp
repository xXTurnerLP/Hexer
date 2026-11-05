// Dockable panels: Inspector, Structure, Console, Search Results, Bookmarks, Strings, Hashes,
// Bitmap, Packets, History, XOR Search, Regions + the status bar.
// Each panel reads the active tab through App helpers and never touches a busy (saving) document.
#include "ui/panels.h"

#include <algorithm>
#include <cctype>
#include <cfloat>
#include <climits>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"
#include "misc/cpp/imgui_stdlib.h"

#include "core/hash.h"
#include "core/highlight.h"
#include "core/inspector.h"
#include "core/nav.h"
#include "core/os_file.h"
#include "core/util.h"
#include "script/cexport.h"
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

// Tooltip / target of following the pointer of type `pt` at `at`.
std::string follow_tip(const Document& d, uint64_t at, const PointerType& pt, bool& ok) {
    uint64_t target = 0;
    ok = decode_pointer(d, at, pt, target);
    return ok ? "Follow " + pointer_type_name(pt) + " \xE2\x86\x92 " + fmt_offset(target) + "  (Alt+Left goes back)"
              : "Cannot follow " + pointer_type_name(pt) + ": negative, below the base or beyond EOF";
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

// The Inspector row under the mouse, for inspector_mark() (which may run before the panel in a
// frame, so the previous frame's row counts too).
struct InspectorHover {
    int row = -1;          // hovered row (index = InspType), -1 = none
    int frame = -100;      // frame `row` was seen
    int drawn_frame = -100;  // last frame the Inspector's rows were drawn
};
InspectorHover g_insp_hover;

// Makes integer row `type` the follow-pointer type (width + signedness; byte order stays the
// Inspector's LE / BE). Nothing for other rows: the last integer type is kept.
void pick_follow_type(App& app, InspType type) {
    int w = 0;
    bool sgn = false;
    if (!insp_int_type(type, w, sgn)) return;
    app.auto_ptr.pick();  // an explicit choice: process documents no longer change the width
    Settings& s = app.settings;
    if (s.pointer_width == w && s.pointer_signed == sgn) return;
    s.pointer_width = w;
    s.pointer_signed = sgn;
    mark_settings_dirty(app);
    set_status(app, "Follow pointer type: " + pointer_type_name(s.pointer_type()) +
                        "  (Ctrl+click / Ctrl+Enter in the hex view)");
}

// Double-click / Enter / "Edit value" on a row: starts the inline edit, or says why it cannot.
void begin_inspector_edit(App& app, const Document& d, const InspRow& r, int i, uint64_t at) {
    if (r.unreadable) {
        set_status(app, std::string("Cannot edit ") + r.name + " at " + fmt_offset(at) +
                            ": its bytes are unreadable (unmapped memory or an I/O error)");
        return;
    }
    if (r.editable && !d.read_only()) app.insp_edit.begin(i, at, r.value);
}

void draw_inspector_row(App& app, Tab& t, Document& d, const InspRow& r, int i, bool be) {
    const uint64_t cur = focus_offset(d.view());
    const PointerType pt = app.settings.pointer_type();
    int iw = 0;
    bool isg = false;
    const bool is_int = insp_int_type(r.type, iw, isg);
    const bool is_follow = is_int && iw == pt.width && isg == pt.is_signed;
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::PushID(i);
    const bool editing = app.insp_edit.active(i, cur);
    const char* value = r.value.empty() ? "-" : r.value.c_str();
    if (ImGui::Selectable(r.name, app.insp_sel == i,
                          ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick |
                              ImGuiSelectableFlags_AllowOverlap)) {
        app.insp_sel = i;
        pick_follow_type(app, r.type);
    }
    const bool hovered = ImGui::IsItemHovered();
    if (hovered) {
        g_insp_hover.row = i;
        g_insp_hover.frame = ImGui::GetFrameCount();
    }
    if (hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) begin_inspector_edit(app, d, r, i, cur);
    if (hovered && !editing && r.unreadable)
        ImGui::SetItemTooltip("%s: unreadable (unmapped memory or an I/O error); not editable", r.name);
    else if (hovered && !editing && (r.size || is_int))
        ImGui::SetItemTooltip("%s: %zu byte%s%s%s", r.name, r.size, r.size == 1 ? "" : "s",
                              r.editable ? "  (double-click or Enter to edit)" : "",
                              is_follow ? "\nThe follow-pointer type (Ctrl+click / Ctrl+Enter in the hex view)"
                              : is_int  ? "\nClick: follow pointers as this type (Ctrl+click in the hex view)"
                                        : "");
    if (ImGui::BeginPopupContextItem("##ctx")) {
        if (ImGui::MenuItem("Copy value")) ImGui::SetClipboardText(value);
        if (ImGui::MenuItem("Edit value", nullptr, false, (r.editable || r.unreadable) && !d.read_only()))
            begin_inspector_edit(app, d, r, i, cur);
        if (is_int) {
            ImGui::Separator();
            if (ImGui::MenuItem("Use as Follow Pointer Type", nullptr, is_follow)) pick_follow_type(app, r.type);
        }
        close_popup_on_escape();
        ImGui::EndPopup();
    }
    if (is_follow) {  // link glyph at the right end of the name cell
        const char* arrow = "\xE2\x86\x92";  // U+2192
        ImGui::SameLine();
        const float aw = ImGui::CalcTextSize(arrow).x;
        const float avail = ImGui::GetContentRegionAvail().x;
        if (avail > aw) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + avail - aw);
        ImGui::TextColored(kInputColor, "%s", arrow);
    }
    ImGui::TableSetColumnIndex(1);
    if (editing) {
        int res = inline_edit_input(app.insp_edit, false);
        if (res > 0) commit_inspector_edit(app, d, r, be);
        if (res < 0) app.insp_edit.end();
    } else {
        ImGui::PushFont(app.fonts.mono, 0.0f);
        if (r.unreadable)
            ImGui::TextColored(kErrColor, "%s", value);
        else if (r.size == 0)
            ImGui::TextDisabled("%s", value);
        else
            ImGui::TextUnformatted(value);
        ImGui::PopFont();
        if (is_follow && r.size && !r.unreadable) {
            bool ok = false;
            const std::string tip = follow_tip(d, cur, pt, ok);
            if (follow_button(ok, tip)) follow_pointer_as(app, t, cur, pt);
        }
    }
    ImGui::PopID();
}

// ---- Bits row: one toggle per bit of the integer at the focus offset ----

constexpr int kBitsRow = int(InspType::Count);  // its row index for g_insp_hover / inspector_mark

// Width in bytes of the Bits row: the selected integer row's (the follow-pointer type), else 1.
int bits_width(const App& app) {
    int w = 1;
    bool sgn = false;
    if (app.insp_sel >= 0 && app.insp_sel < int(InspType::Count) && insp_int_type(InspType(app.insp_sel), w, sgn))
        return w;
    return 1;
}

// Bit names of the Structure field (opts.flags) that covers exactly these `w` bytes at `at`.
const std::vector<Field::FlagItem>* flag_names_at(const Tab& t, const Document& d, uint64_t at, int w) {
    const StructureState& st = t.st;
    if (!st.has_result || st.gen != d.generation()) return nullptr;
    const Highlight* h = st.result.highlights.at(at);
    if (!h || h->field < 0 || h->field >= int(st.result.fields.size())) return nullptr;
    const Field& f = st.result.fields[size_t(h->field)];
    return f.flags && f.offset == at && f.size == uint64_t(w) ? f.flags.get() : nullptr;
}

void draw_bits_row(App& app, Tab& t, Document& d, const uint8_t* buf, const uint8_t* bad, size_t n, bool be) {
    const int w = bits_width(app);
    const uint64_t at = focus_offset(d.view());
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::AlignTextToFramePadding();
    ImGui::Text("bits%d", w * 8);
    if (ImGui::IsItemHovered()) {
        g_insp_hover.row = kBitsRow;
        g_insp_hover.frame = ImGui::GetFrameCount();
        ImGui::SetTooltip("%d bits at the cursor, most significant first (%s). Click a bit to flip it (undoable).\n"
                              "Width: the selected integer row (click uint16 / uint32 / uint64), else 8 bits.",
                              w * 8, be ? "big endian" : "little endian");
    }
    ImGui::TableSetColumnIndex(1);
    ImGui::PushFont(app.fonts.mono, 0.0f);
    bool unreadable = false;
    for (int i = 0; i < w && size_t(i) < n; ++i) unreadable |= bad[i] != 0;
    if (n < size_t(w)) {
        ImGui::TextDisabled("-");
    } else if (unreadable) {
        ImGui::TextColored(kErrColor, "??");
    } else {
        uint64_t v = 0;
        for (int i = 0; i < w; ++i) v |= uint64_t(buf[be ? w - 1 - i : i]) << (8 * i);
        const std::vector<Field::FlagItem>* names = flag_names_at(t, d, at, w);
        const ImGuiStyle& style = ImGui::GetStyle();
        const float pad_x = 3.0f * app.ui_scale;  // compact cells: 16 bits per line fit more often
        const float cell = ImGui::CalcTextSize("0").x + pad_x * 2.0f;
        const float gap = 1.0f * app.ui_scale, group_gap = 5.0f * app.ui_scale;
        const float label_gap = style.ItemSpacing.x;  // read before the PushStyleVar below changes it
        const float label = ImGui::CalcTextSize("63").x + label_gap;
        const float line16 = label + 16.0f * (cell + gap) + 4.0f * group_gap;
        const int per_line = (w >= 2 && ImGui::GetContentRegionAvail().x >= line16) ? 16 : 8;
        const bool ro = d.read_only();
        int flip = -1;
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(pad_x, 0.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(gap, 2.0f * app.ui_scale));
        for (int hi = w * 8 - 1; hi >= 0; hi -= per_line) {
            ImGui::TextDisabled("%2d", hi);
            ImGui::SameLine(0.0f, label_gap);
            for (int k = 0; k < per_line && hi - k >= 0; ++k) {
                const int bit = hi - k;
                const bool set = (v >> bit) & 1;
                if (k) ImGui::SameLine(0.0f, k % 8 == 0 ? 2.0f * group_gap : k % 4 == 0 ? group_gap : gap);
                ImGui::PushID(bit);
                ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetColorU32(set ? ImGuiCol_ButtonActive : ImGuiCol_FrameBg));
                ImGui::BeginDisabled(ro);
                if (ImGui::Button(set ? "1" : "0", ImVec2(cell, 0.0f))) flip = bit;
                ImGui::EndDisabled();
                ImGui::PopStyleColor();
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_ForTooltip)) {
                    std::string name;
                    if (names)
                        for (const Field::FlagItem& it : *names)
                            if (it.bit == bit) name = "  " + it.name;
                    ImGui::SetTooltip("bit %d = %d  (mask 0x%llX)%s\n%s", bit, set ? 1 : 0,
                                      static_cast<unsigned long long>(uint64_t(1) << bit), name.c_str(),
                                      ro ? "Read-only document" : set ? "Click to clear" : "Click to set");
                    g_insp_hover.row = kBitsRow;
                    g_insp_hover.frame = ImGui::GetFrameCount();
                }
                ImGui::PopID();
            }
        }
        ImGui::PopStyleVar(2);
        if (names) {  // set flags of the Structure field here (Lua opts.flags)
            const std::string set_names = format_flags(v, w, *names);
            ImGui::TextDisabled("%s", set_names.empty() ? "(no flags set)" : set_names.c_str());
        }
        if (flip >= 0) {
            std::string err;
            if (inspector_toggle_bit(d, at, w, be, flip, &err)) {
                d.view_generation++;
                set_status(app, "Bit " + std::to_string(flip) + ((v >> flip) & 1 ? " cleared" : " set") + " at " +
                                    fmt_offset(at) + "  (Ctrl+Z undoes)");
            } else {
                set_status(app, "Cannot flip bit " + std::to_string(flip) + ": " + err);
            }
        }
    }
    ImGui::PopFont();
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

    uint8_t buf[16] = {}, bad[16] = {};
    const size_t n = d->read(at, buf, sizeof buf, bad);
    const std::vector<InspRow> rows = inspect(buf, n, be, bad);  // unreadable bytes: "??"
    if (app.insp_edit.row >= 0 && app.insp_edit.ctx != at) app.insp_edit.end();  // moved

    // Enter edits the selected row when the panel has focus (and no text field is active).
    if (app.insp_sel >= 0 && app.insp_sel < int(rows.size()) && app.insp_edit.row < 0 &&
        ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) && !ImGui::GetIO().WantTextInput &&
        !ImGui::GetIO().KeyCtrl &&  // Ctrl+Enter = Follow Pointer at Cursor
        (ImGui::IsKeyPressed(ImGuiKey_Enter) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter))) {
        begin_inspector_edit(app, *d, rows[size_t(app.insp_sel)], app.insp_sel, at);
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
        for (size_t i = 0; i < rows.size(); ++i) {
            draw_inspector_row(app, *active_tab(app), *d, rows[i], int(i), be);
            if (i == 0) draw_bits_row(app, *active_tab(app), *d, buf, bad, n, be);  // after the binary row
        }
        ImGui::EndTable();
        g_insp_hover.drawn_frame = ImGui::GetFrameCount();
    }
    ImGui::Separator();
    draw_selection_info(*d);
    ImGui::End();
}

bool inspector_mark(App& app, const Tab& t, uint64_t& offset, uint64_t& length) {
    offset = length = 0;
    const int frame = ImGui::GetFrameCount();
    if (!app.show_inspector || g_insp_hover.drawn_frame < frame - 1 || active_tab(app) != &t || !t.doc ||
        t.doc->busy())
        return false;
    int row = g_insp_hover.frame >= frame - 1 ? g_insp_hover.row : -1;
    if (row < 0) row = app.insp_sel;
    const Document& d = *t.doc;
    const uint64_t at = focus_offset(d.view());
    if (row == kBitsRow) {  // the Bits grid: the integer it shows
        const uint64_t w = uint64_t(bits_width(app));
        if (at > d.size() || d.size() - at < w) return false;
        offset = at;
        length = w;
        return true;
    }
    if (row < 0 || row >= int(InspType::Count)) return false;
    uint8_t buf[16] = {};
    const size_t n = d.read(at, buf, sizeof buf);
    const std::vector<InspRow> rows = inspect(buf, n, app.settings.big_endian_inspector);
    if (size_t(row) >= rows.size() || rows[size_t(row)].size == 0) return false;
    offset = at;
    length = rows[size_t(row)].size;
    return true;
}

bool follow_pointer_as(App& app, Tab& tab, uint64_t at, const PointerType& type) {
    Document& d = *tab.doc;
    if (d.busy()) return false;
    uint64_t target = 0;
    if (!decode_pointer(d, at, type, target)) {
        set_status(app, "No pointer to follow at " + fmt_offset(at) + " (" + pointer_type_name(type) +
                            "): unreadable, negative, below the base or beyond EOF");
        return false;
    }
    reveal_range(app, tab, target, 0, true);
    set_status(app, "Followed " + pointer_type_name(type) + " at " + fmt_offset(at) + " -> " + fmt_offset(target) +
                        "  (Alt+Left goes back)", 6.0);
    return true;
}

bool draw_pointer_settings(App& app, bool in_menu) {
    Settings& s = app.settings;
    bool changed = false;
    static const int kWidths[] = {1, 2, 3, 4, 8};
    auto width_label = [](int w) {
        return std::to_string(w) + (w == 1 ? " byte" : " bytes") + " (" + std::to_string(w * 8) + "-bit)";
    };
    auto set_width = [&](int w) {
        changed |= s.pointer_width != w;
        s.pointer_width = w;
        app.auto_ptr.pick();  // an explicit choice: process documents no longer change the width
    };
    const char* signed_tip = "Sign-extend the value: a negative absolute pointer cannot be followed, a negative "
                             "relative one points backwards";
    const char* rel_tip = "target = offset of the pointer + value (self-relative offsets, rel32 displacements); "
                          "the base is not used";
    if (in_menu) {
        ImGui::TextDisabled("Type: %s", pointer_type_name(s.pointer_type()).c_str());
        if (ImGui::BeginMenu("Pointer Width")) {
            for (int w : kWidths)
                if (ImGui::MenuItem(width_label(w).c_str(), nullptr, s.pointer_width == w)) set_width(w);
            ImGui::EndMenu();
        }
        changed |= ImGui::MenuItem("Signed", nullptr, &s.pointer_signed);
        ImGui::SetItemTooltip("%s", signed_tip);
        changed |= ImGui::MenuItem("Relative to the Pointer", nullptr, &s.pointer_relative);
        ImGui::SetItemTooltip("%s", rel_tip);
        changed |= ImGui::MenuItem("Big Endian (same as the Inspector)", nullptr, &s.big_endian_inspector);
    } else {
        ImGui::SetNextItemWidth(200.0f * app.ui_scale);
        if (ImGui::BeginCombo("Pointer width", width_label(s.pointer_width).c_str())) {
            for (int w : kWidths)
                if (ImGui::Selectable(width_label(w).c_str(), s.pointer_width == w)) set_width(w);
            ImGui::EndCombo();
        }
        ImGui::SameLine();
        changed |= ImGui::Checkbox("Signed##ptr", &s.pointer_signed);
        ImGui::SetItemTooltip("%s", signed_tip);
        ImGui::SameLine();
        changed |= ImGui::Checkbox("Relative##ptr", &s.pointer_relative);
        ImGui::SetItemTooltip("%s", rel_tip);
        ImGui::TextDisabled("Type: %s  (byte order: the Inspector's; clicking an integer row in the Inspector picks "
                            "width and signedness)",
                            pointer_type_name(s.pointer_type()).c_str());
    }
    ImGui::BeginDisabled(s.pointer_relative);
    ImGui::SetNextItemWidth((in_menu ? 140.0f : 200.0f) * app.ui_scale);
    changed |= ImGui::InputScalar("Pointer base (hex)", ImGuiDataType_U64, &s.pointer_base, nullptr, nullptr, "%llX",
                                  ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_ForTooltip))
        ImGui::SetTooltip("%s", s.pointer_relative
                                    ? "Not used by relative pointers"
                                    : "Subtracted from the value: target offset = value - base (e.g. the load "
                                      "address of an image)");
    // Keep the Inspector's selected row (and its hex-view outline) on the follow type.
    if (changed) {
        if (InspType ft = insp_type_of_int(s.pointer_width, s.pointer_signed); ft != InspType::Count)
            app.insp_sel = int(ft);
    }
    return changed;
}

// =============================================================================================
// Structure
// =============================================================================================

namespace {

// Parses run on a worker (script/parse_job.h). The frame that starts one waits this long for it,
// so a fast parser's tree shows up at once, as when it ran on the UI thread.
constexpr int kInstantParseMs = 8;
constexpr double kParseDebounceS = 0.15;  // re-parse this long after the last edit
constexpr double kParsingShowS = 0.1;     // "parsing..." (greyed tree) only after this long

// A new result is in `st.result` (`old_count` = fields of the previous one): reset the tree view.
void parse_result_changed(App& app, StructureState& st, const Document& d, size_t old_count) {
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

// Takes the finished job's result (it was started for the current inputs).
void adopt_parse(App& app, Tab& t) {
    StructureState& st = t.st;
    std::unique_ptr<ParseJob> job = std::move(st.job);
    const size_t old_count = st.result.fields.size();
    st.result = job->take(*app.engine, *t.doc);
    st.has_result = true;
    st.used_parser = job->parser();
    st.parsed_base = job->base();
    st.parsed_length = job->length();
    st.gen = job->generation();
    st.reload = st.job_reload;
    st.requested = st.job_requested;
    st.last_parse_ms = (now_s() - st.job_t0) * 1000.0;
    st.due = 0.0;
    parse_result_changed(app, st, *t.doc, old_count);
}

// Detects the parser (cheap detect() calls, UI thread) and starts the job; no parser: no tree.
void start_parse(App& app, Tab& t) {
    StructureState& st = t.st;
    Document& d = *t.doc;
    const double t0 = now_s();
    const std::string requested = d.view().parser;
    const std::string name = requested.empty() ? app.engine->detect_parser(d) : requested;
    st.due = 0.0;
    if (name.empty()) {
        const size_t old_count = st.result.fields.size();
        st.result = ParseResult{};
        st.has_result = false;
        st.used_parser.clear();
        st.parsed_base = st.base;
        st.parsed_length = st.length;
        st.gen = d.generation();
        st.reload = app.engine->reload_count();
        st.requested = requested;
        st.last_parse_ms = (now_s() - t0) * 1000.0;
        parse_result_changed(app, st, d, old_count);
        return;
    }
    st.job = std::make_unique<ParseJob>(*app.engine, d, name, st.base, st.length);
    st.job_reload = app.engine->reload_count();
    st.job_requested = requested;
    st.job_t0 = t0;
    if (st.job->wait(kInstantParseMs)) adopt_parse(app, t);
}

// A parse has been running for a while: the shown tree is the previous one.
bool parse_running(const StructureState& st) { return st.job && now_s() - st.job_t0 >= kParsingShowS; }

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
    const std::string& shown = st.job ? st.job->parser() : st.used_parser;  // detected, maybe still parsing
    std::string preview = forced.empty() ? "Auto (" + (shown.empty() ? std::string("none") : shown) + ")" : forced;
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
    ImGui::SameLine();
    ImGui::BeginDisabled(!st.has_result || st.result.fields.empty());
    if (ImGui::Button("C Header")) ImGui::OpenPopup("##cheader");
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("The parsed tree as packed C structs (right-click a struct row for just that struct)");
    if (ImGui::BeginPopup("##cheader")) {
        if (ImGui::MenuItem("Copy as C Header")) structure_copy_c_header(app);
        if (ImGui::MenuItem("Export C Header...")) structure_export_c_header(app);
        close_popup_on_escape();
        ImGui::EndPopup();
    }
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
    ImGui::BeginDisabled(st.base == 0 && st.length == UINT64_MAX);
    if (ImGui::Button("File start")) set_parse_base(app, t, 0);
    ImGui::EndDisabled();
}

// Length of a parse over a range (StructureState::parsed_length), clamped to the document.
uint64_t parsed_len(const StructureState& st, const Document& d) {
    const uint64_t room = d.size() - std::min(st.parsed_base, d.size());
    return std::min(st.parsed_length, room);
}

// "Parsing... 1234 fields [Cancel]" while a background parse has been running for a while.
void draw_parse_progress(StructureState& st) {
    ImGui::TextColored(kWarnColor, "Parsing... %llu fields", ull(st.job->fields()));
    ImGui::SameLine();
    ImGui::BeginDisabled(st.job->cancelled());
    if (ImGui::SmallButton("Cancel")) st.job->cancel();
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("Stop the parser and show the tree it has built so far");
}

void draw_parse_info(App& app, StructureState& st, const Document& d) {
    if (!st.has_result) {
        if (parse_running(st)) {
            draw_parse_progress(st);
        } else if (st.gen == UINT64_MAX || st.job) {
            ImGui::TextDisabled("Parsing...");
        } else {
            ImGui::TextDisabled("No parser matched this document.");
            ImGui::TextDisabled("Pick one above, or add a script (Scripts > Open Scripts Folder).");
        }
        return;
    }
    const ParseResult& r = st.result;
    if (st.parsed_length != UINT64_MAX)  // one packet / range (Packets panel)
        ImGui::TextDisabled("%s @ %s  \xC2\xB7  %zu fields  \xC2\xB7  %.1f ms", r.parser.c_str(),
                            fmt_range(st.parsed_base, parsed_len(st, d)).c_str(), r.fields.size(), r.ms);
    else if (st.parsed_base)
        ImGui::TextDisabled("%s @ %s  \xC2\xB7  %zu fields  \xC2\xB7  %.1f ms", r.parser.c_str(),
                            fmt_offset(st.parsed_base).c_str(), r.fields.size(), r.ms);
    else
        ImGui::TextDisabled("%zu fields  \xC2\xB7  %.1f ms", r.fields.size(), r.ms);
    if (parse_running(st)) {  // the tree below is the previous result (greyed)
        ImGui::SameLine();
        draw_parse_progress(st);
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

// Pointer type of an integer field from its pack format ("<I4", ">h", "B"...): its own width
// (1, 2, 3, 4, 8), signedness (lower-case letter) and byte order; relative mode and base come from
// the follow-pointer settings. Width 0 for anything else (floats, strings, structs).
PointerType int_field_pointer(const App& app, const Field& f) {
    PointerType pt = app.settings.pointer_type();
    pt.width = 0;
    const std::string& p = f.pack;
    size_t i = 0;
    pt.big_endian = false;
    if (i < p.size() && (p[i] == '<' || p[i] == '>' || p[i] == '=')) pt.big_endian = p[i++] == '>';
    if (i >= p.size()) return pt;
    pt.is_signed = p[i] >= 'a' && p[i] <= 'z';
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
        default: return pt;
    }
    if (i == p.size() && uint64_t(w) == f.size && valid_pointer_width(w)) pt.width = w;
    return pt;
}

// Returns whether the row is visible (taken from the name cell: the last cell may be in a hidden column).
bool draw_field_row(App& app, Tab& t, Document& d, int row, int hover_field) {
    StructureState& st = t.st;
    const int fi = st.rows[size_t(row)];
    const Field& f = st.result.fields[size_t(fi)];
    const bool leaf = f.children.empty();
    // A stale result (content changed, not re-parsed yet) has stale offsets: no field edits.
    const bool can_edit = f.editable() && !d.read_only() && st.gen == d.generation();
    const PointerType ptr = int_field_pointer(app, f);
    const int ptr_w = ptr.width;
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
                follow_pointer_as(app, t, f.offset, ptr);
        }
        ImGui::Separator();
        if (!leaf) {  // just this struct / array
            if (ImGui::MenuItem("Copy Struct as C Header")) structure_copy_c_header(app, fi);
            if (ImGui::MenuItem("Export Struct as C Header...")) structure_export_c_header(app, fi);
        }
        if (ImGui::MenuItem("Copy as C Header")) structure_copy_c_header(app);
        ImGui::SetItemTooltip("The whole parse tree as packed C structs");
        if (ImGui::MenuItem("Export C Header...")) structure_export_c_header(app);
        close_popup_on_escape();
        ImGui::EndPopup();
    }

    // Value (+ color swatch) or the in-place editor
    ImGui::TableSetColumnIndex(1);
    if (app.st_edit.active(fi, d.id())) {
        int res = inline_edit_input(app.st_edit, false);
        if (res > 0 && commit_field_edit(app, d, f)) {
            st.gen = UINT64_MAX;  // one explicit edit: re-parse (in the background) without the debounce
            st.pending_gen = UINT64_MAX - 1;
        }
        if (res < 0) app.st_edit.end();
    } else {
        draw_swatch(f.color);
        ImGui::TextUnformatted(f.value.c_str());
        // 32/64-bit integers that point inside the file get a follow button (any width: context menu).
        if ((ptr_w == 4 || ptr_w == 8) && st.gen == d.generation()) {
            bool ok = false;
            const std::string tip = follow_tip(d, f.offset, ptr, ok);
            if (ok && follow_button(true, tip)) follow_pointer_as(app, t, f.offset, ptr);
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
    std::erase_if(st.retired, [](const std::unique_ptr<ParseJob>& j) { return j->done(); });
    const uint64_t gen = d.generation();
    const uint64_t rel = app.engine->reload_count();
    const std::string& want = d.view().parser;
    if (st.job) {
        const ParseJob& j = *st.job;
        const bool current = j.generation() == gen && st.job_reload == rel && st.job_requested == want &&
                             j.base() == st.base && j.length() == st.length;
        if (current && j.done()) {
            adopt_parse(app, t);
        } else if (!current) {  // its result would be stale: stop it, parse again once edits pause
            st.job->cancel();
            st.retired.push_back(std::move(st.job));
        }
    }
    if (st.job || !st.retired.empty()) app.wants_poll = true;  // poll for the result / the worker's end
    if (gen == st.gen && rel == st.reload && want == st.requested && st.base == st.parsed_base &&
        st.length == st.parsed_length) {
        st.due = 0.0;
        return;
    }
    if (st.job) return;  // already parsing the current state
    const double now = now_s();
    if (gen != st.pending_gen || rel != st.pending_reload || want != st.pending_parser) {
        st.pending_gen = gen;
        st.pending_reload = rel;
        st.pending_parser = want;
        // Debounce while typing; the first parse and explicit requests (F5, a field edit, Parse
        // at: st.gen = UINT64_MAX) start at once.
        st.due = now + (st.gen == UINT64_MAX ? 0.0 : kParseDebounceS);
    }
    app.wants_poll = true;
    if (now >= st.due) start_parse(app, t);
}

void set_parse_base(App& app, Tab& t, uint64_t base, uint64_t length) {
    StructureState& st = t.st;
    Document& d = *t.doc;
    if (d.busy()) return;
    base = std::min(base, d.size());
    st.base = base;
    st.length = length;  // UINT64_MAX = up to the end (the engine clamps a longer one)
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
    else if (length != UINT64_MAX)
        set_status(app, "Parsing " + fmt_range(base, std::min(length, d.size() - base)), 3.0);
    else
        set_status(app, base ? "Parsing from " + fmt_offset(base) : std::string("Parsing from the file start"), 3.0);
}

namespace {

// C header of the active tab's parse tree (field -1 = all of it); "" (and a status) if none.
// `file_name` gets a suggestion for the export dialog ("PNG_image.h").
std::string active_c_header(App& app, int field, std::string* file_name) {
    Tab* t = active_tab(app);
    if (!t || !usable_doc(app)) return {};
    const StructureState& st = t->st;
    if (!st.has_result || st.result.fields.empty()) {
        set_status(app, "C header: nothing parsed (pick a parser in the Structure panel)");
        return {};
    }
    if (field >= int(st.result.fields.size())) field = -1;
    const std::string name = field >= 0 ? st.result.fields[size_t(field)].name
                                        : (st.result.parser.empty() ? st.used_parser : st.result.parser);
    std::string h = fields_to_c_header(st.result.fields, field, name);
    if (h.empty()) set_status(app, "C header: the parse tree declares no bytes");
    if (file_name) {
        *file_name = name.empty() ? std::string("structure") : name;
        for (char& c : *file_name)
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-')) c = '_';
        *file_name += ".h";
    }
    return h;
}

}  // namespace

void structure_copy_c_header(App& app, int field) {
    const std::string h = active_c_header(app, field, nullptr);
    if (h.empty()) return;
    ImGui::SetClipboardText(h.c_str());
    const size_t lines = size_t(std::count(h.begin(), h.end(), '\n'));
    set_status(app, "Copied the C header (" + std::to_string(lines) + " lines) to the clipboard");
}

void structure_export_c_header(App& app, int field) {
    std::string name;
    const std::string h = active_c_header(app, field, &name);
    if (h.empty()) return;
    std::string path, err;
    if (!save_file_dialog(app, name, path)) return;
    if (!os_write_whole_atomic(path, h.data(), h.size(), &err))
        notify(app, "Export C header failed: " + (err.empty() ? std::string("write error") : err), true);
    else
        set_status(app, "Wrote the C header to " + path, 6.0);
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
    if (t->st.has_result && !t->st.result.fields.empty()) {
        const bool grey = parse_running(t->st);
        if (grey) ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.5f);
        draw_field_table(app, *t, *d);
        if (grey) ImGui::PopStyleVar();
    }
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
    if (ImGui::Checkbox("All open files", &app.settings.bookmarks_all_files)) mark_settings_dirty(app);
    ImGui::SameLine();
    ImGui::TextDisabled("Ctrl+B toggle  \xC2\xB7  F2 / Shift+F2 next / previous  \xC2\xB7  Ctrl+Shift+B find  \xC2\xB7  "
                        "double-click name or note to edit");

    // The tabs to list: the active one, or every open (not saving) one.
    std::vector<Tab*> tabs;
    size_t total = 0;
    if (app.settings.bookmarks_all_files) {
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
        if (!d && !app.settings.bookmarks_all_files)
            empty_note(app, "No document.");
        else
            ImGui::TextDisabled(app.settings.bookmarks_all_files ? "No bookmarks in the open files." : "No bookmarks in this file.");
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
            if (app.settings.bookmarks_all_files) {  // file header row
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
// Bitmap / Packets (self-contained panels, ui/panel_bitmap.h / ui/panel_packets.h)
// =============================================================================================

void draw_bitmap_panel(App& app) {
    dock_like(kWinStructure);  // the right column: a tall panel suits images
    if (!begin_panel(kWinBitmap, &app.show_bitmap)) return;
    Tab* t = active_tab(app);
    BitmapPanel& bp = app.bitmap_panel;
    bp.mono = app.fonts.mono;
    bp.ui_scale = app.ui_scale;
    const uint64_t doc_id = t ? t->doc->id() : 0;
    BitmapPanelCallbacks cb;
    cb.jump = [&app, doc_id](uint64_t off) {
        if (Tab* tab = find_tab(app, doc_id)) reveal_range(app, *tab, off, 0, false);
    };
    cb.select = [&app, doc_id](uint64_t off, uint64_t len) {
        if (Tab* tab = find_tab(app, doc_id)) reveal_range(app, *tab, off, len, false);
    };
    uint64_t cursor = 0, top = 0;
    if (t && !t->doc->busy()) {
        const ViewState& v = t->doc->view();
        cursor = focus_offset(v);
        const uint64_t bpr = uint64_t(t->top_bpr > 0 ? t->top_bpr : std::max(1, t->ev.bytes_per_row));
        top = v.top_row > t->doc->size() / bpr ? t->doc->size() : v.top_row * bpr;
    }
    bp.draw(t ? t->doc.get() : nullptr, cursor, top, cb);  // a busy document is not read
    if (bp.wants_frames()) app.wants_poll = true;
    // Remember format / width / zoom ("" = the default format, Gray 8-bit).
    Settings& s = app.settings;
    const std::string fmt = bp.format == PixelFormat::Gray8 ? std::string() : std::string(pixel_format_name(bp.format));
    if (fmt != s.bitmap_format || bp.width != s.bitmap_width || bp.zoom != s.bitmap_zoom) {
        s.bitmap_format = fmt;
        s.bitmap_width = bp.width;
        s.bitmap_zoom = bp.zoom;
        mark_settings_dirty(app);
    }
    ImGui::End();
}

void draw_packets_panel(App& app) {
    dock_like(kWinConsole);  // with Console / Strings, below the hex view
    if (!begin_panel(kWinPackets, &app.show_packets)) return;
    Tab* t = active_tab(app);
    PacketsPanel& pp = app.packets_panel;
    pp.mono = app.fonts.mono;
    pp.ui_scale = app.ui_scale;
    std::vector<std::string> names;
    for (const ParserInfo& p : app.engine->parsers()) names.push_back(p.name);
    const uint64_t doc_id = t ? t->doc->id() : 0;
    PacketsPanelCallbacks cb;
    cb.select = [&app, doc_id](uint64_t off, uint64_t len) {
        if (Tab* tab = find_tab(app, doc_id)) reveal_range(app, *tab, off, len, false);
    };
    // The protocol-analysis loop: each selected packet (or its payload) is parsed on its own.
    cb.parse = [&app, doc_id](const std::string& parser, uint64_t off, uint64_t len) {
        Tab* tab = find_tab(app, doc_id);
        if (!tab || tab->doc->busy()) return;
        if (tab->doc->view().parser != parser) {
            tab->doc->view().parser = parser;  // sticky per document; Structure > Auto-detect undoes it
            tab->doc->view_generation++;
        }
        set_parse_base(app, *tab, off, len);
        app.show_structure = true;
    };
    cb.notify = [&app](const std::string& m) { set_status(app, m); };
    // Followed TCP streams / single packets: a new read-only tab; its bookmarks are its initial
    // state (not an undo step), like the bytes of create_from_bytes.
    cb.open_tab = [&app](const std::string& name, const std::vector<uint8_t>& bytes, const std::vector<Bookmark>& marks) {
        if (Document* d = app.open_bytes(name, bytes.data(), bytes.size())) {
            d->view().bookmarks = marks;
            d->set_read_only(true);
        }
    };
    pp.draw(t ? t->doc.get() : nullptr, names, cb);
    if (pp.wants_frames()) app.wants_poll = true;
    ImGui::End();
}

// =============================================================================================
// History / XOR Search / Regions (self-contained panels, ui/panel_history.h / ui/panel_xor.h /
// ui/dialog_targets.h)
// =============================================================================================

void draw_history_panel(App& app) {
    dock_like(kWinBookmarks);
    if (!begin_panel(kWinHistory, &app.show_history)) return;
    Tab* t = active_tab(app);
    HistoryPanel& hp = app.history_panel;
    hp.mono = app.fonts.mono;
    hp.ui_scale = app.ui_scale;
    const uint64_t doc_id = t ? t->doc->id() : 0;
    HistoryPanelCallbacks cb;
    // Undo / redo restored the selection of that state: only scroll there (like do_undo), no
    // reveal_range (it would replace the selection and fill the jump history).
    cb.moved = [&app, doc_id](uint64_t off) {
        if (Tab* tab = find_tab(app, doc_id)) {
            tab->doc->view().low_nibble = false;
            tab->doc->view_generation++;
            tab->view.request_scroll_to(off, false);
        }
    };
    cb.notify = [&app](const std::string& m) { set_status(app, m); };
    hp.draw(t ? t->doc.get() : nullptr, cb);  // the panel shows busy / read-only states itself
    ImGui::End();
}

void draw_xor_panel(App& app) {
    dock_like(kWinConsole);  // below the hex view, with Console / Strings
    if (!begin_panel(kWinXor, &app.show_xor)) return;
    Tab* t = active_tab(app);
    XorPanel& xp = app.xor_panel;
    xp.mono = app.fonts.mono;
    xp.ui_scale = app.ui_scale;
    const uint64_t doc_id = t ? t->doc->id() : 0;
    XorPanelCallbacks cb;
    cb.jump = [&app, doc_id](uint64_t off, uint64_t len) {
        if (Tab* tab = find_tab(app, doc_id)) reveal_range(app, *tab, off, len, false);
    };
    cb.copy = [&app](const std::string& s) {
        ImGui::SetClipboardText(s.c_str());
        set_status(app, "Copied " + s);
    };
    cb.notify = [&app](const std::string& m) { set_status(app, m, 6.0); };
    // cb.apply stays empty: "Decode selection" is then one undoable Document edit
    // (hx::apply_transform, labelled "Decode <key>" in the History panel).
    xp.draw(t ? t->doc.get() : nullptr, cb);
    if (xp.wants_frames()) app.wants_poll = true;
    ImGui::End();
}

void draw_regions_panel(App& app) {
    Tab* t = active_tab(app);
    RegionsPanel& rp = app.regions_panel;
    rp.mono = app.fonts.mono;
    rp.ui_scale = app.ui_scale;
    const uint64_t doc_id = t ? t->doc->id() : 0;
    RegionsPanelCallbacks cb;
    cb.jump = [&app, doc_id](uint64_t base, uint64_t size) {
        if (Tab* tab = find_tab(app, doc_id)) reveal_range(app, *tab, base, size, false);
    };
    cb.notify = [&app](const std::string& m) { set_status(app, m); };
    Document* doc = t && !t->doc->busy() ? t->doc.get() : nullptr;
    dock_like(kWinConsole);
    if (begin_panel(kWinRegions, &app.show_regions)) {
        rp.draw(doc, cb);
        ImGui::End();
    }
    // "Go to Module" popup: outside the panel window, and after it (a closed BeginPopupModal
    // clears the next-window data, e.g. the panel's SetNextWindowFocus).
    rp.draw_module_list(doc, cb);
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

// Where the bytes come from, for a device or a process document ("process 1234 · 47-bit address
// space"; red "exited" once the process is gone). Nothing for files.
void draw_target_status(Document& d) {
    const SourceKind k = d.target();
    if (k == SourceKind::File) return;
    status_sep();
    if (k == SourceKind::Device) {
        ImGui::TextColored(kWarnColor, "device");
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Raw disk / volume: fixed size (overwrite only), saved in place without a backup.\n"
                              "Edit > Read-only toggles writing.");
        return;
    }
    int bits = 0;  // address space bits: the document spans [0, process_address_limit)
    while (bits < 64 && d.size() > 0 && ((d.size() - 1) >> bits) != 0) ++bits;
    ImGui::Text("process %u \xC2\xB7 %d-bit address space", unsigned(d.process_id()), bits);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Live memory of %s. Unmapped pages show as ??. Overwrite only: Save writes the\n"
                          "changed bytes into the process. F5 / File > Refresh Memory re-reads the memory map\n"
                          "(cached bytes also refresh every second). View > Regions lists the regions.",
                          d.display_name().c_str());
    if (!d.target_alive()) {
        ImGui::SameLine();
        ImGui::TextColored(kErrColor, "exited");
    }
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
    draw_target_status(d);
    status_sep();
    ImGui::TextUnformatted(t.insert_mode ? "INS" : "OVR");
    if (ImGui::IsItemClicked() && d.fixed_size()) {
        set_status(app, "Overwrite only: a device / process memory cannot change size");
    } else if (ImGui::IsItemClicked()) {
        t.insert_mode = !t.insert_mode;
        app.settings.insert_mode = t.insert_mode;
        mark_settings_dirty(app);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Insert / overwrite (Insert key)");
    if (d.read_only()) {
        status_sep();
        ImGui::TextColored(kWarnColor, d.target() == SourceKind::File ? "RO" : "read-only");
    }
    if (d.io_error()) {
        status_sep();
        ImGui::TextColored(kErrColor, "I/O error");
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Part of the file could not be read (bad sector, removed drive, or truncated by\n"
                              "another program). Unreadable bytes are shown as ??. Searches stop at them and\n"
                              "saves that rewrite the file refuse; copies and scripts read them as 0.");
    }
    if (t.tail.enabled) {
        status_sep();
        const bool following = v.cursor >= d.size() && !v.has_selection();
        ImGui::TextColored(kResultColor, "TAIL +%s%s", fmt_size(t.tail.added).c_str(), following ? " (following)" : "");
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Live tail: the file is checked for appended data every 0.5 s.\n"
                              "%llu bytes appended since it was turned on. With the caret at the end of\n"
                              "the file (Ctrl+End) the view follows new data. View > Live Tail turns it off.",
                              ull(t.tail.added));
    }
    if (!t.st.used_parser.empty()) {
        status_sep();
        if (t.st.parsed_length != UINT64_MAX)
            ImGui::Text("Parser: %s @ %s", t.st.used_parser.c_str(), fmt_range(t.st.parsed_base, parsed_len(t.st, d)).c_str());
        else if (t.st.parsed_base)
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

// =============================================================================================
// Disassembly (self-contained panel, ui/panel_disasm.h)
// =============================================================================================

namespace {

// Writes the panel's options back into app.settings (settings.ini) when one changed.
void save_disasm_settings(App& app) {
    const DisasmPanel& dp = app.disasm_panel;
    Settings& s = app.settings;
    const bool att = dp.syntax == DisasmSyntax::Att;
    if (s.disasm_mode == dp.mode && s.disasm_att == att && s.disasm_uppercase == dp.uppercase &&
        s.disasm_follow == dp.follow && s.disasm_bytes == dp.show_bytes)
        return;
    s.disasm_mode = dp.mode;
    s.disasm_att = att;
    s.disasm_uppercase = dp.uppercase;
    s.disasm_follow = dp.follow;
    s.disasm_bytes = dp.show_bytes;
    mark_settings_dirty(app);
}

}  // namespace

void load_disasm_settings(App& app) {
    DisasmPanel& dp = app.disasm_panel;
    const Settings& s = app.settings;
    dp.mode = s.disasm_mode;
    dp.syntax = s.disasm_att ? DisasmSyntax::Att : DisasmSyntax::Intel;
    dp.uppercase = s.disasm_uppercase;
    dp.follow = s.disasm_follow;
    dp.show_bytes = s.disasm_bytes;
}

void draw_disasm_panel(App& app) {
    dock_like(kWinStructure);  // the right column: a tall listing
    if (!begin_panel(kWinDisasm, &app.show_disasm)) return;
    Tab* t = active_tab(app);
    DisasmPanel& dp = app.disasm_panel;
    dp.mono = app.fonts.mono;
    dp.ui_scale = app.ui_scale;
    const uint64_t doc_id = t ? t->doc->id() : 0;
    DisasmPanelCallbacks cb;
    // A row click selects the instruction's bytes; not a jump (no history), the listing is local.
    cb.select = [&app, doc_id](uint64_t off, uint64_t len) {
        Tab* tab = find_tab(app, doc_id);
        if (!tab || tab->doc->busy()) return;
        const uint64_t size = tab->doc->size();
        ViewState& v = tab->doc->view();
        v.cursor = std::min(off, size);
        v.anchor = len > size - v.cursor ? size : v.cursor + len;
        v.low_nibble = false;
        tab->doc->view_generation++;
        tab->view.request_scroll_to(v.cursor, false);
    };
    cb.jump = [&app, doc_id](uint64_t off) {
        if (Tab* tab = find_tab(app, doc_id)) reveal_range(app, *tab, off, 0, false);
    };
    cb.copy = [&app](const std::string& s) {
        ImGui::SetClipboardText(s.c_str());
        set_status(app, s.find('\n') == std::string::npos ? "Copied " + s : "Copied the listing");
    };
    cb.notify = [&app](const std::string& m) { set_status(app, m); };
    const uint64_t caret = t && !t->doc->busy() ? focus_offset(t->doc->view()) : 0;
    dp.draw(t ? t->doc.get() : nullptr, caret, cb);
    save_disasm_settings(app);
    ImGui::End();
}

void disasm_at_cursor(App& app) {
    Document* d = usable_doc(app);
    if (!d) return;
    app.show_disasm = app.focus_disasm = true;
    app.disasm_panel.show_at(*d, focus_offset(d->view()), true);
    set_status(app, "Disassembly pinned at " + fmt_offset(focus_offset(d->view())) + " (Follow cursor is off)");
}

void disasm_follow_target(App& app) {
    Tab* t = active_tab(app);
    Document* d = usable_doc(app);
    if (!d) return;
    const uint64_t doc_id = d->id();
    DisasmPanelCallbacks cb;
    cb.jump = [&app, doc_id](uint64_t off) {
        if (Tab* tab = find_tab(app, doc_id)) reveal_range(app, *tab, off, 0, true);
    };
    cb.notify = [&app](const std::string& m) { set_status(app, m); };
    app.show_disasm = true;
    app.disasm_panel.follow_at(*d, focus_offset(t->doc->view()), cb);
}

void disasm_go_to_entry(App& app) {
    Tab* t = active_tab(app);
    Document* d = usable_doc(app);
    if (!d) return;
    uint64_t off = 0;
    if (!app.disasm_panel.entry_offset(*d, off)) {
        set_status(app, "No entry point: not a PE / ELF file, or its header was rejected", 6.0);
        return;
    }
    app.show_disasm = app.focus_disasm = true;
    app.disasm_panel.show_at(*d, off, false);
    reveal_range(app, *t, off, 0, true);
    set_status(app, "Entry point 0x" + fmt_hex(app.disasm_panel.address_map(*d).entry) + " at offset " + fmt_offset(off));
}

void disasm_go_to_symbol(App& app) {
    if (!usable_doc(app)) return;
    app.show_disasm = app.focus_disasm = true;
    app.disasm_panel.open_symbol_list();  // the panel's next draw opens it
}

}  // namespace hx
