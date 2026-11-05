#include "ui/panel_disasm.h"

#include <algorithm>
#include <cfloat>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "imgui.h"
#include "misc/cpp/imgui_stdlib.h"

#include "core/document.h"
#include "core/settings.h"
#include "core/util.h"

namespace hx {

namespace {

const ImVec4 kWarnColor(1.0f, 0.78f, 0.35f, 1.0f);
constexpr uint32_t kCurrentTint = rgba(70, 170, 255);  // current instruction in the hex view
constexpr uint32_t kLabelColor = rgba(120, 220, 160);  // label rows
constexpr uint32_t kSymbolColor = rgba(150, 205, 170); // symbol annotations
constexpr uint64_t kTooltipDelta = 1 << 20;            // "In name+0x..": nearest symbol this close
constexpr uint64_t kInlineDelta = 0x1000;              // "; name+0x.." after a branch: closer still
constexpr int kMaxRows = 400;
constexpr size_t kShownBytes = 8;                      // bytes column: longer ones end in ".."

// Mnemonic color by control flow (operands use the normal text color).
ImU32 flow_color(const Insn& i) {
    if (!i.valid) return ImGui::GetColorU32(ImGuiCol_TextDisabled);
    switch (i.flow) {
    case Insn::Call: return rgba(110, 180, 255);
    case Insn::Jump:
    case Insn::CondJump: return rgba(235, 200, 100);
    case Insn::Ret: return rgba(255, 125, 125);
    case Insn::Int: return rgba(200, 145, 255);
    default: return ImGui::GetColorU32(ImGuiCol_Text);
    }
}

// "1400", "0x1400", "1400h" -> hex value.
bool parse_hex_u64(std::string s, uint64_t& out) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return false;
    s = s.substr(b);
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
    else if (s.size() > 1 && (s.back() == 'h' || s.back() == 'H')) s.pop_back();
    uint64_t v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v, 16);
    if (ec != std::errc() || p != s.data() + s.size()) return false;
    out = v;
    return true;
}

int hex_digits(uint64_t v) {
    int n = 1;
    while (v >>= 4) ++n;
    return n;
}

// Moves to the same line when an item of width `w` still fits there (toolbar wrapping).
void same_line_if_fits(float w) {
    const ImGuiStyle& style = ImGui::GetStyle();
    const float right = ImGui::GetWindowPos().x + ImGui::GetWindowWidth() - style.WindowPadding.x;
    if (ImGui::GetItemRectMax().x + style.ItemSpacing.x + w <= right) ImGui::SameLine();
}

float button_width(const char* label) {
    return ImGui::CalcTextSize(label, nullptr, true).x + ImGui::GetStyle().FramePadding.x * 2.0f;
}

}  // namespace

struct DisasmPanel::DocState {
    bool have_top = false;
    uint64_t top = 0;                  // file offset of the first listed instruction
    uint64_t last_caret = UINT64_MAX;  // caret seen by the last draw (follow reacts to changes)

    DisasmMapChoice choice = DisasmMapChoice::Auto;
    uint64_t manual_base = 0;
    std::string base_input;
    bool base_bad = false;

    AddressMap map;
    std::string map_err;               // why a PE / ELF header was rejected (Auto)
    bool map_valid = false;
    uint64_t map_gen = 0, map_size = 0, map_base = 0;
    DisasmMapChoice map_choice = DisasmMapChoice::Auto;
    uint64_t map_version = 0;          // bumps whenever `map` is rebuilt

    // The decoded listing (rows + 1 instructions from `top`) and what it was decoded for.
    std::vector<Insn> insns;
    bool list_valid = false;
    uint64_t l_gen = 0, l_top = 0, l_mapv = 0;
    int l_rows = 0;
    DisasmOptions l_opt;

    size_t shown = 0;                  // instructions drawn by the last draw (labels take rows)

    HighlightSet layer;                // the current instruction's bytes
    uint64_t layer_off = UINT64_MAX, layer_len = 0;

    SymbolJob sym_job;                 // builds `syms` in the background
    std::shared_ptr<const SymbolTable> syms;
    uint64_t sym_mapv = UINT64_MAX;    // map_version the job was started for
};

DisasmPanel::DisasmPanel() = default;
DisasmPanel::~DisasmPanel() = default;

void DisasmPanel::load_settings(const Settings& s) {
    mode = s.disasm_mode >= 0 && s.disasm_mode <= 2 ? s.disasm_mode : 0;  // unknown: auto
    syntax = s.disasm_att ? DisasmSyntax::Att : DisasmSyntax::Intel;
    uppercase = s.disasm_uppercase;
    follow = s.disasm_follow;
    show_bytes = s.disasm_bytes;
}

bool DisasmPanel::save_settings(Settings& s) const {
    const bool att = syntax == DisasmSyntax::Att;
    if (s.disasm_mode == mode && s.disasm_att == att && s.disasm_uppercase == uppercase && s.disasm_follow == follow &&
        s.disasm_bytes == show_bytes)
        return false;
    s.disasm_mode = mode;
    s.disasm_att = att;
    s.disasm_uppercase = uppercase;
    s.disasm_follow = follow;
    s.disasm_bytes = show_bytes;
    return true;
}

DisasmPanel::DocState& DisasmPanel::state(const Document& doc) {
    std::unique_ptr<DocState>& p = docs_[doc.id()];
    if (!p) p = std::make_unique<DocState>();
    return *p;
}

void DisasmPanel::forget(uint64_t doc_id) { docs_.erase(doc_id); }

std::vector<Insn> DisasmPanel::listing(uint64_t doc_id) const {
    auto it = docs_.find(doc_id);
    if (it == docs_.end() || !it->second->list_valid) return {};
    const std::vector<Insn>& v = it->second->insns;
    return std::vector<Insn>(v.begin(), v.begin() + std::ptrdiff_t(std::min(v.size(), it->second->shown)));
}

std::vector<std::string> DisasmPanel::listing_lines(uint64_t doc_id) const {
    auto it = docs_.find(doc_id);
    if (it == docs_.end() || !it->second->list_valid) return {};
    const DocState& st = *it->second;
    std::vector<std::string> out;
    for (size_t k = 0; k < std::min(st.insns.size(), st.shown); ++k) {
        const Insn& in = st.insns[k];
        const Symbol* s = st.syms && in.mapped ? st.syms->at(in.address) : nullptr;
        if (s) out.push_back(s->label() + ":");
        std::string t = in.text;
        const size_t c = t.find(syntax == DisasmSyntax::Att ? "  # " : "  ; ");
        if (c != std::string::npos) t.resize(c);
        out.push_back(t + insn_comment(st, in));
    }
    return out;
}

bool DisasmPanel::row_pos(int row, float& x, float& y) const {
    if (row < 0 || row >= drawn_rows_ || size_t(row) >= row_ys_.size()) return false;
    x = rows_x_ + row_w_ * 0.5f;
    y = row_ys_[size_t(row)];
    return true;
}

const HighlightSet* DisasmPanel::layer(uint64_t doc_id) const {
    auto it = docs_.find(doc_id);
    return it != docs_.end() && !it->second->layer.empty() ? &it->second->layer : nullptr;
}

void DisasmPanel::ensure_map(DocState& st, const Document& doc) {
    if (st.map_valid && st.map_gen == doc.generation() && st.map_size == doc.size() && st.map_choice == st.choice &&
        st.map_base == st.manual_base)
        return;
    st.map_err.clear();
    switch (st.choice) {
    case DisasmMapChoice::Auto: st.map = detect_address_map(doc, &st.map_err); break;
    case DisasmMapChoice::Manual: st.map = manual_address_map(doc, st.manual_base); break;
    case DisasmMapChoice::None: st.map = no_address_map(doc); break;
    }
    st.map_valid = true;
    st.map_gen = doc.generation();
    st.map_size = doc.size();
    st.map_choice = st.choice;
    st.map_base = st.manual_base;
    ++st.map_version;
}

const AddressMap& DisasmPanel::address_map(const Document& doc) {
    DocState& st = state(doc);
    ensure_map(st, doc);
    return st.map;
}

void DisasmPanel::set_map_choice(const Document& doc, DisasmMapChoice choice, uint64_t base) {
    DocState& st = state(doc);
    st.choice = choice;
    st.manual_base = base;
    st.base_input = fmt_hex(base);
    st.base_bad = false;
}

void DisasmPanel::ensure_symbols(DocState& st, const Document& doc) {
    if (st.sym_mapv != st.map_version) {
        st.sym_mapv = st.map_version;
        st.sym_job.start(doc.snapshot(), st.map);
    }
    st.syms = st.sym_job.result();
}

std::shared_ptr<const SymbolTable> DisasmPanel::current_symbols(const Document& doc) const {
    auto it = docs_.find(doc.id());
    if (it == docs_.end()) return nullptr;
    const DocState& st = *it->second;
    // Auto (= detect_address_map) and up to date with the document's bytes; never process memory.
    if (st.choice != DisasmMapChoice::Auto || !st.map_valid || st.map_choice != DisasmMapChoice::Auto ||
        st.map_gen != doc.generation() || st.map_size != doc.size() || st.sym_mapv != st.map_version ||
        st.map.kind == AddressMap::Process || st.map.in_memory || !st.sym_job.current())
        return nullptr;
    return st.sym_job.result();
}

const SymbolTable* DisasmPanel::symbols(const Document& doc, bool wait) {
    DocState& st = state(doc);
    ensure_map(st, doc);
    ensure_symbols(st, doc);
    if (wait) {
        st.sym_job.wait();
        st.syms = st.sym_job.result();
    }
    return st.syms.get();
}

std::string DisasmPanel::symbol_text(const DocState& st, uint64_t va, uint64_t max_delta) const {
    if (!st.syms) return {};
    if (const Symbol* s = st.syms->at(va)) return s->label();
    if (!max_delta) return {};
    uint64_t delta = 0;
    const Symbol* s = st.syms->nearest(va, &delta);
    if (!s || delta >= max_delta || st.map.section_at_va(s->address) != st.map.section_at_va(va)) return {};
    return s->label() + "+0x" + fmt_hex(delta, 0, uppercase);
}

std::string DisasmPanel::insn_comment(const DocState& st, const Insn& insn, bool* is_symbol) const {
    if (is_symbol) *is_symbol = false;
    const char* mark = syntax == DisasmSyntax::Att ? "  # " : "  ; ";
    std::string zydis;  // the formatter's own comment (RIP-relative operand address)
    if (const size_t c = insn.text.find(mark); c != std::string::npos) zydis = insn.text.substr(c);
    if (insn.has_target) {
        const std::string sym = symbol_text(st, insn.target, kInlineDelta);
        if (!sym.empty()) {
            if (is_symbol) *is_symbol = true;
            return mark + sym;
        }
    }
    const std::string note = target_note(st, insn);
    return note.empty() ? zydis : zydis + "  <" + note + ">";
}

void DisasmPanel::save_extras(Document& doc) const {
    auto it = docs_.find(doc.id());
    const DocState* st = it != docs_.end() ? it->second.get() : nullptr;
    const DisasmMapChoice c = st ? st->choice : DisasmMapChoice::Auto;
    doc.set_extra("disasm.map", c == DisasmMapChoice::Manual ? "manual" : c == DisasmMapChoice::None ? "none" : "");
    doc.set_extra("disasm.base", st && (st->manual_base || c == DisasmMapChoice::Manual) ? fmt_hex(st->manual_base) : "");
    doc.set_extra("disasm.top", st && st->have_top && !follow ? std::to_string(st->top) : "");
}

void DisasmPanel::restore_extras(const Document& doc) {
    const std::string m = doc.extra("disasm.map"), b = doc.extra("disasm.base"), t = doc.extra("disasm.top");
    if (m.empty() && b.empty() && t.empty()) return;
    DocState& st = state(doc);
    st.choice = m == "manual" ? DisasmMapChoice::Manual : m == "none" ? DisasmMapChoice::None : DisasmMapChoice::Auto;
    uint64_t v = 0;
    if (parse_hex_u64(b, v)) st.manual_base = v;
    st.base_input = b.empty() ? std::string() : fmt_hex(st.manual_base);
    uint64_t top = 0;
    auto [p, ec] = std::from_chars(t.data(), t.data() + t.size(), top);
    if (!t.empty() && ec == std::errc() && p == t.data() + t.size()) {
        st.top = std::min(top, doc.size());
        st.have_top = true;
    }
}

DisasmOptions DisasmPanel::options_for(const Document& doc) {
    const AddressMap& m = address_map(doc);
    DisasmOptions o;
    o.mode = mode == 1 ? DisasmMode::X64 : mode == 2 ? DisasmMode::X86 : (m.bits == 32 ? DisasmMode::X86 : DisasmMode::X64);
    o.syntax = syntax;
    o.uppercase = uppercase;
    return o;
}

bool DisasmPanel::entry_offset(const Document& doc, uint64_t& off) { return address_map(doc).entry_offset(off); }

void DisasmPanel::show_at(const Document& doc, uint64_t offset, bool pin) {
    DocState& st = state(doc);
    st.top = std::min(offset, doc.size());
    st.have_top = true;
    st.last_caret = offset;
    if (pin) follow = false;
}

std::string DisasmPanel::target_note(const DocState& st, const Insn& insn) const {
    if (!insn.has_target) return {};
    const AddressMap& m = st.map;
    if (m.kind == AddressMap::Pe || m.kind == AddressMap::Elf) {
        std::string sec = m.section_at_va(insn.target);
        if (!sec.empty()) return sec;
        return m.contains_va(insn.target) ? std::string() : "outside image";
    }
    uint64_t off = 0;
    return m.va_to_offset(insn.target, off) ? std::string() : "outside file";
}

void DisasmPanel::anchor(DocState& st, const Document& doc, uint64_t off) {
    bool landed = false;
    st.top = disasm_sync_back(doc, off, size_t(std::clamp(rows_ / 4, 0, 8)), options_for(doc), &landed);
    if (!landed) st.top = off;  // no decode lands on it: start the listing there
    st.have_top = true;
}

void DisasmPanel::scroll(DocState& st, const Document& doc, int rows) {
    if (!rows) return;
    const DisasmOptions opt = options_for(doc);
    if (rows < 0) {
        st.top = disasm_sync_back(doc, st.top, size_t(-rows), opt);
    } else {
        std::vector<Insn> tmp;
        disasm_range(doc, st.top, size_t(rows) + 1, st.map, opt, tmp);
        if (tmp.size() > size_t(rows)) st.top = tmp[size_t(rows)].offset;
        else if (tmp.size() > 1) st.top = tmp.back().offset;  // keep the last instruction listed
    }
    st.have_top = true;
}

bool DisasmPanel::follow_target(DocState& st, const Document& doc, const Insn& insn, const DisasmPanelCallbacks& cb) {
    if (!insn.has_target) {
        if (cb.notify) cb.notify("'" + insn.text + "' has no target to follow");
        return false;
    }
    uint64_t off = 0;
    const std::string addr = "0x" + fmt_hex(insn.target);
    if (!st.map.va_to_offset(insn.target, off) || off >= doc.size()) {
        if (cb.notify) cb.notify("Target " + addr + " is not in the file");
        return false;
    }
    // A listed instruction start: just move the caret there. Else (also a target in the middle of
    // a listed instruction: the listing is misaligned there) list it a few rows from the top.
    const size_t shown = st.list_valid ? std::min(st.insns.size(), st.shown) : 0;
    bool listed = false;
    for (size_t r = 0; r < shown && !listed; ++r) listed = st.insns[r].offset == off;
    if (!listed) {
        anchor(st, doc, off);
    }
    st.last_caret = off;
    if (cb.jump) cb.jump(off);
    if (cb.notify) cb.notify("Followed to " + addr);
    return true;
}

bool DisasmPanel::follow_at(const Document& doc, uint64_t at, const DisasmPanelCallbacks& cb) {
    DocState& st = state(doc);
    ensure_map(st, doc);
    const size_t shown = st.list_valid ? std::min(st.insns.size(), st.shown) : 0;
    for (size_t r = 0; r < shown; ++r) {
        const Insn& in = st.insns[r];
        if (at >= in.offset && at < in.offset + std::max<uint64_t>(in.length, 1)) {
            const Insn copy = in;  // follow_target may move the listing
            return follow_target(st, doc, copy, cb);
        }
    }
    std::vector<Insn> one;
    disasm_range(doc, at, 1, st.map, options_for(doc), one);
    if (one.empty()) return false;
    return follow_target(st, doc, one[0], cb);
}

void DisasmPanel::draw(Document* doc, uint64_t caret, const DisasmPanelCallbacks& cb) {
    if (!doc) {
        ImGui::TextDisabled("No document open");
        return;
    }
    if (doc->busy()) {
        ImGui::TextDisabled("Document is being saved...");
        return;
    }
    DocState& st = state(*doc);
    ensure_map(st, *doc);
    ensure_symbols(st, *doc);
    draw_toolbar(st, *doc, caret, cb);
    draw_listing(st, *doc, caret, cb);
    draw_symbol_list(st, *doc, cb);
}

void DisasmPanel::draw_toolbar(DocState& st, const Document& doc, uint64_t caret, const DisasmPanelCallbacks& cb) {
    // Combo width that fits `preview` (the selected item).
    auto combo_w = [](const char* preview) {
        return ImGui::CalcTextSize(preview).x + ImGui::GetFrameHeight() + ImGui::GetStyle().FramePadding.x * 2.0f;
    };
    if (ImGui::Checkbox("Follow", &follow) && follow) st.last_caret = UINT64_MAX;  // re-check now
    ImGui::SetItemTooltip("Follow cursor: list the code at the hex caret whenever it moves outside the listing");

    const char* auto_label = st.map.bits == 32 ? "Auto (32-bit)" : "Auto (64-bit)";
    const char* modes[] = {auto_label, "64-bit", "32-bit"};
    const float mode_w = combo_w(modes[std::clamp(mode, 0, 2)]);
    same_line_if_fits(mode_w);
    ImGui::SetNextItemWidth(mode_w);
    ImGui::Combo("##mode", &mode, modes, 3);
    ImGui::SetItemTooltip("x86-64 (long mode) or 32-bit x86. Auto: the PE / ELF header's, else 64-bit");

    const char* maps[] = {"Map: Auto", "Map: Manual base", "Map: None"};
    const float map_w = combo_w(maps[int(st.choice)]);
    same_line_if_fits(map_w);
    ImGui::SetNextItemWidth(map_w);
    int choice = int(st.choice);
    if (ImGui::Combo("##map", &choice, maps, 3)) {
        st.choice = DisasmMapChoice(choice);
        if (st.choice == DisasmMapChoice::Manual && st.base_input.empty()) st.base_input = fmt_hex(st.manual_base);
    }
    ImGui::SetItemTooltip("Address map: virtual addresses from the PE / ELF headers (Auto), file offset + a base "
                          "(Manual), or the file offset itself (None)");
    if (st.choice == DisasmMapChoice::Manual) {
        const float base_w = ImGui::CalcTextSize("0000000140000000").x + ImGui::GetStyle().FramePadding.x * 2.0f;
        same_line_if_fits(base_w);
        ImGui::SetNextItemWidth(base_w);
        if (st.base_bad) ImGui::PushStyleColor(ImGuiCol_Text, kWarnColor);
        if (ImGui::InputTextWithHint("##base", "base (hex)", &st.base_input)) {
            uint64_t v = 0;
            st.base_bad = !parse_hex_u64(st.base_input, v);
            if (!st.base_bad) st.manual_base = v;
        }
        if (st.base_bad) ImGui::PopStyleColor();
        ImGui::SetItemTooltip("Load address of file offset 0 (hex), e.g. 08000000 for a firmware image");
    }

    uint64_t entry = 0;
    const bool has_entry = st.map.entry_offset(entry);
    same_line_if_fits(button_width("Entry"));
    ImGui::BeginDisabled(!has_entry);
    if (ImGui::Button("Entry")) {
        show_at(doc, entry, false);
        if (cb.jump) cb.jump(entry);
    }
    ImGui::EndDisabled();
    ImGui::SetItemTooltip(has_entry ? "Go to the entry point (0x%s)" : "No entry point (not a PE / ELF file?)",
                          fmt_hex(st.map.entry).c_str());

    same_line_if_fits(button_width("Symbols"));
    if (ImGui::Button("Symbols")) open_symbols_ = true;
    if (!st.syms) ImGui::SetItemTooltip("Go to Symbol... (reading the symbol tables)");
    else ImGui::SetItemTooltip("Go to Symbol... (%zu symbols: PE exports / imports, ELF symtab / PLT)",
                               st.syms->symbols.size());

    same_line_if_fits(button_width("Options"));
    if (ImGui::Button("Options")) ImGui::OpenPopup("##disopt");
    if (ImGui::BeginPopup("##disopt")) {
        ImGui::Checkbox("Uppercase", &uppercase);
        ImGui::Checkbox("Bytes column", &show_bytes);
        ImGui::Separator();
        if (ImGui::RadioButton("Intel syntax", syntax == DisasmSyntax::Intel)) syntax = DisasmSyntax::Intel;
        if (ImGui::RadioButton("AT&T syntax", syntax == DisasmSyntax::Att)) syntax = DisasmSyntax::Att;
        ImGui::EndPopup();
    }

    // Info line: the map, the current section, problems.
    std::string info = st.map.format;
    if (st.map.kind == AddressMap::None) info = "No address map (address = file offset)";
    if (const std::string sec = st.map.section_at_offset(caret); !sec.empty()) info += "  \xC2\xB7  caret in " + sec;
    if (st.map.has_entry) info += "  \xC2\xB7  entry 0x" + fmt_hex(st.map.entry);
    ImGui::TextDisabled("%s", info.c_str());
    if (!st.map_err.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(header rejected: %s)", st.map_err.c_str());
    }
}

void DisasmPanel::draw_listing(DocState& st, const Document& doc, uint64_t caret, const DisasmPanelCallbacks& cb) {
    const ImGuiStyle& style = ImGui::GetStyle();
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    if (avail.y < 4.0f || avail.x < 4.0f) return;
    const ImGuiWindowFlags cflags = ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
    if (!ImGui::BeginChild("##listing", avail, ImGuiChildFlags_None, cflags)) {
        ImGui::EndChild();
        return;
    }
    const float header_h = ImGui::GetTextLineHeightWithSpacing();
    if (mono) ImGui::PushFont(mono, 0.0f);
    ImFont* font = ImGui::GetFont();
    const float font_size = ImGui::GetFontSize();
    const float row_h = std::floor(ImGui::GetTextLineHeight() + 2.0f);
    const float char_w = ImGui::CalcTextSize("0").x;
    if (mono) ImGui::PopFont();
    rows_ = std::clamp(int((avail.y - header_h) / row_h), 1, kMaxRows);
    const DisasmOptions opt = options_for(doc);
    const uint64_t size = doc.size();

    // ---- follow the caret / first show ----
    {
        const size_t shown = st.list_valid ? std::min(st.insns.size(), st.shown) : 0;
        const bool inside = shown && caret >= st.insns.front().offset &&
                            caret < st.insns[shown - 1].offset + std::max<uint64_t>(st.insns[shown - 1].length, 1);
        if (!st.have_top || (follow && caret != st.last_caret && !inside)) {
            anchor(st, doc, std::min(caret, size));
        }
        st.last_caret = caret;
        if (st.top >= size && size) st.top = disasm_sync_back(doc, size, 1, opt);
    }

    // ---- keyboard / wheel scrolling ----
    const bool focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput;
    int delta = 0;
    bool follow_enter = false, page_up = false;
    if (ImGui::IsWindowHovered() && !ImGui::GetIO().KeyCtrl) {  // Ctrl+wheel is the app's zoom
        wheel_accum_ -= double(ImGui::GetIO().MouseWheel) * 3.0;
        const int whole = int(wheel_accum_);
        delta += whole;
        wheel_accum_ -= whole;
    }
    if (focused) {
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) delta += 1;
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) delta -= 1;
        // A page = the instructions the last draw listed (label rows take rows too), so paging
        // never jumps over instructions that were not shown.
        if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) {
            const size_t listed = st.list_valid ? std::min(st.insns.size(), st.shown) : size_t(rows_);
            delta += std::max(1, int(std::min(listed, size_t(rows_))) - 1);
        }
        if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) page_up = true;
        if (ImGui::IsKeyPressed(ImGuiKey_Enter, false) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false))
            follow_enter = true;
        if (ImGui::IsKeyPressed(ImGuiKey_Home, false)) {
            anchor(st, doc, std::min(caret, size));
        }
    }
    if (delta) scroll(st, doc, delta);
    if (page_up) {
        // Back one page so that the old first instruction is the last listed one: go back a row
        // count of instructions, then drop from the front what the label rows push off the page.
        const uint64_t old_top = st.top;
        scroll(st, doc, -std::max(1, rows_ - 1));
        std::vector<Insn> back;
        disasm_range(doc, st.top, size_t(std::max(1, rows_)), st.map, opt, back);
        auto cost = [&](const Insn& in) { return st.syms && in.mapped && st.syms->at(in.address) ? 2 : 1; };
        int used = 0;
        for (const Insn& in : back)
            if (in.offset >= old_top) {
                used = cost(in);  // the old top itself (+ its label) ends the page
                break;
            }
        size_t first = back.size();
        for (size_t k = back.size(); k-- > 0;) {
            if (back[k].offset >= old_top) continue;
            if (used + cost(back[k]) > rows_) break;
            used += cost(back[k]);
            first = k;
        }
        if (first < back.size()) st.top = back[first].offset;
    }

    // ---- decode the visible rows (only when something changed) ----
    if (!st.list_valid || st.l_gen != doc.generation() || st.l_top != st.top || st.l_rows != rows_ ||
        st.l_mapv != st.map_version || !(st.l_opt == opt)) {
        st.insns.clear();
        disasm_range(doc, st.top, size_t(rows_) + 1, st.map, opt, st.insns);
        st.list_valid = true;
        st.l_gen = doc.generation();
        st.l_top = st.top;
        st.l_rows = rows_;
        st.l_mapv = st.map_version;
        st.l_opt = opt;
    }
    // ---- layout: a label row above each instruction at a symbol address ----
    std::vector<const Symbol*> labels;  // per listed instruction (nullptr: none)
    {
        int used = 0;
        for (size_t k = 0; k < st.insns.size() && used < rows_; ++k) {
            const Insn& in = st.insns[k];
            const Symbol* sym = st.syms && in.mapped ? st.syms->at(in.address) : nullptr;
            if (sym && used + 2 > rows_) {
                if (used) break;  // no room for label + instruction: list it on the next page
                sym = nullptr;    // a one-row panel: the instruction only
            }
            labels.push_back(sym);
            used += sym ? 2 : 1;
        }
    }
    const size_t nrows = labels.size();
    st.shown = nrows;
    // Instruction text without the formatter's comment + the comment drawn after it.
    const char* mark = syntax == DisasmSyntax::Att ? "  # " : "  ; ";
    auto plain_len = [&](const Insn& in) { return std::min(in.text.find(mark), in.text.size()); };
    auto full_text = [&](const Insn& in) { return in.text.substr(0, plain_len(in)) + insn_comment(st, in); };

    // ---- columns ----
    uint64_t max_addr = 0;
    for (size_t r = 0; r < nrows; ++r) max_addr = std::max(max_addr, st.insns[r].address);
    const int addr_digits = std::max(8, hex_digits(max_addr));
    const float pad = style.FramePadding.x;
    const float gap = std::floor(char_w * 1.5f);
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const float addr_x = origin.x + pad;
    const float bytes_x = addr_x + char_w * float(addr_digits) + gap;
    // Bytes column: as wide as the longest listed instruction (at most kShownBytes), narrower when
    // the instruction column would get fewer than ~30 characters.
    size_t shown_bytes = 2;
    for (size_t r = 0; r < nrows; ++r) shown_bytes = std::max<size_t>(shown_bytes, st.insns[r].length);
    shown_bytes = std::min(shown_bytes, kShownBytes);
    auto bytes_width = [&](size_t n) { return char_w * float(n * 3 + 2); };
    while (shown_bytes > 3 && origin.x + avail.x - (bytes_x + bytes_width(shown_bytes) + gap) < char_w * 30.0f)
        --shown_bytes;
    const float bytes_w = show_bytes ? bytes_width(shown_bytes) : 0.0f;
    const float text_x = show_bytes ? bytes_x + bytes_w + gap : bytes_x;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImU32 dim = ImGui::GetColorU32(ImGuiCol_TextDisabled);
    const ImU32 normal = ImGui::GetColorU32(ImGuiCol_Text);
    dl->AddText(ImVec2(addr_x, origin.y), dim, "Address");
    if (show_bytes) dl->AddText(ImVec2(bytes_x, origin.y), dim, "Bytes");
    dl->AddText(ImVec2(text_x, origin.y), dim, "Instruction");
    const float rows_y = origin.y + header_h;
    dl->AddLine(ImVec2(origin.x, rows_y - 1.0f), ImVec2(origin.x + avail.x, rows_y - 1.0f),
                ImGui::GetColorU32(ImGuiCol_Separator));

    row_ys_.clear();
    if (nrows == 0) {
        drawn_rows_ = 0;
        ImGui::SetCursorScreenPos(ImVec2(addr_x, rows_y + 2.0f));
        ImGui::TextDisabled(size ? "End of file" : "Empty document");
        ImGui::EndChild();
        return;
    }

    // ---- rows ----
    if (!ImGui::IsMouseDown(ImGuiMouseButton_Left) && !ImGui::IsMouseReleased(ImGuiMouseButton_Left))
        swallow_release_ = false;
    rows_x_ = origin.x;
    rows_y_ = rows_y;
    row_w_ = avail.x;
    row_h_ = row_h;
    drawn_rows_ = int(nrows);
    int current = -1, hovered = -1;
    for (size_t r = 0; r < nrows; ++r) {
        const Insn& in = st.insns[r];
        if (caret >= in.offset && caret < in.offset + std::max<uint64_t>(in.length, 1)) current = int(r);
    }
    const Insn* follow_req = nullptr;
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(style.ItemSpacing.x, 0.0f));
    int line = 0;
    for (size_t r = 0; r < nrows; ++r) {
        const Insn& in = st.insns[r];
        if (labels[r]) {  // "kernel32.dll!CreateFileW:"
            const float ly = rows_y + float(line++) * row_h;
            const std::string label = labels[r]->label() + ":";
            const ImVec4 clip(origin.x, ly, origin.x + avail.x, ly + row_h);
            dl->AddText(font, font_size, ImVec2(addr_x, ly + (row_h - font_size) * 0.5f), kLabelColor, label.data(),
                        label.data() + label.size(), 0.0f, &clip);
        }
        const float y = rows_y + float(line++) * row_h;
        row_ys_.push_back(y + row_h * 0.5f);
        ImGui::SetCursorScreenPos(ImVec2(origin.x, y));
        ImGui::PushID(int(r));
        bool clicked = ImGui::Selectable("##row", int(r) == current, ImGuiSelectableFlags_AllowDoubleClick,
                                         ImVec2(avail.x, row_h));
        if (clicked && swallow_release_ && !ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
            clicked = false;
            swallow_release_ = false;
        }
        const bool hov = ImGui::IsItemHovered();
        if (hov) hovered = int(r);
        if (clicked) {
            const bool dbl = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
            if ((ImGui::GetIO().KeyCtrl || dbl) && in.has_target) {
                follow_req = &in;
                swallow_release_ = dbl;
            }
            else if (cb.select)
                cb.select(in.offset, in.length);
            st.last_caret = in.offset;  // the caret lands inside the listing: no re-anchor
        }
        const std::string where = hov && in.mapped ? symbol_text(st, in.address, kTooltipDelta) : std::string();
        if (hov && (in.has_target || !where.empty()) && ImGui::BeginItemTooltip()) {
            ImGui::TextUnformatted(full_text(in).c_str());  // the full text (the row may clip it)
            if (!where.empty()) ImGui::TextDisabled("In %s", where.c_str());
            if (in.has_target) {
                std::string note = symbol_text(st, in.target, kTooltipDelta);
                if (note.empty()) note = target_note(st, in);
                ImGui::TextDisabled("Target 0x%s%s%s  -  double-click / Ctrl+click / Enter follows it",
                                    fmt_hex(in.target).c_str(), note.empty() ? "" : "  ", note.c_str());
            }
            ImGui::EndTooltip();
        }
        if (ImGui::BeginPopupContextItem("##ctx")) {
            const std::string addr = fmt_hex(in.address, addr_digits);
            if (ImGui::MenuItem("Copy instruction") && cb.copy) cb.copy(full_text(in));
            if (ImGui::MenuItem("Copy address") && cb.copy) cb.copy("0x" + addr);
            if (ImGui::MenuItem("Copy bytes") && cb.copy) cb.copy(insn_bytes_hex(in));
            if (ImGui::MenuItem("Copy visible listing") && cb.copy) {
                std::string all;
                for (size_t k = 0; k < nrows; ++k) {
                    const Insn& i = st.insns[k];
                    if (labels[k]) all += labels[k]->label() + ":\n";
                    std::string b = insn_bytes_hex(i);
                    b.resize(std::max<size_t>(b.size(), Insn::kMaxLength * 3), ' ');
                    all += fmt_hex(i.address, addr_digits) + "  " + b + " " + full_text(i) + "\n";
                }
                cb.copy(all);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Follow target", "Ctrl+click", false, in.has_target)) follow_req = &in;
            if (ImGui::MenuItem("List from here")) {
                st.top = in.offset;
                st.have_top = true;
            }
            ImGui::EndPopup();
        }
        ImGui::PopID();

        // Address (dim when the offset is outside the map: it is the file offset then).
        const std::string addr = fmt_hex(in.address, addr_digits);
        const float ty = y + (row_h - font_size) * 0.5f;
        dl->AddText(font, font_size, ImVec2(addr_x, ty), in.mapped ? normal : dim, addr.c_str());
        if (show_bytes) {
            std::string b;
            const size_t n = in.length > shown_bytes ? shown_bytes - 1 : in.length;  // room for ".."
            for (size_t k = 0; k < n; ++k) {
                if (k) b += ' ';
                b += fmt_hex(in.bytes[k], 2);
            }
            if (in.length > shown_bytes) b += " ..";
            if (!in.readable) b = "??";
            dl->AddText(font, font_size, ImVec2(bytes_x, ty), dim, b.c_str());
        }
        // Instruction: mnemonic in its flow color, operands, then the comment (symbol / RIP address /
        // target section).
        const std::string& t = in.text;
        const size_t comment = plain_len(in);
        size_t sp = t.find(' ');
        if (sp == std::string::npos || sp > comment) sp = comment;
        float x = text_x;
        const ImVec4 clip(text_x, y, origin.x + avail.x, y + row_h);
        auto put = [&](const char* b, const char* e, ImU32 col) {
            dl->AddText(font, font_size, ImVec2(x, ty), col, b, e, 0.0f, &clip);
            x += float(e - b) * char_w;
        };
        put(t.data(), t.data() + sp, flow_color(in));
        put(t.data() + sp, t.data() + comment, in.valid ? normal : dim);
        bool is_sym = false;
        const std::string c = insn_comment(st, in, &is_sym);
        put(c.data(), c.data() + c.size(), is_sym ? kSymbolColor : dim);
    }
    ImGui::PopStyleVar();
    ImGui::EndChild();

    // The current instruction (hovered row, else the caret's) for the hex view layer.
    const int cur = hovered >= 0 ? hovered : current;
    const uint64_t loff = cur >= 0 ? st.insns[size_t(cur)].offset : UINT64_MAX;
    const uint64_t llen = cur >= 0 ? st.insns[size_t(cur)].length : 0;
    if (loff != st.layer_off || llen != st.layer_len) {
        st.layer_off = loff;
        st.layer_len = llen;
        st.layer.clear();
        if (cur >= 0) st.layer.add({loff, llen, kCurrentTint, st.insns[size_t(cur)].text, -1});
        st.layer.finalize();
    }
    if (!follow_req && follow_enter && current >= 0) follow_req = &st.insns[size_t(current)];
    if (follow_req) {
        const Insn target = *follow_req;  // follow_target may re-decode st.insns
        follow_target(st, doc, target, cb);
    }
}

// ---- Go to Symbol ----------------------------------------------------------------------------------

void DisasmPanel::goto_symbol(DocState& st, const Document& doc, const Symbol& s, const DisasmPanelCallbacks& cb) {
    uint64_t off = 0;
    if (!st.map.va_to_offset(s.address, off) || off >= doc.size()) {
        if (cb.notify) cb.notify(s.label() + " (0x" + fmt_hex(s.address) + ") is not in the file");
        return;
    }
    st.top = off;  // the label on the first row
    st.have_top = true;
    st.last_caret = off;
    if (cb.jump) cb.jump(off);
    if (cb.notify) cb.notify(s.label() + " at 0x" + fmt_hex(s.address));
}

void DisasmPanel::draw_symbol_list(DocState& st, const Document& doc, const DisasmPanelCallbacks& cb) {
    const char* title = "Go to Symbol";
    // Opened once the panel was drawn two frames in a row: a docked tab that just came to the
    // front settles first (it is hidden for a frame, which would close a popup opened before).
    const int frame = ImGui::GetFrameCount();
    const bool settled = last_draw_frame_ == frame - 1;
    last_draw_frame_ = frame;
    if (open_symbols_ && settled) {
        open_symbols_ = false;
        ImGui::OpenPopup(title);
        sym_filter_.clear();
        sym_sel_ = 0;
        sym_matched_.reset();
        symbols_focus_ = true;
    }
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(std::min(640.0f * ui_scale, vp->Size.x * 0.9f), std::min(480.0f * ui_scale, vp->Size.y * 0.8f)),
                             ImGuiCond_Appearing);
    symbols_open_ = ImGui::BeginPopupModal(title, nullptr, ImGuiWindowFlags_NoSavedSettings);
    if (!symbols_open_) return;
    const SymbolTable* t = st.syms.get();
    if (symbols_focus_) {
        ImGui::SetKeyboardFocusHere();
        symbols_focus_ = false;
    }
    ImGui::SetNextItemWidth(-FLT_MIN);
    const bool edited = ImGui::InputTextWithHint("##symfilter", "filter (part of the name, any case)", &sym_filter_);
    // Matches: recomputed when the filter or the table changes (one scan over the table's lowercase
    // labels, precomputed by the SymbolJob worker: a few ms also for 1M symbols).
    if (edited || sym_matched_ != st.syms || sym_matched_filter_ != sym_filter_) {
        sym_matched_ = st.syms;
        sym_matched_filter_ = sym_filter_;
        sym_sel_ = 0;
        if (t) t->match(sym_filter_, sym_matches_);
        else sym_matches_.clear();
    }
    const int n = int(sym_matches_.size());
    bool go = false;
    int step = 0;
    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) step = 1;
    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) step = -1;
    if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) step = 10;
    if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) step = -10;
    if (step) {
        sym_sel_ += step;
        sym_scroll_ = true;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Enter, false) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false)) go = n > 0;
    sym_sel_ = std::clamp(sym_sel_, 0, std::max(n - 1, 0));
    if (!t) ImGui::TextDisabled(st.sym_job.running() ? "Reading the symbol tables..." : "No symbols");
    else if (t->symbols.empty()) ImGui::TextDisabled("No symbols (PE exports / imports, ELF symtab / PLT)");
    else ImGui::TextDisabled("%d of %zu symbols%s", n, t->symbols.size(), t->truncated ? " (truncated)" : "");
    if (t && !t->note.empty()) ImGui::TextColored(kWarnColor, "%s", t->note.c_str());

    const float foot = ImGui::GetFrameHeightWithSpacing();
    if (ImGui::BeginChild("##symlist", ImVec2(0, -foot), ImGuiChildFlags_Borders)) {
        if (mono) ImGui::PushFont(mono, 0.0f);
        const float addr_w = ImGui::CalcTextSize("0000000000000000").x;
        ImGuiListClipper clip;
        clip.Begin(n);
        if (sym_scroll_) {
            clip.IncludeItemByIndex(sym_sel_);
        }
        while (clip.Step()) {
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                const Symbol& s = t->symbols[sym_matches_[size_t(i)]];
                ImGui::PushID(i);
                const ImVec2 p = ImGui::GetCursorScreenPos();
                if (ImGui::Selectable("##s", i == sym_sel_, ImGuiSelectableFlags_AllowDoubleClick)) {
                    sym_sel_ = i;
                    go = true;
                }
                if (sym_scroll_ && i == sym_sel_) {
                    ImGui::SetScrollHereY(0.5f);
                    sym_scroll_ = false;
                }
                ImDrawList* dl = ImGui::GetWindowDrawList();
                dl->AddText(p, ImGui::GetColorU32(ImGuiCol_TextDisabled), fmt_hex(s.address, 8).c_str());
                const std::string text = s.label() + "  (" + symbol_kind_name(s.kind) + ")";
                dl->AddText(ImVec2(p.x + addr_w, p.y), s.kind == Symbol::Import ? kSymbolColor : kLabelColor,
                            text.c_str());
                ImGui::PopID();
            }
        }
        if (mono) ImGui::PopFont();
    }
    ImGui::EndChild();
    if (ImGui::Button("Go") && n > 0) go = true;
    ImGui::SameLine();
    if (ImGui::Button("Close") || ImGui::IsKeyPressed(ImGuiKey_Escape, false)) ImGui::CloseCurrentPopup();
    if (go && t && sym_sel_ < n) {
        const Symbol s = t->symbols[sym_matches_[size_t(sym_sel_)]];
        ImGui::CloseCurrentPopup();
        goto_symbol(st, doc, s, cb);
    }
    ImGui::EndPopup();
}

}  // namespace hx
