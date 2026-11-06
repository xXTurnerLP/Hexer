#include "ui/panel_xor.h"

#include <algorithm>
#include <cfloat>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "imgui.h"
#include "misc/cpp/imgui_stdlib.h"

#include "core/document.h"
#include "core/settings.h"
#include "core/util.h"
#include "ui/hex_view.h"

namespace hx {

namespace {

const ImVec4 kWarnColor(1.0f, 0.78f, 0.35f, 1.0f);
const ImVec4 kErrColor(1.0f, 0.42f, 0.42f, 1.0f);
constexpr size_t kHitPreview = 32;     // decoded bytes shown per hit
constexpr size_t kGuessPreview = 64;   // decoded bytes shown per key candidate
constexpr size_t kMaxGuesses = 16;
constexpr size_t kMaxPlaintext = 4096;

struct Preset {
    const char* label;
    const char* text;  // text-mode input (C escapes)
};
const Preset kPresets[] = {
    {"MZ (DOS/PE header)", "MZ"},
    {"PE\\0\\0 (PE signature)", "PE\\0\\0"},
    {"http", "http"},
    {"This program (DOS stub)", "This program"},
    {"\\x89PNG (PNG signature)", "\\x89PNG"},
};

std::string fmt_off(uint64_t v) { return "0x" + fmt_hex(v, 8); }

std::string fmt_count(uint64_t v) {
    std::string s = std::to_string(v);
    for (int i = int(s.size()) - 3; i > 0; i -= 3) s.insert(size_t(i), ",");
    return s;
}

// Printable ASCII as is, everything else as '.'.
std::string printable(const std::vector<uint8_t>& b) {
    std::string s;
    s.reserve(b.size());
    for (uint8_t c : b) s.push_back(c >= 0x20 && c < 0x7F ? char(c) : '.');
    return s;
}

// Bytes -> text-mode input (the inverse of parse_plaintext(.., false, ..)).
std::string escape_plaintext(const std::vector<uint8_t>& b) {
    std::string s;
    for (uint8_t c : b) {
        if (c == '\\') s += "\\\\";
        else if (c == 0) s += "\\0";
        else if (c >= 0x20 && c < 0x7F) s.push_back(char(c));
        else s += "\\x" + fmt_hex(c, 2);
    }
    return s;
}

std::string key_hex(const std::vector<uint8_t>& key) { return copy_as(key.data(), key.size(), CopyFormat::HexSpaced); }

}  // namespace

struct XorPanel::DocState {
    XorScanJob job;
    uint64_t seen_gen = 0;         // job generation already picked up
    uint64_t pending_doc_gen = 0;  // document generation when the running scan started
    std::shared_ptr<const XorScanJob::Result> res;
    uint64_t res_doc_gen = 0;
    size_t selected = SIZE_MAX;    // index into res->scan.hits

    // The key "Decode selection" applies (from a hit or a guess).
    bool have_key = false;
    XorTransform key_t = XorTransform::Xor;
    std::vector<uint8_t> key;

    // Key guess of the selection.
    bool guessed = false;
    std::vector<KeyCandidate> guesses;
    std::vector<uint8_t> guess_head;  // first kGuessPreview bytes of the guessed range
    uint64_t guess_begin = 0, guess_len = 0, guess_doc_gen = 0;
    bool guess_add = false;           // the candidates are ADD keys
    size_t guess_selected = SIZE_MAX;
};

XorPanel::XorPanel() = default;
XorPanel::~XorPanel() = default;

void XorPanel::load_settings(const Settings& s) {
    options.xor8 = s.xor_xor;
    options.add8 = s.xor_add;
    options.rol = s.xor_rol;
    options.xor_multi = s.xor_key;
    options.add_multi = s.xor_add_key;
    options.max_key_len = uint32_t(std::clamp(s.xor_max_key_len, 2, int(kXorMaxKeyLen)));
}

bool XorPanel::save_settings(Settings& s) const {
    const int len = int(std::clamp<uint32_t>(options.max_key_len, 2, kXorMaxKeyLen));
    if (s.xor_xor == options.xor8 && s.xor_add == options.add8 && s.xor_rol == options.rol &&
        s.xor_key == options.xor_multi && s.xor_add_key == options.add_multi && s.xor_max_key_len == len)
        return false;
    s.xor_xor = options.xor8;
    s.xor_add = options.add8;
    s.xor_rol = options.rol;
    s.xor_key = options.xor_multi;
    s.xor_add_key = options.add_multi;
    s.xor_max_key_len = len;
    return true;
}

XorPanel::DocState& XorPanel::state(uint64_t doc_id) {
    auto& p = docs_[doc_id];
    if (!p) p = std::make_unique<DocState>();
    return *p;
}

void XorPanel::forget(uint64_t doc_id) {
    auto it = docs_.find(doc_id);
    if (it == docs_.end()) return;
    it->second->job.cancel();
    docs_.erase(it);  // the job's destructor joins its worker (it stops at the next block)
}

void XorPanel::draw(Document* doc, const XorPanelCallbacks& cb) {
    wants_frames_ = false;
    if (!doc) {
        scan_requested_ = guess_requested_ = false;
        ImGui::TextDisabled("No document open.");
        return;
    }
    DocState& st = state(doc->id());

    // ---- pick up a finished scan ----
    if (st.job.generation() != st.seen_gen) {
        st.seen_gen = st.job.generation();
        st.res = st.job.result();
        st.res_doc_gen = st.pending_doc_gen;
        st.selected = SIZE_MAX;
        if (st.res && cb.notify) {
            const auto& sc = st.res->scan;
            std::string msg = "XOR scan: " + fmt_count(sc.hits.size()) + (sc.truncated ? "+" : "") +
                              (sc.hits.size() == 1 ? " match" : " matches");
            if (sc.cancelled) msg += " (cancelled)";
            if (sc.io_error) msg += " (read error at " + fmt_off(sc.io_error_offset) + ")";
            if (sc.skipped) msg += " (" + fmt_size(sc.skipped) + " unreadable skipped)";
            cb.notify(msg);
        }
    }

    // ---- chosen key + apply ----
    const ViewState& v = doc->view();
    const bool sel_ok = v.has_selection();
    if (st.have_key) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted("Key:");
        ImGui::SameLine();
        if (mono) ImGui::PushFont(mono, 0.0f);
        ImGui::TextUnformatted(describe_key(st.key_t, st.key).c_str());
        if (mono) ImGui::PopFont();
        ImGui::SameLine();
        ImGui::BeginDisabled(!sel_ok || doc->busy() || doc->read_only());
        if (ImGui::Button("Decode selection")) {
            const uint64_t phase = v.sel_begin() % st.key.size();  // 1-byte keys: always 0
            if (cb.apply) {
                cb.apply(st.key_t, st.key, phase);
            } else {
                std::string err;
                const bool ok = apply_transform(*doc, v.sel_begin(), v.sel_len(), st.key_t, st.key, phase, true, &err);
                if (cb.notify) cb.notify(ok ? "Decoded " + fmt_size(v.sel_len()) + " with " + describe_key(st.key_t, st.key)
                                            : "Decode failed: " + err);
            }
        }
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
            if (!sel_ok) ImGui::SetTooltip("Select the bytes to decode in the hex view first");
            else if (doc->read_only()) ImGui::SetTooltip("The document is read-only");
            else ImGui::SetTooltip("Decode the %s selection with this key (one undo step)", fmt_size(v.sel_len()).c_str());
        }
    } else {
        ImGui::TextDisabled("Pick a match or a guessed key to decode the selection with it.");
    }

    if (ImGui::BeginTabBar("##xortabs")) {
        // A palette request shows its tab (it runs once that tab draws).
        const ImGuiTabItemFlags sf = scan_requested_ ? int(ImGuiTabItemFlags_SetSelected) : 0;
        if (ImGui::BeginTabItem("Known plaintext", nullptr, sf)) {
            draw_scan_tab(*doc, st, cb);
            ImGui::EndTabItem();
        }
        const ImGuiTabItemFlags gf = guess_requested_ && !scan_requested_ ? int(ImGuiTabItemFlags_SetSelected) : 0;
        if (ImGui::BeginTabItem("Guess key", nullptr, gf)) {
            draw_guess_tab(*doc, st, cb);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

void XorPanel::draw_scan_tab(Document& doc, DocState& st, const XorPanelCallbacks& cb) {
    const float s = ui_scale;
    const ViewState& v = doc.view();
    const bool sel_ok = v.has_selection();
    const bool use_sel = selection_only && sel_ok;

    // ---- plaintext ----
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Plaintext");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-150.0f * s);
    if (mono) ImGui::PushFont(mono, 0.0f);
    ImGui::InputTextWithHint("##plain", plaintext_hex ? "4D 5A 90 00" : "text, \\0 \\xHH escapes", &plaintext);
    if (mono) ImGui::PopFont();
    ImGui::SameLine();
    bool hex = plaintext_hex;
    if (ImGui::Checkbox("Hex", &hex)) {
        std::vector<uint8_t> b;
        if (parse_plaintext(plaintext, plaintext_hex, b))  // convert the input when it parses
            plaintext = hex ? key_hex(b) : escape_plaintext(b);
        plaintext_hex = hex;
    }
    ImGui::SameLine();
    if (ImGui::Button("Presets")) ImGui::OpenPopup("##presets");
    if (ImGui::BeginPopup("##presets")) {
        for (const Preset& p : kPresets) {
            if (ImGui::MenuItem(p.label)) {
                plaintext = p.text;
                plaintext_hex = false;
            }
        }
        ImGui::EndPopup();
    }

    std::vector<uint8_t> plain;
    std::string perr;
    bool plain_ok = parse_plaintext(plaintext, plaintext_hex, plain, &perr);
    if (plain_ok && plain.size() < 2) {
        plain_ok = false;
        perr = "enter at least 2 bytes";
    } else if (plain_ok && plain.size() > kMaxPlaintext) {
        plain_ok = false;
        perr = "at most " + std::to_string(kMaxPlaintext) + " bytes";
    }

    // ---- transforms ----
    ImGui::Checkbox("XOR", &options.xor8);
    ImGui::SameLine();
    ImGui::Checkbox("ADD/SUB", &options.add8);
    ImGui::SameLine();
    ImGui::Checkbox("ROL/ROR", &options.rol);
    ImGui::SameLine();
    ImGui::Checkbox("XOR key", &options.xor_multi);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Multi-byte XOR keys of 2..%u bytes; a key of length L needs at least 2*L and L+4 plaintext bytes",
                          unsigned(options.max_key_len));
    ImGui::SameLine();
    ImGui::Checkbox("ADD key", &options.add_multi);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Multi-byte ADD keys of 2..%u bytes (byte + key byte, mod 256); a key of length L needs at "
                          "least 2*L and L+4 plaintext bytes",
                          unsigned(options.max_key_len));
    if (options.xor_multi || options.add_multi) {
        ImGui::SameLine();
        int ml = int(options.max_key_len);
        ImGui::SetNextItemWidth(80.0f * s);
        if (ImGui::SliderInt("max len", &ml, 2, int(kXorMaxKeyLen))) options.max_key_len = uint32_t(std::clamp(ml, 2, int(kXorMaxKeyLen)));
    }
    const bool any_t = options.xor8 || options.add8 || options.rol || options.xor_multi || options.add_multi;

    // ---- scan controls ----
    const bool running = st.job.running();
    const bool can_scan = !doc.busy() && any_t && plain_ok;
    ImGui::BeginDisabled(!can_scan);
    const bool requested = scan_requested_ && can_scan;
    if (ImGui::Button(running ? "Rescan###scan" : "Scan###scan") || requested) {
        const uint64_t b = use_sel ? v.sel_begin() : 0;
        const uint64_t e = use_sel ? v.sel_end() : UINT64_MAX;
        st.pending_doc_gen = doc.generation();
        st.job.start(doc.snapshot(), b, e, plain, options);
    }
    ImGui::EndDisabled();
    if (scan_requested_ && !can_scan && cb.notify)
        cb.notify(plain_ok ? std::string("XOR scan: nothing to do") : "XOR scan: plaintext " + perr);
    scan_requested_ = false;
    if (doc.busy() && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Document is being saved...");
    ImGui::SameLine();
    if (ImGui::RadioButton("Whole file", !use_sel)) selection_only = false;
    ImGui::SameLine();
    ImGui::BeginDisabled(!sel_ok);
    if (ImGui::RadioButton("Selection", use_sel)) selection_only = true;
    ImGui::EndDisabled();
    if (!plain_ok) {
        ImGui::SameLine();
        ImGui::TextColored(kErrColor, "Plaintext: %s", perr.c_str());
    } else if (plain.size() < 4) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "short plaintext: expect random matches");
    }

    if (running) {
        wants_frames_ = true;
        char pct[32];
        std::snprintf(pct, sizeof pct, "Scanning %.0f%%", st.job.progress() * 100.0);
        ImGui::ProgressBar(float(st.job.progress()), ImVec2(-80.0f * s, 0.0f), pct);
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) st.job.cancel();
    }

    if (!st.res) {
        if (!running) ImGui::TextDisabled("Enter a plaintext you expect in the file and press Scan.");
        return;
    }
    const XorScanJob::Result& res = *st.res;
    const auto& sc = res.scan;
    const std::vector<XorHit>& hits = sc.hits;

    // ---- summary ----
    std::string line = fmt_count(hits.size()) + (sc.truncated ? "+" : "") +
                       (hits.size() == 1 ? " match" : " matches") + " of \"" + escape_plaintext(res.plaintext) + "\"";
    if (sc.begin != 0 || sc.end != res.snap->size()) line += " in " + fmt_range(sc.begin, sc.end - sc.begin);
    ImGui::TextUnformatted(line.c_str());
    if (sc.truncated) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(stopped at %s)", fmt_count(res.options.max_results).c_str());
    }
    if (sc.cancelled) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(cancelled)");
    }
    if (sc.io_error) {
        ImGui::SameLine();
        ImGui::TextColored(kErrColor, "(read error at %s)", fmt_off(sc.io_error_offset).c_str());
    }
    if (sc.skipped) {  // holes of process memory: not errors
        ImGui::SameLine();
        ImGui::TextDisabled("(%s unreadable skipped)", fmt_size(sc.skipped).c_str());
    }
    if (st.res_doc_gen != doc.generation()) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(document changed since the scan)");
    }

    // ---- table ----
    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_Resizable;
    if (!ImGui::BeginTable("##xorhits", 4, flags)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 130.0f * s);
    ImGui::TableSetupColumn("Transform", ImGuiTableColumnFlags_WidthFixed, 80.0f * s);
    ImGui::TableSetupColumn("Key", ImGuiTableColumnFlags_WidthFixed, 200.0f * s);
    ImGui::TableSetupColumn("Decoded", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    ImGuiListClipper clip;
    clip.Begin(int(std::min<size_t>(hits.size(), size_t(INT_MAX))));
    std::vector<uint8_t> buf;
    while (clip.Step()) {
        for (int row = clip.DisplayStart; row < clip.DisplayEnd; ++row) {
            const size_t i = size_t(row);
            const XorHit& h = hits[i];
            const std::string key = describe_key(h.transform, h.key);
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(row);
            if (mono) ImGui::PushFont(mono, 0.0f);
            const std::string off = fmt_off(h.offset);
            if (ImGui::Selectable(off.c_str(), st.selected == i, ImGuiSelectableFlags_SpanAllColumns)) {
                st.selected = i;
                st.have_key = true;
                st.key_t = h.transform;
                st.key = h.key;
                if (cb.jump) cb.jump(h.offset, sc.plaintext_len);
            }
            if (mono) ImGui::PopFont();
            if (ImGui::BeginPopupContextItem("##ctx")) {
                st.selected = i;
                auto copy = [&cb](const std::string& t) {
                    if (cb.copy) cb.copy(t);
                    else ImGui::SetClipboardText(t.c_str());
                };
                if (ImGui::MenuItem("Copy offset")) copy(off);
                if (ImGui::MenuItem("Copy key (hex)")) copy(key_hex(h.key));
                if (ImGui::MenuItem("Copy description")) copy(off + "  " + key);
                ImGui::EndPopup();
            }
            ImGui::PopID();
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(transform_name(h.transform));
            ImGui::TableSetColumnIndex(2);
            if (mono) ImGui::PushFont(mono, 0.0f);
            ImGui::TextUnformatted(key.c_str() + std::string(transform_name(h.transform)).size() + 1);
            ImGui::TableSetColumnIndex(3);
            buf.assign(kHitPreview, 0);
            buf.resize(res.snap->read(h.offset, buf.data(), buf.size()));
            apply_transform(buf.data(), buf.size(), h.transform, h.key, h.offset, true);
            ImGui::TextUnformatted(printable(buf).c_str());
            if (mono) ImGui::PopFont();
        }
    }
    ImGui::EndTable();
}

void XorPanel::draw_guess_tab(Document& doc, DocState& st, const XorPanelCallbacks& cb) {
    const float s = ui_scale;
    const ViewState& v = doc.view();
    const bool sel_ok = v.has_selection();
    ImGui::BeginDisabled(!sel_ok);
    const bool requested = guess_requested_ && sel_ok;
    if (ImGui::Button("Guess key from selection") || requested) {
        const uint64_t len = std::min<uint64_t>(v.sel_len(), kGuessMax);
        std::vector<uint8_t> data(static_cast<size_t>(len));
        data.resize(doc.read(v.sel_begin(), data.data(), data.size()));
        st.guess_add = guess_add;
        st.guesses = key_guess(data.data(), data.size(), v.sel_begin(), guess_spaces ? uint8_t(' ') : uint8_t(0),
                               kXorMaxKeyLen, guess_add ? XorTransform::Add : XorTransform::Xor);
        if (st.guesses.size() > kMaxGuesses) st.guesses.resize(kMaxGuesses);
        data.resize(std::min(data.size(), kGuessPreview));
        st.guess_head = std::move(data);
        st.guess_begin = v.sel_begin();
        st.guess_len = len;
        st.guess_doc_gen = doc.generation();
        st.guess_selected = SIZE_MAX;
        st.guessed = true;
        if (cb.notify && !st.guesses.empty())
            cb.notify("Best key guess: " + describe_key(keyed_transform(st.guesses[0].key.size(), guess_add),
                                                         st.guesses[0].key));
    }
    ImGui::EndDisabled();
    if (guess_requested_ && !sel_ok && cb.notify) cb.notify("Guess key: select the obfuscated bytes first");
    guess_requested_ = false;
    if (!sel_ok && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Select the obfuscated bytes in the hex view first");
    ImGui::SameLine();
    ImGui::TextUnformatted("Plaintext mostly");
    ImGui::SameLine();
    if (ImGui::RadioButton("0x00", !guess_spaces)) guess_spaces = false;
    ImGui::SameLine();
    if (ImGui::RadioButton("spaces", guess_spaces)) guess_spaces = true;
    ImGui::SameLine();
    ImGui::TextUnformatted("  Key");
    ImGui::SameLine();
    if (ImGui::RadioButton("XOR", !guess_add)) guess_add = false;
    ImGui::SameLine();
    if (ImGui::RadioButton("ADD", guess_add)) guess_add = true;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Data obfuscated by adding a key (decoded by subtracting it)");

    if (!st.guessed) {
        ImGui::TextDisabled("Select XOR-obfuscated data (e.g. a zero-padded table or a text block)");
        ImGui::TextDisabled("and press Guess: the most common byte per key column gives the key.");
        return;
    }
    std::string line = "Candidates for " + fmt_range(st.guess_begin, st.guess_len);
    if (st.guess_len == kGuessMax) line += " (first " + fmt_size(kGuessMax) + ")";
    ImGui::TextUnformatted(line.c_str());
    if (st.guess_doc_gen != doc.generation()) {
        ImGui::SameLine();
        ImGui::TextColored(kWarnColor, "(document changed)");
    }
    if (st.guesses.empty()) {
        ImGui::TextDisabled("Selection too short (needs at least 2 bytes).");
        return;
    }
    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_Resizable;
    if (!ImGui::BeginTable("##xorguess", 4, flags)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Len", ImGuiTableColumnFlags_WidthFixed, 40.0f * s);
    ImGui::TableSetupColumn("Score", ImGuiTableColumnFlags_WidthFixed, 60.0f * s);
    ImGui::TableSetupColumn("Key", ImGuiTableColumnFlags_WidthFixed, 260.0f * s);
    ImGui::TableSetupColumn("Decoded (first 64 bytes)", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    for (size_t i = 0; i < st.guesses.size(); ++i) {
        const KeyCandidate& c = st.guesses[i];
        const XorTransform t = keyed_transform(c.key.size(), st.guess_add);
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        ImGui::PushID(int(i));
        const std::string len = std::to_string(c.key.size());
        if (ImGui::Selectable(len.c_str(), st.guess_selected == i, ImGuiSelectableFlags_SpanAllColumns)) {
            st.guess_selected = i;
            st.have_key = true;
            st.key_t = t;
            st.key = c.key;
        }
        if (ImGui::BeginPopupContextItem("##gctx")) {
            if (ImGui::MenuItem("Copy key (hex)")) {
                if (cb.copy) cb.copy(key_hex(c.key));
                else ImGui::SetClipboardText(key_hex(c.key).c_str());
            }
            ImGui::EndPopup();
        }
        ImGui::PopID();
        ImGui::TableSetColumnIndex(1);
        ImGui::Text("%.1f%%", std::max(0.0, c.score) * 100.0);
        ImGui::TableSetColumnIndex(2);
        if (mono) ImGui::PushFont(mono, 0.0f);
        const std::string d = describe_key(t, c.key);
        ImGui::TextUnformatted(d.c_str() + std::string(transform_name(t)).size() + 1);
        ImGui::TableSetColumnIndex(3);
        ImGui::TextUnformatted(printable(apply_transform(st.guess_head, t, c.key, st.guess_begin, true)).c_str());
        if (mono) ImGui::PopFont();
    }
    ImGui::EndTable();
}

}  // namespace hx
