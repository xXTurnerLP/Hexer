#include "ui/dialog_targets.h"

#include <algorithm>
#include <cctype>
#include <cfloat>
#include <climits>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "imgui.h"
#include "misc/cpp/imgui_stdlib.h"

#include "core/document.h"
#include "core/procmem.h"
#include "core/util.h"
#include "ui/text_select.h"

namespace hx {

namespace {

const ImVec4 kWarnColor(1.0f, 0.78f, 0.35f, 1.0f);
const ImVec4 kErrColor(1.0f, 0.42f, 0.42f, 1.0f);
const ImVec4 kDimColor(0.62f, 0.62f, 0.66f, 1.0f);

std::string lower(std::string s) {
    for (char& c : s) c = char(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool contains_icase(const std::string& hay, const std::string& needle_lower) {
    return lower(hay).find(needle_lower) != std::string::npos;
}

// Addresses with as many hex digits as the address space needs (8 / 12 / 16).
std::string fmt_addr(uint64_t a, uint64_t space) {
    const int digits = space <= (1ull << 32) ? 8 : space <= (1ull << 48) ? 12 : 16;
    char buf[24];
    std::snprintf(buf, sizeof buf, "%0*llX", digits, static_cast<unsigned long long>(a));
    return buf;
}

void mono_text(ImFont* mono, const char* s) {
    if (mono) ImGui::PushFont(mono, 0.0f);
    ImGui::TextUnformatted(s);
    if (mono) ImGui::PopFont();
}

// Address digits for a module list: the document's space, or more for modules above it (the
// 64-bit ntdll / wow64*.dll of a WOW64 process).
uint64_t module_space(const std::vector<ModuleInfo>& mods, uint64_t doc_size) {
    return mods.empty() ? doc_size : std::max(doc_size, mods.back().end());
}

// Jumps to a module, or says why not (above a WOW64 process's 4 GiB document).
void jump_to_module(const ModuleInfo& m, uint64_t doc_size, const RegionsPanelCallbacks& cb) {
    if (m.base >= doc_size) {
        if (cb.notify) cb.notify(m.name + " lies outside this document's address space (a 64-bit module of a 32-bit process)");
        return;
    }
    if (cb.jump) cb.jump(m.base, std::min(m.size, doc_size - m.base));
}

// Right-aligned on the current line: "Restart as Administrator" (only when cb.restart_elevated is set).
void restart_button(const TargetsDialogCallbacks& cb, const std::string& target) {
    if (!cb.restart_elevated) return;
    const char* label = "Restart as Administrator";
    const float w = ImGui::CalcTextSize(label).x + ImGui::GetStyle().FramePadding.x * 2.0f;
    ImGui::SameLine();
    const float avail = ImGui::GetContentRegionAvail().x;
    if (avail > w) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + avail - w);
    if (ImGui::Button(label)) cb.restart_elevated(target);
    ImGui::SetItemTooltip("Keeps this session (unsaved edits included), starts Hexer with administrator rights "
                          "(Windows asks first)%s%s and closes this window.",
                          target.empty() ? "" : ", opens ", target.c_str());
}

const ImGuiTableFlags kTableFlags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                                    ImGuiTableFlags_Resizable;

}  // namespace

// ---------------------------------------------------------------------------------------------
// TargetsDialog
// ---------------------------------------------------------------------------------------------
void TargetsDialog::open_process_picker() {
    proc_open_ = proc_focus_ = true;
    procs_ = list_processes();
    proc_err_.clear();
}

void TargetsDialog::open_disk_picker() {
    disk_open_ = disk_focus_ = true;
    devs_ = list_devices();
    disk_err_.clear();
}

std::vector<const ProcessInfo*> TargetsDialog::filter_processes(const std::vector<ProcessInfo>& all,
                                                                const std::string& filter) {
    std::vector<const ProcessInfo*> out;
    std::string f = lower(filter);
    while (!f.empty() && f.back() == ' ') f.pop_back();
    while (!f.empty() && f.front() == ' ') f.erase(f.begin());
    out.reserve(all.size());
    for (const ProcessInfo& p : all) {
        if (!f.empty() && !contains_icase(p.name, f) && !contains_icase(p.path, f) &&
            std::to_string(p.pid).rfind(f, 0) != 0)
            continue;
        out.push_back(&p);
    }
    return out;
}

void TargetsDialog::draw(ImFont* mono, float ui_scale, const TargetsDialogCallbacks& cb) {
    if (proc_open_) draw_process_picker(mono, ui_scale, cb);
    if (disk_open_) draw_disk_picker(mono, ui_scale, cb);
}

void TargetsDialog::draw_process_picker(ImFont* mono, float s, const TargetsDialogCallbacks& cb) {
    ImGui::SetNextWindowSize(ImVec2(780.0f * s, 540.0f * s), ImGuiCond_FirstUseEver);
    if (proc_focus_) ImGui::SetNextWindowFocus();
    if (!ImGui::Begin("Open Process", &proc_open_)) {
        ImGui::End();
        return;
    }
    if (proc_focus_) {
        ImGui::SetKeyboardFocusHere();
        proc_focus_ = false;
    }
    const float refresh_w = ImGui::CalcTextSize("Refresh").x + ImGui::GetStyle().FramePadding.x * 2.0f;
    ImGui::SetNextItemWidth(-(refresh_w + ImGui::GetStyle().ItemSpacing.x));
    ImGui::InputTextWithHint("##filter", "Filter: name, pid or path", &process_filter);
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {
        procs_ = list_processes();
        proc_err_.clear();
    }
    ImGui::Checkbox("Writable", &process_writable);
    ImGui::SameLine();
    if (process_writable)
        ImGui::TextColored(kWarnColor, "Save writes your overwrites straight into the running process.");
    else
        ImGui::TextColored(kDimColor, "Read-only: view, search and analyse (turn read-only off later to edit and save).");

    const auto rows = filter_processes(procs_, process_filter);
    const ProcessInfo* sel = nullptr;
    for (const ProcessInfo* p : rows)
        if (p->pid == proc_sel_) sel = p;
    if (!sel && rows.size() == 1) sel = rows[0];  // Enter opens the only match

    bool open_now = false;
    const float footer = ImGui::GetFrameHeightWithSpacing() + (proc_err_.empty() ? 0.0f : ImGui::GetTextLineHeightWithSpacing() * 2.0f);
    if (ImGui::BeginTable("##procs", 4, kTableFlags, ImVec2(0.0f, -footer))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 70.0f * s);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 230.0f * s);
        ImGui::TableSetupColumn("Bits", ImGuiTableColumnFlags_WidthFixed, 40.0f * s);
        ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        ImGuiListClipper clip;
        clip.Begin(int(std::min<size_t>(rows.size(), size_t(INT_MAX))));
        while (clip.Step()) {
            for (int row = clip.DisplayStart; row < clip.DisplayEnd; ++row) {
                const ProcessInfo& p = *rows[size_t(row)];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(int(p.pid));
                const std::string pid = std::to_string(p.pid);
                if (mono) ImGui::PushFont(mono, 0.0f);
                if (ImGui::Selectable(pid.c_str(), sel == &p,
                                      ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    proc_sel_ = p.pid;
                    sel = &p;
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) open_now = true;
                }
                if (mono) ImGui::PopFont();
                ImGui::PopID();
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(p.name.c_str());
                ImGui::TableSetColumnIndex(2);
                if (p.bits) ImGui::Text("%d", p.bits);
                else ImGui::TextColored(kDimColor, "?");
                ImGui::TableSetColumnIndex(3);
                if (p.path.empty()) ImGui::TextColored(kDimColor, "(no access)");
                else ImGui::TextUnformatted(p.path.c_str());
            }
        }
        ImGui::EndTable();
    }
    if (!proc_err_.empty()) selectable_text("##proc_err", proc_err_, ImGui::GetColorU32(kErrColor));
    ImGui::BeginDisabled(!sel || !cb.open_process);
    if (ImGui::Button("Open")) open_now = true;
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (sel)
        ImGui::Text("%s (%u)%s", sel->name.c_str(), sel->pid, process_writable ? ", writable" : "");
    else
        ImGui::TextColored(kDimColor, "%zu of %zu processes", rows.size(), procs_.size());
    restart_button(cb, sel ? process_url(sel->pid) : std::string());
    if (sel && ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        (ImGui::IsKeyPressed(ImGuiKey_Enter) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter)))
        open_now = true;
    if (open_now && sel && cb.open_process) {
        std::string err;
        if (cb.open_process(sel->pid, process_writable, &err)) {
            proc_open_ = false;
            proc_err_.clear();
        } else {
            proc_err_ = err.empty() ? "Cannot open process " + std::to_string(sel->pid) : err;
        }
    }
    ImGui::End();
}

void TargetsDialog::draw_disk_picker(ImFont* mono, float s, const TargetsDialogCallbacks& cb) {
    ImGui::SetNextWindowSize(ImVec2(760.0f * s, 460.0f * s), ImGuiCond_FirstUseEver);
    if (disk_focus_) {
        ImGui::SetNextWindowFocus();
        disk_focus_ = false;
    }
    if (!ImGui::Begin("Open Disk", &disk_open_)) {
        ImGui::End();
        return;
    }
#ifdef _WIN32
    const char* rights = "Raw disk access needs administrator rights; without them the list may lack sizes and "
                         "opening fails with \"Access is denied\".";
    const char* hint = "\\\\.\\PhysicalDrive0 or \\\\.\\C:";
#else
    const char* rights = "Raw disk access needs root (or membership in the disk group); otherwise opening fails "
                         "with \"Permission denied\".";
    const char* hint = "/dev/sda or /dev/nvme0n1p1";
#endif
    ImGui::PushStyleColor(ImGuiCol_Text, kDimColor);
    ImGui::TextWrapped("%s", rights);
    ImGui::PopStyleColor();

    bool open_now = false;
    const float footer = ImGui::GetFrameHeightWithSpacing() * 3.0f +
                         (disk_err_.empty() ? 0.0f : ImGui::GetTextLineHeightWithSpacing() * 2.0f);
    if (ImGui::BeginTable("##devs", 4, kTableFlags, ImVec2(0.0f, -footer))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Device", ImGuiTableColumnFlags_WidthFixed, 200.0f * s);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 100.0f * s);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 60.0f * s);
        ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < devs_.size(); ++i) {
            const DeviceInfo& d = devs_[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(int(i));
            if (mono) ImGui::PushFont(mono, 0.0f);
            if (ImGui::Selectable(d.path.c_str(), disk_path == d.path,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                disk_path = d.path;
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) open_now = true;
            }
            if (mono) ImGui::PopFont();
            ImGui::PopID();
            ImGui::TableSetColumnIndex(1);
            if (d.size) mono_text(mono, fmt_size(d.size).c_str());
            else ImGui::TextColored(kDimColor, "?");
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(d.is_volume ? "volume" : "disk");
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(d.description.c_str());
        }
        ImGui::EndTable();
    }
    if (devs_.empty()) ImGui::TextColored(kDimColor, "No devices found (try Refresh, or type a device path below).");

    const float refresh_w = ImGui::CalcTextSize("Refresh").x + ImGui::GetStyle().FramePadding.x * 2.0f;
    ImGui::SetNextItemWidth(-(refresh_w + ImGui::GetStyle().ItemSpacing.x));
    if (ImGui::InputTextWithHint("##path", hint, &disk_path, ImGuiInputTextFlags_EnterReturnsTrue)) open_now = true;
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {
        devs_ = list_devices();
        disk_err_.clear();
    }
    ImGui::Checkbox("Writable", &disk_writable);
    ImGui::SameLine();
    if (disk_writable)
        ImGui::TextColored(kErrColor, "Danger: saving writes straight to the device and can destroy its file system.");
    else
        ImGui::TextColored(kDimColor, "Read-only (recommended).");
    if (!disk_err_.empty()) selectable_text("##disk_err", disk_err_, ImGui::GetColorU32(kErrColor));
    ImGui::BeginDisabled(disk_path.empty() || !cb.open_device);
    if (ImGui::Button("Open")) open_now = true;
    ImGui::EndDisabled();
    restart_button(cb, disk_path);
    if (open_now && !disk_path.empty() && cb.open_device) {
        std::string err;
        if (cb.open_device(disk_path, disk_writable, &err)) {
            disk_open_ = false;
            disk_err_.clear();
        } else {
            disk_err_ = err.empty() ? "Cannot open " + disk_path : err;
        }
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------------------------
// RegionsPanel
// ---------------------------------------------------------------------------------------------
bool RegionsPanel::region_matches(const MemRegion& r, const std::string& filter) {
    std::string f = lower(filter);
    while (!f.empty() && f.back() == ' ') f.pop_back();
    while (!f.empty() && f.front() == ' ') f.erase(f.begin());
    if (f.empty()) return true;
    if (contains_icase(r.name, f) || contains_icase(r.type, f) || r.prot.find(f) != std::string::npos) return true;
    std::string hex = f.rfind("0x", 0) == 0 ? f.substr(2) : f;
    if (hex.empty() || hex.find_first_not_of("0123456789abcdef") != std::string::npos) return false;
    char buf[24];
    std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(r.base));
    return std::string(buf).find(hex) != std::string::npos;
}

bool RegionsPanel::module_matches(const ModuleInfo& m, const std::string& filter) {
    std::string f = lower(filter);
    while (!f.empty() && f.back() == ' ') f.pop_back();
    while (!f.empty() && f.front() == ' ') f.erase(f.begin());
    if (f.empty()) return true;
    if (contains_icase(m.name, f) || contains_icase(m.path, f)) return true;
    std::string hex = f.rfind("0x", 0) == 0 ? f.substr(2) : f;
    if (hex.empty() || hex.find_first_not_of("0123456789abcdef") != std::string::npos) return false;
    char buf[24];
    std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(m.base));
    return std::string(buf).find(hex) != std::string::npos;
}

void RegionsPanel::forget(uint64_t doc_id) { docs_.erase(doc_id); }

RegionsPanel::DocState& RegionsPanel::state(const Document& doc) {
    auto& slot = docs_[doc.id()];
    if (!slot) slot = std::make_unique<DocState>();
    return *slot;
}

void RegionsPanel::list_modules(const Document& doc, DocState& st) {
    st.mod_error.clear();
    if (!process_modules(doc.process_id(), st.modules, &st.mod_error)) st.modules.clear();
    st.mod_listed = true;
}

void RegionsPanel::draw(Document* doc, const RegionsPanelCallbacks& cb) {
    if (!doc || doc->target() != SourceKind::Process) {
        ImGui::TextColored(kDimColor, "Memory regions are shown for process documents (File > Open Process...).");
        refresh_requested_ = false;
        return;
    }
    DocState& st = state(*doc);
    if (refresh_requested_) st.listed = st.mod_listed = false;  // each tab re-lists when shown
    refresh_requested_ = false;
    if (!doc->target_alive()) ImGui::TextColored(kErrColor, "The process has exited.");
    if (!ImGui::BeginTabBar("##regtabs")) return;
    const ImGuiTabItemFlags mod_flags = select_modules_ ? ImGuiTabItemFlags_SetSelected : 0;
    select_modules_ = false;
    if (ImGui::BeginTabItem("Regions")) {
        draw_regions(*doc, st, cb);
        ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Modules", nullptr, mod_flags)) {
        draw_modules(*doc, st, cb);
        ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
}

void RegionsPanel::draw_regions(Document& doc, DocState& st, const RegionsPanelCallbacks& cb) {
    const float s = ui_scale;
    const uint32_t pid = doc.process_id();
    const float refresh_w = ImGui::CalcTextSize("Refresh").x + ImGui::GetStyle().FramePadding.x * 2.0f;
    ImGui::SetNextItemWidth(-(refresh_w + ImGui::GetStyle().ItemSpacing.x));
    ImGui::InputTextWithHint("##filter", "Filter: module, type, rwx or address", &st.filter);
    ImGui::SameLine();
    const bool refresh = ImGui::Button("Refresh");
    if (refresh || !st.listed) {
        st.error.clear();
        if (!process_regions(pid, st.regions, &st.error)) st.regions.clear();
        st.listed = true;
        if (refresh && !doc.busy()) doc.refresh_target();  // also show the current bytes
        if (refresh && cb.notify) cb.notify(std::to_string(st.regions.size()) + " regions");
    }
    if (!st.error.empty()) ImGui::TextColored(kErrColor, "%s", st.error.c_str());

    std::vector<size_t> rows;
    rows.reserve(st.regions.size());
    uint64_t total = 0;
    for (size_t i = 0; i < st.regions.size(); ++i)
        if (region_matches(st.regions[i], st.filter)) {
            rows.push_back(i);
            total += st.regions[i].size;
        }
    ImGui::TextColored(kDimColor, "%zu regions, %s committed", rows.size(), fmt_size(total).c_str());

    const uint64_t caret = doc.view().cursor;
    const uint64_t space = doc.size();
    if (!ImGui::BeginTable("##regions", 5, kTableFlags)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 120.0f * s);
    ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f * s);
    ImGui::TableSetupColumn("Prot", ImGuiTableColumnFlags_WidthFixed, 45.0f * s);
    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 60.0f * s);
    ImGui::TableSetupColumn("Module / mapping", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    ImGuiListClipper clip;
    clip.Begin(int(std::min<size_t>(rows.size(), size_t(INT_MAX))));
    while (clip.Step()) {
        for (int row = clip.DisplayStart; row < clip.DisplayEnd; ++row) {
            const MemRegion& r = st.regions[rows[size_t(row)]];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(row);
            const bool here = caret >= r.base && caret < r.end();
            const std::string base = fmt_addr(r.base, space);
            if (mono) ImGui::PushFont(mono, 0.0f);
            if (ImGui::Selectable(base.c_str(), here, ImGuiSelectableFlags_SpanAllColumns) && cb.jump)
                cb.jump(r.base, r.size);
            if (mono) ImGui::PopFont();
            ImGui::PopID();
            const ImVec4 col = r.readable ? ImGui::GetStyleColorVec4(ImGuiCol_Text) : kDimColor;
            ImGui::TableSetColumnIndex(1);
            ImGui::PushStyleColor(ImGuiCol_Text, col);
            mono_text(mono, fmt_size(r.size).c_str());
            ImGui::TableSetColumnIndex(2);
            mono_text(mono, r.prot.c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(r.type.c_str());
            ImGui::TableSetColumnIndex(4);
            ImGui::TextUnformatted(r.name.c_str());
            ImGui::PopStyleColor();
        }
    }
    ImGui::EndTable();
}

void RegionsPanel::draw_modules(Document& doc, DocState& st, const RegionsPanelCallbacks& cb) {
    const float s = ui_scale;
    const float refresh_w = ImGui::CalcTextSize("Refresh").x + ImGui::GetStyle().FramePadding.x * 2.0f;
    ImGui::SetNextItemWidth(-(refresh_w + ImGui::GetStyle().ItemSpacing.x));
    ImGui::InputTextWithHint("##modfilter", "Filter: name, path or address", &st.mod_filter);
    ImGui::SameLine();
    const bool refresh = ImGui::Button("Refresh##mods");
    if (refresh || !st.mod_listed) {
        list_modules(doc, st);
        if (refresh && cb.notify) cb.notify(std::to_string(st.modules.size()) + " modules");
    }
    if (!st.mod_error.empty()) ImGui::TextColored(kErrColor, "%s", st.mod_error.c_str());

    std::vector<size_t> rows;
    rows.reserve(st.modules.size());
    for (size_t i = 0; i < st.modules.size(); ++i)
        if (module_matches(st.modules[i], st.mod_filter)) rows.push_back(i);
    ImGui::TextColored(kDimColor, "%zu of %zu modules (palette: Go to Module...)", rows.size(), st.modules.size());

    const uint64_t caret = doc.view().cursor;
    const uint64_t space = module_space(st.modules, doc.size());
    if (!ImGui::BeginTable("##modules", 4, kTableFlags)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 120.0f * s);
    ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f * s);
    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 180.0f * s);
    ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    ImGuiListClipper clip;
    clip.Begin(int(std::min<size_t>(rows.size(), size_t(INT_MAX))));
    while (clip.Step()) {
        for (int row = clip.DisplayStart; row < clip.DisplayEnd; ++row) {
            const ModuleInfo& m = st.modules[rows[size_t(row)]];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(row);
            const bool here = caret >= m.base && caret - m.base < m.size;
            const std::string base = fmt_addr(m.base, space);
            if (mono) ImGui::PushFont(mono, 0.0f);
            const bool reachable = m.base < doc.size();
            if (!reachable) ImGui::PushStyleColor(ImGuiCol_Text, kDimColor);
            if (ImGui::Selectable(base.c_str(), here, ImGuiSelectableFlags_SpanAllColumns))
                jump_to_module(m, doc.size(), cb);
            if (mono) ImGui::PopFont();
            ImGui::PopID();
            ImGui::TableSetColumnIndex(1);
            mono_text(mono, fmt_size(m.size).c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(m.name.c_str());
            if (!reachable) ImGui::PopStyleColor();
            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(kDimColor, "%s", m.path.c_str());
        }
    }
    ImGui::EndTable();
}

void RegionsPanel::draw_module_list(Document* doc, const RegionsPanelCallbacks& cb) {
    const char* title = "Go to Module";
    const bool is_proc = doc && doc->target() == SourceKind::Process;
    if (open_modules_) {
        open_modules_ = false;
        if (is_proc) {
            ImGui::OpenPopup(title);
            list_modules(*doc, state(*doc));  // fresh: modules come and go
            pick_filter_.clear();
            pick_sel_ = 0;
            modules_focus_ = true;
        }
    }
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(std::min(640.0f * ui_scale, vp->Size.x * 0.9f),
                                    std::min(480.0f * ui_scale, vp->Size.y * 0.8f)),
                             ImGuiCond_Appearing);
    modules_open_ = ImGui::BeginPopupModal(title, nullptr, ImGuiWindowFlags_NoSavedSettings);
    if (!modules_open_) return;
    if (!is_proc) {  // the active tab changed under the popup
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    DocState& st = state(*doc);
    if (modules_focus_) {
        ImGui::SetKeyboardFocusHere();
        modules_focus_ = false;
    }
    ImGui::SetNextItemWidth(-FLT_MIN);
    if (ImGui::InputTextWithHint("##modpick", "filter: name, path or address", &pick_filter_)) pick_sel_ = 0;
    std::vector<size_t> rows;
    for (size_t i = 0; i < st.modules.size(); ++i)
        if (module_matches(st.modules[i], pick_filter_)) rows.push_back(i);
    const int n = int(std::min<size_t>(rows.size(), size_t(INT_MAX)));
    int step = 0;
    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) step = 1;
    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) step = -1;
    if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) step = 10;
    if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) step = -10;
    if (step) {
        pick_sel_ += step;
        modules_scroll_ = true;
    }
    pick_sel_ = std::clamp(pick_sel_, 0, std::max(n - 1, 0));
    bool go = (ImGui::IsKeyPressed(ImGuiKey_Enter, false) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false)) && n > 0;
    if (!st.mod_error.empty()) ImGui::TextColored(kErrColor, "%s", st.mod_error.c_str());
    else ImGui::TextDisabled("%d of %zu modules", n, st.modules.size());

    const float foot = ImGui::GetFrameHeightWithSpacing();
    const uint64_t space = module_space(st.modules, doc->size());
    if (ImGui::BeginChild("##modlist", ImVec2(0, -foot), ImGuiChildFlags_Borders)) {
        if (mono) ImGui::PushFont(mono, 0.0f);
        const float addr_w = ImGui::CalcTextSize((fmt_addr(0, space) + "  ").c_str()).x;
        if (mono) ImGui::PopFont();
        ImGuiListClipper clip;
        clip.Begin(n);
        if (modules_scroll_) clip.IncludeItemByIndex(pick_sel_);
        while (clip.Step()) {
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                const ModuleInfo& m = st.modules[rows[size_t(i)]];
                ImGui::PushID(i);
                const ImVec2 p = ImGui::GetCursorScreenPos();
                if (ImGui::Selectable("##m", i == pick_sel_)) {
                    pick_sel_ = i;
                    go = true;
                }
                if (ImGui::IsItemHovered() && !m.path.empty()) ImGui::SetItemTooltip("%s", m.path.c_str());
                if (modules_scroll_ && i == pick_sel_) {
                    ImGui::SetScrollHereY(0.5f);
                    modules_scroll_ = false;
                }
                ImDrawList* dl = ImGui::GetWindowDrawList();
                const std::string addr = fmt_addr(m.base, space);
                if (mono) ImGui::PushFont(mono, 0.0f);
                dl->AddText(p, ImGui::GetColorU32(ImGuiCol_TextDisabled), addr.c_str());
                if (mono) ImGui::PopFont();
                const std::string text = m.name + "  (" + fmt_size(m.size) + ")";
                dl->AddText(ImVec2(p.x + addr_w, p.y),
                            m.base < doc->size() ? ImGui::GetColorU32(ImGuiCol_Text) : ImGui::GetColorU32(kDimColor),
                            text.c_str());
                ImGui::PopID();
            }
        }
    }
    ImGui::EndChild();
    if (ImGui::Button("Go") && n > 0) go = true;
    ImGui::SameLine();
    if (ImGui::Button("Close") || ImGui::IsKeyPressed(ImGuiKey_Escape, false)) ImGui::CloseCurrentPopup();
    if (go && pick_sel_ < n) {
        const ModuleInfo m = st.modules[rows[size_t(pick_sel_)]];
        ImGui::CloseCurrentPopup();
        const bool reachable = m.base < doc->size();
        jump_to_module(m, doc->size(), cb);
        if (reachable && cb.notify) cb.notify(m.name + " at 0x" + fmt_addr(m.base, space));
    }
    ImGui::EndPopup();
}

}  // namespace hx
