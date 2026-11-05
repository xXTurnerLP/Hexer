#include "ui/dialog_cstruct.h"

#include <cfloat>
#include <string>

#include "imgui.h"
#include "misc/cpp/imgui_stdlib.h"

#include "core/os_file.h"

namespace hx {

namespace {

const ImVec4 kErrColor(1.0f, 0.42f, 0.42f, 1.0f);
const ImVec4 kOkColor(0.60f, 0.90f, 0.65f, 1.0f);
const char* const kPopOverwrite = "Overwrite parser?##cstruct";

const char* const kExample =
    "// Paste C struct definitions. The last struct is the root (or pick one above).\n"
    "// Array sizes may use #defines, enum constants or earlier fields: uint8_t data[len];\n"
    "// Put // @be (or // @le) before a struct to override the endianness.\n"
    "#define NAME_LEN 8\n"
    "\n"
    "enum MsgType : uint8_t { HELLO = 1, DATA = 2, BYE = 3 };\n"
    "\n"
    "struct Header {\n"
    "    char     magic[4];\n"
    "    uint8_t  version : 4;\n"
    "    uint8_t  flags   : 4;\n"
    "    enum MsgType type;\n"
    "    uint16_t length;\n"
    "};\n"
    "\n"
    "struct Packet {\n"
    "    struct Header hdr;\n"
    "    char     name[NAME_LEN];\n"
    "    uint16_t count;\n"
    "    uint32_t values[count];\n"
    "};\n";

struct PackChoice {
    const char* label;
    int pack;
};
const PackChoice kPacks[] = {
    {"Packed (1)", 1}, {"Max 2", 2}, {"Max 4", 4}, {"Max 8", 8}, {"Natural alignment", 0},
};

}  // namespace

CStructDialog::CStructDialog() : source(kExample) {}

void CStructDialog::open() {
    open_ = true;
    focus_ = true;
}

void CStructDialog::regenerate() {
    dirty_ = false;
    error_.clear();
    if (!cstruct_to_lua(source, options, lua_, &error_, &info_)) lua_.clear();
}

std::string CStructDialog::script_path(const std::string& dir, const std::string& parser_name) {
    std::string f;
    for (char c : parser_name) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
                  c == '_' || c == '.';
        f += ok ? c : '_';
    }
    while (!f.empty() && f.front() == '.') f.erase(0, 1);  // no hidden / "../" names
    if (f.empty()) f = "c_struct";
    return path_join(dir, f + ".lua");
}

void CStructDialog::do_save(const std::string& path, const CStructDialogCallbacks& cb) {
    std::string err;
    bool ok;
    if (cb.save) {
        ok = cb.save(path, lua_, &err);
    } else {
        os_mkdirs(path_dirname(path));
        ok = os_write_whole_atomic(path, lua_.data(), lua_.size(), &err);
    }
    message_is_error_ = !ok;
    message_ = ok ? "Saved " + path : "Cannot save " + path + (err.empty() ? "" : ": " + err);
    if (ok && cb.status) cb.status("Saved parser '" + options.name + "' to " + path);
}

void CStructDialog::draw(const char* title, ImFont* mono, float ui_scale, const CStructDialogCallbacks& cb) {
    if (!open_) return;
    if (focus_) {
        ImGui::SetNextWindowFocus();
        focus_ = false;
    }
    ImGui::SetNextWindowSize(ImVec2(980.0f * ui_scale, 600.0f * ui_scale), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &open_)) {
        ImGui::End();
        return;
    }
    if (dirty_) regenerate();

    // ---- options (labels in front of their widgets) ---------------------------------------------
    auto label = [](const char* text) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted(text);
        ImGui::SameLine();
    };
    label("Parser name");
    ImGui::SetNextItemWidth(180.0f * ui_scale);
    if (ImGui::InputText("##name", &options.name)) dirty_ = true;
    ImGui::SameLine(0.0f, ImGui::GetStyle().ItemSpacing.x * 3.0f);
    label("Root");
    ImGui::SetNextItemWidth(170.0f * ui_scale);
    std::string root_label = options.root.empty() ? "Last: " + (info_.root.empty() ? std::string("-") : info_.root)
                                                  : options.root;
    if (ImGui::BeginCombo("##root", root_label.c_str())) {
        if (ImGui::Selectable("Last struct", options.root.empty())) options.root.clear(), dirty_ = true;
        for (const CStructInfo::Item& it : info_.structs) {
            std::string label = it.name + "  (" + (it.fixed ? "" : ">= ") + std::to_string(it.size) + " B)";
            if (ImGui::Selectable(label.c_str(), options.root == it.name)) options.root = it.name, dirty_ = true;
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine(0.0f, ImGui::GetStyle().ItemSpacing.x * 3.0f);
    label("Byte order");
    ImGui::SetNextItemWidth(130.0f * ui_scale);
    int endian = options.big_endian ? 1 : 0;
    if (ImGui::Combo("##endian", &endian, "Little-endian\0Big-endian\0")) {
        options.big_endian = endian == 1;
        dirty_ = true;
    }
    ImGui::SameLine(0.0f, ImGui::GetStyle().ItemSpacing.x * 3.0f);
    label("Packing");
    ImGui::SetNextItemWidth(150.0f * ui_scale);
    const char* pack_label = "Packed (1)";
    for (const PackChoice& pc : kPacks)
        if (pc.pack == options.pack) pack_label = pc.label;
    if (ImGui::BeginCombo("##packing", pack_label)) {
        for (const PackChoice& pc : kPacks)
            if (ImGui::Selectable(pc.label, pc.pack == options.pack)) options.pack = pc.pack, dirty_ = true;
        ImGui::EndCombo();
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Default member alignment; #pragma pack and __attribute__((packed)) override it");

    // ---- code panes ---------------------------------------------------------------------------
    // Below the panes: status line, message line, buttons (+ the table's own spacing).
    const ImGuiStyle& style = ImGui::GetStyle();
    float footer = ImGui::GetFrameHeightWithSpacing() + ImGui::GetTextLineHeightWithSpacing() * 2.0f +
                   style.ItemSpacing.y * 2.0f + style.CellPadding.y * 2.0f;
    float h = ImGui::GetContentRegionAvail().y - footer - ImGui::GetTextLineHeightWithSpacing();
    if (h < 80.0f * ui_scale) h = 80.0f * ui_scale;
    if (ImGui::BeginTable("##cstruct_panes", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableNextColumn();
        ImGui::TextUnformatted("C definitions");
        if (mono) ImGui::PushFont(mono, 0.0f);
        if (ImGui::InputTextMultiline("##c_src", &source, ImVec2(-FLT_MIN, h), ImGuiInputTextFlags_AllowTabInput))
            dirty_ = true;
        if (mono) ImGui::PopFont();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted("Generated Lua (read-only; save it to edit it as a script)");
        if (mono) ImGui::PushFont(mono, 0.0f);
        ImGui::InputTextMultiline("##lua_out", &lua_, ImVec2(-FLT_MIN, h),
                                  ImGuiInputTextFlags_ReadOnly | ImGuiInputTextFlags_WordWrap);
        if (mono) ImGui::PopFont();
        ImGui::EndTable();
    }

    // ---- status -------------------------------------------------------------------------------
    if (!error_.empty()) {
        ImGui::TextColored(kErrColor, "%s", error_.c_str());
    } else {
        std::string s = "Root: " + info_.root;
        for (const CStructInfo::Item& it : info_.structs)
            if (it.name == info_.root)
                s += it.fixed ? "  (" + std::to_string(it.size) + " bytes)"
                              : "  (variable size, at least " + std::to_string(it.size) + " bytes)";
        s += "   -   " + std::to_string(info_.structs.size()) + " struct" + (info_.structs.size() == 1 ? "" : "s");
        ImGui::TextUnformatted(s.c_str());
    }
    if (!message_.empty()) ImGui::TextColored(message_is_error_ ? kErrColor : kOkColor, "%s", message_.c_str());
    else ImGui::NewLine();

    // ---- buttons ------------------------------------------------------------------------------
    bool can = error_.empty() && !lua_.empty();
    ImGui::BeginDisabled(!can || cb.scripts_dir.empty());
    if (ImGui::Button("Save as parser...")) {
        std::string path = script_path(cb.scripts_dir, options.name);
        if (os_stat(path).exists) {
            pending_path_ = path;
            ImGui::OpenPopup(kPopOverwrite);
        } else {
            do_save(path, cb);
        }
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) && !cb.scripts_dir.empty())
        ImGui::SetTooltip("%s", script_path(cb.scripts_dir, options.name).c_str());
    ImGui::SameLine();
    ImGui::BeginDisabled(!can || !cb.apply_at_cursor);
    if (ImGui::Button("Apply at cursor")) {
        std::string err;
        bool ok = cb.apply_at_cursor(lua_, options.name, &err);
        message_is_error_ = !ok;
        message_ = ok ? "Parsed '" + options.name + "' at the cursor (see the Structure panel)"
                      : (err.empty() ? std::string("Apply failed") : err);
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Copy Lua")) ImGui::SetClipboardText(lua_.c_str());
    ImGui::SameLine();
    if (ImGui::Button("Close")) open_ = false;

    if (ImGui::BeginPopupModal(kPopOverwrite, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("%s already exists.", pending_path_.c_str());
        ImGui::TextUnformatted("Replace it with the generated parser?");
        if (ImGui::Button("Overwrite")) {
            do_save(pending_path_, cb);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            message_.clear();
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    ImGui::End();
}

}  // namespace hx
