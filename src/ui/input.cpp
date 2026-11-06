// Keyboard shortcut routing, inline row editor, Ctrl+wheel steps (see ui/input.h).
#include "ui/input.h"

#include <cfloat>
#include <utility>

#include "misc/cpp/imgui_stdlib.h"

namespace hx {

namespace {

// A key that types a character when pressed without Ctrl (or with Ctrl+Alt = AltGr).
bool char_key(ImGuiKey k) {
    return (k >= ImGuiKey_0 && k <= ImGuiKey_9) || (k >= ImGuiKey_A && k <= ImGuiKey_Z) ||
           (k >= ImGuiKey_Apostrophe && k <= ImGuiKey_GraveAccent) ||
           (k >= ImGuiKey_Keypad0 && k <= ImGuiKey_KeypadEqual) || k == ImGuiKey_Space || k == ImGuiKey_Oem102;
}

}  // namespace

bool text_editing_chord(ImGuiKeyChord chord) {
    const ImGuiKey key = ImGuiKey(chord & ~ImGuiMod_Mask_);
    const bool ctrl = (chord & ImGuiMod_Ctrl) != 0, shift = (chord & ImGuiMod_Shift) != 0;
    const bool alt = (chord & ImGuiMod_Alt) != 0;
    switch (key) {
        case ImGuiKey_LeftArrow: case ImGuiKey_RightArrow: case ImGuiKey_UpArrow: case ImGuiKey_DownArrow:
        case ImGuiKey_Home: case ImGuiKey_End: case ImGuiKey_PageUp: case ImGuiKey_PageDown:
        case ImGuiKey_Insert: case ImGuiKey_Delete: case ImGuiKey_Backspace:
        case ImGuiKey_Enter: case ImGuiKey_KeypadEnter: case ImGuiKey_Escape:
            return true;                // caret moves, edits, commit / cancel (any modifier)
        case ImGuiKey_Tab:
            return !ctrl;               // Tab / Shift+Tab: next field; Ctrl+Tab switches tabs
        case ImGuiKey_Z: case ImGuiKey_Y:
            if (ctrl && !alt) return true;  // undo / redo (Ctrl+Shift+Z too)
            break;
        case ImGuiKey_A: case ImGuiKey_C: case ImGuiKey_V: case ImGuiKey_X:
            if (ctrl && !alt && !shift) return true;  // select all, clipboard
            break;
        default:
            break;
    }
    return char_key(key) && (!ctrl || alt);
}

bool global_shortcut(ImGuiKeyChord chord, bool in_text, bool repeat) {
    if (!chord) return false;
    const ImGuiInputFlags fl = ImGuiInputFlags_RouteGlobal | (repeat ? ImGuiInputFlags_Repeat : 0);
    if (!ImGui::Shortcut(chord, fl)) return false;
    return !ImGui::GetIO().WantTextInput || (in_text && !text_editing_chord(chord));
}

int wheel_steps(float& accum, float wheel) {
    if (wheel == 0.0f) return 0;
    if ((wheel > 0.0f) != (accum > 0.0f)) accum = 0.0f;  // new direction (or a fresh start)
    accum += wheel;
    // A notch is 1.0; 0.999 counts as one too (float sums of touchpad fractions).
    const int steps = int(accum + (accum > 0.0f ? 0.001f : -0.001f));
    accum -= float(steps);
    return steps;
}

void InlineEdit::begin(int r, uint64_t c, std::string text) {
    row = r;
    ctx = c;
    buf = std::move(text);
    error.clear();
    focus = true;
    start_frame = ImGui::GetFrameCount();
}

void InlineEdit::retry(const std::string& err) {
    error = err.empty() ? "invalid value" : err;
    focus = true;
    start_frame = ImGui::GetFrameCount();
}

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
    // Not focused (any more): a click elsewhere. The first frames wait for the focus request.
    if (!ImGui::IsItemActive() && ImGui::GetFrameCount() > e.start_frame + 2) return -1;
    return 0;
}

}  // namespace hx
