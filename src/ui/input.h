#pragma once
// Keyboard shortcut routing, the inline (in-place) editor of panel rows and Ctrl+wheel steps.
// No App dependency: tests/test_ui.cpp drives them headlessly.
//
// Shortcut routing while a text field (an ImGui InputText) has keyboard focus -- the one policy:
//  * Text-editing chords always go to the text field (text_editing_chord()): Ctrl+Z / Ctrl+Y /
//    Ctrl+Shift+Z, Ctrl+A / Ctrl+C / Ctrl+V / Ctrl+X, Insert, Delete, Backspace, Enter, Tab /
//    Shift+Tab, Escape, the arrows, Home / End / PageUp / PageDown (with any modifier), and every
//    chord that may type a character (letters, digits, punctuation, space, keypad without Ctrl).
//  * Any other app shortcut fires while typing only when its action allows it (`in_text` in the
//    action table, ui/app.cpp): the global ones do - Ctrl+Tab / Ctrl+Shift+Tab (tabs), F3 /
//    Shift+F3 (find next / previous, also from the Find bar), Ctrl+S / Ctrl+Shift+S, Ctrl+W,
//    Ctrl+Shift+T, Ctrl+N / Ctrl+O, Ctrl+F, Ctrl+G, Ctrl+Shift+P, Ctrl+Shift+B, Ctrl+comma, F5,
//    zoom; the ones that act on the document caret / selection do not - Ctrl+B, F2 / Shift+F2,
//    Alt+Left / Alt+Right, Ctrl+Enter, Ctrl+Shift+C, Ctrl+\, F6.
// ImGui itself also hands chords an active InputText registers (Ctrl+A, Ctrl+Z...) to the field
// and drops character-typing chords; text_editing_chord() makes the policy hold regardless.
#include <cstdint>
#include <string>

#include "imgui.h"

namespace hx {

// True for a chord the focused text field needs (see above); never an app shortcut while typing.
bool text_editing_chord(ImGuiKeyChord chord);

// One app-wide shortcut: ImGui::Shortcut(chord, RouteGlobal [| Repeat]) filtered by the policy
// above (`in_text` = the action may fire while a text field has focus). Call it every frame for
// every chord (Shortcut registers the route for the next frame). 0 never fires.
bool global_shortcut(ImGuiKeyChord chord, bool in_text, bool repeat);

// Ctrl+wheel zoom: whole steps from the wheel delta of this frame. Fractional (touchpad) deltas
// accumulate in `accum`; turning the wheel the other way drops the leftover. Returns the signed
// number of steps (usually -1, 0 or +1).
int wheel_steps(float& accum, float wheel);

// In-place editor of one panel row (Inspector value, Structure field value, Bookmark name / note).
// The panels share one interaction: double-click (or the row's "Edit ..." context menu item, or
// Enter on the selected row where the panel has one) begins it with the current text all
// selected; Enter commits (one undo step - the caller applies it), Esc cancels. Clicking elsewhere
// cancels byte edits (Inspector, Structure: `commit_on_blur` false) and commits text edits
// (Bookmarks: true).
struct InlineEdit {
    int row = -1;                     // -1 = not editing
    uint64_t ctx = 0;                 // extra key (e.g. cursor offset / doc id) so edits cancel on change
    std::string buf;
    std::string error;
    int start_frame = 0;
    bool focus = false;
    bool active(int r, uint64_t c) const { return row == r && ctx == c; }
    void begin(int r, uint64_t c, std::string text);
    // Keep editing after a rejected value (`err` shown as a tooltip while the field is active).
    void retry(const std::string& err);
    void end() { row = -1; }
};

// Draws the editor (full cell width) for an active InlineEdit. Returns +1 = commit (e.buf holds
// the text), -1 = cancelled, 0 = still editing. The caller ends the edit (or retries) on != 0.
int inline_edit_input(InlineEdit& e, bool commit_on_blur);

}  // namespace hx
