#pragma once
// Dockable panels and the status bar. Each panel is a plain function drawing one ImGui window
// from the shared App state (see ui/app_internal.h). All of them cope with "no document open"
// and with a document that is currently being saved (busy: not touched at all).
#include <cstdint>

#include "core/nav.h"

namespace hx {

struct App;
struct Tab;
class Document;

// Debounced re-parse of the tab's document (~150 ms after generation / parser / script reload
// changed; at once after F5, a field edit or Parse at). Called every frame for the active tab,
// before the hex view is drawn, so the parser highlight layer is current. The parse runs on a
// worker (script/parse_job.h): a fast one is adopted in the frame that starts it, a slow one
// leaves the previous tree shown (greyed, "Parsing... N fields [Cancel]") until it finishes. In
// Auto mode the parser's detect() calls run first on a worker too (DetectJob, "Detecting..."
// while slow). A job whose inputs changed meanwhile is cancelled and its result dropped. Keeps
// the last result per document.
void update_structure(App& app, Tab& tab);
// Parse at offset: the Structure panel parses [base, base + length) of the tab's document (base 0
// and length UINT64_MAX = the whole file; UINT64_MAX = to EOF) and re-parses now. A non-zero base
// in Auto mode picks the detected parser (detect() only looks at the file start), so set
// view().parser first to use another one. One undo step ("Parse at 0x100"; set_parse).
void set_parse_base(App& app, Tab& tab, uint64_t base, uint64_t length = UINT64_MAX);
// Parser + Parse at range in one go (ViewState::parser / parse_base / parse_length), then
// re-parses now. `undoable`: one view undo step (Document::set_view_options); false for the
// Packets panel, whose parse follows the selected packet like a caret move.
void set_parse(App& app, Tab& tab, const std::string& parser, uint64_t base, uint64_t length, bool undoable);
// The parser alone ("" = Auto-detect) as one view undo step "Parser: <name>"; false if unchanged.
bool choose_parser(Document& d, const std::string& parser);
// Structure -> C header (script/cexport.h) of the active tab's parse tree; `field` = a struct /
// array field's index for just that subtree, -1 = the whole tree. Copy puts it on the clipboard
// (action "Structure: Copy as C Header"); Export asks for a .h file (native dialog).
void structure_copy_c_header(App& app, int field = -1);
void structure_export_c_header(App& app, int field = -1);

void draw_inspector_panel(App& app);       // "Inspector": typed values at focus_offset(), editable
void draw_structure_panel(App& app);       // "Structure": parser tree (virtualised), editable fields
void draw_console_panel(App& app);         // "Console": script output + Lua REPL input
void draw_search_results_panel(App& app);  // "Search Results": Find All hits (virtualised)
void draw_bookmarks_panel(App& app);       // "Bookmarks": name / note / offset / length / bytes, this
                                           // file or all open files; edits are undoable
void draw_strings_panel(App& app);         // "Strings": ui/panel_strings.h (click jumps)
void draw_hash_panel(App& app);            // "Hashes": ui/panel_hash.h (selection or whole file)
void draw_bitmap_panel(App& app);          // "Bitmap": ui/panel_bitmap.h (bytes as pixels, click jumps)
void draw_packets_panel(App& app);         // "Packets": ui/panel_packets.h (pcap/pcapng packet list;
                                           // a row selects the packet, "Parse with" parses it)
void draw_history_panel(App& app);         // "History": ui/panel_history.h (click a state to undo / redo to it)
void draw_xor_panel(App& app);             // "XOR Search": ui/panel_xor.h (known plaintext / key guess)
void draw_regions_panel(App& app);         // "Regions": memory map of a process document (ui/dialog_targets.h)
void draw_disasm_panel(App& app);          // "Disassembly": ui/panel_disasm.h (x86-64 listing at the caret)
// Disassembly panel actions: list from the caret and pin it there ("Disassemble at Cursor");
// jump to the PE / ELF entry point and list it ("Go to Entry Point"; status message if none).
void disasm_at_cursor(App& app);
void disasm_go_to_entry(App& app);
// Follow the branch / RIP-relative target of the instruction at the caret (as a double-click on
// its Disassembly row does; recorded in the jump history).
void disasm_follow_target(App& app);
// Shows the Disassembly panel with its "Go to Symbol" list (PE exports / imports, ELF symbols).
void disasm_go_to_symbol(App& app);
void draw_status_bar(App& app);            // fixed bottom bar (call before the dockspace)

// Bookmark the selection (or the caret byte) of `d`, undoable; reports in the status bar.
void add_bookmark_here(App& app, Document& d);
// Color choices for a bookmark whose color is `cur` (0 = default), drawn into the current popup /
// menu: preset swatches, "Default" and a custom picker. True when the user picked one: *out is
// the new color (0 = default). A drag in the custom picker reports once, when it ends.
bool bookmark_color_menu(uint32_t cur, uint32_t* out);
// Index of the bookmark under the caret / selection start of `d` (the last added wins when they
// overlap), or SIZE_MAX.
size_t bookmark_at_focus(const Document& d);
// Sets bookmark `index` of `d` to `color` as one undo step ("Edit bookmark"); reports failures.
void set_bookmark_color(App& app, Document& d, size_t index, uint32_t color);

// ---- follow pointer type (picked in the Inspector, Settings or Search > Follow Pointer Settings) ----
// The type itself is app.settings.pointer_type(): width / signedness (clicking an integer row in
// the Inspector sets them), relative, base, byte order = the Inspector's LE / BE.
//
// Decodes the pointer of `type` at `at` in the tab's document and jumps there (recorded in the
// history, reveal_range). Reports success / failure in the status bar.
bool follow_pointer_as(App& app, Tab& tab, uint64_t at, const PointerType& type);
// Width / Signed / Relative / Big endian / base editors (Search menu: in_menu = true; Settings
// window: false). Edits app.settings in place; returns true on change (caller marks settings dirty).
bool draw_pointer_settings(App& app, bool in_menu);
// The bytes the Inspector's hovered row (else its selected row) covers at its decode position, for
// HexViewConfig::mark_offset / mark_length of `t`'s view. False (0, 0) when `t` is not the active
// tab, the Inspector is hidden or the row does not decode there.
bool inspector_mark(App& app, const Tab& t, uint64_t& offset, uint64_t& length);

}  // namespace hx
