#pragma once
// Dockable panels and the status bar. Each panel is a plain function drawing one ImGui window
// from the shared App state (see ui/app_internal.h). All of them cope with "no document open"
// and with a document that is currently being saved (busy: not touched at all).
#include <cstdint>

namespace hx {

struct App;
struct Tab;
class Document;

// Debounced re-parse of the tab's document (~120 ms after generation / parser / script reload
// changed). Called every frame for the active tab, before the hex view is drawn, so the parser
// highlight layer is current. Keeps the last result per document. A parse that took longer than
// ~50 ms (or hit the field limit) is not re-run on content edits; it shows as stale until F5.
void update_structure(App& app, Tab& tab);
// Parse at offset: the Structure panel parses [base, base + length) of the tab's document (base 0
// and length UINT64_MAX = the whole file; UINT64_MAX = to EOF) and re-parses now. A non-zero base
// in Auto mode picks the detected parser (detect() only looks at the file start), so set
// view().parser first to use another one.
void set_parse_base(App& app, Tab& tab, uint64_t base, uint64_t length = UINT64_MAX);

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
void draw_status_bar(App& app);            // fixed bottom bar (call before the dockspace)

// Bookmark the selection (or the caret byte) of `d`, undoable; reports in the status bar.
void add_bookmark_here(App& app, Document& d);

}  // namespace hx
