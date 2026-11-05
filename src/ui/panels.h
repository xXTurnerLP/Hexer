#pragma once
// Dockable panels and the status bar. Each panel is a plain function drawing one ImGui window
// from the shared App state (see ui/app_internal.h). All of them cope with "no document open"
// and with a document that is currently being saved (busy: not touched at all).
namespace hx {

struct App;
struct Tab;

// Debounced re-parse of the tab's document (~120 ms after generation / parser / script reload
// changed). Called every frame for the active tab, before the hex view is drawn, so the parser
// highlight layer is current. Keeps the last result per document.
void update_structure(App& app, Tab& tab);

void draw_inspector_panel(App& app);       // "Inspector": typed values at the cursor, editable
void draw_structure_panel(App& app);       // "Structure": parser tree (virtualised), editable fields
void draw_console_panel(App& app);         // "Console": script output + Lua REPL input
void draw_search_results_panel(App& app);  // "Search Results": Find All hits (virtualised)
void draw_bookmarks_panel(App& app);       // "Bookmarks": name / offset / length, undoable edits
void draw_status_bar(App& app);            // fixed bottom bar (call before the dockspace)

}  // namespace hx
