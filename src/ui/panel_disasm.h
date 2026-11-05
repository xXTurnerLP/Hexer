#pragma once
// Disassembly panel: an x86-64 / x86-32 listing (core/disasm.h) of the active document with
// virtual addresses from its address map (core/exe_map.h: PE / ELF headers, a manual base, none;
// process memory: identity). Self-contained (no App dependency): the host owns one DisasmPanel and
// calls draw() inside its own Begin/End every frame with the active document and caret.
//
//   * Columns Address | Bytes | Instruction (mono font). Only the visible rows are decoded (and
//     re-decoded only when the document, the start, the options or the panel height change).
//   * "Follow cursor": when the caret moves outside the listed instructions, the listing re-anchors
//     a few rows above it (disasm_sync_back), so the caret byte starts an instruction. Off: the
//     listing stays where it is ("Disassemble at Cursor" / show_at pins it).
//   * The instruction containing the caret is the highlighted row; it (or the hovered row) is the
//     current instruction, whose bytes layer() tints in the hex view.
//   * Click a row = cb.select(its bytes); double-click or Ctrl+click a row with a target (branch,
//     RIP-relative operand) = follow it via cb.jump (a big jump: the host records it in the jump
//     history). Targets are annotated with their section, "outside image" / "outside file".
//   * Mouse wheel, Up / Down, PageUp / PageDown scroll the listing (backwards with
//     disasm_sync_back); Home re-anchors at the caret, Enter follows the caret row's target. Right-click: copy instruction / address /
//     bytes / visible listing, follow target.
//   * Toolbar: Follow cursor, mode (Auto = the header's 32 / 64, else 64-bit), address map (Auto,
//     Manual base [hex], None), Entry point, options (uppercase, bytes column, AT&T syntax).
// Per-document state (start, address map choice) is kept by Document::id(); call forget() when a
// document is closed. A busy (saving) document is not read.
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/disasm.h"
#include "core/exe_map.h"
#include "core/highlight.h"

struct ImFont;

namespace hx {

class Document;

struct DisasmPanelCallbacks {
    std::function<void(uint64_t offset, uint64_t len)> select;  // caret + selection, no history
    std::function<void(uint64_t offset)> jump;                  // big jump (history), e.g. a target
    std::function<void(const std::string& text)> copy;          // put text on the clipboard
    std::function<void(const std::string& msg)> notify;         // short status-bar message
};

enum class DisasmMapChoice : uint8_t { Auto, Manual, None };

class DisasmPanel {
public:
    DisasmPanel();
    ~DisasmPanel();
    DisasmPanel(const DisasmPanel&) = delete;
    DisasmPanel& operator=(const DisasmPanel&) = delete;

    // ---- options (shared by all documents; the host persists them) ----
    int mode = 0;                  // 0 = auto (header bits, else 64), 1 = 64-bit, 2 = 32-bit
    DisasmSyntax syntax = DisasmSyntax::Intel;
    bool uppercase = false;
    bool follow = true;            // follow the hex caret
    bool show_bytes = true;
    ImFont* mono = nullptr;        // listing font (nullptr = current)
    float ui_scale = 1.0f;

    // Draws into the current window. `doc` may be null; `caret` = focus_offset() of its view.
    void draw(Document* doc, uint64_t caret, const DisasmPanelCallbacks& cb);
    void forget(uint64_t doc_id);

    // Lists from `offset` (an instruction start). `pin`: also turns Follow cursor off
    // ("Disassemble at Cursor"). The caret at `offset` does not re-anchor the listing.
    void show_at(const Document& doc, uint64_t offset, bool pin);
    // Follows the branch / RIP-relative target of the instruction at file offset `at` (the listed
    // instruction containing it, else one decoded there), as a double-click on its row does.
    // False (+ cb.notify) when it has no target or the target is not in the file.
    bool follow_at(const Document& doc, uint64_t at, const DisasmPanelCallbacks& cb);
    // File offset of the document's entry point under its current address map (false: none).
    bool entry_offset(const Document& doc, uint64_t& off);
    // The address map the panel uses for `doc` (detected / manual / none, refreshed after edits).
    const AddressMap& address_map(const Document& doc);
    // Hex view layer with the current instruction's bytes for that document (nullptr: none).
    const HighlightSet* layer(uint64_t doc_id) const;
    // Decoding options in effect for `doc` (mode resolved from the map in Auto mode).
    DisasmOptions options_for(const Document& doc);

    // ---- for tests / automation: the last draw() of `doc_id` ----
    // The listed (visible) instructions; empty if none.
    std::vector<Insn> listing(uint64_t doc_id) const;
    // Screen position of the middle of listed row `row` (false if not drawn).
    bool row_pos(int row, float& x, float& y) const;

private:
    struct DocState;
    DocState& state(const Document& doc);
    void ensure_map(DocState& st, const Document& doc);
    void draw_toolbar(DocState& st, const Document& doc, uint64_t caret, const DisasmPanelCallbacks& cb);
    void draw_listing(DocState& st, const Document& doc, uint64_t caret, const DisasmPanelCallbacks& cb);
    bool follow_target(DocState& st, const Document& doc, const Insn& insn, const DisasmPanelCallbacks& cb);
    void scroll(DocState& st, const Document& doc, int rows);
    void anchor(DocState& st, const Document& doc, uint64_t off);  // list `off` a few rows down
    std::string target_note(const DocState& st, const Insn& insn) const;

    std::map<uint64_t, std::unique_ptr<DocState>> docs_;
    int rows_ = 24;                // visible rows of the last draw
    float rows_x_ = 0, rows_y_ = 0, row_w_ = 0, row_h_ = 0;  // row geometry of the last draw
    int drawn_rows_ = 0;
    double wheel_accum_ = 0.0;
    // A double-click followed a target (the listing moved): ignore the button release that ends it,
    // which would otherwise select whatever row is now under the mouse.
    bool swallow_release_ = false;
};

}  // namespace hx
