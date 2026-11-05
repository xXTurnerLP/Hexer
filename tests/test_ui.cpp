// Headless UI tests: a Dear ImGui context without a window or GL context drives HexView::draw()
// with simulated mouse and keyboard events, and checks the resulting selection, caret and bytes.
//
// How it works: io.DisplaySize is set by hand and the backend flag RendererHasTextures is set, so
// fonts are rasterised on demand into textures nobody uploads (no GL needed). Every input event is
// queued with io.Add*Event() and followed by one frame (the queue trickles one event per frame).
// Positions come from HexView::cell_pos(), i.e. from the layout of the previous frame, exactly
// what a user clicking on a drawn byte hits.
//
// Add a case here for every input-handling change in src/ui/hex_view.cpp.
#include <doctest/doctest.h>

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "imgui.h"

#include "core/document.h"
#include "core/entropy.h"
#include "core/highlight.h"
#include "ui/hex_view.h"
#include "ui/minimap.h"
#include "ui/theme.h"

using namespace hx;

namespace {

using Bytes = std::vector<uint8_t>;

Bytes iota_bytes(size_t n) {
    Bytes b(n);
    for (size_t i = 0; i < n; ++i) b[i] = uint8_t(i);
    return b;
}

int64_t g_ms = 0;
int64_t fake_ms() { return g_ms; }

// One ImGui context + one document + one HexView filling a host window.
struct Ui {
    ImGuiContext* ctx = nullptr;
    std::unique_ptr<Document> doc;
    HexView view;
    HexViewConfig cfg;
    HexViewEvents ev;
    std::vector<const HighlightSet*> layers;
    float w = 1000.0f, h = 600.0f;

    explicit Ui(const Bytes& data, int bytes_per_row = 16) {
        ctx = ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.LogFilename = nullptr;
        io.BackendFlags |= ImGuiBackendFlags_RendererHasTextures;  // fonts baked on demand, never uploaded
        io.Fonts->AddFontDefault();
        doc = Document::create_from_bytes("test", data.data(), data.size());
        cfg.bytes_per_row = bytes_per_row;
        cfg.group_size = 8;
        cfg.font_size = 13.0f;
        view.request_focus();
        frame();
        frame();
        REQUIRE(view.geometry().valid);
    }
    ~Ui() { ImGui::DestroyContext(ctx); }

    ViewState& v() { return doc->view(); }

    void frame(float dt = 1.0f / 60.0f) {
        ImGuiIO& io = ImGui::GetIO();
        io.DisplaySize = ImVec2(w, h);
        io.DeltaTime = dt;
        ImGui::NewFrame();
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(w, h));
        ImGui::Begin("host", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);
        view.draw("##hex", *doc, layers, cfg, ev);
        ImGui::End();
        ImGui::Render();
    }
    // Long gap: the next click is never part of a double-click.
    void settle() { frame(1.0f); }

    void move(ImVec2 p) {
        ImGui::GetIO().AddMousePosEvent(p.x, p.y);
        frame();
    }
    void button(bool down, int b = 0) {
        ImGui::GetIO().AddMouseButtonEvent(b, down);
        frame();
    }
    void mods(int m, bool down) {
        ImGuiIO& io = ImGui::GetIO();
        if (m & ImGuiMod_Shift) io.AddKeyEvent(ImGuiMod_Shift, down);
        if (m & ImGuiMod_Ctrl) io.AddKeyEvent(ImGuiMod_Ctrl, down);
        if (m) frame();
    }
    void click(ImVec2 p, int m = 0, int b = 0) {
        mods(m, true);
        move(p);
        button(true, b);
        button(false, b);
        mods(m, false);
        settle();
    }
    void double_click(ImVec2 p) {
        move(p);
        button(true);
        button(false);
        button(true);
        button(false);
        settle();
    }
    void drag(ImVec2 a, ImVec2 b) {
        move(a);
        button(true);
        // a few intermediate positions, like a real drag
        for (int i = 1; i <= 4; ++i) move(ImVec2(a.x + (b.x - a.x) * float(i) / 4.0f, a.y + (b.y - a.y) * float(i) / 4.0f));
        button(false);
        settle();
    }
    void key(ImGuiKey k, int m = 0) {
        mods(m, true);
        ImGui::GetIO().AddKeyEvent(k, true);
        frame();
        ImGui::GetIO().AddKeyEvent(k, false);
        frame();
        mods(m, false);
    }
    void type(const char* s) {
        for (; *s; ++s) {
            ImGui::GetIO().AddInputCharacter(unsigned(uint8_t(*s)));
            frame();
        }
    }
    // Hex cell of byte `off` (high digit unless `low`), or its text column cell.
    ImVec2 hex(uint64_t off, bool low = false) const { return view.cell_pos(off, false, low ? 0.75f : 0.25f); }
    ImVec2 txt(uint64_t off) const { return view.cell_pos(off, true, 0.5f); }

    uint8_t byte(uint64_t off) const {
        uint8_t b = 0;
        doc->read(off, &b, 1);
        return b;
    }
    std::pair<uint64_t, uint64_t> sel() { return {v().sel_begin(), v().sel_end()}; }
};

using Range = std::pair<uint64_t, uint64_t>;

}  // namespace

// =============================================================================================
// selection helpers
// =============================================================================================

TEST_CASE("ui: caret_byte / focus_offset / fmt_range follow the one selection convention") {
    ViewState v;
    v.cursor = v.anchor = 7;
    CHECK(caret_byte(v) == 7);
    CHECK(focus_offset(v) == 7);
    v.anchor = 4;  // forward selection 4..7 inclusive? no: [4, 7) = bytes 4..6
    CHECK(caret_byte(v) == 6);
    CHECK(focus_offset(v) == 4);
    v.anchor = 10;  // backward selection [7, 10)
    CHECK(caret_byte(v) == 7);
    CHECK(focus_offset(v) == 7);
    CHECK(fmt_range(0x10, 16) == "0x00000010-0x0000001F (16 bytes)");
    CHECK(fmt_range(0x10, 1) == "0x00000010 (1 byte)");
    CHECK(fmt_range(0, 2048) == "0x00000000-0x000007FF (2.00 KiB, 2048 bytes)");
}

// =============================================================================================
// mouse: hit testing
// =============================================================================================

TEST_CASE("ui: click on a byte's digits, the gaps between bytes and the text column") {
    Ui ui(iota_bytes(100));
    ui.click(ui.hex(5));
    CHECK(ui.v().cursor == 5);
    CHECK(ui.v().anchor == 5);
    CHECK(!ui.v().low_nibble);
    CHECK(!ui.v().ascii_focus);

    ui.click(ui.hex(5, true));  // second digit
    CHECK(ui.v().cursor == 5);
    CHECK(ui.v().low_nibble);

    const HexViewGeometry& g = ui.view.geometry();
    REQUIRE(g.adv > 0.0f);
    // The one-cell gap between bytes 5 and 6 is split in the middle.
    const ImVec2 b5 = ui.view.cell_pos(5, false, 0.0f), b6 = ui.view.cell_pos(6, false, 0.0f);
    CHECK(b6.x - b5.x == doctest::Approx(3.0f * g.adv));
    ui.click(ImVec2(b5.x + 2.0f * g.adv + 0.3f * g.adv, b5.y));
    CHECK(ui.v().cursor == 5);
    ui.click(ImVec2(b5.x + 2.0f * g.adv + 0.7f * g.adv, b5.y));
    CHECK(ui.v().cursor == 6);
    CHECK(!ui.v().low_nibble);

    // The group gap after byte 7 (two cells) is split in the middle too.
    const ImVec2 b7 = ui.view.cell_pos(7, false, 0.0f), b8 = ui.view.cell_pos(8, false, 0.0f);
    CHECK(b8.x - b7.x == doctest::Approx(4.0f * g.adv));
    ui.click(ImVec2(b7.x + 2.9f * g.adv, b7.y));
    CHECK(ui.v().cursor == 7);
    ui.click(ImVec2(b7.x + 3.1f * g.adv, b7.y));
    CHECK(ui.v().cursor == 8);

    // Text column.
    ui.click(ui.txt(21));
    CHECK(ui.v().cursor == 21);
    CHECK(ui.v().ascii_focus);
    CHECK(!ui.v().low_nibble);
    ui.click(ui.hex(3));
    CHECK(!ui.v().ascii_focus);

    // Left of the hex column (offset column): first byte of that row.
    ui.click(ImVec2(g.hex_x - 4.0f * g.adv, ui.hex(35).y));
    CHECK(ui.v().cursor == 32);
}

TEST_CASE("ui: clicks on the header row, below the last row and past the last byte") {
    Ui ui(iota_bytes(40));  // rows: 0..15, 16..31, 32..39 (+ EOF at 40)
    ui.click(ui.hex(9));
    REQUIRE(ui.v().cursor == 9);
    const HexViewGeometry& g = ui.view.geometry();
    ui.click(ImVec2(ui.hex(3).x, g.rows_y - 0.5f * g.line_h));  // header row: ignored
    CHECK(ui.v().cursor == 9);

    ui.click(ui.hex(39));  // last byte of the partial last row
    CHECK(ui.v().cursor == 39);
    ui.click(ui.hex(45));  // empty cell after it, same row
    CHECK(ui.v().cursor == 40);
    CHECK(!ui.v().low_nibble);
    ui.click(ui.hex(2 + 16 * 6));  // far below the last row, at column 2: EOF, not byte 34
    CHECK(ui.v().cursor == 40);
    CHECK(ui.v().anchor == 40);

    // Exactly full rows: the row below holds only the EOF position.
    Ui full(iota_bytes(32));
    full.click(full.hex(33));
    CHECK(full.v().cursor == 32);
}

TEST_CASE("ui: last partial row and the text column past the end") {
    Ui ui(iota_bytes(20));
    ui.click(ui.txt(19));
    CHECK(ui.v().cursor == 19);
    CHECK(ui.v().ascii_focus);
    ui.click(ui.txt(25));
    CHECK(ui.v().cursor == 20);
}

// =============================================================================================
// mouse: selection
// =============================================================================================

TEST_CASE("ui: drag forward and backward selects the bytes under the mouse, inclusive") {
    Ui ui(iota_bytes(256));
    ui.drag(ui.hex(4), ui.hex(9));
    CHECK(ui.sel() == Range{4, 10});
    CHECK(ui.v().anchor == 4);
    CHECK(caret_byte(ui.v()) == 9);    // drawn on the last selected byte, not after it
    CHECK(focus_offset(ui.v()) == 4);  // the Inspector decodes from the selection start

    ui.drag(ui.hex(9), ui.hex(4));
    CHECK(ui.sel() == Range{4, 10});
    CHECK(caret_byte(ui.v()) == 4);
    CHECK(focus_offset(ui.v()) == 4);

    // Across rows, on the low digits.
    ui.drag(ui.hex(14, true), ui.hex(18, true));
    CHECK(ui.sel() == Range{14, 19});
    CHECK(!ui.v().low_nibble);

    // Back onto the start byte: that one byte stays selected.
    ui.move(ui.hex(30));
    ui.button(true);
    ui.move(ui.hex(34));
    ui.move(ui.hex(30));
    ui.button(false);
    ui.settle();
    CHECK(ui.sel() == Range{30, 31});

    // Text column drag.
    ui.drag(ui.txt(40), ui.txt(43));
    CHECK(ui.sel() == Range{40, 44});
    CHECK(ui.v().ascii_focus);
}

TEST_CASE("ui: drag below the data selects to EOF; a plain click clears the selection") {
    Ui ui(iota_bytes(40));
    ui.drag(ui.hex(20), ui.hex(5 + 16 * 8));
    CHECK(ui.sel() == Range{20, 40});
    ui.click(ui.hex(3));
    CHECK(!ui.v().has_selection());
    CHECK(ui.v().cursor == 3);
}

TEST_CASE("ui: shift+click extends from the selection's fixed end, both directions") {
    Ui ui(iota_bytes(256));
    ui.click(ui.hex(10));
    ui.click(ui.hex(20), ImGuiMod_Shift);
    CHECK(ui.sel() == Range{10, 21});
    ui.click(ui.hex(5), ImGuiMod_Shift);  // flips over the fixed end: byte 10 stays selected
    CHECK(ui.sel() == Range{5, 11});
    CHECK(caret_byte(ui.v()) == 5);
    ui.click(ui.hex(30), ImGuiMod_Shift);
    CHECK(ui.sel() == Range{10, 31});

    // Backward drag, then shift+click beyond its fixed end.
    ui.drag(ui.hex(50), ui.hex(45));
    REQUIRE(ui.sel() == Range{45, 51});
    ui.click(ui.hex(60), ImGuiMod_Shift);
    CHECK(ui.sel() == Range{50, 61});
}

TEST_CASE("ui: double-click selects the highlight under the mouse") {
    Ui ui(iota_bytes(256));
    HighlightSet hs;
    hs.add({0x20, 12, 0xFF00FF00u, "field", -1});
    hs.finalize();
    ui.layers.push_back(&hs);
    ui.double_click(ui.hex(0x25));
    CHECK(ui.sel() == Range{0x20, 0x2C});
    CHECK(focus_offset(ui.v()) == 0x20);
    CHECK(caret_byte(ui.v()) == 0x2B);
    ui.double_click(ui.hex(0x60));  // no highlight: a plain caret
    CHECK(!ui.v().has_selection());
    CHECK(ui.v().cursor == 0x60);
}

TEST_CASE("ui: right-click keeps a selection it lands in, else moves the caret") {
    Ui ui(iota_bytes(256));
    ui.drag(ui.hex(4), ui.hex(9));
    ui.click(ui.hex(6), 0, 1);
    CHECK(ui.sel() == Range{4, 10});
    CHECK(ui.ev.open_context_menu == false);  // reported on the click frame only
    ui.click(ui.hex(40), 0, 1);
    CHECK(!ui.v().has_selection());
    CHECK(ui.v().cursor == 40);
}

TEST_CASE("ui: horizontal scroll and auto-fit keep hit testing on the drawn bytes") {
    Ui ui(iota_bytes(4096), 64);
    ui.w = 700.0f;  // 64 bytes per row do not fit: horizontal scrollbar
    ui.frame();
    ui.frame();
    ui.click(ui.hex(2));
    ui.key(ImGuiKey_End);  // caret to the row's last byte scrolls right
    ui.frame();
    ui.frame();
    CHECK(ui.v().cursor == 63);
    ui.click(ui.hex(60));
    CHECK(ui.v().cursor == 60);
    ui.key(ImGuiKey_Tab);  // caret to the text column: scrolls it into view
    ui.frame();
    ui.frame();
    ui.click(ui.txt(61));
    CHECK(ui.v().cursor == 61);
    CHECK(ui.v().ascii_focus);

    Ui fit(iota_bytes(4096), 0);  // auto-fit
    const int bpr = fit.view.geometry().bpr;
    CHECK(bpr >= 8);
    CHECK(bpr % 8 == 0);
    fit.click(fit.hex(uint64_t(bpr) * 3 + 5));
    CHECK(fit.v().cursor == uint64_t(bpr) * 3 + 5);
    fit.w = 520.0f;
    fit.frame();
    fit.frame();
    const int bpr2 = fit.view.geometry().bpr;
    CHECK(bpr2 < bpr);
    fit.click(fit.hex(uint64_t(bpr2) * 2 + 1));
    CHECK(fit.v().cursor == uint64_t(bpr2) * 2 + 1);
}

// =============================================================================================
// keyboard
// =============================================================================================

TEST_CASE("ui: shift+arrows select, plain arrows start from the drawn caret") {
    Ui ui(iota_bytes(256));
    ui.click(ui.hex(20));
    ui.key(ImGuiKey_RightArrow, ImGuiMod_Shift);
    ui.key(ImGuiKey_RightArrow, ImGuiMod_Shift);
    ui.key(ImGuiKey_RightArrow, ImGuiMod_Shift);
    CHECK(ui.sel() == Range{20, 23});
    CHECK(caret_byte(ui.v()) == 22);
    ui.key(ImGuiKey_LeftArrow, ImGuiMod_Shift);
    CHECK(ui.sel() == Range{20, 22});
    ui.key(ImGuiKey_DownArrow, ImGuiMod_Shift);
    CHECK(ui.sel() == Range{20, 38});
    CHECK(caret_byte(ui.v()) == 37);  // directly below byte 21

    ui.key(ImGuiKey_RightArrow);  // collapses onto the caret and moves one right
    CHECK(!ui.v().has_selection());
    CHECK(ui.v().cursor == 38);

    ui.drag(ui.hex(40), ui.hex(44));
    ui.key(ImGuiKey_LeftArrow);
    CHECK(!ui.v().has_selection());
    CHECK(ui.v().cursor == 43);
    ui.drag(ui.hex(40), ui.hex(44));
    ui.key(ImGuiKey_DownArrow);
    CHECK(ui.v().cursor == 44 + 16);

    // Backward keyboard selection.
    ui.click(ui.hex(50));
    ui.key(ImGuiKey_LeftArrow, ImGuiMod_Shift);
    ui.key(ImGuiKey_LeftArrow, ImGuiMod_Shift);
    CHECK(ui.sel() == Range{48, 50});
    CHECK(caret_byte(ui.v()) == 48);
    CHECK(focus_offset(ui.v()) == 48);
}

TEST_CASE("ui: Home/End use the caret byte's row") {
    Ui ui(iota_bytes(100));
    ui.drag(ui.hex(18), ui.hex(31));  // ends on the row's last byte: cursor = 32 (next row start)
    REQUIRE(ui.sel() == Range{18, 32});
    ui.key(ImGuiKey_End, ImGuiMod_Shift);  // already through the row's end: unchanged
    CHECK(ui.sel() == Range{18, 32});
    ui.key(ImGuiKey_Home, ImGuiMod_Shift);
    CHECK(ui.sel() == Range{16, 18});
    ui.click(ui.hex(20));
    ui.key(ImGuiKey_End);
    CHECK(ui.v().cursor == 31);
    ui.key(ImGuiKey_End, ImGuiMod_Shift);
    CHECK(ui.sel() == Range{31, 32});
    ui.click(ui.hex(97));
    ui.key(ImGuiKey_End);  // short last row
    CHECK(ui.v().cursor == 99);
    ui.key(ImGuiKey_End, ImGuiMod_Ctrl);
    CHECK(ui.v().cursor == 100);
    ui.key(ImGuiKey_Home, ImGuiMod_Ctrl | ImGuiMod_Shift);
    CHECK(ui.sel() == Range{0, 100});
    CHECK(focus_offset(ui.v()) == 0);
}

TEST_CASE("ui: select all and structure-style reveal put the caret inside the selection") {
    Ui ui(iota_bytes(64));
    ui.v().anchor = 0;  // what Edit > Select All does
    ui.v().cursor = 64;
    ui.frame();
    CHECK(caret_byte(ui.v()) == 63);
    CHECK(focus_offset(ui.v()) == 0);
    ui.v().cursor = 8;  // what reveal_range (Structure / Bookmarks / search results) does
    ui.v().anchor = 12;
    ui.frame();
    CHECK(caret_byte(ui.v()) == 8);
    CHECK(focus_offset(ui.v()) == 8);
}

// =============================================================================================
// typing
// =============================================================================================

TEST_CASE("ui: typing hex nibbles in overwrite and insert mode") {
    Ui ui(iota_bytes(32));
    ui.click(ui.hex(4));
    ui.type("a");
    CHECK(ui.byte(4) == 0xA4);
    CHECK(ui.v().cursor == 4);
    CHECK(ui.v().low_nibble);
    ui.type("b");
    CHECK(ui.byte(4) == 0xAB);
    CHECK(ui.v().cursor == 5);
    CHECK(!ui.v().low_nibble);
    ui.type("xz");  // not hex: ignored
    CHECK(ui.byte(5) == 5);

    ui.click(ui.hex(8, true));  // second digit: overwrites the low nibble
    ui.type("f");
    CHECK(ui.byte(8) == 0x0F);
    CHECK(ui.v().cursor == 9);

    ui.cfg.insert_mode = true;
    ui.click(ui.hex(10));
    ui.type("1");
    CHECK(ui.doc->size() == 33);
    CHECK(ui.byte(10) == 0x10);
    CHECK(ui.byte(11) == 10);
    ui.type("2");
    CHECK(ui.byte(10) == 0x12);
    CHECK(ui.doc->size() == 33);
    CHECK(ui.v().cursor == 11);

    // Overwrite with a selection writes from the selection start.
    ui.cfg.insert_mode = false;
    ui.drag(ui.hex(20), ui.hex(23));
    ui.type("ee");
    CHECK(ui.byte(20) == 0xEE);
    CHECK(ui.byte(21) == 20);  // shifted by the insert above: byte 20 of the original is now at 21
    CHECK(!ui.v().has_selection());

    // Text column types characters.
    ui.click(ui.txt(0));
    ui.type("Hi");
    CHECK(ui.byte(0) == 'H');
    CHECK(ui.byte(1) == 'i');
    CHECK(ui.v().cursor == 2);

    // Insert mode + selection: the typed byte replaces the selection.
    ui.cfg.insert_mode = true;
    const uint64_t before = ui.doc->size();
    ui.drag(ui.txt(2), ui.txt(5));
    ui.type("Z");
    CHECK(ui.doc->size() == before - 3);
    CHECK(ui.byte(2) == 'Z');
}

TEST_CASE("ui: a typing pause or the byte limit starts a new undo step") {
    g_ms = 1000;
    Document::set_clock_for_tests(&fake_ms);
    Document::set_undo_merge(500, 4);
    {
        Ui ui(iota_bytes(64));
        ui.click(ui.hex(0));
        ui.type("1122");  // fast: one step
        CHECK(ui.doc->undo_stack().size() == 1);
        g_ms += 600;  // pause
        ui.type("33");
        CHECK(ui.doc->undo_stack().size() == 2);
        g_ms += 100;
        ui.type("4455");  // run of 33 44 55 66 hits the 4-byte limit at the 5th byte
        ui.type("66");
        CHECK(ui.doc->undo_stack().size() == 2);
        ui.type("77");
        CHECK(ui.doc->undo_stack().size() == 3);
        CHECK(ui.byte(0) == 0x11);
        CHECK(ui.byte(6) == 0x77);

        // Ctrl+Z is the app's shortcut; undo directly and check the steps.
        REQUIRE(ui.doc->undo());
        CHECK(ui.byte(6) == 6);
        CHECK(ui.byte(5) == 0x66);
        REQUIRE(ui.doc->undo());
        CHECK(ui.byte(2) == 2);
        CHECK(ui.byte(1) == 0x22);
        REQUIRE(ui.doc->undo());
        CHECK(ui.byte(0) == 0);
    }
    Document::set_clock_for_tests(nullptr);
    Document::set_undo_merge(500, 32);
}

TEST_CASE("ui: Delete, Backspace and Tab") {
    Ui ui(iota_bytes(32));
    ui.drag(ui.hex(4), ui.hex(7));
    ui.key(ImGuiKey_Delete);
    CHECK(ui.doc->size() == 28);
    CHECK(ui.byte(4) == 8);
    CHECK(ui.v().cursor == 4);
    ui.key(ImGuiKey_Backspace);  // overwrite mode: moves left only
    CHECK(ui.doc->size() == 28);
    CHECK(ui.v().cursor == 3);
    ui.key(ImGuiKey_Tab);
    CHECK(ui.v().ascii_focus);
    ui.key(ImGuiKey_Tab);
    CHECK(!ui.v().ascii_focus);
}

// =============================================================================================
// follow pointer (Ctrl+click) and mouse back/forward buttons
// =============================================================================================

namespace {

// Presses button `b` (with modifiers `m`) at `p` and returns the view's events of the press frame.
HexViewEvents press_events(Ui& ui, ImVec2 p, int m, int b = 0) {
    ui.mods(m, true);
    ui.move(p);
    ui.button(true, b);
    HexViewEvents ev = ui.ev;
    ui.button(false, b);
    ui.mods(m, false);
    ui.settle();
    return ev;
}

void put(Ui& ui, uint64_t off, const Bytes& b) { REQUIRE(ui.doc->overwrite(off, b.data(), b.size())); }

}  // namespace

TEST_CASE("ui: ctrl+click follows a little-endian pointer without moving the caret") {
    Ui ui(iota_bytes(100));
    put(ui, 8, {0x20, 0x00, 0x00, 0x00});
    ui.click(ui.hex(3));
    REQUIRE(ui.v().cursor == 3);

    HexViewEvents ev = press_events(ui, ui.hex(8), ImGuiMod_Ctrl);
    CHECK(ev.follow_requested);
    CHECK(ev.follow_target == 0x20);
    CHECK(ev.follow_from == 8);
    CHECK(ui.v().cursor == 3);
    CHECK(ui.v().anchor == 3);
    CHECK(!ui.v().has_selection());

    // the text column works too
    ev = press_events(ui, ui.txt(8), ImGuiMod_Ctrl);
    CHECK(ev.follow_requested);
    CHECK(ev.follow_target == 0x20);
    CHECK(ui.v().cursor == 3);
}

TEST_CASE("ui: ctrl+click honours pointer width, endianness and base") {
    Ui ui(iota_bytes(100));
    put(ui, 12, {0x00, 0x00, 0x00, 0x30});
    put(ui, 20, {0x34, 0x12});

    ui.cfg.pointer_big_endian = true;
    HexViewEvents ev = press_events(ui, ui.hex(12), ImGuiMod_Ctrl);
    CHECK(ev.follow_requested);
    CHECK(ev.follow_target == 0x30);

    ui.cfg.pointer_big_endian = false;
    ui.cfg.pointer_width = 2;
    ui.cfg.pointer_base = 0x1200;
    ev = press_events(ui, ui.hex(20), ImGuiMod_Ctrl);
    CHECK(ev.follow_requested);
    CHECK(ev.follow_target == 0x34);
    CHECK(ev.follow_from == 20);

    ui.cfg.pointer_base = 0;
    ui.cfg.pointer_width = 1;
    ev = press_events(ui, ui.hex(40), ImGuiMod_Ctrl);  // iota: byte 40 == 40
    CHECK(ev.follow_requested);
    CHECK(ev.follow_target == 40);

    ui.cfg.pointer_width = 8;
    put(ui, 50, {0x05, 0, 0, 0, 0, 0, 0, 0});
    ev = press_events(ui, ui.hex(50), ImGuiMod_Ctrl);
    CHECK(ev.follow_requested);
    CHECK(ev.follow_target == 5);
}

TEST_CASE("ui: ctrl+click on a pointer beyond EOF or cut off by EOF does nothing") {
    Ui ui(iota_bytes(100));
    put(ui, 8, {0x20, 0x00, 0x00, 0x00});
    ui.click(ui.hex(3));

    ui.cfg.pointer_big_endian = true;  // 0x20000000 > size
    HexViewEvents ev = press_events(ui, ui.hex(8), ImGuiMod_Ctrl);
    CHECK(!ev.follow_requested);
    CHECK(ui.v().cursor == 3);

    ui.cfg.pointer_big_endian = false;
    ev = press_events(ui, ui.hex(98), ImGuiMod_Ctrl);  // only 2 bytes left
    CHECK(!ev.follow_requested);
    CHECK(ui.v().cursor == 3);

    ui.cfg.pointer_base = 0x21;  // 0x20 - 0x21 underflows
    ev = press_events(ui, ui.hex(8), ImGuiMod_Ctrl);
    CHECK(!ev.follow_requested);
}

TEST_CASE("ui: plain and shift clicks are unaffected by follow pointer") {
    Ui ui(iota_bytes(100));
    put(ui, 8, {0x20, 0x00, 0x00, 0x00});
    HexViewEvents ev = press_events(ui, ui.hex(8), 0);
    CHECK(!ev.follow_requested);
    CHECK(ui.v().cursor == 8);
    CHECK(!ui.v().has_selection());

    ev = press_events(ui, ui.hex(12), ImGuiMod_Shift);
    CHECK(!ev.follow_requested);
    CHECK(ui.sel() == Range{8, 13});
}

TEST_CASE("ui: mouse X1/X2 report back/forward while hovered") {
    Ui ui(iota_bytes(100));
    HexViewEvents ev = press_events(ui, ui.hex(4), 0, 3);
    CHECK(ev.nav_back);
    CHECK(!ev.nav_forward);
    ev = press_events(ui, ui.hex(4), 0, 4);
    CHECK(ev.nav_forward);
    CHECK(!ev.nav_back);
    CHECK(ui.v().cursor == 0);  // neither moves the caret by itself
    CHECK(!ui.ev.nav_back);     // one frame only
    CHECK(!ui.ev.nav_forward);

    ev = press_events(ui, ImVec2(ui.w + 50.0f, ui.h + 50.0f), 0, 3);  // outside the view
    CHECK(!ev.nav_back);
}

// ================================================================================================
// byte-class coloring
// ================================================================================================

TEST_CASE("ui: byte text color precedence and classes") {
    const HexColors& C = hex_colors();
    // Plain scheme (unchanged behaviour).
    CHECK(byte_text_color(0x00, false, false, false, false) == C.zero_text);
    CHECK(byte_text_color(0x41, false, false, false, false) == C.hex_text);
    CHECK(byte_text_color(0x41, true, false, false, false) == C.ascii_text);
    CHECK(byte_text_color(0x01, true, false, false, false) == C.nonprint_text);
    CHECK(byte_text_color(0xFF, true, false, false, false) == C.nonprint_text);
    // Class scheme: same color in both columns, one per class.
    for (int v = 0; v < 256; ++v) {
        const uint8_t b = uint8_t(v);
        const uint32_t want = byte_class_color(byte_class(b));
        CHECK(byte_text_color(b, false, false, false, true) == want);
        CHECK(byte_text_color(b, true, false, false, true) == want);
    }
    CHECK(byte_class_color(ByteClass::Zero) == C.byte_class[0]);
    for (int a = 0; a < kByteClassCount; ++a)
        for (int b = a + 1; b < kByteClassCount; ++b) CHECK(C.byte_class[a] != C.byte_class[b]);
    for (int a = 0; a < kByteClassCount; ++a) {
        CHECK(C.byte_class[a] != C.modified_text);
        CHECK(C.byte_class[a] != C.unreadable_text);
    }
    // Precedence: unreadable > modified > class.
    for (bool cls : {false, true})
        for (bool text : {false, true}) {
            CHECK(byte_text_color(0x41, text, true, true, cls) == C.unreadable_text);
            CHECK(byte_text_color(0x41, text, false, true, cls) == C.modified_text);
        }
}

TEST_CASE("ui: byte-class coloring does not change layout or hit testing") {
    Ui ui(iota_bytes(300));
    const HexViewGeometry g0 = ui.view.geometry();
    const ImVec2 h0 = ui.hex(37), t0 = ui.txt(37);
    ui.cfg.byte_class_colors = true;
    ui.frame();
    ui.frame();
    const HexViewGeometry& g1 = ui.view.geometry();
    CHECK(g1.hex_x == g0.hex_x);
    CHECK(g1.text_x == g0.text_x);
    CHECK(g1.adv == g0.adv);
    CHECK(g1.rows_y == g0.rows_y);
    CHECK(g1.bpr == g0.bpr);
    CHECK(g1.full_rows == g0.full_rows);
    CHECK(ui.hex(37).x == h0.x);
    CHECK(ui.txt(37).x == t0.x);
    ui.click(ui.hex(37));
    CHECK(ui.v().cursor == 37);
    ui.drag(ui.hex(40), ui.txt(43));
    CHECK(ui.sel() == Range{40, 44});
    ui.click(ui.hex(5, true));
    CHECK(ui.v().cursor == 5);
    CHECK(ui.v().low_nibble);
}

// ================================================================================================
// minimap
// ================================================================================================

namespace {

// ImGui context drawing one Minimap strip (sh px tall) in a host window.
struct MapUi {
    ImGuiContext* ctx = nullptr;
    Minimap map;
    MinimapEvents ev;
    const EntropyResult* r = nullptr;
    uint64_t size = 1000, vb = 0, ve = 0;
    MinimapMode mode = MinimapMode::Entropy;
    float sw = 16.0f, sh = 400.0f;
    ImVec2 p0;                         // strip origin of the last frame
    std::vector<MinimapEvents> jumps;  // every frame that requested a jump

    MapUi() {
        ctx = ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.LogFilename = nullptr;
        io.BackendFlags |= ImGuiBackendFlags_RendererHasTextures;
        io.Fonts->AddFontDefault();
        frame();
        frame();
    }
    ~MapUi() { ImGui::DestroyContext(ctx); }
    void frame(float dt = 1.0f / 60.0f) {
        ImGuiIO& io = ImGui::GetIO();
        io.DisplaySize = ImVec2(600, 600);
        io.DeltaTime = dt;
        ImGui::NewFrame();
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(600, 600));
        ImGui::Begin("host", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);
        p0 = ImGui::GetCursorScreenPos();
        map.draw("##map", sw, sh, r, size, vb, ve, mode, ev);
        if (ev.jump_requested) jumps.push_back(ev);
        ImGui::End();
        ImGui::Render();
    }
    ImVec2 at(float fy) const { return ImVec2(p0.x + sw * 0.5f, p0.y + sh * fy); }
    void move(ImVec2 p) {
        ImGui::GetIO().AddMousePosEvent(p.x, p.y);
        frame();
    }
    void button(bool down) {
        ImGui::GetIO().AddMouseButtonEvent(0, down);
        frame();
    }
};

}  // namespace

TEST_CASE("ui: minimap row geometry") {
    CHECK(minimap_row_offset(0, 400, 1000) == 0);
    CHECK(minimap_row_offset(1, 400, 1000) == 2);  // floor(2.5)
    CHECK(minimap_row_offset(200, 400, 1000) == 500);
    CHECK(minimap_row_offset(400, 400, 1000) == 1000);
    CHECK(minimap_row_offset(999, 400, 1000) == 1000);
    CHECK(minimap_row_offset(5, 0, 1000) == 0);
    const uint64_t big = 3ull << 40;
    CHECK(minimap_row_offset(399, 400, big) == big * 399 / 400);  // fits: exact reference
    CHECK(minimap_row_offset(1, 3, UINT64_MAX) == UINT64_MAX / 3);  // no overflow
    CHECK(minimap_offset_row(0, 400, 1000) == 0);
    CHECK(minimap_offset_row(500, 400, 1000) == 200);
    CHECK(minimap_offset_row(1000, 400, 1000) == 399);  // clamped to the last row
    CHECK(minimap_offset_row(5, 400, 0) == 0);
    CHECK(minimap_offset_row(big - 1, 400, big) == 399);
    CHECK(minimap_offset_row(UINT64_MAX / 2, 400, UINT64_MAX) == 200);
    CHECK(minimap_offset_row(501, 400, 1000) == 200);  // row 200 is [500, 502)
    CHECK(minimap_offset_row(502, 400, 1000) == 201);
    CHECK(minimap_offset_row(2, 400, 3) == 399);       // tiny: the last row holding byte 2
    for (uint64_t y = 0; y < 400; ++y) CHECK(minimap_offset_row(minimap_row_offset(y, 400, big), 400, big) == y);
}

TEST_CASE("ui: minimap click and drag request jumps") {
    MapUi ui;
    ui.size = 1000;
    ui.vb = 0;
    ui.ve = 100;
    ui.move(ui.at(0.5f));
    CHECK(ui.ev.hovered);
    CHECK(ui.ev.hover_offset == 500);
    CHECK(ui.jumps.empty());
    ui.button(true);
    REQUIRE(ui.jumps.size() == 1);
    CHECK(ui.jumps[0].jump_offset == 501);  // centre of the row [500, 502)
    ui.button(false);
    CHECK(ui.jumps.size() == 1);

    // Drag down past the end: offsets grow, clamped to the last row.
    ui.jumps.clear();
    ui.move(ui.at(0.1f));
    ui.button(true);
    for (float f : {0.3f, 0.6f, 0.9f, 1.5f}) ui.move(ui.at(f));
    ui.button(false);
    REQUIRE(ui.jumps.size() >= 4);
    for (size_t i = 1; i < ui.jumps.size(); ++i) CHECK(ui.jumps[i].jump_offset > ui.jumps[i - 1].jump_offset);
    CHECK(ui.jumps.back().jump_offset == 998);  // centre of the last row [997, 1000)
    CHECK(ui.jumps.front().jump_offset == 101);
    // Holding still does not repeat the jump.
    ui.jumps.clear();
    ui.move(ui.at(0.2f));
    ui.button(true);
    ui.frame();
    ui.frame();
    CHECK(ui.jumps.size() == 1);
    ui.button(false);

    // Outside the strip: nothing.
    ui.jumps.clear();
    ui.move(ImVec2(ui.p0.x + ui.sw + 40.0f, ui.p0.y + 10.0f));
    CHECK_FALSE(ui.ev.hovered);
    ui.button(true);
    ui.button(false);
    CHECK(ui.jumps.empty());
}

TEST_CASE("ui: minimap draws pending, partial and tiny results without trouble") {
    EntropyResult r = entropy_layout(1000, 64);
    for (size_t i = 0; i < r.buckets.size() / 2; ++i) {
        r.buckets[i].done = true;
        r.buckets[i].bytes_read = r.buckets[i].length;
        r.buckets[i].entropy = float(i % 9);
        r.buckets[i].class_frac[int(ByteClass::Printable)] = 0.75f;
        r.buckets[i].class_frac[int(ByteClass::Zero)] = 0.25f;
    }
    r.buckets[3].unreadable = true;
    r.buckets[4].unreadable = true;
    r.buckets[4].bytes_read = 0;
    r.done = uint32_t(r.buckets.size() / 2);
    MapUi ui;
    ui.r = &r;
    for (MinimapMode m : {MinimapMode::Entropy, MinimapMode::ByteClass}) {
        ui.mode = m;
        for (float f : {0.01f, 0.2f, 0.9f}) {
            ui.move(ui.at(f));
            ui.frame(1.0f);  // past the tooltip delay
            CHECK(ui.ev.hovered);
        }
    }
    // Tiny document stretched over many rows, empty document, no result.
    EntropyResult tiny = entropy_layout(3, 1024);
    ui.r = &tiny;
    ui.size = 3;
    ui.ve = 3;
    ui.move(ui.at(0.9f));
    CHECK(ui.ev.hover_offset == 2);
    ui.button(true);
    CHECK(ui.ev.jump_requested);
    CHECK(ui.ev.jump_offset == 2);
    ui.button(false);
    ui.size = 0;
    ui.frame();
    CHECK_FALSE(ui.ev.hovered);
    ui.r = nullptr;
    ui.size = 50;
    ui.frame();
    CHECK(ui.ev.hovered);
}

TEST_CASE("ui: minimap strips shorter than the viewport box and the extremes") {
    MapUi ui;
    ui.size = 1000;
    ui.vb = 990;
    ui.ve = 1000;
    for (float h : {1.0f, 2.0f, 3.0f}) {  // the 3 px viewport box does not fit: no bad clamp
        ui.sh = h;
        ui.move(ui.at(0.5f));
        CHECK(ui.ev.hovered);
    }
    // Offset 0 / last byte: pressing on the first and the last pixel row of a 400 px strip.
    ui.sh = 400.0f;
    ui.move(ImVec2(ui.p0.x + 2.0f, ui.p0.y + 0.2f));
    ui.button(true);
    REQUIRE(ui.ev.jump_requested);
    CHECK(ui.ev.jump_offset == 1);  // centre of row 0 = [0, 2)
    ui.button(false);
    ui.move(ImVec2(ui.p0.x + 2.0f, ui.p0.y + 399.5f));
    ui.button(true);
    REQUIRE(ui.ev.jump_requested);
    CHECK(ui.ev.jump_offset == 998);  // centre of the last row [997, 1000)
    ui.button(false);
    // 1-byte document: every row shows byte 0, a press anywhere jumps there.
    ui.size = 1;
    ui.vb = 0;
    ui.ve = 1;
    for (float f : {0.0f, 0.5f, 0.999f}) {
        ui.move(ui.at(f));
        CHECK(ui.ev.hover_offset == 0);
        ui.button(true);
        REQUIRE(ui.ev.jump_requested);
        CHECK(ui.ev.jump_offset == 0);
        ui.button(false);
    }
    // Empty document: no hover, no jump.
    ui.size = 0;
    ui.vb = ui.ve = 0;
    ui.move(ui.at(0.5f));
    CHECK_FALSE(ui.ev.hovered);
    ui.button(true);
    CHECK_FALSE(ui.ev.jump_requested);
    ui.button(false);
}

TEST_CASE("ui: reserve_right leaves room beside the view") {
    Ui ui(iota_bytes(4000), 0);  // auto-fit bytes per row
    const int full = ui.ev.bytes_per_row;
    ui.cfg.reserve_right = 500.0f;
    ui.frame();
    ui.frame();
    CHECK(ui.ev.bytes_per_row < full);
    CHECK(ui.ev.bytes_per_row >= 8);
    ui.click(ui.hex(9));
    CHECK(ui.v().cursor == 9);
    // A click in the reserved strip does not reach the view.
    ui.click(ImVec2(ui.w - 100.0f, ui.hex(20).y));
    CHECK(ui.v().cursor == 9);
}

TEST_CASE("ui: take_scroll_request hands a pending scroll over instead of applying it") {
    Ui ui(iota_bytes(64 * 1024));
    uint64_t off = 0;
    bool center = false;
    CHECK_FALSE(ui.view.take_scroll_request(off, center));  // nothing pending
    ui.view.request_scroll_to(0x8000, true);
    REQUIRE(ui.view.take_scroll_request(off, center));
    CHECK(off == 0x8000);
    CHECK(center);
    CHECK_FALSE(ui.view.take_scroll_request(off, center));  // taken once
    ui.frame();
    CHECK(ui.v().top_row == 0);  // the taken request is not applied by the next draw
    ui.view.request_scroll_to(0x8000, false);
    ui.frame();
    CHECK(ui.v().top_row > 0);  // an untaken one still is
    CHECK_FALSE(ui.view.take_scroll_request(off, center));
}
