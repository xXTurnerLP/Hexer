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
#include "core/highlight.h"
#include "ui/hex_view.h"

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
