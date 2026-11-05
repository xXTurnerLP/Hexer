// Headless tests of the Packets and Bitmap panels: a Dear ImGui context without a window or GL
// (io.DisplaySize set by hand, ImGuiBackendFlags_RendererHasTextures so fonts bake on demand into
// textures nobody uploads; same approach as tests/test_ui.cpp) draws a panel inside a full-size
// host window, input is queued one event per frame, positions come from the panels' last-draw
// accessors (PacketsPanel::row_pos, BitmapPanel::image_x / image_y / shown_zoom).
//
// The Bitmap panel's texture is created but never uploaded here (no renderer backend): the panel
// still decodes the visible window into it, which is what these tests check.
#include <doctest/doctest.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "imgui.h"

#include "core/document.h"
#include "core/highlight.h"
#include "ui/panel_bitmap.h"
#include "ui/panel_packets.h"

using namespace hx;

namespace {

using Bytes = std::vector<uint8_t>;

// One ImGui context; frame() draws `body` inside a host window filling the display.
struct Gui {
    ImGuiContext* ctx = nullptr;
    float w = 900.0f, h = 700.0f;
    std::function<void()> body;

    Gui() {
        ctx = ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.LogFilename = nullptr;
        io.BackendFlags |= ImGuiBackendFlags_RendererHasTextures;  // fonts baked on demand, never uploaded
        io.Fonts->AddFontDefault();
    }
    ~Gui() { ImGui::DestroyContext(ctx); }

    void frame(float dt = 1.0f / 60.0f) {
        ImGuiIO& io = ImGui::GetIO();
        io.DisplaySize = ImVec2(w, h);
        io.DeltaTime = dt;
        ImGui::NewFrame();
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(w, h));
        ImGui::Begin("host", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);
        if (body) body();
        ImGui::End();
        ImGui::Render();
    }
    void settle() { frame(1.0f); }  // the next click is never part of a double-click
    void move(ImVec2 p) {
        ImGui::GetIO().AddMousePosEvent(p.x, p.y);
        frame();
    }
    void button(bool down) {
        ImGui::GetIO().AddMouseButtonEvent(0, down);
        frame();
    }
    void click(ImVec2 p) {
        move(p);
        button(true);
        button(false);
        settle();
    }
    void drag(ImVec2 a, ImVec2 b) {
        move(a);
        button(true);
        for (int i = 1; i <= 4; ++i) move(ImVec2(a.x + (b.x - a.x) * float(i) / 4.0f, a.y + (b.y - a.y) * float(i) / 4.0f));
        button(false);
        settle();
    }
    void key(ImGuiKey k) {
        ImGui::GetIO().AddKeyEvent(k, true);
        frame();
        ImGui::GetIO().AddKeyEvent(k, false);
        frame();
    }
};

// ---- a small classic pcap: Ethernet / IPv4 / UDP packets ----------------------------------------

void le32(Bytes& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(uint8_t(v >> (8 * i)));
}
void be16(Bytes& b, uint32_t v) {
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v));
}

Bytes udp_frame(uint16_t port, size_t payload) {
    Bytes b = {0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01};  // Ethernet dst, src
    be16(b, 0x0800);
    b.push_back(0x45);  // IPv4, 20-byte header
    b.push_back(0);
    be16(b, uint32_t(20 + 8 + payload));
    be16(b, 1);
    be16(b, 0);
    b.push_back(64);
    b.push_back(17);  // UDP
    be16(b, 0);
    for (uint8_t v : {10, 0, 0, 1, 10, 0, 0, 2}) b.push_back(v);
    be16(b, 5000);
    be16(b, port);
    be16(b, uint32_t(8 + payload));
    be16(b, 0);
    for (size_t i = 0; i < payload; ++i) b.push_back(uint8_t('a' + i % 26));
    return b;
}

constexpr size_t kFrameLen = 14 + 20 + 8 + 10;  // udp_frame(port, 10)

// `n` packets; packet i's data starts at data_off(i).
Bytes make_pcap(int n) {
    Bytes b;
    le32(b, 0xA1B2C3D4);
    b.push_back(2), b.push_back(0), b.push_back(4), b.push_back(0);  // version 2.4
    le32(b, 0), le32(b, 0), le32(b, 65535), le32(b, 1);              // Ethernet
    for (int i = 0; i < n; ++i) {
        const Bytes f = udp_frame(uint16_t(1000 + i), 10);
        le32(b, uint32_t(100 + i)), le32(b, 0), le32(b, uint32_t(f.size())), le32(b, uint32_t(f.size()));
        for (uint8_t v : f) b.push_back(v);  // (vector::insert trips a GCC 13 -Wstringop-overflow false positive)
    }
    return b;
}
uint64_t data_off(size_t i) { return 24 + 16 * (i + 1) + kFrameLen * i; }

}  // namespace

// =============================================================================================
// Packets panel
// =============================================================================================

TEST_CASE("panels: Packets indexes a capture; row click, Up / Down / Home / End select packets") {
    Gui gui;
    const Bytes cap = make_pcap(6);
    auto doc = Document::create_from_bytes("cap.pcap", cap.data(), cap.size());
    REQUIRE(PacketsPanel::is_capture(*doc));
    PacketsPanel panel;
    std::vector<std::pair<uint64_t, uint64_t>> selects;
    std::vector<std::string> notes;
    PacketsPanelCallbacks cb;
    cb.select = [&](uint64_t off, uint64_t len) { selects.emplace_back(off, len); };
    cb.notify = [&](const std::string& m) { notes.push_back(m); };
    gui.body = [&] { panel.draw(doc.get(), {}, cb); };

    // The index starts by itself and finishes on its worker thread.
    float x = 0, y = 0;
    const auto t0 = std::chrono::steady_clock::now();
    while (!panel.row_pos(5, x, y)) {
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        gui.frame();
    }
    gui.frame();
    CHECK_FALSE(panel.wants_frames());
    REQUIRE(notes.size() == 1);
    CHECK(notes[0] == "Packets: 6 indexed");
    CHECK(selects.empty());
    CHECK(panel.selected_packet(doc->id()) == SIZE_MAX);

    // Click on row 2: packet #3's captured bytes are selected.
    REQUIRE(panel.row_pos(2, x, y));
    gui.click(ImVec2(x, y));
    REQUIRE(selects.size() == 1);
    CHECK(selects[0] == std::make_pair(data_off(2), uint64_t(kFrameLen)));
    CHECK(panel.selected_packet(doc->id()) == 2);

    // The keyboard steps through the packets (the panel's window has focus after the click).
    gui.key(ImGuiKey_DownArrow);
    CHECK(panel.selected_packet(doc->id()) == 3);
    CHECK(selects.back() == std::make_pair(data_off(3), uint64_t(kFrameLen)));
    gui.key(ImGuiKey_UpArrow);
    gui.key(ImGuiKey_UpArrow);
    CHECK(panel.selected_packet(doc->id()) == 1);
    CHECK(selects.back().first == data_off(1));
    gui.key(ImGuiKey_End);
    CHECK(panel.selected_packet(doc->id()) == 5);
    CHECK(selects.back().first == data_off(5));
    gui.key(ImGuiKey_DownArrow);  // already the last one: nothing happens
    CHECK(selects.size() == 5);
    gui.key(ImGuiKey_Home);
    CHECK(panel.selected_packet(doc->id()) == 0);
    CHECK(selects.back().first == data_off(0));
    CHECK(selects.size() == 6);

    // A click on another row; the state is per document and forget() drops it.
    REQUIRE(panel.row_pos(4, x, y));
    gui.click(ImVec2(x, y));
    CHECK(panel.selected_packet(doc->id()) == 4);
    CHECK(selects.back().first == data_off(4));
    panel.forget(doc->id());
    CHECK(panel.selected_packet(doc->id()) == SIZE_MAX);
}

TEST_CASE("panels: Packets on a document that is not a capture") {
    Gui gui;
    const Bytes junk(100, 0x42);
    auto doc = Document::create_from_bytes("junk.bin", junk.data(), junk.size());
    PacketsPanel panel;
    int selects = 0;
    PacketsPanelCallbacks cb;
    cb.select = [&](uint64_t, uint64_t) { ++selects; };
    gui.body = [&] { panel.draw(doc.get(), {"parser"}, cb); };
    for (int i = 0; i < 5; ++i) gui.frame();
    float x = 0, y = 0;
    CHECK_FALSE(panel.row_pos(0, x, y));  // no table
    CHECK_FALSE(panel.wants_frames());    // no index was started
    gui.key(ImGuiKey_DownArrow);
    CHECK(selects == 0);
    gui.body = [&] { panel.draw(nullptr, {}, cb); };  // no document
    gui.frame();
}

// =============================================================================================
// Bitmap panel
// =============================================================================================

namespace {

struct BitmapFixture {
    Gui gui;
    Bytes data;
    std::unique_ptr<Document> doc;
    BitmapPanel panel;
    uint64_t cursor = 0, view_top = 0;
    std::vector<uint64_t> jumps;
    std::vector<std::pair<uint64_t, uint64_t>> selects;

    BitmapFixture() : data(4096) {
        for (size_t i = 0; i < data.size(); ++i) data[i] = uint8_t(i);
        doc = Document::create_from_bytes("img.bin", data.data(), data.size());
        panel.width = 64;
        panel.zoom = 2;
        BitmapPanelCallbacks cb;
        cb.jump = [this](uint64_t off) { jumps.push_back(off); };
        cb.select = [this](uint64_t off, uint64_t len) { selects.emplace_back(off, len); };
        gui.body = [this, cb] { panel.draw(doc.get(), cursor, view_top, cb); };
        gui.frame();
        gui.frame();
    }
    ~BitmapFixture() { panel.shutdown(); }  // while the context is alive

    uint32_t px(int x, int y) const {
        const size_t i = size_t(y) * size_t(panel.shown_cols()) + size_t(x);
        return i < panel.shown_pixels().size() ? panel.shown_pixels()[i] : 0;
    }
    // Screen position of the centre of image pixel (x, y).
    ImVec2 at(int x, int y) const {
        const float z = float(panel.shown_zoom());
        return ImVec2(panel.image_x() + (float(x) + 0.5f) * z, panel.image_y() + (float(y) + 0.5f) * z);
    }
};

}  // namespace

TEST_CASE("panels: Bitmap decodes the visible window without a renderer; format and zoom changes") {
    BitmapFixture f;
    REQUIRE(f.panel.decoded());
    CHECK(f.panel.wants_frames());  // the texture waits for a backend that never uploads it
    CHECK(f.panel.offset() == 0);
    CHECK(f.panel.shown_zoom() == 2);
    CHECK(f.panel.shown_cols() == 64);
    CHECK(f.panel.shown_rows() > 20);
    CHECK(f.px(0, 0) == rgba(0, 0, 0));
    CHECK(f.px(5, 1) == rgba(69, 69, 69));  // gray: byte 64 + 5

    f.panel.format = PixelFormat::RGB24;
    f.gui.frame();
    CHECK(f.px(0, 0) == rgba(0, 1, 2));
    CHECK(f.px(1, 0) == rgba(3, 4, 5));
    CHECK(f.px(0, 1) == rgba(192, 193, 194));  // row stride 64 * 3 bytes

    f.panel.zoom = 4;  // a bigger window: the texture is re-created (never uploaded, freed at once)
    f.gui.frame();
    REQUIRE(f.panel.decoded());
    CHECK(f.panel.shown_zoom() == 4);
    CHECK(f.px(1, 0) == rgba(3, 4, 5));
    f.panel.width = 8;
    f.gui.frame();
    CHECK(f.panel.shown_cols() == 8);
    CHECK(f.px(0, 1) == rgba(24, 25, 26));

    // Editing the document re-decodes (the generation is part of the cache key).
    const uint8_t red[3] = {255, 0, 0};
    REQUIRE(f.doc->overwrite(0, red, 3));
    f.gui.frame();
    CHECK(f.px(0, 0) == rgba(255, 0, 0));
}

TEST_CASE("panels: Bitmap sources: follow view / cursor, Show at Cursor (fixed offset)") {
    BitmapFixture f;
    f.view_top = 128;
    f.gui.frame();
    CHECK(f.panel.offset() == 128);  // follows the hex view's top row
    CHECK(f.px(0, 0) == rgba(128, 128, 128));
    f.panel.source = BitmapSource::FollowCursor;
    f.cursor = 300;
    f.gui.frame();
    CHECK(f.panel.offset() == 300);
    CHECK(f.px(0, 0) == rgba(44, 44, 44));  // 300 & 0xFF

    // "Bitmap: Show at Cursor": a fixed offset that stays when the cursor moves on.
    f.panel.set_fixed_offset(f.cursor);
    f.cursor = 1000;
    f.gui.frame();
    CHECK(f.panel.source == BitmapSource::Fixed);
    CHECK(f.panel.offset() == 300);
    f.panel.set_fixed_offset(999999);  // clamped to the document
    f.gui.frame();
    CHECK(f.panel.offset() == f.doc->size());
}

TEST_CASE("panels: Bitmap click jumps, drag selects, keys scroll (and fix the offset)") {
    BitmapFixture f;
    f.panel.format = PixelFormat::RGB24;
    f.gui.frame();
    f.gui.click(f.at(3, 2));
    REQUIRE(f.jumps.size() == 1);
    CHECK(f.jumps[0] == (2 * 64 + 3) * 3);
    CHECK(f.selects.empty());

    f.gui.drag(f.at(1, 0), f.at(11, 0));  // 20 px: a drag, not a click
    CHECK(f.jumps.size() == 1);
    REQUIRE(f.selects.size() == 1);
    CHECK(f.selects[0] == std::make_pair(uint64_t(3), uint64_t(11 * 3)));  // pixels 1..11

    // The window has focus after the clicks: Down scrolls one row, End to the last page. (8 pixels
    // = 24 bytes per row: 171 rows, more than a page at 4x.)
    f.panel.width = 8;
    f.panel.zoom = 4;
    f.gui.frame();
    CHECK(f.panel.source == BitmapSource::FollowView);
    f.gui.key(ImGuiKey_DownArrow);
    CHECK(f.panel.source == BitmapSource::Fixed);
    CHECK(f.panel.offset() == 24);
    CHECK(f.px(0, 0) == rgba(24, 25, 26));
    f.gui.key(ImGuiKey_End);
    const uint64_t last_page = f.panel.offset();
    CHECK(last_page > 24);
    CHECK(last_page % 24 == 0);
    CHECK(last_page + uint64_t(f.panel.shown_rows() - 1) * 24 >= f.doc->size() - 24);  // shows the end
    f.gui.key(ImGuiKey_Home);
    CHECK(f.panel.offset() == 0);
}
