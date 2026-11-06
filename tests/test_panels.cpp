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
#include <filesystem>
#include <fstream>
#include <system_error>
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
#include "core/session.h"
#include "core/settings.h"
#include "ui/panel_bitmap.h"
#include "ui/panel_packets.h"
#include "ui/panel_strings.h"
#include "ui/panel_xor.h"
#include "pcap_fixture.h"

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
    // (The Stream column is numbered on a worker of its own after the index: wait for it too.)
    while (!panel.row_pos(5, x, y) || panel.stream_of(doc->id(), 5) == kNoStream) {
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

namespace {

// Draws frames until the index of `doc` is shown (row 0 drawn).
void wait_index(Gui& gui, PacketsPanel& panel) {
    float x = 0, y = 0;
    const auto t0 = std::chrono::steady_clock::now();
    while (!panel.row_pos(0, x, y)) {
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        gui.frame();
    }
}
// Draws frames until `done()` (workers: filter / stream jobs).
void wait_for(Gui& gui, const std::function<bool()>& done) {
    const auto t0 = std::chrono::steady_clock::now();
    while (!done()) {
        REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        gui.frame();
    }
}
void type(Gui& gui, const char* s) {
    ImGui::GetIO().AddInputCharactersUTF8(s);
    gui.frame();
    gui.frame();
}
void select_all(Gui& gui) {
    ImGuiIO& io = ImGui::GetIO();
    io.AddKeyEvent(ImGuiMod_Ctrl, true);
    io.AddKeyEvent(ImGuiKey_A, true);
    gui.frame();
    io.AddKeyEvent(ImGuiKey_A, false);
    io.AddKeyEvent(ImGuiMod_Ctrl, false);
    gui.frame();
}

}  // namespace

TEST_CASE("panels: Packets filter box: expressions, inline error, previous filter kept, worker filter") {
    Gui gui;
    std::vector<pcapfx::Bytes> frames;
    for (int i = 0; i < 6; ++i)
        frames.push_back(pcapfx::udp_frame("10.0.0.1", 5000, "10.0.0.2", uint16_t(1000 + i), pcapfx::str("payload")));
    frames.push_back(pcapfx::tcp_frame("10.0.0.1", 51000, "10.0.0.2", 80, 1, 1, pcapfx::ACK, pcapfx::str("GET")));
    frames.push_back(pcapfx::arp_frame());
    frames.push_back(pcapfx::tcp_frame("10.0.0.2", 80, "10.0.0.1", 51000, 1, 4, pcapfx::ACK, pcapfx::str("200")));
    const pcapfx::Bytes cap = pcapfx::pcap_file(frames);
    auto doc = Document::create_from_bytes("cap.pcap", cap.data(), cap.size());
    PacketsPanel panel;
    std::vector<std::pair<uint64_t, uint64_t>> selects;
    PacketsPanelCallbacks cb;
    cb.select = [&](uint64_t off, uint64_t len) { selects.emplace_back(off, len); };
    gui.body = [&] { panel.draw(doc.get(), {}, cb); };
    wait_index(gui, panel);
    const uint64_t id = doc->id();
    CHECK(panel.shown_rows(id) == 9);

    float fx = 0, fy = 0;
    REQUIRE(panel.filter_box_pos(fx, fy));
    gui.click(ImVec2(fx, fy));
    type(gui, "udp.dstport == 1002");
    CHECK(panel.applied_filter(id) == "udp.dstport == 1002");
    CHECK(panel.filter_error(id).empty());
    CHECK(panel.shown_rows(id) == 1);
    float x = 0, y = 0;
    REQUIRE(panel.row_pos(0, x, y));
    CHECK_FALSE(panel.row_pos(1, x, y));
    gui.click(ImVec2(x, y));
    CHECK(panel.selected_packet(id) == 2);  // the filtered row shows packet #3
    REQUIRE(selects.size() == 1);

    // An incomplete expression: error at its end, the previous filter stays.
    gui.click(ImVec2(fx, fy));
    type(gui, " and");
    size_t pos = 0;
    CHECK_FALSE(panel.filter_error(id, &pos).empty());
    CHECK(pos == 23);
    CHECK(panel.applied_filter(id) == "udp.dstport == 1002");
    CHECK(panel.shown_rows(id) == 1);
    type(gui, " not arp");
    CHECK(panel.filter_error(id).empty());
    CHECK(panel.applied_filter(id) == "udp.dstport == 1002 and not arp");
    CHECK(panel.shown_rows(id) == 1);

    // Replace the whole text.
    select_all(gui);
    type(gui, "tcp or arp");
    CHECK(panel.applied_filter(id) == "tcp or arp");
    CHECK(panel.shown_rows(id) == 3);
    type(gui, " or ip.addr == 10.0.0.300");
    CHECK(panel.filter_error(id).find("address") != std::string::npos);
    CHECK(panel.shown_rows(id) == 3);

    // Above filter_sync_max the filter runs on a worker: no rows until it is done.
    panel.filter_sync_max = 0;
    select_all(gui);
    type(gui, "\"seq=1 ack=4\" or udp.port == 1005");
    CHECK(panel.applied_filter(id) == "\"seq=1 ack=4\" or udp.port == 1005");
    wait_for(gui, [&] { return panel.shown_rows(id) != SIZE_MAX; });
    gui.frame();
    CHECK(panel.shown_rows(id) == 2);
    REQUIRE(panel.row_pos(1, x, y));
    gui.click(ImVec2(x, y));
    CHECK(panel.selected_packet(id) == 8);
    CHECK_FALSE(panel.wants_frames());

    // Empty text: no filter.
    gui.click(ImVec2(fx, fy));
    select_all(gui);
    ImGui::GetIO().AddKeyEvent(ImGuiKey_Delete, true);
    gui.frame();
    ImGui::GetIO().AddKeyEvent(ImGuiKey_Delete, false);
    gui.frame();
    CHECK(panel.applied_filter(id).empty());
    CHECK(panel.shown_rows(id) == 9);
}

TEST_CASE("panels: Packets worker filter never adopts a result made for the previous index") {
    // A worker filter run finishes unseen while the capture is re-indexed (here: after the last
    // packets were deleted); the next draw takes the new index and restarts the filter. The old
    // run's matches (same filter text, old packet numbers) must not be shown for the new index.
    Gui gui;
    std::vector<pcapfx::Bytes> frames;
    for (int i = 0; i < 20000; ++i)
        frames.push_back(i < 19900 ? pcapfx::udp_frame("10.0.0.1", 5000, "10.0.0.2", 53, pcapfx::str("q"))
                                   : pcapfx::tcp_frame("10.0.0.1", 51000, "10.0.0.2", 80, 1, 1, pcapfx::ACK));
    const pcapfx::Bytes cap = pcapfx::pcap_file(frames);
    auto doc = Document::create_from_bytes("cap.pcap", cap.data(), cap.size());
    PacketsPanel panel;
    panel.filter_sync_max = 0;  // always the worker
    PacketsPanelCallbacks cb;
    gui.body = [&] { panel.draw(doc.get(), {}, cb); };
    wait_index(gui, panel);
    const uint64_t id = doc->id();
    float fx = 0, fy = 0;
    REQUIRE(panel.filter_box_pos(fx, fy));
    gui.click(ImVec2(fx, fy));
    // Delete the last 50 packets, then in one frame: re-index and type the filter (the worker
    // filter starts over the old index, the new index is being built).
    const uint64_t rec = 16 + frames.back().size();
    REQUIRE(doc->erase(doc->size() - 50 * rec, 50 * rec));
    panel.request_index();
    ImGui::GetIO().AddInputCharactersUTF8("tcp");
    gui.frame();
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));  // both workers finish unseen
    wait_for(gui, [&] { return panel.shown_rows(id) != SIZE_MAX; });
    CHECK(panel.applied_filter(id) == "tcp");
    CHECK(panel.shown_rows(id) == 50);
}

TEST_CASE("panels: Packets Follow TCP Stream / Open Packet as Tab / Filter Conversation") {
    Gui gui;
    std::vector<pcapfx::Bytes> f;
    using pcapfx::ACK;
    using pcapfx::PSH;
    using pcapfx::SYN;
    f.push_back(pcapfx::udp_frame("10.0.0.9", 53, "10.0.0.1", 4000, pcapfx::str("dns")));
    f.push_back(pcapfx::tcp_frame("10.0.0.1", 51000, "10.0.0.2", 80, 100, 0, SYN));
    f.push_back(pcapfx::tcp_frame("10.0.0.2", 80, "10.0.0.1", 51000, 900, 101, SYN | ACK));
    f.push_back(pcapfx::tcp_frame("10.0.0.1", 51000, "10.0.0.2", 80, 101, 901, PSH | ACK, pcapfx::str("GET /")));
    f.push_back(pcapfx::tcp_frame("10.0.0.2", 80, "10.0.0.1", 51000, 901, 106, PSH | ACK, pcapfx::str("200 OK")));
    f.push_back(pcapfx::tcp_frame("10.0.0.1", 51001, "10.0.0.2", 80, 5, 5, PSH | ACK, pcapfx::str("other")));
    const pcapfx::Bytes cap = pcapfx::pcapng_file(f);
    auto doc = Document::create_from_bytes("cap.pcapng", cap.data(), cap.size());
    PacketsPanel panel;
    std::vector<std::string> notes;
    struct Opened {
        std::string name;
        std::vector<uint8_t> bytes;
        std::vector<Bookmark> marks;
    };
    std::vector<Opened> opened;
    PacketsPanelCallbacks cb;
    cb.notify = [&](const std::string& m) { notes.push_back(m); };
    cb.open_tab = [&](const std::string& n, const std::vector<uint8_t>& b, const std::vector<Bookmark>& m) {
        opened.push_back(Opened{n, b, m});
    };
    gui.body = [&] { panel.draw(doc.get(), {}, cb); };
    const uint64_t id = doc->id();

    // Requested before the index exists, no row selected: the packet under the caret (#5), once
    // the index is ready.
    PcapIndexResult ix;
    index_pcap(*doc->snapshot(), ix);
    REQUIRE(ix.packets.size() == 6);
    doc->view().cursor = doc->view().anchor = ix.packets[4].data_off + 20;
    panel.request_follow_stream(true);
    wait_for(gui, [&] { return !opened.empty(); });
    REQUIRE(opened.size() == 1);
    CHECK(opened[0].name == "TCP 10.0.0.1:51000 > 10.0.0.2:80 (interleaved)");
    CHECK(std::string(opened[0].bytes.begin(), opened[0].bytes.end()) == "GET /200 OK");
    REQUIRE(opened[0].marks.size() == 2);
    CHECK(opened[0].marks[0].name == "#4 C>S");
    CHECK(opened[0].marks[1].name == "#5 S>C");
    CHECK(opened[0].marks[1].offset == 5);
    CHECK(notes.back().find("TCP stream: 5 bytes client -> server, 6 bytes server -> client") == 0);
    CHECK(panel.selected_packet(id) == 4);
    CHECK_FALSE(panel.stream_running());
    // The capture's list now shows that conversation only.
    CHECK(panel.applied_filter(id) == "ip.addr == 10.0.0.2 and ip.addr == 10.0.0.1 and tcp.port == 80 and tcp.port == 51000");
    gui.frame();
    CHECK(panel.shown_rows(id) == 4);

    // Sequential, from the selected row (a click on row 0 = packet #2, the SYN).
    float x = 0, y = 0;
    REQUIRE(panel.row_pos(0, x, y));
    gui.click(ImVec2(x, y));
    CHECK(panel.selected_packet(id) == 1);
    panel.request_follow_stream(false);
    wait_for(gui, [&] { return opened.size() == 2; });
    CHECK(opened[1].name == "TCP 10.0.0.1:51000 > 10.0.0.2:80");
    CHECK(std::string(opened[1].bytes.begin(), opened[1].bytes.end()) == "GET /200 OK");

    // Open Packet / Payload as Tab.
    panel.request_open_packet(false);
    gui.frame();
    REQUIRE(opened.size() == 3);
    CHECK(opened[2].name == "cap.pcapng #2");
    CHECK(opened[2].bytes.size() == ix.packets[1].cap_len);
    CHECK(opened[2].marks.empty());  // a SYN has no payload
    REQUIRE(panel.row_pos(2, x, y));
    gui.click(ImVec2(x, y));
    CHECK(panel.selected_packet(id) == 3);
    panel.request_open_packet(true);
    gui.frame();
    REQUIRE(opened.size() == 4);
    CHECK(opened[3].name == "cap.pcapng #4 payload");
    CHECK(std::string(opened[3].bytes.begin(), opened[3].bytes.end()) == "GET /");
    panel.request_open_packet(false);
    gui.frame();
    REQUIRE(opened.size() == 5);
    REQUIRE(opened[4].marks.size() == 1);
    CHECK(opened[4].marks[0].name == "TCP payload");
    CHECK(opened[4].marks[0].offset == 14 + 20 + 20);
    CHECK(opened[4].marks[0].length == 5);

    // A UDP packet: no stream; its conversation filter uses udp ports.
    gui.click(ImVec2(x, y));  // keeps the selection
    panel.request_conversation_filter();
    gui.frame();
    CHECK(panel.applied_filter(id) == "ip.addr == 10.0.0.1 and ip.addr == 10.0.0.2 and tcp.port == 51000 and tcp.port == 80");
    float fx = 0, fy = 0;
    REQUIRE(panel.filter_box_pos(fx, fy));
    gui.click(ImVec2(fx, fy));
    select_all(gui);
    type(gui, "udp");
    REQUIRE(panel.shown_rows(id) == 1);
    REQUIRE(panel.row_pos(0, x, y));
    gui.click(ImVec2(x, y));
    CHECK(panel.selected_packet(id) == 0);
    panel.request_follow_stream(false);
    gui.frame();
    gui.frame();
    CHECK(opened.size() == 5);
    CHECK(notes.back() == "Follow TCP Stream: packet #1 is not a TCP packet");
    panel.request_conversation_filter();
    gui.frame();
    CHECK(panel.applied_filter(id) == "ip.addr == 10.0.0.9 and ip.addr == 10.0.0.1 and udp.port == 53 and udp.port == 4000");

    // Not a capture: the request is dropped with a message.
    const std::vector<uint8_t> junk(64, 0x11);
    auto other = Document::create_from_bytes("junk.bin", junk.data(), junk.size());
    gui.body = [&] { panel.draw(other.get(), {}, cb); };
    panel.request_follow_stream(false);
    gui.frame();
    gui.frame();
    CHECK(opened.size() == 5);
    CHECK(notes.back().find("not a pcap") != std::string::npos);
}

TEST_CASE("panels: Packets live tail: appended records are indexed incrementally (selection, filter, Stream)") {
    std::error_code ec;
    const std::filesystem::path dir =
        std::filesystem::temp_directory_path(ec) /
        ("hexer_panels_tail_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    REQUIRE(std::filesystem::create_directories(dir, ec));
    std::vector<pcapfx::Bytes> frames;
    for (int i = 0; i < 12; ++i) {
        if (i % 3 == 2)
            frames.push_back(pcapfx::tcp_frame("10.0.0.1", uint16_t(51000 + i % 2), "10.0.0.2", 80, 1, 1, pcapfx::ACK));
        else
            frames.push_back(pcapfx::udp_frame("10.0.0.3", uint16_t(4000 + i % 4), "10.0.0.4", 53, pcapfx::str("q")));
    }
    const pcapfx::Bytes full = pcapfx::pcap_file(frames);
    const size_t first = 24 + 6 * 76;  // header + 6 records (frames padded to 60 bytes)
    const std::filesystem::path path = dir / "live.pcap";
    auto write = [&](size_t from, size_t to, bool append) {
        std::ofstream f(path, std::ios::binary | (append ? std::ios::app : std::ios::trunc));
        f.write(reinterpret_cast<const char*>(full.data() + from), std::streamsize(to - from));
    };
    write(0, first, false);
    {
        auto doc = Document::open_file(path.string());
        REQUIRE(doc);
        REQUIRE(doc->refresh_appended() == GrowResult::Unchanged);
        const uint64_t id = doc->id();
        Gui gui;
        PacketsPanel panel;
        std::vector<std::string> notes;
        PacketsPanelCallbacks cb;
        cb.notify = [&](const std::string& m) { notes.push_back(m); };
        gui.body = [&] { panel.draw(doc.get(), {}, cb); };
        wait_index(gui, panel);
        CHECK(panel.indexed_packets(id) == 6);
        CHECK_FALSE(panel.last_index_incremental(id));
        // Stream numbers (UDP ports 4000, 4001, 4003, 4002 in order of appearance -> 0..3; TCP 51000 /
        // 51001 -> 0 / 1)
        wait_for(gui, [&] { return panel.stream_of(id, 5) != kNoStream; });
        CHECK(panel.stream_of(id, 0) == 0);
        CHECK(panel.stream_of(id, 1) == 1);
        CHECK(panel.stream_of(id, 2) == 0);  // TCP
        CHECK(panel.stream_of(id, 3) == 2);
        CHECK(panel.stream_of(id, 5) == 1);  // TCP 51001
        // Select row 1, filter "udp".
        float x = 0, y = 0;
        REQUIRE(panel.row_pos(1, x, y));
        gui.click(ImVec2(x, y));
        CHECK(panel.selected_packet(id) == 1);
        float fx = 0, fy = 0;
        REQUIRE(panel.filter_box_pos(fx, fy));
        gui.click(ImVec2(fx, fy));
        type(gui, "udp");
        wait_for(gui, [&] { return panel.shown_rows(id) != SIZE_MAX; });
        CHECK(panel.shown_rows(id) == 4);
        const size_t notes_before = notes.size();

        // The capture grows (the second half of a record, then the rest): only the new records are read.
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        write(first, full.size(), true);
        const uint64_t g0 = doc->generation();
        REQUIRE(doc->refresh_appended() == GrowResult::Grown);
        panel.appended(id, g0, doc->generation());
        wait_for(gui, [&] { return panel.indexed_packets(id) == 12 && panel.shown_rows(id) == 8; });
        CHECK(panel.last_index_incremental(id));
        CHECK(panel.selected_packet(id) == 1);  // kept
        CHECK(panel.applied_filter(id) == "udp");
        wait_for(gui, [&] { return panel.stream_of(id, 11) != kNoStream; });
        CHECK(panel.stream_of(id, 1) == 1);
        CHECK(panel.stream_of(id, 6) == 3);   // UDP 4002: new
        CHECK(panel.stream_of(id, 8) == 0);   // TCP 51000 again
        CHECK(panel.stream_of(id, 11) == 1);  // TCP 51001 again
        CHECK(notes.size() == notes_before);  // an append is quiet

        // An edit between two growths: the index is no longer the document's, no automatic append.
        const uint8_t z = 0;
        REQUIRE(doc->overwrite(30, &z, 1));
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        write(0, 24 + 76, true);  // one more record (a copy of the first one)
        const uint64_t g1 = doc->generation();
        REQUIRE(doc->refresh_appended() == GrowResult::Grown);
        panel.appended(id, g1, doc->generation());
        for (int i = 0; i < 20; ++i) gui.frame();
        CHECK(panel.indexed_packets(id) == 12);
    }
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("panels: Packets Follow UDP Stream (palette request, toolbar Any) and its messages") {
    Gui gui;
    std::vector<pcapfx::Bytes> f;
    f.push_back(pcapfx::udp_frame("10.0.0.5", 5353, "10.0.0.9", 53, pcapfx::str("ask")));
    f.push_back(pcapfx::tcp_frame("10.0.0.1", 51000, "10.0.0.2", 80, 100, 0, pcapfx::SYN));
    f.push_back(pcapfx::udp_frame("10.0.0.9", 53, "10.0.0.5", 5353, pcapfx::str("reply")));
    f.push_back(pcapfx::arp_frame());
    const pcapfx::Bytes cap = pcapfx::pcap_file(f);
    auto doc = Document::create_from_bytes("cap.pcap", cap.data(), cap.size());
    PacketsPanel panel;
    std::vector<std::string> notes, names;
    std::vector<std::string> texts;
    PacketsPanelCallbacks cb;
    cb.notify = [&](const std::string& m) { notes.push_back(m); };
    cb.open_tab = [&](const std::string& n, const std::vector<uint8_t>& b, const std::vector<Bookmark>&) {
        names.push_back(n);
        texts.emplace_back(b.begin(), b.end());
    };
    gui.body = [&] { panel.draw(doc.get(), {}, cb); };
    const uint64_t id = doc->id();
    wait_index(gui, panel);
    float x = 0, y = 0;
    REQUIRE(panel.row_pos(2, x, y));
    gui.click(ImVec2(x, y));
    CHECK(panel.selected_packet(id) == 2);
    panel.request_follow_stream(true, PacketsPanel::FollowProto::Udp);
    wait_for(gui, [&] { return !names.empty() && !panel.stream_running(); });
    CHECK(names[0] == "UDP 10.0.0.5:5353 > 10.0.0.9:53 (interleaved)");
    CHECK(texts[0] == "askreply");
    CHECK(notes.back() == "UDP stream: 3 bytes client -> server, 5 bytes server -> client, 2 datagrams");
    CHECK(panel.applied_filter(id) ==
          "ip.addr == 10.0.0.9 and ip.addr == 10.0.0.5 and udp.port == 53 and udp.port == 5353");
    // The palette's TCP action on a UDP packet refuses; Any follows what the packet is.
    panel.request_follow_stream(false, PacketsPanel::FollowProto::Tcp);
    gui.frame();
    gui.frame();
    CHECK(notes.back() == "Follow TCP Stream: packet #3 is not a TCP packet");
    panel.request_follow_stream(false, PacketsPanel::FollowProto::Any);
    wait_for(gui, [&] { return names.size() == 2 && !panel.stream_running(); });
    CHECK(names[1] == "UDP 10.0.0.5:5353 > 10.0.0.9:53");
    CHECK(texts[1] == "askreply");
    // UDP on a TCP packet / Any on ARP: refused with the protocol in the message.
    float fx = 0, fy = 0;
    REQUIRE(panel.filter_box_pos(fx, fy));
    gui.click(ImVec2(fx, fy));
    select_all(gui);
    type(gui, "not udp");
    wait_for(gui, [&] { return panel.shown_rows(id) == 2; });
    REQUIRE(panel.row_pos(0, x, y));
    gui.click(ImVec2(x, y));
    CHECK(panel.selected_packet(id) == 1);
    panel.request_follow_stream(false, PacketsPanel::FollowProto::Udp);
    gui.frame();
    gui.frame();
    CHECK(notes.back() == "Follow UDP Stream: packet #2 is not a UDP packet");
    REQUIRE(panel.row_pos(1, x, y));
    gui.click(ImVec2(x, y));
    CHECK(panel.selected_packet(id) == 3);
    panel.request_follow_stream(false, PacketsPanel::FollowProto::Any);
    gui.frame();
    gui.frame();
    CHECK(notes.back() == "Follow Stream: packet #4 is not a TCP or UDP packet");
    CHECK(names.size() == 2);
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

TEST_CASE("panels: Bitmap zoom below 1x averages blocks; Fit downscales a very wide image") {
    // 4 rows of 4096 gray pixels: columns alternate black / white in blocks of 4, rows 2..3 are 0.
    BitmapFixture f;
    Bytes wide(4096 * 4, 0);
    for (size_t x = 0; x < 4096; ++x) wide[x] = wide[4096 + x] = ((x / 4) % 2) ? 255 : 0;
    f.doc = Document::create_from_bytes("wide.bin", wide.data(), wide.size());
    f.panel.width = 4096;
    f.panel.zoom = -4;
    f.gui.frame();
    REQUIRE(f.panel.decoded());
    CHECK(f.panel.shown_step() == 4);
    CHECK(f.panel.shown_zoom() == 1);
    CHECK(f.px(0, 0) == rgba(0, 0, 0));
    CHECK(f.px(1, 0) == rgba(128, 128, 128));  // 8 of the 16 pixels are white (2040 / 16, rounded)
    CHECK((f.px(0, 1) >> 24) == 0);              // past the data: the missing marker
    // A click on a cell = the first byte of its block.
    f.gui.click(f.at(3, 0));
    REQUIRE(f.jumps.size() == 1);
    CHECK(f.jumps[0] == 12);
    // Ctrl+wheel steps through the levels: 1/4x -> 1/2x -> 1x, and down to 1/16x at most.
    ImGuiIO& io = ImGui::GetIO();
    for (int i = 0; i < 2; ++i) {
        io.AddKeyEvent(ImGuiMod_Ctrl, true);
        io.AddMouseWheelEvent(0.0f, 1.0f);
        f.gui.frame();
        io.AddKeyEvent(ImGuiMod_Ctrl, false);
        f.gui.frame();
    }
    CHECK(f.panel.zoom == 1);
    for (int i = 0; i < 6; ++i) {
        io.AddKeyEvent(ImGuiMod_Ctrl, true);
        io.AddMouseWheelEvent(0.0f, -1.0f);
        f.gui.frame();
        io.AddKeyEvent(ImGuiMod_Ctrl, false);
        f.gui.frame();
    }
    CHECK(f.panel.zoom == -16);
    // Fit: the smallest downscale at which a whole row fits (4096 / 8 = 512 cells <= ~880 px).
    f.panel.fit_width = true;
    f.gui.frame();
    CHECK(f.panel.zoom == -8);
    CHECK(f.panel.shown_step() == 8);
    CHECK(f.panel.shown_cols() == 512);
    CHECK(f.px(0, 0) == rgba(64, 64, 64));  // 8 white of the 32 pixels there (rows 4..7 are past the end)
    // The level is a setting like any zoom.
    Settings s;
    CHECK(f.panel.save_settings(s));
    CHECK(s.bitmap_zoom == -8);
    BitmapPanel other;
    other.load_settings(s);
    CHECK(other.zoom == -8);
}

TEST_CASE("panels: Bitmap downscale of a short wide image stays within the byte budget") {
    // 20 rows of 8192 RGBA pixels (640 KiB) at 1/16x: the panel is many cell rows tall, but only
    // the 2 cell rows that hold data are gathered (not panel rows x 16 sampled rows of 32 KiB).
    BitmapFixture f;
    Bytes img(size_t(8192) * 4 * 20, 0);
    for (size_t i = 0; i < img.size(); i += 4) img[i] = img[i + 3] = 255;  // opaque red
    f.doc = Document::create_from_bytes("short.bin", img.data(), img.size());
    f.panel.format = PixelFormat::RGBA32;
    f.panel.width = 8192;
    f.panel.zoom = -16;
    f.gui.frame();
    REQUIRE(f.panel.decoded());
    CHECK(f.panel.shown_step() == 16);
    CHECK(f.panel.shown_rows() > 2);
    CHECK(f.panel.read_buffer_bytes() <= BitmapPanel::kMaxBytes);
    CHECK(f.panel.decoded_pixel_count() * 4 <= BitmapPanel::kMaxBytes * 2);
    CHECK(f.px(0, 0) == rgba(255, 0, 0, 255));
    CHECK(f.px(0, 1) == rgba(255, 0, 0, 255));  // rows 16..19 of the image
    CHECK((f.px(0, 2) >> 24) == 0);              // past the data: the missing marker
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

// =============================================================================================
// Persistence: panel options <-> Settings, per-document Packets state <-> Document extras
// =============================================================================================

TEST_CASE("panels: Strings / XOR / Bitmap / Packets options load from and save to Settings") {
    Settings s;
    {  // defaults: the panels' own defaults are the settings' defaults (nothing to save)
        StringsPanel sp;
        XorPanel xp;
        BitmapPanel bp;
        PacketsPanel pp;
        CHECK_FALSE(sp.save_settings(s));
        CHECK_FALSE(xp.save_settings(s));
        CHECK_FALSE(bp.save_settings(s));
        CHECK_FALSE(pp.save_settings(s));
        bp.shutdown();
    }
    StringsPanel sp;
    sp.options.ascii = false;
    sp.options.utf16be = true;
    sp.options.include_newlines = true;
    sp.options.min_length = 9;
    CHECK(sp.save_settings(s));
    CHECK_FALSE(sp.save_settings(s));  // unchanged now
    CHECK_FALSE(s.strings_ascii);
    CHECK(s.strings_utf16le);
    CHECK(s.strings_utf16be);
    CHECK(s.strings_newlines);
    CHECK(s.strings_min_length == 9);
    StringsPanel sp2;
    sp2.load_settings(s);
    CHECK_FALSE(sp2.options.ascii);
    CHECK(sp2.options.utf16be);
    CHECK(sp2.options.include_newlines);
    CHECK(sp2.options.min_length == 9);

    XorPanel xp;
    xp.options.rol = false;
    xp.options.xor_multi = true;
    xp.options.max_key_len = 5;
    CHECK(xp.save_settings(s));
    CHECK_FALSE(xp.save_settings(s));
    XorPanel xp2;
    xp2.load_settings(s);
    CHECK(xp2.options.xor8);
    CHECK_FALSE(xp2.options.rol);
    CHECK(xp2.options.xor_multi);
    CHECK_FALSE(xp2.options.add_multi);
    xp.options.add_multi = true;  // multi-byte ADD keys
    CHECK(xp.save_settings(s));
    CHECK(s.xor_add_key);
    xp2.load_settings(s);
    CHECK(xp2.options.add_multi);
    CHECK(xp2.options.max_key_len == 5);
    s.xor_max_key_len = 99;  // a hand-edited value out of range is clamped
    xp2.load_settings(s);
    CHECK(xp2.options.max_key_len == kXorMaxKeyLen);

    BitmapPanel bp;
    bp.format = PixelFormat::RGB24;
    bp.width = 640;
    bp.zoom = 3;
    bp.fit_width = true;
    bp.use_alpha = true;
    bp.source = BitmapSource::FollowCursor;
    CHECK(bp.save_settings(s));
    CHECK(s.bitmap_format == "RGB 24-bit");
    CHECK(s.bitmap_source == 1);
    // "Fixed offset" is not a setting: the saved follow source stays.
    bp.set_fixed_offset(0x1234);
    CHECK_FALSE(bp.save_settings(s));
    CHECK(s.bitmap_source == 1);
    BitmapPanel bp2;
    bp2.load_settings(s);
    CHECK(bp2.format == PixelFormat::RGB24);
    CHECK(bp2.width == 640);
    CHECK(bp2.zoom == 3);
    CHECK(bp2.fit_width);
    CHECK(bp2.use_alpha);
    CHECK(bp2.source == BitmapSource::FollowCursor);
    s.bitmap_format = "no such format";
    s.bitmap_width = 0;
    bp2.load_settings(s);
    CHECK(bp2.format == PixelFormat::Gray8);
    CHECK(bp2.width == 1);
    bp.shutdown();
    bp2.shutdown();

    PacketsPanel pp;
    pp.absolute_time = true;
    pp.request_follow_stream(true);  // the palette's last choice
    CHECK(pp.save_settings(s));
    CHECK(s.packets_absolute_time);
    CHECK_FALSE(s.packets_payload_only);
    CHECK(s.packets_follow_interleaved);
    PacketsPanel pp2;
    pp2.load_settings(s);
    CHECK(pp2.absolute_time);
    CHECK_FALSE(pp2.payload_only);
    CHECK(pp2.follow_interleaved);
}

TEST_CASE("panels: Packets filter and parser survive a session round trip (Document extras)") {
    std::error_code ec;
    const std::filesystem::path dir =
        std::filesystem::temp_directory_path(ec) /
        ("hexer_panels_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    REQUIRE(std::filesystem::create_directories(dir, ec));
    const Bytes cap = make_pcap(12);
    const std::string filter = "udp.dstport == 1003 or udp.dstport == 1007";
    {
        Gui gui;
        auto doc = Document::create_from_bytes("cap.pcap", cap.data(), cap.size());
        auto plain = Document::create_from_bytes("plain.bin", cap.data(), 10);
        PacketsPanel panel;
        // A document the panel never saw: no extras.
        panel.save_extras(*plain);
        CHECK(plain->extras().empty());
        // Set the state as restore_extras does (same as typing into the box / picking a parser).
        doc->set_extra("packets.filter", filter);
        doc->set_extra("packets.parser", "My proto");
        panel.restore_extras(*doc);
        doc->set_extra("packets.filter", "");
        doc->set_extra("packets.parser", "");
        gui.body = [&] { panel.draw(doc.get(), {}, {}); };
        wait_index(gui, panel);
        wait_for(gui, [&] { return panel.shown_rows(doc->id()) != SIZE_MAX; });
        CHECK(panel.applied_filter(doc->id()) == filter);
        CHECK(panel.shown_rows(doc->id()) == 2);
        panel.save_extras(*doc);
        CHECK(doc->extra("packets.filter") == filter);
        CHECK(doc->extra("packets.parser") == "My proto");
        Session s(dir.string());
        REQUIRE(s.save({doc.get()}, 0));
    }
    Session s(dir.string());
    auto r = s.load();
    REQUIRE(r.docs.size() == 1);
    Document& doc = *r.docs[0];
    Gui gui;
    PacketsPanel panel;
    panel.restore_extras(doc);  // before the capture is indexed: applied once the index is there
    gui.body = [&] { panel.draw(&doc, {}, {}); };
    wait_index(gui, panel);
    wait_for(gui, [&] { return panel.shown_rows(doc.id()) != SIZE_MAX; });
    CHECK(panel.applied_filter(doc.id()) == filter);
    CHECK(panel.shown_rows(doc.id()) == 2);
    // Clearing them erases the extras again.
    PacketsPanel fresh;
    fresh.save_extras(doc);
    CHECK(doc.extra("packets.filter").empty());
    CHECK(doc.extra("packets.parser").empty());
    // An invalid saved filter shows its error and filters nothing.
    doc.set_extra("packets.filter", "ip.src ==");
    PacketsPanel bad;
    bad.restore_extras(doc);
    gui.body = [&] { bad.draw(&doc, {}, {}); };
    wait_index(gui, bad);
    CHECK(bad.applied_filter(doc.id()).empty());
    CHECK_FALSE(bad.filter_error(doc.id()).empty());
    CHECK(bad.shown_rows(doc.id()) == 12);
    s.clear();
    std::filesystem::remove_all(dir, ec);
}
