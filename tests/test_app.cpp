// Headless App-level tests: the whole App (ui/app.cpp + panels.cpp: menus, tabs, panels, session)
// without a window or GL context, through the driver in ui/app_internal.h (app_startup /
// app_frame / app_shutdown, run_named_action). Each HeadlessApp owns its ImGui context (docking,
// io.DisplaySize set by hand, ImGuiBackendFlags_RendererHasTextures so fonts bake on demand) and
// a temporary config dir, so the hot-exit session one App writes is what the next one restores.
#include <doctest/doctest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include "imgui.h"

#include "core/document.h"
#include "core/highlight.h"
#include "core/os_file.h"
#include "core/settings.h"
#include "ui/app_internal.h"
#include "ui/panel_history.h"
#include "ui/panels.h"
#include "ui/theme.h"

using namespace hx;

namespace {

using Bytes = std::vector<uint8_t>;

struct TempDir {
    std::string path;
    TempDir() {
        std::error_code ec;
        std::string base = std::filesystem::temp_directory_path(ec).string();
        if (ec || base.empty()) base = ".";
        path = path_join(base, "hexer_app_" + std::to_string(std::random_device{}()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        REQUIRE(os_mkdirs(path));
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(std::filesystem::path(path), ec);
    }
    std::string file(const std::string& name, const Bytes& data) const {
        const std::string p = path_join(path, name);
        std::string err;
        REQUIRE(os_write_whole_atomic(p, data.data(), data.size(), &err));
        return p;
    }
};

Bytes pattern(size_t n, unsigned seed) {
    Bytes b(n);
    std::mt19937 rng(seed);
    for (auto& v : b) v = uint8_t(rng());
    return b;
}

// One App without a window: startup in the constructor, shutdown (hot-exit session written) in
// the destructor.
struct HeadlessApp {
    ImGuiContext* ctx = nullptr;
    std::unique_ptr<App> app;

    HeadlessApp(const std::string& config_dir, std::vector<std::string> files, bool no_session = false) {
        paths::set_config_dir_override(config_dir);
        paths::ensure_dirs();
        ctx = ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.LogFilename = nullptr;
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
        io.BackendFlags |= ImGuiBackendFlags_RendererHasTextures;
        io.DisplaySize = ImVec2(1600, 1000);
        ImFont* font = io.Fonts->AddFontDefault();
        apply_dark_theme(1.0f);
        app = std::make_unique<App>();
        app->opts.files = std::move(files);
        app->opts.no_session = no_session;
        app->settings.load(paths::settings_file());
        app->fonts.ui = app->fonts.mono = font;
        app->build_layout = true;  // no layout.ini: the default dock layout
        app_startup(*app);
        frames(5);  // the layout settles (its focus steps)
    }
    ~HeadlessApp() {
        app_shutdown(*app);
        app.reset();
        ImGui::DestroyContext(ctx);
    }

    void frames(int n = 1) {
        for (int i = 0; i < n; ++i) {
            ImGuiIO& io = ImGui::GetIO();
            io.DisplaySize = ImVec2(1600, 1000);
            io.DeltaTime = 1.0f / 60.0f;
            ImGui::NewFrame();
            app_frame(*app);
            ImGui::Render();
        }
    }
    // Frames until `done` holds (fails after 30 s).
    void frames_until(const std::function<bool()>& done) {
        const auto t0 = std::chrono::steady_clock::now();
        while (!done()) {
            REQUIRE(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(30));
            frames();
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }
    void action(const std::string& name) {
        std::string err;
        const bool ok = run_named_action(*app, name, &err);
        INFO(name << ": " << err);
        REQUIRE(ok);
        frames(2);
    }
    void select(int tab) {
        app->select_request = tab;
        frames(2);
        REQUIRE(app->active == tab);
    }
    void key(ImGuiKey k) {
        ImGui::GetIO().AddKeyEvent(k, true);
        frames();
        ImGui::GetIO().AddKeyEvent(k, false);
        frames();
    }
    Tab& tab(size_t i) {
        REQUIRE(i < app->tabs.size());
        return *app->tabs[i];
    }
};

}  // namespace

TEST_CASE("app: the session restores tab order, split view, live tail, Parse at and the Compare tab") {
    TempDir dir;
    const std::string cfg = path_join(dir.path, "config");
    const std::string a = dir.file("a.bin", pattern(8192, 1));
    const std::string b = dir.file("b.bin", pattern(8192, 2));
    const std::string c = dir.file("c.bin", pattern(4096, 3));
    int active = -1;
    {
        HeadlessApp h(cfg, {c, a, b});  // tab order = command-line order
        REQUIRE(h.app->tabs.size() == 3);
        CHECK(h.app->hot_exit);
        // a: Parse at 0x20 with the PNG parser.
        h.select(1);
        h.tab(1).doc->view().cursor = h.tab(1).doc->view().anchor = 0x20;
        h.action("Parser: PNG image");
        h.action("Structure: Parse at Cursor");
        CHECK(h.tab(1).doc->view().parse_base == 0x20);
        CHECK(h.tab(1).doc->view().parser == "PNG image");
        // b: split side by side, the second pane active.
        h.select(2);
        h.action("Split Vertically");
        REQUIRE(h.tab(2).split);
        CHECK(h.tab(2).split_vertical);
        h.action("Split View: Switch Pane");
        CHECK(h.tab(2).split_active_pos == 1);
        // c: live tail.
        h.select(0);
        h.action("Toggle Live Tail");
        CHECK(h.tab(0).tail.enabled);
        // a compared with b (the Compare tab shown last).
        h.select(1);
        active = h.app->active;
        h.action("Compare with: b.bin");
        REQUIRE(h.app->diff);
        h.frames_until([&] { return h.app->diff_shown; });
        CHECK(h.app->diff_a == h.tab(1).doc->id());
        CHECK(h.app->diff_b == h.tab(2).doc->id());
    }
    {
        HeadlessApp h(cfg, {});
        REQUIRE(h.app->tabs.size() == 3);
        CHECK(path_filename(h.tab(0).path) == "c.bin");
        CHECK(path_filename(h.tab(1).path) == "a.bin");
        CHECK(path_filename(h.tab(2).path) == "b.bin");
        CHECK(h.app->active == active);
        CHECK(h.tab(0).tail.enabled);
        CHECK_FALSE(h.tab(1).tail.enabled);
        CHECK(h.tab(1).doc->view().parse_base == 0x20);
        CHECK(h.tab(1).doc->view().parser == "PNG image");
        CHECK(h.tab(2).split);
        CHECK(h.tab(2).split_vertical);
        CHECK(h.tab(2).split_active_pos == 1);
        CHECK_FALSE(h.tab(0).split);
        REQUIRE(h.app->diff);
        CHECK(h.app->diff_a == h.tab(1).doc->id());
        CHECK(h.app->diff_b == h.tab(2).doc->id());
        h.frames_until([&] { return h.app->diff_shown; });
        // Changes are written again: end the split and the compare, and the next start has neither.
        h.select(2);
        h.action("Toggle Split View");
        CHECK_FALSE(h.tab(2).split);
        h.action("Close Compare");
        CHECK_FALSE(h.app->diff);
    }
    {
        HeadlessApp h(cfg, {});
        REQUIRE(h.app->tabs.size() == 3);
        CHECK_FALSE(h.tab(2).split);
        CHECK_FALSE(h.app->diff);
        CHECK(h.tab(0).tail.enabled);
    }
}

TEST_CASE("app: script doc:jump / doc:select are Back / Forward jumps; Reset Layout closes on-demand panels") {
    TempDir dir;
    const std::string f = dir.file("j.bin", pattern(65536, 9));
    HeadlessApp h(path_join(dir.path, "config"), {f}, true);
    Document& d = *h.tab(0).doc;
    d.view().cursor = d.view().anchor = 0x10;
    h.app->engine->exec("doc:jump(0x8000)");
    h.frames(2);
    CHECK(d.view().cursor == 0x8000);
    REQUIRE(h.tab(0).nav.can_back());
    h.app->engine->exec("doc:select(0x9000, 4)");
    h.frames(2);
    CHECK(d.view().sel_begin() == 0x9000);
    CHECK(d.view().sel_len() == 4);
    h.action("Navigate Back");  // Alt+Left
    CHECK(d.view().sel_begin() == 0x8000);
    CHECK(d.view().sel_len() == 0);
    h.action("Navigate Back");
    CHECK(d.view().cursor == 0x10);
    h.action("Navigate Forward");
    CHECK(d.view().cursor == 0x8000);

    // Reset Layout: the default panels, the on-demand ones closed; settings.ini follows.
    h.action("Toggle Bitmap");
    h.action("Show History");
    h.action("Toggle Disassembly");
    h.app->show_inspector = false;
    h.frames(2);
    CHECK(h.app->show_bitmap);
    CHECK(h.app->settings.panel_history);
    h.action("Reset Layout");
    h.frames(3);
    CHECK_FALSE(h.app->show_bitmap);
    CHECK_FALSE(h.app->show_history);
    CHECK_FALSE(h.app->show_disasm);
    CHECK(h.app->show_inspector);
    CHECK(h.app->show_structure);
    CHECK_FALSE(h.app->settings.panel_bitmap);
    CHECK_FALSE(h.app->settings.panel_history);
    CHECK(h.app->settings.panel_inspector);
}

TEST_CASE("app: Select All Matches selects the Find All hits; stale hits are not selected") {
    TempDir dir;
    Bytes data = pattern(8192, 4);
    for (size_t at : {0x40, 0x800, 0x1F00}) std::memcpy(&data[at], "HEXERxyz", 8);
    const std::string f = dir.file("m.bin", data);
    HeadlessApp h(path_join(dir.path, "config"), {f}, true);
    Document& d = *h.tab(0).doc;
    h.app->find.kind = int(SearchKind::Text);
    h.app->find.input = "HEXERxyz";
    h.action("Select All Matches");  // starts Find All, selects its hits when it is done
    h.frames_until([&] { return !d.view().extra_sel.empty(); });
    CHECK(d.view().sel_begin() == 0x40);
    CHECK(d.view().sel_len() == 8);
    CHECK(d.view().extra_sel == std::vector<ByteRange>{{0x800, 0x808}, {0x1F00, 0x1F08}});
    h.action("Clear Extra Selections");
    CHECK(d.view().extra_sel.empty());

    // The document changed since the search (bytes inserted in front): the hits are stale, so the
    // Search Results panel's Select All must not select them (they no longer hold the matches).
    REQUIRE(h.tab(0).hits.offsets.size() == 3);
    const uint8_t b = 0;
    REQUIRE(d.insert(0, &b, 1));
    h.frames(2);
    d.view().cursor = d.view().anchor = 0;
    select_hits(*h.app, h.tab(0));
    CHECK(d.view().extra_sel.empty());
    CHECK_FALSE(d.view().has_selection());
    // Select All Matches searches again and selects the moved matches.
    h.action("Select All Matches");
    h.frames_until([&] { return !d.view().extra_sel.empty(); });
    CHECK(d.view().sel_begin() == 0x41);
    CHECK(d.view().extra_sel == std::vector<ByteRange>{{0x801, 0x809}, {0x1F01, 0x1F09}});
}

TEST_CASE("app: History panel keys undo / redo through the document") {
    TempDir dir;
    const std::string f = dir.file("h.bin", Bytes(256, 0x11));
    HeadlessApp h(path_join(dir.path, "config"), {f}, true);
    Document& d = *h.tab(0).doc;
    for (uint64_t i = 0; i < 3; ++i) {
        const uint8_t v = uint8_t(0xA0 + i);
        REQUIRE(d.overwrite(i * 16, &v, 1));
    }
    REQUIRE(history_count(d) == 4);
    REQUIRE(history_current(d) == 3);
    h.action("Show History");
    h.frames(3);
    h.key(ImGuiKey_Home);  // the oldest state: three undo steps
    CHECK(history_current(d) == 0);
    uint8_t x = 0;
    REQUIRE(d.read(0, &x, 1) == 1);
    CHECK(x == 0x11);
    h.key(ImGuiKey_DownArrow);  // one redo
    CHECK(history_current(d) == 1);
    REQUIRE(d.read(0, &x, 1) == 1);
    CHECK(x == 0xA0);
    h.key(ImGuiKey_End);
    CHECK(history_current(d) == 3);
    REQUIRE(d.read(32, &x, 1) == 1);
    CHECK(x == 0xA2);
}

TEST_CASE("app: XOR Search panel scans the file and guesses a key from the selection") {
    TempDir dir;
    Bytes data = pattern(16384, 7);
    const std::string plain = "This program";
    for (size_t i = 0; i < plain.size(); ++i) data[5000 + i] = uint8_t(plain[i]) ^ 0x5A;
    for (size_t i = 0; i < 512; ++i) data[9000 + i] = 0x00 ^ 0x37;  // zeros under a 1-byte key
    const std::string f = dir.file("x.bin", data);
    HeadlessApp h(path_join(dir.path, "config"), {f}, true);
    h.app->xor_panel.plaintext = plain;
    h.action("XOR: Scan File");
    CHECK(h.app->show_xor);
    h.frames_until([&] { return h.app->status.rfind("XOR scan:", 0) == 0; });
    CHECK(h.app->status.find("XOR scan: 1 match") == 0);
    // Select the zero-heavy bytes and guess.
    ViewState& v = h.tab(0).doc->view();
    v.anchor = 9000;
    v.cursor = 9512;
    h.action("XOR: Guess Key from Selection");
    h.frames_until([&] { return h.app->status.rfind("Best key guess:", 0) == 0; });
    CHECK(h.app->status.find("37") != std::string::npos);
}

TEST_CASE("app: bookmark colors: the color menu, the bookmark under the caret, one undo step each") {
    TempDir dir;
    const std::string f = dir.file("bm.bin", Bytes(256, 0));
    HeadlessApp h(path_join(dir.path, "config"), {f}, true);
    Document& d = *h.tab(0).doc;
    REQUIRE(d.add_bookmark({0x10, 4, "a", 0, ""}));
    REQUIRE(d.add_bookmark({0x12, 8, "b", 0, ""}));
    auto caret = [&](uint64_t at) { d.view().cursor = d.view().anchor = at; };
    caret(0x13);
    CHECK(bookmark_at_focus(d) == 1);  // overlapping: the later one
    caret(0x10);
    CHECK(bookmark_at_focus(d) == 0);
    caret(0x40);
    CHECK(bookmark_at_focus(d) == SIZE_MAX);

    // The color menu: a click on the first preset swatch picks red.
    uint32_t picked = 1;
    bool got = false;
    const ImVec2 at(100.0f, 100.0f);
    auto menu_frame = [&](ImVec2 mouse, bool down) {
        ImGuiIO& io = ImGui::GetIO();
        io.AddMousePosEvent(mouse.x, mouse.y);
        io.AddMouseButtonEvent(ImGuiMouseButton_Left, down);
        io.DisplaySize = ImVec2(1600, 1000);
        io.DeltaTime = 1.0f / 60.0f;
        ImGui::NewFrame();
        ImGui::SetNextWindowPos(at);
        ImGui::Begin("color menu test", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize);
        uint32_t c = 0;
        if (bookmark_color_menu(0, &c)) {
            picked = c;
            got = true;
        }
        ImGui::End();
        ImGui::Render();
    };
    const ImVec2 pad = ImGui::GetStyle().WindowPadding;
    const ImVec2 first(at.x + pad.x + 3.0f, at.y + pad.y + 3.0f);
    menu_frame(first, false);
    menu_frame(first, false);
    menu_frame(first, true);
    menu_frame(first, false);
    REQUIRE(got);
    uint32_t red = 0;
    REQUIRE(parse_color("red", red));
    CHECK(picked == red);

    // Setting it is one undo step; the same color again is none; undo restores the default.
    const size_t steps = d.undo_stack().size();
    set_bookmark_color(*h.app, d, 0, red);
    CHECK(d.view().bookmarks[0].color == red);
    CHECK(d.undo_stack().size() == steps + 1);
    set_bookmark_color(*h.app, d, 0, red);
    CHECK(d.undo_stack().size() == steps + 1);
    CHECK(d.view().bookmarks[1].color == 0);
    REQUIRE(d.undo());
    CHECK(d.view().bookmarks[0].color == 0);
    REQUIRE(d.redo());
    CHECK(d.view().bookmarks[0].color == red);
}

TEST_CASE("app: Toggle Bookmark grows the one bookmark a selection overlaps; never shrinks one") {
    TempDir dir;
    const std::string f = dir.file("tb.bin", Bytes(256, 0));
    HeadlessApp h(path_join(dir.path, "config"), {f}, true);
    Document& d = *h.tab(0).doc;
    auto select = [&](uint64_t a, uint64_t e) {
        d.view().anchor = a;
        d.view().cursor = e;
    };
    REQUIRE(d.add_bookmark({0x10, 4, "a", 0, ""}));
    const size_t steps = d.undo_stack().size();
    select(0x08, 0x20);  // covers it and more
    h.action("Toggle Bookmark");
    REQUIRE(d.view().bookmarks.size() == 1);
    CHECK(d.view().bookmarks[0].offset == 0x08);
    CHECK(d.view().bookmarks[0].length == 0x18);
    CHECK(d.view().bookmarks[0].name == "a");
    CHECK(d.undo_stack().size() == steps + 1);
    select(0x18, 0x30);  // overlaps its end: grows to the union
    h.action("Toggle Bookmark");
    REQUIRE(d.view().bookmarks.size() == 1);
    CHECK(d.view().bookmarks[0].offset == 0x08);
    CHECK(d.view().bookmarks[0].length == 0x28);
    select(0x10, 0x14);  // inside it (not at its start): a new bookmark
    h.action("Toggle Bookmark");
    REQUIRE(d.view().bookmarks.size() == 2);
    CHECK(d.view().bookmarks[1].offset == 0x10);
    select(0x00, 0x40);  // two bookmarks: a new one, nothing grows
    h.action("Toggle Bookmark");
    REQUIRE(d.view().bookmarks.size() == 3);
    CHECK(d.view().bookmarks[0].length == 0x28);
    select(0x08, 0x30);  // exactly the first one: removed
    h.action("Toggle Bookmark");
    CHECK(d.view().bookmarks.size() == 2);
    REQUIRE(d.undo());
    REQUIRE(d.undo());
    REQUIRE(d.undo());
    REQUIRE(d.undo());
    REQUIRE(d.view().bookmarks.size() == 1);
    CHECK(d.view().bookmarks[0].offset == 0x08);
    CHECK(d.view().bookmarks[0].length == 0x18);
}

TEST_CASE("app: the Bookmarks panel edits offset, length and bytes in place") {
    TempDir dir;
    const std::string f = dir.file("be.bin", pattern(256, 5));
    HeadlessApp h(path_join(dir.path, "config"), {f}, true);
    Document& d = *h.tab(0).doc;
    REQUIRE(d.add_bookmark({0x10, 4, "a", 0, ""}));
    h.action("Show All Bookmarks");
    h.frames(3);
    // Row of the InlineEdit: bookmark index * 5 + field (0 name, 1 note, 2 offset, 3 length, 4 bytes).
    auto edit = [&](int field, const std::string& text) {
        h.app->bm_edit.begin(field, d.id(), text);
        h.frames(3);
        REQUIRE(h.app->bm_edit.active(field, d.id()));
        h.key(ImGuiKey_Enter);
        h.frames(2);
    };
    edit(2, "0x20");
    CHECK(d.view().bookmarks[0].offset == 0x20);
    CHECK(d.view().bookmarks[0].length == 4);
    CHECK_FALSE(h.app->bm_edit.active(2, d.id()));
    edit(2, "+0x8");  // relative to the bookmark's offset
    CHECK(d.view().bookmarks[0].offset == 0x28);
    edit(3, "16");  // decimal by default
    CHECK(d.view().bookmarks[0].length == 16);
    edit(3, "0x400");  // past the end: refused, the editor stays open
    CHECK(d.view().bookmarks[0].length == 16);
    CHECK(h.app->bm_edit.active(3, d.id()));
    CHECK_FALSE(h.app->bm_edit.error.empty());
    h.app->bm_edit.end();
    h.frames(2);  // the field goes away (an active InputText keeps its own text)
    edit(3, "4");
    CHECK(d.view().bookmarks[0].length == 4);

    const Bytes before = [&] { Bytes b(4); d.read(0x28, b.data(), 4); return b; }();
    edit(4, "AA BB");  // wrong count: refused
    CHECK(h.app->bm_edit.active(4, d.id()));
    h.app->bm_edit.end();
    h.frames(2);
    Bytes now(4);
    REQUIRE(d.read(0x28, now.data(), 4) == 4);
    CHECK(now == before);
    const size_t steps = d.undo_stack().size();
    edit(4, "AA BB CC DD");
    REQUIRE(d.read(0x28, now.data(), 4) == 4);
    CHECK(now == Bytes{0xAA, 0xBB, 0xCC, 0xDD});
    CHECK(d.undo_stack().size() == steps + 1);
    CHECK(d.undo_stack().back().label == "Edit bookmark bytes");
    REQUIRE(d.undo());
    REQUIRE(d.read(0x28, now.data(), 4) == 4);
    CHECK(now == before);
}
