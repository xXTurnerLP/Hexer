// Headless tests for the Compare view (ui/view_diff.h DiffView): two documents side by side in an
// ImGui context without a window or GL (same setup as tests/test_ui.cpp). Covers Next / Previous
// difference, Find Shift (worker job -> shift applied -> recompare), and synced scrolling.
#include <doctest/doctest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "imgui.h"

#include "core/diff.h"
#include "core/document.h"
#include "core/settings.h"
#include "ui/hex_view.h"
#include "ui/view_diff.h"

using namespace hx;

namespace {

using Bytes = std::vector<uint8_t>;

Bytes random_bytes(size_t n, uint64_t seed) {
    std::mt19937_64 rng(seed);
    Bytes b(n);
    for (auto& x : b) x = uint8_t(rng());
    return b;
}

// One ImGui context, two documents and a DiffView filling a host window.
struct Cmp {
    ImGuiContext* ctx = nullptr;
    std::unique_ptr<Document> a, b;
    DiffView dv;
    DiffViewCallbacks cb;
    std::vector<std::string> notes;
    float w = 1600.0f, h = 700.0f;

    Cmp(const Bytes& da, const Bytes& db) {
        ctx = ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.LogFilename = nullptr;
        io.BackendFlags |= ImGuiBackendFlags_RendererHasTextures;  // fonts baked on demand, never uploaded
        io.Fonts->AddFontDefault();
        a = Document::create_from_bytes("a", da.data(), da.size());
        b = Document::create_from_bytes("b", db.data(), db.size());
        cb.config.bytes_per_row = 16;
        cb.config.group_size = 8;
        cb.config.font_size = 13.0f;
        cb.notify = [this](const std::string& m) { notes.push_back(m); };
        frame();
        frame();
    }
    ~Cmp() { ImGui::DestroyContext(ctx); }

    void frame(float dt = 1.0f / 60.0f) {
        ImGuiIO& io = ImGui::GetIO();
        io.DisplaySize = ImVec2(w, h);
        io.DeltaTime = dt;
        ImGui::NewFrame();
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(w, h));
        ImGui::Begin("host", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);
        dv.draw("##cmp", *a, *b, cb);
        ImGui::End();
        ImGui::Render();
    }
    // Draws frames until `done` holds (the workers run in the background), at most ~20 s.
    bool until(const std::function<bool()>& done) {
        auto t0 = std::chrono::steady_clock::now();
        while (!done()) {
            if (std::chrono::steady_clock::now() - t0 > std::chrono::seconds(20)) return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            frame();
        }
        frame();
        return true;
    }
    bool compared() {
        return until([&] { return dv.result() && !dv.stale() && !dv.wants_frames(); });
    }
    std::pair<uint64_t, uint64_t> sel(const Document& d) const { return {d.view().sel_begin(), d.view().sel_end()}; }
};

using Range = std::pair<uint64_t, uint64_t>;

}  // namespace

TEST_CASE("diffview: Next / Previous difference select and reveal the range on both sides") {
    const Bytes da = random_bytes(64 * 1024, 1);
    Bytes db = da;
    for (size_t i = 1000; i < 1004; ++i) db[i] ^= 0xFF;
    db[30000] ^= 1;
    for (size_t i = 60000; i < 60010; ++i) db[i] ^= 0x80;
    Cmp c(da, db);
    REQUIRE(c.compared());
    REQUIRE(c.dv.result()->ranges.size() == 3);

    c.dv.request_next();
    c.frame();
    CHECK(c.sel(*c.a) == Range(1000, 1004));
    CHECK(c.sel(*c.b) == Range(1000, 1004));
    c.dv.request_next();
    c.frame();
    CHECK(c.sel(*c.a) == Range(30000, 30001));
    c.dv.request_next();
    c.frame();
    c.frame();
    CHECK(c.sel(*c.a) == Range(60000, 60010));
    CHECK(c.sel(*c.b) == Range(60000, 60010));
    // Scrolled there, both sides at the same row (shift 0).
    const uint64_t row = 60000 / 16;
    CHECK(c.a->view().top_row <= row);
    CHECK(row < c.a->view().top_row + 20);
    CHECK(c.b->view().top_row == c.a->view().top_row);
    CHECK(c.dv.note().find("3 of 3") != std::string::npos);

    c.dv.request_next();  // past the last one: stays, says so
    c.frame();
    CHECK(c.sel(*c.a) == Range(60000, 60010));
    CHECK(c.dv.note() == "No more differences after the caret");
    c.dv.request_prev();
    c.frame();
    CHECK(c.sel(*c.a) == Range(30000, 30001));
    c.dv.request_prev();
    c.frame();
    CHECK(c.sel(*c.b) == Range(1000, 1004));
    c.dv.request_prev();
    c.frame();
    CHECK(c.dv.note() == "No differences before the caret");
    CHECK(c.notes.size() >= 6);
}

TEST_CASE("diffview: Find Shift applies the shift, recompares and shows the match") {
    const Bytes body = random_bytes(200 * 1024, 2);
    Bytes head = random_bytes(300, 3);
    head[0] = uint8_t(body[0] ^ 0x33);
    Bytes db = head;
    db.insert(db.end(), body.begin(), body.end());
    Cmp c(body, db);
    REQUIRE(c.compared());
    CHECK(c.dv.result()->range_count > 1);  // misaligned: differences everywhere
    CHECK(c.dv.shift == 0);

    c.dv.request_find_shift();
    REQUIRE(c.until([&] { return !c.dv.finding_shift() && c.dv.shift != 0; }));
    CHECK(c.dv.shift == 300);
    CHECK(c.dv.note().find("B has 300 bytes more at B 0x0") != std::string::npos);
    CHECK(c.a->view().cursor == 0);
    CHECK(c.b->view().cursor == 300);
    REQUIRE(c.compared());
    const auto r = c.dv.result();
    CHECK(r->shift == 300);
    REQUIRE(r->ranges.size() == 1);  // only B's header is left
    CHECK(r->ranges[0] == DiffRange{0, 0, 300, DiffRange::OnlyB});
    // Both sides show the same content: B's first row is A's plus the shift.
    CHECK(c.b->view().top_row == (c.a->view().top_row * 16 + 300) / 16);

    // Identical overlap now: a second Find Shift has nothing to align and keeps the shift.
    c.dv.request_find_shift();
    REQUIRE(c.until([&] { return !c.dv.finding_shift() && !c.dv.wants_frames(); }));
    CHECK(c.dv.shift == 300);
    CHECK(c.dv.note().find("Nothing to align") != std::string::npos);
}

TEST_CASE("diffview: both sides scroll together, the shift applied") {
    const Bytes da = random_bytes(512 * 1024, 4);
    Bytes db(256, 0xEE);
    db.insert(db.end(), da.begin(), da.end());
    Cmp c(da, db);
    c.dv.shift = 256;
    c.frame();  // starts the compare with the new shift
    REQUIRE(c.compared());
    REQUIRE(c.dv.result()->ranges.size() == 1);

    // Moved from outside (e.g. Go to in A's tab): B follows, 256 bytes = 16 rows further.
    c.a->view().top_row = 1000;
    c.frame();
    CHECK(c.b->view().top_row == 1016);
    c.b->view().top_row = 2016;  // ...and the other way round
    c.frame();
    CHECK(c.a->view().top_row == 2000);

    // Mouse wheel over side B scrolls both.
    ImGui::GetIO().AddMousePosEvent(c.w * 0.75f, c.h * 0.5f);
    c.frame();
    ImGui::GetIO().AddMouseWheelEvent(0.0f, -4.0f);
    c.frame();
    c.frame();
    CHECK(c.b->view().top_row > 2016);
    CHECK(c.a->view().top_row + 16 == c.b->view().top_row);
    // ...and over side A.
    const uint64_t before = c.a->view().top_row;
    ImGui::GetIO().AddMousePosEvent(c.w * 0.25f, c.h * 0.5f);
    c.frame();
    ImGui::GetIO().AddMouseWheelEvent(0.0f, 2.0f);
    c.frame();
    c.frame();
    CHECK(c.a->view().top_row < before);
    CHECK(c.a->view().top_row + 16 == c.b->view().top_row);

    // Sync scroll off: the sides move independently.
    c.dv.sync_scroll = false;
    c.a->view().top_row = 10;
    c.frame();
    CHECK(c.b->view().top_row != 26);
}

TEST_CASE("diffview: Sync scroll / Sync caret load from and save to Settings") {
    Settings s;
    DiffView dv;
    CHECK_FALSE(dv.save_settings(s));  // the view's defaults are the settings' defaults
    dv.sync_scroll = false;
    dv.sync_caret = true;
    CHECK(dv.save_settings(s));
    CHECK_FALSE(dv.save_settings(s));
    CHECK_FALSE(s.compare_sync_scroll);
    CHECK(s.compare_sync_caret);
    DiffView next;  // the next compare starts with the user's choice
    next.load_settings(s);
    CHECK_FALSE(next.sync_scroll);
    CHECK(next.sync_caret);
}
