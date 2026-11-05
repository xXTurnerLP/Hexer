#pragma once
// Bitmap panel: renders the document's bytes as pixels (core/bitmap.h) to spot tables, images,
// sprites and structure. Self-contained (no App dependency): the host owns one BitmapPanel and calls
// draw() inside its own Begin/End every frame with the active document.
//
//   * Toolbar: pixel format, width (1..8192, -/+, presets, x2 and /2), zoom (1x..16x, nearest) or
//     fit-to-width, source ("Follow hex view" = start at the hex view's top row, "Follow cursor",
//     "Fixed offset" with a Goto-style expression field).
//   * The image scrolls through the whole file by its own 64-bit row index (mouse wheel, slim custom
//     scrollbar, PageUp/PageDown/Home/End while the panel is focused). Scrolling a follow mode
//     switches to "Fixed offset". Shift+wheel scrolls horizontally when the width does not fit,
//     Ctrl+wheel zooms.
//   * Hover shows offset / pixel / bytes / color in the status line; click = cb.jump(offset);
//     drag = cb.select(range of the dragged pixels). The hex caret is outlined when visible.
//   * Only the visible window is decoded (at most kMaxPixels x kMaxPixels pixels and kMaxBytes bytes
//     per refresh, read through Document::read), and only when offset / width / format / zoom /
//     panel size / document generation change. The pixels go to an ImGui-managed user texture
//     (ImTextureData, uploaded by the renderer backend); nothing is drawn while the backend has not
//     created it yet (a headless context never does).
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "core/bitmap.h"

struct ImFont;
struct ImTextureData;
struct ImGuiContext;

namespace hx {

class Document;
struct Settings;

struct BitmapPanelCallbacks {
    std::function<void(uint64_t offset)> jump;                   // move the hex caret there + reveal
    std::function<void(uint64_t offset, uint64_t len)> select;  // select [offset, offset+len)
};

enum class BitmapSource : uint8_t { FollowView, FollowCursor, Fixed };

class BitmapPanel {
public:
    static constexpr int kMaxWidth = 8192;                     // image width limit (pixels)
    static constexpr int kMaxZoom = 16;
    static constexpr int kMaxPixels = 2048;                    // decoded window limit per axis
    static constexpr uint64_t kMaxBytes = uint64_t(8) << 20;   // bytes read per refresh
    static constexpr int kMaxTexture = 4096;                   // texture limit per axis (screen px)

    BitmapPanel();
    ~BitmapPanel();
    BitmapPanel(const BitmapPanel&) = delete;
    BitmapPanel& operator=(const BitmapPanel&) = delete;

    PixelFormat format = PixelFormat::Gray8;
    int width = 256;               // pixels per row
    int zoom = 2;                  // 1..kMaxZoom (ignored while fit_width)
    bool fit_width = false;        // largest integer zoom at which `width` fits the panel
    bool use_alpha = false;        // alpha formats: composite over a checkerboard (else opaque)
    BitmapSource source = BitmapSource::FollowView;
    ImFont* mono = nullptr;        // font for offsets (nullptr = current font)
    float ui_scale = 1.0f;

    // Options <-> settings.ini (Settings::bitmap_*: format, width, zoom, Fit, Alpha and the follow
    // source): load_settings at startup; save_settings writes them back and returns true when one
    // changed (the host then saves settings.ini). "Fixed offset" is not a setting (an offset
    // belongs to one file): save_settings keeps the saved follow source while it is on, and the
    // host keeps the fixed offset in its session (fixed_offset / set_fixed_offset).
    void load_settings(const Settings& s);
    bool save_settings(Settings& s) const;

    // Draws into the current window (the caller owns Begin/End). `doc` may be null. `cursor` is the
    // hex caret (doc->view().cursor, or focus_offset()), `view_top_offset` the first byte of the hex
    // view's top row. Never mutates the document; a busy (saving) document is not read.
    void draw(Document* doc, uint64_t cursor, uint64_t view_top_offset, const BitmapPanelCallbacks& cb = {});

    // Frees the texture. Call while the ImGui context is still alive, ideally after the renderer
    // backend shut down (ImGui_ImplOpenGL3_Shutdown destroys the GPU side of registered textures);
    // the destructor does the same if the context is still current.
    void shutdown();

    // The texture was just (re)created and the backend uploads it during this frame's render: the
    // host should draw one more frame instead of waiting for input so the image shows up.
    bool wants_frames() const { return wants_frames_; }

    // First byte of the image currently shown (follow modes: the followed offset).
    uint64_t offset() const { return base_; }
    // Switch to "Fixed offset" at `off` (e.g. from a palette action "Bitmap: Show at Cursor").
    void set_fixed_offset(uint64_t off) {
        source = BitmapSource::Fixed;
        fixed_ = off;
    }
    uint64_t fixed_offset() const { return fixed_; }  // the "Fixed offset" source value

    // The last draw (for headless tests, tests/test_panels.cpp): the image's top-left screen
    // corner, and the decoded window: zoom, cols x rows pixels (packed 0xAABBGGRR, row-major).
    // decoded() stays false while there is no texture to decode into (renderer without
    // ImGuiBackendFlags_RendererHasTextures); a headless context with that flag decodes normally
    // (the texture is simply never uploaded).
    float image_x() const { return image_x_; }
    float image_y() const { return image_y_; }
    bool decoded() const { return have_key_; }
    int shown_zoom() const { return key_.zoom; }
    int shown_cols() const { return key_.cols; }
    int shown_rows() const { return key_.rows; }
    const std::vector<uint32_t>& shown_pixels() const { return pixels_; }

private:
    struct Key {                   // what the current texture contents were built from
        uint64_t doc_id = 0, gen = 0, size = 0, base = 0;
        uint64_t col0 = 0;
        int width = 0, cols = 0, rows = 0, zoom = 0;
        PixelFormat format = PixelFormat::Gray8;
        bool alpha = false;
        bool operator==(const Key&) const = default;
    };
    void draw_toolbar(const Document& doc);
    void refresh(const Document& doc, const Key& k);
    bool ensure_texture(int w, int h);  // false: no texture support / too big
    void collect_retired();

    uint64_t base_ = 0;            // first byte of row 0 of the image (follow / fixed)
    uint64_t fixed_ = 0;           // the "Fixed offset" source value
    uint64_t col0_ = 0;            // first visible column (multiple of 8)
    double wheel_accum_ = 0.0;
    bool dragging_thumb_ = false, dragging_hthumb_ = false;
    double thumb_grab_ = 0.0;      // drag offset inside the thumb (px)
    bool pressed_ = false;         // left button went down on the image
    bool drag_select_ = false;     // ... and moved: selecting
    uint64_t press_off_ = 0;
    uint64_t ctx_off_ = 0;         // context menu: offset under the mouse when it opened
    bool ctx_valid_ = false;
    std::string offset_text_;      // the offset field's text while not being edited
    bool offset_editing_ = false;
    std::string offset_err_;
    uint64_t shown_doc_id_ = 0;
    float image_x_ = 0.0f, image_y_ = 0.0f;  // image corner of the last draw (screen)

    Key key_;
    bool have_key_ = false;
    std::vector<uint8_t> bytes_;   // gathered bytes of the visible window
    std::vector<uint32_t> pixels_; // decoded window (cols x rows)
    ImTextureData* tex_ = nullptr;
    std::vector<ImTextureData*> retired_;  // waiting for the backend to destroy the GPU texture
    ImGuiContext* tex_ctx_ = nullptr;      // context the textures are registered with
    bool wants_frames_ = false;
};

}  // namespace hx
