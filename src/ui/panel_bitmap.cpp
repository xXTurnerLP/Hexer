#include "ui/panel_bitmap.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

#include "imgui.h"
#include "imgui_internal.h"  // RegisterUserTexture / UnregisterUserTexture / ImTextureDataQueueUpload
#include "misc/cpp/imgui_stdlib.h"

#include "core/document.h"
#include "core/highlight.h"
#include "core/settings.h"
#include "core/util.h"
#include "ui/hex_view.h"
#include "ui/theme.h"

namespace hx {

namespace {

const ImVec4 kErrColor(1.0f, 0.42f, 0.42f, 1.0f);
const int kWidthPresets[] = {8, 16, 32, 64, 128, 256, 320, 512, 640, 800, 1024};

std::string fmt_off(uint64_t v) { return "0x" + fmt_hex(v, 8); }

uint32_t with_alpha(uint32_t c, uint8_t a) { return (c & 0x00FFFFFFu) | (uint32_t(a) << 24); }

// c (straight alpha) over an opaque background color.
uint32_t over(uint32_t c, uint32_t bg) {
    const uint32_t a = c >> 24;
    uint32_t out = 0xFF000000u;
    for (int sh = 0; sh < 24; sh += 8) {
        const uint32_t fc = (c >> sh) & 0xFF, bc = (bg >> sh) & 0xFF;
        out |= ((fc * a + bc * (255 - a) + 127) / 255) << sh;
    }
    return out;
}

// Slim scrollbar over [0, total) units with `page` units visible; `pos` is the first visible unit.
// Returns true when the user moved it (dragging the thumb, or clicking the track pages).
bool slim_scrollbar(const char* id, ImVec2 p0, ImVec2 sz, bool vertical, uint64_t total, uint64_t page,
                    uint64_t& pos, bool& dragging, double& grab) {
    ImGui::SetCursorScreenPos(p0);
    ImGui::InvisibleButton(id, ImVec2(std::max(sz.x, 1.0f), std::max(sz.y, 1.0f)));
    const bool hovered = ImGui::IsItemHovered(), active = ImGui::IsItemActive();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 p1(p0.x + sz.x, p0.y + sz.y);
    dl->AddRectFilled(p0, p1, rgba(0, 0, 0, 40));
    const uint64_t max_pos = total > page ? total - page : 0;
    if (max_pos == 0) {
        dragging = false;
        return false;
    }
    const uint64_t old = pos;
    pos = std::min(pos, max_pos);
    const float len = vertical ? sz.y : sz.x;
    const float m = vertical ? ImGui::GetIO().MousePos.y - p0.y : ImGui::GetIO().MousePos.x - p0.x;
    const double frac = double(page) / double(total);
    const float thumb = float(std::clamp(double(len) * frac, double(std::min(len, 18.0f)), double(len)));
    auto thumb_at = [&] { return float(double(len - thumb) * (double(pos) / double(max_pos))); };
    float t0 = thumb_at();
    if (ImGui::IsItemActivated() && m >= t0 && m < t0 + thumb) {
        dragging = true;
        grab = double(m - t0);
    }
    if (!active) dragging = false;
    bool moved = false;
    if (dragging) {
        const double range = double(len - thumb);
        if (range > 0.0) {
            const double t = std::clamp((double(m) - grab) / range, 0.0, 1.0);
            pos = std::min(max_pos, uint64_t(t * double(max_pos) + 0.5));
            moved = pos != old;
        }
    } else if (active && ImGui::IsMouseClicked(ImGuiMouseButton_Left, true)) {
        if (m < t0) pos = pos > page ? pos - page : 0;
        else if (m >= t0 + thumb) pos = std::min(max_pos, pos + page);
        moved = pos != old;
    }
    t0 = thumb_at();
    const ImGuiCol ci = dragging ? ImGuiCol_ScrollbarGrabActive
                        : hovered ? ImGuiCol_ScrollbarGrabHovered
                                  : ImGuiCol_ScrollbarGrab;
    const float th = vertical ? sz.x : sz.y;
    const float pad = std::max(2.0f, std::floor(th * 0.2f));
    const float r = (th - 2.0f * pad) * 0.5f;
    if (vertical)
        dl->AddRectFilled(ImVec2(p0.x + pad, p0.y + t0 + 1.0f), ImVec2(p1.x - pad, p0.y + t0 + thumb - 1.0f),
                          ImGui::GetColorU32(ci), r);
    else
        dl->AddRectFilled(ImVec2(p0.x + t0 + 1.0f, p0.y + pad), ImVec2(p0.x + t0 + thumb - 1.0f, p1.y - pad),
                          ImGui::GetColorU32(ci), r);
    return moved;
}

const char* source_name(BitmapSource s) {
    switch (s) {
    case BitmapSource::FollowView: return "Follow hex view";
    case BitmapSource::FollowCursor: return "Follow cursor";
    case BitmapSource::Fixed: return "Fixed offset";
    }
    return "?";
}

}  // namespace

BitmapPanel::BitmapPanel() = default;

BitmapPanel::~BitmapPanel() { shutdown(); }

void BitmapPanel::load_settings(const Settings& s) {
    format = PixelFormat::Gray8;
    for (int i = 0; i < kPixelFormatCount; ++i)
        if (s.bitmap_format == pixel_format_name(PixelFormat(i))) format = PixelFormat(i);
    width = std::clamp(s.bitmap_width, 1, kMaxWidth);
    zoom = bitmap_zoom_clamp(s.bitmap_zoom, kMaxZoom);
    fit_width = s.bitmap_fit;
    use_alpha = s.bitmap_alpha;
    source = s.bitmap_source == 1 ? BitmapSource::FollowCursor : BitmapSource::FollowView;
}

bool BitmapPanel::save_settings(Settings& s) const {
    // "" = the default format (Gray 8-bit), so an untouched choice follows future defaults.
    const std::string fmt = format == PixelFormat::Gray8 ? std::string() : std::string(pixel_format_name(format));
    const int src = source == BitmapSource::Fixed ? s.bitmap_source : source == BitmapSource::FollowCursor ? 1 : 0;
    if (fmt == s.bitmap_format && width == s.bitmap_width && zoom == s.bitmap_zoom && fit_width == s.bitmap_fit &&
        use_alpha == s.bitmap_alpha && src == s.bitmap_source)
        return false;
    s.bitmap_format = fmt;
    s.bitmap_width = width;
    s.bitmap_zoom = zoom;
    s.bitmap_fit = fit_width;
    s.bitmap_alpha = use_alpha;
    s.bitmap_source = src;
    return true;
}

void BitmapPanel::shutdown() {
    ImGuiContext* ctx = ImGui::GetCurrentContext();
    auto drop = [&](ImTextureData* t) {
        if (!t) return;
        if (ctx && ctx == tex_ctx_) {
            ImGui::UnregisterUserTexture(t);
            IM_DELETE(t);
        } else if (!ctx) {
            IM_DELETE(t);  // the context is gone, nothing references the texture any more
        }
        // else: another context is current; leak it rather than leave a dangling registration
    };
    drop(tex_);
    for (ImTextureData* t : retired_) drop(t);
    tex_ = nullptr;
    retired_.clear();
    tex_ctx_ = nullptr;
    have_key_ = false;
}

void BitmapPanel::collect_retired() {
    if (retired_.empty() || tex_ctx_ != ImGui::GetCurrentContext()) return;
    for (size_t i = 0; i < retired_.size();) {
        ImTextureData* t = retired_[i];
        if (t->Status == ImTextureStatus_Destroyed) {
            ImGui::UnregisterUserTexture(t);
            IM_DELETE(t);
            retired_.erase(retired_.begin() + ptrdiff_t(i));
        } else {
            ++i;
        }
    }
}

bool BitmapPanel::ensure_texture(int w, int h) {
    if (!(ImGui::GetIO().BackendFlags & ImGuiBackendFlags_RendererHasTextures)) return false;
    ImGuiContext* ctx = ImGui::GetCurrentContext();
    if (tex_ctx_ && tex_ctx_ != ctx) {  // a different context (tests): forget, never touch the old one
        tex_ = nullptr;
        retired_.clear();
        tex_ctx_ = nullptr;
    }
    w = std::clamp(w, 1, kMaxTexture);
    h = std::clamp(h, 1, kMaxTexture);
    auto round_up = [](int v) { return std::min((v + 255) & ~255, int(kMaxTexture)); };
    const int rw = round_up(w), rh = round_up(h);
    if (tex_) {
        const bool fits = tex_->Width >= w && tex_->Height >= h;
        const bool wasteful = int64_t(tex_->Width) * tex_->Height > 4 * int64_t(rw) * rh;
        if (fits && !wasteful) return true;
        ImTextureData* old = tex_;
        tex_ = nullptr;
        if (old->TexID == ImTextureID_Invalid && old->BackendUserData == nullptr) {
            ImGui::UnregisterUserTexture(old);  // never reached the backend
            IM_DELETE(old);
        } else {
            // Ask the backend to free the GPU side; without pixels it stays Destroyed afterwards
            // (instead of being re-created) and collect_retired() frees it.
            old->WantDestroyNextFrame = true;
            old->DestroyPixels();
            old->SetStatus(ImTextureStatus_WantDestroy);
            old->UnusedFrames = 1;
            retired_.push_back(old);
        }
    }
    tex_ = IM_NEW(ImTextureData)();
    tex_->Create(ImTextureFormat_RGBA32, rw, rh);
    ImGui::RegisterUserTexture(tex_);
    tex_ctx_ = ctx;
    have_key_ = false;
    return true;
}

void BitmapPanel::refresh(const Document& doc, const Key& k) {
    key_ = k;
    have_key_ = true;
    const uint64_t stride = bitmap_row_stride(k.format, k.width);
    // A cell is step x step image pixels (1 unless downscaled); a cell row reads `sub` of its
    // step image rows (all of them while that stays within kMaxBytes, else evenly spaced ones),
    // each `w` pixels from col0 on.
    const int step = std::max(1, k.step);
    const int w = int(std::min<uint64_t>(uint64_t(k.width) - std::min<uint64_t>(k.col0, uint64_t(k.width)),
                                         uint64_t(k.cols) * uint64_t(step)));
    const size_t row_bytes = size_t(bitmap_row_stride(k.format, w));
    // Cell rows that hold data (the rest is past the end: missing, not read).
    const uint64_t data_rows = std::clamp<uint64_t>(
        (bitmap_row_count(k.base, k.size, k.format, k.width) + uint64_t(step) - 1) / uint64_t(step), 1, uint64_t(k.rows));
    const int sub = int(std::clamp<uint64_t>(kMaxBytes / std::max<uint64_t>(1, uint64_t(row_bytes) * data_rows), 1,
                                             uint64_t(step)));
    // Downscaled: only the cell rows that hold data are gathered (bitmap_downscale marks the others
    // missing), so a short image in a tall panel stays within the byte budget too.
    const int rows_read = step > 1 ? int(data_rows) * sub : k.rows;
    const uint64_t col_byte = k.col0 * uint64_t(pixel_format_bits(k.format)) / 8;  // col0 % 8 == 0
    bytes_.assign(row_bytes * size_t(rows_read), 0);
    size_t valid = 0;
    for (int r = 0; r < rows_read; ++r) {
        const uint64_t img_row = uint64_t(r / sub) * uint64_t(step) + uint64_t(r % sub) * uint64_t(step) / uint64_t(sub);
        const uint64_t off = k.base + img_row * stride + col_byte;
        if (off >= k.size) break;
        const size_t got = doc.read(off, bytes_.data() + size_t(r) * row_bytes, row_bytes);
        valid = size_t(r) * row_bytes + got;
        if (got < row_bytes) break;  // end of file: the rest is missing
    }
    size_t valid_px = decode_pixels(bytes_.data(), valid, k.format, w, rows_read, pixels_);
    if (step > 1) {  // average the blocks: one pixel per cell
        valid_px = bitmap_downscale(pixels_, valid_px, w, k.rows, step, sub, scaled_);
        pixels_.swap(scaled_);
    }

    // Upscale (nearest) into the texture so it is sampled 1:1 (the backend filters linearly).
    const int z = k.zoom, line_w = k.cols * z;
    const bool alpha_fmt = pixel_format_has_alpha(k.format);
    const int sq = std::max(1, 8 / z);  // alpha checkerboard square, in image pixels
    std::vector<uint32_t> line(static_cast<size_t>(line_w));
    unsigned char* tp = tex_->Pixels;
    const size_t pitch = size_t(tex_->GetPitch());
    for (int y = 0; y < k.rows; ++y) {
        for (int x = 0; x < k.cols; ++x) {
            const size_t i = size_t(y) * size_t(k.cols) + size_t(x);
            uint32_t c = pixels_[i];
            if (i >= valid_px) c |= 0xFF000000u;  // missing marker, drawn opaque
            else if (alpha_fmt)
                c = k.alpha ? over(c, (((x / sq) ^ (y / sq)) & 1) ? rgba(0x9A, 0x9A, 0x9A) : rgba(0x66, 0x66, 0x66))
                            : (c | 0xFF000000u);
            std::fill_n(line.begin() + ptrdiff_t(x) * z, z, c);
        }
        for (int r = 0; r < z; ++r)
            std::memcpy(tp + size_t(y * z + r) * pitch, line.data(), size_t(line_w) * 4);
    }
    if (tex_->Status == ImTextureStatus_OK || tex_->Status == ImTextureStatus_WantUpdates) {
        // User textures are not processed by ImGui itself: drop the requests the backend already
        // honored, then queue the whole used rect.
        tex_->Updates.resize(0);
        tex_->UpdateRect.x = tex_->UpdateRect.y = (unsigned short)~0;
        tex_->UpdateRect.w = tex_->UpdateRect.h = 0;
        ImTextureDataQueueUpload(tex_, 0, 0, line_w, k.rows * z);
    }
    // WantCreate: the backend uploads all pixels when it creates the texture.
}

void BitmapPanel::draw_toolbar(const Document& doc) {
    const float s = ui_scale;
    const ImGuiStyle& style = ImGui::GetStyle();
    const float right = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
    bool first = true;
    auto place = [&](float w) {  // SameLine if the next item (w wide) still fits, else wrap
        if (!first && ImGui::GetItemRectMax().x + style.ItemSpacing.x + w <= right) ImGui::SameLine();
        first = false;
    };

    // Format
    place(150.0f * s);
    ImGui::SetNextItemWidth(150.0f * s);
    if (ImGui::BeginCombo("##format", pixel_format_name(format))) {
        for (int i = 0; i < kPixelFormatCount; ++i) {
            const PixelFormat f = PixelFormat(i);
            if (ImGui::Selectable(pixel_format_name(f), f == format)) format = f;
            if (f == format) ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
    ImGui::SetItemTooltip("Pixel format (%d bits per pixel)", pixel_format_bits(format));

    // Width: InputInt with -/+, presets, /2, x2
    const float width_w = 110.0f * s;
    place(ImGui::CalcTextSize("Width").x + style.ItemInnerSpacing.x + width_w + ImGui::GetFrameHeight() +
          ImGui::CalcTextSize("/2x2").x + 4.0f * style.FramePadding.x + 3.0f * style.ItemSpacing.x);
    ImGui::BeginGroup();
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Width");
    ImGui::SameLine(0.0f, style.ItemInnerSpacing.x);
    ImGui::SetNextItemWidth(width_w);
    if (ImGui::InputInt("##width", &width, 1, 8)) width = std::clamp(width, 1, kMaxWidth);
    ImGui::SetItemTooltip("Pixels per row (1..%d); row stride %llu bytes", kMaxWidth,
                          (unsigned long long)bitmap_row_stride(format, width));
    ImGui::SameLine(0.0f, style.ItemInnerSpacing.x);
    if (ImGui::BeginCombo("##presets", nullptr, ImGuiComboFlags_NoPreview | ImGuiComboFlags_PopupAlignLeft)) {
        for (int p : kWidthPresets) {
            char buf[16];
            std::snprintf(buf, sizeof buf, "%d", p);
            if (ImGui::Selectable(buf, p == width)) width = p;
        }
        ImGui::EndCombo();
    }
    ImGui::SetItemTooltip("Width presets");
    ImGui::SameLine(0.0f, style.ItemInnerSpacing.x);
    if (ImGui::Button("/2")) width = std::max(1, width / 2);
    ImGui::SetItemTooltip("Halve the width");
    ImGui::SameLine(0.0f, style.ItemInnerSpacing.x);
    if (ImGui::Button("x2")) width = std::min(kMaxWidth, width * 2);
    ImGui::SetItemTooltip("Double the width");
    ImGui::EndGroup();

    // Zoom
    const float zoom_w = 90.0f * s;
    place(ImGui::CalcTextSize("Zoom").x + zoom_w + ImGui::GetFrameHeight() + ImGui::CalcTextSize("Fit").x +
          3.0f * style.ItemSpacing.x);
    ImGui::BeginGroup();
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Zoom");
    ImGui::SameLine(0.0f, style.ItemInnerSpacing.x);
    ImGui::SetNextItemWidth(zoom_w);
    ImGui::BeginDisabled(fit_width);
    {
        // Levels 1/16x .. 1/2x, 1x .. 16x as one slider position each.
        int levels[4 + kMaxZoom];
        int n = 0, at = 0;
        for (int d = 16; d >= 2; d /= 2) levels[n++] = -d;
        for (int z = 1; z <= kMaxZoom; ++z) levels[n++] = z;
        for (int i = 0; i < n; ++i)
            if (levels[i] == zoom) at = i;
        if (ImGui::SliderInt("##zoom", &at, 0, n - 1, bitmap_zoom_label(zoom), ImGuiSliderFlags_NoInput))
            zoom = levels[std::clamp(at, 0, n - 1)];
    }
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("Zoom (Ctrl+wheel over the image); below 1x a screen pixel averages\n"
                          "a block of image pixels (for very wide images)");
    ImGui::SameLine();
    ImGui::Checkbox("Fit", &fit_width);
    ImGui::SetItemTooltip("Largest zoom at which a whole row fits the panel (down to 1/16x)");
    ImGui::EndGroup();

    // Source + offset
    const float src_w = 140.0f * s, off_w = 140.0f * s;
    place(src_w + off_w + style.ItemInnerSpacing.x);
    ImGui::BeginGroup();
    ImGui::SetNextItemWidth(src_w);
    if (ImGui::BeginCombo("##source", source_name(source))) {
        for (int i = 0; i < 3; ++i) {
            const BitmapSource src = BitmapSource(i);
            if (ImGui::Selectable(source_name(src), src == source)) {
                if (src == BitmapSource::Fixed && source != BitmapSource::Fixed) fixed_ = base_;  // keep the view
                source = src;
            }
        }
        ImGui::EndCombo();
    }
    ImGui::SetItemTooltip("Where the image starts: the hex view's top row, the cursor, or a fixed offset.\n"
                          "Scrolling the image switches to a fixed offset.");
    ImGui::SameLine(0.0f, style.ItemInnerSpacing.x);
    ImGui::SetNextItemWidth(off_w);
    if (!offset_editing_) offset_text_ = fmt_off(base_);
    if (ImGui::InputText("##offset", &offset_text_, ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll)) {
        uint64_t off = 0;
        std::string err;
        if (parse_offset(offset_text_, base_, doc.size(), true, off, &err)) {
            set_fixed_offset(off);
            offset_err_.clear();
        } else {
            offset_err_ = err.empty() ? "invalid offset" : err;
        }
    }
    offset_editing_ = ImGui::IsItemActive();
    if (ImGui::IsItemEdited()) offset_err_.clear();
    ImGui::SetItemTooltip("First byte of the image (Enter: fixed offset).\n0x1F00, 1F00h, #4096, 50%%, end-0x100, cur+0x40...");
    ImGui::EndGroup();

    if (pixel_format_has_alpha(format)) {
        place(ImGui::GetFrameHeight() + ImGui::CalcTextSize("Alpha").x + style.ItemInnerSpacing.x);
        ImGui::Checkbox("Alpha", &use_alpha);
        ImGui::SetItemTooltip("Blend the alpha channel over a checkerboard (off: draw opaque)");
    }
}

void BitmapPanel::draw(Document* doc, uint64_t cursor, uint64_t view_top_offset, const BitmapPanelCallbacks& cb) {
    wants_frames_ = false;
    collect_retired();
    if (!doc) {
        ImGui::TextDisabled("No document open.");
        return;
    }
    ImGui::PushID("bitmap_panel");
    if (doc->id() != shown_doc_id_) {
        shown_doc_id_ = doc->id();
        col0_ = 0;
        pressed_ = drag_select_ = false;
    }
    width = std::clamp(width, 1, kMaxWidth);
    zoom = bitmap_zoom_clamp(zoom, kMaxZoom);
    draw_toolbar(*doc);
    if (doc->busy()) {
        ImGui::TextDisabled("Saving...");
        ImGui::PopID();
        return;
    }

    ImGuiIO& io = ImGui::GetIO();
    const ImGuiStyle& style = ImGui::GetStyle();
    const uint64_t size = doc->size();
    const int bits = pixel_format_bits(format);
    const uint64_t stride = bitmap_row_stride(format, width);

    // ---- layout ----------------------------------------------------------------------------------
    const float sb = std::max(std::floor(style.ScrollbarSize * 0.8f), 8.0f);
    const float status_h = ImGui::GetTextLineHeightWithSpacing();
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    p0.x = std::floor(p0.x);
    p0.y = std::floor(p0.y);  // whole pixels: the texture is sampled 1:1
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const float area_w = std::floor(avail.x - sb);
    float area_h = std::floor(avail.y - status_h);
    if (area_w < 8.0f || area_h < 8.0f) {
        ImGui::PopID();
        return;
    }
    const bool area_hovered = ImGui::IsWindowHovered() &&
                              ImGui::IsMouseHoveringRect(p0, ImVec2(p0.x + area_w, p0.y + area_h));
    // Ctrl+wheel zooms (leaves fit mode).
    if (area_hovered && io.KeyCtrl && io.MouseWheel != 0.0f) {
        if (fit_width) fit_width = false;
        zoom = bitmap_zoom_next(zoom, io.MouseWheel > 0.0f ? 1 : -1, kMaxZoom);
    }
    const int level = fit_width ? bitmap_fit_level(width, area_w, kMaxZoom) : zoom;
    if (fit_width) zoom = level;
    // A cell = step x step image pixels drawn as z x z screen pixels (step 1: zoomed in or 1x;
    // z 1: downscaled). sc = screen pixels per image pixel.
    const int z = bitmap_zoom_px(level), step = bitmap_zoom_step(level);
    const float sc = float(z) / float(step);
    // Columns / rows one page shows: what fits the panel, capped like the decoded window below so
    // scrolling by a page never skips pixels that were not drawn.
    const uint64_t cells_fit = std::clamp<uint64_t>(uint64_t(area_w) / uint64_t(z), 1,
                                                    std::min<uint64_t>(kMaxPixels, uint64_t(kMaxTexture / z)));
    const uint64_t cols_fit = cells_fit * uint64_t(step);  // image columns
    const bool need_h = uint64_t(width) > cols_fit;
    if (need_h) area_h -= sb;
    if (area_h < 4.0f) {
        ImGui::PopID();
        return;
    }
    const uint64_t rows_cap = std::min<uint64_t>(
        {uint64_t(kMaxPixels), uint64_t(kMaxTexture / z),
         std::max<uint64_t>(1, kMaxBytes / bitmap_row_stride(format, int(std::min<uint64_t>(uint64_t(width), cols_fit))))});
    const uint64_t cell_rows_full = std::clamp<uint64_t>(uint64_t(area_h) / uint64_t(z), 1, rows_cap);
    const uint64_t rows_full = cell_rows_full * uint64_t(step);  // image rows one page shows

    // ---- scrolling (64-bit row index; the phase base % stride is kept) ---------------------------
    uint64_t base = source == BitmapSource::FollowView     ? view_top_offset
                    : source == BitmapSource::FollowCursor ? cursor
                                                           : fixed_;
    base = std::min(base, size);
    const uint64_t phase = base % stride;
    const uint64_t top = base / stride;
    const uint64_t total_rows = std::max<uint64_t>(1, bitmap_row_count(phase, size, format, width));
    const uint64_t max_top = total_rows > rows_full ? total_rows - rows_full : 0;
    uint64_t new_top = top;
    auto scroll_by = [&](int64_t d) {
        if (d < 0) new_top = new_top > uint64_t(-d) ? new_top - uint64_t(-d) : 0;
        else new_top = std::max(new_top, std::min(new_top + uint64_t(d), max_top));
    };
    {
        uint64_t pos = std::min(top, max_top);
        if (slim_scrollbar("##vsb", ImVec2(p0.x + area_w, p0.y), ImVec2(sb, area_h), true, total_rows, rows_full,
                           pos, dragging_thumb_, thumb_grab_))
            new_top = pos;
    }
    const uint64_t max_col0 = bitmap_max_col0(width, cols_fit);
    col0_ = std::min(col0_, max_col0) & ~uint64_t(7);
    if (need_h) {
        uint64_t pos = col0_;
        if (slim_scrollbar("##hsb", ImVec2(p0.x, p0.y + area_h), ImVec2(area_w, sb), false, uint64_t(width), cols_fit,
                           pos, dragging_hthumb_, thumb_grab_))
            col0_ = std::min(max_col0, (pos + 4) & ~uint64_t(7));
    } else {
        col0_ = 0;
        dragging_hthumb_ = false;
    }
    if (area_hovered && !io.KeyCtrl) {
        const float wheel_v = io.KeyShift ? 0.0f : io.MouseWheel;
        const float wheel_h = io.KeyShift ? io.MouseWheel : io.MouseWheelH;
        if (wheel_v != 0.0f) {
            wheel_accum_ -= double(wheel_v) * double(std::max<uint64_t>(1, rows_full / 8));
            const double n = std::trunc(wheel_accum_);
            wheel_accum_ -= n;
            scroll_by(int64_t(n));
        }
        if (wheel_h != 0.0f && need_h) {
            const uint64_t step = std::max<uint64_t>(8, (cols_fit / 8) & ~uint64_t(7));
            if (wheel_h > 0.0f) col0_ = col0_ > step ? col0_ - step : 0;
            else col0_ = std::min(max_col0, col0_ + step);
        }
    }
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::IsAnyItemActive() && !io.KeyCtrl) {
        if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) scroll_by(int64_t(rows_full));
        if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) scroll_by(-int64_t(rows_full));
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) scroll_by(1);
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) scroll_by(-1);
        if (ImGui::IsKeyPressed(ImGuiKey_Home, false)) new_top = 0;
        if (ImGui::IsKeyPressed(ImGuiKey_End, false)) new_top = max_top;
    }
    if (new_top != top) {
        source = BitmapSource::Fixed;
        fixed_ = std::min(phase + new_top * stride, size);
        base = fixed_;
    }
    if (source == BitmapSource::Fixed) fixed_ = base;
    base_ = base;

    // ---- decode the visible window ---------------------------------------------------------------
    // cols x rows cells; vis_cols x vis_rows image pixels from (col0_, top row).
    const uint64_t ustep = uint64_t(step);
    const int cols = int(std::min<uint64_t>({(uint64_t(width) - col0_ + ustep - 1) / ustep, cells_fit,
                                             uint64_t(kMaxPixels), uint64_t(kMaxTexture / z)}));
    const uint64_t vis_cols = std::min<uint64_t>(uint64_t(width) - col0_, uint64_t(cols) * ustep);
    const uint64_t row_bytes = bitmap_row_stride(format, int(vis_cols));
    const int rows = int(std::min<uint64_t>({uint64_t(std::ceil(area_h / float(z))), uint64_t(kMaxPixels),
                                             uint64_t(kMaxTexture / z), std::max<uint64_t>(1, kMaxBytes / row_bytes)}));
    const uint64_t vis_rows = uint64_t(rows) * ustep;
    Key k;
    k.doc_id = doc->id();
    k.gen = doc->generation();
    k.size = size;
    k.base = base;
    k.col0 = col0_;
    k.width = width;
    k.cols = cols;
    k.rows = rows;
    k.zoom = z;
    k.step = step;
    k.format = format;
    k.alpha = use_alpha && pixel_format_has_alpha(format);
    const bool have_tex = ensure_texture(cols * z, rows * z);
    if (have_tex && (!have_key_ || !(k == key_))) refresh(*doc, k);

    // ---- image -----------------------------------------------------------------------------------
    const ImVec2 a0 = p0, a1(p0.x + area_w, p0.y + area_h);
    image_x_ = a0.x;
    image_y_ = a0.y;
    ImGui::SetCursorScreenPos(a0);
    ImGui::InvisibleButton("##image", ImVec2(area_w, area_h));
    const bool img_hovered = ImGui::IsItemHovered();
    ImGui::SetItemKeyOwner(ImGuiKey_MouseWheelY);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->PushClipRect(a0, a1, true);
    dl->AddRectFilled(a0, a1, rgba(0, 0, 0, 70));
    const float img_w = float(cols * z), img_h = float(rows * z);
    if (have_tex && tex_->TexID != ImTextureID_Invalid) {
        dl->AddImage(tex_->GetTexRef(), a0, ImVec2(a0.x + img_w, a0.y + img_h), ImVec2(0.0f, 0.0f),
                     ImVec2(img_w / float(tex_->Width), img_h / float(tex_->Height)));
    } else if (have_tex) {
        wants_frames_ = true;  // created this frame: the backend uploads it during render
    } else {
        dl->AddText(ImVec2(a0.x + 8.0f, a0.y + 8.0f), ImGui::GetColorU32(ImGuiCol_TextDisabled),
                    "The renderer does not support dynamic textures.");
    }

    const uint64_t ppb = bits < 8 ? uint64_t(8 / bits) : 1;  // pixels per byte
    // Screen rectangles of the bytes [lo, hi) in the visible window (at most 3 rects).
    auto draw_range = [&](uint64_t lo, uint64_t hi, uint32_t col) {
        if (hi <= lo || hi <= base) return;
        lo = std::max(lo, base);
        uint64_t x0 = 0, y0 = 0, x1 = 0, y1 = 0;
        offset_to_pixel(base, format, width, lo, x0, y0);
        offset_to_pixel(base, format, width, hi - 1, x1, y1);
        x1 = std::min<uint64_t>(x1 + ppb, uint64_t(width));  // exclusive
        if (y0 >= vis_rows) return;
        const uint64_t vx0 = col0_, vx1 = col0_ + vis_cols;
        auto rect = [&](uint64_t xa, uint64_t xb, uint64_t ya, uint64_t yb) {  // [xa,xb) x [ya,yb]
            xa = std::max(xa, vx0);
            xb = std::min(xb, vx1);
            yb = std::min<uint64_t>(yb, vis_rows - 1);
            if (xa >= xb || ya > yb) return;
            const float x0f = a0.x + std::floor(float(xa - col0_) * sc), y0f = a0.y + std::floor(float(ya) * sc);
            const float x1f = std::max(x0f + 1.0f, a0.x + std::floor(float(xb - col0_) * sc));  // >= 1 px
            const float y1f = std::max(y0f + 1.0f, a0.y + std::floor(float(yb + 1) * sc));
            dl->AddRectFilled(ImVec2(x0f, y0f), ImVec2(x1f, y1f), col);
        };
        if (y0 == y1) {
            rect(x0, x1, y0, y0);
            return;
        }
        rect(x0, uint64_t(width), y0, y0);
        if (y1 > y0 + 1) rect(0, uint64_t(width), y0 + 1, y1 - 1);
        if (y1 < vis_rows) rect(0, x1, y1, y1);
    };
    const HexColors& C = hex_colors();
    const ViewState& v = doc->view();
    if (v.has_selection()) draw_range(v.sel_begin(), v.sel_end(), with_alpha(C.selection, 110));

    // Hover -> offset
    const ImVec2 mouse = io.MousePos;
    // Image pixel (relative to col0_ / the top row) under a screen point: the top-left pixel of
    // the cell's block.
    auto pixel_at = [&](float mx, float my, bool clamp_inside, uint64_t& px, uint64_t& py) {
        float fx = std::floor((mx - a0.x) / float(z)), fy = std::floor((my - a0.y) / float(z));
        if (clamp_inside) {
            fx = std::clamp(fx, 0.0f, float(cols - 1));
            fy = std::clamp(fy, 0.0f, float(std::min<uint64_t>(uint64_t(rows), cell_rows_full + 1) - 1));
        }
        if (fx < 0.0f || fy < 0.0f || fx >= float(cols) || fy >= float(rows) || fy * float(z) >= area_h) return false;
        px = uint64_t(fx) * ustep;
        py = uint64_t(fy) * ustep;
        return true;
    };
    uint64_t hpx = 0, hpy = 0, hover_off = 0;
    bool hover_valid = false;
    if (img_hovered && pixel_at(mouse.x, mouse.y, false, hpx, hpy)) {
        hover_off = pixel_to_offset(base, format, width, col0_ + hpx, hpy);
        hover_valid = hover_off < size;
    }

    // Click = jump, drag = select (applied on release so a following hex view cannot move the
    // image under the mouse while dragging).
    const uint64_t pix_bytes = uint64_t(pixel_format_bytes(format));
    if (ImGui::IsItemActivated() && hover_valid) {
        pressed_ = true;
        drag_select_ = false;
        press_off_ = hover_off;
    }
    uint64_t drag_lo = 0, drag_hi = 0;
    if (pressed_ && size > 0) {
        if (!drag_select_ && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) drag_select_ = true;
        if (drag_select_) {
            uint64_t px = 0, py = 0;
            pixel_at(mouse.x, mouse.y, true, px, py);
            const uint64_t cur = std::min(pixel_to_offset(base, format, width, col0_ + px, py), size - 1);
            drag_lo = std::min(press_off_, cur);
            drag_hi = std::min(size, std::max(press_off_, cur) + pix_bytes);
            draw_range(drag_lo, drag_hi, with_alpha(C.selection, 150));
        }
        if (!ImGui::IsItemActive()) {
            if (drag_select_) {
                if (cb.select) cb.select(drag_lo, drag_hi - drag_lo);
            } else if (cb.jump) {
                cb.jump(press_off_);
            }
            pressed_ = drag_select_ = false;
        }
    }

    // Hex caret: outline (+ crosshair ticks when the pixels are small).
    uint64_t cx = 0, cy = 0;
    if (cursor <= size && offset_to_pixel(base, format, width, cursor, cx, cy) && cy < vis_rows &&
        cx >= col0_ && cx < col0_ + vis_cols) {
        const uint64_t cw = std::min<uint64_t>(ppb, col0_ + vis_cols - cx);
        const ImVec2 c0(a0.x + std::floor(float(cx - col0_) * sc), a0.y + std::floor(float(cy) * sc));
        const ImVec2 c1(c0.x + std::max(1.0f, float(cw) * sc), c0.y + std::max(1.0f, sc));
        dl->AddRect(ImVec2(c0.x - 2.0f, c0.y - 2.0f), ImVec2(c1.x + 2.0f, c1.y + 2.0f), rgba(0, 0, 0, 200), 0.0f, 0, 3.0f);
        dl->AddRect(ImVec2(c0.x - 1.0f, c0.y - 1.0f), ImVec2(c1.x + 1.0f, c1.y + 1.0f), C.cursor, 0.0f, 0, 1.5f);
        if (c1.y - c0.y < 6.0f) {
            const float mx = std::floor((c0.x + c1.x) * 0.5f) + 0.5f, my = std::floor((c0.y + c1.y) * 0.5f) + 0.5f;
            const float g = 4.0f, l = 9.0f;
            dl->AddLine(ImVec2(c0.x - g - l, my), ImVec2(c0.x - g, my), C.cursor, 1.5f);
            dl->AddLine(ImVec2(c1.x + g, my), ImVec2(c1.x + g + l, my), C.cursor, 1.5f);
            dl->AddLine(ImVec2(mx, c0.y - g - l), ImVec2(mx, c0.y - g), C.cursor, 1.5f);
            dl->AddLine(ImVec2(mx, c1.y + g), ImVec2(mx, c1.y + g + l), C.cursor, 1.5f);
        }
    }
    if (hover_valid && z >= 4 && !drag_select_) {  // z >= 4: step 1, hpx / hpy are cells
        const ImVec2 h0(a0.x + float(hpx * uint64_t(z)), a0.y + float(hpy * uint64_t(z)));
        dl->AddRect(h0, ImVec2(h0.x + float(z), h0.y + float(z)), rgba(255, 255, 255, 140));
    }
    dl->PopClipRect();

    // Context menu
    if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
        ctx_off_ = hover_off;
        ctx_valid_ = hover_valid;
    }
    if (ImGui::BeginPopupContextItem("##bitmap_ctx")) {
        if (ImGui::MenuItem("Start Image Here", nullptr, false, ctx_valid_)) set_fixed_offset(ctx_off_);
        if (ImGui::MenuItem("Start Image at Cursor")) set_fixed_offset(std::min(cursor, size));
        if (ImGui::MenuItem("Jump Here", nullptr, false, ctx_valid_ && cb.jump != nullptr)) cb.jump(ctx_off_);
        if (ImGui::MenuItem("Copy Offset", nullptr, false, ctx_valid_)) ImGui::SetClipboardText(fmt_off(ctx_off_).c_str());
        ImGui::Separator();
        for (int i = 0; i < 3; ++i) {
            const BitmapSource src = BitmapSource(i);
            if (ImGui::MenuItem(source_name(src), nullptr, source == src)) {
                if (src == BitmapSource::Fixed && source != BitmapSource::Fixed) fixed_ = base_;
                source = src;
            }
        }
        ImGui::EndPopup();
    }

    // ---- status line -----------------------------------------------------------------------------
    ImGui::SetCursorScreenPos(ImVec2(p0.x, a1.y + (need_h ? sb : 0.0f) + 2.0f));
    if (mono) ImGui::PushFont(mono, 0.0f);
    if (!offset_err_.empty()) {
        ImGui::TextColored(kErrColor, "%s", offset_err_.c_str());
    } else if (hover_valid) {
        uint8_t b[4] = {};
        const size_t n = doc->read(hover_off, b, size_t(pix_bytes));
        const uint64_t ix = col0_ + hpx;
        std::string line = fmt_off(hover_off) + "  x " + std::to_string(ix) + " y " + std::to_string(base / stride + hpy) + " ";
        for (size_t i = 0; i < n; ++i) line += " " + fmt_hex(b[i], 2);
        if (bits == 1) {
            const unsigned bit = unsigned(7 - (ix & 7));
            line += " bit " + std::to_string(bit) + "=" + std::to_string((b[0] >> bit) & 1u);
        } else if (bits == 4) {
            line += " nibble=" + fmt_hex((ix & 1) ? unsigned(b[0] & 15u) : unsigned(b[0] >> 4), 1);
        }
        const size_t pi = size_t(hpy / ustep) * size_t(cols) + size_t(hpx / ustep);  // its cell
        if (have_key_ && key_ == k && pi < pixels_.size()) {
            const uint32_t c = pixels_[pi];
            // packed 0xAABBGGRR -> #RRGGBB[AA]
            line += "  #" + fmt_hex(c & 0xFF, 2) + fmt_hex((c >> 8) & 0xFF, 2) + fmt_hex((c >> 16) & 0xFF, 2);
            if (pixel_format_has_alpha(format)) line += fmt_hex(c >> 24, 2);
        }
        ImGui::TextUnformatted(line.c_str());
    } else {
        const uint64_t last = std::min(size, base + std::min<uint64_t>(vis_rows, rows_full) * stride);
        char buf[256];
        std::snprintf(buf, sizeof buf, "%s - %s  row %llu / %llu  %s  %llu B/row",
                      fmt_off(base).c_str(), fmt_off(last ? last - 1 : 0).c_str(), (unsigned long long)(base / stride),
                      (unsigned long long)total_rows, bitmap_zoom_label(level), (unsigned long long)stride);
        ImGui::TextDisabled("%s", size ? buf : "Empty document");
    }
    if (mono) ImGui::PopFont();
    ImGui::PopID();
}

}  // namespace hx
