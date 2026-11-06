#pragma once
// Bitmap view core: interprets bytes as pixels (bytes -> packed rgba colors) and maps between
// pixel coordinates and file offsets. No UI; the Bitmap panel (ui/panel_bitmap.h) decodes only the
// visible window of the image through these helpers.
//
// Image layout: the image starts at a `base` offset; every row takes bitmap_row_stride(fmt, width)
// bytes = ceil(width * bits_per_pixel / 8), i.e. sub-byte formats (Gray4, Gray1) pad each row to a
// whole byte. Pixel (x, y) lives in the byte at base + y * stride + x * bpp / 8 (for Gray4 the high
// nibble is the left pixel; Gray1 is MSB first).
#include <cstddef>
#include <cstdint>
#include <vector>

#include "core/entropy.h"

namespace hx {

enum class PixelFormat : uint8_t {
    Gray8,      // 1 byte, v -> (v, v, v)
    Gray4,      // 2 pixels per byte, high nibble first, v * 17
    Gray1,      // 8 pixels per byte, MSB first, 0 = black, 1 = white
    RGB24,      // r g b
    BGR24,      // b g r
    RGBA32,     // r g b a
    BGRA32,     // b g r a
    ARGB32,     // a r g b
    RGB565LE,   // 16-bit little endian rrrrrggg gggbbbbb
    RGB565BE,   // same, big endian
    RGB555LE,   // 16-bit little endian xrrrrrgg gggbbbbb (top bit ignored)
    ByteClass,  // 1 byte, colored by byte_class() (bitmap_byte_class_color)
};
constexpr int kPixelFormatCount = 12;

const char* pixel_format_name(PixelFormat f);   // "Gray 8-bit", "RGB565 LE", "Byte class", ...
int pixel_format_bits(PixelFormat f);           // bits per pixel: 1, 4, 8, 16, 24 or 32
bool pixel_format_has_alpha(PixelFormat f);     // RGBA32 / BGRA32 / ARGB32
// Bytes one pixel touches (1 for the sub-byte formats).
inline int pixel_format_bytes(PixelFormat f) { return pixel_format_bits(f) <= 8 ? 1 : pixel_format_bits(f) / 8; }

// Bytes per image row: ceil(width * bpp / 8). width < 1 counts as 1.
uint64_t bitmap_row_stride(PixelFormat f, int width);

// Color of a byte class in the ByteClass format (packed 0xAABBGGRR, opaque).
uint32_t bitmap_byte_class_color(hx::ByteClass c);

// Marker for pixels whose bytes are not available (past src_len / end of file): a 4x4 checker of
// two dark grays with alpha 0, so it can never be mistaken for a decoded opaque pixel. (x, y) are
// coordinates inside the decoded window.
constexpr uint32_t kBitmapMissingA = 0x00342E2Eu;  // rgba(0x2E, 0x2E, 0x34, 0)
constexpr uint32_t kBitmapMissingB = 0x00483F3Fu;  // rgba(0x3F, 0x3F, 0x48, 0)
inline uint32_t bitmap_missing_color(int x, int y) {
    return (((x >> 2) ^ (y >> 2)) & 1) ? kBitmapMissingB : kBitmapMissingA;
}

// Decodes a width x height image whose rows are bitmap_row_stride(fmt, width) bytes apart from
// src[0, src_len) into `out` (resized to width * height, row-major, packed rgba() 0xAABBGGRR).
// Pixels whose bytes reach past src_len get bitmap_missing_color(). Because missing bytes are
// always a suffix, so are missing pixels: returns the number of decoded (non-missing) pixels in
// row-major order. width/height < 1 produce an empty image.
size_t decode_pixels(const uint8_t* src, size_t src_len, PixelFormat fmt, int width, int height,
                     std::vector<uint32_t>& out);

// Offset of the (first) byte holding pixel (x, y) of the image starting at `base`.
uint64_t pixel_to_offset(uint64_t base, PixelFormat fmt, int width, uint64_t x, uint64_t y);
// Inverse: the pixel that `offset` belongs to (for sub-byte formats, the leftmost pixel of that
// byte). Returns false if offset < base.
bool offset_to_pixel(uint64_t base, PixelFormat fmt, int width, uint64_t offset, uint64_t& x, uint64_t& y);

// Number of rows needed to show bytes [base, size) (the last one may be partial); 0 if base >= size.
uint64_t bitmap_row_count(uint64_t base, uint64_t size, PixelFormat fmt, int width);

// Horizontal scrolling: the largest first visible column when `page_cols` columns of a `width`
// pixel row fit the panel. A multiple of 8 (whole bytes for the sub-byte formats), rounded up so the
// last columns can be reached, but always < width (0 when the row fits).
uint64_t bitmap_max_col0(int width, uint64_t page_cols);

// Largest integer zoom in [1, max_zoom] at which `width` pixels fit into `avail_px` (1 if none fits).
int bitmap_fit_zoom(int width, float avail_px, int max_zoom = 16);

// ---- zoom levels: 1/16 .. 1/2 (downscale) and 1 .. 16 (nearest upscale) ---------------------------
// A level is an int: n >= 1 = n screen pixels per image pixel; -2, -4, -8, -16 = 1/2 .. 1/16 (one
// screen pixel averages a 2x2 .. 16x16 block of image pixels). Other values are not levels.
constexpr int kBitmapMinZoom = -16;
bool bitmap_zoom_valid(int level, int max_zoom = 16);
int bitmap_zoom_clamp(int level, int max_zoom = 16);   // nearest valid level (0 / -1 -> 1, -3 -> -2)
int bitmap_zoom_px(int level);                          // screen pixels per cell (1 when downscaled)
int bitmap_zoom_step(int level);                        // image pixels per cell side (1 when zoomed in)
int bitmap_zoom_next(int level, int dir, int max_zoom = 16);  // one level in (+1) or out (-1), clamped
const char* bitmap_zoom_label(int level);               // "4x", "1/4x" (static strings)
// Fit to width with downscaling: the largest level whose row of `width` pixels fits `avail_px`
// (down to 1/16; a row too wide even then gets 1/16).
int bitmap_fit_level(int width, float avail_px, int max_zoom = 16);

// Downscale (box filter): `px` holds h * sub decoded rows of w pixels (row-major, `valid` of them
// decoded: the rest is a missing suffix, see decode_pixels); every cell of the ceil(w / step) x h
// result averages the decoded pixels [x * step, x * step + step) of its `sub` rows (y * sub ..
// y * sub + sub - 1; `sub` <= step sampled rows of the step x step block, so the work stays within
// the caller's byte budget). A cell without a decoded pixel gets bitmap_missing_color(); those form
// a suffix, and the return value is the number of the others.
size_t bitmap_downscale(const std::vector<uint32_t>& px, size_t valid, int w, int h, int step, int sub,
                        std::vector<uint32_t>& out);

}  // namespace hx
