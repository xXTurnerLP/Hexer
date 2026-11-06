#include "core/bitmap.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "core/highlight.h"

namespace hx {

const char* pixel_format_name(PixelFormat f) {
    switch (f) {
    case PixelFormat::Gray8: return "Gray 8-bit";
    case PixelFormat::Gray4: return "Gray 4-bit";
    case PixelFormat::Gray1: return "Gray 1-bit (MSB first)";
    case PixelFormat::RGB24: return "RGB 24-bit";
    case PixelFormat::BGR24: return "BGR 24-bit";
    case PixelFormat::RGBA32: return "RGBA 32-bit";
    case PixelFormat::BGRA32: return "BGRA 32-bit";
    case PixelFormat::ARGB32: return "ARGB 32-bit";
    case PixelFormat::RGB565LE: return "RGB565 LE";
    case PixelFormat::RGB565BE: return "RGB565 BE";
    case PixelFormat::RGB555LE: return "RGB555 LE";
    case PixelFormat::ByteClass: return "Byte class";
    }
    return "?";
}

int pixel_format_bits(PixelFormat f) {
    switch (f) {
    case PixelFormat::Gray1: return 1;
    case PixelFormat::Gray4: return 4;
    case PixelFormat::Gray8:
    case PixelFormat::ByteClass: return 8;
    case PixelFormat::RGB565LE:
    case PixelFormat::RGB565BE:
    case PixelFormat::RGB555LE: return 16;
    case PixelFormat::RGB24:
    case PixelFormat::BGR24: return 24;
    case PixelFormat::RGBA32:
    case PixelFormat::BGRA32:
    case PixelFormat::ARGB32: return 32;
    }
    return 8;
}

bool pixel_format_has_alpha(PixelFormat f) {
    return f == PixelFormat::RGBA32 || f == PixelFormat::BGRA32 || f == PixelFormat::ARGB32;
}

uint64_t bitmap_row_stride(PixelFormat f, int width) {
    const uint64_t w = uint64_t(std::max(width, 1));
    return (w * uint64_t(pixel_format_bits(f)) + 7) / 8;
}

uint32_t bitmap_byte_class_color(hx::ByteClass c) {
    switch (c) {
    case hx::ByteClass::Zero: return rgba(0x00, 0x00, 0x00);
    case hx::ByteClass::Whitespace: return rgba(0x9C, 0xE3, 0xFF);
    case hx::ByteClass::Printable: return rgba(0x3B, 0x82, 0xF6);
    case hx::ByteClass::Control: return rgba(0x22, 0xC5, 0x5E);
    case hx::ByteClass::High: return rgba(0xEF, 0x44, 0x44);
    case hx::ByteClass::Full: return rgba(0xFF, 0xFF, 0xFF);
    }
    return rgba(0x80, 0x80, 0x80);
}

namespace {

inline uint8_t expand5(unsigned v) { return uint8_t((v << 3) | (v >> 2)); }
inline uint8_t expand6(unsigned v) { return uint8_t((v << 2) | (v >> 4)); }

// Decodes one whole-byte pixel at p (pixel_format_bytes(f) bytes available).
inline uint32_t decode_one(PixelFormat f, const uint8_t* p) {
    switch (f) {
    case PixelFormat::Gray8: return rgba(p[0], p[0], p[0]);
    case PixelFormat::ByteClass: return bitmap_byte_class_color(byte_class(p[0]));
    case PixelFormat::RGB24: return rgba(p[0], p[1], p[2]);
    case PixelFormat::BGR24: return rgba(p[2], p[1], p[0]);
    case PixelFormat::RGBA32: return rgba(p[0], p[1], p[2], p[3]);
    case PixelFormat::BGRA32: return rgba(p[2], p[1], p[0], p[3]);
    case PixelFormat::ARGB32: return rgba(p[1], p[2], p[3], p[0]);
    case PixelFormat::RGB565LE:
    case PixelFormat::RGB565BE: {
        const unsigned v = f == PixelFormat::RGB565LE ? unsigned(p[0]) | (unsigned(p[1]) << 8)
                                                      : (unsigned(p[0]) << 8) | unsigned(p[1]);
        return rgba(expand5((v >> 11) & 31), expand6((v >> 5) & 63), expand5(v & 31));
    }
    case PixelFormat::RGB555LE: {
        const unsigned v = unsigned(p[0]) | (unsigned(p[1]) << 8);
        return rgba(expand5((v >> 10) & 31), expand5((v >> 5) & 31), expand5(v & 31));
    }
    case PixelFormat::Gray4:
    case PixelFormat::Gray1: break;  // handled by the caller
    }
    return 0;
}

}  // namespace

size_t decode_pixels(const uint8_t* src, size_t src_len, PixelFormat fmt, int width, int height,
                     std::vector<uint32_t>& out) {
    if (width < 1 || height < 1) {
        out.clear();
        return 0;
    }
    const size_t w = size_t(width), h = size_t(height);
    out.resize(w * h);
    const size_t stride = size_t(bitmap_row_stride(fmt, width));
    const int bits = pixel_format_bits(fmt);
    const size_t bpp_bytes = size_t(pixel_format_bytes(fmt));
    if (!src) src_len = 0;
    size_t valid = 0;
    for (size_t y = 0; y < h; ++y) {
        const size_t row = y * stride;
        uint32_t* dst = &out[y * w];
        for (size_t x = 0; x < w; ++x) {
            const size_t byte = row + (x * size_t(bits)) / 8;
            const bool have = bits < 8 ? byte < src_len : byte + bpp_bytes <= src_len;
            if (!have) {
                dst[x] = bitmap_missing_color(int(x), int(y));
                continue;
            }
            ++valid;
            if (bits == 1) {
                const bool on = (src[byte] >> (7 - (x & 7))) & 1;
                dst[x] = on ? rgba(255, 255, 255) : rgba(0, 0, 0);
            } else if (bits == 4) {
                const uint8_t v = (x & 1) ? uint8_t(src[byte] & 0x0F) : uint8_t(src[byte] >> 4);
                dst[x] = rgba(uint8_t(v * 17), uint8_t(v * 17), uint8_t(v * 17));
            } else {
                dst[x] = decode_one(fmt, src + byte);
            }
        }
    }
    return valid;
}

uint64_t pixel_to_offset(uint64_t base, PixelFormat fmt, int width, uint64_t x, uint64_t y) {
    return base + y * bitmap_row_stride(fmt, width) + (x * uint64_t(pixel_format_bits(fmt))) / 8;
}

bool offset_to_pixel(uint64_t base, PixelFormat fmt, int width, uint64_t offset, uint64_t& x, uint64_t& y) {
    if (offset < base) return false;
    const uint64_t stride = bitmap_row_stride(fmt, width);
    const uint64_t rel = offset - base;
    y = rel / stride;
    x = (rel % stride) * 8 / uint64_t(pixel_format_bits(fmt));
    return true;
}

uint64_t bitmap_row_count(uint64_t base, uint64_t size, PixelFormat fmt, int width) {
    if (base >= size) return 0;
    const uint64_t stride = bitmap_row_stride(fmt, width);
    const uint64_t n = size - base;
    return n / stride + (n % stride ? 1 : 0);
}

uint64_t bitmap_max_col0(int width, uint64_t page_cols) {
    const uint64_t w = uint64_t(std::max(width, 1));
    if (w <= page_cols) return 0;
    return std::min(((w - page_cols) + 7) & ~uint64_t(7), (w - 1) & ~uint64_t(7));
}

int bitmap_fit_zoom(int width, float avail_px, int max_zoom) {
    if (width < 1 || !(avail_px >= 1.0f)) return 1;
    const int z = int(std::floor(avail_px / float(width)));
    return std::clamp(z, 1, std::max(max_zoom, 1));
}

bool bitmap_zoom_valid(int level, int max_zoom) {
    if (level >= 1) return level <= std::max(max_zoom, 1);
    return level == -2 || level == -4 || level == -8 || level == -16;
}

int bitmap_zoom_clamp(int level, int max_zoom) {
    if (level >= 1) return std::min(level, std::max(max_zoom, 1));
    if (level > -2) return 1;
    int d = 2;
    while (d < 16 && -level >= 2 * d) d *= 2;
    return -d;
}

int bitmap_zoom_px(int level) { return level >= 1 ? level : 1; }

int bitmap_zoom_step(int level) { return level >= 1 ? 1 : -bitmap_zoom_clamp(level); }

int bitmap_zoom_next(int level, int dir, int max_zoom) {
    level = bitmap_zoom_clamp(level, max_zoom);
    if (dir > 0) {
        if (level == -2) return 1;
        return level < 0 ? level / 2 : std::min(level + 1, std::max(max_zoom, 1));
    }
    if (dir < 0) {
        if (level == 1) return -2;
        return level < 0 ? std::max(level * 2, kBitmapMinZoom) : level - 1;
    }
    return level;
}

const char* bitmap_zoom_label(int level) {
    static const char* const kIn[] = {"1x", "2x", "3x", "4x", "5x", "6x", "7x", "8x",
                                      "9x", "10x", "11x", "12x", "13x", "14x", "15x", "16x"};
    switch (bitmap_zoom_clamp(level)) {
    case -2: return "1/2x";
    case -4: return "1/4x";
    case -8: return "1/8x";
    case -16: return "1/16x";
    default: break;
    }
    return kIn[std::clamp(level, 1, 16) - 1];
}

int bitmap_fit_level(int width, float avail_px, int max_zoom) {
    if (width < 1 || !(avail_px >= 1.0f)) return 1;
    if (float(width) <= avail_px) return bitmap_fit_zoom(width, avail_px, max_zoom);
    for (int d = 2; d < 16; d *= 2)
        if (float((width + d - 1) / d) <= avail_px) return -d;
    return kBitmapMinZoom;
}

size_t bitmap_downscale(const std::vector<uint32_t>& px, size_t valid, int w, int h, int step, int sub,
                        std::vector<uint32_t>& out) {
    out.clear();
    if (w < 1 || h < 1 || step < 1 || sub < 1) return 0;
    const int cw = (w + step - 1) / step;
    out.resize(size_t(cw) * size_t(h));
    valid = std::min(valid, px.size());
    size_t cells = 0;
    std::vector<uint64_t> sum(size_t(cw) * 5);  // r, g, b, a, count per cell of one cell row
    for (int y = 0; y < h; ++y) {
        std::fill(sum.begin(), sum.end(), 0);
        for (int s = 0; s < sub; ++s) {
            const size_t row = (size_t(y) * size_t(sub) + size_t(s)) * size_t(w);
            for (int x = 0; x < w; ++x) {
                const size_t i = row + size_t(x);
                if (i >= valid) break;
                const uint32_t c = px[i];
                uint64_t* a = &sum[size_t(x / step) * 5];
                a[0] += c & 0xFF;
                a[1] += (c >> 8) & 0xFF;
                a[2] += (c >> 16) & 0xFF;
                a[3] += c >> 24;
                a[4] += 1;
            }
        }
        for (int x = 0; x < cw; ++x) {
            const uint64_t* a = &sum[size_t(x) * 5];
            uint32_t& o = out[size_t(y) * size_t(cw) + size_t(x)];
            if (!a[4]) {
                o = bitmap_missing_color(x, y);
                continue;
            }
            const uint64_t n = a[4], half = n / 2;
            o = uint32_t((a[0] + half) / n) | (uint32_t((a[1] + half) / n) << 8) |
                (uint32_t((a[2] + half) / n) << 16) | (uint32_t((a[3] + half) / n) << 24);
            ++cells;
        }
    }
    return cells;
}

}  // namespace hx
