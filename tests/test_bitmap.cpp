// Tests for core/bitmap: every pixel format decodes to exact colors, row stride with sub-byte
// formats, missing pixels past the data (partial last row), pixel <-> offset mapping.
#include <doctest/doctest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "core/bitmap.h"
#include "core/entropy.h"
#include "core/highlight.h"

using namespace hx;

namespace {

using Bytes = std::vector<uint8_t>;
using Pixels = std::vector<uint32_t>;

Pixels decode(const Bytes& b, PixelFormat f, int w, int h, size_t* valid = nullptr) {
    Pixels out;
    const size_t v = decode_pixels(b.data(), b.size(), f, w, h, out);
    if (valid) *valid = v;
    return out;
}

}  // namespace

TEST_CASE("bitmap: format names, bits, stride") {
    for (int i = 0; i < kPixelFormatCount; ++i) {
        const PixelFormat f = PixelFormat(i);
        CHECK(std::string(pixel_format_name(f)) != "?");
        const int b = pixel_format_bits(f);
        CHECK((b == 1 || b == 4 || b == 8 || b == 16 || b == 24 || b == 32));
    }
    CHECK(pixel_format_bits(PixelFormat::Gray1) == 1);
    CHECK(pixel_format_bits(PixelFormat::Gray4) == 4);
    CHECK(pixel_format_bits(PixelFormat::RGB565BE) == 16);
    CHECK(pixel_format_bits(PixelFormat::BGR24) == 24);
    CHECK(pixel_format_bits(PixelFormat::ARGB32) == 32);
    CHECK(pixel_format_bytes(PixelFormat::Gray1) == 1);
    CHECK(pixel_format_bytes(PixelFormat::RGBA32) == 4);
    CHECK(pixel_format_has_alpha(PixelFormat::BGRA32));
    CHECK_FALSE(pixel_format_has_alpha(PixelFormat::RGB24));

    CHECK(bitmap_row_stride(PixelFormat::Gray8, 7) == 7);
    CHECK(bitmap_row_stride(PixelFormat::Gray4, 7) == 4);   // 28 bits -> 4 bytes
    CHECK(bitmap_row_stride(PixelFormat::Gray4, 8) == 4);
    CHECK(bitmap_row_stride(PixelFormat::Gray1, 1) == 1);
    CHECK(bitmap_row_stride(PixelFormat::Gray1, 9) == 2);
    CHECK(bitmap_row_stride(PixelFormat::Gray1, 16) == 2);
    CHECK(bitmap_row_stride(PixelFormat::RGB24, 5) == 15);
    CHECK(bitmap_row_stride(PixelFormat::RGB565LE, 3) == 6);
    CHECK(bitmap_row_stride(PixelFormat::RGBA32, 8192) == 32768);
    CHECK(bitmap_row_stride(PixelFormat::Gray8, 0) == 1);   // width < 1 counts as 1
}

TEST_CASE("bitmap: 8-bit and byte-wise formats") {
    SUBCASE("Gray8") {
        auto p = decode({0x00, 0x7F, 0xFF}, PixelFormat::Gray8, 3, 1);
        CHECK(p == Pixels{rgba(0, 0, 0), rgba(0x7F, 0x7F, 0x7F), rgba(255, 255, 255)});
    }
    SUBCASE("RGB24 / BGR24") {
        Bytes b = {0x10, 0x20, 0x30, 0xA0, 0xB0, 0xC0};
        CHECK(decode(b, PixelFormat::RGB24, 2, 1) == Pixels{rgba(0x10, 0x20, 0x30), rgba(0xA0, 0xB0, 0xC0)});
        CHECK(decode(b, PixelFormat::BGR24, 2, 1) == Pixels{rgba(0x30, 0x20, 0x10), rgba(0xC0, 0xB0, 0xA0)});
    }
    SUBCASE("32-bit orders") {
        Bytes b = {0x11, 0x22, 0x33, 0x44};
        CHECK(decode(b, PixelFormat::RGBA32, 1, 1) == Pixels{rgba(0x11, 0x22, 0x33, 0x44)});
        CHECK(decode(b, PixelFormat::BGRA32, 1, 1) == Pixels{rgba(0x33, 0x22, 0x11, 0x44)});
        CHECK(decode(b, PixelFormat::ARGB32, 1, 1) == Pixels{rgba(0x22, 0x33, 0x44, 0x11)});
        // packed layout really is 0xAABBGGRR
        CHECK(decode(b, PixelFormat::RGBA32, 1, 1)[0] == 0x44332211u);
    }
    SUBCASE("ByteClass") {
        Bytes b = {0x00, 0x20, 'A', 0x01, 0x80, 0xFF, 0x0A, 0x7F};
        auto p = decode(b, PixelFormat::ByteClass, 8, 1);
        REQUIRE(p.size() == 8);
        for (size_t i = 0; i < b.size(); ++i) CHECK(p[i] == bitmap_byte_class_color(byte_class(b[i])));
        CHECK(p[0] == rgba(0, 0, 0));
        CHECK(p[5] == rgba(255, 255, 255));
        // every class gets its own opaque color
        for (int i = 0; i < kByteClassCount; ++i) {
            CHECK((bitmap_byte_class_color(ByteClass(i)) >> 24) == 0xFF);
            for (int j = i + 1; j < kByteClassCount; ++j)
                CHECK(bitmap_byte_class_color(ByteClass(i)) != bitmap_byte_class_color(ByteClass(j)));
        }
    }
}

TEST_CASE("bitmap: 16-bit formats") {
    // 0xF800 = pure red, 0x07E0 = pure green, 0x001F = pure blue, 0xFFFF = white
    SUBCASE("RGB565LE") {
        Bytes b = {0x00, 0xF8, 0xE0, 0x07, 0x1F, 0x00, 0xFF, 0xFF};
        CHECK(decode(b, PixelFormat::RGB565LE, 4, 1) ==
              Pixels{rgba(255, 0, 0), rgba(0, 255, 0), rgba(0, 0, 255), rgba(255, 255, 255)});
    }
    SUBCASE("RGB565BE") {
        Bytes b = {0xF8, 0x00, 0x07, 0xE0, 0x00, 0x1F, 0x00, 0x00};
        CHECK(decode(b, PixelFormat::RGB565BE, 4, 1) ==
              Pixels{rgba(255, 0, 0), rgba(0, 255, 0), rgba(0, 0, 255), rgba(0, 0, 0)});
    }
    SUBCASE("RGB565 mid values expand by bit replication") {
        // r=0b10000 (16) -> 0x84, g=0b100000 (32) -> 0x82, b=0b00001 -> 0x08
        const unsigned v = (16u << 11) | (32u << 5) | 1u;
        Bytes b = {uint8_t(v & 0xFF), uint8_t(v >> 8)};
        CHECK(decode(b, PixelFormat::RGB565LE, 1, 1) == Pixels{rgba(0x84, 0x82, 0x08)});
    }
    SUBCASE("RGB555LE ignores the top bit") {
        // 0x7C00 red, 0x03E0 green, 0x001F blue, 0x8000 black (top bit only)
        Bytes b = {0x00, 0x7C, 0xE0, 0x03, 0x1F, 0x00, 0x00, 0x80};
        CHECK(decode(b, PixelFormat::RGB555LE, 4, 1) ==
              Pixels{rgba(255, 0, 0), rgba(0, 255, 0), rgba(0, 0, 255), rgba(0, 0, 0)});
        const unsigned v = (16u << 10) | (1u << 5) | 31u;  // r 0x84, g 0x08, b 0xFF
        Bytes c = {uint8_t(v & 0xFF), uint8_t(v >> 8)};
        CHECK(decode(c, PixelFormat::RGB555LE, 1, 1) == Pixels{rgba(0x84, 0x08, 0xFF)});
    }
}

TEST_CASE("bitmap: sub-byte formats and row padding") {
    SUBCASE("Gray4 high nibble first") {
        auto p = decode({0x0F, 0x8A}, PixelFormat::Gray4, 4, 1);
        CHECK(p == Pixels{rgba(0, 0, 0), rgba(255, 255, 255), rgba(0x88, 0x88, 0x88), rgba(0xAA, 0xAA, 0xAA)});
    }
    SUBCASE("Gray4 odd width pads each row to a byte") {
        // width 3 -> stride 2; row 0 = 0x12 0x3x, row 1 = 0x45 0x6x (low nibble of byte 1 is padding)
        auto p = decode({0x12, 0x3F, 0x45, 0x6F}, PixelFormat::Gray4, 3, 2);
        auto g = [](int v) { return rgba(uint8_t(v * 17), uint8_t(v * 17), uint8_t(v * 17)); };
        CHECK(p == Pixels{g(1), g(2), g(3), g(4), g(5), g(6)});
    }
    SUBCASE("Gray1 MSB first") {
        auto p = decode({0xA5}, PixelFormat::Gray1, 8, 1);
        const uint32_t W = rgba(255, 255, 255), B = rgba(0, 0, 0);
        CHECK(p == Pixels{W, B, W, B, B, W, B, W});
    }
    SUBCASE("Gray1 width 3: each row starts on a new byte") {
        // row 0: 0b101xxxxx, row 1: 0b011xxxxx
        auto p = decode({0xBF, 0x7F}, PixelFormat::Gray1, 3, 2);
        const uint32_t W = rgba(255, 255, 255), B = rgba(0, 0, 0);
        CHECK(p == Pixels{W, B, W, B, W, W});
    }
    SUBCASE("Gray1 width 10 uses 2 bytes per row") {
        auto p = decode({0xFF, 0xC0, 0x00, 0x40}, PixelFormat::Gray1, 10, 2);
        const uint32_t W = rgba(255, 255, 255), B = rgba(0, 0, 0);
        CHECK(p == Pixels{W, W, W, W, W, W, W, W, W, W, B, B, B, B, B, B, B, B, B, W});
    }
}

TEST_CASE("bitmap: missing pixels past the data") {
    SUBCASE("partial last row") {
        size_t valid = 0;
        auto p = decode({1, 2, 3, 4, 5}, PixelFormat::Gray8, 4, 2, &valid);
        REQUIRE(p.size() == 8);
        CHECK(valid == 5);
        CHECK(p[4] == rgba(5, 5, 5));
        for (size_t i = 5; i < 8; ++i) {
            CHECK((p[i] >> 24) == 0);  // transparent marker
            CHECK(p[i] == bitmap_missing_color(int(i % 4), int(i / 4)));
        }
    }
    SUBCASE("multi-byte pixel cut in half is missing") {
        size_t valid = 0;
        auto p = decode({1, 2, 3, 4, 5}, PixelFormat::RGB24, 2, 1, &valid);
        CHECK(valid == 1);
        CHECK(p[0] == rgba(1, 2, 3));
        CHECK(p[1] == bitmap_missing_color(1, 0));
    }
    SUBCASE("sub-byte: a present byte decodes all its pixels") {
        size_t valid = 0;
        auto p = decode({0xFF}, PixelFormat::Gray1, 4, 3, &valid);  // stride 1, rows 1-2 missing
        CHECK(valid == 4);
        for (size_t i = 4; i < 12; ++i) CHECK((p[i] >> 24) == 0);
    }
    SUBCASE("no data at all / null source") {
        Pixels out;
        CHECK(decode_pixels(nullptr, 100, PixelFormat::Gray8, 8, 8, out) == 0);
        REQUIRE(out.size() == 64);
        CHECK(out[0] == kBitmapMissingA);
        CHECK(out[4] == kBitmapMissingB);    // 4x4 checker
        CHECK(out[4 * 8] == kBitmapMissingB);
        CHECK(out[4 * 8 + 4] == kBitmapMissingA);
    }
    SUBCASE("empty image") {
        Pixels out = {1, 2, 3};
        CHECK(decode_pixels(nullptr, 0, PixelFormat::Gray8, 0, 5, out) == 0);
        CHECK(out.empty());
    }
    CHECK(kBitmapMissingA != kBitmapMissingB);
    CHECK((kBitmapMissingA >> 24) == 0);
}

TEST_CASE("bitmap: pixel <-> offset mapping") {
    SUBCASE("byte formats") {
        CHECK(pixel_to_offset(100, PixelFormat::RGB24, 10, 0, 0) == 100);
        CHECK(pixel_to_offset(100, PixelFormat::RGB24, 10, 3, 2) == 100 + 2 * 30 + 9);
        uint64_t x = 0, y = 0;
        REQUIRE(offset_to_pixel(100, PixelFormat::RGB24, 10, 100 + 2 * 30 + 10, x, y));  // middle byte
        CHECK(x == 3);
        CHECK(y == 2);
        CHECK_FALSE(offset_to_pixel(100, PixelFormat::RGB24, 10, 99, x, y));
        for (uint64_t yy = 0; yy < 4; ++yy)
            for (uint64_t xx = 0; xx < 10; ++xx) {
                const uint64_t off = pixel_to_offset(7, PixelFormat::RGB565BE, 10, xx, yy);
                REQUIRE(offset_to_pixel(7, PixelFormat::RGB565BE, 10, off, x, y));
                CHECK(x == xx);
                CHECK(y == yy);
            }
    }
    SUBCASE("sub-byte formats") {
        // Gray1 width 10: stride 2, pixel 9 is in the second byte
        CHECK(pixel_to_offset(0, PixelFormat::Gray1, 10, 9, 0) == 1);
        CHECK(pixel_to_offset(0, PixelFormat::Gray1, 10, 0, 1) == 2);
        CHECK(pixel_to_offset(0, PixelFormat::Gray4, 3, 2, 1) == 3);
        uint64_t x = 0, y = 0;
        REQUIRE(offset_to_pixel(0, PixelFormat::Gray1, 10, 1, x, y));
        CHECK(x == 8);  // leftmost pixel of that byte
        CHECK(y == 0);
        REQUIRE(offset_to_pixel(0, PixelFormat::Gray4, 3, 3, x, y));
        CHECK(x == 2);
        CHECK(y == 1);
    }
    SUBCASE("multi-TiB offsets stay exact") {
        const uint64_t base = (uint64_t(3) << 40) + 5;  // 3 TiB + 5
        const uint64_t row = (uint64_t(1) << 30);
        const uint64_t off = pixel_to_offset(base, PixelFormat::RGBA32, 8192, 100, row);
        CHECK(off == base + row * 32768 + 400);
        uint64_t x = 0, y = 0;
        REQUIRE(offset_to_pixel(base, PixelFormat::RGBA32, 8192, off + 3, x, y));
        CHECK(x == 100);
        CHECK(y == row);
    }
}

TEST_CASE("bitmap: row count and fit zoom") {
    CHECK(bitmap_row_count(0, 0, PixelFormat::Gray8, 16) == 0);
    CHECK(bitmap_row_count(0, 16, PixelFormat::Gray8, 16) == 1);
    CHECK(bitmap_row_count(0, 17, PixelFormat::Gray8, 16) == 2);
    CHECK(bitmap_row_count(10, 17, PixelFormat::Gray8, 16) == 1);
    CHECK(bitmap_row_count(20, 17, PixelFormat::Gray8, 16) == 0);
    CHECK(bitmap_row_count(0, 7, PixelFormat::Gray1, 10) == 4);  // stride 2
    const uint64_t tib3 = uint64_t(3) << 40;
    CHECK(bitmap_row_count(0, tib3, PixelFormat::Gray8, 512) == tib3 / 512);

    CHECK(bitmap_fit_zoom(256, 1024.0f) == 4);
    CHECK(bitmap_fit_zoom(256, 1023.0f) == 3);
    CHECK(bitmap_fit_zoom(8, 1000.0f) == 16);   // capped
    CHECK(bitmap_fit_zoom(8, 1000.0f, 8) == 8);
    CHECK(bitmap_fit_zoom(4096, 500.0f) == 1);  // does not fit at all
    CHECK(bitmap_fit_zoom(0, 500.0f) == 1);
    CHECK(bitmap_fit_zoom(16, 0.0f) == 1);
}

TEST_CASE("bitmap: zoom levels below 1x, fit with downscaling, box downscale") {
    CHECK(bitmap_zoom_valid(1));
    CHECK(bitmap_zoom_valid(16));
    CHECK_FALSE(bitmap_zoom_valid(17));
    CHECK(bitmap_zoom_valid(-2));
    CHECK(bitmap_zoom_valid(-16));
    CHECK_FALSE(bitmap_zoom_valid(-3));
    CHECK_FALSE(bitmap_zoom_valid(0));
    CHECK_FALSE(bitmap_zoom_valid(-1));
    CHECK(bitmap_zoom_clamp(0) == 1);
    CHECK(bitmap_zoom_clamp(-1) == 1);
    CHECK(bitmap_zoom_clamp(-3) == -2);
    CHECK(bitmap_zoom_clamp(-12) == -8);
    CHECK(bitmap_zoom_clamp(-1000) == -16);
    CHECK(bitmap_zoom_clamp(40) == 16);
    CHECK(bitmap_zoom_clamp(9, 8) == 8);
    CHECK(bitmap_zoom_px(4) == 4);
    CHECK(bitmap_zoom_px(-4) == 1);
    CHECK(bitmap_zoom_step(4) == 1);
    CHECK(bitmap_zoom_step(-4) == 4);
    CHECK(bitmap_zoom_next(2, -1) == 1);
    CHECK(bitmap_zoom_next(1, -1) == -2);
    CHECK(bitmap_zoom_next(-2, -1) == -4);
    CHECK(bitmap_zoom_next(-16, -1) == -16);
    CHECK(bitmap_zoom_next(-4, 1) == -2);
    CHECK(bitmap_zoom_next(-2, 1) == 1);
    CHECK(bitmap_zoom_next(16, 1) == 16);
    CHECK(std::string(bitmap_zoom_label(-4)) == "1/4x");
    CHECK(std::string(bitmap_zoom_label(3)) == "3x");
    // Fit: zooms in while the row fits, else the smallest downscale that fits.
    CHECK(bitmap_fit_level(256, 1024.0f) == 4);
    CHECK(bitmap_fit_level(1024, 1024.0f) == 1);
    CHECK(bitmap_fit_level(1025, 1024.0f) == -2);
    CHECK(bitmap_fit_level(4096, 1024.0f) == -4);
    CHECK(bitmap_fit_level(4097, 1024.0f) == -8);
    CHECK(bitmap_fit_level(8192, 100.0f) == -16);  // too wide even at 1/16x
    CHECK(bitmap_fit_level(0, 100.0f) == 1);

    // Box filter: 5 x 2 pixels, step 2, both rows read -> 3 x 1 cells (the last one 1 pixel wide).
    std::vector<uint32_t> px = {rgba(0, 0, 0),     rgba(100, 0, 0),  rgba(10, 20, 30), rgba(10, 20, 30), rgba(7, 7, 7),
                                rgba(100, 100, 0), rgba(0, 100, 0), rgba(30, 40, 50), rgba(30, 40, 50), rgba(9, 9, 9)};
    std::vector<uint32_t> out;
    CHECK(bitmap_downscale(px, px.size(), 5, 1, 2, 2, out) == 3);
    REQUIRE(out.size() == 3);
    CHECK(out[0] == rgba(50, 50, 0));
    CHECK(out[1] == rgba(20, 30, 40));
    CHECK(out[2] == rgba(8, 8, 8));
    // One sampled row per cell row (sub 1): only that row counts.
    CHECK(bitmap_downscale(px, px.size(), 5, 2, 2, 1, out) == 6);
    CHECK(out[0] == rgba(50, 0, 0));
    CHECK(out[3] == rgba(50, 100, 0));
    // Missing pixels: a partly decoded cell averages what it has, an empty one is the marker.
    CHECK(bitmap_downscale(px, 3, 5, 2, 2, 1, out) == 2);
    CHECK(out[1] == rgba(10, 20, 30));
    CHECK(out[2] == bitmap_missing_color(2, 0));
    CHECK(out[3] == bitmap_missing_color(0, 1));
    CHECK(bitmap_downscale(px, px.size(), 0, 1, 2, 1, out) == 0);
    CHECK(out.empty());
}

TEST_CASE("bitmap: horizontal scroll limit stays inside the row") {
    CHECK(bitmap_max_col0(256, 300) == 0);    // fits
    CHECK(bitmap_max_col0(256, 256) == 0);
    CHECK(bitmap_max_col0(256, 100) == 160);  // 156 rounded up: columns 160..255 are shown
    CHECK(bitmap_max_col0(8192, 1000) == 7192);
    // A page narrower than 8 columns (high zoom, narrow panel): rounding up must not pass the row.
    CHECK(bitmap_max_col0(20, 3) == 16);
    CHECK(bitmap_max_col0(8, 1) == 0);
    CHECK(bitmap_max_col0(9, 1) == 8);
    CHECK(bitmap_max_col0(0, 0) == 0);
    for (int w = 1; w <= 80; ++w)
        for (uint64_t page = 1; page <= 90; ++page) {
            const uint64_t m = bitmap_max_col0(w, page);
            CHECK(m % 8 == 0);
            CHECK(m < uint64_t(w));
            if (uint64_t(w) > page) CHECK(m + page + 7 >= uint64_t(w));  // the last columns are within reach
        }
}
