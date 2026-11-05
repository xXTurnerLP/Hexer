#pragma once
// Entropy / byte-class minimap: a narrow vertical strip (meant to sit right of the hex view) that
// shows the whole document top to bottom, one EntropyResult bucket per pixel row (several buckets
// are averaged into a row when there are more buckets than pixels; few buckets are stretched).
// Self-contained (no App dependency): the caller owns the EntropyJob and passes its result().
#include <cstdint>

#include "core/entropy.h"

namespace hx {

enum class MinimapMode {
    Entropy,    // heat ramp of bits/byte (core entropy_color)
    ByteClass,  // per row: the six byte classes stacked left to right by their share (theme colors)
};

struct MinimapEvents {
    bool jump_requested = false;  // click / drag on the strip this frame
    uint64_t jump_offset = 0;     // with jump_requested: centre the hex view here (< doc_size)
    bool hovered = false;
    uint64_t hover_offset = 0;    // first byte of the hovered pixel row
};

// Pure geometry helpers (also used by tests). `rows` pixel rows show [0, size).
uint64_t minimap_row_offset(uint64_t row, uint64_t rows, uint64_t size);  // floor(row * size / rows)
// The pixel row (0..rows-1) that shows `offset`.
uint64_t minimap_offset_row(uint64_t offset, uint64_t rows, uint64_t size);

struct Minimap {
    // Draws the strip at the current cursor position (width x height; height <= 0 = the remaining
    // content height). `r` may be null (nothing scanned yet: neutral strip). [view_begin, view_end)
    // is the byte range visible in the hex view, drawn as a translucent box (min 3 px tall).
    // Hover shows a tooltip: offset range, entropy, class percentages, "sampled".
    void draw(const char* id, float width, float height, const EntropyResult* r, uint64_t doc_size,
              uint64_t view_begin, uint64_t view_end, MinimapMode mode, MinimapEvents& ev);

    uint64_t last_jump_ = UINT64_MAX;  // drag: only report a jump when the target row changes
};

}  // namespace hx
