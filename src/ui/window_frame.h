#pragma once
// The OS window frame (title bar with minimize / maximize / close) in the app's dark colors.
#include <cstdint>

struct GLFWwindow;

namespace hx {

// Windows: a dark title bar (DWMWA_USE_IMMERSIVE_DARK_MODE, Windows 10 1809+), on Windows 11 also
// in the app's own caption / text colors (packed IM_COL32), so it blends into the menu bar. Call it
// while the window is still hidden so it never shows up white. Elsewhere a no-op (Linux window
// managers draw the frame in the desktop's theme).
void apply_window_frame_colors(GLFWwindow* w, uint32_t caption_rgba, uint32_t text_rgba);

}  // namespace hx
