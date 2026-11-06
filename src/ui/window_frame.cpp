#include "ui/window_frame.h"

#ifdef _WIN32
#include <windows.h>
#include <dwmapi.h>
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3.h>
#include <GLFW/glfw3native.h>
#endif

namespace hx {

void apply_window_frame_colors(GLFWwindow* w, uint32_t caption_rgba, uint32_t text_rgba) {
#ifdef _WIN32
    HWND hwnd = w ? glfwGetWin32Window(w) : nullptr;
    if (!hwnd) return;
    // The attribute numbers are spelled out: older SDK headers do not name them all.
    // 20 = DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 10 2004+); builds 1809..1909 used 19.
    const BOOL dark = TRUE;
    if (FAILED(DwmSetWindowAttribute(hwnd, 20, &dark, sizeof dark)))
        DwmSetWindowAttribute(hwnd, 19, &dark, sizeof dark);
    // 35 = DWMWA_CAPTION_COLOR, 36 = DWMWA_TEXT_COLOR (Windows 11). IM_COL32 is 0xAABBGGRR and a
    // COLORREF 0x00BBGGRR, so dropping alpha converts. Older systems reject them: dark mode stays.
    const COLORREF caption = COLORREF(caption_rgba & 0x00FFFFFFu);
    const COLORREF text = COLORREF(text_rgba & 0x00FFFFFFu);
    DwmSetWindowAttribute(hwnd, 35, &caption, sizeof caption);
    DwmSetWindowAttribute(hwnd, 36, &text, sizeof text);
#else
    (void)w;
    (void)caption_rgba;
    (void)text_rgba;
#endif
}

}  // namespace hx
