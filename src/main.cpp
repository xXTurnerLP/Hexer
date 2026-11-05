#include <cstdio>

#include "ui/app.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// Release builds use the GUI subsystem (no console window, src/meson.build). When such a build is
// started from a terminal, attach to that terminal so usage text and errors still show up there.
static void attach_parent_console() {
    if (GetConsoleWindow()) return;  // console build, or already attached
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) return;  // started from Explorer: stay silent
    FILE* f = nullptr;
    if (_fileno(stdout) < 0) freopen_s(&f, "CONOUT$", "w", stdout);
    if (_fileno(stderr) < 0) freopen_s(&f, "CONOUT$", "w", stderr);
}
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
    attach_parent_console();
#endif
    hx::AppOptions opts;
    std::string err;
    if (!hx::parse_args(argc, argv, opts, &err)) {
        std::fprintf(stderr, "hexer: %s\n", err.c_str());
        return 2;
    }
    return hx::run_app(opts);
}
