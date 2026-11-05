#pragma once
// Application entry: window, main loop, tabs, menus, panels, session, scripting host.
#include <string>
#include <vector>

namespace hx {

struct AppOptions {
    std::vector<std::string> files;  // files to open (positional args)
    std::string config_dir;          // --config-dir DIR : override config/session/scripts location
    bool no_session = false;         // --no-session     : don't restore or write the hot-exit session
    std::string screenshot;          // --screenshot out.ppm : render, save framebuffer (binary PPM), exit
    int frames = 0;                  // --frames N       : exit after N frames (smoke tests; with --screenshot default 30)
    std::string run_lua;             // --exec "lua code": run in the console after startup (tests / automation)
    std::vector<std::string> actions;  // --action NAME (repeatable): run menu/palette actions after startup
    bool new_instance = false;       // --new-instance   : never hand the files to a running Hexer
};

bool parse_args(int argc, char** argv, AppOptions& out, std::string* err);
int run_app(const AppOptions& opts);

}  // namespace hx
