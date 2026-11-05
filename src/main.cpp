#include <cstdio>

#include "ui/app.h"

int main(int argc, char** argv) {
    hx::AppOptions opts;
    std::string err;
    if (!hx::parse_args(argc, argv, opts, &err)) {
        std::fprintf(stderr, "hexer: %s\n", err.c_str());
        return 2;
    }
    return hx::run_app(opts);
}
