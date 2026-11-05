// The Lua 5.5 core + standard libraries as ONE C++ translation unit (the "onelua" layout Lua's own
// sources support). The wrap (subprojects/lua-5.5.0) only provides the sources and headers.
//
// Why C++: compiled as C, lua_error() longjmp()s over the C++ frames of our lua_CFunctions and skips
// their destructors (undefined behaviour; with MSVC it was seen to crash). Compiled as C++, ldo.c's
// LUAI_THROW / LUAI_TRY use throw / try-catch, so a Lua error unwinds through our code like any C++
// exception and every std::string / std::vector / shared_ptr alive there is destroyed.
//
// Consequences for the rest of the code base:
//   * The Lua API has C++ linkage: include "lua.h", "lualib.h", "lauxlib.h" directly (as
//     script/lua_internal.h does), never lua.hpp (its extern "C" block would not link).
//   * A catch (...) on a path called from Lua would swallow Lua errors: there must be none (catch
//     specific exception types only, or rethrow).
//   * No noexcept function (or destructor) may let a Lua error escape: std::terminate.
// This TU is third-party code: it is built without warnings (root meson.build).
#if !defined(__cplusplus) || defined(LUA_USE_LONGJMP) || defined(LUAI_THROW)
#error "Lua must be compiled as C++ with its exception-based error handling"
#endif

#include "lprefix.h"  // must come first (feature macros)

// Every system header the Lua sources use, up front: llex.c defines a `next(ls)` macro, and a
// libstdc++ header pulled in later (math.h -> <cmath> -> std::next) would hit it. Included here
// first, the later #includes inside the .c files are no-ops.
#include <cassert>
#include <cctype>
#include <cerrno>
#include <cfloat>
#include <climits>
#include <clocale>
#include <cmath>
#include <csetjmp>
#include <csignal>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(LUA_USE_DLOPEN)
#include <dlfcn.h>
#endif
#endif

// One definition for every file below (each defines LUA_CORE or LUA_LIB itself; identical
// redefinitions are fine). luaconf.h reads them on its first inclusion.
#define LUA_CORE
#define LUA_LIB
#include "luaconf.h"

// core
#include "lzio.c"
#include "lctype.c"
#include "lopcodes.c"
#include "lmem.c"
#include "lundump.c"
#include "ldump.c"
#include "lstate.c"
#include "lgc.c"
#include "llex.c"
#undef next  // llex.c-local helper; must not reach any header included later
#include "lcode.c"
#include "lparser.c"
#include "ldebug.c"
#include "lfunc.c"
#include "lobject.c"
#include "ltm.c"
#include "lstring.c"
#include "ltable.c"
#include "ldo.c"
#include "lvm.c"
#include "lapi.c"

// auxiliary + standard libraries
#include "lauxlib.c"
#include "lbaselib.c"
#include "lcorolib.c"
#include "ldblib.c"
#include "liolib.c"
#include "lmathlib.c"
#include "loadlib.c"
#include "loslib.c"
#include "lstrlib.c"
#include "ltablib.c"
#include "lutf8lib.c"
#include "linit.c"
