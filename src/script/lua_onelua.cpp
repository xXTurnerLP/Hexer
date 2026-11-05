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
