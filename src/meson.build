inc = include_directories('.')

# ---- core: documents, streaming I/O, edits, session, search, inspector, utils (no UI, no Lua) ----
core_lib = static_library('hexer_core',
  'core/os_file.cpp',
  'core/file_source.cpp',
  'core/piece_table.cpp',
  'core/highlight.cpp',
  'core/document.cpp',
  'core/session.cpp',
  'core/search.cpp',
  'core/inspector.cpp',
  'core/util.cpp',
  'core/settings.cpp',
  include_directories : inc,
  cpp_args : conf_args,
  dependencies : [threads_dep],
)
core_dep = declare_dependency(link_with : core_lib, include_directories : inc,
  dependencies : [threads_dep] + sys_deps)

# ---- script: Lua engine + hexer API ----
script_lib = static_library('hexer_script',
  'script/script_engine.cpp',
  'script/lua_api.cpp',
  include_directories : inc,
  cpp_args : conf_args,
  dependencies : [core_dep, lua_dep],
)
script_dep = declare_dependency(link_with : script_lib, dependencies : [core_dep, lua_dep])

# ---- ui: ImGui application ----
ui_lib = static_library('hexer_ui',
  'ui/theme.cpp',
  'ui/hex_view.cpp',
  'ui/panels.cpp',
  'ui/app.cpp',
  include_directories : inc,
  cpp_args : conf_args,
  dependencies : [script_dep, imgui_dep, glfw_dep, nfd_dep],
)

hexer_exe = executable('hexer',
  'main.cpp',
  include_directories : inc,
  cpp_args : conf_args,
  link_with : ui_lib,
  dependencies : [script_dep, imgui_dep, glfw_dep, nfd_dep] + sys_deps,
  win_subsystem : get_option('buildtype') == 'release' ? 'windows' : 'console',
  link_args : (cpp.get_id() == 'msvc' and get_option('buildtype') == 'release') ? ['/ENTRY:mainCRTStartup'] : [],
  install : true,
)

install_subdir(meson.project_source_root() / 'scripts', install_dir : get_option('bindir'))
