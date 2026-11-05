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
  'core/nav.cpp',            # pointer follow + jump history
  'core/strings_scan.cpp',   # background strings extraction
  'core/hash.cpp',           # checksums / hashes of ranges
  'core/cstruct.cpp',        # C struct definitions -> Lua parser source
  'core/entropy.cpp',        # byte classes + entropy overview (minimap)
  'core/bitmap.cpp',         # bytes -> pixels (bitmap view)
  'core/diff.cpp',           # compare two documents
  'core/pcap.cpp',           # pcap/pcapng packet index
  'core/procmem.cpp',        # process memory as a byte source
  'core/devices.cpp',        # enumerate processes / disks
  'core/xorscan.cpp',        # XOR / ADD / ROL brute force
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

# ---- ui view: theme/fonts + the hex view widget (no window, no Lua; tests/test_ui.cpp drives it) ----
ui_view_lib = static_library('hexer_ui_view',
  'ui/theme.cpp',
  'ui/hex_view.cpp',
  'ui/minimap.cpp',
  'ui/third_party/imgui_freetype.cpp',  # vendored from imgui misc/freetype (MIT)
  include_directories : inc,
  cpp_args : conf_args,
  dependencies : [core_dep, imgui_dep, freetype_dep],
)
ui_view_dep = declare_dependency(link_with : ui_view_lib, include_directories : inc,
  dependencies : [core_dep, imgui_dep, freetype_dep])

# ---- ui: ImGui application ----
ui_lib = static_library('hexer_ui',
  'ui/panels.cpp',
  'ui/app.cpp',
  'ui/panel_strings.cpp',
  'ui/panel_hash.cpp',
  'ui/dialog_cstruct.cpp',
  'ui/panel_bitmap.cpp',
  'ui/view_diff.cpp',
  'ui/panel_packets.cpp',
  'ui/dialog_targets.cpp',
  'ui/panel_history.cpp',
  'ui/panel_xor.cpp',
  include_directories : inc,
  cpp_args : conf_args,
  link_with : ui_view_lib,
  dependencies : [script_dep, imgui_dep, glfw_dep, nfd_dep, freetype_dep],
)

hexer_src = ['main.cpp']
hexer_link_args = []
if host_machine.system() == 'windows'
  # App icon + manifest (UTF-8 active code page, Win10/11, per-monitor DPI v2).
  windows = import('windows')
  hexer_src += windows.compile_resources('hexer.rc',
    depend_files : ['hexer.manifest', '../assets/icon/hexer.ico'],
    include_directories : include_directories('.', '../assets/icon'))
  if cpp.get_argument_syntax() == 'msvc'  # MSVC and clang-cl (link.exe / lld-link)
    hexer_link_args += ['/MANIFEST:NO']  # ours is the only one (no linker-generated manifest)
  endif
endif
if cpp.get_id() == 'msvc' and get_option('buildtype') == 'release'
  hexer_link_args += ['/ENTRY:mainCRTStartup']
endif

hexer_exe = executable('hexer',
  hexer_src,
  include_directories : inc,
  cpp_args : conf_args,
  link_with : ui_lib,
  dependencies : [script_dep, imgui_dep, glfw_dep, nfd_dep] + sys_deps,
  win_subsystem : get_option('buildtype') == 'release' ? 'windows' : 'console',
  link_args : hexer_link_args,
  install : true,
)

install_subdir(meson.project_source_root() / 'scripts', install_dir : get_option('bindir'))

# Linux desktop integration: launcher entry + hicolor theme icons.
if host_machine.system() == 'linux'
  install_data('../assets/hexer.desktop', install_dir : get_option('datadir') / 'applications')
  foreach s : [16, 24, 32, 48, 64, 128, 256]
    install_data('../assets/icon/hexer-@0@.png'.format(s), rename : 'hexer.png',
      install_dir : get_option('datadir') / 'icons' / 'hicolor' / '@0@x@0@'.format(s) / 'apps')
  endforeach
endif
