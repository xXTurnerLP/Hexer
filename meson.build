project('hexer', ['c', 'cpp'],
  version : '0.1.0',
  meson_version : '>=1.3.0',
  default_options : [
    'cpp_std=c++20',
    'warning_level=2',
    'buildtype=debugoptimized',
    'b_vscrt=static_from_buildtype',
    'default_library=static',
    'lua:interpreter=false',
    'imgui-docking:dx9=disabled', 'imgui-docking:dx10=disabled', 'imgui-docking:dx11=disabled',
    'imgui-docking:dx12=disabled', 'imgui-docking:metal=disabled', 'imgui-docking:vulkan=disabled',
    'imgui-docking:webgpu=disabled', 'imgui-docking:sdl2=disabled', 'imgui-docking:sdl3=disabled',
    'imgui-docking:sdl2_renderer=disabled', 'imgui-docking:sdl3_renderer=disabled',
    'imgui-docking:sdl3_gpu=disabled', 'imgui-docking:osx=disabled', 'imgui-docking:win=disabled',
    'imgui-docking:allegro5=disabled',
    'imgui-docking:opengl=enabled', 'imgui-docking:glfw=enabled',
  ],
)

cpp = meson.get_compiler('cpp')
proj_args = []
if host_machine.system() == 'windows'
  proj_args += ['-DNOMINMAX', '-DWIN32_LEAN_AND_MEAN', '-D_CRT_SECURE_NO_WARNINGS', '-DUNICODE', '-D_UNICODE']
endif
if cpp.get_id() == 'msvc'
  proj_args += ['/utf-8', '/Zc:__cplusplus']
endif
add_project_arguments(proj_args, language : 'cpp')

threads_dep = dependency('threads')
lua_dep     = dependency('lua', fallback : ['lua', 'lua_dep'])
glfw_dep    = dependency('glfw3')
imgui_dep   = dependency('imgui-docking')
# FreeType (hinted font rasteriser) only reads plain TTF/OTF files here: no optional codecs.
# Its own sources are third-party code: build them without warnings when it is a subproject.
freetype_dep = dependency('freetype2', default_options : ['png=disabled', 'zlib=disabled',
  'bzip2=disabled', 'brotli=disabled', 'harfbuzz=disabled', 'tests=disabled', 'warning_level=0'])
nfd_dep     = dependency('nativefiledialog-extended')
doctest_dep = dependency('doctest', required : get_option('tests'))

sys_deps = []
if host_machine.system() == 'windows'
  foreach l : ['shell32', 'ole32', 'uuid', 'user32', 'comdlg32']
    sys_deps += cpp.find_library(l)
  endforeach
endif

scripts_src_dir = (meson.project_source_root() / 'scripts').replace('\\', '/')
conf_args = [
  '-DHEXER_VERSION="@0@"'.format(meson.project_version()),
  '-DHEXER_SOURCE_SCRIPTS_DIR="@0@"'.format(scripts_src_dir),
]

subdir('src')

if get_option('tests')
  subdir('tests')
endif
