# One executable per module so modules can be built/tested independently.
test_main = files('test_main.cpp')

test_core = executable('test_core', 'test_core.cpp', test_main,
  dependencies : [core_dep, doctest_dep], cpp_args : conf_args)
test('core', test_core, timeout : 300)

test_util = executable('test_util', 'test_util.cpp', test_main,
  dependencies : [core_dep, doctest_dep], cpp_args : conf_args)
test('util', test_util, timeout : 300)

test_script = executable('test_script', 'test_script.cpp', test_main,
  dependencies : [script_dep, doctest_dep], cpp_args : conf_args)
test('script', test_script, timeout : 300)

# Cross-module tests (search over Snapshots, settings/paths via os_file).
test_search = executable('test_search', 'test_search.cpp', test_main,
  dependencies : [core_dep, doctest_dep], cpp_args : conf_args)
test('search', test_search, timeout : 300)

# Headless UI tests: an ImGui context without a window/GL drives HexView with simulated mouse and
# keyboard input (selection, hit testing, typing, undo merging).
test_ui = executable('test_ui', 'test_ui.cpp', test_main,
  dependencies : [ui_view_dep, doctest_dep], cpp_args : conf_args)
test('ui', test_ui, timeout : 300)

# Feature suites (one exe each so features can be built/tested independently).
foreach t : ['nav', 'strings', 'hash', 'entropy', 'bitmap', 'diff', 'pcap', 'tail', 'procmem', 'history', 'xorscan', 'session']
  exe = executable('test_' + t, 'test_' + t + '.cpp', test_main,
    dependencies : [core_dep, doctest_dep], cpp_args : conf_args)
  test(t, exe, timeout : 300)
endforeach
test_cstruct = executable('test_cstruct', 'test_cstruct.cpp', test_main,
  dependencies : [script_dep, doctest_dep], cpp_args : conf_args)
test('cstruct', test_cstruct, timeout : 300)

# Disassembly (Zydis) + PE / ELF address maps + hx.disasm / doc:disasm + the headless Disassembly panel.
test_disasm = executable('test_disasm', 'test_disasm.cpp', test_main,
  dependencies : [script_dep, ui_view_dep, doctest_dep], cpp_args : conf_args)
test('disasm', test_disasm, timeout : 300)
