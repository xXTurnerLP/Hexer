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

# Headless Compare view (DiffView): next / previous difference, Find Shift, synced scrolling.
test_diffview = executable('test_diffview', 'test_diffview.cpp', test_main,
  dependencies : [ui_view_dep, doctest_dep], cpp_args : conf_args)
test('diffview', test_diffview, timeout : 300)

# Headless Packets + Bitmap panels: row clicks / Up / Down, format change, show at cursor, image clicks.
test_panels = executable('test_panels', 'test_panels.cpp', test_main,
  dependencies : [ui_view_dep, doctest_dep], cpp_args : conf_args)
test('panels', test_panels, timeout : 300)

# Feature suites (one exe each so features can be built/tested independently).
foreach t : ['nav', 'strings', 'hash', 'entropy', 'bitmap', 'diff', 'pcap', 'tail', 'history', 'xorscan', 'session', 'symbols']
  exe = executable('test_' + t, 'test_' + t + '.cpp', test_main,
    dependencies : [core_dep, doctest_dep], cpp_args : conf_args)
  test(t, exe, timeout : 300)
endforeach

# Process memory / devices / modules + in-memory PE symbols; Lua hx.open_process (script_dep).
test_procmem = executable('test_procmem', 'test_procmem.cpp', test_main,
  dependencies : [script_dep, doctest_dep], cpp_args : conf_args)
test('procmem', test_procmem, timeout : 300)

# Packet filter expressions (core/pcap_filter) and TCP stream reassembly (core/pcap_stream).
foreach t : ['pcapfilter', 'tcpstream']
  exe = executable('test_' + t, 'test_' + t + '.cpp', test_main,
    dependencies : [core_dep, doctest_dep], cpp_args : conf_args)
  test(t, exe, timeout : 300)
endforeach
test_cstruct = executable('test_cstruct', 'test_cstruct.cpp', test_main,
  dependencies : [script_dep, doctest_dep], cpp_args : conf_args)
test('cstruct', test_cstruct, timeout : 300)

# Structure -> C header export (+ round trip through cstruct), opts.flags / opts.bitfield, Inspector bit toggles.
test_cexport = executable('test_cexport', 'test_cexport.cpp', test_main,
  dependencies : [script_dep, doctest_dep], cpp_args : conf_args)
test('cexport', test_cexport, timeout : 300)

# Background parses (script/parse_job.h): worker thread, own Lua state, cancel, stale results, holes.
test_parsejob = executable('test_parsejob', 'test_parsejob.cpp', test_main,
  dependencies : [script_dep, doctest_dep], cpp_args : conf_args)
test('parsejob', test_parsejob, timeout : 300)

# Disassembly (Zydis) + PE / ELF address maps + hx.disasm / doc:disasm + the headless Disassembly panel.
test_disasm = executable('test_disasm', 'test_disasm.cpp', test_main,
  dependencies : [script_dep, ui_view_dep, doctest_dep], cpp_args : conf_args)
test('disasm', test_disasm, timeout : 300)
