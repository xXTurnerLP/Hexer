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
