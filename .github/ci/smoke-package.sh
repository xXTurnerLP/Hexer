#!/usr/bin/env bash
# Smoke-test a packaged Hexer (run from the repository root):
#   smoke-package.sh NAME CMD [ARGS...]
#   e.g. smoke-package.sh appimage xvfb-run -a ./hexer-x86_64.AppImage --appimage-extract-and-run
# Runs CMD once with a screenshot (smoke/NAME.png) and checks from Lua that the package's bundled
# scripts were loaded. The source tree's scripts/ is moved away meanwhile: dev builds fall back to
# it (HEXER_SOURCE_SCRIPTS_DIR), which would hide a package without its scripts.
name=$1
shift
base=$PWD
if command -v cygpath > /dev/null; then base=$(cygpath -m "$PWD"); fi  # Windows path for hexer.exe
mkdir -p smoke
check="smoke/$name-scripts.txt"
rm -f "$check"
lua="local ok = pcall(hx.run, 'Selection: print as C array'); local f = assert(io.open('$base/$check', 'w')); f:write(ok and 'found' or 'missing'); f:close()"

mv scripts scripts.off
timeout 300 "$@" --no-session --config-dir "$base/smoke/cfg-$name" --screenshot "$base/smoke/$name.ppm" \
    --frames 30 --exec "$lua" "$base/README.md" > "smoke/$name.log" 2>&1
rc=$?
mv scripts.off scripts

found=$(cat "$check" 2> /dev/null)
if [ -s "smoke/$name.log" ]; then bash .github/ci/annotate.sh tail notice "smoke $name output" "smoke/$name.log" 30; fi
if [ -f "smoke/$name.ppm" ]; then python tools/ppm2png.py "smoke/$name.ppm" "smoke/$name.png" && rm -f "smoke/$name.ppm"; fi
echo "$name: exit=$rc, bundled scripts: ${found:-no result}"
if [ $rc -ne 0 ] || [ "$found" != "found" ] || [ ! -f "smoke/$name.png" ]; then
    echo "::error title=Package smoke test failed ($name)::exit=$rc, bundled scripts: ${found:-no result}"
    exit 1
fi
exit 0
