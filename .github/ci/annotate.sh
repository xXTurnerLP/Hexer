#!/usr/bin/env bash
# CI helpers that turn log files into workflow annotations (readable without auth via the
# check-run annotations API, unlike the raw logs).
#   annotate.sh tail LEVEL TITLE FILE [N]  one annotation with the last N (40) lines of FILE
#   annotate.sh grep LEVEL TITLE FILE ERE   one annotation with the lines of FILE matching ERE
#   annotate.sh warnings LOG                notice with warning counts + list of project warnings
# Run with problem matchers removed, or the matchers re-match the echoed lines.

join() {  # stdin lines -> one workflow-command message (%, CR, LF escaped)
    sed 's/\r$//' | sed 's/%/%25/g' | awk 'BEGIN { ORS = "%0A" } { print }'
}

mode=$1
shift
case "$mode" in
tail)
    level=$1 title=$2 file=$3 n=${4:-40}
    if [ ! -f "$file" ]; then echo "::$level title=$title::$file is missing"; exit 0; fi
    echo "::$level title=$title::$(tail -n "$n" "$file" | join)"
    ;;
grep)
    level=$1 title=$2 file=$3 re=$4
    if [ ! -f "$file" ]; then echo "::$level title=$title::$file is missing"; exit 0; fi
    echo "::$level title=$title::$(grep -E -- "$re" "$file" | head -n 100 | join)"
    ;;
warnings)
    log=$1
    [ -f "$log" ] || exit 0
    all=$(grep -E ': warning:|warning C[0-9]{4}' "$log" | sed 's/\r$//' | sort -u)
    proj=$(printf '%s\n' "$all" | grep -v -i 'subprojects')
    n_all=$(printf '%s\n' "$all" | grep -c .)
    n_proj=$(printf '%s\n' "$proj" | grep -c .)
    echo "::notice title=Warnings::$n_proj unique project warnings, $n_all unique in total (incl. subprojects)"
    if [ "$n_proj" -gt 0 ]; then
        echo "::warning title=Project warnings::$(printf '%s\n' "$proj" | head -n 100 | join)"
        # Warnings reported inside system headers only name the header; the preceding
        # "In function / inlined from / required from" lines say which project code caused them.
        ctx=$(grep -E -B 25 ': warning:' "$log" | sed 's/\r$//' \
            | grep -E 'In (member )?function|inlined from|required from|instantiated from|FAILED:|: warning:' \
            | grep -v -i 'subprojects' | head -n 60)
        if [ -n "$ctx" ]; then
            echo "::warning title=Warning context::$(printf '%s\n' "$ctx" | join)"
        fi
    fi
    ;;
*)
    echo "usage: annotate.sh tail|grep|warnings ..." >&2
    exit 2
    ;;
esac
exit 0
