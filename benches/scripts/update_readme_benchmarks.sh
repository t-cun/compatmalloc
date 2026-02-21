#!/bin/bash
# update_readme_benchmarks.sh
# Updates the Performance section of README.md from CI benchmark artifacts.
#
# Usage: ./benches/scripts/update_readme_benchmarks.sh <bench-dir> [readme-path]
#
# Expected files in <bench-dir>:
#   bench-{allocator}-best.txt  - BEST|name|latency_64=X|throughput_1t=X|throughput_4t=X|rss_kb=X
#   bench-apps.txt              - APP|name|glibc=Xs|compat=Xs|overhead=X%

set -euo pipefail
export LC_ALL=C

BENCH_DIR="${1:?Usage: $0 <bench-dir> [readme-path]}"
README="${2:-README.md}"

[ -f "$README" ] || { echo "ERROR: $README not found"; exit 1; }
command -v bc >/dev/null 2>&1 || { echo "ERROR: bc is required"; exit 1; }

# --- Helpers ---

parse_field() {
    local file="$1" field="$2"
    sed "s/.*${field}=\([0-9.]*\).*/\1/" "$file"
}

fmt_ratio() {
    printf "%.2f" "$1"
}

# --- Build x86_64 comparison table rows ---

glibc_best="$BENCH_DIR/bench-glibc-best.txt"
if [ ! -f "$glibc_best" ]; then
    echo "WARNING: $glibc_best not found, skipping README update"
    exit 0
fi

g_lat=$(parse_field "$glibc_best" "latency_64")
g_t1=$(parse_field "$glibc_best" "throughput_1t")
g_t4=$(parse_field "$glibc_best" "throughput_4t")

x86_rows=""
for name in compatmalloc glibc jemalloc mimalloc scudo; do
    best="$BENCH_DIR/bench-${name}-best.txt"
    [ -f "$best" ] || continue

    lat=$(parse_field "$best" "latency_64")
    t1=$(parse_field "$best" "throughput_1t")
    t4=$(parse_field "$best" "throughput_4t")

    lat_r=$(fmt_ratio "$(echo "$lat / $g_lat" | bc -l)")
    t1_r=$(fmt_ratio "$(echo "$t1 / $g_t1" | bc -l)")
    t4_r=$(fmt_ratio "$(echo "$t4 / $g_t4" | bc -l)")

    if [ "$name" = "compatmalloc" ]; then
        dn="**compatmalloc**"
    else
        dn="$name"
    fi

    x86_rows="${x86_rows}| ${dn} | ${lat} ns | ${lat_r}x | ${t1} Mops/s | ${t1_r}x | ${t4} Mops/s | ${t4_r}x |\n"
done

# --- Build app overhead table rows ---

app_rows=""
if [ -f "$BENCH_DIR/bench-apps.txt" ]; then
    while IFS='|' read -r _ app_name glibc_val compat_val overhead_val; do
        g_s="${glibc_val#glibc=}"
        c_s="${compat_val#compat=}"
        oh="${overhead_val#overhead=}"
        oh_num="${oh%%%}"  # strip % sign

        # Format times: ensure leading zero, 3 decimal places
        g_fmt=$(printf "%.3fs" "${g_s%s}")
        c_fmt=$(printf "%.3fs" "${c_s%s}")

        # Format overhead: bold if <= 0, +prefix if > 0
        if [[ "$oh_num" =~ ^-?[0-9.]+$ ]]; then
            oh_int=$(printf "%.0f" "$oh_num")
            if [ "$oh_int" -gt 0 ]; then
                oh_display="+${oh_int}%"
            elif [ "$oh_int" -eq 0 ]; then
                oh_display="**0%**"
            else
                oh_display="**${oh_int}%**"
            fi
        else
            oh_display="N/A"
        fi

        app_rows="${app_rows}| ${app_name} | ${g_fmt} | ${c_fmt} | ${oh_display} |\n"
    done < "$BENCH_DIR/bench-apps.txt"
fi

# --- Replace table data rows in README ---

tmp=$(mktemp)

awk -v x86_data="$x86_rows" -v app_data="$app_rows" '
BEGIN { state = "normal" }

# x86_64 table: match header row
state == "normal" && /^\| Allocator \| Latency \(64B\) \| vs glibc/ {
    print
    state = "x86_sep"
    next
}

# x86_64 table: print separator, inject new rows, skip old
state == "x86_sep" {
    print
    printf "%s", x86_data
    state = "x86_skip"
    next
}

state == "x86_skip" && /^\|/ { next }

state == "x86_skip" { state = "normal" }

# App overhead table: match header row
state == "normal" && /^\| Application \| glibc/ {
    print
    if (app_data != "") {
        state = "app_sep"
    }
    next
}

# App overhead table: print separator, inject new rows, skip old
state == "app_sep" {
    print
    printf "%s", app_data
    state = "app_skip"
    next
}

state == "app_skip" && /^\|/ { next }

state == "app_skip" { state = "normal" }

# Default: print line as-is
{ print }
' "$README" > "$tmp"

mv "$tmp" "$README"
echo "Updated $README with latest benchmark data"
