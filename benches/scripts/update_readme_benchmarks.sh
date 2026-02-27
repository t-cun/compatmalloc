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

compute_composite() {
  local alloc_file="$1" baseline_file="$2"
  local sizes="16 32 64 128 256 512 1024 4096 16384 65536 262144"
  local weights="0.20 0.15 0.15 0.12 0.10 0.08 0.05 0.05 0.04 0.03 0.03"
  local composite=0
  local i=1
  for size in $sizes; do
    local w=$(echo "$weights" | cut -d' ' -f$i)
    local a_lat=$(parse_field "$alloc_file" "latency_${size}")
    local g_lat=$(parse_field "$baseline_file" "latency_${size}")
    if [ -n "$a_lat" ] && [ -n "$g_lat" ] && [ "$g_lat" != "0" ] && [ "$g_lat" != "0.0" ]; then
      local ratio=$(echo "$a_lat / $g_lat" | bc -l)
      composite=$(echo "$composite + $w * $ratio" | bc -l)
    else
      composite=$(echo "$composite + $w" | bc -l)
    fi
    i=$((i + 1))
  done
  printf "%.1f" "$(echo "($composite - 1) * 100" | bc -l)"
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

    t1_r=$(fmt_ratio "$(echo "$t1 / $g_t1" | bc -l)")
    t4_r=$(fmt_ratio "$(echo "$t4 / $g_t4" | bc -l)")

    composite=$(compute_composite "$best" "$glibc_best")
    if [ "$(echo "$composite > 0" | bc)" = "1" ]; then
      comp_display="+${composite}%"
    elif [ "$composite" = "0.0" ] || [ "$composite" = "0" ]; then
      comp_display="**0%**"
    else
      comp_display="**${composite}%**"
    fi

    if [ "$name" = "compatmalloc" ]; then
        dn="**compatmalloc**"
    else
        dn="$name"
    fi

    x86_rows="${x86_rows}| ${dn} | ${comp_display} | ${lat} ns | ${t1} Mops/s | ${t1_r}x | ${t4} Mops/s | ${t4_r}x |\n"
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
state == "normal" && /^\| Allocator \| Weighted Overhead/ {
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
