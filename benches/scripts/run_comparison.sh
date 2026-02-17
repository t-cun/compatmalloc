#!/bin/bash
# Run benchmarks comparing compatmalloc against system allocator, jemalloc,
# mimalloc, and scudo (when available).
#
# Usage: ./run_comparison.sh [bench_binary] [args...]
#
# Example:
#   ./run_comparison.sh target/release/larson 4 5
#   ./run_comparison.sh target/release/micro
#   ./run_comparison.sh target/release/cfrac 1000000

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR/../.."
LIB="$PROJECT_ROOT/target/release/libcompatmalloc.so"

BENCH_BINARY="${1:-$PROJECT_ROOT/target/release/micro}"
shift || true
BENCH_ARGS="$*"

# Collect summary lines for final comparison table
declare -a SUMMARY_LINES=()

# Build everything
echo "=== Building ==="
cargo build --release --manifest-path "$PROJECT_ROOT/Cargo.toml"

# Build benchmark binaries
for src in "$PROJECT_ROOT/benches/src"/*.rs; do
    name=$(basename "$src" .rs)
    rustc -O "$src" -o "$PROJECT_ROOT/target/release/$name" 2>/dev/null || true
done

echo ""
echo "=== Benchmark: $(basename "$BENCH_BINARY") $BENCH_ARGS ==="
echo ""

run_bench() {
    local name="$1"
    local preload="${2:-}"
    local env_extra="${3:-}"

    echo "--- $name ---"
    local output
    if [ -n "$preload" ]; then
        output=$(export ALLOCATOR_NAME="$name"; [ -n "$env_extra" ] && export $env_extra; LD_PRELOAD="$preload" "$BENCH_BINARY" $BENCH_ARGS 2>&1) || true
    else
        output=$(export ALLOCATOR_NAME="$name"; [ -n "$env_extra" ] && export $env_extra; "$BENCH_BINARY" $BENCH_ARGS 2>&1) || true
    fi
    echo "$output"
    echo ""

    # Extract SUMMARY line if present
    local summary_line
    summary_line=$(echo "$output" | grep "^SUMMARY|" || true)
    if [ -n "$summary_line" ]; then
        SUMMARY_LINES+=("$summary_line")
    fi
}

# System allocator (baseline)
run_bench "glibc"

# compatmalloc hardened
run_bench "compatmalloc" "$LIB"

# compatmalloc passthrough
run_bench "passthrough" "$LIB" "COMPATMALLOC_DISABLE=1"

# jemalloc (if available)
JEMALLOC_LIB=$(ldconfig -p 2>/dev/null | grep libjemalloc.so | head -1 | awk '{print $NF}' || true)
if [ -n "$JEMALLOC_LIB" ]; then
    run_bench "jemalloc" "$JEMALLOC_LIB"
else
    echo "--- jemalloc: not found (install libjemalloc-dev) ---"
    echo ""
fi

# mimalloc (if available)
MIMALLOC_LIB=$(ldconfig -p 2>/dev/null | grep libmimalloc.so | head -1 | awk '{print $NF}' || true)
if [ -z "$MIMALLOC_LIB" ]; then
    # Try common paths
    for p in /usr/lib/x86_64-linux-gnu/libmimalloc.so /usr/local/lib/libmimalloc.so; do
        if [ -f "$p" ]; then
            MIMALLOC_LIB="$p"
            break
        fi
    done
fi
if [ -n "$MIMALLOC_LIB" ]; then
    run_bench "mimalloc" "$MIMALLOC_LIB"
else
    echo "--- mimalloc: not found (install libmimalloc-dev) ---"
    echo ""
fi

# scudo (if available) - from LLVM compiler-rt
SCUDO_LIB=""
for p in /usr/lib/x86_64-linux-gnu/libscudo*.so /usr/lib/llvm-*/lib/clang/*/lib/linux/libclang_rt.scudo*-x86_64.so; do
    if [ -f "$p" ]; then
        SCUDO_LIB="$p"
        break
    fi
done
if [ -n "$SCUDO_LIB" ]; then
    run_bench "scudo" "$SCUDO_LIB"
else
    echo "--- scudo: not found (install from LLVM compiler-rt) ---"
    echo ""
fi

# Print comparison summary table
if [ ${#SUMMARY_LINES[@]} -ge 2 ]; then
    echo "============================================================"
    echo "=== Comparison Summary ==="
    echo "============================================================"
    printf "%-20s %12s %14s %14s\n" "Allocator" "Latency(64B)" "Throughput(1T)" "Throughput(4T)"
    printf "%-20s %12s %14s %14s\n" "---" "ns/op" "Mops/sec" "Mops/sec"

    # Parse baseline (glibc) values
    baseline_latency=""
    baseline_t1=""
    baseline_t4=""
    for line in "${SUMMARY_LINES[@]}"; do
        name=$(echo "$line" | cut -d'|' -f2)
        if [ "$name" = "glibc" ]; then
            baseline_latency=$(echo "$line" | sed 's/.*latency_64=\([0-9.]*\).*/\1/')
            baseline_t1=$(echo "$line" | sed 's/.*throughput_1t=\([0-9.]*\).*/\1/')
            baseline_t4=$(echo "$line" | sed 's/.*throughput_4t=\([0-9.]*\).*/\1/')
        fi
    done

    for line in "${SUMMARY_LINES[@]}"; do
        name=$(echo "$line" | cut -d'|' -f2)
        latency=$(echo "$line" | sed 's/.*latency_64=\([0-9.]*\).*/\1/')
        t1=$(echo "$line" | sed 's/.*throughput_1t=\([0-9.]*\).*/\1/')
        t4=$(echo "$line" | sed 's/.*throughput_4t=\([0-9.]*\).*/\1/')

        # Calculate relative to baseline
        if [ -n "$baseline_latency" ] && [ "$baseline_latency" != "0" ] && [ "$baseline_latency" != "0.0" ]; then
            rel_lat=$(echo "scale=1; $latency / $baseline_latency" | bc 2>/dev/null || echo "?")
            printf "%-20s %8s (%sx) %10s %10s\n" "$name" "$latency" "$rel_lat" "$t1" "$t4"
        else
            printf "%-20s %12s %14s %14s\n" "$name" "$latency" "$t1" "$t4"
        fi
    done
    echo ""
fi

echo "=== Done ==="
