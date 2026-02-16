#!/bin/bash
# Run benchmarks comparing compatmalloc against system allocator and jemalloc.
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

# System allocator (baseline)
echo "--- System allocator (glibc) ---"
"$BENCH_BINARY" $BENCH_ARGS 2>&1 || true
echo ""

# compatmalloc hardened
echo "--- compatmalloc (hardened) ---"
LD_PRELOAD="$LIB" "$BENCH_BINARY" $BENCH_ARGS 2>&1 || true
echo ""

# compatmalloc passthrough
echo "--- compatmalloc (passthrough / disabled) ---"
COMPATMALLOC_DISABLE=1 LD_PRELOAD="$LIB" "$BENCH_BINARY" $BENCH_ARGS 2>&1 || true
echo ""

# jemalloc (if available)
JEMALLOC_LIB=$(ldconfig -p 2>/dev/null | grep libjemalloc.so | head -1 | awk '{print $NF}')
if [ -n "$JEMALLOC_LIB" ]; then
    echo "--- jemalloc ---"
    LD_PRELOAD="$JEMALLOC_LIB" "$BENCH_BINARY" $BENCH_ARGS 2>&1 || true
    echo ""
fi

echo "=== Done ==="
