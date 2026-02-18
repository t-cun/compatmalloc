#!/bin/bash
# Compile and run CVE PoCs with glibc and compatmalloc.
# Usage: ./tests/cve/run_demos.sh [path/to/libcompatmalloc.so]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${1:-target/release/libcompatmalloc.so}"

echo "=== CVE Demo Runner ==="
echo "Library: $LIB"
echo ""

for src in "$SCRIPT_DIR"/*.c; do
    name=$(basename "$src" .c)
    bin="/tmp/cve_demo_${name}"

    echo "============================================"
    echo "=== $name ==="
    echo "============================================"

    gcc -o "$bin" "$src" -Wall -Wextra
    echo "Compiled: $src -> $bin"
    echo ""

    echo "--- glibc ---"
    "$bin" 2>&1 || echo "(exited with code $?)"
    echo ""

    echo "--- compatmalloc ---"
    LD_PRELOAD="$LIB" "$bin" 2>&1 || echo "(exited with code $?)"
    echo ""
done

echo "=== All demos complete ==="
