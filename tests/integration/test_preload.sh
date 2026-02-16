#!/usr/bin/env bash
#
# Integration test: verify that libcompatmalloc.so works as an LD_PRELOAD
# library with various real-world programs.
#
# Usage:
#   ./tests/integration/test_preload.sh [path/to/libcompatmalloc.so]
#
# If no path is given, the script builds the release library first.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output (disabled if not a terminal)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN=''
    RED=''
    YELLOW=''
    BOLD=''
    RESET=''
fi

PASS=0
FAIL=0
SKIP=0

pass() {
    PASS=$((PASS + 1))
    printf "${GREEN}  PASS${RESET}  %s\n" "$1"
}

fail() {
    FAIL=$((FAIL + 1))
    printf "${RED}  FAIL${RESET}  %s\n" "$1"
}

skip() {
    SKIP=$((SKIP + 1))
    printf "${YELLOW}  SKIP${RESET}  %s\n" "$1"
}

# Determine library path
if [ $# -ge 1 ]; then
    LIB_PATH="$1"
else
    LIB_PATH="$PROJECT_ROOT/target/release/libcompatmalloc.so"
fi

# Build if the library does not exist
if [ ! -f "$LIB_PATH" ]; then
    printf "${BOLD}Building release library...${RESET}\n"
    (cd "$PROJECT_ROOT" && cargo build --release --quiet)
fi

if [ ! -f "$LIB_PATH" ]; then
    printf "${RED}ERROR: Library not found at %s${RESET}\n" "$LIB_PATH"
    exit 1
fi

LIB_PATH="$(realpath "$LIB_PATH")"
printf "${BOLD}Testing with: %s${RESET}\n\n" "$LIB_PATH"

# ---- Test runner ----

# run_test NAME COMMAND...
# Runs the command with LD_PRELOAD set. Passes if exit code is 0.
run_test() {
    local name="$1"
    shift
    if LD_PRELOAD="$LIB_PATH" "$@" > /dev/null 2>&1; then
        pass "$name"
    else
        fail "$name"
    fi
}

# run_test_output NAME EXPECTED COMMAND...
# Runs the command with LD_PRELOAD set. Passes if stdout contains EXPECTED.
run_test_output() {
    local name="$1"
    local expected="$2"
    shift 2
    local output
    if output=$(LD_PRELOAD="$LIB_PATH" "$@" 2>/dev/null); then
        if echo "$output" | grep -qF "$expected"; then
            pass "$name"
        else
            fail "$name (output did not contain '$expected')"
        fi
    else
        fail "$name (non-zero exit)"
    fi
}

# ---- Tests ----

printf "${BOLD}=== Basic programs ===${RESET}\n"

run_test_output "bash: echo" "hello" \
    bash -c 'echo hello'

run_test "bash: ls /tmp" \
    bash -c 'ls -la /tmp'

run_test "bash: echo + ls combined" \
    bash -c 'echo hello; ls -la /tmp'

run_test "ls: root directory" \
    ls -la /

run_test "cat: /etc/hostname" \
    cat /etc/hostname

run_test_output "echo: simple string" "compatmalloc-test" \
    echo "compatmalloc-test"

printf "\n${BOLD}=== Python ===${RESET}\n"

if command -v python3 &>/dev/null; then
    run_test_output "python3: json encode/decode" '"test": true' \
        python3 -c 'import json; print(json.dumps({"test": True}))'

    run_test_output "python3: list comprehension" "499999500000" \
        python3 -c 'print(sum(range(1000000)))'

    run_test "python3: import multiple modules" \
        python3 -c 'import os, sys, json, hashlib, collections; print("ok")'
else
    skip "python3: not installed"
fi

printf "\n${BOLD}=== Git ===${RESET}\n"

if command -v git &>/dev/null; then
    # Find a git repo to test with (use our own project)
    run_test "git: log in project repo" \
        git -C "$PROJECT_ROOT" log --oneline -5

    run_test "git: status in project repo" \
        git -C "$PROJECT_ROOT" status --short

    run_test "git: branch list" \
        git -C "$PROJECT_ROOT" branch --list
else
    skip "git: not installed"
fi

printf "\n${BOLD}=== Coreutils ===${RESET}\n"

run_test "date" \
    date

run_test "uname -a" \
    uname -a

run_test "id" \
    id

run_test "env (print environment)" \
    env

run_test "wc /etc/passwd" \
    wc -l /etc/passwd

run_test "sort (pipe)" \
    bash -c 'echo -e "c\na\nb" | sort'

run_test "head /etc/passwd" \
    head -5 /etc/passwd

run_test "find /tmp (shallow)" \
    find /tmp -maxdepth 1 -type f

printf "\n${BOLD}=== Disabled mode (COMPATMALLOC_DISABLE) ===${RESET}\n"

if COMPATMALLOC_DISABLE=1 LD_PRELOAD="$LIB_PATH" bash -c 'echo disabled-ok' 2>/dev/null | grep -qF "disabled-ok"; then
    pass "disabled mode: bash"
else
    fail "disabled mode: bash"
fi

if COMPATMALLOC_DISABLE=1 LD_PRELOAD="$LIB_PATH" ls / > /dev/null 2>&1; then
    pass "disabled mode: ls"
else
    fail "disabled mode: ls"
fi

printf "\n${BOLD}=== Stress: rapid alloc/free via Python ===${RESET}\n"

if command -v python3 &>/dev/null; then
    run_test "python3: many small allocations" \
        python3 -c '
data = []
for i in range(100000):
    data.append("x" * (i % 256))
    if i % 1000 == 0:
        data = data[-100:]
print("ok")
'

    run_test "python3: dict operations (hash table stress)" \
        python3 -c '
d = {}
for i in range(50000):
    d[str(i)] = [i] * 10
for i in range(0, 50000, 2):
    del d[str(i)]
print(len(d))
'
else
    skip "python3: stress tests (not installed)"
fi

# ---- Summary ----

printf "\n${BOLD}=== Summary ===${RESET}\n"
printf "  Passed:  %d\n" "$PASS"
printf "  Failed:  %d\n" "$FAIL"
printf "  Skipped: %d\n" "$SKIP"
printf "  Total:   %d\n" "$((PASS + FAIL + SKIP))"

if [ "$FAIL" -gt 0 ]; then
    printf "\n${RED}${BOLD}FAILED${RESET}\n"
    exit 1
else
    printf "\n${GREEN}${BOLD}ALL TESTS PASSED${RESET}\n"
    exit 0
fi
