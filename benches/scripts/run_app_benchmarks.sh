#!/bin/bash
# Benchmark real-world applications with and without compatmalloc (LD_PRELOAD).
# Measures wall-time overhead for: Python JSON, Redis, nginx, SQLite, Git.
#
# Usage: ./run_app_benchmarks.sh [path/to/libcompatmalloc.so]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR/../.."
LIB="${1:-$PROJECT_ROOT/target/release/libcompatmalloc.so}"

if [ ! -f "$LIB" ]; then
    echo "ERROR: Library not found at $LIB"
    echo "  Build first: cargo build --release"
    exit 1
fi

LIB="$(realpath "$LIB")"
echo "=== Real-World Application Benchmarks ==="
echo "Library: $LIB"
echo ""

RESULTS_FILE="$PROJECT_ROOT/bench-apps.txt"
> "$RESULTS_FILE"

# Track whether any LD_PRELOAD test crashed (= compatmalloc bug)
PRELOAD_FAILURES=0

# ---- Helpers ----------------------------------------------------------------

# time_cmd: measure wall time of a command in seconds (nanosecond precision).
# Usage: elapsed=$(time_cmd cmd arg1 arg2 ...)
# Returns time on stdout. Command's stdout/stderr go to /dev/null.
# Returns 0 even if the command fails.
time_cmd() {
    local start end elapsed_ns
    start=$(date +%s%N)
    "$@" > /dev/null 2>&1 || true
    end=$(date +%s%N)
    elapsed_ns=$((end - start))
    echo "scale=4; $elapsed_ns / 1000000000" | bc
}

record() {
    local name="$1" glibc_time="$2" compat_time="$3"
    local overhead
    overhead=$(echo "scale=2; ($compat_time / $glibc_time - 1) * 100" | bc 2>/dev/null || echo "N/A")
    echo "APP|$name|glibc=${glibc_time}s|compat=${compat_time}s|overhead=${overhead}%" | tee -a "$RESULTS_FILE"
}

cleanup_list=()
register_cleanup() {
    cleanup_list+=("$1")
}
do_cleanup() {
    for d in "${cleanup_list[@]}"; do
        rm -rf "$d" 2>/dev/null || true
    done
}
trap do_cleanup EXIT

# ---- 1. Python JSON ----------------------------------------------------------

echo "--- [1/5] Python JSON (json.dumps/loads, 5 iterations) ---"

PYTHON_SCRIPT='
import json, string, random
random.seed(42)
data = {f"key_{i}": {"nested": list(range(100)), "text": "".join(random.choices(string.ascii_letters, k=200))} for i in range(500)}
for _ in range(5):
    s = json.dumps(data)
    _ = json.loads(s)
'

glibc_time=$(time_cmd python3 -c "$PYTHON_SCRIPT")
echo "  glibc:        ${glibc_time}s"

compat_time=$(time_cmd env LD_PRELOAD="$LIB" python3 -c "$PYTHON_SCRIPT")
echo "  compatmalloc: ${compat_time}s"

record "python-json" "$glibc_time" "$compat_time"
echo ""

# ---- 2. Redis ----------------------------------------------------------------

echo "--- [2/5] Redis (set/get 100k keys) ---"

if command -v redis-server &>/dev/null && command -v redis-benchmark &>/dev/null; then
    REDIS_PORT=16399
    REDIS_DIR=$(mktemp -d /tmp/bench-redis.XXXXXX)
    register_cleanup "$REDIS_DIR"

    # run_redis_bench label [env-prefix-args...]
    # Prints elapsed time on stdout. Diagnostic messages go to stderr.
    run_redis_bench() {
        local label="$1"
        shift
        local server_cmd=("$@")

        # Start redis-server (may crash with LD_PRELOAD)
        if ! "${server_cmd[@]}" redis-server \
            --port "$REDIS_PORT" \
            --daemonize yes \
            --dir "$REDIS_DIR" \
            --pidfile "$REDIS_DIR/redis.pid" \
            --logfile "$REDIS_DIR/redis.log" \
            --save "" \
            --appendonly no 2>/dev/null; then
            echo "FAIL"
            return 0
        fi

        # Wait for server to be ready
        local tries=0
        while ! redis-cli -p "$REDIS_PORT" ping &>/dev/null; do
            sleep 0.1
            tries=$((tries + 1))
            if [ "$tries" -gt 50 ]; then
                echo "FAIL"
                return 0
            fi
        done

        # Run benchmark
        local elapsed
        elapsed=$(time_cmd redis-benchmark -p "$REDIS_PORT" -t set,get -n 100000 -q)

        # Stop server
        redis-cli -p "$REDIS_PORT" shutdown nosave &>/dev/null || true
        sleep 0.2

        echo "$elapsed"
    }

    glibc_time=$(run_redis_bench "glibc")
    if [ "$glibc_time" = "FAIL" ]; then
        echo "  glibc:        FAILED (redis-server could not start)"
        echo "  SKIPPED: redis benchmark"
    else
        echo "  glibc:        ${glibc_time}s"

        compat_time=$(run_redis_bench "compatmalloc" env LD_PRELOAD="$LIB")
        if [ "$compat_time" = "FAIL" ]; then
            echo "  compatmalloc: FAILED (redis-server crashed with LD_PRELOAD)"
            echo "  ERROR: redis crashed under LD_PRELOAD — this is a compatmalloc bug"
            PRELOAD_FAILURES=$((PRELOAD_FAILURES + 1))
        else
            echo "  compatmalloc: ${compat_time}s"
            record "redis" "$glibc_time" "$compat_time"
        fi
    fi
else
    echo "  SKIPPED: redis-server or redis-benchmark not found"
fi
echo ""

# ---- 3. nginx ----------------------------------------------------------------

echo "--- [3/5] nginx + wrk (static file, 5s) ---"

if command -v nginx &>/dev/null && command -v wrk &>/dev/null; then
    NGINX_PORT=18080
    NGINX_DIR=$(mktemp -d /tmp/bench-nginx.XXXXXX)
    register_cleanup "$NGINX_DIR"

    mkdir -p "$NGINX_DIR/html" "$NGINX_DIR/logs"

    # Create a 4KB random file to serve
    dd if=/dev/urandom of="$NGINX_DIR/html/test.bin" bs=4096 count=1 2>/dev/null

    # Minimal nginx config
    cat > "$NGINX_DIR/nginx.conf" <<NGINX_CONF
worker_processes 2;
pid $NGINX_DIR/nginx.pid;
error_log $NGINX_DIR/logs/error.log;
daemon on;

events {
    worker_connections 128;
}

http {
    access_log off;
    server {
        listen $NGINX_PORT;
        location / {
            root $NGINX_DIR/html;
        }
    }
}
NGINX_CONF

    # run_nginx_bench label [env-prefix-args...]
    run_nginx_bench() {
        local label="$1"
        shift
        local prefix=("$@")

        # Start nginx
        if ! "${prefix[@]}" nginx -c "$NGINX_DIR/nginx.conf" -p "$NGINX_DIR" 2>/dev/null; then
            echo "FAIL"
            return 0
        fi

        # Wait for it to come up
        local tries=0
        while ! curl -s -o /dev/null "http://127.0.0.1:$NGINX_PORT/test.bin" 2>/dev/null; do
            sleep 0.1
            tries=$((tries + 1))
            if [ "$tries" -gt 50 ]; then
                echo "FAIL"
                return 0
            fi
        done

        # Run wrk
        local elapsed
        elapsed=$(time_cmd wrk -t2 -c10 -d5s "http://127.0.0.1:$NGINX_PORT/test.bin")

        # Stop nginx
        nginx -c "$NGINX_DIR/nginx.conf" -p "$NGINX_DIR" -s stop 2>/dev/null || true
        sleep 0.3

        echo "$elapsed"
    }

    glibc_time=$(run_nginx_bench "glibc")
    if [ "$glibc_time" = "FAIL" ]; then
        echo "  glibc:        FAILED (nginx could not start)"
        echo "  SKIPPED: nginx benchmark"
    else
        echo "  glibc:        ${glibc_time}s"

        compat_time=$(run_nginx_bench "compatmalloc" env LD_PRELOAD="$LIB")
        if [ "$compat_time" = "FAIL" ]; then
            echo "  compatmalloc: FAILED (nginx crashed with LD_PRELOAD)"
            echo "  ERROR: nginx crashed under LD_PRELOAD — this is a compatmalloc bug"
            PRELOAD_FAILURES=$((PRELOAD_FAILURES + 1))
        else
            echo "  compatmalloc: ${compat_time}s"
            record "nginx" "$glibc_time" "$compat_time"
        fi
    fi
else
    if ! command -v nginx &>/dev/null; then
        echo "  SKIPPED: nginx not found"
    else
        echo "  SKIPPED: wrk not found (install wrk for HTTP benchmarking)"
    fi
fi
echo ""

# ---- 4. SQLite ---------------------------------------------------------------

echo "--- [4/5] SQLite (50k inserts + queries) ---"

if command -v sqlite3 &>/dev/null; then
    SQLITE_DIR=$(mktemp -d /tmp/bench-sqlite.XXXXXX)
    register_cleanup "$SQLITE_DIR"

    # Generate SQL to a file to avoid slow shell expansion
    SQLITE_SQL_FILE="$SQLITE_DIR/bench.sql"
    {
        echo "CREATE TABLE bench (id INTEGER PRIMARY KEY, name TEXT, value REAL);"
        echo "BEGIN;"
        for i in $(seq 1 50000); do
            echo "INSERT INTO bench VALUES ($i, 'name_$i', $i.$(($i % 100)));"
        done
        echo "COMMIT;"
        echo "SELECT COUNT(*) FROM bench;"
        echo "SELECT AVG(value) FROM bench WHERE id BETWEEN 10000 AND 20000;"
        echo "SELECT name FROM bench WHERE value > 49000 LIMIT 10;"
        echo "DROP TABLE bench;"
    } > "$SQLITE_SQL_FILE"

    glibc_time=$(time_cmd sqlite3 "$SQLITE_DIR/glibc.db" ".read $SQLITE_SQL_FILE")
    echo "  glibc:        ${glibc_time}s"

    compat_time=$(time_cmd env LD_PRELOAD="$LIB" sqlite3 "$SQLITE_DIR/compat.db" ".read $SQLITE_SQL_FILE")
    echo "  compatmalloc: ${compat_time}s"

    record "sqlite" "$glibc_time" "$compat_time"
else
    echo "  SKIPPED: sqlite3 not found"
fi
echo ""

# ---- 5. Git ------------------------------------------------------------------

echo "--- [5/5] Git (shallow clone + log) ---"

GIT_DIR=$(mktemp -d /tmp/bench-git.XXXXXX)
register_cleanup "$GIT_DIR"

REPO_URL="https://github.com/t-cun/compatmalloc.git"

run_git_bench() {
    local label="$1" dest="$2"
    shift 2
    local prefix=("$@")

    local start end elapsed_ns
    start=$(date +%s%N)
    if ! "${prefix[@]}" git clone --depth=50 "$REPO_URL" "$dest" > /dev/null 2>&1; then
        echo "FAIL"
        return 0
    fi
    (cd "$dest" && "${prefix[@]}" git log --all --oneline > /dev/null 2>&1) || true
    end=$(date +%s%N)
    elapsed_ns=$((end - start))
    echo "scale=4; $elapsed_ns / 1000000000" | bc
}

glibc_time=$(run_git_bench "glibc" "$GIT_DIR/glibc-clone")
if [ "$glibc_time" = "FAIL" ]; then
    echo "  glibc:        FAILED (git clone failed)"
    echo "  SKIPPED: git benchmark"
else
    echo "  glibc:        ${glibc_time}s"

    compat_time=$(run_git_bench "compatmalloc" "$GIT_DIR/compat-clone" env LD_PRELOAD="$LIB")
    if [ "$compat_time" = "FAIL" ]; then
        echo "  compatmalloc: FAILED (git clone crashed with LD_PRELOAD)"
        echo "  ERROR: git crashed under LD_PRELOAD — this is a compatmalloc bug"
        PRELOAD_FAILURES=$((PRELOAD_FAILURES + 1))
    else
        echo "  compatmalloc: ${compat_time}s"
        record "git" "$glibc_time" "$compat_time"
    fi
fi
echo ""

# ---- Summary -----------------------------------------------------------------

echo "============================================================"
echo "=== Summary ==="
echo "============================================================"
printf "%-15s %10s %10s %10s\n" "Application" "glibc(s)" "compat(s)" "overhead"
printf "%-15s %10s %10s %10s\n" "---" "---" "---" "---"

while IFS='|' read -r _ name glibc_val compat_val overhead_val; do
    glibc_s="${glibc_val#glibc=}"
    compat_s="${compat_val#compat=}"
    oh="${overhead_val#overhead=}"
    printf "%-15s %10s %10s %10s\n" "$name" "$glibc_s" "$compat_s" "$oh"
done < "$RESULTS_FILE"

echo ""
echo "Results written to: $RESULTS_FILE"

if [ "$PRELOAD_FAILURES" -gt 0 ]; then
    echo "ERROR: $PRELOAD_FAILURES application(s) crashed under LD_PRELOAD"
    echo "This indicates a bug in compatmalloc. Failing the benchmark."
    exit 1
fi

echo "=== Done ==="
