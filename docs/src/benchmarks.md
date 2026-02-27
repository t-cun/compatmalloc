# Benchmarks

compatmalloc prioritizes security over raw performance. This page describes the performance characteristics, overhead sources, and how to run benchmarks to measure the impact on your workloads.

{{#include generated/benchmark-results.md}}

## Performance characteristics

### Expected overhead

Compared to glibc's ptmalloc2, compatmalloc adds overhead from several sources:

| Source | Per-malloc cost | Per-free cost |
|--------|----------------|---------------|
| Metadata table insert | Hash + linear probe + mutex | -- |
| Metadata table lookup | -- | Hash + linear probe + mutex |
| Canary write | `memset` of gap bytes | Canary check (byte comparison) |
| Poison fill | -- | `memset` of allocation |
| Quarantine push/evict | -- | Mutex + ring buffer enqueue |
| Zero-on-free | -- | `memset` of allocation (on eviction) |
| Guard page setup | `mprotect` (large alloc only) | -- |

For small allocations (16-256 bytes), the dominant costs are the metadata table operations and the canary/poison fills. For large allocations, the `mmap`/`munmap` syscalls dominate regardless of hardening.

### Size class efficiency

The slab allocator uses 4-per-doubling size classes, which means internal fragmentation is at most 25% for any allocation. Size classes range from 16 bytes to 16,384 bytes (36 classes total).

### Arena contention

With the default arena count (one per CPU), contention is low for most workloads. Programs with many threads performing high-frequency allocations may benefit from explicitly setting `COMPATMALLOC_ARENA_COUNT` to a higher value.

## Running benchmarks

### Microbenchmark suite

The benchmark suite is a standalone binary that measures allocator performance via `LD_PRELOAD`:

```bash
# Build the library and benchmark
cargo build --release
rustc -O benches/src/micro.rs -o target/release/micro

# Run with glibc (baseline)
ALLOCATOR_NAME=glibc ./target/release/micro

# Run with compatmalloc
ALLOCATOR_NAME=compatmalloc \
  LD_PRELOAD=./target/release/libcompatmalloc.so \
  ./target/release/micro
```

### Full comparison script

To compare against multiple allocators (glibc, jemalloc, mimalloc, scudo):

```bash
./benches/scripts/run_comparison.sh
```

### Disabling hardening for comparison

To measure the overhead of hardening features, build with no features:

```bash
cargo build --release --no-default-features
ALLOCATOR_NAME=minimal \
  LD_PRELOAD=./target/release/libcompatmalloc.so \
  ./target/release/micro
```

### LD_PRELOAD benchmarks with external programs

For realistic benchmarks, test with real applications:

```bash
# Time a build with and without compatmalloc
time cargo build --release

time LD_PRELOAD=./target/release/libcompatmalloc.so \
  cargo build --release

# Python workload
time python3 -c "
import json
data = [{'key': str(i), 'value': list(range(100))} for i in range(10000)]
result = json.dumps(data)
parsed = json.loads(result)
"

time LD_PRELOAD=./target/release/libcompatmalloc.so python3 -c "
import json
data = [{'key': str(i), 'value': list(range(100))} for i in range(10000)]
result = json.dumps(data)
parsed = json.loads(result)
"
```

## Tuning for performance

If the overhead is too high for your use case, you can selectively disable features:

| Configuration | Approximate overhead reduction |
|---------------|-------------------------------|
| Disable `zero-on-free` | Removes one `memset` per free |
| Disable `poison-on-free` | Removes one `memset` per free (and disables write-after-free check) |
| Reduce quarantine size | Reduces memory pressure and eviction processing |
| Disable `guard-pages` | Removes `mprotect` calls and reduces virtual address space usage |
| Disable `canaries` | Removes canary write/check per alloc/free |
| `COMPATMALLOC_DISABLE=1` | Bypasses all hardening (passthrough to glibc) |

## Weighted composite overhead

The headline "Weighted Overhead" metric computes a single overhead percentage that accounts for real-world allocation size distributions. Instead of reporting only the 64-byte latency, we weight each allocation size by its frequency in typical programs (based on jemalloc/tcmalloc telemetry data):

| Size | Weight | Rationale |
|------|--------|-----------|
| 16B  | 20%    | Most common (tiny objects, pointers, small structs) |
| 32B  | 15%    | Second most common |
| 64B  | 15%    | Common for small structs, string headers |
| 128B | 12%    | Medium-small objects |
| 256B | 10%    | Strings, small buffers |
| 512B | 8%     | Buffers |
| 1K   | 5%     | Page-ish allocations |
| 4K   | 5%     | Page-aligned allocations |
| 16K  | 4%     | Large buffers |
| 64K  | 3%     | Near mmap threshold |
| 256K | 3%     | Very large allocations |

**Formula:** `overhead = (Σ weight_i × (alloc_latency_i / glibc_latency_i) − 1) × 100%`

A weighted overhead of +15% means compatmalloc is 15% slower than glibc across a representative workload mix. Negative values indicate compatmalloc is faster.

## Methodology notes

When benchmarking allocators, keep the following in mind:

1. **Warm up the allocator.** The first few allocations may be slower due to slab initialization and metadata table growth.
2. **Test with realistic workloads.** Microbenchmarks of `malloc`/`free` loops do not represent real application behavior.
3. **Measure RSS, not just time.** Hardening features (quarantine, guard pages) increase resident memory. Use `getrusage` or `/proc/self/status` to measure `VmRSS`.
4. **Account for variance.** Run benchmarks multiple times and report medians. Allocator performance can be sensitive to ASLR and system load.
5. **Best-of-3 selection.** CI results use the minimum latency and maximum throughput from 3 runs. This filters out noise from shared infrastructure while reflecting the allocator's true capability.
6. **Compare against other allocators.** The comparison table includes jemalloc and mimalloc (performance-focused) alongside scudo (hardened, like compatmalloc). This provides context for the overhead of hardening features.
