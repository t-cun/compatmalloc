# Benchmarks

compatmalloc prioritizes security over raw performance. This page describes the performance characteristics, overhead sources, and how to run benchmarks to measure the impact on your workloads.

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

### Basic benchmark run

```bash
cargo bench --workspace
```

This runs all benchmarks defined in the `benches/` directory and outputs timing results to the console. Results are also saved under `target/criterion/` if Criterion is used.

### Comparing against baseline

To compare the current build against a baseline:

```bash
# Save a baseline
cargo bench --workspace -- --save-baseline main

# Make changes, then compare
cargo bench --workspace -- --baseline main
```

### Disabling hardening for comparison

To measure the overhead of hardening features, compare against a build with no features:

```bash
# With all hardening (default)
cargo bench --workspace

# Without hardening
cargo bench --workspace --no-default-features
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

## Methodology notes

When benchmarking allocators, keep the following in mind:

1. **Warm up the allocator.** The first few allocations may be slower due to slab initialization and metadata table growth.
2. **Test with realistic workloads.** Microbenchmarks of `malloc`/`free` loops do not represent real application behavior.
3. **Measure RSS, not just time.** Hardening features (quarantine, guard pages) increase resident memory. Use `getrusage` or `/proc/self/status` to measure `VmRSS`.
4. **Account for variance.** Run benchmarks multiple times and report medians. Allocator performance can be sensitive to ASLR and system load.
