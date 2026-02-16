# Configuration

compatmalloc reads configuration from environment variables at initialization time (before `main()` runs). All configuration is optional; the defaults provide a good balance of security and performance.

## Environment variables

### COMPATMALLOC_DISABLE

**Type:** presence-based (any value enables it)
**Default:** not set (allocator is enabled)

When this variable is set to any non-empty value, the hardened allocator is completely bypassed. All `malloc`/`free`/`realloc`/`calloc` calls are forwarded directly to glibc via `dlsym(RTLD_NEXT)`.

Use this as a kill-switch if you suspect the allocator is causing issues with a specific program:

```bash
COMPATMALLOC_DISABLE=1 LD_PRELOAD=./libcompatmalloc.so ./my-program
```

**Implementation:** Checked during init via `config::is_disabled()`. The init state machine transitions to `DISABLED` instead of `READY`, and the dispatch macro routes all calls to the passthrough allocator.

### COMPATMALLOC_ARENA_COUNT

**Type:** unsigned integer
**Default:** number of CPUs (capped at 32)

Sets the number of slab arenas. Each arena has its own set of size-class slabs and its own locks, so more arenas reduce contention in multi-threaded programs.

```bash
COMPATMALLOC_ARENA_COUNT=8 LD_PRELOAD=./libcompatmalloc.so ./my-server
```

**Valid range:** 1 to 32 (`MAX_ARENAS`). Values above 32 are clamped. A value of 0 means "use the default" (number of CPUs).

**Tradeoff:** More arenas reduce lock contention but increase memory usage (each arena independently maps slab regions). For single-threaded programs, `COMPATMALLOC_ARENA_COUNT=1` is optimal.

**Thread-to-arena mapping:** Threads are assigned to arenas by `thread_id % num_arenas`. This provides a rough approximation of per-CPU arenas without requiring `sched_getcpu`.

### COMPATMALLOC_QUARANTINE_SIZE

**Type:** unsigned integer (bytes)
**Default:** `4194304` (4 MiB)

Sets the maximum total bytes held in the quarantine queue. When the quarantine's total byte count would exceed this limit, the oldest entries are evicted (and their slots returned to the free list) until the limit is satisfied.

```bash
# Larger quarantine for more thorough use-after-free detection
COMPATMALLOC_QUARANTINE_SIZE=16777216 LD_PRELOAD=./libcompatmalloc.so ./my-program

# Smaller quarantine to reduce memory overhead
COMPATMALLOC_QUARANTINE_SIZE=1048576 LD_PRELOAD=./libcompatmalloc.so ./my-program
```

**Valid range:** 0 to `usize::MAX`. A value of 0 means entries are evicted immediately (effectively disabling quarantine delay, though the quarantine code path is still executed).

**Note:** This variable only has effect when the `quarantine` feature is enabled (it is enabled by default in the `hardened` feature set).

## Configuration timing

All environment variables are read once during the library constructor (`__attribute__((constructor))` equivalent via `.init_array`). Configuration cannot be changed at runtime. This design avoids the need for synchronization on configuration reads in the hot path.

The read sequence during init:

1. `passthrough::resolve_real_functions()` -- resolve glibc symbols via `dlsym`.
2. `config::read_config()` -- read `COMPATMALLOC_ARENA_COUNT` and `COMPATMALLOC_QUARANTINE_SIZE`.
3. `config::is_disabled()` -- check `COMPATMALLOC_DISABLE`.
4. `HardenedAllocator::init()` -- apply configuration values.

## Summary table

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `COMPATMALLOC_DISABLE` | presence | not set | Bypass hardened allocator entirely |
| `COMPATMALLOC_ARENA_COUNT` | uint | CPU count (max 32) | Number of per-thread slab arenas |
| `COMPATMALLOC_QUARANTINE_SIZE` | uint (bytes) | 4194304 (4 MiB) | Maximum quarantine queue size |
