# Introduction

**compatmalloc** is a drop-in memory-hardening allocator for Linux. It builds as a shared library (`libcompatmalloc.so`) that you can inject into any dynamically linked program via `LD_PRELOAD`, replacing the standard C memory allocator with one that actively detects and mitigates common heap exploitation techniques.

## Why compatmalloc?

Heap vulnerabilities -- use-after-free, heap buffer overflows, double frees, and metadata corruption -- remain among the most exploited bug classes in native software. Standard allocators like glibc's ptmalloc2 are optimized for throughput and make no attempt to detect misuse at runtime.

compatmalloc exists to close that gap. It provides:

- **Detection** of use-after-free, buffer overruns (via canaries), and double-free conditions.
- **Mitigation** through delayed memory reuse (quarantine), out-of-band metadata, and guard pages.
- **Compatibility** with the full glibc malloc ABI, so existing binaries work without recompilation.

## Design goals

1. **Drop-in replacement.** Export every symbol that glibc's malloc provides (`malloc`, `free`, `realloc`, `calloc`, `posix_memalign`, `aligned_alloc`, `memalign`, `valloc`, `pvalloc`, `malloc_usable_size`, `mallopt`, `mallinfo`, `mallinfo2`). Programs that link against glibc should work unchanged.

2. **Defense in depth.** Each hardening feature targets a different exploitation primitive. Features can be toggled individually through Cargo feature flags.

3. **No standard library dependency.** The allocator is built as a `cdylib` with `#![no_std]`-style patterns internally, using `libc` for system calls and `dlsym(RTLD_NEXT)` for fallback to the real allocator. This avoids circular dependencies and keeps the binary small.

4. **Reasonable performance.** The allocator is not a benchmark champion, but its overhead should be acceptable for development, testing, and hardened production deployments.

## How it works

When loaded via `LD_PRELOAD`, compatmalloc's exported symbols override glibc's. A library constructor (`__attribute__((constructor))` equivalent via `.init_array`) runs before `main()`, resolving the real libc functions via `dlsym(RTLD_NEXT)` and initializing the hardened allocator.

All allocations smaller than 16 KiB go through a **slab allocator** with per-CPU arenas. Larger allocations get individual `mmap` regions with optional guard pages on both sides. An **out-of-band metadata table** (stored in a separate `mmap` region) tracks each allocation's requested size, canary value, and freed-state flag, preventing attackers from corrupting heap metadata by overflowing adjacent allocations.

When the allocator is disabled (via `COMPATMALLOC_DISABLE=1`), all calls pass through to glibc, making it easy to toggle off in production if needed.
