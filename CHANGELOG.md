# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.1] - 2026-03-15

### Fixed

- Flaky `freed_memory_poison_full_slot` test: gate on `quarantine` feature to prevent race with parallel test threads reusing freed slots

## [0.2.0] - 2026-03-15

### Added

- **ARM64 MTE (Memory Tagging Extension) support** — hardware-enforced memory safety on ARMv8.5-A+ hardware, replacing software canaries at zero overhead:
  - MTE tagging wired into malloc and free hot paths
  - `PROT_MTE` flag used for slab backing memory when MTE is available
  - MTE re-tagging on free invalidates dangling pointers
  - Always compiled on aarch64 with runtime detection (no feature flag needed)
- **Thread-local large allocation cache** — eliminates syscalls and global lock contention from the large allocation hot path
- **Weighted composite overhead score** in CI benchmark reports using real-world allocation size distribution

### Fixed

- Abort on `free()` of invalid pointers instead of silently ignoring them
- Preserve alignment in `realloc` for `memalign`-allocated pointers
- Pass caller alignment through `arena.alloc` for `memalign`
- `check_integrity` false positives and `memalign` canary mismatch
- Prevent segfault when glibc frees thread-local state after thread exit
- Guard all canary/poison paths for MTE correctness
- Fail CI when applications crash under `LD_PRELOAD`
- ARM64 benchmark CI: install matching LLVM 21 toolchain for LTO builds

### Performance

- Eliminate syscalls and global locks from large allocation TLS cache hot path
- Enable LTO and LSE atomics for ARM64 CI builds

## [0.1.0] - 2026-02-21

Initial release.

### Added

- **LD_PRELOAD interposer** with glibc-compatible C ABI — 14 exported symbols (malloc, free, realloc, calloc, posix_memalign, aligned_alloc, memalign, valloc, pvalloc, malloc_usable_size, mallopt, mallinfo, mallinfo2, compatmalloc_check_integrity)
- **`#[global_allocator]` support** via `CompatMalloc` struct (feature: `global-allocator`)
- **8 configurable hardening features**, all enabled by default:
  - `quarantine` — per-arena free ring buffer delays reuse
  - `guard-pages` — PROT_NONE boundary pages around slab regions
  - `slot-randomization` — randomized allocation slot selection
  - `canaries` — non-invertible hash canaries detect overflow on free
  - `poison-on-free` — 0xFE fill on free detects use-after-free reads
  - `write-after-free-check` — verifies poison pattern on reallocation
  - `zero-on-free` — zeroes memory on free to prevent information leaks
  - `mte` — ARM64 Memory Tagging Extension support (not in default feature set)
- **musl/Alpine Linux support** for both LD_PRELOAD and `#[global_allocator]` modes
- **Large allocation cache** with MADV_DONTNEED to prevent data leaks on reuse
- **Per-arena locking** for reduced contention in multi-threaded workloads
- **Thread-local slab caches** with fast TLS via C initial-exec shim
- **Runtime configuration** via environment variables (COMPATMALLOC_QUARANTINE_SIZE, COMPATMALLOC_ARENA_COUNT)
- **Integrity checking** via `compatmalloc_check_integrity()` exported C function

### Platform Support

- Linux x86_64 (glibc and musl) — full support
- macOS and Windows — compilation stubs (not functional)
