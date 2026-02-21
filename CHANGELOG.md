# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
