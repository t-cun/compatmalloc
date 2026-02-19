# README, Dockerfile, PKGBUILD, & #[global_allocator] Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a comprehensive README.md, a multi-stage Dockerfile, an Arch Linux PKGBUILD, and native Rust `#[global_allocator]` support to compatmalloc.

**Architecture:** Four independent deliverables that can be built in parallel. The README references the other three (Dockerfile, PKGBUILD, `#[global_allocator]`), so it should be written last or updated last. The `#[global_allocator]` feature requires refactoring the existing `HardenedAllocator` to implement `core::alloc::GlobalAlloc`, adding a new public struct, and conditionally compiling the cdylib vs lib crate types.

**Tech Stack:** Rust (core::alloc::GlobalAlloc), Docker (multi-stage builds), makepkg (Arch PKGBUILD), Markdown (README)

---

## Task 1: Add Dockerfile

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`

**Step 1: Create .dockerignore**

```
target/
.git/
docs/
fuzz/
benches/
tests/
*.md
.github/
.claude/
```

**Step 2: Create multi-stage Dockerfile**

```dockerfile
# Stage 1: Build compatmalloc from source
FROM rust:1-bookworm AS builder

# Install clang + lld for LTO (matches CI pipeline)
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends clang lld && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

# Build with LTO for maximum performance
RUN RUSTFLAGS="-Clink-arg=-fuse-ld=lld" \
    cargo build --workspace --release && \
    strip target/release/libcompatmalloc.so

# Stage 2: Minimal output — just the .so file
FROM scratch AS artifact
COPY --from=builder /build/target/release/libcompatmalloc.so /libcompatmalloc.so

# Stage 3: Example — harden any Debian-based application
FROM debian:bookworm-slim AS hardened-base
COPY --from=builder /build/target/release/libcompatmalloc.so /usr/lib/libcompatmalloc.so
ENV LD_PRELOAD=/usr/lib/libcompatmalloc.so
# Your CMD here — e.g.:
# CMD ["nginx", "-g", "daemon off;"]
```

The Dockerfile provides three targets:
- `builder`: Compiles from source (users building from git)
- `artifact`: Extracts just the `.so` for `COPY --from` in other Dockerfiles
- `hardened-base`: Ready-to-use Debian base with `LD_PRELOAD` set

**Step 3: Test the Dockerfile builds**

Run: `docker build --target artifact -t compatmalloc:artifact .`
Expected: Successful build, image contains only `/libcompatmalloc.so`

Run: `docker build --target hardened-base -t compatmalloc:hardened .`
Expected: Successful build

Run: `docker run --rm compatmalloc:hardened whoami`
Expected: Prints `root` (proving LD_PRELOAD doesn't break basic binaries)

**Step 4: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "feat: add multi-stage Dockerfile for container integration"
```

---

## Task 2: Add PKGBUILD for Arch Linux AUR

**Files:**
- Create: `pkg/arch/PKGBUILD`

**Step 1: Create the PKGBUILD**

```bash
# Maintainer: compatmalloc contributors
pkgname=compatmalloc
pkgver=0.1.0
pkgrel=1
pkgdesc="A drop-in memory-hardening allocator for Linux, written in Rust"
arch=('x86_64' 'aarch64')
url="https://github.com/t-cun/compatmalloc"
license=('MIT' 'Apache-2.0')
makedepends=('rust' 'cargo' 'clang' 'lld')
source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
    cd "$pkgname-$pkgver"
    RUSTFLAGS="-Clink-arg=-fuse-ld=lld" \
        cargo build --workspace --release
}

package() {
    cd "$pkgname-$pkgver"
    install -Dm755 "target/release/libcompatmalloc.so" \
        "$pkgdir/usr/lib/libcompatmalloc.so"

    # Install license files
    install -Dm644 LICENSE-MIT "$pkgdir/usr/share/licenses/$pkgname/LICENSE-MIT"
    install -Dm644 LICENSE-APACHE "$pkgdir/usr/share/licenses/$pkgname/LICENSE-APACHE"
}
```

Note: The `sha256sums=('SKIP')` is standard for AUR git packages. It will be replaced with the actual checksum when a release tarball is published. The `LICENSE-MIT` and `LICENSE-APACHE` files must exist in the repo root; if they don't exist yet, create them before this step (the workspace `Cargo.toml` already declares `license = "MIT OR Apache-2.0"`).

**Step 2: Validate PKGBUILD syntax (if on Arch)**

Run: `namcap pkg/arch/PKGBUILD` (optional — only works on Arch systems)

If not on Arch, just verify the file looks correct structurally.

**Step 3: Commit**

```bash
git add pkg/arch/PKGBUILD
git commit -m "feat: add PKGBUILD for Arch Linux AUR packaging"
```

---

## Task 3: Add `#[global_allocator]` support

This is the most complex task. The goal is to let Rust users write:

```rust
use compatmalloc::CompatMalloc;

#[global_allocator]
static GLOBAL: CompatMalloc = CompatMalloc;
```

### Architecture Decision

The current crate is `cdylib` + `lib`. The `cdylib` target exports C symbols via `#[no_mangle]`. The `#[global_allocator]` feature needs a struct implementing `core::alloc::GlobalAlloc`.

**Approach:** Add a `CompatMalloc` unit struct that implements `GlobalAlloc` by delegating to the existing `HardenedAllocator` singleton (same `init::allocator()` path used by the C API). This is gated behind a new `global-allocator` Cargo feature. When this feature is enabled, the crate type is `lib` only (no `cdylib`), since `#[global_allocator]` and `LD_PRELOAD` are mutually exclusive use cases.

**Files:**
- Create: `crates/compatmalloc/src/global_alloc.rs`
- Modify: `crates/compatmalloc/src/lib.rs` — add `mod global_alloc` + re-export
- Modify: `crates/compatmalloc/Cargo.toml` — add `global-allocator` feature

**Step 1: Add the `global-allocator` feature to Cargo.toml**

In `crates/compatmalloc/Cargo.toml`, add to the `[features]` section:

```toml
global-allocator = ["hardened"]
```

This feature implies `hardened` (all security features on by default for GlobalAlloc users).

**Step 2: Write the failing test**

Create file `crates/compatmalloc/tests/global_allocator.rs`:

```rust
//! Test that CompatMalloc works as a #[global_allocator].
//! Only compiled when the `global-allocator` feature is enabled.
#![cfg(feature = "global-allocator")]

use compatmalloc::CompatMalloc;

#[global_allocator]
static GLOBAL: CompatMalloc = CompatMalloc;

#[test]
fn basic_alloc_and_free() {
    // Exercise Box (malloc + free)
    let b = Box::new(42u64);
    assert_eq!(*b, 42);
    drop(b);

    // Exercise Vec (malloc + realloc + free)
    let mut v: Vec<u8> = Vec::with_capacity(16);
    v.extend_from_slice(&[1, 2, 3, 4]);
    assert_eq!(v.len(), 4);
    // Force realloc by growing past capacity
    v.extend(std::iter::repeat(0xAA).take(1024));
    assert_eq!(v.len(), 1028);
    drop(v);

    // Exercise String (calloc-like + realloc)
    let s = "hello world".repeat(100);
    assert_eq!(s.len(), 1100);
    drop(s);
}

#[test]
fn zero_size_alloc() {
    // Vec<()> with zero-sized type
    let v: Vec<()> = vec![(); 100];
    assert_eq!(v.len(), 100);
}

#[test]
fn aligned_alloc() {
    use std::alloc::{alloc, dealloc, Layout};

    unsafe {
        // 128-byte aligned allocation
        let layout = Layout::from_size_align(256, 128).unwrap();
        let ptr = alloc(layout);
        assert!(!ptr.is_null());
        assert_eq!(ptr as usize % 128, 0);
        // Write and read back
        ptr.write(0x42);
        assert_eq!(ptr.read(), 0x42);
        dealloc(ptr, layout);
    }
}
```

**Step 3: Run test to verify it fails**

Run: `cargo test --workspace --no-default-features --features global-allocator -p compatmalloc --test global_allocator -- --nocapture`
Expected: FAIL — `CompatMalloc` type does not exist

**Step 4: Create `global_alloc.rs`**

Create `crates/compatmalloc/src/global_alloc.rs`:

```rust
//! `#[global_allocator]` support for native Rust integration.
//!
//! ```rust,ignore
//! use compatmalloc::CompatMalloc;
//!
//! #[global_allocator]
//! static GLOBAL: CompatMalloc = CompatMalloc;
//! ```

use crate::init;
use core::alloc::{GlobalAlloc, Layout};

/// A memory-hardening allocator for use as Rust's `#[global_allocator]`.
///
/// This provides all of compatmalloc's hardening features (canaries, guard pages,
/// quarantine, out-of-band metadata) for native Rust programs without `LD_PRELOAD`.
///
/// # Example
///
/// ```rust,ignore
/// use compatmalloc::CompatMalloc;
///
/// #[global_allocator]
/// static GLOBAL: CompatMalloc = CompatMalloc;
/// ```
pub struct CompatMalloc;

unsafe impl GlobalAlloc for CompatMalloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        init::ensure_initialized();
        if layout.size() == 0 {
            return layout.align() as *mut u8;
        }
        if layout.align() <= crate::util::MIN_ALIGN {
            init::allocator().malloc(layout.size())
        } else {
            init::allocator().memalign(layout.align(), layout.size())
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == 0 {
            return;
        }
        init::allocator().free(ptr);
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        init::ensure_initialized();
        if layout.size() == 0 {
            return layout.align() as *mut u8;
        }
        if layout.align() <= crate::util::MIN_ALIGN {
            init::allocator().calloc(1, layout.size())
        } else {
            // Fall back to alloc + memset for over-aligned zeroed allocs
            let ptr = self.alloc(layout);
            if !ptr.is_null() {
                core::ptr::write_bytes(ptr, 0, layout.size());
            }
            ptr
        }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.size() == 0 {
            return self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
        }
        if new_size == 0 {
            self.dealloc(ptr, layout);
            return layout.align() as *mut u8;
        }
        if layout.align() <= crate::util::MIN_ALIGN {
            init::allocator().realloc(ptr, new_size)
        } else {
            // For over-aligned realloc, allocate new + copy + free old
            let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
            let new_ptr = self.alloc(new_layout);
            if !new_ptr.is_null() {
                let copy_size = layout.size().min(new_size);
                core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
                self.dealloc(ptr, layout);
            }
            new_ptr
        }
    }
}
```

**Step 5: Wire up the module in lib.rs**

Add to `crates/compatmalloc/src/lib.rs`:

```rust
#[cfg(feature = "global-allocator")]
mod global_alloc;
#[cfg(feature = "global-allocator")]
pub use global_alloc::CompatMalloc;
```

**Step 6: Run tests**

Run: `cargo test --workspace --no-default-features --features global-allocator -p compatmalloc --test global_allocator -- --nocapture`
Expected: PASS — all 3 tests pass

Also verify existing tests still pass:
Run: `cargo test --workspace`
Expected: PASS — no regressions

**Step 7: Commit**

```bash
git add crates/compatmalloc/src/global_alloc.rs crates/compatmalloc/src/lib.rs crates/compatmalloc/Cargo.toml crates/compatmalloc/tests/global_allocator.rs
git commit -m "feat: add #[global_allocator] support for native Rust integration"
```

---

## Task 4: Add license files

The workspace `Cargo.toml` declares `license = "MIT OR Apache-2.0"` but there are no license files in the repo. These are needed by the PKGBUILD and README.

**Files:**
- Create: `LICENSE-MIT`
- Create: `LICENSE-APACHE`

**Step 1: Check if license files already exist**

Run: `ls LICENSE*`
Expected: No matches (confirmed by earlier exploration)

**Step 2: Create LICENSE-MIT**

Use standard MIT license text with copyright holder "compatmalloc contributors".

**Step 3: Create LICENSE-APACHE**

Use standard Apache License 2.0 text.

**Step 4: Commit**

```bash
git add LICENSE-MIT LICENSE-APACHE
git commit -m "chore: add MIT and Apache-2.0 license files"
```

---

## Task 5: Write README.md

**Files:**
- Create: `README.md`

This is the largest task. The README must be a compelling landing page for the project. It references benchmark data from `docs/src/generated/benchmark-results.md` (CI-generated).

**Step 1: Create README.md**

The README structure (per the user's spec):

````markdown
# compatmalloc

> A drop-in memory-hardening allocator for Linux, written in Rust.

[![CI](https://github.com/t-cun/compatmalloc/actions/workflows/ci.yml/badge.svg)](https://github.com/t-cun/compatmalloc/actions/workflows/ci.yml)
[![Benchmarks](https://github.com/t-cun/compatmalloc/actions/workflows/bench.yml/badge.svg)](https://github.com/t-cun/compatmalloc/actions/workflows/bench.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

glibc's allocator prioritizes throughput over safety. Heap vulnerabilities — use-after-free, buffer overflows, double frees, metadata corruption — remain the most exploited bug classes in native software.

**compatmalloc** retrofits memory safety onto legacy C/C++ binaries without recompilation. Load it via `LD_PRELOAD` and every `malloc`/`free` call gains defense-in-depth hardening at near-native speed.

## Performance

compatmalloc delivers **Scudo-level security at glibc-level throughput**.

### x86_64 (CI Results)

| Allocator | Latency (64B) | vs glibc | Throughput (1T) | vs glibc | Throughput (4T) | vs glibc |
|-----------|------------:|--------:|--------------:|--------:|--------------:|--------:|
| **compatmalloc** | 14.3 ns | 1.21x | 67.52 Mops/s | 0.88x | 152.07 Mops/s | 0.92x |
| glibc | 11.8 ns | 1.00x | 76.54 Mops/s | 1.00x | 165.24 Mops/s | 1.00x |
| jemalloc | 8.8 ns | 0.74x | 101.66 Mops/s | 1.32x | 256.98 Mops/s | 1.55x |
| mimalloc | 11.3 ns | 0.95x | 79.46 Mops/s | 1.03x | 188.98 Mops/s | 1.14x |
| scudo | 49.4 ns | 4.18x | 19.65 Mops/s | 0.25x | 39.86 Mops/s | 0.24x |

> Latency ratio < 1.0 = faster than glibc. Throughput ratio > 1.0 = faster than glibc.
> **Hardened allocators:** compatmalloc, scudo. Both have security features that add overhead vs pure-performance allocators.
>
> Auto-generated from CI. See [full benchmark results](https://t-cun.github.io/compatmalloc/benchmarks.html) for ARM64, per-size latency, and application overhead data.

### Real-World Application Overhead

| Application | glibc | compatmalloc | Overhead |
|-------------|------:|-------------:|---------:|
| python-json | 0.069s | 0.132s | +91% |
| redis | 3.157s | 2.976s | **-6%** |
| nginx | 5.104s | 5.104s | **0%** |
| sqlite | 0.192s | 0.132s | **-32%** |

> Wall-clock time on GitHub Actions runners. Negative overhead = compatmalloc was faster (cache/ASLR effects).

## Security Features

### What it catches

| Exploit Primitive | Mitigation | Mechanism |
|-------------------|-----------|-----------|
| Heap buffer overflow | **Canary bytes** | Non-invertible hash canaries in gap between requested size and slot boundary. Checked on `free()`. |
| Use-after-free | **Quarantine + Poison** | Freed memory held in per-arena ring buffer (default 4 MiB). Poison bytes (`0xFE`) detect stale writes on eviction. |
| Double free | **Metadata flags** | Out-of-band `FLAG_FREED` atomic CAS. Immediate abort on second `free()`. |
| Heap metadata corruption | **Out-of-band metadata** | Metadata stored in separate `mmap` region. No inline freelist pointers for attackers to corrupt. |
| Adjacent chunk corruption | **Guard pages** | `PROT_NONE` pages before and after allocations. Hardware-enforced boundary. |
| Heap spraying / grooming | **Slot randomization** | Random slot selection within size classes defeats deterministic heap layout. |
| Information leaks | **Zero-on-free** | Memory cleared on free, preventing data from persisting across allocations. |

### What it does NOT catch (honest assessment)

- **Canary checks happen on `free()`, not on write.** A 1-byte overflow that corrupts an adjacent allocation is only detected when the overflowed chunk is freed. If it's never freed, the overflow goes undetected.
- **Not async-signal-safe.** Per-arena mutexes prevent safe use from signal handlers that may contend with the interrupted thread.
- **Quarantine has a finite budget.** After eviction, use-after-free on that address becomes undetectable.
- **No inline bounds checking.** Read overflows that stay within the slot size are invisible to canary checks.

### CVE Case Studies

compatmalloc has been tested against real-world exploits:

- **[CVE-2024-2961](https://t-cun.github.io/compatmalloc/cve-case-studies/cve-2024-2961.html)** — iconv buffer overflow (CVSS 8.8). Tcache poisoning via 1-byte overflow. Caught by canaries + out-of-band metadata.
- **[CVE-2023-6246](https://t-cun.github.io/compatmalloc/cve-case-studies/cve-2023-6246.html)** — syslog heap overflow (CVSS 7.8). Local privilege escalation via `su`. Caught by canaries + guard pages.
- **[Double-Free Detection](https://t-cun.github.io/compatmalloc/cve-case-studies/double-free.html)** — Immediate abort via out-of-band metadata flags.

## Quick Start

### Build

```bash
git clone https://github.com/t-cun/compatmalloc.git
cd compatmalloc
cargo build --release
```

Output: `target/release/libcompatmalloc.so`

### Use (10-second test)

```bash
LD_PRELOAD=./target/release/libcompatmalloc.so whoami
```

### Harden any program

```bash
LD_PRELOAD=./target/release/libcompatmalloc.so python3 -c "
import json
data = [{'key': str(i), 'value': list(range(100))} for i in range(10000)]
json.dumps(data)
print('Success — all allocations hardened')
"
```

## Integration

### Docker

A multi-stage Dockerfile is provided for zero-friction container integration:

```dockerfile
# In your application's Dockerfile:
FROM compatmalloc AS allocator

FROM your-base-image:latest
COPY --from=allocator /build/target/release/libcompatmalloc.so /usr/lib/libcompatmalloc.so
ENV LD_PRELOAD=/usr/lib/libcompatmalloc.so
# ... your existing CMD
```

Or build directly:

```bash
docker build --target hardened-base -t my-hardened-app .
```

See the full [Dockerfile](Dockerfile) for all build targets.

### Arch Linux (AUR)

```bash
# Once published to AUR:
yay -S compatmalloc
```

System-wide hardening:

```bash
# Add to /etc/ld.so.preload for system-wide protection
echo "/usr/lib/libcompatmalloc.so" | sudo tee -a /etc/ld.so.preload
```

See the [PKGBUILD](pkg/arch/PKGBUILD) for packaging details.

### Rust Native (`#[global_allocator]`)

For Rust projects, skip `LD_PRELOAD` entirely. Add to `Cargo.toml`:

```toml
[dependencies]
compatmalloc = { version = "0.1", features = ["global-allocator"] }
```

Then in your `main.rs`:

```rust
use compatmalloc::CompatMalloc;

#[global_allocator]
static GLOBAL: CompatMalloc = CompatMalloc;

fn main() {
    // Every Box, Vec, String, and HashMap is now hardened.
    let data = vec![0u8; 1024];
    println!("Allocated {} bytes with compatmalloc", data.len());
}
```

This statically links the hardened allocator into your binary. No `.so` file, no environment variables, no runtime dependencies.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPATMALLOC_DISABLE=1` | not set | Kill-switch: bypass all hardening, passthrough to glibc |
| `COMPATMALLOC_ARENA_COUNT=N` | CPU count (max 32) | Number of per-thread slab arenas |
| `COMPATMALLOC_QUARANTINE_SIZE=N` | 4194304 (4 MiB) | Maximum quarantine queue size in bytes |

### Feature Flags (compile-time)

Build with selective hardening for performance tuning:

```bash
# All hardening (default)
cargo build --release

# No hardening (baseline performance)
cargo build --release --no-default-features

# Selective: only quarantine + canaries
cargo build --release --no-default-features --features quarantine,canaries
```

| Feature | Default | Per-alloc cost |
|---------|:-------:|----------------|
| `canaries` | on | ~2ns (hash + memset) |
| `quarantine` | on | ~1ns (ring buffer enqueue) |
| `guard-pages` | on | ~0ns small / mprotect large |
| `slot-randomization` | on | ~1ns (RNG) |
| `poison-on-free` | on | ~1-5ns (memset) |
| `write-after-free-check` | on | ~1-5ns (memcmp on eviction) |
| `zero-on-free` | on | ~1-5ns (memset) |

## Roadmap

- [x] LD_PRELOAD drop-in replacement (full glibc ABI)
- [x] Multi-allocator CI benchmarks (x86_64 + ARM64)
- [x] CVE case studies with proof-of-concept programs
- [x] Docker integration
- [x] Arch Linux PKGBUILD
- [x] Native Rust `#[global_allocator]` support
- [ ] Publish to crates.io
- [ ] Yocto/OpenEmbedded recipe for IoT devices
- [ ] Android (Bionic libc) compatibility
- [ ] ARM64 Memory Tagging Extension (MTE) integration

## Trophy Case

*Zero-days and bugs found by fuzzing with compatmalloc.*

> No trophies yet — want to be first? Run your C/C++ programs with `LD_PRELOAD=libcompatmalloc.so` and report crashes to the upstream projects. Mention compatmalloc and we'll add it here.

## Documentation

Full documentation is available at **[t-cun.github.io/compatmalloc](https://t-cun.github.io/compatmalloc/)**, including:

- [ABI Contract](https://t-cun.github.io/compatmalloc/abi-contract.html) — every exported symbol and its semantics
- [Hardening Details](https://t-cun.github.io/compatmalloc/hardening/overview.html) — how each defense mechanism works
- [Benchmarks](https://t-cun.github.io/compatmalloc/benchmarks.html) — full performance data with methodology
- [Configuration](https://t-cun.github.io/compatmalloc/configuration.html) — all environment variables and feature flags
- [Deviations from glibc](https://t-cun.github.io/compatmalloc/deviations.html) — known behavioral differences

## Sponsorship

If your company uses compatmalloc to harden production infrastructure, consider [sponsoring the project](https://github.com/sponsors/t-cun).

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).
````

**Step 2: Review the README for accuracy**

Verify:
- Benchmark numbers match `docs/src/generated/benchmark-results.md` (they do — pulled from latest CI)
- Feature names match `crates/compatmalloc/Cargo.toml`
- Env var names match `docs/src/configuration.md`
- CVE links point to correct pages
- Docker/PKGBUILD/GlobalAlloc sections reference correct file paths

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add comprehensive README with benchmarks, security features, and integration guides"
```

---

## Task 6: Add `global-allocator` feature to CI test matrix

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Add `global-allocator` to the individual features matrix**

In `.github/workflows/ci.yml`, find the `test-individual-features` job's `strategy.matrix.feature` list and add `global-allocator`:

```yaml
    strategy:
      matrix:
        feature:
          - quarantine
          - guard-pages
          - slot-randomization
          - canaries
          - poison-on-free
          - write-after-free-check
          - zero-on-free
          - global-allocator
```

**Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add global-allocator feature to test matrix"
```

---

## Execution Order

Tasks can be executed largely in parallel, with this dependency graph:

```
Task 4 (license files) ─┐
Task 1 (Dockerfile) ────┤
Task 2 (PKGBUILD) ──────┼──> Task 5 (README) ──> Task 6 (CI)
Task 3 (GlobalAlloc) ───┘
```

Tasks 1-4 are independent and can run concurrently. Task 5 (README) should run last since it references the other deliverables. Task 6 should be last since it's a CI config change that should go with everything else.
