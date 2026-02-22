# compatmalloc

> A drop-in memory-hardening allocator for Linux, written in Rust.

[![CI](https://github.com/t-cun/compatmalloc/actions/workflows/ci.yml/badge.svg)](https://github.com/t-cun/compatmalloc/actions/workflows/ci.yml)
[![Benchmarks](https://github.com/t-cun/compatmalloc/actions/workflows/bench.yml/badge.svg)](https://github.com/t-cun/compatmalloc/actions/workflows/bench.yml)
[![crates.io](https://img.shields.io/crates/v/compatmalloc.svg)](https://crates.io/crates/compatmalloc)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

glibc's allocator prioritizes throughput over safety. Heap vulnerabilities -- use-after-free, buffer overflows, double frees, metadata corruption -- remain the most exploited bug classes in native software.

**compatmalloc** retrofits memory safety onto legacy C/C++ binaries without recompilation. Load it via `LD_PRELOAD` and every `malloc`/`free` call gains defense-in-depth hardening at near-native speed.

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
print('Success -- all allocations hardened')
"
```

### Troubleshooting

If `LD_PRELOAD` appears to have no effect:

- **Use an absolute path.** `LD_PRELOAD` requires a full path or a library name findable via `ld.so`. Relative paths like `./target/...` work from the repo root but not elsewhere.
- **setuid/setgid binaries ignore `LD_PRELOAD`.** This is a kernel security policy. Use `/etc/ld.so.preload` for system-wide coverage instead.
- **Verify it loaded.** Run `LD_DEBUG=libs LD_PRELOAD=./target/release/libcompatmalloc.so ls 2>&1 | grep compatmalloc` -- you should see it being loaded.

## Performance

compatmalloc delivers **hardened-allocator security at near-glibc throughput** -- 3-4x faster than Scudo in microbenchmarks with comparable protections.

### x86_64 (CI Results)

| Allocator | Latency (64B) | vs glibc | Throughput (1T) | vs glibc | Throughput (4T) | vs glibc |
|-----------|------------:|--------:|--------------:|--------:|--------------:|--------:|
| **compatmalloc** | 13.7 ns | 1.19x | 69.12 Mops/s | 0.88x | 154.25 Mops/s | 0.92x |
| glibc | 11.5 ns | 1.00x | 78.36 Mops/s | 1.00x | 167.96 Mops/s | 1.00x |
| jemalloc | 8.8 ns | 0.77x | 102.82 Mops/s | 1.31x | 249.80 Mops/s | 1.49x |
| mimalloc | 11.3 ns | 0.98x | 81.08 Mops/s | 1.03x | 190.78 Mops/s | 1.14x |
| scudo | 49.0 ns | 4.26x | 19.83 Mops/s | 0.25x | 40.28 Mops/s | 0.24x |

> Latency ratio < 1.0 = faster than glibc. Throughput ratio > 1.0 = faster than glibc.
> **Hardened allocators:** compatmalloc, scudo. Both have security features (guard pages, quarantine, etc.) that add overhead vs pure-performance allocators.
>
> Auto-generated from CI. See [full benchmark results](https://t-cun.github.io/compatmalloc/benchmarks.html) for ARM64, per-size latency, and application overhead data.

### Real-World Application Overhead

| Application | glibc | compatmalloc | Overhead |
|-------------|------:|-------------:|---------:|
| python-json | 0.066s | 0.075s | +13% |
| redis | 2.431s | 2.426s | **-1%** |
| nginx | 5.103s | 5.103s | **-1%** |
| sqlite | 0.147s | 0.131s | **-12%** |

> Wall-clock time on shared GitHub Actions runners (no CPU pinning, no isolated cores). Results vary between runs due to noisy-neighbor effects, ASLR, and cache alignment. Negative overhead does not necessarily mean compatmalloc is faster -- it means the difference is within noise. These numbers show that overhead is low in practice, not that it is zero.

## Security Features

### What it catches

| Exploit Primitive | Mitigation | Mechanism |
|-------------------|-----------|-----------|
| Heap buffer overflow | Canary bytes | Non-invertible hash canaries in gap between requested size and slot boundary. Checked on `free()`. |
| Use-after-free | Quarantine + Poison | Freed memory held in per-arena ring buffer (default 4 MiB). Poison bytes (`0xFE`) detect stale writes on eviction. |
| Double free | Metadata flags | Out-of-band `FLAG_FREED` set atomically on `free()`. Second `free()` detects the flag and aborts immediately. |
| Heap metadata corruption | Out-of-band metadata | Metadata stored in separate `mmap` region. No inline freelist pointers for attackers to corrupt. |
| Adjacent chunk corruption | Guard pages | `PROT_NONE` pages before and after allocations. Hardware-enforced boundary. |
| Heap spraying / grooming | Slot randomization | Random slot selection within size classes defeats deterministic heap layout. |
| Information leaks | Zero-on-free | Memory cleared on free, preventing data from persisting across allocations. |

### Limitations (honest assessment)

- **Canary checks happen on `free()`, not on write.** A 1-byte overflow is only detected when the overflowed chunk is freed. If it's never freed, the overflow goes undetected.
- **Not async-signal-safe.** Per-arena mutexes prevent safe use from signal handlers that may contend with the interrupted thread.
- **Quarantine has a finite budget.** After eviction, use-after-free on that address becomes undetectable.
- **No inline bounds checking.** Read overflows that stay within the slot size are invisible to canary checks.

### CVE Case Studies

compatmalloc has been tested against real-world exploits:

- **[CVE-2024-2961](https://t-cun.github.io/compatmalloc/cve-case-studies/cve-2024-2961.html)** -- iconv buffer overflow (CVSS 8.8). Tcache poisoning via 1-byte overflow. Caught by canaries + out-of-band metadata.
- **[CVE-2023-6246](https://t-cun.github.io/compatmalloc/cve-case-studies/cve-2023-6246.html)** -- syslog heap overflow (CVSS 7.8). Local privilege escalation via `su`. Caught by canaries + guard pages.
- **[Double-Free Detection](https://t-cun.github.io/compatmalloc/cve-case-studies/double-free.html)** -- Immediate abort via out-of-band metadata flags.

## Integration

### Docker

A multi-stage [Dockerfile](Dockerfile) is provided for container integration. Build the `.so` artifact first, then copy it into your application image:

```bash
# Build the artifact image (one-time)
docker build --target artifact -t compatmalloc-artifact .
```

Then in your application's Dockerfile:

```dockerfile
# Copy the prebuilt .so from the artifact image
COPY --from=compatmalloc-artifact /libcompatmalloc.so /usr/lib/libcompatmalloc.so
ENV LD_PRELOAD=/usr/lib/libcompatmalloc.so
```

Or use the ready-made hardened base image directly:

```bash
docker build --target hardened-base -t my-hardened-app .
docker run --rm my-hardened-app whoami
```

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

### Alpine / musl

compatmalloc supports musl-based systems (Alpine Linux) via both LD_PRELOAD and `#[global_allocator]`.

**LD_PRELOAD (container hardening):**

```bash
docker build -f Dockerfile.alpine --target hardened-base -t myapp-hardened .
```

**Rust native (`#[global_allocator]`):**

```bash
cargo add compatmalloc --features global-allocator
cargo build --target x86_64-unknown-linux-musl
```

See the [Dockerfile.alpine](Dockerfile.alpine) for packaging details.

### Rust Native (`#[global_allocator]`)

For Rust projects, skip `LD_PRELOAD` entirely. Add to `Cargo.toml`:

```toml
[dependencies]
compatmalloc = { git = "https://github.com/t-cun/compatmalloc.git", features = ["global-allocator"] }
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

This statically links the hardened allocator into your binary -- no `.so` file, no environment variables, no runtime dependencies.

> **Note:** The `global-allocator` feature implies `hardened` (all security features enabled). To select individual features, use `LD_PRELOAD` with compile-time feature flags instead.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPATMALLOC_DISABLE` | not set | Kill-switch: bypass all hardening, passthrough to glibc. **Presence-based** -- any value (even `=0`) triggers disable. Unset the variable entirely to re-enable. |
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
- [x] Alpine / musl support (LD_PRELOAD + `#[global_allocator]`)
- [ ] Publish to crates.io
- [ ] Yocto/OpenEmbedded recipe for IoT devices
- [ ] Android (Bionic libc) compatibility
- [ ] ARM64 Memory Tagging Extension (MTE) integration

## Trophy Case

*Zero-days and bugs found by fuzzing with compatmalloc.*

> No trophies yet -- want to be first? Run your C/C++ programs with `LD_PRELOAD=libcompatmalloc.so` and report crashes to the upstream projects. Mention compatmalloc and we'll add it here.

## Documentation

Full documentation: **[t-cun.github.io/compatmalloc](https://t-cun.github.io/compatmalloc/)**

- [ABI Contract](https://t-cun.github.io/compatmalloc/abi-contract.html) -- every exported symbol and its semantics
- [Hardening Details](https://t-cun.github.io/compatmalloc/hardening/overview.html) -- how each defense mechanism works
- [Benchmarks](https://t-cun.github.io/compatmalloc/benchmarks.html) -- full performance data with methodology
- [Configuration](https://t-cun.github.io/compatmalloc/configuration.html) -- all environment variables and feature flags
- [Deviations from glibc](https://t-cun.github.io/compatmalloc/deviations.html) -- known behavioral differences

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Sponsorship

If your company uses compatmalloc to harden production infrastructure, consider [sponsoring the project](https://github.com/sponsors/t-cun).

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).
