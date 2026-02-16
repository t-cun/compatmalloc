# Building

## Prerequisites

- **Rust stable toolchain.** Install via [rustup](https://rustup.rs/):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **Linux x86_64.** The primary supported platform. The library uses Linux-specific APIs (`mmap`, `mprotect`, `futex`, `/proc/self/maps`).
- **C linker.** The `cc` crate will use `gcc` or `clang` for linking the cdylib. On Ubuntu/Debian: `apt install build-essential`.

## Build commands

### Debug build

```bash
cargo build --workspace
```

Output: `target/debug/libcompatmalloc.so`

The debug build includes debug assertions (`debug_assert!`) and debug symbols. It is suitable for development and testing but not for performance measurement.

### Release build

```bash
cargo build --workspace --release
```

Output: `target/release/libcompatmalloc.so`

The release profile is configured in the workspace `Cargo.toml` with aggressive optimizations:

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
```

- `opt-level = 3` -- maximum optimization.
- `lto = "fat"` -- full link-time optimization across all crates.
- `codegen-units = 1` -- single codegen unit for better optimization (slower compile).
- `panic = "abort"` -- no unwinding (smaller binary, no landing pads).

### Hardened profile

A custom `hardened` profile is available for deployments that want a balance between debuggability and performance:

```bash
cargo build --workspace --profile hardened
```

```toml
[profile.hardened]
inherits = "release"
opt-level = 2
overflow-checks = true
debug = 1
```

- `opt-level = 2` -- slightly less aggressive optimization (faster compile, slightly larger binary).
- `overflow-checks = true` -- arithmetic overflow panics instead of wrapping.
- `debug = 1` -- line-level debug info (for useful backtraces without full debug bloat).

## Feature flags

The `compatmalloc` crate defines the following features:

| Feature | Default | Description |
|---------|---------|-------------|
| `hardened` | Yes | Meta-feature that enables all hardening features below |
| `quarantine` | Via `hardened` | Delay reuse of freed memory |
| `guard-pages` | Via `hardened` | Place inaccessible pages around allocations |
| `slot-randomization` | Via `hardened` | Randomize slot selection within size classes |
| `canaries` | Via `hardened` | Detect buffer overflows via canary bytes |
| `poison-on-free` | Via `hardened` | Fill freed memory with a poison pattern |
| `write-after-free-check` | Via `hardened` | Detect writes to freed memory during quarantine eviction |
| `zero-on-free` | Via `hardened` | Zero memory on free (defense against information leaks) |

### Building with specific features

```bash
# All hardening (default)
cargo build --release

# No hardening (passthrough-like performance)
cargo build --release --no-default-features

# Only quarantine and guard pages
cargo build --release --no-default-features --features quarantine,guard-pages

# Everything except zero-on-free (reduce free overhead)
cargo build --release --no-default-features \
  --features quarantine,guard-pages,slot-randomization,canaries,poison-on-free,write-after-free-check
```

## Linker scripts

The build script (`build.rs`) configures platform-specific linker behavior:

- **Linux:** A version script (`linker/version_script.lds`) controls which symbols are exported. Only the standard C allocator symbols are exported; all internal Rust symbols are hidden.
- **macOS:** All symbols are exported by default (no special configuration yet).
- **Windows:** A `.def` file (`linker/exports.def`) lists exported symbols.

## Running tests

```bash
# All tests
cargo test --workspace

# Release mode tests
cargo test --workspace --release

# Tests with no default features
cargo test --workspace --no-default-features

# Tests for a single feature
cargo test --workspace --no-default-features --features canaries
```

## Checking code quality

```bash
# Format check
cargo fmt --all -- --check

# Clippy lints
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Cross-compilation

The library is primarily designed for Linux x86_64. Cross-compilation to other Linux architectures (aarch64, etc.) should work but is not tested in CI. Non-Linux platforms (macOS, Windows) have stub platform implementations but are not fully supported.

```bash
# Example: cross-compile for aarch64-linux
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
```
