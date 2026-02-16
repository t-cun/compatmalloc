# Getting Started

## Prerequisites

- **Rust toolchain** (stable channel). Install via [rustup](https://rustup.rs/).
- **Linux x86_64** (the primary supported platform).
- A C compiler toolchain (`gcc` or `clang`) for linking the cdylib.

## Build

Clone the repository and build the release library:

```bash
git clone https://github.com/user/compatmalloc.git
cd compatmalloc
cargo build --release
```

The output shared library is at:

```
target/release/libcompatmalloc.so
```

## Basic usage with LD_PRELOAD

Inject the library into any dynamically linked program:

```bash
LD_PRELOAD=./target/release/libcompatmalloc.so <your-program>
```

For example:

```bash
# Run bash with compatmalloc
LD_PRELOAD=./target/release/libcompatmalloc.so bash -c 'echo "hello from hardened malloc"'

# Run Python
LD_PRELOAD=./target/release/libcompatmalloc.so python3 -c 'print("works")'

# Run a server
LD_PRELOAD=./target/release/libcompatmalloc.so ./my-server
```

## Verify it works

You can confirm that compatmalloc is intercepting allocations by checking that the library is loaded:

```bash
LD_PRELOAD=./target/release/libcompatmalloc.so \
  bash -c 'cat /proc/self/maps | grep compatmalloc'
```

This should show the library mapped into the process address space.

You can also check exported symbols:

```bash
nm -D target/release/libcompatmalloc.so | grep -E ' T (malloc|free|calloc|realloc)$'
```

Expected output:

```
0000000000xxxxxx T calloc
0000000000xxxxxx T free
0000000000xxxxxx T malloc
0000000000xxxxxx T realloc
```

## Disable at runtime

If you need to bypass the hardened allocator without removing `LD_PRELOAD`, set the kill-switch environment variable:

```bash
COMPATMALLOC_DISABLE=1 LD_PRELOAD=./target/release/libcompatmalloc.so <your-program>
```

This makes all allocator calls pass through to glibc. See [Configuration](./configuration.md) for all available options.

## Run the test suite

```bash
cargo test --workspace
```

This runs unit tests for all internal modules (size classes, bitmap, metadata table, etc.).
