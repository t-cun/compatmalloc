# Hardening Overview

compatmalloc implements multiple layers of heap hardening, each targeting a different exploitation primitive. All hardening features are enabled by default through the `hardened` Cargo feature set and can be toggled individually.

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `quarantine` | On | Delay memory reuse to detect use-after-free |
| `guard-pages` | On | Place inaccessible pages around allocations |
| `slot-randomization` | On | Randomize slot selection within size classes |
| `canaries` | On | Write canary bytes after allocations to detect overflows |
| `poison-on-free` | On | Fill freed memory with a poison pattern |
| `write-after-free-check` | On | Verify poison bytes on eviction from quarantine |
| `zero-on-free` | On | Zero memory after free (defense against information leaks) |

To build with all hardening (the default):

```bash
cargo build --release
```

To build with no hardening (passthrough performance baseline):

```bash
cargo build --release --no-default-features
```

To build with specific features:

```bash
cargo build --release --no-default-features --features quarantine,guard-pages
```

## Defense-in-depth model

The hardening features form layers that work together:

```
Allocation request
       |
       v
  [Slab allocator with per-CPU arenas]
       |
       +-- Slot randomization (unpredictable address)
       +-- Canary bytes (detect buffer overruns)
       +-- Out-of-band metadata (prevent metadata corruption)
       +-- Guard pages (hardware-enforced bounds)
       |
  On free:
       |
       +-- Double-free detection (metadata flag check)
       +-- Poison fill (detect use-after-free reads)
       +-- Quarantine (delay reuse, detect stale writes)
       +-- Zero-on-free (clear sensitive data)
```

Each layer provides value independently, but their combination makes exploitation significantly more difficult. An attacker must simultaneously bypass:

1. **Canary validation** to overflow without detection.
2. **Poison checking** to write after free without detection.
3. **Quarantine delays** to reclaim a specific address.
4. **Guard pages** to overflow beyond the allocation region.
5. **Out-of-band metadata** to corrupt heap management data.
6. **Slot randomization** to predict allocation addresses.

## Per-feature documentation

- [Use-After-Free Detection](./use-after-free.md) -- Quarantine and poison-based detection.
- [Heap Metadata Protection](./heap-metadata.md) -- Out-of-band metadata table.
- [Stale Pointer Mitigation](./stale-pointers.md) -- Delayed reuse through quarantine.
- [Guard Pages](./guard-pages.md) -- Hardware-enforced memory boundaries.
- [ARM Memory Tagging (MTE)](./mte.md) -- Hardware memory tagging on ARM64 (replaces canaries, poison, and zero-on-free).
