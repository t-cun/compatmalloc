# Guard Pages

Guard pages are regions of virtual memory marked as inaccessible (`PROT_NONE`) that the allocator places around allocation regions. Any read or write that crosses the boundary of an allocation into a guard page triggers an immediate hardware fault (segfault), providing deterministic detection of buffer overflows and underflows.

## How guard pages work

**Feature flag:** `guard-pages`

When guard pages are enabled, the allocator inserts inaccessible pages at the boundaries of memory regions:

### Large allocations

Each large allocation (>16 KiB) gets its own `mmap` region with the following layout:

```
+-------------------+---------------------+-------------------+
|   Guard page      |    User data        |   Guard page      |
|   (PROT_NONE)     |    (PROT_READ |     |   (PROT_NONE)     |
|   4096 bytes      |     PROT_WRITE)     |   4096 bytes      |
+-------------------+---------------------+-------------------+
^                   ^                                         ^
|                   |                                         |
base           user_ptr                              base + total_size
```

A buffer overflow past the end of the user data hits the rear guard page and faults. A buffer underflow (writing before the allocation) hits the front guard page.

### Slab regions

Slab regions use the same pattern: guard pages are placed before and after the contiguous block of slots. This means that an overflow past the last slot in a slab, or an underflow before the first slot, will hit a guard page. However, overflows between adjacent slots within the same slab will not be caught by guard pages (canaries provide detection for those cases).

## Implementation

Guard pages are implemented using platform memory protection primitives:

- **Linux:** `mprotect(addr, PAGE_SIZE, PROT_NONE)` on the guard regions after mapping the full region with `mmap`.
- The guard pages consume virtual address space but no physical memory (the kernel does not back `PROT_NONE` pages with RAM).

The overhead functions are defined in `hardening::guard_pages`:

```rust
// Per slab region: one guard page before + one after
pub const fn slab_guard_overhead() -> usize {
    PAGE_SIZE * 2  // 8192 bytes when enabled
}

// Per large allocation: one guard page before + one after
pub const fn large_guard_overhead() -> usize {
    PAGE_SIZE * 2
}
```

When the `guard-pages` feature is disabled, these functions return `0` and no guard pages are mapped.

## What guard pages catch

| Scenario | Detected? |
|----------|-----------|
| Linear buffer overflow past end of large allocation | Yes -- hits rear guard page |
| Linear buffer underflow before large allocation | Yes -- hits front guard page |
| Overflow past the last slot in a slab | Yes -- hits rear guard page |
| Overflow between adjacent slots in same slab | No -- caught by canaries instead |
| Wild pointer write to an arbitrary address | Only if it happens to land on a guard page |

## Virtual memory cost

Guard pages consume virtual address space but not physical RAM. On 64-bit Linux, the virtual address space is 128 TiB, so the overhead is negligible. The per-region cost is:

- **Large allocations:** +8 KiB virtual per allocation (2 pages).
- **Slab regions:** +8 KiB virtual per slab (2 pages, amortized across all slots in the slab).

For a slab with 64 slots of 1024 bytes each (64 KiB data), the guard page overhead is 8 KiB / 64 KiB = 12.5% of virtual address space. For smaller size classes with more slots per slab, the overhead is proportionally lower.

## Interaction with other features

Guard pages complement the other hardening features:

- **Canaries** detect overflows within a slab (between adjacent slots) that guard pages cannot catch.
- **Poison filling** detects use-after-free, which guard pages do not address.
- **Out-of-band metadata** prevents corruption of allocator state, which guard pages alone cannot guarantee for within-slab overflows.

Together, these features provide comprehensive coverage: guard pages handle boundary overflows with hardware enforcement, canaries handle intra-slab overflows with software checks, and metadata isolation prevents allocator state corruption regardless of overflow direction.
