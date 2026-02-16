# Use-After-Free Detection

Use-after-free (UAF) is one of the most exploited memory safety vulnerabilities. It occurs when a program continues to access memory through a pointer after that memory has been freed. compatmalloc employs two complementary techniques to detect UAF: **poison filling** and **quarantine-based write detection**.

## Poison on free

**Feature flag:** `poison-on-free`

When memory is freed, the entire allocation is overwritten with a poison byte pattern (`0xFE`). This provides two benefits:

1. **Deterministic crash on read-after-free.** Programs that read freed memory will encounter the poison pattern instead of stale data. Dereferencing a pointer value of `0xFEFEFEFEFEFEFEFE` on x86_64 will typically cause a segfault, turning a silent data corruption bug into a crash.

2. **Information leak prevention.** Sensitive data (passwords, keys, session tokens) is overwritten immediately on free, reducing the window during which it can be extracted from the heap.

### Implementation

The poison fill is performed by `hardening::poison::poison_region`, which calls `core::ptr::write_bytes` with the poison byte (`0xFE`, defined in `util::POISON_BYTE`). The operation is a simple `memset` and adds minimal overhead.

## Write-after-free detection

**Feature flag:** `write-after-free-check`

When an allocation is evicted from quarantine (see [Stale Pointer Mitigation](./stale-pointers.md)), the allocator checks whether the poison bytes are still intact. If any byte has been modified, it indicates that something wrote to the memory after it was freed -- a write-after-free condition.

### Detection flow

```
free(ptr)
   |
   +-- Poison fill: memset(ptr, 0xFE, size)
   +-- Mark as freed in metadata table
   +-- Push into quarantine
   |
   ... time passes, quarantine fills up ...
   |
   Quarantine eviction:
   +-- Check poison: are all bytes still 0xFE?
   |     |
   |     +-- YES: no write-after-free, safe to reuse
   |     +-- NO:  write-after-free detected, abort
   |
   +-- Actually recycle the slot
```

### Poison checking implementation

The poison check (`hardening::poison::check_poison`) reads memory in 8-byte (`u64`) chunks for performance, comparing against the expected pattern `0xFEFEFEFEFEFEFEFE`. Remaining bytes are checked individually. This makes the check fast even for large allocations.

## Zero on free

**Feature flag:** `zero-on-free`

When enabled alongside `poison-on-free`, memory is zeroed after the poison check passes (or unconditionally if poison checking is disabled). This ensures that no sensitive data remains in the allocation even after it leaves quarantine.

The zeroing happens just before the slot is returned to the free pool:

```
Quarantine eviction:
   +-- Check poison (if enabled)
   +-- Zero fill: memset(ptr, 0x00, size)
   +-- Return slot to slab free list
```

## Double-free detection

The out-of-band metadata table tracks whether each allocation has been freed via a `FLAG_FREED` bit in the `AllocationMeta::flags` field. When `free` is called:

1. The metadata for the pointer is looked up.
2. If `is_freed()` returns `true`, the allocator writes a diagnostic message to stderr and calls `abort()`.
3. Otherwise, the freed flag is set via `mark_freed()`.

This detection is more reliable than glibc's inline freelist checks because the metadata is stored in a separate memory region that cannot be corrupted by a heap buffer overflow.
