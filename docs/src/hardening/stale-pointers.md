# Stale Pointer Mitigation

A stale pointer is a pointer that once referred to a valid allocation but now points to memory that has been freed and potentially reallocated for a different purpose. Stale pointers are the root cause of use-after-free vulnerabilities: if the memory is reallocated, the stale pointer now aliases a live object, and reads/writes through it corrupt unrelated data.

compatmalloc mitigates stale pointer exploitation through **quarantine** -- a bounded queue that delays the reuse of freed memory.

## The quarantine

**Feature flag:** `quarantine`

When memory is freed, it is not immediately returned to the slab allocator's free list. Instead, it is pushed into a FIFO quarantine queue. The memory remains allocated (from the OS perspective) but is not available for new allocations. When the quarantine is full, the oldest entry is evicted and its slot is finally returned to the free list.

### How it helps

Without quarantine, a freed slot can be immediately reused by the next `malloc` of the same size class. An attacker can trigger this reliably by controlling the timing of allocations and frees. With quarantine:

1. **Temporal separation.** Hundreds of frees must occur before a specific slot is reused, making timing-based heap grooming attacks much harder.

2. **Write-after-free detection window.** While memory is in quarantine, it remains poisoned. If anything writes to it during this window, the poison check on eviction will detect the corruption.

3. **Reduced exploit reliability.** Even if an attacker can trigger a use-after-free, the window during which the freed memory is reused for a useful (to the attacker) object is dramatically reduced.

## Implementation

The quarantine (`hardening::quarantine::Quarantine`) is a fixed-capacity ring buffer with 256 slots per arena, protected by the arena lock.

```
                  head                        tail
                   |                            |
    [ evicted ] [ entry ] [ entry ] [ ... ] [ entry ] [ empty ] [ empty ]
                   |__________________________________|
                        queued (not yet reusable)
```

### Eviction policy

Entries are evicted when either condition is met:

1. **Byte budget exceeded.** The total bytes in quarantine plus the new entry would exceed `max_bytes`. Oldest entries are evicted until the budget is satisfied.
2. **Slot count exceeded.** The ring buffer is full (256 entries). The oldest entry is evicted.

The byte budget defaults to **4 MiB** (`DEFAULT_QUARANTINE_BYTES`) and can be configured via the `COMPATMALLOC_QUARANTINE_SIZE` environment variable.

### Eviction processing

When an entry is evicted from quarantine:

1. If `write-after-free-check` is enabled, the poison bytes are verified.
2. If `zero-on-free` is enabled, the memory is zeroed.
3. The slot is returned to the slab allocator's free list for reuse.

### Concurrency

The quarantine is embedded in each arena and protected by the arena lock. No separate quarantine lock is needed. A `free` call pushes one entry and potentially evicts older entries while the arena lock is held.

## Configuration

| Environment variable | Default | Description |
|---------------------|---------|-------------|
| `COMPATMALLOC_QUARANTINE_SIZE` | `4194304` (4 MiB) | Maximum bytes held in quarantine |

Setting the quarantine size to `0` effectively disables quarantine (entries are evicted immediately), though the feature flag must also be disabled to eliminate the overhead entirely.

Setting a larger quarantine size increases the delay before memory is reused, improving detection probability at the cost of higher memory usage.

## Tradeoffs

| Benefit | Cost |
|---------|------|
| Delays memory reuse, breaking heap grooming attacks | Increased resident memory (up to `quarantine_size` bytes held in reserve) |
| Enables write-after-free detection during quarantine window | One mutex acquisition per `free` call |
| Makes exploit timing unreliable | Slight increase in `free` latency |
