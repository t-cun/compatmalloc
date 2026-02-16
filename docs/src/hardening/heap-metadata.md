# Heap Metadata Protection

Traditional allocators like glibc's ptmalloc2 store heap metadata (chunk sizes, freelist pointers) inline, immediately adjacent to user data. This design is efficient but means that a heap buffer overflow can corrupt the allocator's own bookkeeping, enabling powerful exploitation techniques like unlink attacks, fastbin corruption, and tcache poisoning.

compatmalloc eliminates this attack surface by storing all allocation metadata **out-of-band** in a separate memory region.

## Out-of-band metadata table

The metadata table (`hardening::metadata::MetadataTable`) is a hash table backed by its own `mmap` region, completely separate from the slab and large allocation regions. It maps pointer addresses to `AllocationMeta` structs:

```rust
pub struct AllocationMeta {
    pub requested_size: usize,  // The size the caller asked for
    pub canary_value: u64,      // Expected canary for overflow detection
    pub flags: u8,              // State flags (e.g., FLAG_FREED)
}
```

### Why this matters

With inline metadata, an attacker who can overflow a heap buffer by even a single byte may be able to:

- Modify the size of the next chunk, enabling overlapping allocations.
- Corrupt freelist pointers, redirecting allocations to attacker-controlled addresses.
- Forge fake chunks to confuse the allocator's validation checks.

With out-of-band metadata, none of these attacks work. The metadata lives in a different virtual memory region, so overflowing a user allocation cannot reach it.

## Implementation details

### Hash table design

The metadata table uses open addressing with linear probing:

- **Keys** are the pointer address cast to `usize`.
- **Initial capacity** is 16,384 entries.
- **Load factor threshold** is 75%. When exceeded, the table grows by 2x via a new `mmap` and full rehash.
- **Hash function** uses a multiplicative hash (`key * 0x9E3779B97F4A7C15`, the golden ratio constant) with a xor-shift mix for good distribution.
- **Deletion** uses backward-shift deletion (not tombstones) to maintain probe chain integrity.

### Concurrency

The table is protected by a raw mutex (`sync::RawMutex`, implemented via Linux `futex`). All operations (`insert`, `get`, `remove`, `mark_freed`) acquire the lock for their duration.

### Memory isolation

The table's backing memory is allocated via `mmap(MAP_PRIVATE | MAP_ANONYMOUS)`, placing it at an address chosen by the kernel. This address is independent of the slab and large allocation regions, providing spatial separation.

### Growth

When the load factor exceeds 75%, a new region of double the capacity is mapped, all entries are rehashed into it, and the old region is unmapped. This operation is performed under the lock to ensure consistency.

## Lookup on every free

Every call to `free` looks up the pointer in the metadata table to:

1. Check the `FLAG_FREED` bit for double-free detection.
2. Retrieve the `requested_size` for canary checking and poison filling.
3. Retrieve the `canary_value` for canary validation.

This adds a hash table lookup to every free operation, but the table is kept small relative to the number of live allocations, and the multiplicative hash provides good cache behavior.

## Tradeoffs

| Benefit | Cost |
|---------|------|
| Immune to heap metadata corruption attacks | Extra memory for the hash table (~25 bytes per live allocation) |
| Reliable double-free detection | Hash table lookup on `malloc`, `free`, and `realloc` |
| Canary and size tracking without inline headers | Mutex contention under heavy multi-threaded allocation |
