# Beat glibc: Deferred Verification Architecture

## Current State
- 64B malloc+free: 26.6ns (glibc: 9.3ns, 2.86x slower)
- Single-thread throughput: 35.35 Mops/s (glibc: 97.39 Mops/s)

## Target
- Match or beat glibc (<9.3ns) while maintaining security hardening

## Core Architecture: Deferred Verification

Move ALL expensive security operations from per-operation hot path to batch-flush cold path.

### Hot path (per malloc/free):
- malloc: TLS access → cache pop → write 1 u64 security token → return
- free: page_map lookup → atomic CAS double-free check → cache push → return

### Cold path (batch flush, every ~64 ops):
- Verify security tokens for all 64 slots
- Poison/zero all 64 slots
- Check canaries for all 64 slots
- Push to quarantine

### Key innovations:
1. **Unified security token**: Single non-invertible u64 replaces separate checksum + canary
2. **Atomic double-free**: CAS on flags field, no lock needed
3. **Batch amortization**: 30+ cycles of security work / 64 ops = <0.5 cycles per op

## Implementation Phases

### Phase 1: Foundation fixes
- page_size() branch elimination
- Quarantine bitmask
- Seed slot RNG from canary secret
- pub(crate) canary::secret()

### Phase 2: Security model
- Atomic CAS double-free detection
- Non-invertible canary derivation
- Separate checksum from canary value

### Phase 3: Deferred verification (big win)
- Move poison/zero to batch-flush
- Move checksum verify to batch-flush
- Move canary check to batch-flush
- Global fork flag optimization

### Phase 4: Hot path restructuring
- Split try_cache_alloc fast/cold
- Scale thread cache by size class
- Slab creation outside lock

### Phase 5: Machine patterns
- u64 canary write/check (not byte-by-byte)
- Prefetch page map L2
- Zero-copy thread cache recycling
