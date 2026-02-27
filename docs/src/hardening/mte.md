# ARM Memory Tagging (MTE)

On ARM64 processors with Memory Tagging Extension (ARMv8.5-A+), compatmalloc uses hardware memory tagging to replace several software hardening mechanisms with zero-cost hardware enforcement.

## How it works

MTE assigns a 4-bit tag (values 1-15) to each 16-byte memory granule. Every pointer also carries a tag in its top byte. On every memory access, the CPU checks that the pointer tag matches the memory tag — a mismatch triggers a synchronous fault.

compatmalloc uses MTE as follows:

- **On malloc**: the slot is tagged with a random hardware tag via the `IRG` (Insert Random Tag) instruction. The returned pointer carries this tag.
- **On free**: the slot is re-tagged with a different random tag via `tag_freed`. Any dangling pointers still carrying the old tag will fault on access.

## Runtime detection

MTE support is always compiled on `aarch64` targets. At startup, compatmalloc checks for MTE hardware via `getauxval(AT_HWCAP2)` and enables it in synchronous mode via `prctl(PR_SET_TAGGED_ADDR_CTRL)`. If MTE is not available, the allocator falls back to software hardening with no overhead from the detection check.

Slab backing memory is mapped with `PROT_MTE` when MTE is available to enable tag storage.

## What MTE replaces

When MTE is active, the following software mechanisms are skipped:

| Software mechanism | What it does | MTE equivalent |
|-------------------|-------------|----------------|
| Canary write (malloc) | Fills gap bytes with checksum-derived pattern | Hardware tag covers the entire slot |
| Canary check (free) | Verifies gap bytes are uncorrupted | Tag mismatch faults on any out-of-bounds access |
| Poison fill (free) | Fills freed memory with 0xCD pattern | Re-tagging prevents access to freed memory |
| Zero-on-free | Zeros freed memory to prevent info leak | Re-tagging prevents reads of freed memory |

The following mechanisms are **kept** with MTE because they are orthogonal:

| Mechanism | Why it stays |
|-----------|-------------|
| Quarantine | Delays slot reuse; MTE re-tagging detects access, but quarantine makes exploitation harder even if the 1/15 tag collision occurs |
| Guard pages | Protects against large overflows at page boundaries; MTE operates at 16-byte granularity |
| Slot randomization | Reduces heap spray predictability; orthogonal to tag-based detection |
| Double-free detection | Atomic CAS flag (`try_mark_freed`) runs before any MTE operations; MTE is not involved |
| Metadata integrity check | Checksum verification on out-of-band metadata; independent of MTE |

## Coverage comparison

| Threat | Software hardening | MTE |
|--------|-------------------|-----|
| Heap buffer overflow | Canary detects on free | Faults immediately on access |
| Heap buffer underflow | Front canary detects on free | Faults immediately on access |
| Use-after-free read | Poison corrupts data; zero-on-free clears it | Faults immediately (freed memory re-tagged) |
| Use-after-free write | Poison check detects on quarantine eviction | Faults immediately |
| Double free | Atomic CAS flag aborts immediately | Atomic CAS flag aborts immediately (same mechanism) |
| Info leak (freed data) | Zero-on-free clears freed slots | Re-tagging prevents reads (data not cleared) |

MTE provides strictly better detection timing for overflow, underflow, and use-after-free: faults occur at the moment of the invalid access rather than on the next `free()` or quarantine eviction.

## Trade-offs

**Probabilistic detection**: MTE uses 15 possible tag values (4 bits, excluding tag 0). When a slot is freed and re-tagged, there is a 1/15 (~6.7%) chance the new tag matches the old tag, which would not detect a stale access. Software canaries are deterministic but only checked at free time.

**No data clearing**: MTE prevents access to freed memory but does not zero or poison the contents. If the 1/15 tag collision occurs, stale data could be read. Software zero-on-free eliminates this possibility entirely.

**Hardware requirement**: MTE requires ARMv8.5-A or later with OS kernel support. Compatible Linux platforms include AWS Graviton 3+ and Android devices with Pixel 8+ (or equivalent Armv9 SoCs). Apple Silicon has the hardware capability but macOS does not currently expose MTE to userspace. On hardware without MTE, the software fallback provides equivalent coverage at higher cost.

## Performance impact

MTE eliminates the per-operation cost of canary writes, canary checks, poison fills, and zero-on-free. On MTE-capable hardware, this removes the dominant per-allocation overhead sources while maintaining equivalent or better security coverage.
