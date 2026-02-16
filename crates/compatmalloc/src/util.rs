/// Align `value` up to the next multiple of `align`.
/// `align` must be a power of two.
#[inline(always)]
pub const fn align_up(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

/// Align `value` down to the previous multiple of `align`.
/// `align` must be a power of two.
#[inline(always)]
pub const fn align_down(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    value & !(align - 1)
}

/// Check if `value` is aligned to `align`.
#[inline(always)]
pub const fn is_aligned(value: usize, align: usize) -> bool {
    value & (align - 1) == 0
}

/// Minimum alignment for all allocations (matches max_align_t on 64-bit).
pub const MIN_ALIGN: usize = 16;

/// Page size (4 KiB on most platforms).
pub const PAGE_SIZE: usize = 4096;

/// Threshold between small (slab) and large (mmap) allocations.
pub const LARGE_THRESHOLD: usize = 16384; // 16 KiB

/// Maximum number of arenas.
pub const MAX_ARENAS: usize = 32;

/// Default quarantine size in bytes.
pub const DEFAULT_QUARANTINE_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

/// Poison byte written to freed memory.
pub const POISON_BYTE: u8 = 0xFE;

/// Byte used for junk-filling new allocations (debug).
pub const JUNK_BYTE: u8 = 0xCD;
