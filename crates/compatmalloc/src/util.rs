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

/// Runtime page size, initialized from sysconf(_SC_PAGESIZE) at startup.
/// Falls back to 4096 if not yet initialized.
/// Initialize to 4096 (the universal default) to eliminate the branch in page_size().
/// After init_page_size() runs, this holds the real value from sysconf.
static PAGE_SIZE_CACHED: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(4096);

/// Cached log2(page_size) for fast division-free page number computation.
/// Avoids ~35-cycle hardware `div` on every page_map lookup.
static PAGE_SHIFT_CACHED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(12);

/// Initialize the page size from the OS. Must be called once during init.
///
/// # Safety
/// Must be called from single-threaded context (init).
pub unsafe fn init_page_size() {
    let ps = libc::sysconf(libc::_SC_PAGESIZE);
    let ps = if ps > 0 { ps as usize } else { 4096 };
    PAGE_SIZE_CACHED.store(ps, core::sync::atomic::Ordering::Release);
    PAGE_SHIFT_CACHED.store(ps.trailing_zeros(), core::sync::atomic::Ordering::Release);
}

/// Get the system page size. Always returns a valid value (4096 default, real value after init).
/// Branchless: PAGE_SIZE_CACHED is initialized to 4096 so it's never zero.
#[inline(always)]
pub fn page_size() -> usize {
    PAGE_SIZE_CACHED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Get log2(page_size) for shift-based division. Returns 12 (for 4096) before init.
#[inline(always)]
pub fn page_shift() -> u32 {
    PAGE_SHIFT_CACHED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Threshold between small (slab) and large (mmap) allocations.
pub const LARGE_THRESHOLD: usize = 16384; // 16 KiB

/// Maximum number of arenas.
pub const MAX_ARENAS: usize = 32;

/// Default quarantine size in bytes.
pub const DEFAULT_QUARANTINE_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

/// Largest power of 2 that divides `x`. Returns x's lowest set bit.
/// E.g., 128 -> 128, 96 -> 32, 48 -> 16.
#[inline(always)]
pub const fn largest_pow2_dividing(x: usize) -> usize {
    if x == 0 {
        return 1;
    }
    x & x.wrapping_neg()
}

/// Poison byte written to freed memory.
pub const POISON_BYTE: u8 = 0xFE;

/// Byte used for junk-filling new allocations (debug).
pub const JUNK_BYTE: u8 = 0xCD;
