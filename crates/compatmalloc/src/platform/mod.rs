#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as sys;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos as sys;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows as sys;

/// Map anonymous memory. Returns null on failure.
///
/// # Safety
/// Caller must ensure `size` is page-aligned and non-zero.
#[inline]
pub unsafe fn map_anonymous(size: usize) -> *mut u8 {
    sys::map_anonymous(size)
}

/// Unmap previously mapped memory.
///
/// # Safety
/// `ptr` must have been returned by `map_anonymous` and `size` must match.
#[inline]
pub unsafe fn unmap(ptr: *mut u8, size: usize) {
    sys::unmap(ptr, size);
}

/// Protect a memory region as inaccessible (guard page).
///
/// # Safety
/// `ptr` and `size` must refer to a valid mapped region and be page-aligned.
#[inline]
pub unsafe fn protect_none(ptr: *mut u8, size: usize) {
    sys::protect_none(ptr, size);
}

/// Mark memory as read-write.
///
/// # Safety
/// `ptr` and `size` must refer to a valid mapped region and be page-aligned.
#[inline]
pub unsafe fn protect_read_write(ptr: *mut u8, size: usize) {
    sys::protect_read_write(ptr, size);
}

/// Advise the kernel that the memory range is no longer needed.
/// The kernel may reclaim the physical pages.
///
/// # Safety
/// `ptr` and `size` must refer to a valid mapped region and be page-aligned.
#[inline]
pub unsafe fn advise_free(ptr: *mut u8, size: usize) {
    sys::advise_free(ptr, size);
}

/// Get the number of online CPUs.
pub fn num_cpus() -> usize {
    sys::num_cpus()
}

/// Get a cheap thread-local identifier for arena selection.
#[inline]
pub fn thread_id() -> usize {
    sys::thread_id()
}

/// Get a fast, non-cryptographic random u64.
/// Falls back to address-space randomization if no better source.
pub fn fast_random_u64() -> u64 {
    // Use stack address as a simple entropy source mixed with a counter
    static COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let stack_addr = &count as *const _ as u64;
    // Simple xorshift-style mixing
    let mut x = stack_addr.wrapping_mul(0x517cc1b727220a95).wrapping_add(count);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    x
}
