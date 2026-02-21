#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as sys;

#[cfg(feature = "mte")]
pub mod mte;

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
#[allow(dead_code)]
#[inline]
pub unsafe fn protect_none(ptr: *mut u8, size: usize) {
    sys::protect_none(ptr, size);
}

/// Mark memory as read-write.
///
/// # Safety
/// `ptr` and `size` must refer to a valid mapped region and be page-aligned.
#[allow(dead_code)]
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
/// Uses thread-local xorshift64* state to avoid global atomic contention.
#[allow(dead_code)]
pub fn fast_random_u64() -> u64 {
    use core::cell::Cell;

    thread_local! {
        static RNG_STATE: Cell<u64> = const { Cell::new(0) };
    }

    // Try thread-local fast path
    let result = RNG_STATE.try_with(|state| {
        let mut s = state.get();
        if s == 0 {
            // Seed from stack address + thread id for uniqueness
            let stack_addr = &s as *const _ as u64;
            s = stack_addr
                .wrapping_mul(0x517cc1b727220a95)
                .wrapping_add(thread_id() as u64)
                | 1; // ensure non-zero
        }
        // xorshift64*
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        state.set(s);
        s.wrapping_mul(0x2545F4914F6CDD1D)
    });

    match result {
        Ok(val) => val,
        Err(_) => {
            // TLS not available (early init or thread destruction) -- fallback
            static COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
            let count = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            splitmix64(count.wrapping_add(0x9E3779B97F4A7C15))
        }
    }
}

/// splitmix64 finalizer -- good hash for sequential inputs.
#[inline(always)]
pub fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}
