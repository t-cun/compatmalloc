use crate::allocator::passthrough;
use crate::init::{self, STATE_READY};
use core::ffi::c_void;
use core::ptr;

/// Dispatch macro: check init state and route to hardened or passthrough.
/// Hot path: single branch on STATE_READY (most common).
/// Cold path: slow_dispatch handles UNINIT and DISABLED cases.
macro_rules! dispatch {
    ($hardened_fn:expr, $passthrough_fn:expr) => {{
        if init::state() == STATE_READY {
            $hardened_fn
        } else {
            #[cold]
            #[inline(never)]
            unsafe fn slow_init() {
                init::ensure_initialized();
            }
            slow_init();
            if init::state() == STATE_READY {
                $hardened_fn
            } else {
                $passthrough_fn
            }
        }
    }};
}

// ============================================================================
// Standard C allocator API
// ============================================================================

/// # Safety
/// Standard C malloc semantics apply.
#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    dispatch!(
        init::allocator().malloc(size) as *mut c_void,
        passthrough::malloc(size) as *mut c_void
    )
}

/// # Safety
/// `ptr` must be null or previously returned by an allocation function.
#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    dispatch!(
        init::allocator().free(ptr as *mut u8),
        passthrough::free(ptr as *mut u8)
    );
}

/// # Safety
/// `ptr` must be null or previously returned by an allocation function.
#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    dispatch!(
        init::allocator().realloc(ptr as *mut u8, size) as *mut c_void,
        passthrough::realloc(ptr as *mut u8, size) as *mut c_void
    )
}

/// # Safety
/// Standard C calloc semantics apply.
#[no_mangle]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    dispatch!(
        init::allocator().calloc(nmemb, size) as *mut c_void,
        passthrough::calloc(nmemb, size) as *mut c_void
    )
}

// ============================================================================
// POSIX alignment APIs
// ============================================================================

/// # Safety
/// `memptr` must be a valid non-null pointer. Standard POSIX semantics apply.
#[no_mangle]
pub unsafe extern "C" fn posix_memalign(
    memptr: *mut *mut c_void,
    alignment: usize,
    size: usize,
) -> libc::c_int {
    if memptr.is_null() {
        return libc::EINVAL;
    }

    // alignment must be a power of 2 and a multiple of sizeof(void*)
    if !alignment.is_power_of_two() || alignment < core::mem::size_of::<*mut c_void>() {
        return libc::EINVAL;
    }

    let ptr = dispatch!(
        init::allocator().memalign(alignment, size) as *mut c_void,
        passthrough::memalign(alignment, size) as *mut c_void
    );

    if ptr.is_null() {
        return libc::ENOMEM;
    }

    *memptr = ptr;
    0
}

/// # Safety
/// Standard C11 aligned_alloc semantics apply.
#[no_mangle]
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    // C11: size must be a multiple of alignment
    if !alignment.is_power_of_two() || (!size.is_multiple_of(alignment) && size != 0) {
        *libc::__errno_location() = libc::EINVAL;
        return ptr::null_mut();
    }

    dispatch!(
        init::allocator().memalign(alignment, size) as *mut c_void,
        passthrough::memalign(alignment, size) as *mut c_void
    )
}

/// # Safety
/// Standard memalign semantics apply.
#[no_mangle]
pub unsafe extern "C" fn memalign(alignment: usize, size: usize) -> *mut c_void {
    dispatch!(
        init::allocator().memalign(alignment, size) as *mut c_void,
        passthrough::memalign(alignment, size) as *mut c_void
    )
}

/// # Safety
/// Standard valloc semantics apply.
#[no_mangle]
pub unsafe extern "C" fn valloc(size: usize) -> *mut c_void {
    let ps = crate::util::page_size();
    dispatch!(
        init::allocator().memalign(ps, size) as *mut c_void,
        passthrough::memalign(ps, size) as *mut c_void
    )
}

/// # Safety
/// Standard pvalloc semantics apply.
#[no_mangle]
pub unsafe extern "C" fn pvalloc(size: usize) -> *mut c_void {
    let ps = crate::util::page_size();
    let rounded = crate::util::align_up(size, ps);
    dispatch!(
        init::allocator().memalign(ps, rounded) as *mut c_void,
        passthrough::memalign(ps, rounded) as *mut c_void
    )
}

// ============================================================================
// GNU extensions
// ============================================================================

/// # Safety
/// `ptr` must be null or a valid allocation pointer.
#[no_mangle]
pub unsafe extern "C" fn malloc_usable_size(ptr: *mut c_void) -> usize {
    if ptr.is_null() {
        return 0;
    }
    dispatch!(
        init::allocator().usable_size(ptr as *mut u8),
        passthrough::malloc_usable_size(ptr as *mut u8)
    )
}

/// mallopt: accept but ignore options for compatibility.
///
/// # Safety
/// No special requirements; this is a no-op stub.
#[no_mangle]
pub unsafe extern "C" fn mallopt(_param: libc::c_int, _value: libc::c_int) -> libc::c_int {
    // Return 1 (success) but don't actually do anything
    1
}

/// mallinfo: return zeroed struct for compatibility.
///
/// # Safety
/// No special requirements; returns a zeroed struct.
#[no_mangle]
pub unsafe extern "C" fn mallinfo() -> libc::mallinfo {
    core::mem::zeroed()
}

/// mallinfo2: return zeroed struct for compatibility.
///
/// # Safety
/// No special requirements; returns a zeroed struct.
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn mallinfo2() -> libc::mallinfo2 {
    core::mem::zeroed()
}

// ============================================================================
// Integrity check API
// ============================================================================

/// Scan all arenas and verify integrity of all allocated slots.
/// Returns 0 on success, or the number of errors found on corruption.
///
/// # Safety
/// Safe to call at any time; handles uninitialized state gracefully.
#[no_mangle]
pub unsafe extern "C" fn compatmalloc_check_integrity() -> libc::c_int {
    if init::state() != STATE_READY {
        return 0;
    }
    let result = init::allocator().check_integrity();
    result.errors_found as libc::c_int
}
