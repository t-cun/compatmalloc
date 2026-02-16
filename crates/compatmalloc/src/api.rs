use crate::allocator::passthrough;
use crate::init::{self, STATE_DISABLED, STATE_READY};
use core::ffi::c_void;
use core::ptr;

/// Dispatch macro: check init state and route to hardened or passthrough.
macro_rules! dispatch {
    ($hardened_fn:expr, $passthrough_fn:expr) => {{
        match init::state() {
            STATE_READY => $hardened_fn,
            STATE_DISABLED => $passthrough_fn,
            _ => {
                init::ensure_initialized();
                match init::state() {
                    STATE_READY => $hardened_fn,
                    _ => $passthrough_fn,
                }
            }
        }
    }};
}

// ============================================================================
// Standard C allocator API
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    dispatch!(
        init::allocator().malloc(size) as *mut c_void,
        passthrough::malloc(size) as *mut c_void
    )
}

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

#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    dispatch!(
        init::allocator().realloc(ptr as *mut u8, size) as *mut c_void,
        passthrough::realloc(ptr as *mut u8, size) as *mut c_void
    )
}

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

#[no_mangle]
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    // C11: size must be a multiple of alignment
    if !alignment.is_power_of_two() || (size % alignment != 0 && size != 0) {
        *libc::__errno_location() = libc::EINVAL;
        return ptr::null_mut();
    }

    dispatch!(
        init::allocator().memalign(alignment, size) as *mut c_void,
        passthrough::memalign(alignment, size) as *mut c_void
    )
}

#[no_mangle]
pub unsafe extern "C" fn memalign(alignment: usize, size: usize) -> *mut c_void {
    dispatch!(
        init::allocator().memalign(alignment, size) as *mut c_void,
        passthrough::memalign(alignment, size) as *mut c_void
    )
}

#[no_mangle]
pub unsafe extern "C" fn valloc(size: usize) -> *mut c_void {
    let page_size = crate::util::PAGE_SIZE;
    dispatch!(
        init::allocator().memalign(page_size, size) as *mut c_void,
        passthrough::memalign(page_size, size) as *mut c_void
    )
}

#[no_mangle]
pub unsafe extern "C" fn pvalloc(size: usize) -> *mut c_void {
    let page_size = crate::util::PAGE_SIZE;
    let rounded = crate::util::align_up(size, page_size);
    dispatch!(
        init::allocator().memalign(page_size, rounded) as *mut c_void,
        passthrough::memalign(page_size, rounded) as *mut c_void
    )
}

// ============================================================================
// GNU extensions
// ============================================================================

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
#[no_mangle]
pub unsafe extern "C" fn mallopt(_param: libc::c_int, _value: libc::c_int) -> libc::c_int {
    // Return 1 (success) but don't actually do anything
    1
}

/// mallinfo: return zeroed struct for compatibility.
#[no_mangle]
pub unsafe extern "C" fn mallinfo() -> libc::mallinfo {
    core::mem::zeroed()
}

/// mallinfo2: return zeroed struct for compatibility.
#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn mallinfo2() -> libc::mallinfo2 {
    core::mem::zeroed()
}
