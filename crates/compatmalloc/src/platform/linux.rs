use core::ptr;

/// Map anonymous read-write memory.
///
/// # Safety
/// `size` must be page-aligned and non-zero.
pub unsafe fn map_anonymous(size: usize) -> *mut u8 {
    let result = libc::mmap(
        ptr::null_mut(),
        size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if result == libc::MAP_FAILED {
        ptr::null_mut()
    } else {
        result as *mut u8
    }
}

/// Unmap memory.
///
/// # Safety
/// `ptr` must have been returned by `map_anonymous` with the same `size`.
pub unsafe fn unmap(ptr: *mut u8, size: usize) {
    libc::munmap(ptr as *mut libc::c_void, size);
}

/// Mark memory as inaccessible (guard page).
///
/// # Safety
/// Region must be valid and page-aligned.
#[allow(dead_code)]
pub unsafe fn protect_none(ptr: *mut u8, size: usize) {
    libc::mprotect(ptr as *mut libc::c_void, size, libc::PROT_NONE);
}

/// Mark memory as read-write.
///
/// # Safety
/// Region must be valid and page-aligned.
#[allow(dead_code)]
pub unsafe fn protect_read_write(ptr: *mut u8, size: usize) {
    libc::mprotect(
        ptr as *mut libc::c_void,
        size,
        libc::PROT_READ | libc::PROT_WRITE,
    );
}

/// Advise kernel that pages can be reclaimed.
/// On Linux, MADV_DONTNEED guarantees zero-filled pages on next access.
///
/// # Safety
/// Region must be valid and page-aligned.
pub unsafe fn advise_free(ptr: *mut u8, size: usize) {
    let ret = libc::madvise(ptr as *mut libc::c_void, size, libc::MADV_DONTNEED);
    debug_assert!(ret == 0, "madvise(MADV_DONTNEED) failed");
}

/// Get the number of online CPUs.
pub fn num_cpus() -> usize {
    unsafe {
        let n = libc::sysconf(libc::_SC_NPROCESSORS_ONLN);
        if n < 1 {
            1
        } else {
            n as usize
        }
    }
}

/// Get a cheap thread identifier for arena affinity.
/// Cached in TLS to avoid a syscall on every allocation.
#[inline]
pub fn thread_id() -> usize {
    use std::cell::Cell;

    thread_local! {
        static CACHED_TID: Cell<usize> = const { Cell::new(0) };
    }

    CACHED_TID.with(|tid| {
        let cached = tid.get();
        if cached != 0 {
            return cached;
        }
        let new_tid = unsafe { libc::syscall(libc::SYS_gettid) as usize };
        tid.set(new_tid);
        new_tid
    })
}
