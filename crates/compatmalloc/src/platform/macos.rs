use core::ptr;

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

pub unsafe fn unmap(ptr: *mut u8, size: usize) {
    libc::munmap(ptr as *mut libc::c_void, size);
}

pub unsafe fn protect_none(ptr: *mut u8, size: usize) {
    libc::mprotect(ptr as *mut libc::c_void, size, libc::PROT_NONE);
}

pub unsafe fn protect_read_write(ptr: *mut u8, size: usize) {
    libc::mprotect(
        ptr as *mut libc::c_void,
        size,
        libc::PROT_READ | libc::PROT_WRITE,
    );
}

pub unsafe fn advise_free(ptr: *mut u8, size: usize) {
    libc::madvise(ptr as *mut libc::c_void, size, libc::MADV_FREE);
}

pub fn num_cpus() -> usize {
    unsafe {
        let n = libc::sysconf(libc::_SC_NPROCESSORS_ONLN);
        if n < 1 { 1 } else { n as usize }
    }
}

#[inline]
pub fn thread_id() -> usize {
    unsafe {
        let mut tid: u64 = 0;
        libc::pthread_threadid_np(libc::pthread_self(), &mut tid);
        tid as usize
    }
}
