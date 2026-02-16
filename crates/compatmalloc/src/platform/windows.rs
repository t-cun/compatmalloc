use core::ptr;

// Windows stubs - will be fully implemented in Phase 6
// For now, provide the interface so the crate compiles on Windows

pub unsafe fn map_anonymous(_size: usize) -> *mut u8 {
    ptr::null_mut() // TODO: VirtualAlloc
}

pub unsafe fn unmap(_ptr: *mut u8, _size: usize) {
    // TODO: VirtualFree
}

pub unsafe fn protect_none(_ptr: *mut u8, _size: usize) {
    // TODO: VirtualProtect PAGE_NOACCESS
}

pub unsafe fn protect_read_write(_ptr: *mut u8, _size: usize) {
    // TODO: VirtualProtect PAGE_READWRITE
}

pub unsafe fn advise_free(_ptr: *mut u8, _size: usize) {
    // TODO: VirtualAlloc MEM_RESET
}

pub fn num_cpus() -> usize {
    1 // TODO: GetSystemInfo
}

#[inline]
pub fn thread_id() -> usize {
    0 // TODO: GetCurrentThreadId
}
