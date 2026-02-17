/// Passthrough allocator: delegates to the real system allocator.
///
/// Because our library exports `malloc`/`free` symbols, calling `libc::malloc`
/// from within our library would recurse back to us. We must use dlsym(RTLD_NEXT)
/// to find the real libc implementations.

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

type MallocFn = unsafe extern "C" fn(usize) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type ReallocFn = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
type CallocFn = unsafe extern "C" fn(usize, usize) -> *mut c_void;
type PosixMemalignFn = unsafe extern "C" fn(*mut *mut c_void, usize, usize) -> libc::c_int;
type MallocUsableSizeFn = unsafe extern "C" fn(*mut c_void) -> usize;

static REAL_MALLOC: AtomicUsize = AtomicUsize::new(0);
static REAL_FREE: AtomicUsize = AtomicUsize::new(0);
static REAL_REALLOC: AtomicUsize = AtomicUsize::new(0);
static REAL_CALLOC: AtomicUsize = AtomicUsize::new(0);
static REAL_POSIX_MEMALIGN: AtomicUsize = AtomicUsize::new(0);
static REAL_MALLOC_USABLE_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Resolve real libc functions via dlsym(RTLD_NEXT, ...).
/// Must be called once during init.
pub unsafe fn resolve_real_functions() {
    let rtld_next = -1isize as *mut c_void; // RTLD_NEXT

    let m = libc::dlsym(rtld_next, b"malloc\0".as_ptr() as *const _);
    if !m.is_null() {
        REAL_MALLOC.store(m as usize, Ordering::Release);
    }

    let f = libc::dlsym(rtld_next, b"free\0".as_ptr() as *const _);
    if !f.is_null() {
        REAL_FREE.store(f as usize, Ordering::Release);
    }

    let r = libc::dlsym(rtld_next, b"realloc\0".as_ptr() as *const _);
    if !r.is_null() {
        REAL_REALLOC.store(r as usize, Ordering::Release);
    }

    let c = libc::dlsym(rtld_next, b"calloc\0".as_ptr() as *const _);
    if !c.is_null() {
        REAL_CALLOC.store(c as usize, Ordering::Release);
    }

    let pm = libc::dlsym(rtld_next, b"posix_memalign\0".as_ptr() as *const _);
    if !pm.is_null() {
        REAL_POSIX_MEMALIGN.store(pm as usize, Ordering::Release);
    }

    let mu = libc::dlsym(rtld_next, b"malloc_usable_size\0".as_ptr() as *const _);
    if !mu.is_null() {
        REAL_MALLOC_USABLE_SIZE.store(mu as usize, Ordering::Release);
    }
}

/// Bootstrap malloc using mmap -- used before dlsym resolves the real malloc.
/// dlsym itself may call malloc, so we need a fallback that doesn't depend on libc malloc.
static BOOTSTRAP_BUF_USED: AtomicUsize = AtomicUsize::new(0);
const BOOTSTRAP_BUF_SIZE: usize = 65536;
static mut BOOTSTRAP_BUF: [u8; BOOTSTRAP_BUF_SIZE] = [0u8; BOOTSTRAP_BUF_SIZE];

unsafe fn bootstrap_malloc(size: usize) -> *mut u8 {
    let aligned_size = (size + 15) & !15;
    // CAS loop to avoid permanently advancing the counter past buffer size.
    loop {
        let offset = BOOTSTRAP_BUF_USED.load(Ordering::Relaxed);
        if offset + aligned_size > BOOTSTRAP_BUF_SIZE {
            return ptr::null_mut();
        }
        if BOOTSTRAP_BUF_USED
            .compare_exchange_weak(
                offset,
                offset + aligned_size,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            return core::ptr::addr_of_mut!(BOOTSTRAP_BUF)
                .cast::<u8>()
                .add(offset);
        }
    }
}

unsafe fn bootstrap_memalign(alignment: usize, size: usize) -> *mut u8 {
    // We need at most (alignment - 1) extra bytes to find an aligned offset.
    let extra = alignment - 1;
    let total = match size.checked_add(extra) {
        Some(t) => t,
        None => return ptr::null_mut(),
    };
    let aligned_total = (total + 15) & !15;
    // CAS loop to reserve space in the bootstrap buffer.
    loop {
        let offset = BOOTSTRAP_BUF_USED.load(Ordering::Relaxed);
        if offset + aligned_total > BOOTSTRAP_BUF_SIZE {
            return ptr::null_mut();
        }
        if BOOTSTRAP_BUF_USED
            .compare_exchange_weak(
                offset,
                offset + aligned_total,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            let base = core::ptr::addr_of_mut!(BOOTSTRAP_BUF)
                .cast::<u8>()
                .add(offset);
            // Align the pointer within the reserved region
            let aligned = ((base as usize + alignment - 1) & !(alignment - 1)) as *mut u8;
            return aligned;
        }
    }
}

unsafe fn is_bootstrap_ptr(ptr: *mut u8) -> bool {
    let base = core::ptr::addr_of!(BOOTSTRAP_BUF) as usize;
    let p = ptr as usize;
    p >= base && p < base + BOOTSTRAP_BUF_SIZE
}

#[inline]
pub unsafe fn malloc(size: usize) -> *mut u8 {
    let f = REAL_MALLOC.load(Ordering::Acquire);
    if f != 0 {
        let func: MallocFn = core::mem::transmute(f);
        func(size) as *mut u8
    } else {
        bootstrap_malloc(size)
    }
}

#[inline]
pub unsafe fn free(ptr: *mut u8) {
    if ptr.is_null() || is_bootstrap_ptr(ptr) {
        return;
    }
    let f = REAL_FREE.load(Ordering::Acquire);
    if f != 0 {
        let func: FreeFn = core::mem::transmute(f);
        func(ptr as *mut c_void);
    }
}

#[inline]
pub unsafe fn realloc(ptr: *mut u8, size: usize) -> *mut u8 {
    if ptr.is_null() {
        return malloc(size);
    }
    if is_bootstrap_ptr(ptr) {
        // Can't realloc bootstrap memory, allocate new and copy
        let new = malloc(size);
        if !new.is_null() {
            // Cap copy at the remaining bootstrap buffer from the old offset
            // to avoid reading past the original allocation.
            let base = core::ptr::addr_of!(BOOTSTRAP_BUF) as usize;
            let old_offset = ptr as usize - base;
            let max_old_size = BOOTSTRAP_BUF_SIZE - old_offset;
            let copy_size = size.min(max_old_size);
            ptr::copy_nonoverlapping(ptr, new, copy_size);
        }
        return new;
    }
    let f = REAL_REALLOC.load(Ordering::Acquire);
    if f != 0 {
        let func: ReallocFn = core::mem::transmute(f);
        func(ptr as *mut c_void, size) as *mut u8
    } else {
        ptr::null_mut()
    }
}

#[inline]
pub unsafe fn calloc(nmemb: usize, size: usize) -> *mut u8 {
    let f = REAL_CALLOC.load(Ordering::Acquire);
    if f != 0 {
        let func: CallocFn = core::mem::transmute(f);
        func(nmemb, size) as *mut u8
    } else {
        // Bootstrap calloc
        let total = match nmemb.checked_mul(size) {
            Some(t) => t,
            None => return ptr::null_mut(),
        };
        let p = bootstrap_malloc(total);
        if !p.is_null() {
            ptr::write_bytes(p, 0, total);
        }
        p
    }
}

#[inline]
pub unsafe fn memalign(alignment: usize, size: usize) -> *mut u8 {
    let f = REAL_POSIX_MEMALIGN.load(Ordering::Acquire);
    if f != 0 {
        let func: PosixMemalignFn = core::mem::transmute(f);
        let mut out: *mut c_void = ptr::null_mut();
        let ret = func(&mut out, alignment, size);
        if ret == 0 {
            out as *mut u8
        } else {
            ptr::null_mut()
        }
    } else {
        // Bootstrap: return properly aligned pointer from bootstrap buffer
        bootstrap_memalign(alignment, size)
    }
}

#[inline]
pub unsafe fn malloc_usable_size(ptr: *mut u8) -> usize {
    let f = REAL_MALLOC_USABLE_SIZE.load(Ordering::Acquire);
    if f != 0 {
        let func: MallocUsableSizeFn = core::mem::transmute(f);
        func(ptr as *mut c_void)
    } else {
        0
    }
}
