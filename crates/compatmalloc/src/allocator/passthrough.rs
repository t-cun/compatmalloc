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
///
/// # Safety
/// Must be called from single-threaded context during init.
pub unsafe fn resolve_real_functions() {
    let rtld_next = -1isize as *mut c_void; // RTLD_NEXT

    let m = libc::dlsym(rtld_next, c"malloc".as_ptr());
    if !m.is_null() {
        REAL_MALLOC.store(m as usize, Ordering::Release);
    }

    let f = libc::dlsym(rtld_next, c"free".as_ptr());
    if !f.is_null() {
        REAL_FREE.store(f as usize, Ordering::Release);
    }

    let r = libc::dlsym(rtld_next, c"realloc".as_ptr());
    if !r.is_null() {
        REAL_REALLOC.store(r as usize, Ordering::Release);
    }

    let c = libc::dlsym(rtld_next, c"calloc".as_ptr());
    if !c.is_null() {
        REAL_CALLOC.store(c as usize, Ordering::Release);
    }

    let pm = libc::dlsym(rtld_next, c"posix_memalign".as_ptr());
    if !pm.is_null() {
        REAL_POSIX_MEMALIGN.store(pm as usize, Ordering::Release);
    }

    let mu = libc::dlsym(rtld_next, c"malloc_usable_size".as_ptr());
    if !mu.is_null() {
        REAL_MALLOC_USABLE_SIZE.store(mu as usize, Ordering::Release);
    }
}

/// Lazily resolve a single libc function via dlsym(RTLD_NEXT).
/// Called on the cold path when eager init didn't populate the pointer
/// (e.g. musl where RTLD_NEXT may not resolve during .init_array).
///
/// Uses compare_exchange so concurrent callers converge on the same pointer.
/// Returns the resolved address, or 0 if dlsym returned NULL.
#[cold]
#[inline(never)]
unsafe fn lazy_resolve(slot: &AtomicUsize, name: &core::ffi::CStr) -> usize {
    let rtld_next = -1isize as *mut c_void; // RTLD_NEXT
    let ptr = libc::dlsym(rtld_next, name.as_ptr());
    if ptr.is_null() {
        return 0;
    }
    let val = ptr as usize;
    // CAS: if another thread resolved first, use their value.
    let _ = slot.compare_exchange(0, val, Ordering::Release, Ordering::Acquire);
    slot.load(Ordering::Acquire)
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
    (base..base + BOOTSTRAP_BUF_SIZE).contains(&p)
}

/// # Safety
/// Caller must ensure `size` is valid.
#[inline]
pub unsafe fn malloc(size: usize) -> *mut u8 {
    let mut f = REAL_MALLOC.load(Ordering::Acquire);
    if f == 0 {
        f = lazy_resolve(&REAL_MALLOC, c"malloc");
    }
    if f != 0 {
        let func: MallocFn = core::mem::transmute(f);
        func(size) as *mut u8
    } else {
        bootstrap_malloc(size)
    }
}

/// # Safety
/// `ptr` must be null or a valid allocation pointer.
#[inline]
pub unsafe fn free(ptr: *mut u8) {
    if ptr.is_null() || is_bootstrap_ptr(ptr) {
        return;
    }
    let mut f = REAL_FREE.load(Ordering::Acquire);
    if f == 0 {
        f = lazy_resolve(&REAL_FREE, c"free");
    }
    if f != 0 {
        let func: FreeFn = core::mem::transmute(f);
        func(ptr as *mut c_void);
    }
}

/// # Safety
/// `ptr` must be null or a valid allocation pointer.
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
    let mut f = REAL_REALLOC.load(Ordering::Acquire);
    if f == 0 {
        f = lazy_resolve(&REAL_REALLOC, c"realloc");
    }
    if f != 0 {
        let func: ReallocFn = core::mem::transmute(f);
        func(ptr as *mut c_void, size) as *mut u8
    } else {
        ptr::null_mut()
    }
}

/// # Safety
/// Caller must ensure `nmemb` and `size` are valid.
#[inline]
pub unsafe fn calloc(nmemb: usize, size: usize) -> *mut u8 {
    let mut f = REAL_CALLOC.load(Ordering::Acquire);
    if f == 0 {
        f = lazy_resolve(&REAL_CALLOC, c"calloc");
    }
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

/// # Safety
/// `alignment` must be a power of two.
#[inline]
pub unsafe fn memalign(alignment: usize, size: usize) -> *mut u8 {
    let mut f = REAL_POSIX_MEMALIGN.load(Ordering::Acquire);
    if f == 0 {
        f = lazy_resolve(&REAL_POSIX_MEMALIGN, c"posix_memalign");
    }
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

/// # Safety
/// `ptr` must be a valid allocation pointer.
#[inline]
pub unsafe fn malloc_usable_size(ptr: *mut u8) -> usize {
    let mut f = REAL_MALLOC_USABLE_SIZE.load(Ordering::Acquire);
    if f == 0 {
        f = lazy_resolve(&REAL_MALLOC_USABLE_SIZE, c"malloc_usable_size");
    }
    if f != 0 {
        let func: MallocUsableSizeFn = core::mem::transmute(f);
        func(ptr as *mut c_void)
    } else {
        0
    }
}
