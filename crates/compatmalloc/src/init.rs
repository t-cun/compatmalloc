use crate::allocator::passthrough;
use crate::allocator::HardenedAllocator;
use crate::config;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};

const UNINIT: u8 = 0;
const INITIALIZING: u8 = 1;
const READY: u8 = 2;
const DISABLED: u8 = 3;

pub static INIT_STATE: AtomicU8 = AtomicU8::new(UNINIT);

struct AllocatorHolder(UnsafeCell<HardenedAllocator>);
unsafe impl Sync for AllocatorHolder {}

static ALLOCATOR: AllocatorHolder = AllocatorHolder(UnsafeCell::new(HardenedAllocator::new()));

/// Library constructor -- called before main().
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static CTOR: unsafe extern "C" fn() = {
    unsafe extern "C" fn init() {
        compatmalloc_init();
    }
    init
};

pub unsafe fn compatmalloc_init() {
    match INIT_STATE.compare_exchange(UNINIT, INITIALIZING, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {}
        Err(INITIALIZING) => {
            while INIT_STATE.load(Ordering::Acquire) == INITIALIZING {
                core::hint::spin_loop();
            }
            return;
        }
        Err(_) => return,
    }

    // Resolve real libc functions first (needed for passthrough and bootstrap)
    passthrough::resolve_real_functions();

    // Read config from env vars
    config::read_config();

    // Check kill-switch
    if config::is_disabled() {
        INIT_STATE.store(DISABLED, Ordering::Release);
        return;
    }

    // Initialize the hardened allocator
    if !(*ALLOCATOR.0.get()).init() {
        INIT_STATE.store(DISABLED, Ordering::Release);
        return;
    }

    INIT_STATE.store(READY, Ordering::Release);
}

#[cold]
#[inline(never)]
pub unsafe fn ensure_initialized() {
    compatmalloc_init();
}

#[inline(always)]
pub unsafe fn allocator() -> &'static HardenedAllocator {
    &*ALLOCATOR.0.get()
}

#[inline(always)]
pub fn state() -> u8 {
    INIT_STATE.load(Ordering::Acquire)
}

pub const STATE_READY: u8 = READY;
pub const STATE_DISABLED: u8 = DISABLED;
