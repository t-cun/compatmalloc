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

/// # Safety
/// Must only be called during library initialization.
pub unsafe fn compatmalloc_init() {
    match INIT_STATE.compare_exchange(UNINIT, INITIALIZING, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {}
        Err(INITIALIZING) => {
            // Bounded spin-wait with exponential backoff + yield fallback.
            let mut spins = 0u32;
            while INIT_STATE.load(Ordering::Acquire) == INITIALIZING {
                if spins < 100 {
                    for _ in 0..(1 << spins.min(6)) {
                        core::hint::spin_loop();
                    }
                } else {
                    libc::sched_yield();
                }
                spins = spins.saturating_add(1);
            }
            return;
        }
        Err(_) => return,
    }

    // Initialize page size from OS before anything else
    crate::util::init_page_size();

    // Resolve real libc functions first (needed for passthrough and bootstrap)
    passthrough::resolve_real_functions();

    // Read config from env vars
    config::read_config();

    // Check kill-switch
    if config::is_disabled() {
        INIT_STATE.store(DISABLED, Ordering::Release);
        return;
    }

    // Initialize canary secret from getrandom(2) -- used for canaries and
    // metadata integrity checksums
    crate::hardening::canary::init_canary_secret();

    // Try to enable ARM64 MTE if available
    #[cfg(feature = "mte")]
    {
        crate::platform::mte::init();
    }

    // Initialize the hardened allocator
    if !(*ALLOCATOR.0.get()).init() {
        INIT_STATE.store(DISABLED, Ordering::Release);
        return;
    }

    // Initialize pthread-based TLS for fast thread cache access.
    // Must happen after allocator init (uses passthrough for any internal allocs)
    // but before READY (so hot path can use it).
    crate::allocator::thread_cache::init_tls();

    // Register fork safety handlers
    crate::hardening::fork::register_atfork();

    INIT_STATE.store(READY, Ordering::Release);
}

/// # Safety
/// Safe to call from any context; handles concurrent init.
#[cold]
#[inline(never)]
pub unsafe fn ensure_initialized() {
    compatmalloc_init();
}

/// # Safety
/// Must only be called after initialization is complete.
#[inline(always)]
pub unsafe fn allocator() -> &'static HardenedAllocator {
    &*ALLOCATOR.0.get()
}

/// Check init state. Uses Acquire ordering to pair with the Release store
/// at end of init, ensuring all init side-effects (page map, canary secret,
/// config, TLS) are visible to any thread that observes READY/DISABLED.
/// On x86 this compiles to a plain `mov` (zero cost); on ARM64 it emits
/// `ldar` which is required for correctness.
#[inline(always)]
pub fn state() -> u8 {
    INIT_STATE.load(Ordering::Acquire)
}

pub const STATE_READY: u8 = READY;
pub const STATE_DISABLED: u8 = DISABLED;
