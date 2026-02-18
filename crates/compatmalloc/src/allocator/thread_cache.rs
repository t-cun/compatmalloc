//! Per-thread free list cache to eliminate arena lock on the fast path.
//!
//! Each thread maintains a small array of cached slots per size class.
//! - `malloc` fast path: pop from thread cache (no lock)
//! - `free` fast path: push to thread cache free buffer (no lock)
//! - When free buffer is full: flush batch to arena (amortized locking)
//! - When alloc cache is empty on malloc: batch-fill from arena
//!
//! TLS access uses `pthread_getspecific` instead of `thread_local!` because
//! shared libraries use the general-dynamic TLS model, which requires a PLT
//! call to `__tls_get_addr` (~25 cycles). `pthread_getspecific` for keys < 32
//! compiles to a direct `fs:` segment load on glibc (~5 cycles).

use core::sync::atomic::{AtomicI32, Ordering as AtomicOrdering};

use crate::slab::size_class::NUM_SIZE_CLASSES;

/// Maximum cached slots per size class (for allocation).
const CACHE_SIZE: usize = 64;

/// Maximum deferred free slots per size class.
const FREE_CACHE_SIZE: usize = 64;

/// A cached free slot: pointer + slab info for O(1) recycle.
/// Compact layout: 24 bytes (down from 40) for better cache utilization.
/// `cached_size` stores requested_size from the last allocation, enabling
/// same-size detection without touching slab metadata (saves a pointer chase).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CachedSlot {
    pub ptr: *mut u8,
    pub slab_ptr: *mut u8,
    pub slot_index: u16,
    pub arena_index: u8,
    pub _pad: u8,
    pub cached_size: u32,
}

/// Per-size-class cache: a small stack of free slots + deferred free buffer.
struct ClassCache {
    /// Allocation cache (pop from here on malloc)
    alloc_slots: [CachedSlot; CACHE_SIZE],
    alloc_count: usize,
    /// Deferred free buffer (push here on free, flush when full)
    free_slots: [CachedSlot; FREE_CACHE_SIZE],
    free_count: usize,
}

impl ClassCache {
    const fn new() -> Self {
        const EMPTY: CachedSlot = CachedSlot {
            ptr: core::ptr::null_mut(),
            slab_ptr: core::ptr::null_mut(),
            slot_index: 0,
            arena_index: 0,
            _pad: 0,
            cached_size: 0,
        };
        ClassCache {
            alloc_slots: [EMPTY; CACHE_SIZE],
            alloc_count: 0,
            free_slots: [EMPTY; FREE_CACHE_SIZE],
            free_count: 0,
        }
    }

    #[inline]
    fn push(&mut self, slot: CachedSlot) -> bool {
        if self.alloc_count < CACHE_SIZE {
            self.alloc_slots[self.alloc_count] = slot;
            self.alloc_count += 1;
            true
        } else {
            false
        }
    }

    #[inline]
    fn pop(&mut self) -> Option<CachedSlot> {
        if self.alloc_count > 0 {
            self.alloc_count -= 1;
            Some(self.alloc_slots[self.alloc_count])
        } else {
            None
        }
    }

    #[inline]
    fn push_free(&mut self, slot: CachedSlot) -> bool {
        if self.free_count < FREE_CACHE_SIZE {
            self.free_slots[self.free_count] = slot;
            self.free_count += 1;
            true
        } else {
            false
        }
    }

    /// Pop the most recent entry from the free buffer (LIFO).
    /// Used for direct recycling when alloc cache is empty.
    #[inline]
    fn pop_free(&mut self) -> Option<CachedSlot> {
        if self.free_count > 0 {
            self.free_count -= 1;
            Some(self.free_slots[self.free_count])
        } else {
            None
        }
    }

    #[inline]
    fn free_is_full(&self) -> bool {
        self.free_count >= FREE_CACHE_SIZE
    }

    /// Recycle entries from the free buffer to the alloc cache.
    /// Returns the number of entries remaining in the free buffer (for arena flush).
    /// Moves up to `max_recycle` entries from free to alloc. Remaining entries
    /// stay in the free buffer for later quarantine flush.
    #[inline]
    fn recycle_frees_to_alloc(&mut self, max_recycle: usize) -> usize {
        let available = self.free_count;
        if available == 0 {
            return 0;
        }
        let to_recycle = available
            .min(max_recycle)
            .min(CACHE_SIZE - self.alloc_count);
        if to_recycle == 0 {
            return available;
        }
        // Move the newest entries (end of free buffer) to alloc cache
        let start = available - to_recycle;
        for i in 0..to_recycle {
            self.alloc_slots[self.alloc_count] = self.free_slots[start + i];
            self.alloc_count += 1;
        }
        self.free_count = start;
        start // remaining in free buffer
    }
}

/// Thread-local cache for all size classes.
pub struct ThreadCache {
    caches: [ClassCache; NUM_SIZE_CLASSES],
}

impl ThreadCache {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        const EMPTY: ClassCache = ClassCache::new();
        ThreadCache {
            caches: [EMPTY; NUM_SIZE_CLASSES],
        }
    }

    /// Try to pop a cached pointer for the given size class.
    #[inline]
    pub fn pop(&mut self, class_index: usize) -> Option<CachedSlot> {
        self.caches[class_index].pop()
    }

    /// Try to push a freed slot into the alloc cache. Returns false if full.
    #[inline]
    pub fn push(&mut self, class_index: usize, slot: CachedSlot) -> bool {
        self.caches[class_index].push(slot)
    }

    /// Try to push a freed slot into the deferred free buffer. Returns false if full.
    #[inline]
    pub fn push_free(&mut self, class_index: usize, slot: CachedSlot) -> bool {
        self.caches[class_index].push_free(slot)
    }

    /// Check if the deferred free buffer for a size class is full.
    #[inline]
    pub fn free_is_full(&self, class_index: usize) -> bool {
        self.caches[class_index].free_is_full()
    }

    /// Pop directly from the free buffer for a size class.
    /// Fast path for tight malloc/free loops: skip the recycle copy.
    #[inline]
    pub fn pop_free(&mut self, class_index: usize) -> Option<CachedSlot> {
        self.caches[class_index].pop_free()
    }

    /// Recycle free buffer entries to alloc cache (lock-free fast path).
    /// Returns the number of entries remaining in the free buffer.
    #[inline]
    pub fn recycle_frees(&mut self, class_index: usize, max_recycle: usize) -> usize {
        self.caches[class_index].recycle_frees_to_alloc(max_recycle)
    }

    /// Get a reference to the free buffer and its count, then reset the count.
    /// Avoids copying the 1536-byte buffer to the caller's stack frame.
    #[inline(always)]
    pub fn drain_frees_ref(&mut self, class_index: usize) -> (&[CachedSlot], usize) {
        let cache = &mut self.caches[class_index];
        let count = cache.free_count;
        cache.free_count = 0;
        (&cache.free_slots[..count], count)
    }
}

/// Consolidated thread-local state: cache + thread ID + RNG + page map MRU.
/// Allocated via mmap per thread (zeroed = valid initial state).
pub(crate) struct ThreadState {
    pub(crate) cache: ThreadCache,
    pub(crate) tid: usize,
    pub(crate) rng: u64,
    pub(crate) active: bool,
    /// Fork generation at last access. On mismatch, cache is stale.
    pub(crate) generation: u64,
    /// Cached arena index (computed once per thread, avoids splitmix64 per alloc).
    pub(crate) cached_arena_idx: usize,
    /// Whether the arena index has been computed.
    pub(crate) arena_idx_valid: bool,
    /// Page map MRU cache: avoids the two-level radix lookup for consecutive
    /// frees to the same slab page (~10 cycles saved per hit).
    pub(crate) mru_page: usize,
    pub(crate) mru_slab_ptr: *mut u8,
    pub(crate) mru_arena_index: u8,
    pub(crate) mru_class_index: u8,
    pub(crate) mru_valid: bool,
    /// Cycle-sharing fast register: most recently freed slot.
    /// malloc checks this before array caches for O(1) reuse in tight loops.
    pub(crate) fast_reg: CachedSlot,
    pub(crate) fast_reg_class: u8,
    /// Amortized fork generation check counter.
    /// 0 = time to check; decremented each operation. Saves ~5 cycles/op.
    pub(crate) fork_check_counter: u8,
}

impl ThreadState {
    /// Check and handle fork generation mismatch.
    /// After fork, thread caches contain stale pointers from the parent;
    /// clear everything and reset thread identity.
    #[inline]
    pub(crate) fn check_fork_generation(&mut self) {
        let current_gen = crate::hardening::fork::fork_generation();
        if self.generation != current_gen {
            self.cache = ThreadCache::new();
            self.tid = 0;
            self.rng = 0;
            self.arena_idx_valid = false;
            self.mru_valid = false;
            self.fast_reg.ptr = core::ptr::null_mut();
            self.generation = current_gen;
        }
    }

    /// Get or compute the thread ID.
    #[inline]
    pub(crate) fn thread_id(&mut self) -> usize {
        if self.tid != 0 {
            return self.tid;
        }
        let new_tid = unsafe { libc::syscall(libc::SYS_gettid) as usize };
        self.tid = new_tid;
        new_tid
    }

    /// Get or compute the arena index for this thread.
    #[inline]
    pub(crate) fn arena_index(&mut self, num_arenas: usize) -> usize {
        if self.arena_idx_valid {
            return self.cached_arena_idx;
        }
        let tid = self.thread_id();
        let idx = crate::platform::splitmix64(tid as u64) as usize % num_arenas;
        self.cached_arena_idx = idx;
        self.arena_idx_valid = true;
        idx
    }

    /// Amortized fork check: only performs the actual check every 256 operations.
    /// Fork is extremely rare (~100μs+ syscall); saves ~5 cycles on the hot path.
    #[inline(always)]
    pub(crate) fn amortized_fork_check(&mut self) {
        if self.fork_check_counter == 0 {
            self.check_fork_generation();
            self.fork_check_counter = 255;
        } else {
            self.fork_check_counter -= 1;
        }
    }

    /// Get a fast random u64 using xorshift64*.
    #[inline]
    fn fast_random(&mut self) -> u64 {
        let mut s = self.rng;
        if s == 0 {
            // Seed from canary secret (cryptographic) + thread id for uniqueness.
            // This is much stronger than stack address which only has ~28 bits of entropy.
            let secret = crate::hardening::canary::secret();
            s = secret
                .wrapping_mul(0x517cc1b727220a95)
                .wrapping_add(self.thread_id() as u64)
                | 1; // ensure non-zero
        }
        // xorshift64*
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        self.rng = s;
        s.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

// ---------------------------------------------------------------------------
// Fast TLS via global_asm! + inline asm with initial-exec TLS model.
//
// Shared libraries default to general-dynamic TLS which calls __tls_get_addr
// through PLT (~25 cycles). We define a TLS variable directly in .tbss with
// initial-exec model and access it via inline asm for direct fs: segment loads
// (~2-4 cycles total). No function call overhead at all.
//
// initial-exec is safe for LD_PRELOAD / DT_NEEDED libraries.
//
// The C shim (csrc/tls_fast.c) is still compiled but only used as a fallback.
// The primary hot path uses the inline asm below.
// ---------------------------------------------------------------------------

// Define a TLS variable in .tbss with initial-exec model (via assembly).
// This variable lives in the thread-local storage block and is accessed
// via %fs: segment on x86-64 Linux.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".section .tbss,\"awT\",@nobits",
    ".align 8",
    ".type _cm_tls_state, @tls_object",
    ".size _cm_tls_state, 8",
    "_cm_tls_state:",
    ".zero 8",
    ".section .text",
);

/// Read the TLS state pointer directly via %fs: segment (no function call).
/// On x86-64 Linux with initial-exec TLS, this is 2 instructions:
///   mov rax, [rip + _cm_tls_state@GOTTPOFF]  (load TLS offset from GOT)
///   mov rax, fs:[rax]                         (load value from TLS)
/// Total: ~2-4 cycles. Compare: GOT-indirect C shim call (~7-10 cycles).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn tls_get_inline() -> *mut libc::c_void {
    let result: *mut libc::c_void;
    core::arch::asm!(
        "mov {tmp}, qword ptr [rip + _cm_tls_state@GOTTPOFF]",
        "mov {out}, qword ptr fs:[{tmp}]",
        tmp = out(reg) _,
        out = out(reg) result,
        options(nostack, pure, readonly),
    );
    result
}

/// Write the TLS state pointer directly via %fs: segment.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn tls_set_inline(ptr: *mut libc::c_void) {
    core::arch::asm!(
        "mov {tmp}, qword ptr [rip + _cm_tls_state@GOTTPOFF]",
        "mov qword ptr fs:[{tmp}], {val}",
        tmp = out(reg) _,
        val = in(reg) ptr,
        options(nostack),
    );
}

// Fallback for non-x86_64: use the C shim via extern "C".
#[cfg(not(target_arch = "x86_64"))]
extern "C" {
    fn compatmalloc_tls_get() -> *mut libc::c_void;
    fn compatmalloc_tls_set(ptr: *mut libc::c_void);
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
unsafe fn tls_get_inline() -> *mut libc::c_void {
    compatmalloc_tls_get()
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
unsafe fn tls_set_inline(ptr: *mut libc::c_void) {
    compatmalloc_tls_set(ptr)
}

/// Pthread key for thread cleanup on exit.
/// The fast path uses the C shim, not pthread_getspecific.
static PTHREAD_KEY: AtomicI32 = AtomicI32::new(-1);

/// Initialize TLS infrastructure. Called during allocator init.
///
/// # Safety
/// Must be called before any hot-path TLS access.
pub unsafe fn init_tls() {
    // Create pthread key solely for the thread-exit destructor.
    // The hot-path read/write uses the C __thread shim.
    let mut key: libc::pthread_key_t = 0;
    if libc::pthread_key_create(&mut key, Some(thread_state_destructor)) == 0 {
        PTHREAD_KEY.store(key as i32, AtomicOrdering::Release);
    }
}

/// Destructor called when a thread exits. Frees the mmap'd ThreadState.
unsafe extern "C" fn thread_state_destructor(ptr: *mut libc::c_void) {
    if ptr.is_null() {
        return;
    }
    let size = core::mem::size_of::<ThreadState>();
    let aligned_size = crate::util::align_up(size, crate::util::page_size());
    libc::munmap(ptr, aligned_size);
}

/// Get the thread-local state pointer via inline asm %fs: access (fast path).
/// On x86-64 Linux, this is 2 inline instructions (~2-4 cycles total).
/// Compare: GOT-indirect C shim (~7-10 cycles), __tls_get_addr (~25 cycles).
#[inline(always)]
unsafe fn get_thread_state_ptr() -> *mut ThreadState {
    let ptr = tls_get_inline() as *mut ThreadState;
    if !ptr.is_null() {
        return ptr;
    }
    alloc_thread_state_slow()
}

/// Get the raw thread state pointer for direct access from the allocator.
/// Eliminates closure overhead by letting callers work with ThreadState directly.
///
/// # Safety
/// Caller must handle reentrancy checks and fork generation.
#[inline(always)]
pub(crate) unsafe fn get_thread_state_raw() -> *mut ThreadState {
    get_thread_state_ptr()
}

/// Cold path: mmap a new ThreadState for this thread and register it.
/// mmap returns zeroed memory which is a valid ThreadState (all zeros = initial state).
#[cold]
#[inline(never)]
unsafe fn alloc_thread_state_slow() -> *mut ThreadState {
    let size = core::mem::size_of::<ThreadState>();
    let aligned_size = crate::util::align_up(size, crate::util::page_size());
    let ptr = libc::mmap(
        core::ptr::null_mut(),
        aligned_size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if ptr == libc::MAP_FAILED || ptr.is_null() {
        return core::ptr::null_mut();
    }
    // mmap zeroed memory ≡ ThreadState { all fields zero } ≡ valid initial state
    // Store in TLS for fast access
    tls_set_inline(ptr);
    // Also register with pthread for thread-exit cleanup
    let key = PTHREAD_KEY.load(AtomicOrdering::Relaxed);
    if key >= 0 {
        libc::pthread_setspecific(key as libc::pthread_key_t, ptr);
    }
    ptr as *mut ThreadState
}

/// Access the consolidated thread-local state. Returns None if TLS is not available
/// (e.g., during very early init or thread destruction) or if already entered (reentrant).
#[inline(always)]
fn with_thread_state<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut ThreadState) -> R,
{
    let state = unsafe { get_thread_state_ptr() };
    if state.is_null() {
        return None;
    }
    let state = unsafe { &mut *state };
    if state.active {
        // Reentrant call (e.g., recursive malloc from thread_local init)
        return None;
    }
    state.active = true;
    state.check_fork_generation();
    let result = f(state);
    state.active = false;
    Some(result)
}

/// Access cache, arena index, and thread ID.
/// Arena index is cached per-thread (computed once per thread lifetime).
#[inline(always)]
pub fn with_cache_tid_arena<F, R>(f: F, num_arenas: usize) -> Option<R>
where
    F: FnOnce(&mut ThreadCache, usize, usize) -> R,
{
    with_thread_state(|state| {
        let tid = state.thread_id();
        let arena_idx = state.arena_index(num_arenas);
        f(&mut state.cache, tid, arena_idx)
    })
}

/// Get thread ID from consolidated state, or fallback to platform.
#[inline]
pub fn thread_id() -> usize {
    match with_thread_state(|state| state.thread_id()) {
        Some(tid) => tid,
        None => crate::platform::thread_id(),
    }
}

/// Get fast random from consolidated state, or fallback to platform.
#[inline]
pub fn fast_random_u64() -> u64 {
    match with_thread_state(|state| state.fast_random()) {
        Some(val) => val,
        None => crate::platform::fast_random_u64(),
    }
}
