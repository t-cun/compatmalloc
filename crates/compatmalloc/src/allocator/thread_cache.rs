//! Per-thread free list cache to eliminate arena lock on the fast path.
//!
//! Each thread maintains a small array of cached slots per size class.
//! - `malloc` fast path: pop from thread cache (no lock)
//! - `free` fast path: push to thread cache free buffer (no lock)
//! - When free buffer is full: flush batch to arena (amortized locking)
//! - When alloc cache is empty on malloc: batch-fill from arena
//!
//! All thread-local state (cache, thread ID, RNG) is consolidated into a
//! single ThreadState struct using UnsafeCell + bool reentrancy guard,
//! eliminating RefCell overhead and multiple TLS lookups.

use crate::slab::size_class::NUM_SIZE_CLASSES;

/// Maximum cached slots per size class (for allocation).
const CACHE_SIZE: usize = 64;

/// Maximum deferred free slots per size class.
const FREE_CACHE_SIZE: usize = 64;

/// A cached free slot: pointer + slab info for O(1) recycle.
/// Compact layout: 24 bytes (down from 40) for better cache utilization.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CachedSlot {
    pub ptr: *mut u8,
    pub slab_ptr: *mut u8,
    pub slot_index: u16,
    pub arena_index: u8,
    pub _pad: u8,
    pub _pad2: u32,
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
            _pad2: 0,
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

    /// Drain all deferred frees into a buffer. Returns the count.
    fn drain_frees(&mut self, buf: &mut [CachedSlot; FREE_CACHE_SIZE]) -> usize {
        let count = self.free_count;
        buf[..count].copy_from_slice(&self.free_slots[..count]);
        self.free_count = 0;
        count
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

    /// Drain half the alloc cache into a buffer, returning the number drained.
    fn drain_half(&mut self, buf: &mut [CachedSlot; CACHE_SIZE]) -> usize {
        let to_drain = self.alloc_count / 2;
        if to_drain == 0 {
            return 0;
        }
        let new_count = self.alloc_count - to_drain;
        buf[..to_drain].copy_from_slice(&self.alloc_slots[new_count..new_count + to_drain]);
        self.alloc_count = new_count;
        to_drain
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

    /// Drain all deferred frees for a size class. Returns (buffer, count).
    pub fn drain_frees(&mut self, class_index: usize) -> ([CachedSlot; FREE_CACHE_SIZE], usize) {
        let mut buf = [CachedSlot {
            ptr: core::ptr::null_mut(),
            slab_ptr: core::ptr::null_mut(),
            slot_index: 0,
            arena_index: 0,
            _pad: 0,
            _pad2: 0,
        }; FREE_CACHE_SIZE];
        let count = self.caches[class_index].drain_frees(&mut buf);
        (buf, count)
    }

    /// Drain half the alloc entries for a size class. Returns (buffer, count).
    pub fn drain_half(&mut self, class_index: usize) -> ([CachedSlot; CACHE_SIZE], usize) {
        let mut buf = [CachedSlot {
            ptr: core::ptr::null_mut(),
            slab_ptr: core::ptr::null_mut(),
            slot_index: 0,
            arena_index: 0,
            _pad: 0,
            _pad2: 0,
        }; CACHE_SIZE];
        let count = self.caches[class_index].drain_half(&mut buf);
        (buf, count)
    }
}

/// Consolidated thread-local state: cache + thread ID + RNG.
/// Uses UnsafeCell + bool reentrancy guard instead of RefCell for lower overhead.
struct ThreadState {
    cache: ThreadCache,
    tid: usize,
    rng: u64,
    active: bool,
    /// Fork generation at last access. On mismatch, cache is stale.
    generation: u64,
    /// Cached arena index (computed once per thread, avoids splitmix64 per alloc).
    cached_arena_idx: usize,
    /// Whether the arena index has been computed.
    arena_idx_valid: bool,
}

impl ThreadState {
    const fn new() -> Self {
        ThreadState {
            cache: ThreadCache::new(),
            tid: 0,
            rng: 0,
            active: false,
            generation: 0,
            cached_arena_idx: 0,
            arena_idx_valid: false,
        }
    }

    /// Check and handle fork generation mismatch.
    /// After fork, thread caches contain stale pointers from the parent;
    /// clear everything and reset thread identity.
    #[inline]
    fn check_fork_generation(&mut self) {
        let current_gen = crate::hardening::fork::fork_generation();
        if self.generation != current_gen {
            self.cache = ThreadCache::new();
            self.tid = 0;
            self.rng = 0;
            self.arena_idx_valid = false;
            self.generation = current_gen;
        }
    }

    /// Get or compute the thread ID.
    #[inline]
    fn thread_id(&mut self) -> usize {
        if self.tid != 0 {
            return self.tid;
        }
        let new_tid = unsafe { libc::syscall(libc::SYS_gettid) as usize };
        self.tid = new_tid;
        new_tid
    }

    /// Get or compute the arena index for this thread.
    #[inline]
    fn arena_index(&mut self, num_arenas: usize) -> usize {
        if self.arena_idx_valid {
            return self.cached_arena_idx;
        }
        let tid = self.thread_id();
        let idx = crate::platform::splitmix64(tid as u64) as usize % num_arenas;
        self.cached_arena_idx = idx;
        self.arena_idx_valid = true;
        idx
    }

    /// Get a fast random u64 using xorshift64*.
    #[inline]
    fn fast_random(&mut self) -> u64 {
        let mut s = self.rng;
        if s == 0 {
            // Seed from stack address + thread id for uniqueness
            let stack_addr = &s as *const _ as u64;
            s = stack_addr
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

/// Access the consolidated thread-local state. Returns None if TLS is not available
/// (e.g., during very early init or thread destruction) or if already entered (reentrant).
#[inline(always)]
fn with_thread_state<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut ThreadState) -> R,
{
    use core::cell::UnsafeCell;

    thread_local! {
        static STATE: UnsafeCell<ThreadState> = const { UnsafeCell::new(ThreadState::new()) };
    }

    STATE.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        if state.active {
            // Reentrant call (e.g., recursive malloc from thread_local init)
            return None;
        }
        // Set active flag for reentrancy guard. With panic = "abort" (release mode),
        // no unwind can occur, so a simple set/reset is safe. In debug mode, a
        // reentrant panic would abort anyway.
        state.active = true;
        state.check_fork_generation();
        let result = f(state);
        state.active = false;
        Some(result)
    })
}

/// Access the thread-local cache. Returns None if TLS is not available
/// (e.g., during very early init or thread destruction).
/// Thin wrapper around with_thread_state for backward compatibility.
#[inline(always)]
pub fn with_thread_cache<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut ThreadCache) -> R,
{
    with_thread_state(|state| f(&mut state.cache))
}

/// Access both the thread-local cache and thread ID in a single TLS access.
/// Avoids the reentrant TLS fallback that occurs when select_arena() is called
/// inside a with_thread_cache() closure.
#[inline(always)]
pub fn with_cache_and_tid<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut ThreadCache, usize) -> R,
{
    with_thread_state(|state| {
        let tid = state.thread_id();
        f(&mut state.cache, tid)
    })
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
