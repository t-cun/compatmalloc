//! Per-thread free list cache to eliminate arena lock on the fast path.
//!
//! Each thread maintains a small array of cached slots per size class.
//! - `malloc` fast path: pop from thread cache (no lock)
//! - `free` fast path: push to thread cache free buffer (no lock)
//! - When free buffer is full: flush batch to arena (amortized locking)
//! - When alloc cache is empty on malloc: batch-fill from arena

use crate::slab::size_class::NUM_SIZE_CLASSES;

/// Maximum cached slots per size class (for allocation).
const CACHE_SIZE: usize = 32;

/// Maximum deferred free slots per size class.
const FREE_CACHE_SIZE: usize = 16;

/// A cached free slot: pointer + slab info for O(1) recycle.
#[derive(Clone, Copy)]
pub struct CachedSlot {
    pub ptr: *mut u8,
    pub slab_ptr: *mut u8,
    pub slot_index: usize,
    pub class_index: usize,
    pub arena_index: usize,
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
            class_index: 0,
            arena_index: 0,
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

    #[inline]
    fn free_is_full(&self) -> bool {
        self.free_count >= FREE_CACHE_SIZE
    }

    /// Drain all deferred frees into a buffer. Returns the count.
    fn drain_frees(&mut self, buf: &mut [CachedSlot; FREE_CACHE_SIZE]) -> usize {
        let count = self.free_count;
        for i in 0..count {
            buf[i] = self.free_slots[i];
        }
        self.free_count = 0;
        count
    }

    /// Drain half the alloc cache into a buffer, returning the number drained.
    fn drain_half(&mut self, buf: &mut [CachedSlot; CACHE_SIZE]) -> usize {
        let to_drain = self.alloc_count / 2;
        if to_drain == 0 {
            return 0;
        }
        let new_count = self.alloc_count - to_drain;
        for i in 0..to_drain {
            buf[i] = self.alloc_slots[new_count + i];
        }
        self.alloc_count = new_count;
        to_drain
    }
}

/// Thread-local cache for all size classes.
pub struct ThreadCache {
    caches: [ClassCache; NUM_SIZE_CLASSES],
}

impl ThreadCache {
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

    /// Drain all deferred frees for a size class. Returns (buffer, count).
    pub fn drain_frees(&mut self, class_index: usize) -> ([CachedSlot; FREE_CACHE_SIZE], usize) {
        let mut buf = [CachedSlot {
            ptr: core::ptr::null_mut(),
            slab_ptr: core::ptr::null_mut(),
            slot_index: 0,
            class_index: 0,
            arena_index: 0,
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
            class_index: 0,
            arena_index: 0,
        }; CACHE_SIZE];
        let count = self.caches[class_index].drain_half(&mut buf);
        (buf, count)
    }
}

/// Access the thread-local cache. Returns None if TLS is not available
/// (e.g., during very early init or thread destruction).
#[inline]
pub fn with_thread_cache<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut ThreadCache) -> R,
{
    use std::cell::RefCell;

    thread_local! {
        static CACHE: RefCell<ThreadCache> = const { RefCell::new(ThreadCache::new()) };
    }

    CACHE.with(|cell| {
        // Use try_borrow_mut to avoid panicking if we're already in the cache
        // (e.g., recursive malloc from thread_local init)
        cell.try_borrow_mut().ok().map(|mut cache| f(&mut cache))
    })
}
