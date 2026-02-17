//! Per-thread free list cache to eliminate arena lock on the fast path.
//!
//! Each thread maintains a small array of cached slots per size class.
//! - `malloc` fast path: pop from thread cache (no lock)
//! - `free` fast path: push to thread cache (no lock)
//! - When cache is full on free: flush half to arena (amortized locking)
//! - When cache is empty on malloc: batch-fill from arena

use crate::slab::size_class::NUM_SIZE_CLASSES;

/// Maximum cached slots per size class.
const CACHE_SIZE: usize = 32;

/// A cached free slot: pointer + slab info for O(1) recycle.
#[derive(Clone, Copy)]
pub struct CachedSlot {
    pub ptr: *mut u8,
    pub slab_ptr: *mut u8,
    pub slot_index: usize,
    pub class_index: usize,
}

/// Per-size-class cache: a small stack of free slots.
struct ClassCache {
    slots: [CachedSlot; CACHE_SIZE],
    count: usize,
}

impl ClassCache {
    const fn new() -> Self {
        const EMPTY: CachedSlot = CachedSlot {
            ptr: core::ptr::null_mut(),
            slab_ptr: core::ptr::null_mut(),
            slot_index: 0,
            class_index: 0,
        };
        ClassCache {
            slots: [EMPTY; CACHE_SIZE],
            count: 0,
        }
    }

    #[inline]
    fn push(&mut self, slot: CachedSlot) -> bool {
        if self.count < CACHE_SIZE {
            self.slots[self.count] = slot;
            self.count += 1;
            true
        } else {
            false
        }
    }

    #[inline]
    fn pop(&mut self) -> Option<CachedSlot> {
        if self.count > 0 {
            self.count -= 1;
            Some(self.slots[self.count])
        } else {
            None
        }
    }

    #[inline]
    fn is_full(&self) -> bool {
        self.count >= CACHE_SIZE
    }

    /// Drain half the cache into a buffer, returning the number drained.
    fn drain_half(&mut self, buf: &mut [CachedSlot; CACHE_SIZE]) -> usize {
        let to_drain = self.count / 2;
        if to_drain == 0 {
            return 0;
        }
        let new_count = self.count - to_drain;
        for i in 0..to_drain {
            buf[i] = self.slots[new_count + i];
        }
        self.count = new_count;
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

    /// Try to push a freed slot into the cache. Returns false if cache is full.
    #[inline]
    pub fn push(&mut self, class_index: usize, slot: CachedSlot) -> bool {
        self.caches[class_index].push(slot)
    }

    /// Check if the cache for a size class is full.
    #[inline]
    pub fn is_full(&self, class_index: usize) -> bool {
        self.caches[class_index].is_full()
    }

    /// Drain half the entries for a size class. Returns (buffer, count).
    pub fn drain_half(&mut self, class_index: usize) -> ([CachedSlot; CACHE_SIZE], usize) {
        let mut buf = [CachedSlot {
            ptr: core::ptr::null_mut(),
            slab_ptr: core::ptr::null_mut(),
            slot_index: 0,
            class_index: 0,
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
