pub mod guard;

use crate::hardening::metadata::{AllocationMeta, MetadataTable};
use crate::slab::page_map;
use crate::sync::RawMutex;
use crate::platform;
use core::cell::UnsafeCell;
use core::ptr;
use guard::LargeAlloc;

/// Hash table capacity for large allocations. Must be a power of two.
const LARGE_TABLE_CAPACITY: usize = 4096;

#[derive(Clone, Copy)]
struct LargeEntry {
    /// Key: user_ptr as usize (0 = empty slot).
    key: usize,
    base: *mut u8,
    total_size: usize,
    data_size: usize,
    requested_size: usize,
}

impl LargeEntry {
    const fn empty() -> Self {
        LargeEntry {
            key: 0,
            base: ptr::null_mut(),
            total_size: 0,
            data_size: 0,
            requested_size: 0,
        }
    }
}

struct LargeInner {
    entries: [LargeEntry; LARGE_TABLE_CAPACITY],
    count: usize,
}

pub struct LargeAllocator {
    lock: RawMutex,
    inner: UnsafeCell<LargeInner>,
}

unsafe impl Send for LargeAllocator {}
unsafe impl Sync for LargeAllocator {}

/// Hash a pointer for the large allocation table.
#[inline]
fn hash_large_ptr(key: usize) -> usize {
    // splitmix64 finalizer
    let mut x = key as u64;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x as usize
}

impl LargeAllocator {
    pub const fn new() -> Self {
        const EMPTY: LargeEntry = LargeEntry::empty();
        LargeAllocator {
            lock: RawMutex::new(),
            inner: UnsafeCell::new(LargeInner {
                entries: [EMPTY; LARGE_TABLE_CAPACITY],
                count: 0,
            }),
        }
    }

    /// Reset the lock. Only safe in single-threaded post-fork child.
    pub unsafe fn reset_lock(&self) {
        self.lock.force_unlock();
    }

    pub unsafe fn alloc(&self, size: usize, metadata: &MetadataTable) -> *mut u8 {
        let alloc = match LargeAlloc::create(size) {
            Some(a) => a,
            None => return ptr::null_mut(),
        };

        let user_ptr = alloc.user_ptr;
        let entry = LargeEntry {
            key: user_ptr as usize,
            base: alloc.base,
            total_size: alloc.total_size,
            data_size: alloc.data_size,
            requested_size: alloc.requested_size,
        };

        #[cfg(feature = "canaries")]
        {
            let canary = crate::hardening::canary::generate_canary(user_ptr);
            metadata.insert(user_ptr, AllocationMeta::new(size, canary));
        }
        #[cfg(not(feature = "canaries"))]
        {
            metadata.insert(user_ptr, AllocationMeta::new(size, 0));
        }

        self.lock.lock();
        let inner = &mut *self.inner.get();
        let stored = Self::insert_entry(inner, entry);
        self.lock.unlock();

        if !stored {
            alloc.destroy();
            metadata.remove(user_ptr);
            return ptr::null_mut();
        }

        // Register in page map for O(1) lookup
        page_map::register_large(user_ptr, alloc.data_size);

        user_ptr
    }

    pub unsafe fn free(&self, ptr: *mut u8, metadata: &MetadataTable) -> bool {
        // Check metadata BEFORE acquiring large lock to match alloc's lock order
        // (metadata lock -> large lock), preventing ABBA deadlock.
        if let Some(meta) = metadata.get(ptr) {
            if meta.is_freed() {
                crate::hardening::abort_with_message(
                    "compatmalloc: double free detected (large)\n",
                );
            }
        }
        metadata.remove(ptr);

        self.lock.lock();
        let inner = &mut *self.inner.get();

        let key = ptr as usize;
        let mask = LARGE_TABLE_CAPACITY - 1;
        let mut idx = hash_large_ptr(key) & mask;

        loop {
            let entry = &inner.entries[idx];
            if entry.key == key {
                let base = entry.base;
                let total_size = entry.total_size;
                let data_size = entry.data_size;

                // Remove entry and rehash
                Self::remove_at(inner, idx);
                self.lock.unlock();

                // Unregister from page map before unmapping
                page_map::unregister_large(ptr, data_size);
                platform::unmap(base, total_size);
                return true;
            }
            if entry.key == 0 {
                break;
            }
            idx = (idx + 1) & mask;
        }
        self.lock.unlock();
        false
    }

    pub unsafe fn usable_size(&self, ptr: *mut u8) -> Option<usize> {
        self.lock.lock();
        let inner = &*self.inner.get();
        let result = Self::lookup_entry(inner, ptr).map(|e| e.requested_size);
        self.lock.unlock();
        result
    }

    pub unsafe fn contains(&self, ptr: *mut u8) -> bool {
        self.lock.lock();
        let inner = &*self.inner.get();
        let result = Self::lookup_entry(inner, ptr).is_some();
        self.lock.unlock();
        result
    }

    pub unsafe fn requested_size(&self, ptr: *mut u8) -> Option<usize> {
        self.lock.lock();
        let inner = &*self.inner.get();
        let result = Self::lookup_entry(inner, ptr).map(|e| e.requested_size);
        self.lock.unlock();
        result
    }

    // ========================================================================
    // Hash table operations (caller must hold lock)
    // ========================================================================

    /// Insert an entry into the hash table. Returns false if table is full.
    unsafe fn insert_entry(inner: &mut LargeInner, entry: LargeEntry) -> bool {
        if inner.count >= LARGE_TABLE_CAPACITY * 3 / 4 {
            return false; // Table too full
        }
        let mask = LARGE_TABLE_CAPACITY - 1;
        let mut idx = hash_large_ptr(entry.key) & mask;
        loop {
            if inner.entries[idx].key == 0 {
                inner.entries[idx] = entry;
                inner.count += 1;
                return true;
            }
            if inner.entries[idx].key == entry.key {
                // Replace existing
                inner.entries[idx] = entry;
                return true;
            }
            idx = (idx + 1) & mask;
        }
    }

    /// Look up an entry by user_ptr.
    unsafe fn lookup_entry(inner: &LargeInner, ptr: *mut u8) -> Option<LargeEntry> {
        let key = ptr as usize;
        if key == 0 {
            return None;
        }
        let mask = LARGE_TABLE_CAPACITY - 1;
        let mut idx = hash_large_ptr(key) & mask;
        loop {
            let entry = &inner.entries[idx];
            if entry.key == key {
                return Some(*entry);
            }
            if entry.key == 0 {
                return None;
            }
            idx = (idx + 1) & mask;
        }
    }

    /// Remove entry at given index and rehash subsequent entries.
    unsafe fn remove_at(inner: &mut LargeInner, idx: usize) {
        let mask = LARGE_TABLE_CAPACITY - 1;
        inner.entries[idx] = LargeEntry::empty();
        inner.count -= 1;

        // Backward shift deletion
        let mut next = (idx + 1) & mask;
        let mut vacancy = idx;
        loop {
            if inner.entries[next].key == 0 {
                break;
            }
            let ideal = hash_large_ptr(inner.entries[next].key) & mask;
            let should_move = if next > vacancy {
                ideal <= vacancy || ideal > next
            } else {
                ideal <= vacancy && ideal > next
            };
            if should_move {
                inner.entries[vacancy] = inner.entries[next];
                inner.entries[next] = LargeEntry::empty();
                vacancy = next;
            }
            next = (next + 1) & mask;
        }
    }
}
