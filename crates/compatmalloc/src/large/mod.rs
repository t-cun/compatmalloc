pub mod guard;

use crate::hardening::metadata::{AllocationMeta, MetadataTable};
use crate::platform;
use crate::slab::page_map;
use crate::sync::RawMutex;
use core::cell::UnsafeCell;
use core::ptr;
use guard::LargeAlloc;

use crate::util::{align_up, page_size};

/// Hash table capacity for large allocations. Must be a power of two.
const LARGE_TABLE_CAPACITY: usize = 4096;

/// Maximum cached mappings for reuse. Eliminates mmap/munmap/mprotect syscalls
/// in steady-state allocation patterns.
const MAPPING_CACHE_SIZE: usize = 16;

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

/// A cached VMA mapping available for reuse.
///
/// Invariant: data pages have been MADV_DONTNEED'd (zeroed by kernel on next access).
/// Guard pages (when enabled) remain PROT_NONE throughout the cache lifetime.
#[derive(Clone, Copy)]
struct CachedMapping {
    base: *mut u8,
    total_size: usize,
    data_size: usize,
}

impl CachedMapping {
    const fn empty() -> Self {
        CachedMapping {
            base: ptr::null_mut(),
            total_size: 0,
            data_size: 0,
        }
    }
}

struct LargeInner {
    entries: [LargeEntry; LARGE_TABLE_CAPACITY],
    count: usize,
    /// Mapping cache: reusable VMAs with guard pages intact.
    mapping_cache: [CachedMapping; MAPPING_CACHE_SIZE],
    mapping_cache_count: usize,
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
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        const EMPTY: LargeEntry = LargeEntry::empty();
        const EMPTY_MAPPING: CachedMapping = CachedMapping::empty();
        LargeAllocator {
            lock: RawMutex::new(),
            inner: UnsafeCell::new(LargeInner {
                entries: [EMPTY; LARGE_TABLE_CAPACITY],
                count: 0,
                mapping_cache: [EMPTY_MAPPING; MAPPING_CACHE_SIZE],
                mapping_cache_count: 0,
            }),
        }
    }

    /// Reset the lock. Only safe in single-threaded post-fork child.
    ///
    /// # Safety
    /// Must only be called from single-threaded post-fork child.
    pub unsafe fn reset_lock(&self) {
        self.lock.force_unlock();
    }

    /// # Safety
    /// Caller must ensure the allocator has been initialized.
    pub unsafe fn alloc(&self, size: usize, metadata: &MetadataTable) -> *mut u8 {
        let data_size = align_up(size, page_size());

        #[cfg(feature = "guard-pages")]
        let needed_total = page_size() + data_size + page_size();
        #[cfg(not(feature = "guard-pages"))]
        let needed_total = data_size;

        // Try mapping cache first (single lock acquisition for check + hash insert)
        self.lock.lock();
        let inner = &mut *self.inner.get();
        if let Some(mapping) = Self::pop_cached(inner, needed_total) {
            #[cfg(feature = "guard-pages")]
            let user_ptr = mapping.base.add(page_size());
            #[cfg(not(feature = "guard-pages"))]
            let user_ptr = mapping.base;

            let entry = LargeEntry {
                key: user_ptr as usize,
                base: mapping.base,
                total_size: mapping.total_size,
                data_size: mapping.data_size,
                requested_size: size,
            };
            let stored = Self::insert_entry(inner, entry);
            self.lock.unlock();

            if !stored {
                platform::unmap(mapping.base, mapping.total_size);
                return ptr::null_mut();
            }

            page_map::register_large(user_ptr, mapping.data_size);

            #[cfg(feature = "canaries")]
            {
                let canary = crate::hardening::canary::generate_canary(user_ptr);
                metadata.insert(user_ptr, AllocationMeta::new(size, canary));
            }
            #[cfg(not(feature = "canaries"))]
            {
                metadata.insert(user_ptr, AllocationMeta::new(size, 0));
            }

            return user_ptr;
        }
        self.lock.unlock();

        // Cache miss: create new mapping (mmap + mprotect)
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

        page_map::register_large(user_ptr, alloc.data_size);

        user_ptr
    }

    /// # Safety
    /// `ptr` must be a valid large allocation pointer.
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

                // Remove entry from hash table
                Self::remove_at(inner, idx);

                // Cache the mapping for reuse. Data pages are MADV_DONTNEED'd
                // in push_cached to prevent information leaks. Guard pages
                // remain PROT_NONE throughout.
                Self::push_cached(
                    inner,
                    CachedMapping {
                        base,
                        total_size,
                        data_size,
                    },
                );
                self.lock.unlock();

                // Unregister from page map (lock-free atomic stores)
                page_map::unregister_large(ptr, data_size);
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

    /// # Safety
    /// `ptr` must be a valid allocation pointer.
    pub unsafe fn usable_size(&self, ptr: *mut u8) -> Option<usize> {
        self.lock.lock();
        let inner = &*self.inner.get();
        let result = Self::lookup_entry(inner, ptr).map(|e| e.requested_size);
        self.lock.unlock();
        result
    }

    /// # Safety
    /// `ptr` must be a valid pointer.
    pub unsafe fn contains(&self, ptr: *mut u8) -> bool {
        self.lock.lock();
        let inner = &*self.inner.get();
        let result = Self::lookup_entry(inner, ptr).is_some();
        self.lock.unlock();
        result
    }

    /// # Safety
    /// `ptr` must be a valid allocation pointer.
    pub unsafe fn requested_size(&self, ptr: *mut u8) -> Option<usize> {
        self.lock.lock();
        let inner = &*self.inner.get();
        let result = Self::lookup_entry(inner, ptr).map(|e| e.requested_size);
        self.lock.unlock();
        result
    }

    // ========================================================================
    // Mapping cache operations (caller must hold lock)
    // ========================================================================

    /// Pop a cached mapping with total_size >= needed. Prefers exact match,
    /// then smallest fit. Returns None if no suitable mapping is cached.
    unsafe fn pop_cached(inner: &mut LargeInner, needed_total: usize) -> Option<CachedMapping> {
        let count = inner.mapping_cache_count;
        if count == 0 {
            return None;
        }
        let mut best_idx: Option<usize> = None;
        let mut best_size = usize::MAX;
        for i in 0..count {
            let ts = inner.mapping_cache[i].total_size;
            if ts >= needed_total && ts < best_size {
                best_size = ts;
                best_idx = Some(i);
                if ts == needed_total {
                    break; // exact match
                }
            }
        }
        let idx = best_idx?;
        let mapping = inner.mapping_cache[idx];
        // Swap-remove: replace with last entry
        inner.mapping_cache_count -= 1;
        if idx < inner.mapping_cache_count {
            inner.mapping_cache[idx] = inner.mapping_cache[inner.mapping_cache_count];
        }
        Some(mapping)
    }

    /// Push a mapping into the cache. If full, evicts the smallest cached
    /// mapping (munmaps it) to make room, keeping larger mappings cached
    /// since they're more expensive to recreate.
    ///
    /// Note: `advise_free()` is a syscall executed under the large allocator
    /// lock. This adds latency to the critical section but is necessary for
    /// correctness — moving it outside the lock would create a window where
    /// another thread could `pop_cached` and receive non-zeroed pages.
    unsafe fn push_cached(inner: &mut LargeInner, mapping: CachedMapping) {
        // Release physical pages to prevent information leaks on reuse.
        #[cfg(feature = "guard-pages")]
        let data_start = mapping.base.add(page_size());
        #[cfg(not(feature = "guard-pages"))]
        let data_start = mapping.base;
        crate::platform::advise_free(data_start, mapping.data_size);

        if inner.mapping_cache_count < MAPPING_CACHE_SIZE {
            inner.mapping_cache[inner.mapping_cache_count] = mapping;
            inner.mapping_cache_count += 1;
            return;
        }
        // Cache full: find the smallest entry to evict
        let mut smallest_idx = 0;
        for i in 1..MAPPING_CACHE_SIZE {
            if inner.mapping_cache[i].total_size < inner.mapping_cache[smallest_idx].total_size {
                smallest_idx = i;
            }
        }
        if mapping.total_size >= inner.mapping_cache[smallest_idx].total_size {
            // Evict the smallest, cache our (larger or equal) mapping
            let evict = inner.mapping_cache[smallest_idx];
            inner.mapping_cache[smallest_idx] = mapping;
            platform::unmap(evict.base, evict.total_size);
        } else {
            // Our mapping is the smallest — just unmap it
            platform::unmap(mapping.base, mapping.total_size);
        }
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
