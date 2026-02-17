use crate::platform;
use crate::sync::RawMutex;
use crate::util::{align_up, PAGE_SIZE};
use core::cell::UnsafeCell;
use core::ptr;

/// Flags for allocation state.
const FLAG_FREED: u8 = 0x01;

/// Out-of-band metadata for a single allocation.
/// Stored separately from user data to prevent heap metadata corruption attacks.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct AllocationMeta {
    pub requested_size: usize,
    pub canary_value: u64,
    pub flags: u8,
}

impl AllocationMeta {
    pub fn new(requested_size: usize, canary_value: u64) -> Self {
        AllocationMeta {
            requested_size,
            canary_value,
            flags: 0,
        }
    }

    #[inline]
    pub fn is_freed(&self) -> bool {
        self.flags & FLAG_FREED != 0
    }

    pub fn mark_freed(&mut self) {
        self.flags |= FLAG_FREED;
    }
}

/// Hash table entry for the metadata table.
#[derive(Clone, Copy)]
#[repr(C)]
struct MetaEntry {
    /// Pointer key (0 = empty slot).
    key: usize,
    /// Metadata value.
    meta: AllocationMeta,
}

/// Mutable state for the metadata table.
pub struct MetadataInner {
    entries: *mut MetaEntry,
    capacity: usize,
    count: usize,
    mapped_size: usize,
}

impl MetadataInner {
    pub const fn new() -> Self {
        MetadataInner {
            entries: ptr::null_mut(),
            capacity: 0,
            count: 0,
            mapped_size: 0,
        }
    }
}

/// Out-of-band metadata hash table.
/// Uses open addressing with linear probing.
/// Cache-line aligned to prevent false sharing between stripes.
#[repr(C, align(128))]
pub struct MetadataTable {
    lock: RawMutex,
    inner: UnsafeCell<MetadataInner>,
}

unsafe impl Send for MetadataTable {}
unsafe impl Sync for MetadataTable {}

impl MetadataTable {
    const INITIAL_CAPACITY: usize = 16384;

    pub const fn new() -> Self {
        MetadataTable {
            lock: RawMutex::new(),
            inner: UnsafeCell::new(MetadataInner::new()),
        }
    }

    /// Initialize the metadata table (must be called before use).
    pub unsafe fn init(&self) -> bool {
        let inner = &mut *self.inner.get();
        Self::init_inner(inner, Self::INITIAL_CAPACITY)
    }

    unsafe fn init_inner(inner: &mut MetadataInner, capacity: usize) -> bool {
        let size = align_up(capacity * core::mem::size_of::<MetaEntry>(), PAGE_SIZE);
        let mem = platform::map_anonymous(size);
        if mem.is_null() {
            return false;
        }
        inner.entries = mem as *mut MetaEntry;
        inner.capacity = capacity;
        inner.count = 0;
        inner.mapped_size = size;
        true
    }

    // ========================================================================
    // Locked methods (for standalone use, e.g. large allocator metadata)
    // ========================================================================

    pub unsafe fn insert(&self, ptr: *mut u8, meta: AllocationMeta) {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        Self::insert_inner(inner, ptr, meta);
        self.lock.unlock();
    }

    pub unsafe fn get(&self, ptr: *mut u8) -> Option<AllocationMeta> {
        self.lock.lock();
        let inner = &*self.inner.get();
        let result = Self::get_inner(inner, ptr);
        self.lock.unlock();
        result
    }

    pub unsafe fn get_and_mark_freed(&self, ptr: *mut u8) -> Option<AllocationMeta> {
        self.lock.lock();
        let inner = &*self.inner.get();
        let result = Self::get_and_mark_freed_inner(inner, ptr);
        self.lock.unlock();
        result
    }

    pub unsafe fn remove(&self, ptr: *mut u8) {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        Self::remove_inner(inner, ptr);
        self.lock.unlock();
    }

    // ========================================================================
    // Unlocked methods (for use when caller holds an external lock, e.g. arena lock)
    //
    // # Safety
    // Caller MUST hold the arena lock (or another external lock) that serializes
    // access to the metadata table. These must not be called concurrently.
    // ========================================================================

    #[inline]
    pub(crate) unsafe fn insert_unlocked(&self, ptr: *mut u8, meta: AllocationMeta) {
        let inner = &mut *self.inner.get();
        Self::insert_inner(inner, ptr, meta);
    }

    #[inline]
    pub(crate) unsafe fn get_unlocked(&self, ptr: *mut u8) -> Option<AllocationMeta> {
        let inner = &*self.inner.get();
        Self::get_inner(inner, ptr)
    }

    #[inline]
    pub(crate) unsafe fn get_and_mark_freed_unlocked(&self, ptr: *mut u8) -> Option<AllocationMeta> {
        let inner = &*self.inner.get();
        Self::get_and_mark_freed_inner(inner, ptr)
    }

    #[inline]
    pub(crate) unsafe fn remove_unlocked(&self, ptr: *mut u8) {
        let inner = &mut *self.inner.get();
        Self::remove_inner(inner, ptr);
    }

    // ========================================================================
    // Inner implementations (no locking)
    // ========================================================================

    unsafe fn insert_inner(inner: &mut MetadataInner, ptr: *mut u8, meta: AllocationMeta) {
        if inner.entries.is_null() || inner.capacity == 0 {
            return;
        }
        // Grow if load factor > 75%
        if inner.count * 4 >= inner.capacity * 3 {
            Self::grow(inner);
        }
        let key = ptr as usize;
        debug_assert!(key != 0);
        let mask = inner.capacity - 1;
        let mut idx = hash_ptr(key) & mask;
        loop {
            let entry = &mut *inner.entries.add(idx);
            if entry.key == 0 || entry.key == key {
                if entry.key == 0 {
                    inner.count += 1;
                }
                entry.key = key;
                entry.meta = meta;
                return;
            }
            idx = (idx + 1) & mask;
        }
    }

    unsafe fn get_inner(inner: &MetadataInner, ptr: *mut u8) -> Option<AllocationMeta> {
        if inner.entries.is_null() || inner.capacity == 0 {
            return None;
        }
        let key = ptr as usize;
        let mask = inner.capacity - 1;
        let mut idx = hash_ptr(key) & mask;
        loop {
            let entry = &*inner.entries.add(idx);
            if entry.key == key {
                return Some(entry.meta);
            }
            if entry.key == 0 {
                return None;
            }
            idx = (idx + 1) & mask;
        }
    }

    unsafe fn get_and_mark_freed_inner(
        inner: &MetadataInner,
        ptr: *mut u8,
    ) -> Option<AllocationMeta> {
        if inner.entries.is_null() || inner.capacity == 0 {
            return None;
        }
        let key = ptr as usize;
        let mask = inner.capacity - 1;
        let mut idx = hash_ptr(key) & mask;
        loop {
            let entry = &mut *inner.entries.add(idx);
            if entry.key == key {
                let result = entry.meta;
                entry.meta.mark_freed();
                return Some(result);
            }
            if entry.key == 0 {
                return None;
            }
            idx = (idx + 1) & mask;
        }
    }

    unsafe fn remove_inner(inner: &mut MetadataInner, ptr: *mut u8) {
        if inner.entries.is_null() || inner.capacity == 0 {
            return;
        }
        let key = ptr as usize;
        let mask = inner.capacity - 1;
        let mut idx = hash_ptr(key) & mask;

        loop {
            let entry = &mut *inner.entries.add(idx);
            if entry.key == key {
                entry.key = 0;
                inner.count -= 1;

                // Rehash subsequent entries (backward shift deletion)
                let mut next = (idx + 1) & mask;
                loop {
                    let next_entry = &*inner.entries.add(next);
                    if next_entry.key == 0 {
                        break;
                    }
                    let ideal = hash_ptr(next_entry.key) & mask;
                    let should_move = if next > idx {
                        ideal <= idx || ideal > next
                    } else {
                        ideal <= idx && ideal > next
                    };
                    if should_move {
                        let saved = *next_entry;
                        (*inner.entries.add(next)).key = 0;
                        (*inner.entries.add(idx)).key = saved.key;
                        (*inner.entries.add(idx)).meta = saved.meta;
                        idx = next;
                    }
                    next = (next + 1) & mask;
                }
                return;
            }
            if entry.key == 0 {
                return;
            }
            idx = (idx + 1) & mask;
        }
    }

    /// Grow the hash table. Allocates new table outside the critical section concept,
    /// then rehashes entries.
    unsafe fn grow(inner: &mut MetadataInner) {
        let new_capacity = inner.capacity * 2;
        let new_size = align_up(new_capacity * core::mem::size_of::<MetaEntry>(), PAGE_SIZE);
        let new_mem = platform::map_anonymous(new_size);
        if new_mem.is_null() {
            return;
        }

        let new_entries = new_mem as *mut MetaEntry;
        let old_entries = inner.entries;
        let old_capacity = inner.capacity;
        let old_size = inner.mapped_size;

        inner.entries = new_entries;
        inner.capacity = new_capacity;
        inner.mapped_size = new_size;
        inner.count = 0;

        let mask = new_capacity - 1;
        for i in 0..old_capacity {
            let entry = &*old_entries.add(i);
            if entry.key != 0 {
                let mut idx = hash_ptr(entry.key) & mask;
                loop {
                    let new_entry = &mut *new_entries.add(idx);
                    if new_entry.key == 0 {
                        *new_entry = *entry;
                        inner.count += 1;
                        break;
                    }
                    idx = (idx + 1) & mask;
                }
            }
        }

        if !old_entries.is_null() {
            platform::unmap(old_entries as *mut u8, old_size);
        }
    }
}

/// splitmix64 finalizer for proper distribution of pointer keys.
#[inline]
fn hash_ptr(key: usize) -> usize {
    let mut x = key as u64;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x as usize
}
