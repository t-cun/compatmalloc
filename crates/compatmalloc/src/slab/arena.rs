use crate::hardening::metadata::{AllocationMeta, MetadataTable};
use crate::platform;
use crate::slab::bitmap::SlabBitmap;
use crate::slab::page_map;
use crate::slab::size_class::{self, NUM_SIZE_CLASSES};
use crate::sync::RawMutex;
use crate::util::{align_up, PAGE_SIZE};
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

/// A single slab region for one size class.
#[repr(C)]
pub struct Slab {
    /// Start of the slot data region.
    pub data: *mut u8,
    /// Total mapped size (data + bitmap + guard pages if enabled).
    #[allow(dead_code)]
    mapped_size: usize,
    /// Bitmap tracking free/allocated slots.
    pub bitmap: SlabBitmap,
    /// Size class index.
    pub class_index: usize,
    /// Next slab in the linked list for this size class (null = end).
    next: *mut Slab,
    /// Whether any slot in this slab has ever been freed (for calloc optimization).
    /// AtomicBool to allow lock-free reads from calloc while writes happen under arena lock.
    pub ever_freed: AtomicBool,
}

impl Slab {
    /// Allocate a new slab for the given size class and register it in the page map.
    /// This can be called OUTSIDE the arena lock (4A: slab creation outside lock).
    unsafe fn create(class_index: usize, arena_index: usize) -> *mut Slab {
        let slot_sz = size_class::slot_size(class_index);
        let num_slots = size_class::slots_per_slab(class_index);
        let data_size = num_slots * slot_sz;
        let bitmap_bytes = SlabBitmap::storage_bytes(num_slots);
        let slab_header_size = core::mem::size_of::<Slab>();

        let header_and_bitmap = align_up(slab_header_size + bitmap_bytes, PAGE_SIZE);
        let data_pages = align_up(data_size, PAGE_SIZE);

        #[cfg(feature = "guard-pages")]
        let total_size = PAGE_SIZE + header_and_bitmap + data_pages + PAGE_SIZE;
        #[cfg(not(feature = "guard-pages"))]
        let total_size = header_and_bitmap + data_pages;

        let base = platform::map_anonymous(total_size);
        if base.is_null() {
            return ptr::null_mut();
        }

        #[cfg(feature = "guard-pages")]
        {
            platform::protect_none(base, PAGE_SIZE);
            platform::protect_none(base.add(PAGE_SIZE + header_and_bitmap + data_pages), PAGE_SIZE);
        }

        #[cfg(feature = "guard-pages")]
        let header_ptr = base.add(PAGE_SIZE) as *mut Slab;
        #[cfg(not(feature = "guard-pages"))]
        let header_ptr = base as *mut Slab;

        let bitmap_storage = (header_ptr as *mut u8).add(slab_header_size) as *mut u64;
        let data_ptr = (header_ptr as *mut u8).add(header_and_bitmap);

        let bitmap = SlabBitmap::init(bitmap_storage, num_slots);

        header_ptr.write(Slab {
            data: data_ptr,
            mapped_size: total_size,
            bitmap,
            class_index,
            next: ptr::null_mut(),
            ever_freed: AtomicBool::new(false),
        });

        // Register data pages in the page map for O(1) lookup
        page_map::register_slab(
            data_ptr,
            data_pages,
            header_ptr as *mut u8,
            class_index,
            arena_index,
        );

        header_ptr
    }

    #[inline]
    pub unsafe fn slot_ptr(&self, slot: usize) -> *mut u8 {
        let slot_sz = size_class::slot_size(self.class_index);
        self.data.add(slot * slot_sz)
    }

    pub fn slot_for_ptr(&self, ptr: *mut u8) -> Option<usize> {
        let offset = ptr as usize - self.data as usize;
        let slot_sz = size_class::slot_size(self.class_index);
        if offset % slot_sz != 0 {
            return None;
        }
        let slot = offset / slot_sz;
        let num_slots = size_class::slots_per_slab(self.class_index);
        if slot < num_slots {
            Some(slot)
        } else {
            None
        }
    }

    #[inline]
    fn contains(&self, ptr: *mut u8) -> bool {
        let start = self.data as usize;
        let data_size =
            size_class::slots_per_slab(self.class_index) * size_class::slot_size(self.class_index);
        let end = start + data_size;
        let p = ptr as usize;
        p >= start && p < end
    }
}

struct SlabList {
    head: *mut Slab,
}

impl SlabList {
    const fn new() -> Self {
        SlabList {
            head: ptr::null_mut(),
        }
    }
}

struct ArenaInner {
    slab_lists: [SlabList; NUM_SIZE_CLASSES],
    metadata: MetadataTable,
    #[cfg(feature = "quarantine")]
    quarantine: crate::hardening::quarantine::QuarantineRing,
}

/// One arena: contains slab lists for every size class, per-arena metadata,
/// and per-arena quarantine. All protected by a single lock.
/// Cache-line aligned to prevent false sharing between arenas.
#[repr(C, align(128))]
pub struct Arena {
    lock: RawMutex,
    inner: UnsafeCell<ArenaInner>,
    arena_index: usize,
}

unsafe impl Send for Arena {}
unsafe impl Sync for Arena {}

impl Arena {
    pub const fn new() -> Self {
        const EMPTY: SlabList = SlabList::new();
        Arena {
            lock: RawMutex::new(),
            inner: UnsafeCell::new(ArenaInner {
                slab_lists: [EMPTY; NUM_SIZE_CLASSES],
                metadata: MetadataTable::new(),
                #[cfg(feature = "quarantine")]
                quarantine: crate::hardening::quarantine::QuarantineRing::new(),
            }),
            arena_index: 0,
        }
    }

    /// Set the arena index (called during init).
    pub fn set_arena_index(&mut self, idx: usize) {
        self.arena_index = idx;
    }

    /// Initialize per-arena metadata table.
    pub unsafe fn init_metadata(&self) -> bool {
        let inner = &mut *self.inner.get();
        inner.metadata.init()
    }

    /// Configure quarantine max_bytes for this arena.
    #[cfg(feature = "quarantine")]
    pub unsafe fn set_quarantine_max_bytes(&self, max: usize) {
        let inner = &mut *self.inner.get();
        inner.quarantine.set_max_bytes(max);
    }

    /// Get allocation metadata (takes arena lock).
    pub unsafe fn get_metadata(&self, ptr: *mut u8) -> Option<AllocationMeta> {
        self.lock.lock();
        let inner = &*self.inner.get();
        let result = inner.metadata.get_unlocked(ptr);
        self.lock.unlock();
        result
    }

    pub unsafe fn alloc(&self, size: usize, class_index: usize) -> *mut u8 {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        let result = Self::alloc_inner(inner, size, class_index, self.arena_index);
        self.lock.unlock();
        result
    }

    unsafe fn alloc_inner(
        inner: &mut ArenaInner,
        size: usize,
        class_index: usize,
        arena_index: usize,
    ) -> *mut u8 {
        let list = &mut inner.slab_lists[class_index];

        // Try to allocate from existing slabs
        let mut slab_ptr = list.head;
        while !slab_ptr.is_null() {
            let slab = &mut *slab_ptr;
            if let Some(ptr) = Self::try_alloc_from_slab(slab, size, &inner.metadata) {
                return ptr;
            }
            slab_ptr = slab.next;
        }

        // Need a new slab -- create it (mmap happens here, still under lock
        // but could be optimized to drop lock for mmap in a future iteration)
        let new_slab = Slab::create(class_index, arena_index);
        if new_slab.is_null() {
            return ptr::null_mut();
        }

        (*new_slab).next = list.head;
        list.head = new_slab;

        Self::try_alloc_from_slab(&mut *new_slab, size, &inner.metadata)
            .unwrap_or(ptr::null_mut())
    }

    unsafe fn try_alloc_from_slab(
        slab: &mut Slab,
        size: usize,
        metadata: &MetadataTable,
    ) -> Option<*mut u8> {
        #[cfg(feature = "slot-randomization")]
        let slot = slab.bitmap.alloc_random(platform::fast_random_u64())?;
        #[cfg(not(feature = "slot-randomization"))]
        let slot = slab.bitmap.alloc_first_free()?;

        let ptr = slab.slot_ptr(slot);
        let slot_sz = size_class::slot_size(slab.class_index);

        #[cfg(feature = "canaries")]
        {
            let canary = crate::hardening::canary::generate_canary(ptr);
            crate::hardening::canary::write_canary(ptr, size, slot_sz, canary);
            metadata.insert_unlocked(ptr, AllocationMeta::new(size, canary));
        }

        #[cfg(not(feature = "canaries"))]
        {
            let _ = slot_sz;
            metadata.insert_unlocked(ptr, AllocationMeta::new(size, 0));
        }

        Some(ptr)
    }

    /// Batch-allocate raw slots for thread cache. Returns the number of slots allocated.
    /// Slots are "allocated" in the bitmap but no metadata is set up.
    /// The caller is responsible for setting up metadata before handing to the user.
    pub unsafe fn alloc_batch_raw(
        &self,
        class_index: usize,
        buf: &mut [crate::allocator::thread_cache::CachedSlot],
        max_count: usize,
    ) -> usize {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        let mut count = 0;

        let list = &mut inner.slab_lists[class_index];

        // Try existing slabs
        let mut slab_ptr = list.head;
        while !slab_ptr.is_null() && count < max_count {
            let slab = &mut *slab_ptr;
            while count < max_count {
                #[cfg(feature = "slot-randomization")]
                let slot_opt = slab.bitmap.alloc_random(platform::fast_random_u64());
                #[cfg(not(feature = "slot-randomization"))]
                let slot_opt = slab.bitmap.alloc_first_free();

                match slot_opt {
                    Some(slot) => {
                        buf[count] = crate::allocator::thread_cache::CachedSlot {
                            ptr: slab.slot_ptr(slot),
                            slab_ptr: slab as *mut Slab as *mut u8,
                            slot_index: slot,
                            class_index,
                            arena_index: self.arena_index,
                        };
                        count += 1;
                    }
                    None => break,
                }
            }
            slab_ptr = slab.next;
        }

        // If we still need more, create a new slab
        if count == 0 {
            let new_slab = Slab::create(class_index, self.arena_index);
            if !new_slab.is_null() {
                (*new_slab).next = list.head;
                list.head = new_slab;
                let slab = &mut *new_slab;
                while count < max_count {
                    #[cfg(feature = "slot-randomization")]
                    let slot_opt = slab.bitmap.alloc_random(platform::fast_random_u64());
                    #[cfg(not(feature = "slot-randomization"))]
                    let slot_opt = slab.bitmap.alloc_first_free();

                    match slot_opt {
                        Some(slot) => {
                            buf[count] = crate::allocator::thread_cache::CachedSlot {
                                ptr: slab.slot_ptr(slot),
                                slab_ptr: slab as *mut Slab as *mut u8,
                                slot_index: slot,
                                class_index,
                                arena_index: self.arena_index,
                            };
                            count += 1;
                        }
                        None => break,
                    }
                }
            }
        }

        self.lock.unlock();
        count
    }

    /// Free a batch of raw slots back to the arena bitmap.
    pub unsafe fn free_batch_raw(
        &self,
        slots: &[crate::allocator::thread_cache::CachedSlot],
        count: usize,
    ) {
        if count == 0 {
            return;
        }
        self.lock.lock();
        for i in 0..count {
            let cached = &slots[i];
            if !cached.slab_ptr.is_null() {
                let slab = &mut *(cached.slab_ptr as *mut Slab);
                slab.bitmap.free_slot(cached.slot_index);
            }
        }
        self.lock.unlock();
    }

    /// Set up metadata for a cached allocation slot.
    /// Canary write is lock-free (per-slot, no contention).
    /// Metadata insertion uses the metadata table's own internal lock.
    pub unsafe fn setup_cached_alloc_metadata(
        &self,
        ptr: *mut u8,
        size: usize,
        class_idx: usize,
    ) {
        let slot_sz = size_class::slot_size(class_idx);

        #[cfg(feature = "canaries")]
        {
            let canary = crate::hardening::canary::generate_canary(ptr);
            crate::hardening::canary::write_canary(ptr, size, slot_sz, canary);
            // Use the locked insert -- no arena lock needed here
            let inner = &*self.inner.get();
            inner.metadata.insert(ptr, AllocationMeta::new(size, canary));
        }

        #[cfg(not(feature = "canaries"))]
        {
            let _ = slot_sz;
            let inner = &*self.inner.get();
            inner.metadata.insert(ptr, AllocationMeta::new(size, 0));
        }
    }

    /// Free a pointer using direct slab info from the page map (O(1) path).
    pub unsafe fn free_direct(&self, slab_raw: *mut u8, ptr: *mut u8) -> bool {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        let slab = &mut *(slab_raw as *mut Slab);
        let result = Self::free_from_slab(inner, slab, ptr);
        self.lock.unlock();
        result
    }

    /// Free a pointer by scanning slabs (fallback O(n) path).
    pub unsafe fn free(&self, ptr: *mut u8) -> bool {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        let result = Self::free_inner(inner, ptr);
        self.lock.unlock();
        result
    }

    /// Batch-free from deferred free buffer: perform security checks + free under one lock.
    pub unsafe fn free_batch_deferred(
        &self,
        slots: &[crate::allocator::thread_cache::CachedSlot],
        count: usize,
    ) {
        if count == 0 {
            return;
        }
        self.lock.lock();
        let inner = &mut *self.inner.get();
        for i in 0..count {
            let cached = &slots[i];
            if !cached.slab_ptr.is_null() {
                let slab = &mut *(cached.slab_ptr as *mut Slab);
                Self::free_from_slab(inner, slab, cached.ptr);
            }
        }
        self.lock.unlock();
    }

    unsafe fn free_inner(inner: &mut ArenaInner, ptr: *mut u8) -> bool {
        for list in &mut inner.slab_lists {
            let mut slab_ptr = list.head;
            while !slab_ptr.is_null() {
                let slab = &mut *slab_ptr;
                if slab.contains(ptr) {
                    return Self::free_from_slab(inner, slab, ptr);
                }
                slab_ptr = slab.next;
            }
        }
        false
    }

    unsafe fn free_from_slab(inner: &mut ArenaInner, slab: &mut Slab, ptr: *mut u8) -> bool {
        let slot_idx = match slab.slot_for_ptr(ptr) {
            Some(s) => s,
            None => return false,
        };

        if let Some(meta) = inner.metadata.get_and_mark_freed_unlocked(ptr) {
            if meta.is_freed() {
                crate::hardening::abort_with_message("compatmalloc: double free detected\n");
            }

            #[cfg(any(feature = "canaries", feature = "poison-on-free"))]
            let slot_sz = size_class::slot_size(slab.class_index);

            #[cfg(feature = "canaries")]
            {
                if !crate::hardening::canary::check_canary(
                    ptr,
                    meta.requested_size,
                    slot_sz,
                    meta.canary_value,
                ) {
                    crate::hardening::abort_with_message(
                        "compatmalloc: heap buffer overflow detected (canary corrupted)\n",
                    );
                }
            }

            // Zero (information leak defense) or poison (UAF detection).
            #[cfg(all(feature = "zero-on-free", not(feature = "poison-on-free")))]
            {
                ptr::write_bytes(ptr, 0, meta.requested_size);
            }

            #[cfg(feature = "poison-on-free")]
            {
                crate::hardening::poison::poison_region(ptr, slot_sz);
            }

            slab.ever_freed.store(true, Ordering::Relaxed);

            #[cfg(feature = "quarantine")]
            {
                use crate::hardening::quarantine::QuarantineEntry;
                let q_entry = QuarantineEntry {
                    ptr,
                    size: slot_sz,
                    slab_ptr: slab as *mut Slab as *mut u8,
                    slot_index: slot_idx,
                    class_index: slab.class_index,
                };
                let metadata = &inner.metadata;
                // Recycle each evicted entry inline via callback -- no entry can be lost
                inner.quarantine.push_enriched(q_entry, |evicted| {
                    Self::recycle_evicted_inline(metadata, evicted);
                });
                return true;
            }
        }

        #[cfg(not(feature = "quarantine"))]
        {
            slab.bitmap.free_slot(slot_idx);
        }

        #[cfg(feature = "quarantine")]
        let _ = slot_idx;

        true
    }

    /// Recycle a quarantine-evicted slot inline (for use in push callback).
    #[cfg(feature = "quarantine")]
    unsafe fn recycle_evicted_inline(
        metadata: &MetadataTable,
        entry: &crate::hardening::quarantine::QuarantineEntry,
    ) {
        let ptr = entry.ptr;

        #[cfg(feature = "write-after-free-check")]
        {
            let slot_sz = size_class::slot_size(entry.class_index);
            if !crate::hardening::poison::check_poison(ptr, slot_sz) {
                crate::hardening::abort_with_message(
                    "compatmalloc: write-after-free detected\n",
                );
            }
        }

        if !entry.slab_ptr.is_null() {
            let slab = &mut *(entry.slab_ptr as *mut Slab);
            slab.bitmap.free_slot(entry.slot_index);
            metadata.remove_unlocked(ptr);
        }
    }

    /// Check if a slab has ever had slots freed (for calloc optimization).
    /// Safe to call without the arena lock -- ever_freed is an AtomicBool.
    pub unsafe fn slab_ever_freed(&self, slab_raw: *mut u8) -> bool {
        let slab = &*(slab_raw as *mut Slab);
        slab.ever_freed.load(Ordering::Relaxed)
    }

    pub unsafe fn usable_size(&self, ptr: *mut u8) -> Option<usize> {
        // Try page map first for O(1) lookup
        if let Some(info) = page_map::lookup(ptr) {
            if !info.is_large() {
                return Some(size_class::slot_size(info.class_index as usize));
            }
        }

        // Fallback: scan
        self.lock.lock();
        let inner = &*self.inner.get();
        let result = Self::usable_size_inner(inner, ptr);
        self.lock.unlock();
        result
    }

    unsafe fn usable_size_inner(inner: &ArenaInner, ptr: *mut u8) -> Option<usize> {
        for list in &inner.slab_lists {
            let mut slab_ptr = list.head;
            while !slab_ptr.is_null() {
                let slab = &*slab_ptr;
                if slab.contains(ptr) {
                    return Some(size_class::slot_size(slab.class_index));
                }
                slab_ptr = slab.next;
            }
        }
        None
    }
}
