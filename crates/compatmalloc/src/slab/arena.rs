use crate::hardening::metadata::{AllocationMeta, MetadataTable};
use crate::platform;
use crate::slab::bitmap::SlabBitmap;
use crate::slab::size_class::{self, NUM_SIZE_CLASSES};
use crate::sync::RawMutex;
use crate::util::{align_up, PAGE_SIZE};
use core::cell::UnsafeCell;
use core::ptr;

/// A single slab region for one size class.
struct Slab {
    /// Start of the slot data region.
    data: *mut u8,
    /// Total mapped size (data + bitmap + guard pages if enabled).
    #[allow(dead_code)]
    mapped_size: usize,
    /// Bitmap tracking free/allocated slots.
    bitmap: SlabBitmap,
    /// Size class index.
    class_index: usize,
    /// Next slab in the linked list for this size class (null = end).
    next: *mut Slab,
}

impl Slab {
    /// Allocate a new slab for the given size class.
    unsafe fn create(class_index: usize) -> *mut Slab {
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
        });

        header_ptr
    }

    #[inline]
    unsafe fn slot_ptr(&self, slot: usize) -> *mut u8 {
        let slot_sz = size_class::slot_size(self.class_index);
        self.data.add(slot * slot_sz)
    }

    fn slot_for_ptr(&self, ptr: *mut u8) -> Option<usize> {
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
}

/// One arena: contains slab lists for every size class and a lock.
pub struct Arena {
    lock: RawMutex,
    inner: UnsafeCell<ArenaInner>,
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
            }),
        }
    }

    pub unsafe fn alloc(
        &self,
        size: usize,
        class_index: usize,
        metadata: &MetadataTable,
    ) -> *mut u8 {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        let result = Self::alloc_inner(inner, size, class_index, metadata);
        self.lock.unlock();
        result
    }

    unsafe fn alloc_inner(
        inner: &mut ArenaInner,
        size: usize,
        class_index: usize,
        metadata: &MetadataTable,
    ) -> *mut u8 {
        let list = &mut inner.slab_lists[class_index];

        // Try to allocate from existing slabs
        let mut slab_ptr = list.head;
        while !slab_ptr.is_null() {
            let slab = &mut *slab_ptr;
            if let Some(ptr) = Self::try_alloc_from_slab(slab, size, metadata) {
                return ptr;
            }
            slab_ptr = slab.next;
        }

        // Need a new slab
        let new_slab = Slab::create(class_index);
        if new_slab.is_null() {
            return ptr::null_mut();
        }

        (*new_slab).next = list.head;
        list.head = new_slab;

        Self::try_alloc_from_slab(&mut *new_slab, size, metadata).unwrap_or(ptr::null_mut())
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
            metadata.insert(ptr, AllocationMeta::new(size, canary));
        }

        #[cfg(not(feature = "canaries"))]
        {
            let _ = slot_sz;
            metadata.insert(ptr, AllocationMeta::new(size, 0));
        }

        Some(ptr)
    }

    pub unsafe fn free(
        &self,
        ptr: *mut u8,
        metadata: &MetadataTable,
        #[cfg(feature = "quarantine")] quarantine: &crate::hardening::quarantine::Quarantine,
    ) -> bool {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        let result = Self::free_inner(
            inner,
            ptr,
            metadata,
            #[cfg(feature = "quarantine")]
            quarantine,
        );
        self.lock.unlock();
        result
    }

    unsafe fn free_inner(
        inner: &mut ArenaInner,
        ptr: *mut u8,
        metadata: &MetadataTable,
        #[cfg(feature = "quarantine")] quarantine: &crate::hardening::quarantine::Quarantine,
    ) -> bool {
        for list in &mut inner.slab_lists {
            let mut slab_ptr = list.head;
            while !slab_ptr.is_null() {
                let slab = &mut *slab_ptr;
                if slab.contains(ptr) {
                    return Self::free_from_slab(
                        inner,
                        slab,
                        ptr,
                        metadata,
                        #[cfg(feature = "quarantine")]
                        quarantine,
                    );
                }
                slab_ptr = slab.next;
            }
        }
        false
    }

    unsafe fn free_from_slab(
        inner: &mut ArenaInner,
        slab: &mut Slab,
        ptr: *mut u8,
        metadata: &MetadataTable,
        #[cfg(feature = "quarantine")] quarantine: &crate::hardening::quarantine::Quarantine,
    ) -> bool {
        let _slot = match slab.slot_for_ptr(ptr) {
            Some(s) => s,
            None => return false,
        };

        if let Some(meta) = metadata.get(ptr) {
            if meta.is_freed() {
                crate::hardening::abort_with_message("compatmalloc: double free detected\n");
            }

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

            metadata.mark_freed(ptr);

            // Zero first (information leak defense), then poison (UAF detection).
            // Poison must be last so the write-after-free check sees 0xFE.
            #[cfg(feature = "zero-on-free")]
            {
                ptr::write_bytes(ptr, 0, meta.requested_size);
            }

            #[cfg(feature = "poison-on-free")]
            {
                crate::hardening::poison::poison_region(ptr, slot_sz);
            }

            #[cfg(feature = "quarantine")]
            {
                let evicted = quarantine.push(ptr, slot_sz);
                if let Some((evicted_ptr, _evicted_size)) = evicted {
                    Self::recycle_slot(inner, evicted_ptr, metadata);
                }
                return true;
            }
        }

        #[cfg(not(feature = "quarantine"))]
        {
            let _ = inner;
            slab.bitmap.free_slot(slot);
        }

        true
    }

    unsafe fn recycle_slot(inner: &mut ArenaInner, ptr: *mut u8, metadata: &MetadataTable) {
        #[cfg(feature = "write-after-free-check")]
        {
            // Find the slab to get slot size for poison check
            for list in &inner.slab_lists {
                let mut slab_ptr = list.head;
                while !slab_ptr.is_null() {
                    let slab = &*slab_ptr;
                    if slab.contains(ptr) {
                        let slot_sz = size_class::slot_size(slab.class_index);
                        if !crate::hardening::poison::check_poison(ptr, slot_sz) {
                            crate::hardening::abort_with_message(
                                "compatmalloc: write-after-free detected\n",
                            );
                        }
                    }
                    slab_ptr = slab.next;
                }
            }
        }

        // Find the slab and free the slot
        for list in &mut inner.slab_lists {
            let mut slab_ptr = list.head;
            while !slab_ptr.is_null() {
                let slab = &mut *slab_ptr;
                if slab.contains(ptr) {
                    if let Some(slot) = slab.slot_for_ptr(ptr) {
                        slab.bitmap.free_slot(slot);
                        metadata.remove(ptr);
                        return;
                    }
                }
                slab_ptr = slab.next;
            }
        }

        #[cfg(not(feature = "write-after-free-check"))]
        let _ = inner;
    }

    pub unsafe fn usable_size(&self, ptr: *mut u8) -> Option<usize> {
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
