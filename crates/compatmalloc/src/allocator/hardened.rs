use crate::hardening::metadata::StripedMetadata;
use crate::large::LargeAllocator;
use crate::slab::page_map;
use crate::slab::{size_class_index, Arena};
use crate::util::{align_up, MAX_ARENAS, MIN_ALIGN};
use crate::{config, platform};
use core::ptr;

/// The hardened allocator: primary allocation path when enabled.
pub struct HardenedAllocator {
    arenas: [Arena; MAX_ARENAS],
    num_arenas: usize,
    large: LargeAllocator,
    pub metadata: StripedMetadata,
    #[cfg(feature = "quarantine")]
    pub quarantine: crate::hardening::quarantine::Quarantine,
}

unsafe impl Send for HardenedAllocator {}
unsafe impl Sync for HardenedAllocator {}

impl HardenedAllocator {
    pub const fn new() -> Self {
        const ARENA: Arena = Arena::new();
        HardenedAllocator {
            arenas: [ARENA; MAX_ARENAS],
            num_arenas: 1,
            large: LargeAllocator::new(),
            metadata: StripedMetadata::new(),
            #[cfg(feature = "quarantine")]
            quarantine: crate::hardening::quarantine::Quarantine::new(),
        }
    }

    /// Initialize the allocator. Must be called before any allocations.
    pub unsafe fn init(&mut self) -> bool {
        // Initialize the page map
        if !page_map::init() {
            return false;
        }

        // Determine arena count
        let cpus = platform::num_cpus();
        let configured = config::arena_count();
        self.num_arenas = if configured > 0 {
            configured.min(MAX_ARENAS)
        } else {
            cpus.min(MAX_ARENAS).max(1)
        };

        // Set arena indices for page map registration
        for i in 0..self.num_arenas {
            self.arenas[i].set_arena_index(i);
        }

        // Initialize metadata table
        if !self.metadata.init() {
            return false;
        }

        // Configure quarantine
        #[cfg(feature = "quarantine")]
        {
            let qsize = config::quarantine_bytes();
            if qsize > 0 {
                self.quarantine.set_max_bytes(qsize);
            }
        }

        true
    }

    /// Select an arena for the current thread.
    #[inline]
    fn select_arena(&self) -> &Arena {
        let tid = platform::thread_id();
        let idx = tid % self.num_arenas;
        &self.arenas[idx]
    }

    /// Allocate memory.
    pub unsafe fn malloc(&self, size: usize) -> *mut u8 {
        // malloc(0) returns a unique non-NULL pointer
        let alloc_size = if size == 0 { 1 } else { size };

        match size_class_index(alloc_size) {
            Some(class_idx) => {
                // Thread cache fast path: try to reuse a cached slot
                if let Some(ptr) = self.try_cache_alloc(alloc_size, class_idx) {
                    return ptr;
                }
                let arena = self.select_arena();
                arena.alloc(alloc_size, class_idx, &self.metadata)
            }
            None => {
                // Large allocation
                self.large.alloc(alloc_size, &self.metadata)
            }
        }
    }

    /// Try to allocate from the thread cache. Returns the pointer if successful.
    /// On cache miss, batch-fills the cache from the arena for future hits.
    #[inline]
    unsafe fn try_cache_alloc(&self, size: usize, class_idx: usize) -> Option<*mut u8> {
        use crate::allocator::thread_cache::{self, CachedSlot};

        thread_cache::with_thread_cache(|cache| {
            // Fast path: pop from cache
            if let Some(cached) = cache.pop(class_idx) {
                return Some(self.setup_cached_alloc(cached.ptr, size, class_idx));
            }

            // Cache miss: batch-fill from arena
            const BATCH_SIZE: usize = 16;
            let mut buf = [CachedSlot {
                ptr: core::ptr::null_mut(),
                slab_ptr: core::ptr::null_mut(),
                slot_index: 0,
                class_index: 0,
            }; BATCH_SIZE];

            let arena = self.select_arena();
            let n = arena.alloc_batch_raw(class_idx, &mut buf, BATCH_SIZE);
            if n == 0 {
                return None;
            }

            // First slot goes to the caller, rest to the cache
            let result = self.setup_cached_alloc(buf[0].ptr, size, class_idx);
            for i in 1..n {
                cache.push(class_idx, buf[i]);
            }
            Some(result)
        })?
    }

    /// Set up metadata for a cached allocation slot.
    #[inline]
    unsafe fn setup_cached_alloc(&self, ptr: *mut u8, size: usize, class_idx: usize) -> *mut u8 {
        let slot_sz = crate::slab::size_class::slot_size(class_idx);

        #[cfg(feature = "canaries")]
        {
            let canary = crate::hardening::canary::generate_canary(ptr);
            crate::hardening::canary::write_canary(ptr, size, slot_sz, canary);
            self.metadata.insert(
                ptr,
                crate::hardening::metadata::AllocationMeta::new(size, canary),
            );
        }
        #[cfg(not(feature = "canaries"))]
        {
            let _ = slot_sz;
            self.metadata.insert(
                ptr,
                crate::hardening::metadata::AllocationMeta::new(size, 0),
            );
        }

        ptr
    }

    /// Free memory.
    pub unsafe fn free(&self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }

        // Use page map for O(1) dispatch
        if let Some(info) = page_map::lookup(ptr) {
            if info.is_large() {
                self.large.free(ptr, &self.metadata);
                return;
            }
            // Slab allocation: dispatch to the correct arena directly
            let arena_idx = info.arena_index as usize;
            if arena_idx < self.num_arenas {
                self.arenas[arena_idx].free_direct(
                    info.slab_ptr,
                    ptr,
                    &self.metadata,
                    #[cfg(feature = "quarantine")]
                    &self.quarantine,
                );
                return;
            }
        }

        // Fallback: try large allocator then scan arenas
        if self.large.contains(ptr) {
            self.large.free(ptr, &self.metadata);
            return;
        }

        for i in 0..self.num_arenas {
            if self.arenas[i].free(
                ptr,
                &self.metadata,
                #[cfg(feature = "quarantine")]
                &self.quarantine,
            ) {
                return;
            }
        }
    }

    /// Reallocate memory.
    pub unsafe fn realloc(&self, ptr: *mut u8, new_size: usize) -> *mut u8 {
        if ptr.is_null() {
            return self.malloc(new_size);
        }

        if new_size == 0 {
            self.free(ptr);
            return ptr::null_mut();
        }

        // Get old size from metadata
        let old_size = if let Some(meta) = self.metadata.get(ptr) {
            meta.requested_size
        } else if let Some(sz) = self.large.requested_size(ptr) {
            sz
        } else {
            // Unknown pointer -- try usable size
            self.usable_size(ptr)
        };

        // If the new size fits in the same slot, just update metadata
        if new_size <= old_size {
            // For slab allocations, check if it fits in the same size class
            if let Some(old_class) = size_class_index(old_size) {
                if let Some(new_class) = size_class_index(new_size) {
                    if old_class == new_class {
                        // Update metadata
                        #[cfg(feature = "canaries")]
                        {
                            let slot_sz = crate::slab::size_class::slot_size(old_class);
                            let canary = crate::hardening::canary::generate_canary(ptr);
                            crate::hardening::canary::write_canary(ptr, new_size, slot_sz, canary);
                            self.metadata.insert(
                                ptr,
                                crate::hardening::metadata::AllocationMeta::new(new_size, canary),
                            );
                        }
                        #[cfg(not(feature = "canaries"))]
                        {
                            self.metadata.insert(
                                ptr,
                                crate::hardening::metadata::AllocationMeta::new(new_size, 0),
                            );
                        }
                        return ptr;
                    }
                }
            }
        }

        // Allocate new, copy, free old
        let new_ptr = self.malloc(new_size);
        if new_ptr.is_null() {
            return ptr::null_mut();
        }

        let copy_size = old_size.min(new_size);
        ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
        self.free(ptr);

        new_ptr
    }

    /// Calloc: allocate zeroed memory.
    pub unsafe fn calloc(&self, nmemb: usize, size: usize) -> *mut u8 {
        // Check for overflow
        let total = match nmemb.checked_mul(size) {
            Some(t) => t,
            None => {
                // Set errno to ENOMEM
                *libc::__errno_location() = libc::ENOMEM;
                return ptr::null_mut();
            }
        };

        let ptr = self.malloc(total);
        if !ptr.is_null() {
            // Zero the memory (mmap gives us zeroed pages, but slab slots
            // may have been recycled, so we must zero explicitly)
            ptr::write_bytes(ptr, 0, total);
        }
        ptr
    }

    /// Get usable size of an allocation.
    pub unsafe fn usable_size(&self, ptr: *mut u8) -> usize {
        if ptr.is_null() {
            return 0;
        }

        // Use page map for O(1) lookup
        if let Some(info) = page_map::lookup(ptr) {
            if info.is_large() {
                if let Some(sz) = self.large.usable_size(ptr) {
                    return sz;
                }
            } else {
                return crate::slab::size_class::slot_size(info.class_index as usize);
            }
        }

        // Fallback: check large allocator then scan arenas
        if let Some(sz) = self.large.usable_size(ptr) {
            return sz;
        }

        for i in 0..self.num_arenas {
            if let Some(sz) = self.arenas[i].usable_size(ptr) {
                return sz;
            }
        }

        0
    }

    /// Aligned allocation.
    pub unsafe fn memalign(&self, alignment: usize, size: usize) -> *mut u8 {
        if !alignment.is_power_of_two() {
            return ptr::null_mut();
        }

        if alignment <= MIN_ALIGN {
            // Our minimum alignment already satisfies this
            return self.malloc(size);
        }

        // For larger alignments, we over-allocate and return an aligned address.
        // This is simple but wastes some memory. For a production allocator,
        // we'd have dedicated aligned slabs.
        let padded = size + alignment;
        let raw = self.malloc(padded);
        if raw.is_null() {
            return ptr::null_mut();
        }

        let aligned = align_up(raw as usize, alignment) as *mut u8;
        if aligned != raw {
            // Store the original pointer just before the aligned pointer
            // so we can find it on free. We store it in metadata.
            // For now, we just return the aligned pointer and track it in metadata.
            // The arena will find it by checking slab containment.
            //
            // Note: this approach works because arena.free checks slab containment
            // by range, so aligned pointers within a slab are still found.
            // However, we need to update metadata to point to the aligned address.
            self.metadata.remove(raw);
            #[cfg(feature = "canaries")]
            {
                let canary = crate::hardening::canary::generate_canary(aligned);
                self.metadata.insert(
                    aligned,
                    crate::hardening::metadata::AllocationMeta::new(size, canary),
                );
            }
            #[cfg(not(feature = "canaries"))]
            {
                self.metadata.insert(
                    aligned,
                    crate::hardening::metadata::AllocationMeta::new(size, 0),
                );
            }
        }

        aligned
    }
}
