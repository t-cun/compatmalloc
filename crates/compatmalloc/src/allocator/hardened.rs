use crate::hardening::metadata::MetadataTable;
use crate::large::LargeAllocator;
use crate::slab::{size_class_index, Arena};
use crate::util::{align_up, MAX_ARENAS, MIN_ALIGN};
use crate::{config, platform};
use core::ptr;

/// The hardened allocator: primary allocation path when enabled.
pub struct HardenedAllocator {
    arenas: [Arena; MAX_ARENAS],
    num_arenas: usize,
    large: LargeAllocator,
    pub metadata: MetadataTable,
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
            metadata: MetadataTable::new(),
            #[cfg(feature = "quarantine")]
            quarantine: crate::hardening::quarantine::Quarantine::new(),
        }
    }

    /// Initialize the allocator. Must be called before any allocations.
    pub unsafe fn init(&mut self) -> bool {
        // Determine arena count
        let cpus = platform::num_cpus();
        let configured = config::arena_count();
        self.num_arenas = if configured > 0 {
            configured.min(MAX_ARENAS)
        } else {
            cpus.min(MAX_ARENAS).max(1)
        };

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
                let arena = self.select_arena();
                arena.alloc(alloc_size, class_idx, &self.metadata)
            }
            None => {
                // Large allocation
                self.large.alloc(alloc_size, &self.metadata)
            }
        }
    }

    /// Free memory.
    pub unsafe fn free(&self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }

        // Try large allocator first (quick check)
        if self.large.contains(ptr) {
            self.large.free(ptr, &self.metadata);
            return;
        }

        // Try each arena
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

        // Pointer not found -- could be from bootstrap allocator or invalid
        // In a hardened allocator we could abort, but for compatibility we ignore.
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

        // Check large allocator
        if let Some(sz) = self.large.usable_size(ptr) {
            return sz;
        }

        // Check arenas
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
