use crate::hardening::metadata::MetadataTable;
use crate::large::LargeAllocator;
use crate::slab::page_map;
use crate::slab::size_class::{NUM_SIZE_CLASSES, SIZE_CLASSES};
use crate::slab::{size_class_index, Arena};
use crate::util::{MAX_ARENAS, MIN_ALIGN};
use crate::{config, platform};
use core::ptr;

/// The hardened allocator: primary allocation path when enabled.
pub struct HardenedAllocator {
    arenas: [Arena; MAX_ARENAS],
    num_arenas: usize,
    large: LargeAllocator,
    /// Metadata table for large allocations only (not per-arena).
    large_metadata: MetadataTable,
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
            large_metadata: MetadataTable::new(),
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

        // Set arena indices and init per-arena metadata
        for i in 0..self.num_arenas {
            self.arenas[i].set_arena_index(i);
            if !self.arenas[i].init_metadata() {
                return false;
            }
        }

        // Initialize large-allocation metadata table
        if !self.large_metadata.init() {
            return false;
        }

        // Configure per-arena quarantine
        #[cfg(feature = "quarantine")]
        {
            let qsize = config::quarantine_bytes();
            if qsize > 0 {
                let per_arena = qsize / self.num_arenas;
                let per_arena = if per_arena == 0 { 1 } else { per_arena };
                for i in 0..self.num_arenas {
                    self.arenas[i].set_quarantine_max_bytes(per_arena);
                }
            }
        }

        true
    }

    /// Select an arena for the current thread using splitmix64(tid).
    #[inline]
    fn select_arena(&self) -> &Arena {
        let tid = platform::thread_id();
        let idx = platform::splitmix64(tid as u64) as usize % self.num_arenas;
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
                arena.alloc(alloc_size, class_idx)
            }
            None => {
                // Large allocation
                self.large.alloc(alloc_size, &self.large_metadata)
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
                let arena_idx = cached.arena_index;
                if arena_idx < self.num_arenas {
                    self.arenas[arena_idx].setup_cached_alloc_metadata(
                        cached.ptr,
                        size,
                        class_idx,
                    );
                    return Some(cached.ptr);
                }
                // Invalid arena index -- skip this slot, fall through to batch fill
            }

            // Cache miss: batch-fill from arena
            const BATCH_SIZE: usize = 16;
            let mut buf = [CachedSlot {
                ptr: core::ptr::null_mut(),
                slab_ptr: core::ptr::null_mut(),
                slot_index: 0,
                class_index: 0,
                arena_index: 0,
            }; BATCH_SIZE];

            let arena = self.select_arena();
            let n = arena.alloc_batch_raw(class_idx, &mut buf, BATCH_SIZE);
            if n == 0 {
                return None;
            }

            // First slot goes to the caller with metadata set up
            let first = buf[0];
            if first.arena_index >= self.num_arenas {
                return None;
            }
            self.arenas[first.arena_index].setup_cached_alloc_metadata(
                first.ptr,
                size,
                class_idx,
            );

            // Rest go to the cache (metadata set up later when popped)
            for i in 1..n {
                cache.push(class_idx, buf[i]);
            }
            Some(first.ptr)
        })?
    }

    /// Free memory.
    pub unsafe fn free(&self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }

        // Use page map for O(1) dispatch
        if let Some(info) = page_map::lookup(ptr) {
            if info.is_large() {
                self.large.free(ptr, &self.large_metadata);
                return;
            }
            // Slab allocation: dispatch to correct arena
            let arena_idx = info.arena_index as usize;

            if arena_idx < self.num_arenas {
                // Direct free to arena (single lock covers metadata + quarantine + bitmap)
                self.arenas[arena_idx].free_direct(info.slab_ptr, ptr);
                return;
            }
        }

        // Fallback: try large allocator then scan arenas
        if self.large.contains(ptr) {
            self.large.free(ptr, &self.large_metadata);
            return;
        }

        for i in 0..self.num_arenas {
            if self.arenas[i].free(ptr) {
                return;
            }
        }
    }

    /// Try to defer a free to the thread-local free buffer.
    /// Returns true if the free was deferred (or flushed).
    /// Currently unused: deferred frees delay security checks (canary, poison, double-free).
    /// Kept as infrastructure for future optimization with immediate security pre-checks.
    #[allow(dead_code)]
    #[inline]
    unsafe fn try_cache_free(
        &self,
        ptr: *mut u8,
        slab_ptr: *mut u8,
        class_idx: usize,
        arena_idx: usize,
    ) -> bool {
        use crate::allocator::thread_cache::{self, CachedSlot};

        let slot_index = {
            let slab = &*(slab_ptr as *mut crate::slab::arena::Slab);
            match slab.slot_for_ptr(ptr) {
                Some(s) => s,
                None => return false,
            }
        };

        let cached = CachedSlot {
            ptr,
            slab_ptr,
            slot_index,
            class_index: class_idx,
            arena_index: arena_idx,
        };

        let result = thread_cache::with_thread_cache(|cache| {
            if cache.free_is_full(class_idx) {
                // Flush the full buffer to arena, then push this one
                let (buf, count) = cache.drain_frees(class_idx);
                self.arenas[arena_idx].free_batch_deferred(&buf, count);
            }
            cache.push_free(class_idx, cached)
        });

        matches!(result, Some(true))
    }

    /// Reallocate memory.
    pub unsafe fn realloc(&self, ptr: *mut u8, new_size: usize) -> *mut u8 {
        if ptr.is_null() {
            return self.malloc(new_size);
        }

        // realloc(ptr, 0) is implementation-defined. Treat as realloc(ptr, 1)
        // to avoid returning NULL (which callers interpret as failure, leading to
        // use-after-free of the old pointer).
        let new_size = if new_size == 0 { 1 } else { new_size };

        // Get old size from metadata (check per-arena, then large)
        let old_size = self.get_requested_size(ptr);

        // If the new size fits in the same slot, just update metadata
        if new_size <= old_size {
            if let Some(old_class) = size_class_index(old_size) {
                if let Some(new_class) = size_class_index(new_size) {
                    if old_class == new_class {
                        // Verify old canary before overwriting
                        #[cfg(feature = "canaries")]
                        {
                            if let Some(info) = page_map::lookup(ptr) {
                                if !info.is_large() {
                                    let arena_idx = info.arena_index as usize;
                                    if arena_idx < self.num_arenas {
                                        if let Some(meta) = self.arenas[arena_idx].get_metadata(ptr) {
                                            let slot_sz = crate::slab::size_class::slot_size(old_class);
                                            if !crate::hardening::canary::check_canary(
                                                ptr, meta.requested_size, slot_sz, meta.canary_value,
                                            ) {
                                                crate::hardening::abort_with_message(
                                                    "compatmalloc: heap buffer overflow detected (canary corrupted in realloc)\n",
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // Update metadata in the correct arena
                        self.update_metadata_for_realloc(ptr, new_size, old_class);
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

    /// Get the requested size for a pointer (checks arena metadata and large allocator).
    unsafe fn get_requested_size(&self, ptr: *mut u8) -> usize {
        if let Some(info) = page_map::lookup(ptr) {
            if info.is_large() {
                if let Some(meta) = self.large_metadata.get(ptr) {
                    return meta.requested_size;
                }
                if let Some(sz) = self.large.requested_size(ptr) {
                    return sz;
                }
            } else {
                let arena_idx = info.arena_index as usize;
                if arena_idx < self.num_arenas {
                    if let Some(meta) = self.arenas[arena_idx].get_metadata(ptr) {
                        return meta.requested_size;
                    }
                }
            }
        }
        self.usable_size(ptr)
    }

    /// Update metadata for in-place realloc (same size class).
    unsafe fn update_metadata_for_realloc(
        &self,
        ptr: *mut u8,
        new_size: usize,
        class_idx: usize,
    ) {
        if let Some(info) = page_map::lookup(ptr) {
            if !info.is_large() {
                let arena_idx = info.arena_index as usize;
                if arena_idx < self.num_arenas {
                    self.arenas[arena_idx].setup_cached_alloc_metadata(
                        ptr, new_size, class_idx,
                    );
                }
            }
        }
    }

    /// Calloc: allocate zeroed memory.
    pub unsafe fn calloc(&self, nmemb: usize, size: usize) -> *mut u8 {
        // Check for overflow
        let total = match nmemb.checked_mul(size) {
            Some(t) => t,
            None => {
                *libc::__errno_location() = libc::ENOMEM;
                return ptr::null_mut();
            }
        };

        let ptr = self.malloc(total);
        if !ptr.is_null() {
            // Optimization: skip zeroing for fresh mmap pages that haven't been freed.
            let needs_zeroing = if let Some(info) = page_map::lookup(ptr) {
                if info.is_large() {
                    // Large allocations are always fresh mmap pages
                    false
                } else {
                    // Check if the slab has ever had slots freed
                    let arena_idx = info.arena_index as usize;
                    if arena_idx < self.num_arenas {
                        self.arenas[arena_idx].slab_ever_freed(info.slab_ptr)
                    } else {
                        true
                    }
                }
            } else {
                true
            };

            if needs_zeroing {
                ptr::write_bytes(ptr, 0, total);
            }
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

        let alloc_size = if size == 0 { 1 } else { size };

        // Find a size class where slot_size >= alloc_size AND slot_size is a multiple
        // of alignment. This ensures all slots are naturally aligned since slab data
        // starts at a page-aligned boundary.
        if let Some(class_idx) = Self::find_aligned_size_class(alloc_size, alignment) {
            // Use the regular allocation path with this class
            if let Some(ptr) = self.try_cache_alloc(alloc_size, class_idx) {
                return ptr;
            }
            let arena = self.select_arena();
            return arena.alloc(alloc_size, class_idx);
        }

        // No suitable slab class: use large allocator (page-aligned via mmap).
        // mmap guarantees PAGE_SIZE alignment; for larger alignments, the caller
        // would need a specialized path, but in practice alignments > PAGE_SIZE
        // are extremely rare and mmap addresses are often naturally over-aligned.
        self.large.alloc(alloc_size, &self.large_metadata)
    }

    /// Get metadata for a pointer (for testing/debugging). Routes to correct arena or large.
    pub unsafe fn get_metadata(
        &self,
        ptr: *mut u8,
    ) -> Option<crate::hardening::metadata::AllocationMeta> {
        if let Some(info) = page_map::lookup(ptr) {
            if info.is_large() {
                return self.large_metadata.get(ptr);
            }
            let arena_idx = info.arena_index as usize;
            if arena_idx < self.num_arenas {
                return self.arenas[arena_idx].get_metadata(ptr);
            }
        }
        None
    }

    /// Find the smallest size class where slot_size >= size AND slot_size % alignment == 0.
    fn find_aligned_size_class(size: usize, alignment: usize) -> Option<usize> {
        for i in 0..NUM_SIZE_CLASSES {
            let ss = SIZE_CLASSES[i];
            if ss >= size && ss % alignment == 0 {
                return Some(i);
            }
        }
        None
    }
}
