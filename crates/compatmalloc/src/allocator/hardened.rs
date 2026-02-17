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
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        #[allow(clippy::declare_interior_mutable_const)]
        const ARENA: Arena = Arena::new();
        HardenedAllocator {
            arenas: [ARENA; MAX_ARENAS],
            num_arenas: 1,
            large: LargeAllocator::new(),
            large_metadata: MetadataTable::new(),
        }
    }

    /// Initialize the allocator. Must be called before any allocations.
    ///
    /// # Safety
    /// Must be called exactly once before any allocations are made.
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
            cpus.clamp(1, MAX_ARENAS)
        };

        // Set arena indices (per-slab metadata needs no init)
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
        let tid = crate::allocator::thread_cache::thread_id();
        let idx = platform::splitmix64(tid as u64) as usize % self.num_arenas;
        &self.arenas[idx]
    }

    /// Allocate memory.
    ///
    /// # Safety
    /// Caller must ensure the allocator has been initialized.
    pub unsafe fn malloc(&self, size: usize) -> *mut u8 {
        // malloc(0) returns a unique non-NULL pointer
        let alloc_size = if size == 0 { 1 } else { size };

        match size_class_index(alloc_size) {
            Some(class_idx) => {
                // Thread cache fast path: try to reuse a cached slot
                if let Some(ptr) = self.try_cache_alloc(alloc_size, class_idx, MIN_ALIGN) {
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
    /// On cache miss, first tries to recycle from the free buffer (lock-free!),
    /// then falls back to batch-fill from the arena.
    /// Uses consolidated TLS access (cache + tid + arena_idx) to avoid reentrant TLS.
    #[inline(always)]
    unsafe fn try_cache_alloc(
        &self,
        size: usize,
        class_idx: usize,
        align: usize,
    ) -> Option<*mut u8> {
        use crate::allocator::thread_cache::{self, CachedSlot};

        thread_cache::with_cache_tid_arena(
            |cache, _tid, arena_idx| {
                // Fast path: pop from alloc cache
                if let Some(cached) = cache.pop(class_idx) {
                    let cached_arena = cached.arena_index as usize;
                    if cached_arena < self.num_arenas {
                        let user_ptr = self.arenas[cached_arena].setup_cached_alloc_metadata(
                            cached.slab_ptr,
                            cached.slot_index,
                            cached.ptr,
                            size,
                            class_idx,
                            align,
                        );
                        return Some(user_ptr);
                    }
                }

                // Quick path: pop directly from free buffer (avoids recycle copy overhead
                // in tight malloc/free loops where alloc cache is always empty)
                if let Some(cached) = cache.pop_free(class_idx) {
                    let cached_arena = cached.arena_index as usize;
                    if cached_arena < self.num_arenas {
                        let user_ptr = self.arenas[cached_arena].setup_cached_alloc_metadata(
                            cached.slab_ptr,
                            cached.slot_index,
                            cached.ptr,
                            size,
                            class_idx,
                            align,
                        );
                        return Some(user_ptr);
                    }
                }

                // Full recycle: move remaining free buffer entries to alloc cache
                let remaining = cache.recycle_frees(class_idx, 32);

                // Flush oldest remaining entries to arena for quarantine (amortized)
                if remaining > 0 {
                    let (buf, count) = cache.drain_frees(class_idx);
                    if count > 0 {
                        self.arenas[arena_idx].free_batch_deferred(&buf, count);
                    }
                }

                // Try again after recycle
                if let Some(cached) = cache.pop(class_idx) {
                    let cached_arena = cached.arena_index as usize;
                    if cached_arena < self.num_arenas {
                        let user_ptr = self.arenas[cached_arena].setup_cached_alloc_metadata(
                            cached.slab_ptr,
                            cached.slot_index,
                            cached.ptr,
                            size,
                            class_idx,
                            align,
                        );
                        return Some(user_ptr);
                    }
                }

                // Still empty: batch-fill from arena
                const BATCH_SIZE: usize = 32;
                let mut buf = [CachedSlot {
                    ptr: core::ptr::null_mut(),
                    slab_ptr: core::ptr::null_mut(),
                    slot_index: 0,
                    arena_index: 0,
                    _pad: 0,
                    _pad2: 0,
                }; BATCH_SIZE];

                let arena = &self.arenas[arena_idx];
                let n = arena.alloc_batch_raw(class_idx, &mut buf, BATCH_SIZE);
                if n == 0 {
                    return None;
                }

                let first = buf[0];
                if first.arena_index as usize >= self.num_arenas {
                    return None;
                }
                let user_ptr = self.arenas[first.arena_index as usize].setup_cached_alloc_metadata(
                    first.slab_ptr,
                    first.slot_index,
                    first.ptr,
                    size,
                    class_idx,
                    align,
                );

                for item in buf.iter().take(n).skip(1) {
                    cache.push(class_idx, *item);
                }
                Some(user_ptr)
            },
            self.num_arenas,
        )?
    }

    /// Free memory.
    ///
    /// # Safety
    /// `ptr` must be null or previously returned by this allocator and not yet freed.
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
            // Slab allocation: do eager security checks then defer
            let arena_idx = info.arena_index as usize;
            let class_idx = info.class_index as usize;

            if arena_idx < self.num_arenas {
                // Eager security checks via per-slab metadata (no lock!)
                let slab = &*(info.slab_ptr as *mut crate::slab::arena::Slab);
                let slot_index = match slab.slot_for_ptr(ptr) {
                    Some(s) => s,
                    None => return,
                };
                let meta = slab.get_slot_meta_mut(slot_index);

                if meta.is_freed() {
                    crate::hardening::abort_with_message("compatmalloc: double free detected\n");
                }

                // Compute slot_size once for all checks below.
                // Compute slot_base inline to avoid redundant slot_size lookup
                // inside slab.slot_base().
                let slot_sz = crate::slab::size_class::slot_size(class_idx);
                let slot_base = slab.data.add(slot_index * slot_sz);

                // Always verify metadata integrity checksum
                if !crate::hardening::integrity::verify_checksum(
                    slot_base as usize,
                    meta.requested_size,
                    meta.flags,
                    meta.checksum,
                ) {
                    crate::hardening::abort_with_message(
                        "compatmalloc: metadata integrity check failed\n",
                    );
                }

                #[cfg(feature = "canaries")]
                {
                    let front_gap = ptr as usize - slot_base as usize;
                    if front_gap > 0
                        && !crate::hardening::canary::check_canary_front(
                            slot_base,
                            front_gap,
                            meta.checksum,
                        )
                    {
                        crate::hardening::abort_with_message(
                            "compatmalloc: heap buffer overflow detected (canary corrupted)\n",
                        );
                    }
                    let effective_slot_sz = slot_sz - front_gap;
                    let req_sz = meta.requested_size as usize;
                    if req_sz < effective_slot_sz
                        && !crate::hardening::canary::check_canary(
                            ptr,
                            req_sz,
                            effective_slot_sz,
                            meta.checksum,
                        )
                    {
                        crate::hardening::abort_with_message(
                            "compatmalloc: heap buffer overflow detected (canary corrupted)\n",
                        );
                    }
                }

                // Mark freed eagerly for back-to-back double-free detection
                meta.mark_freed();

                // Poison/zero eagerly using slot_base for full slot coverage
                #[cfg(feature = "poison-on-free")]
                {
                    crate::hardening::poison::poison_region(slot_base, slot_sz);
                }

                #[cfg(all(feature = "zero-on-free", not(feature = "poison-on-free")))]
                {
                    core::ptr::write_bytes(slot_base, 0, slot_sz);
                }

                // Mark ever_freed eagerly for calloc optimization.
                // Check-before-store avoids cache line invalidation when already true
                // (critical for multi-threaded performance).
                if !slab.ever_freed.load(core::sync::atomic::Ordering::Relaxed) {
                    slab.ever_freed
                        .store(true, core::sync::atomic::Ordering::Release);
                }

                // Try to defer the actual bitmap/quarantine work via thread cache
                if self.try_cache_free(slot_base, info.slab_ptr, slot_index, class_idx, arena_idx) {
                    return;
                }

                // TLS not available: fall through to direct arena free (prechecked)
                self.arenas[arena_idx].free_direct_prechecked(info.slab_ptr, ptr, slot_index);
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
    /// Security checks (canary, double-free) have already been done eagerly.
    /// `slot_base` is the pre-computed base address (avoids redundant slot_size lookup).
    /// Returns true if the free was deferred (or flushed).
    #[inline(always)]
    unsafe fn try_cache_free(
        &self,
        slot_base: *mut u8,
        slab_ptr: *mut u8,
        slot_index: usize,
        class_idx: usize,
        arena_idx: usize,
    ) -> bool {
        use crate::allocator::thread_cache::{self, CachedSlot};

        let cached = CachedSlot {
            ptr: slot_base,
            slab_ptr,
            slot_index: slot_index as u16,
            arena_index: arena_idx as u8,
            _pad: 0,
            _pad2: 0,
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
    ///
    /// # Safety
    /// `ptr` must be null or previously returned by this allocator and not yet freed.
    pub unsafe fn realloc(&self, ptr: *mut u8, new_size: usize) -> *mut u8 {
        if ptr.is_null() {
            return self.malloc(new_size);
        }

        // realloc(ptr, 0) is implementation-defined. Treat as realloc(ptr, 1)
        // to avoid returning NULL (which callers interpret as failure, leading to
        // use-after-free of the old pointer).
        let new_size = if new_size == 0 { 1 } else { new_size };

        // Get old size from metadata (check per-slab, then large)
        let old_size = self.get_requested_size(ptr);

        // If the new size fits in the same size class, do in-place realloc.
        // With right-aligned layout the user pointer may shift, so we copy
        // within the slot if needed.
        if let Some(old_class) = size_class_index(old_size) {
            if let Some(new_class) = size_class_index(new_size) {
                if old_class == new_class {
                    if let Some(info) = page_map::lookup(ptr) {
                        if !info.is_large() {
                            let slab = &*(info.slab_ptr as *mut crate::slab::arena::Slab);
                            if let Some(slot_idx) = slab.slot_for_ptr(ptr) {
                                let slot_base = slab.slot_base(slot_idx);

                                // Verify metadata integrity + canary before overwriting
                                {
                                    let slot_meta = slab.get_slot_meta(slot_idx);
                                    if !crate::hardening::integrity::verify_checksum(
                                        slot_base as usize,
                                        slot_meta.requested_size,
                                        slot_meta.flags,
                                        slot_meta.checksum,
                                    ) {
                                        crate::hardening::abort_with_message(
                                            "compatmalloc: metadata integrity check failed in realloc\n",
                                        );
                                    }

                                    #[cfg(feature = "canaries")]
                                    {
                                        let slot_sz = crate::slab::size_class::slot_size(old_class);
                                        let front_gap = ptr as usize - slot_base as usize;
                                        if front_gap > 0
                                            && !crate::hardening::canary::check_canary_front(
                                                slot_base,
                                                front_gap,
                                                slot_meta.checksum,
                                            )
                                        {
                                            crate::hardening::abort_with_message(
                                                "compatmalloc: heap buffer overflow detected (canary corrupted in realloc)\n",
                                            );
                                        }
                                        let effective_slot_sz = slot_sz - front_gap;
                                        let req_sz = slot_meta.requested_size as usize;
                                        if req_sz < effective_slot_sz
                                            && !crate::hardening::canary::check_canary(
                                                ptr,
                                                req_sz,
                                                effective_slot_sz,
                                                slot_meta.checksum,
                                            )
                                        {
                                            crate::hardening::abort_with_message(
                                                "compatmalloc: heap buffer overflow detected (canary corrupted in realloc)\n",
                                            );
                                        }
                                    }
                                }

                                // Compute new user pointer and copy data within slot
                                let arena_idx = info.arena_index as usize;
                                if arena_idx < self.num_arenas {
                                    let new_user_ptr = self.arenas[arena_idx]
                                        .setup_cached_alloc_metadata(
                                            info.slab_ptr,
                                            slot_idx as u16,
                                            slot_base,
                                            new_size,
                                            old_class,
                                            MIN_ALIGN,
                                        );
                                    if new_user_ptr != ptr {
                                        let copy_size = old_size.min(new_size);
                                        // memmove-safe since src/dst may overlap
                                        core::ptr::copy(ptr, new_user_ptr, copy_size);
                                    }
                                    return new_user_ptr;
                                }
                            }
                        }
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

    /// Get the requested size for a pointer (checks per-slab metadata and large allocator).
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
                // Read directly from per-slab metadata (no lock needed for read)
                if let Some((slot_meta, _slot)) = Arena::get_slot_meta_from_slab(info.slab_ptr, ptr)
                {
                    return slot_meta.requested_size as usize;
                }
            }
        }
        self.usable_size(ptr)
    }

    /// Calloc: allocate zeroed memory.
    ///
    /// # Safety
    /// Caller must ensure the allocator has been initialized.
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
    /// When canaries are enabled, returns requested_size (not slot_size) because
    /// the gap between requested_size and slot_size contains canary bytes that
    /// must not be overwritten.
    ///
    /// # Safety
    /// `ptr` must be null or a valid allocation pointer.
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
                #[cfg(feature = "canaries")]
                {
                    // With canaries, the usable region is only the requested_size
                    // because the gap contains canary bytes.
                    if let Some((slot_meta, _slot)) =
                        Arena::get_slot_meta_from_slab(info.slab_ptr, ptr)
                    {
                        return slot_meta.requested_size as usize;
                    }
                }
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
    ///
    /// # Safety
    /// Caller must ensure the allocator has been initialized.
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
            // Use the regular allocation path with this class, passing alignment
            // for correct right-aligned gap computation
            if let Some(ptr) = self.try_cache_alloc(alloc_size, class_idx, alignment) {
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
    ///
    /// # Safety
    /// `ptr` must be a valid allocation pointer.
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

    /// Reset all locks after fork. Only safe in single-threaded post-fork child.
    ///
    /// # Safety
    /// Must only be called from atfork child handler when no other threads exist.
    pub unsafe fn reset_locks_after_fork(&self) {
        for i in 0..self.num_arenas {
            self.arenas[i].reset_lock();
        }
        self.large.reset_lock();
        self.large_metadata.reset_lock();
    }

    /// Scan all arenas and verify integrity of all allocated slots.
    /// Returns an IntegrityResult with counts of errors found.
    ///
    /// # Safety
    /// Caller must ensure the allocator has been initialized.
    pub unsafe fn check_integrity(&self) -> crate::hardening::self_check::IntegrityResult {
        let mut result = crate::hardening::self_check::IntegrityResult::default();
        for i in 0..self.num_arenas {
            let arena_result = self.arenas[i].check_integrity();
            result.merge(&arena_result);
        }
        result
    }

    /// Find the smallest size class where slot_size >= size AND slot_size % alignment == 0.
    fn find_aligned_size_class(size: usize, alignment: usize) -> Option<usize> {
        for (i, &ss) in SIZE_CLASSES.iter().enumerate().take(NUM_SIZE_CLASSES) {
            if ss >= size && ss.is_multiple_of(alignment) {
                return Some(i);
            }
        }
        None
    }
}
