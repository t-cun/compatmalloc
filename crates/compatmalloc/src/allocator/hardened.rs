use crate::allocator::thread_cache;
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
        let alloc_size = if size == 0 { 1 } else { size };

        match size_class_index(alloc_size) {
            Some(class_idx) => {
                // Direct TLS access — eliminates outlined closure overhead.
                let state = thread_cache::get_thread_state_raw();
                if !state.is_null() {
                    let s = &mut *state;
                    s.amortized_fork_check();

                    // Ultra-fast: try fast register WITHOUT reentrancy guard.
                    // Safe because fast_reg is a separate field from cache arrays,
                    // and popping it doesn't conflict with cold-path cache management.
                    if !s.fast_reg.ptr.is_null() && s.fast_reg_class as usize == class_idx {
                        let cached = s.fast_reg;
                        s.fast_reg.ptr = ptr::null_mut();
                        let ca = cached.arena_index as usize;
                        if ca < self.num_arenas {
                            if cached.cached_size == alloc_size as u32 {
                                let slab = &*(cached.slab_ptr as *mut crate::slab::arena::Slab);
                                let meta = slab.get_slot_meta_ref(cached.slot_index as usize);
                                meta.flags.store(0, core::sync::atomic::Ordering::Relaxed);
                                return cached.ptr;
                            }
                            return self.arenas[ca].setup_cached_alloc_metadata(
                                cached.slab_ptr,
                                cached.slot_index,
                                alloc_size,
                                class_idx,
                                MIN_ALIGN,
                                false,
                            );
                        }
                    }

                    // Cache/arena paths need reentrancy guard (cold paths call arena methods)
                    if !s.active {
                        s.active = true;
                        let result = self.malloc_from_cache(s, alloc_size, class_idx);
                        s.active = false;
                        if let Some(p) = result {
                            return p;
                        }
                    }
                }
                let arena = self.select_arena();
                arena.alloc(alloc_size, class_idx, MIN_ALIGN)
            }
            None => {
                // Try thread-local large cache first
                let state = thread_cache::get_thread_state_raw();
                if !state.is_null() {
                    let s = &mut *state;
                    if let Some(ptr) = self.malloc_large_from_cache(s, alloc_size) {
                        return ptr;
                    }
                }
                self.large.alloc(alloc_size, &self.large_metadata)
            }
        }
    }

    /// Cache/arena paths: alloc cache → free buffer → cold miss.
    /// Protected by reentrancy guard (s.active) in the caller.
    #[inline(always)]
    unsafe fn malloc_from_cache(
        &self,
        s: &mut thread_cache::ThreadState,
        size: usize,
        class_idx: usize,
    ) -> Option<*mut u8> {
        // Alloc cache pop with same-size fast path
        if let Some(cached) = s.cache.pop(class_idx) {
            let ca = cached.arena_index as usize;
            if ca < self.num_arenas {
                if cached.cached_size == size as u32 {
                    let slab = &*(cached.slab_ptr as *mut crate::slab::arena::Slab);
                    let meta = slab.get_slot_meta_ref(cached.slot_index as usize);
                    meta.flags.store(0, core::sync::atomic::Ordering::Relaxed);
                    return Some(cached.ptr);
                }
                return Some(self.arenas[ca].setup_cached_alloc_metadata(
                    cached.slab_ptr,
                    cached.slot_index,
                    size,
                    class_idx,
                    MIN_ALIGN,
                    false,
                ));
            }
        }

        // Free buffer pop with same-size recycling
        if let Some(cached) = s.cache.pop_free(class_idx) {
            let ca = cached.arena_index as usize;
            if ca < self.num_arenas {
                if cached.cached_size == size as u32 {
                    let slab = &*(cached.slab_ptr as *mut crate::slab::arena::Slab);
                    let meta = slab.get_slot_meta_ref(cached.slot_index as usize);
                    meta.flags.store(0, core::sync::atomic::Ordering::Relaxed);
                    return Some(cached.ptr);
                }
                return Some(self.arenas[ca].setup_cached_alloc_metadata(
                    cached.slab_ptr,
                    cached.slot_index,
                    size,
                    class_idx,
                    MIN_ALIGN,
                    false,
                ));
            }
        }

        // Cold: recycle + batch fill
        self.malloc_cache_miss(s, size, class_idx)
    }

    /// Cold path: recycle free buffer entries and batch-fill from arena.
    #[cold]
    #[inline(never)]
    unsafe fn malloc_cache_miss(
        &self,
        s: &mut thread_cache::ThreadState,
        size: usize,
        class_idx: usize,
    ) -> Option<*mut u8> {
        use crate::allocator::thread_cache::CachedSlot;

        let remaining = s.cache.recycle_frees(class_idx, 32);
        if remaining > 0 {
            self.drain_and_flush(&mut s.cache, class_idx);
        }

        if let Some(cached) = s.cache.pop(class_idx) {
            let ca = cached.arena_index as usize;
            if ca < self.num_arenas {
                return Some(self.arenas[ca].setup_cached_alloc_metadata(
                    cached.slab_ptr,
                    cached.slot_index,
                    size,
                    class_idx,
                    MIN_ALIGN,
                    false,
                ));
            }
        }

        const BATCH_SIZE: usize = 32;
        let mut buf = [CachedSlot {
            ptr: ptr::null_mut(),
            slab_ptr: ptr::null_mut(),
            slot_index: 0,
            arena_index: 0,
            _pad: 0,
            cached_size: 0,
        }; BATCH_SIZE];

        let arena_idx = s.arena_index(self.num_arenas);
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
            size,
            class_idx,
            MIN_ALIGN,
            false,
        );

        for item in buf.iter().take(n).skip(1) {
            s.cache.push(class_idx, *item);
        }
        Some(user_ptr)
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
                            size,
                            class_idx,
                            align,
                            false,
                        );
                        return Some(user_ptr);
                    }
                }

                // Quick path: pop directly from free buffer (avoids recycle copy overhead
                // in tight malloc/free loops where alloc cache is always empty)
                if let Some(cached) = cache.pop_free(class_idx) {
                    let cached_arena = cached.arena_index as usize;
                    if cached_arena < self.num_arenas {
                        // Same-size recycling: if metadata from the previous alloc matches,
                        // skip all metadata writes + checksum. Just clear the freed bit.
                        // Saves ~8-10 cycles in tight malloc/free loops.
                        if align == MIN_ALIGN {
                            let slab = &*(cached.slab_ptr as *mut crate::slab::arena::Slab);
                            let meta = slab.get_slot_meta_ref(cached.slot_index as usize);
                            if meta.requested_size.get() == size as u32 {
                                meta.flags.store(0, core::sync::atomic::Ordering::Relaxed);
                                return Some(cached.ptr);
                            }
                        }
                        let user_ptr = self.arenas[cached_arena].setup_cached_alloc_metadata(
                            cached.slab_ptr,
                            cached.slot_index,
                            size,
                            class_idx,
                            align,
                            false,
                        );
                        return Some(user_ptr);
                    }
                }

                // Full recycle: move remaining free buffer entries to alloc cache
                let remaining = cache.recycle_frees(class_idx, 32);

                // Verified flush: do deferred security checks then arena processing
                if remaining > 0 {
                    self.drain_and_flush(cache, class_idx);
                }

                // Try again after recycle
                if let Some(cached) = cache.pop(class_idx) {
                    let cached_arena = cached.arena_index as usize;
                    if cached_arena < self.num_arenas {
                        let user_ptr = self.arenas[cached_arena].setup_cached_alloc_metadata(
                            cached.slab_ptr,
                            cached.slot_index,
                            size,
                            class_idx,
                            align,
                            false,
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
                    cached_size: 0,
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
                    size,
                    class_idx,
                    align,
                    false,
                );

                for item in buf.iter().take(n).skip(1) {
                    cache.push(class_idx, *item);
                }
                Some(user_ptr)
            },
            self.num_arenas,
        )?
    }

    /// Try to allocate a large block from the thread-local cache.
    /// Avoids the global lock for mmap, mprotect, and hash table insert on the hot path.
    #[inline(always)]
    unsafe fn malloc_large_from_cache(
        &self,
        s: &mut thread_cache::ThreadState,
        size: usize,
    ) -> Option<*mut u8> {
        if s.large_cache_base.is_null() {
            return None;
        }

        let data_size = crate::util::align_up(size, crate::util::page_size());

        #[cfg(feature = "guard-pages")]
        let needed_total = crate::util::page_size() + data_size + crate::util::page_size();
        #[cfg(not(feature = "guard-pages"))]
        let needed_total = data_size;

        if s.large_cache_total_size < needed_total {
            return None;
        }

        // Take the cached mapping
        let user_ptr = s.large_cache_user_ptr;
        let old_requested_size = s.large_cache_requested_size;
        s.large_cache_base = core::ptr::null_mut();
        s.large_cache_user_ptr = core::ptr::null_mut();

        // Same-thread reuse: data belongs to this thread (no cross-thread leak).
        // Zeroing is deferred to eviction (evict_to_global_cache does MADV_DONTNEED).
        // calloc handles its own zeroing independently via memset.

        // NO page_map::register_large — entry was never unregistered.
        // NO large.lock_and_insert — hash table entry was never removed.

        // Update metadata: clear freed flag, update requested_size and canary.
        #[cfg(feature = "canaries")]
        {
            let canary = crate::hardening::canary::generate_canary(user_ptr);
            self.large_metadata.insert(
                user_ptr,
                crate::hardening::metadata::AllocationMeta::new(size, canary),
            );
        }
        #[cfg(not(feature = "canaries"))]
        {
            self.large_metadata.insert(
                user_ptr,
                crate::hardening::metadata::AllocationMeta::new(size, 0),
            );
        }

        // Update hash table entry's requested_size only if it changed
        // (for malloc_usable_size / realloc correctness). Same-size reuse
        // (the common case in tight loops) skips the global lock entirely.
        if size != old_requested_size {
            self.large.lock_and_update_requested_size(user_ptr, size);
        }

        Some(user_ptr)
    }

    /// Free memory.
    ///
    /// # Safety
    /// `ptr` must be null or previously returned by this allocator and not yet freed.
    pub unsafe fn free(&self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }

        // Direct TLS access — no closure overhead, no reentrancy guard on free.
        // Fork check omitted here: malloc's fork check handles cache invalidation,
        // and parent's addresses are valid in the child (inherited memory).
        let state = thread_cache::get_thread_state_raw();
        if !state.is_null() {
            let s = &mut *state;
            if self.free_to_cache(s, ptr) {
                return;
            }
            // Try thread-local large cache before slow path
            if self.free_large_to_cache(s, ptr) {
                return;
            }
        }

        self.free_slow(ptr);
    }

    /// Inline free fast path: MRU page lookup → CAS double-free → fast register.
    /// Shares cycles with malloc: stores freed slot in fast register for O(1) reuse.
    #[inline(always)]
    unsafe fn free_to_cache(&self, s: &mut thread_cache::ThreadState, ptr: *mut u8) -> bool {
        use crate::allocator::thread_cache::CachedSlot;

        // Page map MRU lookup
        let page = ptr as usize >> 12;
        let (slab_ptr, arena_idx_u8, class_idx_u8) = if s.mru_valid && s.mru_page == page {
            (s.mru_slab_ptr, s.mru_arena_index, s.mru_class_index)
        } else {
            match page_map::lookup(ptr) {
                Some(i) if !i.is_large() => {
                    s.mru_page = page;
                    s.mru_slab_ptr = i.slab_ptr;
                    s.mru_arena_index = i.arena_index;
                    s.mru_class_index = i.class_index;
                    s.mru_valid = true;
                    (i.slab_ptr, i.arena_index, i.class_index)
                }
                _ => return false,
            }
        };

        let arena_idx = arena_idx_u8 as usize;
        if arena_idx >= self.num_arenas {
            return false;
        }

        let slab = &*(slab_ptr as *mut crate::slab::arena::Slab);
        let slot_index = match slab.slot_for_ptr(ptr) {
            Some(si) => si,
            None => return false,
        };
        let meta = slab.get_slot_meta_ref(slot_index);

        // Non-atomic double-free detection: single-writer guaranteed by TLS ownership.
        // Replaces `lock cmpxchg` (~10-15 cycles) with plain load+store (~3 cycles).
        if !meta.try_mark_freed_fast() {
            crate::hardening::abort_with_message("compatmalloc: double free detected\n");
        }

        // Mark ever_freed for calloc optimization (Relaxed load = 1 cycle on x86)
        if !slab.ever_freed.load(core::sync::atomic::Ordering::Relaxed) {
            slab.ever_freed
                .store(true, core::sync::atomic::Ordering::Release);
        }

        // Store in fast register; evict old to free buffer.
        // Hot path (fast_reg empty after malloc pop): write fields directly
        // to fast_reg without intermediate stack copy. Cold path (eviction
        // needed): build CachedSlot and call cold function.
        let cached_size = meta.requested_size.get();
        if s.fast_reg.ptr.is_null() {
            s.fast_reg.ptr = ptr;
            s.fast_reg.slab_ptr = slab_ptr;
            s.fast_reg.slot_index = slot_index as u16;
            s.fast_reg.arena_index = arena_idx_u8;
            s.fast_reg._pad = 0;
            s.fast_reg.cached_size = cached_size;
            s.fast_reg_class = class_idx_u8;
        } else {
            let cached = CachedSlot {
                ptr,
                slab_ptr,
                slot_index: slot_index as u16,
                arena_index: arena_idx_u8,
                _pad: 0,
                cached_size,
            };
            self.free_evict_fast_reg(s, cached, class_idx_u8);
        }

        true
    }

    /// Try to cache a large allocation in the thread-local single-entry cache.
    /// On the hot path: metadata mark-freed + hash table read-only lookup only.
    /// No MADV_DONTNEED, no hash table remove, no page map unregister.
    /// These expensive operations are deferred to eviction (evict_large_cache).
    #[inline(always)]
    unsafe fn free_large_to_cache(&self, s: &mut thread_cache::ThreadState, ptr: *mut u8) -> bool {
        // Check page map to verify this is a large allocation (lock-free)
        match page_map::lookup(ptr) {
            Some(info) if info.is_large() => {}
            _ => return false,
        }

        // Local double-free check: if this pointer is already in our TLS cache
        // (freed but not yet reused), it's an immediate double free.
        if s.large_cache_user_ptr == ptr && !s.large_cache_base.is_null() {
            crate::hardening::abort_with_message("compatmalloc: double free detected (large)\n");
        }

        // Double-free check and mark freed in metadata (single metadata lock).
        // Also captures requested_size to compute mapping dimensions locally,
        // avoiding a separate hash table lookup (saves one lock acquisition).
        let cached_requested_size;
        if let Some(meta) = self.large_metadata.get_and_mark_freed(ptr) {
            if meta.is_freed() {
                crate::hardening::abort_with_message(
                    "compatmalloc: double free detected (large)\n",
                );
            }
            cached_requested_size = meta.requested_size;
        } else {
            return false;
        }

        // Compute mapping dimensions from requested_size and pointer.
        // This avoids acquiring the large lock for a hash table lookup.
        // For oversized mappings (reused from global cache), the computed
        // data_size may be smaller than the actual mapping, causing some
        // cache misses for different-size reuse. Same-size reuse (the
        // common case) always computes correct values.
        let data_size = crate::util::align_up(cached_requested_size, crate::util::page_size());

        #[cfg(feature = "guard-pages")]
        let base = ptr.sub(crate::util::page_size());
        #[cfg(not(feature = "guard-pages"))]
        let base = ptr;

        #[cfg(feature = "guard-pages")]
        let total_size = crate::util::page_size() + data_size + crate::util::page_size();
        #[cfg(not(feature = "guard-pages"))]
        let total_size = data_size;

        // Evict old TLS cache entry if present (full cleanup: hash table remove,
        // page map unregister, MADV_DONTNEED via global cache push).
        if !s.large_cache_base.is_null() {
            self.evict_large_cache(s);
        }

        // Store in thread-local cache. Hash table entry and page map
        // registration are left in place (no remove, no unregister).
        s.large_cache_base = base;
        s.large_cache_total_size = total_size;
        s.large_cache_data_size = data_size;
        s.large_cache_user_ptr = ptr;
        s.large_cache_requested_size = cached_requested_size;

        true
    }

    /// Evict the thread-local large cache entry: full cleanup.
    /// Removes from hash table + page map, pushes mapping to global cache
    /// (which does MADV_DONTNEED for security), and removes metadata.
    #[cold]
    #[inline(never)]
    unsafe fn evict_large_cache(&self, s: &mut thread_cache::ThreadState) {
        let old_ptr = s.large_cache_user_ptr;

        // Remove metadata entry (lock order: metadata lock first)
        self.large_metadata.remove(old_ptr);

        // Look up actual mapping dimensions from hash table, remove entry,
        // and push mapping to global cache (MADV_DONTNEED) — single large lock.
        let actual_data_size = self.large.evict_to_global_cache(old_ptr);

        // Unregister from page map using actual data_size (lock-free atomic stores)
        if actual_data_size > 0 {
            page_map::unregister_large(old_ptr, actual_data_size);
        }

        s.large_cache_base = core::ptr::null_mut();
        s.large_cache_user_ptr = core::ptr::null_mut();
    }

    /// Flush the thread-local large cache during thread exit.
    /// Called from `thread_state_destructor` before the ThreadState is unmapped.
    ///
    /// # Safety
    /// `state` must be a valid pointer to the thread's ThreadState.
    pub(crate) unsafe fn flush_large_cache_on_thread_exit(
        &self,
        state: &mut thread_cache::ThreadState,
    ) {
        self.evict_large_cache(state);
    }

    /// Slow free path: handles large allocations, TLS-unavailable fallback,
    /// and arena scanning. Cold path — not inlined.
    #[cold]
    #[inline(never)]
    unsafe fn free_slow(&self, ptr: *mut u8) {
        // Try page map for large allocation or slab with eager checks
        if let Some(info) = page_map::lookup(ptr) {
            if info.is_large() {
                self.large.free(ptr, &self.large_metadata);
                return;
            }
            let arena_idx = info.arena_index as usize;
            let class_idx = info.class_index as usize;
            if arena_idx < self.num_arenas {
                let slab = &*(info.slab_ptr as *mut crate::slab::arena::Slab);
                let slot_index = match slab.slot_for_ptr(ptr) {
                    Some(s) => s,
                    None => {
                        crate::hardening::abort_with_message(
                            "compatmalloc: free() called on invalid pointer (not a slot boundary)\n",
                        );
                    }
                };
                let meta = slab.get_slot_meta_ref(slot_index);
                if !meta.try_mark_freed() {
                    crate::hardening::abort_with_message("compatmalloc: double free detected\n");
                }
                if !slab.ever_freed.load(core::sync::atomic::Ordering::Relaxed) {
                    slab.ever_freed
                        .store(true, core::sync::atomic::Ordering::Release);
                }
                self.verify_and_free_eager(info.slab_ptr, ptr, slot_index, class_idx, arena_idx);
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

        crate::hardening::abort_with_message(
            "compatmalloc: free() called on invalid pointer (unknown allocation)\n",
        );
    }

    /// Cold path: evict the old fast register to the free buffer, storing the
    /// new cached slot in its place. Separated from the hot path so the compiler
    /// doesn't need to save registers for the drain call across the store.
    #[cold]
    #[inline(never)]
    unsafe fn free_evict_fast_reg(
        &self,
        s: &mut thread_cache::ThreadState,
        new_cached: thread_cache::CachedSlot,
        new_class: u8,
    ) {
        let old_class = s.fast_reg_class as usize;
        s.cache.push_free(old_class, s.fast_reg);
        if s.cache.free_is_full(old_class) {
            self.drain_and_flush(&mut s.cache, old_class);
        }
        s.fast_reg = new_cached;
        s.fast_reg_class = new_class;
    }

    /// Cold path: drain the per-class free buffer and flush it with security
    /// verification. Separated from the hot free path so the 1536-byte drain
    /// buffer is only stack-allocated when actually needed (avoids inflating
    /// the hot path's stack frame from ~64 bytes to ~1560 bytes).
    #[cold]
    #[inline(never)]
    unsafe fn drain_and_flush(&self, cache: &mut thread_cache::ThreadCache, class_index: usize) {
        let (buf, count) = cache.drain_frees_ref(class_index);
        if count > 0 {
            self.flush_free_buffer_verified(buf, count);
        }
    }

    /// Verify deferred security checks for a batch of freed slots, then
    /// hand them to the correct arena for quarantine/bitmap processing.
    /// Each entry is dispatched to its own arena (entries may belong to
    /// different arenas due to cross-thread frees).
    /// Runs at batch boundaries (~every 64 frees), amortizing the cost.
    #[inline(never)]
    unsafe fn flush_free_buffer_verified(
        &self,
        buf: &[crate::allocator::thread_cache::CachedSlot],
        count: usize,
    ) {
        for cached in buf.iter().take(count) {
            if cached.slab_ptr.is_null() {
                continue;
            }
            let slab = &*(cached.slab_ptr as *const crate::slab::arena::Slab);
            let slot_idx = cached.slot_index as usize;
            let meta = slab.get_slot_meta_ref(slot_idx);
            let class_idx = slab.class_index;
            let slot_sz = crate::slab::size_class::slot_size(class_idx);
            let slot_base = slab.data.add(slot_idx * slot_sz);
            // Verify integrity checksum (mask out freed bit)
            let flags_masked = meta.flags.load(core::sync::atomic::Ordering::Relaxed) & !0x01;
            if !crate::hardening::integrity::verify_checksum(
                slot_base as usize,
                meta.requested_size.get(),
                flags_masked,
                meta.checksum.get(),
            ) {
                crate::hardening::abort_with_message(
                    "compatmalloc: metadata integrity check failed\n",
                );
            }

            // Verify canary bytes
            #[cfg(feature = "canaries")]
            {
                let user_ptr = cached.ptr;
                let front_gap = user_ptr as usize - slot_base as usize;
                if front_gap > 0
                    && !crate::hardening::canary::check_canary_front(
                        slot_base,
                        front_gap,
                        meta.checksum.get(),
                    )
                {
                    crate::hardening::abort_with_message(
                        "compatmalloc: heap buffer overflow detected (canary corrupted)\n",
                    );
                }
                let effective_slot_sz = slot_sz - front_gap;
                let req_sz = meta.requested_size.get() as usize;
                if req_sz < effective_slot_sz
                    && !crate::hardening::canary::check_canary(
                        user_ptr,
                        req_sz,
                        effective_slot_sz,
                        meta.checksum.get(),
                    )
                {
                    crate::hardening::abort_with_message(
                        "compatmalloc: heap buffer overflow detected (canary corrupted)\n",
                    );
                }
            }

            // Poison/zero the full slot
            #[cfg(feature = "poison-on-free")]
            {
                crate::hardening::poison::poison_region(slot_base, slot_sz);
            }

            #[cfg(all(feature = "zero-on-free", not(feature = "poison-on-free")))]
            {
                core::ptr::write_bytes(slot_base, 0, slot_sz);
            }

            // Dispatch to the entry's own arena for quarantine/bitmap processing
            let entry_arena = cached.arena_index as usize;
            if entry_arena < self.num_arenas {
                self.arenas[entry_arena].free_direct_prechecked(
                    cached.slab_ptr,
                    cached.ptr,
                    slot_idx,
                );
            }
        }
    }

    /// Eager fallback: verify + poison + free directly when TLS is unavailable.
    /// CAS double-free has already been done by the caller.
    #[cold]
    #[inline(never)]
    unsafe fn verify_and_free_eager(
        &self,
        slab_ptr_raw: *mut u8,
        user_ptr: *mut u8,
        slot_index: usize,
        class_idx: usize,
        arena_idx: usize,
    ) {
        let slab = &*(slab_ptr_raw as *mut crate::slab::arena::Slab);
        let meta = slab.get_slot_meta_ref(slot_index);
        let slot_sz = crate::slab::size_class::slot_size(class_idx);
        let slot_base = slab.data.add(slot_index * slot_sz);

        // Verify integrity checksum
        let flags_masked = meta.flags.load(core::sync::atomic::Ordering::Relaxed) & !0x01;
        if !crate::hardening::integrity::verify_checksum(
            slot_base as usize,
            meta.requested_size.get(),
            flags_masked,
            meta.checksum.get(),
        ) {
            crate::hardening::abort_with_message("compatmalloc: metadata integrity check failed\n");
        }

        // Verify canary bytes
        #[cfg(feature = "canaries")]
        {
            let front_gap = user_ptr as usize - slot_base as usize;
            if front_gap > 0
                && !crate::hardening::canary::check_canary_front(
                    slot_base,
                    front_gap,
                    meta.checksum.get(),
                )
            {
                crate::hardening::abort_with_message(
                    "compatmalloc: heap buffer overflow detected (canary corrupted)\n",
                );
            }
            let effective_slot_sz = slot_sz - front_gap;
            let req_sz = meta.requested_size.get() as usize;
            if req_sz < effective_slot_sz
                && !crate::hardening::canary::check_canary(
                    user_ptr,
                    req_sz,
                    effective_slot_sz,
                    meta.checksum.get(),
                )
            {
                crate::hardening::abort_with_message(
                    "compatmalloc: heap buffer overflow detected (canary corrupted)\n",
                );
            }
        }

        // Poison/zero the full slot
        #[cfg(feature = "poison-on-free")]
        {
            crate::hardening::poison::poison_region(slot_base, slot_sz);
        }

        #[cfg(all(feature = "zero-on-free", not(feature = "poison-on-free")))]
        {
            core::ptr::write_bytes(slot_base, 0, slot_sz);
        }

        // Free directly to arena (prechecked)
        self.arenas[arena_idx].free_direct_prechecked(slab_ptr_raw, user_ptr, slot_index);
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
                                        slot_meta.requested_size.get(),
                                        slot_meta.flags.load(core::sync::atomic::Ordering::Relaxed),
                                        slot_meta.checksum.get(),
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
                                                slot_meta.checksum.get(),
                                            )
                                        {
                                            crate::hardening::abort_with_message(
                                                "compatmalloc: heap buffer overflow detected (canary corrupted in realloc)\n",
                                            );
                                        }
                                        let effective_slot_sz = slot_sz - front_gap;
                                        let req_sz = slot_meta.requested_size.get() as usize;
                                        if req_sz < effective_slot_sz
                                            && !crate::hardening::canary::check_canary(
                                                ptr,
                                                req_sz,
                                                effective_slot_sz,
                                                slot_meta.checksum.get(),
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
                                            new_size,
                                            old_class,
                                            MIN_ALIGN,
                                            true,
                                        );
                                    if new_user_ptr != ptr {
                                        let copy_size = old_size.min(new_size);
                                        // memmove-safe since src/dst may overlap
                                        core::ptr::copy(ptr, new_user_ptr, copy_size);
                                    }
                                    // Clear stale canary bytes in newly exposed region (growing).
                                    // Must happen AFTER copy to avoid destroying user data.
                                    #[cfg(feature = "canaries")]
                                    if new_size > old_size {
                                        core::ptr::write_bytes(
                                            new_user_ptr.add(old_size),
                                            0,
                                            new_size - old_size,
                                        );
                                    }

                                    // Write canaries AFTER the copy (and growing clear).
                                    // setup_cached_alloc_metadata defers canary writes for
                                    // realloc because the copy may read from the canary region
                                    // when the user pointer shifts within the slot.
                                    #[cfg(feature = "canaries")]
                                    {
                                        let slot_sz = crate::slab::size_class::slot_size(old_class);
                                        let front_gap = new_user_ptr as usize - slot_base as usize;
                                        let checksum =
                                            crate::hardening::integrity::compute_checksum(
                                                slot_base as usize,
                                                new_size as u32,
                                                0,
                                            );
                                        if front_gap > 0 {
                                            crate::hardening::canary::write_canary_front(
                                                slot_base, front_gap, checksum,
                                            );
                                        }
                                        let effective_slot_sz = slot_sz - front_gap;
                                        if new_size < effective_slot_sz {
                                            crate::hardening::canary::write_canary(
                                                new_user_ptr,
                                                new_size,
                                                effective_slot_sz,
                                                checksum,
                                            );
                                        }
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
                if let Some((req_size, _slot)) = Arena::get_slot_meta_from_slab(info.slab_ptr, ptr)
                {
                    return req_size as usize;
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
            // Large allocs may come from the mapping cache (dirty pages), so
            // they always need zeroing. Only fresh slab pages can skip.
            let needs_zeroing = if let Some(info) = page_map::lookup(ptr) {
                if info.is_large() {
                    true
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
                    if let Some((req_size, _slot)) =
                        Arena::get_slot_meta_from_slab(info.slab_ptr, ptr)
                    {
                        return req_size as usize;
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
            return arena.alloc(alloc_size, class_idx, alignment);
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
