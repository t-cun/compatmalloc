use crate::hardening::metadata::AllocationMeta;
use crate::platform;
use crate::slab::bitmap::SlabBitmap;
use crate::slab::page_map;
use crate::slab::size_class::{self, NUM_SIZE_CLASSES};
use crate::sync::RawMutex;
use crate::util::align_up;
use core::cell::{Cell, UnsafeCell};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

/// Per-slot metadata stored inline in the slab header.
/// Eliminates all hashing, locking, and backward-shift deletion from the hot path.
/// Field order optimized: u64 first to avoid alignment padding (16 bytes vs 24).
///
/// The `flags` field uses AtomicU8 for race-free double-free detection via CAS.
/// `checksum` and `requested_size` use `Cell` for interior mutability (written
/// through `&self` when bitmap ownership guarantees exclusive access). `Cell`
/// compiles to plain loads/stores — zero overhead vs raw field access.
#[repr(C)]
pub struct SlotMeta {
    pub checksum: Cell<u64>,
    pub requested_size: Cell<u32>,
    pub flags: core::sync::atomic::AtomicU8,
    /// log2(alignment) used for the front-gap calculation.
    /// Stored so check_integrity() can reproduce the correct gap
    /// for memalign/posix_memalign allocations.
    pub align_shift: Cell<u8>,
    _pad: [u8; 2],
}

const SLOT_META_FLAG_FREED: u8 = 0x01;

impl SlotMeta {
    #[allow(dead_code)]
    pub const fn empty() -> Self {
        SlotMeta {
            requested_size: Cell::new(0),
            checksum: Cell::new(0),
            flags: core::sync::atomic::AtomicU8::new(0),
            align_shift: Cell::new(0),
            _pad: [0; 2],
        }
    }

    /// Atomically check if this slot is marked as freed.
    #[inline(always)]
    pub fn is_freed(&self) -> bool {
        self.flags.load(core::sync::atomic::Ordering::Relaxed) & SLOT_META_FLAG_FREED != 0
    }

    /// Atomically mark this slot as freed using CAS.
    /// Returns true if we successfully transitioned from live to freed.
    /// Returns false if already freed (double-free detected).
    #[inline(always)]
    pub fn try_mark_freed(&self) -> bool {
        let old = self
            .flags
            .fetch_or(SLOT_META_FLAG_FREED, core::sync::atomic::Ordering::AcqRel);
        old & SLOT_META_FLAG_FREED == 0
    }

    /// Relaxed-atomic mark-freed for the TLS hot path where single-writer is
    /// guaranteed by thread-cache ownership. Uses Relaxed ordering (not a CAS)
    /// so the compiler emits plain `movzbl` + `test` + `movb` on x86 — same
    /// codegen as non-atomic access, but without the UB of mixing atomic and
    /// non-atomic ops on the same `AtomicU8`.
    ///
    /// # Safety
    /// Caller must guarantee no concurrent *write* to this slot's flags
    /// (e.g., TLS ownership or arena lock held).
    #[inline(always)]
    pub unsafe fn try_mark_freed_fast(&self) -> bool {
        let old = self.flags.load(core::sync::atomic::Ordering::Relaxed);
        if old & SLOT_META_FLAG_FREED != 0 {
            return false;
        }
        self.flags.store(
            old | SLOT_META_FLAG_FREED,
            core::sync::atomic::Ordering::Release,
        );
        true
    }

    #[inline(always)]
    pub fn clear(&self) {
        self.checksum.set(0);
        self.requested_size.set(0);
        self.flags.store(0, core::sync::atomic::Ordering::Relaxed);
        self.align_shift.set(0);
    }

    /// Write helpers using Cell — sound interior mutability without UnsafeCell
    /// casts. Cell::set compiles to a plain store (zero overhead).
    #[inline(always)]
    pub fn checksum_store(&self, val: u64) {
        self.checksum.set(val);
    }

    #[inline(always)]
    pub fn requested_size_store(&self, val: u32) {
        self.requested_size.set(val);
    }
}

/// A single slab region for one size class.
#[repr(C)]
pub struct Slab {
    /// Start of the slot data region.
    pub data: *mut u8,
    /// Total mapped size (data + bitmap + metadata + guard pages if enabled).
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
    /// Per-slot metadata array, co-allocated in the slab header region.
    pub meta: *mut SlotMeta,
}

impl Slab {
    /// Allocate a new slab for the given size class and register it in the page map.
    /// This can be called OUTSIDE the arena lock (4A: slab creation outside lock).
    unsafe fn create(class_index: usize, arena_index: usize) -> *mut Slab {
        let slot_sz = size_class::slot_size(class_index);
        let num_slots = size_class::slots_per_slab(class_index);
        let data_size = num_slots * slot_sz;
        let bitmap_bytes = SlabBitmap::storage_bytes(num_slots);
        let meta_bytes = num_slots * core::mem::size_of::<SlotMeta>();
        let slab_header_size = core::mem::size_of::<Slab>();

        let header_and_bitmap_and_meta = align_up(
            slab_header_size + bitmap_bytes + meta_bytes,
            crate::util::page_size(),
        );
        let data_pages = align_up(data_size, crate::util::page_size());

        #[cfg(feature = "guard-pages")]
        let total_size = crate::util::page_size()
            + header_and_bitmap_and_meta
            + data_pages
            + crate::util::page_size();
        #[cfg(not(feature = "guard-pages"))]
        let total_size = header_and_bitmap_and_meta + data_pages;

        let base = if platform::mte::is_available() {
            platform::mte::map_anonymous_mte(total_size)
        } else {
            platform::map_anonymous(total_size)
        };
        if base.is_null() {
            return ptr::null_mut();
        }

        #[cfg(feature = "guard-pages")]
        {
            platform::protect_none(base, crate::util::page_size());
            platform::protect_none(
                base.add(crate::util::page_size() + header_and_bitmap_and_meta + data_pages),
                crate::util::page_size(),
            );
        }

        #[cfg(feature = "guard-pages")]
        let header_ptr = base.add(crate::util::page_size()) as *mut Slab;
        #[cfg(not(feature = "guard-pages"))]
        let header_ptr = base as *mut Slab;

        let bitmap_storage = (header_ptr as *mut u8).add(slab_header_size) as *mut u64;
        let meta_storage =
            (header_ptr as *mut u8).add(slab_header_size + bitmap_bytes) as *mut SlotMeta;
        let data_ptr = (header_ptr as *mut u8).add(header_and_bitmap_and_meta);

        let bitmap = SlabBitmap::init(bitmap_storage, num_slots);

        // mmap returns zeroed memory, so SlotMeta array is already zero-initialized

        header_ptr.write(Slab {
            data: data_ptr,
            mapped_size: total_size,
            bitmap,
            class_index,
            next: ptr::null_mut(),
            ever_freed: AtomicBool::new(false),
            meta: meta_storage,
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

    /// Get the base address of a slot (start of the slot region).
    ///
    /// # Safety
    /// `slot` must be a valid slot index within this slab.
    #[inline(always)]
    pub unsafe fn slot_base(&self, slot: usize) -> *mut u8 {
        let slot_sz = size_class::slot_size(self.class_index);
        self.data.add(slot * slot_sz)
    }

    /// Get the right-aligned user pointer within a slot.
    /// User data is placed at the end of the slot so forward overflows
    /// hit the guard page (or next slot's front-gap canary).
    ///
    /// Layout: [front_gap][user_data] within slot
    ///
    /// The gap is aligned to `align` to preserve alignment guarantees.
    /// For regular malloc, pass MIN_ALIGN. For memalign, pass the requested alignment.
    ///
    /// # Safety
    /// `slot` must be a valid slot index within this slab.
    #[inline(always)]
    pub unsafe fn slot_user_ptr(
        &self,
        slot: usize,
        requested_size: usize,
        align: usize,
    ) -> *mut u8 {
        let slot_sz = size_class::slot_size(self.class_index);
        let base = self.data.add(slot * slot_sz);
        let aligned_size = align_up(requested_size, crate::util::MIN_ALIGN);
        if aligned_size >= slot_sz {
            base
        } else {
            let gap = crate::util::align_down(slot_sz - aligned_size, align);
            base.add(gap)
        }
    }

    /// Compute slot index from pointer using division-free magic multiply.
    /// Accepts interior pointers (right-aligned user ptrs within a slot).
    #[inline(always)]
    pub fn slot_for_ptr(&self, ptr: *mut u8) -> Option<usize> {
        let offset = ptr as usize - self.data as usize;
        // Use magic multiplier instead of hardware div (~4 cycles vs ~25 cycles)
        // floor(offset / slot_sz) correctly maps any interior pointer to its slot
        let slot = size_class::fast_div_slot(offset, self.class_index);
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
        (start..end).contains(&p)
    }

    /// Get per-slot metadata for a given slot index (no lock needed).
    ///
    /// # Safety
    /// `slot` must be a valid slot index within this slab.
    #[inline(always)]
    pub unsafe fn get_slot_meta(&self, slot: usize) -> &SlotMeta {
        &*self.meta.add(slot)
    }

    /// Get per-slot metadata for a given slot index (mutable-like access).
    /// Since SlotMeta uses interior mutability (AtomicU8 for flags, unsafe writes
    /// for other fields protected by bitmap ownership), &self suffices.
    ///
    /// # Safety
    /// `slot` must be a valid slot index within this slab.
    /// Non-atomic fields must only be written when the bitmap guarantees exclusive access.
    #[inline(always)]
    pub unsafe fn get_slot_meta_ref(&self, slot: usize) -> &SlotMeta {
        &*self.meta.add(slot)
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
    #[cfg(feature = "quarantine")]
    quarantine: crate::hardening::quarantine::QuarantineRing,
}

/// One arena: contains slab lists for every size class and per-arena quarantine.
/// Metadata is stored per-slab inline (no per-arena hash table).
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
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        const EMPTY: SlabList = SlabList::new();
        Arena {
            lock: RawMutex::new(),
            inner: UnsafeCell::new(ArenaInner {
                slab_lists: [EMPTY; NUM_SIZE_CLASSES],
                #[cfg(feature = "quarantine")]
                quarantine: crate::hardening::quarantine::QuarantineRing::new(),
            }),
            arena_index: 0,
        }
    }

    /// Reset the arena lock. Only safe in single-threaded post-fork child.
    ///
    /// # Safety
    /// Must only be called from single-threaded post-fork child.
    pub unsafe fn reset_lock(&self) {
        self.lock.force_unlock();
    }

    /// Set the arena index (called during init).
    pub fn set_arena_index(&mut self, idx: usize) {
        self.arena_index = idx;
    }

    /// Initialize per-arena state. With per-slab metadata, no hash table init needed.
    ///
    /// # Safety
    /// Must be called during allocator init before any allocations.
    pub unsafe fn init_metadata(&self) -> bool {
        true
    }

    /// Configure quarantine max_bytes for this arena.
    ///
    /// # Safety
    /// Must be called during init when no other threads are accessing this arena.
    #[cfg(feature = "quarantine")]
    pub unsafe fn set_quarantine_max_bytes(&self, max: usize) {
        let inner = &mut *self.inner.get();
        inner.quarantine.set_max_bytes(max);
    }

    /// Get allocation metadata by looking up per-slab metadata (takes arena lock).
    ///
    /// # Safety
    /// `ptr` must be a valid allocation pointer within this arena.
    pub unsafe fn get_metadata(&self, ptr: *mut u8) -> Option<AllocationMeta> {
        self.lock.lock();
        let inner = &*self.inner.get();
        let result = Self::get_metadata_inner(inner, ptr);
        self.lock.unlock();
        result
    }

    unsafe fn get_metadata_inner(inner: &ArenaInner, ptr: *mut u8) -> Option<AllocationMeta> {
        for list in &inner.slab_lists {
            let mut slab_ptr = list.head;
            while !slab_ptr.is_null() {
                let slab = &*slab_ptr;
                if slab.contains(ptr) {
                    if let Some(slot) = slab.slot_for_ptr(ptr) {
                        let slot_meta = slab.get_slot_meta(slot);
                        let mut alloc_meta = AllocationMeta::new(
                            slot_meta.requested_size.get() as usize,
                            slot_meta.checksum.get(),
                        );
                        if slot_meta.is_freed() {
                            alloc_meta.mark_freed();
                        }
                        return Some(alloc_meta);
                    }
                }
                slab_ptr = slab.next;
            }
        }
        None
    }

    /// Get slot metadata using slab pointer + slot index (lock-free read).
    /// Returns (requested_size, slot_index). Used by hardened.rs for realloc.
    ///
    /// # Safety
    /// `slab_raw` must point to a valid Slab, `ptr` must be within its data region.
    pub unsafe fn get_slot_meta_from_slab(slab_raw: *mut u8, ptr: *mut u8) -> Option<(u32, usize)> {
        let slab = &*(slab_raw as *mut Slab);
        if let Some(slot) = slab.slot_for_ptr(ptr) {
            let meta = slab.get_slot_meta(slot);
            Some((meta.requested_size.get(), slot))
        } else {
            None
        }
    }

    /// # Safety
    /// Caller must ensure the arena has been initialized.
    /// `align` controls the front-gap alignment (MIN_ALIGN for malloc,
    /// requested alignment for memalign).
    pub unsafe fn alloc(&self, size: usize, class_index: usize, align: usize) -> *mut u8 {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        let result = Self::alloc_inner(inner, size, class_index, self.arena_index, align);
        self.lock.unlock();
        result
    }

    unsafe fn alloc_inner(
        inner: &mut ArenaInner,
        size: usize,
        class_index: usize,
        arena_index: usize,
        align: usize,
    ) -> *mut u8 {
        let list = &mut inner.slab_lists[class_index];

        // Try to allocate from existing slabs
        let mut slab_ptr = list.head;
        while !slab_ptr.is_null() {
            let slab = &mut *slab_ptr;
            if let Some(ptr) = Self::try_alloc_from_slab(slab, size, align) {
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

        Self::try_alloc_from_slab(&mut *new_slab, size, align).unwrap_or(ptr::null_mut())
    }

    unsafe fn try_alloc_from_slab(slab: &mut Slab, size: usize, align: usize) -> Option<*mut u8> {
        #[cfg(feature = "slot-randomization")]
        let slot = slab
            .bitmap
            .alloc_random(crate::allocator::thread_cache::fast_random_u64())?;
        #[cfg(not(feature = "slot-randomization"))]
        let slot = slab.bitmap.alloc_first_free()?;

        // Right-aligned: user pointer is at end of slot
        let user_ptr = slab.slot_user_ptr(slot, size, align);

        // Write metadata directly to per-slab array (no hash, no lock)
        let meta = slab.get_slot_meta(slot);

        meta.requested_size_store(size as u32);
        meta.flags.store(0, core::sync::atomic::Ordering::Relaxed);
        meta.align_shift.set(align.trailing_zeros() as u8);

        let slot_base = slab.slot_base(slot);

        // Always compute metadata integrity checksum
        let checksum =
            crate::hardening::integrity::compute_checksum(slot_base as usize, size as u32, 0);
        meta.checksum_store(checksum);

        if crate::platform::mte::is_available() {
            // MTE: tag the entire slot with a random hardware tag.
            // Overflow/underflow detected immediately on access via tag mismatch.
            let slot_sz = size_class::slot_size(slab.class_index);
            let tagged_base = crate::platform::mte::tag_alloc(slot_base);
            crate::platform::mte::tag_region(tagged_base, slot_sz);
            // Apply the same tag to user_ptr
            let tag_bits = tagged_base as usize & (0xFu64 << 56) as usize;
            let user_tagged = ((user_ptr as usize) & !((0xFu64 << 56) as usize)) | tag_bits;
            return Some(user_tagged as *mut u8);
        }

        // Use checksum value as canary for gap fill
        #[cfg(feature = "canaries")]
        {
            let slot_sz = size_class::slot_size(slab.class_index);
            let front_gap = user_ptr as usize - slot_base as usize;
            if front_gap > 0 {
                crate::hardening::canary::write_canary_front(slot_base, front_gap, checksum);
            }
            let effective_slot_sz = slot_sz - front_gap;
            if size < effective_slot_sz {
                crate::hardening::canary::write_canary(user_ptr, size, effective_slot_sz, checksum);
            }
        }

        Some(user_ptr)
    }

    /// Batch-allocate raw slots for thread cache. Returns the number of slots allocated.
    /// Slots are "allocated" in the bitmap but no metadata is set up.
    /// The caller is responsible for setting up metadata before handing to the user.
    /// Stores slot_base in CachedSlot.ptr (size not known during batch fill).
    ///
    /// # Safety
    /// Caller must ensure the arena has been initialized and `buf` is large enough.
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
                let slot_opt = slab
                    .bitmap
                    .alloc_random(crate::allocator::thread_cache::fast_random_u64());
                #[cfg(not(feature = "slot-randomization"))]
                let slot_opt = slab.bitmap.alloc_first_free();

                match slot_opt {
                    Some(slot) => {
                        buf[count] = crate::allocator::thread_cache::CachedSlot {
                            ptr: slab.slot_base(slot),
                            slab_ptr: slab as *mut Slab as *mut u8,
                            slot_index: slot as u16,
                            arena_index: self.arena_index as u8,
                            _pad: 0,
                            cached_size: 0,
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
                    let slot_opt = slab
                        .bitmap
                        .alloc_random(crate::allocator::thread_cache::fast_random_u64());
                    #[cfg(not(feature = "slot-randomization"))]
                    let slot_opt = slab.bitmap.alloc_first_free();

                    match slot_opt {
                        Some(slot) => {
                            buf[count] = crate::allocator::thread_cache::CachedSlot {
                                ptr: slab.slot_base(slot),
                                slab_ptr: slab as *mut Slab as *mut u8,
                                slot_index: slot as u16,
                                arena_index: self.arena_index as u8,
                                _pad: 0,
                                cached_size: 0,
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
    ///
    /// # Safety
    /// All slots in `slots` must be valid previously-allocated slots.
    #[allow(dead_code)]
    pub unsafe fn free_batch_raw(
        &self,
        slots: &[crate::allocator::thread_cache::CachedSlot],
        count: usize,
    ) {
        if count == 0 {
            return;
        }
        self.lock.lock();
        for cached in slots.iter().take(count) {
            if !cached.slab_ptr.is_null() {
                let slab = &mut *(cached.slab_ptr as *mut Slab);
                slab.bitmap.free_slot(cached.slot_index as usize);
            }
        }
        self.lock.unlock();
    }

    /// Set up metadata for a cached allocation slot and compute the right-aligned user pointer.
    /// Writes directly to per-slab inline metadata -- NO lock needed.
    /// Returns the right-aligned user pointer.
    /// `align` controls the gap alignment (MIN_ALIGN for regular malloc, requested alignment for memalign).
    /// `is_realloc`: when true, skip clearing stale canary bytes (the realloc caller
    /// copies data first and clears the newly exposed region itself).
    ///
    /// # Safety
    /// `slab_raw` must point to a valid Slab, `slot_base_ptr` must be the slot's base address.
    #[inline(always)]
    pub unsafe fn setup_cached_alloc_metadata(
        &self,
        slab_raw: *mut u8,
        slot_index: u16,
        size: usize,
        class_idx: usize,
        align: usize,
        is_realloc: bool,
    ) -> *mut u8 {
        let _ = is_realloc;
        let slab = &*(slab_raw as *mut Slab);
        let meta = slab.get_slot_meta_ref(slot_index as usize);

        let slot_sz = size_class::slot_size(class_idx);
        let slot_base_ptr = slab.data.add(slot_index as usize * slot_sz);

        // Fast path: when aligned_size >= slot_sz (very common: 16, 32, 64, 128...),
        // gap is zero, user_ptr == slot_base. Skip alignment/gap computation.
        let aligned_size = align_up(size, crate::util::MIN_ALIGN);
        if aligned_size >= slot_sz {
            // Clear the user-visible region of recycled slots to remove stale
            // canary bytes from a previous allocation. Canary writes below will
            // fill [size, slot_sz); this zeros [0, size).
            // Skipped for realloc: the caller copies data first, then clears.
            #[cfg(feature = "canaries")]
            if !is_realloc {
                core::ptr::write_bytes(slot_base_ptr, 0, size.min(slot_sz));
            }

            meta.requested_size_store(size as u32);
            meta.flags.store(0, core::sync::atomic::Ordering::Relaxed);
            meta.align_shift.set(align.trailing_zeros() as u8);
            let checksum = crate::hardening::integrity::compute_checksum(
                slot_base_ptr as usize,
                size as u32,
                0,
            );
            meta.checksum_store(checksum);

            if crate::platform::mte::is_available() {
                let tagged_base = crate::platform::mte::tag_alloc(slot_base_ptr);
                crate::platform::mte::tag_region(tagged_base, slot_sz);
                let tag_bits = tagged_base as usize & (0xFu64 << 56) as usize;
                let result = ((slot_base_ptr as usize) & !((0xFu64 << 56) as usize)) | tag_bits;
                return result as *mut u8;
            }

            // Still need back-gap canary when requested_size < slot_size
            // (e.g., malloc(49) with slot_size=64: gap=0 but 15 bytes of back canary).
            // Skipped for realloc: canary must be written AFTER the caller copies data,
            // otherwise the copy may read canary bytes from the source region when the
            // user pointer shifts within the slot.
            #[cfg(feature = "canaries")]
            if !is_realloc && size < slot_sz {
                crate::hardening::canary::write_canary(slot_base_ptr, size, slot_sz, checksum);
            }
            return slot_base_ptr;
        }

        // Slow path: compute gap for right-alignment and canary regions
        let gap = crate::util::align_down(slot_sz - aligned_size, align);
        let user_ptr = slot_base_ptr.add(gap);

        // Clear the user-visible region (same rationale as fast path).
        #[cfg(feature = "canaries")]
        if !is_realloc {
            core::ptr::write_bytes(user_ptr, 0, size);
        }

        meta.requested_size_store(size as u32);
        meta.flags.store(0, core::sync::atomic::Ordering::Relaxed);
        meta.align_shift.set(align.trailing_zeros() as u8);

        let checksum =
            crate::hardening::integrity::compute_checksum(slot_base_ptr as usize, size as u32, 0);
        meta.checksum_store(checksum);

        if crate::platform::mte::is_available() {
            let tagged_base = crate::platform::mte::tag_alloc(slot_base_ptr);
            crate::platform::mte::tag_region(tagged_base, slot_sz);
            let tag_bits = tagged_base as usize & (0xFu64 << 56) as usize;
            let result = ((user_ptr as usize) & !((0xFu64 << 56) as usize)) | tag_bits;
            return result as *mut u8;
        }

        // Write canary bytes in the gap regions.
        // Skipped for realloc: canary must be written AFTER the caller copies data.
        #[cfg(feature = "canaries")]
        if !is_realloc {
            if gap > 0 {
                crate::hardening::canary::write_canary_front(slot_base_ptr, gap, checksum);
            }
            let effective_slot_sz = slot_sz - gap;
            if size < effective_slot_sz {
                crate::hardening::canary::write_canary(user_ptr, size, effective_slot_sz, checksum);
            }
        }

        user_ptr
    }

    /// Free a pointer using direct slab info from the page map (O(1) path).
    ///
    /// # Safety
    /// `slab_raw` must point to a valid Slab, `ptr` must be within its data region.
    #[allow(dead_code)]
    pub unsafe fn free_direct(&self, slab_raw: *mut u8, ptr: *mut u8) -> bool {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        let slab = &mut *(slab_raw as *mut Slab);
        let result = Self::free_from_slab(inner, slab, ptr);
        self.lock.unlock();
        result
    }

    /// Free a pointer by scanning slabs (fallback O(n) path).
    ///
    /// # Safety
    /// `ptr` must be a valid allocation pointer within this arena.
    pub unsafe fn free(&self, ptr: *mut u8) -> bool {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        let result = Self::free_inner(inner, ptr);
        self.lock.unlock();
        result
    }

    /// Free a pointer whose security checks have already been done eagerly.
    /// Only does poison + quarantine/bitmap under the arena lock.
    ///
    /// # Safety
    /// `slab_raw` must be a valid Slab, `slot_idx` must be a valid slot index.
    pub unsafe fn free_direct_prechecked(&self, slab_raw: *mut u8, ptr: *mut u8, slot_idx: usize) {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        let slab = &mut *(slab_raw as *mut Slab);
        Self::free_from_slab_prechecked(inner, slab, ptr, slot_idx);
        self.lock.unlock();
    }

    /// Batch-free from deferred free buffer. Security checks (canary, double-free)
    /// have already been done eagerly. Only does poison + quarantine/bitmap.
    ///
    /// # Safety
    /// All slots in `slots` must be valid previously-allocated slots with checks done.
    #[allow(dead_code)]
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
        for cached in slots.iter().take(count) {
            if !cached.slab_ptr.is_null() {
                let slab = &mut *(cached.slab_ptr as *mut Slab);
                Self::free_from_slab_prechecked(
                    inner,
                    slab,
                    cached.ptr,
                    cached.slot_index as usize,
                );
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

    #[allow(unused_variables)]
    unsafe fn free_from_slab(inner: &mut ArenaInner, slab: &mut Slab, ptr: *mut u8) -> bool {
        let slot_idx = match slab.slot_for_ptr(ptr) {
            Some(s) => s,
            None => return false,
        };

        let meta = slab.get_slot_meta_ref(slot_idx);

        // Atomic CAS double-free detection (race-free)
        if !meta.try_mark_freed() {
            crate::hardening::abort_with_message("compatmalloc: double free detected\n");
        }

        let slot_sz = size_class::slot_size(slab.class_index);
        let slot_base = slab.slot_base(slot_idx);

        // Verify metadata integrity checksum (mask out freed bit we just set)
        if !crate::hardening::integrity::verify_checksum(
            slot_base as usize,
            meta.requested_size.get(),
            meta.flags.load(core::sync::atomic::Ordering::Relaxed) & !0x01,
            meta.checksum.get(),
        ) {
            crate::hardening::abort_with_message("compatmalloc: metadata integrity check failed\n");
        }

        if crate::platform::mte::is_available() {
            // MTE: re-tag the slot with a new random tag.
            // Any dangling pointers with the old tag will fault on access.
            // This replaces: canary check, poison fill, zero-on-free.
            crate::platform::mte::tag_freed(slot_base, slot_sz);
        } else {
            #[cfg(feature = "canaries")]
            {
                let requested_size = meta.requested_size.get() as usize;
                let front_gap = ptr as usize - slot_base as usize;
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
                if requested_size < effective_slot_sz
                    && !crate::hardening::canary::check_canary(
                        ptr,
                        requested_size,
                        effective_slot_sz,
                        meta.checksum.get(),
                    )
                {
                    crate::hardening::abort_with_message(
                        "compatmalloc: heap buffer overflow detected (canary corrupted)\n",
                    );
                }
            }

            // Zero (information leak defense) or poison (UAF detection).
            // Use slot_base for full slot coverage.
            #[cfg(all(feature = "zero-on-free", not(feature = "poison-on-free")))]
            {
                ptr::write_bytes(slot_base, 0, slot_sz);
            }

            #[cfg(feature = "poison-on-free")]
            {
                crate::hardening::poison::poison_region(slot_base, slot_sz);
            }
        }

        if !slab.ever_freed.load(Ordering::Relaxed) {
            slab.ever_freed.store(true, Ordering::Release);
        }

        #[cfg(feature = "quarantine")]
        {
            use crate::hardening::quarantine::QuarantineEntry;
            let q_entry = QuarantineEntry {
                ptr: slot_base,
                size: size_class::slot_size(slab.class_index),
                slab_ptr: slab as *mut Slab as *mut u8,
                slot_index: slot_idx,
                class_index: slab.class_index,
            };
            // Recycle each evicted entry inline via callback -- no entry can be lost
            inner.quarantine.push_enriched(q_entry, |evicted| {
                Self::recycle_evicted_inline(evicted);
            });
        }

        #[cfg(not(feature = "quarantine"))]
        {
            // Clear metadata and free the slot
            meta.clear();
            slab.bitmap.free_slot(slot_idx);
        }

        true
    }

    /// Free a slot whose security checks (canary, double-free, poison, ever_freed)
    /// have already been done eagerly. Only does quarantine/bitmap under the arena lock.
    unsafe fn free_from_slab_prechecked(
        inner: &mut ArenaInner,
        slab: &mut Slab,
        _ptr: *mut u8,
        slot_idx: usize,
    ) {
        #[cfg(feature = "quarantine")]
        {
            use crate::hardening::quarantine::QuarantineEntry;
            // Use slot_base (not user pointer) so poison checks cover the full slot
            let slot_base = slab.slot_base(slot_idx);
            let q_entry = QuarantineEntry {
                ptr: slot_base,
                size: size_class::slot_size(slab.class_index),
                slab_ptr: slab as *mut Slab as *mut u8,
                slot_index: slot_idx,
                class_index: slab.class_index,
            };
            inner.quarantine.push_enriched(q_entry, |evicted| {
                Self::recycle_evicted_inline(evicted);
            });
        }

        #[cfg(not(feature = "quarantine"))]
        {
            slab.get_slot_meta_ref(slot_idx).clear();
            slab.bitmap.free_slot(slot_idx);
        }

        let _ = inner;
    }

    /// Recycle a quarantine-evicted slot inline (for use in push callback).
    #[cfg(feature = "quarantine")]
    unsafe fn recycle_evicted_inline(entry: &crate::hardening::quarantine::QuarantineEntry) {
        let ptr = entry.ptr;

        // Skip poison check when MTE is active: poison bytes were not written
        // (MTE re-tagging replaces poison fill), so check_poison would always fail.
        // MTE's hardware tag mismatch provides equivalent UAF detection.
        #[cfg(feature = "write-after-free-check")]
        if !crate::platform::mte::is_available() {
            let slot_sz = size_class::slot_size(entry.class_index);
            if !crate::hardening::poison::check_poison(ptr, slot_sz) {
                crate::hardening::abort_with_message("compatmalloc: write-after-free detected\n");
            }
        }

        let _ = ptr;

        if !entry.slab_ptr.is_null() {
            let slab = &mut *(entry.slab_ptr as *mut Slab);
            slab.get_slot_meta_ref(entry.slot_index).clear();
            slab.bitmap.free_slot(entry.slot_index);

            // If slab is fully empty, return physical pages to kernel
            if slab.bitmap.free_count() == slab.bitmap.num_slots() {
                let data_size = size_class::slots_per_slab(entry.class_index)
                    * size_class::slot_size(entry.class_index);
                let data_pages = crate::util::align_up(data_size, crate::util::page_size());
                crate::platform::advise_free(slab.data, data_pages);
            }
        }
    }

    /// Check if a slab has ever had slots freed (for calloc optimization).
    /// Safe to call without the arena lock -- ever_freed is an AtomicBool.
    ///
    /// # Safety
    /// `slab_raw` must point to a valid Slab.
    pub unsafe fn slab_ever_freed(&self, slab_raw: *mut u8) -> bool {
        let slab = &*(slab_raw as *mut Slab);
        slab.ever_freed.load(Ordering::Acquire)
    }

    /// # Safety
    /// `ptr` must be a valid allocation pointer.
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

    /// Scan all slabs in this arena and verify integrity of allocated slots.
    /// Returns an IntegrityResult with counts of errors found.
    ///
    /// # Safety
    /// Caller must ensure the arena has been initialized.
    pub unsafe fn check_integrity(&self) -> crate::hardening::self_check::IntegrityResult {
        use crate::hardening::self_check::IntegrityResult;

        let mut result = IntegrityResult::default();

        self.lock.lock();
        let inner = &*self.inner.get();

        for list in &inner.slab_lists {
            let mut slab_ptr = list.head;
            while !slab_ptr.is_null() {
                let slab = &*slab_ptr;
                result.total_slabs += 1;

                #[allow(unused_variables)]
                let slot_sz = size_class::slot_size(slab.class_index);
                let num_slots = size_class::slots_per_slab(slab.class_index);

                for slot in 0..num_slots {
                    let is_allocated = slab.bitmap.is_allocated(slot);
                    let meta = slab.get_slot_meta(slot);

                    if !is_allocated {
                        // Free slot: metadata should be cleared
                        if meta.requested_size.get() != 0 && !meta.is_freed() {
                            result.bitmap_inconsistencies += 1;
                            result.errors_found += 1;
                        }
                        continue;
                    }

                    // Skip pre-allocated thread-cache slots whose metadata
                    // hasn't been initialized. alloc_batch_raw() marks slots
                    // as allocated in the bitmap but defers metadata setup to
                    // setup_cached_alloc_metadata() when actually used.
                    // requested_size is always >= 1 for real allocations
                    // (malloc(0) becomes malloc(1)), so 0 means uninitialized.
                    if meta.requested_size.get() == 0 {
                        continue;
                    }

                    result.total_slots_checked += 1;

                    if meta.is_freed() {
                        // Allocated in bitmap but marked freed in metadata
                        // This is valid if in quarantine, so only count as inconsistency
                        // if quarantine is not enabled
                        #[cfg(not(feature = "quarantine"))]
                        {
                            result.bitmap_inconsistencies += 1;
                            result.errors_found += 1;
                        }
                        continue;
                    }

                    // Verify metadata integrity checksum
                    let slot_base = slab.slot_base(slot);
                    if !crate::hardening::integrity::verify_checksum(
                        slot_base as usize,
                        meta.requested_size.get(),
                        meta.flags.load(core::sync::atomic::Ordering::Relaxed),
                        meta.checksum.get(),
                    ) {
                        result.checksum_failures += 1;
                        result.errors_found += 1;
                        continue;
                    }

                    // Verify canary bytes if enabled (skip when MTE is active:
                    // no canary bytes were written, hardware tags handle detection)
                    #[cfg(feature = "canaries")]
                    if !crate::platform::mte::is_available() {
                        let requested_size = meta.requested_size.get() as usize;
                        let aligned_size = align_up(requested_size, crate::util::MIN_ALIGN);
                        // Use the stored alignment (not MIN_ALIGN) to match
                        // the gap computed during allocation. memalign/
                        // posix_memalign use a larger alignment which produces
                        // a different (smaller) front gap.
                        let align = 1usize << meta.align_shift.get().min(30);
                        let gap = if aligned_size >= slot_sz {
                            0
                        } else {
                            crate::util::align_down(slot_sz - aligned_size, align)
                        };
                        // Check front-gap canary
                        if gap > 0
                            && !crate::hardening::canary::check_canary_front(
                                slot_base,
                                gap,
                                meta.checksum.get(),
                            )
                        {
                            result.canary_failures += 1;
                            result.errors_found += 1;
                        }
                        // Check back-gap canary
                        let user_ptr = slot_base.add(gap);
                        let effective_slot_sz = slot_sz - gap;
                        if requested_size < effective_slot_sz
                            && !crate::hardening::canary::check_canary(
                                user_ptr,
                                requested_size,
                                effective_slot_sz,
                                meta.checksum.get(),
                            )
                        {
                            result.canary_failures += 1;
                            result.errors_found += 1;
                        }
                    }
                }

                slab_ptr = slab.next;
            }
        }

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
