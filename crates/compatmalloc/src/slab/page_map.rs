//! Two-level radix tree mapping virtual page addresses to slab/large allocation info.
//!
//! This provides O(1) lookup from any pointer to the slab (or large allocation) that owns it,
//! eliminating all O(n) scans in free, recycle, and usable_size paths.
//!
//! Level 1: 2^21 entries covering 48-bit address space in 128KB chunks (each L1 entry covers 32 pages)
//! Level 2: lazily allocated, 32 AtomicU64 entries per L1 slot covering individual 4KB pages
//!
//! Each L2 entry packs PageInfo into a single AtomicU64 to eliminate torn reads:
//!   Bit 63: large allocation flag
//!   Bits [16..63): slab_ptr >> 12 (47 bits, covers 59-bit address space)
//!   Bits [8..16): class_index
//!   Bits [0..8): arena_index

use crate::platform;
use crate::util::PAGE_SIZE;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};

/// Sentinel value indicating a large allocation (not a slab).
pub const LARGE_ALLOC_SENTINEL: *mut u8 = usize::MAX as *mut u8;

/// Info stored per page in the page map.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PageInfo {
    /// Pointer to the Slab header (or LARGE_ALLOC_SENTINEL for large allocs).
    pub slab_ptr: *mut u8,
    /// Size class index (meaningless for large allocs).
    pub class_index: u8,
    /// Arena index that owns this slab.
    pub arena_index: u8,
}

impl PageInfo {
    pub const fn empty() -> Self {
        PageInfo {
            slab_ptr: ptr::null_mut(),
            class_index: 0,
            arena_index: 0,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.slab_ptr.is_null()
    }

    #[inline]
    pub fn is_large(&self) -> bool {
        self.slab_ptr == LARGE_ALLOC_SENTINEL
    }
}

/// Bit flag for large allocation in packed u64.
const LARGE_BIT: u64 = 1 << 63;

/// Pack a slab PageInfo into a u64 for atomic storage.
#[inline]
fn pack_slab(slab_ptr: *mut u8, class_index: u8, arena_index: u8) -> u64 {
    let ptr_bits = (slab_ptr as u64) >> 12;
    (ptr_bits << 16) | ((class_index as u64) << 8) | (arena_index as u64)
}

/// Pack a large allocation marker into a u64.
#[inline]
fn pack_large() -> u64 {
    LARGE_BIT
}

/// Unpack a u64 into a PageInfo. Returns None for empty (0).
#[inline]
fn unpack(packed: u64) -> Option<PageInfo> {
    if packed == 0 {
        return None;
    }
    if packed & LARGE_BIT != 0 {
        return Some(PageInfo {
            slab_ptr: LARGE_ALLOC_SENTINEL,
            class_index: 0,
            arena_index: 0,
        });
    }
    let arena_index = (packed & 0xFF) as u8;
    let class_index = ((packed >> 8) & 0xFF) as u8;
    let ptr_bits = packed >> 16;
    let slab_ptr = (ptr_bits << 12) as *mut u8;
    Some(PageInfo {
        slab_ptr,
        class_index,
        arena_index,
    })
}

/// Number of pages covered by each L1 entry.
const L2_SIZE: usize = 32;

/// Number of L1 entries. Uses bits [17..38) of the address (21 bits = 2M entries).
const L1_BITS: usize = 21;
const L1_SIZE: usize = 1 << L1_BITS;

/// A level-2 page map block: 32 AtomicU64 entries for 32 consecutive pages.
#[repr(C)]
struct L2Block {
    entries: [AtomicU64; L2_SIZE],
}

/// The global page map: a two-level radix tree.
pub struct PageMap {
    /// Level-1 table: AtomicPtr to L2Block (null = no mappings in this region).
    l1: *mut AtomicPtr<L2Block>,
    /// Whether the page map has been initialized.
    initialized: AtomicBool,
}

unsafe impl Send for PageMap {}
unsafe impl Sync for PageMap {}

impl PageMap {
    pub const fn new() -> Self {
        PageMap {
            l1: ptr::null_mut(),
            initialized: AtomicBool::new(false),
        }
    }

    /// Initialize the page map. Must be called once before use.
    pub unsafe fn init(&mut self) -> bool {
        let l1_bytes = L1_SIZE * core::mem::size_of::<AtomicPtr<L2Block>>();
        let l1_bytes_aligned = crate::util::align_up(l1_bytes, PAGE_SIZE);
        let mem = platform::map_anonymous(l1_bytes_aligned);
        if mem.is_null() {
            return false;
        }
        // mmap returns zeroed memory, and null pointer is all zeros, so L1 is already initialized
        self.l1 = mem as *mut AtomicPtr<L2Block>;
        self.initialized.store(true, Ordering::Release);
        true
    }

    /// Extract L1 index and L2 index from a pointer.
    #[inline]
    fn indices(ptr: *mut u8) -> (usize, usize) {
        let addr = ptr as usize;
        let page = addr / PAGE_SIZE;
        let l1_idx = (page >> 5) & (L1_SIZE - 1); // bits [5..26) of the page number
        let l2_idx = page & (L2_SIZE - 1); // bits [0..5) of the page number
        (l1_idx, l2_idx)
    }

    /// Get or allocate the L2 block for the given L1 index.
    #[inline]
    unsafe fn get_or_alloc_l2(&self, l1_idx: usize) -> *mut L2Block {
        let slot = &*self.l1.add(l1_idx);
        let l2 = slot.load(Ordering::Acquire);
        if !l2.is_null() {
            return l2;
        }
        self.alloc_l2(l1_idx)
    }

    #[cold]
    unsafe fn alloc_l2(&self, l1_idx: usize) -> *mut L2Block {
        let l2_bytes = core::mem::size_of::<L2Block>();
        let l2_bytes_aligned = crate::util::align_up(l2_bytes, PAGE_SIZE);
        let mem = platform::map_anonymous(l2_bytes_aligned);
        if mem.is_null() {
            return ptr::null_mut();
        }
        // mmap returns zeroed memory; AtomicU64(0) = empty entry, which is correct
        let new_l2 = mem as *mut L2Block;
        let slot = &*self.l1.add(l1_idx);
        // Try to install our new block; if someone else beat us, use theirs
        match slot.compare_exchange(ptr::null_mut(), new_l2, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => new_l2,
            Err(existing) => {
                platform::unmap(mem, l2_bytes_aligned);
                existing
            }
        }
    }

    /// Register a range of pages as belonging to a slab.
    pub unsafe fn register_slab(
        &self,
        data_start: *mut u8,
        data_size: usize,
        slab_ptr: *mut u8,
        class_index: usize,
        arena_index: usize,
    ) {
        if !self.initialized.load(Ordering::Relaxed) {
            return;
        }
        let packed = pack_slab(slab_ptr, class_index as u8, arena_index as u8);
        let num_pages = (data_size + PAGE_SIZE - 1) / PAGE_SIZE;
        for i in 0..num_pages {
            let page_addr = data_start.add(i * PAGE_SIZE);
            let (l1_idx, l2_idx) = Self::indices(page_addr);
            let l2 = self.get_or_alloc_l2(l1_idx);
            if !l2.is_null() {
                (*l2).entries[l2_idx].store(packed, Ordering::Release);
            }
        }
    }

    /// Register a large allocation's pages.
    pub unsafe fn register_large(&self, user_ptr: *mut u8, data_size: usize) {
        if !self.initialized.load(Ordering::Relaxed) {
            return;
        }
        let packed = pack_large();
        let num_pages = (data_size + PAGE_SIZE - 1) / PAGE_SIZE;
        for i in 0..num_pages {
            let page_addr = user_ptr.add(i * PAGE_SIZE);
            let (l1_idx, l2_idx) = Self::indices(page_addr);
            let l2 = self.get_or_alloc_l2(l1_idx);
            if !l2.is_null() {
                (*l2).entries[l2_idx].store(packed, Ordering::Release);
            }
        }
    }

    /// Unregister a large allocation's pages.
    pub unsafe fn unregister_large(&self, user_ptr: *mut u8, data_size: usize) {
        if !self.initialized.load(Ordering::Relaxed) {
            return;
        }
        let num_pages = (data_size + PAGE_SIZE - 1) / PAGE_SIZE;
        for i in 0..num_pages {
            let page_addr = user_ptr.add(i * PAGE_SIZE);
            let (l1_idx, l2_idx) = Self::indices(page_addr);
            let slot = &*self.l1.add(l1_idx);
            let l2 = slot.load(Ordering::Acquire);
            if !l2.is_null() {
                (*l2).entries[l2_idx].store(0, Ordering::Release);
            }
        }
    }

    /// Look up the page info for a pointer. Returns None if the page is not registered.
    #[inline]
    pub unsafe fn lookup(&self, ptr: *mut u8) -> Option<PageInfo> {
        if !self.initialized.load(Ordering::Relaxed) {
            return None;
        }
        let (l1_idx, l2_idx) = Self::indices(ptr);
        let slot = &*self.l1.add(l1_idx);
        let l2 = slot.load(Ordering::Acquire);
        if l2.is_null() {
            return None;
        }
        let packed = (*l2).entries[l2_idx].load(Ordering::Acquire);
        unpack(packed)
    }
}

/// Global page map instance, wrapped for safe static access.
struct PageMapHolder(core::cell::UnsafeCell<PageMap>);
unsafe impl Sync for PageMapHolder {}

static PAGE_MAP: PageMapHolder = PageMapHolder(core::cell::UnsafeCell::new(PageMap::new()));

/// Initialize the global page map.
pub unsafe fn init() -> bool {
    (*PAGE_MAP.0.get()).init()
}

/// Register slab pages in the global page map.
pub unsafe fn register_slab(
    data_start: *mut u8,
    data_size: usize,
    slab_ptr: *mut u8,
    class_index: usize,
    arena_index: usize,
) {
    (*PAGE_MAP.0.get()).register_slab(data_start, data_size, slab_ptr, class_index, arena_index);
}

/// Register large allocation pages.
pub unsafe fn register_large(user_ptr: *mut u8, data_size: usize) {
    (*PAGE_MAP.0.get()).register_large(user_ptr, data_size);
}

/// Unregister large allocation pages.
pub unsafe fn unregister_large(user_ptr: *mut u8, data_size: usize) {
    (*PAGE_MAP.0.get()).unregister_large(user_ptr, data_size);
}

/// Look up page info for a pointer.
#[inline]
pub unsafe fn lookup(ptr: *mut u8) -> Option<PageInfo> {
    (*PAGE_MAP.0.get()).lookup(ptr)
}
