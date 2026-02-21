use crate::platform;
use crate::util::{align_up, page_size, DEFAULT_QUARANTINE_BYTES};

/// Default quarantine slots per arena (reduced from 1024 for memory savings).
const DEFAULT_QUARANTINE_SLOTS: usize = 256;

/// Enriched quarantine entry storing slab info for O(1) recycle.
#[derive(Clone, Copy)]
pub struct QuarantineEntry {
    pub ptr: *mut u8,
    pub size: usize,
    /// Pointer to the Slab that owns this slot (null if unknown).
    pub slab_ptr: *mut u8,
    /// Precomputed slot index within the slab.
    pub slot_index: usize,
    /// Size class index for poison checks.
    pub class_index: usize,
}

impl QuarantineEntry {
    #[allow(dead_code)]
    pub const fn empty() -> Self {
        QuarantineEntry {
            ptr: core::ptr::null_mut(),
            size: 0,
            slab_ptr: core::ptr::null_mut(),
            slot_index: 0,
            class_index: 0,
        }
    }
}

/// Quarantine ring buffer. Designed to be embedded directly in an Arena
/// (protected by the arena lock, no separate lock needed).
/// Entries are heap-allocated on init to avoid bloating inactive arenas.
pub struct QuarantineRing {
    entries: *mut QuarantineEntry,
    capacity: usize,
    head: usize,
    tail: usize,
    count: usize,
    total_bytes: usize,
    max_bytes: usize,
}

impl QuarantineRing {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        QuarantineRing {
            entries: core::ptr::null_mut(),
            capacity: 0,
            head: 0,
            tail: 0,
            count: 0,
            total_bytes: 0,
            max_bytes: DEFAULT_QUARANTINE_BYTES,
        }
    }

    /// Lazily allocate the quarantine ring buffer.
    unsafe fn ensure_init(&mut self) {
        if !self.entries.is_null() {
            return;
        }
        let cap = DEFAULT_QUARANTINE_SLOTS;
        let bytes = align_up(cap * core::mem::size_of::<QuarantineEntry>(), page_size());
        let mem = platform::map_anonymous(bytes);
        if mem.is_null() {
            return;
        }
        self.entries = mem as *mut QuarantineEntry;
        self.capacity = cap;
    }

    pub fn set_max_bytes(&mut self, max: usize) {
        self.max_bytes = max;
    }

    /// Push a freed pointer into quarantine with enriched slab info.
    /// Calls `recycle_fn` for each evicted entry so no entries are ever lost.
    /// All evicted entries belong to the same arena (by design of per-arena quarantine).
    ///
    /// # Safety
    /// `entry.ptr` must point to a valid freed slot. `entry.slab_ptr` must be valid.
    pub unsafe fn push_enriched<F>(&mut self, entry: QuarantineEntry, mut recycle_fn: F)
    where
        F: FnMut(&QuarantineEntry),
    {
        self.ensure_init();
        if self.entries.is_null() || self.capacity == 0 {
            // Allocation failed -- recycle immediately
            recycle_fn(&entry);
            return;
        }

        let cap = self.capacity;

        // Evict oldest entries until we have space
        while self.total_bytes + entry.size > self.max_bytes && self.count > 0 {
            let old = *self.entries.add(self.head);
            self.head = (self.head + 1) & (cap - 1);
            self.count -= 1;
            self.total_bytes -= old.size;
            recycle_fn(&old);
        }

        // Also evict if ring buffer is full by count
        if self.count >= cap {
            let old = *self.entries.add(self.head);
            self.head = (self.head + 1) & (cap - 1);
            self.count -= 1;
            self.total_bytes -= old.size;
            recycle_fn(&old);
        }

        // Push new entry
        *self.entries.add(self.tail) = entry;
        self.tail = (self.tail + 1) & (cap - 1);
        self.count += 1;
        self.total_bytes += entry.size;
    }
}
