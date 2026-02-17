use crate::util::DEFAULT_QUARANTINE_BYTES;

/// Default quarantine slots per arena.
const QUARANTINE_SLOTS: usize = 1024;

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
pub struct QuarantineRing {
    entries: [QuarantineEntry; QUARANTINE_SLOTS],
    head: usize,
    tail: usize,
    count: usize,
    total_bytes: usize,
    max_bytes: usize,
}

impl QuarantineRing {
    pub const fn new() -> Self {
        QuarantineRing {
            entries: [QuarantineEntry::empty(); QUARANTINE_SLOTS],
            head: 0,
            tail: 0,
            count: 0,
            total_bytes: 0,
            max_bytes: DEFAULT_QUARANTINE_BYTES,
        }
    }

    pub fn set_max_bytes(&mut self, max: usize) {
        self.max_bytes = max;
    }

    /// Push a freed pointer into quarantine with enriched slab info.
    /// Calls `recycle_fn` for each evicted entry so no entries are ever lost.
    /// All evicted entries belong to the same arena (by design of per-arena quarantine).
    pub unsafe fn push_enriched<F>(
        &mut self,
        entry: QuarantineEntry,
        mut recycle_fn: F,
    ) where
        F: FnMut(&QuarantineEntry),
    {
        // Evict oldest entries until we have space
        while self.total_bytes + entry.size > self.max_bytes && self.count > 0 {
            let old = self.entries[self.head];
            self.head = (self.head + 1) % QUARANTINE_SLOTS;
            self.count -= 1;
            self.total_bytes -= old.size;
            recycle_fn(&old);
        }

        // Also evict if ring buffer is full by count
        if self.count >= QUARANTINE_SLOTS {
            let old = self.entries[self.head];
            self.head = (self.head + 1) % QUARANTINE_SLOTS;
            self.count -= 1;
            self.total_bytes -= old.size;
            recycle_fn(&old);
        }

        // Push new entry
        self.entries[self.tail] = entry;
        self.tail = (self.tail + 1) % QUARANTINE_SLOTS;
        self.count += 1;
        self.total_bytes += entry.size;
    }
}

