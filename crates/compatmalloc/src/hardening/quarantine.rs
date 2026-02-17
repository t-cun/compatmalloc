use crate::sync::RawMutex;
use crate::util::DEFAULT_QUARANTINE_BYTES;
use core::cell::UnsafeCell;

const QUARANTINE_SLOTS: usize = 8192;

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

struct QuarantineInner {
    entries: [QuarantineEntry; QUARANTINE_SLOTS],
    head: usize,
    tail: usize,
    count: usize,
    total_bytes: usize,
    max_bytes: usize,
}

/// A quarantine queue that delays reuse of freed memory.
pub struct Quarantine {
    lock: RawMutex,
    inner: UnsafeCell<QuarantineInner>,
}

unsafe impl Send for Quarantine {}
unsafe impl Sync for Quarantine {}

impl Quarantine {
    pub const fn new() -> Self {
        Quarantine {
            lock: RawMutex::new(),
            inner: UnsafeCell::new(QuarantineInner {
                entries: [QuarantineEntry::empty(); QUARANTINE_SLOTS],
                head: 0,
                tail: 0,
                count: 0,
                total_bytes: 0,
                max_bytes: DEFAULT_QUARANTINE_BYTES,
            }),
        }
    }

    pub fn set_max_bytes(&self, max: usize) {
        unsafe {
            (*self.inner.get()).max_bytes = max;
        }
    }

    /// Push a freed pointer into quarantine with enriched slab info.
    /// Returns the evicted entry if the quarantine was full.
    pub unsafe fn push_enriched(&self, entry: QuarantineEntry) -> Option<QuarantineEntry> {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        let mut evicted = None;

        // Evict oldest entries until we have space
        while inner.total_bytes + entry.size > inner.max_bytes && inner.count > 0 {
            let old = inner.entries[inner.head];
            inner.head = (inner.head + 1) % QUARANTINE_SLOTS;
            inner.count -= 1;
            inner.total_bytes -= old.size;
            evicted = Some(old);
        }

        // Also evict if ring buffer is full by count
        if inner.count >= QUARANTINE_SLOTS {
            let old = inner.entries[inner.head];
            inner.head = (inner.head + 1) % QUARANTINE_SLOTS;
            inner.count -= 1;
            inner.total_bytes -= old.size;
            evicted = Some(old);
        }

        // Push new entry
        inner.entries[inner.tail] = entry;
        inner.tail = (inner.tail + 1) % QUARANTINE_SLOTS;
        inner.count += 1;
        inner.total_bytes += entry.size;

        self.lock.unlock();
        evicted
    }

    /// Push a freed pointer into quarantine (legacy interface).
    /// Returns the evicted entry (ptr, size) if the quarantine was full.
    pub unsafe fn push(&self, ptr: *mut u8, size: usize) -> Option<(*mut u8, usize)> {
        let entry = QuarantineEntry {
            ptr,
            size,
            slab_ptr: core::ptr::null_mut(),
            slot_index: 0,
            class_index: 0,
        };
        self.push_enriched(entry)
            .map(|e| (e.ptr, e.size))
    }
}
