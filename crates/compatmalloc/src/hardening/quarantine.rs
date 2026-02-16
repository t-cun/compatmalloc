use crate::sync::RawMutex;
use crate::util::DEFAULT_QUARANTINE_BYTES;
use core::cell::UnsafeCell;

const QUARANTINE_SLOTS: usize = 8192;

#[derive(Clone, Copy)]
struct QuarantineEntry {
    ptr: *mut u8,
    size: usize,
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
        const EMPTY: QuarantineEntry = QuarantineEntry {
            ptr: core::ptr::null_mut(),
            size: 0,
        };
        Quarantine {
            lock: RawMutex::new(),
            inner: UnsafeCell::new(QuarantineInner {
                entries: [EMPTY; QUARANTINE_SLOTS],
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

    /// Push a freed pointer into quarantine.
    /// Returns the evicted entry (ptr, size) if the quarantine was full.
    pub unsafe fn push(&self, ptr: *mut u8, size: usize) -> Option<(*mut u8, usize)> {
        self.lock.lock();
        let inner = &mut *self.inner.get();
        let mut evicted = None;

        // Evict oldest entries until we have space
        while inner.total_bytes + size > inner.max_bytes && inner.count > 0 {
            let entry = inner.entries[inner.head];
            inner.head = (inner.head + 1) % QUARANTINE_SLOTS;
            inner.count -= 1;
            inner.total_bytes -= entry.size;
            evicted = Some((entry.ptr, entry.size));
        }

        // Also evict if ring buffer is full by count
        if inner.count >= QUARANTINE_SLOTS {
            let entry = inner.entries[inner.head];
            inner.head = (inner.head + 1) % QUARANTINE_SLOTS;
            inner.count -= 1;
            inner.total_bytes -= entry.size;
            evicted = Some((entry.ptr, entry.size));
        }

        // Push new entry
        inner.entries[inner.tail] = QuarantineEntry { ptr, size };
        inner.tail = (inner.tail + 1) % QUARANTINE_SLOTS;
        inner.count += 1;
        inner.total_bytes += size;

        self.lock.unlock();
        evicted
    }
}
