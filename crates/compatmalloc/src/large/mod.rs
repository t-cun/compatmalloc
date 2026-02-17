pub mod guard;

use crate::hardening::metadata::{AllocationMeta, StripedMetadata};
use crate::slab::page_map;
use crate::sync::RawMutex;
use core::cell::UnsafeCell;
use core::ptr;
use guard::LargeAlloc;

const MAX_LARGE_ALLOCS: usize = 4096;

#[derive(Clone, Copy)]
struct LargeEntry {
    alloc: Option<LargeEntryData>,
}

#[derive(Clone, Copy)]
struct LargeEntryData {
    base: *mut u8,
    total_size: usize,
    user_ptr: *mut u8,
    #[allow(dead_code)]
    data_size: usize,
    requested_size: usize,
}

struct LargeInner {
    entries: [LargeEntry; MAX_LARGE_ALLOCS],
}

pub struct LargeAllocator {
    lock: RawMutex,
    inner: UnsafeCell<LargeInner>,
}

unsafe impl Send for LargeAllocator {}
unsafe impl Sync for LargeAllocator {}

impl LargeAllocator {
    pub const fn new() -> Self {
        const EMPTY: LargeEntry = LargeEntry { alloc: None };
        LargeAllocator {
            lock: RawMutex::new(),
            inner: UnsafeCell::new(LargeInner {
                entries: [EMPTY; MAX_LARGE_ALLOCS],
            }),
        }
    }

    pub unsafe fn alloc(&self, size: usize, metadata: &StripedMetadata) -> *mut u8 {
        let alloc = match LargeAlloc::create(size) {
            Some(a) => a,
            None => return ptr::null_mut(),
        };

        let entry_data = LargeEntryData {
            base: alloc.base,
            total_size: alloc.total_size,
            user_ptr: alloc.user_ptr,
            data_size: alloc.data_size,
            requested_size: alloc.requested_size,
        };
        let user_ptr = alloc.user_ptr;

        #[cfg(feature = "canaries")]
        {
            let canary = crate::hardening::canary::generate_canary(user_ptr);
            metadata.insert(user_ptr, AllocationMeta::new(size, canary));
        }
        #[cfg(not(feature = "canaries"))]
        {
            metadata.insert(user_ptr, AllocationMeta::new(size, 0));
        }

        self.lock.lock();
        let inner = &mut *self.inner.get();
        let mut stored = false;
        for entry in inner.entries.iter_mut() {
            if entry.alloc.is_none() {
                entry.alloc = Some(entry_data);
                stored = true;
                break;
            }
        }
        self.lock.unlock();

        if !stored {
            alloc.destroy();
            metadata.remove(user_ptr);
            return ptr::null_mut();
        }

        // Register in page map for O(1) lookup
        page_map::register_large(user_ptr, alloc.data_size);

        user_ptr
    }

    pub unsafe fn free(&self, ptr: *mut u8, metadata: &StripedMetadata) -> bool {
        self.lock.lock();
        let inner = &mut *self.inner.get();

        for entry in inner.entries.iter_mut() {
            if let Some(ref data) = entry.alloc {
                if data.user_ptr == ptr {
                    if let Some(meta) = metadata.get(ptr) {
                        if meta.is_freed() {
                            self.lock.unlock();
                            crate::hardening::abort_with_message(
                                "compatmalloc: double free detected (large)\n",
                            );
                        }
                    }

                    metadata.remove(ptr);
                    let base = data.base;
                    let total_size = data.total_size;
                    let data_size = data.data_size;
                    entry.alloc = None;
                    self.lock.unlock();
                    // Unregister from page map before unmapping
                    page_map::unregister_large(ptr, data_size);
                    crate::platform::unmap(base, total_size);
                    return true;
                }
            }
        }
        self.lock.unlock();
        false
    }

    pub unsafe fn usable_size(&self, ptr: *mut u8) -> Option<usize> {
        self.lock.lock();
        let inner = &*self.inner.get();
        for entry in &inner.entries {
            if let Some(ref data) = entry.alloc {
                if data.user_ptr == ptr {
                    let size = data.requested_size;
                    self.lock.unlock();
                    return Some(size);
                }
            }
        }
        self.lock.unlock();
        None
    }

    pub unsafe fn contains(&self, ptr: *mut u8) -> bool {
        self.lock.lock();
        let inner = &*self.inner.get();
        for entry in &inner.entries {
            if let Some(ref data) = entry.alloc {
                if data.user_ptr == ptr {
                    self.lock.unlock();
                    return true;
                }
            }
        }
        self.lock.unlock();
        false
    }

    pub unsafe fn requested_size(&self, ptr: *mut u8) -> Option<usize> {
        self.lock.lock();
        let inner = &*self.inner.get();
        for entry in &inner.entries {
            if let Some(ref data) = entry.alloc {
                if data.user_ptr == ptr {
                    let size = data.requested_size;
                    self.lock.unlock();
                    return Some(size);
                }
            }
        }
        self.lock.unlock();
        None
    }
}
