use crate::platform;
use crate::util::{align_up, page_size};
/// A large allocation: individual mmap region with optional guard pages.
///
/// Layout: [guard page] [user data pages] [guard page]
///
/// The user pointer is at the start of the data pages.
pub struct LargeAlloc {
    /// The base of the entire mmap region (including guard pages).
    pub base: *mut u8,
    /// Total mapped size (including guard pages).
    pub total_size: usize,
    /// Pointer returned to the user.
    pub user_ptr: *mut u8,
    /// Size of the user data region (page-aligned).
    pub data_size: usize,
    /// Requested allocation size (may be smaller than data_size).
    pub requested_size: usize,
}

impl LargeAlloc {
    /// Create a new large allocation.
    /// Returns None on failure.
    pub unsafe fn create(size: usize) -> Option<Self> {
        let data_size = align_up(size, page_size());

        #[cfg(feature = "guard-pages")]
        let total_size = page_size() + data_size + page_size();
        #[cfg(not(feature = "guard-pages"))]
        let total_size = data_size;

        let base = platform::map_anonymous(total_size);
        if base.is_null() {
            return None;
        }

        #[cfg(feature = "guard-pages")]
        {
            // Front guard page
            platform::protect_none(base, page_size());
            // Rear guard page
            platform::protect_none(base.add(page_size() + data_size), page_size());
        }

        #[cfg(feature = "guard-pages")]
        let user_ptr = base.add(page_size());
        #[cfg(not(feature = "guard-pages"))]
        let user_ptr = base;

        Some(LargeAlloc {
            base,
            total_size,
            user_ptr,
            data_size,
            requested_size: size,
        })
    }

    /// Destroy this large allocation, unmapping all memory.
    pub unsafe fn destroy(&self) {
        platform::unmap(self.base, self.total_size);
    }
}
