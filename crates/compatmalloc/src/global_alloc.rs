//! `#[global_allocator]` support for compatmalloc.
//!
//! Allows Rust programs to use compatmalloc as their global allocator:
//!
//! ```rust,ignore
//! use compatmalloc::CompatMalloc;
//!
//! #[global_allocator]
//! static GLOBAL: CompatMalloc = CompatMalloc;
//! ```

use crate::init;
use crate::util::MIN_ALIGN;
use core::alloc::{GlobalAlloc, Layout};

/// A zero-sized unit struct that implements [`GlobalAlloc`] by delegating to
/// the compatmalloc hardened allocator.
///
/// # Example
///
/// ```rust,ignore
/// use compatmalloc::CompatMalloc;
///
/// #[global_allocator]
/// static GLOBAL: CompatMalloc = CompatMalloc;
/// ```
pub struct CompatMalloc;

unsafe impl GlobalAlloc for CompatMalloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();

        // Zero-size types: return a well-aligned dangling pointer.
        // This is the standard pattern used by the Rust standard library.
        if size == 0 {
            return align as *mut u8;
        }

        init::ensure_initialized();
        let alloc = init::allocator();

        if align <= MIN_ALIGN {
            alloc.malloc(size)
        } else {
            alloc.memalign(align, size)
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();

        if size == 0 {
            return align as *mut u8;
        }

        init::ensure_initialized();
        let alloc = init::allocator();

        if align <= MIN_ALIGN {
            alloc.calloc(1, size)
        } else {
            // No calloc equivalent with alignment control; allocate then zero.
            let ptr = alloc.memalign(align, size);
            if !ptr.is_null() {
                core::ptr::write_bytes(ptr, 0, size);
            }
            ptr
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == 0 {
            return;
        }

        // init::ensure_initialized() is not needed here: if we are freeing
        // a pointer, alloc() must have already been called which initialized
        // the allocator.
        init::allocator().free(ptr);
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let old_size = layout.size();
        let align = layout.align();

        // Old allocation was zero-sized: this is effectively a fresh alloc.
        if old_size == 0 {
            return self.alloc(Layout::from_size_align_unchecked(new_size, align));
        }

        // Rust's GlobalAlloc contract guarantees new_size > 0.
        debug_assert!(new_size > 0, "GlobalAlloc::realloc called with new_size == 0");

        // ensure_initialized() is not needed here: if we have a valid ptr
        // from a prior allocation, the allocator is already initialized.
        let alloc = init::allocator();

        if align <= MIN_ALIGN {
            // Normal alignment: delegate directly to the allocator's realloc
            // which handles in-place resizing within the same size class.
            alloc.realloc(ptr, new_size)
        } else {
            // Over-aligned realloc: the underlying realloc() uses malloc()
            // internally which only guarantees MIN_ALIGN. We must use the
            // alloc+copy+dealloc pattern to preserve alignment.
            let new_ptr = alloc.memalign(align, new_size);
            if !new_ptr.is_null() {
                let copy_size = old_size.min(new_size);
                core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
                alloc.free(ptr);
            }
            new_ptr
        }
    }
}
