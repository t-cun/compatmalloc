// Guard page management is handled inline by the slab and large allocation code.
// This module provides utility functions for guard page configuration.

use crate::util::page_size;

/// Check if guard pages are enabled.
#[allow(dead_code)]
#[inline]
pub fn guard_pages_enabled() -> bool {
    cfg!(feature = "guard-pages")
}

/// Size overhead per slab region from guard pages (before + after).
#[allow(dead_code)]
#[inline]
pub fn slab_guard_overhead() -> usize {
    if cfg!(feature = "guard-pages") {
        page_size() * 2
    } else {
        0
    }
}

/// Size overhead per large allocation from guard pages.
#[allow(dead_code)]
#[inline]
pub fn large_guard_overhead() -> usize {
    if cfg!(feature = "guard-pages") {
        page_size() * 2
    } else {
        0
    }
}
