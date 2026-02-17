//! ABI behavior tests for compatmalloc.
//!
//! These tests exercise the standard C allocator API semantics by calling into
//! the hardened allocator through the crate's public Rust API.

use std::collections::HashSet;
use std::ptr;

/// Helper: initialize the allocator and return a reference to it.
///
/// # Safety
/// Must be called before any allocator operations.  The returned reference
/// is `'static` and backed by a global; it is safe to use from a single
/// test at a time (Rust's default test runner serializes `#[test]` functions).
unsafe fn alloc() -> &'static compatmalloc::allocator::HardenedAllocator {
    compatmalloc::init::ensure_initialized();
    compatmalloc::init::allocator()
}

// ---------------------------------------------------------------------------
// malloc(0) returns a unique, non-NULL, freeable pointer
// ---------------------------------------------------------------------------

#[test]
fn malloc_zero_returns_non_null() {
    unsafe {
        let a = alloc();
        let p = a.malloc(0);
        assert!(!p.is_null(), "malloc(0) must return non-NULL");
        // Must be freeable without crashing.
        a.free(p);
    }
}

#[test]
fn malloc_zero_returns_unique_pointers() {
    unsafe {
        let a = alloc();
        let mut ptrs = Vec::new();
        for _ in 0..64 {
            let p = a.malloc(0);
            assert!(!p.is_null());
            ptrs.push(p);
        }
        // All pointers should be distinct.
        let unique: HashSet<usize> = ptrs.iter().map(|p| *p as usize).collect();
        assert_eq!(
            unique.len(),
            ptrs.len(),
            "malloc(0) must return unique pointers"
        );
        for p in ptrs {
            a.free(p);
        }
    }
}

// ---------------------------------------------------------------------------
// free(NULL) is a no-op
// ---------------------------------------------------------------------------

#[test]
fn free_null_is_noop() {
    unsafe {
        let a = alloc();
        // Should not crash or panic.
        a.free(ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// realloc(NULL, n) == malloc(n)
// ---------------------------------------------------------------------------

#[test]
fn realloc_null_acts_as_malloc() {
    unsafe {
        let a = alloc();
        let p = a.realloc(ptr::null_mut(), 128);
        assert!(!p.is_null(), "realloc(NULL, 128) must behave like malloc");
        // Write to it to prove it is usable.
        ptr::write_bytes(p, 0xAB, 128);
        a.free(p);
    }
}

// ---------------------------------------------------------------------------
// realloc(p, 0) returns a minimum-size allocation (not NULL, to prevent
// use-after-free when callers interpret NULL as failure).
// ---------------------------------------------------------------------------

#[test]
fn realloc_to_zero_returns_minimum_allocation() {
    unsafe {
        let a = alloc();
        let p = a.malloc(64);
        assert!(!p.is_null());
        let q = a.realloc(p, 0);
        assert!(!q.is_null(), "realloc(p, 0) must return a valid pointer");
        a.free(q);
    }
}

// ---------------------------------------------------------------------------
// calloc overflow detection
// ---------------------------------------------------------------------------

#[test]
fn calloc_overflow_returns_null() {
    unsafe {
        let a = alloc();
        // usize::MAX / 2 + 1 elements of size 2 overflows.
        let p = a.calloc(usize::MAX / 2 + 1, 2);
        assert!(
            p.is_null(),
            "calloc with overflowing nmemb*size must return NULL"
        );

        // Another obvious overflow pair.
        let q = a.calloc(usize::MAX, usize::MAX);
        assert!(q.is_null(), "calloc(MAX, MAX) must return NULL");
    }
}

// ---------------------------------------------------------------------------
// calloc returns zero-filled memory
// ---------------------------------------------------------------------------

#[test]
fn calloc_returns_zeroed_memory() {
    unsafe {
        let a = alloc();
        for &size in &[1usize, 16, 64, 256, 1024, 4096] {
            let p = a.calloc(size, 1);
            assert!(!p.is_null(), "calloc({}, 1) returned NULL", size);
            let slice = std::slice::from_raw_parts(p, size);
            assert!(
                slice.iter().all(|&b| b == 0),
                "calloc({}, 1) memory is not zero-filled",
                size
            );
            a.free(p);
        }
    }
}

#[test]
fn calloc_zeroed_with_nmemb_and_size() {
    unsafe {
        let a = alloc();
        // 10 elements of 100 bytes each.
        let p = a.calloc(10, 100);
        assert!(!p.is_null());
        let slice = std::slice::from_raw_parts(p, 1000);
        assert!(
            slice.iter().all(|&b| b == 0),
            "calloc(10, 100) memory is not zero-filled"
        );
        a.free(p);
    }
}

// ---------------------------------------------------------------------------
// malloc returns 16-byte aligned pointers
// ---------------------------------------------------------------------------

#[test]
fn malloc_returns_16_byte_aligned_pointers() {
    unsafe {
        let a = alloc();
        for &size in &[1usize, 2, 4, 7, 8, 15, 16, 17, 31, 32, 33, 64, 100, 256, 1024, 4096] {
            let p = a.malloc(size);
            assert!(!p.is_null(), "malloc({}) returned NULL", size);
            assert_eq!(
                (p as usize) % 16,
                0,
                "malloc({}) returned pointer {:?} not aligned to 16 bytes",
                size,
                p
            );
            a.free(p);
        }
    }
}

// ---------------------------------------------------------------------------
// malloc_usable_size(p) >= requested_size
// ---------------------------------------------------------------------------

#[test]
fn usable_size_at_least_requested() {
    unsafe {
        let a = alloc();
        for &size in &[1usize, 7, 16, 17, 32, 100, 256, 512, 1024, 4096, 8192, 16384] {
            let p = a.malloc(size);
            assert!(!p.is_null(), "malloc({}) returned NULL", size);
            let usable = a.usable_size(p);
            assert!(
                usable >= size,
                "usable_size({}) = {} < requested {}",
                size,
                usable,
                size
            );
            a.free(p);
        }
    }
}

// ---------------------------------------------------------------------------
// Various size allocations: 1 byte through 1 MB
// ---------------------------------------------------------------------------

#[test]
fn various_allocation_sizes() {
    unsafe {
        let a = alloc();
        let sizes: Vec<usize> = vec![
            1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 100, 128, 200, 255, 256,
            257, 512, 1000, 1024, 2048, 4096, 8192, 10000, 16384, 32768, 65536, 131072, 262144,
            524288, 1048576,
        ];

        for &size in &sizes {
            let p = a.malloc(size);
            assert!(!p.is_null(), "malloc({}) returned NULL", size);

            // Write a pattern to verify the memory is usable.
            ptr::write_bytes(p, 0xAA, size);

            // Verify we can read the pattern back.
            let slice = std::slice::from_raw_parts(p, size);
            assert!(
                slice.iter().all(|&b| b == 0xAA),
                "malloc({}) memory is not writable/readable",
                size
            );

            a.free(p);
        }
    }
}

// ---------------------------------------------------------------------------
// posix_memalign with various alignments
// ---------------------------------------------------------------------------

#[test]
fn memalign_various_alignments() {
    unsafe {
        let a = alloc();
        // Test power-of-two alignments from 8 (sizeof void*) up to 4096.
        let alignments = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

        for &alignment in &alignments {
            let size = 100;
            let p = a.memalign(alignment, size);
            assert!(
                !p.is_null(),
                "memalign({}, {}) returned NULL",
                alignment,
                size
            );
            assert_eq!(
                (p as usize) % alignment,
                0,
                "memalign({}, {}) returned {:?} which is not aligned",
                alignment,
                size,
                p
            );

            // Verify the memory is usable.
            ptr::write_bytes(p, 0xBB, size);
            let slice = std::slice::from_raw_parts(p, size);
            assert!(
                slice.iter().all(|&b| b == 0xBB),
                "memalign({}, {}) memory not writable/readable",
                alignment,
                size
            );

            a.free(p);
        }
    }
}

#[test]
fn memalign_with_varying_sizes() {
    unsafe {
        let a = alloc();
        let alignment = 64;
        for &size in &[0usize, 1, 63, 64, 65, 128, 256, 1024, 4096] {
            let p = a.memalign(alignment, size);
            assert!(
                !p.is_null(),
                "memalign({}, {}) returned NULL",
                alignment,
                size
            );
            assert_eq!(
                (p as usize) % alignment,
                0,
                "memalign({}, {}) returned {:?} which is not aligned",
                alignment,
                size,
                p
            );
            a.free(p);
        }
    }
}

#[test]
fn memalign_non_power_of_two_returns_null() {
    unsafe {
        let a = alloc();
        // Alignment 3 is not a power of two -- should return NULL.
        let p = a.memalign(3, 100);
        assert!(
            p.is_null(),
            "memalign with non-power-of-two alignment must return NULL"
        );
    }
}

// ---------------------------------------------------------------------------
// Allocation round-trip: malloc -> write -> read -> realloc -> read -> free
// ---------------------------------------------------------------------------

#[test]
fn allocation_round_trip() {
    unsafe {
        let a = alloc();
        let initial_size = 64;
        let p = a.malloc(initial_size);
        assert!(!p.is_null());

        // Write pattern.
        for i in 0..initial_size {
            p.add(i).write((i & 0xFF) as u8);
        }

        // Realloc to larger size.
        let new_size = 256;
        let q = a.realloc(p, new_size);
        assert!(!q.is_null(), "realloc to larger size returned NULL");

        // Original data must be preserved.
        for i in 0..initial_size {
            assert_eq!(
                q.add(i).read(),
                (i & 0xFF) as u8,
                "data corruption at offset {} after realloc",
                i
            );
        }

        a.free(q);
    }
}

// ---------------------------------------------------------------------------
// Realloc to smaller size preserves data
// ---------------------------------------------------------------------------

#[test]
fn realloc_shrink_preserves_data() {
    unsafe {
        let a = alloc();
        let p = a.malloc(256);
        assert!(!p.is_null());

        for i in 0..256usize {
            p.add(i).write((i & 0xFF) as u8);
        }

        let q = a.realloc(p, 32);
        assert!(!q.is_null());

        // First 32 bytes must be intact.
        for i in 0..32usize {
            assert_eq!(
                q.add(i).read(),
                (i & 0xFF) as u8,
                "data corruption at offset {} after shrinking realloc",
                i
            );
        }

        a.free(q);
    }
}

// ---------------------------------------------------------------------------
// Rapid malloc/free cycles (single thread, many iterations)
// ---------------------------------------------------------------------------

#[test]
fn rapid_malloc_free_single_thread() {
    unsafe {
        let a = alloc();
        for _ in 0..10_000 {
            let p = a.malloc(64);
            assert!(!p.is_null());
            a.free(p);
        }
    }
}
