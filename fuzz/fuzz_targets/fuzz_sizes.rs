#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz target that exercises size boundaries and alignment.
// Interprets input as a series of (size, alignment_shift) pairs,
// allocates memory of that size, writes to the full extent,
// verifies alignment, and frees.

fuzz_target!(|data: &[u8]| {
    let mut i = 0;
    while i + 4 <= data.len() {
        // Read a u32 size from the fuzzer input
        let raw_size = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        i += 4;

        // Cap size to prevent OOM
        let size = (raw_size as usize) % (1024 * 1024); // Max 1 MiB

        // Test malloc
        let ptr = unsafe { libc::malloc(size) } as *mut u8;
        if size == 0 {
            // malloc(0) should return non-NULL (our implementation)
            // or NULL (also valid per spec) -- don't assert
            if !ptr.is_null() {
                unsafe { libc::free(ptr as *mut libc::c_void) };
            }
            continue;
        }

        if ptr.is_null() {
            continue; // OOM is ok
        }

        // Verify alignment (must be at least 16-byte aligned)
        assert_eq!(
            (ptr as usize) % 16,
            0,
            "malloc({}) returned unaligned pointer {:p}",
            size,
            ptr
        );

        // Write to full extent -- this should not crash
        unsafe {
            std::ptr::write_bytes(ptr, 0xBB, size);
        }

        // Read back and verify
        for j in 0..size {
            assert_eq!(unsafe { *ptr.add(j) }, 0xBB);
        }

        // Test malloc_usable_size
        let usable = unsafe { libc::malloc_usable_size(ptr as *mut libc::c_void) };
        assert!(
            usable >= size,
            "malloc_usable_size({}) = {} < requested {}",
            size,
            usable,
            size
        );

        unsafe { libc::free(ptr as *mut libc::c_void) };

        // Test calloc for the same size
        if size < 65536 {
            let cptr = unsafe { libc::calloc(1, size) } as *mut u8;
            if !cptr.is_null() {
                // Verify zero-fill
                for j in 0..std::cmp::min(size, 4096) {
                    assert_eq!(unsafe { *cptr.add(j) }, 0, "calloc not zeroed at {}", j);
                }
                unsafe { libc::free(cptr as *mut libc::c_void) };
            }
        }
    }
});
