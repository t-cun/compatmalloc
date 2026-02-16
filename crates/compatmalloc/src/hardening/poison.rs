use crate::util::POISON_BYTE;

/// Fill a memory region with poison bytes.
///
/// # Safety
/// `ptr` must point to a valid writable region of at least `size` bytes.
#[inline]
pub unsafe fn poison_region(ptr: *mut u8, size: usize) {
    core::ptr::write_bytes(ptr, POISON_BYTE, size);
}

/// Check that a memory region still contains poison bytes.
/// Returns true if all bytes are poison (no write-after-free).
///
/// # Safety
/// `ptr` must point to a valid readable region of at least `size` bytes.
pub unsafe fn check_poison(ptr: *mut u8, size: usize) -> bool {
    // Check in u64 chunks for performance
    let ptr64 = ptr as *const u64;
    let expected = u64::from_le_bytes([POISON_BYTE; 8]);
    let full_words = size / 8;
    let remainder = size % 8;

    for i in 0..full_words {
        if ptr64.add(i).read_unaligned() != expected {
            return false;
        }
    }

    let tail = ptr.add(full_words * 8);
    for i in 0..remainder {
        if tail.add(i).read() != POISON_BYTE {
            return false;
        }
    }

    true
}
