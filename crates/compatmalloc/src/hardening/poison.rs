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
/// Uses constant-time accumulate-and-compare to prevent timing side-channels
/// from revealing the offset of a write-after-free corruption.
///
/// # Safety
/// `ptr` must point to a valid readable region of at least `size` bytes.
pub unsafe fn check_poison(ptr: *mut u8, size: usize) -> bool {
    // Constant-time check: accumulate XOR diffs, no early returns
    let ptr64 = ptr as *const u64;
    let expected = u64::from_le_bytes([POISON_BYTE; 8]);
    let full_words = size / 8;
    let remainder = size % 8;

    let mut diff: u64 = 0;
    for i in 0..full_words {
        diff |= ptr64.add(i).read_unaligned() ^ expected;
    }

    let tail = ptr.add(full_words * 8);
    for i in 0..remainder {
        diff |= (tail.add(i).read() ^ POISON_BYTE) as u64;
    }

    diff == 0
}
