use crate::platform;

/// Generate a canary value for an allocation.
/// The canary is derived from the pointer address and a random value,
/// making it unpredictable to an attacker.
#[inline]
pub fn generate_canary(ptr: *mut u8) -> u64 {
    let addr = ptr as u64;
    let random = platform::fast_random_u64();
    // Mix address and random value
    addr ^ random ^ 0xDEAD_BEEF_CAFE_BABEu64
}

/// Write canary bytes in the gap between requested_size and slot_size.
///
/// # Safety
/// `ptr` must point to a valid allocation of at least `slot_size` bytes.
/// `requested_size <= slot_size`.
#[inline]
pub unsafe fn write_canary(ptr: *mut u8, requested_size: usize, slot_size: usize, canary: u64) {
    let gap = slot_size - requested_size;
    if gap == 0 {
        return;
    }

    let canary_start = ptr.add(requested_size);
    let canary_bytes = canary.to_le_bytes();

    // Fill the gap with repeating canary bytes
    let mut i = 0;
    while i < gap {
        canary_start.add(i).write(canary_bytes[i % 8]);
        i += 1;
    }
}

/// Check that canary bytes are intact.
///
/// # Safety
/// Same requirements as `write_canary`.
#[inline]
pub unsafe fn check_canary(
    ptr: *mut u8,
    requested_size: usize,
    slot_size: usize,
    canary: u64,
) -> bool {
    let gap = slot_size - requested_size;
    if gap == 0 {
        return true;
    }

    let canary_start = ptr.add(requested_size);
    let canary_bytes = canary.to_le_bytes();

    let mut i = 0;
    while i < gap {
        if canary_start.add(i).read() != canary_bytes[i % 8] {
            return false;
        }
        i += 1;
    }
    true
}
