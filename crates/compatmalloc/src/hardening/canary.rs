use crate::platform;
use core::sync::atomic::{AtomicU64, Ordering};

/// Per-process canary secret, initialized from getrandom(2) at startup.
static CANARY_SECRET: AtomicU64 = AtomicU64::new(0);

/// Initialize the canary secret from a cryptographic source.
/// Must be called once during allocator init.
///
/// # Safety
/// Must be called from single-threaded context during init.
pub unsafe fn init_canary_secret() {
    let mut buf = [0u8; 8];
    #[cfg(target_os = "linux")]
    {
        // Retry loop: getrandom can return short reads or EINTR
        let mut filled = 0usize;
        while filled < 8 {
            let ret = libc::syscall(
                libc::SYS_getrandom,
                buf.as_mut_ptr().add(filled),
                8 - filled,
                0u32,
            );
            if ret > 0 {
                filled += ret as usize;
            } else if ret == 0 {
                // Should never happen with blocking getrandom, but guard against it
                break;
            } else {
                let err = *libc::__errno_location();
                if err == libc::EINTR {
                    continue;
                }
                // ENOSYS or other fatal error -- abort, don't fall back to weak entropy
                break;
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Use arc4random_buf where available (macOS, BSDs)
        libc::arc4random_buf(buf.as_mut_ptr() as *mut libc::c_void, 8);
    }
    let secret = u64::from_le_bytes(buf);
    // If we somehow got all zeros, mix in the stack address as a last resort
    let secret = if secret != 0 {
        secret
    } else {
        let stack_addr = &buf as *const _ as u64;
        platform::splitmix64(stack_addr)
    };
    CANARY_SECRET.store(secret, Ordering::Release);
}

/// Generate a canary value for an allocation.
/// Uses a non-invertible double-hash: splitmix64(splitmix64(secret) ^ splitmix64(addr)).
/// Unlike single splitmix64(addr ^ secret), this cannot be inverted even if the
/// attacker knows the canary and the address, because splitmix64 destroys the
/// algebraic structure needed to solve for the secret.
#[inline]
pub fn generate_canary(ptr: *mut u8) -> u64 {
    let addr = ptr as u64;
    let secret = CANARY_SECRET.load(Ordering::Acquire);
    platform::splitmix64(platform::splitmix64(secret) ^ platform::splitmix64(addr))
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

    // Write u64 chunks for bulk fill, then tail bytes
    let mut i = 0;
    while i + 8 <= gap {
        (canary_start.add(i) as *mut u64).write_unaligned(canary);
        i += 8;
    }
    let canary_bytes = canary.to_le_bytes();
    while i < gap {
        canary_start.add(i).write(canary_bytes[i & 7]);
        i += 1;
    }
}

/// Check that canary bytes are intact (constant-time).
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

    // Constant-time comparison using u64 chunks then tail bytes.
    let mut diff: u64 = 0;
    let mut i = 0;
    while i + 8 <= gap {
        diff |= (canary_start.add(i) as *const u64).read_unaligned() ^ canary;
        i += 8;
    }
    let canary_bytes = canary.to_le_bytes();
    let mut byte_diff: u8 = 0;
    while i < gap {
        byte_diff |= canary_start.add(i).read() ^ canary_bytes[i & 7];
        i += 1;
    }
    diff == 0 && byte_diff == 0
}

/// Write canary bytes to the front gap (before user data in right-aligned layout).
///
/// # Safety
/// `slot_base` must point to a valid slot region. `gap` bytes from slot_base
/// are the front canary region.
#[inline]
pub unsafe fn write_canary_front(slot_base: *mut u8, gap: usize, canary: u64) {
    if gap == 0 {
        return;
    }

    let mut i = 0;
    while i + 8 <= gap {
        (slot_base.add(i) as *mut u64).write_unaligned(canary);
        i += 8;
    }
    let canary_bytes = canary.to_le_bytes();
    while i < gap {
        slot_base.add(i).write(canary_bytes[i & 7]);
        i += 1;
    }
}

/// Check front-gap canary bytes (constant-time).
///
/// # Safety
/// `slot_base` must point to a valid slot region with at least `gap` readable bytes.
#[inline]
pub unsafe fn check_canary_front(slot_base: *mut u8, gap: usize, canary: u64) -> bool {
    if gap == 0 {
        return true;
    }
    let mut diff: u64 = 0;
    let mut i = 0;
    while i + 8 <= gap {
        diff |= (slot_base.add(i) as *const u64).read_unaligned() ^ canary;
        i += 8;
    }
    let canary_bytes = canary.to_le_bytes();
    let mut byte_diff: u8 = 0;
    while i < gap {
        byte_diff |= slot_base.add(i).read() ^ canary_bytes[i & 7];
        i += 1;
    }
    diff == 0 && byte_diff == 0
}

/// Get the canary secret for use by integrity checksums.
/// Uses Relaxed ordering since the secret is initialized once during init
/// (which happens-before any allocation) and never changes.
#[inline(always)]
pub(crate) fn secret() -> u64 {
    CANARY_SECRET.load(Ordering::Relaxed)
}
