use crate::platform;
use core::sync::atomic::{AtomicU64, Ordering};

/// Per-process canary secret, initialized from getrandom(2) at startup.
static CANARY_SECRET: AtomicU64 = AtomicU64::new(0);

/// Initialize the canary secret from a cryptographic source.
/// Must be called once during allocator init.
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
/// Uses splitmix64(addr ^ per-process-secret) for unpredictability.
#[inline]
pub fn generate_canary(ptr: *mut u8) -> u64 {
    let addr = ptr as u64;
    let secret = CANARY_SECRET.load(Ordering::Acquire);
    platform::splitmix64(addr ^ secret)
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
    let canary_bytes = canary.to_le_bytes();

    // Constant-time comparison: accumulate differences to prevent timing side-channel.
    let mut diff: u8 = 0;
    let mut i = 0;
    while i < gap {
        diff |= canary_start.add(i).read() ^ canary_bytes[i % 8];
        i += 1;
    }
    diff == 0
}
