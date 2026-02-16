use crate::util::DEFAULT_QUARANTINE_BYTES;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Cached config values (read once at init, never allocate).
static ARENA_COUNT: AtomicUsize = AtomicUsize::new(0);
static QUARANTINE_BYTES: AtomicUsize = AtomicUsize::new(DEFAULT_QUARANTINE_BYTES);

/// Read configuration from environment variables.
/// Must be called during init, before any allocations.
///
/// # Safety
/// Must be called from single-threaded context (init).
pub unsafe fn read_config() {
    if let Some(val) = getenv_usize(b"COMPATMALLOC_ARENA_COUNT\0") {
        ARENA_COUNT.store(val, Ordering::Relaxed);
    }
    if let Some(val) = getenv_usize(b"COMPATMALLOC_QUARANTINE_SIZE\0") {
        QUARANTINE_BYTES.store(val, Ordering::Relaxed);
    }
}

/// Check if the allocator is disabled via env var.
///
/// # Safety
/// Calls libc::getenv which is not thread-safe, so must be called during init.
pub unsafe fn is_disabled() -> bool {
    let key = b"COMPATMALLOC_DISABLE\0".as_ptr() as *const libc::c_char;
    !libc::getenv(key).is_null()
}

pub fn arena_count() -> usize {
    ARENA_COUNT.load(Ordering::Relaxed)
}

pub fn quarantine_bytes() -> usize {
    QUARANTINE_BYTES.load(Ordering::Relaxed)
}

/// Parse an environment variable as a usize.
///
/// # Safety
/// Calls libc::getenv.
unsafe fn getenv_usize(key: &[u8]) -> Option<usize> {
    let val = libc::getenv(key.as_ptr() as *const libc::c_char);
    if val.is_null() {
        return None;
    }

    // Parse manually (no std allocation)
    let mut result: usize = 0;
    let mut ptr = val as *const u8;
    loop {
        let byte = *ptr;
        if byte == 0 {
            break;
        }
        if byte < b'0' || byte > b'9' {
            return None; // Invalid
        }
        result = result.checked_mul(10)?.checked_add((byte - b'0') as usize)?;
        ptr = ptr.add(1);
    }
    Some(result)
}
