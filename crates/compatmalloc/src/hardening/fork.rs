//! Fork safety: pthread_atfork handlers and generation counter.
//!
//! After fork(), locks may be in an inconsistent state (held by threads that
//! no longer exist in the child). We register an atfork child handler that
//! resets all allocator locks and bumps a generation counter so thread caches
//! know to reinitialize.

use core::sync::atomic::{AtomicU64, Ordering};

/// Global fork generation counter. Incremented in the child after each fork.
/// Thread caches compare their cached generation against this to detect stale state.
static FORK_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Get the current fork generation.
/// Uses Relaxed ordering since fork generation changes are rare (only on fork)
/// and a stale read just means we check cache validity one operation late.
#[inline(always)]
pub fn fork_generation() -> u64 {
    FORK_GENERATION.load(Ordering::Relaxed)
}

/// Child handler called after fork(). Resets allocator locks and bumps generation.
///
/// # Safety
/// This is called by the C runtime in the child process after fork().
/// At this point, only one thread exists (the one that called fork()), so
/// accessing global state without locks is safe.
unsafe extern "C" fn atfork_child() {
    // Reset all allocator locks (they may be held by now-dead threads)
    crate::init::allocator().reset_locks_after_fork();

    // Bump generation so thread caches know to reinitialize
    FORK_GENERATION.fetch_add(1, Ordering::Release);
}

/// Register the pthread_atfork handler. Must be called once during init.
///
/// # Safety
/// Must be called from the initialization path.
pub unsafe fn register_atfork() {
    libc::pthread_atfork(None, None, Some(atfork_child));
}
