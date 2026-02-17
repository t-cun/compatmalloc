pub mod metadata;
pub mod fork;
pub mod integrity;
pub mod self_check;

// canary module is always compiled (integrity.rs uses canary::secret())
pub mod canary;

#[cfg(feature = "poison-on-free")]
pub mod poison;

#[cfg(feature = "quarantine")]
pub mod quarantine;

pub mod guard_pages;

/// Abort with a diagnostic message to stderr.
/// This is used when unrecoverable corruption is detected.
#[cold]
#[inline(never)]
pub fn abort_with_message(msg: &str) -> ! {
    unsafe {
        // Write directly to stderr fd (2) -- no allocation needed
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::abort();
    }
}
