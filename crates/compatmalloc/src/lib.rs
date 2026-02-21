//! A memory-hardening drop-in allocator for Linux.
//!
//! compatmalloc provides defense-in-depth heap protection as either an
//! `LD_PRELOAD` interposer (C/C++ programs, no recompilation needed) or a
//! Rust `#[global_allocator]` (`CompatMalloc`, requires the
//! `global-allocator` feature).
//!
//! # Quick Start (Rust)
//!
//! ```rust,ignore
//! use compatmalloc::CompatMalloc;
//!
//! #[global_allocator]
//! static GLOBAL: CompatMalloc = CompatMalloc;
//! ```
//!
//! # Quick Start (C/C++ via LD_PRELOAD)
//!
//! ```bash,ignore
//! LD_PRELOAD=libcompatmalloc.so ./your_program
//! ```

// Internal modules — not part of the public API.
pub(crate) mod api;
pub(crate) mod config;
pub(crate) mod large;
pub(crate) mod platform;
pub(crate) mod slab;
pub(crate) mod sync;
pub(crate) mod util;

pub(crate) mod allocator;
pub(crate) mod hardening;
pub(crate) mod init;

/// Test-support re-exports. Hidden from docs.
/// NOT part of the public API; may change without notice.
#[doc(hidden)]
pub mod __test_support {
    pub use crate::allocator::HardenedAllocator;
    pub use crate::init::{allocator, ensure_initialized};
}

#[cfg(feature = "global-allocator")]
mod global_alloc;
#[cfg(feature = "global-allocator")]
pub use global_alloc::CompatMalloc;
