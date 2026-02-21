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

extern crate libc;

// Internal modules — not part of the public API.
// allow(dead_code) on modules with scaffolded items for future platform
// support (MTE, Windows) and API surface (batch free, generic Mutex).
pub(crate) mod api;
pub(crate) mod config;
pub(crate) mod large;
#[allow(dead_code)]
pub(crate) mod platform;
#[allow(dead_code)]
pub(crate) mod slab;
#[allow(dead_code)]
pub(crate) mod sync;
#[allow(dead_code)]
pub(crate) mod util;

// These modules are pub for integration test access but hidden from docs.
// They are NOT part of the stability guarantee and may change without notice.
#[doc(hidden)]
pub mod allocator;
#[doc(hidden)]
pub mod hardening;
#[doc(hidden)]
pub mod init;

#[cfg(feature = "global-allocator")]
mod global_alloc;
#[cfg(feature = "global-allocator")]
pub use global_alloc::CompatMalloc;
