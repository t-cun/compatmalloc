extern crate libc;

pub mod allocator;
pub mod api;
pub mod config;
pub mod hardening;
pub mod init;
pub mod large;
pub mod platform;
pub mod slab;
pub mod sync;
pub mod util;

#[cfg(feature = "global-allocator")]
mod global_alloc;
#[cfg(feature = "global-allocator")]
pub use global_alloc::CompatMalloc;
