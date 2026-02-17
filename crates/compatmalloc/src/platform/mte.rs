//! ARM64 Memory Tagging Extension (MTE) support.
//!
//! When running on MTE-capable hardware (ARMv8.5-A+), this module provides
//! hardware-enforced memory safety by tagging allocations and checking tags
//! on every memory access. This replaces software canaries at zero cost.
//!
//! On non-MTE hardware, all operations are no-ops and `is_available()` returns false.

use core::sync::atomic::{AtomicBool, Ordering};

static MTE_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Detect and enable MTE if available. Must be called during init.
///
/// # Safety
/// Must be called from single-threaded context (init).
#[cfg(target_arch = "aarch64")]
pub unsafe fn init() {
    // Check for MTE support via getauxval(AT_HWCAP2)
    const AT_HWCAP2: libc::c_ulong = 26;
    const HWCAP2_MTE: libc::c_ulong = 1 << 18;

    let hwcap2 = libc::getauxval(AT_HWCAP2);
    if hwcap2 & HWCAP2_MTE == 0 {
        return;
    }

    // Enable MTE in synchronous mode (immediate fault on tag mismatch)
    const PR_SET_TAGGED_ADDR_CTRL: libc::c_int = 55;
    const PR_TAGGED_ADDR_ENABLE: libc::c_ulong = 1;
    const PR_MTE_TCF_SYNC: libc::c_ulong = 1 << 1;
    // Allow all 16 tags (excluding tag 0 which is reserved)
    const PR_MTE_TAG_MASK: libc::c_ulong = 0xfffe << 3;

    let ret = libc::prctl(
        PR_SET_TAGGED_ADDR_CTRL,
        PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC | PR_MTE_TAG_MASK,
        0,
        0,
        0,
    );
    if ret == 0 {
        MTE_AVAILABLE.store(true, Ordering::Release);
    }
}

/// Stub for non-aarch64 targets.
///
/// # Safety
/// No-op on non-aarch64 targets.
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn init() {}

/// Check if MTE is available and enabled.
#[inline(always)]
pub fn is_available() -> bool {
    MTE_AVAILABLE.load(Ordering::Relaxed)
}

/// Generate a random tagged pointer from an untagged base pointer.
/// Uses the IRG (Insert Random Tag) instruction.
///
/// # Safety
/// `ptr` must be a valid pointer. Only meaningful on MTE-enabled hardware.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub unsafe fn tag_alloc(ptr: *mut u8) -> *mut u8 {
    let tagged: *mut u8;
    core::arch::asm!(
        "irg {out}, {inp}",
        inp = in(reg) ptr,
        out = out(reg) tagged,
        options(nomem, nostack, preserves_flags),
    );
    tagged
}

/// # Safety
/// `ptr` must be a valid pointer. No-op on non-aarch64.
#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
pub unsafe fn tag_alloc(ptr: *mut u8) -> *mut u8 {
    ptr
}

/// Tag a memory region with the tag from the pointer.
/// Uses STG (Store Allocation Tag) in a loop over 16-byte MTE granules.
///
/// # Safety
/// `ptr` must be a tagged pointer from `tag_alloc`. `size` must be a multiple of 16.
/// The memory must be mapped with PROT_MTE.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn tag_region(ptr: *mut u8, size: usize) {
    let mut offset = 0usize;
    while offset < size {
        core::arch::asm!(
            "stg {ptr}, [{ptr}]",
            ptr = in(reg) ptr.add(offset),
            options(nostack, preserves_flags),
        );
        offset += 16;
    }
}

/// # Safety
/// No-op on non-aarch64.
#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
pub unsafe fn tag_region(_ptr: *mut u8, _size: usize) {}

/// Re-tag a freed memory region with a different random tag.
/// This ensures that any dangling pointers with the old tag will fault.
///
/// # Safety
/// `ptr` must point to a valid, mapped MTE region. `size` must be a multiple of 16.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn tag_freed(ptr: *mut u8, size: usize) {
    // Generate a new random tag (different from the allocation tag)
    let new_tagged = tag_alloc(ptr);
    tag_region(new_tagged, size);
}

/// # Safety
/// No-op on non-aarch64.
#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
pub unsafe fn tag_freed(_ptr: *mut u8, _size: usize) {}

/// Map anonymous memory with PROT_MTE flag for MTE support.
///
/// # Safety
/// `size` must be page-aligned and non-zero.
#[cfg(target_arch = "aarch64")]
pub unsafe fn map_anonymous_mte(size: usize) -> *mut u8 {
    const PROT_MTE: libc::c_int = 0x20;
    let result = libc::mmap(
        core::ptr::null_mut(),
        size,
        libc::PROT_READ | libc::PROT_WRITE | PROT_MTE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if result == libc::MAP_FAILED {
        core::ptr::null_mut()
    } else {
        result as *mut u8
    }
}

/// # Safety
/// `size` must be page-aligned and non-zero.
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn map_anonymous_mte(size: usize) -> *mut u8 {
    crate::platform::map_anonymous(size)
}
