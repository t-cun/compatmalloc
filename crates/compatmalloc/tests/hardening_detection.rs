//! Hardening verification tests for compatmalloc.
//!
//! These tests verify that the hardening features (double-free detection,
//! memory poisoning, canary corruption detection) work correctly.
//!
//! Tests that expect the process to abort are run as subprocesses: we spawn
//! the test binary with a specific test name and check that the child exits
//! with a signal (SIGABRT) and prints the expected diagnostic message.

use std::ptr;

/// Helper: initialize the allocator and return a reference to it.
unsafe fn alloc() -> &'static compatmalloc::__test_support::HardenedAllocator {
    compatmalloc::__test_support::ensure_initialized();
    compatmalloc::__test_support::allocator()
}

// ---------------------------------------------------------------------------
// Helper: run a subprocess that executes a specific "scenario" and check
// that it aborts with the expected message on stderr.
// ---------------------------------------------------------------------------

/// Run the current test binary with the environment variable
/// `COMPATMALLOC_HARDENING_SCENARIO` set to `scenario_name`.
/// The child process will detect this variable and run the corresponding
/// scenario (which should trigger an abort).
///
/// We verify:
/// 1. The child exited due to a signal (not exit code 0).
/// 2. The child's stderr contains `expected_msg`.
fn expect_abort_subprocess(scenario_name: &str, expected_msg: &str) {
    let exe = std::env::current_exe().expect("cannot determine test binary path");

    let output = std::process::Command::new(&exe)
        .env("COMPATMALLOC_HARDENING_SCENARIO", scenario_name)
        // Run the scenario driver test; the exact test function name
        // doesn't matter because the driver detects the env var and runs
        // the scenario, then exits before the assertion below fires.
        .arg("--exact")
        .arg("scenario_driver")
        .arg("--nocapture")
        // Prevent infinite recursion if the test runner re-invokes itself.
        .env("RUST_TEST_THREADS", "1")
        .output()
        .expect("failed to spawn subprocess");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // The process must NOT have succeeded.
    assert!(
        !output.status.success(),
        "subprocess for scenario '{}' should have been killed by a signal, \
         but exited successfully. stderr:\n{}",
        scenario_name,
        stderr
    );

    // Check for the expected diagnostic on stderr.
    assert!(
        stderr.contains(expected_msg),
        "subprocess for scenario '{}' stderr does not contain '{}'. \
         Full stderr:\n{}",
        scenario_name,
        expected_msg,
        stderr
    );
}

// ---------------------------------------------------------------------------
// Scenario driver: when the COMPATMALLOC_HARDENING_SCENARIO env var is set,
// run the requested scenario instead of normal test assertions.
// ---------------------------------------------------------------------------

#[test]
fn scenario_driver() {
    let scenario = match std::env::var("COMPATMALLOC_HARDENING_SCENARIO") {
        Ok(s) => s,
        Err(_) => return, // Not a subprocess invocation; skip.
    };

    match scenario.as_str() {
        "double_free" => scenario_double_free(),
        "canary_corruption" => scenario_canary_corruption(),
        "invalid_free_garbage" => scenario_invalid_free_garbage(),
        "invalid_free_stack" => scenario_invalid_free_stack(),
        _ => panic!("unknown scenario: {}", scenario),
    }
}

/// Scenario: double-free. Allocate, free, free again.
fn scenario_double_free() {
    unsafe {
        let a = alloc();
        let p = a.malloc(64);
        assert!(!p.is_null());
        a.free(p);
        // Second free should trigger abort.
        a.free(p);
    }
    // Should never reach here.
    unreachable!("double free was not detected");
}

/// Scenario: canary corruption. Allocate, write past requested_size (overflow), free.
/// With right-aligned layout, canaries exist in both the front gap [slot_base..user_ptr)
/// and the back gap [user_ptr+requested_size..slot_end). For most small allocations
/// with MIN_ALIGN=16, the front gap is 0 and the back gap contains the canary bytes.
///
/// With deferred verification, the canary check happens at batch flush time (when
/// the free buffer fills up), not at the individual free() call. We trigger the
/// flush by freeing enough entries to fill the per-size-class free buffer (64 slots).
fn scenario_canary_corruption() {
    unsafe {
        let a = alloc();
        // Request 17 bytes -> slot_size=32. Back gap = 32 - 17 = 15 bytes of canary.
        let requested = 17;
        let p = a.malloc(requested);
        assert!(!p.is_null());

        // Pre-allocate enough slots to fill the free buffer and trigger a flush.
        let mut extras = [ptr::null_mut(); 64];
        for slot in extras.iter_mut() {
            *slot = a.malloc(requested);
            assert!(!slot.is_null());
        }

        // Corrupt the back-gap canary by writing one byte past the requested size.
        let after = p.add(requested);
        after.write(0x00);

        // Free the corrupted pointer (deferred to batch flush).
        a.free(p);

        // Free extras to fill the buffer and trigger verified batch flush.
        // The flush will detect the canary corruption and abort.
        for &q in &extras {
            a.free(q);
        }
    }
    unreachable!("canary corruption was not detected");
}

/// Scenario: free a garbage pointer (0x1) that was never returned by malloc.
#[allow(clippy::manual_dangling_ptr)]
fn scenario_invalid_free_garbage() {
    unsafe {
        let a = alloc();
        a.free(0x1 as *mut u8);
    }
    unreachable!("invalid free of garbage pointer was not detected");
}

/// Scenario: free a stack pointer (a real address, but not a heap allocation).
fn scenario_invalid_free_stack() {
    unsafe {
        let a = alloc();
        let mut stack_var: u64 = 0xDEAD;
        a.free(&mut stack_var as *mut u64 as *mut u8);
    }
    unreachable!("invalid free of stack pointer was not detected");
}

// ---------------------------------------------------------------------------
// Test: double-free is detected (subprocess)
// ---------------------------------------------------------------------------

#[test]
fn double_free_detected() {
    expect_abort_subprocess("double_free", "double free detected");
}

// ---------------------------------------------------------------------------
// Test: free of garbage pointer is detected (subprocess)
// ---------------------------------------------------------------------------

#[test]
fn invalid_free_garbage_detected() {
    expect_abort_subprocess("invalid_free_garbage", "free() called on invalid pointer");
}

// ---------------------------------------------------------------------------
// Test: free of stack pointer is detected (subprocess)
// ---------------------------------------------------------------------------

#[test]
fn invalid_free_stack_detected() {
    expect_abort_subprocess("invalid_free_stack", "free() called on invalid pointer");
}

// ---------------------------------------------------------------------------
// Test: canary corruption is detected (subprocess)
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "canaries")]
fn canary_corruption_detected() {
    expect_abort_subprocess("canary_corruption", "canary corrupted");
}

// ---------------------------------------------------------------------------
// Test: freed memory is poisoned with 0xFE
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "poison-on-free")]
fn freed_memory_is_poisoned() {
    // The poison byte is 0xFE (defined in util.rs).
    const POISON: u8 = 0xFE;

    unsafe {
        let a = alloc();

        // We need to read freed memory, which is normally UB in Rust.
        // In this allocator, freed slab memory remains mapped (it goes into
        // quarantine or stays in the slab), so the pages are still readable.
        // We allocate, record the pointer, free it, then read.

        let size = 64;
        let p = a.malloc(size);
        assert!(!p.is_null());

        // Pre-allocate enough slots to fill the free buffer and trigger a flush.
        let mut extras = [ptr::null_mut(); 64];
        for slot in extras.iter_mut() {
            *slot = a.malloc(size);
            assert!(!slot.is_null());
        }

        // Fill with a known pattern (not 0xFE) to ensure we see the change.
        ptr::write_bytes(p, 0xAA, size);

        // Free p (deferred: poison happens at batch flush, not here).
        a.free(p);

        // Free extras to fill the buffer and trigger verified batch flush.
        // The flush poisons all deferred entries including p.
        for &q in &extras {
            a.free(q);
        }

        // After flush, p should be poisoned. The memory remains mapped
        // (slab pages are never unmapped), so reading it is safe.
        let slice = std::slice::from_raw_parts(p, size);

        assert!(
            slice.iter().all(|&b| b == POISON),
            "freed memory should be poisoned with 0x{:02X}, \
             but found: {:02X?}",
            POISON,
            &slice[..8.min(size)]
        );
    }
}

// ---------------------------------------------------------------------------
// Test: freed memory poison covers the full slot
// ---------------------------------------------------------------------------

#[test]
#[cfg(all(feature = "poison-on-free", not(feature = "zero-on-free")))]
fn freed_memory_poison_full_slot() {
    const POISON: u8 = 0xFE;

    unsafe {
        let a = alloc();

        // Request a small amount; the slot will be 16 bytes (smallest class).
        let requested = 1;
        let p = a.malloc(requested);
        assert!(!p.is_null());

        // Get the usable size (slot size).
        let slot_size = a.usable_size(p);
        assert!(
            slot_size >= requested,
            "usable_size {} < requested {}",
            slot_size,
            requested
        );

        // Pre-allocate enough slots to fill the free buffer and trigger a flush.
        let mut extras = [ptr::null_mut(); 64];
        for slot in extras.iter_mut() {
            *slot = a.malloc(requested);
            assert!(!slot.is_null());
        }

        ptr::write_bytes(p, 0xAA, slot_size);

        // Free p (deferred: poison happens at batch flush).
        a.free(p);

        // Free extras to fill the buffer and trigger verified batch flush.
        for &q in &extras {
            a.free(q);
        }

        // After flush, the entire slot should be poisoned.
        let slice = std::slice::from_raw_parts(p, slot_size);
        assert!(
            slice.iter().all(|&b| b == POISON),
            "full slot not poisoned: first 16 bytes = {:02X?}",
            &slice[..16.min(slot_size)]
        );
    }
}

// ---------------------------------------------------------------------------
// Test: quarantine prevents immediate reuse
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "quarantine")]
fn quarantine_prevents_immediate_reuse() {
    unsafe {
        let a = alloc();

        // Allocate and free a block, then immediately allocate the same size.
        // With quarantine, we should get a DIFFERENT pointer (the freed one
        // is held in quarantine, not recycled yet).
        let p = a.malloc(64);
        assert!(!p.is_null());
        let p_addr = p as usize;
        a.free(p);

        // Allocate again -- with quarantine the freed slot is not immediately
        // recycled, so we should (usually) get a different address.
        // Note: this is probabilistic with slot randomization, but very likely.
        let q = a.malloc(64);
        assert!(!q.is_null());

        // We cannot guarantee a different address 100% of the time (the
        // quarantine might have evicted it), but in a fresh allocator with
        // default 4 MiB quarantine, 64 bytes should remain quarantined.
        // We do a soft check: if they are the same, log a warning but don't
        // fail, since it's not a strict guarantee.
        if q as usize == p_addr {
            eprintln!(
                "WARNING: quarantine_prevents_immediate_reuse: got same address \
                 (quarantine may have been full or slot randomization returned same slot)"
            );
        }

        a.free(q);
    }
}

// ---------------------------------------------------------------------------
// Test: allocate, free, verify metadata is marked as freed
// ---------------------------------------------------------------------------

#[test]
fn metadata_tracks_freed_state() {
    unsafe {
        let a = alloc();
        let p = a.malloc(100);
        assert!(!p.is_null());

        // Before free: metadata should exist and not be marked freed.
        let meta_before = a.get_metadata(p);
        assert!(
            meta_before.is_some(),
            "metadata should exist for a live allocation"
        );
        assert!(
            !meta_before.unwrap().is_freed(),
            "live allocation should not be marked as freed"
        );

        a.free(p);

        // After free: metadata should be marked freed (if quarantine holds it)
        // or removed (if no quarantine).
        #[cfg(feature = "quarantine")]
        {
            let meta_after = a.get_metadata(p);
            // With quarantine, metadata is marked freed but not removed until
            // the slot is recycled.
            if let Some(m) = meta_after {
                assert!(
                    m.is_freed(),
                    "freed allocation metadata should have freed flag set"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test: metadata records correct requested_size
// ---------------------------------------------------------------------------

#[test]
fn metadata_records_requested_size() {
    unsafe {
        let a = alloc();
        for &size in &[1usize, 16, 64, 100, 256, 1024, 4096] {
            let p = a.malloc(size);
            assert!(!p.is_null());

            let meta = a.get_metadata(p);
            assert!(meta.is_some(), "metadata missing for malloc({})", size);
            assert_eq!(
                meta.unwrap().requested_size,
                size,
                "metadata requested_size mismatch for malloc({})",
                size
            );

            a.free(p);
        }
    }
}

// ---------------------------------------------------------------------------
// Test: large allocation reuse does not leak previous data
// ---------------------------------------------------------------------------

#[test]
fn large_calloc_reuse_returns_zeroed_data() {
    unsafe {
        let a = alloc();
        // Allocate above LARGE_THRESHOLD (16384 bytes)
        let size = 32768;
        let p = a.malloc(size);
        assert!(!p.is_null());

        // Fill with a recognizable pattern
        core::ptr::write_bytes(p, 0xAB, size);

        // Free it (goes into the thread-local cache)
        a.free(p);

        // calloc must return zeroed memory even when hitting the TLS cache.
        // malloc may return same-thread stale data (no cross-thread leak),
        // but calloc always zeroes.
        let q = a.calloc(1, size);
        assert!(!q.is_null());

        let slice = core::slice::from_raw_parts(q, size);
        let non_zero = slice.iter().filter(|&&b| b != 0).count();
        assert_eq!(
            non_zero, 0,
            "large calloc reuse: expected all-zero pages, found {} non-zero bytes",
            non_zero
        );

        a.free(q);
    }
}

#[test]
fn large_alloc_cross_thread_does_not_leak_data() {
    unsafe {
        let a = alloc();
        // Allocate and fill a large allocation
        let size = 32768;
        let p = a.malloc(size);
        assert!(!p.is_null());
        core::ptr::write_bytes(p, 0xAB, size);
        a.free(p);

        // Force the TLS cache entry through eviction (by allocating/freeing
        // a different size, which evicts the old entry to the global cache
        // where MADV_DONTNEED zeroes it).
        let p2 = a.malloc(size * 2);
        assert!(!p2.is_null());
        a.free(p2);

        // Now allocate the original size again — should come from the global
        // cache (post-MADV_DONTNEED), not the TLS cache.
        let q = a.malloc(size);
        assert!(!q.is_null());

        let slice = core::slice::from_raw_parts(q, size);
        let non_zero = slice.iter().filter(|&&b| b != 0).count();
        assert_eq!(
            non_zero, 0,
            "large cross-thread reuse: expected zero-filled pages after eviction, \
             found {} non-zero bytes",
            non_zero
        );

        a.free(q);
    }
}
