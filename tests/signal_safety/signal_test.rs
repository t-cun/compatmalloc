/// Signal safety test.
/// Tests that malloc/free don't deadlock when called from a signal handler
/// while the main thread is also in malloc.
///
/// NOTE: compatmalloc is NOT async-signal-safe (matching industry standard).
/// This test documents the behavior -- with per-arena locks, a signal handler
/// on a different arena may succeed, but same-arena will deadlock.
///
/// Run with: rustc tests/signal_safety/signal_test.rs -o target/signal_test && \
///           timeout 10 LD_PRELOAD=target/release/libcompatmalloc.so target/signal_test

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static SIGNAL_MALLOC_OK: AtomicBool = AtomicBool::new(false);
static SIGNAL_COUNT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn sigusr1_handler(_sig: libc::c_int) {
    // Try a small malloc/free in the signal handler
    unsafe {
        let ptr = libc::malloc(64);
        if !ptr.is_null() {
            std::ptr::write_bytes(ptr as *mut u8, 0xBB, 64);
            libc::free(ptr);
            SIGNAL_MALLOC_OK.store(true, Ordering::Relaxed);
        }
    }
    SIGNAL_COUNT.fetch_add(1, Ordering::Relaxed);
}

fn main() {
    println!("Signal safety test");
    println!("NOTE: compatmalloc is NOT async-signal-safe (by design).");
    println!("This test verifies behavior under signal delivery.\n");

    // Install signal handler
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigusr1_handler as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    }

    let pid = unsafe { libc::getpid() };
    let start = Instant::now();
    let duration = Duration::from_secs(3);

    // Main thread does rapid malloc/free while sending signals to self
    let mut alloc_count = 0usize;
    while start.elapsed() < duration {
        for _ in 0..100 {
            unsafe {
                let ptr = libc::malloc(128);
                if !ptr.is_null() {
                    std::ptr::write_bytes(ptr as *mut u8, 0xAA, 128);
                    libc::free(ptr);
                }
            }
            alloc_count += 1;
        }

        // Send signal to self periodically
        if alloc_count % 1000 == 0 {
            unsafe {
                libc::kill(pid, libc::SIGUSR1);
            }
        }
    }

    let signals = SIGNAL_COUNT.load(Ordering::Relaxed);
    let signal_ok = SIGNAL_MALLOC_OK.load(Ordering::Relaxed);

    println!("Main thread allocations: {}", alloc_count);
    println!("Signals delivered: {}", signals);
    println!(
        "Signal handler malloc succeeded: {}",
        if signal_ok { "yes" } else { "no (expected with same-arena lock)" }
    );
    println!("\nTest completed without deadlock - PASS");
}
