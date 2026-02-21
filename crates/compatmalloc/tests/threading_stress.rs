//! Thread stress tests for compatmalloc.
//!
//! These tests exercise the allocator under heavy multi-threaded contention,
//! verifying that concurrent malloc/free operations do not cause data corruption,
//! deadlocks, or crashes.

use std::ptr;
use std::sync::{Arc, Barrier};
use std::thread;

/// Helper: initialize the allocator and return a reference to it.
unsafe fn alloc() -> &'static compatmalloc::__test_support::HardenedAllocator {
    compatmalloc::__test_support::ensure_initialized();
    compatmalloc::__test_support::allocator()
}

// ---------------------------------------------------------------------------
// N threads doing rapid malloc/free cycles
// ---------------------------------------------------------------------------

fn stress_malloc_free_n_threads(num_threads: usize) {
    const ITERATIONS: usize = 10_000;
    const ALLOC_SIZE: usize = 128;

    // Ensure the allocator is initialized on the main thread first.
    unsafe {
        alloc();
    }

    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                unsafe {
                    let a = alloc();
                    for _ in 0..ITERATIONS {
                        let p = a.malloc(ALLOC_SIZE);
                        assert!(!p.is_null(), "malloc returned NULL under contention");
                        // Write a pattern.
                        ptr::write_bytes(p, 0xCC, ALLOC_SIZE);
                        a.free(p);
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked during malloc/free stress");
    }
}

#[test]
fn stress_malloc_free_4_threads() {
    stress_malloc_free_n_threads(4);
}

#[test]
fn stress_malloc_free_8_threads() {
    stress_malloc_free_n_threads(8);
}

#[test]
fn stress_malloc_free_16_threads() {
    stress_malloc_free_n_threads(16);
}

// ---------------------------------------------------------------------------
// Cross-thread free: thread A allocates, thread B frees
// ---------------------------------------------------------------------------

/// Wrapper to allow sending `*mut u8` across thread boundaries.
/// Safety: the pointers inside are heap-allocated by our allocator, which is
/// thread-safe. We only send ownership (one thread allocates, another frees).
#[derive(Clone, Copy)]
struct SendPtr(*mut u8);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

#[test]
fn cross_thread_free() {
    const COUNT: usize = 1_000;
    const SIZE: usize = 64;

    unsafe {
        alloc();
    }

    let barrier = Arc::new(Barrier::new(2));

    // Channel-like approach using a shared vector protected by a mutex.
    let shared: Arc<std::sync::Mutex<Vec<SendPtr>>> =
        Arc::new(std::sync::Mutex::new(Vec::with_capacity(COUNT)));

    // Producer thread: allocates and pushes pointers.
    let shared_producer = Arc::clone(&shared);
    let barrier_producer = Arc::clone(&barrier);
    let producer = thread::spawn(move || {
        barrier_producer.wait();
        unsafe {
            let a = alloc();
            for _ in 0..COUNT {
                let p = a.malloc(SIZE);
                assert!(!p.is_null());
                // Write a pattern so the memory is "used".
                ptr::write_bytes(p, 0xDD, SIZE);
                shared_producer.lock().unwrap().push(SendPtr(p));
            }
        }
    });

    // Consumer thread: waits for pointers and frees them.
    let shared_consumer = Arc::clone(&shared);
    let barrier_consumer = Arc::clone(&barrier);
    let consumer = thread::spawn(move || {
        barrier_consumer.wait();
        unsafe {
            let a = alloc();
            let mut freed = 0;
            while freed < COUNT {
                let batch: Vec<SendPtr> = {
                    let mut guard = shared_consumer.lock().unwrap();
                    guard.drain(..).collect()
                };
                for sp in batch {
                    a.free(sp.0);
                    freed += 1;
                }
                if freed < COUNT {
                    thread::yield_now();
                }
            }
        }
    });

    producer.join().expect("producer thread panicked");
    consumer.join().expect("consumer thread panicked");
}

// ---------------------------------------------------------------------------
// Data corruption check: write pattern, verify after free/realloc in threads
// ---------------------------------------------------------------------------

#[test]
fn no_data_corruption_under_contention() {
    const NUM_THREADS: usize = 8;
    const ITERATIONS: usize = 2_000;
    const SIZE: usize = 256;

    unsafe {
        alloc();
    }

    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|tid| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                unsafe {
                    let a = alloc();
                    let pattern = (tid & 0xFF) as u8;

                    for _ in 0..ITERATIONS {
                        let p = a.malloc(SIZE);
                        assert!(!p.is_null());

                        // Fill with a thread-specific pattern.
                        ptr::write_bytes(p, pattern, SIZE);

                        // Verify the pattern is intact.
                        let slice = std::slice::from_raw_parts(p, SIZE);
                        assert!(
                            slice.iter().all(|&b| b == pattern),
                            "data corruption detected: thread {} found unexpected byte",
                            tid
                        );

                        a.free(p);
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked during corruption check");
    }
}

// ---------------------------------------------------------------------------
// Various sizes under contention
// ---------------------------------------------------------------------------

#[test]
fn various_sizes_under_contention() {
    const NUM_THREADS: usize = 8;
    const SIZES: [usize; 10] = [1, 16, 32, 64, 128, 256, 512, 1024, 4096, 16384];

    unsafe {
        alloc();
    }

    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|tid| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                unsafe {
                    let a = alloc();
                    for _ in 0..500 {
                        let size = SIZES[tid % SIZES.len()];
                        let p = a.malloc(size);
                        assert!(
                            !p.is_null(),
                            "malloc({}) returned NULL in thread {}",
                            size,
                            tid
                        );

                        // Write and verify.
                        ptr::write_bytes(p, 0xEE, size);
                        let slice = std::slice::from_raw_parts(p, size);
                        assert!(
                            slice.iter().all(|&b| b == 0xEE),
                            "data corruption for size {} in thread {}",
                            size,
                            tid
                        );

                        a.free(p);
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked during various-sizes test");
    }
}

// ---------------------------------------------------------------------------
// Hold-and-free: each thread holds multiple live allocations at once
// ---------------------------------------------------------------------------

#[test]
fn hold_and_free_multiple_allocations() {
    const NUM_THREADS: usize = 8;
    const LIVE_COUNT: usize = 100;
    const ROUNDS: usize = 50;
    const SIZE: usize = 128;

    unsafe {
        alloc();
    }

    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|tid| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                unsafe {
                    let a = alloc();
                    let pattern = ((tid + 1) & 0xFF) as u8;

                    for _ in 0..ROUNDS {
                        let mut ptrs = Vec::with_capacity(LIVE_COUNT);

                        // Allocate a batch.
                        for _ in 0..LIVE_COUNT {
                            let p = a.malloc(SIZE);
                            assert!(!p.is_null());
                            ptr::write_bytes(p, pattern, SIZE);
                            ptrs.push(p);
                        }

                        // Verify all are still intact.
                        for &p in &ptrs {
                            let slice = std::slice::from_raw_parts(p, SIZE);
                            assert!(
                                slice.iter().all(|&b| b == pattern),
                                "corruption in hold-and-free, thread {}",
                                tid
                            );
                        }

                        // Free all.
                        for p in ptrs {
                            a.free(p);
                        }
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked during hold-and-free test");
    }
}

// ---------------------------------------------------------------------------
// Interleaved realloc under contention
// ---------------------------------------------------------------------------

#[test]
fn realloc_under_contention() {
    const NUM_THREADS: usize = 4;
    const ITERATIONS: usize = 1_000;

    unsafe {
        alloc();
    }

    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|tid| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                unsafe {
                    let a = alloc();
                    let pattern = ((tid + 0x10) & 0xFF) as u8;

                    for _ in 0..ITERATIONS {
                        let initial_size = 32;
                        let p = a.malloc(initial_size);
                        assert!(!p.is_null());
                        ptr::write_bytes(p, pattern, initial_size);

                        // Grow.
                        let grown_size = 256;
                        let q = a.realloc(p, grown_size);
                        assert!(!q.is_null());

                        // Original bytes must still match.
                        let slice = std::slice::from_raw_parts(q, initial_size);
                        assert!(
                            slice.iter().all(|&b| b == pattern),
                            "corruption after realloc grow, thread {}",
                            tid
                        );

                        a.free(q);
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join()
            .expect("thread panicked during realloc contention test");
    }
}
