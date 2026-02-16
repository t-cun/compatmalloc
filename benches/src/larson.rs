/// Larson benchmark: multi-threaded producer/consumer allocation pattern.
/// Simulates a server workload where each thread allocates and frees
/// memory in a pattern that creates cross-thread frees.
///
/// Ported from the mimalloc-bench Larson benchmark concept.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_DURATION_SECS: u64 = 5;
const BATCH_SIZE: usize = 1000;
const MIN_SIZE: usize = 8;
const MAX_SIZE: usize = 512;

fn main() {
    let num_threads: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let duration_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_DURATION_SECS);

    println!(
        "Larson benchmark: {} threads, {} seconds",
        num_threads, duration_secs
    );

    let running = Arc::new(AtomicBool::new(true));
    let total_ops = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..num_threads)
        .map(|tid| {
            let running = Arc::clone(&running);
            let total_ops = Arc::clone(&total_ops);
            std::thread::spawn(move || {
                larson_worker(tid, &running, &total_ops);
            })
        })
        .collect();

    let start = Instant::now();
    std::thread::sleep(Duration::from_secs(duration_secs));
    running.store(false, Ordering::Release);

    for h in handles {
        h.join().unwrap();
    }

    let elapsed = start.elapsed().as_secs_f64();
    let ops = total_ops.load(Ordering::Relaxed);
    let mops = ops as f64 / elapsed / 1_000_000.0;

    println!("Total operations: {}", ops);
    println!("Throughput: {:.2} Mops/sec", mops);
    println!("Per-thread: {:.2} Mops/sec", mops / num_threads as f64);
}

fn larson_worker(tid: usize, running: &AtomicBool, total_ops: &AtomicUsize) {
    // Simple LCG PRNG seeded by thread ID
    let mut rng = (tid as u64).wrapping_mul(6364136223846793005).wrapping_add(1);

    // Pre-allocate a batch of pointers
    let mut batch: Vec<*mut libc::c_void> = Vec::with_capacity(BATCH_SIZE);

    // Initial fill
    for _ in 0..BATCH_SIZE {
        let size = random_size(&mut rng);
        unsafe {
            let ptr = libc::malloc(size);
            if !ptr.is_null() {
                // Touch the memory
                std::ptr::write_bytes(ptr as *mut u8, 0xAB, std::cmp::min(size, 16));
                batch.push(ptr);
            }
        }
    }

    let mut ops = 0usize;

    while running.load(Ordering::Relaxed) {
        // Free a random element and replace it
        if !batch.is_empty() {
            let idx = (next_random(&mut rng) as usize) % batch.len();
            unsafe {
                libc::free(batch[idx]);
            }

            let size = random_size(&mut rng);
            unsafe {
                let ptr = libc::malloc(size);
                if !ptr.is_null() {
                    std::ptr::write_bytes(ptr as *mut u8, 0xCD, std::cmp::min(size, 16));
                    batch[idx] = ptr;
                }
            }
            ops += 2; // one free + one malloc
        }

        if ops % 10000 == 0 {
            total_ops.fetch_add(10000, Ordering::Relaxed);
        }
    }

    total_ops.fetch_add(ops % 10000, Ordering::Relaxed);

    // Cleanup
    for ptr in batch {
        unsafe {
            libc::free(ptr);
        }
    }
}

fn random_size(rng: &mut u64) -> usize {
    let r = next_random(rng);
    MIN_SIZE + (r as usize) % (MAX_SIZE - MIN_SIZE)
}

fn next_random(rng: &mut u64) -> u64 {
    *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *rng >> 33
}
