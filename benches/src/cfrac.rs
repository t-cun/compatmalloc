/// cfrac-inspired benchmark: allocation-intensive computation.
/// Simulates the allocation pattern of continued fraction integer factorization,
/// which is extremely allocation-heavy (many small allocs/frees).

use std::time::Instant;

const DEFAULT_ITERATIONS: usize = 5_000_000;

fn main() {
    let iterations: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_ITERATIONS);

    println!("cfrac-style benchmark: {} iterations", iterations);

    let start = Instant::now();

    // Simulate bignum-style allocation pattern:
    // Many small allocations (16-128 bytes) with frequent realloc
    let mut active: Vec<(*mut libc::c_void, usize)> = Vec::new();
    let mut rng: u64 = 12345;

    for i in 0..iterations {
        let op = next_random(&mut rng) % 100;

        if op < 40 || active.is_empty() {
            // 40%: allocate a new "bignum"
            let size = 16 + (next_random(&mut rng) as usize % 112); // 16-128 bytes
            unsafe {
                let ptr = libc::malloc(size);
                if !ptr.is_null() {
                    // Initialize like a bignum header
                    std::ptr::write_bytes(ptr as *mut u8, 0, size);
                    active.push((ptr, size));
                }
            }
        } else if op < 60 {
            // 20%: free a random bignum
            let idx = next_random(&mut rng) as usize % active.len();
            unsafe {
                libc::free(active[idx].0);
            }
            active.swap_remove(idx);
        } else if op < 80 {
            // 20%: realloc (grow a bignum)
            let idx = next_random(&mut rng) as usize % active.len();
            let (ptr, old_size) = active[idx];
            let new_size = old_size + 16 + (next_random(&mut rng) as usize % 64);
            unsafe {
                let new_ptr = libc::realloc(ptr, new_size);
                if !new_ptr.is_null() {
                    active[idx] = (new_ptr, new_size);
                }
            }
        } else {
            // 20%: calloc (allocate zeroed)
            let size = 32 + (next_random(&mut rng) as usize % 96);
            unsafe {
                let ptr = libc::calloc(1, size);
                if !ptr.is_null() {
                    active.push((ptr, size));
                }
            }
        }

        // Periodically free everything to prevent unbounded growth
        if i % 50000 == 49999 {
            for (ptr, _) in active.drain(..) {
                unsafe {
                    libc::free(ptr);
                }
            }
        }
    }

    // Cleanup
    for (ptr, _) in active {
        unsafe {
            libc::free(ptr);
        }
    }

    let elapsed = start.elapsed();
    let ops_sec = iterations as f64 / elapsed.as_secs_f64();
    println!(
        "Elapsed: {:.3}s ({:.2} Mops/sec)",
        elapsed.as_secs_f64(),
        ops_sec / 1_000_000.0
    );
}

fn next_random(rng: &mut u64) -> u64 {
    *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *rng >> 33
}
