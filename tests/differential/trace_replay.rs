/// Trace-driven differential testing.
/// Generates deterministic random op traces and replays them,
/// verifying that core ABI contracts hold.
///
/// Run with: rustc -O tests/differential/trace_replay.rs -o target/trace_replay && \
///           LD_PRELOAD=target/release/libcompatmalloc.so target/trace_replay

use std::collections::HashMap;

const MAX_LIVE: usize = 10000;

#[derive(Debug, Clone, Copy)]
enum Op {
    Malloc(usize),
    Free(usize), // slot id
    Realloc(usize, usize), // slot id, new size
    Calloc(usize, usize), // nmemb, size
}

/// Simple seeded PRNG
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn next_usize(&mut self, max: usize) -> usize {
        (self.next() as usize) % max
    }
}

fn generate_trace(seed: u64, count: usize) -> Vec<Op> {
    let mut rng = Rng::new(seed);
    let mut ops = Vec::with_capacity(count);
    let mut live_count = 0usize;

    for _ in 0..count {
        let r = rng.next() % 100;
        if r < 40 || live_count == 0 {
            // malloc with various size distributions
            let size = match rng.next() % 4 {
                0 => rng.next_usize(16) + 1, // tiny: 1-16
                1 => rng.next_usize(256) + 1, // small: 1-256
                2 => rng.next_usize(4096) + 1, // medium: 1-4096
                _ => rng.next_usize(65536) + 1, // large: 1-65536
            };
            ops.push(Op::Malloc(size));
            live_count += 1;
        } else if r < 65 {
            // free
            let slot = rng.next_usize(live_count.max(1));
            ops.push(Op::Free(slot));
            if live_count > 0 {
                live_count -= 1;
            }
        } else if r < 85 {
            // realloc
            let slot = rng.next_usize(live_count.max(1));
            let new_size = match rng.next() % 3 {
                0 => rng.next_usize(64) + 1,
                1 => rng.next_usize(1024) + 1,
                _ => rng.next_usize(16384) + 1,
            };
            ops.push(Op::Realloc(slot, new_size));
        } else {
            // calloc
            let nmemb = rng.next_usize(100) + 1;
            let size = rng.next_usize(256) + 1;
            ops.push(Op::Calloc(nmemb, size));
            live_count += 1;
        }

        // Cap live count
        if live_count > MAX_LIVE {
            ops.push(Op::Free(rng.next_usize(live_count)));
            live_count -= 1;
        }
    }

    ops
}

fn replay_trace(ops: &[Op]) -> (usize, usize) {
    let mut slots: Vec<(*mut u8, usize)> = Vec::new(); // (ptr, size)
    let mut alloc_count = 0usize;
    let mut free_count = 0usize;

    for op in ops {
        match *op {
            Op::Malloc(size) => {
                let ptr = unsafe { libc::malloc(size) } as *mut u8;
                assert!(!ptr.is_null(), "malloc({}) returned NULL", size);
                assert_eq!(
                    (ptr as usize) % 16,
                    0,
                    "malloc({}) returned unaligned ptr",
                    size
                );
                // Write a pattern
                unsafe {
                    std::ptr::write_bytes(ptr, 0xAA, size);
                }
                slots.push((ptr, size));
                alloc_count += 1;
            }
            Op::Free(slot_hint) => {
                if slots.is_empty() {
                    continue;
                }
                let idx = slot_hint % slots.len();
                let (ptr, _size) = slots.swap_remove(idx);
                unsafe {
                    libc::free(ptr as *mut libc::c_void);
                }
                free_count += 1;
            }
            Op::Realloc(slot_hint, new_size) => {
                if slots.is_empty() {
                    continue;
                }
                let idx = slot_hint % slots.len();
                let (old_ptr, old_size) = slots[idx];

                let new_ptr =
                    unsafe { libc::realloc(old_ptr as *mut libc::c_void, new_size) } as *mut u8;

                if new_size == 0 {
                    // realloc(p, 0) may return NULL (free behavior)
                    slots.swap_remove(idx);
                } else {
                    assert!(!new_ptr.is_null(), "realloc({}) returned NULL", new_size);
                    assert_eq!((new_ptr as usize) % 16, 0, "realloc returned unaligned ptr");
                    // Verify preserved content
                    let check_len = std::cmp::min(old_size, new_size);
                    for j in 0..check_len {
                        let byte = unsafe { *new_ptr.add(j) };
                        assert_eq!(
                            byte, 0xAA,
                            "realloc corrupted content at offset {} (old_size={}, new_size={})",
                            j, old_size, new_size
                        );
                    }
                    // Fill new region
                    unsafe {
                        std::ptr::write_bytes(new_ptr, 0xAA, new_size);
                    }
                    slots[idx] = (new_ptr, new_size);
                }
            }
            Op::Calloc(nmemb, size) => {
                let ptr = unsafe { libc::calloc(nmemb, size) } as *mut u8;
                let total = nmemb * size;
                if total == 0 {
                    continue;
                }
                assert!(!ptr.is_null(), "calloc({}, {}) returned NULL", nmemb, size);
                // Verify zero-fill
                for j in 0..std::cmp::min(total, 4096) {
                    assert_eq!(unsafe { *ptr.add(j) }, 0, "calloc not zeroed at {}", j);
                }
                // Write pattern for future realloc checks
                unsafe {
                    std::ptr::write_bytes(ptr, 0xAA, total);
                }
                slots.push((ptr, total));
                alloc_count += 1;
            }
        }
    }

    // Cleanup
    for (ptr, _) in slots {
        unsafe {
            libc::free(ptr as *mut libc::c_void);
        }
    }

    (alloc_count, free_count)
}

fn main() {
    let trace_size: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);

    println!("Differential test: {} ops per trace", trace_size);

    for seed in 0..10 {
        print!("  Seed {}: ", seed);
        let trace = generate_trace(seed, trace_size);
        let (allocs, frees) = replay_trace(&trace);
        println!("OK ({} allocs, {} frees)", allocs, frees);
    }

    println!("All traces passed.");
}
