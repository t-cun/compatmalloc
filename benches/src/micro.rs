/// Microbenchmarks for compatmalloc.
/// Run with: cargo bench (requires criterion as dev-dependency)
///
/// Since compatmalloc is a cdylib, these benchmarks measure the allocator
/// through direct LD_PRELOAD testing rather than Rust criterion.
/// See scripts/run_comparison.sh for the comparison runner.

use std::time::Instant;

/// Measure malloc/free latency for a given size, N iterations.
fn bench_malloc_free(size: usize, iterations: usize) -> f64 {
    let start = Instant::now();
    for _ in 0..iterations {
        unsafe {
            let ptr = libc::malloc(size);
            if !ptr.is_null() {
                // Touch the memory to make it realistic
                std::ptr::write_bytes(ptr as *mut u8, 0xAB, std::cmp::min(size, 64));
                libc::free(ptr);
            }
        }
    }
    let elapsed = start.elapsed();
    elapsed.as_nanos() as f64 / iterations as f64
}

/// Measure calloc/free latency.
fn bench_calloc_free(size: usize, iterations: usize) -> f64 {
    let start = Instant::now();
    for _ in 0..iterations {
        unsafe {
            let ptr = libc::calloc(1, size);
            if !ptr.is_null() {
                libc::free(ptr);
            }
        }
    }
    let elapsed = start.elapsed();
    elapsed.as_nanos() as f64 / iterations as f64
}

/// Measure realloc growing pattern.
fn bench_realloc_grow(iterations: usize) -> f64 {
    let start = Instant::now();
    for _ in 0..iterations {
        unsafe {
            let mut ptr = libc::malloc(16);
            for size in [32, 64, 128, 256, 512, 1024] {
                ptr = libc::realloc(ptr, size);
            }
            if !ptr.is_null() {
                libc::free(ptr);
            }
        }
    }
    let elapsed = start.elapsed();
    elapsed.as_nanos() as f64 / iterations as f64
}

/// Measure multi-threaded throughput.
fn bench_threaded_throughput(num_threads: usize, ops_per_thread: usize, size: usize) -> f64 {
    let start = Instant::now();
    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            std::thread::spawn(move || {
                for _ in 0..ops_per_thread {
                    unsafe {
                        let ptr = libc::malloc(size);
                        if !ptr.is_null() {
                            std::ptr::write_bytes(ptr as *mut u8, 0xCD, std::cmp::min(size, 16));
                            libc::free(ptr);
                        }
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
    let elapsed = start.elapsed();
    let total_ops = num_threads * ops_per_thread;
    total_ops as f64 / elapsed.as_secs_f64() // ops/sec
}

fn main() {
    let iterations = 1_000_000;

    println!("=== compatmalloc microbenchmarks ===\n");

    println!("--- malloc/free latency (ns/op) ---");
    for &size in &[16, 32, 64, 128, 256, 512, 1024, 4096, 16384, 65536, 262144] {
        let ns = bench_malloc_free(size, iterations);
        println!("  size={:>8}: {:.1} ns", size, ns);
    }

    println!("\n--- calloc/free latency (ns/op) ---");
    for &size in &[16, 64, 256, 1024, 4096, 65536] {
        let ns = bench_calloc_free(size, iterations);
        println!("  size={:>8}: {:.1} ns", size, ns);
    }

    println!("\n--- realloc grow pattern (ns/op) ---");
    let ns = bench_realloc_grow(iterations / 10);
    println!("  16->1024: {:.1} ns", ns);

    println!("\n--- multi-threaded throughput (Mops/sec) ---");
    for &threads in &[1, 2, 4, 8] {
        let ops_sec = bench_threaded_throughput(threads, iterations / threads, 64);
        println!("  threads={}: {:.2} Mops/sec", threads, ops_sec / 1_000_000.0);
    }

    println!("\n--- memory overhead ---");
    // Allocate many small objects and check RSS
    let mut ptrs = Vec::new();
    let count = 100_000;
    let alloc_size = 64;
    let requested = count * alloc_size;

    for _ in 0..count {
        unsafe {
            let ptr = libc::malloc(alloc_size);
            if !ptr.is_null() {
                std::ptr::write_bytes(ptr as *mut u8, 0, alloc_size);
                ptrs.push(ptr);
            }
        }
    }

    // Read RSS from /proc/self/statm
    if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
        let parts: Vec<&str> = statm.split_whitespace().collect();
        if parts.len() >= 2 {
            let rss_pages: usize = parts[1].parse().unwrap_or(0);
            let rss_bytes = rss_pages * 4096;
            println!(
                "  {} allocs x {} bytes = {} bytes requested",
                count, alloc_size, requested
            );
            println!("  RSS: {} bytes ({:.1}x overhead)", rss_bytes, rss_bytes as f64 / requested as f64);
        }
    }

    for ptr in ptrs {
        unsafe { libc::free(ptr) };
    }

    println!("\nDone.");
}
