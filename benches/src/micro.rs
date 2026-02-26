/// Microbenchmarks for compatmalloc.
///
/// Since compatmalloc is a cdylib, these benchmarks measure the allocator
/// through direct LD_PRELOAD testing rather than Rust criterion.
/// See scripts/run_comparison.sh for the comparison runner.

use std::hint::black_box;
use std::time::Instant;

extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn free(ptr: *mut u8);
    fn calloc(nmemb: usize, size: usize) -> *mut u8;
    fn realloc(ptr: *mut u8, size: usize) -> *mut u8;
}

/// Get the allocator name from environment or default.
fn allocator_name() -> String {
    std::env::var("ALLOCATOR_NAME").unwrap_or_else(|_| "unknown".to_string())
}

/// Measure malloc/free latency for a given size, N iterations.
fn bench_malloc_free(size: usize, iterations: usize) -> f64 {
    // Warmup
    for _ in 0..1000 {
        unsafe {
            let ptr = malloc(black_box(size));
            std::ptr::write_bytes(ptr, 0xAB, std::cmp::min(size, 64));
            free(black_box(ptr));
        }
    }
    let start = Instant::now();
    for _ in 0..iterations {
        unsafe {
            let ptr = malloc(black_box(size));
            std::ptr::write_bytes(ptr, 0xAB, std::cmp::min(size, 64));
            free(black_box(ptr));
        }
    }
    let elapsed = start.elapsed();
    elapsed.as_nanos() as f64 / iterations as f64
}

/// Measure calloc/free latency.
fn bench_calloc_free(size: usize, iterations: usize) -> f64 {
    for _ in 0..1000 {
        unsafe {
            let ptr = calloc(black_box(1), black_box(size));
            free(black_box(ptr));
        }
    }
    let start = Instant::now();
    for _ in 0..iterations {
        unsafe {
            let ptr = calloc(black_box(1), black_box(size));
            free(black_box(ptr));
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
            let mut ptr = malloc(black_box(16));
            for &size in black_box(&[32usize, 64, 128, 256, 512, 1024]) {
                ptr = realloc(black_box(ptr), size);
            }
            free(black_box(ptr));
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
                        let ptr = malloc(black_box(size));
                        std::ptr::write_bytes(ptr, 0xCD, std::cmp::min(size, 16));
                        free(black_box(ptr));
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
    let name = allocator_name();

    println!("=== microbenchmarks ({}) ===\n", name);

    // Machine-parseable key results for comparison
    let mut latencies: Vec<(usize, f64)> = Vec::new();
    let mut key_throughput_1t = 0.0f64;
    let mut key_throughput_4t = 0.0f64;

    println!("--- malloc/free latency (ns/op) ---");
    for &size in &[16, 32, 64, 128, 256, 512, 1024, 4096, 16384, 65536, 262144] {
        let ns = bench_malloc_free(size, iterations);
        println!("  size={:>8}: {:>8.1} ns", size, ns);
        latencies.push((size, ns));
    }

    println!("\n--- calloc/free latency (ns/op) ---");
    for &size in &[16, 64, 256, 1024, 4096, 65536] {
        let ns = bench_calloc_free(size, iterations);
        println!("  size={:>8}: {:>8.1} ns", size, ns);
    }

    println!("\n--- realloc grow pattern (ns/op) ---");
    let ns = bench_realloc_grow(iterations / 10);
    println!("  16->1024: {:.1} ns", ns);

    println!("\n--- multi-threaded throughput (Mops/sec) ---");
    for &threads in &[1, 2, 4, 8] {
        let ops_sec = bench_threaded_throughput(threads, iterations / threads, 64);
        let mops = ops_sec / 1_000_000.0;
        println!("  threads={}: {:>6.2} Mops/sec", threads, mops);
        if threads == 1 {
            key_throughput_1t = mops;
        }
        if threads == 4 {
            key_throughput_4t = mops;
        }
    }

    println!("\n--- memory overhead ---");
    // Allocate many small objects and check RSS
    let mut ptrs = Vec::new();
    let count = 100_000;
    let alloc_size = 64;
    let requested = count * alloc_size;

    for _ in 0..count {
        unsafe {
            let ptr = malloc(alloc_size);
            if !ptr.is_null() {
                std::ptr::write_bytes(ptr, 0, alloc_size);
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
        unsafe { free(ptr) };
    }

    // Print machine-parseable summary line
    print!("\nSUMMARY|{}", name);
    for &(size, ns) in &latencies {
        print!("|latency_{}={:.1}", size, ns);
    }
    println!("|throughput_1t={:.2}|throughput_4t={:.2}",
        key_throughput_1t, key_throughput_4t);

    println!("\nDone.");
}
