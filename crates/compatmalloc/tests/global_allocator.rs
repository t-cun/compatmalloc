#![cfg(feature = "global-allocator")]

use compatmalloc::CompatMalloc;

#[global_allocator]
static GLOBAL: CompatMalloc = CompatMalloc;

#[test]
fn basic_alloc_and_free() {
    // Box allocation
    let b = Box::new(42u64);
    assert_eq!(*b, 42);
    drop(b);

    // Vec allocation
    let mut v: Vec<u32> = Vec::new();
    for i in 0..1000 {
        v.push(i);
    }
    assert_eq!(v.len(), 1000);
    assert_eq!(v[999], 999);
    drop(v);

    // String allocation
    let s = String::from("hello, compatmalloc global allocator!");
    assert_eq!(s, "hello, compatmalloc global allocator!");
    drop(s);
}

#[test]
fn zero_size_alloc() {
    // Vec<()> has zero-sized elements
    let mut v: Vec<()> = Vec::new();
    for _ in 0..100 {
        v.push(());
    }
    assert_eq!(v.len(), 100);
    drop(v);

    // Zero-capacity Vec should also work
    let v: Vec<u8> = Vec::new();
    assert_eq!(v.len(), 0);
    drop(v);
}

#[test]
fn aligned_alloc() {
    use std::alloc::{alloc, dealloc, Layout};

    unsafe {
        // 128-byte aligned allocation
        let layout = Layout::from_size_align(256, 128).unwrap();
        let ptr = alloc(layout);
        assert!(!ptr.is_null(), "128-byte aligned allocation returned null");
        assert_eq!(
            ptr as usize % 128,
            0,
            "pointer is not 128-byte aligned: {:p}",
            ptr
        );

        // Write and read back
        core::ptr::write(ptr, 0xAB);
        core::ptr::write(ptr.add(255), 0xCD);
        assert_eq!(core::ptr::read(ptr), 0xAB);
        assert_eq!(core::ptr::read(ptr.add(255)), 0xCD);

        dealloc(ptr, layout);

        // 64-byte aligned allocation
        let layout = Layout::from_size_align(512, 64).unwrap();
        let ptr = alloc(layout);
        assert!(!ptr.is_null(), "64-byte aligned allocation returned null");
        assert_eq!(
            ptr as usize % 64,
            0,
            "pointer is not 64-byte aligned: {:p}",
            ptr
        );
        dealloc(ptr, layout);
    }
}

#[test]
fn realloc_works() {
    // Realloc through Vec growth
    let mut v: Vec<u8> = Vec::with_capacity(16);
    for i in 0u8..200 {
        v.push(i);
    }
    // Verify data integrity after reallocations
    for i in 0u8..200 {
        assert_eq!(v[i as usize], i);
    }
}

#[test]
fn alloc_zeroed_works() {
    use std::alloc::{alloc_zeroed, dealloc, Layout};

    unsafe {
        let layout = Layout::from_size_align(1024, 16).unwrap();
        let ptr = alloc_zeroed(layout);
        assert!(!ptr.is_null(), "alloc_zeroed returned null");

        // Verify all bytes are zero
        let slice = core::slice::from_raw_parts(ptr, 1024);
        assert!(
            slice.iter().all(|&b| b == 0),
            "alloc_zeroed did not return zeroed memory"
        );

        dealloc(ptr, layout);
    }
}

#[test]
fn over_aligned_realloc() {
    use std::alloc::{alloc, dealloc, realloc, Layout};

    unsafe {
        let layout = Layout::from_size_align(64, 128).unwrap();
        let ptr = alloc(layout);
        assert!(!ptr.is_null());
        assert_eq!(ptr as usize % 128, 0, "not 128-byte aligned: {:p}", ptr);
        core::ptr::write(ptr, 0xAB);

        let new_ptr = realloc(ptr, layout, 256);
        assert!(!new_ptr.is_null());
        assert_eq!(
            new_ptr as usize % 128,
            0,
            "realloc lost alignment: {:p}",
            new_ptr
        );
        assert_eq!(core::ptr::read(new_ptr), 0xAB, "realloc lost data");

        let new_layout = Layout::from_size_align(256, 128).unwrap();
        dealloc(new_ptr, new_layout);
    }
}

#[test]
fn over_aligned_alloc_zeroed() {
    use std::alloc::{alloc_zeroed, dealloc, Layout};

    unsafe {
        let layout = Layout::from_size_align(512, 128).unwrap();
        let ptr = alloc_zeroed(layout);
        assert!(!ptr.is_null());
        assert_eq!(ptr as usize % 128, 0, "not 128-byte aligned: {:p}", ptr);

        let slice = core::slice::from_raw_parts(ptr, 512);
        assert!(
            slice.iter().all(|&b| b == 0),
            "over-aligned alloc_zeroed did not return zeroed memory"
        );

        dealloc(ptr, layout);
    }
}
