#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz target that interprets a byte slice as a sequence of allocator operations.
///
/// Each operation is encoded as:
///   byte 0: opcode (0=malloc, 1=free, 2=realloc, 3=calloc)
///   byte 1-2: size (little-endian u16)
///   byte 3: slot index (which tracked pointer to operate on)
///
/// We track up to 64 live pointers.
const MAX_SLOTS: usize = 64;

fuzz_target!(|data: &[u8]| {
    let mut slots: [*mut u8; MAX_SLOTS] = [std::ptr::null_mut(); MAX_SLOTS];
    let mut sizes: [usize; MAX_SLOTS] = [0; MAX_SLOTS];

    let mut i = 0;
    while i + 4 <= data.len() {
        let opcode = data[i] & 0x03;
        let size = u16::from_le_bytes([data[i + 1], data[i + 2]]) as usize;
        let slot = (data[i + 3] as usize) % MAX_SLOTS;
        i += 4;

        match opcode {
            0 => {
                // malloc
                if !slots[slot].is_null() {
                    unsafe { libc::free(slots[slot] as *mut libc::c_void) };
                }
                let ptr = unsafe { libc::malloc(size) } as *mut u8;
                slots[slot] = ptr;
                sizes[slot] = size;
                if !ptr.is_null() && size > 0 {
                    // Write pattern
                    unsafe {
                        std::ptr::write_bytes(ptr, 0xAA, std::cmp::min(size, 256));
                    }
                }
            }
            1 => {
                // free
                if !slots[slot].is_null() {
                    unsafe { libc::free(slots[slot] as *mut libc::c_void) };
                    slots[slot] = std::ptr::null_mut();
                    sizes[slot] = 0;
                }
            }
            2 => {
                // realloc
                if !slots[slot].is_null() {
                    let ptr = unsafe {
                        libc::realloc(slots[slot] as *mut libc::c_void, size)
                    } as *mut u8;
                    if !ptr.is_null() {
                        slots[slot] = ptr;
                        sizes[slot] = size;
                    } else if size == 0 {
                        slots[slot] = std::ptr::null_mut();
                        sizes[slot] = 0;
                    }
                    // If realloc returns null for non-zero size, original is still valid
                } else {
                    // realloc(NULL, size) = malloc(size)
                    let ptr = unsafe { libc::realloc(std::ptr::null_mut(), size) } as *mut u8;
                    slots[slot] = ptr;
                    sizes[slot] = size;
                }
            }
            3 => {
                // calloc
                if !slots[slot].is_null() {
                    unsafe { libc::free(slots[slot] as *mut libc::c_void) };
                }
                let nmemb = (size >> 8).max(1);
                let elem_size = (size & 0xFF).max(1);
                let ptr = unsafe { libc::calloc(nmemb, elem_size) } as *mut u8;
                let total = nmemb * elem_size;
                slots[slot] = ptr;
                sizes[slot] = total;
                // Verify zero-fill
                if !ptr.is_null() && total > 0 {
                    let check_len = std::cmp::min(total, 256);
                    for j in 0..check_len {
                        assert_eq!(
                            unsafe { *ptr.add(j) },
                            0,
                            "calloc memory not zeroed at offset {}",
                            j
                        );
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    // Cleanup
    for slot in &mut slots {
        if !slot.is_null() {
            unsafe { libc::free(*slot as *mut libc::c_void) };
            *slot = std::ptr::null_mut();
        }
    }
});
