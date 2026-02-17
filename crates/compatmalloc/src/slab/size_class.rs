use crate::util::{LARGE_THRESHOLD, MIN_ALIGN};

/// Size classes for the slab allocator.
/// We use 4-per-doubling size classes: for each power-of-two range [2^k, 2^(k+1)),
/// we have sizes at 1/4, 2/4, 3/4, and 4/4 of the range.
///
/// Classes: 16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256,
///          320, 384, 448, 512, 640, 768, 896, 1024, 1280, 1536, 1792, 2048,
///          2560, 3072, 3584, 4096, 5120, 6144, 7168, 8192,
///          10240, 12288, 14336, 16384
pub const NUM_SIZE_CLASSES: usize = 36;

/// The size class table, sorted ascending.
pub static SIZE_CLASSES: [usize; NUM_SIZE_CLASSES] = {
    let mut table = [0usize; NUM_SIZE_CLASSES];
    let mut idx = 0;

    // First group: 16, 32, 48, 64
    let mut step = 16;
    let mut base = 0;
    let mut i = 0;
    while i < 4 {
        base += step;
        table[idx] = base;
        idx += 1;
        i += 1;
    }

    // Subsequent groups: 4 per doubling
    base = 64;
    while idx < NUM_SIZE_CLASSES {
        step = base / 4;
        let mut j = 0;
        while j < 4 && idx < NUM_SIZE_CLASSES {
            base += step;
            table[idx] = base;
            idx += 1;
            j += 1;
        }
    }

    table
};

/// Number of entries in the O(1) lookup table.
/// Covers sizes 1..=LARGE_THRESHOLD in 16-byte granularity: LARGE_THRESHOLD / 16 + 1 = 1025.
const LOOKUP_TABLE_SIZE: usize = LARGE_THRESHOLD / MIN_ALIGN + 1;

/// O(1) lookup table mapping (size + 15) / 16 - 1 -> size class index.
/// Built at compile time. Each entry is the size class index for that 16-byte bucket.
static LOOKUP_TABLE: [u8; LOOKUP_TABLE_SIZE] = {
    let mut table = [0u8; LOOKUP_TABLE_SIZE];
    let mut i = 0;
    while i < LOOKUP_TABLE_SIZE {
        let size = (i + 1) * MIN_ALIGN; // size for this bucket
        // Find smallest class >= size (binary search at compile time)
        let mut lo = 0usize;
        let mut hi = NUM_SIZE_CLASSES;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if SIZE_CLASSES[mid] < size {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        table[i] = lo as u8;
        i += 1;
    }
    table
};

/// Look up the size class index for a given allocation size.
/// Returns `None` if the size exceeds the largest size class.
/// Uses O(1) table lookup instead of binary search.
#[inline]
pub fn size_class_index(size: usize) -> Option<usize> {
    // Minimum allocation is MIN_ALIGN bytes
    let size = if size < MIN_ALIGN { MIN_ALIGN } else { size };

    if size > LARGE_THRESHOLD {
        return None;
    }

    // O(1) lookup: (size + 15) / 16 - 1 maps to the correct bucket
    let bucket = (size + MIN_ALIGN - 1) / MIN_ALIGN - 1;
    Some(LOOKUP_TABLE[bucket] as usize)
}

/// Get the slot size for a given size class index.
#[inline(always)]
pub fn slot_size(class_index: usize) -> usize {
    SIZE_CLASSES[class_index]
}

/// Magic multipliers for division-free slot index computation.
/// For divisor d, magic = ceil(2^64 / d). Then n / d == ((n as u128 * magic as u128) >> 64).
/// This replaces a ~25-cycle hardware `div` with a ~4-cycle `mul` + shift.
pub static SLOT_MAGIC: [u64; NUM_SIZE_CLASSES] = {
    let mut table = [0u64; NUM_SIZE_CLASSES];
    let mut i = 0;
    while i < NUM_SIZE_CLASSES {
        let d = SIZE_CLASSES[i] as u128;
        let two_64 = 1u128 << 64;
        table[i] = ((two_64 + d - 1) / d) as u64;
        i += 1;
    }
    table
};

/// Compute offset / slot_size without hardware division using magic multiplier.
#[inline(always)]
pub fn fast_div_slot(offset: usize, class_index: usize) -> usize {
    let magic = SLOT_MAGIC[class_index];
    ((offset as u128 * magic as u128) >> 64) as usize
}

/// Precomputed slots-per-slab table. Eliminates a ~35-cycle hardware division
/// from the hot free path (slot_for_ptr calls slots_per_slab on every free).
static SLOTS_PER_SLAB: [usize; NUM_SIZE_CLASSES] = {
    let mut table = [0usize; NUM_SIZE_CLASSES];
    let target = 65536usize; // 64 KiB
    let mut i = 0;
    while i < NUM_SIZE_CLASSES {
        let sz = SIZE_CLASSES[i];
        let count = target / sz;
        table[i] = if count < 16 { 16 } else { count };
        i += 1;
    }
    table
};

/// Number of slots per slab for a given size class.
/// Uses precomputed table for O(1) lookup (no division).
#[inline(always)]
pub fn slots_per_slab(class_index: usize) -> usize {
    SLOTS_PER_SLAB[class_index]
}

/// Total memory needed for a slab of a given class (just the slot data, no metadata).
pub fn slab_data_size(class_index: usize) -> usize {
    slots_per_slab(class_index) * slot_size(class_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_classes_are_sorted() {
        for i in 1..NUM_SIZE_CLASSES {
            assert!(
                SIZE_CLASSES[i] > SIZE_CLASSES[i - 1],
                "class {} ({}) <= class {} ({})",
                i,
                SIZE_CLASSES[i],
                i - 1,
                SIZE_CLASSES[i - 1]
            );
        }
    }

    #[test]
    fn first_class_is_min_align() {
        assert_eq!(SIZE_CLASSES[0], MIN_ALIGN);
    }

    #[test]
    fn last_class_is_large_threshold() {
        assert_eq!(SIZE_CLASSES[NUM_SIZE_CLASSES - 1], LARGE_THRESHOLD);
    }

    #[test]
    fn all_classes_aligned() {
        for &sz in &SIZE_CLASSES {
            assert_eq!(sz % MIN_ALIGN, 0, "class {} not aligned to {}", sz, MIN_ALIGN);
        }
    }

    #[test]
    fn magic_division_correct() {
        for (ci, &sz) in SIZE_CLASSES.iter().enumerate() {
            let num_slots = slots_per_slab(ci);
            for slot in 0..num_slots {
                let offset = slot * sz;
                let computed = fast_div_slot(offset, ci);
                assert_eq!(computed, slot, "fast_div_slot({}, class={}) = {} expected {}", offset, ci, computed, slot);
            }
        }
    }

    #[test]
    fn lookup_boundary_sizes() {
        // Size 0 -> class 0 (16 bytes)
        assert_eq!(size_class_index(0), Some(0));
        // Size 1 -> class 0
        assert_eq!(size_class_index(1), Some(0));
        // Size 16 -> class 0
        assert_eq!(size_class_index(16), Some(0));
        // Size 17 -> class 1 (32)
        assert_eq!(size_class_index(17), Some(1));
        // Exact boundary
        assert_eq!(size_class_index(16384), Some(NUM_SIZE_CLASSES - 1));
        // Over threshold
        assert_eq!(size_class_index(16385), None);
    }
}
