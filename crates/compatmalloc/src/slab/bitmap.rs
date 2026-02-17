/// A bitmap for tracking free slots in a slab.
/// Each bit represents one slot: 1 = free, 0 = allocated.
pub struct SlabBitmap {
    /// Bitmap words. We use u64 for efficient bit scanning.
    words: *mut u64,
    /// Number of u64 words.
    num_words: usize,
    /// Total number of slots.
    num_slots: usize,
    /// Number of currently free slots.
    free_count: usize,
}

impl SlabBitmap {
    /// Create a new bitmap with all slots marked as free.
    ///
    /// # Safety
    /// `storage` must point to `num_words(num_slots)` u64s of valid, writable memory.
    pub unsafe fn init(storage: *mut u64, num_slots: usize) -> Self {
        let num_words = Self::num_words_for(num_slots);

        // Set all bits to 1 (free)
        for i in 0..num_words {
            storage.add(i).write(u64::MAX);
        }

        // Clear excess bits in the last word
        let excess = num_words * 64 - num_slots;
        if excess > 0 {
            let last = storage.add(num_words - 1);
            let mask = u64::MAX >> excess;
            last.write(mask);
        }

        SlabBitmap {
            words: storage,
            num_words,
            num_slots,
            free_count: num_slots,
        }
    }

    /// Number of u64 words needed for `num_slots` slots.
    pub const fn num_words_for(num_slots: usize) -> usize {
        num_slots.div_ceil(64)
    }

    /// Number of bytes needed for bitmap storage.
    pub const fn storage_bytes(num_slots: usize) -> usize {
        Self::num_words_for(num_slots) * 8
    }

    /// Number of free slots.
    #[inline]
    pub fn free_count(&self) -> usize {
        self.free_count
    }

    /// Total number of slots.
    #[inline]
    pub fn num_slots(&self) -> usize {
        self.num_slots
    }

    /// Allocate the first free slot. Returns the slot index, or None if full.
    pub fn alloc_first_free(&mut self) -> Option<usize> {
        for i in 0..self.num_words {
            let word = unsafe { self.words.add(i).read() };
            if word != 0 {
                let bit = word.trailing_zeros() as usize;
                let slot = i * 64 + bit;
                if slot < self.num_slots {
                    unsafe {
                        self.words.add(i).write(word & !(1u64 << bit));
                    }
                    self.free_count -= 1;
                    return Some(slot);
                }
            }
        }
        None
    }

    /// Allocate a random free slot using the given random value.
    /// Uses fast range reduction and trailing_zeros instead of iterative nth_set_bit.
    #[cfg(feature = "slot-randomization")]
    #[inline(always)]
    pub fn alloc_random(&mut self, random: u64) -> Option<usize> {
        if self.free_count == 0 {
            return None;
        }

        // Fast range reduction: (random * num_slots) >> 64. No division!
        let start = ((random as u128 * self.num_slots as u128) >> 64) as usize;
        let start_word = start / 64; // shift, not div
        let start_bit = start & 63; // mask, not mod

        // Check starting word from start_bit onward
        let first_word = unsafe { self.words.add(start_word).read() };
        let masked = first_word & (u64::MAX << start_bit);
        if masked != 0 {
            let bit = masked.trailing_zeros() as usize;
            let slot = start_word * 64 + bit;
            if slot < self.num_slots {
                unsafe {
                    self.words
                        .add(start_word)
                        .write(first_word & !(1u64 << bit));
                }
                self.free_count -= 1;
                return Some(slot);
            }
        }

        // Scan forward through remaining words (no modulo, use conditional wrap)
        let mut i = start_word + 1;
        if i >= self.num_words {
            i = 0;
        }

        for _ in 1..self.num_words {
            let word = unsafe { self.words.add(i).read() };
            if word != 0 {
                let bit = word.trailing_zeros() as usize;
                let slot = i * 64 + bit;
                if slot < self.num_slots {
                    unsafe {
                        self.words.add(i).write(word & !(1u64 << bit));
                    }
                    self.free_count -= 1;
                    return Some(slot);
                }
            }
            i += 1;
            if i >= self.num_words {
                i = 0;
            }
        }

        // Check bits before start_bit in the starting word
        if start_bit > 0 {
            let pre = first_word & ((1u64 << start_bit) - 1);
            if pre != 0 {
                let bit = pre.trailing_zeros() as usize;
                let slot = start_word * 64 + bit;
                if slot < self.num_slots {
                    unsafe {
                        self.words
                            .add(start_word)
                            .write(first_word & !(1u64 << bit));
                    }
                    self.free_count -= 1;
                    return Some(slot);
                }
            }
        }

        None
    }

    /// Free a slot (mark it as available).
    ///
    /// # Safety
    /// `slot` must be a valid slot index that was previously allocated.
    pub unsafe fn free_slot(&mut self, slot: usize) {
        debug_assert!(slot < self.num_slots);
        let word_idx = slot / 64;
        let bit_idx = slot % 64;
        let word = self.words.add(word_idx).read();
        debug_assert!(
            word & (1u64 << bit_idx) == 0,
            "double free of slot {}",
            slot
        );
        self.words.add(word_idx).write(word | (1u64 << bit_idx));
        self.free_count += 1;
    }

    /// Check if a slot is currently allocated (not free).
    #[inline]
    pub fn is_allocated(&self, slot: usize) -> bool {
        debug_assert!(slot < self.num_slots);
        let word_idx = slot / 64;
        let bit_idx = slot % 64;
        let word = unsafe { self.words.add(word_idx).read() };
        word & (1u64 << bit_idx) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{alloc, dealloc, Layout};

    fn make_bitmap(num_slots: usize) -> (SlabBitmap, *mut u64) {
        let num_words = SlabBitmap::num_words_for(num_slots);
        let layout = Layout::array::<u64>(num_words).unwrap();
        let storage = unsafe { alloc(layout) as *mut u64 };
        let bm = unsafe { SlabBitmap::init(storage, num_slots) };
        (bm, storage)
    }

    fn free_bitmap(storage: *mut u64, num_slots: usize) {
        let num_words = SlabBitmap::num_words_for(num_slots);
        let layout = Layout::array::<u64>(num_words).unwrap();
        unsafe { dealloc(storage as *mut u8, layout) };
    }

    #[test]
    fn alloc_and_free() {
        let (mut bm, storage) = make_bitmap(128);
        assert_eq!(bm.free_count(), 128);

        let s0 = bm.alloc_first_free().unwrap();
        assert_eq!(bm.free_count(), 127);
        assert!(bm.is_allocated(s0));

        unsafe { bm.free_slot(s0) };
        assert_eq!(bm.free_count(), 128);
        assert!(!bm.is_allocated(s0));

        free_bitmap(storage, 128);
    }

    #[test]
    fn exhaust_slots() {
        let n = 65; // Not a multiple of 64
        let (mut bm, storage) = make_bitmap(n);

        for _ in 0..n {
            assert!(bm.alloc_first_free().is_some());
        }
        assert_eq!(bm.free_count(), 0);
        assert!(bm.alloc_first_free().is_none());

        free_bitmap(storage, n);
    }
}
