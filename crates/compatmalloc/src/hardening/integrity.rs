/// Compute a metadata integrity checksum for a slot.
///
/// Incorporates the slot address, requested size, and flags into a single
/// u64 checksum using a fast multiplicative hash with the process-wide secret.
/// Protects against metadata corruption (e.g., adjacent slot overflow).
///
/// Uses a single multiply-XOR round (~4 cycles) instead of full splitmix64
/// (~9 cycles). Sufficient for integrity detection with secret-dependent output.
#[inline(always)]
pub fn compute_checksum(slot_addr: usize, requested_size: u32, flags: u8) -> u64 {
    let secret = super::canary::secret();
    let input = (slot_addr as u64)
        ^ ((requested_size as u64) << 32)
        ^ (flags as u64)
        ^ secret;
    // Single-round multiplicative hash: good avalanche, ~4 cycle latency
    let h = input.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^ (h >> 31)
}

/// Verify a metadata integrity checksum.
#[inline(always)]
pub fn verify_checksum(slot_addr: usize, requested_size: u32, flags: u8, stored: u64) -> bool {
    compute_checksum(slot_addr, requested_size, flags) == stored
}
