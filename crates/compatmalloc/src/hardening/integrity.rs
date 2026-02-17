/// Compute a metadata integrity checksum for a slot.
///
/// Uses a DIFFERENT constant than the canary derivation, ensuring that
/// leaking canary bytes (which are visible in the slot gap) does NOT
/// reveal the integrity checksum. This breaks the Security C2 cascading
/// failure mode identified in the security audit.
///
/// Single-round multiplicative hash with domain-separated secret. ~3 cycles.
/// The secret prevents forging without brute force; the multiply provides
/// good bit mixing for accidental corruption detection.
#[inline(always)]
pub fn compute_checksum(slot_addr: usize, requested_size: u32, flags: u8) -> u64 {
    let secret = super::canary::secret();
    // Domain separation: XOR secret with a fixed constant so checksum derivation
    // uses a different effective secret than canary derivation
    let checksum_secret = secret ^ 0x9E3779B97F4A7C15; // golden ratio constant
    let input =
        (slot_addr as u64) ^ ((requested_size as u64) << 32) ^ (flags as u64) ^ checksum_secret;
    // Single-round hash: multiply + xor-shift for good bit distribution (~3 cycles)
    let h = input.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^ (h >> 31)
}

/// Verify a metadata integrity checksum.
#[inline(always)]
pub fn verify_checksum(slot_addr: usize, requested_size: u32, flags: u8, stored: u64) -> bool {
    compute_checksum(slot_addr, requested_size, flags) == stored
}
