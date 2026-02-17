/// Result of an integrity scan across all arenas.
#[derive(Debug, Default)]
pub struct IntegrityResult {
    pub total_slabs: usize,
    pub total_slots_checked: usize,
    pub errors_found: usize,
    pub bitmap_inconsistencies: usize,
    pub checksum_failures: usize,
    pub canary_failures: usize,
}

impl IntegrityResult {
    pub fn is_ok(&self) -> bool {
        self.errors_found == 0
    }

    pub fn merge(&mut self, other: &IntegrityResult) {
        self.total_slabs += other.total_slabs;
        self.total_slots_checked += other.total_slots_checked;
        self.errors_found += other.errors_found;
        self.bitmap_inconsistencies += other.bitmap_inconsistencies;
        self.checksum_failures += other.checksum_failures;
        self.canary_failures += other.canary_failures;
    }
}
