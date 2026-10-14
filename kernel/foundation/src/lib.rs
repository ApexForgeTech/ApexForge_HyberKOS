#![no_std]
//! Platform-independent native mechanisms; no new Object/Handle model.
pub const PAGE: usize = 4096;
pub const FRAMES: usize = 128 * 1024 * 1024 / PAGE;

/// 0 unavailable, 1 free, 2 allocated, 3 explicitly reserved.
/// Explicit reservations cannot be undone by a later available-range import.
pub struct Frames {
    states: [u8; FRAMES],
}
impl Default for Frames {
    fn default() -> Self {
        Self::new()
    }
}
impl Frames {
    pub const fn new() -> Self {
        Self {
            states: [0; FRAMES],
        }
    }
    pub fn available(&mut self, start: u64, length: u64) -> Result<(), &'static str> {
        if length == 0 {
            return Ok(());
        }
        let end = start.checked_add(length).ok_or("memory range overflow")?;
        let first = start
            .checked_add((PAGE - 1) as u64)
            .ok_or("alignment overflow")?
            / PAGE as u64;
        let last = (end / PAGE as u64).min(FRAMES as u64);
        if (first.min(FRAMES as u64)..last).any(|i| self.states[i as usize] == 2) {
            return Err("range contains allocated frame");
        }
        for i in first.min(FRAMES as u64)..last {
            if self.states[i as usize] != 3 {
                self.states[i as usize] = 1;
            }
        }
        Ok(())
    }
    pub fn reserve(&mut self, start: u64, length: u64) -> Result<(), &'static str> {
        if length == 0 {
            return Ok(());
        }
        let end = start.checked_add(length).ok_or("memory range overflow")?;
        let last = end.div_ceil(PAGE as u64).min(FRAMES as u64);
        if ((start / PAGE as u64).min(FRAMES as u64)..last).any(|i| self.states[i as usize] == 2) {
            return Err("range contains allocated frame");
        }
        for i in (start / PAGE as u64).min(FRAMES as u64)..last {
            self.states[i as usize] = 3;
        }
        Ok(())
    }
    pub fn allocate(&mut self) -> Option<usize> {
        let i = self.states.iter().position(|s| *s == 1)?;
        self.states[i] = 2;
        Some(i * PAGE)
    }
    pub fn release(&mut self, address: usize) -> Result<(), &'static str> {
        if !address.is_multiple_of(PAGE)
            || address / PAGE >= FRAMES
            || self.states[address / PAGE] != 2
        {
            return Err("invalid frame release");
        }
        self.states[address / PAGE] = 1;
        Ok(())
    }
}

/// Validates the complete bounded Multiboot2 memory-map structure before use.
pub fn memory_map(bytes: &[u8], mut visit: impl FnMut(u64, u64, u32)) -> Result<(), &'static str> {
    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }
    if bytes.len() < 16
        || bytes.len() > 1024 * 1024
        || u32_at(bytes, 0) as usize != bytes.len()
        || u32_at(bytes, 4) != 0
    {
        return Err("invalid boot info");
    }
    // Two passes ensure callbacks never see partially validated input.
    for pass in 0..2 {
        let mut offset = 8;
        let mut found = false;
        loop {
            if offset + 8 > bytes.len() {
                return Err("missing end tag");
            }
            let kind = u32_at(bytes, offset);
            let size = u32_at(bytes, offset + 4) as usize;
            if size < 8 || size > bytes.len() - offset {
                return Err("invalid tag size");
            }
            if kind == 0 {
                if size != 8 || offset + 8 != bytes.len() || !found {
                    return Err("invalid end tag");
                }
                break;
            }
            if kind == 6 {
                if found || size < 16 {
                    return Err("invalid memory map");
                }
                found = true;
                let stride = u32_at(bytes, offset + 8) as usize;
                if stride < 24
                    || u32_at(bytes, offset + 12) != 0
                    || !(size - 16).is_multiple_of(stride)
                {
                    return Err("invalid memory map entries");
                }
                for entry in bytes[offset + 16..offset + size].chunks_exact(stride) {
                    if u32_at(entry, 20) != 0 {
                        return Err("nonzero reserved memory-map field");
                    }
                    let base = u64::from_le_bytes(entry[0..8].try_into().unwrap());
                    let length = u64::from_le_bytes(entry[8..16].try_into().unwrap());
                    base.checked_add(length).ok_or("memory map overflow")?;
                    if pass == 1 {
                        visit(base, length, u32_at(entry, 16));
                    }
                }
            }
            if kind == 3 {
                return Err("boot modules are not supported by this kernel");
            }
            offset += (size + 7) & !7;
        }
    }
    Ok(())
}

/// Fixed-size reclaimable heap blocks; bounded bring-up policy, not general malloc.
#[derive(Default)]
pub struct Blocks {
    used: u64,
}
impl Blocks {
    pub const fn new() -> Self {
        Self { used: 0 }
    }
    pub fn allocate(&mut self, size: usize, align: usize) -> Option<usize> {
        if size == 0
            || size > PAGE
            || !align.is_power_of_two()
            || align > PAGE
            || self.used == u64::MAX
        {
            return None;
        }
        let slot = self.used.trailing_ones() as usize;
        self.used |= 1 << slot;
        Some(slot)
    }
    pub fn release(&mut self, slot: usize) -> Result<(), &'static str> {
        if slot >= 64 || self.used & (1 << slot) == 0 {
            return Err("invalid heap release");
        }
        self.used &= !(1 << slot);
        Ok(())
    }
}

pub struct RoundRobin {
    current: usize,
    count: usize,
}
impl RoundRobin {
    pub fn new(count: usize) -> Option<Self> {
        (count > 0 && count <= 64).then_some(Self { current: 0, count })
    }
    pub fn advance(&mut self) -> (usize, usize) {
        let old = self.current;
        self.current = (old + 1) % self.count;
        (old, self.current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frames_reservation_reuse_and_overflow() {
        let mut f = Frames::new();
        assert_eq!(f.allocate(), None);
        f.available(0, 3 * PAGE as u64).unwrap();
        f.reserve(0, 1).unwrap();
        assert_eq!(f.allocate(), Some(PAGE));
        assert!(f.release(0).is_err());
        f.release(PAGE).unwrap();
        assert!(f.release(PAGE).is_err());
        assert_eq!(f.allocate(), Some(PAGE));
        assert_eq!(f.allocate(), Some(2 * PAGE));
        assert_eq!(f.allocate(), None);
        assert!(f.available(u64::MAX, 1).is_err());
        assert!(f.reserve(u64::MAX, 1).is_err());
    }
    #[test]
    fn heap_exhaustion_alignment_and_reuse() {
        let mut h = Blocks::new();
        assert_eq!(h.allocate(1, 3), None);
        assert_eq!(h.allocate(PAGE + 1, 1), None);
        for i in 0..64 {
            assert_eq!(h.allocate(PAGE, PAGE), Some(i));
        }
        assert_eq!(h.allocate(1, 1), None);
        h.release(17).unwrap();
        assert_eq!(h.allocate(2, 2), Some(17));
        assert!(h.release(64).is_err());
        h.release(0).unwrap();
        assert!(h.release(0).is_err());
    }
    #[test]
    fn scheduler_is_bounded_and_fair() {
        assert!(RoundRobin::new(0).is_none());
        assert!(RoundRobin::new(65).is_none());
        let mut s = RoundRobin::new(2).unwrap();
        for _ in 0..100 {
            assert_eq!(s.advance(), (0, 1));
            assert_eq!(s.advance(), (1, 0));
        }
    }
    #[test]
    fn ranges_cannot_reclassify_live_frames() {
        let mut frames = Frames::new();
        frames.available(0, (4 * PAGE) as u64).unwrap();
        frames.reserve(0, 1).unwrap();
        assert_eq!(frames.allocate(), Some(PAGE));
        assert!(frames.available(0, (4 * PAGE) as u64).is_err());
        assert!(frames.reserve(0, (4 * PAGE) as u64).is_err());
        frames.reserve((2 * PAGE + 1) as u64, 0).unwrap();
        assert_eq!(frames.allocate(), Some(2 * PAGE));
    }
    #[test]
    fn reservations_win_independent_of_import_order() {
        let mut frames = Frames::new();
        frames.reserve(0, (2 * PAGE) as u64).unwrap();
        frames.available(0, (3 * PAGE) as u64).unwrap();
        assert_eq!(frames.allocate(), Some(2 * PAGE));
        assert_eq!(frames.allocate(), None);
    }
    #[test]
    fn malformed_boot_map_has_no_partial_effects() {
        let mut bytes = [0u8; 56];
        bytes[0..4].copy_from_slice(&56u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&6u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&40u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&24u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&1u32.to_le_bytes());
        bytes[52..56].copy_from_slice(&8u32.to_le_bytes());
        let mut count = 0;
        memory_map(&bytes, |_, _, _| count += 1).unwrap();
        assert_eq!(count, 1);
        for len in 0..bytes.len() {
            assert!(memory_map(&bytes[..len], |_, _, _| panic!("partial callback")).is_err());
        }
        bytes[44] = 1;
        assert!(memory_map(&bytes, |_, _, _| panic!("partial callback")).is_err());
        bytes[44] = 0;
        bytes[52] = 7;
        count = 0;
        assert!(memory_map(&bytes, |_, _, _| count += 1).is_err());
        assert_eq!(count, 0);
    }
}
