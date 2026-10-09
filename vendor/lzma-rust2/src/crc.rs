const CRC32_POLY: u32 = 0xEDB88320;

const fn make_crc32_table() -> [[u32; 256]; 8] {
    let mut table = [[0; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32_POLY;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[0][i] = crc;
        i += 1;
    }
    let mut slice = 1;
    while slice < 8 {
        let mut i = 0;
        while i < 256 {
            let crc = table[slice - 1][i];
            table[slice][i] = (crc >> 8) ^ table[0][(crc & 0xFF) as usize];
            i += 1;
        }
        slice += 1;
    }
    table
}

const CRC32_TABLE: [[u32; 256]; 8] = make_crc32_table();

/// CRC_32_ISO_HDLC
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(crate) struct Crc32 {
    state: u32,
}

impl Crc32 {
    pub(crate) fn new() -> Self {
        Self { state: 0xFFFFFFFF }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        // Each table accounts for the remaining bytes in an eight-byte group.
        let mut chunks = data.chunks_exact(8);
        for chunk in &mut chunks {
            let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ self.state;
            self.state = CRC32_TABLE[7][(word & 0xFF) as usize]
                ^ CRC32_TABLE[6][((word >> 8) & 0xFF) as usize]
                ^ CRC32_TABLE[5][((word >> 16) & 0xFF) as usize]
                ^ CRC32_TABLE[4][((word >> 24) & 0xFF) as usize]
                ^ CRC32_TABLE[3][chunk[4] as usize]
                ^ CRC32_TABLE[2][chunk[5] as usize]
                ^ CRC32_TABLE[1][chunk[6] as usize]
                ^ CRC32_TABLE[0][chunk[7] as usize];
        }
        for &byte in chunks.remainder() {
            let index = ((self.state ^ (byte as u32)) & 0xFF) as usize;
            self.state = (self.state >> 8) ^ CRC32_TABLE[0][index];
        }
    }

    pub(crate) fn finalize(self) -> u32 {
        self.state ^ 0xFFFFFFFF
    }

    pub(crate) fn checksum(data: &[u8]) -> u32 {
        let mut crc = Self::new();
        crc.update(data);
        crc.finalize()
    }
}

const CRC64_POLY: u64 = 0xC96C5795D7870F42;

const fn make_crc64_table() -> [[u64; 256]; 8] {
    let mut table = [[0; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u64;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC64_POLY;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[0][i] = crc;
        i += 1;
    }
    let mut slice = 1;
    while slice < 8 {
        let mut i = 0;
        while i < 256 {
            let crc = table[slice - 1][i];
            table[slice][i] = (crc >> 8) ^ table[0][(crc & 0xFF) as usize];
            i += 1;
        }
        slice += 1;
    }
    table
}

const CRC64_TABLE: [[u64; 256]; 8] = make_crc64_table();

/// CRC_64_XZ
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(crate) struct Crc64 {
    state: u64,
}

impl Crc64 {
    pub(crate) fn new() -> Self {
        Self {
            state: 0xFFFFFFFFFFFFFFFF,
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        // Each table accounts for the remaining bytes in an eight-byte group.
        let mut chunks = data.chunks_exact(8);
        for chunk in &mut chunks {
            let word = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]) ^ self.state;
            self.state = CRC64_TABLE[7][(word & 0xFF) as usize]
                ^ CRC64_TABLE[6][((word >> 8) & 0xFF) as usize]
                ^ CRC64_TABLE[5][((word >> 16) & 0xFF) as usize]
                ^ CRC64_TABLE[4][((word >> 24) & 0xFF) as usize]
                ^ CRC64_TABLE[3][((word >> 32) & 0xFF) as usize]
                ^ CRC64_TABLE[2][((word >> 40) & 0xFF) as usize]
                ^ CRC64_TABLE[1][((word >> 48) & 0xFF) as usize]
                ^ CRC64_TABLE[0][((word >> 56) & 0xFF) as usize];
        }
        for &byte in chunks.remainder() {
            let index = ((self.state ^ (byte as u64)) & 0xFF) as usize;
            self.state = (self.state >> 8) ^ CRC64_TABLE[0][index];
        }
    }

    pub(crate) fn finalize(self) -> u64 {
        self.state ^ 0xFFFFFFFFFFFFFFFF
    }

    pub(crate) fn checksum(data: &[u8]) -> u64 {
        let mut crc = Self::new();
        crc.update(data);
        crc.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_DATA: &[u8] = &[1, 2, 3, 7, 16, 31, 64, 255];

    #[test]
    fn slicing_matches_bitwise_crc_across_alignments_and_splits() {
        let mut bytes = [0u8; 521];
        let mut seed = 0x12345678u32;
        for byte in &mut bytes {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *byte = seed as u8;
        }
        for offset in 0..8 {
            for len in 0..=513 {
                let data = &bytes[offset..offset + len];
                let mut expected32 = !0u32;
                let mut expected64 = !0u64;
                for &byte in data {
                    expected32 ^= byte as u32;
                    expected64 ^= byte as u64;
                    for _ in 0..8 {
                        expected32 =
                            (expected32 >> 1) ^ (CRC32_POLY & 0u32.wrapping_sub(expected32 & 1));
                        expected64 =
                            (expected64 >> 1) ^ (CRC64_POLY & 0u64.wrapping_sub(expected64 & 1));
                    }
                }
                assert_eq!(Crc32::checksum(data), !expected32);
                assert_eq!(Crc64::checksum(data), !expected64);
                for split in 0..=len.min(17) {
                    let mut crc32 = Crc32::new();
                    let mut crc64 = Crc64::new();
                    for part in [&data[..split], &data[split..]] {
                        crc32.update(part);
                        crc64.update(part);
                    }
                    assert_eq!(crc32.finalize(), !expected32);
                    assert_eq!(crc64.finalize(), !expected64);
                }
            }
        }
    }

    #[test]
    fn crc32_empty() {
        assert_eq!(Crc32::checksum(&[]), 0);
    }

    #[test]
    fn crc64_empty() {
        assert_eq!(Crc64::checksum(&[]), 0);
    }

    #[test]
    fn crc32_simple_data() {
        assert_eq!(Crc32::checksum(SIMPLE_DATA), 2428203834);
    }

    #[test]
    fn crc64_simple_data() {
        assert_eq!(Crc64::checksum(SIMPLE_DATA), 11721292222009571391);
    }
}
