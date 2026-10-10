/*-
 * Copyright (c) 2009 Joerg Sonnenberger
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Ported from libarchive/archive_crc32.c.

//! CRC-32 (the zlib/IEEE polynomial), continued from a previous value.
//! Bulk little-endian updates use crc32fast; small updates and other targets
//! retain the local slicing-by-eight implementation.

/// `TABLES[0]` is the usual byte-at-a-time table; `TABLES[k]` is the CRC of
/// a byte followed by `k` zero bytes, which lets eight bytes go at once.
const TABLES: [[u32; 256]; 8] = {
    let mut tables = [[0; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        tables[0][i] = c;
        i += 1;
    }
    let mut i = 0;
    while i < 256 {
        let mut k = 1;
        while k < 8 {
            let prev = tables[k - 1][i];
            tables[k][i] = tables[0][(prev & 0xFF) as usize] ^ (prev >> 8);
            k += 1;
        }
        i += 1;
    }
    tables
};

/// The CRC-32 of `data`, continued from `crc` (0 to start).
pub(crate) fn crc32(crc: u32, data: &[u8]) -> u32 {
    // Keep tiny ZipCrypto updates local. The hardware backend reads native-endian words.
    #[cfg(target_endian = "little")]
    if data.len() >= 64 {
        let mut hasher = crc32fast::Hasher::new_with_initial(crc);
        hasher.update(data);
        return hasher.finalize();
    }
    let at = |k: usize, x: u32| TABLES[k][usize::from(x as u8)];
    let mut c = !crc;
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        let (lo, hi) = chunk.split_at(4);
        let lo = u32::from_le_bytes(lo.try_into().unwrap_or_default()) ^ c;
        let hi = u32::from_le_bytes(hi.try_into().unwrap_or_default());
        c = at(7, lo)
            ^ at(6, lo >> 8)
            ^ at(5, lo >> 16)
            ^ at(4, lo >> 24)
            ^ at(3, hi)
            ^ at(2, hi >> 8)
            ^ at(1, hi >> 16)
            ^ at(0, hi >> 24);
    }
    for &b in chunks.remainder() {
        c = at(0, c ^ u32::from(b)) ^ (c >> 8);
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::crc32;

    /// The bitwise reference of upstream's test_archive_crc32.
    fn bitcrc32(crc: u32, data: &[u8]) -> u32 {
        let mut c = !crc;
        for &b in data {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
        }
        !c
    }

    #[test]
    fn known_values() {
        assert_eq!(crc32(0, b""), 0);
        assert_eq!(crc32(0, b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(0, b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn matches_the_bitwise_reference() {
        let buf: Vec<u8> = (0..4096u32).map(|i| (i * 7 + i / 3) as u8).collect();
        assert_eq!(crc32(0, &buf[..0]), bitcrc32(0, &buf[..0]));
        assert_eq!(crc32(0, &buf[..128]), bitcrc32(0, &buf[..128]));
        let inc = crc32(crc32(0, &buf[..33]), &buf[33..128]);
        assert_eq!(inc, bitcrc32(bitcrc32(0, &buf[..33]), &buf[33..128]));
        assert_eq!(crc32(0, &buf[1..128]), bitcrc32(0, &buf[1..128]));
        assert_eq!(crc32(0, &buf[3..131]), bitcrc32(0, &buf[3..131]));
        assert_eq!(crc32(0, &buf), bitcrc32(0, &buf));
        assert_eq!(crc32(0, &buf), crc32fast::hash(&buf));
    }
    #[test]
    fn hardware_dispatch_matches_bitwise_for_seeds_lengths_and_alignments() {
        let mut state = 0x1234_5678u32;
        let data: Vec<_> = (0..8216)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect();
        for len in (0..=200).chain([255, 256, 1535, 1536, 1537, 4096, 8192, 8199]) {
            for offset in 0..16 {
                let bytes = &data[offset..offset + len];
                for seed in [0, 1, u32::MAX, 0xCBF4_3926, 0x8000_0000] {
                    assert_eq!(
                        crc32(seed, bytes),
                        bitcrc32(seed, bytes),
                        "len={len} offset={offset} seed={seed}"
                    );
                }
            }
        }
    }

    #[test]
    fn continuation_across_dispatch_and_hardware_boundaries() {
        let data: Vec<_> = (0..4096u32).map(|n| (n * 31 + n / 7) as u8).collect();
        for seed in [0, 1, u32::MAX, 0xCBF4_3926] {
            let whole = bitcrc32(seed, &data);
            for split in [
                0, 1, 63, 64, 65, 127, 128, 1535, 1536, 1537, 4032, 4095, 4096,
            ] {
                assert_eq!(crc32(crc32(seed, &data[..split]), &data[split..]), whole);
            }
            assert_eq!(
                data.iter()
                    .fold(seed, |crc, b| crc32(crc, std::slice::from_ref(b))),
                whole
            );
        }
    }
}
