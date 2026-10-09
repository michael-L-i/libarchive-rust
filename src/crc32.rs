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
//! Upstream uses zlib, or a 256-entry table without it; this is the table.

const TABLE: [u32; 256] = {
    let mut table = [0; 256];
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
        table[i] = c;
        i += 1;
    }
    table
};

/// The CRC-32 of `data`, continued from `crc` (0 to start).
pub(crate) fn crc32(crc: u32, data: &[u8]) -> u32 {
    !data.iter().fold(!crc, |c, &b| {
        TABLE
            .get(usize::from((c as u8) ^ b))
            .map_or(0, |t| t ^ (c >> 8))
    })
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
}
