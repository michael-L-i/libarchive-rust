/*-
 * Copyright (c) 2014 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_cryptor.c.

//! PBKDF2-HMAC-SHA1 and AES in WinZip's counter mode, for encrypted zip
//! entries. Upstream's per-platform backends (CommonCrypto, CNG, mbed TLS,
//! Nettle, OpenSSL) and its "unsupported" stub are replaced by the `aes`,
//! `pbkdf2` and `hmac` crates, so nothing here is ever unsupported.

use aes::cipher::{Block, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use sha1::Sha1;

const AES_BLOCK_SIZE: usize = 16;

/// PKCS5 PBKDF2 with HMAC-SHA1, filling `derived_key`.
pub fn pbkdf2_sha1(password: &[u8], salt: &[u8], rounds: u32, derived_key: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, rounds, derived_key);
}

enum Cipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

/// AES-CTR with the little-endian counter WinZip uses, for both directions.
/// The counter is the low 8 bytes of a block that starts at zero and is
/// incremented before each block is encrypted, so the first block of key
/// stream is for counter 1.
pub struct AesCtr {
    cipher: Cipher,
    nonce: [u8; AES_BLOCK_SIZE],
    encr_buf: [u8; AES_BLOCK_SIZE],
    encr_pos: usize,
}

impl AesCtr {
    /// `None` unless `key` is 16, 24 or 32 bytes.
    pub fn new(key: &[u8]) -> Option<AesCtr> {
        let cipher = match key.len() {
            16 => Cipher::Aes128(Aes128::new_from_slice(key).ok()?),
            24 => Cipher::Aes192(Aes192::new_from_slice(key).ok()?),
            32 => Cipher::Aes256(Aes256::new_from_slice(key).ok()?),
            _ => return None,
        };
        Some(AesCtr {
            cipher,
            nonce: [0; AES_BLOCK_SIZE],
            encr_buf: [0; AES_BLOCK_SIZE],
            encr_pos: AES_BLOCK_SIZE,
        })
    }

    /// Encrypts the counter for the next block of key stream.
    fn next_block(&mut self) {
        for b in &mut self.nonce[..8] {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        let mut block = Block::<Aes128>::from(self.nonce);
        match &self.cipher {
            Cipher::Aes128(c) => c.encrypt_block(&mut block),
            Cipher::Aes192(c) => c.encrypt_block(&mut block),
            Cipher::Aes256(c) => c.encrypt_block(&mut block),
        }
        self.encr_buf = block.into();
    }

    /// XORs `input` with the key stream into `output` and returns how many
    /// bytes that was: the shorter of the two lengths. A partial block's key
    /// stream carries over to the next call.
    pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> usize {
        let max = input.len().min(output.len());
        for (i, o) in input.iter().zip(output.iter_mut()) {
            if self.encr_pos == AES_BLOCK_SIZE {
                self.next_block();
                self.encr_pos = 0;
            }
            *o = i ^ self.encr_buf[self.encr_pos];
            self.encr_pos += 1;
        }
        max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or_default())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn pbkdf2(password: &[u8], salt: &[u8], rounds: u32, len: usize) -> String {
        let mut dk = vec![0; len];
        pbkdf2_sha1(password, salt, rounds, &mut dk);
        hex(&dk)
    }

    #[test]
    fn pbkdf2_rfc6070() {
        assert_eq!(
            pbkdf2(b"password", b"salt", 1, 20),
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        );
        assert_eq!(
            pbkdf2(b"password", b"salt", 2, 20),
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
        );
        assert_eq!(
            pbkdf2(b"password", b"salt", 4096, 20),
            "4b007901b765489abead49d926f721d065a429c1"
        );
        assert_eq!(
            pbkdf2(
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                25
            ),
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
        );
        assert_eq!(
            pbkdf2(b"pass\0word", b"sa\0lt", 4096, 16),
            "56fa6aa75548099dcc37d7f03425e0c3"
        );
    }

    /// SP 800-38A F.5: the first block of CTR key stream is the encrypted
    /// initial counter block. WinZip's counter is incremented before use and
    /// little-endian, so the state is set one step before NIST's counter.
    #[test]
    fn first_block_is_the_encrypted_counter() {
        let plain = unhex("6bc1bee22e409f96e93d7e117393172a");
        let counter = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        for (key, cipher) in [
            (
                "2b7e151628aed2a6abf7158809cf4f3c",
                "874d6191b620e3261bef6864990db6ce",
            ),
            (
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "1abc932417521ca24f2b0459fe7e6e0b",
            ),
            (
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "601ec313775789a5b7a7f504bbf3d228",
            ),
        ] {
            let mut ctr = AesCtr::new(&unhex(key)).unwrap();
            ctr.nonce.copy_from_slice(&counter);
            ctr.nonce[0] -= 1;
            let mut out = [0; 16];
            assert_eq!(ctr.update(&plain, &mut out), 16);
            assert_eq!(hex(&out), cipher);
        }
    }

    #[test]
    fn counter_is_little_endian_and_starts_at_one() {
        let key = [7; 16];
        let mut ctr = AesCtr::new(&key).unwrap();
        let mut stream = vec![0; 16 * 300];
        ctr.update(&vec![0; 16 * 300], &mut stream);
        let aes = Aes128::new_from_slice(&key).unwrap();
        for n in [1u64, 2, 255, 256, 257, 300] {
            let mut block = Block::<Aes128>::default();
            block[..8].copy_from_slice(&n.to_le_bytes());
            aes.encrypt_block(&mut block);
            let at = 16 * (n as usize - 1);
            assert_eq!(&stream[at..at + 16], &block[..], "block {n}");
        }
    }

    #[test]
    fn counter_carries_only_within_eight_bytes() {
        let mut ctr = AesCtr::new(&[1; 32]).unwrap();
        ctr.nonce = [0xff; 16];
        ctr.next_block();
        assert_eq!(
            ctr.nonce,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255
            ]
        );
    }

    /// Output of upstream's OpenSSL/CommonCrypto backends for a key and 34
    /// bytes of input, in one update and in arbitrary pieces.
    #[test]
    fn matches_upstream() {
        let key = unhex("431838ec373f4cd2c969609dfd4f26dc");
        let input = unhex("f063c36fd7113975bde887000d2c75bcdae4d1703eba825fa8cb3a2f4b5616f5f8fd");
        let want = "bc0c96c96f03b3df572fc1f3f5f98d649e68b42d03797e87ffebd6693f842c3ab9d7";
        let mut one = vec![0; input.len()];
        AesCtr::new(&key).unwrap().update(&input, &mut one);
        assert_eq!(hex(&one), want);

        let mut ctr = AesCtr::new(&key).unwrap();
        let mut pieces = vec![0; input.len()];
        let mut at = 0;
        for len in [1, 0, 15, 2, 16] {
            let end = at + len;
            assert_eq!(ctr.update(&input[at..end], &mut pieces[at..end]), len);
            at = end;
        }
        ctr.update(&input[at..], &mut pieces[at..]);
        assert_eq!(pieces, one);
    }

    #[test]
    fn update_stops_at_the_shorter_buffer() {
        let mut ctr = AesCtr::new(&[0; 16]).unwrap();
        let mut out = [0; 5];
        assert_eq!(ctr.update(&[0; 9], &mut out), 5);
        let mut rest = [0; 4];
        assert_eq!(ctr.update(&[0; 4], &mut rest), 4);
        let mut whole = [0; 9];
        AesCtr::new(&[0; 16]).unwrap().update(&[0; 9], &mut whole);
        assert_eq!([&out[..], &rest[..]].concat(), whole);
    }

    #[test]
    fn only_aes_key_lengths_are_accepted() {
        for len in [0, 8, 15, 17, 31, 33] {
            assert!(AesCtr::new(&vec![0; len]).is_none(), "{len}");
        }
        for len in [16, 24, 32] {
            assert!(AesCtr::new(&vec![0; len]).is_some(), "{len}");
        }
    }
}
