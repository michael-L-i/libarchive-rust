/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2011 Andres Mejia
 * Copyright (c) 2011 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_digest.c.

//! Message digests for the xar reader and the mtree, xar and zip writers:
//! MD5, RIPEMD-160, SHA-1, SHA-256, SHA-384 and SHA-512. Upstream picks one
//! platform library per build and fills a table of init/update/final
//! functions; here the RustCrypto crates are the only backend and the table
//! is `Digest`.

#![allow(dead_code)] // RIPEMD-160 and SHA-384, for the mtree writer (phase 5)

use md5::Md5;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::digest::DynDigest;
use sha2::{Sha256, Sha384, Sha512};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Md5,
    Rmd160,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// A running digest. Every algorithm is always available, so unlike
/// upstream's `archive_*_init` creating one cannot fail.
pub struct Digest(Box<dyn DynDigest>);

impl Digest {
    pub fn new(algorithm: Algorithm) -> Digest {
        Digest(match algorithm {
            Algorithm::Md5 => Box::new(Md5::default()),
            Algorithm::Rmd160 => Box::new(Ripemd160::default()),
            Algorithm::Sha1 => Box::new(Sha1::default()),
            Algorithm::Sha256 => Box::new(Sha256::default()),
            Algorithm::Sha384 => Box::new(Sha384::default()),
            Algorithm::Sha512 => Box::new(Sha512::default()),
        })
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of everything passed to `update`: 16, 20, 20, 32, 48 or 64
    /// bytes.
    pub fn finalize(self) -> Vec<u8> {
        self.0.finalize().into_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn digest(algorithm: Algorithm, data: &[u8]) -> String {
        let mut d = Digest::new(algorithm);
        d.update(data);
        hex(&d.finalize())
    }

    #[test]
    fn md5_rfc1321() {
        let vectors: [(&[u8], &str); 5] = [
            (b"", "d41d8cd98f00b204e9800998ecf8427e"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (data, md) in vectors {
            assert_eq!(digest(Algorithm::Md5, data), md);
        }
    }

    #[test]
    fn rmd160_paper() {
        let vectors: [(&[u8], &str); 4] = [
            (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
            (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            (
                b"message digest",
                "5d0689ef49d2fae572b881b123a85ffa21595f36",
            ),
        ];
        for (data, md) in vectors {
            assert_eq!(digest(Algorithm::Rmd160, data), md);
        }
    }

    #[test]
    fn sha_fips_180() {
        let two_blocks = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            digest(Algorithm::Sha1, b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            digest(Algorithm::Sha1, two_blocks),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            digest(Algorithm::Sha256, b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            digest(Algorithm::Sha256, two_blocks),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            digest(Algorithm::Sha384, b"abc"),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            digest(Algorithm::Sha512, b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn updates_in_pieces_match_one_update() {
        let mut d = Digest::new(Algorithm::Sha1);
        for _ in 0..1_000_000 / 100 {
            d.update(&[b'a'; 100]);
        }
        assert_eq!(
            hex(&d.finalize()),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn digest_lengths() {
        for (algorithm, len) in [
            (Algorithm::Md5, 16),
            (Algorithm::Rmd160, 20),
            (Algorithm::Sha1, 20),
            (Algorithm::Sha256, 32),
            (Algorithm::Sha384, 48),
            (Algorithm::Sha512, 64),
        ] {
            assert_eq!(Digest::new(algorithm).finalize().len(), len);
        }
    }
}
