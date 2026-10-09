/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/

// Ported from libarchive/archive_blake2sp_ref.c.

//! BLAKE2sp: eight BLAKE2s leaves that hash 64-byte blocks taken in turn, and a
//! root that hashes the leaf digests. Unkeyed only.

use crate::blake2s_ref::{Blake2s, Tree};

const PARALLELISM: usize = 8;
const BLOCK: usize = 64;
const DIGEST: usize = 32;
const STRIPE: usize = PARALLELISM * BLOCK;

pub struct Blake2sp {
    leaves: [Blake2s; PARALLELISM],
    root: Blake2s,
    buf: [u8; STRIPE],
    buflen: usize,
    outlen: usize,
}

impl Blake2sp {
    /// Starts a hash with an `outlen`-byte digest, or returns `None` unless
    /// `outlen` is 1 to 32.
    pub fn new(outlen: usize) -> Option<Self> {
        if !(1..=DIGEST).contains(&outlen) {
            return None;
        }
        let digest_length = u8::try_from(outlen).ok()?;
        let leaf_tree = |i: usize| Tree {
            fanout: PARALLELISM as u8,
            depth: 2,
            node_offset: i as u32,
            node_depth: 0,
            inner_length: DIGEST as u8,
        };
        Some(Self {
            leaves: std::array::from_fn(|i| {
                Blake2s::new(digest_length, leaf_tree(i), i == PARALLELISM - 1)
            }),
            root: Blake2s::new(
                digest_length,
                Tree {
                    fanout: PARALLELISM as u8,
                    depth: 2,
                    node_offset: 0,
                    node_depth: 1,
                    inner_length: DIGEST as u8,
                },
                true,
            ),
            buf: [0; STRIPE],
            buflen: 0,
            outlen,
        })
    }

    pub fn update(&mut self, mut input: &[u8]) {
        let mut left = self.buflen;
        if left != 0 && input.len() >= STRIPE - left {
            let (head, rest) = input.split_at(STRIPE - left);
            self.buf[left..].copy_from_slice(head);
            for (leaf, block) in self.leaves.iter_mut().zip(self.buf.chunks_exact(BLOCK)) {
                leaf.update(block);
            }
            input = rest;
            left = 0;
        }

        let (stripes, tail) = input.split_at(input.len() - input.len() % STRIPE);
        for stripe in stripes.chunks_exact(STRIPE) {
            for (leaf, block) in self.leaves.iter_mut().zip(stripe.chunks_exact(BLOCK)) {
                leaf.update(block);
            }
        }
        self.buf[left..left + tail.len()].copy_from_slice(tail);
        self.buflen = left + tail.len();
    }

    /// Writes the digest to the first `outlen` bytes of `out`, or returns
    /// `None` (writing nothing) if `out` is shorter than that.
    pub fn finalize(self, out: &mut [u8]) -> Option<()> {
        let Self {
            leaves,
            mut root,
            buf,
            buflen,
            outlen,
        } = self;
        let out = out.get_mut(..outlen)?;
        for (i, (mut leaf, block)) in leaves.into_iter().zip(buf.chunks_exact(BLOCK)).enumerate() {
            let used = buflen.saturating_sub(i * BLOCK).min(BLOCK);
            leaf.update(&block[..used]);
            root.update(&leaf.finalize());
        }
        out.copy_from_slice(root.finalize().get(..outlen)?);
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(data: &[u8], outlen: usize, step: usize) -> Vec<u8> {
        let mut s = Blake2sp::new(outlen).unwrap();
        for chunk in data.chunks(step) {
            s.update(chunk);
        }
        let mut out = vec![0; outlen];
        s.finalize(&mut out).unwrap();
        out
    }

    fn kat(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // (input length, digest) for the bytes 0, 1, 2, ... as in upstream's KAT
    // input, and for "abc". Digests from upstream's C code at 8bb3bbd.
    const VECTORS: [(usize, &str); 11] = [
        (
            0,
            "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f",
        ),
        (
            1,
            "a6b9eecc25227ad788c99d3f236debc8da408849e9a5178978727a81457f7239",
        ),
        (
            63,
            "1024c940be7341449b5010522b509f65bbdc1287b455c2bb7f72b2c92fd0d189",
        ),
        (
            64,
            "52603b6cbfad4966cb044cb267568385cf35f21e6c45cf30aed19832cb51e9f5",
        ),
        (
            65,
            "fff24d3cc729d395daf978b0157306cb495797e6c8dca1731d2f6f81b849baae",
        ),
        (
            255,
            "25059f10605e67adfe681350666e15ae976a5a571c13cf5bc8053f430e120a52",
        ),
        (
            511,
            "50285271956932d39b0967202b56006cbb6d738ee29e5a867edf72c8c4386f1b",
        ),
        (
            512,
            "322ce06cc141a0b3d89bcdcfcb385975dbca56e5719a78c34000fcec2e15b55d",
        ),
        (
            513,
            "1336628c7f1541c7815fc0ff1fb5dfb07a85cf5a17a2872a3ce4b322d4a03d0b",
        ),
        (
            1100,
            "86269f9a50f569244f3236215c9eb4c3036d7f7f0044d43481288c27afb4232b",
        ),
        (
            2049,
            "e49a04e1acbb4b17a75a1a77434baae49650b6c8dbf0670a5cedcd29e3bb45df",
        ),
    ];

    #[test]
    fn known_answers() {
        for (len, expected) in VECTORS {
            assert_eq!(
                hex(&digest(&kat(len), 32, len.max(1))),
                expected,
                "len {len}"
            );
        }
        assert_eq!(
            hex(&digest(b"abc", 32, 1)),
            "70f75b58f1fecab821db43c88ad84edde5a52600616cd22517b7bb14d440a7d5"
        );
    }

    #[test]
    fn short_digests_use_their_own_parameter_block() {
        // Upstream's oracle output for outlen 1 and 31 over 600 bytes.
        assert_eq!(hex(&digest(&kat(600), 1, 600)), "aa");
        assert_eq!(
            hex(&digest(&kat(600), 31, 600)),
            "7b5bd4c6e2f5ea222f3d1649d9d36d10786e16ff80cec7bc9cf2363653dc1c"
        );
    }

    #[test]
    fn chunking_does_not_change_the_digest() {
        let data = kat(2049);
        for step in [1, 3, 63, 64, 65, 255, 511, 512, 513, 1000] {
            assert_eq!(
                digest(&data, 32, step),
                digest(&data, 32, data.len()),
                "step {step}"
            );
        }
    }

    #[test]
    fn rejects_bad_output_lengths() {
        assert!(Blake2sp::new(0).is_none());
        assert!(Blake2sp::new(33).is_none());
        let mut short = [0u8; 31];
        assert!(Blake2sp::new(32).unwrap().finalize(&mut short).is_none());
    }
}
