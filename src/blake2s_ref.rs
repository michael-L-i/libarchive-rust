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

// Ported from libarchive/archive_blake2s_ref.c.

//! BLAKE2s compression, as BLAKE2sp (`blake2sp_ref`) uses it. Only the
//! parameter blocks BLAKE2sp needs are built: unkeyed, unsalted and not
//! personalized.

const BLOCK: usize = 64;
const DIGEST: usize = 32;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

// The word indices of the eight G calls in each round, as upstream's ROUND.
const G_INDEX: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

/// The parameter block fields that describe a node's place in the tree.
/// The key, salt and personalization are always zero.
#[derive(Clone, Copy)]
pub(crate) struct Tree {
    pub fanout: u8,
    pub depth: u8,
    pub node_offset: u32,
    pub node_depth: u8,
    pub inner_length: u8,
}

#[derive(Clone)]
pub(crate) struct Blake2s {
    h: [u32; 8],
    t: [u32; 2],
    f: [u32; 2],
    buf: [u8; BLOCK],
    buflen: usize,
    last_node: bool,
}

impl Blake2s {
    /// Starts a hash whose parameter block is `digest_length` and `tree`.
    /// `last_node` marks the last node of a tree, which sets the second
    /// finalization flag.
    pub(crate) fn new(digest_length: u8, tree: Tree, last_node: bool) -> Self {
        let params = [
            u32::from(digest_length)
                | (u32::from(tree.fanout) << 16)
                | (u32::from(tree.depth) << 24),
            0,
            tree.node_offset,
            (u32::from(tree.node_depth) << 16) | (u32::from(tree.inner_length) << 24),
            0,
            0,
            0,
            0,
        ];
        let mut h = IV;
        for (h, p) in h.iter_mut().zip(params) {
            *h ^= p;
        }
        Self {
            h,
            t: [0; 2],
            f: [0; 2],
            buf: [0; BLOCK],
            buflen: 0,
            last_node,
        }
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        let left = self.buflen;
        let fill = BLOCK - left;
        if input.len() > fill {
            let (head, rest) = input.split_at(fill);
            self.buf[left..].copy_from_slice(head);
            self.buflen = 0;
            self.increment(BLOCK as u32);
            let block = self.buf;
            self.compress(&block);
            input = rest;
            // The last full block stays buffered until finalization.
            while input.len() > BLOCK {
                let Some((block, rest)) = input.split_first_chunk::<BLOCK>() else {
                    break;
                };
                self.increment(BLOCK as u32);
                self.compress(block);
                input = rest;
            }
        }
        self.buf[self.buflen..self.buflen + input.len()].copy_from_slice(input);
        self.buflen += input.len();
    }

    pub(crate) fn finalize(mut self) -> [u8; DIGEST] {
        self.increment(self.buflen as u32);
        self.f[0] = u32::MAX;
        if self.last_node {
            self.f[1] = u32::MAX;
        }
        self.buf[self.buflen..].fill(0);
        let block = self.buf;
        self.compress(&block);

        let mut out = [0; DIGEST];
        for (chunk, h) in out.chunks_exact_mut(4).zip(self.h) {
            chunk.copy_from_slice(&h.to_le_bytes());
        }
        out
    }

    fn increment(&mut self, inc: u32) {
        self.t[0] = self.t[0].wrapping_add(inc);
        self.t[1] = self.t[1].wrapping_add(u32::from(self.t[0] < inc));
    }

    fn compress(&mut self, block: &[u8; BLOCK]) {
        let mut m = [0u32; 16];
        for (w, c) in m.iter_mut().zip(block.chunks_exact(4)) {
            *w = u32::from_le_bytes(c.try_into().unwrap_or_default());
        }

        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t[0];
        v[13] ^= self.t[1];
        v[14] ^= self.f[0];
        v[15] ^= self.f[1];

        for s in &SIGMA {
            for (j, &idx) in G_INDEX.iter().enumerate() {
                g(&mut v, idx, m[s[2 * j]], m[s[2 * j + 1]]);
            }
        }

        let (lo, hi) = v.split_at(8);
        for ((h, a), b) in self.h.iter_mut().zip(lo).zip(hi) {
            *h ^= a ^ b;
        }
    }
}

fn g(v: &mut [u32; 16], [a, b, c, d]: [usize; 4], x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEQUENTIAL: Tree = Tree {
        fanout: 1,
        depth: 1,
        node_offset: 0,
        node_depth: 0,
        inner_length: 0,
    };

    fn digest(data: &[u8], step: usize) -> [u8; DIGEST] {
        let mut s = Blake2s::new(DIGEST as u8, SEQUENTIAL, false);
        for chunk in data.chunks(step) {
            s.update(chunk);
        }
        s.finalize()
    }

    #[test]
    fn known_answers() {
        // Published BLAKE2s digests, also produced by upstream's C code.
        let empty = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9";
        let abc = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";
        assert_eq!(hex(&digest(b"", 1)), empty);
        assert_eq!(hex(&digest(b"abc", 3)), abc);
    }

    #[test]
    fn chunking_does_not_change_the_digest() {
        let data: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let whole = digest(&data, data.len());
        for step in [1, 2, 13, 63, 64, 65, 128, 299] {
            assert_eq!(digest(&data, step), whole, "step {step}");
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
