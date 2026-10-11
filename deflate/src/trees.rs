/* trees.c -- output deflated data using Huffman coding
 * Copyright (C) 1995-2021 Jean-loup Gailly
 * detect_data_type() function provided freely by Cosmin Truta, 2006
 * For conditions of distribution and use, see copyright notice in zlib.h
 */

// Altered from the original: translated to Rust from zlib 1.2.12's trees.c.
// detect_data_type() is left out; it only sets strm->data_type.

//  ALGORITHM
//
//      The "deflation" process uses several Huffman trees. The more
//      common source values are represented by shorter bit sequences.
//
//      Each code tree is stored in a compressed form which is itself
// a Huffman encoding of the lengths of all the code strings (in
// ascending order by source values).  The actual code strings are
// reconstructed from the lengths in the inflate process, as described
// in the deflate specification.

use crate::State;

/// Number of length codes, not counting the special END_BLOCK code.
const LENGTH_CODES: usize = 29;
/// Number of literal bytes 0..255.
const LITERALS: usize = 256;
/// Number of Literal or Length codes, including the END_BLOCK code.
const L_CODES: usize = LITERALS + 1 + LENGTH_CODES;
/// Number of distance codes.
const D_CODES: usize = 30;
/// Number of codes used to transfer the bit lengths.
const BL_CODES: usize = 19;
/// Maximum heap size.
pub(crate) const HEAP_SIZE: usize = 2 * L_CODES + 1;
/// All codes must not exceed MAX_BITS bits.
const MAX_BITS: usize = 15;
/// Bit length codes must not exceed MAX_BL_BITS bits.
const MAX_BL_BITS: usize = 7;
/// End of block literal code.
const END_BLOCK: usize = 256;
/// Repeat previous bit length 3-6 times (2 bits of repeat count).
const REP_3_6: usize = 16;
/// Repeat a zero length 3-10 times (3 bits of repeat count).
const REPZ_3_10: usize = 17;
/// Repeat a zero length 11-138 times (7 bits of repeat count).
const REPZ_11_138: usize = 18;

const STORED_BLOCK: u64 = 0;
const STATIC_TREES: u64 = 1;
const DYN_TREES: u64 = 2;

/// Extra bits for each length code.
const EXTRA_LBITS: [u8; LENGTH_CODES] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// Extra bits for each distance code.
const EXTRA_DBITS: [u8; D_CODES] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// Extra bits for each bit length code.
const EXTRA_BLBITS: [u8; BL_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];
/// The lengths of the bit length codes are sent in order of decreasing
/// probability, to avoid transmitting the lengths for unused bit length codes.
const BL_ORDER: [u8; BL_CODES] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// A tree node (zlib's ct_data). Each field is a union in zlib.
#[derive(Clone, Copy, Default)]
pub(crate) struct Ct {
    /// Frequency count while the tree is built, then the bit string.
    pub(crate) fc: u16,
    /// Father node in the Huffman tree while it is built, then the bit length.
    pub(crate) dl: u16,
}

/// The tables trees.c builds once in tr_static_init().
struct Tables {
    /// The static literal tree. Since the bit lengths are imposed, there is no
    /// need for the L_CODES extra codes used during heap construction. However
    /// the codes 286 and 287 are needed to build a canonical tree.
    ltree: [Ct; L_CODES + 2],
    /// The static distance tree. (Actually a trivial tree since all codes use
    /// 5 bits.)
    dtree: [Ct; D_CODES],
    /// Distance codes. The first 256 values correspond to the distances 3 ..
    /// 258, the last 256 values correspond to the top 8 bits of the 15 bit
    /// distances.
    dist_code: [u8; 512],
    /// Length code for each normalized match length (0 == MIN_MATCH).
    length_code: [u8; 256],
    /// First normalized length for each code (0 = MIN_MATCH).
    base_length: [u8; LENGTH_CODES],
    /// First normalized distance for each code (0 = distance of 1).
    base_dist: [u16; D_CODES],
}

static TABLES: Tables = tr_static_init();

const fn tr_static_init() -> Tables {
    let mut t = Tables {
        ltree: [Ct { fc: 0, dl: 0 }; L_CODES + 2],
        dtree: [Ct { fc: 0, dl: 0 }; D_CODES],
        dist_code: [0; 512],
        length_code: [0; 256],
        base_length: [0; LENGTH_CODES],
        base_dist: [0; D_CODES],
    };
    // Initialize the mapping length (0..255) -> length code (0..28)
    let mut length = 0;
    let mut code = 0;
    while code < LENGTH_CODES - 1 {
        t.base_length[code] = length as u8;
        let mut n = 0;
        while n < 1 << EXTRA_LBITS[code] {
            t.length_code[length] = code as u8;
            length += 1;
            n += 1;
        }
        code += 1;
    }
    // Note that the length 255 (match length 258) can be represented in two
    // different ways: code 284 + 5 bits or code 285, so we overwrite
    // length_code[255] to use the best encoding:
    t.length_code[length - 1] = code as u8;

    // Initialize the mapping dist (0..32K) -> dist code (0..29)
    let mut dist = 0;
    code = 0;
    while code < 16 {
        t.base_dist[code] = dist as u16;
        let mut n = 0;
        while n < 1 << EXTRA_DBITS[code] {
            t.dist_code[dist] = code as u8;
            dist += 1;
            n += 1;
        }
        code += 1;
    }
    dist >>= 7; // from now on, all distances are divided by 128
    while code < D_CODES {
        t.base_dist[code] = (dist << 7) as u16;
        let mut n = 0;
        while n < 1 << (EXTRA_DBITS[code] - 7) {
            t.dist_code[256 + dist] = code as u8;
            dist += 1;
            n += 1;
        }
        code += 1;
    }

    // Construct the codes of the static literal tree
    let mut bl_count = [0u16; MAX_BITS + 1];
    let mut n = 0;
    while n <= 287 {
        let len = match n {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
        t.ltree[n].dl = len;
        bl_count[len as usize] += 1;
        n += 1;
    }
    // Codes 286 and 287 do not exist, but we must include them in the tree
    // construction to get a canonical Huffman tree (longest code all ones)
    gen_codes(&mut t.ltree, L_CODES + 1, &bl_count);

    // The static distance tree is trivial:
    n = 0;
    while n < D_CODES {
        t.dtree[n] = Ct {
            fc: bi_reverse(n as u16, 5),
            dl: 5,
        };
        n += 1;
    }
    t
}

/// A static tree and the extra bits of its codes (zlib's static_tree_desc).
pub(crate) struct TreeDesc {
    static_tree: Option<&'static [Ct]>,
    extra_bits: &'static [u8],
    extra_base: usize,
    elems: usize,
    max_length: usize,
}

static STATIC_L_DESC: TreeDesc = TreeDesc {
    static_tree: Some(&TABLES.ltree),
    extra_bits: &EXTRA_LBITS,
    extra_base: LITERALS + 1,
    elems: L_CODES,
    max_length: MAX_BITS,
};

static STATIC_D_DESC: TreeDesc = TreeDesc {
    static_tree: Some(&TABLES.dtree),
    extra_bits: &EXTRA_DBITS,
    extra_base: 0,
    elems: D_CODES,
    max_length: MAX_BITS,
};

static STATIC_BL_DESC: TreeDesc = TreeDesc {
    static_tree: None,
    extra_bits: &EXTRA_BLBITS,
    extra_base: 0,
    elems: BL_CODES,
    max_length: MAX_BL_BITS,
};

/// Mapping from a distance to a distance code. dist is the distance - 1.
fn d_code(dist: usize) -> usize {
    usize::from(if dist < 256 {
        TABLES.dist_code[dist]
    } else {
        TABLES.dist_code[256 + (dist >> 7)]
    })
}

/// Reverse the first len bits of a code.
const fn bi_reverse(code: u16, len: u32) -> u16 {
    code.reverse_bits() >> (16 - len)
}

/// Generate the codes for a given tree and bit counts (which need not be
/// optimal).
/// IN assertion: the array bl_count contains the bit length statistics for
/// the given tree and the field len is set for all tree elements.
/// OUT assertion: the field code is set for all tree elements of non
///     zero code length.
const fn gen_codes(tree: &mut [Ct], max_code: usize, bl_count: &[u16; MAX_BITS + 1]) {
    let mut next_code = [0u16; MAX_BITS + 1];
    let mut code = 0u32;
    // The distribution counts are first used to generate the code values
    // without bit reversal.
    let mut bits = 1;
    while bits <= MAX_BITS {
        code = (code + bl_count[bits - 1] as u32) << 1;
        next_code[bits] = code as u16;
        bits += 1;
    }
    let mut n = 0;
    while n <= max_code {
        let len = tree[n].dl as usize;
        if len != 0 {
            // Now reverse the bits
            tree[n].fc = bi_reverse(next_code[len], len as u32);
            next_code[len] += 1;
        }
        n += 1;
    }
}

/// The heap used to build the Huffman trees, and the bit lengths of the
/// current block.
pub(crate) struct Heap {
    /// The sons of heap[n] are heap[2*n] and heap[2*n+1]. heap[0] is not used.
    /// The same heap array is used to build all trees.
    heap: [usize; HEAP_SIZE],
    /// Number of elements in the heap.
    len: usize,
    /// Element of largest frequency.
    max: usize,
    /// Depth of each subtree used as tie breaker for trees of equal frequency.
    depth: [u8; HEAP_SIZE],
    /// Number of codes at each bit length for an optimal tree.
    bl_count: [u16; MAX_BITS + 1],
    /// Bit length of current block with optimal trees.
    opt_len: i64,
    /// Bit length of current block with static trees.
    static_len: i64,
}

impl Default for Heap {
    fn default() -> Self {
        Self {
            heap: [0; HEAP_SIZE],
            len: 0,
            max: 0,
            depth: [0; HEAP_SIZE],
            bl_count: [0; MAX_BITS + 1],
            opt_len: 0,
            static_len: 0,
        }
    }
}

/// Compares to subtrees, using the tree depth as tie breaker when the subtrees
/// have equal frequency. This minimizes the worst case length.
fn smaller(tree: &[Ct], n: usize, m: usize, depth: &[u8; HEAP_SIZE]) -> bool {
    tree[n].fc < tree[m].fc || (tree[n].fc == tree[m].fc && depth[n] <= depth[m])
}

impl Heap {
    /// Restore the heap property by moving down the tree starting at node k,
    /// exchanging a node with the smallest of its two sons if necessary,
    /// stopping when the heap property is re-established (each father smaller
    /// than its two sons).
    fn pqdownheap(&mut self, tree: &[Ct], mut k: usize) {
        let v = self.heap[k];
        let mut j = k << 1; // left son of k
        while j <= self.len {
            // Set j to the smallest of the two sons:
            if j < self.len && smaller(tree, self.heap[j + 1], self.heap[j], &self.depth) {
                j += 1;
            }
            // Exit if v is smaller than both sons
            if smaller(tree, v, self.heap[j], &self.depth) {
                break;
            }
            // Exchange v with the smallest son
            self.heap[k] = self.heap[j];
            k = j;
            // And continue down the tree, setting j to the left son of k
            j <<= 1;
        }
        self.heap[k] = v;
    }

    /// Compute the optimal bit lengths for a tree and update the total bit
    /// length for the current block.
    /// IN assertion: the fields freq and dad are set, heap[heap_max] and above
    ///    are the tree nodes sorted by increasing frequency.
    /// OUT assertions: the field len is set to the optimal bit length, the
    ///     array bl_count contains the frequencies for each bit length. The
    ///     length opt_len is updated; static_len is also updated if stree is
    ///     not null.
    fn gen_bitlen(&mut self, tree: &mut [Ct], max_code: usize, desc: &TreeDesc) {
        let max_length = desc.max_length;
        let mut overflow = 0i32; // number of elements with bit length too large
        self.bl_count = [0; MAX_BITS + 1];

        // In a first pass, compute the optimal bit lengths (which may overflow
        // in the case of the bit length tree).
        tree[self.heap[self.max]].dl = 0; // root of the heap

        let mut h = self.max + 1;
        while h < HEAP_SIZE {
            let n = self.heap[h];
            let mut bits = usize::from(tree[usize::from(tree[n].dl)].dl) + 1;
            if bits > max_length {
                bits = max_length;
                overflow += 1;
            }
            // We overwrite tree[n].Dad which is no longer needed
            tree[n].dl = bits as u16;
            h += 1;
            if n > max_code {
                continue; // not a leaf node
            }
            self.bl_count[bits] += 1;
            let xbits = match n.checked_sub(desc.extra_base) {
                Some(i) => usize::from(desc.extra_bits[i]),
                None => 0,
            };
            let f = i64::from(tree[n].fc);
            self.opt_len += f * (bits + xbits) as i64;
            if let Some(stree) = desc.static_tree {
                self.static_len += f * (usize::from(stree[n].dl) + xbits) as i64;
            }
        }
        if overflow == 0 {
            return;
        }

        // This happens for example on obj2 and pic of the Calgary corpus
        // Find the first bit length which could increase:
        loop {
            let mut bits = max_length - 1;
            while self.bl_count[bits] == 0 {
                bits -= 1;
            }
            self.bl_count[bits] -= 1; // move one leaf down the tree
            self.bl_count[bits + 1] += 2; // move one overflow item as its brother
            self.bl_count[max_length] -= 1;
            // The brother of the overflow item also moves one step up, but
            // this does not affect bl_count[max_length]
            overflow -= 2;
            if overflow <= 0 {
                break;
            }
        }

        // Now recompute all bit lengths, scanning in increasing frequency.
        // h is still equal to HEAP_SIZE. (It is simpler to reconstruct all
        // lengths instead of fixing only the wrong ones. This idea is taken
        // from 'ar' written by Haruhiko Okumura.)
        for bits in (1..=max_length).rev() {
            let mut n = self.bl_count[bits];
            while n != 0 {
                h -= 1;
                let m = self.heap[h];
                if m > max_code {
                    continue;
                }
                if usize::from(tree[m].dl) != bits {
                    self.opt_len += (bits as i64 - i64::from(tree[m].dl)) * i64::from(tree[m].fc);
                    tree[m].dl = bits as u16;
                }
                n -= 1;
            }
        }
    }

    /// Construct one Huffman tree and assigns the code bit strings and
    /// lengths. Update the total bit length for the current block, and return
    /// the largest code with non zero frequency.
    /// IN assertion: the field freq is set for all tree elements.
    /// OUT assertions: the fields len and code are set to the optimal bit
    ///     length and corresponding code. The length opt_len is updated;
    ///     static_len is also updated if stree is not null.
    fn build_tree(&mut self, tree: &mut [Ct], desc: &TreeDesc) -> usize {
        let elems = desc.elems;
        let mut max_code: isize = -1; // largest code with non zero frequency

        // Construct the initial heap, with least frequent element in
        // heap[SMALLEST]. The sons of heap[n] are heap[2*n] and heap[2*n+1].
        // heap[0] is not used.
        self.len = 0;
        self.max = HEAP_SIZE;
        for (n, node) in tree[..elems].iter_mut().enumerate() {
            if node.fc != 0 {
                self.len += 1;
                self.heap[self.len] = n;
                max_code = n as isize;
                self.depth[n] = 0;
            } else {
                node.dl = 0;
            }
        }

        // The pkzip format requires that at least one distance code exists,
        // and that at least one bit should be sent even if there is only one
        // possible code. So to avoid special checks later on we force at least
        // two codes of non zero frequency.
        while self.len < 2 {
            let node = if max_code < 2 {
                max_code += 1;
                max_code as usize
            } else {
                0
            };
            self.len += 1;
            self.heap[self.len] = node;
            tree[node].fc = 1;
            self.depth[node] = 0;
            self.opt_len -= 1;
            if let Some(stree) = desc.static_tree {
                self.static_len -= i64::from(stree[node].dl);
            }
            // node is 0 or 1 so it does not have extra bits
        }
        let max_code = max_code as usize;

        // The elements heap[heap_len/2+1 .. heap_len] are leaves of the tree,
        // establish sub-heaps of increasing lengths:
        for n in (1..=self.len / 2).rev() {
            self.pqdownheap(tree, n);
        }

        // Construct the Huffman tree by repeatedly combining the least two
        // frequent nodes.
        let mut node = elems; // next internal node of the tree
        loop {
            // n = node of least frequency
            let n = self.heap[1];
            self.heap[1] = self.heap[self.len];
            self.len -= 1;
            self.pqdownheap(tree, 1);
            let m = self.heap[1]; // m = node of next least frequency

            // keep the nodes sorted by frequency
            self.max -= 1;
            self.heap[self.max] = n;
            self.max -= 1;
            self.heap[self.max] = m;

            // Create a new node father of n and m
            tree[node].fc = tree[n].fc + tree[m].fc;
            self.depth[node] = self.depth[n].max(self.depth[m]) + 1;
            tree[n].dl = node as u16;
            tree[m].dl = node as u16;
            // and insert the new node in the heap
            self.heap[1] = node;
            node += 1;
            self.pqdownheap(tree, 1);
            if self.len < 2 {
                break;
            }
        }
        self.max -= 1;
        self.heap[self.max] = self.heap[1];

        // At this point, the fields freq and dad are set. We can now generate
        // the bit lengths.
        self.gen_bitlen(tree, max_code, desc);

        // The field len is now set, we can generate the bit codes
        gen_codes(tree, max_code, &self.bl_count);
        max_code
    }
}

/// Scan a literal or distance tree to determine the frequencies of the codes
/// in the bit length tree.
fn scan_tree(tree: &mut [Ct], max_code: usize, bl_tree: &mut [Ct]) {
    let mut prevlen = None; // last emitted length
    let mut nextlen = tree[0].dl; // length of next code
    let mut count = 0; // repeat count of the current code
    let (mut max_count, mut min_count) = if nextlen == 0 { (138, 3) } else { (7, 4) };
    tree[max_code + 1].dl = 0xffff; // guard

    for n in 0..=max_code {
        let curlen = nextlen;
        nextlen = tree[n + 1].dl;
        count += 1;
        if count < max_count && curlen == nextlen {
            continue;
        } else if count < min_count {
            bl_tree[usize::from(curlen)].fc += count;
        } else if curlen != 0 {
            if Some(curlen) != prevlen {
                bl_tree[usize::from(curlen)].fc += 1;
            }
            bl_tree[REP_3_6].fc += 1;
        } else if count <= 10 {
            bl_tree[REPZ_3_10].fc += 1;
        } else {
            bl_tree[REPZ_11_138].fc += 1;
        }
        count = 0;
        prevlen = Some(curlen);
        (max_count, min_count) = if nextlen == 0 {
            (138, 3)
        } else if curlen == nextlen {
            (6, 3)
        } else {
            (7, 4)
        };
    }
}

/// The pending output: compressed bytes not yet copied to the stream, and the
/// bits not yet forming a byte.
#[derive(Default)]
pub(crate) struct Pending {
    /// Output still pending, from its start.
    pub(crate) buf: Vec<u8>,
    /// Next pending byte to output to the stream.
    pub(crate) out: usize,
    /// Output buffer. Bits are inserted starting at the bottom (least
    /// significant bits).
    bi_buf: u64,
    /// Number of valid bits in bi_buf. All bits above the last valid bit are
    /// always zero.
    pub(crate) bi_valid: u32,
}

impl Pending {
    pub(crate) fn put_byte(&mut self, c: u8) {
        self.buf.push(c);
    }

    /// Output a short LSB first on the stream.
    fn put_short(&mut self, w: u16) {
        self.buf.extend_from_slice(&w.to_le_bytes());
    }

    /// Send a value on a given number of bits.
    /// IN assertion: length <= 16 and value fits in length bits.
    fn send_bits(&mut self, value: u64, length: u32) {
        self.bi_buf |= value << self.bi_valid;
        self.bi_valid += length;
        if self.bi_valid >= 48 {
            self.buf.extend_from_slice(&self.bi_buf.to_le_bytes()[..6]);
            self.bi_buf >>= 48;
            self.bi_valid -= 48;
        }
    }

    /// Send a code of the given tree.
    fn send_code(&mut self, c: usize, tree: &[Ct]) {
        self.send_bits(u64::from(tree[c].fc), u32::from(tree[c].dl));
    }

    /// Flush the bit buffer, keeping at most 7 bits in it.
    pub(crate) fn bi_flush(&mut self) {
        while self.bi_valid >= 8 {
            self.put_byte(self.bi_buf as u8);
            self.bi_buf >>= 8;
            self.bi_valid -= 8;
        }
    }

    /// Flush the bit buffer and align the output on a byte boundary.
    fn bi_windup(&mut self) {
        self.bi_flush();
        if self.bi_valid > 0 {
            self.put_byte(self.bi_buf as u8);
        }
        self.bi_buf = 0;
        self.bi_valid = 0;
    }

    /// Send a literal or distance tree in compressed form, using the codes in
    /// bl_tree.
    fn send_tree(&mut self, tree: &[Ct], max_code: usize, bl_tree: &[Ct]) {
        let mut prevlen = None; // last emitted length
        let mut nextlen = tree[0].dl; // length of next code
        let mut count = 0; // repeat count of the current code
        let (mut max_count, mut min_count) = if nextlen == 0 { (138, 3) } else { (7, 4) };

        // tree[max_code+1].Len = -1;  guard already set
        for n in 0..=max_code {
            let curlen = nextlen;
            nextlen = tree[n + 1].dl;
            count += 1;
            if count < max_count && curlen == nextlen {
                continue;
            } else if count < min_count {
                for _ in 0..count {
                    self.send_code(usize::from(curlen), bl_tree);
                }
            } else if curlen != 0 {
                if Some(curlen) != prevlen {
                    self.send_code(usize::from(curlen), bl_tree);
                    count -= 1;
                }
                self.send_code(REP_3_6, bl_tree);
                self.send_bits(count - 3, 2);
            } else if count <= 10 {
                self.send_code(REPZ_3_10, bl_tree);
                self.send_bits(count - 3, 3);
            } else {
                self.send_code(REPZ_11_138, bl_tree);
                self.send_bits(count - 11, 7);
            }
            count = 0;
            prevlen = Some(curlen);
            (max_count, min_count) = if nextlen == 0 {
                (138, 3)
            } else if curlen == nextlen {
                (6, 3)
            } else {
                (7, 4)
            };
        }
    }

    /// Send the block data compressed using the given Huffman trees.
    fn compress_block(&mut self, sym_buf: &[u8], ltree: &[Ct], dtree: &[Ct]) {
        for sym in sym_buf.chunks_exact(3) {
            let dist = usize::from(u16::from_le_bytes([sym[0], sym[1]]));
            let lc = usize::from(sym[2]);
            if dist == 0 {
                self.send_code(lc, ltree); // send a literal byte
            } else {
                // Here, lc is the match length - MIN_MATCH
                let code = usize::from(TABLES.length_code[lc]);
                self.send_code(code + LITERALS + 1, ltree); // send the length code
                let extra = EXTRA_LBITS[code];
                if extra != 0 {
                    let lc = lc - usize::from(TABLES.base_length[code]);
                    self.send_bits(lc as u64, u32::from(extra)); // send the extra length bits
                }
                let dist = dist - 1; // dist is now the match distance - 1
                let code = d_code(dist);
                self.send_code(code, dtree); // send the distance code
                let extra = EXTRA_DBITS[code];
                if extra != 0 {
                    let dist = dist - usize::from(TABLES.base_dist[code]);
                    self.send_bits(dist as u64, u32::from(extra)); // send the extra distance bits
                }
            }
        }
        self.send_code(END_BLOCK, ltree);
    }
}

/// The trees of the current block (zlib keeps them in deflate_state).
pub(crate) struct Trees {
    /// Literal and length tree.
    ltree: [Ct; HEAP_SIZE],
    /// Distance tree.
    dtree: [Ct; 2 * D_CODES + 1],
    /// Huffman tree for bit lengths.
    bl_tree: [Ct; 2 * BL_CODES + 1],
    heap: Heap,
}

impl Default for Trees {
    fn default() -> Self {
        Self {
            ltree: [Ct::default(); HEAP_SIZE],
            dtree: [Ct::default(); 2 * D_CODES + 1],
            bl_tree: [Ct::default(); 2 * BL_CODES + 1],
            heap: Heap::default(),
        }
    }
}

impl State {
    /// Initialize the tree data structures for a new zlib stream.
    pub(crate) fn tr_init(&mut self) {
        self.pending.bi_buf = 0;
        self.pending.bi_valid = 0;
        // Initialize the first block of the first file:
        self.init_block();
    }

    /// Initialize a new block.
    fn init_block(&mut self) {
        let t = &mut self.trees;
        t.ltree[..L_CODES].iter_mut().for_each(|c| c.fc = 0);
        t.dtree[..D_CODES].iter_mut().for_each(|c| c.fc = 0);
        t.bl_tree[..BL_CODES].iter_mut().for_each(|c| c.fc = 0);
        t.ltree[END_BLOCK].fc = 1;
        t.heap.opt_len = 0;
        t.heap.static_len = 0;
        self.sym_next = 0;
    }

    /// Send a stored block.
    pub(crate) fn tr_stored_block(&mut self, buf: usize, stored_len: usize, last: bool) {
        let p = &mut self.pending;
        p.send_bits((STORED_BLOCK << 1) + u64::from(last), 3); // send block type
        p.bi_windup(); // align on byte boundary
        p.put_short(stored_len as u16);
        p.put_short(!stored_len as u16);
        p.buf.extend_from_slice(&self.window[buf..buf + stored_len]);
    }

    /// Send one empty static block to give enough lookahead for inflate. This
    /// takes 10 bits, of which 7 may remain in the bit buffer.
    pub(crate) fn tr_align(&mut self) {
        self.pending.send_bits(STATIC_TREES << 1, 3);
        self.pending.send_code(END_BLOCK, &TABLES.ltree);
        self.pending.bi_flush();
    }

    /// Construct the Huffman tree for the bit lengths and return the index in
    /// bl_order of the last bit length code to send.
    fn build_bl_tree(&mut self, lmax: usize, dmax: usize) -> usize {
        let t = &mut self.trees;
        // Determine the bit length frequencies for literal and distance trees
        scan_tree(&mut t.ltree, lmax, &mut t.bl_tree);
        scan_tree(&mut t.dtree, dmax, &mut t.bl_tree);

        // Build the bit length tree:
        t.heap.build_tree(&mut t.bl_tree, &STATIC_BL_DESC);
        // opt_len now includes the length of the tree representations, except
        // the lengths of the bit lengths codes and the 5+5+4 bits for the
        // counts.

        // Determine the number of bit length codes to send. The pkzip format
        // requires that at least 4 bit length codes be sent. (appnote.txt says
        // 3 but the actual value used is 4.)
        let mut max_blindex = BL_CODES - 1;
        while max_blindex >= 3 && t.bl_tree[usize::from(BL_ORDER[max_blindex])].dl == 0 {
            max_blindex -= 1;
        }
        // Update opt_len to include the bit length tree and counts
        t.heap.opt_len += 3 * (max_blindex as i64 + 1) + 5 + 5 + 4;
        max_blindex
    }

    /// Send the header for a block using dynamic Huffman trees: the counts,
    /// the lengths of the bit length codes, the literal tree and the distance
    /// tree.
    /// IN assertion: lcodes >= 257, dcodes >= 1, blcodes >= 4.
    fn send_all_trees(&mut self, lcodes: usize, dcodes: usize, blcodes: usize) {
        let (p, t) = (&mut self.pending, &self.trees);
        p.send_bits(lcodes as u64 - 257, 5); // not +255 as stated in appnote.txt
        p.send_bits(dcodes as u64 - 1, 5);
        p.send_bits(blcodes as u64 - 4, 4); // not -3 as stated in appnote.txt
        for &rank in &BL_ORDER[..blcodes] {
            p.send_bits(u64::from(t.bl_tree[usize::from(rank)].dl), 3);
        }
        p.send_tree(&t.ltree, lcodes - 1, &t.bl_tree); // literal tree
        p.send_tree(&t.dtree, dcodes - 1, &t.bl_tree); // distance tree
    }

    /// Determine the best encoding for the current block: dynamic trees,
    /// static trees or store, and write out the encoded block. buf is the
    /// block's start in the window, or None if it is too old.
    pub(crate) fn tr_flush_block(&mut self, buf: Option<usize>, stored_len: usize, last: bool) {
        let t = &mut self.trees;
        // Construct the literal and distance trees
        let lmax = t.heap.build_tree(&mut t.ltree, &STATIC_L_DESC);
        let dmax = t.heap.build_tree(&mut t.dtree, &STATIC_D_DESC);
        // At this point, opt_len and static_len are the total bit lengths of
        // the compressed block data, excluding the tree representations.

        // Build the bit length tree for the above two trees, and get the index
        // in bl_order of the last bit length code to send.
        let max_blindex = self.build_bl_tree(lmax, dmax);

        // Determine the best encoding. Compute the block lengths in bytes.
        let heap = &self.trees.heap;
        let mut opt_lenb = ((heap.opt_len + 3 + 7) >> 3) as usize;
        let static_lenb = ((heap.static_len + 3 + 7) >> 3) as usize;
        if static_lenb <= opt_lenb {
            opt_lenb = static_lenb;
        }

        match buf {
            // 4: two words for the lengths
            Some(buf) if stored_len + 4 <= opt_lenb => {
                // The test buf != NULL is only necessary if LIT_BUFSIZE >
                // WSIZE. Otherwise we can't have processed more than WSIZE
                // input bytes since the last block flush, because compression
                // would have been successful. If LIT_BUFSIZE <= WSIZE, it is
                // never too late to transform a block into a stored block.
                self.tr_stored_block(buf, stored_len, last);
            }
            _ if static_lenb == opt_lenb => {
                self.pending
                    .send_bits((STATIC_TREES << 1) + u64::from(last), 3);
                let syms = &self.sym_buf[..self.sym_next];
                self.pending
                    .compress_block(syms, &TABLES.ltree, &TABLES.dtree);
            }
            _ => {
                self.pending
                    .send_bits((DYN_TREES << 1) + u64::from(last), 3);
                self.send_all_trees(lmax + 1, dmax + 1, max_blindex + 1);
                let syms = &self.sym_buf[..self.sym_next];
                self.pending
                    .compress_block(syms, &self.trees.ltree, &self.trees.dtree);
            }
        }
        self.init_block();
        if last {
            self.pending.bi_windup();
        }
    }

    /// Save an unmatched byte and tally its frequency. Return true if the
    /// current block must be flushed.
    pub(crate) fn tr_tally_lit(&mut self, c: u8) -> bool {
        self.sym_buf[self.sym_next..self.sym_next + 3].copy_from_slice(&[0, 0, c]);
        self.sym_next += 3;
        self.trees.ltree[usize::from(c)].fc += 1;
        self.sym_next == self.sym_buf.len()
    }

    /// Save a match (distance, length - MIN_MATCH) and tally its frequency.
    /// Return true if the current block must be flushed.
    pub(crate) fn tr_tally_dist(&mut self, dist: usize, len: usize) -> bool {
        let [d0, d1] = (dist as u16).to_le_bytes();
        self.sym_buf[self.sym_next..self.sym_next + 3].copy_from_slice(&[d0, d1, len as u8]);
        self.sym_next += 3;
        let t = &mut self.trees;
        t.ltree[usize::from(TABLES.length_code[len]) + LITERALS + 1].fc += 1;
        t.dtree[d_code(dist - 1)].fc += 1;
        self.sym_next == self.sym_buf.len()
    }
}
