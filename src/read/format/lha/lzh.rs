/*-
 * Copyright (c) 2008-2014 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_read_support_format_lha.c.

//! The LZHUF decoder behind `-lh5-`, `-lh6-` and `-lh7-`: literals and
//! matches against a sliding window, Huffman coded in blocks. Corrupt data
//! fails the decoder for good, as upstream's `ds->error` does; every table
//! and window index is checked, where upstream trusts its tables.

/// Maximum match length.
const MAXMATCH: i32 = 256;
/// Minimum match length.
const MINMATCH: i32 = 3;
/// Literal table size: 256 literal codes, then the match lengths.
const LT_BITLEN_SIZE: usize = 255 + 1 + MAXMATCH as usize - MINMATCH as usize + 1;
/// Position table size. Note: this is used for both the position table and
/// the pre literal table.
const PT_BITLEN_SIZE: usize = 3 + 16;
/// Bits of the direct access Huffman table.
const HTBL_BITS: i32 = 10;
/// Upstream expands every window to 128 KiB for decompressing performance,
/// whatever its original size is.
const W_SIZE: i32 = 1 << 17;
const W_MASK: i32 = W_SIZE - 1;

const ST_RD_BLOCK: u8 = 0;
const ST_RD_PT_1: u8 = 1;
const ST_RD_PT_2: u8 = 2;
const ST_RD_PT_3: u8 = 3;
const ST_RD_PT_4: u8 = 4;
const ST_RD_LITERAL_1: u8 = 5;
const ST_RD_LITERAL_2: u8 = 6;
const ST_RD_LITERAL_3: u8 = 7;
const ST_RD_POS_DATA_1: u8 = 8;
const ST_GET_LITERAL: u8 = 9;
const ST_GET_POS_1: u8 = 10;
const ST_GET_POS_2: u8 = 11;
const ST_COPY_DATA: u8 = 12;

/// What a decode call reports.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Step {
    /// The output or the input is used up: call again with more.
    Ok,
    /// Decompression is complete.
    Eof,
    /// The data is broken, or `last` was not set properly.
    Failed,
    /// Upstream's 100: keep going in the other half of the state machine.
    More,
}

/// `strm->next_in` and `strm->avail_in`.
pub(super) struct Input<'a> {
    buf: &'a [u8],
    /// Bytes used so far: upstream's `total_in`.
    pub(super) pos: usize,
}

impl<'a> Input<'a> {
    pub(super) fn new(buf: &'a [u8]) -> Self {
        Input { buf, pos: 0 }
    }

    fn avail(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}

const CACHE_MASKS: [u16; 20] = [
    0x0000, 0x0001, 0x0003, 0x0007, 0x000F, 0x001F, 0x003F, 0x007F, 0x00FF, 0x01FF, 0x03FF, 0x07FF,
    0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
];

/// The bit stream reader.
#[derive(Clone, Copy, Default)]
struct Br {
    cache: u64,
    /// How many bits are available in `cache`; negative after an over read.
    avail: i32,
}

impl Br {
    /// Whether the cache buffer has `n` bits.
    fn has(&self, n: i32) -> bool {
        self.avail >= n
    }

    fn mask(n: i32) -> u16 {
        usize::try_from(n)
            .ok()
            .and_then(|n| CACHE_MASKS.get(n))
            .copied()
            .unwrap_or(0xFFFF)
    }

    /// Gets `n` bits of the compressed data; they must be there.
    fn bits(&self, n: i32) -> i32 {
        let shift = self.avail - n;
        if !(0..64).contains(&shift) {
            return 0;
        }
        i32::from((self.cache >> shift) as u16 & Self::mask(n))
    }

    /// Gets `n` bits, taking zeros for the ones past the end.
    fn bits_forced(&self, n: i32) -> i32 {
        let shift = n - self.avail;
        if !(0..64).contains(&shift) {
            return 0;
        }
        i32::from((self.cache << shift) as u16 & Self::mask(n))
    }

    fn consume(&mut self, n: i32) {
        self.avail -= n;
    }

    /// Shifts away used bits in the cache and fills it up with the
    /// following bytes. True if the cache buffer is full, false if the
    /// input ran out first.
    fn fillup(&mut self, input: &mut Input<'_>) -> bool {
        let want = usize::try_from((64 - self.avail) >> 3).unwrap_or(0);
        let take = want.min(input.avail());
        let bytes = input
            .buf
            .get(input.pos..input.pos + take)
            .unwrap_or_default();
        for &b in bytes {
            self.cache = (self.cache << 8) | u64::from(b);
            self.avail += 8;
        }
        input.pos += bytes.len();
        bytes.len() == want
    }

    /// Whether `n` bits are there after trying to fill the cache up.
    fn read_ahead_0(&mut self, input: &mut Input<'_>, n: i32) -> bool {
        self.has(n) || self.fillup(input)
    }

    /// Whether the cache buffer has as many bits as we need: false means
    /// we have to get the following bytes, if we can.
    fn read_ahead(&mut self, input: &mut Input<'_>, n: i32) -> bool {
        self.read_ahead_0(input, n) || self.has(n)
    }
}

#[derive(Clone, Copy, Default)]
struct Node {
    left: u16,
    right: u16,
}

struct Huffman {
    len_size: i32,
    len_avail: i32,
    len_bits: i32,
    freq: [i32; 17],
    bitlen: Vec<u8>,
    max_bits: i32,
    shift_bits: i32,
    tbl_bits: i32,
    tree_used: i32,
    tree_avail: i32,
    /// Direct access table, faster than searching a binary tree.
    tbl: Vec<u16>,
    /// Binary tree table for extra bits over the direct access.
    tree: Vec<Node>,
}

impl Huffman {
    /// `lzh_huffman_init`.
    fn new(len_size: usize, tbl_bits: i32) -> Self {
        let tree_avail = if tbl_bits > HTBL_BITS {
            1 << (tbl_bits - HTBL_BITS + 4)
        } else {
            0
        };
        Huffman {
            len_size: len_size as i32,
            len_avail: 0,
            len_bits: 0,
            freq: [0; 17],
            bitlen: vec![0; len_size],
            max_bits: 0,
            shift_bits: 0,
            tbl_bits,
            tree_used: 0,
            tree_avail,
            tbl: vec![0; 1 << tbl_bits.min(HTBL_BITS)],
            tree: vec![Node::default(); tree_avail as usize],
        }
    }

    /// `lzh_make_fake_table`: a table of one code, `c`, which takes no bits.
    fn make_fake_table(&mut self, c: i32) -> bool {
        if c >= self.len_size {
            return false;
        }
        let Some(len) = usize::try_from(c).ok().and_then(|c| self.bitlen.get_mut(c)) else {
            return false;
        };
        *len = 0;
        if let Some(t) = self.tbl.first_mut() {
            *t = c as u16;
        }
        self.max_bits = 0;
        self.shift_bits = 0;
        true
    }

    /// `lzh_make_huffman_table`.
    fn make_table(&mut self) -> bool {
        let mut bitptn = [0i32; 17];
        let mut weight = [0i32; 17];
        let mut maxbits = 0;

        // Initialize bit patterns.
        let mut ptn = 0;
        let mut w = 1 << 15;
        for i in 1..=16 {
            bitptn[i] = ptn;
            weight[i] = w;
            if self.freq[i] != 0 {
                ptn += self.freq[i] * w;
                maxbits = i as i32;
            }
            w >>= 1;
        }
        if ptn != 0x10000 || maxbits > self.tbl_bits {
            return false; // Invalid
        }
        self.max_bits = maxbits;

        // Cut out extra bits which we won't house in the table. This
        // preparation reduces the same calculation in the for-loop making
        // the table.
        if maxbits < 16 {
            let ebits = 16 - maxbits;
            for i in 1..=maxbits as usize {
                bitptn[i] >>= ebits;
                weight[i] >>= ebits;
            }
        }
        let diffbits;
        if maxbits > HTBL_BITS {
            diffbits = maxbits - HTBL_BITS;
            for i in 1..=HTBL_BITS as usize {
                bitptn[i] >>= diffbits;
                weight[i] >>= diffbits;
            }
            let htbl_max = bitptn[HTBL_BITS as usize]
                + weight[HTBL_BITS as usize] * self.freq[HTBL_BITS as usize];
            if let Some(rest) = self.tbl.get_mut(usize::try_from(htbl_max).unwrap_or(0)..) {
                rest.fill(0);
            }
        } else {
            diffbits = 0;
        }
        self.shift_bits = diffbits;

        // Make the table.
        let tbl_size = 1 << HTBL_BITS;
        let len_avail = self.len_avail;
        self.tree_used = 0;
        for i in 0..usize::try_from(len_avail).unwrap_or(0) {
            let len = match self.bitlen.get(i) {
                Some(&0) | None => continue,
                Some(&len) => usize::from(len),
            };
            // Get a bit pattern.
            let Some((&ptn, &cnt)) = bitptn.get(len).zip(weight.get(len)) else {
                return false;
            };
            if len <= HTBL_BITS as usize {
                // Calculate the next bit pattern.
                let next = ptn + cnt;
                bitptn[len] = next;
                if next > tbl_size {
                    return false; // Invalid
                }
                let Some(slots) = self.tbl.get_mut(ptn as usize..next as usize) else {
                    return false;
                };
                slots.fill(i as u16);
                continue;
            }

            // A bit length is too big to be housed to a direct table, so we
            // use a tree model for its extra bits.
            bitptn[len] = ptn + cnt;
            let mut bit: u16 = 1 << (diffbits - 1);
            let mut extlen = len as i32 - HTBL_BITS;

            let slot = (ptn >> diffbits) as usize;
            let Some(&p) = self.tbl.get(slot) else {
                return false;
            };
            let mut ht;
            if p == 0 {
                if let Some(t) = self.tbl.get_mut(slot) {
                    *t = (len_avail + self.tree_used) as u16;
                }
                let Some(n) = self.new_node() else {
                    return false; // Invalid
                };
                ht = n;
            } else {
                let p = i32::from(p);
                if p < len_avail || p >= len_avail + self.tree_used {
                    return false; // Invalid
                }
                ht = (p - len_avail) as usize;
            }
            loop {
                extlen -= 1;
                if extlen <= 0 {
                    break;
                }
                let Some(&node) = self.tree.get(ht) else {
                    return false;
                };
                let child = if ptn & i32::from(bit) != 0 {
                    node.left
                } else {
                    node.right
                };
                if i32::from(child) < len_avail {
                    let id = len_avail + self.tree_used;
                    let Some(n) = self.new_node() else {
                        return false; // Invalid
                    };
                    if let Some(parent) = self.tree.get_mut(ht) {
                        if ptn & i32::from(bit) != 0 {
                            parent.left = id as u16;
                        } else {
                            parent.right = id as u16;
                        }
                    }
                    ht = n;
                } else {
                    ht = usize::from(child) - len_avail as usize;
                }
                bit >>= 1;
            }
            let Some(node) = self.tree.get_mut(ht) else {
                return false;
            };
            if ptn & i32::from(bit) != 0 {
                if node.left != 0 {
                    return false; // Invalid
                }
                node.left = i as u16;
            } else {
                if node.right != 0 {
                    return false; // Invalid
                }
                node.right = i as u16;
            }
        }
        true
    }

    /// Takes the next free tree node, empty; its index. None if the tree is
    /// full.
    fn new_node(&mut self) -> Option<usize> {
        let id = usize::try_from(self.tree_used).ok()?;
        self.tree_used += 1;
        if self.tree_used > self.tree_avail {
            return None;
        }
        let node = self.tree.get_mut(id)?;
        *node = Node::default();
        Some(id)
    }

    /// `lzh_decode_huffman`: searches the index table for a bit pattern,
    /// then the tree.
    fn decode(&self, rbits: i32) -> i32 {
        let rbits = rbits as u32;
        let c = i32::from(
            self.tbl
                .get((rbits >> self.shift_bits) as usize)
                .copied()
                .unwrap_or(0),
        );
        if c < self.len_avail || self.len_avail == 0 {
            return c;
        }
        // This bit pattern needs to be found out at a huffman tree.
        self.decode_tree(rbits, c)
    }

    fn decode_tree(&self, rbits: u32, mut c: i32) -> i32 {
        let mut extlen = self.shift_bits;
        while c >= self.len_avail {
            c -= self.len_avail;
            let before = extlen;
            extlen -= 1;
            if before <= 0 || c >= self.tree_used {
                return 0;
            }
            let Some(node) = usize::try_from(c).ok().and_then(|c| self.tree.get(c)) else {
                return 0;
            };
            c = i32::from(if rbits & (1 << extlen) != 0 {
                node.left
            } else {
                node.right
            });
        }
        c
    }

    /// `lzh_read_pt_bitlen`: reads the code lengths `start..end` of the
    /// pre literal or position table. Returns how far it got, or -1 for
    /// invalid data.
    fn read_bitlen(&mut self, br: &mut Br, input: &mut Input<'_>, start: i32, end: i32) -> i32 {
        let mut i = start;
        while i < end {
            // bit pattern     the number we need
            //    000           ->  0
            //    001           ->  1
            //    ...
            //    110           ->  6
            //    1110          ->  7
            //    11110         ->  8
            //    ...
            //    1111111111110 ->  16
            if !br.read_ahead(input, 3) {
                return i;
            }
            let mut c = br.bits(3);
            if c == 7 {
                if !br.read_ahead(input, 13) {
                    return i;
                }
                c = bitlen_tbl(br.bits(13) & 0x3FF);
                if c == 0 {
                    return -1; // Invalid data.
                }
                br.consume(c - 3);
            } else {
                br.consume(3);
            }
            if let Some(len) = usize::try_from(i).ok().and_then(|i| self.bitlen.get_mut(i)) {
                *len = c as u8;
            }
            if let Some(f) = usize::try_from(c).ok().and_then(|c| self.freq.get_mut(c)) {
                *f += 1;
            }
            i += 1;
        }
        i
    }

    fn set_bitlen(&mut self, i: i32, len: u8) {
        if let Some(l) = usize::try_from(i).ok().and_then(|i| self.bitlen.get_mut(i)) {
            *l = len;
        }
    }

    fn bitlen_of(&self, c: i32) -> i32 {
        usize::try_from(c)
            .ok()
            .and_then(|c| self.bitlen.get(c))
            .map_or(0, |&l| i32::from(l))
    }
}

/// Upstream's `bitlen_tbl`: the code length for the 10 bits after three
/// ones, which is seven plus the run of ones that follows, or 0 for a run
/// of ten.
fn bitlen_tbl(i: i32) -> i32 {
    let ones = ((i as u32) << 22).leading_ones() as i32;
    if ones == 10 { 0 } else { 7 + ones }
}

pub(super) struct Lzh {
    state: u8,
    /// Window to see the last 8Ki (lh5), 32Ki (lh6) or 64Ki (lh7) bytes of
    /// decoded data. It is a loop buffer.
    w_buff: Vec<u8>,
    /// The insert position to the window.
    w_pos: i32,
    /// The position where we can copy decoded code from the window.
    copy_pos: i32,
    /// The length how many bytes we can copy decoded code from the window.
    copy_len: i32,
    br: Br,
    lt: Huffman,
    pt: Huffman,
    blocks_avail: i32,
    pos_pt_len_size: i32,
    pos_pt_len_bits: i32,
    reading_position: bool,
    loop_: i32,
    failed: bool,
    /// How much of the window the last decode call produced; it is the
    /// window's start.
    pub(super) avail_out: usize,
}

impl Lzh {
    /// `lzh_decode_init`. None if the method is not supported.
    pub(super) fn new(method: &[u8; 3]) -> Option<Self> {
        if method[0] != b'l' || method[1] != b'h' {
            return None;
        }
        let w_bits = match method[2] {
            b'5' => 13, // 8KiB for window
            b'6' => 15, // 32KiB for window
            b'7' => 16, // 64KiB for window
            _ => return None,
        };
        let mut w_buff = vec![0; W_SIZE as usize];
        let w_size = 1usize << w_bits;
        if let Some(tail) = w_buff
            .len()
            .checked_sub(w_size)
            .and_then(|n| w_buff.get_mut(n..))
        {
            tail.fill(0x20);
        }
        let mut lt = Huffman::new(LT_BITLEN_SIZE, 16);
        lt.len_bits = 9;
        Some(Lzh {
            state: ST_RD_BLOCK,
            w_buff,
            w_pos: 0,
            copy_pos: 0,
            copy_len: 0,
            br: Br::default(),
            lt,
            pt: Huffman::new(PT_BITLEN_SIZE, 16),
            blocks_avail: 0,
            pos_pt_len_size: w_bits + 1,
            pos_pt_len_bits: if w_bits == 15 || w_bits == 16 { 5 } else { 4 },
            reading_position: false,
            loop_: 0,
            failed: false,
            avail_out: 0,
        })
    }

    /// The decoded bytes the last call produced.
    pub(super) fn output(&self) -> &[u8] {
        self.w_buff.get(..self.avail_out).unwrap_or_default()
    }

    /// `lzh_decode`.
    ///
    /// 1. Returns `Ok` if the output buffer or the input buffer is empty.
    ///    Set the available buffer and call this function again.
    /// 2. Returns `Eof` if decompression has been completed.
    /// 3. Returns `Failed` if an error occurred; the compressed data is
    ///    broken or you did not set the `last` flag properly.
    /// 4. The `last` flag is very important, you must set it if there is no
    ///    more input data. The lha compressed data format does not provide
    ///    how to know the compressed data is really finished.
    ///    Note: lha command utility check if the total size of output bytes
    ///    is reached the uncompressed size recorded in its header. it does
    ///    not mind that the decoding process is properly finished.
    ///    GNU ZIP can decompress another compressed file made by SCO LZH
    ///    compress. it handles EOF as null to fill read buffer with zero
    ///    until the decoding process meet 2 bytes of zeros at reading a size
    ///    of a next chunk, so the zeros are treated as the mark of the end of
    ///    the data although the zeros is dummy, not the file data.
    pub(super) fn decode(&mut self, input: &mut Input<'_>, last: bool) -> Step {
        self.avail_out = 0;
        if self.failed {
            return Step::Failed;
        }
        loop {
            let r = if self.state < ST_GET_LITERAL {
                self.read_blocks(input, last)
            } else {
                self.decode_blocks(input, last)
            };
            if r != Step::More {
                return r;
            }
        }
    }

    fn fail(&mut self) -> Step {
        self.failed = true;
        Step::Failed
    }

    fn emit_window(&mut self, s: i32) {
        self.avail_out = usize::try_from(s).unwrap_or(0);
    }

    /// `lzh_read_blocks`: reads a block header and its tables.
    fn read_blocks(&mut self, input: &mut Input<'_>, last: bool) -> Step {
        loop {
            match self.state {
                ST_RD_BLOCK => {
                    // Read a block number indicates how many blocks we will
                    // handle. The block is composed of a literal and a
                    // match, sometimes a literal only in particular, there
                    // are no reference data at the beginning of the
                    // decompression.
                    if !self.br.read_ahead_0(input, 16) {
                        if !last {
                            // We need following data.
                            return Step::Ok;
                        }
                        if self.br.has(8) {
                            // It seems there are extra bits.
                            //  1. Compressed data is broken.
                            //  2. `last' flag does not properly set.
                            return self.fail();
                        }
                        if self.w_pos > 0 {
                            self.emit_window(self.w_pos);
                            self.w_pos = 0;
                            return Step::Ok;
                        }
                        // End of compressed data; we have completely
                        // handled all compressed data.
                        return Step::Eof;
                    }
                    self.blocks_avail = self.br.bits(16);
                    if self.blocks_avail == 0 {
                        return self.fail();
                    }
                    self.br.consume(16);
                    // Read a literal table compressed in huffman coding.
                    self.pt.len_size = PT_BITLEN_SIZE as i32;
                    self.pt.len_bits = 5;
                    self.reading_position = false;
                    self.state = ST_RD_PT_1;
                }
                ST_RD_PT_1 => {
                    // Note: ST_RD_PT_1, ST_RD_PT_2 and ST_RD_PT_4 are used in
                    // reading both a literal table and a position table.
                    if !self.br.read_ahead(input, self.pt.len_bits) {
                        if last {
                            return self.fail(); // Truncated data.
                        }
                        return Step::Ok;
                    }
                    self.pt.len_avail = self.br.bits(self.pt.len_bits);
                    self.br.consume(self.pt.len_bits);
                    self.state = ST_RD_PT_2;
                }
                ST_RD_PT_2 => {
                    if self.pt.len_avail == 0 {
                        // There is no bitlen.
                        if !self.br.read_ahead(input, self.pt.len_bits) {
                            if last {
                                return self.fail(); // Truncated data.
                            }
                            return Step::Ok;
                        }
                        if !self.pt.make_fake_table(self.br.bits(self.pt.len_bits)) {
                            return self.fail(); // Invalid data.
                        }
                        self.br.consume(self.pt.len_bits);
                        self.state = if self.reading_position {
                            ST_GET_LITERAL
                        } else {
                            ST_RD_LITERAL_1
                        };
                        continue;
                    } else if self.pt.len_avail > self.pt.len_size {
                        return self.fail(); // Invalid data.
                    }
                    self.loop_ = 0;
                    self.pt.freq = [0; 17];
                    self.state =
                        if self.pt.len_avail < 3 || self.pt.len_size == self.pos_pt_len_size {
                            ST_RD_PT_4
                        } else {
                            ST_RD_PT_3
                        };
                }
                ST_RD_PT_3 => {
                    self.loop_ = self.pt.read_bitlen(&mut self.br, input, self.loop_, 3);
                    if self.loop_ < 3 {
                        if self.loop_ < 0 || last {
                            return self.fail(); // Invalid data.
                        }
                        // Not completed, get following data.
                        return Step::Ok;
                    }
                    // There are some null in bitlen of the literal.
                    if !self.br.read_ahead(input, 2) {
                        if last {
                            return self.fail(); // Truncated data.
                        }
                        return Step::Ok;
                    }
                    let c = self.br.bits(2);
                    self.br.consume(2);
                    if c > self.pt.len_avail - 3 {
                        return self.fail(); // Invalid data.
                    }
                    for i in 3..3 + c {
                        self.pt.set_bitlen(i, 0);
                    }
                    self.loop_ = 3 + c;
                    self.state = ST_RD_PT_4;
                }
                ST_RD_PT_4 => {
                    self.loop_ =
                        self.pt
                            .read_bitlen(&mut self.br, input, self.loop_, self.pt.len_avail);
                    if self.loop_ < self.pt.len_avail {
                        if self.loop_ < 0 || last {
                            return self.fail(); // Invalid data.
                        }
                        // Not completed, get following data.
                        return Step::Ok;
                    }
                    if !self.pt.make_table() {
                        return self.fail(); // Invalid data
                    }
                    self.state = if self.reading_position {
                        ST_GET_LITERAL
                    } else {
                        ST_RD_LITERAL_1
                    };
                }
                ST_RD_LITERAL_1 => {
                    if !self.br.read_ahead(input, self.lt.len_bits) {
                        if last {
                            return self.fail(); // Truncated data.
                        }
                        return Step::Ok;
                    }
                    self.lt.len_avail = self.br.bits(self.lt.len_bits);
                    self.br.consume(self.lt.len_bits);
                    self.state = ST_RD_LITERAL_2;
                }
                ST_RD_LITERAL_2 => {
                    if self.lt.len_avail == 0 {
                        // There is no bitlen.
                        if !self.br.read_ahead(input, self.lt.len_bits) {
                            if last {
                                return self.fail(); // Truncated data.
                            }
                            return Step::Ok;
                        }
                        if !self.lt.make_fake_table(self.br.bits(self.lt.len_bits)) {
                            return self.fail(); // Invalid data
                        }
                        self.br.consume(self.lt.len_bits);
                        self.state = ST_RD_POS_DATA_1;
                        continue;
                    } else if self.lt.len_avail > self.lt.len_size {
                        return self.fail(); // Invalid data
                    }
                    self.loop_ = 0;
                    self.lt.freq = [0; 17];
                    self.state = ST_RD_LITERAL_3;
                }
                ST_RD_LITERAL_3 => {
                    let mut i = self.loop_;
                    while i < self.lt.len_avail {
                        if !self.br.read_ahead(input, self.pt.max_bits) {
                            if last {
                                return self.fail(); // Truncated data.
                            }
                            self.loop_ = i;
                            return Step::Ok;
                        }
                        let rbits = self.br.bits(self.pt.max_bits);
                        let mut c = self.pt.decode(rbits);
                        if c > 2 {
                            // Note: 'c' will never be more than eighteen
                            // since it's limited by PT_BITLEN_SIZE, which is
                            // being set to ds->pt.len_size through
                            // ds->literal_pt_len_size.
                            self.br.consume(self.pt.bitlen_of(c));
                            c -= 2;
                            if let Some(f) = usize::try_from(c)
                                .ok()
                                .and_then(|c| self.lt.freq.get_mut(c))
                            {
                                *f += 1;
                            }
                            self.lt.set_bitlen(i, c as u8);
                            i += 1;
                        } else if c == 0 {
                            self.br.consume(self.pt.bitlen_of(c));
                            self.lt.set_bitlen(i, 0);
                            i += 1;
                        } else {
                            // c == 1 or c == 2
                            let n = if c == 1 { 4 } else { 9 };
                            let pt_len = self.pt.bitlen_of(c);
                            if !self.br.read_ahead(input, pt_len + n) {
                                if last {
                                    return self.fail(); // Truncated data.
                                }
                                self.loop_ = i;
                                return Step::Ok;
                            }
                            self.br.consume(pt_len);
                            c = self.br.bits(n);
                            self.br.consume(n);
                            c += if n == 4 { 3 } else { 20 };
                            if i + c > self.lt.len_avail {
                                return self.fail(); // Invalid data
                            }
                            for k in i..i + c {
                                self.lt.set_bitlen(k, 0);
                            }
                            i += c;
                        }
                    }
                    if i > self.lt.len_avail || !self.lt.make_table() {
                        return self.fail(); // Invalid data
                    }
                    self.state = ST_RD_POS_DATA_1;
                }
                ST_RD_POS_DATA_1 => {
                    // Read a position table compressed in huffman coding.
                    self.pt.len_size = self.pos_pt_len_size;
                    self.pt.len_bits = self.pos_pt_len_bits;
                    self.reading_position = true;
                    self.state = ST_RD_PT_1;
                }
                // ST_GET_LITERAL
                _ => return Step::More,
            }
        }
    }

    /// `lzh_decode_blocks`: decodes the literals and matches of the blocks.
    fn decode_blocks(&mut self, input: &mut Input<'_>, last: bool) -> Step {
        let mut bre = self.br;
        let mut blocks_avail = self.blocks_avail;
        let mut c;
        let mut copy_len = self.copy_len;
        let mut copy_pos = self.copy_pos;
        let mut w_pos = self.w_pos;
        let lt_max_bits = self.lt.max_bits;
        let pt_max_bits = self.pt.max_bits;
        let mut state = self.state;

        // Leaving this block is upstream's `next_data`.
        'next_data: {
            loop {
                match state {
                    ST_GET_LITERAL => {
                        loop {
                            if blocks_avail == 0 {
                                // We have decoded all blocks. Let's handle
                                // next blocks.
                                self.state = ST_RD_BLOCK;
                                self.br = bre;
                                self.blocks_avail = 0;
                                self.w_pos = w_pos;
                                self.copy_pos = 0;
                                return Step::More;
                            }

                            // lzh_br_read_ahead() always tries to fill the
                            // cache buffer up. In specific situation we are
                            // close to the end of the data, the cache buffer
                            // will not be full and thus we have to
                            // determine if the cache buffer has some bits as
                            // much as we need after lzh_br_read_ahead()
                            // failed.
                            if !bre.read_ahead(input, lt_max_bits) {
                                if !last {
                                    break 'next_data;
                                }
                                // Remaining bits are less than maximum
                                // bits(lt.max_bits) but maybe it still
                                // remains as much as we need, so we should
                                // try to use it with dummy bits.
                                c = self.lt.decode(bre.bits_forced(lt_max_bits));
                                bre.consume(self.lt.bitlen_of(c));
                                if !bre.has(0) {
                                    return self.fail(); // Over read.
                                }
                            } else {
                                c = self.lt.decode(bre.bits(lt_max_bits));
                                bre.consume(self.lt.bitlen_of(c));
                            }
                            blocks_avail -= 1;
                            if c > 255 {
                                // Current block is a match data.
                                break;
                            }
                            // 'c' is exactly a literal code. Save a decoded
                            // code to reference it afterward.
                            if let Some(b) = usize::try_from(w_pos)
                                .ok()
                                .and_then(|p| self.w_buff.get_mut(p))
                            {
                                *b = c as u8;
                            }
                            w_pos += 1;
                            if w_pos >= W_SIZE {
                                w_pos = 0;
                                self.emit_window(W_SIZE);
                                break 'next_data;
                            }
                        }
                        // 'c' is the length of a match pattern we have
                        // already extracted, which has be stored in
                        // window(ds->w_buff).
                        copy_len = c - 256 + MINMATCH;
                        state = ST_GET_POS_1;
                    }
                    ST_GET_POS_1 => {
                        // Get a reference position.
                        if !bre.read_ahead(input, pt_max_bits) {
                            if !last {
                                self.copy_len = copy_len;
                                break 'next_data;
                            }
                            copy_pos = self.pt.decode(bre.bits_forced(pt_max_bits));
                            bre.consume(self.pt.bitlen_of(copy_pos));
                            if !bre.has(0) {
                                return self.fail(); // Over read.
                            }
                        } else {
                            copy_pos = self.pt.decode(bre.bits(pt_max_bits));
                            bre.consume(self.pt.bitlen_of(copy_pos));
                        }
                        state = ST_GET_POS_2;
                    }
                    ST_GET_POS_2 => {
                        if copy_pos > 1 {
                            // We need an additional adjustment number to
                            // the position.
                            let p = copy_pos - 1;
                            if !bre.read_ahead(input, p) {
                                if last {
                                    return self.fail(); // Truncated data.
                                }
                                self.copy_len = copy_len;
                                self.copy_pos = copy_pos;
                                break 'next_data;
                            }
                            copy_pos = (1 << p) + bre.bits(p);
                            bre.consume(p);
                        }
                        // The position is actually a distance from the last
                        // code we had extracted and thus we have to convert
                        // it to a position of the window.
                        copy_pos = (w_pos - copy_pos - 1) & W_MASK;
                        state = ST_COPY_DATA;
                    }
                    ST_COPY_DATA => {
                        // Copy `copy_len' bytes as extracted data from the
                        // window into the output buffer.
                        loop {
                            let mut l = copy_len;
                            if copy_pos > w_pos {
                                l = l.min(W_SIZE - copy_pos);
                            } else {
                                l = l.min(W_SIZE - w_pos);
                            }
                            if !self.copy_within_window(copy_pos, w_pos, l) {
                                return self.fail();
                            }
                            w_pos += l;
                            if w_pos == W_SIZE {
                                w_pos = 0;
                                self.emit_window(W_SIZE);
                                if copy_len <= l {
                                    state = ST_GET_LITERAL;
                                } else {
                                    state = ST_COPY_DATA;
                                    self.copy_len = copy_len - l;
                                    self.copy_pos = (copy_pos + l) & W_MASK;
                                }
                                break 'next_data;
                            }
                            if copy_len <= l {
                                // A copy of current pattern ended.
                                break;
                            }
                            copy_len -= l;
                            copy_pos = (copy_pos + l) & W_MASK;
                        }
                        state = ST_GET_LITERAL;
                    }
                    _ => return self.fail(),
                }
            }
        }
        self.br = bre;
        self.blocks_avail = blocks_avail;
        self.state = state;
        self.w_pos = w_pos;
        Step::Ok
    }

    /// Copies `l` bytes of the window from `from` to `to`, front to back, so
    /// that a match overlapping its own output repeats it. False if either
    /// range is out of the window.
    fn copy_within_window(&mut self, from: i32, to: i32, l: i32) -> bool {
        let (Ok(from), Ok(to), Ok(l)) = (
            usize::try_from(from),
            usize::try_from(to),
            usize::try_from(l),
        ) else {
            return false;
        };
        let len = self.w_buff.len();
        if from.saturating_add(l) > len || to.saturating_add(l) > len {
            return false;
        }
        if to <= from || from + l <= to {
            self.w_buff.copy_within(from..from + l, to);
        } else {
            // Overlapping: the output follows the source by `to - from`.
            for k in 0..l {
                if let Some(&b) = self.w_buff.get(from + k)
                    && let Some(d) = self.w_buff.get_mut(to + k)
                {
                    *d = b;
                }
            }
        }
        true
    }
}
