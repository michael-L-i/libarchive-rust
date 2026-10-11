/*-
 * Copyright (c) 2010-2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_read_support_format_cab.c.

//! The LZX decompressor of Microsoft Cabinet files: a resumable decoder fed
//! in chunks, with Huffman decoding through direct lookup tables, as
//! upstream's `lzx_*` functions.

/// The largest file in a cabinet (`UINT16_MAX * MAX_UNCOMPRESS_SIZE`).
const MAX_FILE_SIZE: u32 = 0xFFFF * 0x8000;

// Decoding states.
const ST_RD_TRANSLATION: u8 = 0;
const ST_RD_TRANSLATION_SIZE: u8 = 1;
const ST_RD_BLOCK_TYPE: u8 = 2;
const ST_RD_BLOCK_SIZE: u8 = 3;
const ST_RD_ALIGNMENT: u8 = 4;
const ST_RD_R0: u8 = 5;
const ST_RD_R1: u8 = 6;
const ST_RD_R2: u8 = 7;
const ST_COPY_UNCOMP1: u8 = 8;
const ST_COPY_UNCOMP2: u8 = 9;
const ST_RD_ALIGNED_OFFSET: u8 = 10;
const ST_RD_VERBATIM: u8 = 11;
const ST_RD_PRE_MAIN_TREE_256: u8 = 12;
const ST_MAIN_TREE_256: u8 = 13;
const ST_RD_PRE_MAIN_TREE_REM: u8 = 14;
const ST_MAIN_TREE_REM: u8 = 15;
const ST_RD_PRE_LENGTH_TREE: u8 = 16;
const ST_LENGTH_TREE: u8 = 17;
const ST_MAIN: u8 = 18;
const ST_LENGTH: u8 = 19;
const ST_OFFSET: u8 = 20;
const ST_REAL_POS: u8 = 21;
const ST_COPY: u8 = 22;

const VERBATIM_BLOCK: u8 = 1;
const ALIGNED_OFFSET_BLOCK: u8 = 2;
const UNCOMPRESSED_BLOCK: u8 = 3;

/// Position slots for each window size, 15 to 21 bits.
const SLOTS: [usize; 7] = [30, 32, 34, 36, 38, 42, 50];
const SLOT_BASE: u32 = 15;
const SLOT_MAX: u32 = 21;

/// How `Lzx::decode` went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Status {
    /// The input or the output is used up; call again with more.
    Ok,
    /// The compressed block ended (`ARCHIVE_EOF`).
    Eof,
    /// The data is broken, or `last` was not set properly.
    Failed,
}

/// What one `Lzx::decode` call did.
pub(super) struct Decoded {
    pub status: Status,
    pub consumed: usize,
    pub written: usize,
}

/// Internal result of the block readers: `Cont` is upstream's 100, meaning
/// the tables are read and the symbols follow.
enum Res {
    Ok,
    Eof,
    Failed,
    Cont,
}

/// The input and output buffers of one `decode` call.
struct Io<'a> {
    inp: &'a [u8],
    in_pos: usize,
    out: &'a mut [u8],
    out_pos: usize,
}

impl Io<'_> {
    fn in_left(&self) -> usize {
        self.inp.len() - self.in_pos
    }

    fn out_left(&self) -> usize {
        self.out.len() - self.out_pos
    }

    fn byte(&self, at: usize) -> u64 {
        self.inp.get(self.in_pos + at).map_or(0, |&b| u64::from(b))
    }

    /// The little-endian 16-bit word `at` bytes ahead.
    fn word(&self, at: usize) -> u64 {
        self.byte(at) | self.byte(at + 1) << 8
    }
}

fn mask(n: usize) -> u32 {
    if n >= 32 { u32::MAX } else { (1 << n) - 1 }
}

/// Bit stream reader: 16-bit little-endian words, most significant bit first.
#[derive(Clone, Copy, Default)]
struct BitReader {
    cache: u64,
    /// How many bits of `cache` are valid.
    avail: usize,
    /// A single trailing input byte kept until the next chunk completes it.
    odd: u8,
    have_odd: bool,
}

impl BitReader {
    fn has(&self, n: usize) -> bool {
        self.avail >= n
    }

    /// The next `n` bits, which must be in the cache.
    fn bits(&self, n: usize) -> u32 {
        if n == 0 || self.avail < n {
            return 0;
        }
        (self.cache >> (self.avail - n)) as u32 & mask(n)
    }

    /// The next `n` bits, padded with zeros when the cache has fewer.
    fn bits_forced(&self, n: usize) -> u32 {
        let shifted = self.cache.checked_shl(n.saturating_sub(self.avail) as u32);
        shifted.unwrap_or(0) as u32 & mask(n)
    }

    fn consume(&mut self, n: usize) {
        self.avail = self.avail.saturating_sub(n);
    }

    fn is_unaligned(&self) -> bool {
        self.avail & 0x0f != 0
    }

    /// Whether the cache has `n` bits, reading more input if needed.
    fn read_ahead(&mut self, io: &mut Io, n: usize) -> bool {
        self.has(n) || self.fillup(io) || self.has(n)
    }

    /// Shifts away used bits and fills the cache up with following bits.
    /// True if the cache is now full, false if the input ran out.
    fn fillup(&mut self, io: &mut Io) -> bool {
        let mut n = 64 - self.avail;
        loop {
            match n >> 4 {
                4 if io.in_left() >= 8 => {
                    self.cache =
                        io.word(0) << 48 | io.word(2) << 32 | io.word(4) << 16 | io.word(6);
                    io.in_pos += 8;
                    self.avail += 64;
                    return true;
                }
                3 if io.in_left() >= 6 => {
                    self.cache =
                        self.cache << 48 | io.word(0) << 32 | io.word(2) << 16 | io.word(4);
                    io.in_pos += 6;
                    self.avail += 48;
                    return true;
                }
                // The cache has enough bits.
                0 => return false,
                _ => {}
            }
            if io.in_left() < 2 {
                // Not enough input to fill the cache up.
                if io.in_left() == 1 {
                    self.odd = io.byte(0) as u8;
                    io.in_pos += 1;
                    self.have_odd = true;
                }
                return false;
            }
            self.cache = self.cache << 16 | io.word(0);
            io.in_pos += 2;
            self.avail += 16;
            n -= 16;
        }
    }

    /// Completes the word that the last chunk ended in the middle of.
    fn fixup(&mut self, io: &mut Io) {
        let n = 64 - self.avail;
        if self.have_odd && n >= 16 && io.in_left() > 0 {
            self.cache = self.cache << 16 | io.byte(0) << 8 | u64::from(self.odd);
            io.in_pos += 1;
            self.avail += 16;
            self.have_odd = false;
        }
    }
}

/// Huffman coding.
///
/// Array representation of a Huffman tree for codes of up to 16 bit lengths.
/// Lookups are performed through a direct, expanded lookup table: a table
/// with as many entries as the bit patterns of `lookup_bits` bits, where a
/// code shorter than that fills every entry that starts with it. A user must
/// check the code bit length of a retrieved symbol after the lookup to
/// properly advance the bit stream:
///
/// ```text
/// symbol = tbl[read_bits(lookup_bits)]
/// consume_bits(bitlen[symbol])
/// ```
#[derive(Default)]
struct Huffman {
    /// Symbols are `0..symbol_count`, unused ones included.
    symbol_count: u16,
    /// Number of codes of each bit length; index 0 counts unused symbols.
    freq: [u16; 17],
    /// Map of symbols to their code bit lengths.
    bitlen: Vec<u8>,
    /// Amount of bits to use for lookup (at most `tbl_bits`).
    lookup_bits: u8,
    /// Code bit length the table was allocated for (at most 16).
    tbl_bits: u8,
    tbl: Vec<u16>,
}

impl Huffman {
    fn new(symbol_count: u16, tbl_bits: u8) -> Huffman {
        Huffman {
            symbol_count,
            bitlen: vec![0; usize::from(symbol_count)],
            tbl_bits,
            tbl: vec![0; 1 << tbl_bits],
            ..Huffman::default()
        }
    }

    fn bitlen(&self, symbol: u16) -> usize {
        self.bitlen
            .get(usize::from(symbol))
            .map_or(0, |&b| usize::from(b))
    }

    fn decode(&self, rbits: u32) -> u16 {
        self.tbl.get(rbits as usize).copied().unwrap_or(0)
    }

    /// Creates the direct, expanded lookup table based on the canonical
    /// representation. False if the code lengths are not a complete code.
    fn make_table(&mut self) -> bool {
        // Each `bitptn` element is the smallest code sequence allowed for
        // that length; `weight` is the number of lookup bit patterns a code
        // of that length covers.
        let mut bitptn = [0u16; 17];
        let mut weight = [0u16; 17];
        let mut maxbits = 0u8;
        let mut ptn = 0u32;
        let mut w = 1u16 << 15;
        for i in 1..=16 {
            bitptn[i] = ptn as u16;
            weight[i] = w;
            if self.freq[i] != 0 {
                ptn += u32::from(self.freq[i]) * u32::from(w);
                maxbits = i as u8;
            }
            w >>= 1;
        }
        // Verify Kraft's inequality.
        if ptn != 0 && ptn != 0x10000 {
            return false;
        }

        // Shrink codes to the smallest size by removing the extra bits after
        // the actual code sequences.
        if maxbits < 16 {
            let ebits = 16 - maxbits;
            for i in 1..=usize::from(maxbits) {
                bitptn[i] >>= ebits;
                weight[i] >>= ebits;
            }
        }

        // Grow the table if necessary.
        if maxbits > self.tbl_bits {
            self.tbl_bits = 16;
            self.tbl = vec![0; 1 << 16];
        }
        self.lookup_bits = maxbits;

        // Store each symbol in the table for every bit pattern that starts
        // with its code.
        for (symbol, &len) in self.bitlen.iter().enumerate() {
            if len == 0 {
                continue;
            }
            if len > maxbits {
                return false;
            }
            let len = usize::from(len);
            let ptn = usize::from(bitptn[len]);
            let cnt = usize::from(weight[len]);
            bitptn[len] = (ptn + cnt) as u16;
            let Some(entries) = self.tbl.get_mut(ptn..ptn + cnt) else {
                return false;
            };
            entries.fill(symbol as u16);
        }
        true
    }
}

/// Where a position slot starts and how many extra bits follow it.
#[derive(Clone, Copy, Default)]
struct PosSlot {
    base: u32,
    footer_bits: u8,
}

/// Which tree `read_bitlen` fills in.
#[derive(Clone, Copy)]
enum Tree {
    Main,
    Length,
}

/// The decoder state (upstream's `lzx_dec` and `lzx_stream`).
pub(super) struct Lzx {
    state: u8,
    /// Window to see the last decoded data, from 32 KiB to 2 MiB: a loop
    /// buffer.
    w_size: usize,
    w_mask: usize,
    w_buff: Vec<u8>,
    /// The insert position to the window.
    w_pos: usize,
    /// The number of initialized bytes in the window.
    w_filled: usize,
    /// The position and length of the window copy in progress.
    copy_pos: usize,
    copy_len: usize,
    /// Translation reversal for x86 processor CALL byte sequence (E8).
    translation_size: i32,
    translation: bool,
    block_type: u8,
    block_size: usize,
    block_bytes_avail: usize,
    /// Repeated offsets.
    r0: usize,
    r1: usize,
    r2: usize,
    rbytes: [u8; 4],
    rbytes_avail: usize,
    length_header: u8,
    position_slot: u16,
    offset_bits: u8,
    pos_tbl: Vec<PosSlot>,
    br: BitReader,
    /// Aligned offset tree, length tree, main tree and pre-tree.
    at: Huffman,
    lt: Huffman,
    mt: Huffman,
    pt: Huffman,
    /// Progress through the tree being read.
    loop_: u16,
    /// Set once the data is found broken; every later call fails.
    failed: bool,
}

impl Lzx {
    /// `lzx_decode_init`: a decoder for a window of `1 << w_bits` bytes, or
    /// `None` unless that is from 15 (32 KiB) up to 21 (2 MiB).
    pub fn new(w_bits: u16) -> Option<Lzx> {
        let w_bits = u32::from(w_bits);
        if !(SLOT_BASE..=SLOT_MAX).contains(&w_bits) {
            return None;
        }
        let w_slot = *SLOTS.get((w_bits - SLOT_BASE) as usize)?;
        let w_size = 1usize << w_bits;

        let mut pos_tbl = Vec::with_capacity(w_slot);
        let (mut base, mut footer) = (0u32, 0u8);
        for slot in 0..w_slot {
            if footer == 0 {
                base = slot as u32;
            } else {
                base += 1 << footer;
            }
            if footer < 17 {
                footer = (32 - base.leading_zeros()) as u8;
                footer = footer.saturating_sub(2);
            }
            pos_tbl.push(PosSlot {
                base,
                footer_bits: footer,
            });
        }

        Some(Lzx {
            state: ST_RD_TRANSLATION,
            w_size,
            w_mask: w_size - 1,
            w_buff: vec![0; w_size],
            w_pos: 0,
            w_filled: 0,
            copy_pos: 0,
            copy_len: 0,
            translation_size: 0,
            translation: false,
            block_type: 0,
            block_size: 0,
            block_bytes_avail: 0,
            r0: 1,
            r1: 1,
            r2: 1,
            rbytes: [0; 4],
            rbytes_avail: 0,
            length_header: 0,
            position_slot: 0,
            offset_bits: 0,
            pos_tbl,
            br: BitReader::default(),
            at: Huffman::new(8, 8),
            lt: Huffman::new(249, 16),
            mt: Huffman::new((256 + (w_slot << 3)) as u16, 16),
            pt: Huffman::new(20, 10),
            loop_: 0,
            failed: false,
        })
    }

    /// Drops the bits left in the cache of the previous CFDATA.
    pub fn cleanup_bitstream(&mut self) {
        self.br.avail = 0;
        self.br.have_odd = false;
    }

    /// `lzx_decode`: decodes `input` into `out`. `last` says the input is
    /// all the compressed bytes of this CFDATA there will be.
    pub fn decode(&mut self, input: &[u8], out: &mut [u8], last: bool) -> Decoded {
        let mut io = Io {
            inp: input,
            in_pos: 0,
            out,
            out_pos: 0,
        };
        let status = self.run(&mut io, last);
        Decoded {
            status,
            consumed: io.in_pos,
            written: io.out_pos,
        }
    }

    fn run(&mut self, io: &mut Io, last: bool) -> Status {
        if self.failed {
            return Status::Failed;
        }
        self.br.fixup(io);
        loop {
            let r = if self.state < ST_MAIN {
                self.read_blocks(io, last)
            } else {
                self.decode_blocks(io, last)
            };
            match r {
                Res::Cont => {}
                Res::Ok => return Status::Ok,
                Res::Eof => return Status::Eof,
                Res::Failed => {
                    self.failed = true;
                    return Status::Failed;
                }
            }
        }
    }

    /// E8 call translation reversal.
    pub fn translation(&self, buffer: &mut [u8], offset: i32) {
        const MAX_E8_TRANSLATION: i32 = 0x8000 * 0x8000;
        if !self.translation || offset >= MAX_E8_TRANSLATION || buffer.len() <= 10 {
            return;
        }
        let end = buffer.len() - 10;
        let mut p = 0;
        while p < end {
            let Some(hit) = buffer
                .get(p..end)
                .and_then(|s| s.iter().position(|&b| b == 0xE8))
            else {
                break;
            };
            p += hit;
            let Some(field) = buffer.get_mut(p + 1..p + 5) else {
                break;
            };
            let address = i32::from_le_bytes([field[0], field[1], field[2], field[3]]);
            let position = offset.wrapping_add(p as i32);
            if address >= position.wrapping_neg() && address < self.translation_size {
                let relative = if address >= 0 {
                    address.wrapping_sub(position)
                } else {
                    address.wrapping_add(self.translation_size)
                };
                field.copy_from_slice(&relative.to_le_bytes());
            }
            p += 5;
        }
    }

    /// Reads the block headers, the pre-trees and the trees.
    fn read_blocks(&mut self, io: &mut Io, last: bool) -> Res {
        // Not enough input: ask for more, unless there will be none.
        macro_rules! need {
            () => {
                return if last { Res::Failed } else { Res::Ok }
            };
        }
        loop {
            match self.state {
                ST_RD_TRANSLATION => {
                    if !self.br.read_ahead(io, 1) {
                        need!();
                    }
                    self.translation = self.br.bits(1) != 0;
                    self.br.consume(1);
                    self.state = ST_RD_TRANSLATION_SIZE;
                }
                ST_RD_TRANSLATION_SIZE => {
                    if self.translation {
                        if !self.br.read_ahead(io, 32) {
                            need!();
                        }
                        let mut v = self.br.bits(16);
                        self.br.consume(16);
                        v <<= 16;
                        v |= self.br.bits(16);
                        if v > MAX_FILE_SIZE {
                            return Res::Failed;
                        }
                        self.translation_size = v as i32;
                        self.br.consume(16);
                    }
                    self.state = ST_RD_BLOCK_TYPE;
                }
                ST_RD_BLOCK_TYPE => {
                    if !self.br.read_ahead(io, 3) {
                        need!();
                    }
                    self.block_type = self.br.bits(3) as u8;
                    self.br.consume(3);
                    if !matches!(
                        self.block_type,
                        VERBATIM_BLOCK | ALIGNED_OFFSET_BLOCK | UNCOMPRESSED_BLOCK
                    ) {
                        return Res::Failed;
                    }
                    self.state = ST_RD_BLOCK_SIZE;
                }
                ST_RD_BLOCK_SIZE => {
                    if !self.br.read_ahead(io, 24) {
                        need!();
                    }
                    let mut size = self.br.bits(8) as usize;
                    self.br.consume(8);
                    size <<= 16;
                    size |= self.br.bits(16) as usize;
                    self.br.consume(16);
                    self.block_size = size;
                    if size == 0 {
                        return Res::Failed;
                    }
                    self.block_bytes_avail = size;
                    self.state = match self.block_type {
                        VERBATIM_BLOCK => ST_RD_VERBATIM,
                        ALIGNED_OFFSET_BLOCK => ST_RD_ALIGNED_OFFSET,
                        _ => ST_RD_ALIGNMENT,
                    };
                }
                ST_RD_ALIGNMENT => {
                    // An uncompressed block: skip the padding that aligns
                    // the following field on a 16-bit boundary.
                    if self.br.is_unaligned() {
                        self.br.avail &= !0x0f;
                    } else if self.br.read_ahead(io, 16) {
                        self.br.consume(16);
                    } else {
                        need!();
                    }
                    // Preparation to read the repeated offsets R0, R1, R2.
                    self.rbytes_avail = 0;
                    self.state = ST_RD_R0;
                }
                ST_RD_R0 | ST_RD_R1 | ST_RD_R2 => {
                    // Drain the bits in the cache of the bit stream first.
                    if self.br.has(32) {
                        let lo = self.br.bits(16) as u16;
                        self.br.consume(16);
                        let hi = self.br.bits(16) as u16;
                        self.br.consume(16);
                        self.rbytes[..2].copy_from_slice(&lo.to_le_bytes());
                        self.rbytes[2..].copy_from_slice(&hi.to_le_bytes());
                        self.rbytes_avail = 4;
                    } else if self.br.has(16) {
                        let lo = self.br.bits(16) as u16;
                        self.br.consume(16);
                        self.rbytes[..2].copy_from_slice(&lo.to_le_bytes());
                        self.rbytes_avail = 2;
                    }
                    if self.rbytes_avail < 4 && self.br.have_odd {
                        self.rbytes[self.rbytes_avail] = self.br.odd;
                        self.rbytes_avail += 1;
                        self.br.have_odd = false;
                    }
                    while self.rbytes_avail < 4 {
                        if io.in_left() == 0 {
                            need!();
                        }
                        self.rbytes[self.rbytes_avail] = io.byte(0) as u8;
                        self.rbytes_avail += 1;
                        io.in_pos += 1;
                    }
                    self.rbytes_avail = 0;
                    let v = u32::from_le_bytes(self.rbytes) as usize;
                    if v > i32::MAX as usize {
                        return Res::Failed;
                    }
                    match self.state {
                        ST_RD_R0 => {
                            self.r0 = v;
                            self.state = ST_RD_R1;
                        }
                        ST_RD_R1 => {
                            self.r1 = v;
                            self.state = ST_RD_R2;
                        }
                        _ => {
                            self.r2 = v;
                            // We've gotten all repeated offsets.
                            self.state = ST_COPY_UNCOMP1;
                        }
                    }
                }
                ST_COPY_UNCOMP1 => {
                    // Copy bytes from the input to the output directly.
                    while self.block_bytes_avail != 0 {
                        if io.out_left() == 0 {
                            return Res::Ok;
                        }
                        if io.in_left() == 0 {
                            need!();
                        }
                        let l = self
                            .block_bytes_avail
                            .min(self.w_size - self.w_pos)
                            .min(io.out_left())
                            .min(io.in_left());
                        let src = &io.inp[io.in_pos..io.in_pos + l];
                        io.out[io.out_pos..io.out_pos + l].copy_from_slice(src);
                        self.w_buff[self.w_pos..self.w_pos + l].copy_from_slice(src);
                        io.in_pos += l;
                        io.out_pos += l;
                        self.w_pos = (self.w_pos + l) & self.w_mask;
                        if self.w_filled < self.w_size {
                            self.w_filled = (self.w_filled + l).min(self.w_size);
                        }
                        self.block_bytes_avail -= l;
                    }
                    self.state = ST_COPY_UNCOMP2;
                }
                ST_COPY_UNCOMP2 => {
                    // Re-align; skip the padding byte.
                    if self.block_size & 1 != 0 {
                        if io.in_left() == 0 {
                            need!();
                        }
                        io.in_pos += 1;
                    }
                    // This block ended.
                    self.state = ST_RD_BLOCK_TYPE;
                    return Res::Eof;
                }
                ST_RD_ALIGNED_OFFSET => {
                    // Read the aligned offset tree.
                    if !self
                        .br
                        .read_ahead(io, 3 * usize::from(self.at.symbol_count))
                    {
                        need!();
                    }
                    self.at.freq = [0; 17];
                    for b in &mut self.at.bitlen {
                        *b = self.br.bits(3) as u8;
                        self.at.freq[usize::from(*b)] += 1;
                        self.br.consume(3);
                    }
                    if !self.at.make_table() {
                        return Res::Failed;
                    }
                    self.state = ST_RD_VERBATIM;
                }
                ST_RD_VERBATIM => {
                    self.loop_ = 0;
                    self.state = ST_RD_PRE_MAIN_TREE_256;
                }
                ST_RD_PRE_MAIN_TREE_256 => {
                    // The pre-tree for the first 256 elements of the main tree.
                    if !self.read_pre_tree(io) {
                        need!();
                    }
                    if !self.pt.make_table() {
                        return Res::Failed;
                    }
                    self.loop_ = 0;
                    self.state = ST_MAIN_TREE_256;
                }
                ST_MAIN_TREE_256 => {
                    // The path lengths of the first 256 elements.
                    match self.read_bitlen(io, Tree::Main, 256) {
                        Res::Eof => need!(),
                        Res::Ok => {}
                        _ => return Res::Failed,
                    }
                    self.loop_ = 0;
                    self.state = ST_RD_PRE_MAIN_TREE_REM;
                }
                ST_RD_PRE_MAIN_TREE_REM => {
                    // The pre-tree for the remaining elements of the main tree.
                    if !self.read_pre_tree(io) {
                        need!();
                    }
                    if !self.pt.make_table() {
                        return Res::Failed;
                    }
                    self.loop_ = 256;
                    self.state = ST_MAIN_TREE_REM;
                }
                ST_MAIN_TREE_REM => {
                    match self.read_bitlen(io, Tree::Main, 0) {
                        Res::Eof => need!(),
                        Res::Ok => {}
                        _ => return Res::Failed,
                    }
                    if !self.mt.make_table() {
                        return Res::Failed;
                    }
                    self.loop_ = 0;
                    self.state = ST_RD_PRE_LENGTH_TREE;
                }
                ST_RD_PRE_LENGTH_TREE => {
                    if !self.read_pre_tree(io) {
                        need!();
                    }
                    if !self.pt.make_table() {
                        return Res::Failed;
                    }
                    self.loop_ = 0;
                    self.state = ST_LENGTH_TREE;
                }
                ST_LENGTH_TREE => {
                    match self.read_bitlen(io, Tree::Length, 0) {
                        Res::Eof => need!(),
                        Res::Ok => {}
                        _ => return Res::Failed,
                    }
                    if !self.lt.make_table() {
                        return Res::Failed;
                    }
                    self.state = ST_MAIN;
                    return Res::Cont;
                }
                _ => return Res::Failed,
            }
        }
    }

    /// Reads the pre-tree's 4-bit lengths; false if the input ran out.
    fn read_pre_tree(&mut self, io: &mut Io) -> bool {
        if self.loop_ == 0 {
            self.pt.freq = [0; 17];
        }
        let mut i = self.loop_;
        while i < self.pt.symbol_count {
            if !self.br.read_ahead(io, 4) {
                self.loop_ = i;
                return false;
            }
            let len = self.br.bits(4) as u8;
            if let Some(b) = self.pt.bitlen.get_mut(usize::from(i)) {
                *b = len;
            }
            self.pt.freq[usize::from(len)] += 1;
            self.br.consume(4);
            i += 1;
        }
        self.loop_ = i;
        true
    }

    /// Reads a bunch of bit lengths of `tree` through the pre-tree: `Eof`
    /// if the input ran out, `Failed` if they are invalid.
    fn read_bitlen(&mut self, io: &mut Io, which: Tree, end: u16) -> Res {
        let mut d = std::mem::take(match which {
            Tree::Main => &mut self.mt,
            Tree::Length => &mut self.lt,
        });
        let r = self.read_bitlen_of(io, &mut d, end);
        match which {
            Tree::Main => self.mt = d,
            Tree::Length => self.lt = d,
        }
        r
    }

    fn read_bitlen_of(&mut self, io: &mut Io, d: &mut Huffman, end: u16) -> Res {
        let mut i = self.loop_;
        if i == 0 {
            d.freq = [0; 17];
        }
        let end = if end == 0 { d.symbol_count } else { end };
        let lookup = usize::from(self.pt.lookup_bits);
        let ret = 'run: {
            while i < end {
                self.loop_ = i;
                if !self.br.read_ahead(io, lookup) {
                    break 'run Res::Eof;
                }
                let mut c = self.pt.decode(self.br.bits(lookup));
                let at = usize::from(i);
                let old = i32::from(d.bitlen.get(at).copied().unwrap_or(0));
                match c {
                    // 17: several zero lengths, from 4 to 19. 18: many zero
                    // lengths, from 20 to 51.
                    17 | 18 => {
                        let (extra, min) = if c == 17 { (4, 4) } else { (5, 20) };
                        if !self.br.read_ahead(io, self.pt.bitlen(c) + extra) {
                            break 'run Res::Eof;
                        }
                        self.br.consume(self.pt.bitlen(c));
                        let same = self.br.bits(extra) as u16 + min;
                        if same > end - i {
                            return Res::Failed;
                        }
                        self.br.consume(extra);
                        if let Some(zeros) = d.bitlen.get_mut(at..at + usize::from(same)) {
                            zeros.fill(0);
                        }
                        i += same;
                    }
                    // A few same lengths.
                    19 => {
                        if !self.br.read_ahead(io, self.pt.bitlen(c) + 1 + lookup) {
                            break 'run Res::Eof;
                        }
                        self.br.consume(self.pt.bitlen(c));
                        let same = self.br.bits(1) as u16 + 4;
                        if same > end - i {
                            return Res::Failed;
                        }
                        self.br.consume(1);
                        c = self.pt.decode(self.br.bits(lookup));
                        self.br.consume(self.pt.bitlen(c));
                        if i32::from(c) > old + 17 {
                            return Res::Failed;
                        }
                        let len = ((old + 17 - i32::from(c)) % 17) as u8;
                        if let Some(run) = d.bitlen.get_mut(at..at + usize::from(same)) {
                            run.fill(len);
                        }
                        i += same;
                        d.freq[usize::from(len)] += same;
                    }
                    _ => {
                        self.br.consume(self.pt.bitlen(c));
                        if i32::from(c) > old + 17 {
                            return Res::Failed;
                        }
                        let len = ((old + 17 - i32::from(c)) % 17) as u8;
                        d.freq[usize::from(len)] += 1;
                        if let Some(b) = d.bitlen.get_mut(at) {
                            *b = len;
                        }
                        i += 1;
                    }
                }
            }
            Res::Ok
        };
        self.loop_ = i;
        ret
    }

    /// Decodes the symbols of a compressed block into the output.
    fn decode_blocks(&mut self, io: &mut Io, last: bool) -> Res {
        let mut bre = self.br;
        let mut block_bytes_avail = self.block_bytes_avail;
        let mut copy_len = self.copy_len;
        let mut copy_pos = self.copy_pos;
        let mut w_pos = self.w_pos;
        let (w_mask, w_size) = (self.w_mask, self.w_size);
        let mut w_filled = self.w_filled;
        let mut length_header = self.length_header;
        let mut offset_bits = self.offset_bits;
        let mut position_slot = self.position_slot;
        let (mut r0, mut r1, mut r2) = (self.r0, self.r1, self.r2);
        let mut state = self.state;
        let block_type = self.block_type;
        let (at_lookup, lt_lookup, mt_lookup) = (
            usize::from(self.at.lookup_bits),
            usize::from(self.lt.lookup_bits),
            usize::from(self.mt.lookup_bits),
        );

        // Out of input or output: save the state and return.
        macro_rules! next_data {
            () => {{
                self.br = bre;
                self.block_bytes_avail = block_bytes_avail;
                self.copy_len = copy_len;
                self.copy_pos = copy_pos;
                self.length_header = length_header;
                self.offset_bits = offset_bits;
                self.position_slot = position_slot;
                self.r0 = r0;
                self.r1 = r1;
                self.r2 = r2;
                self.state = state;
                self.w_pos = w_pos;
                self.w_filled = w_filled;
                return Res::Ok;
            }};
        }
        // Decodes one symbol of `$tree`: from the cache if it `$enough`, else
        // (at the end of the data) from the bits that are left, padded with
        // zeros.
        macro_rules! symbol {
            ($tree:expr, $lookup:expr, $enough:expr) => {{
                if $enough {
                    let c = $tree.decode(bre.bits($lookup));
                    bre.consume($tree.bitlen(c));
                    c
                } else {
                    let c = $tree.decode(bre.bits_forced($lookup));
                    if !bre.has($tree.bitlen(c)) {
                        return Res::Failed; // Over read.
                    }
                    bre.consume($tree.bitlen(c));
                    c
                }
            }};
        }

        loop {
            match state {
                ST_MAIN => {
                    let c = loop {
                        if block_bytes_avail == 0 {
                            // This block ended.
                            self.state = ST_RD_BLOCK_TYPE;
                            self.br = bre;
                            self.block_bytes_avail = block_bytes_avail;
                            self.copy_len = copy_len;
                            self.copy_pos = copy_pos;
                            self.length_header = length_header;
                            self.position_slot = position_slot;
                            self.r0 = r0;
                            self.r1 = r1;
                            self.r2 = r2;
                            self.w_pos = w_pos;
                            self.w_filled = w_filled;
                            return Res::Eof;
                        }
                        if io.out_left() == 0 {
                            next_data!();
                        }
                        let enough = bre.read_ahead(io, mt_lookup);
                        if !enough && !last {
                            next_data!();
                        }
                        // The remaining bits are fewer than the maximum code
                        // length but may still hold the code: try them with
                        // dummy bits.
                        let c = symbol!(self.mt, mt_lookup, enough);
                        if c > 255 {
                            break c;
                        }
                        // 'c' is exactly a literal code. Save it to
                        // reference it afterward.
                        if let Some(w) = self.w_buff.get_mut(w_pos) {
                            *w = c as u8;
                        }
                        w_pos = (w_pos + 1) & w_mask;
                        if w_filled < w_size {
                            w_filled += 1;
                        }
                        if let Some(o) = io.out.get_mut(io.out_pos) {
                            *o = c as u8;
                        }
                        io.out_pos += 1;
                        block_bytes_avail -= 1;
                    };
                    // Get a match code, its length and offset.
                    let c = c - 256;
                    length_header = (c & 7) as u8;
                    position_slot = c >> 3;
                    state = ST_LENGTH;
                }
                ST_LENGTH => {
                    // Get a length.
                    if length_header == 7 {
                        let enough = bre.read_ahead(io, lt_lookup);
                        if !enough && !last {
                            next_data!();
                        }
                        let c = symbol!(self.lt, lt_lookup, enough);
                        copy_len = usize::from(c) + 7 + 2;
                    } else {
                        copy_len = usize::from(length_header) + 2;
                    }
                    if copy_len > block_bytes_avail {
                        return Res::Failed;
                    }
                    // Get an offset.
                    match position_slot {
                        // Use the repeated offsets.
                        0 => {
                            copy_pos = r0;
                            state = ST_REAL_POS;
                        }
                        1 => {
                            copy_pos = r1;
                            r1 = r0;
                            r0 = copy_pos;
                            state = ST_REAL_POS;
                        }
                        2 => {
                            copy_pos = r2;
                            r2 = r0;
                            r0 = copy_pos;
                            state = ST_REAL_POS;
                        }
                        _ => {
                            let Some(slot) = self.pos_tbl.get(usize::from(position_slot)) else {
                                return Res::Failed;
                            };
                            offset_bits = slot.footer_bits;
                            state = ST_OFFSET;
                        }
                    }
                }
                ST_OFFSET => {
                    // Get the offset, a distance from the current window
                    // position.
                    let ob = usize::from(offset_bits);
                    if block_type == ALIGNED_OFFSET_BLOCK && ob >= 3 {
                        let offbits = ob - 3;
                        if !bre.read_ahead(io, offbits) {
                            if last {
                                return Res::Failed;
                            }
                            next_data!();
                        }
                        copy_pos = (bre.bits(offbits) as usize) << 3;

                        // Get an aligned number.
                        let enough = bre.read_ahead(io, offbits + at_lookup);
                        if !enough && !last {
                            next_data!();
                        }
                        bre.consume(offbits);
                        let c = symbol!(self.at, at_lookup, enough);
                        // Add the aligned number.
                        copy_pos += usize::from(c);
                    } else {
                        if !bre.read_ahead(io, ob) {
                            if last {
                                return Res::Failed;
                            }
                            next_data!();
                        }
                        copy_pos = bre.bits(ob) as usize;
                        bre.consume(ob);
                    }
                    let Some(slot) = self.pos_tbl.get(usize::from(position_slot)) else {
                        return Res::Failed;
                    };
                    copy_pos += slot.base.saturating_sub(2) as usize;

                    // Update the repeated offset LRU queue.
                    r2 = r1;
                    r1 = r0;
                    r0 = copy_pos;
                    state = ST_REAL_POS;
                }
                ST_REAL_POS => {
                    // Compute a real position in the window.
                    if copy_pos == 0 || copy_pos > w_filled {
                        return Res::Failed;
                    }
                    copy_pos = w_pos.wrapping_sub(copy_pos) & w_mask;
                    state = ST_COPY;
                }
                ST_COPY => {
                    // Copy several bytes of extracted data from the window
                    // into the output.
                    loop {
                        let mut l = copy_len;
                        if copy_pos > w_pos {
                            l = l.min(w_size - copy_pos);
                        } else {
                            l = l.min(w_size - w_pos);
                        }
                        l = l.min(io.out_left());
                        for li in 0..l {
                            let Some(&b) = self.w_buff.get(copy_pos + li) else {
                                return Res::Failed;
                            };
                            if let Some(w) = self.w_buff.get_mut(w_pos + li) {
                                *w = b;
                            }
                            if let Some(o) = io.out.get_mut(io.out_pos + li) {
                                *o = b;
                            }
                        }
                        io.out_pos += l;
                        copy_pos = (copy_pos + l) & w_mask;
                        w_pos = (w_pos + l) & w_mask;
                        if w_filled < w_size {
                            w_filled = (w_filled + l).min(w_size);
                        }
                        block_bytes_avail = block_bytes_avail.saturating_sub(l);
                        if copy_len <= l {
                            // A copy of the current pattern ended.
                            break;
                        }
                        copy_len -= l;
                        if io.out_left() == 0 {
                            state = ST_COPY;
                            next_data!();
                        }
                    }
                    state = ST_MAIN;
                }
                _ => return Res::Failed,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_bits_are_15_to_21() {
        assert!(Lzx::new(14).is_none());
        assert!(Lzx::new(22).is_none());
        assert!(Lzx::new(0x1500).is_none());
        for bits in 15..=21 {
            assert!(Lzx::new(bits).is_some());
        }
    }

    #[test]
    fn position_slots_follow_the_footer_bits() {
        let lzx = Lzx::new(15).unwrap();
        let slots: Vec<_> = lzx
            .pos_tbl
            .iter()
            .map(|s| (s.base, s.footer_bits))
            .collect();
        assert_eq!(slots.len(), 30);
        assert_eq!(
            &slots[..8],
            &[
                (0, 0),
                (1, 0),
                (2, 0),
                (3, 0),
                (4, 1),
                (6, 1),
                (8, 2),
                (12, 2)
            ]
        );
        assert_eq!(slots[29], (24576, 13));
        let big = Lzx::new(21).unwrap();
        assert_eq!(big.pos_tbl.len(), 50);
        assert_eq!(
            (big.pos_tbl[49].base, big.pos_tbl[49].footer_bits),
            (1_966_080, 17)
        );
    }

    #[test]
    fn huffman_table_spans_short_codes() {
        // A: 0b0, B: 0b10, C: 0b11.
        let mut h = Huffman::new(3, 4);
        h.bitlen = vec![1, 2, 2];
        h.freq[1] = 1;
        h.freq[2] = 2;
        assert!(h.make_table());
        assert_eq!(h.lookup_bits, 2);
        assert_eq!(&h.tbl[..4], &[0, 0, 1, 2]);
    }

    #[test]
    fn huffman_table_rejects_incomplete_and_oversubscribed_codes() {
        let mut h = Huffman::new(3, 4);
        h.bitlen = vec![1, 2, 0];
        h.freq[1] = 1;
        h.freq[2] = 1;
        assert!(!h.make_table());
        h.bitlen = vec![1, 1, 1];
        h.freq = [0; 17];
        h.freq[1] = 3;
        assert!(!h.make_table());
        // No codes at all is accepted, as upstream does.
        h.bitlen = vec![0; 3];
        h.freq = [0; 17];
        assert!(h.make_table());
        assert_eq!(h.lookup_bits, 0);
    }

    #[test]
    fn e8_calls_are_translated_back() {
        let mut lzx = Lzx::new(15).unwrap();
        lzx.translation = true;
        lzx.translation_size = 1000;
        let mut buf = [0u8; 16];
        buf[2] = 0xE8;
        buf[3..7].copy_from_slice(&105i32.to_le_bytes());
        lzx.translation(&mut buf, 0);
        // Absolute address 105 at position 2 becomes relative 103.
        assert_eq!(i32::from_le_bytes([buf[3], buf[4], buf[5], buf[6]]), 103);
        // Too short buffers and far offsets are left alone.
        let mut short = [0xE8; 10];
        lzx.translation(&mut short, 0);
        assert_eq!(short, [0xE8; 10]);
        let mut far = buf;
        lzx.translation(&mut far, 0x8000 * 0x8000);
        assert_eq!(far, buf);
    }

    /// Whatever the bytes and however they are cut, the decoder fails or
    /// asks for more; it never panics or writes outside the output.
    #[test]
    fn corrupt_input_does_not_panic() {
        let mut seed = 0x1234_5678_u32;
        let mut next = move || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (seed >> 16) as u8
        };
        for round in 0..400 {
            let n = 1 + usize::from(next()) * 3;
            let mut data: Vec<u8> = (0..n).map(|_| next()).collect();
            // Make the early bits plausible: no E8 header, a verbatim block.
            if round % 2 == 0 {
                data[0] &= 0x7f;
            }
            let mut lzx = Lzx::new(15 + (round % 7) as u16).unwrap();
            let mut out = vec![0u8; 0x8000];
            let chunk = 1 + usize::from(next()) % 40;
            let mut written = 0;
            for piece in data.chunks(chunk) {
                let d = lzx.decode(piece, &mut out[written..], false);
                written += d.written;
                assert!(written <= out.len());
                if d.status == Status::Failed {
                    break;
                }
            }
            let d = lzx.decode(&[], &mut out[written..], true);
            assert!(written + d.written <= out.len());
        }
    }
}
