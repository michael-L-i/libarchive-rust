/*-
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

// Ported from libarchive/archive_read_support_format_7zip.c.

//! The branch converters (BCJ), BCJ2 and Delta filters. Upstream brought
//! them from the LZMA SDK (public domain) and xz-embedded (public domain, or
//! 0BSD, or the XZ Utils permission notice, as noted there) and runs them
//! over the decoder's output a buffer at a time. A converter returns how
//! many bytes it finished; the caller keeps the rest, which it could not
//! convert without more data, for the next call.
//!
//! Upstream gives the branch filters of an LZMA2 coder to liblzma instead;
//! `lzma-rust2`'s stream filters are used for that, with the same protocol.

use super::{CODEC_ARM, CODEC_ARM64, CODEC_ARMTHUMB, CODEC_IA64};
use super::{CODEC_POWERPC, CODEC_RISCV, CODEC_SPARC, CODEC_X86};
use lzma_rust2::filter::StreamFilter;
use lzma_rust2::{FilterConfig, FilterType};

/// The widest instruction the BCJ filters rewrite, and the smallest output
/// buffer that those filters can make progress with. Filters leave up to one
/// byte less than this unconverted at the end of a buffer (when they don't
/// have enough data to continue). Returns 0 for codecs we do not filter
/// ourselves.
pub(super) fn bcj_lookahead(codec2: i64) -> usize {
    match codec2 {
        CODEC_X86 => 5,
        CODEC_RISCV => 8,
        CODEC_IA64 => 16,
        CODEC_ARM | CODEC_ARMTHUMB | CODEC_ARM64 | CODEC_POWERPC | CODEC_SPARC => 4,
        _ => 0,
    }
}

/// The state of the BCJ and Delta converters.
pub(super) struct Filters {
    pub bcj_ip: u32,
    prev_pos_t: usize,
    prev_mask: u32,
    delta_dist: u32,
    delta_pos: u8,
    delta_history: [u8; 256],
    /// Bytes that a converter didn't have enough lookahead to transform yet,
    /// or that BCJ2 could not fit in the output. Big enough to hold the
    /// largest lookahead (IA64).
    pub odd_bcj: [u8; 16],
    /// Number of bytes currently stashed in `odd_bcj`.
    pub odd_bcj_size: usize,
    /// The branch filter of an LZMA2 coder, which liblzma runs upstream.
    xz: Option<StreamFilter>,
}

impl Default for Filters {
    fn default() -> Self {
        Filters {
            bcj_ip: 0,
            prev_pos_t: 0,
            prev_mask: 0,
            delta_dist: 0,
            delta_pos: 0,
            delta_history: [0; 256],
            odd_bcj: [0; 16],
            odd_bcj_size: 0,
            xz: None,
        }
    }
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

impl Filters {
    /// `x86_Init`.
    pub fn x86_init(&mut self) {
        self.prev_pos_t = usize::MAX;
        self.prev_mask = 0;
        self.bcj_ip = 5;
    }

    /// `arm_Init`.
    pub fn arm_init(&mut self) {
        self.bcj_ip = 8;
    }

    /// `armthumb_Init`.
    pub fn armthumb_init(&mut self) {
        self.bcj_ip = 4;
    }

    /// `delta_Init`.
    pub fn delta_init(&mut self, dist: u32) {
        self.delta_dist = dist;
        self.delta_pos = 0;
        self.delta_history = [0; 256];
    }

    /// Sets up (`lzma2`) or drops the branch filter that goes with an LZMA2
    /// coder. `None` if there is no such filter for `codec2`.
    pub fn set_lzma2_filter(&mut self, codec2: Option<i64>) -> Option<()> {
        let cfg = match codec2 {
            None => {
                self.xz = None;
                return Some(());
            }
            Some(CODEC_X86) => FilterType::BcjX86,
            Some(CODEC_ARM) => FilterType::BcjArm,
            Some(CODEC_ARMTHUMB) => FilterType::BcjArmThumb,
            Some(CODEC_ARM64) => FilterType::BcjArm64,
            Some(CODEC_SPARC) => FilterType::BcjSparc,
            Some(CODEC_POWERPC) => FilterType::BcjPpc,
            Some(CODEC_RISCV) => FilterType::BcjRiscv,
            Some(CODEC_IA64) => FilterType::BcjIa64,
            Some(_) => return None,
        };
        let cfg = FilterConfig {
            filter_type: cfg,
            property: 0,
        };
        self.xz = Some(StreamFilter::new(&cfg).ok()?);
        Some(())
    }

    /// Runs the converter for `codec2` over `buf`; returns how many bytes it
    /// converted.
    pub fn convert(&mut self, codec2: i64, buf: &mut [u8]) -> Option<usize> {
        if let Some(xz) = &mut self.xz {
            return Some(xz.decode(buf));
        }
        Some(match codec2 {
            CODEC_X86 => self.x86_convert(buf),
            CODEC_ARM => self.arm_convert(buf),
            CODEC_ARMTHUMB => self.armthumb_convert(buf),
            CODEC_ARM64 => self.arm64_convert(buf),
            CODEC_SPARC => self.sparc_convert(buf),
            CODEC_POWERPC => self.powerpc_convert(buf),
            CODEC_RISCV => self.riscv_convert(buf),
            CODEC_IA64 => self.ia64_convert(buf),
            _ => return None,
        })
    }

    /// Bra86.c -- Converter for x86 code (BCJ). 2008-10-04 : Igor Pavlov :
    /// Public domain.
    fn x86_convert(&mut self, data: &mut [u8]) -> usize {
        const MASK_TO_ALLOWED_STATUS: [bool; 8] =
            [true, true, true, false, true, false, false, false];
        const MASK_TO_BIT_NUMBER: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];
        fn test_ms_byte(b: u8) -> bool {
            b == 0 || b == 0xFF
        }

        let size = data.len();
        if size < 5 {
            return 0;
        }
        let mut buffer_pos = 0usize;
        let mut prev_pos_t = self.prev_pos_t;
        let mut prev_mask = self.prev_mask;
        let ip = self.bcj_ip;
        let limit = size - 4;

        loop {
            let mut p = buffer_pos;
            while p < limit && data[p] & 0xFE != 0xE8 {
                p += 1;
            }
            buffer_pos = p;
            if p >= limit {
                break;
            }
            prev_pos_t = buffer_pos.wrapping_sub(prev_pos_t);
            if prev_pos_t == 0 || prev_pos_t > 3 {
                prev_mask = 0;
            } else {
                prev_mask = (prev_mask << (prev_pos_t - 1)) & 0x7;
                if prev_mask != 0 {
                    let b = data[p + 4 - MASK_TO_BIT_NUMBER[prev_mask as usize] as usize];
                    if !MASK_TO_ALLOWED_STATUS[prev_mask as usize] || test_ms_byte(b) {
                        prev_pos_t = buffer_pos;
                        prev_mask = ((prev_mask << 1) & 0x7) | 1;
                        buffer_pos += 1;
                        continue;
                    }
                }
            }
            prev_pos_t = buffer_pos;

            if test_ms_byte(data[p + 4]) {
                let mut src = le32(&data[p + 1..]);
                let mut dest;
                loop {
                    dest = src.wrapping_sub(ip.wrapping_add(buffer_pos as u32));
                    if prev_mask == 0 {
                        break;
                    }
                    let b_index = MASK_TO_BIT_NUMBER[prev_mask as usize] * 8;
                    let b = (dest >> (24 - b_index)) as u8;
                    if !test_ms_byte(b) {
                        break;
                    }
                    src = dest ^ ((1u32 << (32 - b_index)) - 1);
                }
                data[p + 4] = !((dest >> 24) & 1).wrapping_sub(1) as u8;
                data[p + 3] = (dest >> 16) as u8;
                data[p + 2] = (dest >> 8) as u8;
                data[p + 1] = dest as u8;
                buffer_pos += 5;
            } else {
                prev_mask = ((prev_mask << 1) & 0x7) | 1;
                buffer_pos += 1;
            }
        }
        self.prev_pos_t = prev_pos_t;
        self.prev_mask = prev_mask;
        self.bcj_ip = self.bcj_ip.wrapping_add(buffer_pos as u32);
        buffer_pos
    }

    /// Adapted from `bcj_arm` in xz-embedded (public domain).
    fn arm_convert(&mut self, buf: &mut [u8]) -> usize {
        let mut i = 0;
        while i + 4 <= buf.len() {
            if buf[i + 3] == 0xEB {
                let mut addr = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], 0]);
                addr <<= 2;
                addr = addr.wrapping_sub(self.bcj_ip.wrapping_add(i as u32));
                addr >>= 2;
                buf[i..i + 3].copy_from_slice(&addr.to_le_bytes()[..3]);
            }
            i += 4;
        }
        self.bcj_ip = self.bcj_ip.wrapping_add(i as u32);
        i
    }

    /// Adapted from `bcj_armthumb` in xz-embedded (0BSD).
    fn armthumb_convert(&mut self, buf: &mut [u8]) -> usize {
        let mut i = 0;
        while i + 4 <= buf.len() {
            if (buf[i + 1] & 0xF8) == 0xF0 && (buf[i + 3] & 0xF8) == 0xF8 {
                let mut addr = ((u32::from(buf[i + 1]) & 0x07) << 19)
                    | (u32::from(buf[i]) << 11)
                    | ((u32::from(buf[i + 3]) & 0x07) << 8)
                    | u32::from(buf[i + 2]);
                addr <<= 1;
                addr = addr.wrapping_sub(self.bcj_ip.wrapping_add(i as u32));
                addr >>= 1;
                buf[i + 1] = 0xF0 | ((addr >> 19) & 0x07) as u8;
                buf[i] = (addr >> 11) as u8;
                buf[i + 3] = 0xF8 | ((addr >> 8) & 0x07) as u8;
                buf[i + 2] = addr as u8;
                i += 2;
            }
            i += 2;
        }
        self.bcj_ip = self.bcj_ip.wrapping_add(i as u32);
        i
    }

    /// Adapted from `bcj_arm64` in xz-embedded (public domain).
    fn arm64_convert(&mut self, buf: &mut [u8]) -> usize {
        let mut i = 0;
        while i + 4 <= buf.len() {
            let mut instr = le32(&buf[i..]);
            if (instr >> 26) == 0x25 {
                // BL instruction.
                let addr = instr.wrapping_sub(self.bcj_ip.wrapping_add(i as u32) >> 2);
                instr = 0x9400_0000 | (addr & 0x03FF_FFFF);
                buf[i..i + 4].copy_from_slice(&instr.to_le_bytes());
            } else if (instr & 0x9F00_0000) == 0x9000_0000 {
                // ADRP instruction.
                let mut addr = ((instr >> 29) & 3) | ((instr >> 3) & 0x1F_FFFC);
                // Only convert values in the range +/-512 MiB.
                if (addr.wrapping_add(0x02_0000)) & 0x1C_0000 == 0 {
                    addr = addr.wrapping_sub(self.bcj_ip.wrapping_add(i as u32) >> 12);
                    instr &= 0x9000_001F;
                    instr |= (addr & 3) << 29;
                    instr |= (addr & 0x03_FFFC) << 3;
                    instr |= (0u32.wrapping_sub(addr & 0x02_0000)) & 0xE0_0000;
                    buf[i..i + 4].copy_from_slice(&instr.to_le_bytes());
                }
            }
            i += 4;
        }
        self.bcj_ip = self.bcj_ip.wrapping_add(i as u32);
        i
    }

    /// Adapted from `bcj_sparc` in xz-embedded (XZ Utils permission notice).
    fn sparc_convert(&mut self, buf: &mut [u8]) -> usize {
        let size = buf.len() & !3;
        let mut i = 0;
        while i < size {
            let mut instr = be32(&buf[i..]);
            if (instr >> 22) == 0x100 || (instr >> 22) == 0x1FF {
                instr <<= 2;
                instr = instr.wrapping_sub(self.bcj_ip.wrapping_add(i as u32));
                instr >>= 2;
                instr = 0x4000_0000u32.wrapping_sub(instr & 0x40_0000)
                    | 0x4000_0000
                    | (instr & 0x3F_FFFF);
                buf[i..i + 4].copy_from_slice(&instr.to_be_bytes());
            }
            i += 4;
        }
        self.bcj_ip = self.bcj_ip.wrapping_add(i as u32);
        i
    }

    /// Adapted from `powerpc_code` in XZ Utils (XZ Utils permission notice).
    fn powerpc_convert(&mut self, buf: &mut [u8]) -> usize {
        let size = buf.len() & !3;
        let mut i = 0;
        while i < size {
            // PowerPC branch 6(48) 24(Offset) 1(Abs) 1(Link)
            if (buf[i] >> 2) == 0x12 && (buf[i + 3] & 3) == 1 {
                let src = ((u32::from(buf[i]) & 3) << 24)
                    | (u32::from(buf[i + 1]) << 16)
                    | (u32::from(buf[i + 2]) << 8)
                    | (u32::from(buf[i + 3]) & !3u32);
                let dest = src.wrapping_sub(self.bcj_ip.wrapping_add(i as u32));
                buf[i] = 0x48 | ((dest >> 24) & 0x03) as u8;
                buf[i + 1] = (dest >> 16) as u8;
                buf[i + 2] = (dest >> 8) as u8;
                buf[i + 3] &= 0x03;
                buf[i + 3] |= dest as u8;
            }
            i += 4;
        }
        self.bcj_ip = self.bcj_ip.wrapping_add(i as u32);
        i
    }

    /// Adapted from `bcj_riscv` in xz-embedded (0BSD).
    fn riscv_convert(&mut self, buf: &mut [u8]) -> usize {
        if buf.len() < 8 {
            return 0;
        }
        let size = buf.len() - 8;
        let mut i = 0;
        while i <= size {
            let mut inst = u32::from(buf[i]);

            if inst == 0xEF {
                // JAL. Only filter rd=x1(ra) and rd=x5(t0).
                let b1 = u32::from(buf[i + 1]);
                if (b1 & 0x0D) != 0 {
                    i += 2;
                    continue;
                }
                let b2 = u32::from(buf[i + 2]);
                let b3 = u32::from(buf[i + 3]);

                let mut addr = ((b1 & 0xF0) << 13) | (b2 << 9) | (b3 << 1);
                addr = addr.wrapping_sub(self.bcj_ip.wrapping_add(i as u32));

                buf[i + 1] = ((b1 & 0x0F) | ((addr >> 8) & 0xF0)) as u8;
                buf[i + 2] =
                    (((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0)) as u8;
                buf[i + 3] = (((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80)) as u8;

                i += 4;
            } else if (inst & 0x7F) == 0x17 {
                // AUIPC, paired with a second instruction (inst2) that is
                // within the next four bytes.
                let mut inst2;

                inst |= u32::from(buf[i + 1]) << 8;
                inst |= u32::from(buf[i + 2]) << 16;
                inst |= u32::from(buf[i + 3]) << 24;

                if inst & 0xE80 != 0 {
                    // AUIPC's rd doesn't equal x0 or x2.
                    inst2 = le32(&buf[i + 4..]);

                    if ((inst << 8) ^ inst2.wrapping_sub(3)) & 0xF8003 != 0 {
                        i += 6;
                        continue;
                    }

                    let addr = (inst & 0xFFFF_F000).wrapping_add(inst2 >> 20);

                    inst = 0x17 | (2 << 7) | (inst2 << 12);
                    inst2 = addr;
                } else {
                    // AUIPC's rd equals x0 or x2.
                    let inst2_rs1 = inst >> 27;

                    if inst.wrapping_sub(0x3117) << 18 >= (inst2_rs1 & 0x1D) {
                        i += 4;
                        continue;
                    }

                    let mut addr = be32(&buf[i + 4..]);
                    addr = addr.wrapping_sub(self.bcj_ip.wrapping_add(i as u32));

                    inst2 = (inst >> 12) | (addr << 20);
                    inst = 0x17 | (inst2_rs1 << 7) | (addr.wrapping_add(0x800) & 0xFFFF_F000);
                }

                buf[i..i + 4].copy_from_slice(&inst.to_le_bytes());
                buf[i + 4..i + 8].copy_from_slice(&inst2.to_le_bytes());

                i += 8;
            } else {
                i += 2;
            }
        }
        self.bcj_ip = self.bcj_ip.wrapping_add(i as u32);
        i
    }

    /// Adapted from `bcj_ia64` in xz-embedded (0BSD).
    fn ia64_convert(&mut self, buf: &mut [u8]) -> usize {
        const BRANCH_TABLE: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4,
            4, 0, 0,
        ];

        let size = buf.len() & !15;
        let mut i = 0;
        while i < size {
            let mask = u32::from(BRANCH_TABLE[usize::from(buf[i] & 0x1F)]);
            let mut bit_pos = 5u32;
            for slot in 0..3 {
                if (mask >> slot) & 1 != 0 {
                    let byte_pos = (bit_pos >> 3) as usize;
                    let bit_res = bit_pos & 7;
                    let mut instr = 0u64;
                    for j in 0..6 {
                        instr |= u64::from(buf[i + j + byte_pos]) << (8 * j);
                    }

                    let mut norm = instr >> bit_res;

                    if ((norm >> 37) & 0x0F) == 0x05 && ((norm >> 9) & 0x07) == 0 {
                        let mut addr = ((norm >> 13) & 0x0F_FFFF) as u32;
                        addr |= (((norm >> 36) & 1) as u32) << 20;
                        addr <<= 4;
                        addr = addr.wrapping_sub(self.bcj_ip.wrapping_add(i as u32));
                        addr >>= 4;

                        norm &= !(0x8F_FFFFu64 << 13);
                        norm |= u64::from(addr & 0x0F_FFFF) << 13;
                        norm |= u64::from(addr & 0x10_0000) << (36 - 20);

                        instr &= (1u64 << bit_res) - 1;
                        instr |= norm << bit_res;

                        for j in 0..6 {
                            buf[i + j + byte_pos] = (instr >> (8 * j)) as u8;
                        }
                    }
                }
                bit_pos += 41;
            }
            i += 16;
        }
        self.bcj_ip = self.bcj_ip.wrapping_add(i as u32);
        i
    }

    /// Adapted from `decode_buffer` in liblzma's delta decoder (0BSD).
    pub fn delta_decode(&mut self, buf: &mut [u8]) {
        for b in buf {
            let hist = self.delta_history
                [((self.delta_dist.wrapping_add(u32::from(self.delta_pos))) & 0xFF) as usize];
            *b = b.wrapping_add(hist);
            self.delta_history[usize::from(self.delta_pos)] = *b;
            self.delta_pos = self.delta_pos.wrapping_sub(1);
        }
    }
}

/// The BCJ2 decoder (Bcj2.c, 2008-10-04 : Igor Pavlov : Public domain).
pub(super) struct Bcj2 {
    /// 0 until the range coder is initialized (`bcj_state`), then 1, or 2
    /// right after a jump opcode was copied out.
    state: u8,
    prev_byte: u8,
    probs: [u16; 256 + 2],
    range: u32,
    code: u32,
    /// Bytes of output so far, for the relative addresses.
    out_pos: usize,
    /// The three decoded sub streams (call, jump, range coder) and how
    /// much of each is left.
    pub streams: [Vec<u8>; 3],
    pub remaining: [usize; 3],
    /// The decoded main stream is in `tmp`; `tmp_avail` bytes of it are
    /// valid and `tmp_remaining` of those are not yet used.
    pub tmp: Vec<u8>,
    pub tmp_avail: usize,
    pub tmp_remaining: usize,
}

impl Default for Bcj2 {
    fn default() -> Self {
        Bcj2 {
            state: 0,
            prev_byte: 0,
            probs: [0; 258],
            range: 0,
            code: 0,
            out_pos: 0,
            streams: [Vec::new(), Vec::new(), Vec::new()],
            remaining: [0; 3],
            tmp: Vec::new(),
            tmp_avail: 0,
            tmp_remaining: 0,
        }
    }
}

const K_TOP_VALUE: u32 = 1 << 24;
const K_NUM_BIT_MODEL_TOTAL_BITS: u32 = 11;
const K_BIT_MODEL_TOTAL: u32 = 1 << K_NUM_BIT_MODEL_TOTAL_BITS;
const K_NUM_MOVE_BITS: u32 = 5;

fn is_j(b0: u8, b1: u8) -> bool {
    (b1 & 0xFE) == 0xE8 || (b0 == 0x0F && (b1 & 0xF0) == 0x80)
}

impl Bcj2 {
    /// Starts a new folder: `bcj_state = 0`.
    pub fn reset(&mut self) {
        self.state = 0;
    }

    /// Starts the main stream of a folder: nothing decoded yet.
    pub fn start(&mut self) {
        self.tmp_avail = 0;
        self.tmp_remaining = 0;
        self.out_pos = 0;
    }

    /// Hands out the decoded sub streams in the order BCJ2 reads them.
    pub fn set_streams(&mut self, streams: [Vec<u8>; 3]) {
        self.remaining = streams.each_ref().map(Vec::len);
        self.streams = streams;
    }

    /// `Bcj2_Decode`: decodes the main stream's remaining bytes into `out`
    /// and returns how many it wrote. `Err` is `SZ_ERROR_DATA`.
    pub fn decode(&mut self, odd: &mut Filters, out: &mut [u8]) -> Result<usize, ()> {
        let out_size = out.len();
        let mut in_pos = 0usize;
        let mut out_pos = 0usize;

        let size0 = self.tmp_remaining;
        let base0 = self.tmp_avail.checked_sub(size0).ok_or(())?;
        let mut size1 = self.remaining[0];
        let mut pos1 = self.streams[0].len().checked_sub(size1).ok_or(())?;
        let mut size2 = self.remaining[1];
        let mut pos2 = self.streams[1].len().checked_sub(size2).ok_or(())?;
        let lim3 = self.streams[2].len();
        let mut pos3 = lim3.checked_sub(self.remaining[2]).ok_or(())?;

        // One byte of the range coder's stream, or the end of it.
        macro_rules! rc_byte {
            () => {{
                let Some(&b) = self.streams[2].get(pos3) else {
                    return Err(());
                };
                pos3 += 1;
                b
            }};
        }
        macro_rules! normalize {
            () => {
                if self.range < K_TOP_VALUE {
                    let b = rc_byte!();
                    self.range <<= 8;
                    self.code = (self.code << 8) | u32::from(b);
                }
            };
        }

        if self.state == 0 {
            self.prev_byte = 0;
            self.probs.fill((K_BIT_MODEL_TOTAL >> 1) as u16);
            self.code = 0;
            self.range = 0xFFFF_FFFF;
            for _ in 0..5 {
                let b = rc_byte!();
                self.code = (self.code << 8) | u32::from(b);
            }
            self.state = 1;
        }

        // Gather the odd bytes of a previous call.
        let mut i = 0;
        while odd.odd_bcj_size > 0 && out_pos < out_size {
            out[out_pos] = odd.odd_bcj[i];
            out_pos += 1;
            odd.odd_bcj_size -= 1;
            i += 1;
        }

        if out_size == 0 {
            self.out_pos += out_pos;
            return Ok(out_pos);
        }

        loop {
            let mut limit = (size0 - in_pos).min(out_size - out_pos);

            if self.state == 1 {
                while limit != 0 {
                    let bb = self.tmp[base0 + in_pos];
                    out[out_pos] = bb;
                    out_pos += 1;
                    if is_j(self.prev_byte, bb) {
                        self.state = 2;
                        break;
                    }
                    in_pos += 1;
                    self.prev_byte = bb;
                    limit -= 1;
                }
            }

            if limit == 0 || out_pos == out_size {
                break;
            }
            self.state = 1;

            let b = self.tmp[base0 + in_pos];
            in_pos += 1;

            let prob = match b {
                0xE8 => usize::from(self.prev_byte),
                0xE9 => 256,
                _ => 257,
            };
            let ttt = u32::from(self.probs[prob]);
            let bound = (self.range >> K_NUM_BIT_MODEL_TOTAL_BITS) * ttt;
            if self.code < bound {
                self.range = bound;
                self.probs[prob] = (ttt + ((K_BIT_MODEL_TOTAL - ttt) >> K_NUM_MOVE_BITS)) as u16;
                normalize!();
                self.prev_byte = b;
            } else {
                self.range -= bound;
                self.code -= bound;
                self.probs[prob] = (ttt - (ttt >> K_NUM_MOVE_BITS)) as u16;
                normalize!();
                let v = if b == 0xE8 {
                    if size1 < 4 {
                        return Err(());
                    }
                    let at = pos1;
                    pos1 += 4;
                    size1 -= 4;
                    self.streams[0].get(at..at + 4).ok_or(())?
                } else {
                    if size2 < 4 {
                        return Err(());
                    }
                    let at = pos2;
                    pos2 += 4;
                    size2 -= 4;
                    self.streams[1].get(at..at + 4).ok_or(())?
                };
                let dest =
                    be32(v).wrapping_sub(self.out_pos.wrapping_add(out_pos).wrapping_add(4) as u32);
                let bytes = dest.to_le_bytes();
                self.prev_byte = bytes[3];

                let mut i = 0;
                while i < 4 && out_pos < out_size {
                    out[out_pos] = bytes[i];
                    out_pos += 1;
                    i += 1;
                }
                if i < 4 {
                    // Save odd bytes which we could not add into the output
                    // buffer because of out of space.
                    odd.odd_bcj_size = 4 - i;
                    let first = i;
                    while i < 4 {
                        odd.odd_bcj[i - first] = bytes[i];
                        i += 1;
                    }
                    break;
                }
            }
        }
        self.tmp_remaining -= in_pos;
        self.remaining = [size1, size2, lim3 - pos3];
        self.out_pos += out_pos;

        Ok(out_pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODECS: [i64; 8] = [
        CODEC_X86,
        CODEC_ARM,
        CODEC_ARMTHUMB,
        CODEC_ARM64,
        CODEC_SPARC,
        CODEC_POWERPC,
        CODEC_RISCV,
        CODEC_IA64,
    ];

    /// Runs the converter for `codec` over `data` in pieces cut at `cuts`,
    /// carrying the bytes it did not convert to the next piece, as
    /// `decompress` does. The tail left at the end stays as it is. `xz`
    /// selects the converter that liblzma's counterpart provides.
    fn convert_in_pieces(codec: i64, xz: bool, data: &[u8], cuts: &[usize]) -> Vec<u8> {
        let mut f = Filters::default();
        match codec {
            CODEC_X86 => f.x86_init(),
            CODEC_ARM => f.arm_init(),
            CODEC_ARMTHUMB => f.armthumb_init(),
            _ => {}
        }
        if xz {
            f.set_lzma2_filter(Some(codec)).unwrap();
        }
        let mut out = Vec::new();
        let mut carry: Vec<u8> = Vec::new();
        let mut at = 0;
        for &end in cuts.iter().chain([&data.len()]) {
            let mut piece = std::mem::take(&mut carry);
            piece.extend_from_slice(&data[at..end]);
            at = end;
            let l = f.convert(codec, &mut piece).unwrap();
            out.extend_from_slice(&piece[..l]);
            carry = piece[l..].to_vec();
        }
        out.extend_from_slice(&carry);
        out
    }

    fn hot_data() -> (Vec<u8>, impl FnMut() -> u32) {
        let mut seed = 0x1234_5678u32;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        // Bytes that make the filters' patterns likely.
        let hot = [
            0xE8, 0xE9, 0xEB, 0xF0, 0xF8, 0x94, 0x90, 0x48, 0xEF, 0x17, 0x0F, 0x80, 0, 0xFF,
        ];
        let data = (0..20_000)
            .map(|_| {
                let r = rnd();
                if r & 3 == 0 {
                    r as u8
                } else {
                    hot[(r >> 8) as usize % hot.len()]
                }
            })
            .collect();
        (data, rnd)
    }

    /// The converters upstream runs itself, over the whole of the data,
    /// agree with the ones it hands to liblzma, and the latter do not depend
    /// on the size of the buffers. (Upstream's x86 converter keeps its
    /// `prevPosT` relative to the buffer it was set in, so it does depend on
    /// them: see NOTES.md.)
    #[test]
    fn converters_agree_with_the_xz_ones() {
        let (data, mut rnd) = hot_data();
        for codec in CODECS {
            let whole = convert_in_pieces(codec, false, &data, &[]);
            assert_ne!(whole, data, "codec {codec:#x} changed nothing");
            assert!(
                convert_in_pieces(codec, true, &data, &[]) == whole,
                "codec {codec:#x}"
            );
            for _ in 0..20 {
                let mut cuts: Vec<usize> = (0..8).map(|_| rnd() as usize % data.len()).collect();
                cuts.sort_unstable();
                assert!(
                    convert_in_pieces(codec, true, &data, &cuts) == whole,
                    "codec {codec:#x} cuts {cuts:?}"
                );
                if codec != CODEC_X86 {
                    assert!(
                        convert_in_pieces(codec, false, &data, &cuts) == whole,
                        "codec {codec:#x} cuts {cuts:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn delta_adds_the_byte_a_distance_back() {
        let mut f = Filters::default();
        f.delta_init(2);
        let mut buf = [1u8, 2, 1, 1, 1, 1, 0xFF, 0xFF];
        f.delta_decode(&mut buf[..4]);
        f.delta_decode(&mut buf[4..]);
        assert_eq!(buf, [1, 2, 2, 3, 3, 4, 2, 3]);
    }
}
