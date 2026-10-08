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

// Ported from libarchive/archive_read_support_filter_lz4.c.

//! The lz4 filter: LZ4 frames with their checksums and skippable frames, and
//! the legacy format. The frame parsing is upstream's; the blocks are decoded
//! by `lz4_flex`.

use crate::archive::ARCHIVE_ERRNO_MISC;
use crate::archive::Base;
use crate::read::{Filter, FilterBidder, Read, Reader, Status, filter_code};
use crate::util::Error;
use lz4_flex::block::{decompress_into, decompress_into_with_dict};
use std::ffi::{CStr, c_int};
use xxhash_rust::xxh32::{Xxh32, xxh32};

const LZ4_MAGIC: u32 = 0x184d_2204;
const LZ4_LEGACY: u32 = 0x184c_2102;
// Zstd's skippable frames have the same magic numbers.
const SKIPPABLE: u32 = 0x184d_2a50;
const SKIPPABLE_MASK: u32 = 0xffff_fff0;
/// The history a linked block may refer back to.
const WINDOW: usize = 64 << 10;
const LEGACY_BLOCK: usize = 8 << 20;
/// `LZ4_COMPRESSBOUND(LEGACY_BLOCK)`: a larger legacy block ends the frame.
const LEGACY_BOUND: u32 = (LEGACY_BLOCK + LEGACY_BLOCK / 255 + 16) as u32;

fn truncated() -> Error {
    Error::fatal(ARCHIVE_ERRNO_MISC, "truncated lz4 input")
}

fn malformed() -> Error {
    Error::fatal(ARCHIVE_ERRNO_MISC, "malformed lz4 data")
}

fn decompression_failed() -> Error {
    Error::fatal(ARCHIVE_ERRNO_MISC, "lz4 decompression failed")
}

/// The little-endian word at the start of `b`. Every caller has read ahead
/// the four bytes, so a shorter slice never happens; it reads as zero.
fn le32(b: &[u8]) -> u32 {
    b.first_chunk::<4>().map_or(0, |w| u32::from_le_bytes(*w))
}

/// Fills `window` with the 64 KiB before the next linked block: the previous
/// block `prev`, zero-filled in front when it is short. Upstream keeps only
/// the previous block, not the output before it, and so does this.
fn slide(window: &mut [u8], prev: &[u8]) {
    let keep = prev.len().min(WINDOW);
    let (zeros, tail) = window.split_at_mut(WINDOW - keep);
    zeros.fill(0);
    tail.copy_from_slice(prev.get(prev.len() - keep..).unwrap_or_default());
}

/// Bids on LZ4 frames and legacy streams.
struct Bidder;

impl FilterBidder for Bidder {
    fn bid(&mut self, up: &mut Reader<'_>) -> Result<c_int, Error> {
        // The shortest archive that gets a bid.
        const MIN_ARCHIVE: usize = 11;
        const MAX_LOOKAHEAD: usize = 64 << 10;

        if up.read_ahead(MIN_ARCHIVE)?.is_none() {
            return Ok(0);
        }
        // Skippable frames each add 28 bits, but a frame is never checked
        // beyond the first 64 KiB.
        let mut bits: c_int = 0;
        let mut at = 0;
        let (magic, head) = loop {
            if at + 8 > MAX_LOOKAHEAD {
                return Ok(0);
            }
            let Some(head) = up.read_ahead(at + 8)?.and_then(|b| b.get(at..)) else {
                return Ok(0);
            };
            let magic = le32(head);
            if magic & SKIPPABLE_MASK != SKIPPABLE {
                break (magic, head);
            }
            bits += 28;
            let size = usize::try_from(le32(head.get(4..).unwrap_or_default()));
            let Some(next) = size.ok().and_then(|s| at.checked_add(8)?.checked_add(s)) else {
                return Ok(0);
            };
            at = next;
        };

        if magic == LZ4_LEGACY {
            return Ok(bits + 32);
        }
        if magic != LZ4_MAGIC {
            return Ok(0);
        }
        let (Some(&flag), Some(&bd)) = (head.get(4), head.get(5)) else {
            return Ok(0);
        };
        // Version 01 with the reserved bit clear, then a block maximum of at
        // least 64 KiB and the reserved bits clear.
        if flag & 0xc0 != 0x40 || flag & 0x02 != 0 || (bd & 0x70) >> 4 < 4 || bd & !0x70 != 0 {
            return Ok(0);
        }
        Ok(bits + 32 + 8 + 8)
    }

    fn init(&mut self, _up: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(Lz4::default()))
    }
}

/// An LZ4 frame, from its descriptor on.
struct Frame {
    /// Linked blocks may refer back to the window; independent ones do not.
    linked: bool,
    block_max: usize,
    block_checksum: bool,
    /// Hashes the frame's output, when the frame has a content checksum.
    content: Option<Xxh32>,
    /// Size of the last block, which `slide` moves into the window.
    decoded: usize,
}

/// Where decoding is between blocks.
#[derive(Default)]
enum Stage {
    /// Between frames: the next magic number says what follows.
    #[default]
    Magic,
    Lz4(Frame),
    Legacy,
    /// The end of the input. Sticky.
    Eof,
}

/// What a block decodes into.
#[derive(Default)]
struct Output {
    /// Where decoded blocks go: sized for the frame's block maximum, or 8 MiB
    /// for a legacy block.
    buf: Vec<u8>,
    /// The history a linked block refers back to, as upstream's 64 KiB
    /// prefix.
    window: Vec<u8>,
    /// Length of the block the last `read` produced, at the start of `buf`.
    len: usize,
}

#[derive(Default)]
struct Lz4 {
    stage: Stage,
    out: Output,
}

impl Lz4 {
    /// Skips skippable frames and starts the frame at the next magic number.
    /// Anything else ends the input; so does a frame that ends before any
    /// data, and bytes after it that are not a frame are ignored.
    fn open(&mut self, up: &mut Reader<'_>) -> Result<Stage, Error> {
        loop {
            let Some(magic) = up.read_ahead(4)?.map(le32) else {
                return Ok(Stage::Eof);
            };
            up.consume(4)?;
            match magic {
                LZ4_MAGIC => return Ok(Stage::Lz4(self.descriptor(up)?)),
                LZ4_LEGACY => return Ok(Stage::Legacy),
                magic if magic & SKIPPABLE_MASK == SKIPPABLE => {
                    // Upstream words this one with a capital M.
                    let bad = || Error::fatal(ARCHIVE_ERRNO_MISC, "Malformed lz4 data");
                    let size = up.read_ahead(4)?.map(le32).ok_or_else(bad)?;
                    up.consume(4 + u64::from(size)).map_err(|_| bad())?;
                }
                _ => return Ok(Stage::Eof),
            }
        }
    }

    /// Reads a frame descriptor, after its magic number, and sizes the
    /// buffers for the frame.
    fn descriptor(&mut self, up: &mut Reader<'_>) -> Result<Frame, Error> {
        let [flg, bd] = up
            .read_ahead(2)?
            .and_then(|h| h.first_chunk::<2>().copied())
            .ok_or_else(truncated)?;
        if flg & 0xc0 != 0x40 || flg & 0x02 != 0 || bd & 0x8f != 0 {
            return Err(malformed());
        }
        let block_max = match bd >> 4 {
            4 => 64 << 10,
            5 => 256 << 10,
            6 => 1 << 20,
            7 => 4 << 20,
            _ => return Err(malformed()),
        };
        // The descriptor is FLG, BD, the optional content size and dictionary
        // ID (which upstream reads and ignores), then the header checksum.
        let size = 3 + if flg & 0x08 != 0 { 8 } else { 0 } + if flg & 0x01 != 0 { 4 } else { 0 };
        let desc = up
            .read_ahead(size)?
            .and_then(|d| d.get(..size))
            .ok_or_else(truncated)?;
        let (&check, covered) = desc.split_last().ok_or_else(truncated)?;
        // The checksum's second byte, of xxHash32 over the rest.
        if (xxh32(covered, 0) >> 8) as u8 != check {
            return Err(malformed());
        }
        let linked = flg & 0x20 == 0;
        let frame = Frame {
            linked,
            block_max,
            block_checksum: flg & 0x10 != 0,
            content: (flg & 0x04 != 0).then(|| Xxh32::new(0)),
            decoded: 0,
        };
        up.consume(size)?;

        self.out.buf.resize(block_max, 0);
        if linked {
            self.out.window.clear();
            self.out.window.resize(WINDOW, 0);
        }
        Ok(frame)
    }

    /// The next block of the LZ4 frame, or `None` at its end mark.
    fn lz4_block(
        frame: &mut Frame,
        out: &mut Output,
        up: &mut Reader<'_>,
    ) -> Result<Option<usize>, Error> {
        let head = up.read_ahead(4)?.map(le32).ok_or_else(truncated)?;
        // The high bit marks a stored block; a size over the maximum is
        // malformed.
        let size = usize::try_from(head & 0x7fff_ffff).unwrap_or(usize::MAX);
        if size > frame.block_max {
            return Err(malformed());
        }
        if head == 0 {
            up.consume(4)?;
            if let Some(hash) = frame.content.take() {
                let stored = up.read_ahead(4)?.map(le32).ok_or_else(truncated)?;
                up.consume(4)?;
                if stored != hash.digest() {
                    return Err(Error::fatal(
                        ARCHIVE_ERRNO_MISC,
                        "lz4 stream checksum error",
                    ));
                }
            }
            return Ok(None);
        }

        let checksum = if frame.block_checksum { 4 } else { 0 };
        let total = 4 + size + checksum;
        let body = up.read_ahead(total)?.ok_or_else(truncated)?;
        let data = body.get(4..4 + size).unwrap_or_default();
        if frame.block_checksum {
            let stored = body.get(4 + size..total).map(le32).ok_or_else(truncated)?;
            if xxh32(data, 0) != stored {
                return Err(malformed());
            }
        }

        if frame.linked {
            slide(
                &mut out.window,
                out.buf.get(..frame.decoded).unwrap_or_default(),
            );
        }
        // A stored block of size zero is decoded as a compressed one, which
        // fails, as upstream's does.
        let n = if head & 0x8000_0000 != 0 && size > 0 {
            out.buf
                .get_mut(..size)
                .ok_or_else(malformed)?
                .copy_from_slice(data);
            size
        } else if frame.linked {
            decompress_into_with_dict(data, &mut out.buf, &out.window)
                .map_err(|_| decompression_failed())?
        } else {
            decompress_into(data, &mut out.buf).map_err(|_| decompression_failed())?
        };
        frame.decoded = n;
        if let Some(hash) = &mut frame.content {
            hash.update(out.buf.get(..n).unwrap_or_default());
        }
        out.len = n;
        up.consume(total)?;
        Ok(Some(n))
    }

    /// The next block of a legacy frame, or `None` where the frame ends. A
    /// frame with no block at all (`first`) is truncated.
    fn legacy_block(
        out: &mut Output,
        up: &mut Reader<'_>,
        first: bool,
    ) -> Result<Option<usize>, Error> {
        out.buf.resize(LEGACY_BLOCK, 0);
        let Some(size) = up.read_ahead(4)?.map(le32) else {
            return if first { Err(truncated()) } else { Ok(None) };
        };
        if size > LEGACY_BOUND {
            return Ok(None);
        }
        let total = 4 + usize::try_from(size).unwrap_or(usize::MAX);
        let body = up.read_ahead(total)?.ok_or_else(truncated)?;
        let data = body.get(4..total).unwrap_or_default();
        let n = decompress_into(data, &mut out.buf).map_err(|_| decompression_failed())?;
        out.len = n;
        up.consume(total)?;
        Ok(Some(n))
    }
}

impl Filter for Lz4 {
    fn name(&self) -> &CStr {
        c"lz4"
    }

    fn code(&self) -> c_int {
        filter_code::LZ4
    }

    fn read(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
        self.out.len = 0;
        loop {
            // A frame that has just been opened gives its first block to the
            // caller directly. Upstream's end of input is decided there, so a
            // frame that ends before any data ends the stream.
            let fresh = matches!(self.stage, Stage::Magic);
            if fresh {
                self.stage = self.open(up)?;
            }
            let block = match &mut self.stage {
                Stage::Lz4(frame) => Self::lz4_block(frame, &mut self.out, up)?,
                Stage::Legacy => Self::legacy_block(&mut self.out, up, fresh)?,
                Stage::Magic | Stage::Eof => return Ok(()),
            };
            match block {
                None if !fresh => self.stage = Stage::Magic,
                Some(n) if n > 0 => return Ok(()),
                // A zero-length block is the end of the input too.
                _ => {
                    self.stage = Stage::Eof;
                    return Ok(());
                }
            }
        }
    }

    fn block(&self) -> &[u8] {
        self.out.buf.get(..self.out.len).unwrap_or_default()
    }
}

/// `archive_read_support_filter_lz4`.
pub fn support(r: &mut Read, _: &Base) -> Result<Status, Error> {
    r.register_bidder(Box::new(Bidder))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::filter::testing::decode;

    // `lz4 a.txt`, `lz4 b.txt`, `lz4 -l a.txt` (legacy) and `lz4` of an empty file.
    const A: &[u8] = &[
        0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7, 0x12, 0x00, 0x00, 0x00, 0x1b, 0x41, 0x01, 0x00,
        0xd0, 0x20, 0x66, 0x69, 0x72, 0x73, 0x74, 0x20, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x0a, 0x00,
        0x00, 0x00, 0x00, 0x03, 0xf9, 0xd4, 0x8a,
    ];
    const B: &[u8] = &[
        0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7, 0x13, 0x00, 0x00, 0x00, 0x1b, 0x42, 0x01, 0x00,
        0xe0, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x0a,
        0x00, 0x00, 0x00, 0x00, 0x4b, 0x2c, 0xc3, 0x9c,
    ];
    const LEGACY: &[u8] = &[
        0x02, 0x21, 0x4c, 0x18, 0x12, 0x00, 0x00, 0x00, 0x1b, 0x41, 0x01, 0x00, 0xd0, 0x20, 0x66,
        0x69, 0x72, 0x73, 0x74, 0x20, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x0a,
    ];
    const EMPTY: &[u8] = &[
        0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7, 0x00, 0x00, 0x00, 0x00, 0x05, 0x5d, 0xcc, 0x02,
    ];
    const A_TEXT: &[u8] = b"AAAAAAAAAAAAAAAA first frame\n";
    const B_TEXT: &[u8] = b"BBBBBBBBBBBBBBBB second frame\n";

    /// 70000 bytes of a 36-byte period: `lz4 -BD -BX -B4`, two linked blocks with block checksums.
    const LINKED: &[u8] = &[
        0x04, 0x22, 0x4d, 0x18, 0x54, 0x40, 0xae, 0x2f, 0x01, 0x00, 0x00, 0xff, 0x15, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
        0x77, 0x78, 0x79, 0x7a, 0x24, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc4, 0x50, 0x62, 0x63, 0x64, 0x65, 0x66, 0xee,
        0xfa, 0xc4, 0x06, 0x1b, 0x00, 0x00, 0x00, 0x0f, 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x69, 0x50, 0x62,
        0x63, 0x64, 0x65, 0x66, 0x74, 0xd0, 0x7b, 0x33, 0x00, 0x00, 0x00, 0x00, 0xa7, 0x45, 0xd3,
        0x1c,
    ];
    /// 100 random bytes: `lz4 -BX -B4`, one stored block with a block checksum.
    const STORED: &[u8] = &[
        0x04, 0x22, 0x4d, 0x18, 0x74, 0x40, 0xbd, 0x64, 0x00, 0x00, 0x80, 0xa5, 0x4d, 0xca, 0x18,
        0x25, 0x30, 0xbb, 0x1d, 0x6d, 0x13, 0x2c, 0xde, 0xd6, 0x23, 0x7b, 0x2e, 0xd9, 0x1e, 0x3f,
        0x72, 0x1f, 0xcb, 0x19, 0x71, 0x17, 0x44, 0x94, 0xd6, 0x49, 0x3c, 0x9d, 0x5c, 0x34, 0x60,
        0xbe, 0x31, 0x20, 0x1e, 0x69, 0xfe, 0xda, 0xa0, 0xee, 0xe8, 0xb9, 0x99, 0x7f, 0x5c, 0x7c,
        0x29, 0x99, 0xfd, 0xaf, 0xe5, 0x93, 0x25, 0x3c, 0xd6, 0x54, 0xaf, 0x4d, 0xfa, 0xd7, 0x14,
        0x27, 0xa0, 0xae, 0xb3, 0xfe, 0xe9, 0x23, 0x2f, 0x8a, 0xf2, 0x21, 0x1f, 0x9e, 0xe4, 0x91,
        0xc5, 0xb1, 0x0b, 0xec, 0xb5, 0x56, 0x3b, 0xfc, 0x1e, 0x6f, 0x93, 0x42, 0x7e, 0xcb, 0xc8,
        0xfe, 0x29, 0x55, 0xe5, 0xcd, 0x8e, 0x1d, 0xf9, 0x2c, 0xbd, 0x00, 0x00, 0x00, 0x00, 0x1d,
        0xf9, 0x2c, 0xbd,
    ];

    #[test]
    fn a_frame_decodes_at_any_read_size() {
        for size in [1, 2, 3, 7, 4096] {
            assert_eq!(
                decode(support, A, size),
                Ok(A_TEXT.to_vec()),
                "read size {size}"
            );
        }
    }

    #[test]
    fn frames_concatenate_and_legacy_frames_decode() {
        assert_eq!(
            decode(support, &[A, B].concat(), 5),
            Ok([A_TEXT, B_TEXT].concat())
        );
        assert_eq!(decode(support, LEGACY, 3), Ok(A_TEXT.to_vec()));
    }

    #[test]
    fn an_empty_frame_ends_the_stream() {
        // Upstream stops at a frame with no data, so the frame after it is
        // never read.
        assert_eq!(
            decode(support, &[A, EMPTY, B].concat(), 9),
            Ok(A_TEXT.to_vec())
        );
    }

    #[test]
    fn a_stream_cut_short_is_truncated() {
        assert_eq!(
            decode(support, &A[..A.len() - 1], 3),
            Err("truncated lz4 input".into())
        );
    }

    #[test]
    fn truncation_and_mutation_never_panic() {
        let full = [A, B, LEGACY].concat();
        for n in 0..full.len() {
            let _ = decode(support, full.get(..n).unwrap_or_default(), 1);
        }
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        for _ in 0..300 {
            let mut m = full.clone();
            for _ in 0..3 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let i = usize::try_from(seed).unwrap_or_default() % m.len();
                if let Some(b) = m.get_mut(i) {
                    *b = (seed >> 32) as u8;
                }
            }
            let _ = decode(support, &m, 7);
        }
    }
    #[test]
    fn linked_blocks_refer_back_to_the_previous_block() {
        let mut expected = b"0123456789abcdefghijklmnopqrstuvwxyz".repeat(2100);
        expected.truncate(70000);
        assert_eq!(decode(support, LINKED, 9), Ok(expected));
    }

    #[test]
    fn a_stored_block_is_copied() {
        // The stored data sits after the 7-byte header and the 4-byte size.
        let data = STORED.get(11..111).unwrap_or_default().to_vec();
        assert_eq!(decode(support, STORED, 13), Ok(data));
    }

    #[test]
    fn a_block_checksum_failure_is_malformed() {
        // The first block's checksum starts after its 303 bytes of data.
        let mut bad = LINKED.to_vec();
        bad[7 + 4 + 303] ^= 0xff;
        assert_eq!(
            decode(support, &bad, 4096),
            Err("malformed lz4 data".into())
        );
    }

    #[test]
    fn a_content_checksum_failure_is_a_stream_error() {
        let mut bad = LINKED.to_vec();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert_eq!(
            decode(support, &bad, 4096),
            Err("lz4 stream checksum error".into())
        );
    }

    #[test]
    fn a_skippable_frame_between_frames_is_skipped() {
        let skip = [0x50, 0x2a, 0x4d, 0x18, 3, 0, 0, 0];
        let data = [A, &skip[..], &b"xyz"[..], B].concat();
        assert_eq!(decode(support, &data, 5), Ok([A_TEXT, B_TEXT].concat()));
    }

    #[test]
    fn a_stored_block_of_size_zero_fails_to_decompress() {
        // Upstream decodes the header 0x80000000 as a compressed block of 0 bytes.
        let data = [&A[..7], &[0, 0, 0, 0x80][..], &EMPTY[7..]].concat();
        assert_eq!(
            decode(support, &data, 3),
            Err("lz4 decompression failed".into())
        );
    }
}
