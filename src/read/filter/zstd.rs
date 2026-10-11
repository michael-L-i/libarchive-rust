/*-
 * Copyright (c) 2009-2011 Sean Purcell
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

// Ported from libarchive/archive_read_support_filter_zstd.c.

//! The zstd filter: decompresses zstd frames, with skippable frames allowed
//! before, between and after them. ruzstd decodes the frames. It has no
//! skippable frames and no header checks for the reserved bit or the window
//! log, and it does not check the content checksum, so those are done here.

use crate::archive::*;
use crate::read::{Filter, FilterBidder, Read, Reader, Status, filter_code};
use crate::util::Error;
use ruzstd::decoding::errors::{
    DecodeBlockContentError, DecodeBufferError, FrameDecoderError, ReadFrameHeaderError,
};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use std::ffi::{CStr, c_int};
use std::io;

/// `ZSTD_DStreamOutSize()`: the largest block, as upstream's output block.
const BLOCK: usize = 128 * 1024;
/// libzstd's default window limit (`ZSTD_WINDOWLOG_LIMIT_DEFAULT`).
const MAX_WINDOW: u64 = 1 << 27;
const MAGIC: u32 = 0xFD2F_B528;
const MAGIC_BYTES: [u8; 4] = MAGIC.to_le_bytes();
const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;
const SKIPPABLE_MASK: u32 = 0xFFFF_FFF0;
/// A frame's magic and the frame size that follows a skippable magic.
const MIN_FRAME: usize = 8;
/// Bids look ahead no further than this.
const MAX_LOOKAHEAD: usize = 64 * 1024;
/// The frame header descriptor's reserved bit.
const RESERVED_BIT: u8 = 0x08;

/// `archive_read_support_filter_zstd`.
pub fn support(r: &mut Read, _: &Base) -> Result<Status, Error> {
    r.register_bidder(Box::new(Bidder))
}

fn le_u32(buf: &[u8], at: usize) -> Option<u32> {
    let word = buf.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(word.try_into().ok()?))
}

/// The little-endian u32 at `at`, after reading ahead `need` bytes.
fn peek_u32(up: &mut Reader<'_>, need: usize, at: usize) -> Option<u32> {
    le_u32(up.read_ahead(need).ok()??, at)
}

/// Tests whether the stream is zstd: the frame magic, after any skippable
/// frames. The bid is 28 bits for each skippable frame and 32 for the magic.
fn bid(up: &mut Reader<'_>) -> Option<c_int> {
    let mut bits = 0;
    let mut offset = 0;
    let mut magic = peek_u32(up, MIN_FRAME, 0)?;
    while magic & SKIPPABLE_MASK == SKIPPABLE_MAGIC {
        bits += 28;
        // Skip the magic, read the frame size, and skip it and the data.
        offset += 4;
        let size = peek_u32(up, offset + 4, offset)?;
        offset = offset.checked_add(4)?.checked_add(size as usize)?;
        // There should be at least one more frame if this is zstd data.
        let min = offset.checked_add(MIN_FRAME)?;
        if min > MAX_LOOKAHEAD {
            return None;
        }
        magic = peek_u32(up, min, offset)?;
    }
    (magic == MAGIC).then_some(bits + 32)
}

struct Bidder;

impl FilterBidder for Bidder {
    fn bid(&mut self, up: &mut Reader<'_>) -> Result<c_int, Error> {
        Ok(bid(up).unwrap_or(0))
    }

    fn init(&mut self, _up: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
        let mut out = Vec::new();
        out.try_reserve_exact(BLOCK).map_err(|_| {
            Error::fatal(libc::ENOMEM, "Can't allocate data for zstd decompression")
        })?;
        out.resize(BLOCK, 0);
        let mut decoder = FrameDecoder::new();
        decoder.set_max_window_size(MAX_WINDOW);
        Ok(Box::new(Zstd {
            decoder,
            in_frame: false,
            eof: false,
            out,
            len: 0,
        }))
    }
}

fn truncated() -> Error {
    Error::fatal(ARCHIVE_ERRNO_MISC, "Truncated zstd input")
}

/// libzstd's error for a frame it cannot parse, with the name it reports.
fn failed(name: &str) -> Error {
    Error::fatal(
        ARCHIVE_ERRNO_MISC,
        format!("Zstd decompression failed: {name}"),
    )
}

/// Whether `head` could be the start of a magic number, a frame's or a
/// skippable frame's. A few trailing bytes that could be one are a truncated
/// frame; anything else is garbage.
fn may_start_magic(head: &[u8]) -> bool {
    let frame = head.iter().zip(MAGIC_BYTES).all(|(b, m)| *b == m);
    // A skippable magic is 0x184D2A5X: only the first byte varies.
    let skippable = head
        .iter()
        .zip([0x50, 0x2A, 0x4D, 0x18])
        .enumerate()
        .all(|(i, (b, m))| if i == 0 { b & 0xF0 == m } else { *b == m });
    frame || skippable
}

/// Skips the skippable frames before the next frame. `false` is the end of
/// the input; a frame cut short is a truncated stream.
fn skip_skippable(up: &mut Reader<'_>) -> Result<bool, Error> {
    loop {
        let head = up.peek_available(MIN_FRAME)?;
        if head.is_empty() {
            return Ok(false);
        }
        let Some(magic) = le_u32(head, 0) else {
            return Err(if may_start_magic(head) {
                truncated()
            } else {
                failed("Unknown frame descriptor")
            });
        };
        if magic & SKIPPABLE_MASK != SKIPPABLE_MAGIC {
            return Ok(true);
        }
        let size = le_u32(head, 4).ok_or_else(truncated)?;
        let len = i64::from(size) + MIN_FRAME as i64;
        if up.skip(len)? < len {
            return Err(truncated());
        }
    }
}

/// libzstd's check of the frame header descriptor's reserved bit, which
/// ruzstd does not make.
fn check_frame_header(up: &mut Reader<'_>) -> Result<(), Error> {
    let head = up.peek_available(5)?;
    if le_u32(head, 0) == Some(MAGIC) && head.get(4).is_some_and(|d| d & RESERVED_BIT != 0) {
        return Err(failed("Unsupported frame parameter"));
    }
    Ok(())
}

/// The stage below, as the `Read` that ruzstd pulls frames through. An
/// `io::Error` cannot carry a failure of the stage, so the first one is kept
/// here, and running out of input is noted.
struct Input<'r, 'a> {
    up: &'r mut Reader<'a>,
    error: Option<Error>,
    ended: bool,
}

impl<'r, 'a> Input<'r, 'a> {
    fn new(up: &'r mut Reader<'a>) -> Self {
        Input {
            up,
            error: None,
            ended: false,
        }
    }
}

impl io::Read for Input<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = match self.up.read_ahead(1) {
            Ok(Some(data)) => {
                let n = data.len().min(buf.len());
                if let (Some(dst), Some(src)) = (buf.get_mut(..n), data.get(..n)) {
                    dst.copy_from_slice(src);
                }
                n
            }
            Ok(None) => {
                self.ended = true;
                return Ok(0);
            }
            Err(e) => {
                self.error = Some(e);
                return Err(io::Error::other("input failed"));
            }
        };
        if let Err(e) = self.up.consume(n) {
            self.error = Some(e);
            return Err(io::Error::other("input failed"));
        }
        Ok(n)
    }
}

/// What upstream reports for a failed decode: the stage's own error, a
/// truncated stream if the input ran out, else libzstd's name for the error.
fn decode_failure(input: Input<'_, '_>, e: Option<&FrameDecoderError>) -> Error {
    if let Some(error) = input.error {
        return error;
    }
    if input.ended {
        return truncated();
    }
    let name = match e {
        Some(FrameDecoderError::WindowSizeTooBig { .. }) => {
            "Frame requires too much memory for decoding"
        }
        Some(
            FrameDecoderError::DictNotProvided { .. } | FrameDecoderError::DictionaryDecodeError(_),
        ) => "Dictionary mismatch",
        Some(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::BadMagicNumber(_))) => {
            "Unknown frame descriptor"
        }
        Some(FrameDecoderError::FailedToReadBlockBody(
            DecodeBlockContentError::DecodeBufferError(DecodeBufferError::OutOfMemory),
        )) => "Allocation error : not enough memory",
        _ => "Data corruption detected",
    };
    failed(name)
}

struct Zstd {
    decoder: FrameDecoder,
    /// In the middle of a frame.
    in_frame: bool,
    eof: bool,
    /// The output block; its first `len` bytes are the current block.
    out: Vec<u8>,
    len: usize,
}

impl Filter for Zstd {
    fn name(&self) -> &CStr {
        c"zstd"
    }

    fn code(&self) -> c_int {
        filter_code::ZSTD
    }

    /// Fills the output block, or ends at the end of the input. A frame's
    /// checksum is checked once all its output has been read.
    fn read(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
        self.len = 0;
        while self.len < self.out.len() && !self.eof {
            if !self.in_frame {
                if !skip_skippable(up)? {
                    self.eof = true;
                    break;
                }
                check_frame_header(up)?;
                let mut input = Input::new(up);
                if let Err(e) = self.decoder.reset(&mut input) {
                    return Err(decode_failure(input, Some(&e)));
                }
                self.in_frame = true;
            }
            let mut input = Input::new(up);
            while self.decoder.can_collect() == 0 && !self.decoder.is_finished() {
                let strategy = BlockDecodingStrategy::UptoBytes(1);
                if let Err(e) = self.decoder.decode_blocks(&mut input, strategy) {
                    return Err(decode_failure(input, Some(&e)));
                }
            }
            let room = self.out.get_mut(self.len..).unwrap_or_default();
            let n = match io::Read::read(&mut self.decoder, room) {
                Ok(n) => n,
                Err(_) => return Err(decode_failure(input, None)),
            };
            self.len += n;
            if self.decoder.is_finished() && self.decoder.can_collect() == 0 {
                if let Some(stored) = self.decoder.get_checksum_from_data()
                    && self.decoder.get_calculated_checksum() != Some(stored)
                {
                    return Err(failed("Restored data doesn't match checksum"));
                }
                self.in_frame = false;
            }
        }
        Ok(())
    }

    fn block(&self) -> &[u8] {
        self.out.get(..self.len).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::filter::testing::{decode, noise};
    use ruzstd::encoding::{CompressionLevel, compress_to_vec};

    fn encode(data: &[u8], level: CompressionLevel) -> Vec<u8> {
        compress_to_vec(data, level)
    }

    /// A skippable frame: magic, size, then the data.
    fn skippable(data: &[u8]) -> Vec<u8> {
        let mut f = 0x184D_2A50_u32.to_le_bytes().to_vec();
        f.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        f.extend_from_slice(data);
        f
    }

    fn decode_zst(data: &[u8], block: usize) -> Result<Vec<u8>, String> {
        decode(support, data, block)
    }

    #[test]
    fn decodes_at_any_block_size() {
        let data = noise(300_000);
        for level in [CompressionLevel::Uncompressed, CompressionLevel::Fastest] {
            let frame = encode(&data, level);
            for block in [1, 5, 999, 1 << 20] {
                assert_eq!(decode_zst(&frame, block).unwrap(), data, "block {block}");
            }
        }
    }

    #[test]
    fn decodes_frames_with_skippable_frames_between() {
        let (a, b) = (noise(70_000), b"second frame\n".repeat(90));
        let stream = [
            skippable(b"before"),
            encode(&a, CompressionLevel::Fastest),
            skippable(b""),
            skippable(&noise(9)),
            encode(&b, CompressionLevel::Uncompressed),
            skippable(b"after"),
        ]
        .concat();
        assert_eq!(decode_zst(&stream, 13).unwrap(), [a, b].concat());
    }

    #[test]
    fn bad_content_checksum_is_an_error() {
        let mut frame = encode(&noise(1000), CompressionLevel::Fastest);
        *frame.last_mut().unwrap() ^= 1;
        assert_eq!(
            decode_zst(&frame, 4096),
            Err("Zstd decompression failed: Restored data doesn't match checksum".to_string())
        );
    }

    #[test]
    fn reserved_descriptor_bit_is_unsupported() {
        let mut frame = encode(b"payload", CompressionLevel::Fastest);
        *frame.get_mut(4).unwrap() |= RESERVED_BIT;
        assert_eq!(
            decode_zst(&frame, 4096),
            Err("Zstd decompression failed: Unsupported frame parameter".to_string())
        );
    }

    #[test]
    fn window_log_above_31_needs_too_much_memory() {
        // Magic, a descriptor without the single-segment flag, and a window
        // descriptor for window log 32, padded to the bid's lookahead.
        let frame = [MAGIC_BYTES.as_slice(), &[0x00, (32 - 10) << 3, 0, 0]].concat();
        assert_eq!(
            decode_zst(&frame, 4096),
            Err(
                "Zstd decompression failed: Frame requires too much memory for decoding"
                    .to_string()
            )
        );
    }

    #[test]
    fn one_to_three_trailing_bytes_are_garbage_unless_a_magic_prefix() {
        let frame = encode(b"payload", CompressionLevel::Fastest);
        for junk in [&b"\x00"[..], b"\x00\x01", b"x\x00\x00"] {
            let stream = [frame.as_slice(), junk].concat();
            assert_eq!(
                decode_zst(&stream, 4096),
                Err("Zstd decompression failed: Unknown frame descriptor".to_string())
            );
        }
        for prefix in [&MAGIC_BYTES[..1], &MAGIC_BYTES[..3], &[0x50, 0x2A][..]] {
            let stream = [frame.as_slice(), prefix].concat();
            assert_eq!(
                decode_zst(&stream, 4096),
                Err("Truncated zstd input".to_string())
            );
        }
    }

    #[test]
    fn truncation_at_every_offset_is_an_error_not_a_panic() {
        let frame = encode(&noise(3000), CompressionLevel::Fastest);
        for n in 0..frame.len() {
            match decode_zst(&frame[..n], 7) {
                // Too short to bid, the raw format reads it as it is.
                Ok(out) => assert!(n < 8 && out == frame[..n], "offset {n}"),
                // Too short to bid, the open fails as an unknown format.
                Err(msg) => assert!(n < 8 || msg == "Truncated zstd input", "offset {n}: {msg}"),
            }
        }
    }

    #[test]
    fn random_mutations_do_not_panic() {
        let frame = encode(&noise(20_000), CompressionLevel::Fastest);
        let mut x = 7_u32;
        for _ in 0..300 {
            let mut m = frame.clone();
            for _ in 0..3 {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                let at = (x >> 8) as usize % m.len();
                m[at] = (x >> 4) as u8;
            }
            let _ = decode_zst(&m, 4096);
        }
    }
}
