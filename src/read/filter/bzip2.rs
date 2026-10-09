/*-
 * Copyright (c) 2003-2007 Tim Kientzle
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

// Ported from libarchive/archive_read_support_filter_bzip2.c.

//! The bzip2 filter: decompresses one or more concatenated bzip2 streams.

use crate::archive::*;
use crate::read::{Filter, FilterBidder, Read, Reader, Status, filter_code};
use crate::util::Error;
use crabz2::{BlockDecoder, Step};
use std::ffi::{CStr, c_int};

/// The output block size, as upstream's.
const BLOCK: usize = 64 * 1024;

/// `archive_read_support_filter_bzip2`.
pub fn support(r: &mut Read, _: &Base) -> Result<Status, Error> {
    r.register_bidder(Box::new(Bidder))
}

/// Tests whether the stream is bzip2, so that the error can be better than
/// "Unrecognized archive format". A bzip2 archive is at least 14 bytes, and
/// the bid is 24 bits of "BZh", 5 of the block size digit and 48 of the
/// block (or end-of-data) magic.
fn bid(up: &mut Reader<'_>) -> c_int {
    // An error reading ahead is a failed bid, as upstream's NULL is.
    let Ok(Some(buf)) = up.read_ahead(14) else {
        return 0;
    };
    if signature(buf) { 77 } else { 0 }
}

fn signature(buf: &[u8]) -> bool {
    let block = buf.get(4..10).unwrap_or_default();
    buf.len() >= 14
        && buf.starts_with(b"BZh")
        && buf.get(3).is_some_and(|d| (b'1'..=b'9').contains(d))
        && (block == b"\x31\x41\x59\x26\x53\x59" || block == b"\x17\x72\x45\x38\x50\x90")
}

struct Bidder;

impl FilterBidder for Bidder {
    fn bid(&mut self, up: &mut Reader<'_>) -> Result<c_int, Error> {
        Ok(bid(up))
    }

    fn init(&mut self, _up: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
        let mut out = Vec::new();
        out.try_reserve_exact(BLOCK).map_err(|_| {
            Error::fatal(libc::ENOMEM, "Can't allocate data for bzip2 decompression")
        })?;
        out.resize(BLOCK, 0);
        Ok(Box::new(Bzip2 {
            decoder: BlockDecoder::new(),
            pending: Vec::new(),
            next: 0,
            eof: false,
            out,
            len: 0,
        }))
    }
}

struct Bzip2 {
    decoder: BlockDecoder,
    /// One decoded bzip2 block, drained in 64 KiB pieces.
    pending: Vec<u8>,
    next: usize,
    eof: bool,
    /// The output block; its first `len` bytes are the current block.
    out: Vec<u8>,
    len: usize,
}

impl Filter for Bzip2 {
    fn name(&self) -> &CStr {
        c"bzip2"
    }

    fn code(&self) -> c_int {
        filter_code::BZIP2
    }

    /// Fills the output block, or ends at the first input that is not
    /// another bzip2 stream. Trailing bytes that do not bid are ignored.
    fn read(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
        self.len = 0;
        while !self.eof && self.len < self.out.len() {
            if self.next < self.pending.len() {
                let n = (self.pending.len() - self.next).min(self.out.len() - self.len);
                self.out[self.len..self.len + n]
                    .copy_from_slice(&self.pending[self.next..self.next + n]);
                self.next += n;
                self.len += n;
                continue;
            }
            self.pending.clear();
            self.next = 0;
            // A block has at most 900,000 Huffman symbols, each at most
            // 23 bits, plus tables. Bound compressed read-ahead to 3 MiB.
            const MAX_INPUT: usize = 3 * 1024 * 1024;
            let mut want = 4096;
            loop {
                let input = up.peek_available(want)?;
                let short = input.len() < want;
                let before = self.decoder.consumed();
                let decoded = self.decoder.next_block(input, &mut self.pending);
                let committed = self.decoder.consumed();
                // Advancing past the previous block by more than a header
                // means the end marker and CRC were checked. Upstream ignores
                // a following tail that does not bid as another member.
                let ended = committed.saturating_sub(before) > 4;
                let next_member =
                    signature(input.get(committed.saturating_sub(4)..).unwrap_or_default());
                match decoded {
                    Ok(step) => {
                        let used = self.decoder.consumed();
                        self.decoder.rebase(used);
                        up.consume(used)?;
                        if step == Step::Eof {
                            // The library stops at a clean boundary; another
                            // member may follow once more input is available.
                            if up.read_ahead(1)?.is_none() {
                                self.eof = true;
                            } else {
                                continue;
                            }
                        }
                        break;
                    }
                    Err(error)
                        if ended
                            && (error == crabz2::Error::InvalidMagic
                                || (error == crabz2::Error::Truncated
                                    && short
                                    && !next_member)) =>
                    {
                        // The last committed boundary is either the end
                        // marker or a following four-byte member header.
                        // Locate the checked marker at its bit alignment;
                        // consumed() counts only whole bytes.
                        let mut end = None;
                        for byte in [
                            committed,
                            committed.saturating_sub(4),
                            committed.saturating_sub(5),
                        ] {
                            let Some(start) = byte.checked_sub(10) else {
                                continue;
                            };
                            let Some(magic) = input.get(start..start + 7) else {
                                continue;
                            };
                            let word = magic.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b));
                            for bit in 0..8 {
                                if (word >> (8 - bit)) & 0xffff_ffff_ffff == 0x1772_4538_5090 {
                                    end = Some(byte + usize::from(bit != 0));
                                }
                            }
                        }
                        let used = end.ok_or_else(|| {
                            Error::fatal(ARCHIVE_ERRNO_MISC, "bzip decompression failed")
                        })?;
                        up.consume(used)?;
                        self.eof = true;
                        break;
                    }
                    Err(crabz2::Error::Truncated) if !short && want < MAX_INPUT => {
                        want = (want * 2).min(MAX_INPUT);
                    }
                    Err(crabz2::Error::Truncated) if short => {
                        return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "truncated bzip2 input"));
                    }
                    Err(_) => {
                        return Err(Error::fatal(
                            ARCHIVE_ERRNO_MISC,
                            "bzip decompression failed",
                        ));
                    }
                }
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

    fn encode(data: &[u8]) -> Vec<u8> {
        crabz2::compress(data, crabz2::Level::BEST)
    }

    fn decode_bz(data: &[u8], block: usize) -> Result<Vec<u8>, String> {
        decode(support, data, block)
    }

    #[test]
    fn decodes_at_any_block_size() {
        let data = noise(5000);
        let stream = encode(&data);
        for block in [1, 3, 7, 1000, 1 << 20] {
            assert_eq!(decode_bz(&stream, block).unwrap(), data, "block {block}");
        }
    }

    #[test]
    fn decodes_output_past_one_block() {
        let data = noise(200_000);
        assert_eq!(decode_bz(&encode(&data), 1000).unwrap(), data);
    }

    #[test]
    fn decodes_concatenated_streams() {
        let (a, b) = (noise(100), b"second member\n".repeat(40));
        let stream = [encode(&a), encode(&b)].concat();
        let want = [a, b].concat();
        for block in [1, 13, 4096] {
            assert_eq!(decode_bz(&stream, block).unwrap(), want, "block {block}");
        }
    }

    #[test]
    fn ignores_trailing_bytes_that_do_not_bid() {
        let data = b"payload".to_vec();
        let mut stream = encode(&data);
        stream.extend_from_slice(b"junk that is not bzip2 at all");
        assert_eq!(decode_bz(&stream, 5).unwrap(), data);
    }

    #[test]
    fn consumes_the_end_marker_without_consuming_trailing_garbage() {
        use crate::read::{Read, format::raw};
        use crate::read_open_memory::Memory;
        let payload = b"payload";
        let encoded = encode(payload);
        for tail in [
            b"x".as_slice(),
            b"junk that is not bzip2",
            b"BZh9junk",
            b"BZh",
        ] {
            let bytes = [&encoded, tail].concat();
            let a = Base::new(READ_MAGIC);
            let mut r = Read::default();
            assert_eq!(support(&mut r, &a).unwrap(), Status::Ok);
            assert_eq!(raw::support(&mut r).unwrap(), Status::Ok);
            assert_eq!(r.open(&a, Box::new(Memory::new(bytes, 7))), ARCHIVE_OK);
            assert_eq!(r.filter_bytes(-1), encoded.len() as i64, "tail {tail:?}");
        }
    }

    #[test]
    fn truncation_at_every_offset_is_an_error_not_a_panic() {
        let stream = encode(&noise(3000));
        for n in 0..stream.len() {
            match decode_bz(&stream[..n], 7) {
                // Too short to bid, the raw format reads it as it is.
                Ok(out) => assert!(n < 14 && out == stream[..n], "offset {n}"),
                // Too short to bid, the open fails as an unknown format.
                Err(msg) => assert!(
                    n < 14 || msg == "truncated bzip2 input",
                    "offset {n}: {msg}"
                ),
            }
        }
    }

    #[test]
    fn a_truncated_second_member_is_not_a_trailing_tail() {
        let first = encode(b"first member");
        let second = encode(&noise(3000));
        for end in [14, second.len() / 2, second.len() - 1] {
            let stream = [&first, &second[..end]].concat();
            assert!(decode_bz(&stream, 7).is_err(), "second member cut at {end}");
        }
    }

    #[test]
    fn random_mutations_do_not_panic() {
        let stream = encode(&noise(20_000));
        let mut x = 99_u32;
        for _ in 0..300 {
            let mut m = stream.clone();
            for _ in 0..3 {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                let at = (x >> 8) as usize % m.len();
                m[at] = (x >> 4) as u8;
            }
            let _ = decode_bz(&m, 4096);
        }
    }
}
