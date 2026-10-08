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
use bzip2::{Decompress, Status as Bz};
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
    let block = buf.get(4..10).unwrap_or_default();
    let digit = buf.get(3).is_some_and(|d| (b'1'..=b'9').contains(d));
    if buf.starts_with(b"BZh")
        && digit
        && (block == b"\x31\x41\x59\x26\x53\x59" || block == b"\x17\x72\x45\x38\x50\x90")
    {
        77
    } else {
        0
    }
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
            stream: None,
            eof: false,
            out,
            len: 0,
        }))
    }
}

struct Bzip2 {
    /// The decompressor of the stream being read; `None` between streams.
    stream: Option<Decompress>,
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
            let Some(stream) = self.stream.as_mut() else {
                if bid(up) == 0 {
                    self.eof = true;
                } else {
                    self.stream = Some(Decompress::new(false));
                }
                continue;
            };
            // Upstream reports a failed read and the end of input alike.
            let input = match up.read_ahead(1) {
                Ok(Some(input)) => input,
                _ => return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "truncated bzip2 input")),
            };
            let (in_before, out_before) = (stream.total_in(), stream.total_out());
            let status = stream.decompress(input, self.out.get_mut(self.len..).unwrap_or_default());
            let used = stream.total_in().saturating_sub(in_before);
            let made = stream.total_out().saturating_sub(out_before);
            self.len += usize::try_from(made).unwrap_or(0);
            up.consume(used)?;
            match status {
                Ok(Bz::Ok) => {}
                Ok(Bz::StreamEnd) => self.stream = None,
                _ => {
                    return Err(Error::fatal(
                        ARCHIVE_ERRNO_MISC,
                        "bzip decompression failed",
                    ));
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
    use bzip2::Compression;
    use bzip2::read::BzEncoder;
    use std::io::Read as _;

    fn encode(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        BzEncoder::new(data, Compression::best())
            .read_to_end(&mut out)
            .unwrap();
        out
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
