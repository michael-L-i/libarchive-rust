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
use crabz2::BlockDecoder;
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

/// Bound on the compressed bytes held for one block: a block has at most
/// 900,000 Huffman symbols, each at most 23 bits, plus tables.
const MAX_INPUT: usize = 3 * 1024 * 1024;

/// What one `Decoder::decompress` call did, as `BZ2_bzDecompress` reports it
/// through `avail_in`, `avail_out` and `BZ_STREAM_END`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Progress {
    /// Bytes of `input` consumed. Input that is not used is not held, so the
    /// caller presents it again; at the end of the stream, whatever follows
    /// the end marker is not used.
    pub used: usize,
    /// Bytes written to the start of `output`.
    pub produced: usize,
    /// The end of the stream was reached and all of it has been produced.
    pub end: bool,
}

/// A streaming decoder of one bzip2 stream with the interface of
/// `BZ2_bzDecompress`: it takes whatever input and output space the caller
/// has. The end of the input in the middle of a stream is not an error here;
/// the caller sees it as no `end` and no more input.
///
/// crabz2 decodes whole blocks, so the compressed bytes of an unfinished block
/// are kept (at most 3 MiB) and decoded again when more arrive.
pub(crate) struct Decoder {
    dec: BlockDecoder,
    /// Input taken but not yet part of a decoded block.
    inbuf: Vec<u8>,
    /// The decoded block being handed out from `next`.
    pending: Vec<u8>,
    next: usize,
    /// The stream header has been read.
    started: bool,
    /// The next item is known to be a block, not the end marker.
    in_block: bool,
    done: bool,
}

/// How `Decoder::step` left the input.
enum Next {
    NeedInput,
    /// A block was decoded into `pending`, ending in byte `.0` of `inbuf`.
    Block(usize),
    /// The end marker ended in byte `.0` of `inbuf`.
    End(usize),
}

impl Decoder {
    pub(crate) fn new() -> Decoder {
        Decoder {
            dec: BlockDecoder::new(),
            inbuf: Vec::new(),
            pending: Vec::new(),
            next: 0,
            started: false,
            in_block: false,
            done: false,
        }
    }

    /// How much input `decompress` takes at once unless it is the `last`: a
    /// retry decodes the unfinished block again, so taking input in doubling
    /// pieces keeps the work linear. Callers present
    /// `peek_available(wanted())`.
    pub(crate) fn wanted(&self) -> usize {
        let held = self.inbuf.len();
        held.max(4096).min(MAX_INPUT - held).max(1)
    }

    /// `BZ2_bzDecompress`: consumes some of `input` and fills some of
    /// `output`. Any error is the stream being corrupt. Unless `last` (the
    /// read was cut short by the end of the input, or of the packed data),
    /// fewer than `wanted()` bytes of input are left alone: nothing is
    /// consumed and the caller presents more.
    pub(crate) fn decompress(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        last: bool,
    ) -> Result<Progress, crabz2::Error> {
        let mut p = Progress {
            end: self.done,
            ..Progress::default()
        };
        while !self.done {
            let held = self.pending.get(self.next..).unwrap_or_default();
            let n = held.len().min(output.len() - p.produced);
            let (now, _) = held.split_at(n);
            output[p.produced..p.produced + n].copy_from_slice(now);
            p.produced += n;
            self.next += n;
            if self.next < self.pending.len() || p.produced == output.len() {
                return Ok(p);
            }
            self.pending.clear();
            self.next = 0;

            let rest = input.get(p.used..).unwrap_or_default();
            if !last && rest.len() < self.wanted() {
                return Ok(p);
            }
            let take = rest.len().min(MAX_INPUT - self.inbuf.len());
            if take == 0 {
                return if rest.is_empty() {
                    Ok(p)
                } else {
                    Err(crabz2::Error::BlockOverflow)
                };
            }
            self.inbuf
                .extend_from_slice(rest.get(..take).unwrap_or_default());
            let next = self.step()?;
            match next {
                Next::NeedInput => p.used += take,
                Next::Block(at) | Next::End(at) => {
                    p.used += take - (self.inbuf.len() - at);
                    self.inbuf.clear();
                    self.dec.rebase(at);
                    self.done = matches!(next, Next::End(_));
                }
            }
        }
        p.end = true;
        Ok(p)
    }

    /// Looks at the held input for the stream header, the end marker, or a
    /// whole block.
    fn step(&mut self) -> Result<Next, crabz2::Error> {
        if !self.started {
            let Some(header) = self.inbuf.get(..4) else {
                return Ok(Next::NeedInput);
            };
            // The header commits; the block magic after it is not there yet.
            match self.dec.next_block(header, &mut self.pending) {
                Err(crabz2::Error::Truncated) => {}
                Err(e) => return Err(e),
                Ok(_) => return Err(crabz2::Error::InvalidBlock),
            }
            self.started = true;
            let at = self.dec.consumed();
            self.inbuf.drain(..at);
            self.dec.rebase(at);
        }
        if !self.in_block {
            // The end marker is 10 bytes (48 bits of magic, 32 of CRC),
            // starting at some bit of the next byte: the decoder only
            // reaches the clean end of its input once it is byte aligned,
            // which a 10 or an 11 byte view of it shows. A block needs more.
            for len in [10, 11] {
                let Some(head) = self.inbuf.get(..len) else {
                    return Ok(Next::NeedInput);
                };
                match self.dec.next_block(head, &mut self.pending) {
                    Ok(crabz2::Step::Eof) => return Ok(Next::End(self.dec.consumed())),
                    Err(crabz2::Error::Truncated) => {}
                    Err(e) => return Err(e),
                    Ok(crabz2::Step::Block) => return Err(crabz2::Error::InvalidBlock),
                }
            }
            self.in_block = true;
        }
        match self.dec.next_block(&self.inbuf, &mut self.pending) {
            Ok(crabz2::Step::Block) => {
                self.in_block = false;
                Ok(Next::Block(self.dec.consumed()))
            }
            Err(crabz2::Error::Truncated) => Ok(Next::NeedInput),
            Err(e) => Err(e),
            Ok(crabz2::Step::Eof) => Err(crabz2::Error::InvalidBlock),
        }
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
            decoder: None,
            eof: false,
            out,
            len: 0,
        }))
    }
}

struct Bzip2 {
    /// The stream being decoded; `None` between streams.
    decoder: Option<Decoder>,
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
            let dec = match &mut self.decoder {
                Some(dec) => dec,
                None if bid(up) == 0 => {
                    self.eof = true;
                    break;
                }
                None => self.decoder.insert(Decoder::new()),
            };
            let wanted = dec.wanted();
            let input = up.peek_available(wanted)?;
            if input.is_empty() {
                return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "truncated bzip2 input"));
            }
            let p = dec
                .decompress(
                    input,
                    self.out.get_mut(self.len..).unwrap_or_default(),
                    input.len() < wanted,
                )
                .map_err(|_| Error::fatal(ARCHIVE_ERRNO_MISC, "bzip decompression failed"))?;
            up.consume(p.used)?;
            self.len += p.produced;
            if p.end {
                self.decoder = None;
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

    /// Drives a `Decoder` as the zip, 7zip and xar readers do: at least
    /// `input_step` bytes of what is left, and `wanted()` if more, each call;
    /// `output_step` bytes of room; `last` when the input runs out.
    fn drive(
        stream: &[u8],
        input_step: usize,
        output_step: usize,
    ) -> Result<(Vec<u8>, usize, bool), crabz2::Error> {
        let mut dec = Decoder::new();
        let (mut out, mut pos) = (Vec::new(), 0);
        loop {
            let n = input_step.max(dec.wanted());
            let input = &stream[pos..stream.len().min(pos + n)];
            let mut room = vec![0; output_step];
            let p = dec.decompress(input, &mut room, pos + input.len() == stream.len())?;
            out.extend_from_slice(&room[..p.produced]);
            pos += p.used;
            if p.end {
                return Ok((out, pos, true));
            }
            if p.used == 0 && p.produced == 0 {
                return Ok((out, pos, false));
            }
        }
    }

    #[test]
    fn decoder_stops_exactly_at_the_end_of_the_stream() {
        let data = noise(30_000);
        let stream = encode(&data);
        let tail = b"BZh9 not part of it, and neither is this";
        let all = [stream.as_slice(), tail].concat();
        for (i, o) in [
            (1, 1),
            (7, 5),
            (100, 4096),
            (1 << 20, 1 << 20),
            (13, 1 << 20),
        ] {
            assert_eq!(
                drive(&all, i, o).unwrap(),
                (data.clone(), stream.len(), true),
                "steps {i} {o}"
            );
        }
    }

    #[test]
    fn decoder_takes_small_pieces_only_as_the_last() {
        let data = noise(30_000);
        let stream = encode(&data);
        let mut dec = Decoder::new();
        let mut room = [0; 64];
        // Short of wanted() and not the last: nothing is consumed.
        for piece in [1, 100, 4095] {
            let p = dec.decompress(&stream[..piece], &mut room, false).unwrap();
            assert_eq!(p, Progress::default(), "piece {piece}");
        }
        // The same short pieces as the last decode, and `used` is exact.
        let tail = [stream.as_slice(), b"BZh9 trailing".as_slice()].concat();
        let (mut out, mut pos) = (Vec::new(), 0);
        loop {
            let input = &tail[pos..tail.len().min(pos + 100)];
            let mut room = vec![0; 1000];
            let p = dec.decompress(input, &mut room, true).unwrap();
            out.extend_from_slice(&room[..p.produced]);
            pos += p.used;
            if p.end {
                break;
            }
        }
        assert_eq!((out, pos), (data, stream.len()));
    }

    #[test]
    fn decoder_ends_an_empty_stream_and_the_next_one_starts_fresh() {
        let empty = encode(b"");
        let second = encode(b"after");
        let all = [empty.as_slice(), second.as_slice()].concat();
        for i in [1, 3, 14, 1000] {
            let (out, used, end) = drive(&all, i, 64).unwrap();
            assert_eq!((out.len(), used, end), (0, empty.len(), true), "step {i}");
            let (out, used, end) = drive(&all[used..], i, 64).unwrap();
            assert_eq!((out, used, end), (b"after".to_vec(), second.len(), true));
        }
    }

    #[test]
    fn decoder_waits_for_input_and_reports_corruption() {
        let stream = encode(&noise(3000));
        for n in (0..stream.len()).step_by(11) {
            let (_, used, end) = drive(&stream[..n], 97, 100).unwrap();
            assert!(!end && used == n, "cut at {n}");
        }
        let mut bad = stream.clone();
        bad[0] = b'X';
        assert_eq!(drive(&bad, 100, 100), Err(crabz2::Error::InvalidMagic));
        let mut bad = stream.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x10;
        assert!(drive(&bad, 100, 100).is_err());
        // Past the 3 MiB a block can need.
        let mut dec = Decoder::new();
        let mut junk = b"BZh9\x31\x41\x59\x26\x53\x59".to_vec();
        junk.resize(MAX_INPUT + 10, 0xff);
        let mut out = [0; 16];
        let mut result = Ok(Progress::default());
        let mut pos = 0;
        while pos < junk.len() && result.is_ok() {
            result = dec.decompress(&junk[pos..], &mut out, false);
            pos += result.as_ref().map_or(0, |p| p.used);
        }
        assert!(result.is_err());
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
