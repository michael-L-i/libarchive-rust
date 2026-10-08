/*-
 * Copyright (c) 2009-2011 Michihiro NAKAJIMA
 * Copyright (c) 2003-2008 Tim Kientzle and Miklos Vajna
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

// Ported from libarchive/archive_read_support_filter_xz.c.

//! The xz, lzma (lzma_alone) and lzip filters, which share one decoder.
//! liblzma is replaced by the pure Rust `xz` crate, a port of liblzma 5.8.

use crate::archive::*;
use crate::read::{Filter, FilterBidder, Read, Reader, Status, filter_code};
use crate::util::Error;
use std::ffi::{CStr, c_int};
use xz::stream::{self, Action, Filters, Stream};

/// The three formats this decoder handles.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Xz,
    Lzma,
    Lzip,
}

impl Kind {
    fn code(self) -> c_int {
        match self {
            Kind::Xz => filter_code::XZ,
            Kind::Lzma => filter_code::LZMA,
            Kind::Lzip => filter_code::LZIP,
        }
    }

    fn name(self) -> &'static CStr {
        match self {
            Kind::Xz => c"xz",
            Kind::Lzma => c"lzma",
            Kind::Lzip => c"lzip",
        }
    }
}

fn support(r: &mut Read, kind: Kind) -> Result<Status, Error> {
    r.register_bidder(Box::new(Bidder(kind)))
}

/// `archive_read_support_filter_xz`.
pub fn support_xz(r: &mut Read) -> Result<Status, Error> {
    support(r, Kind::Xz)
}

/// `archive_read_support_filter_lzma`.
pub fn support_lzma(r: &mut Read) -> Result<Status, Error> {
    support(r, Kind::Lzma)
}

/// `archive_read_support_filter_lzip`.
pub fn support_lzip(r: &mut Read) -> Result<Status, Error> {
    support(r, Kind::Lzip)
}

const OUT_BLOCK_SIZE: usize = 64 * 1024;

fn misc(msg: &str) -> Error {
    Error::fatal(ARCHIVE_ERRNO_MISC, msg)
}

/// Chooses an error message for a failure of the library.
fn failure(e: stream::Error) -> Error {
    match e {
        stream::Error::Mem => {
            Error::fatal(libc::ENOMEM, "Lzma library error: Cannot allocate memory")
        }
        stream::Error::MemLimit => Error::fatal(libc::ENOMEM, "Lzma library error: Out of memory"),
        stream::Error::Format => misc("Lzma library error: format not recognized"),
        stream::Error::Options => misc("Lzma library error: Invalid options"),
        stream::Error::Data => misc("Lzma library error: Corrupted input data"),
        _ => misc("Lzma decompression failed:  Unknown error"),
    }
}

struct Bidder(Kind);

impl FilterBidder for Bidder {
    fn bid(&mut self, up: &mut Reader<'_>) -> Result<c_int, Error> {
        match self.0 {
            Kind::Xz => xz_bid(up),
            Kind::Lzma => lzma_bid(up),
            Kind::Lzip => lzip_has_member(up),
        }
    }

    fn init(&mut self, _up: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(Xz::new(self.0)?))
    }
}

/// Test whether we can handle this data: the xz header magic bytes.
fn xz_bid(up: &mut Reader<'_>) -> Result<c_int, Error> {
    Ok(match up.read_ahead(6)? {
        Some(h) if h.starts_with(b"\xFD\x37\x7A\x58\x5A\x00") => 48,
        _ => 0,
    })
}

/// Test whether we can handle this data.
///
/// <sigh> LZMA has a rather poor file signature.  Zeros do not
/// make good signature bytes as a rule, and the only non-zero byte
/// here is an ASCII character.  For example, an uncompressed tar
/// archive whose first file is ']' would satisfy this check.  It may
/// be necessary to exclude LZMA from compression_all() because of
/// this.  Clients of libarchive would then have to explicitly enable
/// LZMA checking instead of (or in addition to) compression_all() when
/// they have other evidence (file name, command-line option) to go on.
fn lzma_bid(up: &mut Reader<'_>) -> Result<c_int, Error> {
    let Some(&[props, d0, d1, d2, d3, s0, s1, s2, s3, s4, s5, s6, s7, _]) =
        up.read_ahead(14)?.and_then(|h| h.first_chunk())
    else {
        return Ok(0);
    };

    // First byte of raw LZMA stream is commonly 0x5d.
    // The first byte is a special number, which consists of
    // three parameters of LZMA compression, a number of literal
    // context bits(which is from 0 to 8, default is 3), a number
    // of literal pos bits(which is from 0 to 4, default is 0),
    // a number of pos bits(which is from 0 to 4, default is 2).
    // The first byte is made by
    // (pos bits * 5 + literal pos bit) * 9 + * literal contest bit,
    // and so the default value in this field is
    // (2 * 5 + 0) * 9 + 3 = 0x5d.
    // lzma of LZMA SDK has options to change those parameters.
    // It means a range of this field is from 0 to 224. And lzma of
    // XZ Utils with option -e records 0x5e in this field.
    // NOTE: If this checking of the first byte increases false
    // recognition, we should allow only 0x5d and 0x5e for the first
    // byte of LZMA stream.
    if props > (4 * 5 + 4) * 9 + 8 {
        return Ok(0);
    }
    let mut bits_checked = 0;
    // Most likely value in the first byte of LZMA stream.
    if props == 0x5d || props == 0x5e {
        bits_checked += 8;
    }

    // Sixth through fourteenth bytes are uncompressed size,
    // stored in little-endian order. `-1' means uncompressed
    // size is unknown and lzma of XZ Utils always records `-1'
    // in this field.
    if u64::from_le_bytes([s0, s1, s2, s3, s4, s5, s6, s7]) == u64::MAX {
        bits_checked += 64;
    }

    // Second through fifth bytes are dictionary size, stored in
    // little-endian order. The minimum dictionary size is
    // 1 << 12(4KiB) which the lzma of LZMA SDK uses with option
    // -d12 and the maximum dictionary size is 1 << 27(128MiB)
    // which the one uses with option -d27. (XZ Utils uses 1 << 16
    // to 1 << 26 for its options -0 to -9.)
    let dicsize = u32::from_le_bytes([d0, d1, d2, d3]);
    if dicsize.is_power_of_two() && (12..=27).contains(&dicsize.trailing_zeros()) {
        bits_checked += 32;
    } else if (0x0030_0000..=0x03F0_0000).contains(&dicsize)
        && dicsize & ((1 << 20) - 1) == 0
        && bits_checked == 8 + 64
    {
        // If a memory usage for encoding was not enough on
        // the platform where LZMA stream was made, lzma of
        // XZ Utils automatically decreased the dictionary
        // size to enough memory for encoding by 1Mi bytes
        // (1 << 20).
        bits_checked += 32;
    } else {
        // Otherwise dictionary size is unlikely. But it is
        // possible that someone makes lzma stream with
        // liblzma/LZMA SDK in one's dictionary size.
        return Ok(0);
    }

    // TODO: The above test is still very weak.  It would be
    // good to do better.

    Ok(bits_checked)
}

/// 48 if a lzip member header starts here: the magic bytes `LZIP`, a
/// version of 0 or 1, and a dictionary size of 1 << 12 to 1 << 29.
fn lzip_has_member(up: &mut Reader<'_>) -> Result<c_int, Error> {
    let valid = |h: &[u8]| {
        h.starts_with(b"LZIP")
            && matches!(h.get(4), Some(0 | 1))
            && h.get(5).is_some_and(|d| (12..=29).contains(&(d & 0x1f)))
    };
    Ok(match up.read_ahead(6)? {
        Some(h) if valid(h) => 48,
        _ => 0,
    })
}

/// The decoder of all three filters.
struct Xz {
    kind: Kind,
    /// `None` between lzip members: the library is initialized from the
    /// header of each.
    stream: Option<Stream>,
    out: Vec<u8>,
    /// The length of the block `read` produced.
    block: usize,
    /// True = found end of compressed data.
    eof: bool,

    // Following variables are used for lzip only.
    lzip_ver: u8,
    crc32: u32,
    member_in: u64,
    member_out: u64,
}

impl Xz {
    /// Sets up the library. xz and lzma are decoded with no memory limit.
    fn new(kind: Kind) -> Result<Self, Error> {
        let stream = match kind {
            Kind::Xz => Some(Stream::new_stream_decoder(u64::MAX, stream::CONCATENATED)),
            Kind::Lzma => Some(Stream::new_lzma_decoder(u64::MAX)),
            Kind::Lzip => None,
        };
        Ok(Xz {
            kind,
            stream: stream.transpose().map_err(failure)?,
            out: vec![0; OUT_BLOCK_SIZE],
            block: 0,
            eof: false,
            lzip_ver: 0,
            crc32: 0,
            member_in: 0,
            member_out: 0,
        })
    }

    /// Initializes the library from the header of a lzip member.
    fn lzip_init(&mut self, up: &mut Reader<'_>) -> Result<Stream, Error> {
        let Some(&[.., ver, log2dic]) = up.read_ahead(6)?.and_then(|h| h.first_chunk::<6>()) else {
            // Unreachable: a bid has already seen the whole header.
            return Err(misc("truncated input"));
        };
        self.lzip_ver = ver;

        // Setup lzma property.
        let mut dicsize = 1u32 << (log2dic & 0x1f);
        if log2dic & 0x1f > 12 {
            dicsize -= (dicsize / 16) * u32::from(log2dic >> 5);
        }
        let mut props = [0x5d; 5];
        props[1..].copy_from_slice(&dicsize.to_le_bytes());

        // Consume lzip header.
        up.consume(6)?;
        self.member_in = 6;

        let mut filters = Filters::new();
        filters.lzma1_properties(&props).map_err(failure)?;
        Stream::new_raw_decoder(&filters).map_err(failure)
    }

    /// Checks the trailer of a lzip member, and prepares for the next member
    /// if there is one.
    fn lzip_tail(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
        let tail = if self.lzip_ver == 0 { 12 } else { 20 };
        let failed = |msg: &str| Error::new(ARCHIVE_FAILED, ARCHIVE_ERRNO_MISC, msg);
        let trailer = up.read_ahead(tail)?.and_then(|p| {
            let (crc, p) = p.split_first_chunk::<4>()?;
            let (size, p) = p.split_first_chunk::<8>()?;
            let member = p.first_chunk().copied().map(u64::from_le_bytes);
            Some((u32::from_le_bytes(*crc), u64::from_le_bytes(*size), member))
        });
        let Some((crc, size, member)) = trailer else {
            return Err(failed("Lzip: Remaining data is less bytes"));
        };

        // Check the crc32 value of the uncompressed data of the current
        // member
        if self.crc32 != crc {
            return Err(failed("Lzip: CRC32 error"));
        }

        // Check the uncompressed size of the current member
        if self.member_out != size {
            return Err(failed("Lzip: Uncompressed size error"));
        }

        // Check the total size of the current member
        if self.lzip_ver == 1 && self.member_in.checked_add(20) != member {
            return Err(failed("Lzip: Member size error"));
        }
        up.consume(tail)?;

        // If current lzip data consists of multi member, try decompressing
        // a next member.
        if lzip_has_member(up)? != 0 {
            self.stream = None;
            self.crc32 = 0;
            self.member_out = 0;
            self.member_in = 0;
            self.eof = false;
        }
        Ok(())
    }
}

impl Filter for Xz {
    fn name(&self) -> &CStr {
        self.kind.name()
    }

    fn code(&self) -> c_int {
        self.kind.code()
    }

    /// Return the next block of decompressed data.
    fn read(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
        loop {
            let member_in = self.member_in;
            let mut filled = 0;

            // Try to fill the output buffer.
            while filled < self.out.len() && !self.eof {
                let stream = match &mut self.stream {
                    Some(stream) => stream,
                    // Initialize the library for lzip.
                    None => {
                        let stream = self.lzip_init(up)?;
                        self.stream.insert(stream)
                    }
                };
                let input = up.peek_available(1).map_err(|_| misc("truncated input"))?;

                // Decompress as much as we can in one pass.
                let action = if input.is_empty() {
                    Action::Finish
                } else {
                    Action::Run
                };
                let (in_before, out_before) = (stream.total_in(), stream.total_out());
                let space = self.out.get_mut(filled..).unwrap_or_default();
                match stream.process(input, space, action) {
                    // Found end of stream.
                    Ok(stream::Status::StreamEnd) => self.eof = true,
                    // Decompressor made some progress.
                    Ok(stream::Status::Ok) => {}
                    Ok(stream::Status::MemNeeded) => {
                        return Err(misc("Lzma library error:  No progress is possible"));
                    }
                    Ok(_) => return Err(misc("Lzma decompression failed:  Unknown error")),
                    Err(e) => return Err(failure(e)),
                }
                let used = stream.total_in() - in_before;
                filled += usize::try_from(stream.total_out() - out_before).unwrap_or_default();
                up.consume(used)?;
                self.member_in += used;
            }

            self.block = filled;
            self.member_out += filled as u64;
            if self.kind != Kind::Lzip {
                return Ok(());
            }
            if filled == 0 {
                if member_in != self.member_in && self.eof {
                    self.lzip_tail(up)?;
                    if !self.eof {
                        continue;
                    }
                }
            } else {
                let mut crc = crc32fast::Hasher::new_with_initial(self.crc32);
                crc.update(self.block());
                self.crc32 = crc.finalize();
                if self.eof {
                    self.lzip_tail(up)?;
                }
            }
            return Ok(());
        }
    }

    fn block(&self) -> &[u8] {
        self.out.get(..self.block).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Entry;
    use crate::read::{Data, Format};
    use crate::read_open_memory::Memory;
    use std::io::Write;
    use xz::stream::LzmaOptions;
    use xz::write::XzEncoder;

    type Register = fn(&mut Read) -> Result<Status, Error>;

    /// A format that takes any stream, so that tests can read the filters'
    /// output directly.
    struct Any;

    impl Format for Any {
        fn name(&self) -> &'static str {
            "any"
        }

        fn bid(&mut self, _r: &mut Reader<'_>, _best_bid: c_int) -> Result<c_int, Error> {
            Ok(1)
        }

        fn read_header(&mut self, _r: &mut Reader<'_>, _e: &mut Entry) -> Result<Status, Error> {
            Ok(Status::Eof)
        }

        fn read_data<'x>(&'x mut self, _r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
            Ok(Data::Eof { offset: 0 })
        }
    }

    fn message(a: &Base) -> String {
        a.error_string()
            .map_or_else(String::new, |m| String::from_utf8_lossy(&m).into())
    }

    /// Everything the filter chain on `data` produces, or the error message.
    /// With `register`, that filter is put on the chain without bidding;
    /// without, all three bid.
    fn decode_with(
        register: Option<Register>,
        data: &[u8],
        block: usize,
    ) -> Result<Vec<u8>, String> {
        let a = Base::new(READ_MAGIC);
        let mut r = Read::default();
        match register {
            Some(register) => {
                assert_eq!(register(&mut r).unwrap(), Status::Ok);
                assert_eq!(r.append_last_bidder(&a), ARCHIVE_OK);
            }
            None => {
                for register in [support_lzip, support_lzma, support_xz] {
                    assert_eq!(register(&mut r).unwrap(), Status::Ok);
                }
            }
        }
        assert_eq!(r.register_format(Box::new(Any)).unwrap(), Status::Ok);
        if r.open(&a, Box::new(Memory::new(data.to_vec(), block))) != ARCHIVE_OK {
            return Err(message(&a));
        }
        let mut rd = r.reader(&a);
        let mut out = Vec::new();
        loop {
            let Ok(chunk) = rd.peek_available(1) else {
                return Err(message(&a));
            };
            if chunk.is_empty() {
                return Ok(out);
            }
            out.extend_from_slice(chunk);
            let n = chunk.len();
            rd.consume(n).map_err(|_| message(&a))?;
        }
    }

    fn decode(data: &[u8], block: usize) -> Result<Vec<u8>, String> {
        decode_with(None, data, block)
    }

    /// Compressible text with some noise, `n` bytes.
    fn sample(n: usize) -> Vec<u8> {
        let mut x = 12345u32;
        (0..n)
            .map(|i| {
                x = x.wrapping_mul(1103515245).wrapping_add(12345);
                if i % 7 == 0 {
                    (x >> 16) as u8
                } else {
                    b'a' + (i % 13) as u8
                }
            })
            .collect()
    }

    fn encode(stream: Stream, data: &[u8]) -> Vec<u8> {
        let mut e = XzEncoder::new_stream(Vec::new(), stream);
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn xz(data: &[u8]) -> Vec<u8> {
        encode(
            Stream::new_easy_encoder(6, stream::Check::Crc64).unwrap(),
            data,
        )
    }

    fn lzma(data: &[u8]) -> Vec<u8> {
        let options = LzmaOptions::new_preset(6).unwrap();
        encode(Stream::new_lzma_encoder(&options).unwrap(), data)
    }

    /// A lzip member of the given version, whose trailer can be damaged.
    fn lzip_with(data: &[u8], ver: u8, crc: u32, size: u64, member: Option<u64>) -> Vec<u8> {
        let mut options = LzmaOptions::new_preset(6).unwrap();
        options.dict_size(1 << 20);
        let mut filters = Filters::new();
        filters.lzma1(&options);
        let mut m = [b"LZIP".as_slice(), &[ver, 20]].concat();
        m.extend(encode(Stream::new_raw_encoder(&filters).unwrap(), data));
        m.extend(crc.to_le_bytes());
        m.extend(size.to_le_bytes());
        if ver == 1 {
            let total = m.len() as u64 + 8;
            m.extend(member.unwrap_or(total).to_le_bytes());
        }
        m
    }

    fn lzip(data: &[u8], ver: u8) -> Vec<u8> {
        lzip_with(data, ver, crc32fast::hash(data), data.len() as u64, None)
    }

    fn lzip1(data: &[u8]) -> Vec<u8> {
        lzip(data, 1)
    }

    type Encoder = fn(&[u8]) -> Vec<u8>;

    const FORMATS: [(&str, Encoder, Register); 3] = [
        ("xz", xz, support_xz),
        ("lzma", lzma, support_lzma),
        ("lzip", lzip1, support_lzip),
    ];

    #[test]
    fn decodes_each_format_in_any_block_size() {
        let data = sample(200_000);
        for (name, encode, _) in FORMATS {
            let packed = encode(&data);
            for block in [7, 4096, 1 << 20] {
                assert_eq!(
                    decode(&packed, block).as_deref(),
                    Ok(&data[..]),
                    "{name} in {block}-byte blocks"
                );
            }
            let small = sample(500);
            assert_eq!(
                decode(&encode(&small), 1),
                Ok(small),
                "{name} in 1-byte blocks"
            );
            // Empty output, and an output of exactly the block size.
            assert_eq!(decode(&encode(b""), 3), Ok(Vec::new()), "{name} empty");
            let exact = sample(OUT_BLOCK_SIZE);
            assert_eq!(decode(&encode(&exact), 5000), Ok(exact), "{name} one block");
        }
        assert_eq!(decode(&lzip(b"v0", 0), 2), Ok(b"v0".to_vec()));
    }

    #[test]
    fn the_filter_is_named_for_its_format() {
        for (code, name, (_, encode, register)) in [
            (filter_code::XZ, c"xz", FORMATS[0]),
            (filter_code::LZMA, c"lzma", FORMATS[1]),
            (filter_code::LZIP, c"lzip", FORMATS[2]),
        ] {
            let a = Base::new(READ_MAGIC);
            let mut r = Read::default();
            assert_eq!(register(&mut r).unwrap(), Status::Ok);
            assert_eq!(r.register_format(Box::new(Any)).unwrap(), Status::Ok);
            let packed = encode(b"x");
            assert_eq!(r.open(&a, Box::new(Memory::new(packed, 100))), ARCHIVE_OK);
            assert_eq!((r.filter_code(0), r.filter_name(0)), (code, Some(name)));
        }
    }

    #[test]
    fn concatenated_streams_and_members_are_one_stream() {
        let (a, b) = (sample(1000), sample(70_000));
        let both = [a.clone(), b.clone(), a.clone()].concat();
        let streams = [xz(&a), xz(&b), xz(&a)].concat();
        assert_eq!(decode(&streams, 11), Ok(both.clone()));
        // Stream padding is a multiple of four zero bytes.
        let padded = [xz(&a), vec![0; 8], xz(&b)].concat();
        assert_eq!(decode(&padded, 1000), Ok([a.clone(), b.clone()].concat()));
        let bad_padding = [xz(&a), vec![0; 6], xz(&b)].concat();
        assert_eq!(
            decode(&bad_padding, 1000),
            Err("Lzma library error: Corrupted input data".into())
        );
        // Mixed lzip versions.
        let members = [lzip(&a, 0), lzip(&b, 1), lzip(&a, 1)].concat();
        for block in [1000, 3] {
            assert_eq!(decode(&members, block), Ok(both.clone()));
        }
    }

    #[test]
    fn lzip_trailers_are_checked() {
        let data = sample(5000);
        let (crc, size) = (crc32fast::hash(&data), data.len() as u64);
        let whole = lzip(&data, 1);
        for (packed, error) in [
            (
                lzip_with(&data, 1, crc ^ 1, size, None),
                "Lzip: CRC32 error",
            ),
            (
                lzip_with(&data, 0, crc ^ 1, size, None),
                "Lzip: CRC32 error",
            ),
            (
                lzip_with(&data, 1, crc, size + 1, None),
                "Lzip: Uncompressed size error",
            ),
            (
                lzip_with(&data, 1, crc, size, Some(1)),
                "Lzip: Member size error",
            ),
            (
                whole[..whole.len() - 1].to_vec(),
                "Lzip: Remaining data is less bytes",
            ),
            (
                [whole.clone(), lzip_with(b"x", 0, 0, 1, None)].concat(),
                "Lzip: CRC32 error",
            ),
        ] {
            assert_eq!(decode(&packed, 100), Err(error.into()));
        }
        // Version 0 has no member size to check; bytes after the last
        // member are ignored.
        let trailing = [lzip(&data, 0), b"LZIP".to_vec(), b"junk".to_vec()].concat();
        assert_eq!(decode(&trailing, 100), Ok(data));
    }

    #[test]
    fn damaged_streams_report_the_librarys_error() {
        let packed = xz(&sample(5000));
        let trailing = [&packed[..], b"garbage!"].concat();
        assert_eq!(
            decode(&trailing, 100),
            Err("Lzma library error:  No progress is possible".into())
        );
        let mut flipped = packed;
        flipped[40] ^= 0x55;
        assert_eq!(
            decode(&flipped, 100),
            Err("Lzma library error: Corrupted input data".into())
        );
        assert_eq!(
            decode_with(Some(support_lzip), b"LZI", 100),
            Err("truncated input".into())
        );
    }

    #[test]
    fn truncation_never_panics_and_never_succeeds() {
        let data = sample(3000);
        for (name, encode, register) in FORMATS {
            let packed = encode(&data);
            for len in 0..packed.len() {
                let cut = &packed[..len];
                assert!(
                    decode_with(Some(register), cut, 64).is_err(),
                    "{name} cut at {len}"
                );
                // With bidding too: a cut too short for its bid is read as
                // plain data, so only the absence of a panic is checked.
                let _ = decode(cut, 1);
            }
            assert_eq!(
                decode_with(Some(register), &packed, 64).as_deref(),
                Ok(&data[..])
            );
        }
    }

    #[test]
    fn mutated_streams_never_panic() {
        let data = sample(2000);
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for (_, encode, _) in FORMATS {
            let packed = encode(&data);
            for _ in 0..300 {
                let mut m = packed.clone();
                for _ in 0..=next() % 3 {
                    let at = (next() % m.len() as u64) as usize;
                    m[at] ^= 1 << (next() % 8);
                }
                let _ = decode(&m, 1 + (next() % 200) as usize);
            }
        }
    }

    /// The bid of `bidder` on `data`.
    fn bid(bidder: fn(&mut Reader<'_>) -> Result<c_int, Error>, data: &[u8]) -> c_int {
        let a = Base::new(READ_MAGIC);
        let mut r = Read::default();
        assert_eq!(r.register_format(Box::new(Any)).unwrap(), Status::Ok);
        assert_eq!(
            r.open(&a, Box::new(Memory::new(data.to_vec(), 5))),
            ARCHIVE_OK
        );
        bidder(&mut r.reader(&a)).unwrap()
    }

    #[test]
    fn bids_follow_upstream() {
        assert_eq!(bid(xz_bid, b"\xFD7zXZ\0"), 48);
        assert_eq!(bid(xz_bid, b"\xFD7zXZ\x01"), 0);
        assert_eq!(bid(xz_bid, b"\xFD7zXZ"), 0);

        assert_eq!(bid(lzip_has_member, b"LZIP\x01\x14"), 48);
        assert_eq!(bid(lzip_has_member, b"LZIP\x00\x0c"), 48);
        assert_eq!(bid(lzip_has_member, b"LZIP\x02\x14"), 0);
        assert_eq!(bid(lzip_has_member, b"LZIP\x01\x0b"), 0);
        // The top three bits of the dictionary byte are a fraction.
        assert_eq!(bid(lzip_has_member, b"LZIP\x01\xf4"), 48);
        assert_eq!(bid(lzip_has_member, b"LZIP\x01\x1e"), 0);
        assert_eq!(bid(lzip_has_member, b"LZIQ\x01\x14"), 0);

        let header = |props: u8, dict: u32, size: u64| {
            [&[props][..], &dict.to_le_bytes(), &size.to_le_bytes(), &[0]].concat()
        };
        let unknown = u64::MAX;
        assert_eq!(bid(lzma_bid, &header(0x5d, 1 << 24, unknown)), 8 + 64 + 32);
        assert_eq!(bid(lzma_bid, &header(0x5e, 1 << 12, unknown)), 8 + 64 + 32);
        assert_eq!(bid(lzma_bid, &header(0x5d, 1 << 27, 100)), 8 + 32);
        assert_eq!(bid(lzma_bid, &header(0x00, 1 << 16, 100)), 32);
        assert_eq!(bid(lzma_bid, &header(0xe0, 1 << 16, unknown)), 64 + 32);
        assert_eq!(bid(lzma_bid, &header(0xe1, 1 << 16, unknown)), 0);
        // Dictionaries that are not a power of two: whole MiBs from 3 to 63,
        // only for the usual properties and an unknown size.
        assert_eq!(
            bid(lzma_bid, &header(0x5d, 0x0050_0000, unknown)),
            8 + 64 + 32
        );
        assert_eq!(
            bid(lzma_bid, &header(0x5d, 0x03F0_0000, unknown)),
            8 + 64 + 32
        );
        assert_eq!(
            bid(lzma_bid, &header(0x5d, 0x0400_0000, unknown)),
            8 + 64 + 32
        );
        assert_eq!(bid(lzma_bid, &header(0x5d, 0x0410_0000, unknown)), 0);
        assert_eq!(bid(lzma_bid, &header(0x5d, 0x0050_0000, 100)), 0);
        assert_eq!(bid(lzma_bid, &header(0x00, 0x0050_0000, unknown)), 0);
        assert_eq!(bid(lzma_bid, &header(0x5d, 0x0050_0001, unknown)), 0);
        assert_eq!(bid(lzma_bid, &header(0x5d, 1 << 28, unknown)), 0);
        assert_eq!(bid(lzma_bid, &header(0x5d, 1 << 11, unknown)), 0);
        assert_eq!(bid(lzma_bid, &header(0x5d, 0, unknown)), 0);
        assert_eq!(bid(lzma_bid, &header(0x5d, 1 << 24, unknown)[..13]), 0);
    }
}
