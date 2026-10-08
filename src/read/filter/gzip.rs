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

// Ported from libarchive/archive_read_support_filter_gzip.c.

//! `archive_read_support_filter_gzip`: the gzip filter. The header and trailer
//! are parsed here; the deflate data is inflated by zlib-rs (`flate2`), in
//! raw mode.

use crate::archive::{ARCHIVE_ERRNO_MISC, ARCHIVE_FATAL, Base};
use crate::entry::Entry;
use crate::read::{Filter, FilterBidder, Read, Reader, Status, filter_code};
use crate::util::Error;
use flate2::{Decompress, FlushDecompress, Status as ZStatus};
use std::ffi::{CStr, c_int};

/// The decompressed bytes one `read` produces at most, as upstream's buffer.
const BLOCK_SIZE: usize = 64 * 1024;
/// How long a file name or comment may be before the header is rejected.
const MAX_FILENAME_LENGTH: usize = 1024 * 1024;
const MAX_COMMENT_LENGTH: usize = 1024 * 1024;

const FHCRC: u8 = 2;
const FEXTRA: u8 = 4;
const FNAME: u8 = 8;
const FCOMMENT: u8 = 16;
/// The flag bits that must be clear.
const RESERVED: u8 = 0xe0;

/// The bid for a valid header: 24 bits for the magic bytes, 3 for the flags
/// byte. The header CRC isn't checked, so it adds nothing.
const BID: c_int = 24 + 3;

/// What the member headers say, for `read_header`. Each header sets the mtime,
/// but only a header with a file name replaces the name.
#[derive(Default)]
struct Meta {
    mtime: u32,
    name: Option<Vec<u8>>,
}

struct Gzip {
    meta: Meta,
    /// The decompressor of the member being read; `None` between members.
    stream: Option<Decompress>,
    out: Box<[u8]>,
    filled: usize,
    eof: bool,
}

/// `archive_read_support_filter_gzip`.
pub fn support(r: &mut Read, _: &Base) -> Result<Status, Error> {
    r.register_bidder(Box::new(Bidder))
}

struct Bidder;

impl FilterBidder for Bidder {
    fn bid(&mut self, up: &mut Reader<'_>) -> Result<c_int, Error> {
        Ok(peek_header(up, None).map_or(0, |_| BID))
    }

    fn init(&mut self, _up: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(Gzip {
            meta: Meta::default(),
            stream: None,
            out: vec![0; BLOCK_SIZE].into_boxed_slice(),
            filled: 0,
            eof: false,
        }))
    }
}

impl Filter for Gzip {
    fn name(&self) -> &CStr {
        c"gzip"
    }

    fn code(&self) -> c_int {
        filter_code::GZIP
    }

    fn read(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
        self.filled = 0;
        while self.filled < self.out.len() && !self.eof {
            let Some(mut stream) = self.next_stream(up)? else {
                self.eof = true;
                break;
            };
            if self.inflate(&mut stream, up)? {
                self.read_trailer(up)?;
            } else {
                self.stream = Some(stream);
            }
        }
        Ok(())
    }

    fn block(&self) -> &[u8] {
        self.out.get(..self.filled).unwrap_or_default()
    }

    fn read_header(&mut self, _up: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        // An mtime of 0 is considered invalid/missing.
        if self.meta.mtime != 0 {
            entry.set_mtime(i64::from(self.meta.mtime), 0);
        }
        if let Some(name) = &self.meta.name {
            entry.set_pathname(name);
        }
        Ok(Status::Ok)
    }
}

impl Gzip {
    /// The decompressor of the member being read, or of the next member once
    /// the last one has ended. `None` at the end of the stream.
    fn next_stream(&mut self, up: &mut Reader<'_>) -> Result<Option<Decompress>, Error> {
        match self.stream.take() {
            Some(stream) => Ok(Some(stream)),
            None => self.start_member(up),
        }
    }

    /// Reads the header of the next member and starts its decompressor. Input
    /// that is not a gzip header (including trailing garbage) ends the stream
    /// without an error.
    fn start_member(&mut self, up: &mut Reader<'_>) -> Result<Option<Decompress>, Error> {
        let Some(len) = peek_header(up, Some(&mut self.meta)) else {
            return Ok(None);
        };
        // A short input (an extra field longer than the input) is not an error
        // here: the read below reports it, as upstream does.
        let _ = up.consume(len);
        if up.read_ahead(1).is_err() {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_MISC,
                "Failed to read gzip input",
            ));
        }
        Ok(Some(Decompress::new(false)))
    }

    /// Inflates the input into the rest of the output block, consuming what
    /// zlib used. Returns whether the member ended.
    fn inflate(&mut self, stream: &mut Decompress, up: &mut Reader<'_>) -> Result<bool, Error> {
        let input = up
            .read_ahead(1)
            .ok()
            .flatten()
            .ok_or_else(|| Error::fatal(ARCHIVE_ERRNO_MISC, "truncated gzip input"))?;
        let (in_before, out_before) = (stream.total_in(), stream.total_out());
        let output = self.out.get_mut(self.filled..).unwrap_or_default();
        let ended = match stream.decompress(input, output, FlushDecompress::None) {
            Ok(ZStatus::Ok) => false,
            Ok(ZStatus::StreamEnd) => true,
            _ => {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_MISC,
                    "gzip decompression failed",
                ));
            }
        };
        let produced = stream.total_out().saturating_sub(out_before);
        self.filled += usize::try_from(produced).unwrap_or_default();
        up.consume(stream.total_in().saturating_sub(in_before))?;
        Ok(ended)
    }

    /// The 8-byte trailer (CRC32 and ISIZE) is not checked, as upstream.
    fn read_trailer(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
        // Upstream fails here with no message of its own.
        if up.read_ahead(8).ok().flatten().is_none() {
            return Err(Error::recorded(ARCHIVE_FATAL));
        }
        up.consume(8)
    }
}

/// `peek_at_header`: the length of the gzip header at the start of the input,
/// or `None` if there isn't one. Input that ends early, or fails to read, is no
/// header either. With `meta`, the mtime and file name are recorded as the
/// header is read, as upstream does.
fn peek_header(up: &mut Reader<'_>, mut meta: Option<&mut Meta>) -> Option<usize> {
    let fixed: [u8; 10] = *peek(up, 10)?.first_chunk()?;
    // Deflate is the only method, and no reserved flag may be set.
    if fixed[..3] != [0x1f, 0x8b, 0x08] || fixed[3] & RESERVED != 0 {
        return None;
    }
    let flags = fixed[3];
    if let Some(meta) = &mut meta {
        meta.mtime = u32::from_le_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
    }

    let mut len = 10;
    if flags & FEXTRA != 0 {
        let xlen = u16::from_le_bytes(*peek(up, len + 2)?.get(len..)?.first_chunk()?);
        len += usize::from(xlen) + 2;
    }
    if flags & FNAME != 0 {
        let start = len;
        let nul = field_end(up, start, MAX_FILENAME_LENGTH)?;
        len = nul + 1;
        if let Some(meta) = &mut meta {
            meta.name = Some(peek(up, nul)?.get(start..nul)?.to_vec());
        }
    }
    if flags & FCOMMENT != 0 {
        len = field_end(up, len, MAX_COMMENT_LENGTH)? + 1;
    }
    if flags & FHCRC != 0 {
        peek(up, len + 2)?;
        len += 2;
    }
    Some(len)
}

/// `__archive_read_filter_ahead`: at least `min` bytes of input, or `None`. A
/// read error reads as the end of the input, as it does upstream.
fn peek<'a>(up: &'a mut Reader<'_>, min: usize) -> Option<&'a [u8]> {
    up.read_ahead(min).ok().flatten()
}

/// The index of the NUL that ends the field starting at `start`, or `None` if
/// the input ends first or the field runs past `max` bytes.
fn field_end(up: &mut Reader<'_>, start: usize, max: usize) -> Option<usize> {
    let mut scanned = start;
    loop {
        let data = up.peek_available(scanned + 1).ok()?;
        if let Some(i) = data
            .get(scanned..)
            .and_then(|rest| rest.iter().position(|&b| b == 0))
        {
            return Some(scanned + i);
        }
        if data.len() <= scanned || data.len() > max {
            return None;
        }
        scanned = data.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ARCHIVE_FATAL, ARCHIVE_OK, Base, READ_MAGIC};
    use crate::read::Client;
    use crate::read::format::raw;
    use flate2::write::DeflateEncoder;
    use flate2::{Compression, GzBuilder};
    use std::io::Write;

    /// A client that hands out `block` bytes per read, and fails once `pos`
    /// reaches `fail_at`.
    struct Blocks {
        data: Vec<u8>,
        pos: usize,
        block: usize,
        out: Vec<u8>,
        fail_at: usize,
    }

    impl Blocks {
        fn new(data: Vec<u8>, block: usize) -> Box<Self> {
            Box::new(Blocks {
                data,
                pos: 0,
                block,
                out: Vec::new(),
                fail_at: usize::MAX,
            })
        }
    }

    impl Client for Blocks {
        fn read(&mut self, _a: &Base, _node: usize) -> Result<(), Error> {
            if self.pos >= self.fail_at {
                return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "client read failed"));
            }
            let end = self.data.len().min(self.pos + self.block);
            self.out = self.data.get(self.pos..end).unwrap_or_default().to_vec();
            self.pos = end;
            Ok(())
        }

        fn block(&self) -> &[u8] {
            &self.out
        }
    }

    /// Opens `data` with the gzip filter and the raw format, which makes one
    /// entry of the decoded stream, and reads it in odd-sized pieces. Returns
    /// the bytes, the status that ended the read and the error message.
    fn decode(data: &[u8], block: usize) -> (Vec<u8>, c_int, String) {
        let mut r = Read::default();
        let a = Base::new(READ_MAGIC);
        assert_eq!(support(&mut r, &Base::new(READ_MAGIC)).unwrap(), Status::Ok);
        assert_eq!(raw::support(&mut r).unwrap(), Status::Ok);
        let mut status = r.open(&a, Blocks::new(data.to_vec(), block));
        let mut entry = Entry::new(None);
        if status == ARCHIVE_OK {
            status = r.next_header2(&a, &mut entry);
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 1000];
        while status == ARCHIVE_OK {
            match usize::try_from(r.read_data(&a, &mut buf)) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(buf.get(..n).unwrap_or_default()),
                Err(_) => status = ARCHIVE_FATAL,
            }
        }
        let error = a
            .error_string()
            .map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned());
        (out, status, error)
    }

    /// Text with some incompressible runs, so that the output spans blocks.
    fn sample(n: usize) -> Vec<u8> {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        (0..n)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                if i % 1000 < 500 {
                    b'a' + (i % 26) as u8
                } else {
                    x as u8
                }
            })
            .collect()
    }

    fn member(data: &[u8], name: Option<&str>, mtime: u32) -> Vec<u8> {
        let mut builder = GzBuilder::new().mtime(mtime);
        if let Some(name) = name {
            builder = builder.filename(name);
        }
        let mut enc = builder.write(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// A header with every optional field, then raw deflate data and a
    /// trailer. The trailer is zeros, which upstream does not check.
    fn all_fields(data: &[u8]) -> Vec<u8> {
        let flags = FEXTRA | FNAME | FCOMMENT | FHCRC;
        let mut out = vec![0x1f, 0x8b, 0x08, flags, 1, 0, 0, 0, 0, 3];
        out.extend_from_slice(&[3, 0, b'x', b'y', b'z']);
        out.extend_from_slice(b"name.txt\0comment\0\x00\x00");
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        out.extend(enc.finish().unwrap());
        out.extend_from_slice(&[0; 8]);
        out
    }

    #[test]
    fn round_trips_in_any_block_size() {
        let data = sample(200_000);
        let gz = member(&data, Some("data.bin"), 1_550_000_000);
        for block in [1, 3, 7, 511, 4096, usize::MAX / 2] {
            let (out, status, error) = decode(&gz, block);
            assert!(
                out == data && status == ARCHIVE_OK && error.is_empty(),
                "block {block}: {status} {error}"
            );
        }
    }

    #[test]
    fn concatenated_members_decode_as_one_stream() {
        let (a, b) = (sample(70_000), b"second member".to_vec());
        let gz = [member(&a, None, 0), member(&b, Some("two"), 5)].concat();
        let (out, status, _) = decode(&gz, 1000);
        assert_eq!((out == [a, b].concat(), status), (true, ARCHIVE_OK));
    }

    #[test]
    fn optional_header_fields_are_skipped() {
        let (out, status, error) = decode(&all_fields(b"payload"), 5);
        assert_eq!(
            (out.as_slice(), status, error.as_str()),
            (&b"payload"[..], ARCHIVE_OK, "")
        );
    }

    #[test]
    fn header_supplies_the_name_and_mtime() {
        let mut r = Read::default();
        let a = Base::new(READ_MAGIC);
        assert_eq!(support(&mut r, &Base::new(READ_MAGIC)).unwrap(), Status::Ok);
        assert_eq!(raw::support(&mut r).unwrap(), Status::Ok);
        let gz = member(b"x", Some("test-file-name.data"), 0x5cba_fd25);
        assert_eq!(r.open(&a, Blocks::new(gz, 64)), ARCHIVE_OK);
        let mut entry = Entry::new(None);
        assert_eq!(r.next_header2(&a, &mut entry), ARCHIVE_OK);
        assert_eq!(
            entry.pathname().map(CStr::to_bytes),
            Some(&b"test-file-name.data"[..])
        );
        assert_eq!(entry.mtime(), 0x5cba_fd25);
    }

    #[test]
    fn errors_match_upstream_messages() {
        let gz = member(&sample(5000), None, 0);
        // Cut inside the deflate data: the input ends first.
        let (_, status, error) = decode(&gz[..gz.len() - 20], 9);
        assert_eq!(
            (status, error.as_str()),
            (ARCHIVE_FATAL, "truncated gzip input")
        );
        // Cut inside the trailer: upstream fails without a message.
        let (_, status, error) = decode(&gz[..gz.len() - 3], 9);
        assert_eq!((status, error.as_str()), (ARCHIVE_FATAL, ""));
        // Deflate block type 3 is invalid.
        let bad = [0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3, 0x07, 0, 0];
        let (_, status, error) = decode(&bad, 4);
        assert_eq!(
            (status, error.as_str()),
            (ARCHIVE_FATAL, "gzip decompression failed")
        );
    }

    /// A header whose extra field declares 512 bytes, followed by 14.
    fn short_extra() -> Vec<u8> {
        let mut gz = vec![0x1f, 0x8b, 0x08, FEXTRA, 0, 0, 0, 0, 0, 3, 0, 2];
        gz.extend_from_slice(&[0; 14]);
        gz
    }

    #[test]
    fn a_short_extra_field_is_truncation_as_upstream() {
        let (out, status, error) = decode(&short_extra(), 5);
        assert_eq!(
            (out.len(), status, error.as_str()),
            (0, ARCHIVE_FATAL, "truncated gzip input")
        );
        // The first member's output is lost with the read that fails, as upstream.
        let gz = [member(b"abc", None, 0), short_extra()].concat();
        let (out, status, error) = decode(&gz, 3);
        assert_eq!(
            (out.len(), status, error.as_str()),
            (0, ARCHIVE_FATAL, "truncated gzip input")
        );
    }

    #[test]
    fn a_read_error_after_the_header_is_reported_as_upstream() {
        let gz = member(b"x", None, 0);
        let mut r = Read::default();
        let a = Base::new(READ_MAGIC);
        assert_eq!(support(&mut r, &Base::new(READ_MAGIC)).unwrap(), Status::Ok);
        assert_eq!(raw::support(&mut r).unwrap(), Status::Ok);
        let mut client = Blocks::new(gz, 10);
        client.fail_at = 10;
        assert_eq!(r.open(&a, client), ARCHIVE_FATAL);
        let error = a
            .error_string()
            .map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned());
        assert_eq!(error, "Failed to read gzip input");
    }

    #[test]
    fn the_trailer_is_not_checked() {
        let mut gz = member(b"unchecked", None, 0);
        let n = gz.len();
        gz[n - 8..].fill(0xee);
        let (out, status, _) = decode(&gz, 64);
        assert_eq!((out.as_slice(), status), (&b"unchecked"[..], ARCHIVE_OK));
    }

    #[test]
    fn every_truncation_fails_cleanly() {
        let (a, b) = (sample(3000), sample(500));
        let first = member(&a, Some("first"), 1);
        let gz = [first.clone(), member(&b, None, 2)].concat();
        for cut in 0..gz.len() {
            let (out, status, _) = decode(&gz[..cut], 3);
            // Too short for a header, the raw format passes the bytes through.
            // A cut that leaves no second header ends the stream cleanly.
            // Anything else in the deflate data or trailer is fatal.
            let passthrough = out == gz[..cut];
            let clean_end = cut >= first.len() && out == a && status == ARCHIVE_OK;
            assert!(
                status == ARCHIVE_FATAL || passthrough || clean_end,
                "cut {cut}: {status}"
            );
        }
    }

    #[test]
    fn random_mutations_never_panic() {
        let gz = [
            member(&sample(4000), Some("m"), 9),
            member(b"tail", None, 0),
        ]
        .concat();
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..500 {
            let mut bad = gz.clone();
            for _ in 0..3 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let at = (x as usize) % bad.len();
                bad[at] = (x >> 32) as u8;
            }
            let _ = decode(&bad, 1 + (x as usize) % 97);
        }
    }
}
