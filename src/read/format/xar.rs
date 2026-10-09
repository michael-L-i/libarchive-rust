/*-
 * Copyright (c) 2009 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_read_support_format_xar.c.

//! The xar format: a 28-byte header, a zlib-compressed XML table of contents
//! (TOC) and the heap of file data that the TOC points into. The TOC is read
//! with the `xml` crate where upstream uses libxml2's xmlTextReader.

mod toc;

use crate::archive::*;
use crate::digest::{Algorithm, Digest};
use crate::entry::{AE_IFDIR, AE_IFMT, Entry};
use crate::read::filter::bzip2::Decoder as Bzip2Decoder;
use crate::read::filter::xz::{MEM_LIMIT_KIB, Stream};
use crate::read::{ARCHIVE_ERRNO_FILE_FORMAT, Data, Format, Read, Reader, Status, format_code};
use crate::string::{StringConv, conversion_charset_name, conversion_from_charset};
use crate::util::Error;
use lzma_rust2::{Action, LzmaStream, Status as XzStatus, XzStream};
use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};
use std::ffi::{CString, c_int};
use std::io::{self, ErrorKind};
use std::sync::{Arc, PoisonError};
use toc::Toc;

const HEADER_MAGIC: u32 = 0x7861_7221;
const HEADER_SIZE: usize = 28;
const HEADER_VERSION: u16 = 1;
const CKSUM_NONE: u32 = 0;
const CKSUM_SHA1: u32 = 1;
const CKSUM_MD5: u32 = 2;
const CKSUM_SHA256: u32 = 3;
const CKSUM_SHA512: u32 = 4;

const MAX_SUM_SIZE: usize = 64;
const OUTBUFF_SIZE: usize = 1024 * 64;

/// The largest TOC (decompressed) that is read. Upstream has no limit; this
/// bounds what the XML parser buffers, which it does not limit itself (a CDATA
/// section, say).
const MAX_TOC_SIZE: u64 = 1 << 30;

#[derive(Clone, Copy, Default, PartialEq)]
enum Enc {
    #[default]
    None,
    Gzip,
    Bzip2,
    Lzma,
    Xz,
}

/// A checksum value from the TOC: the algorithm of the element, and the
/// digits read from its text.
#[derive(Clone)]
struct SumVal {
    alg: u32,
    /// `usize::MAX` for text that was not hexadecimal.
    len: usize,
    val: [u8; MAX_SUM_SIZE],
}

impl Default for SumVal {
    fn default() -> Self {
        SumVal {
            alg: CKSUM_NONE,
            len: 0,
            val: [0; MAX_SUM_SIZE],
        }
    }
}

/// A digest being computed, for one of the two checksums of the data.
#[derive(Default)]
struct SumWork {
    alg: u32,
    digest: Option<Digest>,
}

impl SumWork {
    fn init(&mut self, alg: u32) -> Result<(), Error> {
        self.alg = alg;
        let algorithm = match alg {
            CKSUM_NONE => None,
            CKSUM_SHA1 => Some(Algorithm::Sha1),
            CKSUM_MD5 => Some(Algorithm::Md5),
            CKSUM_SHA256 => Some(Algorithm::Sha256),
            CKSUM_SHA512 => Some(Algorithm::Sha512),
            _ => return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Unsupported checksum")),
        };
        self.digest = algorithm.map(Digest::new);
        Ok(())
    }

    fn update(&mut self, data: &[u8]) {
        if let Some(digest) = &mut self.digest {
            digest.update(data);
        }
    }

    /// Whether the digest equals the `len` bytes of `val`.
    fn matches(&mut self, val: &[u8], len: usize) -> bool {
        match self.alg {
            CKSUM_NONE => true,
            CKSUM_SHA1 | CKSUM_MD5 | CKSUM_SHA256 | CKSUM_SHA512 => {
                let Some(digest) = self.digest.take() else {
                    return false;
                };
                let sum = digest.finalize();
                len == sum.len() && val.get(..len) == Some(sum.as_slice())
            }
            _ => false,
        }
    }
}

/// What decodes the data: `decompression_init`.
enum Codec {
    None,
    Gzip {
        state: Box<InflateState>,
        ended: bool,
    },
    /// `None` after the end of the stream, which upstream has cleaned up.
    Bzip2(Option<Box<Bzip2Decoder>>),
    /// The decoder is chosen, and the errors are named, by the encoding of
    /// the entry, whatever the encoding of the data being read.
    Xz {
        stream: Option<Stream>,
        xz: bool,
    },
}

impl Codec {
    fn new(encoding: Enc, entry_encoding: Enc) -> Codec {
        match encoding {
            Enc::None => Codec::None,
            Enc::Gzip => Codec::Gzip {
                state: InflateState::new_boxed(DataFormat::Zlib),
                ended: false,
            },
            Enc::Bzip2 => Codec::Bzip2(Some(Box::new(Bzip2Decoder::new()))),
            Enc::Lzma | Enc::Xz => {
                let xz = entry_encoding == Enc::Xz;
                let stream = if xz {
                    Stream::Xz(Box::new(XzStream::new_mem_limit(true, MEM_LIMIT_KIB)))
                } else {
                    Stream::Lzma(Box::new(LzmaStream::new_mem_limit(MEM_LIMIT_KIB, None)))
                };
                Codec::Xz {
                    stream: Some(stream),
                    xz,
                }
            }
        }
    }

    /// The input a decoder wants at once, as it asks for it.
    fn wanted(&self) -> usize {
        match self {
            Codec::Bzip2(Some(dec)) => dec.wanted(),
            _ => 1,
        }
    }

    /// `decompress`: consumes some of `input` and fills some of `out`.
    /// Returns the bytes used and produced. `last` says that `input` is
    /// short because the packed data or the file ended.
    fn decompress(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        last: bool,
    ) -> Result<(usize, usize), Error> {
        let fail = |msg: String| Error::fatal(ARCHIVE_ERRNO_MISC, msg);
        match self {
            Codec::Gzip { state, ended } => {
                // Once the stream has ended, zlib keeps saying so.
                if *ended {
                    return Ok((0, 0));
                }
                let res = inflate(state, input, out, MZFlush::None);
                let res = match res.status {
                    // zlib reports no progress as an error.
                    Ok(MZStatus::Ok) if res.bytes_consumed == 0 && res.bytes_written == 0 => {
                        Err(MZError::Buf)
                    }
                    status => status.map(|status| (status, res.bytes_consumed, res.bytes_written)),
                };
                match res {
                    Ok((status, used, produced)) => {
                        *ended = status == MZStatus::StreamEnd;
                        Ok((used, produced))
                    }
                    Err(e) => Err(fail(format!(
                        "File decompression failed ({})",
                        match e {
                            MZError::Stream => -2,
                            MZError::Data => -3,
                            MZError::Mem => -4,
                            MZError::Version => -6,
                            _ => -5,
                        }
                    ))),
                }
            }
            Codec::Bzip2(dec) => {
                let Some(d) = dec else {
                    return Err(fail("bzip decompression failed".into()));
                };
                let p = d
                    .decompress(input, out, last)
                    .map_err(|_| fail("bzip decompression failed".into()))?;
                if p.end {
                    *dec = None;
                }
                Ok((p.used, p.produced))
            }
            Codec::Xz { stream, xz } => {
                let name = if *xz { "xz" } else { "lzma" };
                let code = |c: i32| fail(format!("{name} decompression failed ({c})"));
                // liblzma's LZMA_PROG_ERROR for a stream that was ended.
                let Some(s) = stream else {
                    return Err(code(11));
                };
                let r = s.process(input, out, Action::Run).map_err(|e| {
                    code(match e.kind() {
                        ErrorKind::Unsupported => 8,
                        ErrorKind::UnexpectedEof => 10,
                        ErrorKind::OutOfMemory => 5,
                        _ => 9,
                    })
                })?;
                if r.bytes_consumed > input.len() || r.bytes_produced > out.len() {
                    return Err(code(9));
                }
                if r.status == XzStatus::StreamEnd {
                    *stream = None;
                }
                Ok((r.bytes_consumed, r.bytes_produced))
            }
            Codec::None => {
                // Without a decoder the data is copied.
                let n = input.len().min(out.len());
                out[..n].copy_from_slice(input.get(..n).unwrap_or_default());
                Ok((n, n))
            }
        }
    }

    /// Drains what the decoder holds back once all the input is used:
    /// lzma-rust2's streams keep decoded bytes that did not fit the output,
    /// which liblzma does not.
    fn drain(&mut self, into: &mut Vec<u8>, scratch: &mut Vec<u8>) {
        scratch.resize(OUTBUFF_SIZE, 0);
        while let Ok((_, produced)) = self.decompress(&[], scratch, true) {
            if produced == 0 {
                break;
            }
            into.extend_from_slice(scratch.get(..produced).unwrap_or_default());
        }
    }
}

/// The two checksums of the data being read: of the packed data and of the
/// extracted data.
#[derive(Default)]
struct Sums {
    a: SumWork,
    e: SumWork,
}

impl Sums {
    /// `checksum_init`.
    fn init(&mut self, a_alg: u32, e_alg: u32) -> Result<(), Error> {
        self.a.init(a_alg)?;
        self.e.init(e_alg)
    }

    /// `checksum_final`.
    fn finish(&mut self, a: (&[u8], usize), e: (&[u8], usize)) -> Result<(), Error> {
        if self.a.matches(a.0, a.1) && self.e.matches(e.0, e.1) {
            return Ok(());
        }
        Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Checksum error"))
    }
}

/// The decoder of the contents being read.
#[derive(Default)]
struct Contents {
    codec: Option<Codec>,
    outbuff: Vec<u8>,
    /// Decoded data that did not fit the output, from `pending_pos` on.
    pending: Vec<u8>,
    pending_pos: usize,
    scratch: Vec<u8>,
}

impl Contents {
    /// `decompression_init`.
    fn init(&mut self, encoding: Enc, entry_encoding: Enc) {
        self.codec = Some(Codec::new(encoding, entry_encoding));
        self.pending.clear();
        self.pending_pos = 0;
    }

    fn has_pending(&self) -> bool {
        self.pending_pos < self.pending.len()
    }

    /// `rd_contents`: decodes the data of the packed `remaining` bytes
    /// ahead in the input. Returns the number of input bytes used, which are
    /// not consumed, the decoded bytes: in `out` if given, else in the
    /// output buffer, or the input itself if it is not encoded, and whether
    /// the decoder has more output.
    fn rd_contents<'x>(
        &'x mut self,
        sums: &mut Sums,
        r: &'x mut Reader<'_>,
        remaining: u64,
        out: Option<&'x mut [u8]>,
    ) -> Result<(usize, &'x [u8], bool), Error> {
        let Contents {
            codec,
            outbuff,
            pending,
            pending_pos,
            scratch,
        } = self;
        let internal = out.is_none();
        let out: &'x mut [u8] = match out {
            Some(out) => out,
            None => {
                if outbuff.is_empty() {
                    *outbuff = vec![0; OUTBUFF_SIZE];
                }
                outbuff
            }
        };

        if *pending_pos < pending.len() {
            let held = pending.get(*pending_pos..).unwrap_or_default();
            let n = held.len().min(out.len());
            out[..n].copy_from_slice(held.get(..n).unwrap_or_default());
            *pending_pos += n;
            let data = out.get(..n).unwrap_or_default();
            sums.e.update(data);
            return Ok((0, data, *pending_pos < pending.len()));
        }

        // Get whatever bytes are immediately available.
        let wanted = codec.as_ref().map_or(1, Codec::wanted);
        let b = r.peek_available(wanted)?;
        if b.is_empty() {
            return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Truncated archive file"));
        }
        let bytes = b
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let b = b.get(..bytes).unwrap_or_default();

        // Decompress contents of file.
        let codec = codec.get_or_insert(Codec::None);
        let zero_copy = internal && matches!(codec, Codec::None);
        let (used, size) = if zero_copy {
            (bytes, bytes)
        } else {
            codec.decompress(b, out, bytes < wanted)?
        };
        let data: &'x [u8] = if zero_copy {
            b
        } else {
            out.get(..size).unwrap_or_default()
        };
        if remaining > 0 && used == 0 && size == 0 {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "XAR decompressor made no progress",
            ));
        }

        // Update checksum of a compressed data and a extracted data.
        sums.a.update(b.get(..used).unwrap_or_default());
        sums.e.update(data);

        // The decoder may hold output back when its input is all used.
        if used == bytes && size == out.len() {
            codec.drain(pending, scratch);
        }
        Ok((used, data, *pending_pos < pending.len()))
    }
}

/// The reader of the TOC that the XML parser reads through: `xml2_read_cb`.
struct TocSource<'a, 'b> {
    contents: &'a mut Contents,
    sums: &'a mut Sums,
    r: &'a mut Reader<'b>,
    offset: &'a mut u64,
    remaining: &'a mut u64,
    total: &'a mut u64,
    failure: Option<Error>,
}

impl io::Read for TocSource<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if buf.is_empty() || (*self.remaining == 0 && !self.contents.has_pending()) {
                return Ok(0);
            }
            let (used, size) =
                match self
                    .contents
                    .rd_contents(self.sums, self.r, *self.remaining, Some(&mut *buf))
                {
                    Ok((used, data, _)) => (used, data.len()),
                    Err(e) => return Err(self.fail(e)),
                };
            // The result of the consume is ignored, as upstream.
            let _ = self.r.consume(used);
            *self.remaining -= used as u64;
            *self.offset = self.offset.wrapping_add(used as u64);
            *self.total += size as u64;
            if *self.total > MAX_TOC_SIZE {
                let msg = "Rejecting malformed xar archive: TOC exceeds 1 gigabyte";
                return Err(self.fail(Error::fatal(ARCHIVE_ERRNO_MISC, msg)));
            }
            // A decoder that only took the start of the input would look
            // like the end of the TOC.
            if size > 0 || used == 0 {
                return Ok(size);
            }
        }
    }
}

impl TocSource<'_, '_> {
    fn fail(&mut self, e: Error) -> io::Error {
        self.failure = Some(e);
        io::Error::other("TOC read failed")
    }
}

#[derive(Default)]
struct Xar {
    /// Current position in the file.
    offset: u64,
    h_base: u64,
    end_of_file: bool,

    toc_remaining: u64,
    toc_total: u64,
    toc: Toc,

    contents: Contents,
    sums: Sums,
    sconv: Option<Arc<StringConv>>,

    entry_init: bool,
    entry_total: u64,
    entry_remaining: u64,
    entry_unconsumed: usize,
    entry_size: u64,
    entry_encoding: Enc,
    entry_a_sum: SumVal,
    entry_e_sum: SumVal,
}

/// `archive_read_support_format_xar`.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Xar::default()))
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(*b.get(at..)?.first_chunk()?))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(*b.get(at..)?.first_chunk()?))
}

fn be64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(*b.get(at..)?.first_chunk()?))
}

fn file_format(msg: &str) -> Error {
    Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, msg)
}

impl Format for Xar {
    fn name(&self) -> &'static str {
        "xar"
    }

    fn bid(&mut self, r: &mut Reader<'_>, _best_bid: c_int) -> Result<c_int, Error> {
        let Ok(Some(h)) = r.read_ahead(HEADER_SIZE) else {
            return Ok(-1);
        };
        let mut bid = 0;
        // Verify magic code.
        if be32(h, 0) != Some(HEADER_MAGIC) {
            return Ok(0);
        }
        bid += 32;
        // Verify header size.
        if be16(h, 4) != Some(HEADER_SIZE as u16) {
            return Ok(0);
        }
        bid += 16;
        // Verify header version.
        if be16(h, 6) != Some(HEADER_VERSION) {
            return Ok(0);
        }
        bid += 16;
        // Verify type of checksum.
        match be32(h, 24) {
            Some(CKSUM_NONE | CKSUM_SHA1 | CKSUM_MD5 | CKSUM_SHA256 | CKSUM_SHA512) => bid += 32,
            _ => return Ok(0),
        }
        Ok(bid)
    }

    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        let mut status = Status::Ok;

        if self.offset == 0 {
            // Create a character conversion object.
            if self.sconv.is_none() {
                let a = r.base();
                let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
                let sconv = conversion_from_charset(Some(&mut *cache), b"UTF-8", true)
                    .map_err(|e| Error::fatal(e.errno, e.message))?;
                self.sconv = Some(sconv);
            }
            // Read TOC.
            self.read_toc(r)?;
        }

        let file = loop {
            let Some(file) = self.toc.next_file()? else {
                self.end_of_file = true;
                return Ok(Status::Eof);
            };
            if file.mode & AE_IFMT != AE_IFDIR || file.has != toc::HAS_PATHNAME | toc::HAS_TYPE {
                break file;
            }
            // If a file type is a directory and it does not have
            // any metadata, do not export.
        };
        let sconv = self.sconv.clone();
        let sconv = sconv.as_deref();
        let charset = conversion_charset_name(sconv);
        let a = r.base();
        let convert = |what: &str, status: &mut Status, failed: bool| {
            if failed {
                let msg = [
                    what.as_bytes(),
                    b" cannot be converted from ",
                    charset,
                    b" to current locale",
                ]
                .concat();
                *status = a.warn(ARCHIVE_ERRNO_FILE_FORMAT, msg);
            }
        };

        if file.has & toc::HAS_ATIME != 0 {
            entry.set_atime(file.atime, 0);
        }
        if file.has & toc::HAS_CTIME != 0 {
            entry.set_ctime(file.ctime, 0);
        }
        if file.has & toc::HAS_MTIME != 0 {
            entry.set_mtime(file.mtime, 0);
        }
        entry.set_gid(file.gid);
        if !file.gname.is_empty() {
            convert(
                "Gname",
                &mut status,
                entry.copy_gname_l(&file.gname, sconv).is_err(),
            );
        }
        entry.set_uid(file.uid);
        if !file.uname.is_empty() {
            convert(
                "Uname",
                &mut status,
                entry.copy_uname_l(&file.uname, sconv).is_err(),
            );
        }
        entry.set_mode(file.mode);
        if file.has & toc::HAS_PATHNAME != 0 {
            let failed = entry.copy_pathname_l(&file.pathname, sconv).is_err();
            convert("Pathname", &mut status, failed);
        }
        if !file.symlink.is_empty() {
            let failed = entry.copy_symlink_l(&file.symlink, sconv).is_err();
            convert("Linkname", &mut status, failed);
        }
        // Set proper nlink.
        if file.mode & AE_IFMT == AE_IFDIR {
            entry.set_nlink((file.subdirs + 2) as u32);
        } else {
            entry.set_nlink(file.nlink);
        }
        entry.set_size(file.size as i64);
        if !file.hardlink.is_empty() {
            entry.set_hardlink(&file.hardlink);
        }
        entry.set_ino(file.ino64);
        if file.has & toc::HAS_DEV != 0 {
            entry.set_dev(file.dev);
        }
        if file.has & toc::HAS_DEVMAJOR != 0 {
            entry.set_devmajor(file.devmajor);
        }
        if file.has & toc::HAS_DEVMINOR != 0 {
            entry.set_devminor(file.devminor);
        }
        if !file.fflags_text.is_empty() {
            entry.copy_fflags_text(&file.fflags_text);
        }

        self.entry_init = true;
        self.entry_total = 0;
        self.entry_remaining = file.length;
        self.entry_size = file.size;
        self.entry_encoding = file.encoding;
        self.entry_a_sum = file.a_sum.clone();
        self.entry_e_sum = file.e_sum.clone();

        // Read extended attributes.
        for xattr in &file.xattrs {
            self.move_reading_point(r, xattr.offset)?;
            self.contents.init(xattr.encoding, self.entry_encoding);
            self.sums.init(xattr.a_sum.alg, xattr.e_sum.alg)?;
            // Attribute values are owned by Entry; collect incremental decoder
            // output instead of assuming one client block contains the value.
            // Bound allocation independently of the untrusted TOC size field.
            if xattr.size > 64 * 1024 * 1024 {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_MISC,
                    "XAR attribute exceeds size limit",
                ));
            }
            let mut value = Vec::new();
            let mut remaining = xattr.length;
            while remaining != 0 || self.contents.has_pending() {
                let (used, data, _) =
                    self.contents
                        .rd_contents(&mut self.sums, r, remaining, None)?;
                if value.len() as u64 + data.len() as u64 > xattr.size {
                    return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Decompressed size error"));
                }
                value
                    .try_reserve(data.len())
                    .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate XAR attribute"))?;
                value.extend_from_slice(data);
                r.consume(used)?;
                self.offset = self.offset.wrapping_add(used as u64);
                remaining -= used as u64;
            }
            let d = value.as_slice();
            if d.len() as u64 != xattr.size {
                return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Decompressed size error"));
            }
            let (a_val, a_len) = (xattr.a_sum.val, xattr.a_sum.len);
            let (e_val, e_len) = (xattr.e_sum.val, xattr.e_sum.len);
            if self.sums.finish((&a_val, a_len), (&e_val, e_len)).is_err() {
                return Ok(a.warn(ARCHIVE_ERRNO_MISC, "Xattr checksum error"));
            }
            let Some(name) = &xattr.name else {
                return Ok(a.warn(ARCHIVE_ERRNO_MISC, "Xattr name error"));
            };
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            if let Ok(name) = CString::new(name.get(..end).unwrap_or_default()) {
                entry.xattr_add(&name, d);
            }
        }
        if status != Status::Ok && file.xattrs.is_empty() {
            return Ok(status);
        }

        if self.entry_remaining > 0 {
            // Move reading point to the beginning of current
            // file contents.
            self.move_reading_point(r, file.offset)?;
        }
        Ok(Status::Ok)
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        // What the last call used is consumed first, by the reader.
        self.entry_unconsumed = 0;

        if self.end_of_file || (self.entry_remaining == 0 && !self.contents.has_pending()) {
            return Ok(Data::Eof {
                offset: self.entry_total as i64,
            });
        }

        if self.entry_init {
            self.contents.init(self.entry_encoding, self.entry_encoding);
            let r = self.sums.init(self.entry_a_sum.alg, self.entry_e_sum.alg);
            if let Err(e) = r {
                self.entry_remaining = 0;
                return Err(e);
            }
            self.entry_init = false;
        }

        let later = r.consume_later();
        let (used, data, pending) =
            self.contents
                .rd_contents(&mut self.sums, r, self.entry_remaining, None)?;
        let offset = self.entry_total as i64;
        self.entry_total += data.len() as u64;
        self.offset = self.offset.wrapping_add(used as u64);
        self.entry_remaining -= used as u64;
        self.entry_unconsumed = used;
        later.consume(used);

        if self.entry_remaining == 0 && !pending {
            if self.entry_total != self.entry_size {
                return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Decompressed size error"));
            }
            let (a, e) = (&self.entry_a_sum, &self.entry_e_sum);
            self.sums.finish((&a.val, a.len), (&e.val, e.len))?;
        }
        Ok(Data::Block { data, offset })
    }

    fn read_data_skip(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        if self.end_of_file {
            return Ok(Status::Eof);
        }
        let skipped = self
            .entry_remaining
            .wrapping_add(self.entry_unconsumed as u64);
        r.consume(self.entry_remaining)?;
        self.offset = self.offset.wrapping_add(skipped);
        self.entry_unconsumed = 0;
        Ok(Status::Ok)
    }
}

impl Xar {
    fn read_toc(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        // Read xar header.
        let h = r.peek_available(HEADER_SIZE)?;
        if h.len() < HEADER_SIZE {
            return Err(file_format("Truncated archive header"));
        }
        if be32(h, 0) != Some(HEADER_MAGIC) {
            return Err(file_format("Invalid header magic"));
        }
        let version = be16(h, 6).unwrap_or_default();
        if version != HEADER_VERSION {
            return Err(file_format(&format!(
                "Unsupported header version({version})"
            )));
        }
        let toc_compressed_size = be64(h, 8).unwrap_or_default();
        let toc_uncompressed_size = be64(h, 16).unwrap_or_default();
        let toc_chksum_alg = be32(h, 24).unwrap_or_default();
        self.toc_remaining = toc_compressed_size;
        let _ = r.consume(HEADER_SIZE);
        self.offset = self.offset.wrapping_add(HEADER_SIZE as u64);
        self.toc_total = 0;

        // Read TOC(Table of Contents).
        // Initialize reading contents.
        self.move_reading_point(r, HEADER_SIZE as u64)?;
        self.contents.init(Enc::Gzip, Enc::None);
        self.sums.init(toc_chksum_alg, CKSUM_NONE)?;

        let mut source = TocSource {
            contents: &mut self.contents,
            sums: &mut self.sums,
            r: &mut *r,
            offset: &mut self.offset,
            remaining: &mut self.toc_remaining,
            total: &mut self.toc_total,
            failure: None,
        };
        let parsed = self.toc.parse(&mut source);
        if let Some(e) = source.failure {
            return Err(e);
        }
        parsed?;

        // Set 'The HEAP' base.
        self.h_base = self.offset;
        if self.toc_total != toc_uncompressed_size {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_MISC,
                "TOC uncompressed size error",
            ));
        }

        // Checksum TOC.
        if toc_chksum_alg != CKSUM_NONE {
            let (chksum_offset, size) = (self.toc.chksum_offset, self.toc.chksum_size);
            self.move_reading_point(r, chksum_offset)?;
            let checked = if size <= MAX_SUM_SIZE as u64 {
                let len = size as usize;
                let Some(b) = r.peek_available(len)?.get(..len) else {
                    return Err(file_format("Truncated archive file"));
                };
                let sum = self.sums.finish((b, len), (&[], 0));
                let _ = r.consume(len);
                sum
            } else {
                // No digest is this long: only a short file is told apart.
                let skipped = r.skip(i64::try_from(size).unwrap_or(i64::MAX))?;
                if u64::try_from(skipped).ok() != Some(size) {
                    return Err(file_format("Truncated archive file"));
                }
                Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Checksum error"))
            };
            self.offset = self.offset.wrapping_add(size);
            checked?;
        }

        // Connect hardlinked files.
        self.toc.connect_hardlinks();
        r.set_format(format_code::XAR, c"xar");
        Ok(())
    }

    /// `move_reading_point`.
    fn move_reading_point(&mut self, r: &mut Reader<'_>, offset: u64) -> Result<(), Error> {
        let at = self.offset.wrapping_sub(self.h_base);
        if at != offset {
            // Seek forward to the start of file contents.
            let step = offset.wrapping_sub(at) as i64;
            if step > 0 {
                r.consume(step)?;
                self.offset = self.offset.wrapping_add(step as u64);
            } else {
                match r.seek(
                    self.h_base.wrapping_add(offset) as i64,
                    crate::read::Whence::Set,
                ) {
                    Ok(pos) => self.offset = pos as u64,
                    Err(e) if e.code == ARCHIVE_FAILED => {
                        return Err(Error::new(
                            ARCHIVE_FAILED,
                            ARCHIVE_ERRNO_MISC,
                            "Cannot seek",
                        ));
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{Base, READ_MAGIC};
    use crate::read::filter::testing::noise;
    use crate::read_open_memory::Memory;
    use lzma_rust2::{CheckType, XzOptions, XzWriter};
    use std::io::Write;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn sha1(data: &[u8]) -> Vec<u8> {
        let mut d = Digest::new(Algorithm::Sha1);
        d.update(data);
        d.finalize()
    }

    /// A xar of regular files with their data in `style` (the encoding
    /// MIME type), `(name, data, style)`; sha1 checksums throughout.
    fn archive(files: &[(&str, &[u8], &str)], corrupt_sum: bool) -> Vec<u8> {
        let mut heap = vec![0; 20];
        let mut toc = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><xar><toc>\
             <checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum>",
        );
        for (i, (name, data, style)) in files.iter().enumerate() {
            let packed = match *style {
                "application/x-gzip" => miniz_oxide::deflate::compress_to_vec_zlib(data, 6),
                "application/x-bzip2" => crabz2::compress(data, crabz2::Level::BEST),
                "application/x-xz" => {
                    let mut options = XzOptions::with_preset(6);
                    options.set_check_sum_type(CheckType::Crc64);
                    let mut e = XzWriter::new(Vec::new(), options).unwrap();
                    e.write_all(data).unwrap();
                    e.finish().unwrap()
                }
                _ => data.to_vec(),
            };
            let mut sum = hex(&sha1(&packed));
            if corrupt_sum {
                sum.replace_range(..2, "00");
            }
            toc += &format!(
                "<file id=\"{id}\"><name>{name}</name><type>file</type><data>\
                 <length>{}</length><offset>{}</offset><size>{}</size>\
                 <encoding style=\"{style}\"/>\
                 <archived-checksum style=\"sha1\">{sum}</archived-checksum>\
                 <extracted-checksum style=\"SHA1\">{}</extracted-checksum>\
                 </data></file>",
                packed.len(),
                heap.len(),
                data.len(),
                hex(&sha1(data)),
                id = i + 1,
            );
            heap.extend_from_slice(&packed);
        }
        toc += "</toc></xar>";
        let packed_toc = miniz_oxide::deflate::compress_to_vec_zlib(toc.as_bytes(), 6);
        heap[..20].copy_from_slice(&sha1(&packed_toc));
        let mut out = b"xar!".to_vec();
        out.extend_from_slice(&28u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(packed_toc.len() as u64).to_be_bytes());
        out.extend_from_slice(&(toc.len() as u64).to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&packed_toc);
        out.extend_from_slice(&heap);
        out
    }

    type Files = Vec<(Vec<u8>, Vec<u8>)>;

    /// Every entry's name and data, read through blocks of `block` bytes, or
    /// the error message.
    fn read_all(data: &[u8], block: usize) -> Result<Files, String> {
        let a = Base::new(READ_MAGIC);
        let mut r = Read::default();
        assert_eq!(support(&mut r).unwrap(), Status::Ok);
        let message = || {
            a.error_string()
                .map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned())
        };
        assert_eq!(
            r.open(&a, Box::new(Memory::new(data.to_vec(), block))),
            ARCHIVE_OK
        );
        let mut out = Vec::new();
        loop {
            let mut entry = Entry::new(None);
            match r.next_header2(&a, &mut entry) {
                ARCHIVE_OK => {}
                ARCHIVE_EOF => return Ok(out),
                _ => return Err(message()),
            }
            let name = entry
                .pathname()
                .map(|n| n.to_bytes().to_vec())
                .unwrap_or_default();
            let mut content = Vec::new();
            let mut buf = vec![0; 1 << 16];
            loop {
                match r.read_data(&a, None, &mut buf) {
                    0 => break,
                    n if n < 0 => return Err(message()),
                    n => content.extend_from_slice(buf.get(..n as usize).unwrap_or_default()),
                }
            }
            out.push((name, content));
        }
    }

    #[test]
    fn data_in_every_encoding_in_any_block_size() {
        let mixed = [noise(100_000), vec![0; 300_000], noise(50_000)].concat();
        let zeros = vec![b'z'; (1 << 20) + 7];
        let tail = vec![b'y'; 70_000];
        for style in [
            "application/octet-stream",
            "application/x-gzip",
            "application/x-bzip2",
            "application/x-xz",
        ] {
            let files = [
                ("a", mixed.as_slice(), style),
                ("b", zeros.as_slice(), style),
                ("c", tail.as_slice(), style),
            ];
            let xar = archive(&files, false);
            for block in [13, 4096, 1 << 20] {
                let got = read_all(&xar, block);
                let want: Files = files
                    .iter()
                    .map(|(n, d, _)| (n.as_bytes().to_vec(), d.to_vec()))
                    .collect();
                assert!(
                    got == Ok(want),
                    "{style} in blocks of {block}: {:?}",
                    got.err()
                );
            }
        }
    }

    #[test]
    fn a_wrong_checksum_is_an_error_after_the_data() {
        let xar = archive(&[("a", b"hello", "application/x-gzip")], true);
        assert_eq!(read_all(&xar, 4096), Err("Checksum error".into()));
    }
}
