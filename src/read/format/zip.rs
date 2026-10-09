/*-
 * Copyright (c) 2004-2013 Tim Kientzle
 * Copyright (c) 2011-2012,2014 Michihiro NAKAJIMA
 * Copyright (c) 2013 Konrad Kleine
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

// Ported from libarchive/archive_read_support_format_zip.c.

//! The zip reader, in its streamable and seekable modes.
//!
//! The definitive documentation of the Zip file format is:
//!   http://www.pkware.com/documents/casestudies/APPNOTE.TXT
//!
//! The Info-Zip project has pioneered various extensions to better support
//! Zip on Unix, including the 0x5455 "UT", 0x5855 "UX", 0x7855 "Ux", and
//! 0x7875 "ux" extensions for time and ownership information.
//!
//! History of this code: The streaming Zip reader was first added to
//! libarchive in January 2005. Support for seekable input sources was added
//! in Nov 2011. Zip64 support (including a significant code refactoring)
//! was added in 2014.
//!
//! The streamable reader looks for local file headers as it goes; the
//! seekable reader finds the central directory first and then visits the
//! entries in the order of their local headers. Both are the same type with
//! a different `SEEKABLE`, so that both can be registered.

mod crypto;
mod extra;
mod zipx;

use crate::archive::*;
use crate::crc32::crc32;
use crate::cryptor::pbkdf2_sha1;
use crate::entry::{Entry, Mode};
use crate::hmac::HmacSha1;
use crate::read::{
    ARCHIVE_ERRNO_FILE_FORMAT, CAPS_ENCRYPT, Data, ENCRYPTION_DONT_KNOW, Format, Read, Reader,
    Status, Whence, format_code,
};
use crate::string::{StringConv, conversion_charset_name, conversion_from_charset, until_nul};
use crate::time::dos_to_unix;
use crate::util::Error;
use crypto::{AUTH_CODE_SIZE, Crypto, Trad};
use extra::*;
use libc::wchar_t;
use miniz_oxide::inflate::stream::{InflateState, inflate as mz_inflate};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};
use std::collections::BTreeMap;
use std::ffi::c_int;
use std::ops::Bound;
use std::sync::{Arc, PoisonError};

/// Length of local file header, not including filename and extra.
const ZIP_LOCHDR_LEN: usize = 30;

/// Maximum length of Mac metadata in MiB.
const ZIP_MAX_METADATA: i64 = 10;

/// The size of the buffers the decompressors write to.
const BUFFER_SIZE: usize = 256 * 1024;

/// What a read of the entry's data produced.
enum Out {
    /// The first `n` bytes of the decompression buffer.
    Buf(usize),
    /// The first `n` bytes the stream has, still to be consumed (stored
    /// data).
    Stream(usize),
    /// The first `n` bytes of the decryption buffer (stored, encrypted
    /// data).
    Dec(usize),
    /// `ARCHIVE_WARN`: the problem is recorded and there is no data.
    Warn,
}

/// What a call of zlib's `inflate` did: bytes consumed, bytes written and
/// whether the stream ended, or the error code zlib would have returned.
fn inflate(
    state: &mut InflateState,
    input: &[u8],
    out: &mut [u8],
) -> Result<(usize, usize, bool), i32> {
    let res = mz_inflate(state, input, out, MZFlush::None);
    let ended = match res.status {
        Ok(MZStatus::Ok) => false,
        Ok(MZStatus::StreamEnd) => true,
        // Z_NEED_DICT.
        Ok(MZStatus::NeedDict) => return Err(2),
        Err(e) => return Err(e as i32),
    };
    // zlib returns Z_BUF_ERROR when no progress is possible.
    if !ended && res.bytes_consumed == 0 && res.bytes_written == 0 {
        return Err(MZError::Buf as i32);
    }
    Ok((res.bytes_consumed, res.bytes_written, ended))
}

/// zlib's `Z_MEM_ERROR`.
const Z_MEM_ERROR: i32 = -4;

fn inflate_failed(code: i32) -> Error {
    if code == Z_MEM_ERROR {
        Error::fatal(libc::ENOMEM, "Out of memory for ZIP decompression")
    } else {
        Error::fatal(
            ARCHIVE_ERRNO_MISC,
            format!("ZIP decompression failed ({code})"),
        )
    }
}

/// `compression_methods`.
fn compression_name(compression: u8) -> &'static str {
    match compression {
        0 => "uncompressed",
        1 => "shrinking",
        2 => "reduced-1",
        3 => "reduced-2",
        4 => "reduced-3",
        5 => "reduced-4",
        6 => "imploded",
        7 => "reserved",
        8 => "deflation",
        9 => "deflation-64-bit",
        10 => "ibm-terse",
        11 => "reserved",
        12 => "bzip",
        13 => "reserved",
        14 => "lzma",
        15..=17 => "reserved",
        18 => "ibm-terse-new",
        19 => "ibm-lz777",
        93 => "zstd",
        95 => "xz",
        96 => "jpeg",
        97 => "wav-pack",
        98 => "ppmd-1",
        99 => "aes",
        _ => "??",
    }
}

fn truncated_data() -> Error {
    Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated ZIP file data")
}

fn truncated_header() -> Error {
    Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated ZIP file header")
}

/// Whether two converters are the same one; none is the default.
fn same_conv(a: &Option<Arc<StringConv>>, b: &Option<Arc<StringConv>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}

/// The part of a wide string before its first NUL.
fn wide(s: &[wchar_t]) -> &[wchar_t] {
    s.split(|&c| c == 0).next().unwrap_or_default()
}

/// The name `archive_format_name` has not been set yet.
fn format_name_unset(a: &Base) -> bool {
    a.format_name.get().is_none() && a.format_name_buf.borrow().is_empty()
}

/// An entry in the table of entries by the offset of their local headers
/// (`tree`), and the table of Mac resource forks by name (`tree_rsrc`).
pub struct Zip<const SEEKABLE: bool> {
    /// Structural information about the archive.
    central_directory_offset: i64,
    central_directory_offset_adjusted: i64,
    has_encrypted_entries: c_int,

    /// List of entries (seekable Zip only).
    zip_entries: Vec<ZipEntry>,
    /// Indexes into `zip_entries`, by the offset of the local header. A
    /// second entry at the same offset is not added.
    tree: BTreeMap<i64, usize>,
    /// Resource forks and directories under `__MACOSX/`, by name.
    tree_rsrc: BTreeMap<Vec<u8>, usize>,

    /// The entry in `tree` that is being read (seekable Zip only).
    current: Option<usize>,
    /// The entry we're currently reading.
    entry: ZipEntry,
    entry_bytes_remaining: i64,

    /// These count the number of bytes actually read for the entry.
    entry_compressed_bytes_read: i64,
    entry_uncompressed_bytes_read: i64,

    /// Running CRC32 of the decompressed and decrypted data.
    computed_crc32: u32,
    ignore_crc32: bool,

    /// Flags to mark progress of decompression.
    decompress_init: bool,
    end_of_entry: bool,

    uncompressed_buffer: Vec<u8>,

    inflate: Option<Box<InflateState>>,
    zipx: zipx::Decoders,

    /// `hdrcharset`; none is the current locale.
    sconv: Option<Arc<StringConv>>,
    sconv_utf8: Option<Arc<StringConv>>,
    process_mac_extensions: bool,

    init_decryption: bool,
    crypto: Crypto,
}

impl<const SEEKABLE: bool> Zip<SEEKABLE> {
    fn new() -> Self {
        Zip {
            central_directory_offset: 0,
            central_directory_offset_adjusted: 0,
            // Until enough data has been read, we cannot tell about any
            // encrypted entries yet.
            has_encrypted_entries: ENCRYPTION_DONT_KNOW,
            zip_entries: Vec::new(),
            tree: BTreeMap::new(),
            tree_rsrc: BTreeMap::new(),
            current: None,
            entry: ZipEntry::default(),
            entry_bytes_remaining: 0,
            entry_compressed_bytes_read: 0,
            entry_uncompressed_bytes_read: 0,
            computed_crc32: 0,
            ignore_crc32: false,
            decompress_init: false,
            end_of_entry: false,
            uncompressed_buffer: Vec::new(),
            inflate: None,
            zipx: zipx::Decoders::default(),
            sconv: None,
            sconv_utf8: None,
            // Set this by default on Mac OS; the streamable reader doesn't
            // support mac extensions.
            process_mac_extensions: SEEKABLE && cfg!(target_vendor = "apple"),
            init_decryption: false,
            crypto: Crypto::default(),
        }
    }

    /// `real_crc32` and `fake_crc32`.
    fn crc(&self, crc: u32, data: &[u8]) -> u32 {
        if self.ignore_crc32 {
            0
        } else {
            crc32(crc, data)
        }
    }

    /// Replaces the decompression buffer with one of `size` bytes.
    fn alloc_buffer(&mut self, size: usize, msg: &str) -> Result<(), Error> {
        self.uncompressed_buffer = Vec::new();
        if self.uncompressed_buffer.try_reserve_exact(size).is_err() {
            return Err(Error::fatal(libc::ENOMEM, msg));
        }
        self.uncompressed_buffer.resize(size, 0);
        Ok(())
    }

    /// How many bytes of `avail` the entry's compressed data allows, or none
    /// if the entry has less than none left.
    fn clip(&self, avail: usize) -> Option<usize> {
        let remaining = self.entry_bytes_remaining;
        if !self.entry.length_at_end() && i64::try_from(avail).map_or(true, |a| a > remaining) {
            return usize::try_from(remaining).ok();
        }
        Some(avail)
    }

    /// The number of compressed bytes the entry has left, if it is known.
    fn limit(&self) -> Option<i64> {
        (!self.entry.length_at_end() && self.entry_bytes_remaining > 0)
            .then_some(self.entry_bytes_remaining)
    }

    /// `check_authentication_code`, for the end of an entry's data: the
    /// warning (if any) is the data's result.
    fn authenticate(&mut self, r: &mut Reader<'_>) -> Result<Option<Out>, Error> {
        match self.crypto.check_authentication_code(r, None)? {
            Status::Warn => Ok(Some(Out::Warn)),
            _ => Ok(None),
        }
    }

    /// Sets the format code, and the name unless there is one.
    fn set_format(a: &Base) {
        if format_name_unset(a) {
            a.set_format(format_code::ZIP, c"ZIP");
        } else {
            a.format.set(format_code::ZIP);
        }
    }

    /// `archive_read_format_zip_options`.
    fn option(&mut self, a: &Base, key: &[u8], val: Option<&[u8]>) -> Result<Status, Error> {
        match key {
            // Handle filenames as libarchive 2.x: the default conversion of
            // names is only done on Windows, so there is nothing to switch.
            b"compat-2x" => Ok(Status::Ok),
            b"hdrcharset" => {
                let Some(name) = val.filter(|v| !v.is_empty()) else {
                    // The option is reported as failed.
                    return Err(Error::new(
                        ARCHIVE_FAILED,
                        ARCHIVE_ERRNO_MISC,
                        "zip: hdrcharset option needs a character-set name",
                    ));
                };
                let made = {
                    let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
                    conversion_from_charset(Some(&mut *cache), name, false)
                };
                match made {
                    Ok(sc) => {
                        if name == b"UTF-8" {
                            self.sconv_utf8 = Some(sc.clone());
                        }
                        self.sconv = Some(sc);
                        Ok(Status::Ok)
                    }
                    Err(e) => Err(Error::fatal(e.errno, e.message)),
                }
            }
            b"ignorecrc32" => {
                // Mostly useful for testing.
                self.ignore_crc32 = val.is_some_and(|v| !v.is_empty());
                Ok(Status::Ok)
            }
            b"mac-ext" => {
                self.process_mac_extensions = val.is_some_and(|v| !v.is_empty());
                Ok(Status::Ok)
            }
            // The "warn" return is just to inform the options supervisor that
            // we didn't handle it. It will generate a suitable error if no
            // one used this option.
            _ => Ok(Status::Warn),
        }
    }

    // Common code for streaming or seeking modes.
    //
    // Includes code to read local file headers, decompress data from entry
    // bodies, and common API.

    /// Assumes file pointer is at beginning of local file header.
    fn read_local_file_header(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
    ) -> Result<Status, Error> {
        let a = r.base();
        let mut ret = Status::Ok;

        // Save a copy of the original for consistency checks.
        let central_dir = self.entry.clone();

        self.decompress_init = false;
        self.end_of_entry = false;
        self.entry_uncompressed_bytes_read = 0;
        self.entry_compressed_bytes_read = 0;
        self.computed_crc32 = self.crc(0, &[]);

        let p: Vec<u8> = match r.read_ahead(ZIP_LOCHDR_LEN) {
            Ok(Some(p)) => p.get(..ZIP_LOCHDR_LEN).unwrap_or_default().to_vec(),
            _ => return Err(truncated_header()),
        };

        if !p.starts_with(b"PK\x03\x04") {
            return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Damaged Zip archive"));
        }
        let version = p.get(4).copied().unwrap_or(0) as i8;
        self.entry.system = p.get(5).copied().unwrap_or(0);
        self.entry.zip_flags = le16(&p, 6);
        let zip_flags = self.entry.zip_flags;
        if zip_flags & (ZIP_ENCRYPTED | ZIP_STRONG_ENCRYPTED) != 0 {
            self.has_encrypted_entries = 1;
            entry.set_is_data_encrypted(true);
            if zip_flags & ZIP_CENTRAL_DIRECTORY_ENCRYPTED != 0
                && zip_flags & ZIP_ENCRYPTED != 0
                && zip_flags & ZIP_STRONG_ENCRYPTED != 0
            {
                entry.set_is_metadata_encrypted(true);
                return Err(Error::silent(ARCHIVE_FATAL));
            }
        }
        self.init_decryption = zip_flags & ZIP_ENCRYPTED != 0;
        self.entry.compression = le16(&p, 8) as u8;
        // This DOS timestamp carries no information a Central Directory
        // prescan wouldn't already have, and no sub-second precision: only
        // use it (and reset mtime_ns to match, since it has none) as a
        // fallback default, not an unconditional override of a more precise
        // value the prescan may have already established from an extra field
        // the Local Header doesn't itself repeat.
        if self.entry.flags & LA_MTIME_FROM_EXTRA == 0 {
            self.entry.mtime = dos_to_unix(le32(&p, 10));
            self.entry.mtime_ns = 0;
        }
        self.entry.crc32 = le32(&p, 14);
        self.entry.decdat = p
            .get(if self.entry.length_at_end() { 11 } else { 17 })
            .copied()
            .unwrap_or(0);
        self.entry.compressed_size = i64::from(le32(&p, 18));
        self.entry.uncompressed_size = i64::from(le32(&p, 22));
        let filename_length = usize::from(le16(&p, 26));
        let extra_length = usize::from(le16(&p, 28));

        r.consume(ZIP_LOCHDR_LEN)?;

        // Read the filename.
        let utf8_name = zip_flags & ZIP_UTF8_NAME != 0;
        let sconv = if utf8_name {
            // The filename is stored to be UTF-8.
            if self.sconv_utf8.is_none() {
                self.sconv_utf8 = Some(self.utf8_conversion(a)?);
            }
            self.sconv_utf8.clone()
        } else {
            self.sconv.clone()
        };
        let h = match r.read_ahead(filename_length) {
            Ok(Some(h)) => h.get(..filename_length).unwrap_or_default(),
            _ => return Err(truncated_header()),
        };
        if entry.copy_pathname_l(h, sconv.as_deref()).is_err() {
            let msg = [
                b"Pathname cannot be converted from ".as_slice(),
                conversion_charset_name(sconv.as_deref()),
                b" to current locale",
            ]
            .concat();
            ret = a.warn(ARCHIVE_ERRNO_FILE_FORMAT, msg);
        }
        r.consume(filename_length)?;

        // Read the extra data.
        let h = match r.read_ahead(extra_length) {
            Ok(Some(h)) => h.get(..extra_length).unwrap_or_default(),
            _ => return Err(truncated_header()),
        };
        let mut cx = ExtraContext {
            a,
            sconv_utf8: &mut self.sconv_utf8,
            ignore_crc32: self.ignore_crc32,
        };
        process_extra(&mut cx, Some(&mut *entry), h, &mut self.entry).map_err(|e| Error {
            code: ARCHIVE_FATAL,
            ..e
        })?;
        r.consume(extra_length)?;

        // Work around a bug in Info-Zip: When reading from a pipe, it stats
        // the pipe instead of synthesizing a file entry.
        if self.entry.mode & IFMT == IFIFO {
            self.entry.mode &= !IFMT;
            self.entry.mode |= IFREG;
        }

        // If the mode is totally empty, set some sane default.
        if self.entry.mode == 0 {
            self.entry.mode |= 0o664;
        }

        // Windows archivers sometimes use backslash as the directory
        // separator. Normalize to slash.
        if self.entry.system == 0 {
            let fixed = entry.pathname_w().map(wide).and_then(|wp| {
                let is = |c: char| wp.contains(&(c as wchar_t));
                (!is('/') && is('\\')).then(|| {
                    wp.iter()
                        .map(|&c| {
                            if c == '\\' as wchar_t {
                                '/' as wchar_t
                            } else {
                                c
                            }
                        })
                        .collect::<Vec<_>>()
                })
            });
            if let Some(s) = fixed {
                entry.copy_pathname_w(&s);
            }
        }

        // Make sure that entries with a trailing '/' are marked as
        // directories even if the External File Attributes contains bogus
        // values. If this is not a directory and there is no type, assume a
        // regular file.
        if self.entry.mode & IFMT != IFDIR {
            let has_slash = match entry.pathname_w() {
                Some(wp) => wide(wp).last() == Some(&('/' as wchar_t)),
                None => entry
                    .pathname()
                    .is_some_and(|cp| cp.to_bytes().last() == Some(&b'/')),
            };
            // Correct file type as needed.
            if has_slash {
                self.entry.mode &= !IFMT;
                self.entry.mode |= IFDIR;
                self.entry.mode |= 0o111;
            } else if self.entry.mode & IFMT == 0 {
                self.entry.mode |= IFREG;
            }
        }

        // Make sure directories end in '/'.
        if self.entry.mode & IFMT == IFDIR {
            match entry.pathname_w().map(wide) {
                Some(wp) => {
                    if wp.last().is_some_and(|&c| c != '/' as wchar_t) {
                        let mut s = wp.to_vec();
                        s.push('/' as wchar_t);
                        entry.copy_pathname_w(&s);
                    }
                }
                None => {
                    let cp = entry.pathname().map(|c| c.to_bytes().to_vec());
                    if let Some(mut s) = cp
                        && s.last().is_some_and(|&c| c != b'/')
                    {
                        s.push(b'/');
                        entry.set_pathname(&s);
                    }
                }
            }
        }

        if self.entry.flags & LA_FROM_CENTRAL_DIRECTORY != 0 {
            // If this came from the central dir, its size info is
            // definitive, so ignore the length-at-end flag.
            self.entry.zip_flags &= !ZIP_LENGTH_AT_END;
            // If local header is missing a value, use the one from the
            // central directory. If both have it, warn about mismatches.
            if self.entry.crc32 == 0 {
                self.entry.crc32 = central_dir.crc32;
            } else if !self.ignore_crc32 && self.entry.crc32 != central_dir.crc32 {
                ret = a.warn(ARCHIVE_ERRNO_FILE_FORMAT, "Inconsistent CRC32 values");
            }
            if self.entry.compressed_size == 0 || self.entry.compressed_size == 0xffff_ffff {
                self.entry.compressed_size = central_dir.compressed_size;
            } else if self.entry.compressed_size != central_dir.compressed_size {
                ret = a.warn(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    format!(
                        "Inconsistent compressed size: {} in central directory, {} in local header",
                        central_dir.compressed_size, self.entry.compressed_size
                    ),
                );
            }
            if self.entry.uncompressed_size == 0 || self.entry.uncompressed_size == 0xffff_ffff {
                self.entry.uncompressed_size = central_dir.uncompressed_size;
            } else if self.entry.uncompressed_size != central_dir.uncompressed_size {
                ret = a.warn(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    format!(
                        "Inconsistent uncompressed size: {} in central directory, {} in local header",
                        central_dir.uncompressed_size, self.entry.uncompressed_size
                    ),
                );
            }
        }

        // Populate some additional entry fields:
        let ze = &self.entry;
        entry.set_mode(Mode::from(ze.mode));
        entry.set_uid(ze.uid);
        entry.set_gid(ze.gid);
        entry.set_mtime(ze.mtime, i64::from(ze.mtime_ns));
        // Without an extra field to supply them, leave atime and ctime unset,
        // rather than reporting them as set to the Unix epoch.
        if ze.flags & LA_CTIME_FROM_EXTRA != 0 {
            entry.set_ctime(ze.ctime, 0);
        }
        if ze.flags & LA_ATIME_FROM_EXTRA != 0 {
            entry.set_atime(ze.atime, i64::from(ze.atime_ns));
        }
        if ze.flags & LA_NTFS_BTIME != 0 {
            entry.set_birthtime(ze.btime, i64::from(ze.btime_ns));
        }

        if self.entry.mode & IFMT == IFLNK {
            ret = self.read_symlink(r, entry, ret)?;
        } else if self.entry.size_is_set() {
            entry.set_size(self.entry.uncompressed_size);
        }
        self.entry_bytes_remaining = self.entry.compressed_size;

        // If there's no body, force read_data() to return EOF immediately.
        if !self.entry.length_at_end() && self.entry_bytes_remaining < 1 {
            self.end_of_entry = true;
        }

        // Set up a more descriptive format name.
        a.set_format_name(
            format!(
                "ZIP {}.{} ({})",
                version / 10,
                version % 10,
                compression_name(self.entry.compression)
            )
            .as_bytes(),
        );

        Ok(ret)
    }

    /// The converter from UTF-8 names, which `archive_string_conversion_from_charset`
    /// makes when it is needed.
    fn utf8_conversion(&self, a: &Base) -> Result<Arc<StringConv>, Error> {
        let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
        conversion_from_charset(Some(&mut *cache), b"UTF-8", true)
            .map_err(|e| Error::fatal(e.errno, e.message))
    }

    /// The part of `zip_read_local_file_header` that reads a symlink's
    /// target. Returns the status the header has: `ret` or a warning.
    fn read_symlink(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        mut ret: Status,
    ) -> Result<Status, Error> {
        let a = r.base();
        if self.entry.compressed_size > 64 * 1024 {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_MISC,
                "Zip file with oversized link entry",
            ));
        }

        let linkname_length = usize::try_from(self.entry.compressed_size).unwrap_or(0);

        entry.set_size(0);

        // Take into account link compression if any.
        let link: Vec<u8> = if self.entry.compression != 0 {
            // The symlink target string appeared to be compressed.
            self.entry_bytes_remaining = self.entry.compressed_size;
            let status = match self.entry.compression {
                8 => self.read_deflate(r),
                14 => self.read_lzma_alone(r),
                _ => Err(Error::silent(ARCHIVE_FATAL)),
            };
            match status {
                Ok(Out::Buf(n)) => self
                    .uncompressed_buffer
                    .get(..n)
                    .unwrap_or_default()
                    .to_vec(),
                _ => {
                    return Err(Error::new(
                        ARCHIVE_FAILED,
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        format!(
                            "Unsupported ZIP compression method during decompression of link entry ({}: {})",
                            self.entry.compression,
                            compression_name(self.entry.compression)
                        ),
                    ));
                }
            }
        } else {
            match r.read_ahead(linkname_length) {
                Ok(Some(p)) => p.get(..linkname_length).unwrap_or_default().to_vec(),
                _ => {
                    return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Truncated Zip file"));
                }
            }
        };

        let utf8_name = self.entry.zip_flags & ZIP_UTF8_NAME != 0;
        let mut sconv = self.sconv.clone();
        if sconv.is_none() && utf8_name {
            sconv = self.sconv_utf8.clone();
        }
        if entry.copy_symlink_l(&link, sconv.as_deref()).is_err() {
            if same_conv(&sconv, &self.sconv_utf8) && utf8_name {
                let _ = entry.copy_symlink_l(&link, None);
            }
            // Since there is no character-set regulation for symlink name,
            // do not report the conversion error in an automatic conversion.
            if !same_conv(&sconv, &self.sconv_utf8) || !utf8_name {
                let msg = [
                    b"Symlink cannot be converted from ".as_slice(),
                    conversion_charset_name(sconv.as_deref()),
                    b" to current locale",
                ]
                .concat();
                ret = a.warn(ARCHIVE_ERRNO_FILE_FORMAT, msg);
            }
        }
        self.entry.uncompressed_size = 0;
        self.entry.compressed_size = 0;

        if r.consume(linkname_length).is_err() {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_MISC,
                "Read error skipping symlink target name",
            ));
        }
        Ok(ret)
    }

    /// The Zip end-of-file marker is inherently ambiguous. The specification
    /// in APPNOTE.TXT allows any of four possible formats, and there is no
    /// guaranteed-correct way for a reader to know a priori which one the
    /// writer will have used. The four formats are:
    /// 1. 32-bit format with an initial PK78 marker
    /// 2. 32-bit format without that marker
    /// 3. 64-bit format with the marker
    /// 4. 64-bit format without the marker
    ///
    /// Mark Adler's `sunzip` streaming unzip program solved this ambiguity
    /// by just looking at every possible combination and accepting the
    /// longest one that matches the expected values. His approach always
    /// consumes the longest possible matching EOF marker, based on an
    /// analysis of all the possible failures and how the values could
    /// overlap.
    ///
    /// For example, suppose both of the first two formats listed above
    /// match. In that case, we know the next four 32-bit words match this
    /// pattern:
    /// ```text
    ///  [PK\07\08] [CRC32]        [compressed size]   [uncompressed size]
    /// ```
    /// but we know they must also match this pattern:
    /// ```text
    ///  [CRC32] [compressed size] [uncompressed size] [other PK marker]
    /// ```
    ///
    /// Since the first word here matches both the PK78 signature in the
    /// first form and the CRC32 in the second, we know those two values are
    /// equal, the CRC32 must be exactly 0x08074b50. Similarly, the
    /// compressed and uncompressed size must also be exactly this value. So
    /// we know these four words are all 0x08074b50. If we were to accept the
    /// shorter pattern, it would be immediately followed by another PK78
    /// marker, which is not possible in a well-formed ZIP archive unless
    /// there is garbage between entries. This implies we should not accept
    /// the shorter form in such a case; we should accept the longer form.
    ///
    /// If the second and third possibilities above both match, we have a
    /// slightly different situation. The following words must match both the
    /// 32-bit format
    /// ```text
    ///  [CRC32] [compressed size] [uncompressed size] [other PK marker]
    /// ```
    /// and the 64-bit format
    /// ```text
    ///  [CRC32] [compressed low] [compressed high] [uncompressed low] [uncompressed high] [other PK marker]
    /// ```
    /// Since the 32-bit and 64-bit compressed sizes both match, the actual
    /// size must fit in 32 bits, which implies the high-order word of the
    /// compressed size is zero. So we know the uncompressed low word is
    /// zero, which again implies that if we accept the shorter format, there
    /// will not be a valid PK marker following it.
    ///
    /// Similar considerations rule out the shorter form in every other
    /// possibly-ambiguous pair. So if two of the four possible formats
    /// match, we should accept the longer option.
    ///
    /// If none of the four formats matches, we know the archive must be
    /// corrupted in some fashion. In particular, it's possible that the
    /// length-at-end bit was incorrect and we should not really be looking
    /// for an EOF marker at all. To allow for this possibility, we evaluate
    /// the following words to collect data for a later error report but do
    /// not consume any bytes. We instead rely on the later search for a new
    /// PK marker to re-sync to the next well-formed entry.
    ///
    /// Returns the number of bytes the marker has, to consume.
    fn consume_end_of_file_marker(&mut self, r: &mut Reader<'_>) -> usize {
        const PK78: u32 = 0x0807_4B50;

        // If there shouldn't be a marker, don't consume it.
        if !self.entry.length_at_end() {
            return 0;
        }

        // The longest Zip end-of-file record is 24 bytes. Since an
        // end-of-file record can never appear at the end of the archive, we
        // know 24 bytes will be available unless the archive is severely
        // truncated.
        let marker: Vec<u8> = match r.read_ahead(24) {
            Ok(Some(m)) => m.get(..24).unwrap_or_default().to_vec(),
            _ => return 0,
        };
        let mut p: &[u8] = &marker;

        // The end-of-file record comprises:
        // = Optional PK\007\010 marker
        // = 4-byte CRC32
        // = Compressed size
        // = Uncompressed size
        //
        // The last two fields are either both 32 bits or both 64 bits. We
        // check all possible layouts and accept any one that gives us a
        // complete match, else we make a best-effort attempt to parse out
        // the pieces.

        // CRC32 checking can be tricky:
        // * Test suites sometimes ignore the CRC32
        // * AES AE-2 always writes zero for the CRC32
        // * AES AE-1 sometimes writes zero for the CRC32
        let crc32_ignored = self.ignore_crc32;
        let mut crc32_may_be_zero = false;
        let mut crc32_actual = self.computed_crc32;
        if self.crypto.hmac_valid {
            match self.entry.aes.vendor {
                AES_VENDOR_AE_2 => crc32_actual = 0,
                _ => crc32_may_be_zero = true,
            }
        }

        // Values computed from the actual data in the archive.
        let compressed_actual = self.entry_compressed_bytes_read as u64;
        let uncompressed_actual = self.entry_uncompressed_bytes_read as u64;

        let crc_ok = |off: usize, zero_off: usize| {
            le32(p, off) == crc32_actual
                || (crc32_may_be_zero && le32(p, zero_off) == 0)
                || crc32_ignored
        };

        // Longest: PK78 marker, all 64-bit fields (24 bytes total).
        // Then no PK78 marker, 64-bit fields (20 bytes total), then PK78
        // marker and 32-bit fields (16 bytes total), and the shortest: no
        // PK78 marker, all 32-bit fields (12 bytes total).
        let layouts: [(bool, bool, usize); 4] = [
            (true, true, 24),
            (false, true, 20),
            (true, false, 16),
            (false, false, 12),
        ];
        for (marker_present, wide, len) in layouts {
            let o = if marker_present { 4 } else { 0 };
            let (c, u) = if wide {
                (le64(p, o + 4), le64(p, o + 12))
            } else {
                (u64::from(le32(p, o + 4)), u64::from(le32(p, o + 8)))
            };
            // Upstream tests the second word for zero even where it is
            // not the CRC32.
            if (!marker_present || le32(p, 0) == PK78)
                && crc_ok(o, 4)
                && c == compressed_actual
                && u == uncompressed_actual
            {
                if !crc32_ignored {
                    self.entry.crc32 = crc32_actual;
                }
                self.entry.compressed_size = compressed_actual as i64;
                self.entry.uncompressed_size = uncompressed_actual as i64;
                return len;
            }
        }

        // None of the exact patterns matched. If entry size was unknown
        // (ZIP_LENGTH_AT_END flag), before treating this as corruption,
        // check whether the next ZIP record follows the data immediately: a
        // length-at-end entry whose compression format has its own
        // end-of-stream marker (e.g. PPMd) may be written with no data
        // descriptor at all. In that case the byte counts we measured
        // during decompression are authoritative, so trust them and leave
        // the stream untouched.
        if self.entry.length_at_end() {
            let sig = le32(p, 0);
            if sig == 0x0403_4b50 /* Local file header */
                || sig == 0x0201_4b50 /* Central directory record */
                || sig == 0x0605_4b50
            /* End of central directory */
            {
                self.entry.compressed_size = compressed_actual as i64;
                self.entry.uncompressed_size = uncompressed_actual as i64;
                return 0;
            }
        }

        // If none of the above patterns gives us a full exact match, then
        // there's something definitely amiss. The fallback code below will
        // parse out some plausible values for error reporting purposes. Note
        // that this won't actually consume anything:
        //
        // = If there really is a marker here, the logic to resync to the
        //   next entry will suffice to skip it.
        //
        // = There might not really be a marker: Corruption or bugs may have
        //   set the length-at-end bit without a marker ever having actually
        //   been written. In this case, we explicitly should not consume any
        //   bytes, since that would prevent us from correctly reading the
        //   next entry.
        if le32(p, 0) == PK78 {
            // Ignore PK78 if it appears to be present.
            p = p.get(4..).unwrap_or_default();
        }
        self.entry.crc32 = le32(p, 0); // Parse CRC32
        let p = p.get(4..).unwrap_or_default();

        // Consider both 32- and 64-bit interpretations.
        let compressed32 = u64::from(le32(p, 0));
        let uncompressed32 = u64::from(le32(p, 4));
        let compressed64 = le64(p, 0);
        let uncompressed64 = le64(p, 8);

        // The earlier patterns may have failed because of CRC32 mismatch, so
        // it's still possible that both sizes match. Try to match as many as
        // we can...
        let (c, u) = if compressed32 == compressed_actual && uncompressed32 == uncompressed_actual {
            // Both 32-bit fields match.
            (compressed32, uncompressed32)
        } else if compressed64 == compressed_actual || uncompressed64 == uncompressed_actual {
            // One or both 64-bit fields match.
            (compressed64, uncompressed64)
        } else {
            // Zero or one 32-bit fields match.
            (compressed32, uncompressed32)
        };
        self.entry.compressed_size = c as i64;
        self.entry.uncompressed_size = u as i64;
        0
    }

    /// Read "uncompressed" data.
    ///
    /// This is straightforward if we know the size of the data. This is
    /// always true for the seeking reader (we've examined the Central
    /// Directory already), and will often be true for the streaming reader
    /// (the writer was writing uncompressed so probably knows the size).
    ///
    /// If we don't know the size, then life is more interesting. Note that a
    /// careful reading of the Zip specification says that a writer must use
    /// ZIP_LENGTH_AT_END if it cannot write the CRC into the local header.
    /// And if it uses ZIP_LENGTH_AT_END, then it is prohibited from storing
    /// the sizes in the local header. This prevents fully-compliant
    /// streaming writers from providing any size clues to a streaming
    /// reader. In this case, we have to scan the data as we read to try to
    /// locate the end-of-file marker.
    ///
    /// We assume here that the end-of-file marker always has the PK\007\010
    /// signature. Although it's technically optional, newer writers seem to
    /// provide it pretty consistently, and it's not clear how to efficiently
    /// recognize an end-of-file marker that lacks it.
    ///
    /// Sets `end_of_entry` if it consumes all of the data.
    fn read_none(&mut self, r: &mut Reader<'_>) -> Result<Out, Error> {
        let trailing_extra = if self.crypto.hmac_valid {
            AUTH_CODE_SIZE
        } else {
            0
        };

        let bytes_avail;
        if self.entry.length_at_end() {
            let grabbing_bytes = 24 + trailing_extra;

            // Grab at least 24 bytes.
            let buff = match r.peek_available(grabbing_bytes) {
                // Zip archives have end-of-archive markers that are longer
                // than this, so a failure to get at least 24 bytes really
                // does indicate a truncated file.
                Ok(b) if b.len() >= grabbing_bytes => b,
                _ => return Err(truncated_data()),
            };
            // Check for a complete PK\007\010 signature, followed by the
            // correct 4-byte CRC.
            let mut p = trailing_extra;
            if buff.get(p..p + 4) == Some(b"PK\x07\x08")
                && (le32(buff, p + 4) == self.computed_crc32
                    || self.ignore_crc32
                    || (self.crypto.hmac_valid && self.entry.aes.vendor == AES_VENDOR_AE_2))
            {
                self.end_of_entry = true;
                if self.crypto.hmac_valid {
                    let code = buff.get(..AUTH_CODE_SIZE).unwrap_or_default().to_vec();
                    if self.crypto.check_authentication_code(r, Some(&code))? == Status::Warn {
                        return Ok(Out::Warn);
                    }
                }
                return Ok(Out::Buf(0));
            }
            // If not at EOF, ensure we consume at least one byte.
            p += 1;

            // Scan forward until we see where a PK\007\010 signature might
            // be. Return bytes up until that point. On the next call, the
            // code above will verify the data descriptor.
            let at = |i: usize| buff.get(i).copied().unwrap_or(0);
            while p + 4 < buff.len() {
                if at(p + 3) == b'P' {
                    p += 3;
                } else if at(p + 3) == b'K' {
                    p += 2;
                } else if at(p + 3) == 0o7 {
                    p += 1;
                } else if at(p + 3) == 0o10
                    && at(p + 2) == 0o7
                    && at(p + 1) == b'K'
                    && at(p) == b'P'
                {
                    break;
                } else {
                    p += 4;
                }
            }
            bytes_avail = p - trailing_extra;
        } else {
            if self.entry_bytes_remaining == 0 {
                self.end_of_entry = true;
                if self.crypto.hmac_valid
                    && self.crypto.check_authentication_code(r, None)? == Status::Warn
                {
                    return Ok(Out::Warn);
                }
                return Ok(Out::Buf(0));
            }
            // Grab a bunch of bytes.
            let avail = match r.peek_available(1) {
                Ok(b) if !b.is_empty() => b.len(),
                _ => return Err(truncated_data()),
            };
            // A negative number of bytes left can't be consumed.
            let Ok(remaining) = usize::try_from(self.entry_bytes_remaining) else {
                return Err(truncated_data());
            };
            bytes_avail = avail.min(remaining);
        }
        let mut n = bytes_avail;
        let stored = if self.crypto.active() {
            let buff = r.peek_available(1).map_err(|_| truncated_data())?;
            n = self
                .crypto
                .decrypt_stored(buff.get(..n).unwrap_or_default());
            Out::Dec(n)
        } else {
            Out::Stream(n)
        };
        let n_i64 = n as i64;
        self.entry_bytes_remaining -= n_i64;
        self.entry_uncompressed_bytes_read += n_i64;
        self.entry_compressed_bytes_read += n_i64;
        Ok(stored)
    }

    /// `zip_deflate_init`.
    fn deflate_init(&mut self) {
        // If we haven't yet read any data, initialize the decompressor.
        if !self.decompress_init {
            match &mut self.inflate {
                // Don't check for zlib header.
                Some(s) => s.reset(DataFormat::Raw),
                None => self.inflate = Some(InflateState::new_boxed(DataFormat::Raw)),
            }
            // We've initialized decompression for this stream.
            self.decompress_init = true;
        }
    }

    fn read_deflate(&mut self, r: &mut Reader<'_>) -> Result<Out, Error> {
        // If the buffer hasn't been allocated, allocate it now.
        if self.uncompressed_buffer.is_empty() {
            self.alloc_buffer(BUFFER_SIZE, "No memory for ZIP decompression")?;
        }

        self.deflate_init();

        // Note: '1' here is a performance optimization. Recall that the
        // decompression layer returns a count of available bytes; asking for
        // more than that forces the decompressor to combine reads by
        // copying data.
        let truncated = || Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated ZIP file body");
        let comp = r.peek_available(1).map_err(|_| truncated())?;
        let bytes_avail = self.clip(comp.len()).ok_or_else(truncated)?;

        let limit = self.limit();
        let input = self.crypto.prepare(comp, bytes_avail, limit);

        // stream.avail_in is a uInt, which is 32 bits wide even where
        // ssize_t is 64 bits.
        let input = input
            .get(..input.len().min(u32::MAX as usize))
            .unwrap_or_default();
        let Some(state) = self.inflate.as_mut() else {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_MISC,
                "Can't initialize ZIP decompression",
            ));
        };
        let (consumed, written, ended) =
            inflate(state, input, &mut self.uncompressed_buffer).map_err(inflate_failed)?;
        if ended {
            self.end_of_entry = true;
        }

        // Consume as much as the compressor actually used.
        let to_consume = consumed;
        self.crypto.finish(to_consume, comp);
        r.consume(to_consume)?;
        self.entry_bytes_remaining -= to_consume as i64;
        self.entry_compressed_bytes_read += to_consume as i64;
        self.entry_uncompressed_bytes_read += written as i64;

        if self.end_of_entry
            && self.crypto.hmac_valid
            && let Some(out) = self.authenticate(r)?
        {
            return Ok(out);
        }

        Ok(Out::Buf(written))
    }

    /// `read_decryption_header`: strong encryption, which is not supported.
    fn read_decryption_header(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let corrupted = || Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Corrupted ZIP file data");

        // Read an initialization vector data field.
        let Ok(Some(p)) = r.read_ahead(2) else {
            return Err(truncated_data());
        };
        let iv_size = usize::from(le16(p, 0));
        r.consume(2)?;
        if !matches!(r.read_ahead(iv_size), Ok(Some(_))) {
            return Err(truncated_data());
        }
        r.consume(iv_size)?;

        // Read a size of remaining decryption header field.
        let Ok(Some(p)) = r.read_ahead(14) else {
            return Err(truncated_data());
        };
        let remaining_size = le32(p, 0);
        if !(16..=(1 << 18)).contains(&remaining_size) {
            return Err(corrupted());
        }

        // Check if format version is supported.
        if le16(p, 4) != 3 {
            return Err(Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_FILE_FORMAT,
                format!("Unsupported encryption format version: {}", le16(p, 4)),
            ));
        }

        // Read an encryption algorithm field.
        let alg_id = le16(p, 6);
        match alg_id {
            0x6601 | 0x6602 | 0x6603 | 0x6609 | 0x660E | 0x660F | 0x6610 | 0x6702 | 0x6720
            | 0x6721 | 0x6801 => {}
            _ => {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    format!("Unknown encryption algorithm: {alg_id}"),
                ));
            }
        }

        // Read a flags field. Upstream masks the flags with 0xf000 and then
        // compares them with 1, 2 and 3, so no flags are ever accepted, and
        // the rest of the header (which it doesn't use either) is never
        // read.
        let flags = le16(p, 10);
        Err(Error::new(
            ARCHIVE_FAILED,
            ARCHIVE_ERRNO_FILE_FORMAT,
            format!("Unknown encryption flag: {flags}"),
        ))
    }

    fn init_traditional_pkware_decryption(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        const ENC_HEADER_SIZE: usize = 12;

        if self.crypto.trad.is_some() {
            return Ok(());
        }

        // Read the 12 bytes encryption header stored at the start of the
        // data area.
        if !self.entry.length_at_end() && self.entry_bytes_remaining < ENC_HEADER_SIZE as i64 {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                format!(
                    "Truncated Zip encrypted body: only {} bytes available",
                    self.entry_bytes_remaining
                ),
            ));
        }

        let header: [u8; ENC_HEADER_SIZE] = match r.read_ahead(ENC_HEADER_SIZE) {
            Ok(Some(p)) => p.first_chunk().copied().unwrap_or_default(),
            _ => return Err(truncated_data()),
        };

        let mut retry = 0;
        let ctx = loop {
            let Some(passphrase) = r.next_passphrase() else {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    if retry > 0 {
                        "Incorrect passphrase"
                    } else {
                        "Passphrase required for this entry"
                    },
                ));
            };

            // Initialize ctx for Traditional PKWARE Decryption.
            let (ctx, crcchk) = Trad::new(until_nul(&passphrase), &header);
            if crcchk == self.entry.decdat {
                break ctx; // The passphrase is OK.
            }
            if retry > 10000 {
                // Avoid infinity loop.
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    "Too many incorrect passphrases",
                ));
            }
            retry += 1;
        };

        r.consume(ENC_HEADER_SIZE)?;
        self.crypto.trad = Some(ctx);
        if !self.entry.length_at_end() {
            self.entry_bytes_remaining -= ENC_HEADER_SIZE as i64;
        }
        self.entry_compressed_bytes_read += ENC_HEADER_SIZE as i64;
        self.crypto.start()
    }

    fn init_winzip_aes_decryption(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let corrupted = || Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Corrupted ZIP file data");

        if self.crypto.aes.is_some() || self.crypto.hmac_valid {
            return Ok(());
        }

        let (salt_len, key_len) = match self.entry.aes.strength {
            1 => (8, 16),
            2 => (12, 24),
            3 => (16, 32),
            _ => return Err(corrupted()),
        };
        let p: Vec<u8> = match r.read_ahead(salt_len + 2) {
            Ok(Some(p)) => p.get(..salt_len + 2).unwrap_or_default().to_vec(),
            _ => return Err(truncated_data()),
        };
        let (salt, pv) = p.split_at(salt_len);

        let mut derived_key = [0u8; 32 * 2 + 2];
        let mut retry = 0;
        loop {
            let Some(passphrase) = r.next_passphrase() else {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    if retry > 0 {
                        "Incorrect passphrase"
                    } else {
                        "Passphrase required for this entry"
                    },
                ));
            };
            derived_key.fill(0);
            let dk = derived_key.get_mut(..key_len * 2 + 2).unwrap_or_default();
            pbkdf2_sha1(until_nul(&passphrase), salt, 1000, dk);

            // Check password verification value.
            if dk.get(key_len * 2..key_len * 2 + 2) == Some(pv) {
                break; // The passphrase is OK.
            }
            if retry > 10000 {
                // Avoid infinity loop.
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    "Too many incorrect passphrases",
                ));
            }
            retry += 1;
        }

        let key = derived_key.get(..key_len).unwrap_or_default();
        let Some(aes) = crate::cryptor::AesCtr::new(key) else {
            return Err(Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_MISC,
                "Decryption is unsupported due to lack of crypto library",
            ));
        };
        let Some(hmac) = HmacSha1::new(derived_key.get(key_len..key_len * 2).unwrap_or_default())
        else {
            return Err(Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_MISC,
                "Failed to initialize HMAC-SHA1",
            ));
        };
        self.crypto.aes = Some(aes);
        self.crypto.hmac = Some(hmac);
        self.crypto.hmac_valid = true;
        r.consume(salt_len + 2)?;
        let overhead = (salt_len + 2 + AUTH_CODE_SIZE) as i64;
        self.entry_bytes_remaining -= overhead;
        if !self.entry.length_at_end() && self.entry_bytes_remaining < 0 {
            return Err(corrupted());
        }
        self.entry_compressed_bytes_read += overhead;

        self.entry.compression = self.entry.aes.compression;
        self.crypto.start()
    }

    /// Sets up the decryption of the entry, when its data is first read.
    fn start_decryption(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        self.has_encrypted_entries = 1;
        if self.entry.zip_flags & ZIP_STRONG_ENCRYPTED != 0 {
            self.read_decryption_header(r)?;
        } else if self.entry.compression == WINZIP_AES_ENCRYPTION {
            self.init_winzip_aes_decryption(r)?;
        } else {
            self.init_traditional_pkware_decryption(r)?;
        }
        self.init_decryption = false;
        Ok(())
    }
}

impl<const SEEKABLE: bool> Format for Zip<SEEKABLE> {
    fn name(&self) -> &'static str {
        "zip"
    }

    fn bid(&mut self, r: &mut Reader<'_>, best_bid: c_int) -> Result<c_int, Error> {
        if SEEKABLE {
            self.seekable_bid(r, best_bid)
        } else {
            Ok(Self::streamable_bid(r))
        }
    }

    fn options(
        &mut self,
        a: &Base,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<Result<Status, Error>> {
        Some(self.option(a, key, value))
    }

    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        if SEEKABLE {
            self.read_header_seekable(r, entry)
        } else {
            self.read_header_streamable(r, entry)
        }
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        if self.has_encrypted_entries == ENCRYPTION_DONT_KNOW {
            self.has_encrypted_entries = 0;
        }

        let offset = self.entry_uncompressed_bytes_read;

        // If we hit end-of-entry last time, return ARCHIVE_EOF.
        if self.end_of_entry {
            return Ok(Data::Eof { offset });
        }

        // Return EOF immediately if this is a non-regular file.
        if self.entry.mode & IFMT != IFREG {
            return Ok(Data::Eof { offset });
        }

        let later = r.consume_later();

        if self.init_decryption {
            self.start_decryption(r)?;
        }

        let out = match self.entry.compression {
            0 => self.read_none(r)?,
            12 => self.read_zipx_bzip2(r)?,
            // ZIPx LZMA compression.
            14 => self.read_lzma_alone(r)?,
            // ZIPx XZ compression.
            95 => self.read_zipx_xz(r)?,
            // ZIPx Zstd compression.
            93 => self.read_zipx_zstd(r)?,
            // ZIPx PPMd compression.
            98 => self.read_zipx_ppmd(r)?,
            8 => self.read_deflate(r)?,
            c => {
                // Return a failure: we can't decompress this entry, but we
                // will be able to skip() it and try the next entry.
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    format!(
                        "Unsupported ZIP compression method ({}: {})",
                        c,
                        compression_name(c)
                    ),
                ));
            }
        };
        let (Out::Buf(size) | Out::Stream(size) | Out::Dec(size)) = out else {
            return Ok(Data::Warn);
        };

        // FAIL if there are more uncompressed bytes than were initially
        // advertised. The end-of-entry check below also compares these
        // values, but only once decoding reaches its own natural end. Fail
        // the entry so a caller relying on archive_entry_size() as a hard
        // boundary is never misled; later entries in the archive can still
        // be read normally.
        if size > 0
            && self.entry.size_is_set()
            && self.entry_uncompressed_bytes_read > self.entry.uncompressed_size
        {
            if !matches!(out, Out::Buf(_)) {
                later.consume(size);
            }
            return Err(Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_MISC,
                format!(
                    "ZIP uncompressed data is larger than the declared entry size (read at least {}, expected {})",
                    self.entry_uncompressed_bytes_read, self.entry.uncompressed_size
                ),
            ));
        }

        // Stored data is returned in place and consumed by the next call. It
        // never ends the entry: that is a call that has no data.
        match out {
            Out::Stream(_) => {
                let data = match r.read_ahead(1) {
                    Ok(Some(d)) => d.get(..size).unwrap_or_default(),
                    _ => return Err(truncated_data()),
                };
                self.computed_crc32 = self.crc(self.computed_crc32, data);
                later.consume(size);
                return Ok(Data::Block { data, offset });
            }
            Out::Dec(_) => {
                let data = self.crypto.decrypted(size);
                self.computed_crc32 = if self.ignore_crc32 {
                    0
                } else {
                    crc32(self.computed_crc32, data)
                };
                later.consume(size);
                return Ok(Data::Block { data, offset });
            }
            _ => {}
        }

        if size > 0 {
            let data = self.uncompressed_buffer.get(..size).unwrap_or_default();
            self.computed_crc32 = if self.ignore_crc32 {
                0
            } else {
                crc32(self.computed_crc32, data)
            };
        }
        // If we hit the end, swallow any end-of-data marker and verify the
        // final check values.
        if self.end_of_entry {
            later.consume(self.consume_end_of_file_marker(r));

            // Check computed CRC against header.
            if (!self.crypto.hmac_valid || self.entry.aes.vendor != AES_VENDOR_AE_2)
                && self.entry.crc32 != self.computed_crc32
                && !self.ignore_crc32
            {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    format!(
                        "ZIP bad CRC: 0x{:x} should be 0x{:x}",
                        self.computed_crc32, self.entry.crc32
                    ),
                ));
            }
            // Check file size against header.
            if self.entry.compressed_size != self.entry_compressed_bytes_read {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    format!(
                        "ZIP compressed data is wrong size (read {}, expected {})",
                        self.entry_compressed_bytes_read, self.entry.compressed_size
                    ),
                ));
            }
            if self.entry.uncompressed_size != self.entry_uncompressed_bytes_read {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    format!(
                        "ZIP uncompressed data is wrong size (read {}, expected {})",
                        self.entry_uncompressed_bytes_read, self.entry.uncompressed_size
                    ),
                ));
            }
        }

        Ok(Data::Block {
            data: self.uncompressed_buffer.get(..size).unwrap_or_default(),
            offset,
        })
    }

    fn read_data_skip(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        if SEEKABLE {
            // We're going to seek for the next header anyway, so we don't
            // need to bother doing anything here.
            Ok(Status::Ok)
        } else {
            self.skip_streamable(r)
        }
    }

    fn capabilities(&self) -> c_int {
        CAPS_ENCRYPT
    }

    fn has_encrypted_entries(&self) -> c_int {
        self.has_encrypted_entries
    }
}

// Streaming-mode support.

impl<const SEEKABLE: bool> Zip<SEEKABLE> {
    fn streamable_bid(r: &mut Reader<'_>) -> c_int {
        let Ok(Some(h)) = r.read_ahead(4) else {
            return -1;
        };

        // Bid of 29 here comes from:
        //  + 16 bits for "PK",
        //  + next 16-bit field has 6 options so contributes
        //    about 16 - log_2(6) ~= 16 - 2.6 ~= 13 bits
        //
        // So we've effectively verified ~29 total bits of check data.
        if h.starts_with(b"PK")
            && matches!(
                h.get(2..4),
                Some(b"\x01\x02" | b"\x03\x04" | b"\x05\x06" | b"\x06\x06" | b"\x07\x08" | b"00")
            )
        {
            return 29;
        }

        // TODO: It's worth looking ahead a little bit for a valid PK
        // signature. In particular, that would make it possible to read
        // some UUEncoded SFX files or SFX files coming from a network
        // socket.

        0
    }

    fn read_header_streamable(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
    ) -> Result<Status, Error> {
        Self::set_format(r.base());

        // It should be sufficient to call archive_read_next_header() for a
        // reader to determine if an entry is encrypted or not. If the
        // encryption of an entry is only detectable when calling
        // archive_read_data(), so be it. We'll do the same check there as
        // well.
        if self.has_encrypted_entries == ENCRYPTION_DONT_KNOW {
            self.has_encrypted_entries = 0;
        }

        // Make sure we have a zip_entry structure to use.
        self.entry = ZipEntry::default();

        self.crypto.reset();
        r.reset_passphrase();

        // Search ahead for the next local file header.
        loop {
            let (skipped, found) = {
                let h = r.peek_available(4)?;
                if h.len() < 4 {
                    return Err(Error::silent(ARCHIVE_FATAL));
                }
                let mut skipped = 0usize;
                let mut found = None;
                while let Some(&[a, b, c, d]) = h.get(skipped..skipped + 4) {
                    if a == b'P' && b == b'K' {
                        if c == 3 && d == 4 {
                            // Regular file entry.
                            found = Some(true);
                            break;
                        }

                        // TODO: We cannot restore permissions based only on
                        // the local file headers. Consider scanning the
                        // central directory and returning additional entries
                        // for at least directories. This would allow us to
                        // properly set directory permissions.
                        //
                        // This won't help us fix symlinks and may not help
                        // with regular file permissions, either. <sigh>
                        if c == 1 && d == 2 {
                            found = Some(false);
                            break;
                        }

                        // End of central directory? Must be an empty archive.
                        if (c == 5 && d == 6) || (c == 6 && d == 6) {
                            found = Some(false);
                            break;
                        }
                    }
                    skipped += 1;
                }
                (skipped, found)
            };
            match found {
                Some(true) => {
                    r.consume(skipped)?;
                    return self.read_local_file_header(r, entry);
                }
                Some(false) => return Ok(Status::Eof),
                None => r.consume(skipped)?,
            }
        }
    }

    fn skip_streamable(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        // If we've already read to end of data, we're done.
        if self.end_of_entry {
            return Ok(Status::Ok);
        }

        // So we know we're streaming...
        if !self.entry.length_at_end() || self.entry.compressed_size > 0 {
            // We know the compressed length, so we can just skip.
            r.consume(self.entry_bytes_remaining)?;
            return Ok(Status::Ok);
        }

        if self.init_decryption {
            self.start_decryption(r)?;
        }

        // We're streaming and we don't know the length.
        // If the body is compressed and we know the format, we can find an
        // exact end-of-entry by decompressing it.
        if self.entry.compression == 8 {
            // Deflate compression.
            while !self.end_of_entry {
                if let Out::Warn = self.read_deflate(r)? {
                    return Ok(Status::Warn);
                }
            }
            return Ok(Status::Ok);
        }

        // Uncompressed or unknown. Scan for a PK\007\010 signature.
        loop {
            let (found, advance) = {
                let buff = r.peek_available(16)?;
                if buff.len() < 16 {
                    return Err(truncated_data());
                }
                let at = |i: usize| buff.get(i).copied().unwrap_or(0);
                let mut p = 0usize;
                let mut found = None;
                while p + 16 <= buff.len() {
                    if at(p + 3) == b'P' {
                        p += 3;
                    } else if at(p + 3) == b'K' {
                        p += 2;
                    } else if at(p + 3) == 0o7 {
                        p += 1;
                    } else if at(p + 3) == 0o10
                        && at(p + 2) == 0o7
                        && at(p + 1) == b'K'
                        && at(p) == b'P'
                    {
                        found = Some(if self.entry.flags & LA_USED_ZIP64 != 0 {
                            p + 24
                        } else {
                            p + 16
                        });
                        break;
                    } else {
                        p += 4;
                    }
                }
                (found, p)
            };
            if let Some(n) = found {
                r.consume(n)?;
                return Ok(Status::Ok);
            }
            r.consume(advance)?;
        }
    }
}

// Seeking-mode support.

impl<const SEEKABLE: bool> Zip<SEEKABLE> {
    /// TODO: This is a performance sink because it forces the read core to
    /// drop buffered data from the start of file, which will then have to be
    /// re-read again if this bidder loses.
    ///
    /// We workaround this a little by passing in the best bid so far so that
    /// later bidders can do nothing if they know they'll never outbid. But
    /// we can certainly do better...
    fn read_eocd(&mut self, p: &[u8], current_offset: i64) -> c_int {
        let disk_num = le16(p, 4);
        let cd_size = le32(p, 12);
        let cd_offset = le32(p, 16);

        // Sanity-check the EOCD we've found.

        // This must be the first volume.
        if disk_num != 0 {
            return 0;
        }
        // Central directory must be on this volume.
        if disk_num != le16(p, 6) {
            return 0;
        }
        // All central directory entries must be on this volume.
        if le16(p, 10) != le16(p, 8) {
            return 0;
        }
        // Central directory can't extend beyond start of EOCD record.
        if i64::from(cd_offset) + i64::from(cd_size) > current_offset {
            return 0;
        }

        // Save the central directory location for later use.
        self.central_directory_offset = i64::from(cd_offset);
        self.central_directory_offset_adjusted = current_offset - i64::from(cd_size);

        // This is just a tiny bit higher than the maximum returned by the
        // streaming Zip bidder. This ensures that the more accurate seeking
        // Zip parser wins whenever seek is available.
        32
    }

    /// Examine Zip64 EOCD locator: If it's valid, store the information from
    /// it.
    fn read_zip64_eocd(&mut self, r: &mut Reader<'_>, p: &[u8]) -> c_int {
        // Sanity-check the locator record.

        // Central dir must be on first volume.
        if le32(p, 4) != 0 {
            return 0;
        }
        // Must be only a single volume.
        if le32(p, 16) != 1 {
            return 0;
        }

        // Find the Zip64 EOCD record.
        let eocd64_offset = le64(p, 8) as i64;
        if r.seek(eocd64_offset, Whence::Set).is_err() {
            return 0;
        }
        let Ok(Some(p)) = r.read_ahead(56) else {
            return 0;
        };
        // Make sure we can read all of it.
        let eocd64_size = le64(p, 4).wrapping_add(12) as i64;
        if !(56..=16384).contains(&eocd64_size) {
            return 0;
        }
        let Ok(Some(p)) = r.read_ahead(eocd64_size as usize) else {
            return 0;
        };

        // Sanity-check the EOCD64.
        if le32(p, 16) != 0 {
            // Must be disk #0.
            return 0;
        }
        if le32(p, 20) != 0 {
            // CD must be on disk #0.
            return 0;
        }
        // CD can't be split.
        if le64(p, 24) != le64(p, 32) {
            return 0;
        }

        // Save the central directory offset for later use.
        self.central_directory_offset = le64(p, 48) as i64;
        // TODO: Needs scanning backwards to find the eocd64 instead of
        // assuming.
        self.central_directory_offset_adjusted = self.central_directory_offset;

        32
    }

    fn seekable_bid(&mut self, r: &mut Reader<'_>, best_bid: c_int) -> Result<c_int, Error> {
        // If someone has already bid more than 32, then avoid trashing the
        // look-ahead buffers with a seek.
        if best_bid > 32 {
            return Ok(-1);
        }

        let Ok(file_size) = r.seek(0, Whence::End) else {
            return Ok(0);
        };
        if file_size <= 0 {
            return Ok(0);
        }

        // Search last 16k of file for end-of-central-directory record (which
        // starts with PK\005\006).
        let tail = file_size.min(1024 * 16);
        let Ok(current_offset) = r.seek(-tail, Whence::End) else {
            return Ok(0);
        };
        if current_offset < 0 {
            return Ok(0);
        }
        let h: Vec<u8> = match r.read_ahead(tail as usize) {
            Ok(Some(h)) => h.get(..tail as usize).unwrap_or_default().to_vec(),
            _ => return Ok(0),
        };
        // Boyer-Moore search backwards from the end, since we want to match
        // the last EOCD in the file (there can be more than one if there is
        // an uncompressed Zip archive as a member within this Zip archive).
        //
        // The lower bound is inclusive (>= 0, not > 0): a minimal, valid,
        // zero-entry archive is exactly 22 bytes long, putting the EOCD
        // signature at index 0 of this search window.
        let mut i = tail - 22;
        while i >= 0 {
            let at = i as usize;
            match h.get(at).copied().unwrap_or(0) {
                b'P' => {
                    if h.get(at..at + 4) == Some(b"PK\x05\x06") {
                        let mut ret =
                            self.read_eocd(h.get(at..).unwrap_or_default(), current_offset + i);
                        // Zip64 EOCD locator precedes regular EOCD if present.
                        if at >= 20 && h.get(at - 20..at - 16) == Some(b"PK\x06\x07") {
                            let locator = h.get(at - 20..at).unwrap_or_default();
                            let ret_zip64 = self.read_zip64_eocd(r, locator);
                            if ret_zip64 > ret {
                                ret = ret_zip64;
                            }
                        }
                        return Ok(ret);
                    }
                    i -= 4;
                }
                b'K' => i -= 1,
                5 => i -= 2,
                6 => i -= 3,
                _ => i -= 4,
            }
        }
        Ok(0)
    }

    fn slurp_central_directory(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
    ) -> Result<(), Error> {
        let a = r.base();

        // Find the start of the central directory. The end-of-CD record has
        // our starting point, but there are lots of Zip archives which have
        // had other data prepended to the file, which makes the recorded
        // offsets all too small. So we search forward from the specified
        // offset until we find the real start of the central directory. Then
        // we know the correction we need to apply to account for leading
        // padding.
        if r.seek(self.central_directory_offset_adjusted, Whence::Set)
            .is_err()
        {
            return Err(Error::silent(ARCHIVE_FATAL));
        }

        let mut found = false;
        while !found {
            let mut i = 0usize;
            {
                let p = r.peek_available(20)?;
                if p.len() < 20 {
                    return Err(Error::silent(ARCHIVE_FATAL));
                }
                while !found && i + 4 < p.len() {
                    match p.get(i + 3).copied().unwrap_or(0) {
                        b'P' => i += 3,
                        b'K' => i += 2,
                        1 => i += 1,
                        2 => {
                            if p.get(i..i + 4) == Some(b"PK\x01\x02") {
                                found = true;
                            } else {
                                i += 4;
                            }
                        }
                        5 => i += 1,
                        6 => {
                            if p.get(i..i + 4) == Some(b"PK\x05\x06")
                                || p.get(i..i + 4) == Some(b"PK\x06\x06")
                            {
                                found = true;
                            } else {
                                i += 1;
                            }
                        }
                        _ => i += 4,
                    }
                }
            }
            r.consume(i)?;
        }
        let correction = r.position().wrapping_sub(self.central_directory_offset);

        self.tree.clear();
        self.tree_rsrc.clear();

        loop {
            let p = match r.read_ahead(4) {
                Ok(Some(p)) => p,
                Ok(None) => return Err(Error::silent(ARCHIVE_FATAL)),
                Err(e) => return Err(e),
            };
            if p.starts_with(b"PK\x06\x06") || p.starts_with(b"PK\x05\x06") {
                break;
            } else if !p.starts_with(b"PK\x01\x02") {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_MISC,
                    "Invalid central directory signature",
                ));
            }
            let p: Vec<u8> = match r.read_ahead(46) {
                Ok(Some(p)) => p.get(..46).unwrap_or_default().to_vec(),
                Ok(None) => return Err(Error::silent(ARCHIVE_FATAL)),
                Err(e) => return Err(e),
            };

            let mut ze = ZipEntry {
                flags: LA_FROM_CENTRAL_DIRECTORY,
                ..ZipEntry::default()
            };

            // version = p[4]
            ze.system = p.get(5).copied().unwrap_or(0);
            // version_required = le16(p + 6)
            ze.zip_flags = le16(&p, 8);
            if ze.zip_flags & (ZIP_ENCRYPTED | ZIP_STRONG_ENCRYPTED) != 0 {
                self.has_encrypted_entries = 1;
            }
            ze.compression = le16(&p, 10) as u8;
            ze.mtime = dos_to_unix(le32(&p, 12));
            ze.crc32 = le32(&p, 16);
            ze.decdat = p
                .get(if ze.length_at_end() { 13 } else { 19 })
                .copied()
                .unwrap_or(0);
            ze.compressed_size = i64::from(le32(&p, 20));
            ze.uncompressed_size = i64::from(le32(&p, 24));
            let filename_length = usize::from(le16(&p, 28));
            let extra_length = usize::from(le16(&p, 30));
            let comment_length = usize::from(le16(&p, 32));
            // disk_start = le16(p + 34), better be zero.
            // internal_attributes = le16(p + 36), text bit.
            let external_attributes = le32(&p, 38);
            ze.local_header_offset = i64::from(le32(&p, 42)).wrapping_add(correction);

            // If we can't guess the mode, leave it zero here; when we read
            // the local file header we might get more information.
            ze.mode = ze.mode_from_attributes(external_attributes);

            // We're done with the regular data; get the filename and extra
            // data.
            r.consume(46)?;
            let p = match r.read_ahead(filename_length + extra_length) {
                Ok(Some(p)) => p,
                _ => return Err(truncated_header()),
            };
            let name = p.get(..filename_length).unwrap_or_default();
            let extra = p
                .get(filename_length..filename_length + extra_length)
                .unwrap_or_default();
            let mut cx = ExtraContext {
                a,
                sconv_utf8: &mut self.sconv_utf8,
                ignore_crc32: self.ignore_crc32,
            };
            process_extra(&mut cx, Some(&mut *entry), extra, &mut ze).map_err(|e| Error {
                code: ARCHIVE_FATAL,
                ..e
            })?;

            if self.zip_entries.try_reserve(1).is_err() {
                return Err(Error::fatal(libc::ENOMEM, "Can't allocate zip entry"));
            }
            let index = self.zip_entries.len();

            // Mac resource fork files are stored under the "__MACOSX/"
            // directory, so we should check if it is.
            if !self.process_mac_extensions {
                // Treat every entry as a regular entry.
                let offset = ze.local_header_offset;
                self.zip_entries.push(ze);
                self.tree.entry(offset).or_insert(index);
            } else {
                self.add_mac_entry(ze, name);
            }

            // Skip the comment too ...
            let _ = r.consume(filename_length + extra_length + comment_length);
        }

        Ok(())
    }

    /// The Mac-aware half of the central directory loop: files with a
    /// resource fork under `__MACOSX/` have it found by the name that fork
    /// would have.
    fn add_mac_entry(&mut self, mut ze: ZipEntry, name: &[u8]) {
        let index = self.zip_entries.len();
        let offset = ze.local_header_offset;
        let r = rsrc_basename(name);
        if name.starts_with(b"__MACOSX/") {
            // If this file is not a resource fork nor a directory. We should
            // treat it as a non resource fork file to expose it.
            if name.last() != Some(&b'/')
                && (name.len() - r < 2
                    || name.get(r) != Some(&b'.')
                    || name.get(r + 1) != Some(&b'_'))
            {
                self.zip_entries.push(ze);
                self.tree.entry(offset).or_insert(index);
                // Expose its parent directories.
                self.expose_parent_dirs(name);
            } else {
                // This file is a resource fork file or a directory.
                let rsrcname = until_nul(name).to_vec();
                ze.rsrcname = Some(rsrcname.clone());
                self.zip_entries.push(ze);
                self.tree_rsrc.entry(rsrcname).or_insert(index);
            }
        } else {
            // Generate resource fork name to find its resource file at
            // tree_rsrc.

            // If this is an entry ending with slash, make the resource for
            // name slash-less as the actual resource fork doesn't end with
            // '/'.
            let mut tmp_length = name.len();
            let mut r = r;
            if tmp_length > 0 && name.get(tmp_length - 1) == Some(&b'/') {
                tmp_length -= 1;
                r = rsrc_basename(name.get(..tmp_length).unwrap_or_default());
            }

            let mut rsrcname = b"__MACOSX/".to_vec();
            rsrcname.extend_from_slice(until_nul(name.get(..r).unwrap_or_default()));
            rsrcname.extend_from_slice(b"._");
            rsrcname.extend_from_slice(until_nul(name.get(r..tmp_length).unwrap_or_default()));
            ze.rsrcname = Some(rsrcname);
            // Register an entry to RB tree to sort it by file offset.
            self.zip_entries.push(ze);
            self.tree.entry(offset).or_insert(index);
        }
    }

    fn expose_parent_dirs(&mut self, name: &[u8]) {
        let mut name = until_nul(name);
        while let Some(s) = name.iter().rposition(|&c| c == b'/') {
            name = name.get(..s).unwrap_or_default();
            // Transfer the parent directory from tree_rsrc to tree to
            // expose.
            let Some(dir) = self.tree_rsrc.remove(name) else {
                break;
            };
            let Some(ze) = self.zip_entries.get_mut(dir) else {
                break;
            };
            ze.rsrcname = None;
            let offset = ze.local_header_offset;
            self.tree.entry(offset).or_insert(dir);
        }
    }

    fn zip_get_local_file_header_size(r: &mut Reader<'_>, extra: usize) -> i64 {
        let a = r.base();
        let p = match r.read_ahead(extra + ZIP_LOCHDR_LEN) {
            Ok(Some(p)) => p,
            _ => {
                a.set_error(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    Some(b"Truncated ZIP file header"),
                );
                return i64::from(ARCHIVE_WARN);
            }
        };
        let p = p.get(extra..).unwrap_or_default();

        if !p.starts_with(b"PK\x03\x04") {
            a.set_error(ARCHIVE_ERRNO_MISC, Some(b"Damaged Zip archive"));
            return i64::from(ARCHIVE_WARN);
        }
        let filename_length = i64::from(le16(p, 26));
        let extra_length = i64::from(le16(p, 28));

        ZIP_LOCHDR_LEN as i64 + filename_length + extra_length
    }

    fn read_mac_metadata(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        rsrc: &ZipEntry,
    ) -> Result<Status, Error> {
        let a = r.base();
        let offset = r.position();
        let mut ret = Status::Ok;

        match rsrc.compression {
            0 => {
                // No compression.
                if rsrc.uncompressed_size != rsrc.compressed_size {
                    return Err(Error::fatal(
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        "Malformed OS X metadata entry: inconsistent size",
                    ));
                }
            }
            8 => {}
            c => {
                // Unsupported compression. We can't decompress this entry,
                // but we will be able to skip() it and try the next entry.
                return Ok(a.warn(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    format!(
                        "Unsupported ZIP compression method ({})",
                        compression_name(c)
                    ),
                ));
            }
        }

        if rsrc.uncompressed_size > ZIP_MAX_METADATA * 1_048_576 {
            return Ok(a.warn(
                ARCHIVE_ERRNO_FILE_FORMAT,
                format!(
                    "Mac metadata is too large: {} > {} MiB",
                    rsrc.uncompressed_size, ZIP_MAX_METADATA
                ),
            ));
        }
        if rsrc.compressed_size > ZIP_MAX_METADATA * 1_048_576 {
            return Ok(a.warn(
                ARCHIVE_ERRNO_FILE_FORMAT,
                format!(
                    "Mac metadata is too large: {} > {} MiB",
                    rsrc.compressed_size, ZIP_MAX_METADATA
                ),
            ));
        }

        let mut metadata = Vec::new();
        let size = usize::try_from(rsrc.uncompressed_size).unwrap_or(0);
        if metadata.try_reserve_exact(size).is_err() {
            return Err(Error::fatal(
                libc::ENOMEM,
                "Can't allocate memory for Mac metadata",
            ));
        }
        metadata.resize(size, 0u8);

        if offset < rsrc.local_header_offset {
            let _ = r.consume(rsrc.local_header_offset - offset);
        } else if offset != rsrc.local_header_offset {
            let _ = r.seek(rsrc.local_header_offset, Whence::Set);
        }

        let hsize = Self::zip_get_local_file_header_size(r, 0);
        let _ = r.consume(hsize);

        let mut remaining_bytes = usize::try_from(rsrc.compressed_size).unwrap_or(0);
        let mut metadata_bytes = size;
        let mut mp = 0usize;
        let mut eof = false;
        let result = (|| -> Result<(), Error> {
            while !eof && remaining_bytes > 0 {
                let p = match r.read_ahead(1) {
                    Ok(Some(p)) => p,
                    _ => {
                        ret = a.warn(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated ZIP file header");
                        return Ok(());
                    }
                };
                let bytes_avail = p.len().min(remaining_bytes);
                let bytes_used;
                match rsrc.compression {
                    0 => {
                        // No compression.
                        let n = bytes_avail.min(metadata_bytes);
                        if let (Some(to), Some(from)) = (metadata.get_mut(mp..mp + n), p.get(..n)) {
                            to.copy_from_slice(from);
                        }
                        bytes_used = n;
                        metadata_bytes -= n;
                        mp += n;
                        if metadata_bytes == 0 {
                            eof = true;
                        }
                    }
                    8 => {
                        // Deflate compression.
                        self.deflate_init();
                        let Some(state) = self.inflate.as_mut() else {
                            return Err(Error::fatal(
                                ARCHIVE_ERRNO_MISC,
                                "Can't initialize ZIP decompression",
                            ));
                        };
                        let input = p
                            .get(..bytes_avail.min(u32::MAX as usize))
                            .unwrap_or_default();
                        let out = metadata.get_mut(mp..).unwrap_or_default();
                        let (consumed, written, ended) =
                            inflate(state, input, out).map_err(inflate_failed)?;
                        eof = ended;
                        bytes_used = consumed;
                        metadata_bytes -= written;
                        mp += written;
                    }
                    _ => bytes_used = 0,
                }
                let _ = r.consume(bytes_used);
                remaining_bytes -= bytes_used;
            }
            if ret == Status::Ok {
                entry.copy_mac_metadata(metadata.get(..size - metadata_bytes).unwrap_or_default());
            }
            Ok(())
        })();

        let _ = r.seek(offset, Whence::Set);
        self.decompress_init = false;
        result.map(|()| ret)
    }

    fn read_header_seekable(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
    ) -> Result<Status, Error> {
        // It should be sufficient to call archive_read_next_header() for a
        // reader to determine if an entry is encrypted or not. If the
        // encryption of an entry is only detectable when calling
        // archive_read_data(), so be it. We'll do the same check there as
        // well.
        if self.has_encrypted_entries == ENCRYPTION_DONT_KNOW {
            self.has_encrypted_entries = 0;
        }

        Self::set_format(r.base());

        if self.zip_entries.is_empty() {
            self.slurp_central_directory(r, entry)?;
            // Get first entry whose local header offset is lower than other
            // entries in the archive file.
            self.current = self.tree.values().next().copied();
        } else if let Some(cur) = self.current {
            // Get next entry in local header offset order.
            let after = self.zip_entries.get(cur).map(|e| e.local_header_offset);
            self.current = after.and_then(|o| {
                self.tree
                    .range((Bound::Excluded(o), Bound::Unbounded))
                    .next()
                    .map(|(_, &i)| i)
            });
        }

        let Some(cur) = self.current else {
            return Ok(Status::Eof);
        };
        self.entry = self.zip_entries.get(cur).cloned().unwrap_or_default();

        let rsrc = self
            .entry
            .rsrcname
            .as_ref()
            .and_then(|name| self.tree_rsrc.get(name))
            .and_then(|&i| self.zip_entries.get(i))
            .cloned();

        self.crypto.reset();
        r.reset_passphrase();

        // File entries are sorted by the header offset, we should mostly use
        // __archive_read_consume to advance a read point to avoid redundant
        // data reading.
        let offset = r.position();
        if offset < self.entry.local_header_offset {
            let _ = r.consume(self.entry.local_header_offset - offset);
        } else if offset != self.entry.local_header_offset {
            let _ = r.seek(self.entry.local_header_offset, Whence::Set);
        }
        let status = self.read_local_file_header(r, entry)?;
        if status != Status::Ok {
            return Ok(status);
        }
        if let Some(rsrc) = rsrc {
            return self.read_mac_metadata(r, entry, &rsrc);
        }
        Ok(Status::Ok)
    }
}

/// `rsrc_basename`: where the part of the name after its last '/' starts.
fn rsrc_basename(name: &[u8]) -> usize {
    name.iter().rposition(|&c| c == b'/').map_or(0, |i| i + 1)
}

/// `archive_read_support_format_zip_streamable`.
pub fn support_streamable(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Zip::<false>::new()))
}

/// `archive_read_support_format_zip_seekable`.
pub fn support_seekable(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Zip::<true>::new()))
}

/// `archive_read_support_format_zip`.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    let status = support_streamable(r)?;
    if status != Status::Ok {
        return Ok(status);
    }
    support_seekable(r)
}
