/*-
 * Copyright (c) 2010-2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_read_support_format_cab.c.

//! The Microsoft Cabinet format: CFHEADER, CFFOLDERs of compressed CFDATA
//! blocks (stored, MSZIP or LZX), and the CFFILEs that are slices of a
//! folder's uncompressed bytes.

mod lzx;

use crate::archive::*;
use crate::entry::{AE_IFREG, Entry, Mode};
use crate::ffi::sys::{Tm, mktime};
use crate::read::{ARCHIVE_ERRNO_FILE_FORMAT, Data, Format, Read, Reader, Status, format_code};
use crate::string::{StringConv, conversion_charset_name, conversion_from_charset};
use crate::util::Error;
use libc::wchar_t;
use lzx::Lzx;
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::inflate_flags::{
    TINFL_FLAG_HAS_MORE_INPUT, TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
};
use miniz_oxide::inflate::core::{DecompressorOxide, decompress};
use std::ffi::c_int;
use std::sync::{Arc, PoisonError};

// CFHEADER, CFFOLDER, CFFILE and CFDATA flags and limits.
const PREV_CABINET: u16 = 0x0001;
const NEXT_CABINET: u16 = 0x0002;
const RESERVE_PRESENT: u16 = 0x0004;

const COMPTYPE_NONE: u16 = 0x0000;
const COMPTYPE_MSZIP: u16 = 0x0001;
const COMPTYPE_LZX: u16 = 0x0003;
const COMPRESSION_NAME: [&str; 4] = ["NONE", "MSZIP", "Quantum", "LZX"];

const FOLD_CONTINUED_FROM_PREV: u16 = 0xFFFD;
const FOLD_CONTINUED_TO_NEXT: u16 = 0xFFFE;
const FOLD_CONTINUED_PREV_AND_NEXT: u16 = 0xFFFF;

const ATTR_RDONLY: u8 = 0x01;
const ATTR_NAME_IS_UTF: u8 = 0x80;

const MAX_UNCOMPRESS_SIZE: usize = 0x8000;
const MAX_FILE_SIZE: i64 = 0xFFFF * MAX_UNCOMPRESS_SIZE as i64;
const SFX_MAX_READAHEAD: usize = 1024 * 512;

/// Where a CFDATA's uncompressed bytes start in `Cab::ubuf`. MSZIP keeps the
/// previous block, its dictionary, in the 32 KiB before.
const OUT: usize = MAX_UNCOMPRESS_SIZE;

#[derive(Default)]
struct Cfdata {
    /// Sum value of this CFDATA.
    sum: u32,
    compressed_size: u16,
    compressed_bytes_remaining: u16,
    uncompressed_size: u16,
    uncompressed_bytes_remaining: u16,
    /// To know how many bytes we have decompressed.
    uncompressed_avail: u16,
    /// Offset from the beginning of the uncompressed data of this CFDATA.
    read_offset: u16,
    unconsumed: i64,
    /// To keep the memory image of this CFDATA to compute the sum.
    memimage: Vec<u8>,
    /// Result of calculation of sum.
    sum_calculated: u32,
    sum_extra: [u8; 4],
    sum_extra_avail: usize,
    /// The bytes at the read position are the ones the sum covers next
    /// (upstream's `sum_ptr`).
    sum_pending: bool,
}

#[derive(Default)]
struct Cffolder {
    cfdata_offset_in_cab: u32,
    cfdata_count: u16,
    comptype: u16,
    compdata: u16,
    compname: &'static str,
    /// At the time reading CFDATA.
    cfdata: Cfdata,
    cfdata_index: i32,
    /// Marks that decompression of this folder is set up.
    decompress_init: bool,
}

struct Cffile {
    uncompressed_size: u32,
    offset: u32,
    mtime: i64,
    folder: u16,
    attr: u8,
    pathname: Vec<u8>,
}

#[derive(Default)]
struct Cfheader {
    files_offset: u32,
    folder_count: u16,
    file_count: u16,
    flags: u16,
    cabinet: u16,
    major: u8,
    minor: u8,
    cffolder: u8,
    cfdata: u8,
    /// All folders in a cabinet.
    folders: Vec<Cffolder>,
    /// All files in a cabinet.
    files: Vec<Cffile>,
    file_index: usize,
}

/// Uncompressed bytes of the current CFDATA that are ready to be read.
enum Ahead {
    /// The first bytes of the input stream (stored data).
    Stream(usize),
    /// `Cab::ubuf[start..start + len]`.
    Buffer(usize, usize),
}

impl Ahead {
    fn len(&self) -> usize {
        match *self {
            Ahead::Stream(len) | Ahead::Buffer(_, len) => len,
        }
    }
}

/// What `cab_read_data` hands out.
struct Block {
    src: Ahead,
    size: usize,
    offset: i64,
}

impl Block {
    fn empty(offset: i64) -> Block {
        Block {
            src: Ahead::Buffer(0, 0),
            size: 0,
            offset,
        }
    }
}

#[derive(Default)]
struct Cab {
    /// entry_bytes_remaining is the number of bytes we expect.
    entry_offset: i64,
    entry_bytes_remaining: i64,
    entry_unconsumed: i64,
    /// The folder and file of the current entry, as indexes.
    entry_cffolder: Option<usize>,
    entry_cffile: Option<usize>,
    /// Whether the CFDATA of the entry's folder is the one being read.
    entry_cfdata: bool,

    /// Offset from the beginning of a cabinet file.
    cab_offset: i64,
    cfheader: Cfheader,

    /// Flag to mark progress that the first header of an archive was read.
    found_header: bool,
    end_of_archive: bool,
    end_of_entry: bool,
    end_of_entry_cleanup: bool,
    read_data_invoked: bool,
    bytes_skipped: i64,

    /// The uncompressed bytes of the current CFDATA of a compressed folder.
    ubuf: Vec<u8>,

    sconv: Option<Arc<StringConv>>,
    sconv_utf8: Option<Arc<StringConv>>,

    inflate: Option<Box<DecompressorOxide>>,
    /// How many bytes before `OUT` in `ubuf` are the MSZIP dictionary.
    dict_len: usize,
    lzx: Option<Lzx>,
}

/// `archive_read_support_format_cab`.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Cab::default()))
}

fn find_cab_magic(p: &[u8]) -> usize {
    match p.get(4) {
        // Note: Self-Extraction program has 'MSCF' string in their program.
        // If we were finding 'MSCF' string only, we got wrong place for
        // Cabinet header, thus, we have to check following four bytes which
        // are reserved and must be set to zero.
        Some(0) => {
            if p.get(..8) == Some(b"MSCF\0\0\0\0") {
                0
            } else {
                5
            }
        }
        Some(b'F') => 1,
        Some(b'C') => 2,
        Some(b'S') => 3,
        Some(b'M') => 4,
        _ => 5,
    }
}

fn le16(p: &[u8], at: usize) -> u16 {
    p.get(at..at + 2)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

fn le32(p: &[u8], at: usize) -> u32 {
    p.get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

/// `__archive_read_ahead` where a failure and a short input are the same.
fn ahead<'r>(r: &'r mut Reader<'_>, min: usize) -> Option<&'r [u8]> {
    r.read_ahead(min).ok().flatten()
}

/// `cab_read_ahead_remaining`: up to `max` of what is left of the input.
fn ahead_remaining<'r>(r: &'r mut Reader<'_>, max: usize) -> &'r [u8] {
    match r.peek_available(max) {
        Ok(s) => s.get(..max).unwrap_or(s),
        Err(_) => &[],
    }
}

/// `strnlen`: the length up to the first NUL, or all of `p`.
fn strnlen(p: &[u8]) -> usize {
    p.iter().position(|&b| b == 0).unwrap_or(p.len())
}

fn truncated_error() -> Error {
    Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated CAB header")
}

fn invalid_header() -> Error {
    Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Invalid CAB header")
}

fn invalid_cfdata() -> Error {
    Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Invalid CFDATA")
}

/// A failure whose message, if any, is already on the handle.
fn fatal() -> Error {
    Error::silent(ARCHIVE_FATAL)
}

fn folder_of(hd: &mut Cfheader, index: Option<usize>) -> Result<&mut Cffolder, Error> {
    index.and_then(|i| hd.folders.get_mut(i)).ok_or_else(fatal)
}

/// Looks for a cabinet header in a self-extracting executable.
fn skip_sfx(r: &mut Reader<'_>) -> Result<(), Error> {
    let mut window = 4096;
    loop {
        let Some(h) = r.peek_available(window).ok().filter(|h| h.len() >= window) else {
            // Remaining size is less than window.
            window >>= 1;
            if window < 128 {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Couldn't find out CAB header",
                ));
            }
            continue;
        };

        // Scan ahead until we find something that looks like the cab header.
        let mut p = 0;
        let mut found = false;
        while p + 8 < h.len() {
            let next = find_cab_magic(&h[p..]);
            if next == 0 {
                found = true;
                break;
            }
            p += next;
        }
        let _ = r.consume(p);
        if found {
            return Ok(());
        }
    }
}

/// Convert a path separator '\' -> '/'. False if a '\' may be the second
/// byte of a multi-byte character, which is left for the wide-character
/// pass.
fn convert_path_separator_1(name: &mut [u8], attr: u8) -> bool {
    let mut mb = false;
    for c in name {
        if *c == b'\\' {
            if mb {
                // This may be second byte of multi-byte character.
                return false;
            }
            *c = b'/';
            mb = false;
        } else {
            mb = *c & 0x80 != 0 && attr & ATTR_NAME_IS_UTF == 0;
        }
    }
    true
}

/// Replace a character '\' with '/' in wide character.
fn convert_path_separator_2(entry: &mut Entry) {
    // If a conversion to wide character failed, force the replacement.
    if let Some(wp) = entry.pathname_w() {
        let mut ws = wp.to_vec();
        for w in &mut ws {
            if *w == b'\\' as wchar_t {
                *w = b'/' as wchar_t;
            }
        }
        entry.copy_pathname_w(&ws);
    }
}

/// Convert an MSDOS-style date/time into Unix-style time.
fn dos_time(p: &[u8]) -> i64 {
    let ms_date = i32::from(le16(p, 0));
    let ms_time = i32::from(le16(p, 2));
    mktime(Tm {
        year: ((ms_date >> 9) & 0x7f) + 80, // Years since 1900.
        mon: ((ms_date >> 5) & 0x0f) - 1,   // Month number.
        mday: ms_date & 0x1f,               // Day of month.
        hour: (ms_time >> 11) & 0x1f,
        min: (ms_time >> 5) & 0x3f,
        sec: (ms_time << 1) & 0x3e,
    })
    .unwrap_or(-1)
}

fn checksum_cfdata_4(p: &[u8], seed: u32) -> u32 {
    p.chunks_exact(4).fold(seed, |sum, w| sum ^ le32(w, 0))
}

fn checksum_cfdata(p: &[u8], seed: u32) -> u32 {
    let sum = checksum_cfdata_4(p, seed);
    let tail = p.get(p.len() & !3..).unwrap_or_default();
    sum ^ tail.iter().fold(0, |t, &b| t << 8 | u32::from(b))
}

impl Cfdata {
    /// Adds the bytes consumed from the stream to the sum of this CFDATA,
    /// which is computed in four-byte words.
    fn checksum_update(&mut self, mut p: &[u8]) {
        if self.sum == 0 || !self.sum_pending {
            return;
        }
        if self.sum_extra_avail != 0 {
            while self.sum_extra_avail < 4 {
                let Some((&b, rest)) = p.split_first() else {
                    break;
                };
                self.sum_extra[self.sum_extra_avail] = b;
                self.sum_extra_avail += 1;
                p = rest;
            }
            if self.sum_extra_avail == 4 {
                self.sum_calculated = checksum_cfdata_4(&self.sum_extra, self.sum_calculated);
                self.sum_extra_avail = 0;
            }
        }
        if !p.is_empty() {
            let odd = p.len() & 3;
            let (words, rest) = p.split_at(p.len() - odd);
            self.sum_calculated = checksum_cfdata_4(words, self.sum_calculated);
            self.sum_extra[..odd].copy_from_slice(rest);
            self.sum_extra_avail = odd;
        }
        self.sum_pending = false;
    }
}

impl Format for Cab {
    fn name(&self) -> &'static str {
        "cab"
    }

    fn bid(&mut self, r: &mut Reader<'_>, best_bid: c_int) -> Result<c_int, Error> {
        // If there's already a better bid than we can ever make, don't
        // bother testing.
        if best_bid > 64 {
            return Ok(-1);
        }
        let Some(h) = ahead(r, 16) else {
            return Ok(-1);
        };
        if h.starts_with(b"MSCF") {
            if h.get(4..8) == Some(b"\0\0\0\0") {
                return Ok(64);
            }
            // Some archives do not have all reserved bits set to zero.
            if h.get(12..16) == Some(b"\0\0\0\0") {
                return Ok(32);
            }
        }

        // Attempt to handle self-extracting archives by noting a PE header
        // and searching forward up to 128k for an 'MSCF' marker.
        if h.starts_with(b"MZ") {
            let mut offset = 0;
            let mut window = 4096;
            while offset + window <= SFX_MAX_READAHEAD {
                let Ok(h) = r.peek_available(offset + window) else {
                    return Ok(0);
                };
                if h.len() < offset + window {
                    if h.len() >= offset + 8 {
                        // Remaining bytes are less than window.
                        window = h.len() - offset;
                        continue;
                    }
                    return Ok(0);
                }
                let bytes_avail = h.len().min(SFX_MAX_READAHEAD);
                while offset + 8 <= bytes_avail {
                    let next = find_cab_magic(h.get(offset..).unwrap_or_default());
                    if next == 0 {
                        return Ok(64);
                    }
                    offset += next;
                }
            }
        }
        Ok(0)
    }

    fn options(
        &mut self,
        a: &Base,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<Result<Status, Error>> {
        if key == b"hdrcharset" {
            let Some(name) = value.filter(|v| !v.is_empty()) else {
                return Some(Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    "cab: hdrcharset option needs a character-set name",
                )));
            };
            let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
            return Some(
                conversion_from_charset(Some(&mut *cache), name, false)
                    .map(|sc| {
                        self.sconv = Some(sc);
                        Status::Ok
                    })
                    .map_err(|e| Error::fatal(e.errno, e.message)),
            );
        }

        // Note: The "warn" return is just to inform the options supervisor
        // that we didn't handle it. It will generate a suitable error if no
        // one used this option.
        Some(Ok(Status::Warn))
    }

    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        let mut status = Status::Ok;
        if !self.found_header {
            status = self.read_cab_header(r)?;
            // We've found the header.
            self.found_header = true;
        }
        let a = r.base();

        let hd = &mut self.cfheader;
        if hd.file_index >= usize::from(hd.file_count) {
            self.end_of_archive = true;
            return Ok(Status::Eof);
        }
        let file_index = hd.file_index;
        hd.file_index += 1;

        self.end_of_entry = false;
        self.end_of_entry_cleanup = false;
        self.entry_unconsumed = 0;
        self.entry_cffile = Some(file_index);

        // Choose a proper folder.
        let Some(file) = hd.files.get_mut(file_index) else {
            return Err(fatal());
        };
        let folder = match file.folder {
            FOLD_CONTINUED_FROM_PREV | FOLD_CONTINUED_PREV_AND_NEXT => 0,
            FOLD_CONTINUED_TO_NEXT => usize::from(hd.folder_count) - 1,
            f => usize::from(f),
        };
        let prev_folder = self.entry_cffolder.replace(folder);
        // If a cffolder of this file is changed, reset a cfdata to read file
        // contents from next cfdata.
        if prev_folder != self.entry_cffolder {
            self.entry_cfdata = false;
            // Bytes of files we skipped so far belong to folders we are
            // done with; reading this file will seek directly to the data
            // of the new folder, so we must not charge the skipped bytes
            // against the new folder's data.
            self.bytes_skipped = 0;
        }

        // If a pathname is UTF-8, prepare a string conversion object for
        // UTF-8 and use it.
        let sconv = if file.attr & ATTR_NAME_IS_UTF != 0 {
            if self.sconv_utf8.is_none() {
                let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
                let sc = conversion_from_charset(Some(&mut *cache), b"UTF-8", true)
                    .map_err(|e| Error::fatal(e.errno, e.message))?;
                self.sconv_utf8 = Some(sc);
            }
            self.sconv_utf8.clone()
        } else {
            // Choose the conversion specified by the option, else the
            // default one, which is none on this platform.
            self.sconv.clone()
        };

        // Set a default value and common data.
        let complete = convert_path_separator_1(&mut file.pathname, file.attr);
        if entry
            .copy_pathname_l(&file.pathname, sconv.as_deref())
            .is_err()
        {
            let msg = [
                b"Pathname cannot be converted from ".as_slice(),
                conversion_charset_name(sconv.as_deref()),
                b" to current locale",
            ]
            .concat();
            status = a.warn(ARCHIVE_ERRNO_FILE_FORMAT, msg);
        }
        if !complete {
            // Convert a path separator '\' -> '/'.
            convert_path_separator_2(entry);
        }

        entry.set_size(i64::from(file.uncompressed_size));
        let perm: Mode = if file.attr & ATTR_RDONLY != 0 {
            0o555
        } else {
            0o666
        };
        entry.set_mode(AE_IFREG | perm);
        entry.set_mtime(file.mtime, 0);

        self.entry_bytes_remaining = i64::from(file.uncompressed_size);
        self.entry_offset = 0;
        // We don't need compress data.
        if file.uncompressed_size == 0 {
            self.end_of_entry_cleanup = true;
            self.end_of_entry = true;
        }

        // Set up a more descriptive format name.
        let compname = hd.folders.get(folder).map_or("", |f| f.compname);
        a.set_format_name(format!("CAB {}.{} ({compname})", hd.major, hd.minor).as_bytes());

        Ok(status)
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        match self.file_folder()? {
            FOLD_CONTINUED_FROM_PREV | FOLD_CONTINUED_TO_NEXT | FOLD_CONTINUED_PREV_AND_NEXT => {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Cannot restore this file split in multivolume",
                ));
            }
            _ => {}
        }
        if !self.read_data_invoked {
            if self.bytes_skipped != 0 {
                if !self.entry_cfdata {
                    self.next_cfdata(r)?;
                }
                self.consume_cfdata(r, self.bytes_skipped)?;
                self.bytes_skipped = 0;
            }
            self.read_data_invoked = true;
        }
        if self.entry_unconsumed != 0 {
            // Consume as much as the compressor actually used.
            let n = std::mem::take(&mut self.entry_unconsumed);
            self.consume_cfdata(r, n)?;
        }
        if self.end_of_archive || self.end_of_entry {
            // End-of-entry cleanup done.
            self.end_of_entry_cleanup = true;
            return Ok(Data::Eof {
                offset: self.entry_offset,
            });
        }

        let Block { src, size, offset } = self.cab_read_data(r)?;
        let data = match src {
            Ahead::Stream(_) => r.peek_available(1)?.get(..size),
            Ahead::Buffer(start, _) => self.ubuf.get(start..start + size),
        };
        Ok(Data::Block {
            data: data.unwrap_or_default(),
            offset,
        })
    }

    fn read_data_skip(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        if self.end_of_archive {
            return Ok(Status::Eof);
        }

        if !self.read_data_invoked {
            self.bytes_skipped += self.entry_bytes_remaining;
            self.entry_bytes_remaining = 0;
            // This entry is finished and done.
            self.end_of_entry_cleanup = true;
            self.end_of_entry = true;
            return Ok(Status::Ok);
        }

        if self.entry_unconsumed != 0 {
            // Consume as much as the compressor actually used.
            let n = std::mem::take(&mut self.entry_unconsumed);
            self.consume_cfdata(r, n)?;
        } else if !self.entry_cfdata {
            self.next_cfdata(r)?;
        }

        // If we've already read to end of data, we're done.
        if self.end_of_entry_cleanup {
            return Ok(Status::Ok);
        }

        // If the length is at the beginning, we can skip the compressed data
        // much more quickly.
        self.consume_cfdata(r, self.entry_bytes_remaining)?;

        // If the compression type is none (uncompressed), we've already
        // consumed data as much as the current entry size.
        let entry_cfdata = self.entry_cfdata;
        let folder = folder_of(&mut self.cfheader, self.entry_cffolder)?;
        if folder.comptype == COMPTYPE_NONE && entry_cfdata {
            folder.cfdata.unconsumed = 0;
        }

        // This entry is finished and done.
        self.end_of_entry_cleanup = true;
        self.end_of_entry = true;
        Ok(Status::Ok)
    }
}

impl Cab {
    fn folder(&mut self) -> Result<&mut Cffolder, Error> {
        folder_of(&mut self.cfheader, self.entry_cffolder)
    }

    /// The CFDATA being read of the entry's folder.
    fn cfdata(&mut self) -> Result<&mut Cfdata, Error> {
        if !self.entry_cfdata {
            return Err(fatal());
        }
        Ok(&mut self.folder()?.cfdata)
    }

    /// The `iFolder` of the entry's CFFILE.
    fn file_folder(&self) -> Result<u16, Error> {
        self.entry_cffile
            .and_then(|i| self.cfheader.files.get(i))
            .map(|f| f.folder)
            .ok_or_else(fatal)
    }

    /// Read CFHEADER, CFFOLDER and CFFILE.
    fn read_cab_header(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        let a = r.base();
        a.format.set(format_code::CAB);
        if a.format_name.get().is_none() && a.format_name_buf.borrow().is_empty() {
            a.set_format(format_code::CAB, c"CAB");
        }

        let Some(p) = ahead(r, 42) else {
            return Err(truncated_error());
        };
        if !self.found_header && p.starts_with(b"MZ") {
            // This is an executable? Must be self-extracting...
            skip_sfx(r)?;
        }
        // (Re-)read the header after processing the SFX.
        let Some(p) = ahead(r, 42) else {
            return Err(truncated_error());
        };

        self.cab_offset = 0;
        // Read CFHEADER.
        let hd = &mut self.cfheader;
        if !p.starts_with(b"MSCF") {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Couldn't find out CAB header",
            ));
        }
        hd.files_offset = le32(p, 16);
        hd.minor = p.get(24).copied().unwrap_or(0);
        hd.major = p.get(25).copied().unwrap_or(0);
        hd.folder_count = le16(p, 26);
        if hd.folder_count == 0 {
            return Err(invalid_header());
        }
        hd.file_count = le16(p, 28);
        if hd.file_count == 0 {
            return Err(invalid_header());
        }
        hd.flags = le16(p, 30);
        hd.cabinet = le16(p, 34);
        let mut used = 36;
        let reserved = hd.flags & RESERVE_PRESENT != 0;
        if reserved {
            let cfheader = le16(p, 36);
            if cfheader > 60000 {
                return Err(invalid_header());
            }
            hd.cffolder = p.get(38).copied().unwrap_or(0);
            hd.cfdata = p.get(39).copied().unwrap_or(0);
            used += 4; // cbCFHeader, cbCFFolder and cbCFData
            used += usize::from(cfheader); // abReserve
        } else {
            hd.cffolder = 0;
        }
        let flags = hd.flags;
        // The names of the previous and next cabinets and disks: a NUL
        // terminated string each, the disk names possibly empty.
        let strings = [
            (PREV_CABINET, true),
            (PREV_CABINET, false),
            (NEXT_CABINET, true),
            (NEXT_CABINET, false),
        ];
        for (flag, not_empty) in strings {
            if flags & flag == 0 {
                continue;
            }
            let p = ahead_remaining(r, used + 256);
            let Some(rest) = p.get(used..).filter(|rest| !rest.is_empty()) else {
                return Err(truncated_error());
            };
            let len = strnlen(rest);
            if (not_empty && len == 0) || len == rest.len() {
                return Err(invalid_header());
            }
            used += len + 1;
        }
        let _ = r.consume(used);
        self.cab_offset += used as i64;

        // Read CFFOLDER.
        let hd = &mut self.cfheader;
        let stride = 8 + if reserved {
            usize::from(hd.cffolder)
        } else {
            0
        };
        let bytes = stride * usize::from(hd.folder_count);
        let Some(p) = ahead(r, bytes) else {
            return Err(truncated_error());
        };
        let mut folders = Vec::with_capacity(usize::from(hd.folder_count));
        let mut offset32 = 0;
        for q in p.chunks_exact(stride).take(usize::from(hd.folder_count)) {
            let comptype = le16(q, 6);
            let mut folder = Cffolder {
                cfdata_offset_in_cab: le32(q, 0),
                cfdata_count: le16(q, 4),
                comptype: comptype & 0x0F,
                compdata: comptype >> 8,
                ..Cffolder::default()
            };
            // Get a compression name.
            folder.compname = COMPRESSION_NAME
                .get(usize::from(folder.comptype))
                .copied()
                .unwrap_or("UNKNOWN");
            // Sanity check if each data is acceptable.
            if offset32 >= folder.cfdata_offset_in_cab {
                return Err(invalid_header());
            }
            offset32 = folder.cfdata_offset_in_cab;
            folders.push(folder);
        }
        let _ = r.consume(bytes);
        self.cab_offset += bytes as i64;

        // Read CFFILE.
        // Seek read pointer to the offset of CFFILE if needed.
        let skip = i64::from(hd.files_offset) - self.cab_offset;
        if skip < 0 {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_MISC,
                format!(
                    "Invalid offset of CFFILE {} < {}",
                    hd.files_offset, self.cab_offset
                ),
            ));
        }
        if skip != 0 {
            r.consume(skip).map_err(|_| truncated_error())?;
            self.cab_offset += skip;
        }

        let mut files = Vec::with_capacity(usize::from(hd.file_count));
        let mut prev_folder: i32 = -1;
        for i in 0..usize::from(hd.file_count) {
            let Some(p) = ahead(r, 16) else {
                return Err(truncated_error());
            };
            let mut file = Cffile {
                uncompressed_size: le32(p, 0),
                offset: le32(p, 4),
                folder: le16(p, 8),
                mtime: dos_time(p.get(10..).unwrap_or_default()),
                attr: le16(p, 14) as u8,
                pathname: Vec::new(),
            };
            let _ = r.consume(16);
            self.cab_offset += 16;

            let p = ahead_remaining(r, 256);
            if p.is_empty() {
                return Err(truncated_error());
            }
            let len = strnlen(p);
            if len == 0 || len == p.len() {
                return Err(invalid_header());
            }
            // Copy a pathname.
            file.pathname = p.get(..len).unwrap_or_default().to_vec();
            let _ = r.consume(len + 1);
            self.cab_offset += len as i64 + 1;

            // Sanity check if each data is acceptable.
            if i64::from(file.uncompressed_size) > MAX_FILE_SIZE
                || i64::from(file.offset) + i64::from(file.uncompressed_size) > MAX_FILE_SIZE
            {
                return Err(invalid_header()); // Too large.
            }
            let cur_folder = match file.folder {
                FOLD_CONTINUED_TO_NEXT => {
                    // This must be last file in a folder.
                    if i != usize::from(hd.file_count) - 1 {
                        return Err(invalid_header());
                    }
                    i32::from(hd.folder_count) - 1
                }
                FOLD_CONTINUED_PREV_AND_NEXT | FOLD_CONTINUED_FROM_PREV => {
                    // The former must be the only one file in a folder.
                    if file.folder == FOLD_CONTINUED_PREV_AND_NEXT && hd.file_count != 1 {
                        return Err(invalid_header());
                    }
                    // This must be first file in a folder.
                    if i != 0 {
                        return Err(invalid_header());
                    }
                    prev_folder = 0;
                    offset32 = file.offset;
                    0
                }
                f => {
                    if f >= hd.folder_count {
                        return Err(invalid_header());
                    }
                    i32::from(f)
                }
            };
            // Dot not back track.
            if cur_folder < prev_folder {
                return Err(invalid_header());
            }
            if cur_folder != prev_folder {
                offset32 = 0;
            }
            prev_folder = cur_folder;

            // Make sure there are not any blanks from last file contents.
            if offset32 != file.offset {
                return Err(invalid_header());
            }
            offset32 += file.uncompressed_size;

            // CFDATA is available for file contents.
            let count = usize::try_from(cur_folder)
                .ok()
                .and_then(|f| folders.get(f))
                .map_or(0, |f| f.cfdata_count);
            if file.uncompressed_size > 0 && count == 0 {
                return Err(invalid_header());
            }
            files.push(file);
        }
        hd.folders = folders;
        hd.files = files;

        if hd.cabinet != 0 || hd.flags & (PREV_CABINET | NEXT_CABINET) != 0 {
            return Ok(a.warn(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Multivolume cabinet file is unsupported",
            ));
        }
        Ok(Status::Ok)
    }

    /// Computes the end of the sum of the CFDATA that has just been
    /// consumed whole, and checks it.
    fn checksum_finish(&mut self) -> Result<(), Error> {
        let mut l = 4;
        if self.cfheader.flags & RESERVE_PRESENT != 0 {
            l += usize::from(self.cfheader.cfdata);
        }
        let folder = self.folder()?;
        let index = folder.cfdata_index;
        let cfdata = &mut folder.cfdata;

        // Do not need to compute a sum.
        if cfdata.sum == 0 {
            return Ok(());
        }

        // Calculate the sum of remaining CFDATA.
        if cfdata.sum_extra_avail != 0 {
            let extra = cfdata
                .sum_extra
                .get(..cfdata.sum_extra_avail)
                .unwrap_or_default();
            cfdata.sum_calculated = checksum_cfdata(extra, cfdata.sum_calculated);
            cfdata.sum_extra_avail = 0;
        }

        let Some(image) = cfdata.memimage.get(4..4 + l) else {
            return Err(fatal());
        };
        cfdata.sum_calculated = checksum_cfdata(image, cfdata.sum_calculated);
        if cfdata.sum_calculated != cfdata.sum {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                format!(
                    "Checksum error CFDATA[{}] {:x}:{:x} in {} bytes",
                    index - 1,
                    cfdata.sum,
                    cfdata.sum_calculated,
                    cfdata.compressed_size
                ),
            ));
        }
        Ok(())
    }

    /// Read CFDATA if needed.
    fn next_cfdata(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        // There are remaining bytes in current CFDATA, use it first.
        if self.entry_cfdata && self.cfdata()?.uncompressed_bytes_remaining > 0 {
            return Ok(());
        }

        if !self.entry_cfdata {
            let folder = folder_of(&mut self.cfheader, self.entry_cffolder)?;
            folder.cfdata_index = 0;
            let offset = folder.cfdata_offset_in_cab;

            // Seek read pointer to the offset of CFDATA if needed.
            let skip = i64::from(offset) - self.cab_offset;
            if skip < 0 {
                let folder_index = match self.file_folder()? {
                    FOLD_CONTINUED_FROM_PREV | FOLD_CONTINUED_PREV_AND_NEXT => 0,
                    FOLD_CONTINUED_TO_NEXT => self.cfheader.folder_count.wrapping_sub(1),
                    f => f,
                };
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_MISC,
                    format!(
                        "Invalid offset of CFDATA in folder({folder_index}) {offset} < {}",
                        self.cab_offset
                    ),
                ));
            }
            if skip > 0 {
                r.consume(skip)?;
                self.cab_offset = i64::from(offset);
            }
        }

        // Read a CFDATA.
        let (index, count, comptype) = {
            let f = self.folder()?;
            (f.cfdata_index, f.cfdata_count, f.comptype)
        };
        if index < i32::from(count) {
            let uncompressed_zero_ok = matches!(
                self.file_folder()?,
                FOLD_CONTINUED_PREV_AND_NEXT | FOLD_CONTINUED_TO_NEXT
            );
            let mut l = 8;
            if self.cfheader.flags & RESERVE_PRESENT != 0 {
                l += usize::from(self.cfheader.cfdata);
            }
            let folder = folder_of(&mut self.cfheader, self.entry_cffolder)?;
            folder.cfdata_index += 1;
            self.entry_cfdata = true;
            let cfdata = &mut folder.cfdata;
            cfdata.sum_calculated = 0;
            cfdata.sum_extra_avail = 0;
            cfdata.sum_pending = false;
            let Some(p) = ahead(r, l) else {
                return Err(truncated_error());
            };
            cfdata.sum = le32(p, 0);
            cfdata.compressed_size = le16(p, 4);
            cfdata.compressed_bytes_remaining = cfdata.compressed_size;
            cfdata.uncompressed_size = le16(p, 6);
            cfdata.uncompressed_bytes_remaining = cfdata.uncompressed_size;
            cfdata.uncompressed_avail = 0;
            cfdata.read_offset = 0;
            cfdata.unconsumed = 0;

            // Sanity check if data size is acceptable.
            if cfdata.compressed_size == 0
                || usize::from(cfdata.compressed_size) > MAX_UNCOMPRESS_SIZE + 6144
                || usize::from(cfdata.uncompressed_size) > MAX_UNCOMPRESS_SIZE
                || (cfdata.uncompressed_size == 0 && !uncompressed_zero_ok)
            {
                return Err(invalid_cfdata());
            }
            // If CFDATA is not last in a folder, an uncompressed size must
            // be 0x8000 (32 KiB).
            if folder.cfdata_index < i32::from(count)
                && usize::from(cfdata.uncompressed_size) != MAX_UNCOMPRESS_SIZE
            {
                return Err(invalid_cfdata());
            }
            // A compressed data size and an uncompressed data size must be
            // the same in no compression mode.
            if comptype == COMPTYPE_NONE && cfdata.compressed_size != cfdata.uncompressed_size {
                return Err(invalid_cfdata());
            }

            // Save CFDATA image for sum check.
            cfdata.memimage.clear();
            cfdata
                .memimage
                .extend_from_slice(p.get(..l).unwrap_or_default());

            // Consume bytes as much as we used.
            let _ = r.consume(l);
            self.cab_offset += l as i64;
        } else if count > 0 {
            // Run out of all CFDATA in a folder.
            let cfdata = &mut self.folder()?.cfdata;
            cfdata.compressed_size = 0;
            cfdata.uncompressed_size = 0;
            cfdata.compressed_bytes_remaining = 0;
            cfdata.uncompressed_bytes_remaining = 0;
        } else {
            // Current folder does not have any CFDATA.
            self.entry_cfdata = true;
            self.folder()?.cfdata = Cfdata::default();
        }
        Ok(())
    }

    /// Read ahead CFDATA.
    fn read_ahead_cfdata(&mut self, r: &mut Reader<'_>) -> Result<Ahead, Error> {
        self.next_cfdata(r)?;

        let folder = self.folder()?;
        match folder.comptype {
            COMPTYPE_NONE => self.read_ahead_cfdata_none(r),
            COMPTYPE_MSZIP => self.read_ahead_cfdata_deflate(r),
            COMPTYPE_LZX => self.read_ahead_cfdata_lzx(r),
            // Unsupported compression.
            _ => Err(Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_FILE_FORMAT,
                format!("Unsupported CAB compression: {}", folder.compname),
            )),
        }
    }

    /// The uncompressed bytes of the current CFDATA that are not read yet.
    fn buffered_cfdata(&mut self) -> Result<Ahead, Error> {
        let cfdata = self.cfdata()?;
        let avail = usize::from(cfdata.uncompressed_avail)
            .checked_sub(usize::from(cfdata.read_offset))
            .ok_or_else(fatal)?;
        Ok(Ahead::Buffer(OUT + usize::from(cfdata.read_offset), avail))
    }

    /// Read ahead CFDATA as uncompressed data.
    fn read_ahead_cfdata_none(&mut self, r: &mut Reader<'_>) -> Result<Ahead, Error> {
        // Note: '1' here is a performance optimization. Recall that the
        // decompression layer returns a count of available bytes; asking for
        // more than that forces the decompressor to combine reads by copying
        // data.
        let len = r.peek_available(1).map_or(0, <[u8]>::len);
        if len == 0 {
            return Err(truncated_error());
        }
        let cfdata = self.cfdata()?;
        let avail = len.min(usize::from(cfdata.uncompressed_bytes_remaining));
        cfdata.uncompressed_avail = cfdata.uncompressed_size;
        cfdata.unconsumed = avail as i64;
        cfdata.sum_pending = true;
        Ok(Ahead::Stream(avail))
    }

    /// Consumes the compressed bytes that are left in the current CFDATA
    /// without being used. They still count for its sum.
    fn consume_remaining_compressed(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let cfdata = self.cfdata()?;
        let remaining = cfdata.compressed_bytes_remaining;
        if remaining > 0 {
            if ahead(r, usize::from(remaining)).is_none() {
                return Err(truncated_error());
            }
            cfdata.unconsumed = i64::from(remaining);
            cfdata.sum_pending = true;
            self.minimum_consume_cfdata(r, i64::from(remaining))?;
        }
        Ok(())
    }

    /// Makes sure the buffer for uncompressed bytes exists.
    fn ensure_ubuf(&mut self) {
        if self.ubuf.is_empty() {
            self.ubuf = vec![0; OUT + MAX_UNCOMPRESS_SIZE];
        }
    }

    /// Read ahead CFDATA as deflate data.
    fn read_ahead_cfdata_deflate(&mut self, r: &mut Reader<'_>) -> Result<Ahead, Error> {
        self.ensure_ubuf();
        let cfdata = self.cfdata()?;
        let uavail = cfdata.uncompressed_avail;
        let size = usize::from(cfdata.uncompressed_size);
        if uavail == cfdata.uncompressed_size {
            return self.buffered_cfdata();
        }

        let folder = self.folder()?;
        if !folder.decompress_init {
            // We've initialized decompression for this stream.
            folder.decompress_init = true;
            self.inflate
                .get_or_insert_with(|| Box::new(DecompressorOxide::new()))
                .init();
            self.dict_len = 0;
        }

        let nomszip = || Error::fatal(ARCHIVE_ERRNO_MISC, "CFDATA incorrect(no MSZIP signature)");
        let cfdata = self.cfdata()?;
        // Cut out a two-byte MSZIP signature (0x43, 0x4b).
        let mut mszip = if cfdata.compressed_bytes_remaining == cfdata.compressed_size {
            2
        } else {
            0
        };
        let mut eod = false;
        let mut total_out = usize::from(uavail);
        // We always uncompress all data in current CFDATA.
        while !eod && total_out < size {
            let Some(d) = ahead(r, 1) else {
                return Err(truncated_error());
            };
            let cfdata = self.cfdata()?;
            let bytes_avail = d.len().min(usize::from(cfdata.compressed_bytes_remaining));
            let mut input = d.get(..bytes_avail).unwrap_or_default();
            let mut total_in = 0;

            if mszip > 0 {
                if bytes_avail == 0 {
                    return Err(nomszip());
                }
                if bytes_avail <= mszip {
                    let ok = if mszip == 2 {
                        input.first() == Some(&0x43) && input.get(1).is_none_or(|&b| b == 0x4b)
                    } else {
                        input.first() == Some(&0x4b)
                    };
                    if !ok {
                        return Err(nomszip());
                    }
                    cfdata.unconsumed = bytes_avail as i64;
                    cfdata.sum_pending = true;
                    self.minimum_consume_cfdata(r, bytes_avail as i64)?;
                    mszip -= bytes_avail;
                    continue;
                }
                let signature_ok = if mszip == 2 {
                    input.get(..2) == Some(&[0x43, 0x4b])
                } else {
                    input.first() == Some(&0x4b)
                };
                if !signature_ok {
                    return Err(nomszip());
                }
                input = input.get(mszip..).unwrap_or_default();
                total_in = mszip;
                mszip = 0;
            }

            // zlib's results: 0 is Z_OK, -3 Z_DATA_ERROR, -5 Z_BUF_ERROR.
            let mut code = -5;
            if !input.is_empty() {
                let (Some(dec), Some(window)) = (
                    self.inflate.as_mut(),
                    self.ubuf.get_mut(OUT - self.dict_len..OUT + size),
                ) else {
                    return Err(fatal());
                };
                let (status, used, written) = decompress(
                    dec,
                    input,
                    window,
                    self.dict_len + total_out,
                    TINFL_FLAG_HAS_MORE_INPUT | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
                );
                match status {
                    TINFLStatus::Done => {
                        eod = true;
                        code = 0;
                    }
                    TINFLStatus::NeedsMoreInput | TINFLStatus::HasMoreOutput => code = 0,
                    TINFLStatus::FailedCannotMakeProgress => {}
                    _ => code = -3,
                }
                total_in += used;
                total_out += written;
            }
            if code != 0 {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_MISC,
                    format!("Deflate decompression failed ({code})"),
                ));
            }
            let cfdata = self.cfdata()?;
            cfdata.unconsumed = total_in as i64;
            cfdata.sum_pending = true;
            self.minimum_consume_cfdata(r, total_in as i64)?;
        }
        let uavail = total_out as u16;

        if uavail < self.cfdata()?.uncompressed_size {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_MISC,
                format!(
                    "Invalid uncompressed size ({uavail} < {})",
                    self.cfdata()?.uncompressed_size
                ),
            ));
        }

        // Note: I suspect there is a bug in makecab.exe because, in rare
        // case, compressed bytes are still remaining regardless we have
        // gotten all uncompressed bytes, which size is recorded in CFDATA,
        // as much as we need, and we have to use the garbage so as to
        // correctly compute the sum of CFDATA accordingly.
        self.consume_remaining_compressed(r)?;

        // Set dictionary data for decompressing of next CFDATA, which in the
        // same folder. This is why we always do decompress CFDATA even if
        // beginning CFDATA or some of CFDATA are not used in skipping file
        // data.
        let folder = self.folder()?;
        if folder.cfdata_index < i32::from(folder.cfdata_count) {
            if let Some(dec) = self.inflate.as_mut() {
                dec.init();
            }
            self.ubuf.copy_within(OUT..OUT + size, OUT - size);
            self.dict_len = size;
        }

        self.cfdata()?.uncompressed_avail = uavail;
        self.buffered_cfdata()
    }

    fn read_ahead_cfdata_lzx(&mut self, r: &mut Reader<'_>) -> Result<Ahead, Error> {
        self.ensure_ubuf();
        let cfdata = self.cfdata()?;
        let uavail = cfdata.uncompressed_avail;
        let size = usize::from(cfdata.uncompressed_size);
        if uavail == cfdata.uncompressed_size {
            return self.buffered_cfdata();
        }

        let folder = folder_of(&mut self.cfheader, self.entry_cffolder)?;
        if !folder.decompress_init {
            let Some(lzx) = Lzx::new(folder.compdata) else {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_MISC,
                    "Can't initialize LZX decompression",
                ));
            };
            self.lzx = Some(lzx);
            // We've initialized decompression for this stream.
            folder.decompress_init = true;
        }

        // Clean up remaining bits of previous CFDATA.
        let Some(lzx) = self.lzx.as_mut() else {
            return Err(fatal());
        };
        lzx.cleanup_bitstream();
        let mut total_out = usize::from(uavail);
        while total_out < size {
            let Some(d) = ahead(r, 1) else {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Truncated CAB file data",
                ));
            };
            let remaining = usize::from(self.cfdata()?.compressed_bytes_remaining);
            let bytes_avail = d.len().min(remaining);
            let (Some(lzx), Some(out)) = (
                self.lzx.as_mut(),
                self.ubuf.get_mut(OUT + total_out..OUT + size),
            ) else {
                return Err(fatal());
            };
            let done = lzx.decode(
                d.get(..bytes_avail).unwrap_or_default(),
                out,
                remaining == bytes_avail,
            );
            if done.status == lzx::Status::Failed {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_MISC,
                    format!("LZX decompression failed ({ARCHIVE_FAILED})"),
                ));
            }
            total_out += done.written;
            let cfdata = self.cfdata()?;
            cfdata.unconsumed = done.consumed as i64;
            cfdata.sum_pending = true;
            self.minimum_consume_cfdata(r, done.consumed as i64)?;
        }
        let uavail = total_out as u16;

        // Make sure a read pointer advances to next CFDATA.
        self.consume_remaining_compressed(r)?;

        // Translation reversal of x86 processor CALL byte sequence (E8).
        let index = self.folder()?.cfdata_index;
        if let (Some(lzx), Some(buffer)) = (self.lzx.as_ref(), self.ubuf.get_mut(OUT..OUT + size)) {
            let offset = (index - 1).wrapping_mul(MAX_UNCOMPRESS_SIZE as i32);
            lzx.translation(buffer, offset);
        }

        self.cfdata()?.uncompressed_avail = uavail;
        self.buffered_cfdata()
    }

    /// Consume CFDATA. We always decompress CFDATA to consume CFDATA as
    /// much as we need in uncompressed bytes because all CFDATA in a folder
    /// are related so we do not skip any CFDATA without decompressing.
    /// Note: If the folder of a CFFILE is iFoldCONTINUED_PREV_AND_NEXT or
    /// iFoldCONTINUED_FROM_PREV, we won't decompress because a CFDATA for
    /// the CFFILE is remaining bytes of previous Multivolume CAB file.
    fn consume_cfdata(&mut self, r: &mut Reader<'_>, consumed_bytes: i64) -> Result<i64, Error> {
        let mut rbytes = self.minimum_consume_cfdata(r, consumed_bytes)?;

        while rbytes > 0 {
            let file_folder = self.file_folder()?;
            let cfdata = self.cfdata()?;
            if cfdata.compressed_size == 0 {
                return Err(invalid_cfdata());
            }
            let remaining = i64::from(cfdata.uncompressed_bytes_remaining);
            let mut cbytes = remaining.min(rbytes);
            rbytes -= cbytes;

            if cfdata.uncompressed_avail == 0
                && matches!(
                    file_folder,
                    FOLD_CONTINUED_PREV_AND_NEXT | FOLD_CONTINUED_FROM_PREV
                )
            {
                // We have not read any data yet.
                if cbytes == remaining {
                    // Skip whole current CFDATA.
                    let compressed_size = cfdata.compressed_size;
                    cfdata.compressed_bytes_remaining = 0;
                    cfdata.uncompressed_bytes_remaining = 0;
                    let _ = r.consume(compressed_size);
                    self.cab_offset += i64::from(compressed_size);
                    self.next_cfdata(r)?;
                    if self.cfdata()?.uncompressed_size == 0 {
                        rbytes = 0;
                    }
                    continue;
                }
                cfdata.read_offset = cfdata.read_offset.wrapping_add(cbytes as u16);
                cfdata.uncompressed_bytes_remaining = cfdata
                    .uncompressed_bytes_remaining
                    .wrapping_sub(cbytes as u16);
                break;
            } else if cbytes == 0 {
                self.next_cfdata(r)?;
                if self.cfdata()?.uncompressed_size == 0
                    && matches!(
                        file_folder,
                        FOLD_CONTINUED_PREV_AND_NEXT
                            | FOLD_CONTINUED_TO_NEXT
                            | FOLD_CONTINUED_FROM_PREV
                    )
                {
                    return Err(fatal());
                }
                continue;
            }
            while cbytes > 0 {
                let avail = match self.read_ahead_cfdata(r) {
                    Ok(ahead) => ahead.len(),
                    Err(e) => {
                        // The message stays, and the failure is fatal.
                        r.base().raise(e);
                        return Err(fatal());
                    }
                };
                if avail == 0 {
                    return Err(fatal());
                }
                let avail = avail as i64;
                let avail = avail.min(cbytes);
                self.minimum_consume_cfdata(r, avail)?;
                cbytes -= avail;
            }
        }
        Ok(consumed_bytes)
    }

    /// Consume CFDATA as much as we have already gotten and compute the sum
    /// of CFDATA.
    fn minimum_consume_cfdata(
        &mut self,
        r: &mut Reader<'_>,
        consumed_bytes: i64,
    ) -> Result<i64, Error> {
        let comptype = self.folder()?.comptype;
        let cfdata = self.cfdata()?;
        let mut rbytes = consumed_bytes;
        let cbytes;
        if comptype == COMPTYPE_NONE {
            cbytes = consumed_bytes.min(cfdata.unconsumed);
            rbytes -= cbytes;
            cfdata.read_offset = cfdata.read_offset.wrapping_add(cbytes as u16);
            cfdata.uncompressed_bytes_remaining = cfdata
                .uncompressed_bytes_remaining
                .wrapping_sub(cbytes as u16);
            cfdata.unconsumed -= cbytes;
        } else {
            let unread = i64::from(cfdata.uncompressed_avail) - i64::from(cfdata.read_offset);
            if unread > 0 {
                let n = consumed_bytes.min(unread);
                rbytes -= n;
                cfdata.read_offset = cfdata.read_offset.wrapping_add(n as u16);
                cfdata.uncompressed_bytes_remaining =
                    cfdata.uncompressed_bytes_remaining.wrapping_sub(n as u16);
            }
            cbytes = std::mem::take(&mut cfdata.unconsumed);
        }
        if let Ok(n) = usize::try_from(cbytes)
            && n > 0
        {
            // Compute the sum.
            if cfdata.sum != 0 && cfdata.sum_pending {
                let Some(p) = ahead(r, n) else {
                    return Err(fatal());
                };
                self.cfdata()?
                    .checksum_update(p.get(..n).unwrap_or_default());
            }

            // Consume as much as the compressor actually used.
            let _ = r.consume(n);
            self.cab_offset += cbytes;
            let cfdata = self.cfdata()?;
            cfdata.sum_pending = false;
            cfdata.compressed_bytes_remaining = cfdata
                .compressed_bytes_remaining
                .wrapping_sub(cbytes as u16);
            if cfdata.compressed_bytes_remaining == 0 {
                self.checksum_finish()?;
            }
        }
        Ok(rbytes)
    }

    /// Returns the next block of the entry's data, and sets `end_of_entry`
    /// if it consumes all of the data.
    fn cab_read_data(&mut self, r: &mut Reader<'_>) -> Result<Block, Error> {
        if self.entry_bytes_remaining == 0 {
            self.end_of_entry = true;
            return Ok(Block::empty(self.entry_offset));
        }

        let src = self.read_ahead_cfdata(r)?;
        if src.len() == 0 {
            if self.cfdata()?.uncompressed_size == 0 {
                // All of CFDATA in a folder has been handled.
                return Err(invalid_cfdata());
            }
            return Ok(Block::empty(0));
        }
        let size = i64::try_from(src.len())
            .unwrap_or(i64::MAX)
            .min(self.entry_bytes_remaining);

        let offset = self.entry_offset;
        self.entry_offset += size;
        self.entry_bytes_remaining -= size;
        if self.entry_bytes_remaining == 0 {
            self.end_of_entry = true;
        }
        self.entry_unconsumed = size;
        let entry_unconsumed = self.entry_unconsumed;
        let folder = self.folder()?;
        if folder.comptype == COMPTYPE_NONE {
            // Don't consume more than current entry used.
            folder.cfdata.unconsumed = folder.cfdata.unconsumed.min(entry_unconsumed);
        }
        Ok(Block {
            src,
            size: size as usize,
            offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sum_covers_whole_and_partial_words() {
        assert_eq!(checksum_cfdata(&[1, 0, 0, 0], 0), 1);
        // The last one to three bytes make one word, first byte highest.
        assert_eq!(checksum_cfdata(&[1, 0, 0, 0, 0xAA], 0), 1 ^ 0xAA);
        assert_eq!(checksum_cfdata(&[0, 0, 0, 0, 0xAA, 0xBB], 5), 5 ^ 0xAABB);
        assert_eq!(checksum_cfdata(&[0xAA, 0xBB, 0xCC], 0), 0xAABBCC);
    }

    #[test]
    fn sum_of_pieces_is_the_sum_of_the_whole() {
        let data: Vec<u8> = (0..=250).collect();
        for cut in [1, 2, 3, 4, 5, 7, 100] {
            let mut cfdata = Cfdata {
                sum: 1,
                ..Cfdata::default()
            };
            for piece in data.chunks(cut) {
                cfdata.sum_pending = true;
                cfdata.checksum_update(piece);
            }
            let extra = cfdata.sum_extra.get(..cfdata.sum_extra_avail).unwrap();
            assert_eq!(
                checksum_cfdata(extra, cfdata.sum_calculated),
                checksum_cfdata(&data, 0),
                "pieces of {cut}"
            );
        }
    }

    #[test]
    fn magic_search_steps_by_the_last_possible_overlap() {
        assert_eq!(find_cab_magic(b"MSCF\0\0\0\0"), 0);
        assert_eq!(find_cab_magic(b"xMSCF\0\0\0"), 1);
        // 'MSCF' without the zero reserved bytes after it is not a header.
        assert_eq!(find_cab_magic(b"MSCFxxxx"), 5);
        assert_eq!(find_cab_magic(b"...MSCF."), 3);
        assert_eq!(find_cab_magic(b"..MSCF.."), 2);
    }

    #[test]
    fn separators_are_converted_unless_they_may_be_a_trail_byte() {
        let mut name = b"a\\b\\c".to_vec();
        assert!(convert_path_separator_1(&mut name, 0));
        assert_eq!(name, b"a/b/c");
        // 0x95 0x5c is a CP932 character: the '\\' is left for the wide pass.
        let mut name = b"a\\\x95\\b".to_vec();
        assert!(!convert_path_separator_1(&mut name, 0));
        assert_eq!(name, b"a/\x95\\b");
        let mut name = b"a\\\x95\\b".to_vec();
        assert!(convert_path_separator_1(&mut name, ATTR_NAME_IS_UTF));
        assert_eq!(name, b"a/\x95/b");
    }

    #[test]
    fn dos_time_fields_are_normalized() {
        // 2010-12-18 05:42:12 and the same moment spelled as month 13.
        let date = (30 << 9) | (12 << 5) | 18;
        let time = (5 << 11) | (42 << 5) | 6;
        let mut p = [0; 4];
        p[..2].copy_from_slice(&(date as u16).to_le_bytes());
        p[2..].copy_from_slice(&(time as u16).to_le_bytes());
        let tm = |year, mon| Tm {
            year,
            mon,
            mday: 18,
            hour: 5,
            min: 42,
            sec: 12,
        };
        let t = dos_time(&p);
        assert_eq!(dos_time(&p), t);
        assert_eq!(mktime(tm(110, 12)), mktime(tm(111, 0)));
        assert_eq!(t, mktime(tm(110, 11)).unwrap_or(-1));
    }

    #[test]
    fn format_name_can_be_formatted() {
        let a = Base::new(READ_MAGIC);
        a.set_format(format_code::CAB, c"CAB");
        assert_eq!(a.format_name.get(), Some(c"CAB"));
        a.set_format_name(b"CAB 1.3 (LZX)");
        assert_eq!(a.format_name.get(), None);
        assert_eq!(&*a.format_name_buf.borrow(), b"CAB 1.3 (LZX)\0");
    }
}
