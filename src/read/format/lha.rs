/*-
 * Copyright (c) 2008-2014 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_read_support_format_lha.c.

//! The LHA/LZH format: headers of levels 0 to 3 with their extended headers,
//! stored (`-lh0-`) entries and the LZHUF methods (`-lh5-` to `-lh7-`), which
//! `lzh` decodes. Self-extracting executables are searched for a header.

mod lzh;

use crate::archive::*;
use crate::entry::{AE_IFDIR, AE_IFLNK, AE_IFMT, AE_IFREG, Entry, Mode};
use crate::read::{ARCHIVE_ERRNO_FILE_FORMAT, Data, Format, Read, Reader, Status, format_code};
use crate::string::{
    MString, StringConv, conversion_charset_name, conversion_from_charset, until_nul,
};
use crate::time::{dos_to_unix, ntfs_to_unix};
use crate::util::Error;
use libc::wchar_t;
use lzh::{Input, Lzh, Step};
use std::ffi::{CStr, c_int};
use std::sync::{Arc, PoisonError};

const BIRTHTIME_IS_SET: u8 = 1;
const ATIME_IS_SET: u8 = 2;
const UNIX_MODE_IS_SET: u8 = 4;
const CRC_IS_SET: u8 = 8;

// LHA header common member offset.
/// Compress type.
const H_METHOD_OFFSET: usize = 2;
/// Header Level.
const H_LEVEL_OFFSET: usize = 20;
/// Minimum header size.
const H_SIZE: usize = 22;

const SFX_MAX_READAHEAD: usize = 1024 * 512;

// Extended header types.
/// Header CRC and information.
const EXT_HEADER_CRC: u8 = 0x00;
/// Filename.
const EXT_FILENAME: u8 = 0x01;
/// Directory name.
const EXT_DIRECTORY: u8 = 0x02;
/// MS-DOS attribute.
const EXT_DOS_ATTR: u8 = 0x40;
/// Windows time stamp.
const EXT_TIMESTAMP: u8 = 0x41;
/// Large file size.
const EXT_FILESIZE: u8 = 0x42;
/// UTF-16 filename.
const EXT_UTF16_FILENAME: u8 = 0x44;
/// UTF-16 directory name.
const EXT_UTF16_DIRECTORY: u8 = 0x45;
/// Codepage.
const EXT_CODEPAGE: u8 = 0x46;
/// File permission.
const EXT_UNIX_MODE: u8 = 0x50;
/// gid,uid.
const EXT_UNIX_GID_UID: u8 = 0x51;
/// Group name.
const EXT_UNIX_GNAME: u8 = 0x52;
/// User name.
const EXT_UNIX_UNAME: u8 = 0x53;
/// Modified time.
const EXT_UNIX_MTIME: u8 = 0x54;
/// New attribute (OS/2 only).
const EXT_OS2_NEW_ATTR: u8 = 0x7f;
/// New attribute.
const EXT_NEW_ATTR: u8 = 0xff;

/// `format_name`: upstream formats "lha -%c%c%c-" from the method, which
/// `lha_check_header_format` limits to these.
const FORMAT_NAMES: [(&[u8; 3], &CStr); 12] = [
    (b"lh0", c"lha -lh0-"),
    (b"lh1", c"lha -lh1-"),
    (b"lh2", c"lha -lh2-"),
    (b"lh3", c"lha -lh3-"),
    (b"lh4", c"lha -lh4-"),
    (b"lh5", c"lha -lh5-"),
    (b"lh6", c"lha -lh6-"),
    (b"lh7", c"lha -lh7-"),
    (b"lhd", c"lha -lhd-"),
    (b"lzs", c"lha -lzs-"),
    (b"lz4", c"lha -lz4-"),
    (b"lz5", c"lha -lz5-"),
];

#[derive(Default)]
struct Lha {
    /// `entry_bytes_remaining` is the number of bytes we expect.
    entry_offset: i64,
    entry_bytes_remaining: i64,
    entry_crc_calculated: u16,

    /// Header size.
    header_size: usize,
    /// Header level.
    level: u8,
    /// Compress type.
    method: [u8; 3],
    /// Compressed data size.
    compsize: i64,
    /// Original file size.
    origsize: i64,
    setflag: u8,
    birthtime: (i64, u32),
    mtime: (i64, u32),
    atime: (i64, u32),
    mode: Mode,
    uid: i64,
    gid: i64,
    uname: Vec<u8>,
    gname: Vec<u8>,
    header_crc: u16,
    crc: u16,
    /// dirname and filename could be in different codepages.
    sconv_dir: Option<Arc<StringConv>>,
    sconv_fname: Option<Arc<StringConv>>,
    /// `hdrcharset`. `None` is the current locale.
    opt_sconv: Option<Arc<StringConv>>,

    dirname: Vec<u8>,
    filename: Vec<u8>,

    dos_attr: u8,

    /// Flag to mark progress that an archive was read their first header.
    found_first_header: bool,
    /// Flag to mark that indicates an empty directory.
    directory: bool,

    // Flags to mark progress of decompression.
    decompress_init: bool,
    end_of_entry: bool,
    end_of_entry_cleanup: bool,
    entry_is_compressed: bool,

    dec: Option<Lzh>,
}

/// `archive_read_support_format_lha`.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Lha::default()))
}

/// A byte of a header, 0 past its end.
fn byte(b: &[u8], off: usize) -> u8 {
    b.get(off).copied().unwrap_or(0)
}

fn le16(b: &[u8], off: usize) -> u16 {
    b.get(off..off.saturating_add(2))
        .and_then(|s| s.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

fn le32(b: &[u8], off: usize) -> u32 {
    b.get(off..off.saturating_add(4))
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn le64(b: &[u8], off: usize) -> u64 {
    b.get(off..off.saturating_add(8))
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

/// `__archive_read_ahead` for a caller that treats a failed read like a
/// short input, as upstream does.
fn ahead<'r>(r: &'r mut Reader<'_>, n: usize) -> Option<&'r [u8]> {
    r.read_ahead(n).ok().flatten()
}

/// The first `H_SIZE` bytes of the input, zero filled where it is shorter,
/// if at least `n` bytes are there.
fn header_start(r: &mut Reader<'_>, n: usize) -> Option<[u8; H_SIZE]> {
    let p = ahead(r, n)?;
    let mut h = [0; H_SIZE];
    let n = p.len().min(H_SIZE);
    h.get_mut(..n)?.copy_from_slice(p.get(..n)?);
    Some(h)
}

fn truncated_error() -> Error {
    Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated LHa header")
}

fn invalid_header() -> Error {
    Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Invalid LHa header")
}

/// How many bytes to skip before the next candidate for a header: 0 if `h`
/// is one.
fn check_header_format(h: &[u8]) -> usize {
    let b = |i| byte(h, i);
    let next_skip_bytes;
    match b(H_METHOD_OFFSET + 3) {
        // "-lh0-" ... "-lh7-" "-lhd-"
        // "-lzs-" "-lz5-"
        b'0'..=b'7' | b'd' | b's' => {
            next_skip_bytes = 4;
            'check: {
                // 0 means the end of an LHa archive file.
                if b(0) == 0 {
                    break 'check;
                }
                if b(H_METHOD_OFFSET) != b'-'
                    || b(H_METHOD_OFFSET + 1) != b'l'
                    || b(H_METHOD_OFFSET + 4) != b'-'
                {
                    break 'check;
                }

                if b(H_METHOD_OFFSET + 2) == b'h' {
                    // "-lh?-"
                    if b(H_METHOD_OFFSET + 3) == b's' {
                        break 'check;
                    }
                    // Upstream compares a `char`, signed here: levels 0x80 to
                    // 0xff pass and are refused by read_header.
                    if (b(H_LEVEL_OFFSET) as i8) <= 3 {
                        return 0;
                    }
                }
                if b(H_METHOD_OFFSET + 2) == b'z' {
                    // LArc extensions: -lzs-,-lz4- and -lz5-
                    if b(H_LEVEL_OFFSET) != 0 {
                        break 'check;
                    }
                    if matches!(b(H_METHOD_OFFSET + 3), b's' | b'4' | b'5') {
                        return 0;
                    }
                }
            }
        }
        b'h' | b'z' => next_skip_bytes = 1,
        b'l' => next_skip_bytes = 2,
        b'-' => next_skip_bytes = 3,
        _ => next_skip_bytes = 4,
    }
    next_skip_bytes
}

/// `lha_skip_sfx`: scans ahead until we find something that looks like the
/// lha header.
fn skip_sfx(r: &mut Reader<'_>) -> Result<(), Error> {
    let mut window = 4096;
    loop {
        let skip = match ahead(r, window) {
            None => {
                // Remaining bytes are less than window.
                window >>= 1;
                if window < H_SIZE + 3 {
                    return Err(Error::fatal(
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        "Couldn't find out LHa header",
                    ));
                }
                continue;
            }
            Some(h) => {
                if h.len() < H_SIZE {
                    return Err(Error::fatal(
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        "Couldn't find out LHa header",
                    ));
                }
                let mut p = 0;
                let mut found = false;
                while p + H_SIZE < h.len() {
                    let next = check_header_format(h.get(p..).unwrap_or_default());
                    if next == 0 {
                        found = true;
                        break;
                    }
                    p += next;
                }
                (p, found)
            }
        };
        r.consume(skip.0)?;
        if skip.1 {
            return Ok(());
        }
    }
}

/// `lha_calcsum`.
fn calcsum(sum: u8, p: &[u8]) -> u8 {
    p.iter().fold(sum, |sum, &b| sum.wrapping_add(b))
}

const CRC16_TABLE: [u16; 256] = {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u16;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xA001 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// `lha_crc16`.
fn crc16(crc: u16, p: &[u8]) -> u16 {
    p.iter().fold(crc, |crc, &b| {
        (crc >> 8)
            ^ CRC16_TABLE
                .get(usize::from((crc as u8) ^ b))
                .copied()
                .unwrap_or(0)
    })
}

/// `archive_string_conversion_from_charset` with `best_effort`.
fn charset_conversion(a: &Base, charset: &[u8]) -> Result<Arc<StringConv>, Error> {
    let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
    conversion_from_charset(Some(&mut *cache), charset, true)
        .map_err(|e| Error::fatal(e.errno, e.message))
}

/// A name in the charset of `sc` as wide characters: upstream converts it
/// with `archive_mstring_copy_mbs_len_l` and `archive_mstring_get_wcs`.
fn to_wide(a: &Base, name: &[u8], sc: Option<&StringConv>) -> Result<Vec<wchar_t>, Error> {
    let mut s = MString::default();
    if s.copy_mbs_len_l(name, sc).is_err() {
        return Err(Error::fatal(
            ARCHIVE_ERRNO_FILE_FORMAT,
            [
                b"Pathname cannot be converted from ".as_slice(),
                conversion_charset_name(sc),
                b" to Unicode",
            ]
            .concat(),
        ));
    }
    let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
    match s.get_wcs(Some(&mut *cache)) {
        Ok(Some(w)) => Ok(w.to_vec()),
        _ => Err(Error::silent(ARCHIVE_FATAL)),
    }
}

/// `lha_replace_path_separator`: replaces a DOS path separator '\' by '/'.
/// Some multi-byte character set have a character '\' in its second byte.
fn replace_path_separator(ws: &mut [wchar_t]) {
    for c in ws {
        if *c == wchar_t::from(b'\\') {
            *c = wchar_t::from(b'/');
        }
    }
}

impl Lha {
    /// The charset of the directory and file names: `hdrcharset`, or the
    /// locale's.
    fn reset_conversions(&mut self) {
        self.sconv_dir.clone_from(&self.opt_sconv);
        self.sconv_fname.clone_from(&self.opt_sconv);
    }

    /// Header 0 format
    ///
    /// ```text
    /// +0              +1         +2               +7                  +11
    /// +---------------+----------+----------------+-------------------+
    /// |header size(*1)|header sum|compression type|compressed size(*2)|
    /// +---------------+----------+----------------+-------------------+
    ///                             <---------------------(*1)----------*
    ///
    /// +11               +15       +17       +19            +20              +21
    /// +-----------------+---------+---------+--------------+----------------+
    /// |uncompressed size|time(DOS)|date(DOS)|attribute(DOS)|header level(=0)|
    /// +-----------------+---------+---------+--------------+----------------+
    /// *--------------------------------(*1)---------------------------------*
    ///
    /// +21             +22       +22+(*3)   +22+(*3)+2       +22+(*3)+2+(*4)
    /// +---------------+---------+----------+----------------+------------------+
    /// |name length(*3)|file name|file CRC16|extra header(*4)|  compressed data |
    /// +---------------+---------+----------+----------------+------------------+
    ///                  <--(*3)->                             <------(*2)------>
    /// *----------------------(*1)-------------------------->
    /// ```
    fn read_file_header_0(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        const COMP_SIZE_OFFSET: usize = 7;
        const ORIG_SIZE_OFFSET: usize = 11;
        const DOS_TIME_OFFSET: usize = 15;
        const NAME_LEN_OFFSET: usize = 21;
        const FILE_NAME_OFFSET: usize = 22;
        const FIXED_SIZE: usize = 24;

        let Some(p) = ahead(r, FIXED_SIZE) else {
            return Err(truncated_error());
        };
        self.header_size = usize::from(byte(p, 0)) + 2;
        let headersum = byte(p, 1);
        self.compsize = i64::from(le32(p, COMP_SIZE_OFFSET));
        self.origsize = i64::from(le32(p, ORIG_SIZE_OFFSET));
        self.mtime.0 = dos_to_unix(le32(p, DOS_TIME_OFFSET));
        let namelen = usize::from(byte(p, NAME_LEN_OFFSET));
        // The extended header size; -2 if the header has no CRC16 either.
        let extdsize = self.header_size as isize - FIXED_SIZE as isize - namelen as isize;
        if (namelen > 221 || extdsize < 0) && extdsize != -2 {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Invalid LHa header",
            ));
        }
        let Some(p) = ahead(r, self.header_size) else {
            return Err(truncated_error());
        };

        self.filename.clear();
        self.filename.extend_from_slice(until_nul(
            p.get(FILE_NAME_OFFSET..FILE_NAME_OFFSET + namelen)
                .unwrap_or_default(),
        ));
        // When extdsize == -2, A CRC16 value is not present in the header.
        if extdsize >= 0 {
            self.crc = le16(p, FILE_NAME_OFFSET + namelen);
            self.setflag |= CRC_IS_SET;
        }
        let sum_calculated = calcsum(0, p.get(2..self.header_size).unwrap_or_default());

        // Read an extended header
        if extdsize > 0 {
            // This extended data is set by 'LHa for UNIX' only.
            // Maybe fixed size.
            let p = p.get(FILE_NAME_OFFSET + namelen + 2..).unwrap_or_default();
            if byte(p, 0) == b'U' && extdsize == 12 {
                // p[1] is a minor version.
                self.mtime.0 = i64::from(le32(p, 2));
                self.mode = Mode::from(le16(p, 6));
                self.uid = i64::from(le16(p, 8));
                self.gid = i64::from(le16(p, 10));
                self.setflag |= UNIX_MODE_IS_SET;
            }
        }
        r.consume(self.header_size)?;

        if sum_calculated != headersum {
            return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "LHa header sum error"));
        }
        Ok(())
    }

    /// Header 1 format
    ///
    /// ```text
    /// +0              +1         +2               +7            +11
    /// +---------------+----------+----------------+-------------+
    /// |header size(*1)|header sum|compression type|skip size(*2)|
    /// +---------------+----------+----------------+-------------+
    ///                             <---------------(*1)----------*
    ///
    /// +11               +15       +17       +19            +20              +21
    /// +-----------------+---------+---------+--------------+----------------+
    /// |uncompressed size|time(DOS)|date(DOS)|attribute(DOS)|header level(=1)|
    /// +-----------------+---------+---------+--------------+----------------+
    /// *-------------------------------(*1)----------------------------------*
    ///
    /// +21             +22       +22+(*3)   +22+(*3)+2  +22+(*3)+3  +22+(*3)+3+(*4)
    /// +---------------+---------+----------+-----------+-----------+
    /// |name length(*3)|file name|file CRC16|  creator  |padding(*4)|
    /// +---------------+---------+----------+-----------+-----------+
    ///                  <--(*3)->
    /// *----------------------------(*1)----------------------------*
    ///
    /// +22+(*3)+3+(*4)  +22+(*3)+3+(*4)+2     +22+(*3)+3+(*4)+2+(*5)
    /// +----------------+---------------------+------------------------+
    /// |next header size| extended header(*5) |     compressed data    |
    /// +----------------+---------------------+------------------------+
    /// *------(*1)-----> <--------------------(*2)-------------------->
    /// ```
    fn read_file_header_1(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        const COMP_SIZE_OFFSET: usize = 7;
        const ORIG_SIZE_OFFSET: usize = 11;
        const DOS_TIME_OFFSET: usize = 15;
        const NAME_LEN_OFFSET: usize = 21;
        const FILE_NAME_OFFSET: usize = 22;
        const FIXED_SIZE: usize = 27;

        let Some(p) = ahead(r, FIXED_SIZE) else {
            return Err(truncated_error());
        };

        self.header_size = usize::from(byte(p, 0)) + 2;
        let headersum = byte(p, 1);
        // Note: An extended header size is included in a compsize.
        self.compsize = i64::from(le32(p, COMP_SIZE_OFFSET));
        self.origsize = i64::from(le32(p, ORIG_SIZE_OFFSET));
        self.mtime.0 = dos_to_unix(le32(p, DOS_TIME_OFFSET));
        let namelen = usize::from(byte(p, NAME_LEN_OFFSET));
        // Calculate a padding size. The result will be normally 0 only(?)
        let padding = self.header_size as isize - FIXED_SIZE as isize - namelen as isize;

        if namelen > 230 || padding < 0 {
            return Err(invalid_header());
        }

        let Some(p) = ahead(r, self.header_size) else {
            return Err(truncated_error());
        };

        let name = p
            .get(FILE_NAME_OFFSET..FILE_NAME_OFFSET + namelen)
            .unwrap_or_default();
        if name.contains(&0xff) {
            return Err(invalid_header()); // Invalid filename.
        }
        self.filename.clear();
        self.filename.extend_from_slice(until_nul(name));
        self.crc = le16(p, FILE_NAME_OFFSET + namelen);
        self.setflag |= CRC_IS_SET;

        let sum_calculated = calcsum(0, p.get(2..self.header_size).unwrap_or_default());
        // Consume used bytes but not include `next header size' data since
        // it will be consumed in read_file_extended_header().
        r.consume(self.header_size - 2)?;

        // Read extended headers
        let extdsize = self.read_file_extended_header(r, None, 2, (self.compsize + 2) as u64)?;
        // Get a real compressed file size.
        self.compsize = self.compsize.wrapping_sub((extdsize - 2) as i64);

        if self.compsize < 0 {
            return Err(invalid_header()); // Invalid compressed file size
        }

        if sum_calculated != headersum {
            return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "LHa header sum error"));
        }
        Ok(())
    }

    /// Header 2 format
    ///
    /// ```text
    /// +0              +2               +7                  +11               +15
    /// +---------------+----------------+-------------------+-----------------+
    /// |header size(*1)|compression type|compressed size(*2)|uncompressed size|
    /// +---------------+----------------+-------------------+-----------------+
    ///  <--------------------------------(*1)---------------------------------*
    ///
    /// +15               +19          +20              +21        +23         +24
    /// +-----------------+------------+----------------+----------+-----------+
    /// |data/time(time_t)| 0x20 fixed |header level(=2)|file CRC16|  creator  |
    /// +-----------------+------------+----------------+----------+-----------+
    /// *---------------------------------(*1)---------------------------------*
    ///
    /// +24              +26                 +26+(*3)      +26+(*3)+(*4)
    /// +----------------+-------------------+-------------+-------------------+
    /// |next header size|extended header(*3)| padding(*4) |  compressed data  |
    /// +----------------+-------------------+-------------+-------------------+
    /// *--------------------------(*1)-------------------> <------(*2)------->
    /// ```
    fn read_file_header_2(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        const HEADER_SIZE_OFFSET: usize = 0;
        const COMP_SIZE_OFFSET: usize = 7;
        const ORIG_SIZE_OFFSET: usize = 11;
        const TIME_OFFSET: usize = 15;
        const CRC_OFFSET: usize = 21;
        const FIXED_SIZE: usize = 24;

        let Some(p) = ahead(r, FIXED_SIZE) else {
            return Err(truncated_error());
        };

        self.header_size = usize::from(le16(p, HEADER_SIZE_OFFSET));
        self.compsize = i64::from(le32(p, COMP_SIZE_OFFSET));
        self.origsize = i64::from(le32(p, ORIG_SIZE_OFFSET));
        self.mtime.0 = i64::from(le32(p, TIME_OFFSET));
        self.crc = le16(p, CRC_OFFSET);
        self.setflag |= CRC_IS_SET;

        if self.header_size < FIXED_SIZE {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Invalid LHa header size",
            ));
        }

        let mut header_crc = crc16(0, p.get(..FIXED_SIZE).unwrap_or_default());
        r.consume(FIXED_SIZE)?;

        // Read extended headers
        let extdsize = self.read_file_extended_header(
            r,
            Some(&mut header_crc),
            2,
            (self.header_size - FIXED_SIZE) as u64,
        )?;

        // Calculate a padding size. The result will be normally 0 or 1.
        let padding = self.header_size as isize - (FIXED_SIZE + extdsize) as isize;
        if let Ok(padding @ 1..) = usize::try_from(padding) {
            let Some(p) = ahead(r, padding) else {
                return Err(truncated_error());
            };
            header_crc = crc16(header_crc, p.get(..padding).unwrap_or_default());
            r.consume(padding)?;
        }

        if header_crc != self.header_crc {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "LHa header CRC error",
            ));
        }
        Ok(())
    }

    /// Header 3 format
    ///
    /// ```text
    /// +0           +2               +7                  +11               +15
    /// +------------+----------------+-------------------+-----------------+
    /// | 0x04 fixed |compression type|compressed size(*2)|uncompressed size|
    /// +------------+----------------+-------------------+-----------------+
    ///  <-------------------------------(*1)-------------------------------*
    ///
    /// +15               +19          +20              +21        +23         +24
    /// +-----------------+------------+----------------+----------+-----------+
    /// |date/time(time_t)| 0x20 fixed |header level(=3)|file CRC16|  creator  |
    /// +-----------------+------------+----------------+----------+-----------+
    /// *--------------------------------(*1)----------------------------------*
    ///
    /// +24             +28              +32                 +32+(*3)
    /// +---------------+----------------+-------------------+-----------------+
    /// |header size(*1)|next header size|extended header(*3)| compressed data |
    /// +---------------+----------------+-------------------+-----------------+
    /// *------------------------(*1)-----------------------> <------(*2)----->
    /// ```
    fn read_file_header_3(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        const FIELD_LEN_OFFSET: usize = 0;
        const COMP_SIZE_OFFSET: usize = 7;
        const ORIG_SIZE_OFFSET: usize = 11;
        const TIME_OFFSET: usize = 15;
        const CRC_OFFSET: usize = 21;
        const HEADER_SIZE_OFFSET: usize = 24;
        const FIXED_SIZE: usize = 28;

        let Some(p) = ahead(r, FIXED_SIZE) else {
            return Err(truncated_error());
        };

        if le16(p, FIELD_LEN_OFFSET) != 4 {
            return Err(invalid_header());
        }
        let header_size = le32(p, HEADER_SIZE_OFFSET);
        self.compsize = i64::from(le32(p, COMP_SIZE_OFFSET));
        self.origsize = i64::from(le32(p, ORIG_SIZE_OFFSET));
        self.mtime.0 = i64::from(le32(p, TIME_OFFSET));
        self.crc = le16(p, CRC_OFFSET);
        self.setflag |= CRC_IS_SET;

        if (header_size as usize) < FIXED_SIZE + 4 {
            return Err(invalid_header());
        }
        let mut header_crc = crc16(0, p.get(..FIXED_SIZE).unwrap_or_default());
        r.consume(FIXED_SIZE)?;

        // Reject ridiculously large header
        if header_size > 65536 {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "LHa header size too large",
            ));
        }
        self.header_size = header_size as usize;

        // Read extended headers
        self.read_file_extended_header(
            r,
            Some(&mut header_crc),
            4,
            u64::from(header_size) - FIXED_SIZE as u64,
        )?;

        if header_crc != self.header_crc {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "LHa header CRC error",
            ));
        }
        Ok(())
    }

    /// Extended header format
    ///
    /// ```text
    /// +0             +2        +3  -- used in header 1 and 2
    /// +0             +4        +5  -- used in header 3
    /// +--------------+---------+-------------------+--------------+--
    /// |ex-header size|header id|        data       |ex-header size| .......
    /// +--------------+---------+-------------------+--------------+--
    ///  <-------------( ex-header size)------------> <-- next extended header --*
    /// ```
    ///
    /// If the ex-header size is zero, it is the make of the end of extended
    /// headers. Returns the total size of them.
    fn read_file_extended_header(
        &mut self,
        r: &mut Reader<'_>,
        mut crc: Option<&mut u16>,
        sizefield_length: usize,
        limitsize: u64,
    ) -> Result<usize, Error> {
        let a = r.base();
        let mut total_size = sizefield_length;

        loop {
            // Read an extended header size.
            let Some(h) = ahead(r, sizefield_length) else {
                return Err(truncated_error());
            };
            // Check if the size is the zero indicates the end of the
            // extended header.
            let extdsize = if sizefield_length == 2 {
                usize::from(le16(h, 0))
            } else {
                le32(h, 0) as usize
            };
            if extdsize == 0 {
                // End of extended header
                if let Some(crc) = crc.as_deref_mut() {
                    *crc = crc16(*crc, h.get(..sizefield_length).unwrap_or_default());
                }
                r.consume(sizefield_length)?;
                return Ok(total_size);
            }

            // Sanity check to the extended header size.
            if total_size as u64 + extdsize as u64 > limitsize || extdsize <= sizefield_length {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Invalid extended LHa header",
                ));
            }

            // Read the extended header.
            let Some(h) = ahead(r, extdsize).and_then(|h| h.get(..extdsize)) else {
                return Err(truncated_error());
            };
            total_size += extdsize;

            // Get the extended header type.
            let extdtype = byte(h, sizefield_length);
            // Skip an extended header size field and type field.
            let data = h.get(sizefield_length + 1..).unwrap_or_default();

            if let Some(crc) = crc.as_deref_mut()
                && extdtype != EXT_HEADER_CRC
            {
                *crc = crc16(*crc, h);
            }
            self.extended_header(a, crc.as_deref_mut(), extdtype, h, data)?;

            r.consume(extdsize)?;
        }
    }

    /// The effect of one extended header: `h` is all of it, `data` what
    /// follows its size and type fields.
    fn extended_header(
        &mut self,
        a: &Base,
        crc: Option<&mut u16>,
        extdtype: u8,
        h: &[u8],
        data: &[u8],
    ) -> Result<(), Error> {
        let invalid = || Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Invalid extended LHa header");
        let datasize = data.len();
        match extdtype {
            EXT_HEADER_CRC => {
                // We only use a header CRC. Following data will not be used.
                if datasize >= 2 {
                    self.header_crc = le16(data, 0);
                    if let Some(crc) = crc {
                        *crc = crc16(*crc, h.get(..h.len() - datasize).unwrap_or_default());
                        // CRC value itself as zero
                        *crc = crc16(*crc, &[0, 0]);
                        *crc = crc16(*crc, data.get(2..).unwrap_or_default());
                    }
                }
            }
            EXT_FILENAME => {
                if datasize == 0 {
                    // maybe directory header
                    self.filename.clear();
                } else if byte(data, 0) == 0 {
                    return Err(invalid());
                } else {
                    self.filename.clear();
                    self.filename.extend_from_slice(until_nul(data));
                }
            }
            EXT_UTF16_FILENAME => {
                if datasize == 0 {
                    // maybe directory header
                    self.filename.clear();
                } else if datasize & 1 != 0 || byte(data, 0) == 0 {
                    // UTF-16 characters take always 2 or 4 bytes
                    return Err(invalid());
                } else {
                    self.filename.clear();
                    self.filename.extend_from_slice(data);
                    // Setup a string conversion for a filename.
                    self.sconv_fname = Some(charset_conversion(a, b"UTF-16LE")?);
                }
            }
            EXT_DIRECTORY => {
                if datasize == 0 || byte(data, 0) == 0 {
                    // no directory name data.
                    return Err(invalid());
                }
                self.dirname.clear();
                self.dirname.extend_from_slice(until_nul(data));
                // Convert directory delimiter from 0xFF to '/' for local
                // system.
                for c in &mut self.dirname {
                    if *c == 0xFF {
                        *c = b'/';
                    }
                }
                // Is last character directory separator?
                if self.dirname.last() != Some(&b'/') {
                    // invalid directory data
                    return Err(invalid());
                }
            }
            EXT_UTF16_DIRECTORY => {
                // UTF-16 characters take always 2 or 4 bytes
                if datasize == 0 || datasize & 1 != 0 || byte(data, 0) == 0 {
                    // no directory name data.
                    return Err(invalid());
                }
                self.dirname.clear();
                self.dirname.extend_from_slice(data);
                self.sconv_dir = Some(charset_conversion(a, b"UTF-16LE")?);
                // Convert directory delimiter from 0xFFFF to '/' for local
                // system.
                let sep = u16::from(b'/').to_le_bytes();
                for unit in self.dirname.chunks_exact_mut(2) {
                    if unit == [0xFF, 0xFF] {
                        unit.copy_from_slice(&sep);
                    }
                }
                // Is last character directory separator?
                if self.dirname.chunks_exact(2).last() != Some(&sep[..]) {
                    // invalid directory data
                    return Err(invalid());
                }
            }
            EXT_DOS_ATTR => {
                if datasize == 2 {
                    self.dos_attr = le16(data, 0) as u8;
                }
            }
            EXT_TIMESTAMP => {
                if datasize == 8 * 3 {
                    self.birthtime = ntfs_to_unix(le64(data, 0));
                    self.mtime = ntfs_to_unix(le64(data, 8));
                    self.atime = ntfs_to_unix(le64(data, 16));
                    self.setflag |= BIRTHTIME_IS_SET | ATIME_IS_SET;
                }
            }
            EXT_FILESIZE => {
                if datasize == 8 * 2 {
                    // Range-check before the conversion to the signed type
                    // rather than relying on the implementation-defined
                    // result of it.
                    let (Ok(compsize), Ok(origsize)) =
                        (i64::try_from(le64(data, 0)), i64::try_from(le64(data, 8)))
                    else {
                        return Err(invalid());
                    };
                    self.compsize = compsize;
                    self.origsize = origsize;
                }
            }
            EXT_CODEPAGE => {
                // Get an archived filename charset from codepage. This
                // overwrites the charset specified by hdrcharset option.
                if datasize == 4 {
                    let codepage = le32(data, 0);
                    let charset = if codepage == 65001 {
                        b"UTF-8".to_vec()
                    } else {
                        format!("CP{}", codepage as i32).into_bytes()
                    };
                    self.sconv_dir = Some(charset_conversion(a, &charset)?);
                    self.sconv_fname = Some(charset_conversion(a, &charset)?);
                }
            }
            EXT_UNIX_MODE => {
                if datasize == 2 {
                    self.mode = Mode::from(le16(data, 0));
                    self.setflag |= UNIX_MODE_IS_SET;
                }
            }
            EXT_UNIX_GID_UID => {
                if datasize == 2 * 2 {
                    self.gid = i64::from(le16(data, 0));
                    self.uid = i64::from(le16(data, 2));
                }
            }
            EXT_UNIX_GNAME => {
                if datasize > 0 {
                    self.gname.clear();
                    self.gname.extend_from_slice(until_nul(data));
                }
            }
            EXT_UNIX_UNAME => {
                if datasize > 0 {
                    self.uname.clear();
                    self.uname.extend_from_slice(until_nul(data));
                }
            }
            EXT_UNIX_MTIME => {
                if datasize == 4 {
                    self.mtime.0 = i64::from(le32(data, 0));
                }
            }
            EXT_OS2_NEW_ATTR => {
                // This extended header is OS/2 depend.
                if datasize == 16 {
                    self.dos_attr = le16(data, 0) as u8;
                    self.mode = Mode::from(le16(data, 2));
                    self.gid = i64::from(le16(data, 4));
                    self.uid = i64::from(le16(data, 6));
                    self.birthtime.0 = i64::from(le32(data, 8));
                    self.atime.0 = i64::from(le32(data, 12));
                    self.setflag |= UNIX_MODE_IS_SET | BIRTHTIME_IS_SET | ATIME_IS_SET;
                }
            }
            EXT_NEW_ATTR if datasize == 20 => {
                self.mode = le32(data, 0) as Mode;
                self.gid = i64::from(le32(data, 4));
                self.uid = i64::from(le32(data, 8));
                self.birthtime.0 = i64::from(le32(data, 12));
                self.atime.0 = i64::from(le32(data, 16));
                self.setflag |= UNIX_MODE_IS_SET | BIRTHTIME_IS_SET | ATIME_IS_SET;
            }
            // The time zone is not supported.
            _ => {}
        }
        Ok(())
    }

    /// `lha_end_of_entry`: the end of the data, or a warning about its CRC
    /// once.
    fn end_of_entry(&mut self, a: &Base) -> Data<'static> {
        if !self.end_of_entry_cleanup {
            // End-of-entry cleanup done.
            self.end_of_entry_cleanup = true;
            if self.setflag & CRC_IS_SET != 0 && self.crc != self.entry_crc_calculated {
                let _ = a.warn(ARCHIVE_ERRNO_MISC, "LHa data CRC error");
                return Data::Warn;
            }
        }
        Data::Eof {
            offset: self.entry_offset,
        }
    }

    /// `lha_read_data_none`: reads a file content in no compression.
    fn read_data_none<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        if self.entry_bytes_remaining == 0 {
            self.end_of_entry = true;
            return Ok(Data::Block {
                data: &[],
                offset: self.entry_offset,
            });
        }
        // Note: '1' here is a performance optimization. Recall that the
        // decompression layer returns a count of available bytes; asking
        // for more than that forces the decompressor to combine reads by
        // copying data.
        let later = r.consume_later();
        let Some(buff) = ahead(r, 1) else {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Truncated LHa file data",
            ));
        };
        let n = buff
            .len()
            .min(usize::try_from(self.entry_bytes_remaining).unwrap_or(usize::MAX));
        let data = buff.get(..n).unwrap_or_default();
        self.entry_crc_calculated = crc16(self.entry_crc_calculated, data);
        let offset = self.entry_offset;
        self.entry_offset += n as i64;
        self.entry_bytes_remaining -= n as i64;
        if self.entry_bytes_remaining == 0 {
            self.end_of_entry = true;
        }
        later.consume(n);
        Ok(Data::Block { data, offset })
    }

    /// `lha_read_data_lzh`: reads a file content in LZHUFF encoding. A
    /// compression method that is not supported warns and skips the entry.
    fn read_data_lzh<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        let a = r.base();
        // If we haven't yet read any data, initialize the decompressor.
        if !self.decompress_init {
            let Some(dec) = Lzh::new(&self.method) else {
                // Unsupported compression.
                let msg = [
                    b"Unsupported lzh compression method -".as_slice(),
                    &self.method,
                    b"-",
                ]
                .concat();
                let _ = a.warn(ARCHIVE_ERRNO_FILE_FORMAT, msg);
                // We know compressed size; just skip it.
                let _ = self.read_data_skip(r);
                return Ok(Data::Warn);
            };
            self.dec = Some(dec);
            // We've initialized decompression for this stream.
            self.decompress_init = true;
        }

        // Note: '1' here is a performance optimization. Recall that the
        // decompression layer returns a count of available bytes; asking
        // for more than that forces the decompressor to combine reads by
        // copying data.
        let later = r.consume_later();
        let Some(buff) = ahead(r, 1) else {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Truncated LHa file body",
            ));
        };
        // The decoder counts its input in an int, and the compressed size
        // comes straight from the LHa header.
        let n = buff
            .len()
            .min(usize::try_from(self.entry_bytes_remaining).unwrap_or(usize::MAX))
            .min(i32::MAX as usize);
        let mut input = Input::new(buff.get(..n).unwrap_or_default());
        let Some(dec) = self.dec.as_mut() else {
            return Err(Error::silent(ARCHIVE_FATAL));
        };
        match dec.decode(&mut input, n as i64 == self.entry_bytes_remaining) {
            Step::Eof => self.end_of_entry = true,
            Step::Failed | Step::More => {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    "Bad lzh data",
                ));
            }
            Step::Ok => {}
        }
        later.consume(input.pos);
        self.entry_bytes_remaining -= input.pos as i64;

        let offset = self.entry_offset;
        if dec.avail_out == 0 {
            if self.end_of_entry {
                return Ok(self.end_of_entry(a));
            }
            return Ok(Data::Block { data: &[], offset });
        }
        let out = self.dec.as_ref().map_or(&[][..], Lzh::output);
        self.entry_crc_calculated = crc16(self.entry_crc_calculated, out);
        self.entry_offset += out.len() as i64;
        Ok(Data::Block { data: out, offset })
    }
}

impl Format for Lha {
    fn name(&self) -> &'static str {
        "lha"
    }

    fn bid(&mut self, r: &mut Reader<'_>, best_bid: c_int) -> Result<c_int, Error> {
        // If there's already a better bid than we can ever make, don't
        // bother testing.
        if best_bid > 30 {
            return Ok(-1);
        }

        let Some(h) = ahead(r, H_SIZE) else {
            return Ok(-1);
        };

        if check_header_format(h) == 0 {
            return Ok(30);
        }

        if h.starts_with(b"MZ") {
            // PE file
            let mut offset = 0;
            let mut window = 4096;
            while offset + window <= SFX_MAX_READAHEAD {
                let h = r.peek_available(offset + window).unwrap_or_default();
                if h.len() < offset + window {
                    if h.len() >= offset + H_SIZE {
                        // Remaining bytes are less than window.
                        window = h.len() - offset;
                        continue;
                    }
                    return Ok(0);
                }
                let bytes_avail = h.len().min(SFX_MAX_READAHEAD);
                while offset + H_SIZE <= bytes_avail {
                    let next = check_header_format(h.get(offset..).unwrap_or_default());
                    if next == 0 {
                        return Ok(30);
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
        Some(if key == b"hdrcharset" {
            let Some(name) = value.filter(|v| !v.is_empty()) else {
                return Some(Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    "lha: hdrcharset option needs a character-set name",
                )));
            };
            let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
            conversion_from_charset(Some(&mut *cache), name, false)
                .map(|sc| {
                    self.opt_sconv = Some(sc);
                    Status::Ok
                })
                .map_err(|e| Error::fatal(e.errno, e.message))
        } else {
            // Note: The "warn" return is just to inform the options
            // supervisor that we didn't handle it. It will generate a
            // suitable error if no one used this option.
            Ok(Status::Warn)
        })
    }

    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        let a = r.base();
        a.format.set(format_code::LHA);
        if a.format_name.get().is_none() {
            a.format_name.set(Some(c"lha"));
        }

        self.decompress_init = false;
        self.end_of_entry = false;
        self.end_of_entry_cleanup = false;

        let Some(mut p) = header_start(r, H_SIZE) else {
            // LHa archiver added 0 to the tail of its archive file as the
            // mark of the end of the archive.
            return match ahead(r, 1) {
                Some([0, ..]) | None => Ok(Status::Eof),
                Some(_) => Err(truncated_error()),
            };
        };

        if !self.found_first_header && p.starts_with(b"MZ") {
            // This is an executable? Must be self-extracting...
            skip_sfx(r)?;

            let Some(h) = header_start(r, 1) else {
                return Err(truncated_error());
            };
            p = h;
        }
        // The signature 0 means the end of an LHa archive file.
        if byte(&p, 0) == 0 {
            return Ok(Status::Eof);
        }

        // Check the header format and method type.
        if check_header_format(&p) != 0 {
            return Err(Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Bad LHa file"));
        }

        // We've found the first header.
        self.found_first_header = true;
        // Set a default value and common data
        self.header_size = 0;
        self.level = byte(&p, H_LEVEL_OFFSET);
        self.method = [
            byte(&p, H_METHOD_OFFSET + 1),
            byte(&p, H_METHOD_OFFSET + 2),
            byte(&p, H_METHOD_OFFSET + 3),
        ];
        self.directory = self.method == *b"lhd";
        self.entry_is_compressed = !(self.method == *b"lh0" || self.method == *b"lz4");

        self.compsize = 0;
        self.origsize = 0;
        self.setflag = 0;
        self.birthtime = (0, 0);
        self.mtime = (0, 0);
        self.atime = (0, 0);
        self.mode = if self.directory { 0o777 } else { 0o666 };
        self.uid = 0;
        self.gid = 0;
        self.dirname.clear();
        self.filename.clear();
        self.dos_attr = 0;
        self.reset_conversions();

        match self.level {
            0 => self.read_file_header_0(r)?,
            1 => self.read_file_header_1(r)?,
            2 => self.read_file_header_2(r)?,
            3 => self.read_file_header_3(r)?,
            level => {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    format!("Unsupported LHa header level {}", level as i8),
                ));
            }
        }

        if !self.directory
            && self.filename.is_empty()
            && self.method == *b"lh0"
            && !self.dirname.is_empty()
        {
            self.directory = true; // empty directory entry
        }

        if !self.directory && self.filename.is_empty() {
            // The filename has not been set
            return Err(truncated_error());
        }

        // Make a pathname from a dirname and a filename, after converting to
        // Unicode. This is because codepages might differ between dirname
        // and filename.
        let mut pathname = to_wide(a, &self.dirname, self.sconv_dir.as_deref())?;
        pathname.extend(to_wide(a, &self.filename, self.sconv_fname.as_deref())?);

        let mut linkname = Vec::new();
        if self.mode & AE_IFMT == AE_IFLNK {
            // Extract the symlink-name if it's included in the pathname.
            // 'LHa for UNIX' utility has archived a symbolic-link name
            // after a pathname with '|' character. example.
            //   1. a symbolic-name is 'aaa/bb/cc'
            //   2. a filename is 'xxx/bbb'
            // then an archived pathname is 'xxx/bbb|aaa/bb/cc'
            let Some(bar) = pathname.iter().position(|&c| c == wchar_t::from(b'|')) else {
                // We couldn't get the symlink-name.
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Unknown symlink-name",
                ));
            };
            linkname = pathname.split_off(bar + 1);
            pathname.truncate(bar);
        } else {
            // Make sure a file-type is set. The mode has been overridden if
            // it is in the extended data.
            self.mode = (self.mode & !AE_IFMT) | if self.directory { AE_IFDIR } else { AE_IFREG };
        }
        if self.setflag & UNIX_MODE_IS_SET == 0 && self.dos_attr & 1 != 0 {
            self.mode &= !0o222; // read only.
        }

        // When a header level is 0, there is a possibility that a pathname
        // and a symlink has '' character, a directory separator in
        // DOS/Windows. So we should convert it to '/'.
        if self.level == 0 {
            replace_path_separator(&mut pathname);
            replace_path_separator(&mut linkname);
        }

        // Set basic file parameters.
        entry.copy_pathname_w(&pathname);
        if linkname.is_empty() {
            entry.unset_symlink();
        } else {
            entry.copy_symlink_w(&linkname);
        }

        entry.set_mode(self.mode);
        entry.set_uid(self.uid);
        entry.set_gid(self.gid);
        if !self.uname.is_empty() {
            entry.set_uname(&self.uname);
        }
        if !self.gname.is_empty() {
            entry.set_gname(&self.gname);
        }
        if self.setflag & BIRTHTIME_IS_SET != 0 {
            entry.set_birthtime(self.birthtime.0, i64::from(self.birthtime.1));
            entry.set_ctime(self.birthtime.0, i64::from(self.birthtime.1));
        } else {
            entry.unset_birthtime();
            entry.unset_ctime();
        }
        entry.set_mtime(self.mtime.0, i64::from(self.mtime.1));
        if self.setflag & ATIME_IS_SET != 0 {
            entry.set_atime(self.atime.0, i64::from(self.atime.1));
        } else {
            entry.unset_atime();
        }
        if self.directory || entry.symlink().is_some() {
            entry.unset_size();
        } else {
            entry.set_size(self.origsize);
        }

        // Prepare variables used to read a file content.
        self.entry_bytes_remaining = self.compsize;
        if self.entry_bytes_remaining < 0 {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Invalid LHa entry size",
            ));
        }
        self.entry_offset = 0;
        self.entry_crc_calculated = 0;

        // This file does not have a content.
        if self.directory || self.compsize == 0 {
            self.end_of_entry = true;
        }

        if let Some((_, name)) = FORMAT_NAMES.iter().find(|(m, _)| **m == self.method) {
            a.format_name.set(Some(name));
        }

        Ok(Status::Ok)
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        if self.end_of_entry {
            return Ok(self.end_of_entry(r.base()));
        }
        if self.entry_is_compressed {
            self.read_data_lzh(r)
        } else {
            // No compression.
            self.read_data_none(r)
        }
    }

    fn read_data_skip(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        // If we've already read to end of data, we're done.
        if self.end_of_entry_cleanup {
            return Ok(Status::Ok);
        }

        // If the length is at the beginning, we can skip the compressed data
        // much more quickly.
        r.consume(self.entry_bytes_remaining)?;

        // This entry is finished and done.
        self.end_of_entry_cleanup = true;
        self.end_of_entry = true;
        Ok(Status::Ok)
    }
}
