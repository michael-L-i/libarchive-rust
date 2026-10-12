/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2009 Andreas Henriksson <andreas@fatal.se>
 * Copyright (c) 2009-2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_read_support_format_iso9660.c.

//! The ISO 9660 reader, with the Joliet and Rock Ridge (SUSP) extensions and
//! zisofs.
//!
//! This module works by first reading the volume descriptors, then building
//! a list of directory entries, sorted by starting sector. At each step, it
//! looks for the earliest dir entry that hasn't yet been read, seeks forward
//! to that location and reads that entry. If it's a dir, it slurps in the new
//! dir entries and adds them to the heap; if it's a regular file, it returns
//! the corresponding entry and waits for the client to request the file
//! body. This strategy allows reading most compliant CDs with a single pass
//! through the data, as required by libarchive.
//!
//! Every directory record is kept in `Iso9660::files`, and the lists the
//! upstream code threads through them (`next`, `re_next`, `use_next`) are
//! queues of indexes into it.

use crate::archive::*;
use crate::entry::{AE_IFDIR, AE_IFLNK, AE_IFMT, AE_IFREG, Dev, Entry, Mode};
use crate::read::{ARCHIVE_ERRNO_FILE_FORMAT, Data, Format, Read, Reader, Status, Whence};
use crate::string::{StringConv, conversion_charset_name, conversion_from_charset};
use crate::util::Error;
use miniz_oxide::inflate::stream::{InflateState, inflate as mz_inflate};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};
use std::collections::VecDeque;
use std::ffi::c_int;
use std::sync::{Arc, PoisonError};

const FORMAT_ISO9660: c_int = 0x40000;
const FORMAT_ISO9660_ROCKRIDGE: c_int = 0x40001;

const LOGICAL_BLOCK_SIZE: usize = 2048;
const SYSTEM_AREA_BLOCK: i32 = 16;
const RESERVED_AREA: usize = SYSTEM_AREA_BLOCK as usize * LOGICAL_BLOCK_SIZE;

// Offsets in the on-disk primary volume descriptor.
const PVD_TYPE: usize = 0;
const PVD_VERSION: usize = 6;
const PVD_RESERVED1: usize = 7;
const PVD_RESERVED2: (usize, usize) = (72, 8);
const PVD_VOLUME_SPACE_SIZE: usize = 80;
const PVD_RESERVED3: (usize, usize) = (88, 32);
const PVD_VOLUME_SET_SIZE: usize = 120;
const PVD_VOLUME_SEQUENCE_NUMBER: usize = 124;
const PVD_LOGICAL_BLOCK_SIZE: usize = 128;
const PVD_PATH_TABLE_SIZE: usize = 132;
const PVD_TYPE_1_PATH_TABLE: usize = 140;
const PVD_TYPE_M_PATH_TABLE: usize = 148;
const PVD_ROOT_DIRECTORY_RECORD: usize = 156;
const PVD_FILE_STRUCTURE_VERSION: usize = 881;
const PVD_RESERVED4: (usize, usize) = (882, 1);
const PVD_RESERVED5: (usize, usize) = (1395, 653);

// Offsets in the optional on-disk supplementary volume descriptor.
const SVD_RESERVED1: (usize, usize) = (72, 8);
const SVD_VOLUME_SPACE_SIZE: usize = 80;
const SVD_ESCAPE_SEQUENCES: usize = 88;
const SVD_LOGICAL_BLOCK_SIZE: usize = 128;
const SVD_TYPE_L_PATH_TABLE: usize = 140;
const SVD_TYPE_M_PATH_TABLE: usize = 148;
const SVD_ROOT_DIRECTORY_RECORD: usize = 156;
const SVD_FILE_STRUCTURE_VERSION: usize = 881;
const SVD_RESERVED2: (usize, usize) = (882, 1);
const SVD_RESERVED3: (usize, usize) = (1395, 653);

// Offsets in an on-disk directory record. ISO9660 stores each multi-byte
// integer twice, once in each byte order; these are the little-endian ones.
const DR_LENGTH: usize = 0;
const DR_EXTENT: usize = 2;
const DR_SIZE: usize = 10;
const DR_DATE: usize = 18;
const DR_FLAGS: usize = 25;
const DR_VOLUME_SEQUENCE_NUMBER: usize = 28;
const DR_NAME_LEN: usize = 32;
const DR_NAME: usize = 33;

const ZISOFS_MAGIC: [u8; 8] = [0x37, 0xE4, 0x53, 0x96, 0xC9, 0xDB, 0xD6, 0x07];

/// Bits of `FileInfo::time_is_set`.
const BIRTHTIME_IS_SET: u8 = 1;
const MTIME_IS_SET: u8 = 2;
const ATIME_IS_SET: u8 = 4;
const CTIME_IS_SET: u8 = 8;

/// The buffers for a full Joliet pathname in UTF-16BE.
const UTF16_NAME_MAX: usize = 1024;

fn byte(h: &[u8], off: usize) -> u8 {
    h.get(off).copied().unwrap_or(0)
}

fn le16(h: &[u8], off: usize) -> u16 {
    h.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

fn le32(h: &[u8], off: usize) -> u32 {
    h.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn be32(h: &[u8], off: usize) -> u32 {
    h.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_be_bytes)
}

/// An `archive_string`: a buffer that is NULL until something is appended,
/// and a length. Emptying only sets the length to zero and keeps the bytes,
/// and code that reads the buffer as a C string (`name.s`) still sees them;
/// code that goes by the length does not.
#[derive(Default)]
struct AString {
    buf: Option<Vec<u8>>,
    len: usize,
}

impl AString {
    fn new(s: Vec<u8>) -> Self {
        AString {
            len: s.len(),
            buf: Some(s),
        }
    }

    fn empty(&mut self) {
        self.len = 0;
    }

    /// `archive_strncat`: at most `n` bytes, up to the first NUL.
    fn ncat(&mut self, p: &[u8], n: usize) {
        let p = p.get(..n).unwrap_or(p);
        let end = p.iter().position(|&c| c == 0).unwrap_or(p.len());
        let v = self.buf.get_or_insert_default();
        v.truncate(self.len);
        v.extend_from_slice(p.get(..end).unwrap_or_default());
        self.len = v.len();
    }

    fn cat(&mut self, p: &[u8]) {
        self.ncat(p, p.len());
    }

    fn is_set(&self) -> bool {
        self.buf.is_some()
    }

    /// The string by its length.
    fn bytes(&self) -> &[u8] {
        self.buf
            .as_deref()
            .and_then(|v| v.get(..self.len))
            .unwrap_or_default()
    }

    /// The buffer as a C string, `s`: up to its first NUL, whatever the
    /// length is.
    fn c_str(&self) -> &[u8] {
        let v = self.buf.as_deref().unwrap_or_default();
        v.get(..v.iter().position(|&c| c == 0).unwrap_or(v.len()))
            .unwrap_or_default()
    }

    /// What `%s` prints.
    fn display(&self) -> &[u8] {
        if self.is_set() {
            self.c_str()
        } else {
            b"(null)"
        }
    }
}

/// A binary min-heap of `(key, index)` as upstream hand-rolls it
/// (`heap_add_entry`, `heap_get_entry`, `register_CE` and `next_CE`). Which
/// of several equal keys comes out first decides the order of entries, so
/// `BinaryHeap` is not a substitute.
#[derive(Default)]
struct Heap(Vec<(u64, usize)>);

impl Heap {
    fn add(&mut self, key: u64, item: usize) {
        // Start with hole at end, walk it up tree to find insertion point.
        let mut hole = self.0.len();
        self.0.push((key, item));
        while hole > 0 {
            let parent = (hole - 1) / 2;
            if key >= self.0[parent].0 {
                break;
            }
            // Move parent into hole <==> move hole up tree.
            self.0.swap(hole, parent);
            hole = parent;
        }
    }

    fn first(&self) -> Option<(u64, usize)> {
        self.0.first().copied()
    }

    fn pop(&mut self) -> Option<usize> {
        if self.0.is_empty() {
            return None;
        }
        // The first is the earliest; move the last item to the root of the
        // tree, and rebalance.
        let (_, item) = self.0.swap_remove(0);
        let mut a = 0;
        loop {
            let mut b = a + a + 1;
            if b >= self.0.len() {
                break;
            }
            if self.0.get(b + 1).is_some_and(|c| c.0 < self.0[b].0) {
                b += 1;
            }
            if self.0[a].0 <= self.0[b].0 {
                break;
            }
            self.0.swap(a, b);
            a = b;
        }
        Some(item)
    }
}

/// One extent of a multi-extent file.
#[derive(Clone, Copy)]
struct Content {
    offset: u64,
    size: u64,
}

/// In-memory storage for a directory record.
#[derive(Default)]
struct FileInfo {
    parent: Option<usize>,
    subdirs: i32,
    /// Offset on disk.
    offset: u64,
    /// File size in bytes.
    size: u64,
    /// Offset of CE.
    ce_offset: u32,
    /// Size of CE.
    ce_size: u32,
    /// End offset of processed CE.
    ce_processed_end: u64,
    /// Flag to rr_moved.
    rr_moved: bool,
    rr_moved_has_re_only: bool,
    /// Having RRIP "RE" extension.
    re: bool,
    re_descendant: bool,
    /// Having RRIP "CL" extension.
    cl_offset: u64,
    /// Bitmask indicating which times are known.
    time_is_set: u8,
    birthtime: i64,
    mtime: i64,
    atime: i64,
    ctime: i64,
    rdev: u64,
    mode: Mode,
    uid: u32,
    gid: u32,
    number: i64,
    nlinks: i32,
    /// Pathname.
    name: AString,
    utf16be_name: Vec<u8>,
    /// Non-zero if name continues.
    name_continues: bool,
    symlink: AString,
    /// Non-zero if link continues.
    symlink_continues: bool,
    /// Set if this file is compressed by paged zlib (zisofs).
    pz: bool,
    /// Log2 of block size.
    pz_log2_bs: u32,
    pz_uncompressed_size: u64,
    /// Set if this file is multi extent.
    multi_extent: bool,
    contents: Vec<Content>,
    /// Descendants of an "RE" directory.
    rede_files: VecDeque<usize>,
}

/// A volume descriptor's root directory record.
#[derive(Clone, Copy, Default)]
struct Vd {
    /// Location of Extent.
    location: i32,
    size: u32,
}

/// What `next_cache_entry` found: an entry, or the status that ends the
/// header (the end of the archive, or a warning to return as it is).
enum Pull {
    File(usize),
    Done(Status),
}

#[derive(Default)]
struct Zisofs {
    /// Set if this file is compressed by paged zlib.
    pz: bool,
    /// Log2 of block size.
    pz_log2_bs: u32,
    pz_uncompressed_size: u64,

    initialized: bool,
    uncompressed_buffer: Vec<u8>,

    pz_offset: u32,
    header: [u8; 16],
    header_avail: usize,
    header_passed: bool,
    /// The block pointers read so far.
    block_pointers: Vec<u8>,
    block_pointers_size: usize,
    block_off: usize,
    block_avail: u32,

    stream: Option<Box<InflateState>>,
}

struct Iso9660 {
    opt_support_joliet: bool,
    opt_support_rockridge: bool,

    /// The pathname of the latest entry (not for Joliet).
    pathname: AString,
    /// Set if RR extensions are used.
    seen_rockridge: bool,
    /// Set if SUSP is being used.
    seen_susp: bool,
    /// The Joliet level, 0 if there is none.
    seen_joliet: u8,

    susp_offset: u8,
    rr_moved: Option<usize>,
    /// Pending reads of CE areas, by offset.
    read_ce_req: Heap,

    previous_number: i64,
    previous_pathname: AString,

    /// Every directory record read.
    files: Vec<FileInfo>,
    /// Entries to return, by offset.
    pending_files: Heap,
    cache_files: VecDeque<usize>,
    re_files: VecDeque<usize>,

    current_position: u64,
    logical_block_size: i64,
    /// Total size of volume in bytes.
    volume_size: u64,
    /// Total size of volume in logical blocks.
    volume_block: i32,

    primary: Vd,
    joliet: Vd,

    entry_sparse_offset: i64,
    entry_bytes_remaining: i64,
    entry_zisofs: Zisofs,
    /// The extents of the entry being read, and the one in progress.
    entry_contents: Vec<Content>,
    entry_content: Option<usize>,
    sconv_utf16be: Option<Arc<StringConv>>,
    /// The full pathname in UTF-16BE in Joliet extensions.
    utf16be_path: Vec<u8>,
    utf16be_previous_path: Vec<u8>,
}

/// `archive_read_support_format_iso9660`.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Iso9660 {
        // Enable to support Joliet extensions by default.
        opt_support_joliet: true,
        // Enable to support Rock Ridge extensions by default.
        opt_support_rockridge: true,
        pathname: AString::default(),
        seen_rockridge: false,
        seen_susp: false,
        seen_joliet: 0,
        susp_offset: 0,
        rr_moved: None,
        read_ce_req: Heap::default(),
        previous_number: 0,
        previous_pathname: AString::default(),
        files: Vec::new(),
        pending_files: Heap::default(),
        cache_files: VecDeque::new(),
        re_files: VecDeque::new(),
        current_position: 0,
        logical_block_size: 0,
        volume_size: 0,
        volume_block: 0,
        primary: Vd::default(),
        joliet: Vd::default(),
        entry_sparse_offset: 0,
        entry_bytes_remaining: 0,
        entry_zisofs: Zisofs::default(),
        entry_contents: Vec::new(),
        entry_content: None,
        sconv_utf16be: None,
        utf16be_path: Vec::new(),
        utf16be_previous_path: Vec::new(),
    }))
}

fn is_null(h: &[u8], (offset, bytes): (usize, usize)) -> bool {
    h.get(offset..offset + bytes)
        .is_some_and(|f| f.iter().all(|&c| c == 0))
}

fn is_boot_record(h: &[u8]) -> bool {
    // Type of the Volume Descriptor Boot Record must be 0, and the Volume
    // Descriptor Version must be 1.
    byte(h, 0) == 0 && byte(h, 6) == 1
}

fn is_vd_set_terminator(h: &[u8]) -> bool {
    // Type of the Volume Descriptor Set Terminator must be 255, the Volume
    // Descriptor Version must be 1 and the reserved field must be 0.
    byte(h, 0) == 255 && byte(h, 6) == 1 && is_null(h, (7, 2048 - 7))
}

/// ECMA119/ISO9660 stores multi-byte integers in one of three different
/// formats: little-endian (specified in section 7.2.1 and 7.3.1), big-endian
/// (7.2.2 and 7.3.2), or both (7.2.3 and 7.3.3).
///
/// For values that follow section 7.2.3 (16-bit) or 7.3.3 (32-bit), we can
/// check that the little-endian and big-endian forms agree with each other.
/// This helps us avoid trying to decode files that are not really ISO
/// images.
fn is_valid_723_integer(p: &[u8]) -> bool {
    byte(p, 0) == byte(p, 3) && byte(p, 1) == byte(p, 2)
}

fn is_valid_733_integer(p: &[u8]) -> bool {
    byte(p, 0) == byte(p, 7)
        && byte(p, 1) == byte(p, 6)
        && byte(p, 2) == byte(p, 5)
        && byte(p, 3) == byte(p, 4)
}

fn is_root_directory_record(p: &[u8]) -> bool {
    // ECMA119/ISO9660 requires that the root directory record be _exactly_ 34
    // bytes. However, we've seen images that have root directory records up
    // to 68 bytes.
    if !(34..=68).contains(&byte(p, DR_LENGTH)) {
        return false;
    }
    // The root directory location and size must be 7.3.3 integers.
    if !is_valid_733_integer(p.get(DR_EXTENT..).unwrap_or_default())
        || !is_valid_733_integer(p.get(DR_SIZE..).unwrap_or_default())
    {
        return false;
    }
    // According to the standard, certain bits must be one or zero:
    // Bit 1: must be 1 (this is a directory)
    // Bit 2: must be 0 (not an associated file)
    // Bit 3: must be 0 (doesn't use extended attribute record)
    // Bit 7: must be 0 (final directory record for this file)
    if byte(p, DR_FLAGS) & 0x8E != 0x02 {
        return false;
    }
    // Volume sequence number must be a 7.2.3 integer.
    if !is_valid_723_integer(p.get(DR_VOLUME_SEQUENCE_NUMBER..).unwrap_or_default()) {
        return false;
    }
    // Root directory name is a single zero byte...
    byte(p, DR_NAME_LEN) == 1 && byte(p, DR_NAME) == 0
}

/// Whether the location of a Type L Path Table is available: at least
/// `SYSTEM_AREA_BLOCK + 2` and below the volume space size.
fn path_table_l_ok(location: i32, volume_block: i32) -> bool {
    location >= SYSTEM_AREA_BLOCK + 2 && location < volume_block
}

/// The same for a Type M Path Table, which may be omitted (WinISO and
/// probably other programs do) and so is allowed to be zero.
fn path_table_m_ok(location: i32, volume_block: i32) -> bool {
    !(location > 0 && location < SYSTEM_AREA_BLOCK + 2) && location < volume_block
}

fn is_svd(h: &[u8]) -> bool {
    // Type 2 means it's a SVD.
    if byte(h, PVD_TYPE) != 2 {
        return false;
    }
    // Reserved fields must be 0.
    if !is_null(h, SVD_RESERVED1) || !is_null(h, SVD_RESERVED2) || !is_null(h, SVD_RESERVED3) {
        return false;
    }
    // File structure version must be 1 for ISO9660/ECMA119.
    if byte(h, SVD_FILE_STRUCTURE_VERSION) != 1 {
        return false;
    }
    if le16(h, SVD_LOGICAL_BLOCK_SIZE) == 0 {
        return false;
    }
    let volume_block = le32(h, SVD_VOLUME_SPACE_SIZE) as i32;
    if volume_block <= SYSTEM_AREA_BLOCK + 4 {
        return false;
    }
    path_table_l_ok(le32(h, SVD_TYPE_L_PATH_TABLE) as i32, volume_block)
        && path_table_m_ok(be32(h, SVD_TYPE_M_PATH_TABLE) as i32, volume_block)
        && is_root_directory_record(h.get(SVD_ROOT_DIRECTORY_RECORD..).unwrap_or_default())
}

fn is_evd(h: &[u8]) -> bool {
    // Type of the Enhanced Volume Descriptor must be 2, its version 2 and
    // the reserved fields 0.
    if byte(h, PVD_TYPE) != 2
        || byte(h, PVD_VERSION) != 2
        || byte(h, PVD_RESERVED1) != 0
        || !is_null(h, PVD_RESERVED2)
        || !is_null(h, PVD_RESERVED3)
    {
        return false;
    }
    // Logical block size must be > 0. I've looked at Ecma 119 and can't find
    // any stronger restriction on this field.
    if le16(h, PVD_LOGICAL_BLOCK_SIZE) == 0 {
        return false;
    }
    let volume_block = le32(h, PVD_VOLUME_SPACE_SIZE) as i32;
    if volume_block <= SYSTEM_AREA_BLOCK + 4 {
        return false;
    }
    // File structure version must be 2 for ISO9660:1999.
    if byte(h, PVD_FILE_STRUCTURE_VERSION) != 2 {
        return false;
    }
    path_table_l_ok(le32(h, PVD_TYPE_1_PATH_TABLE) as i32, volume_block)
        && path_table_m_ok(be32(h, PVD_TYPE_M_PATH_TABLE) as i32, volume_block)
        && is_null(h, PVD_RESERVED4)
        && is_null(h, PVD_RESERVED5)
        && is_root_directory_record(h.get(PVD_ROOT_DIRECTORY_RECORD..).unwrap_or_default())
}

/// The days from 1970-01-01 to the given day of the proleptic Gregorian
/// calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// `time_from_tm`, which is `timegm`: fields may be out of range (a 31st of
/// a 30-day month, or a negative minute), and carry into the next. `year`
/// is `tm_year` (since 1900) and `mon` is `tm_mon` (from 0). Zero is
/// returned for the one second before the epoch, which `timegm` reports as
/// failure.
fn time_from_tm(year: i64, mon: i64, mday: i64, hour: i64, min: i64, sec: i64) -> i64 {
    let year = year + 1900 + mon.div_euclid(12);
    let days = days_from_civil(year, mon.rem_euclid(12) + 1, 1) + mday - 1;
    let t = days * 86400 + hour * 3600 + min * 60 + sec;
    if t == -1 { 0 } else { t }
}

/// The time zone offset (in 1/4-hour increments) applied to `hour` and
/// `min`, which `timegm` then normalizes.
fn apply_gmt_offset(offset: i64, hour: i64, min: i64) -> (i64, i64) {
    if offset > -48 && offset < 52 {
        (hour - offset / 4, min - (offset % 4) * 15)
    } else {
        (hour, min)
    }
}

/// The time of a 7-byte directory record date, or `None` if it is not valid.
fn isodate7(v: &[u8]) -> Option<i64> {
    let [year, month, day, hour, minute, second, gmt] = *v.first_chunk::<7>()?;
    let gmt_off = i64::from(gmt as i8);
    // ECMA-119 9.1.5 "If all seven values are zero, it shall mean that the
    // date is unspecified".
    if v.get(..7)?.iter().all(|&c| c == 0) {
        return None;
    }
    // Year can have any value. Month must be 1-12, day 1-31, hour 0-23 and
    // minute 0-59. Second must be 0-59 according to ECMA-119 9.1.5, but we
    // should probably allow for the time being in UTC, which allows up to 61
    // seconds in a minute in certain cases. Offset from GMT must be -48 to
    // +52.
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 61
        || !(-48..=52).contains(&gmt_off)
    {
        return None;
    }
    let (hour, min) = apply_gmt_offset(gmt_off, i64::from(hour), i64::from(minute));
    Some(time_from_tm(
        i64::from(year),
        i64::from(month) - 1,
        i64::from(day),
        hour,
        min,
        i64::from(second),
    ))
}

/// The time of a 17-byte (ASCII digits) date, or `None` if it is not valid.
fn isodate17(v: &[u8]) -> Option<i64> {
    let v = v.get(..17)?;
    // First 16 bytes are all ASCII digits.
    if !v.iter().take(16).all(u8::is_ascii_digit) {
        return None;
    }
    let digits = |i: usize, n: usize| {
        v.get(i..i + n)
            .unwrap_or_default()
            .iter()
            .fold(0i64, |acc, &c| acc * 10 + i64::from(c - b'0'))
    };
    let (year, month, day) = (digits(0, 4), digits(4, 2), digits(6, 2));
    let (hour, minute, second) = (digits(8, 2), digits(10, 2), digits(12, 2));
    let hundredths = digits(14, 2);
    let gmt_off = i64::from(byte(v, 16) as i8);
    if year == 0
        && month == 0
        && day == 0
        && hour == 0
        && minute == 0
        && second == 0
        && hundredths == 0
        && gmt_off == 0
    {
        return None;
    }
    // Year must be 1900-2300 (not specified in ECMA-119, but these seem like
    // reasonable limits).
    if !(1900..=2300).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 61
        || hundredths > 99
        || !(-48..=52).contains(&gmt_off)
    {
        return None;
    }
    let (hour, min) = apply_gmt_offset(gmt_off, hour, minute);
    Some(time_from_tm(year - 1900, month - 1, day, hour, min, second))
}

fn misc(msg: impl Into<Vec<u8>>) -> Error {
    Error::fatal(ARCHIVE_ERRNO_MISC, msg)
}

fn no_full_block() -> Error {
    misc("Failed to read full block when scanning ISO9660 directory list")
}

/// `parse_rockridge_NM1`.
fn parse_rockridge_nm1(file: &mut FileInfo, data: &[u8]) {
    if !file.name_continues {
        file.name.empty();
    }
    file.name_continues = false;
    // NM version 1 extension comprises:
    //   1 byte flag, value is one of:
    //     = 0: remainder is name
    //     = 1: remainder is name, next NM entry continues name
    //     = 2: "."
    //     = 4: ".."
    //     = 32: Implementation specific
    //     All other values are reserved.
    let Some((&flag, name)) = data.split_first() else {
        return;
    };
    match flag {
        0 | 1 => {
            if name.is_empty() {
                return;
            }
            file.name.ncat(name, name.len());
            file.name_continues = flag == 1;
        }
        2 => file.name.cat(b"."),
        4 => file.name.cat(b".."),
        _ => {}
    }
}

/// `parse_rockridge_TF1`.
fn parse_rockridge_tf1(file: &mut FileInfo, data: &[u8]) {
    // TF extension comprises:
    //   one byte flag
    //   create time (optional)
    //   modify time (optional)
    //   access time (optional)
    //   attribute time (optional)
    // Time format and presence of fields is controlled by flag bits.
    let Some((&flag, mut data)) = data.split_first() else {
        return;
    };
    // Use the 17-byte time format, or the 7-byte one.
    let long = flag & 0x80 != 0;
    let size = if long { 17 } else { 7 };
    let fields = [
        (1, BIRTHTIME_IS_SET),
        (2, MTIME_IS_SET),
        (4, ATIME_IS_SET),
        (8, CTIME_IS_SET),
    ];
    for (bit, set) in fields {
        if flag & bit == 0 || data.len() < size {
            continue;
        }
        if let Some(t) = if long {
            isodate17(data)
        } else {
            isodate7(data)
        } {
            file.time_is_set |= set;
            match set {
                BIRTHTIME_IS_SET => file.birthtime = t,
                MTIME_IS_SET => file.mtime = t,
                ATIME_IS_SET => file.atime = t,
                _ => file.ctime = t,
            }
        }
        data = data.get(size..).unwrap_or_default();
    }
}

/// `parse_rockridge_SL1`.
fn parse_rockridge_sl1(file: &mut FileInfo, data: &[u8]) {
    let mut separator: &[u8] = b"";

    if !file.symlink_continues || file.symlink.bytes().is_empty() {
        file.symlink.empty();
    }
    file.symlink_continues = false;

    // Defined flag values:
    //  0: This is the last SL record for this symbolic link
    //  1: this symbolic link field continues in next SL entry
    //  All other values are reserved.
    let Some((&flag, mut data)) = data.split_first() else {
        return;
    };
    match flag {
        0 => {}
        1 => file.symlink_continues = true,
        _ => return,
    }

    // SL extension body stores "components". Basically, this is a
    // complicated way of storing a POSIX path. It also interferes with using
    // symlinks for storing non-path data. <sigh>
    //
    // Each component is 2 bytes (flag and length) possibly followed by name
    // data.
    while let [flag, nlen, rest @ ..] = data {
        let nlen = usize::from(*nlen);
        file.symlink.cat(separator);
        separator = b"/";

        match flag {
            // Usual case, this is text; or the text continues in the next
            // component.
            0 | 1 => {
                if rest.len() < nlen {
                    return;
                }
                file.symlink.ncat(rest, nlen);
                if *flag == 1 {
                    separator = b"";
                }
            }
            // Current dir.
            0x02 => file.symlink.cat(b"."),
            // Parent dir.
            0x04 => file.symlink.cat(b".."),
            // Root of filesystem.
            0x08 => {
                file.symlink.cat(b"/");
                separator = b"";
            }
            // Undefined (historically "volume root").
            0x10 => {
                file.symlink.empty();
                file.symlink.cat(b"ROOT");
            }
            // Undefined (historically "hostname").
            0x20 => file.symlink.cat(b"hostname"),
            // TODO: issue a warning ?
            _ => return,
        }
        data = rest.get(nlen..).unwrap_or_default();
    }
}

/// `parse_rockridge_ZF1`.
fn parse_rockridge_zf1(file: &mut FileInfo, data: &[u8]) {
    if data.len() == 12 && data[0] == 0x70 && data[1] == 0x7a {
        // paged zlib
        file.pz = true;
        file.pz_log2_bs = u32::from(byte(data, 3));
        if !(15..=17).contains(&file.pz_log2_bs) {
            // TODO: Return an error here instead of silently disabling
            // zisofs. That requires propagating an error return through
            // parse_rockridge() and its callers.
            file.pz = false;
            return;
        }
        file.pz_uncompressed_size = u64::from(le32(data, 4));
    }
}

impl Iso9660 {
    /// The logical block size; at least 1 so that dividing by it is safe.
    fn lbs(&self) -> u64 {
        u64::try_from(self.logical_block_size).unwrap_or(1).max(1)
    }

    fn is_volume_partition(&self, h: &[u8]) -> bool {
        // Type of the Volume Partition Descriptor must be 3, the Volume
        // Descriptor Version must be 1 and the unused field 0.
        if byte(h, 0) != 3 || byte(h, 6) != 1 || byte(h, 7) != 0 {
            return false;
        }
        let location = le32(h, 72) as i32;
        if location <= SYSTEM_AREA_BLOCK || location >= self.volume_block {
            return false;
        }
        location as u32 == be32(h, 76)
    }

    fn is_joliet_svd(&mut self, h: &[u8]) -> bool {
        // Check if current sector is a kind of Supplementary Volume
        // Descriptor.
        if !is_svd(h) {
            return false;
        }

        // FIXME: do more validations according to joliet spec.

        // Check if this SVD contains joliet extension! N.B. Joliet spec says
        // p[1] == '\\', but....
        if byte(h, SVD_ESCAPE_SEQUENCES) != b'%' || byte(h, SVD_ESCAPE_SEQUENCES + 1) != b'/' {
            return false;
        }
        self.seen_joliet = match byte(h, SVD_ESCAPE_SEQUENCES + 2) {
            b'@' => 1,
            b'C' => 2,
            b'E' => 3,
            // not joliet
            _ => return false,
        };

        let logical_block_size = le16(h, SVD_LOGICAL_BLOCK_SIZE);
        let volume_block = le32(h, SVD_VOLUME_SPACE_SIZE) as i32;
        self.logical_block_size = i64::from(logical_block_size);
        self.volume_block = volume_block;
        self.volume_size =
            u64::from(logical_block_size).wrapping_mul(i64::from(volume_block) as u64);
        // Read Root Directory Record in Volume Descriptor.
        self.joliet.location = le32(h, SVD_ROOT_DIRECTORY_RECORD + DR_EXTENT) as i32;
        self.joliet.size = le32(h, SVD_ROOT_DIRECTORY_RECORD + DR_SIZE);
        true
    }

    fn is_pvd(&mut self, h: &[u8]) -> bool {
        // Type of the Primary Volume Descriptor must be 1, its version 1
        // and the reserved fields 0.
        if byte(h, PVD_TYPE) != 1
            || byte(h, PVD_VERSION) != 1
            || byte(h, PVD_RESERVED1) != 0
            || !is_null(h, PVD_RESERVED2)
        {
            return false;
        }
        // Volume space size must be encoded according to 7.3.3.
        if !is_valid_733_integer(h.get(PVD_VOLUME_SPACE_SIZE..).unwrap_or_default()) {
            return false;
        }
        let volume_block = le32(h, PVD_VOLUME_SPACE_SIZE) as i32;
        if volume_block <= SYSTEM_AREA_BLOCK + 4 || !is_null(h, PVD_RESERVED3) {
            return false;
        }
        // Volume set size, volume sequence number and logical block size
        // must be encoded according to 7.2.3, and the path table size
        // according to 7.3.3.
        let at = |off: usize| h.get(off..).unwrap_or_default();
        if !is_valid_723_integer(at(PVD_VOLUME_SET_SIZE))
            || !is_valid_723_integer(at(PVD_VOLUME_SEQUENCE_NUMBER))
            || !is_valid_723_integer(at(PVD_LOGICAL_BLOCK_SIZE))
            || !is_valid_733_integer(at(PVD_PATH_TABLE_SIZE))
        {
            return false;
        }
        // Logical block size must be > 0. I've looked at Ecma 119 and can't
        // find any stronger restriction on this field.
        let logical_block_size = le16(h, PVD_LOGICAL_BLOCK_SIZE);
        if logical_block_size == 0 {
            return false;
        }
        // File structure version must be 1 for ISO9660/ECMA119.
        if byte(h, PVD_FILE_STRUCTURE_VERSION) != 1 {
            return false;
        }
        // Although ECMA 119 requires a Type M Path Table, WinISO and
        // probably other programs omit it, so we permit a zero here.
        if !path_table_l_ok(le32(h, PVD_TYPE_1_PATH_TABLE) as i32, volume_block)
            || !path_table_m_ok(be32(h, PVD_TYPE_M_PATH_TABLE) as i32, volume_block)
        {
            return false;
        }
        // Reserved field must be 0. But accept NetBSD/FreeBSD "makefs"
        // images with 0x20 here.
        let (off, len) = PVD_RESERVED4;
        if h.get(off..off + len)
            .is_none_or(|f| f.iter().any(|&c| c != 0 && c != 0x20))
        {
            return false;
        }
        if !is_null(h, PVD_RESERVED5) {
            return false;
        }

        // XXX TODO: Check other values for sanity; reject more malformed
        // PVDs. XXX

        // Read Root Directory Record in Volume Descriptor.
        let p = h.get(PVD_ROOT_DIRECTORY_RECORD..).unwrap_or_default();
        if !is_root_directory_record(p) {
            return false;
        }

        if self.primary.location == 0 {
            self.logical_block_size = i64::from(logical_block_size);
            self.volume_block = volume_block;
            self.volume_size =
                u64::from(logical_block_size).wrapping_mul(i64::from(volume_block) as u64);
            self.primary.location = le32(p, DR_EXTENT) as i32;
            self.primary.size = le32(p, DR_SIZE);
        }
        true
    }

    /// `add_entry`: queue a record by its offset on disk. Records with the
    /// same offset keep rough order of arrival by the low 16 bits of the key
    /// (for more than 65535 entries, reordering will still occur).
    fn add_entry(&mut self, file: usize) {
        let key = self.files[file].offset << 16;
        let key = key.wrapping_add((self.pending_files.0.len() & 0xFFFF) as u64);
        self.pending_files.add(key, file);
    }

    /// `choose_volume`: reads the root directory of the volume to use.
    fn choose_volume(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let mut is_primary = true;
        let mut vd = self.primary;
        if !self.opt_support_joliet {
            self.seen_joliet = 0;
        }
        if self.seen_joliet != 0 && self.primary.location > self.joliet.location {
            // This condition is unlikely; by way of caution.
            is_primary = false;
            vd = self.joliet;
        }

        r.consume(LOGICAL_BLOCK_SIZE as i64 * i64::from(vd.location))?;
        self.current_position = (LOGICAL_BLOCK_SIZE as i64 * i64::from(vd.location)) as u64;

        let budget = r.budget;
        let Some(block) = r.read_ahead(vd.size as usize)? else {
            return Err(no_full_block());
        };

        // While reading Root Directory, flag seenJoliet must be zero to
        // avoid converting special name 0x00(Current Directory) and next
        // byte to UCS2.
        let seen_joliet = self.seen_joliet; // Save flag.
        self.seen_joliet = 0;
        let mut file =
            self.parse_file_info(budget, None, block.get(..vd.size as usize).unwrap_or(block))?;
        self.seen_joliet = seen_joliet;

        // If the iso image has both RockRidge and Joliet, we preferentially
        // use RockRidge Extensions rather than Joliet ones.
        if is_primary && self.seen_rockridge && self.seen_joliet != 0 {
            self.seen_joliet = 0;
        }

        if is_primary && !self.seen_rockridge && self.seen_joliet != 0 {
            // Switch reading data from primary to joliet.
            let vd = self.joliet;
            let skipsize =
                LOGICAL_BLOCK_SIZE as i64 * i64::from(vd.location) - self.current_position as i64;
            r.consume(skipsize)?;
            self.current_position = self.current_position.wrapping_add(skipsize as u64);

            let Some(block) = r.read_ahead(vd.size as usize)? else {
                return Err(no_full_block());
            };
            self.seen_joliet = 0;
            file =
                self.parse_file_info(budget, None, block.get(..vd.size as usize).unwrap_or(block))?;
            self.seen_joliet = seen_joliet;
        }

        // Store the root directory in the pending list.
        self.add_entry(file);
        if self.seen_rockridge {
            r.set_format(
                FORMAT_ISO9660_ROCKRIDGE,
                c"ISO9660 with Rockridge extensions",
            );
        }
        Ok(())
    }

    fn read_children(&mut self, r: &mut Reader<'_>, parent: usize) -> Result<Status, Error> {
        let a = r.base();
        // Flushing any remaining bytes from the last round, to ensure we're
        // positioned, is done by the reader before it calls us.
        let (poffset, psize) = (self.files[parent].offset, self.files[parent].size);
        if self.current_position > poffset {
            return Ok(a.warn(
                ARCHIVE_ERRNO_MISC,
                [
                    b"Ignoring out-of-order directory (".as_slice(),
                    self.files[parent].name.display(),
                    format!(") {} > {}", self.current_position as i64, poffset as i64).as_bytes(),
                ]
                .concat(),
            ));
        }
        if poffset.wrapping_add(psize) > self.volume_size {
            return Ok(a.warn(
                ARCHIVE_ERRNO_MISC,
                [
                    b"Directory is beyond end-of-media: ".as_slice(),
                    self.files[parent].name.display(),
                ]
                .concat(),
            ));
        }
        if self.current_position < poffset {
            r.consume(poffset - self.current_position)?;
            self.current_position = poffset;
        }

        let lbs = self.lbs();
        let step = usize::try_from(psize.div_ceil(lbs) * lbs).unwrap_or(usize::MAX);
        let budget = r.budget;
        budget.check_metadata(step)?;
        let Some(b) = r.read_ahead(step)? else {
            return Err(no_full_block());
        };
        self.current_position = self.current_position.wrapping_add(step as u64);
        let scanned = self.scan_directory(budget, parent, b.get(..step).unwrap_or(b));
        let _ = r.consume(step);
        scanned?;

        // Read data which recorded by RRIP "CE" extension.
        self.read_ce(r)?;
        Ok(Status::Ok)
    }

    /// Parses the directory records in the blocks of a directory.
    fn scan_directory(
        &mut self,
        budget: &crate::read::limits::Budget,
        parent: usize,
        blocks: &[u8],
    ) -> Result<(), Error> {
        let lbs = self.lbs() as usize;
        let mut multi: Option<usize> = None;
        for b in blocks.chunks_exact(lbs) {
            let mut p = 0;
            // A record must fit in the rest of the block and have a name.
            while let Some(rec) = b.get(p..)
                && rec.len() > DR_NAME
                && let Some(&len) = rec.first()
                && len != 0
                && usize::from(len) <= rec.len()
            {
                p += usize::from(len);
                // N.B.: these special directory identifiers are 8 bit
                // "values" even on a Joliet CD with UCS-2 (16bit) encoding.
                // Skip '.' and '..' entries.
                if byte(rec, DR_NAME_LEN) == 1 && byte(rec, DR_NAME) <= 1 {
                    continue;
                }
                let child = self.parse_file_info(budget, Some(parent), rec)?;
                let c = &self.files[child];
                if c.cl_offset == 0 && (c.multi_extent || multi.is_some()) {
                    let con = Content {
                        offset: c.offset,
                        size: c.size,
                    };
                    let (multi_extent, size) = (c.multi_extent, c.size);
                    let m = *multi.get_or_insert(child);
                    self.files[m].contents.push(con);
                    if m == child {
                        self.add_entry(child);
                    } else {
                        self.files[m].size = self.files[m].size.wrapping_add(size);
                        if !multi_extent {
                            multi = None;
                        }
                    }
                } else {
                    self.add_entry(child);
                }
            }
        }
        Ok(())
    }
}

impl Iso9660 {
    /// Whether `ancestor` is `file` or one of its ancestors, or any of them
    /// satisfies `f`. A parent chain that loops (a malformed image can make
    /// one by connecting "CL" and "RE" entries) is cut off after as many
    /// steps as there are records; the result is then `None`.
    fn any_ancestor(&self, from: Option<usize>, f: impl Fn(&FileInfo) -> bool) -> Option<bool> {
        let mut cur = from;
        for _ in 0..=self.files.len() {
            let Some(c) = cur else {
                return Some(false);
            };
            let file = &self.files[c];
            if f(file) {
                return Some(true);
            }
            cur = file.parent;
        }
        None
    }

    /// This routine parses a single ISO directory record, makes sense of any
    /// extensions, and stores the result in memory.
    fn parse_file_info(
        &mut self,
        budget: &crate::read::limits::Budget,
        parent: Option<usize>,
        rec: &[u8],
    ) -> Result<usize, Error> {
        budget.check_entries(
            self.files
                .len()
                .checked_add(1)
                .ok_or_else(|| misc("ISO entry count overflow"))?,
        )?;
        budget.metadata(std::mem::size_of::<FileInfo>())?;
        self.files
            .try_reserve(1)
            .map_err(|_| Error::fatal(libc::ENOMEM, "No memory for ISO entries"))?;
        let reclen = rec.len();
        let dr_len = if reclen != 0 {
            usize::from(byte(rec, DR_LENGTH))
        } else {
            0
        };
        // Sanity check that reclen is not zero and dr_len is greater than
        // reclen but at least 34.
        if reclen == 0 || reclen < dr_len || dr_len < 34 {
            return Err(misc("Invalid length of directory record"));
        }
        let mut name_len = usize::from(byte(rec, DR_NAME_LEN));
        let location = le32(rec, DR_EXTENT) as i32;
        let fsize = u64::from(le32(rec, DR_SIZE));
        // Sanity check that name_len doesn't exceed dr_len.
        if dr_len - 33 < name_len || name_len == 0 {
            return Err(misc("Invalid length of file identifier"));
        }
        // Sanity check that location doesn't exceed volume block. Don't
        // check lower limit of location; it's possibility the location has
        // negative value when file type is symbolic link or file size is
        // zero. As far as I know latest mkisofs do that.
        let lbs = self.lbs();
        if location > 0
            && (location as u64).wrapping_add(fsize.div_ceil(lbs))
                > u64::from(self.volume_block as u32)
        {
            return Err(misc("Invalid location of extent of file"));
        }
        // Sanity check that location doesn't have a negative value when the
        // file is not empty. it's too large.
        if fsize != 0 && location < 0 {
            return Err(misc("Invalid location of extent of file"));
        }

        // Sanity check that this entry does not create a cycle.
        let offset = (i64::from(location) as u64).wrapping_mul(lbs);
        if self.any_ancestor(parent, |f| f.offset == offset) != Some(false) {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Directory structure contains loop",
            ));
        }

        // Create a new file entry and copy data from the ISO dir record.
        let mut file = FileInfo {
            parent,
            offset,
            size: fsize,
            ..FileInfo::default()
        };
        if let Some(t) = isodate7(rec.get(DR_DATE..).unwrap_or_default()) {
            file.time_is_set |= MTIME_IS_SET | ATIME_IS_SET | CTIME_IS_SET;
            file.mtime = t;
            file.ctime = t;
            file.atime = t;
        }

        let p = rec.get(DR_NAME..).unwrap_or_default();
        // Rockridge extensions (if any) follow name. Compute this before
        // fidgeting the name_len below.
        let mut rr_start = DR_NAME + name_len + usize::from(name_len & 1 == 0);
        let rr_end = dr_len;

        if self.seen_joliet != 0 {
            // Joliet names are max 64 chars (128 bytes) according to spec,
            // but genisoimage/mkisofs allows recording longer Joliet names
            // which are 103 UCS2 characters(206 bytes) by their option
            // '-joliet-long'.
            name_len = name_len.min(206) & !1;

            // Trim trailing first version and dot from filename.
            //
            // Remember we were in UTF-16BE land! SEPARATOR 1 (.) and
            // SEPARATOR 2 (;) are both 16 bits big endian characters on
            // Joliet.
            //
            // TODO: sanitize filename? Joliet allows any UCS-2 char except:
            // *, /, :, ;, ? and \.
            //
            // Chop off trailing ';1' from files.
            if name_len > 4 && p.get(name_len - 4..name_len) == Some(&[0, b';', 0, b'1']) {
                name_len -= 4;
            }
            file.utf16be_name = p.get(..name_len).unwrap_or_default().to_vec();
        } else {
            // Chop off trailing ';1' from files.
            if name_len > 2 && p.get(name_len - 2..name_len) == Some(b";1") {
                name_len -= 2;
            }
            // Chop off trailing '.' from filenames.
            if name_len > 1 && byte(p, name_len - 1) == b'.' {
                name_len -= 1;
            }
            file.name.empty();
            file.name.ncat(p, name_len);
        }

        let flags = byte(rec, DR_FLAGS);
        let is_dir = flags & 0x02 != 0;
        file.mode = if is_dir {
            AE_IFDIR | 0o700
        } else {
            AE_IFREG | 0o400
        };
        file.multi_extent = flags & 0x80 != 0;
        // Use a location for the file number, which is treated as an inode
        // number to find out hardlink target. If Rockridge extensions is
        // being used, the file number will be overwritten by FILE SERIAL
        // NUMBER of RRIP "PX" extension.
        // Note: Old mkisofs did not record that FILE SERIAL NUMBER in ISO
        // images.
        // Note2: xorriso set 0 to the location of a symlink file.
        if file.size == 0 && location >= 0 {
            // If file->size is zero, its location points wrong place, and
            // so we should not use it for the file number. When the
            // location has negative value, it can be used for the file
            // number.
            file.number = -1;
            // Do not appear before any directory entries.
            file.offset = u64::MAX;
        } else {
            file.number = i64::from(location as u32);
        }

        let idx = self.files.len();
        self.files.push(file);

        // Rockridge extensions overwrite information from above.
        if self.opt_support_rockridge {
            if parent.is_none() && rr_end >= rr_start + 7 {
                // SP extension stores the suspOffset (Number of bytes to
                // skip between filename and SUSP records.) It is mandatory
                // by the SUSP standard (IEEE 1281).
                //
                // It allows SUSP to coexist with non-SUSP uses of the System
                // Use Area by placing non-SUSP data before SUSP data.
                //
                // SP extension must be in the root directory entry, disable
                // all SUSP processing if not found.
                if rec.get(rr_start..rr_start + 6) == Some(b"SP\x07\x01\xbe\xef") {
                    self.susp_offset = byte(rec, rr_start + 6);
                    self.seen_susp = true;
                    rr_start += 7;
                }
            }
            if self.seen_susp {
                let f = &mut self.files[idx];
                f.name_continues = false;
                f.symlink_continues = false;
                rr_start += usize::from(self.susp_offset);
                self.parse_rockridge(idx, rec.get(rr_start..rr_end).unwrap_or_default())?;
                // A file size of symbolic link files in ISO images made by
                // makefs is not zero and its location is the same as those
                // of next regular file. That is the same as hard like file
                // and it causes unexpected error.
                let f = &mut self.files[idx];
                if f.size > 0 && f.mode & AE_IFMT == AE_IFLNK {
                    f.size = 0;
                    f.number = -1;
                    f.offset = u64::MAX;
                }
            } else {
                // If there isn't SUSP, disable parsing rock ridge
                // extensions.
                self.opt_support_rockridge = false;
            }
        }

        self.files[idx].nlinks = 1; // Reset nlink. we'll calculate it later.
        // Tell file's parent how many children that parent has.
        if let Some(par) = parent
            && is_dir
        {
            self.files[par].subdirs += 1;
        }

        if self.seen_rockridge {
            self.connect_rockridge(idx, parent, is_dir)?;
        }

        Ok(idx)
    }

    /// The Rock Ridge checks and bookkeeping of a new record: `rr_moved`,
    /// "RE" and "CL".
    fn connect_rockridge(
        &mut self,
        idx: usize,
        parent: Option<usize>,
        is_dir: bool,
    ) -> Result<(), Error> {
        let invalid = |what: &str| misc(format!("Invalid Rockridge {what}"));
        let f = &self.files[idx];
        let parent_info = parent.map(|p| {
            let pf = &self.files[p];
            (pf.parent.is_none(), pf.rr_moved, pf.re || pf.re_descendant)
        });
        if let Some(par) = parent
            && parent_info.is_some_and(|(top, _, _)| top)
            && is_dir
            && self.rr_moved.is_none()
            && f.name.is_set()
            && matches!(f.name.c_str(), b"rr_moved" | b".rr_moved")
        {
            self.rr_moved = Some(idx);
            let f = &mut self.files[idx];
            f.rr_moved = true;
            f.rr_moved_has_re_only = true;
            f.re = false;
            self.files[par].subdirs -= 1;
        } else if f.re {
            // Sanity check: file's parent is rr_moved.
            if !parent_info.is_some_and(|(_, moved, _)| moved) {
                return Err(invalid("RE"));
            }
            // Sanity check: file does not have "CL" extension.
            if f.cl_offset != 0 {
                return Err(invalid("RE and CL"));
            }
            // Sanity check: The file type must be a directory.
            if !is_dir {
                return Err(invalid("RE"));
            }
        } else if parent_info.is_some_and(|(_, moved, _)| moved) {
            self.files[idx].rr_moved_has_re_only = false;
        } else if is_dir && parent_info.is_some_and(|(_, _, re)| re) {
            self.files[idx].re_descendant = true;
        }

        let cl_offset = self.files[idx].cl_offset;
        if cl_offset != 0 {
            let Some(par) = parent.filter(|&p| self.files[p].parent.is_some()) else {
                return Err(invalid("CL"));
            };
            // Sanity check: The file type must be a regular file.
            if is_dir {
                return Err(invalid("CL"));
            }
            self.files[par].subdirs += 1;
            // Overwrite an offset and a number of this "CL" entry to appear
            // before other dirs. "+1" to those is to make sure to appear
            // after "RE" entry which this "CL" entry should be connected
            // with.
            let moved = cl_offset.wrapping_add(1);
            self.files[idx].offset = moved;
            self.files[idx].number = moved as i64;

            // Sanity check: cl_offset does not point at its the parents or
            // itself.
            if self.any_ancestor(parent, |r| r.offset == cl_offset) != Some(false) {
                return Err(invalid("CL"));
            }
            if cl_offset == moved || self.files[par].rr_moved {
                return Err(invalid("CL"));
            }
        }
        Ok(())
    }

    fn parse_rockridge(&mut self, file: usize, rr: &[u8]) -> Result<(), Error> {
        let mut entry_seen = false;
        let mut rest = rr;
        // Enough space for another entry, whose name and length look sane.
        while let [
            c0 @ b'A'..=b'Z',
            c1 @ b'A'..=b'Z',
            len @ 4..=255,
            version,
            ..,
        ] = *rest
            && usize::from(len) <= rest.len()
        {
            let len = usize::from(len);
            let data = rest.get(4..len).unwrap_or_default();
            let f = &mut self.files[file];
            match (c0, c1) {
                (b'C', b'E') => {
                    if version == 1 && data.len() == 24 {
                        // CE extension comprises:
                        //   8 byte sector containing extension
                        //   8 byte offset w/in above sector
                        //   8 byte length of continuation
                        let location = le32(data, 0);
                        f.ce_offset = le32(data, 8);
                        f.ce_size = le32(data, 16);
                        self.register_ce(location, file)?;
                    }
                }
                (b'C', b'L') => {
                    if version == 1 && data.len() == 8 {
                        f.cl_offset = self
                            .logical_block_size
                            .unsigned_abs()
                            .wrapping_mul(u64::from(le32(data, 0)));
                        self.seen_rockridge = true;
                    }
                }
                (b'N', b'M') => {
                    if version == 1 {
                        parse_rockridge_nm1(f, data);
                        self.seen_rockridge = true;
                    }
                }
                // PD extension is padding; contents are always ignored.
                //
                // PL extension won't appear; contents are always ignored.
                (b'P', b'N') => {
                    if version == 1 && data.len() == 16 {
                        f.rdev = u64::from(le32(data, 0)) << 32 | u64::from(le32(data, 8));
                        self.seen_rockridge = true;
                    }
                }
                (b'P', b'X') => {
                    // PX extension comprises:
                    //   8 bytes for mode,
                    //   8 bytes for nlinks,
                    //   8 bytes for uid,
                    //   8 bytes for gid,
                    //   8 bytes for inode.
                    if version == 1 {
                        if data.len() >= 8 {
                            f.mode = le32(data, 0) as Mode;
                        }
                        if data.len() >= 16 {
                            f.nlinks = le32(data, 8) as i32;
                        }
                        if data.len() >= 24 {
                            f.uid = le32(data, 16);
                        }
                        if data.len() >= 32 {
                            f.gid = le32(data, 24);
                        }
                        if data.len() >= 40 {
                            f.number = i64::from(le32(data, 32));
                        }
                        self.seen_rockridge = true;
                    }
                }
                (b'R', b'E') if version == 1 => {
                    f.re = true;
                    self.seen_rockridge = true;
                }
                // RR extension comprises one byte flag value. This extension
                // is obsolete, so contents are always ignored.
                (b'S', b'L') => {
                    if version == 1 {
                        parse_rockridge_sl1(f, data);
                        self.seen_rockridge = true;
                    }
                }
                (b'S', b'T') if data.is_empty() && version == 1 => {
                    // ST extension marks end of this block of SUSP entries.
                    //
                    // It allows SUSP to coexist with non-SUSP uses of the
                    // System Use Area by placing non-SUSP data after SUSP
                    // data.
                    self.seen_susp = false;
                    self.seen_rockridge = false;
                    return Ok(());
                }
                (b'T', b'F') if version == 1 => {
                    parse_rockridge_tf1(f, data);
                    self.seen_rockridge = true;
                }
                (b'Z', b'F') if version == 1 => parse_rockridge_zf1(f, data),
                _ => {}
            }
            rest = rest.get(len..).unwrap_or_default();
            entry_seen = true;
        }

        if entry_seen {
            Ok(())
        } else {
            Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Tried to parse Rockridge extensions, but none found",
            ))
        }
    }

    fn register_ce(&mut self, location: u32, file: usize) -> Result<(), Error> {
        let f = &self.files[file];
        let tail = u64::from(f.ce_offset) + u64::from(f.ce_size);
        let offset = u64::from(location).checked_mul(self.lbs());
        let ce_end = offset.and_then(|o| o.checked_add(tail));
        let (Some(offset), Some(ce_end)) = (offset, ce_end) else {
            return Err(invalid_ce());
        };
        if (f.mode & AE_IFMT == AE_IFREG && offset >= f.offset)
            || offset < self.current_position
            || tail > self.lbs()
            || ce_end > self.volume_size
        {
            return Err(invalid_ce());
        }
        self.read_ce_req.add(offset, file);
        Ok(())
    }

    /// `read_CE`: reads the data which RRIP "CE" extensions point to.
    fn read_ce(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let step = self.lbs() as usize;
        while self
            .read_ce_req
            .first()
            .is_some_and(|(offset, _)| offset == self.current_position)
        {
            let Some(b) = r.read_ahead(step)? else {
                return Err(no_full_block());
            };
            let parsed = self.parse_ce_block(b);
            parsed?;
            // NOTE: Do not move this consume's code to front of the loop in
            // parse_ce_block. Registration of nested CE extension might
            // cause error because of current position.
            let _ = r.consume(step);
            self.current_position = self.current_position.wrapping_add(step as u64);
        }
        Ok(())
    }

    /// Parses the continuation areas, in a block read at the current
    /// position, that were asked for.
    fn parse_ce_block(&mut self, b: &[u8]) -> Result<(), Error> {
        let step = b.len().min(self.lbs() as usize);
        while let Some((offset, file)) = self.read_ce_req.first()
            && offset == self.current_position
        {
            let f = &mut self.files[file];
            if u64::from(f.ce_offset.wrapping_add(f.ce_size)) > step as u64 {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Malformed CE information",
                ));
            }
            let ce_start = offset.wrapping_add(u64::from(f.ce_offset));
            let ce_end = ce_start.wrapping_add(u64::from(f.ce_size));
            if ce_start < f.ce_processed_end {
                return Err(invalid_ce());
            }
            let start = f.ce_offset as usize;
            let area = b.get(start..start + f.ce_size as usize).unwrap_or_default();
            f.ce_processed_end = ce_end;
            self.read_ce_req.pop();
            self.parse_rockridge(file, area)?;
        }
        Ok(())
    }
}

fn invalid_ce() -> Error {
    misc("Invalid parameter in SUSP \"CE\" extension")
}

impl Iso9660 {
    /// `rede_add_entry`: queues `file` on its nearest "RE" ancestor, and
    /// fails if it has none.
    ///
    /// A malformed image can chain "CL"/"RE" reparenting so that the parent
    /// pointers form a cycle in which no node carries the "re" flag. A
    /// second pointer advances at half speed (Floyd's cycle detection) so
    /// such a loop is reported as a malformed archive instead of spinning
    /// forever.
    fn rede_add_entry(&mut self, file: usize) -> bool {
        let mut re = self.files[file].parent;
        let mut slow = re;
        let mut slow_turn = false;
        while let Some(c) = re
            && !self.files[c].re
        {
            re = self.files[c].parent;
            if slow_turn {
                slow = slow.and_then(|s| self.files[s].parent);
                if re == slow {
                    return false; // Cyclic parent chain.
                }
            }
            slow_turn = !slow_turn;
        }
        let Some(re) = re else {
            return false;
        };
        self.files[re].rede_files.push_back(file);
        true
    }

    /// Moves an "RE" directory that a "CL" file points at to the "CL"
    /// file's place. Returns the file to go on with, or `None` if the
    /// directory is to be exposed later, with its ancestor.
    fn connect_cl(&mut self, mut file: usize) -> Result<Option<usize>, Error> {
        let fatal_rr = |iso: &Iso9660, cl_offset: u64| {
            misc(format!(
                "Failed to connect 'CL' pointer to 'RE' rr_moved pointer of \
                 Rockridge extensions: current position = {}, CL offset = {}",
                iso.current_position as i64, cl_offset as i64
            ))
        };
        let cl_offset = self.files[file].cl_offset;
        // Find "RE" dir for the current file, which has "CL" flag.
        let mut first_re = None;
        loop {
            let re = self.re_files.pop_front();
            if re == first_re {
                break;
            }
            let Some(re) = re else {
                break;
            };
            if first_re.is_none() {
                first_re = Some(re);
            }
            if self.files[re].offset != cl_offset {
                self.re_files.push_back(re);
                continue;
            }
            if let Some(p) = self.files[re].parent {
                self.files[p].subdirs -= 1;
            }
            let parent = self.files[file].parent;
            self.files[re].parent = parent;
            self.files[re].re = false;
            if parent.is_some_and(|p| self.files[p].re_descendant) {
                self.files[re].re_descendant = true;
                if !self.rede_add_entry(re) {
                    return Err(fatal_rr(self, cl_offset));
                }
                // Move a list of descendants to a new ancestor.
                while let Some(d) = self.files[re].rede_files.pop_front() {
                    if !self.rede_add_entry(d) {
                        return Err(fatal_rr(self, cl_offset));
                    }
                }
                // Do not expose this at this time because we have not gotten
                // its full-path name yet.
                return Ok(None);
            }
            // Replace the current file with "RE" dir, and expose its
            // descendant.
            file = re;
            while let Some(d) = self.files[file].rede_files.pop_front() {
                self.cache_files.push_back(d);
            }
            break;
        }
        Ok(Some(file))
    }

    /// `next_cache_entry`: the next entry to return. Records with the same
    /// file number (hard links) are returned together, and empty files after
    /// them.
    fn next_cache_entry(&mut self, r: &mut Reader<'_>) -> Result<Pull, Error> {
        if let Some(file) = self.cache_files.pop_front() {
            return Ok(Pull::File(file));
        }

        let mut file;
        loop {
            let Some(next) = self.pending_files.pop() else {
                // If directory entries all which are descendant of rr_moved
                // are still remaining, expose their.
                if !self.re_files.is_empty()
                    && let Some(moved) = self.rr_moved
                    && self.files[moved].rr_moved_has_re_only
                {
                    // Expose "rr_moved" entry.
                    self.cache_files.push_back(moved);
                }
                while let Some(re) = self.re_files.pop_front() {
                    // Expose its descendant dirs.
                    while let Some(d) = self.files[re].rede_files.pop_front() {
                        self.cache_files.push_back(d);
                    }
                }
                return Ok(match self.cache_files.pop_front() {
                    Some(file) => Pull::File(file),
                    None => Pull::Done(Status::Eof),
                });
            };
            file = next;

            if self.files[file].cl_offset != 0 {
                match self.connect_cl(file)? {
                    Some(f) => file = f,
                    None => continue,
                }
            } else if self.files[file].mode & AE_IFMT == AE_IFDIR {
                // Read file entries in this dir.
                let status = self.read_children(r, file)?;
                if status != Status::Ok {
                    return Ok(Pull::Done(status));
                }

                // Handle a special dir of Rockridge extensions, "rr_moved".
                let f = &self.files[file];
                if f.rr_moved {
                    // If this has only the subdirectories which have "RE"
                    // flags, do not expose at this time. Otherwise expose
                    // "rr_moved" entry.
                    if f.rr_moved_has_re_only {
                        continue;
                    }
                } else if f.re {
                    // Do not expose this at this time because we have not
                    // gotten its full-path name yet.
                    self.re_files.push_back(file);
                    continue;
                } else if f.re_descendant && self.rede_add_entry(file) {
                    // If the top level "RE" entry of this entry is not
                    // exposed, we, accordingly, should not expose this entry
                    // at this time because we cannot make its proper
                    // full-path name. Otherwise we can expose this entry
                    // because it seems its top level "RE" has already been
                    // exposed.
                    continue;
                }
            }
            break;
        }

        let number = self.files[file].number;
        if self.files[file].mode & AE_IFMT != AE_IFREG || number == -1 {
            return Ok(Pull::File(file));
        }

        let mut count = 0;
        self.cache_files.clear();
        let mut empty_files = Vec::new();
        // Collect files which has the same file serial number. Peek
        // pending_files so that file which number is different is not put
        // back.
        while let Some((_, head)) = self.pending_files.first()
            && (self.files[head].number == -1 || self.files[head].number == number)
        {
            if self.files[file].number == -1 {
                // This file has the same offset but it's wrong offset which
                // empty files and symlink files have.
                // NOTE: This wrong offset was recorded by old mkisofs
                // utility. If ISO images is created by latest mkisofs, this
                // does not happen.
                empty_files.push(file);
            } else {
                count += 1;
                self.cache_files.push_back(file);
            }
            let Some(next) = self.pending_files.pop() else {
                break;
            };
            file = next;
        }

        if count == 0 {
            return Ok(Pull::File(file));
        }
        if self.files[file].number == -1 {
            empty_files.push(file);
        } else {
            count += 1;
            self.cache_files.push_back(file);
        }

        if count > 1 {
            // The count is the same as number of hardlink, so much so that
            // each nlinks of files in cache_file is overwritten by value of
            // the count.
            for &f in &self.cache_files {
                self.files[f].nlinks = count;
            }
        }
        // If there are empty files, that files are added to the tail of the
        // cache_files.
        self.cache_files.extend(empty_files);
        Ok(match self.cache_files.pop_front() {
            Some(file) => Pull::File(file),
            None => Pull::Done(Status::Eof),
        })
    }

    fn next_entry_seek(&mut self, r: &mut Reader<'_>) -> Result<Pull, Error> {
        let file = match self.next_cache_entry(r)? {
            Pull::File(file) => file,
            done @ Pull::Done(_) => return Ok(done),
        };

        // Don't waste time seeking for zero-length bodies.
        if self.files[file].size == 0 {
            self.files[file].offset = self.current_position;
        }

        // Seek forward to the start of the entry. (Flushing any remaining
        // bytes from the last round is the reader's doing.)
        let offset = self.files[file].offset;
        if self.current_position < offset {
            r.consume(offset - self.current_position)?;
            self.current_position = offset;
        }

        // We found body of file; handle it now.
        Ok(Pull::File(file))
    }

    fn build_pathname(&self, file: usize) -> Option<Vec<u8>> {
        // Plain ISO9660 only allows 8 dir levels; if we get to 1000, then
        // something is very, very wrong.
        let mut chain = vec![file];
        while let Some(parent) = self.files[chain[chain.len() - 1]].parent
            && !self.files[parent].name.bytes().is_empty()
        {
            if chain.len() > 1000 {
                return None;
            }
            chain.push(parent);
        }
        let mut path = Vec::new();
        for (i, &c) in chain.iter().rev().enumerate() {
            if i > 0 {
                path.push(b'/');
            }
            match self.files[c].name.bytes() {
                [] => path.push(b'.'),
                name => path.extend_from_slice(name),
            }
        }
        Some(path)
    }

    /// Builds the full pathname of `file` in `utf16be_path`; false if it is
    /// too long.
    ///
    /// Upstream recurses with no depth limit, and a parent chain that loops
    /// (see `rede_add_entry`) overflows its stack; here the chain is cut off
    /// at the length where the path could not fit.
    fn build_pathname_utf16be(&mut self, file: usize) -> bool {
        let mut chain = vec![file];
        while let Some(parent) = self.files[chain[chain.len() - 1]].parent
            && !self.files[parent].utf16be_name.is_empty()
        {
            if chain.len() > UTF16_NAME_MAX {
                return false;
            }
            chain.push(parent);
        }
        let path = &mut self.utf16be_path;
        for (i, &c) in chain.iter().rev().enumerate() {
            if i > 0 {
                if path.len() + 2 > UTF16_NAME_MAX {
                    return false; // Path is too long!
                }
                path.extend_from_slice(&[0, b'/']);
            }
            match self.files[c].utf16be_name.as_slice() {
                [] if path.len() + 2 > UTF16_NAME_MAX => return false,
                [] => path.extend_from_slice(&[0, b'.']),
                name if path.len() + name.len() > UTF16_NAME_MAX => return false,
                name => path.extend_from_slice(name),
            }
        }
        true
    }
}

impl Iso9660 {
    /// `zisofs_read_data`.
    fn zisofs_read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        let later = r.consume_later();
        let p = match r.read_ahead(1) {
            Ok(Some(p)) => p,
            _ => {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Truncated zisofs file body",
                ));
            }
        };
        let z = &mut self.entry_zisofs;
        let bytes_read = p
            .len()
            .min(usize::try_from(self.entry_bytes_remaining).unwrap_or(0));
        let p = p.get(..bytes_read).unwrap_or(p);
        // What is left of `p`, and how much of it has been taken.
        let mut avail = bytes_read;
        let mut uncompressed_size = 0;
        let format_error = |msg: &str| Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, msg);

        'next_data: {
            if !z.initialized {
                // The block pointers: one for each block, and one more for
                // the end of the last.
                let ceil = (z.pz_uncompressed_size + (1u64 << z.pz_log2_bs) - 1) >> z.pz_log2_bs;
                z.block_pointers_size = usize::try_from((ceil + 1) * 4).unwrap_or(usize::MAX);

                // Allocate uncompressed data buffer.
                z.uncompressed_buffer.resize(1usize << z.pz_log2_bs, 0);

                // Read the file header, and check the magic code of zisofs.
                if z.header_avail < z.header.len() {
                    let xsize = (z.header.len() - z.header_avail).min(avail);
                    let taken = p.get(bytes_read - avail..bytes_read - avail + xsize);
                    let to = z.header.get_mut(z.header_avail..z.header_avail + xsize);
                    if let (Some(from), Some(to)) = (taken, to) {
                        to.copy_from_slice(from);
                    }
                    z.header_avail += xsize;
                    avail -= xsize;
                }
                if !z.header_passed && z.header_avail == z.header.len() {
                    if z.header[..8] != ZISOFS_MAGIC
                        || u64::from(le32(&z.header, 8)) != z.pz_uncompressed_size
                        || z.header[12] != 4
                        || u32::from(z.header[13]) != z.pz_log2_bs
                    {
                        return Err(format_error("Illegal zisofs file body"));
                    }
                    z.header_passed = true;
                }
                // Read block pointers.
                if z.header_passed && z.block_pointers.len() < z.block_pointers_size {
                    let xsize = (z.block_pointers_size - z.block_pointers.len()).min(avail);
                    let from = bytes_read - avail;
                    z.block_pointers
                        .extend_from_slice(p.get(from..from + xsize).unwrap_or_default());
                    avail -= xsize;
                    if z.block_pointers.len() == z.block_pointers_size {
                        // We've got all block pointers and initialize
                        // related variables.
                        z.block_off = 0;
                        z.block_avail = 0;
                        // Complete a initialization.
                        z.initialized = true;
                    }
                }

                if !z.initialized {
                    break 'next_data; // We need more data.
                }
            }

            // Get block offsets from block pointers.
            if z.block_avail == 0 {
                if z.block_off + 4 >= z.block_pointers_size {
                    // There isn't a pair of offsets.
                    return Err(format_error("Illegal zisofs block pointers"));
                }
                let bst = le32(&z.block_pointers, z.block_off);
                if u64::from(bst) != u64::from(z.pz_offset) + (bytes_read - avail) as u64 {
                    // TODO: Should we seek offset of current file by bst ?
                    return Err(format_error("Illegal zisofs block pointers(cannot seek)"));
                }
                let bed = le32(&z.block_pointers, z.block_off + 4);
                if bed < bst {
                    return Err(format_error("Illegal zisofs block pointers"));
                }
                z.block_avail = bed - bst;
                z.block_off += 4;

                // Initialize compression library for new block.
                match &mut z.stream {
                    Some(stream) => stream.reset(DataFormat::Zlib),
                    None => z.stream = Some(InflateState::new_boxed(DataFormat::Zlib)),
                }
            }

            // Make uncompressed data.
            if z.block_avail == 0 {
                z.uncompressed_buffer.fill(0);
                uncompressed_size = z.uncompressed_buffer.len();
            } else {
                let from = bytes_read - avail;
                let n = avail.min(z.block_avail as usize);
                let input = p.get(from..from + n).unwrap_or_default();
                let Some(stream) = z.stream.as_mut() else {
                    return Err(misc("Can't initialize zisofs decompression"));
                };
                let res = mz_inflate(stream, input, &mut z.uncompressed_buffer, MZFlush::None);
                let failed = |code: i32| misc(format!("zisofs decompression failed ({code})"));
                match res.status {
                    // Decompressor made some progress, or found the end of
                    // the stream.
                    Ok(MZStatus::Ok | MZStatus::StreamEnd) => {}
                    Ok(MZStatus::NeedDict) => return Err(failed(2)),
                    Err(e) => return Err(failed(e as i32)),
                }
                if res.bytes_consumed == 0 && res.bytes_written == 0 {
                    // The stream has ended with block data left over;
                    // upstream goes on returning empty blocks forever.
                    return Err(failed(-5));
                }
                uncompressed_size = res.bytes_written;
                avail -= res.bytes_consumed;
                z.block_avail -= res.bytes_consumed as u32;
            }
        }

        r.decoded(uncompressed_size)?;
        // next_data:
        let consumed = bytes_read - avail;
        let offset = self.entry_sparse_offset;
        self.entry_sparse_offset += uncompressed_size as i64;
        self.entry_bytes_remaining -= consumed as i64;
        self.current_position += consumed as u64;
        z.pz_offset = z.pz_offset.wrapping_add(consumed as u32);
        later.consume(consumed);

        Ok(Data::Block {
            data: z
                .uncompressed_buffer
                .get(..uncompressed_size)
                .unwrap_or_default(),
            offset,
        })
    }
}

impl Format for Iso9660 {
    fn name(&self) -> &'static str {
        "iso9660"
    }

    fn bid(&mut self, r: &mut Reader<'_>, best_bid: c_int) -> Result<c_int, Error> {
        // If there's already a better bid than we can ever make, don't
        // bother testing.
        if best_bid > 48 {
            return Ok(-1);
        }

        // Skip the first 32k (reserved area) and get the first 8 sectors of
        // the volume descriptor table. Of course, if the I/O layer gives us
        // more, we'll take it.
        let Ok(Some(h)) = r.read_ahead(RESERVED_AREA + 8 * LOGICAL_BLOCK_SIZE) else {
            return Ok(-1);
        };

        // Skip the reserved area, and check each volume descriptor.
        let mut h = h.get(RESERVED_AREA..).unwrap_or_default();
        let mut seen_terminator = false;
        while h.len() > LOGICAL_BLOCK_SIZE {
            // Do not handle undefined Volume Descriptor Type.
            if (4..=254).contains(&h[0]) {
                return Ok(0);
            }
            // Standard Identifier must be "CD001".
            if h.get(1..6) != Some(b"CD001") {
                return Ok(0);
            }
            if !(self.is_pvd(h)
                || (self.joliet.location == 0 && self.is_joliet_svd(h))
                || is_boot_record(h)
                || is_evd(h)
                || is_svd(h)
                || self.is_volume_partition(h))
            {
                if !is_vd_set_terminator(h) {
                    return Ok(0);
                }
                seen_terminator = true;
                break;
            }
            h = h.get(LOGICAL_BLOCK_SIZE..).unwrap_or_default();
        }
        // ISO 9660 format must have Primary Volume Descriptor and Volume
        // Descriptor Set Terminator.
        if seen_terminator && self.primary.location > 16 {
            return Ok(48);
        }

        // We didn't find a valid PVD; return a bid of zero.
        Ok(0)
    }

    fn options(
        &mut self,
        _a: &Base,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<Result<Status, Error>> {
        Some(Ok(match key {
            b"joliet" => {
                self.opt_support_joliet =
                    !matches!(value, None | Some(b"off" | b"ignore" | b"disable" | b"0"));
                Status::Ok
            }
            b"rockridge" | b"Rockridge" => {
                self.opt_support_rockridge = value.is_some();
                Status::Ok
            }
            // The "warn" return is just to inform the options supervisor
            // that we didn't handle it. It will generate a suitable error if
            // no one used this option.
            _ => Status::Warn,
        }))
    }

    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        let a = r.base();
        if a.format.get() == 0 {
            a.set_format(FORMAT_ISO9660, c"ISO9660");
        }

        if self.current_position == 0 {
            self.choose_volume(r)?;
        }

        // Get the next entry that appears after the current offset.
        let file = match self.next_entry_seek(r)? {
            Pull::File(file) => file,
            Pull::Done(status) => return Ok(status),
        };

        let mut rd_r = Status::Ok;
        if self.seen_joliet != 0 {
            // Convert UTF-16BE of a filename to local locale MBS and store
            // the result into a filename field.
            if self.sconv_utf16be.is_none() {
                let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
                self.sconv_utf16be = Some(
                    conversion_from_charset(Some(&mut *cache), b"UTF-16BE", true)
                        .map_err(|e| Error::fatal(e.errno, e.message))?,
                );
            }
            self.utf16be_path.clear();
            if !self.build_pathname_utf16be(file) {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Pathname is too long",
                ));
            }
            let sconv = self.sconv_utf16be.as_deref();
            if entry.copy_pathname_l(&self.utf16be_path, sconv).is_err() {
                rd_r = a.warn(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    [
                        b"Pathname cannot be converted from ".as_slice(),
                        conversion_charset_name(sconv),
                        b" to current locale",
                    ]
                    .concat(),
                );
            }
        } else {
            let Some(path) = self.build_pathname(file) else {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Pathname is too long",
                ));
            };
            entry.set_pathname(&path);
            self.pathname = AString::new(path);
        }

        let f = &self.files[file];
        self.entry_bytes_remaining = f.size as i64;
        // Offset for sparse-file-aware clients.
        self.entry_sparse_offset = 0;

        if f.offset.wrapping_add(f.size) > self.volume_size {
            self.entry_bytes_remaining = 0;
            return Ok(a.warn(
                ARCHIVE_ERRNO_MISC,
                [
                    b"File is beyond end-of-media: ".as_slice(),
                    entry.pathname().map_or(b"(null)", |p| p.to_bytes()),
                ]
                .concat(),
            ));
        }

        // Set up the entry structure with information about this entry.
        entry.set_mode(f.mode);
        entry.set_uid(i64::from(f.uid));
        entry.set_gid(i64::from(f.gid));
        entry.set_nlink(f.nlinks as u32);
        if f.time_is_set & BIRTHTIME_IS_SET != 0 {
            entry.set_birthtime(f.birthtime, 0);
        } else {
            entry.unset_birthtime();
        }
        if f.time_is_set & MTIME_IS_SET != 0 {
            entry.set_mtime(f.mtime, 0);
        } else {
            entry.unset_mtime();
        }
        if f.time_is_set & CTIME_IS_SET != 0 {
            entry.set_ctime(f.ctime, 0);
        } else {
            entry.unset_ctime();
        }
        if f.time_is_set & ATIME_IS_SET != 0 {
            entry.set_atime(f.atime, 0);
        } else {
            entry.unset_atime();
        }
        // N.B.: Rock Ridge supports 64-bit device numbers.
        entry.set_rdev(f.rdev as Dev);
        entry.set_size(self.entry_bytes_remaining);
        if f.symlink.is_set() {
            entry.set_symlink(f.symlink.c_str());
        }

        // Note: If the input isn't seekable, we can't rewind to return the
        // same body again, so if the next entry refers to the same data, we
        // have to return it as a hardlink to the original entry.
        if f.number != -1 && f.number == self.previous_number {
            if self.seen_joliet != 0 {
                let sconv = self.sconv_utf16be.as_deref();
                if entry
                    .copy_hardlink_l(&self.utf16be_previous_path, sconv)
                    .is_err()
                {
                    rd_r = a.warn(
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        [
                            b"Linkname cannot be converted from ".as_slice(),
                            conversion_charset_name(sconv),
                            b" to current locale",
                        ]
                        .concat(),
                    );
                }
            } else {
                // Nothing returned yet: a NULL target, which sets nothing.
                if self.previous_pathname.is_set() {
                    entry.set_hardlink(self.previous_pathname.c_str());
                }
            }
            entry.unset_size();
            self.entry_bytes_remaining = 0;
            return Ok(rd_r);
        }

        if f.mode & AE_IFMT != AE_IFDIR && f.offset < self.current_position {
            match r.seek(f.offset as i64, Whence::Set) {
                Ok(pos) if pos as u64 == f.offset => self.current_position = pos as u64,
                _ => {
                    // We can't seek backwards to extract it, so issue a
                    // warning. Note that this can only happen if this entry
                    // was added to the heap after we passed this offset,
                    // that is, only if the directory mentioning this entry
                    // is later than the body of the entry. Such layouts are
                    // very unusual; most ISO9660 writers lay out and record
                    // all directory information first, then store all file
                    // bodies.
                    self.entry_bytes_remaining = 0;
                    return Ok(a.warn(
                        ARCHIVE_ERRNO_MISC,
                        [
                            format!("Ignoring out-of-order file @{:x} (", f.number).as_bytes(),
                            self.pathname.display(),
                            format!(") {} < {}", f.offset as i64, self.current_position as i64)
                                .as_bytes(),
                        ]
                        .concat(),
                    ));
                }
            }
        }

        // Initialize zisofs variables.
        let z = &mut self.entry_zisofs;
        z.pz = f.pz;
        if f.pz {
            z.initialized = false;
            z.pz_log2_bs = f.pz_log2_bs;
            z.pz_uncompressed_size = f.pz_uncompressed_size;
            z.pz_offset = 0;
            z.header_avail = 0;
            z.header_passed = false;
            z.block_pointers.clear();
            entry.set_size(f.pz_uncompressed_size as i64);
        }

        self.previous_number = f.number;
        if self.seen_joliet != 0 {
            self.utf16be_previous_path.clone_from(&self.utf16be_path);
        } else {
            self.previous_pathname = AString::new(self.pathname.c_str().to_vec());
        }

        // Reset entry_bytes_remaining if the file is multi extent.
        self.entry_contents.clone_from(&f.contents);
        self.entry_content = (!f.contents.is_empty()).then_some(0);
        if let Some(c) = f.contents.first() {
            self.entry_bytes_remaining = c.size as i64;
        }

        if entry.filetype() == AE_IFDIR {
            // Overwrite nlinks by proper link number which is calculated
            // from number of sub directories.
            entry.set_nlink((2 + f.subdirs) as u32);
            // Directory data has been read completely.
            self.entry_bytes_remaining = 0;
        }

        Ok(rd_r)
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        // Any bytes left unconsumed from the last block are consumed by the
        // reader before this call.
        if self.entry_bytes_remaining <= 0 {
            // On to the next extent, if there is one.
            self.entry_content = self
                .entry_content
                .map(|i| i + 1)
                .filter(|&i| i < self.entry_contents.len());
            let Some(content) = self.entry_content.and_then(|i| self.entry_contents.get(i)) else {
                return Ok(Data::Eof {
                    offset: self.entry_sparse_offset,
                });
            };
            let content = *content;
            // Seek forward to the start of the entry.
            if self.current_position < content.offset {
                r.consume(content.offset - self.current_position)?;
                self.current_position = content.offset;
            }
            if content.offset < self.current_position {
                let _ = r.warn(
                    ARCHIVE_ERRNO_MISC,
                    [
                        b"Ignoring out-of-order file (".as_slice(),
                        self.pathname.display(),
                        format!(
                            ") {} < {}",
                            content.offset as i64, self.current_position as i64
                        )
                        .as_bytes(),
                    ]
                    .concat(),
                );
                return Ok(Data::Warn {
                    offset: self.entry_sparse_offset,
                });
            }
            self.entry_bytes_remaining = content.size as i64;
        }
        if self.entry_zisofs.pz {
            return self.zisofs_read_data(r);
        }

        let later = r.consume_later();
        let Some(buff) = r.read_ahead(1)? else {
            return Err(misc("Truncated input file"));
        };
        let n = buff
            .len()
            .min(usize::try_from(self.entry_bytes_remaining).unwrap_or(0));
        let offset = self.entry_sparse_offset;
        self.entry_sparse_offset += n as i64;
        self.entry_bytes_remaining -= n as i64;
        self.current_position += n as u64;
        later.consume(n);
        Ok(Data::Block {
            data: buff.get(..n).unwrap_or_default(),
            offset,
        })
    }

    fn read_data_skip(&mut self, _r: &mut Reader<'_>) -> Result<Status, Error> {
        // Because read_next_header always does an explicit skip to the next
        // entry, we don't need to do anything here.
        Ok(Status::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_returns_the_smallest_key_and_keeps_upstreams_order_for_ties() {
        let mut h = Heap::default();
        for (i, key) in [5u64, 1, 5, 3, 1, 5, 2].into_iter().enumerate() {
            h.add(key, i);
        }
        let order: Vec<_> = std::iter::from_fn(|| h.pop()).collect();
        // Upstream's sift order for these keys, which BinaryHeap would not
        // give for the equal ones.
        assert_eq!(order, [1, 4, 6, 3, 0, 5, 2]);
    }

    #[test]
    fn dates() {
        // 2005-11-07 12:00:00 +0 (7-byte form, years since 1900).
        assert_eq!(isodate7(&[105, 11, 7, 12, 0, 0, 0]), Some(1131364800));
        // The offset is in quarter hours east of UTC.
        assert_eq!(
            isodate7(&[105, 11, 7, 12, 0, 0, 4]),
            Some(1131364800 - 3600)
        );
        assert_eq!(isodate7(&[0; 7]), None);
        assert_eq!(isodate7(&[105, 13, 7, 12, 0, 0, 0]), None);
        assert_eq!(isodate17(b"2005110712000000\0"), Some(1131364800));
        assert_eq!(isodate17(b"0000000000000000\0"), None);
        assert_eq!(isodate17(b"2005110712000x00\0"), None);
        // The second before the epoch is what timegm reports failure with.
        assert_eq!(time_from_tm(69, 11, 31, 23, 59, 59), 0);
        // A 31st of a 30-day month carries into the next.
        assert_eq!(
            time_from_tm(100, 3, 31, 0, 0, 0),
            time_from_tm(100, 4, 1, 0, 0, 0)
        );
    }

    #[test]
    fn rock_ridge_names_and_links() {
        let mut f = FileInfo::default();
        parse_rockridge_nm1(&mut f, b"\x01ab");
        parse_rockridge_nm1(&mut f, b"\x00cd");
        assert_eq!(f.name.bytes(), b"abcd");
        parse_rockridge_nm1(&mut f, b"\x04");
        assert_eq!(f.name.bytes(), b"..");

        // The root, "usr", and "a" that continues the text.
        parse_rockridge_sl1(&mut f, b"\x00\x08\x00\x00\x03usr\x01\x01a");
        assert_eq!(f.symlink.bytes(), b"/usr/a");
        assert!(!f.symlink_continues);
        // A record that only has the flag byte leaves no target at all.
        let mut g = FileInfo::default();
        parse_rockridge_sl1(&mut g, b"\x00");
        assert!(!g.symlink.is_set());
    }

    #[test]
    fn emptied_strings_keep_their_bytes_as_c_strings() {
        let mut f = FileInfo::default();
        parse_rockridge_sl1(&mut f, b"\x00\x00\x01X");
        // A second SL record starts over with a "ROOT" component but its
        // length-0 text leaves the old bytes beyond the new length.
        parse_rockridge_sl1(&mut f, b"\x00\x10\x00");
        assert_eq!(f.symlink.bytes(), b"ROOT");
        let mut n = AString::default();
        n.cat(b"RR_MOVED");
        n.empty();
        assert_eq!((n.bytes(), n.c_str()), (&b""[..], &b"RR_MOVED"[..]));
    }

    #[test]
    fn rock_ridge_times_and_zisofs() {
        let mut f = FileInfo::default();
        // Modify and attribute-change times in the 7-byte form.
        let mut tf = vec![2 | 8];
        tf.extend_from_slice(&[105, 11, 7, 12, 0, 0, 0]);
        tf.extend_from_slice(&[105, 11, 8, 12, 0, 0, 0]);
        parse_rockridge_tf1(&mut f, &tf);
        assert_eq!(f.time_is_set, MTIME_IS_SET | CTIME_IS_SET);
        assert_eq!((f.mtime, f.ctime), (1131364800, 1131364800 + 86400));

        let zf = [0x70, 0x7a, b'Z', 15, 0x10, 0, 0, 0, 0, 0, 0, 0];
        parse_rockridge_zf1(&mut f, &zf);
        assert!(f.pz);
        assert_eq!((f.pz_log2_bs, f.pz_uncompressed_size), (15, 16));
        // A block size out of range turns zisofs off.
        let bad = [0x70, 0x7a, b'Z', 14, 0x10, 0, 0, 0, 0, 0, 0, 0];
        parse_rockridge_zf1(&mut f, &bad);
        assert!(!f.pz);
    }
}
