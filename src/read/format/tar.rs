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

// Ported from libarchive/archive_read_support_format_tar.c.

//! The tar formats: v7, ustar, GNU tar, star and pax interchange, with GNU
//! long names and sparse files, Solaris ACLs and AppleDouble metadata.

mod pax;
mod sparse;

use crate::acl::{TYPE_ACCESS, TYPE_NFS4};
use crate::archive::*;
use crate::entry::{AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFREG, Dev, Entry, Mode};
use crate::read::{ARCHIVE_ERRNO_FILE_FORMAT, Data, Format, Read, Reader, Status};
use crate::string::{StringConv, conversion_charset_name, conversion_from_charset, until_nul};
use crate::util::Error;
use libc::wchar_t;
use sparse::SparseBlock;
use std::collections::VecDeque;
use std::ffi::c_int;
use std::ops::Range;
use std::sync::{Arc, PoisonError};

const FORMAT_TAR: c_int = 0x30000;
const FORMAT_TAR_USTAR: c_int = FORMAT_TAR | 1;
const FORMAT_TAR_PAX_INTERCHANGE: c_int = FORMAT_TAR | 2;
const FORMAT_TAR_GNUTAR: c_int = FORMAT_TAR | 4;

/// A tar header record. The fields of the ustar and GNU layouts are the
/// ranges below.
type Block = [u8; 512];

const NAME: Range<usize> = 0..100;
const MODE: Range<usize> = 100..108;
const UID: Range<usize> = 108..116;
const GID: Range<usize> = 116..124;
const SIZE: Range<usize> = 124..136;
const MTIME: Range<usize> = 136..148;
const CHECKSUM: Range<usize> = 148..156;
const TYPEFLAG: usize = 156;
const LINKNAME: Range<usize> = 157..257;
/// The ustar magic and version, or the GNU magic (which spans both).
const MAGIC: Range<usize> = 257..263;
const VERSION: Range<usize> = 263..265;
const GNU_MAGIC: Range<usize> = 257..265;
const UNAME: Range<usize> = 265..297;
const GNAME: Range<usize> = 297..329;
const RDEVMAJOR: Range<usize> = 329..337;
const RDEVMINOR: Range<usize> = 337..345;
const PREFIX: Range<usize> = 345..500;
const ATIME: Range<usize> = 345..357;
const CTIME: Range<usize> = 357..369;
/// The four sparse descriptors in a GNU header, then its `isextended` flag
/// and the real size of the file.
const GNU_SPARSE: Range<usize> = 386..482;
const GNU_ISEXTENDED: usize = 482;
const GNU_REALSIZE: Range<usize> = 483..495;

/// Track which size fields were present in the headers.
const TAR_SIZE_PAX_SIZE: u8 = 1;
const TAR_SIZE_GNU_SPARSE_REALSIZE: u8 = 2;
const TAR_SIZE_GNU_SPARSE_SIZE: u8 = 4;
const TAR_SIZE_SCHILY_SPARSE_REALSIZE: u8 = 8;

/// Sanity limits: These numbers should be low enough to prevent a
/// maliciously-crafted archive from forcing us to allocate extreme amounts
/// of memory. But of course, they need to be high enough for any correct
/// value. These will likely need some adjustment as we get more experience.
///
/// Longest uname or gname: 64kiB.
const GUNAME_LIMIT: usize = 65536;
/// Longest path name: 1MiB.
const PATHNAME_LIMIT: usize = 1048576;
/// Longest sparse map: 8MiB.
const SPARSE_MAP_LIMIT: usize = 8 * 1048576;
/// Longest xattr: 16MiB.
const XATTR_LIMIT: usize = 16 * 1048576;
/// Longest fflags.
const FFLAGS_LIMIT: usize = 512;
/// Longest textual ACL: 128kiB.
const ACL_LIMIT: usize = 131072;
/// 2^60 bytes = 1 ExbiByte.
const ENTRY_LIMIT: i64 = 0xfffffffffffffff;

/// Which headers an entry has had so far.
const SEEN_A_HEADER: u32 = 1;
const SEEN_G_HEADER: u32 = 2;
const SEEN_K_HEADER: u32 = 4;
const SEEN_L_HEADER: u32 = 8;
const SEEN_V_HEADER: u32 = 16;
/// Also `X`.
const SEEN_X_HEADER: u32 = 32;
const SEEN_MAC_METADATA: u32 = 512;

/// Data specific to this format. The `archive_read_support_format_*`
/// functions' return codes (`ARCHIVE_OK` and friends) are used inside this
/// module, as upstream combines them with `min`; the entry points turn them
/// into `Result<Status, Error>`.
#[derive(Default)]
struct Tar {
    entry_pathname: Vec<u8>,
    /// For "GNU.sparse.name" and other similar path extensions.
    entry_pathname_override: Vec<u8>,
    entry_uname: Vec<u8>,
    entry_gname: Vec<u8>,
    entry_linkpath: Vec<u8>,
    pax_hdrcharset_utf8: bool,
    entry_bytes_remaining: i64,
    entry_padding: i64,
    disk_size: i64,
    gnu_sparse_realsize: i64,
    gnu_sparse_size: i64,
    schily_sparse_realsize: i64,
    pax_size: i64,
    sparse_list: VecDeque<SparseBlock>,
    sparse_offset: i64,
    sparse_numbytes: i64,
    sparse_gnu_major: i32,
    sparse_gnu_minor: i32,
    sparse_gnu_attributes_seen: bool,
    filetype: u8,
    /// Bits defined above.
    size_fields: u8,

    /// `hdrcharset`. `None` is the current locale, which needs no conversion.
    opt_sconv: Option<Arc<StringConv>>,
    /// The conversion for this entry's header fields.
    sconv: Option<Arc<StringConv>>,
    sconv_acl: Option<Arc<StringConv>>,
    compat_2x: bool,
    process_mac_extensions: bool,
    read_concatenated_archives: bool,
    default_inode: i32,
    default_dev: i32,
}

/// `archive_read_support_format_tar`, which `archive_read_support_format_gnutar`
/// is an alias of.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Tar {
        // Set this by default on Mac OS.
        process_mac_extensions: cfg!(target_vendor = "apple"),
        ..Tar::default()
    }))
}

/// Records the error of a failing call and gives its code.
fn fail(a: &Base, errno: c_int, msg: impl AsRef<[u8]>, code: c_int) -> c_int {
    a.set_error(errno, Some(msg.as_ref()));
    code
}

/// The result a format entry point gives for a code.
fn status(code: c_int) -> Result<Status, Error> {
    match code {
        ARCHIVE_OK => Ok(Status::Ok),
        ARCHIVE_WARN => Ok(Status::Warn),
        ARCHIVE_EOF => Ok(Status::Eof),
        // The message, if any, is on the handle already.
        code => Err(Error::silent(code)),
    }
}

/// `tar_flush_unconsumed`: consumes what earlier reads looked at.
fn flush(r: &mut Reader<'_>, unconsumed: &mut i64) -> c_int {
    if *unconsumed != 0 {
        if r.consume(*unconsumed).is_err() {
            return ARCHIVE_FATAL;
        }
        *unconsumed = 0;
    }
    ARCHIVE_OK
}

/// `__archive_read_ahead`: `None` if the input is short or fails.
fn ahead<'r>(r: &'r mut Reader<'_>, n: usize) -> Option<&'r [u8]> {
    r.read_ahead(n).ok().flatten()
}

/// The first header record of `h`.
fn first_block(h: &[u8]) -> Option<Block> {
    h.get(..512)?.try_into().ok()
}

/// Return true if this block contains only nulls.
fn block_is_null(h: &Block) -> bool {
    h.iter().all(|&b| b == 0)
}

/// `set_conversion_failed_error`.
fn conversion_failed(a: &Base, sconv: Option<&StringConv>, name: &str) -> c_int {
    let msg = [
        name.as_bytes(),
        b" can't be converted from ",
        conversion_charset_name(sconv),
        b" to current locale",
    ]
    .concat();
    fail(a, ARCHIVE_ERRNO_FILE_FORMAT, msg, ARCHIVE_WARN)
}

/// Whether the entry has no pathname yet.
fn pathname_unset(entry: &mut Entry) -> bool {
    let mbs_unset = entry.pathname().is_none_or(|s| s.to_bytes().is_empty());
    let wcs_unset = entry
        .pathname_w()
        .is_none_or(|w| w.first().is_none_or(|&c| c == 0));
    mbs_unset && wcs_unset
}

/// Validate number field
///
/// This has to be pretty lenient in order to accommodate the enormous
/// variety of tar writers in the world:
///  = POSIX (IEEE Std 1003.1-1988) ustar requires octal values with leading
///    zeros and allows fields to be terminated with space or null characters
///  = Many writers use different termination (in particular, libarchive
///    omits terminator bytes to squeeze one or two more digits)
///  = Many writers pad with space and omit leading zeros
///  = GNU tar and star write base-256 values if numbers are too
///    big to be represented in octal
///
///  Examples of specific tar headers that we should support:
///  = Perl Archive::Tar terminates uid, gid, devminor and devmajor with two
///    null bytes, pads size with spaces and other numeric fields with zeroes
///  = plexus-archiver prior to 2.6.3 (before switching to commons-compress)
///    may have uid and gid fields filled with spaces without any octal digits
///    at all and pads all numeric fields with spaces
///
/// This should tolerate all variants in use. It will reject a field
/// where the writer just left garbage after a trailing NUL.
fn validate_number_field(p: &[u8]) -> bool {
    match p.first() {
        // Base-256 marker, there's nothing we can check.
        Some(128 | 255 | 0) | None => true,
        // Must be octal: leading spaces, octal digits, then space or NUL
        // padding.
        Some(_) => p
            .iter()
            .skip_while(|&&c| c == b' ')
            .skip_while(|c| (b'0'..=b'7').contains(c))
            .all(|&c| c == b' ' || c == 0),
    }
}

/// How well the header record `h` looks like a tar header.
fn bid_block(h: &Block) -> c_int {
    // If it's an end-of-archive mark, we can handle it.
    if h[0] == 0 && block_is_null(h) {
        // Usually, I bid the number of bits verified, but in this case,
        // 4096 seems excessive so I picked 10 as an arbitrary but
        // reasonable-seeming value.
        return 10;
    }

    // If it's not an end-of-archive mark, it must have a valid checksum.
    if !checksum(h) {
        return 0;
    }
    // Checksum is usually 6 octal digits.
    let mut bid = 48;

    // Recognize POSIX formats.
    if &h[MAGIC] == b"ustar\0" && &h[VERSION] == b"00" {
        bid += 56;
    }

    // Recognize GNU tar format.
    if &h[MAGIC] == b"ustar " && &h[VERSION] == b" \0" {
        bid += 56;
    }

    // Type flag must be null, digit or A-Z, a-z.
    if h[TYPEFLAG] != 0 && !h[TYPEFLAG].is_ascii_alphanumeric() {
        return 0;
    }
    // 6 bits of variation in an 8-bit field leaves 2 bits.
    bid += 2;

    // Check format of mode/uid/gid/mtime/size/rdevmajor/rdevminor fields.
    if [MODE, UID, GID, MTIME, SIZE, RDEVMAJOR, RDEVMINOR]
        .into_iter()
        .any(|f| !validate_number_field(&h[f]))
    {
        bid = 0;
    }

    bid
}

/// Return true if block checksum is correct.
fn checksum(h: &Block) -> bool {
    // Checksum field must hold an octal number.
    if !h[CHECKSUM]
        .iter()
        .all(|&c| c == b' ' || c == 0 || (b'0'..=b'7').contains(&c))
    {
        return false;
    }

    // Test the checksum. Note that POSIX specifies _unsigned_ bytes for
    // this calculation.
    let sum = tar_atol(&h[CHECKSUM]) as i32;
    let check = |byte: fn(u8) -> i32| -> i32 {
        h.iter()
            .enumerate()
            .map(|(i, &b)| if CHECKSUM.contains(&i) { 32 } else { byte(b) })
            .fold(0, i32::wrapping_add)
    };
    if sum == check(i32::from) {
        return true;
    }

    // Repeat test with _signed_ bytes, just in case this archive was
    // created by an old BSD, Solaris, or HP-UX tar with a broken checksum
    // calculation.
    sum == check(|b| i32::from(b as i8))
}

/// Convert text->integer.
///
/// Traditional tar formats (including POSIX) specify base-8 for all of the
/// standard numeric fields. This is a significant limitation in practice:
///   = file size is limited to 8GB
///   = rdevmajor and rdevminor are limited to 21 bits
///   = uid/gid are limited to 21 bits
///
/// There are two workarounds for this:
///   = pax extended headers, which use variable-length string fields
///   = GNU tar and STAR both allow either base-8 or base-256 in most
///      fields. The high bit is set to indicate base-256.
///
/// On read, this implementation supports both extensions.
fn tar_atol(p: &[u8]) -> i64 {
    // Technically, GNU tar considers a field to be in base-256 only if the
    // first byte is 0xff or 0x80.
    if p.first().is_some_and(|c| c & 0x80 != 0) {
        return tar_atol256(p);
    }
    tar_atol_base_n(p, 8)
}

/// Note that this implementation does not (and should not!) obey locale
/// settings; you cannot simply substitute strtol here, since it does obey
/// locale.
fn tar_atol_base_n(p: &[u8], base: i64) -> i64 {
    let mut p = p;
    while let [b' ' | b'\t', rest @ ..] = p {
        p = rest;
    }
    let mut sign = 1;
    if let [b'-', rest @ ..] = p {
        sign = -1;
        p = rest;
    }
    let mut l: i64 = 0;
    for &c in p {
        let digit = i64::from(c) - i64::from(b'0');
        if digit < 0 || digit >= base {
            break;
        }
        match l
            .checked_mul(base)
            .and_then(|v| v.checked_add(sign * digit))
        {
            Some(v) => l = v,
            // Truncate on overflow.
            None => return if sign < 0 { i64::MIN } else { i64::MAX },
        }
    }
    l
}

fn tar_atol10(p: &[u8]) -> i64 {
    tar_atol_base_n(p, 10)
}

/// Parse a base-256 integer. This is just a variable-length twos-complement
/// signed binary value in big-endian order, except that the high-order bit
/// is ignored. The values here can be up to 12 bytes, so we need to be
/// careful about overflowing 64-bit (8-byte) integers.
fn tar_atol256(p: &[u8]) -> i64 {
    let mut bytes = p.iter().copied();
    let mut next = || bytes.next().unwrap_or(0);

    // Extend 7-bit 2s-comp to 8-bit 2s-comp, decide sign.
    let mut c = next();
    let neg: u8;
    let mut l: u64;
    if c & 0x40 != 0 {
        neg = 0xff;
        c |= 0x80;
        l = !0;
    } else {
        neg = 0;
        c &= 0x7f;
        l = 0;
    }
    let overflow = if neg != 0 { i64::MIN } else { i64::MAX };

    // If more than 8 bytes, check that we can ignore high-order bits
    // without overflow.
    let mut char_cnt = p.len();
    while char_cnt > size_of::<i64>() {
        char_cnt -= 1;
        if c != neg {
            return overflow;
        }
        c = next();
    }

    // c is first byte that fits; if sign mismatch, return overflow.
    if (c ^ neg) & 0x80 != 0 {
        return overflow;
    }

    // Accumulate remaining bytes.
    while char_cnt > 1 {
        char_cnt -= 1;
        l = (l << 8) | u64::from(c);
        c = next();
    }
    l = (l << 8) | u64::from(c);
    // Return signed twos-complement value.
    l as i64
}

/// The padding that rounds `size` up to a multiple of 512.
fn padding(size: i64) -> i64 {
    0x1ff & size.wrapping_neg()
}

impl Format for Tar {
    fn name(&self) -> &'static str {
        "tar"
    }

    fn bid(&mut self, r: &mut Reader<'_>, _best_bid: c_int) -> Result<c_int, Error> {
        // Now let's look at the actual header and see if it matches.
        let Some(h) = r.read_ahead(512)?.and_then(first_block) else {
            return Ok(-1);
        };
        Ok(bid_block(&h))
    }

    fn options(
        &mut self,
        a: &Base,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<Result<Status, Error>> {
        let set = value.is_some_and(|v| !v.is_empty());
        Some(match key {
            // Handle UTF-8 filenames as libarchive 2.x.
            b"compat-2x" => {
                self.compat_2x = set;
                Ok(Status::Ok)
            }
            b"hdrcharset" => {
                let Some(name) = value.filter(|v| !v.is_empty()) else {
                    return Some(Err(Error::new(
                        ARCHIVE_FAILED,
                        ARCHIVE_ERRNO_MISC,
                        "tar: hdrcharset option needs a character-set name",
                    )));
                };
                let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
                conversion_from_charset(Some(&mut *cache), name, false)
                    .map(|sc| {
                        self.opt_sconv = Some(sc);
                        Status::Ok
                    })
                    .map_err(|e| Error::fatal(e.errno, e.message))
            }
            b"mac-ext" => {
                self.process_mac_extensions = set;
                Ok(Status::Ok)
            }
            b"read_concatenated_archives" => {
                self.read_concatenated_archives = set;
                Ok(Status::Ok)
            }
            // The "warn" return is just to inform the options supervisor
            // that we didn't handle it. It will generate a suitable error
            // if no one used this option.
            _ => Ok(Status::Warn),
        })
    }

    /// The function invoked by archive_read_next_header(). This just sets
    /// up a few things and then calls the internal tar_read_header()
    /// function below.
    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        // When converting tar archives to cpio archives, it is essential
        // that each distinct file have a distinct inode number. To
        // simplify this, we keep a static count here to assign fake
        // dev/inode numbers to each tar entry. Note that pax format
        // archives may overwrite this with something more useful.
        //
        // Ideally, we would track every file read from the archive so that
        // we could assign the same dev/ino pair to hardlinks, but the
        // memory required to store a complete lookup table is probably not
        // worthwhile just to support the relatively obscure tar->cpio
        // conversion case.
        let a = r.base();
        // Assign default device/inode values. Don't use zero.
        entry.set_dev((1 + self.default_dev) as Dev);
        self.default_inode += 1;
        entry.set_ino(i64::from(self.default_inode));
        // Limit generated st_ino number to 16 bits.
        if self.default_inode >= 0xffff {
            self.default_dev += 1;
            self.default_inode = 0;
        }

        self.sparse_list.clear();
        // We don't have any size info yet.
        self.size_fields = 0;

        // Setup default string conversion: there is none for the locale.
        self.sconv = self.opt_sconv.clone();

        let mut unconsumed = 0;
        let code = self.tar_read_header(r, entry, &mut unconsumed);

        let _ = flush(r, &mut unconsumed);

        // "non-sparse" files are really just sparse files with a single
        // block.
        if self.sparse_list.is_empty() {
            if self.add_sparse_entry(a, 0, self.entry_bytes_remaining) != ARCHIVE_OK {
                return status(ARCHIVE_FATAL);
            }
        } else {
            let mut added = 0;
            for sb in self.sparse_list.iter().filter(|sb| !sb.hole) {
                entry.sparse_add(sb.offset, sb.remaining);
                added += 1;
            }
            if usize::try_from(entry.sparse_count()) != Ok(added) {
                return status(fail(
                    a,
                    ARCHIVE_ERRNO_MISC,
                    "Malformed sparse map data",
                    ARCHIVE_FATAL,
                ));
            }
        }

        if code == ARCHIVE_OK && entry.filetype() == AE_IFREG {
            // "Regular" entry with trailing '/' is really directory: This
            // is needed for certain old tar variants and even for some
            // broken newer ones.
            let slash = match entry.pathname() {
                Some(p) => Some(p.to_bytes().last() == Some(&b'/')),
                None => entry
                    .pathname_w()
                    .map(|w| w.last() == Some(&(b'/' as wchar_t))),
            };
            if slash == Some(true) {
                entry.set_filetype(AE_IFDIR.into());
                self.entry_bytes_remaining = 0;
                self.entry_padding = 0;
            }
        }
        status(code)
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        loop {
            // Remove exhausted entries from sparse list.
            while self.sparse_list.front().is_some_and(|sb| sb.remaining == 0) {
                self.sparse_list.pop_front();
            }

            // If we're at end of file, return EOF.
            if self.sparse_list.is_empty() || self.entry_bytes_remaining == 0 {
                r.consume(self.entry_bytes_remaining + self.entry_padding)?;
                self.entry_padding = 0;
                return Ok(Data::Eof {
                    offset: self.disk_size,
                });
            }

            let Some(available) = r.peek_available(1).ok().map(<[u8]>::len).filter(|&n| n > 0)
            else {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_MISC,
                    "Truncated tar archive detected while reading data",
                ));
            };
            let Some(sb) = self.sparse_list.front_mut() else {
                continue;
            };
            let n = i64::try_from(available)
                .unwrap_or(i64::MAX)
                // Don't read more than is available in the current sparse
                // block.
                .min(self.entry_bytes_remaining)
                .min(sb.remaining);
            let offset = sb.offset;
            sb.remaining -= n;
            sb.offset += n;
            self.entry_bytes_remaining -= n;
            let n = usize::try_from(n).unwrap_or(0);

            if sb.hole {
                // Current is hole data and skip this.
                r.consume(n)?;
                continue;
            }
            // The block stays in the reader's buffer until the next call,
            // which consumes it first (upstream's entry_bytes_unconsumed).
            let later = r.consume_later();
            let Some(data) = ahead(r, 1).and_then(|d| d.get(..n)) else {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_MISC,
                    "Truncated tar archive detected while reading data",
                ));
            };
            later.consume(n);
            return Ok(Data::Block { data, offset });
        }
    }

    fn read_data_skip(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        r.consume(self.entry_bytes_remaining + self.entry_padding)?;
        self.entry_bytes_remaining = 0;
        self.entry_padding = 0;
        // Free the sparse list.
        self.sparse_list.clear();
        Ok(Status::Ok)
    }
}

/// Read the next `size` bytes into the provided string.
fn read_bytes_to_string(
    r: &mut Reader<'_>,
    out: &mut Vec<u8>,
    size: usize,
    unconsumed: &mut i64,
) -> c_int {
    let a = r.base();
    if flush(r, unconsumed) != ARCHIVE_OK {
        return ARCHIVE_FATAL;
    }

    // Read the body into the string.
    let Some(src) = ahead(r, size).and_then(|s| s.get(..size)) else {
        *unconsumed = 0;
        return fail(
            a,
            libc::EINVAL,
            "Truncated archive detected while reading metadata",
            ARCHIVE_FATAL,
        );
    };
    out.clear();
    out.extend_from_slice(src);
    *unconsumed += size as i64;
    ARCHIVE_OK
}

/// Read body of an archive entry into a string.
fn read_body_to_string(
    r: &mut Reader<'_>,
    out: &mut Vec<u8>,
    h: &Block,
    unconsumed: &mut i64,
) -> c_int {
    let a = r.base();
    let size = tar_atol(&h[SIZE]);
    if !(0..=ENTRY_LIMIT).contains(&size) {
        return fail(
            a,
            libc::EINVAL,
            format!("Special header has invalid size: {size}"),
            ARCHIVE_FATAL,
        );
    }
    if size > PATHNAME_LIMIT as i64 {
        out.clear();
        let to_consume = (size + 511) & !511;
        if r.consume(to_consume).is_err() {
            return ARCHIVE_FATAL;
        }
        return fail(
            a,
            libc::EINVAL,
            format!("Special header too large: {size} > 1MiB"),
            ARCHIVE_WARN,
        );
    }
    let code = read_bytes_to_string(r, out, size as usize, unconsumed);
    *unconsumed += padding(size);
    code
}

/// Is this likely an AppleDouble extension? Its last path element starts
/// with "._".
fn is_mac_metadata_entry(entry: &mut Entry) -> bool {
    fn is_mac<T: Copy + PartialEq + From<u8>>(path: &[T]) -> bool {
        let path = path.split(|&c| c == T::from(0)).next().unwrap_or_default();
        // Find the last path element.
        let mut name = path;
        for (i, &c) in path.iter().enumerate() {
            if c == T::from(b'/')
                && let Some(rest) = path.get(i + 1..).filter(|rest| !rest.is_empty())
            {
                name = rest;
            }
        }
        name.len() > 2 && name.starts_with(&[T::from(b'.'), T::from(b'_')])
    }
    match entry.pathname() {
        Some(p) => is_mac(p.to_bytes()),
        None => entry.pathname_w().is_some_and(is_mac),
    }
}

impl Tar {
    /// This function resets the accumulated state while reading a header.
    fn reset_header_state(&mut self) {
        self.pax_hdrcharset_utf8 = true;
        self.sparse_gnu_attributes_seen = false;
        self.entry_gname.clear();
        self.entry_pathname.clear();
        self.entry_pathname_override.clear();
        self.entry_uname.clear();
        self.entry_linkpath.clear();
    }

    /// Finds the next header record with a good checksum. `Err` is what
    /// `tar_read_header` returns instead: the end of the archive or a
    /// failure.
    fn next_block(
        &mut self,
        r: &mut Reader<'_>,
        unconsumed: &mut i64,
        eof_fatal: bool,
    ) -> Result<Block, c_int> {
        let a = r.base();
        loop {
            if flush(r, unconsumed) != ARCHIVE_OK {
                return Err(ARCHIVE_FATAL);
            }

            // Read 512-byte header record.
            let (h, len) = match r.peek_available(512) {
                Ok(d) => (first_block(d), d.len()),
                Err(_) => (None, 1),
            };
            let Some(h) = h else {
                if len == 0 {
                    // EOF at a block boundary.
                    if eof_fatal {
                        // We've read a special header already; if there's
                        // no regular header, then this is a premature EOF.
                        return Err(fail(
                            a,
                            libc::EINVAL,
                            "Damaged tar archive (end-of-archive within a sequence of headers)",
                            ARCHIVE_FATAL,
                        ));
                    }
                    return Err(ARCHIVE_EOF);
                }
                // Short block at EOF; this is bad.
                return Err(fail(
                    a,
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Truncated tar archive detected while reading next header",
                    ARCHIVE_FATAL,
                ));
            };
            *unconsumed += 512;

            if h[0] == 0 && block_is_null(&h) {
                // We found a NULL block which indicates end-of-archive.
                if self.read_concatenated_archives {
                    // We're ignoring NULL blocks, so keep going.
                    continue;
                }

                // Try to consume a second all-null record, as well. If we
                // can't, that's okay.
                let _ = flush(r, unconsumed);
                if ahead(r, 512)
                    .and_then(first_block)
                    .is_some_and(|b| block_is_null(&b))
                {
                    let _ = r.consume(512);
                }

                a.clear_error();
                return Err(ARCHIVE_EOF);
            }

            // This is NOT a null block, so it must be a valid header.
            if !checksum(&h) {
                if flush(r, unconsumed) != ARCHIVE_OK {
                    return Err(ARCHIVE_FATAL);
                }
                a.set_error(
                    libc::EINVAL,
                    Some(b"Damaged tar archive (bad header checksum)"),
                );
                // If we've read some critical information (pax headers,
                // etc) and _then_ see a bad header, we can't really
                // recover.
                return Err(if eof_fatal {
                    ARCHIVE_FATAL
                } else {
                    ARCHIVE_RETRY
                });
            }
            return Ok(h);
        }
    }

    /// This function reads and interprets all of the headers associated
    /// with a single entry.
    fn tar_read_header(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        unconsumed: &mut i64,
    ) -> c_int {
        let a = r.base();
        let mut err = ARCHIVE_OK;
        // EOF is okay at some points...
        let mut eof_fatal = false;
        // Bitmask of what header types we've seen.
        let mut seen_headers = 0;

        self.reset_header_state();

        // Ensure format is set.
        if a.format_name.get().is_none() {
            a.set_format(FORMAT_TAR, c"tar");
        }

        // TODO: Write global/default pax options into 'entry' struct here
        // before overwriting with file-specific options.

        // Loop over all the headers needed for the next entry.
        loop {
            let h = match self.next_block(r, unconsumed, eof_fatal) {
                Ok(h) => h,
                Err(code) => return code,
            };

            // Determine the format variant.
            let err2 = match h[TYPEFLAG] {
                // Solaris tar ACL.
                b'A' => {
                    if seen_headers & SEEN_A_HEADER != 0 {
                        return fail(a, ARCHIVE_ERRNO_MISC, "Redundant 'A' header", ARCHIVE_FATAL);
                    }
                    seen_headers |= SEEN_A_HEADER;
                    a.set_format(FORMAT_TAR_PAX_INTERCHANGE, c"Solaris tar");
                    self.header_solaris_acl(r, entry, &h, unconsumed)
                }
                // POSIX-standard 'g' header.
                b'g' => {
                    if seen_headers & SEEN_G_HEADER != 0 {
                        return fail(a, ARCHIVE_ERRNO_MISC, "Redundant 'g' header", ARCHIVE_FATAL);
                    }
                    seen_headers |= SEEN_G_HEADER;
                    a.set_format(FORMAT_TAR_PAX_INTERCHANGE, c"POSIX pax interchange format");
                    self.header_pax_records(r, entry, &h, unconsumed, true)
                }
                // Long link name (GNU tar, others).
                b'K' => {
                    if seen_headers & SEEN_K_HEADER != 0 {
                        a.set_error(
                            ARCHIVE_ERRNO_MISC,
                            Some(
                                b"Damaged archive: Redundant 'K' headers may cause linknames to be incorrect",
                            ),
                        );
                        err = err.min(ARCHIVE_WARN);
                    }
                    seen_headers |= SEEN_K_HEADER;
                    a.set_format(FORMAT_TAR_GNUTAR, c"GNU tar format");
                    self.header_gnu_longlink(r, entry, &h, unconsumed)
                }
                // Long filename (GNU tar, others).
                b'L' => {
                    if seen_headers & SEEN_L_HEADER != 0 {
                        a.set_error(
                            ARCHIVE_ERRNO_MISC,
                            Some(
                                b"Damaged archive: Redundant 'L' headers may cause filenames to be incorrect",
                            ),
                        );
                        err = err.min(ARCHIVE_WARN);
                    }
                    seen_headers |= SEEN_L_HEADER;
                    a.set_format(FORMAT_TAR_GNUTAR, c"GNU tar format");
                    self.header_gnu_longname(r, entry, &h, unconsumed)
                }
                // GNU volume header.
                b'V' => {
                    if seen_headers & SEEN_V_HEADER != 0 {
                        a.set_error(ARCHIVE_ERRNO_MISC, Some(b"Redundant 'V' header"));
                        err = err.min(ARCHIVE_WARN);
                    }
                    seen_headers |= SEEN_V_HEADER;
                    a.set_format(FORMAT_TAR_GNUTAR, c"GNU tar format");
                    Self::header_volume(&h, unconsumed)
                }
                // Used by SUN tar; same as 'x'.
                t @ (b'X' | b'x') => {
                    if seen_headers & SEEN_X_HEADER != 0 {
                        return fail(
                            a,
                            ARCHIVE_ERRNO_MISC,
                            if t == b'X' {
                                "Redundant 'X'/'x' header"
                            } else {
                                "Redundant 'x' header"
                            },
                            ARCHIVE_FATAL,
                        );
                    }
                    seen_headers |= SEEN_X_HEADER;
                    a.set_format(
                        FORMAT_TAR_PAX_INTERCHANGE,
                        if t == b'X' {
                            c"POSIX pax interchange format (Sun variant)"
                        } else {
                            c"POSIX pax interchange format"
                        },
                    );
                    self.header_pax_records(r, entry, &h, unconsumed, false)
                }
                // Regular header: Legacy tar, GNU tar, or ustar.
                _ => {
                    let err2 = if &h[GNU_MAGIC] == b"ustar  \0" {
                        a.set_format(FORMAT_TAR_GNUTAR, c"GNU tar format");
                        self.header_gnutar(r, entry, &h, unconsumed)
                    } else if h[MAGIC].starts_with(b"ustar") {
                        if a.format.get() != FORMAT_TAR_PAX_INTERCHANGE {
                            a.set_format(FORMAT_TAR_USTAR, c"POSIX ustar format");
                        }
                        self.header_ustar(a, entry, &h)
                    } else {
                        a.set_format(FORMAT_TAR, c"tar (non-POSIX)");
                        self.header_old_tar(a, entry, &h)
                    };
                    err = err.min(err2);
                    // We return warnings or success as-is. Anything else is
                    // fatal.
                    if err < ARCHIVE_WARN {
                        return ARCHIVE_FATAL;
                    }
                    // Filename of the form `._filename` is an AppleDouble
                    // extension entry. The body is the macOS metadata blob;
                    // this is followed by another entry with the actual
                    // regular file data.
                    // This design has two drawbacks:
                    // = it's brittle; you might just have a file with such
                    //   a name
                    // = it duplicates any long pathname extensions
                    //
                    // TODO: This probably shouldn't be here at all.
                    // Consider just returning the contents as a regular
                    // entry here and then dealing with it when we write
                    // data to disk.
                    if !(self.process_mac_extensions
                        && seen_headers & SEEN_MAC_METADATA == 0
                        && is_mac_metadata_entry(entry))
                    {
                        return self.reconcile_sparse(r, err, unconsumed);
                    }
                    let err2 = Self::read_mac_metadata_blob(r, entry, unconsumed);
                    if err2 < ARCHIVE_WARN {
                        return ARCHIVE_FATAL;
                    }
                    err = err.min(err2);
                    // Note: Other headers can appear again.
                    seen_headers = SEEN_MAC_METADATA;
                    self.reset_header_state();
                    err2
                }
            };

            // We're between headers ...
            err = err.min(err2);
            if err == ARCHIVE_FATAL {
                return err;
            }

            // The GNU volume header and the pax `g` global header are both
            // allowed to be the only header in an archive. If we've seen any
            // other header, a following EOF is fatal.
            if seen_headers & !SEEN_V_HEADER & !SEEN_G_HEADER != 0 {
                eof_fatal = true;
            }
        }
    }

    /// Reconcile GNU sparse attributes once the entry's header is read.
    fn reconcile_sparse(&mut self, r: &mut Reader<'_>, err: c_int, unconsumed: &mut i64) -> c_int {
        let a = r.base();
        if !self.sparse_gnu_attributes_seen {
            return err;
        }
        // Only 'S' (GNU sparse) and ustar '0' regular files can be sparse.
        if self.filetype != b'S' && self.filetype != b'0' {
            return fail(
                a,
                ARCHIVE_ERRNO_MISC,
                "Non-regular file cannot be sparse",
                ARCHIVE_WARN,
            );
        }
        match (self.sparse_gnu_major, self.sparse_gnu_minor) {
            // Sparse map already parsed from 'x' header.
            (0, 0) | (0, 1) => {}
            // Sparse map is prepended to file contents.
            (1, 0) => {
                let bytes_read = self.sparse_10_read(r, unconsumed);
                if bytes_read < 0 {
                    return bytes_read as c_int;
                }
                self.entry_bytes_remaining -= bytes_read;
            }
            _ => {
                return fail(
                    a,
                    ARCHIVE_ERRNO_MISC,
                    "Unrecognized GNU sparse file format",
                    ARCHIVE_WARN,
                );
            }
        }
        err
    }

    /// The conversion for ACL text, made on first use.
    fn acl_sconv(&mut self, a: &Base) -> Result<Arc<StringConv>, c_int> {
        if let Some(sc) = &self.sconv_acl {
            return Ok(sc.clone());
        }
        let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
        match conversion_from_charset(Some(&mut *cache), b"UTF-8", true) {
            Ok(sc) => Ok(self.sconv_acl.insert(sc).clone()),
            Err(e) => {
                a.set_error(e.errno, Some(&e.message));
                Err(ARCHIVE_FATAL)
            }
        }
    }

    /// Interpret 'A' Solaris ACL header.
    fn header_solaris_acl(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        h: &Block,
        unconsumed: &mut i64,
    ) -> c_int {
        let a = r.base();
        let mut acl_text = Vec::new();
        let err = read_body_to_string(r, &mut acl_text, h, unconsumed);
        if err != ARCHIVE_OK {
            return err;
        }
        let size = acl_text.len();
        let at = |i: usize| acl_text.get(i).copied().unwrap_or(0);

        // TODO: Examine the first characters to see if this is an AIX ACL
        // descriptor. We'll likely never support them, but it would be
        // polite to recognize and warn when we do see them.

        // Leading octal number indicates ACL type and number of entries.
        let mut p = 0;
        let mut type_: u64 = 0;
        while at(p) != 0 && p < size {
            if !(b'0'..=b'7').contains(&at(p)) {
                return fail(
                    a,
                    ARCHIVE_ERRNO_MISC,
                    "Malformed Solaris ACL attribute (invalid digit)",
                    ARCHIVE_WARN,
                );
            }
            type_ <<= 3;
            type_ += u64::from(at(p) - b'0');
            if type_ > 0o77777777 {
                return fail(
                    a,
                    ARCHIVE_ERRNO_MISC,
                    "Malformed Solaris ACL attribute (count too large)",
                    ARCHIVE_WARN,
                );
            }
            p += 1;
        }
        let acl_type = match type_ & !0o777777 {
            // POSIX.1e ACL
            0o1000000 => TYPE_ACCESS,
            // NFSv4 ACL
            0o3000000 => TYPE_NFS4,
            _ => {
                return fail(
                    a,
                    ARCHIVE_ERRNO_MISC,
                    format!("Malformed Solaris ACL attribute (unsupported type {type_})"),
                    ARCHIVE_WARN,
                );
            }
        };
        p += 1;

        if p >= size {
            return fail(
                a,
                ARCHIVE_ERRNO_MISC,
                "Malformed Solaris ACL attribute (body overflow)",
                ARCHIVE_WARN,
            );
        }

        // ACL text is null-terminated; find the end.
        let acl = p;
        let size = size - p;
        while at(p) != 0 && p < acl + size {
            p += 1;
        }

        let sconv = match self.acl_sconv(a) {
            Ok(sc) => sc,
            Err(code) => return code,
        };
        let text = acl_text.get(acl..p).unwrap_or_default();
        let err = entry.acl.parse_nl(text, acl_type, Some(&sconv));
        // Workaround: Force perm_is_set() to be correct. If this bit were
        // stored in the ACL, this wouldn't be needed.
        entry.set_perm(entry.perm());
        if err != ARCHIVE_OK {
            a.set_error(
                ARCHIVE_ERRNO_MISC,
                Some(b"Malformed Solaris ACL attribute (unparsable)"),
            );
        }
        err
    }

    /// Interpret 'K' long linkname header.
    fn header_gnu_longlink(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        h: &Block,
        unconsumed: &mut i64,
    ) -> c_int {
        let mut linkpath = Vec::new();
        let err = read_body_to_string(r, &mut linkpath, h, unconsumed);
        if err == ARCHIVE_OK {
            entry.set_link(until_nul(&linkpath));
        }
        err
    }

    /// Interpret 'L' long filename header.
    fn header_gnu_longname(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        h: &Block,
        unconsumed: &mut i64,
    ) -> c_int {
        let mut longname = Vec::new();
        let mut err = read_body_to_string(r, &mut longname, h, unconsumed);
        if err == ARCHIVE_OK
            && entry
                .copy_pathname_l(&longname, self.sconv.as_deref())
                .is_err()
        {
            err = conversion_failed(r.base(), self.sconv.as_deref(), "Pathname");
        }
        err
    }

    /// Interpret 'V' GNU tar volume header.
    fn header_volume(h: &Block, unconsumed: &mut i64) -> c_int {
        let size = tar_atol(&h[SIZE]);
        if !(0..=PATHNAME_LIMIT as i64).contains(&size) {
            return ARCHIVE_FATAL;
        }
        *unconsumed += (size + 511) & !511;
        ARCHIVE_OK
    }

    /// Parse out common header elements.
    ///
    /// This would be the same as header_old_tar, except that the filename is
    /// handled slightly differently for old and POSIX entries (POSIX
    /// entries support a 'prefix'). This factoring allows header_old_tar and
    /// header_ustar to handle filenames differently, while still putting
    /// most of the common parsing into one place.
    ///
    /// This is called _after_ ustar, GNU tar, Schily, etc, special fields
    /// have already been parsed into the `tar` structure. So we can make
    /// final decisions here about how to reconcile size, mode, etc,
    /// information.
    fn header_common(&mut self, a: &Base, entry: &mut Entry, h: &Block) -> c_int {
        let mut err = ARCHIVE_OK;

        // Parse out the numeric fields (all are octal).

        // Split mode handling: Set filetype always, perm only if not
        // already set.
        let header_mode = tar_atol(&h[MODE]) as Mode;
        entry.set_filetype(header_mode.into());
        if entry.perm_is_set() == 0 {
            entry.set_perm(header_mode);
        }

        // Set uid, gid, mtime if not already set.
        if entry.uid_is_set() == 0 {
            entry.set_uid(tar_atol(&h[UID]));
        }
        if entry.gid_is_set() == 0 {
            entry.set_gid(tar_atol(&h[GID]));
        }
        if entry.mtime_is_set() == 0 {
            entry.set_mtime(tar_atol(&h[MTIME]), 0);
        }

        // Reconcile the size info.
        // First, how big is the file on disk?
        if self.size_fields & TAR_SIZE_GNU_SPARSE_REALSIZE != 0 {
            // GNU sparse format 1.0 uses `GNU.sparse.realsize` to hold the
            // size of the file on disk.
            self.disk_size = self.gnu_sparse_realsize;
        } else if self.size_fields & TAR_SIZE_GNU_SPARSE_SIZE != 0 && self.sparse_gnu_major == 0 {
            // GNU sparse format 0.0 and 0.1 use `GNU.sparse.size` to hold
            // the size of the file on disk.
            self.disk_size = self.gnu_sparse_size;
        } else if self.size_fields & TAR_SIZE_SCHILY_SPARSE_REALSIZE != 0 {
            self.disk_size = self.schily_sparse_realsize;
        } else if self.size_fields & TAR_SIZE_PAX_SIZE != 0 {
            self.disk_size = self.pax_size;
        } else {
            // There wasn't a suitable pax header, so use the ustar info.
            self.disk_size = tar_atol(&h[SIZE]);
        }

        if self.disk_size < 0 {
            return fail(
                a,
                ARCHIVE_ERRNO_MISC,
                "Tar entry has negative file size",
                ARCHIVE_FATAL,
            );
        } else if self.disk_size > ENTRY_LIMIT {
            return fail(
                a,
                ARCHIVE_ERRNO_MISC,
                "Tar entry size overflow",
                ARCHIVE_FATAL,
            );
        }
        entry.set_size(self.disk_size);

        // Second, how big is the data in the archive?
        if self.size_fields & TAR_SIZE_GNU_SPARSE_SIZE != 0 && self.sparse_gnu_major == 1 {
            // GNU sparse format 1.0 uses `GNU.sparse.size` to hold the size
            // of the data in the archive.
            self.entry_bytes_remaining = self.gnu_sparse_size;
        } else if self.size_fields & TAR_SIZE_PAX_SIZE != 0 {
            self.entry_bytes_remaining = self.pax_size;
        } else {
            self.entry_bytes_remaining = tar_atol(&h[SIZE]);
        }
        if self.entry_bytes_remaining < 0 {
            self.entry_bytes_remaining = 0;
            return fail(
                a,
                ARCHIVE_ERRNO_MISC,
                "Tar entry has negative size",
                ARCHIVE_FATAL,
            );
        } else if self.entry_bytes_remaining > ENTRY_LIMIT {
            self.entry_bytes_remaining = 0;
            return fail(
                a,
                ARCHIVE_ERRNO_MISC,
                "Tar entry size overflow",
                ARCHIVE_FATAL,
            );
        }

        // Handle the tar type flag appropriately.
        self.filetype = h[TYPEFLAG];

        // TODO: If the linkpath came from Pax extension header, then we
        // should obey the hdrcharset_utf8 flag when converting these.
        match self.filetype {
            // Hard link
            b'1' => {
                entry.set_link_to_hardlink();
                let mbs_unset = entry.hardlink().is_none_or(|s| s.to_bytes().is_empty());
                let wcs_unset = entry
                    .hardlink_w()
                    .is_none_or(|w| w.first().is_none_or(|&c| c == 0));
                if mbs_unset && wcs_unset {
                    let linkname = until_nul(&h[LINKNAME]);
                    if entry
                        .copy_hardlink_l(linkname, self.sconv.as_deref())
                        .is_err()
                    {
                        err = conversion_failed(a, self.sconv.as_deref(), "Linkname");
                    }
                }
                // The following may seem odd, but: Technically, tar does
                // not store the file type for a "hard link" entry, only the
                // fact that it is a hard link. So, I leave the type zero
                // normally. But, pax interchange format allows hard links
                // to have data, which implies that the underlying entry is
                // a regular file.
                if entry.size() > 0 {
                    entry.set_filetype(AE_IFREG.into());
                }

                // A tricky point: Traditionally, tar readers have ignored
                // the size field when reading hardlink entries, and some
                // writers put non-zero sizes even though the body is empty.
                // POSIX blessed this convention in the 1988 standard, but
                // broke with this tradition in 2001 by permitting hardlink
                // entries to store valid bodies in pax interchange format,
                // but not in ustar format. Since there is no hard and fast
                // way to distinguish pax interchange from earlier archives
                // (the 'x' and 'g' entries are optional, after all), we
                // need a heuristic.
                let format = a.format.get();
                if entry.size() == 0 {
                    // If the size is already zero, we're done.
                } else if format == FORMAT_TAR_PAX_INTERCHANGE {
                    // Definitely pax extended; must obey hardlink size.
                } else if format == FORMAT_TAR || format == FORMAT_TAR_GNUTAR {
                    // Old-style or GNU tar: we must ignore the size.
                    entry.set_size(0);
                    self.entry_bytes_remaining = 0;
                } else if bid_block(h) > 50 {
                    // We don't know if it's pax: If the bid function sees a
                    // valid ustar header immediately following, then let's
                    // ignore the hardlink size.
                    //
                    // That header is the entry's own: upstream looks at the
                    // stream, where the record just read is not yet
                    // consumed.
                    entry.set_size(0);
                    self.entry_bytes_remaining = 0;
                }
                // TODO: There are still two cases I'd like to handle:
                //   = a ustar non-pax archive with a hardlink entry at
                //     end-of-archive. (Look for block of nulls following?)
                //   = a pax archive that has not seen any pax headers and
                //     has an entry which is a hardlink entry storing a body
                //     containing an uncompressed tar archive.
                // The first is worth addressing; I don't see any reliable
                // way to deal with the second possibility.
            }
            // Symlink
            b'2' => {
                entry.set_link_to_symlink();
                let mbs_unset = entry.symlink().is_none_or(|s| s.to_bytes().is_empty());
                let wcs_unset = entry
                    .symlink_w()
                    .is_none_or(|w| w.first().is_none_or(|&c| c == 0));
                if mbs_unset && wcs_unset {
                    let linkname = until_nul(&h[LINKNAME]);
                    if entry
                        .copy_symlink_l(linkname, self.sconv.as_deref())
                        .is_err()
                    {
                        err = conversion_failed(a, self.sconv.as_deref(), "Linkname");
                    }
                }
                entry.set_filetype(AE_IFLNK.into());
                entry.set_size(0);
                self.entry_bytes_remaining = 0;
            }
            // Character device
            b'3' => self.special(entry, AE_IFCHR),
            // Block device
            b'4' => self.special(entry, AE_IFBLK),
            // Dir
            b'5' => self.special(entry, AE_IFDIR),
            // FIFO device
            b'6' => self.special(entry, AE_IFIFO),
            // GNU incremental directory type.
            //
            // No special handling is actually required here. It might be
            // nice someday to preprocess the file list and provide it to
            // the client, though.
            b'D' => entry.set_filetype(AE_IFDIR.into()),
            // GNU "Multi-volume" (remainder of file from last archive).
            //
            // As far as I can tell, this is just like a regular file entry,
            // except that the contents should be _appended_ to the
            // indicated file at the indicated offset. This may require
            // some API work to fully support.
            b'M' => {}
            // Old GNU "long filename" entry.
            //
            // The body of this entry is a script for renaming
            // previously-extracted entries. Ugh. It will never be
            // supported by libarchive.
            // Sparse files are really just regular files with sparse
            // information in the extended area. Per POSIX: non-recognized
            // types should always be treated as regular files.
            _ => entry.set_filetype(AE_IFREG.into()),
        }
        err
    }

    /// A file type that has no data.
    fn special(&mut self, entry: &mut Entry, filetype: Mode) {
        entry.set_filetype(filetype.into());
        entry.set_size(0);
        self.entry_bytes_remaining = 0;
    }

    /// Parse out header elements for "old-style" tar archives.
    fn header_old_tar(&mut self, a: &Base, entry: &mut Entry, h: &Block) -> c_int {
        let mut err = ARCHIVE_OK;

        // Copy filename over (to ensure null termination). Skip if
        // pathname was already set e.g. by header_gnu_longname().
        if pathname_unset(entry)
            && entry
                .copy_pathname_l(&h[NAME], self.sconv.as_deref())
                .is_err()
        {
            err = conversion_failed(a, self.sconv.as_deref(), "Pathname");
        }

        // Grab rest of common fields.
        err = err.min(self.header_common(a, entry, h));

        self.entry_padding = padding(self.entry_bytes_remaining);
        err
    }

    /// Parse a file header for a Posix "ustar" archive entry. This also
    /// handles "pax" or "extended ustar" entries.
    ///
    /// In order to correctly handle pax attributes (which precede this), we
    /// have to skip parsing any field for which the entry already has
    /// contents.
    fn header_ustar(&mut self, a: &Base, entry: &mut Entry, h: &Block) -> c_int {
        let mut err = ARCHIVE_OK;

        // The name field is fixed-width and may not be NUL-terminated.
        if pathname_unset(entry) {
            let mut as_ = Vec::new();
            let pathname = if h[PREFIX.start] != 0 {
                as_.extend_from_slice(until_nul(&h[PREFIX]));
                if as_.last() != Some(&b'/') {
                    as_.push(b'/');
                }
                as_.extend_from_slice(until_nul(&h[NAME]));
                &as_[..]
            } else {
                &h[NAME]
            };
            if entry
                .copy_pathname_l(pathname, self.sconv.as_deref())
                .is_err()
            {
                err = conversion_failed(a, self.sconv.as_deref(), "Pathname");
            }
        }

        // Handle rest of common fields.
        let r = self.header_common(a, entry, h);
        if r == ARCHIVE_FATAL {
            return r;
        }
        err = err.min(r);

        // Handle POSIX ustar fields.
        err = err.min(self.names_and_rdev(a, entry, h));

        self.entry_padding = padding(self.entry_bytes_remaining);
        err
    }

    /// The user and group names and device numbers, which ustar and GNU
    /// headers have in common.
    fn names_and_rdev(&mut self, a: &Base, entry: &mut Entry, h: &Block) -> c_int {
        let mut err = ARCHIVE_OK;
        if entry.uname().is_none_or(|s| s.to_bytes().is_empty())
            && entry
                .copy_uname_l(&h[UNAME], self.sconv.as_deref())
                .is_err()
        {
            err = conversion_failed(a, self.sconv.as_deref(), "Uname");
        }

        if entry.gname().is_none_or(|s| s.to_bytes().is_empty())
            && entry
                .copy_gname_l(&h[GNAME], self.sconv.as_deref())
                .is_err()
        {
            err = conversion_failed(a, self.sconv.as_deref(), "Gname");
        }

        // Parse out device numbers only for char and block specials.
        if h[TYPEFLAG] == b'3' || h[TYPEFLAG] == b'4' {
            if entry.rdev_is_set() == 0 {
                entry.set_rdevmajor(tar_atol(&h[RDEVMAJOR]) as Dev);
                entry.set_rdevminor(tar_atol(&h[RDEVMINOR]) as Dev);
            }
        } else {
            entry.set_rdev(0);
        }
        err
    }

    /// Parse GNU tar header.
    fn header_gnutar(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        h: &Block,
        unconsumed: &mut i64,
    ) -> c_int {
        let a = r.base();

        // GNU header is like POSIX ustar, except 'prefix' is replaced with
        // some other fields. This also means the filename is stored as in
        // old-style archives.
        //
        // Upstream drops the codes of the conversions here (the messages
        // stay) and returns that of header_common.

        // Copy filename over (to ensure null termination).
        if pathname_unset(entry)
            && entry
                .copy_pathname_l(&h[NAME], self.sconv.as_deref())
                .is_err()
        {
            let _ = conversion_failed(a, self.sconv.as_deref(), "Pathname");
        }

        // Fields common to ustar and GNU.
        // XXX Can the following be factored out since it's common to ustar
        // and gnu tar? Is it okay to move it down into header_common,
        // perhaps?
        let _ = self.names_and_rdev(a, entry, h);

        // Grab GNU-specific fields.
        if entry.atime_is_set() == 0 {
            let t = tar_atol(&h[ATIME]);
            if t > 0 {
                entry.set_atime(t, 0);
            }
        }
        if entry.ctime_is_set() == 0 {
            let t = tar_atol(&h[CTIME]);
            if t > 0 {
                entry.set_ctime(t, 0);
            }
        }

        if h[GNU_REALSIZE.start] != 0 {
            // Treat as a synonym for the pax GNU.sparse.realsize attr.
            self.gnu_sparse_realsize = tar_atol(&h[GNU_REALSIZE]);
            self.size_fields |= TAR_SIZE_GNU_SPARSE_REALSIZE;
        }

        if h[GNU_SPARSE.start] != 0 && self.sparse_old_read(r, h, unconsumed) != ARCHIVE_OK {
            return ARCHIVE_FATAL;
        }
        // (An `isextended` flag without sparse descriptors means nothing.)

        // Grab fields common to all tar variants.
        let err = self.header_common(a, entry, h);
        if err == ARCHIVE_FATAL {
            return err;
        }

        self.entry_padding = padding(self.entry_bytes_remaining);
        err
    }

    /// Read a Mac AppleDouble-encoded blob of file metadata, if there is
    /// one.
    ///
    /// TODO: In Libarchive 4, we should consider ripping this out --
    /// instead, return a file starting with `._` as a regular file and let
    /// the client (or archive_write logic) handle it.
    fn read_mac_metadata_blob(
        r: &mut Reader<'_>,
        entry: &mut Entry,
        unconsumed: &mut i64,
    ) -> c_int {
        let a = r.base();
        // Read the body as a Mac OS metadata blob.
        let size = entry.size();
        let Ok(msize) = usize::try_from(size) else {
            *unconsumed = 0;
            return ARCHIVE_FATAL;
        };

        // TODO: Should this merely skip the overlarge entry and WARN? Or is
        // xattr_limit sufficiently large that we can safely assume anything
        // larger is malicious?
        if msize > XATTR_LIMIT {
            return fail(
                a,
                ARCHIVE_ERRNO_MISC,
                format!("Oversized AppleDouble extension has size {size} > {XATTR_LIMIT}"),
                ARCHIVE_FATAL,
            );
        }

        // TODO: Look beyond the body here to peek at the next header. If
        // it's a regular header (not an extension header) that has the
        // wrong name, just return the current entry as-is, without
        // consuming the body here. That would reduce the risk of us
        // mis-identifying an ordinary file that just happened to have a
        // name starting with "._".
        //
        // Q: Is the above idea really possible? Even when there are GNU or
        // pax extension entries?
        if flush(r, unconsumed) != ARCHIVE_OK {
            return ARCHIVE_FATAL;
        }
        let Some(data) = ahead(r, msize).and_then(|d| d.get(..msize)) else {
            *unconsumed = 0;
            return fail(
                a,
                libc::EINVAL,
                "Truncated archive detected while reading macOS metadata",
                ARCHIVE_FATAL,
            );
        };
        entry.clear();
        entry.copy_mac_metadata(data);
        *unconsumed = (size + 511) & !511;
        ARCHIVE_OK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ustar header with the given name and a correct checksum.
    fn header(name: &[u8], typeflag: u8) -> Block {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name);
        h[MODE].copy_from_slice(b"0000644\0");
        h[SIZE].copy_from_slice(b"00000000000\0");
        h[MTIME].copy_from_slice(b"00000000000\0");
        h[TYPEFLAG] = typeflag;
        h[MAGIC].copy_from_slice(b"ustar\0");
        h[VERSION].copy_from_slice(b"00");
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum::<u32>() + 32 * 8;
        h[CHECKSUM].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }

    #[test]
    fn numbers_are_octal_or_base_256() {
        assert_eq!(tar_atol(b"0000644\0"), 0o644);
        assert_eq!(tar_atol(b"  17 \0"), 0o17);
        assert_eq!(tar_atol(b"-12\0"), -0o12);
        assert_eq!(tar_atol(b"8"), 0);
        assert_eq!(tar_atol(b""), 0);
        assert_eq!(
            tar_atol(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00]),
            256
        );
        assert_eq!(tar_atol(&[0xff; 12]), -1);
        // Too big for 64 bits.
        assert_eq!(tar_atol(&[0x80, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), i64::MAX);
        assert_eq!(tar_atol(b"99999999999999999999"), 0);
        assert_eq!(tar_atol10(b"99999999999999999999"), i64::MAX);
        assert_eq!(tar_atol10(b"-99999999999999999999"), i64::MIN);
        assert_eq!(tar_atol10(b"1234x"), 1234);
    }

    #[test]
    fn number_fields_are_validated() {
        assert!(validate_number_field(b"  0644 \0"));
        assert!(validate_number_field(&[0x80, 1, 2]));
        assert!(validate_number_field(b"\0garbage"));
        assert!(!validate_number_field(b"0644\0x"));
        assert!(!validate_number_field(b"06a4"));
    }

    #[test]
    fn checksums_are_unsigned_or_signed() {
        let mut h = header(b"caf\xe9", b'0');
        assert!(checksum(&h));
        h[0] = b'x';
        assert!(!checksum(&h));

        // An old tar added the bytes as signed chars.
        let mut h = header(b"caf\xe9", b'0');
        let signed: i32 = h
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if CHECKSUM.contains(&i) {
                    32
                } else {
                    i32::from(b as i8)
                }
            })
            .sum();
        h[CHECKSUM].copy_from_slice(format!("{signed:06o}\0 ").as_bytes());
        assert!(checksum(&h));
    }

    #[test]
    fn bids_follow_the_header() {
        assert_eq!(bid_block(&[0; 512]), 10);
        assert_eq!(bid_block(&header(b"f", b'0')), 48 + 56 + 2);
        let mut h = header(b"f", b'0');
        h[MAGIC].copy_from_slice(b"\0\0\0\0\0\0");
        h[VERSION].copy_from_slice(b"\0\0");
        h[CHECKSUM].copy_from_slice(b"      \0 ");
        assert_eq!(bid_block(&h), 0);
        assert_eq!(bid_block(&header(b"f", b'!')), 0);
        assert_eq!(bid_block(&header(b"f", b'x')), 106);
    }
}
