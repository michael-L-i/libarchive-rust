/*-
 * Copyright (c) 2003-2007 Tim Kientzle
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

// Ported from libarchive/archive_read_support_format_cpio.c.

//! The cpio formats: ASCII odc and newc (with and without CRC), afio's
//! large ASCII variant, and little- and big-endian binary.

use crate::archive::*;
use crate::entry::{AE_IFLNK, AE_IFMT, AE_IFREG, Dev, Entry, Mode};
use crate::read::{ARCHIVE_ERRNO_FILE_FORMAT, Data, Format, Read, Reader, Status};
use crate::string::{StringConv, conversion_charset_name, conversion_from_charset};
use crate::util::Error;
use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::{Arc, PoisonError};

const FORMAT_CPIO: c_int = 0x10000;
const FORMAT_POSIX: c_int = FORMAT_CPIO | 1;
const FORMAT_BIN_LE: c_int = FORMAT_CPIO | 2;
const FORMAT_BIN_BE: c_int = FORMAT_CPIO | 3;
const FORMAT_SVR4_NOCRC: c_int = FORMAT_CPIO | 4;
const FORMAT_SVR4_CRC: c_int = FORMAT_CPIO | 5;
const FORMAT_AFIO_LARGE: c_int = FORMAT_CPIO | 6;

const BIN_HEADER_SIZE: usize = 26;
const ODC_HEADER_SIZE: usize = 76;
const NEWC_HEADER_SIZE: usize = 110;
const AFIOL_HEADER_SIZE: usize = 116;

/// Name fields store a full pathname, including the terminating NUL, and
/// symlink contents are bounded the same way.
const PATHNAME_MAX: usize = 1024 * 1024;

#[derive(Clone, Copy)]
enum Kind {
    Odc,
    Newc,
    BinLe,
    BinBe,
}

/// A multiply-linked file already read, until its last hard link is.
struct Link {
    /// Hard links still to come.
    links: u32,
    name: Vec<u8>,
}

#[derive(Default)]
struct Cpio {
    /// The header reader `bid` chose.
    kind: Option<Kind>,
    /// Keyed by device and inode; each key is in the table at most once.
    links: HashMap<(Dev, i64), Link>,
    entry_bytes_remaining: i64,
    entry_padding: i64,
    entry_offset: i64,
    /// `hdrcharset`. `None` is the current locale, which needs no conversion.
    opt_sconv: Option<Arc<StringConv>>,
    /// `pwb`: the binary headers are V6 inodes.
    option_pwb: bool,
}

/// `archive_read_support_format_cpio`.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Cpio::default()))
}

/// `atol8`: octal digits up to the first other character.
fn atol8(p: &[u8]) -> i64 {
    let mut l: u64 = 0;
    for &c in p {
        if !(b'0'..=b'7').contains(&c) {
            break;
        }
        l = (l << 3) | u64::from(c - b'0');
    }
    l as i64
}

/// `atol16u`: hex digits up to the first other character.
fn atol16u(p: &[u8]) -> u64 {
    let mut l: u64 = 0;
    for &c in p {
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => break,
        };
        l = (l << 4) | u64::from(digit);
    }
    l
}

/// `atol16`.
fn atol16(p: &[u8]) -> i64 {
    atol16u(p) as i64
}

/// Whether `s[from..from + len]` exists and every byte passes `ok`.
fn all_in(s: &[u8], from: usize, len: usize, ok: impl Fn(&u8) -> bool) -> bool {
    s.get(from..from.saturating_add(len))
        .is_some_and(|f| f.iter().all(ok))
}

fn is_octal(s: &[u8], from: usize, len: usize) -> bool {
    all_in(s, from, len, |c| (b'0'..=b'7').contains(c))
}

fn is_hex(s: &[u8], from: usize, len: usize) -> bool {
    all_in(s, from, len, u8::is_ascii_hexdigit)
}

/// A field of a fixed-size header that was read in full.
fn field(h: &[u8], off: usize, len: usize) -> &[u8] {
    h.get(off..off.saturating_add(len)).unwrap_or_default()
}

/// A 16-bit binary field in the given byte order.
fn u16_at(h: &[u8], off: usize, big_endian: bool) -> u16 {
    let b: [u8; 2] = field(h, off, 2).try_into().unwrap_or_default();
    if big_endian {
        u16::from_be_bytes(b)
    } else {
        u16::from_le_bytes(b)
    }
}

/// A 32-bit binary field as `cpio_le32dec` and `cpio_be32dec` read it: each
/// half is in the given byte order, and the first half is the high one.
fn u32_at(h: &[u8], off: usize, big_endian: bool) -> i64 {
    (i64::from(u16_at(h, off, big_endian)) << 16) | i64::from(u16_at(h, off + 2, big_endian))
}

/// Whether an odc or afio large header starts at `h[p..]`. The bool is true
/// for afio's format.
fn odc_header_at(h: &[u8], p: usize) -> Option<bool> {
    let s = h.get(p..)?;
    if s.starts_with(b"070707") && is_octal(s, 0, ODC_HEADER_SIZE) {
        Some(false)
    } else if s.starts_with(b"070727") && is_afio_large(s) {
        Some(true)
    } else {
        None
    }
}

/// Whether `s`, which runs from a candidate header to the end of the input,
/// starts with an afio large header.
fn is_afio_large(s: &[u8]) -> bool {
    s.len() >= AFIOL_HEADER_SIZE
        && s.get(30) == Some(&b'm')
        && s.get(85) == Some(&b'n')
        && s.get(98) == Some(&b's')
        && s.get(115) == Some(&b':')
        && is_hex(s, 6, 30 - 6)
        && is_hex(s, 31, 85 - 31)
        && is_hex(s, 86, 98 - 86)
        && is_hex(s, 99, 16)
}

/// Looks through `h` for an odc header that fits whole in it, `size` being
/// the header size the caller read. Returns where it stopped, and whether it
/// found one there (with afio's flag).
fn scan_odc(h: &[u8], size: usize) -> (usize, Option<bool>) {
    let mut p = 0;
    while p + size <= h.len() {
        match h.get(p + 5).copied() {
            Some(b'7') => {
                if let Some(afio) = odc_header_at(h, p) {
                    return (p, Some(afio));
                }
                p += 2;
            }
            Some(b'0') => p += 1,
            _ => p += 6,
        }
    }
    (p, None)
}

/// Whether a newc header starts at `h[p..]`.
fn newc_header_at(h: &[u8], p: usize) -> bool {
    h.get(p..).is_some_and(|s| {
        s.starts_with(b"07070")
            && matches!(s.get(5).copied(), Some(b'1' | b'2'))
            && is_hex(s, 0, NEWC_HEADER_SIZE)
    })
}

/// Looks through `h` for a newc header. Returns where it stopped, and whether
/// it found one there.
fn scan_newc(h: &[u8]) -> (usize, bool) {
    let mut p = 0;
    while p + NEWC_HEADER_SIZE <= h.len() {
        match h.get(p + 5).copied() {
            Some(b'1' | b'2') => {
                if newc_header_at(h, p) {
                    return (p, true);
                }
                p += 2;
            }
            Some(b'0') => p += 1,
            _ => p += 6,
        }
    }
    (p, false)
}

/// Skips to the next odc or afio header. The status is `Warn` when bytes
/// were skipped; the bool is true for afio's format.
fn find_odc_header(r: &mut Reader<'_>) -> Result<(Status, bool), Error> {
    let mut skipped: u64 = 0;
    loop {
        let (p, found) = {
            let h = r.peek_available(AFIOL_HEADER_SIZE)?;
            let size = if h.len() >= AFIOL_HEADER_SIZE {
                AFIOL_HEADER_SIZE
            } else if h.len() >= ODC_HEADER_SIZE {
                ODC_HEADER_SIZE
            } else {
                return Err(Error::silent(ARCHIVE_FATAL));
            };
            // The usual case: a header right here, which is not reported as
            // skipping even when an earlier pass skipped bytes.
            if let Some(afio) = odc_header_at(h, 0) {
                return Ok((Status::Ok, afio));
            }
            scan_odc(h, size)
        };
        r.consume(p)?;
        skipped = skipped.saturating_add(p as u64);
        if let Some(afio) = found {
            return Ok((skipped_status(r, skipped), afio));
        }
    }
}

/// Skips to the next newc header.
fn find_newc_header(r: &mut Reader<'_>) -> Result<Status, Error> {
    let mut skipped: u64 = 0;
    loop {
        let (p, found) = {
            let h = r.peek_available(NEWC_HEADER_SIZE)?;
            if h.len() < NEWC_HEADER_SIZE {
                return Err(Error::silent(ARCHIVE_FATAL));
            }
            if newc_header_at(h, 0) {
                return Ok(Status::Ok);
            }
            scan_newc(h)
        };
        r.consume(p)?;
        skipped = skipped.saturating_add(p as u64);
        if found {
            return Ok(skipped_status(r, skipped));
        }
    }
}

/// The status for a header found after `skipped` bytes of garbage.
fn skipped_status(r: &Reader<'_>, skipped: u64) -> Status {
    if skipped > 0 {
        r.warn(
            0,
            format!("Skipped {skipped} bytes before finding valid header"),
        )
    } else {
        Status::Ok
    }
}

impl Cpio {
    /// `header_odc`. Returns the status, the name length and the name's
    /// padding.
    fn header_odc(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
    ) -> Result<(Status, usize, usize), Error> {
        r.base()
            .set_format(FORMAT_POSIX, c"POSIX octet-oriented cpio");
        let (status, afio) = find_odc_header(r)?;
        if afio {
            let (namelength, name_pad) = self.header_afiol(r, entry)?;
            return Ok((status, namelength, name_pad));
        }

        let Some(h) = r.read_ahead(ODC_HEADER_SIZE)? else {
            return Err(Error::silent(ARCHIVE_FATAL));
        };
        entry.set_dev(atol8(field(h, 6, 6)) as Dev);
        entry.set_ino(atol8(field(h, 12, 6)));
        entry.set_mode(atol8(field(h, 18, 6)) as Mode);
        entry.set_uid(atol8(field(h, 24, 6)));
        entry.set_gid(atol8(field(h, 30, 6)));
        entry.set_nlink(atol8(field(h, 36, 6)) as u32);
        entry.set_rdev(atol8(field(h, 42, 6)) as Dev);
        entry.set_mtime(atol8(field(h, 48, 11)), 0);
        let namelength = atol8(field(h, 59, 6)) as usize;
        let remaining = atol8(field(h, 65, 11));
        entry.set_size(remaining);
        self.entry_bytes_remaining = remaining;
        self.entry_padding = 0;
        r.consume(ODC_HEADER_SIZE)?;
        Ok((status, namelength, 0))
    }

    /// `header_afiol`: an afio large header. Returns the name length and the
    /// name's padding, which is none.
    fn header_afiol(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
    ) -> Result<(usize, usize), Error> {
        r.base().set_format(FORMAT_AFIO_LARGE, c"afio large ASCII");
        let Some(h) = r.read_ahead(AFIOL_HEADER_SIZE)? else {
            return Err(Error::silent(ARCHIVE_FATAL));
        };
        entry.set_dev(atol16(field(h, 6, 8)) as Dev);
        // Masked to 63 bits: ARCHIVE_VERSION_NUMBER is below 4000000 here.
        entry.set_ino((atol16u(field(h, 14, 16)) & (i64::MAX as u64)) as i64);
        entry.set_mode(atol8(field(h, 31, 6)) as Mode);
        entry.set_uid(atol16(field(h, 37, 8)));
        entry.set_gid(atol16(field(h, 45, 8)));
        entry.set_nlink(atol16(field(h, 53, 8)) as u32);
        entry.set_rdev(atol16(field(h, 61, 8)) as Dev);
        entry.set_mtime(atol16(field(h, 69, 16)), 0);
        let namelength = atol16(field(h, 86, 4)) as usize;
        let remaining = atol16(field(h, 99, 16));
        if remaining < 0 {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Nonsensical file size",
            ));
        }
        entry.set_size(remaining);
        self.entry_bytes_remaining = remaining;
        self.entry_padding = 0;
        r.consume(AFIOL_HEADER_SIZE)?;
        Ok((namelength, 0))
    }

    /// `header_newc`, for both the plain and the CRC variant.
    fn header_newc(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
    ) -> Result<(Status, usize, usize), Error> {
        let status = find_newc_header(r)?;
        let a = r.base();
        let Some(h) = r.read_ahead(NEWC_HEADER_SIZE)? else {
            return Err(Error::silent(ARCHIVE_FATAL));
        };
        if h.starts_with(b"070701") {
            a.set_format(FORMAT_SVR4_NOCRC, c"ASCII cpio (SVR4 with no CRC)");
        } else if h.starts_with(b"070702") {
            a.set_format(FORMAT_SVR4_CRC, c"ASCII cpio (SVR4 with CRC)");
        }

        entry.set_devmajor(atol16(field(h, 62, 8)) as Dev);
        entry.set_devminor(atol16(field(h, 70, 8)) as Dev);
        entry.set_ino(atol16(field(h, 6, 8)));
        entry.set_mode(atol16(field(h, 14, 8)) as Mode);
        entry.set_uid(atol16(field(h, 22, 8)));
        entry.set_gid(atol16(field(h, 30, 8)));
        entry.set_nlink(atol16(field(h, 38, 8)) as u32);
        entry.set_rdevmajor(atol16(field(h, 78, 8)) as Dev);
        entry.set_rdevminor(atol16(field(h, 86, 8)) as Dev);
        entry.set_mtime(atol16(field(h, 46, 8)), 0);
        let namelength = atol16(field(h, 94, 8)) as usize;
        // Pad the name to 2 more than a multiple of 4.
        let name_pad = 2usize.wrapping_sub(namelength) & 3;
        if namelength.checked_add(name_pad).is_none() {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "cpio archive has invalid namelength",
            ));
        }
        let remaining = atol16(field(h, 54, 8));
        entry.set_size(remaining);
        self.entry_bytes_remaining = remaining;
        // Pad the contents to a multiple of 4.
        self.entry_padding = remaining.wrapping_neg() & 3;
        r.consume(NEWC_HEADER_SIZE)?;
        Ok((status, namelength, name_pad))
    }

    /// `header_bin_le` and `header_bin_be`.
    fn header_bin(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        big_endian: bool,
    ) -> Result<(Status, usize, usize), Error> {
        let a = r.base();
        if big_endian {
            a.set_format(FORMAT_BIN_BE, c"cpio (big-endian binary)");
        } else {
            a.set_format(FORMAT_BIN_LE, c"cpio (little-endian binary)");
        }
        let Some(h) = r.read_ahead(BIN_HEADER_SIZE)? else {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "End of file trying to read next cpio header",
            ));
        };
        let be = big_endian;
        entry.set_dev(Dev::from(u16_at(h, 2, be)));
        entry.set_ino(i64::from(u16_at(h, 4, be)));
        entry.set_mode(Mode::from(u16_at(h, 6, be)));
        if self.option_pwb {
            // Turn off random bits left over from V6 inodes.
            entry.set_mode(entry.mode() & 0o67777);
            if entry.mode() & AE_IFMT == 0 {
                entry.set_mode(entry.mode() | AE_IFREG);
            }
        }
        entry.set_uid(i64::from(u16_at(h, 8, be)));
        entry.set_gid(i64::from(u16_at(h, 10, be)));
        entry.set_nlink(u32::from(u16_at(h, 12, be)));
        entry.set_rdev(Dev::from(u16_at(h, 14, be)));
        entry.set_mtime(u32_at(h, 16, be), 0);
        let namelength = usize::from(u16_at(h, 20, be));
        // Pad to even.
        let name_pad = namelength & 1;
        let remaining = u32_at(h, 22, be);
        entry.set_size(remaining);
        self.entry_bytes_remaining = remaining;
        self.entry_padding = remaining & 1;
        r.consume(BIN_HEADER_SIZE)?;
        Ok((Status::Ok, namelength, name_pad))
    }

    /// The header the kind `bid` chose reads.
    fn header(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
    ) -> Result<(Status, usize, usize), Error> {
        match self.kind {
            Some(Kind::Odc) => self.header_odc(r, entry),
            Some(Kind::Newc) => self.header_newc(r, entry),
            Some(Kind::BinLe) => self.header_bin(r, entry, false),
            Some(Kind::BinBe) => self.header_bin(r, entry, true),
            None => Err(Error::silent(ARCHIVE_FATAL)),
        }
    }

    /// Records a hard link: a file with several links gives its later links
    /// the first one's name, until the last link is read.
    fn record_hardlink(&mut self, entry: &mut Entry) -> Result<(), Error> {
        if entry.nlink() <= 1 {
            return Ok(());
        }
        let key = (entry.dev(), entry.ino());
        if let Some(le) = self.links.get_mut(&key) {
            entry.copy_hardlink(&le.name);
            le.links = le.links.saturating_sub(1);
            if le.links == 0 {
                self.links.remove(&key);
            }
            return Ok(());
        }
        let Some(pathname) = entry.pathname() else {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Invalid hardlink entry with no pathname",
            ));
        };
        let name = pathname.to_bytes().to_vec();
        self.links.insert(
            key,
            Link {
                links: entry.nlink() - 1,
                name,
            },
        );
        Ok(())
    }
}

impl Format for Cpio {
    fn name(&self) -> &'static str {
        "cpio"
    }

    /// The magic number of each variant, as `bid` checks them. The odc and
    /// newc magics are ASCII; the binary ones are a 16-bit octal 070707 in
    /// either byte order.
    fn bid(&mut self, r: &mut Reader<'_>, _best_bid: c_int) -> Result<c_int, Error> {
        let Some(h) = r.read_ahead(6)? else {
            return Ok(-1);
        };
        let (kind, bid) = if h.starts_with(b"070707") || h.starts_with(b"070727") {
            // ASCII cpio (odc, POSIX.1), and afio's large variant.
            (Kind::Odc, 48)
        } else if h.starts_with(b"070701") || h.starts_with(b"070702") {
            // ASCII cpio (SVR4 without and with CRC).
            (Kind::Newc, 48)
        } else if u16_at(h, 0, true) == 0o70707 {
            (Kind::BinBe, 16)
        } else if u16_at(h, 0, false) == 0o70707 {
            (Kind::BinLe, 16)
        } else {
            return Ok(ARCHIVE_WARN);
        };
        self.kind = Some(kind);
        Ok(bid)
    }

    fn options(
        &mut self,
        a: &Base,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<Result<Status, Error>> {
        Some(match key {
            // Upstream sets up a default name conversion only on Windows; on
            // this platform there is none to switch off.
            b"compat-2x" => Ok(Status::Ok),
            b"hdrcharset" => {
                let Some(name) = value.filter(|v| !v.is_empty()) else {
                    return Some(Err(Error::new(
                        ARCHIVE_FAILED,
                        ARCHIVE_ERRNO_MISC,
                        "cpio: hdrcharset option needs a character-set name",
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
            b"pwb" => {
                if value.is_some_and(|v| !v.is_empty()) {
                    self.option_pwb = true;
                }
                Ok(Status::Ok)
            }
            _ => Ok(Status::Warn),
        })
    }

    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        let sconv = self.opt_sconv.clone();
        let (mut status, namelength, name_pad) = self.header(r, entry)?;
        let a = r.base();
        if namelength > PATHNAME_MAX {
            return Err(Error::fatal(
                libc::ENOMEM,
                "Rejecting malformed cpio archive: pathname exceeds 1 megabyte",
            ));
        }

        r.budget.check_metadata(namelength)?;
        let Some(h) = r.read_ahead(namelength)?.and_then(|h| h.get(..namelength)) else {
            return Err(Error::silent(ARCHIVE_FATAL));
        };
        let charset = conversion_charset_name(sconv.as_deref());
        if entry.copy_pathname_l(h, sconv.as_deref()).is_err() {
            let msg = [
                b"Pathname can't be converted from ".as_slice(),
                charset,
                b" to current locale",
            ]
            .concat();
            status = a.warn(ARCHIVE_ERRNO_FILE_FORMAT, msg);
        }
        // Saved before the name is consumed.
        let is_trailer = namelength == 11 && h.get(..10) == Some(&b"TRAILER!!!"[..]);
        self.entry_offset = 0;
        r.consume(namelength)?;
        // Upstream ignores this result as well: a short input is recorded,
        // and the next header read fails.
        let _ = r.consume(name_pad);

        // A symlink's contents follow the header.
        if entry.filetype() == AE_IFLNK {
            if self.entry_bytes_remaining > PATHNAME_MAX as i64 {
                return Err(Error::fatal(
                    libc::ENOMEM,
                    "Rejecting malformed cpio archive: symlink contents exceed 1 megabyte",
                ));
            }
            let Ok(n) = usize::try_from(self.entry_bytes_remaining) else {
                return Err(Error::silent(ARCHIVE_FATAL));
            };
            r.budget.check_metadata(n)?;
            let Some(hl) = r.read_ahead(n)?.and_then(|hl| hl.get(..n)) else {
                return Err(Error::silent(ARCHIVE_FATAL));
            };
            if entry.copy_symlink_l(hl, sconv.as_deref()).is_err() {
                let msg = [
                    b"Linkname can't be converted from ".as_slice(),
                    charset,
                    b" to current locale",
                ]
                .concat();
                status = a.warn(ARCHIVE_ERRNO_FILE_FORMAT, msg);
            }
            r.consume(n)?;
            self.entry_bytes_remaining = 0;
        }

        if is_trailer {
            a.clear_error();
            return Ok(Status::Eof);
        }
        self.record_hardlink(entry)?;
        Ok(status)
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        if self.entry_bytes_remaining > 0 {
            // The block stays in the reader's buffer until the next call,
            // which consumes it first (upstream's entry_bytes_unconsumed).
            let later = r.consume_later();
            let Some(data) = r.read_ahead(1)? else {
                return Err(Error::silent(ARCHIVE_FATAL));
            };
            let n = i64::try_from(data.len())
                .unwrap_or(i64::MAX)
                .min(self.entry_bytes_remaining);
            let offset = self.entry_offset;
            self.entry_offset = self.entry_offset.saturating_add(n);
            self.entry_bytes_remaining = self.entry_bytes_remaining.saturating_sub(n);
            let n = usize::try_from(n).unwrap_or(0);
            later.consume(n);
            return Ok(Data::Block {
                data: data.get(..n).unwrap_or_default(),
                offset,
            });
        }
        r.consume(self.entry_padding)?;
        self.entry_padding = 0;
        Ok(Data::Eof {
            offset: self.entry_offset,
        })
    }

    fn read_data_skip(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        r.consume(
            self.entry_bytes_remaining
                .saturating_add(self.entry_padding),
        )?;
        self.entry_bytes_remaining = 0;
        self.entry_padding = 0;
        Ok(Status::Ok)
    }
}
