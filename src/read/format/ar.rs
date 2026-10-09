/*-
 * Copyright (c) 2007 Kai Wang
 * Copyright (c) 2007 Tim Kientzle
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
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

// Ported from libarchive/archive_read_support_format_ar.c.

//! The ar format: the GNU/SVR4 and BSD variants, with GNU's filename table
//! (`//`) and BSD's long names (`#1/`).

use crate::archive::*;
use crate::entry::{AE_IFREG, Entry, Mode};
use crate::read::{Data, Format, Read, Reader, Status, format_code};
use crate::util::Error;
use std::ffi::c_int;

const FORMAT_AR_GNU: c_int = format_code::AR | 1;
const FORMAT_AR_BSD: c_int = format_code::AR | 2;

/// The `ar` header is 60 bytes: name 16, date 12, uid 6, gid 6, mode 8,
/// size 10, then the "`\n" magic.
const HEADER_LEN: usize = 60;
const NAME_LEN: usize = 16;
const DATE: usize = 16;
const UID: usize = 28;
const GID: usize = 34;
const MODE: usize = 40;
const SIZE: usize = 48;
const FMAG: usize = 58;

/// The largest GNU filename table we accept.
const MAX_STRTAB: i64 = 1024 * 1024 * 1024;
/// The largest BSD long name we accept.
const MAX_BSD_NAME: u64 = 1024 * 1024;

#[derive(Default)]
struct Ar {
    entry_bytes_remaining: i64,
    /// Bytes `read_data` returned but whose consumption is still owed. They
    /// are consumed at the start of the next call (or by the skip).
    entry_bytes_unconsumed: i64,
    entry_offset: i64,
    entry_padding: i64,
    /// The GNU filename table, NUL-terminated.
    strtab: Option<Vec<u8>>,
    read_global_header: bool,
}

/// `archive_read_support_format_ar`.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Ar::default()))
}

impl Format for Ar {
    fn name(&self) -> &'static str {
        "ar"
    }

    /// Bids 64 on the 8-byte signature.
    fn bid(&mut self, r: &mut Reader<'_>, _best_bid: c_int) -> Result<c_int, Error> {
        // A failed read is a missing signature, as upstream has it.
        let Ok(Some(h)) = r.read_ahead(8) else {
            return Ok(-1);
        };
        Ok(if h.starts_with(b"!<arch>\n") { 64 } else { -1 })
    }

    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        if !self.read_global_header {
            // A truncated global header shows up below as end of archive.
            let _ = r.consume(8);
            self.read_global_header = true;
            // Upstream sets only the code here; the name comes with the first header.
            r.base().format.set(format_code::AR);
        }
        loop {
            let Ok(Some(data)) = r.read_ahead(HEADER_LEN) else {
                return Ok(Status::Eof);
            };
            let Some(&header) = data.first_chunk::<HEADER_LEN>() else {
                return Ok(Status::Eof);
            };
            let mut unconsumed = HEADER_LEN as i64;
            let ret = self.parse_header(r, entry, &header, &mut unconsumed);
            if unconsumed != 0 {
                // Upstream ignores this failure; the error is on the handle.
                let _ = r.consume(unconsumed);
            }
            ret?;
            if entry.pathname().is_some() {
                return Ok(Status::Ok);
            }
        }
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        if self.entry_bytes_unconsumed != 0 {
            let _ = r.consume(self.entry_bytes_unconsumed);
            self.entry_bytes_unconsumed = 0;
        }
        if self.entry_bytes_remaining > 0 {
            let data = r.peek_available(1)?;
            if data.is_empty() {
                return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Truncated ar archive"));
            }
            let avail = i64::try_from(data.len()).unwrap_or(i64::MAX);
            let n = avail.min(self.entry_bytes_remaining);
            let offset = self.entry_offset;
            self.entry_offset = offset.checked_add(n).ok_or(Error::silent(ARCHIVE_FATAL))?;
            self.entry_bytes_remaining = self
                .entry_bytes_remaining
                .checked_sub(n)
                .ok_or(Error::silent(ARCHIVE_FATAL))?;
            self.entry_bytes_unconsumed = n;
            let len = usize::try_from(n).unwrap_or(0);
            return Ok(Data::Block {
                data: data.get(..len).unwrap_or_default(),
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
        self.skip_entry(r).map(|()| Status::Ok)
    }
}

impl Ar {
    /// `_ar_read_header`: parses one header and sets up the entry. Returns
    /// with an error for a fatal problem. `unconsumed` is how much of the
    /// 60 header bytes the caller still has to consume.
    fn parse_header(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        h: &[u8; HEADER_LEN],
        unconsumed: &mut i64,
    ) -> Result<(), Error> {
        if &h[FMAG..] != b"`\n" {
            return Err(Error::fatal(
                libc::EINVAL,
                "Incorrect file header signature",
            ));
        }

        // strncpy into a NUL-terminated buffer: the name ends at its first NUL.
        let mut name = [0u8; NAME_LEN + 1];
        for (dst, &c) in name.iter_mut().zip(&h[..NAME_LEN]) {
            if c == 0 {
                break;
            }
            *dst = c;
        }

        // Guess the variant from the name, unless an earlier entry already did.
        let mut format = r.base().format.get();
        if format == format_code::AR {
            if name.starts_with(b"#1/") {
                format = FORMAT_AR_BSD;
            } else if c_str(&name).contains(&b'/') {
                // GNU special names start with '/', and other GNU names end in '/'.
                format = FORMAT_AR_GNU;
            } else if name.starts_with(b"__.SYMDEF") {
                format = FORMAT_AR_BSD;
            }
        }
        match format {
            FORMAT_AR_GNU => r.set_format(format, c"ar (GNU/SVR4)"),
            FORMAT_AR_BSD => r.set_format(format, c"ar (BSD)"),
            _ => r.set_format(format, c"ar"),
        }

        // Trim trailing spaces, then one trailing '/' unless the name starts
        // with '/' (GNU special entries are not terminated).
        let mut keep = NAME_LEN;
        while keep > 0 && name[keep - 1] == b' ' {
            name[keep - 1] = 0;
            keep -= 1;
        }
        if name[0] != b'/' && keep > 1 && name[keep - 1] == b'/' {
            name[keep - 1] = 0;
        }
        if keep == 0 {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_MISC,
                "Found entry with empty filename",
            ));
        }

        self.parse_common_header(entry, h);

        let fname = c_str(&name);
        // The ranlib index: linker information, not a file.
        if fname == b"/" {
            entry.clear_pathname();
            return self.skip_entry(r);
        }

        // The GNU filename table. Later entries refer to names in it.
        if fname == b"//" {
            entry.clear_pathname();
            let size = entry.size();
            if !(1..=MAX_STRTAB).contains(&size) {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_MISC,
                    "Invalid filename table size",
                ));
            }
            let strtab_size = size as usize;
            if self.strtab.is_some() {
                return Err(Error::fatal(
                    libc::EINVAL,
                    "More than one filename table exists",
                ));
            }
            if *unconsumed != 0 {
                let _ = r.consume(*unconsumed);
                *unconsumed = 0;
            }
            let Some(mut table) = r
                .read_ahead(strtab_size)?
                .and_then(|data| data.get(..strtab_size))
                .map(<[u8]>::to_vec)
            else {
                return Err(Error::silent(ARCHIVE_FATAL));
            };
            self.skip_entry(r)?;
            if !parse_gnu_filename_table(&mut table) {
                return Err(Error::fatal(libc::EINVAL, "Invalid string table"));
            }
            self.strtab = Some(table);
            return Ok(());
        }

        // GNU refers to a long name in the filename table as "/<offset>".
        // TODO upstream: this does not check that all the digits are digits.
        if name[0] == b'/' && name[1].is_ascii_digit() {
            let number = ar_atol(h, 1, NAME_LEN - 1, 10);
            let name = match &self.strtab {
                Some(table) if number < table.len() as u64 => {
                    c_str(table.get(number as usize..).unwrap_or_default())
                }
                _ => {
                    return Err(Error::fatal(
                        libc::EINVAL,
                        "Can't find long filename for GNU/SVR4 archive entry",
                    ));
                }
            };
            entry.set_pathname(name);
            return Ok(());
        }

        // BSD stores "#1/<length>" and puts the name at the start of the data.
        if name.starts_with(b"#1/") {
            let number = ar_atol(h, 3, NAME_LEN - 3, 10);
            let remaining = self.entry_bytes_remaining;
            if number > MAX_BSD_NAME || number > u64::try_from(remaining).unwrap_or(0) {
                return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Bad input file size"));
            }
            // Bounded by MAX_BSD_NAME above, so the casts are exact.
            let len = number as usize;
            self.entry_bytes_remaining = remaining
                .checked_sub(number as i64)
                .ok_or(Error::silent(ARCHIVE_FATAL))?;
            entry.set_size(self.entry_bytes_remaining);
            if *unconsumed != 0 {
                let _ = r.consume(*unconsumed);
                *unconsumed = 0;
            }
            let bytes = match r.read_ahead(len) {
                Ok(Some(data)) => c_str(data.get(..len).unwrap_or_default()).to_vec(),
                _ => return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Truncated input file")),
            };
            // Upstream ignores this failure as well.
            let _ = r.consume(len);
            entry.set_pathname(&bytes);
            return Ok(());
        }

        entry.set_pathname(fname);
        Ok(())
    }

    /// `ar_parse_common_header`: the fields every entry has, and the size
    /// and padding of its data.
    fn parse_common_header(&mut self, entry: &mut Entry, h: &[u8; HEADER_LEN]) {
        entry.set_mtime(ar_atol(h, DATE, 12, 10) as i64, 0);
        // uid_t and gid_t are 32 bits; the casts truncate as upstream's do.
        entry.set_uid(i64::from(ar_atol(h, UID, 6, 10) as u32));
        entry.set_gid(i64::from(ar_atol(h, GID, 6, 10) as u32));
        entry.set_mode(ar_atol(h, MODE, 8, 8) as Mode);
        entry.set_filetype(u32::from(AE_IFREG));
        // Ten digits at most, so the size is never negative.
        let n = ar_atol(h, SIZE, 10, 10) as i64;

        self.entry_offset = 0;
        self.entry_padding = n % 2;
        entry.set_size(n);
        self.entry_bytes_remaining = n;
    }

    /// `archive_read_format_ar_skip`: consumes the rest of the entry, its
    /// padding, and any bytes already handed out but not consumed.
    fn skip_entry(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let total = self
            .entry_bytes_remaining
            .checked_add(self.entry_padding)
            .and_then(|t| t.checked_add(self.entry_bytes_unconsumed))
            .ok_or(Error::silent(ARCHIVE_FATAL))?;
        r.consume(total)?;
        self.entry_bytes_remaining = 0;
        self.entry_bytes_unconsumed = 0;
        self.entry_padding = 0;
        Ok(())
    }
}

/// `ar_parse_gnu_filename_table`: turns the `/\n` separators into NULs
/// (after mapping backslashes to '/') and checks the table's padding.
/// Returns false if the table is not a string table.
fn parse_gnu_filename_table(table: &mut [u8]) -> bool {
    // Upstream never looks at the last byte as a separator.
    let mut p = 0;
    while p + 1 < table.len() {
        if table[p] == b'\\' {
            table[p] = b'/';
        }
        if table[p] == b'/' && table[p + 1] == b'\n' {
            table[p] = 0;
            table[p + 1] = 0;
            p += 2;
        } else {
            p += 1;
        }
    }
    // GNU ar pads the table to an even size with '\n' or '`'; Windows
    // archives use NUL.
    let padded = p >= table.len() || matches!(table.get(p), Some(b'\n' | b'`' | 0));
    if !padded {
        return false;
    }
    if let Some(last) = table.last_mut() {
        *last = 0;
    }
    true
}

/// The C string `buf` holds: everything before its first NUL.
fn c_str(buf: &[u8]) -> &[u8] {
    buf.split(|&c| c == 0).next().unwrap_or_default()
}

/// One more digit or blank may be read. Upstream counts down with `char_cnt--`
/// on a `size_t`; the wrap it can cause never changes the result, because
/// the test that wraps always stops the loop on the same byte.
fn tick(left: &mut usize) -> bool {
    let go = *left > 0;
    *left = left.saturating_sub(1);
    go
}

/// `ar_atol8` and `ar_atol10`: skips blanks, then reads digits in `base`,
/// at most `count` of them (see `tick`). Overflow saturates to `u64::MAX`.
fn ar_atol(h: &[u8], mut p: usize, mut left: usize, base: u8) -> u64 {
    let at = |p: usize| h.get(p).copied().unwrap_or(0);
    while (at(p) == b' ' || at(p) == b'\t') && tick(&mut left) {
        p += 1;
    }
    let mut l: u64 = 0;
    loop {
        let digit = at(p).wrapping_sub(b'0');
        if !(digit < base && tick(&mut left)) {
            break;
        }
        match l
            .checked_mul(u64::from(base))
            .and_then(|v| v.checked_add(u64::from(digit)))
        {
            Some(v) => l = v,
            None => return u64::MAX,
        }
        p += 1;
    }
    l
}

#[cfg(test)]
mod tests {
    use super::ar_atol;

    #[test]
    fn digits_stop_at_the_field_and_saturate() {
        assert_eq!(ar_atol(b"  42  7", 0, 4, 10), 42);
        assert_eq!(ar_atol(b"      ", 0, 6, 10), 0);
        assert_eq!(ar_atol(b"123456789012345678901234", 0, 24, 10), u64::MAX);
    }
}
