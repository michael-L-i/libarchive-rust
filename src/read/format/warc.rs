/*-
 * Copyright (c) 2014 Sebastian Freundt
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

// Ported from libarchive/archive_read_support_format_warc.c.

//! The WARC format: a sequence of records, each with a text header giving its
//! type, target URI, date and content length. Resource and response records
//! become regular files named after their target URI.

use crate::archive::*;
use crate::entry::{AE_IFREG, Entry};
use crate::read::{ARCHIVE_ERRNO_FILE_FORMAT, Data, Format, Read, Reader, Status, format_code};
use crate::util::Error;
use std::ffi::c_int;

/// Bytes of a record header probed for its version.
const HDR_PROBE_LEN: usize = 12;

#[derive(Default)]
struct Warc {
    /// Content length of the current record.
    cntlen: i64,
    /// Bytes processed from the current record.
    cntoff: i64,
}

/// `archive_read_support_format_warc`.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Warc::default()))
}

impl Format for Warc {
    fn name(&self) -> &'static str {
        "warc"
    }

    fn bid(&mut self, r: &mut Reader<'_>, _best_bid: c_int) -> Result<c_int, Error> {
        // A read error bids no, as upstream's NULL read-ahead does.
        let Ok(Some(head)) = r.read_ahead(HDR_PROBE_LEN) else {
            return Ok(-1);
        };
        if !(1200..=10000).contains(&read_version(head)) {
            return Ok(-1);
        }
        Ok(64)
    }

    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        loop {
            let Some(buf) = r.read_ahead(HDR_PROBE_LEN).map_err(|_| bad_header())? else {
                return Ok(Status::Eof);
            };
            let hdr = header_end(buf).ok_or_else(bad_header)?;

            // Only WARC 0.12 through WARC 1.0 are supported.
            let ver = read_version(hdr);
            if ver == 0 {
                return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Invalid record version"));
            } else if !(1200..=10000).contains(&ver) {
                let msg = format!(
                    "Unsupported record version: {}.{}",
                    ver / 10000,
                    (ver % 10000) / 100
                );
                return Err(Error::fatal(ARCHIVE_ERRNO_MISC, msg));
            }
            // This reader requires Content-Length and WARC-Date before
            // processing a record.
            let Some(cntlen) = read_length(hdr) else {
                return Err(Error::fatal(libc::EINVAL, "Bad content length"));
            };
            let Some(rtime) = read_date(hdr) else {
                return Err(Error::fatal(libc::EINVAL, "Bad record time"));
            };

            // Only resource and response records are exposed, and only with
            // a usable target URI; a URI ending in a slash names a directory.
            let target = if is_entry_type(hdr) {
                let uri = read_uri(hdr);
                (!uri.is_empty() && !uri.ends_with(b"/")).then(|| uri.to_vec())
            } else {
                None
            };
            // A Last-Modified record header is the mtime; WARC-Date is the ctime.
            let mtime = match target {
                Some(_) => read_last_modified(hdr).unwrap_or(rtime),
                None => 0,
            };

            let hlen = hdr.len();
            r.base().format.set(format_code::WARC);
            self.cntlen = cntlen;
            self.cntoff = 0;
            r.consume(hlen)?;

            match target {
                Some(path) => {
                    entry.set_filetype(u32::from(AE_IFREG));
                    entry.set_pathname(&path);
                    entry.set_size(cntlen);
                    entry.set_perm(0o644);
                    entry.set_ctime(rtime, 0);
                    entry.set_mtime(mtime, 0);
                    return Ok(Status::Ok);
                }
                // Skip this record body and look for the next one.
                None => self.skip_body(r)?,
            }
        }
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        if self.cntoff >= self.cntlen {
            return Ok(Data::Eof {
                offset: self.cntoff,
            });
        }

        let later = r.consume_later();
        let Some(data) = r.read_ahead(1)? else {
            return Err(Error::new(
                ARCHIVE_FATAL,
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Truncated WARC file data",
            ));
        };
        // Clamp reads to Content-Length.
        let left = usize::try_from(self.cntlen - self.cntoff).unwrap_or(usize::MAX);
        let n = left.min(data.len());
        let offset = self.cntoff;
        self.cntoff += i64::try_from(n).unwrap_or(i64::MAX);
        later.consume(n);
        Ok(Data::Block {
            data: data.get(..n).unwrap_or_default(),
            offset,
        })
    }

    fn read_data_skip(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        self.skip_body(r)?;
        Ok(Status::Ok)
    }
}

impl Warc {
    /// Skips the rest of the record's content and the separator after it.
    fn skip_body(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        if self.cntoff > self.cntlen {
            return Err(Error::silent(ARCHIVE_FATAL));
        }
        r.consume(self.cntlen - self.cntoff)?;
        // The \r\n\r\n separator is skipped without being checked.
        r.consume(4usize)?;
        self.cntlen = 0;
        self.cntoff = 0;
        Ok(())
    }
}

fn bad_header() -> Error {
    Error::fatal(ARCHIVE_ERRNO_MISC, "Bad record header")
}

/// The first occurrence of `needle` (not empty) in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The record header at the start of `buf`, up to and including its blank line.
fn header_end(buf: &[u8]) -> Option<&[u8]> {
    let end = find(buf, b"\r\n\r\n")? + 4;
    buf.get(..end)
}

/// The value of the header field that starts with `key` (a CRLF and the field
/// name), up to the CRLF that ends its line. `None` if either is missing.
fn header_value<'a>(hdr: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let rest = hdr.get(find(hdr, key)? + key.len()..)?;
    rest.get(..find(rest, b"\r\n")?)
}

fn skip_blanks(val: &[u8]) -> &[u8] {
    let n = val.iter().take_while(|&&b| b == b' ' || b == b'\t').count();
    val.get(n..).unwrap_or_default()
}

/// C `isspace` in the C locale.
fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// The version as `major * 10000 + minor * 100` (WARC/1.0 is 10000, WARC/0.12
/// is 1200), or 0 if there is no valid version.
fn read_version(buf: &[u8]) -> u32 {
    if buf.len() < 12 {
        return 0;
    }
    let Some(v) = buf.strip_prefix(b"WARC/") else {
        return 0;
    };
    let &[major, dot, minor1, minor2, ..] = v else {
        return 0;
    };
    let digit = |b: u8| b.is_ascii_digit();
    if !(digit(major) && dot == b'.' && digit(minor1)) {
        return 0;
    }
    // At most two digits in the minor version.
    let two_digits = digit(minor2);
    let mut ver = u32::from(major - b'0') * 10000;
    if two_digits {
        ver += u32::from(minor1 - b'0') * 1000 + u32::from(minor2 - b'0') * 100;
    } else {
        ver += u32::from(minor1 - b'0') * 100;
    }
    // Versions before WARC 0.12 end the version with a space or tab; WARC 0.12
    // and later with CRLF.
    let end = 8 + usize::from(two_digits);
    let ok = if ver >= 1200 {
        buf.get(end..end + 2) == Some(b"\r\n".as_slice())
    } else {
        matches!(buf.get(end), Some(b' ' | b'\t'))
    };
    if ok { ver } else { 0 }
}

/// Whether the record is a resource or response, the types that become
/// files. The other types are skipped.
fn is_entry_type(hdr: &[u8]) -> bool {
    header_value(hdr, b"\r\nWARC-Type:")
        .is_some_and(|val| matches!(skip_blanks(val), b"resource" | b"response"))
}

/// The path that a resource or response record's WARC-Target-URI names, or
/// empty if the URI can't be used.
fn read_uri(hdr: &[u8]) -> &[u8] {
    let Some(val) = header_value(hdr, b"\r\nWARC-Target-URI:") else {
        return &[];
    };
    let val = skip_blanks(val);
    let Some(sep) = find(val, b"://") else {
        return &[];
    };
    // Spaces inside a URI are not allowed.
    if val.iter().any(|&b| is_c_space(b)) {
        return &[];
    }
    // Require enough room for the shortest supported scheme.
    if sep < 3 {
        return &[];
    }
    let rest = val.get(sep + 3..).unwrap_or_default();
    // The scheme is matched by prefix, so "filex://" counts as file.
    let path = if val.starts_with(b"file") {
        rest
    } else if val.starts_with(b"http") || val.starts_with(b"ftp") {
        // Skip the domain and the first slash.
        match rest.iter().position(|&b| b == b'/') {
            Some(i) => rest.get(i + 1..).unwrap_or_default(),
            None => &[],
        }
    } else {
        return &[];
    };
    // Require a valid C string.
    if path.contains(&0) { &[] } else { path }
}

/// The Content-Length, if it is a plain decimal number that fits in an i64.
fn read_length(hdr: &[u8]) -> Option<i64> {
    let val = skip_blanks(header_value(hdr, b"\r\nContent-Length:")?);
    if val.is_empty() || !val.iter().all(u8::is_ascii_digit) {
        return None;
    }
    val.iter().try_fold(0i64, |len, &d| {
        len.checked_mul(10)?.checked_add(i64::from(d - b'0'))
    })
}

/// The WARC-Date, as seconds since the epoch.
fn read_date(hdr: &[u8]) -> Option<i64> {
    parse_zulu_time(header_value(hdr, b"\r\nWARC-Date:")?)
}

/// The Last-Modified, as seconds since the epoch.
fn read_last_modified(hdr: &[u8]) -> Option<i64> {
    parse_zulu_time(header_value(hdr, b"\r\nLast-Modified:")?)
}

/// Parses a whole field value of the form `YYYY-MM-DDThh:mm:ssZ`, with leading
/// blanks allowed. Upstream's `xstrpisotime` with its check that the value
/// ends there.
fn parse_zulu_time(value: &[u8]) -> Option<i64> {
    let mut pos = value
        .iter()
        .take_while(|&&b| b == b' ' || b == b'\t')
        .count();
    let year = strtoi_lim(value, &mut pos, 1583, 4095)?;
    expect(value, &mut pos, b'-')?;
    let month = strtoi_lim(value, &mut pos, 1, 12)?;
    expect(value, &mut pos, b'-')?;
    let day = strtoi_lim(value, &mut pos, 1, 31)?;
    expect(value, &mut pos, b'T')?;
    let hour = strtoi_lim(value, &mut pos, 0, 23)?;
    expect(value, &mut pos, b':')?;
    let min = strtoi_lim(value, &mut pos, 0, 59)?;
    expect(value, &mut pos, b':')?;
    let sec = strtoi_lim(value, &mut pos, 0, 60)?;
    expect(value, &mut pos, b'Z')?;
    if pos != value.len() {
        return None;
    }
    // timegm() normalizes the fields, so day 31 of a 30-day month is the next
    // month's first day, and second 60 is the next minute.
    let days = days_from_civil(year, month, 1) + day - 1;
    let time = days * 86400 + hour * 3600 + min * 60 + sec;
    // Upstream's time_t -1 is its error value, so it is reported as an error.
    (time != -1).then_some(time)
}

/// Parses an unsigned decimal in `llim..=ulim` at `*pos`, as upstream's
/// `strtoi_lim`. Digits are read while the value can still reach `ulim`.
fn strtoi_lim(s: &[u8], pos: &mut usize, llim: i64, ulim: i64) -> Option<i64> {
    let start = *pos;
    let mut res: i64 = 0;
    let mut rulim = ulim.max(10);
    while res * 10 <= ulim && rulim != 0 {
        let Some(c) = s.get(*pos).copied().filter(u8::is_ascii_digit) else {
            break;
        };
        res = res * 10 + i64::from(c - b'0');
        *pos += 1;
        rulim /= 10;
    }
    (*pos != start && (llim..=ulim).contains(&res)).then_some(res)
}

fn expect(s: &[u8], pos: &mut usize, want: u8) -> Option<()> {
    (s.get(*pos) == Some(&want)).then(|| *pos += 1)
}

/// Days from 1970-01-01 to the proleptic Gregorian date `y-m-d`.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
