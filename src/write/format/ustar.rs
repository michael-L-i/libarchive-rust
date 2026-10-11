/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2011-2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_write_set_format_ustar.c.
use crate::archive::*;
use crate::entry::{AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFREG, Entry};
use crate::read::ARCHIVE_ERRNO_FILE_FORMAT;
use crate::string::{StringConv, conversion_charset_name, conversion_to_charset};
use crate::util::Error;
use crate::write::{Format, Sink, unsupported, zeros};
use std::ffi::{CStr, c_int};
use std::sync::{Arc, PoisonError};

const FORMAT_TAR_USTAR: c_int = 0x30001;

#[derive(Default)]
pub struct Ustar {
    entry_bytes_remaining: u64,
    entry_padding: u64,
    opt_sconv: Option<Arc<StringConv>>,
}

// Define structure of POSIX 'ustar' tar header.
const NAME_SIZE: usize = 100;
const LINKNAME_OFFSET: usize = 157;
const LINKNAME_SIZE: usize = 100;
const UNAME_OFFSET: usize = 265;
const UNAME_SIZE: usize = 32;
const GNAME_OFFSET: usize = 297;
const GNAME_SIZE: usize = 32;
const PREFIX_OFFSET: usize = 345;
const PREFIX_SIZE: usize = 155;
pub(crate) const TYPEFLAG_OFFSET: usize = 156;
pub(crate) const CHECKSUM_OFFSET: usize = 148;

/// A header block with `fields` (offset, bytes) filled in; the rest is NUL.
pub(crate) const fn template(fields: &[(usize, &[u8])]) -> [u8; 512] {
    let mut h = [0u8; 512];
    let mut i = 0;
    while i < fields.len() {
        let (offset, bytes) = fields[i];
        let mut j = 0;
        while j < bytes.len() {
            h[offset + j] = bytes[j];
            j += 1;
        }
        i += 1;
    }
    h
}

/// A filled-in copy of the header for initialization.
const TEMPLATE_HEADER: [u8; 512] = template(&[
    (100, b"000000 \0"),    // mode, space-null termination
    (108, b"000000 \0"),    // uid, space-null termination
    (116, b"000000 \0"),    // gid, space-null termination
    (124, b"00000000000 "), // size, space termination
    (136, b"00000000000 "), // mtime, space termination
    (148, b"        "),     // initial checksum value: 8 spaces
    (156, b"0"),            // typeflag: '0' = regular file
    (257, b"ustar\x0000"),  // magic, version
    (329, b"000000 \0"),    // rdevmajor, space-null padding
    (337, b"000000 \0"),    // rdevminor, space-null padding
]);

/// `__archive_write_option_header_charset`.
pub(crate) fn option_header_charset(
    a: &Base,
    format_name: &[u8],
    key: &[u8],
    val: Option<&[u8]>,
    opt_sconv: &mut Option<Arc<StringConv>>,
) -> Result<c_int, Error> {
    if key != b"hdrcharset" {
        return Ok(ARCHIVE_WARN);
    }
    let Some(val) = val.filter(|v| !v.is_empty()) else {
        return Err(Error::new(
            ARCHIVE_FAILED,
            ARCHIVE_ERRNO_MISC,
            [
                format_name,
                b": hdrcharset option needs a character-set name",
            ]
            .concat(),
        ));
    };
    let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
    let r = conversion_to_charset(Some(&mut cache), val, false);
    *opt_sconv = r.as_ref().ok().cloned();
    r.map(|_| ARCHIVE_OK)
        .map_err(|e| Error::fatal(e.errno, e.message))
}

/// Records "Can't translate <what> '<name>' to <charset>" on the archive.
pub(crate) fn translate_error(
    a: &Base,
    what: &str,
    name: Option<&[u8]>,
    sconv: Option<&StringConv>,
) {
    let msg = [
        b"Can't translate ",
        what.as_bytes(),
        b" '",
        name.unwrap_or(b"(null)"),
        b"' to ",
        conversion_charset_name(sconv),
    ]
    .concat();
    a.set_error(ARCHIVE_ERRNO_FILE_FORMAT, Some(&msg));
}

/// Ensure a directory's pathname ends in '/'. Modify the entry so the
/// client sees the change.
pub(crate) fn add_trailing_slash(entry: &mut Entry) {
    if let Some(p) = entry.pathname().map(|p| p.to_bytes().to_vec())
        && !p.is_empty()
        && !p.ends_with(b"/")
    {
        entry.set_pathname(&[&p, b"/".as_slice()].concat());
    }
}

impl Format for Ustar {
    fn code(&self) -> c_int {
        FORMAT_TAR_USTAR
    }
    fn name(&self) -> &'static CStr {
        c"POSIX ustar"
    }
    fn module(&self) -> &'static [u8] {
        b"ustar"
    }
    fn options(&mut self, a: &Base, key: &[u8], value: Option<&[u8]>) -> Result<c_int, Error> {
        option_header_charset(a, self.module(), key, value, &mut self.opt_sconv)
    }
    fn header(&mut self, a: &Base, entry: &mut Entry, sink: &mut dyn Sink) -> Result<c_int, Error> {
        // The default conversion for writing is none on POSIX.
        let sconv = self.opt_sconv.clone();
        // Sanity check.
        if entry.pathname().is_none() {
            return Err(Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_MISC,
                "Can't record entry in tar file without pathname",
            ));
        }
        // Only regular files (not hardlinks) have data.
        if entry.hardlink().is_some() || entry.symlink().is_some() || entry.filetype() != AE_IFREG {
            entry.set_size(0);
        }
        if entry.filetype() == AE_IFDIR {
            add_trailing_slash(entry);
        }
        let mut buff = [0u8; 512];
        let ret = format_header_ustar(a, &mut buff, entry, None, true, sconv.as_deref());
        if ret < ARCHIVE_WARN {
            return Ok(ret);
        }
        sink.write(&buff)?;
        // A strict header has a size field that fits, so it isn't negative.
        self.entry_bytes_remaining = entry.size() as u64;
        self.entry_padding = 0x1ff & self.entry_bytes_remaining.wrapping_neg();
        Ok(ret)
    }
    fn data(&mut self, buff: &[u8], sink: &mut dyn Sink) -> Result<usize, Error> {
        let s = buff.len().min(self.entry_bytes_remaining as usize);
        sink.write(&buff[..s])?;
        self.entry_bytes_remaining -= s as u64;
        Ok(s)
    }
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        let r = zeros(sink, self.entry_bytes_remaining + self.entry_padding);
        self.entry_bytes_remaining = 0;
        self.entry_padding = 0;
        r
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        zeros(sink, 512 * 2)
    }
}

/// Format a basic 512-byte "ustar" header.
///
/// Returns `ARCHIVE_FAILED`, with the error set on `a`, if format failed
/// (due to field overflow). Note that this always formats as much of the
/// header as possible. If `strict` is false, it will extend numeric fields
/// as necessary (overwriting terminators or using base-256 extensions).
///
/// This is exported so that other 'tar' formats can use it.
pub(crate) fn format_header_ustar(
    a: &Base,
    h: &mut [u8; 512],
    entry: &mut Entry,
    tartype: Option<u8>,
    strict: bool,
    sconv: Option<&StringConv>,
) -> c_int {
    let mut ret = ARCHIVE_OK;
    let mut mytartype = None;

    // The "template header" already includes the "ustar" signature,
    // various end-of-field markers and other required elements.
    *h = TEMPLATE_HEADER;

    let (pp, ok) = entry.pathname_l(sconv);
    let pp = pp.unwrap_or_default().to_vec();
    if !ok {
        if let Some(p_mbs) = entry.pathname().map(|p| p.to_bytes().to_vec()) {
            // We have a wrongly-encoded MBS pathname. Warn and use it.
            translate_error(a, "pathname", Some(&p_mbs), sconv);
            ret = ARCHIVE_WARN;
        } else {
            // We have no MBS pathname. Fail.
            let msg = [
                b"Can't translate pathname to ",
                conversion_charset_name(sconv),
            ]
            .concat();
            a.set_error(ARCHIVE_ERRNO_FILE_FORMAT, Some(&msg));
            return ARCHIVE_FAILED;
        }
    }
    if pp.len() <= NAME_SIZE {
        h[..pp.len()].copy_from_slice(&pp);
    } else {
        // Store in two pieces, splitting at a '/'.
        let slash = |from: usize| pp[from..].iter().position(|&b| b == b'/').map(|i| from + i);
        let mut p = slash(pp.len() - NAME_SIZE - 1);
        // Look for the next '/' if we chose the first character as the
        // separator. (ustar format doesn't permit an empty prefix.)
        if p == Some(0) {
            p = slash(1);
        }
        match p {
            // Fail if the name won't fit: no separator; the only feasible
            // separator is a final '/', which would result in a non-empty
            // prefix and an empty name (POSIX doesn't explicitly forbid it,
            // but it just feels wrong); or the prefix is too long.
            Some(p) if p + 1 < pp.len() && p <= PREFIX_SIZE => {
                // Copy prefix and remainder to appropriate places.
                h[PREFIX_OFFSET..PREFIX_OFFSET + p].copy_from_slice(&pp[..p]);
                h[..pp.len() - p - 1].copy_from_slice(&pp[p + 1..]);
            }
            _ => {
                a.set_error(libc::ENAMETOOLONG, Some(b"Pathname too long"));
                ret = ARCHIVE_FAILED;
            }
        }
    }

    let (p, ok) = entry.hardlink_l(sconv);
    let mut link = p.unwrap_or_default().to_vec();
    if !ok {
        translate_error(a, "linkname", p, sconv);
        ret = ARCHIVE_WARN;
    }
    if !link.is_empty() {
        mytartype = Some(b'1');
    } else {
        let (p, ok) = entry.symlink_l(sconv);
        link = p.unwrap_or_default().to_vec();
        if !ok {
            translate_error(a, "linkname", p, sconv);
            ret = ARCHIVE_WARN;
        }
    }
    if !link.is_empty() {
        let mut copy_length = link.len();
        if copy_length > LINKNAME_SIZE {
            a.set_error(libc::ENAMETOOLONG, Some(b"Link contents too long"));
            ret = ARCHIVE_FAILED;
            copy_length = LINKNAME_SIZE;
        }
        h[LINKNAME_OFFSET..LINKNAME_OFFSET + copy_length].copy_from_slice(&link[..copy_length]);
    }

    let mut copy_name = |(p, ok): (Option<&[u8]>, bool), what, offset, size, too_long: &[u8]| {
        if !ok {
            translate_error(a, what, p, sconv);
            ret = ARCHIVE_WARN;
        }
        let p = p.unwrap_or_default();
        if !p.is_empty() {
            let mut copy_length = p.len();
            if copy_length > size {
                if tartype != Some(b'x') {
                    a.set_error(ARCHIVE_ERRNO_MISC, Some(too_long));
                    ret = ARCHIVE_FAILED;
                }
                copy_length = size;
            }
            h[offset..offset + copy_length].copy_from_slice(&p[..copy_length]);
        }
    };
    copy_name(
        entry.uname_l(sconv),
        "uname",
        UNAME_OFFSET,
        UNAME_SIZE,
        b"Username too long",
    );
    copy_name(
        entry.gname_l(sconv),
        "gname",
        GNAME_OFFSET,
        GNAME_SIZE,
        b"Group name too long",
    );

    let numbers = [
        (
            i64::from(entry.mode() & 0o7777),
            100,
            6,
            8,
            "Numeric mode too large",
        ),
        (entry.uid(), 108, 6, 8, "Numeric user ID too large"),
        (entry.gid(), 116, 6, 8, "Numeric group ID too large"),
        (entry.size(), 124, 11, 12, "File size out of range"),
        (
            entry.mtime(),
            136,
            11,
            11,
            "File modification time too large",
        ),
    ];
    for (v, offset, size, max_size, msg) in numbers {
        if !format_number(v, &mut h[offset..], size, max_size, strict) {
            a.set_error(libc::ERANGE, Some(msg.as_bytes()));
            ret = ARCHIVE_FAILED;
        }
    }
    if matches!(entry.filetype(), AE_IFBLK | AE_IFCHR) {
        let devices = [
            (entry.rdevmajor(), 329, "Major device number too large"),
            (entry.rdevminor(), 337, "Minor device number too large"),
        ];
        for (v, offset, msg) in devices {
            if !format_number(v as i64, &mut h[offset..], 6, 8, strict) {
                a.set_error(libc::ERANGE, Some(msg.as_bytes()));
                ret = ARCHIVE_FAILED;
            }
        }
    }

    if let Some(t) = tartype.or(mytartype) {
        h[TYPEFLAG_OFFSET] = t;
    } else {
        h[TYPEFLAG_OFFSET] = match entry.filetype() {
            AE_IFREG => b'0',
            AE_IFLNK => b'2',
            AE_IFCHR => b'3',
            AE_IFBLK => b'4',
            AE_IFDIR => b'5',
            AE_IFIFO => b'6',
            // AE_IFSOCK and unknown
            _ => {
                let e = unsupported(entry, b"ustar");
                a.set_error(e.errno, Some(&e.msg));
                ret = ARCHIVE_FAILED;
                b'0'
            }
        };
    }

    checksum(h);
    ret
}

/// Sets the checksum of a header whose checksum field holds 8 spaces.
pub(crate) fn checksum(h: &mut [u8; 512]) {
    let checksum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    // Can't be pre-set in the template.
    h[CHECKSUM_OFFSET + 6] = 0;
    format_octal(i64::from(checksum), &mut h[CHECKSUM_OFFSET..], 6);
}

/// Format a number into a field, with some intelligence. False if it
/// didn't fit.
pub(crate) fn format_number(
    v: i64,
    p: &mut [u8],
    mut s: usize,
    maxsize: usize,
    strict: bool,
) -> bool {
    let mut limit: i64 = 1 << (s * 3);
    // "Strict" only permits octal values with proper termination.
    if strict {
        return format_octal(v, p, s);
    }
    // In non-strict mode, we allow the number to overwrite one or more
    // bytes of the field termination. Even old tar implementations should
    // be able to handle this with no problem.
    if v >= 0 {
        while s <= maxsize {
            if v < limit {
                return format_octal(v, p, s);
            }
            s += 1;
            limit <<= 3;
        }
    }
    // Base-256 can handle any number, positive or negative.
    format_256(v, p, maxsize)
}

/// Format a number into the specified field using base-256.
pub(crate) fn format_256(mut v: i64, p: &mut [u8], s: usize) -> bool {
    for b in p[..s].iter_mut().rev() {
        *b = v as u8;
        v >>= 8;
    }
    // Set the base-256 marker bit.
    p[0] |= 0x80;
    true
}

/// Format a number into the specified field. False if it didn't fit.
fn format_octal(mut v: i64, p: &mut [u8], s: usize) -> bool {
    // Octal values can't be negative, so use 0.
    if v < 0 {
        p[..s].fill(b'0');
        return false;
    }
    // Start at the end and work backwards.
    for b in p[..s].iter_mut().rev() {
        *b = b'0' + (v & 7) as u8;
        v >>= 3;
    }
    if v == 0 {
        return true;
    }
    // If it overflowed, fill field with max value.
    p[..s].fill(b'7');
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Out(Vec<u8>);
    impl Sink for Out {
        fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.0.extend_from_slice(data);
            Ok(())
        }
    }

    fn header(e: &mut Entry) -> (c_int, Vec<u8>, Vec<u8>) {
        let a = Base::new(WRITE_MAGIC);
        let mut out = Out(Vec::new());
        let r = Ustar::default().header(&a, e, &mut out).unwrap();
        let msg = a.error_string().map_or(Vec::new(), |m| m.to_vec());
        (r, msg, out.0)
    }

    fn entry(path: &[u8]) -> Entry {
        let mut e = Entry::new(None);
        e.set_pathname(path);
        e.set_mode(0o100644);
        e
    }

    // Upstream formats every field and reports the last failure.
    #[test]
    fn last_field_error_wins() {
        let mut e = entry(b"s/biguid");
        e.set_uid(1 << 21);
        e.set_gid((1 << 21) + 1);
        let (r, msg, out) = header(&mut e);
        assert_eq!(
            (r, msg.as_slice(), out.len()),
            (ARCHIVE_FAILED, b"Numeric group ID too large".as_slice(), 0)
        );

        let mut e = entry(b"s/longuname");
        e.set_uname(&[b'u'; 40]);
        e.set_gname(&[b'g'; 40]);
        let (r, msg, _) = header(&mut e);
        assert_eq!(
            (r, msg.as_slice()),
            (ARCHIVE_FAILED, b"Group name too long".as_slice())
        );
    }

    #[test]
    fn long_names_split_at_a_slash_or_fail() {
        let path = [b"t/".as_slice(), &[b'e'; 60], b"/", &[b'f'; 92]].concat();
        let (r, _, out) = header(&mut entry(&path));
        assert_eq!(r, ARCHIVE_OK);
        assert_eq!(&out[..92], &[b'f'; 92]);
        assert_eq!(&out[345..345 + 62], &path[..62]);

        let path = [b"t/".as_slice(), &[b'd'; 101]].concat();
        let (r, msg, _) = header(&mut entry(&path));
        assert_eq!(
            (r, msg.as_slice()),
            (ARCHIVE_FAILED, b"Pathname too long".as_slice())
        );
    }

    #[test]
    fn numbers_extend_like_upstream() {
        let mut field = [0u8; 12];
        assert!(format_number(-1, &mut field, 11, 11, false));
        assert_eq!(
            &field[..11],
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        );
        assert!(format_number(0o777777777777, &mut field, 11, 12, false));
        assert_eq!(&field, b"777777777777");
        assert!(!format_number(-1, &mut field, 6, 8, true));
        assert_eq!(&field[..6], b"000000");
        assert!(!format_number(1 << 18, &mut field, 6, 8, true));
        assert_eq!(&field[..6], b"777777");
    }
}
