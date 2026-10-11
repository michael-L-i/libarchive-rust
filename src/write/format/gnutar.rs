/*-
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
 * Author: Jonas Gastal <jgastal@profusion.mobi>
 * Copyright (c) 2011-2012 Michihiro NAKAJIMA
 *
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

// Ported from libarchive/archive_write_set_format_gnutar.c.
use crate::archive::*;
use crate::entry::{AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFREG, Entry};
use crate::read::ARCHIVE_ERRNO_FILE_FORMAT;
use crate::string::{StringConv, conversion_charset_name};
use crate::util::Error;
use crate::write::format::ustar::{
    TYPEFLAG_OFFSET, add_trailing_slash, checksum, format_256, option_header_charset, template,
    translate_error,
};
use crate::write::{Format, Sink, unsupported, zeros};
use std::ffi::{CStr, c_int};
use std::sync::Arc;

const FORMAT_TAR_GNUTAR: c_int = 0x30004;

#[derive(Default)]
pub struct Gnutar {
    entry_bytes_remaining: u64,
    entry_padding: u64,
    linkname: Vec<u8>,
    pathname: Vec<u8>,
    uname: Vec<u8>,
    gname: Vec<u8>,
    opt_sconv: Option<Arc<StringConv>>,
}

// Define structure of GNU tar header.
const NAME_SIZE: usize = 100;
const LINKNAME_OFFSET: usize = 157;
const LINKNAME_SIZE: usize = 100;
const UNAME_OFFSET: usize = 265;
const UNAME_SIZE: usize = 32;
const GNAME_OFFSET: usize = 297;
const GNAME_SIZE: usize = 32;

/// A filled-in copy of the header for initialization.
const TEMPLATE_HEADER: [u8; 512] = template(&[
    (100, b"0000000\0"),     // mode, null termination
    (108, b"0000000\0"),     // uid, null termination
    (116, b"0000000\0"),     // gid, null termination
    (124, b"00000000000\0"), // size, null termination
    (136, b"00000000000\0"), // mtime, null termination
    (148, b"        "),      // initial checksum value: 8 spaces
    (156, b"0"),             // typeflag: '0' = regular file
    (257, b"ustar  \0"),     // magic
]);

impl Gnutar {
    /// Writes a 'K' or 'L' header for a long link or path name, then the
    /// name and its trailing null byte.
    fn write_long_name(
        &self,
        a: &Base,
        sink: &mut dyn Sink,
        tartype: u8,
        name: &[u8],
    ) -> Result<c_int, Error> {
        let length = name.len() + 1;
        let mut temp = Entry::new(Some(a.conv.clone()));
        // Uname/gname here don't really matter since no one reads them;
        // these are the values that GNU tar happens to use on FreeBSD.
        temp.set_uname(b"root");
        temp.set_gname(b"wheel");
        temp.set_pathname(if tartype == b'K' {
            b"././@LongLink"
        } else {
            b"././@LongName"
        });
        temp.set_size(length as i64);
        let mut buff = [0u8; 512];
        let ret = self.format_header(a, &mut buff, &mut temp, tartype);
        if ret < ARCHIVE_WARN {
            return Ok(ret);
        }
        sink.write(&buff)?;
        // Write name and trailing null byte.
        sink.write(name)?;
        sink.write(&[0])?;
        // Pad to multiple of 512 bytes.
        zeros(sink, 0x1ff & (length as u64).wrapping_neg())?;
        Ok(ret)
    }

    fn format_header(&self, a: &Base, h: &mut [u8; 512], entry: &mut Entry, tartype: u8) -> c_int {
        let mut ret = ARCHIVE_OK;

        // The "template header" already includes the signature, various
        // end-of-field markers, and other required elements.
        *h = TEMPLATE_HEADER;

        let copy = |h: &mut [u8; 512], offset: usize, size: usize, p: &[u8]| {
            let copy_length = p.len().min(size);
            h[offset..offset + copy_length].copy_from_slice(&p[..copy_length]);
        };
        // TODO: How does GNU tar handle unames and gnames longer than
        // GNUTAR_uname_size and GNUTAR_gname_size?
        if matches!(tartype, b'K' | b'L') {
            let text = |p: Option<&CStr>| p.map_or(Vec::new(), |p| p.to_bytes().to_vec());
            copy(h, 0, NAME_SIZE, &text(entry.pathname()));
            copy(h, UNAME_OFFSET, UNAME_SIZE, &text(entry.uname()));
            copy(h, GNAME_OFFSET, GNAME_SIZE, &text(entry.gname()));
        } else {
            copy(h, 0, NAME_SIZE, &self.pathname);
            copy(h, UNAME_OFFSET, UNAME_SIZE, &self.uname);
            copy(h, GNAME_OFFSET, GNAME_SIZE, &self.gname);
        }
        copy(h, LINKNAME_OFFSET, LINKNAME_SIZE, &self.linkname);

        // By truncating the mode here, we ensure it always fits.
        format_octal(i64::from(entry.mode() & 0o7777), &mut h[100..], 7);
        // GNU tar supports base-256 here, so should never overflow.
        let ids = [(entry.uid(), 108, "user"), (entry.gid(), 116, "group")];
        for (v, offset, what) in ids {
            if !format_number(v, &mut h[offset..], 7, 8) {
                let msg = format!("Numeric {what} ID {v} too large for gnutar format");
                a.set_error(libc::ERANGE, Some(msg.as_bytes()));
                ret = ARCHIVE_FAILED;
            }
        }
        // GNU tar supports base-256 here, so should never overflow.
        if !format_number(entry.size(), &mut h[124..], 11, 12) {
            a.set_error(libc::ERANGE, Some(b"File size out of range"));
            ret = ARCHIVE_FAILED;
        }
        // Shouldn't overflow before 2106, since mtime field is 33 bits.
        format_octal(entry.mtime(), &mut h[136..], 11);

        if matches!(entry.filetype(), AE_IFBLK | AE_IFCHR) {
            let devices = [
                (entry.rdevmajor(), 329, "Major"),
                (entry.rdevminor(), 337, "Minor"),
            ];
            for (v, offset, what) in devices {
                if !format_octal(v as i64, &mut h[offset..], 6) {
                    let msg = format!("{what} device number too large for gnutar format");
                    a.set_error(libc::ERANGE, Some(msg.as_bytes()));
                    ret = ARCHIVE_FAILED;
                }
            }
        }

        h[TYPEFLAG_OFFSET] = tartype;
        checksum(h);
        ret
    }
}

impl Format for Gnutar {
    fn code(&self) -> c_int {
        FORMAT_TAR_GNUTAR
    }
    fn name(&self) -> &'static CStr {
        c"GNU tar"
    }
    fn module(&self) -> &'static [u8] {
        b"gnutar"
    }
    fn options(&mut self, a: &Base, key: &[u8], value: Option<&[u8]>) -> Result<c_int, Error> {
        option_header_charset(a, self.module(), key, value, &mut self.opt_sconv)
    }
    fn header(&mut self, a: &Base, entry: &mut Entry, sink: &mut dyn Sink) -> Result<c_int, Error> {
        let mut ret2 = ARCHIVE_OK;
        // The default conversion for writing is none on POSIX.
        let sconv = self.opt_sconv.clone();
        let sconv = sconv.as_deref();

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

        let (p, ok) = entry.pathname_l(sconv);
        self.pathname = p.unwrap_or_default().to_vec();
        if !ok {
            if let Some(p_mbs) = entry.pathname().map(|p| p.to_bytes().to_vec()) {
                // We have a wrongly-encoded MBS pathname. Warn and use it.
                translate_error(a, "pathname", Some(&p_mbs), sconv);
                ret2 = ARCHIVE_WARN;
            } else {
                // We have no MBS pathname. Fail.
                let msg = [
                    b"Can't translate pathname to ",
                    conversion_charset_name(sconv),
                ]
                .concat();
                a.set_error(ARCHIVE_ERRNO_FILE_FORMAT, Some(&msg));
                return Ok(ARCHIVE_FAILED);
            }
        }
        let (p, ok) = entry.uname_l(sconv);
        self.uname = p.unwrap_or_default().to_vec();
        if !ok {
            translate_error(a, "uname", entry.uname().map(CStr::to_bytes), sconv);
            ret2 = ARCHIVE_WARN;
        }
        let (p, ok) = entry.gname_l(sconv);
        self.gname = p.unwrap_or_default().to_vec();
        if !ok {
            translate_error(a, "gname", entry.gname().map(CStr::to_bytes), sconv);
            ret2 = ARCHIVE_WARN;
        }

        // If linkname is longer than 100 chars we need to add a 'K' header.
        let (p, ok) = entry.hardlink_l(sconv);
        self.linkname = p.unwrap_or_default().to_vec();
        if !ok {
            translate_error(a, "linkname", entry.hardlink().map(CStr::to_bytes), sconv);
            ret2 = ARCHIVE_WARN;
        }
        if self.linkname.is_empty() {
            let (p, ok) = entry.symlink_l(sconv);
            self.linkname = p.unwrap_or_default().to_vec();
            if !ok {
                // Upstream names the hardlink here, which is unset.
                translate_error(a, "linkname", entry.hardlink().map(CStr::to_bytes), sconv);
                ret2 = ARCHIVE_WARN;
            }
        }
        if self.linkname.len() > LINKNAME_SIZE {
            let ret = self.write_long_name(a, sink, b'K', &self.linkname.clone())?;
            if ret < ARCHIVE_WARN {
                return Ok(ret);
            }
        }

        // If pathname is longer than 100 chars we need to add an 'L' header.
        if self.pathname.len() > NAME_SIZE {
            let ret = self.write_long_name(a, sink, b'L', &self.pathname.clone())?;
            if ret < ARCHIVE_WARN {
                return Ok(ret);
            }
        }

        let tartype = if entry.hardlink_is_set() != 0 {
            b'1'
        } else {
            match entry.filetype() {
                AE_IFREG => b'0',
                AE_IFLNK => b'2',
                AE_IFCHR => b'3',
                AE_IFBLK => b'4',
                AE_IFDIR => b'5',
                AE_IFIFO => b'6',
                // AE_IFSOCK and unknown
                _ => return Err(unsupported(entry, b"gnutar")),
            }
        };

        let mut buff = [0u8; 512];
        let ret = self.format_header(a, &mut buff, entry, tartype);
        if ret < ARCHIVE_WARN {
            return Ok(ret);
        }
        sink.write(&buff)?;
        // A negative size formats as 0; upstream would then pad out 2^64
        // bytes less what was written.
        self.entry_bytes_remaining = u64::try_from(entry.size()).unwrap_or(0);
        self.entry_padding = 0x1ff & self.entry_bytes_remaining.wrapping_neg();
        Ok(ret.min(ret2))
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

/// Format a number into a field, falling back to base-256 if necessary.
fn format_number(v: i64, p: &mut [u8], s: usize, maxsize: usize) -> bool {
    let limit = 1i64 << (s * 3);
    if v < limit {
        return format_octal(v, p, s);
    }
    format_256(v, p, maxsize)
}

/// Format a number into the specified field using octal. False if it
/// didn't fit.
fn format_octal(v: i64, p: &mut [u8], s: usize) -> bool {
    // Octal values can't be negative, so use 0.
    let mut v = v.max(0);
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
    use crate::entry::Mode;

    struct Out(Vec<u8>);
    impl Sink for Out {
        fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.0.extend_from_slice(data);
            Ok(())
        }
    }

    fn header(e: &mut Entry) -> Vec<u8> {
        let mut out = Out(Vec::new());
        let r = Gnutar::default().header(&Base::new(WRITE_MAGIC), e, &mut out);
        assert_eq!(r, Ok(ARCHIVE_OK));
        out.0
    }

    /// An entry like those of the writer sweep's input tree.
    fn entry(path: &[u8], mode: Mode) -> Entry {
        let mut e = Entry::new(None);
        e.set_pathname(path);
        e.set_mode(mode);
        e.set_uid(501);
        e.set_gid(20);
        e.set_uname(b"michaelli");
        e.set_gname(b"staff");
        e.set_mtime(1_600_000_000, 0);
        e
    }

    // The expected blocks below are upstream bsdtar's output for the same
    // entries.

    #[test]
    fn long_link_gets_upstream_k_header() {
        let target = [b'x'; 120];
        let mut e = entry(b"t/sym_long", 0o120755);
        e.set_symlink(&target);
        let blocks = [
            template(&[
                (0, b"././@LongLink"),
                (
                    100,
                    b"0000000\x000000000\x000000000\x0000000000171\x0000000000000\x00041244\x00 K",
                ),
                (157, &target[..100]),
                (257, b"ustar  \x00root"),
                (297, b"wheel"),
            ]),
            template(&[(0, &target)]),
            template(&[
                (0, b"t/sym_long"),
                (
                    100,
                    b"0000755\x000000765\x000000024\x0000000000000\x0013727410000\x00042232\x00 2",
                ),
                (157, &target[..100]),
                (257, b"ustar  \x00michaelli"),
                (297, b"staff"),
            ]),
        ];
        assert_eq!(header(&mut e), blocks.concat());
    }

    #[test]
    fn long_name_gets_upstream_l_header() {
        let path = [b"t/".as_slice(), &[b'd'; 101]].concat();
        let mut e = entry(&path, 0o100644);
        e.set_size(4);
        let blocks = [
            template(&[
                (0, b"././@LongName"),
                (
                    100,
                    b"0000000\x000000000\x000000000\x0000000000150\x0000000000000\x00011665\x00 L",
                ),
                (257, b"ustar  \x00root"),
                (297, b"wheel"),
            ]),
            template(&[(0, &path)]),
            template(&[
                (0, &path[..100]),
                (
                    100,
                    b"0000644\x000000765\x000000024\x0000000000004\x0013727410000\x00034231\x00 0",
                ),
                (257, b"ustar  \x00michaelli"),
                (297, b"staff"),
            ]),
        ];
        assert_eq!(header(&mut e), blocks.concat());
    }

    #[test]
    fn out_of_range_times_and_ids_never_fail() {
        let mut e = entry(b"f", 0o100644);
        e.set_mtime(-1, 0);
        e.set_uid(-1);
        e.set_gid(1 << 21);
        let h = header(&mut e);
        assert_eq!(&h[108..124], b"0000000\x00\x80\x00\x00\x00\x00\x20\x00\x00");
        assert_eq!(&h[136..148], b"00000000000\x00");
        e.set_mtime(1 << 33, 0);
        assert_eq!(&header(&mut e)[136..148], b"77777777777\x00");
    }
}
