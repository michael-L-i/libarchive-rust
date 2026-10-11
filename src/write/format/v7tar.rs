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

// Ported from libarchive/archive_write_set_format_v7tar.c.
use crate::archive::*;
use crate::entry::{AE_IFDIR, AE_IFLNK, AE_IFREG, Entry};
use crate::read::ARCHIVE_ERRNO_FILE_FORMAT;
use crate::string::{StringConv, conversion_charset_name};
use crate::util::Error;
use crate::write::format::ustar::{
    TYPEFLAG_OFFSET, add_trailing_slash, checksum, format_number, option_header_charset, template,
    translate_error,
};
use crate::write::{Format, Sink, unsupported, zeros};
use std::ffi::{CStr, c_int};
use std::sync::Arc;

const FORMAT_TAR: c_int = 0x30000;

#[derive(Default)]
pub struct V7tar {
    entry_bytes_remaining: u64,
    entry_padding: u64,
    opt_sconv: Option<Arc<StringConv>>,
}

// Define structure of 'v7tar' tar header.
const NAME_SIZE: usize = 100;
const LINKNAME_OFFSET: usize = 157;
const LINKNAME_SIZE: usize = 100;

/// A filled-in copy of the header for initialization.
const TEMPLATE_HEADER: [u8; 512] = template(&[
    (100, b"000000 \0"),    // mode, space-null termination
    (108, b"000000 \0"),    // uid, space-null termination
    (116, b"000000 \0"),    // gid, space-null termination
    (124, b"00000000000 "), // size, space termination
    (136, b"00000000000 "), // mtime, space termination
    (148, b"        "),     // initial checksum value: 8 spaces
]);

impl Format for V7tar {
    fn code(&self) -> c_int {
        FORMAT_TAR
    }
    fn name(&self) -> &'static CStr {
        c"tar (non-POSIX)"
    }
    fn module(&self) -> &'static [u8] {
        b"tar (non-POSIX)"
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
        let ret = format_header_v7tar(a, &mut buff, entry, true, sconv.as_deref());
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

/// Format a basic 512-byte "v7tar" header.
///
/// Returns `ARCHIVE_FAILED`, with the error set on `a`, if format failed
/// (due to field overflow). Note that this always formats as much of the
/// header as possible. If `strict` is false, it will extend numeric fields
/// as necessary (overwriting terminators or using base-256 extensions).
fn format_header_v7tar(
    a: &Base,
    h: &mut [u8; 512],
    entry: &mut Entry,
    strict: bool,
    sconv: Option<&StringConv>,
) -> c_int {
    let mut ret = ARCHIVE_OK;
    let mut mytartype = None;

    // The "template header" already includes the various end-of-field
    // markers and other required elements.
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
    if (strict && pp.len() < NAME_SIZE) || (!strict && pp.len() <= NAME_SIZE) {
        h[..pp.len()].copy_from_slice(&pp);
    } else {
        // Prefix is too long.
        a.set_error(libc::ENAMETOOLONG, Some(b"Pathname too long"));
        ret = ARCHIVE_FAILED;
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
        if copy_length >= LINKNAME_SIZE {
            a.set_error(libc::ENAMETOOLONG, Some(b"Link contents too long"));
            ret = ARCHIVE_FAILED;
            copy_length = LINKNAME_SIZE;
        }
        h[LINKNAME_OFFSET..LINKNAME_OFFSET + copy_length].copy_from_slice(&link[..copy_length]);
    }

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
            12,
            "File modification time too large",
        ),
    ];
    for (v, offset, size, max_size, msg) in numbers {
        if !format_number(v, &mut h[offset..], size, max_size, strict) {
            a.set_error(libc::ERANGE, Some(msg.as_bytes()));
            ret = ARCHIVE_FAILED;
        }
    }

    if let Some(t) = mytartype {
        h[TYPEFLAG_OFFSET] = t;
    } else {
        match entry.filetype() {
            AE_IFREG | AE_IFDIR => {}
            AE_IFLNK => h[TYPEFLAG_OFFSET] = b'2',
            // AE_IFBLK, AE_IFCHR, AE_IFIFO, AE_IFSOCK and unknown
            _ => {
                let e = unsupported(entry, b"v7tar");
                a.set_error(e.errno, Some(&e.msg));
                ret = ARCHIVE_FAILED;
            }
        }
    }

    checksum(h);
    ret
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
        let r = V7tar::default().header(&a, e, &mut out).unwrap();
        let msg = a.error_string().map_or(Vec::new(), |m| m.to_vec());
        (r, msg, out.0)
    }

    fn entry(path: &[u8], mode: crate::entry::Mode) -> Entry {
        let mut e = Entry::new(None);
        e.set_pathname(path);
        e.set_mode(mode);
        e
    }

    #[test]
    fn directories_have_no_typeflag_and_a_trailing_slash() {
        let mut e = entry(b"dir", 0o040755);
        let (r, _, h) = header(&mut e);
        assert_eq!((r, &h[..5], h[156]), (ARCHIVE_OK, b"dir/\0".as_slice(), 0));
        assert_eq!(e.pathname().unwrap().to_bytes(), b"dir/");
    }

    #[test]
    fn names_and_links_must_leave_room_for_a_nul() {
        let (r, msg, out) = header(&mut entry(&[b'n'; 100], 0o100644));
        assert_eq!(
            (r, msg.as_slice(), out.len()),
            (ARCHIVE_FAILED, b"Pathname too long".as_slice(), 0)
        );
        let mut e = entry(b"l", 0o120777);
        e.set_symlink(&[b't'; 100]);
        let (r, msg, _) = header(&mut e);
        assert_eq!(
            (r, msg.as_slice()),
            (ARCHIVE_FAILED, b"Link contents too long".as_slice())
        );
        let (r, msg, _) = header(&mut entry(b"t/fifo", 0o010644));
        assert_eq!(
            (r, msg.as_slice()),
            (
                ARCHIVE_FAILED,
                b"t/fifo: v7tar format cannot archive named pipes".as_slice()
            )
        );
    }

    #[test]
    fn options_are_named_after_the_format() {
        let mut v7 = V7tar::default();
        let e = v7
            .options(&Base::new(WRITE_MAGIC), b"hdrcharset", None)
            .unwrap_err();
        assert_eq!(
            e.msg,
            b"tar (non-POSIX): hdrcharset option needs a character-set name"
        );
    }
}
