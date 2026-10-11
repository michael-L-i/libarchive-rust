/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2006 Rudolf Marek SYSGO s.r.o.
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

// Ported from libarchive/archive_write_set_format_cpio_odc.c,
// archive_write_set_format_cpio_newc.c and
// archive_write_set_format_cpio_binary.c.
use crate::archive::*;
use crate::entry::{AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFREG, AE_IFSOCK, Entry};
use crate::read::ARCHIVE_ERRNO_FILE_FORMAT;
use crate::string::{StringConv, conversion_charset_name};
use crate::util::Error;
use crate::write::{Format, Sink, zeros};
use std::collections::HashMap;
use std::ffi::{CStr, c_int};
use std::sync::Arc;

const ODC: c_int = 0x10001;
const NEWC: c_int = 0x10004;
const PWB: c_int = 0x10007;

pub struct Cpio {
    pub variant: c_int,
    entry_bytes_remaining: u64,
    padding: u64,
    ino_next: i64,
    /// (devmajor, devminor, ino) to the synthetic value; odc and binary
    /// key on ino alone.
    ino_list: HashMap<(i64, i64, i64), i64>,
    conv: Option<Arc<StringConv>>,
}

/// format_octal (bits 3) and format_hex (bits 4): a value that doesn't fit
/// fills the field with its maximum, and the result says it overflowed.
fn format_number(v: i64, out: &mut [u8], bits: usize) -> bool {
    let max = (1i64 << (out.len() * bits)) - 1;
    let overflow = !(0..=max).contains(&v);
    let mut v = if overflow { max } else { v };
    for b in out.iter_mut().rev() {
        *b = b"0123456789abcdef"[(v & ((1 << bits) - 1)) as usize];
        v >>= bits;
    }
    overflow
}

impl Cpio {
    pub fn new(variant: c_int) -> Self {
        Self {
            variant,
            entry_bytes_remaining: 0,
            padding: 0,
            ino_next: 0,
            ino_list: HashMap::new(),
            conv: None,
        }
    }

    /// Ino values are as long as 64 bits on some systems; cpio format only
    /// allows 16 to 32 bits and relies on the ino values to identify
    /// hardlinked files. So, we can't merely "hash" the ino numbers since
    /// collisions would corrupt the archive. Instead, we generate synthetic
    /// ino values to store in the archive and maintain a map of original
    /// ino values to synthetic ones so we can preserve hardlink information.
    fn synthesize_ino_value(&mut self, e: &Entry) -> Result<i64, Error> {
        let ino = e.ino();
        let newc = self.variant == NEWC;
        // If no index number was given, don't assign one. In particular,
        // this handles the end-of-archive marker correctly by giving it a
        // zero index value. (This is also why we start our synthetic
        // index numbers with one below.)
        if ino == 0 {
            return Ok(0);
        }
        let exhausted = || Error::fatal(libc::ERANGE, "No available inode values for cpio format");
        // Directory link counts do not represent separate archive entries.
        if e.nlink() < 2 || (newc && e.filetype() == AE_IFDIR) {
            if newc && self.ino_next == i64::from(u32::MAX) {
                return Err(exhausted());
            }
            self.ino_next += 1;
            return Ok(self.ino_next);
        }
        let key = if newc {
            (e.devmajor() as i64, e.devminor() as i64, ino)
        } else {
            (0, 0, ino)
        };
        if let Some(&n) = self.ino_list.get(&key) {
            return Ok(n);
        }
        if newc && self.ino_next == i64::from(u32::MAX) {
            return Err(exhausted());
        }
        self.ino_list.try_reserve(1).map_err(|_| {
            Error::fatal(
                libc::ENOMEM,
                if newc {
                    "No memory for inode translation table"
                } else {
                    "No memory for ino translation table"
                },
            )
        })?;
        self.ino_next += 1;
        self.ino_list.insert(key, self.ino_next);
        Ok(self.ino_next)
    }

    /// The pathname (or symlink) in the header charset. A failed
    /// conversion only warns: the error is set and `ret` drops to WARN.
    fn converted(
        &self,
        a: Option<&Base>,
        e: &mut Entry,
        symlink: bool,
        ret: &mut c_int,
    ) -> Vec<u8> {
        let sc = self.conv.as_deref();
        let (text, ok) = if symlink {
            e.symlink_l(sc)
        } else {
            e.pathname_l(sc)
        };
        let text = text.unwrap_or_default().to_vec();
        if !ok {
            let (what, original) = if symlink {
                ("linkname", e.symlink().map(|s| s.to_bytes().to_vec()))
            } else {
                ("pathname", e.pathname().map(|s| s.to_bytes().to_vec()))
            };
            if let Some(a) = a {
                let msg = [
                    format!("Can't translate {what} '").as_bytes(),
                    original.as_deref().unwrap_or(b"(null)"),
                    b"' to ",
                    conversion_charset_name(sc),
                ]
                .concat();
                a.set_error(ARCHIVE_ERRNO_FILE_FORMAT, Some(&msg));
            }
            *ret = ARCHIVE_WARN;
        }
        text
    }

    fn write_header(
        &mut self,
        a: Option<&Base>,
        e: &mut Entry,
        sink: &mut dyn Sink,
    ) -> Result<c_int, Error> {
        match self.variant {
            ODC => self.write_header_odc(a, e, sink),
            NEWC => self.write_header_newc(a, e, sink),
            _ => self.write_header_binary(a, e, sink),
        }
    }

    fn write_header_odc(
        &mut self,
        a: Option<&Base>,
        e: &mut Entry,
        sink: &mut dyn Sink,
    ) -> Result<c_int, Error> {
        let mut ret = ARCHIVE_OK;
        let path = self.converted(a, e, false, &mut ret);
        // Include trailing null.
        let pathlength = path.len() + 1;
        let mut h = [0u8; 76];
        format_number(0o70707, &mut h[0..6], 3);
        format_number(e.dev() as i64, &mut h[6..12], 3);
        let ino = self.synthesize_ino_value(e)?;
        if ino > 0o777777 {
            return Err(Error::fatal(
                libc::ERANGE,
                "Too many files for this cpio format",
            ));
        }
        format_number(ino & 0o777777, &mut h[12..18], 3);
        // TODO: Set ret_final to ARCHIVE_WARN if any of these overflow.
        format_number(i64::from(e.mode()), &mut h[18..24], 3);
        format_number(e.uid(), &mut h[24..30], 3);
        format_number(e.gid(), &mut h[30..36], 3);
        format_number(i64::from(e.nlink()), &mut h[36..42], 3);
        let rdev = if matches!(e.filetype(), AE_IFBLK | AE_IFCHR) {
            e.rdev() as i64
        } else {
            0
        };
        format_number(rdev, &mut h[42..48], 3);
        format_number(e.mtime(), &mut h[48..59], 3);
        if format_number(pathlength as i64, &mut h[59..65], 3) {
            return Err(Error::new(
                ARCHIVE_FAILED,
                libc::ERANGE,
                "Filename is too long for cpio format",
            ));
        }
        // Non-regular files don't store bodies.
        if e.filetype() != AE_IFREG {
            e.set_size(0);
        }
        // Symlinks get the link written as the body of the entry.
        let symlink = self.converted(a, e, true, &mut ret);
        let size = if symlink.is_empty() {
            e.size()
        } else {
            symlink.len() as i64
        };
        if format_number(size, &mut h[65..76], 3) {
            return Err(Error::new(
                ARCHIVE_FAILED,
                libc::ERANGE,
                "File is too large for cpio format",
            ));
        }
        sink.write(&h)?;
        sink.write(&path)?;
        sink.write(&[0])?;
        self.entry_bytes_remaining = e.size() as u64;
        sink.write(&symlink)?;
        Ok(ret)
    }

    fn write_header_newc(
        &mut self,
        a: Option<&Base>,
        e: &mut Entry,
        sink: &mut dyn Sink,
    ) -> Result<c_int, Error> {
        let pad4 = |n: usize| (4 - n % 4) % 4;
        let mut ret = ARCHIVE_OK;
        let path = self.converted(a, e, false, &mut ret);
        // Include trailing null.
        let pathlength = path.len() + 1;
        let mut h = [0u8; 110];
        format_number(0x070701, &mut h[0..6], 4);
        format_number(e.devmajor() as i64, &mut h[62..70], 4);
        format_number(e.devminor() as i64, &mut h[70..78], 4);
        let ino = self.synthesize_ino_value(e)?;
        // TODO: Set ret_final to ARCHIVE_WARN if any of these overflow.
        format_number(ino, &mut h[6..14], 4);
        format_number(i64::from(e.mode()), &mut h[14..22], 4);
        format_number(e.uid(), &mut h[22..30], 4);
        format_number(e.gid(), &mut h[30..38], 4);
        format_number(i64::from(e.nlink()), &mut h[38..46], 4);
        let (rdevmajor, rdevminor) = if matches!(e.filetype(), AE_IFBLK | AE_IFCHR) {
            (e.rdevmajor() as i64, e.rdevminor() as i64)
        } else {
            (0, 0)
        };
        format_number(rdevmajor, &mut h[78..86], 4);
        format_number(rdevminor, &mut h[86..94], 4);
        format_number(e.mtime(), &mut h[46..54], 4);
        if format_number(pathlength as i64, &mut h[94..102], 4) {
            return Err(Error::new(
                ARCHIVE_FAILED,
                libc::ERANGE,
                "Filename is too long for cpio format",
            ));
        }
        format_number(0, &mut h[102..110], 4);
        // Non-regular files don't store bodies.
        if e.filetype() != AE_IFREG {
            e.set_size(0);
        }
        // Symlinks get the link written as the body of the entry.
        let symlink = self.converted(a, e, true, &mut ret);
        let size = if symlink.is_empty() {
            e.size()
        } else {
            symlink.len() as i64
        };
        if format_number(size, &mut h[54..62], 4) {
            return Err(Error::new(
                ARCHIVE_FAILED,
                libc::ERANGE,
                "File is too large for this format",
            ));
        }
        sink.write(&h)?;
        // Pad pathname to even length.
        sink.write(&path)?;
        sink.write(&[0])?;
        zeros(sink, pad4(pathlength + h.len()) as u64)?;
        self.entry_bytes_remaining = e.size() as u64;
        self.padding = pad4(e.size() as usize) as u64;
        if !symlink.is_empty() {
            sink.write(&symlink)?;
            zeros(sink, pad4(symlink.len()) as u64)?;
        }
        Ok(ret)
    }

    fn write_header_binary(
        &mut self,
        a: Option<&Base>,
        e: &mut Entry,
        sink: &mut dyn Sink,
    ) -> Result<c_int, Error> {
        let pwb = self.variant == PWB;
        let mut ret = ARCHIVE_OK;
        let path = self.converted(a, e, false, &mut ret);
        // Include trailing null.
        let pathlength = path.len() + 1;
        // 16-bit fields are little-endian, 32-bit ones PDP-endian (the
        // high half first).
        let pdp = |v: u32| [(v >> 16) as u16, v as u16];
        let dev = e.dev() as u16;
        let ino = self.synthesize_ino_value(e)?;
        if ino > 0o77777 {
            return Err(Error::fatal(
                libc::ERANGE,
                "Too many files for this cpio format",
            ));
        }
        if matches!(e.filetype(), AE_IFSOCK | AE_IFIFO) {
            return Err(Error::fatal(
                libc::EINVAL,
                "sockets and fifos cannot be represented in the binary cpio formats",
            ));
        }
        if pwb && e.filetype() == AE_IFLNK {
            // We could turn off AE_IFREG here, but it does no harm, and
            // allows v7 cpio to read the entry without confusion.
            return Err(Error::fatal(
                libc::EINVAL,
                "symbolic links cannot be represented in the PWB cpio format",
            ));
        }
        // mode_t is 16 bits on macOS only.
        #[allow(clippy::unnecessary_cast)]
        let mode = e.mode() as u16;
        let majmin = if matches!(e.filetype(), AE_IFBLK | AE_IFCHR) {
            e.rdev() as u16
        } else {
            0
        };
        if pathlength > 0xffff {
            return Err(Error::new(
                ARCHIVE_FAILED,
                libc::ERANGE,
                "Filename is too long for cpio format",
            ));
        }
        // Non-regular files don't store bodies.
        if e.filetype() != AE_IFREG {
            e.set_size(0);
        }
        // Symlinks get the link written as the body of the entry.
        let symlink = self.converted(a, e, true, &mut ret);
        let filesize = if !symlink.is_empty() {
            if pwb {
                return Err(Error::fatal(
                    libc::EINVAL,
                    "symlinks are not supported by UNIX V6 or by PWB cpio",
                ));
            }
            symlink.len() as u32
        } else if pwb && e.size() > 256 * 256 * 256 - 1 {
            return Err(Error::new(
                ARCHIVE_FAILED,
                libc::ERANGE,
                "File is too large for PWB binary cpio format",
            ));
        } else if e.size() > i64::from(i32::MAX) {
            return Err(Error::new(
                ARCHIVE_FAILED,
                libc::ERANGE,
                "File is too large for binary cpio format",
            ));
        } else {
            e.size() as u32
        };
        let mut h = Vec::with_capacity(26);
        let [mtime_hi, mtime_lo] = pdp(e.mtime() as u32);
        let [size_hi, size_lo] = pdp(filesize);
        for v in [
            0o70707,
            dev,
            ino as u16,
            mode,
            e.uid() as u16,
            e.gid() as u16,
            e.nlink() as u16,
            majmin,
            mtime_hi,
            mtime_lo,
            pathlength as u16,
            size_hi,
            size_lo,
        ] {
            h.extend(v.to_le_bytes());
        }
        sink.write(&h)?;
        sink.write(&path)?;
        sink.write(&[0])?;
        zeros(sink, (pathlength % 2) as u64)?;
        self.entry_bytes_remaining = e.size() as u64;
        self.entry_bytes_remaining += self.entry_bytes_remaining % 2;
        if !symlink.is_empty() {
            sink.write(&symlink)?;
            zeros(sink, (symlink.len() % 2) as u64)?;
        }
        Ok(ret)
    }
}

impl Format for Cpio {
    fn code(&self) -> c_int {
        self.variant
    }
    fn name(&self) -> &'static CStr {
        match self.variant {
            NEWC => c"SVR4 cpio nocrc",
            ODC => c"POSIX cpio",
            PWB => c"PWB cpio",
            _ => c"7th Edition cpio",
        }
    }
    fn module(&self) -> &'static [u8] {
        b"cpio"
    }
    fn options(&mut self, a: &Base, k: &[u8], v: Option<&[u8]>) -> Result<c_int, Error> {
        if k != b"hdrcharset" {
            return Ok(ARCHIVE_WARN);
        }
        let v = v.filter(|v| !v.is_empty()).ok_or_else(|| {
            Error::new(
                ARCHIVE_FAILED,
                -1,
                "cpio: hdrcharset option needs a character-set name",
            )
        })?;
        let mut c = a
            .conv
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.conv = Some(
            crate::string::conversion_to_charset(Some(&mut c), v, false)
                .map_err(|e| Error::fatal(e.errno, e.message))?,
        );
        Ok(ARCHIVE_OK)
    }
    fn header(&mut self, a: &Base, e: &mut Entry, sink: &mut dyn Sink) -> Result<c_int, Error> {
        if e.filetype() == 0 && e.hardlink().is_none() {
            return Err(Error::new(ARCHIVE_FAILED, -1, "Filetype required"));
        }
        if e.pathname_l(self.conv.as_deref())
            .0
            .is_none_or(<[u8]>::is_empty)
        {
            return Err(Error::new(ARCHIVE_FAILED, -1, "Pathname required"));
        }
        // newc alone lets a hardlink go without a size.
        if (self.variant != NEWC || e.hardlink().is_none())
            && (e.size_is_set() == 0 || e.size() < 0)
        {
            return Err(Error::new(ARCHIVE_FAILED, -1, "Size required"));
        }
        self.write_header(Some(a), e, sink)
    }
    fn data(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<usize, Error> {
        let n = data.len().min(self.entry_bytes_remaining as usize);
        sink.write(&data[..n])?;
        self.entry_bytes_remaining -= n as u64;
        Ok(n)
    }
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        zeros(sink, self.entry_bytes_remaining + self.padding)
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        let mut trailer = Entry::new(None);
        // nlink = 1 here for GNU cpio compat.
        trailer.set_nlink(1);
        trailer.set_size(0);
        trailer.set_pathname(b"TRAILER!!!");
        self.write_header(None, &mut trailer, sink).map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Mode;

    struct Output(Vec<u8>);
    impl Sink for Output {
        fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.0.extend_from_slice(data);
            Ok(())
        }
    }

    fn entry(path: &[u8], filetype: Mode) -> Entry {
        let mut e = Entry::new(None);
        e.set_pathname(path);
        e.set_filetype(filetype.into());
        e.set_perm(0o644);
        e.set_size(0);
        e.set_mtime(1600000000, 0);
        e
    }

    fn header(cpio: &mut Cpio, e: &mut Entry) -> (Result<c_int, Error>, Vec<u8>) {
        let mut out = Output(Vec::new());
        let r = cpio.header(&Base::new(WRITE_MAGIC), e, &mut out);
        (r, out.0)
    }

    // Upstream's bytes for s/hugeuid and s/mtime_neg of the sweep's
    // src.tar: a field that overflows holds its maximum.
    #[test]
    fn odc_and_newc_saturate_fields_that_overflow() {
        let mut e = entry(b"s/hugeuid", AE_IFREG);
        e.set_size(1);
        e.set_uid((1 << 32) + 7);
        e.set_gid(3 << 31);
        e.set_dev(1);
        e.set_ino(1);
        let (r, h) = header(&mut Cpio::new(ODC), &mut e);
        assert_eq!(r, Ok(ARCHIVE_OK));
        assert_eq!(
            h,
            b"0707070000010000011006447777777777770000000000001372741000000001200000000001s/hugeuid\0"
        );
        let mut e = entry(b"s/mtime_neg", AE_IFREG);
        e.set_mtime(-(1 << 34), 0);
        e.set_ino(1);
        let (_, h) = header(&mut Cpio::new(ODC), &mut e);
        assert_eq!(&h[48..59], b"77777777777");
        let (_, h) = header(&mut Cpio::new(NEWC), &mut e);
        assert_eq!(&h[46..54], b"ffffffff");
    }

    #[test]
    fn newc_maps_hardlinks_by_device_and_inode_but_not_directories() {
        let mut cpio = Cpio::new(NEWC);
        let mut ino = |filetype, devminor, nlink| {
            let mut e = entry(b"x", filetype);
            e.set_devminor(devminor);
            e.set_ino(7);
            e.set_nlink(nlink);
            let (r, h) = header(&mut cpio, &mut e);
            assert_eq!(r, Ok(ARCHIVE_OK));
            h[6..14].to_vec()
        };
        assert_eq!(ino(AE_IFREG, 1, 2), b"00000001");
        assert_eq!(ino(AE_IFREG, 1, 2), b"00000001");
        assert_eq!(ino(AE_IFREG, 2, 2), b"00000002");
        assert_eq!(ino(AE_IFDIR, 1, 3), b"00000003");
        assert_eq!(ino(AE_IFDIR, 1, 3), b"00000004");
        assert_eq!(ino(AE_IFREG, 1, 1), b"00000005");
    }

    #[test]
    fn binary_formats_refuse_fifos_and_pwb_refuses_symlinks() {
        for variant in [0x10002, PWB] {
            let (r, h) = header(&mut Cpio::new(variant), &mut entry(b"t/fifo", AE_IFIFO));
            assert_eq!(
                r,
                Err(Error::fatal(
                    libc::EINVAL,
                    "sockets and fifos cannot be represented in the binary cpio formats"
                ))
            );
            assert!(h.is_empty());
        }
        let mut e = entry(b"l", AE_IFLNK);
        e.set_symlink(b"target");
        let (r, _) = header(&mut Cpio::new(PWB), &mut e);
        assert_eq!(
            r,
            Err(Error::fatal(
                libc::EINVAL,
                "symbolic links cannot be represented in the PWB cpio format"
            ))
        );
        let (r, h) = header(&mut Cpio::new(0x10002), &mut e);
        assert_eq!(r, Ok(ARCHIVE_OK));
        // Name and link are padded to even lengths; the size is PDP-endian.
        assert_eq!(&h[22..26], &[0, 0, 6, 0]);
        assert_eq!(&h[26..], b"l\0target");
    }
}
