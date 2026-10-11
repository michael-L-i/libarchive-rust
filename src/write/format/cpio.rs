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

// Ported from libarchive/archive_write_set_format_cpio_newc.c.
use crate::archive::*;
use crate::entry::{Dev, Entry};
use crate::string::StringConv;
use crate::util::Error;
use crate::write::{Format, Sink, zeros};
use std::collections::BTreeMap;
use std::ffi::{CStr, c_int};
use std::sync::Arc;
pub struct Cpio {
    pub variant: c_int,
    remaining: u64,
    padding: u64,
    next: u32,
    inos: BTreeMap<(Dev, Dev, i64), u32>,
    conv: Option<Arc<StringConv>>,
}
impl Cpio {
    pub fn new(variant: c_int) -> Self {
        Self {
            variant,
            remaining: 0,
            padding: 0,
            next: 0,
            inos: BTreeMap::new(),
            conv: None,
        }
    }
    fn inode(&mut self, e: &Entry) -> Result<u32, Error> {
        if e.ino() == 0 {
            return Ok(0);
        }
        let key = (e.devmajor(), e.devminor(), e.ino());
        if e.nlink() > 1
            && e.filetype() != 0o040000
            && let Some(n) = self.inos.get(&key)
        {
            return Ok(*n);
        }
        self.next = self.next.checked_add(1).ok_or_else(|| {
            Error::fatal(libc::ERANGE, "No available inode values for cpio format")
        })?;
        if e.nlink() > 1 && e.filetype() != 0o040000 {
            self.inos.insert(key, self.next);
        }
        Ok(self.next)
    }
    fn write_header(&mut self, e: &mut Entry, sink: &mut dyn Sink) -> Result<(), Error> {
        let (path, _) = e.pathname_l(self.conv.as_deref());
        let path = path.unwrap_or_default().to_vec();
        let (sym, _) = e.symlink_l(self.conv.as_deref());
        let sym = sym.unwrap_or_default().to_vec();
        if e.filetype() != 0o100000 {
            e.set_size(0);
        }
        let size = if sym.is_empty() {
            e.size()
        } else {
            sym.len() as i64
        };
        let ino = self.inode(e)?;
        let align = match self.variant {
            0x10004 => 4,
            0x10002 | 0x10006 => 2,
            _ => 1,
        };
        let mut h = Vec::new();
        if self.variant == 0x10004 {
            h.extend(b"070701");
            for v in [
                u64::from(ino),
                u64::from(e.mode()),
                e.uid() as u64,
                e.gid() as u64,
                u64::from(e.nlink()),
                e.mtime() as u64,
                size as u64,
                e.devmajor() as u64,
                e.devminor() as u64,
                if matches!(e.filetype(), 0o020000 | 0o060000) {
                    e.rdevmajor() as u64
                } else {
                    0
                },
                if matches!(e.filetype(), 0o020000 | 0o060000) {
                    e.rdevminor() as u64
                } else {
                    0
                },
                (path.len() + 1) as u64,
                0,
            ] {
                h.extend(format!("{:08x}", v as u32).as_bytes());
            }
            if size < 0 || size > u32::MAX as i64 {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    libc::ERANGE,
                    "File is too large for this format",
                ));
            }
        } else if self.variant == 0x10001 {
            for (v, n) in [
                (0o70707u64, 6),
                (e.dev() as u64, 6),
                (u64::from(ino), 6),
                (u64::from(e.mode()), 6),
                (e.uid() as u64, 6),
                (e.gid() as u64, 6),
                (u64::from(e.nlink()), 6),
                (e.rdev() as u64, 6),
                (e.mtime() as u64, 11),
                ((path.len() + 1) as u64, 6),
                (size as u64, 11),
            ] {
                h.extend(format!("{:0width$o}", v & ((1u64 << (n * 3)) - 1), width = n).as_bytes());
            }
            if !(0..=0o77777777777).contains(&size) {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    libc::ERANGE,
                    "File is too large for this format",
                ));
            }
        } else {
            if size < 0
                || size
                    > if self.variant == 0x10006 {
                        0xffffff
                    } else {
                        i32::MAX as i64
                    }
            {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    libc::ERANGE,
                    if self.variant == 0x10006 {
                        "File is too large for PWB binary cpio format"
                    } else {
                        "File is too large for binary cpio format"
                    },
                ));
            }
            // The header's fields are 16 bits; mode_t is too on macOS only.
            #[allow(clippy::unnecessary_cast)]
            let mode = e.mode() as u16;
            for v in [
                0o70707,
                e.dev() as u16,
                ino as u16,
                mode,
                e.uid() as u16,
                e.gid() as u16,
                e.nlink() as u16,
                e.rdev() as u16,
                (e.mtime() as u64 >> 16) as u16,
                e.mtime() as u16,
                (path.len() + 1) as u16,
                (size as u64 >> 16) as u16,
                size as u16,
            ] {
                h.extend(v.to_le_bytes());
            }
        }
        sink.write(&h)?;
        sink.write(&path)?;
        sink.write(&[0])?;
        zeros(
            sink,
            ((align - (h.len() + path.len() + 1) % align) % align) as u64,
        )?;
        self.remaining = e.size().max(0) as u64;
        self.padding = (align as u64 - self.remaining % align as u64) % align as u64;
        if !sym.is_empty() {
            sink.write(&sym)?;
            zeros(sink, ((align - sym.len() % align) % align) as u64)?;
        }
        Ok(())
    }
}
impl Format for Cpio {
    fn code(&self) -> c_int {
        self.variant
    }
    fn name(&self) -> &'static CStr {
        match self.variant {
            0x10004 => c"SVR4 cpio nocrc",
            0x10001 => c"POSIX cpio",
            0x10006 => c"PWB cpio",
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
    fn header(&mut self, _: &Base, e: &mut Entry, sink: &mut dyn Sink) -> Result<c_int, Error> {
        if e.filetype() == 0 && e.hardlink().is_none() {
            return Err(Error::new(ARCHIVE_FAILED, -1, "Filetype required"));
        }
        if e.pathname().is_none_or(|s| s.to_bytes().is_empty()) {
            return Err(Error::new(ARCHIVE_FAILED, -1, "Pathname required"));
        }
        if e.hardlink().is_none() && (e.size_is_set() == 0 || e.size() < 0) {
            return Err(Error::new(ARCHIVE_FAILED, -1, "Size required"));
        }
        self.write_header(e, sink)?;
        Ok(ARCHIVE_OK)
    }
    fn data(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<usize, Error> {
        let n = data.len().min(self.remaining as usize);
        sink.write(&data[..n])?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        zeros(sink, self.remaining)?;
        zeros(sink, self.padding)?;
        self.remaining = 0;
        self.padding = 0;
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        let mut trailer = Entry::new(None);
        trailer.set_pathname(b"TRAILER!!!");
        trailer.set_size(0);
        trailer.set_nlink(1);
        self.write_header(&mut trailer, sink)
    }
}
