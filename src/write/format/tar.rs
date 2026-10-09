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
use crate::entry::Entry;
use crate::string::StringConv;
use crate::util::Error;
use crate::write::{Format, Sink, zeros};
use std::ffi::{CStr, c_int};
use std::sync::Arc;

pub struct Tar {
    pub variant: c_int,
    remaining: u64,
    padding: u64,
    conv: Option<Arc<StringConv>>,
    sparse: Vec<(u64, u64)>,
    logical: u64,
    xattr: u8,
}
impl Tar {
    pub fn new(variant: c_int) -> Self {
        Self {
            variant,
            remaining: 0,
            padding: 0,
            conv: None,
            sparse: Vec::new(),
            logical: 0,
            xattr: 3,
        }
    }
    fn extended(&self) -> bool {
        matches!(self.variant, 0x30002..=0x30004)
    }
    fn pax(&self) -> bool {
        matches!(self.variant, 0x30002 | 0x30003)
    }
}
fn octal(
    out: &mut [u8],
    mut value: i64,
    digits: usize,
    strict: bool,
    msg: &str,
) -> Result<(), Error> {
    let cap = 1i128 << (digits * 3);
    if value < 0 || i128::from(value) >= cap {
        if strict {
            return Err(Error::new(ARCHIVE_FAILED, libc::ERANGE, msg));
        }
        let maxdigits = out.len();
        if value >= 0 && i128::from(value) < (1i128 << (maxdigits * 3)) {
            for b in out.iter_mut().rev() {
                *b = b'0' + (value & 7) as u8;
                value >>= 3;
            }
            return Ok(());
        }
        for b in out.iter_mut().rev() {
            *b = value as u8;
            value >>= 8;
        }
        out[0] |= 0x80;
        return Ok(());
    }
    for b in out[..digits].iter_mut().rev() {
        *b = b'0' + (value & 7) as u8;
        value >>= 3;
    }
    Ok(())
}
fn checksum(h: &mut [u8; 512]) {
    h[148..156].fill(b' ');
    let sum = h.iter().map(|&b| i64::from(b)).sum();
    let _ = octal(&mut h[148..154], sum, 6, true, "");
    h[154] = 0;
}
fn attr(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    let base = key.len() + value.len() + 3;
    let mut n = base + 1;
    loop {
        let next = base + n.to_string().len();
        if next == n {
            break;
        }
        n = next;
    }
    out.extend(n.to_string().as_bytes());
    out.push(b' ');
    out.extend(key);
    out.push(b'=');
    out.extend(value);
    out.push(b'\n');
}
fn time_value(secs: i64, nsec: i64) -> Vec<u8> {
    if nsec == 0 {
        return secs.to_string().into_bytes();
    }
    let mut s = format!("{secs}.{nsec:09}");
    while s.ends_with('0') {
        s.pop();
    }
    s.into_bytes()
}
impl Format for Tar {
    fn code(&self) -> c_int {
        self.variant
    }
    fn name(&self) -> &'static CStr {
        match self.variant {
            0x30000 => c"tar (non-POSIX)",
            0x30001 => c"POSIX ustar",
            0x30002 => c"POSIX pax interchange",
            0x30003 => c"POSIX pax interchange",
            _ => c"GNU tar format",
        }
    }
    fn module(&self) -> &'static [u8] {
        match self.variant {
            0x30000 => b"v7tar",
            0x30001 => b"ustar",
            0x30004 => b"gnutar",
            _ => b"pax",
        }
    }
    fn options(&mut self, a: &Base, key: &[u8], value: Option<&[u8]>) -> Result<c_int, Error> {
        if key == b"hdrcharset" {
            let Some(v) = value.filter(|v| !v.is_empty()) else {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    -1,
                    [
                        self.module(),
                        b": hdrcharset option needs a character-set name",
                    ]
                    .concat(),
                ));
            };
            if self.pax() && v == b"BINARY" {
                self.conv = None;
                return Ok(ARCHIVE_OK);
            }
            let mut c = a
                .conv
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.conv = Some(
                crate::string::conversion_to_charset(Some(&mut c), v, false)
                    .map_err(|e| Error::fatal(e.errno, e.message))?,
            );
            return Ok(ARCHIVE_OK);
        }
        if self.pax() && key == b"xattrheader" {
            self.xattr = match value {
                Some(b"SCHILY") => 1,
                Some(b"LIBARCHIVE") => 2,
                Some(b"ALL") => 3,
                _ => {
                    return Err(Error::new(
                        ARCHIVE_FAILED,
                        -1,
                        "pax: invalid xattr header name",
                    ));
                }
            };
            return Ok(ARCHIVE_OK);
        }
        if self.pax() && key == b"mac-ext" {
            return Ok(ARCHIVE_OK);
        }
        Ok(ARCHIVE_WARN)
    }
    fn header(&mut self, a: &Base, e: &mut Entry, sink: &mut dyn Sink) -> Result<c_int, Error> {
        let (path, converted) = e.pathname_l(self.conv.as_deref());
        let mut path = path
            .ok_or_else(|| {
                Error::new(
                    ARCHIVE_FAILED,
                    -1,
                    "Can't record entry in tar file without pathname",
                )
            })?
            .to_vec();
        let mut ret = ARCHIVE_OK;
        if !converted && self.conv.is_some() {
            a.set_error(-1, Some(b"Can't translate pathname"));
            ret = ARCHIVE_WARN;
        }
        let hard = e.hardlink().map(|s| s.to_bytes().to_vec());
        let sym = e.symlink().map(|s| s.to_bytes().to_vec());
        if e.filetype() != 0o100000 || hard.is_some() || sym.is_some() {
            e.set_size(0);
        }
        if e.filetype() == 0o040000 && !path.is_empty() && !path.ends_with(b"/") {
            path.push(b'/');
            e.set_pathname(&path);
        }
        let ty = if hard.is_some() {
            b'1'
        } else {
            match e.filetype() {
                0o100000 => b'0',
                0o120000 => b'2',
                0o020000 => b'3',
                0o060000 => b'4',
                0o040000 => b'5',
                0o010000 => b'6',
                _ => {
                    return Err(Error::new(
                        ARCHIVE_FAILED,
                        -1,
                        [self.module(), b": unsupported file type"].concat(),
                    ));
                }
            }
        };
        if self.variant == 0x30000 && !matches!(ty, b'0' | b'1' | b'2' | b'5') {
            return Err(Error::new(
                ARCHIVE_FAILED,
                -1,
                "v7tar: unsupported file type",
            ));
        }
        let link = hard.or(sym).unwrap_or_default();
        let uname = e.uname().map(|s| s.to_bytes().to_vec()).unwrap_or_default();
        let gname = e.gname().map(|s| s.to_bytes().to_vec()).unwrap_or_default();
        if self.variant == 0x30000 && path.len() >= 100 {
            return Err(Error::new(
                ARCHIVE_FAILED,
                libc::ENAMETOOLONG,
                "Pathname too long",
            ));
        }
        let mut h = [0u8; 512];
        for start in [100, 108, 116] {
            h[start..start + 6].fill(b'0');
            h[start + 6] = b' ';
        }
        for start in [124, 136] {
            h[start..start + 11].fill(b'0');
            h[start + 11] = b' ';
        }
        if self.variant != 0x30000 {
            h[257..265].copy_from_slice(b"ustar\x0000");
        }
        if self.variant == 0x30004 {
            h[257..265].copy_from_slice(b"ustar  \0");
        }
        let split = if path.len() > 100 && self.variant != 0x30000 && self.variant != 0x30004 {
            path.iter()
                .enumerate()
                .skip(path.len().saturating_sub(101))
                .find(|&(i, &b)| {
                    i > 0
                        && i <= 155
                        && b == b'/'
                        && path.len() - i - 1 <= 100
                        && i + 1 < path.len()
                })
                .map(|(i, _)| i)
        } else {
            None
        };
        let mut pax = Vec::new();
        let mut sparse_map = Vec::new();
        self.sparse.clear();
        self.logical = 0;
        if self.pax() && e.sparse_count() > 0 && ty == b'0' {
            self.sparse = e
                .sparse
                .iter()
                .map(|s| (s.offset as u64, s.length as u64))
                .collect();
            if self
                .sparse
                .last()
                .is_some_and(|&(o, n)| o + n < e.size() as u64)
            {
                self.sparse.push((e.size() as u64, 0));
            }
            attr(&mut pax, b"GNU.sparse.major", b"1");
            attr(&mut pax, b"GNU.sparse.minor", b"0");
            attr(&mut pax, b"GNU.sparse.name", &path);
            attr(
                &mut pax,
                b"GNU.sparse.realsize",
                e.size().to_string().as_bytes(),
            );
            sparse_map.extend(format!("{}\n", self.sparse.len()).as_bytes());
            for (off, n) in &self.sparse {
                sparse_map.extend(format!("{off}\n{n}\n").as_bytes());
            }
            sparse_map.resize(sparse_map.len().div_ceil(512) * 512, 0);
        }
        let stored_size = if self.sparse.is_empty() {
            e.size()
        } else {
            self.sparse
                .iter()
                .try_fold(sparse_map.len() as i64, |n, (_, len)| {
                    n.checked_add(*len as i64)
                })
                .ok_or_else(|| Error::fatal(libc::EFBIG, "Sparse file is too large"))?
        };
        if path.len() <= 100 {
            h[..path.len()].copy_from_slice(&path);
        } else if let Some(i) = split {
            h[345..345 + i].copy_from_slice(&path[..i]);
            h[..path.len() - i - 1].copy_from_slice(&path[i + 1..]);
        } else if self.pax() {
            attr(&mut pax, b"path", &path);
            let n = path.len().min(100);
            h[..n].copy_from_slice(&path[..n]);
        } else if self.variant == 0x30004 {
            self.long(sink, b'L', &path)?;
            h[..100].copy_from_slice(&path[..100]);
        } else {
            return Err(Error::new(
                ARCHIVE_FAILED,
                libc::ENAMETOOLONG,
                "Pathname too long",
            ));
        }
        if link.len() > 100 {
            if self.pax() {
                attr(&mut pax, b"linkpath", &link);
            } else if self.variant == 0x30004 {
                self.long(sink, b'K', &link)?;
            } else {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    libc::ENAMETOOLONG,
                    "Link contents too long",
                ));
            }
        }
        let n = link.len().min(100);
        h[157..157 + n].copy_from_slice(&link[..n]);
        h[156] = if self.variant == 0x30000 && matches!(ty, b'0' | b'5') {
            0
        } else {
            ty
        };
        for (val, start, digits, msg, key) in [
            (
                i64::from(e.mode() & 0o7777),
                100,
                6,
                "Numeric mode too large",
                b"mode".as_slice(),
            ),
            (e.uid(), 108, 6, "Numeric user ID too large", b"uid"),
            (e.gid(), 116, 6, "Numeric group ID too large", b"gid"),
            (stored_size, 124, 11, "File size out of range", b"size"),
            (
                e.mtime(),
                136,
                11,
                "File modification time too large",
                b"mtime",
            ),
        ] {
            let width = if digits == 6 { 8 } else { 12 };
            if self.pax() && (val < 0 || i128::from(val) >= (1i128 << (digits * 3))) {
                attr(&mut pax, key, val.to_string().as_bytes());
            }
            octal(
                &mut h[start..start + width],
                val,
                digits,
                !self.extended(),
                msg,
            )?;
        }
        if self.variant != 0x30000 {
            for (name, start, key, msg) in [
                (&uname, 265, b"uname".as_slice(), "Username too long"),
                (&gname, 297, b"gname".as_slice(), "Group name too long"),
            ] {
                if name.len() > 32 {
                    if self.pax() {
                        attr(&mut pax, key, name);
                    } else if self.variant != 0x30004 {
                        return Err(Error::new(ARCHIVE_FAILED, -1, msg));
                    }
                }
                let n = name.len().min(32);
                h[start..start + n].copy_from_slice(&name[..n]);
            }
        }
        if self.variant != 0x30000 {
            for start in [329, 337] {
                h[start..start + 6].fill(b'0');
                h[start + 6] = b' ';
            }
        }
        if matches!(ty, b'3' | b'4') {
            octal(
                &mut h[329..337],
                e.rdevmajor() as i64,
                6,
                !self.extended(),
                "Major device number too large",
            )?;
            octal(
                &mut h[337..345],
                e.rdevminor() as i64,
                6,
                !self.extended(),
                "Minor device number too large",
            )?;
        }
        if self.pax() {
            if let Some(flags) = e.fflags_text().filter(|s| !s.to_bytes().is_empty()) {
                attr(&mut pax, b"SCHILY.fflags", flags.to_bytes());
            }
            for (ty, key, style) in [
                (crate::acl::TYPE_ACCESS, b"SCHILY.acl.access".as_slice(), 0),
                (crate::acl::TYPE_DEFAULT, b"SCHILY.acl.default", 0),
                (
                    crate::acl::TYPE_NFS4,
                    b"SCHILY.acl.ace",
                    crate::acl::STYLE_COMPACT,
                ),
            ] {
                if e.acl.count(ty) > 0
                    && let Some(text) = e.acl_to_text(
                        ty | crate::acl::STYLE_EXTRA_ID | crate::acl::STYLE_SEPARATOR_COMMA | style,
                    )
                {
                    attr(&mut pax, key, &text);
                }
            }
            for x in &e.xattrs {
                if self.xattr & 1 != 0 {
                    attr(
                        &mut pax,
                        &[b"SCHILY.xattr.".as_slice(), x.name.as_bytes()].concat(),
                        &x.value,
                    );
                }
                if self.xattr & 2 != 0 {
                    let mut name = Vec::new();
                    for &b in x.name.as_bytes() {
                        if !(33..=126).contains(&b) || matches!(b, b'%' | b'=') {
                            name.extend(format!("%{b:02X}").as_bytes());
                        } else {
                            name.push(b);
                        }
                    }
                    attr(
                        &mut pax,
                        &[b"LIBARCHIVE.xattr.".as_slice(), &name].concat(),
                        &base64(&x.value),
                    );
                }
            }
            if e.symlink_type() != 0 {
                attr(
                    &mut pax,
                    b"LIBARCHIVE.symlinktype",
                    if e.symlink_type() == 1 {
                        b"file"
                    } else {
                        b"dir"
                    },
                );
            }
            if e.mtime_nsec() != 0 && (self.variant == 0x30002 || !pax.is_empty()) {
                attr(&mut pax, b"mtime", &time_value(e.mtime(), e.mtime_nsec()));
            }
            if self.variant == 0x30002 && e.birthtime_is_set() != 0 && e.birthtime() < e.mtime() {
                attr(
                    &mut pax,
                    b"LIBARCHIVE.creationtime",
                    &time_value(e.birthtime(), e.birthtime_nsec()),
                );
            }
            if self.variant == 0x30002 {
                if e.atime() != 0 || e.atime_nsec() != 0 {
                    attr(&mut pax, b"atime", &time_value(e.atime(), e.atime_nsec()));
                }
                if e.ctime() != 0 || e.ctime_nsec() != 0 {
                    attr(&mut pax, b"ctime", &time_value(e.ctime(), e.ctime_nsec()));
                }
            }
        }
        if !pax.is_empty() {
            let mut x = h;
            x[156] = b'x';
            let xp = [b"PaxHeader/".as_slice(), &path].concat();
            x[..100].fill(0);
            let n = xp.len().min(99);
            x[..n].copy_from_slice(&xp[..n]);
            x[345..500].fill(0);
            octal(&mut x[124..136], pax.len() as i64, 11, true, "")?;
            checksum(&mut x);
            sink.write(&x)?;
            sink.write(&pax)?;
            zeros(sink, ((512 - pax.len() % 512) % 512) as u64)?;
        }
        checksum(&mut h);
        sink.write(&h)?;
        self.remaining = u64::try_from(e.size()).unwrap_or(0);
        self.padding = (512 - stored_size.max(0) as u64 % 512) % 512;
        sink.write(&sparse_map)?;
        Ok(ret)
    }
    fn data(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<usize, Error> {
        let n = data.len().min(self.remaining as usize);
        if self.sparse.is_empty() {
            sink.write(&data[..n])?;
        } else {
            let end = self.logical + n as u64;
            for &(off, len) in &self.sparse {
                let start = off.max(self.logical);
                let stop = (off + len).min(end);
                if stop > start {
                    sink.write(
                        &data[(start - self.logical) as usize..(stop - self.logical) as usize],
                    )?;
                }
            }
            self.logical = end;
        }
        self.remaining -= n as u64;
        Ok(n)
    }
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        let missing = if self.sparse.is_empty() {
            self.remaining
        } else {
            self.sparse
                .iter()
                .map(|&(off, len)| (off + len).saturating_sub(self.logical.max(off)))
                .sum()
        };
        zeros(sink, missing)?;
        zeros(sink, self.padding)?;
        self.remaining = 0;
        self.padding = 0;
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        zeros(sink, 1024)
    }
}
impl Tar {
    fn long(&mut self, sink: &mut dyn Sink, ty: u8, value: &[u8]) -> Result<(), Error> {
        let mut h = [0u8; 512];
        h[..13].copy_from_slice(b"././@LongLink\0");
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..124].copy_from_slice(b"0000000\x000000000\0");
        h[257..265].copy_from_slice(b"ustar  \0");
        h[156] = if self.variant == 0x30000 && matches!(ty, b'0' | b'5') {
            0
        } else {
            ty
        };
        octal(&mut h[124..136], (value.len() + 1) as i64, 11, true, "")?;
        checksum(&mut h);
        sink.write(&h)?;
        sink.write(value)?;
        sink.write(&[0])?;
        zeros(sink, ((512 - (value.len() + 1) % 512) % 512) as u64)
    }
}

fn base64(data: &[u8]) -> Vec<u8> {
    let digits = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    for c in data.chunks(3) {
        let a = c[0];
        let b = c.get(1).copied().unwrap_or(0);
        let d = c.get(2).copied().unwrap_or(0);
        out.push(digits[(a >> 2) as usize]);
        out.push(digits[((a << 4 | b >> 4) & 63) as usize]);
        if c.len() > 1 {
            out.push(digits[((b << 2 | d >> 6) & 63) as usize]);
        }
        if c.len() > 2 {
            out.push(digits[(d & 63) as usize]);
        }
    }
    out
}
