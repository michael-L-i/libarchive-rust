/*-
 * Copyright (c) 2008 Anselm Strauss
 * Copyright (c) 2009 Joerg Sonnenberger
 * Copyright (c) 2011-2012,2014 Michihiro NAKAJIMA
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

/*
 * Development supported by Google Summer of Code 2008.
 */

// Ported from libarchive/archive_write_set_format_zip.c.
use crate::archive::*;
use crate::cryptor::AesCtr;
use crate::entry::Entry;
use crate::hmac::HmacSha1;
use crate::string::StringConv;
use crate::util::Error;
use crate::write::{Filter, Format, Sink};
use miniz_oxide::deflate::core::{
    CompressorOxide, TDEFLFlush, TDEFLStatus, compress, create_comp_flags_from_zip_params,
};
use std::ffi::{CStr, c_int};
use std::io::Read;
use std::sync::Arc;

pub struct Zip {
    method: u16,
    level: u8,
    force64: bool,
    avoid64: bool,
    fakecrc: bool,
    experimental: bool,
    central: Vec<u8>,
    entries: u64,
    written: u64,
    current: Option<Member>,
    encryption: u8,
    passphrase: Option<Vec<u8>>,
    conv: Option<Arc<StringConv>>,
}
struct Member {
    name: Vec<u8>,
    extra: Vec<u8>,
    offset: u64,
    mode: u32,
    time: u32,
    mtime: Option<u32>,
    flags: u16,
    version: u16,
    method: u16,
    limit: Option<u64>,
    size: u64,
    packed: u64,
    crc: u32,
    encoder: Option<Box<dyn Filter>>,
    deflate: Option<Box<CompressorOxide>>,
    skip_lzma: usize,
    cipher: Cipher,
    ae2: bool,
}
impl Default for Zip {
    fn default() -> Self {
        Self {
            method: 8,
            level: 6,
            force64: false,
            avoid64: false,
            fakecrc: false,
            experimental: false,
            central: Vec::new(),
            entries: 0,
            written: 0,
            current: None,
            encryption: 0,
            passphrase: None,
            conv: None,
        }
    }
}
fn put16(v: &mut Vec<u8>, n: u16) {
    v.extend(n.to_le_bytes());
}
fn put32(v: &mut Vec<u8>, n: u32) {
    v.extend(n.to_le_bytes());
}
fn put64(v: &mut Vec<u8>, n: u64) {
    v.extend(n.to_le_bytes());
}
enum Cipher {
    None,
    Traditional([u32; 3]),
    Aes(Box<AesCtr>, Box<HmacSha1>),
}
fn trad_update(k: &mut [u32; 3], c: u8) {
    k[0] = !crate::crc32::crc32(!k[0], &[c]);
    k[1] = k[1]
        .wrapping_add(k[0] & 255)
        .wrapping_mul(134775813)
        .wrapping_add(1);
    k[2] = !crate::crc32::crc32(!k[2], &[(k[1] >> 24) as u8]);
}
impl Cipher {
    fn encrypt(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = input.to_vec();
        match self {
            Self::None => {}
            Self::Traditional(k) => {
                for b in &mut out {
                    let c = *b;
                    let temp = k[2] | 2;
                    *b ^= (temp.wrapping_mul(temp ^ 1) >> 8) as u8;
                    trad_update(k, c);
                }
            }
            Self::Aes(a, h) => {
                a.update(input, &mut out);
                h.update(&out);
            }
        }
        out
    }
}
fn random(len: usize) -> Result<Vec<u8>, Error> {
    let mut v = vec![0; len];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut v))
        .map_err(|e| {
            Error::fatal(
                e.raw_os_error().unwrap_or(libc::EIO),
                "Can't generate random bytes",
            )
        })?;
    Ok(v)
}
struct Count<'a> {
    sink: &'a mut dyn Sink,
    written: &'a mut u64,
    packed: &'a mut u64,
    skip: &'a mut usize,
    cipher: &'a mut Cipher,
}
impl Sink for Count<'_> {
    fn write(&mut self, mut data: &[u8]) -> Result<(), Error> {
        let skip = data.len().min(*self.skip);
        *self.skip -= skip;
        data = &data[skip..];
        let encoded = self.cipher.encrypt(data);
        self.sink.write(&encoded)?;
        *self.written = self
            .written
            .checked_add(data.len() as u64)
            .ok_or_else(|| Error::fatal(libc::EFBIG, "ZIP output too large"))?;
        *self.packed = self
            .packed
            .checked_add(data.len() as u64)
            .ok_or_else(|| Error::fatal(libc::EFBIG, "ZIP entry too large"))?;
        Ok(())
    }
}
impl Member {
    fn encode(
        &mut self,
        input: &[u8],
        finish: bool,
        written: &mut u64,
        sink: &mut dyn Sink,
    ) -> Result<(), Error> {
        let mut sink = Count {
            sink,
            written,
            packed: &mut self.packed,
            skip: &mut self.skip_lzma,
            cipher: &mut self.cipher,
        };
        if let Some(encoder) = self.encoder.as_mut() {
            return if finish {
                encoder.close(&mut sink)
            } else {
                encoder.write(input, &mut sink)
            };
        }
        if let Some(state) = self.deflate.as_mut() {
            let mut input = input;
            let mut out = [0u8; 65536];
            loop {
                let (status, used, n) = compress(
                    state,
                    input,
                    &mut out,
                    if finish {
                        TDEFLFlush::Finish
                    } else {
                        TDEFLFlush::None
                    },
                );
                sink.write(&out[..n])?;
                input = &input[used..];
                if status == TDEFLStatus::Done || (!finish && input.is_empty() && n < out.len()) {
                    break;
                }
                if used == 0 && n == 0 || !matches!(status, TDEFLStatus::Okay | TDEFLStatus::Done) {
                    return Err(Error::fatal(-1, "ZIP compression failed"));
                }
            }
            Ok(())
        } else {
            sink.write(input)
        }
    }
}
impl Format for Zip {
    fn needs_passphrase(&self) -> bool {
        self.encryption != 0
    }
    fn set_passphrase(&mut self, p: Option<&[u8]>) {
        self.passphrase = p.map(<[u8]>::to_vec);
    }
    fn code(&self) -> c_int {
        0x50000
    }
    fn name(&self) -> &'static CStr {
        c"ZIP"
    }
    fn module(&self) -> &'static [u8] {
        b"zip"
    }
    fn options(&mut self, a: &Base, key: &[u8], value: Option<&[u8]>) -> Result<c_int, Error> {
        match key {
            b"encryption" => {
                self.encryption = match value {
                    None => 0,
                    Some(b"traditional" | b"zipcrypt" | b"ZipCrypt" | b"1") => 1,
                    Some(b"aes128") => 2,
                    Some(b"aes256") => 3,
                    _ => return Err(Error::new(ARCHIVE_FAILED, -1, "zip: unknown encryption")),
                }
            }
            b"hdrcharset" => {
                let v = value.filter(|v| !v.is_empty()).ok_or_else(|| {
                    Error::new(
                        ARCHIVE_FAILED,
                        -1,
                        "zip: hdrcharset option needs a character-set name",
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
            }
            b"compression" => {
                self.method = match value.unwrap_or_default() {
                    b"store" => 0,
                    b"deflate" => 8,
                    b"bzip2" => 12,
                    b"lzma" => 14,
                    b"xz" => 95,
                    b"zstd" => 93,
                    _ => return Err(Error::new(ARCHIVE_FAILED, -1, "unknown compression")),
                }
            }
            b"compression-level" => {
                self.level = value
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .and_then(|s| s.parse::<u8>().ok())
                    .filter(|&n| n <= 9)
                    .ok_or_else(|| Error::new(ARCHIVE_WARN, -1, "Illegal value"))?;
                if self.level == 0 {
                    self.method = 0;
                }
            }
            b"zip64" => {
                self.force64 = value.is_some_and(|v| !v.is_empty());
                self.avoid64 = !self.force64;
            }
            b"fakecrc32" => self.fakecrc = value.is_some(),
            b"experimental" => self.experimental = value.is_some(),
            b"threads" => {
                if value
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .and_then(|s| s.parse::<u16>().ok())
                    .is_none()
                {
                    return Err(Error::new(ARCHIVE_FAILED, -1, "Illegal value"));
                }
            }
            _ => return Ok(ARCHIVE_WARN),
        }
        Ok(ARCHIVE_OK)
    }
    fn header(&mut self, _: &Base, e: &mut Entry, sink: &mut dyn Sink) -> Result<c_int, Error> {
        let (name, _) = e.pathname_l(self.conv.as_deref());
        let mut name = name
            .map(<[u8]>::to_vec)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                Error::new(
                    ARCHIVE_FAILED,
                    -1,
                    "ZIP format requires a non-empty pathname",
                )
            })?;
        let ty = e.filetype();
        if !matches!(ty, 0o100000 | 0o040000 | 0o120000) {
            return Err(Error::new(
                ARCHIVE_FAILED,
                -1,
                "ZIP format only supports regular files, directories and symbolic links",
            ));
        }
        if ty == 0o040000 {
            if !name.ends_with(b"/") {
                name.push(b'/');
            }
            e.set_size(0);
        }
        if name.len() > u16::MAX as usize {
            return Err(Error::new(
                ARCHIVE_FAILED,
                libc::ENAMETOOLONG,
                "Pathname too long for ZIP format",
            ));
        }
        let sym = e
            .symlink()
            .map(|s| s.to_bytes().to_vec())
            .unwrap_or_default();
        let method = if ty == 0o100000 { self.method } else { 0 };
        let unknown = e.size_is_set() == 0;
        let limit = if ty == 0o100000 {
            if unknown {
                None
            } else {
                Some(e.size().max(0) as u64)
            }
        } else {
            Some(0)
        };
        let encrypted = ty == 0o100000 && self.encryption != 0;
        let mut flags = if ty == 0o100000 { 8 } else { 0 };
        if encrypted {
            flags |= 1;
        }
        if method == 14 {
            flags |= 2;
        }
        if method == 8 {
            flags |= match self.level {
                1 | 2 => 6,
                3 | 4 => 4,
                8 | 9 => 2,
                _ => 0,
            };
        }
        if name.iter().any(|&b| b >= 128) && std::str::from_utf8(&name).is_ok() {
            flags |= 0x800;
        }
        let mut version = match method {
            0 => {
                if ty == 0o100000 {
                    10
                } else {
                    20
                }
            }
            8 => 20,
            12 => 46,
            _ => 63,
        };
        if self.force64 || (unknown && !self.avoid64) || limit.is_some_and(|n| n > 0xfffffff0) {
            version = version.max(45);
        }
        if self.avoid64 && limit.is_some_and(|n| n > u32::MAX as u64) {
            return Err(Error::new(
                ARCHIVE_FAILED,
                -1,
                "Files > 4GB require Zip64 extensions",
            ));
        }
        let time = crate::time::unix_to_dos(e.mtime());
        let mut shared = Vec::new();
        if e.uid_is_set() != 0 || e.gid_is_set() != 0 {
            shared.extend(b"ux\x0b\0\x01\x04");
            put32(&mut shared, e.uid() as u32);
            shared.push(4);
            put32(&mut shared, e.gid() as u32);
        }
        let ae2 = encrypted && self.encryption > 1 && e.size_is_set() != 0 && e.size() < 20;
        if encrypted && self.encryption > 1 {
            shared.extend([1, 0x99, 7, 0]);
            put16(&mut shared, if ae2 { 2 } else { 1 });
            shared.extend(b"AE");
            shared.push(if self.encryption == 2 { 1 } else { 3 });
            put16(&mut shared, method);
        }
        let mtime = (e.mtime_is_set() != 0).then(|| e.mtime() as u32);
        let mut extra = shared.clone();
        let mut times = Vec::new();
        let bits = u8::from(mtime.is_some())
            | if e.atime_is_set() != 0 { 2 } else { 0 }
            | if e.ctime_is_set() != 0 { 4 } else { 0 };
        if bits != 0 {
            times.push(bits);
            if let Some(t) = mtime {
                put32(&mut times, t);
            }
            if bits & 2 != 0 {
                put32(&mut times, e.atime() as u32);
            }
            if bits & 4 != 0 {
                put32(&mut times, e.ctime() as u32);
            }
            extra.extend(b"UT");
            put16(&mut extra, times.len() as u16);
            extra.extend(times);
        }
        if limit.is_some_and(|n| n > u32::MAX as u64) {
            extra.extend([1, 0, 0, 0]);
        }
        if self.experimental {
            extra.extend(b"xl\x09\0\x07");
            put16(&mut extra, 3 * 256 + version);
            put16(&mut extra, 0);
            put32(&mut extra, (e.mode() as u32) << 16);
        }
        let crc = if self.fakecrc {
            0
        } else {
            crate::crc32::crc32(0, &sym)
        };
        let size = if ty == 0o120000 { sym.len() as u64 } else { 0 };
        let mut header = b"PK\x03\x04".to_vec();
        put16(&mut header, version);
        put16(&mut header, flags);
        put16(
            &mut header,
            if encrypted && self.encryption > 1 {
                99
            } else {
                method
            },
        );
        put32(&mut header, time);
        put32(&mut header, if flags & 8 == 0 { crc } else { 0 });
        put32(&mut header, if flags & 8 == 0 { size as u32 } else { 0 });
        put32(&mut header, if flags & 8 == 0 { size as u32 } else { 0 });
        put16(&mut header, name.len() as u16);
        put16(&mut header, extra.len() as u16);
        header.extend(&name);
        header.extend(&extra);
        let offset = self.written;
        sink.write(&header)?;
        self.written += header.len() as u64;
        let mut member = Member {
            name,
            extra: shared,
            offset,
            mode: e.mode() as u32,
            time,
            mtime,
            flags,
            version,
            method,
            limit,
            size,
            packed: 0,
            crc,
            encoder: None,
            deflate: None,
            skip_lzma: 0,
            cipher: Cipher::None,
            ae2,
        };
        if ty == 0o120000 {
            sink.write(&sym)?;
            self.written += sym.len() as u64;
            member.packed = sym.len() as u64;
        }
        if encrypted {
            let p = self
                .passphrase
                .as_deref()
                .ok_or_else(|| Error::new(ARCHIVE_FAILED, -1, "Encryption needs passphrase"))?;
            if self.encryption == 1 {
                let mut k = [305419896, 591751049, 878082192];
                for &c in p {
                    trad_update(&mut k, c);
                }
                let mut prefix = random(12)?;
                prefix[11] = (time >> 8) as u8;
                member.cipher = Cipher::Traditional(k);
                let prefix = member.cipher.encrypt(&prefix);
                sink.write(&prefix)?;
                self.written += 12;
                member.packed += 12;
            } else {
                let keylen = if self.encryption == 2 { 16 } else { 32 };
                let salt = random(keylen / 2)?;
                let mut dk = vec![0; keylen * 2 + 2];
                crate::cryptor::pbkdf2_sha1(p, &salt, 1000, &mut dk);
                sink.write(&salt)?;
                sink.write(&dk[keylen * 2..])?;
                self.written += (salt.len() + 2) as u64;
                member.packed += (salt.len() + 2) as u64;
                member.cipher =
                    Cipher::Aes(
                        Box::new(
                            AesCtr::new(&dk[..keylen])
                                .ok_or_else(|| Error::fatal(-1, "Failed to encrypt file"))?,
                        ),
                        Box::new(HmacSha1::new(&dk[keylen..keylen * 2]).ok_or_else(|| {
                            Error::fatal(-1, "Failed to initialize authentication")
                        })?),
                    );
                dk.fill(0);
            }
        }
        if method == 8 {
            member.deflate = Some(Box::new(CompressorOxide::new(
                create_comp_flags_from_zip_params(i32::from(self.level), -15, 0),
            )));
        } else if method != 0 {
            let code = match method {
                12 => 2,
                14 => 5,
                95 => 6,
                93 => 14,
                _ => 0,
            };
            let mut f = crate::write::filter::by_code(code)?;
            let level = [b'0' + self.level];
            f.options(b"compression-level", Some(&level))?;
            if method == 14 {
                let options = lzma_rust2::LzmaOptions::with_preset(self.level.into());
                let mut prefix = vec![9, 4, 5, 0, 0x5d];
                prefix.extend_from_slice(&options.dict_size.to_le_bytes());
                let prefix = member.cipher.encrypt(&prefix);
                sink.write(&prefix)?;
                self.written += 9;
                member.packed += 9;
                member.skip_lzma = 13;
            }
            member.encoder = Some(f);
        }
        self.current = Some(member);
        Ok(ARCHIVE_OK)
    }
    fn data(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<usize, Error> {
        let m = self
            .current
            .as_mut()
            .ok_or_else(|| Error::fatal(-1, "Missing ZIP entry"))?;
        let n = m.limit.map_or(data.len(), |limit| {
            data.len().min(limit.saturating_sub(m.size) as usize)
        });
        let input = &data[..n];
        if !self.fakecrc {
            m.crc = crate::crc32::crc32(m.crc, input);
        }
        m.size += n as u64;
        m.encode(input, false, &mut self.written, sink)?;
        Ok(n)
    }
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        let Some(mut m) = self.current.take() else {
            return Ok(());
        };
        if m.flags & 8 != 0 {
            m.encode(&[], true, &mut self.written, sink)?;
            if let Cipher::Aes(_, h) = std::mem::replace(&mut m.cipher, Cipher::None) {
                let auth = (*h).finalize();
                sink.write(&auth[..10])?;
                m.packed += 10;
                self.written += 10;
            }
            let mut d = b"PK\x07\x08".to_vec();
            put32(&mut d, if m.ae2 { 0 } else { m.crc });
            if self.force64 || m.packed >= u32::MAX as u64 || m.size >= u32::MAX as u64 {
                put64(&mut d, m.packed);
                put64(&mut d, m.size);
            } else {
                put32(&mut d, m.packed as u32);
                put32(&mut d, m.size as u32);
            }
            sink.write(&d)?;
            self.written += d.len() as u64;
        }
        if let Some(t) = m.mtime {
            m.extra.extend(b"UT\x05\0\x01");
            put32(&mut m.extra, t);
        }
        let mut z64 = Vec::new();
        if m.size >= u32::MAX as u64 {
            put64(&mut z64, m.size);
        }
        if m.packed >= u32::MAX as u64 {
            put64(&mut z64, m.packed);
        }
        if m.offset >= u32::MAX as u64 {
            put64(&mut z64, m.offset);
        }
        if !z64.is_empty() {
            m.extra.extend([1, 0]);
            put16(&mut m.extra, z64.len() as u16);
            m.extra.extend(z64);
        }
        let mut cd = b"PK\x01\x02".to_vec();
        put16(&mut cd, 3 * 256 + m.version);
        put16(&mut cd, m.version);
        put16(&mut cd, m.flags);
        put16(
            &mut cd,
            if m.flags & 1 != 0 && self.encryption > 1 {
                99
            } else {
                m.method
            },
        );
        put32(&mut cd, m.time);
        put32(&mut cd, if m.ae2 { 0 } else { m.crc });
        put32(&mut cd, m.packed.min(u32::MAX as u64) as u32);
        put32(&mut cd, m.size.min(u32::MAX as u64) as u32);
        put16(&mut cd, m.name.len() as u16);
        put16(&mut cd, m.extra.len() as u16);
        cd.extend([0; 6]);
        put32(&mut cd, m.mode << 16);
        put32(&mut cd, m.offset.min(u32::MAX as u64) as u32);
        cd.extend(m.name);
        cd.extend(m.extra);
        self.central
            .try_reserve(cd.len())
            .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate ZIP central directory"))?;
        self.central.extend(cd);
        self.entries += 1;
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        let offset = self.written;
        sink.write(&self.central)?;
        self.written += self.central.len() as u64;
        if self.force64
            || self.central.len() > u32::MAX as usize
            || offset > u32::MAX as u64
            || self.entries > 65535
        {
            let mut z = b"PK\x06\x06".to_vec();
            put64(&mut z, 44);
            put16(&mut z, 45);
            put16(&mut z, 45);
            z.extend([0; 8]);
            put64(&mut z, self.entries);
            put64(&mut z, self.entries);
            put64(&mut z, self.central.len() as u64);
            put64(&mut z, offset);
            sink.write(&z)?;
            let mut loc = b"PK\x06\x07".to_vec();
            put32(&mut loc, 0);
            put64(&mut loc, self.written);
            put32(&mut loc, 1);
            sink.write(&loc)?;
            self.written += 76;
        }
        let mut end = b"PK\x05\x06".to_vec();
        end.extend([0; 4]);
        put16(&mut end, self.entries.min(65535) as u16);
        put16(&mut end, self.entries.min(65535) as u16);
        put32(&mut end, self.central.len().min(u32::MAX as usize) as u32);
        put32(&mut end, offset.min(u32::MAX as u64) as u32);
        put16(&mut end, 0);
        sink.write(&end)?;
        self.written += end.len() as u64;
        Ok(())
    }
}
