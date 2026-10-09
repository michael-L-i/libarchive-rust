/*-
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

// Ported from libarchive/archive_write_set_format_7zip.c.
use crate::archive::*;
use crate::entry::Entry;
use crate::ppmd7::{Ppmd7, Ppmd7RangeEnc};
use crate::read::filter_code;
use crate::util::Error;
use crate::write::{Filter, Format, Sink};
use lzma_rust2::{Lzma2Options, Lzma2Writer, LzmaOptions, LzmaWriter};
use std::ffi::{CStr, c_int};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
const COPY: u32 = 0;
const DEFLATE: u32 = 0x040108;
const BZIP: u32 = 0x040202;
const LZMA: u32 = 0x030101;
const LZMA2: u32 = 0x21;
const PPMD: u32 = 0x030401;
const ZSTD: u32 = 0x04f71101;
struct FileInfo {
    name: Vec<u8>,
    mode: u32,
    size: u64,
    times: [Option<u64>; 3],
    crc: u32,
}
impl FileInfo {
    fn dir(&self) -> bool {
        self.mode & 0o170000 == 0o40000
    }
}
struct Spool {
    file: File,
    len: u64,
}
impl Sink for Spool {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.file.write_all(data).map_err(io_error)?;
        self.len = self
            .len
            .checked_add(data.len() as u64)
            .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "7-Zip file too large"))?;
        Ok(())
    }
}
fn io_error(e: std::io::Error) -> Error {
    Error::fatal(e.raw_os_error().unwrap_or(libc::EIO), e.to_string())
}
enum Coder {
    Filter(Box<dyn Filter>),
    Lzma(LzmaWriter<Vec<u8>>),
    Lzma2(Lzma2Writer<Vec<u8>>),
    Ppmd(Box<Ppmd7>, Ppmd7RangeEnc),
}
impl Coder {
    fn new(codec: u32, level: i64, input_size: Option<usize>) -> Result<(Self, Vec<u8>), Error> {
        let l = level.clamp(0, 9) as u8;
        let mut props = Vec::new();
        let coder = match codec {
            COPY => Self::Filter(crate::write::filter::by_code(filter_code::NONE)?),
            DEFLATE => Self::Filter(Box::new(crate::write::filter::gzip::Gzip::raw(l))),
            BZIP | ZSTD => {
                let mut f = crate::write::filter::by_code(if codec == BZIP {
                    filter_code::BZIP2
                } else {
                    filter_code::ZSTD
                })?;
                let option = if codec == BZIP {
                    l.max(1).to_string()
                } else {
                    level.to_string()
                };
                f.options(b"compression-level", Some(option.as_bytes()))?;
                Self::Filter(f)
            }
            LZMA => {
                let mut options = LzmaOptions::with_preset(l.into());
                props.push(((options.pb * 5 + options.lp) * 9 + options.lc) as u8);
                props.extend_from_slice(&options.dict_size.to_le_bytes());
                limit_dictionary(&mut options, input_size);
                Self::Lzma(LzmaWriter::new_no_header(Vec::new(), &options, true).map_err(io_error)?)
            }
            LZMA2 => {
                let mut options = Lzma2Options::with_preset(l.into());
                let dict = options.lzma_options.dict_size;
                let property = (0u8..=39)
                    .find(|&p| dict <= (2 | u32::from(p & 1)) << (p / 2 + 11))
                    .ok_or_else(|| Error::fatal(libc::EINVAL, "Invalid LZMA2 dictionary"))?;
                props.push(property);
                limit_dictionary(&mut options.lzma_options, input_size);
                Self::Lzma2(Lzma2Writer::new(Vec::new(), options))
            }
            PPMD => {
                let order = 6;
                let memory = 1u32 << 24;
                let mut model = Box::new(Ppmd7::new());
                if !model.alloc(memory) {
                    return Err(Error::fatal(
                        libc::ENOMEM,
                        "Coludn't allocate memory for PPMd",
                    ));
                }
                model.init(order);
                props.push(order as u8);
                props.extend_from_slice(&memory.to_le_bytes());
                Self::Ppmd(model, Ppmd7RangeEnc::new())
            }
            _ => return Err(Error::fatal(libc::EINVAL, "Unknown 7-Zip coder")),
        };
        Ok((coder, props))
    }
    fn write(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        for part in data.chunks(65536) {
            match self {
                Self::Filter(f) => f.write(part, sink)?,
                Self::Lzma(w) => {
                    w.write_all(part).map_err(io_error)?;
                    sink.write(w.inner())?;
                    w.inner_mut().clear();
                }
                Self::Lzma2(w) => {
                    w.write_all(part).map_err(io_error)?;
                    sink.write(w.inner())?;
                    w.inner_mut().clear();
                }
                Self::Ppmd(model, rc) => {
                    for &b in part {
                        if !model.encode_symbol(rc, b.into()) {
                            return Err(Error::fatal(-1, "PPMd compression failed"));
                        }
                    }
                    sink.write(&rc.output)?;
                    rc.output.clear();
                }
            }
        }
        Ok(())
    }
    fn finish(self, sink: &mut dyn Sink) -> Result<(), Error> {
        match self {
            Self::Filter(mut f) => f.close(sink),
            Self::Lzma(w) => sink.write(&w.finish().map_err(io_error)?),
            Self::Lzma2(w) => sink.write(&w.finish().map_err(io_error)?),
            Self::Ppmd(_, mut rc) => {
                rc.finish();
                sink.write(&rc.output)
            }
        }
    }
}
// Once the entire stream is known, no match can reach beyond its input.
// Keep the preset dictionary in the archive properties for compatibility.
fn limit_dictionary(options: &mut LzmaOptions, input_size: Option<usize>) {
    if let Some(size) = input_size {
        options.dict_size = options
            .dict_size
            .min(u32::try_from(size).unwrap_or(u32::MAX).max(4096));
    }
}

pub struct SevenZip {
    files: Vec<FileInfo>,
    current: Option<usize>,
    remaining: u64,
    codec: u32,
    level: i64,
    coder: Option<Coder>,
    pending: Vec<u8>,
    properties: Vec<u8>,
    spool: Option<Spool>,
}
impl Default for SevenZip {
    fn default() -> Self {
        Self {
            files: Vec::new(),
            current: None,
            remaining: 0,
            codec: LZMA,
            level: 6,
            coder: None,
            pending: Vec::new(),
            properties: Vec::new(),
            spool: None,
        }
    }
}
impl SevenZip {
    fn initialize(&mut self) -> Result<(), Error> {
        if self.spool.is_none() {
            if self.codec != ZSTD && !(0..=9).contains(&self.level) {
                return Err(Error::fatal(
                    -1,
                    format!(
                        "compression-level option value `{}` out of range 0-9",
                        self.level
                    ),
                ));
            }
            if self.codec != LZMA && self.codec != LZMA2 {
                self.start_coder(None)?;
            }
            self.spool = Some(Spool {
                file: crate::write::temp_file()?,
                len: 0,
            });
        }
        Ok(())
    }
    fn start_coder(&mut self, input_size: Option<usize>) -> Result<(), Error> {
        let (mut coder, props) = Coder::new(self.codec, self.level, input_size)?;
        if let Some(spool) = &mut self.spool {
            coder.write(&self.pending, spool)?;
        }
        self.pending = Vec::new();
        self.coder = Some(coder);
        self.properties = props;
        Ok(())
    }
    fn append(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.coder.is_none() && self.spool.is_some() && !data.is_empty() {
            // A solid stream may span many entries. Wait for its total size,
            // but bound staging even at presets with very large dictionaries.
            let limit = LzmaOptions::with_preset(self.level.clamp(0, 9) as u32)
                .dict_size
                .min(8 << 20) as usize;
            if data.len() <= limit.saturating_sub(self.pending.len()) {
                let needed = self.pending.len() + data.len();
                if needed > self.pending.capacity() {
                    let capacity = needed
                        .max(self.pending.capacity().saturating_mul(2))
                        .min(limit);
                    self.pending
                        .try_reserve_exact(capacity - self.pending.len())
                        .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate 7-Zip input"))?;
                }
                self.pending.extend_from_slice(data);
            } else {
                self.start_coder(None)?;
                if let (Some(coder), Some(spool)) = (&mut self.coder, &mut self.spool) {
                    coder.write(data, spool)?;
                }
            }
        } else if let (Some(coder), Some(spool)) = (&mut self.coder, &mut self.spool) {
            coder.write(data, spool)?;
        }
        if let Some(file) = self.current.and_then(|i| self.files.get_mut(i)) {
            file.crc = crate::crc32::crc32(file.crc, data);
        }
        Ok(())
    }
    fn header_bytes(&self, files: &[&FileInfo], packed: u64, unpacked: u64) -> Vec<u8> {
        let mut h = vec![1];
        let nonempty: Vec<_> = files.iter().copied().filter(|f| f.size > 0).collect();
        if !nonempty.is_empty() {
            h.push(4);
            streams(
                &mut h,
                0,
                packed,
                unpacked,
                (self.codec, &self.properties),
                Some(&nonempty),
                None,
            );
        }
        h.push(5);
        uint(&mut h, files.len() as u64);
        let empty: Vec<_> = files.iter().copied().filter(|f| f.size == 0).collect();
        if !empty.is_empty() {
            property(&mut h, 14, &bools(files.iter().map(|f| f.size == 0)));
            if empty.iter().any(|f| !f.dir()) {
                property(&mut h, 15, &bools(empty.iter().map(|f| !f.dir())));
            }
        }
        let mut names = vec![0];
        for f in files {
            names.extend_from_slice(&f.name);
            names.extend_from_slice(&[0, 0]);
        }
        property(&mut h, 17, &names);
        for (index, kind) in [20, 18, 19].into_iter().enumerate() {
            let count = files.iter().filter(|f| f.times[index].is_some()).count();
            if count == 0 {
                continue;
            }
            let mut data = vec![u8::from(count == files.len())];
            if count != files.len() {
                data.extend(bools(files.iter().map(|f| f.times[index].is_some())));
            }
            data.push(0);
            for f in files {
                if let Some(t) = f.times[index] {
                    data.extend_from_slice(&t.to_le_bytes());
                }
            }
            property(&mut h, kind, &data);
        }
        let mut attributes = vec![1, 0];
        for f in files {
            let attr = (f.mode << 16)
                | 0x8000
                | if f.dir() { 0x10 } else { 0x20 }
                | u32::from(f.mode & 0o222 == 0);
            attributes.extend_from_slice(&attr.to_le_bytes());
        }
        property(&mut h, 21, &attributes);
        h.extend_from_slice(&[0, 0]);
        h
    }
}
fn uint(out: &mut Vec<u8>, mut n: u64) {
    let at = out.len();
    out.push(0);
    let mut mask = 0x80;
    for _ in 0..8 {
        if n < u64::from(mask) {
            out[at] |= n as u8;
            return;
        }
        out.push(n as u8);
        n >>= 8;
        out[at] |= mask;
        mask >>= 1;
    }
}
fn bools(values: impl Iterator<Item = bool>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut mask = 0x80;
    let mut byte = 0;
    for v in values {
        if v {
            byte |= mask
        }
        mask >>= 1;
        if mask == 0 {
            out.push(byte);
            byte = 0;
            mask = 0x80;
        }
    }
    if mask != 0x80 {
        out.push(byte);
    }
    out
}
fn property(out: &mut Vec<u8>, kind: u8, data: &[u8]) {
    out.push(kind);
    uint(out, data.len() as u64);
    out.extend_from_slice(data);
}
fn streams(
    h: &mut Vec<u8>,
    offset: u64,
    packed: u64,
    unpacked: u64,
    coder: (u32, &[u8]),
    files: Option<&[&FileInfo]>,
    crc: Option<u32>,
) {
    let (codec, props) = coder;
    let folder_count = if codec == COPY {
        files.map_or(1, |f| f.len())
    } else {
        1
    };
    h.push(6);
    uint(h, offset);
    uint(h, folder_count as u64);
    h.push(9);
    for i in 0..folder_count {
        uint(
            h,
            if folder_count > 1 {
                files.and_then(|f| f.get(i)).map_or(0, |f| f.size)
            } else {
                packed
            },
        );
    }
    h.extend_from_slice(&[0, 7, 11]);
    uint(h, folder_count as u64);
    h.push(0);
    let bytes = codec.to_be_bytes();
    let begin = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let id = &bytes[begin..];
    for _ in 0..folder_count {
        h.push(1);
        h.push(id.len() as u8 | if props.is_empty() { 0 } else { 0x20 });
        h.extend_from_slice(id);
        if !props.is_empty() {
            uint(h, props.len() as u64);
            h.extend_from_slice(props);
        }
    }
    h.push(12);
    for i in 0..folder_count {
        uint(
            h,
            if folder_count > 1 {
                files.and_then(|f| f.get(i)).map_or(0, |f| f.size)
            } else {
                unpacked
            },
        );
    }
    if let Some(crc) = crc {
        h.extend_from_slice(&[10, 1]);
        h.extend_from_slice(&crc.to_le_bytes());
    }
    h.push(0);
    if let Some(files) = files {
        h.push(8);
        if files.len() > 1 && codec != COPY {
            h.push(13);
            uint(h, files.len() as u64);
            h.push(9);
            for f in &files[..files.len() - 1] {
                uint(h, f.size);
            }
        }
        h.extend_from_slice(&[10, 1]);
        for f in files {
            h.extend_from_slice(&f.crc.to_le_bytes());
        }
        h.push(0);
    }
    h.push(0);
}
impl Format for SevenZip {
    fn code(&self) -> c_int {
        0xe0000
    }
    fn name(&self) -> &'static CStr {
        c"7zip"
    }
    fn module(&self) -> &'static [u8] {
        b"7zip"
    }
    fn options(&mut self, _: &Base, key: &[u8], value: Option<&[u8]>) -> Result<c_int, Error> {
        match key {
            b"compression" => {
                let name = value.unwrap_or(b"copy");
                self.codec =
                    if name.eq_ignore_ascii_case(b"copy") || name.eq_ignore_ascii_case(b"store") {
                        COPY
                    } else if name.eq_ignore_ascii_case(b"deflate") {
                        DEFLATE
                    } else if name.eq_ignore_ascii_case(b"bzip2") {
                        BZIP
                    } else if name.eq_ignore_ascii_case(b"lzma1") {
                        LZMA
                    } else if name.eq_ignore_ascii_case(b"lzma2") {
                        LZMA2
                    } else if name.eq_ignore_ascii_case(b"ppmd") {
                        PPMD
                    } else if name.eq_ignore_ascii_case(b"zstd") {
                        ZSTD
                    } else {
                        return Err(Error::new(
                            ARCHIVE_FAILED,
                            -1,
                            [b"Unknown compression name: `".as_slice(), name, b"'"].concat(),
                        ));
                    };
            }
            b"compression-level" => {
                let n = value
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .and_then(|v| v.parse::<i64>().ok())
                    .ok_or_else(|| {
                        Error::new(ARCHIVE_FAILED, -1, "Invalid compression-level option value")
                    })?;
                if !(-131072..=22).contains(&n) {
                    return Err(Error::new(
                        ARCHIVE_FAILED,
                        -1,
                        format!("compression-level option value `{n}' out of range"),
                    ));
                }
                self.level = n;
            }
            b"threads" => {
                let n = value
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .and_then(|v| v.parse::<u32>().ok());
                if n.is_none_or(|n| n > i32::MAX as u32) {
                    return Ok(ARCHIVE_WARN);
                }
            }
            _ => return Ok(ARCHIVE_WARN),
        }
        Ok(ARCHIVE_OK)
    }
    fn header(&mut self, a: &Base, e: &mut Entry, _: &mut dyn Sink) -> Result<c_int, Error> {
        self.current = None;
        self.remaining = 0;
        let conv = {
            let mut cache = a
                .conv
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            crate::string::conversion_to_charset(Some(&mut *cache), b"UTF-16LE", true)
                .map_err(|err| Error::fatal(err.errno, err.message))?
        };
        let (name, ok) = e.pathname_l(Some(&conv));
        let name = name
            .ok_or_else(|| Error::new(ARCHIVE_FAILED, -1, "Missing pathname"))?
            .to_vec();
        let mode = u32::from(e.mode());
        let kind = e.filetype();
        let sym = if kind == 0o120000 {
            Some(
                e.symlink_utf8()
                    .ok_or_else(|| {
                        Error::new(
                            ARCHIVE_FAILED,
                            -1,
                            "symlink path could not be converted to UTF-8",
                        )
                    })?
                    .to_bytes()
                    .to_vec(),
            )
        } else {
            None
        };
        let size = if kind == 0o100000 {
            u64::try_from(e.size())
                .map_err(|_| Error::new(ARCHIVE_FAILED, -1, "Invalid entry size"))?
        } else {
            e.set_size(0);
            sym.as_ref().map_or(0, |s| s.len() as u64)
        };
        if kind == 0o40000 && self.files.iter().any(|f| f.dir() && f.name == name) {
            return Ok(ARCHIVE_OK);
        }
        let times = [
            (e.mtime_is_set(), e.mtime(), e.mtime_nsec()),
            (e.ctime_is_set(), e.ctime(), e.ctime_nsec()),
            (e.atime_is_set(), e.atime(), e.atime_nsec()),
        ]
        .map(|(set, secs, ns)| {
            if set != 0 {
                Some(crate::time::unix_to_ntfs(secs, ns as u32))
            } else {
                None
            }
        });
        if size > 0 {
            self.initialize()?;
        }
        self.files
            .try_reserve(1)
            .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate memory"))?;
        self.current = Some(self.files.len());
        self.remaining = size;
        self.files.push(FileInfo {
            name,
            mode,
            size,
            times,
            crc: 0,
        });
        if let Some(sym) = sym {
            self.append(&sym)?;
            self.remaining = 0;
        }
        if !ok {
            a.set_error(-1,Some(b"A filename cannot be converted to UTF-16LE;You should disable making Joliet extension"));
            Ok(ARCHIVE_WARN)
        } else {
            Ok(ARCHIVE_OK)
        }
    }
    fn data(&mut self, data: &[u8], _: &mut dyn Sink) -> Result<usize, Error> {
        let n = data
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        self.append(&data[..n])?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn finish_entry(&mut self, _: &mut dyn Sink) -> Result<(), Error> {
        let zeros = [0; 65536];
        while self.remaining > 0 {
            let n = self.remaining.min(zeros.len() as u64) as usize;
            self.append(&zeros[..n])?;
            self.remaining -= n as u64;
        }
        self.current = None;
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if self.coder.is_none() && self.spool.is_some() {
            self.start_coder(Some(self.pending.len()))?;
        }
        if let (Some(coder), Some(spool)) = (self.coder.take(), self.spool.as_mut()) {
            coder.finish(spool)?;
        }
        let mut files: Vec<_> = self.files.iter().filter(|f| f.size > 0).collect();
        files.extend(self.files.iter().filter(|f| f.size == 0 && !f.dir()));
        let mut dirs: Vec<_> = self.files.iter().filter(|f| f.dir()).collect();
        dirs.sort_by(|a, b| b.name.len().cmp(&a.name.len()).then(b.name.cmp(&a.name)));
        files.extend(dirs);
        let packed = self.spool.as_ref().map_or(0, |s| s.len);
        let unpacked = files
            .iter()
            .try_fold(0u64, |n, f| n.checked_add(f.size))
            .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "7-Zip file too large"))?;
        let mut header = if files.is_empty() {
            Vec::new()
        } else {
            self.header_bytes(&files, packed, unpacked)
        };
        let mut encoded_header = Vec::new();
        if files.len() > 1 && self.codec != COPY {
            let header_codec = if self.codec == LZMA2 { LZMA2 } else { LZMA };
            let (mut coder, props) =
                Coder::new(header_codec, self.level.clamp(0, 9), Some(header.len()))?;
            struct VecSink<'a>(&'a mut Vec<u8>);
            impl Sink for VecSink<'_> {
                fn write(&mut self, data: &[u8]) -> Result<(), Error> {
                    self.0
                        .try_reserve(data.len())
                        .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate 7-Zip header"))?;
                    self.0.extend_from_slice(data);
                    Ok(())
                }
            }
            coder.write(&header, &mut VecSink(&mut encoded_header))?;
            coder.finish(&mut VecSink(&mut encoded_header))?;
            let mut next = vec![23];
            streams(
                &mut next,
                packed,
                encoded_header.len() as u64,
                header.len() as u64,
                (header_codec, &props),
                None,
                Some(crate::crc32::crc32(0, &header)),
            );
            header = next;
        }
        let header_offset = packed
            .checked_add(encoded_header.len() as u64)
            .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "7-Zip header too large"))?;
        let mut start = b"7z\xbc\xaf\x27\x1c\0\x03".to_vec();
        let mut fields = Vec::new();
        fields.extend_from_slice(&header_offset.to_le_bytes());
        fields.extend_from_slice(&(header.len() as u64).to_le_bytes());
        fields.extend_from_slice(&crate::crc32::crc32(0, &header).to_le_bytes());
        start.extend_from_slice(&crate::crc32::crc32(0, &fields).to_le_bytes());
        start.extend_from_slice(&fields);
        sink.write(&start)?;
        if let Some(spool) = &mut self.spool {
            spool.file.seek(SeekFrom::Start(0)).map_err(io_error)?;
            let mut buf = [0; 65536];
            loop {
                let n = spool.file.read(&mut buf).map_err(io_error)?;
                if n == 0 {
                    break;
                }
                sink.write(&buf[..n])?;
            }
        }
        sink.write(&encoded_header)?;
        sink.write(&header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Bytes(Vec<u8>);
    impl Sink for Bytes {
        fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.0.extend_from_slice(data);
            Ok(())
        }
    }

    fn decode(codec: u32, props: &[u8], data: &[u8], size: usize) -> Vec<u8> {
        let mut reader: Box<dyn Read + '_> = if codec == LZMA {
            Box::new(
                lzma_rust2::LzmaReader::new_with_props(
                    data,
                    size as u64,
                    props[0],
                    u32::from_le_bytes(props[1..5].try_into().unwrap()),
                    None,
                )
                .unwrap(),
            )
        } else {
            let p = props[0];
            Box::new(lzma_rust2::Lzma2Reader::new(
                data,
                (2 | u32::from(p & 1)) << (p / 2 + 11),
                None,
            ))
        };
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        decoded
    }

    #[test]
    fn sized_coders_preserve_properties_and_roundtrip() {
        for codec in [LZMA, LZMA2] {
            for size in [0, 1, 4095, 4096, 4097, 65537] {
                let data: Vec<_> = (0..size).map(|i| (i * 37 % 251) as u8).collect();
                let (mut coder, props) = Coder::new(codec, 0, Some(size)).unwrap();
                let mut encoded = Bytes(Vec::new());
                coder.write(&data, &mut encoded).unwrap();
                coder.finish(&mut encoded).unwrap();
                let (_, original_props) = Coder::new(codec, 0, None).unwrap();
                assert_eq!(props, original_props);
                assert_eq!(decode(codec, &props, &encoded.0, size), data);
            }
        }
    }

    #[test]
    fn small_solid_stream_finishes_with_padding_and_per_file_crcs() {
        for codec in [LZMA, LZMA2] {
            let mut archive = SevenZip {
                codec,
                level: 0,
                ..SevenZip::default()
            };
            let mut output = Bytes(Vec::new());
            archive.initialize().unwrap();
            let mut expected = Vec::new();
            for (name, data, padding) in [(b"a", b"first".as_slice(), 0), (b"b", b"second", 3)] {
                let size = data.len() + padding;
                archive.current = Some(archive.files.len());
                archive.remaining = size as u64;
                archive.files.push(FileInfo {
                    name: vec![name[0], 0],
                    mode: 0o100644,
                    size: size as u64,
                    times: [None; 3],
                    crc: 0,
                });
                archive.data(data, &mut output).unwrap();
                archive.finish_entry(&mut output).unwrap();
                let mut padded = data.to_vec();
                padded.resize(size, 0);
                assert_eq!(
                    archive.files.last().unwrap().crc,
                    crate::crc32::crc32(0, &padded)
                );
                expected.extend(padded);
            }
            assert!(archive.coder.is_none());
            archive.close(&mut output).unwrap();
            assert_eq!(archive.pending.capacity(), 0);
            let packed = archive.spool.as_ref().unwrap().len as usize;
            assert_eq!(
                decode(
                    codec,
                    &archive.properties,
                    &output.0[32..32 + packed],
                    expected.len()
                ),
                expected
            );
        }
    }

    #[test]
    fn solid_staging_flushes_once_at_dictionary_boundary() {
        for codec in [LZMA, LZMA2] {
            let mut archive = SevenZip {
                codec,
                level: 0,
                ..SevenZip::default()
            };
            archive.initialize().unwrap();
            let limit = LzmaOptions::with_preset(0).dict_size as usize;
            let data: Vec<_> = (0..limit).map(|i| (i * 17 % 251) as u8).collect();
            // Separate writes stand in for successive entries in a solid stream.
            archive.append(&data[..limit / 3]).unwrap();
            archive.append(&data[limit / 3..2 * limit / 3]).unwrap();
            archive.append(&data[2 * limit / 3..]).unwrap();
            assert!(archive.coder.is_none());
            assert_eq!(archive.pending.len(), limit);
            assert_eq!(archive.pending.capacity(), limit);
            archive.append(&data).unwrap();
            assert!(archive.coder.is_some());
            assert_eq!(archive.pending.capacity(), 0);
            archive
                .coder
                .take()
                .unwrap()
                .finish(archive.spool.as_mut().unwrap())
                .unwrap();
            let spool = archive.spool.as_mut().unwrap();
            spool.file.rewind().unwrap();
            let mut encoded = Vec::new();
            spool.file.read_to_end(&mut encoded).unwrap();
            assert_eq!(
                decode(codec, &archive.properties, &encoded, limit * 2),
                data.repeat(2)
            );
        }
    }
}
