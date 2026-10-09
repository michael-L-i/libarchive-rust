/*-
 * Copyright (c) 2003-2010 Tim Kientzle
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

// Ported from libarchive/archive_write.c.

use crate::archive::*;
use crate::entry::Entry;
use crate::util::Error;
use std::ffi::{CStr, c_int};

pub mod filter;
pub mod format;

pub trait Sink {
    fn write(&mut self, data: &[u8]) -> Result<(), Error>;
    fn open(&mut self) -> Result<c_int, Error> {
        Ok(ARCHIVE_OK)
    }
    fn close(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn free(&mut self) {}
}

pub trait Filter {
    fn open(&mut self, _sink: &mut dyn Sink) -> Result<(), Error> {
        Ok(())
    }
    fn finish_entry(&mut self, _sink: &mut dyn Sink) -> Result<(), Error> {
        Ok(())
    }
    fn write(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<(), Error>;
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error>;
    fn code(&self) -> c_int;
    fn name(&self) -> &CStr;
    fn options(&mut self, _key: &[u8], _value: Option<&[u8]>) -> Result<c_int, Error> {
        Ok(ARCHIVE_WARN)
    }
}

pub trait Format {
    fn needs_passphrase(&self) -> bool {
        false
    }
    fn set_passphrase(&mut self, _: Option<&[u8]>) {}
    fn code(&self) -> c_int;
    fn name(&self) -> &'static CStr;
    fn module(&self) -> &'static [u8];
    fn header(&mut self, a: &Base, entry: &mut Entry, sink: &mut dyn Sink) -> Result<c_int, Error>;
    fn data(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<usize, Error>;
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error>;
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error>;
    fn options(&mut self, _a: &Base, _key: &[u8], _value: Option<&[u8]>) -> Result<c_int, Error> {
        Ok(ARCHIVE_WARN)
    }
}

pub struct Write {
    pub bytes_per_block: c_int,
    pub bytes_in_last_block: c_int,
    pub skip_file: Option<(i64, i64)>,
    pub filters: Vec<Box<dyn Filter>>,
    pub format: Option<Box<dyn Format>>,
    pub passphrase: Option<Vec<u8>>,
    pub passphrase_callback: Option<Box<dyn FnMut() -> Option<Vec<u8>>>>,
    output: Option<Blocking>,
    bytes: Vec<i64>,
}

impl Default for Write {
    fn default() -> Self {
        Self {
            bytes_per_block: 10240,
            bytes_in_last_block: -1,
            skip_file: None,
            filters: Vec::new(),
            format: None,
            passphrase: None,
            passphrase_callback: None,
            output: None,
            bytes: Vec::new(),
        }
    }
}

struct Blocking {
    sink: Box<dyn Sink>,
    block: usize,
    last: c_int,
    buf: Vec<u8>,
    bytes: i64,
}
impl Sink for Blocking {
    fn write(&mut self, mut data: &[u8]) -> Result<(), Error> {
        self.bytes = self.bytes.saturating_add(data.len() as i64);
        if self.block == 0 {
            return self.sink.write(data);
        }
        if !self.buf.is_empty() {
            let n = data.len().min(self.block - self.buf.len());
            self.buf.extend_from_slice(&data[..n]);
            data = &data[n..];
            if self.buf.len() == self.block {
                self.sink.write(&self.buf)?;
                self.buf.clear();
            }
        }
        while data.len() >= self.block {
            self.sink.write(&data[..self.block])?;
            data = &data[self.block..];
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }
    fn close(&mut self) -> Result<(), Error> {
        let result = if self.buf.is_empty() {
            Ok(())
        } else {
            let n = if self.last <= 0 {
                self.block
            } else {
                self.buf
                    .len()
                    .div_ceil(self.last as usize)
                    .saturating_mul(self.last as usize)
                    .min(self.block)
            };
            self.buf.resize(n.max(self.buf.len()), 0);
            let r = self.sink.write(&self.buf);
            self.buf.clear();
            r
        };
        let r = self.sink.close();
        result.and(r)
    }
}

struct Pipeline<'a> {
    filters: &'a mut [Box<dyn Filter>],
    bytes: &'a mut [i64],
    output: &'a mut Blocking,
}
impl Sink for Pipeline<'_> {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        if let Some((first, rest)) = self.filters.split_first_mut() {
            let (count, counts) = self
                .bytes
                .split_first_mut()
                .ok_or_else(|| Error::fatal(-1, "Missing filter state"))?;
            *count = count.saturating_add(data.len() as i64);
            first.write(
                data,
                &mut Pipeline {
                    filters: rest,
                    bytes: counts,
                    output: self.output,
                },
            )
        } else {
            self.output.write(data)
        }
    }
}

impl Write {
    #[allow(dead_code)] // Used by the compression filter API.
    pub fn add_filter(&mut self, filter: Box<dyn Filter>) -> c_int {
        self.filters.push(filter);
        self.bytes.push(0);
        ARCHIVE_OK
    }
    pub fn set_format(&mut self, a: &Base, format: Box<dyn Format>) -> c_int {
        a.format.set(format.code());
        a.format_name.set(Some(format.name()));
        self.format = Some(format);
        ARCHIVE_OK
    }
    pub fn open(&mut self, a: &Base, mut sink: Box<dyn Sink>) -> c_int {
        a.clear_error();
        let block = self.bytes_per_block as usize;
        let mut buf = Vec::new();
        if buf.try_reserve_exact(block).is_err() {
            return a.raise(Error::fatal(
                libc::ENOMEM,
                "Can't allocate data for output buffering",
            ));
        }
        let r = match sink.open() {
            Ok(r) => r,
            Err(e) => {
                sink.free();
                return a.raise(e);
            }
        };
        if r < ARCHIVE_WARN {
            sink.free();
            return r;
        }
        self.output = Some(Blocking {
            sink,
            block,
            last: self.bytes_in_last_block,
            buf,
            bytes: 0,
        });
        if let Some(output) = self.output.as_mut() {
            for i in (0..self.filters.len()).rev() {
                let (head, tail) = self.filters.split_at_mut(i + 1);
                let (_, counts) = self.bytes.split_at_mut(i + 1);
                if let Err(e) = head[i].open(&mut Pipeline {
                    filters: tail,
                    bytes: counts,
                    output,
                }) {
                    return a.raise(e);
                }
            }
        }
        a.state.set(state::HEADER);
        r
    }
    fn run<T>(
        &mut self,
        a: &Base,
        f: impl FnOnce(&mut dyn Format, &mut dyn Sink) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let Some(format) = self.format.as_mut() else {
            a.state.set(state::FATAL);
            return Err(Error::fatal(
                -1,
                "Format must be set before you can write to an archive",
            ));
        };
        let Some(output) = self.output.as_mut() else {
            return Err(Error::fatal(-1, "Archive is not open"));
        };
        let result = f(
            format.as_mut(),
            &mut Pipeline {
                filters: &mut self.filters,
                bytes: &mut self.bytes,
                output,
            },
        );
        if result.as_ref().is_err_and(|e| e.code == ARCHIVE_FATAL) {
            a.state.set(state::FATAL);
        }
        result
    }
    pub fn header(&mut self, a: &Base, entry: &mut Entry) -> c_int {
        if a.check_magic(
            WRITE_MAGIC,
            state::HEADER | state::DATA,
            "archive_write_header",
        ) == ARCHIVE_FATAL
        {
            return ARCHIVE_FATAL;
        }
        a.clear_error();
        let r = self.finish_entry(a);
        if r < ARCHIVE_WARN {
            return r;
        }
        if self.skip_file.is_some_and(|(d, i)| {
            entry.dev_is_set() != 0
                && entry.ino_is_set() != 0
                && entry.dev() as i64 == d
                && entry.ino() == i
        }) {
            return a.raise(Error::new(
                ARCHIVE_FAILED,
                libc::EIO,
                "Can't add archive to itself",
            ));
        }
        if self.format.as_ref().is_some_and(|f| f.needs_passphrase()) {
            if self.passphrase.is_none()
                && let Some(cb) = self.passphrase_callback.as_mut()
            {
                self.passphrase = cb();
            }
            if let Some(f) = self.format.as_mut() {
                f.set_passphrase(self.passphrase.as_deref());
            }
        }
        match self.run(a, |f, s| f.header(a, entry, s)) {
            Ok(ret) => {
                if ret >= ARCHIVE_WARN {
                    a.state.set(state::DATA);
                }
                ret.min(r)
            }
            Err(e) => a.raise(e),
        }
    }
    pub fn data(&mut self, a: &Base, data: &[u8]) -> isize {
        if a.check_magic(WRITE_MAGIC, state::DATA, "archive_write_data") == ARCHIVE_FATAL {
            return ARCHIVE_FATAL as isize;
        }
        a.clear_error();
        let data = &data[..data.len().min(c_int::MAX as usize)];
        match self.run(a, |f, s| f.data(data, s)) {
            Ok(n) => n as isize,
            Err(e) => a.raise(e) as isize,
        }
    }
    pub fn finish_entry(&mut self, a: &Base) -> c_int {
        if a.check_magic(
            WRITE_MAGIC,
            state::HEADER | state::DATA,
            "archive_write_finish_entry",
        ) == ARCHIVE_FATAL
        {
            return ARCHIVE_FATAL;
        }
        if a.state.get() == state::HEADER {
            return ARCHIVE_OK;
        }
        match self.run(a, |f, s| f.finish_entry(s)) {
            Ok(()) => {
                if let Some(output) = self.output.as_mut() {
                    for i in 0..self.filters.len() {
                        let (head, tail) = self.filters.split_at_mut(i + 1);
                        let (_, counts) = self.bytes.split_at_mut(i + 1);
                        if let Err(e) = head[i].finish_entry(&mut Pipeline {
                            filters: tail,
                            bytes: counts,
                            output,
                        }) {
                            return a.raise(e);
                        }
                    }
                }
                a.state.set(state::HEADER);
                ARCHIVE_OK
            }
            Err(e) => a.raise(e),
        }
    }
    pub fn close(&mut self, a: &Base) -> c_int {
        if a.state.get() == state::NEW || a.state.get() == state::CLOSED {
            return ARCHIVE_OK;
        }
        if a.state.get() == state::FATAL {
            return ARCHIVE_FATAL;
        }
        a.clear_error();
        let mut r = ARCHIVE_OK;
        if a.state.get() == state::DATA {
            r = self.finish_entry(a);
        }
        if self.format.is_some()
            && let Err(e) = self.run(a, |f, s| f.close(s))
        {
            r = r.min(a.raise(e));
        }
        if let Some(output) = self.output.as_mut() {
            for i in 0..self.filters.len() {
                let (head, tail) = self.filters.split_at_mut(i + 1);
                let (_, counts) = self.bytes.split_at_mut(i + 1);
                if let Err(e) = head[i].close(&mut Pipeline {
                    filters: tail,
                    bytes: counts,
                    output,
                }) {
                    r = r.min(a.raise(e));
                }
            }
            output.last = self.bytes_in_last_block;
            if let Err(e) = output.close() {
                r = r.min(a.raise(e));
            }
        }
        if a.state.get() != state::FATAL {
            a.state.set(state::CLOSED);
        }
        r
    }
    pub fn option(
        &mut self,
        a: &Base,
        module: Option<&[u8]>,
        key: &[u8],
        value: Option<&[u8]>,
        formats: bool,
        filters: bool,
    ) -> c_int {
        let mut matched = module.is_none();
        let mut result = ARCHIVE_WARN;
        if formats
            && let Some(f) = self.format.as_mut()
            && module.is_none_or(|m| m == f.module())
        {
            matched = true;
            result = match f.options(a, key, value) {
                Ok(r) => r,
                Err(e) => a.raise(e),
            };
        }
        if filters {
            for f in &mut self.filters {
                if module.is_none_or(|m| m == f.name().to_bytes()) {
                    matched = true;
                    let r = match f.options(key, value) {
                        Ok(r) => r,
                        Err(e) => a.raise(e),
                    };
                    if r < ARCHIVE_WARN {
                        return r;
                    }
                    if r == ARCHIVE_OK {
                        result = ARCHIVE_OK;
                    }
                }
            }
        }
        if matched {
            result
        } else {
            crate::options::UNKNOWN_MODULE
        }
    }
    pub fn free(&mut self, a: &Base) -> c_int {
        let r = if a.state.get() == state::FATAL {
            ARCHIVE_OK
        } else {
            self.close(a)
        };
        if let Some(mut out) = self.output.take() {
            out.sink.free();
        }
        if let Some(p) = self.passphrase.as_mut() {
            p.fill(0);
        }
        r
    }
    pub fn filter_count(&self) -> c_int {
        (self.filters.len() + usize::from(self.output.is_some())) as c_int
    }
    fn index(&self, n: c_int) -> Option<usize> {
        let n = if n < 0 { self.filter_count() - 1 } else { n };
        usize::try_from(n).ok()
    }
    pub fn filter_code(&self, n: c_int) -> c_int {
        self.index(n)
            .map_or(-1, |n| self.filters.get(n).map_or(0, |f| f.code()))
    }
    pub fn filter_name(&self, n: c_int) -> Option<&CStr> {
        self.index(n)
            .filter(|&n| n < self.filter_count() as usize)
            .map(|n| self.filters.get(n).map_or(c"none", |f| f.name()))
    }
    pub fn filter_bytes(&self, n: c_int) -> i64 {
        self.index(n).map_or(-1, |n| {
            self.bytes
                .get(n)
                .copied()
                .or_else(|| self.output.as_ref().map(|o| o.bytes))
                .unwrap_or(-1)
        })
    }
}

#[allow(dead_code)] // Shared padding helper for block-oriented formats.
pub fn zeros(sink: &mut dyn Sink, mut count: u64) -> Result<(), Error> {
    let block = [0u8; 8192];
    while count > 0 {
        let n = count.min(block.len() as u64) as usize;
        sink.write(&block[..n])?;
        count -= n as u64;
    }
    Ok(())
}

/// A private seekable spool, unlinked immediately so errors cannot leave it behind.
#[allow(dead_code)] // Shared by XAR, ISO9660 and 7zip writers as they land.
pub(crate) fn temp_file() -> Result<std::fs::File, Error> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for _ in 0..32 {
        let path = std::env::temp_dir().join(format!(
            "libarchive-rust-{}-{stamp:x}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                std::fs::remove_file(&path).map_err(|e| {
                    Error::fatal(
                        e.raw_os_error().unwrap_or(libc::EIO),
                        "Couldn't unlink temporary file",
                    )
                })?;
                return Ok(file);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(Error::fatal(
                    e.raw_os_error().unwrap_or(libc::EIO),
                    "Couldn't create temporary file",
                ));
            }
        }
    }
    Err(Error::fatal(libc::EEXIST, "Couldn't create temporary file"))
}
