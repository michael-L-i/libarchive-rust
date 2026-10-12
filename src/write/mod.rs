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
    fn position(&self) -> u64 {
        0
    }
    fn write(&mut self, data: &[u8]) -> Result<(), Error>;
    fn open(&mut self) -> Result<c_int, Error> {
        Ok(ARCHIVE_OK)
    }
    fn close(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn free(&mut self) {}
    /// archive_write_get_bytes_per_block() of the archive a filter writes
    /// to, or 0 outside a write pipeline.
    fn bytes_per_block(&self) -> usize {
        0
    }
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
    fn has_options(&self) -> bool {
        false
    }
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
    fn close_with_base(&mut self, _a: &Base, sink: &mut dyn Sink) -> Result<(), Error> {
        self.close(sink)
    }
    fn options(&mut self, _a: &Base, _key: &[u8], _value: Option<&[u8]>) -> Result<c_int, Error> {
        Ok(ARCHIVE_WARN)
    }
    /// The `archive_write_set_bytes_in_last_block` a successful `close`
    /// made, if it made one.
    fn bytes_in_last_block(&self) -> Option<c_int> {
        None
    }
}

/// Records a format's error and returns its code. A format call without
/// the handle reports upstream's "set error, return `ARCHIVE_WARN`" as an
/// `Error` carrying `ARCHIVE_WARN`.
fn report(a: &Base, e: Error) -> c_int {
    if e.code == ARCHIVE_WARN {
        a.set_error(e.errno, Some(&e.msg));
        return ARCHIVE_WARN;
    }
    a.raise(e)
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
    fn position(&self) -> u64 {
        self.bytes.max(0) as u64
    }
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
    fn bytes_per_block(&self) -> usize {
        self.output.block
    }
    fn position(&self) -> u64 {
        self.bytes
            .first()
            .map_or(self.output.bytes.max(0) as u64, |n| (*n).max(0) as u64)
    }
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
                    let mut status = a.raise(e);
                    // Only downstream filters have opened successfully.
                    for j in i + 1..self.filters.len() {
                        let (head, tail) = self.filters.split_at_mut(j + 1);
                        let (_, counts) = self.bytes.split_at_mut(j + 1);
                        if let Err(e) = head[j].close(&mut Pipeline {
                            filters: tail,
                            bytes: counts,
                            output,
                        }) {
                            status = status.min(a.raise(e));
                        }
                    }
                    if let Err(e) = output.close() {
                        status = status.min(a.raise(e));
                    }
                    if let Some(mut output) = self.output.take() {
                        output.sink.free();
                    }
                    self.filters.clear();
                    self.bytes.clear();
                    return status;
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
            Err(e) => report(a, e),
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
            Err(e) => report(a, e) as isize,
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
                            a.state.set(if e.code == ARCHIVE_FATAL {
                                state::FATAL
                            } else {
                                state::HEADER
                            });
                            return a.raise(e);
                        }
                    }
                }
                a.state.set(state::HEADER);
                ARCHIVE_OK
            }
            Err(e) => {
                a.state.set(if e.code == ARCHIVE_FATAL {
                    state::FATAL
                } else {
                    state::HEADER
                });
                report(a, e)
            }
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
        if self.format.is_some() {
            match self.run(a, |f, s| f.close_with_base(a, s)) {
                Ok(()) => {
                    if let Some(n) = self.format.as_ref().and_then(|f| f.bytes_in_last_block()) {
                        self.bytes_in_last_block = n;
                    }
                }
                Err(e) => r = r.min(report(a, e)),
            }
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
        // Upstream calls the format's finish_entry and close directly, so
        // their failures leave the state alone and the archive ends closed.
        a.state.set(state::CLOSED);
        r
    }
    /// `archive_set_format_option`.
    fn format_option(
        format: &mut Option<Box<dyn Format>>,
        a: &Base,
        module: Option<&[u8]>,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> c_int {
        let Some(f) = format.as_mut() else {
            return if module.is_none() {
                ARCHIVE_FAILED
            } else {
                crate::options::UNKNOWN_MODULE
            };
        };
        // If the format name didn't match, return a special code.
        if module.is_some_and(|m| m != f.module()) {
            return crate::options::UNKNOWN_MODULE;
        }
        match f.options(a, key, value) {
            Ok(r) => r,
            Err(e) => report(a, e),
        }
    }

    /// `archive_set_filter_option`.
    fn filter_option(
        filters: &mut [Box<dyn Filter>],
        a: &Base,
        module: Option<&[u8]>,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> c_int {
        let mut rv = ARCHIVE_WARN;
        for f in filters {
            if !f.has_options() {
                continue;
            }
            if module.is_some_and(|m| m != f.name().to_bytes()) {
                continue;
            }
            let r = match f.options(key, value) {
                Ok(r) => r,
                Err(e) => a.raise(e),
            };
            if r == ARCHIVE_FATAL {
                return ARCHIVE_FATAL;
            }
            if module.is_some() {
                return r;
            }
            if r == ARCHIVE_OK {
                rv = ARCHIVE_OK;
            }
        }
        // If the filter name didn't match, return a special code.
        if rv == ARCHIVE_WARN && module.is_some() {
            rv = crate::options::UNKNOWN_MODULE;
        }
        rv
    }

    /// One option for the format, the filters, or both as
    /// `_archive_set_either_option` combines them.
    pub fn option(
        &mut self,
        a: &Base,
        module: Option<&[u8]>,
        key: &[u8],
        value: Option<&[u8]>,
        formats: bool,
        filters: bool,
    ) -> c_int {
        let (format, filter) = (&mut self.format, &mut self.filters);
        match (formats, filters) {
            (true, false) => Self::format_option(format, a, module, key, value),
            (false, true) => Self::filter_option(filter, a, module, key, value),
            _ => crate::options::set_either_option(
                module,
                key,
                value,
                &mut |m, o, v| Self::format_option(format, a, m, o, v),
                &mut |m, o, v| Self::filter_option(filter, a, m, o, v),
            ),
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
pub(crate) fn temp_file() -> Result<std::fs::File, Error> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let directory = crate::ffi::util::get_tempdir();
    for _ in 0..32 {
        let path = directory.join(format!(
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

pub fn unsupported(entry: &mut Entry, format: &[u8]) -> Error {
    let description: Option<&[u8]> = match entry.filetype() {
        0o040000 => Some(b"directories".as_slice()),
        0o120000 => Some(b"symbolic links"),
        0o020000 => Some(b"character devices"),
        0o060000 => Some(b"block devices"),
        0o010000 => Some(b"named pipes"),
        0o140000 => Some(b"sockets"),
        _ => None,
    };
    let mode = entry.mode();
    let path = entry.pathname().map(|s| s.to_bytes()).unwrap_or(b"(null)");
    let kind = description
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| format!("files with mode 0{mode:o}").into_bytes());
    Error::new(
        ARCHIVE_FAILED,
        crate::read::ARCHIVE_ERRNO_FILE_FORMAT,
        [path, b": ", format, b" format cannot archive ", &kind].concat(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct Client(Rc<RefCell<Vec<&'static str>>>);
    impl Sink for Client {
        fn write(&mut self, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
        fn close(&mut self) -> Result<(), Error> {
            self.0.borrow_mut().push("client close");
            Ok(())
        }
        fn free(&mut self) {
            self.0.borrow_mut().push("client free");
        }
    }
    struct TestFilter {
        events: Rc<RefCell<Vec<&'static str>>>,
        fail: bool,
    }
    impl Filter for TestFilter {
        fn open(&mut self, _: &mut dyn Sink) -> Result<(), Error> {
            if self.fail {
                Err(Error::fatal(libc::EIO, "test open failure"))
            } else {
                Ok(())
            }
        }
        fn write(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
            sink.write(data)
        }
        fn close(&mut self, _: &mut dyn Sink) -> Result<(), Error> {
            self.events.borrow_mut().push(if self.fail {
                "failed filter close"
            } else {
                "tail close"
            });
            Ok(())
        }
        fn code(&self) -> c_int {
            0
        }
        fn name(&self) -> &CStr {
            c"test"
        }
    }
    struct Collect(Rc<RefCell<Vec<u8>>>);
    impl Sink for Collect {
        fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.0.borrow_mut().extend_from_slice(data);
            Ok(())
        }
    }

    fn file(size: i64) -> Entry {
        let mut e = Entry::new(None);
        e.set_pathname(b"f");
        e.set_mode(0o100644);
        e.set_size(size);
        e
    }

    #[test]
    fn format_warnings_without_the_handle_are_recorded() {
        let base = Base::new(WRITE_MAGIC);
        let mut writer = Write::default();
        writer.set_format(&base, Box::new(format::ar::Ar::new(false)));
        let out = Rc::new(RefCell::new(Vec::new()));
        assert_eq!(writer.open(&base, Box::new(Collect(out))), ARCHIVE_OK);
        assert_eq!(writer.header(&base, &mut file(2)), ARCHIVE_OK);
        assert_eq!(writer.data(&base, b"x"), 1);
        assert_eq!(writer.finish_entry(&base), ARCHIVE_WARN);
        assert_eq!(
            base.error_string().as_deref(),
            Some(b"Entry remaining bytes larger than 0".as_slice())
        );
    }

    #[test]
    fn options_combine_format_and_filter_answers() {
        let base = Base::new(WRITE_MAGIC);
        let mut writer = Write::default();
        writer.set_format(&base, Box::new(format::iso9660::Iso9660::default()));
        // Without a module, the format's failure loses to the filters' "not
        // mine", so the option counts as undefined.
        assert_eq!(
            writer.option(&base, None, b"iso-level", Some(b"9"), true, true),
            ARCHIVE_WARN
        );
        assert_eq!(
            writer.option(
                &base,
                Some(b"iso9660"),
                b"iso-level",
                Some(b"9"),
                true,
                true
            ),
            ARCHIVE_FAILED
        );
        assert_eq!(
            writer.option(&base, Some(b"zip"), b"iso-level", Some(b"2"), true, true),
            crate::options::UNKNOWN_MODULE
        );
        assert_eq!(
            writer.option(&base, None, b"iso-level", Some(b"2"), true, false),
            ARCHIVE_OK
        );
        let mut empty = Write::default();
        assert_eq!(
            empty.option(&base, None, b"x", None, true, false),
            ARCHIVE_FAILED
        );
    }

    #[test]
    fn a_failed_format_close_still_closes() {
        let base = Base::new(WRITE_MAGIC);
        let mut writer = Write::default();
        writer.set_format(&base, Box::new(format::iso9660::Iso9660::default()));
        assert_eq!(
            writer.option(&base, None, b"boot", Some(b"missing"), true, true),
            ARCHIVE_OK
        );
        let out = Rc::new(RefCell::new(Vec::new()));
        assert_eq!(writer.open(&base, Box::new(Collect(out))), ARCHIVE_OK);
        assert_eq!(writer.header(&base, &mut file(1)), ARCHIVE_OK);
        assert_eq!(writer.data(&base, b"x"), 1);
        assert_eq!(writer.close(&base), ARCHIVE_FATAL);
        assert_eq!(base.state.get(), state::CLOSED);
        assert_eq!(writer.close(&base), ARCHIVE_OK);
    }

    #[test]
    fn a_format_close_can_turn_off_padding() {
        let base = Base::new(WRITE_MAGIC);
        let mut writer = Write::default();
        writer.set_format(&base, Box::new(format::shar::Shar::new(false)));
        let out = Rc::new(RefCell::new(Vec::new()));
        assert_eq!(
            writer.open(&base, Box::new(Collect(out.clone()))),
            ARCHIVE_OK
        );
        assert_eq!(writer.header(&base, &mut file(1)), ARCHIVE_OK);
        assert_eq!(writer.data(&base, b"x"), 1);
        assert_eq!(writer.close(&base), ARCHIVE_OK);
        assert_eq!(writer.bytes_in_last_block, 1);
        assert!(out.borrow().ends_with(b"exit\n"));
    }

    #[test]
    fn failed_filter_open_closes_only_opened_tail_and_frees_client_once() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut writer = Write::default();
        for fail in [true, false] {
            writer.add_filter(Box::new(TestFilter {
                events: events.clone(),
                fail,
            }));
        }
        let base = Base::new(WRITE_MAGIC);
        assert_eq!(
            writer.open(&base, Box::new(Client(events.clone()))),
            ARCHIVE_FATAL
        );
        assert_eq!(
            &*events.borrow(),
            &["tail close", "client close", "client free"]
        );
        assert!(writer.filters.is_empty());
        assert_eq!(writer.free(&base), ARCHIVE_OK);
        assert_eq!(events.borrow().len(), 3);
    }
    #[test]
    fn filters_without_option_handlers_are_unknown_modules() {
        let base = Base::new(WRITE_MAGIC);
        let mut filters: Vec<Box<dyn Filter>> =
            vec![filter::by_code(crate::read::filter_code::COMPRESS).unwrap()];
        assert_eq!(
            Write::filter_option(&mut filters, &base, Some(b"compress"), b"foo", Some(b"1")),
            crate::options::UNKNOWN_MODULE
        );
        assert_eq!(
            Write::filter_option(&mut filters, &base, None, b"foo", Some(b"1")),
            ARCHIVE_WARN
        );
        filters.push(filter::by_code(crate::read::filter_code::GZIP).unwrap());
        assert_eq!(
            Write::filter_option(&mut filters, &base, Some(b"gzip"), b"foo", Some(b"1")),
            ARCHIVE_WARN
        );
    }
}
