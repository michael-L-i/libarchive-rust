/*-
 * Copyright (c) 2014 Sebastian Freundt
 * Author: Sebastian Freundt  <devel@fresse.org>
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

// Ported from libarchive/archive_write_set_format_warc.c.
use crate::archive::*;
use crate::entry::Entry;
use crate::util::Error;
use crate::write::{Format, Sink};
use std::ffi::{CStr, c_int};
use std::io::Read;
pub struct Warc {
    omit_info: bool,
    remaining: u64,
    /// The entry's file type; only regular files are stored.
    regular: bool,
    now: i64,
}
impl Default for Warc {
    fn default() -> Self {
        Self {
            omit_info: false,
            remaining: 0,
            regular: false,
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        }
    }
}
fn date(out: &mut Vec<u8>, name: &str, time: i64) {
    if let Some(t) = crate::ffi::sys::gmtime(time) {
        out.extend(
            format!(
                "{name}: {:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z\r\n",
                i64::from(t.year) + 1900,
                t.mon + 1,
                t.mday,
                t.hour,
                t.min,
                t.sec
            )
            .as_bytes(),
        );
    }
}
impl Warc {
    fn header_bytes(
        &self,
        kind: &[u8],
        uri: Option<&[u8]>,
        mtime: i64,
        size: u64,
    ) -> Result<Vec<u8>, Error> {
        let mut out = [b"WARC/1.0\r\nWARC-Type: ".as_slice(), kind, b"\r\n"].concat();
        if let Some(uri) = uri {
            out.extend(b"WARC-Target-URI: ");
            // Prepend file:// unless the first ':' starts a "://".
            let scheme = uri.iter().position(|&b| b == b':');
            if scheme.is_none_or(|i| uri.get(i + 1..i + 3) != Some(b"//")) {
                out.extend(b"file://");
            }
            out.extend(uri);
            out.extend(b"\r\n");
        }
        date(&mut out, "WARC-Date", self.now);
        date(&mut out, "Last-Modified", mtime);
        let mut r = [0; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut r))
            .map_err(|e| {
                Error::fatal(e.raw_os_error().unwrap_or(libc::EIO), "Can't generate UUID")
            })?;
        r[6] = (r[6] & 15) | 64;
        r[8] = (r[8] & 63) | 128;
        let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
        out.extend(
            format!(
                "WARC-Record-ID: <urn:uuid:{}-{}-{}-{}-{}>\r\n",
                &hex[..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..]
            )
            .as_bytes(),
        );
        if kind == b"warcinfo" {
            out.extend(b"Content-Type: application/warc-fields\r\n");
        }
        out.extend(format!("Content-Length: {size}\r\n\r\n").as_bytes());
        if out.len() >= 512 {
            return Err(Error::fatal(
                crate::read::ARCHIVE_ERRNO_FILE_FORMAT,
                "WARC resource header is too large",
            ));
        }
        Ok(out)
    }
}
impl Format for Warc {
    fn code(&self) -> c_int {
        0xf0000
    }
    fn name(&self) -> &'static CStr {
        c"WARC/1.0"
    }
    fn module(&self) -> &'static [u8] {
        b"WARC/1.0"
    }
    fn options(&mut self, _: &Base, k: &[u8], v: Option<&[u8]>) -> Result<c_int, Error> {
        if k == b"omit-warcinfo" && (v.is_none() || v == Some(b"true")) {
            self.omit_info = true;
            Ok(ARCHIVE_OK)
        } else {
            Ok(ARCHIVE_WARN)
        }
    }
    fn header(&mut self, a: &Base, e: &mut Entry, sink: &mut dyn Sink) -> Result<c_int, Error> {
        if !self.omit_info {
            let payload = b"software: libarchive/3.9.0dev\r\nformat: WARC file version 1.0\r\n";
            let h = self.header_bytes(b"warcinfo", None, self.now, payload.len() as u64)?;
            sink.write(&h)?;
            sink.write(payload)?;
            sink.write(b"\r\n\r\n")?;
            self.omit_info = true;
        }
        let Some(name) = e.pathname().map(|s| s.to_bytes().to_vec()) else {
            a.set_error(libc::EINVAL, Some(b"Invalid filename"));
            return Ok(ARCHIVE_WARN);
        };
        self.regular = e.filetype() == 0o100000;
        self.remaining = 0;
        if !self.regular {
            return Err(crate::write::unsupported(e, b"WARC"));
        }
        if e.size_is_set() == 0 || e.size() < 0 {
            return Err(Error::new(ARCHIVE_FAILED, -1, "Size required"));
        }
        self.remaining = e.size() as u64;
        let h = self.header_bytes(b"resource", Some(&name), e.mtime(), self.remaining)?;
        sink.write(&h)?;
        Ok(ARCHIVE_OK)
    }
    fn data(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<usize, Error> {
        if !self.regular {
            return Ok(data.len());
        }
        // Never write more bytes than announced.
        let n = data.len().min(self.remaining as usize);
        sink.write(&data[..n])?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if self.regular {
            if self.remaining != 0 {
                return Err(Error::fatal(
                    -1,
                    "WARC entry is shorter than Content-Length",
                ));
            }
            sink.write(b"\r\n\r\n")?;
        }
        self.regular = false;
        Ok(())
    }
    fn close(&mut self, _: &mut dyn Sink) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Output(Vec<u8>);
    impl Sink for Output {
        fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.0.extend_from_slice(data);
            Ok(())
        }
    }

    #[test]
    fn target_uri_keeps_a_scheme_only_at_the_first_colon() {
        let base = Base::new(WRITE_MAGIC);
        for (path, uri) in [
            (b"http://host/x".as_slice(), b"http://host/x".as_slice()),
            (b"a:b://c", b"file://a:b://c"),
            (b"dir/f", b"file://dir/f"),
        ] {
            let mut warc = Warc::default();
            let mut out = Output(Vec::new());
            let mut e = Entry::new(None);
            e.set_pathname(path);
            e.set_filetype(0o100000);
            e.set_size(0);
            assert_eq!(warc.header(&base, &mut e, &mut out), Ok(ARCHIVE_OK));
            let line = [b"\r\nWARC-Target-URI: ".as_slice(), uri, b"\r\n"].concat();
            assert!(out.0.windows(line.len()).any(|w| w == line));
        }
    }

    // As upstream: no pathname is a warning, and the data that follows is
    // accepted and dropped.
    #[test]
    fn missing_pathname_warns_and_drops_data() {
        let base = Base::new(WRITE_MAGIC);
        let mut warc = Warc {
            omit_info: true,
            ..Default::default()
        };
        let mut out = Output(Vec::new());
        let mut e = Entry::new(None);
        e.set_filetype(0o100000);
        e.set_size(3);
        assert_eq!(warc.header(&base, &mut e, &mut out), Ok(ARCHIVE_WARN));
        assert_eq!(
            base.error_string().as_deref(),
            Some(b"Invalid filename".as_slice())
        );
        assert_eq!(warc.data(b"abc", &mut out), Ok(3));
        warc.finish_entry(&mut out).unwrap();
        assert!(out.0.is_empty());
    }
}
