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
    active: bool,
    now: i64,
}
impl Default for Warc {
    fn default() -> Self {
        Self {
            omit_info: false,
            remaining: 0,
            active: false,
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
            if !uri.windows(3).any(|s| s == b"://") {
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
            return Err(Error::fatal(-1, "WARC resource header is too large"));
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
    fn header(&mut self, _: &Base, e: &mut Entry, sink: &mut dyn Sink) -> Result<c_int, Error> {
        if !self.omit_info {
            let payload = b"software: libarchive/3.9.0dev\r\nformat: WARC file version 1.0\r\n";
            let h = self.header_bytes(b"warcinfo", None, self.now, payload.len() as u64)?;
            sink.write(&h)?;
            sink.write(payload)?;
            sink.write(b"\r\n\r\n")?;
            self.omit_info = true;
        }
        let name = e
            .pathname()
            .map(|s| s.to_bytes().to_vec())
            .ok_or_else(|| Error::new(ARCHIVE_WARN, libc::EINVAL, "Invalid filename"))?;
        if e.filetype() != 0o100000 {
            return Err(Error::new(
                ARCHIVE_FAILED,
                -1,
                "WARC: unsupported file type",
            ));
        }
        if e.size_is_set() == 0 || e.size() < 0 {
            return Err(Error::new(ARCHIVE_FAILED, -1, "Size required"));
        }
        self.remaining = e.size() as u64;
        let h = self.header_bytes(b"resource", Some(&name), e.mtime(), self.remaining)?;
        sink.write(&h)?;
        self.active = true;
        Ok(ARCHIVE_OK)
    }
    fn data(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<usize, Error> {
        let n = data.len().min(self.remaining as usize);
        sink.write(&data[..n])?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if self.active {
            if self.remaining != 0 {
                return Err(Error::fatal(
                    -1,
                    "WARC entry is shorter than Content-Length",
                ));
            }
            sink.write(b"\r\n\r\n")?;
            self.active = false;
        }
        Ok(())
    }
    fn close(&mut self, _: &mut dyn Sink) -> Result<(), Error> {
        Ok(())
    }
}
