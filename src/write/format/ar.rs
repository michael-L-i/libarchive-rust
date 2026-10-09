/*-
 * Copyright (c) 2007 Kai Wang
 * Copyright (c) 2007 Tim Kientzle
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
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

// Ported from libarchive/archive_write_set_format_ar.c.
use crate::archive::*;
use crate::entry::Entry;
use crate::util::Error;
use crate::write::{Format, Sink};
use std::ffi::{CStr, c_int};
pub struct Ar {
    bsd: bool,
    global: bool,
    remaining: u64,
    padding: bool,
    strtab: Option<Vec<u8>>,
    is_strtab: bool,
}
impl Ar {
    pub fn new(bsd: bool) -> Self {
        Self {
            bsd,
            global: false,
            remaining: 0,
            padding: false,
            strtab: None,
            is_strtab: false,
        }
    }
}
fn field(out: &mut [u8], v: i64, oct: bool, msg: &str) -> Result<(), Error> {
    let s = if oct { format!("{v:o}") } else { v.to_string() };
    if v < 0 || s.len() > out.len() {
        return Err(Error::new(ARCHIVE_WARN, libc::ERANGE, msg));
    }
    out[..s.len()].copy_from_slice(s.as_bytes());
    Ok(())
}
impl Format for Ar {
    fn code(&self) -> c_int {
        if self.bsd { 0x70002 } else { 0x70001 }
    }
    fn name(&self) -> &'static CStr {
        if self.bsd {
            c"ar (BSD)"
        } else {
            c"ar (GNU/SVR4)"
        }
    }
    fn module(&self) -> &'static [u8] {
        b"ar"
    }
    fn header(&mut self, _: &Base, e: &mut Entry, sink: &mut dyn Sink) -> Result<c_int, Error> {
        let path = e
            .pathname()
            .map(|s| s.to_bytes().to_vec())
            .unwrap_or_default();
        if path.is_empty() {
            return Err(Error::new(ARCHIVE_WARN, libc::EINVAL, "Invalid filename"));
        }
        if !self.global {
            sink.write(b"!<arch>\n")?;
            self.global = true;
        }
        let mut h = [b' '; 60];
        h[58..].copy_from_slice(b"`\n");
        let mut size = e.size();
        let mut append = None;
        self.is_strtab = path == b"//";
        if matches!(path.as_slice(), b"/" | b"//" | b"/SYM64/" | b"__.SYMDEF") {
            h[..path.len()].copy_from_slice(&path);
        } else {
            let name = path.rsplit(|&b| b == b'/').next().unwrap_or_default();
            if name.is_empty() {
                return Err(Error::new(ARCHIVE_WARN, libc::EINVAL, "Invalid filename"));
            }
            if self.bsd && (name.len() > 16 || name.contains(&b' ')) {
                h[..3].copy_from_slice(b"#1/");
                field(
                    &mut h[3..16],
                    name.len() as i64,
                    false,
                    "File name too long",
                )?;
                size = size.checked_add(name.len() as i64).ok_or_else(|| {
                    Error::new(ARCHIVE_WARN, libc::ERANGE, "File size out of range")
                })?;
                append = Some(name);
            } else if name.len() <= if self.bsd { 16 } else { 15 } {
                h[..name.len()].copy_from_slice(name);
                if !self.bsd {
                    h[name.len()] = b'/';
                }
            } else {
                let tab = self.strtab.as_ref().ok_or_else(|| {
                    Error::new(ARCHIVE_WARN, libc::EINVAL, "Can't find string table")
                })?;
                let search = [name, b"/\n"].concat();
                let at = tab
                    .windows(search.len())
                    .position(|s| s == search)
                    .ok_or_else(|| {
                        Error::new(ARCHIVE_WARN, libc::EINVAL, "Invalid string table")
                    })?;
                h[0] = b'/';
                field(
                    &mut h[1..16],
                    at as i64,
                    false,
                    "string table offset too large",
                )?;
            }
            if e.filetype() != 0o100000 {
                return Err(Error::new(
                    ARCHIVE_WARN,
                    libc::EINVAL,
                    "Regular file required for non-pseudo member",
                ));
            }
        }
        if !self.is_strtab {
            for (v, range, oct, msg) in [
                (e.mtime(), 16..28, false, "File modification time too large"),
                (e.uid(), 28..34, false, "Numeric user ID too large"),
                (e.gid(), 34..40, false, "Numeric group ID too large"),
                (i64::from(e.mode()), 40..48, true, "Numeric mode too large"),
            ] {
                field(&mut h[range], v, oct, msg)?;
            }
        }
        field(&mut h[48..58], size, false, "File size out of range")?;
        sink.write(&h)?;
        self.remaining = size as u64;
        self.padding = size % 2 != 0;
        if let Some(name) = append {
            sink.write(name)?;
            self.remaining -= name.len() as u64;
        }
        Ok(ARCHIVE_OK)
    }
    fn data(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<usize, Error> {
        let n = data.len().min(self.remaining as usize);
        if self.is_strtab {
            if self.strtab.is_some() {
                return Err(Error::new(
                    ARCHIVE_WARN,
                    libc::EINVAL,
                    "More than one string tables exist",
                ));
            }
            self.strtab = Some(data[..n].to_vec());
        }
        sink.write(&data[..n])?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if self.remaining != 0 {
            return Err(Error::new(
                ARCHIVE_WARN,
                -1,
                "Entry remaining bytes larger than 0",
            ));
        }
        if self.padding {
            sink.write(b"\n")?;
            self.padding = false;
        }
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if !self.global {
            sink.write(b"!<arch>\n")?;
            self.global = true;
        }
        Ok(())
    }
}
