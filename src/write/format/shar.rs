/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2008 Joerg Sonnenberger
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

// Ported from libarchive/archive_write_set_format_shar.c.
use crate::archive::*;
use crate::entry::Entry;
use crate::util::Error;
use crate::write::{Format, Sink};
use std::ffi::{CStr, c_int};
pub struct Shar {
    dump: bool,
    started: bool,
    active: bool,
    eol: bool,
    entry: Option<Entry>,
    last_dir: Vec<u8>,
    uu: Vec<u8>,
}
impl Shar {
    pub fn new(dump: bool) -> Self {
        Self {
            dump,
            started: false,
            active: false,
            eol: true,
            entry: None,
            last_dir: Vec::new(),
            uu: Vec::new(),
        }
    }
}
fn quote(name: &[u8], shell: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in name {
        if b == b'\n' {
            out.extend(if shell { b"\"\n\"".as_slice() } else { b"\\n" });
        } else {
            if b" \t'`\";&<>()|*?{}[]\\$!#^~".contains(&b) {
                out.push(b'\\');
            }
            out.push(b);
        }
    }
    out
}
fn uu_line(data: &[u8]) -> Vec<u8> {
    let enc = |n: u8| if n == 0 { b'`' } else { (n & 63) + 32 };
    let mut out = vec![enc(data.len() as u8)];
    for chunk in data.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.extend([
            enc(a >> 2),
            enc((a << 4 | b >> 4) & 63),
            enc((b << 2 | c >> 6) & 63),
            enc(c & 63),
        ]);
    }
    out.push(b'\n');
    out
}
impl Format for Shar {
    fn code(&self) -> c_int {
        if self.dump { 0x20002 } else { 0x20001 }
    }
    fn name(&self) -> &'static CStr {
        if self.dump { c"shar dump" } else { c"shar" }
    }
    fn module(&self) -> &'static [u8] {
        b"shar"
    }
    fn header(&mut self, _: &Base, e: &mut Entry, sink: &mut dyn Sink) -> Result<c_int, Error> {
        let name = e
            .pathname()
            .map(|s| s.to_bytes().to_vec())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                Error::new(
                    ARCHIVE_FAILED,
                    -1,
                    "Can't record entry in shar file without pathname",
                )
            })?;
        if !self.started {
            sink.write(b"#!/bin/sh\n# This is a shell archive\n")?;
            self.started = true;
        }
        self.entry = Some(e.clone_entry());
        self.active = false;
        self.eol = true;
        if e.filetype() != 0o100000 {
            e.set_size(0);
        }
        if e.filetype() == 0o040000 && matches!(name.as_slice(), b"." | b"./") {
            return Ok(ARCHIVE_OK);
        }
        let quoted = quote(&name, true);
        let mut out = [b"echo x ".as_slice(), &quoted, b"\n"].concat();
        if e.filetype() != 0o040000
            && let Some(i) = name.iter().rposition(|&b| b == b'/')
        {
            let parent = &name[..i];
            if parent != b"." && parent != self.last_dir && !self.last_dir.starts_with(parent) {
                out.extend(
                    [
                        b"mkdir -p ".as_slice(),
                        &quote(parent, true),
                        b" > /dev/null 2>&1\n",
                    ]
                    .concat(),
                );
                self.last_dir = parent.to_vec();
            }
        }
        if let Some(link) = e.hardlink() {
            out.extend(
                [
                    b"ln -f ".as_slice(),
                    &quote(link.to_bytes(), true),
                    b" ",
                    &quoted,
                    b"\n",
                ]
                .concat(),
            );
        } else if let Some(link) = e.symlink() {
            out.extend(
                [
                    b"ln -fs ".as_slice(),
                    &quote(link.to_bytes(), true),
                    b" ",
                    &quoted,
                    b"\n",
                ]
                .concat(),
            );
        } else {
            match e.filetype() {
                0o100000 => {
                    if e.size() == 0 {
                        out.extend(
                            [
                                b"test -e \"".as_slice(),
                                &quoted,
                                b"\" || :> \"",
                                &quoted,
                                b"\"\n",
                            ]
                            .concat(),
                        );
                    } else {
                        if self.dump {
                            out.extend(
                                [b"uudecode -p > ".as_slice(), &quoted, b" << 'SHAR_END'\n"]
                                    .concat(),
                            );
                            out.extend(format!("begin {:o} ", e.mode() & 0o777).as_bytes());
                            out.extend(quote(&name, false));
                            out.push(b'\n');
                        } else {
                            out.extend(
                                [b"sed 's/^X//' > ".as_slice(), &quoted, b" << 'SHAR_END'\n"]
                                    .concat(),
                            );
                        }
                        self.active = true;
                    }
                }
                0o040000 => {
                    out.extend([b"mkdir -p ".as_slice(), &quoted, b" > /dev/null 2>&1\n"].concat());
                    self.last_dir = name.strip_suffix(b"/").unwrap_or(&name).to_vec();
                }
                0o010000 => out.extend([b"mkfifo ".as_slice(), &quoted, b"\n"].concat()),
                0o020000 | 0o060000 => {
                    out.extend([b"mknod ".as_slice(), &quoted].concat());
                    out.extend(
                        format!(
                            " {} {} {}\n",
                            if e.filetype() == 0o020000 { 'c' } else { 'b' },
                            e.rdevmajor(),
                            e.rdevminor()
                        )
                        .as_bytes(),
                    );
                }
                _ => return Err(Error::new(ARCHIVE_WARN, -1, "shar: unsupported file type")),
            }
        }
        sink.write(&out)?;
        Ok(ARCHIVE_OK)
    }
    fn data(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<usize, Error> {
        if !self.active || data.is_empty() {
            return Ok(0);
        }
        if self.dump {
            for &b in data {
                self.uu.push(b);
                if self.uu.len() == 45 {
                    sink.write(&uu_line(&self.uu))?;
                    self.uu.clear();
                }
            }
        } else {
            for chunk in data.chunks(32768) {
                let mut out = Vec::with_capacity(chunk.len() * 2);
                for &b in chunk {
                    if self.eol {
                        out.push(b'X');
                        self.eol = false;
                    }
                    out.push(b);
                    if b == b'\n' {
                        self.eol = true;
                    }
                }
                sink.write(&out)?;
            }
        }
        Ok(data.len())
    }
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        let Some(mut e) = self.entry.take() else {
            return Ok(());
        };
        if self.active {
            if self.dump {
                if !self.uu.is_empty() {
                    sink.write(&uu_line(&self.uu))?;
                    self.uu.clear();
                }
                sink.write(b"`\nend\nSHAR_END\n")?;
            } else {
                if !self.eol {
                    sink.write(b"\n")?;
                }
                sink.write(b"SHAR_END\n")?;
            }
        }
        self.active = false;
        if self.dump {
            let name = e
                .pathname()
                .map(|s| quote(s.to_bytes(), true))
                .unwrap_or_default();
            let mut out = format!("chmod {:o} ", e.mode() & 0o7777).into_bytes();
            out.extend(&name);
            out.push(b'\n');
            let u = e.uname().map(|s| quote(s.to_bytes(), true));
            let g = e.gname().map(|s| quote(s.to_bytes(), true));
            if u.is_some() || g.is_some() {
                out.extend(b"chown ");
                if let Some(u) = u {
                    out.extend(u);
                }
                if let Some(g) = g {
                    out.push(b':');
                    out.extend(g);
                }
                out.push(b' ');
                out.extend(&name);
                out.push(b'\n');
            }
            if let Some(flags) = e.fflags_text() {
                out.extend(b"chflags ");
                out.extend(flags.to_bytes());
                out.push(b' ');
                out.extend(&name);
                out.push(b'\n');
            }
            sink.write(&out)?;
        }
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if self.started {
            sink.write(b"exit\n")?;
        }
        Ok(())
    }
}
