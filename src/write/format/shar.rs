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
    end_of_line: bool,
    entry: Option<Entry>,
    has_data: bool,
    last_dir: Option<Vec<u8>>,
    /// Line buffer for uuencoded dump format.
    outbuff: [u8; 45],
    outpos: usize,
    wrote_header: bool,
}
impl Shar {
    pub fn new(dump: bool) -> Self {
        Self {
            dump,
            end_of_line: false,
            entry: None,
            has_data: false,
            last_dir: None,
            outbuff: [0; 45],
            outpos: 0,
            wrote_header: false,
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
    fn header(&mut self, a: &Base, e: &mut Entry, sink: &mut dyn Sink) -> Result<c_int, Error> {
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
        if !self.wrote_header {
            sink.write(b"#!/bin/sh\n# This is a shell archive\n")?;
            self.wrote_header = true;
        }
        // Save the entry for the closing.
        self.entry = Some(e.clone_entry());
        // Handle some preparatory issues. Only regular files have non-zero
        // size. The early returns keep the previous entry's data state,
        // as upstream's do.
        match e.filetype() {
            0o100000 => {}
            0o040000 => {
                e.set_size(0);
                // Don't bother trying to recreate '.'
                if matches!(name.as_slice(), b"." | b"./") {
                    return Ok(ARCHIVE_OK);
                }
            }
            0o010000 | 0o020000 | 0o060000 => e.set_size(0),
            _ => {
                e.set_size(0);
                if e.hardlink().is_none() && e.symlink().is_none() {
                    a.raise(crate::write::unsupported(e, b"shar"));
                    return Ok(ARCHIVE_WARN);
                }
            }
        }
        let quoted = quote(&name, true);
        let mut out = [b"echo x ".as_slice(), &quoted, b"\n"].concat();
        if e.filetype() != 0o040000
            && let Some(i) = name.iter().rposition(|&b| b == b'/')
        {
            // Try to avoid a lot of redundant mkdir commands: not
            // "mkdir .", nor a dir we created, nor a parent of it.
            let parent = &name[..i];
            if parent != b"."
                && self
                    .last_dir
                    .as_ref()
                    .is_none_or(|last| !last.starts_with(parent))
            {
                out.extend(
                    [
                        b"mkdir -p ".as_slice(),
                        &quote(parent, true),
                        b" > /dev/null 2>&1\n",
                    ]
                    .concat(),
                );
                self.last_dir = Some(parent.to_vec());
            }
        }
        // Handle file-type specific issues.
        self.has_data = false;
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
                        self.has_data = true;
                        self.end_of_line = true;
                        self.outpos = 0;
                    }
                }
                0o040000 => {
                    out.extend([b"mkdir -p ".as_slice(), &quoted, b" > /dev/null 2>&1\n"].concat());
                    // Record that we just created this directory.
                    self.last_dir = Some(name.strip_suffix(b"/").unwrap_or(&name).to_vec());
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
        if !self.has_data || data.is_empty() {
            return Ok(0);
        }
        if self.dump {
            let mut src = data;
            if self.outpos != 0 {
                let n = (45 - self.outpos).min(src.len());
                self.outbuff[self.outpos..self.outpos + n].copy_from_slice(&src[..n]);
                if self.outpos + n < 45 {
                    self.outpos += n;
                    return Ok(data.len());
                }
                sink.write(&uu_line(&self.outbuff))?;
                src = &src[n..];
            }
            let mut lines = src.chunks_exact(45);
            for line in &mut lines {
                sink.write(&uu_line(line))?;
            }
            let rest = lines.remainder();
            if !rest.is_empty() {
                self.outbuff[..rest.len()].copy_from_slice(rest);
                self.outpos = rest.len();
            }
        } else {
            for chunk in data.chunks(32768) {
                let mut out = Vec::with_capacity(chunk.len() * 2);
                for &b in chunk {
                    if self.end_of_line {
                        out.push(b'X');
                        self.end_of_line = false;
                    }
                    out.push(b);
                    if b == b'\n' {
                        self.end_of_line = true;
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
        // has_data and the line state are left for the next header: an
        // entry it returns early for repeats the previous one's ending.
        if self.has_data {
            if self.dump {
                // Finish uuencoded data.
                if self.outpos > 0 {
                    sink.write(&uu_line(&self.outbuff[..self.outpos]))?;
                }
                sink.write(b"`\nend\nSHAR_END\n")?;
            } else {
                // Finish sed-encoded data: ensure last line ends.
                if !self.end_of_line {
                    sink.write(b"\n")?;
                }
                sink.write(b"SHAR_END\n")?;
            }
        }
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
        if self.wrote_header {
            sink.write(b"exit\n")?;
        }
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

    fn entry(path: &[u8], filetype: u32, size: i64) -> Entry {
        let mut e = Entry::new(None);
        e.set_pathname(path);
        e.set_filetype(filetype);
        e.set_perm(0o644);
        e.set_size(size);
        e
    }

    fn write(shar: &mut Shar, entries: &mut [(Entry, &[u8])]) -> Vec<u8> {
        let base = Base::new(WRITE_MAGIC);
        let mut out = Output(Vec::new());
        for (e, data) in entries {
            assert_eq!(shar.header(&base, e, &mut out), Ok(ARCHIVE_OK));
            shar.data(data, &mut out).unwrap();
            shar.finish_entry(&mut out).unwrap();
        }
        shar.close(&mut out).unwrap();
        out.0
    }

    // Upstream returns early for "." before resetting the data state, so
    // the previous file's ending is written again (as bsdtar does for the
    // sweep's src.tar).
    #[test]
    fn dot_directory_repeats_the_previous_files_ending() {
        let out = write(
            &mut Shar::new(false),
            &mut [
                (entry(b"f", 0o100000, 2), b"ab"),
                (entry(b".", 0o040000, 0), b""),
            ],
        );
        assert_eq!(
            out,
            b"#!/bin/sh\n# This is a shell archive\necho x f\n\
              sed 's/^X//' > f << 'SHAR_END'\nXab\nSHAR_END\n\nSHAR_END\nexit\n"
        );
        let out = write(
            &mut Shar::new(true),
            &mut [
                (entry(b"f", 0o100000, 2), b"ab"),
                (entry(b"./", 0o040000, 0), b""),
            ],
        );
        assert_eq!(
            out,
            b"#!/bin/sh\n# This is a shell archive\necho x f\n\
              uudecode -p > f << 'SHAR_END'\nbegin 644 f\n\"86(`\n`\nend\nSHAR_END\n\
              chmod 644 f\n\"86(`\n`\nend\nSHAR_END\nchmod 644 ./\nexit\n"
        );
    }

    #[test]
    fn unsupported_file_type_warns() {
        let base = Base::new(WRITE_MAGIC);
        let mut out = Output(Vec::new());
        let mut e = entry(b"sock", 0o140000, 0);
        assert_eq!(
            Shar::new(false).header(&base, &mut e, &mut out),
            Ok(ARCHIVE_WARN)
        );
        assert_eq!(
            base.error_string().as_deref(),
            Some(b"sock: shar format cannot archive sockets".as_slice())
        );
    }
}
