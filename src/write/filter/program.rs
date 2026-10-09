/*-
 * Copyright (c) 2007 Joerg Sonnenberger
 * Copyright (c) 2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_write_add_filter_program.c.

use super::*;
use crate::ffi::filter_fork::{check_child, create_child};
use std::ffi::CString;
use std::io::{ErrorKind, Read as _, Write as _};
use std::process::{Child, ChildStdin, ChildStdout};
pub struct Program {
    code: i32,
    name: CString,
    command: Vec<u8>,
    level: u8,
    compression: Vec<u8>,
    proc: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
}
impl Program {
    pub fn new(command: &[u8]) -> Result<Self, Error> {
        if crate::cmdline::parse(command).is_none() {
            return Err(Error::fatal(libc::EINVAL, "Can't parse program command"));
        }
        Ok(Self {
            code: filter_code::PROGRAM,
            name: CString::new([b"Program: ".as_slice(), command].concat()).unwrap_or_default(),
            command: command.to_vec(),
            level: 0,
            compression: Vec::new(),
            proc: None,
            stdin: None,
            stdout: None,
        })
    }
    pub fn external(code: i32) -> Self {
        let (name, command) = match code {
            filter_code::LRZIP => (c"lrzip", b"lrzip -q".as_slice()),
            filter_code::LZOP => (c"lzop", b"lzop".as_slice()),
            _ => (c"grzip", b"grzip".as_slice()),
        };
        Self {
            code,
            name: name.into(),
            command: command.to_vec(),
            level: 0,
            compression: Vec::new(),
            proc: None,
            stdin: None,
            stdout: None,
        }
    }
    fn start(&mut self) -> Result<(), Error> {
        if self.proc.is_some() {
            return Ok(());
        }
        let mut cmd = self.command.clone();
        if !self.compression.is_empty() {
            cmd.extend_from_slice(&self.compression)
        }
        if self.level != 0 {
            cmd.extend_from_slice(if self.code == filter_code::LRZIP {
                b" -L ".as_slice()
            } else {
                b" -"
            });
            cmd.push(b'0' + self.level)
        }
        let line = crate::cmdline::parse(&cmd)
            .ok_or_else(|| Error::fatal(libc::EINVAL, "Can't parse program command"))?;
        let mut child =
            create_child(&line).map_err(|_| Error::fatal(-1, "Can't launch external program"))?;
        self.stdin = child.stdin.take();
        self.stdout = child.stdout.take();
        self.proc = Some(child);
        Ok(())
    }
    fn drain(&mut self, sink: &mut dyn Sink) -> Result<bool, Error> {
        let mut buf = [0; 65536];
        loop {
            let Some(stdout) = self.stdout.as_mut() else {
                return Ok(true);
            };
            match stdout.read(&mut buf) {
                Ok(0) => {
                    self.stdout = None;
                    return Ok(true);
                }
                Ok(n) => sink.write(&buf[..n])?,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(io_error(e)),
            }
        }
    }
}
impl Filter for Program {
    fn open(&mut self, _: &mut dyn Sink) -> Result<(), Error> {
        self.start()
    }
    fn code(&self) -> i32 {
        self.code
    }
    fn name(&self) -> &CStr {
        &self.name
    }
    fn options(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<i32, Error> {
        match key {
            b"compression-level" if matches!(self.code, filter_code::LRZIP | filter_code::LZOP) => {
                self.level = digit(value, 1, 9, "compression-level invalid")?
            }
            b"compression" if self.code == filter_code::LRZIP => {
                self.compression = match value {
                    Some(b"bzip2") => b" -b".to_vec(),
                    Some(b"gzip") => b" -g".to_vec(),
                    Some(b"lzo") => b" -l".to_vec(),
                    Some(b"none") => b" -n".to_vec(),
                    Some(b"zpaq") => b" -z".to_vec(),
                    Some(b"lzma") => Vec::new(),
                    None => return Err(invalid("compression option requires an argument")),
                    _ => return Err(invalid("compression invalid")),
                }
            }
            _ => return Ok(ARCHIVE_WARN),
        }
        Ok(ARCHIVE_OK)
    }
    fn write(&mut self, mut input: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        self.start()?;
        while !input.is_empty() {
            self.drain(sink)?;
            let pipe = self
                .stdin
                .as_mut()
                .ok_or_else(|| Error::fatal(libc::EPIPE, "Can't write to external program"))?;
            match pipe.write(input) {
                Ok(0) => return Err(Error::fatal(libc::EPIPE, "Can't write to external program")),
                Ok(n) => input = &input[n..],
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    check_child(self.stdin.as_ref(), self.stdout.as_ref())
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(io_error(e)),
            }
        }
        self.drain(sink)?;
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.start()?;
        self.stdin = None;
        while !self.drain(sink)? {
            check_child(None, self.stdout.as_ref())
        }
        if let Some(mut child) = self.proc.take() {
            let status = child.wait().map_err(io_error)?;
            if !status.success() {
                return Err(Error::fatal(-1, "Error closing external program"));
            }
        }
        Ok(())
    }
}
impl Drop for Program {
    fn drop(&mut self) {
        self.stdin = None;
        self.stdout = None;
        if let Some(mut child) = self.proc.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
