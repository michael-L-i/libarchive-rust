/*-
 * Copyright (c) 2003-2010 Tim Kientzle
 * Copyright (c) 2009-2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_write_add_filter_xz.c.

use super::*;
use lzma_rust2::{LzipOptions, LzipWriter, LzmaOptions, LzmaWriter, XzOptions, XzWriter};
use std::io::Write as _;
enum State {
    Xz(XzWriter<Vec<u8>>),
    Lzma(LzmaWriter<Vec<u8>>),
    Lzip(LzipWriter<Vec<u8>>),
}
pub struct Encoder {
    code: i32,
    level: u8,
    state: Option<State>,
}
impl Encoder {
    pub fn new(code: i32) -> Self {
        Self {
            code,
            level: 6,
            state: None,
        }
    }
    fn start(&mut self) -> Result<(), Error> {
        if self.state.is_none() {
            self.state = Some(match self.code {
                filter_code::XZ => State::Xz(
                    XzWriter::new(Vec::new(), XzOptions::with_preset(self.level.into()))
                        .map_err(io_error)?,
                ),
                filter_code::LZMA => State::Lzma(
                    LzmaWriter::new_use_header(
                        Vec::new(),
                        &LzmaOptions::with_preset(self.level.into()),
                        None,
                    )
                    .map_err(io_error)?,
                ),
                _ => State::Lzip(LzipWriter::new(
                    Vec::new(),
                    LzipOptions::with_preset(self.level.into()),
                )),
            });
        }
        Ok(())
    }
}
impl Filter for Encoder {
    fn name(&self) -> &CStr {
        match self.code {
            filter_code::XZ => c"xz",
            filter_code::LZMA => c"lzma",
            _ => c"lzip",
        }
    }
    fn code(&self) -> i32 {
        self.code
    }
    fn options(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<i32, Error> {
        match key {
            b"compression-level" => self.level = digit(value, 0, 9, "compression-level invalid")?,
            b"threads" => {
                let n = number(value, "threads invalid")?;
                if !(0..=i32::MAX.into()).contains(&n) {
                    return Err(invalid("threads invalid"));
                }
            }
            _ => return Ok(ARCHIVE_WARN),
        }
        Ok(ARCHIVE_OK)
    }
    fn write(&mut self, input: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        self.start()?;
        for part in input.chunks(65536) {
            let out = match self.state.as_mut() {
                Some(State::Xz(w)) => {
                    w.write_all(part).map_err(io_error)?;
                    w.inner_mut()
                }
                Some(State::Lzma(w)) => {
                    w.write_all(part).map_err(io_error)?;
                    w.inner_mut()
                }
                Some(State::Lzip(w)) => {
                    w.write_all(part).map_err(io_error)?;
                    w.inner_mut()
                }
                None => return Err(Error::fatal(-1, "Missing LZMA encoder")),
            };
            sink.write(out)?;
            out.clear();
        }
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.start()?;
        let out = match self.state.take() {
            Some(State::Xz(w)) => w.finish(),
            Some(State::Lzma(w)) => w.finish(),
            Some(State::Lzip(w)) => w.finish(),
            None => return Ok(()),
        }
        .map_err(io_error)?;
        sink.write(&out)
    }
}
