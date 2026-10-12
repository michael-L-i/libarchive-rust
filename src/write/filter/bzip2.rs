/*-
 * Copyright (c) 2003-2007 Tim Kientzle
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

// Ported from libarchive/archive_write_add_filter_bzip2.c.

use super::*;
use std::cell::RefCell;
use std::io::Write as _;
use std::rc::Rc;
#[derive(Default, Clone)]
struct Buffer(Rc<RefCell<Vec<u8>>>);
impl std::io::Write for Buffer {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut out = self.0.borrow_mut();
        out.try_reserve(data.len())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        out.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub struct Bzip2 {
    level: u8,
    state: Option<crabz2::Crabz2Writer<Buffer>>,
    out: Buffer,
}
impl Default for Bzip2 {
    fn default() -> Self {
        Self {
            level: 9,
            state: None,
            out: Buffer::default(),
        }
    }
}
impl Bzip2 {
    fn start(&mut self) {
        if self.state.is_none() {
            self.state = Some(crabz2::Crabz2Writer::new(
                self.out.clone(),
                crabz2::Level::new(self.level).unwrap_or_default(),
            ));
        }
    }
    fn drain(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        let mut output = self.out.0.borrow_mut();
        sink.write(&output)?;
        output.clear();
        Ok(())
    }
}
impl Filter for Bzip2 {
    fn name(&self) -> &CStr {
        c"bzip2"
    }
    fn code(&self) -> i32 {
        filter_code::BZIP2
    }
    fn has_options(&self) -> bool {
        true
    }
    fn options(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<i32, Error> {
        if key != b"compression-level" {
            return Ok(ARCHIVE_WARN);
        }
        self.level = digit(value, 1, 9, "compression-level invalid")?;
        Ok(ARCHIVE_OK)
    }
    fn write(&mut self, input: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        self.start();
        for part in input.chunks(65536) {
            if let Some(s) = &mut self.state {
                s.write_all(part).map_err(io_error)?;
            }
            self.drain(sink)?;
        }
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.start();
        if let Some(s) = self.state.take() {
            s.finish().map_err(io_error)?;
        }
        self.drain(sink)
    }
}
