/*-
 * Copyright (c) 2013 Marek Kubica
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

// Ported from libarchive/archive_write_set_format_raw.c.
use crate::archive::*;
use crate::entry::Entry;
use crate::util::Error;
use crate::write::{Format, Sink};
use std::ffi::{CStr, c_int};
#[derive(Default)]
pub struct Raw {
    entries: usize,
}
impl Format for Raw {
    fn code(&self) -> c_int {
        0x90000
    }
    fn name(&self) -> &'static CStr {
        c"RAW"
    }
    fn module(&self) -> &'static [u8] {
        b"raw"
    }
    fn header(&mut self, _: &Base, e: &mut Entry, _: &mut dyn Sink) -> Result<c_int, Error> {
        if e.filetype() != 0o100000 {
            return Err(Error::fatal(
                libc::ERANGE,
                "Raw format only supports filetype AE_IFREG",
            ));
        }
        if self.entries > 0 {
            return Err(Error::fatal(
                libc::ERANGE,
                "Raw format only supports one entry per archive",
            ));
        }
        self.entries += 1;
        Ok(ARCHIVE_OK)
    }
    fn data(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<usize, Error> {
        sink.write(data)?;
        Ok(data.len())
    }
    fn finish_entry(&mut self, _: &mut dyn Sink) -> Result<(), Error> {
        Ok(())
    }
    fn close(&mut self, _: &mut dyn Sink) -> Result<(), Error> {
        Ok(())
    }
}
