/*-
 * Copyright (c) 2003-2007 Tim Kientzle
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

// Ported from libarchive/archive_read_open_file.c.

//! The client behind `archive_read_open_FILE`: reads an archive from a C
//! `FILE *` the caller owns.

use crate::archive::Base;
use crate::ffi::sys::CFile;
use crate::read::{Client, Whence};
use crate::read_open_fd::buffer;
use crate::util::Error;

const BLOCK_SIZE: usize = 128 * 1024;

pub struct ReadFile {
    file: CFile,
    size: i64,
    buffer: Vec<u8>,
    len: usize,
    can_skip: bool,
}

impl ReadFile {
    /// `archive_read_open_FILE`'s setup. Returns the client, and the device
    /// and inode of the input if it is a regular file.
    pub fn new(file: CFile) -> Result<(Self, Option<(i64, i64)>), Error> {
        // If we can't fstat() the file, it may just be that it's not a
        // file. (On some platforms, FILE * objects can wrap I/O streams that
        // don't support fileno(). As a result, fileno() should be used
        // cautiously.)
        let st = file
            .fd()
            .and_then(|fd| fd.fstat().ok())
            .filter(|st| st.is_reg());
        let mine = ReadFile {
            file,
            // Enable the seek optimization only for regular files.
            can_skip: st.is_some(),
            size: st.map_or(0, |st| st.size),
            buffer: buffer(BLOCK_SIZE)?,
            len: 0,
        };
        Ok((mine, st.map(|st| (st.dev, st.ino))))
    }
}

impl Client for ReadFile {
    /// A stream in error records the error and still returns the bytes it
    /// read, which may be none: that is end of file.
    fn read(&mut self, a: &Base, _node: usize) -> Result<(), Error> {
        let (n, failed) = self.file.read(&mut self.buffer);
        self.len = n;
        if let Some(errno) = failed {
            a.set_error(errno, Some(b"Error reading file"));
        }
        Ok(())
    }

    fn block(&self) -> &[u8] {
        self.buffer.get(..self.len).unwrap_or_default()
    }

    fn can_skip(&self) -> bool {
        true
    }

    fn skip(&mut self, _a: &Base, _node: usize, request: i64) -> Result<i64, Error> {
        // If we can't skip, return 0 as the amount we did step and the
        // caller will work around by reading and discarding.
        if !self.can_skip || request == 0 {
            return Ok(0);
        }
        if let Ok(old) = self.file.tell()
            && old < self.size
            && request <= self.size - old
            && self.file.seek(request, libc::SEEK_CUR).is_ok()
            && let Ok(new) = self.file.tell()
        {
            return Ok(new - old);
        }
        self.can_skip = false;
        Ok(0)
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(&mut self, _a: &Base, _node: usize, offset: i64, whence: Whence) -> Result<i64, Error> {
        // If we arrive here, the input is corrupted or truncated so fail.
        let fail = |errno| Error::fatal(errno, "Error seeking in FILE* pointer");
        self.file.seek(offset, whence.to_c()).map_err(fail)?;
        self.file.tell().map_err(fail)
    }
}
