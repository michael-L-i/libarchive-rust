/*-
 * Copyright (c) 2003-2009 Tim Kientzle
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

// Ported from libarchive/archive_read_support_format_raw.c.

//! The raw format: any file is a single entry named "data".

use crate::archive::*;
use crate::entry::{AE_IFREG, Entry};
use crate::read::{Data, Format, Read, Reader, format_code};
use crate::util::Error;
use std::ffi::c_int;

#[derive(Default)]
struct Raw {
    /// Current position in the file.
    offset: i64,
    unconsumed: usize,
    end_of_file: bool,
}

/// `archive_read_support_format_raw`.
pub fn support(r: &mut Read) -> Result<(), Error> {
    r.register_format(Box::new(Raw::default()))
}

impl Raw {
    /// Consume the bytes we read last time.
    fn consume_last(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        r.consume(std::mem::take(&mut self.unconsumed))
    }
}

impl Format for Raw {
    fn name(&self) -> &'static str {
        "raw"
    }

    /// Bid 1 if this is a non-empty file. Anyone who can really support
    /// this should outbid us, so it should generally be safe to use "raw" in
    /// conjunction with other formats. But, this could really confuse folks
    /// if there are bid errors or minor file damage, so we don't include
    /// "raw" as part of support_format_all().
    fn bid(&mut self, r: &mut Reader<'_>, best_bid: c_int) -> Result<c_int, Error> {
        if best_bid < 1 && r.read_ahead(1)?.is_some() {
            return Ok(1);
        }
        Ok(-1)
    }

    /// Mock up a fake header.
    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<(), Error> {
        if self.end_of_file {
            return Err(Error::recorded(ARCHIVE_EOF));
        }

        r.set_format(format_code::RAW, c"raw");
        entry.set_pathname(b"data");
        entry.set_filetype(u32::from(AE_IFREG));
        entry.set_perm(0o644);
        // I'm deliberately leaving most fields unset here.

        // Let the filter fill out any fields it might have.
        r.read_filter_header(entry)
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        self.consume_last(r)?;

        if self.end_of_file {
            // Keep reporting the end of the entry, so that a caller that
            // asks once more after end-of-file still gets a position it can
            // use.
            return Ok(Data::Eof { offset: self.offset });
        }

        // Get whatever bytes are immediately available.
        let Some(data) = r.read_ahead(1)? else {
            // Record and return end-of-file.
            self.end_of_file = true;
            return Ok(Data::Eof { offset: self.offset });
        };
        // Return the bytes we just read.
        let offset = self.offset;
        let mut avail = i64::try_from(data.len()).unwrap_or(i64::MAX);
        match offset.checked_add(avail) {
            Some(end) => self.offset = end,
            None => {
                avail = i64::MAX - offset;
                if avail == 0 {
                    return Err(Error::recorded(ARCHIVE_FATAL));
                }
                self.offset = i64::MAX;
            }
        }
        let avail = usize::try_from(avail).unwrap_or(0);
        self.unconsumed = avail;
        Ok(Data::Block {
            data: data.get(..avail).unwrap_or_default(),
            offset,
        })
    }

    fn read_data_skip(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        self.consume_last(r)?;
        self.end_of_file = true;
        Ok(())
    }
}
