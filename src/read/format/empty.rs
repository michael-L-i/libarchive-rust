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

// Ported from libarchive/archive_read_support_format_empty.c.

//! The empty format: a zero-length input is an archive with no entries.

use crate::entry::Entry;
use crate::read::{Data, Format, Read, Reader, Status, format_code};
use crate::util::Error;
use std::ffi::c_int;

struct Empty;

/// `archive_read_support_format_empty`.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Empty))
}

impl Format for Empty {
    fn name(&self) -> &'static str {
        "empty"
    }

    fn bid(&mut self, r: &mut Reader<'_>, best_bid: c_int) -> Result<c_int, Error> {
        // No data (or none readable) is the only thing this format takes.
        if best_bid < 1 && !matches!(r.read_ahead(1), Ok(Some(_))) {
            return Ok(1);
        }
        Ok(-1)
    }

    fn read_header(&mut self, r: &mut Reader<'_>, _entry: &mut Entry) -> Result<Status, Error> {
        r.set_format(format_code::EMPTY, c"Empty file");
        Ok(Status::Eof)
    }

    fn read_data<'x>(&'x mut self, _r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        Ok(Data::Eof { offset: 0 })
    }
}
