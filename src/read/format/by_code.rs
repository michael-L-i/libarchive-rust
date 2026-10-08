/*-
 * Copyright (c) 2003-2011 Tim Kientzle
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

// Ported from libarchive/archive_read_support_format_by_code.c.

//! `archive_read_support_format_by_code`.

use super::all::FORMATS;
use crate::archive::*;
use crate::read::{ARCHIVE_ERRNO_PROGRAMMER, Read, format_code};
use crate::util::Error;
use std::ffi::c_int;

/// Registers the format for `code` (its base code; the low bits say which
/// variant and don't matter here). A format that is not ported yet fails
/// with `ARCHIVE_FATAL`, as does an unknown code.
pub fn support(r: &mut Read, a: &Base, code: c_int) -> c_int {
    let base = code & format_code::BASE_MASK;
    let Some((_, register)) = FORMATS.iter().find(|(c, _)| *c == base) else {
        return a.raise(Error::fatal(
            ARCHIVE_ERRNO_PROGRAMMER,
            "Invalid format code specified",
        ));
    };
    match register.map_or(Err(Error::recorded(ARCHIVE_FATAL)), |register| register(r)) {
        Ok(status) => status.code(),
        Err(e) => a.raise(e),
    }
}
