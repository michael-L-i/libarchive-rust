/*-
 * Copyright (c) 2020 Martin Matuska
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

// Ported from libarchive/archive_read_support_filter_by_code.c.

//! `archive_read_support_filter_by_code`.

use super::all::FILTERS;
use super::none;
use crate::archive::*;
use crate::read::{Read, filter_code};
use std::ffi::c_int;

/// Registers the filter for `code`. A filter that is not ported yet fails
/// with `ARCHIVE_FATAL`, as does an unknown code.
pub fn support(r: &mut Read, code: c_int) -> c_int {
    if code == filter_code::NONE {
        return none::support();
    }
    FILTERS
        .iter()
        .find(|(c, _)| *c == code)
        .and_then(|(_, register)| *register)
        .map_or(ARCHIVE_FATAL, |register| match register(r) {
            Ok(()) => ARCHIVE_OK,
            Err(e) => e.code,
        })
}
