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

// Ported from libarchive/archive_read_support_filter_all.c.

//! The filters `archive_read_support_filter_all` enables, and the table
//! `archive_read_support_filter_by_code` looks filters up in.

use super::{compress, grzip, gzip, lrzip, lz4, lzop, rpm, xz};
use crate::archive::*;
use crate::read::{Read, Status, filter_code as code};
use crate::util::Error;
use std::ffi::c_int;

/// Registers a filter's bidder with the handle. A filter that needs an
/// external program warns of it through the handle.
pub type Support = fn(&mut Read, &Base) -> Result<Status, Error>;

/// Every filter code (but `NONE` and `PROGRAM`, which are special), with its
/// registration function once it is ported.
pub const FILTERS: &[(c_int, Option<Support>)] = &[
    (code::BZIP2, Some(super::bzip2::support)),
    (code::COMPRESS, Some(compress::support)),
    (code::GZIP, Some(gzip::support)),
    (code::LZIP, Some(xz::support_lzip)),
    // The LZMA file format has a very weak signature, so it may not be
    // feasible to keep this here, but we'll try. This will come back out if
    // there are problems.
    (code::LZMA, Some(xz::support_lzma)),
    (code::XZ, Some(xz::support_xz)),
    (code::UU, Some(super::uu::support)),
    (code::RPM, Some(rpm::support)),
    (code::LRZIP, Some(lrzip::support)),
    (code::LZOP, Some(lzop::support)),
    (code::GRZIP, Some(grzip::support)),
    (code::LZ4, Some(lz4::support)),
    (code::ZSTD, Some(super::zstd::support)),
];

/// `archive_read_support_filter_all`.
pub fn support(r: &mut Read, a: &Base) -> c_int {
    for (_, register) in FILTERS {
        if let Some(register) = register {
            // Note: We always return ARCHIVE_OK here, even if some of the
            // above return ARCHIVE_WARN. The intent here is to enable "as
            // much as possible." Clients who need specific compression
            // should enable those individually so they can verify the level
            // of support.
            let _ = register(r, a);
        }
    }
    // Clear any warning messages set by the above functions.
    a.clear_error();
    ARCHIVE_OK
}
