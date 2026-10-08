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

// Ported from libarchive/archive_read_support_format_all.c.

//! The formats `archive_read_support_format_all` enables, and the table
//! `archive_read_support_format_by_code` looks formats up in.

use crate::archive::*;
use crate::read::{Read, format_code as code};
use crate::util::Error;
use std::ffi::c_int;

/// Registers a format with the handle.
pub type Support = fn(&mut Read) -> Result<(), Error>;

/// Every format code, with its registration function once it is ported.
/// The order is the order of bidding.
///
/// TODO: It would be nice to compute the ordering here automatically so
/// that people who enable just a few formats can still get the benefits.
/// That may just require the format registration to include a "maximum
/// read-ahead" value (anything that uses seek would be essentially infinite
/// read-ahead). The core bid management can then sort the bidders before
/// calling them.
pub const FORMATS: &[(c_int, Option<Support>)] = &[
    // These bidders are all pretty cheap; they just examine a small initial
    // part of the archive. If one of these bids high, we can maybe avoid
    // running any of the more expensive bidders below.
    (code::AR, None),
    (code::CPIO, None),
    (code::EMPTY, Some(super::empty::support)),
    (code::LHA, None),
    (code::MTREE, None),
    (code::TAR, None),
    (code::XAR, None),
    (code::WARC, None),
    // Install expensive bidders last. By doing them last, we increase the
    // chance that a high bid from someone else will make it unnecessary for
    // these to do anything at all.
    //
    // These have potentially large look-ahead.
    (code::SEVENZIP, None),
    (code::CAB, None),
    (code::RAR, None),
    (code::RAR_V5, None),
    (code::ISO9660, None),
    // Seek is really bad, since it forces the read-ahead logic to discard
    // buffered data.
    (code::ZIP, None),
    // Not enabled by `all`, only by name.
    (code::RAW, Some(super::raw::support)),
];

/// `archive_read_support_format_all`.
pub fn support(r: &mut Read, a: &Base) -> c_int {
    for (_, register) in FORMATS.iter().filter(|(c, _)| *c != code::RAW) {
        if let Some(register) = register {
            // Note: We always return ARCHIVE_OK here, even if some of the
            // above return ARCHIVE_WARN. The intent here is to enable "as
            // much as possible." Clients who need specific formats should
            // enable those individually so they can verify the level of
            // support.
            let _ = register(r);
        }
    }
    // Clear any warning messages set by the above functions.
    a.clear_error();
    ARCHIVE_OK
}
