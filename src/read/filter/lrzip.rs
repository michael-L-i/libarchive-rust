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

// Ported from libarchive/archive_read_support_filter_lrzip.c.

//! The lrzip filter, which always uses the external `lrzip` program.

use super::program::Program;
use crate::archive::Base;
use crate::read::{ARCHIVE_ERRNO_MISC, Filter, FilterBidder, Read, Reader, Status, filter_code};
use crate::util::Error;
use std::ffi::c_int;

struct Bidder;

/// `archive_read_support_filter_lrzip`.
pub fn support(r: &mut Read, a: &Base) -> Result<Status, Error> {
    // This filter always uses an external program.
    r.register_bidder(Box::new(Bidder)).map(|_| {
        a.warn(
            ARCHIVE_ERRNO_MISC,
            "Using external lrzip program for lrzip decompression",
        )
    })
}

impl FilterBidder for Bidder {
    /// Bidder just verifies the header and returns the number of verified
    /// bits.
    fn bid(&mut self, up: &mut Reader<'_>) -> Result<c_int, Error> {
        // Start by looking at the first six bytes of the header, which is
        // all fixed layout.
        Ok(match up.read_ahead(6)? {
            // The magic, then the major version, which is always 0, and the
            // minor version: support only v0.6+ lrzip for sanity.
            Some([b'L', b'R', b'Z', b'I', 0, 6..=10, ..]) => 48,
            _ => 0,
        })
    }

    fn init(&mut self, _up: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(Program::start(
            b"lrzip -d -q",
            c"lrzip".into(),
            filter_code::LRZIP,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::super::bid;
    use super::*;
    use crate::archive::READ_MAGIC;

    #[test]
    fn bids_on_the_signature() {
        assert_eq!(bid(&mut Bidder, b"LRZI\0\x06"), 48);
        assert_eq!(bid(&mut Bidder, b"LRZI\0\x0amore"), 48);
        // Too short, a different version, or a different magic.
        assert_eq!(bid(&mut Bidder, b"LRZI\0"), 0);
        assert_eq!(bid(&mut Bidder, b"LRZI\0\x05"), 0);
        assert_eq!(bid(&mut Bidder, b"LRZI\0\x0b"), 0);
        assert_eq!(bid(&mut Bidder, b"LRZI\x01\x06"), 0);
        assert_eq!(bid(&mut Bidder, b"LRZJ\0\x06"), 0);
    }

    #[test]
    fn warns_of_the_external_program() {
        let (mut r, a) = (Read::default(), Base::new(READ_MAGIC));
        assert_eq!(support(&mut r, &a), Ok(Status::Warn));
        assert_eq!(
            a.error_string().as_deref(),
            Some(b"Using external lrzip program for lrzip decompression".as_slice())
        );
        assert_eq!(a.errno.get(), ARCHIVE_ERRNO_MISC);
    }
}
