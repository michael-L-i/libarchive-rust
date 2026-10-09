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

// Ported from libarchive/archive_read_support_filter_lzop.c.

//! The lzop filter. Upstream decodes with liblzo2 when it is compiled in and
//! otherwise runs `lzop -d`; this port always runs the program.

use super::program::Program;
use crate::archive::Base;
use crate::read::{ARCHIVE_ERRNO_MISC, Filter, FilterBidder, Read, Reader, Status, filter_code};
use crate::util::Error;
use std::ffi::c_int;

const MAGIC: &[u8] = b"\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a";

struct Bidder;

/// `archive_read_support_filter_lzop`.
pub fn support(r: &mut Read, a: &Base) -> Result<Status, Error> {
    // This filter always uses an external program.
    r.register_bidder(Box::new(Bidder)).map(|_| {
        a.warn(
            ARCHIVE_ERRNO_MISC,
            "Using external lzop program for lzop decompression",
        )
    })
}

impl FilterBidder for Bidder {
    /// Bidder just verifies the header and returns the number of verified
    /// bits.
    fn bid(&mut self, up: &mut Reader<'_>) -> Result<c_int, Error> {
        Ok(match up.read_ahead(MAGIC.len())? {
            Some(p) if p.starts_with(MAGIC) => MAGIC.len() as c_int * 8,
            _ => 0,
        })
    }

    fn init(&mut self, _up: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(Program::start(
            b"lzop -d",
            c"lzop".into(),
            filter_code::LZOP,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::READ_MAGIC;
    use crate::read::filter::testing::bid;

    #[test]
    fn bids_on_the_signature() {
        assert_eq!(bid(&mut Bidder, MAGIC), 72);
        assert_eq!(bid(&mut Bidder, &MAGIC[..8]), 0);
        assert_eq!(bid(&mut Bidder, b"\x89LZO\0\r\n\x1a\x0b"), 0);
        assert_eq!(bid(&mut Bidder, &[MAGIC, b"more"].concat()), 72);
    }

    #[test]
    fn warns_of_the_external_program() {
        let (mut r, a) = (Read::default(), Base::new(READ_MAGIC));
        assert_eq!(support(&mut r, &a), Ok(Status::Warn));
        assert_eq!(
            a.error_string().as_deref(),
            Some(b"Using external lzop program for lzop decompression".as_slice())
        );
        assert_eq!(a.errno.get(), ARCHIVE_ERRNO_MISC);
    }
}
