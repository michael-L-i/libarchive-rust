/*-
 * Copyright (c) 2003-2012 Tim Kientzle
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

// Ported from libarchive/archive_read_append_filter.c.

//! `archive_read_append_filter`: building the filter chain by hand instead
//! of bidding.

use crate::archive::*;
use crate::read::filter::{by_code, program};
use crate::read::{ARCHIVE_ERRNO_PROGRAMMER, Read, filter_code as code};
use crate::util::Error;
use std::ffi::c_int;

/// Puts the filter for `filter_code` on the chain. Appended filters stack in
/// order, the first nearest the input, and stop the other filters from
/// bidding.
pub fn append_filter(r: &mut Read, a: &Base, filter_code: c_int) -> c_int {
    let r1 = match filter_code {
        // No filter to add, so do nothing.
        // NOTE: An initial "NONE" type filter is always set at the end of
        // the filter chain.
        code::NONE => ARCHIVE_OK,
        code::PROGRAM => {
            return a.raise(Error::fatal(
                ARCHIVE_ERRNO_PROGRAMMER,
                "Cannot append program filter using archive_read_append_filter",
            ));
        }
        code::GZIP
        | code::BZIP2
        | code::COMPRESS
        | code::LZMA
        | code::XZ
        | code::UU
        | code::RPM
        | code::LZ4
        | code::ZSTD
        | code::LZIP
        | code::LZOP
        | code::LRZIP
        | code::GRZIP => by_code::support(r, a, filter_code),
        _ => {
            return a.raise(Error::fatal(
                ARCHIVE_ERRNO_PROGRAMMER,
                "Invalid filter code specified",
            ));
        }
    };

    let r2 = if r1 > ARCHIVE_FATAL && filter_code != code::NONE {
        r.append_last_bidder(a)
    } else {
        ARCHIVE_OK
    };
    r1.min(r2)
}

/// `archive_read_append_filter_program_signature`, and with no signature,
/// `archive_read_append_filter_program`: puts the external program `cmd` on
/// the chain.
pub fn append_filter_program(r: &mut Read, a: &Base, cmd: &[u8], signature: &[u8]) -> c_int {
    match program::support(r, cmd, signature) {
        Ok(_) => r.append_last_bidder(a),
        Err(e) => a.raise(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_program_and_unknown_codes() {
        let (mut r, a) = (Read::default(), Base::new(READ_MAGIC));
        assert_eq!(append_filter(&mut r, &a, code::NONE), ARCHIVE_OK);
        assert_eq!(append_filter(&mut r, &a, code::PROGRAM), ARCHIVE_FATAL);
        assert_eq!(
            a.error_string().as_deref(),
            Some(b"Cannot append program filter using archive_read_append_filter".as_slice())
        );
        assert_eq!(append_filter(&mut r, &a, 99), ARCHIVE_FATAL);
        assert_eq!(a.error_string().as_deref(), Some(b"Invalid filter code specified".as_slice()));
        // A real filter that is not ported yet registers nothing.
        assert_eq!(append_filter(&mut r, &a, code::GZIP), ARCHIVE_FATAL);
    }

    #[test]
    fn appends_a_program() {
        let (mut r, a) = (Read::default(), Base::new(READ_MAGIC));
        assert_eq!(append_filter_program(&mut r, &a, b"cat", b""), ARCHIVE_OK);
        assert_eq!(r.filter_code(0), code::PROGRAM);
        assert_eq!(append_filter_program(&mut r, &a, b"nonexistent", b""), ARCHIVE_FATAL);
    }
}
