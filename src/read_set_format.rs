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

// Ported from libarchive/archive_read_set_format.c.

//! `archive_read_set_format`: forcing the format instead of bidding.

use crate::archive::*;
use crate::read::format::by_code;
use crate::read::{ARCHIVE_ERRNO_PROGRAMMER, Read, format_code as code};
use crate::util::Error;
use std::ffi::c_int;

/// Registers the format for `format_code` and makes it the one to use. A
/// warning if a format was already chosen.
pub fn set_format(r: &mut Read, a: &Base, format_code: c_int) -> c_int {
    let r1 = by_code::support(r, a, format_code);
    if r1 < ARCHIVE_OK {
        return r1;
    }

    let name = match format_code & code::BASE_MASK {
        code::SEVENZIP => "7zip",
        code::AR => "ar",
        code::CAB => "cab",
        code::CPIO => "cpio",
        code::EMPTY => "empty",
        code::ISO9660 => "iso9660",
        code::LHA => "lha",
        code::MTREE => "mtree",
        code::RAR => "rar",
        code::RAR_V5 => "rar5",
        code::RAW => "raw",
        code::TAR => "tar",
        code::WARC => "warc",
        code::XAR => "xar",
        code::ZIP => "zip",
        _ => {
            return a.raise(Error::fatal(
                ARCHIVE_ERRNO_PROGRAMMER,
                "Invalid format code specified",
            ));
        }
    };
    r.select_format(a, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(a: &Base) -> String {
        a.error_string()
            .map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned())
    }

    #[test]
    fn invalid_and_unported_codes_fail() {
        let (mut r, a) = (Read::default(), Base::new(READ_MAGIC));
        assert_eq!(set_format(&mut r, &a, 0x7777_0000), ARCHIVE_FATAL);
        assert_eq!(error(&a), "Invalid format code specified");
        assert_eq!(a.errno.get(), ARCHIVE_ERRNO_PROGRAMMER);
        // Valid, but nothing is ported yet to register.
        a.clear_error();
        assert_eq!(set_format(&mut r, &a, code::CPIO), ARCHIVE_FATAL);
        assert_eq!(r.format, None);
    }
}
