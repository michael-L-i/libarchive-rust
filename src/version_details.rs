/*-
 * Copyright (c) 2009-2012,2014 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_version_details.c.

//! `archive_version_details`: the library version plus the version of every
//! backend compiled in. Upstream links C libraries; the backends here are
//! Rust crates, which phase 2 reports by replacing the `None`s below.
//! There are no C XML, regex or crypto backends, so those upstream sections
//! (and their `archive_*_version` functions) are always absent.

use crate::util::VERSION_STRING;
use std::ffi::{CStr, CString};
use std::sync::OnceLock;

pub const ZLIB: Option<&CStr> = None;
/// The liblzma version the `xz` crate is a port of.
pub const LIBLZMA: Option<&CStr> = Some(c"5.8.3");
/// Like `BZ2_bzlibVersion()`: "1.0.8, 13-Jul-2019".
pub const BZLIB: Option<&CStr> = None;
pub const LIBLZ4: Option<&CStr> = Some(c"lz4_flex 0.14.0");
pub const LIBZSTD: Option<&CStr> = None;
pub const LIBLZO2: Option<&CStr> = None;
pub const LIBRICHACL: Option<&CStr> = None;
pub const LIBACL: Option<&CStr> = None;
pub const LIBATTR: Option<&CStr> = None;
pub const LIBICONV: Option<&CStr> = None;

fn compose(libs: &[(&str, Option<&[u8]>)]) -> CString {
    let mut s = VERSION_STRING.to_bytes().to_vec();
    for (name, version) in libs {
        if let Some(v) = version {
            s.extend_from_slice(format!(" {name}/").as_bytes());
            s.extend_from_slice(v);
        }
    }
    CString::new(s).unwrap_or_default()
}

pub fn details() -> &'static CStr {
    static DETAILS: OnceLock<CString> = OnceLock::new();
    DETAILS.get_or_init(|| {
        let bz2 = BZLIB.map(|v| {
            v.to_bytes()
                .split(|&b| b == b',')
                .next()
                .unwrap_or_default()
        });
        compose(&[
            ("zlib", ZLIB.map(CStr::to_bytes)),
            ("liblzma", LIBLZMA.map(CStr::to_bytes)),
            ("bz2lib", bz2),
            ("liblz4", LIBLZ4.map(CStr::to_bytes)),
            ("libzstd", LIBZSTD.map(CStr::to_bytes)),
            ("liblzo2", LIBLZO2.map(CStr::to_bytes)),
            // BLAKE2 is built in, as upstream's bundled copy is.
            ("libb2", Some(b"bundled")),
            ("librichacl", LIBRICHACL.map(CStr::to_bytes)),
            ("libacl", LIBACL.map(CStr::to_bytes)),
            ("libattr", LIBATTR.map(CStr::to_bytes)),
            ("libiconv", LIBICONV.map(CStr::to_bytes)),
        ])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_ported_backends() {
        assert_eq!(details(), c"libarchive 3.9.0dev liblzma/5.8.3 liblz4/lz4_flex 0.14.0 libb2/bundled");
    }

    #[test]
    fn backends_appear_in_upstream_order() {
        let s = compose(&[
            ("zlib", Some(b"1.3")),
            ("liblzma", None),
            ("libb2", Some(b"bundled")),
            ("libattr", Some(b"system")),
        ]);
        assert_eq!(
            s.as_c_str(),
            c"libarchive 3.9.0dev zlib/1.3 libb2/bundled libattr/system"
        );
    }
}
