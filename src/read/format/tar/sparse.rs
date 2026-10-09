/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2009 Andreas Henriksson <andreas@fatal.se>
 * Copyright (c) 2009-2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_read_support_format_tar.c.

//! The GNU sparse formats of the tar reader: the old header format, the
//! pax 0.0, 0.1 and 1.0 formats and Solaris's `SUN.holesdata`.

use super::*;

/// A run of the entry's data in the archive: data, or a hole whose bytes
/// are stored but not delivered (`SUN.holesdata`).
pub(super) struct SparseBlock {
    pub offset: i64,
    pub remaining: i64,
    pub hole: bool,
}

impl Tar {
    pub(super) fn add_sparse_entry(&mut self, a: &Base, offset: i64, remaining: i64) -> c_int {
        if remaining == 0 {
            return ARCHIVE_OK;
        }
        // As upstream, a rejected block stays in the list, as an empty one.
        self.sparse_list.push_back(SparseBlock {
            offset: 0,
            remaining: 0,
            hole: false,
        });
        if remaining < 0 || offset < 0 || offset > i64::MAX - remaining {
            return fail(
                a,
                ARCHIVE_ERRNO_MISC,
                "Malformed sparse map data",
                ARCHIVE_FATAL,
            );
        }
        if let Some(p) = self.sparse_list.back_mut() {
            p.offset = offset;
            p.remaining = remaining;
        }
        ARCHIVE_OK
    }

    /// GNU tar old-format sparse data.
    ///
    /// GNU old-format sparse data is stored in a fixed-field format.
    /// Offset/size values are 11-byte octal fields (same format as 'size'
    /// field in ustart header). These are stored in the header, allocating
    /// subsequent header blocks as needed. Extending the header in this way
    /// is a pretty severe POSIX violation; this design has earned GNU tar a
    /// lot of criticism.
    pub(super) fn sparse_old_read(
        &mut self,
        r: &mut Reader<'_>,
        h: &Block,
        unconsumed: &mut i64,
    ) -> c_int {
        let a = r.base();
        if self.sparse_old_parse(a, &h[GNU_SPARSE], 4) != ARCHIVE_OK {
            return ARCHIVE_FATAL;
        }
        if h[GNU_ISEXTENDED] == 0 {
            return ARCHIVE_OK;
        }

        loop {
            if flush(r, unconsumed) != ARCHIVE_OK {
                return ARCHIVE_FATAL;
            }
            // An extension block holds 21 descriptors and the `isextended`
            // flag.
            let Some(ext) = ahead(r, 512) else {
                return fail(
                    a,
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Truncated tar archive detected while reading sparse file data",
                    ARCHIVE_FATAL,
                );
            };
            *unconsumed = 512;
            let isextended = ext.get(504).copied().unwrap_or(0);
            let descriptors = ext.get(..504).unwrap_or_default();
            if self.sparse_old_parse(a, descriptors, 21) != ARCHIVE_OK {
                return ARCHIVE_FATAL;
            }
            if isextended == 0 {
                return ARCHIVE_OK;
            }
        }
    }

    /// Adds up to `length` of the 24-byte descriptors in `sparse`, up to the
    /// first one that is empty.
    fn sparse_old_parse(&mut self, a: &Base, sparse: &[u8], length: usize) -> c_int {
        for d in sparse.chunks_exact(24).take(length) {
            let (offset, numbytes) = d.split_at(12);
            if offset.first() == Some(&0) {
                break;
            }
            if self.add_sparse_entry(a, tar_atol(offset), tar_atol(numbytes)) != ARCHIVE_OK {
                return ARCHIVE_FATAL;
            }
        }
        ARCHIVE_OK
    }
}
