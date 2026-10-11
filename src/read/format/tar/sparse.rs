/*-
 * Copyright (c) 2003-2023 Tim Kientzle
 * Copyright (c) 2011-2012 Michihiro NAKAJIMA
 * Copyright (c) 2016 Martin Matuska
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

    /// GNU tar sparse format 0.0
    ///
    /// Beginning with GNU tar 1.15, sparse files are stored using
    /// information in the pax extended header. The GNU tar maintainers have
    /// gone through a number of variations in the process of working out
    /// this scheme; fortunately, they're all numbered.
    ///
    /// Sparse format 0.0 uses attribute GNU.sparse.numblocks to store the
    /// number of blocks, and GNU.sparse.offset/GNU.sparse.numbytes to store
    /// offset/size for each block. The repeated instances of these latter
    /// fields violate the pax specification (which frowns on duplicate
    /// keys), so this format was quickly replaced.
    ///
    /// GNU tar sparse format 0.1
    ///
    /// This version replaced the offset/numbytes attributes with a single
    /// "map" attribute that stored a list of integers. This format had two
    /// problems: First, the "map" attribute could be very long, which
    /// caused problems for some implementations. More importantly, the
    /// sparse data was lost when extracted by archivers that didn't
    /// recognize this extension.
    pub(super) fn sparse_01_parse(&mut self, a: &Base, p: &[u8]) -> c_int {
        let mut offset = -1;
        for field in p.split(|&c| c == b',') {
            if !field.iter().all(u8::is_ascii_digit) {
                return ARCHIVE_WARN;
            }
            if offset < 0 {
                offset = tar_atol10(field);
                if offset < 0 {
                    return ARCHIVE_WARN;
                }
            } else {
                let size = tar_atol10(field);
                if size < 0 {
                    return ARCHIVE_WARN;
                }
                if self.add_sparse_entry(a, offset, size) != ARCHIVE_OK {
                    return ARCHIVE_FATAL;
                }
                offset = -1;
            }
        }
        ARCHIVE_OK
    }

    /// GNU tar sparse format 1.0
    ///
    /// The idea: The offset/size data is stored as a series of base-10
    /// ASCII numbers prepended to the file data, so that dearchivers that
    /// don't support this format will extract the block map along with the
    /// data and a separate post-process can restore the sparseness.
    ///
    /// Unfortunately, GNU tar 1.16 had a bug that added unnecessary
    /// padding to the body of the file when using this format. GNU tar 1.17
    /// corrected this bug without bumping the version number, so it's not
    /// possible to support both variants. This code supports the later
    /// variant at the expense of not supporting the former.
    ///
    /// This variant also introduced the GNU.sparse.major/GNU.sparse.minor
    /// attributes.
    ///
    /// Read the next line from the input, and parse it as a decimal integer
    /// followed by '\n'. Returns positive integer value or negative on
    /// error.
    fn sparse_10_atol(r: &mut Reader<'_>, remaining: &mut i64, unconsumed: &mut i64) -> i64 {
        // Skip any lines starting with '#'; GNU tar specs don't require
        // this, but they should.
        let line = loop {
            let Some(line) = readline(r, (*remaining).min(100), unconsumed) else {
                return i64::from(ARCHIVE_FATAL);
            };
            *remaining -= line.len() as i64;
            if line.first() != Some(&b'#') {
                break line;
            }
        };

        let mut l: i64 = 0;
        for &c in &line {
            if c == b'\n' {
                return l;
            }
            if !c.is_ascii_digit() {
                return i64::from(ARCHIVE_WARN);
            }
            // Truncate on overflow.
            l = l
                .checked_mul(10)
                .and_then(|v| v.checked_add(i64::from(c - b'0')))
                .unwrap_or(i64::MAX);
        }
        // TODO: Error message.
        i64::from(ARCHIVE_WARN)
    }

    /// Returns length (in bytes) of the sparse data description that was
    /// read, or an `ARCHIVE_*` failure.
    pub(super) fn sparse_10_read(&mut self, r: &mut Reader<'_>, unconsumed: &mut i64) -> i64 {
        let a = r.base();
        let fatal = i64::from(ARCHIVE_FATAL);

        // Clear out the existing sparse list.
        self.sparse_list.clear();

        let mut remaining = self.entry_bytes_remaining;

        // Parse entries.
        let mut entries = Self::sparse_10_atol(r, &mut remaining, unconsumed);
        if entries < 0 {
            return fatal;
        }
        // Parse the individual entries.
        while entries > 0 {
            entries -= 1;
            // Parse offset/size.
            let offset = Self::sparse_10_atol(r, &mut remaining, unconsumed);
            if offset < 0 {
                return fatal;
            }
            let size = Self::sparse_10_atol(r, &mut remaining, unconsumed);
            if size < 0 {
                return fatal;
            }
            // Add a new sparse entry.
            if self.add_sparse_entry(a, offset, size) != ARCHIVE_OK {
                return fatal;
            }
        }
        // Skip rest of block...
        if flush(r, unconsumed) != ARCHIVE_OK {
            return fatal;
        }
        let bytes_read = self.entry_bytes_remaining - remaining;
        let to_skip = padding(bytes_read);
        // Fail if tar->entry_bytes_remaing would get negative.
        if to_skip > remaining || r.consume(to_skip).is_err() {
            return fatal;
        }
        bytes_read + to_skip
    }

    /// Solaris pax extension for a sparse file. This is recorded with the
    /// data and hole pairs. The way recording sparse information by
    /// Solaris' pax simply indicates where data and sparse are, so the
    /// stored contents consist of both data and hole.
    pub(super) fn sun_holesdata(&mut self, a: &Base, p: &[u8]) -> c_int {
        let mut end = 0;
        let mut hole = true;
        let Some(p) = p.strip_prefix(b" ") else {
            return ARCHIVE_WARN;
        };
        for field in p.split(|&c| c == b' ') {
            if !field.iter().all(u8::is_ascii_digit) {
                return ARCHIVE_WARN;
            }
            let start = end;
            end = tar_atol10(field);
            if end < 0 {
                return ARCHIVE_WARN;
            }
            if start < end {
                if self.add_sparse_entry(a, start, end - start) != ARCHIVE_OK {
                    return ARCHIVE_FATAL;
                }
                if let Some(last) = self.sparse_list.back_mut() {
                    last.hole = hole;
                }
            }
            hole = !hole;
        }
        ARCHIVE_OK
    }
}

/// Returns the next line, including its trailing newline, or `None` on
/// error: a line longer than `limit`, or the end of the input.
fn readline(r: &mut Reader<'_>, limit: i64, unconsumed: &mut i64) -> Option<Vec<u8>> {
    let a = r.base();
    if flush(r, unconsumed) != ARCHIVE_OK {
        return None;
    }

    let limit = usize::try_from(limit).unwrap_or(0);
    let mut line = Vec::new();
    loop {
        let t = r.peek_available(1).ok().filter(|t| !t.is_empty())?;
        // If we found '\n' in the read buffer, take the line up to it;
        // otherwise, accumulate what is there.
        let found = t.iter().position(|&c| c == b'\n');
        let n = found.map_or(t.len(), |i| i + 1);
        if line.len() + n > limit {
            a.set_error(ARCHIVE_ERRNO_FILE_FORMAT, Some(b"Line too long"));
            return None;
        }
        line.extend_from_slice(t.get(..n)?);
        r.consume(n).ok()?;
        if found.is_some() {
            return Some(line);
        }
    }
}
