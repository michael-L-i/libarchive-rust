/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2010-2011 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_entry_sparse.c.

//! Sparse file maps of an entry.

use crate::archive::{ARCHIVE_OK, ARCHIVE_WARN};
use crate::entry::Entry;
use std::ffi::c_int;

pub struct Sparse {
    pub offset: i64,
    pub length: i64,
}

impl Entry {
    pub fn sparse_clear(&mut self) {
        self.sparse.clear();
        self.sparse_p = None;
    }

    pub fn sparse_add(&mut self, offset: i64, length: i64) {
        if offset < 0 || length < 0 {
            // Invalid value.
            return;
        }
        let Some(end) = offset.checked_add(length) else {
            // A value of "length" parameter is too large.
            return;
        };
        if end > self.size() {
            // A value of "length" parameter is too large.
            return;
        }
        if let Some(sp) = self.sparse.last_mut() {
            // Cannot overflow: this block was checked against the size.
            let sp_end = sp.offset + sp.length;
            if sp_end > offset {
                // Invalid value.
                return;
            }
            if sp_end == offset {
                // Expand existing sparse block size.
                sp.length += length;
                return;
            }
        }

        // Add a new sparse block to the tail of list.
        self.sparse.push(Sparse { offset, length });
    }

    /// Returns number of the sparse entries.
    pub fn sparse_count(&mut self) -> c_int {
        let mut count = self.sparse.len() as c_int;

        // Sanity check if this entry is exactly sparse.
        // If amount of sparse blocks is just one and it indicates the whole
        // file data, we should remove it and return zero.
        if let [sp] = self.sparse.as_slice()
            && sp.offset == 0
            && sp.length >= self.size()
        {
            count = 0;
            self.sparse_clear();
        }

        count
    }

    pub fn sparse_reset(&mut self) -> c_int {
        // Counting can change the list, so do it first.
        let count = self.sparse_count();
        self.sparse_p = (!self.sparse.is_empty()).then_some(0);
        count
    }

    /// The next block's offset and length and `ARCHIVE_OK`, or
    /// `ARCHIVE_WARN` at the end.
    pub fn sparse_next(&mut self) -> (c_int, i64, i64) {
        let Some((i, sp)) = self.sparse_p.and_then(|i| Some((i, self.sparse.get(i)?))) else {
            return (ARCHIVE_WARN, 0, 0);
        };
        let r = (ARCHIVE_OK, sp.offset, sp.length);
        self.sparse_p = (i + 1 < self.sparse.len()).then_some(i + 1);
        r
    }
}
