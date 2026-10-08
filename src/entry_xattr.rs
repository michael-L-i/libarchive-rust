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

// Ported from libarchive/archive_entry_xattr.c.

//! Extended attributes of an entry.

use crate::archive::{ARCHIVE_OK, ARCHIVE_WARN};
use crate::entry::Entry;
use std::ffi::{CStr, CString, c_int};

pub struct Xattr {
    pub name: CString,
    pub value: Vec<u8>,
}

impl Entry {
    pub fn xattr_clear(&mut self) {
        self.xattrs.clear();
        self.xattr_p = None;
    }

    pub fn xattr_add(&mut self, name: &CStr, value: &[u8]) {
        self.xattrs.push(Xattr {
            name: name.to_owned(),
            value: value.to_vec(),
        });
    }

    /// Returns number of the extended attribute entries.
    pub fn xattr_count(&self) -> c_int {
        self.xattrs.len() as c_int
    }

    pub fn xattr_reset(&mut self) -> c_int {
        self.xattr_p = self.xattrs.len().checked_sub(1);
        self.xattr_count()
    }

    /// The next attribute and `ARCHIVE_OK`, or `ARCHIVE_WARN` at the end.
    pub fn xattr_next(&mut self) -> (c_int, Option<(&CStr, &[u8])>) {
        let Some((i, xp)) = self.xattr_p.and_then(|i| Some((i, self.xattrs.get(i)?))) else {
            return (ARCHIVE_WARN, None);
        };
        self.xattr_p = i.checked_sub(1);
        (ARCHIVE_OK, Some((xp.name.as_c_str(), xp.value.as_slice())))
    }
}
