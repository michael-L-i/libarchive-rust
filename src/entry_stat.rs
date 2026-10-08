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

// Ported from libarchive/archive_entry_stat.c.

//! The `struct stat` view of an entry.

use crate::entry::Entry;
use libc::off_t;

impl Entry {
    /// The entry as a `struct stat`, which is cached in the entry and
    /// refilled in place when a field has changed since.
    pub fn stat(&mut self) -> &libc::stat {
        if self.stat.is_none() {
            self.stat = Some(Box::new(crate::ffi::entry::zeroed_stat()));
            self.stat_valid = false;
        }

        // If none of the underlying fields have been changed, we
        // don't need to regenerate.  In theory, we could use a bitmap
        // here to flag only those items that have changed, but the
        // extra complexity probably isn't worth it.  It will be very
        // rare for anyone to change just one field then request a new
        // stat structure.
        if !self.stat_valid {
            self.fill_stat();
        }
        self.stat
            .get_or_insert_with(|| Box::new(crate::ffi::entry::zeroed_stat()))
    }

    fn fill_stat(&mut self) {
        // Use the public interfaces to extract items, so that
        // the appropriate conversions get invoked.
        let mut st = crate::ffi::entry::zeroed_stat();
        st.st_atime = self.atime();
        st.st_ctime = self.ctime();
        st.st_mtime = self.mtime();
        st.st_dev = self.dev();
        st.st_gid = self.gid() as _;
        st.st_uid = self.uid() as _;
        st.st_ino = self.ino() as _;
        st.st_nlink = self.nlink() as _;
        st.st_rdev = self.rdev();
        st.st_size = off_t::try_from(self.size())
            .ok()
            .filter(|s| *s >= 0)
            .unwrap_or(0);
        st.st_mode = self.mode();

        // On systems that support high-res timestamps, copy that
        // information into struct stat.
        st.st_atime_nsec = self.atime_nsec() as _;
        st.st_ctime_nsec = self.ctime_nsec() as _;
        st.st_mtime_nsec = self.mtime_nsec() as _;
        #[cfg(target_vendor = "apple")]
        {
            st.st_birthtime = self.birthtime();
            st.st_birthtime_nsec = self.birthtime_nsec() as _;
        }

        // TODO: On Linux, store 32 or 64 here depending on whether
        // the cached stat structure is a stat32 or a stat64.  This
        // will allow us to support both variants interchangeably.
        if let Some(cached) = self.stat.as_deref_mut() {
            *cached = st;
        }
        self.stat_valid = true;
    }
}
