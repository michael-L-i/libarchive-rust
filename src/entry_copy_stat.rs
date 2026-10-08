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

// Ported from libarchive/archive_entry_copy_stat.c.

//! Filling an entry from a `struct stat`.

use crate::entry::Entry;

impl Entry {
    pub fn copy_stat(&mut self, st: &libc::stat) {
        self.set_atime(st.st_atime, st.st_atime_nsec as _);
        self.set_ctime(st.st_ctime, st.st_ctime_nsec as _);
        self.set_mtime(st.st_mtime, st.st_mtime_nsec as _);
        #[cfg(target_vendor = "apple")]
        self.set_birthtime(st.st_birthtime, st.st_birthtime_nsec as _);
        #[cfg(not(target_vendor = "apple"))]
        self.unset_birthtime();
        self.set_dev(st.st_dev);
        self.set_gid(st.st_gid as _);
        self.set_uid(st.st_uid as _);
        self.set_ino(st.st_ino as _);
        self.set_nlink(st.st_nlink as _);
        self.set_rdev(st.st_rdev);
        self.set_size(st.st_size);
        self.set_mode(st.st_mode);
    }
}
