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

// Ported from libarchive/archive_entry_strmode.c.

//! The `ls -l` style mode string of an entry.

use crate::entry::*;
use std::ffi::CStr;

impl Entry {
    pub fn strmode(&mut self) -> &CStr {
        let filetype = match self.filetype() {
            AE_IFREG => b'-',
            AE_IFBLK => b'b',
            AE_IFCHR => b'c',
            AE_IFDIR => b'd',
            AE_IFLNK => b'l',
            AE_IFSOCK => b's',
            AE_IFIFO => b'p',
            _ if self.hardlink().is_some() => b'h',
            _ => b'?',
        };
        let mode = self.mode();
        let mut bp = [0; 12];
        bp[0] = filetype;
        for (i, c) in bp[1..10].iter_mut().enumerate() {
            let mask = 0o400 >> i;
            *c = if mode & mask != 0 {
                b"rwx"[i % 3]
            } else {
                b'-'
            };
        }

        if mode & libc::S_ISUID != 0 {
            bp[3] = if mode & 0o100 != 0 { b's' } else { b'S' };
        }
        if mode & libc::S_ISGID != 0 {
            bp[6] = if mode & 0o010 != 0 { b's' } else { b'S' };
        }
        if mode & libc::S_ISVTX != 0 {
            bp[9] = if mode & 0o001 != 0 { b't' } else { b'T' };
        }
        bp[10] = if self.acl.types() != 0 { b'+' } else { b' ' };
        bp[11] = 0;

        self.strmode = bp;
        CStr::from_bytes_until_nul(&self.strmode).unwrap_or_default()
    }
}
