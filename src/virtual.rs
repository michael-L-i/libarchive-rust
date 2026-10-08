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

// Ported from libarchive/archive_virtual.c.

//! The public operations that every kind of handle answers by dispatching to
//! its own implementation: a `match` on `Kind`, where later units add arms.

use crate::archive::*;
use crate::entry::Entry;
use crate::util::Error;
use std::ffi::{c_char, c_int};

impl Handle {
    // The filter getters can be called by a client callback on its own
    // handle, while the read state is borrowed for the call into it. Upstream
    // allows that; here the getters answer with their error value.

    pub fn filter_code(&self, n: c_int) -> c_int {
        match &self.kind {
            Kind::Read(r) => r.try_borrow().map_or(ARCHIVE_FATAL, |r| r.filter_code(n)),
        }
    }

    pub fn filter_count(&self) -> c_int {
        match &self.kind {
            Kind::Read(r) => r.try_borrow().map_or(ARCHIVE_FATAL, |r| r.filter_count()),
        }
    }

    /// The filter's name, or NULL. The pointer lives as long as the filter.
    pub fn filter_name(&self, n: c_int) -> *const c_char {
        match &self.kind {
            Kind::Read(r) => r.try_borrow().map_or(std::ptr::null(), |r| {
                r.filter_name(n).map_or(std::ptr::null(), |s| s.as_ptr())
            }),
        }
    }

    pub fn filter_bytes(&self, n: c_int) -> i64 {
        match &self.kind {
            Kind::Read(r) => r
                .try_borrow()
                .map_or(i64::from(ARCHIVE_FATAL), |r| r.filter_bytes(n)),
        }
    }

    /// `archive_read_next_header2` and the read half of `next_header`:
    /// reads the next header into `entry`.
    pub fn read_next_header2(&self, entry: &mut Entry) -> c_int {
        match &self.kind {
            Kind::Read(r) => r
                .try_borrow_mut()
                .map_or(ARCHIVE_FATAL, |mut r| r.next_header2(&self.base, entry)),
        }
    }

    /// The entry a read handle reads headers into, or NULL.
    pub fn read_entry(&self) -> *mut Entry {
        match &self.kind {
            Kind::Read(r) => r
                .try_borrow()
                .map_or(std::ptr::null_mut(), |r| r.entry()),
        }
    }

    /// Takes the read handle's entry for `archive_free` to free.
    pub fn take_read_entry(&self) -> *mut Entry {
        match &self.kind {
            Kind::Read(r) => r
                .try_borrow_mut()
                .map_or(std::ptr::null_mut(), |mut r| r.take_entry()),
        }
    }

    pub fn header_position(&self) -> i64 {
        match &self.kind {
            Kind::Read(r) => r
                .try_borrow()
                .map_or(i64::from(ARCHIVE_FATAL), |r| r.header_position()),
        }
    }

    pub fn close(&self) -> c_int {
        match &self.kind {
            Kind::Read(r) => r.borrow_mut().close(&self.base),
        }
    }

    /// `archive_free`, up to dropping the handle: closes it and releases
    /// what client callbacks may still see. The caller drops the handle
    /// afterwards, so the callbacks run on a live one.
    pub fn free(&self) -> c_int {
        match &self.kind {
            Kind::Read(r) => r.borrow_mut().free(&self.base),
        }
    }

    pub fn write_fail(&self) -> c_int {
        self.base.state.set(state::FATAL);
        // Upstream returns the state, not ARCHIVE_FATAL.
        state::FATAL as c_int
    }

    pub fn write_finish_entry(&self) -> c_int {
        match &self.kind {
            Kind::Read(_) => ARCHIVE_FATAL,
        }
    }

    pub fn write_data(&self, _buf: &[u8]) -> isize {
        match &self.kind {
            Kind::Read(_) => ARCHIVE_FATAL as isize,
        }
    }

    pub fn write_data_block(&self, _buf: &[u8], _offset: i64) -> isize {
        match &self.kind {
            // A kind without a write_data_block slot.
            Kind::Read(_) => {
                self.base.state.set(state::FATAL);
                self.base.raise(Error::fatal(
                    ARCHIVE_ERRNO_MISC,
                    "archive_write_data_block not supported",
                )) as isize
            }
        }
    }
}
