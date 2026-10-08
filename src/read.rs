/*-
 * Copyright (c) 2003-2011 Tim Kientzle
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

// Ported from libarchive/archive_read.c.

//! The read side of `struct archive`: `archive_read_new`, close and free.
//! Phase 1d grows `Read` into the full `struct archive_read`.

use crate::archive::*;
use std::cell::RefCell;
use std::ffi::{CStr, c_int};

/// What a read handle owns beyond `Base`.
pub struct Read {}

/// `archive_read_new`.
pub fn new() -> Handle {
    Handle {
        base: Base::new(READ_MAGIC),
        kind: Kind::Read(RefCell::new(Read {})),
    }
}

impl Read {
    /// `_archive_read_close`, after the caller has checked the handle.
    pub fn close(&mut self, a: &Base) -> c_int {
        if a.state.get() == state::CLOSED {
            return ARCHIVE_OK;
        }
        a.clear_error();
        a.state.set(state::CLOSED);
        // TODO: clean up the formatters and release the filters.
        ARCHIVE_OK
    }

    /// `_archive_read_free`: closes the archive if needed; the rest is
    /// released by `Drop`.
    pub fn free(mut self, a: &Base) -> c_int {
        if a.check_magic(READ_MAGIC, state::ANY | state::FATAL, "archive_read_free")
            == ARCHIVE_FATAL
        {
            return ARCHIVE_FATAL;
        }
        match a.state.get() {
            state::CLOSED | state::FATAL => ARCHIVE_OK,
            _ => self.close(a),
        }
    }

    pub fn filter_count(&self) -> c_int {
        0
    }

    pub fn filter_bytes(&self, _n: c_int) -> i64 {
        -1
    }

    pub fn filter_code(&self, _n: c_int) -> c_int {
        -1
    }

    pub fn filter_name(&self, _n: c_int) -> Option<&CStr> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_handle_is_ready_for_setup() {
        let h = new();
        assert_eq!((h.base.magic, h.base.state.get()), (READ_MAGIC, state::NEW));
        assert_eq!(
            (h.filter_count(), h.filter_code(0), h.filter_bytes(-1)),
            (0, -1, -1)
        );
    }

    #[test]
    fn close_clears_the_error_and_is_idempotent() {
        let h = new();
        h.base.set_error(5, Some(b"stale"));
        assert_eq!(h.close(), ARCHIVE_OK);
        assert_eq!((h.base.state.get(), h.base.errno.get()), (state::CLOSED, 0));
        assert!(h.base.error_string().is_none());
        h.base.set_error(6, Some(b"after close"));
        assert_eq!(h.close(), ARCHIVE_OK);
        assert_eq!(h.base.errno.get(), 6);
    }

    #[test]
    fn fatal_handle_closes_and_frees() {
        let h = new();
        h.base.state.set(state::FATAL);
        assert_eq!(h.close(), ARCHIVE_OK);
        assert_eq!(h.base.state.get(), state::CLOSED);
        assert_eq!(new().free(), ARCHIVE_OK);
    }

    #[test]
    fn write_operations_are_unsupported() {
        let h = new();
        assert_eq!(h.write_data(b"x"), ARCHIVE_FATAL as isize);
        assert_eq!(h.write_data_block(b"x", 0), ARCHIVE_FATAL as isize);
        assert_eq!(h.base.state.get(), state::FATAL);
        let msg = h.base.error_string();
        assert_eq!(
            msg.as_deref(),
            Some(b"archive_write_data_block not supported".as_slice())
        );
    }
}
