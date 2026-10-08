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

// Ported from libarchive/archive_private.h.

//! State shared by every kind of `struct archive` handle.

use crate::util::Error;
use std::ffi::{CStr, CString, c_int};

pub const ARCHIVE_EOF: c_int = 1;
pub const ARCHIVE_OK: c_int = 0;
pub const ARCHIVE_RETRY: c_int = -10;
pub const ARCHIVE_WARN: c_int = -20;
pub const ARCHIVE_FAILED: c_int = -25;
pub const ARCHIVE_FATAL: c_int = -30;

/// `archive_set_error`'s errno for errors that have no better one.
pub const ARCHIVE_ERRNO_MISC: c_int = -1;

pub const WRITE_MAGIC: u32 = 0xb0c5c0de;
pub const READ_MAGIC: u32 = 0xdeb0c5;
pub const WRITE_DISK_MAGIC: u32 = 0xc001b0c5;
pub const READ_DISK_MAGIC: u32 = 0xbadb0c5;
pub const MATCH_MAGIC: u32 = 0xcad11c9;

/// Handle states. A bitmask, so a function can allow a combination of states.
/// Generally checked with `Base::check_magic` in public API entry points.
pub mod state {
    /// Newly created archive object, not yet opened.
    pub const NEW: u32 = 0x01;
    /// Archive is opened.
    pub const OPEN: u32 = 0x02;
    /// Archive is ready to read a header.
    pub const HEADER: u32 = 0x04;
    /// A header has been read: the client can ask for data or for the next
    /// header, and we'll automatically skip the remaining data.
    pub const DATA: u32 = 0x08;
    /// Like `DATA` but after a FAILED header: the client may not read data,
    /// but may ask for the next header and we'll recover.
    pub const DATA_RECOVERY: u32 = 0x10;
    /// End-of-archive has been reached. The client can only close or free.
    pub const EOF: u32 = 0x20;
    /// Archive is closed; the client is only allowed to free it.
    pub const CLOSED: u32 = 0x40;
    /// Archive is in a FATAL error state: a close request is permitted but
    /// ignored.
    pub const FATAL: u32 = 0x8000;
    /// Any valid (non-fatal) state.
    pub const ANY: u32 = 0xFFFF & !FATAL;
}

/// Everything in `struct archive` that does not depend on the handle's kind.
#[derive(Debug)]
pub struct Base {
    /// Identifies the kind of handle; catches calls on invalid pointers.
    pub magic: u32,
    pub state: u32,
    pub format: c_int,
    pub format_name: Option<&'static CStr>,
    /// Number of file entries processed.
    pub file_count: c_int,
    pub errno: c_int,
    /// The message `archive_error_string` returns a pointer into.
    pub error: Option<CString>,
}

impl Base {
    pub fn new(magic: u32) -> Self {
        Base {
            magic,
            state: state::NEW,
            format: 0,
            format_name: None,
            file_count: 0,
            errno: 0,
            error: None,
        }
    }
}

/// What `struct archive_vtable` dispatches to. Each kind of handle implements
/// the operations it supports; the defaults are what a kind without that
/// slot reports. Operations that need an entry (`next_header`, `write_header`)
/// and `read_data_block` join the trait with `archive_entry`.
pub trait Ops {
    fn close(&mut self, a: &mut Base) -> c_int;
    /// Releases what the kind owns; the handle itself is dropped afterwards.
    fn free(&mut self, a: &mut Base) -> c_int;

    fn filter_count(&self) -> c_int {
        0
    }
    fn filter_bytes(&self, _n: c_int) -> i64 {
        -1
    }
    fn filter_code(&self, _n: c_int) -> c_int {
        -1
    }
    fn filter_name(&self, _n: c_int) -> Option<&CStr> {
        None
    }

    fn write_finish_entry(&mut self, _a: &mut Base) -> c_int {
        ARCHIVE_FATAL
    }
    fn write_data(&mut self, _a: &mut Base, _buf: &[u8]) -> isize {
        ARCHIVE_FATAL as isize
    }
    fn write_data_block(&mut self, a: &mut Base, _buf: &[u8], _offset: i64) -> isize {
        a.state = state::FATAL;
        a.raise(Error::fatal(
            ARCHIVE_ERRNO_MISC,
            "archive_write_data_block not supported",
        )) as isize
    }
}

/// What `struct archive` is for each kind of handle. A variant joins when
/// something constructs it.
pub enum Kind {
    /// A stand-in for the tests, which have no real handle to build yet.
    #[cfg(test)]
    Test(Box<dyn Ops>),
}

impl Kind {
    pub fn ops(&mut self) -> &mut dyn Ops {
        match *self {
            #[cfg(test)]
            Kind::Test(ref mut ops) => &mut **ops,
        }
    }
}

/// A `struct archive *` is a leaked `Box<Handle>`.
pub struct Handle {
    pub base: Base,
    pub kind: Kind,
}

impl Handle {
    pub fn new(magic: u32, kind: Kind) -> Self {
        Handle {
            base: Base::new(magic),
            kind,
        }
    }
}
