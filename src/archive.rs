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

use crate::read::Read;
use crate::string::ConvCache;
use std::cell::{Cell, RefCell};
use std::ffi::{CStr, c_int};
use std::sync::{Arc, Mutex};

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
///
/// Exported functions only ever hold a `&Handle`, because a client callback
/// that runs inside one may call back into the same handle (to set an error,
/// say). So every field that changes is a `Cell` or `RefCell`; a nested call
/// that touches only `Base` is always fine.
pub struct Base {
    /// Identifies the kind of handle; catches calls on invalid pointers.
    pub magic: u32,
    pub state: Cell<u32>,
    pub format: Cell<c_int>,
    /// `archive_format_name`, as most formats set it.
    pub format_name: Cell<Option<&'static CStr>>,
    /// A formatted name (a cab's, lha's or zip's version and method) and a
    /// NUL, rewritten in place like `error`, so a pointer to it stays valid
    /// until the buffer has to grow. Reported while `format_name` is `None`.
    pub(crate) format_name_buf: RefCell<Vec<u8>>,
    /// Number of file entries processed.
    pub file_count: Cell<c_int>,
    pub errno: Cell<c_int>,
    /// `archive_error_string`'s storage: the message and a NUL, rewritten in
    /// place so a pointer to it stays valid until the buffer has to grow or
    /// the handle is freed. Empty until the first message.
    pub(crate) error: RefCell<Vec<u8>>,
    /// Whether `archive_error_string` reports the buffer; `archive_set_error`
    /// without a message hides it without clearing it.
    pub(crate) error_shown: Cell<bool>,
    /// The string conversions made for this handle (`a->sconv`). Entries made
    /// for the handle share it, so it outlives the handle while one does.
    pub(crate) conv: Arc<Mutex<ConvCache>>,
    /// `read_data_is_posix_read` and `read_data_requested`: the size of the
    /// `archive_read_data` request being served, for a format that limits
    /// the block it hands out to it. `None` outside such a request.
    pub(crate) read_data_requested: Cell<Option<usize>>,
    /// Set by a format's `seek_data` that restarts the entry's data
    /// (`__archive_reset_read_data`); the core clears it after the call.
    pub(crate) read_data_reset: Cell<bool>,
}

impl Base {
    pub fn new(magic: u32) -> Self {
        Base {
            magic,
            state: Cell::new(state::NEW),
            format: Cell::new(0),
            format_name: Cell::new(None),
            format_name_buf: RefCell::new(Vec::new()),
            file_count: Cell::new(0),
            errno: Cell::new(0),
            error: RefCell::new(Vec::new()),
            error_shown: Cell::new(false),
            conv: Arc::default(),
            read_data_requested: Cell::new(None),
            read_data_reset: Cell::new(false),
        }
    }
}

/// The state of each kind of handle. A variant joins when something
/// constructs it; each kind sits behind its own `RefCell`, so a client
/// callback that re-enters the same kind panics (and `guard` reports
/// `ARCHIVE_FATAL`) instead of aliasing.
#[allow(clippy::large_enum_variant)] // Handles live on the heap; kinds own their state.
pub enum Kind {
    Match(RefCell<crate::matching::Matching>),
    Read(RefCell<Read>),
    Write(RefCell<crate::write::Write>),
    #[allow(dead_code)] // Constructed by disk FFI.
    WriteDisk(RefCell<crate::write_disk::WriteDisk>),
    #[allow(dead_code)]
    ReadDisk(RefCell<crate::read_disk::ReadDisk>),
}

/// A `struct archive *` is a leaked `Box<Handle>`.
pub struct Handle {
    pub base: Base,
    pub kind: Kind,
}
