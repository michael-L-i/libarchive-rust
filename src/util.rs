/*-
 * Copyright (c) 2009-2012,2014 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_util.c.

//! Errors, library version and the accessors common to all handles.

use crate::archive::{ARCHIVE_FATAL, Base};
use std::cell::Ref;
use std::ffi::{CStr, c_int};

pub const VERSION_NUMBER: c_int = 3009000;
pub const VERSION_STRING: &CStr = c"libarchive 3.9.0dev";

/// An error with the three things `archive_set_error` records, plus the
/// return code the C function reports. Code below `src/ffi/` returns
/// `Result<_, Error>` (std's) and `?`-propagates it. A caller that must report
/// upstream's "set error, return `ARCHIVE_WARN`" says so with
/// `a.raise(Error::new(ARCHIVE_WARN, errno, msg))`.
///
/// The message is bytes, not `String`: it may embed a pathname.
#[derive(Debug, PartialEq, Eq)]
pub struct Error {
    pub code: c_int,
    pub errno: c_int,
    pub msg: Vec<u8>,
}

impl Error {
    pub fn new(code: c_int, errno: c_int, msg: impl Into<Vec<u8>>) -> Self {
        Error {
            code,
            errno,
            msg: msg.into(),
        }
    }

    pub fn fatal(errno: c_int, msg: impl Into<Vec<u8>>) -> Self {
        Self::new(ARCHIVE_FATAL, errno, msg)
    }
}

impl Base {
    /// `archive_set_error`. With no message, only the error number changes
    /// and the message is hidden.
    pub fn set_error(&self, errno: c_int, msg: Option<&[u8]>) {
        self.errno.set(errno);
        self.error_shown.set(msg.is_some());
        if let Some(m) = msg {
            // The C message is a NUL-terminated string.
            let end = m.iter().position(|&b| b == 0).unwrap_or(m.len());
            let mut buf = self.error.borrow_mut();
            buf.clear();
            buf.extend_from_slice(m.get(..end).unwrap_or_default());
            buf.push(0);
        }
    }

    /// Records `e` and returns the code to hand back to the C caller.
    pub fn raise(&self, e: Error) -> c_int {
        self.set_error(e.errno, Some(&e.msg));
        e.code
    }

    pub fn clear_error(&self) {
        let mut buf = self.error.borrow_mut();
        buf.clear();
        buf.push(0);
        self.error_shown.set(false);
        self.errno.set(0);
    }

    pub fn copy_error(&self, src: &Base) {
        if std::ptr::eq(self, src) {
            return;
        }
        self.errno.set(src.errno.get());
        let mut buf = self.error.borrow_mut();
        buf.clear();
        buf.extend_from_slice(&src.error.borrow());
        self.error_shown.set(true);
    }

    /// `archive_error_string`: the message without its NUL, or `None` if there
    /// is none. Its `as_ptr()` is a C string that stays put until the message
    /// outgrows the buffer.
    pub fn error_string(&self) -> Option<Ref<'_, [u8]>> {
        if !self.error_shown.get() {
            return None;
        }
        let msg = Ref::map(self.error.borrow(), |v| {
            v.split_last().map_or(&[][..], |(_, m)| m)
        });
        (!msg.is_empty()).then_some(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ARCHIVE_WARN, READ_MAGIC};

    #[test]
    fn set_and_clear_error() {
        let a = Base::new(READ_MAGIC);
        assert_eq!(a.error_string().as_deref(), None);
        a.set_error(5, Some(b"bad thing"));
        assert_eq!(
            (a.errno.get(), a.error_string().as_deref()),
            (5, Some(b"bad thing".as_slice()))
        );
        a.set_error(7, None);
        assert_eq!((a.errno.get(), a.error_string().as_deref()), (7, None));
        a.set_error(1, Some(b"cut\0short"));
        assert_eq!(a.error_string().as_deref(), Some(b"cut".as_slice()));
        a.set_error(1, Some(b""));
        assert_eq!(a.error_string().as_deref(), None);
        a.set_error(1, Some(b"x"));
        a.clear_error();
        assert_eq!((a.errno.get(), a.error_string().as_deref()), (0, None));
    }

    #[test]
    fn raise_records_and_returns_code() {
        let a = Base::new(READ_MAGIC);
        assert_eq!(a.raise(Error::new(ARCHIVE_WARN, 22, "odd")), ARCHIVE_WARN);
        assert_eq!(
            (a.errno.get(), a.error_string().as_deref()),
            (22, Some(b"odd".as_slice()))
        );
        assert_eq!(a.raise(Error::fatal(1, "no")), ARCHIVE_FATAL);
    }

    #[test]
    fn copy_error_between_handles() {
        let a = Base::new(READ_MAGIC);
        let b = Base::new(READ_MAGIC);
        a.set_error(9, Some(b"from a"));
        b.copy_error(&a);
        assert_eq!(
            (b.errno.get(), b.error_string().as_deref()),
            (9, Some(b"from a".as_slice()))
        );
    }
}
