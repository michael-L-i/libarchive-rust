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

use crate::archive::{ARCHIVE_FATAL, ARCHIVE_RETRY, ARCHIVE_WARN, Base};
use std::cell::Ref;
use std::ffi::{CStr, c_int};

pub const VERSION_NUMBER: c_int = 3009000;
pub const VERSION_STRING: &CStr = c"libarchive 3.9.0dev";

/// An error with the three things `archive_set_error` records, plus the
/// return code the C function reports. Code below `src/ffi/` returns
/// `Result<_, Error>` (std's) and `?`-propagates it. The code is a failure:
/// `ARCHIVE_RETRY`, `ARCHIVE_FAILED` or `ARCHIVE_FATAL`. Upstream's "set
/// error, return `ARCHIVE_WARN`" is `Base::warn`, and the end of the input is
/// `Status::Eof`; neither is an `Error`.
///
/// The message is bytes, not `String`: it may embed a pathname.
#[derive(Debug, PartialEq, Eq)]
pub struct Error {
    pub code: c_int,
    pub errno: c_int,
    pub msg: Vec<u8>,
    /// The error is already on the handle (a client callback called
    /// `archive_set_error`, say), so `raise` only reports its code.
    pub recorded: bool,
}

impl Error {
    pub fn new(code: c_int, errno: c_int, msg: impl Into<Vec<u8>>) -> Self {
        Error {
            code,
            errno,
            msg: msg.into(),
            recorded: false,
        }
    }

    pub fn fatal(errno: c_int, msg: impl Into<Vec<u8>>) -> Self {
        Self::new(ARCHIVE_FATAL, errno, msg)
    }

    /// An error of this `code` whose message is already on the handle: the
    /// failure came through `Reader`/`Client`, which recorded it where it
    /// happened. Only that machinery may use it; `raise` leaves the handle's
    /// error alone.
    pub(crate) fn recorded(code: c_int) -> Self {
        Error {
            recorded: true,
            ..Self::new(code, 0, Vec::new())
        }
    }

    /// The failure upstream returns without setting an error message: the
    /// handle keeps whatever error it had.
    pub(crate) fn silent(code: c_int) -> Self {
        Self::recorded(code)
    }
}

/// Whether `code` is one an `Error` may carry.
pub(crate) fn is_failure(code: c_int) -> bool {
    code < ARCHIVE_WARN || code == ARCHIVE_RETRY
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

    /// Records `e` (unless it is `recorded` already) and returns the code to
    /// hand back to the C caller.
    pub fn raise(&self, e: Error) -> c_int {
        debug_assert!(
            is_failure(e.code),
            "an Error carries a failure, not {}",
            e.code
        );
        if !e.recorded {
            self.set_error(e.errno, Some(&e.msg));
        }
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
    use crate::archive::{ARCHIVE_EOF, ARCHIVE_FAILED, ARCHIVE_OK, READ_MAGIC};

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
        assert_eq!(
            a.raise(Error::new(ARCHIVE_FAILED, 22, "odd")),
            ARCHIVE_FAILED
        );
        assert_eq!(
            (a.errno.get(), a.error_string().as_deref()),
            (22, Some(b"odd".as_slice()))
        );
        assert_eq!(a.raise(Error::fatal(1, "no")), ARCHIVE_FATAL);
    }

    #[test]
    fn only_failures_are_errors() {
        assert!(
            [ARCHIVE_RETRY, ARCHIVE_FAILED, ARCHIVE_FATAL]
                .into_iter()
                .all(is_failure)
        );
        assert!(
            ![ARCHIVE_OK, ARCHIVE_EOF, ARCHIVE_WARN]
                .into_iter()
                .any(is_failure)
        );
    }

    #[test]
    #[should_panic(expected = "carries a failure")]
    #[cfg(debug_assertions)]
    fn raising_a_warning_is_a_bug() {
        let _ = Base::new(READ_MAGIC).raise(Error::new(ARCHIVE_WARN, 0, "odd"));
    }

    #[test]
    fn raising_a_recorded_error_keeps_the_recorded_error() {
        let a = Base::new(READ_MAGIC);
        a.set_error(9, Some(b"earlier"));
        assert_eq!(a.raise(Error::recorded(ARCHIVE_FATAL)), ARCHIVE_FATAL);
        assert_eq!(
            (a.errno.get(), a.error_string().as_deref()),
            (9, Some(b"earlier".as_slice()))
        );
        // An empty message with no errno is still a message to record.
        assert_eq!(a.raise(Error::new(ARCHIVE_FAILED, 0, "")), ARCHIVE_FAILED);
        assert_eq!((a.errno.get(), a.error_string().as_deref()), (0, None));
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
