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

use crate::archive::{ARCHIVE_FATAL, ARCHIVE_OK, Base};
use std::ffi::{CStr, CString, c_int};

pub const VERSION_NUMBER: c_int = 3009000;
pub const VERSION_STRING: &CStr = c"libarchive 3.9.0dev";

/// An error with the three things `archive_set_error` records, plus the
/// return code the C function reports. Code below `src/ffi/` returns
/// `Result<_, Error>` and `?`-propagates it. A caller that must report
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

pub type Result<T> = std::result::Result<T, Error>;

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
    /// and the message is cleared.
    pub fn set_error(&mut self, errno: c_int, msg: Option<&[u8]>) {
        self.errno = errno;
        self.error = msg.map(|m| {
            // The C message is a NUL-terminated string.
            let end = m.iter().position(|&b| b == 0).unwrap_or(m.len());
            CString::new(&m[..end]).unwrap_or_default()
        });
    }

    /// Records `e` and returns the code to hand back to the C caller.
    pub fn raise(&mut self, e: Error) -> c_int {
        self.set_error(e.errno, Some(&e.msg));
        e.code
    }

    /// `raise` for a function that returns `Result<()>`.
    pub fn status(&mut self, r: Result<()>) -> c_int {
        r.map_or_else(|e| self.raise(e), |()| ARCHIVE_OK)
    }

    pub fn clear_error(&mut self) {
        self.error = None;
        self.errno = 0;
    }

    pub fn copy_error(&mut self, src: &Base) {
        self.errno = src.errno;
        self.error = src.error.clone();
    }

    /// `archive_error_string`: the message, or `None` if there is none.
    pub fn error_string(&self) -> Option<&CStr> {
        self.error.as_deref().filter(|e| !e.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ARCHIVE_WARN, READ_MAGIC};

    #[test]
    fn set_and_clear_error() {
        let mut a = Base::new(READ_MAGIC);
        assert_eq!(a.error_string(), None);
        a.set_error(5, Some(b"bad thing"));
        assert_eq!((a.errno, a.error_string()), (5, Some(c"bad thing")));
        a.set_error(7, None);
        assert_eq!((a.errno, a.error_string()), (7, None));
        a.set_error(1, Some(b"cut\0short"));
        assert_eq!(a.error_string(), Some(c"cut"));
        a.set_error(1, Some(b""));
        assert_eq!(a.error_string(), None);
        a.set_error(1, Some(b"x"));
        a.clear_error();
        assert_eq!((a.errno, a.error_string()), (0, None));
    }

    #[test]
    fn raise_records_and_returns_code() {
        let mut a = Base::new(READ_MAGIC);
        assert_eq!(a.raise(Error::new(ARCHIVE_WARN, 22, "odd")), ARCHIVE_WARN);
        assert_eq!((a.errno, a.error_string()), (22, Some(c"odd")));
        assert_eq!(a.status(Ok(())), 0);
        assert_eq!(a.status(Err(Error::fatal(1, "no"))), ARCHIVE_FATAL);
    }

    #[test]
    fn copy_error_between_handles() {
        let mut a = Base::new(READ_MAGIC);
        let mut b = Base::new(READ_MAGIC);
        a.set_error(9, Some(b"from a"));
        b.copy_error(&a);
        assert_eq!((b.errno, b.error_string()), (9, Some(c"from a")));
    }
}
