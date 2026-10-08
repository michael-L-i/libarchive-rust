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
//! its own implementation.

use crate::archive::*;
use std::ffi::{CStr, c_int};

impl Handle {
    pub fn filter_code(&mut self, n: c_int) -> c_int {
        self.kind.ops().filter_code(n)
    }

    pub fn filter_count(&mut self) -> c_int {
        self.kind.ops().filter_count()
    }

    pub fn filter_name(&mut self, n: c_int) -> Option<&CStr> {
        self.kind.ops().filter_name(n)
    }

    pub fn filter_bytes(&mut self, n: c_int) -> i64 {
        self.kind.ops().filter_bytes(n)
    }

    pub fn close(&mut self) -> c_int {
        self.kind.ops().close(&mut self.base)
    }

    /// `archive_free`: the handle is gone afterwards.
    pub fn free(mut self) -> c_int {
        self.kind.ops().free(&mut self.base)
    }

    pub fn write_fail(&mut self) -> c_int {
        self.base.state = state::FATAL;
        // Upstream returns the state, not ARCHIVE_FATAL.
        self.base.state as c_int
    }

    pub fn write_finish_entry(&mut self) -> c_int {
        self.kind.ops().write_finish_entry(&mut self.base)
    }

    pub fn write_data(&mut self, buf: &[u8]) -> isize {
        self.kind.ops().write_data(&mut self.base, buf)
    }

    pub fn write_data_block(&mut self, buf: &[u8], offset: i64) -> isize {
        self.kind
            .ops()
            .write_data_block(&mut self.base, buf, offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{Handle, Kind};

    /// A kind with two filters that records what was called on it.
    #[derive(Default)]
    struct Fake {
        log: Vec<&'static str>,
    }

    impl Ops for Fake {
        fn close(&mut self, a: &mut Base) -> c_int {
            a.state = state::CLOSED;
            ARCHIVE_OK
        }
        fn free(&mut self, _a: &mut Base) -> c_int {
            ARCHIVE_WARN
        }
        fn filter_count(&self) -> c_int {
            2
        }
        fn filter_bytes(&self, n: c_int) -> i64 {
            [-1, 100, 40].get((n + 1) as usize).copied().unwrap_or(-1)
        }
        fn filter_code(&self, n: c_int) -> c_int {
            n + 10
        }
        fn filter_name(&self, n: c_int) -> Option<&CStr> {
            (n == 0).then_some(c"gzip")
        }
        fn write_data(&mut self, _a: &mut Base, buf: &[u8]) -> isize {
            self.log.push("write_data");
            buf.len() as isize
        }
    }

    fn handle() -> Handle {
        Handle::new(WRITE_MAGIC, Kind::Test(Box::<Fake>::default()))
    }

    #[test]
    fn dispatch_reaches_the_kind() {
        let mut h = handle();
        assert_eq!(h.filter_count(), 2);
        assert_eq!(h.filter_code(1), 11);
        assert_eq!(h.filter_name(0), Some(c"gzip"));
        assert_eq!(h.filter_name(1), None);
        assert_eq!(h.filter_bytes(0), 100);
        assert_eq!(h.write_data(b"abc"), 3);
        assert_eq!(h.close(), ARCHIVE_OK);
        assert_eq!(h.base.state, state::CLOSED);
        assert_eq!(h.free(), ARCHIVE_WARN);
    }

    #[test]
    fn unsupported_write_data_block_is_fatal() {
        let mut h = handle();
        assert_eq!(h.write_data_block(b"x", 0), ARCHIVE_FATAL as isize);
        assert_eq!(h.base.state, state::FATAL);
        assert_eq!(
            h.base.error_string(),
            Some(b"archive_write_data_block not supported".as_slice())
        );
    }

    #[test]
    fn write_fail_returns_the_fatal_state() {
        let mut h = handle();
        assert_eq!(h.write_fail(), 0x8000);
        assert_eq!(h.base.state, state::FATAL);
    }
}
