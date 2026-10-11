/*-
 * Copyright (c) 2008 Tim Kientzle
 * Copyright (c) 2010 Joerg Sonnenberger
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
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

// Ported from libarchive_fe/line_reader.c.

//! Read lines from file and do something with each one. If
//! `null_separator` is set, lines are terminated with zero bytes;
//! otherwise, they're terminated with newlines.
//!
//! This uses a self-sizing buffer to handle arbitrarily-long lines.

use crate::lafe_err::lafe_errc;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// `struct lafe_line_reader`.
pub struct LineReader {
    /// The input, until its end.
    f: Option<Box<dyn Read>>,
    buff: Vec<u8>,
    line_start: usize,
    /// How far `buff` has been searched for the end of the line.
    line_end: usize,
    pathname: Vec<u8>,
    /// Lines separated by null, not CR/CRLF/etc.
    null_separator: bool,
}

/// Where a line ends. A C string ends at a NUL too, so it ends a line in
/// either mode.
fn is_eol(c: u8, null_separator: bool) -> bool {
    c == 0 || !null_separator && (c == b'\r' || c == b'\n')
}

impl LineReader {
    /// `lafe_line_reader`: reads `pathname`, or standard input for "-".
    /// Exits if it can't be opened.
    pub fn new(pathname: &Path, null_separator: bool) -> LineReader {
        let name = pathname.as_os_str().as_bytes();
        let f: Box<dyn Read> = if name == b"-" {
            Box::new(io::stdin())
        } else {
            match File::open(pathname) {
                Ok(f) => Box::new(f),
                Err(e) => {
                    let errno = e.raw_os_error().unwrap_or(0);
                    lafe_errc(1, errno, [b"Couldn't open ", name].concat())
                }
            }
        };
        LineReader {
            f: Some(f),
            buff: Vec::new(),
            line_start: 0,
            line_end: 0,
            pathname: name.to_vec(),
            null_separator,
        }
    }

    /// `lafe_line_reader_next`: the next line, without its terminator, or
    /// `None` at the end. Empty lines are skipped, unless lines are
    /// separated by nulls. Exits if the input can't be read.
    #[allow(clippy::should_implement_trait)] // A line borrows the reader.
    pub fn next(&mut self) -> Option<&[u8]> {
        let nul = self.null_separator;
        loop {
            // If there's a line in the buffer, return it immediately.
            while let Some(len) = self.buff[self.line_end..]
                .iter()
                .position(|&c| is_eol(c, nul))
            {
                let (start, end) = (self.line_start, self.line_end + len);
                self.line_start = end + 1;
                self.line_end = end + 1;
                if nul || end > start {
                    return Some(&self.buff[start..end]);
                }
            }
            self.line_end = self.buff.len();

            // If we're at end-of-file, process the final data.
            let Some(f) = &mut self.f else {
                if self.line_start == self.buff.len() {
                    return None; // No more text
                }
                let start = self.line_start;
                self.line_start = self.buff.len();
                return Some(&self.buff[start..]);
            };

            // Buffer only has part of a line: move it to the beginning, and
            // get some more data, at least as much again.
            self.buff.drain(..self.line_start);
            self.line_end -= self.line_start;
            self.line_start = 0;
            let have = self.buff.len();
            self.buff.resize(have + have.max(8192), 0);
            match f.read(&mut self.buff[have..]) {
                Ok(n) => {
                    self.buff.truncate(have + n);
                    if n == 0 {
                        self.f = None;
                    }
                }
                Err(e) => {
                    let errno = e.raw_os_error().unwrap_or(0);
                    lafe_errc(
                        1,
                        errno,
                        [b"Can't read ", self.pathname.as_slice()].concat(),
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn lines(data: &[u8], null_separator: bool) -> Vec<Vec<u8>> {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let name = format!("lafe-line-reader-{}-{n}", std::process::id());
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, data).unwrap();
        let mut lr = LineReader::new(&path, null_separator);
        let mut out = Vec::new();
        while let Some(line) = lr.next() {
            out.push(line.to_vec());
        }
        std::fs::remove_file(path).unwrap();
        out
    }

    #[test]
    fn newlines_end_lines_and_empty_lines_are_skipped() {
        let got = lines(b"one\ntwo\r\n\nthree\rfour\0five", false);
        assert_eq!(got, [&b"one"[..], b"two", b"three", b"four", b"five"]);
        assert!(lines(b"\n\r\n", false).is_empty());
    }

    #[test]
    fn nulls_end_lines_and_keep_empty_ones() {
        let got = lines(b"a b\n\0\0c", true);
        assert_eq!(got, [&b"a b\n"[..], b"", b"c"]);
        assert_eq!(lines(b"x\0", true), [b"x"]);
    }

    #[test]
    fn long_lines_grow_the_buffer() {
        let long = vec![b'x'; 100_000];
        let data = [&long[..], b"\nshort\n"].concat();
        assert_eq!(lines(&data, false), [long, b"short".to_vec()]);
    }
}
