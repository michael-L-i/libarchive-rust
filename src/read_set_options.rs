/*-
 * Copyright (c) 2011 Tim Kientzle
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

// Ported from libarchive/archive_read_set_options.c.

#![allow(dead_code)] // exported by ffi next

//! `archive_read_set_options` and friends: offering options to the
//! registered formats. Filters have no options.

use crate::archive::*;
use crate::options::{self, UNKNOWN_MODULE};
use crate::read::Read;
use std::ffi::c_int;

impl Read {
    /// `archive_set_format_option`: offers the option to every format that
    /// has options (only the one named `m`, if there is a module name).
    pub fn set_format_option(
        &mut self,
        a: &Base,
        m: Option<&[u8]>,
        o: &[u8],
        v: Option<&[u8]>,
    ) -> c_int {
        let (mut rv, mut matched_modules) = (ARCHIVE_WARN, 0);

        for i in 0..self.formats.len() {
            if m.is_some_and(|m| self.formats[i].name().as_bytes() != m) {
                continue;
            }
            self.format = Some(i);
            let r = self.formats[i].options(a, o, v);
            self.format = None;
            // This format does not support options.
            let Some(r) = r else { continue };
            if m.is_some() {
                matched_modules += 1;
            }

            match r {
                Ok(()) => rv = ARCHIVE_OK,
                Err(e) if e.code == ARCHIVE_FATAL => {
                    a.raise(e);
                    return ARCHIVE_FATAL;
                }
                Err(e) => {
                    a.raise(e);
                }
            }
        }
        // If the format name didn't match, return a special code for
        // set_option[s].
        if m.is_some() && matched_modules == 0 {
            return UNKNOWN_MODULE;
        }
        rv
    }

    /// `archive_set_option`: to formats and filters.
    pub fn set_option(&mut self, a: &Base, m: Option<&[u8]>, o: &[u8], v: Option<&[u8]>) -> c_int {
        options::set_either_option(
            m,
            o,
            v,
            &mut |m, o, v| self.set_format_option(a, m, o, v),
            &mut |m, _, _| set_filter_option(m),
        )
    }
}

/// `archive_set_filter_option`: no filter has options. If the filter name
/// didn't match, return a special code for set_option[s].
pub fn set_filter_option(m: Option<&[u8]>) -> c_int {
    if m.is_some() {
        UNKNOWN_MODULE
    } else {
        ARCHIVE_WARN
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::{Data, Entry, Format, Reader};
    use crate::util::Error;

    /// A format with a single boolean option `flag`, and a `broken` one that
    /// fails.
    struct Opt {
        name: &'static str,
        seen: Vec<String>,
    }

    impl Format for Opt {
        fn name(&self) -> &'static str {
            self.name
        }

        fn bid(&mut self, _: &mut Reader<'_>, _: c_int) -> c_int {
            0
        }

        fn options(&mut self, _: &Base, key: &[u8], value: Option<&[u8]>) -> Option<Result<(), Error>> {
            Some(match key {
                b"flag" => {
                    self.seen.push(format!("{:?}", value.map(String::from_utf8_lossy)));
                    Ok(())
                }
                b"broken" => Err(Error::fatal(libc::EINVAL, "Broken option")),
                _ => Err(Error::status(ARCHIVE_WARN)),
            })
        }

        fn read_header(&mut self, _: &mut Reader<'_>, _: &mut Entry) -> Result<(), Error> {
            Err(Error::status(ARCHIVE_EOF))
        }

        fn read_data<'x>(&'x mut self, _: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
            Ok(Data::Eof { offset: 0 })
        }
    }

    /// A format without options.
    struct Plain;

    impl Format for Plain {
        fn name(&self) -> &'static str {
            "plain"
        }

        fn bid(&mut self, _: &mut Reader<'_>, _: c_int) -> c_int {
            0
        }

        fn read_header(&mut self, _: &mut Reader<'_>, _: &mut Entry) -> Result<(), Error> {
            Err(Error::status(ARCHIVE_EOF))
        }

        fn read_data<'x>(&'x mut self, _: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
            Ok(Data::Eof { offset: 0 })
        }
    }

    fn handle() -> (Read, Base) {
        let mut r = Read::default();
        r.register_format(Box::new(Plain)).unwrap();
        r.register_format(Box::new(Opt {
            name: "opt",
            seen: Vec::new(),
        }))
        .unwrap();
        (r, Base::new(READ_MAGIC))
    }

    fn error(a: &Base) -> String {
        a.error_string()
            .map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned())
    }

    #[test]
    fn format_options_reach_the_named_module_only() {
        let (mut r, a) = handle();
        assert_eq!(r.set_format_option(&a, Some(b"opt"), b"flag", Some(b"1")), ARCHIVE_OK);
        assert_eq!(r.set_format_option(&a, None, b"flag", None), ARCHIVE_OK);
        // A module without options does not count as matched.
        assert_eq!(r.set_format_option(&a, Some(b"plain"), b"flag", None), UNKNOWN_MODULE);
        assert_eq!(r.set_format_option(&a, Some(b"nope"), b"flag", None), UNKNOWN_MODULE);
        assert_eq!(r.set_format_option(&a, Some(b"opt"), b"other", None), ARCHIVE_WARN);
        // The active format is only set while options run.
        assert_eq!(r.format, None);
    }

    #[test]
    fn a_fatal_option_stops_and_records() {
        let (mut r, a) = handle();
        assert_eq!(r.set_format_option(&a, None, b"broken", None), ARCHIVE_FATAL);
        assert_eq!((error(&a), a.errno.get()), ("Broken option".into(), libc::EINVAL));
    }

    #[test]
    fn set_option_reports_unknown_modules_and_options() {
        let (mut r, a) = handle();
        let mut run = |m: Option<&[u8]>, o: &[u8], v: Option<&[u8]>| {
            options::set_option(&a, m, Some(o), v, &mut |m, o, v| r.set_option(&a, m, o, v))
        };
        assert_eq!(run(Some(b"opt"), b"flag", Some(b"x")), ARCHIVE_OK);
        assert_eq!(run(None, b"flag", None), ARCHIVE_OK);
        assert_eq!(run(Some(b"nomod"), b"flag", None), ARCHIVE_FAILED);
        assert_eq!(error(&a), "Unknown module name: `nomod'");
        assert_eq!(run(None, b"nosuch", Some(b"1")), ARCHIVE_FAILED);
        assert_eq!(error(&a), "Undefined option: `nosuch=1'");
        assert_eq!(run(Some(b"opt"), b"nosuch", None), ARCHIVE_FAILED);
        assert_eq!(error(&a), "Undefined option: `!opt:nosuch'");
    }

    #[test]
    fn filter_options_are_always_unknown() {
        assert_eq!(set_filter_option(Some(b"gzip")), UNKNOWN_MODULE);
        assert_eq!(set_filter_option(None), ARCHIVE_WARN);
    }
}
