/*-
 * Copyright (c) 2003-2010 Tim Kientzle
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

// Ported from libarchive/archive_check_magic.c.

use crate::archive::*;
use crate::util::Error;
use std::ffi::c_int;
use std::io::Write;

fn state_name(s: u32) -> &'static str {
    match s {
        state::NEW => "new",
        state::OPEN => "open",
        state::HEADER => "header",
        state::DATA => "data",
        state::DATA_RECOVERY => "data_recovery",
        state::EOF => "eof",
        state::CLOSED => "closed",
        state::FATAL => "fatal",
        _ => "??",
    }
}

fn handle_type_name(magic: u32) -> Option<&'static str> {
    match magic {
        WRITE_MAGIC => Some("archive_write"),
        READ_MAGIC => Some("archive_read"),
        WRITE_DISK_MAGIC => Some("archive_write_disk"),
        READ_DISK_MAGIC => Some("archive_read_disk"),
        MATCH_MAGIC => Some("archive_match"),
        _ => None,
    }
}

/// Names of the set bits, lowest first: "new/open".
fn all_states(mut states: u32) -> String {
    let mut names = Vec::new();
    while states != 0 {
        let lowbit = states & states.wrapping_neg();
        states &= !lowbit;
        names.push(state_name(lowbit));
    }
    names.join("/")
}

impl Base {
    /// Checks that this is a handle of kind `magic` in one of `states`.
    /// Returns `ARCHIVE_OK`, or records the error, makes the handle fatal and
    /// returns `ARCHIVE_FATAL`. Exported functions reach this through
    /// `ffi::archive::checked`.
    pub fn check_magic(&mut self, magic: u32, states: u32, func: &str) -> c_int {
        // If this isn't some form of archive handle, the library user has
        // screwed up so badly that we have no reliable way to report an error.
        let Some(handle_type) = handle_type_name(self.magic) else {
            let _ = writeln!(
                std::io::stderr(),
                "PROGRAMMER ERROR: Function {func} invoked with invalid archive handle"
            );
            std::process::abort();
        };
        let err = if self.magic != magic {
            format!(
                "PROGRAMMER ERROR: Function '{func}' invoked on '{handle_type}' archive object, which is not supported"
            )
        } else if self.state & states == 0 {
            // If we're already FATAL, don't overwrite the error.
            if self.state == state::FATAL {
                return ARCHIVE_FATAL;
            }
            format!(
                "INTERNAL ERROR: Function '{func}' invoked with archive structure in state '{}', should be in state '{}'",
                all_states(self.state),
                all_states(states)
            )
        } else {
            return ARCHIVE_OK;
        };
        self.state = state::FATAL;
        self.raise(Error::fatal(ARCHIVE_ERRNO_MISC, err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(a: &Base) -> &str {
        a.error_string().and_then(|e| e.to_str().ok()).unwrap_or("")
    }

    #[test]
    fn right_kind_and_state_passes() {
        let mut a = Base::new(READ_MAGIC);
        assert_eq!(
            a.check_magic(READ_MAGIC, state::NEW | state::OPEN, "f"),
            ARCHIVE_OK
        );
        assert_eq!((a.state, error(&a)), (state::NEW, ""));
    }

    #[test]
    fn wrong_kind_is_fatal() {
        let mut a = Base::new(WRITE_DISK_MAGIC);
        assert_eq!(
            a.check_magic(READ_MAGIC, state::ANY, "archive_read_close"),
            ARCHIVE_FATAL
        );
        assert_eq!(a.state, state::FATAL);
        assert_eq!(a.errno, -1);
        assert_eq!(
            error(&a),
            "PROGRAMMER ERROR: Function 'archive_read_close' invoked on 'archive_write_disk' archive object, which is not supported"
        );
    }

    #[test]
    fn wrong_state_names_both_states() {
        let mut a = Base::new(READ_MAGIC);
        a.state = state::DATA | state::EOF;
        assert_eq!(
            a.check_magic(READ_MAGIC, state::NEW | state::OPEN | state::CLOSED, "g"),
            ARCHIVE_FATAL
        );
        assert_eq!(a.state, state::FATAL);
        assert_eq!(
            error(&a),
            "INTERNAL ERROR: Function 'g' invoked with archive structure in state 'data/eof', should be in state 'new/open/closed'"
        );
    }

    #[test]
    fn fatal_state_keeps_its_error() {
        let mut a = Base::new(MATCH_MAGIC);
        a.state = state::FATAL;
        a.set_error(3, Some(b"first"));
        assert_eq!(a.check_magic(MATCH_MAGIC, state::NEW, "h"), ARCHIVE_FATAL);
        assert_eq!((a.errno, error(&a)), (3, "first"));
    }

    #[test]
    fn state_lists() {
        assert_eq!(
            all_states(0x7f),
            "new/open/header/data/data_recovery/eof/closed"
        );
        assert_eq!(all_states(state::FATAL), "fatal");
        assert_eq!(all_states(0x100), "??");
    }
}
