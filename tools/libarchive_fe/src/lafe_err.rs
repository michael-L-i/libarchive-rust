/*-
 * Copyright (c) 2003-2007 Tim Kientzle
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

// Ported from libarchive_fe/lafe_err.c.

//! Messages to standard error, prefixed with the program's name, in the
//! manner of `warnc(3)` and `errc(3)`. A message is bytes, since it may
//! include pathnames; build it with `format!` or by concatenating bytes.

use crate::sys;
use std::ffi::{OsStr, c_int};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::sync::{PoisonError, RwLock};

static LAFE_PROGNAME: RwLock<Vec<u8>> = RwLock::new(Vec::new());

/// `lafe_getprogname`.
pub fn lafe_getprogname() -> Vec<u8> {
    LAFE_PROGNAME
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// `lafe_setprogname`: the last component of `name` (C's `argv[0]`), or
/// `defaultname` if there is none.
pub fn lafe_setprogname(name: Option<&OsStr>, defaultname: &str) {
    let name = name.map_or(defaultname.as_bytes(), OsStr::as_bytes);
    let base = name.rsplit(|&b| b == b'/').next().unwrap_or(name);
    *LAFE_PROGNAME
        .write()
        .unwrap_or_else(PoisonError::into_inner) = base.to_vec();
}

/// "progname: msg", then ": " and `strerror(code)` if `code` is not 0. One
/// write, where upstream's unbuffered stderr makes several.
fn lafe_vwarnc(code: c_int, msg: &[u8]) {
    let mut line = lafe_getprogname();
    line.extend_from_slice(b": ");
    line.extend_from_slice(msg);
    if code != 0 {
        line.extend_from_slice(b": ");
        line.extend(sys::strerror(code));
    }
    line.push(b'\n');
    let _ = std::io::stderr().write_all(&line);
}

/// `lafe_warnc(code, fmt, ...)`, with the message formatted already.
pub fn lafe_warnc(code: c_int, msg: impl AsRef<[u8]>) {
    lafe_vwarnc(code, msg.as_ref());
}

/// `lafe_errc(eval, code, fmt, ...)`: `lafe_warnc`, then exits with
/// `eval`.
pub fn lafe_errc(eval: c_int, code: c_int, msg: impl AsRef<[u8]>) -> ! {
    lafe_vwarnc(code, msg.as_ref());
    std::process::exit(eval)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progname_is_the_last_component() {
        lafe_setprogname(Some(OsStr::new("/usr/local/bin/bsdcat")), "x");
        assert_eq!(lafe_getprogname(), b"bsdcat");
        lafe_setprogname(Some(OsStr::new("bsdtar")), "x");
        assert_eq!(lafe_getprogname(), b"bsdtar");
        lafe_setprogname(Some(OsStr::new("dir/")), "x");
        assert_eq!(lafe_getprogname(), b"");
        lafe_setprogname(None, "bsdcpio");
        assert_eq!(lafe_getprogname(), b"bsdcpio");
    }
}
