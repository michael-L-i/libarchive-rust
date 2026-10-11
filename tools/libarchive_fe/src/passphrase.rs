/*-
 * Copyright (c) 2014 Michihiro NAKAJIMA
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
/*	$OpenBSD: readpassphrase.c,v 1.27 2019/01/25 00:19:25 millert Exp $	*/

/*
 * Copyright (c) 2000-2002, 2007, 2010
 * 	Todd C. Miller <millert@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

// Ported from libarchive_fe/passphrase.c.

//! Prompting for a passphrase without echoing it: the portable
//! `readpassphrase(3)` upstream builds where libc has none (Linux), which
//! is the OpenBSD code macOS's libc has too.

use crate::lafe_err::lafe_errc;
use crate::sys;
use libc::{
    ECHO, ECHONL, EINTR, EINVAL, SIGALRM, SIGHUP, SIGINT, SIGPIPE, SIGQUIT, SIGTERM, SIGTSTP,
    SIGTTIN, SIGTTOU,
};
use std::ffi::c_int;
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd"
))]
const TCSASOFT: c_int = 0x10;
#[cfg(not(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd"
)))]
const TCSASOFT: c_int = 0;
const T_FLUSH: c_int = libc::TCSAFLUSH | TCSASOFT;

/// The signals that would otherwise leave the terminal with echo off.
const SIGNALS: [c_int; 9] = [
    SIGALRM, SIGHUP, SIGINT, SIGPIPE, SIGQUIT, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU,
];

const MAX_SIGNO: usize = {
    let (mut max, mut i) = (0, 0);
    while i < SIGNALS.len() {
        if SIGNALS[i] as usize > max {
            max = SIGNALS[i] as usize;
        }
        i += 1;
    }
    max
};

/// Which of `SIGNALS` arrived while the passphrase was read.
static SIGNO: [AtomicBool; MAX_SIGNO + 1] = [const { AtomicBool::new(false) }; MAX_SIGNO + 1];

extern "C" fn handler(s: c_int) {
    if let Some(caught) = usize::try_from(s).ok().and_then(|s| SIGNO.get(s)) {
        caught.store(true, Ordering::SeqCst);
    }
}

/// `readpassphrase(prompt, buf, bufsiz, RPP_ECHO_OFF)`: reads a line into
/// `buf` and returns its length (what fits of it, `buf.len() - 1` bytes at
/// most, as C needs a byte for the NUL), or the errno.
fn readpassphrase(prompt: &[u8], buf: &mut [u8]) -> Result<usize, c_int> {
    // I suppose we could alloc on demand in this case (XXX).
    let Some(end) = buf.len().checked_sub(1) else {
        return Err(EINVAL);
    };

    loop {
        for s in &SIGNO {
            s.store(false, Ordering::SeqCst);
        }
        // Read and write to /dev/tty if available. If not, read from stdin
        // and write to stderr.
        let tty = File::options().read(true).write(true).open("/dev/tty").ok();
        let (stdin, stderr) = (io::stdin(), io::stderr());
        let (input, output) = match &tty {
            Some(tty) => (tty.as_fd(), tty.as_fd()),
            None => (stdin.as_fd(), stderr.as_fd()),
        };

        // Turn off echo if possible. If we are using a tty but are not the
        // foreground pgrp this will generate SIGTTOU, so do it *before*
        // installing the signal handlers.
        let oterm = tty.as_ref().and_then(|_| sys::tcgetattr(input));
        let mut echo = true;
        let mut changed = false;
        if let Some(oterm) = &oterm {
            let mut term = *oterm;
            term.c_lflag &= !(ECHO | ECHONL);
            #[cfg(any(
                target_vendor = "apple",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "netbsd",
                target_os = "openbsd"
            ))]
            {
                term.c_cc[libc::VSTATUS] = libc::_POSIX_VDISABLE;
            }
            let _ = sys::tcsetattr(input, T_FLUSH, &term);
            echo = false;
            changed = term.c_lflag != oterm.c_lflag || term.c_cc != oterm.c_cc;
        }

        // Catch signals that would otherwise cause the user to end up with
        // echo turned off in the shell. Don't worry about things like
        // SIGXCPU and SIGVTALRM for now.
        let saved = SIGNALS.map(|s| sys::catch(s, handler));

        let _ = sys::write(output, prompt);
        let mut len = 0;
        let mut ch = [0];
        let nr = loop {
            match sys::read(input, &mut ch) {
                Ok(1) if ch[0] != b'\n' && ch[0] != b'\r' => {
                    if len < end {
                        buf[len] = ch[0];
                        len += 1;
                    }
                }
                r => break r,
            }
        };
        if !echo {
            let _ = sys::write(output, b"\n");
        }

        // Restore old terminal settings and signals.
        if let Some(oterm) = oterm.filter(|_| changed) {
            let ttou = &SIGNO[SIGTTOU as usize];
            let sigttou = ttou.load(Ordering::SeqCst);
            // Ignore SIGTTOU generated when we are not the fg pgrp.
            while sys::tcsetattr(input, T_FLUSH, &oterm) == Err(EINTR)
                && !ttou.load(Ordering::SeqCst)
            {}
            ttou.store(sigttou, Ordering::SeqCst);
        }
        for s in saved {
            s.restore();
        }
        drop(tty);

        // If we were interrupted by a signal, resend it to ourselves now
        // that we have restored the signal handlers.
        let mut need_restart = false;
        for (s, caught) in SIGNO.iter().enumerate() {
            let s = s as c_int;
            if caught.load(Ordering::SeqCst) {
                sys::kill_self(s);
                need_restart |= matches!(s, SIGTSTP | SIGTTIN | SIGTTOU);
            }
        }
        if !need_restart {
            return nr.map(|_| len);
        }
    }
}

/// `lafe_readpassphrase`: prompts with `prompt` on the terminal (or
/// standard error) and reads a passphrase into `buf` without echoing it.
/// `None` if a signal interrupted it; any other failure exits.
pub fn lafe_readpassphrase<'a>(prompt: &str, buf: &'a mut [u8]) -> Option<&'a [u8]> {
    match readpassphrase(prompt.as_bytes(), buf) {
        Ok(len) => buf.get(..len),
        Err(EINTR) => None,
        Err(e) => lafe_errc(1, e, "Couldn't read passphrase"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_buffer_needs_room_for_the_nul() {
        assert_eq!(readpassphrase(b"", &mut []), Err(EINVAL));
    }
}
