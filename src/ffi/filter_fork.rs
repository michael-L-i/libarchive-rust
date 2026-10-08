/*-
 * Copyright (c) 2007 Joerg Sonnenberger
 * Copyright (c) 2012 Michihiro NAKAJIMA
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

// Ported from libarchive/filter_fork_posix.c.

//! Running a program with pipes on its standard input and output.

use crate::cmdline::Cmdline;
use std::ffi::OsStr;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// Turns `O_NONBLOCK` on or off, like upstream's `fcntl(F_SETFL)`: an error
/// is ignored.
pub fn set_nonblocking(pipe: &impl AsRawFd, on: bool) {
    let flags = if on { libc::O_NONBLOCK } else { 0 };
    // SAFETY: fcntl on a descriptor has no memory-safety requirements.
    unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags) };
}

/// `__archive_create_child`: starts the program, searching `PATH` unless its
/// name has a `/`, with the environment of this process. Our ends of the
/// pipes, `stdin` and `stdout` of the child, are non-blocking.
pub fn create_child(line: &Cmdline) -> io::Result<Child> {
    let child = Command::new(OsStr::from_bytes(&line.path))
        .arg0(OsStr::from_bytes(&line.name))
        .args(line.args.iter().map(|arg| OsStr::from_bytes(arg)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    if let Some(stdin) = &child.stdin {
        set_nonblocking(stdin, true);
    }
    if let Some(stdout) = &child.stdout {
        set_nonblocking(stdout, true);
    }
    Ok(child)
}

/// `__archive_check_child`: blocks until the child can take more input or
/// has output (or has hung up). At least one pipe must be given.
pub fn check_child(stdin: Option<&ChildStdin>, stdout: Option<&ChildStdout>) {
    let mut fds: Vec<libc::pollfd> = stdin
        .map(|f| (f.as_raw_fd(), libc::POLLOUT))
        .into_iter()
        .chain(stdout.map(|f| (f.as_raw_fd(), libc::POLLIN)))
        .map(|(fd, events)| libc::pollfd {
            fd,
            events,
            revents: 0,
        })
        .collect();
    // SAFETY: `fds` is a valid array of `fds.len()` pollfds, which poll may
    // write the results to.
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn child_echoes_through_nonblocking_pipes() {
        let line = crate::cmdline::parse(b"cat").unwrap();
        let mut child = create_child(&line).unwrap();
        let (mut stdin, mut stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
        let mut buf = [0; 5];
        // Nothing to read yet.
        assert_eq!(
            stdout.read(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        stdin.write_all(b"hello").unwrap();
        check_child(None, Some(&stdout));
        assert_eq!(stdout.read(&mut buf).unwrap(), 5);
        assert_eq!(&buf, b"hello");
        drop(stdin);
        check_child(None, Some(&stdout));
        assert_eq!(stdout.read(&mut buf).unwrap(), 0);
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn missing_program_fails_to_start() {
        let line = crate::cmdline::parse(b"/nonexistent/program -d").unwrap();
        assert_eq!(
            create_child(&line).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
