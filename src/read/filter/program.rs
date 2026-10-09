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

// Ported from libarchive/archive_read_support_filter_program.c.

//! The external program filter: the stream goes to the program's standard
//! input and its standard output is the filtered stream. Other filters use
//! it as the fallback when they have no decoder of their own.

use crate::archive::{ARCHIVE_FATAL, Base};
use crate::cmdline;
use crate::ffi::filter_fork::{check_child, create_child, set_nonblocking};
use crate::read::{ARCHIVE_ERRNO_MISC, Filter, FilterBidder, Read, Reader, Status, filter_code};
use crate::util::Error;
use std::ffi::{CStr, CString, c_int};
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ExitStatus};

/// The size of the output block.
const OUT_LEN: usize = 65536;

/// The bidder object stores the command and the signature to watch for.
/// The `inhibit` entry here is used to ensure that unchecked filters never
/// bid twice in the same pipeline.
struct Bidder {
    cmd: Vec<u8>,
    signature: Vec<u8>,
    inhibit: bool,
}

/// `archive_read_support_filter_program_signature`. An empty `signature`
/// is none.
pub fn support(r: &mut Read, cmd: &[u8], signature: &[u8]) -> Result<Status, Error> {
    if signature.len() > c_int::MAX as usize / 8 {
        return Err(Error::fatal(libc::EINVAL, "Signature too large"));
    }
    r.register_bidder(Box::new(Bidder {
        cmd: cmd.to_vec(),
        signature: signature.to_vec(),
        inhibit: false,
    }))
}

impl FilterBidder for Bidder {
    /// If we do have a signature, bid only if that matches.
    ///
    /// If there's no signature, we bid `INT_MAX` the first time we're
    /// called, then never bid again.
    fn bid(&mut self, up: &mut Reader<'_>) -> Result<c_int, Error> {
        if !self.signature.is_empty() {
            return Ok(match up.read_ahead(self.signature.len())? {
                Some(p) if p.starts_with(&self.signature) => {
                    c_int::try_from(self.signature.len().saturating_mul(8)).unwrap_or(c_int::MAX)
                }
                // No match, so don't bid.
                _ => 0,
            });
        }
        Ok(if std::mem::replace(&mut self.inhibit, true) {
            0
        } else {
            c_int::MAX
        })
    }

    fn init(&mut self, _up: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
        let name = CString::new([b"Program: ".as_slice(), &self.cmd].concat()).unwrap_or_default();
        Ok(Box::new(Program::start(
            &self.cmd,
            name,
            filter_code::PROGRAM,
        )?))
    }
}

/// The filter: a running program, and the block of its output.
pub struct Program {
    name: CString,
    code: c_int,
    proc: Proc,
    out: Box<[u8]>,
    len: usize,
}

impl Program {
    /// `__archive_read_program`: starts `cmd`, which reads the stream the
    /// filter sits on. `name` and `code` are what the filter reports.
    pub fn start(cmd: &[u8], name: CString, code: c_int) -> Result<Program, Error> {
        let child = cmdline::parse(cmd).and_then(|line| create_child(&line).ok());
        let Some(child) = child else {
            return Err(Error::fatal(
                libc::EINVAL,
                [
                    b"Can't initialize filter; unable to run program \"".as_slice(),
                    cmd,
                    b"\"",
                ]
                .concat(),
            ));
        };
        Ok(Program {
            name,
            code,
            proc: Proc {
                child,
                exit: Exit::Running,
            },
            out: vec![0; OUT_LEN].into_boxed_slice(),
            len: 0,
        })
    }
}

impl Filter for Program {
    fn name(&self) -> &CStr {
        &self.name
    }

    fn code(&self) -> c_int {
        self.code
    }

    fn read(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
        self.len = 0;
        let mut total = 0;
        while let Some(room) = self.out.get_mut(total..).filter(|room| !room.is_empty()) {
            // No recovery is possible if we can no longer read from the child.
            match self.proc.read(up, room)? {
                // We got EOF from the child.
                0 => break,
                n => total += n,
            }
        }
        self.len = total;
        Ok(())
    }

    fn block(&self) -> &[u8] {
        self.out.get(..self.len).unwrap_or_default()
    }

    fn close(&mut self, a: &Base) -> Result<Status, Error> {
        Ok(self.proc.stop(a))
    }
}

/// The child process. The pipes are `child.stdin` and `child.stdout`, until
/// they are closed.
struct Proc {
    child: Child,
    exit: Exit,
}

/// Whether the child is reaped, and how it ended.
#[derive(Clone, Copy)]
enum Exit {
    Running,
    Exited(ExitStatus),
    /// Waiting for the child failed.
    WaitFailed,
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.reap();
    }
}

impl Proc {
    /// Closes our side of the I/O with the child and reaps it, once.
    fn reap(&mut self) -> Option<ExitStatus> {
        self.child.stdin = None;
        self.child.stdout = None;
        if let Exit::Running = self.exit {
            self.exit = self.child.wait().map_or(Exit::WaitFailed, Exit::Exited);
        }
        match self.exit {
            Exit::Exited(status) => Some(status),
            _ => None,
        }
    }

    /// Shuts down the child, returns `Ok` if it exited normally.
    ///
    /// Note that the return value is sticky; if we're called again, we won't
    /// reap the child again, but we will return the same status (including
    /// error message if the child came to a bad end).
    fn stop(&mut self, a: &Base) -> Status {
        let Some(status) = self.reap() else {
            // waitpid() failed? This is ugly.
            return a.warn(ARCHIVE_ERRNO_MISC, "Error closing child process");
        };
        if let Some(signal) = status.signal() {
            // If the child died because we stopped reading before it was
            // done, that's okay. Some archive formats have padding at the end
            // that we routinely ignore.
            // The alternative to this would be to add a step before closing
            // the child's output to read from the child until the child has
            // no more to write.
            if signal == libc::SIGPIPE {
                return Status::Ok;
            }
            return a.warn(
                ARCHIVE_ERRNO_MISC,
                format!("Child process exited with signal {signal}"),
            );
        }
        match status.code() {
            Some(0) => Status::Ok,
            Some(code) => a.warn(
                ARCHIVE_ERRNO_MISC,
                format!("Child process exited with status {code}"),
            ),
            None => Status::Warn,
        }
    }

    /// The child's output has ended: reap it and report how it ended, as
    /// the end of the data if it was well.
    fn finish(&mut self, a: &Base) -> Result<usize, Error> {
        match self.stop(a) {
            Status::Ok => Ok(0),
            _ => Err(Error::recorded(ARCHIVE_FATAL)),
        }
    }

    /// With the input closed, nothing more is written, so the output can be
    /// read blocking.
    fn input_closed(&self) {
        if let Some(stdout) = &self.child.stdout {
            set_nonblocking(stdout, false);
        }
    }

    /// Reads some of the child's output into `buf`, feeding the child from
    /// `up` while it has nothing to say: returns 0 at the end of the output.
    fn read(&mut self, up: &mut Reader<'_>, buf: &mut [u8]) -> Result<usize, Error> {
        loop {
            let Some(stdout) = self.child.stdout.as_mut() else {
                return Ok(0);
            };
            match stdout.read(buf).map_err(|e| e.kind()) {
                Ok(n @ 1..) => return Ok(n),
                // The child has closed its output; reap the child and return
                // the status.
                Ok(0) | Err(ErrorKind::BrokenPipe) => return self.finish(up.base()),
                Err(ErrorKind::Interrupted) => continue,
                Err(ErrorKind::WouldBlock) => {}
                Err(_) => return Err(Error::silent(ARCHIVE_FATAL)),
            }

            let Some(mut stdin) = self.child.stdin.take() else {
                // Block until child has some I/O ready.
                check_child(None, self.child.stdout.as_ref());
                continue;
            };
            // Get some more data from upstream.
            let data = match up.read_ahead(1) {
                Ok(Some(data)) => data,
                // The end of the input, or a failure, which `?` reports;
                // `stdin` is closed when this iteration ends.
                end => {
                    self.input_closed();
                    end?;
                    continue;
                }
            };
            let written = loop {
                match stdin.write(data) {
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    written => break written,
                }
            };
            match written.map_err(|e| e.kind()) {
                // Consume whatever we managed to write.
                Ok(n @ 1..) => {
                    self.child.stdin = Some(stdin);
                    up.consume(n)?;
                }
                Err(ErrorKind::WouldBlock) => {
                    // Block until child has some I/O ready.
                    check_child(Some(&stdin), self.child.stdout.as_ref());
                    self.child.stdin = Some(stdin);
                }
                // Write failed. If it was a bad error, we're done; otherwise
                // it was EPIPE or EOF, and we can still read from the child.
                failed => {
                    self.input_closed();
                    if failed.is_err_and(|kind| kind != ErrorKind::BrokenPipe) {
                        return Err(Error::silent(ARCHIVE_FATAL));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ARCHIVE_OK, ARCHIVE_WARN, READ_MAGIC};
    use crate::read::format::raw;
    use crate::read_open_memory::Memory;

    /// Opens `input` with a program filter (and the raw format, which is
    /// happy with any stream).
    fn open(cmd: &str, signature: &[u8], input: Vec<u8>) -> (Read, Base, c_int) {
        let (mut r, a) = (Read::default(), Base::new(READ_MAGIC));
        assert_eq!(support(&mut r, cmd.as_bytes(), signature), Ok(Status::Ok));
        assert_eq!(raw::support(&mut r), Ok(Status::Ok));
        let code = r.open(&a, Box::new(Memory::new(input, 4096)));
        (r, a, code)
    }

    /// Everything the top filter produces.
    fn drain(r: &mut Read, a: &Base) -> Result<Vec<u8>, Error> {
        let (mut rd, mut out) = (r.reader(a), Vec::new());
        loop {
            let block = rd.peek_available(1)?;
            if block.is_empty() {
                return Ok(out);
            }
            out.extend_from_slice(block);
            let n = block.len();
            rd.consume(n)?;
        }
    }

    fn error(a: &Base) -> String {
        String::from_utf8_lossy(&a.error_string().unwrap()).into_owned()
    }

    fn pattern(len: u32) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    #[test]
    fn a_large_stream_goes_through_the_program_and_back() {
        // Far more than fits in a pipe, in both directions.
        let input = pattern(6_000_000);
        let (mut r, a, code) = open("cat", b"", input.clone());
        assert_eq!(code, ARCHIVE_OK);
        assert_eq!(drain(&mut r, &a).unwrap(), input);
        assert_eq!(r.filter_name(0), Some(c"Program: cat"));
        assert_eq!(r.filter_code(0), filter_code::PROGRAM);
        assert_eq!(r.close(&a), ARCHIVE_OK);
        // The name outlives the close.
        assert_eq!(r.filter_name(0), Some(c"Program: cat"));
    }

    #[test]
    fn a_program_that_stops_reading_is_not_an_error() {
        let (mut r, a, code) = open("head -c 100", b"", pattern(6_000_000));
        assert_eq!(code, ARCHIVE_OK);
        assert_eq!(drain(&mut r, &a).unwrap(), pattern(100));
        assert_eq!(r.close(&a), ARCHIVE_OK);
    }

    #[test]
    fn an_empty_stream_gives_an_empty_stream() {
        let (mut r, a, _) = open("cat", b"", Vec::new());
        assert_eq!(drain(&mut r, &a).unwrap(), b"");
        assert_eq!(r.close(&a), ARCHIVE_OK);
    }

    #[test]
    fn the_signature_decides_the_bid() {
        // The output of `tr` is upper case, so the filter does not bid again.
        for (input, filters) in [(&b"abc"[..], 2), (b"xbc", 1), (b"a", 1)] {
            let (r, _, code) = open("tr a-z A-Z", b"ab", input.to_vec());
            assert_eq!((code, r.filter_count()), (ARCHIVE_OK, filters), "{input:?}");
        }
    }

    #[test]
    fn a_signature_that_is_too_large_is_refused() {
        let mut r = Read::default();
        let signature = vec![0; c_int::MAX as usize / 8 + 1];
        let e = support(&mut r, b"cat", &signature).unwrap_err();
        assert_eq!(
            (e.code, e.errno, e.msg),
            (ARCHIVE_FATAL, libc::EINVAL, b"Signature too large".to_vec())
        );
    }

    #[test]
    fn a_missing_program_fails_the_open() {
        let (_, a, code) = open("nonexistent-program -d", b"", b"data".to_vec());
        assert_eq!(code, ARCHIVE_FATAL);
        assert_eq!(
            error(&a),
            "Can't initialize filter; unable to run program \"nonexistent-program -d\""
        );
        assert_eq!(a.errno.get(), libc::EINVAL);
    }

    #[test]
    fn a_failing_program_is_reported_again_at_close() {
        let (mut r, a, code) = open("sh -c \"head -c 100000; exit 3\"", b"", pattern(200_000));
        assert_eq!(code, ARCHIVE_OK);
        assert!(drain(&mut r, &a).is_err());
        assert_eq!(error(&a), "Child process exited with status 3");
        a.clear_error();
        assert_eq!(r.close(&a), ARCHIVE_WARN);
        assert_eq!(error(&a), "Child process exited with status 3");
    }

    #[test]
    fn a_program_killed_by_a_signal_is_reported() {
        let (mut r, a, code) = open(
            "sh -c \"head -c 100000; kill -9 $$\"",
            b"",
            pattern(200_000),
        );
        assert_eq!(code, ARCHIVE_OK);
        assert!(drain(&mut r, &a).is_err());
        assert_eq!(error(&a), "Child process exited with signal 9");
    }

    #[test]
    fn a_program_killed_by_sigpipe_ended_normally() {
        let (mut r, a, _) = open("sh -c \"kill -PIPE $$\"", b"", pattern(1_000_000));
        assert_eq!(drain(&mut r, &a).unwrap(), b"");
        assert_eq!(r.close(&a), ARCHIVE_OK);
    }
}
