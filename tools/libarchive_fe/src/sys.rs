//! The libc calls the front-ends make that std has no wrapper for. This is
//! the only `unsafe` code in the front-ends; every function here is safe
//! to call.

use std::ffi::{CStr, c_int};
use std::os::fd::{AsRawFd, BorrowedFd};

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `strerror(code)`: the system's message for an errno value.
pub fn strerror(code: c_int) -> Vec<u8> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is writable for its length, and strerror_r writes a
    // NUL-terminated message (truncated if need be) into it. An unknown
    // code still gets one ("Unknown error: 99").
    unsafe { libc::strerror_r(code, buf.as_mut_ptr().cast(), buf.len()) };
    CStr::from_bytes_until_nul(&buf).map_or_else(|_| buf.to_vec(), |m| m.to_bytes().to_vec())
}

/// The file mode creation mask. `umask(2)` reads it only by replacing it,
/// so it is set to 0 and back.
pub fn umask() -> libc::mode_t {
    // SAFETY: umask has no memory-safety requirements.
    unsafe {
        let mask = libc::umask(0);
        libc::umask(mask);
        mask
    }
}

/// A signal's action before `catch` replaced it.
pub struct SavedAction {
    sig: c_int,
    action: libc::sigaction,
}

/// Runs `handler` on `sig`, interrupting system calls rather than
/// restarting them (no `SA_RESTART`). Returns the old action.
pub fn catch(sig: c_int, handler: extern "C" fn(c_int)) -> SavedAction {
    // SAFETY: zeroed sigactions are valid (see `default_signal`); `handler`
    // has the C signature a non-SA_SIGINFO handler needs; both structs
    // outlive the call.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        let mut action = std::mem::zeroed();
        libc::sigaction(sig, &sa, &mut action);
        SavedAction { sig, action }
    }
}

impl SavedAction {
    /// Puts the old action back.
    pub fn restore(self) {
        // SAFETY: `self.action` is what sigaction reported, and outlives
        // the call.
        unsafe { libc::sigaction(self.sig, &self.action, std::ptr::null_mut()) };
    }
}

/// `kill(getpid(), sig)`.
pub fn kill_self(sig: c_int) {
    // SAFETY: kill has no memory-safety requirements.
    unsafe { libc::kill(libc::getpid(), sig) };
}

/// `read(2)` into `buf`, or the errno. Reads only what it returns, unlike
/// std's buffered standard input.
pub fn read(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Result<usize, c_int> {
    // SAFETY: `buf` is writable for its length.
    let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    usize::try_from(n).map_err(|_| errno())
}

/// `write(2)`, or the errno.
pub fn write(fd: BorrowedFd<'_>, buf: &[u8]) -> Result<usize, c_int> {
    // SAFETY: `buf` is readable for its length.
    let n = unsafe { libc::write(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
    usize::try_from(n).map_err(|_| errno())
}

/// `tcgetattr`: the terminal's settings, if `fd` is a terminal.
pub fn tcgetattr(fd: BorrowedFd<'_>) -> Option<libc::termios> {
    // SAFETY: a zeroed termios is a valid one, for tcgetattr to fill.
    unsafe {
        let mut term = std::mem::zeroed();
        (libc::tcgetattr(fd.as_raw_fd(), &mut term) == 0).then_some(term)
    }
}

/// `tcsetattr`, or the errno.
pub fn tcsetattr(fd: BorrowedFd<'_>, actions: c_int, term: &libc::termios) -> Result<(), c_int> {
    // SAFETY: `term` is a valid termios that outlives the call.
    match unsafe { libc::tcsetattr(fd.as_raw_fd(), actions, term) } {
        0 => Ok(()),
        _ => Err(errno()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strerror_is_the_bare_message() {
        assert_eq!(strerror(libc::ENOENT), b"No such file or directory");
        assert!(strerror(99999).starts_with(b"Unknown error"));
    }
}
