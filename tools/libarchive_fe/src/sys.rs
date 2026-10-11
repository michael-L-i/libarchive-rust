//! The libc calls the front-ends make that std has no wrapper for: signal
//! dispositions, the terminal's echo, the umask, `strerror`, the locale,
//! `fnmatch`, local time and file times. This is the only `unsafe` code in
//! the front-ends; every function here is safe to call.

use std::ffi::{CStr, CString, c_int};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

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

/// Gives `sig` its default action. Rust programs start with `SIGPIPE`
/// ignored, where C programs inherit it.
pub fn default_signal(sig: c_int) {
    // SAFETY: a zeroed sigaction is a valid one (no flags, and the empty
    // mask sigemptyset makes it); `sa` outlives the calls, and a NULL old
    // action is allowed.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(sig, &sa, std::ptr::null_mut());
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

/// `setlocale(LC_ALL, "")`: whether the environment's locale could be set.
pub fn setlocale_all() -> bool {
    // SAFETY: the locale name is a NUL-terminated string.
    !unsafe { libc::setlocale(libc::LC_ALL, c"".as_ptr()) }.is_null()
}

/// `tolower(c)` in the current locale.
pub fn tolower(c: u8) -> u8 {
    // SAFETY: tolower has no memory-safety requirements for an unsigned
    // char's value.
    unsafe { libc::tolower(c_int::from(c)) as u8 }
}

/// `fnmatch(pattern, name, casefold ? FNM_CASEFOLD : 0) == 0`. A string
/// with a NUL in it matches nothing.
pub fn fnmatch(pattern: &[u8], name: &[u8], casefold: bool) -> bool {
    let (Ok(pattern), Ok(name)) = (CString::new(pattern), CString::new(name)) else {
        return false;
    };
    let flags = if casefold { libc::FNM_CASEFOLD } else { 0 };
    // SAFETY: both are NUL-terminated strings that outlive the call.
    unsafe { libc::fnmatch(pattern.as_ptr(), name.as_ptr(), flags) == 0 }
}

/// `strftime(format)` of `time` as `localtime(3)` breaks it down: empty if
/// that fails.
pub fn strftime_local(format: &CStr, time: i64) -> Vec<u8> {
    let time = time as libc::time_t;
    let mut buf = [0u8; 64];
    // SAFETY: a zeroed tm is a valid one, for localtime_r to fill; `time`
    // and `tm` outlive the call; strftime writes at most `buf.len()` bytes
    // into `buf`, from a NUL-terminated format and the filled-in `tm`.
    unsafe {
        let mut tm = std::mem::zeroed();
        if libc::localtime_r(&time, &mut tm).is_null() {
            return Vec::new();
        }
        let n = libc::strftime(buf.as_mut_ptr().cast(), buf.len(), format.as_ptr(), &tm);
        buf[..n].to_vec()
    }
}

/// Access time now and modification time `sec`.`nsec`, for the `utimes`
/// family.
fn now_and(sec: i64, nsec: i64) -> [libc::timespec; 2] {
    let now = libc::timespec {
        tv_sec: 0,
        tv_nsec: libc::UTIME_NOW as _,
    };
    let mtime = libc::timespec {
        tv_sec: sec as _,
        tv_nsec: nsec as _,
    };
    [now, mtime]
}

/// `futimens(fd, {UTIME_NOW, {sec, nsec}})`, or the errno.
pub fn futimens_now(fd: BorrowedFd<'_>, sec: i64, nsec: i64) -> Result<(), c_int> {
    let times = now_and(sec, nsec);
    // SAFETY: `times` holds the two timespecs futimens reads.
    match unsafe { libc::futimens(fd.as_raw_fd(), times.as_ptr()) } {
        0 => Ok(()),
        _ => Err(errno()),
    }
}

/// `utimensat(AT_FDCWD, path, {UTIME_NOW, {sec, nsec}}, AT_SYMLINK_NOFOLLOW)`,
/// or the errno.
pub fn lutimens_now(path: &Path, sec: i64, nsec: i64) -> Result<(), c_int> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    let times = now_and(sec, nsec);
    // SAFETY: `path` is a NUL-terminated string and `times` holds the two
    // timespecs utimensat reads; both outlive the call.
    match unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } {
        0 => Ok(()),
        _ => Err(errno()),
    }
}

/// `lchmod(path, mode)`, or the errno.
#[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
pub fn lchmod(path: &Path, mode: libc::mode_t) -> Result<(), c_int> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    match unsafe { libc::lchmod(path.as_ptr(), mode) } {
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

    #[test]
    fn fnmatch_globs_and_folds_case() {
        assert!(fnmatch(b"dir/*.c", b"dir/a.c", false));
        assert!(!fnmatch(b"dir/*.c", b"dir/a.h", false));
        assert!(!fnmatch(b"A*", b"abc", false));
        assert!(fnmatch(b"A*", b"abc", true));
        assert!(!fnmatch(b"a\0", b"a\0", false));
    }

    #[test]
    fn strftime_formats_the_local_time() {
        let t = strftime_local(c"%Y", 86400 * 365 * 30);
        assert_eq!(t.len(), 4);
        assert!(t.starts_with(b"1999") || t.starts_with(b"2000"));
    }

    #[test]
    fn tolower_maps_ascii() {
        assert_eq!(tolower(b'Q'), b'q');
        assert_eq!(tolower(b'-'), b'-');
    }
}
