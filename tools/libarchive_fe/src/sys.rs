//! The libc calls the front-ends make that std has no wrapper for: signal
//! dispositions, the terminal's echo, the umask, `strerror`, the locale and
//! its character classes, `fnmatch`, regular expressions, `strtol`, local
//! time, file times, the user and group databases, the effective user and
//! `chroot`. This is the only `unsafe` code in the front-ends; every function
//! here is safe to call.

use std::ffi::{CStr, CString, c_char, c_int, c_long};
use std::os::fd::{AsRawFd, BorrowedFd, IntoRawFd, OwnedFd};
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

/// `isprint(c)` in the current locale.
pub fn isprint(c: u8) -> bool {
    // SAFETY: isprint takes any unsigned char's value.
    unsafe { libc::isprint(c_int::from(c)) != 0 }
}

/// `isspace(c)` in the current locale.
pub fn isspace(c: u8) -> bool {
    // SAFETY: isspace takes any unsigned char's value.
    unsafe { libc::isspace(c_int::from(c)) != 0 }
}

unsafe extern "C" {
    #[link_name = "mbtowc"]
    fn c_mbtowc(pwc: *mut libc::wchar_t, s: *const c_char, n: usize) -> c_int;
    // wint_t is int on macOS and unsigned int on glibc: the same register.
    #[link_name = "iswprint"]
    fn c_iswprint(wc: libc::wchar_t) -> c_int;
}

/// `mbtowc(NULL, NULL, 0)`: resets the conversion state, and tells whether
/// the locale's encoding has shift states.
pub fn mbtowc_reset() -> bool {
    // SAFETY: NULL arguments ask only for the reset.
    unsafe { c_mbtowc(std::ptr::null_mut(), std::ptr::null(), 0) != 0 }
}

/// `mbtowc(&wc, s, s.len())`: the character `s` starts with and how many
/// bytes it takes up, or `None` if they are not a valid character.
pub fn mbtowc(s: &[u8]) -> Option<(libc::wchar_t, usize)> {
    let mut wc = 0;
    // SAFETY: `wc` is writable, and mbtowc reads at most `s.len()` bytes
    // of `s`.
    let n = unsafe { c_mbtowc(&mut wc, s.as_ptr().cast(), s.len()) };
    usize::try_from(n).ok().map(|n| (wc, n))
}

/// `iswprint(wc)` in the current locale.
pub fn iswprint(wc: libc::wchar_t) -> bool {
    // SAFETY: iswprint has no memory-safety requirements.
    unsafe { c_iswprint(wc) != 0 }
}

/// `nl_langinfo(item)`: the locale's string for `item`.
pub fn nl_langinfo(item: libc::nl_item) -> Vec<u8> {
    // SAFETY: nl_langinfo returns a NUL-terminated string (empty for an
    // unknown item), valid until the next call, which the copy precedes.
    unsafe { CStr::from_ptr(libc::nl_langinfo(item)) }
        .to_bytes()
        .to_vec()
}

/// `strtol(s, &end, base)` of the C string in `s`: the number it starts
/// with, and how many bytes that takes up (0 if it doesn't start with one).
pub fn strtol(s: &[u8], base: c_int) -> (c_long, usize) {
    let s = s.split(|&b| b == 0).next().unwrap_or_default();
    let Ok(s) = CString::new(s) else {
        return (0, 0);
    };
    let mut end = s.as_ptr().cast_mut();
    // SAFETY: `s` is a NUL-terminated string, and strtol points `end`
    // into it.
    let n = unsafe { libc::strtol(s.as_ptr(), &mut end, base) };
    (n, end as usize - s.as_ptr() as usize)
}

/// `chroot(path)`, or the errno.
pub fn chroot(path: &Path) -> Result<(), c_int> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    match unsafe { libc::chroot(path.as_ptr()) } {
        0 => Ok(()),
        _ => Err(errno()),
    }
}

/// The start of the platform's `regex_t`, up to `re_nsub`, which
/// `libc::regex_t` keeps private.
#[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
#[repr(C)]
struct RegexHead {
    re_magic: c_int,
    re_nsub: usize,
}
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[repr(C)]
struct RegexHead {
    buffer: *mut libc::c_void,
    allocated: usize,
    used: usize,
    syntax: libc::c_ulong,
    fastmap: *mut c_char,
    translate: *mut libc::c_uchar,
    re_nsub: usize,
}
#[cfg(all(target_os = "linux", target_env = "musl"))]
#[repr(C)]
struct RegexHead {
    re_nsub: usize,
}

/// A POSIX regular expression, compiled with `regcomp` and freed with
/// `regfree`. Boxed, as `regcomp` may point the `regex_t` at itself.
pub struct Regex(Box<libc::regex_t>);

impl Regex {
    /// `regcomp(pattern, cflags)` of the C string in `pattern`, or what
    /// `regerror` says of the failure.
    pub fn new(pattern: &[u8], cflags: c_int) -> Result<Regex, Vec<u8>> {
        let pattern = pattern.split(|&b| b == 0).next().unwrap_or_default();
        let pattern = CString::new(pattern).map_err(|_| Vec::new())?;
        // SAFETY: a zeroed regex_t (integers and pointers) is a valid one
        // for regcomp to fill in; `pattern` is NUL-terminated; `buf` is
        // writable for its length, and regerror writes a NUL-terminated
        // message into it.
        unsafe {
            let mut re = Box::new(std::mem::zeroed::<libc::regex_t>());
            let r = libc::regcomp(&mut *re, pattern.as_ptr(), cflags);
            if r == 0 {
                return Ok(Regex(re));
            }
            let mut buf = [0u8; 256];
            libc::regerror(r, &*re, buf.as_mut_ptr().cast(), buf.len());
            let msg = CStr::from_bytes_until_nul(&buf).map_or(&[][..], CStr::to_bytes);
            Err(msg.to_vec())
        }
    }

    /// `re_nsub`: the number of subexpressions.
    pub fn nsub(&self) -> usize {
        let re: *const libc::regex_t = &*self.0;
        // SAFETY: `RegexHead` is the start of the platform's regex_t, which
        // regcomp filled in.
        unsafe { (*re.cast::<RegexHead>()).re_nsub }
    }

    /// `regexec(s, N, 0)`: where the match and the first `N - 1`
    /// subexpressions start and end in `s` (-1 for those that matched
    /// nothing), or `None` if `s` doesn't match.
    pub fn exec<const N: usize>(&self, s: &CStr) -> Option<[(isize, isize); N]> {
        // SAFETY: a zeroed regmatch_t is a valid one; the compiled regex
        // and `s` outlive the call; regexec writes at most N matches.
        let mut matches = [unsafe { std::mem::zeroed::<libc::regmatch_t>() }; N];
        // SAFETY: as above.
        let r = unsafe { libc::regexec(&*self.0, s.as_ptr(), N, matches.as_mut_ptr(), 0) };
        (r == 0).then(|| matches.map(|m| (m.rm_so as isize, m.rm_eo as isize)))
    }
}

impl Drop for Regex {
    fn drop(&mut self) {
        // SAFETY: regcomp compiled the regex, and nothing uses it after
        // this.
        unsafe { libc::regfree(&mut *self.0) };
    }
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

/// `geteuid()`.
pub fn geteuid() -> libc::uid_t {
    // SAFETY: geteuid has no memory-safety requirements.
    unsafe { libc::geteuid() }
}

/// Calls `call` with a scratch buffer, doubled while it reports `ERANGE`.
/// `call` returns the error number of a `get*_r` function, and what it
/// found if anything. Not found is `Ok(None)`: a zero result, or `ENOENT`.
fn lookup<T>(mut call: impl FnMut(&mut [u8]) -> (c_int, Option<T>)) -> Result<Option<T>, c_int> {
    let mut buf = vec![0u8; 1024];
    loop {
        match call(&mut buf) {
            (libc::ERANGE, _) if buf.len() < 1 << 20 => buf.resize(buf.len() * 2, 0),
            (0 | libc::ENOENT, found) => return Ok(found),
            (err, _) => return Err(err),
        }
    }
}

/// `getpwnam(name)`: the user's name, uid and primary gid, if there is
/// such a user.
pub fn getpwnam(name: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    let name = CString::new(name).ok()?;
    lookup(|buf| {
        // SAFETY: a zeroed passwd is a valid one, for getpwnam_r to fill;
        // `name` is a NUL-terminated string, `buf` is writable for its
        // length and `res` is a valid place for the result. A result is
        // valid until `buf` changes, and its name is copied out before.
        unsafe {
            let mut pw: libc::passwd = std::mem::zeroed();
            let mut res = std::ptr::null_mut();
            let err = libc::getpwnam_r(
                name.as_ptr(),
                &mut pw,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut res,
            );
            let found = (!res.is_null()).then(|| {
                let name = CStr::from_ptr(pw.pw_name).to_bytes().to_vec();
                (name, pw.pw_uid, pw.pw_gid)
            });
            (err, found)
        }
    })
    .ok()
    .flatten()
}

/// `getgrnam(name)`: the group's name and gid, if there is such a group.
pub fn getgrnam(name: &[u8]) -> Option<(Vec<u8>, u32)> {
    let name = CString::new(name).ok()?;
    lookup(|buf| {
        // SAFETY: as in `getpwnam`.
        unsafe {
            let mut gr: libc::group = std::mem::zeroed();
            let mut res = std::ptr::null_mut();
            let err = libc::getgrnam_r(
                name.as_ptr(),
                &mut gr,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut res,
            );
            let found = (!res.is_null())
                .then(|| (CStr::from_ptr(gr.gr_name).to_bytes().to_vec(), gr.gr_gid));
            (err, found)
        }
    })
    .ok()
    .flatten()
}

/// `getpwuid(uid)`: the user's name, `Ok(None)` if there is no such user,
/// or the errno.
pub fn getpwuid(uid: u32) -> Result<Option<Vec<u8>>, c_int> {
    lookup(|buf| {
        // SAFETY: as in `getpwnam`.
        unsafe {
            let mut pw: libc::passwd = std::mem::zeroed();
            let mut res = std::ptr::null_mut();
            let err = libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut res);
            let found = (!res.is_null()).then(|| CStr::from_ptr(pw.pw_name).to_bytes().to_vec());
            (err, found)
        }
    })
}

/// `getgrgid(gid)`: the group's name, `Ok(None)` if there is no such
/// group, or the errno.
pub fn getgrgid(gid: u32) -> Result<Option<Vec<u8>>, c_int> {
    lookup(|buf| {
        // SAFETY: as in `getpwnam`.
        unsafe {
            let mut gr: libc::group = std::mem::zeroed();
            let mut res = std::ptr::null_mut();
            let err = libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr().cast(), buf.len(), &mut res);
            let found = (!res.is_null()).then(|| CStr::from_ptr(gr.gr_name).to_bytes().to_vec());
            (err, found)
        }
    })
}

/// The access time and modification time, as seconds and microseconds,
/// for `futimes` and `lutimes`.
fn timevals(atime: (i64, i64), mtime: (i64, i64)) -> [libc::timeval; 2] {
    let tv = |(sec, usec): (i64, i64)| libc::timeval {
        tv_sec: sec as _,
        tv_usec: usec as _,
    };
    [tv(atime), tv(mtime)]
}

/// `futimes(fd, {atime, mtime})`, with times as seconds and microseconds,
/// or the errno.
pub fn futimes(fd: BorrowedFd<'_>, atime: (i64, i64), mtime: (i64, i64)) -> Result<(), c_int> {
    let times = timevals(atime, mtime);
    // SAFETY: `times` holds the two timevals futimes reads.
    match unsafe { libc::futimes(fd.as_raw_fd(), times.as_ptr()) } {
        0 => Ok(()),
        _ => Err(errno()),
    }
}

/// `lutimes(path, {atime, mtime})`, with times as seconds and
/// microseconds, or the errno.
pub fn lutimes(path: &Path, atime: (i64, i64), mtime: (i64, i64)) -> Result<(), c_int> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    let times = timevals(atime, mtime);
    // SAFETY: `path` is a NUL-terminated string and `times` holds the two
    // timevals lutimes reads; both outlive the call.
    match unsafe { libc::lutimes(path.as_ptr(), times.as_ptr()) } {
        0 => Ok(()),
        _ => Err(errno()),
    }
}

/// `close(fd)`, which std's drop of a descriptor does not report, or the
/// errno.
pub fn close(fd: OwnedFd) -> Result<(), c_int> {
    // SAFETY: `fd` is open and this is its only owner; it is not used again.
    match unsafe { libc::close(fd.into_raw_fd()) } {
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
    fn accounts_are_looked_up_by_name_and_number() {
        assert_eq!(
            getpwnam(b"root").map(|u| (u.0, u.1)),
            Some((b"root".to_vec(), 0))
        );
        assert_eq!(getpwuid(0), Ok(Some(b"root".to_vec())));
        assert_eq!(getpwnam(b"no such user"), None);
        assert_eq!(getpwuid(0x7fff_fff0), Ok(None));
        assert_eq!(getgrnam(b"no such group"), None);
        assert_eq!(getgrgid(0x7fff_fff0), Ok(None));
        let group = getgrgid(0).unwrap().unwrap();
        assert_eq!(getgrnam(&group), Some((group, 0)));
    }

    #[test]
    fn tolower_maps_ascii() {
        assert_eq!(tolower(b'Q'), b'q');
        assert_eq!(tolower(b'-'), b'-');
    }

    #[test]
    fn regex_matches_and_counts_subexpressions() {
        let re = Regex::new(b"\\(a*\\)b\\(c\\)*", 0).unwrap();
        assert_eq!(re.nsub(), 2);
        let m = re.exec::<4>(c"xaab").unwrap();
        assert_eq!(m, [(1, 4), (1, 3), (-1, -1), (-1, -1)]);
        assert!(re.exec::<1>(c"xyz").is_none());
        let err = Regex::new(b"a\\(", 0).err().unwrap();
        assert!(!err.is_empty());
    }

    #[test]
    fn strtol_reports_where_the_number_ends() {
        assert_eq!(strtol(b"123", 10), (123, 3));
        assert_eq!(strtol(b" -5x", 10), (-5, 3));
        assert_eq!(strtol(b"x", 10), (0, 0));
        assert_eq!(strtol(b"99999999999999999999", 10), (c_long::MAX, 20));
    }

    #[test]
    fn ctype_in_the_c_locale() {
        assert!(isprint(b'a') && !isprint(b'\n') && !isprint(0xe9));
        assert!(isspace(b'\t') && !isspace(b'a'));
        assert!(!mbtowc_reset());
        assert_eq!(mbtowc(b"ab"), Some((libc::wchar_t::from(b'a'), 1)));
        assert!(iswprint(libc::wchar_t::from(b'a')));
    }
}
