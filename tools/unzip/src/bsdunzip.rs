/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2009, 2010 Joerg Sonnenberger <joerg@NetBSD.org>
 * Copyright (c) 2007-2008 Dag-Erling Smørgrav
 * Copyright (c) 2023, Martin Matuska
 * All rights reserved.
 */

// Ported from unzip/bsdunzip.c and unzip/bsdunzip.h.

//! bsdunzip: lists, tests and extracts the members of a zip archive.
//!
//! Upstream's `bsdunzip_windows.c`, and the code `bsdunzip.c` has for
//! Windows alone, are not ported.

#![deny(unsafe_code)]

mod cmdline;

use libarchive_fe::lafe_err::{lafe_setprogname, lafe_warnc};
use libarchive_fe::lafe_explicit_bzero::explicit_bzero;
use libarchive_fe::passphrase::lafe_readpassphrase;
use libarchive_fe::sys;
use libarchive_rust::{AE_IFDIR, AE_IFLNK, AE_IFREG, ArchiveRead, Status, version_details};
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString, c_int};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};

/// config.h's, which upstream's CMakeLists.txt makes from build/version.
const BSDUNZIP_VERSION_STRING: &str = "3.9.0";

/// `struct bsdunzip`: the option parser's state.
pub struct Bsdunzip {
    getopt_state: cmdline::State,
    /// What is left of the word being parsed.
    getopt_word: Vec<u8>,
    /// The words of the command line not parsed yet, the program name
    /// first.
    argv: VecDeque<Vec<u8>>,
    argument: Option<Vec<u8>>,
}

/// `OPTION_VERSION`. Upstream's `OPTION_NONE` (0) is never returned.
pub const OPTION_VERSION: c_int = 1;

/// Debug flag.
static UNZIP_DEBUG: AtomicBool = AtomicBool::new(false);

/// Indicates that last info() did not end with EOL. This helps error() et
/// al. avoid printing an error message on the same line as an incomplete
/// informational message.
static NOEOL: AtomicBool = AtomicBool::new(false);

/// What the command line asked for: upstream's file-scope variables.
#[derive(Default)]
struct Unzip {
    /// Convert EOL.
    a_opt: bool,
    /// Match case-insensitively.
    upper_c_opt: bool,
    /// Extract to stdout.
    c_opt: bool,
    /// Directory.
    d_arg: Option<Vec<u8>>,
    /// Update existing files only.
    f_opt: bool,
    /// Encoding.
    upper_o_arg: Option<Vec<u8>>,
    /// Junk directories.
    j_opt: bool,
    /// Lowercase names.
    upper_l_opt: bool,
    /// Never overwrite.
    n_opt: bool,
    /// Always overwrite.
    o_opt: bool,
    /// Extract to stdout, quiet.
    p_opt: bool,
    /// Passphrase.
    upper_p_arg: Option<Vec<u8>>,
    /// Quiet.
    q_opt: bool,
    /// Test.
    t_opt: bool,
    /// Update.
    u_opt: bool,
    /// Verbose/list: 1 for -l, 2 for -v.
    v_opt: u8,
    /// 4 digit year.
    y_str: &'static str,
    /// Zipinfo mode list files only.
    z1_opt: bool,
    /// Version string.
    version_opt: bool,
    /// Zipinfo mode.
    zipinfo_mode: bool,
    /// Running on tty?
    tty: bool,
    /// Processing exclude list.
    unzip_exclude_mode: bool,
    include: Vec<Vec<u8>>,
    exclude: Vec<Vec<u8>>,
}

/// Standard output, as printf writes it.
fn printf(msg: impl AsRef<[u8]>) {
    let _ = io::stdout().write_all(msg.as_ref());
}

/// Starts a message to standard error: ends an incomplete informational
/// line, and flushes standard output.
fn start_message() {
    if NOEOL.load(Ordering::Relaxed) {
        printf("\n");
    }
    let _ = io::stdout().flush();
}

/// "unzip: msg" and, if there is an errno, ": strerror".
fn message(code: Option<c_int>, msg: &[u8]) {
    start_message();
    let mut line = [b"unzip: ", msg].concat();
    if let Some(code) = code {
        line.extend_from_slice(b": ");
        line.extend(sys::strerror(code));
    }
    line.push(b'\n');
    let _ = io::stderr().write_all(&line);
}

/// Fatal error message + errno.
fn error(code: c_int, msg: impl AsRef<[u8]>) -> ! {
    message(Some(code), msg.as_ref());
    exit(1)
}

/// Fatal error message, no errno.
fn errorx(msg: impl AsRef<[u8]>) -> ! {
    message(None, msg.as_ref());
    exit(1)
}

/// Non-fatal error message + errno.
fn warning(code: c_int, msg: impl AsRef<[u8]>) {
    message(Some(code), msg.as_ref());
}

/// Non-fatal error message, no errno.
fn warningx(msg: impl AsRef<[u8]>) {
    message(None, msg.as_ref());
}

/// Debug message (if unzip_debug).
fn debug(msg: impl AsRef<[u8]>) {
    if !UNZIP_DEBUG.load(Ordering::Relaxed) {
        return;
    }
    let msg = msg.as_ref();
    let mut err = io::stderr();
    let _ = err.write_all(msg);
    let _ = err.flush();
    NOEOL.store(msg.last() != Some(&b'\n'), Ordering::Relaxed);
}

/// The archive's error message, which printf prints as "(null)" if there
/// is none.
fn archive_error(a: &ArchiveRead) -> Vec<u8> {
    let error = a.error_string();
    error.as_deref().unwrap_or(b"(null)").to_vec()
}

/// Fails with the archive's error message.
fn ac_fail(a: &ArchiveRead) -> ! {
    errorx(archive_error(a))
}

/// Convenience macro: fails with the archive's error message unless the
/// call succeeds.
/// XXX should differentiate between ARCHIVE_{WARN,FAIL,RETRY}
macro_rules! ac {
    ($a:expr, $call:expr) => {
        if $call != Status::Ok {
            ac_fail(&$a);
        }
    };
}

/// A path as std takes it.
fn os(path: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(path))
}

/// Concatenates two path names.
fn pathcat(prefix: Option<&[u8]>, path: &[u8]) -> Vec<u8> {
    match prefix {
        Some(prefix) => [prefix, b"/", path].concat(),
        None => path.to_vec(),
    }
}

/// System call to remove a file; the error is ignored.
fn system_unlink(pathname: &[u8]) {
    let _ = fs::remove_file(os(pathname));
}

/// System call to create a directory.
fn system_mkdir(pathname: &[u8], mode: u32) -> io::Result<()> {
    DirBuilder::new().mode(mode).create(os(pathname))
}

/// Create the specified directory with the specified mode, taking certain
/// precautions on the way.
fn make_dir(path: &[u8], mode: u32) {
    if let Ok(sb) = fs::symlink_metadata(os(path)) {
        if sb.is_dir() {
            return;
        }
        // Normally, we should either ask the user about removing the
        // non-directory of the same name as a directory we wish to create,
        // or respect the -n or -o command-line options. However, this may
        // lead to a later failure or even compromise (if this
        // non-directory happens to be a symlink to somewhere unsafe), so
        // we don't.
        system_unlink(path);
    }
    if let Err(e) = system_mkdir(path, mode)
        && e.raw_os_error() != Some(libc::EEXIST)
    {
        let msg = [b"mkdir('".as_slice(), path, b"')"].concat();
        error(e.raw_os_error().unwrap_or(0), msg);
    }
}

/// strlen: the length of `path` up to its first NUL.
fn strlen(path: &[u8]) -> usize {
    path.iter().position(|&c| c == 0).unwrap_or(path.len())
}

/// Ensure that all directories leading up to (but not including) the
/// specified path exist.
///
/// XXX inefficient + modifies the file in-place
fn make_parent(path: &mut [u8]) {
    // Retrieve string length of parent directory.
    let mut sep = match path.iter().rposition(|&c| c == b'/') {
        Some(sep) if sep != 0 => sep,
        _ => return,
    };
    let len = sep;

    // Find deepest already existing directory.
    loop {
        path[sep] = 0;
        if let Ok(sb) = fs::symlink_metadata(os(&path[..strlen(path)])) {
            if sb.is_dir() {
                path[sep] = b'/';
                break;
            }
            system_unlink(&path[..strlen(path)]);
        }
        match path[..sep].iter().rposition(|&c| c == b'/') {
            Some(prev) if prev != 0 => sep = prev,
            _ => break,
        }
    }

    // Create missing directories and restore path.
    while strlen(path) <= len {
        let n = strlen(path);
        let _ = system_mkdir(&path[..n], 0o755);
        path[n] = b'/';
    }
}

/// Extract a directory.
fn extract_dir(a: &mut ArchiveRead, unzip: &Unzip, path: &[u8]) {
    // Dropbox likes to create '/' directory entries, just ignore such junk.
    if path.is_empty() {
        return;
    }

    let mut mode = u32::from(a.entry().mode()) & 0o777;
    if mode == 0 {
        mode = 0o755;
    }

    // Some zipfiles contain directories with weird permissions such as 0644
    // or 0444. This can cause strange issues such as being unable to
    // extract files into the directory we just created, or the user being
    // unable to remove the directory later without first manually changing
    // its permissions. Therefore, we whack the permissions into shape,
    // assuming that the user wants full access and that anyone who gets
    // read access also gets execute access.
    mode |= 0o700;
    if mode & 0o040 != 0 {
        mode |= 0o010;
    }
    if mode & 0o004 != 0 {
        mode |= 0o001;
    }

    unzip.info([b"   creating: ".as_slice(), path, b"/\n"].concat());
    make_dir(path, mode);
    ac!(a, a.data_skip());
}

const SPINNER: [u8; 4] = *b"|/-\\";

/// `fgets(buf, n, stdin)`: reads at most `n` - 1 bytes, up to a newline.
/// False at the end of the input or on an error.
fn fgets(stdin: &mut impl BufRead, buf: &mut Vec<u8>, n: u64) -> bool {
    buf.clear();
    matches!(stdin.take(n - 1).read_until(b'\n', buf), Ok(len) if len > 0)
}

/// Black-listed: 0..6, 14..25, 28..31
/// 0xf3ffc07f = 11110011111111111100000001111111b
/// White-listed: 9..10, 13, >= 32
/// 0x00002600 = 00000000000000000010011000000000b
fn byte_is_binary(x: u8) -> bool {
    x < 32 && 0xf3ffc07fu32 & (1 << x) != 0
}

fn byte_is_text(x: u8) -> bool {
    x >= 32 || 0x00002600u32 & (1 << x) != 0
}

/// Detect binary files by a combination of character white list and black
/// list. NUL bytes and other control codes without use in text files result
/// directly in switching the file to binary mode. Otherwise, at least one
/// white-listed byte has to be found.
///
/// See the proginfo/txtvsbin.txt in the zip sources for a detailed
/// discussion.
fn check_binary(buf: &[u8]) -> bool {
    let mut rv = true;
    for &c in buf {
        if byte_is_binary(c) {
            return true;
        }
        if byte_is_text(c) {
            rv = false;
        }
    }
    rv
}

/// `write(fd, buf)` that must write it all.
fn write_all(fd: BorrowedFd<'_>, buf: &[u8], pathname: &[u8]) {
    match sys::write(fd, buf) {
        Ok(len) if len == buf.len() => {}
        r => error(
            r.err().unwrap_or(0),
            [b"write('".as_slice(), pathname, b"')"].concat(),
        ),
    }
}

impl Unzip {
    /// Informational message (if not -q).
    fn info(&self, msg: impl AsRef<[u8]>) {
        if self.q_opt && !UNZIP_DEBUG.load(Ordering::Relaxed) {
            return;
        }
        let msg = msg.as_ref();
        printf(msg);
        let _ = io::stdout().flush();
        NOEOL.store(msg.last() != Some(&b'\n'), Ordering::Relaxed);
    }

    /// Duplicate a path name, possibly converting to lower case.
    fn pathdup(&self, path: Option<&[u8]>) -> Option<Vec<u8>> {
        let mut path = path.filter(|p| !p.is_empty())?;
        while let [rest @ .., b'/'] = path {
            path = rest;
        }
        Some(if self.upper_l_opt {
            path.iter().map(|&c| sys::tolower(c)).collect()
        } else {
            path.to_vec()
        })
    }

    /// Add an entry to a pattern list.
    fn add_pattern(list: &mut Vec<Vec<u8>>, pattern: &[u8]) {
        debug([b"adding pattern '".as_slice(), pattern, b"'\n"].concat());
        list.push(pattern.to_vec());
    }

    /// Match a string against a list of patterns.
    fn match_pattern(&self, list: &[Vec<u8>], str: &[u8]) -> bool {
        list.iter()
            .any(|pattern| sys::fnmatch(pattern, str, self.upper_c_opt))
    }

    /// Verify that a given pathname is in the include list and not in the
    /// exclude list.
    fn accept_pathname(&self, pathname: &[u8]) -> bool {
        if !self.include.is_empty() && !self.match_pattern(&self.include, pathname) {
            return false;
        }
        if !self.exclude.is_empty() && self.match_pattern(&self.exclude, pathname) {
            return false;
        }
        true
    }

    /// Asks what to do about the existing file `path`: 1 to replace it, 0
    /// to try again with the new name now in `path`, -1 to leave it.
    fn handle_existing_file(&mut self, path: &mut Vec<u8>) -> i32 {
        let mut stdin = io::stdin().lock();
        let mut buf = Vec::new();
        loop {
            let prompt = [
                b"replace ".as_slice(),
                path,
                b"? [y]es, [n]o, [A]ll, [N]one, [r]ename: ",
            ]
            .concat();
            let _ = io::stderr().write_all(&prompt);
            if !fgets(&mut stdin, &mut buf, 4) {
                break;
            }
            match buf[0] {
                b'A' | b'y' | b'Y' => {
                    if buf[0] == b'A' {
                        self.o_opt = true;
                    }
                    system_unlink(path);
                    return 1;
                }
                b'N' | b'n' => {
                    if buf[0] == b'N' {
                        self.n_opt = true;
                    }
                    return -1;
                }
                b'r' | b'R' => {
                    printf("New name: ");
                    let _ = io::stdout().flush();
                    path.clear();
                    if !matches!(stdin.read_until(b'\n', path), Ok(len) if len > 0) {
                        break;
                    }
                    if path.last() == Some(&b'\n') {
                        path.pop();
                    }
                    return 0;
                }
                _ => {}
            }
        }
        // EOF or read error.
        printf("NULL\n(EOF or read error, treating as \"[N]one\"...)\n");
        self.n_opt = true;
        -1
    }

    /// Extract to a file descriptor. Returns whether the data was treated
    /// as text.
    fn extract2fd(&self, a: &mut ArchiveRead, pathname: &[u8], fd: BorrowedFd<'_>) -> bool {
        let mut buffer = [0u8; 8192];
        let mut text = self.a_opt;
        let mut warn = false;
        let mut cr = false;

        // Loop over file contents and write to fd.
        for n in 0.. {
            if fd.as_raw_fd() != libc::STDOUT_FILENO && self.tty && n % 4 == 0 {
                self.info([b' ', SPINNER[(n / 4) % SPINNER.len()], 8, 8]);
            }

            let len = match a.data(&mut buffer) {
                Ok(len) => len,
                Err(_) => ac_fail(a),
            };

            // Left over CR from previous buffer.
            if self.a_opt && cr {
                if len == 0 || buffer[0] != b'\n' {
                    write_all(fd, b"\r", pathname);
                }
                cr = false;
            }

            // EOF
            if len == 0 {
                break;
            }
            let buf = &buffer[..len];

            // Detect whether this is a text file. The correct way to do
            // this is to check the least significant bit of the "internal
            // file attributes" field of the corresponding file header in
            // the central directory, but libarchive does not provide
            // access to this field, so we have to guess by looking for
            // non-ASCII characters in the buffer. Hopefully we won't guess
            // wrong. If we do guess wrong, we print a warning message
            // later.
            if self.a_opt && n == 0 && check_binary(buf) {
                text = false;
            }

            // Simple case.
            if !self.a_opt || !text {
                write_all(fd, buf, pathname);
                continue;
            }

            // Hard case: convert \r\n to \n (sigh...).
            let mut p = 0;
            while p < buf.len() {
                let mut q = p;
                while q < buf.len() {
                    if !warn && byte_is_binary(buf[q]) {
                        let msg = [
                            pathname,
                            b" may be corrupted due to weak text file detection heuristic",
                        ];
                        warningx(msg.concat());
                        warn = true;
                    }
                    if buf[q] != b'\r' {
                        q += 1;
                        continue;
                    }
                    if q + 1 == buf.len() {
                        cr = true;
                        break;
                    }
                    if buf[q + 1] == b'\n' {
                        break;
                    }
                    q += 1;
                }
                write_all(fd, &buf[p..q], pathname);
                p = q + 1;
            }
        }

        text
    }

    /// Extract a regular file.
    fn extract_file(&mut self, a: &mut ArchiveRead, path: &mut Vec<u8>) {
        let e = a.entry();
        let mut mode = u32::from(e.mode()) & 0o777;
        if mode == 0 {
            mode = 0o644;
        }
        let (mtime_sec, mtime_nsec) = (e.mtime(), e.mtime_nsec());
        let linkname = e.symlink().map(<[u8]>::to_vec);

        // Look for existing file of same name.
        loop {
            match fs::symlink_metadata(os(path)) {
                Ok(sb) => {
                    if self.u_opt || self.f_opt {
                        // Check if up-to-date.
                        if sb.is_file()
                            && (sb.mtime() > mtime_sec
                                || (sb.mtime() == mtime_sec && sb.mtime_nsec() >= mtime_nsec))
                        {
                            return;
                        }
                        system_unlink(path);
                    } else if self.o_opt {
                        // Overwrite.
                        system_unlink(path);
                    } else if self.n_opt {
                        // Do not overwrite.
                        return;
                    } else {
                        match self.handle_existing_file(path) {
                            0 => continue,
                            -1 => return, // Do not overwrite.
                            _ => {}
                        }
                    }
                }
                Err(_) => {
                    if self.f_opt {
                        return;
                    }
                }
            }
            break;
        }

        // Process symlinks.
        if let Some(linkname) = linkname {
            if let Err(e) = std::os::unix::fs::symlink(OsStr::from_bytes(&linkname), os(path)) {
                let msg = [b"symlink('".as_slice(), path, b"')"].concat();
                error(e.raw_os_error().unwrap_or(0), msg);
            }
            self.info([b" extracting: ".as_slice(), path, b" -> ", &linkname, b"\n"].concat());
            #[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
            if let Err(e) = sys::lchmod(os(path), mode as libc::mode_t) {
                warning(
                    e,
                    [b"Cannot set mode for '".as_slice(), path, b"'"].concat(),
                );
            }
            // Set access and modification time.
            if let Err(e) = sys::lutimens_now(os(path), mtime_sec, mtime_nsec) {
                warning(e, [b"utimensat('".as_slice(), path, b"')"].concat());
            }
            return;
        }

        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(os(path))
        {
            Ok(file) => file,
            Err(e) => {
                let msg = [b"open('".as_slice(), path, b"')"].concat();
                error(e.raw_os_error().unwrap_or(0), msg);
            }
        };

        self.info([b" extracting: ".as_slice(), path].concat());

        let text = self.extract2fd(a, path, file.as_fd());

        if self.tty {
            self.info("  \x08\x08");
        }
        if text {
            self.info(" (text)");
        }
        self.info("\n");

        // Set access and modification time.
        if let Err(e) = sys::futimens_now(file.as_fd(), mtime_sec, mtime_nsec) {
            error(e, [b"futimens('".as_slice(), path, b"')"].concat());
        }
        if let Err(e) = sys::close(file.into()) {
            error(e, [b"close('".as_slice(), path, b"')"].concat());
        }
    }

    /// Extract a zipfile entry: first perform some sanity checks to ensure
    /// that it is either a directory or a regular file and that the path is
    /// not absolute and does not try to break out of the current
    /// directory; then call either extract_dir() or extract_file() as
    /// appropriate.
    ///
    /// This is complicated a bit by the various ways in which we need to
    /// manipulate the path name. Case conversion (if requested by the -L
    /// option) happens first, but the include / exclude patterns are
    /// applied to the full converted path name, before the directory part
    /// of the path is removed in accordance with the -j option. Sanity
    /// checks are intentionally done earlier than they need to be, so the
    /// user will get a warning about insecure paths even for files or
    /// directories which wouldn't be extracted anyway.
    fn extract(&mut self, a: &mut ArchiveRead) {
        let Some(pathname) = self.pathdup(a.entry().pathname()) else {
            warningx("skipping empty or unreadable filename entry");
            ac!(a, a.data_skip());
            return;
        };
        let filetype = a.entry().filetype();

        // Sanity checks.
        if pathname_is_insecure(&pathname) {
            warningx([b"skipping insecure entry '".as_slice(), &pathname, b"'"].concat());
            ac!(a, a.data_skip());
            return;
        }

        if filetype == AE_IFLNK
            && let Some(linktarget) = a.entry().symlink()
            && pathname_is_insecure(linktarget)
        {
            let msg = [
                b"skipping insecure symlink '".as_slice(),
                &pathname,
                b"' to '",
                linktarget,
                b"'",
            ];
            warningx(msg.concat());
            ac!(a, a.data_skip());
            return;
        }

        // I don't think this can happen in a zipfile..
        if filetype != AE_IFDIR && filetype != AE_IFREG && filetype != AE_IFLNK {
            warningx([b"skipping non-regular entry '".as_slice(), &pathname, b"'"].concat());
            ac!(a, a.data_skip());
            return;
        }

        // Skip directories in -j case.
        if filetype == AE_IFDIR && self.j_opt {
            ac!(a, a.data_skip());
            return;
        }

        // Apply include / exclude patterns.
        if !self.accept_pathname(&pathname) {
            ac!(a, a.data_skip());
            return;
        }

        // Apply -j and -d.
        let d_arg = self.d_arg.as_deref();
        let mut realpathname = if self.j_opt {
            let q = pathname
                .iter()
                .rposition(|&c| c == b'/')
                .map_or(0, |p| p + 1);
            pathcat(d_arg, &pathname[q..])
        } else {
            pathcat(d_arg, &pathname)
        };

        // Ensure that parent directory exists.
        make_parent(&mut realpathname);

        if filetype == AE_IFDIR {
            extract_dir(a, self, &realpathname);
        } else {
            self.extract_file(a, &mut realpathname);
        }
    }

    fn extract_stdout(&self, a: &mut ArchiveRead) {
        let Some(pathname) = self.pathdup(a.entry().pathname()) else {
            warningx("skipping empty or unreadable filename entry");
            ac!(a, a.data_skip());
            return;
        };
        let filetype = a.entry().filetype();

        // I don't think this can happen in a zipfile..
        if filetype != AE_IFDIR && filetype != AE_IFREG && filetype != AE_IFLNK {
            warningx([b"skipping non-regular entry '".as_slice(), &pathname, b"'"].concat());
            ac!(a, a.data_skip());
            return;
        }

        // Skip directories in -j case.
        if filetype == AE_IFDIR {
            ac!(a, a.data_skip());
            return;
        }

        // Apply include / exclude patterns.
        if !self.accept_pathname(&pathname) {
            ac!(a, a.data_skip());
            return;
        }

        if self.c_opt {
            self.info([b"x ".as_slice(), &pathname, b"\n"].concat());
        }

        let _ = self.extract2fd(a, &pathname, io::stdout().as_fd());
    }

    /// Print the name of an entry to stdout.
    fn list(&self, a: &mut ArchiveRead) {
        let e = a.entry();
        let format = if self.y_str.is_empty() {
            c"%m-%d-%y %H:%M"
        } else {
            c"%m-%d-%Y %H:%M"
        };
        let buf = sys::strftime_local(format, e.mtime());
        let size = e.size() as u64;
        let pathname = e.pathname().unwrap_or_default().to_vec();
        if !self.zipinfo_mode {
            if self.v_opt == 1 {
                let head = format!(" {size:8}  ");
                printf([head.as_bytes(), &buf, b"   ", &pathname, b"\n"].concat());
            } else if self.v_opt == 2 {
                let head = format!("{size:8}  Stored  {size:7}   0%  ");
                let crc = format!("  {:08x}  ", 0);
                printf([head.as_bytes(), &buf, crc.as_bytes(), &pathname, b"\n"].concat());
            }
        } else if self.z1_opt {
            printf([pathname.as_slice(), b"\n"].concat());
        }
        ac!(a, a.data_skip());
    }

    /// Extract to memory to check CRC. Returns the number of errors.
    fn test(&self, a: &mut ArchiveRead) -> u64 {
        let mut buffer = [0u8; 8192];
        let mut error_count = 0;
        if a.entry().filetype() == AE_IFDIR {
            return 0;
        }

        let pathname = a.entry().pathname().unwrap_or(b"(null)").to_vec();
        self.info([b"    testing: ".as_slice(), &pathname, b"\t"].concat());
        loop {
            match a.data(&mut buffer) {
                Ok(0) => {
                    self.info(" OK\n");
                    break;
                }
                Ok(_) => {}
                Err(_) => {
                    self.info([b" ".as_slice(), &archive_error(a), b"\n"].concat());
                    error_count += 1;
                    break;
                }
            }
        }

        // Shouldn't be necessary, but it doesn't hurt.
        ac!(a, a.data_skip());

        error_count
    }

    /// Main loop: open the zipfile, iterate over its contents and decide
    /// what to do with each entry.
    fn unzip(&mut self, fn_: Option<&[u8]>) {
        let mut a = ArchiveRead::new();

        ac!(a, a.support_format_zip());

        if let Some(charset) = &self.upper_o_arg {
            ac!(
                a,
                a.set_format_option(Some(b"zip"), Some(b"hdrcharset"), Some(charset))
            );
        }

        if let Some(passphrase) = &self.upper_p_arg {
            a.add_passphrase(passphrase);
        } else {
            a.set_passphrase_callback(passphrase_callback);
        }

        let (name, status) = match fn_ {
            Some(name) => {
                // Try fn, fn.zip and fn.ZIP.
                let names = [b"".as_slice(), b".zip", b".ZIP"].map(|ext| [name, ext].concat());
                let opened = names
                    .into_iter()
                    .find_map(|n| fs::File::open(os(&n)).ok().map(|f| (f, n)));
                let Some((file, found)) = opened else {
                    errorx([b"Failed to open '".as_slice(), name, b"'"].concat());
                };
                (found, a.open_fd(file, 64 * 1024))
            }
            // A NULL name is standard input; printf prints it as "(null)".
            None => (b"(null)".to_vec(), a.open_fd(io::stdin(), 64 * 1024)),
        };
        ac!(a, status);

        let y_str = self.y_str.as_bytes();
        if !self.zipinfo_mode {
            if !self.p_opt && !self.q_opt {
                printf([b"Archive:  ".as_slice(), &name, b"\n"].concat());
            }
            if self.v_opt == 1 {
                printf([b"  Length     ".as_slice(), y_str, b"Date   Time    Name\n"].concat());
                printf([b" --------    ".as_slice(), y_str, b"----   ----    ----\n"].concat());
            } else if self.v_opt == 2 {
                let head = b" Length   Method    Size  Ratio   ".as_slice();
                printf([head, y_str, b"Date   Time   CRC-32    Name\n"].concat());
                let head = b"--------  ------  ------- -----   ".as_slice();
                printf([head, y_str, b"----   ----   ------    ----\n"].concat());
            }
        }

        let mut total_size: u64 = 0;
        let mut file_count: u64 = 0;
        let mut error_count: u64 = 0;
        loop {
            let ret = a.next_header();
            if ret == Status::Eof {
                break;
            }
            ac!(a, ret);
            if !self.zipinfo_mode {
                if self.t_opt {
                    error_count += self.test(&mut a);
                } else if self.v_opt != 0 {
                    self.list(&mut a);
                } else if self.p_opt || self.c_opt {
                    self.extract_stdout(&mut a);
                } else {
                    self.extract(&mut a);
                }
            } else if self.z1_opt {
                self.list(&mut a);
            }

            total_size += a.entry().size() as u64;
            file_count += 1;
        }

        if self.zipinfo_mode {
            let s = if file_count != 1 { "s" } else { "" };
            if self.v_opt == 1 {
                printf(
                    [
                        b" --------                   ".as_slice(),
                        y_str,
                        b"-------\n",
                    ]
                    .concat(),
                );
                let tail = format!(" {total_size:8}                   ");
                printf(
                    [
                        tail.as_bytes(),
                        y_str,
                        format!("{file_count} file{s}\n").as_bytes(),
                    ]
                    .concat(),
                );
            } else if self.v_opt == 2 {
                let head = b"--------          -------  ---                            ";
                printf([head.as_slice(), y_str, b"-------\n"].concat());
                let tail = format!(
                    "{total_size:8}          {total_size:7}   0%                            "
                );
                printf(
                    [
                        tail.as_bytes(),
                        y_str,
                        format!("{file_count} file{s}\n").as_bytes(),
                    ]
                    .concat(),
                );
            }
        }

        ac!(a, a.close());
        drop(a);

        if self.t_opt {
            if error_count > 0 {
                errorx(format!("{error_count} checksum error(s) found."));
            } else {
                printf(
                    [
                        b"No errors detected in compressed data of ".as_slice(),
                        &name,
                        b".\n",
                    ]
                    .concat(),
                );
            }
        }
    }

    /// Process the options in `argv`, whose first word is skipped, and
    /// return how many words they used, counting that one.
    fn getopts(&mut self, argv: &[Vec<u8>]) -> usize {
        let mut bsdunzip = Bsdunzip {
            getopt_state: cmdline::State::Start,
            getopt_word: Vec::new(),
            argv: argv.iter().cloned().collect(),
            argument: None,
        };

        while let Some(opt) = bsdunzip.getopt() {
            self.unzip_exclude_mode = false;
            let argument = bsdunzip.argument.take();
            match u8::try_from(opt) {
                Ok(b'a') => self.a_opt = true,
                Ok(b'C') => self.upper_c_opt = true,
                Ok(b'c') => self.c_opt = true,
                Ok(b'd') => self.d_arg = argument,
                Ok(b'f') => self.f_opt = true,
                Ok(b'I' | b'O') => self.upper_o_arg = argument,
                Ok(b'j') => self.j_opt = true,
                Ok(b'L') => self.upper_l_opt = true,
                Ok(b'l') => {
                    if self.v_opt == 0 {
                        self.v_opt = 1;
                    }
                }
                Ok(b'n') => self.n_opt = true,
                Ok(b'o') => {
                    self.o_opt = true;
                    self.q_opt = true;
                }
                Ok(b'p') => self.p_opt = true,
                Ok(b'P') => self.upper_p_arg = argument,
                Ok(b'q') => self.q_opt = true,
                Ok(b't') => self.t_opt = true,
                Ok(b'u') => self.u_opt = true,
                Ok(b'v') => self.v_opt = 2,
                Ok(b'x') => {
                    Self::add_pattern(&mut self.exclude, argument.as_deref().unwrap_or_default());
                    self.unzip_exclude_mode = true;
                }
                Ok(b'y') => self.y_str = "  ",
                Ok(b'Z') => {
                    self.zipinfo_mode = true;
                    if matches!(argument.as_deref(), Some(b"1" | b"-1")) {
                        self.z1_opt = true;
                    }
                }
                _ if opt == OPTION_VERSION => self.version_opt = true,
                _ => usage(),
            }
        }
        argv.len() - bsdunzip.argv.len()
    }
}

/// Callback function for reading passphrase. Originally from cpio.c and
/// passphrase.c, libarchive.
fn passphrase_callback() -> Option<Vec<u8>> {
    const PPBUFF_SIZE: usize = 1024;
    let mut buf = vec![0; PPBUFF_SIZE];
    // lafe_readpassphrase exits on any error but EINTR, which it returns
    // as None.
    let p = lafe_readpassphrase("\nEnter password: ", &mut buf).map(<[u8]>::to_vec);
    explicit_bzero(&mut buf);
    p
}

fn pathname_is_insecure(pathname: &[u8]) -> bool {
    pathname.first() == Some(&b'/')
        || pathname == b".."
        || pathname.starts_with(b"../")
        || pathname.windows(4).any(|w| w == b"/../")
        || pathname.ends_with(b"/..")
}

fn usage() -> ! {
    let _ = io::stderr().write_all(
        b"Usage: unzip [-aCcfjLlnopqtuvyZ1] [{-O|-I} encoding] [-d dir] [-x pattern] \
[-P password] zipfile\n             [member ...]\n",
    );
    exit(1)
}

fn version() -> ! {
    let details = version_details();
    printf(format!("bsdunzip {BSDUNZIP_VERSION_STRING} - {details} \n"));
    exit(0)
}

fn main() {
    // Rust programs start with SIGPIPE ignored; C programs don't.
    sys::default_signal(libc::SIGPIPE);
    // Do not ignore SIGCHLD.
    sys::default_signal(libc::SIGCHLD);

    let argv: Vec<_> = std::env::args_os().map(OsString::into_vec).collect();
    lafe_setprogname(argv.first().map(|a| OsStr::from_bytes(a)), "bsdunzip");

    if !sys::setlocale_all() {
        lafe_warnc(0, "Failed to set default locale");
    }

    let mut unzip = Unzip {
        tty: io::stdout().is_terminal(),
        ..Unzip::default()
    };

    if std::env::var_os("UNZIP_DEBUG").is_some() {
        UNZIP_DEBUG.store(true, Ordering::Relaxed);
    }
    for (i, arg) in argv.iter().enumerate() {
        let sep = if i + 1 < argv.len() { b' ' } else { b'\n' };
        debug([arg.as_slice(), &[sep]].concat());
    }

    // Info-ZIP's unzip(1) expects certain options to come before the
    // zipfile name, and others to come after - though it does not enforce
    // this. For simplicity, we accept *all* options both before and after
    // the zipfile name.
    let mut nopts = unzip.getopts(&argv);

    if unzip.version_opt {
        version();
    }

    // When more of the zipinfo mode options are implemented, this will
    // need to change.
    if unzip.zipinfo_mode && !unzip.z1_opt {
        printf("Zipinfo mode needs additional options\n");
        let _ = io::stdout().flush();
        exit(1);
    }

    if argv.len() <= nopts {
        usage();
    }
    let zipfile = Some(argv[nopts].as_slice()).filter(|z| *z != b"-"); // "-" is STDIN
    nopts += 1;

    unzip.unzip_exclude_mode = false;

    while nopts < argv.len() && !argv[nopts].starts_with(b"-") {
        Unzip::add_pattern(&mut unzip.include, &argv[nopts]);
        nopts += 1;
    }

    nopts -= 1; // Fake argv[0].
    nopts += unzip.getopts(&argv[nopts..]);

    // For compatibility with Info-ZIP's unzip(1) we need to treat
    // non-option arguments following an -x after the zipfile as exclude
    // list members.
    if unzip.unzip_exclude_mode {
        while nopts < argv.len() && !argv[nopts].starts_with(b"-") {
            Unzip::add_pattern(&mut unzip.exclude, &argv[nopts]);
            nopts += 1;
        }
        nopts -= 1; // Fake argv[0].
        nopts += unzip.getopts(&argv[nopts..]);
    }

    // There may be residual arguments if we encountered --
    while nopts < argv.len() {
        Unzip::add_pattern(&mut unzip.include, &argv[nopts]);
        nopts += 1;
    }

    if u8::from(unzip.n_opt) + u8::from(unzip.o_opt) + u8::from(unzip.u_opt) > 1 {
        errorx("-n, -o and -u are contradictory");
    }

    unzip.unzip(zipfile);

    exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_pathnames() {
        for p in ["/a", "..", "../a", "a/../b", "a/b/..", "/"] {
            assert!(pathname_is_insecure(p.as_bytes()), "{p}");
        }
        for p in ["a", "a/b", "..a", "a..", "a/..b", "a/b../c", ""] {
            assert!(!pathname_is_insecure(p.as_bytes()), "{p}");
        }
    }

    #[test]
    fn binary_detection() {
        assert!(!check_binary(b"text\r\nmore\n"));
        assert!(check_binary(b"te\0xt"));
        // No white-listed byte at all: binary.
        assert!(check_binary(b""));
        assert!(check_binary(&[0x0b, 0x0c]));
        assert!(!check_binary(&[0x0b, b'a']));
    }

    #[test]
    fn pathdup_strips_slashes_and_folds_case() {
        let mut unzip = Unzip::default();
        assert_eq!(unzip.pathdup(None), None);
        assert_eq!(unzip.pathdup(Some(b"")), None);
        assert_eq!(unzip.pathdup(Some(b"/")), Some(Vec::new()));
        assert_eq!(unzip.pathdup(Some(b"A/B//")), Some(b"A/B".to_vec()));
        unzip.upper_l_opt = true;
        assert_eq!(unzip.pathdup(Some(b"A/B//")), Some(b"a/b".to_vec()));
    }

    #[test]
    fn pathcat_joins_with_a_slash() {
        assert_eq!(pathcat(None, b"a"), b"a");
        assert_eq!(pathcat(Some(b"d"), b"a"), b"d/a");
        assert_eq!(pathcat(Some(b""), b"a"), b"/a");
    }

    #[test]
    fn patterns_apply_include_then_exclude() {
        let mut unzip = Unzip::default();
        assert!(unzip.accept_pathname(b"a/b"));
        Unzip::add_pattern(&mut unzip.include, b"a/*");
        Unzip::add_pattern(&mut unzip.exclude, b"*.o");
        assert!(unzip.accept_pathname(b"a/b.c"));
        assert!(!unzip.accept_pathname(b"a/b.o"));
        assert!(!unzip.accept_pathname(b"c"));
        assert!(!unzip.accept_pathname(b"A/b.c"));
        unzip.upper_c_opt = true;
        assert!(unzip.accept_pathname(b"A/b.c"));
    }

    #[test]
    fn fgets_reads_at_most_n_minus_1_bytes() {
        let mut input: &[u8] = b"yes\nn\n";
        let mut buf = Vec::new();
        assert!(fgets(&mut input, &mut buf, 4));
        assert_eq!(buf, b"yes");
        assert!(fgets(&mut input, &mut buf, 4));
        assert_eq!(buf, b"\n");
        assert!(fgets(&mut input, &mut buf, 4));
        assert_eq!(buf, b"n\n");
        assert!(!fgets(&mut input, &mut buf, 4));
    }

    #[test]
    fn make_parent_creates_the_directories_above_a_path() {
        let root = std::env::temp_dir().join(format!("bsdunzip-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        // A file where a directory is wanted is replaced.
        fs::write(root.join("f"), b"x").unwrap();
        let mut path = [root.as_os_str().as_bytes(), b"/a/b/c/file"].concat();
        make_parent(&mut path);
        assert_eq!(path, [root.as_os_str().as_bytes(), b"/a/b/c/file"].concat());
        assert!(root.join("a/b/c").is_dir());
        let mut path = [root.as_os_str().as_bytes(), b"/f/g"].concat();
        make_parent(&mut path);
        assert!(root.join("f").is_dir());
        fs::remove_dir_all(&root).unwrap();
    }
}
