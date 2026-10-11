/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2003-2007 Tim Kientzle
 * All rights reserved.
 */

// Ported from tar/util.c.

use crate::subst::apply_substitution;
use crate::{Bsdtar, OPTFLAG_ABSOLUTE_PATHS};
use libarchive_fe::lafe_err::{lafe_errc, lafe_warnc};
use libarchive_fe::lafe_explicit_bzero::explicit_bzero;
use libarchive_fe::passphrase::lafe_readpassphrase;
use libarchive_fe::sys;
use libarchive_rust::{AE_IFBLK, AE_IFCHR, Archive, ArchiveEntry};
use std::ffi::{CStr, OsStr};
use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::exit;
use std::sync::{Mutex, OnceLock, PoisonError};

/// Standard output, buffered as C's stdout is: line by line on a terminal
/// (as Rust's is), else in blocks of its preferred I/O size until `flush`
/// or exit. What bsdtar prints there then interleaves with its messages on
/// standard error as C bsdtar's does when both go to one file.
pub struct Stdout;

/// What `Stdout` holds back, when standard output is not a terminal.
static PENDING: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// The size of `Stdout`'s blocks, or `None` on a terminal.
fn block_size() -> Option<usize> {
    static SIZE: OnceLock<Option<usize>> = OnceLock::new();
    *SIZE.get_or_init(|| {
        let out = io::stdout();
        if out.is_terminal() {
            return None;
        }
        let fd = out.as_fd().try_clone_to_owned().ok();
        let size = fd.and_then(|fd| File::from(fd).metadata().ok());
        // BUFSIZ, if fstat can't tell.
        Some(size.map_or(1024, |m| m.blksize()).max(1) as usize)
    })
}

impl Write for Stdout {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let Some(size) = block_size() else {
            return io::stdout().write(data);
        };
        let mut pending = PENDING.lock().unwrap_or_else(PoisonError::into_inner);
        pending.extend_from_slice(data);
        let full = pending.len() - pending.len() % size;
        if full > 0 {
            let mut out = io::stdout().lock();
            out.write_all(&pending[..full])?;
            out.flush()?;
            pending.drain(..full);
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut pending = PENDING.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out = io::stdout().lock();
        out.write_all(&pending)?;
        pending.clear();
        out.flush()
    }
}

/// Flushes `Stdout` at exit, as C's `exit` flushes stdio.
pub extern "C" fn flush_stdout() {
    let _ = Stdout.flush();
}

/// A file name given as bytes.
pub fn path(name: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(name))
}

/// The error message of `a`, as C's "%s" prints it.
pub fn error_string(a: &Archive) -> Vec<u8> {
    let msg = a.error_string();
    msg.as_deref().unwrap_or(b"(null)").to_vec()
}

/// Print a string, taking care of any non-printable characters. `None`
/// is a NULL string.
pub fn safe_fputs(s: Option<&[u8]>, f: &mut dyn Write) {
    let Some(s) = s else {
        let _ = f.write_all(b"(null)");
        return;
    };

    // Reset the shift state, and see if the encoding has one.
    let stateful = sys::mbtowc_reset();

    // Directly print as many ASCII characters as possible.
    let mut p = 0;
    if !stateful {
        p = s
            .iter()
            .position(|&c| !(sys::isprint(c) && c < 128 && c != b'\\'))
            .unwrap_or(s.len());
    }
    let mut out = s[..p].to_vec();

    // Write data, expanding unprintable characters.
    let mut try_wc = true;
    while p < s.len() {
        // Convert to wide char, test if the wide char is printable in the
        // current locale.
        let wc = if try_wc { sys::mbtowc(&s[p..]) } else { None };
        match wc {
            Some((wc, n)) => {
                let bytes = &s[p..p + n];
                if sys::iswprint(wc) && wc != libc::wchar_t::from(b'\\') {
                    // Printable, copy the bytes through.
                    out.extend_from_slice(bytes);
                } else {
                    // Not printable, format the bytes.
                    bytes.iter().for_each(|&c| bsdtar_expand_char(&mut out, c));
                }
                p += n;
            }
            None => {
                // After any conversion failure, don't bother trying to
                // convert the rest.
                bsdtar_expand_char(&mut out, s[p]);
                p += 1;
                try_wc = false;
            }
        }
    }
    let _ = f.write_all(&out);
}

/// Render an arbitrary sequence of bytes into printable ASCII characters.
fn bsdtar_expand_char(buff: &mut Vec<u8>, c: u8) {
    if sys::isprint(c) && c != b'\\' {
        buff.push(c);
        return;
    }
    buff.push(b'\\');
    match c {
        0x07 => buff.push(b'a'),
        0x08 => buff.push(b'b'),
        0x0c => buff.push(b'f'),
        b'\n' => buff.push(b'n'),
        b'\r' => buff.push(b'r'),
        b'\t' => buff.push(b't'),
        0x0b => buff.push(b'v'),
        b'\\' => buff.push(b'\\'),
        _ => buff.extend_from_slice(format!("{c:03o}").as_bytes()),
    }
}

/// Asks `prompt` " (y/N)? " on standard error and reads the answer from
/// it: to be resilient when stdin is a pipe, bsdtar prefers to read from
/// stderr.
pub fn yes(prompt: &[u8]) -> bool {
    let mut stderr = io::stderr();
    let _ = stderr.write_all(&[prompt, b" (y/N)? "].concat());
    let _ = stderr.flush();

    let mut buff = [0u8; 31];
    let Ok(l) = sys::read(stderr.as_fd(), &mut buff) else {
        let _ = stderr.write_all(b"Keyboard read failed\n");
        exit(1);
    };
    for &c in &buff[..l] {
        if c == 0 {
            break;
        }
        if sys::isspace(c) {
            continue;
        }
        return matches!(c, b'y' | b'Y');
    }
    false
}

/// The logic here for -C <dir> attempts to avoid chdir() as long as
/// possible. For example:
/// "-C /foo -C /bar file"          needs chdir("/bar") but not chdir("/foo")
/// "-C /foo -C bar file"           needs chdir("/foo/bar")
/// "-C /foo -C bar /file1"         does not need chdir()
/// "-C /foo -C bar /file1 file2"   needs chdir("/foo/bar") before file2
///
/// The only correct way to handle this is to record a "pending" chdir
/// request and combine multiple requests intelligently until we need to
/// process a non-absolute file. set_chdir() adds the new dir to the
/// pending list; do_chdir() actually executes any pending chdir.
///
/// This way, programs that build tar command lines don't have to worry
/// about -C with non-existent directories; such requests will only fail
/// if the directory must be accessed.
pub fn set_chdir(bsdtar: &mut Bsdtar, newdir: &[u8]) {
    if newdir.first() == Some(&b'/') {
        // The -C /foo -C /bar case; dump first one.
        bsdtar.pending_chdir = None;
    }
    bsdtar.pending_chdir = Some(match bsdtar.pending_chdir.take() {
        // Easy case: no previously-saved dir.
        None => newdir.to_vec(),
        // The -C /foo -C bar case; concatenate.
        Some(mut old_pending) => {
            if old_pending.last() == Some(&b'/') {
                old_pending.pop();
            }
            [&old_pending, b"/".as_slice(), newdir].concat()
        }
    });
}

pub fn do_chdir(bsdtar: &mut Bsdtar) {
    let Some(dir) = bsdtar.pending_chdir.take() else {
        return;
    };
    if std::env::set_current_dir(path(&dir)).is_err() {
        lafe_errc(
            1,
            0,
            [b"could not chdir to '", dir.as_slice(), b"'"].concat(),
        );
    }
}

/// Skips the first `elements` directory names; `None` if the path is too
/// short.
fn strip_components(mut p: &[u8], mut elements: i32) -> Option<&[u8]> {
    // Skip as many elements as necessary.
    while elements > 0 {
        match p.split_first() {
            Some((b'/', rest)) => {
                elements -= 1;
                p = rest;
            }
            Some((_, rest)) => p = rest,
            // Path is too short, skip it.
            None => return None,
        }
    }

    // Skip any / characters. This handles short paths that have
    // additional / termination. This also handles the case where the logic
    // above stops in the middle of a duplicate // sequence (which would
    // otherwise get converted to an absolute path).
    let p = &p[p.iter().position(|&c| c != b'/')?..];
    Some(p)
}

fn warn_strip_leading_char(bsdtar: &mut Bsdtar, c: u8) {
    if !bsdtar.warned_lead_slash {
        let msg = [
            b"Removing leading '".as_slice(),
            &[c],
            b"' from member names",
        ];
        lafe_warnc(0, msg.concat());
        bsdtar.warned_lead_slash = true;
    }
}

fn warn_strip_drive_letter(bsdtar: &mut Bsdtar) {
    if !bsdtar.warned_lead_slash {
        lafe_warnc(0, "Removing leading drive letter from member names");
        bsdtar.warned_lead_slash = true;
    }
}

/// Convert absolute path to non-absolute path by skipping leading absolute
/// path prefixes.
fn strip_absolute_path<'a>(bsdtar: &mut Bsdtar, mut p: &'a [u8]) -> &'a [u8] {
    let at = |p: &[u8], i: usize| p.get(i).copied().unwrap_or(0);
    let slash = |c: u8| c == b'/' || c == b'\\';

    // Remove leading "//./" or "//?/" or "//?/UNC/" (absolute path prefixes
    // used by Windows API).
    if slash(at(p, 0)) && slash(at(p, 1)) && matches!(at(p, 2), b'.' | b'?') && slash(at(p, 3)) {
        if at(p, 2) == b'?'
            && at(p, 4).eq_ignore_ascii_case(&b'U')
            && at(p, 5).eq_ignore_ascii_case(&b'N')
            && at(p, 6).eq_ignore_ascii_case(&b'C')
            && slash(at(p, 7))
        {
            p = &p[8..];
        } else {
            p = &p[4..];
        }
        warn_strip_drive_letter(bsdtar);
    }

    // Remove multiple leading slashes and Windows drive letters.
    loop {
        let rp = p;
        if at(p, 0).is_ascii_alphabetic() && at(p, 1) == b':' {
            p = &p[2..];
            warn_strip_drive_letter(bsdtar);
        }

        // Remove leading "/../", "/./", "//", etc.
        while slash(at(p, 0)) {
            if at(p, 1) == b'.' && at(p, 2) == b'.' && slash(at(p, 3)) {
                p = &p[3..]; // Remove "/..", leave "/" for next pass.
            } else if at(p, 1) == b'.' && slash(at(p, 2)) {
                p = &p[2..]; // Remove "/.", leave "/" for next pass.
            } else {
                p = &p[1..]; // Remove "/".
            }
            warn_strip_leading_char(bsdtar, at(rp, 0));
        }
        if rp.len() == p.len() {
            return p;
        }
    }
}

/// Handle --strip-components and any future path-rewriting options.
/// Returns non-zero if the pathname should not be extracted.
///
/// Note: The rewrites are applied uniformly to pathnames and hardlink names
/// but not to symlink bodies. This is deliberate: Symlink bodies are not
/// necessarily filenames. Even when they are, they need to be interpreted
/// relative to the directory containing them, so simple rewrites like this
/// are rarely appropriate.
pub fn edit_pathname(bsdtar: &mut Bsdtar, entry: &mut ArchiveEntry) -> i32 {
    let mut original_name = entry.pathname().unwrap_or_default().to_vec();
    let mut original_hardlinkname = entry.hardlink().map(<[u8]>::to_vec);

    // Apply user-specified substitution to pathname.
    match apply_substitution(bsdtar, &original_name, false, false) {
        Err(()) => {
            lafe_warnc(0, "Invalid substitution, skipping entry");
            return 1;
        }
        Ok(Some(subst_name)) => {
            entry.copy_pathname(Some(&subst_name));
            if subst_name.is_empty() {
                return -1;
            }
            original_name = subst_name;
        }
        Ok(None) => {}
    }

    // Apply user-specified substitution to hardlink target.
    if let Some(hardlinkname) = &original_hardlinkname {
        match apply_substitution(bsdtar, hardlinkname, false, true) {
            Err(()) => {
                lafe_warnc(0, "Invalid substitution, skipping entry");
                return 1;
            }
            Ok(Some(subst_name)) => entry.copy_hardlink(Some(&subst_name)),
            Ok(None) => {}
        }
        original_hardlinkname = entry.hardlink().map(<[u8]>::to_vec);
    }

    // Apply user-specified substitution to symlink body.
    if let Some(symlink) = entry.symlink().map(<[u8]>::to_vec) {
        match apply_substitution(bsdtar, &symlink, true, false) {
            Err(()) => {
                lafe_warnc(0, "Invalid substitution, skipping entry");
                return 1;
            }
            Ok(Some(subst_name)) => entry.copy_symlink(Some(&subst_name)),
            Ok(None) => {}
        }
    }

    let mut name = original_name.as_slice();
    let mut hardlinkname = original_hardlinkname.as_deref();

    // Strip leading dir names as per --strip-components option.
    if bsdtar.strip_components > 0 {
        let Some(stripped) = strip_components(name, bsdtar.strip_components) else {
            return 1;
        };
        name = stripped;

        if let Some(h) = hardlinkname {
            let Some(stripped) = strip_components(h, bsdtar.strip_components) else {
                return 1;
            };
            hardlinkname = Some(stripped);
        }
    }

    if bsdtar.flags & OPTFLAG_ABSOLUTE_PATHS == 0 {
        // By default, don't write or restore absolute pathnames.
        name = strip_absolute_path(bsdtar, name);
        if name.is_empty() {
            name = b".";
        }

        if let Some(h) = hardlinkname {
            let h = strip_absolute_path(bsdtar, h);
            if h.is_empty() {
                lafe_warnc(
                    0,
                    [
                        b"Skipping ".as_slice(),
                        &original_name,
                        b": hardlink target becomes empty after removing leading '/'",
                    ]
                    .concat(),
                );
                bsdtar.return_value = 1;
                return 1;
            }
            hardlinkname = Some(h);
        }
    } else {
        // Strip redundant leading '/' characters.
        while name.starts_with(b"//") {
            name = &name[1..];
        }
    }

    // Replace name in archive_entry.
    if name.as_ptr() != original_name.as_ptr() {
        entry.copy_pathname(Some(name));
    }
    if hardlinkname.map(<[u8]>::as_ptr) != original_hardlinkname.as_deref().map(<[u8]>::as_ptr) {
        entry.copy_hardlink(hardlinkname);
    }
    0
}

/// Apply --mtime and --clamp-mtime options.
pub fn edit_mtime(bsdtar: &Bsdtar, entry: &mut ArchiveEntry) {
    if !bsdtar.has_mtime {
        return;
    }
    if !bsdtar.clamp_mtime || entry.mtime() > bsdtar.mtime {
        entry.set_mtime(bsdtar.mtime, 0);
    }
}

const PPBUFF_SIZE: usize = 1024;

/// The passphrase callback: prompts on the terminal for the passphrase.
pub fn passphrase_callback() -> Option<Vec<u8>> {
    let mut ppbuff = [0u8; PPBUFF_SIZE];
    let p = lafe_readpassphrase("Enter passphrase:", &mut ppbuff).map(<[u8]>::to_vec);
    explicit_bzero(&mut ppbuff);
    p
}

/// Display information about the current file.
///
/// The format here roughly duplicates the output of 'ls -l'. This is based
/// on SUSv2, where 'tar tv' is documented as listing additional information
/// in an "unspecified format," and 'pax -l' is documented as using the same
/// format as 'ls -l'.
pub fn list_item_verbose(bsdtar: &mut Bsdtar, out: &mut dyn Write, entry: &mut ArchiveEntry) {
    static NOW: OnceLock<i64> = OnceLock::new();
    let now = *NOW.get_or_init(|| {
        let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        since.map_or(0, |d| d.as_secs() as i64)
    });
    let mut line = Vec::new();

    // We avoid collecting the entire list in memory at once by listing
    // things as we see them. However, that also means we can't just
    // pre-compute the field widths. Instead, we start with guesses and
    // just widen them as necessary. These numbers are completely arbitrary.
    if bsdtar.u_width == 0 {
        bsdtar.u_width = 6;
        bsdtar.gs_width = 13;
    }
    line.extend_from_slice(entry.strmode());
    line.extend_from_slice(format!(" {} ", entry.nlink()).as_bytes());

    // Use uname if it's present, else uid.
    let p = match entry.uname() {
        Some(p) if !p.is_empty() => p.to_vec(),
        _ => format!("{} ", entry.uid()).into_bytes(),
    };
    bsdtar.u_width = bsdtar.u_width.max(p.len());
    line.extend_from_slice(&p);
    line.resize(line.len() + bsdtar.u_width - p.len() + 1, b' ');

    // Use gname if it's present, else gid.
    let p = match entry.gname() {
        Some(p) if !p.is_empty() => p.to_vec(),
        _ => entry.gid().to_string().into_bytes(),
    };
    let w = p.len();
    line.extend_from_slice(&p);

    // Print device number or file size, right-aligned so as to make total
    // width of group and devnum/filesize fields be gs_width. If gs_width is
    // too small, grow it.
    let p = if matches!(entry.filetype(), AE_IFCHR | AE_IFBLK) {
        // C prints them as unsigned longs; dev_t is signed on macOS.
        #[allow(clippy::unnecessary_cast)]
        let (major, minor) = (entry.rdevmajor() as u64, entry.rdevminor() as u64);
        format!("{major},{minor}")
    } else {
        entry.size().to_string()
    };
    if w + p.len() >= bsdtar.gs_width {
        bsdtar.gs_width = w + p.len() + 1;
    }
    line.extend_from_slice(format!("{p:>width$}", width = bsdtar.gs_width - w).as_bytes());

    // Format the time using 'ls -l' conventions.
    let tim = entry.mtime();
    let age = tim as f64 - now as f64;
    const HALF_YEAR: f64 = 365.0 * 86400.0 / 2.0;
    let fmt: &CStr = match (!(-HALF_YEAR..=HALF_YEAR).contains(&age), bsdtar.day_first) {
        (true, true) => c"%e %b  %Y",
        (true, false) => c"%b %e  %Y",
        (false, true) => c"%e %b %H:%M",
        (false, false) => c"%b %e %H:%M",
    };
    let mut p = sys::strftime_local(fmt, tim);
    if p.is_empty() {
        p = b"-- -- ----".to_vec();
    }
    line.push(b' ');
    line.extend_from_slice(&p);
    line.push(b' ');
    let _ = out.write_all(&line);
    safe_fputs(entry.pathname(), out);

    // Extra information for links.
    if let Some(hardlink) = entry.hardlink() {
        // Hard link
        let _ = out.write_all(b" link to ");
        safe_fputs(Some(hardlink), out);
    } else if let Some(symlink) = entry.symlink() {
        // Symbolic link
        let _ = out.write_all(b" -> ");
        safe_fputs(Some(symlink), out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safe(s: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        safe_fputs(Some(s), &mut out);
        out
    }

    #[test]
    fn safe_fputs_escapes_what_is_not_printable() {
        assert_eq!(safe(b"plain/name.txt"), b"plain/name.txt");
        assert_eq!(safe(b"a\\b"), b"a\\\\b");
        assert_eq!(safe(b"tab\there\n"), b"tab\\there\\n");
        assert_eq!(safe(b"\x01\x7f"), b"\\001\\177");
        let mut out = Vec::new();
        safe_fputs(None, &mut out);
        assert_eq!(out, b"(null)");
    }

    #[test]
    fn strip_components_skips_whole_names() {
        assert_eq!(strip_components(b"a/b/c", 1), Some(b"b/c".as_slice()));
        assert_eq!(strip_components(b"a//b", 1), Some(b"b".as_slice()));
        assert_eq!(strip_components(b"a/b/", 2), None);
        assert_eq!(strip_components(b"a", 1), None);
    }
}
