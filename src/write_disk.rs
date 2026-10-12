/*-
 * Copyright (c) 2003-2010 Tim Kientzle
 * Copyright (c) 2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_write_disk_posix.c.

#[cfg(target_vendor = "apple")]
mod hfs;

use crate::archive::{ARCHIVE_ERRNO_MISC, ARCHIVE_FAILED, ARCHIVE_FATAL, ARCHIVE_OK, Base, state};
use crate::entry::Entry;
use crate::ffi::disk_sys::{DirError, Target, check_symlinks, create_dir, euid, fstat, umask};
use crate::util::Error;
use std::ffi::{c_int, c_ulong};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub const OWNER: c_int = 1;
pub const PERM: c_int = 2;
pub const TIME: c_int = 4;
pub const NO_OVERWRITE: c_int = 8;
pub const UNLINK: c_int = 16;
pub const ACL: c_int = 0x20;
pub const FFLAGS: c_int = 0x40;
pub const XATTR: c_int = 0x80;
pub const SECURE_SYMLINKS: c_int = 0x100;
pub const SECURE_NODOTDOT: c_int = 0x200;
pub const NO_AUTODIR: c_int = 0x400;
pub const NO_OVERWRITE_NEWER: c_int = 0x800;
pub const MAC_METADATA: c_int = 0x2000;
pub const SECURE_NOABSOLUTEPATHS: c_int = 0x10000;
pub const CLEAR_NOCHANGE_FFLAGS: c_int = 0x20000;
pub const SAFE_WRITES: c_int = 0x40000;

/// The file flags that forbid changes, which CLEAR_NOCHANGE_FFLAGS clears
/// from what is in the way, and those that would get in the way of the
/// rest of the extraction, which wait for close (upstream's
/// nochange_flags and critical_flags).
#[cfg(target_vendor = "apple")]
const NOCHANGE_FLAGS: c_ulong =
    (libc::SF_IMMUTABLE | libc::UF_IMMUTABLE | libc::SF_APPEND | libc::UF_APPEND) as c_ulong;
#[cfg(target_vendor = "apple")]
const CRITICAL_FLAGS: c_ulong = NOCHANGE_FLAGS;
#[cfg(target_os = "linux")]
const NOCHANGE_FLAGS: c_ulong =
    (crate::ffi::disk_sys::FS_APPEND_FL | crate::ffi::disk_sys::FS_IMMUTABLE_FL) as c_ulong;
#[cfg(target_os = "linux")]
const CRITICAL_FLAGS: c_ulong =
    NOCHANGE_FLAGS | crate::ffi::disk_sys::FS_JOURNAL_DATA_FL as c_ulong;
#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
const NOCHANGE_FLAGS: c_ulong = 0;
#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
const CRITICAL_FLAGS: c_ulong = 0;

/// Upstream's set_fflags_platform for an entry of type `filetype`. Linux
/// keeps flags only on regular files and directories.
fn set_fflags_platform(
    target: &Target,
    filetype: crate::entry::Mode,
    set: c_ulong,
    clear: c_ulong,
) -> std::io::Result<()> {
    if cfg!(target_os = "linux") && ![libc::S_IFREG, libc::S_IFDIR].contains(&filetype) {
        return Ok(());
    }
    target.flags(set as u32, clear as u32)
}

/// Upstream's clear_nochange_fflags, on what is in the way of `entry`.
fn clear_nochange_fflags(target: &Target, entry: &Entry) {
    let _ = set_fflags_platform(target, entry.filetype(), 0, NOCHANGE_FLAGS);
}

/// What close restores on an entry. It holds no descriptor: close finds
/// the entry again by name, and only if it is still the same file.
struct Fixup {
    name: Vec<u8>,
    entry: Entry,
    /// The ARCHIVE_EXTRACT_* bits to restore, and the mode to set, if any.
    todo: c_int,
    mode: Option<u32>,
    /// The device and inode finish_entry found.
    id: (u64, u64),
}

#[derive(Default)]
pub struct WriteDisk {
    pub options: c_int,
    pub bytes: i64,
    pub skip_file: Option<(i64, i64)>,
    pub user: crate::ffi::disk::IdLookup,
    pub group: crate::ffi::disk::IdLookup,
    file: Option<File>,
    current: Option<(PathBuf, Entry, Target, c_int)>,
    fixups: Vec<Fixup>,
    start_time: i64,
    offset: u64,
    max_offset: u64,
    file_offset: Option<u64>,
    file_len: Option<u64>,
    limit: Option<u64>,
    skipped: bool,
    atomic: Option<Target>,
    permissions_created: bool,
    new_directory: bool,
    directory_mode: bool,
    /// The umask, read once per entry as upstream does.
    umask: u32,
}

/// Upstream's cleanup_pathname_fsobj: drops empty and `.` elements and a
/// trailing `/`, keeping `..`, and refuses what the SECURE flags forbid.
fn cleanup_pathname(path: &[u8], options: c_int) -> Result<Vec<u8>, &'static str> {
    if path.is_empty() {
        return Err("Invalid empty pathname");
    }
    let absolute = path.starts_with(b"/");
    if absolute && options & SECURE_NOABSOLUTEPATHS != 0 {
        return Err("Path is absolute");
    }
    let mut clean = Vec::with_capacity(path.len());
    for element in path.split(|&b| b == b'/') {
        if element.is_empty() || element == b"." {
            continue;
        }
        if element == b".." && options & SECURE_NODOTDOT != 0 {
            return Err("Path contains '..'");
        }
        if absolute || !clean.is_empty() {
            clean.push(b'/');
        }
        clean.extend_from_slice(element);
    }
    if clean.is_empty() {
        clean.push(if absolute { b'/' } else { b'.' });
    }
    Ok(clean)
}

fn failure(a: &Base, err: std::io::Error, action: &str, path: &Path) -> c_int {
    a.raise(Error::new(
        ARCHIVE_FAILED,
        err.raw_os_error().unwrap_or(libc::EIO),
        [action.as_bytes(), b" '", path.as_os_str().as_bytes(), b"'"].concat(),
    ))
}

impl WriteDisk {
    pub fn header(&mut self, a: &Base, entry: &mut Entry) -> c_int {
        if self.finish_entry(a) == ARCHIVE_FATAL {
            return ARCHIVE_FATAL;
        }
        a.clear_error();
        a.state.set(state::HEADER);
        self.umask = umask();
        if self.start_time == 0 {
            self.start_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
        }
        self.skipped = false;
        self.permissions_created = false;
        self.new_directory = false;
        let caller = entry;
        let mut entry = caller.clone_entry();
        let raw = entry
            .pathname()
            .map_or(Vec::new(), |p| p.to_bytes().to_vec());
        let name = match cleanup_pathname(&raw, self.options) {
            Ok(name) => name,
            Err(msg) => return a.raise(Error::new(ARCHIVE_FAILED, ARCHIVE_ERRNO_MISC, msg)),
        };
        let path = PathBuf::from(std::ffi::OsStr::from_bytes(&name));
        // Upstream compares the cleaned-up pathname with the link as given.
        if entry.hardlink().is_some_and(|link| link.to_bytes() == name) {
            let msg = [b"Skipping hardlink pointing to itself: ", name.as_slice()];
            return a.warn(ARCHIVE_ERRNO_MISC, msg.concat()).code();
        }
        let mut options = self.options;
        // On Apple, Mac metadata holds the ACLs and extended attributes too:
        // when it is restored, the entry's own are not.
        if cfg!(target_vendor = "apple")
            && options & MAC_METADATA != 0
            && entry.mac_metadata().is_some_and(|m| !m.is_empty())
        {
            options &= !(ACL | XATTR);
        }
        let secure = options & SECURE_SYMLINKS != 0;
        if secure
            && let Err((code, errno, msg)) =
                check_symlinks(&name, options & UNLINK != 0, secure, false)
        {
            return a.raise(Error::new(code, errno, [msg.as_bytes(), &name].concat()));
        }
        self.offset = 0;
        self.max_offset = 0;
        self.limit = (entry.size_is_set() != 0).then(|| entry.size().max(0) as u64);
        if entry.hardlink_is_set() != 0 && entry.size_is_set() == 0 {
            self.limit = Some(0);
        }
        let restored = self.restore_entry(a, &path, &mut entry);
        // Tell the client not to write to what isn't open: dirs, links and so on.
        if self.file.is_none() {
            caller.set_size(0);
            self.limit = Some(0);
        }
        let target = match restored {
            Ok(target) => target,
            Err(code) => return code,
        };
        self.file_offset = self.file.as_ref().map(|_| 0);
        self.file_len = self.file.as_ref().map(|_| 0);
        self.current = Some((path, entry, target, options));
        a.state.set(state::DATA);
        a.file_count.set(a.file_count.get() + 1);
        ARCHIVE_OK
    }

    /// Upstream's restore_entry: creates the entry, recovering from what is
    /// in the way, and returns the target, or the status to return.
    fn restore_entry(&mut self, a: &Base, path: &Path, entry: &mut Entry) -> Result<Target, c_int> {
        let options = self.options;
        let secure = options & SECURE_SYMLINKS != 0;
        let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
        let failed = |errno, msg: &str| Err(a.raise(Error::new(ARCHIVE_FAILED, errno, msg)));
        let directory = entry.filetype() == libc::S_IFDIR;
        if options & UNLINK != 0 && !directory {
            // Unlink whatever is there, or failing that rmdir it.
            let removed = Target::prepare(path, secure).and_then(|t| {
                if options & CLEAR_NOCHANGE_FFLAGS != 0 {
                    clear_nochange_fflags(&t, entry);
                }
                t.remove(false).or_else(|e| match e.raw_os_error() {
                    Some(libc::ENOENT) => Err(e),
                    _ => t.remove(true),
                })
            });
            if let Err(e) = removed
                && e.raw_os_error() != Some(libc::ENOENT)
            {
                return failed(errno(e), "Could not unlink");
            }
        }
        let (mut target, mut en) = self.create(a, path, entry);
        if (en == libc::ENOTDIR || en == libc::ENOENT) && options & NO_AUTODIR == 0 {
            // A failure is reported, but the entry is still tried.
            if let Some(parent) = path.parent()
                && let Err((dir, e)) =
                    create_dir(parent, secure, options & NO_OVERWRITE != 0, self.umask)
            {
                let dir = dir.as_os_str().as_bytes();
                let (errno, msg, tail) = match e {
                    DirError::Exists => (libc::EEXIST, "Can't create directory '", "'"),
                    DirError::Conflict(e) => (
                        errno(e),
                        "Can't create directory '",
                        "': Conflicting file cannot be removed",
                    ),
                    DirError::Test(e) => (errno(e), "Can't test directory '", "'"),
                    DirError::Mkdir(e) => (errno(e), "Failed to create dir '", "'"),
                };
                let msg = [msg.as_bytes(), dir, tail.as_bytes()].concat();
                a.raise(Error::new(ARCHIVE_FAILED, errno, msg));
            }
            (target, en) = self.create(a, path, entry);
        }
        if en == libc::ENOENT
            && let Some(link) = entry.hardlink()
        {
            let msg = [b"Hard-link target '", link.to_bytes(), b"' does not exist"].concat();
            return Err(a.raise(Error::new(ARCHIVE_FAILED, en, msg)));
        }
        if let Some(existing) = target.take_if(|_| en == libc::EEXIST) {
            if options & NO_OVERWRITE != 0 {
                self.skipped = true;
                return Ok(existing);
            }
            // Something is in the way. The SECURE_SYMLINKS check already
            // removed a symlink, so a directory follows one.
            let followed = if directory {
                existing.stat_follow().ok()
            } else {
                None
            };
            let st = match followed.filter(|st| st.st_mode & libc::S_IFMT == libc::S_IFDIR) {
                Some(st) => st,
                None => match existing.stat() {
                    Ok(st) => st,
                    Err(e) => return failed(errno(e), "Can't stat existing object"),
                },
            };
            let in_the_way = st.st_mode & libc::S_IFMT;
            if options & NO_OVERWRITE_NEWER != 0
                && in_the_way != libc::S_IFDIR
                && (st.st_mtime, st.st_mtime_nsec) >= (entry.mtime(), entry.mtime_nsec())
            {
                self.skipped = true;
                return Ok(existing);
            }
            if self.skip_file == Some((st.st_dev as i64, st.st_ino as i64)) {
                return failed(libc::EIO, "Refusing to overwrite archive");
            }
            if in_the_way != libc::S_IFDIR {
                if options & CLEAR_NOCHANGE_FFLAGS != 0 {
                    clear_nochange_fflags(&existing, entry);
                }
                if options & SAFE_WRITES != 0 && entry.filetype() == libc::S_IFREG {
                    // Extract to a temporary file, renamed over it at the end.
                    let (tmp, file) = match existing.atomic_file(self.creation_mode(entry)) {
                        Ok(created) => created,
                        Err(e) => return failed(errno(e), "Can't create temporary file"),
                    };
                    self.atomic = Some(existing);
                    self.file = Some(file);
                    return Ok(tmp);
                }
                if let Err(e) = existing.remove(false) {
                    return failed(errno(e), "Can't unlink already-existing object");
                }
                (target, en) = self.create(a, path, entry);
            } else if !directory {
                if options & CLEAR_NOCHANGE_FFLAGS != 0 {
                    clear_nochange_fflags(&existing, entry);
                }
                if let Err(e) = existing.remove(true) {
                    return failed(
                        errno(e),
                        "Can't replace existing directory with non-directory",
                    );
                }
                (target, en) = self.create(a, path, entry);
            } else {
                // A directory in the way of a directory is kept as it is. If it
                // is a symlink to one, the entry's metadata goes on the link
                // itself, and close skips it: it isn't a directory.
                return Ok(existing);
            }
        }
        match target {
            Some(target) if en == 0 => Ok(target),
            _ => {
                if a.error_string().is_none() {
                    let e = std::io::Error::from_raw_os_error(en);
                    return Err(failure(a, e, "Can't create", path));
                }
                Err(ARCHIVE_FAILED)
            }
        }
    }

    /// The mode upstream creates a file with: the final permissions with
    /// the umask applied, and no set-id bits.
    fn creation_mode(&self, entry: &Entry) -> u32 {
        let mode = entry.mode() as u32 & 0o777 & !self.umask;
        // Writable, so that a user other than root can set its attributes.
        if euid() != 0 && self.options & XATTR != 0 {
            mode | 0o200
        } else {
            mode
        }
    }

    /// Upstream's create_filesystem_object: one attempt to create the entry.
    /// Returns its target, if its parent could be opened, and the errno of
    /// the failure, or 0.
    fn create(&mut self, a: &Base, path: &Path, entry: &mut Entry) -> (Option<Target>, c_int) {
        let options = self.options;
        let secure = options & SECURE_SYMLINKS != 0;
        let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
        let hardlink = entry.hardlink().map(|p| p.to_bytes().to_vec());
        if let Some(link) = &hardlink {
            // A refused target is reported as EPERM, keeping its message.
            let check = cleanup_pathname(link, options)
                .map_err(|msg| (ARCHIVE_ERRNO_MISC, msg.as_bytes().to_vec()))
                .and_then(|clean| {
                    check_symlinks(&clean, options & UNLINK != 0, secure, true)
                        .map_err(|(_, errno, msg)| (errno, [msg.as_bytes(), &clean].concat()))
                });
            if let Err((errno, msg)) = check {
                a.raise(Error::new(ARCHIVE_FAILED, errno, msg));
                return (None, libc::EPERM);
            }
        }
        let target = match Target::prepare(path, secure) {
            Ok(target) => target,
            Err(e) => return (None, errno(e)),
        };
        let created = if let Some(link) = hardlink {
            if options & SAFE_WRITES != 0 {
                let _ = target.remove(false);
            }
            let source = Path::new(std::ffi::OsStr::from_bytes(&link));
            Target::prepare(source, secure)
                .and_then(|source| target.hardlink(&source))
                .and_then(|()| {
                    // A hardlink that carries data is written like a file.
                    if self.limit == Some(0)
                        || target.stat()?.st_mode & libc::S_IFMT != libc::S_IFREG
                    {
                        return Ok(());
                    }
                    self.file = Some(target.open(entry.mode() as u32 & 0o777, false)?);
                    Ok(())
                })
        } else if let Some(link) = entry.symlink() {
            if options & SAFE_WRITES != 0 {
                let _ = target.remove(false);
            }
            self.limit = Some(0);
            target.symlink(Path::new(std::ffi::OsStr::from_bytes(link.to_bytes())))
        } else {
            match entry.filetype() {
                libc::S_IFDIR => {
                    self.limit = Some(0);
                    // Upstream's limits keep a new directory usable and
                    // private to its group until close sets its mode.
                    let final_mode = final_mode(entry, options, self.umask);
                    let mode = ((final_mode & 0o777 & !self.umask) | 0o700) & 0o775;
                    let created = target.mkdir(mode);
                    self.new_directory = created.is_ok();
                    self.directory_mode = mode != final_mode || options & PERM != 0;
                    created
                }
                // Created without set-id bits; the mode is set afterwards
                // unless it is already final. On Apple, creation applies the
                // umask without Linux's default-ACL substitution.
                kind => {
                    let mode = self.creation_mode(entry);
                    self.permissions_created = cfg!(target_vendor = "apple")
                        && mode == final_mode(entry, options, self.umask);
                    match kind {
                        libc::S_IFCHR | libc::S_IFBLK | libc::S_IFIFO => {
                            target.special(kind as u32 | mode, entry.rdev() as u64)
                        }
                        // POSIX requires any other type to be created as a
                        // regular file.
                        _ => target.open(mode, true).map(|file| self.file = Some(file)),
                    }
                }
            }
        };
        match created {
            Ok(()) => (Some(target), 0),
            Err(e) => (Some(target), errno(e)),
        }
    }

    pub fn data(&mut self, a: &Base, data: &[u8]) -> isize {
        if a.check_magic(
            crate::archive::WRITE_DISK_MAGIC,
            state::DATA,
            "archive_write_data",
        ) < ARCHIVE_OK
        {
            return ARCHIVE_FATAL as isize;
        }
        let Some(file) = self.file.as_mut().filter(|_| self.limit != Some(0)) else {
            if data.is_empty() {
                return 0;
            }
            return a
                .warn(libc::EIO, "Attempt to write to an empty file")
                .code() as isize;
        };
        let len = self.limit.map_or(data.len(), |n| {
            data.len().min(n.saturating_sub(self.offset) as usize)
        });
        let sparse = self.options & 0x1000 != 0;
        let chunk_size = if sparse { 4096 } else { len.max(1) };
        let result = data[..len].chunks(chunk_size).try_for_each(|chunk| {
            if sparse && chunk.iter().all(|&b| b == 0) {
                self.file_offset = Some(file.seek(SeekFrom::Current(chunk.len() as i64))?);
            } else {
                file.write_all(chunk)?;
                self.file_offset = self
                    .file_offset
                    .and_then(|n| n.checked_add(chunk.len() as u64));
                self.file_len = self
                    .file_len
                    .zip(self.file_offset)
                    .map(|(len, end)| len.max(end));
            }
            Ok::<_, std::io::Error>(())
        });
        match result {
            Ok(()) => {
                self.offset += len as u64;
                self.max_offset = self.max_offset.max(self.offset);
                self.bytes = self.bytes.saturating_add(len as i64);
                len as isize
            }
            Err(e) => {
                // write_all can fail after a partial write, leaving both unknown.
                self.file_offset = None;
                self.file_len = None;
                a.warn(e.raw_os_error().unwrap_or(libc::EIO), "Write failed")
                    .code() as isize
            }
        }
    }

    pub fn data_block(&mut self, a: &Base, data: &[u8], offset: i64) -> c_int {
        let Ok(offset) = u64::try_from(offset) else {
            return a.raise(Error::new(ARCHIVE_FAILED, libc::EINVAL, "Invalid offset"));
        };
        if let Some(file) = &mut self.file
            && self.file_offset != Some(offset)
        {
            match file.seek(SeekFrom::Start(offset)) {
                Ok(position) => self.file_offset = Some(position),
                Err(e) => {
                    self.file_offset = None;
                    return a.raise(Error::new(
                        ARCHIVE_FAILED,
                        e.raw_os_error().unwrap_or(libc::EIO),
                        "Seek failed",
                    ));
                }
            }
        }
        self.offset = offset;
        match self.data(a, data) {
            result if result < 0 => result as c_int,
            result if (result as usize) < data.len() => {
                let size = self.limit.unwrap_or_default();
                let msg = format!("Too much data: Truncating file at {size} bytes");
                a.warn(libc::EOVERFLOW, msg).code()
            }
            _ => ARCHIVE_OK,
        }
    }

    pub fn finish_entry(&mut self, a: &Base) -> c_int {
        let Some((path, entry, mut target, options)) = self.current.take() else {
            return ARCHIVE_OK;
        };
        a.clear_error();
        a.state.set(state::HEADER);
        let permissions_created = std::mem::take(&mut self.permissions_created);
        if !self.skipped {
            let mut file = self.file.take();
            let length = self.limit.unwrap_or(self.max_offset);
            if let Some(file) = &mut file
                && self.file_len != Some(length)
                && let Err(e) = file.set_len(length)
            {
                let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
                if length == 0 {
                    return a.raise(Error::new(
                        ARCHIVE_FAILED,
                        errno(e),
                        "File size could not be restored",
                    ));
                }
                // Not all platforms extend files with ftruncate; then upstream
                // writes the last byte.
                if !file.metadata().is_ok_and(|m| m.len() >= length) {
                    let failed = match file.seek(SeekFrom::Start(length - 1)) {
                        Err(e) => Some((e, "Seek failed")),
                        Ok(_) => file
                            .write_all(&[0])
                            .err()
                            .map(|e| (e, "Write to restore size failed")),
                    };
                    if let Some((e, msg)) = failed {
                        // The entry stays current, as upstream's does, so the next
                        // call restores its metadata.
                        self.current = Some((path, entry, target, options));
                        self.permissions_created = permissions_created;
                        a.state.set(state::DATA);
                        return a.raise(Error::fatal(errno(e), msg));
                    }
                }
            }
            if let Some(destination) = self.atomic.take() {
                if let Err(e) = target.rename_to(&destination) {
                    let _ = target.remove(false);
                    let errno = e.raw_os_error().unwrap_or(libc::EIO);
                    let msg = "Failed to rename temporary file";
                    return a.raise(Error::new(ARCHIVE_FAILED, errno, msg));
                }
                target = destination;
            }
            if let Some(file) = file {
                target.retain_file(file);
            }
            let mut ret = ARCHIVE_OK;
            // An AppleDouble file "._name" with data is merged into "name"
            // and removed.
            #[cfg(target_vendor = "apple")]
            if entry.size_is_set() != 0
                && entry.size() > 0
                && let Some(name) = path
                    .file_name()
                    .map(std::ffi::OsStr::as_bytes)
                    .filter(|name| name.starts_with(b"._"))
                && let Ok(dest) = target.sibling(&name[2..])
                && dest.stat().is_ok_and(|st| {
                    [libc::S_IFREG, libc::S_IFDIR, libc::S_IFLNK]
                        .contains(&(st.st_mode & libc::S_IFMT))
                })
            {
                use std::io::Read;
                let merged = target
                    .read_file()
                    .map_err(|e| (e, "Failed to open a restoring file"))
                    .and_then(|mut file| {
                        let mut magic = [0; 8];
                        match file.read_exact(&mut magic) {
                            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                                return Ok(false);
                            }
                            Err(e) => return Err((e, "Failed to read a restoring file")),
                            Ok(()) if magic != [0, 5, 22, 7, 0, 2, 0, 0] => return Ok(false),
                            Ok(()) => {}
                        }
                        if file.metadata().map_or(0, |m| m.len()) > 16 * 1024 * 1024 {
                            let e = std::io::Error::from_raw_os_error(libc::ENOMEM);
                            return Err((e, "AppleDouble metadata is too large"));
                        }
                        let mut bytes = Vec::from(magic);
                        file.read_to_end(&mut bytes)
                            .and_then(|_| dest.unpack_mac_metadata(&bytes))
                            .map_err(|e| (e, "Failed to restore metadata"))?;
                        let _ = target.remove(false);
                        Ok(true)
                    });
                match merged {
                    Ok(true) => {
                        a.state.set(state::HEADER);
                        return ARCHIVE_OK;
                    }
                    Ok(false) => {}
                    Err((e, msg)) => {
                        ret = a.warn(e.raw_os_error().unwrap_or(libc::EIO), msg).code();
                    }
                }
            }
            // A hardlink without data says nothing about the file's metadata.
            let link_only =
                entry.hardlink_is_set() != 0 && (entry.size_is_set() == 0 || entry.size() <= 0);
            let todo = if link_only { 0 } else { options };
            // Flags that forbid changes wait for close, after any hardlinks.
            let mut deferred = if entry.fflags().0 & CRITICAL_FLAGS != 0 {
                FFLAGS
            } else {
                0
            };
            let directory = entry.filetype() == libc::S_IFDIR;
            let mode = if !directory {
                !permissions_created
            } else if self.new_directory {
                // Its times wait too, and its mode if mkdir couldn't set it.
                deferred |= TIME | ACL | MAC_METADATA;
                std::mem::take(&mut self.directory_mode)
            } else {
                // One already there keeps its mode, unless PERM changes it.
                deferred |= ACL | MAC_METADATA;
                options & PERM != 0 && target.stat().is_ok_and(|st| st.st_mode != entry.mode())
            };
            let name = path.as_os_str().as_bytes();
            let mode = mode && !link_only;
            let now = todo & !deferred;
            ret = ret.min(self.restore(a, name, &entry, &mut target, now, mode && !directory));
            if (todo & deferred != 0 || (directory && mode))
                && let Ok(st) = target.stat()
            {
                self.fixups.push(Fixup {
                    name: name.to_vec(),
                    todo: todo & (deferred | SECURE_SYMLINKS),
                    mode: (directory && mode).then(|| final_mode(&entry, options, self.umask)),
                    entry,
                    id: (st.st_dev as u64, st.st_ino),
                });
            }
            a.state.set(state::HEADER);
            return ret;
        }
        a.state.set(state::HEADER);
        ARCHIVE_OK
    }

    /// Upstream's metadata restoration in finish_entry, in its order.
    fn restore(
        &mut self,
        a: &Base,
        name: &[u8],
        entry: &Entry,
        target: &mut Target,
        todo: c_int,
        mode: bool,
    ) -> c_int {
        if entry.filetype() == libc::S_IFDIR
            && let Ok(file) = target.directory_file()
        {
            target.retain_file(file);
        }
        let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
        let mut ret = ARCHIVE_OK;
        let warn =
            |ret: &mut c_int, errno, msg: Vec<u8>| *ret = (*ret).min(a.warn(errno, msg).code());
        // Upstream compresses as the data is written, before any metadata.
        #[cfg(target_vendor = "apple")]
        if entry.filetype() == libc::S_IFREG
            && todo & 0x4000 == 0
            && (todo & 0x8000 != 0
                || entry.fflags().0 & libc::UF_COMPRESSED as std::ffi::c_ulong != 0)
            && let Err(e) = hfs::compress(target, entry.size().max(0) as u64)
        {
            warn(&mut ret, errno(e), b"Failed to compress file".to_vec());
        }
        let euid = euid();
        let mut final_mode = final_mode(entry, todo, self.umask);
        let (uid, gid) = if todo & OWNER != 0 || (mode && final_mode & 0o6000 != 0) {
            let mut names = entry.clone_entry();
            let uid = self.user.lookup(names.uname(), entry.uid(), false);
            (uid, self.group.lookup(names.gname(), entry.gid(), true))
        } else {
            (euid.into(), 0)
        };
        let mut owned = false;
        if todo & OWNER != 0 {
            // Elsewhere than on Linux, only root may give a file away.
            if cfg!(not(target_os = "linux")) && euid != 0 && i64::from(euid) != uid {
                warn(
                    &mut ret,
                    libc::EPERM,
                    format!("Can't set UID={uid}").into_bytes(),
                );
            } else if let Err(e) = target.owner(uid, gid) {
                let msg = format!("Can't set user={uid}/group={gid} for ");
                warn(&mut ret, errno(e), [msg.as_bytes(), name].concat());
            } else {
                owned = true;
            }
        }
        // Not being root, set attributes before the mode can forbid it.
        if euid != 0 && todo & XATTR != 0 {
            ret = ret.min(set_xattrs(a, entry, target));
        }
        if mode && entry.filetype() != libc::S_IFDIR {
            let mut chmod = true;
            // The set-id bits stay only on a file with the archive's owner.
            if !owned && final_mode & 0o2000 != 0 {
                match target.stat() {
                    Err(e) => {
                        warn(&mut ret, errno(e), b"Couldn't stat file".to_vec());
                        chmod = false;
                    }
                    Ok(st) => {
                        if i64::from(st.st_gid) != gid {
                            final_mode &= !0o2000;
                            if todo & OWNER != 0 {
                                warn(
                                    &mut ret,
                                    ARCHIVE_ERRNO_MISC,
                                    b"Can't restore SGID bit".to_vec(),
                                );
                            }
                        }
                        if i64::from(st.st_uid) != uid && final_mode & 0o4000 != 0 {
                            final_mode &= !0o4000;
                            if todo & OWNER != 0 {
                                warn(
                                    &mut ret,
                                    ARCHIVE_ERRNO_MISC,
                                    b"Can't restore SUID bit".to_vec(),
                                );
                            }
                        }
                    }
                }
            } else if !owned && final_mode & 0o4000 != 0 && i64::from(euid) != uid {
                final_mode &= !0o4000;
                if todo & OWNER != 0 {
                    warn(
                        &mut ret,
                        ARCHIVE_ERRNO_MISC,
                        b"Can't make file SUID".to_vec(),
                    );
                }
            }
            // A symlink's mode is set with lchmod, whose lack is no error.
            if chmod
                && let Err(e) = target.chmod(final_mode)
                && !(entry.filetype() == libc::S_IFLNK
                    && e.raw_os_error().is_some_and(|errno| {
                        [libc::ENOTSUP, libc::ENOSYS, libc::EOPNOTSUPP].contains(&errno)
                    }))
            {
                warn(
                    &mut ret,
                    errno(e),
                    format!("Can't set permissions to 0{final_mode:o}").into_bytes(),
                );
            }
        }
        // Security attributes go last: other changes remove them.
        if euid == 0 && todo & XATTR != 0 {
            ret = ret.min(set_xattrs(a, entry, target));
        }
        if todo & FFLAGS != 0 {
            let (set, clear) = entry.fflags();
            if let Err(e) = set_fflags_platform(target, entry.filetype(), set, clear) {
                warn(&mut ret, errno(e), b"Failed to set file flags".to_vec());
            }
        }
        if todo & TIME != 0 {
            let start = (self.start_time, 0);
            let time = |set, sec, nsec| if set != 0 { (sec, nsec) } else { start };
            let atime = time(entry.atime_is_set(), entry.atime(), entry.atime_nsec());
            let mtime = time(entry.mtime_is_set(), entry.mtime(), entry.mtime_nsec());
            let birthtime = time(
                entry.birthtime_is_set(),
                entry.birthtime(),
                entry.birthtime_nsec(),
            );
            let birthtime_set = cfg!(target_vendor = "apple") && entry.birthtime_is_set() != 0;
            if (entry.atime_is_set() != 0 || birthtime_set || entry.mtime_is_set() != 0)
                && let Err(e) = set_times(target, atime, birthtime, mtime)
            {
                warn(&mut ret, errno(e), b"Can't restore time".to_vec());
            }
        }
        // Mac metadata includes ACLs, which go after the times they can forbid.
        if todo & MAC_METADATA != 0
            && let Some(metadata) = entry.mac_metadata().filter(|m| !m.is_empty())
            && let Err(e) = target.unpack_mac_metadata(metadata)
        {
            warn(&mut ret, errno(e), b"Failed to restore metadata".to_vec());
        }
        #[cfg(target_vendor = "apple")]
        if todo & ACL != 0 {
            ret = ret.min(self.set_acls(a, entry, target));
        }
        ret
    }

    /// Upstream's archive_write_disk_set_acls on Darwin.
    #[cfg(target_vendor = "apple")]
    fn set_acls(&mut self, a: &Base, entry: &Entry, target: &Target) -> c_int {
        let set = target.metadata_file().and_then(|file| {
            crate::ffi::disk_acl::write(&file, entry, &mut self.user, &mut self.group)
        });
        match set {
            // The filesystem doesn't support ACLs.
            Err(e) if e.raw_os_error() != Some(libc::EOPNOTSUPP) => {
                let msg = if target.is_open() {
                    "Failed to set acl on fd: nfs4"
                } else {
                    "Failed to set acl: nfs4"
                };
                a.warn(e.raw_os_error().unwrap_or(libc::EIO), msg).code()
            }
            _ => ARCHIVE_OK,
        }
    }

    pub fn close(&mut self, a: &Base) -> c_int {
        if a.state.get() == state::FATAL {
            return ARCHIVE_FATAL;
        }
        let ret = self.finish_entry(a);
        // Deepest first, so a directory's mode can't lock out its contents.
        let mut fixups = std::mem::take(&mut self.fixups);
        fixups.sort_by(|x, y| y.name.cmp(&x.name));
        // Upstream fixes up only what still has the entry's type, and its
        // failures leave a message but don't change the result. The parents
        // are walked again as when the entry was made (without following
        // symlinks under SECURE_SYMLINKS), the entry itself is never
        // followed, and anything but the file finish_entry saw is skipped.
        for Fixup {
            name,
            entry,
            todo,
            mode,
            id,
        } in fixups
        {
            let path = Path::new(std::ffi::OsStr::from_bytes(&name));
            let Ok(mut target) = Target::prepare(path, todo & SECURE_SYMLINKS != 0) else {
                continue;
            };
            let same = |st: libc::stat| {
                (st.st_dev as u64, st.st_ino) == id && st.st_mode & libc::S_IFMT == entry.filetype()
            };
            // A symlink's own flags are set through the link, as by lchflags.
            if entry.filetype() == libc::S_IFLNK {
                if !target.stat().is_ok_and(same) {
                    continue;
                }
            } else {
                let file = target.fixup_file(entry.filetype() == libc::S_IFDIR);
                let Some(file) = file.ok().filter(|file| fstat(file).is_ok_and(same)) else {
                    continue;
                };
                target.retain_file(file);
            }
            if todo & TIME != 0 && (entry.mtime_is_set() != 0 || entry.atime_is_set() != 0) {
                let start = (self.start_time, 0);
                let time = |set, sec, nsec| if set != 0 { (sec, nsec) } else { start };
                let atime = time(entry.atime_is_set(), entry.atime(), entry.atime_nsec());
                let mtime = time(entry.mtime_is_set(), entry.mtime(), entry.mtime_nsec());
                let birthtime = match entry.birthtime_is_set() {
                    0 => mtime,
                    _ => (entry.birthtime(), entry.birthtime_nsec()),
                };
                if let Err(e) = set_times(&target, atime, birthtime, mtime) {
                    let _ = a.warn(e.raw_os_error().unwrap_or(libc::EIO), "Can't restore time");
                }
            }
            if let Some(mode) = mode {
                let _ = target.chmod(mode);
            }
            #[cfg(target_vendor = "apple")]
            if todo & ACL != 0 {
                let _ = self.set_acls(a, &entry, &target);
            }
            if todo & FFLAGS != 0
                && let Err(e) = set_fflags_platform(&target, entry.filetype(), entry.fflags().0, 0)
            {
                let _ = a.warn(
                    e.raw_os_error().unwrap_or(libc::EIO),
                    "Failed to set file flags",
                );
            }
            if todo & MAC_METADATA != 0
                && let Some(metadata) = entry.mac_metadata().filter(|m| !m.is_empty())
                && let Err(e) = target.unpack_mac_metadata(metadata)
            {
                let _ = a.warn(
                    e.raw_os_error().unwrap_or(libc::EIO),
                    "Failed to restore metadata",
                );
            }
        }
        a.state.set(state::CLOSED);
        ret
    }
}

/// The permissions an entry ends up with: without PERM, no set-id or
/// sticky bits and the umask applied.
fn final_mode(entry: &Entry, options: c_int, umask: u32) -> u32 {
    if options & PERM != 0 {
        entry.mode() as u32 & 0o7777
    } else {
        entry.mode() as u32 & 0o777 & !umask
    }
}

/// Upstream's set_times. Where files have a birthtime, setting an earlier
/// mtime moves it back, so the birthtime goes first.
fn set_times(
    target: &Target,
    atime: (i64, i64),
    birthtime: (i64, i64),
    mtime: (i64, i64),
) -> std::io::Result<()> {
    let first = if cfg!(target_vendor = "apple") && birthtime < mtime {
        target.times(atime, birthtime)
    } else {
        Ok(())
    };
    let second = target.times(atime, mtime);
    second.and(first)
}

/// Upstream's set_xattrs: sets every attribute it can, and names the ones
/// it couldn't unless the filesystem has no extended attributes.
fn set_xattrs(a: &Base, entry: &Entry, target: &Target) -> c_int {
    let failed = target.write_xattrs(entry);
    if failed.is_empty() {
        return ARCHIVE_OK;
    }
    let unsupported =
        |e: &std::io::Error| [Some(libc::ENOTSUP), Some(libc::ENOSYS)].contains(&e.raw_os_error());
    let msg = if failed.iter().all(|(_, e)| unsupported(e)) {
        b"Cannot restore extended attributes on this file system".to_vec()
    } else {
        let names: Vec<&[u8]> = failed.iter().map(|(name, _)| name.to_bytes()).collect();
        [
            b"Cannot restore extended attributes: ",
            &names.join(&b' ')[..],
        ]
        .concat()
    };
    a.warn(ARCHIVE_ERRNO_MISC, msg).code()
}

impl Drop for WriteDisk {
    fn drop(&mut self) {
        if self.atomic.is_some()
            && let Some((_, _, target, _)) = &self.current
        {
            let _ = target.remove(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ARCHIVE_WARN;
    use crate::archive::WRITE_DISK_MAGIC;
    use crate::ffi::disk_sys::umask;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Output(PathBuf);
    impl Output {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "libarchive-disk-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> PathBuf {
            self.0.join("file")
        }
        fn header(&self, disk: &mut WriteDisk, base: &Base, size: Option<i64>) {
            let mut entry = Entry::new(None);
            entry.set_pathname(self.path().as_os_str().as_bytes());
            entry.set_mode(libc::S_IFREG | 0o600);
            if let Some(size) = size {
                entry.set_size(size);
            }
            assert_eq!(disk.header(base, &mut entry), ARCHIVE_OK);
        }
    }
    impl Drop for Output {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn regular_creation_and_existing_file_modes_preserve_options() {
        use std::os::unix::fs::PermissionsExt;
        for options in [0, PERM, UNLINK, NO_OVERWRITE, SAFE_WRITES] {
            for existing in [false, true] {
                let output = Output::new();
                if existing {
                    std::fs::write(output.path(), b"old").unwrap();
                    std::fs::set_permissions(output.path(), std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                let base = Base::new(WRITE_DISK_MAGIC);
                let mut disk = WriteDisk::default();
                disk.options = options;
                let mut entry = Entry::new(None);
                entry.set_pathname(output.path().as_os_str().as_bytes());
                entry.set_mode(libc::S_IFREG | 0o640);
                entry.set_size(3);
                assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
                // A skipped file isn't open: writing to it is an error.
                let skipped = existing && options == NO_OVERWRITE;
                assert_eq!(entry.size(), if skipped { 0 } else { 3 });
                let written = if skipped { ARCHIVE_WARN as isize } else { 3 };
                assert_eq!(disk.data(&base, b"new"), written);
                assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
                assert_eq!(
                    std::fs::read(output.path()).unwrap(),
                    if skipped { b"old" } else { b"new" }
                );
                let expected = if skipped {
                    0o600
                } else if options == PERM {
                    0o640
                } else {
                    0o640 & !umask()
                };
                assert_eq!(
                    std::fs::metadata(output.path())
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o7777,
                    expected
                );
                assert_eq!(disk.close(&base), ARCHIVE_OK);
            }
        }
    }

    #[test]
    fn existing_file_is_replaced_not_written_into() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        for options in [0, SAFE_WRITES] {
            let output = Output::new();
            std::fs::write(output.path(), b"old").unwrap();
            // Unwritable, as a deny-write ACL makes it: upstream unlinks it, never opens it.
            std::fs::set_permissions(output.path(), std::fs::Permissions::from_mode(0o444))
                .unwrap();
            // A second link keeps the old inode from being reused for the new file.
            let old = output.0.join("old");
            std::fs::hard_link(output.path(), &old).unwrap();
            let base = Base::new(WRITE_DISK_MAGIC);
            let mut disk = WriteDisk::default();
            disk.options = options;
            output.header(&mut disk, &base, Some(3));
            assert_eq!(disk.data(&base, b"new"), 3);
            assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
            assert_eq!(std::fs::read(output.path()).unwrap(), b"new");
            assert_eq!(std::fs::read(&old).unwrap(), b"old");
            assert_ne!(
                std::fs::metadata(output.path()).unwrap().ino(),
                std::fs::metadata(&old).unwrap().ino()
            );
        }
    }

    #[test]
    fn link_without_target_and_socket_entries_become_regular_files() {
        for kind in [libc::S_IFLNK, libc::S_IFSOCK] {
            let output = Output::new();
            let base = Base::new(WRITE_DISK_MAGIC);
            let mut disk = WriteDisk::default();
            let mut entry = Entry::new(None);
            entry.set_pathname(output.path().as_os_str().as_bytes());
            entry.set_mode(kind | 0o644);
            entry.set_size(1);
            assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
            assert_eq!(disk.data(&base, b"x"), 1);
            assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
            let metadata = std::fs::symlink_metadata(output.path()).unwrap();
            assert!(metadata.is_file());
            assert_eq!(std::fs::read(output.path()).unwrap(), b"x");
        }
    }

    #[test]
    fn symlink_mode_is_restored() {
        use std::os::unix::fs::PermissionsExt;
        let output = Output::new();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        let mut entry = Entry::new(None);
        entry.set_pathname(output.path().as_os_str().as_bytes());
        entry.set_mode(libc::S_IFLNK | 0o640);
        entry.set_symlink(b"target");
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
        let mode = std::fs::symlink_metadata(output.path())
            .unwrap()
            .permissions()
            .mode();
        // Linux has no symlink modes; its lchmod fails with EOPNOTSUPP.
        if cfg!(target_vendor = "apple") {
            assert_eq!(mode & 0o777, 0o640 & !umask());
        }
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn hfs_compression_precedes_times() {
        use std::os::unix::fs::MetadataExt;
        let output = Output::new();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        disk.options = TIME;
        let mut entry = Entry::new(None);
        entry.set_pathname(output.path().as_os_str().as_bytes());
        entry.set_mode(libc::S_IFREG | 0o644);
        entry.set_size(8192);
        entry.set_mtime(1_000_000_000, 0);
        entry.set_fflags(libc::UF_COMPRESSED as std::ffi::c_ulong, 0);
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.data(&base, &[b'a'; 8192]), 8192);
        assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
        let metadata = std::fs::metadata(output.path()).unwrap();
        assert_eq!(metadata.mtime(), 1_000_000_000);
        assert_eq!(std::fs::read(output.path()).unwrap(), [b'a'; 8192]);
    }

    fn directory(output: &Output, disk: &mut WriteDisk, base: &Base, mode: crate::entry::Mode) {
        let mut entry = Entry::new(None);
        entry.set_pathname(output.path().as_os_str().as_bytes());
        entry.set_mode(libc::S_IFDIR | mode);
        entry.set_mtime(1_000_000_000, 0);
        assert_eq!(disk.header(base, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.finish_entry(base), ARCHIVE_OK);
    }

    #[test]
    fn only_new_directories_wait_for_close_for_times() {
        use std::os::unix::fs::MetadataExt;
        for existing in [false, true] {
            let output = Output::new();
            if existing {
                std::fs::create_dir(output.path()).unwrap();
            }
            let base = Base::new(WRITE_DISK_MAGIC);
            let mut disk = WriteDisk::default();
            disk.options = TIME;
            directory(&output, &mut disk, &base, 0o755);
            std::fs::write(output.path().join("child"), b"").unwrap();
            assert_eq!(disk.close(&base), ARCHIVE_OK);
            let mtime = std::fs::metadata(output.path()).unwrap().mtime();
            assert_eq!(mtime == 1_000_000_000, !existing);
        }
    }

    #[test]
    fn existing_directory_mode_changes_only_for_perm() {
        use std::os::unix::fs::PermissionsExt;
        for options in [0, PERM] {
            let output = Output::new();
            std::fs::create_dir(output.path()).unwrap();
            std::fs::set_permissions(output.path(), std::fs::Permissions::from_mode(0o777))
                .unwrap();
            let base = Base::new(WRITE_DISK_MAGIC);
            let mut disk = WriteDisk::default();
            disk.options = options;
            directory(&output, &mut disk, &base, 0o700);
            assert_eq!(disk.close(&base), ARCHIVE_OK);
            let mode = std::fs::metadata(output.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, if options == PERM { 0o700 } else { 0o777 });
        }
    }

    #[test]
    fn unrestorable_size_is_fatal_and_metadata_follows() {
        use std::os::unix::fs::MetadataExt;
        let output = Output::new();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        disk.options = TIME;
        let mut entry = Entry::new(None);
        entry.set_pathname(output.path().as_os_str().as_bytes());
        entry.set_mode(libc::S_IFREG | 0o644);
        entry.set_size(i64::MAX);
        entry.set_mtime(1_000_000_000, 0);
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.finish_entry(&base), ARCHIVE_FATAL);
        let message = base.error_string().unwrap().to_vec();
        assert!(matches!(
            message.as_slice(),
            b"Write to restore size failed" | b"Seek failed"
        ));
        assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
        let metadata = std::fs::metadata(output.path()).unwrap();
        assert_eq!((metadata.len(), metadata.mtime()), (0, 1_000_000_000));
    }

    #[test]
    fn failed_parent_mkdir_names_the_directory() {
        use std::os::unix::fs::PermissionsExt;
        if euid() == 0 {
            return; // Permission bits don't stop root.
        }
        let output = Output::new();
        let locked = output.0.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        let mut entry = Entry::new(None);
        entry.set_pathname(locked.join("dir/file").as_os_str().as_bytes());
        entry.set_mode(libc::S_IFREG | 0o644);
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_FAILED);
        let dir = locked.join("dir");
        let expected = [b"Failed to create dir '", dir.as_os_str().as_bytes(), b"'"].concat();
        assert_eq!(*base.error_string().unwrap(), *expected);
    }

    #[test]
    fn pathnames_are_cleaned_up_as_upstream_does() {
        for (path, clean) in [
            (&b"./a//b/."[..], &b"a/b"[..]),
            (b"/", b"/"),
            (b"./", b"."),
            (b"//a/", b"/a"),
            (b"a/../..x", b"a/../..x"),
        ] {
            assert_eq!(cleanup_pathname(path, 0).as_deref(), Ok(clean));
        }
        assert_eq!(
            cleanup_pathname(b"a/..", SECURE_NODOTDOT),
            Err("Path contains '..'")
        );
        assert_eq!(
            cleanup_pathname(b"/a", SECURE_NOABSOLUTEPATHS),
            Err("Path is absolute")
        );
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        let mut entry = Entry::new(None);
        entry.set_mode(libc::S_IFREG | 0o644);
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_FAILED);
        assert_eq!(base.errno.get(), ARCHIVE_ERRNO_MISC);
        assert_eq!(*base.error_string().unwrap(), *b"Invalid empty pathname");
    }

    #[test]
    fn what_is_in_the_way_of_a_parent_is_handled_as_upstream_does() {
        let output = Output::new();
        let root = std::fs::canonicalize(&output.0).unwrap();
        let file = root.join("a");
        let entry_path = file.join("b/c");
        let at = |p: &Path| p.as_os_str().as_bytes().to_vec();
        let quoted = |msg: &[u8], p: &Path| [msg, &at(p), b"'"].concat();
        for (options, code, errno, message) in [
            (0, ARCHIVE_OK, 0, None),
            (
                NO_OVERWRITE,
                ARCHIVE_FAILED,
                libc::EEXIST,
                Some(quoted(b"Can't create directory '", &file)),
            ),
            (
                UNLINK,
                ARCHIVE_FAILED,
                libc::ENOTDIR,
                Some(b"Could not unlink".to_vec()),
            ),
            (
                SECURE_SYMLINKS,
                ARCHIVE_FAILED,
                libc::ENOTDIR,
                Some([&b"Could not stat "[..], &at(&entry_path)].concat()),
            ),
            (
                NO_AUTODIR,
                ARCHIVE_FAILED,
                libc::ENOTDIR,
                Some(quoted(b"Can't create '", &entry_path)),
            ),
        ] {
            let _ = std::fs::remove_dir_all(&file);
            std::fs::write(&file, b"old").unwrap();
            let base = Base::new(WRITE_DISK_MAGIC);
            let mut disk = WriteDisk::default();
            disk.options = options;
            let mut entry = Entry::new(None);
            entry.set_pathname(&at(&entry_path));
            entry.set_mode(libc::S_IFREG | 0o644);
            assert_eq!(disk.header(&base, &mut entry), code, "{options:#x}");
            assert_eq!(base.errno.get(), errno, "{options:#x}");
            assert_eq!(base.error_string().map(|m| m.to_vec()), message);
            assert_eq!(file.is_dir(), code == ARCHIVE_OK);
        }
        // A dangling symlink is in the way, but upstream doesn't remove it.
        let link = root.join("link");
        std::os::unix::fs::symlink("missing", &link).unwrap();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        let mut entry = Entry::new(None);
        entry.set_pathname(&at(&link.join("x")));
        entry.set_mode(libc::S_IFREG | 0o644);
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_FAILED);
        assert_eq!(base.errno.get(), libc::EEXIST);
        let expected = quoted(b"Failed to create dir '", &link);
        assert_eq!(*base.error_string().unwrap(), *expected);
    }

    #[test]
    fn writes_beyond_the_entry_are_refused_as_upstream_does() {
        let output = Output::new();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        let mut entry = Entry::new(None);
        entry.set_pathname(output.0.join("dir").as_os_str().as_bytes());
        entry.set_mode(libc::S_IFDIR | 0o755);
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
        assert_eq!((entry.size_is_set() != 0, entry.size()), (true, 0));
        assert_eq!(disk.data(&base, b"x"), ARCHIVE_WARN as isize);
        assert_eq!(base.errno.get(), libc::EIO);
        let mut entry = Entry::new(None);
        entry.set_pathname(output.0.join("file").as_os_str().as_bytes());
        entry.set_mode(libc::S_IFREG | 0o644);
        entry.set_size(2);
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.data_block(&base, b"xyz", 0), ARCHIVE_WARN);
        assert_eq!(base.errno.get(), libc::EOVERFLOW);
        let expected = b"Too much data: Truncating file at 2 bytes";
        assert_eq!(*base.error_string().unwrap(), *expected);
        assert_eq!(disk.close(&base), ARCHIVE_OK);
        assert_eq!(std::fs::read(output.0.join("file")).unwrap(), b"xy");
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn mac_metadata_replaces_acls_and_extended_attributes() {
        let output = Output::new();
        for with_metadata in [false, true] {
            let base = Base::new(WRITE_DISK_MAGIC);
            let mut disk = WriteDisk::default();
            disk.options = XATTR | MAC_METADATA;
            let mut entry = Entry::new(None);
            entry.set_pathname(output.path().as_os_str().as_bytes());
            entry.set_mode(libc::S_IFREG | 0o644);
            // An attribute name the filesystem refuses.
            entry.xattr_add(&std::ffi::CString::new([b'x'; 200]).unwrap(), b"v");
            if with_metadata {
                entry.copy_mac_metadata(b"metadata");
            }
            assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
            let restored = disk.finish_entry(&base);
            // Only the metadata is restored, and it is no AppleDouble file.
            assert_eq!(restored, ARCHIVE_WARN);
            let message = base.error_string().unwrap().to_vec();
            let expected = if with_metadata {
                b"Failed to restore metadata".to_vec()
            } else {
                [&b"Cannot restore extended attributes: "[..], &[b'x'; 200]].concat()
            };
            assert_eq!(message, expected);
        }
    }

    #[test]
    fn new_directory_waits_only_for_its_times_mode_and_acls() {
        use std::os::unix::fs::PermissionsExt;
        let output = Output::new();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        disk.options = TIME | XATTR | FFLAGS;
        let mut entry = Entry::new(None);
        entry.set_pathname(output.path().as_os_str().as_bytes());
        entry.set_mode(libc::S_IFDIR);
        entry.set_mtime(1_000_000_000, 0);
        entry.xattr_add(c"user.dir", b"v");
        #[cfg(target_vendor = "apple")]
        entry.set_fflags(libc::UF_HIDDEN as std::ffi::c_ulong, 0);
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
        let metadata = std::fs::metadata(output.path()).unwrap();
        // Usable by its owner and closed to others until close.
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        #[cfg(target_vendor = "apple")]
        {
            use std::os::macos::fs::MetadataExt;
            assert_eq!(metadata.st_flags() & libc::UF_HIDDEN, libc::UF_HIDDEN);
            let mut read = Entry::new(None);
            crate::ffi::disk_sys::read_xattrs(&output.path(), &mut read, false).unwrap();
            assert_eq!(read.xattrs.len(), 1);
        }
        assert_eq!(disk.close(&base), ARCHIVE_OK);
        let metadata = std::fs::metadata(output.path()).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0);
        std::fs::set_permissions(output.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn metadata_failures_are_reported_as_upstream_does() {
        let output = Output::new();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        disk.options = OWNER | XATTR | TIME;
        let mut entry = Entry::new(None);
        entry.set_pathname(output.path().as_os_str().as_bytes());
        entry.set_mode(libc::S_IFREG | 0o644);
        entry.set_uid(i64::from(euid()) + 1);
        entry.set_gid(0);
        entry.set_mtime(1_000_000_000, 0);
        let long = std::ffi::CString::new([b'x'; 200]).unwrap();
        entry.xattr_add(c"user.first", b"v");
        entry.xattr_add(&long, b"v");
        entry.xattr_add(c"user.last", b"v");
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.finish_entry(&base), ARCHIVE_WARN);
        // The last failure's message stays.
        let message = base.error_string().unwrap().to_vec();
        if euid() == 0 {
            assert!(message.starts_with(b"Cannot restore extended attributes: "));
        } else if cfg!(target_vendor = "apple") {
            let expected = [&b"Cannot restore extended attributes: "[..], &[b'x'; 200]].concat();
            assert_eq!(message, expected);
            assert_eq!(base.errno.get(), ARCHIVE_ERRNO_MISC);
        }
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            std::fs::metadata(output.path()).unwrap().mtime(),
            1_000_000_000
        );
        #[cfg(target_vendor = "apple")]
        if euid() != 0 {
            let mut read = Entry::new(None);
            crate::ffi::disk_sys::read_xattrs(&output.path(), &mut read, false).unwrap();
            assert_eq!(read.xattrs.len(), 2);
            // Without root, giving the file away isn't tried.
            disk.options = OWNER;
            assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
            assert_eq!(disk.finish_entry(&base), ARCHIVE_WARN);
            let expected = format!("Can't set UID={}", i64::from(euid()) + 1);
            assert_eq!(*base.error_string().unwrap(), *expected.as_bytes());
            entry.set_uid(euid().into());
            assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
            assert_eq!(disk.finish_entry(&base), ARCHIVE_WARN);
            let name = output.path();
            let expected = format!("Can't set user={}/group=0 for {}", euid(), name.display());
            assert_eq!(*base.error_string().unwrap(), *expected.as_bytes());
            assert_eq!(base.errno.get(), libc::EPERM);
        }
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn flags_that_forbid_changes_wait_for_close() {
        use std::os::macos::fs::MetadataExt;
        let output = Output::new();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        disk.options = FFLAGS | TIME;
        let mut entry = Entry::new(None);
        entry.set_pathname(output.path().as_os_str().as_bytes());
        entry.set_mode(libc::S_IFREG | 0o644);
        entry.set_mtime(1_000_000_000, 0);
        let flags = libc::UF_IMMUTABLE | libc::UF_HIDDEN;
        entry.set_fflags(
            flags as std::ffi::c_ulong,
            libc::UF_HIDDEN as std::ffi::c_ulong,
        );
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
        assert_eq!(std::fs::metadata(output.path()).unwrap().st_flags(), 0);
        // A hardlink to it can still be made.
        let mut link = Entry::new(None);
        link.set_pathname(output.0.join("link").as_os_str().as_bytes());
        link.set_hardlink(output.path().as_os_str().as_bytes());
        link.set_mode(libc::S_IFREG | 0o644);
        assert_eq!(disk.header(&base, &mut link), ARCHIVE_OK);
        assert_eq!(disk.close(&base), ARCHIVE_OK);
        let metadata = std::fs::metadata(output.path()).unwrap();
        // A flag both set and cleared stays set, as upstream sets it.
        assert_eq!(metadata.st_flags(), flags);
        assert_eq!(metadata.st_mtime(), 1_000_000_000);
        // Clear them so that the directory can be removed.
        let target = Target::prepare(&output.path(), false).unwrap();
        target.flags(0, flags).unwrap();
    }

    #[test]
    fn hardlink_without_data_leaves_the_file_metadata_alone() {
        use std::os::unix::fs::PermissionsExt;
        let output = Output::new();
        std::fs::write(output.path(), b"data").unwrap();
        std::fs::set_permissions(output.path(), std::fs::Permissions::from_mode(0o751)).unwrap();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        disk.options = PERM | TIME;
        let mut entry = Entry::new(None);
        entry.set_pathname(output.0.join("link").as_os_str().as_bytes());
        entry.set_hardlink(output.path().as_os_str().as_bytes());
        entry.set_mode(libc::S_IFREG | 0o642);
        entry.set_mtime(1_000_000_000, 0);
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.close(&base), ARCHIVE_OK);
        let metadata = std::fs::metadata(output.path()).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o751);
        use std::os::unix::fs::MetadataExt;
        assert_ne!(metadata.mtime(), 1_000_000_000);
    }

    #[test]
    fn hardlink_target_is_checked_after_unlink() {
        for options in [SECURE_NODOTDOT, SECURE_NODOTDOT | UNLINK] {
            let output = Output::new();
            std::fs::write(output.path(), b"old").unwrap();
            let base = Base::new(WRITE_DISK_MAGIC);
            let mut disk = WriteDisk::default();
            disk.options = options;
            let mut entry = Entry::new(None);
            entry.set_pathname(output.path().as_os_str().as_bytes());
            entry.set_hardlink(b"dir/../other");
            entry.set_mode(libc::S_IFREG | 0o644);
            assert_eq!(disk.header(&base, &mut entry), ARCHIVE_FAILED);
            assert_eq!(*base.error_string().unwrap(), *b"Path contains '..'");
            // Upstream unlinks what is in the way before it looks at the link.
            assert_eq!(output.path().exists(), options & UNLINK == 0);
        }
    }

    #[test]
    fn directory_entry_over_a_symlink_leaves_its_target_alone() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        for options in [PERM | TIME | XATTR | FFLAGS, PERM | TIME | UNLINK] {
            let output = Output::new();
            let outside = output.0.join("outside");
            std::fs::create_dir(&outside).unwrap();
            std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o750)).unwrap();
            std::os::unix::fs::symlink(&outside, output.path()).unwrap();
            let before = std::fs::metadata(&outside).unwrap();
            let base = Base::new(WRITE_DISK_MAGIC);
            let mut disk = WriteDisk::default();
            disk.options = options;
            let mut entry = Entry::new(None);
            entry.set_pathname(output.path().as_os_str().as_bytes());
            entry.set_mode(libc::S_IFDIR | 0o777);
            entry.set_mtime(1_000_000_000, 0);
            entry.xattr_add(c"user.dir", b"v");
            #[cfg(target_vendor = "apple")]
            entry.set_fflags(libc::UF_HIDDEN as std::ffi::c_ulong, 0);
            assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
            assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
            assert_eq!(disk.close(&base), ARCHIVE_OK);
            // Upstream keeps the symlink and touches only the link itself.
            assert!(
                std::fs::symlink_metadata(output.path())
                    .unwrap()
                    .is_symlink()
            );
            let after = std::fs::metadata(&outside).unwrap();
            assert_eq!(after.permissions().mode() & 0o7777, 0o750);
            assert_eq!(after.mtime(), before.mtime());
            #[cfg(target_vendor = "apple")]
            {
                use std::os::macos::fs::MetadataExt;
                assert_eq!(after.st_flags(), before.st_flags());
                let mut read = Entry::new(None);
                crate::ffi::disk_sys::read_xattrs(&outside, &mut read, true).unwrap();
                assert!(read.xattrs.is_empty());
            }
        }
    }

    #[test]
    fn waiting_directories_hold_no_descriptors() {
        let open = || std::fs::read_dir("/dev/fd").map_or(0, |d| d.count());
        let output = Output::new();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        disk.options = TIME | PERM;
        let before = open();
        for i in 0..100 {
            let mut entry = Entry::new(None);
            entry.set_pathname(output.0.join(format!("d{i}")).as_os_str().as_bytes());
            entry.set_mode(libc::S_IFDIR | 0o750);
            entry.set_mtime(1_000_000_000, 0);
            assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
        }
        assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
        assert_eq!(disk.fixups.len(), 100);
        // Other tests open files meanwhile; a descriptor per directory would
        // add at least 100.
        assert!(open() < before + 50, "{before} -> {}", open());
        assert_eq!(disk.close(&base), ARCHIVE_OK);
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(output.0.join("d99")).unwrap();
        assert_eq!(
            (metadata.mode() & 0o777, metadata.mtime()),
            (0o750, 1_000_000_000)
        );
    }

    #[test]
    fn close_skips_a_directory_whose_parent_was_swapped() {
        use std::os::unix::fs::MetadataExt;
        let output = Output::new();
        let root = std::fs::canonicalize(&output.0).unwrap();
        let outside = root.join("outside");
        std::fs::create_dir_all(outside.join("sub")).unwrap();
        let before = std::fs::metadata(outside.join("sub")).unwrap().mtime();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        disk.options = TIME | PERM | SECURE_SYMLINKS;
        for name in ["q", "q/sub"] {
            let mut entry = Entry::new(None);
            entry.set_pathname(root.join(name).as_os_str().as_bytes());
            entry.set_mode(libc::S_IFDIR | 0o777);
            entry.set_mtime(1_000_000_000, 0);
            assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
        }
        assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
        std::fs::rename(root.join("q"), root.join("q.orig")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("q")).unwrap();
        assert_eq!(disk.close(&base), ARCHIVE_OK);
        assert_eq!(
            std::fs::metadata(outside.join("sub")).unwrap().mtime(),
            before
        );
    }

    #[test]
    fn only_appledouble_files_with_data_are_merged() {
        let output = Output::new();
        std::fs::write(output.0.join("x"), b"x").unwrap();
        std::fs::create_dir(output.0.join("d")).unwrap();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        // A FIFO, even one claiming data, is never waited on, and a
        // directory is no AppleDouble file.
        for (name, kind, size) in [
            ("._x", libc::S_IFIFO, 0),
            ("._x", libc::S_IFIFO, 8),
            ("._d", libc::S_IFDIR, 0),
        ] {
            let _ = std::fs::remove_file(output.0.join(name));
            let mut entry = Entry::new(None);
            entry.set_pathname(output.0.join(name).as_os_str().as_bytes());
            entry.set_mode(kind | 0o644);
            entry.set_size(size);
            assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
            assert_eq!(
                disk.finish_entry(&base),
                ARCHIVE_OK,
                "{name} {kind:o} {size}"
            );
        }
        assert_eq!(disk.close(&base), ARCHIVE_OK);
    }

    #[test]
    fn files_are_created_without_special_bits_then_get_their_mode() {
        use std::os::unix::fs::PermissionsExt;
        let output = Output::new();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        disk.options = PERM | XATTR;
        let mode = |name: &str| {
            let path = output.0.join(name);
            std::fs::symlink_metadata(path)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        let mut fifo = Entry::new(None);
        fifo.set_pathname(output.0.join("fifo").as_os_str().as_bytes());
        fifo.set_mode(libc::S_IFIFO | 0o4755);
        fifo.set_uid(euid().into());
        assert_eq!(disk.header(&base, &mut fifo), ARCHIVE_OK);
        assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
        assert_eq!(mode("fifo"), 0o4755);
        // A read-only file is created writable for its attributes.
        let mut file = Entry::new(None);
        file.set_pathname(output.0.join("file").as_os_str().as_bytes());
        file.set_mode(libc::S_IFREG | 0o444);
        file.xattr_add(c"user.file", b"v");
        assert_eq!(disk.header(&base, &mut file), ARCHIVE_OK);
        assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
        assert_eq!(mode("file"), 0o444);
        #[cfg(target_vendor = "apple")]
        {
            let mut read = Entry::new(None);
            crate::ffi::disk_sys::read_xattrs(&output.0.join("file"), &mut read, false).unwrap();
            assert_eq!(read.xattrs.len(), 1);
        }
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn a_symlink_gets_its_deferred_flags_at_close() {
        use std::os::macos::fs::MetadataExt;
        let output = Output::new();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        disk.options = FFLAGS;
        let mut entry = Entry::new(None);
        entry.set_pathname(output.path().as_os_str().as_bytes());
        entry.set_mode(libc::S_IFLNK | 0o755);
        entry.set_symlink(b"target");
        entry.set_fflags(libc::UF_IMMUTABLE as std::ffi::c_ulong, 0);
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.close(&base), ARCHIVE_OK);
        let flags = std::fs::symlink_metadata(output.path()).unwrap().st_flags();
        let target = Target::prepare(&output.path(), false).unwrap();
        target.flags(0, libc::UF_IMMUTABLE).unwrap();
        assert_eq!(flags, libc::UF_IMMUTABLE);
    }

    #[test]
    fn hardlink_to_itself_is_skipped() {
        let output = Output::new();
        std::fs::write(output.path(), b"data").unwrap();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        let mut entry = Entry::new(None);
        let name = output.path();
        entry.set_pathname(&[name.as_os_str().as_bytes(), b"/"].concat());
        entry.set_hardlink(name.as_os_str().as_bytes());
        entry.set_mode(libc::S_IFREG | 0o644);
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_WARN);
        let expected = [
            b"Skipping hardlink pointing to itself: ",
            name.as_os_str().as_bytes(),
        ]
        .concat();
        assert_eq!(*base.error_string().unwrap(), *expected);
        assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
        assert_eq!(std::fs::read(output.path()).unwrap(), b"data");
    }

    #[test]
    fn close_skips_directories_that_are_gone_or_replaced() {
        use std::os::unix::fs::PermissionsExt;
        for replaced in [false, true] {
            let output = Output::new();
            let base = Base::new(WRITE_DISK_MAGIC);
            let mut disk = WriteDisk::default();
            disk.options = TIME;
            directory(&output, &mut disk, &base, 0o700);
            std::fs::remove_dir(output.path()).unwrap();
            if replaced {
                std::fs::write(output.path(), b"").unwrap();
                std::fs::set_permissions(output.path(), std::fs::Permissions::from_mode(0o644))
                    .unwrap();
            }
            assert_eq!(disk.close(&base), ARCHIVE_OK);
            if replaced {
                let metadata = std::fs::metadata(output.path()).unwrap();
                assert_eq!(metadata.permissions().mode() & 0o777, 0o644);
            }
        }
    }

    #[test]
    fn archive_is_kept_unless_overwriting_is_off() {
        use std::os::unix::fs::MetadataExt;
        for options in [0, NO_OVERWRITE] {
            let output = Output::new();
            std::fs::write(output.path(), b"archive").unwrap();
            let metadata = std::fs::metadata(output.path()).unwrap();
            let base = Base::new(WRITE_DISK_MAGIC);
            let mut disk = WriteDisk::default();
            disk.options = options;
            disk.skip_file = Some((metadata.dev() as i64, metadata.ino() as i64));
            let mut entry = Entry::new(None);
            entry.set_pathname(output.path().as_os_str().as_bytes());
            entry.set_mode(libc::S_IFREG | 0o644);
            entry.set_size(0);
            let expected = if options == 0 {
                ARCHIVE_FAILED
            } else {
                ARCHIVE_OK
            };
            assert_eq!(disk.header(&base, &mut entry), expected);
            if options == 0 {
                assert_eq!(base.errno.get(), libc::EIO);
            }
            assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
            assert_eq!(std::fs::read(output.path()).unwrap(), b"archive");
        }
    }

    #[test]
    fn contiguous_and_backward_blocks_preserve_file_length() {
        for size in [None, Some(8)] {
            let output = Output::new();
            std::fs::write(output.path(), [1; 100]).unwrap();
            let base = Base::new(WRITE_DISK_MAGIC);
            let mut disk = WriteDisk::default();
            output.header(&mut disk, &base, size);
            assert_eq!(disk.file_len, Some(0));
            assert_eq!(disk.data_block(&base, b"abcd", 0), ARCHIVE_OK);
            assert_eq!(disk.data(&base, b"efgh"), 4);
            assert_eq!(disk.file_offset, Some(8));
            assert_eq!(disk.file_len, Some(8));
            assert_eq!(disk.data_block(&base, b"XY", 2), ARCHIVE_OK);
            assert_eq!(disk.file_offset, Some(4));
            assert_eq!(disk.file_len, Some(8));
            assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
            assert_eq!(std::fs::read(output.path()).unwrap(), b"abXYefgh");
        }
    }

    #[test]
    fn sparse_trailing_holes_and_short_files_are_extended() {
        for (size, sparse) in [(None, true), (Some(12), true), (Some(12), false)] {
            let output = Output::new();
            let base = Base::new(WRITE_DISK_MAGIC);
            let mut disk = WriteDisk::default();
            if sparse {
                disk.options |= 0x1000;
            }
            output.header(&mut disk, &base, size);
            assert_eq!(disk.data_block(&base, b"xy", 2), ARCHIVE_OK);
            assert_eq!(disk.data_block(&base, &[0; 4], 4), ARCHIVE_OK);
            assert_eq!(disk.file_offset, Some(8));
            assert_eq!(disk.file_len, Some(if sparse { 4 } else { 8 }));
            assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
            let mut expected = vec![0; size.unwrap_or(8) as usize];
            expected[2..4].copy_from_slice(b"xy");
            assert_eq!(std::fs::read(output.path()).unwrap(), expected);
        }
    }

    #[test]
    fn failed_write_invalidates_cached_offset_and_length() {
        let output = Output::new();
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = WriteDisk::default();
        output.header(&mut disk, &base, Some(4));
        // A read-only handle gives a deterministic write error without filling
        // the disk or relying on a platform-specific device.
        disk.file = Some(File::open(output.path()).unwrap());
        assert!(disk.data(&base, b"a") < 0);
        assert_eq!(disk.file_offset, None);
        assert_eq!(disk.file_len, None);
        disk.file = Some(
            std::fs::OpenOptions::new()
                .write(true)
                .open(output.path())
                .unwrap(),
        );
        assert_eq!(disk.data_block(&base, b"xy", 2), ARCHIVE_OK);
        assert_eq!(disk.file_offset, Some(4));
        assert_eq!(disk.file_len, None);
        assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
        assert_eq!(std::fs::read(output.path()).unwrap(), b"\0\0xy");
    }
}
