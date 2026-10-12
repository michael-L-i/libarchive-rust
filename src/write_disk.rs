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

use crate::archive::{
    ARCHIVE_ERRNO_MISC, ARCHIVE_FAILED, ARCHIVE_FATAL, ARCHIVE_OK, ARCHIVE_WARN, Base, state,
};
use crate::entry::Entry;
use crate::ffi::disk_sys::{DirError, Target, check_symlinks, create_dir};
use crate::util::Error;
use std::ffi::c_int;
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
pub const SAFE_WRITES: c_int = 0x40000;

#[derive(Default)]
pub struct WriteDisk {
    pub options: c_int,
    pub bytes: i64,
    pub skip_file: Option<(i64, i64)>,
    pub user: crate::ffi::disk::IdLookup,
    pub group: crate::ffi::disk::IdLookup,
    file: Option<File>,
    current: Option<(PathBuf, Entry, Target, c_int)>,
    directories: Vec<(Entry, Target, c_int, bool)>,
    offset: u64,
    max_offset: u64,
    file_offset: Option<u64>,
    file_len: Option<u64>,
    limit: Option<u64>,
    skipped: bool,
    atomic: Option<Target>,
    permissions_created: bool,
    new_directory: bool,
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
        let hardlink = entry
            .hardlink()
            .map(|p| PathBuf::from(std::ffi::OsStr::from_bytes(p.to_bytes())));
        if let Some(target) = &hardlink {
            if name == target.as_os_str().as_bytes() {
                let msg = [b"Skipping hardlink pointing to itself: ", name.as_slice()];
                return a.warn(ARCHIVE_ERRNO_MISC, msg.concat()).code();
            }
            if let Err(msg) = cleanup_pathname(target.as_os_str().as_bytes(), self.options) {
                return a.raise(Error::new(ARCHIVE_FAILED, ARCHIVE_ERRNO_MISC, msg));
            }
        }
        let options = self.options;
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
                && let Err((dir, e)) = create_dir(parent, secure, options & NO_OVERWRITE != 0)
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
        if let Some(mut existing) = target.take_if(|_| en == libc::EEXIST) {
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
                if let Err(e) = existing.remove(true) {
                    return failed(
                        errno(e),
                        "Can't replace existing directory with non-directory",
                    );
                }
                (target, en) = self.create(a, path, entry);
            } else {
                // A directory in the way of a directory is kept as it is.
                if !secure
                    && existing
                        .stat()
                        .is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFLNK)
                {
                    existing = std::fs::canonicalize(path)
                        .and_then(|real| Target::prepare(&real, false))
                        .or_else(|e| failed(errno(e), "Can't follow directory"))?;
                }
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
        entry.mode() as u32 & 0o777 & !crate::ffi::disk_sys::umask()
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
                    let created = target.mkdir(0o777);
                    self.new_directory = created.is_ok();
                    created
                }
                libc::S_IFCHR | libc::S_IFBLK | libc::S_IFIFO => {
                    target.special(entry.mode() as u32, entry.rdev() as u64)
                }
                // POSIX requires any other type to be created as a regular file.
                _ => target.open(self.creation_mode(entry), true).map(|file| {
                    self.file = Some(file);
                    // On Apple, creation applies the umask without Linux's
                    // default-ACL substitution: the mode is final.
                    self.permissions_created = cfg!(target_vendor = "apple") && options & PERM == 0;
                }),
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
                    return failure(a, e, "Can't rename temporary file", &path);
                }
                target = destination;
            }
            if let Some(file) = file {
                target.retain_file(file);
            }
            #[cfg(target_vendor = "apple")]
            if let Some(name) = path
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
                if let Ok(mut file) = target.read_file() {
                    let mut magic = [0; 8];
                    if file.read_exact(&mut magic).is_ok() && magic == [0, 5, 22, 7, 0, 2, 0, 0] {
                        let size = file.metadata().map_or(0, |m| m.len());
                        if size > 16 * 1024 * 1024 {
                            return a
                                .warn(libc::ENOMEM, "AppleDouble metadata is too large")
                                .code();
                        }
                        let mut bytes = Vec::from(magic);
                        if let Err(e) = file.read_to_end(&mut bytes) {
                            return failure(a, e, "Can't read metadata", &path);
                        }
                        if let Err(e) = dest.unpack_mac_metadata(&bytes) {
                            return a
                                .warn(
                                    e.raw_os_error().unwrap_or(libc::EIO),
                                    "Failed to restore metadata",
                                )
                                .code();
                        }
                        if let Err(e) = target.remove(false) {
                            return failure(a, e, "Can't remove AppleDouble", &path);
                        }
                        a.state.set(state::HEADER);
                        return ARCHIVE_OK;
                    }
                }
            }
            if entry.filetype() == libc::S_IFDIR {
                // Only a directory this entry created waits for close to get its
                // times and mode; one already there gets them now, and its mode
                // changes only for PERM. ACLs and Mac metadata always wait.
                let mut deferred = options;
                let mut mode = true;
                if !self.new_directory {
                    mode = options & PERM != 0
                        && target.stat().is_ok_and(|st| st.st_mode != entry.mode());
                    let ret = self.restore(
                        a,
                        &entry,
                        &mut target,
                        options & !(ACL | MAC_METADATA),
                        false,
                    );
                    if ret < 0 {
                        return ret;
                    }
                    deferred &= !(OWNER | TIME | XATTR | FFLAGS);
                }
                self.directories.push((entry, target, deferred, mode));
            } else {
                let ret = self.restore(a, &entry, &mut target, options, !permissions_created);
                if ret < 0 {
                    return ret;
                }
            }
        }
        a.state.set(state::HEADER);
        ARCHIVE_OK
    }

    fn restore(
        &mut self,
        a: &Base,
        entry: &Entry,
        target: &mut Target,
        options: c_int,
        mode: bool,
    ) -> c_int {
        if entry.hardlink_is_set() != 0 && (entry.size_is_set() == 0 || entry.size() == 0) {
            return ARCHIVE_OK;
        }
        if entry.filetype() == libc::S_IFDIR
            && let Ok(file) = target.directory_file()
        {
            target.retain_file(file);
        }
        let mut ret = ARCHIVE_OK;
        // Upstream compresses as the data is written, before any metadata.
        #[cfg(target_vendor = "apple")]
        if entry.filetype() == libc::S_IFREG
            && options & 0x4000 == 0
            && (options & 0x8000 != 0
                || entry.fflags().0 & libc::UF_COMPRESSED as std::ffi::c_ulong != 0)
            && let Err(e) = hfs::compress(target, entry.size().max(0) as u64)
        {
            ret = a
                .warn(
                    e.raw_os_error().unwrap_or(libc::EIO),
                    "Failed to compress file",
                )
                .code();
        }
        if options & OWNER != 0 {
            let mut names = entry.clone_entry();
            let uid = self.user.lookup(names.uname(), entry.uid(), false);
            let gid = self.group.lookup(names.gname(), entry.gid(), true);
            if let Err(e) = target.owner(uid, gid) {
                let _ = a
                    .warn(
                        e.raw_os_error().unwrap_or(libc::EPERM),
                        "Can't restore owner",
                    )
                    .code();
                ret = ARCHIVE_WARN;
            }
        }
        if mode {
            let mut mode = if options & PERM != 0 {
                entry.mode() as u32 & 0o7777
            } else {
                entry.mode() as u32 & 0o777 & !crate::ffi::disk_sys::umask()
            };
            if mode & 0o6000 != 0
                && let Ok(st) = target.stat()
            {
                if st.st_uid as i64 != entry.uid() {
                    mode &= !0o4000;
                }
                if st.st_gid as i64 != entry.gid() {
                    mode &= !0o2000;
                }
            }
            // A symlink's mode is set with lchmod, whose lack is no error.
            if let Err(e) = target.chmod(mode)
                && !(entry.filetype() == libc::S_IFLNK
                    && e.raw_os_error().is_some_and(|errno| {
                        [libc::ENOTSUP, libc::ENOSYS, libc::EOPNOTSUPP].contains(&errno)
                    }))
            {
                let _ = a.warn(
                    e.raw_os_error().unwrap_or(libc::EPERM),
                    format!("Can't set permissions to 0{mode:o}"),
                );
                ret = ARCHIVE_WARN;
            }
        }
        if options & TIME != 0
            && let Err(e) = target.times(entry)
        {
            a.warn(e.raw_os_error().unwrap_or(libc::EIO), "Can't restore times")
                .code();
            ret = ARCHIVE_WARN;
        }
        if options & XATTR != 0
            && let Err(e) = target.write_xattrs(entry)
        {
            a.warn(
                e.raw_os_error().unwrap_or(libc::EIO),
                "Can't restore extended attributes",
            )
            .code();
            ret = ARCHIVE_WARN;
        }
        #[cfg(target_vendor = "apple")]
        if options & ACL != 0
            && let Err(e) = target.metadata_file().and_then(|file| {
                crate::ffi::disk_acl::write(&file, entry, &mut self.user, &mut self.group)
            })
        {
            ret = a
                .warn(e.raw_os_error().unwrap_or(libc::EIO), "Can't restore ACL")
                .code();
        }
        if options & MAC_METADATA != 0
            && let Some(metadata) = entry.mac_metadata()
            && let Err(e) = target.unpack_mac_metadata(metadata)
        {
            let _ = a.warn(
                e.raw_os_error().unwrap_or(libc::EIO),
                "Failed to restore metadata",
            );
            ret = ARCHIVE_WARN;
        }
        if options & FFLAGS != 0 {
            let (set, clear) = entry.fflags();
            if let Err(e) = target.flags(set as u32, clear as u32) {
                let _ = a.warn(
                    e.raw_os_error().unwrap_or(libc::EIO),
                    "Can't restore file flags",
                );
                ret = ARCHIVE_WARN;
            }
        }
        ret
    }

    pub fn close(&mut self, a: &Base) -> c_int {
        if a.state.get() == state::FATAL {
            return ARCHIVE_FATAL;
        }
        let ret = self.finish_entry(a);
        // Upstream fixes up only what is still a directory, and ignores failures.
        while let Some((entry, mut target, options, mode)) = self.directories.pop() {
            if target
                .stat()
                .is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFDIR)
            {
                let _ = self.restore(a, &entry, &mut target, options, mode);
            }
        }
        a.state.set(state::CLOSED);
        ret
    }
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
    use crate::archive::WRITE_DISK_MAGIC;
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
                    0o640 & !crate::ffi::disk_sys::umask()
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
            let inode = std::fs::metadata(output.path()).unwrap().ino();
            let base = Base::new(WRITE_DISK_MAGIC);
            let mut disk = WriteDisk::default();
            disk.options = options;
            output.header(&mut disk, &base, Some(3));
            assert_eq!(disk.data(&base, b"new"), 3);
            assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
            assert_eq!(std::fs::read(output.path()).unwrap(), b"new");
            assert_ne!(std::fs::metadata(output.path()).unwrap().ino(), inode);
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
            assert_eq!(mode & 0o777, 0o640 & !crate::ffi::disk_sys::umask());
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
