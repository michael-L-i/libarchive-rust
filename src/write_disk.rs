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

use crate::archive::{ARCHIVE_FAILED, ARCHIVE_OK, ARCHIVE_WARN, Base, state};
use crate::entry::Entry;
use crate::ffi::disk_sys::Target;
use crate::util::Error;
use std::ffi::c_int;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

pub const OWNER: c_int = 1;
pub const PERM: c_int = 2;
pub const TIME: c_int = 4;
pub const NO_OVERWRITE: c_int = 8;
pub const UNLINK: c_int = 16;
pub const SECURE_SYMLINKS: c_int = 0x100;
pub const SECURE_NODOTDOT: c_int = 0x200;
pub const NO_AUTODIR: c_int = 0x400;
pub const NO_OVERWRITE_NEWER: c_int = 0x800;
pub const SECURE_NOABSOLUTEPATHS: c_int = 0x10000;

#[derive(Default)]
pub struct WriteDisk {
    pub options: c_int,
    pub bytes: i64,
    pub skip_file: Option<(i64, i64)>,
    pub user: crate::ffi::disk::IdLookup,
    pub group: crate::ffi::disk::IdLookup,
    file: Option<File>,
    current: Option<(PathBuf, Entry, Target, c_int)>,
    directories: Vec<(Entry, Target, c_int)>,
    offset: u64,
    max_offset: u64,
    limit: Option<u64>,
    skipped: bool,
    atomic: Option<Target>,
}

fn failure(a: &Base, err: std::io::Error, action: &str, path: &Path) -> c_int {
    a.raise(Error::new(
        ARCHIVE_FAILED,
        err.raw_os_error().unwrap_or(libc::EIO),
        [action.as_bytes(), b" '", path.as_os_str().as_bytes(), b"'"].concat(),
    ))
}

impl WriteDisk {
    pub fn header(&mut self, a: &Base, entry: &Entry) -> c_int {
        let previous = self.finish_entry(a);
        if previous < ARCHIVE_OK {
            return previous;
        }
        a.clear_error();
        a.state.set(state::HEADER);
        self.skipped = false;
        let mut entry = entry.clone_entry();
        let Some(name) = entry.pathname().map(|p| p.to_bytes().to_vec()) else {
            return a.raise(Error::new(
                ARCHIVE_FAILED,
                libc::EINVAL,
                "Invalid empty pathname",
            ));
        };
        let path = PathBuf::from(std::ffi::OsStr::from_bytes(&name));
        if name.is_empty() {
            return a.raise(Error::new(
                ARCHIVE_FAILED,
                libc::EINVAL,
                "Invalid empty pathname",
            ));
        }
        if self.options & SECURE_NOABSOLUTEPATHS != 0 && path.is_absolute() {
            return a.raise(Error::new(
                ARCHIVE_FAILED,
                crate::archive::ARCHIVE_ERRNO_MISC,
                "Path is absolute",
            ));
        }
        if self.options & SECURE_NODOTDOT != 0
            && path.components().any(|c| c == Component::ParentDir)
        {
            return a.raise(Error::new(
                ARCHIVE_FAILED,
                crate::archive::ARCHIVE_ERRNO_MISC,
                "Path contains '..'",
            ));
        }
        let hardlink = entry
            .hardlink()
            .map(|p| PathBuf::from(std::ffi::OsStr::from_bytes(p.to_bytes())));
        let link = entry
            .symlink()
            .map(|p| PathBuf::from(std::ffi::OsStr::from_bytes(p.to_bytes())));
        if let Some(target) = &hardlink {
            if self.options & SECURE_NOABSOLUTEPATHS != 0 && target.is_absolute() {
                return a.raise(Error::new(
                    ARCHIVE_FAILED,
                    crate::archive::ARCHIVE_ERRNO_MISC,
                    "Path is absolute",
                ));
            }
            if self.options & SECURE_NODOTDOT != 0
                && target.components().any(|c| c == Component::ParentDir)
            {
                return a.raise(Error::new(
                    ARCHIVE_FAILED,
                    crate::archive::ARCHIVE_ERRNO_MISC,
                    "Path contains '..'",
                ));
            }
        }
        let secure = self.options & SECURE_SYMLINKS != 0;
        let mut target = match Target::prepare(
            &path,
            secure,
            self.options & UNLINK != 0,
            self.options & NO_AUTODIR == 0,
        ) {
            Ok(t) => t,
            Err(e) => return failure(a, e, "Can't create parent directory", &path),
        };
        if !secure
            && self.options & UNLINK == 0
            && entry.filetype() == libc::S_IFDIR
            && std::fs::metadata(&path).is_ok_and(|m| m.is_dir())
            && target
                .stat()
                .is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFLNK)
            && let Ok(real) = std::fs::canonicalize(&path)
        {
            match Target::prepare(&real, false, false, false) {
                Ok(t) => target = t,
                Err(e) => return failure(a, e, "Can't follow directory", &path),
            }
        }
        if let Ok(existing) = target.stat() {
            let directory = existing.st_mode & libc::S_IFMT == libc::S_IFDIR;
            if directory && entry.filetype() == libc::S_IFDIR && self.options & PERM == 0 {
                entry.set_perm(existing.st_mode);
            }

            if self.skip_file == Some((existing.st_dev as i64, existing.st_ino as i64)) {
                return a.raise(Error::new(
                    ARCHIVE_FAILED,
                    libc::EPERM,
                    "Refusing to overwrite archive",
                ));
            }
            if self.options & NO_OVERWRITE != 0
                || (self.options & NO_OVERWRITE_NEWER != 0
                    && !directory
                    && (existing.st_mtime, existing.st_mtime_nsec)
                        >= (entry.mtime(), entry.mtime_nsec()))
            {
                self.skipped = true;
            } else if !(directory && entry.filetype() == libc::S_IFDIR)
                && (self.options & UNLINK != 0
                    || existing.st_mode & libc::S_IFMT == libc::S_IFLNK
                    || directory
                    || entry.filetype() == libc::S_IFDIR
                    || hardlink.is_some()
                    || link.is_some()
                    || (existing.st_nlink > 1 && self.options & 0x40000 == 0))
                && let Err(e) = target.remove(directory)
            {
                return failure(a, e, "Can't unlink", &path);
            }
        }
        self.offset = 0;
        self.max_offset = 0;
        self.limit = (entry.size_is_set() != 0).then(|| entry.size().max(0) as u64);
        if entry.hardlink_is_set() != 0 && entry.size_is_set() == 0 {
            self.limit = Some(0);
        }
        if !self.skipped {
            let hardlink_name = hardlink.as_ref().map(|p| p.as_os_str().as_bytes().to_vec());
            let result = if let Some(source) = hardlink {
                Target::prepare(&source, secure, false, false)
                    .and_then(|source| target.hardlink(&source, secure))
            } else if let Some(link) = link {
                self.limit = Some(0);
                target.symlink(&link)
            } else if entry.filetype() == libc::S_IFDIR {
                self.limit = Some(0);
                match target.mkdir(0o777) {
                    Err(e)
                        if e.raw_os_error() == Some(libc::EEXIST)
                            && target
                                .stat()
                                .is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFDIR) =>
                    {
                        Ok(())
                    }
                    result => result,
                }
            } else if entry.filetype() == libc::S_IFREG || entry.filetype() == 0 {
                if self.options & 0x40000 != 0 {
                    match target.atomic_file(entry.mode() as u32 & 0o777) {
                        Ok((tmp, file)) => {
                            self.atomic = Some(target);
                            target = tmp;
                            self.file = Some(file);
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    target
                        .open(entry.mode() as u32 & 0o777)
                        .map(|file| self.file = Some(file))
                }
            } else {
                target.special(entry.mode() as u32, entry.rdev() as u64)
            };
            if let Err(e) = result {
                if e.raw_os_error() == Some(libc::ENOENT)
                    && let Some(name) = hardlink_name
                {
                    return a.raise(Error::new(
                        ARCHIVE_FAILED,
                        libc::ENOENT,
                        [b"Hard-link target '".as_slice(), &name, b"' does not exist"].concat(),
                    ));
                }
                return failure(a, e, "Can't create", &path);
            }
            if self.file.is_none() && entry.hardlink_is_set() != 0 && self.limit != Some(0) {
                match target.open(entry.mode() as u32 & 0o777) {
                    Ok(file) => self.file = Some(file),
                    Err(e) => return failure(a, e, "Can't open", &path),
                }
            }
        }
        self.current = Some((path, entry, target, self.options));
        a.state.set(state::DATA);
        a.file_count.set(a.file_count.get() + 1);
        ARCHIVE_OK
    }

    pub fn data(&mut self, a: &Base, data: &[u8]) -> isize {
        if a.check_magic(
            crate::archive::WRITE_DISK_MAGIC,
            state::DATA,
            "archive_write_data",
        ) < ARCHIVE_OK
        {
            return crate::archive::ARCHIVE_FATAL as isize;
        }
        if !data.is_empty() && (self.limit == Some(0) || (!self.skipped && self.file.is_none())) {
            return a.warn(0, "Attempt to write to an empty file").code() as isize;
        }
        let len = self.limit.map_or(data.len(), |n| {
            data.len().min(n.saturating_sub(self.offset) as usize)
        });
        if self.skipped {
            self.offset += len as u64;
            return len as isize;
        }
        let Some(file) = &mut self.file else {
            return 0;
        };
        let result = if self.options & 0x1000 != 0 {
            data[..len].chunks(4096).try_for_each(|chunk| {
                if chunk.iter().all(|&b| b == 0) {
                    file.seek(SeekFrom::Current(chunk.len() as i64)).map(|_| ())
                } else {
                    file.write_all(chunk)
                }
            })
        } else {
            file.write_all(&data[..len])
        };
        match result {
            Ok(()) => {
                self.offset += len as u64;
                self.max_offset = self.max_offset.max(self.offset);
                self.bytes = self.bytes.saturating_add(len as i64);
                len as isize
            }
            Err(e) => a
                .warn(e.raw_os_error().unwrap_or(libc::EIO), "Write failed")
                .code() as isize,
        }
    }

    pub fn data_block(&mut self, a: &Base, data: &[u8], offset: i64) -> c_int {
        let Ok(offset) = u64::try_from(offset) else {
            return a.raise(Error::new(ARCHIVE_FAILED, libc::EINVAL, "Invalid offset"));
        };
        if let Some(file) = &mut self.file
            && let Err(e) = file.seek(SeekFrom::Start(offset))
        {
            return a.raise(Error::new(
                ARCHIVE_FAILED,
                e.raw_os_error().unwrap_or(libc::EIO),
                "Seek failed",
            ));
        }
        self.offset = offset;
        let result = self.data(a, data);
        if result < 0 {
            result as c_int
        } else {
            ARCHIVE_OK
        }
    }

    pub fn finish_entry(&mut self, a: &Base) -> c_int {
        let Some((path, entry, mut target, options)) = self.current.take() else {
            return ARCHIVE_OK;
        };
        a.state.set(state::HEADER);
        if !self.skipped {
            if let Some(file) = self.file.take()
                && let Err(e) = file.set_len(self.limit.unwrap_or(self.max_offset))
            {
                return failure(a, e, "Can't truncate", &path);
            }
            if let Some(destination) = self.atomic.take() {
                if let Err(e) = target.rename_to(&destination) {
                    let _ = target.remove(false);
                    return failure(a, e, "Can't rename temporary file", &path);
                }
                target = destination;
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
                self.directories.push((entry, target, options));
            } else {
                let ret = self.restore(a, &entry, &target, options);
                if ret < 0 {
                    return ret;
                }
            }
        }
        a.state.set(state::HEADER);
        ARCHIVE_OK
    }

    fn restore(&mut self, a: &Base, entry: &Entry, target: &Target, options: c_int) -> c_int {
        if entry.hardlink_is_set() != 0 && (entry.size_is_set() == 0 || entry.size() == 0) {
            return ARCHIVE_OK;
        }
        let mut ret = ARCHIVE_OK;
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
        if entry.filetype() != libc::S_IFLNK || options & PERM != 0 {
            let mut mode = if options & PERM != 0 {
                entry.mode() as u32 & 0o7777
            } else {
                entry.mode() as u32 & 0o777 & !crate::ffi::disk_sys::umask()
            };
            if let Ok(st) = target.stat() {
                if st.st_uid as i64 != entry.uid() {
                    mode &= !0o4000;
                }
                if st.st_gid as i64 != entry.gid() {
                    mode &= !0o2000;
                }
            }
            if let Err(e) = target.chmod(mode) {
                let _ = a
                    .warn(
                        e.raw_os_error().unwrap_or(libc::EPERM),
                        "Can't restore permissions",
                    )
                    .code();
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
        if options & 0x80 != 0
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
        if options & 0x20 != 0
            && let Err(e) = target.metadata_file().and_then(|file| {
                crate::ffi::disk_acl::write(&file, entry, &mut self.user, &mut self.group)
            })
        {
            ret = a
                .warn(e.raw_os_error().unwrap_or(libc::EIO), "Can't restore ACL")
                .code();
        }
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
        if options & 0x2000 != 0
            && let Some(metadata) = entry.mac_metadata()
            && let Err(e) = target.unpack_mac_metadata(metadata)
        {
            let _ = a.warn(
                e.raw_os_error().unwrap_or(libc::EIO),
                "Failed to restore metadata",
            );
            ret = ARCHIVE_WARN;
        }
        if options & 0x40 != 0 {
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
            return crate::archive::ARCHIVE_FATAL;
        }
        let mut ret = self.finish_entry(a);
        while let Some((entry, target, options)) = self.directories.pop() {
            ret = ret.min(self.restore(a, &entry, &target, options));
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
