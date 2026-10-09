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

use crate::archive::{ARCHIVE_FAILED, ARCHIVE_OK, ARCHIVE_WARN, Base, state};
use crate::entry::Entry;
use crate::util::Error;
use std::ffi::c_int;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
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
    pub skip_file: Option<(i64, i64)>,
    file: Option<File>,
    current: Option<(PathBuf, Entry)>,
    directories: Vec<(PathBuf, Entry)>,
    offset: u64,
    limit: Option<u64>,
    skipped: bool,
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
                ARCHIVE_FAILED,
                "Path is absolute",
            ));
        }
        if self.options & SECURE_NODOTDOT != 0
            && path.components().any(|c| c == Component::ParentDir)
        {
            return a.raise(Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_FAILED,
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
                    ARCHIVE_FAILED,
                    "Path is absolute",
                ));
            }
            if self.options & SECURE_NODOTDOT != 0
                && target.components().any(|c| c == Component::ParentDir)
            {
                return a.raise(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_FAILED,
                    "Path contains '..'",
                ));
            }
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if self.options & SECURE_SYMLINKS != 0 {
                let mut prefix = PathBuf::new();
                for component in parent.components() {
                    prefix.push(component.as_os_str());
                    if fs::symlink_metadata(&prefix).is_ok_and(|m| m.file_type().is_symlink()) {
                        if self.options & UNLINK == 0 {
                            return a.raise(Error::new(
                                ARCHIVE_FAILED,
                                libc::EPERM,
                                "Cannot extract through symlink",
                            ));
                        }
                        if let Err(e) = fs::remove_file(&prefix) {
                            return failure(a, e, "Can't unlink", &prefix);
                        }
                    }
                }
            }
            if self.options & NO_AUTODIR == 0
                && let Err(e) = fs::create_dir_all(parent)
            {
                return failure(a, e, "Can't create", parent);
            }
        }
        if let Ok(existing) = fs::symlink_metadata(&path) {
            if self.skip_file == Some((existing.dev() as i64, existing.ino() as i64)) {
                return a.raise(Error::new(
                    ARCHIVE_FAILED,
                    libc::EPERM,
                    "Refusing to overwrite archive",
                ));
            }
            if self.options & NO_OVERWRITE != 0
                || (self.options & NO_OVERWRITE_NEWER != 0 && existing.mtime() > entry.mtime())
            {
                self.skipped = true;
            } else if !(existing.is_dir() && entry.filetype() == libc::S_IFDIR)
                && (self.options & UNLINK != 0
                    || existing.file_type().is_symlink()
                    || hardlink.is_some()
                    || link.is_some())
            {
                let result = if existing.is_dir() {
                    fs::remove_dir(&path)
                } else {
                    fs::remove_file(&path)
                };
                if let Err(e) = result {
                    return failure(a, e, "Can't unlink", &path);
                }
            }
        }
        self.offset = 0;
        self.limit = (entry.size_is_set() != 0).then(|| entry.size().max(0) as u64);
        if !self.skipped {
            let result = if let Some(target) = hardlink {
                fs::hard_link(&target, &path)
            } else if let Some(target) = link {
                self.limit = Some(0);
                symlink(target, &path)
            } else if entry.filetype() == libc::S_IFDIR {
                self.limit = Some(0);
                match fs::create_dir(&path) {
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {
                        Ok(())
                    }
                    result => result,
                }
            } else if entry.filetype() == libc::S_IFREG || entry.filetype() == 0 {
                let mode = entry.mode() as u32 & 0o777;
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(mode)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&path)
                    .map(|file| {
                        self.file = Some(file);
                    })
            } else {
                Err(std::io::Error::from_raw_os_error(libc::ENOTSUP))
            };
            if let Err(e) = result {
                return failure(a, e, "Can't create", &path);
            }
            // Hard links carrying data replace the linked contents.
            if self.file.is_none() && entry.hardlink_is_set() != 0 && self.limit != Some(0) {
                match OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&path)
                {
                    Ok(file) => self.file = Some(file),
                    Err(e) => return failure(a, e, "Can't open", &path),
                }
            }
        }
        self.current = Some((path, entry));
        a.state.set(state::DATA);
        a.file_count.set(a.file_count.get() + 1);
        ARCHIVE_OK
    }

    pub fn data(&mut self, a: &Base, data: &[u8]) -> isize {
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
        match file.write_all(&data[..len]) {
            Ok(()) => {
                self.offset += len as u64;
                len as isize
            }
            Err(e) => a.raise(Error::new(
                ARCHIVE_WARN,
                e.raw_os_error().unwrap_or(libc::EIO),
                "Write failed",
            )) as isize,
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
        let Some((path, entry)) = self.current.take() else {
            return ARCHIVE_OK;
        };
        if !self.skipped {
            if let Some(file) = self.file.take()
                && let Some(size) = self.limit
                && let Err(e) = file.set_len(size)
            {
                return failure(a, e, "Can't truncate", &path);
            }
            if entry.filetype() == libc::S_IFDIR {
                self.directories.push((path, entry));
            } else {
                let ret = self.restore(a, &path, &entry);
                if ret < 0 {
                    return ret;
                }
            }
        }
        a.state.set(state::HEADER);
        ARCHIVE_OK
    }

    fn restore(&self, a: &Base, path: &Path, entry: &Entry) -> c_int {
        if entry.filetype() != libc::S_IFLNK
            && self.options & PERM != 0
            && let Err(e) = fs::set_permissions(
                path,
                fs::Permissions::from_mode(entry.mode() as u32 & 0o7777),
            )
        {
            return failure(a, e, "Can't set permissions", path);
        }
        ARCHIVE_OK
    }

    pub fn close(&mut self, a: &Base) -> c_int {
        let mut ret = self.finish_entry(a);
        while let Some((path, entry)) = self.directories.pop() {
            ret = ret.min(self.restore(a, &path, &entry));
        }
        a.state.set(state::CLOSED);
        ret
    }
}
