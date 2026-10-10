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
    file_offset: Option<u64>,
    file_len: Option<u64>,
    limit: Option<u64>,
    skipped: bool,
    atomic: Option<Target>,
    permissions_created: bool,
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
        self.permissions_created = false;
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
        // A successful exclusive create cannot replace an existing inode. Fall back
        // to the original checks on any error, including a racing creation.
        let created_file = if hardlink.is_none()
            && link.is_none()
            && matches!(entry.filetype(), 0 | libc::S_IFREG)
            && self.options & 0x40000 == 0
        {
            target.open(entry.mode() as u32 & 0o777, true).ok()
        } else {
            None
        };
        if created_file.is_none()
            && let Ok(existing) = target.stat()
        {
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
            let result = if let Some(file) = created_file {
                self.file = Some(file);
                // On Apple, creation applies the umask without Linux's default-ACL
                // substitution. Match upstream's creation-time mask for new files.
                self.permissions_created =
                    cfg!(target_vendor = "apple") && self.options & PERM == 0;
                Ok(())
            } else if let Some(source) = hardlink {
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
                        .open(entry.mode() as u32 & 0o777, false)
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
                match target.open(entry.mode() as u32 & 0o777, false) {
                    Ok(file) => self.file = Some(file),
                    Err(e) => return failure(a, e, "Can't open", &path),
                }
            }
        }
        self.file_offset = self.file.as_ref().map(|_| 0);
        self.file_len = self.file.as_ref().map(|_| 0);
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
        let permissions_created = std::mem::take(&mut self.permissions_created);
        if !self.skipped {
            let file = self.file.take();
            let length = self.limit.unwrap_or(self.max_offset);
            if let Some(file) = &file
                && self.file_len != Some(length)
                && let Err(e) = file.set_len(length)
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
                self.directories.push((entry, target, options));
            } else {
                let ret = self.restore(a, &entry, &mut target, options, permissions_created);
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
        permissions_created: bool,
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
        if !permissions_created && (entry.filetype() != libc::S_IFLNK || options & PERM != 0) {
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
        while let Some((entry, mut target, options)) = self.directories.pop() {
            ret = ret.min(self.restore(a, &entry, &mut target, options, false));
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
            assert_eq!(disk.header(base, &entry), ARCHIVE_OK);
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
        for options in [0, PERM, UNLINK, NO_OVERWRITE, 0x40000] {
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
                assert_eq!(disk.header(&base, &entry), ARCHIVE_OK);
                assert_eq!(disk.data(&base, b"new"), 3);
                assert_eq!(disk.finish_entry(&base), ARCHIVE_OK);
                let skipped = existing && options == NO_OVERWRITE;
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
