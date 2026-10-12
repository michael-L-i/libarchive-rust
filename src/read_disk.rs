/*-
 * Copyright (c) 2003-2009 Tim Kientzle
 * Copyright (c) 2010-2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_read_disk_posix.c.

use crate::api::read_disk::DiskMatcher;
use crate::archive::{ARCHIVE_EOF, ARCHIVE_FAILED, ARCHIVE_OK, ARCHIVE_WARN, Base, Handle, state};
use crate::entry::Entry;
use crate::ffi::disk_sys::{self, Filesystem};
use crate::util::Error;
use std::collections::VecDeque;
use std::ffi::c_int;
#[cfg(test)]
use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// The (dev, ino) of each directory above a path, which catch symlink loops.
type Ancestors = Vec<(u64, u64)>;
/// A path to visit, whether it is the root, and its ancestors.
type Pending = (PathBuf, bool, Ancestors, disk_sys::ReadPath);

/// `archive_read_disk_set_metadata_filter_callback`'s filter: whether to
/// return the entry. Through `Base` it can ask to descend into it.
pub type MetadataFilter = Box<dyn FnMut(&Base, &mut Entry) -> bool>;

/// `archive_read_disk_set_matching`'s callback, which sees each entry the
/// match handle excludes.
pub type ExcludedCallback = Box<dyn FnMut(&Base, &mut Entry)>;

/// Upstream's struct restore_time: the access and modification times,
/// each (seconds, nanoseconds), to put back on what was read, and whether
/// reading it left them alone.
#[derive(Clone, Copy, Default)]
struct RestoreTime {
    atime: (i64, i64),
    mtime: (i64, i64),
    noatime: bool,
}

/// A directory `descend` asked for, upstream's tree_entry: read after the
/// one being read, then, once everything below it is done, left, which
/// puts back its times.
struct Dir {
    path: PathBuf,
    ancestors: Ancestors,
    restore: RestoreTime,
    restore_file: Option<File>,
    access: disk_sys::ReadPath,
    stat: libc::stat,
    follow: bool,
    anchor: Option<Rc<File>>,
    read: bool,
}

#[derive(Default)]
pub struct ReadDisk {
    pub symlinks: u8,
    pub behavior: c_int,
    pub user: crate::ffi::disk::NameLookup,
    pub group: crate::ffi::disk::NameLookup,
    pub metadata_filter: Option<MetadataFilter>,
    pub matching: Option<DiskMatcher>,
    pub excluded: Option<ExcludedCallback>,
    /// The entry `archive_read_next_header` hands to C, which
    /// `archive_read_disk_new` makes and `archive_free` frees; NULL for a
    /// handle that is not C's.
    pub(crate) entry: *mut Entry,
    /// The path `open` was given, until it is visited.
    root: Option<PathBuf>,
    initial: Option<Rc<File>>,
    /// Directories `descend` asked for, the most recent last: upstream's
    /// tree stack. One being read stays under those it asks for.
    stack: Vec<Dir>,
    /// The directory whose entries are being visited, in readdir order.
    reading: Option<(disk_sys::ReadDir, PathBuf, Ancestors, Rc<File>)>,
    current_access: Option<disk_sys::ReadPath>,
    current_stat: Option<libc::stat>,
    current_follow: bool,
    current_dir: Option<Rc<File>>,
    current: Option<PathBuf>,
    ancestors: Ancestors,
    /// The current entry's times, which its data and a descent into it
    /// take.
    restore: RestoreTime,
    can_descend: bool,
    /// The current file's data, opened when it is first read.
    file: Option<File>,
    /// Whether the current entry has no (more) data to open.
    eof: bool,
    block: Vec<u8>,
    /// How far into the current file's data reading is, and how much of
    /// it is left (upstream's entry_total and entry_remaining_bytes).
    offset: i64,
    remaining: i64,
    size: i64,
    /// Upstream's sparse list from the region being read on: each region
    /// (offset, length) to read, the end of a file with holes marked by
    /// an empty region at its size.
    regions: VecDeque<(i64, i64)>,
    pub filesystem: c_int,
    filesystems: Vec<(u64, Option<Filesystem>)>,
}

impl ReadDisk {
    pub fn new() -> Self {
        Self {
            behavior: 4,
            ..Self::default()
        }
    }
    pub fn entry(&self) -> *mut Entry {
        self.entry
    }
    pub fn take_entry(&mut self) -> *mut Entry {
        std::mem::replace(&mut self.entry, std::ptr::null_mut())
    }
    pub fn open(&mut self, a: &Base, path: &[u8]) -> c_int {
        // Upstream's tree_append strips trailing '/', unless the name is "/".
        let mut path = path;
        while let [rest @ .., b'/'] = path
            && !rest.is_empty()
        {
            path = rest;
        }
        self.initial = match disk_sys::ReadPath::initial_dir() {
            Ok(dir) => Some(dir),
            Err(e) => return io_error(a, e, "Can't open initial directory"),
        };
        self.root = Some(PathBuf::from(std::ffi::OsStr::from_bytes(path)));
        self.stack.clear();
        self.reading = None;
        a.state.set(state::HEADER);
        ARCHIVE_OK
    }
    pub fn descend(&mut self, a: &Base) -> c_int {
        if !self.can_descend {
            return ARCHIVE_OK;
        }
        self.can_descend = false;
        a.disk_can_descend.set(false);
        let Some(path) = &self.current else {
            return ARCHIVE_OK;
        };
        let (Some(access), Some(stat)) = (&self.current_access, self.current_stat) else {
            return ARCHIVE_OK;
        };
        self.stack.push(Dir {
            path: path.clone(),
            ancestors: self.ancestors.clone(),
            restore: self.restore,
            restore_file: None,
            access: access.clone(),
            stat,
            follow: self.current_follow,
            anchor: self.current_dir.clone(),
            read: false,
        });
        ARCHIVE_OK
    }
    /// The next path to visit, in upstream's `tree_next` order: the root,
    /// then each directory's entries as readdir returns them, a directory
    /// that `descend` asked for being read only after the one being read,
    /// the most recent request first. A directory that can't be read is
    /// skipped and fails the call that reaches it, as TREE_ERROR_DIR does.
    /// One that was read is left once everything below it is done, which
    /// puts back its times, as tree_ascend does.
    fn next_path(&mut self, a: &Base) -> Result<Option<Pending>, c_int> {
        if let Some(root) = self.root.take() {
            let initial = self.initial.clone().ok_or(ARCHIVE_FAILED)?;
            let access = disk_sys::ReadPath::root(initial, &root)
                .map_err(|e| path_failure(a, &root, e, b"Cannot stat"))?;
            return Ok(Some((root, true, Vec::new(), access)));
        }
        loop {
            if let Some((dir, path, ancestors, anchor)) = &mut self.reading {
                match dir.next() {
                    Some(Ok(child)) => {
                        let access = disk_sys::ReadPath::child(anchor.clone(), child.as_bytes())
                            .map_err(|e| path_failure(a, path, e, b"Cannot stat"))?;
                        return Ok(Some((path.join(child), false, ancestors.clone(), access)));
                    }
                    Some(Err(e)) => {
                        let path = std::mem::take(path);
                        self.reading = None;
                        return Err(path_failure(a, &path, e, b"Couldn't visit directory"));
                    }
                    None => self.reading = None,
                }
            }
            let Some(top) = self.stack.last_mut() else {
                return Ok(None);
            };
            if top.read {
                if let Some(dir) = self.stack.pop()
                    && self.needs_restore(dir.restore)
                    && let Some(file) = dir.restore_file
                {
                    let _ = disk_sys::restore_times(&file, dir.restore.atime, dir.restore.mtime);
                }
                continue;
            }
            top.read = true;
            let opened = top
                .anchor
                .clone()
                .map(Ok)
                .unwrap_or_else(|| top.access.directory(top.follow, &top.stat));
            match opened.and_then(|anchor| {
                disk_sys::ReadDir::open(&anchor).map(|(dir, file)| (anchor, dir, file))
            }) {
                Ok((anchor, dir, file)) => {
                    top.restore_file = Some(file);
                    self.reading = Some((dir, top.path.clone(), top.ancestors.clone(), anchor));
                }
                Err(e) => {
                    let path = self.stack.pop().map(|dir| dir.path).unwrap_or_default();
                    return Err(path_failure(a, &path, e, b"Couldn't visit directory"));
                }
            }
        }
    }
    pub fn next_header2(&mut self, a: &Base, entry: &mut Entry) -> c_int {
        if a.check_magic(
            crate::archive::READ_DISK_MAGIC,
            state::HEADER | state::DATA,
            "archive_read_next_header2",
        ) != ARCHIVE_OK
        {
            return crate::archive::ARCHIVE_FATAL;
        }
        a.clear_error();
        self.close_data();
        self.current_access = None;
        self.current_stat = None;
        self.current_dir = None;
        entry.clear();
        self.block.clear();
        self.offset = 0;
        // Paths below the root that vanished before they could be visited,
        // reported with the next entry; a skipped entry drops them, as each
        // of upstream's next_entry() calls starts afresh.
        let mut removed = Vec::new();
        let mut keep_removed = false;
        loop {
            if !std::mem::take(&mut keep_removed) {
                removed.clear();
            }
            self.can_descend = false;
            a.disk_can_descend.set(false);
            a.disk_descend_requested.set(false);
            let (path, root, ancestors, mut access_path) = match self.next_path(a) {
                Ok(Some(next)) => next,
                Ok(None) => {
                    a.state.set(state::EOF);
                    return ARCHIVE_EOF;
                }
                Err(ret) => return ret,
            };
            let lst = match access_path.stat(false) {
                Ok(st) => st,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) && !root => {
                    if !removed.is_empty() {
                        removed.push(b' ');
                    }
                    removed.extend_from_slice(path.as_os_str().as_bytes());
                    keep_removed = true;
                    continue;
                }
                Err(e) => return path_failure(a, &path, e, b"Cannot stat"),
            };
            if lst.st_mode & libc::S_IFMT == libc::S_IFLNK
                && let Err(e) = access_path.pin_link(&lst)
            {
                return path_failure(a, &path, e, b"Cannot stat");
            }
            if self.behavior & 4 != 0
                && path
                    .file_name()
                    .is_some_and(|n| n.as_bytes().starts_with(b"._"))
            {
                continue;
            }
            entry.clear();
            entry.set_pathname(path.as_os_str().as_bytes());
            self.current = Some(path.clone());
            self.current_access = Some(access_path.clone());
            self.current_stat = None;
            self.current_dir = None;
            self.ancestors = ancestors;
            match self.excluded(a, entry, |m, e| m.match_path_excluded(Some(e))) {
                Ok(false) => {}
                Ok(true) => continue,
                Err(r) => return r,
            }
            // Following symlinks, archive the target unless the link is
            // broken or loops back to a parent; then the link itself.
            let follow = self.symlinks == 1 || (self.symlinks == 2 && root);
            let (st, followed) = if follow {
                match access_path.stat(true) {
                    Ok(st)
                        if !(st.st_mode & libc::S_IFMT == libc::S_IFDIR
                            && self.ancestors.contains(&(st.st_dev as u64, st.st_ino))) =>
                    {
                        (st, true)
                    }
                    _ => (lst, false),
                }
            } else {
                (lst, false)
            };
            #[cfg(target_os = "linux")]
            if let Err(e) = access_path.pin_metadata(&st, followed) {
                return path_failure(a, &path, e, b"Cannot stat");
            }
            self.current_access = Some(access_path.clone());
            self.current_stat = Some(st);
            self.current_follow = followed;
            self.current_dir = if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                access_path.directory(followed, &st).ok()
            } else {
                None
            };
            let fsid = st.st_dev as u64;
            let filesystem = match self.filesystems.iter().position(|&(id, _)| id == fsid) {
                Some(n) => n,
                None => {
                    self.filesystems.push((fsid, None));
                    self.filesystems.len() - 1
                }
            };
            self.filesystem = filesystem as c_int;
            a.disk_filesystem.set(self.filesystem);
            // Only filesystem probing and nodump need a readable file before
            // callbacks; normal metadata opens freshly after callbacks.
            let metadata_early = self.filesystems[filesystem].1.is_none();
            #[cfg(target_os = "linux")]
            let metadata_early = metadata_early || self.behavior & 2 != 0;
            let metadata_file = if metadata_early
                && matches!(st.st_mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFDIR)
            {
                access_path.open(libc::O_NONBLOCK, followed, &st).ok()
            } else {
                None
            };
            #[cfg(target_vendor = "apple")]
            let metadata_file = metadata_file.or_else(|| {
                if !metadata_early
                    && matches!(st.st_mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFDIR)
                {
                    return None;
                }
                if st.st_mode & libc::S_IFMT == libc::S_IFLNK
                    && let Some(link) = access_path.link_file()
                {
                    return link.try_clone().ok();
                }
                let flags = if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
                    libc::O_SYMLINK
                } else {
                    libc::O_EVTONLY
                };
                access_path
                    .open(flags | libc::O_NONBLOCK, followed, &st)
                    .ok()
            });
            entry.copy_stat(&st);
            #[cfg(target_vendor = "apple")]
            if self.behavior & 0x40 == 0 {
                entry.set_fflags(st.st_flags.into(), 0);
            }
            let probe = &mut self.filesystems[filesystem].1;
            let fs = match *probe {
                Some(fs) => fs,
                None => {
                    // Upstream asks about the directory being read (the
                    // working directory for the root), or a symlink's
                    // target on another file system.
                    #[cfg(target_os = "linux")]
                    let inspect = if followed && st.st_dev != lst.st_dev {
                        metadata_file.as_ref().unwrap_or(access_path.parent())
                    } else if root {
                        self.initial.as_deref().unwrap_or(access_path.parent())
                    } else {
                        access_path.parent()
                    };
                    #[cfg(not(target_os = "linux"))]
                    let inspect = metadata_file.as_ref().unwrap_or(access_path.parent());
                    let found = disk_sys::filesystem_fd(inspect);
                    match found {
                        Ok(fs) => {
                            *probe = Some(fs);
                            fs
                        }
                        Err((e, msg)) => {
                            a.state.set(state::FATAL);
                            return a
                                .raise(Error::fatal(e.raw_os_error().unwrap_or(libc::EIO), msg));
                        }
                    }
                }
            };
            a.disk_remote.set(fs.remote);
            a.disk_synthetic.set(fs.synthetic);
            self.can_descend = entry.filetype() == libc::S_IFDIR
                && !(self.behavior & 8 != 0 && self.filesystem != 0);
            a.disk_can_descend.set(self.can_descend);
            if self.can_descend {
                self.ancestors.push((st.st_dev as u64, st.st_ino));
            }
            // Honor nodump flag. Linux reads it through a descriptor, which
            // then serves the rest of the metadata.
            #[cfg(target_vendor = "apple")]
            if self.behavior & 2 != 0 && st.st_flags & libc::UF_NODUMP != 0 {
                continue;
            }
            #[cfg(target_os = "linux")]
            if self.behavior & 2 != 0
                && metadata_file.as_ref().is_some_and(|file| {
                    disk_sys::get_flags(file.as_raw_fd())
                        .is_ok_and(|flags| flags & disk_sys::FS_NODUMP_FL != 0)
                })
            {
                continue;
            }
            self.restore = RestoreTime {
                atime: (entry.atime(), entry.atime_nsec()),
                mtime: (entry.mtime(), entry.mtime_nsec()),
                noatime: fs.noatime,
            };
            match self.excluded(a, entry, |m, e| m.match_time_excluded(Some(e))) {
                Ok(false) => {}
                Ok(true) => continue,
                Err(r) => return r,
            }
            if let Some(name) = self.user.lookup(entry.uid(), false) {
                entry.set_uname(name.to_bytes());
            }
            if let Some(name) = self.group.lookup(entry.gid(), true) {
                entry.set_gname(name.to_bytes());
            }
            match self.excluded(a, entry, |m, e| m.match_owner_excluded(Some(e))) {
                Ok(false) => {}
                Ok(true) => continue,
                Err(r) => return r,
            }
            let include = self.metadata_filter.as_mut().is_none_or(|f| f(a, entry));
            if a.disk_descend_requested.take() {
                let ret = self.descend(a);
                if ret < 0 {
                    return ret;
                }
            }
            if !include {
                continue;
            }
            entry.set_sourcepath(path.as_os_str().as_bytes());
            // Upstream names the file in its messages as it reached it: by
            // its name in the directory being read.
            let access = path
                .file_name()
                .filter(|_| !root)
                .unwrap_or(path.as_os_str());
            // Open metadata after callbacks, but verify the inode selected by stat.
            let metadata_file =
                if matches!(st.st_mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFDIR)
                    || matches!(entry.filetype(), libc::S_IFREG | libc::S_IFDIR)
                {
                    access_path
                        .open(libc::O_NONBLOCK, followed, &st)
                        .ok()
                        .or_else(|| {
                            self.current_dir
                                .as_ref()
                                .and_then(|dir| dir.try_clone().ok())
                        })
                } else {
                    metadata_file
                };
            let ret = self.fill_metadata_at(
                a,
                entry,
                &path,
                followed,
                metadata_file.as_ref().map(AsRawFd::as_raw_fd),
                access.as_bytes(),
                Some((&access_path, &st)),
            );
            if ret < ARCHIVE_WARN {
                return ret;
            }
            self.size = if entry.filetype() == libc::S_IFREG {
                entry.size()
            } else {
                0
            };
            self.remaining = self.size;
            self.eof = self.remaining <= 0;
            self.regions.clear();
            if !self.eof {
                // Upstream's setup_sparse.
                if entry.sparse_count() == 0 {
                    self.regions.push_back((0, self.size));
                } else {
                    self.regions = entry.sparse.iter().map(|s| (s.offset, s.length)).collect();
                    self.regions.push_back((self.size, 0));
                }
            }
            a.file_count.set(a.file_count.get() + 1);
            a.state.set(state::DATA);
            if ret == ARCHIVE_OK && !removed.is_empty() {
                removed.extend_from_slice(b": File removed before we read it");
                return a.warn(libc::ENOENT, removed).code();
            }
            return ret;
        }
    }
    /// Whether the match handle's `test` excludes `entry`, after the
    /// excluded callback has seen it and the walk has descended into it if
    /// the callback asked; or the failure, recorded.
    fn excluded(
        &mut self,
        a: &Base,
        entry: &mut Entry,
        test: impl FnOnce(&Handle, &mut Entry) -> c_int,
    ) -> Result<bool, c_int> {
        let Some(m) = &self.matching else {
            return Ok(false);
        };
        let m = m.handle();
        match test(m, entry) {
            0 => return Ok(false),
            r if r < 0 => {
                a.copy_error(&m.base);
                return Err(r);
            }
            _ => {}
        }
        if let Some(excluded) = &mut self.excluded {
            excluded(a, entry);
        }
        if a.disk_descend_requested.take() {
            let r = self.descend(a);
            if r < 0 {
                return Err(r);
            }
        }
        Ok(true)
    }
    /// Whether times recorded as `rt` are to be put back.
    fn needs_restore(&self, rt: RestoreTime) -> bool {
        self.behavior & 1 != 0 && !rt.noatime
    }
    /// Opens the current file's data, as upstream's
    /// _archive_read_data_block does when first called. On Linux, if its
    /// times are to be restored, it is opened with O_NOATIME, so that they
    /// needn't be; where that fails with EPERM, upstream means to try again
    /// without it but fails (see NOTES.md).
    fn open_data(&mut self, a: &Base) -> Result<(), c_int> {
        if self.file.is_some() || self.eof {
            return Ok(());
        }
        let Some(path) = &self.current else {
            return Ok(());
        };
        #[cfg(target_os = "linux")]
        let flags = if self.needs_restore(self.restore) {
            libc::O_NOATIME
        } else {
            0
        };
        #[cfg(not(target_os = "linux"))]
        let flags = 0;
        let opened = match (&self.current_access, &self.current_stat) {
            (Some(access), Some(st)) => {
                access.open(flags | libc::O_NONBLOCK, self.current_follow, st)
            }
            _ => Err(std::io::Error::from_raw_os_error(libc::ESTALE)),
        };
        match opened {
            Ok(file) => {
                self.restore.noatime |= flags != 0;
                self.file = Some(file);
                Ok(())
            }
            Err(e) => {
                let msg = [b"Couldn't open ", path.as_os_str().as_bytes()].concat();
                let errno = e.raw_os_error().unwrap_or(libc::EIO);
                Err(a.raise(Error::new(ARCHIVE_FAILED, errno, msg)))
            }
        }
    }
    /// Closes the current file's data, putting back its times.
    fn close_data(&mut self) {
        if let Some(file) = self.file.take()
            && self.needs_restore(self.restore)
        {
            let _ = disk_sys::restore_times(&file, self.restore.atime, self.restore.mtime);
        }
    }
    /// Upstream's `archive_read_disk_entry_from_file` after the stat: names,
    /// Linux's file flags, the link target, then ACLs, extended attributes,
    /// Mac metadata and sparse extents; a failure among those last four
    /// warns or fails but the rest are still read, and the worst result is
    /// returned. On Linux these go through `fd`, or one opened for the
    /// flags; `access` is the path upstream's messages name.
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    pub fn fill_metadata(
        &mut self,
        a: &Base,
        entry: &mut Entry,
        path: &Path,
        follow: bool,
        fd: Option<c_int>,
        access: &[u8],
    ) -> c_int {
        self.fill_metadata_at(a, entry, path, follow, fd, access, None)
    }
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    fn fill_metadata_at(
        &mut self,
        a: &Base,
        entry: &mut Entry,
        path: &Path,
        follow: bool,
        fd: Option<c_int>,
        access: &[u8],
        anchored: Option<(&disk_sys::ReadPath, &libc::stat)>,
    ) -> c_int {
        if let Some(name) = self.user.lookup(entry.uid(), false) {
            entry.set_uname(name.to_bytes());
        }
        if let Some(name) = self.group.lookup(entry.gid(), true) {
            entry.set_gname(name.to_bytes());
        }
        #[cfg(target_vendor = "apple")]
        if anchored.is_some()
            && fd.is_none()
            && (self.behavior & 0x20 == 0
                || self.behavior & 0x10 == 0
                || self.behavior & 4 != 0
                || (self.behavior & 0x80 == 0 && entry.filetype() == libc::S_IFREG))
        {
            return failure(
                a,
                ARCHIVE_WARN,
                std::io::Error::from_raw_os_error(libc::EACCES),
                b"Couldn't open metadata descriptor",
            );
        }
        #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
        if anchored.is_some()
            && fd.is_none()
            && self.behavior & 0x80 == 0
            && entry.filetype() == libc::S_IFREG
        {
            // Sparse discovery must not reopen the unanchored display path.
            return failure(
                a,
                ARCHIVE_WARN,
                std::io::Error::from_raw_os_error(libc::EACCES),
                b"Couldn't open metadata descriptor",
            );
        }
        // Linux takes a descriptor to read the file flags, which then
        // serves the rest of the metadata too.
        #[cfg(target_os = "linux")]
        let read_flags =
            self.behavior & 0x40 == 0 && matches!(entry.filetype(), libc::S_IFREG | libc::S_IFDIR);
        #[cfg(target_os = "linux")]
        let opened;
        #[cfg(target_os = "linux")]
        let fd = match fd {
            None if read_flags => {
                opened = anchored
                    .map_or_else(
                        || disk_sys::open_read(path, libc::O_NONBLOCK),
                        |(access, st)| access.open(libc::O_NONBLOCK, follow, st),
                    )
                    .ok();
                opened.as_ref().map(AsRawFd::as_raw_fd)
            }
            fd => fd,
        };
        #[cfg(target_os = "linux")]
        if read_flags
            && let Some(flags) = fd.and_then(|fd| disk_sys::get_flags(fd).ok())
            && flags != 0
        {
            entry.set_fflags(flags as c_int as std::ffi::c_ulong, 0);
        }
        if entry.filetype() == libc::S_IFLNK {
            match anchored.map_or_else(
                || std::fs::read_link(path),
                |(access, st)| access.read_link(st),
            ) {
                Ok(p) => entry.set_symlink(p.as_os_str().as_bytes()),
                Err(e) => return io_error(a, e, "Couldn't read link data"),
            }
        }
        // Linux cannot query symlink xattrs through an O_PATH descriptor.
        // Bracket anchored name lookups to detect replacement; an ABA swap
        // during the native xattr calls can still evade these checks.
        #[cfg(target_os = "linux")]
        if self.behavior & 0x10 == 0
            && entry.filetype() == libc::S_IFLNK
            && let Some((access, st)) = anchored
            && let Err(e) = access.verify_name(st, false)
        {
            return failure(a, ARCHIVE_WARN, e, b"Couldn't list extended attributes");
        }
        let mut ret = ARCHIVE_OK;
        #[cfg(target_vendor = "apple")]
        if self.behavior & 0x20 == 0
            && let Err(e) =
                crate::ffi::disk_acl::read(path, entry, &mut self.user, &mut self.group, fd)
        {
            ret = ret.min(failure(
                a,
                ARCHIVE_WARN,
                e,
                b"Couldn't translate NFSv4 ACLs",
            ));
        }
        #[cfg(target_os = "linux")]
        let metadata_path = fd
            .map(|fd| PathBuf::from(format!("/proc/self/fd/{fd}")))
            .or_else(|| anchored.map(|(access, _)| access.metadata_path()));
        #[cfg(target_os = "linux")]
        let follow = follow || anchored.is_some_and(|(access, _)| access.metadata_follows());
        #[cfg(target_os = "linux")]
        let cpath = disk_sys::path_c(metadata_path.as_deref().unwrap_or(path)).ok();
        #[cfg(target_os = "linux")]
        if self.behavior & 0x20 == 0
            && let Some(cpath) = &cpath
        {
            let (user, group) = (&mut self.user, &mut self.group);
            crate::ffi::disk_acl_linux::read(entry, fd, cpath, follow, user, group);
        }
        #[cfg(target_vendor = "apple")]
        if self.behavior & 0x10 == 0
            && let Err((e, msg)) = disk_sys::read_xattrs_fd(path, entry, follow, fd)
        {
            ret = ret.min(failure(a, ARCHIVE_WARN, e, msg.as_bytes()));
        }
        #[cfg(target_os = "linux")]
        if self.behavior & 0x10 == 0
            && let Some(cpath) = &cpath
        {
            let source = match fd {
                Some(fd) => disk_sys::Source::Fd(fd),
                None => disk_sys::Source::Path(cpath, follow),
            };
            ret = ret.min(setup_xattrs(a, entry, source));
        }
        if self.behavior & 4 != 0
            && let Err(e) = disk_sys::pack_mac_metadata(path, entry, fd)
        {
            ret = ret.min(failure(a, ARCHIVE_FAILED, e, b"Can't read Mac metadata"));
        }
        #[cfg(not(target_os = "linux"))]
        if self.behavior & 0x80 == 0 && entry.filetype() == libc::S_IFREG {
            match disk_sys::sparse(path, self.symlinks != 0, entry.size(), fd) {
                Ok(extents) => {
                    for (offset, len) in extents {
                        entry.sparse_add(offset, len);
                    }
                }
                Err(e) => ret = ret.min(failure(a, ARCHIVE_FAILED, e, b"Can't read sparse data")),
            }
        }
        #[cfg(target_os = "linux")]
        if self.behavior & 0x80 == 0 {
            ret = ret.min(setup_sparse(
                a,
                entry,
                fd,
                metadata_path.as_deref().unwrap_or(path),
                access,
            ));
        }
        #[cfg(target_os = "linux")]
        if self.behavior & 0x10 == 0
            && entry.filetype() == libc::S_IFLNK
            && let Some((access, st)) = anchored
            && let Err(e) = access.verify_name(st, false)
        {
            entry.xattrs.clear();
            ret = ret.min(failure(
                a,
                ARCHIVE_WARN,
                e,
                b"Couldn't retrieve extended attributes",
            ));
        }
        ret
    }
    pub fn data(&mut self, a: &Base, dest: &mut [u8]) -> isize {
        if a.check_magic(
            crate::archive::READ_DISK_MAGIC,
            state::DATA,
            "archive_read_data_block",
        ) != ARCHIVE_OK
        {
            return crate::archive::ARCHIVE_FATAL as isize;
        }
        if let Err(code) = self.open_data(a) {
            return code as isize;
        }
        let Some(file) = &mut self.file else {
            return 0;
        };
        let len = dest
            .len()
            .min(self.size.saturating_sub(self.offset).max(0) as usize);
        match file.read(&mut dest[..len]) {
            Ok(n) => {
                self.offset += n as i64;
                if n == 0 || self.offset >= self.size {
                    self.close_data();
                    self.eof = true;
                }
                n as isize
            }
            Err(e) => io_error(a, e, "Read failed") as isize,
        }
    }
    /// Upstream's _archive_read_data_block: the status, the next block of
    /// the current file's data and its offset, which skips the holes; an
    /// empty region gives an empty block, so that a file that is all hole
    /// has one. A handle not reading data gets the status alone.
    pub fn data_block(&mut self, a: &Base) -> Result<(c_int, &[u8], i64), c_int> {
        if a.check_magic(
            crate::archive::READ_DISK_MAGIC,
            state::DATA,
            "archive_read_data_block",
        ) != ARCHIVE_OK
        {
            return Err(crate::archive::ARCHIVE_FATAL);
        }
        if self.eof || self.remaining <= 0 {
            return Ok(self.abort(ARCHIVE_EOF));
        }
        if let Err(code) = self.open_data(a) {
            return Ok(self.abort(code));
        }
        let Some(&(offset, length)) = self.regions.front() else {
            return Ok(self.abort(ARCHIVE_EOF));
        };
        let fatal = |e: std::io::Error, msg: &str| {
            a.state.set(state::FATAL);
            a.raise(Error::fatal(e.raw_os_error().unwrap_or(libc::EIO), msg))
        };
        // Skip hole.
        if offset > self.offset {
            if let Some(file) = &mut self.file
                && let Err(e) = file.seek(SeekFrom::Start(offset as u64))
            {
                let code = fatal(e, "Seek error");
                return Ok(self.abort(code));
            }
            self.remaining -= offset - self.offset;
            self.offset = offset;
        }
        let block_size = self
            .filesystems
            .get(self.filesystem as usize)
            .and_then(|(_, fs)| fs.as_ref())
            .map_or(64 * 1024, |fs| fs.block_size);
        self.block
            .resize(block_size.min(usize::try_from(length).unwrap_or(0)), 0);
        let n = match &mut self.file {
            Some(file) if !self.block.is_empty() => match file.read(&mut self.block) {
                Ok(n) => n,
                Err(e) => {
                    let code = fatal(e, "Read error");
                    return Ok(self.abort(code));
                }
            },
            _ => 0,
        };
        // An empty region is no end of the data.
        if n == 0 && length != 0 {
            self.eof = true;
            return Ok(self.abort(ARCHIVE_EOF));
        }
        let at = self.offset;
        self.offset += n as i64;
        self.remaining -= n as i64;
        if self.remaining == 0 {
            self.close_data();
            self.eof = true;
        }
        if let Some(region) = self.regions.front_mut() {
            region.0 += n as i64;
            region.1 -= n as i64;
            if region.1 == 0 && !self.eof {
                self.regions.pop_front();
            }
        }
        self.block.truncate(n);
        Ok((ARCHIVE_OK, &self.block, at))
    }
    /// Upstream's abort_read_data: no block, at the offset reached.
    fn abort(&mut self, code: c_int) -> (c_int, &'static [u8], i64) {
        self.close_data();
        (code, &[], self.offset)
    }
    pub fn skip(&mut self, a: &Base) -> c_int {
        if a.check_magic(
            crate::archive::READ_DISK_MAGIC,
            state::DATA | state::DATA_RECOVERY,
            "archive_read_data_skip",
        ) != ARCHIVE_OK
        {
            return crate::archive::ARCHIVE_FATAL;
        }
        self.close_data();
        self.eof = true;
        a.state.set(state::HEADER);
        ARCHIVE_OK
    }
    /// Upstream's tree_close: the directories not yet left keep the times
    /// reading them gave them.
    pub fn close(&mut self, a: &Base) -> c_int {
        self.close_data();
        self.root = None;
        self.initial = None;
        self.current_access = None;
        self.current_stat = None;
        self.current_dir = None;
        self.stack.clear();
        self.reading = None;
        a.state.set(state::CLOSED);
        ARCHIVE_OK
    }
}

/// Upstream's "<path>: <what>" failure for a path the walk can't use.
fn path_failure(a: &Base, path: &Path, e: std::io::Error, what: &[u8]) -> c_int {
    let msg = [path.as_os_str().as_bytes(), b": ", what].concat();
    a.raise(Error::new(
        ARCHIVE_FAILED,
        e.raw_os_error().unwrap_or(libc::EIO),
        msg,
    ))
}

pub fn io_error(a: &Base, e: std::io::Error, msg: &str) -> c_int {
    a.raise(Error::new(
        ARCHIVE_FAILED,
        e.raw_os_error().unwrap_or(libc::EIO),
        msg,
    ))
}

/// Records why some metadata couldn't be read, warning or failing with
/// `code`, which it returns.
fn failure(a: &Base, code: c_int, e: std::io::Error, msg: &[u8]) -> c_int {
    let errno = e.raw_os_error().unwrap_or(libc::EIO);
    if code == ARCHIVE_WARN {
        a.warn(errno, msg).code()
    } else {
        a.raise(Error::new(code, errno, msg))
    }
}

/// Upstream's Linux setup_xattrs: adds the extended attributes of `src`,
/// but those that hold ACLs and the obsolete xfsroot namespace. One that
/// can't be read is left out, its error left on the handle.
#[cfg(target_os = "linux")]
fn setup_xattrs(a: &Base, entry: &mut Entry, src: disk_sys::Source) -> c_int {
    let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
    let size = match src.list(&mut []) {
        Ok(0) => return ARCHIVE_OK,
        Ok(size) if size <= 1024 * 1024 => size,
        Ok(_) => {
            return a
                .warn(libc::ENOMEM, "Couldn't list extended attributes")
                .code();
        }
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTSUP | libc::ENOSYS)) => {
            return ARCHIVE_OK;
        }
        Err(e) => return a.warn(errno(e), "Couldn't list extended attributes").code(),
    };
    let mut list = vec![0; size];
    match src.list(&mut list) {
        Ok(len) => list.truncate(len),
        Err(e) => {
            return a
                .warn(errno(e), "Couldn't retrieve extended attributes")
                .code();
        }
    }
    for name in list.split_inclusive(|&b| b == 0) {
        let Ok(name) = std::ffi::CStr::from_bytes_until_nul(name) else {
            continue;
        };
        let skip: [&[u8]; 4] = [
            // POSIX.1e ACLs.
            b"system.posix_acl_access",
            b"system.posix_acl_default",
            b"trusted.SGI_ACL_DEFAULT",
            b"trusted.SGI_ACL_FILE",
        ];
        // The xfsroot namespace is obsolete and unsupported.
        if skip.contains(&name.to_bytes()) || name.to_bytes().starts_with(b"xfsroot.") {
            continue;
        }
        let value = src
            .get(name, &mut [])
            .map_err(|e| (e, "Couldn't query extended attribute"));
        let value = value.and_then(|size| {
            if size > 16 * 1024 * 1024 {
                let e = std::io::Error::from_raw_os_error(libc::ENOMEM);
                return Err((e, "Out of memory"));
            }
            let mut value = vec![0; size];
            let len = src
                .get(name, &mut value)
                .map_err(|e| (e, "Couldn't read extended attribute"))?;
            value.truncate(len);
            Ok(value)
        });
        match value {
            Ok(value) => entry.xattr_add(name, &value),
            Err((e, msg)) => a.set_error(errno(e), Some(msg.as_bytes())),
        }
    }
    ARCHIVE_OK
}

/// Sparse maps hold at most this many extents.
#[cfg(target_os = "linux")]
const MAX_EXTENTS: usize = 1 << 20;

/// Upstream's setup_sparse with SEEK_HOLE and SEEK_DATA, through `fd` or
/// the file opened, which falls back to FIEMAP where seeking a hole fails.
#[cfg(target_os = "linux")]
fn setup_sparse(
    a: &Base,
    entry: &mut Entry,
    fd: Option<c_int>,
    path: &Path,
    access: &[u8],
) -> c_int {
    use libc::{SEEK_CUR, SEEK_DATA, SEEK_END, SEEK_HOLE, SEEK_SET};
    let failed = |errno, msg: &[u8]| a.raise(Error::new(ARCHIVE_FAILED, errno, msg));
    let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
    if entry.filetype() != libc::S_IFREG || entry.size() <= 0 || entry.hardlink().is_some() {
        return ARCHIVE_OK;
    }
    let opened;
    let (fd, initial) = match fd {
        Some(fd) => {
            let initial = disk_sys::seek(fd, 0, SEEK_CUR).unwrap_or(-1);
            if initial != 0 {
                let _ = disk_sys::seek(fd, 0, SEEK_SET);
            }
            (fd, initial)
        }
        None => match disk_sys::open_read(path, libc::O_NONBLOCK) {
            Ok(file) => {
                opened = file;
                (opened.as_raw_fd(), 0)
            }
            Err(e) => return failed(errno(e), &[b"Can't open `", access, b"'"].concat()),
        },
    };
    // Check if the underlying filesystem supports seek hole.
    match disk_sys::seek(fd, 0, SEEK_HOLE) {
        Err(_) => return setup_sparse_fiemap(a, entry, fd),
        Ok(hole) if hole > 0 => {
            let _ = disk_sys::seek(fd, 0, SEEK_SET);
        }
        Ok(_) => {}
    }
    let size = entry.size();
    let mut ret = ARCHIVE_OK;
    let mut check_fully_sparse = false;
    let mut off_s = 0;
    let mut scanned = 0;
    while off_s < size {
        if scanned == MAX_EXTENTS {
            ret = failed(libc::ENOMEM, b"Can't read sparse data");
            break;
        }
        scanned += 1;
        let requested = off_s;
        off_s = match disk_sys::seek(fd, off_s, SEEK_DATA) {
            Ok(off) => off,
            Err(e) if e.raw_os_error() == Some(libc::ENXIO) => {
                // no more hole; with no data, potentially a fully-sparse file.
                check_fully_sparse = entry.sparse_count() == 0;
                break;
            }
            Err(e) => {
                ret = failed(errno(e), b"lseek(SEEK_HOLE) failed");
                break;
            }
        };
        if off_s < requested {
            ret = failed(libc::EIO, b"Can't read sparse data");
            break;
        }
        let off_e = match disk_sys::seek(fd, off_s, SEEK_HOLE) {
            Ok(off) => off,
            Err(e) => {
                let e = match e.raw_os_error() {
                    Some(libc::ENXIO) => match disk_sys::seek(fd, 0, SEEK_END) {
                        Ok(_) => break, // no more data
                        Err(e) => e,
                    },
                    _ => e,
                };
                ret = failed(errno(e), b"lseek(SEEK_DATA) failed");
                break;
            }
        };
        if off_s == 0 && off_e == size {
            break; // This is not sparse.
        }
        if off_e <= off_s {
            ret = failed(libc::EIO, b"Can't read sparse data");
            break;
        }
        if entry.sparse.len() >= MAX_EXTENTS {
            ret = failed(libc::ENOMEM, b"Can't read sparse data");
            break;
        }
        entry.sparse_add(off_s, off_e - off_s);
        off_s = off_e;
    }
    if check_fully_sparse
        && disk_sys::seek(fd, 0, SEEK_HOLE).is_ok_and(|off| off == 0)
        && disk_sys::seek(fd, 0, SEEK_END).is_ok_and(|off| off == size)
    {
        // Fully sparse file; insert a zero-length "data" entry.
        entry.sparse_add(0, 0);
    }
    let _ = disk_sys::seek(fd, initial, SEEK_SET);
    ret
}

/// Upstream's setup_sparse_fiemap on `fd`: the written extents FIEMAP
/// reports. An error leaves the file as it is, since kernels before
/// 2.6.28 can't map extents.
#[cfg(target_os = "linux")]
fn setup_sparse_fiemap(a: &Base, entry: &mut Entry, fd: c_int) -> c_int {
    let size = entry.size();
    let mut map = disk_sys::Fiemap::new();
    let mut mapped = 0;
    for iter in 0.. {
        if map.map(fd).is_err() {
            break;
        }
        let extents = map.extents();
        let Some(last) = extents.last() else {
            if iter == 0 {
                // Fully sparse file; insert a zero-length "data" entry.
                entry.sparse_add(0, 0);
            }
            break;
        };
        // Unwritten extents consume the scan budget too.
        if extents.len() > MAX_EXTENTS - mapped {
            return a.raise(Error::new(
                ARCHIVE_FAILED,
                libc::ENOMEM,
                "Can't read sparse data",
            ));
        }
        mapped += extents.len();
        let mut more = true;
        for fe in extents {
            let Some(end) = fe.fe_logical.checked_add(fe.fe_length) else {
                return a.raise(Error::new(
                    ARCHIVE_FAILED,
                    libc::EIO,
                    "Can't read sparse data",
                ));
            };
            if fe.fe_flags & disk_sys::FIEMAP_EXTENT_UNWRITTEN == 0 {
                // The fe_length of the last block does not adjust itself
                // to its size files.
                let length = end.min(size as u64).saturating_sub(fe.fe_logical) as i64;
                if fe.fe_logical == 0 && length == size {
                    // This is not sparse.
                    more = false;
                    break;
                }
                if entry.sparse.len() >= MAX_EXTENTS {
                    let e = Error::new(ARCHIVE_FAILED, libc::ENOMEM, "Can't read sparse data");
                    return a.raise(e);
                }
                if length > 0 {
                    entry.sparse_add(fe.fe_logical as i64, length);
                }
            }
            if fe.fe_flags & disk_sys::FIEMAP_EXTENT_LAST != 0 {
                more = false;
            }
        }
        let Some(start) = last.fe_logical.checked_add(last.fe_length) else {
            return a.raise(Error::new(
                ARCHIVE_FAILED,
                libc::EIO,
                "Can't read sparse data",
            ));
        };
        // A map that doesn't move on would be asked for forever.
        if !more || start <= map.fm_start {
            break;
        }
        map.fm_start = start;
    }
    ARCHIVE_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::READ_DISK_MAGIC;

    struct Directory(PathBuf);
    impl Directory {
        fn new(label: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "libarchive-race-{label}-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn concurrent_parent_replacement_before_descent_keeps_the_original_tree() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let root = Directory::new("descent");
        let parent = root.0.join("parent");
        let moved = root.0.join("moved");
        let outside = root.0.join("outside");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(parent.join("file"), b"original").unwrap();
        fs::write(outside.join("file"), b"replaced").unwrap();
        let original_ino = fs::metadata(parent.join("file")).unwrap().ino();
        let a = Base::new(READ_DISK_MAGIC);
        let mut disk = ReadDisk::new();
        let mut entry = Entry::new(None);
        assert_eq!(disk.open(&a, parent.as_os_str().as_bytes()), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        let (start, started) = std::sync::mpsc::channel();
        let (done, finished) = std::sync::mpsc::channel();
        let replacement = parent.clone();
        let worker = std::thread::spawn(move || {
            started.recv().unwrap();
            fs::rename(&replacement, &moved).unwrap();
            symlink(outside, replacement).unwrap();
            done.send(()).unwrap();
        });
        start.send(()).unwrap();
        finished.recv().unwrap();
        assert_eq!(disk.descend(&a), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        assert_eq!(
            entry.pathname().unwrap().to_bytes(),
            parent.join("file").as_os_str().as_bytes()
        );
        assert_eq!(entry.ino(), original_ino as i64);
        assert_eq!(
            disk.data_block(&a).unwrap(),
            (ARCHIVE_OK, &b"original"[..], 0)
        );
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_EOF);
        worker.join().unwrap();
    }

    #[test]
    fn concurrent_parent_replacement_in_metadata_callback_keeps_child_metadata_and_data() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let root = Directory::new("metadata");
        let parent = root.0.join("parent");
        let moved = root.0.join("moved");
        let outside = root.0.join("outside");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(parent.join("file"), b"original").unwrap();
        fs::write(outside.join("file"), b"replaced").unwrap();
        let attr = std::ffi::CString::new("user.libarchive-race").unwrap();
        disk_sys::Target::prepare(&parent.join("file"), false)
            .unwrap()
            .xattr(&attr, b"original")
            .unwrap();
        disk_sys::Target::prepare(&outside.join("file"), false)
            .unwrap()
            .xattr(&attr, b"replaced")
            .unwrap();
        let ino = fs::metadata(parent.join("file")).unwrap().ino();
        let (start, started) = std::sync::mpsc::channel();
        let (done, finished) = std::sync::mpsc::channel();
        let replaced = parent.clone();
        let worker = std::thread::spawn(move || {
            started.recv().unwrap();
            fs::rename(&replaced, moved).unwrap();
            symlink(outside, replaced).unwrap();
            done.send(()).unwrap();
        });
        let a = Base::new(READ_DISK_MAGIC);
        let mut disk = ReadDisk::new();
        disk.metadata_filter = Some(Box::new(move |_, entry| {
            if entry.filetype() == libc::S_IFREG {
                start.send(()).unwrap();
                finished.recv().unwrap();
            }
            true
        }));
        let mut entry = Entry::new(None);
        assert_eq!(disk.open(&a, parent.as_os_str().as_bytes()), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.descend(&a), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        assert_eq!(entry.ino(), ino as i64);
        assert!(
            entry
                .xattrs
                .iter()
                .any(|x| x.name == attr && x.value == b"original")
        );
        assert!(!entry.xattrs.iter().any(|x| x.value == b"replaced"));
        assert_eq!(
            disk.data_block(&a).unwrap(),
            (ARCHIVE_OK, &b"original"[..], 0)
        );
        worker.join().unwrap();
    }

    #[test]
    fn concurrent_leaf_symlink_replacement_before_data_is_refused() {
        use std::os::unix::fs::symlink;
        let root = Directory::new("data");
        let path = root.0.join("file");
        let moved = root.0.join("moved");
        let outside = root.0.join("outside");
        fs::write(&path, b"original").unwrap();
        fs::write(&outside, b"replaced").unwrap();
        for policy in [0, 1, 2] {
            let a = Base::new(READ_DISK_MAGIC);
            let mut disk = ReadDisk::new();
            disk.symlinks = policy;
            let mut entry = Entry::new(None);
            assert_eq!(disk.open(&a, path.as_os_str().as_bytes()), ARCHIVE_OK);
            assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
            let (start, started) = std::sync::mpsc::channel();
            let (done, finished) = std::sync::mpsc::channel();
            let (path, moved, outside) = (path.clone(), moved.clone(), outside.clone());
            let worker = std::thread::spawn(move || {
                started.recv().unwrap();
                fs::rename(&path, &moved).unwrap();
                symlink(&outside, &path).unwrap();
                done.send(()).unwrap();
                (path, moved)
            });
            start.send(()).unwrap();
            finished.recv().unwrap();
            assert_eq!(disk.data_block(&a).unwrap().0, ARCHIVE_FAILED);
            assert!([libc::ELOOP, libc::ESTALE].contains(&a.errno.get()));
            let (path, moved) = worker.join().unwrap();
            fs::remove_file(&path).unwrap();
            fs::rename(moved, path).unwrap();
        }
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn concurrent_symlink_replacement_in_callback_keeps_the_observed_link_text() {
        use std::os::unix::fs::symlink;
        let root = Directory::new("link");
        let path = root.0.join("link");
        symlink("original", &path).unwrap();
        let moved = root.0.join("moved");
        let replacement = path.clone();
        let (start, started) = std::sync::mpsc::channel();
        let (done, finished) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            started.recv().unwrap();
            fs::rename(&replacement, moved).unwrap();
            symlink("replacement", replacement).unwrap();
            done.send(()).unwrap();
        });
        let a = Base::new(READ_DISK_MAGIC);
        let mut disk = ReadDisk::new();
        // Linux symlink xattrs require name lookup; exercise the pinned readlink independently.
        disk.behavior = 0x10 | 0x20;
        disk.metadata_filter = Some(Box::new(move |_, _| {
            start.send(()).unwrap();
            finished.recv().unwrap();
            true
        }));
        let mut entry = Entry::new(None);
        assert_eq!(disk.open(&a, path.as_os_str().as_bytes()), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        assert_eq!(entry.symlink().unwrap().to_bytes(), b"original");
        worker.join().unwrap();
    }

    #[test]
    fn data_open_honors_permission_changes_in_metadata_callback() {
        use std::os::unix::fs::PermissionsExt;
        if disk_sys::euid() == 0 {
            return;
        }
        let root = Directory::new("permissions");
        let path = root.0.join("file");
        fs::write(&path, b"data").unwrap();
        for (before, after) in [(0, 0o600), (0o600, 0)] {
            fs::set_permissions(&path, fs::Permissions::from_mode(before)).unwrap();
            let a = Base::new(READ_DISK_MAGIC);
            let mut disk = ReadDisk::new();
            disk.behavior = 0xf0; // No optional metadata needs a readable descriptor.
            let changed = path.clone();
            disk.metadata_filter = Some(Box::new(move |_, _| {
                fs::set_permissions(&changed, fs::Permissions::from_mode(after)).unwrap();
                true
            }));
            let mut entry = Entry::new(None);
            assert_eq!(disk.open(&a, path.as_os_str().as_bytes()), ARCHIVE_OK);
            assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
            if after == 0 {
                assert_eq!(disk.data_block(&a).unwrap().0, ARCHIVE_FAILED);
                assert_eq!(a.errno.get(), libc::EACCES);
            } else {
                assert_eq!(disk.data_block(&a).unwrap(), (ARCHIVE_OK, &b"data"[..], 0));
            }
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn cached_filesystem_metadata_honors_permission_granted_by_callback() {
        use std::os::unix::fs::PermissionsExt;
        if disk_sys::euid() == 0 {
            return;
        }
        let root = Directory::new("cached-permissions");
        let path = root.0.join("file");
        fs::write(&path, b"data").unwrap();
        disk_sys::Target::prepare(&path, false)
            .unwrap()
            .xattr(c"user.libarchive-permissions", b"granted")
            .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
        let a = Base::new(READ_DISK_MAGIC);
        let mut disk = ReadDisk::new();
        disk.behavior = 0xe0;
        disk.metadata_filter = Some(Box::new(move |_, entry| {
            if entry.filetype() == libc::S_IFREG {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            true
        }));
        let mut entry = Entry::new(None);
        assert_eq!(disk.open(&a, root.0.as_os_str().as_bytes()), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.descend(&a), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        assert!(
            entry
                .xattrs
                .iter()
                .any(|x| { x.name == c"user.libarchive-permissions" && x.value == b"granted" })
        );
        assert_eq!(disk.data_block(&a).unwrap(), (ARCHIVE_OK, &b"data"[..], 0));
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn cached_filesystem_metadata_keeps_callback_type_changes_and_rechecks_access() {
        use std::os::unix::fs::PermissionsExt;
        if disk_sys::euid() == 0 {
            return;
        }
        for behavior in [0xe0, 4] {
            for action in ["unchanged", "revoke", "replace"] {
                let root = Directory::new("mutated-type");
                let path = root.0.join("file");
                fs::write(&path, b"original").unwrap();
                disk_sys::Target::prepare(&path, false)
                    .unwrap()
                    .xattr(c"user.libarchive-mutated", b"original")
                    .unwrap();
                let a = Base::new(READ_DISK_MAGIC);
                let mut disk = ReadDisk::new();
                disk.behavior = behavior;
                let moved = root.0.join("moved");
                disk.metadata_filter = Some(Box::new(move |_, entry| {
                    if entry.filetype() == libc::S_IFREG {
                        entry.set_filetype(libc::S_IFIFO as u32);
                        if action == "revoke" {
                            fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
                        } else if action == "replace" {
                            fs::rename(&path, &moved).unwrap();
                            fs::write(&path, b"replacement").unwrap();
                            disk_sys::Target::prepare(&path, false)
                                .unwrap()
                                .xattr(c"user.libarchive-mutated", b"replacement")
                                .unwrap();
                        }
                    }
                    true
                }));
                let mut entry = Entry::new(None);
                assert_eq!(disk.open(&a, root.0.as_os_str().as_bytes()), ARCHIVE_OK);
                assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
                assert_eq!(disk.descend(&a), ARCHIVE_OK);
                let ret = disk.next_header2(&a, &mut entry);
                assert_eq!(entry.filetype(), libc::S_IFIFO);
                if action == "unchanged" {
                    assert_eq!(ret, ARCHIVE_OK);
                    assert!(entry.xattrs.iter().any(|x| {
                        x.name == c"user.libarchive-mutated" && x.value == b"original"
                    }));
                } else {
                    assert_eq!(ret, ARCHIVE_WARN);
                    assert_eq!(a.errno.get(), libc::EACCES);
                    assert_eq!(
                        a.error.borrow().strip_suffix(b"\0").unwrap(),
                        b"Couldn't open metadata descriptor"
                    );
                    assert!(entry.xattrs.is_empty());
                }
                assert_eq!(disk.data_block(&a).unwrap().0, ARCHIVE_EOF);
            }
        }
    }

    #[test]
    fn empty_root_keeps_the_missing_path_error() {
        let a = Base::new(READ_DISK_MAGIC);
        let mut disk = ReadDisk::new();
        let mut entry = Entry::new(None);
        assert_eq!(disk.open(&a, b""), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_FAILED);
        assert_eq!(a.errno.get(), libc::ENOENT);
    }

    #[test]
    fn fifo_metadata_never_waits_for_a_writer() {
        let root = Directory::new("fifo");
        let path = root.0.join("fifo");
        disk_sys::Target::prepare(&path, false)
            .unwrap()
            .special(libc::S_IFIFO as u32 | 0o600, 0)
            .unwrap();
        let a = Base::new(READ_DISK_MAGIC);
        let mut disk = ReadDisk::new();
        let mut entry = Entry::new(None);
        assert_eq!(disk.open(&a, path.as_os_str().as_bytes()), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        assert_eq!(entry.filetype(), libc::S_IFIFO);
        assert_eq!(disk.data_block(&a).unwrap().0, ARCHIVE_EOF);
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn followed_fifo_symlink_reads_the_targets_metadata() {
        use std::os::unix::fs::symlink;
        let root = Directory::new("fifo-link");
        let fifo = root.0.join("fifo");
        let link = root.0.join("link");
        let target = disk_sys::Target::prepare(&fifo, false).unwrap();
        target.special(libc::S_IFIFO as u32 | 0o600, 0).unwrap();
        target.xattr(c"user.libarchive-fifo", b"target").unwrap();
        symlink(&fifo, &link).unwrap();
        for policy in [1, 2] {
            let a = Base::new(READ_DISK_MAGIC);
            let mut disk = ReadDisk::new();
            disk.symlinks = policy;
            disk.behavior = 0x20;
            let mut entry = Entry::new(None);
            assert_eq!(disk.open(&a, link.as_os_str().as_bytes()), ARCHIVE_OK);
            assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
            assert_eq!(entry.filetype(), libc::S_IFIFO);
            assert!(
                entry
                    .xattrs
                    .iter()
                    .any(|x| { x.name == c"user.libarchive-fifo" && x.value == b"target" })
            );
            assert_eq!(disk.data_block(&a).unwrap().0, ARCHIVE_EOF);
        }
    }

    #[test]
    fn replaced_regular_file_cannot_make_data_open_wait_on_a_fifo() {
        let root = Directory::new("fifo-swap");
        let path = root.0.join("file");
        fs::write(&path, b"data").unwrap();
        let a = Base::new(READ_DISK_MAGIC);
        let mut disk = ReadDisk::new();
        let mut entry = Entry::new(None);
        assert_eq!(disk.open(&a, path.as_os_str().as_bytes()), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        fs::rename(&path, root.0.join("moved")).unwrap();
        disk_sys::Target::prepare(&path, false)
            .unwrap()
            .special(libc::S_IFIFO as u32 | 0o600, 0)
            .unwrap();
        assert_eq!(disk.data_block(&a).unwrap().0, ARCHIVE_FAILED);
        assert_eq!(a.errno.get(), libc::ESTALE);
    }

    #[test]
    fn ascent_restores_the_directory_opened_before_a_rename() {
        use std::os::unix::fs::MetadataExt;
        let root =
            std::env::temp_dir().join(format!("libarchive-restore-dir-{}", std::process::id()));
        let moved = root.with_extension("moved");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&moved);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("file"), b"data").unwrap();
        let times = |seconds| {
            fs::FileTimes::new()
                .set_accessed(std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds))
        };
        File::open(&root)
            .unwrap()
            .set_times(times(123456789))
            .unwrap();
        let a = Base::new(READ_DISK_MAGIC);
        let mut disk = ReadDisk::new();
        disk.behavior = 1;
        let mut entry = Entry::new(None);
        assert_eq!(disk.open(&a, root.as_os_str().as_bytes()), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.descend(&a), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        File::open(&root)
            .unwrap()
            .set_times(times(987654321))
            .unwrap();
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_EOF);
        assert_eq!(fs::metadata(&moved).unwrap().atime(), 123456789);
        assert_eq!(fs::metadata(&root).unwrap().atime(), 987654321);
        disk.close(&a);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn metadata_stays_on_the_inode_renamed_by_the_callback() {
        let root =
            std::env::temp_dir().join(format!("libarchive-metadata-warn-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let path = root.join("file");
        let moved = root.join("moved");
        fs::write(&path, b"entry data").unwrap();
        let a = Base::new(READ_DISK_MAGIC);
        let mut disk = ReadDisk::new();
        disk.behavior = 0x20 | 0x40 | 0x80; // Only xattrs remain enabled.
        let (from, to) = (path.clone(), moved.clone());
        disk.metadata_filter = Some(Box::new(move |_, _| {
            fs::rename(&from, &to).unwrap();
            true
        }));
        assert_eq!(disk.open(&a, path.as_os_str().as_bytes()), ARCHIVE_OK);
        let mut entry = Entry::new(None);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        assert_eq!(a.state.get(), state::DATA);
        assert_eq!(a.file_count.get(), 1);
        fs::rename(&moved, &path).unwrap();
        assert_eq!(
            disk.data_block(&a).unwrap(),
            (ARCHIVE_OK, &b"entry data"[..], 0)
        );
        assert_eq!(disk.data_block(&a).unwrap().0, ARCHIVE_EOF);
        disk.close(&a);
        fs::remove_dir_all(root).unwrap();
    }

    /// Every path the walk yields, descending into every directory, as
    /// bsdtar does.
    fn walk(root: &Path) -> Vec<PathBuf> {
        let a = Base::new(READ_DISK_MAGIC);
        let mut disk = ReadDisk::new();
        let mut entry = Entry::new(None);
        assert_eq!(disk.open(&a, root.as_os_str().as_bytes()), ARCHIVE_OK);
        let mut seen = Vec::new();
        while disk.next_header2(&a, &mut entry) == ARCHIVE_OK {
            let path = entry
                .pathname()
                .map(|p| p.to_bytes().to_vec())
                .unwrap_or_default();
            seen.push(PathBuf::from(std::ffi::OsStr::from_bytes(&path)));
            if a.disk_can_descend.get() {
                assert_eq!(disk.descend(&a), ARCHIVE_OK);
            }
        }
        seen
    }

    fn readdir(path: &Path) -> Vec<PathBuf> {
        fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect()
    }

    #[test]
    fn files_removed_mid_walk_warn_with_the_next_entry() {
        let root = std::env::temp_dir().join(format!("libarchive-gone-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        for name in ["a", "b", "c", "d"] {
            fs::write(root.join(name), b"").unwrap();
        }
        let a = Base::new(READ_DISK_MAGIC);
        let mut disk = ReadDisk::new();
        let mut entry = Entry::new(None);
        assert_eq!(disk.open(&a, root.as_os_str().as_bytes()), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.descend(&a), ARCHIVE_OK);
        // Once the directory is open and its first entry visited, remove
        // all but the last entry readdir returns: the walk still lists them,
        // fails to stat them, and reaches the survivor.
        let mut order = readdir(&root);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        assert_eq!(
            entry.pathname().unwrap().to_bytes(),
            order[0].as_os_str().as_bytes()
        );
        order.remove(0);
        let survivor = order.pop().unwrap();
        for path in &order {
            fs::remove_file(path).unwrap();
        }
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_WARN);
        assert_eq!(
            entry.pathname().unwrap().to_bytes(),
            survivor.as_os_str().as_bytes()
        );
        let gone: Vec<_> = order.iter().map(|p| p.as_os_str().as_bytes()).collect();
        let msg = [
            gone.join(&b' ').as_slice(),
            b": File removed before we read it",
        ]
        .concat();
        assert_eq!(a.errno.get(), libc::ENOENT);
        assert_eq!(a.error.borrow().strip_suffix(b"\0").unwrap(), msg);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_EOF);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn directories_are_read_after_their_parent_most_recent_first() {
        let root = std::env::temp_dir().join(format!("libarchive-walk-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for dir in ["a/x", "b", "c"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        for file in ["f", "a/1", "a/x/2", "b/3", "c/4"] {
            fs::write(root.join(file), b"").unwrap();
        }
        // The root, its entries, then each directory descended into, the
        // last one listed first, each expanded in full before the next.
        let mut expected = vec![root.clone()];
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for child in readdir(&dir) {
                if child.is_dir() {
                    stack.push(child.clone());
                }
                expected.push(child);
            }
        }
        assert_eq!(walk(&root), expected);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_file_that_is_all_hole_has_empty_blocks_as_upstream_gives() {
        let root = std::env::temp_dir().join(format!("libarchive-hole-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let path = root.join("hole");
        File::create(&path).unwrap().set_len(65536).unwrap();
        let a = Base::new(READ_DISK_MAGIC);
        let mut disk = ReadDisk::new();
        let mut entry = Entry::new(None);
        assert_eq!(disk.open(&a, path.as_os_str().as_bytes()), ARCHIVE_OK);
        assert_eq!(disk.next_header2(&a, &mut entry), ARCHIVE_OK);
        let mut blocks = Vec::new();
        loop {
            let (code, data, offset) = disk.data_block(&a).unwrap();
            blocks.push((code, data.len(), offset));
            if code != ARCHIVE_OK {
                break;
            }
        }
        // The file system may not keep the file sparse.
        if entry.sparse_count() != 0 {
            assert_eq!(
                blocks,
                [
                    (ARCHIVE_OK, 0, 0),
                    (ARCHIVE_OK, 0, 65536),
                    (ARCHIVE_EOF, 0, 65536)
                ]
            );
        } else {
            assert_eq!(blocks.last(), Some(&(ARCHIVE_EOF, 0, 65536)));
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fiemap_finds_the_extents_seek_hole_does() {
        use std::io::Write;
        use std::os::unix::fs::FileExt;
        let root = std::env::temp_dir().join(format!("libarchive-fiemap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let path = root.join("sparse");
        let mut file = File::create(&path).unwrap();
        file.set_len(1 << 20).unwrap();
        file.write_all_at(&[1; 4096], 256 * 1024).unwrap();
        file.write_all_at(&[2; 10], (1 << 20) - 10).unwrap();
        file.flush().unwrap();
        let a = Base::new(READ_DISK_MAGIC);
        let extents = |fiemap: bool| {
            let mut entry = Entry::new(None);
            entry.set_mode(libc::S_IFREG | 0o644);
            entry.set_size(1 << 20);
            let file = File::open(&path).unwrap();
            let code = if fiemap {
                setup_sparse_fiemap(&a, &mut entry, file.as_raw_fd())
            } else {
                setup_sparse(&a, &mut entry, Some(file.as_raw_fd()), &path, b"sparse")
            };
            assert_eq!(code, ARCHIVE_OK);
            entry.sparse_count();
            entry
                .sparse
                .iter()
                .map(|s| (s.offset, s.length))
                .collect::<Vec<_>>()
        };
        let seek = extents(false);
        let mapped = extents(true);
        // Where FIEMAP is not supported, upstream leaves the file as it is.
        if !mapped.is_empty() {
            assert_eq!(mapped, seek);
        }
        assert!(seek.iter().any(|&(offset, _)| offset == 256 * 1024));
        fs::remove_dir_all(&root).unwrap();
    }
}
