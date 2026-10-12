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
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The (dev, ino) of each directory above a path, which catch symlink loops.
type Ancestors = Vec<(u64, u64)>;
/// A path to visit, whether it is the root, and its ancestors.
type Pending = (PathBuf, bool, Ancestors);

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
    /// Directories `descend` asked for, the most recent last: upstream's
    /// tree stack. One being read stays under those it asks for.
    stack: Vec<Dir>,
    /// The directory whose entries are being visited, in readdir order.
    reading: Option<(fs::ReadDir, PathBuf, Ancestors)>,
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
        self.stack.push(Dir {
            path: path.clone(),
            ancestors: self.ancestors.clone(),
            restore: self.restore,
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
            return Ok(Some((root, true, Vec::new())));
        }
        loop {
            if let Some((dir, path, ancestors)) = &mut self.reading {
                match dir.next() {
                    Some(Ok(child)) => return Ok(Some((child.path(), false, ancestors.clone()))),
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
                    && let Ok(file) = disk_sys::open_read(&dir.path, libc::O_DIRECTORY)
                {
                    let _ = disk_sys::restore_times(&file, dir.restore.atime, dir.restore.mtime);
                }
                continue;
            }
            top.read = true;
            match fs::read_dir(&top.path) {
                Ok(dir) => self.reading = Some((dir, top.path.clone(), top.ancestors.clone())),
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
            let (path, root, ancestors) = match self.next_path(a) {
                Ok(Some(next)) => next,
                Ok(None) => {
                    a.state.set(state::EOF);
                    return ARCHIVE_EOF;
                }
                Err(ret) => return ret,
            };
            let lst = match disk_sys::stat(&path, -1, false) {
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
            self.ancestors = ancestors;
            match self.excluded(a, entry, |m, e| m.match_path_excluded(Some(e))) {
                Ok(false) => {}
                Ok(true) => continue,
                Err(r) => return r,
            }
            // Following symlinks, archive the target unless the link is
            // broken or loops back to a parent; then the link itself.
            let follow = self.symlinks == 1 || (self.symlinks == 2 && root);
            let (st, followed) = match disk_sys::stat(&path, -1, true) {
                Ok(st)
                    if follow
                        && !(st.st_mode & libc::S_IFMT == libc::S_IFDIR
                            && self.ancestors.contains(&(st.st_dev as u64, st.st_ino))) =>
                {
                    (st, true)
                }
                _ => (lst, false),
            };
            entry.copy_stat(&st);
            #[cfg(target_vendor = "apple")]
            if self.behavior & 0x40 == 0 {
                entry.set_fflags(st.st_flags.into(), 0);
            }
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
            let probe = &mut self.filesystems[filesystem].1;
            let fs = match *probe {
                Some(fs) => fs,
                None => {
                    let found =
                        disk_sys::filesystem(&path, follow && entry.filetype() != libc::S_IFLNK);
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
            #[cfg(target_vendor = "apple")]
            if self.behavior & 2 != 0 && st.st_flags & libc::UF_NODUMP != 0 {
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
            let ret = self.fill_metadata(a, entry, &path, followed);
            if ret < 0 {
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
    /// _archive_read_data_block does when first called.
    fn open_data(&mut self, a: &Base) -> Result<(), c_int> {
        if self.file.is_some() || self.eof {
            return Ok(());
        }
        let Some(path) = &self.current else {
            return Ok(());
        };
        match disk_sys::open_read(path, 0) {
            Ok(file) => {
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
    /// the link target, then ACLs, extended attributes, Mac metadata and
    /// sparse extents; a failure among those last four warns or fails but
    /// the rest are still read, and the worst result is returned.
    pub fn fill_metadata(
        &mut self,
        a: &Base,
        entry: &mut Entry,
        path: &Path,
        follow: bool,
    ) -> c_int {
        if let Some(name) = self.user.lookup(entry.uid(), false) {
            entry.set_uname(name.to_bytes());
        }
        if let Some(name) = self.group.lookup(entry.gid(), true) {
            entry.set_gname(name.to_bytes());
        }
        if entry.filetype() == libc::S_IFLNK {
            match fs::read_link(path) {
                Ok(p) => entry.set_symlink(p.as_os_str().as_bytes()),
                Err(e) => return io_error(a, e, "Couldn't read link data"),
            }
        }
        let mut ret = ARCHIVE_OK;
        #[cfg(target_vendor = "apple")]
        if self.behavior & 0x20 == 0
            && let Err(e) = crate::ffi::disk_acl::read(path, entry, &mut self.user, &mut self.group)
        {
            ret = ret.min(failure(
                a,
                ARCHIVE_WARN,
                e,
                b"Couldn't translate NFSv4 ACLs",
            ));
        }
        if self.behavior & 0x10 == 0
            && let Err((e, msg)) = disk_sys::read_xattrs(path, entry, follow)
        {
            ret = ret.min(failure(a, ARCHIVE_WARN, e, msg.as_bytes()));
        }
        if self.behavior & 4 != 0
            && let Err(e) = disk_sys::pack_mac_metadata(path, entry)
        {
            ret = ret.min(failure(a, ARCHIVE_FAILED, e, b"Can't read Mac metadata"));
        }
        if self.behavior & 0x80 == 0 && entry.filetype() == libc::S_IFREG {
            match disk_sys::sparse(path, self.symlinks != 0, entry.size()) {
                Ok(extents) => {
                    for (offset, len) in extents {
                        entry.sparse_add(offset, len);
                    }
                }
                Err(e) => ret = ret.min(failure(a, ARCHIVE_FAILED, e, b"Can't read sparse data")),
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::READ_DISK_MAGIC;

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
}
