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

use crate::archive::{ARCHIVE_EOF, ARCHIVE_FAILED, ARCHIVE_OK, Base, state};
use crate::entry::Entry;
use crate::util::Error;
use std::ffi::c_int;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

type Pending = (PathBuf, bool, Vec<(u64, u64)>);

#[derive(Default)]
pub struct ReadDisk {
    pub symlinks: u8,
    pub behavior: c_int,
    pub user: crate::ffi::disk::NameLookup,
    pub group: crate::ffi::disk::NameLookup,
    pub metadata_filter: crate::ffi::disk::MetadataFilter,
    pub matching: Option<crate::ffi::matching::MatchingHandle>,
    pub excluded: crate::ffi::disk::ExcludedCallback,
    entry: *mut Entry,
    pending: Vec<Pending>,
    current: Option<PathBuf>,
    ancestors: Vec<(u64, u64)>,
    current_restore: Option<Entry>,
    directory_restore: Vec<(PathBuf, Entry)>,
    can_descend: bool,
    file: Option<File>,
    block: Vec<u8>,
    offset: i64,
    pub filesystem: c_int,
    filesystems: Vec<u64>,
}

impl ReadDisk {
    pub fn new() -> Self {
        Self {
            entry: Box::into_raw(Box::new(Entry::new(None))),
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
        self.pending.clear();
        self.pending.push((
            PathBuf::from(std::ffi::OsStr::from_bytes(path)),
            true,
            Vec::new(),
        ));
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
        let iter = match fs::read_dir(path) {
            Ok(i) => i,
            Err(e) => return io_error(a, e, "Can't open directory"),
        };
        if self.behavior & 1 != 0
            && let Some(entry) = &self.current_restore
        {
            self.directory_restore
                .push((path.clone(), entry.clone_entry()));
        }
        let mut children = Vec::new();
        for child in iter {
            match child {
                Ok(c) => children.push(c.path()),
                Err(e) => return io_error(a, e, "Can't read directory"),
            }
        }
        for path in children.into_iter().rev() {
            self.pending.push((path, false, self.ancestors.clone()));
        }
        ARCHIVE_OK
    }
    pub fn next_header2(&mut self, a: &Base, entry: &mut Entry) -> c_int {
        self.restore_current(a);
        self.file = None;
        self.block.clear();
        self.offset = 0;
        loop {
            self.can_descend = false;
            a.disk_can_descend.set(false);
            a.disk_descend_requested.set(false);
            let Some((path, root, ancestors)) = self.pending.pop() else {
                a.state.set(state::EOF);
                return ARCHIVE_EOF;
            };
            entry.clear();
            entry.set_pathname(path.as_os_str().as_bytes());
            self.current = Some(path.clone());
            self.ancestors = ancestors;
            if let Some(m) = self.matching {
                let excluded = m.path_excluded(entry);
                if excluded < 0 {
                    return excluded;
                }
                if excluded != 0 {
                    self.excluded.call(entry);
                    if a.disk_descend_requested.take() {
                        let ret = self.descend(a);
                        if ret < 0 {
                            return ret;
                        }
                    }
                    continue;
                }
            }
            let follow = self.symlinks == 1 || (self.symlinks == 2 && root);
            let mut st = match crate::ffi::disk_sys::stat(&path, -1, follow) {
                Ok(st) => st,
                Err(_) if follow => match crate::ffi::disk_sys::stat(&path, -1, false) {
                    Ok(st) => st,
                    Err(e) => return io_error(a, e, "Can't stat"),
                },
                Err(e) => return io_error(a, e, "Can't stat"),
            };
            if follow
                && st.st_mode & libc::S_IFMT == libc::S_IFDIR
                && self.ancestors.contains(&(st.st_dev as u64, st.st_ino))
            {
                st = match crate::ffi::disk_sys::stat(&path, -1, false) {
                    Ok(st) => st,
                    Err(e) => return io_error(a, e, "Can't stat"),
                };
            }
            entry.copy_stat(&st);
            self.current_restore = Some(entry.clone_entry());
            let fsid = st.st_dev as u64;
            self.filesystem = match self.filesystems.iter().position(|&id| id == fsid) {
                Some(n) => n as c_int,
                None => {
                    self.filesystems.push(fsid);
                    (self.filesystems.len() - 1) as c_int
                }
            };
            a.disk_filesystem.set(self.filesystem);
            self.can_descend = entry.filetype() == libc::S_IFDIR
                && !(self.behavior & 8 != 0 && self.filesystem != 0);
            a.disk_can_descend.set(self.can_descend);
            if self.can_descend {
                self.ancestors.push((st.st_dev as u64, st.st_ino));
            }
            if self.behavior & 2 != 0 && st.st_flags & libc::UF_NODUMP != 0 {
                continue;
            }
            if let Some(m) = self.matching {
                let excluded = m.time_excluded(entry);
                if excluded < 0 {
                    return excluded;
                }
                if excluded != 0 {
                    self.excluded.call(entry);
                    if a.disk_descend_requested.take() {
                        let ret = self.descend(a);
                        if ret < 0 {
                            return ret;
                        }
                    }
                    continue;
                }
            }
            if let Some(name) = self.user.lookup(entry.uid(), false) {
                entry.set_uname(name.to_bytes());
            }
            if let Some(name) = self.group.lookup(entry.gid(), true) {
                entry.set_gname(name.to_bytes());
            }
            if let Some(m) = self.matching {
                let excluded = m.owner_excluded(entry);
                if excluded < 0 {
                    return excluded;
                }
                if excluded != 0 {
                    self.excluded.call(entry);
                    if a.disk_descend_requested.take() {
                        let ret = self.descend(a);
                        if ret < 0 {
                            return ret;
                        }
                    }
                    continue;
                }
            }
            let include = self.metadata_filter.apply(entry);
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
            let ret = self.fill_metadata(a, entry, &path);
            if ret < 0 {
                return ret;
            }
            if entry.filetype() == libc::S_IFREG {
                match File::open(&path) {
                    Ok(file) => self.file = Some(file),
                    Err(e) => return io_error(a, e, "Can't open file"),
                }
            }
            a.file_count.set(a.file_count.get() + 1);
            a.state.set(state::DATA);
            return ARCHIVE_OK;
        }
    }
    fn restore_current(&mut self, a: &Base) {
        if self.behavior & 1 != 0
            && let Some(entry) = self.current_restore.take()
            && let Some(path) = &self.current
        {
            let _ = crate::ffi::disk_sys::restore_times(path, &entry);
        }
        let _ = a;
    }
    pub fn fill_metadata(&mut self, a: &Base, entry: &mut Entry, path: &Path) -> c_int {
        if let Some(name) = self.user.lookup(entry.uid(), false) {
            entry.set_uname(name.to_bytes());
        }
        if let Some(name) = self.group.lookup(entry.gid(), true) {
            entry.set_gname(name.to_bytes());
        }
        if entry.filetype() == libc::S_IFLNK {
            match fs::read_link(path) {
                Ok(p) => entry.set_symlink(p.as_os_str().as_bytes()),
                Err(e) => return io_error(a, e, "Can't read link"),
            }
        }
        if self.behavior & 0x10 == 0
            && let Err(e) = crate::ffi::disk_sys::read_xattrs(path, entry)
        {
            return io_error(a, e, "Can't read extended attributes");
        }
        ARCHIVE_OK
    }
    pub fn data(&mut self, a: &Base, dest: &mut [u8]) -> isize {
        let Some(file) = &mut self.file else {
            return 0;
        };
        match file.read(dest) {
            Ok(n) => {
                self.offset += n as i64;
                n as isize
            }
            Err(e) => io_error(a, e, "Read failed") as isize,
        }
    }
    pub fn data_block(&mut self, a: &Base) -> Result<(&[u8], i64), c_int> {
        self.block.resize(64 * 1024, 0);
        let offset = self.offset;
        let n = match &mut self.file {
            Some(file) => match file.read(&mut self.block) {
                Ok(n) => n,
                Err(e) => return Err(io_error(a, e, "Read failed")),
            },
            None => 0,
        };
        self.block.truncate(n);
        self.offset += n as i64;
        Ok((&self.block, offset))
    }
    pub fn skip(&mut self, a: &Base) -> c_int {
        self.file = None;
        a.state.set(state::HEADER);
        ARCHIVE_OK
    }
    pub fn close(&mut self, a: &Base) -> c_int {
        self.restore_current(a);
        self.file = None;
        while let Some((path, entry)) = self.directory_restore.pop() {
            let _ = crate::ffi::disk_sys::restore_times(&path, &entry);
        }
        self.pending.clear();
        a.state.set(state::CLOSED);
        ARCHIVE_OK
    }
}

pub fn io_error(a: &Base, e: std::io::Error, msg: &str) -> c_int {
    a.raise(Error::new(
        ARCHIVE_FAILED,
        e.raw_os_error().unwrap_or(libc::EIO),
        msg,
    ))
}
