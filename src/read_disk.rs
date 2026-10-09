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
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct ReadDisk {
    pub symlinks: u8,
    pub behavior: c_int,
    entry: *mut Entry,
    pending: Vec<(PathBuf, bool)>,
    current: Option<PathBuf>,
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
        self.pending
            .push((PathBuf::from(std::ffi::OsStr::from_bytes(path)), true));
        a.state.set(state::HEADER);
        ARCHIVE_OK
    }
    pub fn can_descend(&self) -> c_int {
        c_int::from(self.can_descend)
    }
    pub fn descend(&mut self, a: &Base) -> c_int {
        if !self.can_descend {
            return ARCHIVE_OK;
        }
        self.can_descend = false;
        let Some(path) = &self.current else {
            return ARCHIVE_OK;
        };
        let iter = match fs::read_dir(path) {
            Ok(i) => i,
            Err(e) => return io_error(a, e, "Can't open directory"),
        };
        let mut children = Vec::new();
        for child in iter {
            match child {
                Ok(c) => children.push(c.path()),
                Err(e) => return io_error(a, e, "Can't read directory"),
            }
        }
        for path in children.into_iter().rev() {
            self.pending.push((path, false));
        }
        ARCHIVE_OK
    }
    pub fn next_header2(&mut self, a: &Base, entry: &mut Entry) -> c_int {
        self.file = None;
        self.block.clear();
        self.offset = 0;
        self.can_descend = false;
        let Some((path, root)) = self.pending.pop() else {
            a.state.set(state::EOF);
            return ARCHIVE_EOF;
        };
        entry.clear();
        entry.set_pathname(path.as_os_str().as_bytes());
        entry.set_sourcepath(path.as_os_str().as_bytes());
        let follow = self.symlinks == 1 || (self.symlinks == 2 && root);
        let ret = metadata(a, entry, &path, follow);
        if ret < 0 {
            return ret;
        }
        self.can_descend = entry.filetype() == libc::S_IFDIR;
        if entry.filetype() == libc::S_IFREG {
            match File::open(&path) {
                Ok(f) => self.file = Some(f),
                Err(e) => return io_error(a, e, "Can't open file"),
            }
        }
        if let Ok(m) = fs::metadata(&path) {
            let fsid = m.dev();
            self.filesystem = match self.filesystems.iter().position(|&id| id == fsid) {
                Some(n) => n as c_int,
                None => {
                    self.filesystems.push(fsid);
                    (self.filesystems.len() - 1) as c_int
                }
            };
        }
        self.current = Some(path);
        a.file_count.set(a.file_count.get() + 1);
        a.state.set(state::DATA);
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
        self.file = None;
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
pub fn metadata(a: &Base, entry: &mut Entry, path: &Path, follow: bool) -> c_int {
    let m = match if follow {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    } {
        Ok(m) => m,
        Err(e) => return io_error(a, e, "Can't stat"),
    };
    entry.set_mode(m.mode() as _);
    entry.set_uid(m.uid().into());
    entry.set_gid(m.gid().into());
    entry.set_size(m.len() as i64);
    entry.set_ino(m.ino() as i64);
    entry.set_dev(m.dev() as _);
    entry.set_nlink(m.nlink() as u32);
    entry.set_rdev(m.rdev() as _);
    entry.set_atime(m.atime(), m.atime_nsec());
    entry.set_mtime(m.mtime(), m.mtime_nsec());
    entry.set_ctime(m.ctime(), m.ctime_nsec());
    if m.file_type().is_symlink() {
        match fs::read_link(path) {
            Ok(p) => entry.set_symlink(p.as_os_str().as_bytes()),
            Err(e) => return io_error(a, e, "Can't read link"),
        }
    }
    ARCHIVE_OK
}
