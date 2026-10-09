/*-
 * Copyright (c) 2003-2010 Tim Kientzle
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
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

// Ported from libarchive/archive_read_open_filename.c.

//! The client behind `archive_read_open_filename`: reads an archive from
//! one file, or from several, one after another (a multi-volume archive).
//! A missing name is the standard input.

use crate::archive::Base;
use crate::ffi::sys::Fd;
use crate::read::{Client, Status, Whence};
use crate::read_open_fd::buffer;
use crate::util::Error;
use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;

/// The standard input's descriptor.
const STDIN: Fd = Fd(0);

struct FileNode {
    /// `None` is the standard input.
    name: Option<Vec<u8>>,
    /// The open file, for a named node.
    file: Option<File>,
    fd: Option<Fd>,
    block_size: usize,
    buffer: Vec<u8>,
    /// Mode bits of the opened file, so close can decide whether to flush.
    mode: u32,
    size: i64,
    use_lseek: bool,
    /// Device and inode, if the node is a regular file.
    identity: Option<(i64, i64)>,
}

pub struct Filenames {
    nodes: Vec<FileNode>,
    /// The node `block` belongs to, and the block's length.
    current: usize,
    len: usize,
}

/// The message a failing operation on a node reports: "Error seeking in
/// stdin" or "Error seeking in 'name'".
fn about(name: &Option<Vec<u8>>, what: &[u8]) -> Vec<u8> {
    match name {
        None => [what, b" stdin"].concat(),
        Some(n) => [what, b" '", n, b"'"].concat(),
    }
}

impl Filenames {
    /// A client over `names` (`None` for standard input), read in blocks of
    /// about `block_size`.
    pub fn new(names: Vec<Option<Vec<u8>>>, block_size: usize) -> Self {
        let nodes = names
            .into_iter()
            .map(|name| FileNode {
                name,
                file: None,
                fd: None,
                block_size,
                buffer: Vec::new(),
                mode: 0,
                size: 0,
                use_lseek: false,
                identity: None,
            })
            .collect();
        Filenames {
            nodes,
            current: 0,
            len: 0,
        }
    }
}

/// Whether `fd` is a device that seeks like a disk.
fn is_disk_like(fd: Fd, st: &crate::ffi::sys::Stat) -> bool {
    // Regular files act like disks.
    if st.is_reg() {
        return true;
    }
    // Linux: all block devices are disk-like.
    cfg!(target_os = "linux")
        && st.is_blk()
        && fd.lseek(0, libc::SEEK_CUR) == Ok(0)
        && fd.lseek(0, libc::SEEK_SET) == Ok(0)
        && fd.lseek(0, libc::SEEK_END).is_ok_and(|end| end > 0)
        && fd.lseek(0, libc::SEEK_SET) == Ok(0)
}

impl FileNode {
    /// `file_open`.
    fn open(&mut self) -> Result<(), Error> {
        let (fd, file) = match &self.name {
            // We used to delegate stdin support by directly calling
            // archive_read_open_fd(a,0,block_size) here, but that doesn't
            // (and shouldn't) handle the end-of-file flush when reading
            // stdout from a pipe. Basically, read_open_fd() is intended for
            // folks who are willing to handle such details themselves. This
            // API is intended to be a little smarter for folks who want easy
            // handling of the common case.
            None => (STDIN, None),
            Some(name) => {
                let file = File::open(OsStr::from_bytes(name)).map_err(|e| {
                    let msg = [b"Failed to open '".as_slice(), name, b"'"].concat();
                    Error::fatal(e.raw_os_error().unwrap_or(0), msg)
                })?;
                (Fd(file.as_raw_fd()), Some(file))
            }
        };
        let st = fd.fstat().map_err(|errno| {
            let name = self.name.clone().unwrap_or_default();
            Error::fatal(errno, [b"Can't stat '".as_slice(), &name, b"'"].concat())
        })?;

        // Determine whether the input looks like a disk device or a tape
        // device. The results are used below to select an I/O strategy:
        //  = "disk-like" devices support arbitrary lseek() and will support
        //    I/O requests of any size. So we get easy skipping and can
        //    cheat on block sizes to get better performance.
        //  = "tape-like" devices require strict blocking and use
        //    specialized ioctls for seeking.
        //  = "socket-like" devices cannot seek at all but can improve
        //    performance by using nonblocking I/O to read "whatever is
        //    available right now".
        //
        // Right now, we only specially recognize disk-like devices, but it
        // should be straightforward to add probes and strategy here for
        // tape-like and socket-like devices.
        let disk_like = is_disk_like(fd, &st);

        // Disk-like devices prefer power-of-two block sizes. Use provided
        // block_size as a guide so users have some control.
        if disk_like {
            let mut block_size = 64 * 1024;
            while block_size < self.block_size && block_size < 64 * 1024 * 1024 {
                block_size *= 2;
            }
            self.block_size = block_size;
        }
        self.buffer = buffer(self.block_size)?;
        self.file = file;
        self.fd = Some(fd);
        self.mode = st.mode;
        // Safety: tell the extractor not to overwrite the input.
        self.identity = st.is_reg().then_some((st.dev, st.ino));
        // Disk-like inputs can use lseek().
        if disk_like {
            self.use_lseek = true;
            self.size = st.size;
        }
        Ok(())
    }

    /// `file_close2`.
    fn close(&mut self) {
        // Only flush and close if open succeeded.
        if let Some(fd) = self.fd.take() {
            // Sometimes, we should flush the input before closing.
            //   Regular files: faster to just close without flush.
            //   Disk-like devices:  Ditto.
            //   Tapes: must not flush (user might need to read the "next"
            //      item on a non-rewind device).
            //   Pipes and sockets:  must flush (otherwise, the program
            //      feeding the pipe or socket may complain).
            // Here, I flush everything except for regular files and device
            // nodes.
            let kind = self.mode & u32::from(libc::S_IFMT);
            let skip_flush = [libc::S_IFREG, libc::S_IFCHR, libc::S_IFBLK]
                .iter()
                .any(|&k| kind == u32::from(k));
            if !skip_flush {
                while fd.read(&mut self.buffer).is_ok_and(|n| n > 0) {}
            }
            // If a named file was opened, then it needs to be closed.
            self.file = None;
        }
        self.buffer = Vec::new();
    }
}

impl Client for Filenames {
    fn nodes(&self) -> usize {
        self.nodes.len()
    }

    fn open(&mut self, _a: &Base, node: usize) -> Result<(), Error> {
        self.nodes.get_mut(node).map_or(Ok(()), FileNode::open)
    }

    fn read(&mut self, _a: &Base, node: usize) -> Result<(), Error> {
        self.len = 0;
        let Some(mine) = self.nodes.get_mut(node) else {
            return Ok(());
        };
        self.current = node;
        let Some(fd) = mine.fd else {
            return Ok(());
        };
        loop {
            match fd.read(&mut mine.buffer) {
                Ok(n) => {
                    self.len = n;
                    return Ok(());
                }
                Err(libc::EINTR) => continue,
                Err(errno) => return Err(Error::fatal(errno, about(&mine.name, b"Error reading"))),
            }
        }
    }

    fn block(&self) -> &[u8] {
        self.nodes
            .get(self.current)
            .and_then(|n| n.buffer.get(..self.len))
            .unwrap_or_default()
    }

    fn can_skip(&self) -> bool {
        true
    }

    /// Regular files and disk-like block devices can use simple lseek
    /// without needing to round the request to the block size.
    ///
    /// TODO: This can leave future reads mis-aligned. Since we know the
    /// offset here, we should store it and use it in the read to determine
    /// whether we should perform a short read to get back into alignment.
    fn skip(&mut self, _a: &Base, node: usize, request: i64) -> Result<i64, Error> {
        let Some(mine) = self.nodes.get_mut(node) else {
            return Ok(0);
        };
        // If we can't skip, return 0; libarchive will read+discard instead.
        let (Some(fd), true) = (mine.fd, mine.use_lseek) else {
            return Ok(0);
        };
        let errno = match fd.lseek(0, libc::SEEK_CUR) {
            Ok(old) if old >= mine.size || request > mine.size - old => {
                // Do not seek past end of file.
                libc::ESPIPE
            }
            Ok(old) => match fd.lseek(request, libc::SEEK_CUR) {
                Ok(new) => return Ok(new - old),
                Err(errno) => errno,
            },
            Err(errno) => errno,
        };

        // If lseek() fails, don't bother trying again.
        mine.use_lseek = false;

        // Let libarchive recover with read+discard.
        if errno == libc::ESPIPE {
            return Ok(0);
        }

        // If the input is corrupted or truncated, fail.
        Err(Error::fatal(errno, about(&mine.name, b"Error seeking in")))
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(&mut self, _a: &Base, node: usize, offset: i64, whence: Whence) -> Result<i64, Error> {
        let Some(mine) = self.nodes.get(node) else {
            return Ok(0);
        };
        let r = match mine.fd {
            Some(fd) => fd.lseek(offset, whence.to_c()),
            None => Err(libc::EBADF),
        };
        // If the input is corrupted or truncated, fail.
        r.map_err(|errno| Error::fatal(errno, about(&mine.name, b"Error seeking in")))
    }

    fn close(&mut self, _a: &Base, node: usize) -> Result<Status, Error> {
        if let Some(mine) = self.nodes.get_mut(node) {
            mine.close();
        }
        Ok(Status::Ok)
    }

    /// The device and inode of the current node, if it is a regular file.
    fn skip_file(&self) -> Option<(i64, i64)> {
        self.nodes.get(self.current)?.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::READ_MAGIC;

    fn base() -> Base {
        Base::new(READ_MAGIC)
    }
    use std::path::PathBuf;

    /// Files named `tag-N` in the temp dir, removed on drop.
    struct Files(Vec<PathBuf>);

    impl Files {
        fn new(tag: &str, contents: &[&[u8]]) -> Self {
            let dir = std::env::temp_dir();
            let paths: Vec<_> = (0..contents.len())
                .map(|i| dir.join(format!("archive-{tag}-{}-{i}", std::process::id())))
                .collect();
            for (p, c) in paths.iter().zip(contents) {
                std::fs::write(p, c).unwrap();
            }
            Files(paths)
        }

        fn client(&self, block_size: usize) -> Filenames {
            let names = self
                .0
                .iter()
                .map(|p| Some(p.as_os_str().as_bytes().to_vec()))
                .collect();
            Filenames::new(names, block_size)
        }
    }

    impl Drop for Files {
        fn drop(&mut self) {
            for p in &self.0 {
                let _ = std::fs::remove_file(p);
            }
        }
    }

    #[test]
    fn reads_the_files_one_after_another() {
        let files = Files::new("multi", &[b"AAAA", b"BBBBBB"]);
        let mut c = files.client(4);
        assert_eq!(c.nodes(), 2);
        c.open(&base(), 0).unwrap();
        c.read(&base(), 0).unwrap();
        // Disk-like inputs get a block size of at least 64k, so the whole
        // file arrives at once.
        assert_eq!(c.block(), b"AAAA");
        assert!(c.skip_file().is_some());
        c.read(&base(), 0).unwrap();
        assert!(c.block().is_empty());
        c.switch(&base(), 0, 1).unwrap();
        c.read(&base(), 1).unwrap();
        assert_eq!(c.block(), b"BBBBBB");
        assert_eq!(c.close(&base(), 0).unwrap(), Status::Ok);
        assert_eq!(c.close(&base(), 1).unwrap(), Status::Ok);
        // Closing twice is harmless.
        assert_eq!(c.close(&base(), 1).unwrap(), Status::Ok);
    }

    #[test]
    fn skip_and_seek_use_lseek() {
        let data: Vec<u8> = (0..200).collect();
        let files = Files::new("skip", &[&data]);
        let mut c = files.client(16);
        c.open(&base(), 0).unwrap();
        assert_eq!(c.skip(&base(), 0, 50).unwrap(), 50);
        assert_eq!(c.seek(&base(), 0, 0, Whence::Cur).unwrap(), 50);
        // Past the end: nothing skipped, and no more tries.
        assert_eq!(c.skip(&base(), 0, 1000).unwrap(), 0);
        assert_eq!(c.skip(&base(), 0, 10).unwrap(), 0);
        assert_eq!(c.seek(&base(), 0, 190, Whence::Set).unwrap(), 190);
        c.read(&base(), 0).unwrap();
        assert_eq!(c.block(), &data[190..]);
        let e = c.seek(&base(), 0, -1, Whence::Set).unwrap_err();
        assert_eq!(e.errno, libc::EINVAL);
        assert!(e.msg.starts_with(b"Error seeking in '"));
    }

    #[test]
    fn open_errors_name_the_file() {
        let mut c = Filenames::new(vec![Some(b"/nonexistent/archive-test".to_vec())], 4);
        let e = c.open(&base(), 0).unwrap_err();
        assert_eq!(e.errno, libc::ENOENT);
        assert_eq!(e.msg, b"Failed to open '/nonexistent/archive-test'");
        // Closing a node that never opened is harmless.
        assert_eq!(c.close(&base(), 0).unwrap(), Status::Ok);
        assert!(c.block().is_empty());
    }

    #[test]
    fn read_errors_name_the_file() {
        let dir = std::env::temp_dir();
        let mut c = Filenames::new(vec![Some(dir.as_os_str().as_bytes().to_vec())], 4);
        c.open(&base(), 0).unwrap();
        let e = c.read(&base(), 0).unwrap_err();
        assert_eq!(e.errno, libc::EISDIR);
        assert!(e.msg.starts_with(b"Error reading '"));
    }
}
