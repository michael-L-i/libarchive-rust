/*-
 * Copyright (c) 2003-2007 Tim Kientzle
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

// Ported from libarchive/archive_read_open_fd.c.

//! The client behind `archive_read_open_fd`: reads an archive from a file
//! descriptor the caller owns.

use crate::archive::ARCHIVE_FAILED;
use crate::ffi::sys::Fd;
use crate::read::{Client, Whence};
use crate::util::Error;

pub struct ReadFd {
    fd: Fd,
    block_size: usize,
    size: i64,
    use_lseek: bool,
    buffer: Vec<u8>,
    len: usize,
}

/// `Error` for a failure to allocate a block buffer of `block_size`.
pub fn buffer(block_size: usize) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    b.try_reserve_exact(block_size)
        .map_err(|_| Error::fatal(libc::ENOMEM, "No memory"))?;
    b.resize(block_size, 0);
    Ok(b)
}

impl ReadFd {
    /// `archive_read_open_fd`'s setup. Returns the client, and the device
    /// and inode of the input if it is a regular file (so extraction can
    /// avoid overwriting it).
    pub fn new(fd: Fd, block_size: usize) -> Result<(Self, Option<(i64, i64)>), Error> {
        let st = fd
            .fstat()
            .map_err(|errno| Error::fatal(errno, format!("Can't stat fd {}", fd.0)))?;
        let mine = ReadFd {
            fd,
            block_size,
            size: st.size,
            // Skip support is a performance optimization for anything that
            // supports lseek(). On FreeBSD, only regular files and raw disk
            // devices support lseek() and there's no portable way to
            // determine if a device is a raw disk device, so we only enable
            // this optimization for regular files.
            use_lseek: st.is_reg(),
            buffer: buffer(block_size)?,
            len: 0,
        };
        Ok((mine, st.is_reg().then_some((st.dev, st.ino))))
    }
}

impl Client for ReadFd {
    fn read(&mut self, _node: usize) -> Result<(), Error> {
        self.len = 0;
        loop {
            match self.fd.read(&mut self.buffer) {
                Ok(n) => {
                    self.len = n;
                    return Ok(());
                }
                Err(libc::EINTR) => continue,
                Err(errno) => {
                    return Err(Error::fatal(
                        errno,
                        format!("Error reading fd {}", self.fd.0),
                    ));
                }
            }
        }
    }

    fn block(&self) -> &[u8] {
        self.buffer.get(..self.len).unwrap_or_default()
    }

    fn can_skip(&self) -> bool {
        true
    }

    fn skip(&mut self, _node: usize, request: i64) -> Result<i64, Error> {
        if !self.use_lseek {
            return Ok(0);
        }
        // Reduce 'skip' to the next smallest multiple of block_size.
        let block_size = i64::try_from(self.block_size).unwrap_or(i64::MAX);
        let skip = request.checked_div(block_size).unwrap_or(0) * block_size;
        if skip == 0 {
            return Ok(0);
        }

        let errno = match self.fd.lseek(0, libc::SEEK_CUR) {
            Ok(old) if old >= self.size || skip > self.size - old => {
                // Do not seek past end of file.
                libc::ESPIPE
            }
            Ok(old) => match self.fd.lseek(skip, libc::SEEK_CUR) {
                Ok(new) => return Ok(new - old),
                Err(errno) => errno,
            },
            Err(errno) => errno,
        };

        // If seek failed once, it will probably fail again.
        self.use_lseek = false;

        // Let libarchive recover with read+discard.
        if errno == libc::ESPIPE {
            return Ok(0);
        }

        // There's been an error other than ESPIPE. This is most likely
        // caused by a programmer error (too large request) or a corrupted
        // archive file.
        Err(Error::fatal(errno, "Error seeking"))
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(&mut self, _node: usize, offset: i64, whence: Whence) -> Result<i64, Error> {
        self.fd.lseek(offset, whence.to_c()).map_err(|errno| {
            if errno == libc::ESPIPE {
                Error::new(
                    ARCHIVE_FAILED,
                    errno,
                    format!("A file descriptor({}) is not seekable(PIPE)", self.fd.0),
                )
            } else {
                // If the input is corrupted or truncated, fail.
                Error::fatal(
                    errno,
                    format!("Error seeking in a file descriptor({})", self.fd.0),
                )
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    fn file(data: &[u8]) -> std::fs::File {
        let path = std::env::temp_dir().join(format!(
            "archive-fd-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, data).unwrap();
        let f = std::fs::File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        f
    }

    #[test]
    fn regular_file_reads_skips_and_seeks() {
        let data: Vec<u8> = (0..100).collect();
        let f = file(&data);
        let (mut c, skip_file) = ReadFd::new(Fd(f.as_raw_fd()), 8).unwrap();
        assert!(skip_file.is_some());
        c.read(0).unwrap();
        assert_eq!(c.block(), &data[..8]);
        // Skips whole blocks only, and never past the end.
        assert_eq!(c.skip(0, 20).unwrap(), 16);
        c.read(0).unwrap();
        assert_eq!(c.block(), &data[24..32]);
        assert_eq!(c.skip(0, 7).unwrap(), 0);
        assert_eq!(c.skip(0, 1000).unwrap(), 0);
        assert_eq!(c.seek(0, -4, Whence::End).unwrap(), 96);
        c.read(0).unwrap();
        assert_eq!(c.block(), &data[96..]);
        c.read(0).unwrap();
        assert!(c.block().is_empty());
        let e = c.seek(0, -1, Whence::Set).unwrap_err();
        assert_eq!((e.code, e.errno), (crate::archive::ARCHIVE_FATAL, libc::EINVAL));
        assert_eq!(e.msg, format!("Error seeking in a file descriptor({})", f.as_raw_fd()).into_bytes());
    }

    #[test]
    fn bad_descriptor_is_reported() {
        let Err(e) = ReadFd::new(Fd(-1), 8) else {
            panic!("fd -1 opened");
        };
        assert_eq!((e.errno, e.msg.as_slice()), (libc::EBADF, b"Can't stat fd -1".as_slice()));
    }

    #[test]
    fn pipes_read_but_neither_skip_nor_seek() {
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(b"pipe data").unwrap();
        let r = Fd(reader.as_raw_fd());
        let (mut c, skip_file) = ReadFd::new(r, 4).unwrap();
        assert!(skip_file.is_none());
        c.read(0).unwrap();
        assert_eq!(c.block(), b"pipe");
        assert_eq!(c.skip(0, 100).unwrap(), 0);
        let e = c.seek(0, 0, Whence::Set).unwrap_err();
        assert_eq!((e.code, e.errno), (ARCHIVE_FAILED, libc::ESPIPE));
        assert_eq!(e.msg, format!("A file descriptor({}) is not seekable(PIPE)", r.0).into_bytes());
    }

    #[test]
    fn read_errors_name_the_descriptor() {
        let f = file(b"x");
        let fd = Fd(f.as_raw_fd());
        let (mut c, _) = ReadFd::new(fd, 4).unwrap();
        c.fd = Fd(-1);
        let e = c.read(0).unwrap_err();
        assert_eq!((e.errno, e.msg.as_slice()), (libc::EBADF, b"Error reading fd -1".as_slice()));
    }
}
