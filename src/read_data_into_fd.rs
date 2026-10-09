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

// Ported from libarchive/archive_read_data_into_fd.c.

//! `archive_read_data_into_fd`: copying an entry's data to a file.

use crate::archive::*;
use crate::ffi::sys::Fd;
use crate::read::{Data, Read};
use crate::util::Error;
use std::ffi::c_int;

/// Maximum amount of data to write at one time.
const MAX_WRITE: usize = 1024 * 1024;

/// How much of the data is written to the file so far, and where it should
/// be: this implementation minimizes copying of data and is sparse-file
/// aware.
struct Output {
    fd: Fd,
    can_lseek: bool,
    /// Zeros to write for holes, when the file can't seek.
    nulls: Vec<u8>,
    /// The offset in the entry of the data being written.
    target_offset: i64,
    /// How far the file has got.
    actual_offset: i64,
    declared_size: Option<i64>,
}

/// What a block of data did to the output.
enum Step {
    Continue,
    Eof,
    /// Stop with this status.
    Stop(c_int),
}

impl Output {
    fn pad_to(&mut self, a: &Base) -> c_int {
        const NULLS_SIZE: usize = 16384;
        if self.can_lseek {
            let Some(relative) = self.target_offset.checked_sub(self.actual_offset) else {
                a.set_error(ARCHIVE_ERRNO_MISC, Some(b"Seek error"));
                return ARCHIVE_FATAL;
            };
            let r = self.fd.lseek(relative, libc::SEEK_CUR);
            if r != Ok(self.target_offset) {
                let errno = r.err().unwrap_or(ARCHIVE_ERRNO_MISC);
                a.set_error(errno, Some(b"Seek error"));
                return ARCHIVE_FATAL;
            }
            return ARCHIVE_OK;
        }
        if self.nulls.is_empty() {
            self.nulls = vec![0; NULLS_SIZE];
        }
        while self.target_offset > self.actual_offset {
            let left = self
                .target_offset
                .checked_sub(self.actual_offset)
                .and_then(|left| usize::try_from(left).ok())
                .unwrap_or(NULLS_SIZE);
            let chunk = self.nulls.get(..left.min(NULLS_SIZE)).unwrap_or_default();
            match self.fd.write(chunk) {
                Ok(n) if n > 0 => self.actual_offset += i64::try_from(n).unwrap_or(0),
                other => {
                    a.set_error(other.err().unwrap_or(libc::EIO), Some(b"Write error"));
                    return ARCHIVE_FATAL;
                }
            }
        }
        ARCHIVE_OK
    }

    fn overran(&self, a: &Base, declared: i64) -> c_int {
        a.raise(Error::new(
            ARCHIVE_FAILED,
            ARCHIVE_ERRNO_MISC,
            format!(
                "Actual entry size exceeds the declared size ({declared}); truncated output at the declared size"
            ),
        ))
    }

    /// One block of the entry.
    fn block(&mut self, a: &Base, data: &[u8], offset: i64) -> Step {
        self.target_offset = offset;
        let mut data = data;
        let mut overran = false;

        if let Some(declared) = self.declared_size {
            // We know the expected size, let's enforce that we don't overrun.
            let room = declared
                .checked_sub(self.target_offset)
                .and_then(|room| usize::try_from(room).ok());
            if self.target_offset > declared || room.is_none() {
                // We're already beyond the end? Don't write any more.
                self.target_offset = declared;
                data = &[];
                overran = true;
            } else if let Some(room) = room
                && data.len() > room
            {
                // This block is bigger than the expected remainder.
                data = data.get(..room).unwrap_or_default();
                overran = true;
            }
        }

        if self.target_offset > self.actual_offset {
            let r = self.pad_to(a);
            if r != ARCHIVE_OK {
                return Step::Stop(r);
            }
            self.actual_offset = self.target_offset;
        }
        for chunk in data.chunks(MAX_WRITE) {
            let mut chunk = chunk;
            while !chunk.is_empty() {
                match self.fd.write(chunk) {
                    Ok(n) if n > 0 => {
                        self.actual_offset += i64::try_from(n).unwrap_or(0);
                        chunk = chunk.get(n..).unwrap_or_default();
                    }
                    other => {
                        a.set_error(other.err().unwrap_or(libc::EIO), Some(b"Write error"));
                        return Step::Stop(ARCHIVE_FATAL);
                    }
                }
            }
        }
        match (overran, self.declared_size) {
            (true, Some(declared)) => Step::Stop(self.overran(a, declared)),
            _ => Step::Continue,
        }
    }
}

/// `archive_read_data_into_fd`, after the caller has checked the state:
/// writes the rest of the entry to `fd`, seeking over holes if it can.
pub fn data_into_fd(r: &mut Read, a: &Base, fd: Fd) -> c_int {
    let declared_size = r.entry_bytes_declared;
    let (can_lseek, fd_offset) = match fd.fstat() {
        Ok(st) if st.is_reg() => match fd.lseek(0, libc::SEEK_CUR) {
            Ok(offset) => (true, offset),
            Err(_) => (false, 0),
        },
        _ => (false, 0),
    };
    let mut out = Output {
        fd,
        can_lseek,
        nulls: Vec::new(),
        target_offset: 0,
        actual_offset: 0,
        declared_size,
    };

    let mut status = loop {
        let step = r.read_data_block(a, |data| match data {
            Data::Block { data, offset } => out.block(a, data, offset),
            Data::Eof { offset } => {
                out.target_offset = offset;
                Step::Eof
            }
            Data::Warn { .. } => Step::Stop(ARCHIVE_WARN),
        });
        match step {
            Ok(Step::Continue) => {}
            Ok(Step::Eof) => break ARCHIVE_EOF,
            Ok(Step::Stop(code)) | Err(code) => break code,
        }
    };

    if status == ARCHIVE_EOF && out.target_offset > out.actual_offset {
        let trailing_hole_overran = declared_size.is_some_and(|d| out.target_offset > d);
        if let (true, Some(declared)) = (trailing_hole_overran, declared_size) {
            out.target_offset = declared;
        }
        if out.target_offset > out.actual_offset {
            let r2 = out.pad_to(a);
            if r2 != ARCHIVE_OK {
                status = r2;
            } else {
                out.actual_offset = out.target_offset;
            }
        }
        if let (true, Some(declared)) = (trailing_hole_overran, declared_size) {
            status = out.overran(a, declared);
        }
    }

    if status != ARCHIVE_EOF {
        return status;
    }
    if can_lseek {
        let offset = fd.lseek(0, libc::SEEK_CUR);
        if offset.map(|o| o.checked_sub(fd_offset)) != Ok(Some(out.actual_offset)) {
            a.set_error(
                offset.err().unwrap_or(ARCHIVE_ERRNO_MISC),
                Some(b"Seek error"),
            );
            return ARCHIVE_FATAL;
        }
    }
    ARCHIVE_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Entry;
    use crate::read::{Format, Reader, Status};
    use crate::read_open_memory::Memory;
    use std::io::{Read as _, Seek, SeekFrom};
    use std::os::fd::AsRawFd;

    /// Serves blocks of an entry at given offsets, then ends at `end`.
    struct Blocks {
        blocks: Vec<(i64, Vec<u8>)>,
        end: i64,
        next: usize,
        /// The size the entry's header declares.
        declared: Option<i64>,
    }

    impl Format for Blocks {
        fn name(&self) -> &'static str {
            "blocks"
        }

        fn bid(&mut self, _: &mut Reader<'_>, _: c_int) -> Result<c_int, Error> {
            Ok(1)
        }

        fn read_header(&mut self, _: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
            if let Some(size) = self.declared {
                entry.set_size(size);
            }
            Ok(Status::Ok)
        }

        fn read_data<'x>(&'x mut self, _: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
            self.next += 1;
            Ok(match self.blocks.get(self.next - 1) {
                Some((offset, data)) => Data::Block {
                    data,
                    offset: *offset,
                },
                None => Data::Eof { offset: self.end },
            })
        }
    }

    fn entry(blocks: &[(i64, &[u8])], end: i64, declared: Option<i64>) -> (Read, Base) {
        let mut r = Read::default();
        let blocks = blocks.iter().map(|(o, d)| (*o, d.to_vec())).collect();
        let format = Blocks {
            blocks,
            end,
            next: 0,
            declared,
        };
        assert_eq!(r.register_format(Box::new(format)).unwrap(), Status::Ok);
        let a = Base::new(READ_MAGIC);
        assert_eq!(
            r.open(&a, Box::new(Memory::new(b"x".to_vec(), 1))),
            ARCHIVE_OK
        );
        // The declared size comes from the header, as it does for a caller.
        assert_eq!(r.next_header2(&a, &mut Entry::new(None)), ARCHIVE_OK);
        assert_eq!(r.entry_bytes_declared, declared);
        (r, a)
    }

    fn temp_file() -> std::fs::File {
        let p = std::env::temp_dir().join(format!(
            "archive-into-fd-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&p)
            .unwrap();
        std::fs::remove_file(&p).unwrap();
        f
    }

    fn contents(f: &mut std::fs::File) -> Vec<u8> {
        let mut v = Vec::new();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read_to_end(&mut v).unwrap();
        v
    }

    fn error(a: &Base) -> String {
        a.error_string()
            .map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned())
    }

    #[test]
    fn writes_blocks_and_seeks_over_holes() {
        let (mut r, a) = entry(&[(0, b"abc"), (6, b"def")], 12, None);
        let mut f = temp_file();
        assert_eq!(data_into_fd(&mut r, &a, Fd(f.as_raw_fd())), ARCHIVE_OK);
        // The trailing hole is created by seeking, so the file ends at 9.
        assert_eq!(contents(&mut f), b"abc\0\0\0def");
    }

    #[test]
    fn writes_zeros_where_it_cannot_seek() {
        let (mut r, a) = entry(&[(2, b"ab")], 7, None);
        let (mut reader, writer) = std::io::pipe().unwrap();
        assert_eq!(data_into_fd(&mut r, &a, Fd(writer.as_raw_fd())), ARCHIVE_OK);
        drop(writer);
        let mut v = Vec::new();
        reader.read_to_end(&mut v).unwrap();
        assert_eq!(v, b"\0\0ab\0\0\0");
    }

    #[test]
    fn stops_at_the_declared_size() {
        let (mut r, a) = entry(&[(0, b"abcdef")], 6, Some(4));
        let mut f = temp_file();
        assert_eq!(data_into_fd(&mut r, &a, Fd(f.as_raw_fd())), ARCHIVE_FAILED);
        assert_eq!(contents(&mut f), b"abcd");
        assert_eq!(
            error(&a),
            "Actual entry size exceeds the declared size (4); truncated output at the declared size"
        );

        // A block that starts beyond the end writes nothing.
        let (mut r, a) = entry(&[(0, b"ab"), (9, b"zz")], 11, Some(4));
        let mut f = temp_file();
        assert_eq!(data_into_fd(&mut r, &a, Fd(f.as_raw_fd())), ARCHIVE_FAILED);
        assert_eq!(contents(&mut f), b"ab");

        // So does a trailing hole.
        let (mut r, a) = entry(&[(0, b"ab")], 10, Some(4));
        let mut f = temp_file();
        assert_eq!(data_into_fd(&mut r, &a, Fd(f.as_raw_fd())), ARCHIVE_FAILED);
        assert_eq!(contents(&mut f), b"ab");

        // Within the declared size is fine.
        let (mut r, a) = entry(&[(0, b"ab")], 2, Some(2));
        let mut f = temp_file();
        assert_eq!(data_into_fd(&mut r, &a, Fd(f.as_raw_fd())), ARCHIVE_OK);
        assert_eq!(contents(&mut f), b"ab");
    }

    #[test]
    fn write_errors_are_fatal() {
        let (mut r, a) = entry(&[(0, b"ab")], 2, None);
        assert_eq!(data_into_fd(&mut r, &a, Fd(-1)), ARCHIVE_FATAL);
        assert_eq!(
            (error(&a), a.errno.get()),
            ("Write error".into(), libc::EBADF)
        );
    }

    #[test]
    fn hostile_offsets_do_not_overflow() {
        let (mut r, a) = entry(&[(-5, b"ab")], 0, Some(i64::MAX));
        let mut f = temp_file();
        let code = data_into_fd(&mut r, &a, Fd(f.as_raw_fd()));
        assert!(code == ARCHIVE_FAILED || code == ARCHIVE_FATAL);
        let (mut r, a) = entry(&[(i64::MAX - 1, b"ab")], i64::MAX, None);
        let code = data_into_fd(&mut r, &a, Fd(f.as_raw_fd()));
        assert!(code < ARCHIVE_OK);
        assert_eq!(contents(&mut f), b"");
    }
}
