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

// Ported from libarchive/archive_read_open_memory.c.

//! The client behind `archive_read_open_memory`: reads an archive from a
//! block of memory. Mostly a huge help in building test harnesses; test
//! programs can build archives in memory and read them back again without
//! having to mess with files on disk.

use crate::archive::ARCHIVE_FATAL;
use crate::read::{Client, Whence};
use crate::util::Error;
use std::ops::Range;

pub struct Memory<D> {
    data: D,
    /// Where the next read starts.
    pos: usize,
    /// The block the last read produced.
    block: Range<usize>,
    read_size: usize,
}

impl<D: AsRef<[u8]>> Memory<D> {
    /// A client over `data` that hands out at most `read_size` bytes per
    /// read. Limiting to a read size is not technically necessary, but it
    /// exercises more of the internal logic when used with a small block
    /// size in a test harness. Production use should not specify one; then
    /// this is much faster (`archive_read_open_memory` passes the size).
    pub fn new(data: D, read_size: usize) -> Self {
        Memory {
            data,
            pos: 0,
            block: 0..0,
            read_size,
        }
    }
}

impl<D: AsRef<[u8]>> Client for Memory<D> {
    /// This is scary simple: just advance a pointer.
    fn read(&mut self, _node: usize) -> Result<(), Error> {
        let len = self.data.as_ref().len();
        let end = len.min(self.pos.saturating_add(self.read_size));
        self.block = self.pos.min(end)..end;
        self.pos = end;
        Ok(())
    }

    fn block(&self) -> &[u8] {
        self.data.as_ref().get(self.block.clone()).unwrap_or_default()
    }

    fn can_skip(&self) -> bool {
        true
    }

    /// Advancing is just as simple. Again, this is doing more than necessary
    /// in order to better exercise internal code when used as a test
    /// harness.
    fn skip(&mut self, _node: usize, request: i64) -> Result<i64, Error> {
        let left = self.data.as_ref().len().saturating_sub(self.pos);
        let skip = usize::try_from(request).unwrap_or(0).min(left);
        // Round down to block size.
        let skip = skip.checked_div(self.read_size).unwrap_or(0) * self.read_size;
        self.pos += skip;
        Ok(i64::try_from(skip).unwrap_or(0))
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(&mut self, _node: usize, offset: i64, whence: Whence) -> Result<i64, Error> {
        let len = i64::try_from(self.data.as_ref().len()).unwrap_or(i64::MAX);
        let base = match whence {
            Whence::Set => 0,
            Whence::Cur => i64::try_from(self.pos).unwrap_or(i64::MAX),
            Whence::End => len,
        };
        match base.checked_add(offset) {
            Some(p) if (0..=len).contains(&p) => {
                self.pos = usize::try_from(p).unwrap_or(0);
                Ok(p)
            }
            _ => Err(Error::recorded(ARCHIVE_FATAL)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(m: &mut Memory<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            m.read(0).unwrap();
            if m.block().is_empty() {
                return out;
            }
            out.push(m.block().to_vec());
        }
    }

    #[test]
    fn reads_in_blocks_of_the_read_size() {
        let mut m = Memory::new(b"0123456789".to_vec(), 4);
        assert_eq!(collect(&mut m), [b"0123".to_vec(), b"4567".to_vec(), b"89".to_vec()]);
        let mut m = Memory::new(b"0123456789".to_vec(), 100);
        assert_eq!(collect(&mut m), [b"0123456789".to_vec()]);
        // A zero read size reads nothing, rather than looping or dividing
        // by zero when skipping.
        let mut m = Memory::new(b"abc".to_vec(), 0);
        assert!(collect(&mut m).is_empty());
        assert_eq!(m.skip(0, 2).unwrap(), 0);
        let mut m = Memory::new(Vec::new(), 4);
        assert!(collect(&mut m).is_empty());
    }

    #[test]
    fn skip_rounds_down_to_whole_blocks() {
        let mut m = Memory::new(b"0123456789".to_vec(), 4);
        assert_eq!(m.skip(0, 3).unwrap(), 0);
        assert_eq!(m.skip(0, 9).unwrap(), 8);
        m.read(0).unwrap();
        assert_eq!(m.block(), b"89");
        assert_eq!(m.skip(0, -5).unwrap(), 0);
        assert_eq!(m.skip(0, i64::MAX).unwrap(), 0);
    }

    #[test]
    fn seek_stays_inside_the_memory() {
        let mut m = Memory::new(b"0123456789".to_vec(), 4);
        assert_eq!(m.seek(0, 3, Whence::Set).unwrap(), 3);
        m.read(0).unwrap();
        assert_eq!(m.block(), b"3456");
        assert_eq!(m.seek(0, -2, Whence::Cur).unwrap(), 5);
        assert_eq!(m.seek(0, 0, Whence::End).unwrap(), 10);
        assert_eq!(m.seek(0, -10, Whence::End).unwrap(), 0);
        for (off, whence) in [(-1, Whence::Set), (11, Whence::Set), (1, Whence::End), (i64::MAX, Whence::Cur), (i64::MIN, Whence::End)] {
            assert_eq!(m.seek(0, off, whence).unwrap_err().code, ARCHIVE_FATAL);
        }
        // A failed seek leaves the position alone.
        assert_eq!(m.seek(0, 0, Whence::Cur).unwrap(), 0);
    }
}
