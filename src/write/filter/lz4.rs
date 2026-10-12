/*-
 * Copyright (c) 2014 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_write_add_filter_lz4.c.

use super::*;
use xxhash_rust::xxh32::{Xxh32, xxh32};
pub struct Lz4 {
    block: u8,
    independent: bool,
    checksum: bool,
    block_checksum: bool,
    started: bool,
    input: Vec<u8>,
    hash: Xxh32,
}
impl Default for Lz4 {
    fn default() -> Self {
        Self {
            block: 7,
            independent: true,
            checksum: true,
            block_checksum: false,
            started: false,
            input: Vec::new(),
            hash: Xxh32::new(0),
        }
    }
}
impl Lz4 {
    fn start(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if self.started {
            return Ok(());
        }
        let flags = 0x40
            | (u8::from(self.independent) * 0x20)
            | (u8::from(self.block_checksum) * 0x10)
            | (u8::from(self.checksum) * 4);
        let descriptor = [flags, self.block << 4];
        let mut head = vec![4, 0x22, 0x4d, 0x18];
        head.extend_from_slice(&descriptor);
        head.push((xxh32(&descriptor, 0) >> 8) as u8);
        sink.write(&head)?;
        self.started = true;
        Ok(())
    }
    fn block(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if self.input.is_empty() {
            return Ok(());
        }
        self.hash.update(&self.input);
        let compressed = lz4_flex::block::compress(&self.input);
        let (data, flag) = if compressed.len() < self.input.len() {
            (compressed.as_slice(), 0)
        } else {
            (self.input.as_slice(), 0x80000000)
        };
        sink.write(&(data.len() as u32 | flag).to_le_bytes())?;
        sink.write(data)?;
        if self.block_checksum {
            sink.write(&xxh32(data, 0).to_le_bytes())?
        }
        self.input.clear();
        Ok(())
    }
}
impl Filter for Lz4 {
    fn open(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.start(sink)
    }
    fn code(&self) -> i32 {
        filter_code::LZ4
    }
    fn name(&self) -> &CStr {
        c"lz4"
    }
    fn has_options(&self) -> bool {
        true
    }
    fn options(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<i32, Error> {
        match key {
            b"compression-level" => {
                digit(value, 1, 9, "compression-level invalid")?;
            }
            b"block-size" => self.block = digit(value, 4, 7, "block-size invalid")?,
            b"stream-checksum" => self.checksum = value.is_some(),
            b"block-checksum" => self.block_checksum = value.is_some(),
            b"block-dependence" => self.independent = value.is_none(),
            _ => return Ok(ARCHIVE_WARN),
        }
        Ok(ARCHIVE_OK)
    }
    fn write(&mut self, mut input: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        self.start(sink)?;
        let max = 1usize << (8 + 2 * usize::from(self.block));
        while !input.is_empty() {
            let n = input.len().min(max - self.input.len());
            self.input.extend_from_slice(&input[..n]);
            input = &input[n..];
            if self.input.len() == max {
                self.block(sink)?
            }
        }
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.start(sink)?;
        self.block(sink)?;
        sink.write(&[0; 4])?;
        if self.checksum {
            sink.write(&self.hash.digest().to_le_bytes())?;
        }
        Ok(())
    }
}
