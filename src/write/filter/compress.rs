/*-
 * Copyright (c) 2008 Joerg Sonnenberger
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

// Ported from libarchive/archive_write_add_filter_compress.c.

use super::*;
use std::collections::HashMap;
pub struct Compress {
    dict: HashMap<(u32, u8), u32>,
    current: u32,
    free: u32,
    width: u32,
    max: u32,
    bits: u32,
    buffer: u32,
    count: u64,
    out_count: u64,
    checkpoint: u64,
    ratio: u64,
    started: bool,
}
impl Default for Compress {
    fn default() -> Self {
        Self {
            dict: HashMap::new(),
            current: 0,
            free: 257,
            width: 9,
            max: 511,
            bits: 0,
            buffer: 0,
            count: 0,
            out_count: 3,
            checkpoint: 10000,
            ratio: 0,
            started: false,
        }
    }
}
impl Compress {
    fn byte(&mut self, b: u8, out: &mut Vec<u8>) {
        out.push(b);
        self.out_count += 1;
    }
    fn emit(&mut self, code: u32, out: &mut Vec<u8>) {
        let clear = code == 256;
        self.code_raw(code, out);
        if clear || self.free > self.max {
            self.align(out, clear)
        }
    }
    fn code_raw(&mut self, mut code: u32, out: &mut Vec<u8>) {
        let offset = self.bits % 8;
        self.buffer |= (code << offset) & 255;
        self.byte(self.buffer as u8, out);
        let mut n = self.width - (8 - offset);
        code >>= 8 - offset;
        if n >= 8 {
            self.byte(code as u8, out);
            code >>= 8;
            n -= 8
        }
        self.bits += self.width;
        self.buffer = code & ((1 << n) - 1);
        if self.bits == self.width * 8 {
            self.bits = 0
        }
    }
    fn align(&mut self, out: &mut Vec<u8>, clear: bool) {
        if self.bits > 0 {
            while self.bits < self.width * 8 {
                self.byte(self.buffer as u8, out);
                self.bits += 8;
                self.buffer = 0
            }
        }
        self.bits = 0;
        self.buffer = 0;
        if clear {
            self.width = 9;
            self.max = 511
        } else {
            self.width += 1;
            self.max = if self.width == 16 {
                65536
            } else {
                (1 << self.width) - 1
            }
        }
    }
    fn start(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if !self.started {
            sink.write(&[0x1f, 0x9d, 0x90])?;
            self.started = true;
        }
        Ok(())
    }
}
impl Filter for Compress {
    fn name(&self) -> &CStr {
        c"compress"
    }
    fn code(&self) -> i32 {
        filter_code::COMPRESS
    }
    fn write(&mut self, input: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        self.start(sink)?;
        let mut out = Vec::with_capacity(65536);
        for &c in input {
            self.count += 1;
            if self.count == 1 {
                self.current = c.into();
                continue;
            }
            if let Some(&code) = self.dict.get(&(self.current, c)) {
                self.current = code;
                continue;
            }
            let old = self.current;
            self.emit(old, &mut out);
            self.current = c.into();
            if self.free < 65536 {
                self.dict.insert((old, c), self.free);
                self.free += 1;
            } else if self.count >= self.checkpoint {
                self.checkpoint = self.count.saturating_add(10000);
                let ratio = if self.count <= 0x7fffff && self.out_count != 0 {
                    self.count * 256 / self.out_count
                } else {
                    self.count
                        .checked_div(self.out_count / 256)
                        .unwrap_or(0x7fffffff)
                };
                if ratio > self.ratio {
                    self.ratio = ratio
                } else {
                    self.ratio = 0;
                    self.dict.clear();
                    self.free = 257;
                    self.emit(256, &mut out)
                }
            }
            if out.len() >= 65000 {
                sink.write(&out)?;
                out.clear();
            }
        }
        sink.write(&out)
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.start(sink)?;
        let mut out = Vec::new();
        self.emit(self.current, &mut out);
        if !self.bits.is_multiple_of(8) {
            self.byte(self.buffer as u8, &mut out)
        }
        sink.write(&out)
    }
}
