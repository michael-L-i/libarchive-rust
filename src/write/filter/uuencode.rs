/*-
 * Copyright (c) 2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_write_add_filter_uuencode.c.

use super::*;
pub struct Encode {
    base64: bool,
    mode: u32,
    filename: Vec<u8>,
    hold: Vec<u8>,
    started: bool,
}
impl Encode {
    pub fn new(code: i32) -> Self {
        Self {
            base64: code == 15,
            mode: 0o644,
            filename: b"-".to_vec(),
            hold: Vec::new(),
            started: false,
        }
    }
    fn start(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if self.started {
            return Ok(());
        }
        let mut h = format!(
            "{} {:o} ",
            if self.base64 { "begin-base64" } else { "begin" },
            self.mode
        )
        .into_bytes();
        h.extend_from_slice(&self.filename);
        h.push(b'\n');
        sink.write(&h)?;
        self.started = true;
        Ok(())
    }
    fn line(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        let mut out = Vec::with_capacity(80);
        if !self.base64 {
            out.push(uu(self.hold.len() as u8));
        }
        for chunk in self.hold.chunks(3) {
            let a = chunk[0];
            let b = chunk.get(1).copied().unwrap_or(0);
            let c = chunk.get(2).copied().unwrap_or(0);
            let q = [
                a >> 2,
                ((a & 3) << 4) | (b >> 4),
                ((b & 15) << 2) | (c >> 6),
                c & 63,
            ];
            for (i, v) in q.into_iter().enumerate() {
                out.push(if self.base64 {
                    if (i == 2 && chunk.len() == 1) || (i == 3 && chunk.len() < 3) {
                        b'='
                    } else {
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                            [usize::from(v)]
                    }
                } else {
                    uu(v)
                });
            }
        }
        out.push(b'\n');
        self.hold.clear();
        sink.write(&out)
    }
}
fn uu(v: u8) -> u8 {
    if v == 0 { b'`' } else { v + 32 }
}
impl Filter for Encode {
    fn open(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.start(sink)
    }
    fn code(&self) -> i32 {
        filter_code::UU
    }
    fn name(&self) -> &CStr {
        if self.base64 {
            c"b64encode"
        } else {
            c"uuencode"
        }
    }
    fn has_options(&self) -> bool {
        true
    }
    fn options(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<i32, Error> {
        match key {
            b"mode" => {
                let v = value.ok_or_else(|| invalid("mode option requires octal digits"))?;
                let n = std::str::from_utf8(v)
                    .ok()
                    .and_then(|s| u32::from_str_radix(s, 8).ok())
                    .filter(|n| *n <= i32::MAX as u32)
                    .ok_or_else(|| invalid("invalid mode option"))?;
                self.mode = n & 0o777;
            }
            b"name" => {
                self.filename = value
                    .ok_or_else(|| invalid("name option requires a string"))?
                    .to_vec()
            }
            _ => return Ok(ARCHIVE_WARN),
        }
        Ok(ARCHIVE_OK)
    }
    fn write(&mut self, mut input: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        self.start(sink)?;
        let max = if self.base64 { 57 } else { 45 };
        while !input.is_empty() {
            let n = input.len().min(max - self.hold.len());
            self.hold.extend_from_slice(&input[..n]);
            input = &input[n..];
            if self.hold.len() == max {
                self.line(sink)?
            }
        }
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.start(sink)?;
        if !self.hold.is_empty() {
            self.line(sink)?
        }
        sink.write(if self.base64 { b"====\n" } else { b"`\nend\n" })
    }
}
