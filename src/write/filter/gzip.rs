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

// Ported from libarchive/archive_write_add_filter_gzip.c.

use super::*;
use miniz_oxide::deflate::core::{
    CompressorOxide, TDEFLFlush, TDEFLStatus, compress, create_comp_flags_from_zip_params,
};
pub struct Gzip {
    level: u8,
    timestamp: bool,
    filename: Vec<u8>,
    state: Option<Box<CompressorOxide>>,
    crc: u32,
    size: u32,
}
impl Default for Gzip {
    fn default() -> Self {
        Self {
            level: 6,
            timestamp: true,
            filename: Vec::new(),
            state: None,
            crc: 0,
            size: 0,
        }
    }
}
impl Gzip {
    fn start(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if self.state.is_some() {
            return Ok(());
        }
        let time = if self.timestamp {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32
        } else {
            0
        };
        let mut header = vec![0x1f, 0x8b, 8, if self.filename.is_empty() { 0 } else { 8 }];
        header.extend_from_slice(&time.to_le_bytes());
        header.push(if self.level == 9 {
            2
        } else if self.level == 1 {
            4
        } else {
            0
        });
        header.push(3);
        if !self.filename.is_empty() {
            header.extend_from_slice(&self.filename);
            header.push(0)
        }
        sink.write(&header)?;
        self.state = Some(Box::new(CompressorOxide::new(
            create_comp_flags_from_zip_params(i32::from(self.level), -15, 0),
        )));
        Ok(())
    }
    fn encode(&mut self, mut input: &[u8], finish: bool, sink: &mut dyn Sink) -> Result<(), Error> {
        self.start(sink)?;
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| Error::fatal(libc::EINVAL, "Missing gzip encoder"))?;
        let mut out = [0; 65536];
        loop {
            let (status, used, n) = compress(
                state,
                input,
                &mut out,
                if finish {
                    TDEFLFlush::Finish
                } else {
                    TDEFLFlush::None
                },
            );
            sink.write(&out[..n])?;
            input = &input[used..];
            if status == TDEFLStatus::Done || (!finish && input.is_empty() && n < out.len()) {
                break;
            }
            if (used == 0 && n == 0) || (status != TDEFLStatus::Okay && status != TDEFLStatus::Done)
            {
                return Err(Error::fatal(-1, "GZip compression failed"));
            }
        }
        Ok(())
    }
}
impl Filter for Gzip {
    fn open(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.start(sink)
    }
    fn name(&self) -> &CStr {
        c"gzip"
    }
    fn code(&self) -> i32 {
        filter_code::GZIP
    }
    fn options(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<i32, Error> {
        match key {
            b"compression-level" => self.level = digit(value, 0, 9, "compression-level invalid")?,
            b"timestamp" => self.timestamp = value.is_some(),
            b"original-filename" => self.filename = value.unwrap_or_default().to_vec(),
            _ => return Ok(ARCHIVE_WARN),
        }
        Ok(ARCHIVE_OK)
    }
    fn write(&mut self, input: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        self.crc = crate::crc32::crc32(self.crc, input);
        self.size = self.size.wrapping_add(input.len() as u32);
        self.encode(input, false, sink)
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.encode(&[], true, sink)?;
        sink.write(&self.crc.to_le_bytes())?;
        sink.write(&self.size.to_le_bytes())
    }
}
