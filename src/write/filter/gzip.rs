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
use deflate::{Deflate, Flush, Status};

/// Upstream's error for a failed deflate() call.
pub(crate) fn failed(e: deflate::Error) -> Error {
    Error::fatal(
        -1,
        format!(
            "GZip compression failed: deflate() call returned status {}",
            e.code()
        ),
    )
}

/// What frames the deflate stream.
#[derive(Clone, Copy, PartialEq)]
enum Wrap {
    /// The gzip filter's header and trailer.
    Gzip,
    /// None: 7-Zip's and ZIP's deflate coders.
    Raw,
    /// A zlib header and trailer: XAR's gzip encoding.
    Zlib,
}

pub struct Gzip {
    level: u8,
    timestamp: bool,
    filename: Vec<u8>,
    wrap: Wrap,
    state: Option<Deflate>,
    /// The compressed buffer and how much of it is filled.
    compressed: Vec<u8>,
    used: usize,
    crc: u32,
    size: u32,
}
impl Default for Gzip {
    fn default() -> Self {
        Self {
            level: 6,
            timestamp: true,
            filename: Vec::new(),
            wrap: Wrap::Gzip,
            state: None,
            compressed: Vec::new(),
            used: 0,
            crc: 0,
            size: 0,
        }
    }
}
impl Gzip {
    /// A raw deflate stream, buffered like 7-Zip's coders.
    pub(crate) fn raw(level: u8) -> Self {
        Self {
            level,
            wrap: Wrap::Raw,
            ..Self::default()
        }
    }
    /// A zlib stream, buffered like XAR's.
    pub(crate) fn zlib(level: u8) -> Self {
        Self {
            level,
            wrap: Wrap::Zlib,
            ..Self::default()
        }
    }
    fn start(&mut self, sink: &dyn Sink) -> Result<(), Error> {
        if self.state.is_some() {
            return Ok(());
        }
        let size = match self.wrap {
            Wrap::Gzip => {
                // Buffer size should be a multiple number of the of bytes per
                // block for performance.
                let (bs, bpb) = (65536, sink.bytes_per_block());
                if bpb > bs {
                    bpb
                } else if bpb != 0 {
                    bs - bs % bpb
                } else {
                    bs
                }
            }
            // The callers' write buffers: 7-Zip's 512 * 20 * 6, XAR's 64K.
            Wrap::Raw => 61440,
            Wrap::Zlib => 65536,
        };
        if self.compressed.try_reserve_exact(size).is_err() {
            return Err(Error::fatal(
                libc::ENOMEM,
                "Can't allocate data for compression buffer",
            ));
        }
        if self.wrap == Wrap::Gzip {
            // Prime output buffer with a gzip header.
            let time = if self.timestamp {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32
            } else {
                0
            };
            let flags = if self.filename.is_empty() { 0 } else { 8 };
            self.compressed.extend_from_slice(&[0x1f, 0x8b, 8, flags]);
            self.compressed.extend_from_slice(&time.to_le_bytes());
            self.compressed.push(match self.level {
                9 => 2,
                1 => 4,
                _ => 0,
            });
            self.compressed.push(3); // OS=Unix
            if !self.filename.is_empty() {
                self.compressed.extend_from_slice(&self.filename);
                self.compressed.push(0);
            }
        }
        self.used = self.compressed.len();
        self.compressed.resize(size.max(self.used), 0);
        let window_bits = if self.wrap == Wrap::Zlib { 15 } else { -15 };
        self.state = Some(
            Deflate::new(i32::from(self.level), window_bits, 8).ok_or_else(|| {
                Error::fatal(
                    -1,
                    "Internal error initializing compression library: invalid setup parameter",
                )
            })?,
        );
        Ok(())
    }
    /// Push input data through the compressor, writing full output blocks as
    /// necessary.
    fn drive(
        &mut self,
        mut input: &[u8],
        finishing: bool,
        sink: &mut dyn Sink,
    ) -> Result<(), Error> {
        self.start(sink)?;
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| Error::fatal(libc::EINVAL, "Missing gzip encoder"))?;
        let flush = if finishing {
            Flush::Finish
        } else {
            Flush::None
        };
        loop {
            if self.used == self.compressed.len() {
                sink.write(&self.compressed)?;
                self.used = 0;
            }
            // If there's nothing to do, we're done.
            if !finishing && input.is_empty() {
                return Ok(());
            }
            match state.deflate(input, &mut self.compressed[self.used..], flush) {
                Ok((status, consumed, produced)) => {
                    input = &input[consumed..];
                    self.used += produced;
                    if status == Status::StreamEnd || (!finishing && input.is_empty()) {
                        return Ok(());
                    }
                }
                Err(e) => return Err(failed(e)),
            }
        }
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
    fn has_options(&self) -> bool {
        true
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
        if self.wrap == Wrap::Gzip {
            self.crc = crate::crc32::crc32(self.crc, input);
            self.size = self.size.wrapping_add(input.len() as u32);
        }
        self.drive(input, false, sink)
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.drive(&[], true, sink)?;
        // Write the last compressed data.
        sink.write(&self.compressed[..self.used])?;
        if self.wrap != Wrap::Gzip {
            return Ok(());
        }
        // Build and write out 8-byte trailer.
        sink.write(&self.crc.to_le_bytes())?;
        sink.write(&self.size.to_le_bytes())
    }
}
