/*-
 * Copyright (c) 2017 Sean Purcell
 * Copyright (c) 2023-2024 Klara, Inc.
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

// Ported from libarchive/archive_write_add_filter_zstd.c.

use super::*;
use ruzstd::encoding::{CompressionLevel, FrameCompressor, Matcher, Sequence};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::JoinHandle;

// The safe backend exposes its matcher protocol but only one compression
// strategy. Larger levels spend more memory matching larger blocks.
struct Matches {
    size: usize,
    data: Vec<u8>,
}
impl Matcher for Matches {
    fn get_next_space(&mut self) -> Vec<u8> {
        vec![0; self.size]
    }
    fn get_last_space(&mut self) -> &[u8] {
        &self.data
    }
    fn commit_space(&mut self, data: Vec<u8>) {
        self.data = data;
    }
    fn skip_matching(&mut self) {}
    fn reset(&mut self, _: CompressionLevel) {
        self.data.clear();
    }
    fn window_size(&self) -> u64 {
        self.size as u64
    }
    fn start_matching(&mut self, mut emit: impl for<'a> FnMut(Sequence<'a>)) {
        let data = &self.data;
        let mut positions = HashMap::new();
        let mut literal = 0;
        let mut at = 0;
        while at + 5 <= data.len() {
            let key = u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
            let prior = positions.insert(key, at);
            if let Some(prev) = prior.filter(|&prev| data[prev..prev + 5] == data[at..at + 5]) {
                let mut n = 5;
                while at + n < data.len() && data[prev + n] == data[at + n] {
                    n += 1;
                }
                emit(Sequence::Triple {
                    literals: &data[literal..at],
                    offset: at - prev,
                    match_len: n,
                });
                at += n;
                literal = at;
            } else {
                at += 1;
            }
        }
        emit(Sequence::Literals {
            literals: &data[literal..],
        });
    }
}
struct Input {
    rx: Receiver<Vec<u8>>,
    data: Vec<u8>,
    at: usize,
}
impl Read for Input {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.at == self.data.len() {
            match self.rx.recv() {
                Ok(v) => {
                    self.data = v;
                    self.at = 0
                }
                Err(_) => return Ok(0),
            }
        }
        let n = out.len().min(self.data.len() - self.at);
        out[..n].copy_from_slice(&self.data[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}
struct Output(SyncSender<Vec<u8>>);
impl Write for Output {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0
            .send(data.to_vec())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct Worker {
    tx: Option<SyncSender<Vec<u8>>>,
    rx: Receiver<Vec<u8>>,
    thread: Option<JoinHandle<bool>>,
}
impl Worker {
    fn new(level: i64) -> Result<Self, Error> {
        let (tx, input) = mpsc::sync_channel(1);
        let (output, rx) = mpsc::sync_channel(1);
        let size = if level <= 1 {
            16 * 1024
        } else if level <= 3 {
            64 * 1024
        } else {
            128 * 1024
        };
        let thread = std::thread::Builder::new()
            .name("archive-zstd-encoder".into())
            .spawn(move || {
                std::panic::catch_unwind(|| {
                    let mut encoder = FrameCompressor::new_with_matcher(
                        Matches {
                            size,
                            data: Vec::new(),
                        },
                        CompressionLevel::Fastest,
                    );
                    encoder.set_source(Input {
                        rx: input,
                        data: Vec::new(),
                        at: 0,
                    });
                    encoder.set_drain(Output(output));
                    encoder.compress();
                })
                .is_ok()
            })
            .map_err(io_error)?;
        Ok(Self {
            tx: Some(tx),
            rx,
            thread: Some(thread),
        })
    }
    fn drain(&self, sink: &mut dyn Sink) -> Result<(), Error> {
        loop {
            match self.rx.try_recv() {
                Ok(data) => sink.write(&data)?,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return Ok(()),
            }
        }
    }
    fn write(&self, data: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        for part in data.chunks(65536) {
            let mut pending = part.to_vec();
            loop {
                self.drain(sink)?;
                match self
                    .tx
                    .as_ref()
                    .ok_or_else(|| Error::fatal(-1, "Zstd encoder closed"))?
                    .try_send(pending)
                {
                    Ok(()) => break,
                    Err(TrySendError::Full(v)) => {
                        pending = v;
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        return Err(Error::fatal(-1, "Zstd compression failed"));
                    }
                }
            }
        }
        self.drain(sink)
    }
    fn finish(mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.tx = None;
        while let Ok(data) = self.rx.recv() {
            sink.write(&data)?;
        }
        if !self
            .thread
            .take()
            .is_some_and(|t| t.join().unwrap_or(false))
        {
            return Err(Error::fatal(-1, "Zstd compression failed"));
        }
        Ok(())
    }
}
// Dropping both channels lets a worker blocked on either one finish; do not
// wait on it while its output receiver is still live.

pub struct Zstd {
    level: i64,
    worker: Option<Worker>,
    frame_per_file: bool,
    min_in: u64,
    max_in: u64,
    min_out: u64,
    max_out: u64,
    frame_in: u64,
    frame_out: u64,
}
impl Default for Zstd {
    fn default() -> Self {
        Self {
            level: 3,
            worker: None,
            frame_per_file: false,
            min_in: 0,
            max_in: u64::MAX,
            min_out: 0,
            max_out: u64::MAX,
            frame_in: 0,
            frame_out: 0,
        }
    }
}
struct Count<'a> {
    sink: &'a mut dyn Sink,
    count: &'a mut u64,
}
impl Sink for Count<'_> {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.sink.write(data)?;
        *self.count = self.count.saturating_add(data.len() as u64);
        Ok(())
    }
}
impl Zstd {
    fn start(&mut self) -> Result<(), Error> {
        if self.worker.is_none() {
            self.worker = Some(Worker::new(self.level)?);
            self.frame_in = 0;
            self.frame_out = 0;
        }
        Ok(())
    }
    fn finish(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if let Some(worker) = self.worker.take() {
            worker.finish(&mut Count {
                sink,
                count: &mut self.frame_out,
            })?;
        }
        Ok(())
    }
}
fn size(value: Option<&[u8]>, msg: &str) -> Result<u64, Error> {
    let v = value.ok_or_else(|| invalid(msg))?;
    let end = v
        .iter()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(v.len());
    if end == 0 {
        return Err(invalid(msg));
    }
    let n = std::str::from_utf8(&v[..end])
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| invalid(msg))?;
    let shift = match &v[end..] {
        b"" | b"b" | b"B" => 0,
        b"k" | b"K" | b"kB" | b"kb" | b"KB" | b"Kb" => 10,
        b"m" | b"M" | b"mB" | b"mb" | b"MB" | b"Mb" => 20,
        b"g" | b"G" | b"gB" | b"gb" | b"GB" | b"Gb" => 30,
        _ => return Err(invalid(msg)),
    };
    n.checked_mul(1 << shift).ok_or_else(|| invalid(msg))
}
impl Filter for Zstd {
    fn name(&self) -> &CStr {
        c"zstd"
    }
    fn code(&self) -> i32 {
        filter_code::ZSTD
    }
    fn options(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<i32, Error> {
        match key {
            b"compression-level" => {
                let n = number(value, "compression-level invalid")?;
                if !(-131072..=22).contains(&n) {
                    return Err(invalid("compression-level out of range"));
                }
                self.level = n;
            }
            b"threads" => {
                let n = number(value, "threads invalid")?;
                if !(0..=i32::MAX.into()).contains(&n) {
                    return Err(invalid("threads out of rnage"));
                }
            }
            b"long" => {
                let n = number(value, "long invalid")?;
                if !(10..=31).contains(&n) {
                    return Err(invalid("long out of range"));
                }
            }
            b"frame-per-file" => self.frame_per_file = true,
            b"min-frame-in" => self.min_in = size(value, "min-frame-in invalid")?,
            b"min-frame-out" | b"min-frame-size" => {
                self.min_out = size(value, "min-frame-out invalid")?
            }
            b"max-frame-in" | b"max-frame-size" => {
                let n = size(value, "max-frame-size invalid")?;
                if n < 1024 {
                    return Err(invalid("max-frame-size invalid"));
                }
                self.max_in = n;
            }
            b"max-frame-out" => {
                let n = size(value, "max-frame-out invalid")?;
                if n < 1024 {
                    return Err(invalid("max-frame-out invalid"));
                }
                self.max_out = n;
            }
            _ => return Ok(ARCHIVE_WARN),
        }
        Ok(ARCHIVE_OK)
    }
    fn write(&mut self, mut input: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        while !input.is_empty() {
            self.start()?;
            let room = self.max_in.saturating_sub(self.frame_in);
            let n = input
                .len()
                .min(65536)
                .min(usize::try_from(room).unwrap_or(usize::MAX));
            if n > 0 {
                if let Some(w) = &self.worker {
                    w.write(
                        &input[..n],
                        &mut Count {
                            sink,
                            count: &mut self.frame_out,
                        },
                    )?;
                }
                self.frame_in += n as u64;
                input = &input[n..];
            }
            if self.frame_in >= self.max_in || self.frame_out >= self.max_out {
                self.finish(sink)?;
            }
        }
        Ok(())
    }
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if self.frame_per_file && self.frame_in >= self.min_in && self.frame_out >= self.min_out {
            self.finish(sink)?;
        }
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.start()?;
        self.finish(sink)
    }
}
