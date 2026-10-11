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
use ruzstd::encoding::{CompressionLevel, FrameCompressor, StreamCompressor};
use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::JoinHandle;

struct Input {
    rx: Receiver<Vec<u8>>,
    data: Vec<u8>,
    at: usize,
    ready: SyncSender<()>,
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
                    self.at = 0;
                    let _ = self.ready.try_send(());
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
struct Output {
    tx: SyncSender<Vec<u8>>,
    ready: SyncSender<()>,
}
impl Write for Output {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.tx
            .send(data.to_vec())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        let _ = self.ready.try_send(());
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
    ready: Receiver<()>,
    pending: Vec<u8>,
    chunk_size: usize,
}
/// Input batches handed to the worker thread.
const CHUNK_SIZE: usize = 65536;

impl Worker {
    fn new(level: i64, window_log: Option<u32>) -> Result<Self, Error> {
        let (tx, input) = mpsc::sync_channel(1);
        let (output, rx) = mpsc::sync_channel(1);
        // Coalesced wakeups cover either resource that can unblock a send.
        let (notify, ready) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("archive-zstd-encoder".into())
            .spawn(move || {
                std::panic::catch_unwind(|| {
                    let mut encoder = FrameCompressor::new(compression_level(level));
                    encoder.set_window_log(window_log);
                    encoder.set_source(Input {
                        rx: input,
                        data: Vec::new(),
                        at: 0,
                        ready: notify.clone(),
                    });
                    encoder.set_drain(Output {
                        tx: output,
                        ready: notify,
                    });
                    encoder.compress();
                })
                .is_ok()
            })
            .map_err(io_error)?;
        Ok(Self {
            tx: Some(tx),
            rx,
            thread: Some(thread),
            ready,
            pending: Vec::with_capacity(CHUNK_SIZE),
            chunk_size: CHUNK_SIZE,
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
    fn send(&self, mut pending: Vec<u8>, sink: &mut dyn Sink) -> Result<(), Error> {
        loop {
            self.drain(sink)?;
            match self
                .tx
                .as_ref()
                .ok_or_else(|| Error::fatal(-1, "Zstd encoder closed"))?
                .try_send(pending)
            {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(v)) => {
                    pending = v;
                    self.ready
                        .recv()
                        .map_err(|_| Error::fatal(-1, "Zstd compression failed"))?;
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(Error::fatal(-1, "Zstd compression failed"));
                }
            }
        }
    }
    fn write(&mut self, mut data: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        // Tar headers and padding are often only 512 bytes. Amortize channel
        // traffic without letting input or compressed output grow unbounded.
        while !data.is_empty() {
            let n = data.len().min(self.chunk_size - self.pending.len());
            self.pending.extend_from_slice(&data[..n]);
            data = &data[n..];
            if self.pending.len() == self.chunk_size {
                let pending =
                    std::mem::replace(&mut self.pending, Vec::with_capacity(self.chunk_size));
                self.send(pending, sink)?;
            }
        }
        self.drain(sink)
    }
    fn finish(mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            self.send(pending, sink)?;
        }
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
impl Drop for Worker {
    fn drop(&mut self) {
        // Disconnect both directions before joining: the worker can be
        // blocked receiving input or sending compressed output.
        self.tx = None;
        let replacement = mpsc::channel().1;
        drop(std::mem::replace(&mut self.rx, replacement));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// Codec panics keep the worker's error mapping; sink panics still propagate
// to the archive callback guard just as they do on the threaded path.
fn encode(
    sink: &mut dyn Sink,
    operation: impl FnOnce(&mut dyn FnMut(&[u8]) -> Result<(), Error>) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut in_sink = false;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        operation(&mut |data| {
            in_sink = true;
            let result = sink.write(data);
            in_sink = false;
            result
        })
    }));
    match result {
        Ok(result) => result,
        Err(panic) if in_sink => std::panic::resume_unwind(panic),
        Err(_) => Err(Error::fatal(-1, "Zstd compression failed")),
    }
}

enum Encoder {
    Threaded(Worker),
    Direct(Box<StreamCompressor>),
    Failed,
}
fn compression_level(level: i64) -> CompressionLevel {
    // Options are range checked: -131072..=22.
    CompressionLevel::Level(level as i32)
}

impl Encoder {
    fn direct(level: i64, window_log: Option<u32>) -> Result<Self, Error> {
        std::panic::catch_unwind(|| {
            let mut encoder = StreamCompressor::new(compression_level(level));
            encoder.set_window_log(window_log);
            encoder.begin();
            Self::Direct(Box::new(encoder))
        })
        .map_err(|_| Error::fatal(-1, "Zstd compression failed"))
    }
    fn write(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        match self {
            Self::Threaded(worker) => worker.write(data, sink),
            Self::Direct(encoder) => {
                let result = encode(sink, |emit| encoder.write(data, emit));
                if result.is_err() {
                    *self = Self::Failed;
                }
                result
            }
            Self::Failed => Err(Error::fatal(-1, "Zstd compression failed")),
        }
    }
    fn finish(self, sink: &mut dyn Sink) -> Result<(), Error> {
        match self {
            Self::Threaded(worker) => worker.finish(sink),
            Self::Direct(mut encoder) => encode(sink, |emit| encoder.finish(emit)),
            Self::Failed => Err(Error::fatal(-1, "Zstd compression failed")),
        }
    }
}

pub struct Zstd {
    level: i64,
    /// `long`: libzstd's `ZSTD_c_windowLog`.
    window_log: Option<u32>,
    encoder: Option<Encoder>,
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
            window_log: None,
            encoder: None,
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
        if self.encoder.is_none() {
            // Framing thresholds retain their existing asynchronous output
            // accounting. Ordinary single-frame writes need no worker bridge.
            let direct = !self.frame_per_file
                && self.min_in == 0
                && self.max_in == u64::MAX
                && self.min_out == 0
                && self.max_out == u64::MAX;
            self.encoder = Some(if direct {
                Encoder::direct(self.level, self.window_log)?
            } else {
                Encoder::Threaded(Worker::new(self.level, self.window_log)?)
            });
            self.frame_in = 0;
            self.frame_out = 0;
        }
        Ok(())
    }
    fn finish(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if let Some(worker) = self.encoder.take() {
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
                self.window_log = Some(n as u32);
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
                if let Some(w) = &mut self.encoder {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};

    fn compressed(data: &[u8], level: i32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut encoder = FrameCompressor::new(CompressionLevel::Level(level));
        encoder.set_source(data);
        encoder.set_drain(&mut out);
        encoder.compress();
        out
    }
    fn decoded(encoded: &[u8]) -> Vec<u8> {
        // Level 22's 128 MiB window, like the archive reader.
        let mut decoder = ruzstd::decoding::FrameDecoder::new();
        decoder.set_max_window_size(1 << 27);
        let mut decoded = Vec::new();
        ruzstd::decoding::StreamingDecoder::new_with_decoder(encoded, decoder)
            .unwrap()
            .read_to_end(&mut decoded)
            .unwrap();
        decoded
    }
    fn roundtrip(data: &[u8], level: i32) -> usize {
        let encoded = compressed(data, level);
        assert!(
            decoded(&encoded) == data,
            "level {level}, {} bytes",
            data.len()
        );
        encoded.len()
    }
    fn random_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x12345678u32;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }
    /// Words from a small vocabulary with numbers, like logs or source.
    fn text(len: usize) -> Vec<u8> {
        const WORDS: [&[u8]; 12] = [
            b"archive ",
            b"entry ",
            b"header ",
            b"size ",
            b"the ",
            b"of ",
            b"and ",
            b"compress ",
            b"block ",
            b"window ",
            b"match ",
            b"literal ",
        ];
        let mut state = 0x9E3779B9u32;
        let mut out = Vec::with_capacity(len + 16);
        while out.len() < len {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            out.extend_from_slice(WORDS[state as usize % WORDS.len()]);
            if state.is_multiple_of(7) {
                out.extend_from_slice(format!("{}\n", state % 1000).as_bytes());
            }
        }
        out.truncate(len);
        out
    }
    /// Frame blocks as (type, decoded size): 0 raw, 1 RLE, 2 compressed.
    fn blocks(frame: &[u8]) -> Vec<(u8, usize)> {
        assert_eq!(&frame[..5], &[0x28, 0xB5, 0x2F, 0xFD, 4]);
        let mut at = 6;
        let mut blocks = Vec::new();
        loop {
            let header = u32::from_le_bytes([frame[at], frame[at + 1], frame[at + 2], 0]);
            let (kind, size) = ((header >> 1 & 3) as u8, (header >> 3) as usize);
            blocks.push((kind, size));
            at += 3 + if kind == 1 { 1 } else { size };
            if header & 1 == 1 {
                assert_eq!(at + 4, frame.len());
                return blocks;
            }
        }
    }

    #[test]
    fn push_encoder_restarts_after_success_and_emit_failure() {
        let block = 131072;
        let data = random_bytes(block * 2 + 7);
        let mut encoder = StreamCompressor::new(CompressionLevel::Level(3));
        for len in [0, block, data.len(), 1] {
            encoder.begin();
            let mut actual = Vec::new();
            encoder.write(&[], |_| Ok::<_, ()>(())).unwrap();
            for part in data[..len].chunks(511) {
                encoder
                    .write(part, |b| {
                        actual.extend_from_slice(b);
                        Ok::<_, ()>(())
                    })
                    .unwrap();
            }
            encoder
                .finish(|b| {
                    actual.extend_from_slice(b);
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert_eq!(actual, compressed(&data[..len], 3));
        }
        // Fail both the first full block and the separate final checksum write.
        encoder.begin();
        assert_eq!(encoder.write(&data, |_| Err(17)), Err(17));
        encoder.begin();
        encoder.write(&data[..1], |_| Ok::<_, i32>(())).unwrap();
        let mut calls = 0;
        assert_eq!(
            encoder.finish(|_| {
                calls += 1;
                if calls == 2 { Err(23) } else { Ok(()) }
            }),
            Err(23)
        );
        encoder.begin();
        let mut actual = Vec::new();
        encoder
            .write(&data, |b| {
                actual.extend_from_slice(b);
                Ok::<_, ()>(())
            })
            .unwrap();
        encoder
            .finish(|b| {
                actual.extend_from_slice(b);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(actual, compressed(&data, 3));
    }

    #[test]
    fn every_level_round_trips() {
        let mut data = text(300_000);
        data.extend_from_slice(&random_bytes(150_000));
        data.extend_from_slice(&[0; 140_000]);
        data.extend_from_slice(&text(200_000));
        let mut sizes = Vec::new();
        for level in [-131072, -1000, -5, -1, 0].into_iter().chain(1..=22) {
            sizes.push((level, roundtrip(&data, level)));
        }
        // Stronger strategies compress this better than the fastest ones.
        let size = |l| sizes.iter().find(|&&(level, _)| level == l).unwrap().1;
        assert!(size(3) < size(1) && size(9) < size(3) && size(1) < size(-5));
        assert_eq!(size(0), size(3));
    }

    #[test]
    fn edge_inputs_round_trip() {
        let patterns: [fn(usize) -> Vec<u8>; 4] = [
            |n| vec![0; n],
            random_bytes,
            |n| b"abcd".iter().copied().cycle().take(n).collect(),
            text,
        ];
        let sizes = [
            0, 1, 2, 6, 7, 8, 15, 16, 17, 255, 256, 1023, 1024, 16383, 16384, 131071, 131072,
            131073, 262143, 262144, 262145, 393221,
        ];
        for level in [-3, 1, 3, 5, 6, 8] {
            for pattern in patterns {
                for size in sizes {
                    roundtrip(&pattern(size), level);
                }
            }
        }
    }

    #[test]
    fn long_matches_use_the_largest_length_codes() {
        // Matches far longer than 65538 bytes need match length code 52.
        let pattern = random_bytes(1024);
        let data: Vec<u8> = pattern.iter().copied().cycle().take(1 << 20).collect();
        for level in [-1, 1, 3, 5, 7, 12] {
            assert!(roundtrip(&data, level) < 2048, "level {level}");
        }
        // And literal runs beyond 65535 bytes before a match.
        let mut data = random_bytes(100_000);
        data.extend_from_within(..20_000);
        roundtrip(&data, 3);
    }

    #[test]
    fn matches_reach_back_through_the_window_and_no_further() {
        let block = random_bytes(32768);
        let mut data = block.clone();
        data.extend_from_slice(&block);
        data.extend_from_slice(&block);
        assert!(roundtrip(&data, 3) < block.len() + 2048);
        // Level 1's 512 KiB window, counted from the end of each block as in
        // libzstd. Zeros between the repeats keep the search from skipping
        // ahead, and history beyond twice the window is discarded first.
        for (gap, compressible) in [(300 * 1024, true), (500 * 1024, false)] {
            let repeated = random_bytes(64 * 1024);
            let mut data = text(700 * 1024);
            data.extend_from_slice(&repeated);
            data.resize(data.len() + gap, 0);
            data.extend_from_slice(&repeated);
            let size = roundtrip(&data, 1);
            let (without, with) = (
                compressed(&data[..data.len() - repeated.len()], 1).len(),
                size,
            );
            assert_eq!(
                with < without + 4096,
                compressible,
                "gap {gap}: {without} -> {with}"
            );
        }
    }

    #[test]
    fn search_resumes_dense_after_incompressible_regions() {
        let mut data = random_bytes(65536);
        for _ in 0..2048 {
            data.extend_from_slice(b"a repeated sentence after random bytes.\n");
        }
        data.extend_from_slice(&random_bytes(32768));
        for _ in 0..2048 {
            data.extend_from_slice(b"a second repeated sentence after random bytes.\n");
        }
        for level in [1, 3, 5, 9] {
            assert!(roundtrip(&data, level) < 101_000, "level {level}");
        }
    }

    #[test]
    fn raw_blocks_keep_the_previous_entropy_tables() {
        // A raw middle block must not replace the tables the decoder holds:
        // the last block may reuse the first block's Huffman table.
        let size = 131072;
        let mut data = random_bytes(size * 3);
        let (first, rest) = data.split_at_mut(size);
        for byte in first.iter_mut().chain(&mut rest[size..]) {
            *byte %= 127;
        }
        let encoded = compressed(&data, 3);
        assert!(decoded(&encoded) == data);
        // The last block is empty.
        let kinds: Vec<u8> = blocks(&encoded).iter().map(|b| b.0).collect();
        assert!(
            kinds.len() > 3 && kinds[0] == 2 && kinds.contains(&0) && kinds[kinds.len() - 2] == 2
        );
        assert!(encoded.len() < data.len() - 2 * 15_000);
    }

    #[test]
    fn repeated_blocks_after_the_first_are_rle() {
        let mut data = random_bytes(1000);
        data.extend_from_slice(&[7; 131072 * 3]);
        for level in [-1, 1, 3, 6] {
            let encoded = compressed(&data, level);
            assert_eq!(decoded(&encoded), data);
            assert_eq!(blocks(&encoded)[1..], [(1, 131072), (1, 131072), (1, 1000)]);
        }
    }

    #[test]
    fn frame_reset_discards_previous_positions() {
        let block = text(300_000);
        let mut encoder = FrameCompressor::new(CompressionLevel::Level(5));
        let mut first = Vec::new();
        encoder.set_source(block.as_slice());
        encoder.set_drain(&mut first);
        encoder.compress();
        let mut second = Vec::new();
        encoder.set_source(block.as_slice());
        encoder.set_drain(&mut second);
        encoder.compress();
        assert_eq!(first, second);
    }

    #[test]
    fn long_option_sets_the_window() {
        let mut data = text(70_000);
        data.extend_from_slice(&random_bytes(5000));
        data.extend_from_within(..3000);
        for (log, block) in [(10, 1024), (12, 4096), (17, 131072), (23, 131072)] {
            let mut filter = Zstd::default();
            filter
                .options(b"long", Some(log.to_string().as_bytes()))
                .unwrap();
            let mut out = Bytes::default();
            filter.write(&data, &mut out).unwrap();
            filter.close(&mut out).unwrap();
            assert_eq!(out.0[5], (log - 10) << 3);
            assert!(decoded(&out.0) == data);
            let blocks = blocks(&out.0);
            assert_eq!(blocks.len() > 1, block < data.len());
            assert!(
                blocks
                    .iter()
                    .all(|&(kind, size)| kind == 1 || size <= block)
            );
        }
    }

    #[test]
    #[ignore = "Set LIBARCHIVE_ZSTD_DECODER to an independent bsdcat executable"]
    fn frames_decode_with_independent_backend() {
        use std::io::{Seek, SeekFrom};
        use std::process::{Command, Stdio};
        let decoder = std::env::var_os("LIBARCHIVE_ZSTD_DECODER")
            .expect("LIBARCHIVE_ZSTD_DECODER must name an independent bsdcat executable");
        let mut data = random_bytes(3 << 20);
        let repeated = data[data.len() - 65536..].to_vec();
        data.extend_from_slice(&repeated);
        data.extend_from_slice(&[0; 300_000]);
        data.extend_from_slice(&text(500_000));
        data.extend_from_slice(b"abcdabcdabcdabcdx");
        let periodic: Vec<_> = b"abcd".iter().copied().cycle().take(400003).collect();
        for level in [-5, 1, 3, 5, 7, 12, 19] {
            for data in [data.as_slice(), periodic.as_slice()] {
                let encoded = compressed(data, level);
                let mut input = crate::write::temp_file().unwrap();
                input.write_all(&encoded).unwrap();
                input.seek(SeekFrom::Start(0)).unwrap();
                let result = Command::new(&decoder)
                    .stdin(input)
                    .stdout(Stdio::piped())
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                assert!(result.stdout == data, "level {level}");
            }
        }
    }

    #[test]
    #[ignore = "Streams 4.5 GiB to exercise index overflow correction"]
    fn indices_are_corrected_beyond_3500_mib() {
        // Three 512 KiB segments, repeated within level 3's 2 MiB window.
        let segments: Vec<Vec<u8>> = (0..3)
            .map(|k| {
                let mut segment = random_bytes(512 * 1024 + k);
                segment.truncate(512 * 1024);
                segment[..8].copy_from_slice(&(k as u64).to_le_bytes());
                segment
            })
            .collect();
        let count = 9 * 1024;
        let mut encoder = StreamCompressor::new(CompressionLevel::Level(3));
        let mut encoded = Vec::new();
        let mut emit = |b: &[u8]| {
            encoded.extend_from_slice(b);
            Ok::<_, ()>(())
        };
        encoder.begin();
        for n in 0..count {
            encoder.write(&segments[n % 3], &mut emit).unwrap();
        }
        encoder.finish(&mut emit).unwrap();
        let mut decoder = ruzstd::decoding::StreamingDecoder::new(encoded.as_slice()).unwrap();
        let mut segment = vec![0; 512 * 1024];
        for n in 0..count {
            decoder.read_exact(&mut segment).unwrap();
            assert!(segment == segments[n % 3], "segment {n}");
        }
        assert_eq!(decoder.read(&mut segment).unwrap(), 0);
    }

    #[test]
    fn dropping_worker_disconnects_blocked_output_and_joins_thread() {
        let (tx, _input) = mpsc::sync_channel(1);
        let (output, rx) = mpsc::sync_channel(1);
        let ready = Arc::new(Barrier::new(2));
        let stopped = Arc::new(AtomicBool::new(false));
        let barrier = ready.clone();
        let completed = stopped.clone();
        let thread = std::thread::spawn(move || {
            output.send(vec![0]).unwrap();
            barrier.wait();
            let _ = output.send(vec![1]);
            completed.store(true, Ordering::Release);
            true
        });
        let worker = Worker {
            tx: Some(tx),
            rx,
            thread: Some(thread),
            ready: mpsc::channel().1,
            pending: Vec::new(),
            chunk_size: 65536,
        };
        ready.wait();
        drop(worker);
        assert!(stopped.load(Ordering::Acquire));
    }

    #[derive(Default)]
    struct Bytes(Vec<u8>);
    impl Sink for Bytes {
        fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.0.extend_from_slice(data);
            Ok(())
        }
    }
    #[test]
    fn tiny_writes_and_partial_batches_produce_the_same_valid_stream() {
        for size in [0, 1, 65535, 65536, 65537, 262149] {
            let data: Vec<_> = (0..size)
                .map(|n: usize| (n.wrapping_mul(37) >> 5) as u8)
                .collect();
            let mut whole = Zstd::default();
            let mut a = Bytes::default();
            whole.write(&data, &mut a).unwrap();
            whole.close(&mut a).unwrap();
            let mut fragmented = Zstd::default();
            let mut b = Bytes::default();
            for chunk in data.chunks(73) {
                fragmented.write(chunk, &mut b).unwrap();
            }
            fragmented.close(&mut b).unwrap();
            assert_eq!(a.0, b.0);
            let mut decoded = Vec::new();
            ruzstd::decoding::StreamingDecoder::new(b.0.as_slice())
                .unwrap()
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, data);
        }
    }

    #[test]
    fn batched_input_preserves_file_and_input_limited_frames() {
        for level in [1, 3, 9] {
            for frame_per_file in [false, true] {
                let mut filter = Zstd {
                    level,
                    frame_per_file,
                    ..Zstd::default()
                };
                if !frame_per_file {
                    filter.max_in = 1024;
                }
                let mut out = Bytes::default();
                let mut expected = Vec::new();
                for size in [511, 16385, 65537] {
                    let data: Vec<_> = (0..size)
                        .map(|n: usize| (n.wrapping_mul(37) >> 5) as u8)
                        .collect();
                    for chunk in data.chunks(73) {
                        filter.write(chunk, &mut out).unwrap();
                    }
                    filter.finish_entry(&mut out).unwrap();
                    expected.extend_from_slice(&data);
                }
                filter.close(&mut out).unwrap();
                let mut input = out.0.as_slice();
                let mut decoded = Vec::new();
                let mut frames = 0;
                while !input.is_empty() {
                    let mut decoder = ruzstd::decoding::StreamingDecoder::new(input).unwrap();
                    decoder.read_to_end(&mut decoded).unwrap();
                    input = decoder.into_inner();
                    frames += 1;
                }
                assert_eq!(decoded, expected);
                assert!(frames >= 3);
            }
        }
    }

    #[test]
    fn direct_and_threaded_encoders_match_at_every_level() {
        let data = random_bytes(262149);
        for level in [1, 3, 9] {
            let mut direct = Encoder::direct(level, None).unwrap();
            let mut threaded = Encoder::Threaded(Worker::new(level, None).unwrap());
            let mut a = Bytes::default();
            let mut b = Bytes::default();
            for part in data.chunks(511) {
                direct.write(part, &mut a).unwrap();
                threaded.write(part, &mut b).unwrap();
            }
            direct.finish(&mut a).unwrap();
            threaded.finish(&mut b).unwrap();
            assert_eq!(a.0, b.0);
        }
    }

    #[test]
    fn sink_panic_keeps_its_original_payload() {
        struct PanicSink;
        impl Sink for PanicSink {
            fn write(&mut self, _: &[u8]) -> Result<(), Error> {
                std::panic::panic_any(12345u32);
            }
        }
        let mut encoder = Encoder::direct(3, None).unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            encoder.write(&vec![0; 131072], &mut PanicSink).unwrap();
        }))
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<u32>(), Some(&12345));
        drop(encoder);
    }

    #[test]
    fn uncompressed_pull_and_push_agree() {
        for size in [0, 1, 16384, 131073] {
            let data = random_bytes(size);
            let mut pull = Vec::new();
            let mut encoder = FrameCompressor::new(CompressionLevel::Uncompressed);
            encoder.set_source(data.as_slice());
            encoder.set_drain(&mut pull);
            encoder.compress();
            let mut encoder = StreamCompressor::new(CompressionLevel::Uncompressed);
            let mut push = Vec::new();
            encoder.begin();
            encoder
                .write(&data, |b| {
                    push.extend_from_slice(b);
                    Ok::<_, ()>(())
                })
                .unwrap();
            encoder
                .finish(|b| {
                    push.extend_from_slice(b);
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert_eq!(pull, push);
            let mut decoded = Vec::new();
            ruzstd::decoding::StreamingDecoder::new(push.as_slice())
                .unwrap()
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, data);
        }
    }

    struct FailedSink;
    impl Sink for FailedSink {
        fn write(&mut self, _: &[u8]) -> Result<(), Error> {
            Err(Error::fatal(libc::EIO, "test sink failed"))
        }
    }
    #[test]
    fn sink_failure_is_preserved_when_encoder_is_dropped() {
        let mut filter = Zstd::default();
        let data: Vec<_> = (0..262144usize)
            .map(|n| (n.wrapping_mul(37) >> 5) as u8)
            .collect();
        let error = filter
            .write(&data, &mut FailedSink)
            .and_then(|()| filter.close(&mut FailedSink))
            .unwrap_err();
        assert_eq!(error.errno, libc::EIO);
        assert_eq!(error.msg, b"test sink failed");
        drop(filter);
    }
}
