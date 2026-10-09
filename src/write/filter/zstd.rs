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
use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::JoinHandle;

// Keep history across blocks: tar headers and small files often repeat beyond
// the block boundary. A fixed table avoids allocating and hashing a map for
// every block, while the advertised window bounds both memory and offsets.
const WINDOW: usize = 1024 * 1024;
const HASH_BITS: usize = 16;
struct Matches {
    size: usize,
    data: Vec<u8>,
    start: usize,
    base: u64,
    positions: Vec<u64>,
    space: Vec<u8>,
}
impl Matches {
    fn new(size: usize) -> Self {
        Self {
            size,
            data: Vec::with_capacity(WINDOW + size),
            start: 0,
            base: 0,
            positions: vec![0; 1 << HASH_BITS],
            space: Vec::new(),
        }
    }
    fn key(data: &[u8]) -> usize {
        let word = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        (word.wrapping_mul(0x9e3779b1) >> (32 - HASH_BITS)) as usize
    }
    fn remember(&mut self, at: usize) {
        if at + 4 <= self.data.len() {
            self.positions[Self::key(&self.data[at..])] = self.base + at as u64 + 1;
        }
    }
}
impl Matcher for Matches {
    fn get_next_space(&mut self) -> Vec<u8> {
        let mut space = std::mem::take(&mut self.space);
        space.resize(self.size, 0);
        space
    }
    fn get_last_space(&mut self) -> &[u8] {
        &self.data[self.start..]
    }
    fn commit_space(&mut self, mut data: Vec<u8>) {
        let remove = self.data.len().saturating_sub(WINDOW);
        if self
            .base
            .checked_add((remove + WINDOW + self.size + 1) as u64)
            .is_none()
        {
            // Positions need not wrap even for an indefinitely long stream.
            self.data.clear();
            self.positions.fill(0);
            self.base = 0;
        } else {
            self.data.copy_within(remove.., 0);
            self.data.truncate(self.data.len() - remove);
            self.base += remove as u64;
        }
        self.start = self.data.len();
        self.data.extend_from_slice(&data);
        data.clear();
        self.space = data;
        // Include keys straddling the previous block boundary.
        for at in self.start.saturating_sub(3)..self.start {
            self.remember(at);
        }
    }
    fn skip_matching(&mut self) {
        // ruzstd skips matching for RLE blocks, but subsequent blocks may
        // still reference their bytes.
        if self.start + 4 <= self.data.len() {
            self.remember(self.start);
            self.remember(self.data.len() - 4);
        }
    }
    fn reset(&mut self, _: CompressionLevel) {
        self.data.clear();
        self.positions.fill(0);
        self.start = 0;
        self.base = 0;
    }
    fn window_size(&self) -> u64 {
        WINDOW as u64
    }
    fn start_matching(&mut self, mut emit: impl for<'a> FnMut(Sequence<'a>)) {
        let mut literal = self.start;
        // ruzstd's FSE builder cannot encode a literal-length alphabet
        // containing only symbol zero. One leading literal keeps that table
        // valid even when the entire block repeats earlier history.
        self.remember(literal);
        let mut at = literal + usize::from(literal < self.data.len());
        while at + 4 <= self.data.len() {
            let key = Self::key(&self.data[at..]);
            let position = self.positions[key];
            self.positions[key] = self.base + at as u64 + 1;
            let prior = position
                .checked_sub(self.base + 1)
                .and_then(|p| usize::try_from(p).ok())
                .filter(|&p| p < at && at - p <= WINDOW);
            if let Some(prev) = prior.filter(|&p| self.data[p..p + 4] == self.data[at..at + 4]) {
                // ruzstd 0.9's code-52 extra-bit baseline is incorrect;
                // splitting very long matches avoids that malformed encoding.
                let limit = (self.data.len() - at).min(65538);
                let mut n = 4;
                while n + 8 <= limit
                    && self.data[prev + n..prev + n + 8] == self.data[at + n..at + n + 8]
                {
                    n += 8;
                }
                while n < limit && self.data[prev + n] == self.data[at + n] {
                    n += 1;
                }
                emit(Sequence::Triple {
                    literals: &self.data[literal..at],
                    offset: at - prev,
                    match_len: n,
                });
                at += n;
                literal = at;
                // Seed the tail without hashing every byte of long matches.
                self.remember(at.saturating_sub(2));
                self.remember(at.saturating_sub(1));
            } else {
                at += 1;
            }
        }
        emit(Sequence::Literals {
            literals: &self.data[literal..],
        });
    }
}
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
impl Worker {
    fn new(level: i64) -> Result<Self, Error> {
        let (tx, input) = mpsc::sync_channel(1);
        let (output, rx) = mpsc::sync_channel(1);
        // Coalesced wakeups cover either resource that can unblock a send.
        let (notify, ready) = mpsc::sync_channel(1);
        let size = if level <= 1 {
            16 * 1024
        } else if level <= 3 {
            96 * 1024
        } else {
            128 * 1024
        };
        let thread = std::thread::Builder::new()
            .name("archive-zstd-encoder".into())
            .spawn(move || {
                std::panic::catch_unwind(|| {
                    let mut encoder = FrameCompressor::new_with_matcher(
                        Matches::new(size),
                        CompressionLevel::Fastest,
                    );
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
            pending: Vec::with_capacity(size.min(65536)),
            chunk_size: size.min(65536),
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
                if let Some(w) = &mut self.worker {
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

    fn compressed(data: &[u8], block_size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut encoder =
            FrameCompressor::new_with_matcher(Matches::new(block_size), CompressionLevel::Fastest);
        encoder.set_source(data);
        encoder.set_drain(&mut out);
        encoder.compress();
        out
    }
    fn roundtrip(data: &[u8], block_size: usize) -> usize {
        let encoded = compressed(data, block_size);
        let mut decoded = Vec::new();
        ruzstd::decoding::StreamingDecoder::new(encoded.as_slice())
            .unwrap()
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, data);
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
    #[test]
    fn matcher_reuses_previous_blocks_and_expires_old_history() {
        let block = random_bytes(32768);
        let mut data = block.clone();
        data.extend_from_slice(&block);
        data.extend_from_slice(&block);
        assert!(roundtrip(&data, 32768) < block.len() + 2048);
        // Force history compaction and then repeat across that boundary.
        let mut data = random_bytes(WINDOW + 32768);
        let tail = data[data.len() - 32768..].to_vec();
        data.extend_from_slice(&tail);
        assert!(roundtrip(&data, 32768) < data.len() - 30000);
    }
    #[test]
    fn matcher_handles_overlap_short_tails_and_skipped_rle_blocks() {
        for length in [0, 1, 2, 3, 4, 5, 7, 15, 31, 1023, 4097, 65539] {
            let data: Vec<_> = b"abcd".iter().copied().cycle().take(length).collect();
            roundtrip(&data, 16384);
        }
        let data: Vec<_> = b"abcd".iter().copied().cycle().take(400003).collect();
        roundtrip(&data, 131072);
        let mut data = vec![b'x'; 32768];
        data.extend_from_slice(&[b'x'; 16384]);
        data.extend_from_slice(&random_bytes(16384));
        assert!(roundtrip(&data, 32768) < 17000);
    }
    #[test]
    #[ignore = "Set LIBARCHIVE_ZSTD_DECODER to an independent bsdcat executable"]
    fn matcher_frames_decode_with_independent_backend() {
        use std::io::{Seek, SeekFrom};
        use std::process::{Command, Stdio};
        let decoder = std::env::var_os("LIBARCHIVE_ZSTD_DECODER")
            .expect("LIBARCHIVE_ZSTD_DECODER must name an independent bsdcat executable");
        let mut data = random_bytes(WINDOW + 65536);
        let repeated = data[data.len() - 65536..].to_vec();
        data.extend_from_slice(&repeated);
        data.extend_from_slice(&[0; 65536]);
        data.extend_from_slice(b"abcdabcdabcdabcdx");
        let periodic: Vec<_> = b"abcd".iter().copied().cycle().take(400003).collect();
        for (data, block_size) in [(data.as_slice(), 65536), (periodic.as_slice(), 131072)] {
            let encoded = compressed(data, block_size);
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
            assert_eq!(result.stdout, data);
        }
    }

    #[test]
    fn matcher_frame_reset_discards_previous_positions() {
        let block = random_bytes(8192);
        let mut encoder =
            FrameCompressor::new_with_matcher(Matches::new(8192), CompressionLevel::Fastest);
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

    struct FailedSink;
    impl Sink for FailedSink {
        fn write(&mut self, _: &[u8]) -> Result<(), Error> {
            Err(Error::fatal(libc::EIO, "test sink failed"))
        }
    }
    #[test]
    fn sink_failure_is_preserved_while_worker_is_reaped() {
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
