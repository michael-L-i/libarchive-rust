//! Frames and blocks, ported from libzstd 1.5.7's streaming compressor
//! (`ZSTD_compressStream2()`, `ZSTD_compress_frameChunk()` and
//! `ZSTD_compressBlock_internal()` in `zstd_compress.c`).

use alloc::vec;
use alloc::vec::Vec;
#[cfg(feature = "hash")]
use core::hash::Hasher;
#[cfg(feature = "hash")]
use twox_hash::XxHash64;

use super::literals::min_gain;
use super::match_state::{MatchState, CURRENT_MAX};
use super::params::{CParams, Strategy};
use super::sequences::{self, Entropy, Scratch, SeqStore};
use super::{double_fast, fast, lazy, pre_split, CompressionLevel};
use crate::common::MAGIC_NUM;
use crate::io::{Read, Write};

/// `ZSTD_BLOCKSIZE_MAX`.
const MAX_BLOCK_SIZE: usize = 128 * 1024;
const RAW_BLOCK: u32 = 0;
const RLE_BLOCK: u32 = 1;
const COMPRESSED_BLOCK: u32 = 2;

/// A push-based Zstd frame encoder.
///
/// Call [StreamCompressor::begin] to start a frame, feed data with [StreamCompressor::write]
/// and end the frame with [StreamCompressor::finish]. Encoded bytes are handed to `emit`;
/// concatenated, they are identical to [FrameCompressor::compress] output for the same input,
/// regardless of how the input is chunked.
///
/// `write` and `finish` panic unless a frame is open. A frame is closed by `finish` and by any
/// `emit` error; `begin` always starts a fresh frame.
pub struct StreamCompressor {
    level: CompressionLevel,
    window_log: Option<u32>,
    params: CParams,
    /// The window followed by input not yet compressed, `data[pending..]`.
    data: Vec<u8>,
    pending: usize,
    ms: MatchState,
    /// The repeat offsets as the decoder will see them.
    rep: [u32; 3],
    prev: Entropy,
    next: Entropy,
    store: SeqStore,
    scratch: Scratch,
    body: Vec<u8>,
    output: Vec<u8>,
    first_block: bool,
    consumed: u64,
    produced: u64,
    #[cfg(feature = "hash")]
    hasher: XxHash64,
    open: bool,
    /// The match state is unused since `new`.
    fresh: bool,
}

impl StreamCompressor {
    /// Create a new `StreamCompressor`. No frame is open yet.
    pub fn new(level: CompressionLevel) -> Self {
        let params = params(level, None);
        Self {
            level,
            window_log: None,
            params,
            data: Vec::new(),
            pending: 0,
            ms: MatchState::new(params),
            rep: [1, 4, 8],
            prev: Entropy::default(),
            next: Entropy::default(),
            store: SeqStore::new(MAX_BLOCK_SIZE),
            scratch: Scratch::default(),
            body: vec![0; MAX_BLOCK_SIZE + (MAX_BLOCK_SIZE >> 8) + 64],
            output: Vec::new(),
            first_block: true,
            consumed: 0,
            produced: 0,
            #[cfg(feature = "hash")]
            hasher: XxHash64::with_seed(0),
            open: false,
            fresh: true,
        }
    }

    /// Start a new frame, abandoning any frame still open.
    ///
    /// The frame header is buffered and emitted together with the first block.
    pub fn begin(&mut self) {
        self.open = false;
        self.params = params(self.level, self.window_log);
        if !self.fresh || self.ms.params != self.params {
            self.ms = MatchState::new(self.params);
        }
        self.fresh = false;
        self.data.clear();
        // The most the window buffer holds, see append().
        self.data
            .reserve(2 * (1 << self.params.window_log) + self.block_max());
        self.pending = 0;
        self.rep = [1, 4, 8];
        self.prev = Entropy::default();
        self.first_block = true;
        #[cfg(feature = "hash")]
        {
            self.hasher = XxHash64::with_seed(0);
        }
        // ZSTD_writeFrameHeader() for an unknown content size: no content
        // size or dictionary, a window descriptor and the checksum flag.
        self.output.clear();
        self.output.extend_from_slice(&MAGIC_NUM.to_le_bytes());
        self.output.push(u8::from(cfg!(feature = "hash")) << 2);
        self.output.push(((self.params.window_log - 10) << 3) as u8);
        self.consumed = 0;
        self.produced = self.output.len() as u64;
        self.open = true;
    }

    /// Compress `data` into the open frame, emitting every block that fills up.
    pub fn write<E>(
        &mut self,
        mut data: &[u8],
        mut emit: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        assert!(
            self.open,
            "StreamCompressor::write called without an open frame"
        );
        let block_max = self.block_max();
        while !data.is_empty() {
            let n = (block_max - (self.data.len() - self.pending)).min(data.len());
            self.append(&data[..n]);
            data = &data[n..];
            if self.data.len() - self.pending == block_max {
                // Stays closed if compression panics or emitting fails.
                self.open = false;
                self.compress_chunk(false);
                self.flush(&mut emit)?;
                self.open = true;
            }
        }
        Ok(())
    }

    /// Emit the last block (an empty Raw block if no data is pending) and the checksum.
    ///
    /// The frame is closed afterwards, even if `emit` fails.
    pub fn finish<E>(&mut self, mut emit: impl FnMut(&[u8]) -> Result<(), E>) -> Result<(), E> {
        assert!(
            self.open,
            "StreamCompressor::finish called without an open frame"
        );
        self.open = false;
        self.compress_chunk(true);
        self.flush(&mut emit)?;
        #[cfg(feature = "hash")]
        emit(&(self.hasher.finish() as u32).to_le_bytes())?;
        Ok(())
    }

    /// Between frames you can replace the compression level
    pub fn set_compression_level(
        &mut self,
        compression_level: CompressionLevel,
    ) -> CompressionLevel {
        core::mem::replace(&mut self.level, compression_level)
    }

    /// Get the current compression level
    pub fn compression_level(&self) -> CompressionLevel {
        self.level
    }

    /// Between frames you can override the level's window size, as libzstd's
    /// `ZSTD_c_windowLog` does: a window of `1 << log` bytes, `log` in
    /// 10..=31. `None` restores the level's window.
    pub fn set_window_log(&mut self, log: Option<u32>) {
        assert!(log.is_none_or(|log| (10..=31).contains(&log)));
        self.window_log = log;
    }

    /// `ZSTD_compressStream2()` buffers a block of `min(128 KiB, window)`.
    fn block_max(&self) -> usize {
        MAX_BLOCK_SIZE.min(1 << self.params.window_log)
    }

    /// Append input, first dropping history beyond the window. Up to another
    /// window's worth of history is kept to amortize the copy.
    fn append(&mut self, input: &[u8]) {
        let window = 1usize << self.params.window_log;
        if self.data.len() + input.len() > 2 * window + self.block_max() && self.pending > window {
            self.discard(self.pending - window);
        }
        self.data.extend_from_slice(input);
        #[cfg(feature = "hash")]
        self.hasher.write(input);
    }

    fn discard(&mut self, len: usize) {
        self.data.drain(..len);
        self.pending -= len;
        self.ms.base += len as u32;
    }

    fn flush<E>(&mut self, mut emit: impl FnMut(&[u8]) -> Result<(), E>) -> Result<(), E> {
        let result = emit(&self.output);
        self.output.clear();
        result
    }

    /// `ZSTD_compress_frameChunk()`: compress the pending input into one or
    /// more blocks.
    fn compress_chunk(&mut self, last: bool) {
        let chunk_len = self.data.len() - self.pending;
        let output_start = self.output.len();
        if chunk_len == 0 {
            if last {
                // ZSTD_writeLastEmptyBlock()
                block_header(&mut self.output, true, RAW_BLOCK, 0);
            }
            return;
        }
        // ZSTD_overflowCorrectIfNeeded(), for the whole chunk. Indices then
        // drop to about a window, so keep no more history than that.
        if self.ms.base + self.data.len() as u32 > CURRENT_MAX {
            let window = 1usize << self.params.window_log;
            self.discard(self.pending.saturating_sub(window));
            self.ms.correct_overflow(self.ms.base + self.pending as u32);
        }
        let mut savings = self.consumed as i64 - self.produced as i64;
        let mut done = 0;
        while done < chunk_len {
            let start = self.pending + done;
            let size = pre_split::block_size(
                &self.data[start..],
                self.block_max(),
                self.params.strategy,
                savings,
            );
            let last_block = last && done + size == chunk_len;
            let written = self.compress_block(start, start + size, last_block);
            savings += size as i64 - written as i64;
            done += size;
            self.first_block = false;
        }
        self.pending = self.data.len();
        self.consumed += chunk_len as u64;
        self.produced += (self.output.len() - output_start) as u64;
    }

    /// `ZSTD_compressBlock_internal()`: append the block `data[start..end]`
    /// with its header to the output, compressed, RLE or raw. Returns the
    /// size written.
    fn compress_block(&mut self, start: usize, end: usize, last: bool) -> usize {
        let ms = &mut self.ms;
        ms.enforce_max_dist(ms.base + start as u32);
        let block = &self.data[start..end];
        let mut c_size = 0;
        // Don't attempt compressing tiny blocks; a compressed block needs a
        // literals header, a sequences header and a block header.
        if !matches!(self.level, CompressionLevel::Uncompressed) && block.len() >= 7 {
            // Limited update after a very long match.
            let curr = ms.base + start as u32;
            if curr > ms.next_to_update + 384 {
                ms.next_to_update = curr - (curr - ms.next_to_update - 384).min(192);
            }
            let src = &self.data[..end];
            let store = &mut self.store;
            store.clear();
            let last_literals = match self.params.strategy {
                Strategy::Fast => fast::compress_block(ms, store, &self.rep, src, start),
                Strategy::DFast => double_fast::compress_block(ms, store, &self.rep, src, start),
                _ => lazy::compress_block(ms, store, &self.rep, src, start),
            };
            store.store_last_literals(src, last_literals);
            let mut rep = self.rep;
            c_size = sequences::compress_block(
                &mut self.body,
                store,
                &mut self.scratch,
                &self.prev,
                &mut self.next,
                &mut rep,
                &self.params,
            )
            .filter(|&size| size < block.len() - min_gain(block.len()))
            .unwrap_or(0);
            // Emit an RLE block only if it is not the frame's first block:
            // zstd 1.4.3 and earlier reject a frame starting with one.
            if !self.first_block && c_size < 25 && block.iter().all(|&b| b == block[0]) {
                c_size = 1;
            }
            if c_size > 1 {
                core::mem::swap(&mut self.prev, &mut self.next);
                self.rep = rep;
            }
        }
        let output = &mut self.output;
        match c_size {
            0 => {
                block_header(output, last, RAW_BLOCK, block.len());
                output.extend_from_slice(block);
                3 + block.len()
            }
            1 => {
                block_header(output, last, RLE_BLOCK, block.len());
                output.push(block[0]);
                4
            }
            _ => {
                block_header(output, last, COMPRESSED_BLOCK, c_size);
                output.extend_from_slice(&self.body[..c_size]);
                3 + c_size
            }
        }
    }
}

fn params(level: CompressionLevel, window_log: Option<u32>) -> CParams {
    let mut params = CParams::for_level(match level {
        CompressionLevel::Uncompressed | CompressionLevel::Fastest => 1,
        CompressionLevel::Default => 3,
        CompressionLevel::Better => 7,
        CompressionLevel::Best => 11,
        CompressionLevel::Level(level) => level,
    });
    if let Some(log) = window_log {
        params.window_log = log;
    }
    params
}

fn block_header(output: &mut Vec<u8>, last: bool, kind: u32, size: usize) {
    let header = u32::from(last) + (kind << 1) + ((size as u32) << 3);
    output.extend_from_slice(&header.to_le_bytes()[..3]);
}

/// An interface for compressing arbitrary data with the ZStandard compression algorithm.
///
/// `FrameCompressor` will generally be used by:
/// 1. Initializing a compressor by providing a buffer of data using `FrameCompressor::new()`
/// 2. Starting compression and writing that compression into a vec using `FrameCompressor::begin`
///
/// # Examples
/// ```
/// use ruzstd::encoding::{FrameCompressor, CompressionLevel};
/// let mock_data: &[_] = &[0x1, 0x2, 0x3, 0x4];
/// let mut output = std::vec::Vec::new();
/// // Initialize a compressor.
/// let mut compressor = FrameCompressor::new(CompressionLevel::Uncompressed);
/// compressor.set_source(mock_data);
/// compressor.set_drain(&mut output);
///
/// // `compress` writes the compressed output into the provided buffer.
/// compressor.compress();
/// ```
pub struct FrameCompressor<R: Read, W: Write> {
    uncompressed_data: Option<R>,
    compressed_data: Option<W>,
    core: StreamCompressor,
}

impl<R: Read, W: Write> FrameCompressor<R, W> {
    /// Create a new `FrameCompressor`
    pub fn new(compression_level: CompressionLevel) -> Self {
        Self {
            uncompressed_data: None,
            compressed_data: None,
            core: StreamCompressor::new(compression_level),
        }
    }

    /// Before calling [FrameCompressor::compress] you need to set the source.
    ///
    /// This is the data that is compressed and written into the drain.
    pub fn set_source(&mut self, uncompressed_data: R) -> Option<R> {
        self.uncompressed_data.replace(uncompressed_data)
    }

    /// Before calling [FrameCompressor::compress] you need to set the drain.
    ///
    /// As the compressor compresses data, the drain serves as a place for the output to be writte.
    pub fn set_drain(&mut self, compressed_data: W) -> Option<W> {
        self.compressed_data.replace(compressed_data)
    }

    /// Compress the uncompressed data from the provided source as one Zstd frame and write it to the provided drain
    ///
    /// This will repeatedly call [Read::read] on the source to fill up blocks until the source returns 0 on the read call.
    /// Also [Write::write_all] will be called on the drain after each block has been encoded.
    ///
    /// To avoid endlessly encoding from a potentially endless source (like a network socket) you can use the
    /// [Read::take] function
    pub fn compress(&mut self) {
        let enc = &mut self.core;
        enc.begin();
        let source = self.uncompressed_data.as_mut().unwrap();
        let drain = self.compressed_data.as_mut().unwrap();
        let mut buffer = vec![0; MAX_BLOCK_SIZE];
        loop {
            let read_bytes = source.read(&mut buffer).unwrap();
            if read_bytes == 0 {
                enc.finish(|b| drain.write_all(b)).unwrap();
                break;
            }
            enc.write(&buffer[..read_bytes], |b| drain.write_all(b))
                .unwrap();
        }
    }

    /// Get a mutable reference to the source
    pub fn source_mut(&mut self) -> Option<&mut R> {
        self.uncompressed_data.as_mut()
    }

    /// Get a mutable reference to the drain
    pub fn drain_mut(&mut self) -> Option<&mut W> {
        self.compressed_data.as_mut()
    }

    /// Get a reference to the source
    pub fn source(&self) -> Option<&R> {
        self.uncompressed_data.as_ref()
    }

    /// Get a reference to the drain
    pub fn drain(&self) -> Option<&W> {
        self.compressed_data.as_ref()
    }

    /// Retrieve the source
    pub fn take_source(&mut self) -> Option<R> {
        self.uncompressed_data.take()
    }

    /// Retrieve the drain
    pub fn take_drain(&mut self) -> Option<W> {
        self.compressed_data.take()
    }

    /// Before calling [FrameCompressor::compress] you can replace the compression level
    pub fn set_compression_level(
        &mut self,
        compression_level: CompressionLevel,
    ) -> CompressionLevel {
        self.core.set_compression_level(compression_level)
    }

    /// Get the current compression level
    pub fn compression_level(&self) -> CompressionLevel {
        self.core.compression_level()
    }

    /// Before calling [FrameCompressor::compress] you can override the level's window size, see
    /// [StreamCompressor::set_window_log]
    pub fn set_window_log(&mut self, log: Option<u32>) {
        self.core.set_window_log(log);
    }
}
