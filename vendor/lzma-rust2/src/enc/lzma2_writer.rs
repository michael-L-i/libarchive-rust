use alloc::vec::Vec;
use core::num::NonZeroU64;

use super::{
    encoder::{EncodeMode, LZMA2_CHUNK_MAX, LzmaEncoder, Settings, new_mf},
    lz::{Action, Mf, MfType},
};
use crate::{AutoFinish, AutoFinisher, Write};

/// Encoder settings when compressing with LZMA and LZMA2.
#[derive(Debug, Clone)]
pub struct LzmaOptions {
    /// Dictionary size in bytes.
    pub dict_size: u32,
    /// Number of literal context bits (0-8).
    pub lc: u32,
    /// Number of literal position bits (0-4).
    pub lp: u32,
    /// Number of position bits (0-4).
    pub pb: u32,
    /// Compression mode.
    pub mode: EncodeMode,
    /// Match finder nice length.
    pub nice_len: u32,
    /// Match finder type.
    pub mf: MfType,
    /// Match finder depth limit.
    pub depth_limit: i32,
    /// Preset dictionary data.
    pub preset_dict: Option<Vec<u8>>,
}

impl Default for LzmaOptions {
    fn default() -> Self {
        Self::with_preset(6)
    }
}

impl LzmaOptions {
    /// Default number of literal context bits.
    pub const LC_DEFAULT: u32 = 3;

    /// Default number of literal position bits.
    pub const LP_DEFAULT: u32 = 0;

    /// Default number of position bits.
    pub const PB_DEFAULT: u32 = 2;

    /// Maximum match finder nice length.
    pub const NICE_LEN_MAX: u32 = 273;

    /// Minimum match finder nice length.
    pub const NICE_LEN_MIN: u32 = 8;

    /// Default dictionary size (8MB).
    pub const DICT_SIZE_DEFAULT: u32 = 8 << 20;

    /// Creates new LZMA encoding options with specified parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dict_size: u32,
        lc: u32,
        lp: u32,
        pb: u32,
        mode: EncodeMode,
        nice_len: u32,
        mf: MfType,
        depth_limit: i32,
    ) -> Self {
        Self {
            dict_size,
            lc,
            lp,
            pb,
            mode,
            nice_len,
            mf,
            depth_limit,
            preset_dict: None,
        }
    }

    /// preset: [0..9]
    #[inline]
    pub fn with_preset(preset: u32) -> Self {
        let mut opt = Self::new(0, 0, 0, 0, EncodeMode::Normal, 0, MfType::Bt4, 0);
        opt.set_preset(preset);
        opt
    }

    /// preset: [0..9], as liblzma's `lzma_lzma_preset()`.
    pub fn set_preset(&mut self, preset: u32) {
        const DICT_POW2: [u8; 10] = [18, 20, 21, 22, 22, 23, 23, 24, 25, 26];
        const DEPTHS: [i32; 4] = [4, 8, 24, 48];
        let level = preset.min(9);

        self.preset_dict = None;
        self.lc = Self::LC_DEFAULT;
        self.lp = Self::LP_DEFAULT;
        self.pb = Self::PB_DEFAULT;
        self.dict_size = 1 << DICT_POW2[level as usize];
        if level <= 3 {
            self.mode = EncodeMode::Fast;
            self.mf = if level == 0 { MfType::Hc3 } else { MfType::Hc4 };
            self.nice_len = if level <= 1 { 128 } else { Self::NICE_LEN_MAX };
            self.depth_limit = DEPTHS[level as usize];
        } else {
            self.mode = EncodeMode::Normal;
            self.mf = MfType::Bt4;
            self.nice_len = match level {
                4 => 16,
                5 => 32,
                _ => 64,
            };
            self.depth_limit = 0;
        }
    }

    /// Returns the estimated memory usage in kilobytes for these options.
    pub fn get_memory_usage(&self) -> u32 {
        let opts = if self.mode == EncodeMode::Normal {
            super::encoder::OPTS as u64 * size_of::<super::encoder::Optimal>() as u64
        } else {
            0
        };
        let probs = (0x300u64 << (self.lc.min(8) + self.lp.min(4))) * 2;
        ((self.mf.mem_usage(self) + opts + probs + (80 << 10)) >> 10) as u32
    }

    /// Returns the LZMA properties byte for these options.
    #[inline(always)]
    pub fn get_props(&self) -> u8 {
        ((self.pb * 5 + self.lp) * 9 + self.lc) as u8
    }
}

/// Options for LZMA2 compression.
#[derive(Default, Debug, Clone)]
pub struct Lzma2Options {
    /// LZMA compression options.
    pub lzma_options: LzmaOptions,
    /// The size of each independent chunk in bytes.
    /// If not set, the whole data will be written as one chunk.
    /// Will get clamped to be at least the dict size to not waste memory.
    pub chunk_size: Option<NonZeroU64>,
}

impl Lzma2Options {
    /// Create options with specific preset.
    pub fn with_preset(preset: u32) -> Self {
        Self {
            lzma_options: LzmaOptions::with_preset(preset),
            chunk_size: None,
        }
    }

    /// Set the chunk size (None means a single chunk, which is the default).
    /// Chunk size will be clamped to be at least the dictionary size.
    pub fn set_chunk_size(&mut self, chunk_size: Option<NonZeroU64>) {
        self.chunk_size = chunk_size;
    }
}

/// Maximum uncompressed size of LZMA chunk (no headers)
const LZMA2_UNCOMPRESSED_MAX: u32 = 1 << 21;

/// A single-threaded LZMA2 compressor, ported from liblzma 5.8.4
/// (`lzma/lzma2_encoder.c`; Igor Pavlov, Lasse Collin; 0BSD).
pub struct Lzma2Writer<W: Write> {
    inner: W,
    mf: Mf,
    lzma: LzmaEncoder,
    /// True while an LZMA chunk is being encoded (`SEQ_LZMA_ENCODE`).
    in_chunk: bool,
    need_properties: bool,
    need_state_reset: bool,
    need_dictionary_reset: bool,
    /// Uncompressed size of the current chunk
    uncompressed_size: u32,
    /// Input bytes after which the dictionary is reset, and bytes taken
    /// since the last reset.
    chunk_size: Option<u64>,
    consumed: u64,
    options: Lzma2Options,
}

impl<W: Write> Lzma2Writer<W> {
    /// Creates a new LZMA2 writer that will write compressed data to the given writer.
    pub fn new(inner: W, options: Lzma2Options) -> Self {
        let lzma_options = &options.lzma_options;
        let settings = Settings::new(lzma_options);
        let mf = new_mf(lzma_options, &settings, true);
        let mut lzma = LzmaEncoder::new(lzma_options, &settings, false);
        lzma.rc.out.reserve(LZMA2_CHUNK_MAX as usize);
        let chunk_size = options
            .chunk_size
            .map(|s| s.get().max(u64::from(lzma_options.dict_size)));
        Self {
            inner,
            mf,
            lzma,
            in_chunk: false,
            need_properties: true,
            need_state_reset: false,
            need_dictionary_reset: lzma_options
                .preset_dict
                .as_ref()
                .is_none_or(|d| d.is_empty()),
            uncompressed_size: 0,
            chunk_size,
            consumed: 0,
            options,
        }
    }

    /// Writes the header and data of a finished LZMA chunk.
    fn write_lzma_chunk(&mut self) -> crate::Result<()> {
        let compressed_size = self.lzma.rc.out.len();
        debug_assert!(
            self.uncompressed_size > 0 && self.uncompressed_size <= LZMA2_UNCOMPRESSED_MAX
        );
        debug_assert!(compressed_size > 0 && compressed_size <= LZMA2_CHUNK_MAX as usize);

        let control = if self.need_properties {
            if self.need_dictionary_reset {
                0x80 + (3 << 5)
            } else {
                0x80 + (2 << 5)
            }
        } else if self.need_state_reset {
            0x80 + (1 << 5)
        } else {
            0x80
        };

        let size = self.uncompressed_size - 1;
        let packed = compressed_size - 1;
        let header = [
            control + (size >> 16) as u8,
            (size >> 8) as u8,
            size as u8,
            (packed >> 8) as u8,
            packed as u8,
            self.lzma.lclppb(),
        ];
        let len = if self.need_properties { 6 } else { 5 };
        self.inner.write_all(&header[..len])?;
        self.inner.write_all(&self.lzma.rc.out)?;

        self.need_properties = false;
        self.need_state_reset = false;
        self.need_dictionary_reset = false;
        Ok(())
    }

    /// Writes the current chunk's data from the history buffer as an
    /// uncompressed chunk.
    fn write_uncompressed_chunk(&mut self) -> crate::Result<()> {
        let size = self.uncompressed_size;
        debug_assert!(size > 0 && size <= LZMA2_CHUNK_MAX);

        // If this is the first chunk, we need to include dictionary
        // reset indicator.
        let control = if self.need_dictionary_reset { 1 } else { 2 };
        self.need_dictionary_reset = false;
        self.inner
            .write_all(&[control, ((size - 1) >> 8) as u8, (size - 1) as u8])?;

        debug_assert_eq!(self.mf.read_ahead, 0);
        let end = self.mf.read_pos as usize;
        self.inner
            .write_all(&self.mf.buffer[end - size as usize..end])
    }

    /// Encodes the buffered input into chunks (`lzma2_encode()`). Returns
    /// true once all of it is encoded when flushing or finishing.
    fn encode(&mut self) -> crate::Result<bool> {
        loop {
            if !self.in_chunk {
                // If there's no input left and we are flushing or finishing,
                // don't start a new chunk.
                if self.mf.unencoded() == 0 {
                    // Write end of payload marker if finishing.
                    if self.mf.action == Action::Finish {
                        self.inner.write_all(&[0])?;
                    }
                    return Ok(self.mf.action != Action::Run);
                }

                if self.need_state_reset {
                    self.lzma.reset();
                }
                self.uncompressed_size = 0;
                self.lzma.rc.out.clear();
                self.in_chunk = true;
            }

            // Calculate how much more uncompressed data this chunk
            // could accept.
            let left = LZMA2_UNCOMPRESSED_MAX - self.uncompressed_size;
            let limit = if left < self.mf.match_len_max {
                // Must flush immediately since the next LZMA symbol
                // could make the uncompressed size of the chunk too big.
                0
            } else {
                // Calculate maximum read_limit that is OK from point
                // of view of LZMA2 chunk size.
                self.mf.read_pos - self.mf.read_ahead + left - self.mf.match_len_max
            };

            // Save the start position so that we can update
            // uncompressed_size.
            let read_start = self.mf.read_pos - self.mf.read_ahead;
            let finished = self.lzma.encode(&mut self.mf, Some(limit));
            self.uncompressed_size += self.mf.read_pos - self.mf.read_ahead - read_start;
            if !finished {
                return Ok(false);
            }
            self.in_chunk = false;

            // See if the chunk compressed. If it didn't, we encode it
            // as uncompressed chunk. This saves a few bytes of space
            // and makes decoding faster.
            if self.lzma.rc.out.len() >= self.uncompressed_size as usize {
                self.uncompressed_size += self.mf.read_ahead;
                debug_assert!(self.uncompressed_size <= LZMA2_UNCOMPRESSED_MAX);
                self.mf.read_ahead = 0;
                self.write_uncompressed_chunk()?;
                self.need_state_reset = true;
            } else {
                // The chunk did compress at least by one byte, so we store
                // the chunk as LZMA.
                self.write_lzma_chunk()?;
            }
        }
    }

    /// Encodes all buffered input with the given action (`lz_encode()`
    /// with no input left).
    fn finish_input(&mut self, action: Action) -> crate::Result<()> {
        loop {
            if self.mf.action == Action::Run && self.mf.read_pos >= self.mf.read_limit {
                self.mf.fill_window(&[], action);
            }
            if self.encode()? {
                self.mf.action = Action::Run;
                return Ok(());
            }
        }
    }

    /// Ends the current independent chunk: encodes the buffered input and
    /// starts over with a fresh dictionary.
    fn start_independent_chunk(&mut self) -> crate::Result<()> {
        self.finish_input(Action::SyncFlush)?;
        let lzma_options = &self.options.lzma_options;
        let settings = Settings::new(lzma_options);
        self.mf = new_mf(lzma_options, &settings, true);
        self.lzma = LzmaEncoder::new(lzma_options, &settings, false);
        self.need_properties = true;
        self.need_state_reset = false;
        self.need_dictionary_reset = true;
        self.consumed = 0;
        Ok(())
    }

    /// Returns a wrapper around `self` that will finish the stream on drop.
    pub fn auto_finish(self) -> AutoFinisher<Self> {
        AutoFinisher(Some(self))
    }

    /// Unwraps the writer, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Returns a reference to the inner writer.
    pub fn inner(&self) -> &W {
        &self.inner
    }

    /// Returns a mutable reference to the inner writer.
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Finishes the compression and returns the underlying writer.
    pub fn finish(mut self) -> crate::Result<W> {
        self.finish_input(Action::Finish)?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for Lzma2Writer<W> {
    fn write(&mut self, buf: &[u8]) -> crate::Result<usize> {
        let mut pos = 0;
        while pos < buf.len() {
            let mut input = &buf[pos..];
            if let Some(chunk_size) = self.chunk_size {
                if self.consumed >= chunk_size {
                    self.start_independent_chunk()?;
                }
                let room = chunk_size - self.consumed;
                input = &input[..input.len().min(usize::try_from(room).unwrap_or(usize::MAX))];
            }
            // Read more data to the history buffer if needed.
            if self.mf.action == Action::Run && self.mf.read_pos >= self.mf.read_limit {
                let used = self.mf.fill_window(input, Action::Run);
                pos += used;
                self.consumed += used as u64;
            }
            self.encode()?;
        }
        Ok(pos)
    }

    /// Encodes all input written so far into complete chunks
    /// (`LZMA_SYNC_FLUSH`).
    fn flush(&mut self) -> crate::Result<()> {
        self.finish_input(Action::SyncFlush)?;
        self.inner.flush()
    }
}

impl<W: Write> AutoFinish for Lzma2Writer<W> {
    fn finish_ignore_error(self) {
        let _ = self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eager<W: Write>(writer: &mut Lzma2Writer<W>) {
        writer.mf.buffer.resize(writer.mf.buffer.capacity(), 0);
        writer.mf.son.resize(writer.mf.son.capacity(), 0);
    }

    #[test]
    fn partial_match_finder_initialization_preserves_streams() {
        let mut seed = 0x82f6_eab9u32;
        let data: Vec<u8> = (0..160_003)
            .map(|i| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                if i % 997 < 800 {
                    (i % 251) as u8
                } else {
                    seed as u8
                }
            })
            .collect();
        for preset in [0, 2, 6] {
            for dict_size in [4096, 65536, 1 << 23] {
                for part_size in [1, 31, 65536] {
                    for preset_dict in [None, Some(data[..10_007].to_vec())] {
                        let mut options = Lzma2Options::with_preset(preset);
                        options.lzma_options.dict_size = dict_size;
                        options.lzma_options.preset_dict = preset_dict;
                        let mut lazy = Lzma2Writer::new(Vec::new(), options.clone());
                        let mut full = Lzma2Writer::new(Vec::new(), options);
                        eager(&mut full);
                        for (i, part) in data.chunks(part_size).enumerate() {
                            lazy.write_all(part).unwrap();
                            full.write_all(part).unwrap();
                            if i % 211 == 210 {
                                lazy.flush().unwrap();
                                full.flush().unwrap();
                            }
                            assert!(lazy.mf.buffer.len() <= full.mf.buffer.len());
                            assert!(lazy.mf.son.len() <= full.mf.son.len());
                        }
                        assert_eq!(lazy.finish().unwrap(), full.finish().unwrap());
                    }
                }
            }
        }
    }

    #[test]
    fn partial_initialization_survives_independent_dictionary_resets() {
        let data: Vec<u8> = (0..160_003).map(|i| (i % 251) as u8).collect();
        for preset in [0, 2, 6] {
            let mut options = Lzma2Options::with_preset(preset);
            options.lzma_options.dict_size = 4096;
            options.chunk_size = NonZeroU64::new(4096);
            let mut lazy = Lzma2Writer::new(Vec::new(), options.clone());
            let mut full = Lzma2Writer::new(Vec::new(), options);
            eager(&mut full);
            for part in data.chunks(4096) {
                lazy.write_all(part).unwrap();
                full.write_all(part).unwrap();
                eager(&mut full);
            }
            assert_eq!(lazy.finish().unwrap(), full.finish().unwrap());
        }
    }

    #[test]
    fn short_input_leaves_unused_window_and_nodes_uninitialized() {
        let mut writer = Lzma2Writer::new(Vec::new(), Lzma2Options::with_preset(6));
        assert!(writer.mf.buffer.is_empty());
        assert!(writer.mf.son.is_empty());
        let buffer_capacity = writer.mf.buffer.capacity();
        let son_capacity = writer.mf.son.capacity();
        writer.write_all(&[0; 4096]).unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.mf.buffer.capacity(), buffer_capacity);
        assert_eq!(writer.mf.son.capacity(), son_capacity);
        assert!(writer.mf.buffer.len() < 8192);
        assert!(writer.mf.son.len() < 16384);
        assert_eq!(writer.mf.hash.len(), writer.mf.hash_mask as usize + 1);
        writer.finish().unwrap();
    }
}
