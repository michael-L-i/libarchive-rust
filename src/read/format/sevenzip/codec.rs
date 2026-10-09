// Ported from libarchive/archive_read_support_format_7zip.c.

//! The coders: `init_decompression` sets one up for a folder and
//! `decompress` runs it over a buffer of the packed stream, with the
//! branch filters after it.
//!
//! liblzma, zlib, libbz2 and libzstd are replaced by the safe Rust
//! `lzma-rust2`, `miniz_oxide`, the bzip2 filter's `Decoder` and `ruzstd`.
//! The branch (BCJ) and Delta filters always run here, on the coder's
//! output, where upstream hands them to liblzma for LZMA2 (and Delta for
//! LZMA); the output is the same.

use super::filters::bcj_lookahead;
use super::*;
use crate::ppmd::ByteIn;
use crate::ppmd7::{
    PPMD7_MAX_MEM_SIZE, PPMD7_MAX_ORDER, PPMD7_MIN_MEM_SIZE, PPMD7_MIN_ORDER, Ppmd7, Ppmd7RangeDec,
};
use crate::read::filter::bzip2::Decoder as Bz2Decoder;
use lzma_rust2::{Action, Lzma2Stream, LzmaStream, Status as LzStatus};
use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};
use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use std::io;

/// libzstd's default window limit (`ZSTD_WINDOWLOG_LIMIT_DEFAULT`).
const ZSTD_MAX_WINDOW: u64 = 1 << 27;
/// The same dictionary/model budget as the XZ read filter.
const MAX_DECODER_MEMORY: u32 = 256 * 1024 * 1024;
const ZSTD_MAGIC: [u8; 4] = 0xFD2F_B528u32.to_le_bytes();
/// The frame header descriptor's reserved bit.
const ZSTD_RESERVED_BIT: u8 = 0x08;

/// One coder's decompressor state.
enum Backend {
    None,
    Lzma(Box<LzmaStream>),
    Lzma2(Box<Lzma2Stream>),
    /// The state, and whether the last call filled the output (so the
    /// decoder may hold more).
    Deflate(Box<InflateState>, bool),

    /// The decoder, and whether the last call filled the output.
    Bzip2(Box<Bz2Decoder>, bool),
    Zstd(Box<Zstd>),
    Ppmd,
}

struct Zstd {
    decoder: FrameDecoder,
    /// In the middle of a frame.
    in_frame: bool,
    /// The packed stream ended in the middle of a frame.
    stalled: bool,
    /// Bytes output for the frame so far, and whether its header declares
    /// its content size, which libzstd checks and ruzstd does not.
    frame_out: u64,
    fcs_present: bool,
}

/// What one `step` did.
pub(super) struct Step {
    /// Bytes of the input used.
    pub used: usize,
    /// Bytes written to the output.
    pub produced: usize,
    /// The coder reached the end of its stream.
    pub eof: bool,
}

pub(super) struct Coders {
    backend: Backend,
    /// Decoding PPMd data. One model lives as long as the reader.
    ppmd: Ppmd7,
    range_dec: Ppmd7RangeDec,
    ppmd_valid: bool,
    ppmd_stat: i32,
}

impl Default for Coders {
    fn default() -> Self {
        Coders {
            backend: Backend::None,
            ppmd: Ppmd7::new(),
            range_dec: Ppmd7RangeDec::new_7z(),
            ppmd_valid: false,
            ppmd_stat: 0,
        }
    }
}

/// `ppmd_read`'s source: the packed stream, read ahead from the position
/// the call started at.
struct PpmdIn<'r, 'a> {
    r: &'r mut Reader<'a>,
    stream_in: usize,
    /// `pack_stream_inbytes_remaining`.
    limit: i64,
    overconsumed: bool,
}

impl ByteIn for PpmdIn<'_, '_> {
    fn read_byte(&mut self) -> u8 {
        // Ppmd7_DecodeSymbol might require reading multiple bytes and we are
        // on boundary; last resort to read using __archive_read_ahead.
        let byte = if self.limit <= 0 || self.stream_in as u64 >= self.limit as u64 {
            None
        } else {
            match self.r.read_ahead(self.stream_in + 1) {
                Ok(Some(d)) => d.get(self.stream_in).copied(),
                _ => None,
            }
        };
        match byte {
            Some(b) => {
                self.stream_in += 1;
                b
            }
            None => {
                self.r
                    .base()
                    .set_error(ARCHIVE_ERRNO_FILE_FORMAT, Some(b"Truncated 7z file data"));
                self.overconsumed = true;
                0
            }
        }
    }
}

/// The packed stream as the `Read` ruzstd decodes frames from.
struct PackIn<'r, 'a> {
    r: &'r mut Reader<'a>,
    pos: usize,
    limit: usize,
    /// The packed stream ran out.
    ended: bool,
    error: Option<Error>,
}

impl io::Read for PackIn<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = buf.len().min(self.limit - self.pos);
        if want == 0 {
            self.ended = true;
            return Ok(0);
        }
        let data = match self.r.peek_available(self.pos + want) {
            Ok(d) => d.get(self.pos..).unwrap_or_default(),
            Err(e) => {
                self.error = Some(e);
                return Err(io::Error::other("input failed"));
            }
        };
        let n = want.min(data.len());
        if n == 0 {
            self.ended = true;
        }
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), data.get(..n)) {
            dst.copy_from_slice(src);
        }
        self.pos += n;
        Ok(n)
    }
}

fn failed(msg: impl Into<Vec<u8>>) -> Error {
    Error::new(ARCHIVE_FAILED, ARCHIVE_ERRNO_MISC, msg)
}

/// libzstd's name for a failure of ruzstd.
fn zstd_failure(e: Option<&FrameDecoderError>) -> Error {
    let name = match e {
        Some(FrameDecoderError::WindowSizeTooBig { .. }) => {
            "Frame requires too much memory for decoding"
        }
        Some(
            FrameDecoderError::DictNotProvided { .. } | FrameDecoderError::DictionaryDecodeError(_),
        ) => "Dictionary mismatch",
        Some(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::BadMagicNumber(_))) => {
            "Unknown frame descriptor"
        }
        _ => "Data corruption detected",
    };
    failed(format!("Zstd decompression failed: {name}"))
}

/// `set_error` for liblzma's `LZMA_OPTIONS_ERROR`.
fn lzma_options_error() -> Error {
    failed("Lzma library error: Invalid options")
}

impl Coders {
    /// How much input to ask the stream for: 1 ("a performance
    /// optimization": asking for more than is there forces copying), except
    /// for the bzip2 decoder, which wants a whole piece of a block.
    pub(super) fn wanted_input(&self) -> usize {
        match &self.backend {
            Backend::Bzip2(d, _) => d.wanted(),
            _ => 1,
        }
    }

    /// Whether the coder holds decoded bytes it has not output yet, beyond
    /// the input it was given. liblzma and zlib leave unused input behind
    /// when the output is full; these decoders take all of it, and the
    /// bytes come out of later calls, which may have no input.
    pub(super) fn pending_output(&self) -> bool {
        match &self.backend {
            Backend::Lzma(s) => s.has_output(),
            Backend::Lzma2(s) => s.has_output(),
            Backend::Deflate(_, full) | Backend::Bzip2(_, full) => *full,
            Backend::Zstd(z) => z.decoder.can_collect() > 0,
            Backend::None | Backend::Ppmd => false,
        }
    }

    /// Runs the coder for `codec` over up to `bytes_in` bytes of the packed
    /// stream (read ahead, not consumed) into `out`.
    ///
    /// `ppmd_flush` is how many bytes PPMd is still to produce once the
    /// packed stream is used up; `inbytes_remaining` the packed stream's
    /// remaining size.
    fn step(
        &mut self,
        codec: i64,
        r: &mut Reader<'_>,
        out: &mut [u8],
        bytes_in: usize,
        ppmd_flush: i64,
        inbytes_remaining: i64,
    ) -> Result<Step, Error> {
        match codec {
            CODEC_COPY => {
                let src = r.peek_available(1).ok().and_then(|d| d.get(..bytes_in));
                let src = src.unwrap_or_default();
                let n = src.len().min(out.len());
                if let (Some(dst), Some(src)) = (out.get_mut(..n), src.get(..n)) {
                    dst.copy_from_slice(src);
                }
                Ok(Step {
                    used: n,
                    produced: n,
                    eof: bytes_in == 0,
                })
            }
            CODEC_LZMA | CODEC_LZMA2 => {
                let src = r.peek_available(1).ok().and_then(|d| d.get(..bytes_in));
                let src = src.unwrap_or_default();
                let res = match &mut self.backend {
                    Backend::Lzma(s) => s.process(src, out, Action::Run),
                    Backend::Lzma2(s) => s.process(src, out, Action::Run),
                    // liblzma's LZMA_PROG_ERROR, for a stream that has ended.
                    _ => return Err(failed("Decompression failed (11)")),
                };
                match res {
                    Ok(sr) => {
                        let ended = sr.status == LzStatus::StreamEnd;
                        let mut used = sr.bytes_consumed;
                        let mut eof = ended;
                        if matches!(self.backend, Backend::Lzma(_)) {
                            // A stream that has all its data takes no more
                            // input, but liblzma, without a size, goes on
                            // reading (and decoding) it, and can't tell the
                            // end of a stream with no end marker.
                            if ended
                                || (used == 0 && sr.bytes_produced == 0 && !self.pending_output())
                            {
                                used = bytes_in;
                            }
                            eof = false;
                        } else if ended {
                            self.backend = Backend::None;
                        }
                        Ok(Step {
                            used,
                            produced: sr.bytes_produced,
                            eof,
                        })
                    }
                    Err(e) => {
                        let code = match e.kind() {
                            io::ErrorKind::OutOfMemory => 5,
                            io::ErrorKind::Unsupported | io::ErrorKind::InvalidInput => 8,
                            _ => 9,
                        };
                        Err(failed(format!("Decompression failed ({code})")))
                    }
                }
            }
            CODEC_BZ2 => {
                let src = r.peek_available(self.wanted_input()).ok();
                let src = src.and_then(|d| d.get(..bytes_in)).unwrap_or_default();
                let Backend::Bzip2(d, full) = &mut self.backend else {
                    return Err(failed("bzip decompression failed"));
                };
                let last = src.len() < d.wanted();
                match d.decompress(src, out, last) {
                    Ok(p) => {
                        *full = p.produced == out.len();
                        if p.end {
                            self.backend = Backend::None;
                        }
                        Ok(Step {
                            used: p.used,
                            produced: p.produced,
                            eof: p.end,
                        })
                    }
                    Err(_) => Err(failed("bzip decompression failed")),
                }
            }
            CODEC_DEFLATE => {
                let src = r.peek_available(1).ok().and_then(|d| d.get(..bytes_in));
                let src = src.unwrap_or_default();
                let Backend::Deflate(state, full) = &mut self.backend else {
                    return Err(failed("File decompression failed (-2)"));
                };
                let res = inflate(state, src, out, MZFlush::None);
                match res.status {
                    // Found end of stream, or the decompressor made some
                    // progress.
                    Ok(MZStatus::Ok) | Ok(MZStatus::StreamEnd) => {
                        let eof = matches!(res.status, Ok(MZStatus::StreamEnd));
                        *full = !eof && res.bytes_written == out.len();
                        Ok(Step {
                            used: res.bytes_consumed,
                            produced: res.bytes_written,
                            eof,
                        })
                    }
                    Ok(MZStatus::NeedDict) => Err(failed("File decompression failed (2)")),
                    Err(e) => Err(failed(format!("File decompression failed ({})", e as i32))),
                }
            }
            CODEC_ZSTD => {
                let Backend::Zstd(z) = &mut self.backend else {
                    return Err(failed(
                        "Zstd decompression failed: Data corruption detected",
                    ));
                };
                zstd_step(z, r, out, usize::try_from(inbytes_remaining).unwrap_or(0))
            }
            CODEC_PPMD => self.ppmd_step(r, out, bytes_in, ppmd_flush, inbytes_remaining),
            _ => Err(failed("Decompression internal error")),
        }
    }

    fn ppmd_step(
        &mut self,
        r: &mut Reader<'_>,
        out: &mut [u8],
        bytes_in: usize,
        ppmd_flush: i64,
        inbytes_remaining: i64,
    ) -> Result<Step, Error> {
        if !self.ppmd_valid || self.ppmd_stat < 0 || out.is_empty() {
            return Err(failed("Decompression internal error"));
        }
        let mut src = PpmdIn {
            r,
            stream_in: 0,
            limit: inbytes_remaining,
            overconsumed: false,
        };
        if self.ppmd_stat == 0 {
            if !self.range_dec.init(&mut src) {
                self.ppmd_stat = -1;
                return Err(failed("Failed to initialize PPMd range decoder"));
            }
            if src.overconsumed {
                self.ppmd_stat = -1;
                return Err(Error::silent(ARCHIVE_FAILED));
            }
            self.ppmd_stat = 1;
        }

        let mut produced = 0;
        let mut flush_bytes;
        if bytes_in == 0 {
            // XXX Flush out remaining decoded data XXX
            //
            // The bytes a BCJ filter parked on the previous call have just
            // been written to the output buffer, and count towards what the
            // folder still owes. Asking PPMd to decode them a second time
            // would run the range decoder off the end of the packed stream.
            flush_bytes = ppmd_flush;
            // Those bytes were all that was left of the folder.
            if flush_bytes <= 0 {
                return Ok(Step {
                    used: src.stream_in,
                    produced,
                    eof: false,
                });
            }
        } else {
            flush_bytes = 0;
        }

        loop {
            let sym = self.ppmd.decode_symbol(&mut self.range_dec, &mut src);
            if sym < 0 {
                self.ppmd_stat = -1;
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Failed to decode PPMd",
                ));
            }
            if src.overconsumed {
                self.ppmd_stat = -1;
                return Err(Error::silent(ARCHIVE_FAILED));
            }
            if let Some(o) = out.get_mut(produced) {
                *o = sym as u8;
            }
            produced += 1;
            if flush_bytes > 0 {
                flush_bytes -= 1;
            }
            let avail_in = bytes_in.saturating_sub(src.stream_in);
            if !(produced < out.len() && (avail_in != 0 || flush_bytes != 0)) {
                break;
            }
        }
        Ok(Step {
            used: src.stream_in,
            produced,
            eof: false,
        })
    }
}

/// ZSTD_decompressStream, over the packed stream: fills `out`, reading
/// frames from the packed stream as the decoder needs them.
fn zstd_step(
    z: &mut Zstd,
    r: &mut Reader<'_>,
    out: &mut [u8],
    limit: usize,
) -> Result<Step, Error> {
    let mut input = PackIn {
        r,
        pos: 0,
        limit,
        ended: false,
        error: None,
    };
    let mut produced = 0;
    while produced < out.len() && !z.stalled {
        if z.decoder.can_collect() > 0 {
            let room = out.get_mut(produced..).unwrap_or_default();
            let n = io::Read::read(&mut z.decoder, room).map_err(|_| zstd_failure(None))?;
            produced += n;
            z.frame_out += n as u64;
            continue;
        }
        if z.in_frame && z.decoder.is_finished() {
            if z.fcs_present && z.decoder.content_size() != z.frame_out {
                return Err(zstd_failure(None));
            }
            if let Some(stored) = z.decoder.get_checksum_from_data()
                && z.decoder.get_calculated_checksum() != Some(stored)
            {
                return Err(failed(
                    "Zstd decompression failed: Restored data doesn't match checksum",
                ));
            }
            z.in_frame = false;
        }
        if !z.in_frame {
            // Skip the skippable frames before the next frame.
            loop {
                if input.pos >= input.limit {
                    break;
                }
                let at = input.pos;
                let head = input
                    .r
                    .peek_available(at + 8)?
                    .get(at..)
                    .unwrap_or_default();
                let skip = match head.first_chunk::<8>() {
                    Some(h)
                        if u32::from_le_bytes([h[0], h[1], h[2], h[3]]) & 0xFFFF_FFF0
                            == 0x184D_2A50 =>
                    {
                        u64::from(u32::from_le_bytes([h[4], h[5], h[6], h[7]])) + 8
                    }
                    _ => break,
                };
                if skip > (input.limit - at) as u64 {
                    input.ended = true;
                    z.stalled = true;
                    break;
                }
                input.pos += skip as usize;
            }
            if z.stalled || input.pos >= input.limit {
                break;
            }
            let at = input.pos;
            let head = input
                .r
                .peek_available(at + 5)?
                .get(at..)
                .unwrap_or_default();
            let descriptor = head.get(4).copied().unwrap_or(0);
            if head.get(..4) == Some(&ZSTD_MAGIC[..]) && descriptor & ZSTD_RESERVED_BIT != 0 {
                return Err(failed(
                    "Zstd decompression failed: Unsupported frame parameter",
                ));
            }
            if let Err(e) = z.decoder.reset(&mut input) {
                if input.ended {
                    z.stalled = true;
                    break;
                }
                return Err(input.error.take().unwrap_or_else(|| zstd_failure(Some(&e))));
            }
            z.in_frame = true;
            z.frame_out = 0;
            z.fcs_present = descriptor >> 6 != 0 || descriptor & 0x20 != 0;
            continue;
        }
        if let Err(e) = z
            .decoder
            .decode_blocks(&mut input, BlockDecodingStrategy::UptoBytes(1))
        {
            if input.ended {
                z.stalled = true;
                break;
            }
            return Err(input.error.take().unwrap_or_else(|| zstd_failure(Some(&e))));
        }
    }
    Ok(Step {
        used: input.pos,
        produced,
        eof: false,
    })
}

impl SevenZip {
    /// `init_decompression`: sets up the decoder for a folder's first coder
    /// and the filter (second coder) after it. A failure is
    /// `ARCHIVE_FAILED` unless noted.
    pub(super) fn init_decompression(
        &mut self,
        coder1: &Coder,
        coder2: Option<&Coder>,
    ) -> Result<(), Error> {
        self.codec = coder1.codec;
        self.codec2 = -1;
        self.filters.set_lzma2_filter(None);

        if matches!(
            self.codec,
            CODEC_COPY | CODEC_BZ2 | CODEC_DEFLATE | CODEC_ZSTD | CODEC_PPMD
        ) && let Some(c2) = coder2
        {
            if !matches!(
                c2.codec,
                CODEC_X86
                    | CODEC_X86_BCJ2
                    | CODEC_ARM
                    | CODEC_ARMTHUMB
                    | CODEC_ARM64
                    | CODEC_IA64
                    | CODEC_POWERPC
                    | CODEC_RISCV
                    | CODEC_SPARC
                    | CODEC_DELTA
            ) {
                return Err(failed(format!(
                    "Unsupported filter {:x} for {:x}",
                    c2.codec, coder1.codec
                )));
            }
            self.codec2 = c2.codec;
            self.bcj2.reset();
            self.init_filter(c2)?;
        }

        match self.codec {
            CODEC_COPY => {}
            CODEC_LZMA | CODEC_LZMA2 => self.init_lzma(coder1, coder2)?,
            CODEC_BZ2 => self.coders.backend = Backend::Bzip2(Box::new(Bz2Decoder::new()), false),
            CODEC_ZSTD => {
                let mut decoder = FrameDecoder::new();
                decoder.set_max_window_size(ZSTD_MAX_WINDOW);
                self.coders.backend = Backend::Zstd(Box::new(Zstd {
                    decoder,
                    in_frame: false,
                    stalled: false,
                    frame_out: 0,
                    fcs_present: false,
                }));
            }
            CODEC_DEFLATE => {
                // Don't check for zlib header.
                self.coders.backend =
                    Backend::Deflate(InflateState::new_boxed(DataFormat::Raw), false);
            }
            CODEC_PPMD => self.init_ppmd(coder1)?,
            CODEC_X86 | CODEC_X86_BCJ2 | CODEC_POWERPC | CODEC_IA64 | CODEC_ARM
            | CODEC_ARMTHUMB | CODEC_ARM64 | CODEC_RISCV | CODEC_SPARC | CODEC_DELTA => {
                return Err(failed(format!("Unexpected codec ID: {:X}", self.codec)));
            }
            c if is_crypto(c) => {
                if self.in_read_header {
                    self.entry_encrypted = true;
                }
                self.has_encrypted_entries = 1;
                return Err(failed(format!(
                    "Crypto codec not supported yet (ID: 0x{c:X})"
                )));
            }
            c => return Err(failed(format!("Unknown codec ID: {c:X}"))),
        }
        Ok(())
    }

    /// Starts the filter after a coder other than LZMA and LZMA2.
    fn init_filter(&mut self, c2: &Coder) -> Result<(), Error> {
        match c2.codec {
            CODEC_X86 => self.filters.x86_init(),
            CODEC_ARM => self.filters.arm_init(),
            CODEC_ARMTHUMB => self.filters.armthumb_init(),
            CODEC_ARM64 | CODEC_IA64 | CODEC_POWERPC | CODEC_RISCV | CODEC_SPARC => {
                self.filters.bcj_ip = 0;
            }
            CODEC_DELTA => {
                let &[dist] = c2.properties.as_slice() else {
                    return Err(failed("Invalid Delta parameter"));
                };
                self.filters.delta_init(u32::from(dist) + 1);
            }
            _ => {}
        }
        Ok(())
    }

    fn init_lzma(&mut self, coder1: &Coder, coder2: Option<&Coder>) -> Result<(), Error> {
        self.coders.backend = Backend::None;

        // NOTE: liblzma incompletely handle the BCJ+LZMA compressed data
        // made by 7-Zip because 7-Zip does not add End-Of-Payload
        // Marker(EOPM) at the end of LZMA compressed data, and so liblzma
        // cannot know the end of the compressed data without EOPM. So
        // consequently liblzma will not return last three or four bytes of
        // uncompressed data because LZMA_FILTER_X86 filter does not handle
        // input data if its data size is less than five bytes. If liblzma
        // detect EOPM or know the uncompressed data size, liblzma will flush
        // out the remaining that three or four bytes of uncompressed data.
        // That is why we have to use our converting program for BCJ+LZMA.
        //
        // Reference: https://web.archive.org/web/20240405171610/https://www.mail-archive.com/xz-devel@tukaani.org/msg00373.html
        if let Some(c2) = coder2 {
            self.codec2 = c2.codec;
            match c2.codec {
                CODEC_X86_BCJ2 => self.bcj2.reset(),
                CODEC_DELTA => self.init_filter(c2)?,
                c if bcj_lookahead(c) != 0 && self.codec == CODEC_LZMA2 => {
                    // liblzma runs the branch filters of LZMA2 upstream.
                    self.filters.set_lzma2_filter(Some(c));
                }
                c if bcj_lookahead(c) != 0 => self.init_filter(c2)?,
                c => return Err(failed(format!("Unexpected codec ID: {c:X}"))),
            }
        }

        let size = if self.codec2 == CODEC_X86_BCJ2 {
            self.main_stream_bytes_remaining
        } else {
            self.folder_outbytes_remaining
        };
        let props = coder1.properties.as_slice();
        if self.codec == CODEC_LZMA2 {
            let &[b] = props else {
                return Err(lzma_options_error());
            };
            if b > 40 {
                return Err(lzma_options_error());
            }
            let dict_size = if b == 40 {
                u32::MAX
            } else {
                (2 | u32::from(b & 1)) << (b / 2 + 11)
            };
            if dict_size > MAX_DECODER_MEMORY {
                return Err(failed("Decompression failed (5)"));
            }
            // No valid match can refer farther back than this stream's output.
            // Encoded headers often advertise a much larger dictionary.
            let dict_size =
                u32::try_from(size).map_or(dict_size, |size| dict_size.min(size.max(4096)));
            self.coders.backend = Backend::Lzma2(Box::new(Lzma2Stream::new(dict_size)));
        } else {
            let &[b, d0, d1, d2, d3] = props else {
                return Err(lzma_options_error());
            };
            if b > (4 * 5 + 4) * 9 + 8 {
                return Err(lzma_options_error());
            }
            let dict_size = u32::from_le_bytes([d0, d1, d2, d3]);
            if dict_size > MAX_DECODER_MEMORY {
                return Err(failed("Decompression failed (5)"));
            }
            // The size of the stream is known; a stream with no end marker
            // (7-Zip writes none) can't be finished otherwise.
            let stream = LzmaStream::new_with_props(
                u64::try_from(size).unwrap_or(u64::MAX),
                b,
                dict_size,
                None,
            )
            .map_err(|_| lzma_options_error())?;
            self.coders.backend = Backend::Lzma(Box::new(stream));
        }
        Ok(())
    }

    fn init_ppmd(&mut self, coder1: &Coder) -> Result<(), Error> {
        let c = &mut self.coders;
        if c.ppmd_valid {
            c.ppmd.free();
            c.ppmd_valid = false;
        }

        let malformed = || failed("Malformed PPMd parameter");
        let &[order, m0, m1, m2, m3, ..] = coder1.properties.as_slice() else {
            return Err(malformed());
        };
        let order = u32::from(order);
        let msize = u32::from_le_bytes([m0, m1, m2, m3]);
        if !(PPMD7_MIN_ORDER..=PPMD7_MAX_ORDER).contains(&order)
            || !(PPMD7_MIN_MEM_SIZE..=PPMD7_MAX_MEM_SIZE).contains(&msize)
        {
            return Err(malformed());
        }
        if msize > MAX_DECODER_MEMORY {
            return Err(Error::fatal(
                libc::ENOMEM,
                "Coludn't allocate memory for PPMd",
            ));
        }
        c.ppmd.free();
        if !c.ppmd.alloc(msize) {
            return Err(Error::fatal(
                libc::ENOMEM,
                "Coludn't allocate memory for PPMd",
            ));
        }
        c.ppmd.init(order);
        c.range_dec = Ppmd7RangeDec::new_7z();
        c.ppmd_valid = true;
        c.ppmd_stat = 0;
        c.backend = Backend::Ppmd;
        Ok(())
    }

    /// `decompress`: runs the coder over up to `bytes_in` bytes of the
    /// packed stream into `buff`, then the filter. Returns the bytes of the
    /// input used, of `buff` filled, and whether the coder is done.
    pub(super) fn decompress(
        &mut self,
        r: &mut Reader<'_>,
        buff: &mut [u8],
        bytes_in: usize,
    ) -> Result<(usize, usize, bool), Error> {
        // Whether more output can come: input is left, or the coder holds
        // output (`o_avail_in != 0` upstream).
        let has_input = bytes_in != 0 || self.coders.pending_output();
        let o_avail_out = buff.len();
        let mut t_avail_out = o_avail_out;
        let mut out_pos = 0usize;
        let mut odd_bcj_out = 0usize;
        let lookahead = bcj_lookahead(self.codec2);

        if lookahead != 0 {
            // Do not copy out the BCJ remaining bytes when the output buffer
            // size is less than the filter's lookahead size.
            if has_input && t_avail_out < lookahead && self.filters.odd_bcj_size != 0 {
                return Ok((0, 0, false));
            }
            let mut i = 0;
            while self.filters.odd_bcj_size > 0 && t_avail_out > 0 {
                buff[out_pos] = self.filters.odd_bcj[i];
                out_pos += 1;
                t_avail_out -= 1;
                self.filters.odd_bcj_size -= 1;
                odd_bcj_out += 1;
                i += 1;
            }
            // PPMd is the only codec which can still produce output after
            // its packed stream has been consumed: it is asked to flush the
            // rest of the folder when called with no input. Returning here
            // would skip that flush and leave the folder short, so let it
            // through.
            if (!has_input && self.codec != CODEC_PPMD) || t_avail_out == 0 {
                return Ok((0, o_avail_out - t_avail_out, !has_input));
            }
        }

        let mut bcj2_pos = out_pos;
        let mut bcj2_avail_out = t_avail_out;
        if self.codec2 == CODEC_X86_BCJ2 {
            // Decode a remaining decompressed main stream for BCJ2.
            if self.bcj2.tmp_remaining != 0 {
                let remaining = self.bcj2.tmp_remaining;
                let dst = buff
                    .get_mut(out_pos..out_pos + t_avail_out)
                    .unwrap_or_default();
                let bytes = self
                    .bcj2
                    .decode(&mut self.filters, dst)
                    .map_err(|()| failed("BCJ2 conversion failed"))?;
                self.main_stream_bytes_remaining -= (remaining - self.bcj2.tmp_remaining) as i64;
                t_avail_out -= bytes;
                if !has_input || t_avail_out == 0 {
                    return Ok((
                        0,
                        o_avail_out - t_avail_out,
                        !has_input && self.bcj2.tmp_remaining != 0,
                    ));
                }
                out_pos += bytes;
                bcj2_pos = out_pos;
                bcj2_avail_out = t_avail_out;
            }
        }

        let ppmd_flush = self.folder_outbytes_remaining - odd_bcj_out as i64;
        let step = if self.codec2 == CODEC_X86_BCJ2 {
            // The main stream is decoded into the temporary buffer.
            self.coders.step(
                self.codec,
                r,
                &mut self.bcj2.tmp,
                bytes_in,
                ppmd_flush,
                self.pack_stream_inbytes_remaining,
            )?
        } else {
            let dst = buff.get_mut(out_pos..).unwrap_or_default();
            self.coders.step(
                self.codec,
                r,
                dst,
                bytes_in,
                ppmd_flush,
                self.pack_stream_inbytes_remaining,
            )?
        };
        let used = step.used;
        let mut outbytes = out_pos + step.produced;
        let eof = step.eof;

        // Decode BCJ.
        if lookahead != 0 {
            let l = self
                .filters
                .convert(self.codec2, buff.get_mut(..outbytes).unwrap_or_default())
                .unwrap_or(0);

            // Keep the bytes which could not be converted yet, they are
            // prepended to the output buffer on the next call.
            let odd = outbytes - l;
            if odd > 0 && odd <= self.filters.odd_bcj.len() && has_input && !eof {
                self.filters.odd_bcj_size = odd;
                if let (Some(dst), Some(src)) =
                    (self.filters.odd_bcj.get_mut(..odd), buff.get(l..outbytes))
                {
                    dst.copy_from_slice(src);
                }
                outbytes = l;
            } else {
                self.filters.odd_bcj_size = 0;
            }
        }

        // Decode BCJ2 with a decompressed main stream.
        if self.codec2 == CODEC_X86_BCJ2 {
            let avail = step.produced;
            self.bcj2.tmp_avail =
                avail.min(usize::try_from(self.main_stream_bytes_remaining).unwrap_or(0));
            self.bcj2.tmp_remaining = self.bcj2.tmp_avail;
            let dst = buff
                .get_mut(bcj2_pos..bcj2_pos + bcj2_avail_out)
                .unwrap_or_default();
            let bytes = self
                .bcj2
                .decode(&mut self.filters, dst)
                .map_err(|()| failed("BCJ2 conversion failed"))?;
            self.main_stream_bytes_remaining -=
                (self.bcj2.tmp_avail - self.bcj2.tmp_remaining) as i64;
            outbytes = bcj2_pos + bytes;
        }

        // Decode Delta.
        if self.codec2 == CODEC_DELTA {
            self.filters
                .delta_decode(buff.get_mut(..outbytes).unwrap_or_default());
        }

        Ok((used, outbytes, eof))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lzma2_dictionary_covers_the_decoded_stream() {
        use lzma_rust2::{Lzma2Options, Lzma2Writer};
        use std::io::Write;

        // The second half needs history beyond the minimum dictionary.
        let mut state = 0x12345678u32;
        let mut data: Vec<u8> = (0..8192)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        data.extend_from_within(..);
        let mut encoder = Lzma2Writer::new(Vec::new(), Lzma2Options::with_preset(1));
        encoder.write_all(&data).unwrap();
        let encoded = encoder.finish().unwrap();
        let coder = Coder {
            codec: CODEC_LZMA2,
            properties: vec![22], // 8 MiB advertised dictionary.
            ..Coder::default()
        };
        let bcj2 = Coder {
            codec: CODEC_X86_BCJ2,
            ..Coder::default()
        };
        for (size, main_size, filter) in [
            (data.len() as i64, 0, None),
            (-1, 0, None),
            (i64::MAX, 0, None),
            (1, data.len() as i64, Some(&bcj2)),
        ] {
            let mut reader = SevenZip {
                codec: CODEC_LZMA2,
                folder_outbytes_remaining: size,
                main_stream_bytes_remaining: main_size,
                ..SevenZip::default()
            };
            reader.init_lzma(&coder, filter).unwrap();
            let Backend::Lzma2(stream) = &mut reader.coders.backend else {
                panic!("missing LZMA2 decoder");
            };
            let mut output = vec![0; data.len() + 1];
            let result = stream
                .process(&encoded, &mut output, Action::Finish)
                .unwrap();
            assert_eq!(result.status, LzStatus::StreamEnd);
            assert_eq!(&output[..result.bytes_produced], data);
        }

        // A false tiny size must still reject matches outside its history.
        let mut reader = SevenZip {
            codec: CODEC_LZMA2,
            folder_outbytes_remaining: 1,
            ..SevenZip::default()
        };
        reader.init_lzma(&coder, None).unwrap();
        let Backend::Lzma2(stream) = &mut reader.coders.backend else {
            panic!("missing LZMA2 decoder");
        };
        assert!(
            stream
                .process(&encoded, &mut vec![0; data.len() + 1], Action::Finish)
                .is_err()
        );
    }

    #[test]
    fn oversized_decoder_models_fail_before_allocation() {
        for (codec, properties) in [
            (CODEC_LZMA, vec![0x5d, 0xff, 0xff, 0xff, 0xff]),
            (CODEC_LZMA2, vec![40]),
            (CODEC_PPMD, vec![6, 0, 0, 0, 0x40]),
        ] {
            let mut reader = SevenZip {
                codec,
                ..SevenZip::default()
            };
            let coder = Coder {
                codec,
                properties,
                ..Coder::default()
            };
            let error = if codec == CODEC_PPMD {
                reader.init_ppmd(&coder)
            } else {
                reader.init_lzma(&coder, None)
            }
            .unwrap_err();
            if codec == CODEC_PPMD {
                assert_eq!(error.errno, libc::ENOMEM);
                assert!(!reader.coders.ppmd.was_allocated());
            } else {
                assert_eq!(error.msg, b"Decompression failed (5)");
                assert!(matches!(reader.coders.backend, Backend::None));
            }
        }
    }
}
