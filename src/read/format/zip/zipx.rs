/*-
 * Copyright (c) 2004-2013 Tim Kientzle
 * Copyright (c) 2011-2012,2014 Michihiro NAKAJIMA
 * Copyright (c) 2013 Konrad Kleine
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

// Ported from libarchive/archive_read_support_format_zip.c.

//! The compression methods zipx adds to deflate: bzip2, LZMA, XZ, Zstandard
//! and PPMd.

use super::{BUFFER_SIZE, Out, Zip};
use crate::archive::*;
use crate::ppmd::ByteIn;
use crate::ppmd8::Ppmd8;
use crate::read::filter::bzip2::Decoder as Bzip2Decoder;
use crate::read::{ARCHIVE_ERRNO_FILE_FORMAT, ARCHIVE_ERRNO_PROGRAMMER, Reader};
use crate::util::Error;
use lzma_rust2::{Action, LzmaStream, Status, StreamResult, XzStream};
use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use std::io::{self, ErrorKind};

/// liblzma's return codes, which its messages print.
const LZMA_OK: i32 = 0;
const LZMA_STREAM_END: i32 = 1;
const LZMA_MEMLIMIT_ERROR: i32 = 6;
const LZMA_FORMAT_ERROR: i32 = 7;
const LZMA_OPTIONS_ERROR: i32 = 8;
const LZMA_DATA_ERROR: i32 = 9;
const LZMA_BUF_ERROR: i32 = 10;

/// The memory an xz stream may ask for, in KiB. Upstream has no limit; a
/// header can ask for 4 GiB.
const XZ_MEM_LIMIT_KIB: u32 = 256 * 1024;

/// The memory the LZMA decoder may use, in bytes. Upstream allows 576 MiB;
/// keep the same 256 MiB safety bound as the standalone filter.
const LZMA_MEMLIMIT: u64 = 256 * (1 << 20);

/// The state of the decompressors that aren't deflate. They are kept for the
/// reader's lifetime: PPMd's escape estimate carries over between entries,
/// as it does in upstream's zeroed `struct zip`.
#[derive(Default)]
pub(super) struct Decoders {
    /// `zipx_lzma_stream`, for lzma alone, or xz.
    lzma: Option<LzmaStream>,
    xz: Option<XzStream>,
    /// Whether liblzma would return `LZMA_BUF_ERROR` if there is no
    /// progress now: it does when the previous call made none either.
    lz_allow_buf_error: bool,
    /// All the entry's compressed bytes are in the LZMA decoder, which may
    /// hold back the output of the last few of them until it is told that
    /// nothing follows (by being called with no input).
    lzma_drain: bool,
    /// The LZMA decoder was told the uncompressed size, so it stops there
    /// and doesn't read an end marker.
    lzma_sized: bool,
    bzip2: Option<Bzip2Decoder>,
    zstd: Option<Zstd>,
    ppmd8: Ppmd8,
    ppmd8_stream_failed: bool,
    /// The number of compressed bytes PPMd's byte source has read.
    ppmd_read_compressed: i64,
}

/// What a call of `lzma_code` did.
struct Step {
    code: i32,
    consumed: usize,
    produced: usize,
}

fn lz_error_code(e: &io::Error) -> i32 {
    match e.kind() {
        ErrorKind::OutOfMemory => LZMA_MEMLIMIT_ERROR,
        ErrorKind::Unsupported => LZMA_OPTIONS_ERROR,
        ErrorKind::InvalidInput => LZMA_FORMAT_ERROR,
        _ => LZMA_DATA_ERROR,
    }
}

/// What liblzma would have returned for the call, given the crate's.
/// `unused` is the input a finished stream took but didn't use.
fn lz_step(res: io::Result<StreamResult>, unused: usize, allow_buf_error: &mut bool) -> Step {
    match res {
        Ok(r) => {
            let ended = r.status == Status::StreamEnd;
            let mut code = if ended { LZMA_STREAM_END } else { LZMA_OK };
            if !ended {
                if r.bytes_consumed == 0 && r.bytes_produced == 0 {
                    if *allow_buf_error {
                        code = LZMA_BUF_ERROR;
                    } else {
                        *allow_buf_error = true;
                    }
                } else {
                    *allow_buf_error = false;
                }
            }
            Step {
                code,
                consumed: if ended {
                    r.bytes_consumed.saturating_sub(unused)
                } else {
                    r.bytes_consumed
                },
                produced: r.bytes_produced,
            }
        }
        Err(e) => Step {
            code: lz_error_code(&e),
            consumed: 0,
            produced: 0,
        },
    }
}

fn misc(msg: String) -> Error {
    Error::fatal(ARCHIVE_ERRNO_MISC, msg)
}

impl<const SEEKABLE: bool> Zip<SEEKABLE> {
    fn lzma_alone_init(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        self.zipx.lzma = None;

        // To unpack ZIPX's "LZMA" (id 14) stream we can use standard liblzma
        // that is a part of XZ Utils. The stream format stored inside ZIPX
        // file is a modified "lzma alone" file format, that was used by the
        // `lzma` utility which was later deprecated in favour of `xz`
        // utility. Since those formats are nearly the same, we can use a
        // standard "lzma alone" decoder from XZ Utils.
        //
        // The "lzma alone" file format and the stream format inside ZIPx
        // are almost the same. Here's an example of a structure of "lzma
        // alone" format:
        //
        // $ cat /bin/ls | lzma | xxd | head -n 1
        // 00000000: 5d00 0080 00ff ffff ffff ffff ff00 2814
        //
        //    5 bytes        8 bytes        n bytes
        // <lzma_params><uncompressed_size><data...>
        //
        // lzma_params is a 5-byte blob that has to be decoded to extract
        // parameters of this LZMA stream. The uncompressed_size field is an
        // uint64_t value that contains information about the size of the
        // uncompressed file, or UINT64_MAX if this value is unknown. The
        // <data...> part is the actual lzma-compressed data stream.
        //
        // Now here's the structure of the stream inside the ZIPX file:
        //
        // $ cat stream_inside_zipx | xxd | head -n 1
        // 00000000: 0914 0500 5d00 8000 0000 2814 .... ....
        //
        //  2byte   2byte    5 bytes     n bytes
        // <magic1><magic2><lzma_params><data...>
        //
        // This means that the ZIPX file contains an additional magic1 and
        // magic2 headers, the lzma_params field contains the same parameter
        // set as in the "lzma alone" format, and the <data...> field is the
        // same as in the "lzma alone" format as well. Note that also the
        // zipx format is missing the uncompressed_size field.
        //
        // So, in order to use the "lzma alone" decoder for the zipx lzma
        // stream, we simply need to use the lzma_params, with an unknown
        // uncompressed size, and then we can start feeding normal zipx lzma
        // stream into the decoder.

        // Read magic1,magic2,lzma_params from the ZIPX stream. When the
        // compressed size is unknown (e.g. ZIP_LENGTH_AT_END read from a
        // non-seekable source), entry_bytes_remaining is 0 or negative
        // here. We can still attempt to read the 9-byte header; if the data
        // is truly truncated, the reads below will catch it.
        if self.entry_bytes_remaining > 0 && self.entry_bytes_remaining < 9 {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Truncated lzma data",
            ));
        }

        let p: Vec<u8> = if self.crypto.active() {
            self.crypto.read_header(r, 9)?
        } else {
            match r.read_ahead(9) {
                Ok(Some(p)) => p.get(..9).unwrap_or_default().to_vec(),
                _ => {
                    return Err(Error::fatal(
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        "Truncated lzma data",
                    ));
                }
            }
        };

        if p.get(2) != Some(&0x05) || p.get(3) != Some(&0x00) {
            return Err(Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Invalid lzma data"));
        }

        if self.uncompressed_buffer.is_empty() {
            self.alloc_buffer(BUFFER_SIZE, "No memory for lzma decompression")?;
        }

        // Initialize the decoder with the parameters. liblzma is given an
        // uncompressed size of unknown and we manually monitor how many
        // bytes there are still to be uncompressed. The decoder here holds
        // back the output of the last bytes of a stream without an end
        // marker until it is told where it ends, so it gets the size when
        // that is known.
        let size = if self.entry_bytes_remaining > 0 {
            u64::try_from(self.entry.uncompressed_size).unwrap_or(u64::MAX)
        } else {
            u64::MAX
        };
        let props = p.get(4).copied().unwrap_or(0);
        let dict_size = super::le32(&p, 5);
        let init_error =
            || Error::fatal(ARCHIVE_ERRNO_PROGRAMMER, "lzma stream initialization error");
        if props > (4 * 5 + 4) * 9 + 8 {
            return Err(init_error());
        }
        // The dictionary and the decoder's tables have to fit the limit.
        if u64::from(dict_size) + 32 * 1024 > r.decoder_memory(LZMA_MEMLIMIT) {
            return Err(Error::fatal(
                libc::ENOMEM,
                "lzma stream requires too much memory",
            ));
        }
        let stream = LzmaStream::new_with_props(size, props, dict_size.max(4096), None)
            .map_err(|_| init_error())?;
        self.zipx.lzma = Some(stream);
        self.zipx.lz_allow_buf_error = false;
        self.zipx.lzma_drain = false;
        self.zipx.lzma_sized = size != u64::MAX;

        // We've already consumed some bytes, so take this into account.
        r.consume(9)?;
        self.entry_compressed_bytes_read += 9;
        if self.entry_bytes_remaining > 0 {
            self.entry_bytes_remaining -= 9;
        }

        self.decompress_init = true;
        Ok(())
    }

    pub(super) fn read_lzma_alone(&mut self, r: &mut Reader<'_>) -> Result<Out, Error> {
        // Initialize decompressor if not yet initialized.
        if !self.decompress_init {
            self.lzma_alone_init(r)?;
        }

        // Fetch more compressed data. The same note as in deflate handler
        // applies here as well:
        //
        // Note: '1' here is a performance optimization. Recall that the
        // decompression layer returns a count of available bytes; asking for
        // more than that forces the decompressor to combine reads by
        // copying data.
        let comp = r
            .peek_available(1)
            .map_err(|_| Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated lzma file body"))?;
        let mut bytes_avail = comp.len();
        if self.zipx.lzma_drain {
            bytes_avail = 0;
        } else if self.entry_bytes_remaining > 0
            && i64::try_from(bytes_avail).map_or(true, |b| b > self.entry_bytes_remaining)
        {
            bytes_avail = usize::try_from(self.entry_bytes_remaining).unwrap_or(0);
        }

        let limit = self.limit();
        let input = self.crypto.prepare(comp, bytes_avail, limit);

        // These lzma_alone streams lack an end of stream marker in some
        // cases, so when the uncompressed size is known we cap avail_out to
        // make sure the unpacker won't try to unpack more than it's
        // supposed to. When the compressed size is unknown
        // (entry_bytes_remaining <= 0, e.g. ZIP_LENGTH_AT_END from a
        // non-seekable source) we must use the full buffer and rely on the
        // LZMA stream end marker to detect the end of the entry.
        let buffer_size = self.uncompressed_buffer.len();
        let cap = if self.entry_bytes_remaining <= 0 && !self.zipx.lzma_drain {
            buffer_size
        } else {
            let left = self.entry.uncompressed_size - self.entry_uncompressed_bytes_read;
            usize::try_from(left.max(0)).map_or(buffer_size, |l| l.min(buffer_size))
        };

        // Perform the decompression.
        let step = if cap == 0 {
            // Nothing more may be written: liblzma has no progress to make.
            Step {
                code: LZMA_BUF_ERROR,
                consumed: 0,
                produced: 0,
            }
        } else {
            let z = &mut self.zipx;
            let Some(stream) = z.lzma.as_mut() else {
                return Err(misc("lzma unknown error (10)".into()));
            };
            let out = self.uncompressed_buffer.get_mut(..cap).unwrap_or_default();
            let res = stream.process(input, out, Action::Run);
            let unused = stream.unused_input().len();
            let mut step = lz_step(res, unused, &mut z.lz_allow_buf_error);
            // liblzma doesn't look for the end marker once the output is
            // full, and the entry ends in the next call; the same goes for a
            // decoder that stops at the size it was given.
            if z.lzma_sized && step.code == LZMA_STREAM_END && step.produced > 0 {
                step.code = LZMA_OK;
            }
            step
        };
        match step.code {
            LZMA_DATA_ERROR => {
                return Err(misc(format!("lzma data error ({})", step.code)));
            }

            // This case is optional in lzma alone format. It can happen,
            // but most of the files don't have it. (GitHub #1257)
            LZMA_STREAM_END => {
                // This assertion is only possible if the size of the
                // compressed data stream is known.
                if step.consumed as i64 != self.entry_bytes_remaining
                    && self.entry_bytes_remaining > 0
                    && !self.zipx.lzma_sized
                {
                    return Err(misc("lzma alone premature end of stream".into()));
                }

                self.end_of_entry = true;
            }

            LZMA_OK => {}

            LZMA_BUF_ERROR if step.produced == cap => {
                // The output buffer was filled exactly. When the
                // uncompressed size is known this means we have
                // decompressed all expected bytes. When the size is unknown
                // a full buffer just means we need another iteration.
                if self.entry_bytes_remaining > 0 || self.zipx.lzma_drain {
                    self.end_of_entry = true;
                }
            }

            code => return Err(misc(format!("lzma unknown error ({code})"))),
        }

        let to_consume = step.consumed;

        // Update pointers.
        self.crypto.finish(to_consume, comp);
        r.consume(to_consume)?;
        self.entry_compressed_bytes_read += to_consume as i64;
        r.decoded(step.produced)?;
        self.entry_uncompressed_bytes_read += step.produced as i64;

        if self.zipx.lzma_drain {
            // The decoder may still hold output the input has already been
            // consumed for.
            if !self.zipx.lzma.as_ref().is_some_and(LzmaStream::has_output) {
                self.end_of_entry = true;
            }
        } else if self.entry_bytes_remaining > 0 {
            self.entry_bytes_remaining -= to_consume as i64;
            if self.entry_bytes_remaining == 0 && !self.end_of_entry {
                self.zipx.lzma_drain = true;
            }
        }

        while self.end_of_entry && self.entry_bytes_remaining > 0 {
            let Ok(Some(p)) = r.read_ahead(1) else {
                break;
            };
            let n = p
                .len()
                .min(usize::try_from(self.entry_bytes_remaining).unwrap_or(0));
            if self.crypto.hmac_valid
                && let Some(h) = &mut self.crypto.hmac
            {
                h.update(p.get(..n).unwrap_or_default());
            }
            r.consume(n)?;
            self.entry_compressed_bytes_read += n as i64;
            self.entry_bytes_remaining -= n as i64;
        }

        // Free lzma decoder handle because we'll no longer need it. This
        // cannot be folded into LZMA_STREAM_END handling above because the
        // stream end marker is not required in this format.
        if self.end_of_entry {
            self.zipx.lzma = None;

            if self.crypto.hmac_valid
                && let Some(out) = self.authenticate(r)?
            {
                return Ok(out);
            }
        }

        // If we're here, then we're good!
        Ok(Out::Buf(step.produced))
    }

    fn xz_init(&mut self, r: &Reader<'_>) -> Result<(), Error> {
        self.zipx.lzma = None;
        self.zipx.xz = Some(XzStream::new_mem_limit(
            false,
            u32::try_from(r.decoder_memory(u64::from(XZ_MEM_LIMIT_KIB) * 1024) / 1024)
                .unwrap_or(XZ_MEM_LIMIT_KIB),
        ));
        self.zipx.lz_allow_buf_error = false;
        self.alloc_buffer(BUFFER_SIZE, "No memory for xz decompression")?;
        self.decompress_init = true;
        Ok(())
    }

    pub(super) fn read_zipx_xz(&mut self, r: &mut Reader<'_>) -> Result<Out, Error> {
        // Initialize decompressor if not yet initialized.
        if !self.decompress_init {
            self.xz_init(r)?;
        }

        let truncated = || Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated xz file body");
        let comp = r.peek_available(1).map_err(|_| truncated())?;
        let bytes_avail = self.clip(comp.len()).ok_or_else(truncated)?;

        let limit = self.limit();
        let input = self.crypto.prepare(comp, bytes_avail, limit);

        // Perform the decompression.
        let z = &mut self.zipx;
        let Some(stream) = z.xz.as_mut() else {
            return Err(misc(format!("xz unknown error ({LZMA_BUF_ERROR})")));
        };
        let res = stream.process(input, &mut self.uncompressed_buffer, Action::Run);
        let step = lz_step(res, 0, &mut z.lz_allow_buf_error);
        match step.code {
            LZMA_DATA_ERROR => {
                return Err(misc(format!("xz data error ({})", step.code)));
            }

            LZMA_OK => {}

            LZMA_STREAM_END => {
                z.xz = None;

                // This assertion is only possible if the size of the
                // compressed data stream is known -> !ZIP_LENGTH_AT_END.
                if step.consumed as i64 != self.entry_bytes_remaining && !self.entry.length_at_end()
                {
                    return Err(misc("xz premature end of stream".into()));
                }

                self.end_of_entry = true;
            }

            code => return Err(misc(format!("xz unknown error ({code})"))),
        }

        let to_consume = step.consumed;

        self.crypto.finish(to_consume, comp);
        r.consume(to_consume)?;
        self.entry_bytes_remaining -= to_consume as i64;
        self.entry_compressed_bytes_read += to_consume as i64;
        r.decoded(step.produced)?;
        self.entry_uncompressed_bytes_read += step.produced as i64;

        if self.end_of_entry
            && self.crypto.hmac_valid
            && let Some(out) = self.authenticate(r)?
        {
            return Ok(out);
        }

        Ok(Out::Buf(step.produced))
    }

    fn ppmd8_init(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        // Remove previous decompression context if it exists, and create a
        // new one.
        self.zipx.ppmd8.free();
        self.zipx.ppmd8_stream_failed = false;

        // Reset number of read bytes to 0.
        self.zipx.ppmd_read_compressed = 0;

        // Read Ppmd8 header (2 bytes).
        let p: Vec<u8> = if self.crypto.active() {
            self.crypto.read_header(r, 2)?
        } else {
            match r.read_ahead(2) {
                Ok(Some(p)) => p.get(..2).unwrap_or_default().to_vec(),
                _ => {
                    return Err(Error::fatal(
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        "Truncated file data in PPMd8 stream",
                    ));
                }
            }
        };
        r.consume(2)?;

        // Decode the stream's compression parameters.
        let val = u32::from(super::le16(&p, 0));
        let order = (val & 15) + 1;
        let mem = ((val >> 4) & 0xff) + 1;
        let restore_method = val >> 12;

        if order < 2 || restore_method > 2 {
            return Err(Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_FILE_FORMAT,
                format!(
                    "Invalid parameter set in PPMd8 stream (order={order}, restore={restore_method})"
                ),
            ));
        }

        if u64::from(mem << 20) > r.decoder_memory(u64::MAX) {
            return Err(Error::fatal(
                libc::ENOMEM,
                "PPMd8 stream requires too much memory",
            ));
        }
        // Allocate the memory needed to properly decompress the file.
        if !self.zipx.ppmd8.alloc(mem << 20) {
            return Err(Error::fatal(
                libc::ENOMEM,
                format!(
                    "Unable to allocate memory for PPMd8 stream: {} bytes",
                    mem << 20
                ),
            ));
        }

        // Perform further Ppmd8 initialization.
        let z = &mut self.zipx;
        let ok = z.ppmd8.range_dec_init(&mut PpmdIn {
            r,
            crypto: &mut self.crypto,
            failed: &mut z.ppmd8_stream_failed,
            read: &mut z.ppmd_read_compressed,
        });
        if !ok {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_PROGRAMMER,
                "PPMd8 stream range decoder initialization error",
            ));
        }

        z.ppmd8.init(order, restore_method);

        // Allocate the buffer that will hold uncompressed data.
        self.alloc_buffer(BUFFER_SIZE, "No memory for PPMd8 decompression")?;

        // Ppmd8 initialization is done.
        self.decompress_init = true;

        // We've already read 2 bytes in the output stream. Additionally,
        // Ppmd8 initialization code could read some data as well. So we are
        // advancing the stream by 2 bytes plus whatever number of bytes
        // Ppmd8 init function used.
        self.entry_compressed_bytes_read += 2 + self.zipx.ppmd_read_compressed;

        Ok(())
    }

    pub(super) fn read_zipx_ppmd(&mut self, r: &mut Reader<'_>) -> Result<Out, Error> {
        // If we're here for the first time, initialize Ppmd8 decompression
        // context first.
        if !self.decompress_init {
            self.ppmd8_init(r)?;
        }

        // Fetch for more data. We're reading 1 byte here, but libarchive
        // should prefetch more bytes.
        if !matches!(r.read_ahead(1), Ok(Some(_))) {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Truncated PPMd8 file body",
            ));
        }

        // This counter will be updated by the byte source, which at one
        // point will be called by decode_symbol.
        self.zipx.ppmd_read_compressed = 0;

        // Decompression loop.
        let z = &mut self.zipx;
        let mut consumed_bytes = 0;
        while let Some(slot) = self.uncompressed_buffer.get_mut(consumed_bytes) {
            let sym = z.ppmd8.decode_symbol(&mut PpmdIn {
                r,
                crypto: &mut self.crypto,
                failed: &mut z.ppmd8_stream_failed,
                read: &mut z.ppmd_read_compressed,
            });
            if sym < 0 {
                self.end_of_entry = true;
                break;
            }

            // This field is set by the byte source when there was no more
            // data to be read.
            if z.ppmd8_stream_failed {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Truncated PPMd8 file body",
                ));
            }

            *slot = sym as u8;
            consumed_bytes += 1;
        }

        // Update pointers so we can continue decompression in another call.
        self.entry_bytes_remaining -= z.ppmd_read_compressed;
        self.entry_compressed_bytes_read += z.ppmd_read_compressed;
        r.decoded(consumed_bytes)?;
        self.entry_uncompressed_bytes_read += consumed_bytes as i64;

        // If we're at the end of stream, deinitialize Ppmd8 context.
        if self.end_of_entry {
            z.ppmd8.free();

            if self.crypto.hmac_valid
                && let Some(out) = self.authenticate(r)?
            {
                return Ok(out);
            }
        }

        // Update pointers for libarchive.
        Ok(Out::Buf(consumed_bytes))
    }

    pub(super) fn read_zipx_bzip2(&mut self, r: &mut Reader<'_>) -> Result<Out, Error> {
        // Initialize decompression context if we're here for the first
        // time.
        if !self.decompress_init {
            self.zipx.bzip2 = Some(Bzip2Decoder::new());
            // (Re)allocate the buffer that will contain decompressed bytes.
            self.alloc_buffer(BUFFER_SIZE, "No memory for bzip2 decompression")?;
            self.decompress_init = true;
        }
        let wanted = self.zipx.bzip2.as_ref().map_or(1, Bzip2Decoder::wanted);

        // Fetch more compressed bytes.
        let truncated = || Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated bzip2 file body");
        let comp = r.peek_available(wanted).map_err(|_| truncated())?;
        let bytes_avail = self
            .clip(comp.len())
            .filter(|&n| n >= 1)
            .ok_or_else(truncated)?;
        // The decoder takes as much as it wants at once, unless this is all
        // there is.
        let last = bytes_avail < wanted;

        if self.crypto.active() {
            self.crypto.ensure_buffer(wanted)?;
        }
        let limit = self.limit();
        let input = self.crypto.prepare(comp, bytes_avail, limit);

        // bzstream.avail_in is 32 bits wide, so clamp the available byte
        // count.
        let input = input
            .get(..input.len().min(u32::MAX as usize))
            .unwrap_or_default();
        let Some(dec) = self.zipx.bzip2.as_mut() else {
            return Err(misc("bzip2 decompression failed".into()));
        };

        // Perform the decompression.
        let Ok(progress) = dec.decompress(input, &mut self.uncompressed_buffer, last) else {
            return Err(misc("bzip2 decompression failed".into()));
        };
        if progress.end {
            // If we're at the end of the stream, deinitialize the
            // decompression context now.
            self.zipx.bzip2 = None;
            self.end_of_entry = true;
        }

        // Update the pointers so decompressor can continue decoding.
        let to_consume = progress.used;
        self.crypto.finish(to_consume, comp);
        r.consume(to_consume)?;

        self.entry_bytes_remaining -= to_consume as i64;
        self.entry_compressed_bytes_read += to_consume as i64;
        r.decoded(progress.produced)?;
        self.entry_uncompressed_bytes_read += progress.produced as i64;

        if self.end_of_entry
            && self.crypto.hmac_valid
            && let Some(out) = self.authenticate(r)?
        {
            return Ok(out);
        }

        // Give libarchive its due.
        Ok(Out::Buf(progress.produced))
    }

    pub(super) fn read_zipx_zstd(&mut self, r: &mut Reader<'_>) -> Result<Out, Error> {
        // Initialize decompression context if we're here for the first
        // time.
        if !self.decompress_init {
            let mut decoder = FrameDecoder::new();
            decoder.set_max_window_size(r.decoder_memory(ZSTD_MAX_WINDOW));
            self.zipx.zstd = Some(Zstd {
                decoder,
                in_frame: false,
            });
            // (Re)allocate the buffer that will contain decompressed bytes:
            // `ZSTD_DStreamOutSize()`.
            self.alloc_buffer(ZSTD_OUT_SIZE, "No memory for Zstd decompression")?;
            self.decompress_init = true;
        }

        // Fetch more compressed bytes. The decoder asks for input as it
        // needs it, and `ZipInput` hands out what is left of the entry.
        // The decoder reads whole blocks, which may be more than it gives
        // out at once, so the input may well have run out already.
        let has_output = self
            .zipx
            .zstd
            .as_ref()
            .is_some_and(|st| st.decoder.can_collect() > 0);
        if !has_output {
            let truncated = || Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated zstd file body");
            let avail = r.peek_available(1).map_err(|_| truncated())?.len();
            self.clip(avail).filter(|&n| n >= 1).ok_or_else(truncated)?;
        }

        let length_at_end = self.entry.length_at_end();
        let z = &mut self.zipx;
        let Some(st) = z.zstd.as_mut() else {
            return Err(misc(
                "Error during zstd decompression: Unknown error".into(),
            ));
        };
        let mut input = ZipInput {
            r,
            crypto: &mut self.crypto,
            remaining: &mut self.entry_bytes_remaining,
            read: &mut self.entry_compressed_bytes_read,
            unbounded: length_at_end,
            error: None,
            ended: false,
        };
        let size = self.uncompressed_buffer.len();
        let mut produced = 0;
        let mut frame_done = false;

        // Perform the decompression.
        'frames: while produced < size {
            if !st.in_frame {
                if let Err(e) = st.decoder.reset(&mut input) {
                    if let Some(error) = input.error.take() {
                        return Err(error);
                    }
                    if input.ended {
                        break 'frames;
                    }
                    return Err(zstd_failure(&e));
                }
                st.in_frame = true;
            }
            while st.decoder.can_collect() == 0 && !st.decoder.is_finished() {
                let strategy = BlockDecodingStrategy::UptoBytes(1);
                if let Err(e) = st.decoder.decode_blocks(&mut input, strategy) {
                    if let Some(error) = input.error.take() {
                        return Err(error);
                    }
                    if input.ended {
                        // The entry's data ends in the middle of the frame:
                        // the next call finds there is none left.
                        break 'frames;
                    }
                    return Err(zstd_failure(&e));
                }
            }
            let room = self
                .uncompressed_buffer
                .get_mut(produced..)
                .unwrap_or_default();
            match io::Read::read(&mut st.decoder, room) {
                Ok(n) => produced += n,
                Err(_) => return Err(zstd_message("Data corruption detected")),
            }
            if st.decoder.is_finished() && st.decoder.can_collect() == 0 {
                if let Some(stored) = st.decoder.get_checksum_from_data()
                    && st.decoder.get_calculated_checksum() != Some(stored)
                {
                    return Err(zstd_message("Restored data doesn't match checksum"));
                }
                st.in_frame = false;
                frame_done = true;
                break;
            }
        }

        // End of stream handling for zips with ZIP_LENGTH_AT_END flag, and
        // the end of the data: the frame is complete and the output buffer
        // is not full.
        if frame_done && (length_at_end || (*input.remaining == 0 && produced < size)) {
            self.end_of_entry = true;
            z.zstd = None;
        }

        r.decoded(produced)?;
        self.entry_uncompressed_bytes_read += produced as i64;

        if self.end_of_entry
            && self.crypto.hmac_valid
            && let Some(out) = self.authenticate(r)?
        {
            return Ok(out);
        }

        Ok(Out::Buf(produced))
    }
}

/// `ZSTD_DStreamOutSize()`.
const ZSTD_OUT_SIZE: usize = 128 * 1024;
/// libzstd's default window limit (`ZSTD_WINDOWLOG_LIMIT_DEFAULT`).
const ZSTD_MAX_WINDOW: u64 = 1 << 27;

/// The Zstandard decoder: ruzstd pulls the compressed bytes it needs.
struct Zstd {
    decoder: FrameDecoder,
    /// In the middle of a frame.
    in_frame: bool,
}

fn zstd_message(name: &str) -> Error {
    misc(format!("Error during zstd decompression: {name}"))
}

/// libzstd's name for an error of ruzstd's.
fn zstd_failure(e: &FrameDecoderError) -> Error {
    zstd_message(match e {
        FrameDecoderError::WindowSizeTooBig { .. } => "Frame requires too much memory for decoding",
        FrameDecoderError::DictNotProvided { .. } | FrameDecoderError::DictionaryDecodeError(_) => {
            "Dictionary mismatch"
        }
        FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::BadMagicNumber(_)) => {
            "Unknown frame descriptor"
        }
        _ => "Data corruption detected",
    })
}

/// The entry's compressed data, as the `Read` that ruzstd pulls from. It
/// decrypts and consumes what it hands out, and counts it. An `io::Error`
/// can't carry a failure of the stream, so the first one is kept here, and
/// the end of the entry's data is noted.
struct ZipInput<'a, 'b> {
    r: &'a mut Reader<'b>,
    crypto: &'a mut super::crypto::Crypto,
    /// `entry_bytes_remaining`.
    remaining: &'a mut i64,
    /// `entry_compressed_bytes_read`.
    read: &'a mut i64,
    /// The size of the compressed data is not known.
    unbounded: bool,
    error: Option<Error>,
    ended: bool,
}

impl io::Read for ZipInput<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let limit = if self.unbounded {
            usize::MAX
        } else {
            usize::try_from(*self.remaining).unwrap_or(0)
        };
        if limit == 0 {
            self.ended = true;
            return Ok(0);
        }
        let n = match self.r.read_ahead(1) {
            Ok(Some(data)) => {
                let n = data.len().min(buf.len()).min(limit);
                let out = buf.get_mut(..n).unwrap_or_default();
                self.crypto
                    .decrypt_into(data.get(..n).unwrap_or_default(), out);
                n
            }
            Ok(None) => {
                self.ended = true;
                return Ok(0);
            }
            Err(e) => {
                self.error = Some(e);
                return Err(io::Error::other("input failed"));
            }
        };
        if let Err(e) = self.r.consume(n) {
            self.error = Some(e);
            return Err(io::Error::other("input failed"));
        }
        *self.remaining -= n as i64;
        *self.read += n as i64;
        Ok(n)
    }
}

/// This is used by `Ppmd8_DecodeSymbol` during decompression of Ppmd8
/// streams inside ZIP files. It has 2 purposes: one is to fetch the next
/// compressed byte from the stream, second one is to increase the counter
/// how many compressed bytes were read.
struct PpmdIn<'a, 'b> {
    r: &'a mut Reader<'b>,
    crypto: &'a mut super::crypto::Crypto,
    failed: &'a mut bool,
    read: &'a mut i64,
}

impl ByteIn for PpmdIn<'_, '_> {
    fn read_byte(&mut self) -> u8 {
        // Fetch next byte.
        let Ok(Some(&[byte, ..])) = self.r.read_ahead(1) else {
            *self.failed = true;
            return 0;
        };
        let mut val = [byte];
        if self.crypto.active() {
            self.crypto.decrypt_into(&[byte], &mut val);
        }
        if self.r.consume(1).is_err() {
            *self.failed = true;
        }
        // Increment the counter.
        *self.read += 1;

        // Return the next compressed byte.
        val[0]
    }
}
