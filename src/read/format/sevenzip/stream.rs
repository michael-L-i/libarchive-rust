/*-
 * Copyright (c) 2011 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_read_support_format_7zip.c.

//! Reading the archive's streams: the header, then each folder's packed
//! streams decoded into the uncompressed buffer, and the central directory
//! (signature header) that points at them.
//!
//! `pack_stream_bytes_unconsumed` is how much of the input the last read
//! used; it is consumed at the start of the next one, so that what was
//! handed out stays valid until then.

use super::filters::bcj_lookahead;
use super::parse::{Fail, HeaderInfo, folder_uncompressed_size};
use super::sfx::{get_data_offset, seek_compat};
use super::*;
use crate::crc32::crc32;
use crate::read::Whence;

/// Where the bytes of a `Chunk` are.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Src {
    /// Nowhere: the end of the data.
    None,
    /// In the uncompressed buffer, from this offset.
    Buffer(usize),
    /// In the input, at the current position.
    Ahead,
}

/// Bytes `read_stream` handed out. They stay valid until the next read.
#[derive(Clone, Copy)]
pub(super) struct Chunk {
    src: Src,
    pub len: usize,
    /// How much of the input was asked for with `Src::Ahead`.
    reach: usize,
}

impl Chunk {
    const NONE: Chunk = Chunk {
        src: Src::None,
        len: 0,
        reach: 0,
    };
}

fn align_size(s: usize) -> usize {
    match s.checked_add(1023) {
        Some(r) => r & !0x3ff,
        None => s,
    }
}

impl SevenZip {
    /// The bytes of a chunk `read_stream` returned.
    pub(super) fn chunk_bytes<'x>(&'x self, r: &'x mut Reader<'_>, c: Chunk) -> &'x [u8] {
        self.chunk_reach(r, c).get(..c.len).unwrap_or_default()
    }

    /// The bytes of a chunk and, with `Src::Ahead`, up to what was asked for.
    fn chunk_reach<'x>(&'x self, r: &'x mut Reader<'_>, c: Chunk) -> &'x [u8] {
        match c.src {
            Src::None => &[],
            Src::Buffer(at) => self.ubuf.get(at..at + c.len).unwrap_or_default(),
            Src::Ahead => r.peek_available(c.reach.max(c.len)).unwrap_or_default(),
        }
    }

    /// `read_consume`.
    pub(super) fn read_consume(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        if self.pack_stream_bytes_unconsumed != 0 {
            r.consume(self.pack_stream_bytes_unconsumed)?;
            self.stream_offset += self.pack_stream_bytes_unconsumed as i64;
            self.pack_stream_bytes_unconsumed = 0;
        }
        Ok(())
    }

    /// `header_bytes`: `f` gets the next `n` bytes of the header; `None` if
    /// they can't be read.
    pub(super) fn header_with<T>(
        &mut self,
        r: &mut Reader<'_>,
        n: usize,
        f: impl FnOnce(&[u8]) -> T,
    ) -> Option<T> {
        if u64::try_from(self.header_bytes_remaining).ok()? < n as u64 {
            return None;
        }
        if self.pack_stream_bytes_unconsumed != 0 {
            let _ = self.read_consume(r);
        }

        let n_i64 = n as i64;
        if !self.header_is_encoded {
            let p = r.read_ahead(n).ok()??.get(..n)?;
            self.header_bytes_remaining -= n_i64;
            self.pack_stream_bytes_unconsumed = n;
            self.header_crc32 = crc32(self.header_crc32, p);
            Some(f(p))
        } else {
            let chunk = self.read_stream(r, n, n).ok()?;
            if chunk.len == 0 {
                return None;
            }
            self.header_bytes_remaining -= chunk.len as i64;
            let p = self.chunk_reach(r, chunk).get(..n)?;
            let crc = crc32(self.header_crc32, p);
            let out = f(p);
            self.header_crc32 = crc;
            Some(out)
        }
    }

    /// `slurp_central_directory`: reads the signature header and the
    /// header it points at. `Status::Eof` if the archive has no entries.
    pub(super) fn slurp_central_directory(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        let data_offset = get_data_offset(r, true)?;
        r.consume(data_offset)
            .map_err(|_| Error::fatal(ARCHIVE_ERRNO_MISC, "Seek error"))?;
        let Some((p, bytes_avail)) = r
            .read_ahead(32)
            .ok()
            .flatten()
            .and_then(|d| Some((<[u8; 32]>::try_from(d.get(..32)?).ok()?, d.len() as i64)))
        else {
            return Err(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Truncated 7-Zip file header",
            ));
        };

        let malformed = || Error::fatal(-1, "Malformed 7-Zip archive");
        self.seek_base = data_offset.checked_add(32).ok_or_else(malformed)?;

        if p[..6] != SIGNATURE[..] {
            return Err(Error::fatal(-1, "Not 7-Zip archive file"));
        }

        // CRC check.
        if crc32(0, &p[12..32]) != u32::from_le_bytes([p[8], p[9], p[10], p[11]]) {
            return Err(Error::fatal(-1, "Header CRC error"));
        }

        let next_header_offset = i64::from_le_bytes(p[12..20].try_into().map_err(|_| malformed())?);
        if next_header_offset < 0 {
            return Err(malformed());
        }
        let next_header_size = i64::from_le_bytes(p[20..28].try_into().map_err(|_| malformed())?);
        if next_header_size < 0 {
            return Err(malformed());
        }
        let mut next_header_crc = u32::from_le_bytes([p[28], p[29], p[30], p[31]]);

        if next_header_size == 0 {
            // There is no entry in the archive file.
            return Ok(Status::Eof);
        }

        let _ = r.consume(32usize);
        if next_header_offset != 0 {
            if bytes_avail >= next_header_offset {
                let _ = r.consume(next_header_offset);
            } else {
                let target = self.seek_base.checked_add(next_header_offset);
                if target.is_none_or(|t| seek_compat(r, t, Whence::Set, true).is_err()) {
                    return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Seek error"));
                }
            }
        }
        self.stream_offset = next_header_offset;
        self.header_offset = next_header_offset;
        self.header_bytes_remaining = next_header_size;
        self.header_crc32 = 0;
        self.header_is_encoded = false;
        self.header_is_being_read = true;
        self.has_encrypted_entries = 0;
        let mut check_header_crc = true;

        let Some(id) = self.header_with(r, 1, |p| p.first().copied()).flatten() else {
            return Err(truncated_body_header());
        };
        // Parse ArchiveProperties.
        match id {
            K_ENCODED_HEADER => {
                // The archive has an encoded header and we have to decode it
                // in order to parse the header correctly.
                let mut res = self.decode_encoded_header_info(r);

                // Check the EncodedHeader CRC.
                if res.is_ok() && self.header_crc32 != next_header_crc {
                    res = Err(Error::fatal(-1, "Damaged 7-Zip archive"));
                }
                if res.is_ok() {
                    match self.si.folders.first() {
                        Some(f) if f.digest_defined => next_header_crc = f.digest,
                        _ => check_header_crc = false,
                    }
                    if self.pack_stream_bytes_unconsumed != 0 {
                        let _ = self.read_consume(r);
                    }
                    if let Some(folder) = self.si.folders.first().cloned() {
                        res = self.setup_decode_folder(r, &folder, true);
                    }
                    if res.is_ok() {
                        self.header_bytes_remaining = self.folder_outbytes_remaining;
                        res = self.seek_pack(r);
                    }
                }
                // Clean up StreamsInfo.
                self.si = StreamInfo::default();
                // An error of upstream's is fatal here, however it failed.
                res.map_err(|mut e| {
                    e.code = ARCHIVE_FATAL;
                    e
                })?;
                self.header_is_encoded = true;
                self.header_crc32 = 0;
            }
            K_HEADER => {}
            id => {
                return Err(Error::fatal(-1, format!("Unexpected Property ID = {id:X}")));
            }
        }

        // Parse the header.
        let mut header = HeaderInfo::default();
        if let Err(f) = self.read_header_info(r, &mut header, self.header_is_encoded) {
            return Err(match f {
                Fail::NoMem => Error::fatal(-1, "Couldn't allocate memory"),
                Fail::Bad => Error::fatal(-1, "Damaged 7-Zip archive"),
            });
        }

        // Must be kEnd.
        if self.header_with(r, 1, |p| p.first().copied()).flatten() != Some(K_END) {
            return Err(Error::fatal(-1, "Malformed 7-Zip archive"));
        }

        // Check the Header CRC.
        if check_header_crc && self.header_crc32 != next_header_crc {
            return Err(Error::fatal(-1, "Malformed 7-Zip archive"));
        }

        // Clean up variables be used for decoding the archive header.
        self.pack_stream_remaining = 0;
        self.pack_stream_index = 0;
        self.folder_outbytes_remaining = 0;
        self.ubuf_bytes_remaining = 0;
        self.pack_stream_bytes_unconsumed = 0;
        self.header_is_being_read = false;

        Ok(Status::Ok)
    }

    /// `get_uncompressed_data`.
    fn get_uncompressed_data(
        &mut self,
        r: &mut Reader<'_>,
        size: usize,
        minimum: usize,
    ) -> Result<Chunk, Error> {
        let bytes_avail;
        let chunk;
        if self.codec == CODEC_COPY && self.codec2 == -1 {
            // Copy mode.
            let truncated = || Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated 7-Zip file data");
            let avail = r
                .read_ahead(minimum)
                .ok()
                .flatten()
                .ok_or_else(truncated)?
                .len();
            bytes_avail = avail.min(self.ubuf_bytes_remaining).min(size);
            self.pack_stream_bytes_unconsumed = bytes_avail;
            chunk = Chunk {
                src: Src::Ahead,
                len: bytes_avail,
                reach: minimum,
            };
        } else if self.ubuf_pointer.is_none() {
            // Decompression has failed.
            return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Damaged 7-Zip archive"));
        } else {
            // Packed mode.
            if minimum > self.ubuf_bytes_remaining {
                // If remaining uncompressed data size is less than the
                // minimum size, fill the buffer up to the minimum size.
                self.extract_pack_stream(r, minimum)?;
            }
            bytes_avail = size.min(self.ubuf_bytes_remaining);
            let at = self.ubuf_pointer.ok_or_else(damaged)?;
            chunk = Chunk {
                src: Src::Buffer(at),
                len: bytes_avail,
                reach: bytes_avail,
            };
            self.ubuf_pointer = Some(at + bytes_avail);
        }
        self.ubuf_bytes_remaining -= bytes_avail;
        Ok(chunk)
    }

    /// `extract_pack_stream`: decodes more of the current folder into the
    /// uncompressed buffer, until it has at least `minimum` bytes.
    fn extract_pack_stream(&mut self, r: &mut Reader<'_>, mut minimum: usize) -> Result<(), Error> {
        if self.codec == CODEC_COPY && self.codec2 == -1 {
            if minimum == 0 {
                minimum = 1;
            }
            let avail = match r.read_ahead(minimum) {
                Ok(Some(d)) if !d.is_empty() => d.len() as i64,
                _ => return Err(truncated_body()),
            };
            let mut bytes_avail = avail.min(self.pack_stream_inbytes_remaining);
            self.pack_stream_inbytes_remaining -= bytes_avail;
            bytes_avail = bytes_avail.min(self.folder_outbytes_remaining);
            self.folder_outbytes_remaining -= bytes_avail;
            self.ubuf_bytes_remaining = bytes_avail as usize;
            return Ok(());
        }

        // If the buffer hasn't been allocated, allocate it now.
        if self.ubuf.is_empty() {
            let mut new_size = UBUFF_SIZE;
            if new_size < minimum {
                new_size = align_size(minimum);
            }
            self.grow_ubuf(new_size)?;
            self.ubuf_bytes_remaining = 0;
        } else if self.ubuf.len() < minimum || self.ubuf_bytes_remaining < minimum {
            // Make sure the uncompressed buffer can have bytes at least
            // `minimum' bytes.
            // NOTE: This case happen when reading the header.
            let used = self.ubuf_pointer.unwrap_or(0);
            if self.ubuf.len() < minimum {
                // Expand the uncompressed buffer up to the minimum size.
                self.grow_ubuf(align_size(minimum))?;
            }
            // Move unconsumed bytes to the head.
            if used != 0 {
                if used + self.ubuf_bytes_remaining > self.ubuf.len() {
                    return Err(damaged());
                }
                self.ubuf
                    .copy_within(used..used + self.ubuf_bytes_remaining, 0);
            }
        } else {
            self.ubuf_bytes_remaining = 0;
        }
        self.ubuf_pointer = None;
        loop {
            // Note: '1' here is a performance optimization. Recall that the
            // decompression layer returns a count of available bytes; asking
            // for more than that forces the decompressor to combine reads by
            // copying data.
            let wanted = self.coders.wanted_input();
            let bytes_avail = match r.peek_available(wanted) {
                Ok(d) => d.len(),
                Err(_) => 0,
            };
            if bytes_avail == 0 {
                return Err(truncated_body());
            }

            let size = self.ubuf.len();
            let out_start = self.ubuf_bytes_remaining;
            let bytes_in = usize::try_from(self.pack_stream_inbytes_remaining)
                .map_or(bytes_avail, |m| bytes_avail.min(m));
            // Drive decompression.
            let mut buf = std::mem::take(&mut self.ubuf);
            let res = self.decompress(r, buf.get_mut(out_start..).unwrap_or_default(), bytes_in);
            self.ubuf = buf;
            let (bytes_in, mut bytes_out, end_of_data) = res.map_err(|mut e| {
                e.code = ARCHIVE_FATAL;
                e
            })?;
            self.pack_stream_inbytes_remaining -= bytes_in as i64;
            if bytes_out as u64 > self.folder_outbytes_remaining as u64 {
                bytes_out = self.folder_outbytes_remaining as usize;
            }
            self.folder_outbytes_remaining -= bytes_out as i64;
            self.ubuf_bytes_remaining += bytes_out;
            self.pack_stream_bytes_unconsumed = bytes_in;

            // Continue decompression until uncompressed_buffer is full.
            if self.ubuf_bytes_remaining == size {
                break;
            }
            if self.filters.odd_bcj_size != 0
                && self.ubuf_bytes_remaining + bcj_lookahead(self.codec2) > size
            {
                break;
            }
            if self.pack_stream_inbytes_remaining == 0 && self.folder_outbytes_remaining == 0 {
                break;
            }
            if end_of_data || (bytes_in == 0 && bytes_out == 0) {
                return Err(damaged());
            }
            let _ = self.read_consume(r);
        }
        if self.ubuf_bytes_remaining < minimum {
            return Err(damaged());
        }
        self.ubuf_pointer = Some(0);
        Ok(())
    }

    /// Makes the uncompressed buffer `new_size` bytes.
    fn grow_ubuf(&mut self, new_size: usize) -> Result<(), Error> {
        let extra = new_size.saturating_sub(self.ubuf.len());
        self.ubuf
            .try_reserve_exact(extra)
            .map_err(|_| Error::fatal(libc::ENOMEM, "No memory for 7-Zip decompression"))?;
        self.ubuf.resize(new_size, 0);
        Ok(())
    }

    /// `seek_pack`: moves to the next packed stream.
    pub(super) fn seek_pack(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        if self.pack_stream_remaining == 0 {
            return Err(damaged());
        }
        let pi = &self.si.pi;
        let (Some(&size), Some(&pack_offset)) = (
            pi.sizes.get(self.pack_stream_index),
            pi.positions.get(self.pack_stream_index),
        ) else {
            return Err(damaged());
        };
        self.pack_stream_inbytes_remaining = size;
        if self.stream_offset != pack_offset {
            let target = self.seek_base.checked_add(pack_offset);
            if target.is_none_or(|t| seek_compat(r, t, Whence::Set, true).is_err()) {
                return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Seek error"));
            }
            self.stream_offset = pack_offset;
        }
        self.pack_stream_index += 1;
        self.pack_stream_remaining -= 1;
        Ok(())
    }

    /// `read_stream`: up to `size` bytes (at least `minimum`) of the
    /// decoded data; an empty chunk when every folder has been consumed.
    pub(super) fn read_stream(
        &mut self,
        r: &mut Reader<'_>,
        size: usize,
        minimum: usize,
    ) -> Result<Chunk, Error> {
        let mut skip_bytes = 0i64;

        if self.ubuf_bytes_remaining == 0 {
            if self.pack_stream_inbytes_remaining > 0 || self.folder_outbytes_remaining > 0 {
                // Extract a remaining pack stream.
                self.extract_pack_stream(r, 0)?;
                return self.get_uncompressed_data(r, size, minimum);
            }
        } else {
            return self.get_uncompressed_data(r, size, minimum);
        }

        // Current pack stream has been consumed.
        if self.pack_stream_remaining == 0 {
            if self.header_is_being_read {
                // Invalid sequence. This might happen when reading a
                // malformed archive.
                return Err(Error::fatal(ARCHIVE_ERRNO_MISC, "Malformed 7-Zip archive"));
            }

            // All current folder's pack streams have been consumed. Switch
            // to next folder.
            let entry_folder = self.current_entry_folder()?;
            if self.folder_index == 0
                && (self
                    .si
                    .folders
                    .get(entry_folder)
                    .is_some_and(|f| f.skipped_bytes != 0)
                    || self.folder_index != entry_folder)
            {
                self.folder_index = entry_folder;
                skip_bytes = self
                    .si
                    .folders
                    .get(entry_folder)
                    .map_or(0, |f| f.skipped_bytes);
            }

            let Some(folder) = self.si.folders.get(self.folder_index).cloned() else {
                // We have consumed all folders and its pack streams.
                return Ok(Chunk::NONE);
            };
            self.setup_decode_folder(r, &folder, false)?;

            self.folder_index += 1;
        }

        // Switch to next pack stream.
        self.seek_pack(r)?;

        // Extract a new pack stream.
        self.extract_pack_stream(r, 0)?;

        // Skip the bytes we already have skipped in skip_stream().
        loop {
            if self.ubuf_bytes_remaining == 0 {
                if self.pack_stream_inbytes_remaining > 0 || self.folder_outbytes_remaining > 0 {
                    // Extract a remaining pack stream.
                    self.extract_pack_stream(r, 0)?;
                } else {
                    return Err(truncated_body());
                }
            }

            if skip_bytes == 0 {
                break;
            }

            let request = usize::try_from(skip_bytes).map_or(MAX_READ, |s| s.min(MAX_READ));
            let skipped = self.get_uncompressed_data(r, request, 0)?;
            skip_bytes -= skipped.len as i64;
            if self.pack_stream_bytes_unconsumed != 0 {
                let _ = self.read_consume(r);
            }
        }

        self.get_uncompressed_data(r, size, minimum)
    }

    /// The folder of the entry being read.
    fn current_entry_folder(&self) -> Result<usize, Error> {
        self.entries
            .as_ref()
            .and_then(|e| e.get(self.entry))
            .and_then(|e| e.folder_index)
            .ok_or_else(damaged)
    }

    /// `setup_decode_folder`.
    pub(super) fn setup_decode_folder(
        &mut self,
        r: &mut Reader<'_>,
        folder: &Folder,
        header: bool,
    ) -> Result<(), Error> {
        let cname = if header {
            "archive header"
        } else {
            "file content"
        };
        let mut found_bcj2 = 0;

        // Release the memory which the previous folder used for BCJ2.
        self.bcj2.set_streams([Vec::new(), Vec::new(), Vec::new()]);

        // Check coder types before modifying any stream-reader state, so
        // that an early return leaves zip unchanged (avoids
        // partially-initialized state that callers would have to reason
        // about).
        for c in &folder.coders {
            if is_crypto(c.codec) {
                // For entry that is associated with this folder, mark it as
                // encrypted (data+metadata).
                self.has_encrypted_entries = 1;
                if self.in_read_header {
                    self.entry_encrypted = true;
                }
                return Err(Error::new(
                    if header {
                        ARCHIVE_FATAL
                    } else {
                        ARCHIVE_FAILED
                    },
                    ARCHIVE_ERRNO_MISC,
                    format!("The {cname} is encrypted, but currently not supported"),
                ));
            }
            if c.codec == CODEC_X86_BCJ2 {
                found_bcj2 += 1;
            }
        }
        // Now that we've checked for encryption, if there were still no
        // encrypted entries found we can say for sure that there are none.
        if self.has_encrypted_entries == ENCRYPTION_DONT_KNOW {
            self.has_encrypted_entries = 0;
        }

        if (folder.coders.len() > 2 && found_bcj2 == 0) || found_bcj2 > 1 {
            return Err(Error::new(
                if header {
                    ARCHIVE_FATAL
                } else {
                    ARCHIVE_FAILED
                },
                ARCHIVE_ERRNO_MISC,
                format!("The {cname} is encoded with many filters, but currently not supported"),
            ));
        }

        // Initialize a stream reader.
        self.pack_stream_remaining = folder.num_packed_streams;
        self.pack_stream_index = folder.pack_index;
        self.folder_outbytes_remaining = folder_uncompressed_size(folder);
        self.ubuf_bytes_remaining = 0;
        let mut coder1 = folder.coders.first().cloned().unwrap_or_default();
        let mut coder2 = (folder.coders.len() == 2)
            .then(|| folder.coders.get(1).cloned())
            .flatten();

        if found_bcj2 != 0 {
            (coder1, coder2) = self.setup_bcj2(r, folder, coder1, coder2)?;
        }

        // Initialize the decompressor for the new folder's pack streams.
        self.init_decompression(&coder1, coder2.as_ref())
            .map_err(|mut e| {
                e.code = ARCHIVE_FATAL;
                e
            })
    }

    /// The BCJ2 part of `setup_decode_folder`. Decoding BCJ2 requires four
    /// sources. Those are at least, as far as I know, two types of the
    /// storage form. Returns the coders for the main stream.
    fn setup_bcj2(
        &mut self,
        r: &mut Reader<'_>,
        folder: &Folder,
        mut coder1: Coder,
        mut coder2: Option<Coder>,
    ) -> Result<(Coder, Option<Coder>), Error> {
        let fc = &folder.coders;
        let coder_copy = Coder {
            num_in_streams: 1,
            num_out_streams: 1,
            ..Coder::default()
        };
        let mut scoder = [coder_copy.clone(), coder_copy.clone(), coder_copy];
        let mut sunpack = [-1i64; 3];
        let mut idx = [0usize, 1, 2];
        let unsupported = || Error::fatal(ARCHIVE_ERRNO_MISC, "Unsupported form of BCJ2 streams");

        let remaining;
        if fc.len() == 4
            && fc.get(3).is_some_and(|c| c.codec == CODEC_X86_BCJ2)
            && folder.num_in_streams == 7
            && folder.num_out_streams == 4
            && self.pack_stream_remaining == 4
        {
            // Source type 1 made by 7zr or 7z with -m options.
            if folder
                .bind_pairs
                .first()
                .is_some_and(|&(in_index, _)| in_index == 5)
            {
                // The form made by 7zr.
                idx = [1, 2, 0];
                scoder[1] = fc[1].clone();
                scoder[2] = fc[0].clone();
                sunpack[1] = folder.unpack_size[1];
                sunpack[2] = folder.unpack_size[0];
                coder1 = fc[2].clone();
            } else {
                // NOTE: Some patterns do not work.
                // work:
                //  7z a -m0=BCJ2 -m1=COPY -m2=COPY
                //       -m3=(any)
                //  7z a -m0=BCJ2 -m1=COPY -m2=(any)
                //       -m3=COPY
                //  7z a -m0=BCJ2 -m1=(any) -m2=COPY
                //       -m3=COPY
                // not work:
                //  other patterns.
                //
                // We have to handle this like `pipe' or
                // our libarchive7s filter frame work,
                // decoding the BCJ2 main stream sequentially,
                // m3 -> m2 -> m1 -> BCJ2.
                if fc[0].codec == CODEC_COPY && fc[1].codec == CODEC_COPY {
                    coder1 = fc[2].clone();
                } else if fc[0].codec == CODEC_COPY && fc[2].codec == CODEC_COPY {
                    coder1 = fc[1].clone();
                } else if fc[1].codec == CODEC_COPY && fc[2].codec == CODEC_COPY {
                    coder1 = fc[0].clone();
                } else {
                    return Err(unsupported());
                }
            }
            coder2 = Some(fc[3].clone());
            remaining = folder.unpack_size[2];
        } else if coder2.as_ref().is_some_and(|c| c.codec == CODEC_X86_BCJ2)
            && self.pack_stream_remaining == 4
            && folder.num_in_streams == 5
            && folder.num_out_streams == 2
        {
            // Source type 0 made by 7z.
            remaining = folder.unpack_size[0];
        } else {
            // We got an unexpected form.
            return Err(unsupported());
        }
        self.main_stream_bytes_remaining = remaining;

        // Skip the main stream at this time.
        self.seek_pack(r)?;
        self.pack_stream_bytes_unconsumed =
            usize::try_from(self.pack_stream_inbytes_remaining).map_err(|_| damaged())?;
        self.read_consume(r)?;

        // Read following three sub streams.
        let mut b: [Vec<u8>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        for i in 0..3 {
            self.seek_pack(r)?;

            self.folder_outbytes_remaining = if sunpack[i] == -1 {
                self.pack_stream_inbytes_remaining
            } else {
                sunpack[i]
            };

            self.init_decompression(&scoder[i], None).map_err(|mut e| {
                e.code = ARCHIVE_FATAL;
                e
            })?;

            // Extract a sub stream. The decoded size is the stream's own,
            // whatever the header claims, so the buffer grows with the data.
            // Decoders that take all the input before they have output all
            // of it (liblzma leaves input behind) are asked for the rest.
            while self.pack_stream_inbytes_remaining > 0
                || (self.folder_outbytes_remaining > 0 && self.coders.pending_output())
            {
                self.extract_pack_stream(r, 0)?;
                let n = self.ubuf_bytes_remaining;
                let chunk = self.get_uncompressed_data(r, n, 0)?;
                let bytes = self.chunk_bytes(r, chunk);
                b[i].try_reserve(bytes.len())
                    .map_err(|_| Error::fatal(libc::ENOMEM, "No memory for 7-Zip decompression"))?;
                b[i].extend_from_slice(bytes);
                let progress = !bytes.is_empty();
                if self.pack_stream_bytes_unconsumed != 0 {
                    let _ = self.read_consume(r);
                }
                if !progress && self.pack_stream_inbytes_remaining <= 0 {
                    break;
                }
            }
        }

        // Set the sub streams to the right place.
        let [b0, b1, b2] = b;
        let mut b = [Some(b0), Some(b1), Some(b2)];
        self.bcj2
            .set_streams(idx.map(|i| b[i].take().unwrap_or_default()));

        // Allocate memory used for decoded main stream bytes.
        if self.bcj2.tmp.is_empty() {
            let mut tmp = Vec::new();
            tmp.try_reserve_exact(32 * 1024)
                .map_err(|_| Error::fatal(libc::ENOMEM, "No memory for 7-Zip decompression"))?;
            tmp.resize(32 * 1024, 0);
            self.bcj2.tmp = tmp;
        }
        self.bcj2.start();
        self.filters.odd_bcj_size = 0;

        // Reset a stream reader in order to read the main stream of BCJ2.
        self.pack_stream_remaining = 1;
        self.pack_stream_index = folder.pack_index;
        self.folder_outbytes_remaining = folder_uncompressed_size(folder);
        self.ubuf_bytes_remaining = 0;
        Ok((coder1, coder2))
    }

    /// `skip_stream`.
    pub(super) fn skip_stream(&mut self, r: &mut Reader<'_>, skip_bytes: i64) -> Result<(), Error> {
        if self.folder_index == 0 {
            // Optimization for a list mode. Avoid unnecessary decoding
            // operations.
            let folder = self.current_entry_folder()?;
            let v = self.si.folders.get_mut(folder).ok_or_else(damaged)?;
            v.skipped_bytes = v
                .skipped_bytes
                .checked_add(skip_bytes)
                .ok_or_else(|| Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Too many bytes to skip"))?;
            return Ok(());
        }

        let mut bytes = skip_bytes;
        while bytes != 0 {
            let request = usize::try_from(bytes).map_or(MAX_READ, |b| b.min(MAX_READ));

            let skipped = self.read_stream(r, request, 0)?;
            if skipped.len == 0 {
                return Err(truncated_body());
            }
            bytes -= skipped.len as i64;
            if self.pack_stream_bytes_unconsumed != 0 {
                let _ = self.read_consume(r);
            }
        }
        Ok(())
    }
}

fn truncated_body_header() -> Error {
    Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated 7-Zip file body")
}
