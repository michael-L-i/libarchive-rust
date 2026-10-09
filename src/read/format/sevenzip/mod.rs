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

//! The 7-Zip format (`.7z`), including SFX archives, encoded headers and
//! the COPY, LZMA, LZMA2, DEFLATE, BZIP2, PPMd and ZSTD coders with the BCJ,
//! BCJ2 and Delta filters. A Rust identifier can't start with a digit, so
//! the module is `sevenzip`, matching `format_code::SEVENZIP`.
//!
//! The reader works as upstream does: the header is parsed once, with
//! `header_bytes` reading either the file or the decoded (encoded) header;
//! each folder is then decoded a buffer at a time from its packed streams.

mod codec;
mod filters;
mod parse;
mod sfx;
mod stream;

use crate::archive::*;
use crate::entry::{AE_IFDIR, AE_IFLNK, AE_IFMT, AE_IFREG, Entry, Mode};
use crate::read::{
    ARCHIVE_ERRNO_FILE_FORMAT, CAPS_ENCRYPT, Data, ENCRYPTION_DONT_KNOW, Format, Read, Reader,
    Status, format_code,
};
use crate::string::{StringConv, conversion_charset_name, conversion_from_charset};
use crate::util::Error;
use codec::Coders;
use filters::{Bcj2, Filters};
use std::ffi::c_int;
use std::sync::{Arc, PoisonError};

const SIGNATURE: &[u8; 6] = b"7z\xBC\xAF\x27\x1C";

/// Codec IDs.
const CODEC_COPY: i64 = 0;
const CODEC_LZMA: i64 = 0x030101;
const CODEC_LZMA2: i64 = 0x21;
const CODEC_DEFLATE: i64 = 0x040108;
const CODEC_BZ2: i64 = 0x040202;
const CODEC_PPMD: i64 = 0x030401;
const CODEC_DELTA: i64 = 0x03;
/// Main Zip crypto algo.
const CODEC_CRYPTO_MAIN_ZIP: i64 = 0x06F10101;
/// Rar29 AES-128 + (modified SHA-1).
const CODEC_CRYPTO_RAR_29: i64 = 0x06F10303;
/// AES-256 + SHA-256.
const CODEC_CRYPTO_AES_256_SHA_256: i64 = 0x06F10701;
const CODEC_X86: i64 = 0x03030103;
const CODEC_X86_BCJ2: i64 = 0x0303011B;
const CODEC_POWERPC: i64 = 0x03030205;
const CODEC_IA64: i64 = 0x03030401;
const CODEC_ARM: i64 = 0x03030501;
const CODEC_ARMTHUMB: i64 = 0x03030701;
const CODEC_ARM64: i64 = 0xa;
const CODEC_RISCV: i64 = 0xb;
const CODEC_SPARC: i64 = 0x03030805;
/// Copied from https://github.com/mcmilk/7-Zip-zstd.git
const CODEC_ZSTD: i64 = 0x4F71101;

fn is_crypto(codec: i64) -> bool {
    matches!(
        codec,
        CODEC_CRYPTO_MAIN_ZIP | CODEC_CRYPTO_RAR_29 | CODEC_CRYPTO_AES_256_SHA_256
    )
}

// 7-Zip header property IDs.
const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_ARCHIVE_PROPERTIES: u8 = 0x02;
const K_MAIN_STREAMS_INFO: u8 = 0x04;
const K_FILES_INFO: u8 = 0x05;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SUBSTREAMS_INFO: u8 = 0x08;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_NUM_UNPACK_STREAM: u8 = 0x0D;
const K_EMPTY_STREAM: u8 = 0x0E;
const K_EMPTY_FILE: u8 = 0x0F;
const K_ANTI: u8 = 0x10;
const K_NAME: u8 = 0x11;
const K_CTIME: u8 = 0x12;
const K_ATIME: u8 = 0x13;
const K_MTIME: u8 = 0x14;
const K_ATTRIBUTES: u8 = 0x15;
const K_ENCODED_HEADER: u8 = 0x17;
const K_DUMMY: u8 = 0x19;

// Windows file attribute constants.
// Reference: https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
const FILE_ATTRIBUTE_READONLY: u32 = 0x00000001;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x00000002;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x00000004;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;

// This value is defined in 7zip with the comment "trick for Unix".
//
// 7z archives created on unix have this bit set in the high 16 bits of
// the attr field along with the unix permissions.
const FILE_ATTRIBUTE_UNIX_EXTENSION: u32 = 0x8000;

/// Maximum entry size. This limitation prevents reading intentional
/// corrupted 7-zip files on assuming there are not so many entries in
/// the files.
const UMAX_ENTRY: i64 = 100_000_000;

/// Don't try to read more than 16 MB at a time.
const MAX_READ: usize = 16 * 1024 * 1024;

/// Uncompressed buffer size.
const UBUFF_SIZE: usize = 64 * 1024;

#[derive(Clone, Default)]
struct Digests {
    defineds: Vec<bool>,
    digests: Vec<u32>,
}

#[derive(Clone, Default)]
struct Coder {
    codec: i64,
    num_in_streams: usize,
    num_out_streams: usize,
    properties: Vec<u8>,
}

#[derive(Clone, Default)]
struct Folder {
    coders: Vec<Coder>,
    /// `(inIndex, outIndex)`.
    bind_pairs: Vec<(usize, usize)>,
    num_packed_streams: usize,
    num_in_streams: usize,
    num_out_streams: usize,
    unpack_size: Vec<i64>,
    digest_defined: bool,
    digest: u32,
    num_unpack_streams: usize,
    pack_index: usize,
    /// Unoperated bytes.
    skipped_bytes: i64,
}

#[derive(Default)]
struct PackInfo {
    pos: i64,
    num_pack_streams: usize,
    sizes: Vec<i64>,
    digest: Digests,
    /// Calculated from pos and the sizes.
    positions: Vec<i64>,
}

#[derive(Default)]
struct SubStreamInfo {
    unpack_streams: usize,
    unpack_sizes: Vec<i64>,
    digests_defined: Vec<bool>,
    digests: Vec<u32>,
}

#[derive(Default)]
struct StreamInfo {
    pi: PackInfo,
    folders: Vec<Folder>,
    ss: SubStreamInfo,
}

const MTIME_IS_SET: u8 = 1 << 0;
const ATIME_IS_SET: u8 = 1 << 1;
const CTIME_IS_SET: u8 = 1 << 2;
const CRC32_IS_SET: u8 = 1 << 3;
const HAS_STREAM: u8 = 1 << 4;

#[derive(Clone, Default)]
struct ZEntry {
    /// The UTF-16LE name in `entry_names`, up to its terminator.
    name_off: usize,
    name_len: usize,
    folder_index: Option<usize>,
    ss_index: Option<usize>,
    flg: u8,
    mtime: (i64, u32),
    atime: (i64, u32),
    ctime: (i64, u32),
    mode: u32,
    attr: u32,
}

#[derive(Default)]
struct SevenZip {
    /// Structural information about the archive.
    si: StreamInfo,

    header_is_being_read: bool,
    header_is_encoded: bool,
    header_bytes_remaining: i64,
    header_crc32: u32,
    /// Header offset to check that reading points of the file contents
    /// will not exceed the header.
    header_offset: i64,
    /// Base offset of the archive file for a seek in case reading SFX.
    seek_base: i64,

    /// List of entries; `None` until the header has been read.
    entries_remaining: usize,
    num_files: usize,
    entries: Option<Vec<ZEntry>>,
    entry: usize,
    /// The UTF-16LE names; `None` if the header has no kName.
    entry_names: Option<Vec<u8>>,

    /// entry_bytes_remaining is the number of bytes we expect.
    entry_offset: i64,
    entry_bytes_remaining: i64,

    /// Running CRC32 of the decompressed data.
    entry_crc32: u32,

    /// Flags to mark progress of decompression.
    end_of_entry: bool,
    /// The warning for a bad CRC, to deliver after the entry's last block.
    crc_warning: Option<Vec<u8>>,

    /// Uncompressed buffer control: `ubuf` is the buffer, `ubuf_pointer` the
    /// start of the unread bytes (`None` when decompression has failed or
    /// not started) and `ubuf_bytes_remaining` their number.
    ubuf: Vec<u8>,
    ubuf_pointer: Option<usize>,
    ubuf_bytes_remaining: usize,

    /// Offset of the compressed data.
    stream_offset: i64,

    // Decompressing control data.
    folder_index: usize,
    folder_outbytes_remaining: i64,
    pack_stream_index: usize,
    pack_stream_remaining: usize,
    pack_stream_inbytes_remaining: i64,
    pack_stream_bytes_unconsumed: usize,

    /// The codec information of a folder.
    codec: i64,
    codec2: i64,

    /// Decompressor controllers.
    coders: Coders,
    /// Decoding BCJ and Delta data.
    filters: Filters,
    /// Decoding BCJ2 data.
    bcj2: Bcj2,
    main_stream_bytes_remaining: i64,

    /// Filename character-set conversion data.
    sconv: Option<Arc<StringConv>>,

    /// Custom value that is non-zero if this archive contains encrypted entries.
    has_encrypted_entries: c_int,

    /// Set while a header is being read: an encrypted folder then marks the
    /// entry being filled in (`a->entry` upstream).
    in_read_header: bool,
    entry_encrypted: bool,
}

/// `archive_read_support_format_7zip`.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    // Until enough data has been read, we cannot tell about any encrypted
    // entries yet.
    r.register_format(Box::new(SevenZip {
        has_encrypted_entries: ENCRYPTION_DONT_KNOW,
        codec2: -1,
        ..SevenZip::default()
    }))
}

fn truncated_body() -> Error {
    Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Truncated 7-Zip file body")
}

fn damaged() -> Error {
    Error::fatal(ARCHIVE_ERRNO_MISC, "Damaged 7-Zip archive")
}

impl Format for SevenZip {
    fn name(&self) -> &'static str {
        "7zip"
    }

    fn capabilities(&self) -> c_int {
        CAPS_ENCRYPT
    }

    fn has_encrypted_entries(&self) -> c_int {
        self.has_encrypted_entries
    }

    fn bid(&mut self, r: &mut Reader<'_>, best_bid: c_int) -> Result<c_int, Error> {
        // If someone has already bid more than 48, then avoid trashing the
        // look-ahead buffers with a seek.
        if best_bid > 48 {
            return Ok(-1);
        }
        match sfx::get_data_offset(r, false) {
            Ok(_) => Ok(48),
            Err(e) => {
                r.base().raise(e);
                Ok(0)
            }
        }
    }

    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        self.in_read_header = true;
        self.entry_encrypted = false;
        let res = self.read_header_inner(r, entry);
        self.in_read_header = false;
        if self.entry_encrypted {
            entry.set_is_data_encrypted(true);
            entry.set_is_metadata_encrypted(true);
        }
        res
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        if self.has_encrypted_entries == ENCRYPTION_DONT_KNOW {
            self.has_encrypted_entries = 0;
        }

        // The CRC warning follows the block it was found at: a block can't
        // carry a status, and `Data::Warn` carries no block.
        if let Some(msg) = self.crc_warning.take() {
            let _ = r.warn(ARCHIVE_ERRNO_MISC, msg);
            return Ok(Data::Warn);
        }
        let offset = self.entry_offset;
        let Some((chunk, crc_warning)) = self.read_entry_block(r)? else {
            return Ok(Data::Eof { offset });
        };
        self.crc_warning = crc_warning;
        Ok(Data::Block {
            data: self.chunk_bytes(r, chunk),
            offset,
        })
    }

    fn read_data_skip(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        if self.pack_stream_bytes_unconsumed != 0 {
            let _ = self.read_consume(r);
        }

        // If we've already read to end of data, we're done.
        if self.end_of_entry {
            return Ok(Status::Ok);
        }

        // If the length is at the beginning, we can skip the compressed
        // data much more quickly.
        self.skip_stream(r, self.entry_bytes_remaining)?;
        self.entry_bytes_remaining = 0;

        // This entry is finished and done.
        self.end_of_entry = true;
        Ok(Status::Ok)
    }
}

impl SevenZip {
    fn read_header_inner(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
    ) -> Result<Status, Error> {
        let mut ret = Status::Ok;

        // It should be sufficient to call archive_read_next_header() for a
        // reader to determine if an entry is encrypted or not. If the
        // encryption of an entry is only detectable when calling
        // archive_read_data(), so be it. We'll do the same check there as
        // well.
        if self.has_encrypted_entries == ENCRYPTION_DONT_KNOW {
            self.has_encrypted_entries = 0;
        }

        r.set_format(format_code::SEVENZIP, c"7-Zip");

        if self.entries.is_none() {
            if self.slurp_central_directory(r)? == Status::Eof {
                return Ok(Status::Eof);
            }
            self.entries_remaining = self.num_files;
            self.entry = 0;
        } else {
            self.entry += 1;
        }
        let zip_entry = match self.entries.as_ref().and_then(|e| e.get(self.entry)) {
            Some(e) if self.entries_remaining != 0 => e.clone(),
            _ => return Ok(Status::Eof),
        };
        self.entries_remaining -= 1;

        self.entry_offset = 0;
        self.end_of_entry = false;
        self.entry_crc32 = 0;
        self.crc_warning = None;

        // Setup a string conversion for a filename.
        if self.sconv.is_none() {
            let mut cache = r.base().conv.lock().unwrap_or_else(PoisonError::into_inner);
            let sc = conversion_from_charset(Some(&mut *cache), b"UTF-16LE", true)
                .map_err(|e| Error::fatal(e.errno, e.message))?;
            self.sconv = Some(sc);
        }

        // Figure out if the entry is encrypted by looking at the folder
        // that is associated to the current 7zip entry. If the folder has a
        // coder with a _7Z_CRYPTO codec then the folder is encrypted. Hence
        // the entry must also be encrypted.
        if let Some(folder) = zip_entry.folder_index.and_then(|i| self.si.folders.get(i))
            && folder.coders.iter().any(|c| is_crypto(c.codec))
        {
            entry.set_is_data_encrypted(true);
            self.has_encrypted_entries = 1;
        }

        let sconv = self.sconv.clone();
        match self.entry_names.as_deref() {
            // No kName property (eg from `7z a -si`): 7-Zip derives the name
            // from the archive filename, which we don't know.
            None => entry.set_pathname(b"data"),
            Some(names) => {
                let name = names
                    .get(zip_entry.name_off..zip_entry.name_off + zip_entry.name_len)
                    .unwrap_or_default();
                if entry.copy_pathname_l(name, sconv.as_deref()).is_err() {
                    let mut msg = b"Pathname cannot be converted from ".to_vec();
                    msg.extend_from_slice(conversion_charset_name(sconv.as_deref()));
                    msg.extend_from_slice(b" to current locale");
                    ret = r.warn(ARCHIVE_ERRNO_FILE_FORMAT, msg);
                }
            }
        }

        // Populate some additional entry fields:
        entry.set_mode(zip_entry.mode as Mode);
        if zip_entry.flg & MTIME_IS_SET != 0 {
            entry.set_mtime(zip_entry.mtime.0, i64::from(zip_entry.mtime.1));
        }
        if zip_entry.flg & CTIME_IS_SET != 0 {
            entry.set_ctime(zip_entry.ctime.0, i64::from(zip_entry.ctime.1));
        }
        if zip_entry.flg & ATIME_IS_SET != 0 {
            entry.set_atime(zip_entry.atime.0, i64::from(zip_entry.atime.1));
        }
        match zip_entry.ss_index {
            Some(i) => {
                self.entry_bytes_remaining = self
                    .si
                    .ss
                    .unpack_sizes
                    .get(i)
                    .copied()
                    .ok_or_else(damaged)?;
                entry.set_size(self.entry_bytes_remaining);
            }
            None => {
                self.entry_bytes_remaining = 0;
                entry.set_size(0);
            }
        }

        // These attributes are supported by the windows implementation of
        // archive_write_disk.
        let supported_attrs =
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
        if zip_entry.attr & supported_attrs != 0 {
            let flags: Vec<&[u8]> = [
                (FILE_ATTRIBUTE_READONLY, &b"rdonly"[..]),
                (FILE_ATTRIBUTE_HIDDEN, b"hidden"),
                (FILE_ATTRIBUTE_SYSTEM, b"system"),
            ]
            .iter()
            .filter(|(bit, _)| zip_entry.attr & bit != 0)
            .map(|&(_, name)| name)
            .collect();
            entry.copy_fflags_text(&flags.join(&b','));
        }

        // If there's no body, force read_data() to return EOF immediately.
        if self.entry_bytes_remaining < 1 {
            self.end_of_entry = true;
        }

        if zip_entry.mode & u32::from(AE_IFMT) == u32::from(AE_IFLNK) {
            if self.entry_bytes_remaining > 1024 * 1024 {
                return Err(Error::fatal(
                    libc::ENOMEM,
                    "Rejecting malformed 7zip archive: symlink contents exceed 1 megabyte",
                ));
            }

            // Symbolic-name is recorded as its contents. We have to read
            // the contents at this time.
            let mut symname = Vec::new();
            while self.entry_bytes_remaining > 0 {
                let Some((chunk, _)) = self.read_entry_block(r)? else {
                    break;
                };
                let block = self.chunk_bytes(r, chunk);
                symname
                    .try_reserve(block.len())
                    .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate memory for Symname"))?;
                symname.extend_from_slice(block);
            }
            if symname.is_empty() {
                // If there is no symname, handle it as a regular file.
                let mode = (zip_entry.mode & !u32::from(AE_IFMT)) | u32::from(AE_IFREG);
                if let Some(e) = self.entries.as_mut().and_then(|e| e.get_mut(self.entry)) {
                    e.mode = mode;
                }
                entry.set_mode(mode as Mode);
            } else {
                // Symbolic links are embedded as UTF-8 strings.
                let utf8_conv = {
                    let mut cache = r.base().conv.lock().unwrap_or_else(PoisonError::into_inner);
                    conversion_from_charset(Some(&mut *cache), b"UTF-8", true)
                        .map_err(|e| Error::fatal(e.errno, e.message))?
                };
                let _ = entry.copy_symlink_l(&symname, Some(&*utf8_conv));
            }
            entry.set_size(0);
        }

        Ok(ret)
    }

    /// The body of `archive_read_format_7zip_read_data`, up to the block:
    /// `None` at the end of the entry. The block's bad CRC is reported along
    /// with it, as upstream's `ARCHIVE_WARN`, and its message is already set.
    fn read_entry_block(
        &mut self,
        r: &mut Reader<'_>,
    ) -> Result<Option<(stream::Chunk, Option<Vec<u8>>)>, Error> {
        if self.pack_stream_bytes_unconsumed != 0 {
            let _ = self.read_consume(r);
        }

        // If we hit end-of-entry last time, clean up and return ARCHIVE_EOF
        // this time.
        if self.end_of_entry {
            return Ok(None);
        }

        let bytes_to_read = usize::try_from(self.entry_bytes_remaining)
            .unwrap_or(usize::MAX)
            .min(MAX_READ);
        let chunk = self.read_stream(r, bytes_to_read, 0)?;
        if chunk.len == 0 {
            return Err(truncated_body());
        }
        self.entry_bytes_remaining -= chunk.len as i64;
        if self.entry_bytes_remaining == 0 {
            self.end_of_entry = true;
        }

        let entry = self.entries.as_ref().and_then(|e| e.get(self.entry));
        let has_crc = entry.is_some_and(|e| e.flg & CRC32_IS_SET != 0);
        let expected = entry
            .and_then(|e| e.ss_index)
            .and_then(|i| self.si.ss.digests.get(i))
            .copied();

        // Update checksum.
        if has_crc {
            self.entry_crc32 = crate::crc32::crc32(self.entry_crc32, self.chunk_bytes(r, chunk));
        }

        // If we hit the end, swallow any end-of-data marker.
        let mut warning = None;
        if self.end_of_entry && has_crc {
            // Check computed CRC against file contents.
            if let Some(expected) = expected.filter(|&e| e != self.entry_crc32) {
                let msg = format!(
                    "7-Zip bad CRC: 0x{:x} should be 0x{:x}",
                    self.entry_crc32, expected
                )
                .into_bytes();
                r.base().set_error(ARCHIVE_ERRNO_MISC, Some(&msg));
                warning = Some(msg);
            }
        }

        self.entry_offset += chunk.len as i64;
        Ok(Some((chunk, warning)))
    }
}
