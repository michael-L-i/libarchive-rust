/*-
* Copyright (c) 2003-2007 Tim Kientzle
* Copyright (c) 2011 Andres Mejia
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

// Ported from libarchive/archive_read_support_format_rar.c.

//! The RAR 1.5 through 4.x format: headers, stored data, and the LZSS and
//! PPMd decompressors with RAR's standard filters. Encrypted data and solid
//! archives are refused, as upstream does.

mod filters;
mod huffman;

use crate::archive::*;
use crate::crc32::crc32;
use crate::entry::{AE_IFDIR, AE_IFLNK, AE_IFMT, AE_IFREG, Entry, Mode};
use crate::ffi::sys;
use crate::ppmd::ByteIn;
use crate::ppmd7::{Ppmd7, Ppmd7RangeDec};
use crate::read::{
    ARCHIVE_ERRNO_FILE_FORMAT, CAPS_ENCRYPT, Data, ENCRYPTION_DONT_KNOW, Format, Read, Reader,
    Status, Whence, format_code,
};
use crate::string::{StringConv, conversion_charset_name, conversion_from_charset};
use crate::time::dos_to_unix;
use crate::util::Error;
use filters::Filters;
use huffman::Code;
use std::ffi::c_int;
use std::sync::{Arc, PoisonError};

/// RAR signature, also known as the mark header.
const RAR_SIGNATURE: &[u8; 7] = b"\x52\x61\x72\x21\x1A\x07\x00";

// Header types.
const MARK_HEAD: u8 = 0x72;
const MAIN_HEAD: u8 = 0x73;
const FILE_HEAD: u8 = 0x74;
const COMM_HEAD: u8 = 0x75;
const AV_HEAD: u8 = 0x76;
const SUB_HEAD: u8 = 0x77;
const PROTECT_HEAD: u8 = 0x78;
const SIGN_HEAD: u8 = 0x79;
const NEWSUB_HEAD: u8 = 0x7a;
const ENDARC_HEAD: u8 = 0x7b;

// Main header flags.
const MHD_VOLUME: u32 = 0x0001;
const MHD_PASSWORD: u32 = 0x0080;
const MHD_ENCRYPTVER: u32 = 0x0200;

/// Flag common to all headers.
const HD_ADD_SIZE_PRESENT: u32 = 0x8000;

// File header flags.
const FHD_SPLIT_BEFORE: u32 = 0x0001;
const FHD_SPLIT_AFTER: u32 = 0x0002;
const FHD_PASSWORD: u32 = 0x0004;
const FHD_SOLID: u32 = 0x0010;
const FHD_LARGE: u32 = 0x0100;
const FHD_UNICODE: u32 = 0x0200;
const FHD_SALT: u32 = 0x0400;
const FHD_EXTTIME: u32 = 0x1000;

// Host operating systems.
const OS_MSDOS: u8 = 0;
const OS_OS2: u8 = 1;
const OS_WIN32: u8 = 2;
const OS_UNIX: u8 = 3;
const OS_MAC_OS: u8 = 4;
const OS_BEOS: u8 = 5;

// Compression methods.
const COMPRESS_METHOD_STORE: i8 = 0x30;
const COMPRESS_METHOD_FASTEST: i8 = 0x31;
const COMPRESS_METHOD_BEST: i8 = 0x35;

const NS_UNIT: u32 = 10_000_000;

const DICTIONARY_MAX_SIZE: i64 = 0x40_0000;

const MAINCODE_SIZE: usize = 299;
const OFFSETCODE_SIZE: usize = 60;
const LOWOFFSETCODE_SIZE: usize = 17;
const LENGTHCODE_SIZE: usize = 28;
const HUFFMAN_TABLE_SIZE: usize =
    MAINCODE_SIZE + OFFSETCODE_SIZE + LOWOFFSETCODE_SIZE + LENGTHCODE_SIZE;

const MAX_SYMBOL_LENGTH: i32 = 0xF;
const MAX_SYMBOLS: usize = 20;

const SFX_MAX_READAHEAD: usize = 1024 * 512;

/// Considering L1,L2 cache miss and a calling of write system-call,
/// the best size of the output buffer(uncompressed buffer) is 128K.
/// If the structure of extracting process is changed, this value
/// might be researched again.
const UNP_BUFFER_SIZE: usize = 128 * 1024;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

/// Stack overflow check.
const MAX_COMPRESS_DEPTH: usize = 1024;

/// Size of the fields common to all headers.
const RAR_HEADER_SIZE: usize = 7;
/// Size of the fields common to all file headers.
const RAR_FILE_HEADER_SIZE: usize = 25;

const LENGTH_BASES: [u8; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const LENGTH_BITS: [u8; 28] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
const OFFSET_BASES: [u32; 60] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
    1048576, 1310720, 1572864, 1835008, 2097152, 2359296, 2621440, 2883584, 3145728, 3407872,
    3670016, 3932160,
];
const OFFSET_BITS: [u8; 60] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18,
];
const SHORT_BASES: [u8; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_BITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

fn le16(b: &[u8]) -> u32 {
    b.first_chunk::<2>()
        .map_or(0, |c| u32::from(u16::from_le_bytes(*c)))
}

fn le32(b: &[u8]) -> u32 {
    b.first_chunk::<4>().map_or(0, |c| u32::from_le_bytes(*c))
}

/// `archive_set_error` with `ARCHIVE_ERRNO_FILE_FORMAT`, for the cases where
/// upstream goes on after setting it.
fn set_error(a: &Base, msg: &str) {
    a.set_error(ARCHIVE_ERRNO_FILE_FORMAT, Some(msg.as_bytes()));
}

/// Sets the error as upstream does at the spot it fails, so a later failure
/// replaces it exactly when it would upstream.
fn fail(a: &Base, code: c_int, msg: &str) -> Error {
    set_error(a, msg);
    Error::silent(code)
}

fn failed(a: &Base, msg: &str) -> Error {
    fail(a, ARCHIVE_FAILED, msg)
}

fn fatal(a: &Base, msg: &str) -> Error {
    fail(a, ARCHIVE_FATAL, msg)
}

/// `get_time`: an MS-DOS date and time as a local time.
fn get_time(ttime: u32) -> i64 {
    dos_to_unix(ttime)
}

/// Where a part of a (possibly multivolume) file's data sits in the input.
#[derive(Clone, Copy)]
struct DataBlockOffsets {
    header_size: i64,
    start_offset: i64,
    end_offset: i64,
}

/// The bit stream reader. Upstream reads ahead in the input and consumes
/// what the decompressor used at its next opportunity; we consume the bytes
/// as they go into the cache, which no one can tell apart.
#[derive(Default)]
struct BitReader {
    cache: u64,
    /// How many bits of `cache` are valid.
    avail: u32,
    /// `next_in != NULL`: the input was looked at since the last header.
    ready: bool,
}

fn cache_mask(n: u32) -> u32 {
    1u32.checked_shl(n).map_or(u32::MAX, |v| v - 1)
}

/// The code `read_next_symbol` reads with.
#[derive(Clone, Copy)]
enum Which {
    Main,
    Offset,
    LowOffset,
    Length,
}

/// The PPMd model, which RAR keeps for as long as the reader lives.
struct Ppmd {
    model: Ppmd7,
    range_dec: Ppmd7RangeDec,
}

/// What `read_data_compressed` produced, to be handed out.
enum Out {
    /// The first `len` bytes of the output buffer.
    Unpacked {
        len: usize,
        offset: i64,
    },
    /// Filter output in the VM's memory.
    Filtered {
        start: usize,
        len: usize,
        offset: i64,
    },
    Eof {
        offset: i64,
    },
}

pub struct Rar {
    // Entries from the main RAR header.
    main_flags: u32,
    file_crc: u32,

    // File header entries.
    compression_method: i8,
    file_flags: u32,
    packed_size: i64,
    unp_size: i64,
    mtime: i64,
    mnsec: i64,
    mode: Mode,
    /// The name as the header gives it plus a terminating NUL, which a
    /// split file's next part must match exactly.
    filename: Vec<u8>,
    filename_save: Option<Vec<u8>>,

    // File header optional entries.
    atime: i64,
    ansec: i64,
    ctime: i64,
    cnsec: i64,

    // Fields to help with tracking decompression of files.
    bytes_remaining: i64,
    bytes_uncopied: i64,
    offset: i64,
    offset_outgoing: i64,
    offset_seek: i64,
    valid: bool,
    unp_offset: usize,
    unp_buffer: Vec<u8>,
    dictionary_size: u32,
    entry_eof: bool,
    crc_calculated: u32,
    found_first_header: bool,
    dbo: Vec<DataBlockOffsets>,
    cursor: usize,
    filename_must_match: bool,

    // LZSS members.
    maincode: Code,
    offsetcode: Code,
    lowoffsetcode: Code,
    lengthcode: Code,
    length_table: [u8; HUFFMAN_TABLE_SIZE],
    /// The window; its size is a power of two.
    window: Vec<u8>,
    position: i64,
    last_length: u32,
    last_offset: u32,
    old_offset: [u32; 4],
    last_low_offset: u32,
    num_low_offset_repeats: u32,
    start_new_table: bool,

    filters: Filters,

    // PPMd variant H members.
    ppmd_valid: bool,
    ppmd_eod: bool,
    is_ppmd_block: bool,
    ppmd_escape: u32,
    /// Taken out while it decodes, because its byte source is the reader.
    ppmd: Option<Box<Ppmd>>,

    // String conversion.
    opt_sconv: Option<Arc<StringConv>>,
    sconv_utf8: Option<Arc<StringConv>>,
    sconv_utf16be: Option<Arc<StringConv>>,

    br: BitReader,

    /// Custom field to denote that this archive contains encrypted entries.
    has_encrypted_entries: c_int,
}

/// `archive_read_support_format_rar`.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Rar::new()))
}

impl Rar {
    fn new() -> Rar {
        Rar {
            main_flags: 0,
            file_crc: 0,
            compression_method: 0,
            file_flags: 0,
            packed_size: 0,
            unp_size: 0,
            mtime: 0,
            mnsec: 0,
            mode: 0,
            filename: Vec::new(),
            filename_save: None,
            atime: 0,
            ansec: 0,
            ctime: 0,
            cnsec: 0,
            bytes_remaining: 0,
            bytes_uncopied: 0,
            offset: 0,
            offset_outgoing: 0,
            offset_seek: 0,
            valid: false,
            unp_offset: 0,
            unp_buffer: Vec::new(),
            dictionary_size: 0,
            entry_eof: false,
            crc_calculated: 0,
            found_first_header: false,
            dbo: Vec::new(),
            cursor: 0,
            filename_must_match: false,
            maincode: Code::default(),
            offsetcode: Code::default(),
            lowoffsetcode: Code::default(),
            lengthcode: Code::default(),
            length_table: [0; HUFFMAN_TABLE_SIZE],
            window: Vec::new(),
            position: 0,
            last_length: 0,
            last_offset: 0,
            old_offset: [0; 4],
            last_low_offset: 0,
            num_low_offset_repeats: 0,
            start_new_table: false,
            filters: Filters::default(),
            ppmd_valid: false,
            ppmd_eod: false,
            is_ppmd_block: false,
            ppmd_escape: 0,
            ppmd: Some(Box::new(Ppmd {
                model: Ppmd7::new(),
                range_dec: Ppmd7RangeDec::new_rar(),
            })),
            opt_sconv: None,
            sconv_utf8: None,
            sconv_utf16be: None,
            br: BitReader::default(),
            // Until enough data has been read, we cannot tell about
            // any encrypted entries yet.
            has_encrypted_entries: ENCRYPTION_DONT_KNOW,
        }
    }
}

/// Whether `h` starts like a self-extracting executable: a DOS/Windows one
/// ("MZ") or an ELF one.
fn looks_like_sfx(h: &[u8]) -> bool {
    h.starts_with(b"MZ") || h.starts_with(b"\x7FELF")
}

/// `skip_sfx`: skips to the RAR signature in a self-extracting executable.
fn skip_sfx(r: &mut Reader<'_>) -> Result<(), Error> {
    let mut total = 0;
    let mut window: usize = 4096;
    while total + window <= SFX_MAX_READAHEAD {
        let h = match r.peek_available(window) {
            Ok(h) if h.len() >= window => h,
            // Remaining bytes are less than window.
            _ => {
                window >>= 1;
                if window < 0x40 {
                    break;
                }
                continue;
            }
        };
        if h.len() < 0x40 {
            break;
        }

        // Scan ahead until we find something that looks like the RAR header.
        let mut p = 0;
        while p + 7 < h.len() {
            if h.get(p..p + 7) == Some(RAR_SIGNATURE) {
                // Upstream doesn't look at the result of consuming.
                let _ = r.consume(p);
                return Ok(());
            }
            p += 0x10;
        }
        let _ = r.consume(p);
        total += p;
    }
    Err(fatal(r.base(), "Couldn't find out RAR header"))
}

impl Rar {
    /// `rar_read_ahead`: looks at the next `min` bytes of the input. `None`
    /// is where upstream returns NULL; otherwise how many of the bytes
    /// available belong to the current file's data, and the caller gets them
    /// from `r.peek_available(min)`. At the end of a part of a multivolume
    /// file, reads the next part's header.
    fn read_ahead_len(&mut self, r: &mut Reader<'_>, min: usize) -> Option<usize> {
        loop {
            let (mut avail, short) = match r.peek_available(min) {
                Ok(d) => (d.len() as i64, d.len() < min),
                Err(_) => return None,
            };
            if let Some(requested) = r.read_data_requested() {
                avail = avail.min(requested as i64);
            }
            avail = avail.min(self.bytes_remaining);
            if avail < 0 {
                return None;
            }
            if avail == 0
                && self.main_flags & MHD_VOLUME != 0
                && self.file_flags & FHD_SPLIT_AFTER != 0
            {
                self.filename_must_match = true;
                let mut ret = r.with_entry(|r, e| self.read_header(r, e));
                if matches!(ret, Ok(Status::Eof)) {
                    ret = r.with_entry(|r, e| self.read_header(r, e));
                }
                self.filename_must_match = false;
                match ret {
                    Ok(Status::Ok) => continue,
                    Ok(_) => return None,
                    Err(e) => {
                        r.base().raise(e);
                        return None;
                    }
                }
            }
            return if short { None } else { Some(avail as usize) };
        }
    }

    /// `archive_read_format_rar_read_header`. The calls in the middle of
    /// reading data pass the handle's own entry, as upstream passes
    /// `a->entry` (`Reader::with_entry`).
    fn read_header(
        &mut self,
        r: &mut Reader<'_>,
        entry: Option<&mut Entry>,
    ) -> Result<Status, Error> {
        r.with_metadata(|r| self.read_header_inner(r, entry))
    }

    fn read_header_inner(
        &mut self,
        r: &mut Reader<'_>,
        mut entry: Option<&mut Entry>,
    ) -> Result<Status, Error> {
        let a = r.base();
        a.format.set(format_code::RAR);
        if a.format_name.get().is_none() {
            a.format_name.set(Some(c"RAR"));
        }

        // It should be sufficient to call archive_read_next_header() for
        // a reader to determine if an entry is encrypted or not. If the
        // encryption of an entry is only detectable when calling
        // archive_read_data(), so be it. We'll do the same check there
        // as well.
        if self.has_encrypted_entries == ENCRYPTION_DONT_KNOW {
            self.has_encrypted_entries = 0;
        }

        // RAR files can be generated without EOF headers, so return
        // ARCHIVE_EOF if this fails.
        let Ok(Some(h)) = r.read_ahead(7) else {
            return Ok(Status::Eof);
        };
        if !self.found_first_header && looks_like_sfx(h) {
            // This is an executable? Must be self-extracting...
            skip_sfx(r)?;
        }
        self.found_first_header = true;

        loop {
            let Ok(Some(h)) = r.read_ahead(7) else {
                return Err(fatal(a, "Failed to read next header"));
            };
            let mut head = [0u8; 7];
            head.copy_from_slice(h.get(..7).unwrap_or_default());
            let head_type = head[2];
            match head_type {
                MARK_HEAD => {
                    if head != *RAR_SIGNATURE {
                        return Err(fatal(a, "Invalid marker header"));
                    }
                    r.consume(7)?;
                }

                MAIN_HEAD => {
                    self.main_flags = le16(&head[3..]);
                    let skip = le16(&head[5..]) as usize;
                    if skip < 7 + 2 + 4 {
                        return Err(fatal(a, "Invalid header size"));
                    }
                    let Ok(Some(h)) = r.read_ahead(skip) else {
                        return Err(Error::silent(ARCHIVE_FATAL));
                    };
                    if self.main_flags & MHD_ENCRYPTVER != 0 && skip < 7 + 2 + 4 + 1 {
                        return Err(fatal(a, "Invalid header size"));
                    }

                    // Main header is password encrypted, so we cannot read
                    // any file names or any other info about files from the
                    // header.
                    if self.main_flags & MHD_PASSWORD != 0 {
                        if let Some(entry) = entry.as_deref_mut() {
                            entry.set_is_metadata_encrypted(true);
                            entry.set_is_data_encrypted(true);
                        }
                        self.has_encrypted_entries = 1;
                        return Err(fatal(a, "RAR encryption support unavailable"));
                    }

                    let crc = crc32(0, h.get(2..skip).unwrap_or_default());
                    if crc & 0xffff != le16(h) {
                        return Err(fatal(a, "Header CRC error"));
                    }
                    r.consume(skip)?;
                }

                FILE_HEAD => return self.read_file_header(r, entry, head_type),

                COMM_HEAD | AV_HEAD | SUB_HEAD | PROTECT_HEAD | SIGN_HEAD | ENDARC_HEAD => {
                    let flags = le16(&head[3..]);
                    let mut skip = i64::from(le16(&head[5..]));
                    if skip < 7 {
                        return Err(fatal(a, "Invalid header size too small"));
                    }
                    let crc_expected = le16(&head);
                    if flags & HD_ADD_SIZE_PRESENT != 0 {
                        if skip < 7 + 4 {
                            return Err(fatal(a, "Invalid header size too small"));
                        }
                        let Ok(Some(h)) = r.read_ahead(skip as usize) else {
                            return Err(Error::silent(ARCHIVE_FATAL));
                        };
                        skip += i64::from(le32(h.get(7..).unwrap_or_default()));
                    }

                    // Skip over the 2-byte CRC at the beginning of the
                    // header.
                    r.consume(2)?;
                    skip -= 2;

                    // Skim the entire header and compute the CRC.
                    let mut crc = 0;
                    while skip > 0 {
                        let to_read = skip.min(32 * 1024) as usize;
                        let Ok(Some(h)) = r.read_ahead(to_read) else {
                            return Err(fatal(a, "Bad RAR file"));
                        };
                        crc = crc32(crc, h.get(..to_read).unwrap_or_default());
                        r.consume(to_read)?;
                        skip -= to_read as i64;
                    }
                    if crc & 0xffff != crc_expected {
                        return Err(fatal(a, "Header CRC error"));
                    }
                    if head_type == ENDARC_HEAD {
                        return Ok(Status::Eof);
                    }
                }

                NEWSUB_HEAD => {
                    // A warning is dropped; the next header decides.
                    let _ = self.read_file_header(r, entry.as_deref_mut(), head_type)?;
                }

                _ => return Err(fatal(a, "Bad RAR file")),
            }
        }
    }
}

/// The name of a file, as `read_header` decodes it.
struct Name {
    /// The decoded name and its terminator, as `Rar::filename` keeps it.
    buf: Vec<u8>,
    /// What upstream calls `filename_size`: the length of `buf` less its
    /// last byte.
    size: usize,
    /// Where in the header the name's data ends.
    end: usize,
    /// The conversion for the name.
    unicode: Unicode,
}

#[derive(Clone, Copy, PartialEq)]
enum Unicode {
    /// The code page of the archive.
    No,
    Utf8,
    Utf16Be,
}

/// Decodes a name with RAR's `FHD_UNICODE` encoding, in which the name is
/// followed by a NUL and the encoded Unicode form. `name` is the name's
/// `filename_size` bytes in the header.
fn decode_unicode_name(name: &[u8]) -> Name {
    let end = name.len();
    let fn_end = end * 2;
    let byte = |i: usize| name.get(i).copied().unwrap_or(0);
    let mut buf: Vec<u8> = Vec::new();
    let mut offset = name.iter().position(|&b| b == 0).unwrap_or(end) + 1;
    let highbyte = if offset >= end {
        0
    } else {
        offset += 1;
        byte(offset - 1)
    };
    let mut flagbits = 0;
    let mut flagbyte = 0;
    while offset < end && buf.len() < fn_end {
        if flagbits == 0 {
            flagbyte = byte(offset);
            offset += 1;
            flagbits = 8;
        }

        flagbits -= 2;
        match (flagbyte >> flagbits) & 3 {
            0 => {
                if offset >= end {
                    continue;
                }
                buf.extend([0, byte(offset)]);
                offset += 1;
            }
            1 => {
                if offset >= end {
                    continue;
                }
                buf.extend([highbyte, byte(offset)]);
                offset += 1;
            }
            2 => {
                if offset >= end - 1 {
                    offset = end;
                    continue;
                }
                buf.extend([byte(offset + 1), byte(offset)]);
                offset += 2;
            }
            _ => {
                if offset >= end {
                    continue;
                }
                let mut length = byte(offset);
                offset += 1;
                let mut extra = 0;
                let mut high = 0;
                if length & 0x80 != 0 {
                    if offset >= end {
                        continue;
                    }
                    extra = byte(offset);
                    offset += 1;
                    high = highbyte;
                }
                length = (length & 0x7f) + 2;
                while length != 0 && buf.len() < fn_end {
                    let cp = buf.len() >> 1;
                    buf.extend([high, byte(cp).wrapping_add(extra)]);
                    length -= 1;
                }
            }
        }
    }
    // The terminator, which `filename_size` includes, and one more.
    buf.extend([0, 0]);
    let size = buf.len() - 1;

    // Fix up the separators.
    for pair in buf.chunks_exact_mut(2) {
        if pair[0] == 0 {
            match pair[1] {
                0 => break,
                b'\\' => pair[1] = b'/',
                _ => {}
            }
        }
    }
    Name {
        buf,
        size,
        end: offset,
        unicode: Unicode::Utf16Be,
    }
}

impl Rar {
    /// `read_header`: a file header, or a subblock's, whose first byte
    /// `r` is at.
    fn read_file_header(
        &mut self,
        r: &mut Reader<'_>,
        mut entry: Option<&mut Entry>,
        head_type: u8,
    ) -> Result<Status, Error> {
        let a = r.base();
        let mut ret = Status::Ok;

        // `None` is the current locale, which needs no conversion.
        let sconv = self.opt_sconv.clone();

        let Ok(Some(h)) = r.read_ahead(RAR_HEADER_SIZE) else {
            return Err(Error::silent(ARCHIVE_FATAL));
        };
        let mut rar_header = [0u8; RAR_HEADER_SIZE];
        rar_header.copy_from_slice(h.get(..RAR_HEADER_SIZE).unwrap_or_default());
        self.file_flags = le16(&rar_header[3..]);
        let header_size = i64::from(le16(&rar_header[5..]));
        if header_size < (RAR_FILE_HEADER_SIZE + RAR_HEADER_SIZE) as i64 {
            return Err(fatal(a, "Invalid header size"));
        }
        let mut crc32_computed = crc32(0, &rar_header[2..]);
        r.consume(RAR_HEADER_SIZE)?;

        if self.file_flags & FHD_SOLID == 0 {
            self.compression_method = 0;
            self.packed_size = 0;
            self.unp_size = 0;
            self.mtime = 0;
            self.mode = 0;
            self.atime = 0;
            self.ansec = 0;
            self.ctime = 0;
            self.cnsec = 0;
            self.mnsec = 0;
        } else {
            return Err(fatal(a, "RAR solid archive support unavailable"));
        }

        let body_len = header_size as usize - RAR_HEADER_SIZE;
        let Ok(Some(h)) = r.read_ahead(body_len) else {
            return Err(fatal(a, "Failed to read full header content"));
        };
        let hdr = h.get(..body_len).unwrap_or_default().to_vec();

        // File Header CRC check.
        crc32_computed = crc32(crc32_computed, &hdr);
        if crc32_computed & 0xffff != le16(&rar_header) {
            return Err(fatal(a, "Header CRC error"));
        }
        // If no CRC error, go on parsing File Header.
        let endp = hdr.len();
        let file_header = hdr.get(..RAR_FILE_HEADER_SIZE).unwrap_or_default();
        let mut p = RAR_FILE_HEADER_SIZE;

        self.compression_method = file_header.get(18).map_or(0, |&m| m as i8);

        self.mtime = get_time(le32(file_header.get(13..).unwrap_or_default()));

        self.file_crc = le32(file_header.get(9..).unwrap_or_default());

        if self.file_flags & FHD_PASSWORD != 0 {
            if let Some(entry) = entry.as_deref_mut() {
                entry.set_is_data_encrypted(true);
            }
            self.has_encrypted_entries = 1;
            set_error(a, "RAR encryption support unavailable");
            // Since it is only the data part itself that is encrypted we
            // can at least extract information about the currently
            // processed entry and don't need to return ARCHIVE_FATAL here.
        }

        let pack_size = le32(file_header);
        let unp_size = le32(file_header.get(4..).unwrap_or_default());
        if self.file_flags & FHD_LARGE != 0 {
            if p + 8 > endp {
                return Err(fatal(a, "Invalid header size"));
            }
            // The high halves of the sizes.
            let high_pack = le32(hdr.get(p..).unwrap_or_default());
            let high_unp = le32(hdr.get(p + 4..).unwrap_or_default());
            p += 8;
            self.packed_size = (u64::from(high_pack) << 32 | u64::from(pack_size)) as i64;
            self.unp_size = (u64::from(high_unp) << 32 | u64::from(unp_size)) as i64;
        } else {
            self.packed_size = i64::from(pack_size);
            self.unp_size = i64::from(unp_size);
        }

        if self.packed_size < 0 || self.unp_size < 0 {
            return Err(fatal(a, "Invalid sizes specified"));
        }

        self.bytes_remaining = self.packed_size;

        // TODO: RARv3 subblocks contain comments. For now the complete block
        // is consumed at the end.
        if head_type == NEWSUB_HEAD {
            let skip = match self.packed_size.checked_add(header_size) {
                Some(skip) if skip >= 7 => skip,
                _ => {
                    return Err(fatal(a, "Invalid RAR file: Overlarge extended header"));
                }
            };
            if r.consume(skip - 7).is_err() {
                return Err(fatal(
                    a,
                    "Invalid RAR file: Cannot read extended header data",
                ));
            }

            // NEWSUB records are metadata-only in this reader. The block
            // header has already been validated, so it is safe to skip
            // exactly the remaining header bytes and the associated data
            // payload.
            return Ok(ret);
        }

        let mut filename_size = le16(file_header.get(19..).unwrap_or_default()) as usize;
        if p + filename_size > endp {
            return Err(fatal(a, "Invalid filename size"));
        }
        let raw_name = hdr.get(p..p + filename_size).unwrap_or_default();
        let name = if self.file_flags & FHD_UNICODE != 0 {
            if raw_name.contains(&0) {
                decode_unicode_name(raw_name)
            } else {
                // If FHD_UNICODE is set but no unicode data, this file name
                // form is UTF-8.
                let mut buf = raw_name.to_vec();
                buf.push(0);
                Name {
                    buf,
                    size: filename_size,
                    end: filename_size,
                    unicode: Unicode::Utf8,
                }
            }
        } else {
            let mut buf = raw_name.to_vec();
            buf.push(0);
            Name {
                buf,
                size: filename_size,
                end: filename_size,
                unicode: Unicode::No,
            }
        };
        let Name {
            mut buf,
            size,
            end,
            unicode,
        } = name;
        if unicode != Unicode::Utf16Be {
            for b in buf.iter_mut().take_while(|b| **b != 0) {
                if *b == b'\\' {
                    *b = b'/';
                }
            }
        }
        filename_size = size;
        p += end;
        let fn_sconv = match unicode {
            Unicode::No => sconv.clone(),
            Unicode::Utf8 => {
                if self.sconv_utf8.is_none() {
                    self.sconv_utf8 = Some(conversion(a, b"UTF-8")?);
                }
                self.sconv_utf8.clone()
            }
            Unicode::Utf16Be => {
                // Decoded unicode form is UTF-16BE, so we have to update a
                // string conversion object for it.
                if self.sconv_utf16be.is_none() {
                    self.sconv_utf16be = Some(conversion(a, b"UTF-16BE")?);
                }
                self.sconv_utf16be.clone()
            }
        };
        self.filename = buf;

        // Split file in multivolume RAR. No more need to process header.
        if self.filename_save.as_ref() == Some(&self.filename) {
            r.consume(body_len)?;
            self.br.ready = false;
            self.cursor += 1;
            if self.cursor >= self.dbo.len() {
                self.dbo.push(DataBlockOffsets {
                    header_size,
                    start_offset: -1,
                    end_offset: -1,
                });
            }
            let position = r.position();
            let packed_size = self.packed_size;
            let Some(dbo) = self.dbo.get_mut(self.cursor) else {
                return Err(fail(a, ARCHIVE_FATAL, "Couldn't allocate memory"));
            };
            if dbo.start_offset < 0 {
                if packed_size > i64::MAX - position {
                    return Err(fatal(a, "Unable to store offsets"));
                }
                dbo.start_offset = position;
                dbo.end_offset = dbo.start_offset + packed_size;
            }
            return Ok(ret);
        } else if self.filename_must_match {
            return Err(fatal(
                a,
                "Mismatch of file parts split across multi-volume archive",
            ));
        }

        self.filename_save = Some(self.filename.clone());

        // Set info for seeking.
        self.dbo.clear();
        self.dbo.push(DataBlockOffsets {
            header_size,
            start_offset: -1,
            end_offset: -1,
        });
        self.cursor = 0;

        if self.file_flags & FHD_SALT != 0 {
            if p + 8 > endp {
                return Err(fatal(a, "Invalid header size"));
            }
            p += 8;
        }

        if self.file_flags & FHD_EXTTIME != 0 && !self.read_exttime(&hdr, p) {
            return Err(fatal(a, "Invalid header size"));
        }

        r.consume(body_len)?;
        let position = r.position();
        if self.packed_size > i64::MAX - position {
            return Err(fatal(a, "Unable to store offsets"));
        }
        let packed_size = self.packed_size;
        if let Some(dbo) = self.dbo.first_mut() {
            dbo.start_offset = position;
            dbo.end_offset = position + packed_size;
        }

        let host_os = file_header.get(8).copied().unwrap_or(0);
        let attr = le32(file_header.get(21..).unwrap_or_default());
        let rw = (libc::S_IRUSR | libc::S_IWUSR | libc::S_IRGRP | libc::S_IROTH) as Mode;
        match host_os {
            OS_MSDOS | OS_OS2 | OS_WIN32 => {
                self.mode = attr as Mode;
                self.mode = if u32::from(self.mode) & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    AE_IFDIR | (libc::S_IXUSR | libc::S_IXGRP | libc::S_IXOTH) as Mode
                } else {
                    AE_IFREG
                };
                self.mode |= rw;
            }
            OS_UNIX | OS_MAC_OS | OS_BEOS => self.mode = attr as Mode,
            _ => {
                return Err(fatal(a, "Unknown file attributes from RAR file's host OS"));
            }
        }

        self.bytes_uncopied = 0;
        self.position = 0;
        self.offset = 0;
        self.offset_seek = 0;
        self.dictionary_size = 0;
        self.offset_outgoing = 0;
        self.br.cache = 0;
        self.br.avail = 0;
        self.br.ready = false;
        self.crc_calculated = 0;
        self.entry_eof = false;
        self.valid = true;
        self.is_ppmd_block = false;
        self.start_new_table = true;
        self.unp_buffer = Vec::new();
        self.unp_offset = 0;
        self.length_table = [0; HUFFMAN_TABLE_SIZE];
        if let Some(ppmd) = self.ppmd.as_mut() {
            ppmd.model.free();
        }
        self.ppmd_valid = false;
        self.ppmd_eod = false;
        self.filters.filter_start = i64::MAX;

        if let Some(entry) = entry.as_deref_mut() {
            entry.set_mtime(self.mtime, self.mnsec);
            entry.set_ctime(self.ctime, self.cnsec);
            entry.set_atime(self.atime, self.ansec);
            entry.set_size(self.unp_size);
            entry.set_mode(self.mode);

            let name = buf_name(&self.filename, filename_size);
            if entry.copy_pathname_l(name, fn_sconv.as_deref()).is_err() {
                let msg = [
                    b"Pathname cannot be converted from ".as_slice(),
                    conversion_charset_name(fn_sconv.as_deref()),
                    b" to current locale",
                ]
                .concat();
                ret = a.warn(ARCHIVE_ERRNO_FILE_FORMAT, msg);
            }
        }

        if self.mode & AE_IFMT == AE_IFLNK {
            // Make sure a symbolic-link file does not have its body.
            self.bytes_remaining = 0;
            if let Some(entry) = entry.as_deref_mut() {
                entry.set_size(0);
            }

            // Read a symbolic-link name.
            if self.read_symlink_stored(r, entry, sconv.as_deref())? == Status::Warn {
                ret = Status::Warn;
            }
        }

        if self.bytes_remaining == 0 {
            self.entry_eof = true;
        }

        Ok(ret)
    }
}

/// `archive_string_conversion_from_charset(a, charset, 1)`.
fn conversion(a: &Base, charset: &[u8]) -> Result<Arc<StringConv>, Error> {
    let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
    conversion_from_charset(Some(&mut *cache), charset, true)
        .map_err(|e| Error::fatal(e.errno, e.message))
}

/// The first `size` bytes of the name, which may stop at a NUL sooner.
fn buf_name(filename: &[u8], size: usize) -> &[u8] {
    filename.get(..size).unwrap_or_default()
}

impl Rar {
    /// `read_exttime`: the extended times at `hdr[p..]`. False if the header
    /// is too short.
    fn read_exttime(&mut self, hdr: &[u8], mut p: usize) -> bool {
        let endp = hdr.len();
        if p + 2 > endp {
            return false;
        }
        let flags = le16(hdr.get(p..).unwrap_or_default());
        p += 2;

        for i in (0..4).rev() {
            let mut t = 0;
            if i == 3 {
                t = self.mtime;
            }
            let rmode = flags >> (i * 4);
            if rmode & 8 != 0 {
                if t == 0 {
                    if p + 4 > endp {
                        return false;
                    }
                    t = get_time(le32(hdr.get(p..).unwrap_or_default()));
                    p += 4;
                }
                let mut rem = 0u32;
                let count = (rmode & 3) as usize;
                if p + count > endp {
                    return false;
                }
                for &b in hdr.get(p..p + count).unwrap_or_default() {
                    rem = (u32::from(b) << 16) | (rem >> 8);
                }
                p += count;
                let Some(mut tm) = sys::localtime(t) else {
                    return false;
                };
                let nsec = i64::from(tm.sec) + i64::from(rem / NS_UNIT);
                if rmode & 4 != 0 {
                    tm.sec += 1;
                    t = sys::mktime(tm).unwrap_or(-1);
                }
                match i {
                    3 => {
                        self.mtime = t;
                        self.mnsec = nsec;
                    }
                    2 => {
                        self.ctime = t;
                        self.cnsec = nsec;
                    }
                    1 => {
                        self.atime = t;
                        self.ansec = nsec;
                    }
                    // The archive time, which nothing uses.
                    _ => {}
                }
            }
        }
        true
    }

    /// `read_symlink_stored`.
    fn read_symlink_stored(
        &mut self,
        r: &mut Reader<'_>,
        entry: Option<&mut Entry>,
        sconv: Option<&StringConv>,
    ) -> Result<Status, Error> {
        let a = r.base();
        let mut ret = Status::Ok;

        let size = usize::try_from(self.packed_size).unwrap_or(usize::MAX);
        r.budget.check_metadata(size)?;
        let Ok(Some(link)) = r.read_ahead(size) else {
            return Err(fatal(a, "Failed to read link"));
        };
        if let Some(entry) = entry
            && entry
                .copy_symlink_l(link.get(..size).unwrap_or_default(), sconv)
                .is_err()
        {
            let msg = [
                b"link cannot be converted from ".as_slice(),
                conversion_charset_name(sconv),
                b" to current locale",
            ]
            .concat();
            ret = a.warn(ARCHIVE_ERRNO_FILE_FORMAT, msg);
        }
        r.consume(size)?;
        Ok(ret)
    }

    /// `read_data_stored`.
    fn read_data_stored<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        let a = r.base();
        if self.bytes_remaining == 0
            && !(self.main_flags & MHD_VOLUME != 0 && self.file_flags & FHD_SPLIT_AFTER != 0)
        {
            if self.file_crc != self.crc_calculated {
                return Err(failed(a, "File CRC error"));
            }
            self.entry_eof = true;
            return Ok(Data::Eof {
                offset: self.offset,
            });
        }

        let avail = self.read_ahead_len(r, 1).unwrap_or(0);
        if avail == 0 {
            return Err(failed(a, "Truncated RAR file data"));
        }

        // The block stays in the reader's buffer until the next call, which
        // consumes it first (upstream's bytes_unconsumed).
        let later = r.consume_later();
        let data = match r.peek_available(1) {
            Ok(d) => d.get(..avail).unwrap_or(d),
            Err(_) => return Err(failed(a, "Truncated RAR file data")),
        };
        let n = data.len() as i64;
        let offset = self.offset;
        self.offset += n;
        self.offset_seek += n;
        self.bytes_remaining -= n;
        later.consume(data.len());
        // Calculate File CRC.
        self.crc_calculated = crc32(self.crc_calculated, data);
        Ok(Data::Block { data, offset })
    }
}

impl Format for Rar {
    fn name(&self) -> &'static str {
        "rar"
    }

    fn bid(&mut self, r: &mut Reader<'_>, best_bid: c_int) -> Result<c_int, Error> {
        // If there's already a bid > 30, we'll never win.
        if best_bid > 30 {
            return Ok(-1);
        }

        let Ok(Some(h)) = r.read_ahead(7) else {
            return Ok(-1);
        };
        if h.starts_with(RAR_SIGNATURE) {
            return Ok(30);
        }

        if looks_like_sfx(h) {
            // This is a PE file.
            let mut offset: usize = 0x10000;
            let mut window: usize = 4096;

            while offset + window <= SFX_MAX_READAHEAD {
                let h = r.peek_available(offset + window).unwrap_or_default();
                let mut avail = h.len();
                if avail < offset + window {
                    if avail >= offset + 0x10 {
                        // Remaining bytes are less than window.
                        window = avail - offset;
                        continue;
                    }
                    return Ok(0);
                }
                avail = avail.min(SFX_MAX_READAHEAD);
                while offset + 7 <= avail {
                    if h.get(offset..offset + 7) == Some(RAR_SIGNATURE) {
                        return Ok(30);
                    }
                    offset += 0x10;
                }
            }
        }
        Ok(0)
    }

    fn options(
        &mut self,
        a: &Base,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<Result<Status, Error>> {
        Some(if key == b"hdrcharset" {
            match value.filter(|v| !v.is_empty()) {
                None => Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    "rar: hdrcharset option needs a character-set name",
                )),
                Some(charset) => {
                    let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
                    conversion_from_charset(Some(&mut *cache), charset, false)
                        .map(|sc| {
                            self.opt_sconv = Some(sc);
                            Status::Ok
                        })
                        .map_err(|e| Error::fatal(e.errno, e.message))
                }
            }
        } else {
            // The "warn" return is just to inform the options supervisor
            // that we didn't handle it. It will generate a suitable error if
            // no one used this option.
            Ok(Status::Warn)
        })
    }

    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        Rar::read_header(self, r, Some(entry))
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        if self.has_encrypted_entries == ENCRYPTION_DONT_KNOW {
            self.has_encrypted_entries = 0;
        }

        if self.entry_eof || self.offset_seek >= self.unp_size {
            return Ok(Data::Eof {
                offset: self.offset,
            });
        }

        match self.compression_method {
            COMPRESS_METHOD_STORE => self.read_data_stored(r),
            COMPRESS_METHOD_FASTEST..=COMPRESS_METHOD_BEST => {
                let out = self.read_data_compressed(r);
                if !matches!(out, Ok(Out::Unpacked { .. } | Out::Filtered { .. })) {
                    if let Some(ppmd) = self.ppmd.as_mut() {
                        ppmd.model.free();
                    }
                    self.start_new_table = true;
                    self.ppmd_valid = false;
                }
                let out = out?;
                Ok(match out {
                    Out::Unpacked { len, offset } => Data::Block {
                        data: self.unp_buffer.get(..len).unwrap_or_default(),
                        offset,
                    },
                    Out::Filtered { start, len, offset } => Data::Block {
                        data: self
                            .filters
                            .vm_memory
                            .get(start..start + len)
                            .unwrap_or_default(),
                        offset,
                    },
                    Out::Eof { offset } => Data::Eof { offset },
                })
            }
            _ => Err(failed(
                r.base(),
                "Unsupported compression method for RAR file",
            )),
        }
    }

    fn read_data_skip(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        loop {
            if self.bytes_remaining > 0 {
                r.consume(self.bytes_remaining)?;
            }

            // Compressed data to skip must be read from each header in a
            // multivolume archive.
            if self.main_flags & MHD_VOLUME == 0 || self.file_flags & FHD_SPLIT_AFTER == 0 {
                return Ok(Status::Ok);
            }
            let mut ret = r.with_entry(|r, e| self.read_header(r, e))?;
            if ret == Status::Eof {
                ret = r.with_entry(|r, e| self.read_header(r, e))?;
            }
            if ret != Status::Ok {
                return Ok(ret);
            }
        }
    }

    fn seek_data(&mut self, r: &mut Reader<'_>, offset: i64, whence: c_int) -> Result<i64, Error> {
        self.seek(r, offset, whence)
    }

    fn capabilities(&self) -> c_int {
        CAPS_ENCRYPT
    }

    fn has_encrypted_entries(&self) -> c_int {
        self.has_encrypted_entries
    }
}

impl Rar {
    /// `archive_read_format_rar_seek_data`.
    fn seek(&mut self, r: &mut Reader<'_>, offset: i64, whence: c_int) -> Result<i64, Error> {
        let a = r.base();
        if self.compression_method != COMPRESS_METHOD_STORE {
            return Err(Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_MISC,
                "Seeking of compressed RAR files is unsupported",
            ));
        }
        let state_error = || failed(a, "Invalid RAR seek cursor state");
        let dbo = |s: &Rar, i: usize| s.dbo.get(i).copied().ok_or_else(state_error);

        // Modify the offset for use with SEEK_SET.
        let mut client_offset = match Whence::from_c(whence) {
            Some(Whence::Cur) => self.offset_seek,
            Some(Whence::End) => self.unp_size,
            _ => 0,
        };
        client_offset = client_offset.wrapping_add(offset);
        if client_offset < 0 {
            // Can't seek past beginning of data block.
            return Ok(-1);
        } else if client_offset > self.unp_size {
            // Set the returned offset but only seek to the end of the data
            // block.
            self.offset_seek = client_offset;
            client_offset = self.unp_size;
        }

        client_offset = client_offset.wrapping_add(dbo(self, 0)?.start_offset);
        for i in 1..=self.cursor {
            client_offset = client_offset.wrapping_add(
                dbo(self, i)?
                    .start_offset
                    .wrapping_sub(dbo(self, i - 1)?.end_offset),
            );
        }
        if self.main_flags & MHD_VOLUME != 0 {
            // Find the appropriate offset among the multivolume archive.
            loop {
                let current = dbo(self, self.cursor)?;
                if client_offset < current.start_offset && self.file_flags & FHD_SPLIT_BEFORE != 0 {
                    // Search backwards for the correct data block.
                    if self.cursor == 0 {
                        return Err(Error::new(
                            ARCHIVE_FAILED,
                            ARCHIVE_ERRNO_MISC,
                            "Attempt to seek past beginning of RAR data block",
                        ));
                    }
                    self.cursor -= 1;
                    let previous = dbo(self, self.cursor)?;
                    client_offset = client_offset
                        .wrapping_sub(current.start_offset.wrapping_sub(previous.end_offset));
                    if client_offset < previous.start_offset {
                        continue;
                    }
                    r.seek(
                        previous.start_offset.wrapping_sub(previous.header_size),
                        Whence::Set,
                    )?;
                    if r.with_entry(|r, e| self.read_header(r, e)).ok() != Some(Status::Ok) {
                        return Err(Error::new(
                            ARCHIVE_FAILED,
                            ARCHIVE_ERRNO_MISC,
                            "Error during seek of RAR file",
                        ));
                    }
                    self.cursor = self.cursor.saturating_sub(1);
                    break;
                } else if client_offset > current.end_offset
                    && self.file_flags & FHD_SPLIT_AFTER != 0
                {
                    // Search forward for the correct data block.
                    self.cursor += 1;
                    if self.cursor < self.dbo.len() {
                        let next = dbo(self, self.cursor)?;
                        if client_offset > next.end_offset {
                            client_offset = client_offset.wrapping_add(
                                next.start_offset
                                    .wrapping_sub(dbo(self, self.cursor - 1)?.end_offset),
                            );
                            continue;
                        }
                    }
                    self.cursor -= 1;
                    r.seek(dbo(self, self.cursor)?.end_offset, Whence::Set)?;
                    let mut ret = r.with_entry(|r, e| self.read_header(r, e)).ok();
                    if ret == Some(Status::Eof) {
                        ret = r.with_entry(|r, e| self.read_header(r, e)).ok();
                    }
                    if ret != Some(Status::Ok) {
                        return Err(Error::new(
                            ARCHIVE_FAILED,
                            ARCHIVE_ERRNO_MISC,
                            "Error during seek of RAR file",
                        ));
                    }
                    if self.cursor == 0 {
                        return Err(Error::new(
                            ARCHIVE_FAILED,
                            ARCHIVE_ERRNO_MISC,
                            "Invalid RAR seek cursor state",
                        ));
                    }
                    client_offset = client_offset.wrapping_add(
                        dbo(self, self.cursor)?
                            .start_offset
                            .wrapping_sub(dbo(self, self.cursor - 1)?.end_offset),
                    );
                    continue;
                }
                break;
            }
        }

        let mut ret = r.seek(client_offset, Whence::Set)?;
        self.bytes_remaining = dbo(self, self.cursor)?.end_offset.wrapping_sub(ret);
        for i in (0..self.cursor).rev() {
            ret = ret.wrapping_sub(
                dbo(self, i + 1)?
                    .start_offset
                    .wrapping_sub(dbo(self, i)?.end_offset),
            );
        }
        ret = ret.wrapping_sub(dbo(self, 0)?.start_offset);

        // Always restart reading the file after a seek.
        r.reset_read_data();

        self.offset = 0;

        // If a seek past the end of file was requested, return the requested
        // offset.
        if ret == self.unp_size && self.offset_seek > self.unp_size {
            return Ok(self.offset_seek);
        }

        // Return the new offset.
        self.offset_seek = ret;
        Ok(self.offset_seek)
    }
}

/// The byte source of the PPMd range decoder: the bit stream.
struct PpmdInput<'a, 'b> {
    rar: &'a mut Rar,
    r: &'a mut Reader<'b>,
}

impl ByteIn for PpmdInput<'_, '_> {
    /// `ppmd_read`.
    fn read_byte(&mut self) -> u8 {
        if !self.rar.br_read_ahead(self.r, 8) {
            set_error(self.r.base(), "Truncated RAR file data");
            self.rar.valid = false;
            return 0;
        }
        let b = self.rar.br_bits(8) as u8;
        self.rar.br_consume(8);
        b
    }
}

impl Rar {
    // The bit stream reader.

    /// Whether the cache has `n` bits, after reading ahead if need be.
    fn br_read_ahead(&mut self, r: &mut Reader<'_>, n: u32) -> bool {
        self.br.avail >= n || self.br_fillup(r) || self.br.avail >= n
    }

    /// The next `n` bits, once `br_read_ahead` found them.
    fn br_bits(&self, n: u32) -> u32 {
        let shift = self.br.avail.wrapping_sub(n);
        (self.br.cache.checked_shr(shift).unwrap_or(0) as u32) & cache_mask(n)
    }

    fn br_consume(&mut self, n: u32) {
        self.br.avail = self.br.avail.saturating_sub(n);
    }

    /// Shifts away used bits in the cache data and fills it up with
    /// following bits. Call this when the cache does not have enough bits
    /// you need. Returns whether the cache is full; if not, the input is
    /// used up.
    fn br_fillup(&mut self, r: &mut Reader<'_>) -> bool {
        loop {
            let need = ((64 - self.br.avail) >> 3) as usize;
            if need == 0 {
                // We have enough compressed data in the cache.
                return true;
            }
            let Some(avail) = self.read_ahead_len(r, 1) else {
                self.br.ready = false;
                return false;
            };
            self.br.ready = true;
            if avail == 0 {
                return false;
            }
            let n = avail.min(need);
            let Ok(data) = r.peek_available(1) else {
                return false;
            };
            for &b in data.get(..n).unwrap_or_default() {
                self.br.cache = (self.br.cache << 8) | u64::from(b);
            }
            self.br.avail += 8 * n as u32;
            self.bytes_remaining -= n as i64;
            if r.consume(n).is_err() {
                return false;
            }
        }
    }

    /// `rar_br_preparation`.
    fn br_preparation(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        if self.bytes_remaining > 0 {
            if self.read_ahead_len(r, 1).is_none() {
                return Err(fatal(r.base(), "Truncated RAR file data"));
            }
            self.br.ready = true;
            if self.br.avail == 0 {
                self.br_fillup(r);
            }
        }
        Ok(())
    }

    /// `rar_decode_byte`.
    fn decode_byte(&mut self, r: &mut Reader<'_>) -> Option<u8> {
        if !self.br_read_ahead(r, 8) {
            return None;
        }
        let b = self.br_bits(8) as u8;
        self.br_consume(8);
        Some(b)
    }

    /// `read_next_symbol` with one of the codes of the block, or with
    /// `code` for the one that isn't. -1 on failure, with the error set.
    fn read_next_symbol(&mut self, r: &mut Reader<'_>, code: &mut Code) -> i32 {
        let a = r.base();
        if !code.has_table()
            && let Err(msg) = code.make_table()
        {
            set_error(a, msg);
            return -1;
        }

        // Look ahead (peek) at bits.
        let table_size = code.table_size();
        if !self.br_read_ahead(r, table_size) {
            set_error(a, "Truncated RAR file data");
            self.valid = false;
            return -1;
        }
        let entry = code.lookup(self.br_bits(table_size));

        if entry.length <= table_size {
            // Skip length bits.
            self.br_consume(entry.length);
            return entry.value;
        }

        // Skip tablesize bits.
        self.br_consume(table_size);

        let mut node = entry.value;
        loop {
            let Some([b0, b1]) = code.branches(node) else {
                return -1;
            };
            if b0 == b1 {
                return b0;
            }
            if !self.br_read_ahead(r, 1) {
                set_error(a, "Truncated RAR file data");
                self.valid = false;
                return -1;
            }
            let bit = self.br_bits(1);
            self.br_consume(1);

            let next = if bit == 0 { b0 } else { b1 };
            if next < 0 {
                set_error(a, "Invalid prefix code in bitstream");
                return -1;
            }
            node = next;
        }
    }

    fn symbol(&mut self, r: &mut Reader<'_>, which: Which) -> i32 {
        let mut code = std::mem::take(match which {
            Which::Main => &mut self.maincode,
            Which::Offset => &mut self.offsetcode,
            Which::LowOffset => &mut self.lowoffsetcode,
            Which::Length => &mut self.lengthcode,
        });
        let symbol = self.read_next_symbol(r, &mut code);
        *match which {
            Which::Main => &mut self.maincode,
            Which::Offset => &mut self.offsetcode,
            Which::LowOffset => &mut self.lowoffsetcode,
            Which::Length => &mut self.lengthcode,
        } = code;
        symbol
    }

    /// Decodes a PPMd symbol; negative on failure, as in upstream.
    fn ppmd_symbol(&mut self, r: &mut Reader<'_>) -> i32 {
        let Some(mut ppmd) = self.ppmd.take() else {
            return -2;
        };
        let symbol = {
            let mut input = PpmdInput { rar: self, r };
            ppmd.model.decode_symbol(&mut ppmd.range_dec, &mut input)
        };
        self.ppmd = Some(ppmd);
        symbol
    }
}

/// `rar_fls`: the highest bit set in `word`.
fn rar_fls(word: u32) -> u32 {
    if word == 0 { 0 } else { 1 << word.ilog2() }
}

impl Rar {
    fn free_codes(&mut self) {
        self.maincode = Code::default();
        self.offsetcode = Code::default();
        self.lowoffsetcode = Code::default();
        self.lengthcode = Code::default();
    }

    /// Reads `n` bits, failing with upstream's `truncated_data`.
    fn bits(&mut self, r: &mut Reader<'_>, n: u32) -> Result<u32, Error> {
        if !self.br_read_ahead(r, n) {
            return Err(self.truncated(r));
        }
        let bits = self.br_bits(n);
        self.br_consume(n);
        Ok(bits)
    }

    /// `truncated_data`.
    fn truncated(&mut self, r: &Reader<'_>) -> Error {
        self.valid = false;
        failed(r.base(), "Truncated RAR file data")
    }

    /// `parse_codes`: the start of a block.
    fn parse_codes(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let a = r.base();
        self.free_codes();

        // Skip to the next byte.
        self.br.avail &= !7;

        // PPMd block flag.
        self.is_ppmd_block = self.bits(r, 1)? != 0;
        if self.is_ppmd_block {
            let ppmd_flags = self.bits(r, 7)?;

            // Memory is allocated in MB.
            if ppmd_flags & 0x20 != 0 {
                self.dictionary_size = (self.bits(r, 8)? + 1) << 20;
            }

            if ppmd_flags & 0x40 != 0 {
                self.ppmd_escape = self.bits(r, 8)?;
                if let Some(ppmd) = self.ppmd.as_mut() {
                    ppmd.model.init_esc = self.ppmd_escape;
                }
            } else {
                self.ppmd_escape = 2;
            }

            let Some(mut ppmd) = self.ppmd.take() else {
                return Err(Error::silent(ARCHIVE_FATAL));
            };
            let result = self.start_ppmd_block(r, &mut ppmd, ppmd_flags);
            self.ppmd = Some(ppmd);
            result?;
        } else {
            // Low-distance repeat state belongs to the current LZ table and
            // must not be reused after starting a new table.
            self.last_low_offset = 0;
            self.num_low_offset_repeats = 0;

            // Keep existing table flag.
            if self.bits(r, 1)? == 0 {
                self.length_table = [0; HUFFMAN_TABLE_SIZE];
            }

            let mut bitlengths = [0u8; MAX_SYMBOLS];
            let mut i = 0;
            while i < MAX_SYMBOLS {
                let length = self.bits(r, 4)? as u8;
                bitlengths[i] = length;
                i += 1;
                if length == 0xF {
                    let zerocount = self.bits(r, 4)? as usize;
                    if zerocount != 0 {
                        i -= 1;
                        for _ in 0..zerocount + 2 {
                            if i >= MAX_SYMBOLS {
                                break;
                            }
                            bitlengths[i] = 0;
                            i += 1;
                        }
                    }
                }
            }

            let mut precode =
                Code::create(&bitlengths, MAX_SYMBOL_LENGTH).map_err(|m| failed(a, m))?;

            let mut i = 0;
            while i < HUFFMAN_TABLE_SIZE {
                let val = self.read_next_symbol(r, &mut precode);
                if val < 0 {
                    return Err(Error::silent(ARCHIVE_FAILED));
                }
                if val < 16 {
                    if let Some(l) = self.length_table.get_mut(i) {
                        *l = l.wrapping_add(val as u8) & 0xF;
                    }
                    i += 1;
                } else if val < 18 {
                    if i == 0 {
                        return Err(failed(a, "Internal error extracting RAR file"));
                    }

                    let n = (if val == 16 {
                        self.bits(r, 3)? + 3
                    } else {
                        self.bits(r, 7)? + 11
                    }) as usize;

                    for _ in 0..n {
                        if i >= HUFFMAN_TABLE_SIZE {
                            break;
                        }
                        self.length_table[i] = self.length_table[i - 1];
                        i += 1;
                    }
                } else {
                    let n = (if val == 18 {
                        self.bits(r, 3)? + 3
                    } else {
                        self.bits(r, 7)? + 11
                    }) as usize;

                    for _ in 0..n {
                        if i >= HUFFMAN_TABLE_SIZE {
                            break;
                        }
                        self.length_table[i] = 0;
                        i += 1;
                    }
                }
            }

            let table = self.length_table;
            let (main, rest) = table.split_at(MAINCODE_SIZE);
            let (offset, rest) = rest.split_at(OFFSETCODE_SIZE);
            let (low_offset, length) = rest.split_at(LOWOFFSETCODE_SIZE);
            let create =
                |lengths: &[u8]| Code::create(lengths, MAX_SYMBOL_LENGTH).map_err(|m| failed(a, m));
            self.maincode = create(main)?;
            self.offsetcode = create(offset)?;
            self.lowoffsetcode = create(low_offset)?;
            self.lengthcode = create(length)?;
        }

        if self.dictionary_size == 0
            || self.window.is_empty()
            || (self.window.len() as u64) < u64::from(self.dictionary_size)
        {
            // Seems as though dictionary sizes are not used. Even so,
            // minimize memory usage as much as possible.
            let new_size = if self.unp_size >= DICTIONARY_MAX_SIZE {
                DICTIONARY_MAX_SIZE as u32
            } else {
                rar_fls(self.unp_size as u32) << 1
            };
            if new_size == 0 {
                return Err(failed(a, "Zero window size is invalid"));
            }
            if u64::from(new_size) > r.decoder_memory(u64::MAX) {
                return Err(Error::fatal(
                    libc::ENOMEM,
                    "RAR window requires too much memory",
                ));
            }
            self.window.clear();
            if self.window.try_reserve_exact(new_size as usize).is_err() {
                return Err(Error::fatal(
                    libc::ENOMEM,
                    "Unable to allocate memory for uncompressed data",
                ));
            }
            self.window.resize(new_size as usize, 0);
            self.dictionary_size = new_size;
        }

        self.start_new_table = false;
        Ok(())
    }

    /// The part of `parse_codes` that starts a PPMd block, whose flags are
    /// `ppmd_flags`.
    fn start_ppmd_block(
        &mut self,
        r: &mut Reader<'_>,
        ppmd: &mut Ppmd,
        ppmd_flags: u32,
    ) -> Result<(), Error> {
        let a = r.base();
        if ppmd_flags & 0x20 != 0 {
            let mut max_order = (ppmd_flags & 0x1F) + 1;
            if max_order > 16 {
                max_order = 16 + (max_order - 16) * 3;
            }

            if max_order == 1 {
                return Err(failed(a, "Truncated RAR file data"));
            }

            // Make sure the model is freed before it is allocated, because
            // reading a broken file causes this abnormal sequence.
            ppmd.model.free();

            let allocation = u64::from(self.dictionary_size)
                + u64::from(4 - (self.dictionary_size & 3))
                + u64::from(crate::ppmd::UNIT_SIZE);
            if allocation > r.decoder_memory(u64::MAX) {
                return Err(Error::fatal(
                    libc::ENOMEM,
                    "PPMd model requires too much memory",
                ));
            }
            if !ppmd.model.alloc(self.dictionary_size) {
                return Err(Error::fatal(libc::ENOMEM, "Out of memory"));
            }
            let mut input = PpmdInput { rar: self, r };
            if !ppmd.range_dec.init(&mut input) {
                return Err(failed(a, "Unable to initialize PPMd range decoder"));
            }
            ppmd.model.init(max_order);
            self.ppmd_valid = true;
        } else {
            if !self.ppmd_valid {
                return Err(failed(a, "Invalid PPMd sequence"));
            }
            let mut input = PpmdInput { rar: self, r };
            if !ppmd.range_dec.init(&mut input) {
                return Err(failed(a, "Unable to initialize PPMd range decoder"));
            }
        }
        Ok(())
    }
}

impl Rar {
    // The LZSS window.

    fn emit_literal(&mut self, literal: u8) {
        let mask = self.window.len().wrapping_sub(1);
        if let Some(b) = self.window.get_mut(self.position as usize & mask) {
            *b = literal;
        }
        self.position += 1;
    }

    fn emit_match(&mut self, offset: usize, length: usize) {
        let size = self.window.len();
        if size == 0 {
            return;
        }
        let mask = size - 1;
        let mut dstoffs = self.position as usize & mask;
        let mut srcoffs = dstoffs.wrapping_sub(offset) & mask;

        let mut remaining = length;
        while remaining > 0 {
            let mut l = remaining;
            if dstoffs > srcoffs {
                l = l.min(size - dstoffs);
            } else {
                l = l.min(size - srcoffs);
            }
            if dstoffs + l < srcoffs || srcoffs + l < dstoffs {
                self.window.copy_within(srcoffs..srcoffs + l, dstoffs);
            } else {
                // An overlapping copy repeats the bytes it has just written.
                for li in 0..l {
                    self.window[dstoffs + li] = self.window[srcoffs + li];
                }
            }
            remaining -= l;
            dstoffs = (dstoffs + l) & mask;
            srcoffs = (srcoffs + l) & mask;
        }
        self.position += length as i64;
    }

    /// `copy_from_lzss_window`: `length` bytes of the `window` from
    /// `startpos` into `buffer`.
    fn copy_from_lzss_window(
        a: &Base,
        window: &[u8],
        buffer: &mut [u8],
        startpos: i64,
        length: usize,
    ) -> Result<(), Error> {
        let size = window.len();
        let windowoffs = (startpos as usize) & size.wrapping_sub(1);
        if length > size {
            return Err(failed(a, "Bad RAR file data"));
        }
        let firstpart = size.wrapping_sub(windowoffs);
        let bad = || failed(a, "Bad RAR file data");
        if firstpart < length {
            let (first, second) = buffer
                .get_mut(..length)
                .ok_or_else(bad)?
                .split_at_mut(firstpart);
            first.copy_from_slice(window.get(windowoffs..).ok_or_else(bad)?);
            second.copy_from_slice(window.get(..length - firstpart).ok_or_else(bad)?);
        } else {
            buffer.get_mut(..length).ok_or_else(bad)?.copy_from_slice(
                window
                    .get(windowoffs..windowoffs + length)
                    .ok_or_else(bad)?,
            );
        }
        Ok(())
    }

    /// `copy_from_lzss_window_to_unp`: appends `length` bytes of the window
    /// from `startpos` to the output buffer. True if the buffer is full.
    fn copy_from_lzss_window_to_unp(
        &mut self,
        a: &Base,
        startpos: i64,
        length: usize,
    ) -> Result<bool, Error> {
        let bad = || failed(a, "Bad RAR file data");
        if length > UNP_BUFFER_SIZE {
            return Err(bad());
        }

        if self.unp_buffer.is_empty() {
            if self.unp_buffer.try_reserve_exact(UNP_BUFFER_SIZE).is_err() {
                return Err(Error::fatal(
                    libc::ENOMEM,
                    "Unable to allocate memory for uncompressed data",
                ));
            }
            self.unp_buffer.resize(UNP_BUFFER_SIZE, 0);
        }

        let size = self.window.len();
        let windowoffs = (startpos as usize) & size.wrapping_sub(1);
        let dest = self
            .unp_buffer
            .get_mut(self.unp_offset..self.unp_offset + length)
            .ok_or_else(bad)?;
        if windowoffs + length <= size {
            dest.copy_from_slice(
                self.window
                    .get(windowoffs..windowoffs + length)
                    .ok_or_else(bad)?,
            );
        } else if length <= size {
            let firstpart = size - windowoffs;
            let (first, second) = dest.split_at_mut(firstpart);
            first.copy_from_slice(self.window.get(windowoffs..).ok_or_else(bad)?);
            second.copy_from_slice(self.window.get(..length - firstpart).ok_or_else(bad)?);
        } else {
            return Err(bad());
        }
        self.unp_offset += length;
        Ok(self.unp_offset >= UNP_BUFFER_SIZE)
    }

    /// `expand`: decodes LZSS until the window position reaches `end`, which
    /// is lowered to where decoding stopped if that is earlier.
    fn expand(&mut self, r: &mut Reader<'_>, end: &mut i64) -> Result<(), Error> {
        let a = r.base();
        let bad_data = || failed(a, "Bad RAR file data");

        if self.filters.filter_start < *end {
            *end = self.filters.filter_start;
        }

        loop {
            if self.position >= *end {
                return Ok(());
            }

            if self.is_ppmd_block {
                *end = self.position;
                return Ok(());
            }

            let symbol = self.symbol(r, Which::Main);
            if symbol < 0 {
                return Err(bad_data());
            }

            let offs: u32;
            let len: u32;
            if symbol < 256 {
                r.decoded(1u64)?;
                self.emit_literal(symbol as u8);
                continue;
            } else if symbol == 256 {
                let newfile = self.bits(r, 1)? == 0;
                if newfile {
                    self.start_new_table = self.bits(r, 1)? != 0;
                    *end = self.position;
                    return Ok(());
                }
                if self.parse_codes(r).is_err() {
                    return Err(bad_data());
                }
                continue;
            } else if symbol == 257 {
                if !self.read_filter(r, end) {
                    return Err(bad_data());
                }
                continue;
            } else if symbol == 258 {
                if self.last_length == 0 {
                    continue;
                }
                offs = self.last_offset;
                len = self.last_length;
            } else if symbol <= 262 {
                let offsindex = (symbol - 259) as usize;
                offs = self.old_offset.get(offsindex).copied().unwrap_or(0);

                let lensymbol = self.symbol(r, Which::Length);
                if lensymbol < 0 {
                    return Err(bad_data());
                }
                let Some((&base, &bits)) = LENGTH_BASES
                    .get(lensymbol as usize)
                    .zip(LENGTH_BITS.get(lensymbol as usize))
                else {
                    return Err(bad_data());
                };
                let mut l = u32::from(base) + 2;
                if bits > 0 {
                    l += self.bits(r, u32::from(bits))?;
                }
                len = l;

                for i in (1..=offsindex).rev() {
                    self.old_offset[i] = self.old_offset[i - 1];
                }
                self.old_offset[0] = offs;
            } else if symbol <= 270 {
                let index = (symbol - 263) as usize;
                let (Some(&base), Some(&bits)) = (SHORT_BASES.get(index), SHORT_BITS.get(index))
                else {
                    return Err(bad_data());
                };
                let mut o = u32::from(base) + 1;
                if bits > 0 {
                    o += self.bits(r, u32::from(bits))?;
                }
                offs = o;
                len = 2;

                self.old_offset.copy_within(0..3, 1);
                self.old_offset[0] = offs;
            } else {
                let Some((&base, &bits)) = LENGTH_BASES
                    .get((symbol - 271) as usize)
                    .zip(LENGTH_BITS.get((symbol - 271) as usize))
                else {
                    return Err(bad_data());
                };
                let mut l = u32::from(base) + 3;
                if bits > 0 {
                    l += self.bits(r, u32::from(bits))?;
                }

                let offssymbol = self.symbol(r, Which::Offset);
                if offssymbol < 0 {
                    return Err(bad_data());
                }
                let Some((&base, &bits)) = OFFSET_BASES
                    .get(offssymbol as usize)
                    .zip(OFFSET_BITS.get(offssymbol as usize))
                else {
                    return Err(bad_data());
                };
                let mut o = base + 1;
                if bits > 0 {
                    if offssymbol > 9 {
                        if bits > 4 {
                            o += self.bits(r, u32::from(bits) - 4)? << 4;
                        }

                        if self.num_low_offset_repeats > 0 {
                            self.num_low_offset_repeats -= 1;
                            o += self.last_low_offset;
                        } else {
                            let lowoffsetsymbol = self.symbol(r, Which::LowOffset);
                            if lowoffsetsymbol < 0 {
                                return Err(bad_data());
                            }
                            if lowoffsetsymbol == 16 {
                                self.num_low_offset_repeats = 15;
                                o += self.last_low_offset;
                            } else {
                                o += lowoffsetsymbol as u32;
                                self.last_low_offset = lowoffsetsymbol as u32;
                            }
                        }
                    } else {
                        o += self.bits(r, u32::from(bits))?;
                    }
                }

                if o >= 0x40000 {
                    l += 1;
                }
                if o >= 0x2000 {
                    l += 1;
                }
                offs = o;
                len = l;

                self.old_offset.copy_within(0..3, 1);
                self.old_offset[0] = offs;
            }

            self.last_offset = offs;
            self.last_length = len;

            r.decoded(len)?;
            self.emit_match(offs as usize, len as usize);
        }
    }
}

impl Rar {
    /// `read_filter`: reads a filter's definition from the bit stream.
    fn read_filter(&mut self, r: &mut Reader<'_>, end: &mut i64) -> bool {
        let Some(flags) = self.decode_byte(r) else {
            return false;
        };
        let mut length = u16::from(flags & 0x07) + 1;
        if length == 7 {
            let Some(val) = self.decode_byte(r) else {
                return false;
            };
            length = u16::from(val) + 7;
        } else if length == 8 {
            let Some(high) = self.decode_byte(r) else {
                return false;
            };
            let Some(low) = self.decode_byte(r) else {
                return false;
            };
            length = (u16::from(high) << 8) | u16::from(low);
        }

        let mut code = Vec::with_capacity(usize::from(length));
        for _ in 0..length {
            let Some(b) = self.decode_byte(r) else {
                return false;
            };
            code.push(b);
        }
        if !self.filters.parse(
            &code,
            flags,
            self.position,
            self.dictionary_size,
            self.window.len(),
        ) {
            return false;
        }

        if self.filters.filter_start < *end {
            *end = self.filters.filter_start;
        }

        true
    }

    /// `run_filters`: decodes the block the first filter applies to, and
    /// runs the filters on it. The output is left in the filters for
    /// `read_data_compressed` to hand out.
    fn run_filters(&mut self, r: &mut Reader<'_>) -> bool {
        let a = r.base();
        let Some(mut filter) = self.filters.stack.front().cloned() else {
            return false;
        };

        let start = self.filters.filter_start as usize;
        let block_length = filter.block_length as usize;
        let end = start.wrapping_add(block_length);

        self.filters.filter_start = i64::MAX;
        let mut tend = end as i64;
        if self.expand(r, &mut tend).is_err() {
            return false;
        }

        // Check if the filter stack was modified in expand().
        if !self.filters.stack.iter().any(|f| f.id() == filter.id()) {
            return false;
        }

        if tend < 0 {
            return false;
        }
        let end = tend as usize;
        if end != start.wrapping_add(block_length) {
            set_error(
                a,
                "Bad RAR file data: filter block was not fully decompressed",
            );
            return false;
        }

        if !self.filters.alloc_vm() {
            return false;
        }

        if block_length > filters::VM_MEMORY_SIZE {
            set_error(a, "Bad RAR file data");
            return false;
        }

        if Rar::copy_from_lzss_window(
            a,
            &self.window,
            &mut self.filters.vm_memory,
            start as i64,
            block_length,
        )
        .is_err()
        {
            return false;
        }
        let position = self.offset as usize;
        let mut output = match self.execute_filter(a, &mut filter, position) {
            Some(output) => output,
            None => return false,
        };
        self.filters.stack.pop_front();

        while let Some(next) = self.filters.stack.front().cloned() {
            if next.block_start_pos as i64 != self.filters.filter_start
                || next.block_length as usize != output.length
            {
                break;
            }
            let memory = &mut self.filters.vm_memory;
            if output
                .address
                .checked_add(output.length)
                .is_none_or(|e| e > memory.len())
            {
                return false;
            }
            memory.copy_within(output.address..output.address + output.length, 0);
            let mut next = next;
            output = match self.execute_filter(a, &mut next, position) {
                Some(output) => output,
                None => return false,
            };
            self.filters.stack.pop_front();
        }

        if let Some(next) = self.filters.stack.front() {
            if (next.block_start_pos as usize) < end {
                return false;
            }
            self.filters.filter_start = next.block_start_pos as i64;
        }

        self.filters.last_end = end as i64;
        self.filters.bytes = output.address;
        self.filters.bytes_ready = output.length;

        true
    }

    /// `execute_filter`: where the output of the filter is, if it ran.
    fn execute_filter(
        &mut self,
        a: &Base,
        filter: &mut filters::Filter,
        position: usize,
    ) -> Option<filters::Filtered> {
        match self.filters.execute(filter, position) {
            None => {
                set_error(a, "No support for RAR VM program filter");
                None
            }
            Some(false) => None,
            Some(true) => Some(filter.output()),
        }
    }
}

impl Rar {
    /// Hands out the first `len` bytes of the output buffer.
    fn unpacked(&mut self, len: usize) -> Out {
        let offset = self.offset_outgoing;
        self.offset_outgoing += len as i64;
        // Calculate File CRC.
        self.crc_calculated = crc32(
            self.crc_calculated,
            self.unp_buffer.get(..len).unwrap_or_default(),
        );
        Out::Unpacked { len, offset }
    }

    /// How much of `bytes_uncopied` fits in the output buffer.
    fn copy_size(&self) -> usize {
        let room = (UNP_BUFFER_SIZE - self.unp_offset) as i64;
        usize::try_from(self.bytes_uncopied.min(room)).unwrap_or(usize::MAX)
    }

    /// `read_data_compressed`.
    fn read_data_compressed(&mut self, r: &mut Reader<'_>) -> Result<Out, Error> {
        let a = r.base();
        let mut looper = 0;
        'restart: loop {
            if looper > MAX_COMPRESS_DEPTH {
                return Err(Error::silent(ARCHIVE_FAILED));
            }
            looper += 1;

            loop {
                if !self.valid {
                    return Err(Error::silent(ARCHIVE_FAILED));
                }

                if self.filters.bytes_ready > 0 {
                    // Flush unp_buffer first.
                    if self.unp_offset > 0 {
                        let len = self.unp_offset;
                        self.unp_offset = 0;
                        return Ok(self.unpacked(len));
                    }
                    let start = self.filters.bytes;
                    let len = self.filters.bytes_ready;

                    self.offset += len as i64;
                    let offset = self.offset_outgoing;
                    self.offset_outgoing += len as i64;

                    self.filters.bytes_ready -= len;
                    self.filters.bytes += len;
                    self.crc_calculated = crc32(
                        self.crc_calculated,
                        self.filters
                            .vm_memory
                            .get(start..start + len)
                            .unwrap_or_default(),
                    );
                    return Ok(Out::Filtered { start, len, offset });
                }

                if self.ppmd_eod || (self.dictionary_size != 0 && self.offset >= self.unp_size) {
                    if self.unp_offset > 0 {
                        // We have unprocessed extracted data. Write it out.
                        let len = self.unp_offset;
                        self.unp_offset = 0;
                        return Ok(self.unpacked(len));
                    }
                    if self.file_crc != self.crc_calculated {
                        return Err(failed(a, "File CRC error"));
                    }
                    self.entry_eof = true;
                    return Ok(Out::Eof {
                        offset: self.offset,
                    });
                }

                if !self.is_ppmd_block && self.dictionary_size != 0 && self.bytes_uncopied > 0 {
                    let bs = self.copy_size();
                    let full = self.copy_from_lzss_window_to_unp(a, self.offset, bs)?;
                    self.offset += bs as i64;
                    self.bytes_uncopied -= bs as i64;
                    if full {
                        self.unp_offset = 0;
                        return Ok(self.unpacked(UNP_BUFFER_SIZE));
                    }
                    continue;
                }

                if self.filters.last_end == self.filters.filter_start {
                    if !self.run_filters(r) {
                        return Err(Error::silent(ARCHIVE_FAILED));
                    }
                    continue;
                }

                if !self.br.ready {
                    self.br_preparation(r)?;
                }
                if self.start_new_table {
                    self.parse_codes(r)?;
                }

                if self.is_ppmd_block {
                    let invalid = || failed(a, "Invalid symbol");
                    let sym = self.ppmd_symbol(r);
                    if sym < 0 {
                        return Err(invalid());
                    }
                    if sym as u32 != self.ppmd_escape {
                        r.decoded(1u64)?;
                        self.emit_literal(sym as u8);
                        self.bytes_uncopied += 1;
                    } else {
                        let code = self.ppmd_symbol(r);
                        if code < 0 {
                            return Err(invalid());
                        }

                        match code {
                            0 => {
                                self.start_new_table = true;
                                continue 'restart;
                            }

                            2 => {
                                // End Of ppmd Data.
                                self.ppmd_eod = true;
                                continue;
                            }

                            3 => {
                                a.set_error(
                                    ARCHIVE_ERRNO_MISC,
                                    Some(b"Parsing filters is unsupported"),
                                );
                                return Err(Error::silent(ARCHIVE_FAILED));
                            }

                            4 => {
                                let mut lzss_offset = 0;
                                for i in (0..=2).rev() {
                                    let code = self.ppmd_symbol(r);
                                    if code < 0 {
                                        return Err(invalid());
                                    }
                                    lzss_offset |= code << (i * 8);
                                }
                                let length = self.ppmd_symbol(r);
                                if length < 0 {
                                    return Err(invalid());
                                }
                                r.decoded(u64::try_from(length).unwrap_or(0) + 32)?;
                                self.emit_match(lzss_offset as usize + 2, length as usize + 32);
                                self.bytes_uncopied += i64::from(length) + 32;
                            }

                            5 => {
                                let length = self.ppmd_symbol(r);
                                if length < 0 {
                                    return Err(invalid());
                                }
                                r.decoded(u64::try_from(length).unwrap_or(0) + 4)?;
                                self.emit_match(1, length as usize + 4);
                                self.bytes_uncopied += i64::from(length) + 4;
                            }

                            _ => {
                                r.decoded(1u64)?;
                                self.emit_literal(sym as u8);
                                self.bytes_uncopied += 1;
                            }
                        }
                    }
                } else {
                    let start = self.offset;
                    let mut end = start + i64::from(self.dictionary_size);

                    // We don't want to overflow the window and overwrite data
                    // that we write at 'start'. Therefore, reduce the end
                    // length by the maximum match size, which is 260 bytes.
                    // You can compute this maximum by looking at the
                    // definition of 'expand', in particular when
                    // 'symbol >= 271'.
                    // NOTE: It's possible for 'dictionary_size' to be less
                    // than this 260 value, however that will only be the case
                    // when 'unp_size' is small, which should only happen when
                    // the entry size is small and there's no risk of
                    // overflowing the buffer.
                    if self.dictionary_size > 260 {
                        end -= 260;
                    }

                    if self.filters.filter_start < end {
                        end = self.filters.filter_start;
                    }

                    self.expand(r, &mut end)?;

                    self.bytes_uncopied = end - start;
                    self.filters.last_end = end;
                    if self.filters.last_end != self.filters.filter_start
                        && self.bytes_uncopied == 0
                    {
                        // Broken RAR files cause this case.
                        // NOTE: If this case were possible on a normal RAR
                        // file we would find out where it was actually bad
                        // and what we would do to solve it.
                        return Err(failed(a, "Internal error extracting RAR file"));
                    }
                }
                let bs = self.copy_size();
                let full = self.copy_from_lzss_window_to_unp(a, self.offset, bs)?;
                self.offset += bs as i64;
                self.bytes_uncopied -= bs as i64;
                // If the buffer is not full, we have to continue extracting
                // a RAR file.
                if full {
                    self.unp_offset = 0;
                    return Ok(self.unpacked(UNP_BUFFER_SIZE));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_charge_window_production_before_output_is_returned() {
        use crate::archive::{ARCHIVE_OK, Base, READ_MAGIC};
        use crate::read::ReadLimits;
        let a = Base::new(READ_MAGIC);
        let mut read = Read::default();
        assert_eq!(
            read.set_limits(
                &a,
                ReadLimits {
                    decoded_bytes: Some(1),
                    ..ReadLimits::default()
                }
            ),
            ARCHIVE_OK
        );
        let mut rar = Rar::new();
        rar.window = vec![0; 8];
        rar.filters.filter_start = i64::MAX;
        rar.br.avail = 32;
        rar.br.ready = true;
        rar.maincode = Code::create(&[1, 1], MAX_SYMBOL_LENGTH).unwrap();
        let e = rar.expand(&mut read.reader(&a), &mut 4).unwrap_err();
        assert_eq!(e.errno, libc::EFBIG);
        assert_eq!(rar.position, 1);
        assert!(rar.unp_buffer.is_empty());
    }

    /// The Unicode name decoder against upstream's, compiled from the
    /// pinned source: (case, size, end, FNV-1a of the name and its two
    /// terminating NULs). The names are pseudo-random bytes with a NUL
    /// somewhere, which is what makes `read_header` decode one.
    #[test]
    fn unicode_names_decode_as_upstream_does() {
        let case_name = |case: u64| {
            let mut state = 77 + case;
            let mut rnd = move || {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 33) as u32
            };
            let n = 1 + rnd() % 40;
            let zpos = (rnd() % n) as usize;
            let mut name: Vec<u8> = (0..n)
                .map(|_| if rnd() % 7 == 0 { 0 } else { rnd() as u8 })
                .collect();
            if !case.is_multiple_of(5) {
                name[zpos] = 0;
            }
            name
        };
        let fnv = |bytes: &[u8]| {
            bytes.iter().fold(2166136261u32, |h, &b| {
                (h ^ u32::from(b)).wrapping_mul(16777619)
            })
        };
        let expected = [
            (0, 65, 19, 0x15d03f7d),
            (1, 79, 17, 0x41244716),
            (2, 75, 12, 0x7171b0ca),
            (3, 1, 4, 0x117697cd),
            (4, 1, 3, 0x117697cd),
            (5, 1, 9, 0x117697cd),
            (6, 17, 16, 0x9c17d519),
            (7, 31, 10, 0xd295c06f),
            (8, 43, 19, 0xc2035e45),
            (9, 57, 7, 0x6e3089ce),
            (10, 53, 13, 0x97a54716),
            (11, 67, 18, 0xc4a8e2f3),
            (12, 81, 9, 0xa9672943),
            (13, 77, 24, 0x637411d5),
            (14, 1, 5, 0x117697cd),
            (15, 25, 6, 0xdb6975d7),
            (16, 1, 10, 0x117697cd),
            (17, 17, 17, 0xed018392),
            (18, 49, 6, 0xac1141cf),
            (19, 45, 11, 0xb3cdc07),
            (20, 59, 20, 0x852c36d3),
            (21, 73, 8, 0x40220565),
            (22, 69, 23, 0xa906fb95),
            (23, 1, 1, 0x117697cd),
            (24, 3, 8, 0xada63f00),
            (26, 27, 9, 0x9bb864ff),
            (27, 41, 12, 0x37cf57fc),
            (28, 37, 17, 0x7747a2bf),
            (29, 51, 13, 0xf6076853),
            (30, 63, 23, 0xf2de5873),
            (31, 61, 8, 0xdec9c77),
            (32, 75, 31, 0x8a5c8640),
            (33, 71, 19, 0x4018bd0b),
            (34, 1, 2, 0x117697cd),
            (35, 19, 7, 0xcaa85d73),
            (36, 5, 7, 0x1595ae9e),
            (37, 15, 14, 0x6b70533b),
            (38, 43, 11, 0xec62ffe6),
            (39, 39, 8, 0x3a0d028d),
            (40, 53, 26, 0xad0cfcce),
        ];
        for (case, size, end, hash) in expected {
            let name = case_name(case);
            let decoded = decode_unicode_name(&name);
            assert_eq!(
                (decoded.size, decoded.end, fnv(&decoded.buf)),
                (size, end, hash),
                "case {case}"
            );
        }
    }
}
