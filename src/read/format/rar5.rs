/*-
* Copyright (c) 2018 Grzegorz Antoniak (http://antoniak.org)
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

// Ported from libarchive/archive_read_support_format_rar5.c.

//! The RAR 5.0 format: the headers, solid and multivolume archives, the
//! checksums and the data flow. `decompress` has the LZ decoder and
//! `filter` the post-processing filters.

mod decompress;
mod filter;

use crate::archive::*;
use crate::blake2sp_ref::Blake2sp;
use crate::crc32::crc32;
use crate::entry::{AE_IFDIR, AE_IFLNK, AE_IFREG, Entry, Mode};
use crate::read::{
    ARCHIVE_ERRNO_FILE_FORMAT, ARCHIVE_ERRNO_PROGRAMMER, CAPS_ENCRYPT, Data, ENCRYPTION_DONT_KNOW,
    Format, Read, Reader, Status, format_code,
};
use crate::time::ntfs_to_unix;
use crate::util::Error;
use decompress::{BitPos, DecodeTable};
use filter::Filter;
use std::collections::VecDeque;
use std::ffi::c_int;

/// The signature, "Rar!\x1a\x07\x01\x00". Upstream stores it XORed with 0xA1
/// so that programs that scan for the marker don't trigger on its own binary.
const SIGNATURE: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];

/// Bid returned when the RAR5 signature is found at offset 0.  Bidders
/// conventionally return the number of bits they verified, so an exact
/// match of the 8-byte signature bids 64 (like the ar and warc readers
/// do for their 8-byte magics).  This must stay above the seekable Zip
/// bidder's 32 so that a RAR archive which merely stores an uncompressed
/// Zip is still recognized as RAR (see issue #2249).  The weaker SFX
/// heuristic, which only scans for the signature somewhere inside an
/// executable, deliberately keeps its lower bid of 30.
const SIGNATURE_BID: c_int = 64;

const UNPACK_WINDOW_SIZE: u64 = 0x20000;
const MAX_NAME_IN_CHARS: usize = 2048;
/// Maximum header size for RAR5 is 2MB.
const MAX_HEADER_SIZE: usize = 2 * 1024 * 1024;
const OWNER_MAXNAMELEN: usize = 256;
const SFX_MAX_READAHEAD: usize = 1024 * 512;

const AE_SYMLINK_TYPE_FILE: c_int = 1;
const AE_SYMLINK_TYPE_DIRECTORY: c_int = 2;

const HFL_EXTRA_DATA: usize = 0x0001;
const HFL_DATA: usize = 0x0002;
const HFL_SKIP_IF_UNKNOWN: usize = 0x0004;
const HFL_SPLIT_BEFORE: usize = 0x0008;
const HFL_SPLIT_AFTER: usize = 0x0010;

const EX_CRYPT: u64 = 0x01;
const EX_HASH: u64 = 0x02;
const EX_HTIME: u64 = 0x03;
const EX_VERSION: u64 = 0x04;
const EX_REDIR: u64 = 0x05;
const EX_UOWNER: u64 = 0x06;

const REDIR_SYMLINK_IS_DIR: u64 = 1;
const REDIR_TYPE_NONE: u64 = 0;
const REDIR_TYPE_UNIXSYMLINK: u64 = 1;
const REDIR_TYPE_WINSYMLINK: u64 = 2;
const REDIR_TYPE_HARDLINK: u64 = 4;

const OWNER_USER_NAME: u64 = 0x01;
const OWNER_GROUP_NAME: u64 = 0x02;
const OWNER_USER_UID: u64 = 0x04;
const OWNER_GROUP_GID: u64 = 0x08;

const HEAD_MARK: usize = 0x00;
const HEAD_MAIN: usize = 0x01;
const HEAD_FILE: usize = 0x02;
const HEAD_SERVICE: usize = 0x03;
const HEAD_CRYPT: usize = 0x04;
const HEAD_ENDARC: usize = 0x05;

/// The filters' queue holds at most this many entries.
const MAX_FILTERS: usize = 8192;

/// Why a step stopped other than by finishing: upstream's `ARCHIVE_EOF`
/// return, or a failure with its error. (`ARCHIVE_RETRY` is `Step::Retry`.)
enum Stop {
    Eof,
    Err(Error),
}

impl From<Error> for Stop {
    fn from(e: Error) -> Stop {
        Stop::Err(e)
    }
}

type Res<T> = Result<T, Stop>;

#[derive(PartialEq)]
enum Step {
    Ok,
    Retry,
}

fn fatal(errno: c_int, msg: impl Into<Vec<u8>>) -> Stop {
    Stop::Err(Error::fatal(errno, msg))
}

fn failed(errno: c_int, msg: impl Into<Vec<u8>>) -> Stop {
    Stop::Err(Error::new(ARCHIVE_FAILED, errno, msg))
}

fn format_error(msg: impl Into<Vec<u8>>) -> Stop {
    fatal(ARCHIVE_ERRNO_FILE_FORMAT, msg)
}

/// A failure upstream reports without a message of its own.
fn silent_fatal() -> Stop {
    Stop::Err(Error::silent(ARCHIVE_FATAL))
}

/// Upstream returns `ARCHIVE_EOF` where a consume fails, so the caller sees
/// the end of the archive (the message is on the handle).
fn consume_or_eof(r: &mut Reader<'_>, n: impl TryInto<i64>) -> Res<()> {
    r.consume(n).map_err(|_| Stop::Eof)
}

fn ahead<'a>(r: &'a mut Reader<'_>, n: usize) -> Option<&'a [u8]> {
    r.read_ahead(n).ok().flatten()
}

fn read_u32(r: &mut Reader<'_>) -> Option<u32> {
    let v = u32::from_le_bytes(*ahead(r, 4)?.first_chunk()?);
    r.consume(4usize).ok()?;
    Some(v)
}

fn read_u64(r: &mut Reader<'_>) -> Option<u64> {
    let v = u64::from_le_bytes(*ahead(r, 8)?.first_chunk()?);
    r.consume(8usize).ok()?;
    Some(v)
}

/// Reads a RAR5 variable sized numeric value. Returns the value and the byte
/// count of the number, which the caller has to consume.
///
/// Up to 10 bytes are read, since that's the longest a RAR5 varint can
/// legally be. A varint is self-terminating (a byte with the MSB clear ends
/// the value), and it's legal for one to end fewer than 10 bytes before the
/// end of the archive, e.g. a file header's extra field butting up against
/// ENDARC with no padding. So decode within however many bytes remain; only
/// reaching the real end of the archive with zero bytes left, or exhausting
/// the available bytes without hitting a terminator, is an error.
fn peek_var(r: &mut Reader<'_>) -> Res<(u64, usize)> {
    let a = r.base();
    let p = r.peek_available(10).map_err(|_| silent_fatal())?;
    if p.is_empty() {
        return Err(Stop::Eof);
    }
    let mut multiplier: u64 = 1;
    let mut result: u64 = 0;
    for (i, &b) in p.iter().take(10).enumerate() {
        // Strip the MSB from the input byte and add the resulting number to
        // the `result`.
        let Some(sum) = u64::from(b & 0x7F)
            .checked_mul(multiplier)
            .and_then(|val| result.checked_add(val))
        else {
            a.set_error(ARCHIVE_ERRNO_FILE_FORMAT, Some(b"Number too large"));
            return Err(silent_fatal());
        };
        result = sum;
        // MSB set to 0 means we're done.
        if b & 0x80 == 0 {
            return Ok((result, 1 + i));
        }
        multiplier = multiplier.wrapping_mul(128);
    }
    // Either all 10 bytes had their continuation bit set (a malformed
    // varint), or fewer than 10 bytes were available and none of them
    // terminated the value (a truncated archive).
    Err(silent_fatal())
}

/// `peek_var` for a value that has to fit a `usize`.
fn peek_size(r: &mut Reader<'_>) -> Res<(usize, usize)> {
    let (v, len) = peek_var(r)?;
    match usize::try_from(v) {
        Ok(v) => Ok((v, len)),
        Err(_) => {
            r.base()
                .set_error(ARCHIVE_ERRNO_FILE_FORMAT, Some(b"Number too large"));
            Err(silent_fatal())
        }
    }
}

/// A varint, consumed.
fn take_var(r: &mut Reader<'_>) -> Res<u64> {
    let (v, len) = peek_var(r)?;
    r.consume(len).map_err(|_| silent_fatal())?;
    Ok(v)
}

/// A varint that fits a `usize`, consumed.
fn take_size(r: &mut Reader<'_>) -> Res<usize> {
    let (v, len) = peek_size(r)?;
    r.consume(len).map_err(|_| silent_fatal())?;
    Ok(v)
}

/// The text of a C string argument: up to the first NUL.
fn c_str(bytes: &[u8]) -> &[u8] {
    bytes.split(|&b| b == 0).next().unwrap_or_default()
}

fn truncated_multivolume_error() -> Stop {
    // Report that the archive ended while the current file was still
    // expected to continue in a following volume (its header had the 'split
    // after' flag set), which typically happens when a multivolume set is
    // opened without supplying its later volumes.  Returning a clean EOF
    // here would silently hand back a short, corrupted read, so this is a
    // fatal error.
    format_error(
        "Truncated RAR5 archive: file continues in a subsequent volume that is not available",
    )
}

fn alloc_zeroed(n: usize) -> Option<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).ok()?;
    v.resize(n, 0);
    Some(v)
}

#[derive(Default)]
struct File {
    bytes_remaining: i64,
    unpacked_size: i64,
    /// Used in sanity checks.
    last_offset: i64,
    last_size: i64,

    solid: bool,
    /// Is this file service data?
    service: bool,
    /// Did we finish unpacking the file?
    eof: bool,
    dir: bool,

    stored_crc32: u32,
    calculated_crc32: u32,
    blake2sp: [u8; 32],
    b2state: Option<Blake2sp>,
    has_blake2: bool,

    redir_type: u64,

    /// Used in file format check.
    solid_window_size: i64,
}

#[derive(Default)]
struct Main {
    solid: bool,
    volume: bool,
    endarc: bool,
    vol_no: u32,
}

#[derive(Default)]
struct Generic {
    split_after: bool,
    split_before: bool,
    last_header_id: usize,
}

#[derive(Default)]
struct Multivolume {
    expected_vol_no: u32,
    push_buf: Vec<u8>,
}

/// Which buffer a pending output range lives in.
#[derive(Clone, Copy)]
enum Buf {
    Window,
    Filtered,
}

/// A range of unpacked data waiting for `read_data` to hand it out.
#[derive(Clone, Copy)]
struct DataReady {
    buf: Buf,
    start: usize,
    size: usize,
    offset: i64,
}

#[derive(Default)]
struct CompState {
    /// Flag used to specify if unpacker needs to reinitialize the
    /// uncompression context.
    initialized: bool,
    /// Flag used when applying filters.
    all_filters_applied: bool,
    /// Flag used to skip file context reinitialization, used when unpacker
    /// is skipping through different multivolume archives.
    switch_multivolume: bool,
    /// Flag used to specify if unpacker has processed the whole data block
    /// or just a part of it.
    block_parsing_finished: bool,
    /// Flag used to indicate that a previous file using this buffer was
    /// encrypted, meaning no data in the buffer can be trusted.
    data_encrypted: bool,

    /// Uncompression algorithm method.
    method: u32,
    /// Size of the window.
    window_size: i64,
    /// Circular buffer used during decompression; empty if not allocated.
    window: Vec<u8>,
    /// Buffer used when applying filters.
    filtered: Vec<u8>,
    /// Whether the block being decoded lives in the merge buffer
    /// (`Multivolume::push_buf`) rather than in the input.
    block_in_push_buf: bool,
    /// Convenience field; window_size - 1.
    window_mask: i64,
    /// This amount of data has been unpacked in the window buffer.
    write_ptr: i64,
    /// This amount of data has been stored in the output file.
    last_write_ptr: i64,
    /// Counter of bytes extracted during unstoring. This is separate from
    /// last_write_ptr because of how SERVICE base blocks are handled during
    /// skipping in solid multiarchive archives.
    last_unstore_ptr: i64,
    /// Additional offset inside the window buffer, used in unpacking solid
    /// archives.
    solid_offset: i64,
    /// Size of current data block.
    cur_block_size: i64,
    /// Flag used in lzss decompression.
    last_len: i32,

    // Decode tables used during lzss uncompression.
    /// huffman bit lengths
    bd: DecodeTable,
    /// literals
    ld: DecodeTable,
    /// distances
    dd: DecodeTable,
    /// lower bits of distances
    ldd: DecodeTable,
    /// repeating distances
    rd: DecodeTable,

    /// Filters, in the order of their blocks.
    filters: VecDeque<Filter>,
    /// Used for sanity checking.
    last_block_start: i64,
    last_block_length: i64,

    /// Distance cache used during lzss uncompression.
    dist_cache: [i32; 4],

    /// Data buffer stack.
    dready: [Option<DataReady>; 2],
}

struct Rar5 {
    header_initialized: bool,
    /// Set if current file is positioned AFTER the magic value of the
    /// archive file. This is used in header reading functions.
    skipped_magic: bool,
    /// Non-zero if we're in skip mode (either by calling the data skip
    /// function or when skipping over solid streams). It is a counter
    /// because skipping can be nested. This is used during checksum
    /// calculation functions.
    skip_mode: u32,
    /// Non-zero if we're in block merging mode (i.e. when switching to
    /// another file in multivolume archive, last block from 1st archive
    /// needs to be merged with 1st block from 2nd archive). This flag
    /// guards against recursive use of the merging function, which doesn't
    /// support recursive calls.
    merge_mode: u32,

    generic: Generic,
    main: Main,
    cstate: CompState,
    file: File,
    bits: BitPos,
    vol: Multivolume,

    /// The flags of the currently processed compressed block's header. Used
    /// in main decompression logic loop.
    last_block_flags: u8,

    /// Custom field to denote that this archive contains encrypted entries.
    has_encrypted_entries: c_int,
    headers_are_encrypted: bool,
}

/// `archive_read_support_format_rar5`.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Rar5::new()))
}

impl Rar5 {
    fn new() -> Rar5 {
        Rar5 {
            header_initialized: false,
            skipped_magic: false,
            skip_mode: 0,
            merge_mode: 0,
            generic: Generic::default(),
            main: Main::default(),
            cstate: CompState::default(),
            file: File::default(),
            bits: BitPos::default(),
            vol: Multivolume::default(),
            last_block_flags: 0,
            // Until enough data has been read, we cannot tell about any
            // encrypted entries yet.
            has_encrypted_entries: ENCRYPTION_DONT_KNOW,
            headers_are_encrypted: false,
        }
    }
}

fn bid_standard(r: &mut Reader<'_>) -> c_int {
    match ahead(r, SIGNATURE.len()) {
        Some(h) if h.starts_with(&SIGNATURE) => SIGNATURE_BID,
        _ => -1,
    }
}

fn is_executable(h: &[u8]) -> bool {
    h.starts_with(b"MZ") || h.starts_with(b"\x7F\x45LF")
}

fn bid_sfx(r: &mut Reader<'_>) -> c_int {
    match ahead(r, 7) {
        Some(h) if is_executable(h) => {}
        Some(_) => return 0,
        None => return -1,
    }

    // This is a PE file.
    let mut offset: usize = 0x10000;
    let mut window: usize = 4096;
    while offset + window <= SFX_MAX_READAHEAD {
        let Ok(h) = r.peek_available(offset + window) else {
            return 0;
        };
        if h.len() < offset + window {
            if h.len() >= offset + 0x10 {
                // Remaining bytes are less than window.
                window = h.len() - offset;
                continue;
            }
            return 0;
        }
        let avail = h.len().min(SFX_MAX_READAHEAD);
        while offset + 8 <= avail {
            if h.get(offset..offset + 8) == Some(&SIGNATURE[..]) {
                return 30;
            }
            offset += 0x10;
        }
    }
    0
}

/// Skips the executable stub of a self-extracting archive.
fn try_skip_sfx(r: &mut Reader<'_>) -> Res<()> {
    match ahead(r, 7) {
        Some(p) if is_executable(p) => {}
        Some(_) => return Ok(()),
        None => return Err(Stop::Eof),
    }

    let mut total: usize = 0;
    let mut window: usize = 4096;
    while total + window <= SFX_MAX_READAHEAD {
        let h = r.peek_available(window).unwrap_or_default();
        if h.len() < window {
            // Remaining bytes are less than window.
            window >>= 1;
            if window < 0x40 {
                return Err(couldnt_find_header());
            }
            continue;
        }

        // Scan ahead until we find something that looks like the RAR header.
        let found = (0..h.len().saturating_sub(8))
            .step_by(0x10)
            .find(|&i| h.get(i..i + 8) == Some(&SIGNATURE[..]));
        let skip = found.unwrap_or_else(|| (h.len().saturating_sub(8)).div_ceil(0x10) * 0x10);
        // A failure here shows up as a read failure below.
        let _ = r.consume(skip);
        if found.is_some() {
            return Ok(());
        }
        total += skip;
    }
    Ok(())
}

fn couldnt_find_header() -> Stop {
    format_error("Couldn't find out RAR header")
}

/// Binary search for the RARv5 signature.
fn scan_for_signature(r: &mut Reader<'_>) -> Res<()> {
    const CHUNK_SIZE: usize = 512;

    // If we're here, it means we're on an 'unknown territory' data.
    // There's no indication what kind of data we're reading here.
    // It could be some text comment, any kind of binary data,
    // digital sign, dragons, etc.
    //
    // We want to find a valid RARv5 magic header inside this unknown
    // data.
    loop {
        let p = ahead(r, CHUNK_SIZE).ok_or(Stop::Eof)?;
        let found = (0..CHUNK_SIZE - SIGNATURE.len())
            .find(|&i| p.get(i..i + SIGNATURE.len()) == Some(&SIGNATURE[..]));
        if let Some(i) = found {
            // Consume the number of bytes we've used to search for the
            // signature, as well as the number of bytes used by the
            // signature itself. After this we should be standing on a valid
            // base block header.
            let _ = r.consume(i + SIGNATURE.len());
            return Ok(());
        }
        let _ = r.consume(CHUNK_SIZE);
    }
}

impl Format for Rar5 {
    fn name(&self) -> &'static str {
        "rar5"
    }

    fn bid(&mut self, r: &mut Reader<'_>, best_bid: c_int) -> Result<c_int, Error> {
        if best_bid >= SIGNATURE_BID {
            return Ok(-1);
        }
        let my_bid = bid_standard(r);
        if my_bid > -1 {
            return Ok(my_bid);
        }
        let my_bid = bid_sfx(r);
        if my_bid > -1 {
            return Ok(my_bid);
        }
        Ok(-1)
    }

    fn options(
        &mut self,
        _a: &Base,
        _key: &[u8],
        _value: Option<&[u8]>,
    ) -> Option<Result<Status, Error>> {
        // No options supported in this version. Return the warning to
        // signal the options supervisor that the unpacker didn't handle
        // setting this option.
        Some(Ok(Status::Warn))
    }

    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        // It should be sufficient to call archive_read_next_header() for a
        // reader to determine if an entry is encrypted or not.
        if self.has_encrypted_entries == ENCRYPTION_DONT_KNOW {
            self.has_encrypted_entries = 0;
        }

        if !self.header_initialized {
            r.set_format(format_code::RAR_V5, c"RAR5");
            match try_skip_sfx(r) {
                Err(Stop::Err(e)) => return Err(e),
                Ok(()) | Err(Stop::Eof) => {}
            }
            self.header_initialized = true;
        }

        if !self.skipped_magic {
            if r.consume(SIGNATURE.len()).is_err() {
                return Ok(Status::Eof);
            }
            self.skipped_magic = true;
        }

        loop {
            match self.process_base_block(r, entry) {
                Ok(Step::Retry) => {}
                Ok(Step::Ok) if self.main.endarc => {}
                Ok(Step::Ok) => return Ok(Status::Ok),
                Err(Stop::Eof) => return Ok(Status::Eof),
                Err(Stop::Err(e)) => return Err(e),
            }
        }
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        let mut offset = 0;
        match self.read_block(r, &mut offset) {
            Ok(data) => Ok(Data::Block { data, offset }),
            Err(Stop::Eof) => Ok(Data::Eof { offset }),
            Err(Stop::Err(e)) => Err(e),
        }
    }

    fn read_data_skip(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        match self.skip_data(r) {
            // The end of the data is not an error when skipping.
            Ok(()) | Err(Stop::Eof) => Ok(Status::Ok),
            Err(Stop::Err(e)) => Err(e),
        }
    }

    fn seek_data(
        &mut self,
        _r: &mut Reader<'_>,
        _offset: i64,
        _whence: c_int,
    ) -> Result<i64, Error> {
        // We're a streaming unpacker, and we don't support seeking.
        // That's a capability gap, not a fatal error.
        Err(Error::new(
            ARCHIVE_FAILED,
            ARCHIVE_ERRNO_MISC,
            "Seeking of RAR5 files is unsupported",
        ))
    }

    fn capabilities(&self) -> c_int {
        CAPS_ENCRYPT
    }

    fn has_encrypted_entries(&self) -> c_int {
        self.has_encrypted_entries
    }
}

impl Rar5 {
    fn reset_file_context(&mut self) {
        self.file = File {
            b2state: Blake2sp::new(32),
            redir_type: REDIR_TYPE_NONE,
            ..File::default()
        };

        let c = &mut self.cstate;
        if self.main.solid {
            c.solid_offset = c.solid_offset.wrapping_add(c.write_ptr);
        } else {
            c.solid_offset = 0;
        }

        c.write_ptr = 0;
        c.last_write_ptr = 0;
        c.last_unstore_ptr = 0;

        // Free any remaining filters. All filters should be naturally
        // consumed by the unpacking function, so remaining filters after
        // unpacking normally mean that unpacking wasn't successful.
        c.filters.clear();
        // Also clear out the variables needed for sanity checking.
        c.last_block_start = 0;
        c.last_block_length = 0;
    }

    fn init_window_mask(&mut self) {
        let c = &mut self.cstate;
        c.window_mask = if c.window_size != 0 {
            c.window_size - 1
        } else {
            0
        };
    }

    fn process_main_locator_extra_block(&mut self, r: &mut Reader<'_>) -> Res<()> {
        const QLIST: u64 = 0x01;
        const RECOVERY: u64 = 0x02;

        let locator_flags = take_var(r)?;

        // The offsets of the QuickOpen list and of the recovery data are not
        // used: this is a streaming unpacker.
        if locator_flags & QLIST != 0 {
            take_var(r)?;
        }
        if locator_flags & RECOVERY != 0 {
            take_var(r)?;
        }
        Ok(())
    }

    fn parse_file_extra_hash(&mut self, r: &mut Reader<'_>, extra_data_size: &mut i64) -> Res<()> {
        const BLAKE2SP: usize = 0x00;

        let (hash_type, value_len) = peek_size(r)?;
        *extra_data_size = extra_data_size.wrapping_sub(value_len as i64);
        consume_or_eof(r, value_len)?;

        // The file uses BLAKE2sp checksum algorithm instead of plain old
        // CRC32.
        if hash_type == BLAKE2SP {
            let hash_size = self.file.blake2sp.len();
            let p = ahead(r, hash_size).ok_or(Stop::Eof)?;
            self.file.has_blake2 = true;
            self.file
                .blake2sp
                .copy_from_slice(p.get(..hash_size).unwrap_or_default());
            consume_or_eof(r, hash_size)?;
            *extra_data_size = extra_data_size.wrapping_sub(hash_size as i64);
            Ok(())
        } else {
            Err(format_error(format!(
                "Unsupported hash type (0x{hash_type:x})"
            )))
        }
    }

    fn parse_file_extra_version(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        extra_data_size: &mut i64,
    ) -> Res<()> {
        // Flags are ignored.
        let (_flags, value_len) = peek_size(r)?;
        *extra_data_size = extra_data_size.wrapping_sub(value_len as i64);
        consume_or_eof(r, value_len)?;

        let (version, value_len) = peek_size(r)?;
        *extra_data_size = extra_data_size.wrapping_sub(value_len as i64);
        consume_or_eof(r, value_len)?;

        // extra_data_size should be zero here.

        let Some(cur_filename) = entry.pathname_utf8() else {
            return Err(fatal(
                ARCHIVE_ERRNO_PROGRAMMER,
                "Version entry without file name",
            ));
        };

        // Build the new filename: the old one with a ;123 suffix, where
        // '123' is the version value of this file.
        let mut name = cur_filename.to_bytes().to_vec();
        name.extend_from_slice(format!(";{version}").as_bytes());
        entry.update_pathname_utf8(&name);
        Ok(())
    }

    fn parse_file_extra_htime(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        extra_data_size: &mut i64,
    ) -> Res<()> {
        const IS_UNIX: usize = 0x01;
        const HAS_MTIME: usize = 0x02;
        const HAS_CTIME: usize = 0x04;
        const HAS_ATIME: usize = 0x08;
        const HAS_UNIX_NS: usize = 0x10;

        let (flags, value_len) = peek_size(r)?;
        *extra_data_size = extra_data_size.wrapping_sub(value_len as i64);
        consume_or_eof(r, value_len)?;

        let unix_time = flags & IS_UNIX != 0;
        let has_unix_ns = unix_time && flags & HAS_UNIX_NS != 0;
        let has = [
            flags & HAS_MTIME != 0,
            flags & HAS_CTIME != 0,
            flags & HAS_ATIME != 0,
        ];
        let mut secs = [0i64; 3];
        let mut nsecs = [0u32; 3];

        for (i, _) in has.iter().enumerate().filter(|(_, h)| **h) {
            if unix_time {
                let time_val = read_u32(r).ok_or(Stop::Eof)?;
                *extra_data_size = extra_data_size.wrapping_sub(4);
                secs[i] = i64::from(time_val);
            } else {
                let windows_time = read_u64(r).ok_or(Stop::Eof)?;
                (secs[i], nsecs[i]) = ntfs_to_unix(windows_time);
                *extra_data_size = extra_data_size.wrapping_sub(8);
            }
        }

        for (i, _) in has.iter().enumerate().filter(|(_, h)| **h) {
            if has_unix_ns {
                nsecs[i] = read_u32(r).ok_or(Stop::Eof)?;
                *extra_data_size = extra_data_size.wrapping_sub(4);
            }
        }

        // The seconds and nanoseconds are either together, or separated in
        // two fields so we parse them, then set the archive_entry's times.
        if has[0] {
            entry.set_mtime(secs[0], i64::from(nsecs[0]));
        }
        if has[1] {
            entry.set_ctime(secs[1], i64::from(nsecs[1]));
        }
        if has[2] {
            entry.set_atime(secs[2], i64::from(nsecs[2]));
        }
        Ok(())
    }

    fn parse_file_extra_redir(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        extra_data_size: &mut i64,
    ) -> Res<()> {
        let (redir_type, value_size) = peek_var(r)?;
        self.file.redir_type = redir_type;
        consume_or_eof(r, value_size)?;
        *extra_data_size = extra_data_size.wrapping_sub(value_size as i64);

        let (redir_flags, value_size) = peek_var(r)?;
        consume_or_eof(r, value_size)?;
        *extra_data_size = extra_data_size.wrapping_sub(value_size as i64);

        let (target_size, varint_len) = peek_size(r)?;
        consume_or_eof(r, varint_len)?;

        if target_size > MAX_NAME_IN_CHARS - 1 {
            return Err(format_error("Link target is too long"));
        }
        if target_size == 0 {
            return Err(format_error("No link target specified"));
        }
        if i64::try_from(target_size + varint_len).map_or(true, |n| n > *extra_data_size) {
            return Err(format_error("Extra data size is too small for link target"));
        }
        *extra_data_size -= (target_size + varint_len) as i64;

        let p = ahead(r, target_size).ok_or(Stop::Eof)?;
        let target = c_str(p.get(..target_size).unwrap_or_default()).to_vec();
        consume_or_eof(r, target_size)?;

        match redir_type {
            REDIR_TYPE_UNIXSYMLINK | REDIR_TYPE_WINSYMLINK => {
                entry.set_filetype(u32::from(AE_IFLNK));
                entry.update_symlink_utf8(&target);
                entry.set_symlink_type(if redir_flags & REDIR_SYMLINK_IS_DIR != 0 {
                    AE_SYMLINK_TYPE_DIRECTORY
                } else {
                    AE_SYMLINK_TYPE_FILE
                });
            }
            REDIR_TYPE_HARDLINK => {
                entry.set_filetype(u32::from(AE_IFREG));
                entry.update_hardlink_utf8(&target);
            }
            // Unknown redir type, skip it.
            _ => {}
        }
        Ok(())
    }

    fn parse_file_extra_owner(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        extra_data_size: &mut i64,
    ) -> Res<()> {
        let (flags, value_size) = peek_var(r)?;
        consume_or_eof(r, value_size)?;
        *extra_data_size = extra_data_size.wrapping_sub(value_size as i64);

        for (flag, what) in [(OWNER_USER_NAME, "Owner"), (OWNER_GROUP_NAME, "Group")] {
            if flags & flag == 0 {
                continue;
            }
            let (name_size, varint_len) = peek_size(r)?;

            // The name cannot be larger than the remaining extra data of
            // this field. Rejecting an oversized length here also avoids
            // requesting a huge allocation from read_ahead() below.
            if *extra_data_size < 0 || name_size as u64 > *extra_data_size as u64 {
                return Err(format_error(format!("{what} name is too long")));
            }
            consume_or_eof(r, varint_len)?;
            *extra_data_size = extra_data_size.wrapping_sub((name_size + varint_len) as i64);

            let p = ahead(r, name_size).ok_or(Stop::Eof)?;
            let name_len = name_size.min(OWNER_MAXNAMELEN - 1);
            let name = c_str(p.get(..name_len).unwrap_or_default()).to_vec();
            consume_or_eof(r, name_size)?;

            if flag == OWNER_USER_NAME {
                entry.set_uname(&name);
            } else {
                entry.set_gname(&name);
            }
        }

        for flag in [OWNER_USER_UID, OWNER_GROUP_GID] {
            if flags & flag == 0 {
                continue;
            }
            let (id, value_size) = peek_var(r)?;
            consume_or_eof(r, value_size)?;
            *extra_data_size = extra_data_size.wrapping_sub(value_size as i64);

            if flag == OWNER_USER_UID {
                entry.set_uid(id as i64);
            } else {
                entry.set_gid(id as i64);
            }
        }
        Ok(())
    }

    fn process_head_file_extra(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        mut extra_data_size: i64,
    ) -> Res<()> {
        while extra_data_size > 0 {
            let (extra_field_size, var_size) = peek_var(r)?;
            extra_data_size = extra_data_size.wrapping_sub(var_size as i64);
            consume_or_eof(r, var_size)?;

            let (extra_field_id, var_size) = peek_var(r)?;
            let extra_field_size = extra_field_size.wrapping_sub(var_size as u64);
            extra_data_size = extra_data_size.wrapping_sub(var_size as i64);
            consume_or_eof(r, var_size)?;

            match extra_field_id {
                EX_HASH => self.parse_file_extra_hash(r, &mut extra_data_size)?,
                EX_HTIME => self.parse_file_extra_htime(r, entry, &mut extra_data_size)?,
                EX_REDIR => self.parse_file_extra_redir(r, entry, &mut extra_data_size)?,
                EX_UOWNER => self.parse_file_extra_owner(r, entry, &mut extra_data_size)?,
                EX_VERSION => self.parse_file_extra_version(r, entry, &mut extra_data_size)?,
                id => {
                    if id == EX_CRYPT {
                        // Mark the entry as encrypted.
                        entry.set_is_data_encrypted(true);
                        self.has_encrypted_entries = 1;
                        self.cstate.data_encrypted = true;
                    }
                    // Skip unsupported entry.
                    // A negative remainder compares as a huge unsigned number, as
                    // upstream has it.
                    if extra_field_size > extra_data_size as u64 {
                        return Err(format_error(
                            "RAR5 extra-field size exceeds remaining extra-field data",
                        ));
                    }
                    extra_data_size = extra_data_size.wrapping_sub(extra_field_size as i64);
                    consume_or_eof(r, extra_field_size)?;
                }
            }
        }

        if extra_data_size != 0 {
            // We didn't skip everything, or we skipped too much; either way,
            // there's an error in this parsing function.
            return Err(fatal(
                ARCHIVE_ERRNO_PROGRAMMER,
                "unsupported structure of file header extra data",
            ));
        }
        Ok(())
    }

    fn process_head_file(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        block_flags: usize,
    ) -> Res<Step> {
        const DIRECTORY: usize = 0x0001;
        const UTIME: usize = 0x0002;
        const CRC32: usize = 0x0004;
        const UNKNOWN_UNPACKED_SIZE: usize = 0x0008;

        const ATTR_READONLY: usize = 0x1;
        const ATTR_HIDDEN: usize = 0x2;
        const ATTR_SYSTEM: usize = 0x4;
        const ATTR_DIRECTORY: usize = 0x10;

        const SOLID: usize = 0x0040;

        const HOST_WINDOWS: usize = 0;
        const HOST_UNIX: usize = 1;

        entry.clear();

        // Do not reset file context if we're switching archives.
        if !self.cstate.switch_multivolume {
            self.reset_file_context();
        }

        let mut extra_data_size: i64 = 0;
        if block_flags & HFL_EXTRA_DATA != 0 {
            let edata_size = take_var(r)?;

            // The extra area is part of the file header, which
            // process_base_block() has already bounded to MAX_HEADER_SIZE.
            // A declared extra-area size larger than that cannot be valid,
            // and if left unchecked it is later used as the ceiling for the
            // owner/group name length in parse_file_extra_owner(), letting
            // a crafted archive drive read_ahead() into an
            // attacker-controlled allocation. Reject it here.
            if edata_size > MAX_HEADER_SIZE as u64 {
                return Err(format_error("File extra data size is too large"));
            }
            extra_data_size = edata_size as i64;
        }

        let mut data_size = 0;
        if block_flags & HFL_DATA != 0 {
            data_size = take_size(r)?;
            self.file.bytes_remaining = i64::try_from(data_size)
                .map_err(|_| format_error("File data size is too large"))?;
        } else {
            self.file.bytes_remaining = 0;
        }

        let file_flags = take_size(r)?;
        let unpacked_size = take_var(r)?;

        if file_flags & UNKNOWN_UNPACKED_SIZE != 0 {
            return Err(fatal(
                ARCHIVE_ERRNO_PROGRAMMER,
                "Files with unknown unpacked size are not supported",
            ));
        }

        self.file.dir = file_flags & DIRECTORY != 0;

        if self.file.dir {
            // FILE entries for directories still declare HFL_DATA in block
            // flags, even though attaching data to such blocks doesn't make
            // much sense.
            if unpacked_size != 0 || data_size != 0 {
                return Err(format_error("directory entries cannot have any data"));
            }
        } else if block_flags & HFL_DATA == 0 {
            return Err(format_error("no data found in file/service block"));
        }

        let file_attr = take_size(r)?;

        let mut mtime = 0;
        if file_flags & UTIME != 0 {
            mtime = read_u32(r).ok_or(Stop::Eof)?;
        }

        let mut crc = 0;
        if file_flags & CRC32 != 0 {
            crc = read_u32(r).ok_or(Stop::Eof)?;
        }

        let compression_info = take_size(r)?;

        // RAR5 seems to limit the dictionary size to 64MB.
        let window_size: u64 = if self.file.dir {
            0
        } else {
            UNPACK_WINDOW_SIZE << ((compression_info >> 10) & 15)
        };
        self.cstate.method = ((compression_info >> 7) & 0x7) as u32;
        self.file.solid = compression_info & SOLID != 0;

        // Archives which declare solid files without initializing the window
        // buffer first are invalid, unless previous data was encrypted, in
        // which case we may never have had the chance.
        if self.file.solid && !self.cstate.data_encrypted && self.cstate.window.is_empty() {
            return Err(format_error(
                "Declared solid file, but no window buffer initialized yet",
            ));
        }

        // Check if window_size is a sane value. Also, if the file is not
        // declared as a directory, disallow window_size == 0.
        if window_size > 64 * 1024 * 1024 || (!self.file.dir && window_size == 0) {
            return Err(format_error("Declared dictionary size is not supported"));
        }
        // Values up to 64M fit every type.
        if window_size > r.decoder_memory(u64::MAX) {
            return Err(fatal(libc::ENOMEM, "RAR5 window requires too much memory"));
        }
        let window_size = window_size as i64;

        if self.file.solid {
            // Re-check if current window size is the same as previous window
            // size (for solid files only).
            if self.file.solid_window_size > 0 && self.file.solid_window_size != window_size {
                return Err(format_error(
                    "Window size for this solid file doesn't match the window size used in \
                     previous solid file",
                ));
            }
        } else {
            // Reset for new buffer.
            self.cstate.data_encrypted = false;
        }

        if self.cstate.window_size < window_size && !self.cstate.window.is_empty() {
            // The `data_ready` stack contains ranges of the window buffer
            // and the filter buffer. Since we're about to reallocate the
            // first buffer, dispose of all entries from the stack before
            // attempting the realloc.
            self.cstate.dready = [None; 2];

            // If the window buffer has been allocated before, reallocate
            // it, so that its size will match new window_size.
            let window = &mut self.cstate.window;
            let wanted = window_size as usize;
            if wanted > window.len() && window.try_reserve_exact(wanted - window.len()).is_err() {
                return Err(fatal(
                    ARCHIVE_ERRNO_PROGRAMMER,
                    "Not enough memory when trying to realloc the window buffer",
                ));
            }
            window.resize(wanted, 0);
        }

        self.cstate.window_size = window_size;

        if self.file.solid && self.file.solid_window_size == 0 {
            // Solid files have to have the same window_size across whole
            // archive. Remember the window_size parameter for first solid
            // file found.
            self.file.solid_window_size = self.cstate.window_size;
        }

        self.init_window_mask();

        self.file.service = false;

        let host_os = take_size(r)?;

        if host_os == HOST_WINDOWS {
            // Host OS is Windows.
            let readonly = file_attr & ATTR_READONLY != 0;
            let mode: Mode = match (file_attr & ATTR_DIRECTORY != 0, readonly) {
                (true, true) => 0o555 | AE_IFDIR,
                (true, false) => 0o755 | AE_IFDIR,
                (false, true) => 0o444 | AE_IFREG,
                (false, false) => 0o644 | AE_IFREG,
            };
            entry.set_mode(mode);

            if file_attr & (ATTR_READONLY | ATTR_HIDDEN | ATTR_SYSTEM) != 0 {
                let mut fflags = Vec::new();
                for (attr, name) in [
                    (ATTR_READONLY, "rdonly"),
                    (ATTR_HIDDEN, "hidden"),
                    (ATTR_SYSTEM, "system"),
                ] {
                    if file_attr & attr != 0 {
                        if !fflags.is_empty() {
                            fflags.push(b',');
                        }
                        fflags.extend_from_slice(name.as_bytes());
                    }
                }
                entry.copy_fflags_text(&fflags);
            }
        } else if host_os == HOST_UNIX {
            // Host OS is Unix.
            entry.set_mode(file_attr as Mode);
        } else {
            // Unknown host OS.
            return Err(format_error(format!("Unsupported Host OS: 0x{host_os:x}")));
        }

        let name_size = take_size(r)?;

        if name_size > MAX_NAME_IN_CHARS - 1 {
            return Err(format_error("Filename is too long"));
        }
        if name_size == 0 {
            return Err(format_error("No filename specified"));
        }

        let p = ahead(r, name_size).ok_or(Stop::Eof)?;
        let name = c_str(p.get(..name_size).unwrap_or_default()).to_vec();
        consume_or_eof(r, name_size)?;

        entry.update_pathname_utf8(&name);

        if extra_data_size > 0 {
            self.process_head_file_extra(r, entry, extra_data_size)?;
        }

        // The unknown-size flag was refused above.
        self.file.unpacked_size = unpacked_size as i64;
        if self.file.redir_type == REDIR_TYPE_NONE {
            entry.set_size(unpacked_size as i64);
        }

        if file_flags & UTIME != 0 {
            entry.set_mtime(i64::from(mtime), 0);
        }

        if file_flags & CRC32 != 0 {
            self.file.stored_crc32 = crc;
        }

        if !self.cstate.switch_multivolume {
            // Do not reinitialize unpacking state if we're switching
            // archives.
            self.cstate.block_parsing_finished = true;
            self.cstate.all_filters_applied = true;
            self.cstate.initialized = false;
        }

        if self.generic.split_before {
            // If now we're standing on a header that has a 'split before'
            // mark, it means we're standing on a 'continuation' file
            // header. Signal the caller that if it wants to move to
            // another file, it must call rar5_read_header() function
            // again.
            Ok(Step::Retry)
        } else {
            Ok(Step::Ok)
        }
    }

    fn process_head_service(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        block_flags: usize,
    ) -> Res<Step> {
        // Process this SERVICE block the same way as FILE blocks.
        if self.process_head_file(r, entry, block_flags)? != Step::Ok {
            return Ok(Step::Retry);
        }

        self.file.service = true;

        // But skip the data part automatically. It's no use for the user
        // anyway.  It contains only service data, not even needed to
        // properly unpack the file.
        self.skip_data(r)?;

        // After skipping, try parsing another block automatically.
        Ok(Step::Retry)
    }

    fn process_head_main(&mut self, r: &mut Reader<'_>, block_flags: usize) -> Res<()> {
        const VOLUME: usize = 0x0001;
        const VOLUME_NUMBER: usize = 0x0002;
        const SOLID: usize = 0x0004;

        // Just one attribute here.
        const LOCATOR: usize = 0x01;

        let extra_data_size = if block_flags & HFL_EXTRA_DATA != 0 {
            take_var(r)?
        } else {
            0
        };

        let archive_flags = take_size(r)?;

        self.main.volume = archive_flags & VOLUME != 0;
        self.main.solid = archive_flags & SOLID != 0;

        self.main.vol_no = 0;
        if archive_flags & VOLUME_NUMBER != 0 {
            let v = take_size(r)?;
            self.main.vol_no =
                u32::try_from(v).map_err(|_| format_error("Invalid volume number"))?;
        }

        if self.vol.expected_vol_no > 0 && self.main.vol_no != self.vol.expected_vol_no {
            // Returning EOF instead of FATAL because of strange libarchive
            // behavior. When opening multiple files via
            // archive_read_open_filenames(), after reading up the whole
            // last file, the __archive_read_ahead function wraps up to the
            // first archive instead of returning EOF.
            return Err(Stop::Eof);
        }

        if extra_data_size == 0 {
            // Early return.
            return Ok(());
        }

        let extra_field_size = take_size(r)?;
        let extra_field_id = take_size(r)?;

        if extra_field_size == 0 {
            return Err(format_error("Invalid extra field size"));
        }

        match extra_field_id {
            LOCATOR => self.process_main_locator_extra_block(r),
            id => Err(format_error(format!("Unsupported extra type (0x{id:x})"))),
        }
    }

    fn skip_unprocessed_bytes(&mut self, r: &mut Reader<'_>) -> Res<()> {
        if self.file.bytes_remaining != 0 {
            // Use different skipping method in block merging mode than in
            // normal mode. If merge mode is active, the data skip can't be
            // used, because it could allow recursive use of merge_block()
            // function, and this function doesn't support recursive use.
            if self.merge_mode != 0 {
                // Discard whole merged block. This is valid in solid mode as
                // well, because the code will discard blocks only if those
                // blocks are safe to discard (i.e. they're not FILE
                // blocks).
                r.consume(self.file.bytes_remaining)?;
                self.file.bytes_remaining = 0;
            } else {
                // If we're not in merge mode, use safe skipping code. This
                // will ensure we'll handle solid archives properly.
                self.skip_data(r)?;
            }
        }
        Ok(())
    }

    /// Base block processing function. A 'base block' is a RARv5 header
    /// block that tells the reader what kind of data is stored inside the
    /// block.
    ///
    /// From the birds-eye view a RAR file looks file this:
    ///
    /// `<magic><base_block_1><base_block_2>...<base_block_n>`
    ///
    /// There are a few types of base blocks. For example, a standard RARv5
    /// file could look like this:
    ///
    /// `<magic><MAIN><FILE><FILE><FILE><SERVICE><ENDARC>`
    ///
    /// The example above could describe an archive file with 3 files in it,
    /// one service "QuickOpen" block (that is ignored by this parser), and
    /// an end of file base block marker.
    ///
    /// If the file is stored in multiple archive files ("multiarchive"), it
    /// might look like this:
    ///
    /// ```text
    /// .part01.rar: <magic><MAIN><FILE><ENDARC>
    /// .part02.rar: <magic><MAIN><FILE><ENDARC>
    /// .part03.rar: <magic><MAIN><FILE><ENDARC>
    /// ```
    ///
    /// This example could describe 3 RAR files that contain ONE archived
    /// file. Or it could describe 3 RAR files that contain 3 different
    /// files. Or 3 RAR files than contain 2 files. It all depends what
    /// metadata is stored in the headers of <FILE> blocks.
    ///
    /// Each <FILE> block contains info about its size, the name of the file
    /// it's storing inside, and whether this FILE block is a continuation
    /// block of previous archive ('split before'), and is this FILE block
    /// should be continued in another archive ('split after'). By parsing
    /// the 'split before' and 'split after' flags, we're able to tell if
    /// multiple <FILE> base blocks are describing one file, or multiple
    /// files (with the same filename, for example).
    ///
    /// One thing to note is that if we're parsing the first <FILE> block,
    /// and we see 'split after' flag, then we need to jump over to another
    /// <FILE> block to be able to decompress rest of the data. To do this,
    /// we need to skip the <ENDARC> block, then switch to another file, then
    /// skip the <magic> block, <MAIN> block, and then we're standing on the
    /// proper <FILE> block.
    fn process_base_block(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Res<Step> {
        const SMALLEST_RAR5_BLOCK_SIZE: usize = 3;

        // Skip any unprocessed data for this file.
        self.skip_unprocessed_bytes(r)?;

        // Read the expected CRC32 checksum.
        let hdr_crc = read_u32(r).ok_or(Stop::Eof)?;

        // Read header size.
        let (raw_hdr_size, hdr_size_len) = peek_size(r)?;

        // Sanity check.  Bounding raw_hdr_size (instead of the sum) also
        // ensures that adding hdr_size_len below cannot wrap hdr_size
        // around SIZE_MAX.
        if raw_hdr_size > MAX_HEADER_SIZE - hdr_size_len {
            return Err(format_error("Base block header is too large"));
        }

        let hdr_size = raw_hdr_size + hdr_size_len;

        // Additional sanity checks to weed out invalid files.
        if raw_hdr_size == 0 || hdr_size_len == 0 || hdr_size < SMALLEST_RAR5_BLOCK_SIZE {
            return Err(format_error(format!(
                "Too small block encountered ({raw_hdr_size} bytes)"
            )));
        }

        // Read the whole header data into memory, maximum memory use here is
        // 2MB.
        let p = ahead(r, hdr_size).ok_or(Stop::Eof)?;

        // Verify the CRC32 of the header data.
        if crc32(0, p.get(..hdr_size).unwrap_or_default()) != hdr_crc {
            return Err(format_error("Header CRC error"));
        }

        // If the checksum is OK, we proceed with parsing.
        consume_or_eof(r, hdr_size_len)?;
        // Remember where the block body starts so we can later skip any
        // bytes the sub-parser leaves unconsumed.
        let body_start = r.position();

        let header_id = take_size(r)?;
        let header_flags = take_size(r)?;

        self.generic.split_after = header_flags & HFL_SPLIT_AFTER != 0;
        self.generic.split_before = header_flags & HFL_SPLIT_BEFORE != 0;
        self.generic.last_header_id = header_id;
        self.main.endarc = false;

        // Those are possible header ids in RARv5.
        match header_id {
            HEAD_MAIN => {
                self.process_head_main(r, header_flags)?;

                // Main header doesn't have any files in it, so it's
                // pointless to return to the caller. Retry to next header,
                // which should be HEAD_FILE/HEAD_SERVICE.
                skip_remaining_block(r, body_start, raw_hdr_size);
                Ok(Step::Retry)
            }
            HEAD_SERVICE => self.process_head_service(r, entry, header_flags),
            HEAD_FILE => self.process_head_file(r, entry, header_flags),
            HEAD_CRYPT => {
                entry.set_is_metadata_encrypted(true);
                entry.set_is_data_encrypted(true);
                self.has_encrypted_entries = 1;
                self.headers_are_encrypted = true;
                Err(format_error("Encryption is not supported"))
            }
            HEAD_ENDARC => {
                self.main.endarc = true;

                // After encountering an end of file marker, we need to take
                // into consideration if this archive is continued in
                // another file (i.e. is it part01.rar: is there a
                // part02.rar?)
                if !self.main.volume {
                    return Err(Stop::Eof);
                }
                // In case there is part02.rar, position the read pointer in
                // a proper place, so we can resume parsing. Running out of
                // input here is not an error.
                let _ = scan_for_signature(r);
                if self.vol.expected_vol_no == u32::MAX {
                    return Err(format_error("Header error"));
                }
                self.vol.expected_vol_no = self.main.vol_no.wrapping_add(1);
                Ok(Step::Ok)
            }
            HEAD_MARK => Err(Stop::Eof),
            _ => {
                if header_flags & HFL_SKIP_IF_UNKNOWN == 0 {
                    return Err(format_error("Header type error"));
                }
                // If the block is marked as 'skip if unknown', do as the
                // flag says: skip the block instead on failing on it.
                skip_remaining_block(r, body_start, raw_hdr_size);
                Ok(Step::Retry)
            }
        }
    }

    fn skip_base_block(&mut self, r: &mut Reader<'_>) -> Res<Step> {
        // Create a new local archive_entry structure that will be operated
        // on by header reader; operations on this archive_entry will be
        // discarded.
        let mut entry = Entry::new(None);
        let ret = self.process_base_block(r, &mut entry);

        if matches!(&ret, Err(Stop::Err(e)) if e.code == ARCHIVE_FATAL) {
            return ret;
        }
        if self.generic.last_header_id == HEAD_FILE && self.generic.split_before {
            return Ok(Step::Ok);
        }
        match ret {
            Ok(Step::Ok) => Ok(Step::Retry),
            other => other,
        }
    }
}

/// A header that carries no file data (HEAD_MAIN, or an unknown block flagged
/// HFL_SKIP_IF_UNKNOWN) may leave bytes in its body that the sub-parser did
/// not read. Skip them before returning `Step::Retry`, otherwise the header
/// reader re-parses the same block region O(N) times instead of O(1),
/// letting a crafted RAR5 file stall the reader (GHSA-9h2c-464f-j3hj).
fn skip_remaining_block(r: &mut Reader<'_>, body_start: i64, raw_hdr_size: usize) {
    if ahead(r, 1).is_some() {
        let body_used = usize::try_from(r.position() - body_start).unwrap_or(usize::MAX);
        if body_used < raw_hdr_size {
            let _ = r.consume(raw_hdr_size - body_used);
        }
    }
}

impl File {
    fn update_crc(&mut self, p: &[u8]) {
        // Don't update CRC32 if the file doesn't have the `stored_crc32`
        // info filled in.
        if self.stored_crc32 > 0 {
            self.calculated_crc32 = crc32(self.calculated_crc32, p);
        }

        // Check if the file uses an optional BLAKE2sp checksum algorithm.
        if let Some(state) = self.b2state.as_mut().filter(|_| self.has_blake2) {
            state.update(p);
        }
    }
}

impl Rar5 {
    fn init_unpack(&mut self) -> Res<()> {
        self.file.calculated_crc32 = 0;
        self.init_window_mask();

        let c = &mut self.cstate;
        c.window = Vec::new();
        c.filtered = Vec::new();

        if c.window_size > 0 {
            c.window = usize::try_from(c.window_size)
                .ok()
                .and_then(alloc_zeroed)
                .ok_or_else(silent_fatal)?;
        }

        c.dready = [None; 2];

        c.write_ptr = 0;
        c.last_write_ptr = 0;

        c.bd = DecodeTable::default();
        c.ld = DecodeTable::default();
        c.dd = DecodeTable::default();
        c.ldd = DecodeTable::default();
        c.rd = DecodeTable::default();
        Ok(())
    }

    /// Pushes a range of the output to the `dready` stack. Those values will
    /// be popped from this stack by `use_data`. Returns false (with the
    /// error recorded) if it is not possible.
    fn push_data_ready(
        &mut self,
        a: &Base,
        buf: Buf,
        start: usize,
        size: usize,
        offset: i64,
    ) -> bool {
        // Don't push if we're in skip mode. This is needed because solid
        // streams need full processing even if we're skipping data. After
        // fully processing the stream, we need to discard the generated
        // bytes, because we're interested only in the side effect: building
        // up the internal window circular buffer. This window buffer will be
        // used later during unpacking of requested data.
        if self.skip_mode != 0 {
            return true;
        }

        // Sanity check.
        if offset != self.file.last_offset.wrapping_add(self.file.last_size) {
            a.set_error(
                ARCHIVE_ERRNO_PROGRAMMER,
                Some(b"Sanity check error: output stream is not continuous"),
            );
            return false;
        }

        let c = &mut self.cstate;
        let Some(slot) = c.dready.iter_mut().find(|d| d.is_none()) else {
            // The stack is full. The code shouldn't allow such situation to
            // occur, so this is an internal error.
            a.set_error(
                ARCHIVE_ERRNO_PROGRAMMER,
                Some(b"Premature end of data_ready stack"),
            );
            return false;
        };
        let source = match buf {
            Buf::Window => &c.window,
            Buf::Filtered => &c.filtered,
        };
        let Some(data) = source.get(start..start.saturating_add(size)) else {
            a.set_error(
                ARCHIVE_ERRNO_PROGRAMMER,
                Some(b"Premature end of data_ready stack"),
            );
            return false;
        };
        *slot = Some(DataReady {
            buf,
            start,
            size,
            offset,
        });

        // These fields are used only in sanity checking.
        self.file.last_offset = offset;
        self.file.last_size = size as i64;

        // Calculate the checksum of this new block before submitting data
        // to libarchive's engine.
        self.file.update_crc(data);
        true
    }

    /// The `push_data` function submits the selected window range to the
    /// user. Next call of `use_data` will use the range. If it is wrapped
    /// inside the window circular buffer, it is submitted in two parts.
    fn push_window_data(&mut self, a: &Base, mut idx_begin: i64, mut idx_end: i64) {
        let c = &self.cstate;
        let wmask = c.window_mask;
        let solid_write_ptr = c.solid_offset.wrapping_add(c.last_write_ptr) & wmask;
        let last_write_ptr = c.last_write_ptr;
        let window_size = c.window_size;

        idx_begin = idx_begin.wrapping_add(c.solid_offset);
        idx_end = idx_end.wrapping_add(c.solid_offset);

        // Check if our unpacked data is wrapped inside the window circular
        // buffer.  If it's not wrapped, it can be copied out by using a
        // single memcpy, but when it's wrapped, we need to copy the first
        // part with one memcpy, and the second part with another memcpy.
        // The pushes fail only for a stream that is not continuous, which
        // upstream ignores here.
        if (idx_begin & wmask) > (idx_end & wmask) {
            // The data is wrapped (begin offset is bigger than end offset).
            let frag1_size = window_size - (idx_begin & wmask);
            let frag2_size = idx_end & wmask;

            // Copy the first part of the buffer first.
            self.push_data_ready(
                a,
                Buf::Window,
                solid_write_ptr as usize,
                frag1_size as usize,
                last_write_ptr,
            );
            // Copy the second part of the buffer.
            self.push_data_ready(
                a,
                Buf::Window,
                0,
                frag2_size as usize,
                last_write_ptr.wrapping_add(frag1_size),
            );

            self.cstate.last_write_ptr = last_write_ptr.wrapping_add(frag1_size + frag2_size);
        } else {
            // Data is not wrapped, so we can just use one call to copy the
            // data.
            self.push_data_ready(
                a,
                Buf::Window,
                solid_write_ptr as usize,
                (idx_end.wrapping_sub(idx_begin) & wmask) as usize,
                last_write_ptr,
            );

            self.cstate.last_write_ptr =
                last_write_ptr.wrapping_add(idx_end.wrapping_sub(idx_begin));
        }
    }

    /// Pops the first range from the `dready` stack, `None` when there is no
    /// data on the stack.
    fn use_data(&mut self) -> Option<DataReady> {
        self.cstate.dready.iter_mut().find_map(Option::take)
    }

    fn ready_slice(&self, d: &DataReady) -> Res<&[u8]> {
        let source = match d.buf {
            Buf::Window => &self.cstate.window,
            Buf::Filtered => &self.cstate.filtered,
        };
        source
            .get(d.start..d.start.saturating_add(d.size))
            .ok_or_else(|| {
                fatal(
                    ARCHIVE_ERRNO_PROGRAMMER,
                    "Premature end of data_ready stack",
                )
            })
    }

    /// This function will switch the multivolume archive file to another
    /// file, i.e. from part03 to part 04.
    fn advance_multivolume(&mut self, r: &mut Reader<'_>) -> Res<()> {
        // A small state machine that will skip unnecessary data, needed to
        // switch from one multivolume to another. Such skipping is needed if
        // we want to be an stream-oriented (instead of file-oriented)
        // unpacker.
        //
        // The state machine starts with `endarc` == 0. It also assumes that
        // current stream pointer points to some base block header.
        //
        // The `endarc` field is being set when the base block parsing
        // function encounters the 'end of archive' marker.
        loop {
            if self.main.endarc {
                self.main.endarc = false;
                while self.skip_base_block(r)? == Step::Retry {}
                return Ok(());
            }

            // Skip current base block. In order to properly skip it, we
            // really need to simply parse it and discard the results.
            //
            // The `skip_base_block` function tells us if we should continue
            // with skipping, or we should stop skipping. We're trying to
            // skip everything up to a base FILE block.
            match self.skip_base_block(r) {
                Ok(Step::Retry) => {}
                Err(Stop::Err(e)) => return Err(Stop::Err(e)),
                other => {
                    // There was an error during skipping, or we have just
                    // skipped a FILE base block...
                    if !self.main.endarc {
                        return other.map(|_| ());
                    }
                }
            }
        }
    }

    /// Merges the partial block from the first multivolume archive file, and
    /// partial block from the second multivolume archive file. The result is
    /// a chunk of memory containing the whole block, and the stream pointer
    /// is advanced to the next block in the second multivolume archive file.
    fn merge_block(&mut self, r: &mut Reader<'_>, block_size: i64) -> Res<()> {
        if self.merge_mode != 0 {
            return Err(fatal(
                ARCHIVE_ERRNO_PROGRAMMER,
                "Recursive merge is not allowed",
            ));
        }

        // Set a flag that we're in the switching mode.
        self.cstate.switch_multivolume = true;
        let ret = self.merge_chunks(r, block_size);
        if ret.is_err() {
            self.cstate.switch_multivolume = false;
        }
        ret
    }

    fn merge_chunks(&mut self, r: &mut Reader<'_>, block_size: i64) -> Res<()> {
        // Reallocate the memory which will hold the whole block. Increasing
        // the allocation block by 8 is due to the bit reading functions,
        // which are using additional 2 or 4 bytes: they read a little past
        // the end of the block.
        let block_len = usize::try_from(block_size).map_err(|_| silent_fatal())?;
        self.vol.push_buf = alloc_zeroed(block_len + 8).ok_or_else(|| {
            fatal(
                libc::ENOMEM,
                "Can't allocate memory for a merge block buffer",
            )
        })?;

        // A single block can span across multiple multivolume archive files,
        // so we use a loop here. This loop will consume enough multivolume
        // archive files until the whole block is read.
        let mut partial_offset = 0;
        loop {
            // Get the size of current block chunk in this multivolume
            // archive file and read it.
            let cur_block_size = self.file.bytes_remaining.min(block_size - partial_offset);

            if cur_block_size < 1 {
                // bytes_remaining is less than 1 at the wrong point in the
                // merge loop, indicating corrupt volume accounting.
                return Err(format_error(
                    "Encountered invalid block size during block merge",
                ));
            }

            // We are in the middle of merging a block that spans volumes, so
            // more data must follow; running out of input here means the
            // following volume is missing.
            let chunk_len = usize::try_from(cur_block_size).map_err(|_| silent_fatal())?;
            let lp = ahead(r, chunk_len).ok_or_else(truncated_multivolume_error)?;

            // Merge previous block chunk with current block chunk, or create
            // first block chunk if this is our first iteration.
            let start = partial_offset as usize;
            let Some(dst) = self.vol.push_buf.get_mut(start..start + chunk_len) else {
                // Sanity check; there should never be a situation where this
                // function reads more data than the block's size.
                return Err(fatal(
                    ARCHIVE_ERRNO_PROGRAMMER,
                    "Consumed too much data when merging blocks",
                ));
            };
            dst.copy_from_slice(lp.get(..chunk_len).unwrap_or_default());

            // Advance the stream read pointer by this block chunk size.
            r.consume(chunk_len).map_err(|_| silent_fatal())?;

            // Update the pointers. `partial_offset` contains information
            // about the sum of merged block chunks.
            partial_offset += cur_block_size;
            self.file.bytes_remaining -= cur_block_size;

            // If `partial_offset` is the same as `block_size`, this means
            // we've merged all block chunks and we have a valid full block.
            if partial_offset == block_size {
                break;
            }

            // If we don't have any bytes to read, this means we should
            // switch to another multivolume archive file.
            if self.file.bytes_remaining == 0 {
                self.merge_mode += 1;
                let ret = self.advance_multivolume(r);
                self.merge_mode -= 1;
                match ret {
                    // The block is only partially merged but the input
                    // ended, so the volume that holds the rest of it is
                    // missing.
                    Err(Stop::Eof) => return Err(truncated_multivolume_error()),
                    other => other?,
                }
            }
        }

        // If we're here, we can resume unpacking by processing the block
        // in the merge buffer.
        self.cstate.block_in_push_buf = true;
        Ok(())
    }

    fn process_block(&mut self, r: &mut Reader<'_>) -> Res<()> {
        let a = r.base();

        // If we don't have any data to be processed, this most probably
        // means we need to switch to the next volume.
        if self.main.volume && self.file.bytes_remaining == 0 {
            // Capture 'split after' before advancing: advance_multivolume()
            // parses following headers and overwrites this flag.
            let split_after = self.generic.split_after;
            match self.advance_multivolume(r) {
                // The file is promised to continue in a following volume,
                // but the input ended first.
                Err(Stop::Eof) if split_after => return Err(truncated_multivolume_error()),
                other => other?,
            }
        }

        let new_block = self.cstate.block_parsing_finished;
        if new_block {
            // The header size won't be bigger than 6 bytes.
            let p = ahead(r, 6).ok_or(Stop::Eof)?;

            // Read block_size by parsing block header. Validate the header
            // by calculating CRC byte stored inside the header. Size of the
            // header is not constant (block size can be stored either in 1
            // or 2 bytes), that's why block size is left out from the
            // header and returned as the second value.
            let (block_size, flags) = decompress::parse_block_header(p)?;
            self.last_block_flags = flags;

            // Skip block header. Next data is huffman tables, if present.
            let to_skip = 2 + i64::from((flags >> 3) & 7) + 1;

            // If the block header's to_skip value exceeds the declared
            // remaining data, the archive is malformed.
            if to_skip > self.file.bytes_remaining {
                return Err(format_error(
                    "Block header size exceeds remaining file data",
                ));
            }

            consume_or_eof(r, to_skip)?;
            self.file.bytes_remaining -= to_skip;

            // The block size gives information about the whole block size,
            // but the block could be stored in split form when using
            // multi-volume archives. In this case, the block size will be
            // bigger than the actual data stored in this file. Remaining
            // part of the data will be in another file.
            let mut cur_block_size = self.file.bytes_remaining.min(block_size);

            if block_size > self.file.bytes_remaining {
                // If current blocks' size is bigger than our data size, this
                // means we have a multivolume archive. In this case, skip
                // all base headers until the end of the file, proceed to
                // next "partXXX.rar" volume, find its signature, skip all
                // headers up to the first FILE base header, and continue
                // from there.
                //
                // Note that `merge_block` will update the `rar` context
                // structure quite extensively.
                self.merge_block(r, block_size)?;
                cur_block_size = block_size;

                // Current stream pointer should be now directly *after* the
                // block that spanned through multiple archive files. The
                // merge buffer should have the data of the *whole* block
                // (merged from partial blocks stored in multiple archives
                // files).
            } else {
                self.cstate.switch_multivolume = false;

                // Read the whole block size into memory. This can take up
                // to 8 megabytes of memory in theoretical cases. Might be
                // worth to optimize this and use a standard chunk of 4kb's.
                // (The 4 bytes are for the bit reader.)
                let need = usize::try_from(4 + cur_block_size).map_err(|_| Stop::Eof)?;
                ahead(r, need).ok_or(Stop::Eof)?;
                self.cstate.block_in_push_buf = false;
            }

            self.cstate.cur_block_size = cur_block_size;
            self.cstate.block_parsing_finished = false;
            self.bits = BitPos::default();
        }

        // Uncompress the block, or a part of it, depending on how many bytes
        // will be generated by uncompressing the block.
        //
        // In case too many bytes will be generated, calling this function
        // again will resume the uncompression operation.
        let before_decode = self.cstate.write_ptr;
        if self.cstate.block_in_push_buf {
            let buf = std::mem::take(&mut self.vol.push_buf);
            let ret = self.decode_block(a, &buf, new_block);
            self.vol.push_buf = buf;
            ret?;
        } else {
            // Block parsing not finished: the block is still where it was.
            let need = usize::try_from(4 + self.cstate.cur_block_size).map_err(|_| Stop::Eof)?;
            let p = ahead(r, need).ok_or(Stop::Eof)?;
            self.decode_block(a, p, new_block)?;
        }

        r.decoded(
            self.cstate
                .write_ptr
                .checked_sub(before_decode)
                .ok_or_else(|| fatal(libc::EOVERFLOW, "RAR decoded byte count overflow"))?,
        )?;

        if self.cstate.block_parsing_finished
            && !self.cstate.switch_multivolume
            && self.cstate.cur_block_size > 0
        {
            // If we're processing a normal block, consume the whole block.
            // We can do this because we've already read the whole block to
            // memory.
            r.consume(self.cstate.cur_block_size)?;
            self.file.bytes_remaining -= self.cstate.cur_block_size;
        } else if self.cstate.switch_multivolume {
            // Don't consume the block if we're doing multivolume
            // processing. The volume switching function will consume the
            // proper count of bytes instead.
            self.cstate.switch_multivolume = false;
        }

        Ok(())
    }

    /// This function uncompresses the data that is stored in the <FILE> base
    /// block.
    ///
    /// The FILE base block looks like this:
    ///
    /// `<header><huffman tables><block_1><block_2>...<block_n>`
    ///
    /// The <header> is a block header, that is parsed in
    /// `parse_block_header()`. It contains metadata needed to know when we
    /// should stop looking for more <block_n> blocks.
    ///
    /// <huffman tables> contain data needed to set up the huffman tables,
    /// needed for the actual decompression.
    ///
    /// Each <block_n> consists of series of literals:
    ///
    /// `<literal><literal><literal>...<literal>`
    ///
    /// Those literals generate the uncompression data. They operate on a
    /// circular buffer, sometimes writing raw data into it, sometimes
    /// referencing some previous data inside this buffer, and sometimes
    /// declaring a filter that will need to be executed on the data stored
    /// in the circular buffer. It all depends on the literal that is used.
    ///
    /// Sometimes blocks produce output data, sometimes they don't. For
    /// example, for some huge files that use lots of filters, sometimes a
    /// block is filled with only filter declaration literals. Such blocks
    /// won't produce any data in the circular buffer.
    ///
    /// Sometimes blocks will produce 4 bytes of data, and sometimes 1
    /// megabyte, because a literal can reference previously decompressed
    /// data. For example, there can be a literal that says: 'append a byte
    /// 0xFE here', and after it another literal can say 'append 1 megabyte
    /// of data from circular buffer offset 0x12345'. This is how RAR format
    /// handles compressing repeated patterns.
    ///
    /// The RAR compressor creates those literals and the actual efficiency
    /// of compression depends on what those literals are. The literals can
    /// also be seen as a kind of a non-turing-complete virtual machine that
    /// simply tells the decompressor what it should do.
    fn do_uncompress_file(&mut self, r: &mut Reader<'_>) -> Res<Step> {
        let a = r.base();

        if !self.cstate.initialized {
            // Don't perform full context reinitialization if we're
            // processing a solid archive.
            if !self.main.solid || self.cstate.window.is_empty() {
                self.init_unpack()?;
            }
            self.cstate.initialized = true;
        }

        // Don't allow extraction if window_size is invalid.
        if self.cstate.window_size == 0
            || (self.cstate.window.len() as i64) < self.cstate.window_size
        {
            // This should never happen in valid files.
            return Err(failed(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Invalid window size declaration in this file",
            ));
        }

        if self.cstate.all_filters_applied {
            // We use a loop here, but standard case allows for just 1
            // iteration. The loop will iterate if process_block() didn't
            // generate any data at all. This can happen if the block
            // contains only filter definitions (this is common in big
            // files).
            loop {
                self.process_block(r)?;

                if self.cstate.last_write_ptr == self.cstate.write_ptr {
                    // The block didn't generate any new data, so just
                    // process a new block if this one wasn't the last block
                    // in the file.
                    if (self.last_block_flags >> 6) & 1 != 0 {
                        return Err(Stop::Eof);
                    }
                    continue;
                }

                // The block has generated some new data, so break the loop.
                break;
            }
        }

        // Try to run filters. If filters won't be applied, it means that
        // insufficient data was generated.
        if self.apply_filters(a)? {
            return Ok(Step::Ok);
        }

        let c = &self.cstate;
        let max_end_pos = match c.filters.front() {
            // Check if we can write something before hitting first filter.
            Some(flt) => flt.block_start.min(c.write_ptr),
            // There are no filters defined, or all filters were applied.
            // This means we can just store the data without any
            // postprocessing.
            None => c.write_ptr,
        };

        if max_end_pos == c.last_write_ptr {
            // We can't write anything yet. The block uncompression function
            // did not generate enough data, and no filter can be applied. At
            // the same time we don't have any data that can be stored
            // without filter postprocessing. This means we need to wait for
            // more data to be generated, so we can apply the filters.
            //
            // Signal the caller that we need more data to be able to do
            // anything.
            Ok(Step::Retry)
        } else {
            // We can write the data before hitting the first filter. So
            // let's do it. The push_window_data() function will effectively
            // return the selected data block to the user application.
            let last_write_ptr = c.last_write_ptr;
            self.push_window_data(a, last_write_ptr, max_end_pos);
            self.cstate.last_write_ptr = max_end_pos;
            Ok(Step::Ok)
        }
    }

    fn uncompress_file(&mut self, r: &mut Reader<'_>) -> Res<()> {
        // Sometimes the uncompression function will return a 'retry'
        // signal. If this will happen, we have to retry the function.
        while self.do_uncompress_file(r)? == Step::Retry {}
        Ok(())
    }

    fn do_unstore_file<'x>(&mut self, r: &'x mut Reader<'_>, offset: &mut i64) -> Res<&'x [u8]> {
        // This function returns without any data on more than one path, and
        // the end of the stored data is the position all of them should
        // report.
        *offset = self.cstate.last_unstore_ptr;

        if self.file.bytes_remaining == 0 && self.main.volume && self.generic.split_after {
            self.cstate.switch_multivolume = true;
            let ret = self.advance_multivolume(r);
            self.cstate.switch_multivolume = false;

            match ret {
                // We only reach this advance because 'split after' was set,
                // i.e. the file is promised to continue in a following
                // volume, but the input ended before we could reach it (for
                // example, only the first volume of the set was supplied).
                // The data decoded so far is incomplete, so report
                // truncation rather than silently returning a short read as
                // a clean end of file.
                Err(Stop::Eof) => return Err(truncated_multivolume_error()),
                // Failed to advance to next multivolume archive file.
                other => other?,
            }
        }

        // A negative count is an absurd size that read-ahead refuses.
        let to_read =
            usize::try_from(self.file.bytes_remaining.min(64 * 1024)).unwrap_or(usize::MAX);
        if to_read == 0 {
            return Err(Stop::Eof);
        }

        let later = r.consume_later();
        let Some(p) = ahead(r, to_read) else {
            return Err(format_error("I/O error when unstoring file"));
        };
        let p = p.get(..to_read).unwrap_or_default();
        later.consume(to_read);

        *offset = self.cstate.last_unstore_ptr;

        self.file.bytes_remaining -= to_read as i64;
        self.cstate.last_unstore_ptr += to_read as i64;

        if self.skip_mode == 0 {
            self.file.update_crc(p);
        }
        Ok(p)
    }

    fn do_unpack<'x>(&mut self, r: &'x mut Reader<'_>, offset: &mut i64) -> Res<&'x [u8]> {
        const STORE: u32 = 0;
        const BEST: u32 = 5;

        if self.file.service {
            return self.do_unstore_file(r, offset);
        }
        match self.cstate.method {
            STORE => self.do_unstore_file(r, offset),
            // FASTEST, FAST, NORMAL, GOOD and BEST.
            1..=BEST => {
                // No data is returned here. But because a sparse-file aware
                // caller (like archive_read_data_into_fd) may treat
                // zero-size as a sparse file block, we need to update the
                // offset accordingly. At this point the decoder doesn't have
                // any pending uncompressed data blocks, so the current
                // position in the output file should be last_write_ptr.
                *offset = self.cstate.last_write_ptr;
                self.uncompress_file(r)?;
                Ok(&[])
            }
            method => Err(format_error(format!(
                "Compression method not supported: 0x{method:x}"
            ))),
        }
    }

    fn verify_checksums(&mut self) -> Res<()> {
        // Check checksums only when actually unpacking the data. There's no
        // need to calculate checksum when we're skipping data in solid
        // archives (skipping in solid archives is the same thing as
        // unpacking compressed data and discarding the result).
        if self.skip_mode != 0 {
            return Ok(());
        }

        // During unpacking, on each unpacked block we're calling the
        // update_crc() function. Since we are here, the unpacking process is
        // already over and we can check if calculated checksum (CRC32 or
        // BLAKE2sp) is the same as what is stored in the archive.
        if self.file.stored_crc32 > 0 {
            // Check CRC32 only when the file contains a CRC32 value for this
            // file.
            if self.file.calculated_crc32 != self.file.stored_crc32 {
                // Checksums do not match; the unpacked file is corrupted.
                return Err(failed(ARCHIVE_ERRNO_FILE_FORMAT, "Checksum error: CRC32"));
            }
        }

        if self.file.has_blake2 {
            // BLAKE2sp is an optional checksum algorithm that is added to
            // RARv5 archives when using the `-htb` switch during creation of
            // archive.
            let mut b2_buf = [0u8; 32];
            if let Some(state) = self.file.b2state.take() {
                let _ = state.finalize(&mut b2_buf);
            }

            if self.file.blake2sp != b2_buf {
                return Err(failed(ARCHIVE_ERRNO_FILE_FORMAT, "Checksum error: BLAKE2"));
            }
        }

        // Finalization for this file has been successfully completed.
        Ok(())
    }

    /// The unpacked data of the entry, a piece at a time. `offset` is where
    /// the piece, or the end of the data, is in the entry.
    fn read_block<'x>(&'x mut self, r: &'x mut Reader<'_>, offset: &mut i64) -> Res<&'x [u8]> {
        if self.has_encrypted_entries == ENCRYPTION_DONT_KNOW {
            self.has_encrypted_entries = 0;
        }

        if self.headers_are_encrypted || self.cstate.data_encrypted {
            return Err(failed(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Reading encrypted data is not currently supported",
            ));
        }

        if self.file.dir {
            // Don't process any data if this file entry was declared as a
            // directory. This is needed, because entries marked as directory
            // doesn't have any dictionary buffer allocated, so it's
            // impossible to perform any decompression.
            return Err(format_error(
                "Can't decompress an entry marked as a directory",
            ));
        }

        if self.skip_mode == 0 && self.cstate.last_write_ptr > self.file.unpacked_size {
            return Err(fatal(
                ARCHIVE_ERRNO_PROGRAMMER,
                "Unpacker has written too many bytes",
            ));
        }

        if let Some(d) = self.use_data() {
            *offset = d.offset;
            return self.ready_slice(&d);
        }

        if self.file.eof {
            // The entry is over; report the end of the unpacked data, so
            // that a sparse-file aware caller does not have to guess where
            // it is.
            *offset = self.cstate.last_write_ptr;
            return Err(Stop::Eof);
        }

        let data = self.do_unpack(r, offset)?;

        if self.file.bytes_remaining == 0 && self.cstate.last_write_ptr == self.file.unpacked_size {
            // If all bytes of current file were processed, run
            // finalization.
            //
            // Finalization will check checksum against proper values. If
            // some of the checksums will not match, we'll return an error
            // value in the last `archive_read_data` call to signal an error
            // to the user.
            self.file.eof = true;
            self.verify_checksums()?;
        }

        Ok(data)
    }

    fn skip_data(&mut self, r: &mut Reader<'_>) -> Res<()> {
        if self.main.solid && !self.cstate.data_encrypted {
            // In solid archives, instead of skipping the data, we need to
            // extract it, and dispose the result. The side effect of this
            // operation will be setting up the initial window buffer state
            // needed to be able to extract the selected file. Note that this
            // is only possible when data within this solid block is not
            // encrypted, in which case we'll skip and fail if the user tries
            // to read data.

            // Make sure to process all blocks in the compressed stream.
            while self.file.bytes_remaining > 0 {
                // Setting the "skip mode" will allow us to skip checksum
                // checks during data skipping. Checking the checksum of
                // skipped data isn't really necessary and it's only slowing
                // things down.
                //
                // This is incremented instead of set because this data
                // skipping function can be called recursively.
                self.skip_mode += 1;

                // We're disposing 1 block of data.
                let ret = self.read_block(r, &mut 0).map(|_| ());

                // Turn off "skip mode".
                self.skip_mode -= 1;

                // Propagate any potential error conditions to the caller.
                ret?;
            }
        } else {
            // In standard archives, we can just jump over the compressed
            // stream. Each file in non-solid archives starts from an empty
            // window buffer.
            r.consume(self.file.bytes_remaining)?;
            self.file.bytes_remaining = 0;
        }
        Ok(())
    }
}
