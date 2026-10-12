/*-
 * Copyright (c) 2003-2011 Tim Kientzle
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

// Ported from libarchive/archive_read.c.

//! The read side of `struct archive`: the filter chain with its read-ahead
//! buffer, and the traits that format readers and decompression filters are
//! written against.
//!
//! # The chain
//!
//! A read handle pulls bytes through a chain of stages. The bottom stage is
//! the *client*: whatever supplies the raw bytes (a file, a block of memory,
//! the C caller's callbacks). Each decompression `Filter` sits on top of the
//! stage below it, and the top stage is what a `Format` reads. Every stage
//! has the same buffering logic: it asks its filter for blocks and serves
//! `read_ahead` requests from them, copying into a private buffer only when
//! a request spans blocks.
//!
//! Filters and formats reach the stage below through a `Reader`. A format
//! sees the whole chain (it reads the top stage); a filter's `read` sees the
//! chain below itself, so the same `Reader` methods serve both.

use crate::archive::*;
use crate::entry::Entry;
use crate::read_add_passphrase::Passphrases;
use crate::util::Error;
use std::any::Any;
use std::cell::{Cell, RefCell};
use std::ffi::{CStr, c_int};
use std::rc::Rc;

/// `ARCHIVE_ERRNO_FILE_FORMAT`: unrecognized or invalid file format.
/// `EFTYPE` where the platform has it, else `EILSEQ`, as upstream picks.
#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
pub const ARCHIVE_ERRNO_FILE_FORMAT: c_int = libc::EFTYPE;
#[cfg(not(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
pub const ARCHIVE_ERRNO_FILE_FORMAT: c_int = libc::EILSEQ;
/// `ARCHIVE_ERRNO_PROGRAMMER`: illegal usage of the library.
pub const ARCHIVE_ERRNO_PROGRAMMER: c_int = libc::EINVAL;

/// The `ARCHIVE_FILTER_*` codes.
pub mod filter_code {
    use std::ffi::c_int;

    pub const NONE: c_int = 0;
    pub const GZIP: c_int = 1;
    pub const BZIP2: c_int = 2;
    pub const COMPRESS: c_int = 3;
    pub const PROGRAM: c_int = 4;
    pub const LZMA: c_int = 5;
    pub const XZ: c_int = 6;
    pub const UU: c_int = 7;
    pub const RPM: c_int = 8;
    pub const LZIP: c_int = 9;
    pub const LRZIP: c_int = 10;
    pub const LZOP: c_int = 11;
    pub const GRZIP: c_int = 12;
    pub const LZ4: c_int = 13;
    pub const ZSTD: c_int = 14;
}

/// The `ARCHIVE_FORMAT_*` base codes.
pub mod format_code {
    use std::ffi::c_int;

    pub const BASE_MASK: c_int = 0xff0000;
    pub const CPIO: c_int = 0x10000;
    pub const TAR: c_int = 0x30000;
    pub const ISO9660: c_int = 0x40000;
    pub const ZIP: c_int = 0x50000;
    pub const EMPTY: c_int = 0x60000;
    pub const AR: c_int = 0x70000;
    pub const MTREE: c_int = 0x80000;
    pub const RAW: c_int = 0x90000;
    pub const XAR: c_int = 0xA0000;
    pub const LHA: c_int = 0xB0000;
    pub const CAB: c_int = 0xC0000;
    pub const RAR: c_int = 0xD0000;
    pub const SEVENZIP: c_int = 0xE0000;
    pub const WARC: c_int = 0xF0000;
    pub const RAR_V5: c_int = 0x100000;
}

#[cfg(test)]
mod ar_example;
pub mod filter;
pub mod format;
mod limits;
use limits::Budget;
pub use limits::ReadLimits;

/// A seek origin, as `lseek` and the client seek callback take it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Whence {
    Set,
    Cur,
    End,
}

impl Whence {
    /// The C `whence` (`SEEK_SET` and friends).
    pub fn to_c(self) -> c_int {
        match self {
            Whence::Set => libc::SEEK_SET,
            Whence::Cur => libc::SEEK_CUR,
            Whence::End => libc::SEEK_END,
        }
    }

    /// The origin for a C `whence`.
    #[allow(dead_code)] // for the formats' seek_data (phase 4)
    pub fn from_c(whence: c_int) -> Option<Whence> {
        match whence {
            libc::SEEK_SET => Some(Whence::Set),
            libc::SEEK_CUR => Some(Whence::Cur),
            libc::SEEK_END => Some(Whence::End),
            _ => None,
        }
    }
}

/// How a call that can warn went: the failures are `Err`.
#[must_use = "a warning has to reach the return value"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// `ARCHIVE_OK`.
    Ok,
    /// `ARCHIVE_WARN`: it worked, but something was wrong. The message is
    /// already recorded on the handle (see `Reader::warn`).
    Warn,
    /// `ARCHIVE_EOF`: there is nothing more. Only `Format::read_header` has
    /// an end.
    Eof,
}

impl Status {
    /// The `ARCHIVE_*` code.
    pub fn code(self) -> c_int {
        match self {
            Status::Ok => ARCHIVE_OK,
            Status::Warn => ARCHIVE_WARN,
            Status::Eof => ARCHIVE_EOF,
        }
    }
}

impl Base {
    /// Records a warning, as `archive_set_error` before `return
    /// ARCHIVE_WARN`, and gives the status to return.
    #[must_use = "return the status so the warning reaches the caller"]
    pub fn warn(&self, errno: c_int, msg: impl AsRef<[u8]>) -> Status {
        self.set_error(errno, Some(msg.as_ref()));
        Status::Warn
    }

    /// Sets the format code and name `archive_format` reports.
    pub fn set_format(&self, code: c_int, name: &'static CStr) {
        self.format.set(code);
        self.format_name.set(Some(name));
    }

    /// Sets a formatted `archive_format_name`, such as "CAB 1.3 (LZX)", in
    /// place of a static one. The name ends at a NUL, as a C string would.
    pub fn set_format_name(&self, name: &[u8]) {
        let mut buf = self.format_name_buf.borrow_mut();
        buf.clear();
        buf.extend_from_slice(crate::string::until_nul(name));
        buf.push(0);
        self.format_name.set(None);
    }
}

/// What a decompression filter implements. A filter owns its output buffer
/// and exposes it as the current block; the stage above it copies from the
/// block only when a request spans blocks, so most reads are zero-copy.
pub trait Filter {
    /// The name `archive_filter_name` reports; it must stay valid for as
    /// long as the filter.
    fn name(&self) -> &CStr;

    /// The `ARCHIVE_FILTER_*` code `archive_filter_code` reports.
    fn code(&self) -> c_int;

    /// Produces the next block, readable through `block`. An empty block is
    /// end of input. An error is fatal for the stage: the filter has its
    /// message set in the `Error` (or has already recorded it, for a bare
    /// `Error::recorded`; or upstream sets none, for `Error::silent`), and the
    /// stage reports `ARCHIVE_FATAL` from then on.
    ///
    /// `up` reads the stage below. Whatever `up` hands out is only valid
    /// until the next call on it, so a filter that passes bytes through
    /// copies them into its own block.
    fn read(&mut self, up: &mut Reader<'_>) -> Result<(), Error>;

    /// The block the last `read` produced, exactly: the same bytes and the
    /// same length every time it is called, until the next `read`. The stage
    /// records the length after `read` and indexes into the block later, so
    /// a block that changes (or a `read` that leaves `block` stale) corrupts
    /// the stream; debug builds assert on it.
    fn block(&self) -> &[u8];

    /// Fills in the entry with what the filter's header says (the gzip
    /// file name and time, say), for formats that make an entry from a
    /// stream with no structure. The default has nothing to add.
    fn read_header(&mut self, _up: &mut Reader<'_>, _entry: &mut Entry) -> Result<Status, Error> {
        Ok(Status::Ok)
    }

    /// Closes just this filter; the stage below is closed separately. A
    /// failure is reported by `archive_read_close`, but every filter is
    /// closed regardless.
    fn close(&mut self, _a: &Base) -> Result<Status, Error> {
        Ok(Status::Ok)
    }
}

/// A source of raw bytes: what sits at the bottom of the chain. A client can
/// supply several `nodes` (the volumes of a multi-volume archive), which the
/// core reads one after another, calling `switch` between them.
///
/// Each call gets the handle `a`, to record a warning and carry on (a stream
/// that fails to read but returns its bytes, say). A returned `Err` is a
/// failure.
///
/// The C callbacks, `archive_read_open_memory`'s block of memory and the file
/// readers all implement this; the C-callback implementation is the only one
/// that needs `unsafe`, and lives in `ffi`.
pub trait Client {
    /// How many nodes the client has.
    fn nodes(&self) -> usize {
        1
    }

    /// Opens node `node`. A failure aborts the open; the core then calls
    /// `close` for every node.
    fn open(&mut self, _a: &Base, _node: usize) -> Result<(), Error> {
        Ok(())
    }

    /// Reads the next block of node `node` into `block`; an empty block is
    /// the end of the node.
    fn read(&mut self, _a: &Base, node: usize) -> Result<(), Error>;

    /// The block the last `read` produced, exactly, until the next `read`
    /// (see `Filter::block`).
    fn block(&self) -> &[u8];

    /// Whether `skip` is worth calling. When it is not, the core reads and
    /// discards instead.
    fn can_skip(&self) -> bool {
        false
    }

    /// Skips up to `request` bytes forward and returns how many were
    /// skipped; the client may skip less (to keep block alignment) or
    /// nothing (0 makes the core read and discard).
    fn skip(&mut self, _a: &Base, _node: usize, _request: i64) -> Result<i64, Error> {
        Ok(0)
    }

    /// Whether `seek` works.
    fn can_seek(&self) -> bool {
        false
    }

    /// Seeks within node `node` and returns the new offset in the node. A
    /// negative-code error means the node cannot seek.
    fn seek(
        &mut self,
        _a: &Base,
        _node: usize,
        _offset: i64,
        _whence: Whence,
    ) -> Result<i64, Error> {
        Err(Error::recorded(ARCHIVE_FAILED))
    }

    /// Closes node `node`.
    fn close(&mut self, _a: &Base, _node: usize) -> Result<Status, Error> {
        Ok(Status::Ok)
    }

    /// The device and inode of the input being read, if it is a regular
    /// file: extraction must not overwrite it.
    fn skip_file(&self) -> Option<(i64, i64)> {
        None
    }

    /// Moves from node `from` to node `to`. Without a dedicated switch, the
    /// old node is closed and the new one opened.
    fn switch(&mut self, a: &Base, from: usize, to: usize) -> Result<(), Error> {
        let closed = self.close(a, from);
        let opened = self.open(a, to).map(|()| Status::Ok);
        worse(closed, opened).map(|_| ())
    }
}

/// Of two results, the worse: the failure with the lower code, else a
/// warning, else OK.
pub(crate) fn worse(a: Result<Status, Error>, b: Result<Status, Error>) -> Result<Status, Error> {
    match (a, b) {
        (Err(a), Err(b)) => Err(if b.code < a.code { b } else { a }),
        (Err(e), _) | (_, Err(e)) => Err(e),
        (Ok(Status::Warn), _) | (_, Ok(Status::Warn)) => Ok(Status::Warn),
        _ => Ok(Status::Ok),
    }
}

/// Where one node of a multi-volume client begins and how long it is, in the
/// concatenated stream; negative until known.
struct Node {
    begin_position: i64,
    total_size: i64,
}

/// The bottom stage's filter: `Client` plus the multi-volume bookkeeping.
struct ClientFilter {
    client: Box<dyn Client>,
    nodes: Vec<Node>,
    /// The node being read.
    cursor: usize,
}

impl ClientFilter {
    fn new(client: Box<dyn Client>) -> Self {
        let nodes = (0..client.nodes().max(1))
            .map(|_| Node {
                begin_position: -1,
                total_size: -1,
            })
            .collect();
        ClientFilter {
            client,
            nodes,
            cursor: 0,
        }
    }

    /// `client_switch_proxy`: makes node `index` the current one.
    fn switch_to(&mut self, a: &Base, index: usize) -> Result<(), Error> {
        // Don't do anything if already in the specified data node.
        if self.cursor == index {
            return Ok(());
        }
        let from = std::mem::replace(&mut self.cursor, index);
        self.client.switch(a, from, index)
    }

    /// `client_close_proxy`: closes every node, returning the worst failure.
    fn close_all(&mut self, a: &Base) -> Result<Status, Error> {
        let mut r = Ok(Status::Ok);
        for i in 0..self.nodes.len() {
            r = worse(r, self.client.close(a, i));
        }
        r
    }

    /// The seek of `__archive_read_filter_seek`, across nodes. `position` is
    /// the stage's position in the concatenated stream. Returns the new
    /// position.
    fn seek(&mut self, a: &Base, position: i64, offset: i64, whence: Whence) -> Result<i64, Error> {
        let mut offset = offset;
        let mut cursor = 0;
        let mut r;
        match whence {
            Whence::Cur | Whence::Set => {
                if whence == Whence::Cur {
                    // Adjust the offset and use SEEK_SET instead.
                    offset = offset.saturating_add(position);
                }
                while let Some(next) = self.known_node_before(cursor, offset) {
                    cursor = next;
                }
                loop {
                    self.switch_to(a, cursor)?;
                    r = self.client.seek(a, cursor, 0, Whence::End)?;
                    self.nodes[cursor].total_size = r;
                    if self.node_end(cursor).saturating_sub(1) > offset
                        || cursor + 1 >= self.nodes.len()
                    {
                        break;
                    }
                    cursor += 1;
                    self.nodes[cursor].begin_position = self.node_end(cursor - 1);
                }
                offset = offset.saturating_sub(self.nodes[cursor].begin_position);
                if offset < 0 || offset > self.nodes[cursor].total_size {
                    return Err(Error::recorded(ARCHIVE_FATAL));
                }
                r = self.client.seek(a, cursor, offset, Whence::Set)?;
            }
            Whence::End => {
                while self.nodes[cursor].begin_position >= 0
                    && self.nodes[cursor].total_size >= 0
                    && cursor + 1 < self.nodes.len()
                {
                    cursor += 1;
                    self.nodes[cursor].begin_position = self.node_end(cursor - 1);
                }
                loop {
                    self.switch_to(a, cursor)?;
                    self.nodes[cursor].total_size = self.client.seek(a, cursor, 0, Whence::End)?;
                    r = self.node_end(cursor);
                    if cursor + 1 >= self.nodes.len() {
                        break;
                    }
                    cursor += 1;
                    self.nodes[cursor].begin_position = r;
                }
                while r.saturating_add(offset) < self.nodes[cursor].begin_position {
                    offset = offset.saturating_add(self.nodes[cursor].total_size);
                    if cursor == 0 {
                        break;
                    }
                    cursor -= 1;
                    r = self.node_end(cursor);
                }
                offset = r
                    .saturating_add(offset)
                    .saturating_sub(self.nodes[cursor].begin_position);
                self.switch_to(a, cursor)?;
                r = self.client.seek(a, cursor, offset, Whence::Set)?;
            }
        }
        Ok(r.saturating_add(self.nodes[cursor].begin_position))
    }

    /// Where node `index` ends in the concatenated stream.
    fn node_end(&self, index: usize) -> i64 {
        self.nodes[index]
            .begin_position
            .saturating_add(self.nodes[index].total_size)
    }

    /// If node `cursor` is fully known and ends before `offset`, and there is
    /// a node after it, the index of that node (whose start is now known).
    fn known_node_before(&mut self, cursor: usize, offset: i64) -> Option<usize> {
        let n = &self.nodes[cursor];
        if n.begin_position < 0
            || n.total_size < 0
            || self.node_end(cursor).saturating_sub(1) > offset
            || cursor + 1 >= self.nodes.len()
        {
            return None;
        }
        self.nodes[cursor + 1].begin_position = self.node_end(cursor);
        Some(cursor + 1)
    }
}

impl Filter for ClientFilter {
    fn name(&self) -> &CStr {
        c"none"
    }

    fn code(&self) -> c_int {
        filter_code::NONE
    }

    /// `client_read_proxy`: reads from the current node, and automatically
    /// continues with the next node at the end of one. This simplifies
    /// handling of multi volume archives for readers.
    fn read(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
        loop {
            self.client.read(up.a, self.cursor)?;
            if self.client.block().is_empty() && self.cursor + 1 < self.nodes.len() {
                // Continue with next client object if available.
                match self.switch_to(up.a, self.cursor + 1) {
                    Ok(()) => continue,
                    Err(e) => {
                        up.a.raise(e);
                    }
                }
            }
            return Ok(());
        }
    }

    fn block(&self) -> &[u8] {
        self.client.block()
    }

    fn close(&mut self, a: &Base) -> Result<Status, Error> {
        self.close_all(a)
    }
}

/// What a stage reads from: the client at the bottom of the chain, or a
/// decompression filter.
enum Imp {
    Client(ClientFilter),
    Filter(Box<dyn Filter>),
}

impl Imp {
    fn filter(&self) -> &dyn Filter {
        match self {
            Imp::Client(c) => c,
            Imp::Filter(f) => f.as_ref(),
        }
    }

    fn filter_mut(&mut self) -> &mut dyn Filter {
        match self {
            Imp::Client(c) => c,
            Imp::Filter(f) => f.as_mut(),
        }
    }
}

/// One link of the chain: a filter with the read-ahead state that serves
/// requests from its blocks. Mirrors `struct archive_read_filter`.
struct Stage {
    imp: Imp,
    /// Bytes consumed from this stage so far.
    position: i64,
    /// Bytes `consume_later` promised to consume; taken by the next call
    /// that reads or moves the position (`Reader::flush`).
    later: Rc<Cell<usize>>,
    /// Set for the client stage when it can skip or seek.
    can_skip: bool,
    can_seek: bool,

    // The copy buffer, used when a request spans blocks. `buffer` holds
    // `next` stale bytes and then `avail` bytes of data.
    buffer: Vec<u8>,
    buffer_size: usize,
    next: usize,
    avail: usize,

    // The filter's current block: its length, the read offset in it and the
    // bytes not yet consumed. Anything in the copy buffer was copied from
    // just before `client_next` in the same block.
    client_total: usize,
    client_next: usize,
    client_avail: usize,

    end_of_file: bool,
    closed: bool,
    fatal: bool,
}

/// Where `fill` left the data a request asked for.
#[derive(Clone, Copy)]
enum Loc {
    Client,
    Copy,
}

impl Stage {
    fn new(imp: Imp) -> Self {
        let (can_skip, can_seek) = match &imp {
            Imp::Client(c) => (c.client.can_skip(), c.client.can_seek()),
            Imp::Filter(_) => (false, false),
        };
        Stage {
            imp,
            position: 0,
            later: Rc::default(),
            can_skip,
            can_seek,
            buffer: Vec::new(),
            buffer_size: 0,
            next: 0,
            avail: 0,
            client_total: 0,
            client_next: 0,
            client_avail: 0,
            end_of_file: false,
            closed: false,
            fatal: false,
        }
    }

    /// The bytes at `loc`.
    fn data(&self, loc: Loc) -> &[u8] {
        let (buf, start, len) = match loc {
            Loc::Client => (
                self.imp.filter().block(),
                self.client_next,
                self.client_avail,
            ),
            Loc::Copy => (self.buffer.as_slice(), self.next, self.avail),
        };
        let end = start.saturating_add(len);
        debug_assert!(end <= buf.len(), "a stage's data is outside its buffer");
        buf.get(start..end).unwrap_or_default()
    }

    /// `read_client_data`: pulls the next block from the filter. Returns its
    /// length; 0 is end of file. A failure is recorded and makes the stage
    /// fatal.
    fn read_block(&mut self, up: &mut Reader<'_>) -> Result<usize, Error> {
        if self.end_of_file {
            return Ok(0);
        }
        self.client_next = 0;
        if let Err(e) = self.imp.filter_mut().read(up) {
            self.client_total = 0;
            self.client_avail = 0;
            self.fatal = true;
            up.a.raise(e);
            return Err(Error::recorded(ARCHIVE_FATAL));
        }
        let n = self.imp.filter().block().len();
        if let Err(e) = up.budget.decoded(n) {
            self.client_total = 0;
            self.client_avail = 0;
            self.fatal = true;
            up.a.raise(e);
            return Err(Error::recorded(ARCHIVE_FATAL));
        }
        self.client_total = n;
        self.client_avail = n;
        self.end_of_file = n == 0;
        Ok(n)
    }

    /// `__archive_read_filter_ahead`: makes at least `request` bytes
    /// (default 1) available, copying across blocks if need be. Short data
    /// is end of file. Does not move the file pointer.
    fn fill(&mut self, up: &mut Reader<'_>, request: usize) -> Result<Loc, Error> {
        if self.fatal {
            return Err(Error::recorded(ARCHIVE_FATAL));
        }
        // request == 0 is perfectly well-defined.
        let min = request.max(1);

        // Keep pulling more data until we can satisfy the request.
        loop {
            // We can satisfy directly from the client buffer if everything
            // currently in the copy buffer is still in the client buffer.
            let both = self.client_avail.saturating_add(self.avail);
            if self.client_total >= both && both >= min {
                // "Roll back" to the client buffer.
                self.client_avail = both;
                self.client_next = self.client_next.saturating_sub(self.avail);
                // The copy buffer is now empty.
                self.avail = 0;
                self.next = 0;
                self.buffer.clear();
                return Ok(Loc::Client);
            }

            // If we can satisfy from the copy buffer, we're done.
            if self.avail >= min {
                return Ok(Loc::Copy);
            }

            // If we've used up the client data, get more.
            if self.client_avail == 0 {
                if self.read_block(up)? == 0 {
                    // Premature end-of-file. Return whatever we do have.
                    return Ok(Loc::Copy);
                }
                continue;
            }

            // We can't satisfy the request from the copy buffer or the
            // existing client data, so we need to copy more client data
            // over to the copy buffer. Don't waste time buffering more than
            // we need to, or more than is available.
            let tocopy = (min - self.avail).min(self.client_avail);
            if let Err(e) = self.make_room(min, tocopy) {
                self.fatal = true;
                up.a.raise(e);
                return Err(Error::recorded(ARCHIVE_FATAL));
            }
            let end = self.client_next.saturating_add(tocopy);
            debug_assert_eq!(
                self.client_total,
                self.imp.filter().block().len(),
                "a filter's block() must be what its last read produced"
            );
            let src = self.imp.filter().block().get(self.client_next..end);
            let Some(src) = src else {
                // The filter's block shrank under us.
                self.fatal = true;
                return Err(Error::recorded(ARCHIVE_FATAL));
            };
            self.buffer.extend_from_slice(src);
            // Remove this data from the client buffer and add it to the copy
            // buffer.
            self.client_next = end;
            self.client_avail -= tocopy;
            self.avail += tocopy;
        }
    }

    /// Ensures the copy buffer can take data up to `min` bytes: grows it
    /// (doubling, watching for overflow) or moves the data forward.
    fn make_room(&mut self, min: usize, tocopy: usize) -> Result<(), Error> {
        let no_memory = || Error::fatal(libc::ENOMEM, "Unable to allocate copy buffer");
        if min > self.buffer_size {
            let mut size = if self.buffer_size == 0 {
                min
            } else {
                self.buffer_size
            };
            while size < min {
                size = size.checked_mul(2).ok_or_else(no_memory)?;
            }
            // Now size >= min, so allocate a new buffer and move the data
            // into it. `min` comes from the archive and may exceed the input,
            // so reserve at most 1 MiB up front; `fill` grows it as data
            // arrives.
            let mut buffer = Vec::new();
            buffer
                .try_reserve_exact(size.min(1 << 20))
                .map_err(|_| no_memory())?;
            buffer.extend_from_slice(self.data(Loc::Copy));
            self.buffer = buffer;
            self.buffer_size = size;
            self.next = 0;
        } else if self.next > 0 && min > self.buffer_size.saturating_sub(self.next) {
            // Move data forward in the copy buffer.
            self.buffer.drain(..self.next);
            self.next = 0;
        }
        self.buffer.try_reserve(tocopy).map_err(|_| no_memory())
    }

    /// `advance_file_pointer`: moves the file pointer forward by up to
    /// `request` bytes and returns how many it moved, fewer than requested
    /// only at end of file. An error is recorded and makes the stage fatal.
    fn advance(&mut self, up: &mut Reader<'_>, request: i64) -> Result<i64, Error> {
        if self.fatal {
            return Err(Error::recorded(ARCHIVE_FATAL));
        }
        let mut request = request;
        let mut skipped = 0;

        // Use up the copy buffer first, then the client buffer.
        let n = eat(&mut self.next, &mut self.avail, request);
        let m = eat(&mut self.client_next, &mut self.client_avail, request - n);
        request -= n + m;
        self.position = self.position.saturating_add(n + m);
        skipped += n + m;
        if request == 0 {
            return Ok(skipped);
        }

        // If there's an optimized skip function, use it.
        if self.can_skip {
            while request > 0 {
                let get = self.client_skip(up, request)?;
                if get < 0 || get > request {
                    self.fatal = true;
                    return Err(Error::recorded(ARCHIVE_FATAL));
                }
                if get == 0 {
                    break;
                }
                up.budget.decoded(u64::try_from(get).unwrap_or(u64::MAX))?;
                self.position = self.position.saturating_add(get);
                skipped += get;
                request -= get;
            }
            if request == 0 {
                return Ok(skipped);
            }
        } else if self.can_seek && request > 64 * 1024 {
            // If the client provided a seeker but not a skipper, we can use
            // the seeker to skip forward.
            //
            // Note: This isn't always a good idea. The client skipper is
            // allowed to skip by less than requested if it needs to maintain
            // block alignment. The seeker is not allowed to play such games,
            // so using the seeker here may be a performance loss compared to
            // just reading and discarding. That's why we only do this for
            // skips of over 64k.
            let before = self.position;
            let after = self.client_seek(up, request, Whence::Cur)?;
            if Some(after) != before.checked_add(request) {
                self.fatal = true;
                return Err(Error::recorded(ARCHIVE_FATAL));
            }
            up.budget
                .decoded(u64::try_from(request).unwrap_or(u64::MAX))?;
            self.position = after;
            skipped += request;
            return Ok(skipped);
        }

        // Use ordinary reads as necessary to complete the request.
        loop {
            let n = self.read_block(up)?;
            if n == 0 {
                return Ok(skipped);
            }
            let n = i64::try_from(n).unwrap_or(i64::MAX);
            if n >= request {
                // `request` fits in the block: `n` is a length.
                self.client_next = usize::try_from(request).unwrap_or(0);
                self.client_avail -= self.client_next;
                self.position = self.position.saturating_add(request);
                return Ok(skipped + request);
            }
            self.position = self.position.saturating_add(n);
            skipped += n;
            request -= n;
        }
    }

    /// The client's skip, for a stage that can skip.
    fn client_skip(&mut self, up: &mut Reader<'_>, request: i64) -> Result<i64, Error> {
        let Imp::Client(c) = &mut self.imp else {
            return Ok(0);
        };
        c.client.skip(up.a, c.cursor, request).map_err(|e| {
            self.fatal = true;
            Error::recorded(up.a.raise(e))
        })
    }

    /// The client's seek in the current node, without the multi-volume
    /// logic: DO NOT use the skipper here! If we transparently handled
    /// forward seek here by using the skipper, that will break other
    /// libarchive code that assumes a successful forward seek means it can
    /// also seek backwards.
    fn client_seek(
        &mut self,
        up: &mut Reader<'_>,
        offset: i64,
        whence: Whence,
    ) -> Result<i64, Error> {
        let Imp::Client(c) = &mut self.imp else {
            return Err(Error::recorded(ARCHIVE_FAILED));
        };
        c.client.seek(up.a, c.cursor, offset, whence).map_err(|e| {
            self.fatal = true;
            Error::recorded(up.a.raise(e))
        })
    }

    /// `__archive_read_filter_seek`: seeks the stream and discards what was
    /// buffered. Fails with `ARCHIVE_FAILED` if the stage can't seek.
    fn seek(&mut self, up: &mut Reader<'_>, offset: i64, whence: Whence) -> Result<i64, Error> {
        if self.closed || self.fatal {
            return Err(Error::recorded(ARCHIVE_FATAL));
        }
        let Imp::Client(c) = &mut self.imp else {
            return Err(Error::recorded(ARCHIVE_FAILED));
        };
        if !self.can_seek {
            return Err(Error::recorded(ARCHIVE_FAILED));
        }
        let r = c.seek(up.a, self.position, offset, whence);

        // Ouch. Clearing the buffer like this hurts, especially at bid time.
        // A lot of our efficiency at bid time comes from having bidders
        // reuse the data we've already read.
        //
        // TODO: If the seek request is in data we already have, then don't
        // call the seek callback.
        //
        // TODO: Zip seeks to end-of-file at bid time. If other formats also
        // start doing this, we may need to find a way for clients to fudge
        // the seek offset to a block boundary.
        self.avail = 0;
        self.client_avail = 0;
        self.next = 0;
        self.buffer.clear();
        match r {
            Ok(position) => {
                self.position = position;
                self.end_of_file = false;
                Ok(position)
            }
            Err(e) => {
                self.fatal = true;
                Err(Error::recorded(up.a.raise(e)))
            }
        }
    }

    /// Closes the filter once, and frees the buffer.
    fn close(&mut self, a: &Base) -> Result<Status, Error> {
        let r = if self.closed {
            Ok(Status::Ok)
        } else {
            self.closed = true;
            self.imp.filter_mut().close(a)
        };
        self.buffer = Vec::new();
        self.buffer_size = 0;
        self.next = 0;
        self.avail = 0;
        r
    }
}

/// Consumes up to `request` of the `avail` bytes at `next`; returns how many.
fn eat(next: &mut usize, avail: &mut usize, request: i64) -> i64 {
    let n = usize::try_from(request).map_or(*avail, |r| r.min(*avail));
    *next = next.saturating_add(n);
    *avail -= n;
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// What filters and formats read through: the stages of the chain up to and
/// including the one being read, plus the handle they report to.
///
/// A format gets a `Reader` over the whole chain. A filter's `read` gets one
/// over the stages below it.
///
/// Every method that fails has already recorded the error on the handle
/// (the message, or `Error::recorded` when the callee did), so the `Error` it
/// returns is a bare status that is safe to `?` upward.
pub struct Reader<'a> {
    chain: &'a mut [Stage],
    budget: &'a Budget,
    metadata: bool,
    a: &'a Base,
    passphrases: &'a mut Passphrases,
    /// The handle's own entry (upstream's `a->entry`), for the calls a
    /// format makes in the middle of reading data that upstream passes it to.
    entry: Option<&'a mut Entry>,
}

impl<'a> Reader<'a> {
    /// Charges newly decoded format output, including hidden headers and skips.
    pub(crate) fn decoded(&self, n: impl TryInto<u64>) -> Result<(), Error> {
        self.budget.decoded(n)
    }

    /// Checks an eagerly parsed entry table before allocating its next entry.
    pub(crate) fn check_entries(&self, n: impl TryInto<u64>) -> Result<(), Error> {
        self.budget.check_entries(n)
    }

    /// Charges metadata retained outside the ordinary header input stream.
    pub(crate) fn metadata(&self, n: impl TryInto<u64>) -> Result<(), Error> {
        self.budget.metadata(n)
    }

    /// Includes headers read internally while seeking or changing volumes.
    pub(crate) fn with_metadata<T>(&mut self, f: impl FnOnce(&mut Self) -> T) -> T {
        let metadata = std::mem::replace(&mut self.metadata, true);
        let result = f(self);
        self.metadata = metadata;
        result
    }

    /// The configured per-decoder memory cap, bounded by the existing hard cap.
    pub(crate) fn decoder_memory(&self, hard_cap: u64) -> u64 {
        self.budget
            .limits
            .decoder_memory
            .map_or(hard_cap, |n| n.min(hard_cap))
    }

    /// The handle, to record warnings and set the format. The reference does
    /// not borrow the reader, so it can be used while a `read_ahead` slice is
    /// held: take it first, `let a = r.base();`.
    pub fn base(&self) -> &'a Base {
        self.a
    }

    /// The top stage and a `Reader` for the stages below it.
    fn split(&mut self) -> Option<(&mut Stage, Reader<'_>)> {
        let (top, below) = self.chain.split_last_mut()?;
        let up = Reader {
            chain: below,
            budget: self.budget,
            metadata: false,
            a: self.a,
            passphrases: &mut *self.passphrases,
            entry: None,
        };
        Some((top, up))
    }

    /// Calls `f` with this reader and the handle's own entry, which upstream's
    /// `a->entry` is: what a format passes to the header reads it makes in
    /// the middle of `read_data`, `read_data_skip` and `seek_data`. `None`
    /// outside those.
    pub fn with_entry<T>(&mut self, f: impl FnOnce(&mut Self, Option<&mut Entry>) -> T) -> T {
        let mut entry = self.entry.take();
        let result = f(self, entry.as_deref_mut());
        self.entry = entry;
        result
    }

    /// `__archive_read_header`: lets the top filter fill in `entry`.
    pub fn read_filter_header(&mut self, entry: &mut Entry) -> Result<Status, Error> {
        match self.split() {
            Some((top, mut up)) => top.imp.filter_mut().read_header(&mut up, entry),
            None => Ok(Status::Ok),
        }
    }

    /// `__archive_read_ahead`: looks ahead in the input stream without
    /// moving the file pointer.
    ///
    /// - `Some(slice)` is everything currently buffered: at least `min`
    ///   bytes, often much more (the rest of the current block). If you just
    ///   want "some data", ask for 1 byte and look at the length, then
    ///   `consume` whatever you used. With `min == 0` it is `Some` even at
    ///   the end of the input, and may be empty.
    /// - `None` means the input ends before `min` bytes are available. Use
    ///   `peek_available` to see what there is.
    /// - An error is a failed read, or the stream having failed before.
    ///
    /// The slice stays valid until the next call on this reader or the
    /// stages below it.
    pub fn read_ahead(&mut self, min: usize) -> Result<Option<&[u8]>, Error> {
        let data = self.peek_available(min)?;
        Ok((data.len() >= min).then_some(data))
    }

    /// Like `read_ahead`, but a short slice is returned as it is instead of
    /// `None`: whatever is available when the input ends before `min` bytes
    /// (empty at the end of input). Check the length before indexing it:
    /// `peek_available(512)?[..512]` panics on a short archive.
    pub fn peek_available(&mut self, min: usize) -> Result<&[u8], Error> {
        self.budget.check()?;
        self.flush()?;
        let Some((top, mut up)) = self.split() else {
            return Ok(&[]);
        };
        let loc = top.fill(&mut up, min)?;
        Ok(top.data(loc))
    }

    /// Reads the next `n` bytes into a `Vec` and consumes them, or `None`
    /// (nothing consumed) if the input ends first. For fixed-size fields a
    /// format keeps, where a `read_ahead` slice would be in the way.
    #[allow(dead_code)] // used by the format readers (phases 3-4)
    pub fn read_exact_vec(&mut self, n: usize) -> Result<Option<Vec<u8>>, Error> {
        let Some(data) = self.read_ahead(n)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(n)
            .map_err(|_| Error::fatal(libc::ENOMEM, "No memory for archive input"))?;
        bytes.extend_from_slice(data.get(..n).unwrap_or_default());
        self.consume(n)?;
        Ok(Some(bytes))
    }

    /// Consumes `n` bytes that a `read_ahead` (or `peek_available`) just
    /// showed were there: `consume`, but running out is a bug in the caller,
    /// which debug builds assert on, rather than a truncated input.
    #[allow(dead_code)] // used by the format readers (phases 3-4)
    pub fn consume_ahead(&mut self, n: usize) -> Result<(), Error> {
        self.flush()?;
        debug_assert!(
            self.chain
                .last()
                .is_some_and(|s| s.avail + s.client_avail >= n),
            "consume_ahead({n}) without that much read ahead"
        );
        self.consume(n)
    }

    /// `__archive_read_consume`: moves the file pointer forward by `n`, which
    /// the reader should have looked at (or not) first. It is a fatal error
    /// for the stream to end first, or for `n` to be negative.
    pub fn consume(&mut self, n: impl TryInto<i64>) -> Result<(), Error> {
        self.flush()?;
        self.consume_now(n)
    }

    /// `consume` without the flush.
    fn consume_now(&mut self, n: impl TryInto<i64>) -> Result<(), Error> {
        self.budget.check()?;
        let a = self.a;
        let request = match n.try_into() {
            Ok(n) if n >= 0 => n,
            _ => return Err(Error::recorded(ARCHIVE_FATAL)),
        };
        if request == 0 {
            return Ok(());
        }
        if self.metadata {
            self.budget
                .metadata(u64::try_from(request).unwrap_or(u64::MAX))?;
        }
        let skipped = match self.split() {
            // A failure counts as nothing skipped.
            Some((top, mut up)) => match top.advance(&mut up, request) {
                Ok(n) => n,
                Err(_) => {
                    up.budget.check()?;
                    0
                }
            },
            None => 0,
        };
        if skipped == request {
            return Ok(());
        }
        // We hit EOF before we satisfied the skip request.
        a.raise(Error::fatal(
            ARCHIVE_ERRNO_MISC,
            format!("Truncated input file (needed {request} bytes, only {skipped} available)"),
        ));
        Err(Error::recorded(ARCHIVE_FATAL))
    }

    /// A handle for `consume_later`. Like `base()` it does not borrow the
    /// reader, so it can be taken before `read_ahead` and used while the
    /// slice is held.
    pub fn consume_later(&self) -> ConsumeLater<'a> {
        ConsumeLater(
            self.chain
                .last()
                .map(|s| Rc::clone(&s.later))
                .unwrap_or_default(),
            self.metadata.then_some(self.budget),
        )
    }

    /// Consumes what `consume_later` promised. Runs first in every method
    /// that reads or moves the position, and before the core calls the
    /// format. A failure is exactly the one an explicit `consume` would give.
    pub(crate) fn flush(&mut self) -> Result<(), Error> {
        let n = self.chain.last().map_or(0, |s| s.later.take());
        let metadata = std::mem::replace(&mut self.metadata, false);
        let result = self.consume_now(n);
        self.metadata = metadata;
        result
    }

    /// Moves the file pointer forward by up to `n` bytes, using the client's
    /// skip where it has one, and returns how far it moved: less than `n`
    /// only at the end of the stream. `consume` is this with the end of the
    /// stream being an error.
    pub fn skip(&mut self, n: i64) -> Result<i64, Error> {
        self.flush()?;
        if n < 0 {
            return Err(Error::recorded(ARCHIVE_FATAL));
        }
        match self.split() {
            Some((top, mut up)) => top.advance(&mut up, n),
            None => Ok(0),
        }
    }

    /// `__archive_read_seek`: seeks the input stream, discarding what was
    /// buffered. `ARCHIVE_FAILED` if the input can't seek. Returns the new
    /// position.
    pub fn seek(&mut self, offset: i64, whence: Whence) -> Result<i64, Error> {
        self.flush()?;
        match self.split() {
            Some((top, mut up)) => top.seek(&mut up, offset, whence),
            None => Err(Error::recorded(ARCHIVE_FATAL)),
        }
    }

    /// The number of bytes consumed from the stream: the offset in the
    /// uncompressed data, where the next `read_ahead` looks. Bytes promised
    /// to `consume_later` are not counted until the next call that moves the
    /// position, as in upstream, where the format consumes them at the top
    /// of its next call.
    ///
    /// A `read_ahead` slice borrows the stage this number lives in, so the
    /// position can't be read while one is held; read it first. (It doesn't
    /// change until `consume`, so nothing is lost.)
    pub fn position(&self) -> i64 {
        self.chain.last().map_or(0, |s| s.position)
    }

    /// Whether `seek` can work. Seeking is only possible if the client seeks
    /// and no filter is in the way.
    #[allow(dead_code)] // used by the format readers (phases 3-4)
    pub fn can_seek(&self) -> bool {
        self.chain.last().is_some_and(|s| s.can_seek)
    }

    /// Sets the format code and name `archive_format` reports.
    pub fn set_format(&self, code: c_int, name: &'static CStr) {
        self.a.set_format(code, name);
    }

    /// The size of the `archive_read_data` request being served
    /// (`read_data_is_posix_read` with `read_data_requested`), `None` for
    /// `archive_read_data_block`. A format may hand out less than it has.
    pub fn read_data_requested(&self) -> Option<usize> {
        self.a.read_data_requested.get()
    }

    /// `__archive_reset_read_data`, for a `seek_data` that restarts the
    /// entry's data; the core does it when the call returns.
    pub fn reset_read_data(&self) {
        self.a.read_data_reset.set(true);
    }

    /// Records a warning; return the `Status` it gives to say so.
    #[must_use = "return the status so the warning reaches the caller"]
    #[allow(dead_code)] // used by the format readers (phases 3-4)
    pub fn warn(&self, errno: c_int, msg: impl AsRef<[u8]>) -> Status {
        self.a.warn(errno, msg)
    }

    /// `__archive_read_reset_passphrase`: call when you start looking for a
    /// passphrase for an entry.
    #[allow(dead_code)] // used by the zip, rar and 7zip readers (phase 4)
    pub fn reset_passphrase(&mut self) {
        self.passphrases.reset();
    }

    /// `__archive_read_next_passphrase`: the next passphrase to try, `None`
    /// when the candidates and the client's callback have run out.
    #[allow(dead_code)] // used by the zip, rar and 7zip readers (phase 4)
    pub fn next_passphrase(&mut self) -> Option<Vec<u8>> {
        self.passphrases.next()
    }
}

/// Consumes bytes at the start of the reader's next call: the way for a
/// format to return a `read_ahead` slice from `read_data` and still move
/// the position past it, since the slice must stay valid until then. See
/// `Reader::consume_later`.
pub struct ConsumeLater<'a>(Rc<Cell<usize>>, Option<&'a Budget>);

impl ConsumeLater<'_> {
    /// Consumes `n` more bytes before the reader's next call that reads or
    /// moves the position. Only bytes that `read_ahead` showed were there.
    pub fn consume(&self, n: usize) {
        if let Some(budget) = self.1 {
            let _ = budget.metadata(n);
        }
        self.0.set(self.0.get().saturating_add(n));
    }
}

/// What a read handle owns beyond `Base`.
#[derive(Default)]
pub struct Read {
    /// The client first, then each filter on top of the one before; the last
    /// stage is what formats read.
    chain: Vec<Stage>,
    budget: Rc<Budget>,
    pub(crate) passphrases: Passphrases,
    /// Registered filter bidders, in registration order.
    bidders: Vec<Box<dyn FilterBidder>>,
    /// Whether filters were appended by hand, so bidding is skipped.
    bypass_filter_bidding: bool,
    /// Registered formats, in registration order.
    pub(crate) formats: Vec<Box<dyn Format>>,
    /// The active format: an index into `formats`.
    pub(crate) format: Option<usize>,
    /// File offset of the beginning of the most recently read header.
    header_position: i64,
    /// Declared size of the entry whose header was most recently read, if
    /// any: lets format-agnostic consumers like `archive_read_data_into_fd`
    /// cap their output at the size an entry actually promised.
    pub(crate) entry_bytes_declared: Option<i64>,
    read_data: ReadData,
    /// The entry `archive_read_next_header` hands out: a raw pointer from
    /// `Box::into_raw`, so the `&mut Entry` C calls derive never aliases a
    /// live `Box`. `archive_read_new` makes it, and `archive_free` takes it
    /// back with `take_entry`; NULL for a handle that is not C's.
    pub(crate) entry: *mut Entry,
    /// The device and inode extraction must not overwrite, as the client or
    /// `archive_read_extract_set_skip_file` set it.
    pub(crate) skip_file: Option<(i64, i64)>,
    pub(crate) extract: Option<crate::read_extract2::Extract>,
    /// The client callbacks `archive_read_set_*_callback` have collected,
    /// until the archive is opened.
    pub(crate) callbacks: crate::ffi::client::Callbacks,
}

/// `archive_read_new`, without the entry `archive_read_next_header` uses.
pub fn new() -> Handle {
    Handle {
        base: Base::new(READ_MAGIC),
        kind: Kind::Read(RefCell::new(Read::default())),
    }
}

impl Read {
    pub(crate) fn set_limits(&mut self, a: &Base, limits: ReadLimits) -> c_int {
        let depth = self
            .chain
            .iter()
            .filter(|s| matches!(s.imp, Imp::Filter(_)))
            .count();
        if depth != 0 && limits.decoder_memory != self.budget.limits.decoder_memory {
            return a.raise(Error::new(
                ARCHIVE_FAILED,
                libc::EINVAL,
                "Decoder memory limit must be configured before appending filters",
            ));
        }
        if limits.filter_depth.is_some_and(|max| depth > max) {
            return a.raise(Error::new(
                ARCHIVE_FAILED,
                libc::EINVAL,
                "Configured filter depth is below the appended filter count",
            ));
        }
        let Some(budget) = Rc::get_mut(&mut self.budget) else {
            return a.raise(Error::fatal(libc::EINVAL, "Archive limits are in use"));
        };
        budget.limits = limits;
        ARCHIVE_OK
    }

    pub(crate) fn resource_option(&mut self, a: &Base, o: &[u8], v: Option<&[u8]>) -> c_int {
        let value = match v {
            Some(b"unlimited") | None => None,
            Some(v) => {
                let parsed = v.iter().try_fold(0u64, |n, &b| {
                    if !b.is_ascii_digit() {
                        return None;
                    }
                    n.checked_mul(10)?.checked_add(u64::from(b - b'0'))
                });
                let Some(n) = parsed.filter(|_| !v.is_empty()) else {
                    return a.raise(Error::new(
                        ARCHIVE_FAILED,
                        libc::EINVAL,
                        "Invalid archive resource limit: expected an unsigned decimal integer",
                    ));
                };
                Some(n)
            }
        };
        let mut limits = self.budget.limits;
        match o {
            b"decoded-bytes" => limits.decoded_bytes = value,
            b"entries" => limits.entries = value,
            b"metadata-bytes" => limits.metadata_bytes = value,
            b"decoder-memory" => limits.decoder_memory = value,
            b"filter-depth" => {
                limits.filter_depth = match value.map(usize::try_from).transpose() {
                    Ok(n) => n,
                    Err(_) => {
                        return a.raise(Error::new(
                            ARCHIVE_FAILED,
                            libc::EINVAL,
                            "Invalid archive resource limit: filter depth is too large",
                        ));
                    }
                };
            }
            _ => return ARCHIVE_WARN,
        }
        self.set_limits(a, limits)
    }

    /// A reader over the whole chain.
    #[cfg(test)]
    pub fn reader<'a>(&'a mut self, a: &'a Base) -> Reader<'a> {
        Reader {
            chain: &mut self.chain,
            budget: &self.budget,
            metadata: false,
            a,
            passphrases: &mut self.passphrases,
            entry: None,
        }
    }

    /// Opens `client`'s first node and installs it as the bottom of the
    /// chain, below any filters appended before. On failure every node is
    /// closed; the caller records the error.
    fn open_client(&mut self, a: &Base, client: Box<dyn Client>) -> Result<(), Error> {
        let mut client = ClientFilter::new(client);
        if let Err(e) = client.client.open(a, 0) {
            // If the open failed, call the closer to clean up.
            let _ = client.close_all(a);
            return Err(e);
        }
        client.nodes[0].begin_position = 0;
        self.chain.insert(0, Stage::new(Imp::Client(client)));
        Ok(())
    }

    /// `close_filters`: closes each filter in the pipeline, top first. The
    /// result is the worst failure.
    fn close_filters(&mut self, a: &Base) -> c_int {
        let mut r = ARCHIVE_OK;
        for stage in self.chain.iter_mut().rev() {
            match stage.close(a) {
                Ok(Status::Warn) => r = r.min(ARCHIVE_WARN),
                Ok(_) => {}
                Err(e) => r = r.min(a.raise(e)),
            }
        }
        r
    }

    /// `__archive_read_free_filters`: closes the filters and drops them.
    fn free_filters(&mut self, a: &Base) {
        self.close_filters(a);
        self.chain.clear();
    }

    /// `_archive_read_close`, after the caller has checked the handle.
    pub fn close(&mut self, a: &Base) -> c_int {
        if a.state.get() == state::CLOSED {
            return ARCHIVE_OK;
        }
        a.clear_error();
        a.state.set(state::CLOSED);
        let extract = self.extract.as_mut().map_or(ARCHIVE_OK, |e| e.close());
        // TODO: clean up the formatters.
        // Release the filter objects.
        self.close_filters(a).min(extract)
    }

    /// `_archive_read_free`, after the caller has checked the handle: closes
    /// the archive if needed. The rest is released by `Drop`, once the
    /// caller drops the handle; client callbacks still see it alive (the
    /// caller's check of the handle is in `archive_free`).
    pub fn free(&mut self, a: &Base) -> c_int {
        let r = match a.state.get() {
            state::CLOSED | state::FATAL => ARCHIVE_OK,
            _ => self.close(a),
        };
        // Close filters a failed open or a fatal error left open.
        self.free_filters(a);
        r
    }

    /// `get_filter`: the stage `n` below the top, or the client for -1.
    fn get_filter(&self, n: c_int) -> Option<&Stage> {
        if n == -1 {
            return self.chain.first();
        }
        let from_top = usize::try_from(n).ok()?;
        let index = self.chain.len().checked_sub(from_top.checked_add(1)?)?;
        self.chain.get(index)
    }

    /// `_archive_filter_count`.
    pub fn filter_count(&self) -> c_int {
        c_int::try_from(self.chain.len()).unwrap_or(c_int::MAX)
    }

    /// `_archive_filter_bytes`.
    pub fn filter_bytes(&self, n: c_int) -> i64 {
        self.get_filter(n).map_or(-1, |s| s.position)
    }

    /// `_archive_filter_code`.
    pub fn filter_code(&self, n: c_int) -> c_int {
        self.get_filter(n).map_or(-1, |s| s.imp.filter().code())
    }

    /// `_archive_filter_name`.
    pub fn filter_name(&self, n: c_int) -> Option<&CStr> {
        self.get_filter(n).map(|s| s.imp.filter().name())
    }
}

/// What `Format::read_data` produces.
pub enum Data<'r> {
    /// The next block of the entry's data, which starts at `offset` in the
    /// entry (sparse files have gaps between blocks).
    Block { data: &'r [u8], offset: i64 },
    /// The end of the entry's data, at `offset` (a sparse file may end in a
    /// hole).
    Eof { offset: i64 },
    /// A problem with the entry's data, already recorded on the handle (see
    /// `Reader::warn`): there is no block this time, and the caller gets
    /// `ARCHIVE_WARN`. A later call may carry on. `offset` is what the
    /// caller gets as the block's offset.
    #[allow(dead_code)] // returned by the zip and rar readers (phase 4)
    Warn { offset: i64 },
}

/// What a format reader implements. A format owns its own state in `self`;
/// everything it reads comes through the `Reader` passed to each call, so a
/// format's state, the stream and the entry are separate borrows.
///
/// # Statuses
///
/// A call that can warn returns `Result<Status, Error>`. `Status::Warn` means
/// carry on, with the warning already recorded (`Reader::warn`); `Err` is only
/// `ARCHIVE_FAILED` (this entry can't be read, but the next may be) or
/// `ARCHIVE_FATAL`, with its message in the `Error`. So a warning never ends
/// the function early by way of `?`.
///
/// # Deferred consume
///
/// A format that returns data in place from `read_data` can't consume it
/// first: the slice must stay valid until the next call. So it returns a
/// slice from `read_ahead`, then calls `consume_later(n)` (take the handle
/// first, `let later = r.consume_later();`, as with `base()`). The core
/// consumes the `n` bytes before the next call into the format
/// (`read_header`, `read_data`, `read_data_skip`) and before the next
/// `Reader` call that reads or moves the position, so the format has no
/// bookkeeping of its own. `position()` counts them only from then on, as
/// `archive_read_header_position` and `archive_filter_bytes` do in upstream.
///
/// # Example
///
/// A small `ar` reader, the shape every reader has. It is compiled and run by
/// the tests.
///
#[doc = concat!("```ignore\n", include_str!("read/ar_example.rs"), "```")]
pub trait Format: Any {
    /// The name `archive_read_set_format` and the option modules use.
    fn name(&self) -> &'static str;

    /// How well the stream matches this format: 0 for not at all. Peek with
    /// `read_ahead`; the core rewinds a seekable stream afterwards.
    /// `best_bid` is the best bid so far, so an expensive check can be
    /// skipped. `ARCHIVE_FATAL` aborts the open.
    fn bid(&mut self, r: &mut Reader<'_>, best_bid: c_int) -> Result<c_int, Error>;

    /// Handles a format option. `None` if the format has no options at all;
    /// otherwise `Status::Ok` if it took the option and `Status::Warn` if it
    /// doesn't know it.
    fn options(
        &mut self,
        _a: &Base,
        _key: &[u8],
        _value: Option<&[u8]>,
    ) -> Option<Result<Status, Error>> {
        None
    }

    /// Reads the next entry's header into `entry`: `Status::Eof` at the end
    /// of the archive, `Status::Warn` for an entry that is usable but not
    /// quite right.
    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error>;

    /// The next block of the entry's data. A format that returns the data in
    /// place (the usual zero-copy case) calls `consume_later` for it.
    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error>;

    /// Skips the rest of the entry's data. The default reads and discards it.
    fn read_data_skip(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        loop {
            match self.read_data(r)? {
                Data::Block { .. } => {}
                Data::Eof { .. } => return Ok(Status::Ok),
                Data::Warn { .. } => return Ok(Status::Warn),
            }
        }
    }

    /// `archive_seek_data`. `whence` is the caller's, unchecked, as upstream
    /// passes it; `Whence::from_c` converts the valid ones.
    fn seek_data(
        &mut self,
        _r: &mut Reader<'_>,
        _offset: i64,
        _whence: c_int,
    ) -> Result<i64, Error> {
        Err(Error::new(
            ARCHIVE_FAILED,
            ARCHIVE_ERRNO_MISC,
            "Cannot seek data with this format",
        ))
    }

    /// `ARCHIVE_READ_FORMAT_CAPS_*` bits.
    fn capabilities(&self) -> c_int {
        0
    }

    /// `archive_read_has_encrypted_entries` for a format that can tell.
    fn has_encrypted_entries(&self) -> c_int {
        ENCRYPTION_DONT_KNOW
    }
}

/// `ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW`.
pub const ENCRYPTION_DONT_KNOW: c_int = -1;
/// `ARCHIVE_READ_FORMAT_ENCRYPTION_UNSUPPORTED`.
pub const ENCRYPTION_UNSUPPORTED: c_int = -2;
/// `ARCHIVE_READ_FORMAT_CAPS_ENCRYPT_DATA` and `_METADATA`.
pub const CAPS_ENCRYPT: c_int = 1 | 2;

/// A decompression filter's bidder. Bidding works like this: the core asks
/// each registered bidder, with the stream so far, how well it matches. The
/// winner initializes a new filter that becomes the top of the chain, and
/// the process repeats until no bidder bids above 0.
pub trait FilterBidder {
    /// Taste the stream (`read_ahead` on `up`) to see if this filter handles
    /// it: 0 for not at all, higher for a surer match.
    fn bid(&mut self, up: &mut Reader<'_>) -> Result<c_int, Error>;

    /// Creates the filter. `up` is the stream the filter will sit on.
    fn init(&mut self, up: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error>;
}

/// At most this many formats or filter bidders can be registered.
const MAX_REGISTERED: usize = 16;

/// We won't build a filter pipeline with more stages than this.
const MAX_NUMBER_FILTERS: usize = 25;

impl Read {
    /// `__archive_read_register_format`. A format of a type that is already
    /// registered is a warning (and is dropped).
    pub fn register_format(&mut self, format: Box<dyn Format>) -> Result<Status, Error> {
        let id = (*format).type_id();
        if self.formats.iter().any(|f| (**f).type_id() == id) {
            return Ok(Status::Warn);
        }
        if self.formats.len() >= MAX_REGISTERED {
            return Err(Error::fatal(
                libc::ENOMEM,
                "Not enough slots for format registration",
            ));
        }
        self.formats.push(format);
        Ok(Status::Ok)
    }

    /// `__archive_read_register_bidder`.
    pub fn register_bidder(&mut self, bidder: Box<dyn FilterBidder>) -> Result<Status, Error> {
        if self.bidders.len() >= MAX_REGISTERED {
            return Err(Error::fatal(
                libc::ENOMEM,
                "Not enough slots for filter registration",
            ));
        }
        self.bidders.push(bidder);
        Ok(Status::Ok)
    }

    /// `archive_read_append_filter_last_bidder`: puts the filter of the most
    /// recently registered bidder on the chain without bidding.
    pub fn append_last_bidder(&mut self, a: &Base) -> c_int {
        let Self {
            chain,
            passphrases,
            bidders,
            budget,
            ..
        } = self;
        let Some(bidder) = bidders.last_mut() else {
            return a.raise(Error::fatal(
                ARCHIVE_ERRNO_PROGRAMMER,
                "Internal error: no bidder to append",
            ));
        };
        if let Err(e) = budget.filter_depth(chain.len() + 1) {
            return a.raise(e);
        }
        let mut rd = Reader {
            chain,
            budget,
            metadata: false,
            a,
            passphrases,
            entry: None,
        };
        match bidder.init(&mut rd) {
            Ok(filter) => {
                chain.push(Stage::new(Imp::Filter(filter)));
                self.bypass_filter_bidding = true;
                ARCHIVE_OK
            }
            Err(e) => {
                a.raise(e);
                self.free_filters(a);
                ARCHIVE_FATAL
            }
        }
    }

    /// `choose_filters`: lets the bidders build the chain of filters.
    fn choose_filters(&mut self, a: &Base) -> c_int {
        for _ in 0..MAX_NUMBER_FILTERS {
            let mut best_bid = 0;
            let mut best = None;
            for (i, bidder) in self.bidders.iter_mut().enumerate() {
                let mut rd = Reader {
                    chain: &mut self.chain,
                    budget: &self.budget,
                    metadata: false,
                    a,
                    passphrases: &mut self.passphrases,
                    entry: None,
                };
                let bid = match bidder.bid(&mut rd) {
                    Ok(bid) => bid,
                    Err(e) => {
                        a.raise(e);
                        self.free_filters(a);
                        return ARCHIVE_FATAL;
                    }
                };
                if bid > best_bid {
                    best_bid = bid;
                    best = Some(i);
                }
            }
            let mut rd = Reader {
                chain: &mut self.chain,
                budget: &self.budget,
                metadata: false,
                a,
                passphrases: &mut self.passphrases,
                entry: None,
            };
            let Some(best) = best else {
                // If no bidder, we're done. Verify the filter by asking it
                // for some data.
                if rd.peek_available(1).is_err() {
                    self.free_filters(a);
                    return ARCHIVE_FATAL;
                }
                return ARCHIVE_OK;
            };
            if let Err(e) = rd.budget.filter_depth(rd.chain.len()) {
                a.raise(e);
                self.free_filters(a);
                return ARCHIVE_FATAL;
            }
            match self.bidders[best].init(&mut rd) {
                Ok(filter) => self.chain.push(Stage::new(Imp::Filter(filter))),
                Err(e) => {
                    a.raise(e);
                    self.free_filters(a);
                    return ARCHIVE_FATAL;
                }
            }
        }
        a.raise(Error::fatal(
            ARCHIVE_ERRNO_FILE_FORMAT,
            "Input requires too many filters for decoding",
        ))
    }

    /// `bid_format`: the bid of format `index`, rewinding the stream if the
    /// bidder moved it.
    fn bid_format(&mut self, a: &Base, index: usize, best_bid: c_int) -> c_int {
        let Some(format) = self.formats.get_mut(index) else {
            return ARCHIVE_FATAL;
        };
        let mut rd = Reader {
            chain: &mut self.chain,
            budget: &self.budget,
            metadata: false,
            a,
            passphrases: &mut self.passphrases,
            entry: None,
        };
        rd.metadata = true;
        // An error from a bidder, say a failed read, is fatal.
        let Ok(bid) = format.bid(&mut rd, best_bid).map_err(|e| a.raise(e)) else {
            return ARCHIVE_FATAL;
        };
        if bid == ARCHIVE_FATAL || (rd.position() != 0 && rd.seek(0, Whence::Set).is_err()) {
            return ARCHIVE_FATAL;
        }
        bid
    }

    /// `choose_format`: lets each registered format bid on whether it wants
    /// to handle the stream. Returns the winner's index, with an error
    /// recorded if there is none.
    fn choose_format(&mut self, a: &Base) -> Option<usize> {
        let mut best_bid = -1;
        let mut best_slot = None;
        // Set up the active format for convenience of bidders.
        for i in 0..self.formats.len() {
            self.format = Some(i);
            let bid = self.bid_format(a, i, best_bid);
            if bid == ARCHIVE_FATAL {
                return None;
            }
            if bid > best_bid || best_slot.is_none() {
                best_bid = bid;
                best_slot = Some(i);
            }
        }

        // There were no bidders; this is a serious programmer error.
        let Some(slot) = best_slot else {
            a.raise(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "No formats registered",
            ));
            return None;
        };
        // There were bidders, but no non-zero bids; this means we can't
        // support this stream.
        if best_bid < 1 {
            a.raise(Error::fatal(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Unrecognized archive format",
            ));
            return None;
        }
        Some(slot)
    }

    /// `archive_read_open1`, after the caller has checked the handle and
    /// built `client`: opens the client, builds the filter chain, picks the
    /// format.
    pub fn open(&mut self, a: &Base, client: Box<dyn Client>) -> c_int {
        a.clear_error();
        a.state.set(state::OPEN);

        self.budget.reset();
        // Open data source.
        if let Err(e) = self.open_client(a, client) {
            a.state.set(state::FATAL);
            // The opener's literal status is returned even for ARCHIVE_WARN.
            // Its error is already recorded by the callback.
            return if e.recorded { e.code } else { a.raise(e) };
        }
        if !self.bypass_filter_bidding {
            // Build out the input pipeline.
            if self.choose_filters(a) < ARCHIVE_WARN {
                a.state.set(state::FATAL);
                if let Err(e) = self.budget.check() {
                    a.raise(e);
                }
                return ARCHIVE_FATAL;
            }
        }

        match self.format {
            None => match self.choose_format(a) {
                Some(slot) => self.format = Some(slot),
                None => {
                    self.close_filters(a);
                    a.state.set(state::FATAL);
                    if let Err(e) = self.budget.check() {
                        a.raise(e);
                    }
                    return ARCHIVE_FATAL;
                }
            },
            Some(index) => {
                if self.bid_format(a, index, -1) < 0 {
                    a.raise(Error::fatal(
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        "Registered format does not match",
                    ));
                    self.close_filters(a);
                    a.state.set(state::FATAL);
                    if let Err(e) = self.budget.check() {
                        a.raise(e);
                    }
                    return ARCHIVE_FATAL;
                }
            }
        }

        if let Err(e) = self.budget.check() {
            a.state.set(state::FATAL);
            return a.raise(e);
        }
        a.state.set(state::HEADER);

        // Ensure libarchive starts from the first node in a multivolume set.
        if let Some(stage) = self.chain.first_mut()
            && let Imp::Client(c) = &mut stage.imp
            && c.cursor != 0
        {
            if let Err(e) = c.switch_to(a, 0) {
                a.raise(e);
            }
            stage.client_total = 0;
            stage.client_avail = 0;
        }
        ARCHIVE_OK
    }

    /// The tail of `archive_read_set_format`, once the format for the code is
    /// registered: makes the format named `name` the active one. A warning if
    /// there already was one.
    pub fn select_format(&mut self, a: &Base, name: &str) -> c_int {
        let warn = self.format.is_some();
        let Some(index) = self.formats.iter().position(|f| f.name() == name) else {
            return a.raise(Error::fatal(
                ARCHIVE_ERRNO_PROGRAMMER,
                "Internal error: Unable to set format",
            ));
        };
        self.format = Some(index);
        if warn { ARCHIVE_WARN } else { ARCHIVE_OK }
    }
}

/// Copies `data`, which starts at entry offset `blk_off`, into `dest` after
/// the `written` bytes already there, padding the gap since the last output
/// (`out_off`) with zeros: callers of `archive_read_data` can be completely
/// ignorant of sparse files. Returns how many bytes of `data` it used.
fn copy_out(
    dest: &mut [u8],
    written: &mut usize,
    out_off: &mut i64,
    blk_off: &mut i64,
    data: &[u8],
    budget: &Budget,
) -> Result<usize, Error> {
    let total = dest.len();
    // Compute the amount of zero padding needed.
    let space = i64::try_from(total - *written).unwrap_or(i64::MAX);
    let gap = if out_off.saturating_add(space) < *blk_off {
        total - *written
    } else if *out_off < *blk_off {
        usize::try_from(*blk_off - *out_off).unwrap_or(0)
    } else {
        0
    };
    budget.decoded(gap)?;
    if let Some(zeros) = dest.get_mut(*written..*written + gap) {
        zeros.fill(0);
    }
    *written += gap;
    *out_off = out_off.saturating_add(i64::try_from(gap).unwrap_or(0));

    // Copy data if there is any space left.
    let n = data.len().min(total - *written);
    if let Some(out) = dest.get_mut(*written..*written + n) {
        out.copy_from_slice(&data[..n]);
    }
    *written += n;
    let n64 = i64::try_from(n).unwrap_or(0);
    *out_off = out_off.saturating_add(n64);
    *blk_off = blk_off.saturating_add(n64);
    Ok(n)
}

impl Read {
    /// Consumes what the format promised with `consume_later`, before the
    /// core calls into it.
    fn flush(&mut self, a: &Base) -> Result<(), Error> {
        Reader {
            chain: &mut self.chain,
            budget: &self.budget,
            metadata: false,
            a,
            passphrases: &mut self.passphrases,
            entry: None,
        }
        .flush()
    }

    /// Records `e` and gives its code; a fatal one makes the handle fatal.
    fn fail(a: &Base, e: Error) -> c_int {
        let code = a.raise(e);
        if code == ARCHIVE_FATAL {
            a.state.set(state::FATAL);
        }
        code
    }

    /// The active format and a `Reader` over the chain, as separate borrows.
    fn active<'a>(
        &'a mut self,
        a: &'a Base,
        entry: Option<&'a mut Entry>,
    ) -> Option<(&'a mut dyn Format, Reader<'a>)> {
        let format = self.formats.get_mut(self.format?)?;
        let rd = Reader {
            chain: &mut self.chain,
            budget: &self.budget,
            metadata: false,
            a,
            passphrases: &mut self.passphrases,
            entry,
        };
        Some((format.as_mut(), rd))
    }

    /// `_archive_read_data_block`, after the caller has checked the state:
    /// gets the next block of the entry's data and gives it to `f`, which
    /// must copy what it needs (or hand out a pointer that stays valid until
    /// the next read). `Err` is the status to return, already recorded.
    pub fn read_data_block<R>(
        &mut self,
        a: &Base,
        entry: Option<&mut Entry>,
        f: impl FnOnce(Data<'_>) -> R,
    ) -> Result<R, c_int> {
        if let Err(e) = self.flush(a) {
            return Err(Self::fail(a, e));
        }
        let Some((format, mut rd)) = self.active(a, entry) else {
            a.state.set(state::FATAL);
            return Err(a.raise(Error::fatal(
                ARCHIVE_ERRNO_PROGRAMMER,
                "Internal error: No format->read_data function registered",
            )));
        };
        let budget = rd.budget;
        match format.read_data(&mut rd) {
            Ok(data) => match budget.check() {
                Ok(()) => Ok(f(data)),
                Err(e) => Err(Self::fail(a, e)),
            },
            Err(e) => Err(Self::fail(a, budget.check().err().unwrap_or(e))),
        }
    }

    /// `archive_read_data_skip`, after the caller has checked the state:
    /// skips over all remaining data in this entry.
    pub fn read_data_skip(&mut self, a: &Base, entry: Option<&mut Entry>) -> c_int {
        let r = self.flush(a).and_then(|()| match self.active(a, entry) {
            Some((format, mut rd)) => format.read_data_skip(&mut rd),
            None => Ok(Status::Ok),
        });
        let r = self.budget.check().and(r);
        let code = match r {
            Ok(Status::Warn) => ARCHIVE_WARN,
            Ok(_) => ARCHIVE_OK,
            Err(e) => a.raise(e),
        };
        if code == ARCHIVE_FATAL {
            a.state.set(state::FATAL);
        } else {
            a.state.set(state::HEADER);
        }
        code
    }

    /// `archive_seek_data`, after the caller has checked the state.
    pub fn seek_data(
        &mut self,
        a: &Base,
        entry: Option<&mut Entry>,
        offset: i64,
        whence: c_int,
    ) -> i64 {
        if let Err(e) = self.flush(a) {
            return Self::fail(a, e).into();
        }
        let Some((format, mut rd)) = self.active(a, entry) else {
            return a
                .raise(Error::fatal(
                    ARCHIVE_ERRNO_PROGRAMMER,
                    "Internal error: no format",
                ))
                .into();
        };
        let result = format.seek_data(&mut rd, offset, whence);
        if a.read_data_reset.take() {
            self.reset_read_data(a);
        }
        match result {
            Ok(r) => r,
            Err(e) => Self::fail(a, e).into(),
        }
    }

    /// `__archive_reset_read_data`: forgets the state of `read_data`, for a
    /// new entry.
    fn reset_read_data(&mut self, a: &Base) {
        self.read_data = ReadData::default();
        a.read_data_requested.set(None);
    }

    /// `archive_read_data`, after the caller has checked the state: a
    /// `read(2)`-style read of the entry's data, with holes filled with
    /// zeros. Returns the byte count, or a negative status. Don't mix this
    /// with `read_data_block` on one entry.
    pub fn read_data(&mut self, a: &Base, mut entry: Option<&mut Entry>, dest: &mut [u8]) -> isize {
        let mut st = std::mem::take(&mut self.read_data);
        let mut written = 0;
        let result = 'read: loop {
            if written == dest.len() {
                // Upstream's `while (s > 0)` leaves the flags alone when it
                // doesn't run.
                if !dest.is_empty() {
                    a.read_data_requested.set(None);
                }
                break written as isize;
            }
            if st.offset == st.output_offset && st.pos == st.pending.len() {
                let (mut out_off, mut blk_off) = (st.output_offset, st.offset);
                a.read_data_requested.set(Some(dest.len() - written));
                let mut leftover = Vec::new();
                let mut out_of_order = false;
                let mut copy_error = None;
                let budget = Rc::clone(&self.budget);
                let mut eof = false;
                let mut warned = false;
                let got = self.read_data_block(a, entry.as_deref_mut(), |d| match d {
                    Data::Eof { offset } => {
                        blk_off = offset;
                        eof = true;
                    }
                    Data::Warn { .. } => warned = true,
                    Data::Block { data, offset } => {
                        blk_off = offset;
                        if blk_off < out_off {
                            out_of_order = true;
                            return;
                        }
                        match copy_out(
                            dest,
                            &mut written,
                            &mut out_off,
                            &mut blk_off,
                            data,
                            &budget,
                        ) {
                            Ok(n) => {
                                let rest = data.get(n..).unwrap_or_default();
                                if leftover.try_reserve_exact(rest.len()).is_err() {
                                    copy_error = Some(Error::fatal(
                                        libc::ENOMEM,
                                        "No memory for archive data",
                                    ));
                                } else {
                                    leftover.extend_from_slice(rest);
                                }
                            }
                            Err(e) => copy_error = Some(e),
                        }
                    }
                });
                if let Some(e) = copy_error {
                    break Self::fail(a, e) as isize;
                }
                if let Err(code) = got {
                    break 'read code as isize;
                }
                if warned {
                    break 'read ARCHIVE_WARN as isize;
                }
                (st.output_offset, st.offset, st.pending, st.pos) = (out_off, blk_off, leftover, 0);
                if eof && blk_off == out_off {
                    break 'read written as isize;
                }
                if out_of_order || blk_off < out_off {
                    break 'read a.raise(Error::new(
                        ARCHIVE_RETRY,
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        "Encountered out-of-order sparse blocks",
                    )) as isize;
                }
                continue;
            }
            if st.offset < st.output_offset {
                break a.raise(Error::new(
                    ARCHIVE_RETRY,
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    "Encountered out-of-order sparse blocks",
                )) as isize;
            }
            let n = copy_out(
                dest,
                &mut written,
                &mut st.output_offset,
                &mut st.offset,
                st.pending.get(st.pos..).unwrap_or_default(),
                &self.budget,
            );
            match n {
                Ok(n) => st.pos += n,
                Err(e) => break Self::fail(a, e) as isize,
            }
        };
        self.read_data = st;
        result
    }

    /// The handle's entry, as `archive_read_next_header` returns it.
    pub fn entry(&self) -> *mut Entry {
        self.entry
    }

    /// Gives up the entry, for `archive_free` to free. NULL afterwards.
    pub fn take_entry(&mut self) -> *mut Entry {
        std::mem::replace(&mut self.entry, std::ptr::null_mut())
    }

    /// The device and inode of the input, which extraction must not
    /// overwrite.
    pub fn skip_file(&self) -> Option<(i64, i64)> {
        self.skip_file.or_else(|| match &self.chain.first()?.imp {
            Imp::Client(c) => c.client.skip_file(),
            Imp::Filter(_) => None,
        })
    }

    /// `archive_read_header_position`.
    pub fn header_position(&self) -> i64 {
        self.header_position
    }

    /// `archive_read_format_capabilities`.
    pub fn format_capabilities(&self) -> c_int {
        self.format
            .and_then(|i| self.formats.get(i))
            .map_or(0, |f| f.capabilities())
    }

    /// `archive_read_has_encrypted_entries`.
    pub fn has_encrypted_entries(&self) -> c_int {
        if self.format_capabilities() & CAPS_ENCRYPT == 0 {
            // Format in general doesn't support encryption.
            return ENCRYPTION_UNSUPPORTED;
        }
        // A reader potentially has read enough data now.
        self.format
            .and_then(|i| self.formats.get(i))
            .map_or(ENCRYPTION_DONT_KNOW, |f| f.has_encrypted_entries())
    }

    /// `_archive_read_next_header2`, after the caller has checked the state.
    pub fn next_header2(&mut self, a: &Base, entry: &mut Entry) -> c_int {
        let mut r1 = ARCHIVE_OK;
        entry.clear();
        a.clear_error();

        // If client didn't consume entire data, skip any remainder (This is
        // especially important for GNU incremental directories.) A header
        // that failed to parse (DATA_RECOVERY) still needs the same
        // treatment: whatever of its body the format reader left unconsumed
        // must be skipped before we can read the next header.
        if matches!(a.state.get(), state::DATA | state::DATA_RECOVERY) {
            r1 = self.read_data_skip(a, Some(&mut *entry));
            if r1 == ARCHIVE_EOF {
                a.set_error(libc::EIO, Some(b"Premature end-of-file"));
            }
            if r1 == ARCHIVE_EOF || r1 == ARCHIVE_FATAL {
                a.state.set(state::FATAL);
                return ARCHIVE_FATAL;
            }
        }

        // Whatever the format's last read_data left to consume comes first,
        // so that the header starts where the data ended.
        let flushed = self.flush(a);

        // Record start-of-header offset in uncompressed stream.
        self.header_position = self.chain.last().map_or(0, |s| s.position);

        let Some(file_count) = a.file_count.get().checked_add(1) else {
            return Self::fail(
                a,
                Error::fatal(libc::EOVERFLOW, "Archive entry count overflow"),
            );
        };
        a.file_count.set(file_count);
        let mut r2 = match flushed.map(|()| self.active(a, None)) {
            Ok(Some((format, mut rd))) => {
                rd.metadata = true;
                match format.read_header(&mut rd, entry) {
                    Ok(status) => status.code(),
                    Err(e) => a.raise(e),
                }
            }
            Ok(None) => ARCHIVE_FATAL,
            Err(e) => a.raise(e),
        };

        if matches!(r2, ARCHIVE_OK | ARCHIVE_WARN)
            && let Err(e) = self.budget.entry()
        {
            r2 = a.raise(e);
        }
        if matches!(r2, ARCHIVE_OK | ARCHIVE_WARN) && self.budget.limits.metadata_bytes.is_some() {
            match entry.resource_metadata_size() {
                Some(size) => {
                    if let Err(e) = self.budget.metadata(size) {
                        r2 = a.raise(e);
                    }
                }
                None => {
                    r2 = a.raise(Error::fatal(
                        libc::EOVERFLOW,
                        "Archive metadata size overflow",
                    ))
                }
            }
        }
        if let Err(e) = self.budget.check() {
            r2 = a.raise(e);
        }

        // EOF and FATAL are persistent at this layer. By modifying the
        // state, we guarantee that future calls to read a header or read
        // data will fail.
        match r2 {
            ARCHIVE_EOF => {
                a.state.set(state::EOF);
                // Revert a file counter.
                a.file_count.set(a.file_count.get() - 1);
            }
            ARCHIVE_OK | ARCHIVE_WARN => a.state.set(state::DATA),
            ARCHIVE_FATAL => a.state.set(state::FATAL),
            // This entry's header could not be parsed, so its metadata
            // cannot be trusted. DATA_RECOVERY still permits skipping past
            // it (the format reader is responsible for ensuring that's
            // actually possible), but blocks archive_read_data() and
            // friends, which all check for DATA specifically.
            ARCHIVE_FAILED => a.state.set(state::DATA_RECOVERY),
            _ => {}
        }

        // The entry's size, if it is set, for archive_read_data_into_fd to
        // enforce.
        self.entry_bytes_declared = (matches!(r2, ARCHIVE_OK | ARCHIVE_WARN)
            && entry.size_is_set() != 0)
            .then(|| entry.size());
        self.reset_read_data(a);

        // EOF always wins; otherwise return the worst error.
        if r2 < r1 || r2 == ARCHIVE_EOF { r2 } else { r1 }
    }
}

/// The state of `archive_read_data` between calls: how far the output has
/// got, and the rest of the block it was copying from.
#[derive(Default)]
struct ReadData {
    /// Offset in the entry of the next byte `read_data` hands out.
    output_offset: i64,
    /// Offset in the entry of the first byte of `pending` not handed out.
    offset: i64,
    pending: Vec<u8>,
    /// How much of `pending` is handed out. A cursor rather than draining
    /// the front, which made small reads of a large block quadratic.
    pos: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell as Cell_;
    use std::rc::Rc;

    /// What the test client was asked to do, shared with the test.
    #[derive(Default)]
    struct Log {
        events: Vec<String>,
    }

    /// A client over in-memory nodes that hands out `block_size` bytes per
    /// read and logs the calls it gets.
    struct Mem {
        nodes: Vec<Vec<u8>>,
        pos: usize,
        block: Vec<u8>,
        block_size: usize,
        skippable: bool,
        seekable: bool,
        fail_read_at: Option<usize>,
        reads: usize,
        log: Rc<Cell_<Log>>,
    }

    impl Mem {
        fn new(data: &[u8], block_size: usize) -> (Self, Rc<Cell_<Log>>) {
            Self::multi(&[data], block_size)
        }

        fn multi(nodes: &[&[u8]], block_size: usize) -> (Self, Rc<Cell_<Log>>) {
            let log = Rc::new(Cell_::new(Log::default()));
            let mem = Mem {
                nodes: nodes.iter().map(|n| n.to_vec()).collect(),
                pos: 0,
                block: Vec::new(),
                block_size,
                skippable: false,
                seekable: false,
                fail_read_at: None,
                reads: 0,
                log: Rc::clone(&log),
            };
            (mem, log)
        }

        fn note(&self, what: String) {
            self.log.borrow_mut().events.push(what);
        }
    }

    impl Client for Mem {
        fn nodes(&self) -> usize {
            self.nodes.len()
        }

        fn open(&mut self, _a: &Base, node: usize) -> Result<(), Error> {
            self.pos = 0;
            self.note(format!("open {node}"));
            Ok(())
        }

        fn read(&mut self, _a: &Base, node: usize) -> Result<(), Error> {
            self.reads += 1;
            if self.fail_read_at == Some(self.reads) {
                self.block.clear();
                return Err(Error::fatal(libc::EIO, "Error reading test input"));
            }
            let data = &self.nodes[node];
            let end = data.len().min(self.pos + self.block_size);
            self.block = data[self.pos..end].to_vec();
            self.pos = end;
            Ok(())
        }

        fn block(&self) -> &[u8] {
            &self.block
        }

        fn can_skip(&self) -> bool {
            self.skippable
        }

        fn skip(&mut self, _a: &Base, node: usize, request: i64) -> Result<i64, Error> {
            let left = (self.nodes[node].len() - self.pos) as i64;
            // Round down to the block size, as upstream's memory client does.
            let n = request.min(left) / self.block_size as i64 * self.block_size as i64;
            self.pos += n as usize;
            self.note(format!("skip {request} -> {n}"));
            Ok(n)
        }

        fn can_seek(&self) -> bool {
            self.seekable
        }

        fn seek(
            &mut self,
            _a: &Base,
            node: usize,
            offset: i64,
            whence: Whence,
        ) -> Result<i64, Error> {
            let len = self.nodes[node].len() as i64;
            let to = match whence {
                Whence::Set => offset,
                Whence::Cur => self.pos as i64 + offset,
                Whence::End => len + offset,
            };
            if !(0..=len).contains(&to) {
                return Err(Error::recorded(ARCHIVE_FATAL));
            }
            self.pos = to as usize;
            self.note(format!("seek {node} {whence:?} {offset} -> {to}"));
            Ok(to)
        }

        fn close(&mut self, _a: &Base, node: usize) -> Result<Status, Error> {
            self.note(format!("close {node}"));
            Ok(Status::Ok)
        }
    }

    /// A pass-through filter with its own output blocks, to test chains.
    struct Upper {
        out: Vec<u8>,
        closed: Rc<Cell_<bool>>,
    }

    impl Filter for Upper {
        fn name(&self) -> &CStr {
            c"upper"
        }

        fn code(&self) -> c_int {
            99
        }

        fn read(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
            let n = {
                let data = up.peek_available(1)?;
                self.out.clear();
                self.out.extend(data.iter().map(u8::to_ascii_uppercase));
                data.len()
            };
            up.consume(n)
        }

        fn block(&self) -> &[u8] {
            &self.out
        }

        fn close(&mut self, _a: &Base) -> Result<Status, Error> {
            *self.closed.borrow_mut() = true;
            Ok(Status::Ok)
        }
    }

    fn setup(mem: Mem) -> (Read, Base) {
        let mut r = Read::default();
        let a = Base::new(READ_MAGIC);
        r.open_client(&a, Box::new(mem)).unwrap();
        (r, a)
    }

    fn text(n: usize) -> Vec<u8> {
        (0..n).map(|i| b'a' + (i % 26) as u8).collect()
    }

    fn error(a: &Base) -> String {
        a.error_string()
            .map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned())
    }

    #[test]
    fn read_ahead_returns_the_current_block_without_copying() {
        let data = text(10);
        let (mem, _) = Mem::new(&data, 4);
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        // "I just want some data": the whole block comes back.
        assert_eq!(rd.peek_available(1).unwrap(), &data[..4]);
        assert_eq!(rd.peek_available(0).unwrap(), &data[..4]);
        assert_eq!(rd.peek_available(4).unwrap(), &data[..4]);
        assert_eq!(rd.position(), 0);
        rd.consume(3).unwrap();
        assert_eq!(rd.position(), 3);
        assert_eq!(rd.peek_available(1).unwrap(), &data[3..4]);
    }

    /// A header field can ask for far more than the input holds (found by
    /// fuzzing rar): that is a short read, not an allocation of that size.
    #[test]
    fn read_ahead_of_an_absurd_size_is_a_short_read() {
        let data = text(10);
        let (mem, _) = Mem::new(&data, 4);
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        assert!(rd.read_ahead(0x7fff_ffff_0000_0000).unwrap().is_none());
    }

    #[test]
    fn read_ahead_across_blocks_copies_and_then_rolls_back() {
        let data = text(10);
        let (mem, _) = Mem::new(&data, 4);
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        // A request spanning blocks is served from the copy buffer, which
        // holds only what was needed.
        assert_eq!(rd.peek_available(6).unwrap(), &data[..6]);
        assert_eq!(rd.peek_available(1).unwrap(), &data[..6]);
        rd.consume(5).unwrap();
        // The rest of the second block is back to being served directly.
        assert_eq!(rd.peek_available(1).unwrap(), &data[5..8]);
        rd.consume(3).unwrap();
        assert_eq!(rd.peek_available(1).unwrap(), &data[8..10]);
        assert_eq!(rd.position(), 8);
    }

    #[test]
    fn the_copy_buffer_grows_to_fit_big_requests() {
        let data = text(1000);
        let (mem, _) = Mem::new(&data, 7);
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        for want in [1, 10, 11, 100, 101, 700, 1000] {
            assert_eq!(
                rd.peek_available(want).unwrap().get(..want),
                Some(&data[..want])
            );
        }
        // Data stays contiguous when the buffer has to move it forward.
        rd.consume(995).unwrap();
        assert_eq!(rd.peek_available(5).unwrap(), &data[995..]);
        rd.consume(5).unwrap();
        assert_eq!(rd.peek_available(1).unwrap(), b"");
    }

    #[test]
    fn short_data_is_end_of_file() {
        let data = text(6);
        let (mem, _) = Mem::new(&data, 4);
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        // Asking for more than there is returns what there is.
        assert_eq!(rd.peek_available(10).unwrap(), &data[..]);
        assert_eq!(rd.read_ahead(10).unwrap(), None);
        assert_eq!(rd.read_ahead(6).unwrap(), Some(&data[..]));
        // Everything buffered comes back, not just what was asked for.
        assert_eq!(rd.read_ahead(2).unwrap(), Some(&data[..]));
        assert_eq!(rd.read_ahead(0).unwrap(), Some(&data[..]));
        rd.consume(6).unwrap();
        assert_eq!(rd.peek_available(1).unwrap(), b"");
        assert_eq!(rd.peek_available(0).unwrap(), b"");
        assert_eq!(rd.peek_available(5).unwrap(), b"");
        // The end of input is None, except when nothing was asked for.
        assert_eq!(rd.read_ahead(1).unwrap(), None);
        assert_eq!(rd.read_ahead(0).unwrap(), Some(&b""[..]));
        assert!(error(&a).is_empty());
    }

    #[test]
    fn consume_past_the_end_is_fatal() {
        let data = text(6);
        let (mem, _) = Mem::new(&data, 4);
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        assert_eq!(rd.consume(0), Ok(()));
        assert_eq!(rd.consume(-1).unwrap_err().code, ARCHIVE_FATAL);
        assert_eq!(rd.consume(u64::MAX).unwrap_err().code, ARCHIVE_FATAL);
        assert_eq!(rd.consume(7).unwrap_err().code, ARCHIVE_FATAL);
        assert_eq!(
            error(&a),
            "Truncated input file (needed 7 bytes, only 6 available)"
        );
        assert_eq!(a.errno.get(), ARCHIVE_ERRNO_MISC);
        // The file pointer moved as far as it could.
        assert_eq!(rd.position(), 6);
    }

    #[test]
    fn skip_stops_quietly_at_the_end() {
        let data = text(20);
        let (mem, _) = Mem::new(&data, 4);
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        assert_eq!(rd.skip(5).unwrap(), 5);
        assert_eq!(rd.peek_available(1).unwrap(), &data[5..8]);
        assert_eq!(rd.skip(100).unwrap(), 15);
        assert_eq!((rd.position(), rd.skip(1).unwrap()), (20, 0));
        assert!(error(&a).is_empty());
    }

    #[test]
    fn client_skip_is_used_for_what_is_not_buffered() {
        let data = text(100);
        let (mut mem, log) = Mem::new(&data, 8);
        mem.skippable = true;
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        assert_eq!(rd.peek_available(1).unwrap(), &data[..8]);
        // 3 bytes left in the block... no: all 8 are buffered and used first,
        // then the skipper rounds down to blocks (82 -> 80) and a read
        // finishes the job.
        rd.consume(90).unwrap();
        assert_eq!(rd.position(), 90);
        assert_eq!(rd.peek_available(1).unwrap(), &data[90..96]);
        assert!(log.borrow().events.contains(&"skip 82 -> 80".to_string()));
    }

    #[test]
    fn a_skipper_that_skips_nothing_falls_back_to_reading() {
        let data = text(40);
        let (mut mem, log) = Mem::new(&data, 64);
        mem.skippable = true;
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        // Less than a block: the skipper returns 0 and reads take over.
        rd.consume(30).unwrap();
        assert_eq!(rd.peek_available(1).unwrap(), &data[30..]);
        assert!(log.borrow().events.iter().any(|e| e == "skip 30 -> 0"));
    }

    #[test]
    fn the_seeker_skips_big_requests_when_there_is_no_skipper() {
        let data = text(300_000);
        let (mut mem, log) = Mem::new(&data, 4096);
        mem.seekable = true;
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        rd.consume(100).unwrap();
        // Over 64k: a relative seek, not reads.
        rd.consume(200_000).unwrap();
        assert_eq!(rd.position(), 200_100);
        assert_eq!(rd.peek_available(1).unwrap().first(), Some(&data[200_100]));
        let seeks: Vec<_> = log
            .borrow()
            .events
            .iter()
            .filter(|e| e.starts_with("seek"))
            .cloned()
            .collect();
        assert_eq!(seeks.len(), 1);
        // Under 64k it reads instead.
        rd.consume(1000).unwrap();
        assert_eq!(rd.position(), 201_100);
        assert_eq!(
            log.borrow()
                .events
                .iter()
                .filter(|e| e.starts_with("seek"))
                .count(),
            1
        );
    }

    #[test]
    fn seek_discards_the_buffers_and_resets_the_position() {
        let data = text(100);
        let (mut mem, _) = Mem::new(&data, 8);
        mem.seekable = true;
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        assert!(rd.can_seek());
        assert_eq!(rd.peek_available(20).unwrap(), &data[..20]);
        rd.consume(5).unwrap();
        assert_eq!(rd.seek(50, Whence::Set).unwrap(), 50);
        assert_eq!(
            (rd.position(), rd.peek_available(1).unwrap()),
            (50, &data[50..58])
        );
        assert_eq!(rd.seek(-10, Whence::Cur).unwrap(), 40);
        assert_eq!(rd.peek_available(1).unwrap(), &data[40..48]);
        assert_eq!(rd.seek(-4, Whence::End).unwrap(), 96);
        assert_eq!(rd.peek_available(10).unwrap(), &data[96..]);
        // Seeking back out of the end of file works, too.
        rd.consume(4).unwrap();
        assert_eq!(rd.peek_available(1).unwrap(), b"");
        assert_eq!(rd.seek(0, Whence::Set).unwrap(), 0);
        assert_eq!(rd.peek_available(1).unwrap(), &data[..8]);
    }

    #[test]
    fn a_failed_seek_makes_the_stream_fatal() {
        let data = text(10);
        let (mut mem, _) = Mem::new(&data, 8);
        mem.seekable = true;
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        assert_eq!(rd.seek(11, Whence::Set).unwrap_err().code, ARCHIVE_FATAL);
        assert_eq!(rd.peek_available(1).unwrap_err().code, ARCHIVE_FATAL);
        assert_eq!(rd.seek(0, Whence::Set).unwrap_err().code, ARCHIVE_FATAL);
    }

    #[test]
    fn seek_without_a_seeker_fails_but_leaves_the_stream_usable() {
        let data = text(10);
        let (mem, _) = Mem::new(&data, 8);
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        assert!(!rd.can_seek());
        assert_eq!(rd.seek(0, Whence::Set).unwrap_err().code, ARCHIVE_FAILED);
        assert_eq!(rd.peek_available(1).unwrap(), &data[..8]);
    }

    #[test]
    fn a_read_error_is_recorded_and_sticks() {
        let data = text(100);
        let (mut mem, _) = Mem::new(&data, 8);
        mem.fail_read_at = Some(2);
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        assert_eq!(rd.peek_available(8).unwrap(), &data[..8]);
        rd.consume(8).unwrap();
        let e = rd.peek_available(1).unwrap_err();
        assert!(e.recorded && e.code == ARCHIVE_FATAL);
        assert_eq!(
            (error(&a), a.errno.get()),
            ("Error reading test input".into(), libc::EIO)
        );
        a.clear_error();
        // Once a stream has failed, so does everything after it.
        assert_eq!(rd.peek_available(1).unwrap_err().code, ARCHIVE_FATAL);
        assert_eq!(rd.skip(1).unwrap_err().code, ARCHIVE_FATAL);
        // A consume on a failed stream says it was truncated.
        assert!(rd.consume(1).is_err());
        assert_eq!(
            error(&a),
            "Truncated input file (needed 1 bytes, only 0 available)"
        );
    }

    #[test]
    fn a_filter_reads_from_the_stage_below_it() {
        let (mem, log) = Mem::new(b"hello, world", 5);
        let (mut r, a) = setup(mem);
        let closed = Rc::new(Cell_::new(false));
        r.chain.push(Stage::new(Imp::Filter(Box::new(Upper {
            out: Vec::new(),
            closed: Rc::clone(&closed),
        }))));
        assert_eq!(r.filter_count(), 2);
        assert_eq!(
            (
                r.filter_code(0),
                r.filter_name(0),
                r.filter_code(1),
                r.filter_code(-1)
            ),
            (99, Some(c"upper"), 0, 0)
        );
        assert_eq!(r.filter_name(2), None);
        assert_eq!(r.filter_code(-2), -1);
        {
            let mut rd = r.reader(&a);
            assert_eq!(rd.peek_available(7).unwrap(), b"HELLO, ");
            rd.consume(7).unwrap();
            assert_eq!(rd.peek_available(1).unwrap(), b"WOR");
            rd.consume(3).unwrap();
            assert_eq!(rd.peek_available(1).unwrap(), b"LD");
            rd.consume(2).unwrap();
            assert_eq!(rd.peek_available(1).unwrap(), b"");
        }
        // The client position is the compressed position.
        assert_eq!((r.filter_bytes(0), r.filter_bytes(-1)), (12, 12));
        assert_eq!(r.close_filters(&a), ARCHIVE_OK);
        assert!(*closed.borrow());
        let events = log.borrow().events.clone();
        assert_eq!(events.last().map(String::as_str), Some("close 0"));
        // Closing twice does nothing.
        assert_eq!(r.close_filters(&a), ARCHIVE_OK);
        assert_eq!(log.borrow().events.len(), events.len());
    }

    #[test]
    fn multi_volume_clients_read_straight_through() {
        let (mem, log) = Mem::multi(&[b"0123456", b"abcdefg", b"XYZ"], 4);
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        // Nodes are switched at the end of each; a request can span them.
        assert_eq!(rd.peek_available(17).unwrap(), b"0123456abcdefgXYZ");
        assert_eq!(rd.peek_available(18).unwrap(), b"0123456abcdefgXYZ");
        rd.consume(17).unwrap();
        assert_eq!(rd.peek_available(1).unwrap(), b"");
        // The default switch closes the old node and opens the new one.
        let events = log.borrow().events.clone();
        assert_eq!(
            events[..5],
            ["open 0", "close 0", "open 1", "close 1", "open 2"]
        );
    }

    #[test]
    fn seeking_a_multi_volume_client_finds_the_node() {
        let (mut mem, _) = Mem::multi(&[b"0123456", b"abcdefg", b"XYZ"], 4);
        mem.seekable = true;
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        assert_eq!(rd.seek(9, Whence::Set).unwrap(), 9);
        assert_eq!(rd.peek_available(1).unwrap(), b"cdef");
        assert_eq!(rd.seek(3, Whence::Set).unwrap(), 3);
        assert_eq!(rd.peek_available(1).unwrap(), b"3456");
        assert_eq!(rd.seek(-2, Whence::End).unwrap(), 15);
        assert_eq!(rd.peek_available(1).unwrap(), b"YZ");
        assert_eq!(rd.seek(1, Whence::Cur).unwrap(), 16);
        assert_eq!(rd.peek_available(1).unwrap(), b"Z");
        // Past the end is an error.
        assert_eq!(rd.seek(18, Whence::Set).unwrap_err().code, ARCHIVE_FATAL);
    }

    #[test]
    fn handle_lifecycle() {
        let h = new();
        assert_eq!((h.base.magic, h.base.state.get()), (READ_MAGIC, state::NEW));
        assert_eq!(
            (h.filter_count(), h.filter_code(0), h.filter_bytes(-1)),
            (0, -1, -1)
        );
        h.base.set_error(5, Some(b"stale"));
        assert_eq!(h.close(), ARCHIVE_OK);
        assert_eq!((h.base.state.get(), h.base.errno.get()), (state::CLOSED, 0));
        h.base.set_error(6, Some(b"after close"));
        assert_eq!(h.close(), ARCHIVE_OK);
        assert_eq!(h.base.errno.get(), 6);
        let f = new();
        f.base.state.set(state::FATAL);
        assert_eq!(f.close(), ARCHIVE_OK);
        assert_eq!(f.base.state.get(), state::CLOSED);
        assert_eq!(new().free(), ARCHIVE_OK);
        let w = new();
        assert_eq!(w.write_data_block(b"x", 0), ARCHIVE_FATAL as isize);
        assert_eq!(w.base.state.get(), state::FATAL);
    }

    #[test]
    fn an_empty_chain_is_empty_input() {
        let mut r = Read::default();
        let a = Base::new(READ_MAGIC);
        let mut rd = r.reader(&a);
        assert_eq!(rd.peek_available(4).unwrap(), b"");
        assert_eq!(rd.skip(3).unwrap(), 0);
        assert!(rd.consume(1).is_err());
        assert_eq!(rd.seek(0, Whence::Set).unwrap_err().code, ARCHIVE_FATAL);
        assert_eq!((rd.position(), rd.can_seek()), (0, false));
        assert_eq!(
            (r.filter_count(), r.filter_bytes(-1), r.filter_name(0)),
            (0, -1, None)
        );
    }

    #[test]
    fn failed_open_closes_every_node() {
        struct Failing(Rc<Cell_<Vec<String>>>);
        impl Client for Failing {
            fn nodes(&self) -> usize {
                2
            }
            fn open(&mut self, _a: &Base, _: usize) -> Result<(), Error> {
                Err(Error::fatal(libc::ENOENT, "nope"))
            }
            fn read(&mut self, _a: &Base, _: usize) -> Result<(), Error> {
                Ok(())
            }
            fn block(&self) -> &[u8] {
                &[]
            }
            fn close(&mut self, _a: &Base, node: usize) -> Result<Status, Error> {
                self.0.borrow_mut().push(format!("close {node}"));
                Ok(Status::Ok)
            }
        }
        let closed = Rc::new(Cell_::new(Vec::new()));
        let mut r = Read::default();
        let e = r
            .open_client(
                &Base::new(READ_MAGIC),
                Box::new(Failing(Rc::clone(&closed))),
            )
            .unwrap_err();
        assert_eq!(
            (e.code, e.errno, e.msg.as_slice()),
            (ARCHIVE_FATAL, libc::ENOENT, b"nope".as_slice())
        );
        assert_eq!(*closed.borrow(), ["close 0", "close 1"]);
        assert_eq!(r.filter_count(), 0);
    }

    /// A format whose bid is fixed, and that peeks `peek` bytes (consuming
    /// them if `eat`) when asked.
    struct Fake<const N: usize> {
        bid: c_int,
        peek: usize,
        eat: bool,
        bids: Rc<Cell_<Vec<(usize, c_int)>>>,
    }

    impl<const N: usize> Format for Fake<N> {
        fn name(&self) -> &'static str {
            ["zero", "one", "two", "three"][N % 4]
        }

        fn bid(&mut self, r: &mut Reader<'_>, best_bid: c_int) -> Result<c_int, Error> {
            self.bids.borrow_mut().push((N, best_bid));
            if self.peek > 0 {
                r.peek_available(self.peek)?;
            }
            if self.eat {
                r.consume(self.peek)?;
            }
            Ok(self.bid)
        }

        fn read_header(&mut self, _: &mut Reader<'_>, _: &mut Entry) -> Result<Status, Error> {
            Ok(Status::Eof)
        }

        fn read_data<'x>(&'x mut self, _: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
            Ok(Data::Eof { offset: 0 })
        }
    }

    fn fake<const N: usize>(bid: c_int, log: &Rc<Cell_<Vec<(usize, c_int)>>>) -> Box<Fake<N>> {
        Box::new(Fake::<N> {
            bid,
            peek: 0,
            eat: false,
            bids: Rc::clone(log),
        })
    }

    /// Bids `bid` if the stream starts with a lowercase letter, then
    /// upper-cases it.
    struct UpperBidder(c_int);

    impl FilterBidder for UpperBidder {
        fn bid(&mut self, up: &mut Reader<'_>) -> Result<c_int, Error> {
            let lowercase = up
                .peek_available(1)?
                .first()
                .is_some_and(u8::is_ascii_lowercase);
            Ok(if lowercase { self.0 } else { 0 })
        }

        fn init(&mut self, _up: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
            Ok(Box::new(Upper {
                out: Vec::new(),
                closed: Rc::default(),
            }))
        }
    }

    fn open_with(r: &mut Read, a: &Base, data: &[u8]) -> c_int {
        let (mem, _) = Mem::new(data, 4);
        r.open(a, Box::new(mem))
    }

    #[test]
    fn the_highest_bid_wins_and_the_first_wins_ties() {
        let log = Rc::default();
        let mut r = Read::default();
        assert_eq!(r.register_format(fake::<0>(0, &log)).unwrap(), Status::Ok);
        assert_eq!(r.register_format(fake::<1>(5, &log)).unwrap(), Status::Ok);
        assert_eq!(r.register_format(fake::<2>(5, &log)).unwrap(), Status::Ok);
        assert_eq!(r.register_format(fake::<3>(3, &log)).unwrap(), Status::Ok);
        let a = Base::new(READ_MAGIC);
        assert_eq!(open_with(&mut r, &a, b"data"), ARCHIVE_OK);
        assert_eq!(r.format, Some(1));
        assert_eq!(a.state.get(), state::HEADER);
        // Each bidder is told the best bid so far, starting from -1.
        assert_eq!(*log.borrow(), [(0, -1), (1, 0), (2, 5), (3, 5)]);
    }

    #[test]
    fn a_stream_nobody_bids_on_is_unrecognized() {
        let log = Rc::default();
        let mut r = Read::default();
        let a = Base::new(READ_MAGIC);
        assert_eq!(open_with(&mut r, &a, b"data"), ARCHIVE_FATAL);
        assert_eq!(error(&a), "No formats registered");
        assert_eq!(
            (a.errno.get(), a.state.get()),
            (ARCHIVE_ERRNO_FILE_FORMAT, state::FATAL)
        );

        let mut r = Read::default();
        assert_eq!(r.register_format(fake::<0>(0, &log)).unwrap(), Status::Ok);
        let a = Base::new(READ_MAGIC);
        assert_eq!(open_with(&mut r, &a, b"data"), ARCHIVE_FATAL);
        assert_eq!(error(&a), "Unrecognized archive format");
        assert_eq!(a.state.get(), state::FATAL);
    }

    #[test]
    fn a_fatal_bid_aborts_the_open() {
        let log = Rc::default();
        let mut r = Read::default();
        assert_eq!(
            r.register_format(fake::<0>(ARCHIVE_FATAL, &log)).unwrap(),
            Status::Ok
        );
        assert_eq!(r.register_format(fake::<1>(9, &log)).unwrap(), Status::Ok);
        let a = Base::new(READ_MAGIC);
        assert_eq!(open_with(&mut r, &a, b"data"), ARCHIVE_FATAL);
        assert_eq!(log.borrow().len(), 1);
    }

    #[test]
    fn bidders_that_consume_rewind_a_seekable_stream() {
        let log = Rc::default();
        let mut r = Read::default();
        let mut f = fake::<0>(7, &log);
        (f.peek, f.eat) = (3, true);
        assert_eq!(r.register_format(f).unwrap(), Status::Ok);
        let a = Base::new(READ_MAGIC);
        let (mut mem, _) = Mem::new(b"abcdefgh", 4);
        mem.seekable = true;
        assert_eq!(r.open(&a, Box::new(mem)), ARCHIVE_OK);
        assert_eq!(r.reader(&a).position(), 0);
        assert_eq!(r.reader(&a).peek_available(1).unwrap(), b"abcd");

        // Without a seeker, that is fatal.
        let mut r = Read::default();
        let mut f = fake::<0>(7, &log);
        (f.peek, f.eat) = (3, true);
        assert_eq!(r.register_format(f).unwrap(), Status::Ok);
        let a = Base::new(READ_MAGIC);
        assert_eq!(open_with(&mut r, &a, b"abcdefgh"), ARCHIVE_FATAL);
    }

    #[test]
    fn duplicate_and_excess_registrations() {
        let log = Rc::default();
        let mut r = Read::default();
        assert_eq!(r.register_format(fake::<0>(1, &log)).unwrap(), Status::Ok);
        assert_eq!(r.register_format(fake::<0>(1, &log)).unwrap(), Status::Warn);
        assert_eq!(r.formats.len(), 1);
        for _ in 0..16 {
            assert_eq!(
                r.register_bidder(Box::new(UpperBidder(1))).unwrap(),
                Status::Ok
            );
        }
        let e = r.register_bidder(Box::new(UpperBidder(1))).unwrap_err();
        assert_eq!((e.code, e.errno), (ARCHIVE_FATAL, libc::ENOMEM));
        assert_eq!(e.msg, b"Not enough slots for filter registration");
    }

    #[test]
    fn the_best_bidding_filter_is_stacked_until_nobody_bids() {
        let mut r = Read::default();
        assert_eq!(
            r.register_bidder(Box::new(UpperBidder(1))).unwrap(),
            Status::Ok
        );
        assert_eq!(
            r.register_bidder(Box::new(UpperBidder(3))).unwrap(),
            Status::Ok
        );
        assert_eq!(
            r.register_format(fake::<0>(1, &Rc::default())).unwrap(),
            Status::Ok
        );
        let a = Base::new(READ_MAGIC);
        assert_eq!(open_with(&mut r, &a, b"abc"), ARCHIVE_OK);
        // One filter: after upper-casing nobody bids.
        assert_eq!((r.filter_count(), r.filter_code(0)), (2, 99));
        assert_eq!(r.reader(&a).peek_available(3).unwrap(), b"ABC");
    }

    #[test]
    fn too_many_filters_is_fatal() {
        struct Always;
        impl FilterBidder for Always {
            fn bid(&mut self, _: &mut Reader<'_>) -> Result<c_int, Error> {
                Ok(1)
            }
            fn init(&mut self, _: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
                Ok(Box::new(Upper {
                    out: Vec::new(),
                    closed: Rc::default(),
                }))
            }
        }
        let mut r = Read::default();
        assert_eq!(r.register_bidder(Box::new(Always)).unwrap(), Status::Ok);
        assert_eq!(
            r.register_format(fake::<0>(1, &Rc::default())).unwrap(),
            Status::Ok
        );
        let a = Base::new(READ_MAGIC);
        assert_eq!(open_with(&mut r, &a, b"abc"), ARCHIVE_FATAL);
        assert_eq!(error(&a), "Input requires too many filters for decoding");
    }

    #[test]
    fn appended_filters_skip_bidding_and_sit_on_the_client() {
        let mut r = Read::default();
        assert_eq!(
            r.register_bidder(Box::new(UpperBidder(1))).unwrap(),
            Status::Ok
        );
        let a = Base::new(READ_MAGIC);
        assert_eq!(r.append_last_bidder(&a), ARCHIVE_OK);
        assert_eq!(
            r.register_format(fake::<0>(1, &Rc::default())).unwrap(),
            Status::Ok
        );
        assert_eq!(open_with(&mut r, &a, b"xyz"), ARCHIVE_OK);
        assert_eq!(
            (r.filter_count(), r.filter_code(0), r.filter_code(1)),
            (2, 99, 0)
        );
        assert_eq!(r.reader(&a).peek_available(3).unwrap(), b"XYZ");
        // Appending with no bidder is a programmer error.
        let mut none = Read::default();
        assert_eq!(none.append_last_bidder(&a), ARCHIVE_FATAL);
    }

    #[test]
    fn set_format_names_an_active_format_and_open_checks_it() {
        let log = Rc::default();
        let mut r = Read::default();
        let a = Base::new(READ_MAGIC);
        assert_eq!(r.register_format(fake::<1>(0, &log)).unwrap(), Status::Ok);
        assert_eq!(r.register_format(fake::<2>(9, &log)).unwrap(), Status::Ok);
        assert_eq!(r.select_format(&a, "nope"), ARCHIVE_FATAL);
        assert_eq!(error(&a), "Internal error: Unable to set format");
        assert_eq!(r.select_format(&a, "one"), ARCHIVE_OK);
        assert_eq!(r.select_format(&a, "two"), ARCHIVE_WARN);
        // The chosen format is not bid against others, only checked.
        assert_eq!(open_with(&mut r, &a, b"data"), ARCHIVE_OK);
        assert_eq!(r.format, Some(1));
        assert_eq!(*log.borrow(), [(2, -1)]);

        let mut r = Read::default();
        assert_eq!(r.register_format(fake::<1>(-1, &log)).unwrap(), Status::Ok);
        r.select_format(&a, "one");
        assert_eq!(open_with(&mut r, &a, b"data"), ARCHIVE_FATAL);
        assert_eq!(error(&a), "Registered format does not match");
    }

    /// A format that serves scripted data blocks and header statuses.
    struct Script {
        blocks: Vec<(i64, Vec<u8>)>,
        end: i64,
        next: usize,
        headers: Vec<c_int>,
        caps: c_int,
    }

    impl Script {
        fn new(blocks: &[(i64, &[u8])], end: i64) -> Self {
            Script {
                blocks: blocks.iter().map(|(o, d)| (*o, d.to_vec())).collect(),
                end,
                next: 0,
                headers: Vec::new(),
                caps: 0,
            }
        }
    }

    impl Format for Script {
        fn name(&self) -> &'static str {
            "script"
        }

        fn bid(&mut self, _: &mut Reader<'_>, _: c_int) -> Result<c_int, Error> {
            Ok(1)
        }

        fn read_header(&mut self, r: &mut Reader<'_>, _: &mut Entry) -> Result<Status, Error> {
            match self.headers.pop().unwrap_or(ARCHIVE_EOF) {
                ARCHIVE_OK => Ok(Status::Ok),
                ARCHIVE_WARN => Ok(r.warn(0, "odd")),
                ARCHIVE_EOF => Ok(Status::Eof),
                code => Err(Error::new(code, 0, "bad header")),
            }
        }

        fn read_data<'x>(&'x mut self, _: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
            let block = self.blocks.get(self.next);
            self.next += 1;
            Ok(match block {
                Some((offset, data)) => Data::Block {
                    data,
                    offset: *offset,
                },
                None => Data::Eof { offset: self.end },
            })
        }

        fn capabilities(&self) -> c_int {
            self.caps
        }
    }

    fn opened(script: Script) -> (Read, Base) {
        let mut r = Read::default();
        assert_eq!(r.register_format(Box::new(script)).unwrap(), Status::Ok);
        let a = Base::new(READ_MAGIC);
        assert_eq!(open_with(&mut r, &a, b"x"), ARCHIVE_OK);
        a.state.set(state::DATA);
        (r, a)
    }

    #[test]
    fn read_data_copies_blocks_and_fills_holes_with_zeros() {
        let (mut r, a) = opened(Script::new(&[(0, b"abc"), (5, b"de")], 9));
        let mut buf = [b'#'; 4];
        // Small destination: blocks are split across calls.
        assert_eq!(r.read_data(&a, None, &mut buf), 4);
        assert_eq!(&buf, b"abc\0");
        assert_eq!(r.read_data(&a, None, &mut buf), 4);
        assert_eq!(&buf, b"\0de\0");
        let mut big = [b'#'; 10];
        // The trailing hole up to the end offset is zeros, then EOF.
        assert_eq!(r.read_data(&a, None, &mut big), 1);
        assert_eq!(big[0], 0);
        assert_eq!(r.read_data(&a, None, &mut big), 0);
        assert_eq!(r.read_data(&a, None, &mut []), 0);
    }

    #[test]
    fn read_data_rejects_out_of_order_blocks() {
        let (mut r, a) = opened(Script::new(&[(0, b"abcd"), (2, b"xx")], 6));
        let mut buf = [0; 16];
        assert_eq!(r.read_data(&a, None, &mut buf), ARCHIVE_RETRY as isize);
        assert_eq!(error(&a), "Encountered out-of-order sparse blocks");
    }

    #[test]
    fn read_data_block_hands_out_the_formats_blocks() {
        let (mut r, a) = opened(Script::new(&[(7, b"hi")], 9));
        let first = r.read_data_block(&a, None, |d| match d {
            Data::Block { data, offset } => Some((data.to_vec(), offset)),
            Data::Eof { .. } | Data::Warn { .. } => None,
        });
        assert_eq!(first, Ok(Some((b"hi".to_vec(), 7))));
        assert!(matches!(
            r.read_data_block(&a, None, |d| matches!(d, Data::Eof { offset: 9 })),
            Ok(true)
        ));
    }

    #[test]
    fn data_skip_discards_the_rest_and_ends_in_the_header_state() {
        let (mut r, a) = opened(Script::new(&[(0, b"a"), (1, b"b")], 2));
        assert_eq!(r.read_data_skip(&a, None), ARCHIVE_OK);
        assert_eq!(a.state.get(), state::HEADER);
        assert_eq!(r.format, Some(0));
        // The default skip read everything.
        assert_eq!(r.format.map(|i| r.formats[i].name()), Some("script"));
    }

    #[test]
    fn seek_data_is_refused_by_default() {
        let (mut r, a) = opened(Script::new(&[], 0));
        assert_eq!(
            r.seek_data(&a, None, 0, libc::SEEK_SET),
            i64::from(ARCHIVE_FAILED)
        );
        assert_eq!(error(&a), "Cannot seek data with this format");
        assert_eq!(a.errno.get(), ARCHIVE_ERRNO_MISC);
    }

    #[test]
    fn next_header_moves_through_the_states() {
        let mut script = Script::new(&[], 0);
        // Popped from the back: OK, WARN, FAILED, then EOF.
        script.headers = vec![ARCHIVE_EOF, ARCHIVE_FAILED, ARCHIVE_WARN, ARCHIVE_OK];
        let mut r = Read::default();
        assert_eq!(r.register_format(Box::new(script)).unwrap(), Status::Ok);
        let a = Base::new(READ_MAGIC);
        assert_eq!(open_with(&mut r, &a, b"abcdef"), ARCHIVE_OK);
        let mut e = Entry::new(None);
        assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_OK);
        assert_eq!((a.state.get(), a.file_count.get()), (state::DATA, 1));
        // The remaining data of the entry is skipped first.
        assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_WARN);
        assert_eq!((a.state.get(), error(&a)), (state::DATA, "odd".to_string()));
        assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_FAILED);
        assert_eq!(a.state.get(), state::DATA_RECOVERY);
        assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_EOF);
        assert_eq!((a.state.get(), a.file_count.get()), (state::EOF, 3));
    }

    #[test]
    fn header_position_is_where_the_header_started() {
        let mut script = Script::new(&[], 0);
        script.headers = vec![ARCHIVE_OK, ARCHIVE_OK];
        let mut r = Read::default();
        assert_eq!(r.register_format(Box::new(script)).unwrap(), Status::Ok);
        let a = Base::new(READ_MAGIC);
        assert_eq!(open_with(&mut r, &a, b"abcdef"), ARCHIVE_OK);
        r.reader(&a).consume(2).unwrap();
        r.next_header2(&a, &mut Entry::new(None));
        assert_eq!(r.header_position(), 2);
    }

    #[test]
    fn encryption_queries_follow_the_formats_capabilities() {
        let mut r = Read::default();
        assert_eq!(r.format_capabilities(), 0);
        assert_eq!(r.has_encrypted_entries(), ENCRYPTION_UNSUPPORTED);
        let mut s = Script::new(&[], 0);
        s.caps = 1;
        assert_eq!(r.register_format(Box::new(s)).unwrap(), Status::Ok);
        r.format = Some(0);
        assert_eq!(r.format_capabilities(), 1);
        assert_eq!(r.has_encrypted_entries(), ENCRYPTION_DONT_KNOW);
    }

    #[test]
    fn a_bid_that_fails_aborts_the_open_with_its_error() {
        struct Failing;
        impl FilterBidder for Failing {
            fn bid(&mut self, _: &mut Reader<'_>) -> Result<c_int, Error> {
                Err(Error::fatal(libc::EIO, "bidder failed"))
            }
            fn init(&mut self, _: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
                Err(Error::fatal(libc::EIO, "never"))
            }
        }
        let mut r = Read::default();
        assert_eq!(r.register_bidder(Box::new(Failing)).unwrap(), Status::Ok);
        assert_eq!(
            r.register_format(fake::<0>(1, &Rc::default())).unwrap(),
            Status::Ok
        );
        let a = Base::new(READ_MAGIC);
        assert_eq!(open_with(&mut r, &a, b"abc"), ARCHIVE_FATAL);
        assert_eq!(
            (error(&a), a.state.get()),
            ("bidder failed".into(), state::FATAL)
        );
    }

    /// A format whose data ends in a warning.
    struct WarnsAtTheEnd(bool);

    impl Format for WarnsAtTheEnd {
        fn name(&self) -> &'static str {
            "warns"
        }

        fn bid(&mut self, _: &mut Reader<'_>, _: c_int) -> Result<c_int, Error> {
            Ok(1)
        }

        fn read_header(&mut self, r: &mut Reader<'_>, _: &mut Entry) -> Result<Status, Error> {
            // Record the warning first, then go on: nothing is skipped.
            let warned = r.warn(libc::EILSEQ, "header oddity");
            r.set_format(7, c"warns");
            Ok(warned)
        }

        fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
            if std::mem::replace(&mut self.0, true) {
                return Ok(Data::Eof { offset: 0 });
            }
            // `Data::Warn` is what carries the warning back.
            let _ = r.warn(libc::EILSEQ, "bad checksum");
            Ok(Data::Warn { offset: 0 })
        }
    }

    #[test]
    fn warnings_continue_and_are_not_errors() {
        let mut r = Read::default();
        assert_eq!(
            r.register_format(Box::new(WarnsAtTheEnd(false))).unwrap(),
            Status::Ok
        );
        let a = Base::new(READ_MAGIC);
        assert_eq!(open_with(&mut r, &a, b"x"), ARCHIVE_OK);
        let mut e = Entry::new(None);
        assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_WARN);
        // The entry is usable: the state is DATA and the format got set.
        assert_eq!((a.state.get(), a.format.get()), (state::DATA, 7));
        assert_eq!(error(&a), "header oddity");
        // The data's warning is a status, with no block.
        let got = r.read_data_block(&a, None, |d| matches!(d, Data::Warn { .. }));
        assert_eq!(got, Ok(true));
        assert_eq!(error(&a), "bad checksum");
        // A skip stops at a warning and reports it, but the handle is fine.
        let (mut r, a) = {
            let mut r = Read::default();
            assert_eq!(
                r.register_format(Box::new(WarnsAtTheEnd(false))).unwrap(),
                Status::Ok
            );
            let a = Base::new(READ_MAGIC);
            open_with(&mut r, &a, b"x");
            (r, a)
        };
        a.state.set(state::DATA);
        assert_eq!(r.read_data_skip(&a, None), ARCHIVE_WARN);
        assert_eq!(a.state.get(), state::HEADER);
        // read_data hands the status on, as upstream's archive_read_data does.
        let (mut r, a) = {
            let mut r = Read::default();
            assert_eq!(
                r.register_format(Box::new(WarnsAtTheEnd(false))).unwrap(),
                Status::Ok
            );
            let a = Base::new(READ_MAGIC);
            open_with(&mut r, &a, b"x");
            (r, a)
        };
        a.state.set(state::DATA);
        assert_eq!(r.read_data(&a, None, &mut [0; 4]), ARCHIVE_WARN as isize);
    }

    #[test]
    fn the_handle_is_usable_while_a_read_ahead_slice_is_held() {
        let (mem, _) = Mem::new(b"hello", 5);
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        // This is the pattern formats use: take the handle (and the
        // position) first, then keep the slice while recording things.
        let base = rd.base();
        let position = rd.position();
        let data = rd.read_ahead(5).unwrap().unwrap();
        base.set_format(5, c"five");
        assert_eq!(base.warn(libc::EILSEQ, "noted"), Status::Warn);
        assert_eq!((data, position), (&b"hello"[..], 0));
        assert_eq!((a.format.get(), error(&a)), (5, "noted".to_string()));
    }

    /// An `ar` member: name, mtime, mode and data, padded to even length.
    fn ar_member(name: &str, mtime: u64, data: &[u8]) -> Vec<u8> {
        let mut m = format!(
            "{name:<16}{mtime:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            0,
            0,
            "100644",
            data.len()
        )
        .into_bytes();
        m.extend_from_slice(data);
        if data.len() % 2 == 1 {
            m.push(b'\n');
        }
        m
    }

    fn ar_archive(members: &[Vec<u8>]) -> Vec<u8> {
        let mut a = b"!<arch>\n".to_vec();
        for m in members {
            a.extend_from_slice(m);
        }
        a
    }

    fn ar_open(bytes: &[u8], read_size: usize) -> (Read, Base) {
        let mut r = Read::default();
        assert_eq!(
            r.register_format(Box::new(ar_example::Ar::default()))
                .unwrap(),
            Status::Ok
        );
        let a = Base::new(READ_MAGIC);
        let mem = crate::read_open_memory::Memory::new(bytes.to_vec(), read_size);
        assert_eq!(r.open(&a, Box::new(mem)), ARCHIVE_OK);
        (r, a)
    }

    fn ar_data(r: &mut Read, a: &Base) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let more = r.read_data_block(a, None, |d| match d {
                Data::Block { data, .. } => {
                    out.extend_from_slice(data);
                    true
                }
                _ => false,
            });
            if more != Ok(true) {
                return out;
            }
        }
    }

    #[test]
    fn the_ar_example_reads_members_in_place() {
        let bytes = ar_archive(&[
            ar_member("hello.txt/", 1000, b"hello"),
            ar_member("b/", 2000, b"abcdefghijklmnop"),
            ar_member("c/", 3000, b"xy"),
        ]);
        // Small blocks make the data span several read_ahead calls.
        for read_size in [3, 7, 1000] {
            let (mut r, a) = ar_open(&bytes, read_size);
            let mut e = Entry::new(None);
            assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_OK);
            assert_eq!((e.size(), a.format.get()), (5, 0x70000));
            assert_eq!(
                e.pathname().map(|p| p.to_bytes().to_vec()),
                Some(b"hello.txt".to_vec())
            );
            assert_eq!(e.mtime(), 1000);
            assert_eq!(ar_data(&mut r, &a), b"hello");
            // The padding byte and unread data are skipped.
            assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_OK);
            assert_eq!(ar_data(&mut r, &a), b"abcdefghijklmnop");
            assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_OK);
            assert_eq!(r.read_data_skip(&a, None), ARCHIVE_OK);
            assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_EOF);
            assert_eq!(r.header_position(), bytes.len() as i64);
        }
    }

    #[test]
    fn the_ar_example_reports_broken_input() {
        let good = ar_archive(&[ar_member("a/", 1, b"data")]);
        // Truncated in the middle of a header.
        let (mut r, a) = ar_open(&good[..good.len() - 30], 16);
        let mut e = Entry::new(None);
        assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_FATAL);
        assert_eq!(error(&a), "Truncated ar archive");
        // Truncated in the middle of the data.
        let (mut r, a) = ar_open(&good[..good.len() - 2], 16);
        assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_OK);
        // Like upstream's archive_read_data, the error wins over the 2 bytes.
        assert_eq!(r.read_data(&a, None, &mut [0; 8]), ARCHIVE_FATAL as isize);
        assert_eq!(error(&a), "Truncated ar archive");
        // A bad signature.
        let mut bad = good.clone();
        bad[8 + 58] = b'x';
        let (mut r, a) = ar_open(&bad, 16);
        assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_FATAL);
        assert_eq!(error(&a), "Incorrect file header signature");
        // A warning keeps the entry.
        let nameless = ar_archive(&[ar_member("", 1, b"data")]);
        let (mut r, a) = ar_open(&nameless, 16);
        assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_WARN);
        assert_eq!(
            (a.state.get(), error(&a)),
            (state::DATA, "ar member without a name".into())
        );
        assert_eq!(ar_data(&mut r, &a), b"data");
    }

    /// Collects the blocks of the current entry: (offset, bytes), and the
    /// stream position seen from outside after each one.
    fn blocks(r: &mut Read, a: &Base) -> (Vec<(i64, Vec<u8>)>, Vec<i64>) {
        let (mut blocks, mut positions) = (Vec::new(), Vec::new());
        while let Ok(Some(block)) = r.read_data_block(a, None, |d| match d {
            Data::Block { data, offset } => Some((offset, data.to_vec())),
            _ => None,
        }) {
            blocks.push(block);
            positions.push(r.filter_bytes(0));
        }
        (blocks, positions)
    }

    #[test]
    fn raw_reads_many_blocks_and_consumes_each_on_the_next_call() {
        let data = text(1000);
        let mut r = Read::default();
        assert_eq!(
            crate::read::format::raw::support(&mut r).unwrap(),
            Status::Ok
        );
        let a = Base::new(READ_MAGIC);
        let (mem, _) = Mem::new(&data, 7);
        assert_eq!(r.open(&a, Box::new(mem)), ARCHIVE_OK);
        let mut e = Entry::new(None);
        assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_OK);

        let (blocks, positions) = blocks(&mut r, &a);
        // The data comes back in place, one client block at a time.
        assert!(blocks.len() > 100);
        let mut expect = 0;
        for (i, (offset, bytes)) in blocks.iter().enumerate() {
            assert_eq!(*offset, expect as i64);
            assert_eq!(bytes[..], data[expect..expect + bytes.len()]);
            // A block is not consumed until the next call: the position
            // lags by one block, as it does in upstream.
            assert_eq!(positions[i], expect as i64);
            expect += bytes.len();
        }
        assert_eq!(expect, data.len());
        // The call that found the end consumed the last block.
        assert_eq!(r.filter_bytes(0), data.len() as i64);
        // So did the one that skips, for a reader that stopped early.
        let (mem, _) = Mem::new(&data, 7);
        let mut r2 = Read::default();
        assert_eq!(
            crate::read::format::raw::support(&mut r2).unwrap(),
            Status::Ok
        );
        assert_eq!(r2.open(&a, Box::new(mem)), ARCHIVE_OK);
        assert_eq!(r2.next_header2(&a, &mut e), ARCHIVE_OK);
        assert!(r2.read_data_block(&a, None, |_| ()).is_ok());
        assert_eq!(r2.filter_bytes(0), 0);
        assert_eq!(r2.read_data_skip(&a, None), ARCHIVE_OK);
        assert_eq!(r2.filter_bytes(0), 7);
        assert_eq!(r2.next_header2(&a, &mut e), ARCHIVE_EOF);
        assert_eq!(r2.header_position(), 7);
    }

    /// Promises to consume more than there is, to make the flush fail.
    struct Over;

    impl Format for Over {
        fn name(&self) -> &'static str {
            "over"
        }

        fn bid(&mut self, _: &mut Reader<'_>, _: c_int) -> Result<c_int, Error> {
            Ok(1)
        }

        fn read_header(&mut self, _: &mut Reader<'_>, _: &mut Entry) -> Result<Status, Error> {
            Ok(Status::Ok)
        }

        fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
            let later = r.consume_later();
            let data = r.peek_available(1)?;
            later.consume(100);
            Ok(Data::Block { data, offset: 0 })
        }
    }

    fn over() -> (Read, Base, Entry) {
        let mut r = Read::default();
        assert_eq!(r.register_format(Box::new(Over)).unwrap(), Status::Ok);
        let a = Base::new(READ_MAGIC);
        assert_eq!(open_with(&mut r, &a, b"12345"), ARCHIVE_OK);
        let mut e = Entry::new(None);
        assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_OK);
        (r, a, e)
    }

    #[test]
    fn a_failed_deferred_consume_fails_like_an_explicit_one() {
        let truncated = "Truncated input file (needed 100 bytes, only 5 available)";
        // The next read_data.
        let (mut r, a, _) = over();
        assert_eq!(
            r.read_data_block(
                &a,
                None,
                |d| matches!(d, Data::Block { data, .. } if data == b"1234")
            ),
            Ok(true)
        );
        assert_eq!(r.read_data_block(&a, None, |_| ()), Err(ARCHIVE_FATAL));
        assert_eq!(
            (a.state.get(), error(&a)),
            (state::FATAL, truncated.to_string())
        );

        // The skip that the next header does.
        let (mut r, a, mut e) = over();
        assert!(r.read_data_block(&a, None, |_| ()).is_ok());
        assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_FATAL);
        assert_eq!(
            (a.state.get(), error(&a)),
            (state::FATAL, truncated.to_string())
        );

        // An explicit read_data_skip.
        let (mut r, a, _) = over();
        assert!(r.read_data_block(&a, None, |_| ()).is_ok());
        assert_eq!(r.read_data_skip(&a, None), ARCHIVE_FATAL);
        assert_eq!(error(&a), truncated);

        // The reader's own calls report it as consume does.
        let (mut r, a, _) = over();
        assert!(r.read_data_block(&a, None, |_| ()).is_ok());
        let mut rd = r.reader(&a);
        assert_eq!(
            rd.read_ahead(1).unwrap_err(),
            Error::recorded(ARCHIVE_FATAL)
        );
        assert_eq!(error(&a), truncated);
    }

    #[test]
    fn helpers_read_fixed_amounts() {
        let (mem, _) = Mem::new(b"0123456789", 3);
        let (mut r, a) = setup(mem);
        let mut rd = r.reader(&a);
        assert_eq!(rd.read_exact_vec(4).unwrap(), Some(b"0123".to_vec()));
        assert_eq!(rd.position(), 4);
        // Too little: nothing is consumed.
        assert_eq!(rd.read_exact_vec(7).unwrap(), None);
        assert_eq!(rd.position(), 4);
        assert!(rd.read_ahead(2).unwrap().is_some());
        rd.consume_ahead(2).unwrap();
        assert_eq!(rd.peek_available(1).unwrap().first(), Some(&b'6'));
    }
}
