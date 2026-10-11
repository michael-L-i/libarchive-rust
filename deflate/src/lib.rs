/* deflate.c -- compress data using the deflation algorithm
 * Copyright (C) 1995-2022 Jean-loup Gailly and Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h
 */

// Altered from the original: translated to Rust from zlib 1.2.12's deflate.c
// and deflate.h, keeping what libarchive's writers use. Not ported: the gzip
// wrapper, the filtered, Huffman-only, RLE and fixed strategies,
// deflateSetDictionary(), deflateParams() and the other tuning calls.

//  ALGORITHM
//
//      The "deflation" process depends on being able to identify portions
//      of the input text which are identical to earlier input (within a
//      sliding window trailing behind the input currently being processed).
//
//      The most straightforward technique turns out to be the fastest for
//      most input files: try all possible matches and select the longest.
//      The key feature of this algorithm is that insertions into the string
//      dictionary are very simple and thus fast, and deletions are avoided
//      completely. Insertions are performed at each input character, whereas
//      string matches are performed only when the previous match ends. So it
//      is preferable to spend more time in matches to allow very fast string
//      insertions and avoid deletions. The matching algorithm for small
//      strings is inspired from that of Rabin & Karp. A brute force approach
//      is used to find longer strings when a small match has been found.
//      A similar algorithm is used in comic (by Jan-Mark Wams) and freeze
//      (by Leonid Broukhis).
//
//  ACKNOWLEDGEMENTS
//
//      The idea of lazy evaluation of matches is due to Jan-Mark Wams, and
//      I found it in 'freeze' written by Leonid Broukhis.
//      Thanks to many people for bug reports and testing.

//! zlib 1.2.12's deflate compressor in safe Rust. For the same parameters and
//! the same sequence of calls it produces the same bytes as zlib: levels 0-9,
//! raw or zlib-wrapped streams, window bits 9-15, memory levels 1-9, the
//! default strategy and every flush mode.

#![forbid(unsafe_code)]

mod trees;

use adler2::Adler32;
use std::cmp::min;
use trees::{Pending, Trees};

const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
/// Minimum amount of lookahead, except at the end of the input file.
const MIN_LOOKAHEAD: usize = MAX_MATCH + MIN_MATCH + 1;
/// Matches of length 3 are discarded if their distance exceeds TOO_FAR.
const TOO_FAR: usize = 4096;
/// Maximum stored block length in deflate format (not including header).
const MAX_STORED: usize = 65535;

/// The flush parameter of zlib's deflate().
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flush {
    None,
    Partial,
    Sync,
    Full,
    Finish,
    Block,
}

impl Flush {
    /// Rank Z_BLOCK between Z_NO_FLUSH and Z_PARTIAL_FLUSH.
    fn rank(self) -> u8 {
        match self {
            Flush::None => 0,
            Flush::Block => 1,
            Flush::Partial => 2,
            Flush::Sync => 4,
            Flush::Full => 6,
            Flush::Finish => 8,
        }
    }
}

/// A successful deflate() result: Z_OK or Z_STREAM_END.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    StreamEnd,
}

/// A failed deflate() call, which consumed and produced nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Z_STREAM_ERROR: input after a finish that has not been completed.
    Stream,
    /// Z_BUF_ERROR: no progress was possible.
    Buf,
}

impl Error {
    /// zlib's return code.
    pub fn code(self) -> i32 {
        match self {
            Error::Stream => -2,
            Error::Buf => -5,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum BlockState {
    /// block not completed, need more input or more output
    NeedMore,
    /// block flush performed
    BlockDone,
    /// finish started, need only more output at next deflate
    FinishStarted,
    /// finish done, accept no more input or output
    FinishDone,
}

#[derive(Clone, Copy, PartialEq)]
enum Func {
    Stored,
    Fast,
    Slow,
}

struct Config {
    /// reduce lazy search above this match length
    good_length: usize,
    /// do not perform lazy search above this match length
    max_lazy: usize,
    /// quit search above this match length
    nice_length: usize,
    max_chain: usize,
    func: Func,
}

const fn config(good: usize, lazy: usize, nice: usize, chain: usize, func: Func) -> Config {
    Config {
        good_length: good,
        max_lazy: lazy,
        nice_length: nice,
        max_chain: chain,
        func,
    }
}

/// Values for max_lazy_match, good_match and max_chain_length, depending on
/// the desired pack level (0..9). The values given below have been tuned to
/// exclude worst case performance for pathological files. Better values may be
/// found for specific files.
/// Note: the deflate() code requires max_lazy >= MIN_MATCH and max_chain >= 4.
/// For deflate_fast() (levels <= 3) good is ignored and lazy has a different
/// meaning.
const CONFIGURATION_TABLE: [Config; 10] = [
    //     good lazy nice chain
    config(0, 0, 0, 0, Func::Stored),       // store only
    config(4, 4, 8, 4, Func::Fast),         // max speed, no lazy matches
    config(4, 5, 16, 8, Func::Fast),        //
    config(4, 6, 32, 32, Func::Fast),       //
    config(4, 4, 16, 16, Func::Slow),       // lazy matches
    config(8, 16, 32, 32, Func::Slow),      //
    config(8, 16, 128, 128, Func::Slow),    //
    config(8, 32, 128, 256, Func::Slow),    //
    config(32, 128, 258, 1024, Func::Slow), //
    config(32, 258, 258, 4096, Func::Slow), // max compression
];

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    /// zlib header -> Busy
    Init,
    /// deflate -> Finish
    Busy,
    /// stream complete
    Finish,
}

/// One deflate() call's view of z_stream: the input and output buffers and
/// how far into them it got.
struct Strm<'a> {
    input: &'a [u8],
    next_in: usize,
    output: &'a mut [u8],
    next_out: usize,
}

impl<'a> Strm<'a> {
    fn avail_in(&self) -> usize {
        self.input.len() - self.next_in
    }

    fn avail_out(&self) -> usize {
        self.output.len() - self.next_out
    }

    fn write(&mut self, data: &[u8]) {
        self.output[self.next_out..self.next_out + data.len()].copy_from_slice(data);
        self.next_out += data.len();
    }
}

/// A deflate stream (deflateInit2() through deflateEnd()).
pub struct Deflate(Box<State>);

impl Deflate {
    /// deflateInit2() with method Z_DEFLATED and strategy Z_DEFAULT_STRATEGY:
    /// level -1 (Z_DEFAULT_COMPRESSION) or 0-9, window_bits 8-15 for a zlib
    /// stream or -9 to -15 for raw deflate, and mem_level 1-9. Returns None for
    /// other parameters.
    pub fn new(level: i32, window_bits: i32, mem_level: i32) -> Option<Self> {
        let level = if level == -1 { 6 } else { level };
        let (wrap, w_bits) = match window_bits {
            -15..=-9 => (0, -window_bits),
            // until 256-byte window bug fixed
            8 => (1, 9),
            9..=15 => (1, window_bits),
            _ => return None,
        };
        if !(1..=9).contains(&mem_level) || !(0..=9).contains(&level) {
            return None;
        }
        let w_size = 1 << w_bits;
        let hash_bits = mem_level as u32 + 7;
        let lit_bufsize = 1 << (mem_level + 6); // 16K elements by default
        let mut s = Box::new(State {
            status: Phase::Init,
            pending: Pending::default(),
            pending_buf_size: lit_bufsize * 4,
            wrap,
            last_flush: None,
            w_size,
            w_bits: w_bits as usize,
            w_mask: w_size - 1,
            window: vec![0; 2 * w_size],
            window_size: 2 * w_size,
            prev: vec![0; w_size],
            head: vec![0; 1 << hash_bits],
            ins_h: 0,
            hash_mask: (1 << hash_bits) - 1,
            hash_shift: hash_bits.div_ceil(MIN_MATCH as u32),
            block_start: 0,
            match_length: 0,
            prev_match: 0,
            match_available: false,
            strstart: 0,
            match_start: 0,
            lookahead: 0,
            prev_length: 0,
            max_chain_length: 0,
            max_lazy_match: 0,
            level: level as usize,
            good_match: 0,
            nice_match: 0,
            trees: Trees::default(),
            // We avoid equality with lit_bufsize*3 because of wraparound at
            // 64K on 16 bit machines and because stored blocks are restricted
            // to 64K-1 bytes.
            sym_buf: vec![0; (lit_bufsize - 1) * 3],
            sym_next: 0,
            insert: 0,
            adler: Adler32::new(),
        });
        s.reset();
        Some(Self(s))
    }

    /// deflateReset(): start a new stream with the same parameters.
    pub fn reset(&mut self) {
        self.0.reset();
    }

    /// deflate(): compress from `input` into `output` as far as `flush`
    /// allows. Returns the status and the numbers of input bytes consumed and
    /// output bytes produced.
    pub fn deflate(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        flush: Flush,
    ) -> Result<(Status, usize, usize), Error> {
        let mut strm = Strm {
            input,
            next_in: 0,
            output,
            next_out: 0,
        };
        let status = self.0.deflate(&mut strm, flush)?;
        Ok((status, strm.next_in, strm.next_out))
    }
}

struct State {
    /// as the name implies
    status: Phase,
    pending: Pending,
    /// size of pending_buf
    pending_buf_size: usize,
    /// 1 for a zlib stream, 0 for raw deflate; negated once the trailer is
    /// written.
    wrap: i32,
    /// value of flush param for previous deflate call, None for zlib's -1 and
    /// -2
    last_flush: Option<Flush>,

    /// LZ77 window size (32K by default)
    w_size: usize,
    /// log2(w_size)  (8..16)
    w_bits: usize,
    /// w_size - 1
    w_mask: usize,

    /// Sliding window. Input bytes are read into the second half of the
    /// window, and move to the first half later to keep a dictionary of at
    /// least wSize bytes. With this organization, matches are limited to a
    /// distance of wSize-MAX_MATCH bytes, but this ensures that IO is always
    /// performed with a length multiple of the block size.
    window: Vec<u8>,
    /// Actual size of window: 2*wSize, except when the user input buffer is
    /// directly used as sliding window.
    window_size: usize,
    /// Link to older string with same hash index. To limit the size of this
    /// array to 64K, this link is maintained only for the last 32K strings.
    /// An index in this array is thus a window index modulo 32K.
    prev: Vec<u16>,
    /// Heads of the hash chains or NIL.
    head: Vec<u16>,

    /// hash index of string to be inserted
    ins_h: usize,
    /// hash_size-1
    hash_mask: usize,
    /// Number of bits by which ins_h must be shifted at each input step. It
    /// must be such that after MIN_MATCH steps, the oldest byte no longer
    /// takes part in the hash key, that is: hash_shift * MIN_MATCH >=
    /// hash_bits
    hash_shift: u32,

    /// Window position at the beginning of the current output block. Gets
    /// negative when the window is moved backwards.
    block_start: isize,

    /// length of best match
    match_length: usize,
    /// previous match
    prev_match: usize,
    /// set if previous match exists
    match_available: bool,
    /// start of string to insert
    strstart: usize,
    /// start of matching string
    match_start: usize,
    /// number of valid bytes ahead in window
    lookahead: usize,

    /// Length of the best match at previous step. Matches not greater than
    /// this are discarded. This is used in the lazy match evaluation.
    prev_length: usize,
    /// To speed up deflation, hash chains are never searched beyond this
    /// length. A higher limit improves compression ratio but degrades the
    /// speed.
    max_chain_length: usize,
    /// Attempt to find a better match only when the current match is strictly
    /// smaller than this value. This mechanism is used only for compression
    /// levels >= 4. For levels <= 3 it is max_insert_length: insert new
    /// strings in the hash table only if the match length is not greater than
    /// this length.
    max_lazy_match: usize,
    /// compression level (1..9)
    level: usize,
    /// Use a faster search when the previous match is longer than this
    good_match: usize,
    /// Stop searching when current match exceeds this
    nice_match: usize,

    trees: Trees,
    /// buffer for distances and literals/lengths; full when sym_next reaches
    /// its length
    sym_buf: Vec<u8>,
    /// running index in sym_buf
    sym_next: usize,
    /// bytes at end of window left to insert
    insert: usize,
    adler: Adler32,
}

impl State {
    /// deflateResetKeep() and lm_init().
    fn reset(&mut self) {
        self.pending.buf.clear();
        self.pending.out = 0;
        self.wrap = self.wrap.abs(); // was made negative by deflate(..., Z_FINISH);
        self.status = Phase::Init;
        self.adler = Adler32::new();
        self.last_flush = None;
        self.tr_init();

        // Initialize the "longest match" routines for a new zlib stream
        self.head.fill(0);
        let c = &CONFIGURATION_TABLE[self.level];
        self.max_lazy_match = c.max_lazy;
        self.good_match = c.good_length;
        self.nice_match = c.nice_length;
        self.max_chain_length = c.max_chain;
        self.strstart = 0;
        self.block_start = 0;
        self.lookahead = 0;
        self.insert = 0;
        self.match_length = MIN_MATCH - 1;
        self.prev_length = MIN_MATCH - 1;
        self.match_available = false;
        self.ins_h = 0;
    }

    /// In order to simplify the code, particularly on 16 bit machines, match
    /// distances are limited to MAX_DIST instead of WSIZE.
    fn max_dist(&self) -> usize {
        self.w_size - MIN_LOOKAHEAD
    }

    /// Update a hash value with the given input byte
    /// IN  assertion: all calls to UPDATE_HASH are made with consecutive input
    ///    characters, so that a running hash key can be computed from the
    ///    previous key instead of complete recalculation each time.
    fn update_hash(&mut self, c: u8) {
        self.ins_h = ((self.ins_h << self.hash_shift) ^ usize::from(c)) & self.hash_mask;
    }

    /// Insert string str in the dictionary and return the previous head of the
    /// hash chain (the most recent string with same hash key).
    /// IN  assertion: all calls to INSERT_STRING are made with consecutive
    ///    input characters and the first MIN_MATCH bytes of str are valid
    ///    (except for the last MIN_MATCH-1 bytes of the input file).
    fn insert_string(&mut self, str: usize) -> usize {
        self.update_hash(self.window[str + (MIN_MATCH - 1)]);
        let head = self.head[self.ins_h];
        self.prev[str & self.w_mask] = head;
        self.head[self.ins_h] = str as u16;
        usize::from(head)
    }

    /// Slide the hash table when sliding the window down (could be avoided
    /// with 32 bit values at the expense of memory usage).
    fn slide_hash(&mut self) {
        let wsize = self.w_size as u16;
        for p in self.head.iter_mut().chain(self.prev.iter_mut()) {
            // If p is not on any hash chain, prev[p] is garbage but its value
            // will never be used.
            *p = p.saturating_sub(wsize);
        }
    }

    /// Flush as much pending output as possible. All deflate() output, except
    /// for some deflate_stored() output, goes through this function.
    fn flush_pending(&mut self, strm: &mut Strm) {
        let p = &mut self.pending;
        p.bi_flush();
        let len = min(p.buf.len() - p.out, strm.avail_out());
        if len == 0 {
            return;
        }
        strm.write(&p.buf[p.out..p.out + len]);
        p.out += len;
        if p.out == p.buf.len() {
            p.buf.clear();
            p.out = 0;
        }
    }

    fn deflate(&mut self, strm: &mut Strm, flush: Flush) -> Result<Status, Error> {
        if self.status == Phase::Finish && flush != Flush::Finish {
            return Err(Error::Stream);
        }
        if strm.avail_out() == 0 {
            return Err(Error::Buf);
        }
        let old_flush = self.last_flush;
        self.last_flush = Some(flush);

        // Flush as much pending output as possible
        if self.pending.buf.len() != self.pending.out {
            self.flush_pending(strm);
            if strm.avail_out() == 0 {
                // Since avail_out is 0, deflate will be called again with more
                // output space, but possibly with both pending and avail_in
                // equal to zero. There won't be anything to do, but this is
                // not an error situation so make sure we return OK instead of
                // BUF_ERROR at next call of deflate:
                self.last_flush = None;
                return Ok(Status::Ok);
            }
        // Make sure there is something to do and avoid duplicate consecutive
        // flushes. For repeated and useless calls with Z_FINISH, we keep
        // returning Z_STREAM_END instead of Z_BUF_ERROR.
        } else if strm.avail_in() == 0
            && old_flush.is_some_and(|old| flush.rank() <= old.rank())
            && flush != Flush::Finish
        {
            return Err(Error::Buf);
        }

        // User must not provide more input after the first FINISH:
        if self.status == Phase::Finish && strm.avail_in() != 0 {
            return Err(Error::Buf);
        }

        // Write the header
        if self.status == Phase::Init && self.wrap == 0 {
            self.status = Phase::Busy;
        }
        if self.status == Phase::Init {
            // zlib header
            let mut header = (8 + ((self.w_bits - 8) << 4)) << 8;
            let level_flags = match self.level {
                0 | 1 => 0,
                2..=5 => 1,
                6 => 2,
                _ => 3,
            };
            header |= level_flags << 6;
            header += 31 - (header % 31);
            self.pending
                .buf
                .extend_from_slice(&(header as u16).to_be_bytes());
            self.adler = Adler32::new();
            self.status = Phase::Busy;

            // Compression must start with an empty pending buffer
            self.flush_pending(strm);
            if self.pending.buf.len() != self.pending.out {
                self.last_flush = None;
                return Ok(Status::Ok);
            }
        }

        // Start a new block or continue the current one.
        if strm.avail_in() != 0
            || self.lookahead != 0
            || (flush != Flush::None && self.status != Phase::Finish)
        {
            let bstate = match CONFIGURATION_TABLE[self.level].func {
                Func::Stored => self.deflate_stored(strm, flush),
                Func::Fast => self.deflate_fast(strm, flush),
                Func::Slow => self.deflate_slow(strm, flush),
            };
            if matches!(bstate, BlockState::FinishStarted | BlockState::FinishDone) {
                self.status = Phase::Finish;
            }
            if matches!(bstate, BlockState::NeedMore | BlockState::FinishStarted) {
                if strm.avail_out() == 0 {
                    self.last_flush = None; // avoid BUF_ERROR next call, see above
                }
                return Ok(Status::Ok);
                // If flush != Z_NO_FLUSH && avail_out == 0, the next call of
                // deflate should use the same flush parameter to make sure
                // that the flush is complete. So we don't have to output an
                // empty block here, this will be done at next call. This also
                // ensures that for a very small output buffer, we emit at most
                // one empty block.
            }
            if bstate == BlockState::BlockDone {
                if flush == Flush::Partial {
                    self.tr_align();
                } else if flush != Flush::Block {
                    // FULL_FLUSH or SYNC_FLUSH
                    self.tr_stored_block(0, 0, false);
                    // For a full flush, this empty block will be recognized as
                    // a special marker by inflate_sync().
                    if flush == Flush::Full {
                        self.head.fill(0); // forget history
                        if self.lookahead == 0 {
                            self.strstart = 0;
                            self.block_start = 0;
                            self.insert = 0;
                        }
                    }
                }
                self.flush_pending(strm);
                if strm.avail_out() == 0 {
                    self.last_flush = None; // avoid BUF_ERROR at next call, see above
                    return Ok(Status::Ok);
                }
            }
        }

        if flush != Flush::Finish {
            return Ok(Status::Ok);
        }
        if self.wrap <= 0 {
            return Ok(Status::StreamEnd);
        }

        // Write the trailer
        let adler = self.adler.checksum();
        self.pending.buf.extend_from_slice(&adler.to_be_bytes());
        self.flush_pending(strm);
        // If avail_out is zero, the application will call deflate again to
        // flush the rest.
        self.wrap = -self.wrap; // write the trailer only once!
        Ok(if self.pending.buf.len() != self.pending.out {
            Status::Ok
        } else {
            Status::StreamEnd
        })
    }

    /// Read a new buffer from the current input stream, update the adler32 and
    /// total number of bytes read. All deflate() input goes through this
    /// function.
    fn read_buf<'a>(&mut self, strm: &mut Strm<'a>, size: usize) -> &'a [u8] {
        let len = min(strm.avail_in(), size);
        let buf = &strm.input[strm.next_in..strm.next_in + len];
        strm.next_in += len;
        if self.wrap == 1 {
            self.adler.write_slice(buf);
        }
        buf
    }

    /// Set match_start to the longest match starting at the given string and
    /// return its length. Matches shorter or equal to prev_length are
    /// discarded, in which case the result is equal to prev_length and
    /// match_start is garbage.
    /// IN assertions: cur_match is the head of the hash chain for the current
    ///   string (strstart) and its distance is <= MAX_DIST, and prev_length >=
    ///   1
    /// OUT assertion: the match length is not greater than s->lookahead.
    fn longest_match(&mut self, mut cur_match: usize) -> usize {
        let mut chain_length = self.max_chain_length; // max hash chain length
        let window = &self.window[..];
        let scan = self.strstart; // current string
        let mut best_len = self.prev_length; // best match length so far
        let mut nice_match = self.nice_match; // stop if match long enough
        // Stop when cur_match becomes <= limit. To simplify the code, we
        // prevent matches with the string of window index 0.
        let limit = self.strstart.saturating_sub(self.max_dist());
        let strend = scan + MAX_MATCH;
        let mut scan_end1 = window[scan + best_len - 1];
        let mut scan_end = window[scan + best_len];

        // Do not waste too much time if we already have a good match:
        if self.prev_length >= self.good_match {
            chain_length >>= 2;
        }
        // Do not look for matches beyond the end of the input. This is
        // necessary to make deflate deterministic.
        if nice_match > self.lookahead {
            nice_match = self.lookahead;
        }

        loop {
            let m = cur_match;
            // Skip to next match if the match length cannot increase or if the
            // match length is less than 2. Note that the checks below for
            // insufficient lookahead only occur occasionally for performance
            // reasons. Therefore bytes past the input will be compared.
            // However the length of the match is limited to the lookahead, so
            // the output of deflate is not affected by those values.
            if window[m + best_len] == scan_end
                && window[m + best_len - 1] == scan_end1
                && window[m] == window[scan]
                && window[m + 1] == window[scan + 1]
            {
                // The check at best_len-1 can be removed because it will be
                // made again later. (This heuristic is not always a win.) It
                // is not necessary to compare scan[2] and match[2] since they
                // are always equal when the other bytes match, given that the
                // hash keys are equal and that HASH_BITS >= 8.
                let (mut s, mut mm) = (scan + 2, m + 2);
                // We check for insufficient lookahead only every 8th
                // comparison; the 256th check will be made at strstart+258.
                'scan: loop {
                    for _ in 0..8 {
                        s += 1;
                        mm += 1;
                        if window[s] != window[mm] {
                            break 'scan;
                        }
                    }
                    if s >= strend {
                        break;
                    }
                }
                let len = MAX_MATCH - (strend - s);
                if len > best_len {
                    self.match_start = cur_match;
                    best_len = len;
                    if len >= nice_match {
                        break;
                    }
                    scan_end1 = window[scan + best_len - 1];
                    scan_end = window[scan + best_len];
                }
            }
            cur_match = usize::from(self.prev[cur_match & self.w_mask]);
            if cur_match <= limit {
                break;
            }
            chain_length -= 1;
            if chain_length == 0 {
                break;
            }
        }
        min(best_len, self.lookahead)
    }

    /// Fill the window when the lookahead becomes insufficient. Updates
    /// strstart and lookahead.
    ///
    /// IN assertion: lookahead < MIN_LOOKAHEAD
    /// OUT assertions: strstart <= window_size-MIN_LOOKAHEAD
    ///    At least one byte has been read, or avail_in == 0; reads are
    ///    performed for at least two bytes (required for the zip translate_eol
    ///    option -- not supported here).
    ///
    /// zlib zeroes the window bytes up to WIN_INIT past the input the first
    /// time it reaches them, for memory checkers; here the window starts
    /// zeroed, so it holds the same bytes.
    fn fill_window(&mut self, strm: &mut Strm) {
        let wsize = self.w_size;
        loop {
            // Amount of free space at the end of the window.
            let mut more = self.window_size - self.lookahead - self.strstart;

            // If the window is almost full and there is insufficient
            // lookahead, move the upper half to the lower one to make room in
            // the upper half.
            if self.strstart >= wsize + self.max_dist() {
                self.window.copy_within(wsize..2 * wsize - more, 0);
                self.match_start = self.match_start.wrapping_sub(wsize);
                self.strstart -= wsize; // we now have strstart >= MAX_DIST
                self.block_start -= wsize as isize;
                if self.insert > self.strstart {
                    self.insert = self.strstart;
                }
                self.slide_hash();
                more += wsize;
            }
            if strm.avail_in() == 0 {
                break;
            }

            // If there was no sliding:
            //    strstart <= WSIZE+MAX_DIST-1 && lookahead <= MIN_LOOKAHEAD - 1 &&
            //    more == window_size - lookahead - strstart
            // => more >= window_size - (MIN_LOOKAHEAD-1 + WSIZE + MAX_DIST-1)
            // => more >= window_size - 2*WSIZE + 2
            // In the BIG_MEM or MMAP case (not yet supported),
            //   window_size == input_size + MIN_LOOKAHEAD  &&
            //   strstart + s->lookahead <= input_size => more >= MIN_LOOKAHEAD.
            // Otherwise, window_size == 2*WSIZE so more >= 2.
            // If there was sliding, more >= WSIZE. So in all cases, more >= 2.
            let at = self.strstart + self.lookahead;
            let buf = self.read_buf(strm, more);
            self.window[at..at + buf.len()].copy_from_slice(buf);
            self.lookahead += buf.len();

            // Initialize the hash value now that we have some input:
            if self.lookahead + self.insert >= MIN_MATCH {
                let mut str = self.strstart - self.insert;
                self.ins_h = usize::from(self.window[str]);
                self.update_hash(self.window[str + 1]);
                while self.insert != 0 {
                    self.update_hash(self.window[str + MIN_MATCH - 1]);
                    self.prev[str & self.w_mask] = self.head[self.ins_h];
                    self.head[self.ins_h] = str as u16;
                    str += 1;
                    self.insert -= 1;
                    if self.lookahead + self.insert < MIN_MATCH {
                        break;
                    }
                }
            }
            // If the whole input has less than MIN_MATCH bytes, ins_h is
            // garbage, but this is not important since only literal bytes will
            // be emitted.

            if self.lookahead >= MIN_LOOKAHEAD || strm.avail_in() == 0 {
                break;
            }
        }
    }

    /// Flush the current block, with given end-of-file flag.
    /// IN assertion: strstart is set to the end of the current match.
    fn flush_block_only(&mut self, strm: &mut Strm, last: bool) {
        let buf = usize::try_from(self.block_start).ok();
        let stored_len = (self.strstart as isize - self.block_start) as usize;
        self.tr_flush_block(buf, stored_len, last);
        self.block_start = self.strstart as isize;
        self.flush_pending(strm);
    }

    /// Copy without compression as much as possible from the input stream,
    /// return the current block state.
    ///
    /// deflate_stored() is written to minimize the number of times an input
    /// byte is copied. It is most efficient with large input and output
    /// buffers, which maximizes the opportunites to have a single copy from
    /// next_in to next_out.
    ///
    /// zlib also counts here the hash table slides and the bytes to insert
    /// for deflateParams(), which is not ported.
    fn deflate_stored(&mut self, strm: &mut Strm, flush: Flush) -> BlockState {
        // Smallest worthy block size when not flushing or finishing. By
        // default this is 32K. This can be as small as 507 bytes for memLevel
        // == 1. For large input and output buffers, the stored block size will
        // be larger.
        let mut min_block = min(self.pending_buf_size - 5, self.w_size);

        // Copy as many min_block or larger stored blocks directly to next_out
        // as possible. If flushing, copy the remaining available input to
        // next_out as stored blocks, if there is enough space.
        let mut last = false;
        let used = strm.avail_in();
        loop {
            // Set len to the maximum size block that we can copy directly with
            // the available input data and output space. Set left to how much
            // of that would be copied from what's left in the window.
            let have = (self.pending.bi_valid as usize + 42) >> 3; // number of header bytes
            if strm.avail_out() < have {
                // need room for header
                break;
            }
            // maximum stored block length that will fit in avail_out:
            let have = strm.avail_out() - have;
            let mut left = (self.strstart as isize - self.block_start) as usize; // bytes left in window
            let input = left + strm.avail_in();
            let mut len = MAX_STORED.min(input).min(have);

            // If the stored block would be less than min_block in length, or
            // if unable to copy all of the available input when flushing, then
            // try copying to the window and the pending buffer instead. Also
            // don't write an empty block when flushing -- deflate() does that.
            if len < min_block
                && ((len == 0 && flush != Flush::Finish) || flush == Flush::None || len != input)
            {
                break;
            }

            // Make a dummy stored block in pending to get the header bytes,
            // including any pending bits.
            last = flush == Flush::Finish && len == input;
            self.tr_stored_block(0, 0, last);

            // Replace the lengths in the dummy stored block with len.
            let n = self.pending.buf.len();
            let len16 = len as u16;
            self.pending.buf[n - 4..n - 2].copy_from_slice(&len16.to_le_bytes());
            self.pending.buf[n - 2..].copy_from_slice(&(!len16).to_le_bytes());

            // Write the stored block header bytes.
            self.flush_pending(strm);

            // Copy uncompressed bytes from the window to next_out.
            if left != 0 {
                left = min(left, len);
                let start = self.block_start as usize;
                strm.write(&self.window[start..start + left]);
                self.block_start += left as isize;
                len -= left;
            }

            // Copy uncompressed bytes directly from next_in to next_out,
            // updating the check value.
            if len != 0 {
                let buf = self.read_buf(strm, len);
                strm.write(buf);
            }
            if last {
                break;
            }
        }

        // Update the sliding window with the last s->w_size bytes of the
        // copied data, or append all of the copied data to the existing window
        // if less than s->w_size bytes were copied.
        let used = used - strm.avail_in(); // number of input bytes directly copied
        if used != 0 {
            // If any input was used, then no unused input remains in the
            // window, therefore s->block_start == s->strstart.
            let consumed = &strm.input[..strm.next_in];
            if used >= self.w_size {
                // supplant the previous history
                self.window[..self.w_size]
                    .copy_from_slice(&consumed[consumed.len() - self.w_size..]);
                self.strstart = self.w_size;
            } else {
                if self.window_size - self.strstart <= used {
                    // Slide the window down.
                    self.strstart -= self.w_size;
                    self.window
                        .copy_within(self.w_size..self.w_size + self.strstart, 0);
                }
                self.window[self.strstart..self.strstart + used]
                    .copy_from_slice(&consumed[consumed.len() - used..]);
                self.strstart += used;
            }
            self.block_start = self.strstart as isize;
        }

        // If the last block was written to next_out, then done.
        if last {
            return BlockState::FinishDone;
        }

        // If flushing and all input has been consumed, then done.
        if flush != Flush::None
            && flush != Flush::Finish
            && strm.avail_in() == 0
            && self.strstart as isize == self.block_start
        {
            return BlockState::BlockDone;
        }

        // Fill the window with any remaining input.
        let mut have = self.window_size - self.strstart;
        if strm.avail_in() > have && self.block_start >= self.w_size as isize {
            // Slide the window down.
            self.block_start -= self.w_size as isize;
            self.strstart -= self.w_size;
            self.window
                .copy_within(self.w_size..self.w_size + self.strstart, 0);
            have += self.w_size; // more space now
        }
        if have > strm.avail_in() {
            have = strm.avail_in();
        }
        if have != 0 {
            let at = self.strstart;
            let buf = self.read_buf(strm, have);
            self.window[at..at + have].copy_from_slice(buf);
            self.strstart += have;
        }

        // There was not enough avail_out to write a complete worthy or flushed
        // stored block to next_out. Write a stored block to pending instead,
        // if we have enough input for a worthy block, or if flushing and there
        // is enough room for the remaining input as a stored block in the
        // pending buffer.
        let have = (self.pending.bi_valid as usize + 42) >> 3; // number of header bytes
        // maximum stored block length that will fit in pending:
        let have = min(self.pending_buf_size - have, MAX_STORED);
        min_block = min(have, self.w_size);
        let left = (self.strstart as isize - self.block_start) as usize;
        if left >= min_block
            || ((left != 0 || flush == Flush::Finish)
                && flush != Flush::None
                && strm.avail_in() == 0
                && left <= have)
        {
            let len = min(left, have);
            last = flush == Flush::Finish && strm.avail_in() == 0 && len == left;
            self.tr_stored_block(self.block_start as usize, len, last);
            self.block_start += len as isize;
            self.flush_pending(strm);
        }

        // We've done all we can with the available input and output.
        if last {
            BlockState::FinishStarted
        } else {
            BlockState::NeedMore
        }
    }

    /// Compress as much as possible from the input stream, return the current
    /// block state. This function does not perform lazy evaluation of matches
    /// and inserts new strings in the dictionary only for unmatched strings or
    /// for short matches. It is used only for the fast compression options.
    fn deflate_fast(&mut self, strm: &mut Strm, flush: Flush) -> BlockState {
        loop {
            // Make sure that we always have enough lookahead, except at the
            // end of the input file. We need MAX_MATCH bytes for the next
            // match, plus MIN_MATCH bytes to insert the string following the
            // next match.
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(strm);
                if self.lookahead < MIN_LOOKAHEAD && flush == Flush::None {
                    return BlockState::NeedMore;
                }
                if self.lookahead == 0 {
                    break; // flush the current block
                }
            }

            // Insert the string window[strstart .. strstart+2] in the
            // dictionary, and set hash_head to the head of the hash chain:
            let mut hash_head = 0;
            if self.lookahead >= MIN_MATCH {
                hash_head = self.insert_string(self.strstart);
            }

            // Find the longest match, discarding those <= prev_length. At this
            // point we have always match_length < MIN_MATCH
            if hash_head != 0 && self.strstart - hash_head <= self.max_dist() {
                // To simplify the code, we prevent matches with the string of
                // window index 0 (in particular we have to avoid a match of
                // the string with itself at the start of the input file).
                self.match_length = self.longest_match(hash_head);
                // longest_match() sets match_start
            }
            let bflush;
            if self.match_length >= MIN_MATCH {
                bflush = self.tr_tally_dist(
                    self.strstart - self.match_start,
                    self.match_length - MIN_MATCH,
                );
                self.lookahead -= self.match_length;

                // Insert new strings in the hash table only if the match
                // length is not too large. This saves time but degrades
                // compression.
                if self.match_length <= self.max_lazy_match && self.lookahead >= MIN_MATCH {
                    self.match_length -= 1; // string at strstart already in table
                    loop {
                        self.strstart += 1;
                        self.insert_string(self.strstart);
                        // strstart never exceeds WSIZE-MAX_MATCH, so there are
                        // always MIN_MATCH bytes ahead.
                        self.match_length -= 1;
                        if self.match_length == 0 {
                            break;
                        }
                    }
                    self.strstart += 1;
                } else {
                    self.strstart += self.match_length;
                    self.match_length = 0;
                    self.ins_h = usize::from(self.window[self.strstart]);
                    self.update_hash(self.window[self.strstart + 1]);
                    // If lookahead < MIN_MATCH, ins_h is garbage, but it does
                    // not matter since it will be recomputed at next deflate
                    // call.
                }
            } else {
                // No match, output a literal byte
                bflush = self.tr_tally_lit(self.window[self.strstart]);
                self.lookahead -= 1;
                self.strstart += 1;
            }
            if bflush {
                self.flush_block_only(strm, false);
                if strm.avail_out() == 0 {
                    return BlockState::NeedMore;
                }
            }
        }
        self.finish_blocks(strm, flush)
    }

    /// Same as above, but achieves better compression. We use a lazy
    /// evaluation for matches: a match is finally adopted only if there is no
    /// better match at the next window position.
    fn deflate_slow(&mut self, strm: &mut Strm, flush: Flush) -> BlockState {
        // Process the input block.
        loop {
            // Make sure that we always have enough lookahead, except at the
            // end of the input file. We need MAX_MATCH bytes for the next
            // match, plus MIN_MATCH bytes to insert the string following the
            // next match.
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(strm);
                if self.lookahead < MIN_LOOKAHEAD && flush == Flush::None {
                    return BlockState::NeedMore;
                }
                if self.lookahead == 0 {
                    break; // flush the current block
                }
            }

            // Insert the string window[strstart .. strstart+2] in the
            // dictionary, and set hash_head to the head of the hash chain:
            let mut hash_head = 0;
            if self.lookahead >= MIN_MATCH {
                hash_head = self.insert_string(self.strstart);
            }

            // Find the longest match, discarding those <= prev_length.
            self.prev_length = self.match_length;
            self.prev_match = self.match_start;
            self.match_length = MIN_MATCH - 1;

            if hash_head != 0
                && self.prev_length < self.max_lazy_match
                && self.strstart - hash_head <= self.max_dist()
            {
                // To simplify the code, we prevent matches with the string of
                // window index 0 (in particular we have to avoid a match of
                // the string with itself at the start of the input file).
                self.match_length = self.longest_match(hash_head);
                // longest_match() sets match_start

                // If prev_match is also MIN_MATCH, match_start is garbage but
                // we will ignore the current match anyway.
                if self.match_length == MIN_MATCH
                    && self.strstart.wrapping_sub(self.match_start) > TOO_FAR
                {
                    self.match_length = MIN_MATCH - 1;
                }
            }
            // If there was a match at the previous step and the current match
            // is not better, output the previous match:
            if self.prev_length >= MIN_MATCH && self.match_length <= self.prev_length {
                // Do not insert strings in hash table beyond this.
                let max_insert = self.strstart + self.lookahead - MIN_MATCH;

                let bflush = self.tr_tally_dist(
                    self.strstart - 1 - self.prev_match,
                    self.prev_length - MIN_MATCH,
                );

                // Insert in hash table all strings up to the end of the match.
                // strstart-1 and strstart are already inserted. If there is
                // not enough lookahead, the last two strings are not inserted
                // in the hash table.
                self.lookahead -= self.prev_length - 1;
                self.prev_length -= 2;
                loop {
                    self.strstart += 1;
                    if self.strstart <= max_insert {
                        self.insert_string(self.strstart);
                    }
                    self.prev_length -= 1;
                    if self.prev_length == 0 {
                        break;
                    }
                }
                self.match_available = false;
                self.match_length = MIN_MATCH - 1;
                self.strstart += 1;

                if bflush {
                    self.flush_block_only(strm, false);
                    if strm.avail_out() == 0 {
                        return BlockState::NeedMore;
                    }
                }
            } else if self.match_available {
                // If there was no match at the previous position, output a
                // single literal. If there was a match but the current match
                // is longer, truncate the previous match to a single literal.
                if self.tr_tally_lit(self.window[self.strstart - 1]) {
                    self.flush_block_only(strm, false);
                }
                self.strstart += 1;
                self.lookahead -= 1;
                if strm.avail_out() == 0 {
                    return BlockState::NeedMore;
                }
            } else {
                // There is no previous match to compare with, wait for the
                // next step to decide.
                self.match_available = true;
                self.strstart += 1;
                self.lookahead -= 1;
            }
        }
        if self.match_available {
            self.tr_tally_lit(self.window[self.strstart - 1]);
            self.match_available = false;
        }
        self.finish_blocks(strm, flush)
    }

    /// The common end of deflate_fast() and deflate_slow(), once the input is
    /// exhausted and flushing is requested.
    fn finish_blocks(&mut self, strm: &mut Strm, flush: Flush) -> BlockState {
        self.insert = min(self.strstart, MIN_MATCH - 1);
        if flush == Flush::Finish {
            self.flush_block_only(strm, true);
            if strm.avail_out() == 0 {
                return BlockState::FinishStarted;
            }
            return BlockState::FinishDone;
        }
        if self.sym_next != 0 {
            self.flush_block_only(strm, false);
            if strm.avail_out() == 0 {
                return BlockState::NeedMore;
            }
        }
        BlockState::BlockDone
    }
}
