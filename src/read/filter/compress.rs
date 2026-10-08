/*-
 * Copyright (c) 2003-2007 Tim Kientzle
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

/*
 * This code borrows heavily from "compress" source code, which is
 * protected by the following copyright.  (Clause 3 dropped by request
 * of the Regents.)
 */

/*-
 * Copyright (c) 1985, 1986, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Diomidis Spinellis and James A. Woods, derived from original
 * work by Spencer Thomas and Joseph Orost.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

// Ported from libarchive/archive_read_support_filter_compress.c.

//! The compress (`.Z`) filter: the LZW decoder of the Unix `compress` tool.

use crate::archive::Base;
use crate::read::{Filter, FilterBidder, Read, Reader, Status, filter_code};
use crate::util::Error;
use std::cmp::Ordering;
use std::ffi::{CStr, c_int};

/// The output block, as upstream's: each `read` fills at most this much.
const OUT_BLOCK: usize = 64 * 1024;
/// Codes are at most 16 bits, so the dictionary has this many entries.
const CODES: usize = 1 << 16;
/// The reset code, when the header sets `use_reset_code`.
const RESET: usize = 256;

/// `archive_read_support_filter_compress`.
pub fn support(r: &mut Read, _: &Base) -> Result<Status, Error> {
    r.register_bidder(Box::new(Bidder))
}

struct Bidder;

impl FilterBidder for Bidder {
    /// The shortest valid file is 3 bytes: the magic, then the parameter
    /// byte, whose reserved bits must be zero.
    fn bid(&mut self, up: &mut Reader<'_>) -> Result<c_int, Error> {
        Ok(match up.read_ahead(3)? {
            Some(&[0x1f, 0x9d, params, ..]) if params & 0x60 == 0 => 18,
            _ => 0,
        })
    }

    fn init(&mut self, _up: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
        let mut suffix = table(CODES, 0u8)?;
        for (s, code) in suffix.iter_mut().zip(0..=u8::MAX) {
            *s = code;
        }
        Ok(Box::new(Compress {
            out: alloc(OUT_BLOCK)?,
            block_used: 0,
            bit_buffer: 0,
            bits_avail: 0,
            bytes_in_section: 0,
            initialized: false,
            end_of_stream: false,
            use_reset_code: false,
            maxcode: 0,
            maxcode_bits: 0,
            section_end_code: 0,
            bits: 9,
            oldcode: None,
            finbyte: 0,
            free_ent: 0,
            prefix: table(CODES, 0u16)?,
            suffix,
            stack: Vec::new(),
        }))
    }
}

/// An empty buffer with room for `n` elements. A failed allocation is ENOMEM,
/// as upstream reports it.
fn alloc<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| {
        Error::fatal(
            libc::ENOMEM,
            "Can't allocate data for compress (.Z) decompression",
        )
    })?;
    Ok(v)
}

/// A table of `n` copies of `fill`.
fn table<T: Clone>(n: usize, fill: T) -> Result<Vec<T>, Error> {
    let mut v = alloc(n)?;
    v.resize(n, fill);
    Ok(v)
}

fn invalid() -> Error {
    Error::fatal(-1, "Invalid compressed data")
}

/// The decoder: upstream's `struct compress`.
struct Compress {
    /// The block `read` produced.
    out: Vec<u8>,
    /// Bytes of the current input block that are used. Upstream consumes a
    /// block only when it fetches the next one, so the stage below keeps the
    /// used bytes until then.
    block_used: usize,
    /// The bits read but not yet taken: the low `bits_avail` of `bit_buffer`.
    bit_buffer: usize,
    bits_avail: usize,
    /// Bytes read since the code width last changed.
    bytes_in_section: usize,
    initialized: bool,
    end_of_stream: bool,
    use_reset_code: bool,
    maxcode: usize,
    maxcode_bits: usize,
    /// The largest code at the current width; reaching it widens the codes.
    section_end_code: usize,
    /// The current code width, in bits.
    bits: usize,
    /// The previous code, `None` before the first one and after a reset.
    oldcode: Option<usize>,
    /// The first byte of the last expansion.
    finbyte: u8,
    /// The next free dictionary entry.
    free_ent: usize,
    /// Entry `c` (from 256) is `suffix[c]` appended to the string for
    /// `prefix[c]`. Entries below 256 are the single bytes.
    prefix: Vec<u16>,
    suffix: Vec<u8>,
    /// The expansion of a code still to be output, last byte first.
    stack: Vec<u8>,
}

impl Filter for Compress {
    fn name(&self) -> &CStr {
        c"compress (.Z)"
    }

    fn code(&self) -> c_int {
        filter_code::COMPRESS
    }

    /// `compress_filter_read`: decodes until the output block is full or the
    /// input ends.
    fn read(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
        if !self.initialized {
            self.start(up)?;
        }
        self.out.clear();
        while self.out.len() < OUT_BLOCK && !self.end_of_stream {
            if let Some(byte) = self.stack.pop() {
                self.out.push(byte);
            } else if !self.next_code(up)? {
                self.end_of_stream = true;
            }
        }
        Ok(())
    }

    fn block(&self) -> &[u8] {
        &self.out
    }
}

impl Compress {
    /// `compress_filter_init`: reads the header and starts the dictionary.
    fn start(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
        self.initialized = true;
        // The bidder has checked the magic, so these reads only skip it.
        let _ = self.getbits(up, 8);
        let _ = self.getbits(up, 8);
        let params = match self.getbits(up, 8) {
            Ok(Some(params)) => params,
            _ => return Err(invalid()),
        };
        if (params & 0x1f) > 16 {
            return Err(invalid());
        }
        self.maxcode_bits = params & 0x1f;
        self.maxcode = 1 << self.maxcode_bits;
        self.use_reset_code = params & 0x80 != 0;
        self.free_ent = if self.use_reset_code { 257 } else { 256 };
        self.bits = 9;
        self.section_end_code = (1 << self.bits) - 1;
        self.oldcode = None;
        // Upstream decodes the first code here and ignores the result, but
        // `next_code` has already set the error on the handle, and that stays
        // there while decoding carries on.
        if let Err(e) = self.next_code(up) {
            up.base().raise(e);
        }
        Ok(())
    }

    /// `next_code`: decodes the next code and pushes its expansion on the
    /// stack. `Ok(false)` at the end of the input.
    fn next_code(&mut self, up: &mut Reader<'_>) -> Result<bool, Error> {
        let code = loop {
            let Some(code) = self.getbits(up, self.bits)? else {
                return Ok(false);
            };
            if code != RESET || !self.use_reset_code {
                break code;
            }
            // The original 'compress' implementation blocked its I/O in a
            // manner that resulted in junk bytes being inserted after every
            // reset. The next section skips this junk. (Yes, the number of
            // *bytes* to skip is a function of the current *bit* length.)
            let bits = self.bits;
            let skip = (bits - self.bytes_in_section % bits) % bits;
            // Discard the rest of this byte. Only the count goes: upstream
            // leaves the bits in `bit_buffer`, and the next byte is ORed
            // onto them.
            self.bits_avail = 0;
            for _ in 0..skip {
                if self.getbits(up, 8)?.is_none() {
                    return Ok(false);
                }
            }
            self.bytes_in_section = 0;
            self.bits = 9;
            self.section_end_code = (1 << self.bits) - 1;
            self.free_ent = 257;
            self.oldcode = None;
        };
        let previous = self.oldcode;
        let mut string = match (code.cmp(&self.free_ent), previous) {
            (Ordering::Less, _) => code,
            // The KwKwK case: the code being defined is the previous string
            // followed by its own first byte.
            (Ordering::Equal, Some(old)) => {
                self.stack.push(self.finbyte);
                old
            }
            _ => return Err(invalid()),
        };
        self.oldcode = Some(code);

        // Generate output characters in reverse order. Every code is below
        // `free_ent`, which is at most `CODES`, so the table lookups are in
        // range.
        while string >= 256 {
            self.stack.push(self.suffix[string]);
            string = usize::from(self.prefix[string]);
        }
        self.finbyte = string as u8;
        self.stack.push(self.finbyte);

        // Generate the new entry.
        if self.free_ent < self.maxcode
            && let Some(old) = previous
        {
            self.prefix[self.free_ent] = old as u16;
            self.suffix[self.free_ent] = self.finbyte;
            self.free_ent += 1;
        }
        if self.free_ent > self.section_end_code {
            self.bits += 1;
            self.bytes_in_section = 0;
            self.section_end_code = if self.bits == self.maxcode_bits {
                self.maxcode
            } else {
                (1 << self.bits) - 1
            };
        }
        Ok(true)
    }

    /// `getbits`: the next `n` bits of the input, least significant first.
    /// `None` at the end of the input.
    fn getbits(&mut self, up: &mut Reader<'_>, n: usize) -> Result<Option<usize>, Error> {
        while self.bits_avail < n {
            let block = up.peek_available(1)?;
            let mut used = self.block_used;
            while self.bits_avail < n {
                let Some(&byte) = block.get(used) else {
                    break;
                };
                used += 1;
                self.bit_buffer |= usize::from(byte) << self.bits_avail;
                self.bits_avail += 8;
                self.bytes_in_section = self.bytes_in_section.saturating_add(1);
            }
            self.block_used = used;
            if self.bits_avail >= n {
                break;
            }
            if block.is_empty() {
                return Ok(None);
            }
            // The block is used up: consume it before the next one is fetched.
            up.consume(used)?;
            self.block_used = 0;
        }
        let code = self.bit_buffer & ((1 << n) - 1);
        self.bit_buffer >>= n;
        self.bits_avail -= n;
        Ok(Some(code))
    }
}

#[cfg(test)]
mod tests {
    use super::support;
    use crate::read::filter::testing::{decode, decode_with_message};

    /// `test_read_format_raw.data.Z`, which holds "foo\n".
    const FOO: &[u8] = &[0x1f, 0x9d, 0x90, 0x66, 0xde, 0xbc, 0x51, 0x00];
    /// "TOBEORNOTTOBEORTOBEORNOT", encoded with 9-bit codes and no reset code.
    const CLASSIC: &[u8] = &[
        0x1f, 0x9d, 0x10, 0x54, 0x9e, 0x08, 0x29, 0xf2, 0x44, 0x8a, 0x93, 0x27, 0x54, 0x00, 0x0a,
        0x24, 0x98, 0x70, 0x60, 0xc1, 0x83,
    ];
    const CLASSIC_TEXT: &[u8] = b"TOBEORNOTTOBEORTOBEORNOT";

    #[test]
    fn decodes() {
        assert_eq!(decode(support, FOO, 4096), Ok(b"foo\n".to_vec()));
        assert_eq!(decode(support, CLASSIC, 4096), Ok(CLASSIC_TEXT.to_vec()));
    }

    #[test]
    fn block_size_does_not_matter() {
        for data in [FOO, CLASSIC] {
            let whole = decode(support, data, 4096);
            for block in [1, 2, 3, 7] {
                assert_eq!(decode(support, data, block), whole);
            }
        }
    }

    /// The end of the input is not an error: a truncated stream decodes to a
    /// prefix of the whole. (Shorter than the first code, nothing decodes, and
    /// the core finds no format for the empty output.)
    #[test]
    fn truncation_gives_a_prefix() {
        let whole = decode(support, CLASSIC, 4096).expect("decodes");
        for n in 5..CLASSIC.len() {
            let out = decode(support, &CLASSIC[..n], 1).expect("not an error");
            assert!(whole.starts_with(&out), "truncated at {n}");
        }
    }

    #[test]
    fn corrupt_code_is_invalid() {
        // 65, then 300: the second code is past the 256 entries, with no
        // previous code to define one.
        let data = [0x1f, 0x9d, 0x10, 0x41, 0x58, 0x02];
        assert_eq!(
            decode(support, &data, 4096),
            Err("Invalid compressed data".to_string())
        );
    }

    /// An invalid first code is dropped and decoding carries on, but the error
    /// stays on the handle.
    #[test]
    fn invalid_first_code_is_kept_on_the_handle() {
        // 300 (invalid as the first code), then 65.
        let data = [0x1f, 0x9d, 0x90, 0x2c, 0x83, 0x00];
        let (out, message) = decode_with_message(support, &data, 4096);
        assert_eq!(out, Ok(b"A".to_vec()));
        assert_eq!(message, "Invalid compressed data");
    }

    #[test]
    fn bad_parameters_are_invalid() {
        let data = [0x1f, 0x9d, 0x1f, 0x41];
        assert_eq!(
            decode(support, &data, 4096),
            Err("Invalid compressed data".to_string())
        );
    }

    /// A parameter byte with a reserved bit set is not compress: the raw
    /// format passes the bytes through.
    #[test]
    fn reserved_bits_are_not_compress() {
        let data = [0x1f, 0x9d, 0x30, 0x41];
        assert_eq!(decode(support, &data, 4096), Ok(data.to_vec()));
    }

    #[test]
    fn mutations_do_not_panic() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        for _ in 0..500 {
            let mut data = CLASSIC.to_vec();
            for _ in 0..3 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let pos = usize::try_from(seed % data.len() as u64).unwrap_or(0);
                data[pos] = (seed >> 32) as u8;
            }
            let _ = decode(support, &data, 3);
        }
    }
}
