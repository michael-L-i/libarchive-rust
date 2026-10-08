/*-
 * Copyright (c) 2009 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_read_support_filter_rpm.c.

//! The rpm filter: skips the lead and the signature and header sections, and
//! passes the payload (usually compressed cpio) through to the filter above.

use crate::archive::ARCHIVE_FATAL;
use crate::archive::Base;
use crate::read::{ARCHIVE_ERRNO_FILE_FORMAT, Filter, FilterBidder, Read, Reader, Status, filter_code};
use crate::util::Error;
use std::ffi::{CStr, c_int};

/// Size of the 'Lead' section.
const LEAD_SIZE: usize = 96;
/// Minimum size of a 'Header' section: its magic, counts and size.
const MIN_HEADER_SIZE: usize = 16;

/// `archive_read_support_filter_rpm`.
pub fn support(r: &mut Read, _: &Base) -> Result<Status, Error> {
    r.register_bidder(Box::new(Bidder))
}

struct Bidder;

impl FilterBidder for Bidder {
    /// The lead's magic, then the major version (3 or 4), a zero byte, and the
    /// package type (0 binary, 1 source).
    fn bid(&mut self, up: &mut Reader<'_>) -> Result<c_int, Error> {
        Ok(match up.read_ahead(8)? {
            Some(&[0xED, 0xAB, 0xEE, 0xDB, major, _, 0, kind, ..])
                if matches!(major, 3 | 4) && kind <= 1 =>
            {
                56
            }
            _ => 0,
        })
    }

    fn init(&mut self, _up: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(Rpm {
            data_reached: false,
            block: Vec::new(),
        }))
    }
}

struct Rpm {
    /// Whether the lead and the headers have been skipped.
    data_reached: bool,
    /// The payload block being passed through.
    block: Vec<u8>,
}

impl Filter for Rpm {
    fn name(&self) -> &CStr {
        c"rpm"
    }

    fn code(&self) -> c_int {
        filter_code::RPM
    }

    /// `rpm_filter_read`: the payload, a block at a time, after the headers.
    fn read(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
        if !self.data_reached {
            skip_prologue(up)?;
            self.data_reached = true;
        }
        let data = up.peek_available(1)?;
        self.block.clear();
        self.block.extend_from_slice(data);
        up.consume(self.block.len())?;
        Ok(())
    }

    fn block(&self) -> &[u8] {
        &self.block
    }
}

/// `skip_prologue`: skips the lead and every header section that follows
/// it, each with its padding. At least one header must be there.
fn skip_prologue(up: &mut Reader<'_>) -> Result<(), Error> {
    up.consume(LEAD_SIZE)?;
    let mut seen_header = false;
    loop {
        let head = up
            .read_ahead(MIN_HEADER_SIZE)?
            .and_then(|h| h.first_chunk::<MIN_HEADER_SIZE>().copied());
        let Some(head) = head else {
            return Err(no_message());
        };
        if head.first_chunk::<4>() != Some(&[0x8E, 0xAD, 0xE8, 0x01]) {
            break;
        }
        seen_header = true;
        // The header, then 16 bytes per index entry and the data. Both counts
        // are 32-bit, so the length cannot overflow a u64.
        let [.., s0, s1, s2, s3, b0, b1, b2, b3] = head;
        let section = u64::from(u32::from_be_bytes([s0, s1, s2, s3]));
        let bytes = u64::from(u32::from_be_bytes([b0, b1, b2, b3]));
        up.consume(16 + section * 16 + bytes)?;
        skip_padding(up)?;
    }
    if !seen_header {
        return Err(Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Unrecognized rpm header"));
    }
    Ok(())
}

/// `skip_padding`: skips the zero bytes that pad a header to its boundary.
fn skip_padding(up: &mut Reader<'_>) -> Result<(), Error> {
    loop {
        let data = up.peek_available(1)?;
        if data.is_empty() {
            return Err(no_message());
        }
        let zeros = data.iter().take_while(|&&b| b == 0).count();
        let all = zeros == data.len();
        up.consume(zeros)?;
        if !all {
            return Ok(());
        }
    }
}

/// Upstream fails at the end of the input without setting a message, so the
/// handle keeps whatever it had.
fn no_message() -> Error {
    Error::recorded(ARCHIVE_FATAL)
}

#[cfg(test)]
mod tests {
    use super::support;
    use crate::read::filter::testing::decode;

    /// At least 16 bytes: upstream reads that much to look for another header.
    const PAYLOAD: &[u8] = b"foo\nfoo\nfoo\nfoo\n";

    /// A package: the lead, a signature header of 3 data bytes followed by a
    /// zero of padding, a header with none, and the payload.
    fn package() -> Vec<u8> {
        let mut p = vec![0xED, 0xAB, 0xEE, 0xDB, 3, 0, 0, 0];
        p.resize(96, 0);
        p.extend_from_slice(&[0x8E, 0xAD, 0xE8, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        p.extend_from_slice(b"abc\0");
        p.extend_from_slice(&[0x8E, 0xAD, 0xE8, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(PAYLOAD);
        p
    }

    #[test]
    fn strips_the_lead_and_headers() {
        assert_eq!(decode(support, &package(), 4096), Ok(PAYLOAD.to_vec()));
    }

    #[test]
    fn block_size_does_not_matter() {
        for block in [1, 5, 17] {
            assert_eq!(decode(support, &package(), block), Ok(PAYLOAD.to_vec()));
        }
    }

    #[test]
    fn without_a_header_is_unrecognized() {
        let mut data = vec![0xED, 0xAB, 0xEE, 0xDB, 4, 0, 0, 0];
        data.resize(96, 0);
        data.extend_from_slice(b"0123456789abcdef");
        assert_eq!(
            decode(support, &data, 4096),
            Err("Unrecognized rpm header".to_string())
        );
    }

    /// Any other major version or package type is not an rpm: the raw format
    /// passes the bytes through.
    #[test]
    fn other_versions_are_not_rpm() {
        let data = [0xED, 0xAB, 0xEE, 0xDB, 5, 0, 0, 0, b'x'];
        assert_eq!(decode(support, &data, 4096), Ok(data.to_vec()));
    }

    #[test]
    fn mutations_and_truncations_do_not_panic() {
        let whole = package();
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        for n in 0..whole.len() {
            let _ = decode(support, &whole[..n], 2);
        }
        for _ in 0..500 {
            let mut data = whole.clone();
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
