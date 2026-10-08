/*-
 * Copyright (c) 2009-2011 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_read_support_filter_uu.c.

//! `archive_read_support_filter_uu`: decodes a uuencoded or base64 body that
//! follows a `begin` line.

use crate::archive::{ARCHIVE_ERRNO_MISC, Base};
use crate::entry::{AE_IFREG, Entry, Mode};
use crate::read::{
    ARCHIVE_ERRNO_FILE_FORMAT, Filter, FilterBidder, Read, Reader, Status, filter_code,
};
use crate::util::Error;
use std::ffi::{CStr, c_int};

/// Upstream's `MAX_LINE_LENGTH`: the longest line that is looked at.
const MAX_LINE_LENGTH: usize = 128 * 1024;
/// Upstream's `OUT_BUFF_SIZE`: the most one `read` decodes.
const OUT_BUFF_SIZE: usize = 64 * 1024;

/// Registers the uudecode bidder with the handle.
pub fn support(r: &mut Read, _: &Base) -> Result<Status, Error> {
    r.register_bidder(Box::new(Bidder))
}

struct Bidder;

impl FilterBidder for Bidder {
    /// Looks for a `begin` line and checks the line after it. The bid is 50
    /// for a header on the first line, 30 for one later.
    fn bid(&mut self, up: &mut Reader<'_>) -> Result<c_int, Error> {
        let mut offset = 0;
        let mut firstline = 20;
        let header = loop {
            let (line, unconsumed) = read_line_ahead(up, false, offset)?;
            let Some(line) = line else { return Ok(0) };
            offset += unconsumed;
            if let Some(header) = parse_header(line) {
                break header;
            }
            firstline = 0;
        };
        let (line, unconsumed) = read_line_ahead(up, false, offset)?;
        let Some(line) = line else { return Ok(0) };
        let score = firstline + 30;
        if header.base64 {
            return Ok(if line.iter().all(|&c| is_base64(c)) {
                score
            } else {
                0
            });
        }
        let Some(&first) = line.first().filter(|&&c| is_uu(c)) else {
            return Ok(0);
        };
        let count = uudecode(first) as usize;
        // An empty encoded file.
        if count == 0 {
            return Ok(score);
        }
        // Normally the maximum length is 45 bytes, the character 'M'.
        let coded = line
            .get(1..=count)
            .is_some_and(|c| c.iter().all(|&b| is_uu(b)));
        if count > 45 || !coded {
            return Ok(0);
        }
        let (next, _) = read_line_ahead(up, false, offset + unconsumed)?;
        Ok(if next.and_then(|n| n.first()).is_some_and(|&c| is_uu(c)) {
            score
        } else {
            0
        })
    }

    fn init(&mut self, _up: &mut Reader<'_>) -> Result<Box<dyn Filter>, Error> {
        let mut out = Vec::new();
        out.try_reserve_exact(OUT_BUFF_SIZE)
            .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate data for uudecode"))?;
        Ok(Box::new(Uudecode {
            out,
            state: State::FindHead,
            mode: None,
            name: None,
        }))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    FindHead,
    ReadUu,
    UuEnd,
    ReadBase64,
    Ignore,
}

struct Uudecode {
    /// The output of the last `read`, which is the block.
    out: Vec<u8>,
    state: State,
    /// The permission bits and the name from the `begin` line.
    mode: Option<Mode>,
    name: Option<Vec<u8>>,
}

impl Filter for Uudecode {
    fn name(&self) -> &CStr {
        c"uu"
    }

    fn code(&self) -> c_int {
        filter_code::UU
    }

    fn read(&mut self, up: &mut Reader<'_>) -> Result<(), Error> {
        self.out.clear();
        while self.state != State::Ignore {
            let parsed = !self.out.is_empty();
            let (line, unconsumed) = read_line_ahead(up, parsed, 0)?;
            let Some(line) = line else {
                if unconsumed == MAX_LINE_LENGTH {
                    return Err(Error::fatal(
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        "Invalid format data",
                    ));
                }
                // The block ends here; the line is read again by the next call.
                if parsed {
                    break;
                }
                if self.state != State::FindHead {
                    return Err(insufficient());
                }
                // Non-ASCII character or end of stream is found.
                self.state = State::Ignore;
                up.consume(unconsumed)?;
                break;
            };
            let in_body = matches!(self.state, State::ReadUu | State::ReadBase64);
            if in_body && self.out.len() + 2 * line.len() > OUT_BUFF_SIZE {
                break;
            }
            self.decode(line)?;
            up.consume(unconsumed)?;
        }
        Ok(())
    }

    fn block(&self) -> &[u8] {
        &self.out
    }

    fn read_header(&mut self, _up: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        if let Some(mode) = self.mode {
            entry.set_mode(AE_IFREG | mode);
        }
        if let Some(name) = &self.name {
            entry.set_pathname(name);
        }
        Ok(Status::Ok)
    }
}

impl Uudecode {
    fn decode(&mut self, line: &[u8]) -> Result<(), Error> {
        match self.state {
            State::FindHead => {
                if let Some(header) = parse_header(line) {
                    self.state = if header.base64 {
                        State::ReadBase64
                    } else {
                        State::ReadUu
                    };
                    self.mode = Some(header.mode);
                    let name = line.get(header.name_offset..).unwrap_or_default();
                    // Upstream drops a one-byte name.
                    if name.len() > 1 {
                        // The name is a C string, so it ends at a NUL.
                        self.name = Some(name.iter().take_while(|&&c| c != 0).copied().collect());
                    }
                }
                Ok(())
            }
            State::ReadUu => self.uu_line(line),
            State::UuEnd => {
                if line == b"end" {
                    self.state = State::Ignore;
                    Ok(())
                } else {
                    Err(insufficient())
                }
            }
            State::ReadBase64 => self.base64_line(line),
            State::Ignore => Ok(()),
        }
    }

    /// A line of a uuencoded body: a length character, then the characters
    /// that encode that many bytes. A zero length ends the body.
    fn uu_line(&mut self, line: &[u8]) -> Result<(), Error> {
        let Some(&first) = line.first().filter(|&&c| is_uu(c)) else {
            return Err(insufficient());
        };
        let body = line.get(1..).unwrap_or_default();
        let mut left = uudecode(first) as usize;
        if left > body.len() {
            return Err(insufficient());
        }
        if left == 0 {
            self.state = State::UuEnd;
            return Ok(());
        }
        let mut i = 0;
        while left > 0 {
            if !is_uu(at(body, i)) || !is_uu(at(body, i + 1)) {
                break;
            }
            let mut n = (uudecode(at(body, i)) << 18) | (uudecode(at(body, i + 1)) << 12);
            i += 2;
            self.out.push((n >> 16) as u8);
            left -= 1;
            if left > 0 {
                if !is_uu(at(body, i)) {
                    break;
                }
                n |= uudecode(at(body, i)) << 6;
                i += 1;
                self.out.push((n >> 8) as u8);
                left -= 1;
            }
            if left > 0 {
                if !is_uu(at(body, i)) {
                    break;
                }
                n |= uudecode(at(body, i));
                i += 1;
                self.out.push(n as u8);
                left -= 1;
            }
        }
        if left != 0 {
            return Err(insufficient());
        }
        Ok(())
    }

    /// A line of a base64 body: groups of four characters that decode to
    /// three bytes, the last group padded with `=`. `===` ends the body.
    fn base64_line(&mut self, line: &[u8]) -> Result<(), Error> {
        if line.starts_with(b"===") {
            self.state = State::Ignore;
            return Ok(());
        }
        let mut i = 0;
        while i < line.len() {
            if !is_base64(at(line, i)) || !is_base64(at(line, i + 1)) {
                break;
            }
            let mut n = (base64_value(at(line, i)) << 18) | (base64_value(at(line, i + 1)) << 12);
            i += 2;
            self.out.push((n >> 16) as u8);
            if i == line.len() || !is_base64_digit(at(line, i)) {
                break;
            }
            n |= base64_value(at(line, i)) << 6;
            i += 1;
            self.out.push((n >> 8) as u8);
            if i == line.len() || !is_base64_digit(at(line, i)) {
                break;
            }
            n |= base64_value(at(line, i));
            i += 1;
            self.out.push(n as u8);
        }
        if i < line.len() && at(line, i) != b'=' {
            return Err(insufficient());
        }
        Ok(())
    }
}

fn insufficient() -> Error {
    Error::fatal(ARCHIVE_ERRNO_MISC, "Insufficient compressed data")
}

/// `uuchar`: the characters a uuencoded line is made of, space to backquote.
fn is_uu(c: u8) -> bool {
    matches!(c, b' '..=b'`')
}

/// `UUDECODE`: the value of a uuencoded character.
fn uudecode(c: u8) -> u32 {
    u32::from(c.wrapping_sub(b' ') & 0x3f)
}

/// `base64`: the characters of a base64 line, including the `=` padding.
fn is_base64(c: u8) -> bool {
    is_base64_digit(c) || c == b'='
}

fn is_base64_digit(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/')
}

/// `base64num`: the value of a base64 digit. `=` counts as 0, as upstream's
/// table has it.
fn base64_value(c: u8) -> u32 {
    u32::from(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => 0,
    })
}

/// The byte at `i` of a line. Past its end is the newline that ends the
/// line, which is in neither table, so the decoders stop there as upstream
/// does.
fn at(line: &[u8], i: usize) -> u8 {
    line.get(i).copied().unwrap_or(b'\n')
}

/// A `begin` line.
struct Header {
    base64: bool,
    mode: Mode,
    /// Where the name starts in the line.
    name_offset: usize,
}

/// `parse_header`. The mode is at least three octal digits, because
/// encoders don't all write the same number (644, 0644, 4755), and a looser
/// check would take other data for a header.
fn parse_header(line: &[u8]) -> Option<Header> {
    let (base64, prefix) = if line.starts_with(b"begin ") {
        (false, 6)
    } else if line.starts_with(b"begin-base64 ") {
        (true, 13)
    } else {
        return None;
    };
    let mut mode: Mode = 0;
    let mut end = prefix;
    while let Some(&d @ b'0'..=b'7') = line.get(end) {
        mode = ((mode << 3) | Mode::from(d - b'0')) & 0o777;
        end += 1;
    }
    // Then a space and at least one byte of name.
    if end < prefix + 3 || end + 1 >= line.len() || line.get(end) != Some(&b' ') {
        return None;
    }
    Some(Header {
        base64,
        mode,
        name_offset: end + 1,
    })
}

/// `read_line_ahead`: the line that starts `start` bytes into the input,
/// without its newline, and how many bytes it takes up with the newline.
/// With no whole line, the line is `None` and the count is the bytes looked
/// at, which the caller reports as unconsumed. Nothing is consumed. With
/// `parsed`, only bytes already buffered are looked at.
fn read_line_ahead<'r>(
    up: &'r mut Reader<'_>,
    parsed: bool,
    start: usize,
) -> Result<(Option<&'r [u8]>, usize), Error> {
    // Look at about two lines per round.
    let mut step = 160;
    let mut offset = start;
    let mut request = if start == 0 { 1 } else { start + step };
    let mut looked_at;
    let found = loop {
        let data = up.peek_available(request)?;
        let avail = data.len().min(MAX_LINE_LENGTH);
        looked_at = avail;
        if data.len() < request && avail <= offset {
            break None;
        }
        // A line starting at the cap gets an empty window, as upstream. Past
        // it, upstream's `avail - offset` wraps and its memchr reads on, so
        // search the buffered data.
        let end = if offset <= avail { avail } else { data.len() };
        let window = data.get(offset..end).unwrap_or_default();
        if let Some(i) = window.iter().position(|&c| c == b'\n') {
            let mut end = offset + i;
            let mut newline = 1;
            // A CR LF ends the line with its CR.
            if end > start && data.get(end - 1) == Some(&b'\r') {
                end -= 1;
                newline = 2;
            }
            break Some((end, newline));
        }
        if let Some(i) = window.iter().position(|&c| c == b'\r') {
            let cr = offset + i;
            // A CR that is the last byte looked at may be the first half of
            // a CR LF, so look at one more byte before taking it.
            if cr + 1 != avail || step == 1 {
                break Some((cr, 1));
            }
            step = 1;
        }
        if avail >= MAX_LINE_LENGTH || parsed {
            break None;
        }
        if step != 1 {
            offset = avail;
        }
        request = (avail + step).min(MAX_LINE_LENGTH);
    };
    match found {
        Some((end, newline)) => {
            let line = up.peek_available(end)?.get(start..end);
            Ok((line, end - start + newline))
        }
        None => Ok((None, looked_at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ARCHIVE_OK, Base, READ_MAGIC};
    use crate::read::format::raw;
    use crate::read::{Data, Status};
    use crate::read_open_memory::Memory;

    /// The data of the one entry in `input`, read through the raw format and
    /// this filter with the input delivered `block` bytes at a time. Or the
    /// message the failure left on the handle.
    fn decode(input: &[u8], block: usize) -> Result<Vec<u8>, String> {
        let mut r = Read::default();
        assert_eq!(support(&mut r, &Base::new(READ_MAGIC)).unwrap(), Status::Ok);
        assert_eq!(raw::support(&mut r).unwrap(), Status::Ok);
        let a = Base::new(READ_MAGIC);
        let failed = |a: &Base| {
            a.error_string()
                .map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned())
        };
        if r.open(&a, Box::new(Memory::new(input.to_vec(), block))) != ARCHIVE_OK {
            return Err(failed(&a));
        }
        if r.next_header2(&a, &mut Entry::new(None)) != ARCHIVE_OK {
            return Err(failed(&a));
        }
        let mut out = Vec::new();
        loop {
            match r.read_data_block(&a, |d| match d {
                Data::Block { data, .. } => Some(data.to_vec()),
                _ => None,
            }) {
                Ok(Some(chunk)) => out.extend(chunk),
                Ok(None) => return Ok(out),
                Err(_) => return Err(failed(&a)),
            }
        }
    }

    const UU: &[u8] = b"begin 644 test.txt\n#:&D*\n`\nend\n";
    const BASE64: &[u8] = b"begin-base64 600 test.txt\naGkK\n====\n";

    #[test]
    fn decodes_uuencode_and_base64() {
        assert_eq!(decode(UU, 1 << 16).unwrap(), b"hi\n");
        assert_eq!(decode(BASE64, 1 << 16).unwrap(), b"hi\n");
    }

    #[test]
    fn any_block_size_decodes_the_same() {
        for block in [1, 2, 3, 5, 7, 64] {
            assert_eq!(decode(UU, block).unwrap(), b"hi\n", "uu, block {block}");
            assert_eq!(
                decode(BASE64, block).unwrap(),
                b"hi\n",
                "base64, block {block}"
            );
        }
    }

    /// A `begin` line starting exactly at the 128k window's end is not seen,
    /// so the input passes through raw, as with upstream.
    #[test]
    fn begin_at_the_window_end_is_not_found() {
        let mut input = format!("{}\n", "a".repeat(1023)).repeat(128).into_bytes();
        input.extend_from_slice(UU);
        input.extend("`\n".repeat(200).bytes());
        assert_eq!(decode(&input, 1 << 16).unwrap(), input);
    }

    /// `test_read_filter_uudecode_newlines`: 810 zero bytes with each kind of
    /// line end.
    #[test]
    fn newlines_of_each_kind() {
        for nl in ["\r", "\n", "\r\n"] {
            let mut s = format!("begin 644 zeros{nl}");
            for _ in 0..18 {
                s += &format!("M{}{nl}", "`".repeat(60));
            }
            s += &format!("`{nl}end{nl}");
            assert_eq!(decode(s.as_bytes(), 4).unwrap(), vec![0; 810], "{nl:?}");
        }
    }

    #[test]
    fn a_short_body_line_is_insufficient_data() {
        // The bid takes the first line for a header; the line decodes short.
        let input = b"begin 644 t\n#:&D\n`\nend\n";
        assert_eq!(decode(input, 4), Err("Insufficient compressed data".into()));
    }

    #[test]
    fn a_body_without_end_is_insufficient_data() {
        let input = b"begin 644 t\n#:&D*\n`\n";
        assert_eq!(
            decode(input, 1 << 16),
            Err("Insufficient compressed data".into())
        );
    }

    #[test]
    fn truncation_at_every_offset_never_panics() {
        for input in [UU, BASE64] {
            for n in 0..=input.len() {
                for block in [1, 3, 1 << 16] {
                    let _ = decode(&input[..n], block);
                }
            }
        }
    }

    #[test]
    fn random_mutations_never_panic() {
        // A deterministic xorshift, so every run mutates the same way.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..500 {
            let mut input = if next() % 2 == 0 { UU } else { BASE64 }.to_vec();
            for _ in 0..=next() % 4 {
                let i = usize::try_from(next() % input.len() as u64).unwrap();
                input[i] = next() as u8;
            }
            let _ = decode(&input, usize::try_from(1 + next() % 9).unwrap());
        }
    }
}
