/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2008 Joerg Sonnenberger
 * Copyright (c) 2011-2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_read_support_format_mtree.c.

//! The mtree reader: a specification of a file tree, read whole into memory
//! on the first request, optionally checked against the file system.

use crate::archive::*;
use crate::entry::{AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFREG, Dev, Entry, Mode};
use crate::entry_link_resolver::LinkResolver;
use crate::pack_dev::pack_find;
use crate::read::{ARCHIVE_ERRNO_FILE_FORMAT, Data, Format, Read, Reader, Status, format_code};
use crate::string::string_dirname;
use crate::util::Error;
use std::collections::HashMap;
use std::ffi::{OsStr, c_int};
use std::fs::{self, File, Metadata};
use std::io::Read as _;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::rc::Rc;

const HAS_DEVICE: u32 = 0x0001;
const HAS_FFLAGS: u32 = 0x0002;
const HAS_GID: u32 = 0x0004;
const HAS_GNAME: u32 = 0x0008;
const HAS_MTIME: u32 = 0x0010;
const HAS_NLINK: u32 = 0x0020;
const HAS_PERM: u32 = 0x0040;
const HAS_SIZE: u32 = 0x0080;
const HAS_TYPE: u32 = 0x0100;
const HAS_UID: u32 = 0x0200;
const HAS_UNAME: u32 = 0x0400;
const HAS_OPTIONAL: u32 = 0x0800;
/// FreeBSD specific.
const HAS_NOCHANGE: u32 = 0x1000;

const MAX_LINE_LEN: usize = 1024 * 1024;

/// `ARCHIVE_ENTRY_DIGEST_*`.
const DIGEST_MD5: c_int = 1;
const DIGEST_RMD160: c_int = 2;
const DIGEST_SHA1: c_int = 3;
const DIGEST_SHA256: c_int = 4;
const DIGEST_SHA384: c_int = 5;
const DIGEST_SHA512: c_int = 6;

/// One line of the specification.
struct MtreeEntry {
    name: Vec<u8>,
    /// The `/set` options in effect when the line was read. Upstream copies
    /// them into every entry; the snapshot is shared instead.
    global: Rc<Vec<Vec<u8>>>,
    /// The `keyword=value` options of the line itself.
    own: Vec<Vec<u8>>,
    /// The name is a full path, not relative to the current directory.
    full: bool,
    used: bool,
}

#[derive(Default)]
struct Mtree {
    /// The bytes of the file a regular entry's data comes from.
    buff: Vec<u8>,
    offset: i64,
    file: Option<File>,
    entries: Vec<MtreeEntry>,
    this_entry: Option<usize>,
    current_dir: Vec<u8>,
    contents_name: Vec<u8>,
    resolver: Option<LinkResolver>,
    /// The full entries by name, in order: "full" entries are allowed to
    /// have multiple lines and those lines aren't required to be adjacent.
    by_name: HashMap<Vec<u8>, Vec<usize>>,
    cur_size: i64,
    checkfs: bool,
}

/// `archive_read_support_format_mtree`.
pub fn support(r: &mut Read) -> Result<Status, Error> {
    r.register_format(Box::new(Mtree::default()))
}

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

/// The text up to the first NUL, as a C string would read it.
fn until_nul(s: &[u8]) -> &[u8] {
    s.split(|&c| c == 0).next().unwrap_or_default()
}

/// Byte `i` of `p`, or NUL beyond either end.
fn at(p: &[u8], i: isize) -> u8 {
    usize::try_from(i)
        .ok()
        .and_then(|i| p.get(i))
        .copied()
        .unwrap_or(0)
}

/// `p + i`.
fn sub(p: &[u8], i: isize) -> &[u8] {
    usize::try_from(i)
        .ok()
        .and_then(|i| p.get(i..))
        .unwrap_or_default()
}

fn msg(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

impl Format for Mtree {
    fn name(&self) -> &'static str {
        "mtree"
    }

    fn bid(&mut self, r: &mut Reader<'_>, _best_bid: c_int) -> Result<c_int, Error> {
        const SIGNATURE: &[u8] = b"#mtree";

        // Now let's look at the actual header and see if it matches.
        let Ok(Some(h)) = r.read_ahead(SIGNATURE.len()) else {
            return Ok(-1);
        };
        if h.starts_with(SIGNATURE) {
            return Ok(8 * SIGNATURE.len() as c_int);
        }

        // There is not a mtree signature. Let's try to detect mtree format.
        Ok(detect_form(r).0)
    }

    fn options(
        &mut self,
        _a: &Base,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<Result<Status, Error>> {
        if key == b"checkfs" {
            // Allows to read information missing from the mtree from the
            // file system.
            self.checkfs = value.is_some_and(|v| !v.is_empty());
            return Some(Ok(Status::Ok));
        }

        // Note: The "warn" return is just to inform the options
        // supervisor that we didn't handle it.  It will generate
        // a suitable error if no one used this option.
        Some(Ok(Status::Warn))
    }

    /// Read in the entire mtree file into memory on the first request.
    /// Then use the next unused file to satisfy each header request.
    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        self.file = None;

        if self.entries.is_empty() {
            let mut resolver = LinkResolver::new();
            resolver.set_strategy(format_code::MTREE);
            self.resolver = Some(resolver);
            self.read_mtree(r)?;
            r.set_format(format_code::MTREE, c"mtree");
        }
        let a = r.base();

        loop {
            let Some(idx) = self.this_entry else {
                return Ok(Status::Eof);
            };
            let Some(me) = self.entries.get_mut(idx) else {
                return Ok(Status::Eof);
            };
            if me.name == b".." {
                me.used = true;
                if !self.current_dir.is_empty() {
                    // Roll back current path.
                    string_dirname(&mut self.current_dir);
                    if self.current_dir == b"." {
                        self.current_dir.clear();
                    }
                }
            }
            if !me.used {
                let (status, use_next) = self.parse_file(a, entry, idx);
                if !use_next {
                    return Ok(status);
                }
            }
            self.this_entry = Some(idx + 1).filter(|&n| n < self.entries.len());
        }
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        let a = r.base();
        let Some(file) = self.file.as_mut() else {
            return Ok(Data::Eof { offset: 0 });
        };
        if self.buff.is_empty() {
            self.buff = vec![0; 64 * 1024];
        }

        let offset = self.offset;
        let remaining = usize::try_from(self.cur_size.saturating_sub(offset)).unwrap_or(0);
        let want = remaining.min(self.buff.len());
        let bytes_read = match file.read(self.buff.get_mut(..want).unwrap_or_default()) {
            Ok(n) => n,
            Err(e) => {
                let _ = a.warn(e.raw_os_error().unwrap_or(0), "Can't read");
                return Ok(Data::Warn { offset: 0 });
            }
        };
        if bytes_read == 0 {
            return Ok(Data::Eof { offset });
        }
        // At most `want` more, which is within the size of the entry.
        self.offset = offset.saturating_add(i64::try_from(bytes_read).unwrap_or(0));
        Ok(Data::Block {
            data: self.buff.get(..bytes_read).unwrap_or_default(),
            offset,
        })
    }

    /// Skip does nothing except possibly close the contents file.
    fn read_data_skip(&mut self, _r: &mut Reader<'_>) -> Result<Status, Error> {
        self.file = None;
        Ok(Status::Ok)
    }
}

/// Compare characters with an mtree keyword.
/// Returns the length of an mtree keyword if matched.
/// Returns 0 if not matched.
fn bid_keycmp(p: &[u8], key: &[u8], mut len: isize) -> isize {
    let mut i = 0;
    while len > 0 && at(p, i) != 0 && at(key, i) != 0 {
        if at(p, i) != at(key, i) {
            return 0; // Not match
        }
        len -= 1;
        i += 1;
    }
    if at(key, i) != 0 {
        return 0; // Not match
    }

    // A following character should be specified characters
    let c = at(p, i);
    if matches!(c, b'=' | b' ' | b'\t' | b'\n' | b'\r')
        || (c == b'\\' && matches!(at(p, i + 1), b'\n' | b'\r'))
    {
        return i;
    }
    0 // Not match
}

/// Test whether the characters 'p' has is mtree keyword.
/// Returns the length of a detected keyword.
/// Returns 0 if any keywords were not found.
fn bid_keyword(p: &[u8], len: isize) -> isize {
    const KEYS_C: &[&[u8]] = &[b"content", b"contents", b"cksum"];
    const KEYS_DF: &[&[u8]] = &[b"device", b"flags"];
    const KEYS_G: &[&[u8]] = &[b"gid", b"gname"];
    const KEYS_IL: &[&[u8]] = &[b"ignore", b"inode", b"link"];
    const KEYS_M: &[&[u8]] = &[b"md5", b"md5digest", b"mode"];
    const KEYS_NO: &[&[u8]] = &[b"nlink", b"nochange", b"optional"];
    const KEYS_R: &[&[u8]] = &[b"resdevice", b"rmd160", b"rmd160digest"];
    const KEYS_S: &[&[u8]] = &[
        b"sha1",
        b"sha1digest",
        b"sha256",
        b"sha256digest",
        b"sha384",
        b"sha384digest",
        b"sha512",
        b"sha512digest",
        b"size",
    ];
    const KEYS_T: &[&[u8]] = &[b"tags", b"time", b"type"];
    const KEYS_U: &[&[u8]] = &[b"uid", b"uname"];

    let keys = match at(p, 0) {
        b'c' => KEYS_C,
        b'd' | b'f' => KEYS_DF,
        b'g' => KEYS_G,
        b'i' | b'l' => KEYS_IL,
        b'm' => KEYS_M,
        b'n' | b'o' => KEYS_NO,
        b'r' => KEYS_R,
        b's' => KEYS_S,
        b't' => KEYS_T,
        b'u' => KEYS_U,
        _ => return 0, // Unknown key
    };
    keys.iter()
        .map(|key| bid_keycmp(p, key, len))
        .find(|&l| l > 0)
        .unwrap_or(0) // Unknown key
}

/// Test whether there is a set of mtree keywords.
/// Returns the number of keywords.
/// Returns -1 if we got incorrect sequence.
/// This function expects a set of "<space characters>keyword=value".
/// When "unset" is specified, expects a set of "<space characters>keyword".
fn bid_keyword_list(p: &[u8], mut len: isize, unset: bool, last_is_path: bool) -> isize {
    let mut keycnt = 0;
    let mut i = 0;

    while len > 0 && at(p, i) != 0 {
        let mut blank = false;

        // Test whether there are blank characters in the line.
        while len > 0 && matches!(at(p, i), b' ' | b'\t') {
            i += 1;
            len -= 1;
            blank = true;
        }
        if matches!(at(p, i), b'\n' | b'\r') {
            break;
        }
        if at(p, i) == b'\\' && matches!(at(p, i + 1), b'\n' | b'\r') {
            break;
        }
        if !blank && !last_is_path {
            // No blank character.
            return -1;
        }
        if last_is_path && len == 0 {
            return keycnt;
        }

        if unset && bid_keycmp(sub(p, i), b"all", len) > 0 {
            return 1;
        }
        // Test whether there is a correct key in the line.
        let l = bid_keyword(sub(p, i), len);
        if l == 0 {
            return -1; // Unknown keyword was found.
        }
        i += l;
        len -= l;
        keycnt += 1;

        // Skip value
        if at(p, i) == b'=' {
            let mut value = false;
            i += 1;
            len -= 1;
            while len > 0 && !matches!(at(p, i), b' ' | b'\t') {
                i += 1;
                len -= 1;
                value = true;
            }
            // A keyword should have a value unless this is
            // an "/unset" operation.
            if !unset && !value {
                return -1;
            }
        }
    }
    keycnt
}

/// The bytes a path-name may consist of when it is not quoted.
fn safe_char(c: u8) -> bool {
    matches!(c, 0x21 | 0x22 | 0x24..=0x3c | 0x3e..=0x7e)
}

/// Returns the number of keywords (or -1) and whether the path-name was
/// found last.
fn bid_entry(p: &[u8], len: isize, nl: isize) -> (isize, bool) {
    let mut f = false;
    let mut last_is_path = false;

    // Skip the path-name which is quoted.
    let mut pp = 0;
    while pp < len {
        let c = at(p, pp);
        if !safe_char(c) {
            if !is_ws(c) {
                f = false;
            }
            break;
        }
        f = true;
        pp += 1;
    }
    let mut ll = len - pp;

    // If a path-name was not found at the first, try to check
    // a mtree format(a.k.a form D) ``NetBSD's mtree -D'' creates,
    // which places the path-name at the last.
    if !f {
        let mut pb = len - nl;
        let mut name_len = 0;
        let mut slash = false;

        // The form D accepts only a single line for an entry.
        if at(p, pb - 1) == b'\\' && matches!(at(p, pb - 2), b' ' | b'\t') {
            return (-1, last_is_path);
        }
        if at(p, pb - 1) == b'\\' {
            return (-1, last_is_path);
        }

        loop {
            pb -= 1;
            if pb < 0 || matches!(at(p, pb), b' ' | b'\t') {
                break;
            }
            if !safe_char(at(p, pb)) {
                return (-1, last_is_path);
            }
            name_len += 1;
            // The pathname should have a slash in this format.
            if at(p, pb) == b'/' {
                slash = true;
            }
        }
        if name_len == 0 || !slash {
            return (-1, last_is_path);
        }
        // If '/' is placed at the first in this field, this is not
        // a valid filename.
        if at(p, pb + 1) == b'/' {
            return (-1, last_is_path);
        }
        ll = len - nl - name_len;
        pp = 0;
        last_is_path = true;
    }

    (
        bid_keyword_list(sub(p, pp), ll, false, last_is_path),
        last_is_path,
    )
}

const MAX_BID_ENTRY: c_int = 3;

/// Returns the length of the line at the start of `b`, with the length of
/// its newline, or -1 if there is a NUL in it. A line that does not end in
/// `avail` bytes is all of them, with no newline.
fn get_line_size(b: &[u8], avail: usize) -> (isize, usize) {
    let mut len = 0;
    while len < avail {
        match at(b, len as isize) {
            // Non-ascii character or control character.
            0 => return (-1, 0),
            b'\r' if avail - len > 1 && at(b, len as isize + 1) == b'\n' => {
                return (len as isize + 2, 2);
            }
            b'\r' | b'\n' => return (len as isize + 1, 1),
            _ => len += 1,
        }
    }
    (avail as isize, 0)
}

/// The next line, which starts at `pos` in the read-ahead of `ravail`
/// bytes, as its length (0 at the end of the input, -1 if it can't be
/// used) and the length of its newline. Reads more bytes while it does not
/// reach the end of line.
///
/// ```text
///  <---------------- ravail --------------------->
///  <-- pos -------> <---  avail ----------------->
///                   <---- len ----------->
/// | Previous lines | line being parsed  nl extra |
/// ```
fn next_line(r: &mut Reader<'_>, pos: usize, ravail: &mut usize) -> (isize, usize) {
    let mut avail = ravail.saturating_sub(pos);
    let Ok(buf) = r.peek_available(*ravail) else {
        return (0, 0);
    };
    let (mut len, mut nl) = if avail == 0 {
        (0, 0)
    } else {
        get_line_size(sub(buf, pos as isize), avail)
    };
    let mut quit = false;
    // Read bytes more while it does not reach the end of line.
    while nl == 0 && len == avail as isize && !quit {
        // Place an arbitrary limit on the line length.
        // mtree is almost free-form input and without line length limits,
        // it can consume a lot of memory.
        if len >= MAX_LINE_LEN as isize {
            return (-1, nl);
        }

        // Increase reading bytes if it is not enough for at least
        // two new lines.
        let mut nbytes_req = ravail.saturating_add(1023) & 0xffff_fc00;
        if nbytes_req < ravail.saturating_add(160) {
            nbytes_req <<= 1;
        }

        let Ok(data) = r.peek_available(nbytes_req) else {
            return (0, nl);
        };
        if data.len() < nbytes_req {
            if *ravail >= data.len() {
                return (0, nl);
            }
            // Reading bytes reaches the end of file.
            quit = true;
        }
        *ravail = data.len();
        avail = ravail.saturating_sub(pos);
        // Skip some bytes we already determined.
        let tested = usize::try_from(len).unwrap_or(0);
        (len, nl) = get_line_size(
            sub(data, (pos + tested) as isize),
            avail.saturating_sub(tested),
        );
        if len >= 0 {
            len += tested as isize;
        }
    }
    (len, nl)
}

/// Whether the stream is an mtree specification without the `#mtree`
/// signature: the bid, and whether the file is in the form `NetBSD mtree -D`
/// creates ("form D").
fn detect_form(r: &mut Reader<'_>) -> (c_int, bool) {
    let mut entry_cnt = 0;
    let mut multiline = 0;
    let mut form_d = 0;
    let Ok(Some(first)) = r.read_ahead(1) else {
        return (-1, false);
    };
    let mut ravail = first.len();
    let mut pos = 0usize;
    let mut len;
    loop {
        let (l, nl) = next_line(r, pos, &mut ravail);
        len = l;
        // The terminal character of the line should be
        // a new line character, '\r\n' or '\n'.
        if len <= 0 || nl == 0 {
            break;
        }
        let Ok(buf) = r.peek_available(ravail) else {
            break;
        };
        let mut p = sub(buf, pos as isize);
        let nl = nl as isize;
        // The byte before the newline.
        let last = |p: &[u8], len: isize| at(p, len - nl - 1);
        if multiline == 0 {
            // Leading whitespace is never significant,
            // ignore it.
            while len > 0 && matches!(at(p, 0), b' ' | b'\t') {
                p = sub(p, 1);
                pos += 1;
                len -= 1;
            }
            // Skip comment or empty line.
            if matches!(at(p, 0), b'#' | b'\n' | b'\r') {
                pos += len as usize;
                continue;
            }
        } else {
            // A continuance line; the terminal
            // character of previous line was '\' character.
            if bid_keyword_list(p, len, false, false) <= 0 {
                break;
            }
            if last(p, len) != b'\\' {
                if multiline == 1 {
                    entry_cnt += 1;
                    if entry_cnt >= MAX_BID_ENTRY {
                        break;
                    }
                }
                multiline = 0;
            }
            pos += len as usize;
            continue;
        }
        if at(p, 0) != b'/' {
            let (keywords, last_is_path) = bid_entry(p, len, nl);
            if keywords < 0 {
                break;
            }
            if form_d == 0 {
                if last_is_path {
                    form_d = 1;
                } else if keywords > 0 {
                    // This line is not `form D'.
                    form_d = -1;
                }
            } else if form_d == 1 && !last_is_path && keywords > 0 {
                // This this is not `form D'
                // and we cannot accept mixed
                // format.
                break;
            }
            if !last_is_path && last(p, len) == b'\\' {
                // This line continues.
                multiline = 1;
            } else {
                // We've got plenty of correct lines
                // to assume that this file is an mtree
                // format.
                entry_cnt += 1;
                if entry_cnt >= MAX_BID_ENTRY {
                    break;
                }
            }
        } else if len > 4 && p.starts_with(b"/set") {
            if bid_keyword_list(sub(p, 4), len - 4, false, false) <= 0 {
                break;
            }
            // This line continues.
            if last(p, len) == b'\\' {
                multiline = 2;
            }
        } else if len > 6 && p.starts_with(b"/unset") {
            if bid_keyword_list(sub(p, 6), len - 6, true, false) <= 0 {
                break;
            }
            // This line continues.
            if last(p, len) == b'\\' {
                multiline = 2;
            }
        } else {
            break;
        }

        // Test next line.
        pos += len as usize;
    }
    if entry_cnt >= MAX_BID_ENTRY || (entry_cnt > 0 && len == 0) {
        return (32, form_d == 1);
    }
    (0, false)
}

/// Adds `token` (`keyword` or `keyword=value`) to `options`, replacing the
/// option of the same keyword.
fn set_option<T: AsRef<[u8]>>(options: &mut Vec<T>, token: T) {
    let bytes = token.as_ref();
    let len = bytes.iter().position(|&c| c == b'=').unwrap_or(bytes.len());
    remove_option(options, bytes.get(..len).unwrap_or_default());
    options.push(token);
}

fn remove_option<T: AsRef<[u8]>>(options: &mut Vec<T>, key: &[u8]) {
    let found = options.iter().rposition(|o| {
        let o = o.as_ref();
        o.starts_with(key) && o.get(key.len()).is_none_or(|&c| c == b'=')
    });
    if let Some(i) = found {
        options.remove(i);
    }
}

/// The whitespace-separated words of `line` from `start` up to `end`.
fn tokens(line: &[u8], start: usize, end: usize) -> impl Iterator<Item = &[u8]> {
    let mut i = start;
    std::iter::from_fn(move || {
        while line.get(i).is_some_and(|&c| is_ws(c)) {
            i += 1;
        }
        if i >= end || line.get(i).is_none_or(|&c| c == 0) {
            return None;
        }
        let from = i;
        while line.get(i).is_some_and(|&c| c != 0 && !is_ws(c)) {
            i += 1;
        }
        line.get(from..i)
    })
}

/// Since parsing backslash sequences always makes strings shorter,
/// upstream does this conversion in place.
fn parse_escapes(src: &[u8]) -> Vec<u8> {
    let src = until_nul(src);
    let mut dest = Vec::with_capacity(src.len());
    let octal = |c: u8| (b'0'..=b'7').contains(&c);
    let mut i = 0;

    while let Some(&first) = src.get(i) {
        let mut c = first;
        i += 1;
        if c == b'\\' {
            let s0 = at(src, i as isize);
            let s1 = at(src, i as isize + 1);
            let s2 = at(src, i as isize + 2);
            let simple = match s0 {
                b'0' if !octal(s1) => Some(0),
                b'0'..=b'3' => {
                    if octal(s1) && octal(s2) {
                        c = ((s0 - b'0') << 6) | ((s1 - b'0') << 3) | (s2 - b'0');
                        i += 3;
                    }
                    None
                }
                b'a' => Some(7),
                b'b' => Some(8),
                b'f' => Some(12),
                b'n' => Some(b'\n'),
                b'r' => Some(b'\r'),
                b's' => Some(b' '),
                b't' => Some(b'\t'),
                b'v' => Some(11),
                b'\\' => Some(b'\\'),
                _ => None,
            };
            if let Some(escaped) = simple {
                c = escaped;
                i += 1;
            }
        }
        dest.push(c);
    }
    // The result is a C string.
    dest.truncate(dest.iter().position(|&c| c == 0).unwrap_or(dest.len()));
    dest
}

/// Parse a hex digit. Note that this implementation does not (and should
/// not!) obey locale settings; you cannot simply substitute strtol here,
/// since it does obey locale.
fn parsedigit(c: u8) -> Option<i64> {
    char::from(c).to_digit(16).map(i64::from)
}

/// The number at the start of `p`, which moves past it. A base of 0 is
/// chosen by the prefix, as strtol does. A number that doesn't fit is the
/// limit of its sign.
fn mtree_atol(p: &mut &[u8], mut base: i64) -> i64 {
    if base == 0 {
        if at(p, 0) != b'0' {
            base = 10;
        } else if matches!(at(p, 1), b'x' | b'X') {
            *p = sub(p, 2);
            base = 16;
        } else {
            base = 8;
        }
    }

    let negative = at(p, 0) == b'-';
    if negative {
        *p = sub(p, 1);
    }
    let mut l: i64 = 0;
    while let Some(digit) = parsedigit(at(p, 0)).filter(|&d| d < base) {
        let next = l.checked_mul(base).and_then(|l| {
            if negative {
                l.checked_sub(digit)
            } else {
                l.checked_add(digit)
            }
        });
        let Some(next) = next else {
            return if negative { i64::MIN } else { i64::MAX };
        };
        l = next;
        *p = sub(p, 1);
    }
    l
}

/// Device entries have one of the following forms:
///  - raw dev_t
///  - format,major,minor[,subdevice]
fn parse_device(a: &Base, val: &[u8]) -> Result<Dev, Status> {
    const MAX_PACK_ARGS: usize = 3;
    let Some(comma) = val.iter().position(|&c| c == b',') else {
        // file system raw value.
        return Ok(mtree_atol(&mut { val }, 0) as Dev);
    };

    // Device's major/minor are given in a specified format.
    // Decode and pack it accordingly.
    let (format, mut rest) = val.split_at(comma);
    rest = sub(rest, 1);
    let Some(pack) = pack_find(format) else {
        return Err(a.warn(
            ARCHIVE_ERRNO_FILE_FORMAT,
            msg(&[b"Unknown format `", format, b"'"]),
        ));
    };
    let mut numbers = Vec::with_capacity(MAX_PACK_ARGS);
    while !rest.is_empty() {
        let end = rest.iter().position(|&c| c == b',').unwrap_or(rest.len());
        let (number, tail) = rest.split_at(end);
        rest = sub(tail, 1);
        if number.is_empty() {
            return Err(a.warn(ARCHIVE_ERRNO_FILE_FORMAT, "Missing number"));
        }
        if numbers.len() >= MAX_PACK_ARGS {
            return Err(a.warn(ARCHIVE_ERRNO_FILE_FORMAT, "Too many arguments"));
        }
        numbers.push(mtree_atol(&mut { number }, 0) as u64);
    }
    if numbers.len() < 2 {
        return Err(a.warn(ARCHIVE_ERRNO_FILE_FORMAT, "Not enough arguments"));
    }
    match pack(&numbers) {
        (dev, None) => Ok(dev),
        (_, Some(error)) => Err(a.warn(ARCHIVE_ERRNO_FILE_FORMAT, error)),
    }
}

fn parse_digest(a: &Base, entry: &mut Entry, digest: &[u8], ty: c_int) -> Status {
    let len = crate::entry::digest_len(ty).map_or(0, |n| n * 2);
    if digest.len() != len {
        return a.warn(
            ARCHIVE_ERRNO_FILE_FORMAT,
            "incorrect digest length, ignoring",
        );
    }

    let mut bytes = Vec::with_capacity(len / 2);
    for pair in digest.chunks_exact(2) {
        // XXX: Is uppercase something we should support?
        let nibble = |c: &u8| {
            char::from(*c)
                .to_digit(16)
                .filter(|_| !c.is_ascii_uppercase())
        };
        let (Some(high), Some(low)) = (pair.first().and_then(nibble), pair.get(1).and_then(nibble))
        else {
            return a.warn(ARCHIVE_ERRNO_FILE_FORMAT, "invalid digest data, ignoring");
        };
        bytes.push((high << 4 | low) as u8);
    }

    if entry.set_digest(ty, &bytes) == ARCHIVE_OK {
        Status::Ok
    } else {
        Status::Warn
    }
}

/// Parse a single keyword and its value.
fn parse_keyword(
    a: &Base,
    contents_name: &mut Vec<u8>,
    entry: &mut Entry,
    opt: &[u8],
    parsed_kws: &mut u32,
) -> Status {
    if opt.is_empty() {
        return Status::Ok;
    }

    match opt {
        b"nochange" => {
            *parsed_kws |= HAS_NOCHANGE;
            return Status::Ok;
        }
        b"optional" => {
            *parsed_kws |= HAS_OPTIONAL;
            return Status::Ok;
        }
        // The mtree processing is not recursive, so
        // recursion will only happen for explicitly listed
        // entries.
        b"ignore" => return Status::Ok,
        _ => {}
    }

    let Some(eq) = opt.iter().position(|&c| c == b'=') else {
        return a.warn(
            ARCHIVE_ERRNO_FILE_FORMAT,
            msg(&[
                b"Malformed attribute \"",
                opt,
                b"\" (",
                (at(opt, 0) as i8).to_string().as_bytes(),
                b")",
            ]),
        );
    };
    let (key, val) = opt.split_at(eq);
    let val = sub(val, 1);
    let mut num = val;

    match key {
        b"content" | b"contents" => *contents_name = parse_escapes(val),
        b"cksum" => {}
        b"device" => {
            // stat(2) st_rdev field, e.g. the major/minor IDs
            // of a char/block special file
            *parsed_kws |= HAS_DEVICE;
            match parse_device(a, val) {
                Ok(dev) => entry.set_rdev(dev),
                Err(status) => return status,
            }
        }
        b"flags" => {
            *parsed_kws |= HAS_FFLAGS;
            entry.copy_fflags_text(val);
        }
        b"gid" => {
            *parsed_kws |= HAS_GID;
            entry.set_gid(mtree_atol(&mut num, 10));
        }
        b"gname" => {
            *parsed_kws |= HAS_GNAME;
            entry.set_gname(val);
        }
        b"inode" => entry.set_ino(mtree_atol(&mut num, 10)),
        b"link" => entry.set_symlink(&parse_escapes(val)),
        b"md5" | b"md5digest" => return parse_digest(a, entry, val, DIGEST_MD5),
        b"mode" => {
            if !(b'0'..=b'7').contains(&at(val, 0)) {
                return a.warn(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    msg(&[b"Symbolic or non-octal mode \"", val, b"\" unsupported"]),
                );
            }
            *parsed_kws |= HAS_PERM;
            entry.set_perm(mtree_atol(&mut num, 8) as Mode);
        }
        b"nlink" => {
            *parsed_kws |= HAS_NLINK;
            entry.set_nlink(mtree_atol(&mut num, 10) as u32);
        }
        b"resdevice" => {
            // stat(2) st_dev field, e.g. the device ID where the
            // inode resides
            match parse_device(a, val) {
                Ok(dev) => entry.set_dev(dev),
                Err(status) => return status,
            }
        }
        b"rmd160" | b"rmd160digest" => return parse_digest(a, entry, val, DIGEST_RMD160),
        b"sha1" | b"sha1digest" => return parse_digest(a, entry, val, DIGEST_SHA1),
        b"sha256" | b"sha256digest" => return parse_digest(a, entry, val, DIGEST_SHA256),
        b"sha384" | b"sha384digest" => return parse_digest(a, entry, val, DIGEST_SHA384),
        b"sha512" | b"sha512digest" => return parse_digest(a, entry, val, DIGEST_SHA512),
        b"size" => {
            *parsed_kws |= HAS_SIZE;
            entry.set_size(mtree_atol(&mut num, 10));
        }
        // Comma delimited list of tags.
        // Ignore the tags for now, but the interface
        // should be extended to allow inclusion/exclusion.
        b"tags" => {}
        b"time" => {
            let mut ns = 0;

            *parsed_kws |= HAS_MTIME;
            let m = mtree_atol(&mut num, 10);
            // Replicate an old mtree bug:
            // 123456789.1 represents 123456789
            // seconds and 1 nanosecond.
            if at(num, 0) == b'.' {
                num = sub(num, 1);
                ns = mtree_atol(&mut num, 10).clamp(0, 999_999_999);
            }
            entry.set_mtime(m, ns);
        }
        b"type" => {
            let filetype = match val {
                b"block" => AE_IFBLK,
                b"char" => AE_IFCHR,
                b"dir" => AE_IFDIR,
                b"fifo" => AE_IFIFO,
                b"file" => AE_IFREG,
                b"link" => AE_IFLNK,
                _ => {
                    entry.set_filetype(u32::from(AE_IFREG));
                    return a.warn(
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        msg(&[b"Unrecognized file type \"", val, b"\"; assuming \"file\""]),
                    );
                }
            };
            *parsed_kws |= HAS_TYPE;
            entry.set_filetype(u32::from(filetype));
        }
        b"uid" => {
            *parsed_kws |= HAS_UID;
            entry.set_uid(mtree_atol(&mut num, 10));
        }
        b"uname" => {
            *parsed_kws |= HAS_UNAME;
            entry.set_uname(val);
        }
        _ => {
            return a.warn(
                ARCHIVE_ERRNO_FILE_FORMAT,
                msg(&[b"Unrecognized key ", key, b"=", val]),
            );
        }
    }
    Status::Ok
}

impl Mtree {
    /// The extended mtree format permits multiple lines specifying
    /// attributes for each file.  For those entries, only the last line
    /// is actually used.  Practically speaking, that means we have
    /// to read the entire mtree file into memory up front.
    ///
    /// The parsing is done in two steps.  First, it is decided if a line
    /// changes the global defaults and if it does, it is processed accordingly.
    /// Otherwise, the options of the line are merged with the current
    /// global options.
    fn process_add_entry(&mut self, global: &Rc<Vec<Vec<u8>>>, line: &[u8], is_form_d: bool) {
        let (name, start, end) = if is_form_d {
            // Filename is last item on line.
            // Trim trailing whitespace.
            let trimmed_len = line.iter().rposition(|&c| !is_ws(c)).map_or(0, |i| i + 1);
            let trimmed = line.get(..trimmed_len).unwrap_or_default();
            // Name starts after the last whitespace separator
            let name_start = trimmed.iter().rposition(|&c| is_ws(c)).map_or(0, |i| i + 1);
            (sub(trimmed, name_start as isize), 0, name_start)
        } else {
            // Filename is first item on line
            let name_len = line
                .iter()
                .position(|&c| c == 0 || is_ws(c))
                .unwrap_or(line.len());
            (
                line.get(..name_len).unwrap_or_default(),
                name_len,
                line.len(),
            )
        };
        // name is the name within the line.
        // start..end brackets the entire line except the name

        let raw_name = until_nul(name);
        let full = raw_name == b"." || raw_name.contains(&b'/');
        let idx = self.entries.len();
        let mut entry = MtreeEntry {
            name: parse_escapes(name),
            global: Rc::clone(global),
            own: Vec::new(),
            full,
            used: false,
        };
        if full {
            self.by_name
                .entry(entry.name.clone())
                .or_default()
                .push(idx);
        }
        for token in tokens(line, start, end) {
            set_option(&mut entry.own, token.to_vec());
        }
        self.entries.push(entry);
    }

    fn read_mtree(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let mut global: Rc<Vec<Vec<u8>>> = Rc::default();
        let mut line = Vec::new();

        let is_form_d = detect_form(r).1;

        let mut counter: u64 = 1;
        loop {
            let len = self.readline(r, &mut line, 65536)?;
            if len == 0 {
                self.this_entry = Some(0).filter(|&n| n < self.entries.len());
                return Ok(());
            }
            // Leading whitespace is never significant, ignore it.
            let trimmed = line.get(..len).unwrap_or_default();
            let p = trimmed
                .iter()
                .position(|&c| c != b' ' && c != b'\t')
                .map_or(&[][..], |i| sub(trimmed, i as isize));
            // Skip content lines and blank lines.
            if matches!(at(p, 0), b'#' | b'\r' | b'\n' | 0) {
                counter += 1;
                continue;
            }
            // Non-printable characters are not allowed. Upstream sets an
            // error for this, but gives up the same way as for a line it
            // can't parse, which replaces the message.
            if p.get(..p.len() - 1)
                .is_some_and(|s| s.iter().any(|&c| !matches!(c, 0x20..=0x7e | b'\t')))
            {
                break;
            }
            let text = until_nul(p);
            if at(p, 0) != b'/' {
                self.process_add_entry(&global, p, is_form_d);
            } else if p.len() > 4 && p.starts_with(b"/set") {
                if !matches!(at(p, 4), b' ' | b'\t') {
                    break;
                }
                for token in tokens(text, 4, text.len()) {
                    set_option(Rc::make_mut(&mut global), token.to_vec());
                }
            } else if p.len() > 6 && p.starts_with(b"/unset") {
                if !matches!(at(p, 6), b' ' | b'\t') {
                    break;
                }
                let args = sub(text, 6);
                if args.contains(&b'=') {
                    return Err(Error::fatal(
                        ARCHIVE_ERRNO_MISC,
                        "/unset shall not contain `='",
                    ));
                }
                for token in tokens(args, 0, args.len()) {
                    if token == b"all" {
                        global = Rc::default();
                    } else {
                        remove_option(Rc::make_mut(&mut global), token);
                    }
                }
            } else {
                break;
            }
            counter += 1;
        }

        Err(Error::fatal(
            ARCHIVE_ERRNO_FILE_FORMAT,
            format!("Can't parse line {counter}"),
        ))
    }

    /// Reads the next line into `line`. Returns the length of the line
    /// (including trailing newline), or 0 at the end of the input.
    fn readline(
        &mut self,
        r: &mut Reader<'_>,
        line: &mut Vec<u8>,
        limit: usize,
    ) -> Result<usize, Error> {
        let mut total_size = 0usize;
        let mut find_off = 0usize;

        // Accumulate line in a line buffer.
        loop {
            // Read some more.
            let Ok(Some(t)) = r.read_ahead(1) else {
                return Ok(0);
            };
            let nl = t.iter().position(|&c| c == b'\n');
            // If we found '\n', trim the read to end exactly there.
            let bytes_read = nl.map_or(t.len(), |i| i + 1);
            if total_size
                .checked_add(bytes_read)
                .and_then(|n| n.checked_add(1))
                .is_none_or(|n| n > limit)
            {
                return Err(Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, "Line too long"));
            }
            // Append new bytes to string.
            line.truncate(total_size);
            line.extend_from_slice(t.get(..bytes_read).unwrap_or_default());
            r.consume(bytes_read)?;
            total_size += bytes_read;

            let mut u = find_off;
            while u < total_size && at(line, u as isize) != 0 {
                match at(line, u as isize) {
                    b'\n' => {
                        // Ends with unescaped newline.
                        // Check if preceded by '\r' for CRLF handling
                        if u > 0 && at(line, u as isize - 1) == b'\r' {
                            // CRLF ending - remove the '\r'
                            line.truncate(u);
                            if let Some(c) = line.last_mut() {
                                *c = b'\n';
                            }
                            total_size -= 1;
                        }
                        line.truncate(total_size);
                        return Ok(total_size);
                    }
                    b'#' => {
                        // Ends with comment sequence #...\n
                        if nl.is_none() {
                            // But we've not found the \n yet
                            break;
                        }
                    }
                    b'\\' => {
                        if at(line, u as isize + 1) == b'\n' {
                            // Trim escaped newline.
                            total_size -= 2;
                            break;
                        } else if at(line, u as isize + 1) == b'\r'
                            && at(line, u as isize + 2) == b'\n'
                        {
                            // Trim escaped CRLF.
                            total_size -= 3;
                            break;
                        } else if at(line, u as isize + 1) != 0 {
                            // Skip the two-char escape sequence
                            u += 1;
                        }
                    }
                    _ => {}
                }
                u += 1;
            }
            find_off = u;
        }
    }

    /// Each line contains a sequence of keywords.
    fn parse_line(&mut self, a: &Base, entry: &mut Entry, idx: usize, kws: &mut u32) -> Status {
        let Some(mp) = self.entries.get(idx) else {
            return Status::Ok;
        };
        let mut r = Status::Ok;
        // An entry starts with the global options, each added to the front
        // of its list, which reverses their order. Its own options follow,
        // each replacing an option of the same keyword. Parsing goes from
        // the front of the list, which is the end here.
        let mut options: Vec<&[u8]> = mp.global.iter().rev().map(|o| o.as_slice()).collect();
        for token in &mp.own {
            set_option(&mut options, token);
        }
        for opt in options.iter().rev() {
            if parse_keyword(a, &mut self.contents_name, entry, opt, kws) == Status::Warn {
                r = Status::Warn;
            }
        }
        if r == Status::Ok && *kws & HAS_TYPE == 0 {
            return a.warn(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Missing type keyword in mtree specification",
            );
        }
        r
    }

    /// A single file can have multiple lines contribute specifications.
    /// Parse as many lines as necessary, then pull additional information
    /// from a backing file on disk as necessary. The flag says to go on to
    /// the next entry instead of returning this one.
    fn parse_file(&mut self, a: &Base, entry: &mut Entry, idx: usize) -> (Status, bool) {
        let Some(mentry) = self.entries.get_mut(idx) else {
            return (Status::Ok, false);
        };
        mentry.used = true;
        let (full, name) = (mentry.full, mentry.name.clone());

        // Initialize reasonable defaults.
        entry.set_filetype(u32::from(AE_IFREG));
        entry.set_size(0);
        self.contents_name.clear();

        // Parse options from this line.
        let mut parsed_kws = 0;
        let mut r = self.parse_line(a, entry, idx, &mut parsed_kws);

        if full {
            entry.set_pathname(&name);
            // "Full" entries are allowed to have multiple lines
            // and those lines aren't required to be adjacent.  We
            // don't support multiple lines for "relative" entries
            // nor do we make any attempt to merge data from
            // separate "relative" and "full" entries.  (Merging
            // "relative" and "full" entries would require dealing
            // with pathname canonicalization, which is a very
            // tricky subject.)
            for mp in self.by_name.get(&name).cloned().unwrap_or_default() {
                let Some(m) = self.entries.get_mut(mp) else {
                    continue;
                };
                if !m.full || m.used {
                    continue;
                }
                // Later lines override earlier ones.
                m.used = true;
                if self.parse_line(a, entry, mp, &mut parsed_kws) == Status::Warn {
                    r = Status::Warn;
                }
            }
        } else {
            // Relative entries require us to construct
            // the full path and possibly update the
            // current directory.
            let n = self.current_dir.len();
            if n > 0 {
                self.current_dir.push(b'/');
            }
            self.current_dir.extend_from_slice(&name);
            entry.set_pathname(&self.current_dir);
            if entry.filetype() != AE_IFDIR {
                self.current_dir.truncate(n);
            }
        }

        if self.checkfs {
            // Try to open and stat the file to get the real size
            // and other file info.  It would be nice to avoid
            // this here so that getting a listing of an mtree
            // wouldn't require opening every referenced contents
            // file.  But then we wouldn't know the actual
            // contents size, so I don't see a really viable way
            // around this.  (Also, we may want to someday pull
            // other unspecified info from the contents file on
            // disk.)
            self.file = None;
            let path = if self.contents_name.is_empty() {
                entry.pathname().map(|p| p.to_bytes().to_vec())
            } else {
                Some(self.contents_name.clone())
            }
            .unwrap_or_default();
            let os_path = Path::new(OsStr::from_bytes(&path));

            if matches!(entry.filetype(), AE_IFREG | AE_IFDIR) {
                match File::open(os_path) {
                    Ok(file) => self.file = Some(file),
                    Err(e) => {
                        let errno = e.raw_os_error().unwrap_or(0);
                        if errno != libc::ENOENT || !self.contents_name.is_empty() {
                            r = a.warn(errno, msg(&[b"Can't open ", &path]));
                        }
                    }
                }
            }

            let st: Option<Metadata> = if let Some(file) = &self.file {
                file.metadata()
                    .inspect_err(|e| {
                        r = a.warn(
                            e.raw_os_error().unwrap_or(0),
                            msg(&[b"Could not fstat ", &path]),
                        );
                        // If we can't stat it, don't keep it open.
                    })
                    .ok()
            } else {
                fs::symlink_metadata(os_path).ok()
            };
            if st.is_none() {
                self.file = None;
            }

            // Check for a mismatch between the type in the specification
            // and the type of the contents object on disk.
            if let Some(st) = &st
                && st.mode() & 0o170000 != u32::from(entry.filetype())
            {
                // Types don't match; bail out gracefully.
                self.file = None;
                if parsed_kws & HAS_OPTIONAL != 0 {
                    // It's not an error for an optional
                    // entry to not match disk.
                    return (r, true);
                }
                if r == Status::Ok {
                    let pathname = entry.pathname().map(|p| p.to_bytes().to_vec());
                    r = a.warn(
                        ARCHIVE_ERRNO_MISC,
                        msg(&[
                            b"mtree specification has different type for ",
                            &pathname.unwrap_or_default(),
                        ]),
                    );
                }
                return (r, false);
            }

            // If there is a contents file on disk, pick some of the
            // metadata from that file.  For most of these, we only
            // set it from the contents if it wasn't already parsed
            // from the specification.
            if let Some(st) = st {
                let nochange = parsed_kws & HAS_NOCHANGE != 0;
                if (parsed_kws & HAS_DEVICE == 0 || nochange)
                    && matches!(entry.filetype(), AE_IFCHR | AE_IFBLK)
                {
                    entry.set_rdev(st.rdev() as Dev);
                }
                if parsed_kws & (HAS_GID | HAS_GNAME) == 0 || nochange {
                    entry.set_gid(i64::from(st.gid()));
                }
                if parsed_kws & (HAS_UID | HAS_UNAME) == 0 || nochange {
                    entry.set_uid(i64::from(st.uid()));
                }
                if parsed_kws & HAS_MTIME == 0 || nochange {
                    entry.set_mtime(st.mtime(), st.mtime_nsec());
                }
                if parsed_kws & HAS_NLINK == 0 || nochange {
                    entry.set_nlink(st.nlink() as u32);
                }
                if parsed_kws & HAS_PERM == 0 || nochange {
                    entry.set_perm(st.mode() as Mode);
                }
                if parsed_kws & HAS_SIZE == 0 || nochange {
                    entry.set_size(i64::try_from(st.size()).unwrap_or(i64::MAX));
                }
                entry.set_ino(st.ino() as i64);
                entry.set_dev(st.dev() as Dev);

                if let Some(resolver) = self.resolver.as_mut() {
                    // The mtree strategy always hands the entry back.
                    let owned = Box::new(std::mem::replace(entry, Entry::new(None)));
                    if let (Some(linked), _) = resolver.linkify(Some(owned)) {
                        *entry = *linked;
                    }
                }
            } else if parsed_kws & HAS_OPTIONAL != 0 {
                // Couldn't open the entry, stat it or the on-disk type
                // didn't match.  If this entry is optional, just
                // ignore it and read the next header entry.
                return (Status::Ok, true);
            }
        }

        self.cur_size = entry.size();
        self.offset = 0;

        (r, false)
    }
}
