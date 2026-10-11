/*-
 * Copyright (c) 2003-2023 Tim Kientzle
 * Copyright (c) 2011-2012 Michihiro NAKAJIMA
 * Copyright (c) 2016 Martin Matuska
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

// Ported from libarchive/archive_read_support_format_tar.c.

//! The pax interchange format of the tar reader: `x` and `g` headers and
//! their attributes, including the vendor extensions.

use super::*;
use crate::acl::TYPE_DEFAULT;
use crate::string::SCONV_SET_OPT_UTF8_LIBARCHIVE2X;
use std::ffi::CString;

/// `AE_SYMLINK_TYPE_FILE` and `AE_SYMLINK_TYPE_DIRECTORY`.
const SYMLINK_TYPE_FILE: c_int = 1;
const SYMLINK_TYPE_DIRECTORY: c_int = 2;

/// Attributes that we act on when we see them in an `x` header.
///
/// A `g` header supplies defaults for every following member, which we do
/// not implement. Silently ignoring one of these would therefore change how
/// those members are interpreted, so we reject the archive instead.
/// Anything not listed here we already ignore wherever it appears, so
/// ignoring it in a `g` header is no less correct; that keeps well-formed
/// archives readable, in particular the `g` headers that star always writes
/// for its `exustar` format.
///
/// The flag says the key is a prefix.
const PAX_GLOBAL_UNSUPPORTED_ATTRS: &[(&[u8], bool)] = &[
    // POSIX-standard attributes that describe the member.
    (b"atime", false),
    (b"ctime", false),
    (b"gid", false),
    (b"gname", false),
    (b"hdrcharset", false),
    (b"linkpath", false),
    (b"mtime", false),
    (b"path", false),
    (b"size", false),
    (b"uid", false),
    (b"uname", false),
    // Vendor attributes that we honor.
    (b"GNU.sparse", false),
    (b"GNU.sparse.", true),
    (b"LIBARCHIVE.creationtime", false),
    (b"LIBARCHIVE.symlinktype", false),
    (b"LIBARCHIVE.xattr.", true),
    (b"RHT.security.selinux", false),
    (b"SCHILY.acl.access", false),
    (b"SCHILY.acl.ace", false),
    (b"SCHILY.acl.default", false),
    (b"SCHILY.dev", false),
    (b"SCHILY.devmajor", false),
    (b"SCHILY.devminor", false),
    (b"SCHILY.fflags", false),
    (b"SCHILY.ino", false),
    (b"SCHILY.nlink", false),
    (b"SCHILY.realsize", false),
    (b"SCHILY.xattr.", true),
    (b"SUN.holesdata", false),
];

fn pax_global_attribute_unsupported(key: &[u8]) -> bool {
    PAX_GLOBAL_UNSUPPORTED_ATTRS.iter().any(|&(k, is_prefix)| {
        if is_prefix {
            key.len() > k.len() && key.starts_with(k)
        } else {
            key == k
        }
    })
}

/// Parses the size and name of the attribute at the start of `p`, the part
/// of the extension body (`ext_size` bytes) that is buffered. Returns the
/// length of the "size name=" prolog, the length of the whole line and the
/// name, or what to warn about.
fn parse_prolog(p: &[u8], ext_size: i64) -> Result<(usize, usize, Vec<u8>), String> {
    /// Largest attribute: 100 million characters. This cannot be raised to
    /// more than 2GiB without exceeding a `size_t` on 32-bit platforms.
    const MAX_PARSED_LINE_LENGTH: usize = 99999999;

    // Parse size of attribute.
    let mut line_length: usize = 0;
    let mut i = 0;
    loop {
        match p.get(i) {
            None => {
                return Err(
                    "Ignoring malformed pax attributes: overlarge attribute size field".into(),
                );
            }
            Some(b' ') => {
                i += 1;
                break;
            }
            Some(c) if c.is_ascii_digit() => {
                line_length = line_length * 10 + usize::from(c - b'0');
                if line_length > MAX_PARSED_LINE_LENGTH {
                    return Err(format!(
                        "Ignoring malformed pax attribute: size > {MAX_PARSED_LINE_LENGTH}"
                    ));
                }
                i += 1;
            }
            Some(_) => {
                return Err(
                    "Ignoring malformed pax attributes: malformed attribute size field".into(),
                );
            }
        }
    }

    if i64::try_from(line_length).is_ok_and(|n| n > ext_size) {
        return Err(format!(
            "Ignoring malformed pax attribute:  {line_length} > {ext_size}"
        ));
    }

    // Parse name of attribute.
    if i >= p.len() || i >= line_length || p.get(i) == Some(&b'=') {
        return Err("Ignoring malformed pax attributes: empty name found".into());
    }
    let name_start = i;
    loop {
        if i >= line_length {
            return Err("Ignoring malformed pax attributes: overlarge attribute name".into());
        }
        match p.get(i) {
            None => {
                return Err("Ignoring malformed pax attributes: overlarge attribute name".into());
            }
            Some(b'=') => break,
            Some(_) => i += 1,
        }
    }
    // The name is a C string in upstream.
    let name = until_nul(p.get(name_start..i).unwrap_or_default()).to_vec();
    // Skip '='.
    Ok((i + 1, line_length, name))
}

/// Parse a decimal time value, which may include a fractional portion.
/// Returns seconds and nanoseconds.
///
/// The seconds are `i64::MIN` on error, including syntax issues such as
/// non-digits, or a time value that's outside the range of `i64`.
fn pax_time(p: &[u8]) -> (i64, i64) {
    const ERROR: (i64, i64) = (i64::MIN, 0);
    if p.is_empty() {
        return (0, 0);
    }
    let (sign, p) = match p.strip_prefix(b"-") {
        Some(rest) => (-1, rest),
        None => (1, p),
    };
    let digits = p.iter().take_while(|c| c.is_ascii_digit()).count();
    let (int_part, mut rest) = p.split_at(digits);
    let mut s: i64 = 0;
    for &c in int_part {
        match s
            .checked_mul(10)
            .and_then(|v| v.checked_add(i64::from(c - b'0')))
        {
            Some(v) => s = v,
            None => return ERROR,
        }
    }
    let sec = s * sign;

    // Calculate nanoseconds.
    if rest.is_empty() {
        return (sec, 0);
    }

    // Skip `.`.
    let Some(frac) = rest.strip_prefix(b".") else {
        return ERROR;
    };
    rest = frac;

    let mut nanos: i64 = 0;
    let mut l: i64 = 100_000_000;
    while l > 0 {
        let Some((&c, tail)) = rest.split_first() else {
            return (sec, nanos);
        };
        if !c.is_ascii_digit() {
            return ERROR;
        }
        nanos += i64::from(c - b'0') * l;
        rest = tail;
        l /= 10;
    }

    // Ignore resolution beyond nanoseconds, but verify it's all decimal
    // digits.
    if rest.iter().all(u8::is_ascii_digit) {
        (sec, nanos)
    } else {
        ERROR
    }
}

fn tohex(c: u8) -> Option<u8> {
    char::from(c)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

fn url_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut s = input;
    while let [c, rest @ ..] = s {
        if *c == 0 {
            break;
        }
        if *c == b'%'
            && let [d1, d2, ..] = rest
            // Try to convert % escape; else treat '%' as normal char.
            && let (Some(d1), Some(d2)) = (tohex(*d1), tohex(*d2))
        {
            // Looks good, consume three chars.
            out.push((d1 << 4) | d2);
            s = rest.get(2..).unwrap_or_default();
            continue;
        }
        out.push(*c);
        s = rest;
    }
    out
}

/// base64_decode - Base64 decode
///
/// This accepts most variations of base-64 encoding, including with or
/// without line breaks, and with or without the final group padded with '='
/// or '_' characters. (The most economical Base-64 variant does not pad the
/// last group and omits line breaks; RFC1341 used for MIME requires both.)
fn base64_decode(s: &[u8]) -> Vec<u8> {
    fn decode(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() - s.len() / 4);
    let mut src = s.iter();
    let mut done = false;
    while !done {
        // Collect the next group of (up to) four characters.
        let mut v: u32 = 0;
        let mut group_size = 0;
        while group_size < 4 {
            let Some(&c) = src.next() else {
                done = true;
                break;
            };
            // '=' or '_' padding indicates final group.
            if c == b'=' || c == b'_' {
                done = true;
                break;
            }
            // Skip illegal characters (including line breaks).
            let Some(d) = decode(c) else {
                continue;
            };
            v = (v << 6) | d;
            group_size += 1;
        }
        // Align a short group properly.
        v <<= 6 * (4 - group_size);
        // Unpack the group we just collected. A group of one is invalid.
        let bytes = [(v >> 16) as u8, (v >> 8) as u8, v as u8];
        out.extend_from_slice(bytes.get(..group_size * 3 / 4).unwrap_or_default());
    }
    out
}

/// `pax_attribute_read_number`.
fn read_number(r: &mut Reader<'_>, value_length: usize) -> (c_int, i64) {
    if value_length > 64 {
        let _ = r.consume(value_length);
        return (ARCHIVE_FATAL, 0);
    }

    let mut s = Vec::new();
    let mut unconsumed = 0;
    let code = read_bytes_to_string(r, &mut s, value_length, &mut unconsumed);
    if flush(r, &mut unconsumed) != ARCHIVE_OK {
        return (ARCHIVE_FATAL, 0);
    }
    if code < ARCHIVE_OK {
        return (code, 0);
    }

    let result = tar_atol10(&s);
    if result < 0 || result == i64::MAX {
        return (ARCHIVE_WARN, i64::MAX);
    }
    (ARCHIVE_OK, result)
}

/// `pax_attribute_read_time`: the code, seconds and nanoseconds.
fn read_time(r: &mut Reader<'_>, value_length: usize, unconsumed: &mut i64) -> (c_int, i64, i64) {
    if value_length > 128 {
        let _ = r.consume(value_length);
        return (ARCHIVE_FATAL, 0, 0);
    }

    let mut s = Vec::new();
    let code = read_bytes_to_string(r, &mut s, value_length, unconsumed);
    if code < ARCHIVE_OK {
        return (code, 0, 0);
    }

    match pax_time(&s) {
        (i64::MIN, _) => (ARCHIVE_WARN, 0, 0),
        (sec, nsec) => (ARCHIVE_OK, sec, nsec),
    }
}

/// `pax_attribute_LIBARCHIVE_xattr`.
fn libarchive_xattr(entry: &mut Entry, name: &[u8], value: &[u8]) {
    // URL-decode name. The name is a C string: it ends at a decoded NUL.
    let name_decoded = url_decode(name);
    if let Ok(name) = CString::new(until_nul(&name_decoded)) {
        // Base-64 decode value.
        entry.xattr_add(&name, &base64_decode(value));
    }
}

/// `pax_attribute_SCHILY_xattr`: whether the attribute was bad.
fn schily_xattr(entry: &mut Entry, name: &[u8], value: &[u8]) -> bool {
    if name.is_empty() || name.len() > 128 {
        return true;
    }
    // The name is a C string.
    if let Ok(name) = CString::new(until_nul(name)) {
        entry.xattr_add(&name, value);
    }
    false
}

impl Tar {
    /// Parse the attribute records in the body of an `x` or `g` header.
    ///
    /// With `global` false each attribute is applied to the entry. With
    /// `global` true the attributes are only inspected: we do not implement
    /// global defaults, so we reject any attribute that we would otherwise
    /// have honored and ignore the rest.
    pub(super) fn header_pax_records(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        h: &Block,
        unconsumed: &mut i64,
        global: bool,
    ) -> c_int {
        // Sanity checks: The largest `x` body I've ever heard of was a
        // little over 4MB. So I doubt there has ever been a well-formed
        // archive with an `x` body over 1GiB. Similarly, it seems
        // plausible that no single attribute has ever been larger than
        // 100MB. So if we see a larger value here, it's almost certainly a
        // sign of a corrupted/malicious archive.

        // Maximum sane size for extension body: 1 GiB. This cannot be
        // raised to larger than 8GiB without exceeding the maximum size for
        // a standard ustar entry.
        const EXT_SIZE_LIMIT: i64 = 1024 * 1024 * 1024;
        // Largest attribute prolog: size + name.
        const MAX_SIZE_NAME: i64 = 512;

        let a = r.base();
        let mut err = ARCHIVE_OK;

        // Size and padding of the full extension body.
        let mut ext_size = tar_atol(&h[SIZE]);
        if ext_size > ENTRY_LIMIT {
            return ARCHIVE_FATAL;
        }
        if ext_size < 0 {
            return fail(
                a,
                libc::EINVAL,
                format!("pax extension header has invalid size: {ext_size}"),
                ARCHIVE_FATAL,
            );
        }
        if ext_size == 0 {
            return fail(
                a,
                libc::EINVAL,
                if global {
                    "Invalid empty pax global extended header"
                } else {
                    "Invalid empty pax extended header"
                },
                ARCHIVE_FATAL,
            );
        }

        let ext_padding = padding(ext_size);
        if ext_size > EXT_SIZE_LIMIT {
            // Consume the pax extension body and return an error.
            if r.consume(ext_size + ext_padding).is_err() {
                return ARCHIVE_FATAL;
            }
            return fail(
                a,
                libc::EINVAL,
                format!("Ignoring oversized pax extensions: {ext_size} > {EXT_SIZE_LIMIT}"),
                ARCHIVE_WARN,
            );
        }
        if flush(r, unconsumed) != ARCHIVE_OK {
            return ARCHIVE_FATAL;
        }

        // Parse the size/name of each pax attribute in the body.
        while ext_size > 0 {
            // Read enough bytes to parse the size/name of the next
            // attribute.
            let to_read = MAX_SIZE_NAME.min(ext_size) as usize;
            let Some(p) = ahead(r, to_read) else {
                return fail(
                    a,
                    libc::EINVAL,
                    "Truncated tar archive detected while reading pax attribute name",
                    ARCHIVE_FATAL,
                );
            };
            let did_read = usize::try_from(ext_size).map_or(p.len(), |n| p.len().min(n));
            let prolog = parse_prolog(p.get(..did_read).unwrap_or_default(), ext_size);
            let (prolog_length, line_length, attr_name) = match prolog {
                Ok(parsed) => parsed,
                Err(msg) => {
                    a.set_error(ARCHIVE_ERRNO_MISC, Some(msg.as_bytes()));
                    *unconsumed += ext_size + ext_padding;
                    return ARCHIVE_WARN;
                }
            };

            ext_size -= prolog_length as i64;
            let value_length = line_length.saturating_sub(prolog_length);

            // Consume size, name, and `=`.
            *unconsumed += prolog_length as i64;
            if flush(r, unconsumed) != ARCHIVE_OK {
                return ARCHIVE_FATAL;
            }

            if value_length == 0 {
                a.set_error(libc::EINVAL, Some(b"Malformed pax attributes"));
                *unconsumed += ext_size + ext_padding;
                return ARCHIVE_WARN;
            }

            let res = if global {
                if pax_global_attribute_unsupported(&attr_name) {
                    let msg = [
                        b"Unsupported pax global extended header attribute '".as_slice(),
                        &attr_name,
                        b"'",
                    ]
                    .concat();
                    a.set_error(ARCHIVE_ERRNO_FILE_FORMAT, Some(&msg));
                    *unconsumed += ext_size + ext_padding;
                    return ARCHIVE_FATAL;
                }
                // Not an attribute we would have acted on, so ignoring it
                // here changes nothing.
                let _ = r.consume(value_length - 1);
                ARCHIVE_OK
            } else {
                // pax_attribute will consume value_length - 1.
                self.pax_attribute(r, entry, &attr_name, value_length - 1, unconsumed)
            };
            ext_size -= value_length as i64 - 1;

            if res < ARCHIVE_WARN {
                *unconsumed += ext_size + ext_padding;
                return res;
            }
            err = err.min(res);

            // Consume the `\n` that follows the pax attribute value.
            if flush(r, unconsumed) != ARCHIVE_OK {
                return ARCHIVE_FATAL;
            }
            let Some(newline) = ahead(r, 1).and_then(<[u8]>::first).map(|&c| c == b'\n') else {
                return fail(
                    a,
                    libc::EINVAL,
                    "Truncated tar archive detected while completing pax attribute",
                    ARCHIVE_FATAL,
                );
            };
            if !newline {
                a.set_error(libc::EINVAL, Some(b"Malformed pax attributes"));
                *unconsumed += ext_size + ext_padding;
                return ARCHIVE_WARN;
            }
            ext_size -= 1;
            *unconsumed += 1;
            if flush(r, unconsumed) != ARCHIVE_OK {
                return ARCHIVE_FATAL;
            }
        }
        *unconsumed += ext_size + ext_padding;

        // Some PAX values -- pathname, linkpath, uname, gname -- can't be
        // copied into the entry until we know the character set to use:
        let sconv = if !self.pax_hdrcharset_utf8 {
            // PAX specified "BINARY", so use the default charset.
            self.opt_sconv.clone()
        } else {
            // PAX default UTF-8.
            let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
            match conversion_from_charset(Some(&mut *cache), b"UTF-8", true) {
                Ok(sc) => {
                    if self.compat_2x {
                        sc.set_opt(SCONV_SET_OPT_UTF8_LIBARCHIVE2X);
                    }
                    Some(sc)
                }
                Err(e) => {
                    a.set_error(e.errno, Some(&e.message));
                    return ARCHIVE_FATAL;
                }
            }
        };
        let sconv = sconv.as_deref();

        // Pathname: prefer GNU.sparse.name attribute if present. GNU sparse
        // files store a fake name under the standard "pathname" key.
        let pas = if !self.entry_pathname_override.is_empty() {
            Some(&self.entry_pathname_override)
        } else if !self.entry_pathname.is_empty() {
            // Use standard "pathname" PAX extension.
            Some(&self.entry_pathname)
        } else {
            None
        };
        if let Some(pas) = pas
            && entry.copy_pathname_l(pas, sconv).is_err()
        {
            err = conversion_failed(a, sconv, "Pathname");
            // Use raw name without conversion.
            entry.set_pathname(until_nul(pas));
        }
        // Uname
        if !self.entry_uname.is_empty() && entry.copy_uname_l(&self.entry_uname, sconv).is_err() {
            err = conversion_failed(a, sconv, "Uname");
            entry.set_uname(until_nul(&self.entry_uname));
        }
        // Gname
        if !self.entry_gname.is_empty() && entry.copy_gname_l(&self.entry_gname, sconv).is_err() {
            err = conversion_failed(a, sconv, "Gname");
            entry.set_gname(until_nul(&self.entry_gname));
        }
        // Linkpath
        if !self.entry_linkpath.is_empty()
            && entry.copy_link_l(&self.entry_linkpath, sconv).is_err()
        {
            err = conversion_failed(a, sconv, "Linkpath");
            entry.set_link(until_nul(&self.entry_linkpath));
        }

        // Extension may have given us a corrected `entry_bytes_remaining`
        // for the main entry; update the padding appropriately.
        self.entry_padding = padding(self.entry_bytes_remaining);
        err
    }

    /// `pax_attribute_SCHILY_acl`.
    fn schily_acl(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        value_length: usize,
        type_: c_int,
    ) -> c_int {
        let a = r.base();
        let errstr = match type_ {
            TYPE_ACCESS => "SCHILY.acl.access",
            TYPE_DEFAULT => "SCHILY.acl.default",
            _ => "SCHILY.acl.ace",
        };

        let sconv = match self.acl_sconv(a) {
            Ok(sc) => sc,
            Err(code) => return code,
        };

        if value_length > ACL_LIMIT {
            let _ = r.consume(value_length);
            return fail(
                a,
                ARCHIVE_ERRNO_MISC,
                format!("Unreasonably large ACL: {value_length} > {ACL_LIMIT}"),
                ARCHIVE_WARN,
            );
        }

        let Some(p) = ahead(r, value_length).and_then(|p| p.get(..value_length)) else {
            return fail(
                a,
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Truncated tar archive detected while reading ACL data",
                ARCHIVE_FATAL,
            );
        };

        let res = entry.acl.parse_nl(p, type_, Some(&sconv));
        let _ = r.consume(value_length);
        // Workaround: Force perm_is_set() to be correct. If this bit were
        // stored in the ACL, this wouldn't be needed.
        entry.set_perm(entry.perm());
        if res != ARCHIVE_OK {
            a.set_error(
                ARCHIVE_ERRNO_MISC,
                Some(format!("Parse error: {errstr}").as_bytes()),
            );
        }
        res
    }

    /// Parse a single key=value attribute.
    ///
    /// POSIX reserves all-lowercase keywords. Vendor-specific extensions
    /// should always have keywords of the form "VENDOR.attribute". In
    /// particular, it's quite feasible to support many different vendor
    /// extensions here. I'm using "LIBARCHIVE" for extensions unique to this
    /// library.
    ///
    /// TODO: Investigate other vendor-specific extensions and see if any of
    /// them look useful.
    fn pax_attribute(
        &mut self,
        r: &mut Reader<'_>,
        entry: &mut Entry,
        key: &[u8],
        value_length: usize,
        unconsumed: &mut i64,
    ) -> c_int {
        let a = r.base();
        let mut err = ARCHIVE_OK;

        // GNU.* extensions.
        // GNU.sparse marks the existence of GNU sparse information.
        if key == b"GNU.sparse" {
            self.sparse_gnu_attributes_seen = true;
        }
        // GNU.sparse.* extensions.
        else if let Some(key) = key
            .strip_prefix(b"GNU.sparse.")
            .filter(|key| !key.is_empty())
        {
            self.sparse_gnu_attributes_seen = true;
            match key {
                // GNU "0.0" sparse pax format.
                b"numblocks" => {
                    self.sparse_offset = -1;
                    self.sparse_numbytes = -1;
                    self.sparse_gnu_major = 0;
                    self.sparse_gnu_minor = 0;
                }
                b"offset" => {
                    let (err, t) = read_number(r, value_length);
                    if err == ARCHIVE_OK {
                        self.sparse_offset = t;
                        if self.sparse_numbytes != -1 {
                            if self.add_sparse_entry(a, self.sparse_offset, self.sparse_numbytes)
                                != ARCHIVE_OK
                            {
                                return ARCHIVE_FATAL;
                            }
                            self.sparse_offset = -1;
                            self.sparse_numbytes = -1;
                        }
                    }
                    return err;
                }
                b"numbytes" => {
                    let (err, t) = read_number(r, value_length);
                    if err == ARCHIVE_OK {
                        self.sparse_numbytes = t;
                        if self.sparse_offset != -1 {
                            if self.add_sparse_entry(a, self.sparse_offset, self.sparse_numbytes)
                                != ARCHIVE_OK
                            {
                                return ARCHIVE_FATAL;
                            }
                            self.sparse_offset = -1;
                            self.sparse_numbytes = -1;
                        }
                    }
                    return err;
                }
                // This is either the size of stored entry OR the size of
                // data on disk, depending on which GNU sparse format
                // version is in use. Since pax attributes can be in any
                // order, we may not actually know at this point how to
                // interpret this.
                b"size" => {
                    let (err, t) = read_number(r, value_length);
                    if err == ARCHIVE_OK {
                        self.gnu_sparse_size = t;
                        self.size_fields |= TAR_SIZE_GNU_SPARSE_SIZE;
                    }
                    return err;
                }

                // GNU "0.1" sparse pax format.
                b"map" => {
                    self.sparse_gnu_major = 0;
                    self.sparse_gnu_minor = 1;
                    if value_length > SPARSE_MAP_LIMIT {
                        err = fail(
                            a,
                            ARCHIVE_ERRNO_MISC,
                            format!(
                                "Unreasonably large sparse map: {value_length} > {SPARSE_MAP_LIMIT}"
                            ),
                            ARCHIVE_FAILED,
                        );
                    } else {
                        let Some(p) = ahead(r, value_length).and_then(|p| p.get(..value_length))
                        else {
                            return fail(
                                a,
                                libc::EINVAL,
                                "Truncated archive detected while reading GNU sparse data",
                                ARCHIVE_FATAL,
                            );
                        };
                        if self.sparse_01_parse(a, p) != ARCHIVE_OK {
                            err = ARCHIVE_WARN;
                        }
                    }
                    let _ = r.consume(value_length);
                    return err;
                }

                // GNU "1.0" sparse pax format.
                b"major" => {
                    let (err, t) = read_number(r, value_length);
                    if err == ARCHIVE_OK && (0..=10).contains(&t) {
                        self.sparse_gnu_major = t as i32;
                    }
                    return err;
                }
                b"minor" => {
                    let (err, t) = read_number(r, value_length);
                    if err == ARCHIVE_OK && (0..=10).contains(&t) {
                        self.sparse_gnu_minor = t as i32;
                    }
                    return err;
                }
                // The real filename; when storing sparse files, GNU tar
                // puts a synthesized name into the regular 'path' attribute
                // in an attempt to limit confusion. ;-)
                b"name" => {
                    return self.pax_string(r, value_length, PATHNAME_LIMIT, unconsumed, |tar| {
                        &mut tar.entry_pathname_override
                    });
                }
                // GNU.sparse.realsize = size of file on disk.
                b"realsize" => {
                    let (err, t) = read_number(r, value_length);
                    if err == ARCHIVE_OK {
                        self.gnu_sparse_realsize = t;
                        self.size_fields |= TAR_SIZE_GNU_SPARSE_REALSIZE;
                    }
                    return err;
                }
                _ => {}
            }
        }
        // LIBARCHIVE extensions.
        else if let Some(key) = key
            .strip_prefix(b"LIBARCHIVE.")
            .filter(|key| !key.is_empty())
        {
            // TODO: Handle arbitrary extended attributes...
            if key == b"creationtime" {
                let (err, sec, n) = read_time(r, value_length, unconsumed);
                if err == ARCHIVE_OK {
                    entry.set_birthtime(sec, n);
                } else {
                    a.set_error(
                        ARCHIVE_ERRNO_MISC,
                        Some(b"Ignoring malformed pax creationtime"),
                    );
                }
                return err;
            } else if key == b"symlinktype" {
                if value_length < 16 {
                    let Some(p) = ahead(r, value_length).and_then(|p| p.get(..value_length)) else {
                        return fail(
                            a,
                            ARCHIVE_ERRNO_FILE_FORMAT,
                            "Truncated tar archive detected while reading `symlinktype` attribute",
                            ARCHIVE_FATAL,
                        );
                    };
                    if p == b"file" {
                        entry.set_symlink_type(SYMLINK_TYPE_FILE);
                    } else if p == b"dir" {
                        entry.set_symlink_type(SYMLINK_TYPE_DIRECTORY);
                    } else {
                        err = fail(
                            a,
                            ARCHIVE_ERRNO_MISC,
                            "Unrecognized symlink type",
                            ARCHIVE_WARN,
                        );
                    }
                } else {
                    err = fail(
                        a,
                        ARCHIVE_ERRNO_MISC,
                        format!(
                            "symlink type is very long(longest recognized value is 4 bytes, this is {value_length})"
                        ),
                        ARCHIVE_WARN,
                    );
                }
                let _ = r.consume(value_length);
                return err;
            } else if let Some(name) = key.strip_prefix(b"xattr.").filter(|n| !n.is_empty()) {
                if value_length > XATTR_LIMIT {
                    err = ARCHIVE_WARN;
                } else {
                    let Some(p) = ahead(r, value_length).and_then(|p| p.get(..value_length)) else {
                        return fail(
                            a,
                            libc::EINVAL,
                            "Truncated archive detected while reading xattr information",
                            ARCHIVE_FATAL,
                        );
                    };
                    libarchive_xattr(entry, name, p);
                }
                let _ = r.consume(value_length);
                return err;
            }
        }
        // GNU tar uses RHT.security header to store SELinux xattrs
        // SCHILY.xattr.security.selinux == RHT.security.selinux
        else if key == b"RHT.security.selinux" {
            if value_length > XATTR_LIMIT {
                err = fail(
                    a,
                    ARCHIVE_ERRNO_MISC,
                    format!(
                        "Ignoring unreasonably large security.selinux attribute: {value_length} > {XATTR_LIMIT}"
                    ),
                    // TODO: Should this be FAILED instead?
                    ARCHIVE_WARN,
                );
            } else {
                let Some(p) = ahead(r, value_length).and_then(|p| p.get(..value_length)) else {
                    return fail(
                        a,
                        libc::EINVAL,
                        "Truncated archive detected while reading selinux data",
                        ARCHIVE_FATAL,
                    );
                };
                entry.xattr_add(c"security.selinux", p);
            }
            let _ = r.consume(value_length);
            return err;
        }
        // SCHILY.* extensions used by "star" archiver.
        else if let Some(key) = key.strip_prefix(b"SCHILY.").filter(|key| !key.is_empty()) {
            match key {
                b"acl.access" => {
                    return self.schily_acl(r, entry, value_length, TYPE_ACCESS);
                    // TODO: Mark mode as set.
                }
                b"acl.default" => {
                    return self.schily_acl(r, entry, value_length, TYPE_DEFAULT);
                }
                b"acl.ace" => {
                    return self.schily_acl(r, entry, value_length, TYPE_NFS4);
                    // TODO: Mark mode as set.
                }
                b"devmajor" => {
                    let (err, t) = read_number(r, value_length);
                    if err == ARCHIVE_OK {
                        entry.set_rdevmajor(t as Dev);
                    }
                    return err;
                }
                b"devminor" => {
                    let (err, t) = read_number(r, value_length);
                    if err == ARCHIVE_OK {
                        entry.set_rdevminor(t as Dev);
                    }
                    return err;
                }
                b"fflags" => {
                    if value_length < FFLAGS_LIMIT {
                        let Some(p) = ahead(r, value_length).and_then(|p| p.get(..value_length))
                        else {
                            return fail(
                                a,
                                libc::EINVAL,
                                "Truncated archive detected while reading SCHILY.fflags",
                                ARCHIVE_FATAL,
                            );
                        };
                        entry.copy_fflags_text(p);
                    } else {
                        // Overlong fflags field.
                        err = ARCHIVE_WARN;
                    }
                    let _ = r.consume(value_length);
                    return err;
                }
                b"dev" => {
                    let (err, t) = read_number(r, value_length);
                    if err == ARCHIVE_OK {
                        entry.set_dev(t as Dev);
                    }
                    return err;
                }
                b"ino" => {
                    let (err, t) = read_number(r, value_length);
                    if err == ARCHIVE_OK {
                        entry.set_ino(t);
                    }
                    return err;
                }
                b"nlink" => {
                    let (err, t) = read_number(r, value_length);
                    if err == ARCHIVE_OK {
                        entry.set_nlink(t as u32);
                    }
                    return err;
                }
                b"realsize" => {
                    let (err, t) = read_number(r, value_length);
                    if err == ARCHIVE_OK {
                        self.schily_sparse_realsize = t;
                        self.size_fields |= TAR_SIZE_SCHILY_SPARSE_REALSIZE;
                    }
                    return err;
                }
                // TODO: Is there a SCHILY.sparse.size similar to
                // GNU.sparse.size ?
                _ => {
                    if let Some(name) = key.strip_prefix(b"xattr.").filter(|n| !n.is_empty()) {
                        if value_length < XATTR_LIMIT {
                            let Some(p) =
                                ahead(r, value_length).and_then(|p| p.get(..value_length))
                            else {
                                return fail(
                                    a,
                                    libc::EINVAL,
                                    "Truncated archive detected while reading SCHILY.xattr",
                                    ARCHIVE_FATAL,
                                );
                            };
                            if schily_xattr(entry, name, p) {
                                // TODO: Unable to parse xattr.
                                err = ARCHIVE_WARN;
                            }
                        } else {
                            err = fail(
                                a,
                                ARCHIVE_ERRNO_MISC,
                                format!("Unreasonably large xattr: {value_length} > {XATTR_LIMIT}"),
                                ARCHIVE_WARN,
                            );
                        }
                        let _ = r.consume(value_length);
                        return err;
                    }
                }
            }
        }
        // SUN.* extensions from Solaris tar.
        else if key == b"SUN.holesdata" {
            if value_length < SPARSE_MAP_LIMIT {
                let Some(p) = ahead(r, value_length).and_then(|p| p.get(..value_length)) else {
                    return fail(
                        a,
                        libc::EINVAL,
                        "Truncated archive detected while reading SUN.holesdata",
                        ARCHIVE_FATAL,
                    );
                };
                err = self.sun_holesdata(a, p);
                if err < ARCHIVE_OK {
                    a.set_error(ARCHIVE_ERRNO_MISC, Some(b"Parse error: SUN.holesdata"));
                }
            } else {
                err = fail(
                    a,
                    ARCHIVE_ERRNO_MISC,
                    format!("Unreasonably large sparse map: {value_length} > {SPARSE_MAP_LIMIT}"),
                    ARCHIVE_FAILED,
                );
            }
            let _ = r.consume(value_length);
            return err;
        } else if key == b"atime" {
            let (err, sec, n) = read_time(r, value_length, unconsumed);
            if err == ARCHIVE_OK {
                entry.set_atime(sec, n);
            } else {
                a.set_error(ARCHIVE_ERRNO_MISC, Some(b"Ignoring malformed pax atime"));
            }
            return err;
        } else if key == b"ctime" {
            let (err, sec, n) = read_time(r, value_length, unconsumed);
            if err == ARCHIVE_OK {
                entry.set_ctime(sec, n);
            } else {
                a.set_error(ARCHIVE_ERRNO_MISC, Some(b"Ignoring malformed pax ctime"));
            }
            return err;
        }
        // TODO: Publish charset information in entry.
        // TODO: Publish comment in entry.
        else if key == b"gid" {
            let (err, t) = read_number(r, value_length);
            if err == ARCHIVE_OK {
                entry.set_gid(t);
            }
            return err;
        } else if key == b"gname" {
            return self.pax_string(r, value_length, GUNAME_LIMIT, unconsumed, |tar| {
                &mut tar.entry_gname
            });
        } else if key == b"hdrcharset" {
            if value_length < 64 {
                let Some(p) = ahead(r, value_length).and_then(|p| p.get(..value_length)) else {
                    return fail(
                        a,
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        "Truncated tar archive detected while reading hdrcharset attribute",
                        ARCHIVE_FATAL,
                    );
                };
                if p == b"BINARY" {
                    // Binary mode.
                    self.pax_hdrcharset_utf8 = false;
                } else if p == b"ISO-IR 10646 2000 UTF-8" {
                    self.pax_hdrcharset_utf8 = true;
                } else {
                    // TODO: Unrecognized character set.
                    err = ARCHIVE_WARN;
                }
            } else {
                err = fail(
                    a,
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    format!("hdrcharset attribute is unreasonably large ({value_length} bytes)"),
                    ARCHIVE_WARN,
                );
            }
            let _ = r.consume(value_length);
            return err;
        }
        // pax interchange doesn't distinguish hardlink vs. symlink.
        else if key == b"linkpath" {
            return self.pax_string(r, value_length, PATHNAME_LIMIT, unconsumed, |tar| {
                &mut tar.entry_linkpath
            });
        } else if key == b"mtime" {
            let (err, sec, n) = read_time(r, value_length, unconsumed);
            if err == ARCHIVE_OK {
                entry.set_mtime(sec, n);
            } else {
                a.set_error(ARCHIVE_ERRNO_MISC, Some(b"Ignoring malformed pax mtime"));
            }
            return err;
        } else if key == b"path" {
            return self.pax_string(r, value_length, PATHNAME_LIMIT, unconsumed, |tar| {
                &mut tar.entry_pathname
            });
        }
        // POSIX has reserved 'realtime.*'.
        // POSIX has reserved 'security.*'.
        // Someday: if (strcmp(key, "security.acl") == 0) { ... }
        else if key == b"size" {
            // "size" is the size of the data in the entry.
            let (err, t) = read_number(r, value_length);
            if err == ARCHIVE_OK {
                self.pax_size = t;
                self.size_fields |= TAR_SIZE_PAX_SIZE;
            } else if t == i64::MAX {
                // Note: pax_attr_read_number returns INT64_MAX on overflow
                // or < 0.
                self.entry_bytes_remaining = 0;
                return fail(
                    a,
                    ARCHIVE_ERRNO_MISC,
                    "Tar size attribute overflow",
                    ARCHIVE_FATAL,
                );
            }
            return err;
        } else if key == b"uid" {
            let (err, t) = read_number(r, value_length);
            if err == ARCHIVE_OK {
                entry.set_uid(t);
            }
            return err;
        } else if key == b"uname" {
            return self.pax_string(r, value_length, GUNAME_LIMIT, unconsumed, |tar| {
                &mut tar.entry_uname
            });
        }

        // Unrecognized key, just skip the entire value.
        let _ = r.consume(value_length);
        ARCHIVE_OK
    }

    /// A value that is kept for after all the attributes are read. A value
    /// over `limit` is skipped with a warning.
    fn pax_string(
        &mut self,
        r: &mut Reader<'_>,
        value_length: usize,
        limit: usize,
        unconsumed: &mut i64,
        field: fn(&mut Tar) -> &mut Vec<u8>,
    ) -> c_int {
        if value_length > limit {
            *unconsumed += value_length as i64;
            return ARCHIVE_WARN;
        }
        read_bytes_to_string(r, field(self), value_length, unconsumed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_have_optional_fractions() {
        assert_eq!(pax_time(b"12"), (12, 0));
        assert_eq!(pax_time(b"-12.5"), (-12, 500_000_000));
        assert_eq!(pax_time(b"1.123456789999"), (1, 123_456_789));
        assert_eq!(pax_time(b"1.5"), (1, 500_000_000));
        assert_eq!(pax_time(b""), (0, 0));
        assert_eq!(pax_time(b"1.").0, 1);
        assert_eq!(pax_time(b"1x").0, i64::MIN);
        assert_eq!(pax_time(b"1.5x").0, i64::MIN);
        assert_eq!(pax_time(b"99999999999999999999").0, i64::MIN);
    }

    #[test]
    fn url_and_base64_decoding_are_lenient() {
        assert_eq!(url_decode(b"a%20b%zz%4"), b"a b%zz%4");
        assert_eq!(url_decode(b"%41%"), b"A%");
        assert_eq!(url_decode(b"ab\0cd"), b"ab");
        assert_eq!(base64_decode(b"Zm9vYmFy"), b"foobar");
        assert_eq!(base64_decode(b"Zm9v\nYmE="), b"fooba");
        assert_eq!(base64_decode(b"Zm9vYg"), b"foob");
        assert_eq!(base64_decode(b"Z"), b"");
        assert_eq!(base64_decode(b"Zg_x"), b"f");
    }

    #[test]
    fn prologs_are_parsed_or_refused() {
        let ok = parse_prolog(b"20 path=abc\nrest", 100).unwrap();
        assert_eq!(ok, (8, 20, b"path".to_vec()));
        assert!(
            parse_prolog(b"2x path=abc", 100)
                .unwrap_err()
                .contains("malformed")
        );
        assert!(
            parse_prolog(b"20 =abc", 100)
                .unwrap_err()
                .contains("empty name")
        );
        assert!(
            parse_prolog(b"20 path", 100)
                .unwrap_err()
                .contains("overlarge")
        );
        assert!(parse_prolog(b"20", 100).unwrap_err().contains("overlarge"));
        assert!(
            parse_prolog(b"200 a=b", 100)
                .unwrap_err()
                .contains("200 > 100")
        );
        assert!(
            parse_prolog(b"999999999 a=b", 1 << 30)
                .unwrap_err()
                .contains("size >")
        );
    }

    #[test]
    fn global_headers_refuse_attributes_that_would_matter() {
        assert!(pax_global_attribute_unsupported(b"path"));
        assert!(pax_global_attribute_unsupported(b"SCHILY.xattr.user.x"));
        assert!(!pax_global_attribute_unsupported(b"SCHILY.xattr."));
        assert!(!pax_global_attribute_unsupported(b"SCHILY.unknown"));
    }
}
