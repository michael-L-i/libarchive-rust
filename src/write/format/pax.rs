/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2010-2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_write_set_format_pax.c.
use crate::acl::{
    STYLE_COMPACT, STYLE_EXTRA_ID, STYLE_SEPARATOR_COMMA, TYPE_ACCESS, TYPE_DEFAULT, TYPE_NFS4,
};
use crate::archive::*;
use crate::entry::{AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFREG, Entry};
use crate::read::ARCHIVE_ERRNO_FILE_FORMAT;
use crate::string::{StringConv, conversion_to_charset, strncpy_l};
use crate::util::Error;
use crate::write::format::ustar::{add_trailing_slash, format_header_ustar, translate_error};
use crate::write::{Format, Sink, unsupported, zeros};
use std::collections::VecDeque;
use std::ffi::{CStr, c_int};
use std::sync::{Arc, PoisonError};

const FORMAT_TAR_PAX_INTERCHANGE: c_int = 0x30002;
const FORMAT_TAR_PAX_RESTRICTED: c_int = 0x30003;
const PAX_MAX_ALIGN: usize = 1 << 20;
const WRITE_SCHILY_XATTR: u32 = 1 << 0;
const WRITE_LIBARCHIVE_XATTR: u32 = 1 << 1;
/// Technically, the mtime field in the ustar header can support 33 bits.
/// We are using all of them to keep tar/test/test_option_C_mtree.c simple
/// and passing after 2038.
const USTAR_MAX_MTIME: i64 = 0x1ffffffff;
const AE_SYMLINK_TYPE_FILE: c_int = 1;
const AE_SYMLINK_TYPE_DIRECTORY: c_int = 2;

struct SparseBlock {
    is_hole: bool,
    offset: u64,
    remaining: u64,
}

pub struct Pax {
    restricted: bool,
    entry_bytes_remaining: u64,
    entry_padding: u64,
    pax_header: Vec<u8>,
    sparse_map: Vec<u8>,
    sparse_map_padding: u64,
    sparse_list: VecDeque<SparseBlock>,
    sconv_utf8: Option<Arc<StringConv>>,
    opt_binary: bool,
    /// If non-zero, align regular file data to this many bytes in the
    /// uncompressed stream (power of two, multiple of 512).
    align: usize,
    flags: u32,
}

impl Pax {
    /// The 'pax' format, or with `restricted` the 'restricted pax' format.
    /// That is the same as normal 'pax', but tries to suppress the pax
    /// header whenever possible. This is the default for bsdtar, for
    /// instance.
    pub fn new(restricted: bool) -> Self {
        Self {
            restricted,
            entry_bytes_remaining: 0,
            entry_padding: 0,
            pax_header: Vec::new(),
            sparse_map: Vec::new(),
            sparse_map_padding: 0,
            sparse_list: VecDeque::new(),
            sconv_utf8: None,
            opt_binary: false,
            align: 0,
            flags: WRITE_LIBARCHIVE_XATTR | WRITE_SCHILY_XATTR,
        }
    }

    fn sparse_list_add(&mut self, offset: u64, length: u64) {
        let last_offset = self
            .sparse_list
            .back()
            .map_or(0, |b| b.offset.wrapping_add(b.remaining));
        if last_offset < offset {
            // Add a hole block.
            self.sparse_list.push_back(SparseBlock {
                is_hole: true,
                offset: last_offset,
                remaining: offset - last_offset,
            });
        }
        // Add data block.
        self.sparse_list.push_back(SparseBlock {
            is_hole: false,
            offset,
            remaining: length,
        });
    }

    fn header_xattr(&mut self, encoded_name: &[u8], value: &[u8]) {
        if self.flags & WRITE_LIBARCHIVE_XATTR != 0 {
            let key = [b"LIBARCHIVE.xattr.", encoded_name].concat();
            add_pax_attr(&mut self.pax_header, &key, &base64_encode(value));
        }
        if self.flags & WRITE_SCHILY_XATTR != 0 {
            let key = [b"SCHILY.xattr.", encoded_name].concat();
            add_pax_attr(&mut self.pax_header, &key, value);
        }
    }

    fn header_xattrs(&mut self, entry: &mut Entry) -> Result<(), Error> {
        let mut encoded_name = Vec::new();
        for _ in 0..entry.xattr_reset() {
            let (_, xattr) = entry.xattr_next();
            let Some((name, value)) = xattr.map(|(n, v)| (url_encode(n.to_bytes()), v.to_vec()))
            else {
                break;
            };
            // Convert narrow-character to UTF-8.
            if strncpy_l(&mut encoded_name, &name, self.sconv_utf8.as_deref()).is_err() {
                // Upstream takes any conversion failure for a failed
                // allocation, but the URL-encoded name is all ASCII.
                return Err(Error::fatal(libc::ENOMEM, "Can't allocate memory"));
            }
            self.header_xattr(&encoded_name, &value);
        }
        Ok(())
    }

    /// Add ACL to pax header
    fn add_pax_acl(&mut self, a: &Base, entry: &mut Entry, flags: c_int) -> c_int {
        let acl_types = entry.acl.types();
        let attr: &[u8] = if acl_types & TYPE_NFS4 != 0 {
            b"SCHILY.acl.ace"
        } else if flags & TYPE_ACCESS != 0 {
            b"SCHILY.acl.access"
        } else if flags & TYPE_DEFAULT != 0 {
            b"SCHILY.acl.default"
        } else {
            return ARCHIVE_FATAL;
        };
        let Some(p) = entry.acl.format_l(flags, self.sconv_utf8.as_deref()) else {
            let msg = [b"Can't translate  ", attr, b"  to UTF-8"].concat();
            a.set_error(ARCHIVE_ERRNO_FILE_FORMAT, Some(&msg));
            return ARCHIVE_WARN;
        };
        if !p.is_empty() {
            add_pax_attr(&mut self.pax_header, attr, &p);
        }
        ARCHIVE_OK
    }
}

/// Note: This code assumes that 'nanos' has the same sign as 'sec', which
/// implies that sec=-1, nanos=200000000 represents -1.2 seconds and not -0.8
/// seconds. This is a pretty pedantic point, as we're unlikely to encounter
/// many real files created before Jan 1, 1970, much less ones with
/// timestamps recorded to sub-second resolution.
fn add_pax_attr_time(out: &mut Vec<u8>, key: &[u8], sec: i64, mut nanos: u64) {
    let mut t = sec.to_string().into_bytes();
    // Skip trailing zeros in the fractional part.
    let (mut digit, mut i) = (0, 10);
    while i > 0 && digit == 0 {
        digit = nanos % 10;
        nanos /= 10;
        i -= 1;
    }
    // Only format the fraction if it's non-zero.
    if i > 0 {
        let mut fraction = Vec::new();
        while i > 0 {
            fraction.push(b'0' + digit as u8);
            digit = nanos % 10;
            nanos /= 10;
            i -= 1;
        }
        fraction.push(b'.');
        t.extend(fraction.iter().rev());
    }
    add_pax_attr(out, key, &t);
}

fn add_pax_attr_int(out: &mut Vec<u8>, key: &[u8], value: i64) {
    add_pax_attr(out, key, value.to_string().as_bytes());
}

/// Add a key/value attribute to the pax header. This function handles the
/// length field and various other syntactic requirements.
fn add_pax_attr(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    // PAX attributes have the following layout:
    //     <len> <space> <key> <=> <value> <nl>
    let len = 1 + key.len() + 1 + value.len() + 1;
    // The <len> field includes the length of the <len> field, so computing
    // the correct length is tricky. I start by counting the number of
    // base-10 digits in 'len' and computing the next higher power of 10.
    let (mut digits, mut next_ten, mut i) = (0, 1usize, len);
    while i > 0 {
        i /= 10;
        digits += 1;
        next_ten = next_ten.saturating_mul(10);
    }
    // For example, if string without the length field is 99 chars, then
    // adding the 2 digit length "99" will force the total length past 100,
    // requiring an extra digit. The next statement adjusts for this effect.
    if len + digits >= next_ten {
        digits += 1;
    }
    // Now, we have the right length so we can build the line.
    out.extend((len + digits).to_string().as_bytes());
    out.push(b' ');
    out.extend(key);
    out.push(b'=');
    out.extend(value);
    out.push(b'\n');
}

/// Append the length/key prefix of an ignorable "LIBARCHIVE.pad" record
/// whose full length rounds the pax body up to 'target_len'. Return the
/// number of value/newline bytes that must be emitted after the in-memory
/// header.
fn add_pax_padding_prefix(out: &mut Vec<u8>, cur_len: usize, target_len: usize) -> usize {
    const KEY: &[u8] = b"LIBARCHIVE.pad";
    if target_len <= cur_len {
        return 0;
    }
    let record_len = target_len - cur_len;
    let length = record_len.to_string();
    let prefix_len = length.len() + 1 + KEY.len() + 1;
    if record_len <= prefix_len {
        return 0; // not enough room; leave unaligned
    }
    out.extend(length.as_bytes());
    out.push(b' ');
    out.extend(KEY);
    out.push(b'=');
    record_len - prefix_len
}

/// Emit a deferred pax padding value followed by its record newline.
fn write_pax_padding(sink: &mut dyn Sink, mut length: usize) -> Result<(), Error> {
    let padding = [b'X'; 1024];
    if length == 0 {
        return Ok(());
    }
    while length > 1 {
        let to_write = (length - 1).min(padding.len());
        sink.write(&padding[..to_write])?;
        length -= to_write;
    }
    sink.write(b"\n")
}

/// For the pax "align" option: given entry offset 'off' (a multiple of 512)
/// and current extended-header body length 'l0', return the body length
/// needed so the file data (after the x header) lands on 'align', or 'l0'
/// if already aligned.
fn pax_align_body_len(off: u64, l0: usize, align: usize) -> usize {
    let amask = align as u64 - 1;
    let l0 = l0 as u64;
    // Data offset with no extra padding (no x header when l0 == 0).
    let natural_off = if l0 == 0 {
        off.wrapping_add(512)
    } else {
        off.wrapping_add(1024).wrapping_add((l0 + 511) & !511)
    };
    if natural_off & amask == 0 {
        return l0 as usize;
    }
    // Grow the body (past l0 plus pad-record room) to land data on align.
    let base = off.wrapping_add(1024);
    let end = base.wrapping_add(l0 + 64 + amask) & !amask;
    end.wrapping_sub(base) as usize
}

/// A conversion of `entry`'s text field, retried in binary mode (no
/// conversion) when it fails: the text, and whether the first try worked.
fn binary_fallback(
    sconv: Option<&StringConv>,
    entry: &mut Entry,
    get: impl for<'e> Fn(&'e mut Entry, Option<&StringConv>) -> (Option<&'e [u8]>, bool),
) -> (Option<Vec<u8>>, bool) {
    let (p, ok) = get(entry, sconv);
    if ok {
        (p.map(<[u8]>::to_vec), true)
    } else {
        (get(entry, None).0.map(<[u8]>::to_vec), false)
    }
}

impl Format for Pax {
    fn code(&self) -> c_int {
        if self.restricted {
            FORMAT_TAR_PAX_RESTRICTED
        } else {
            FORMAT_TAR_PAX_INTERCHANGE
        }
    }
    fn name(&self) -> &'static CStr {
        if self.restricted {
            c"restricted POSIX pax interchange"
        } else {
            c"POSIX pax interchange"
        }
    }
    fn module(&self) -> &'static [u8] {
        b"pax"
    }
    fn options(&mut self, a: &Base, key: &[u8], val: Option<&[u8]>) -> Result<c_int, Error> {
        let failed = |msg: &str| Err(Error::new(ARCHIVE_FAILED, ARCHIVE_ERRNO_MISC, msg));
        let val = val.filter(|v| !v.is_empty());
        match key {
            // The character-set we can use are defined in IEEE Std
            // 1003.1-2001
            b"hdrcharset" => match val {
                None => failed("pax: hdrcharset option needs a character-set name"),
                Some(b"BINARY" | b"binary") => {
                    // Specify binary mode. We will not convert filenames,
                    // uname and gname to any charsets.
                    self.opt_binary = true;
                    Ok(ARCHIVE_OK)
                }
                Some(b"UTF-8") => {
                    // Specify UTF-8 character-set to be used for
                    // filenames. This is almost the test that running
                    // platform supports the string conversion. Especially
                    // libarchive_test needs this trick for its test.
                    let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
                    let r = conversion_to_charset(Some(&mut cache), b"UTF-8", false);
                    self.sconv_utf8 = r.as_ref().ok().cloned();
                    r.map(|_| ARCHIVE_OK)
                        .map_err(|e| Error::fatal(e.errno, e.message))
                }
                Some(_) => failed("pax: invalid charset name"),
            },
            b"xattrheader" => {
                match val {
                    None => return failed("pax: xattrheader requires a value"),
                    Some(b"ALL" | b"all") => {
                        self.flags |= WRITE_LIBARCHIVE_XATTR | WRITE_SCHILY_XATTR;
                    }
                    Some(b"SCHILY" | b"schily") => {
                        self.flags |= WRITE_SCHILY_XATTR;
                        self.flags &= !WRITE_LIBARCHIVE_XATTR;
                    }
                    Some(b"LIBARCHIVE" | b"libarchive") => {
                        self.flags |= WRITE_LIBARCHIVE_XATTR;
                        self.flags &= !WRITE_SCHILY_XATTR;
                    }
                    Some(_) => return failed("pax: invalid xattr header name"),
                }
                Ok(ARCHIVE_OK)
            }
            b"align" => {
                let Some(val) = val else {
                    return failed("pax: align option needs a value");
                };
                match strtoul(val) {
                    Some(v)
                        if v != 0
                            && v % 512 == 0
                            && v.is_power_of_two()
                            && v <= PAX_MAX_ALIGN as u64 =>
                    {
                        self.align = v as usize;
                        Ok(ARCHIVE_OK)
                    }
                    _ => failed(
                        "pax: align must be a power of two, a multiple of 512, and no larger than 1 MiB",
                    ),
                }
            }
            // Note: The "warn" return is just to inform the options
            // supervisor that we didn't handle it. It will generate a
            // suitable error if no one used this option.
            _ => Ok(ARCHIVE_WARN),
        }
    }
    fn header(
        &mut self,
        a: &Base,
        entry_original: &mut Entry,
        sink: &mut dyn Sink,
    ) -> Result<c_int, Error> {
        let mut ret = ARCHIVE_OK;
        let mut need_extension = false;

        // Sanity check.
        if entry_original.pathname().is_none() {
            return Err(Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_MISC,
                "Can't record entry in tar file without pathname",
            ));
        }

        // Choose a header encoding.
        let mut sconv = if self.opt_binary {
            None // Binary mode.
        } else {
            // Header encoding is UTF-8.
            if self.sconv_utf8.is_none() {
                // Initialize the string conversion object we must need
                let mut cache = a.conv.lock().unwrap_or_else(PoisonError::into_inner);
                let sc = conversion_to_charset(Some(&mut cache), b"UTF-8", true)
                    .map_err(|e| Error::new(ARCHIVE_FAILED, e.errno, e.message))?;
                self.sconv_utf8 = Some(sc);
            }
            self.sconv_utf8.clone()
        };

        let (mut hardlink, ok) =
            binary_fallback(sconv.as_deref(), entry_original, Entry::hardlink_l);
        if !ok {
            translate_error(a, "linkname", hardlink.as_deref(), sconv.as_deref());
            ret = ARCHIVE_WARN;
            sconv = None; // The header charset switches to binary mode.
        }

        // Make sure this is a type of entry that we can handle here
        if hardlink.is_none() {
            match entry_original.filetype() {
                AE_IFBLK | AE_IFCHR | AE_IFIFO | AE_IFLNK | AE_IFREG => {}
                // Ensure a trailing '/'. Modify the original entry so the
                // client sees the change.
                AE_IFDIR => add_trailing_slash(entry_original),
                // AE_IFSOCK and unknown
                _ => return Err(unsupported(entry_original, b"pax")),
            }
        }

        // If Mac OS metadata blob is here, recurse to write that as a
        // separate entry. This is really a pretty poor design: In
        // particular, it doubles the overhead for long filenames.
        // TODO: Help Apple folks design something better and figure out
        // how to transition from this legacy format.
        //
        // Note that this code is present on every platform; clients on
        // non-Mac are unlikely to ever provide this data, but applications
        // that copy entries from one archive to another should not lose
        // data just because the local filesystem can't store it.
        if let Some(mac_metadata) = entry_original.mac_metadata().map(<[u8]>::to_vec) {
            let mut name = entry_original
                .pathname()
                .map_or(Vec::new(), |p| p.to_bytes().to_vec());
            // Find last '/'; strip trailing '/' characters
            let mut bname = name.iter().rposition(|&b| b == b'/');
            while let Some(i) = bname.filter(|&i| i + 1 == name.len()) {
                name.truncate(i);
                bname = name.iter().rposition(|&b| b == b'/');
            }
            let at = bname.map_or(0, |i| i + 1);
            name.splice(at..at, *b"._");
            let mut extra = Entry::new(Some(a.conv.clone()));
            extra.set_pathname(&name);
            extra.set_size(mac_metadata.len() as i64);
            extra.set_filetype(AE_IFREG.into());
            extra.set_perm(entry_original.perm());
            extra.set_mtime(entry_original.mtime(), entry_original.mtime_nsec());
            extra.set_gid(entry_original.gid());
            if let Some(g) = entry_original.gname() {
                extra.set_gname(g.to_bytes());
            }
            extra.set_uid(entry_original.uid());
            if let Some(u) = entry_original.uname() {
                extra.set_uname(u.to_bytes());
            }
            // Recurse to write the special copyfile entry.
            let r = self.header(a, &mut extra, sink)?;
            if r < ARCHIVE_WARN {
                return Ok(r);
            }
            ret = ret.min(r);
            self.data(&mac_metadata, sink)?;
            self.finish_entry(sink)?;
        }

        // Copy entry so we can modify it as needed.
        let mut entry_main = entry_original.clone_entry();
        self.pax_header.clear(); // Blank our work area.
        self.sparse_map.clear();
        let mut sparse_total: u64 = 0;
        self.sparse_list.clear();

        let mut sparse_count = if hardlink.is_none() && entry_main.filetype() == AE_IFREG {
            entry_main.sparse_reset()
        } else {
            0
        };
        if sparse_count > 0 {
            // Get the last entry of sparse block.
            let mut last_offset = 0;
            loop {
                let (r, offset, length) = entry_main.sparse_next();
                if r != ARCHIVE_OK {
                    break;
                }
                last_offset = offset + length;
            }
            // If the last sparse block does not reach the end of file, We
            // have to add a empty sparse block as the last entry to manage
            // storing file data.
            if last_offset < entry_main.size() {
                entry_main.sparse_add(entry_main.size(), 0);
            }
            sparse_count = entry_main.sparse_reset();
        }

        // First, check the name fields and see if any of them require
        // binary coding. If any of them does, then all of them do.
        let (path, ok) = binary_fallback(sconv.as_deref(), &mut entry_main, Entry::pathname_l);
        let mut path = path.unwrap_or_default();
        if !ok {
            translate_error(a, "pathname", Some(&path), sconv.as_deref());
            ret = ARCHIVE_WARN;
            sconv = None; // The header charset switches to binary mode.
        }
        let (mut uname, ok) = binary_fallback(sconv.as_deref(), &mut entry_main, Entry::uname_l);
        if !ok {
            translate_error(a, "uname", uname.as_deref(), sconv.as_deref());
            ret = ARCHIVE_WARN;
            sconv = None; // The header charset switches to binary mode.
        }
        let (mut gname, ok) = binary_fallback(sconv.as_deref(), &mut entry_main, Entry::gname_l);
        if !ok {
            translate_error(a, "gname", gname.as_deref(), sconv.as_deref());
            ret = ARCHIVE_WARN;
            sconv = None; // The header charset switches to binary mode.
        }
        let mut linkpath = hardlink.clone();
        if linkpath.is_none() {
            let ok;
            (linkpath, ok) = binary_fallback(sconv.as_deref(), &mut entry_main, Entry::symlink_l);
            if !ok {
                translate_error(a, "linkname", linkpath.as_deref(), sconv.as_deref());
                ret = ARCHIVE_WARN;
                sconv = None;
            }
        }

        // If any string conversions failed, get all attributes in
        // binary-mode.
        if sconv.is_none() && !self.opt_binary {
            if hardlink.is_some() {
                hardlink = entry_main.hardlink_l(None).0.map(<[u8]>::to_vec);
                linkpath = hardlink.clone();
            }
            path = entry_main.pathname_l(None).0.unwrap_or_default().to_vec();
            uname = entry_main.uname_l(None).0.map(<[u8]>::to_vec);
            gname = entry_main.gname_l(None).0.map(<[u8]>::to_vec);
        }

        // Store the header encoding first, to be nice to readers.
        if sconv.is_none() {
            add_pax_attr(&mut self.pax_header, b"hdrcharset", b"BINARY");
        }

        // If name is too long, or has non-ASCII characters, add 'path' to
        // pax extended attrs. (Note that an unconvertible name must have
        // non-ASCII characters.)
        let mut long_path = has_non_ascii(&path);
        if !long_path && path.len() > 100 {
            // We have an all-ASCII path; we'd like to just store it in the
            // ustar header if it will fit. Yes, this duplicates some of the
            // logic in archive_write_set_format_ustar.c
            let slash = |from: usize| {
                path[from..]
                    .iter()
                    .position(|&b| b == b'/')
                    .map(|i| from + i)
            };
            // Find largest suffix that will fit.
            let mut suffix = slash(path.len() - 100 - 1);
            // Don't attempt an empty prefix.
            if suffix == Some(0) {
                suffix = slash(1);
            }
            // We can put it in the ustar header if it's all ASCII and it's
            // either <= 100 characters or can be split at a '/' into a
            // prefix <= 155 chars and a suffix <= 100 chars. (Note the
            // search above finds nothing exactly when the path can't be
            // split.)
            long_path = suffix.is_none_or(|s| s + 1 == path.len() || s > 155);
        }
        if long_path {
            add_pax_attr(&mut self.pax_header, b"path", &path);
            entry_main.set_pathname(&build_ustar_entry_name(&path, None));
            need_extension = true;
        }

        if let Some(linkpath) = &linkpath {
            // If link name is too long or has non-ASCII characters, add
            // 'linkpath' to pax extended attrs.
            if linkpath.len() > 100 || has_non_ascii(linkpath) {
                add_pax_attr(&mut self.pax_header, b"linkpath", linkpath);
                if linkpath.len() > 100 {
                    if hardlink.is_some() {
                        entry_main.set_hardlink(b"././@LongHardLink");
                    } else {
                        entry_main.set_symlink(b"././@LongSymLink");
                    }
                } else if hardlink.is_some() {
                    // Otherwise, has non-ASCII characters; update the paths
                    // to however they got decoded above
                    entry_main.set_hardlink(linkpath);
                } else {
                    entry_main.set_symlink(linkpath);
                }
                need_extension = true;
            }
        }

        // Save a pathname since it will be renamed if `entry_main` has
        // sparse blocks.
        let entry_name = entry_main
            .pathname()
            .map_or(Vec::new(), |p| p.to_bytes().to_vec());

        // If file size is too large, we need pax extended attrs.
        if entry_main.size() >= 1 << 33 {
            need_extension = true;
        }

        // If numeric GID is too large, add 'gid' to pax extended attrs.
        if entry_main.gid() >= 1 << 18 {
            add_pax_attr_int(&mut self.pax_header, b"gid", entry_main.gid());
            need_extension = true;
        }

        // If group name is too large or has non-ASCII characters, add
        // 'gname' to pax extended attrs.
        if let Some(gname) = &gname
            && (gname.len() > 31 || has_non_ascii(gname))
        {
            add_pax_attr(&mut self.pax_header, b"gname", gname);
            need_extension = true;
        }

        // If numeric UID is too large, add 'uid' to pax extended attrs.
        if entry_main.uid() >= 1 << 18 {
            add_pax_attr_int(&mut self.pax_header, b"uid", entry_main.uid());
            need_extension = true;
        }

        // Add 'uname' to pax extended attrs if necessary.
        if let Some(uname) = &uname
            && (uname.len() > 31 || has_non_ascii(uname))
        {
            add_pax_attr(&mut self.pax_header, b"uname", uname);
            need_extension = true;
        }

        // POSIX/SUSv3 doesn't provide a standard key for large device
        // numbers. I use the same keys here that Joerg Schilling used for
        // 'star.' (Which, somewhat confusingly, are called "devXXX" even
        // though they code "rdev" values.) No doubt, other implementations
        // use other keys. Note that there's no reason we can't write the
        // same information into a number of different keys.
        //
        // Of course, this is only needed for block or char device entries.
        if matches!(entry_main.filetype(), AE_IFBLK | AE_IFCHR) {
            // Non-strict formatting below means we don't have to truncate
            // here. Not truncating improves the chance that some more
            // modern tar archivers (such as GNU tar 1.13) can restore the
            // full value even if they don't understand the pax extended
            // attributes.
            let rdevmajor = entry_main.rdevmajor() as c_int;
            let rdevminor = entry_main.rdevminor() as c_int;
            if rdevmajor >= 1 << 18 {
                let v = i64::from(rdevmajor);
                add_pax_attr_int(&mut self.pax_header, b"SCHILY.devmajor", v);
                need_extension = true;
            }
            if rdevminor >= 1 << 18 {
                let v = i64::from(rdevminor);
                add_pax_attr_int(&mut self.pax_header, b"SCHILY.devminor", v);
                need_extension = true;
            }
        }

        // Yes, this check is duplicated just below; this helps to avoid
        // writing an mtime attribute just to handle a high-resolution
        // timestamp in "restricted pax" mode.
        let mtime = entry_main.mtime();
        if !need_extension && !(0..USTAR_MAX_MTIME).contains(&mtime) {
            need_extension = true;
        }

        // I use a star-compatible file flag attribute.
        let fflags = entry_main
            .fflags_text()
            .map(|p| p.to_bytes().to_vec())
            .filter(|p| !p.is_empty());
        if !need_extension && fflags.is_some() {
            need_extension = true;
        }

        // If there are extended attributes, we need an extension
        if !need_extension && entry_original.xattr_count() > 0 {
            need_extension = true;
        }

        // If there are sparse info, we need an extension
        if !need_extension && sparse_count > 0 {
            need_extension = true;
        }

        let acl_types = entry_original.acl.types();

        // If there are any ACL entries, we need an extension
        if !need_extension && acl_types != 0 {
            need_extension = true;
        }

        // If the symlink type is defined, we need an extension
        if !need_extension && entry_main.symlink_type() > 0 {
            need_extension = true;
        }

        // Libarchive used to include these in extended headers for
        // restricted pax format, but that confused people who expected
        // ustar-like time semantics. So now we only include them in full
        // pax format.
        if !self.restricted {
            let e = &entry_main;
            if e.ctime() != 0 || e.ctime_nsec() != 0 {
                add_pax_attr_time(
                    &mut self.pax_header,
                    b"ctime",
                    e.ctime(),
                    e.ctime_nsec() as u64,
                );
            }
            if e.atime() != 0 || e.atime_nsec() != 0 {
                add_pax_attr_time(
                    &mut self.pax_header,
                    b"atime",
                    e.atime(),
                    e.atime_nsec() as u64,
                );
            }
            // Store birth/creationtime only if it's earlier than mtime
            if e.birthtime_is_set() != 0 && e.birthtime() < mtime {
                let (sec, nsec) = (e.birthtime(), e.birthtime_nsec() as u64);
                add_pax_attr_time(&mut self.pax_header, b"LIBARCHIVE.creationtime", sec, nsec);
            }
        }

        // The following items are handled differently in "pax restricted"
        // format. In particular, in "pax restricted" format they won't be
        // added unless need_extension is already set (we're already
        // generating an extended header, so may as well include these).
        if !self.restricted || need_extension {
            let nsec = entry_main.mtime_nsec();
            if !(0..USTAR_MAX_MTIME).contains(&mtime) || nsec != 0 {
                add_pax_attr_time(&mut self.pax_header, b"mtime", mtime, nsec as u64);
            }

            // I use a star-compatible file flag attribute.
            if let Some(p) = &fflags {
                add_pax_attr(&mut self.pax_header, b"SCHILY.fflags", p);
            }

            // I use star-compatible ACL attributes.
            let acls = [
                (TYPE_NFS4, STYLE_COMPACT),
                (TYPE_ACCESS, TYPE_ACCESS),
                (TYPE_DEFAULT, TYPE_DEFAULT),
            ];
            for (ty, flags) in acls {
                if acl_types & ty != 0 {
                    let flags = flags | STYLE_EXTRA_ID | STYLE_SEPARATOR_COMMA;
                    ret = self.add_pax_acl(a, entry_original, flags);
                    if ret == ARCHIVE_FATAL {
                        return Err(Error::silent(ARCHIVE_FATAL));
                    }
                }
            }

            // We use GNU-tar-compatible sparse attributes.
            if sparse_count > 0 {
                add_pax_attr_int(&mut self.pax_header, b"GNU.sparse.major", 1);
                add_pax_attr_int(&mut self.pax_header, b"GNU.sparse.minor", 0);
                // Make sure to store the original path, since truncation to
                // ustar limit happened already.
                add_pax_attr(&mut self.pax_header, b"GNU.sparse.name", &path);
                let realsize = entry_main.size();
                add_pax_attr_int(&mut self.pax_header, b"GNU.sparse.realsize", realsize);

                // Rename the file name which will be used for ustar header
                // to a special name, which GNU PAX Format 1.0 requires
                entry_main.set_pathname(&build_gnu_sparse_name(&entry_name));

                // - Make a sparse map, which will precede a file data.
                // - Get the total size of available data of sparse.
                self.sparse_map
                    .extend(format!("{sparse_count}\n").as_bytes());
                loop {
                    let (r, soffset, slength) = entry_main.sparse_next();
                    if r != ARCHIVE_OK {
                        break;
                    }
                    self.sparse_map
                        .extend(format!("{soffset}\n{slength}\n").as_bytes());
                    sparse_total = sparse_total.wrapping_add(slength as u64);
                    self.sparse_list_add(soffset as u64, slength as u64);
                }
            }

            // Store extended attributes
            self.header_xattrs(entry_original)?;

            // Store extended symlink information
            match entry_main.symlink_type() {
                AE_SYMLINK_TYPE_FILE => {
                    add_pax_attr(&mut self.pax_header, b"LIBARCHIVE.symlinktype", b"file");
                }
                AE_SYMLINK_TYPE_DIRECTORY => {
                    add_pax_attr(&mut self.pax_header, b"LIBARCHIVE.symlinktype", b"dir");
                }
                _ => {}
            }
        }

        // Only regular files have data.
        if entry_main.filetype() != AE_IFREG {
            entry_main.set_size(0);
        }

        // XXX Full pax interchange format does permit a hardlink entry to
        // have data associated with it. I'm not supporting that here
        // because the client expects me to tell them whether or not this
        // format expects data for hardlinks. If I don't check here, then
        // every pax archive will end up with duplicated data for
        // hardlinks. Someday, there may be need to select this behavior,
        // in which case the following will need to be revisited. XXX
        if hardlink.is_some() {
            entry_main.set_size(0);
        }

        // Save a real file size.
        let real_size = entry_main.size();

        // Overwrite a file size by the total size of sparse blocks and the
        // size of sparse map info. That file size is the length of the
        // data, which we will exactly store into an archive file.
        if !self.sparse_map.is_empty() {
            let mapsize = self.sparse_map.len() as u64;
            self.sparse_map_padding = 0x1ff & mapsize.wrapping_neg();
            let size = mapsize + self.sparse_map_padding + sparse_total;
            entry_main.set_size(size as i64);
        }

        // If file size is too large, add 'size' to pax extended attrs.
        if entry_main.size() >= 1 << 33 {
            add_pax_attr_int(&mut self.pax_header, b"size", entry_main.size());
        }

        // Format 'ustar' header for main entry.
        //
        // The trouble with file size: If the reader can't understand the
        // file size, they may not be able to locate the next entry and the
        // rest of the archive is toast. Pax-compliant readers are supposed
        // to ignore the file size in the main header, so the question
        // becomes how to maximize portability for readers that don't
        // support pax attribute extensions. For maximum compatibility, I
        // permit numeric extensions in the main header so that the file
        // size stored will always be correct, even if it's in a format
        // that only some implementations understand. The technique used
        // here is:
        //
        //  a) If possible, follow the standard exactly. This handles files
        //  up to 8 gigabytes minus 1.
        //
        //  b) If that fails, try octal but omit the field terminator. That
        //  handles files up to 64 gigabytes minus 1.
        //
        //  c) Otherwise, use base-256 extensions. That handles files up to
        //  2^63 in this implementation, with the potential to go up to
        //  2^94. That should hold us for a while. ;-)
        //
        // The non-strict formatter uses similar logic for other numeric
        // fields, though they're less critical.
        let mut ustarbuff = [0u8; 512];
        format_header_ustar(a, &mut ustarbuff, &mut entry_main, None, false, None);

        // Pad the extended header so contiguous file data starts on a
        // pax->align boundary (for reflinking); short and sparse files are
        // left alone.
        let mut pax_header_padding = 0;
        if self.align > 0
            && entry_main.filetype() == AE_IFREG
            && hardlink.is_none()
            && sparse_count == 0
            && real_size as u64 >= self.align as u64
        {
            let l0 = self.pax_header.len();
            let needed = pax_align_body_len(sink.position(), l0, self.align);
            if needed != l0 {
                pax_header_padding = add_pax_padding_prefix(&mut self.pax_header, l0, needed);
            }
        }

        // If we built any extended attributes, write that entry first.
        if !self.pax_header.is_empty() {
            let mut pax_attr_entry = Entry::new(Some(a.conv.clone()));
            pax_attr_entry.set_pathname(&build_pax_attribute_name(&entry_name));
            let size = (self.pax_header.len() + pax_header_padding) as u64;
            pax_attr_entry.set_size(size as i64);

            // Copy uid/gid (but clip to ustar limits).
            pax_attr_entry.set_uid(entry_main.uid().min((1 << 18) - 1));
            pax_attr_entry.set_gid(entry_main.gid().min((1 << 18) - 1));

            // Copy mode over (but not setuid/setgid bits)
            pax_attr_entry.set_mode(entry_main.mode() & !0o7000);

            // Copy uname/gname.
            if let Some(u) = entry_main.uname() {
                pax_attr_entry.set_uname(u.to_bytes());
            }
            if let Some(g) = entry_main.gname() {
                pax_attr_entry.set_gname(g.to_bytes());
            }

            // Copy mtime, but clip to ustar limits.
            pax_attr_entry.set_mtime(mtime.clamp(0, USTAR_MAX_MTIME), 0);

            let mut paxbuff = [0u8; 512];
            let r =
                format_header_ustar(a, &mut paxbuff, &mut pax_attr_entry, Some(b'x'), true, None);
            // Note that the 'x' header shouldn't ever fail to format
            if r < ARCHIVE_WARN {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_MISC,
                    "archive_write_pax_header: 'x' header failed?!  This can't happen",
                ));
            }
            ret = ret.min(r);
            // If a write fails, we're pretty much toast.
            let fatal = |e: Error| Error {
                code: ARCHIVE_FATAL,
                ..e
            };
            sink.write(&paxbuff).map_err(fatal)?;
            self.entry_padding = 0x1ff & size.wrapping_neg();
            sink.write(&self.pax_header).map_err(fatal)?;
            write_pax_padding(sink, pax_header_padding).map_err(fatal)?;
            // Pad out the end of the entry.
            zeros(sink, self.entry_padding).map_err(fatal)?;
            self.entry_bytes_remaining = 0;
            self.entry_padding = 0;
        }

        // Write the header for main entry.
        sink.write(&ustarbuff)?;

        // Inform the client of the on-disk size we're using, so they can
        // avoid unnecessarily writing a body for something that we're just
        // going to ignore.
        entry_original.set_size(real_size);
        if self.sparse_list.is_empty() && real_size > 0 {
            // This is not a sparse file but we handle its data as a sparse
            // block.
            self.sparse_list_add(0, real_size as u64);
            sparse_total = real_size as u64;
        }
        self.entry_padding = 0x1ff & sparse_total.wrapping_neg();
        Ok(ret)
    }
    fn data(&mut self, buff: &[u8], sink: &mut dyn Sink) -> Result<usize, Error> {
        // According to GNU PAX format 1.0, write a sparse map before the
        // body.
        if !self.sparse_map.is_empty() {
            sink.write(&self.sparse_map)?;
            zeros(sink, self.sparse_map_padding)?;
            self.sparse_map.clear();
        }
        let mut total = 0;
        while total < buff.len() {
            while self.sparse_list.front().is_some_and(|b| b.remaining == 0) {
                self.sparse_list.pop_front();
            }
            let Some(block) = self.sparse_list.front_mut() else {
                return Ok(total);
            };
            let ws = ((buff.len() - total) as u64).min(block.remaining) as usize;
            block.remaining -= ws as u64;
            let p = &buff[total..total + ws];
            total += ws;
            // A hole is not written.
            if !block.is_hole {
                sink.write(p)?;
            }
        }
        Ok(total)
    }
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        let mut remaining = self.entry_bytes_remaining;
        if remaining == 0 {
            for b in self.sparse_list.drain(..) {
                if !b.is_hole {
                    remaining += b.remaining;
                }
            }
        }
        let r = zeros(sink, remaining + self.entry_padding);
        self.entry_bytes_remaining = 0;
        self.entry_padding = 0;
        r
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        // Write two null blocks for the end of archive
        zeros(sink, 512 * 2)
    }
}

/// `strtoul(val, &end, 10)` with `*end == '\0'` required; None if that
/// fails or the value is negative or out of range (every such value is
/// rejected as an alignment anyway).
fn strtoul(val: &[u8]) -> Option<u64> {
    let val = val.trim_ascii_start();
    let digits = val.strip_prefix(b"+").unwrap_or(val);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

/// We need a valid name for the regular 'ustar' entry. This routine tries
/// to hack something more-or-less reasonable.
///
/// The approach here tries to preserve leading dir names. We do so by
/// working with four sections:
///   1) "prefix" directory names,
///   2) "suffix" directory names,
///   3) inserted dir name (optional),
///   4) filename.
///
/// These sections must satisfy the following requirements:
///   * Parts 1 & 2 together form an initial portion of the dir name.
///   * Part 3 is specified by the caller. (It should not contain a leading
///     or trailing '/'.)
///   * Part 4 forms an initial portion of the base filename.
///   * The filename must be <= 99 chars to fit the ustar 'name' field.
///   * Parts 2, 3, 4 together must be <= 99 chars to fit the ustar 'name'
///     fld.
///   * Part 1 must be <= 155 chars to fit the ustar 'prefix' field.
///   * If the original name ends in a '/', the new name must also end in a
///     '/'
///   * Trailing '/.' sequences may be stripped.
///
/// Note: Recall that the ustar format does not store the '/' separating
/// parts 1 & 2, but does store the '/' separating parts 2 & 3.
fn build_ustar_entry_name(src: &[u8], insert: Option<&[u8]>) -> Vec<u8> {
    let mut need_slash = false; // Was there a trailing slash?
    let mut suffix_length: usize = 98; // 99 - 1 for trailing slash
    // Length of additional dir element to be added. +2 here allows for '/'
    // before and after the insert.
    let insert_length = insert.map_or(0, |i| i.len() + 2);

    // Step 0: Quick bailout in a common case.
    if src.len() < 100 && insert.is_none() {
        return src.to_vec();
    }

    // Step 1: Locate filename and enforce the length restriction.
    let mut filename_end = src.len();
    // Remove trailing '/' chars and '/.' pairs.
    loop {
        if filename_end > 0 && src[filename_end - 1] == b'/' {
            filename_end -= 1;
            need_slash = true; // Remember to restore trailing '/'.
            continue;
        }
        if filename_end > 1 && src[filename_end - 1] == b'.' && src[filename_end - 2] == b'/' {
            filename_end -= 2;
            need_slash = true; // "foo/." will become "foo/"
            continue;
        }
        break;
    }

    // Pathological case: after trimming trailing '/' characters and '/.'
    // path elements, there is no filename component left. This happens for
    // pathnames made entirely of '/' characters. Emit a root-like ustar
    // name instead.
    if filename_end == 0 {
        let mut dest = insert.unwrap_or_default().to_vec();
        dest.push(b'/');
        return dest;
    }
    if need_slash {
        suffix_length -= 1;
    }
    // Find start of filename.
    let mut filename = filename_end - 1;
    while filename > 0 && src[filename] != b'/' {
        filename -= 1;
    }
    if src[filename] == b'/' && filename < filename_end - 1 {
        filename += 1;
    }
    // Adjust filename_end so that filename + insert fits in 99 chars.
    suffix_length -= insert_length;
    if filename_end > filename + suffix_length {
        filename_end = filename + suffix_length;
    }
    // Calculate max size for "suffix" section (#3 above).
    suffix_length -= filename_end - filename;

    // Step 2: Locate the "prefix" section of the dirname, including
    // trailing '/'.
    let prefix = 0;
    let mut prefix_end = (prefix + 154).min(filename); // 155 - 1 for trailing /
    while prefix_end > prefix && src[prefix_end] != b'/' {
        prefix_end -= 1;
    }
    if prefix_end < filename && src[prefix_end] == b'/' {
        prefix_end += 1;
    }

    // Step 3: Locate the "suffix" section of the dirname, including
    // trailing '/'.
    let suffix = prefix_end;
    let mut suffix_end = (suffix + suffix_length).min(filename).max(suffix); // Enforce limit.
    while suffix_end > suffix && src[suffix_end] != b'/' {
        suffix_end -= 1;
    }
    if suffix_end < filename && src[suffix_end] == b'/' {
        suffix_end += 1;
    }

    // Step 4: Build the new name.
    let mut dest = src[prefix..prefix_end].to_vec();
    dest.extend(&src[suffix..suffix_end]);
    if let Some(insert) = insert {
        // Note: assume insert does not have leading or trailing '/'
        dest.extend(insert);
        dest.push(b'/');
    }
    dest.extend(&src[filename..filename_end]);
    if need_slash {
        dest.push(b'/');
    }
    dest
}

/// `src` without its final '/' and "/." elements.
fn prune_final_elements(src: &[u8]) -> &[u8] {
    let mut p = src.len();
    loop {
        // Ends in "/", remove the '/'
        if p > 0 && src[p - 1] == b'/' {
            p -= 1;
            continue;
        }
        // Ends in "/.", remove the '.'
        if p > 1 && src[p - 1] == b'.' && src[p - 2] == b'/' {
            p -= 1;
            continue;
        }
        break;
    }
    &src[..p]
}

/// The ustar header for the pax extended attributes must have a reasonable
/// name: SUSv3 requires 'dirname'/PaxHeader.'pid'/'filename' where 'pid'
/// is the PID of the archiving process. Unfortunately, that makes testing
/// a pain since the output varies for each run, so I'm sticking with the
/// simpler 'dirname'/PaxHeader/'filename' for now. (Someday, I'll make
/// this settable. Then I can use the SUS recommendation as default and
/// test harnesses can override it to get predictable results.)
///
/// Joerg Schilling has argued that this is unnecessary because, in
/// practice, if the pax extended attributes get extracted as regular
/// files, no one is going to bother reading those attributes to manually
/// restore them. Based on this, 'star' uses /tmp/PaxHeader/'basename' as
/// the ustar header name. This is a tempting argument, in part because
/// it's simpler than the SUSv3 recommendation, but I'm not entirely
/// convinced. I'm also uncomfortable with the fact that "/tmp" is a
/// Unix-ism.
///
/// The following routine leverages build_ustar_entry_name() above and so
/// is simpler than you might think. It just needs to provide the
/// additional path element and handle a few pathological cases).
fn build_pax_attribute_name(src: &[u8]) -> Vec<u8> {
    // Handle the null filename case.
    if src.is_empty() {
        return b"PaxHeader/blank".to_vec();
    }
    // Prune final '/' and other unwanted final elements.
    let p = prune_final_elements(src);
    // Pathological case: After above, there was nothing left. This
    // includes "/." "/./." "/.//./." etc.
    if p.is_empty() {
        return b"/PaxHeader/rootdir".to_vec();
    }
    // Convert unadorned "." into a suitable filename.
    if p == b"." {
        return b"PaxHeader/currentdir".to_vec();
    }
    // General case: build a ustar-compatible name adding "/PaxHeader/".
    build_ustar_entry_name(p, Some(b"PaxHeader"))
}

/// GNU PAX Format 1.0 requires the special name, which pattern is:
/// <dir>/GNUSparseFile.<pid>/<original file name>
///
/// Since reproducible archives are more important, use 0 as pid.
///
/// This function is used for only Sparse file, a file type of which is
/// regular file.
fn build_gnu_sparse_name(src: &[u8]) -> Vec<u8> {
    // Handle the null filename case.
    if src.is_empty() {
        return b"GNUSparseFile/blank".to_vec();
    }
    // Prune final '/' and other unwanted final elements.
    let p = prune_final_elements(src);
    // General case: build a ustar-compatible name adding
    // "/GNUSparseFile.0/".
    if p.is_empty() {
        return b"/GNUSparseFile.0/rootdir".to_vec();
    }
    build_ustar_entry_name(p, Some(b"GNUSparseFile.0"))
}

fn has_non_ascii(p: &[u8]) -> bool {
    p.iter().any(|&b| b >= 128)
}

/// Used by extended attribute support; encodes the name so that there will
/// be no '=' characters in the result.
fn url_encode(input: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(input.len());
    for &c in input {
        // encode any non-printable ASCII character or '%' or '='
        if !(33..=126).contains(&c) || c == b'%' || c == b'=' {
            // URL encoding is '%' followed by two hex digits
            out.extend([b'%', HEX[usize::from(c >> 4)], HEX[usize::from(c & 0x0f)]]);
        } else {
            out.push(c);
        }
    }
    out
}

/// Encode a sequence of bytes using base-64 encoding, without padding.
fn base64_encode(s: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len().div_ceil(3) * 4);
    // Convert each group of 3 bytes into 4 characters; a final group of 1
    // byte becomes 2 chars and one of 2 bytes 3 chars.
    for group in s.chunks(3) {
        let v = group
            .iter()
            .enumerate()
            .fold(0u32, |v, (i, &b)| v | u32::from(b) << (16 - 8 * i));
        for i in 0..=group.len() {
            out.push(DIGITS[(v >> (18 - 6 * i) & 0x3f) as usize]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Mode;
    use crate::write::format::ustar::template;

    struct Out(Vec<u8>);
    impl Sink for Out {
        fn position(&self) -> u64 {
            self.0.len() as u64
        }
        fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.0.extend_from_slice(data);
            Ok(())
        }
    }

    /// An entry like those of the writer sweep's input tree.
    fn entry(path: &[u8], mode: Mode) -> Entry {
        let mut e = Entry::new(None);
        e.set_pathname(path);
        e.set_mode(mode);
        e.set_uid(501);
        e.set_gid(20);
        e.set_uname(b"michaelli");
        e.set_gname(b"staff");
        e.set_mtime(1_600_000_000, 0);
        e
    }

    fn header(pax: &mut Pax, e: &mut Entry) -> Vec<u8> {
        let mut out = Out(Vec::new());
        assert_eq!(
            pax.header(&Base::new(WRITE_MAGIC), e, &mut out),
            Ok(ARCHIVE_OK)
        );
        out.0
    }

    // The expected blocks below are upstream bsdtar's output for the same
    // entries.

    #[test]
    fn long_symlink_gets_upstream_pax_header() {
        let mut e = entry(b"t/sym_long", 0o120755);
        e.set_symlink(&[b'x'; 120]);
        let blocks = [
            template(&[
                (0, b"t/PaxHeader/sym_long"),
                (
                    100,
                    b"000755 \x00000765 \x00000024 \x0000000000206 13727410000 016131\x00 x",
                ),
                (257, b"ustar\x0000michaelli"),
                (297, b"staff"),
                (329, b"000000 \x00000000 "),
            ]),
            template(&[(
                0,
                &[b"134 linkpath=".as_slice(), &[b'x'; 120], b"\n"].concat(),
            )]),
            template(&[
                (0, b"t/sym_long"),
                (
                    100,
                    b"000755 \x00000765 \x00000024 \x0000000000000 13727410000 016673\x00 2",
                ),
                (157, b"././@LongSymLink"),
                (257, b"ustar\x0000michaelli"),
                (297, b"staff"),
                (329, b"000000 \x00000000 "),
            ]),
        ];
        assert_eq!(header(&mut Pax::new(true), &mut e), blocks.concat());
    }

    #[test]
    fn negative_subsecond_mtime_is_one_attribute_and_clipped() {
        let mut e = entry(b"t/mtime_neg_ns", 0o100644);
        e.set_size(1);
        e.set_mtime(-5, 250_000_000);
        let blocks = [
            template(&[
                (0, b"t/PaxHeader/mtime_neg_ns"),
                (
                    100,
                    b"000644 \x00000765 \x00000024 \x0000000000017 00000000000 016712\x00 x",
                ),
                (257, b"ustar\x0000michaelli"),
                (297, b"staff"),
                (329, b"000000 \x00000000 "),
            ]),
            template(&[(0, b"15 mtime=-5.25\n")]),
            template(&[
                (0, b"t/mtime_neg_ns"),
                (100, b"000644 \x00000765 \x00000024 \x0000000000001 "),
                (
                    136,
                    b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfb 021273\x00 0",
                ),
                (257, b"ustar\x0000michaelli"),
                (297, b"staff"),
                (329, b"000000 \x00000000 "),
            ]),
        ];
        assert_eq!(header(&mut Pax::new(true), &mut e), blocks.concat());
    }

    #[test]
    fn long_path_keeps_leading_dirs_in_both_headers() {
        let dirs: Vec<Vec<u8>> = (0..6)
            .map(|i| format!("deep{i}").repeat(9).into_bytes())
            .collect();
        let path = [b"t/".as_slice(), &dirs.join(&b'/'), b"/leaf"].concat();
        let prefix = [b"t/".as_slice(), &dirs[..3].join(&b'/')].concat();
        let mut e = entry(&path, 0o100644);
        e.set_size(5);
        let blocks = [
            template(&[
                (0, &[&dirs[3], b"/PaxHeader/leaf".as_slice()].concat()),
                (
                    100,
                    b"000644 \x00000765 \x00000024 \x0000000000444 13727410000 056105\x00 x",
                ),
                (257, b"ustar\x0000michaelli"),
                (297, b"staff"),
                (329, b"000000 \x00000000 "),
                (345, &prefix),
            ]),
            template(&[(0, &[b"292 path=".as_slice(), &path, b"\n"].concat())]),
            template(&[
                (0, &[&dirs[3], b"/".as_slice(), &dirs[4], b"/leaf"].concat()),
                (
                    100,
                    b"000644 \x00000765 \x00000024 \x0000000000005 13727410000 064346\x00 0",
                ),
                (257, b"ustar\x0000michaelli"),
                (297, b"staff"),
                (329, b"000000 \x00000000 "),
                (345, &prefix),
            ]),
        ];
        assert_eq!(header(&mut Pax::new(true), &mut e), blocks.concat());
    }

    #[test]
    fn pax_header_names_match_upstream() {
        let check = |path: &[u8], mode: Mode, prefix: &[u8], name: &[u8]| {
            let mut e = Entry::new(None);
            e.set_pathname(path);
            e.set_mode(mode);
            e.set_uid(300_000);
            let h = header(&mut Pax::new(true), &mut e);
            let field = |f: &[u8]| f[..f.iter().position(|&b| b == 0).unwrap_or(f.len())].to_vec();
            assert_eq!(
                (field(&h[345..500]), field(&h[..100])),
                (prefix.to_vec(), name.to_vec())
            );
        };
        check(b"/", 0o040755, b"", b"/PaxHeader/rootdir");
        check(b".", 0o040755, b"", b"PaxHeader/currentdir");
        check(b"s/.", 0o040755, b"", b"PaxHeader/s");
        check(b"s/dot/./", 0o040755, b"", b"s/PaxHeader/dot");
        check(b"a//b//", 0o040755, b"", b"a//PaxHeader/b");
        let (x, y) = ([b'x'; 99], [b'y'; 99]);
        check(
            &[&x, b"/".as_slice(), &y, b"/."].concat(),
            0o040755,
            &x,
            &[b"PaxHeader/".as_slice(), &y[..87]].concat(),
        );
        check(
            &[b"./".as_slice(), &[b'q'; 120]].concat(),
            0o100755,
            b"",
            &[b"./PaxHeader/".as_slice(), &[b'q'; 87]].concat(),
        );
        check(
            &[[b'p'; 160].as_slice(), b"/", &[b'z'; 30]].concat(),
            0o100755,
            b"",
            &[b"PaxHeader/".as_slice(), &[b'z'; 30]].concat(),
        );
    }

    #[test]
    fn pax_attr_length_counts_its_own_digits() {
        let mut out = Vec::new();
        add_pax_attr(&mut out, b"k", &[b'v'; 94]); // 98 bytes before the length
        assert!(out.starts_with(b"101 k=v"));
        out.clear();
        add_pax_attr(&mut out, b"k", &[b'v'; 3]);
        assert_eq!(out, b"8 k=vvv\n");
    }

    #[test]
    fn xattrs_are_url_and_base64_encoded() {
        let mut pax = Pax::new(false);
        pax.header_xattr(&url_encode(b"user.a=b%"), b"\x00\xffx");
        assert_eq!(
            pax.pax_header,
            b"39 LIBARCHIVE.xattr.user.a%3Db%25=AP94\n34 SCHILY.xattr.user.a%3Db%25=\x00\xffx\n"
        );
    }

    #[test]
    fn options_match_upstream() {
        let a = Base::new(WRITE_MAGIC);
        let mut pax = Pax::new(false);
        let msg = |r: Result<c_int, Error>| r.unwrap_err().msg;
        assert_eq!(
            msg(pax.options(&a, b"xattrheader", None)),
            b"pax: xattrheader requires a value"
        );
        assert_eq!(pax.options(&a, b"mac-ext", Some(b"1")), Ok(ARCHIVE_WARN));
        assert_eq!(pax.options(&a, b"align", Some(b" +4096")), Ok(ARCHIVE_OK));
        assert_eq!(pax.align, 4096);
        for bad in [b"4096x".as_slice(), b"-512", b"256", b"3072", b"2097152"] {
            assert!(pax.options(&a, b"align", Some(bad)).is_err());
        }
    }
}
