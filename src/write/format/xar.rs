/*-
 * Copyright (c) 2010-2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_write_set_format_xar.c.

use crate::archive::*;
use crate::digest::{Algorithm, Digest};
use crate::entry::Entry;
use crate::ffi::sys;
use crate::read::{filter_code, format_code};
use crate::util::Error;
use crate::write::{Filter, Format, Sink};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

#[derive(Clone, Copy)]
enum Checksum {
    None,
    Sha1,
    Md5,
    Sha256,
    Sha512,
}
impl Checksum {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Sha1 => "sha1",
            Self::Md5 => "md5",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
    fn code(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Sha1 => 1,
            Self::Md5 => 2,
            Self::Sha256 => 3,
            Self::Sha512 => 4,
        }
    }
    fn algorithm(self) -> Option<Algorithm> {
        match self {
            Self::None => None,
            Self::Sha1 => Some(Algorithm::Sha1),
            Self::Md5 => Some(Algorithm::Md5),
            Self::Sha256 => Some(Algorithm::Sha256),
            Self::Sha512 => Some(Algorithm::Sha512),
        }
    }
    fn size(self) -> u64 {
        match self {
            Self::None => 0,
            Self::Sha1 => 20,
            Self::Md5 => 16,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
    fn digest(self) -> Option<Digest> {
        self.algorithm().map(Digest::new)
    }
    fn parse(value: Option<&[u8]>) -> Result<Self, Error> {
        Ok(match value {
            None | Some(b"none") => Self::None,
            Some(b"sha1") => Self::Sha1,
            Some(b"md5") => Self::Md5,
            Some(b"sha256") => Self::Sha256,
            Some(b"sha512") => Self::Sha512,
            Some(v) => {
                return Err(failed(
                    [b"Unknown checksum name: `".as_slice(), v, b"'"].concat(),
                ));
            }
        })
    }
}
#[derive(Clone, Copy)]
enum Compression {
    None,
    Gzip,
    Bzip2,
    Lzma,
    Xz,
}
impl Compression {
    fn name(self) -> &'static str {
        match self {
            Self::None => "application/octet-stream",
            Self::Gzip => "application/x-gzip",
            Self::Bzip2 => "application/x-bzip2",
            Self::Lzma => "application/x-lzma",
            Self::Xz => "application/x-xz",
        }
    }
}
struct Heap {
    offset: u64,
    length: u64,
    size: u64,
    compression: Compression,
    sum: Checksum,
    archived: Vec<u8>,
    extracted: Vec<u8>,
}
struct Node {
    entry: Entry,
    name: Vec<u8>,
    children: Vec<usize>,
    virtual_dir: bool,
    data: Option<Heap>,
    xattrs: Vec<(Vec<u8>, Heap)>,
    link: Option<usize>,
    script: Vec<u8>,
}
/// The encoder of a file's data or extended attribute, None if it is stored.
type Encoder = Option<Box<dyn Filter>>;
struct Active {
    index: usize,
    encoder: Encoder,
    offset: u64,
    size: u64,
    remaining: u64,
    compression: Compression,
    sum: Checksum,
    archived: Option<Digest>,
    extracted: Option<Digest>,
}
pub struct Xar {
    nodes: Vec<Node>,
    paths: BTreeMap<Vec<u8>, usize>,
    roots: Vec<usize>,
    current: Option<Active>,
    heap: Option<File>,
    offset: u64,
    toc_sum: Checksum,
    sum: Checksum,
    compression: Compression,
    level: u8,
    sc: Option<std::sync::Arc<crate::string::StringConv>>,
}
impl Default for Xar {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            paths: BTreeMap::new(),
            roots: Vec::new(),
            current: None,
            heap: None,
            offset: 0,
            toc_sum: Checksum::Sha1,
            sum: Checksum::Sha1,
            compression: Compression::Gzip,
            level: 6,
            sc: None,
        }
    }
}
fn failed(message: impl Into<Vec<u8>>) -> Error {
    Error::new(ARCHIVE_FAILED, -1, message)
}
fn io(e: std::io::Error) -> Error {
    Error::fatal(e.raw_os_error().unwrap_or(libc::EIO), e.to_string())
}
struct HeapSink<'a> {
    file: &'a mut File,
    offset: &'a mut u64,
    digest: &'a mut Option<Digest>,
}
impl Sink for HeapSink<'_> {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.file.write_all(data).map_err(io)?;
        *self.offset = self
            .offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "XAR heap too large"))?;
        if let Some(d) = self.digest {
            d.update(data);
        }
        Ok(())
    }
}
fn encode(
    encoder: &mut Encoder,
    input: &[u8],
    finish: bool,
    sink: &mut dyn Sink,
) -> Result<(), Error> {
    match encoder {
        None => sink.write(input),
        Some(f) => {
            f.write(input, sink)?;
            if finish {
                f.close(sink)?;
            }
            Ok(())
        }
    }
}
impl Xar {
    fn encoder(&self, kind: Compression) -> Result<Encoder, Error> {
        Ok(match kind {
            Compression::None => None,
            Compression::Gzip => Some(Box::new(crate::write::filter::gzip::Gzip::zlib(self.level))),
            c => {
                let code = match c {
                    Compression::Bzip2 => filter_code::BZIP2,
                    Compression::Lzma => filter_code::LZMA,
                    _ => filter_code::XZ,
                };
                let mut filter = crate::write::filter::by_code(code)?;
                let level = [b'0' + self.level];
                let _ = filter.options(b"compression-level", Some(&level))?;
                Some(filter)
            }
        })
    }
    fn spool(&mut self) -> Result<(), Error> {
        if self.heap.is_none() {
            let mut f = crate::write::temp_file()?;
            self.offset = self.toc_sum.size();
            f.seek(SeekFrom::Start(self.offset)).map_err(io)?;
            self.heap = Some(f);
        }
        Ok(())
    }
    fn save_attribute(&mut self, data: &[u8]) -> Result<Heap, Error> {
        self.spool()?;
        let offset = self.offset;
        let mut archived = self.sum.digest();
        let mut extracted = self.sum.digest();
        if let Some(d) = extracted.as_mut() {
            d.update(data);
        }
        let mut encoder = self.encoder(self.compression)?;
        let file = self
            .heap
            .as_mut()
            .ok_or_else(|| Error::fatal(-1, "Missing XAR heap"))?;
        encode(
            &mut encoder,
            data,
            true,
            &mut HeapSink {
                file,
                offset: &mut self.offset,
                digest: &mut archived,
            },
        )?;
        Ok(Heap {
            offset,
            length: self.offset - offset,
            size: data.len() as u64,
            compression: self.compression,
            sum: self.sum,
            archived: archived.map_or(Vec::new(), Digest::finalize),
            extracted: extracted.map_or(Vec::new(), Digest::finalize),
        })
    }
    fn normalize(path: &[u8]) -> Vec<Vec<u8>> {
        let mut parts = Vec::new();
        for p in path.split(|&b| b == b'/') {
            match p {
                b"" | b"." => {}
                b".." => {
                    parts.pop();
                }
                _ => parts.push(p.to_vec()),
            }
        }
        parts
    }
    fn add(&mut self, mut entry: Entry) -> Result<Option<usize>, Error> {
        let path = entry
            .pathname()
            .ok_or_else(|| failed("Can't translate pathname to UTF-8"))?
            .to_bytes()
            .to_vec();
        let parts = Self::normalize(&path);
        if parts.is_empty() {
            return Ok(None);
        }
        let mut full = Vec::new();
        let mut parent = None;
        for (n, name) in parts.iter().enumerate() {
            if n > 0 {
                full.push(b'/');
            }
            full.extend(name);
            let last = n + 1 == parts.len();
            if !last && name.len() > 255 {
                return Err(Error::fatal(
                    crate::archive::ARCHIVE_ERRNO_MISC,
                    "A name buffer is too small",
                ));
            }
            if let Some(&index) = self.paths.get(&full) {
                if !last && self.nodes[index].entry.filetype() != libc::S_IFDIR {
                    return Err(failed(
                        [
                            b"`".as_slice(),
                            full.as_slice(),
                            b"' is not directory, we cannot insert `",
                            path.as_slice(),
                            b"' ",
                        ]
                        .concat(),
                    ));
                }
                if last {
                    if self.nodes[index].entry.filetype() != entry.filetype() {
                        return Err(failed(
                            [
                                b"Found duplicate entries `".as_slice(),
                                full.as_slice(),
                                b"' and its file type is different",
                            ]
                            .concat(),
                        ));
                    }
                    self.nodes[index].entry = entry.clone_entry();
                    self.nodes[index].virtual_dir = false;
                    return Ok(Some(index));
                }
                parent = Some(index);
                continue;
            }
            let mut e = if last {
                entry.clone_entry()
            } else {
                let mut e = Entry::new(None);
                e.set_mode(libc::S_IFDIR | 0o755);
                e
            };
            e.set_pathname(&full);
            let index = self.nodes.len();
            self.nodes.push(Node {
                entry: e,
                name: name.clone(),
                children: Vec::new(),
                virtual_dir: !last,
                data: None,
                xattrs: Vec::new(),
                link: None,
                script: Vec::new(),
            });
            self.paths.insert(full.clone(), index);
            if let Some(p) = parent {
                self.nodes[p].children.push(index);
            } else {
                self.roots.push(index);
            }
            parent = Some(index);
            if last {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }
}
/// libxml2's xmlTextWriter with indentation on, which upstream writes the
/// TOC with: one space per level, a text-only element on one line, an
/// empty one as `<name/>`, and base64 broken into 72-column CRLF lines.
#[derive(Default)]
struct Xml {
    out: Vec<u8>,
    /// Open elements, each with whether its start tag still lacks `>`.
    open: Vec<(&'static str, bool)>,
    doindent: bool,
}
impl Xml {
    fn new() -> Self {
        Self {
            out: b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n".to_vec(),
            ..Self::default()
        }
    }
    fn indent(&mut self) {
        let n = self.open.len().saturating_sub(1);
        self.out.resize(self.out.len() + n, b' ');
    }
    /// Close a pending start tag before content.
    fn content(&mut self) {
        if let Some((_, pending)) = self.open.last_mut()
            && *pending
        {
            self.out.push(b'>');
            *pending = false;
        }
    }
    fn start(&mut self, name: &'static str) {
        if let Some((_, pending)) = self.open.last_mut()
            && *pending
        {
            self.out.extend(b">\n");
            *pending = false;
        }
        self.open.push((name, true));
        self.indent();
        self.out.push(b'<');
        self.out.extend(name.as_bytes());
    }
    fn attribute(&mut self, key: &str, value: &str) {
        self.out.push(b' ');
        self.out.extend(key.as_bytes());
        self.out.extend(b"=\"");
        for &b in value.as_bytes() {
            match b {
                b'<' => self.out.extend(b"&lt;"),
                b'>' => self.out.extend(b"&gt;"),
                b'&' => self.out.extend(b"&amp;"),
                b'"' => self.out.extend(b"&quot;"),
                b'\n' => self.out.extend(b"&#10;"),
                b'\r' => self.out.extend(b"&#13;"),
                b'\t' => self.out.extend(b"&#9;"),
                _ => self.out.push(b),
            }
        }
        self.out.push(b'"');
    }
    /// xmlEncodeSpecialChars() escaping.
    fn text(&mut self, text: &[u8]) {
        self.content();
        self.doindent = false;
        for &b in text {
            match b {
                b'<' => self.out.extend(b"&lt;"),
                b'>' => self.out.extend(b"&gt;"),
                b'&' => self.out.extend(b"&amp;"),
                b'"' => self.out.extend(b"&quot;"),
                b'\r' => self.out.extend(b"&#13;"),
                _ => self.out.push(b),
            }
        }
    }
    fn base64(&mut self, data: &[u8]) {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        self.content();
        self.doindent = false;
        for (i, group) in data.chunks(3).enumerate() {
            if i > 0 && i % 18 == 0 {
                self.out.extend(b"\r\n");
            }
            let a = group[0];
            let b = group.get(1).copied().unwrap_or(0);
            let c = group.get(2).copied().unwrap_or(0);
            self.out.extend([
                TABLE[usize::from(a >> 2)],
                TABLE[usize::from((a & 3) << 4 | b >> 4)],
                if group.len() > 1 {
                    TABLE[usize::from((b & 15) << 2 | c >> 6)]
                } else {
                    b'='
                },
                if group.len() > 2 {
                    TABLE[usize::from(c & 63)]
                } else {
                    b'='
                },
            ]);
        }
    }
    fn end(&mut self) {
        let Some(&(name, pending)) = self.open.last() else {
            return;
        };
        if pending {
            self.out.extend(b"/>");
        } else {
            if self.doindent {
                self.indent();
            }
            self.out.extend(b"</");
            self.out.extend(name.as_bytes());
            self.out.push(b'>');
        }
        self.doindent = true;
        self.out.push(b'\n');
        self.open.pop();
    }
    fn element(&mut self, key: &'static str, value: impl AsRef<[u8]>) {
        self.start(key);
        self.text(value.as_ref());
        self.end();
    }
    /// xmlwrite_time(): UTC, with `Z` only when asked for.
    fn time(&mut self, name: &'static str, seconds: i64, z: bool) {
        if let Some((tm, _, _)) = sys::date_clock(seconds, true) {
            self.element(
                name,
                format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}",
                    tm.year + 1900,
                    tm.mon + 1,
                    tm.mday,
                    tm.hour,
                    tm.min,
                    tm.sec,
                    if z { "Z" } else { "" }
                ),
            );
        }
    }
    fn heap(&mut self, h: &Heap) {
        self.element("length", h.length.to_string());
        self.element("offset", h.offset.to_string());
        self.element("size", h.size.to_string());
        self.start("encoding");
        self.attribute("style", h.compression.name());
        self.end();
        for (key, value) in [
            ("archived-checksum", &h.archived),
            ("extracted-checksum", &h.extracted),
        ] {
            if !value.is_empty() {
                self.start(key);
                self.attribute("style", h.sum.name());
                self.text(hex(value).as_bytes());
                self.end();
            }
        }
    }
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
impl Xar {
    fn node_xml(&mut self, index: usize, xml: &mut Xml) {
        let node = &mut self.nodes[index];
        let latin1 =
            std::str::from_utf8(&node.name).is_ok_and(|s| s.chars().all(|c| u32::from(c) <= 255));
        if latin1 {
            xml.element("name", &node.name);
        } else {
            xml.start("name");
            xml.attribute("enctype", "base64");
            xml.base64(&node.name);
            xml.end();
        }
        let entry = &mut node.entry;
        let kind = match entry.filetype() {
            libc::S_IFDIR => "directory",
            libc::S_IFLNK => "symlink",
            libc::S_IFCHR => "character special",
            libc::S_IFBLK => "block special",
            libc::S_IFIFO => "fifo",
            libc::S_IFSOCK => "socket",
            _ => "file",
        };
        if let Some(link) = node.link {
            xml.start("type");
            xml.attribute(
                "link",
                &if link == index {
                    "original".to_owned()
                } else {
                    (link + 1).to_string()
                },
            );
            xml.text(b"hardlink");
            xml.end();
        } else {
            xml.element("type", kind);
        }
        if node.virtual_dir {
            return;
        }
        if let (Some(link), _) = entry.symlink_l(self.sc.as_deref()) {
            xml.start("link");
            xml.attribute("type", "broken");
            xml.text(link);
            xml.end();
        }
        if matches!(entry.filetype(), libc::S_IFCHR | libc::S_IFBLK) {
            xml.start("device");
            xml.element("major", entry.rdevmajor().to_string());
            xml.element("minor", entry.rdevminor().to_string());
            xml.end();
        }
        xml.element("inode", entry.ino().to_string());
        if entry.dev() != 0 {
            xml.element("deviceno", entry.dev().to_string());
        }
        xml.element("mode", format!("0{:03o}", entry.mode() & 0o777));
        xml.element("uid", entry.uid().to_string());
        if let (Some(name), _) = entry.uname_l(self.sc.as_deref())
            && !name.is_empty()
        {
            xml.element("user", name);
        }
        xml.element("gid", entry.gid().to_string());
        if let (Some(name), _) = entry.gname_l(self.sc.as_deref())
            && !name.is_empty()
        {
            xml.element("group", name);
        }
        if entry.ctime_is_set() != 0 {
            xml.time("ctime", entry.ctime(), true);
        }
        if entry.mtime_is_set() != 0 {
            xml.time("mtime", entry.mtime(), true);
        }
        if entry.atime_is_set() != 0 {
            xml.time("atime", entry.atime(), true);
        }
        if let Some(flags) = entry.fflags_text() {
            flags_xml(xml, flags.to_bytes());
        }
        for (i, (name, heap)) in node.xattrs.iter().enumerate() {
            xml.start("ea");
            xml.attribute("id", &i.to_string());
            xml.heap(heap);
            xml.element("name", name);
            xml.end();
        }
        if !node.script.is_empty() {
            xml.start("content");
            xml.element("interpreter", &node.script);
            xml.element("type", "script");
            xml.end();
        }
        if let Some(data) = node.data.as_ref().filter(|d| d.length > 0) {
            xml.start("data");
            xml.heap(data);
            xml.end();
        }
    }
    fn toc(&mut self) -> Vec<u8> {
        let mut xml = Xml::new();
        xml.start("xar");
        xml.start("toc");
        xml.time(
            "creation-time",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            false,
        );
        if self.toc_sum.size() != 0 {
            xml.start("checksum");
            xml.attribute("style", self.toc_sum.name());
            xml.element("offset", "0");
            xml.element("size", self.toc_sum.size().to_string());
            xml.end();
        }
        let mut stack: Vec<_> = self.roots.iter().rev().map(|&i| (i, false)).collect();
        while let Some((index, end)) = stack.pop() {
            if end {
                xml.end();
                continue;
            }
            xml.start("file");
            xml.attribute("id", &(index + 1).to_string());
            self.node_xml(index, &mut xml);
            stack.push((index, true));
            stack.extend(self.nodes[index].children.iter().rev().map(|&i| (i, false)));
        }
        xml.end();
        xml.end();
        xml.out
    }
}
impl Format for Xar {
    fn code(&self) -> i32 {
        format_code::XAR
    }
    fn name(&self) -> &'static CStr {
        c"xar"
    }
    fn module(&self) -> &'static [u8] {
        b"xar"
    }
    fn header(&mut self, a: &Base, entry: &mut Entry, _sink: &mut dyn Sink) -> Result<i32, Error> {
        self.current = None;
        if self.sc.is_none() {
            let mut cache = a.conv.lock().ok();
            self.sc = Some(
                crate::string::conversion_to_charset(cache.as_deref_mut(), b"UTF-8", true)
                    .map_err(|_| {
                        Error::fatal(libc::ENOMEM, "Can't allocate memory for Pathname")
                    })?,
            );
        }
        let mut cloned = entry.clone_entry();
        let (path, converted) = cloned.pathname_l(self.sc.as_deref());
        let path = path.unwrap_or_default().to_vec();
        let mut result = if converted {
            ARCHIVE_OK
        } else {
            a.set_error(
                crate::read::ARCHIVE_ERRNO_FILE_FORMAT,
                Some(
                    &[
                        b"Can't translate pathname '".as_slice(),
                        entry.pathname().map_or(&[][..], CStr::to_bytes),
                        b"' to UTF-8",
                    ]
                    .concat(),
                ),
            );
            ARCHIVE_WARN
        };
        cloned.set_pathname(&path);
        if cloned.filetype() == libc::S_IFLNK {
            let (link, converted) = cloned.symlink_l(self.sc.as_deref());
            let link = link.map(<[u8]>::to_vec);
            if !converted {
                a.set_error(
                    crate::read::ARCHIVE_ERRNO_FILE_FORMAT,
                    Some(
                        &[
                            b"Can't translate symlink '".as_slice(),
                            entry.symlink().map_or(&[][..], CStr::to_bytes),
                            b"' to UTF-8",
                        ]
                        .concat(),
                    ),
                );
                result = ARCHIVE_WARN;
            }
            if let Some(link) = link {
                cloned.set_symlink(&link);
            }
        }
        let Some(index) = self.add(cloned)? else {
            return Ok(result);
        };
        self.spool()?;
        let hardlink = self.nodes[index]
            .entry
            .hardlink()
            .map(|p| p.to_bytes().to_vec());
        if hardlink.is_none() {
            let attributes: Vec<_> = self.nodes[index]
                .entry
                .xattrs
                .iter()
                .map(|a| (a.name.clone(), a.value.clone()))
                .collect();
            let mut saved = Vec::new();
            for attr in attributes {
                let heap = self.save_attribute(&attr.1)?;
                saved.push((attr.0.to_bytes().to_vec(), heap));
            }
            self.nodes[index].xattrs = saved;
        }
        if let Some(link) = hardlink {
            let parts = Self::normalize(&link);
            let full = parts.join(&b'/');
            if let Some(&original) = self.paths.get(&full)
                && self.nodes[original].entry.nlink() > 1
            {
                self.nodes[index].link = Some(original);
                self.nodes[original].link = Some(original);
                self.nodes[index].entry.unset_size();
            }
            return Ok(result);
        }
        if self.nodes[index].entry.filetype() != libc::S_IFREG {
            return Ok(result);
        }
        let size = self.nodes[index].entry.size().max(0) as u64;
        self.current = Some(Active {
            index,
            encoder: self.encoder(self.compression)?,
            offset: self.offset,
            size,
            remaining: size,
            compression: self.compression,
            sum: self.sum,
            archived: self.sum.digest(),
            extracted: self.sum.digest(),
        });
        Ok(result)
    }
    fn data(&mut self, data: &[u8], _sink: &mut dyn Sink) -> Result<usize, Error> {
        let Some(active) = self.current.as_mut() else {
            return Ok(0);
        };
        let n = data
            .len()
            .min(usize::try_from(active.remaining).unwrap_or(usize::MAX));
        let data = &data[..n];
        if active.remaining == active.size && data.len() > 2 && data.starts_with(b"#!") {
            let start = if data.get(2) == Some(&b' ') { 3 } else { 2 };
            let end = data[start..]
                .iter()
                .take(1024)
                .position(|&b| matches!(b, 0 | b'\n' | b'\r' | b' ' | b'\t'))
                .map_or(data.len().min(start + 1024), |n| start + n);
            self.nodes[active.index].script = data[start..end].to_vec();
        }
        if let Some(d) = active.extracted.as_mut() {
            d.update(data);
        }
        let file = self
            .heap
            .as_mut()
            .ok_or_else(|| Error::fatal(-1, "Missing XAR heap"))?;
        encode(
            &mut active.encoder,
            data,
            false,
            &mut HeapSink {
                file,
                offset: &mut self.offset,
                digest: &mut active.archived,
            },
        )?;
        active.remaining -= n as u64;
        Ok(n)
    }
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        let zeros = [0; 65536];
        while self.current.as_ref().is_some_and(|a| a.remaining > 0) {
            let n = self
                .current
                .as_ref()
                .map_or(0, |a| a.remaining.min(zeros.len() as u64) as usize);
            self.data(&zeros[..n], sink)?;
        }
        if let Some(mut active) = self.current.take() {
            let file = self
                .heap
                .as_mut()
                .ok_or_else(|| Error::fatal(-1, "Missing XAR heap"))?;
            if active.size > 0 {
                encode(
                    &mut active.encoder,
                    &[],
                    true,
                    &mut HeapSink {
                        file,
                        offset: &mut self.offset,
                        digest: &mut active.archived,
                    },
                )?;
            }
            self.nodes[active.index].data = Some(Heap {
                offset: active.offset,
                length: self.offset - active.offset,
                size: active.size,
                compression: active.compression,
                sum: active.sum,
                archived: active.archived.map_or(Vec::new(), Digest::finalize),
                extracted: active.extracted.map_or(Vec::new(), Digest::finalize),
            });
        }
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.finish_entry(sink)?;
        if self.nodes.is_empty() {
            return Ok(());
        }
        // Upstream aborts TOC generation when owner-name conversion warns.
        for node in self.nodes.iter_mut().filter(|node| !node.virtual_dir) {
            let entry = &mut node.entry;
            let original = entry
                .uname()
                .map_or(Vec::new(), |name| name.to_bytes().to_vec());
            if !entry.uname_l(self.sc.as_deref()).1 {
                return Err(Error::fatal(
                    crate::read::ARCHIVE_ERRNO_FILE_FORMAT,
                    [
                        b"Can't translate uname '".as_slice(),
                        &original,
                        b"' to UTF-8",
                    ]
                    .concat(),
                ));
            }
            let original = entry
                .gname()
                .map_or(Vec::new(), |name| name.to_bytes().to_vec());
            if !entry.gname_l(self.sc.as_deref()).1 {
                return Err(Error::fatal(
                    crate::read::ARCHIVE_ERRNO_FILE_FORMAT,
                    [
                        b"Can't translate gname '".as_slice(),
                        &original,
                        b"' to UTF-8",
                    ]
                    .concat(),
                ));
            }
        }
        let toc = self.toc();
        // Upstream compresses the TOC at level 6, whatever the files' level.
        let mut compressed = Vec::new();
        deflate::Deflate::new(6, 15, 8)
            .ok_or_else(|| Error::fatal(-1, "Internal error initializing compression library"))?
            .compress(&toc, &mut compressed)
            .map_err(crate::write::filter::gzip::failed)?;
        let mut sum = self.toc_sum.digest();
        if let Some(d) = sum.as_mut() {
            d.update(&compressed);
        }
        let sum = sum.map_or(Vec::new(), Digest::finalize);
        let mut header = Vec::from(b"xar!");
        header.extend_from_slice(&28u16.to_be_bytes());
        header.extend_from_slice(&1u16.to_be_bytes());
        header.extend_from_slice(&(compressed.len() as u64).to_be_bytes());
        header.extend_from_slice(&(toc.len() as u64).to_be_bytes());
        header.extend_from_slice(&self.toc_sum.code().to_be_bytes());
        sink.write(&header)?;
        sink.write(&compressed)?;
        sink.write(&sum)?;
        if let Some(file) = self.heap.as_mut() {
            file.seek(SeekFrom::Start(self.toc_sum.size()))
                .map_err(io)?;
            let mut buf = [0; 65536];
            loop {
                let n = file.read(&mut buf).map_err(io)?;
                if n == 0 {
                    break;
                }
                sink.write(&buf[..n])?;
            }
        }
        Ok(())
    }
    fn options(&mut self, _a: &Base, key: &[u8], value: Option<&[u8]>) -> Result<i32, Error> {
        match key {
            b"checksum" => self.sum = Checksum::parse(value)?,
            b"toc-checksum" => self.toc_sum = Checksum::parse(value)?,
            b"compression" => {
                self.compression = match value {
                    None | Some(b"none") => Compression::None,
                    Some(b"gzip") => Compression::Gzip,
                    Some(b"bzip2") => Compression::Bzip2,
                    Some(b"lzma") => Compression::Lzma,
                    Some(b"xz") => Compression::Xz,
                    Some(v) => {
                        return Err(failed(
                            [b"Unknown compression name: `".as_slice(), v, b"'"].concat(),
                        ));
                    }
                }
            }
            b"compression-level" => match value {
                Some([level @ b'0'..=b'9']) => self.level = *level - b'0',
                _ => {
                    return Err(failed(
                        [
                            b"Illegal value `".as_slice(),
                            value.unwrap_or_default(),
                            b"'",
                        ]
                        .concat(),
                    ));
                }
            },
            b"threads" => {
                let n = value
                    .and_then(|s| std::str::from_utf8(s).ok())
                    .and_then(|s| s.parse::<u32>().ok())
                    .filter(|&n| n <= i32::MAX as u32);
                if n.is_none() {
                    return Err(failed(
                        [
                            b"Illegal value `".as_slice(),
                            value.unwrap_or_default(),
                            b"'",
                        ]
                        .concat(),
                    ));
                }
                return Ok(ARCHIVE_WARN);
            }
            _ => return Ok(ARCHIVE_WARN),
        }
        Ok(ARCHIVE_OK)
    }
}

/// Upstream's make_fflags_entry() passes a NULL value to xmlwrite_string(),
/// which writes nothing, so a known flag only yields an empty `<flags/>` or
/// `<ext2/>`.
fn flags_xml(xml: &mut Xml, text: &[u8]) {
    const BSD: &[&[u8]] = &[
        b"sappnd",
        b"sappend",
        b"arch",
        b"archived",
        b"schg",
        b"schange",
        b"simmutable",
        b"nosunlnk",
        b"nosunlink",
        b"snapshot",
        b"uappnd",
        b"uappend",
        b"uchg",
        b"uchange",
        b"uimmutable",
        b"nodump",
        b"noopaque",
        b"nouunlnk",
        b"nouunlink",
    ];
    const EXT2: &[&[u8]] = &[
        b"sappnd",
        b"sappend",
        b"schg",
        b"schange",
        b"simmutable",
        b"nodump",
        b"nouunlnk",
        b"nouunlink",
        b"btree",
        b"comperr",
        b"compress",
        b"noatime",
        b"compdirty",
        b"comprblk",
        b"dirsync",
        b"hashidx",
        b"imagic",
        b"journal",
        b"securedeletion",
        b"sync",
        b"notail",
        b"topdir",
        b"reserved",
    ];
    for (element, known) in [("flags", BSD), ("ext2", EXT2)] {
        if text.split(|&b| b == b',').any(|flag| known.contains(&flag)) {
            xml.start(element);
            xml.end();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::Read;
    use crate::read_open_memory::Memory;
    #[derive(Default)]
    struct Output(Vec<u8>);
    impl Sink for Output {
        fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.0.extend(data);
            Ok(())
        }
    }
    #[test]
    fn toc_is_indented_like_libxml2() {
        // libxml2's xmlTextWriter with indentation, as upstream uses it.
        let mut xml = Xml::new();
        xml.start("xar");
        xml.start("toc");
        xml.time("creation-time", 0, false);
        xml.start("file");
        xml.attribute("id", "1");
        xml.start("name");
        xml.attribute("enctype", "base64");
        xml.base64(&[0xff; 57]);
        xml.end();
        xml.element("user", "a<&>\"'\r");
        xml.time("mtime", 0, true);
        flags_xml(&mut xml, b"uchg,nodump");
        xml.start("encoding");
        xml.attribute("style", "application/x-gzip");
        xml.end();
        xml.end();
        xml.end();
        xml.end();
        assert_eq!(
            String::from_utf8(xml.out).unwrap(),
            [
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                "<xar>\n",
                " <toc>\n",
                "  <creation-time>1970-01-01T00:00:00</creation-time>\n",
                "  <file id=\"1\">\n",
                "   <name enctype=\"base64\">",
                &"/".repeat(72),
                "\r\n",
                &"/".repeat(4),
                "</name>\n",
                "   <user>a&lt;&amp;&gt;&quot;'&#13;</user>\n",
                "   <mtime>1970-01-01T00:00:00Z</mtime>\n",
                "   <flags/>\n",
                "   <ext2/>\n",
                "   <encoding style=\"application/x-gzip\"/>\n",
                "  </file>\n",
                " </toc>\n",
                "</xar>\n",
            ]
            .concat()
        );
    }
    #[test]
    fn invalid_utf8_path_returns_warning_without_panicking() {
        // Converting names to UTF-8 depends on the locale.
        let _locale = crate::ffi::charset::lock_locale();
        let base = Base::new(WRITE_MAGIC);
        let mut xar = Xar::default();
        let mut entry = Entry::new(None);
        entry.set_pathname(b"invalid-\xff");
        entry.set_mode(libc::S_IFDIR | 0o755);
        assert_eq!(
            xar.header(&base, &mut entry, &mut Output::default())
                .unwrap(),
            ARCHIVE_WARN
        );
    }
    #[test]
    fn invalid_utf8_symlink_returns_warning_at_header() {
        // Converting names to UTF-8 depends on the locale.
        let _locale = crate::ffi::charset::lock_locale();
        let base = Base::new(WRITE_MAGIC);
        let mut xar = Xar::default();
        let mut entry = Entry::new(None);
        entry.set_pathname(b"link");
        entry.set_mode(libc::S_IFLNK | 0o755);
        entry.set_symlink(b"invalid-\xff");
        assert_eq!(
            xar.header(&base, &mut entry, &mut Output::default())
                .unwrap(),
            ARCHIVE_WARN
        );
    }
    #[test]
    fn invalid_owner_charset_aborts_toc_without_emitting_archive() {
        // Converting names to UTF-8 depends on the locale.
        let _locale = crate::ffi::charset::lock_locale();
        for group in [false, true] {
            let base = Base::new(WRITE_MAGIC);
            let mut xar = Xar::default();
            let mut entry = Entry::new(None);
            entry.set_pathname(b"file");
            entry.set_mode(libc::S_IFDIR | 0o755);
            if group {
                entry.set_gname(b"invalid-\xff");
            } else {
                entry.set_uname(b"invalid-\xff");
            }
            let mut out = Output::default();
            assert_eq!(xar.header(&base, &mut entry, &mut out).unwrap(), ARCHIVE_OK);
            assert_eq!(xar.close(&mut out).unwrap_err().code, ARCHIVE_FATAL);
            assert!(out.0.is_empty());
        }
    }
    #[test]
    fn parent_component_limit_does_not_restrict_leaf_names() {
        let mut xar = Xar::default();
        let mut entry = Entry::new(None);
        entry.set_mode(libc::S_IFDIR | 0o755);
        entry.set_pathname(&[vec![b'a'; 256], b"leaf".to_vec()].join(&b'/'));
        let error = xar.add(entry).unwrap_err();
        assert_eq!(error.code, ARCHIVE_FATAL);
        assert_eq!(error.msg, b"A name buffer is too small");
        let mut entry = Entry::new(None);
        entry.set_mode(libc::S_IFDIR | 0o755);
        entry.set_pathname(&vec![b'a'; 512]);
        assert!(xar.add(entry).unwrap().is_some());
    }
    #[test]
    fn upstream_basic_fixture_roundtrips_codecs_and_checksums() {
        for (compression, checksum) in [
            (Compression::None, Checksum::Sha1),
            (Compression::Gzip, Checksum::Sha1),
            (Compression::Bzip2, Checksum::Sha1),
            (Compression::Lzma, Checksum::Sha1),
            (Compression::Xz, Checksum::Sha1),
            (Compression::Gzip, Checksum::None),
            (Compression::Gzip, Checksum::Md5),
            (Compression::Gzip, Checksum::Sha256),
            (Compression::Gzip, Checksum::Sha512),
        ] {
            let a = Base::new(WRITE_MAGIC);
            let mut xar = Xar {
                compression,
                sum: checksum,
                toc_sum: checksum,
                ..Xar::default()
            };
            let mut out = Output::default();
            let mut e = Entry::new(None);
            e.set_pathname(b"file");
            e.set_mode(libc::S_IFREG | 0o755);
            e.set_nlink(2);
            e.set_size(8);
            e.set_atime(2, 20);
            e.set_ctime(4, 40);
            e.set_mtime(5, 50);
            e.xattr_add(c"user.data1", b"ABCDEFG");
            e.xattr_add(c"user.data2", b"XYZ");
            assert_eq!(xar.header(&a, &mut e, &mut out).unwrap(), ARCHIVE_OK);
            assert_eq!(xar.data(b"123456789", &mut out).unwrap(), 8);
            xar.finish_entry(&mut out).unwrap();
            e = Entry::new(None);
            e.set_pathname(b"dir/..//dir/dir2/file4");
            e.set_mode(libc::S_IFREG | 0o755);
            e.set_nlink(2);
            e.set_size(0);
            e.copy_hardlink(b"file");
            assert_eq!(xar.header(&a, &mut e, &mut out).unwrap(), ARCHIVE_OK);
            xar.close(&mut out).unwrap();
            let a = Base::new(READ_MAGIC);
            let mut r = Read::default();
            let _ = crate::read::format::xar::support(&mut r).unwrap();
            assert_eq!(r.open(&a, Box::new(Memory::new(out.0, 7))), ARCHIVE_OK);
            let mut e = Entry::new(None);
            assert_eq!(
                r.next_header2(&a, &mut e),
                ARCHIVE_OK,
                "{:?}",
                a.error_string()
            );
            assert_eq!(e.pathname().unwrap().to_bytes(), b"file");
            assert_eq!(e.mode(), libc::S_IFREG | 0o755);
            assert_eq!(e.nlink(), 2);
            assert_eq!((e.atime(), e.ctime(), e.mtime()), (2, 4, 5));
            assert_eq!((e.atime_nsec(), e.ctime_nsec(), e.mtime_nsec()), (0, 0, 0));
            assert_eq!(e.xattr_reset(), 2);
            assert_eq!(e.xattr_next().1.unwrap().0, c"user.data2");
            let mut buffer = [0; 10];
            assert_eq!(r.read_data(&a, None, &mut buffer), 8);
            assert_eq!(&buffer[..8], b"12345678");
            assert_eq!(
                r.next_header2(&a, &mut e),
                ARCHIVE_OK,
                "{:?}",
                a.error_string()
            );
            assert_eq!(e.pathname().unwrap().to_bytes(), b"dir/dir2/file4");
            assert_eq!(e.hardlink().unwrap().to_bytes(), b"file");
            assert_eq!(e.size(), 0);
            assert_eq!(r.next_header2(&a, &mut e), ARCHIVE_EOF);
            assert_eq!(r.close(&a), ARCHIVE_OK);
        }
    }
}
