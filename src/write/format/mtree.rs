/*-
 * Copyright (c) 2008 Joerg Sonnenberger
 * Copyright (c) 2009-2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_write_set_format_mtree.c.
use crate::archive::*;
use crate::digest::{Algorithm, Digest};
use crate::entry::Entry;
use crate::util::Error;
use crate::write::{Format, Sink};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, c_int};
const KEYS: &[&[u8]] = &[
    b"cksum",
    b"device",
    b"flags",
    b"gid",
    b"gname",
    b"link",
    b"md5",
    b"mode",
    b"nlink",
    b"rmd160",
    b"sha1",
    b"sha256",
    b"sha384",
    b"sha512",
    b"size",
    b"time",
    b"type",
    b"uid",
    b"uname",
    b"inode",
    b"resdevice",
];
const HASHES: &[(i32, &[u8], Algorithm)] = &[
    (1, b"md5", Algorithm::Md5),
    (2, b"rmd160", Algorithm::Rmd160),
    (3, b"sha1", Algorithm::Sha1),
    (4, b"sha256", Algorithm::Sha256),
    (5, b"sha384", Algorithm::Sha384),
    (6, b"sha512", Algorithm::Sha512),
];
struct Record {
    entry: Entry,
    virtual_dir: bool,
    sums: Vec<(&'static [u8], Vec<u8>)>,
    cksum: Option<u32>,
}
pub struct Mtree {
    classic: bool,
    indent: bool,
    use_set: bool,
    dironly: bool,
    keys: BTreeSet<Vec<u8>>,
    entries: BTreeMap<Vec<u8>, Record>,
    current: Option<(Vec<u8>, Record)>,
    digests: Vec<(&'static [u8], Digest)>,
    remaining: u64,
    crc: u32,
    length: u64,
    global: BTreeMap<Vec<u8>, Vec<u8>>,
}
impl Mtree {
    pub fn new(classic: bool) -> Self {
        Self {
            classic,
            indent: false,
            use_set: classic,
            dironly: false,
            keys: [
                b"device".as_slice(),
                b"flags",
                b"gid",
                b"gname",
                b"link",
                b"mode",
                b"nlink",
                b"size",
                b"time",
                b"type",
                b"uid",
                b"uname",
            ]
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect(),
            entries: BTreeMap::new(),
            current: None,
            digests: Vec::new(),
            remaining: 0,
            crc: 0,
            length: 0,
            global: BTreeMap::new(),
        }
    }
    fn enabled(&self, key: &[u8]) -> bool {
        self.keys.contains(key)
    }
}
fn quote(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in s {
        if b > 32 && b < 127 && !matches!(b, b'#' | b'=' | b'\\') {
            out.push(b);
        } else {
            out.extend(format!("\\{b:03o}").as_bytes());
        }
    }
    out
}
fn normalize(path: &[u8]) -> Vec<u8> {
    let mut parts = Vec::new();
    for p in path.split(|&b| b == b'/') {
        if p.is_empty() || p == b"." {
            continue;
        }
        if p == b".." {
            parts.pop();
        } else {
            parts.push(p);
        }
    }
    if parts.is_empty() {
        return b".".to_vec();
    }
    let mut out = b".".to_vec();
    for p in parts {
        out.push(b'/');
        out.extend(p);
    }
    out
}
fn parent(path: &[u8]) -> Vec<u8> {
    path.iter()
        .rposition(|&b| b == b'/')
        .map_or_else(|| b".".to_vec(), |p| path[..p].to_vec())
}
fn kind(e: &Entry) -> &'static [u8] {
    match e.filetype() {
        0o040000 => b"dir",
        0o120000 => b"link",
        0o140000 => b"socket",
        0o020000 => b"char",
        0o060000 => b"block",
        0o010000 => b"fifo",
        _ => b"file",
    }
}
fn crc_step(mut c: u32, b: u8) -> u32 {
    c ^= u32::from(b) << 24;
    for _ in 0..8 {
        c = if c & 0x80000000 != 0 {
            c << 1 ^ 0x04c11db7
        } else {
            c << 1
        };
    }
    c
}
fn metadata(e: &mut Entry, k: &[u8]) -> Vec<u8> {
    match k {
        b"type" => kind(e).to_vec(),
        b"uid" => e.uid().to_string().into_bytes(),
        b"gid" => e.gid().to_string().into_bytes(),
        b"mode" => format!("{:o}", e.mode() & 0o7777).into_bytes(),
        b"flags" => e
            .fflags_text()
            .map(|s| quote(s.to_bytes()))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| b"none".to_vec()),
        b"uname" => e.uname().map(|s| quote(s.to_bytes())).unwrap_or_default(),
        b"gname" => e.gname().map(|s| quote(s.to_bytes())).unwrap_or_default(),
        _ => Vec::new(),
    }
}
impl Mtree {
    fn global_set(&mut self, children: &[Vec<u8>], out: &mut Vec<u8>) {
        if !self.use_set {
            return;
        }
        let mut changes = Vec::new();
        for &key in &[
            b"type".as_slice(),
            b"uname",
            b"uid",
            b"gname",
            b"gid",
            b"mode",
            b"flags",
        ] {
            if !self.enabled(key) {
                continue;
            }
            let mut values = BTreeMap::<Vec<u8>, usize>::new();
            for child in children {
                if let Some(r) = self.entries.get_mut(child) {
                    let v = metadata(&mut r.entry, key);
                    if !v.is_empty() {
                        *values.entry(v).or_default() += 1;
                    }
                }
            }
            let Some((value, count)) = values.into_iter().max_by_key(|(_, n)| *n) else {
                continue;
            };
            if key == b"flags" && value == b"none" && !self.global.contains_key(key) {
                continue;
            }
            if self.global.get(key) == Some(&value) {
                continue;
            }
            if !self.global.is_empty() && count < 2 {
                continue;
            }
            if key == b"type" && self.global.contains_key(key) {
                continue;
            }
            self.global.insert(key.to_vec(), value.clone());
            changes.push((key, value));
        }
        if !changes.is_empty() {
            out.extend(b"/set");
            for (k, v) in changes {
                out.push(b' ');
                out.extend(k);
                out.push(b'=');
                out.extend(v);
            }
            out.push(b'\n');
        }
    }
    fn line(&mut self, path: &[u8], depth: usize, out: &mut Vec<u8>) {
        let keys = self.keys.clone();
        let Some(r) = self.entries.get_mut(path) else {
            return;
        };
        if r.virtual_dir && !self.classic {
            return;
        }
        let e = &mut r.entry;
        let mut attrs = Vec::new();
        let mut add = |key: &[u8], value: Vec<u8>| {
            if keys.contains(key)
                && !value.is_empty()
                && self.global.get(key).is_none_or(|g| g != &value)
            {
                attrs.push([key, b"=", &value].concat());
            }
        };
        if e.nlink() != 0 && e.nlink() != 1 && e.filetype() != 0o040000 {
            add(b"nlink", e.nlink().to_string().into_bytes());
        }
        add(b"gname", metadata(e, b"gname"));
        add(b"uname", metadata(e, b"uname"));
        if keys.contains(b"flags".as_slice()) {
            let flags = metadata(e, b"flags");
            if flags != b"none" || self.global.contains_key(b"flags".as_slice()) {
                add(b"flags", flags);
            }
        }
        add(
            b"time",
            format!("{}.{}", e.mtime(), e.mtime_nsec()).into_bytes(),
        );
        for key in [b"mode".as_slice(), b"gid", b"uid"] {
            add(key, metadata(e, key));
        }
        add(b"inode", e.ino().to_string().into_bytes());
        add(
            b"resdevice",
            format!("native,{},{}", e.devmajor(), e.devminor()).into_bytes(),
        );
        add(b"type", kind(e).to_vec());
        if e.filetype() == 0o120000 {
            add(
                b"link",
                e.symlink().map(|s| quote(s.to_bytes())).unwrap_or_default(),
            );
        }
        if matches!(e.filetype(), 0o020000 | 0o060000) {
            add(
                b"device",
                format!("native,{},{}", e.rdevmajor(), e.rdevminor()).into_bytes(),
            );
        }
        if !matches!(
            e.filetype(),
            0o040000 | 0o120000 | 0o010000 | 0o020000 | 0o060000 | 0o140000
        ) {
            add(b"size", e.size().to_string().into_bytes());
        }
        if let Some(c) = r.cksum {
            attrs.push(format!("cksum={c}").into_bytes());
        }
        for (key, digest) in &r.sums {
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            attrs.push([*key, b"digest=", hex.as_bytes()].concat());
        }
        let name = quote(if self.classic {
            path.rsplit(|&b| b == b'/').next().unwrap_or(path)
        } else {
            path
        });
        if self.classic || self.indent {
            let pad = if self.classic {
                if self.indent {
                    depth * 4
                } else {
                    usize::from(depth > 0) * 4
                }
            } else {
                0
            };
            out.resize(out.len() + pad, b' ');
            out.extend(&name);
            let spaces = if self.classic && self.indent {
                16usize.saturating_sub(name.len())
            } else {
                16usize.saturating_sub(name.len() + pad)
            };
            if !attrs.is_empty() {
                out.resize(out.len() + spaces.max(1), b' ');
            }
        } else {
            out.extend(&name);
            if !attrs.is_empty() {
                out.push(b' ');
            }
        }
        for (i, attr) in attrs.iter().enumerate() {
            if i != 0 {
                out.push(b' ');
            }
            out.extend(attr);
        }
        out.push(b'\n');
    }
}
impl Format for Mtree {
    fn code(&self) -> c_int {
        0x80000
    }
    fn name(&self) -> &'static CStr {
        c"mtree"
    }
    fn module(&self) -> &'static [u8] {
        b"mtree"
    }
    fn options(&mut self, _: &Base, key: &[u8], value: Option<&[u8]>) -> Result<c_int, Error> {
        match key {
            b"use-set" => self.use_set = value.is_some(),
            b"dironly" => self.dironly = value.is_some(),
            b"indent" => self.indent = value.is_some(),
            b"all" => {
                self.keys.clear();
                if value.is_some() {
                    self.keys.extend(KEYS.iter().map(|k| k.to_vec()));
                }
            }
            _ => {
                let key = if key.ends_with(b"digest") {
                    &key[..key.len() - 6]
                } else {
                    key
                };
                let key = if key == b"ripemd160" {
                    b"rmd160".as_slice()
                } else {
                    key
                };
                if !KEYS.contains(&key) {
                    return Ok(ARCHIVE_WARN);
                }
                if value.is_some() {
                    self.keys.insert(key.to_vec());
                } else {
                    self.keys.remove(key);
                }
            }
        }
        Ok(ARCHIVE_OK)
    }
    fn header(&mut self, _: &Base, e: &mut Entry, _: &mut dyn Sink) -> Result<c_int, Error> {
        let path = e
            .pathname()
            .map(|s| s.to_bytes().to_vec())
            .ok_or_else(|| Error::new(ARCHIVE_FAILED, -1, "Pathname required"))?;
        let path = normalize(&path);
        if path == b"." && e.filetype() != 0o040000 {
            return Err(Error::new(
                ARCHIVE_FAILED,
                -1,
                "mtree root must be a directory",
            ));
        }
        if path.len() > 1048576 || path.iter().filter(|&&b| b == b'/').count() > 1000 {
            return Err(Error::fatal(libc::ENOMEM, "mtree pathname is too long"));
        }
        self.remaining = e.size().max(0) as u64;
        self.crc = 0;
        self.length = 0;
        let mut record = Record {
            entry: e.clone_entry(),
            virtual_dir: false,
            sums: Vec::new(),
            cksum: None,
        };
        self.digests.clear();
        if matches!(e.filetype(), 0 | 0o100000) {
            for &(id, key, algorithm) in HASHES {
                if self.enabled(key) {
                    if e.digest_is_set(id) {
                        record
                            .sums
                            .push((key, e.digest(id).unwrap_or_default().to_vec()));
                    }
                    self.digests.push((key, Digest::new(algorithm)));
                }
            }
        }
        self.current = Some((path, record));
        Ok(ARCHIVE_OK)
    }
    fn data(&mut self, data: &[u8], _: &mut dyn Sink) -> Result<usize, Error> {
        let n = data.len().min(self.remaining as usize);
        self.remaining -= n as u64;
        self.length += n as u64;
        for (_, d) in &mut self.digests {
            d.update(&data[..n]);
        }
        if self.enabled(b"cksum") {
            for &b in &data[..n] {
                self.crc = crc_step(self.crc, b);
            }
        }
        Ok(n)
    }
    fn finish_entry(&mut self, _: &mut dyn Sink) -> Result<(), Error> {
        let Some((path, mut record)) = self.current.take() else {
            return Ok(());
        };
        for (key, d) in self.digests.drain(..) {
            if self.length == 0 && record.sums.iter().any(|(k, _)| *k == key) {
                continue;
            }
            record.sums.retain(|(k, _)| *k != key);
            record.sums.push((key, d.finalize()));
        }
        if self.enabled(b"cksum") && matches!(record.entry.filetype(), 0 | 0o100000) {
            let mut len = self.length;
            while len != 0 {
                self.crc = crc_step(self.crc, len as u8);
                len >>= 8;
            }
            record.cksum = Some(!self.crc);
        }
        if !self.dironly || record.entry.filetype() == 0o040000 {
            self.entries.insert(path, record);
        }
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if self.entries.is_empty() {
            return Ok(());
        }
        let original: Vec<Vec<u8>> = self.entries.keys().cloned().collect();
        for path in original {
            let mut p = parent(&path);
            while !self.entries.contains_key(&p) {
                let mut e = Entry::new(None);
                e.set_pathname(&p);
                e.set_mode(0o040755);
                self.entries.insert(
                    p.clone(),
                    Record {
                        entry: e,
                        virtual_dir: true,
                        sums: Vec::new(),
                        cksum: None,
                    },
                );
                if p == b"." {
                    break;
                }
                p = parent(&p);
            }
        }
        let mut children: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
        for path in self.entries.keys() {
            if path != b"." {
                children.entry(parent(path)).or_default().push(path.clone());
            }
        }
        let mut out = b"#mtree\n".to_vec();
        let mut stack = vec![(b".".to_vec(), 0usize, false)];
        while let Some((path, depth, leave)) = stack.pop() {
            let is_dir = self
                .entries
                .get(&path)
                .is_some_and(|r| r.entry.filetype() == 0o040000);
            if leave {
                if self.classic {
                    let pad = if self.indent { depth * 4 } else { 0 };
                    if path != b"." {
                        out.resize(out.len() + pad, b' ');
                        out.extend([b"# ".as_slice(), &path, b"\n"].concat());
                    }
                    out.resize(out.len() + pad, b' ');
                    out.extend(if self.dironly {
                        b"..\n".as_slice()
                    } else {
                        b"..\n\n"
                    });
                }
                continue;
            }
            if is_dir {
                let ch = children.get(&path).cloned().unwrap_or_default();
                if self.classic {
                    if !self.dironly {
                        out.push(b'\n');
                    }
                    out.extend([b"# ".as_slice(), &path, b"\n"].concat());
                }
                self.global_set(&ch, &mut out);
                self.line(&path, depth, &mut out);
                stack.push((path.clone(), depth, true));
                let mut dirs = Vec::new();
                for child in ch {
                    if self
                        .entries
                        .get(&child)
                        .is_some_and(|r| r.entry.filetype() == 0o040000)
                    {
                        dirs.push(child);
                    } else {
                        self.line(&child, depth + 1, &mut out);
                    }
                }
                for child in dirs.into_iter().rev() {
                    stack.push((child, if self.indent { depth + 1 } else { 0 }, false));
                }
            } else {
                self.line(&path, depth, &mut out);
            }
        }
        sink.write(&out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Output(Vec<u8>);
    impl Sink for Output {
        fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.0.extend(data);
            Ok(())
        }
    }
    #[test]
    fn preset_digests_survive_empty_data_and_are_replaced_by_written_data() {
        for data in [b"".as_slice(), b"abcd"] {
            let mut mtree = Mtree::new(false);
            let base = Base::new(WRITE_MAGIC);
            mtree.options(&base, b"all", Some(b"1")).unwrap();
            let mut entry = Entry::new(None);
            entry.set_pathname(b"data");
            entry.set_filetype(0o100000);
            entry.set_size(4);
            let mut expected = Vec::new();
            for &(id, key, alg) in HASHES {
                let n = entry.digest(id).unwrap().len();
                entry.set_digest(id, &vec![0xab; n]);
                let digest = if data.is_empty() {
                    vec![0xab; n]
                } else {
                    let mut d = Digest::new(alg);
                    d.update(data);
                    d.finalize()
                };
                expected.push((key, digest));
            }
            let mut out = Output(Vec::new());
            mtree.header(&base, &mut entry, &mut out).unwrap();
            mtree.data(data, &mut out).unwrap();
            mtree.finish_entry(&mut out).unwrap();
            mtree.close(&mut out).unwrap();
            let output = String::from_utf8(out.0).unwrap();
            for (key, digest) in expected {
                let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                assert!(output.contains(&format!(
                    "{}digest={hex}",
                    std::str::from_utf8(key).unwrap()
                )));
            }
        }
    }
}
