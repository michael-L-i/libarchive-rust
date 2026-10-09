/*-
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

// Ported from libarchive/archive_write_set_format_iso9660.c.
use crate::archive::*;
use crate::entry::Entry;
use crate::util::Error;
use crate::write::{Format, Sink, zeros};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{CStr, c_int};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
const BLOCK: usize = 2048;
const ER:&[u8]=b"ER\xed\x01\x0aT\x87\x01RRIP_1991ATHE ROCK RIDGE INTERCHANGE PROTOCOL PROVIDES SUPPORT FOR POSIX FILE SYSTEM SEMANTICSPLEASE CONTACT DISC PUBLISHER FOR SPECIFICATION SOURCE.  SEE PUBLISHER IDENTIFIER IN PRIMARY VOLUME DESCRIPTOR FOR CONTACT INFORMATION.";
// boot.rs is implemented independently by the integration agent.
mod boot;
mod info;
use boot::{Boot, Media};
struct Node {
    entry: Entry,
    name: Vec<u8>,
    path: Vec<u8>,
    parent: usize,
    children: Vec<usize>,
    ident: [Vec<u8>; 2],
    directory: bool,
    virtual_dir: bool,
    offset: u64,
    size: u64,
    extent: u32,
    hardlink: Option<usize>,
    symlink: Vec<u8>,
    zisofs: Option<(u32, u8, u8)>,
    rr_child: Option<usize>,
    rr_parent: Option<usize>,
    joliet_hidden: bool,
}
impl Node {
    fn new(mut entry: Entry, path: Vec<u8>, parent: usize, virtual_dir: bool) -> Self {
        let name = path
            .rsplit(|&b| b == b'/')
            .next()
            .unwrap_or_default()
            .to_vec();
        let directory = entry.filetype() == 0o40000;
        let symlink = entry
            .symlink()
            .map_or_else(Vec::new, |s| s.to_bytes().to_vec());
        Self {
            entry,
            name,
            path,
            parent,
            children: Vec::new(),
            ident: [Vec::new(), Vec::new()],
            directory,
            virtual_dir,
            offset: 0,
            size: 0,
            extent: 0,
            hardlink: None,
            symlink,
            zisofs: None,
            rr_child: None,
            rr_parent: None,
            joliet_hidden: false,
        }
    }
}
#[derive(Default)]
struct DirLayout {
    location: u32,
    blocks: u32,
    extra_blocks: u32,
}
struct Tree {
    directories: Vec<usize>,
    order: Vec<usize>,
    numbers: HashMap<usize, u16>,
    layout: HashMap<usize, DirLayout>,
    path_size: u32,
    path_blocks: u32,
    path_l: u32,
    path_m: u32,
}
pub struct Iso9660 {
    nodes: Vec<Node>,
    names: HashMap<Vec<u8>, usize>,
    spool: Option<File>,
    spool_size: u64,
    data_order: Vec<usize>,
    current: Option<usize>,
    remaining: u64,
    level: u8,
    joliet: u8,
    rr: u8,
    pad: bool,
    limit_depth: bool,
    limit_dirs: bool,
    allow_vernum: bool,
    zisofs: bool,
    compression: u8,
    strings: HashMap<Vec<u8>, Vec<u8>>,
    boot: Boot,
    boot_enabled: bool,
    boot_floppy: bool,
    boot_auto: bool,
    birth: i64,
    er_location: u32,
    primary_children: HashMap<usize, Vec<usize>>,
    primary_parent: HashMap<usize, usize>,
    too_deep: Option<usize>,
    info_options: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}
impl Default for Iso9660 {
    fn default() -> Self {
        let mut root = Entry::new(None);
        root.set_mode(0o40555);
        root.set_nlink(2);
        let mut names = HashMap::new();
        names.insert(Vec::new(), 0);
        let mut strings = HashMap::new();
        strings.insert(b"volume-id".to_vec(), b"CDROM".to_vec());
        strings.insert(b"application-id".to_vec(), b"libarchive 3.9.0dev".to_vec());
        Self {
            nodes: vec![Node::new(root, Vec::new(), 0, true)],
            names,
            spool: None,
            spool_size: 0,
            data_order: Vec::new(),
            current: None,
            remaining: 0,
            level: 1,
            joliet: 1,
            rr: 2,
            pad: true,
            limit_depth: true,
            limit_dirs: true,
            allow_vernum: true,
            zisofs: false,
            compression: 6,
            strings,
            boot: Boot {
                filename: Vec::new(),
                catalog: b"boot.catalog".to_vec(),
                info_table: false,
                load_segment: 0,
                load_size: 4,
                media: Media::NoEmulation,
                system_type: 0,
                platform_id: 0,
                identifier: Vec::new(),
            },
            boot_enabled: false,
            boot_floppy: false,
            boot_auto: true,
            birth: 0,
            er_location: 0,
            primary_children: HashMap::new(),
            primary_parent: HashMap::new(),
            too_deep: None,
            info_options: Vec::new(),
        }
    }
}
fn io_error(e: std::io::Error) -> Error {
    Error::fatal(e.raw_os_error().unwrap_or(libc::EIO), e.to_string())
}
fn bad(key: &[u8]) -> Error {
    Error::new(
        ARCHIVE_FAILED,
        -1,
        [b"Invalid value for option ``".as_slice(), key, b"''"].concat(),
    )
}
fn normalize(path: &[u8]) -> Vec<u8> {
    let mut components = Vec::new();
    for part in path.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                components.pop();
            }
            _ => components.push(part),
        }
    }
    let mut out = Vec::new();
    for p in components {
        if !out.is_empty() {
            out.push(b'/')
        }
        out.extend_from_slice(p);
    }
    out
}
fn both32(n: u32) -> [u8; 8] {
    let mut b = [0; 8];
    b[..4].copy_from_slice(&n.to_le_bytes());
    b[4..].copy_from_slice(&n.to_be_bytes());
    b
}
fn both16(n: u16) -> [u8; 4] {
    let mut b = [0; 4];
    b[..2].copy_from_slice(&n.to_le_bytes());
    b[2..].copy_from_slice(&n.to_be_bytes());
    b
}
fn date(secs: i64) -> [u8; 7] {
    let Some(t) = crate::ffi::sys::localtime(secs) else {
        return [0; 7];
    };
    let local = crate::time::days_from_civil(
        i64::from(t.year) + 1900,
        i64::from(t.mon) + 1,
        i64::from(t.mday),
    )
    .saturating_mul(86400)
    .saturating_add(i64::from(t.hour) * 3600 + i64::from(t.min) * 60 + i64::from(t.sec));
    let offset = (local.saturating_sub(secs) / 900).clamp(-48, 52) as i8;
    [
        t.year as u8,
        (t.mon + 1) as u8,
        t.mday as u8,
        t.hour as u8,
        t.min as u8,
        t.sec as u8,
        offset as u8,
    ]
}
fn volume_date(secs: i64) -> [u8; 17] {
    let mut out = [b'0'; 17];
    if let Some(t) = crate::ffi::sys::localtime(secs) {
        let s = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}00",
            t.year + 1900,
            t.mon + 1,
            t.mday,
            t.hour,
            t.min,
            t.sec
        );
        if s.len() == 16 {
            out[..16].copy_from_slice(s.as_bytes())
        }
    }
    out[16] = date(secs)[6];
    out
}
fn rr_field(sig: &[u8; 2], data: &[u8]) -> Vec<u8> {
    let mut out = vec![sig[0], sig[1], (data.len() + 4) as u8, 1];
    out.extend_from_slice(data);
    out
}
fn continuation(block: u32, offset: u32, len: u32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&both32(block));
    data.extend_from_slice(&both32(offset));
    data.extend_from_slice(&both32(len));
    rr_field(b"CE", &data)
}
fn ascii_identifier(
    name: &[u8],
    directory: bool,
    level: u8,
    rr: bool,
    allow_vernum: bool,
) -> Vec<u8> {
    let max = if level == 1 {
        8
    } else if level <= 3 {
        31
    } else if rr {
        193
    } else {
        207
    };
    if level == 4 {
        let mut id: Vec<u8> = name
            .iter()
            .copied()
            .map(|b| if b == b'/' || b == 0 { b'_' } else { b })
            .take(max)
            .collect();
        while id.last() == Some(&b'.') {
            id.pop();
        }
        if id.is_empty() {
            id.push(b'_');
        }
        return id;
    }
    let mut mapped: Vec<_> = name
        .iter()
        .copied()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' {
                b.to_ascii_uppercase()
            } else {
                b'_'
            }
        })
        .collect();
    if directory {
        for b in &mut mapped {
            if *b == b'.' {
                *b = b'_'
            }
        }
        mapped.truncate(max);
        return mapped;
    }
    if !allow_vernum {
        for b in &mut mapped {
            if *b == b';' {
                *b = b'_'
            }
        }
    }
    let dot = mapped.iter().rposition(|&b| b == b'.');
    let (stem, ext) = dot.map_or((mapped.as_slice(), &[][..]), |i| {
        (&mapped[..i], &mapped[i + 1..])
    });
    let mut stem = stem.to_vec();
    for b in &mut stem {
        if *b == b'.' {
            *b = b'_'
        }
    }
    let extmax = if level == 1 { 3 } else { ext.len().min(29) };
    let ext = &ext[..ext.len().min(extmax)];
    stem.truncate(if level == 1 { 8 } else { 30 - ext.len() });
    if stem.is_empty() {
        stem.push(b'_')
    }
    stem.push(b'.');
    stem.extend_from_slice(ext);
    if allow_vernum {
        stem.extend_from_slice(b";1");
    }
    stem
}
impl Iso9660 {
    fn ensure_spool(&mut self) -> Result<&mut File, Error> {
        if self.spool.is_none() {
            self.spool = Some(crate::write::temp_file()?);
        }
        self.spool
            .as_mut()
            .ok_or_else(|| Error::fatal(-1, "Missing ISO temporary file"))
    }
    fn append(&mut self, data: &[u8]) -> Result<(), Error> {
        self.ensure_spool()?.write_all(data).map_err(io_error)?;
        self.spool_size = self
            .spool_size
            .checked_add(data.len() as u64)
            .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "ISO image too large"))?;
        Ok(())
    }
    fn directory(&mut self, path: &[u8]) -> Result<usize, Error> {
        let mut parent = 0;
        let mut prefix = Vec::new();
        for component in path.split(|&b| b == b'/').filter(|p| !p.is_empty()) {
            if !prefix.is_empty() {
                prefix.push(b'/');
            }
            prefix.extend_from_slice(component);
            if let Some(&i) = self.names.get(&prefix) {
                if !self.nodes[i].directory {
                    return Err(Error::new(
                        ARCHIVE_FAILED,
                        -1,
                        [b"`".as_slice(), prefix.as_slice(), b"' is not directory"].concat(),
                    ));
                }
                parent = i;
                continue;
            }
            let mut entry = Entry::new(None);
            entry.set_mode(0o40555);
            entry.set_nlink(2);
            entry.set_pathname(&prefix);
            let i = self.nodes.len();
            self.nodes
                .try_reserve(1)
                .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate data"))?;
            self.nodes
                .push(Node::new(entry, prefix.clone(), parent, true));
            self.nodes[parent].children.push(i);
            self.names.insert(prefix.clone(), i);
            parent = i;
        }
        Ok(parent)
    }
    fn identifiers(&mut self) -> Result<(), Error> {
        let conv = crate::string::conversion_to_charset(None, b"UTF-16BE", true)
            .map_err(|e| Error::fatal(e.errno, e.message))?;
        for i in 1..self.nodes.len() {
            let node = &mut self.nodes[i];
            node.ident[0] = ascii_identifier(
                &node.name,
                node.directory,
                self.level,
                self.rr != 0,
                self.allow_vernum,
            );
            if self.joliet == 0 {
                continue;
            }
            let mut joliet = Vec::new();
            if crate::string::strncpy_l(&mut joliet, &node.name, Some(&conv)).is_err() {
                return Err(Error::fatal(
                    -1,
                    "A filename cannot be converted to UTF-16BE;You should disable making Joliet extension",
                ));
            }
            let max = if self.joliet == 2 { 206 } else { 128 };
            joliet.truncate(max);
            for unit in joliet.chunks_exact_mut(2) {
                let ch = u16::from_be_bytes([unit[0], unit[1]]);
                if ch < 32 || b"*/:;?\\".contains(&(ch as u8)) && ch < 128 {
                    unit.copy_from_slice(&[0, b'_']);
                }
            }
            node.ident[1] = joliet;
        }
        for parent in 0..self.nodes.len() {
            for tree in 0..2 {
                let children = self.children(parent, tree);
                let mut used = HashSet::new();
                for &i in &children {
                    let base = self.nodes[i].ident[tree].clone();
                    let mut name = base.clone();
                    let mut counter = 0;
                    while used.contains(&name) {
                        let suffix = format!("{counter:03}");
                        counter += 1;
                        if counter > 1000 {
                            return Err(Error::fatal(-1, "Too many duplicate ISO identifiers"));
                        }
                        if tree == 0 {
                            let ext = base.iter().rposition(|&b| b == b'.').unwrap_or(base.len());
                            let capacity: usize = if self.level == 1 {
                                8
                            } else if self.level <= 3 {
                                31usize.saturating_sub((base.len() - ext).saturating_sub(
                                    if self.nodes[i].directory || !self.allow_vernum {
                                        0
                                    } else {
                                        2
                                    },
                                ))
                            } else {
                                let max = if self.rr != 0 { 193usize } else { 207usize };
                                max.saturating_sub(base.len() - ext)
                            };
                            let stem = &base[..ext.min(capacity.saturating_sub(3))];
                            name = stem.to_vec();
                            name.extend_from_slice(suffix.as_bytes());
                            name.extend_from_slice(&base[ext..]);
                        } else {
                            let max = if self.joliet == 2 { 206 } else { 128 };
                            name = base[..base.len().min(max - 6)].to_vec();
                            for b in suffix.bytes() {
                                name.extend_from_slice(&[0, b]);
                            }
                        }
                    }
                    used.insert(name.clone());
                    self.nodes[i].ident[tree] = name;
                }
            }
        }
        if self.joliet != 0 {
            let mut queue = VecDeque::from([(0, 0usize)]);
            while let Some((parent, parent_len)) = queue.pop_front() {
                for child in self.children(parent, 1) {
                    let id = &self.nodes[child].ident[1];
                    let units: Vec<u16> = id
                        .chunks_exact(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    let name_len = String::from_utf16_lossy(&units).len();
                    if parent_len.checked_add(name_len).is_none_or(|n| n > 240) {
                        return Err(Error::fatal(
                            -1,
                            "The regulation of Joliet extensions; A length of a full-pathname is longer than 240 bytes",
                        ));
                    }
                    if self.is_dir(child, 1) {
                        queue.push_back((child, parent_len + name_len + 1));
                    }
                }
            }
        }
        Ok(())
    }
    fn children(&self, index: usize, kind: usize) -> Vec<usize> {
        if kind == 0 {
            self.primary_children
                .get(&index)
                .unwrap_or(&self.nodes[index].children)
                .clone()
        } else {
            self.nodes[index]
                .children
                .iter()
                .copied()
                .filter(|&i| !self.nodes[i].joliet_hidden)
                .collect()
        }
    }
    fn parent(&self, index: usize, kind: usize) -> usize {
        if kind == 0 {
            self.primary_parent
                .get(&index)
                .copied()
                .unwrap_or(self.nodes[index].parent)
        } else {
            self.nodes[index].parent
        }
    }
    fn is_dir(&self, index: usize, kind: usize) -> bool {
        if kind == 0 {
            self.nodes[index].directory
        } else {
            self.nodes[index].entry.filetype() == 0o40000
        }
    }
    fn relocate(&mut self) -> Result<(), Error> {
        if !self.limit_depth || self.level >= 4 {
            return Ok(());
        }
        if self.rr == 0 {
            let mut queue = VecDeque::from([(0, 0usize)]);
            while let Some((parent, depth)) = queue.pop_front() {
                let children = self.children(parent, 0);
                if depth >= 7 && !children.is_empty() {
                    self.too_deep = Some(parent);
                    self.primary_children.insert(parent, Vec::new());
                    continue;
                }
                for child in children {
                    if self.nodes[child].directory {
                        queue.push_back((child, depth + 1));
                    }
                }
            }
            return Ok(());
        }
        let mut moved = None;
        let mut queue = VecDeque::from([(0, 0usize)]);
        while let Some((parent, depth)) = queue.pop_front() {
            for child in self.children(parent, 0) {
                if !self.nodes[child].directory {
                    continue;
                }
                if depth < 7 {
                    queue.push_back((child, depth + 1));
                    continue;
                }
                let target = if let Some(i) = moved {
                    i
                } else {
                    let existed = self.names.contains_key(b"rr_moved".as_slice());
                    let i = self.directory(b"rr_moved")?;
                    if !existed {
                        self.nodes[i].joliet_hidden = true;
                    }
                    moved = Some(i);
                    i
                };
                if self
                    .children(target, 0)
                    .iter()
                    .any(|&i| self.nodes[i].name == self.nodes[child].name)
                {
                    return Err(Error::fatal(-1, "Duplicate relocated directory name"));
                }
                let mut node = Node::new(
                    self.nodes[child].entry.clone_entry(),
                    self.nodes[child].path.clone(),
                    target,
                    false,
                );
                node.children = self.nodes[child].children.clone();
                node.rr_parent = Some(parent);
                node.joliet_hidden = true;
                let relocated = self.nodes.len();
                self.nodes.push(node);
                self.nodes[child].rr_child = Some(relocated);
                self.nodes[child].directory = false;
                self.primary_children.insert(child, Vec::new());
                for &i in &self.nodes[relocated].children {
                    self.primary_parent.insert(i, relocated);
                }
                let mut children = self.children(target, 0);
                children.push(relocated);
                self.primary_children.insert(target, children);
                queue.push_back((relocated, 2));
            }
        }
        Ok(())
    }
    fn tree(&self, kind: usize) -> Result<Tree, Error> {
        let mut directories = Vec::new();
        let mut queue = VecDeque::from([0]);
        while let Some(i) = queue.pop_front() {
            directories.push(i);
            let mut children: Vec<_> = self
                .children(i, kind)
                .into_iter()
                .filter(|&c| self.is_dir(c, kind))
                .collect();
            children.sort_by(|&a, &b| self.nodes[a].ident[kind].cmp(&self.nodes[b].ident[kind]));
            queue.extend(children);
        }
        if self.limit_dirs && directories.len() > u16::MAX as usize {
            return Err(Error::fatal(-1, "Too many directories"));
        }
        let numbers = directories
            .iter()
            .enumerate()
            .map(|(n, &i)| (i, (n + 1) as u16))
            .collect();
        let size = directories
            .iter()
            .try_fold(0usize, |size, &i| {
                let n = if i == 0 {
                    1
                } else {
                    self.nodes[i].ident[kind].len()
                };
                size.checked_add(8 + n + n % 2)
            })
            .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "ISO path table too large"))?;
        let path_size = u32::try_from(size)
            .map_err(|_| Error::fatal(libc::EOVERFLOW, "ISO path table too large"))?;
        let mut order = Vec::new();
        let mut stack = vec![0];
        while let Some(i) = stack.pop() {
            order.push(i);
            let mut children: Vec<_> = self
                .children(i, kind)
                .into_iter()
                .filter(|&c| self.is_dir(c, kind))
                .collect();
            children.sort_by(|&a, &b| self.nodes[b].ident[kind].cmp(&self.nodes[a].ident[kind]));
            if kind == 0 {
                children.sort_by_key(|&i| self.nodes[i].name == b"rr_moved");
            }
            stack.extend(children);
        }
        Ok(Tree {
            directories,
            order,
            numbers,
            layout: HashMap::new(),
            path_size,
            path_blocks: (path_size as usize).div_ceil(4096) as u32 * 2,
            path_l: 0,
            path_m: 0,
        })
    }
    fn rr(&self, index: usize, kind: u8) -> Vec<Vec<u8>> {
        let original = &self.nodes[index];
        let node = if kind == 4 {
            &self.nodes[original.rr_parent.unwrap_or(index)]
        } else {
            original
        };
        let e = &node.entry;
        let mut out = Vec::new();
        if index == 0 && kind == 0 {
            out.push(rr_field(b"SP", &[0xbe, 0xef, 0]));
        }
        let mut flags = 0x81;
        if kind == 2 {
            flags |= 8;
            if e.filetype() == 0o120000 {
                flags |= 4
            }
            if matches!(e.filetype(), 0o20000 | 0o60000) {
                flags |= 2
            }
        }
        if kind == 2 && node.rr_child.is_some() {
            flags |= 0x10;
        }
        if kind == 2 && node.rr_parent.is_some() {
            flags |= 0x40;
        }
        if kind == 4 {
            flags |= 0x20;
        }
        out.push(rr_field(b"RR", &[flags]));
        if kind == 2 {
            if let Some(i) = node.rr_child {
                out.push(rr_field(b"CL", &both32(self.nodes[i].extent)));
            }
            if node.rr_parent.is_some() {
                out.push(rr_field(b"RE", &[]));
            }
        }
        if kind == 4 {
            out.push(rr_field(b"PL", &both32(node.extent)));
        }
        if kind == 2 {
            let count = node.name.len().div_ceil(250);
            for (n, name) in node.name.chunks(250).enumerate() {
                let mut data = vec![u8::from(n + 1 < count)];
                data.extend_from_slice(name);
                out.push(rr_field(b"NM", &data));
            }
        }
        let mut mode = u32::from(e.mode());
        if self.rr == 2 {
            mode |= 0o444;
            if mode & 0o111 != 0 {
                mode |= 0o111
            }
            mode &= !0o7222;
        }
        let mut px = Vec::new();
        let serial = if node.directory {
            node.extent
        } else if let Some(i) = node.hardlink {
            self.nodes[i].extent
        } else {
            node.extent
        };
        for n in [mode, e.nlink(), e.uid() as u32, e.gid() as u32, serial] {
            px.extend_from_slice(&both32(n));
        }
        out.push(rr_field(b"PX", &px));
        if kind == 2 && e.filetype() == 0o120000 {
            let sym = node.symlink.as_slice();
            let mut components = Vec::new();
            if sym.starts_with(b"/") {
                components.push(vec![8, 0]);
            }
            for component in sym.split(|&b| b == b'/').filter(|p| !p.is_empty()) {
                match component {
                    b"." => components.push(vec![2, 0]),
                    b".." => components.push(vec![4, 0]),
                    _ => {
                        let count = component.len().div_ceil(245);
                        for (n, c) in component.chunks(245).enumerate() {
                            let mut p = vec![u8::from(n + 1 < count), c.len() as u8];
                            p.extend_from_slice(c);
                            components.push(p);
                        }
                    }
                }
            }
            let mut data = vec![0];
            for component in components {
                if data.len() + component.len() > 251 {
                    data[0] = 1;
                    out.push(rr_field(b"SL", &data));
                    data = vec![0];
                }
                data.extend(component);
            }
            out.push(rr_field(b"SL", &data));
        }
        if kind == 2 && matches!(e.filetype(), 0o20000 | 0o60000) {
            let mut data = Vec::new();
            data.extend_from_slice(&both32(e.rdevmajor() as u32));
            data.extend_from_slice(&both32(e.rdevminor() as u32));
            out.push(rr_field(b"PN", &data));
        }
        let times = [
            (
                e.birthtime_is_set() != 0 && e.birthtime() <= e.mtime(),
                e.birthtime(),
                1,
            ),
            (e.mtime_is_set() != 0, e.mtime(), 2),
            (e.atime_is_set() != 0, e.atime(), 4),
            (e.ctime_is_set() != 0, e.ctime(), 8),
        ];
        let mut data = vec![0];
        for (set, seconds, flag) in times {
            if set {
                data[0] |= flag;
                data.extend_from_slice(&date(seconds));
            }
        }
        out.push(rr_field(b"TF", &data));
        if kind == 2
            && let Some((size, header, log)) = node.zisofs
        {
            let mut data = vec![b'p', b'z', header, log];
            data.extend_from_slice(&both32(size));
            out.push(rr_field(b"ZF", &data));
        }
        if index == 0 && kind == 0 {
            out.push(continuation(self.er_location, 0, ER.len() as u32));
        }
        out
    }
    fn record(
        &self,
        index: usize,
        id: &[u8],
        kind: u8,
        tree: &Tree,
        placement: (usize, u32, Option<(u32, u32, bool)>),
        extra: &mut Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let (tree_kind, extra_base, segment) = placement;
        let actual = if kind == 4 {
            self.nodes[index].rr_parent.unwrap_or(index)
        } else {
            index
        };
        let node = &self.nodes[actual];
        let data_node = node.hardlink.map_or(node, |n| &self.nodes[n]);
        let mut out = vec![0; 33 + id.len() + usize::from(id.len().is_multiple_of(2))];
        if out.len() > 254 {
            return Err(Error::fatal(-1, "ISO identifier too long"));
        }
        let (extent, len) = if self.is_dir(actual, tree_kind) {
            let l = tree.layout.get(&actual);
            (
                l.map_or(0, |l| l.location),
                l.map_or(2048, |l| l.blocks * BLOCK as u32),
            )
        } else {
            (
                data_node.extent,
                if segment.is_some() {
                    0
                } else {
                    u32::try_from(data_node.size)
                        .map_err(|_| Error::fatal(-1, "ISO extent too large"))?
                },
            )
        };
        let (extent, len, multi) = segment.unwrap_or((extent, len, false));
        out[2..10].copy_from_slice(&both32(extent));
        out[10..18].copy_from_slice(&both32(len));
        out[18..25].copy_from_slice(&date(node.entry.mtime()));
        out[25] = if self.is_dir(actual, tree_kind) { 2 } else { 0 };
        if multi {
            out[25] |= 0x80;
        }
        out[28..32].copy_from_slice(&both16(1));
        out[32] = id.len() as u8;
        out[33..33 + id.len()].copy_from_slice(id);
        if tree_kind == 0 && self.rr != 0 && kind != 3 {
            let fields = self.rr(index, kind);
            let full = fields.iter().map(Vec::len).sum::<usize>();
            if out.len() + full <= 254 {
                for field in fields {
                    out.extend(field);
                }
            } else {
                let mut remaining = Vec::new();
                let mut overflow = false;
                for field in fields {
                    if !overflow && out.len() + field.len() + 28 <= 254 {
                        out.extend(field);
                    } else {
                        overflow = true;
                        remaining.extend(field);
                    }
                }
                let offset = extra.len() % BLOCK;
                if offset + remaining.len() > BLOCK {
                    extra.resize(extra.len() + BLOCK - offset, 0);
                }
                let at = extra.len();
                extra.extend_from_slice(&remaining);
                out.extend(continuation(
                    extra_base + (at / BLOCK) as u32,
                    (at % BLOCK) as u32,
                    u32::try_from(remaining.len()).map_err(|_| {
                        Error::fatal(libc::EOVERFLOW, "Rock Ridge continuation too large")
                    })?,
                ));
            }
        }
        out[0] = out.len() as u8;
        Ok(out)
    }
    fn directory_bytes(
        &self,
        index: usize,
        kind: usize,
        tree: &Tree,
        extra_base: u32,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut out = Vec::new();
        let mut extra = Vec::new();
        let parent_record = if kind == 0 && self.nodes[index].rr_parent.is_some() {
            (index, vec![1], 4)
        } else {
            (self.parent(index, kind), vec![1], 1)
        };
        let mut records = vec![(index, vec![0], 0), parent_record];
        let mut children = self.children(index, kind);
        children.sort_by(|&a, &b| self.nodes[a].ident[kind].cmp(&self.nodes[b].ident[kind]));
        for i in children {
            records.push((i, self.nodes[i].ident[kind].clone(), 2));
        }
        for (i, id, record_kind) in records {
            let node = self.nodes[i]
                .hardlink
                .map_or(&self.nodes[i], |n| &self.nodes[n]);
            let mut remaining = if record_kind == 2 && !self.is_dir(i, kind) {
                node.size
            } else {
                0
            };
            let mut extent = node.extent;
            loop {
                let segment = if remaining > u32::MAX as u64 {
                    Some((extent, 0xfffff800, true))
                } else if remaining > 0 && extent != node.extent {
                    Some((extent, remaining as u32, false))
                } else {
                    None
                };
                let record = self.record(
                    i,
                    &id,
                    record_kind,
                    tree,
                    (kind, extra_base, segment),
                    &mut extra,
                )?;
                let offset = out.len() % BLOCK;
                if offset + record.len() > BLOCK {
                    out.resize(out.len() + BLOCK - offset, 0);
                }
                out.extend(record);
                if let Some((_, size, true)) = segment {
                    remaining -= size as u64;
                    extent = extent
                        .checked_add(size / BLOCK as u32)
                        .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "ISO extent too large"))?;
                } else {
                    break;
                }
            }
        }
        out.resize(out.len().div_ceil(BLOCK) * BLOCK, 0);
        extra.resize(extra.len().div_ceil(BLOCK) * BLOCK, 0);
        Ok((out, extra))
    }
    fn layout(&self, tree: &mut Tree, kind: usize, mut block: u32) -> Result<u32, Error> {
        for &i in &tree.order {
            let (data, extra) = self.directory_bytes(i, kind, tree, 0)?;
            let blocks = u32::try_from(data.len() / BLOCK)
                .map_err(|_| Error::fatal(libc::EOVERFLOW, "ISO directory too large"))?;
            let extra_blocks = u32::try_from(extra.len() / BLOCK)
                .map_err(|_| Error::fatal(libc::EOVERFLOW, "ISO directory too large"))?;
            tree.layout.insert(
                i,
                DirLayout {
                    location: block,
                    blocks,
                    extra_blocks,
                },
            );
            block = block
                .checked_add(blocks)
                .and_then(|n| n.checked_add(extra_blocks))
                .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "ISO directory too large"))?;
        }
        Ok(block)
    }
    fn path_table(&self, tree: &Tree, kind: usize, big: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for &i in &tree.directories {
            let id = if i == 0 {
                vec![0]
            } else {
                self.nodes[i].ident[kind].clone()
            };
            let location = tree.layout.get(&i).map_or(0, |l| l.location);
            let parent = tree
                .numbers
                .get(&self.parent(i, kind))
                .copied()
                .unwrap_or(1);
            out.extend_from_slice(&[id.len() as u8, 0]);
            out.extend_from_slice(&if big {
                location.to_be_bytes()
            } else {
                location.to_le_bytes()
            });
            out.extend_from_slice(&if big {
                parent.to_be_bytes()
            } else {
                parent.to_le_bytes()
            });
            out.extend_from_slice(&id);
            if id.len() % 2 != 0 {
                out.push(0)
            }
        }
        out.resize(tree.path_blocks as usize * BLOCK, 0);
        out
    }
}
impl Iso9660 {
    fn descriptor(
        &self,
        tree: &Tree,
        kind: usize,
        enhanced: bool,
        total: u32,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; BLOCK];
        out[0] = if kind == 0 && !enhanced { 1 } else { 2 };
        out[1..6].copy_from_slice(b"CD001");
        out[6] = if enhanced { 2 } else { 1 };
        let conv = if kind == 1 {
            Some(
                crate::string::conversion_to_charset(None, b"UTF-16BE", true)
                    .map_err(|e| Error::fatal(e.errno, e.message))?,
            )
        } else {
            None
        };
        let text = |out: &mut [u8], raw: &[u8]| -> Result<(), Error> {
            if let Some(conv) = &conv {
                for unit in out.chunks_exact_mut(2) {
                    unit.copy_from_slice(&[0, b' ']);
                }
                let mut encoded = Vec::new();
                crate::string::strncpy_l(&mut encoded, raw, Some(conv))
                    .map_err(|_| Error::fatal(-1, "Can't convert volume identifier to UTF-16BE"))?;
                let n = out.len().min(encoded.len()) & !1;
                out[..n].copy_from_slice(&encoded[..n]);
            } else {
                out.fill(b' ');
                for (d, &s) in out.iter_mut().zip(raw) {
                    *d = if enhanced { s } else { s.to_ascii_uppercase() };
                }
            }
            Ok(())
        };
        text(
            &mut out[8..40],
            if cfg!(target_os = "macos") {
                b"Darwin"
            } else {
                b"Linux"
            },
        )?;
        text(
            &mut out[40..72],
            self.strings
                .get(b"volume-id".as_slice())
                .map_or(b"CDROM".as_slice(), Vec::as_slice),
        )?;
        out[80..88].copy_from_slice(&both32(total));
        if kind == 1 {
            out[88..91].copy_from_slice(b"%/E")
        }
        out[120..124].copy_from_slice(&both16(1));
        out[124..128].copy_from_slice(&both16(1));
        out[128..132].copy_from_slice(&both16(2048));
        out[132..140].copy_from_slice(&both32(tree.path_size));
        out[140..144].copy_from_slice(&tree.path_l.to_le_bytes());
        out[148..152].copy_from_slice(&tree.path_m.to_be_bytes());
        let root = self.record(0, &[0], 3, tree, (kind, 0, None), &mut Vec::new())?;
        out[156..190].copy_from_slice(&root);
        for (range, key) in [
            (190..318, b"".as_slice()),
            (318..446, b"publisher"),
            (446..574, b"data-preparer"),
            (574..702, b"application-id"),
            (702..739, b"copyright-file"),
            (739..776, b"abstract-file"),
            (776..813, b"biblio-file"),
        ] {
            text(
                &mut out[range],
                self.strings.get(key).map_or(&[][..], Vec::as_slice),
            )?;
        }
        out[813..830].copy_from_slice(&volume_date(self.birth));
        out[830..847].copy_from_slice(&volume_date(self.birth));
        out[847..863].fill(b'0');
        out[864..881].copy_from_slice(&volume_date(self.birth));
        out[881] = if enhanced { 2 } else { 1 };
        out[883..1395].fill(b' ');
        Ok(out)
    }
    fn compress_zisofs(&mut self, index: usize) -> Result<(), Error> {
        let size = self.nodes[index].size;
        if !self.zisofs || self.rr == 0 || !(24..1 << 32).contains(&size) {
            return Ok(());
        }
        let offset = self.nodes[index].offset;
        let mut header = [0; 64];
        let spool_end = self.spool_size;
        {
            let file = self.ensure_spool()?;
            file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
            file.read_exact(&mut header[..size.min(64) as usize])
                .map_err(io_error)?;
            file.seek(SeekFrom::Start(spool_end)).map_err(io_error)?;
        }
        let magic = b"\x37\xe4\x53\x96\xc9\xdb\xd6\x07";
        if header[..8] == *magic {
            let original = u32::from_le_bytes(header[8..12].try_into().unwrap_or_default());
            let log = header[13];
            if original >= 24 && header[12] == 4 && (7..=30).contains(&log) {
                let count = (u64::from(original) + (1u64 << log) - 1) >> log;
                let table_size = 16 + (count + 1) * 4;
                if table_size <= size {
                    let mut pointer = table_size as u32;
                    let mut valid = true;
                    for pair in header[16..size.min(64) as usize].windows(8).step_by(4) {
                        let begin = u32::from_le_bytes(pair[..4].try_into().unwrap_or_default());
                        let end = u32::from_le_bytes(pair[4..].try_into().unwrap_or_default());
                        if begin != pointer || end < begin || u64::from(end) > size {
                            valid = false;
                            break;
                        }
                        pointer = end;
                    }
                    if valid {
                        self.nodes[index].zisofs = Some((original, 4, log));
                        return Ok(());
                    }
                }
            }
        }
        if size <= BLOCK as u64 {
            return Ok(());
        }
        let count = size.div_ceil(32768);
        let table_size = 16 + (count + 1) * 4;
        let mut temporary = crate::write::temp_file()?;
        let mut metadata = Vec::new();
        let table_size_usize = usize::try_from(table_size)
            .map_err(|_| Error::fatal(libc::ENOMEM, "Zisofs pointer table too large"))?;
        metadata
            .try_reserve_exact(table_size_usize)
            .map_err(|_| Error::fatal(libc::ENOMEM, "Zisofs pointer table too large"))?;
        metadata.resize(table_size_usize, 0);
        metadata[..8].copy_from_slice(magic);
        metadata[8..12].copy_from_slice(&(size as u32).to_le_bytes());
        metadata[12] = 4;
        metadata[13] = 15;
        temporary.write_all(&metadata).map_err(io_error)?;
        let mut total = table_size;
        let mut remaining = size;
        let mut input = [0; 32768];
        for block in 0..count {
            let n = remaining.min(input.len() as u64) as usize;
            {
                let file = self.ensure_spool()?;
                file.seek(SeekFrom::Start(offset + size - remaining))
                    .map_err(io_error)?;
                file.read_exact(&mut input[..n]).map_err(io_error)?;
            }
            let at = 16 + block as usize * 4;
            metadata[at..at + 4].copy_from_slice(&(total as u32).to_le_bytes());
            if n != 32768 || input[..n].iter().any(|&b| b != 0) {
                let compressed =
                    miniz_oxide::deflate::compress_to_vec_zlib(&input[..n], self.compression);
                temporary.write_all(&compressed).map_err(io_error)?;
                total = total
                    .checked_add(compressed.len() as u64)
                    .filter(|&s| s <= u32::MAX.into())
                    .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "Zisofs file too large"))?;
            }
            remaining -= n as u64;
        }
        let at = 16 + count as usize * 4;
        metadata[at..at + 4].copy_from_slice(&(total as u32).to_le_bytes());
        temporary.seek(SeekFrom::Start(0)).map_err(io_error)?;
        temporary.write_all(&metadata).map_err(io_error)?;
        temporary.seek(SeekFrom::Start(0)).map_err(io_error)?;
        self.nodes[index].offset = self.spool_size;
        let end = self.spool_size;
        self.ensure_spool()?
            .seek(SeekFrom::Start(end))
            .map_err(io_error)?;
        let mut buffer = [0; 65536];
        loop {
            let n = temporary.read(&mut buffer).map_err(io_error)?;
            if n == 0 {
                break;
            }
            self.append(&buffer[..n])?;
        }
        self.nodes[index].size = total;
        self.nodes[index].zisofs = Some((size as u32, 4, 15));
        Ok(())
    }
}
impl Format for Iso9660 {
    fn code(&self) -> c_int {
        0x40000
    }
    fn name(&self) -> &'static CStr {
        c"ISO9660"
    }
    fn module(&self) -> &'static [u8] {
        b"iso9660"
    }
    fn options(&mut self, _: &Base, key: &[u8], value: Option<&[u8]>) -> Result<c_int, Error> {
        match key {
            b"iso-level" => {
                self.level = match value {
                    Some([b'1'..=b'4']) => {
                        value.and_then(|v| v.first()).copied().unwrap_or(b'1') - b'0'
                    }
                    _ => return Err(bad(key)),
                }
            }
            b"joliet" => {
                self.joliet = match value {
                    None => 0,
                    Some(b"1") => 1,
                    Some(b"long") => 2,
                    _ => return Err(bad(key)),
                }
            }
            b"rockridge" | b"Rockridge" => {
                self.rr = match value {
                    None => 0,
                    Some(b"1") | Some(b"useful") => 2,
                    Some(b"strict") => 1,
                    _ => return Err(bad(key)),
                }
            }
            b"pad" => self.pad = value.is_some(),
            b"limit-depth" => self.limit_depth = value.is_some(),
            b"limit-dirs" => self.limit_dirs = value.is_some(),
            b"allow-vernum" => self.allow_vernum = value.is_some(),
            b"zisofs" => self.zisofs = value.is_some(),
            b"compression-level" => {
                self.compression = match value {
                    Some([b'0'..=b'9']) => {
                        value.and_then(|v| v.first()).copied().unwrap_or(b'6') - b'0'
                    }
                    _ => return Err(bad(key)),
                }
            }
            b"abstract-file" | b"application-id" | b"biblio-file" | b"copyright-file"
            | b"publisher" | b"volume-id" => {
                let value = value.ok_or_else(|| bad(key))?;
                let max = match key {
                    b"application-id" | b"publisher" => 128,
                    b"volume-id" => 32,
                    _ => 37,
                };
                if value.len() > max {
                    return Err(Error::fatal(
                        -1,
                        format!(
                            "Value is longer than {max} characters for option ``{}''",
                            String::from_utf8_lossy(key)
                        ),
                    ));
                }
                self.strings.insert(key.to_vec(), value.to_vec());
            }
            b"boot" => {
                self.boot_enabled = value.is_some();
                self.boot.filename = value.unwrap_or_default().to_vec();
            }
            b"boot-catalog" => {
                let name = value.ok_or_else(|| bad(key))?;
                if name.len() > 1024 {
                    return Err(Error::fatal(
                        -1,
                        "Value is longer than 1024 characters for option ``boot-catalog''",
                    ));
                }
                self.boot.catalog = name.to_vec();
            }
            b"boot-info-table" => self.boot.info_table = value.is_some(),
            b"boot-load-seg" => {
                let value = value
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .ok_or_else(|| bad(key))?;
                let value = value
                    .strip_prefix("0x")
                    .or_else(|| value.strip_prefix("0X"))
                    .unwrap_or(value);
                self.boot.load_segment = u16::from_str_radix(value, 16).map_err(|_| bad(key))?;
            }
            b"boot-load-size" => {
                let value = value
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .and_then(|v| v.parse::<u16>().ok())
                    .filter(|n| *n > 0)
                    .ok_or_else(|| bad(key))?;
                self.boot.load_size = value;
            }
            b"boot-type" => {
                self.boot_auto = false;
                match value {
                    Some(b"no-emulation") => {
                        self.boot.media = Media::NoEmulation;
                        self.boot_floppy = false;
                    }
                    Some(b"fd") => self.boot_floppy = true,
                    Some(b"hard-disk") => {
                        self.boot.media = Media::HardDisk;
                        self.boot_floppy = false;
                    }
                    _ => return Err(bad(key)),
                }
            }
            _ => return Ok(ARCHIVE_WARN),
        }
        let key = if key == b"Rockridge" {
            b"rockridge".as_slice()
        } else {
            key
        };
        self.info_options.retain(|(k, _)| k != key);
        let changed = match key {
            b"allow-vernum" | b"pad" | b"limit-depth" | b"limit-dirs" => value.is_none(),
            b"joliet" => self.joliet != 1,
            b"rockridge" => self.rr != 2,
            b"zisofs" | b"boot-info-table" | b"boot" => value.is_some(),
            b"iso-level" => self.level != 1,
            b"compression-level" => self.compression != 6,
            _ => true,
        };
        if changed {
            let value = match key {
                b"boot-load-seg" => Some(format!("{:x}", self.boot.load_segment).into_bytes()),
                b"boot-load-size" => Some(self.boot.load_size.to_string().into_bytes()),
                _ => value.map(<[u8]>::to_vec),
            };
            self.info_options.push((key.to_vec(), value));
        }
        Ok(ARCHIVE_OK)
    }
    fn header(&mut self, a: &Base, e: &mut Entry, _: &mut dyn Sink) -> Result<c_int, Error> {
        self.current = None;
        self.remaining = 0;
        if e.filetype() == 0o120000 && self.rr == 0 {
            a.set_error(-1, Some(b"Ignore symlink file"));
            return Ok(ARCHIVE_WARN);
        }
        if e.filetype() == 0o100000 && e.size() >= 1i64 << 32 && self.level < 3 {
            a.set_error(
                -1,
                Some(b"Ignore over 4294967296 bytes file. This file too large"),
            );
            return Ok(ARCHIVE_WARN);
        }
        let path = normalize(
            e.pathname()
                .ok_or_else(|| Error::new(ARCHIVE_FAILED, -1, "Missing pathname"))?
                .to_bytes(),
        );
        if path.is_empty() {
            return Ok(ARCHIVE_OK);
        }
        let parentpath = path
            .iter()
            .rposition(|&b| b == b'/')
            .map_or(&[][..], |p| &path[..p]);
        if parentpath.split(|&b| b == b'/').any(|p| p.len() > 255) {
            return Err(Error::fatal(-1, "A name buffer is too small"));
        }
        let parent = self.directory(parentpath)?;
        let index = if let Some(&i) = self.names.get(&path) {
            if self.nodes[i].entry.filetype() != e.filetype() {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    -1,
                    [
                        b"Found duplicate entries `".as_slice(),
                        &path,
                        b"' and its file type is different",
                    ]
                    .concat(),
                ));
            }
            let children = std::mem::take(&mut self.nodes[i].children);
            self.nodes[i] = Node::new(e.clone_entry(), path.clone(), parent, false);
            self.nodes[i].children = children;
            i
        } else {
            let i = self.nodes.len();
            self.nodes
                .try_reserve(1)
                .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate data"))?;
            self.nodes
                .push(Node::new(e.clone_entry(), path.clone(), parent, false));
            self.nodes[parent].children.push(i);
            self.names.insert(path, i);
            i
        };
        if e.filetype() == 0o100000 && e.hardlink().is_none() {
            let size = u64::try_from(e.size())
                .map_err(|_| Error::new(ARCHIVE_FAILED, -1, "Invalid entry size"))?;
            self.ensure_spool()?;
            self.nodes[index].offset = self.spool_size;
            self.nodes[index].size = size;
            self.current = Some(index);
            self.remaining = size;
        }
        Ok(ARCHIVE_OK)
    }
    fn data(&mut self, data: &[u8], _: &mut dyn Sink) -> Result<usize, Error> {
        let n = data
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        self.append(&data[..n])?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn finish_entry(&mut self, _: &mut dyn Sink) -> Result<(), Error> {
        let Some(index) = self.current.take() else {
            return Ok(());
        };
        if self.remaining != 0 && self.remaining == self.nodes[index].size {
            if !self.boot_enabled || self.nodes[index].path != normalize(&self.boot.filename) {
                self.nodes[index].size = 0;
            }
            return Ok(());
        }
        let zero = [0; 65536];
        while self.remaining > 0 {
            let n = self.remaining.min(zero.len() as u64) as usize;
            self.append(&zero[..n])?;
            self.remaining -= n as u64;
        }
        if self.nodes[index].size > 0 {
            self.compress_zisofs(index)?;
            let pad = (BLOCK as u64 - self.nodes[index].size % BLOCK as u64) % BLOCK as u64;
            self.append(&zero[..pad as usize])?;
            self.data_order.push(index);
        }
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.close_image(sink)
    }
}
impl Iso9660 {
    fn restore_zisofs(&mut self, index: usize) -> Result<(), Error> {
        let Some((size, _, log)) = self.nodes[index].zisofs else {
            return Ok(());
        };
        if log > 28 {
            return Err(Error::fatal(
                libc::ENOMEM,
                "Zisofs block exceeds memory limit",
            ));
        }
        let count = u64::from(size).div_ceil(1 << log);
        let offset = self.nodes[index].offset;
        let table_size = (count + 1) * 4;
        let mut pointers = Vec::new();
        pointers
            .try_reserve_exact(table_size as usize)
            .map_err(|_| Error::fatal(libc::ENOMEM, "No memory for zisofs pointer table"))?;
        pointers.resize(table_size as usize, 0);
        {
            let file = self.ensure_spool()?;
            file.seek(SeekFrom::Start(offset + 16)).map_err(io_error)?;
            file.read_exact(&mut pointers).map_err(io_error)?;
        }
        let mut restored = crate::write::temp_file()?;
        let mut remaining = u64::from(size);
        for pair in pointers.windows(8).step_by(4) {
            let begin = u32::from_le_bytes(pair[..4].try_into().unwrap_or_default());
            let end = u32::from_le_bytes(pair[4..].try_into().unwrap_or_default());
            if end < begin || u64::from(end) > self.nodes[index].size {
                return Err(Error::fatal(-1, "Invalid zisofs block pointer"));
            }
            let amount = remaining.min(1 << log) as usize;
            if begin == end {
                let zero = [0; 65536];
                let mut n = amount;
                while n > 0 {
                    let take = n.min(zero.len());
                    restored.write_all(&zero[..take]).map_err(io_error)?;
                    n -= take;
                }
            } else {
                if end - begin > 256 * 1024 * 1024 {
                    return Err(Error::fatal(
                        libc::ENOMEM,
                        "Zisofs compressed block exceeds memory limit",
                    ));
                }
                let mut compressed = Vec::new();
                compressed
                    .try_reserve_exact((end - begin) as usize)
                    .map_err(|_| Error::fatal(libc::ENOMEM, "No memory for zisofs block"))?;
                compressed.resize((end - begin) as usize, 0);
                {
                    let file = self.ensure_spool()?;
                    file.seek(SeekFrom::Start(offset + u64::from(begin)))
                        .map_err(io_error)?;
                    file.read_exact(&mut compressed).map_err(io_error)?;
                }
                let data =
                    miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&compressed, amount)
                        .map_err(|_| Error::fatal(-1, "Invalid zisofs compressed block"))?;
                if data.len() != amount {
                    return Err(Error::fatal(-1, "Invalid zisofs decompressed size"));
                }
                restored.write_all(&data).map_err(io_error)?;
            }
            remaining -= amount as u64;
        }
        let end = self.spool_size;
        self.ensure_spool()?
            .seek(SeekFrom::Start(end))
            .map_err(io_error)?;
        restored.seek(SeekFrom::Start(0)).map_err(io_error)?;
        self.nodes[index].offset = end;
        let mut buffer = [0; 65536];
        loop {
            let n = restored.read(&mut buffer).map_err(io_error)?;
            if n == 0 {
                break;
            }
            self.append(&buffer[..n])?;
        }
        self.nodes[index].size = size.into();
        self.nodes[index].entry.set_size(size.into());
        self.nodes[index].zisofs = None;
        let padding = (BLOCK as u64 - u64::from(size) % BLOCK as u64) % BLOCK as u64;
        self.append(
            &buffer[..padding as usize]
                .iter()
                .map(|_| 0)
                .collect::<Vec<_>>(),
        )?;
        Ok(())
    }
    fn close_image(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.birth = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .min(i64::MAX as u64) as i64;
        let mut boot_index = None;
        let mut catalog_index = None;
        let mut boot_allocation = 0;
        if self.boot_enabled {
            let filename = normalize(&self.boot.filename);
            let index = self.names.get(&filename).copied().ok_or_else(|| {
                Error::fatal(
                    -1,
                    [
                        b"Can't find the boot image file ``".as_slice(),
                        &self.boot.filename,
                        b"''",
                    ]
                    .concat(),
                )
            })?;
            self.restore_zisofs(index)?;
            let size = self.nodes[index].size;
            if self.boot_floppy {
                self.boot.media = if size <= 1200 * 1024 {
                    Media::Floppy1200
                } else if size <= 1440 * 1024 {
                    Media::Floppy1440
                } else if size <= 2880 * 1024 {
                    Media::Floppy2880
                } else {
                    return Err(Error::fatal(
                        -1,
                        "Boot image file size is too big for fd type",
                    ));
                };
            } else if self.boot_auto {
                self.boot.media = match size {
                    1228800 => Media::Floppy1200,
                    1474560 => Media::Floppy1440,
                    2949120 => Media::Floppy2880,
                    _ => Media::NoEmulation,
                };
            }
            boot_allocation = match self.boot.media {
                Media::Floppy1200 => 1200 * 1024,
                Media::Floppy1440 => 1440 * 1024,
                Media::Floppy2880 => 2880 * 1024,
                _ => size,
            };
            self.boot.identifier = self
                .strings
                .get(b"publisher".as_slice())
                .cloned()
                .unwrap_or_default();
            let catalog_name = normalize(&self.boot.catalog);
            let parentpath = catalog_name
                .iter()
                .rposition(|&b| b == b'/')
                .map_or(&[][..], |p| &catalog_name[..p]);
            let parent = self.directory(parentpath)?;
            let mut entry = Entry::new(None);
            entry.set_pathname(&catalog_name);
            entry.set_mode(0o100444);
            entry.set_size(2048);
            entry.set_nlink(1);
            entry.set_mtime(self.birth, 0);
            entry.set_atime(self.birth, 0);
            entry.set_ctime(self.birth, 0);
            let catalog = self.nodes.len();
            let mut node = Node::new(entry, catalog_name.clone(), parent, false);
            node.size = 2048;
            self.nodes.push(node);
            self.nodes[parent].children.push(catalog);
            self.names.insert(catalog_name, catalog);
            boot_index = Some(index);
            catalog_index = Some(catalog);
        }
        let identities = {
            use std::os::unix::fs::MetadataExt;
            let metadata = self.ensure_spool()?.metadata().map_err(io_error)?;
            (metadata.uid(), metadata.gid())
        };
        for node in &mut self.nodes {
            if node.virtual_dir {
                node.entry.set_mtime(self.birth, 0);
                node.entry.set_atime(self.birth, 0);
                node.entry.set_ctime(self.birth, 0);
                node.entry.set_uid(identities.0.into());
                node.entry.set_gid(identities.1.into());
            }
        }
        for i in 1..self.nodes.len() {
            if let Some(target) = self.nodes[i]
                .entry
                .hardlink()
                .map(|s| normalize(s.to_bytes()))
                && let Some(&target) = self.names.get(&target)
                && target != i
            {
                self.nodes[i].hardlink = Some(target);
                self.nodes[i].size = 0;
            }
        }
        let mut links = vec![1u32; self.nodes.len()];
        for node in &self.nodes {
            if let Some(i) = node.hardlink {
                links[i] = links[i].saturating_add(1);
            }
        }
        for (i, node) in self.nodes.iter_mut().enumerate().skip(1) {
            let count = links[node.hardlink.unwrap_or(i)];
            if count > 1 {
                node.entry.set_nlink(count);
            }
        }
        let deep = self
            .nodes
            .iter()
            .any(|n| n.path.iter().filter(|&&b| b == b'/').count() >= 7 && n.directory);
        if self.rr != 0
            && self.limit_depth
            && self.level < 4
            && deep
            && let Some(&i) = self.names.get(b"rr_moved".as_slice())
            && !self.nodes[i].directory
        {
            return Err(Error::fatal(
                -1,
                "Unable to relocate directories into rr_moved: the existing entry is not a directory",
            ));
        }
        self.relocate()?;
        for node in &mut self.nodes {
            if node.virtual_dir {
                node.entry.set_mtime(self.birth, 0);
                node.entry.set_atime(self.birth, 0);
                node.entry.set_ctime(self.birth, 0);
                node.entry.set_uid(identities.0.into());
                node.entry.set_gid(identities.1.into());
            }
        }
        self.identifiers()?;
        let mut primary = self.tree(0)?;
        let mut joliet = if self.joliet != 0 {
            Some(self.tree(1)?)
        } else {
            None
        };
        let mut block = 20 + u32::from(self.boot_enabled) + u32::from(self.level == 4)
            - u32::from(self.joliet == 0);
        primary.path_l = block;
        block = block
            .checked_add(primary.path_blocks)
            .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "ISO image too large"))?;
        primary.path_m = block;
        block += primary.path_blocks;
        if let Some(tree) = &mut joliet {
            tree.path_l = block;
            block += tree.path_blocks;
            tree.path_m = block;
            block += tree.path_blocks;
        }
        block = self.layout(&mut primary, 0, block)?;
        if let Some(tree) = &mut joliet {
            block = self.layout(tree, 1, block)?;
        }
        if self.rr != 0 {
            self.er_location = block;
            block += 1;
        }
        for (&index, layout) in &primary.layout {
            self.nodes[index].extent = layout.location;
        }
        let mut empty_extent = u32::MAX - 15;
        for node in &mut self.nodes {
            if !node.directory && node.size == 0 && node.hardlink.is_none() {
                node.extent = empty_extent;
                empty_extent = empty_extent.wrapping_sub(1);
            }
        }
        if let Some(catalog) = catalog_index {
            self.nodes[catalog].extent = block;
            block += 1;
        }
        if let Some(index) = boot_index {
            self.nodes[index].extent = block;
            block = block
                .checked_add(
                    u32::try_from(boot_allocation.div_ceil(BLOCK as u64))
                        .map_err(|_| Error::fatal(libc::EOVERFLOW, "Boot image is too large"))?,
                )
                .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "Boot image is too large"))?;
            if self.boot.info_table {
                let offset = self.nodes[index].offset;
                let extent = self.nodes[index].extent;
                let size = self.nodes[index].size;
                boot::patch_info_table(
                    self.ensure_spool()?,
                    offset,
                    extent,
                    size,
                    boot_allocation,
                )?;
            }
        }
        let mut emitted = HashSet::new();
        for &index in &self.data_order {
            if Some(index) == boot_index
                || self.nodes[index].hardlink.is_some()
                || self.nodes[index].size == 0
                || !emitted.insert(index)
            {
                continue;
            }
            self.nodes[index].extent = block;
            block = block
                .checked_add(
                    u32::try_from(self.nodes[index].size.div_ceil(BLOCK as u64))
                        .map_err(|_| Error::fatal(libc::EOVERFLOW, "ISO file too large"))?,
                )
                .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "ISO image too large"))?;
        }
        let total = block
            .checked_add(if self.pad { 150 } else { 0 })
            .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "ISO image too large"))?;
        zeros(sink, (16 * BLOCK) as u64)?;
        sink.write(&self.descriptor(&primary, 0, false, total)?)?;
        if let Some(catalog) = catalog_index {
            let mut descriptor = vec![0; BLOCK];
            descriptor[1..6].copy_from_slice(b"CD001");
            descriptor[6] = 1;
            descriptor[7..30].copy_from_slice(b"EL TORITO SPECIFICATION");
            descriptor[71..75].copy_from_slice(&self.nodes[catalog].extent.to_le_bytes());
            sink.write(&descriptor)?;
        }
        if self.level == 4 {
            sink.write(&self.descriptor(&primary, 0, true, total)?)?;
        }
        if let Some(tree) = &joliet {
            sink.write(&self.descriptor(tree, 1, false, total)?)?;
        }
        let mut terminator = vec![0; BLOCK];
        terminator[0] = 255;
        terminator[1..6].copy_from_slice(b"CD001");
        terminator[6] = 1;
        sink.write(&terminator)?;
        sink.write(&info::block(self.birth, &self.info_options)?)?;
        for (kind, tree) in [(0, Some(&primary)), (1, joliet.as_ref())] {
            if let Some(tree) = tree {
                sink.write(&self.path_table(tree, kind, false))?;
                sink.write(&self.path_table(tree, kind, true))?;
            }
        }
        for (kind, tree) in [(0, Some(&primary)), (1, joliet.as_ref())] {
            if let Some(tree) = tree {
                for &index in &tree.order {
                    let layout = tree
                        .layout
                        .get(&index)
                        .ok_or_else(|| Error::fatal(-1, "Missing ISO directory layout"))?;
                    let (data, extra) =
                        self.directory_bytes(index, kind, tree, layout.location + layout.blocks)?;
                    if data.len() / BLOCK != layout.blocks as usize
                        || extra.len() / BLOCK != layout.extra_blocks as usize
                    {
                        return Err(Error::fatal(-1, "ISO directory layout changed"));
                    }
                    sink.write(&data)?;
                    sink.write(&extra)?;
                }
            }
        }
        if self.rr != 0 {
            let mut er = vec![0; BLOCK];
            er[..ER.len()].copy_from_slice(ER);
            sink.write(&er)?;
        }
        if let Some(index) = boot_index {
            sink.write(&boot::catalog(
                self.nodes[index].extent,
                self.nodes[index].size,
                &self.boot,
            )?)?;
            self.copy_data(index, sink)?;
            zeros(
                sink,
                boot_allocation.div_ceil(BLOCK as u64) * BLOCK as u64 - self.nodes[index].size,
            )?;
        }
        for index in self.data_order.clone() {
            if Some(index) == boot_index || !emitted.remove(&index) {
                continue;
            }
            self.copy_data(index, sink)?;
            let pad = (BLOCK as u64 - self.nodes[index].size % BLOCK as u64) % BLOCK as u64;
            zeros(sink, pad)?;
        }
        if self.pad {
            zeros(sink, (150 * BLOCK) as u64)?;
        }
        if let Some(index) = self.too_deep {
            return Err(Error::new(
                ARCHIVE_WARN,
                -1,
                [self.nodes[index].path.as_slice(), b": Directories too deep"].concat(),
            ));
        }
        Ok(())
    }
    fn copy_data(&mut self, index: usize, sink: &mut dyn Sink) -> Result<(), Error> {
        let offset = self.nodes[index].offset;
        let mut left = self.nodes[index].size;
        let file = self.ensure_spool()?;
        file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
        let mut buffer = [0; 65536];
        while left > 0 {
            let n = left.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..n]).map_err(io_error)?;
            sink.write(&buffer[..n])?;
            left -= n as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Discard;
    impl Sink for Discard {
        fn write(&mut self, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
    }
    #[test]
    fn root_entry_is_ignored_and_version_option_is_preserved() {
        let mut iso = Iso9660::default();
        let base = Base::new(crate::archive::WRITE_MAGIC);
        let mut root = Entry::new(None);
        root.set_pathname(b".");
        root.set_mode(0o40700);
        root.set_uid(123);
        root.set_mtime(456, 0);
        iso.header(&base, &mut root, &mut Discard).unwrap();
        assert_eq!(iso.nodes[0].entry.uid(), 0);
        assert_eq!(iso.nodes[0].entry.mtime(), 0);
        assert!(iso.nodes[0].virtual_dir);
        iso.options(&base, b"allow-vernum", None).unwrap();
        iso.directory(&[b'a'; 40]).unwrap();
        iso.directory(&[b'A'; 40]).unwrap();
        let mut e = Entry::new(None);
        e.set_mode(0o100444);
        e.set_pathname(b"file");
        e.set_size(0);
        iso.header(&base, &mut e, &mut Discard).unwrap();
        iso.identifiers().unwrap();
        let i = iso.names[b"file".as_slice()];
        assert_eq!(iso.nodes[i].ident[0], b"FILE.");
        assert_eq!(iso.info_options, vec![(b"allow-vernum".to_vec(), None)]);
    }
    #[test]
    fn joliet_rejects_path_longer_than_240_bytes() {
        let mut iso = Iso9660::default();
        let name = [b'a'; 64];
        let mut path = Vec::new();
        for _ in 0..4 {
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(&name);
        }
        iso.directory(&path).unwrap();
        assert!(iso.identifiers().is_err());
    }

    #[test]
    fn unwritten_regular_file_is_empty_without_spooling_zeroes() {
        let mut iso = Iso9660::default();
        let base = Base::new(crate::archive::WRITE_MAGIC);
        let mut e = Entry::new(None);
        e.set_pathname(b"empty");
        e.set_mode(0o100444);
        e.set_size(1 << 30);
        iso.header(&base, &mut e, &mut Discard).unwrap();
        iso.finish_entry(&mut Discard).unwrap();
        let i = iso.names[b"empty".as_slice()];
        assert_eq!(iso.nodes[i].size, 0);
        assert_eq!(iso.spool_size, 0);
        assert!(iso.data_order.is_empty());
    }
    #[test]
    fn truncated_directory_names_are_unique() {
        let mut iso = Iso9660 {
            level: 2,
            ..Default::default()
        };
        iso.directory(&[b'a'; 40]).unwrap();
        iso.directory(&[b'A'; 40]).unwrap();
        iso.identifiers().unwrap();
        assert_ne!(iso.nodes[1].ident[0], iso.nodes[2].ident[0]);
        assert!(iso.nodes[2].ident[0].len() <= 31);
    }
    #[test]
    fn large_file_directory_records_are_block_aligned_multiextents() {
        let mut iso = Iso9660 {
            level: 3,
            ..Default::default()
        };
        let mut e = Entry::new(None);
        e.set_mode(0o100444);
        let mut node = Node::new(e, b"large".to_vec(), 0, false);
        node.size = u32::MAX as u64 + 123;
        node.extent = 100;
        iso.nodes.push(node);
        iso.nodes[0].children.push(1);
        iso.identifiers().unwrap();
        let tree = iso.tree(0).unwrap();
        let (bytes, _) = iso.directory_bytes(0, 0, &tree, 0).unwrap();
        let mut at = 0;
        let mut segments = Vec::new();
        while bytes[at] != 0 {
            let len = bytes[at] as usize;
            let record = &bytes[at..at + len];
            if record[32] > 1 {
                segments.push((
                    u32::from_le_bytes(record[2..6].try_into().unwrap()),
                    u32::from_le_bytes(record[10..14].try_into().unwrap()),
                    record[25],
                ));
            }
            at += len;
        }
        assert_eq!(
            segments,
            vec![(100, 0xfffff800, 0x80), (100 + 0xfffff800 / 2048, 2170, 0)]
        );
    }
    #[test]
    fn primary_relocation_preserves_joliet_tree() {
        let mut iso = Iso9660::default();
        let leaf = iso.directory(b"a/b/c/d/e/f/g/h/i").unwrap();
        iso.relocate().unwrap();
        iso.identifiers().unwrap();
        let h = iso.names[b"a/b/c/d/e/f/g/h".as_slice()];
        let relocated = iso.nodes[h].rr_child.unwrap();
        assert!(!iso.is_dir(h, 0));
        assert!(iso.is_dir(h, 1));
        assert_eq!(iso.parent(leaf, 0), relocated);
        assert_eq!(iso.parent(leaf, 1), h);
        assert!(iso.tree(0).unwrap().directories.contains(&relocated));
        assert!(!iso.tree(1).unwrap().directories.contains(&relocated));
    }
    #[test]
    fn disabling_joliet_accepts_nonunicode_filename() {
        let mut iso = Iso9660 {
            joliet: 0,
            ..Default::default()
        };
        let mut e = Entry::new(None);
        e.set_mode(0o100444);
        iso.nodes.push(Node::new(e, vec![0xff], 0, false));
        iso.nodes[0].children.push(1);
        assert!(iso.identifiers().is_ok());
    }
}
