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
use crate::entry::{
    AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFREG, AE_IFSOCK, Dev, Entry, Mode,
};
use crate::util::Error;
use crate::write::{Format, Sink};
use std::collections::BTreeMap;
use std::ffi::{CStr, c_int, c_ulong};

const INDENTNAMELEN: usize = 15;
const MAXLINELEN: usize = 80;

const F_CKSUM: u32 = 0x00000001; // checksum
const F_DEV: u32 = 0x00000002; // device type
const F_FLAGS: u32 = 0x00000008; // file flags
const F_GID: u32 = 0x00000010; // gid
const F_GNAME: u32 = 0x00000020; // group name
const F_MD5: u32 = 0x00000100; // MD5 digest
const F_MODE: u32 = 0x00000200; // mode
const F_NLINK: u32 = 0x00000400; // number of links
const F_RMD160: u32 = 0x00002000; // RIPEMD160 digest
const F_SHA1: u32 = 0x00004000; // SHA-1 digest
const F_SIZE: u32 = 0x00008000; // size
const F_SLINK: u32 = 0x00010000; // symbolic link
const F_TIME: u32 = 0x00040000; // modification time
const F_TYPE: u32 = 0x00080000; // file type
const F_UID: u32 = 0x00100000; // uid
const F_UNAME: u32 = 0x00200000; // user name
const F_SHA256: u32 = 0x00800000; // SHA-256 digest
const F_SHA384: u32 = 0x01000000; // SHA-384 digest
const F_SHA512: u32 = 0x02000000; // SHA-512 digest
const F_INO: u32 = 0x04000000; // inode number
const F_RESDEV: u32 = 0x08000000; // device ID on which the entry resides

const SET_KEYS: u32 = F_FLAGS | F_GID | F_GNAME | F_MODE | F_TYPE | F_UID | F_UNAME;
const DEFAULT_KEYS: u32 = F_DEV
    | F_FLAGS
    | F_GID
    | F_GNAME
    | F_SLINK
    | F_MODE
    | F_NLINK
    | F_SIZE
    | F_TIME
    | F_TYPE
    | F_UID
    | F_UNAME;

/// The digests in `sum_write` order. Entry digest type `i + 1` and the
/// entry's `mset_digest` bit `1 << i` belong to `SUMS[i]`.
const SUMS: [(u32, &[u8], Algorithm); 6] = [
    (F_MD5, b"md5", Algorithm::Md5),
    (F_RMD160, b"rmd160", Algorithm::Rmd160),
    (F_SHA1, b"sha1", Algorithm::Sha1),
    (F_SHA256, b"sha256", Algorithm::Sha256),
    (F_SHA384, b"sha384", Algorithm::Sha384),
    (F_SHA512, b"sha512", Algorithm::Sha512),
];

/// The data only for a directory file.
struct DirInfo {
    /// The children by basename, iterated in `strcmp` order.
    children: BTreeMap<Vec<u8>, usize>,
    /// The subdirectories still to visit, linked through `chnext`.
    first: Option<usize>,
    last: Option<usize>,
    chnext: Option<usize>,
    virtual_dir: bool,
}

/// The data only for a regular file.
#[derive(Default)]
struct RegInfo {
    compute_sum: u32,
    crc: u32,
    mset_digest: u32,
    digest: [Vec<u8>; 6],
}

struct MtreeEntry {
    /// Index of the parent in `Mtree::entries`; the root is its own parent.
    parent: usize,
    dir_info: Option<DirInfo>,
    reg_info: Option<RegInfo>,
    /// `None` only for the pathname ".", which upstream leaves unallocated.
    parentdir: Option<Vec<u8>>,
    basename: Vec<u8>,
    pathname: Vec<u8>,
    symlink: Vec<u8>,
    uname: Vec<u8>,
    gname: Vec<u8>,
    fflags_text: Vec<u8>,
    nlink: u32,
    filetype: Mode,
    mode: Mode,
    size: i64,
    uid: i64,
    gid: i64,
    mtime: i64,
    mtime_nsec: i64,
    fflags_set: c_ulong,
    fflags_clear: c_ulong,
    rdevmajor: Dev,
    rdevminor: Dev,
    devmajor: Dev,
    devminor: Dev,
    ino: i64,
}

impl MtreeEntry {
    fn new(entry: &mut Entry) -> Self {
        let pathname = entry
            .pathname()
            .map(|s| s.to_bytes().to_vec())
            .unwrap_or_default();
        let (parentdir, basename) = setup_filenames(&pathname);
        let text = |s: Option<&CStr>| s.map(|s| s.to_bytes().to_vec()).unwrap_or_default();
        let filetype = entry.filetype();
        let (fflags_set, fflags_clear) = entry.fflags();
        Self {
            parent: 0,
            dir_info: (filetype == AE_IFDIR).then(|| DirInfo {
                children: BTreeMap::new(),
                first: None,
                last: None,
                chnext: None,
                virtual_dir: false,
            }),
            reg_info: (filetype == AE_IFREG).then(RegInfo::default),
            parentdir,
            basename,
            pathname,
            symlink: text(entry.symlink()),
            uname: text(entry.uname()),
            gname: text(entry.gname()),
            fflags_text: text(entry.fflags_text()),
            nlink: entry.nlink(),
            filetype,
            mode: entry.mode() & 0o7777,
            size: entry.size(),
            uid: entry.uid(),
            gid: entry.gid(),
            mtime: entry.mtime(),
            mtime_nsec: entry.mtime_nsec(),
            fflags_set,
            fflags_clear,
            rdevmajor: entry.rdevmajor(),
            rdevminor: entry.rdevminor(),
            devmajor: entry.devmajor(),
            devminor: entry.devminor(),
            ino: entry.ino(),
        }
    }
}

/// An entry and how many children share its value of one attribute. A list
/// keeps the most used value first; ties keep the value seen first.
struct AttrCounter {
    entry: usize,
    count: u32,
}

#[derive(Default)]
struct AttrCounterSet {
    uid_list: Vec<AttrCounter>,
    gid_list: Vec<AttrCounter>,
    mode_list: Vec<AttrCounter>,
    flags_list: Vec<AttrCounter>,
}

/// The global values set by `/set`.
#[derive(Default)]
struct GlobalSet {
    processing: bool,
    ty: Mode,
    keys: u32,
    uid: i64,
    gid: i64,
    mode: Mode,
    fflags_set: c_ulong,
    fflags_clear: c_ulong,
}

pub struct Mtree {
    /// Every entry, in registration order (upstream's `file_list`).
    entries: Vec<MtreeEntry>,
    mtree_entry: Option<usize>,
    root: Option<usize>,
    cur_dirent: Option<usize>,
    cur_dirstr: Vec<u8>,
    ebuf: Vec<u8>,
    buf: Vec<u8>,
    first: bool,
    entry_bytes_remaining: u64,
    set: GlobalSet,
    acs: AttrCounterSet,
    classic: bool,
    depth: usize,
    compute_sum: u32,
    crc: u32,
    crc_len: u64,
    sum_ctx: [Option<Digest>; 6],
    keys: u32,
    dironly: bool,
    indent: bool,
    output_global_set: bool,
}

impl Mtree {
    pub fn new(classic: bool) -> Self {
        Self {
            entries: Vec::new(),
            mtree_entry: None,
            root: None,
            cur_dirent: None,
            cur_dirstr: Vec::new(),
            ebuf: Vec::new(),
            buf: Vec::new(),
            first: true,
            entry_bytes_remaining: 0,
            set: GlobalSet::default(),
            acs: AttrCounterSet::default(),
            classic,
            depth: 0,
            compute_sum: 0,
            crc: 0,
            crc_len: 0,
            sum_ctx: Default::default(),
            keys: DEFAULT_KEYS,
            dironly: false,
            indent: false,
            // Basically, mtree classic format uses '/set' global value.
            output_global_set: classic,
        }
    }
}

fn safe_char(c: u8) -> bool {
    (0x21..0x7f).contains(&c) && !matches!(c, b'#' | b'*' | b'=' | b'?' | b'[' | b'\\')
}

fn mtree_quote(s: &mut Vec<u8>, text: &[u8]) {
    for &c in text {
        if safe_char(c) {
            s.push(c);
        } else {
            s.extend([b'\\', c / 64 + b'0', c / 8 % 8 + b'0', c % 8 + b'0']);
        }
    }
}

fn pad(s: &mut Vec<u8>, n: usize) {
    s.resize(s.len() + n, b' ');
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

/// Generate a parent directory name and a base name from a pathname.
fn setup_filenames(pathname: &[u8]) -> (Option<Vec<u8>>, Vec<u8>) {
    if pathname == b"." {
        return (None, b".".to_vec());
    }
    let at = |d: &[u8], i: usize| d.get(i).copied().unwrap_or(0);
    let mut d = pathname.to_vec();
    // Remove leading '/' and '../' elements.
    let mut p = 0;
    while p < d.len() {
        if d[p] == b'/' {
            p += 1;
        } else if d[p] != b'.' {
            break;
        } else if at(&d, p + 1) == b'.' && at(&d, p + 2) == b'/' {
            p += 3;
        } else {
            break;
        }
    }
    d.drain(..p);
    // Remove "/","/." and "/.." elements from tail.
    loop {
        let len = d.len();
        if d.ends_with(b"/") {
            d.pop();
        }
        if d.len() > 1 && d.ends_with(b"/.") {
            d.truncate(d.len() - 2);
        }
        if d.len() > 2 && d.ends_with(b"/..") {
            d.truncate(d.len() - 3);
        }
        if len == d.len() {
            break;
        }
    }
    let mut p = 0;
    while p < d.len() {
        if d[p] == b'/' {
            if at(&d, p + 1) == b'/' {
                // Convert '//' --> '/'
                d.remove(p);
            } else if at(&d, p + 1) == b'.' && at(&d, p + 2) == b'/' {
                // Convert '/./' --> '/'
                d.drain(p..p + 2);
            } else if at(&d, p + 1) == b'.' && at(&d, p + 2) == b'.' && at(&d, p + 3) == b'/' {
                // Convert 'dir/dir1/../dir2/' --> 'dir/dir2/'
                let mut off = 4;
                while at(&d, p + off) == b'/' {
                    off += 1;
                }
                match d[..p].iter().rposition(|&b| b == b'/') {
                    Some(rp) if rp > 0 => {
                        d.drain(rp + 1..p + off);
                        p = rp;
                    }
                    _ => {
                        d.drain(..p + off);
                        p = 0;
                    }
                }
            } else {
                p += 1;
            }
        } else if p == 0 && d.starts_with(b"../") {
            let mut off = 3;
            while at(&d, off) == b'/' {
                off += 1;
            }
            d.drain(..off);
        } else {
            p += 1;
        }
    }
    // Add "./" prefix.
    // NOTE: If the pathname does not have a path separator, we have
    // to add "./" to the head of the pathname because mtree reader
    // will suppose that it is v1(a.k.a classic) mtree format and
    // change the directory unexpectedly and so it will make a wrong
    // path.
    if d != b"." && !d.starts_with(b"./") {
        d.splice(0..0, *b"./");
    }
    match d.iter().rposition(|&b| b == b'/') {
        // The pathname doesn't have a parent directory.
        None => (Some(Vec::new()), d),
        Some(slash) => {
            let basename = d.split_off(slash + 1);
            d.pop();
            (Some(d), basename)
        }
    }
}

/// The length of the first component of `fn_`, or `None` if it doesn't fit
/// upstream's `NAME_MAX + 1` name buffer.
fn get_path_component(fn_: &[u8]) -> Option<usize> {
    let l = fn_.iter().position(|&b| b == b'/').unwrap_or(fn_.len());
    (l <= 255).then_some(l)
}

fn attr_counter_inc(list: &mut Vec<AttrCounter>, found: Option<usize>, me: usize) {
    let Some(i) = found else {
        list.push(AttrCounter {
            entry: me,
            count: 1,
        });
        return;
    };
    list[i].count += 1;
    let count = list[i].count;
    if i == 0 || list[i - 1].count >= count {
        return;
    }
    let to = list[..i]
        .iter()
        .rposition(|ac| ac.count >= count)
        .map_or(0, |p| p + 1);
    let ac = list.remove(i);
    list.insert(to, ac);
}

impl Mtree {
    /// Indent a line as the mtree utility does so it is readable for people.
    fn mtree_indent(&mut self) {
        let (nd, pd) = if !self.classic {
            (0, 0)
        } else if self.indent {
            (0, self.depth * 4)
        } else {
            (if self.depth != 0 { 4 } else { 0 }, 0)
        };
        let e = std::mem::take(&mut self.ebuf);
        let buf = &mut self.buf;
        let mut first = true;
        let mut s = 0;
        let mut r = e.iter().take_while(|&&b| b == b' ').count();
        let mut x = None;
        while let Some(off) = e[r..].iter().position(|&b| b == b' ') {
            r += off;
            if first {
                first = false;
                pad(buf, nd + pd);
                buf.extend(&e[s..r]);
                if nd + (r - s) > INDENTNAMELEN {
                    buf.extend(b" \\\n");
                    pad(buf, INDENTNAMELEN + 1 + pd);
                } else {
                    pad(buf, (INDENTNAMELEN + 1).saturating_sub(r - s + nd));
                }
                r += 1;
                s = r;
                x = None;
                continue;
            }
            if pd + (r - s) <= MAXLINELEN - 3 - INDENTNAMELEN {
                x = Some(r);
                r += 1;
            } else {
                let brk = x.unwrap_or(r);
                buf.extend(&e[s..brk]);
                buf.extend(b" \\\n");
                pad(buf, INDENTNAMELEN + 1 + pd);
                s = brk + 1;
                r = s;
                x = None;
            }
        }
        if first {
            pad(buf, nd + pd);
            buf.extend(&e[s..]);
            s = e.len();
        }
        if let Some(brk) = x
            && pd + (e.len() - s) > MAXLINELEN - 3 - INDENTNAMELEN
        {
            // Last keyword is longer.
            buf.extend(&e[s..brk]);
            buf.extend(b" \\\n");
            pad(buf, INDENTNAMELEN + 1 + pd);
            s = brk + 1;
        }
        buf.extend(&e[s..]);
    }

    /// Write /set keyword.
    /// Set the most used value of uid, gid, mode and fflags, which are
    /// collected by the attr_counter_set_collect() function.
    fn write_global(&mut self) {
        let mut setstr = Vec::new();
        let mut unsetstr = Vec::new();
        let mut keys = self.keys & SET_KEYS;
        let oldkeys = self.set.keys;
        let mut effkeys = keys;
        let acs = &self.acs;
        let top = |list: &[AttrCounter]| list.first().map(|ac| (&self.entries[ac.entry], ac.count));
        let (uid, gid, mode, flags) = (
            top(&acs.uid_list),
            top(&acs.gid_list),
            top(&acs.mode_list),
            top(&acs.flags_list),
        );
        if self.set.processing {
            // Check if the global data needs updating.
            effkeys &= !F_TYPE;
            match uid {
                None => effkeys &= !(F_UNAME | F_UID),
                Some((me, count)) => {
                    if oldkeys & (F_UNAME | F_UID) != 0 && (count < 2 || self.set.uid == me.uid) {
                        effkeys &= !(F_UNAME | F_UID);
                    }
                }
            }
            match gid {
                None => effkeys &= !(F_GNAME | F_GID),
                Some((me, count)) => {
                    if oldkeys & (F_GNAME | F_GID) != 0 && (count < 2 || self.set.gid == me.gid) {
                        effkeys &= !(F_GNAME | F_GID);
                    }
                }
            }
            match mode {
                None => effkeys &= !F_MODE,
                Some((me, count)) => {
                    if oldkeys & F_MODE != 0 && (count < 2 || self.set.mode == me.mode) {
                        effkeys &= !F_MODE;
                    }
                }
            }
            match flags {
                None => effkeys &= !F_FLAGS,
                Some((me, count)) => {
                    if oldkeys & F_FLAGS != 0
                        && (count < 2
                            || (me.fflags_set == self.set.fflags_set
                                && me.fflags_clear == self.set.fflags_clear))
                    {
                        effkeys &= !F_FLAGS;
                    }
                }
            }
        } else {
            if uid.is_none() {
                keys &= !(F_UNAME | F_UID);
            }
            if gid.is_none() {
                keys &= !(F_GNAME | F_GID);
            }
            if mode.is_none() {
                keys &= !F_MODE;
            }
            if flags.is_none() {
                keys &= !F_FLAGS;
            }
        }
        if keys & effkeys & F_TYPE != 0 {
            if self.dironly {
                setstr.extend(b" type=dir");
                self.set.ty = AE_IFDIR;
            } else {
                setstr.extend(b" type=file");
                self.set.ty = AE_IFREG;
            }
        }
        if let Some((me, _)) = uid {
            if keys & effkeys & F_UNAME != 0 {
                if !me.uname.is_empty() {
                    setstr.extend(b" uname=");
                    mtree_quote(&mut setstr, &me.uname);
                } else {
                    keys &= !F_UNAME;
                    if oldkeys & F_UNAME != 0 {
                        unsetstr.extend(b" uname");
                    }
                }
            }
            if keys & effkeys & F_UID != 0 {
                self.set.uid = me.uid;
                setstr.extend(format!(" uid={}", me.uid).as_bytes());
            }
        }
        if let Some((me, _)) = gid {
            if keys & effkeys & F_GNAME != 0 {
                if !me.gname.is_empty() {
                    setstr.extend(b" gname=");
                    mtree_quote(&mut setstr, &me.gname);
                } else {
                    keys &= !F_GNAME;
                    if oldkeys & F_GNAME != 0 {
                        unsetstr.extend(b" gname");
                    }
                }
            }
            if keys & effkeys & F_GID != 0 {
                self.set.gid = me.gid;
                setstr.extend(format!(" gid={}", me.gid).as_bytes());
            }
        }
        if let Some((me, _)) = mode
            && keys & effkeys & F_MODE != 0
        {
            self.set.mode = me.mode;
            setstr.extend(format!(" mode={:o}", me.mode).as_bytes());
        }
        if let Some((me, _)) = flags
            && keys & effkeys & F_FLAGS != 0
        {
            if !me.fflags_text.is_empty() {
                setstr.extend(b" flags=");
                mtree_quote(&mut setstr, &me.fflags_text);
                self.set.fflags_set = me.fflags_set;
                self.set.fflags_clear = me.fflags_clear;
            } else {
                keys &= !F_FLAGS;
                if oldkeys & F_FLAGS != 0 {
                    unsetstr.extend(b" flags");
                }
            }
        }
        if !unsetstr.is_empty() {
            self.buf
                .extend([b"/unset".as_slice(), &unsetstr, b"\n"].concat());
        }
        if !setstr.is_empty() {
            self.buf
                .extend([b"/set".as_slice(), &setstr, b"\n"].concat());
        }
        self.set.keys = keys;
        self.set.processing = true;
    }

    /// Tabulate uid, gid, mode and fflags of a entry in order to be used for /set.
    fn attr_counter_set_collect(&mut self, me: usize) {
        let keys = self.keys;
        let entries = &self.entries;
        let e = &entries[me];
        let acs = &mut self.acs;
        if keys & (F_UNAME | F_UID) != 0 {
            let found = acs
                .uid_list
                .iter()
                .position(|ac| entries[ac.entry].uid == e.uid);
            attr_counter_inc(&mut acs.uid_list, found, me);
        }
        if keys & (F_GNAME | F_GID) != 0 {
            let found = acs
                .gid_list
                .iter()
                .position(|ac| entries[ac.entry].gid == e.gid);
            attr_counter_inc(&mut acs.gid_list, found, me);
        }
        if keys & F_MODE != 0 {
            let found = acs
                .mode_list
                .iter()
                .position(|ac| entries[ac.entry].mode == e.mode);
            attr_counter_inc(&mut acs.mode_list, found, me);
        }
        if keys & F_FLAGS != 0 {
            let found = acs.flags_list.iter().position(|ac| {
                entries[ac.entry].fflags_set == e.fflags_set
                    && entries[ac.entry].fflags_clear == e.fflags_clear
            });
            attr_counter_inc(&mut acs.flags_list, found, me);
        }
    }

    fn get_global_set_keys(&self, me: &MtreeEntry) -> u32 {
        let mut keys = self.keys;
        // If a keyword has been set by /set, we do not need to
        // output it.
        let set = &self.set;
        if set.keys == 0 {
            return keys; // /set is not used.
        }
        if set.keys & (F_GNAME | F_GID) != 0 && set.gid == me.gid {
            keys &= !(F_GNAME | F_GID);
        }
        if set.keys & (F_UNAME | F_UID) != 0 && set.uid == me.uid {
            keys &= !(F_UNAME | F_UID);
        }
        if set.keys & F_FLAGS != 0
            && set.fflags_set == me.fflags_set
            && set.fflags_clear == me.fflags_clear
        {
            keys &= !F_FLAGS;
        }
        if set.keys & F_MODE != 0 && set.mode == me.mode {
            keys &= !F_MODE;
        }
        match me.filetype {
            AE_IFLNK | AE_IFSOCK | AE_IFCHR | AE_IFBLK | AE_IFIFO => {}
            AE_IFDIR => {
                if set.keys & F_TYPE != 0 && set.ty == AE_IFDIR {
                    keys &= !F_TYPE;
                }
            }
            // Handle unknown file types as regular files.
            _ => {
                if set.keys & F_TYPE != 0 && set.ty == AE_IFREG {
                    keys &= !F_TYPE;
                }
            }
        }
        keys
    }

    fn write_mtree_entry(&mut self, i: usize) {
        if self.entries[i].dir_info.is_some() {
            if self.classic {
                // Output a comment line to describe the full
                // pathname of the entry as mtree utility does
                // while generating classic format.
                if !self.dironly {
                    self.buf.push(b'\n');
                }
                let me = &self.entries[i];
                match &me.parentdir {
                    Some(pd) => self
                        .buf
                        .extend([b"# ", &pd[..], b"/", &me.basename, b"\n"].concat()),
                    None => self.buf.extend([b"# ", &me.basename[..], b"\n"].concat()),
                }
            }
            if self.output_global_set {
                self.write_global();
            }
        }
        let me = &self.entries[i];
        let mut line = Vec::new();
        if !self.classic
            && let Some(pd) = &me.parentdir
        {
            // If generating format is not classic one(v1), output
            // a full pathname.
            mtree_quote(&mut line, pd);
            if me.basename != b"." {
                line.push(b'/');
            }
        }
        mtree_quote(&mut line, &me.basename);

        let keys = self.get_global_set_keys(me);
        let kv = |line: &mut Vec<u8>, key: u32, s: String| {
            if keys & key != 0 {
                line.extend(s.as_bytes());
            }
        };
        if keys & F_NLINK != 0 && me.nlink != 0 && me.nlink != 1 && me.filetype != AE_IFDIR {
            line.extend(format!(" nlink={}", me.nlink).as_bytes());
        }
        if keys & F_GNAME != 0 && !me.gname.is_empty() {
            line.extend(b" gname=");
            mtree_quote(&mut line, &me.gname);
        }
        if keys & F_UNAME != 0 && !me.uname.is_empty() {
            line.extend(b" uname=");
            mtree_quote(&mut line, &me.uname);
        }
        if keys & F_FLAGS != 0 {
            if !me.fflags_text.is_empty() {
                line.extend(b" flags=");
                mtree_quote(&mut line, &me.fflags_text);
            } else if self.set.processing && self.set.keys & F_FLAGS != 0 {
                // Overwrite the global parameter.
                line.extend(b" flags=none");
            }
        }
        kv(
            &mut line,
            F_TIME,
            format!(" time={}.{}", me.mtime, me.mtime_nsec),
        );
        kv(&mut line, F_MODE, format!(" mode={:o}", me.mode));
        kv(&mut line, F_GID, format!(" gid={}", me.gid));
        kv(&mut line, F_UID, format!(" uid={}", me.uid));
        kv(&mut line, F_INO, format!(" inode={}", me.ino));
        kv(
            &mut line,
            F_RESDEV,
            format!(
                " resdevice=native,{},{}",
                me.devmajor as u64, me.devminor as u64
            ),
        );
        let device = format!(
            " device=native,{},{}",
            me.rdevmajor as u64, me.rdevminor as u64
        );
        match me.filetype {
            AE_IFLNK => {
                kv(&mut line, F_TYPE, " type=link".into());
                if keys & F_SLINK != 0 {
                    line.extend(b" link=");
                    mtree_quote(&mut line, &me.symlink);
                }
            }
            AE_IFSOCK => kv(&mut line, F_TYPE, " type=socket".into()),
            AE_IFCHR => {
                kv(&mut line, F_TYPE, " type=char".into());
                kv(&mut line, F_DEV, device);
            }
            AE_IFBLK => {
                kv(&mut line, F_TYPE, " type=block".into());
                kv(&mut line, F_DEV, device);
            }
            AE_IFDIR => kv(&mut line, F_TYPE, " type=dir".into()),
            AE_IFIFO => kv(&mut line, F_TYPE, " type=fifo".into()),
            // Handle unknown file types as regular files.
            _ => {
                kv(&mut line, F_TYPE, " type=file".into());
                kv(&mut line, F_SIZE, format!(" size={}", me.size));
            }
        }

        // Write a bunch of sum.
        if let Some(reg) = &me.reg_info {
            sum_write(&mut line, reg);
        }

        line.push(b'\n');
        if self.indent || self.classic {
            self.ebuf = line;
            self.mtree_indent();
        } else {
            self.buf.extend(line);
        }
    }

    fn write_dot_dot_entry(&mut self, n: usize) {
        let me = &self.entries[n];
        if let Some(pd) = &me.parentdir {
            if self.indent {
                pad(&mut self.buf, self.depth * 4);
            }
            self.buf
                .extend([b"# ", &pd[..], b"/", &me.basename, b"\n"].concat());
        }
        let dotdot = &b"..\n\n"[..if self.dironly { 3 } else { 4 }];
        if self.indent {
            self.ebuf = dotdot.to_vec();
            self.mtree_indent();
        } else {
            self.buf.extend(dotdot);
        }
    }

    fn add_child_tail(&mut self, parent: usize, child: usize) {
        if let Some(d) = self.entries[child].dir_info.as_mut() {
            d.chnext = None;
        }
        let last = self.entries[parent].dir_info.as_ref().and_then(|d| d.last);
        match last {
            Some(l) => {
                if let Some(d) = self.entries[l].dir_info.as_mut() {
                    d.chnext = Some(child);
                }
            }
            None => {
                if let Some(d) = self.entries[parent].dir_info.as_mut() {
                    d.first = Some(child);
                }
            }
        }
        if let Some(d) = self.entries[parent].dir_info.as_mut() {
            d.last = Some(child);
        }
    }

    /// Write mtree entries saved at attr_counter_set_collect() function.
    fn write_mtree_entry_tree(&mut self, root: usize) {
        let mut np = root;
        while let Some(dir) = &self.entries[np].dir_info {
            let children: Vec<usize> = dir.children.values().copied().collect();
            let virtual_dir = dir.virtual_dir;
            if self.output_global_set {
                // Collect attribute information to know which value
                // is frequently used among the children.
                self.acs = AttrCounterSet::default();
                for &e in &children {
                    self.attr_counter_set_collect(e);
                }
            }
            if !virtual_dir || self.classic {
                self.write_mtree_entry(np);
            } else if self.output_global_set {
                // Whenever output_global_set is enabled
                // output global value(/set keywords)
                // even if the directory entry is not allowed
                // to be written because the global values
                // can be used for the children.
                self.write_global();
            }
            // Output the attribute of all files except directory files.
            self.depth += 1;
            for &e in &children {
                if self.entries[e].dir_info.is_some() {
                    self.add_child_tail(np, e);
                } else {
                    self.write_mtree_entry(e);
                }
            }
            self.depth -= 1;

            if let Some(first) = self.entries[np].dir_info.as_ref().and_then(|d| d.first) {
                // Descend the tree.
                np = first;
                if self.indent {
                    self.depth += 1;
                }
                continue;
            } else if self.classic {
                // While printing mtree classic, if there are not
                // any directory files(except "." and "..") in the
                // directory, output two dots ".." as returning
                // the parent directory.
                self.write_dot_dot_entry(np);
            }

            while np != self.entries[np].parent {
                match self.entries[np].dir_info.as_ref().and_then(|d| d.chnext) {
                    None => {
                        // Ascend the tree; go back to the parent.
                        if self.indent {
                            self.depth = self.depth.saturating_sub(1);
                        }
                        let parent = self.entries[np].parent;
                        if self.classic {
                            self.write_dot_dot_entry(parent);
                        }
                        np = parent;
                    }
                    Some(next) => {
                        // Switch to next mtree entry in the directory.
                        np = next;
                        break;
                    }
                }
            }
            if np == self.entries[np].parent {
                break;
            }
        }
    }

    fn sum_init(&mut self) {
        self.compute_sum = 0;
        if self.keys & F_CKSUM != 0 {
            self.compute_sum |= F_CKSUM;
            self.crc = 0;
            self.crc_len = 0;
        }
        for (ctx, &(bit, _, algorithm)) in self.sum_ctx.iter_mut().zip(&SUMS) {
            if self.keys & bit != 0 {
                *ctx = Some(Digest::new(algorithm));
                self.compute_sum |= bit;
            }
        }
    }

    fn sum_update(&mut self, data: &[u8]) {
        if self.compute_sum & F_CKSUM != 0 {
            // Compute a POSIX 1003.2 checksum
            for &b in data {
                self.crc = crc_step(self.crc, b);
            }
            self.crc_len += data.len() as u64;
        }
        let reg = self
            .mtree_entry
            .and_then(|i| self.entries[i].reg_info.as_mut());
        let mut mset = 0;
        for (i, (ctx, &(bit, _, _))) in self.sum_ctx.iter_mut().zip(&SUMS).enumerate() {
            if self.compute_sum & bit != 0
                && let Some(ctx) = ctx
            {
                ctx.update(data);
                mset |= 1 << i;
            }
        }
        if let Some(reg) = reg {
            reg.mset_digest &= !mset;
        }
    }

    fn sum_final(&mut self, i: usize) {
        let Some(reg) = self.entries[i].reg_info.as_mut() else {
            return;
        };
        if self.compute_sum & F_CKSUM != 0 {
            // Include the length of the file.
            let mut len = self.crc_len;
            while len != 0 {
                self.crc = crc_step(self.crc, len as u8);
                len >>= 8;
            }
            reg.crc = !self.crc;
        }
        for (k, (ctx, &(bit, _, _))) in self.sum_ctx.iter_mut().zip(&SUMS).enumerate() {
            if self.compute_sum & bit != 0
                && let Some(ctx) = ctx.take()
            {
                let digest = ctx.finalize();
                if reg.mset_digest & (1 << k) == 0 {
                    reg.digest[k] = digest;
                }
            }
        }
        // Save what types of sum are computed.
        reg.compute_sum = self.compute_sum;
    }

    fn find_child(&self, parent: usize, name: &[u8]) -> Option<usize> {
        self.entries[parent]
            .dir_info
            .as_ref()?
            .children
            .get(name)
            .copied()
    }

    /// Insert `file` under the directory `dent`, or merge it into the entry
    /// that already has its name.
    fn insert_child(&mut self, dent: usize, mut file: MtreeEntry) -> usize {
        if let Some(np) = self.find_child(dent, &file.basename) {
            return self.exchange_same_entry(np, file);
        }
        let i = self.entries.len();
        if let Some(dir) = self.entries[dent].dir_info.as_mut() {
            dir.children.insert(file.basename.clone(), i);
        }
        file.parent = dent;
        self.entries.push(file);
        i
    }

    fn create_virtual_dir(pathname: &[u8]) -> MtreeEntry {
        let mut entry = Entry::new(None);
        entry.set_pathname(pathname);
        entry.set_mode(AE_IFDIR | 0o755);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        entry.set_mtime(now, 0);
        let mut file = MtreeEntry::new(&mut entry);
        if let Some(d) = file.dir_info.as_mut() {
            d.virtual_dir = true;
        }
        file
    }

    /// Add a new entry into the tree, or merge it into the entry of the same
    /// name; returns where it went. Upstream returns `ARCHIVE_WARN` for a
    /// merge, which its caller drops.
    fn tree_add(&mut self, mut file: MtreeEntry) -> Result<usize, Error> {
        let parentdir = file.parentdir.clone().unwrap_or_default();
        if parentdir.is_empty() && file.basename == b"." {
            if file.filetype != AE_IFDIR {
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    "Root entry '.' must be a directory",
                ));
            }
            if let Some(root) = self.root {
                return Ok(self.exchange_same_entry(root, file));
            }
            let i = self.entries.len();
            file.parent = i;
            self.root = Some(i);
            self.entries.push(file);
            return Ok(i);
        }
        let not_canonical = || {
            Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_MISC,
                [
                    b"Internal programming error in generating canonical name for ".as_slice(),
                    &file.pathname,
                ]
                .concat(),
            )
        };
        if parentdir.is_empty() {
            return Err(not_canonical());
        }

        // If the path of the parent directory of `file' entry is
        // the same as the path of `cur_dirent', add `file' entry to
        // `cur_dirent'.
        if let Some(cur) = self.cur_dirent
            && self.cur_dirstr == parentdir
        {
            return Ok(self.insert_child(cur, file));
        }

        let too_long = || Error::fatal(ARCHIVE_ERRNO_MISC, "A name buffer is too small");
        let mut dent = self.root;
        let mut f = 0;
        let mut l;
        loop {
            l = get_path_component(&parentdir[f..]).ok_or_else(too_long)?;
            if l == 0 {
                break;
            }
            let name = &parentdir[f..f + l];
            if name == b"." && dent.is_some() && dent == self.root {
                f += l;
                if parentdir.get(f) == Some(&b'/') {
                    f += 1;
                }
                continue;
            }
            let Some(np) = dent.and_then(|d| self.find_child(d, name)) else {
                break;
            };
            // Find next sub directory.
            if self.entries[np].dir_info.is_none() {
                // NOT a directory!
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    [
                        b"`".as_slice(),
                        &self.entries[np].pathname,
                        b"' is not a directory, we cannot insert `",
                        &file.pathname,
                        b"' ",
                    ]
                    .concat(),
                ));
            }
            f += l;
            if parentdir.get(f) == Some(&b'/') {
                f += 1;
            }
            dent = Some(np);
        }
        // Create virtual parent directories.
        while f < parentdir.len() {
            let mut path = parentdir[..f + l].to_vec();
            if path.last() == Some(&b'/') {
                path.pop();
            }
            let vp = Self::create_virtual_dir(&path);
            let np = if vp.pathname == b"." {
                let i = self.entries.len();
                self.entries.push(MtreeEntry { parent: i, ..vp });
                self.root = Some(i);
                i
            } else {
                // A canonical parentdir starts with ".", which made the root.
                self.insert_child(dent.ok_or_else(not_canonical)?, vp)
            };
            f += l;
            if parentdir.get(f) == Some(&b'/') {
                f += 1;
            }
            l = get_path_component(&parentdir[f..]).ok_or_else(too_long)?;
            dent = Some(np);
        }

        // Found out the parent directory where `file' can be
        // inserted.
        let dent = dent.ok_or_else(not_canonical)?;
        self.cur_dirent = Some(dent);
        let d = &self.entries[dent];
        self.cur_dirstr = match &d.parentdir {
            Some(pd) if !pd.is_empty() => [&pd[..], b"/", &d.basename].concat(),
            _ => d.basename.clone(),
        };
        Ok(self.insert_child(dent, file))
    }

    /// We already have an entry with same filename: update the existing
    /// entry's attributes by the new one's. Upstream first compares the
    /// file types of the two `mode` fields, which hold only permission
    /// bits, so that check never fails.
    fn exchange_same_entry(&mut self, np: usize, file: MtreeEntry) -> usize {
        let e = &mut self.entries[np];
        e.symlink = file.symlink;
        e.uname = file.uname;
        e.gname = file.gname;
        e.fflags_text = file.fflags_text;
        e.nlink = file.nlink;
        e.filetype = file.filetype;
        e.mode = file.mode;
        e.size = file.size;
        e.uid = file.uid;
        e.gid = file.gid;
        e.fflags_set = file.fflags_set;
        e.fflags_clear = file.fflags_clear;
        e.mtime = file.mtime;
        e.mtime_nsec = file.mtime_nsec;
        e.rdevmajor = file.rdevmajor;
        e.rdevminor = file.rdevminor;
        e.devmajor = file.devmajor;
        e.devminor = file.devminor;
        e.ino = file.ino;
        if let Some(d) = e.dir_info.as_mut() {
            d.virtual_dir = false;
        }
        np
    }
}

fn sum_write(line: &mut Vec<u8>, reg: &RegInfo) {
    if reg.compute_sum & F_CKSUM != 0 {
        line.extend(format!(" cksum={}", reg.crc).as_bytes());
    }
    for (digest, &(bit, name, _)) in reg.digest.iter().zip(&SUMS) {
        if reg.compute_sum & bit != 0 {
            line.extend([b" ", name, b"digest="].concat());
            for b in digest {
                line.extend(format!("{b:02x}").as_bytes());
            }
        }
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
        let keybit = match key {
            b"all" => !0,
            b"cksum" => F_CKSUM,
            b"device" => F_DEV,
            b"dironly" => {
                self.dironly = value.is_some();
                return Ok(ARCHIVE_OK);
            }
            b"flags" => F_FLAGS,
            b"gid" => F_GID,
            b"gname" => F_GNAME,
            b"indent" => {
                self.indent = value.is_some();
                return Ok(ARCHIVE_OK);
            }
            b"inode" => F_INO,
            b"link" => F_SLINK,
            b"md5" | b"md5digest" => F_MD5,
            b"mode" => F_MODE,
            b"nlink" => F_NLINK,
            b"resdevice" => F_RESDEV,
            b"ripemd160digest" | b"rmd160" | b"rmd160digest" => F_RMD160,
            b"sha1" | b"sha1digest" => F_SHA1,
            b"sha256" | b"sha256digest" => F_SHA256,
            b"sha384" | b"sha384digest" => F_SHA384,
            b"sha512" | b"sha512digest" => F_SHA512,
            b"size" => F_SIZE,
            b"time" => F_TIME,
            b"type" => F_TYPE,
            b"uid" => F_UID,
            b"uname" => F_UNAME,
            b"use-set" => {
                self.output_global_set = value.is_some();
                return Ok(ARCHIVE_OK);
            }
            // Note: The "warn" return is just to inform the options
            // supervisor that we didn't handle it.  It will generate
            // a suitable error if no one used this option.
            _ => return Ok(ARCHIVE_WARN),
        };
        if value.is_some() {
            self.keys |= keybit;
        } else {
            self.keys &= !keybit;
        }
        Ok(ARCHIVE_OK)
    }
    fn header(&mut self, _: &Base, entry: &mut Entry, _: &mut dyn Sink) -> Result<c_int, Error> {
        if self.first {
            self.first = false;
            self.buf.extend(b"#mtree\n");
            if self.keys & SET_KEYS == 0 {
                self.output_global_set = false; // Disabled.
            }
        }
        self.entry_bytes_remaining = entry.size() as u64;
        // While directory only mode, we do not handle non directory files.
        if self.dironly && entry.filetype() != AE_IFDIR {
            return Ok(ARCHIVE_OK);
        }
        let i = self.tree_add(MtreeEntry::new(entry))?;
        self.mtree_entry = Some(i);
        // If the current file is a regular file, we have to
        // compute the sum of its content.
        // Initialize a bunch of checksum context.
        if self.entries[i].reg_info.is_some() {
            self.sum_init();
            // honor archive_entry_set_digest() calls. These values will be
            // overwritten if archive_write_mtree_data() is called
            let compute_sum = self.compute_sum;
            if let Some(reg) = self.entries[i].reg_info.as_mut() {
                reg.compute_sum = compute_sum;
                reg.mset_digest = 0;
                for (k, &(bit, _, _)) in SUMS.iter().enumerate() {
                    let ty = k as c_int + 1;
                    if entry.digest_is_set(ty) {
                        reg.mset_digest |= 1 << k;
                        if compute_sum & bit != 0 {
                            reg.digest[k] = entry.digest(ty).unwrap_or_default().to_vec();
                        }
                    }
                }
            }
        }
        Ok(ARCHIVE_OK)
    }
    fn data(&mut self, data: &[u8], _: &mut dyn Sink) -> Result<usize, Error> {
        let n = data
            .len()
            .min(usize::try_from(self.entry_bytes_remaining).unwrap_or(usize::MAX));
        self.entry_bytes_remaining -= n as u64;
        // We don't need to compute a regular file sum
        let Some(i) = self.mtree_entry else {
            return Ok(n);
        };
        if self.entries[i].filetype == AE_IFREG {
            self.sum_update(&data[..n]);
        }
        Ok(n)
    }
    fn finish_entry(&mut self, _: &mut dyn Sink) -> Result<(), Error> {
        if let Some(i) = self.mtree_entry.take() {
            self.sum_final(i);
        }
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if let Some(root) = self.root {
            self.write_mtree_entry_tree(root);
        }
        sink.write(&self.buf)
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

    fn entry(path: &[u8], mode: Mode, owner: (i64, i64, &[u8], &[u8])) -> Entry {
        let mut e = Entry::new(None);
        e.set_pathname(path);
        e.set_mode(mode);
        e.set_uid(owner.0);
        e.set_gid(owner.1);
        e.set_uname(owner.2);
        e.set_gname(owner.3);
        e.set_mtime(1000, 0);
        e
    }

    /// The entries of a pax archive written by Python's tarfile, and the
    /// bytes upstream's bsdtar wrote for them (`@in.tar`).
    fn write_sample(classic: bool, options: &[&[u8]]) -> Vec<u8> {
        let base = Base::new(WRITE_MAGIC);
        let mut mtree = Mtree::new(classic);
        for o in options {
            assert_eq!(mtree.options(&base, o, Some(b"1")).unwrap(), ARCHIVE_OK);
        }
        let ug = (1, 2, b"u".as_slice(), b"g".as_slice());
        let none = (3, 4, b"".as_slice(), b"".as_slice());
        let mut entries = vec![
            (entry(b"./", AE_IFDIR | 0o755, (0, 0, b"root", b"wheel")), 0),
            (entry(b"a", AE_IFREG | 0o644, ug), 3),
            (entry(b"b", AE_IFREG | 0o644, ug), 0),
            (entry(b"c", AE_IFREG | 0o600, (3, 2, b"", b"g")), 0),
            (entry(b"d/", AE_IFDIR | 0o755, ug), 0),
            (
                entry(
                    &[b"d/".as_slice(), &[b'e'; 40]].concat(),
                    AE_IFREG | 0o640,
                    ug,
                ),
                1,
            ),
            (entry(b"d/f*?[ #=\\", AE_IFREG | 0o644, ug), 0),
            (entry(b"d/sub/", AE_IFDIR | 0o700, none), 0),
            (entry(b"d/sub/z", AE_IFREG | 0o444, none), 0),
            (entry(b"lnk", AE_IFLNK | 0o777, ug), 0),
            (entry(b"fifo", AE_IFIFO | 0o644, ug), 0),
        ];
        entries[9].0.set_symlink(b"a b");
        let mut out = Output(Vec::new());
        for (mut e, size) in entries {
            e.set_size(size);
            assert_eq!(mtree.header(&base, &mut e, &mut out).unwrap(), ARCHIVE_OK);
            mtree.data(&b"abc"[..size as usize], &mut out).unwrap();
            mtree.finish_entry(&mut out).unwrap();
        }
        mtree.close(&mut out).unwrap();
        out.0
    }

    #[test]
    fn use_set_and_indent_match_upstream() {
        let expected = "#mtree
/set type=file uname=u uid=1 gname=g gid=2 mode=644
.               gname=wheel uname=root time=1000.0 mode=755 gid=0 uid=0 \\
                type=dir
./a             time=1000.0 size=3
./b             time=1000.0 size=0
./c             time=1000.0 mode=600 uid=3 size=0
./fifo          time=1000.0 type=fifo
./lnk           time=1000.0 mode=777 type=link link=a\\040b
./d             time=1000.0 mode=755 type=dir
./d/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \\
                time=1000.0 mode=640 size=1
./d/f\\052\\077\\133\\040\\043\\075\\134 \\
                time=1000.0 size=0
./d/sub         time=1000.0 mode=700 gid=4 uid=3 type=dir
./d/sub/z       time=1000.0 mode=444 gid=4 uid=3 size=0
";
        let out = write_sample(false, &[b"use-set", b"indent"]);
        assert_eq!(String::from_utf8(out).unwrap(), expected);
    }

    #[test]
    fn classic_matches_upstream() {
        let expected = "#mtree

# /.
/set type=file uname=u uid=1 gname=g gid=2 mode=644
.               gname=wheel uname=root time=1000.0 mode=755 gid=0 uid=0 \\
                type=dir
    a           time=1000.0 size=3
    b           time=1000.0 size=0
    c           time=1000.0 mode=600 uid=3 size=0
    fifo        time=1000.0 type=fifo
    lnk         time=1000.0 mode=777 type=link link=a\\040b

# ./d
d               time=1000.0 mode=755 type=dir
    eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \\
                time=1000.0 mode=640 size=1
    f\\052\\077\\133\\040\\043\\075\\134 \\
                time=1000.0 size=0

# ./d/sub
sub             time=1000.0 mode=700 gid=4 uid=3 type=dir
    z           time=1000.0 mode=444 gid=4 uid=3 size=0
# ./d/sub
..

# ./d
..

# /.
..

";
        let out = write_sample(true, &[]);
        assert_eq!(String::from_utf8(out).unwrap(), expected);
    }

    #[test]
    fn classic_indent_matches_upstream() {
        let expected = "#mtree

# /.
/set type=file uname=u uid=1 gname=g gid=2 mode=644
.               gname=wheel uname=root time=1000.0 mode=755 gid=0 uid=0 \\
                type=dir
    a               time=1000.0 size=3
    b               time=1000.0 size=0
    c               time=1000.0 mode=600 uid=3 size=0
    fifo            time=1000.0 type=fifo
    lnk             time=1000.0 mode=777 type=link link=a\\040b

# ./d
    d               time=1000.0 mode=755 type=dir
        eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \\
                        time=1000.0 mode=640 size=1
        f\\052\\077\\133\\040\\043\\075\\134 \\
                        time=1000.0 size=0

# ./d/sub
        sub             time=1000.0 mode=700 gid=4 uid=3 type=dir
            z               time=1000.0 mode=444 gid=4 uid=3 size=0
        # ./d/sub
        ..

    # ./d
    ..

# /.
..

";
        let out = write_sample(true, &[b"indent"]);
        assert_eq!(String::from_utf8(out).unwrap(), expected);
    }

    #[test]
    fn filenames_are_canonicalized_like_upstream() {
        for (path, parentdir, basename) in [
            (b".".as_slice(), None, b".".as_slice()),
            (b"./", Some(b"".as_slice()), b"."),
            (b"", Some(b"."), b""),
            (b"/abs/x", Some(b"./abs"), b"x"),
            (b"a/../b", Some(b"."), b"b"),
            (b"../../y", Some(b"."), b"y"),
            (b"a//b/./c", Some(b"./a/b"), b"c"),
            (b"p/q/../../r", Some(b"."), b"r"),
            (b"s/./t/.", Some(b"./s"), b"t"),
            (b"u/v/..", Some(b"./u"), b"v"),
            (b"w/x/../../../z", Some(b"."), b"z"),
            (b"m/n/o/../../p", Some(b"./m"), b"p"),
            (b"..dots", Some(b"."), b"..dots"),
            (b"k2/", Some(b"."), b"k2"),
        ] {
            assert_eq!(
                setup_filenames(path),
                (parentdir.map(<[u8]>::to_vec), basename.to_vec()),
                "{}",
                String::from_utf8_lossy(path)
            );
        }
    }

    #[test]
    fn tree_errors_match_upstream() {
        let base = Base::new(WRITE_MAGIC);
        let mut mtree = Mtree::new(false);
        let mut out = Output(Vec::new());
        let mut header = |path: &[u8], mode| {
            let mut e = entry(path, mode, (0, 0, b"", b""));
            let r = mtree.header(&base, &mut e, &mut out);
            mtree.finish_entry(&mut out).unwrap();
            r.map_err(|e| (e.code, String::from_utf8(e.msg).unwrap()))
        };
        assert_eq!(
            header(b".", AE_IFREG | 0o644),
            Err((ARCHIVE_FAILED, "Root entry '.' must be a directory".into()))
        );
        assert_eq!(header(b"ff", AE_IFREG | 0o644), Ok(ARCHIVE_OK));
        // A duplicate is merged into the first entry without a warning.
        assert_eq!(header(b"ff", AE_IFREG | 0o600), Ok(ARCHIVE_OK));
        assert_eq!(
            header(b"ff/g", AE_IFREG | 0o644),
            Err((
                ARCHIVE_FAILED,
                "`ff' is not a directory, we cannot insert `ff/g' ".into()
            ))
        );
        assert_eq!(
            header(&[b"q/".as_slice(), &[b'M'; 256], b"/y"].concat(), AE_IFREG),
            Err((ARCHIVE_FATAL, "A name buffer is too small".into()))
        );
    }

    /// The checks of upstream's test_write_format_mtree_preset_digests.c:
    /// a digest set on the entry is kept unless data is written, even
    /// zero bytes of it.
    #[test]
    fn preset_digests_are_replaced_by_any_written_data() {
        for k in 0..SUMS.len() {
            for data in [None, Some(b"".as_slice()), Some(b"abcd")] {
                let base = Base::new(WRITE_MAGIC);
                let mut mtree = Mtree::new(false);
                mtree.options(&base, b"all", Some(b"1")).unwrap();
                let mut e = Entry::new(None);
                e.set_pathname(b"test.data");
                e.set_filetype(AE_IFREG.into());
                e.set_size(4);
                let ty = k as c_int + 1;
                let preset = vec![0xfe; crate::entry::digest_len(ty).unwrap()];
                e.set_digest(ty, &preset);
                let mut out = Output(Vec::new());
                mtree.header(&base, &mut e, &mut out).unwrap();
                if let Some(data) = data {
                    mtree.data(data, &mut out).unwrap();
                }
                mtree.finish_entry(&mut out).unwrap();
                mtree.close(&mut out).unwrap();
                let out = String::from_utf8(out.0).unwrap();
                for (j, &(_, other, algorithm)) in SUMS.iter().enumerate() {
                    let digest = if j == k && data.is_none() {
                        preset.clone()
                    } else {
                        let mut d = Digest::new(algorithm);
                        d.update(data.unwrap_or_default());
                        d.finalize()
                    };
                    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                    let other = std::str::from_utf8(other).unwrap();
                    assert!(out.contains(&format!(" {other}digest={hex}")), "{out}");
                }
            }
        }
    }
}
