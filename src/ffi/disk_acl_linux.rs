/*-
 * Copyright (c) 2003-2009 Tim Kientzle
 * Copyright (c) 2010-2012 Michihiro NAKAJIMA
 * Copyright (c) 2017 Martin Matuska
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

// Ported from libarchive/archive_disk_acl_linux.c.

//! POSIX.1e ACLs on Linux. Upstream goes through libacl; here the ACLs are
//! the `system.posix_acl_access` and `system.posix_acl_default` extended
//! attributes libacl reads and writes, in the kernel's format (a
//! little-endian version 2 header, then `{u16 tag, u16 perm, u32 id}`
//! entries), with libacl's semantics: a file without an access ACL has the
//! one its mode makes, a directory without a default ACL an empty one, and
//! entries are kept in libacl's order. RichACLs need a library and a kernel
//! patch that never reached mainline; like upstream's usual build, this has
//! none. Elsewhere, only the format's tests build it.
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use crate::acl::{self, TYPE_ACCESS, TYPE_DEFAULT, TYPE_POSIX1E};
use crate::archive::{ARCHIVE_ERRNO_MISC, ARCHIVE_FAILED, ARCHIVE_OK, Base};
use crate::entry::Entry;
use std::ffi::{CStr, c_int};

// libacl's tags, in the order its entries sort.
const USER_OBJ: u16 = 0x01;
const USER: u16 = 0x02;
const GROUP_OBJ: u16 = 0x04;
const GROUP: u16 = 0x08;
const MASK: u16 = 0x10;
const OTHER: u16 = 0x20;
/// ACL_UNDEFINED_ID: the qualifier of an entry that has none.
const UNDEFINED_ID: u32 = u32::MAX;
/// ACL_EA_VERSION.
const VERSION: u32 = 2;
const ACCESS: &CStr = c"system.posix_acl_access";
const DEFAULT: &CStr = c"system.posix_acl_default";

const PERMS: [(c_int, u16); 3] = [
    (acl::EXECUTE, 0x1), // ACL_EXECUTE
    (acl::WRITE, 0x2),   // ACL_WRITE
    (acl::READ, 0x4),    // ACL_READ
];

/// One libacl entry: its tag, permission bits and qualifier.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Ace {
    tag: u16,
    perm: u16,
    id: u32,
}

impl Ace {
    fn key(&self) -> (u16, u32) {
        (self.tag, self.id)
    }
}

/// libacl's __acl_from_xattr: the entries sorted by tag, then qualifier
/// (glibc's qsort is a stable merge sort), or `None` where libacl fails
/// with EINVAL.
fn decode(bytes: &[u8]) -> Option<Vec<Ace>> {
    let (header, body) = bytes.split_first_chunk::<4>()?;
    if u32::from_le_bytes(*header) != VERSION || body.len() % 8 != 0 {
        return None;
    }
    let mut entries = body
        .chunks_exact(8)
        .map(|e| {
            let &[t0, t1, p0, p1, i0, i1, i2, i3] = e.first_chunk::<8>()?;
            let tag = u16::from_le_bytes([t0, t1]);
            let id = match tag {
                USER_OBJ | GROUP_OBJ | MASK | OTHER => UNDEFINED_ID,
                USER | GROUP => u32::from_le_bytes([i0, i1, i2, i3]),
                _ => return None,
            };
            let perm = u16::from_le_bytes([p0, p1]);
            Some(Ace { tag, perm, id })
        })
        .collect::<Option<Vec<_>>>()?;
    entries.sort_by_key(Ace::key);
    Some(entries)
}

/// libacl's __acl_to_xattr.
fn encode(entries: &[Ace]) -> Vec<u8> {
    let mut bytes = VERSION.to_le_bytes().to_vec();
    for e in entries {
        let id = if matches!(e.tag, USER | GROUP) {
            e.id
        } else {
            UNDEFINED_ID
        };
        bytes.extend_from_slice(&e.tag.to_le_bytes());
        bytes.extend_from_slice(&e.perm.to_le_bytes());
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    bytes
}

/// libacl's acl_from_mode.
fn from_mode(mode: u32) -> Vec<Ace> {
    [(USER_OBJ, 6), (GROUP_OBJ, 3), (OTHER, 0)]
        .map(|(tag, shift)| Ace {
            tag,
            perm: ((mode >> shift) & 7) as u16,
            id: UNDEFINED_ID,
        })
        .to_vec()
}

/// Adds an entry as upstream's set_acl builds one with libacl:
/// acl_create_entry appends it, then acl_set_tag_type and, for a named
/// user or group, acl_set_qualifier each move it after the entries that
/// sort before it or equal to it. An entry is not moved while it is the
/// only one, nor while a named one's qualifier is ACL_UNDEFINED_ID.
fn add(entries: &mut Vec<Ace>, tag: u16, perm: u16, id: Option<u32>) {
    fn reorder(entries: &mut Vec<Ace>, i: usize) -> usize {
        let Some(&e) = entries.get(i) else {
            return i;
        };
        if entries.len() <= 1 || (matches!(e.tag, USER | GROUP) && e.id == UNDEFINED_ID) {
            return i;
        }
        entries.remove(i);
        let at = entries
            .iter()
            .position(|h| h.key() > e.key())
            .unwrap_or(entries.len());
        entries.insert(at, e);
        at
    }
    entries.push(Ace {
        tag,
        perm,
        id: UNDEFINED_ID,
    });
    let i = reorder(entries, entries.len() - 1);
    if let Some(id) = id
        && let Some(e) = entries.get_mut(i)
    {
        e.id = id;
        reorder(entries, i);
    }
}

/// libacl's acl_get_fd (with `fd`) or acl_get_file: the ACL in the
/// attribute, or for a file without one, the one its mode makes (access)
/// or an empty one if it is a directory (default); `None` where libacl
/// returns NULL.
#[cfg(target_os = "linux")]
fn get(src: super::disk_sys::Source, name: &CStr) -> Option<Vec<Ace>> {
    let value = src.get(name, &mut []).and_then(|len| {
        if len > 16 * 1024 * 1024 {
            return Err(std::io::Error::from_raw_os_error(libc::ENOMEM));
        }
        let mut value = vec![0; len];
        let len = src.get(name, &mut value)?;
        value.truncate(len);
        Ok(value)
    });
    match value {
        Ok(bytes) if !bytes.is_empty() => decode(&bytes),
        Err(e) if e.raw_os_error() != Some(libc::ENODATA) => None,
        _ => {
            let st = src.stat().ok()?;
            if name == ACCESS {
                Some(from_mode(st.st_mode as u32))
            } else {
                (st.st_mode & libc::S_IFMT == libc::S_IFDIR).then(Vec::new)
            }
        }
    }
}

/// Upstream's translate_acl: adds `acl`'s entries to `entry` as `kind`.
#[cfg(target_os = "linux")]
fn translate(
    entry: &mut Entry,
    acl: &[Ace],
    kind: c_int,
    user: &mut super::disk::NameLookup,
    group: &mut super::disk::NameLookup,
) {
    for ace in acl {
        let id = ace.id as c_int;
        let (tag, id, name) = match ace.tag {
            USER => (acl::USER, id, user.lookup(id.into(), false)),
            GROUP => (acl::GROUP, id, group.lookup(id.into(), true)),
            MASK => (acl::MASK, -1, None),
            USER_OBJ => (acl::USER_OBJ, -1, None),
            GROUP_OBJ => (acl::GROUP_OBJ, -1, None),
            OTHER => (acl::OTHER, -1, None),
            // Skip types that libarchive can't support.
            _ => continue,
        };
        let perm = PERMS
            .iter()
            .filter(|(_, p)| ace.perm & p != 0)
            .fold(0, |perm, (a, _)| perm | a);
        entry
            .acl
            .add_entry(kind, perm, tag, id, name.map(CStr::to_bytes));
    }
}

/// Upstream's archive_read_disk_entry_setup_acls with libacl: the access
/// ACL of `fd`, or else of `path` unless it is a symlink not followed, and
/// a directory's default ACL by `path`. Where libacl finds no ACL, there
/// is none.
#[cfg(target_os = "linux")]
pub fn read(
    entry: &mut Entry,
    fd: Option<c_int>,
    path: &CStr,
    follow: bool,
    user: &mut super::disk::NameLookup,
    group: &mut super::disk::NameLookup,
) {
    use super::disk_sys::Source;
    entry.acl.clear();
    let file = Source::Path(path, true);
    let access = match fd {
        Some(fd) => get(Source::Fd(fd), ACCESS),
        // We can't get the ACL of a symlink, so we assume it can't have one.
        None if !follow && entry.filetype() == libc::S_IFLNK => None,
        None => get(file, ACCESS),
    };
    if let Some(acl) = access {
        translate(entry, &acl, TYPE_ACCESS, user, group);
    }
    // Only directories can have default ACLs.
    if entry.filetype() == libc::S_IFDIR
        && let Some(acl) = get(file, DEFAULT)
    {
        translate(entry, &acl, TYPE_DEFAULT, user, group);
    }
}

/// Upstream's set_acl with libacl: sets `entry`'s ACL of type `want` on
/// `target`, whose mode is `mode`.
#[cfg(target_os = "linux")]
fn set_acl(
    a: &Base,
    target: &super::disk_sys::Target,
    entry: &mut Entry,
    mode: u32,
    want: c_int,
    user: &mut super::disk::IdLookup,
    group: &mut super::disk::IdLookup,
) -> c_int {
    if entry.acl.reset(want) == 0 {
        return ARCHIVE_OK;
    }
    let (name, tname) = if want == TYPE_ACCESS {
        (ACCESS, "access")
    } else {
        (DEFAULT, "default")
    };
    // Linux does not support ACLs on symbolic links.
    if mode & libc::S_IFMT as u32 == libc::S_IFLNK as u32 {
        return ARCHIVE_OK;
    }
    if want == TYPE_DEFAULT && mode & libc::S_IFMT as u32 != libc::S_IFDIR as u32 {
        return a
            .warn(libc::EINVAL, "Cannot set default ACL on non-directory")
            .code();
    }
    let mut aces = Vec::new();
    loop {
        let (r, item) = entry.acl_next(want);
        if r != ARCHIVE_OK {
            break;
        }
        let (tag, id) = match item.tag {
            acl::USER => (
                USER,
                Some(user.lookup(item.name, item.id.into(), false) as u32),
            ),
            acl::GROUP => (
                GROUP,
                Some(group.lookup(item.name, item.id.into(), true) as u32),
            ),
            acl::USER_OBJ => (USER_OBJ, None),
            acl::GROUP_OBJ => (GROUP_OBJ, None),
            acl::MASK => (MASK, None),
            acl::OTHER => (OTHER, None),
            _ => {
                let e = crate::util::Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    "Unsupported ACL tag",
                );
                return a.raise(e);
            }
        };
        let perm = PERMS
            .iter()
            .filter(|(p, _)| item.permset & p != 0)
            .fold(0, |perm, (_, l)| perm | l);
        add(&mut aces, tag, perm, id);
    }
    match target.xattr(name, &encode(&aces)) {
        Ok(()) => ARCHIVE_OK,
        // Filesystem doesn't support ACLs.
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => ARCHIVE_OK,
        Err(e) => {
            let msg = if target.is_open() && want == TYPE_ACCESS {
                format!("Failed to set acl on fd: {tname}")
            } else {
                format!("Failed to set acl: {tname}")
            };
            a.warn(e.raw_os_error().unwrap_or(libc::EIO), msg).code()
        }
    }
}

/// Upstream's archive_write_disk_set_acls with libacl: the access ACL,
/// then, if that worked, the default ACL. `mode` is the one upstream
/// passes; only its file type matters.
#[cfg(target_os = "linux")]
pub fn write(
    a: &Base,
    target: &super::disk_sys::Target,
    entry: &Entry,
    mode: u32,
    user: &mut super::disk::IdLookup,
    group: &mut super::disk::IdLookup,
) -> c_int {
    let mut entry = entry.clone_entry();
    let types = entry.acl.types();
    let mut ret = ARCHIVE_OK;
    if types & TYPE_POSIX1E != 0 {
        if types & TYPE_ACCESS != 0 {
            ret = set_acl(a, target, &mut entry, mode, TYPE_ACCESS, user, group);
            if ret != ARCHIVE_OK {
                return ret;
            }
        }
        if types & TYPE_DEFAULT != 0 {
            ret = set_acl(a, target, &mut entry, mode, TYPE_DEFAULT, user, group);
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ace(tag: u16, perm: u16, id: u32) -> Ace {
        Ace { tag, perm, id }
    }

    #[test]
    fn decoding_checks_and_sorts_as_libacl_does() {
        let bytes = |entries: &[(u16, u16, u32)]| {
            let mut b = 2u32.to_le_bytes().to_vec();
            for &(t, p, i) in entries {
                b.extend_from_slice(&t.to_le_bytes());
                b.extend_from_slice(&p.to_le_bytes());
                b.extend_from_slice(&i.to_le_bytes());
            }
            b
        };
        // The kernel keeps whatever order was set; libacl sorts by tag and
        // id, keeping duplicates in order, and ignores the id of an entry
        // that has none.
        let stored = bytes(&[
            (OTHER, 4, 7),
            (USER, 4, 2000),
            (USER_OBJ, 7, 0),
            (USER, 2, 1000),
            (USER, 1, 1000),
            (MASK, 7, UNDEFINED_ID),
            (GROUP_OBJ, 5, UNDEFINED_ID),
        ]);
        assert_eq!(
            decode(&stored),
            Some(vec![
                ace(USER_OBJ, 7, UNDEFINED_ID),
                ace(USER, 2, 1000),
                ace(USER, 1, 1000),
                ace(USER, 4, 2000),
                ace(GROUP_OBJ, 5, UNDEFINED_ID),
                ace(MASK, 7, UNDEFINED_ID),
                ace(OTHER, 4, UNDEFINED_ID),
            ])
        );
        assert_eq!(decode(&bytes(&[])), Some(Vec::new()));
        // EINVAL: a short header, another version, a partial entry, an
        // unknown tag.
        assert_eq!(decode(&[2, 0, 0]), None);
        assert_eq!(decode(&1u32.to_le_bytes()), None);
        assert_eq!(
            decode(&[&bytes(&[(USER_OBJ, 7, 0)])[..], &[0]].concat()),
            None
        );
        assert_eq!(decode(&bytes(&[(0x40, 7, 0)])), None);
        assert_eq!(decode(&bytes(&[(0, 7, 0)])), None);
    }

    #[test]
    fn encoding_is_the_kernel_format() {
        let entries = [
            ace(USER_OBJ, 7, 5),
            ace(USER, 4, 1000),
            ace(GROUP_OBJ, 5, 0),
            ace(MASK, 6, 0),
            ace(OTHER, 0, 0),
        ];
        let expected: &[u8] = &[
            2, 0, 0, 0, //
            1, 0, 7, 0, 0xff, 0xff, 0xff, 0xff, //
            2, 0, 4, 0, 0xe8, 0x03, 0, 0, //
            4, 0, 5, 0, 0xff, 0xff, 0xff, 0xff, //
            0x10, 0, 6, 0, 0xff, 0xff, 0xff, 0xff, //
            0x20, 0, 0, 0, 0xff, 0xff, 0xff, 0xff,
        ];
        assert_eq!(encode(&entries), expected);
        let decoded = decode(expected).unwrap();
        assert_eq!(encode(&decoded), expected);
        assert_eq!(
            from_mode(0o40751),
            vec![
                ace(USER_OBJ, 7, UNDEFINED_ID),
                ace(GROUP_OBJ, 5, UNDEFINED_ID),
                ace(OTHER, 1, UNDEFINED_ID),
            ]
        );
    }

    #[test]
    fn entries_are_placed_as_libacl_places_them() {
        // archive_acl_next's order: the mode's three entries, then the
        // list as added.
        let mut entries = Vec::new();
        add(&mut entries, USER_OBJ, 7, None);
        add(&mut entries, GROUP_OBJ, 5, None);
        add(&mut entries, OTHER, 4, None);
        add(&mut entries, MASK, 7, None);
        add(&mut entries, USER, 4, Some(2000));
        add(&mut entries, GROUP, 2, Some(15));
        add(&mut entries, USER, 2, Some(1000));
        add(&mut entries, USER, 1, Some(1000));
        assert_eq!(
            entries,
            vec![
                ace(USER_OBJ, 7, UNDEFINED_ID),
                ace(USER, 2, 1000),
                ace(USER, 1, 1000),
                ace(USER, 4, 2000),
                ace(GROUP_OBJ, 5, UNDEFINED_ID),
                ace(GROUP, 2, 15),
                ace(MASK, 7, UNDEFINED_ID),
                ace(OTHER, 4, UNDEFINED_ID),
            ]
        );
        // A named entry whose qualifier is ACL_UNDEFINED_ID is never
        // moved, so later entries go around it.
        let mut entries = Vec::new();
        add(&mut entries, USER_OBJ, 7, None);
        add(&mut entries, OTHER, 4, None);
        add(&mut entries, USER, 4, Some(UNDEFINED_ID));
        add(&mut entries, MASK, 7, None);
        add(&mut entries, GROUP_OBJ, 5, None);
        assert_eq!(
            entries,
            vec![
                ace(USER_OBJ, 7, UNDEFINED_ID),
                ace(GROUP_OBJ, 5, UNDEFINED_ID),
                ace(MASK, 7, UNDEFINED_ID),
                ace(OTHER, 4, UNDEFINED_ID),
                ace(USER, 4, UNDEFINED_ID),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn acls_round_trip_through_the_kernel() {
        use crate::archive::WRITE_DISK_MAGIC;
        use std::os::unix::ffi::OsStrExt;
        let root = std::env::temp_dir().join(format!(
            "libarchive-posix-acl-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let dir = root.join("dir");
        let mut entry = Entry::new(None);
        entry.set_pathname(dir.as_os_str().as_bytes());
        entry.set_mode(libc::S_IFDIR | 0o750);
        // SAFETY: getuid only returns the process's credentials.
        let uid = unsafe { libc::getuid() } as c_int;
        entry
            .acl
            .add_entry(TYPE_ACCESS, acl::READ, acl::USER, uid + 1, None);
        entry.acl.add_entry(
            TYPE_ACCESS,
            acl::READ | acl::WRITE | acl::EXECUTE,
            acl::MASK,
            -1,
            None,
        );
        // In the order libacl reads it back in.
        for (tag, id, perm) in [
            (acl::USER_OBJ, -1, 7),
            (acl::GROUP_OBJ, -1, 5),
            (acl::GROUP, uid + 2, 4),
            (acl::MASK, -1, 4),
            (acl::OTHER, -1, 0),
        ] {
            entry.acl.add_entry(TYPE_DEFAULT, perm, tag, id, None);
        }
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = crate::write_disk::WriteDisk::default();
        disk.options = crate::write_disk::ACL | crate::write_disk::PERM;
        assert_eq!(disk.header(&base, &mut entry), ARCHIVE_OK);
        assert_eq!(disk.close(&base), ARCHIVE_OK);
        let mut read_back = Entry::new(None);
        read_back.set_mode(libc::S_IFDIR | 0o750);
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
        let mut user = super::super::disk::NameLookup::default();
        let mut group = super::super::disk::NameLookup::default();
        read(&mut read_back, None, &path, false, &mut user, &mut group);
        // Some file systems have no ACLs; then neither has the entry.
        if read_back.acl.types() != 0 {
            let text =
                |e: &mut Entry, kind| String::from_utf8(e.acl_to_text(kind).unwrap()).unwrap();
            assert_eq!(
                text(&mut read_back, TYPE_ACCESS),
                text(&mut entry, TYPE_ACCESS)
            );
            assert_eq!(
                text(&mut read_back, TYPE_DEFAULT),
                text(&mut entry, TYPE_DEFAULT)
            );
        }
        std::fs::remove_dir_all(&root).unwrap();
    }
}
