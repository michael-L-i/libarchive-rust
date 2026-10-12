/*-
 * Copyright (c) 2003-2010 Tim Kientzle
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

// Ported from libarchive/archive_acl.c.

//! ACLs: POSIX.1e and NFSv4 entries, their text forms and the iteration
//! state behind `archive_entry_acl_next`. `Acl` also holds the file mode,
//! because the three standard POSIX.1e entries live there.

use crate::archive::{ARCHIVE_EOF, ARCHIVE_FAILED, ARCHIVE_FATAL, ARCHIVE_OK, ARCHIVE_WARN};
use crate::string::{ConvCache, MString, StringConv};
use libc::{mode_t, wchar_t};
use std::ffi::{CStr, c_int};
use std::ops::Range;

/// Permission bits.
pub const EXECUTE: c_int = 0x1;
pub const WRITE: c_int = 0x2;
pub const READ: c_int = 0x4;
pub const READ_DATA: c_int = 0x8;
pub const LIST_DIRECTORY: c_int = 0x8;
pub const WRITE_DATA: c_int = 0x10;
pub const ADD_FILE: c_int = 0x10;
pub const APPEND_DATA: c_int = 0x20;
pub const ADD_SUBDIRECTORY: c_int = 0x20;
pub const READ_NAMED_ATTRS: c_int = 0x40;
pub const WRITE_NAMED_ATTRS: c_int = 0x80;
pub const DELETE_CHILD: c_int = 0x100;
pub const READ_ATTRIBUTES: c_int = 0x200;
pub const WRITE_ATTRIBUTES: c_int = 0x400;
pub const DELETE: c_int = 0x800;
pub const READ_ACL: c_int = 0x1000;
pub const WRITE_ACL: c_int = 0x2000;
pub const WRITE_OWNER: c_int = 0x4000;
pub const SYNCHRONIZE: c_int = 0x8000;

const PERMS_POSIX1E: c_int = EXECUTE | WRITE | READ;
const PERMS_NFS4: c_int = EXECUTE
    | READ_DATA
    | LIST_DIRECTORY
    | WRITE_DATA
    | ADD_FILE
    | APPEND_DATA
    | ADD_SUBDIRECTORY
    | READ_NAMED_ATTRS
    | WRITE_NAMED_ATTRS
    | DELETE_CHILD
    | READ_ATTRIBUTES
    | WRITE_ATTRIBUTES
    | DELETE
    | READ_ACL
    | WRITE_ACL
    | WRITE_OWNER
    | SYNCHRONIZE;

/// Inheritance values (NFS4 ACLs only); included in permset.
const ENTRY_INHERITED: c_int = 0x0100_0000;
const ENTRY_FILE_INHERIT: c_int = 0x0200_0000;
const ENTRY_DIRECTORY_INHERIT: c_int = 0x0400_0000;
const ENTRY_NO_PROPAGATE_INHERIT: c_int = 0x0800_0000;
const ENTRY_INHERIT_ONLY: c_int = 0x1000_0000;
const ENTRY_SUCCESSFUL_ACCESS: c_int = 0x2000_0000;
const ENTRY_FAILED_ACCESS: c_int = 0x4000_0000;
const INHERITANCE_NFS4: c_int = ENTRY_FILE_INHERIT
    | ENTRY_DIRECTORY_INHERIT
    | ENTRY_NO_PROPAGATE_INHERIT
    | ENTRY_INHERIT_ONLY
    | ENTRY_SUCCESSFUL_ACCESS
    | ENTRY_FAILED_ACCESS
    | ENTRY_INHERITED;

pub const TYPE_ACCESS: c_int = 0x100;
pub const TYPE_DEFAULT: c_int = 0x200;
pub const TYPE_ALLOW: c_int = 0x400;
pub const TYPE_DENY: c_int = 0x800;
pub const TYPE_AUDIT: c_int = 0x1000;
pub const TYPE_ALARM: c_int = 0x2000;
pub const TYPE_POSIX1E: c_int = TYPE_ACCESS | TYPE_DEFAULT;
pub const TYPE_NFS4: c_int = TYPE_ALLOW | TYPE_DENY | TYPE_AUDIT | TYPE_ALARM;

/// Tag values mimic POSIX.1e.
pub const USER: c_int = 10001;
pub const USER_OBJ: c_int = 10002;
pub const GROUP: c_int = 10003;
pub const GROUP_OBJ: c_int = 10004;
pub const MASK: c_int = 10005;
pub const OTHER: c_int = 10006;
pub const EVERYONE: c_int = 10107;

pub const STYLE_EXTRA_ID: c_int = 0x1;
pub const STYLE_MARK_DEFAULT: c_int = 0x2;
pub const STYLE_SOLARIS: c_int = 0x4;
pub const STYLE_SEPARATOR_COMMA: c_int = 0x8;
pub const STYLE_COMPACT: c_int = 0x10;

const NFSV4_PERM_MAP: [(c_int, u8); 14] = [
    (READ_DATA | LIST_DIRECTORY, b'r'),
    (WRITE_DATA | ADD_FILE, b'w'),
    (EXECUTE, b'x'),
    (APPEND_DATA | ADD_SUBDIRECTORY, b'p'),
    (DELETE, b'd'),
    (DELETE_CHILD, b'D'),
    (READ_ATTRIBUTES, b'a'),
    (WRITE_ATTRIBUTES, b'A'),
    (READ_NAMED_ATTRS, b'R'),
    (WRITE_NAMED_ATTRS, b'W'),
    (READ_ACL, b'c'),
    (WRITE_ACL, b'C'),
    (WRITE_OWNER, b'o'),
    (SYNCHRONIZE, b's'),
];

const NFSV4_FLAG_MAP: [(c_int, u8); 7] = [
    (ENTRY_FILE_INHERIT, b'f'),
    (ENTRY_DIRECTORY_INHERIT, b'd'),
    (ENTRY_INHERIT_ONLY, b'i'),
    (ENTRY_NO_PROPAGATE_INHERIT, b'n'),
    (ENTRY_SUCCESSFUL_ACCESS, b'S'),
    (ENTRY_FAILED_ACCESS, b'F'),
    (ENTRY_INHERITED, b'I'),
];

struct AclEntry {
    /// E.g., access or default.
    type_: c_int,
    /// E.g., user/group/other/mask.
    tag: c_int,
    /// r/w/x bits.
    permset: c_int,
    /// uid/gid for user/group.
    id: c_int,
    /// uname/gname.
    name: MString,
}

/// One entry as `archive_acl_next` reports it.
pub struct Item<'a> {
    pub type_: c_int,
    pub permset: c_int,
    pub tag: c_int,
    pub id: c_int,
    pub name: Option<&'a CStr>,
}

#[derive(Default)]
pub struct Acl {
    pub mode: mode_t,
    entries: Vec<AclEntry>,
    /// Index of the entry `next` reads; `entries.len()` is the end.
    p: usize,
    /// See `next` for details.
    state: c_int,
    /// The text last returned by the deprecated `archive_entry_acl_text_w`,
    /// with its NUL.
    pub text_w: Option<Vec<wchar_t>>,
    /// The text last returned by the deprecated `archive_entry_acl_text`,
    /// with its NUL.
    pub text: Option<Vec<u8>>,
    types: c_int,
}

fn nonempty<T: PartialEq + From<u8>>(name: Option<&[T]>) -> Option<&[T]> {
    name.filter(|n| n.first().is_some_and(|c| *c != T::from(0)))
}

impl Acl {
    pub(crate) fn resource_metadata_size(&self) -> Option<usize> {
        let entries = self.entries.iter().try_fold(0usize, |n, e| {
            n.checked_add(std::mem::size_of::<AclEntry>())?
                .checked_add(e.name.resource_metadata_size()?)
        })?;
        entries
            .checked_add(self.text.as_ref().map_or(0, Vec::len))?
            .checked_add(
                self.text_w
                    .as_ref()
                    .map_or(0, Vec::len)
                    .checked_mul(std::mem::size_of::<wchar_t>())?,
            )
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.text_w = None;
        self.text = None;
        self.p = 0;
        self.types = 0;
        self.state = 0; // Not counting.
    }

    pub fn copy_from(&mut self, src: &Acl) {
        self.clear();
        self.mode = src.mode;
        for ap in &src.entries {
            if let Some(ap2) = self.new_entry(ap.type_, ap.permset, ap.tag, ap.id) {
                ap2.name = ap.name.clone();
            }
        }
    }

    pub fn add_entry(
        &mut self,
        type_: c_int,
        permset: c_int,
        tag: c_int,
        id: c_int,
        name: Option<&[u8]>,
    ) -> c_int {
        if self.special(type_, permset, tag) {
            return ARCHIVE_OK;
        }
        let Some(ap) = self.new_entry(type_, permset, tag, id) else {
            return ARCHIVE_FAILED;
        };
        match nonempty(name) {
            Some(name) => ap.name.copy_mbs(name),
            None => ap.name.clear(),
        }
        ARCHIVE_OK
    }

    pub fn add_entry_w(
        &mut self,
        type_: c_int,
        permset: c_int,
        tag: c_int,
        id: c_int,
        name: Option<&[wchar_t]>,
    ) -> c_int {
        if self.special(type_, permset, tag) {
            return ARCHIVE_OK;
        }
        let Some(ap) = self.new_entry(type_, permset, tag, id) else {
            return ARCHIVE_FAILED;
        };
        match nonempty(name) {
            Some(name) => ap.name.copy_wcs(name),
            None => ap.name.clear(),
        }
        ARCHIVE_OK
    }

    /// Like `add_entry` with a name in the charset of `sc`.
    pub fn add_entry_l(
        &mut self,
        type_: c_int,
        permset: c_int,
        tag: c_int,
        id: c_int,
        name: Option<&[u8]>,
        sc: Option<&StringConv>,
    ) -> c_int {
        if self.special(type_, permset, tag) {
            return ARCHIVE_OK;
        }
        let Some(ap) = self.new_entry(type_, permset, tag, id) else {
            return ARCHIVE_FAILED;
        };
        match nonempty(name) {
            Some(name) => {
                if ap.name.copy_mbs_len_l(name, sc).is_err() {
                    return ARCHIVE_WARN;
                }
            }
            None => ap.name.clear(),
        }
        ARCHIVE_OK
    }

    /// If this ACL entry is part of the standard POSIX permissions set,
    /// store the permissions in the mode and return true.
    fn special(&mut self, type_: c_int, permset: c_int, tag: c_int) -> bool {
        if type_ == TYPE_ACCESS && (permset & !0o7) == 0 {
            let (shift, mask) = match tag {
                USER_OBJ => (6, 0o700),
                GROUP_OBJ => (3, 0o070),
                OTHER => (0, 0o007),
                _ => return false,
            };
            self.mode &= !mask;
            self.mode |= ((permset & 7) << shift) as mode_t;
            return true;
        }
        false
    }

    /// Allocate and populate a new ACL entry with everything but the name.
    fn new_entry(
        &mut self,
        type_: c_int,
        permset: c_int,
        tag: c_int,
        id: c_int,
    ) -> Option<&mut AclEntry> {
        // Reject an invalid type.
        if ![
            TYPE_ACCESS,
            TYPE_DEFAULT,
            TYPE_ALLOW,
            TYPE_DENY,
            TYPE_AUDIT,
            TYPE_ALARM,
        ]
        .contains(&type_)
        {
            return None;
        }

        // Type argument must be a valid NFS4 or POSIX.1e type.
        // The type must agree with anything already set and
        // the permset must be compatible.
        if type_ & TYPE_NFS4 != 0 {
            if self.types & !TYPE_NFS4 != 0 {
                return None;
            }
            if permset & !(PERMS_NFS4 | INHERITANCE_NFS4) != 0 {
                return None;
            }
        } else {
            if self.types & !TYPE_POSIX1E != 0 {
                return None;
            }
            if permset & !PERMS_POSIX1E != 0 {
                return None;
            }
        }

        // Verify the tag is valid and compatible with NFS4 or POSIX.1e.
        match tag {
            // Tags valid in both NFS4 and POSIX.1e.
            USER | USER_OBJ | GROUP | GROUP_OBJ => {}
            // Tags valid only in POSIX.1e.
            MASK | OTHER if type_ & !TYPE_POSIX1E == 0 => {}
            // Tags valid only in NFS4.
            EVERYONE if type_ & !TYPE_NFS4 == 0 => {}
            _ => return None,
        }

        self.text_w = None;
        self.text = None;

        // If there's a matching entry already in the list, overwrite it.
        // NFSv4 entries may be repeated and are not overwritten.
        //
        // TODO: compare names of no id is provided (needs more rework)
        let found = (type_ & TYPE_NFS4 == 0)
            .then(|| {
                self.entries.iter().position(|ap| {
                    ap.type_ == type_
                        && ap.tag == tag
                        && ap.id == id
                        && (id != -1 || (tag != USER && tag != GROUP))
                })
            })
            .flatten();
        if let Some(i) = found {
            let ap = self.entries.get_mut(i)?;
            ap.permset = permset;
            return Some(ap);
        }

        // Add a new entry to the end of the list.
        self.entries.push(AclEntry {
            type_,
            tag,
            permset,
            id,
            name: MString::default(),
        });
        self.types |= type_;
        self.entries.last_mut()
    }

    /// Return a count of entries matching "want_type".
    pub fn count(&self, want_type: c_int) -> c_int {
        let mut count = self
            .entries
            .iter()
            .filter(|ap| ap.type_ & want_type != 0)
            .count() as c_int;
        if count > 0 && want_type & TYPE_ACCESS != 0 {
            count += 3;
        }
        count
    }

    /// Return a bitmask of stored ACL types in an ACL list.
    pub fn types(&self) -> c_int {
        self.types
    }

    /// Prepare for reading entries from the ACL data.  Returns a count
    /// of entries matching "want_type", or zero if there are no
    /// non-extended ACL entries of that type.
    pub fn reset(&mut self, want_type: c_int) -> c_int {
        let count = self.count(want_type);

        // If the only entries are the three standard ones,
        // then don't return any ACL data.  (In this case,
        // client can just use chmod(2) to set permissions.)
        let cutoff = if want_type & TYPE_ACCESS != 0 { 3 } else { 0 };

        self.state = if count > cutoff { USER_OBJ } else { 0 };
        self.p = 0;
        count
    }

    /// Return the next ACL entry in the list.  Fake entries for the
    /// standard permissions and include them in the returned list.
    ///
    /// On `ARCHIVE_WARN` only the name and id of the result are meaningful.
    pub fn next(&mut self, a: Option<&mut ConvCache>, want_type: c_int) -> (c_int, Item<'_>) {
        let mut item = Item {
            type_: 0,
            permset: 0,
            tag: 0,
            id: -1,
            name: None,
        };

        // The acl_state is either zero (no entries available), -1
        // (reading from list), or an entry type (retrieve that type
        // from ae_stat.aest_mode).
        if self.state == 0 {
            return (ARCHIVE_WARN, item);
        }

        // The first three access entries are special.
        if want_type & TYPE_ACCESS != 0 {
            let standard = match self.state {
                USER_OBJ => Some((self.mode >> 6, USER_OBJ, GROUP_OBJ)),
                GROUP_OBJ => Some((self.mode >> 3, GROUP_OBJ, OTHER)),
                OTHER => Some((self.mode, OTHER, -1)),
                _ => None,
            };
            if let Some((perms, tag, next_state)) = standard {
                item.permset = (perms & 7) as c_int;
                item.type_ = TYPE_ACCESS;
                item.tag = tag;
                self.state = next_state;
                if tag == OTHER {
                    self.p = 0;
                }
                return (ARCHIVE_OK, item);
            }
        }

        let start = self.p.min(self.entries.len());
        let found = self
            .entries
            .iter()
            .skip(start)
            .position(|ap| ap.type_ & want_type != 0)
            .map(|i| start + i);
        let Some(i) = found else {
            // End of ACL entries.
            self.p = self.entries.len();
            self.state = 0;
            return (ARCHIVE_EOF, item);
        };
        self.p = i + 1;
        let Some(ap) = self.entries.get_mut(i) else {
            return (ARCHIVE_EOF, item);
        };
        item.type_ = ap.type_;
        item.permset = ap.permset;
        item.tag = ap.tag;
        item.id = ap.id;
        item.name = ap.name.get_mbs_c(a).ok().flatten();
        (ARCHIVE_OK, item)
    }

    /// Determine what type of ACL do we want.
    fn text_want_type(&self, flags: c_int) -> c_int {
        // Check if ACL is NFSv4.
        if self.types & TYPE_NFS4 != 0 {
            // NFSv4 should never mix with POSIX.1e.
            return if self.types & TYPE_POSIX1E != 0 {
                0
            } else {
                TYPE_NFS4
            };
        }

        // Now deal with POSIX.1e ACLs.
        let want_type = flags & TYPE_POSIX1E;

        // By default we want both access and default ACLs.
        if want_type == 0 {
            TYPE_POSIX1E
        } else {
            want_type
        }
    }

    /// Filemode-mapping ACL entries are stored exclusively in the mode so
    /// they should not be in the list.
    fn is_mode_entry(ap: &AclEntry) -> bool {
        ap.type_ == TYPE_ACCESS && matches!(ap.tag, USER_OBJ | GROUP_OBJ | OTHER)
    }

    /// Check if ACL text would be empty.
    fn text_empty(&self, want_type: c_int) -> bool {
        !self
            .entries
            .iter()
            .any(|ap| ap.type_ & want_type != 0 && !Self::is_mode_entry(ap))
    }

    /// Generate a wide text version of the ACL. The flags parameter controls
    /// the type and style of the generated ACL. An entry whose name does not
    /// convert is left out.
    pub fn format_w(&mut self, flags: c_int, a: Option<&mut ConvCache>) -> Option<Vec<wchar_t>> {
        let mut a = a;
        self.format(flags, true, |name| {
            name.get_wcs(a.as_deref_mut())
                .map(|n| n.map(<[wchar_t]>::to_vec))
                .map_err(|_| ())
        })
    }

    /// Generate a text version of the ACL. The flags parameter controls
    /// the type and style of the generated ACL. Names are converted to the
    /// charset of `sc`; if one fails, there is no text.
    pub fn format_l(&mut self, flags: c_int, sc: Option<&StringConv>) -> Option<Vec<u8>> {
        self.format(flags, false, |name| {
            let (n, ok) = name.get_mbs_l(None, sc);
            if ok {
                Ok(n.map(<[u8]>::to_vec))
            } else {
                Err(())
            }
        })
    }

    fn format<T: Copy + From<u8>>(
        &mut self,
        mut flags: c_int,
        skip_unconvertible: bool,
        mut name_of: impl FnMut(&mut MString) -> Result<Option<Vec<T>>, ()>,
    ) -> Option<Vec<T>> {
        let want_type = self.text_want_type(flags);

        // Both NFSv4 and POSIX.1 types found.
        if want_type == 0 {
            return None;
        }

        if want_type == TYPE_POSIX1E {
            flags |= STYLE_MARK_DEFAULT;
        }

        if self.text_empty(want_type) {
            return None;
        }

        let separator = T::from(if flags & STYLE_SEPARATOR_COMMA != 0 {
            b','
        } else {
            b'\n'
        });
        let mut s = Vec::new();

        if want_type & TYPE_ACCESS != 0 {
            for (tag, shift) in [(USER_OBJ, 6), (GROUP_OBJ, 3), (OTHER, 0)] {
                if tag != USER_OBJ {
                    s.push(separator);
                }
                let perm = (self.mode & (0o7 << shift)) as c_int;
                append_entry(&mut s, None, TYPE_ACCESS, tag, flags, None, perm, -1);
            }
        }

        for ap in &mut self.entries {
            if ap.type_ & want_type == 0 || Self::is_mode_entry(ap) {
                continue;
            }
            let prefix =
                (ap.type_ == TYPE_DEFAULT && flags & STYLE_MARK_DEFAULT != 0).then_some("default:");
            let name = match name_of(&mut ap.name) {
                Ok(name) => name,
                Err(()) if skip_unconvertible => continue,
                Err(()) => return None,
            };
            if !s.is_empty() {
                s.push(separator);
            }
            let id = if flags & STYLE_EXTRA_ID != 0 || name.is_none() {
                ap.id
            } else {
                -1
            };
            let perm = ap.permset;
            append_entry(
                &mut s,
                prefix,
                ap.type_,
                ap.tag,
                flags,
                name.as_deref(),
                perm,
                id,
            );
        }
        // Entries may have been skipped.
        (!s.is_empty()).then_some(s)
    }

    /// Parse a wide ACL text string. See `parse_nl`.
    pub fn parse_w(&mut self, text: &[wchar_t], want_type: c_int) -> c_int {
        let cls: Vec<u8> = text
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| u8::try_from(c).unwrap_or(0xff))
            .collect();
        self.parse_into(
            &cls,
            true,
            want_type,
            |acl, type_, permset, tag, id, name| {
                acl.add_entry_w(type_, permset, tag, id, text.get(name))
            },
        )
    }

    /// Parse an ACL text string, which need not end in a NUL.
    ///
    /// The want_type argument may be one of the following:
    /// ARCHIVE_ENTRY_ACL_TYPE_ACCESS - text is a POSIX.1e ACL of type ACCESS
    /// ARCHIVE_ENTRY_ACL_TYPE_DEFAULT - text is a POSIX.1e ACL of type DEFAULT
    /// ARCHIVE_ENTRY_ACL_TYPE_NFS4 - text is as a NFSv4 ACL
    ///
    /// POSIX.1e ACL entries prefixed with "default:" are treated as
    /// ARCHIVE_ENTRY_ACL_TYPE_DEFAULT unless type is ARCHIVE_ENTRY_ACL_TYPE_NFS4
    pub fn parse_nl(&mut self, text: &[u8], want_type: c_int, sc: Option<&StringConv>) -> c_int {
        self.parse_into(
            text,
            false,
            want_type,
            |acl, type_, permset, tag, id, name| {
                acl.add_entry_l(type_, permset, tag, id, text.get(name), sc)
            },
        )
    }

    fn parse_into(
        &mut self,
        cls: &[u8],
        wide: bool,
        want_type: c_int,
        mut add: impl FnMut(&mut Acl, c_int, c_int, c_int, c_int, Range<usize>) -> c_int,
    ) -> c_int {
        match parse_text(cls, wide, want_type, |t, p, g, i, n| {
            add(self, t, p, g, i, n)
        }) {
            Ok((ret, types)) => {
                // Reset ACL.
                self.reset(types);
                ret
            }
            Err(r) => r,
        }
    }
}

/// Appends the ASCII `lit`.
fn put<T: From<u8>>(s: &mut Vec<T>, lit: &str) {
    s.extend(lit.bytes().map(T::from));
}

fn append_id<T: From<u8>>(s: &mut Vec<T>, id: c_int) {
    s.extend(id.max(0).to_string().bytes().map(T::from));
}

#[allow(clippy::too_many_arguments)]
fn append_entry<T: Copy + From<u8>>(
    s: &mut Vec<T>,
    prefix: Option<&str>,
    type_: c_int,
    tag: c_int,
    flags: c_int,
    mut name: Option<&[T]>,
    perm: c_int,
    mut id: c_int,
) {
    if let Some(prefix) = prefix {
        put(s, prefix);
    }
    match tag {
        USER_OBJ | GROUP_OBJ => {
            name = None;
            id = -1;
            if type_ & TYPE_NFS4 != 0 {
                put(s, if tag == USER_OBJ { "owner@" } else { "group@" });
            } else {
                put(s, if tag == USER_OBJ { "user" } else { "group" });
            }
        }
        USER => put(s, "user"),
        GROUP => put(s, "group"),
        MASK | OTHER | EVERYONE => {
            put(
                s,
                match tag {
                    MASK => "mask",
                    OTHER => "other",
                    _ => "everyone@",
                },
            );
            name = None;
            id = -1;
        }
        _ => {}
    }
    s.push(T::from(b':'));
    if type_ & TYPE_POSIX1E != 0 || tag == USER || tag == GROUP {
        if let Some(name) = name {
            s.extend_from_slice(name);
        } else if tag == USER || tag == GROUP {
            append_id(s, id);
            if type_ & TYPE_NFS4 == 0 {
                id = -1;
            }
        }
        // Solaris style has no second colon after other and mask.
        if flags & STYLE_SOLARIS == 0 || (tag != OTHER && tag != MASK) {
            s.push(T::from(b':'));
        }
    }
    if type_ & TYPE_POSIX1E != 0 {
        // POSIX.1e ACL perms.
        for (bits, c) in [(0o444, b'r'), (0o222, b'w'), (0o111, b'x')] {
            s.push(T::from(if perm & bits != 0 { c } else { b'-' }));
        }
    } else {
        // NFSv4 ACL perms.
        for map in [&NFSV4_PERM_MAP[..], &NFSV4_FLAG_MAP[..]] {
            for &(bits, c) in map {
                if perm & bits != 0 {
                    s.push(T::from(c));
                } else if flags & STYLE_COMPACT == 0 {
                    s.push(T::from(b'-'));
                }
            }
            s.push(T::from(b':'));
        }
        put(
            s,
            match type_ {
                TYPE_ALLOW => "allow",
                TYPE_DENY => "deny",
                TYPE_AUDIT => "audit",
                TYPE_ALARM => "alarm",
                _ => "",
            },
        );
    }
    if id != -1 {
        s.push(T::from(b':'));
        append_id(s, id);
    }
}

/// The part of `text` in `r`, which is empty if out of range.
fn field(text: &[u8], r: (usize, usize)) -> &[u8] {
    text.get(r.0..r.1).unwrap_or_default()
}

/// Parse the ACL text `text` into entries and hand each to `add`, with the
/// range of its name in `text`. Wide text is passed as its ASCII
/// projection, where every other character is a byte that matches nothing.
/// Returns the result code and the union of the entry types, or the code of
/// an `add` that failed.
fn parse_text(
    text: &[u8],
    wide: bool,
    mut want_type: c_int,
    mut add: impl FnMut(c_int, c_int, c_int, c_int, Range<usize>) -> c_int,
) -> Result<(c_int, c_int), c_int> {
    let numfields = match want_type {
        TYPE_POSIX1E | TYPE_ACCESS | TYPE_DEFAULT => 5,
        TYPE_NFS4 => 6,
        _ => return Err(ARCHIVE_FATAL),
    };
    if want_type == TYPE_POSIX1E {
        want_type = TYPE_ACCESS;
    }
    let mut ret = ARCHIVE_OK;
    let mut types = 0;
    let mut pos = 0;

    while text.get(pos).is_some_and(|&c| c != 0) {
        // Parse the fields out of the next entry,
        // advance 'pos' to start of next entry.
        let mut fields = 0;
        // Unused fields are blank: an empty range.
        let mut fld = [(0, 0); 6];
        loop {
            let (start, end, sep, next) = if wide {
                next_field_w(text, pos)
            } else {
                next_field(text, pos)
            };
            pos = next;
            if let Some(f) = fld.get_mut(fields).filter(|_| fields < numfields) {
                *f = (start, end);
            }
            fields += 1;
            if sep != b':' {
                break;
            }
        }
        let f = |fld: &[(usize, usize); 6], k: usize| {
            field(text, fld.get(k).copied().unwrap_or((0, 0)))
        };
        let range = |fld: &[(usize, usize); 6], k: usize| fld.get(k).copied().unwrap_or((0, 0));

        if text.get(range(&fld, 0).0) == Some(&b'#') {
            // Comment, skip entry.
            continue;
        }

        let mut n = 0;
        let mut sol = 0;
        let mut id = -1;
        let mut permset = 0;
        let mut name = (0, 0);
        let type_;
        let tag;

        if want_type != TYPE_NFS4 {
            // POSIX.1e ACLs.
            // Default keyword "default:user::rwx"
            // if found, we have one more field
            //
            // We also support old Solaris extension:
            // "defaultuser::rwx" is the default ACL corresponding
            // to "user::rwx", etc. valid only for first field.
            let s = f(&fld, 0);
            if s.first() == Some(&b'd')
                && (s.len() == 1 || (s.len() >= 7 && s.get(1..7) == Some(b"efault")))
            {
                type_ = TYPE_DEFAULT;
                if s.len() > 7 {
                    if let Some(f0) = fld.first_mut() {
                        f0.0 += 7;
                    }
                } else {
                    n = 1;
                }
            } else {
                type_ = want_type;
            }

            // Check for a numeric ID in field n+1 or n+3.
            match isint(f(&fld, n + 1)) {
                Err(()) => {
                    ret = ARCHIVE_WARN;
                    continue;
                }
                Ok(Some(v)) => id = v,
                Ok(None) => {}
            }
            // Field n+3 is optional.
            if id == -1 && fields > n + 3 {
                match isint(f(&fld, n + 3)) {
                    Err(()) => {
                        ret = ARCHIVE_WARN;
                        continue;
                    }
                    Ok(Some(v)) => id = v,
                    Ok(None) => {}
                }
            }

            let s = f(&fld, n);
            if s.is_empty() {
                ret = ARCHIVE_WARN;
                continue;
            }
            let rest = s.get(1..).unwrap_or_default();
            let named = |full: &[u8]| s.len() == 1 || rest == full;
            let mut t = match s.first() {
                Some(b'u') if named(b"ser") => USER_OBJ,
                Some(b'g') if named(b"roup") => GROUP_OBJ,
                Some(b'o') if named(b"ther") => OTHER,
                Some(b'm') if named(b"ask") => MASK,
                _ => 0,
            };

            match t {
                OTHER | MASK => {
                    let next = f(&fld, n + 1);
                    if fields == n + 2 && !next.is_empty() && ismode(next, &mut permset) {
                        // This is Solaris-style "other:rwx".
                        sol = 1;
                    } else if fields == n + 3 && !next.is_empty() {
                        // Invalid mask or other field.
                        ret = ARCHIVE_WARN;
                        continue;
                    }
                }
                USER_OBJ | GROUP_OBJ => {
                    if id != -1 || !f(&fld, n + 1).is_empty() {
                        name = range(&fld, n + 1);
                        t = if t == USER_OBJ { USER } else { GROUP };
                    }
                }
                _ => {
                    // Invalid tag, skip entry.
                    ret = ARCHIVE_WARN;
                    continue;
                }
            }
            tag = t;

            // Without "default:" we expect mode in field 2.
            // Exception: Solaris other and mask fields.
            if permset == 0 && !ismode(f(&fld, n + 2 - sol), &mut permset) {
                // Invalid mode, skip entry.
                ret = ARCHIVE_WARN;
                continue;
            }
        } else {
            // NFS4 ACLs.
            tag = match f(&fld, 0) {
                b"user" => USER,
                b"group" => GROUP,
                b"owner@" => USER_OBJ,
                b"group@" => GROUP_OBJ,
                b"everyone@" => EVERYONE,
                _ => {
                    // Invalid tag, skip entry.
                    ret = ARCHIVE_WARN;
                    continue;
                }
            };
            if tag == USER || tag == GROUP {
                n = 1;
                name = range(&fld, 1);
                match isint(f(&fld, 1)) {
                    Err(()) => {
                        ret = ARCHIVE_WARN;
                        continue;
                    }
                    Ok(Some(v)) => id = v,
                    Ok(None) => {}
                }
            }

            if !is_nfs4_perms(f(&fld, 1 + n), &mut permset) {
                // Invalid NFSv4 perms, skip entry.
                ret = ARCHIVE_WARN;
                continue;
            }
            if !is_nfs4_flags(f(&fld, 2 + n), &mut permset) {
                // Invalid NFSv4 flags, skip entry.
                ret = ARCHIVE_WARN;
                continue;
            }
            type_ = match f(&fld, 3 + n) {
                b"deny" => TYPE_DENY,
                b"allow" => TYPE_ALLOW,
                b"audit" => TYPE_AUDIT,
                b"alarm" => TYPE_ALARM,
                _ => {
                    // Invalid entry type, skip entry.
                    ret = ARCHIVE_WARN;
                    continue;
                }
            };
            match isint(f(&fld, 4 + n)) {
                Err(()) => {
                    ret = ARCHIVE_WARN;
                    continue;
                }
                Ok(Some(v)) => id = v,
                Ok(None) => {}
            }
        }

        // Add entry to the internal list.
        let r = add(type_, permset, tag, id, name.0..name.1);
        if r < ARCHIVE_WARN {
            return Err(r);
        }
        if r != ARCHIVE_OK {
            ret = ARCHIVE_WARN;
        }
        types |= type_;
    }
    Ok((ret, types))
}

/// Parse a string to a positive decimal integer. `Ok(None)` if the string is
/// empty or not all decimal digits, an error if the number is too large.
fn isint(s: &[u8]) -> Result<Option<c_int>, ()> {
    if s.is_empty() {
        return Ok(None);
    }
    let mut n: c_int = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return Ok(None);
        }
        let d = c_int::from(c - b'0');
        if n > c_int::MAX / 10 || (n == c_int::MAX / 10 && d >= c_int::MAX % 10) {
            return Err(());
        }
        n = n * 10 + d;
    }
    Ok(Some(n))
}

/// Parse a string as a mode field.  Returns true if the string is non-empty
/// and consists only of mode characters, false otherwise. Like upstream, it
/// leaves the bits found so far in `permset` when it fails.
fn ismode(s: &[u8], permset: &mut c_int) -> bool {
    if s.is_empty() {
        return false;
    }
    *permset = 0;
    for &c in s {
        *permset |= match c {
            b'r' | b'R' => READ,
            b'w' | b'W' => WRITE,
            b'x' | b'X' => EXECUTE,
            b'-' => 0,
            _ => return false,
        };
    }
    true
}

/// Parse a string as a NFS4 ACL permission field.
/// Returns true if the string consists only of NFS4 ACL permission
/// characters, false otherwise.
fn is_nfs4_perms(s: &[u8], permset: &mut c_int) -> bool {
    for &c in s {
        *permset |= match c {
            b'-' => 0,
            _ => match NFSV4_PERM_MAP.iter().find(|m| m.1 == c) {
                Some(&(bits, _)) => bits,
                None => return false,
            },
        };
    }
    true
}

/// Parse a string as a NFS4 ACL flags field.
/// Returns true if the string consists only of NFS4 ACL flag characters,
/// false otherwise.
fn is_nfs4_flags(s: &[u8], permset: &mut c_int) -> bool {
    for &c in s {
        *permset |= match c {
            b'-' => 0,
            _ => match NFSV4_FLAG_MAP.iter().find(|m| m.1 == c) {
                Some(&(bits, _)) => bits,
                None => return false,
            },
        };
    }
    true
}

/// Match "[:whitespace:]*(.*)[:whitespace:]*[:,\n]" in `text` from `pos`.
/// Returns the start and end of the field body (not including leading or
/// trailing whitespace), the separator (0 at the end of the text) and the
/// position just after the separator.
fn next_field(text: &[u8], mut p: usize) -> (usize, usize, u8, usize) {
    let at = |p: usize| text.get(p).copied();
    // Skip leading whitespace to find start of field.
    while matches!(at(p), Some(b' ' | b'\t' | b'\n')) {
        p += 1;
    }
    let start = p;

    // Locate end of field.
    while at(p).is_some_and(|c| !b" \t\n,:#".contains(&c)) {
        p += 1;
    }
    let end = p;

    // Scan for the separator.
    while at(p).is_some_and(|c| !b",:\n#".contains(&c)) {
        p += 1;
    }
    let mut sep = at(p).unwrap_or(0);

    // Handle in-field comments.
    if sep == b'#' {
        while at(p).is_some_and(|c| !b",\n".contains(&c)) {
            p += 1;
        }
        sep = at(p).unwrap_or(0);
    }

    // Skip separator.
    if p < text.len() {
        p += 1;
    }
    (start, end, sep, p)
}

/// `next_field` for wide text: the field may contain whitespace. `text`
/// ends where the wide string does.
fn next_field_w(text: &[u8], mut p: usize) -> (usize, usize, u8, usize) {
    let at = |p: usize| text.get(p).copied().unwrap_or(0);
    // Skip leading whitespace to find start of field.
    while matches!(at(p), b' ' | b'\t' | b'\n') {
        p += 1;
    }
    let start = p;

    // Scan for the separator.
    while !matches!(at(p), 0 | b',' | b':' | b'\n' | b'#') {
        p += 1;
    }
    let mut sep = at(p);

    // Locate end of field, trim trailing whitespace if necessary.
    let mut end = p;
    while end > start && matches!(at(end - 1), b' ' | b'\t' | b'\n') {
        end -= 1;
    }

    // Handle in-field comments.
    if sep == b'#' {
        while !matches!(at(p), 0 | b',' | b'\n') {
            p += 1;
        }
        sep = at(p);
    }

    // Adjust scanner location.
    if at(p) != 0 {
        p += 1;
    }
    (start, end, sep, p)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The checks of test_acl_from_text_overread.c. In upstream the text is
    // copied into a buffer of exactly its length so that a read past its end
    // is out of bounds; here the slice is that buffer.
    #[test]
    fn whitespace_entries_do_not_overread() {
        for text in [" ", "   ", "\t", "\n\n", "user::rwx,   "] {
            for ty in [TYPE_ACCESS, TYPE_NFS4] {
                Acl::default().parse_nl(text.as_bytes(), ty, None);
            }
        }
    }

    #[test]
    fn trailing_whitespace_does_not_change_the_parse() {
        let count = |text: &str| {
            let mut acl = Acl::default();
            acl.parse_nl(text.as_bytes(), TYPE_ACCESS, None);
            acl.count(TYPE_ACCESS)
        };
        assert!(count("user:100:rwx") > 0);
        assert_eq!(count("user:100:rwx"), count("user:100:rwx   "));
    }

    #[test]
    fn standard_entries_live_in_the_mode() {
        let mut acl = Acl::default();
        assert_eq!(
            acl.add_entry(TYPE_ACCESS, 0o6, USER_OBJ, -1, None),
            ARCHIVE_OK
        );
        assert_eq!(acl.add_entry(TYPE_ACCESS, 0o4, OTHER, -1, None), ARCHIVE_OK);
        assert_eq!(
            (acl.mode, acl.count(TYPE_ACCESS), acl.types()),
            (0o604, 0, 0)
        );
        assert_eq!(
            acl.add_entry(TYPE_ACCESS, 0o5, USER, 7, Some(b"bob")),
            ARCHIVE_OK
        );
        assert_eq!(acl.reset(TYPE_ACCESS), 4);
        let mut tags = Vec::new();
        loop {
            let (r, item) = acl.next(None, TYPE_ACCESS);
            if r != ARCHIVE_OK {
                assert_eq!(r, ARCHIVE_EOF);
                break;
            }
            tags.push((
                item.tag,
                item.permset,
                item.name.map(|n| n.to_bytes().to_vec()),
            ));
        }
        assert_eq!(
            tags,
            [
                (USER_OBJ, 6, None),
                (GROUP_OBJ, 0, None),
                (OTHER, 4, None),
                (USER, 5, Some(b"bob".to_vec())),
            ]
        );
        assert_eq!(acl.next(None, TYPE_ACCESS).0, ARCHIVE_WARN);
    }

    #[test]
    fn mixed_types_are_rejected() {
        let mut acl = Acl::default();
        assert_eq!(acl.add_entry(TYPE_ACCESS, 0o5, USER, 1, None), ARCHIVE_OK);
        assert_eq!(
            acl.add_entry(TYPE_ALLOW, READ_DATA, USER, 1, None),
            ARCHIVE_FAILED
        );
        assert_eq!(acl.parse_nl(b"", 0, None), ARCHIVE_FATAL);
    }

    #[test]
    fn text_roundtrip() {
        let mut acl = Acl::default();
        let text =
            b"user::rw-\nuser:bob:r-x\ngroup::r--\nmask::rwx\nother::---\ndefault:user:alice:rwx";
        assert_eq!(acl.parse_nl(text, TYPE_POSIX1E, None), ARCHIVE_OK);
        let out = acl.format_l(0, None).unwrap_or_default();
        assert_eq!(
            String::from_utf8_lossy(&out),
            "user::rw-\ngroup::r--\nother::---\nuser:bob:r-x\nmask::rwx\ndefault:user:alice:rwx"
        );
        let comma = acl
            .format_l(STYLE_SEPARATOR_COMMA | STYLE_EXTRA_ID | TYPE_ACCESS, None)
            .unwrap_or_default();
        assert_eq!(
            String::from_utf8_lossy(&comma),
            "user::rw-,group::r--,other::---,user:bob:r-x,mask::rwx"
        );
    }

    #[test]
    fn wide_fields_may_hold_spaces() {
        let wide: Vec<wchar_t> = "user:big bob:r-x".chars().map(|c| c as wchar_t).collect();
        let mut acl = Acl::default();
        assert_eq!(acl.parse_w(&wide, TYPE_ACCESS), ARCHIVE_OK);
        let out = acl.format_w(0, None).unwrap_or_default();
        let out: String = out
            .iter()
            .filter_map(|&c| char::from_u32(c as u32))
            .collect();
        assert_eq!(out, "user::---\ngroup::---\nother::---\nuser:big bob:r-x");
        // The narrow parser ends a name at whitespace.
        let mut acl = Acl::default();
        assert_eq!(
            acl.parse_nl(b"user:big bob:r-x", TYPE_ACCESS, None),
            ARCHIVE_OK
        );
        let out = acl.format_l(0, None).unwrap_or_default();
        assert_eq!(
            String::from_utf8_lossy(&out),
            "user::---\ngroup::---\nother::---\nuser:big:r-x"
        );
    }
}
