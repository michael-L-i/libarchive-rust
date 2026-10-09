/*-
 * Copyright (c) 2003-2007 Tim Kientzle
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

// Ported from libarchive/archive_entry.c.

//! `struct archive_entry`: the description of one archive member, basically
//! a `struct stat` with a few text fields added in.
//!
//! Note that the file type bits of the mode can be 0! This occurs when the
//! actual file type of the object is not in the archive. For example, 'tar'
//! archives store hardlinks without marking the type of the underlying
//! object.
//!
//! A `struct archive_entry *` is a leaked `Box<Entry>` (`src/ffi/entry.rs`).
//! Text fields return C strings that stay valid until the field changes or
//! the entry is freed.

use crate::acl::{self, Acl};
use crate::archive::{ARCHIVE_OK, ARCHIVE_WARN};
use crate::string::{ConvCache, ConvFailed, MString, StringConv};
use libc::{dev_t, mode_t, wchar_t};
use std::ffi::{CStr, c_int, c_ulong};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

pub type Mode = mode_t;
pub type Dev = dev_t;

/// The string conversions of the archive that made the entry, shared with
/// it and with every clone.
pub type Cache = Arc<Mutex<ConvCache>>;

pub const AE_IFMT: Mode = 0o170000;
pub const AE_IFREG: Mode = 0o100000;
pub const AE_IFLNK: Mode = 0o120000;
pub const AE_IFSOCK: Mode = 0o140000;
pub const AE_IFCHR: Mode = 0o020000;
pub const AE_IFBLK: Mode = 0o060000;
pub const AE_IFDIR: Mode = 0o040000;
pub const AE_IFIFO: Mode = 0o010000;

// Bitmap of the fields that are currently set.
const AE_SET_HARDLINK: u32 = 1;
const AE_SET_SYMLINK: u32 = 2;
const AE_SET_ATIME: u32 = 4;
const AE_SET_CTIME: u32 = 8;
const AE_SET_MTIME: u32 = 16;
const AE_SET_BIRTHTIME: u32 = 32;
const AE_SET_SIZE: u32 = 64;
const AE_SET_INO: u32 = 128;
const AE_SET_DEV: u32 = 256;
const AE_SET_PERM: u32 = 512;
const AE_SET_FILETYPE: u32 = 1024;
const AE_SET_UID: u32 = 2048;
const AE_SET_GID: u32 = 4096;
const AE_SET_RDEV: u32 = 8192;

const AE_ENCRYPTION_DATA: u8 = 1;
const AE_ENCRYPTION_METADATA: u8 = 2;

const DIGEST_MD5: c_int = 1;
const DIGEST_SHA512: c_int = 6;
/// The size of each digest, by type.
const DIGEST_LEN: [usize; 6] = [16, 20, 20, 32, 48, 64];

/// The size of a digest of type `ty`, if there is one.
pub fn digest_len(ty: c_int) -> Option<usize> {
    DIGEST_LEN.get(digest_index(ty)?).copied()
}

fn digest_index(ty: c_int) -> Option<usize> {
    if !(DIGEST_MD5..=DIGEST_SHA512).contains(&ty) {
        return None;
    }
    usize::try_from(ty - DIGEST_MD5).ok()
}

#[derive(Clone, Copy, Default)]
struct Time {
    sec: i64,
    nsec: u32,
}

/// The file metadata.
///
/// This is not just a `struct stat` because on some platforms the
/// `struct stat` has fields which are too narrow to hold the range of
/// possible values; we don't want to lose information if we read an archive
/// and write out another (e.g., in "tar -cf new.tar @old.tar").
#[derive(Clone, Copy, Default)]
struct Aest {
    atime: Time,
    ctime: Time,
    mtime: Time,
    birthtime: Time,
    gid: i64,
    ino: i64,
    nlink: u32,
    size: u64,
    uid: i64,
    // Because converting between device codes and major/minor values is
    // platform-specific and inherently a bit risky, we only do that
    // conversion lazily. That way, we will do a better job of preserving
    // information in those cases where no conversion is actually required.
    dev_is_broken_down: bool,
    dev: Dev,
    devmajor: Dev,
    devminor: Dev,
    rdev_is_broken_down: bool,
    rdev: Dev,
    rdevmajor: Dev,
    rdevminor: Dev,
}

pub struct Entry {
    /// The conversions of the archive the entry was made for, if any.
    pub(crate) cache: Option<Cache>,

    /// The `struct stat` handed out by `stat`. It is allocated once and
    /// refilled in place, so a pointer to it stays valid until the entry is
    /// cleared or freed.
    pub(crate) stat: Option<Box<libc::stat>>,
    /// Set to false whenever a field in `ae` changes.
    pub(crate) stat_valid: bool,

    ae: Aest,
    /// Bitmap of fields that are currently set.
    set: u32,

    /// Text fflags per fflagstostr(3).
    fflags_text: MString,
    /// Bitmap fflags.
    fflags_set: c_ulong,
    fflags_clear: c_ulong,
    /// Name of owning group.
    gname: MString,
    /// Name of target for hardlink or symlink.
    linkname: MString,
    /// Name of entry.
    pathname: MString,
    /// Name of owner.
    uname: MString,
    /// Not used within libarchive; useful for some clients: the path this
    /// entry is sourced from.
    sourcepath: MString,

    encryption: u8,
    mac_metadata: Vec<u8>,
    /// Bitmap of the digests that are set, by `1 << (type - 1)`.
    #[allow(dead_code)] // read by the mtree writer (phase 5)
    mset_digest: u32,
    digest: [[u8; 64]; 6],

    pub acl: Acl,

    /// Extended attributes. The list is walked from the last element back,
    /// as upstream prepends new ones.
    pub(crate) xattrs: Vec<crate::entry_xattr::Xattr>,
    /// The index of the attribute `xattr_next` returns next.
    pub(crate) xattr_p: Option<usize>,

    pub(crate) sparse: Vec<crate::entry_sparse::Sparse>,
    /// The index of the block `sparse_next` returns next.
    pub(crate) sparse_p: Option<usize>,

    pub(crate) strmode: [u8; 12],

    /// Symlink type support.
    symlink_type: c_int,
}

/// Locks the conversions for the duration of one getter or setter.
fn lock(cache: &Option<Cache>) -> Option<MutexGuard<'_, ConvCache>> {
    cache
        .as_ref()
        .map(|c| c.lock().unwrap_or_else(PoisonError::into_inner))
}

/// A text to store in a field: multibyte, UTF-8 or wide.
enum Text<'a> {
    Mbs(&'a [u8]),
    Utf8(&'a [u8]),
    Wcs(&'a [wchar_t]),
}

fn store(s: &mut MString, t: Text) {
    match t {
        Text::Mbs(v) => s.copy_mbs(v),
        Text::Utf8(v) => {
            s.copy_utf8(v);
        }
        Text::Wcs(v) => s.copy_wcs(v),
    }
}

fn update_utf8(s: &mut MString, cache: &Option<Cache>, v: &[u8]) -> bool {
    s.update_utf8(lock(cache).as_deref_mut(), v).is_ok()
}

/// `makedev`, `major` and `minor` as the platform's `<sys/types.h>` defines
/// them. libc's types for them differ between platforms.
#[allow(clippy::unnecessary_cast)]
pub(crate) fn make_dev(major: Dev, minor: Dev) -> Dev {
    libc::makedev(major as _, minor as _)
}

#[allow(clippy::unnecessary_cast)]
pub(crate) fn dev_major(dev: Dev) -> Dev {
    libc::major(dev) as Dev
}

#[allow(clippy::unnecessary_cast)]
pub(crate) fn dev_minor(dev: Dev) -> Dev {
    libc::minor(dev) as Dev
}

/// Getters and setters of one text field. The `_l` variants convert from or
/// to the charset of a string conversion, for the format readers and
/// writers. A getter returns the partial text of a failed conversion along
/// with false; a setter that fails leaves the field unset, so it only
/// reports the failure.
macro_rules! text_field {
    ($field:ident: $get_utf8:ident, $get_w:ident, $get_l:ident,
     $set:ident, $set_utf8:ident, $copy_w:ident, $update_utf8:ident, $clear:ident,
     $copy_l:ident) => {
        pub fn $get_utf8(&mut self) -> Option<&CStr> {
            let mut g = lock(&self.cache);
            self.$field.get_utf8_c(g.as_deref_mut()).ok().flatten()
        }

        pub fn $get_w(&mut self) -> Option<&[wchar_t]> {
            let mut g = lock(&self.cache);
            self.$field.get_wcs_z(g.as_deref_mut()).ok().flatten()
        }

        /// The string in the charset of `sc`; false if it did not convert
        /// completely.
        #[allow(dead_code)] // used by the format readers and writers (phases 3-4)
        pub fn $get_l(&mut self, sc: Option<&StringConv>) -> (Option<&[u8]>, bool) {
            let mut g = lock(&self.cache);
            self.$field.get_mbs_l(g.as_deref_mut(), sc)
        }

        pub fn $set(&mut self, v: &[u8]) {
            store(&mut self.$field, Text::Mbs(v));
        }

        pub fn $set_utf8(&mut self, v: &[u8]) {
            store(&mut self.$field, Text::Utf8(v));
        }

        pub fn $copy_w(&mut self, v: &[wchar_t]) {
            store(&mut self.$field, Text::Wcs(v));
        }

        pub fn $update_utf8(&mut self, v: &[u8]) -> bool {
            update_utf8(&mut self.$field, &self.cache, v)
        }

        /// Unsets the field, as C does when it passes NULL.
        pub fn $clear(&mut self) {
            self.$field.clear();
        }

        #[allow(dead_code)] // used by the format readers (phases 3-4)
        pub fn $copy_l(&mut self, v: &[u8], sc: Option<&StringConv>) -> Result<(), ConvFailed> {
            self.$field.copy_mbs_len_l(v, sc)
        }
    };
}

/// One timestamp: how to read it, set it and unset it.
macro_rules! time_field {
    ($field:ident, $bit:ident: $get:ident, $nsec:ident, $is_set:ident, $set:ident, $unset:ident) => {
        pub fn $get(&self) -> i64 {
            self.ae.$field.sec
        }

        pub fn $nsec(&self) -> i64 {
            i64::from(self.ae.$field.nsec)
        }

        pub fn $is_set(&self) -> c_int {
            (self.set & $bit) as c_int
        }

        pub fn $set(&mut self, t: i64, ns: i64) {
            self.stat_valid = false;
            self.set |= $bit;
            self.ae.$field = fix_ns(t, ns);
        }

        pub fn $unset(&mut self) {
            self.$set(0, 0);
            self.set &= !$bit;
        }
    };
}

/// This adjustment is needed to support the following idiom for adding
/// 1000ns to the stored time:
/// archive_entry_set_atime(archive_entry_atime(),
///                         archive_entry_atime_nsec() + 1000)
/// The additional if() here compensates for ambiguity in the C standard,
/// which permits two possible interpretations of a % b when a is negative.
fn fix_ns(mut t: i64, mut ns: i64) -> Time {
    t = t.wrapping_add(ns / 1_000_000_000);
    ns %= 1_000_000_000;
    if ns < 0 {
        t = t.wrapping_sub(1);
        ns += 1_000_000_000;
    }
    Time {
        sec: t,
        nsec: ns as u32,
    }
}

impl Entry {
    /// `archive_entry_new2`: an entry that converts text with the
    /// conversions of an archive, if given.
    pub fn new(cache: Option<Cache>) -> Entry {
        Entry {
            cache,
            stat: None,
            stat_valid: false,
            ae: Aest::default(),
            set: 0,
            fflags_text: MString::default(),
            fflags_set: 0,
            fflags_clear: 0,
            gname: MString::default(),
            linkname: MString::default(),
            pathname: MString::default(),
            uname: MString::default(),
            sourcepath: MString::default(),
            encryption: 0,
            mac_metadata: Vec::new(),
            mset_digest: 0,
            digest: [[0; 64]; 6],
            acl: Acl::default(),
            xattrs: Vec::new(),
            xattr_p: None,
            sparse: Vec::new(),
            sparse_p: None,
            strmode: [0; 12],
            symlink_type: 0,
        }
    }

    /// `archive_entry_clear`. Like upstream, it also forgets the archive.
    pub fn clear(&mut self) {
        *self = Entry::new(None);
    }

    /// `archive_entry_clone`.
    pub fn clone_entry(&self) -> Entry {
        let mut e = Entry::new(self.cache.clone());
        e.ae = self.ae;
        e.fflags_set = self.fflags_set;
        e.fflags_clear = self.fflags_clear;

        e.fflags_text = self.fflags_text.clone();
        e.gname = self.gname.clone();
        e.linkname = self.linkname.clone();
        e.pathname = self.pathname.clone();
        e.sourcepath = self.sourcepath.clone();
        e.set = self.set;
        e.uname = self.uname.clone();

        e.symlink_type = self.symlink_type;
        e.encryption = self.encryption;
        e.digest = self.digest;
        e.acl.copy_from(&self.acl);
        e.mac_metadata = self.mac_metadata.clone();

        // Each attribute is prepended to the copy, which reverses the list.
        for xp in self.xattrs.iter().rev() {
            e.xattr_add(&xp.name, &xp.value);
        }
        for sp in &self.sparse {
            e.sparse_add(sp.offset, sp.length);
        }
        e
    }

    // Functions for reading fields from an archive_entry.

    time_field!(atime, AE_SET_ATIME: atime, atime_nsec, atime_is_set, set_atime, unset_atime);
    time_field!(
        birthtime, AE_SET_BIRTHTIME:
        birthtime, birthtime_nsec, birthtime_is_set, set_birthtime, unset_birthtime
    );
    time_field!(ctime, AE_SET_CTIME: ctime, ctime_nsec, ctime_is_set, set_ctime, unset_ctime);
    time_field!(mtime, AE_SET_MTIME: mtime, mtime_nsec, mtime_is_set, set_mtime, unset_mtime);

    pub fn dev(&self) -> Dev {
        if self.ae.dev_is_broken_down {
            make_dev(self.ae.devmajor, self.ae.devminor)
        } else {
            self.ae.dev
        }
    }

    pub fn dev_is_set(&self) -> c_int {
        (self.set & AE_SET_DEV) as c_int
    }

    pub fn devmajor(&self) -> Dev {
        if self.ae.dev_is_broken_down {
            self.ae.devmajor
        } else {
            dev_major(self.ae.dev)
        }
    }

    pub fn devminor(&self) -> Dev {
        if self.ae.dev_is_broken_down {
            self.ae.devminor
        } else {
            dev_minor(self.ae.dev)
        }
    }

    pub fn filetype(&self) -> Mode {
        AE_IFMT & self.acl.mode
    }

    pub fn filetype_is_set(&self) -> c_int {
        (self.set & AE_SET_FILETYPE) as c_int
    }

    pub fn fflags(&self) -> (c_ulong, c_ulong) {
        (self.fflags_set, self.fflags_clear)
    }

    /// Note: if text was provided, this just returns that text.  If you
    /// really need the text to be rebuilt in a canonical form, set the
    /// text, ask for the bitmaps, then set the bitmaps.  (Setting the
    /// bitmaps clears any stored text.)  This design is deliberate: if
    /// we're editing archives, we don't want to discard flags just because
    /// they aren't supported on the current system.  The bitmap<->text
    /// conversions are platform-specific (see below).
    pub fn fflags_text(&mut self) -> Option<&CStr> {
        let mut g = lock(&self.cache);
        let has_text = matches!(self.fflags_text.get_mbs_c(g.as_deref_mut()), Ok(Some(_)));
        if !has_text {
            if self.fflags_set == 0 && self.fflags_clear == 0 {
                return None;
            }
            let p = fflags_to_str(self.fflags_set, self.fflags_clear)?;
            self.fflags_text.copy_mbs(&p);
        }
        self.fflags_text.get_mbs_c(g.as_deref_mut()).ok().flatten()
    }

    pub fn gid(&self) -> i64 {
        self.ae.gid
    }

    pub fn gid_is_set(&self) -> c_int {
        (self.set & AE_SET_GID) as c_int
    }

    pub fn ino(&self) -> i64 {
        self.ae.ino
    }

    pub fn ino_is_set(&self) -> c_int {
        (self.set & AE_SET_INO) as c_int
    }

    pub fn mode(&self) -> Mode {
        self.acl.mode
    }

    pub fn nlink(&self) -> u32 {
        self.ae.nlink
    }

    pub fn perm(&self) -> Mode {
        !AE_IFMT & self.acl.mode
    }

    pub fn perm_is_set(&self) -> c_int {
        (self.set & AE_SET_PERM) as c_int
    }

    pub fn rdev_is_set(&self) -> c_int {
        (self.set & AE_SET_RDEV) as c_int
    }

    pub fn rdev(&self) -> Dev {
        if self.rdev_is_set() == 0 {
            0
        } else if self.ae.rdev_is_broken_down {
            make_dev(self.ae.rdevmajor, self.ae.rdevminor)
        } else {
            self.ae.rdev
        }
    }

    pub fn rdevmajor(&self) -> Dev {
        if self.rdev_is_set() == 0 {
            0
        } else if self.ae.rdev_is_broken_down {
            self.ae.rdevmajor
        } else {
            dev_major(self.ae.rdev)
        }
    }

    pub fn rdevminor(&self) -> Dev {
        if self.rdev_is_set() == 0 {
            0
        } else if self.ae.rdev_is_broken_down {
            self.ae.rdevminor
        } else {
            dev_minor(self.ae.rdev)
        }
    }

    pub fn size(&self) -> i64 {
        self.ae.size as i64
    }

    pub fn size_is_set(&self) -> c_int {
        (self.set & AE_SET_SIZE) as c_int
    }

    pub fn symlink_type(&self) -> c_int {
        self.symlink_type
    }

    pub fn uid(&self) -> i64 {
        self.ae.uid
    }

    pub fn uid_is_set(&self) -> c_int {
        (self.set & AE_SET_UID) as c_int
    }

    pub fn is_data_encrypted(&self) -> bool {
        self.encryption & AE_ENCRYPTION_DATA == AE_ENCRYPTION_DATA
    }

    pub fn is_metadata_encrypted(&self) -> bool {
        self.encryption & AE_ENCRYPTION_METADATA == AE_ENCRYPTION_METADATA
    }

    pub fn is_encrypted(&self) -> c_int {
        c_int::from(self.encryption & (AE_ENCRYPTION_DATA | AE_ENCRYPTION_METADATA))
    }

    // Functions to set archive_entry properties.

    #[allow(clippy::unnecessary_cast)] // mode_t is narrower on some platforms
    pub fn set_filetype(&mut self, ty: u32) {
        self.stat_valid = false;
        self.acl.mode &= !AE_IFMT;
        self.acl.mode |= AE_IFMT & ty as Mode;
        self.set |= AE_SET_FILETYPE;
    }

    pub fn set_fflags(&mut self, set: c_ulong, clear: c_ulong) {
        self.fflags_text.clear();
        self.fflags_set = set;
        self.fflags_clear = clear;
    }

    /// Sets the flags from their text. Returns where the first token that is
    /// not a flag starts.
    pub fn copy_fflags_text(&mut self, flags: &[u8]) -> Option<usize> {
        self.fflags_text.copy_mbs(flags);
        let (set, clear, failed) = str_to_fflags(flags);
        self.fflags_set = set;
        self.fflags_clear = clear;
        failed
    }

    /// `copy_fflags_text` for wide text.
    pub fn copy_fflags_text_w(&mut self, flags: &[wchar_t]) -> Option<usize> {
        self.fflags_text.copy_wcs(flags);
        let (set, clear, failed) = str_to_fflags(&ascii_projection(flags));
        self.fflags_set = set;
        self.fflags_clear = clear;
        failed
    }

    pub fn set_gid(&mut self, g: i64) {
        self.stat_valid = false;
        self.ae.gid = g.max(0);
        self.set |= AE_SET_GID;
    }

    pub fn set_ino(&mut self, ino: i64) {
        self.stat_valid = false;
        if ino < 0 {
            self.set &= !AE_SET_INO;
            return;
        }
        self.set |= AE_SET_INO;
        self.ae.ino = ino;
    }

    pub fn set_dev(&mut self, d: Dev) {
        self.stat_valid = false;
        self.set |= AE_SET_DEV;
        self.ae.dev_is_broken_down = false;
        self.ae.dev = d;
    }

    pub fn set_devmajor(&mut self, m: Dev) {
        self.stat_valid = false;
        self.set |= AE_SET_DEV;
        self.ae.dev_is_broken_down = true;
        self.ae.devmajor = m;
    }

    pub fn set_devminor(&mut self, m: Dev) {
        self.stat_valid = false;
        self.set |= AE_SET_DEV;
        self.ae.dev_is_broken_down = true;
        self.ae.devminor = m;
    }

    pub fn set_mode(&mut self, m: Mode) {
        self.stat_valid = false;
        self.acl.mode = m;
        self.set |= AE_SET_PERM | AE_SET_FILETYPE;
    }

    pub fn set_nlink(&mut self, nlink: u32) {
        self.stat_valid = false;
        self.ae.nlink = nlink;
    }

    pub fn set_perm(&mut self, p: Mode) {
        self.stat_valid = false;
        self.acl.mode &= AE_IFMT;
        self.acl.mode |= !AE_IFMT & p;
        self.set |= AE_SET_PERM;
    }

    pub fn set_rdev(&mut self, m: Dev) {
        self.stat_valid = false;
        self.ae.rdev = m;
        self.ae.rdev_is_broken_down = false;
        self.ae.rdevmajor = 0;
        self.ae.rdevminor = 0;
        self.set |= AE_SET_RDEV;
    }

    pub fn set_rdevmajor(&mut self, m: Dev) {
        self.stat_valid = false;
        self.ae.rdev_is_broken_down = true;
        self.ae.rdev = 0;
        self.ae.rdevmajor = m;
        self.set |= AE_SET_RDEV;
    }

    pub fn set_rdevminor(&mut self, m: Dev) {
        self.stat_valid = false;
        self.ae.rdev_is_broken_down = true;
        self.ae.rdev = 0;
        self.ae.rdevminor = m;
        self.set |= AE_SET_RDEV;
    }

    pub fn set_size(&mut self, s: i64) {
        self.stat_valid = false;
        self.ae.size = s.max(0) as u64;
        self.set |= AE_SET_SIZE;
    }

    pub fn unset_size(&mut self) {
        self.set_size(0);
        self.set &= !AE_SET_SIZE;
    }

    pub fn set_symlink_type(&mut self, ty: c_int) {
        self.symlink_type = ty;
    }

    pub fn set_uid(&mut self, u: i64) {
        self.stat_valid = false;
        self.ae.uid = u.max(0);
        self.set |= AE_SET_UID;
    }

    pub fn set_is_data_encrypted(&mut self, is_encrypted: bool) {
        if is_encrypted {
            self.encryption |= AE_ENCRYPTION_DATA;
        } else {
            self.encryption &= !AE_ENCRYPTION_DATA;
        }
    }

    pub fn set_is_metadata_encrypted(&mut self, is_encrypted: bool) {
        if is_encrypted {
            self.encryption |= AE_ENCRYPTION_METADATA;
        } else {
            self.encryption &= !AE_ENCRYPTION_METADATA;
        }
    }

    text_field!(gname: gname_utf8, gname_w, gname_l,
        set_gname, set_gname_utf8, copy_gname_w, update_gname_utf8, clear_gname, copy_gname_l);
    text_field!(uname: uname_utf8, uname_w, uname_l,
        set_uname, set_uname_utf8, copy_uname_w, update_uname_utf8, clear_uname, copy_uname_l);
    text_field!(pathname: pathname_utf8, pathname_w, pathname_l,
        set_pathname, set_pathname_utf8, copy_pathname_w, update_pathname_utf8, clear_pathname,
        copy_pathname_l);

    pub fn gname(&mut self) -> Option<&CStr> {
        let mut g = lock(&self.cache);
        self.gname.get_mbs_c(g.as_deref_mut()).ok().flatten()
    }

    pub fn uname(&mut self) -> Option<&CStr> {
        let mut g = lock(&self.cache);
        self.uname.get_mbs_c(g.as_deref_mut()).ok().flatten()
    }

    /// Instead, our caller could have chosen a specific encoding
    /// (archive_mstring_get_mbs, archive_mstring_get_utf8,
    /// archive_mstring_get_wcs).  So we should try multiple
    /// encodings.  Try mbs first because of history, even though
    /// utf8 might be better for pathname portability.
    /// Also omit wcs because of type mismatch (char * versus wchar *)
    pub fn pathname(&mut self) -> Option<&CStr> {
        let mut g = lock(&self.cache);
        if self.pathname.get_mbs_c(g.as_deref_mut()).is_ok() {
            return self.pathname.get_mbs_c(g.as_deref_mut()).ok().flatten();
        }
        self.pathname.get_utf8_c(g.as_deref_mut()).ok().flatten()
    }

    pub fn sourcepath(&mut self) -> Option<&CStr> {
        let mut g = lock(&self.cache);
        self.sourcepath.get_mbs_c(g.as_deref_mut()).ok().flatten()
    }

    pub fn sourcepath_w(&mut self) -> Option<&[wchar_t]> {
        let mut g = lock(&self.cache);
        self.sourcepath.get_wcs_z(g.as_deref_mut()).ok().flatten()
    }

    pub fn set_sourcepath(&mut self, path: &[u8]) {
        store(&mut self.sourcepath, Text::Mbs(path));
    }

    pub fn copy_sourcepath_w(&mut self, path: &[wchar_t]) {
        store(&mut self.sourcepath, Text::Wcs(path));
    }

    pub fn clear_sourcepath(&mut self) {
        self.sourcepath.clear();
    }

    // The link target is one string for both kinds of link.

    pub fn set_link_to_hardlink(&mut self) {
        self.set &= !AE_SET_SYMLINK;
        self.set |= AE_SET_HARDLINK;
    }

    pub fn set_link_to_symlink(&mut self) {
        self.set &= !AE_SET_HARDLINK;
        self.set |= AE_SET_SYMLINK;
    }

    pub fn hardlink_is_set(&self) -> c_int {
        (self.set & AE_SET_HARDLINK) as c_int
    }

    pub fn hardlink(&mut self) -> Option<&CStr> {
        if self.set & AE_SET_HARDLINK == 0 {
            return None;
        }
        let mut g = lock(&self.cache);
        self.linkname.get_mbs_c(g.as_deref_mut()).ok().flatten()
    }

    pub fn hardlink_utf8(&mut self) -> Option<&CStr> {
        if self.set & AE_SET_HARDLINK == 0 {
            return None;
        }
        let mut g = lock(&self.cache);
        self.linkname.get_utf8_c(g.as_deref_mut()).ok().flatten()
    }

    pub fn hardlink_w(&mut self) -> Option<&[wchar_t]> {
        if self.set & AE_SET_HARDLINK == 0 {
            return None;
        }
        let mut g = lock(&self.cache);
        self.linkname.get_wcs_z(g.as_deref_mut()).ok().flatten()
    }

    #[allow(dead_code)] // for the format writers
    pub fn hardlink_l(&mut self, sc: Option<&StringConv>) -> (Option<&[u8]>, bool) {
        if self.set & AE_SET_HARDLINK == 0 {
            return (None, true);
        }
        let mut g = lock(&self.cache);
        self.linkname.get_mbs_l(g.as_deref_mut(), sc)
    }

    pub fn symlink(&mut self) -> Option<&CStr> {
        if self.set & AE_SET_SYMLINK == 0 {
            return None;
        }
        let mut g = lock(&self.cache);
        self.linkname.get_mbs_c(g.as_deref_mut()).ok().flatten()
    }

    pub fn symlink_utf8(&mut self) -> Option<&CStr> {
        if self.set & AE_SET_SYMLINK == 0 {
            return None;
        }
        let mut g = lock(&self.cache);
        self.linkname.get_utf8_c(g.as_deref_mut()).ok().flatten()
    }

    pub fn symlink_w(&mut self) -> Option<&[wchar_t]> {
        if self.set & AE_SET_SYMLINK == 0 {
            return None;
        }
        let mut g = lock(&self.cache);
        self.linkname.get_wcs_z(g.as_deref_mut()).ok().flatten()
    }

    #[allow(dead_code)] // for the format writers
    pub fn symlink_l(&mut self, sc: Option<&StringConv>) -> (Option<&[u8]>, bool) {
        if self.set & AE_SET_SYMLINK == 0 {
            return (None, true);
        }
        let mut g = lock(&self.cache);
        self.linkname.get_mbs_l(g.as_deref_mut(), sc)
    }

    // The setters of the link target. A NULL target of C has its own
    // `unset_*` method, which leaves the other kind of link alone and
    // returns false if it had to.

    /// Stores a hardlink target. Unlike the other setters, `set_hardlink`
    /// also unsets a symlink.
    fn put_hardlink(&mut self, t: Text) {
        store(&mut self.linkname, t);
        self.set |= AE_SET_HARDLINK;
    }

    pub fn set_hardlink(&mut self, target: &[u8]) {
        self.set &= !AE_SET_SYMLINK;
        self.put_hardlink(Text::Mbs(target));
    }

    pub fn set_hardlink_utf8(&mut self, target: &[u8]) {
        self.put_hardlink(Text::Utf8(target));
    }

    pub fn copy_hardlink(&mut self, target: &[u8]) {
        self.put_hardlink(Text::Mbs(target));
    }

    pub fn copy_hardlink_w(&mut self, target: &[wchar_t]) {
        self.put_hardlink(Text::Wcs(target));
    }

    pub fn update_hardlink_utf8(&mut self, target: &[u8]) -> bool {
        self.set |= AE_SET_HARDLINK;
        update_utf8(&mut self.linkname, &self.cache, target)
    }

    #[allow(dead_code)] // used by the format readers (phases 3-4)
    pub fn copy_hardlink_l(
        &mut self,
        target: &[u8],
        sc: Option<&StringConv>,
    ) -> Result<(), ConvFailed> {
        let r = self.linkname.copy_mbs_len_l(target, sc);
        self.set = (self.set & !AE_SET_HARDLINK) | if r.is_ok() { AE_SET_HARDLINK } else { 0 };
        r
    }

    pub fn unset_hardlink(&mut self) -> bool {
        if self.set & AE_SET_SYMLINK != 0 {
            return false;
        }
        self.set &= !AE_SET_HARDLINK;
        self.linkname.clear();
        true
    }

    fn put_symlink(&mut self, t: Text) {
        self.set &= !AE_SET_HARDLINK;
        store(&mut self.linkname, t);
        self.set |= AE_SET_SYMLINK;
    }

    pub fn set_symlink(&mut self, linkname: &[u8]) {
        self.put_symlink(Text::Mbs(linkname));
    }

    pub fn set_symlink_utf8(&mut self, linkname: &[u8]) {
        self.put_symlink(Text::Utf8(linkname));
    }

    pub fn copy_symlink_w(&mut self, linkname: &[wchar_t]) {
        self.put_symlink(Text::Wcs(linkname));
    }

    pub fn update_symlink_utf8(&mut self, linkname: &[u8]) -> bool {
        self.set = (self.set & !AE_SET_HARDLINK) | AE_SET_SYMLINK;
        update_utf8(&mut self.linkname, &self.cache, linkname)
    }

    #[allow(dead_code)] // used by the format readers (phases 3-4)
    pub fn copy_symlink_l(
        &mut self,
        linkname: &[u8],
        sc: Option<&StringConv>,
    ) -> Result<(), ConvFailed> {
        self.set &= !AE_SET_HARDLINK;
        let r = self.linkname.copy_mbs_len_l(linkname, sc);
        self.set = (self.set & !AE_SET_SYMLINK) | if r.is_ok() { AE_SET_SYMLINK } else { 0 };
        r
    }

    pub fn unset_symlink(&mut self) -> bool {
        if self.set & AE_SET_HARDLINK != 0 {
            return false;
        }
        self.set &= !(AE_SET_HARDLINK | AE_SET_SYMLINK);
        self.linkname.clear();
        true
    }

    /// Set symlink if symlink is already set, else set hardlink.
    fn put_link(&mut self, t: Option<Text>) {
        match t {
            Some(t) => store(&mut self.linkname, t),
            None => self.linkname.clear(),
        }
        self.put_link_flag();
    }

    fn put_link_flag(&mut self) {
        if self.set & AE_SET_SYMLINK == 0 {
            self.set |= AE_SET_HARDLINK;
        }
    }

    pub fn set_link(&mut self, target: &[u8]) {
        self.put_link(Some(Text::Mbs(target)));
    }

    pub fn set_link_utf8(&mut self, target: &[u8]) {
        self.put_link(Some(Text::Utf8(target)));
    }

    pub fn copy_link_w(&mut self, target: &[wchar_t]) {
        self.put_link(Some(Text::Wcs(target)));
    }

    pub fn update_link_utf8(&mut self, target: &[u8]) -> bool {
        let r = update_utf8(&mut self.linkname, &self.cache, target);
        self.put_link_flag();
        r
    }

    /// C's NULL target: the link is emptied but still counts as a link.
    pub fn unset_link(&mut self) {
        self.put_link(None);
    }

    #[allow(dead_code)] // used by the format readers (phases 3-4)
    pub fn copy_link_l(
        &mut self,
        target: &[u8],
        sc: Option<&StringConv>,
    ) -> Result<(), ConvFailed> {
        let r = self.linkname.copy_mbs_len_l(target, sc);
        self.put_link_flag();
        r
    }

    /// The Mac OS metadata, if there is any.
    pub fn mac_metadata(&self) -> Option<&[u8]> {
        (!self.mac_metadata.is_empty()).then_some(self.mac_metadata.as_slice())
    }

    /// Sets the metadata; empty metadata is none.
    pub fn copy_mac_metadata(&mut self, p: &[u8]) {
        self.mac_metadata = p.to_vec();
    }

    /// Digest handling.
    pub fn digest(&self, ty: c_int) -> Option<&[u8]> {
        self.digest.get(digest_index(ty)?)?.get(..digest_len(ty)?)
    }

    /// Copies a digest of the size `digest_len(ty)`.
    pub fn set_digest(&mut self, ty: c_int, digest: &[u8]) -> c_int {
        let slot = digest_index(ty)
            .and_then(|i| self.digest.get_mut(i))
            .zip(digest_len(ty))
            .and_then(|(slot, len)| Some((slot.get_mut(..len)?, digest.get(..len)?)));
        match slot {
            Some((slot, digest)) => {
                slot.copy_from_slice(digest);
                self.mset_digest |= 1 << (ty - DIGEST_MD5);
                ARCHIVE_OK
            }
            None => ARCHIVE_WARN,
        }
    }

    // ACL management.  The following would, of course, be a lot simpler
    // if: 1) the last draft of POSIX.1e were a really thorough and
    // complete standard that addressed the needs of ACL archiving and 2)
    // everyone followed it faithfully.  Alas, neither is true, so the
    // following is a lot more complex than might seem necessary to the
    // uninitiated.

    /// Return the next ACL entry in the list.  Fake entries for the
    /// standard permissions and include them in the returned list.
    pub fn acl_next(&mut self, want_type: c_int) -> (c_int, acl::Item<'_>) {
        let mut g = lock(&self.cache);
        self.acl.next(g.as_deref_mut(), want_type)
    }

    /// Generate a text version of the ACL. The flags parameter controls the
    /// style of the generated ACL.
    pub fn acl_to_text_w(&mut self, flags: c_int) -> Option<Vec<wchar_t>> {
        let mut g = lock(&self.cache);
        self.acl.format_w(flags, g.as_deref_mut())
    }

    pub fn acl_to_text(&mut self, flags: c_int) -> Option<Vec<u8>> {
        self.acl.format_l(flags, None)
    }

    /// Deprecated: the flags of the old text styles become the new ones.
    /// Returns false for an ACL that is not POSIX.1e, which has no text.
    fn acl_text_compat(flags: &mut c_int) -> bool {
        if *flags & acl::TYPE_POSIX1E == 0 {
            return false;
        }

        // ABI compat with old ARCHIVE_ENTRY_ACL_STYLE_EXTRA_ID.
        if *flags & OLD_STYLE_EXTRA_ID != 0 {
            *flags |= acl::STYLE_EXTRA_ID;
        }

        // ABI compat with old ARCHIVE_ENTRY_ACL_STYLE_MARK_DEFAULT.
        if *flags & OLD_STYLE_MARK_DEFAULT != 0 {
            *flags |= acl::STYLE_MARK_DEFAULT;
        }

        *flags |= acl::STYLE_SEPARATOR_COMMA;
        true
    }

    /// Deprecated: the text is kept in the ACL until the next call or the
    /// next change to the ACL.
    pub fn acl_text_w(&mut self, mut flags: c_int) -> Option<&[wchar_t]> {
        self.acl.text_w = None;
        if Self::acl_text_compat(&mut flags) {
            self.acl.text_w = self.acl_to_text_w(flags).map(|mut t| {
                t.push(0);
                t
            });
        }
        self.acl.text_w.as_deref()
    }

    /// Deprecated: the text is kept in the ACL until the next call or the
    /// next change to the ACL.
    pub fn acl_text(&mut self, mut flags: c_int) -> Option<&CStr> {
        self.acl.text = None;
        if Self::acl_text_compat(&mut flags) {
            self.acl.text = self.acl_to_text(flags).map(|mut t| {
                t.push(0);
                t
            });
        }
        CStr::from_bytes_until_nul(self.acl.text.as_deref()?).ok()
    }

    pub fn acl_from_text_w(&mut self, text: &[wchar_t], ty: c_int) -> c_int {
        self.acl.parse_w(text, ty)
    }

    pub fn acl_from_text(&mut self, text: &[u8], ty: c_int) -> c_int {
        self.acl.parse_nl(text, ty, None)
    }

    #[allow(dead_code)] // for the format readers
    pub fn acl_from_text_l(&mut self, text: &[u8], ty: c_int, sc: Option<&StringConv>) -> c_int {
        self.acl.parse_nl(text, ty, sc)
    }
}

const OLD_STYLE_EXTRA_ID: c_int = 1024;
const OLD_STYLE_MARK_DEFAULT: c_int = 2048;

/// The ASCII projection of wide text up to its NUL, in which every other
/// character is a byte that matches nothing.
fn ascii_projection(s: &[wchar_t]) -> Vec<u8> {
    s.iter()
        .take_while(|&&c| c != 0)
        .map(|&c| u8::try_from(c).unwrap_or(0xff))
        .collect()
}

/// A file flag: the names it goes by (the first being the canonical one, and
/// all starting with "no"), the bits it sets and the bits it clears.
struct Flag {
    names: &'static [&'static str],
    set: c_ulong,
    clear: c_ulong,
}

macro_rules! flag {
    ($set:expr, $clear:expr; $($name:literal),+) => {
        Flag { names: &[$($name),+], set: $set as c_ulong, clear: $clear as c_ulong }
    };
}

// Following code is modified from UC Berkeley sources, and
// is subject to the following copyright notice.
//
// Copyright (c) 1993
//    The Regents of the University of California.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 4. Neither the name of the University nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.

// Supported file flags on FreeBSD and Mac OS:
// sappnd,sappend        SF_APPEND
// arch,archived        SF_ARCHIVED
// schg,schange,simmutable    SF_IMMUTABLE
// sunlnk,sunlink        SF_NOUNLINK    (FreeBSD only)
// uappnd,uappend        UF_APPEND
// compressed            UF_COMPRESSED    (Mac OS only)
// hidden,uhidden        UF_HIDDEN
// uchg,uchange,uimmutable    UF_IMMUTABLE
// nodump            UF_NODUMP
// uunlnk,uunlink        UF_NOUNLINK    (FreeBSD only)
// offline,uoffline        UF_OFFLINE    (FreeBSD only)
// opaque            UF_OPAQUE
// rdonly,urdonly,readonly    UF_READONLY    (FreeBSD only)
// reparse,ureparse        UF_REPARSE    (FreeBSD only)
// sparse,usparse        UF_SPARSE    (FreeBSD only)
// system,usystem        UF_SYSTEM    (FreeBSD only)
//
// See chflags(2) for more information
//
// Supported file attributes on Linux:
// a    append only            FS_APPEND_FL        sappnd
// A    no atime updates        FS_NOATIME_FL        atime
// c    compress            FS_COMPR_FL        compress
// C    no copy on write        FS_NOCOW_FL        cow
// d    no dump                FS_NODUMP_FL        dump
// D    synchronous directory updates    FS_DIRSYNC_FL        dirsync
// i    immutable            FS_IMMUTABLE_FL        schg
// j    data journalling        FS_JOURNAL_DATA_FL    journal
// P    project hierarchy        FS_PROJINHERIT_FL    projinherit
// s    secure deletion            FS_SECRM_FL        securedeletion
// S    synchronous updates        FS_SYNC_FL        sync
// t    no tail-merging            FS_NOTAIL_FL        tail
// T    top of directory hierarchy    FS_TOPDIR_FL        topdir
// u    undeletable            FS_UNRM_FL        undel
//
// See ioctl_iflags(2) for more information
//
// Equivalent file flags supported on FreeBSD / Mac OS and Linux:
// SF_APPEND        FS_APPEND_FL        sappnd
// SF_IMMUTABLE        FS_IMMUTABLE_FL        schg
// UF_NODUMP        FS_NODUMP_FL        nodump
//
// Only the flags of Mac OS and Linux are supported here: the table is that
// of upstream's build on those systems, with the constants of
// <sys/stat.h> and <linux/fs.h>.

/// Preferred (shorter) names per flag first, all prefixed by "no".
#[cfg(target_vendor = "apple")]
const FILEFLAGS: &[Flag] = &[
    flag!(libc::SF_APPEND, 0; "nosappnd", "nosappend"),
    flag!(libc::SF_ARCHIVED, 0; "noarch", "noarchived"),
    flag!(libc::SF_IMMUTABLE, 0; "noschg", "noschange", "nosimmutable"),
    flag!(0x0010_0000, 0; "nosunlnk", "nosunlink"), // SF_NOUNLINK
    flag!(libc::UF_APPEND, 0; "nouappnd", "nouappend"),
    flag!(libc::UF_IMMUTABLE, 0; "nouchg", "nouchange", "nouimmutable"),
    flag!(0, libc::UF_NODUMP; "nodump"),
    flag!(libc::UF_OPAQUE, 0; "noopaque"),
    flag!(libc::UF_COMPRESSED, 0; "nocompressed"),
    flag!(libc::UF_HIDDEN, 0; "nohidden", "nouhidden"),
];

#[cfg(target_os = "linux")]
const FILEFLAGS: &[Flag] = &[
    flag!(0x20, 0; "nosappnd", "nosappend"), // FS_APPEND_FL 'a'
    flag!(0x10, 0; "noschg", "noschange", "nosimmutable"), // FS_IMMUTABLE_FL 'i'
    flag!(0, 0x40; "nodump"),                // FS_NODUMP_FL 'd'
    flag!(0x2, 0; "noundel"),                // FS_UNRM_FL 'u'
    flag!(0x4, 0; "nocompress"),             // FS_COMPR_FL 'c'
    flag!(0, 0x80; "noatime"),               // FS_NOATIME_FL 'A'
    flag!(0x10000, 0; "nodirsync"),          // FS_DIRSYNC_FL 'D'
    flag!(0x4000, 0; "nojournal-data", "nojournal"), // FS_JOURNAL_DATA_FL 'j'
    flag!(0x1, 0; "nosecdel", "nosecuredeletion"), // FS_SECRM_FL 's'
    flag!(0x8, 0; "nosync"),                 // FS_SYNC_FL 'S'
    flag!(0, 0x8000; "notail"),              // FS_NOTAIL_FL 't'
    flag!(0x20000, 0; "notopdir"),           // FS_TOPDIR_FL 'T'
    flag!(0, 0x800000; "nocow"),             // FS_NOCOW_FL 'C'
    flag!(0x20000000, 0; "noprojinherit"),   // FS_PROJINHERIT_FL 'P'
];

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
const FILEFLAGS: &[Flag] = &[];

/// fflagstostr --
///    Convert file flags to a comma-separated string.  If no flags
///    are set, return the empty string.
fn fflags_to_str(mut bitset: c_ulong, mut bitclear: c_ulong) -> Option<Vec<u8>> {
    let mut bits = bitset | bitclear;
    let mut any = false;
    for flag in FILEFLAGS {
        if bits & (flag.set | flag.clear) != 0 {
            any = true;
            bits &= !(flag.set | flag.clear);
        }
    }
    if !any {
        return None;
    }

    let mut string = Vec::new();
    for flag in FILEFLAGS {
        let name = flag.names.first()?;
        let sp = if bitset & flag.set != 0 || bitclear & flag.clear != 0 {
            name.get(2..)?
        } else if bitset & flag.clear != 0 || bitclear & flag.set != 0 {
            name
        } else {
            continue;
        };
        bitset &= !(flag.set | flag.clear);
        bitclear &= !(flag.set | flag.clear);
        if !string.is_empty() {
            string.push(b',');
        }
        string.extend_from_slice(sp.as_bytes());
    }
    Some(string)
}

/// strtofflags --
///    Take string of arguments and return file flags.  This
///    version works a little differently than strtofflags(3).
///    In particular, it always tests every token, skipping any
///    unrecognized tokens.  It returns the location of the first
///    unrecognized token, or None if every token was recognized.
///    This version is also const-correct and does not modify the
///    provided string.
fn str_to_fflags(s: &[u8]) -> (c_ulong, c_ulong, Option<usize>) {
    let is_sep = |c: &u8| matches!(c, b'\t' | b' ' | b',');
    let (mut set, mut clear) = (0, 0);
    let mut failed = None;
    // Find start of first token.
    let mut start = s.iter().take_while(|c| is_sep(c)).count();
    while start < s.len() {
        // Locate end of token.
        let length = s.iter().skip(start).take_while(|c| !is_sep(c)).count();
        let token = s.get(start..start + length).unwrap_or_default();
        let found = FILEFLAGS.iter().find_map(|flag| {
            flag.names.iter().find_map(|name| {
                if token == name.as_bytes() {
                    // Matched "noXXXX", so reverse the sense.
                    Some((flag.clear, flag.set))
                } else if token == name.as_bytes().get(2..)? {
                    // Matched "XXXX", so don't reverse.
                    Some((flag.set, flag.clear))
                } else {
                    None
                }
            })
        });
        match found {
            Some((s, c)) => {
                set |= s;
                clear |= c;
            }
            // Ignore unknown flag names.
            None => {
                failed.get_or_insert(start);
            }
        }

        // Find start of next token.
        start += length;
        start += s.iter().skip(start).take_while(|c| is_sep(c)).count();
    }
    (set, clear, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nanoseconds_are_normalised() {
        let mut e = Entry::new(None);
        e.set_atime(1, -1);
        e.set_mtime(5, 2_500_000_000);
        assert_eq!((e.atime(), e.atime_nsec()), (0, 999_999_999));
        assert_eq!((e.mtime(), e.mtime_nsec()), (7, 500_000_000));
        assert_eq!(e.atime_is_set(), 4);
        e.unset_atime();
        assert_eq!((e.atime(), e.atime_nsec(), e.atime_is_set()), (0, 0, 0));
    }

    #[test]
    fn links_share_one_target() {
        let mut e = Entry::new(None);
        e.set_symlink(b"target");
        assert_eq!(e.symlink().map(CStr::to_bytes), Some(&b"target"[..]));
        assert!(e.hardlink().is_none());
        // Unsetting a hardlink leaves a symlink alone.
        assert!(!e.unset_hardlink());
        assert!(e.symlink().is_some());
        e.set_hardlink(b"other");
        assert!(e.symlink().is_none());
        assert_eq!(e.hardlink().map(CStr::to_bytes), Some(&b"other"[..]));
        assert!(!e.unset_symlink());
    }

    #[test]
    fn mode_and_perm_share_the_acl_mode() {
        let mut e = Entry::new(None);
        e.set_mode(AE_IFDIR | 0o755);
        e.set_perm(0o700);
        assert_eq!(
            (e.filetype(), e.perm(), e.mode()),
            (AE_IFDIR, 0o700, AE_IFDIR | 0o700)
        );
        e.set_filetype(u32::from(AE_IFREG));
        assert_eq!(e.strmode().to_bytes(), b"-rwx------ ");
    }

    #[test]
    fn stat_is_refilled_in_place() {
        let mut e = Entry::new(None);
        e.set_size(10);
        let p = std::ptr::from_ref(e.stat());
        assert_eq!(e.stat().st_size, 10);
        e.set_size(20);
        assert_eq!(std::ptr::from_ref(e.stat()), p);
        assert_eq!(e.stat().st_size, 20);
    }

    #[test]
    fn clone_copies_fields_and_shares_the_cache() {
        let cache = Cache::default();
        let mut e = Entry::new(Some(cache.clone()));
        e.set_pathname(b"file");
        e.set_size(100);
        e.xattr_add(c"a", b"1");
        e.xattr_add(c"b", b"2");
        e.sparse_add(0, 10);
        e.sparse_add(10, 10);
        e.sparse_add(50, 10);
        let mut c = e.clone_entry();
        assert!(c.cache.as_ref().is_some_and(|x| Arc::ptr_eq(x, &cache)));
        assert_eq!(c.pathname().map(CStr::to_bytes), Some(&b"file"[..]));
        // Upstream prepends each attribute to the copy, which reverses them.
        assert_eq!(c.xattr_reset(), 2);
        let names: Vec<_> = (0..2)
            .filter_map(|_| c.xattr_next().1.map(|x| x.0.to_owned()))
            .collect();
        assert_eq!(names, [c"a".to_owned(), c"b".to_owned()]);
        assert_eq!(e.xattr_reset(), 2);
        assert_eq!(e.xattr_next().1.map(|x| x.0), Some(c"b"));
        // Adjacent blocks merge.
        assert_eq!(c.sparse_reset(), 2);
        assert_eq!(c.sparse_next(), (ARCHIVE_OK, 0, 20));
        e.clear();
        assert!(e.cache.is_none() && e.pathname().is_none());
    }

    #[test]
    fn fflags_text_round_trips_known_flags() {
        let mut e = Entry::new(None);
        assert_eq!(e.copy_fflags_text(b"nodump bogus"), Some(7));
        let (set, clear) = e.fflags();
        assert_ne!(set, 0);
        assert_eq!(clear, 0);
        assert_eq!(
            e.fflags_text().map(CStr::to_bytes),
            Some(&b"nodump bogus"[..])
        );
        e.set_fflags(set, clear);
        assert_eq!(e.fflags_text().map(CStr::to_bytes), Some(&b"nodump"[..]));
        let wide: Vec<wchar_t> = "nodump".chars().map(|c| c as wchar_t).collect();
        assert_eq!(e.copy_fflags_text_w(&wide), None);
        assert_eq!(e.fflags(), (set, clear));
    }

    #[test]
    fn is_set_reports_bits_and_encryption_is_masked() {
        let mut e = Entry::new(None);
        e.set_size(1);
        e.set_ctime(1, 0);
        e.set_uid(1);
        assert_eq!(
            (e.size_is_set(), e.ctime_is_set(), e.uid_is_set()),
            (64, 8, 2048)
        );
        e.set_is_metadata_encrypted(true);
        assert_eq!((e.is_encrypted(), e.is_data_encrypted()), (2, false));
        e.set_is_data_encrypted(true);
        assert_eq!(e.is_encrypted(), 3);
    }

    #[test]
    fn digests_have_fixed_sizes() {
        let mut e = Entry::new(None);
        assert_eq!(e.set_digest(1, &[7; 16]), ARCHIVE_OK);
        assert_eq!(e.set_digest(3, &[7; 20]), ARCHIVE_OK);
        assert_eq!(e.mset_digest, 0b101);
        assert_eq!(e.digest(1), Some(&[7; 16][..]));
        assert_eq!(e.digest(4).map(<[u8]>::len), Some(32));
        assert_eq!(e.set_digest(7, &[0; 64]), ARCHIVE_WARN);
        assert_eq!(e.digest(0), None);
        assert_eq!(e.digest(c_int::MIN), None);
    }
}
