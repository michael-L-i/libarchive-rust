/*-
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

// Ported from libarchive/archive_disk_acl_darwin.c.

use crate::acl::*;
use crate::entry::Entry;
use std::ffi::{c_int, c_void};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

unsafe extern "C" {
    fn acl_get_file(path: *const libc::c_char, kind: c_int) -> *mut c_void;
    fn acl_get_link_np(path: *const libc::c_char, kind: c_int) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, next: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_get_qualifier(entry: *mut c_void) -> *mut c_void;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
    fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> c_int;
    fn acl_get_flagset_np(entry: *mut c_void, flags: *mut *mut c_void) -> c_int;
    fn acl_get_flag_np(flags: *mut c_void, flag: u32) -> c_int;
    fn acl_free(acl: *mut c_void) -> c_int;
    fn acl_init(count: c_int) -> *mut c_void;
    fn acl_create_entry(acl: *mut *mut c_void, entry: *mut *mut c_void) -> c_int;
    fn acl_set_tag_type(entry: *mut c_void, tag: c_int) -> c_int;
    fn acl_set_qualifier(entry: *mut c_void, qualifier: *const c_void) -> c_int;
    fn acl_set_permset_mask_np(entry: *mut c_void, mask: u64) -> c_int;
    fn acl_add_flag_np(flags: *mut c_void, flag: u32) -> c_int;
    fn acl_set_fd_np(fd: c_int, acl: *mut c_void, kind: c_int) -> c_int;
    fn mbr_uuid_to_id(uuid: *const u8, id: *mut u32, kind: *mut c_int) -> c_int;
    fn mbr_uid_to_uuid(id: u32, uuid: *mut u8) -> c_int;
    fn mbr_gid_to_uuid(id: u32, uuid: *mut u8) -> c_int;
}
const PERMS: [(c_int, u64); 14] = [
    (READ_DATA, 1 << 1),
    (WRITE_DATA, 1 << 2),
    (EXECUTE, 1 << 3),
    (DELETE, 1 << 4),
    (APPEND_DATA, 1 << 5),
    (DELETE_CHILD, 1 << 6),
    (READ_ATTRIBUTES, 1 << 7),
    (WRITE_ATTRIBUTES, 1 << 8),
    (READ_NAMED_ATTRS, 1 << 9),
    (WRITE_NAMED_ATTRS, 1 << 10),
    (READ_ACL, 1 << 11),
    (WRITE_ACL, 1 << 12),
    (WRITE_OWNER, 1 << 13),
    (SYNCHRONIZE, 1 << 20),
];
const FLAGS: [(c_int, u32); 5] = [
    (0x01000000, 1 << 4),
    (0x02000000, 1 << 5),
    (0x04000000, 1 << 6),
    (0x08000000, 1 << 7),
    (0x10000000, 1 << 8),
];
struct Native(*mut c_void);
impl Drop for Native {
    fn drop(&mut self) {
        // SAFETY: Native owns this allocation from acl_get_file/acl_init.
        unsafe { acl_free(self.0) };
    }
}
fn code(ret: c_int) -> std::io::Result<()> {
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
pub fn read(
    path: &Path,
    entry: &mut Entry,
    user: &mut super::disk::NameLookup,
    group: &mut super::disk::NameLookup,
) -> std::io::Result<()> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: path terminated and live; successful call allocates owned ACL.
    let ptr = unsafe {
        if entry.filetype() == libc::S_IFLNK {
            acl_get_link_np(path.as_ptr(), 0x100)
        } else {
            acl_get_file(path.as_ptr(), 0x100)
        }
    };
    if ptr.is_null() {
        return Ok(());
    }
    let acl = Native(ptr);
    let mut native = std::ptr::null_mut();
    let mut first = true;
    let mut found = false;
    loop {
        // SAFETY: ACL is valid, and native is a writable entry pointer.
        let ret = unsafe { acl_get_entry(acl.0, if first { 0 } else { -1 }, &mut native) };
        first = false;
        if ret != 0 {
            break;
        }
        let mut tag = 0;
        let mut mask = 0;
        // SAFETY: entry belongs to acl, output destinations are valid.
        code(unsafe { acl_get_tag_type(native, &mut tag) })?;
        if ![1, 2].contains(&tag) {
            continue;
        }
        // SAFETY: entry belongs to ACL; qualifier is a new owned UUID buffer.
        let qualifier = unsafe { acl_get_qualifier(native) };
        if qualifier.is_null() {
            continue;
        }
        let qualifier = Native(qualifier);
        let mut id = 0;
        let mut kind = 0;
        // SAFETY: qualifier is a UUID of 16 bytes returned by native ACL API.
        if unsafe { mbr_uuid_to_id(qualifier.0.cast(), &mut id, &mut kind) } != 0
            || ![0, 1].contains(&kind)
        {
            continue;
        }
        // SAFETY: live ACL entry and writable u64 mask.
        code(unsafe { acl_get_permset_mask_np(native, &mut mask) })?;
        let mut perms = PERMS
            .iter()
            .filter(|(_, platform)| mask & platform != 0)
            .fold(0, |p, (archive, _)| p | archive);
        let mut flags = std::ptr::null_mut();
        // SAFETY: entry valid; flagset pointer borrowed from ACL.
        code(unsafe { acl_get_flagset_np(native, &mut flags) })?;
        for (archive, platform) in FLAGS {
            // SAFETY: flagset borrowed from live ACL entry.
            if unsafe { acl_get_flag_np(flags, platform) } > 0 {
                perms |= archive;
            }
        }
        let name = if kind == 0 {
            user.lookup(id.into(), false)
        } else {
            group.lookup(id.into(), true)
        };
        entry.acl.add_entry(
            if tag == 1 { TYPE_ALLOW } else { TYPE_DENY },
            perms,
            if kind == 0 { USER } else { GROUP },
            id as c_int,
            name.map(std::ffi::CStr::to_bytes),
        );
        found = true;
    }
    if found {
        add_trivial(entry);
    }
    Ok(())
}
fn add_trivial(entry: &mut Entry) {
    let public = READ_ATTRIBUTES | READ_NAMED_ATTRS | READ_ACL | SYNCHRONIZE;
    let owner = public | WRITE_ATTRIBUTES | WRITE_NAMED_ATTRS | WRITE_ACL | WRITE_OWNER;
    let mut perms = [0, 0, 0, owner, public, public];
    let mode = entry.mode();
    for (ownerbit, groupbit, otherbit, permission) in [
        (0o400, 0o40, 4, READ_DATA),
        (0o200, 0o20, 2, WRITE_DATA | APPEND_DATA),
        (0o100, 0o10, 1, EXECUTE),
    ] {
        if mode & otherbit != 0 {
            perms[5] |= permission;
        }
        if mode & groupbit != 0 {
            perms[4] |= permission;
        } else if mode & otherbit != 0 {
            perms[2] |= permission;
        }
        if mode & ownerbit != 0 {
            perms[3] |= permission;
            if mode & groupbit == 0 && mode & otherbit != 0 {
                perms[0] |= permission;
            }
        } else if mode & (groupbit | otherbit) != 0 {
            perms[1] |= permission;
        }
    }
    for (i, (ty, tag)) in [
        (TYPE_ALLOW, USER_OBJ),
        (TYPE_DENY, USER_OBJ),
        (TYPE_DENY, GROUP_OBJ),
        (TYPE_ALLOW, USER_OBJ),
        (TYPE_ALLOW, GROUP_OBJ),
        (TYPE_ALLOW, EVERYONE),
    ]
    .into_iter()
    .enumerate()
    {
        if perms[i] != 0 {
            entry.acl.add_entry(ty, perms[i], tag, -1, None);
        }
    }
}
pub fn write(
    file: &std::fs::File,
    entry: &Entry,
    user: &mut super::disk::IdLookup,
    group: &mut super::disk::IdLookup,
) -> std::io::Result<()> {
    let mut entry = entry.clone_entry();
    let count = entry.acl.reset(TYPE_NFS4);
    if count == 0 {
        return Ok(());
    }
    // SAFETY: creates a new owned ACL container.
    let ptr = unsafe { acl_init(count) };
    if ptr.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let mut acl = Native(ptr);
    loop {
        let (ret, item) = entry.acl_next(TYPE_NFS4);
        if ret != 0 {
            break;
        }
        if ![USER, GROUP].contains(&item.tag) || ![TYPE_ALLOW, TYPE_DENY].contains(&item.type_) {
            continue;
        }
        let mut uuid = [0; 16];
        let id = if item.tag == USER {
            user.lookup(item.name, item.id.into(), false)
        } else {
            group.lookup(item.name, item.id.into(), true)
        };
        // SAFETY: writable fixed UUID buffer and valid scalar id.
        if unsafe {
            if item.tag == USER {
                mbr_uid_to_uuid(id as _, uuid.as_mut_ptr())
            } else {
                mbr_gid_to_uuid(id as _, uuid.as_mut_ptr())
            }
        } != 0
        {
            continue;
        }
        let mut native = std::ptr::null_mut();
        // SAFETY: ACL pointer mutable for native reallocation and writable entry out pointer.
        code(unsafe { acl_create_entry(&mut acl.0, &mut native) })?;
        // SAFETY: newly created entry and fixed UUID remain live.
        code(unsafe { acl_set_tag_type(native, if item.type_ == TYPE_ALLOW { 1 } else { 2 }) })?;
        // SAFETY: UUID is exactly the 16-byte qualifier native ACLs require.
        code(unsafe { acl_set_qualifier(native, uuid.as_ptr().cast()) })?;
        let mask = PERMS
            .iter()
            .filter(|(archive, _)| item.permset & archive != 0)
            .fold(0, |m, (_, platform)| m | platform);
        // SAFETY: ACL entry valid, mask passed by value.
        code(unsafe { acl_set_permset_mask_np(native, mask) })?;
        let mut flags = std::ptr::null_mut();
        // SAFETY: valid entry and output pointer for flagset.
        code(unsafe { acl_get_flagset_np(native, &mut flags) })?;
        for (archive, platform) in FLAGS {
            if item.permset & archive != 0 {
                // SAFETY: borrowed flagset of live entry.
                code(unsafe { acl_add_flag_np(flags, platform) })?;
            }
        }
    }
    // SAFETY: live file descriptor and owned valid ACL pointer.
    code(unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0, 0x100) })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extended_acl_restores_through_open_descriptor_at_mode_zero() {
        use crate::archive::{Base, WRITE_DISK_MAGIC};
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("libarchive-acl-{}-{unique}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let path = root.join("file");
        // SAFETY: getuid only returns process credentials and takes no pointers.
        let uid = unsafe { libc::getuid() };
        let mut entry = Entry::new(None);
        entry.set_pathname(path.as_os_str().as_bytes());
        entry.set_mode(libc::S_IFREG);
        entry.set_size(0);
        entry.set_uid(uid.into());
        entry
            .acl
            .add_entry(TYPE_ALLOW, READ_DATA | WRITE_DATA, USER, uid as c_int, None);
        let base = Base::new(WRITE_DISK_MAGIC);
        let mut disk = crate::write_disk::WriteDisk::default();
        disk.options = 0x20 | 0x40 | 0x2;
        assert_eq!(disk.header(&base, &entry), 0);
        assert_eq!(disk.finish_entry(&base), 0);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0
        );
        let mut restored = Entry::new(None);
        restored.set_mode(libc::S_IFREG | 0o600);
        let mut user = super::super::disk::NameLookup::default();
        let mut group = super::super::disk::NameLookup::default();
        read(&path, &mut restored, &mut user, &mut group).unwrap();
        assert!(restored.acl.reset(TYPE_NFS4) > 0);
        let (code, item) = restored.acl_next(TYPE_NFS4);
        assert_eq!(code, 0);
        assert_eq!(
            (item.tag, item.id, item.type_, item.permset),
            (USER, uid as c_int, TYPE_ALLOW, READ_DATA | WRITE_DATA)
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
