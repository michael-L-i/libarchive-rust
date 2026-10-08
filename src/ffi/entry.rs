//! The exported functions of archive_entry.c and its satellites.
//!
//! A `struct archive_entry *` is a leaked `Box<Entry>`. Each function
//! derives a short-lived `&mut Entry` from the pointer after a NULL check
//! (upstream dereferences a NULL entry; we return the fallback), and runs
//! under `guard`. A returned `const char *` points into storage owned by the
//! entry and stays valid until that field changes or the entry is freed.

use super::archive::{bytes, cptr};
use super::{ARCHIVE_FATAL, Archive, ArchiveAcl, ArchiveEntry, guard};
use crate::archive::{ARCHIVE_WARN, Handle};
use crate::entry::{Dev, Entry, Mode, digest_len};
use libc::{mode_t, wchar_t};
use std::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};

/// A zeroed `struct stat`, which is a plain C struct.
pub(crate) fn zeroed_stat() -> libc::stat {
    // SAFETY: every field of `struct stat` is an integer, for which all
    // zeroes is a valid value.
    unsafe { std::mem::zeroed() }
}

fn with_entry<T: Copy>(e: *mut ArchiveEntry, fallback: T, f: impl FnOnce(&mut Entry) -> T) -> T {
    guard(fallback, || {
        // SAFETY: `e` is NULL or an entry leaked by `archive_entry_new` or
        // `archive_entry_clone`, which the caller does not use concurrently.
        unsafe { e.cast::<Entry>().as_mut() }.map_or(fallback, f)
    })
}

/// Copies input before a setter can overwrite an entry-owned buffer.
fn cstr(p: *const c_char) -> Option<Vec<u8>> {
    // SAFETY: the caller passes NULL or a NUL-terminated string.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

/// The wide string at `p`, without its NUL, if `p` is not NULL.
fn wstr(p: *const wchar_t) -> Option<Vec<wchar_t>> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller passes a NUL-terminated wide string.
    let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
    // SAFETY: the `len` characters before the terminator are valid.
    Some(unsafe { std::slice::from_raw_parts(p, len) }.to_vec())
}

fn wptr(s: Option<&[wchar_t]>) -> *const wchar_t {
    s.map_or(std::ptr::null(), <[wchar_t]>::as_ptr)
}

/// Stores `v` through an out parameter, if the caller gave one.
pub(super) fn put<T>(p: *mut T, v: T) {
    if !p.is_null() {
        // SAFETY: the caller passes NULL or a pointer to writable storage.
        unsafe { p.write(v) };
    }
}

/// A copy of `v` and a trailing `nul` in memory from `malloc`, which the
/// caller frees.
fn malloc_copy<T: Copy>(v: &[T], nul: T) -> *mut T {
    // SAFETY: the allocation has room for the `v.len() + 1` elements that
    // are written to it.
    unsafe {
        let p = libc::malloc((v.len() + 1) * size_of::<T>()).cast::<T>();
        if !p.is_null() {
            std::ptr::copy_nonoverlapping(v.as_ptr(), p, v.len());
            p.add(v.len()).write(nul);
        }
        p
    }
}

/// Calls `$set` with the string at `$p`, or `$clear` for NULL. An update
/// returns 1 or 0 for success or failure; the form with a result says what
/// clearing returns.
macro_rules! or_clear {
    ($e:ident, $p:expr, $get:ident, $set:ident, $clear:ident) => {
        match $get($p) {
            Some(v) => {
                $e.$set(&v);
            }
            None => {
                $e.$clear();
            }
        }
    };
    ($e:ident, $p:expr, $get:ident, $update:ident, $clear:ident, $ok:expr) => {
        match $get($p) {
            Some(v) => c_int::from($e.$update(&v)),
            None => {
                $e.$clear();
                $ok
            }
        }
    };
}

/// Defines exported functions that run a body on the entry. A function with
/// a result names its type and the value for a NULL entry.
macro_rules! entry_fns {
    (@fallback $fb:expr) => { $fb };
    (@fallback) => { () };
    ($($name:ident($($arg:ident: $ty:ty),*) $(-> $ret:ty = $fb:expr)? => |$e:ident| $body:expr;)*) => {$(
        #[unsafe(no_mangle)]
        pub extern "C" fn $name(entry: *mut ArchiveEntry $(, $arg: $ty)*) $(-> $ret)? {
            with_entry(entry, entry_fns!(@fallback $($fb)?), |$e| $body)
        }
    )*};
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_entry_new() -> *mut ArchiveEntry {
    guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(Entry::new(None))).cast()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_entry_new2(a: *mut Archive) -> *mut ArchiveEntry {
    guard(std::ptr::null_mut(), || {
        // SAFETY: `a` is NULL or a handle leaked by an `archive_*_new`
        // function, and it is only ever borrowed shared.
        let cache = unsafe { a.cast::<Handle>().as_ref() }.map(|h| h.base.conv.clone());
        Box::into_raw(Box::new(Entry::new(cache))).cast()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_entry_clear(entry: *mut ArchiveEntry) -> *mut ArchiveEntry {
    with_entry(entry, std::ptr::null_mut(), |e| {
        e.clear();
        entry
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_entry_clone(entry: *mut ArchiveEntry) -> *mut ArchiveEntry {
    with_entry(entry, std::ptr::null_mut(), |e| {
        Box::into_raw(Box::new(e.clone_entry())).cast()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_entry_free(entry: *mut ArchiveEntry) {
    if !entry.is_null() {
        // SAFETY: `entry` is a live entry and the caller gives up ownership.
        guard((), || drop(unsafe { Box::from_raw(entry.cast::<Entry>()) }));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_entry_copy_stat(entry: *mut ArchiveEntry, st: *const libc::stat) {
    guard((), || {
        if entry.is_null() {
            return;
        }
        // SAFETY: the caller passes NULL or a readable stat, possibly owned by entry.
        let st = unsafe { st.as_ref() }.copied();
        if let Some(st) = st {
            with_entry(entry, (), |e| e.copy_stat(&st));
        }
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_entry_set_digest(
    entry: *mut ArchiveEntry,
    ty: c_int,
    digest: *const u8,
) -> c_int {
    guard(ARCHIVE_WARN, || {
        if entry.is_null() {
            return ARCHIVE_WARN;
        }
        let Some(input) = digest_len(ty).and_then(|len| bytes(digest.cast(), len)) else {
            return ARCHIVE_WARN;
        };
        // Snapshot before borrowing the entry: input may point into its digest array.
        let mut copy = [0; 64];
        copy[..input.len()].copy_from_slice(input);
        with_entry(entry, ARCHIVE_WARN, |e| e.set_digest(ty, &copy))
    })
}

entry_fns! {
    // Functions for reading fields from an archive_entry.
    archive_entry_atime() -> libc::time_t = 0 => |e| e.atime();
    archive_entry_atime_nsec() -> c_long = 0 => |e| e.atime_nsec();
    archive_entry_atime_is_set() -> c_int = 0 => |e| e.atime_is_set();
    archive_entry_birthtime() -> libc::time_t = 0 => |e| e.birthtime();
    archive_entry_birthtime_nsec() -> c_long = 0 => |e| e.birthtime_nsec();
    archive_entry_birthtime_is_set() -> c_int = 0 => |e| e.birthtime_is_set();
    archive_entry_ctime() -> libc::time_t = 0 => |e| e.ctime();
    archive_entry_ctime_nsec() -> c_long = 0 => |e| e.ctime_nsec();
    archive_entry_ctime_is_set() -> c_int = 0 => |e| e.ctime_is_set();
    archive_entry_dev() -> Dev = 0 => |e| e.dev();
    archive_entry_dev_is_set() -> c_int = 0 => |e| e.dev_is_set();
    archive_entry_devmajor() -> Dev = 0 => |e| e.devmajor();
    archive_entry_devminor() -> Dev = 0 => |e| e.devminor();
    archive_entry_filetype() -> Mode = 0 => |e| e.filetype();
    archive_entry_filetype_is_set() -> c_int = 0 => |e| e.filetype_is_set();
    archive_entry_fflags(set: *mut c_ulong, clear: *mut c_ulong) => |e| {
        let (s, c) = e.fflags();
        put(set, s);
        put(clear, c);
    };
    archive_entry_fflags_text() -> *const c_char = std::ptr::null() => |e| cptr(e.fflags_text());
    archive_entry_gid() -> i64 = 0 => |e| e.gid();
    archive_entry_gid_is_set() -> c_int = 0 => |e| e.gid_is_set();
    archive_entry_gname() -> *const c_char = std::ptr::null() => |e| cptr(e.gname());
    archive_entry_gname_utf8() -> *const c_char = std::ptr::null() => |e| cptr(e.gname_utf8());
    archive_entry_gname_w() -> *const wchar_t = std::ptr::null() => |e| wptr(e.gname_w());
    archive_entry_set_link_to_hardlink() => |e| e.set_link_to_hardlink();
    archive_entry_hardlink() -> *const c_char = std::ptr::null() => |e| cptr(e.hardlink());
    archive_entry_hardlink_utf8() -> *const c_char = std::ptr::null() => |e| cptr(e.hardlink_utf8());
    archive_entry_hardlink_w() -> *const wchar_t = std::ptr::null() => |e| wptr(e.hardlink_w());
    archive_entry_hardlink_is_set() -> c_int = 0 => |e| e.hardlink_is_set();
    archive_entry_ino() -> i64 = 0 => |e| e.ino();
    archive_entry_ino64() -> i64 = 0 => |e| e.ino();
    archive_entry_ino_is_set() -> c_int = 0 => |e| e.ino_is_set();
    archive_entry_mode() -> Mode = 0 => |e| e.mode();
    archive_entry_mtime() -> libc::time_t = 0 => |e| e.mtime();
    archive_entry_mtime_nsec() -> c_long = 0 => |e| e.mtime_nsec();
    archive_entry_mtime_is_set() -> c_int = 0 => |e| e.mtime_is_set();
    archive_entry_nlink() -> c_uint = 0 => |e| e.nlink();
    archive_entry_pathname() -> *const c_char = std::ptr::null() => |e| cptr(e.pathname());
    archive_entry_pathname_utf8() -> *const c_char = std::ptr::null() => |e| cptr(e.pathname_utf8());
    archive_entry_pathname_w() -> *const wchar_t = std::ptr::null() => |e| wptr(e.pathname_w());
    archive_entry_perm() -> Mode = 0 => |e| e.perm();
    archive_entry_perm_is_set() -> c_int = 0 => |e| e.perm_is_set();
    archive_entry_rdev_is_set() -> c_int = 0 => |e| e.rdev_is_set();
    archive_entry_rdev() -> Dev = 0 => |e| e.rdev();
    archive_entry_rdevmajor() -> Dev = 0 => |e| e.rdevmajor();
    archive_entry_rdevminor() -> Dev = 0 => |e| e.rdevminor();
    archive_entry_size() -> i64 = 0 => |e| e.size();
    archive_entry_size_is_set() -> c_int = 0 => |e| e.size_is_set();
    archive_entry_sourcepath() -> *const c_char = std::ptr::null() => |e| cptr(e.sourcepath());
    archive_entry_sourcepath_w() -> *const wchar_t = std::ptr::null() => |e| wptr(e.sourcepath_w());
    archive_entry_strmode() -> *const c_char = std::ptr::null() => |e| e.strmode().as_ptr();
    archive_entry_set_link_to_symlink() => |e| e.set_link_to_symlink();
    archive_entry_symlink() -> *const c_char = std::ptr::null() => |e| cptr(e.symlink());
    archive_entry_symlink_utf8() -> *const c_char = std::ptr::null() => |e| cptr(e.symlink_utf8());
    archive_entry_symlink_type() -> c_int = 0 => |e| e.symlink_type();
    archive_entry_symlink_w() -> *const wchar_t = std::ptr::null() => |e| wptr(e.symlink_w());
    archive_entry_uid() -> i64 = 0 => |e| e.uid();
    archive_entry_uid_is_set() -> c_int = 0 => |e| e.uid_is_set();
    archive_entry_uname() -> *const c_char = std::ptr::null() => |e| cptr(e.uname());
    archive_entry_uname_utf8() -> *const c_char = std::ptr::null() => |e| cptr(e.uname_utf8());
    archive_entry_uname_w() -> *const wchar_t = std::ptr::null() => |e| wptr(e.uname_w());
    archive_entry_is_data_encrypted() -> c_int = 0 => |e| c_int::from(e.is_data_encrypted());
    archive_entry_is_metadata_encrypted() -> c_int = 0
        => |e| c_int::from(e.is_metadata_encrypted());
    archive_entry_is_encrypted() -> c_int = 0 => |e| e.is_encrypted();

    // Functions to set archive_entry properties.
    archive_entry_set_atime(t: libc::time_t, ns: c_long) => |e| e.set_atime(t, ns);
    archive_entry_unset_atime() => |e| e.unset_atime();
    archive_entry_set_birthtime(t: libc::time_t, ns: c_long) => |e| e.set_birthtime(t, ns);
    archive_entry_unset_birthtime() => |e| e.unset_birthtime();
    archive_entry_set_ctime(t: libc::time_t, ns: c_long) => |e| e.set_ctime(t, ns);
    archive_entry_unset_ctime() => |e| e.unset_ctime();
    archive_entry_set_mtime(t: libc::time_t, ns: c_long) => |e| e.set_mtime(t, ns);
    archive_entry_unset_mtime() => |e| e.unset_mtime();
    archive_entry_set_dev(d: Dev) => |e| e.set_dev(d);
    archive_entry_set_devmajor(m: Dev) => |e| e.set_devmajor(m);
    archive_entry_set_devminor(m: Dev) => |e| e.set_devminor(m);
    archive_entry_set_filetype(ty: c_uint) => |e| e.set_filetype(ty);
    archive_entry_set_fflags(set: c_ulong, clear: c_ulong) => |e| e.set_fflags(set, clear);
    archive_entry_set_gid(g: i64) => |e| e.set_gid(g);
    archive_entry_set_ino(ino: i64) => |e| e.set_ino(ino);
    archive_entry_set_ino64(ino: i64) => |e| e.set_ino(ino);
    archive_entry_set_mode(m: mode_t) => |e| e.set_mode(m);
    archive_entry_set_nlink(nlink: c_uint) => |e| e.set_nlink(nlink);
    archive_entry_set_perm(p: mode_t) => |e| e.set_perm(p);
    archive_entry_set_rdev(m: Dev) => |e| e.set_rdev(m);
    archive_entry_set_rdevmajor(m: Dev) => |e| e.set_rdevmajor(m);
    archive_entry_set_rdevminor(m: Dev) => |e| e.set_rdevminor(m);
    archive_entry_set_size(s: i64) => |e| e.set_size(s);
    archive_entry_unset_size() => |e| e.unset_size();
    archive_entry_set_symlink_type(ty: c_int) => |e| e.set_symlink_type(ty);
    archive_entry_set_uid(u: i64) => |e| e.set_uid(u);
    archive_entry_set_is_data_encrypted(is_encrypted: c_char)
        => |e| e.set_is_data_encrypted(is_encrypted != 0);
    archive_entry_set_is_metadata_encrypted(is_encrypted: c_char)
        => |e| e.set_is_metadata_encrypted(is_encrypted != 0);

    // The text fields. `copy` and `set` are the same operation. C's NULL
    // unsets the field.
    archive_entry_set_gname(v: *const c_char) => |e| or_clear!(e, v, cstr, set_gname, clear_gname);
    archive_entry_copy_gname(v: *const c_char) => |e| or_clear!(e, v, cstr, set_gname, clear_gname);
    archive_entry_set_gname_utf8(v: *const c_char)
        => |e| or_clear!(e, v, cstr, set_gname_utf8, clear_gname);
    archive_entry_copy_gname_w(v: *const wchar_t)
        => |e| or_clear!(e, v, wstr, copy_gname_w, clear_gname);
    archive_entry_update_gname_utf8(v: *const c_char) -> c_int = 0
        => |e| or_clear!(e, v, cstr, update_gname_utf8, clear_gname, 1);
    archive_entry_set_uname(v: *const c_char) => |e| or_clear!(e, v, cstr, set_uname, clear_uname);
    archive_entry_copy_uname(v: *const c_char) => |e| or_clear!(e, v, cstr, set_uname, clear_uname);
    archive_entry_set_uname_utf8(v: *const c_char)
        => |e| or_clear!(e, v, cstr, set_uname_utf8, clear_uname);
    archive_entry_copy_uname_w(v: *const wchar_t)
        => |e| or_clear!(e, v, wstr, copy_uname_w, clear_uname);
    archive_entry_update_uname_utf8(v: *const c_char) -> c_int = 0
        => |e| or_clear!(e, v, cstr, update_uname_utf8, clear_uname, 1);
    archive_entry_set_pathname(v: *const c_char) => |e| or_clear!(e, v, cstr, set_pathname, clear_pathname);
    archive_entry_copy_pathname(v: *const c_char) => |e| or_clear!(e, v, cstr, set_pathname, clear_pathname);
    archive_entry_set_pathname_utf8(v: *const c_char)
        => |e| or_clear!(e, v, cstr, set_pathname_utf8, clear_pathname);
    archive_entry_copy_pathname_w(v: *const wchar_t)
        => |e| or_clear!(e, v, wstr, copy_pathname_w, clear_pathname);
    archive_entry_update_pathname_utf8(v: *const c_char) -> c_int = 0
        => |e| or_clear!(e, v, cstr, update_pathname_utf8, clear_pathname, 1);
    archive_entry_copy_sourcepath(v: *const c_char)
        => |e| or_clear!(e, v, cstr, set_sourcepath, clear_sourcepath);
    archive_entry_copy_sourcepath_w(v: *const wchar_t)
        => |e| or_clear!(e, v, wstr, copy_sourcepath_w, clear_sourcepath);

    // The link target.
    archive_entry_set_hardlink(v: *const c_char) => |e| {
        or_clear!(e, v, cstr, set_hardlink, unset_hardlink);
    };
    archive_entry_copy_hardlink(v: *const c_char) => |e| {
        or_clear!(e, v, cstr, copy_hardlink, unset_hardlink);
    };
    archive_entry_set_hardlink_utf8(v: *const c_char) => |e| {
        or_clear!(e, v, cstr, set_hardlink_utf8, unset_hardlink);
    };
    archive_entry_copy_hardlink_w(v: *const wchar_t) => |e| {
        or_clear!(e, v, wstr, copy_hardlink_w, unset_hardlink);
    };
    archive_entry_set_symlink(v: *const c_char) => |e| {
        or_clear!(e, v, cstr, set_symlink, unset_symlink);
    };
    archive_entry_copy_symlink(v: *const c_char) => |e| {
        or_clear!(e, v, cstr, set_symlink, unset_symlink);
    };
    archive_entry_set_symlink_utf8(v: *const c_char) => |e| {
        or_clear!(e, v, cstr, set_symlink_utf8, unset_symlink);
    };
    archive_entry_copy_symlink_w(v: *const wchar_t) => |e| {
        or_clear!(e, v, wstr, copy_symlink_w, unset_symlink);
    };
    archive_entry_set_link(v: *const c_char) => |e| or_clear!(e, v, cstr, set_link, unset_link);
    archive_entry_copy_link(v: *const c_char) => |e| or_clear!(e, v, cstr, set_link, unset_link);
    archive_entry_set_link_utf8(v: *const c_char) => |e| or_clear!(e, v, cstr, set_link_utf8, unset_link);
    archive_entry_copy_link_w(v: *const wchar_t) => |e| or_clear!(e, v, wstr, copy_link_w, unset_link);
    archive_entry_update_hardlink_utf8(v: *const c_char) -> c_int = 0
        => |e| match cstr(v) {
            Some(v) => c_int::from(e.update_hardlink_utf8(&v)),
            None => c_int::from(e.unset_hardlink()),
        };
    archive_entry_update_symlink_utf8(v: *const c_char) -> c_int = 0
        => |e| match cstr(v) {
            Some(v) => c_int::from(e.update_symlink_utf8(&v)),
            None => c_int::from(e.unset_symlink()),
        };
    archive_entry_update_link_utf8(v: *const c_char) -> c_int = 0
        => |e| or_clear!(e, v, cstr, update_link_utf8, unset_link, 1);

    archive_entry_copy_fflags_text(flags: *const c_char) -> *const c_char = std::ptr::null()
        => |e| cstr(flags).map_or(std::ptr::null(), |f| {
            e.copy_fflags_text(&f).map_or(std::ptr::null(), |i| flags.wrapping_add(i))
        });
    archive_entry_copy_fflags_text_len(flags: *const c_char, len: usize) -> *const c_char
        = std::ptr::null()
        => |e| bytes(flags.cast(), len).map(<[u8]>::to_vec).map_or(std::ptr::null(), |f| {
            e.copy_fflags_text(&f).map_or(std::ptr::null(), |i| flags.wrapping_add(i))
        });
    archive_entry_copy_fflags_text_w(flags: *const wchar_t) -> *const wchar_t = std::ptr::null()
        => |e| wstr(flags).map_or(std::ptr::null(), |f| {
            e.copy_fflags_text_w(&f).map_or(std::ptr::null(), |i| flags.wrapping_add(i))
        });

    archive_entry_stat() -> *const libc::stat = std::ptr::null() => |e| std::ptr::from_ref(e.stat());


    archive_entry_mac_metadata(size: *mut usize) -> *const c_void = std::ptr::null() => |e| {
        let m = e.mac_metadata();
        put(size, m.map_or(0, <[u8]>::len));
        m.map_or(std::ptr::null(), |m| m.as_ptr().cast())
    };
    archive_entry_copy_mac_metadata(p: *const c_void, s: usize) => |e| {
        e.copy_mac_metadata(if p.is_null() { &[] } else { bytes(p, s).unwrap_or_default() });
    };

    archive_entry_digest(ty: c_int) -> *const u8 = std::ptr::null()
        => |e| e.digest(ty).map_or(std::ptr::null(), <[u8]>::as_ptr);


    // ACL management.
    archive_entry_acl() -> *mut ArchiveAcl = std::ptr::null_mut()
        => |e| std::ptr::from_mut(&mut e.acl).cast();
    archive_entry_acl_clear() => |e| e.acl.clear();
    archive_entry_acl_add_entry(ty: c_int, permset: c_int, tag: c_int, id: c_int, name: *const c_char)
        -> c_int = ARCHIVE_FATAL
        => |e| e.acl.add_entry(ty, permset, tag, id, cstr(name).as_deref());
    archive_entry_acl_add_entry_w(ty: c_int, permset: c_int, tag: c_int, id: c_int, name: *const wchar_t)
        -> c_int = ARCHIVE_FATAL
        => |e| e.acl.add_entry_w(ty, permset, tag, id, wstr(name).as_deref());
    archive_entry_acl_types() -> c_int = 0 => |e| e.acl.types();
    archive_entry_acl_count(want_type: c_int) -> c_int = 0 => |e| e.acl.count(want_type);
    archive_entry_acl_reset(want_type: c_int) -> c_int = 0 => |e| e.acl.reset(want_type);
    archive_entry_acl_next(
        want_type: c_int,
        ty: *mut c_int,
        permset: *mut c_int,
        tag: *mut c_int,
        id: *mut c_int,
        name: *mut *const c_char
    ) -> c_int = ARCHIVE_FATAL => |e| {
        let (r, item) = e.acl_next(want_type);
        put(id, item.id);
        put(name, cptr(item.name));
        if r != ARCHIVE_WARN {
            put(ty, item.type_);
            put(permset, item.permset);
            put(tag, item.tag);
        }
        r
    };
    archive_entry_acl_to_text_w(len: *mut isize, flags: c_int) -> *mut wchar_t
        = std::ptr::null_mut()
        => |e| e.acl_to_text_w(flags).map_or(std::ptr::null_mut(), |t| {
            put(len, t.len() as isize);
            malloc_copy(&t, 0)
        });
    archive_entry_acl_to_text(len: *mut isize, flags: c_int) -> *mut c_char
        = std::ptr::null_mut()
        => |e| e.acl_to_text(flags).map_or(std::ptr::null_mut(), |t| {
            put(len, t.len() as isize);
            malloc_copy(&t, 0).cast()
        });
    archive_entry_acl_from_text_w(wtext: *const wchar_t, ty: c_int) -> c_int = ARCHIVE_FATAL
        => |e| e.acl_from_text_w(wstr(wtext).as_deref().unwrap_or_default(), ty);
    archive_entry_acl_from_text(text: *const c_char, ty: c_int) -> c_int = ARCHIVE_FATAL
        => |e| e.acl_from_text(cstr(text).as_deref().unwrap_or_default(), ty);
    archive_entry_acl_text_w(flags: c_int) -> *const wchar_t = std::ptr::null()
        => |e| wptr(e.acl_text_w(flags));
    archive_entry_acl_text(flags: c_int) -> *const c_char = std::ptr::null()
        => |e| cptr(e.acl_text(flags));

    // Extended attributes.
    archive_entry_xattr_clear() => |e| e.xattr_clear();
    archive_entry_xattr_add_entry(name: *const c_char, value: *const c_void, size: usize) => |e| {
        if !name.is_null()
            && let Some(value) = bytes(value, size)
        {
            // SAFETY: `name` is not NULL and the caller passes a NUL-terminated string.
            e.xattr_add(unsafe { CStr::from_ptr(name) }, value);
        }
    };
    archive_entry_xattr_count() -> c_int = 0 => |e| e.xattr_count();
    archive_entry_xattr_reset() -> c_int = 0 => |e| e.xattr_reset();
    archive_entry_xattr_next(name: *mut *const c_char, value: *mut *const c_void, size: *mut usize)
        -> c_int = ARCHIVE_FATAL => |e| {
        let (r, xattr) = e.xattr_next();
        put(name, cptr(xattr.map(|x| x.0)));
        put(value, xattr.map_or(std::ptr::null(), |x| x.1.as_ptr().cast()));
        put(size, xattr.map_or(0, |x| x.1.len()));
        r
    };

    // Sparse maps.
    archive_entry_sparse_clear() => |e| e.sparse_clear();
    archive_entry_sparse_add_entry(offset: i64, length: i64) => |e| e.sparse_add(offset, length);
    archive_entry_sparse_count() -> c_int = 0 => |e| e.sparse_count();
    archive_entry_sparse_reset() -> c_int = 0 => |e| e.sparse_reset();
    archive_entry_sparse_next(offset: *mut i64, length: *mut i64) -> c_int = ARCHIVE_FATAL => |e| {
        let (r, o, l) = e.sparse_next();
        put(offset, o);
        put(length, l);
        r
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_setters_accept_entry_owned_input() {
        let e = archive_entry_new();
        let fields = [
            (
                archive_entry_copy_pathname as extern "C" fn(_, _),
                archive_entry_pathname as extern "C" fn(_) -> _,
            ),
            (archive_entry_copy_uname, archive_entry_uname),
            (archive_entry_copy_gname, archive_entry_gname),
            (archive_entry_copy_hardlink, archive_entry_hardlink),
            (archive_entry_copy_symlink, archive_entry_symlink),
            (archive_entry_copy_sourcepath, archive_entry_sourcepath),
        ];
        for (set, get) in fields {
            set(e, c"abcdefghij".as_ptr());
            set(e, get(e));
            assert_eq!(cstr(get(e)).as_deref(), Some(b"abcdefghij".as_slice()));
            set(e, get(e).wrapping_add(2));
            assert_eq!(cstr(get(e)).as_deref(), Some(b"cdefghij".as_slice()));
        }
        archive_entry_free(e);
    }

    #[test]
    fn digests_and_stat_accept_entry_owned_input() {
        let e = archive_entry_new();
        for ty in 1..=6 {
            assert_eq!(archive_entry_set_digest(e, ty, [7; 64].as_ptr()), 0);
            assert_eq!(
                archive_entry_set_digest(e, ty, archive_entry_digest(e, ty)),
                0
            );
            let len = digest_len(ty).unwrap();
            assert_eq!(
                bytes(archive_entry_digest(e, ty).cast(), len),
                Some(&[7; 64][..len])
            );
        }
        archive_entry_set_size(e, 123);
        archive_entry_set_mtime(e, 45, 678);
        archive_entry_set_perm(e, 0o640);
        archive_entry_copy_stat(e, archive_entry_stat(e));
        assert_eq!(archive_entry_size(e), 123);
        assert_eq!(archive_entry_mtime(e), 45);
        assert_eq!(archive_entry_mtime_nsec(e), 678);
        assert_eq!(archive_entry_perm(e), 0o640);
        archive_entry_free(e);
    }

    #[test]
    fn flag_setters_accept_entry_owned_input() {
        let e = archive_entry_new();
        archive_entry_copy_fflags_text(e, c"nodump bogus".as_ptr());
        let p = archive_entry_fflags_text(e);
        assert_eq!(
            archive_entry_copy_fflags_text_len(e, p, 12),
            p.wrapping_add(7)
        );
        assert_eq!(
            cstr(archive_entry_fflags_text(e)).as_deref(),
            Some(b"nodump bogus".as_slice())
        );
        archive_entry_free(e);
    }

    #[test]
    fn wide_and_utf8_setters_accept_entry_owned_input() {
        let e = archive_entry_new();
        let wide: Vec<wchar_t> = "abcdefghij"
            .chars()
            .map(|c| c as wchar_t)
            .chain([0])
            .collect();
        archive_entry_copy_pathname_w(e, wide.as_ptr());
        archive_entry_copy_pathname_w(e, archive_entry_pathname_w(e).wrapping_add(2));
        assert_eq!(
            wstr(archive_entry_pathname_w(e)).as_deref(),
            Some(&wide[2..wide.len() - 1])
        );
        // The getter fills a converted buffer, then the setter copies it back.
        archive_entry_copy_pathname(e, archive_entry_pathname(e));
        assert_eq!(
            cstr(archive_entry_pathname(e)).as_deref(),
            Some(b"cdefghij".as_slice())
        );
        archive_entry_set_pathname_utf8(e, c"abcdefghij".as_ptr());
        archive_entry_set_pathname_utf8(e, archive_entry_pathname_utf8(e).wrapping_add(2));
        assert_eq!(
            cstr(archive_entry_pathname_utf8(e)).as_deref(),
            Some(b"cdefghij".as_slice())
        );
        // Changing representation must copy before clearing the source form.
        archive_entry_copy_pathname(e, archive_entry_pathname_utf8(e));
        assert_eq!(
            cstr(archive_entry_pathname(e)).as_deref(),
            Some(b"cdefghij".as_slice())
        );
        archive_entry_free(e);
    }
}
