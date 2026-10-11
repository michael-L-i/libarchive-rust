//! C ABI for archive_match; callback users borrow the live matcher.
use super::archive::with;
use super::entry::put;
use super::{Archive, ArchiveEntry, guard};
use crate::archive::*;
use crate::entry::Entry;
use crate::matching::Matching;
use crate::string::MString;
use crate::util::Error;
use std::ffi::{CStr, c_char, c_int, c_long};

fn text(p: *const c_char) -> MString {
    let mut text = MString::default();
    // SAFETY: the caller supplies NULL or a NUL-terminated string.
    if !p.is_null() {
        text.copy_mbs(unsafe { CStr::from_ptr(p) }.to_bytes());
    }
    text
}
fn wide(p: *const libc::wchar_t) -> MString {
    let mut text = MString::default();
    if !p.is_null() {
        // SAFETY: the caller supplies a NUL-terminated wide string.
        let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
        // SAFETY: the preceding count found this many readable characters.
        text.copy_wcs(unsafe { std::slice::from_raw_parts(p, len) });
    }
    text
}
fn operation(
    a: *mut Archive,
    name: &str,
    f: impl FnOnce(&Base, &mut Matching) -> Result<c_int, Error>,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.match_operation(name, f))
}
/// An entry argument, as the reference the call uses.
fn entry<'a>(e: *mut ArchiveEntry) -> Option<&'a mut Entry> {
    // SAFETY: the caller passes NULL or a live entry it owns, which nothing
    // else uses during the call.
    unsafe { e.cast::<Entry>().as_mut() }
}
/// A match handle C lends a disk reader (`archive_read_disk_set_matching`).
#[derive(Clone, Copy)]
pub(crate) struct MatchingHandle(*mut Archive);
impl MatchingHandle {
    /// The caller retains the handle until the disk reader no longer uses it.
    pub(crate) fn new(p: *mut Archive) -> Option<Self> {
        with(p, None, |h| {
            (h.base.magic == MATCH_MAGIC).then_some(Self(p))
        })
    }
    pub(crate) fn handle(&self) -> &Handle {
        // SAFETY: `new` checked that this is a live handle, which the C
        // caller keeps alive while the disk reader uses it; handles are only
        // ever borrowed shared.
        unsafe { &*self.0.cast::<Handle>() }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_match_new() -> *mut Archive {
    guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(crate::api::matching::new())).cast()
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_match_free(a: *mut Archive) -> c_int {
    if a.is_null() {
        return ARCHIVE_OK;
    }
    guard(ARCHIVE_FATAL, || {
        // SAFETY: a live match handle is only freed by its owning C caller.
        let h = unsafe { &*a.cast::<Handle>() };
        if h.base
            .check_magic(MATCH_MAGIC, state::ANY | state::FATAL, "archive_match_free")
            != ARCHIVE_OK
        {
            return ARCHIVE_FATAL;
        }
        // SAFETY: this function reclaims the Box leaked by archive_match_new.
        drop(unsafe { Box::from_raw(a.cast::<Handle>()) });
        ARCHIVE_OK
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_match_set_inclusion_recursion(a: *mut Archive, enabled: c_int) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_set_inclusion_recursion(enabled != 0)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_match_path_unmatched_inclusions(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, Handle::match_path_unmatched_inclusions)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_match_path_unmatched_inclusions_next(
    a: *mut Archive,
    p: *mut *const c_char,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_path_unmatched_inclusions_next("archive_match_unmatched_inclusions_next", |s| {
            let s = s.map(|s| s.get_mbs_c(None).ok().flatten().unwrap_or(c""));
            put(p, s.map_or(std::ptr::null(), CStr::as_ptr));
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_match_path_unmatched_inclusions_next_w(
    a: *mut Archive,
    p: *mut *const libc::wchar_t,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_path_unmatched_inclusions_next("archive_match_unmatched_inclusions_next_w", |s| {
            static EMPTY: [libc::wchar_t; 1] = [0];
            let s = s.map(|s| s.get_wcs_z(None).ok().flatten().unwrap_or(&EMPTY));
            put(p, s.map_or(std::ptr::null(), <[libc::wchar_t]>::as_ptr));
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_time(
    a: *mut Archive,
    flag: c_int,
    sec: libc::time_t,
    nsec: c_long,
) -> c_int {
    operation(a, "archive_match_include_time", |_, m| {
        m.include_time(flag, (sec, nsec), (sec, nsec))?;
        Ok(ARCHIVE_OK)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_match_exclude_entry(
    a: *mut Archive,
    flag: c_int,
    e: *mut ArchiveEntry,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.match_exclude_entry(flag, entry(e)))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_parse_date(now: libc::time_t, p: *const c_char) -> libc::time_t {
    guard(-1, || {
        if p.is_null() {
            return -1;
        } // SAFETY: p is a NUL-terminated date string.
        crate::parse_date::parse(now, unsafe { CStr::from_ptr(p) }.to_bytes()).unwrap_or(-1)
            as libc::time_t
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_excluded(a: *mut Archive, e: *mut ArchiveEntry) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.match_excluded(entry(e)))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_path_excluded(a: *mut Archive, e: *mut ArchiveEntry) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.match_path_excluded(entry(e)))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_time_excluded(a: *mut Archive, e: *mut ArchiveEntry) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.match_time_excluded(entry(e)))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_owner_excluded(a: *mut Archive, e: *mut ArchiveEntry) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.match_owner_excluded(entry(e)))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_pattern(a: *mut Archive, p: *const c_char) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_pattern("archive_match_include_pattern", true, text(p))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_pattern_from_file(
    a: *mut Archive,
    p: *const c_char,
    null: c_int,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_pattern_from_file(
            "archive_match_include_pattern_from_file",
            true,
            text(p),
            null != 0,
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_pattern_w(
    a: *mut Archive,
    p: *const libc::wchar_t,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_pattern("archive_match_include_pattern_w", true, wide(p))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_pattern_from_file_w(
    a: *mut Archive,
    p: *const libc::wchar_t,
    null: c_int,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_pattern_from_file(
            "archive_match_include_pattern_from_file_w",
            true,
            wide(p),
            null != 0,
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_exclude_pattern(a: *mut Archive, p: *const c_char) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_pattern("archive_match_exclude_pattern", false, text(p))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_exclude_pattern_from_file(
    a: *mut Archive,
    p: *const c_char,
    null: c_int,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_pattern_from_file(
            "archive_match_exclude_pattern_from_file",
            false,
            text(p),
            null != 0,
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_exclude_pattern_w(
    a: *mut Archive,
    p: *const libc::wchar_t,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_pattern("archive_match_exclude_pattern_w", false, wide(p))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_exclude_pattern_from_file_w(
    a: *mut Archive,
    p: *const libc::wchar_t,
    null: c_int,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_pattern_from_file(
            "archive_match_exclude_pattern_from_file_w",
            false,
            wide(p),
            null != 0,
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_uname(a: *mut Archive, p: *const c_char) -> c_int {
    operation(a, "archive_match_include_uname", |_, m| {
        m.include_owner(true, text(p));
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_gname(a: *mut Archive, p: *const c_char) -> c_int {
    operation(a, "archive_match_include_gname", |_, m| {
        m.include_owner(false, text(p));
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_file_time(
    a: *mut Archive,
    flag: c_int,
    p: *const c_char,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_include_file_time("archive_match_include_file_time", flag, text(p))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_date(
    a: *mut Archive,
    flag: c_int,
    p: *const c_char,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_include_date("archive_match_include_date", flag, text(p))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_uname_w(a: *mut Archive, p: *const libc::wchar_t) -> c_int {
    operation(a, "archive_match_include_uname_w", |_, m| {
        m.include_owner(true, wide(p));
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_gname_w(a: *mut Archive, p: *const libc::wchar_t) -> c_int {
    operation(a, "archive_match_include_gname_w", |_, m| {
        m.include_owner(false, wide(p));
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_file_time_w(
    a: *mut Archive,
    flag: c_int,
    p: *const libc::wchar_t,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_include_file_time("archive_match_include_file_time_w", flag, wide(p))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_date_w(
    a: *mut Archive,
    flag: c_int,
    p: *const libc::wchar_t,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.match_include_date("archive_match_include_date_w", flag, wide(p))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_uid(a: *mut Archive, id: i64) -> c_int {
    operation(a, "archive_match_include_uid", |_, m| {
        m.include_id(true, id);
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_gid(a: *mut Archive, id: i64) -> c_int {
    operation(a, "archive_match_include_gid", |_, m| {
        m.include_id(false, id);
        Ok(ARCHIVE_OK)
    })
}
