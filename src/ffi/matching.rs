//! C ABI for archive_match; callback users borrow the live matcher.
use super::archive::with;
use super::entry::put;
use super::{Archive, ArchiveEntry, guard};
use crate::archive::*;
use crate::entry::Entry;
use crate::matching::{Matching, invalid};
use crate::string::MString;
use crate::util::Error;
use std::cell::RefCell;
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
    with(a, ARCHIVE_FATAL, |h| {
        if h.base.check_magic(MATCH_MAGIC, state::NEW, name) == ARCHIVE_FATAL {
            return ARCHIVE_FATAL;
        }
        let Kind::Match(m) = &h.kind else {
            return ARCHIVE_FATAL;
        };
        let mut m = m.borrow_mut();
        f(&h.base, &mut m).unwrap_or_else(|e| {
            if e.code == ARCHIVE_FATAL {
                h.base.state.set(state::FATAL);
            }
            h.base.raise(e)
        })
    })
}
fn entry(
    a: *mut Archive,
    p: *mut ArchiveEntry,
    name: &str,
    f: impl FnOnce(&Base, &mut Matching, &mut Entry) -> Result<c_int, Error>,
) -> c_int {
    operation(a, name, |b, m| {
        // SAFETY: the caller supplies NULL or a live archive_entry allocation.
        let e = unsafe { p.cast::<Entry>().as_mut() }.ok_or_else(|| invalid("entry is NULL"))?;
        f(b, m, e)
    })
}
#[allow(dead_code)] // Used by the disk reader being integrated in Phase 5.
#[derive(Clone, Copy)]
pub(crate) struct MatchingHandle(*mut Archive);
#[allow(dead_code)] // Removed when the disk reader lands.
impl MatchingHandle {
    /// The caller retains the handle until the disk reader no longer uses it.
    pub(crate) fn new(p: *mut Archive) -> Option<Self> {
        with(p, None, |h| {
            (h.base.magic == MATCH_MAGIC).then_some(Self(p))
        })
    }
    pub(crate) fn path_excluded(self, e: &mut Entry) -> c_int {
        operation(self.0, "archive_match_path_excluded", |b, m| {
            Ok(m.path_excluded(b, e))
        })
    }
    pub(crate) fn time_excluded(self, e: &mut Entry) -> c_int {
        operation(self.0, "archive_match_time_excluded_ae", |_, m| {
            Ok(m.time_excluded(e))
        })
    }
    pub(crate) fn owner_excluded(self, e: &mut Entry) -> c_int {
        operation(self.0, "archive_match_owner_excluded_ae", |_, m| {
            Ok(m.owner_excluded(e))
        })
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_match_new() -> *mut Archive {
    guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(Handle {
            base: Base::new(MATCH_MAGIC),
            kind: Kind::Match(RefCell::new(Matching::default())),
        }))
        .cast()
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
    operation(a, "archive_match_set_inclusion_recursion", |_, m| {
        m.recursive = enabled != 0;
        Ok(ARCHIVE_OK)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_match_path_unmatched_inclusions(a: *mut Archive) -> c_int {
    operation(a, "archive_match_unmatched_inclusions", |_, m| {
        Ok(m.unmatched())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_match_path_unmatched_inclusions_next(
    a: *mut Archive,
    p: *mut *const c_char,
) -> c_int {
    operation(a, "archive_match_unmatched_inclusions_next", |_, m| {
        let (r, s, _) = m.unmatched_next(false);
        put(p, s);
        Ok(r)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_match_path_unmatched_inclusions_next_w(
    a: *mut Archive,
    p: *mut *const libc::wchar_t,
) -> c_int {
    operation(a, "archive_match_unmatched_inclusions_next_w", |_, m| {
        let (r, _, s) = m.unmatched_next(true);
        put(p, s);
        Ok(r)
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
    entry(a, e, "archive_match_time_include_entry", |_, m, e| {
        m.exclude_entry(flag, e)?;
        Ok(ARCHIVE_OK)
    })
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
    entry(a, e, "archive_match_excluded", |b, m, e| {
        let _ = b;
        Ok(m.excluded(b, e))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_path_excluded(a: *mut Archive, e: *mut ArchiveEntry) -> c_int {
    entry(a, e, "archive_match_path_excluded", |b, m, e| {
        let _ = b;
        Ok(m.path_excluded(b, e))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_time_excluded(a: *mut Archive, e: *mut ArchiveEntry) -> c_int {
    entry(a, e, "archive_match_time_excluded", |b, m, e| {
        let _ = b;
        Ok(m.time_excluded(e))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_owner_excluded(a: *mut Archive, e: *mut ArchiveEntry) -> c_int {
    entry(a, e, "archive_match_owner_excluded", |b, m, e| {
        let _ = b;
        Ok(m.owner_excluded(e))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_pattern(a: *mut Archive, p: *const c_char) -> c_int {
    operation(a, "archive_match_include_pattern", |_, m| {
        m.pattern(true, text(p))?;
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_pattern_from_file(
    a: *mut Archive,
    p: *const c_char,
    null: c_int,
) -> c_int {
    operation(a, "archive_match_include_pattern_from_file", |_, m| {
        let mut t = text(p);
        let path = t
            .get_mbs_c(None)
            .ok()
            .flatten()
            .ok_or_else(|| invalid("pathname is empty"))?;
        if path.to_bytes().is_empty() {
            return Err(invalid("pathname is empty"));
        }
        m.patterns_file(true, path.to_bytes(), null != 0)?;
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_pattern_w(
    a: *mut Archive,
    p: *const libc::wchar_t,
) -> c_int {
    operation(a, "archive_match_include_pattern_w", |_, m| {
        m.pattern(true, wide(p))?;
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_pattern_from_file_w(
    a: *mut Archive,
    p: *const libc::wchar_t,
    null: c_int,
) -> c_int {
    operation(a, "archive_match_include_pattern_from_file_w", |_, m| {
        let mut t = wide(p);
        let path = t
            .get_mbs_c(None)
            .ok()
            .flatten()
            .ok_or_else(|| invalid("pathname is empty"))?;
        if path.to_bytes().is_empty() {
            return Err(invalid("pathname is empty"));
        }
        m.patterns_file(true, path.to_bytes(), null != 0)?;
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_exclude_pattern(a: *mut Archive, p: *const c_char) -> c_int {
    operation(a, "archive_match_exclude_pattern", |_, m| {
        m.pattern(false, text(p))?;
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_exclude_pattern_from_file(
    a: *mut Archive,
    p: *const c_char,
    null: c_int,
) -> c_int {
    operation(a, "archive_match_exclude_pattern_from_file", |_, m| {
        let mut t = text(p);
        let path = t
            .get_mbs_c(None)
            .ok()
            .flatten()
            .ok_or_else(|| invalid("pathname is empty"))?;
        if path.to_bytes().is_empty() {
            return Err(invalid("pathname is empty"));
        }
        m.patterns_file(false, path.to_bytes(), null != 0)?;
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_exclude_pattern_w(
    a: *mut Archive,
    p: *const libc::wchar_t,
) -> c_int {
    operation(a, "archive_match_exclude_pattern_w", |_, m| {
        m.pattern(false, wide(p))?;
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_exclude_pattern_from_file_w(
    a: *mut Archive,
    p: *const libc::wchar_t,
    null: c_int,
) -> c_int {
    operation(a, "archive_match_exclude_pattern_from_file_w", |_, m| {
        let mut t = wide(p);
        let path = t
            .get_mbs_c(None)
            .ok()
            .flatten()
            .ok_or_else(|| invalid("pathname is empty"))?;
        if path.to_bytes().is_empty() {
            return Err(invalid("pathname is empty"));
        }
        m.patterns_file(false, path.to_bytes(), null != 0)?;
        Ok(ARCHIVE_OK)
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
    operation(a, "archive_match_include_file_time", |_, m| {
        crate::matching::validate_time(flag)?;
        let mut t = text(p);
        let path = t
            .get_mbs_c(None)
            .ok()
            .flatten()
            .ok_or_else(|| invalid("pathname is empty"))?;
        m.include_file_time(flag, path.to_bytes())?;
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_date(
    a: *mut Archive,
    flag: c_int,
    p: *const c_char,
) -> c_int {
    operation(a, "archive_match_include_date", |_, m| {
        crate::matching::validate_time(flag)?;
        let mut t = text(p);
        let date = t
            .get_mbs_c(None)
            .ok()
            .flatten()
            .ok_or_else(|| invalid("date is empty"))?
            .to_bytes();
        if date.is_empty() {
            return Err(invalid("date is empty"));
        }
        let sec =
            crate::parse_date::parse(m.now, date).ok_or_else(|| invalid("invalid date string"))?;
        m.include_time(flag, (sec, 0), (sec, 0))?;
        Ok(ARCHIVE_OK)
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
    operation(a, "archive_match_include_file_time_w", |_, m| {
        crate::matching::validate_time(flag)?;
        let mut t = wide(p);
        let path = t
            .get_mbs_c(None)
            .ok()
            .flatten()
            .ok_or_else(|| invalid("pathname is empty"))?;
        m.include_file_time(flag, path.to_bytes())?;
        Ok(ARCHIVE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_match_include_date_w(
    a: *mut Archive,
    flag: c_int,
    p: *const libc::wchar_t,
) -> c_int {
    operation(a, "archive_match_include_date_w", |_, m| {
        crate::matching::validate_time(flag)?;
        let mut t = wide(p);
        let date = t
            .get_mbs_c(None)
            .ok()
            .flatten()
            .ok_or_else(|| invalid("date is empty"))?
            .to_bytes();
        if date.is_empty() {
            return Err(invalid("date is empty"));
        }
        let sec =
            crate::parse_date::parse(m.now, date).ok_or_else(|| invalid("invalid date string"))?;
        m.include_time(flag, (sec, 0), (sec, 0))?;
        Ok(ARCHIVE_OK)
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
