//! `archive_match_*`: selecting entries by pathname pattern, time and
//! owner.

use super::{Archive, ArchiveEntry, Status};
use crate::archive::{ARCHIVE_FATAL, ARCHIVE_OK, Base, Handle, Kind, MATCH_MAGIC, state};
use crate::entry::Entry;
use crate::matching::{self, Matching, invalid};
use crate::string::{MString, until_nul};
use crate::util::Error;
use std::cell::RefCell;
use std::ffi::{CStr, c_int};
use std::ops::{Deref, DerefMut};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// The pathname or date a function was given, as a C string: `None` if it
/// is NULL or doesn't convert.
fn c_text(text: &mut MString) -> Option<&[u8]> {
    text.get_mbs_c(None).ok().flatten().map(CStr::to_bytes)
}

impl Handle {
    /// `f` on the match state, after `archive_check_magic(a,
    /// ARCHIVE_MATCH_MAGIC, ARCHIVE_STATE_NEW, func)`. A failure is
    /// recorded, and a fatal one makes the handle fatal.
    pub(crate) fn match_operation(
        &self,
        func: &str,
        f: impl FnOnce(&Base, &mut Matching) -> Result<c_int, Error>,
    ) -> c_int {
        self.checked(MATCH_MAGIC, state::NEW, func, ARCHIVE_FATAL, || {
            let Kind::Match(m) = &self.kind else {
                return ARCHIVE_FATAL;
            };
            f(&self.base, &mut m.borrow_mut()).unwrap_or_else(|e| {
                if e.code == ARCHIVE_FATAL {
                    self.base.state.set(state::FATAL);
                }
                self.base.raise(e)
            })
        })
    }

    /// A function that tests an entry: the entry is NULL-checked after the
    /// handle.
    fn match_entry(
        &self,
        func: &str,
        e: Option<&mut Entry>,
        f: impl FnOnce(&Base, &mut Matching, &mut Entry) -> Result<c_int, Error>,
    ) -> c_int {
        self.match_operation(func, |a, m| {
            f(a, m, e.ok_or_else(|| invalid("entry is NULL"))?)
        })
    }

    pub(crate) fn match_excluded(&self, e: Option<&mut Entry>) -> c_int {
        let func = "archive_match_excluded_ae";
        self.match_entry(func, e, |a, m, e| Ok(m.excluded(a, e)))
    }

    pub(crate) fn match_path_excluded(&self, e: Option<&mut Entry>) -> c_int {
        let func = "archive_match_path_excluded";
        self.match_entry(func, e, |a, m, e| Ok(m.path_excluded(a, e)))
    }

    pub(crate) fn match_time_excluded(&self, e: Option<&mut Entry>) -> c_int {
        let func = "archive_match_time_excluded_ae";
        self.match_entry(func, e, |_, m, e| Ok(m.time_excluded(e)))
    }

    pub(crate) fn match_owner_excluded(&self, e: Option<&mut Entry>) -> c_int {
        let func = "archive_match_id_excluded_ae";
        self.match_entry(func, e, |_, m, e| Ok(m.owner_excluded(e)))
    }

    /// `archive_match_exclude_entry`.
    pub(crate) fn match_exclude_entry(&self, flag: c_int, e: Option<&mut Entry>) -> c_int {
        self.match_entry("archive_match_time_include_entry", e, |_, m, e| {
            m.exclude_entry(flag, e)?;
            Ok(ARCHIVE_OK)
        })
    }

    pub(crate) fn match_set_inclusion_recursion(&self, enabled: bool) -> c_int {
        self.match_operation("archive_match_set_inclusion_recursion", |_, m| {
            m.recursive = enabled;
            Ok(ARCHIVE_OK)
        })
    }

    pub(crate) fn match_path_unmatched_inclusions(&self) -> c_int {
        let func = "archive_match_unmatched_inclusions";
        self.match_operation(func, |_, m| Ok(m.unmatched()))
    }

    /// `archive_match_path_unmatched_inclusions_next` and its `_w` twin
    /// (`func`): gives the next unmatched pattern to `f`.
    pub(crate) fn match_path_unmatched_inclusions_next(
        &self,
        func: &str,
        f: impl FnOnce(Option<&mut MString>),
    ) -> c_int {
        self.match_operation(func, |_, m| {
            let (r, pattern) = m.unmatched_next();
            f(pattern);
            Ok(r)
        })
    }

    /// `archive_match_include_pattern`, `archive_match_exclude_pattern`
    /// and their `_w` twins (`func`).
    pub(crate) fn match_pattern(&self, func: &str, include: bool, pattern: MString) -> c_int {
        self.match_operation(func, |_, m| {
            m.pattern(include, pattern)?;
            Ok(ARCHIVE_OK)
        })
    }

    /// The `archive_match_*_pattern_from_file*` functions (`func`): the
    /// patterns in the file `path` (standard input for NULL or an empty
    /// name), one a line or, with `null`, separated by NULs.
    pub(crate) fn match_pattern_from_file(
        &self,
        func: &str,
        include: bool,
        mut path: MString,
        null: bool,
    ) -> c_int {
        self.match_operation(func, |a, m| {
            m.patterns_file(a, include, c_text(&mut path), null)
        })
    }

    /// `archive_match_include_file_time` and its `_w` twin (`func`).
    pub(crate) fn match_include_file_time(
        &self,
        func: &str,
        flag: c_int,
        mut path: MString,
    ) -> c_int {
        self.match_operation(func, |_, m| {
            matching::validate_time(flag)?;
            let path = c_text(&mut path).ok_or_else(|| invalid("pathname is empty"))?;
            m.include_file_time(flag, path)?;
            Ok(ARCHIVE_OK)
        })
    }

    /// `archive_match_include_date` and its `_w` twin (`func`).
    pub(crate) fn match_include_date(&self, func: &str, flag: c_int, mut date: MString) -> c_int {
        self.match_operation(func, |_, m| {
            matching::validate_time(flag)?;
            let date = c_text(&mut date).filter(|d| !d.is_empty());
            let date = date.ok_or_else(|| invalid("date is empty"))?;
            let sec = crate::parse_date::parse(m.now, date)
                .filter(|&sec| sec != -1)
                .ok_or_else(|| invalid("invalid date string"))?;
            m.include_time(flag, (sec, 0), (sec, 0))?;
            Ok(ARCHIVE_OK)
        })
    }
}

/// `archive_match_new`.
pub(crate) fn new() -> Handle {
    Handle {
        base: Base::new(MATCH_MAGIC),
        kind: Kind::Match(RefCell::new(Matching::default())),
    }
}

/// A C string the caller passed, as the matcher keeps it.
fn text(s: &[u8]) -> MString {
    let mut text = MString::default();
    text.copy_mbs(until_nul(s));
    text
}

/// A pathname as C would pass it.
fn path_text(path: &Path) -> MString {
    text(path.as_os_str().as_bytes())
}

/// The result of a test: whether the entry is excluded, or the failure.
fn excluded(r: c_int) -> Result<bool, Status> {
    if r < 0 {
        Err(Status::from_code(r))
    } else {
        Ok(r != 0)
    }
}

/// A handle that selects entries: `archive_match_new`. Where C tests
/// `if (archive_match_excluded(m, e))`, failures count as excluded, so
/// test `m.excluded(e) != Ok(false)`.
pub struct ArchiveMatch {
    a: Archive,
}

impl ArchiveMatch {
    /// `archive_match_new`.
    pub fn new() -> Self {
        ArchiveMatch {
            a: Archive { h: new() },
        }
    }

    /// `archive_match_excluded`: whether the entry is excluded by any
    /// test.
    pub fn excluded(&mut self, entry: &mut ArchiveEntry) -> Result<bool, Status> {
        excluded(self.a.h.match_excluded(Some(&mut entry.0)))
    }

    /// `archive_match_path_excluded`: whether the pathname is excluded.
    pub fn path_excluded(&mut self, entry: &mut ArchiveEntry) -> Result<bool, Status> {
        excluded(self.a.h.match_path_excluded(Some(&mut entry.0)))
    }

    /// `archive_match_time_excluded`.
    pub fn time_excluded(&mut self, entry: &mut ArchiveEntry) -> Result<bool, Status> {
        excluded(self.a.h.match_time_excluded(Some(&mut entry.0)))
    }

    /// `archive_match_owner_excluded`.
    pub fn owner_excluded(&mut self, entry: &mut ArchiveEntry) -> Result<bool, Status> {
        excluded(self.a.h.match_owner_excluded(Some(&mut entry.0)))
    }

    /// `archive_match_exclude_entry`: excludes the files newer, older or as
    /// old (`ARCHIVE_MATCH_*` in `flag`) as the entry's pathname.
    pub fn exclude_entry(&mut self, flag: c_int, entry: &mut ArchiveEntry) -> Status {
        Status::from_code(self.a.h.match_exclude_entry(flag, Some(&mut entry.0)))
    }

    /// `archive_match_set_inclusion_recursion`: whether an inclusion
    /// pattern includes what is under the directories it matches.
    pub fn set_inclusion_recursion(&mut self, enabled: bool) -> Status {
        Status::from_code(self.a.h.match_set_inclusion_recursion(enabled))
    }

    /// `archive_match_path_unmatched_inclusions`: how many inclusion
    /// patterns nothing has matched.
    pub fn path_unmatched_inclusions(&mut self) -> Result<usize, Status> {
        Status::from_size(self.a.h.match_path_unmatched_inclusions() as isize)
    }

    /// `archive_match_path_unmatched_inclusions_next`: `Ok` and the next
    /// pattern nothing has matched, or `Eof` after the last one.
    pub fn path_unmatched_inclusions_next(&mut self) -> (Status, Option<Vec<u8>>) {
        let func = "archive_match_unmatched_inclusions_next";
        let mut next = None;
        let r = self.a.h.match_path_unmatched_inclusions_next(func, |p| {
            next = p.map(|p| c_text(p).unwrap_or_default().to_vec());
        });
        (Status::from_code(r), next)
    }

    /// `archive_match_include_pattern`.
    pub fn include_pattern(&mut self, pattern: &[u8]) -> Status {
        let func = "archive_match_include_pattern";
        Status::from_code(self.a.h.match_pattern(func, true, text(pattern)))
    }

    /// `archive_match_exclude_pattern`.
    pub fn exclude_pattern(&mut self, pattern: &[u8]) -> Status {
        let func = "archive_match_exclude_pattern";
        Status::from_code(self.a.h.match_pattern(func, false, text(pattern)))
    }

    /// `archive_match_include_pattern_from_file`: the patterns in `path`,
    /// one a line, or separated by NULs.
    pub fn include_pattern_from_file(&mut self, path: &Path, null_separator: bool) -> Status {
        let func = "archive_match_include_pattern_from_file";
        let r = self
            .a
            .h
            .match_pattern_from_file(func, true, path_text(path), null_separator);
        Status::from_code(r)
    }

    /// `archive_match_exclude_pattern_from_file`.
    pub fn exclude_pattern_from_file(&mut self, path: &Path, null_separator: bool) -> Status {
        let func = "archive_match_exclude_pattern_from_file";
        let r = self
            .a
            .h
            .match_pattern_from_file(func, false, path_text(path), null_separator);
        Status::from_code(r)
    }

    /// `archive_match_include_file_time`: includes the files newer, older
    /// or as old (`ARCHIVE_MATCH_*` in `flag`) as the file `path`.
    pub fn include_file_time(&mut self, flag: c_int, path: &Path) -> Status {
        let func = "archive_match_include_file_time";
        Status::from_code(
            self.a
                .h
                .match_include_file_time(func, flag, path_text(path)),
        )
    }

    /// `archive_match_include_date`: as `include_file_time`, for a date as
    /// `archive_parse_date` reads it.
    pub fn include_date(&mut self, flag: c_int, date: &[u8]) -> Status {
        let func = "archive_match_include_date";
        Status::from_code(self.a.h.match_include_date(func, flag, text(date)))
    }
}

impl Default for ArchiveMatch {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for ArchiveMatch {
    type Target = Archive;

    fn deref(&self) -> &Archive {
        &self.a
    }
}

impl DerefMut for ArchiveMatch {
    fn deref_mut(&mut self) -> &mut Archive {
        &mut self.a
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{ARCHIVE_MATCH_MTIME, ARCHIVE_MATCH_NEWER};

    fn entry(path: &[u8]) -> ArchiveEntry {
        let mut e = ArchiveEntry::new();
        e.set_pathname(Some(path));
        e
    }

    fn error(m: &ArchiveMatch) -> String {
        let msg = m.error_string();
        msg.map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned())
    }

    #[test]
    fn patterns_include_and_exclude_paths() {
        let mut m = ArchiveMatch::new();
        assert_eq!(m.include_pattern(b"dir"), Status::Ok);
        assert_eq!(m.exclude_pattern(b"*.o"), Status::Ok);
        assert_eq!(m.path_excluded(&mut entry(b"dir/a.c")), Ok(false));
        assert_eq!(m.path_excluded(&mut entry(b"dir/a.o")), Ok(true));
        assert_eq!(m.excluded(&mut entry(b"other")), Ok(true));
        assert_eq!(m.set_inclusion_recursion(false), Status::Ok);
        assert_eq!(m.path_excluded(&mut entry(b"dir/b.c")), Ok(true));
    }

    #[test]
    fn unmatched_inclusions_are_listed_once() {
        let mut m = ArchiveMatch::new();
        for p in [b"a".as_slice(), b"b", b"c"] {
            assert_eq!(m.include_pattern(p), Status::Ok);
        }
        assert_eq!(m.path_excluded(&mut entry(b"b")), Ok(false));
        assert_eq!(m.path_unmatched_inclusions(), Ok(2));
        assert_eq!(
            m.path_unmatched_inclusions_next(),
            (Status::Ok, Some(b"a".to_vec()))
        );
        assert_eq!(
            m.path_unmatched_inclusions_next(),
            (Status::Ok, Some(b"c".to_vec()))
        );
        assert_eq!(m.path_unmatched_inclusions_next(), (Status::Eof, None));
    }

    #[test]
    fn patterns_from_a_file() {
        let path = std::env::temp_dir().join(format!("api-match-{}", std::process::id()));
        // The first pattern straddles two of the reader's blocks.
        let long = [vec![b'x'; 10238], b".tmp".to_vec()].concat();
        std::fs::write(&path, [&long[..], b"\r\n\n*.bak"].concat()).unwrap();
        let mut m = ArchiveMatch::new();
        assert_eq!(m.exclude_pattern_from_file(&path, false), Status::Ok);
        std::fs::write(&path, b"*.c\0dir\0").unwrap();
        assert_eq!(m.include_pattern_from_file(&path, true), Status::Ok);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(m.path_excluded(&mut entry(&long)), Ok(true));
        assert_eq!(m.path_excluded(&mut entry(b"x.bak")), Ok(true));
        assert_eq!(m.path_excluded(&mut entry(b"x.c")), Ok(false));
        assert_eq!(m.path_excluded(&mut entry(b"dir/y")), Ok(false));
        assert_eq!(m.path_excluded(&mut entry(b"y")), Ok(true));

        // A file that can't be read fails this call, not the handle.
        let missing = Path::new("/nonexistent/api-match");
        assert_eq!(m.include_pattern_from_file(missing, false), Status::Fatal);
        assert_eq!(error(&m), "Failed to open '/nonexistent/api-match'");
        assert_eq!(m.include_pattern(b"z"), Status::Ok);
    }

    #[test]
    fn times_select_by_mtime() {
        let mut m = ArchiveMatch::new();
        let newer = ARCHIVE_MATCH_MTIME | ARCHIVE_MATCH_NEWER;
        assert_eq!(
            m.include_date(newer, b"1970-01-02 00:00:00 UTC"),
            Status::Ok
        );
        let mut old = entry(b"old");
        old.set_mtime(10, 0);
        let mut new = entry(b"new");
        new.set_mtime(100_000, 0);
        assert_eq!(m.time_excluded(&mut old), Ok(true));
        assert_eq!(m.time_excluded(&mut new), Ok(false));
        assert_eq!(m.include_date(newer, b"not a date"), Status::Failed);
        assert_eq!(error(&m), "invalid date string");
        // A date that comes to -1 is as bad.
        assert_eq!(m.include_date(newer, b"@-1"), Status::Failed);
        assert_eq!(m.include_date(0, b"1970-01-01"), Status::Failed);
        assert_eq!(error(&m), "No time flag");
        assert_eq!(m.owner_excluded(&mut old), Ok(false));
    }
}
