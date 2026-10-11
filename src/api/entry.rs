//! `archive_entry_*`: the description of one archive member, and the
//! resolver that pairs up hard links.

use crate::entry::{Dev, Entry, Mode};
use crate::entry_link_resolver::LinkResolver;
use crate::string::until_nul;
use std::ffi::{CStr, c_int, c_uint};

/// `struct archive_entry`: `archive_entry_new`, freed when dropped, copied
/// with `clone` (`archive_entry_clone`).
pub struct ArchiveEntry(pub(crate) Box<Entry>);

/// Sets a text field to the C string `v`, or unsets it for NULL.
fn set_text(e: &mut Entry, v: Option<&[u8]>, set: fn(&mut Entry, &[u8]), unset: fn(&mut Entry)) {
    match v {
        Some(v) => set(e, until_nul(v)),
        None => unset(e),
    }
}

impl ArchiveEntry {
    /// `archive_entry_new`.
    pub fn new() -> Self {
        ArchiveEntry(Box::new(Entry::new(None)))
    }

    /// `archive_entry_atime`.
    pub fn atime(&self) -> i64 {
        self.0.atime()
    }

    /// `archive_entry_atime_nsec`.
    pub fn atime_nsec(&self) -> i64 {
        self.0.atime_nsec()
    }

    /// `archive_entry_filetype`: the `AE_IF*` bits of the mode.
    pub fn filetype(&self) -> Mode {
        self.0.filetype()
    }

    /// `archive_entry_gid`.
    pub fn gid(&self) -> i64 {
        self.0.gid()
    }

    /// `archive_entry_gname`.
    pub fn gname(&mut self) -> Option<&[u8]> {
        self.0.gname().map(CStr::to_bytes)
    }

    /// `archive_entry_hardlink`: the target, if this is a hard link.
    pub fn hardlink(&mut self) -> Option<&[u8]> {
        self.0.hardlink().map(CStr::to_bytes)
    }

    /// `archive_entry_mode`.
    pub fn mode(&self) -> Mode {
        self.0.mode()
    }

    /// `archive_entry_mtime`.
    pub fn mtime(&self) -> i64 {
        self.0.mtime()
    }

    /// `archive_entry_mtime_nsec`.
    pub fn mtime_nsec(&self) -> i64 {
        self.0.mtime_nsec()
    }

    /// `archive_entry_nlink`.
    pub fn nlink(&self) -> c_uint {
        self.0.nlink()
    }

    /// `archive_entry_pathname`.
    pub fn pathname(&mut self) -> Option<&[u8]> {
        self.0.pathname().map(CStr::to_bytes)
    }

    /// `archive_entry_rdevmajor`.
    pub fn rdevmajor(&self) -> Dev {
        self.0.rdevmajor()
    }

    /// `archive_entry_rdevminor`.
    pub fn rdevminor(&self) -> Dev {
        self.0.rdevminor()
    }

    /// `archive_entry_size`.
    pub fn size(&self) -> i64 {
        self.0.size()
    }

    /// `archive_entry_size_is_set`.
    pub fn size_is_set(&self) -> bool {
        self.0.size_is_set() != 0
    }

    /// `archive_entry_sourcepath`.
    pub fn sourcepath(&mut self) -> Option<&[u8]> {
        self.0.sourcepath().map(CStr::to_bytes)
    }

    /// `archive_entry_strmode`: the mode as `ls -l` shows it, "-rw-r--r-- ".
    pub fn strmode(&mut self) -> &[u8] {
        self.0.strmode().to_bytes()
    }

    /// `archive_entry_symlink`: the target, if this is a symbolic link.
    pub fn symlink(&mut self) -> Option<&[u8]> {
        self.0.symlink().map(CStr::to_bytes)
    }

    /// `archive_entry_uid`.
    pub fn uid(&self) -> i64 {
        self.0.uid()
    }

    /// `archive_entry_uname`.
    pub fn uname(&mut self) -> Option<&[u8]> {
        self.0.uname().map(CStr::to_bytes)
    }

    /// `archive_entry_copy_hardlink`: makes this a hard link to `target`;
    /// `None` unsets it, unless the entry is a symbolic link.
    pub fn copy_hardlink(&mut self, target: Option<&[u8]>) {
        set_text(&mut self.0, target, Entry::copy_hardlink, |e| {
            e.unset_hardlink();
        });
    }

    /// `archive_entry_copy_pathname`.
    pub fn copy_pathname(&mut self, name: Option<&[u8]>) {
        set_text(
            &mut self.0,
            name,
            Entry::set_pathname,
            Entry::clear_pathname,
        );
    }

    /// `archive_entry_copy_sourcepath`.
    pub fn copy_sourcepath(&mut self, path: Option<&[u8]>) {
        set_text(
            &mut self.0,
            path,
            Entry::set_sourcepath,
            Entry::clear_sourcepath,
        );
    }

    /// `archive_entry_copy_symlink`: makes this a symbolic link to `target`;
    /// `None` unsets it, unless the entry is a hard link.
    pub fn copy_symlink(&mut self, target: Option<&[u8]>) {
        set_text(&mut self.0, target, Entry::set_symlink, |e| {
            e.unset_symlink();
        });
    }

    /// `archive_entry_set_gid`.
    pub fn set_gid(&mut self, gid: i64) {
        self.0.set_gid(gid);
    }

    /// `archive_entry_set_gname`.
    pub fn set_gname(&mut self, name: Option<&[u8]>) {
        set_text(&mut self.0, name, Entry::set_gname, Entry::clear_gname);
    }

    /// `archive_entry_set_hardlink`: like `copy_hardlink`, but a target also
    /// unsets a symbolic link.
    pub fn set_hardlink(&mut self, target: Option<&[u8]>) {
        set_text(&mut self.0, target, Entry::set_hardlink, |e| {
            e.unset_hardlink();
        });
    }

    /// `archive_entry_set_mode`.
    pub fn set_mode(&mut self, mode: Mode) {
        self.0.set_mode(mode);
    }

    /// `archive_entry_set_mtime`.
    pub fn set_mtime(&mut self, sec: i64, nsec: i64) {
        self.0.set_mtime(sec, nsec);
    }

    /// `archive_entry_set_pathname`.
    pub fn set_pathname(&mut self, name: Option<&[u8]>) {
        set_text(
            &mut self.0,
            name,
            Entry::set_pathname,
            Entry::clear_pathname,
        );
    }

    /// `archive_entry_set_size`.
    pub fn set_size(&mut self, size: i64) {
        self.0.set_size(size);
    }

    /// `archive_entry_set_uid`.
    pub fn set_uid(&mut self, uid: i64) {
        self.0.set_uid(uid);
    }

    /// `archive_entry_set_uname`.
    pub fn set_uname(&mut self, name: Option<&[u8]>) {
        set_text(&mut self.0, name, Entry::set_uname, Entry::clear_uname);
    }
}

impl Default for ArchiveEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ArchiveEntry {
    fn clone(&self) -> Self {
        ArchiveEntry(Box::new(self.0.clone_entry()))
    }
}

/// `struct archive_entry_linkresolver`: matches up the hard links of the
/// entries an archive writer is given, in the way the writer's format
/// wants (`archive_entry_linkresolver_set_strategy`).
pub struct ArchiveEntryLinkresolver(LinkResolver);

impl ArchiveEntryLinkresolver {
    /// `archive_entry_linkresolver_new`.
    pub fn new() -> Self {
        ArchiveEntryLinkresolver(LinkResolver::new())
    }

    /// `archive_entry_linkresolver_set_strategy`: the strategy of the
    /// `ARCHIVE_FORMAT_*` code `format`.
    pub fn set_strategy(&mut self, format: c_int) {
        self.0.set_strategy(format);
    }

    /// `archive_entry_linkify(res, &e, &f)`: takes the entry in `e` (`None`
    /// at the end of the input) and puts back the entry to write now, if
    /// any. Returns `f`: another entry to write after it.
    pub fn linkify(&mut self, e: &mut Option<ArchiveEntry>) -> Option<ArchiveEntry> {
        let (out, extra) = self.0.linkify(e.take().map(|e| e.0));
        *e = out.map(ArchiveEntry);
        extra.map(ArchiveEntry)
    }
}

impl Default for ArchiveEntryLinkresolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{AE_IFDIR, AE_IFREG};

    #[test]
    fn text_fields_read_back_as_c_strings() {
        let mut e = ArchiveEntry::new();
        assert_eq!(e.pathname(), None);
        e.set_pathname(Some(b"dir/file"));
        assert_eq!(e.pathname(), Some(b"dir/file".as_slice()));
        // A C string ends at its NUL.
        e.copy_pathname(Some(b"cut\0off"));
        assert_eq!(e.pathname(), Some(b"cut".as_slice()));
        e.set_pathname(None);
        assert_eq!(e.pathname(), None);

        e.set_uname(Some(b"root"));
        e.set_gname(Some(b"wheel"));
        e.copy_sourcepath(Some(b"/src"));
        assert_eq!(e.uname(), Some(b"root".as_slice()));
        assert_eq!(e.gname(), Some(b"wheel".as_slice()));
        assert_eq!(e.sourcepath(), Some(b"/src".as_slice()));
        e.set_uname(None);
        assert_eq!(e.uname(), None);
    }

    #[test]
    fn links_are_one_target_of_two_kinds() {
        let mut e = ArchiveEntry::new();
        e.copy_symlink(Some(b"target"));
        assert_eq!(e.hardlink(), None);
        assert_eq!(e.symlink(), Some(b"target".as_slice()));
        // Unsetting the other kind of link leaves this one alone.
        e.copy_hardlink(None);
        assert_eq!(e.symlink(), Some(b"target".as_slice()));
        // set_hardlink replaces a symlink.
        e.set_hardlink(Some(b"first"));
        assert_eq!(e.symlink(), None);
        assert_eq!(e.hardlink(), Some(b"first".as_slice()));
        e.set_hardlink(None);
        assert_eq!(e.hardlink(), None);
    }

    #[test]
    fn numbers_and_mode() {
        let mut e = ArchiveEntry::new();
        assert!(!e.size_is_set());
        e.set_size(1234);
        e.set_uid(1000);
        e.set_gid(20);
        e.set_mtime(5, 1_000_000_001);
        e.set_mode(AE_IFREG | 0o644);
        assert!(e.size_is_set());
        assert_eq!((e.size(), e.uid(), e.gid()), (1234, 1000, 20));
        assert_eq!((e.mtime(), e.mtime_nsec()), (6, 1));
        assert_eq!((e.filetype(), e.mode()), (AE_IFREG, AE_IFREG | 0o644));
        assert_eq!(e.strmode(), b"-rw-r--r-- ");
        assert_eq!((e.atime(), e.atime_nsec(), e.nlink()), (0, 0, 0));
        assert_eq!((e.rdevmajor(), e.rdevminor()), (0, 0));
    }

    #[test]
    fn clones_are_independent() {
        let mut e = ArchiveEntry::new();
        e.set_pathname(Some(b"a"));
        let mut c = e.clone();
        c.set_pathname(Some(b"b"));
        assert_eq!(e.pathname(), Some(b"a".as_slice()));
        assert_eq!(c.pathname(), Some(b"b".as_slice()));
    }

    fn file(name: &[u8], ino: i64, nlink: u32, mode: Mode) -> Option<ArchiveEntry> {
        let mut e = ArchiveEntry::new();
        e.set_pathname(Some(name));
        e.0.set_dev(1);
        e.0.set_ino(ino);
        e.0.set_nlink(nlink);
        e.set_mode(mode);
        e.set_size(10);
        Some(e)
    }

    #[test]
    fn linkify_holds_back_new_cpio_links_until_the_last() {
        let mut res = ArchiveEntryLinkresolver::new();
        // ARCHIVE_FORMAT_CPIO_SVR4_NOCRC.
        res.set_strategy(0x10004);
        let mut e = file(b"one", 7, 2, AE_IFREG | 0o644);
        assert!(res.linkify(&mut e).is_none());
        assert!(e.is_none(), "the first link is held back");
        let mut e = file(b"two", 7, 2, AE_IFREG | 0o644);
        let extra = res.linkify(&mut e);
        let (mut first, mut last) = (e.unwrap(), extra.unwrap());
        assert_eq!(first.pathname(), Some(b"one".as_slice()));
        assert!(!first.size_is_set());
        assert_eq!(last.pathname(), Some(b"two".as_slice()));
        // Directories never have hard links.
        let mut e = file(b"dir", 8, 3, AE_IFDIR | 0o755);
        assert!(res.linkify(&mut e).is_none());
        assert!(e.is_some());
        // Nothing is left at the end.
        let mut end = None;
        assert!(res.linkify(&mut end).is_none() && end.is_none());
    }
}
