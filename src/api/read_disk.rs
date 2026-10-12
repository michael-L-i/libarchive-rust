//! `archive_read_disk_*`: reading entries from the file system.

use super::{Archive, ArchiveEntry, ArchiveMatch, Status};
use crate::archive::READ_DISK_MAGIC;
use crate::archive::{ARCHIVE_FAILED, ARCHIVE_FATAL, ARCHIVE_OK, Base, Handle, Kind};
use crate::entry::Entry;
use crate::ffi::disk::NameLookup;
use crate::ffi::matching::MatchingHandle;
use crate::read_disk::{ExcludedCallback, MetadataFilter, ReadDisk};
use crate::string::until_nul;
use std::cell::RefCell;
use std::ffi::{CStr, OsStr, c_int};
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub const ARCHIVE_READDISK_RESTORE_ATIME: c_int = 0x0001;
pub const ARCHIVE_READDISK_HONOR_NODUMP: c_int = 0x0002;
pub const ARCHIVE_READDISK_MAC_COPYFILE: c_int = 0x0004;
pub const ARCHIVE_READDISK_NO_TRAVERSE_MOUNTS: c_int = 0x0008;
pub const ARCHIVE_READDISK_NO_XATTR: c_int = 0x0010;
pub const ARCHIVE_READDISK_NO_ACL: c_int = 0x0020;
pub const ARCHIVE_READDISK_NO_FFLAGS: c_int = 0x0040;
pub const ARCHIVE_READDISK_NO_SPARSE: c_int = 0x0080;

/// The match handle a disk reader tests entries with: one C lent it, or
/// one of its own (boxed, since a handle can't contain itself).
pub(crate) enum DiskMatcher {
    Lent(MatchingHandle),
    Owned(Box<ArchiveMatch>),
}

impl DiskMatcher {
    pub(crate) fn handle(&self) -> &Handle {
        match self {
            DiskMatcher::Lent(m) => m.handle(),
            DiskMatcher::Owned(m) => &m.h,
        }
    }
}

impl Handle {
    /// Runs `f` on the read-disk state; another kind of handle gets
    /// `fallback`, as does a callback that calls back into its own handle.
    pub(crate) fn with_read_disk<T>(
        &self,
        fallback: T,
        f: impl FnOnce(&Base, &mut ReadDisk) -> T,
    ) -> T {
        match &self.kind {
            Kind::ReadDisk(d) => d
                .try_borrow_mut()
                .map_or(fallback, |mut d| f(&self.base, &mut d)),
            _ => fallback,
        }
    }

    pub(crate) fn read_disk_open(&self, path: &[u8]) -> c_int {
        self.with_read_disk(ARCHIVE_FATAL, |a, d| d.open(a, path))
    }

    /// The `archive_read_disk_set_symlink_*` functions: 0 physical, 1
    /// logical, 2 hybrid.
    pub(crate) fn read_disk_set_symlinks(&self, mode: u8) -> c_int {
        self.with_read_disk(ARCHIVE_FATAL, |_, d| {
            d.symlinks = mode;
            ARCHIVE_OK
        })
    }

    pub(crate) fn read_disk_set_behavior(&self, flags: c_int) -> c_int {
        self.with_read_disk(ARCHIVE_FATAL, |_, d| {
            d.behavior = flags;
            ARCHIVE_OK
        })
    }

    pub(crate) fn read_disk_set_standard_lookup(&self) -> c_int {
        self.with_read_disk(ARCHIVE_FATAL, |_, d| {
            d.user = NameLookup::standard();
            d.group = NameLookup::standard();
            ARCHIVE_OK
        })
    }

    pub(crate) fn read_disk_set_matching(
        &self,
        matching: Option<DiskMatcher>,
        excluded: Option<ExcludedCallback>,
    ) -> c_int {
        self.with_read_disk(ARCHIVE_FATAL, |_, d| {
            d.matching = matching;
            d.excluded = excluded;
            ARCHIVE_OK
        })
    }

    pub(crate) fn read_disk_set_metadata_filter_callback(
        &self,
        filter: Option<MetadataFilter>,
    ) -> c_int {
        self.with_read_disk(ARCHIVE_FATAL, |_, d| {
            d.metadata_filter = filter;
            ARCHIVE_OK
        })
    }

    /// `archive_read_disk_entry_from_file`: fills in `entry` from the file
    /// its source path or pathname names, with `st` if given, else from
    /// `fd` (if not -1) or the path.
    pub(crate) fn read_disk_entry_from_file(
        &self,
        entry: &mut Entry,
        fd: c_int,
        st: Option<&libc::stat>,
    ) -> c_int {
        self.with_read_disk(ARCHIVE_FATAL, |a, d| {
            let source = entry
                .sourcepath()
                .map(|p| p.to_bytes().to_vec())
                .or_else(|| entry.pathname().map(|p| p.to_bytes().to_vec()));
            let Some(path) = source.map(|p| PathBuf::from(OsStr::from_bytes(&p))) else {
                return ARCHIVE_FATAL;
            };
            if let Some(st) = st {
                entry.copy_stat(st);
            } else {
                let follow = d.symlinks != 0;
                let stat = match crate::ffi::disk_sys::stat(&path, fd, follow) {
                    Ok(s) => s,
                    Err(e) => {
                        let name = path.as_os_str().as_bytes();
                        let msg = match (fd >= 0, follow) {
                            (true, _) => b"Can't fstat".to_vec(),
                            (false, false) => [b"Can't lstat ", name].concat(),
                            (false, true) => [b"Can't stat ", name].concat(),
                        };
                        let errno = e.raw_os_error().unwrap_or(libc::EIO);
                        return a.raise(crate::util::Error::new(ARCHIVE_FAILED, errno, msg));
                    }
                };
                entry.copy_stat(&stat);
            }
            let fd = (fd >= 0).then_some(fd);
            d.fill_metadata(a, entry, &path, d.symlinks != 0, fd)
        })
    }

    /// `archive_read_disk_descend`. From a callback inside the traversal
    /// (the metadata filter), where the state is in use, it is a request
    /// the traversal carries out.
    pub(crate) fn read_disk_descend(&self) -> c_int {
        match &self.kind {
            Kind::ReadDisk(d) => match d.try_borrow_mut() {
                Ok(mut d) => d.descend(&self.base),
                Err(_) => {
                    self.base.disk_descend_requested.set(true);
                    ARCHIVE_OK
                }
            },
            _ => ARCHIVE_FATAL,
        }
    }
}

/// `archive_read_disk_new`, without the entry `archive_read_next_header`
/// hands to C.
pub(crate) fn new() -> Handle {
    Handle {
        base: Base::new(READ_DISK_MAGIC),
        kind: Kind::ReadDisk(RefCell::new(ReadDisk::new())),
    }
}

/// The disk reader as its callbacks see it: C's callbacks get the handle,
/// but in the middle of the walk they may only ask about the entry just
/// read.
pub struct ReadDiskView<'a>(&'a Base);

impl ReadDiskView<'_> {
    /// `archive_read_disk_can_descend`.
    pub fn can_descend(&self) -> bool {
        self.0.disk_can_descend.get()
    }

    /// `archive_read_disk_descend`: the walk goes into the directory once
    /// the callback returns.
    pub fn descend(&self) -> Status {
        self.0.disk_descend_requested.set(true);
        Status::Ok
    }
}

/// A read-disk callback's entry argument: the reader's `Entry`, lent as
/// an `ArchiveEntry` for the call.
fn lend<T>(entry: &mut Entry, f: impl FnOnce(&mut ArchiveEntry) -> T) -> T {
    let mut lent = ArchiveEntry(Box::new(std::mem::replace(entry, Entry::new(None))));
    let r = f(&mut lent);
    *entry = *lent.0;
    r
}

/// A handle that walks the file system and reads entries from it:
/// `archive_read_disk_new`. The `archive_read_*` functions that work on any
/// reader (`archive_read_next_header2` and so on) are its methods too.
pub struct ArchiveReadDisk {
    a: Archive,
}

impl ArchiveReadDisk {
    /// `archive_read_disk_new`.
    pub fn new() -> Self {
        ArchiveReadDisk {
            a: Archive { h: new() },
        }
    }

    /// `archive_read_disk_open`: starts the walk at `path`.
    pub fn open(&mut self, path: &Path) -> Status {
        let path = until_nul(path.as_os_str().as_bytes());
        Status::from_code(self.a.h.read_disk_open(path))
    }

    /// `archive_read_next_header2`: the next file of the walk.
    pub fn next_header2(&mut self, entry: &mut ArchiveEntry) -> Status {
        Status::from_code(self.a.h.read_next_header2(&mut entry.0))
    }

    /// `archive_read_data_block`: the next block of the file's data and its
    /// offset; `Eof` at the end.
    pub fn data_block(&mut self) -> (Status, &[u8], i64) {
        let h = &mut self.a.h;
        let Kind::ReadDisk(d) = &mut h.kind else {
            return (Status::Fatal, &[], 0);
        };
        match d.get_mut().data_block(&h.base) {
            Ok((code, data, offset)) => (Status::from_code(code), data, offset),
            Err(code) => (Status::from_code(code), &[], 0),
        }
    }

    /// `archive_read_disk_descend`: walks into the directory just read.
    pub fn descend(&mut self) -> Status {
        Status::from_code(self.a.h.read_disk_descend())
    }

    /// `archive_read_disk_can_descend`: whether the entry just read is a
    /// directory the walk can go into.
    pub fn can_descend(&self) -> bool {
        self.a.h.base.disk_can_descend.get()
    }

    /// `archive_read_disk_current_filesystem_is_remote`: 1, 0, or -1 if
    /// unknown.
    pub fn current_filesystem_is_remote(&self) -> c_int {
        self.a.h.base.disk_remote.get()
    }

    /// `archive_read_disk_set_behavior`: the `ARCHIVE_READDISK_*` flags.
    pub fn set_behavior(&mut self, flags: c_int) -> Status {
        Status::from_code(self.a.h.read_disk_set_behavior(flags))
    }

    /// `archive_read_disk_set_symlink_logical`: follows symbolic links.
    pub fn set_symlink_logical(&mut self) -> Status {
        Status::from_code(self.a.h.read_disk_set_symlinks(1))
    }

    /// `archive_read_disk_set_symlink_physical`: doesn't follow them.
    pub fn set_symlink_physical(&mut self) -> Status {
        Status::from_code(self.a.h.read_disk_set_symlinks(0))
    }

    /// `archive_read_disk_set_symlink_hybrid`: follows those named on the
    /// command line (the paths given to `open`).
    pub fn set_symlink_hybrid(&mut self) -> Status {
        Status::from_code(self.a.h.read_disk_set_symlinks(2))
    }

    /// `archive_read_disk_set_standard_lookup`: maps ids to user and group
    /// names with the system's databases.
    pub fn set_standard_lookup(&mut self) -> Status {
        Status::from_code(self.a.h.read_disk_set_standard_lookup())
    }

    /// `archive_read_disk_set_matching`: skips the entries `matching`
    /// excludes, after `excluded` has seen them. The reader keeps the
    /// match handle; `matching` lends it back.
    #[allow(clippy::type_complexity)] // The C callback's arguments.
    pub fn set_matching(
        &mut self,
        matching: Option<ArchiveMatch>,
        excluded: Option<Box<dyn FnMut(&ReadDiskView<'_>, &mut ArchiveEntry)>>,
    ) -> Status {
        let matching = matching.map(|m| DiskMatcher::Owned(Box::new(m)));
        let excluded = excluded.map(|mut f| -> ExcludedCallback {
            Box::new(move |a, entry| lend(entry, |e| f(&ReadDiskView(a), e)))
        });
        Status::from_code(self.a.h.read_disk_set_matching(matching, excluded))
    }

    /// The match handle `set_matching` gave the reader.
    pub fn matching(&mut self) -> Option<&mut ArchiveMatch> {
        match &mut self.a.h.kind {
            Kind::ReadDisk(d) => match &mut d.get_mut().matching {
                Some(DiskMatcher::Owned(m)) => Some(m),
                _ => None,
            },
            _ => None,
        }
    }

    /// `archive_read_disk_set_metadata_filter_callback`: skips the entries
    /// `filter` returns false for.
    #[allow(clippy::type_complexity)] // The C callback's arguments.
    pub fn set_metadata_filter_callback(
        &mut self,
        filter: Option<Box<dyn FnMut(&ReadDiskView<'_>, &mut ArchiveEntry) -> bool>>,
    ) -> Status {
        let filter = filter.map(|mut f| -> MetadataFilter {
            Box::new(move |a, entry| lend(entry, |e| f(&ReadDiskView(a), e)))
        });
        Status::from_code(self.a.h.read_disk_set_metadata_filter_callback(filter))
    }

    /// `archive_read_disk_entry_from_file`: fills in `entry` from the file
    /// its source path (or else its pathname) names, or from `fd`.
    pub fn entry_from_file(
        &mut self,
        entry: &mut ArchiveEntry,
        fd: Option<BorrowedFd<'_>>,
    ) -> Status {
        let fd = fd.map_or(-1, |fd| fd.as_raw_fd());
        Status::from_code(self.a.h.read_disk_entry_from_file(&mut entry.0, fd, None))
    }

    /// `archive_read_disk_uname`: the name of user `uid`, as the lookup
    /// set up finds it.
    pub fn uname(&mut self, uid: i64) -> Option<&[u8]> {
        let Kind::ReadDisk(d) = &mut self.a.h.kind else {
            return None;
        };
        d.get_mut().user.lookup(uid, false).map(CStr::to_bytes)
    }

    /// `archive_read_disk_gname`: the name of group `gid`.
    pub fn gname(&mut self, gid: i64) -> Option<&[u8]> {
        let Kind::ReadDisk(d) = &mut self.a.h.kind else {
            return None;
        };
        d.get_mut().group.lookup(gid, true).map(CStr::to_bytes)
    }

    /// `archive_read_close`.
    pub fn close(&mut self) -> Status {
        Status::from_code(self.a.h.close())
    }
}

impl Default for ArchiveReadDisk {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for ArchiveReadDisk {
    type Target = Archive;

    fn deref(&self) -> &Archive {
        &self.a
    }
}

impl DerefMut for ArchiveReadDisk {
    fn deref_mut(&mut self) -> &mut Archive {
        &mut self.a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_a_directory_and_reads_its_files() {
        let dir = std::env::temp_dir().join(format!("api-read-disk-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/file"), b"on disk").unwrap();

        let mut d = ArchiveReadDisk::new();
        assert_eq!(d.set_standard_lookup(), Status::Ok);
        assert_eq!(d.set_symlink_physical(), Status::Ok);
        assert_eq!(d.open(&dir), Status::Ok);
        let mut entry = ArchiveEntry::new();
        let mut names = Vec::new();
        let mut data = Vec::new();
        while d.next_header2(&mut entry) == Status::Ok {
            names.push(entry.pathname().unwrap_or_default().to_vec());
            if d.can_descend() {
                assert_eq!(d.descend(), Status::Ok);
            }
            loop {
                let (r, block, _) = d.data_block();
                data.extend_from_slice(block);
                if r != Status::Ok {
                    break;
                }
            }
        }
        let root = dir.as_os_str().as_bytes().to_vec();
        let sub = [&root[..], b"/sub"].concat();
        let file = [&root[..], b"/sub/file"].concat();
        assert_eq!(names, [root, sub, file]);
        assert_eq!(data, b"on disk");
        assert_eq!(d.close(), Status::Ok);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A directory with `dir/a.c`, `dir/b.o` and `skip/c.c`.
    fn tree(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("api-read-disk-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("dir")).unwrap();
        std::fs::create_dir_all(dir.join("skip")).unwrap();
        for f in ["dir/a.c", "dir/b.o", "skip/c.c"] {
            std::fs::write(dir.join(f), f).unwrap();
        }
        dir
    }

    /// The names the walk returns, relative to `dir`.
    fn walk(d: &mut ArchiveReadDisk, dir: &Path) -> Vec<String> {
        assert_eq!(d.open(dir), Status::Ok);
        let mut entry = ArchiveEntry::new();
        let mut names = Vec::new();
        while d.next_header2(&mut entry) == Status::Ok {
            let name = entry.pathname().unwrap_or_default();
            let name = name.strip_prefix(dir.as_os_str().as_bytes()).unwrap();
            names.push(String::from_utf8_lossy(name).into_owned());
        }
        names.sort();
        names
    }

    #[test]
    fn callbacks_filter_and_descend() {
        use std::cell::RefCell;
        use std::rc::Rc;
        let dir = tree("callbacks");
        let mut d = ArchiveReadDisk::new();
        let mut matching = ArchiveMatch::new();
        assert_eq!(matching.exclude_pattern(b"*.o"), Status::Ok);
        let excluded = Rc::new(RefCell::new(Vec::new()));
        let seen = Rc::clone(&excluded);
        let callback = move |_: &ReadDiskView<'_>, e: &mut ArchiveEntry| {
            seen.borrow_mut()
                .push(e.pathname().unwrap_or_default().to_vec());
        };
        assert_eq!(
            d.set_matching(Some(matching), Some(Box::new(callback))),
            Status::Ok
        );
        // The filter walks into the directories but "skip", and leaves out
        // the directories themselves.
        let filter = |w: &ReadDiskView<'_>, e: &mut ArchiveEntry| {
            let skip = e.pathname().is_some_and(|p| p.ends_with(b"/skip"));
            if w.can_descend() && !skip {
                assert_eq!(w.descend(), Status::Ok);
            }
            e.filetype() != crate::api::AE_IFDIR
        };
        assert_eq!(
            d.set_metadata_filter_callback(Some(Box::new(filter))),
            Status::Ok
        );
        assert_eq!(walk(&mut d, &dir), ["/dir/a.c"]);
        let b_o = [dir.as_os_str().as_bytes(), b"/dir/b.o"].concat();
        assert_eq!(*excluded.borrow(), [b_o]);

        // The reader lends its match handle back, and lets go of it.
        let mut entry = ArchiveEntry::new();
        entry.set_pathname(Some(b"x.o"));
        assert_eq!(d.matching().unwrap().path_excluded(&mut entry), Ok(true));
        assert_eq!(d.set_matching(None, None), Status::Ok);
        assert_eq!(d.set_metadata_filter_callback(None), Status::Ok);
        assert!(d.matching().is_none());
        assert_eq!(walk(&mut d, &dir), [""]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn entry_from_file_and_names() {
        use std::os::fd::AsFd;
        let dir = tree("entry");
        let path = dir.join("dir/a.c");
        let mut d = ArchiveReadDisk::new();
        let mut entry = ArchiveEntry::new();
        entry.set_pathname(Some(path.as_os_str().as_bytes()));
        assert_eq!(d.entry_from_file(&mut entry, None), Status::Ok);
        assert_eq!((entry.size(), entry.filetype()), (7, crate::api::AE_IFREG));
        // The descriptor wins over the name.
        let other = std::fs::File::open(dir.join("skip/c.c")).unwrap();
        assert_eq!(
            d.entry_from_file(&mut entry, Some(other.as_fd())),
            Status::Ok
        );
        assert_eq!(entry.size(), 8);

        // Names come from the lookup set up.
        let (uid, gid) = (entry.uid(), entry.gid());
        assert_eq!((d.uname(uid), entry.uname()), (None, None));
        assert_eq!(d.set_standard_lookup(), Status::Ok);
        assert_eq!(d.entry_from_file(&mut entry, None), Status::Ok);
        let uname = entry.uname().map(<[u8]>::to_vec);
        assert!(uname.is_some());
        assert_eq!(d.uname(uid).map(<[u8]>::to_vec), uname);
        let gname = entry.gname().map(<[u8]>::to_vec);
        assert_eq!(d.gname(gid).map(<[u8]>::to_vec), gname);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
