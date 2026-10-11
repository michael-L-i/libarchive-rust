//! `archive_read_disk_*`: reading entries from the file system.

use super::{Archive, ArchiveEntry, Status};
use crate::archive::READ_DISK_MAGIC;
use crate::archive::{ARCHIVE_EOF, ARCHIVE_FATAL, ARCHIVE_OK, Base, Handle, Kind};
use crate::ffi::disk::NameLookup;
use crate::read_disk::ReadDisk;
use crate::string::until_nul;
use std::cell::RefCell;
use std::ffi::c_int;
use std::ops::{Deref, DerefMut};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

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

/// `archive_read_data_block`'s code for what `ReadDisk::data_block` gave:
/// an empty block is the end of the file's data.
pub(crate) fn block_code(block: &Result<(&[u8], i64), c_int>) -> c_int {
    match block {
        Ok(([], _)) => ARCHIVE_EOF,
        Ok(_) => ARCHIVE_OK,
        Err(code) => *code,
    }
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
        let block = d.get_mut().data_block(&h.base);
        let code = Status::from_code(block_code(&block));
        block.map_or((code, &[], 0), |(data, offset)| (code, data, offset))
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
}
