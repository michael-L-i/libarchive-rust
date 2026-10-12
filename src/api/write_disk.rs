//! `archive_write_disk_*`: writing entries to the file system.

use super::{Archive, ArchiveEntry, Status};
use crate::archive::{ARCHIVE_FATAL, ARCHIVE_OK, Base, Handle, Kind, WRITE_DISK_MAGIC};
use crate::ffi::disk::IdLookup;
use crate::write_disk::WriteDisk;
use std::cell::RefCell;
use std::ffi::c_int;
use std::ops::{Deref, DerefMut};

pub const ARCHIVE_EXTRACT_OWNER: c_int = 0x0001;
pub const ARCHIVE_EXTRACT_PERM: c_int = 0x0002;
pub const ARCHIVE_EXTRACT_TIME: c_int = 0x0004;
pub const ARCHIVE_EXTRACT_NO_OVERWRITE: c_int = 0x0008;
pub const ARCHIVE_EXTRACT_UNLINK: c_int = 0x0010;
pub const ARCHIVE_EXTRACT_ACL: c_int = 0x0020;
pub const ARCHIVE_EXTRACT_FFLAGS: c_int = 0x0040;
pub const ARCHIVE_EXTRACT_XATTR: c_int = 0x0080;
pub const ARCHIVE_EXTRACT_SECURE_SYMLINKS: c_int = 0x0100;
pub const ARCHIVE_EXTRACT_SECURE_NODOTDOT: c_int = 0x0200;
pub const ARCHIVE_EXTRACT_NO_AUTODIR: c_int = 0x0400;
pub const ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER: c_int = 0x0800;
pub const ARCHIVE_EXTRACT_SPARSE: c_int = 0x1000;
pub const ARCHIVE_EXTRACT_MAC_METADATA: c_int = 0x2000;
pub const ARCHIVE_EXTRACT_NO_HFS_COMPRESSION: c_int = 0x4000;
pub const ARCHIVE_EXTRACT_HFS_COMPRESSION_FORCED: c_int = 0x8000;
pub const ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS: c_int = 0x10000;
pub const ARCHIVE_EXTRACT_CLEAR_NOCHANGE_FFLAGS: c_int = 0x20000;
pub const ARCHIVE_EXTRACT_SAFE_WRITES: c_int = 0x40000;

impl Handle {
    /// Runs `f` on the write-disk state. Upstream's setters check no
    /// state; another kind of handle gets `fallback`, as does a client
    /// callback that calls back into its own handle.
    pub(crate) fn with_write_disk<T>(
        &self,
        fallback: T,
        f: impl FnOnce(&Base, &mut WriteDisk) -> T,
    ) -> T {
        match &self.kind {
            Kind::WriteDisk(d) => d
                .try_borrow_mut()
                .map_or(fallback, |mut d| f(&self.base, &mut d)),
            _ => fallback,
        }
    }

    pub(crate) fn write_disk_set_options(&self, flags: c_int) -> c_int {
        self.with_write_disk(ARCHIVE_FATAL, |_, d| {
            d.options = flags;
            ARCHIVE_OK
        })
    }

    pub(crate) fn write_disk_set_skip_file(&self, dev: i64, ino: i64) -> c_int {
        self.with_write_disk(ARCHIVE_FATAL, |_, d| {
            d.skip_file = Some((dev, ino));
            ARCHIVE_OK
        })
    }

    pub(crate) fn write_disk_set_standard_lookup(&self) -> c_int {
        self.with_write_disk(ARCHIVE_FATAL, |_, d| {
            d.user = IdLookup::standard();
            d.group = IdLookup::standard();
            ARCHIVE_OK
        })
    }
}

/// `archive_write_disk_new`.
pub(crate) fn new() -> Handle {
    let base = Base::new(WRITE_DISK_MAGIC);
    base.state.set(crate::archive::state::HEADER);
    Handle {
        base,
        kind: Kind::WriteDisk(RefCell::new(WriteDisk::default())),
    }
}

/// A handle that writes entries to the file system:
/// `archive_write_disk_new`. The `archive_write_*` functions that work on
/// any writer (`archive_write_header` and so on) are its methods too.
pub struct ArchiveWriteDisk {
    a: Archive,
}

impl ArchiveWriteDisk {
    /// `archive_write_disk_new`.
    pub fn new() -> Self {
        ArchiveWriteDisk {
            a: Archive { h: new() },
        }
    }

    /// `archive_write_disk_set_options`: the `ARCHIVE_EXTRACT_*` flags.
    pub fn set_options(&mut self, flags: c_int) -> Status {
        Status::from_code(self.a.h.write_disk_set_options(flags))
    }

    /// `archive_write_disk_set_skip_file`: the file (device and inode) not
    /// to overwrite.
    pub fn set_skip_file(&mut self, dev: i64, ino: i64) -> Status {
        Status::from_code(self.a.h.write_disk_set_skip_file(dev, ino))
    }

    /// `archive_write_disk_set_standard_lookup`: maps user and group names
    /// to ids with the system's databases.
    pub fn set_standard_lookup(&mut self) -> Status {
        Status::from_code(self.a.h.write_disk_set_standard_lookup())
    }

    /// `archive_write_header`: creates the entry's file.
    pub fn header(&mut self, entry: &mut ArchiveEntry) -> Status {
        Status::from_code(self.a.h.write_header(&mut entry.0))
    }

    /// `archive_write_data`: writes data at the current offset.
    pub fn data(&mut self, buf: &[u8]) -> Result<usize, Status> {
        Status::from_size(self.a.h.write_data(buf))
    }

    /// `archive_write_data_block`: writes data at `offset` in the file.
    pub fn data_block(&mut self, buf: &[u8], offset: i64) -> Result<usize, Status> {
        Status::from_size(self.a.h.write_data_block(buf, offset))
    }

    /// `archive_write_finish_entry`: sets the file's metadata.
    pub fn finish_entry(&mut self) -> Status {
        Status::from_code(self.a.h.write_finish_entry())
    }

    /// `archive_write_close`: finishes the directories' metadata.
    pub fn close(&mut self) -> Status {
        Status::from_code(self.a.h.close())
    }
}

impl Default for ArchiveWriteDisk {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for ArchiveWriteDisk {
    type Target = Archive;

    fn deref(&self) -> &Archive {
        &self.a
    }
}

impl DerefMut for ArchiveWriteDisk {
    fn deref_mut(&mut self) -> &mut Archive {
        &mut self.a
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ArchiveRead;
    use std::cell::Cell;
    use std::os::unix::ffi::OsStrExt;
    use std::rc::Rc;

    #[test]
    fn header_and_finish_entry_check_the_state() {
        let mut disk = ArchiveWriteDisk::new();
        let mut entry = ArchiveEntry::new();
        // No pathname: the header fails, so the handle stays in the header
        // state and writing data is a programming error.
        assert_eq!(disk.header(&mut entry), Status::Failed);
        assert_eq!(disk.data(b"x"), Err(Status::Fatal));
        assert_eq!(disk.finish_entry(), Status::Fatal);
        assert_eq!(disk.header(&mut entry), Status::Fatal);
    }

    #[test]
    fn extract2_writes_an_entry_and_reports_progress() {
        let dir = std::env::temp_dir().join(format!("api-extract-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out");

        let mut a = ArchiveRead::new();
        assert_eq!(a.support_format_raw(), Status::Ok);
        assert_eq!(a.open_memory(b"extracted".as_slice()), Status::Ok);
        let blocks = Rc::new(Cell::new(0));
        let counter = Rc::clone(&blocks);
        let name = path.as_os_str().as_bytes().to_vec();
        a.extract_set_progress_callback(move |a, e| {
            assert_eq!(a.file_count(), 1);
            assert_eq!(e.pathname(), Some(name.as_slice()));
            counter.set(counter.get() + 1);
        });
        let mut entry = ArchiveEntry::new();
        assert_eq!(a.next_header2(&mut entry), Status::Ok);
        entry.set_pathname(Some(path.as_os_str().as_bytes()));
        entry.set_mode(crate::api::AE_IFREG | 0o644);

        let mut disk = ArchiveWriteDisk::new();
        assert_eq!(disk.set_options(ARCHIVE_EXTRACT_TIME), Status::Ok);
        assert_eq!(disk.set_standard_lookup(), Status::Ok);
        assert_eq!(a.extract2(&mut entry, &mut disk), Status::Ok);
        assert_eq!(disk.close(), Status::Ok);
        assert_eq!(std::fs::read(&path).unwrap(), b"extracted");
        assert_eq!(blocks.get(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
