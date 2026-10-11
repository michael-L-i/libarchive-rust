//! `archive_write_*`: writing an archive.

use super::{Archive, ArchiveEntry, Status};
use crate::archive::{ARCHIVE_FATAL, ARCHIVE_OK, Base, Handle, Kind, WRITE_MAGIC, state};
use crate::write::Write;
use std::cell::RefCell;
use std::ffi::c_int;
use std::ops::{Deref, DerefMut};

impl Handle {
    /// `f` on the write state, after `archive_check_magic(a,
    /// ARCHIVE_WRITE_MAGIC, states, func)`.
    pub(crate) fn write_checked<T: Copy>(
        &self,
        func: &str,
        states: u32,
        fallback: T,
        f: impl FnOnce(&Base, &mut Write) -> T,
    ) -> T {
        self.checked(WRITE_MAGIC, states, func, fallback, || match &self.kind {
            Kind::Write(w) => w
                .try_borrow_mut()
                .map_or(fallback, |mut w| f(&self.base, &mut w)),
            _ => fallback,
        })
    }

    pub(crate) fn write_set_bytes_per_block(&self, n: c_int) -> c_int {
        let func = "archive_write_set_bytes_per_block";
        self.write_checked(func, state::NEW, ARCHIVE_FATAL, |_, w| {
            if n >= 0 {
                w.bytes_per_block = n;
            }
            ARCHIVE_OK
        })
    }

    pub(crate) fn write_set_bytes_in_last_block(&self, n: c_int) -> c_int {
        let func = "archive_write_set_bytes_in_last_block";
        self.write_checked(func, state::ANY, ARCHIVE_FATAL, |_, w| {
            w.bytes_in_last_block = n;
            ARCHIVE_OK
        })
    }
}

/// `archive_write_new`.
pub(crate) fn new() -> Handle {
    Handle {
        base: Base::new(WRITE_MAGIC),
        kind: Kind::Write(RefCell::new(Write::default())),
    }
}

/// A handle that writes an archive: `archive_write_new`.
pub struct ArchiveWrite {
    a: Archive,
}

impl ArchiveWrite {
    /// `archive_write_new`.
    pub fn new() -> Self {
        ArchiveWrite {
            a: Archive { h: new() },
        }
    }

    /// `archive_write_set_bytes_per_block`: the size of the writes to the
    /// output; 0 writes as soon as there is data.
    pub fn set_bytes_per_block(&mut self, n: c_int) -> Status {
        Status::from_code(self.a.h.write_set_bytes_per_block(n))
    }

    /// `archive_write_set_bytes_in_last_block`: pads the last block to a
    /// multiple of `n`.
    pub fn set_bytes_in_last_block(&mut self, n: c_int) -> Status {
        Status::from_code(self.a.h.write_set_bytes_in_last_block(n))
    }

    /// `archive_write_header`.
    pub fn header(&mut self, entry: &mut ArchiveEntry) -> Status {
        Status::from_code(self.a.h.write_header(&mut entry.0))
    }

    /// `archive_write_data`: the entry's data, after its header.
    pub fn data(&mut self, buf: &[u8]) -> Result<usize, Status> {
        Status::from_size(self.a.h.write_data(buf))
    }

    /// `archive_write_finish_entry`.
    pub fn finish_entry(&mut self) -> Status {
        Status::from_code(self.a.h.write_finish_entry())
    }

    /// `archive_write_close`: writes the end of the archive and flushes it.
    pub fn close(&mut self) -> Status {
        Status::from_code(self.a.h.close())
    }
}

impl Default for ArchiveWrite {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for ArchiveWrite {
    type Target = Archive;

    fn deref(&self) -> &Archive {
        &self.a
    }
}

impl DerefMut for ArchiveWrite {
    fn deref_mut(&mut self) -> &mut Archive {
        &mut self.a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setters_check_the_state() {
        let mut a = ArchiveWrite::new();
        assert_eq!(a.set_bytes_per_block(10240), Status::Ok);
        assert_eq!(a.set_bytes_in_last_block(1), Status::Ok);
        assert_eq!(a.header(&mut ArchiveEntry::new()), Status::Fatal);
        assert_eq!(a.set_bytes_per_block(512), Status::Fatal);
    }
}
