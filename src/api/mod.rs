//! The Rust API: libarchive's C API as typed handles, for Rust programs
//! such as the front-ends in `tools/`.
//!
//! It mirrors the C API rather than reinventing it, so C that uses
//! libarchive ports mechanically:
//!
//! - Each kind of `struct archive *` is a type: `archive_read_X(a, ...)` is
//!   `ArchiveRead::X`, `archive_write_disk_X` is `ArchiveWriteDisk::X`, and
//!   so on; `archive_entry_X(e)` is `ArchiveEntry::X`. Every handle
//!   dereferences to `Archive`, which has what any `struct archive *`
//!   answers (`archive_errno`, `archive_error_string`, `archive_filter_*`).
//!   `archive_X_new` is `new`, and `archive_X_free` is dropping the handle.
//! - A function that returns `ARCHIVE_OK` and friends returns `Status`; one
//!   that returns a count or a status (`ssize_t`) returns
//!   `Result<usize, Status>`. The error message and errno stay on the
//!   handle, as in C.
//! - Strings are bytes (`&[u8]`), since pathnames need not be UTF-8; a
//!   string C may pass as NULL is an `Option`. Names of files on disk are
//!   `&Path`, and file descriptors are `AsFd`.
//! - A callback is a closure. It cannot reach the handle it is registered
//!   on, so it captures whatever else it needs.
//!
//! The functions' behavior lives in `impl Handle` blocks in this module:
//! the C exports in `ffi` and the typed handles both call them, so they
//! can't drift apart.

mod entry;
pub(crate) mod matching;
mod read;
pub(crate) mod read_disk;
pub(crate) mod write;
pub(crate) mod write_disk;

pub use crate::entry::{
    AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFMT, AE_IFREG, AE_IFSOCK, Dev, Mode,
};
pub use crate::matching::{
    CTIME as ARCHIVE_MATCH_CTIME, EQUAL as ARCHIVE_MATCH_EQUAL, MTIME as ARCHIVE_MATCH_MTIME,
    NEWER as ARCHIVE_MATCH_NEWER, OLDER as ARCHIVE_MATCH_OLDER,
};
pub use entry::{ArchiveEntry, ArchiveEntryLinkresolver};
pub use matching::ArchiveMatch;
pub use read::ArchiveRead;
pub use read_disk::{
    ARCHIVE_READDISK_HONOR_NODUMP, ARCHIVE_READDISK_MAC_COPYFILE, ARCHIVE_READDISK_NO_ACL,
    ARCHIVE_READDISK_NO_FFLAGS, ARCHIVE_READDISK_NO_SPARSE, ARCHIVE_READDISK_NO_TRAVERSE_MOUNTS,
    ARCHIVE_READDISK_NO_XATTR, ARCHIVE_READDISK_RESTORE_ATIME, ArchiveReadDisk, ReadDiskView,
};
pub use write::ArchiveWrite;
pub use write_disk::{
    ARCHIVE_EXTRACT_ACL, ARCHIVE_EXTRACT_CLEAR_NOCHANGE_FFLAGS, ARCHIVE_EXTRACT_FFLAGS,
    ARCHIVE_EXTRACT_HFS_COMPRESSION_FORCED, ARCHIVE_EXTRACT_MAC_METADATA,
    ARCHIVE_EXTRACT_NO_AUTODIR, ARCHIVE_EXTRACT_NO_HFS_COMPRESSION, ARCHIVE_EXTRACT_NO_OVERWRITE,
    ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER, ARCHIVE_EXTRACT_OWNER, ARCHIVE_EXTRACT_PERM,
    ARCHIVE_EXTRACT_SAFE_WRITES, ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS,
    ARCHIVE_EXTRACT_SECURE_NODOTDOT, ARCHIVE_EXTRACT_SECURE_SYMLINKS, ARCHIVE_EXTRACT_SPARSE,
    ARCHIVE_EXTRACT_TIME, ARCHIVE_EXTRACT_UNLINK, ARCHIVE_EXTRACT_XATTR, ArchiveWriteDisk,
};

use crate::archive::{
    ARCHIVE_EOF, ARCHIVE_FAILED, ARCHIVE_FATAL, ARCHIVE_OK, ARCHIVE_RETRY, ARCHIVE_WARN, Handle,
};
use std::cell::Ref;
use std::ffi::c_int;

/// `ARCHIVE_OK` and the other codes an `archive_*` function returns. The
/// order is the codes', so `r < Status::Ok` and `r <= Status::Warn` read
/// as they do in C.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum Status {
    /// `ARCHIVE_FATAL`: no more operations are possible.
    Fatal = ARCHIVE_FATAL,
    /// `ARCHIVE_FAILED`: this operation failed, but others may work.
    Failed = ARCHIVE_FAILED,
    /// `ARCHIVE_WARN`: partial success.
    Warn = ARCHIVE_WARN,
    /// `ARCHIVE_RETRY`: retry might succeed.
    Retry = ARCHIVE_RETRY,
    /// `ARCHIVE_OK`: success.
    Ok = ARCHIVE_OK,
    /// `ARCHIVE_EOF`: found end of archive.
    Eof = ARCHIVE_EOF,
}

impl Status {
    /// The C code.
    pub fn code(self) -> c_int {
        self as c_int
    }

    /// The status of a C code; a code that is none of them is fatal.
    pub(crate) fn from_code(code: c_int) -> Status {
        match code {
            ARCHIVE_EOF => Status::Eof,
            ARCHIVE_OK => Status::Ok,
            ARCHIVE_RETRY => Status::Retry,
            ARCHIVE_WARN => Status::Warn,
            ARCHIVE_FAILED => Status::Failed,
            _ => Status::Fatal,
        }
    }

    /// A `ssize_t` result: the count, or the status of a negative one.
    pub(crate) fn from_size(n: isize) -> Result<usize, Status> {
        usize::try_from(n)
            .map_err(|_| Status::from_code(c_int::try_from(n).unwrap_or(ARCHIVE_FATAL)))
    }
}

/// `struct archive`: what every kind of handle answers. The typed handles
/// dereference to it, and dropping one frees it (`archive_free`), closing
/// it first if needed.
pub struct Archive {
    pub(crate) h: Handle,
}

impl Archive {
    /// `archive_errno`.
    pub fn errno(&self) -> c_int {
        self.h.base.errno.get()
    }

    /// `archive_error_string`: `None` if there is no message.
    pub fn error_string(&self) -> Option<Ref<'_, [u8]>> {
        self.h.base.error_string()
    }

    /// `archive_clear_error`.
    pub fn clear_error(&mut self) {
        self.h.base.clear_error();
    }

    /// `archive_file_count`: the number of entries processed.
    pub fn file_count(&self) -> c_int {
        self.h.base.file_count.get()
    }

    /// `archive_format`: the `ARCHIVE_FORMAT_*` code.
    pub fn format(&self) -> c_int {
        self.h.base.format.get()
    }

    /// `archive_format_name`.
    pub fn format_name(&self) -> Option<Ref<'_, [u8]>> {
        self.h.base.format_name()
    }

    /// `archive_filter_count`.
    pub fn filter_count(&self) -> c_int {
        self.h.filter_count()
    }

    /// `archive_filter_code`: the `ARCHIVE_FILTER_*` code of filter `n`,
    /// counting from the one nearest the format (0); -1 is the one nearest
    /// the file.
    pub fn filter_code(&self, n: c_int) -> c_int {
        self.h.filter_code(n)
    }

    /// `archive_filter_name`.
    pub fn filter_name(&self, n: c_int) -> Option<Ref<'_, [u8]>> {
        self.h
            .filter_name(n)
            .map(|name| Ref::map(name, |name| name.to_bytes()))
    }

    /// `archive_filter_bytes`: the bytes filter `n` has processed.
    pub fn filter_bytes(&self, n: c_int) -> i64 {
        self.h.filter_bytes(n)
    }
}

impl Drop for Archive {
    fn drop(&mut self) {
        let _ = self.h.free();
    }
}

/// `archive_version_number`.
pub fn version_number() -> c_int {
    crate::util::VERSION_NUMBER
}

/// `archive_version_string`: "libarchive 3.9.0dev".
pub fn version_string() -> &'static str {
    crate::util::VERSION_STRING.to_str().unwrap_or_default()
}

/// `archive_version_details`: the version string followed by the version
/// of each compression backend.
pub fn version_details() -> &'static str {
    crate::version_details::details()
        .to_str()
        .unwrap_or_default()
}

/// `archive_parse_date`: the time `date` describes, relative to `now` for
/// relative dates, or -1 if it can't be parsed.
pub fn parse_date(now: i64, date: &[u8]) -> i64 {
    crate::parse_date::parse(now, crate::string::until_nul(date)).unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_order_and_convert_like_the_c_codes() {
        let all = [
            Status::Fatal,
            Status::Failed,
            Status::Warn,
            Status::Retry,
            Status::Ok,
            Status::Eof,
        ];
        assert!(
            all.windows(2)
                .all(|w| w[0] < w[1] && w[0].code() < w[1].code())
        );
        for s in all {
            assert_eq!(Status::from_code(s.code()), s);
        }
        assert_eq!(Status::from_code(-7), Status::Fatal);
        assert_eq!(Status::from_size(12), Ok(12));
        assert_eq!(Status::from_size(-20), Err(Status::Warn));
        assert_eq!(Status::from_size(isize::MIN), Err(Status::Fatal));
    }

    #[test]
    fn versions() {
        assert_eq!(version_number(), 3009000);
        assert_eq!(version_string(), "libarchive 3.9.0dev");
        assert!(version_details().starts_with("libarchive 3.9.0dev zlib/"));
    }

    #[test]
    fn parse_date_reads_c_strings() {
        assert_eq!(parse_date(0, b"1970-01-02 00:00:00 UTC"), 86400);
        assert_eq!(parse_date(0, b"1970-01-02 00:00:00 UTC\0junk"), 86400);
        assert_eq!(parse_date(0, b"no date"), -1);
    }
}
