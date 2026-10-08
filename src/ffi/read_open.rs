//! The exported `archive_read_open_*` functions: opening an archive from a
//! block of memory, a file descriptor, a `FILE *` or file names. The clients
//! themselves are safe Rust; this is the argument conversion.
//!
//! Upstream builds each of these from `archive_read_set_*_callback` calls
//! and `archive_read_open1`. The callbacks check that the archive is new and
//! name themselves in the error if not, so the checks here carry the name of
//! the first callback upstream sets.

use super::client::UserMem;
use super::read::with_read;
use super::sys::{CFile, Fd};
use super::{ARCHIVE_FATAL, Archive};
use crate::archive::{Handle, READ_MAGIC, state};
use crate::read::Client;
use crate::read_open_fd::ReadFd;
use crate::read_open_file::ReadFile;
use crate::read_open_filename::Filenames;
use crate::read_open_memory::Memory;
use crate::string::MString;
use crate::util::Error;
use std::ffi::{CStr, c_char, c_int, c_void};

use super::archive::with;

/// `archive_read_open1` for a native client, after the state check that the
/// first `archive_read_set_*_callback` call upstream makes.
fn open(h: &Handle, first_callback: &str, client: Box<dyn Client>) -> c_int {
    if h.base.check_magic(READ_MAGIC, state::NEW, first_callback) == ARCHIVE_FATAL {
        return ARCHIVE_FATAL;
    }
    with_read(h, ARCHIVE_FATAL, |r| r.open(&h.base, client))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_open_memory(a: *mut Archive, buff: *const c_void, size: usize) -> c_int {
    archive_read_open_memory2(a, buff, size, size)
}

/// Don't use `archive_read_open_memory2` in production code; the
/// `archive_read_open_memory` version is the one you really want. This is
/// just here so that test harnesses can exercise block operations inside the
/// library.
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_open_memory2(
    a: *mut Archive,
    buff: *const c_void,
    size: usize,
    read_size: usize,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        // SAFETY: the caller promises the block stays valid until the
        // archive is closed or freed.
        let Some(mem) = (unsafe { UserMem::new(buff, size) }) else {
            return h.base.raise(Error::fatal(libc::EINVAL, "Invalid memory block"));
        };
        open(h, "archive_read_set_open_callback", Box::new(Memory::new(mem, read_size)))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_open_fd(a: *mut Archive, fd: c_int, block_size: usize) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.base.clear_error();
        match ReadFd::new(Fd(fd), block_size) {
            Ok((client, skip_file)) => {
                with_read(h, (), |r| r.skip_file = skip_file.or(r.skip_file));
                open(h, "archive_read_set_read_callback", Box::new(client))
            }
            Err(e) => h.base.raise(e),
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_open_FILE(a: *mut Archive, file: *mut libc::FILE) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.base.clear_error();
        if file.is_null() {
            return h.base.raise(Error::fatal(libc::EINVAL, "Invalid FILE pointer"));
        }
        // SAFETY: the caller promises the stream stays valid, and unused by
        // anyone else, until the archive is closed or freed.
        let file = unsafe { CFile::new(file) };
        match ReadFile::new(file) {
            Ok((client, skip_file)) => {
                with_read(h, (), |r| r.skip_file = skip_file.or(r.skip_file));
                open(h, "archive_read_set_read_callback", Box::new(client))
            }
            Err(e) => h.base.raise(e),
        }
    })
}

/// The names of `archive_read_open_filenames`: the first (or standard input
/// if there is none), then those up to a NULL or empty one. Standard input
/// is `None`.
///
/// # Safety
///
/// `filenames` is NULL, or points to a NULL-terminated array of C strings.
unsafe fn names(filenames: *const *const c_char) -> Vec<Option<Vec<u8>>> {
    fn name(p: *const c_char) -> Option<Vec<u8>> {
        // SAFETY: a string in the caller's array (see `names`).
        let name = (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec());
        name.filter(|n| !n.is_empty())
    }
    if filenames.is_null() {
        return vec![None];
    }
    // SAFETY: elements before the terminating NULL are readable.
    let first = unsafe { *filenames };
    let mut names = vec![name(first)];
    let mut next = 1;
    loop {
        // SAFETY: the array is NULL-terminated, and we stop at the NULL.
        let Some(n) = name(unsafe { *filenames.add(next) }) else {
            return names;
        };
        names.push(Some(n));
        next += 1;
    }
}

fn open_names(a: *mut Archive, names: Vec<Option<Vec<u8>>>, block_size: usize) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.base.clear_error();
        open(h, "archive_read_add_callback_data", Box::new(Filenames::new(names, block_size)))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_open_filenames(
    a: *mut Archive,
    filenames: *mut *const c_char,
    block_size: usize,
) -> c_int {
    // SAFETY: the caller passes NULL or a NULL-terminated array of strings.
    open_names(a, unsafe { names(filenames) }, block_size)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_open_filename(
    a: *mut Archive,
    filename: *const c_char,
    block_size: usize,
) -> c_int {
    let list = [filename, std::ptr::null()];
    // SAFETY: `list` is a NULL-terminated array of the caller's string.
    open_names(a, unsafe { names(list.as_ptr()) }, block_size)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_open_file(
    a: *mut Archive,
    filename: *const c_char,
    block_size: usize,
) -> c_int {
    archive_read_open_filename(a, filename, block_size)
}

/// POSIX has no wide-character `open`, so the name is converted to a
/// multibyte one.
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_open_filename_w(
    a: *mut Archive,
    wfilename: *const libc::wchar_t,
    block_size: usize,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.base.clear_error();
        let mut wide = Vec::new();
        if !wfilename.is_null() {
            // SAFETY: the caller passes a NUL-terminated wide string.
            while let Some(&c) = (unsafe { wfilename.add(wide.len()).as_ref() }).filter(|&&c| c != 0) {
                wide.push(c);
            }
        }
        let name = if wide.is_empty() {
            None
        } else {
            let mut s = MString::default();
            s.copy_wcs(&wide);
            match s.get_mbs(None) {
                Ok(mbs) => mbs.map(<[u8]>::to_vec),
                Err(_) => {
                    return h.base.raise(Error::fatal(
                        libc::EINVAL,
                        "Failed to convert a wide-character filename to a multi-byte filename",
                    ));
                }
            }
        };
        open(
            h,
            "archive_read_add_callback_data",
            Box::new(Filenames::new(vec![name], block_size)),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::super::ARCHIVE_OK;
    use super::super::archive::archive_free;
    use super::super::read::archive_read_new;
    use super::super::read::tests::{drain, error, register_anything};
    use super::*;
    use std::ffi::CString;
    use std::path::{Path, PathBuf};

    fn new() -> *mut Archive {
        let a = archive_read_new();
        register_anything(a);
        a
    }

    fn temp(tag: &str, i: usize, data: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!("archive-open-{tag}-{}-{i}", std::process::id()));
        std::fs::write(&p, data).unwrap();
        p
    }

    fn c(p: &Path) -> CString {
        CString::new(p.to_str().unwrap()).unwrap()
    }

    #[test]
    fn open_memory_reads_the_block() {
        let data = b"memory block contents".to_vec();
        for read_size in [4, 1000] {
            let a = new();
            assert_eq!(archive_read_open_memory2(a, data.as_ptr().cast(), data.len(), read_size), ARCHIVE_OK);
            assert_eq!(drain(a), data);
            assert_eq!(archive_free(a), ARCHIVE_OK);
        }
        let a = new();
        assert_eq!(archive_read_open_memory(a, data.as_ptr().cast(), data.len()), ARCHIVE_OK);
        assert_eq!(archive_free(a), ARCHIVE_OK);
        // An empty block is fine; a NULL block with a size is not.
        let a = new();
        assert_eq!(archive_read_open_memory(a, std::ptr::null(), 0), ARCHIVE_OK);
        assert_eq!(drain(a), b"");
        assert_eq!(archive_free(a), ARCHIVE_OK);
        let a = new();
        assert_eq!(archive_read_open_memory(a, std::ptr::null(), 5), ARCHIVE_FATAL);
        assert_eq!(error(a).as_deref(), Some("Invalid memory block"));
        assert_eq!(archive_free(a), ARCHIVE_OK);
    }

    #[test]
    fn opening_twice_names_the_first_callback() {
        let a = new();
        assert_eq!(archive_read_open_memory(a, b"x".as_ptr().cast(), 1), ARCHIVE_OK);
        assert_eq!(archive_read_open_memory(a, b"x".as_ptr().cast(), 1), ARCHIVE_FATAL);
        assert_eq!(
            error(a).as_deref(),
            Some("INTERNAL ERROR: Function 'archive_read_set_open_callback' invoked with archive structure in state 'header', should be in state 'new'")
        );
        assert_eq!(archive_free(a), ARCHIVE_OK);
    }

    #[test]
    fn open_fd_reads_a_file_descriptor() {
        use std::os::fd::AsRawFd;
        let p = temp("fd", 0, b"contents of a file");
        let f = std::fs::File::open(&p).unwrap();
        let a = new();
        assert_eq!(archive_read_open_fd(a, f.as_raw_fd(), 5), ARCHIVE_OK);
        assert_eq!(drain(a), b"contents of a file");
        assert_eq!(archive_free(a), ARCHIVE_OK);
        // A regular file is not to be overwritten by extraction.
        let a = new();
        archive_read_open_fd(a, f.as_raw_fd(), 5);
        assert!(with(a, false, |h| with_read(h, false, |r| r.skip_file().is_some())));
        assert_eq!(archive_free(a), ARCHIVE_OK);
        let a = new();
        assert_eq!(archive_read_open_fd(a, -1, 5), ARCHIVE_FATAL);
        assert_eq!(error(a).as_deref(), Some("Can't stat fd -1"));
        assert_eq!(archive_free(a), ARCHIVE_OK);
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn open_file_pointer_reads_a_stream() {
        let p = temp("file", 0, b"stream data");
        let path = c(&p);
        // SAFETY: both arguments are valid C strings.
        let file = unsafe { libc::fopen(path.as_ptr(), c"r".as_ptr()) };
        assert!(!file.is_null());
        let a = new();
        assert_eq!(archive_read_open_FILE(a, file), ARCHIVE_OK);
        assert_eq!(drain(a), b"stream data");
        assert_eq!(archive_free(a), ARCHIVE_OK);
        // SAFETY: the stream is open and no longer used.
        unsafe { libc::fclose(file) };
        let a = new();
        assert_eq!(archive_read_open_FILE(a, std::ptr::null_mut()), ARCHIVE_FATAL);
        assert_eq!(archive_free(a), ARCHIVE_OK);
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn open_filename_reads_a_file_and_names_failures() {
        let p = temp("name", 0, b"named file");
        let path = c(&p);
        let a = new();
        assert_eq!(archive_read_open_filename(a, path.as_ptr(), 10240), ARCHIVE_OK);
        assert_eq!(drain(a), b"named file");
        assert_eq!(archive_free(a), ARCHIVE_OK);
        let a = new();
        assert_eq!(archive_read_open_file(a, path.as_ptr(), 10240), ARCHIVE_OK);
        assert_eq!(archive_free(a), ARCHIVE_OK);

        let a = new();
        assert_eq!(archive_read_open_filename(a, c"/nonexistent/x".as_ptr(), 10240), ARCHIVE_FATAL);
        assert_eq!(error(a).as_deref(), Some("Failed to open '/nonexistent/x'"));
        assert_eq!(archive_free(a), ARCHIVE_OK);
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn open_filenames_reads_volumes_in_order() {
        let paths: Vec<_> = [&b"part one, "[..], b"part two, ", b"part three"]
            .iter()
            .enumerate()
            .map(|(i, d)| temp("multi", i, d))
            .collect();
        let cs: Vec<_> = paths.iter().map(|p| c(p)).collect();
        let mut list: Vec<*const c_char> = cs.iter().map(|s| s.as_ptr()).collect();
        list.push(std::ptr::null());
        let a = new();
        assert_eq!(archive_read_open_filenames(a, list.as_mut_ptr(), 10240), ARCHIVE_OK);
        assert_eq!(drain(a), b"part one, part two, part three");
        assert_eq!(archive_free(a), ARCHIVE_OK);

        // An empty name ends the list.
        list.insert(2, c"".as_ptr());
        let a = new();
        assert_eq!(archive_read_open_filenames(a, list.as_mut_ptr(), 10240), ARCHIVE_OK);
        assert_eq!(drain(a), b"part one, part two, ");
        assert_eq!(archive_free(a), ARCHIVE_OK);
        for p in paths {
            std::fs::remove_file(p).unwrap();
        }
    }

    #[test]
    fn open_filename_w_converts_the_name() {
        let p = temp("wide", 0, b"wide name");
        let wide: Vec<libc::wchar_t> = p
            .to_str()
            .unwrap()
            .chars()
            .map(|ch| ch as libc::wchar_t)
            .chain([0])
            .collect();
        let a = new();
        assert_eq!(archive_read_open_filename_w(a, wide.as_ptr(), 10240), ARCHIVE_OK);
        assert_eq!(drain(a), b"wide name");
        assert_eq!(archive_free(a), ARCHIVE_OK);
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn a_stream_in_error_records_it_and_ends() {
        let p = temp("filerr", 0, b"x");
        let path = c(&p);
        // Reading a stream opened for writing fails.
        // SAFETY: both arguments are valid C strings.
        let file = unsafe { libc::fopen(path.as_ptr(), c"w".as_ptr()) };
        assert!(!file.is_null());
        let a = new();
        assert_eq!(archive_read_open_FILE(a, file), ARCHIVE_OK);
        assert_eq!(drain(a), b"");
        assert_eq!(error(a).as_deref(), Some("Error reading file"));
        assert_eq!(archive_free(a), ARCHIVE_OK);
        // SAFETY: the stream is open and no longer used.
        unsafe { libc::fclose(file) };
        std::fs::remove_file(p).unwrap();
    }
}
