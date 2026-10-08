//! The exported functions every kind of handle answers: errors, formats,
//! versions and the vtable dispatch of archive_virtual.c.
//!
//! Each exported function is a thin shell around safe Rust: `with` or
//! `checked` does the shared prologue, and the closure converts arguments,
//! calls into the crate and converts the result back. A returned
//! `const char *` points into storage owned by the handle (or a static) and
//! stays valid until that field changes or the handle is freed.

use super::{ARCHIVE_FATAL, ARCHIVE_OK, Archive, guard};
use crate::archive::Handle;
use crate::util::{VERSION_NUMBER, VERSION_STRING};
use std::ffi::{CStr, c_char, c_int, c_void};

/// The prologue shared by every exported function that takes a handle: reject
/// NULL, then run `f` on the handle under `guard`, so a panic becomes
/// `fallback` instead of crossing the C ABI.
pub(super) fn with<T: Copy>(a: *mut Archive, fallback: T, f: impl FnOnce(&mut Handle) -> T) -> T {
    guard(fallback, || {
        // SAFETY: `a` is NULL or a handle leaked by a `archive_*_new`
        // function; as in C, the caller must not use it concurrently.
        unsafe { a.cast::<Handle>().as_mut() }.map_or(fallback, f)
    })
}

/// `with`, preceded by `__archive_check_magic`: if the handle is not of kind
/// `magic` in one of `states`, record the error and return `fallback`.
#[allow(dead_code)] // The first user is archive_read_new's family in phase 1d.
pub(super) fn checked<T: Copy>(
    a: *mut Archive,
    magic: u32,
    states: u32,
    func: &str,
    fallback: T,
    f: impl FnOnce(&mut Handle) -> T,
) -> T {
    with(a, fallback, |h| {
        if h.base.check_magic(magic, states, func) == ARCHIVE_FATAL {
            return fallback;
        }
        f(h)
    })
}

/// The `(buff, size)` pair of a C data argument.
fn bytes<'a>(buff: *const c_void, size: usize) -> &'a [u8] {
    if buff.is_null() {
        return &[];
    }
    // SAFETY: the caller promises `size` readable bytes at `buff`.
    unsafe { std::slice::from_raw_parts(buff.cast(), size) }
}

fn cptr(s: Option<&CStr>) -> *const c_char {
    s.map_or(std::ptr::null(), CStr::as_ptr)
}

/// Called by `archive_set_error` in variadic.c with the formatted message.
#[unsafe(no_mangle)]
pub extern "C" fn __archive_rs_set_error(a: *mut Archive, error_number: c_int, msg: *const c_char) {
    with(a, (), |h| {
        // SAFETY: variadic.c passes NULL or a NUL-terminated string.
        let msg = (!msg.is_null()).then(|| unsafe { CStr::from_ptr(msg) });
        h.base.set_error(error_number, msg.map(CStr::to_bytes));
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_version_number() -> c_int {
    VERSION_NUMBER
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_version_string() -> *const c_char {
    VERSION_STRING.as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_errno(a: *mut Archive) -> c_int {
    with(a, 0, |h| h.base.errno)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_error_string(a: *mut Archive) -> *const c_char {
    with(a, std::ptr::null(), |h| cptr(h.base.error_string()))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_clear_error(a: *mut Archive) {
    with(a, (), |h| h.base.clear_error());
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_copy_error(dest: *mut Archive, src: *mut Archive) {
    if dest != src {
        with(dest, (), |d| with(src, (), |s| d.base.copy_error(&s.base)));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_file_count(a: *mut Archive) -> c_int {
    with(a, 0, |h| h.base.file_count)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_format(a: *mut Archive) -> c_int {
    with(a, 0, |h| h.base.format)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_format_name(a: *mut Archive) -> *const c_char {
    with(a, std::ptr::null(), |h| cptr(h.base.format_name))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_compression(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.filter_code(0))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_compression_name(a: *mut Archive) -> *const c_char {
    with(a, std::ptr::null(), |h| cptr(h.filter_name(0)))
}

/// Number of compressed bytes processed.
#[unsafe(no_mangle)]
pub extern "C" fn archive_position_compressed(a: *mut Archive) -> i64 {
    with(a, i64::from(ARCHIVE_FATAL), |h| h.filter_bytes(-1))
}

/// Number of uncompressed bytes processed.
#[unsafe(no_mangle)]
pub extern "C" fn archive_position_uncompressed(a: *mut Archive) -> i64 {
    with(a, i64::from(ARCHIVE_FATAL), |h| h.filter_bytes(0))
}

/// Sorts a NULL-terminated array of strings.
#[unsafe(no_mangle)]
pub extern "C" fn archive_utility_string_sort(strings: *mut *mut c_char) -> c_int {
    guard(ARCHIVE_FATAL, || {
        if strings.is_null() {
            return ARCHIVE_FATAL;
        }
        // SAFETY: the caller passes a NULL-terminated array.
        let len = (0..)
            .take_while(|&i| unsafe { !(*strings.add(i)).is_null() })
            .count();
        // SAFETY: the `len` entries before the terminator are valid.
        let strings = unsafe { std::slice::from_raw_parts_mut(strings, len) };
        // SAFETY: each entry is a valid NUL-terminated string.
        strings.sort_unstable_by(|&a, &b| unsafe { CStr::from_ptr(a).cmp(CStr::from_ptr(b)) });
        ARCHIVE_OK
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_filter_code(a: *mut Archive, n: c_int) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.filter_code(n))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_filter_count(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.filter_count())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_filter_name(a: *mut Archive, n: c_int) -> *const c_char {
    with(a, std::ptr::null(), |h| cptr(h.filter_name(n)))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_filter_bytes(a: *mut Archive, n: c_int) -> i64 {
    with(a, i64::from(ARCHIVE_FATAL), |h| h.filter_bytes(n))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_free(a: *mut Archive) -> c_int {
    if a.is_null() {
        return ARCHIVE_OK;
    }
    guard(ARCHIVE_FATAL, || {
        // SAFETY: `a` is a live handle and the caller gives up ownership.
        unsafe { Box::from_raw(a.cast::<Handle>()) }.free()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_free(a: *mut Archive) -> c_int {
    archive_free(a)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_finish(a: *mut Archive) -> c_int {
    archive_free(a)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_write_free(a: *mut Archive) -> c_int {
    archive_free(a)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_write_finish(a: *mut Archive) -> c_int {
    archive_free(a)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_close(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.close())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_write_close(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.close())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_write_fail(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.write_fail())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_write_finish_entry(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.write_finish_entry())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_write_data(a: *mut Archive, buff: *const c_void, size: usize) -> isize {
    with(a, ARCHIVE_FATAL as isize, |h| {
        h.write_data(bytes(buff, size))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_write_data_block(
    a: *mut Archive,
    buff: *const c_void,
    size: usize,
    offset: i64,
) -> isize {
    with(a, ARCHIVE_FATAL as isize, |h| {
        h.write_data_block(bytes(buff, size), offset)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ARCHIVE_WARN, Base};
    use crate::archive::{Kind, Ops, READ_MAGIC, WRITE_MAGIC, state};
    use std::ffi::c_char;

    unsafe extern "C" {
        fn archive_set_error(a: *mut Archive, errno: c_int, fmt: *const c_char, ...);
    }

    struct Fake;

    impl Ops for Fake {
        fn close(&mut self, _a: &mut Base) -> c_int {
            ARCHIVE_OK
        }
        fn free(&mut self, _a: &mut Base) -> c_int {
            ARCHIVE_WARN
        }
        fn filter_count(&self) -> c_int {
            1
        }
        fn filter_code(&self, n: c_int) -> c_int {
            n + 5
        }
        fn filter_name(&self, _n: c_int) -> Option<&CStr> {
            Some(c"fake")
        }
    }

    fn new_handle(magic: u32) -> *mut Archive {
        let h = Handle::new(magic, Kind::Test(Box::new(Fake)));
        Box::into_raw(Box::new(h)).cast()
    }

    fn string(p: *const c_char) -> Option<String> {
        // SAFETY: the tests only pass pointers the library returned.
        (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }

    #[test]
    fn set_error_formats_and_reports() {
        let a = new_handle(READ_MAGIC);
        assert_eq!(string(archive_error_string(a)), None);
        // SAFETY: `a` is a live handle and the format matches its arguments.
        unsafe { archive_set_error(a, 22, c"bad %s #%d".as_ptr(), c"entry".as_ptr(), 7 as c_int) };
        assert_eq!(archive_errno(a), 22);
        assert_eq!(
            string(archive_error_string(a)).as_deref(),
            Some("bad entry #7")
        );

        let b = new_handle(READ_MAGIC);
        archive_copy_error(b, a);
        assert_eq!(
            string(archive_error_string(b)).as_deref(),
            Some("bad entry #7")
        );
        archive_clear_error(a);
        assert_eq!(
            (archive_errno(a), string(archive_error_string(a))),
            (0, None)
        );
        // SAFETY: as above, with no message.
        unsafe { archive_set_error(b, 5, std::ptr::null()) };
        assert_eq!(
            (archive_errno(b), string(archive_error_string(b))),
            (5, None)
        );
        assert_eq!(archive_free(a), ARCHIVE_WARN);
        assert_eq!(archive_free(b), ARCHIVE_WARN);
    }

    #[test]
    fn dispatch_and_null_handles() {
        let a = new_handle(WRITE_MAGIC);
        assert_eq!(archive_filter_count(a), 1);
        assert_eq!(archive_compression(a), 5);
        assert_eq!(string(archive_compression_name(a)).as_deref(), Some("fake"));
        assert_eq!(archive_write_fail(a), state::FATAL as c_int);
        assert_eq!(archive_write_free(a), ARCHIVE_WARN);

        let null = std::ptr::null_mut();
        assert_eq!(archive_free(null), ARCHIVE_OK);
        assert_eq!(archive_filter_count(null), ARCHIVE_FATAL);
        assert_eq!(archive_errno(null), 0);
        assert_eq!(string(archive_error_string(null)), None);
    }

    #[test]
    fn string_sort_orders_bytes() {
        let mut v = [c"pear", c"apple", c"Zed", c"apple pie"].map(|s| s.as_ptr().cast_mut());
        let mut list = v.to_vec();
        list.push(std::ptr::null_mut());
        assert_eq!(archive_utility_string_sort(list.as_mut_ptr()), ARCHIVE_OK);
        v.sort_by_key(|&p| string(p));
        assert_eq!(&list[..4], &v);
        assert!(list[4].is_null());
        assert_eq!(string(list[0]).as_deref(), Some("Zed"));
    }
}
