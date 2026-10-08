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
use std::ffi::{CStr, c_char, c_int};

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
