//! libarchive's C ABI. The exported functions live in `libarchive_rust`'s
//! `ffi` module; this crate links them into `libarchive.{so,dylib,a}` with
//! `variadic.c`, a formatting shim retained for the minimum Rust 1.95 compiler:
//! `archive_set_error`, which takes printf-style arguments. Rust programs
//! use `libarchive_rust` directly and contain no C.

extern crate libarchive_rust;

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)]

    use std::ffi::{CStr, c_char, c_int, c_void};

    unsafe extern "C" {
        fn archive_read_new() -> *mut c_void;
        fn archive_free(a: *mut c_void) -> c_int;
        fn archive_errno(a: *mut c_void) -> c_int;
        fn archive_error_string(a: *mut c_void) -> *const c_char;
        fn archive_set_error(a: *mut c_void, errno: c_int, fmt: *const c_char, ...);
    }

    fn error(a: *mut c_void) -> (c_int, Option<String>) {
        // SAFETY: `a` is a live handle; the string is NULL or NUL-terminated.
        unsafe {
            let p = archive_error_string(a);
            let msg = (!p.is_null()).then(|| CStr::from_ptr(p).to_string_lossy().into_owned());
            (archive_errno(a), msg)
        }
    }

    #[test]
    fn set_error_formats_its_arguments() {
        // SAFETY: `a` is a live handle and each format matches its arguments.
        unsafe {
            let a = archive_read_new();
            archive_set_error(a, 22, c"bad %s #%d".as_ptr(), c"entry".as_ptr(), 7 as c_int);
            assert_eq!(error(a), (22, Some("bad entry #7".into())));
            archive_set_error(a, 5, std::ptr::null());
            assert_eq!(error(a), (5, None));
            assert_eq!(archive_free(a), 0);
        }
    }
}
