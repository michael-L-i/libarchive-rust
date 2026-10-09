//! The exported functions every kind of handle answers: errors, formats,
//! versions and the vtable dispatch of archive_virtual.c.
//!
//! Each exported function is a thin shell around safe Rust: `with` or
//! `checked` does the shared prologue, and the closure converts arguments,
//! calls into the crate and converts the result back. A returned
//! `const char *` points into storage owned by the handle (or a static) and
//! stays valid until that field changes or the handle is freed.

use super::{ARCHIVE_FATAL, ARCHIVE_OK, Archive, guard};
use crate::archive::{Handle, READ_MAGIC, state};
use crate::util::{VERSION_NUMBER, VERSION_STRING};
use crate::version_details as vd;
use std::ffi::{CStr, c_char, c_int, c_void};

/// The prologue shared by every exported function that takes a handle: reject
/// NULL, then run `f` on the handle under `guard`, so a panic becomes
/// `fallback` instead of crossing the C ABI.
///
/// `f` gets a `&Handle`, never a `&mut`: a client callback running inside
/// can call back into the same handle (see `Base`).
pub(super) fn with<T: Copy>(a: *mut Archive, fallback: T, f: impl FnOnce(&Handle) -> T) -> T {
    guard(fallback, || {
        // SAFETY: `a` is NULL or a handle leaked by a `archive_*_new`
        // function, and it is only ever borrowed shared.
        unsafe { a.cast::<Handle>().as_ref() }.map_or(fallback, f)
    })
}

/// `with`, preceded by `__archive_check_magic`: if the handle is not of kind
/// `magic` in one of `states`, record the error and return `fallback`. The
/// function name in the error message is taken from `$name`.
macro_rules! checked {
    ($name:ident, $a:expr, $magic:expr, $states:expr, $fallback:expr, |$h:ident| $body:expr) => {
        with($a, $fallback, |$h| {
            if $h.base.check_magic($magic, $states, stringify!($name)) == ARCHIVE_FATAL {
                return $fallback;
            }
            $body
        })
    };
}

/// The `(buff, size)` pair of a C data argument. `None` if it cannot be a
/// slice.
pub(super) fn bytes<'a>(buff: *const c_void, size: usize) -> Option<&'a [u8]> {
    if size == 0 {
        return Some(&[]);
    }
    if buff.is_null() || size > isize::MAX as usize {
        return None;
    }
    // SAFETY: the caller promises `size` readable bytes at `buff`.
    Some(unsafe { std::slice::from_raw_parts(buff.cast(), size) })
}

pub(super) fn cptr(s: Option<&CStr>) -> *const c_char {
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
    with(a, 0, |h| h.base.errno.get())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_error_string(a: *mut Archive) -> *const c_char {
    with(a, std::ptr::null(), |h| {
        h.base
            .error_string()
            .map_or(std::ptr::null(), |m| m.as_ptr().cast())
    })
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
    with(a, 0, |h| h.base.file_count.get())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_format(a: *mut Archive) -> c_int {
    with(a, 0, |h| h.base.format.get())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_format_name(a: *mut Archive) -> *const c_char {
    with(a, std::ptr::null(), |h| match h.base.format_name.get() {
        Some(name) => name.as_ptr(),
        None => {
            let buf = h.base.format_name_buf.borrow();
            if buf.is_empty() {
                std::ptr::null()
            } else {
                buf.as_ptr().cast()
            }
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_compression(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.filter_code(0))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_compression_name(a: *mut Archive) -> *const c_char {
    with(a, std::ptr::null(), |h| h.filter_name(0))
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
    with(a, std::ptr::null(), |h| h.filter_name(n))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_filter_bytes(a: *mut Archive, n: c_int) -> i64 {
    with(a, i64::from(ARCHIVE_FATAL), |h| h.filter_bytes(n))
}

/// `archive_free`: checks the handle as its kind's free function does, then
/// closes it and drops it. The handle is borrowed, not owned, while it
/// closes: client callbacks run on it and may use it.
#[unsafe(no_mangle)]
pub extern "C" fn archive_free(a: *mut Archive) -> c_int {
    if a.is_null() {
        return ARCHIVE_OK;
    }
    guard(ARCHIVE_FATAL, || {
        // SAFETY: `a` is a live handle, only ever borrowed shared.
        let h = unsafe { &*a.cast::<Handle>() };
        // Only read handles exist so far.
        let states = state::ANY | state::FATAL;
        if h.base.check_magic(READ_MAGIC, states, "archive_read_free") == ARCHIVE_FATAL {
            return ARCHIVE_FATAL;
        }
        let r = h.free();
        let entry = h.take_read_entry();
        // SAFETY: the entry is a `Box` leak that only this handle owned, and
        // nothing refers to it or the handle any more; the caller gives up
        // ownership of the handle.
        unsafe {
            if !entry.is_null() {
                drop(Box::from_raw(entry));
            }
            drop(Box::from_raw(a.cast::<Handle>()));
        }
        r
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
    checked!(
        archive_read_close,
        a,
        READ_MAGIC,
        state::ANY | state::FATAL,
        ARCHIVE_FATAL,
        |h| h.close()
    )
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
        bytes(buff, size).map_or(ARCHIVE_FATAL as isize, |b| h.write_data(b))
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
        bytes(buff, size).map_or(ARCHIVE_FATAL as isize, |b| h.write_data_block(b, offset))
    })
}

// The version of each backend, NULL if it is not compiled in. There are no C
// XML, regex or crypto backends here, so those are always NULL.

#[unsafe(no_mangle)]
pub extern "C" fn archive_version_details() -> *const c_char {
    vd::details().as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_zlib_version() -> *const c_char {
    cptr(vd::zlib())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_liblzma_version() -> *const c_char {
    cptr(vd::liblzma())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_bzlib_version() -> *const c_char {
    cptr(vd::bzlib())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_liblz4_version() -> *const c_char {
    cptr(vd::liblz4())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_libzstd_version() -> *const c_char {
    cptr(vd::libzstd())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_liblzo2_version() -> *const c_char {
    cptr(vd::LIBLZO2)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_librichacl_version() -> *const c_char {
    cptr(vd::LIBRICHACL)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_libacl_version() -> *const c_char {
    cptr(vd::LIBACL)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_libattr_version() -> *const c_char {
    cptr(vd::LIBATTR)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_libiconv_version() -> *const c_char {
    cptr(vd::LIBICONV)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_libexpat_version() -> *const c_char {
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_libbsdxml_version() -> *const c_char {
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_libxml2_version() -> *const c_char {
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_xmllite_version() -> *const c_char {
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_mbedtls_version() -> *const c_char {
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_nettle_version() -> *const c_char {
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_openssl_version() -> *const c_char {
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_libmd_version() -> *const c_char {
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_commoncrypto_version() -> *const c_char {
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_cng_version() -> *const c_char {
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_wincrypt_version() -> *const c_char {
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_libpcre_version() -> *const c_char {
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_libpcre2_version() -> *const c_char {
    std::ptr::null()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::read::archive_read_new;

    unsafe extern "C" {
        fn archive_set_error(a: *mut Archive, errno: c_int, fmt: *const c_char, ...);
    }

    fn string(p: *const c_char) -> Option<String> {
        // SAFETY: the tests only pass pointers the library returned.
        (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }

    #[test]
    fn a_formatted_format_name_is_rewritten_in_place() {
        let a = archive_read_new();
        assert_eq!(string(archive_format_name(a)), None);
        let set = |name: &[u8]| with(a, (), |h| h.base.set_format_name(name));
        set(b"CAB 1.3 (NONE)");
        let first = archive_format_name(a);
        assert_eq!(string(first).as_deref(), Some("CAB 1.3 (NONE)"));
        // A pointer handed out earlier still reads the current name.
        set(b"CAB 1.3 (LZX)\0junk");
        assert_eq!(archive_format_name(a), first);
        assert_eq!(string(first).as_deref(), Some("CAB 1.3 (LZX)"));
        // A static name takes over, and the buffer stays readable.
        with(a, (), |h| h.base.set_format(0x60000, c"lha"));
        assert_eq!(string(archive_format_name(a)).as_deref(), Some("lha"));
        assert_eq!(string(first).as_deref(), Some("CAB 1.3 (LZX)"));
        assert_eq!(archive_free(a), ARCHIVE_OK);
    }

    #[test]
    fn set_error_formats_and_reports() {
        let a = archive_read_new();
        assert_eq!(string(archive_error_string(a)), None);
        // SAFETY: `a` is a live handle and the format matches its arguments.
        unsafe { archive_set_error(a, 22, c"bad %s #%d".as_ptr(), c"entry".as_ptr(), 7 as c_int) };
        assert_eq!(archive_errno(a), 22);
        assert_eq!(
            string(archive_error_string(a)).as_deref(),
            Some("bad entry #7")
        );

        let b = archive_read_new();
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
        assert_eq!(archive_free(a), ARCHIVE_OK);
        assert_eq!(archive_free(b), ARCHIVE_OK);
    }

    #[test]
    fn error_string_pointer_survives_clear_and_shorter_messages() {
        let a = archive_read_new();
        // SAFETY: `a` is a live handle and the formats take no arguments.
        unsafe { archive_set_error(a, 1, c"a long first message".as_ptr()) };
        let p = archive_error_string(a);
        archive_clear_error(a);
        // Like upstream, the buffer is emptied in place, not freed.
        assert_eq!(string(p).as_deref(), Some(""));
        // SAFETY: as above.
        unsafe { archive_set_error(a, 1, c"short".as_ptr()) };
        assert_eq!(archive_error_string(a), p);
        assert_eq!(string(p).as_deref(), Some("short"));
        assert_eq!(archive_free(a), ARCHIVE_OK);
    }

    #[test]
    fn read_handle_lifecycle() {
        let a = archive_read_new();
        assert!(!a.is_null());
        assert_eq!((archive_filter_count(a), archive_compression(a)), (0, -1));
        assert_eq!(string(archive_compression_name(a)), None);
        assert_eq!(archive_position_compressed(a), -1);
        archive_clear_error(a);
        assert_eq!(archive_read_close(a), ARCHIVE_OK);
        assert_eq!(archive_read_close(a), ARCHIVE_OK);
        assert_eq!(archive_write_fail(a), state::FATAL as c_int);
        assert_eq!(archive_read_free(a), ARCHIVE_OK);

        let b = archive_read_new();
        assert_eq!(archive_free(b), ARCHIVE_OK);
    }

    #[test]
    fn bad_arguments_are_rejected() {
        let a = archive_read_new();
        let byte = 0u8;
        let p = std::ptr::from_ref(&byte).cast();
        assert_eq!(archive_write_data(a, p, usize::MAX), ARCHIVE_FATAL as isize);
        assert_eq!(
            archive_write_data(a, std::ptr::null(), 1),
            ARCHIVE_FATAL as isize
        );
        assert_eq!(archive_free(a), ARCHIVE_OK);

        let null = std::ptr::null_mut();
        assert_eq!(archive_free(null), ARCHIVE_OK);
        assert_eq!(archive_filter_count(null), ARCHIVE_FATAL);
        assert_eq!(archive_read_close(null), ARCHIVE_FATAL);
        assert_eq!(archive_errno(null), 0);
        assert_eq!(string(archive_error_string(null)), None);
    }

    #[test]
    fn versions() {
        assert_eq!(archive_version_number(), 3009000);
        let s = string(archive_version_string()).unwrap_or_default();
        assert!(string(archive_version_details()).is_some_and(|d| d.starts_with(&s)));
        for v in [
            archive_zlib_version(),
            archive_liblzma_version(),
            archive_bzlib_version(),
            archive_liblz4_version(),
            archive_libzstd_version(),
        ] {
            assert!(string(v).is_some());
        }
        assert_eq!(string(archive_liblzo2_version()), None);
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
