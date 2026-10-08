#![allow(unsafe_code)]
#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_void};
use std::marker::{PhantomData, PhantomPinned};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[rustfmt::skip]
mod stubs;

macro_rules! opaque {
    ($($name:ident),*) => {$(
        #[repr(C)]
        pub struct $name {
            _data: [u8; 0],
            _marker: PhantomData<(*mut u8, PhantomPinned)>,
        }
    )*};
}

opaque!(Archive, ArchiveEntry, ArchiveEntryLinkresolver, ArchiveAcl);

pub type archive_read_callback =
    Option<unsafe extern "C" fn(*mut Archive, *mut c_void, *mut *const c_void) -> isize>;
pub type archive_skip_callback =
    Option<unsafe extern "C" fn(*mut Archive, *mut c_void, i64) -> i64>;
pub type archive_seek_callback =
    Option<unsafe extern "C" fn(*mut Archive, *mut c_void, i64, c_int) -> i64>;
pub type archive_write_callback =
    Option<unsafe extern "C" fn(*mut Archive, *mut c_void, *const c_void, usize) -> isize>;
pub type archive_open_callback = Option<unsafe extern "C" fn(*mut Archive, *mut c_void) -> c_int>;
pub type archive_close_callback = Option<unsafe extern "C" fn(*mut Archive, *mut c_void) -> c_int>;
pub type archive_free_callback = Option<unsafe extern "C" fn(*mut Archive, *mut c_void) -> c_int>;
pub type archive_switch_callback =
    Option<unsafe extern "C" fn(*mut Archive, *mut c_void, *mut c_void) -> c_int>;
pub type archive_passphrase_callback =
    Option<unsafe extern "C" fn(*mut Archive, *mut c_void) -> *const c_char>;

pub const ARCHIVE_EOF: c_int = 1;
pub const ARCHIVE_OK: c_int = 0;
pub const ARCHIVE_RETRY: c_int = -10;
pub const ARCHIVE_WARN: c_int = -20;
pub const ARCHIVE_FAILED: c_int = -25;
pub const ARCHIVE_FATAL: c_int = -30;

/// Called by `archive_set_error` in variadic.c with the formatted message.
#[unsafe(no_mangle)]
pub extern "C" fn __archive_rs_set_error(
    _a: *mut Archive,
    _error_number: c_int,
    _msg: *const c_char,
) {
}

/// Runs `f`, returning `fallback` if it panics so panics never cross the C ABI.
#[allow(dead_code)]
pub fn guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}
