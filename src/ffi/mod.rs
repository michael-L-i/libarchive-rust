#![allow(unsafe_code)]
#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_void};
use std::marker::{PhantomData, PhantomPinned};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[macro_use]
mod archive;
pub(crate) mod client;
pub(crate) mod disk;
#[cfg(target_vendor = "apple")]
pub(crate) mod disk_acl;
#[cfg(any(target_os = "linux", test))]
pub(crate) mod disk_acl_linux;
pub(crate) mod disk_sys;
pub(crate) mod entry;
mod entry_link_resolver;
pub(crate) mod matching;
mod read;
mod read_open;
pub(crate) mod write;
mod write_filter;
#[rustfmt::skip]
mod stubs;
pub(crate) mod charset;
pub(crate) mod filter_fork;
pub(crate) mod qsort;
pub(crate) mod sys;
pub(crate) mod util;

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

pub use crate::archive::{ARCHIVE_FATAL, ARCHIVE_OK};

/// Runs `f`, returning `fallback` if it panics so panics never cross the C ABI.
pub fn guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}
