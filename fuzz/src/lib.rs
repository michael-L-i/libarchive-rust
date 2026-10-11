//! Shared harness: open `data` from memory with the given readers enabled,
//! walk every entry, read all its data and touch the getters the tools use.
#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_void};
use std::sync::Once;

pub use libfuzzer_sys;

extern crate libarchive_rust;

pub enum Archive {}
pub enum Entry {}

pub type Setup = unsafe extern "C" fn(*mut Archive) -> c_int;

unsafe extern "C" {
    fn archive_read_new() -> *mut Archive;
    fn archive_read_open_memory(a: *mut Archive, buf: *const c_void, n: usize) -> c_int;
    fn archive_read_next_header(a: *mut Archive, e: *mut *mut Entry) -> c_int;
    fn archive_read_data(a: *mut Archive, buf: *mut c_void, n: usize) -> isize;
    fn archive_read_close(a: *mut Archive) -> c_int;
    fn archive_read_free(a: *mut Archive) -> c_int;
    fn archive_error_string(a: *mut Archive) -> *const c_char;
    fn archive_entry_pathname(e: *mut Entry) -> *const c_char;
    fn archive_entry_size(e: *mut Entry) -> i64;
    fn archive_entry_mtime(e: *mut Entry) -> libc::time_t;
    fn archive_entry_mode(e: *mut Entry) -> u32;
    fn archive_entry_symlink(e: *mut Entry) -> *const c_char;
    fn archive_entry_hardlink(e: *mut Entry) -> *const c_char;
    fn archive_entry_uname(e: *mut Entry) -> *const c_char;
    fn archive_entry_gname(e: *mut Entry) -> *const c_char;

    pub fn archive_read_support_format_tar(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_zip(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_7zip(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_rar(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_rar5(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_iso9660(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_cab(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_lha(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_xar(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_cpio(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_ar(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_warc(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_mtree(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_raw(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_empty(a: *mut Archive) -> c_int;
    pub fn archive_read_support_format_all(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_all(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_gzip(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_bzip2(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_xz(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_lzma(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_lzip(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_zstd(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_lz4(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_compress(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_uu(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_lzop(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_rpm(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_grzip(a: *mut Archive) -> c_int;
    pub fn archive_read_support_filter_lrzip(a: *mut Archive) -> c_int;
}

/// Define a fuzz target that enables the named `archive_read_*` setups.
#[macro_export]
macro_rules! target {
    ($($setup:ident),+) => {
        $crate::libfuzzer_sys::fuzz_target!(|data: &[u8]| {
            $crate::run(data, &[$($crate::$setup),+])
        });
    };
}

pub fn run(data: &[u8], setups: &[Setup]) {
    static HOOK: Once = Once::new();
    // Exported functions swallow panics into ARCHIVE_FATAL; make them crashes.
    HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            eprintln!("panic: {info}");
            std::process::abort();
        }));
    });
    // SAFETY: `a` comes from archive_read_new and is freed once; `data`
    // outlives the handle; entry pointers are valid until the next header;
    // getter strings are NUL-terminated or null and only read here.
    unsafe {
        let a = archive_read_new();
        for s in setups {
            s(a);
        }
        if archive_read_open_memory(a, data.as_ptr().cast(), data.len()) == 0 {
            let mut buf = vec![0u8; 1 << 16];
            // Upstream has no output limit either: a tiny gzip can expand
            // through the 25 filter layers it may nest into without end, so
            // stop reading after 1 MiB of data.
            let mut budget: usize = 1 << 20;
            let mut e = std::ptr::null_mut();
            // ARCHIVE_OK 0, ARCHIVE_WARN -20 continue; RETRY -10 and FATAL -30 stop.
            while matches!(archive_read_next_header(a, &mut e), 0 | -20) {
                touch(e);
                loop {
                    let n = archive_read_data(a, buf.as_mut_ptr().cast(), buf.len());
                    budget = budget.saturating_sub(usize::try_from(n).unwrap_or(0));
                    if n <= 0 || budget == 0 {
                        break;
                    }
                }
                if budget == 0 {
                    break;
                }
            }
        }
        std::hint::black_box(archive_error_string(a));
        archive_read_close(a);
        archive_read_free(a);
    }
}

unsafe fn touch(e: *mut Entry) {
    // SAFETY: caller passes the live entry from archive_read_next_header.
    unsafe {
        for p in [
            archive_entry_pathname(e),
            archive_entry_symlink(e),
            archive_entry_hardlink(e),
            archive_entry_uname(e),
            archive_entry_gname(e),
        ] {
            if !p.is_null() {
                std::hint::black_box(std::ffi::CStr::from_ptr(p).to_bytes().len());
            }
        }
        std::hint::black_box((
            archive_entry_size(e),
            archive_entry_mtime(e),
            archive_entry_mode(e),
        ));
    }
}
