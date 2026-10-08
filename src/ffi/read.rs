//! The exported functions of archive_read.c.

use super::{Archive, guard};
use crate::read;

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_new() -> *mut Archive {
    guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(read::new())).cast()
    })
}
