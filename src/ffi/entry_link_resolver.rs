//! The exported functions of archive_entry_link_resolver.c.
//!
//! A `struct archive_entry_linkresolver *` is a leaked `Box<LinkResolver>`.
//! The resolver owns the entries it keeps as `Box<Entry>`. C passes an entry
//! to `archive_entry_linkify` through a pointer slot and gets the entries
//! the resolver gives back through the same slots, so an entry is never
//! reachable from both sides at once.

use super::entry::put;
use super::{ArchiveEntry, ArchiveEntryLinkresolver, guard};
use crate::entry::Entry;
use crate::entry_link_resolver::LinkResolver;
use std::ffi::{c_int, c_uint};

/// The entry a C pointer leaks, or NULL.
fn into_c(e: Option<Box<Entry>>) -> *mut ArchiveEntry {
    e.map_or(std::ptr::null_mut(), |e| Box::into_raw(e).cast())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_entry_linkresolver_new() -> *mut ArchiveEntryLinkresolver {
    guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(LinkResolver::new())).cast()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_entry_linkresolver_set_strategy(
    res: *mut ArchiveEntryLinkresolver,
    fmt: c_int,
) {
    guard((), || {
        // SAFETY: `res` is NULL or a resolver leaked by
        // `archive_entry_linkresolver_new`, which the caller uses alone.
        if let Some(res) = unsafe { res.cast::<LinkResolver>().as_mut() } {
            res.set_strategy(fmt);
        }
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_entry_linkresolver_free(res: *mut ArchiveEntryLinkresolver) {
    if !res.is_null() {
        // SAFETY: `res` is a live resolver and the caller gives it up. Its
        // held entries are freed with it.
        guard((), || {
            drop(unsafe { Box::from_raw(res.cast::<LinkResolver>()) })
        });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_entry_linkify(
    res: *mut ArchiveEntryLinkresolver,
    e: *mut *mut ArchiveEntry,
    f: *mut *mut ArchiveEntry,
) {
    guard((), || {
        put(f, std::ptr::null_mut());
        // SAFETY: `e` is NULL or a slot holding NULL or an entry leaked by
        // an `archive_entry_*` constructor, which the caller gives up here.
        let Some(slot) = (unsafe { e.as_mut() }) else {
            return;
        };
        // SAFETY: `res` is NULL or a live resolver, as above.
        let Some(res) = (unsafe { res.cast::<LinkResolver>().as_mut() }) else {
            return;
        };
        let p = std::mem::replace(slot, std::ptr::null_mut());
        let input = (!p.is_null()).then(|| {
            // SAFETY: `p` is the leaked entry the slot held, now owned here.
            unsafe { Box::from_raw(p.cast::<Entry>()) }
        });
        let (out_e, out_f) = res.linkify(input);
        *slot = into_c(out_e);
        put(f, into_c(out_f));
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_entry_partial_links(
    res: *mut ArchiveEntryLinkresolver,
    links: *mut c_uint,
) -> *mut ArchiveEntry {
    guard(std::ptr::null_mut(), || {
        // SAFETY: `res` is NULL or a live resolver, as above.
        let (e, n) = match unsafe { res.cast::<LinkResolver>().as_mut() } {
            Some(res) => res.partial_links(),
            None => (None, 0),
        };
        put(links, n);
        into_c(e)
    })
}
