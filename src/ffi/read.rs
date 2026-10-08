//! The exported functions of archive_read.c and the files around it.

use super::archive::with;
use super::client::CClient;
use super::{
    ARCHIVE_FATAL, ARCHIVE_OK, Archive, archive_close_callback, archive_open_callback,
    archive_passphrase_callback, archive_read_callback, archive_seek_callback, archive_skip_callback, archive_switch_callback,
    guard,
};
use crate::archive::{Handle, Kind, READ_MAGIC, state};
use crate::read::filter::{
    all as filter_all, by_code as filter_by_code, compress, none as filter_none, uu as filter_uu,
};
use crate::read::format::{all as format_all, by_code as format_by_code, empty, raw};
use crate::read::{self, Read, Status};
use super::ArchiveEntry;
use super::sys::Fd;
use crate::entry::Entry;
use crate::archive::{ARCHIVE_EOF, ARCHIVE_WARN};
use crate::read::Data;
use crate::read_add_passphrase::PassphraseCallback;
use crate::util::Error;
use crate::{options, read_append_filter, read_data_into_fd, read_set_format, read_set_options};
use std::ffi::{CStr, c_char, c_int, c_uint, c_void};

/// Runs `f` on the read state of a handle that has passed its magic check.
/// A re-entrant call from a client callback finds the state in use and gets
/// `fallback`.
pub(super) fn with_read<T>(h: &Handle, fallback: T, f: impl FnOnce(&mut Read) -> T) -> T {
    match &h.kind {
        Kind::Read(r) => r.try_borrow_mut().map_or(fallback, |mut r| f(&mut r)),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_new() -> *mut Archive {
    guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(read::new())).cast()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_support_filter_none(a: *mut Archive) -> c_int {
    checked!(
        archive_read_support_filter_none,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |_h| filter_none::support()
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_support_compression_none(a: *mut Archive) -> c_int {
    archive_read_support_filter_none(a)
}

/// Registers a decompression filter's bidder: what the filter exports do.
fn support_filter(h: &Handle, support: fn(&mut Read) -> Result<Status, Error>) -> c_int {
    with_read(h, ARCHIVE_FATAL, |r| {
        support(r).map_or_else(|e| h.base.raise(e), |status| status.code())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_support_filter_compress(a: *mut Archive) -> c_int {
    checked!(
        archive_read_support_filter_compress,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| support_filter(h, compress::support)
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_support_compression_compress(a: *mut Archive) -> c_int {
    archive_read_support_filter_compress(a)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_support_filter_all(a: *mut Archive) -> c_int {
    checked!(
        archive_read_support_filter_all,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| filter_all::support(r, &h.base))
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_support_compression_all(a: *mut Archive) -> c_int {
    archive_read_support_filter_all(a)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_support_filter_uu(a: *mut Archive) -> c_int {
    checked!(
        archive_read_support_filter_uu,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| {
            filter_uu::support(r).map_or_else(|e| h.base.raise(e), |status| status.code())
        })
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_support_compression_uu(a: *mut Archive) -> c_int {
    archive_read_support_filter_uu(a)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_support_filter_by_code(a: *mut Archive, code: c_int) -> c_int {
    checked!(
        archive_read_support_filter_by_code,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| filter_by_code::support(r, code))
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_support_format_all(a: *mut Archive) -> c_int {
    checked!(
        archive_read_support_format_all,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| format_all::support(r, &h.base))
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_support_format_by_code(a: *mut Archive, code: c_int) -> c_int {
    checked!(
        archive_read_support_format_by_code,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| format_by_code::support(r, &h.base, code))
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_format(a: *mut Archive, code: c_int) -> c_int {
    // Upstream's first check is the one in support_format_by_code.
    checked!(
        archive_read_support_format_by_code,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| read_set_format::set_format(r, &h.base, code))
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_append_filter(a: *mut Archive, code: c_int) -> c_int {
    checked!(
        archive_read_append_filter,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| read_append_filter::append_filter(r, &h.base, code))
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_open_callback(a: *mut Archive, callback: archive_open_callback) -> c_int {
    checked!(archive_read_set_open_callback, a, READ_MAGIC, state::NEW, ARCHIVE_FATAL, |h| {
        with_read(h, ARCHIVE_FATAL, |r| {
            r.callbacks.opener = callback;
            ARCHIVE_OK
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_read_callback(a: *mut Archive, callback: archive_read_callback) -> c_int {
    checked!(archive_read_set_read_callback, a, READ_MAGIC, state::NEW, ARCHIVE_FATAL, |h| {
        with_read(h, ARCHIVE_FATAL, |r| {
            r.callbacks.reader = callback;
            ARCHIVE_OK
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_skip_callback(a: *mut Archive, callback: archive_skip_callback) -> c_int {
    checked!(archive_read_set_skip_callback, a, READ_MAGIC, state::NEW, ARCHIVE_FATAL, |h| {
        with_read(h, ARCHIVE_FATAL, |r| {
            r.callbacks.skipper = callback;
            ARCHIVE_OK
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_seek_callback(a: *mut Archive, callback: archive_seek_callback) -> c_int {
    checked!(archive_read_set_seek_callback, a, READ_MAGIC, state::NEW, ARCHIVE_FATAL, |h| {
        with_read(h, ARCHIVE_FATAL, |r| {
            r.callbacks.seeker = callback;
            ARCHIVE_OK
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_close_callback(a: *mut Archive, callback: archive_close_callback) -> c_int {
    checked!(archive_read_set_close_callback, a, READ_MAGIC, state::NEW, ARCHIVE_FATAL, |h| {
        with_read(h, ARCHIVE_FATAL, |r| {
            r.callbacks.closer = callback;
            ARCHIVE_OK
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_switch_callback(a: *mut Archive, callback: archive_switch_callback) -> c_int {
    checked!(archive_read_set_switch_callback, a, READ_MAGIC, state::NEW, ARCHIVE_FATAL, |h| {
        with_read(h, ARCHIVE_FATAL, |r| {
            r.callbacks.switcher = callback;
            ARCHIVE_OK
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_callback_data(a: *mut Archive, client_data: *mut c_void) -> c_int {
    archive_read_set_callback_data2(a, client_data, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_callback_data2(
    a: *mut Archive,
    client_data: *mut c_void,
    index: c_uint,
) -> c_int {
    checked!(
        archive_read_set_callback_data2,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| {
            let data = &mut r.callbacks.data;
            if data.is_empty() {
                data.push(std::ptr::null_mut());
            }
            match data.get_mut(index as usize) {
                Some(slot) => {
                    *slot = client_data;
                    ARCHIVE_OK
                }
                None => h.base.raise(Error::fatal(libc::EINVAL, "Invalid index specified")),
            }
        })
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_add_callback_data(
    a: *mut Archive,
    client_data: *mut c_void,
    index: c_uint,
) -> c_int {
    checked!(
        archive_read_add_callback_data,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| {
            let data = &mut r.callbacks.data;
            let index = index as usize;
            if index > data.len() {
                return h.base.raise(Error::fatal(libc::EINVAL, "Invalid index specified"));
            }
            if data.len() >= c_uint::MAX as usize || data.try_reserve(1).is_err() {
                return h.base.raise(Error::fatal(libc::ENOMEM, "No memory"));
            }
            data.insert(index, client_data);
            ARCHIVE_OK
        })
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_append_callback_data(a: *mut Archive, client_data: *mut c_void) -> c_int {
    // The number of nodes, which is where the new one goes.
    let nodes = with(a, 0, |h| {
        with_read(h, 0, |r| r.callbacks.data.len())
    });
    archive_read_add_callback_data(a, client_data, c_uint::try_from(nodes).unwrap_or(c_uint::MAX))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_prepend_callback_data(a: *mut Archive, client_data: *mut c_void) -> c_int {
    archive_read_add_callback_data(a, client_data, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_open1(a: *mut Archive) -> c_int {
    checked!(archive_read_open, a, READ_MAGIC, state::NEW, ARCHIVE_FATAL, |h| {
        with_read(h, ARCHIVE_FATAL, |r| {
            h.base.clear_error();
            if r.callbacks.reader.is_none() {
                h.base.set_error(
                    libc::EINVAL,
                    Some(b"No reader function provided to archive_read_open"),
                );
                h.base.state.set(state::FATAL);
                return ARCHIVE_FATAL;
            }
            let callbacks = std::mem::take(&mut r.callbacks);
            // SAFETY: `a` is this live handle, which owns the client; the C
            // caller registered the callbacks to be called with it.
            let client = unsafe { CClient::new(a, callbacks) };
            r.open(&h.base, Box::new(client))
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_open(
    a: *mut Archive,
    client_data: *mut c_void,
    client_opener: archive_open_callback,
    client_reader: archive_read_callback,
    client_closer: archive_close_callback,
) -> c_int {
    // Old archive_read_open() is just a thin shell around
    // archive_read_open1.
    archive_read_set_open_callback(a, client_opener);
    archive_read_set_read_callback(a, client_reader);
    archive_read_set_close_callback(a, client_closer);
    let r = archive_read_set_callback_data(a, client_data);
    if r < 0 {
        return r;
    }
    archive_read_open1(a)
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_open2(
    a: *mut Archive,
    client_data: *mut c_void,
    client_opener: archive_open_callback,
    client_reader: archive_read_callback,
    client_skipper: archive_skip_callback,
    client_closer: archive_close_callback,
) -> c_int {
    // Old archive_read_open2() is just a thin shell around
    // archive_read_open1.
    let r = archive_read_set_callback_data(a, client_data);
    if r < 0 {
        return r;
    }
    archive_read_set_open_callback(a, client_opener);
    archive_read_set_read_callback(a, client_reader);
    archive_read_set_skip_callback(a, client_skipper);
    archive_read_set_close_callback(a, client_closer);
    archive_read_open1(a)
}

/// Record the do-not-extract-to file. This belongs in archive_read_extract.c.
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_extract_set_skip_file(a: *mut Archive, dev: i64, ino: i64) {
    with(a, (), |h| {
        let name = "archive_read_extract_set_skip_file";
        if h.base.check_magic(READ_MAGIC, state::ANY, name) == ARCHIVE_OK {
            with_read(h, (), |r| r.skip_file = Some((dev, ino)));
        }
    });
}

/// The bytes of a C string, `None` for NULL.
fn cstr<'a>(p: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller passes NULL or a NUL-terminated string.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes())
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_format_option(
    a: *mut Archive,
    m: *const c_char,
    o: *const c_char,
    v: *const c_char,
) -> c_int {
    checked!(
        archive_read_set_format_option,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| {
            options::set_option(&h.base, cstr(m), cstr(o), cstr(v), &mut |m, o, v| {
                r.set_format_option(&h.base, m, o, v)
            })
        })
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_filter_option(
    a: *mut Archive,
    m: *const c_char,
    o: *const c_char,
    v: *const c_char,
) -> c_int {
    checked!(
        archive_read_set_filter_option,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| options::set_option(&h.base, cstr(m), cstr(o), cstr(v), &mut |m, _, _| {
            read_set_options::set_filter_option(m)
        })
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_option(
    a: *mut Archive,
    m: *const c_char,
    o: *const c_char,
    v: *const c_char,
) -> c_int {
    checked!(
        archive_read_set_option,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| {
            options::set_option(&h.base, cstr(m), cstr(o), cstr(v), &mut |m, o, v| {
                r.set_option(&h.base, m, o, v)
            })
        })
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_options(a: *mut Archive, opts: *const c_char) -> c_int {
    checked!(
        archive_read_set_options,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| {
            let opts = cstr(opts).unwrap_or_default();
            options::set_options(&h.base, opts, &mut |m, o, v| r.set_option(&h.base, m, o, v))
        })
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_add_passphrase(a: *mut Archive, passphrase: *const c_char) -> c_int {
    checked!(
        archive_read_add_passphrase,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| {
            match r.passphrases.add(cstr(passphrase).unwrap_or_default()) {
                Ok(()) => ARCHIVE_OK,
                Err(e) => h.base.raise(e),
            }
        })
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_set_passphrase_callback(
    a: *mut Archive,
    client_data: *mut c_void,
    callback: archive_passphrase_callback,
) -> c_int {
    checked!(
        archive_read_set_passphrase_callback,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| {
            r.passphrases.set_callback(callback.map(|callback| -> PassphraseCallback {
                Box::new(move || {
                    // SAFETY: the caller registered the callback to be called
                    // with this handle and data; the handle owns this
                    // closure.
                    let p = unsafe { callback(a, client_data) };
                    cstr(p).map(<[u8]>::to_vec)
                })
            }));
            ARCHIVE_OK
        })
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_header_position(a: *mut Archive) -> i64 {
    checked!(
        archive_read_header_position,
        a,
        READ_MAGIC,
        state::ANY,
        i64::from(ARCHIVE_FATAL),
        |h| h.header_position()
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_format_capabilities(a: *mut Archive) -> c_int {
    with(a, 0, |h| match &h.kind {
        Kind::Read(r) => r.try_borrow().map_or(0, |r| r.format_capabilities()),
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_has_encrypted_entries(a: *mut Archive) -> c_int {
    with(a, read::ENCRYPTION_UNSUPPORTED, |h| match &h.kind {
        Kind::Read(r) => r
            .try_borrow()
            .map_or(read::ENCRYPTION_UNSUPPORTED, |r| r.has_encrypted_entries()),
    })
}

/// Writes through an out pointer the caller may have left NULL.
fn put<T>(p: *mut T, value: T) {
    // SAFETY: the caller passes NULL or a valid, writable `T`.
    if let Some(out) = unsafe { p.as_mut() } {
        *out = value;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_data_block(
    a: *mut Archive,
    buff: *mut *const c_void,
    size: *mut usize,
    offset: *mut i64,
) -> c_int {
    checked!(
        archive_read_data_block,
        a,
        READ_MAGIC,
        state::DATA,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| {
            let block = r.read_data_block(&h.base, |data| match data {
                Data::Block { data, offset } => (data.as_ptr().cast(), data.len(), offset, ARCHIVE_OK),
                Data::Eof { offset } => (std::ptr::null(), 0, offset, ARCHIVE_EOF),
                Data::Warn => (std::ptr::null(), 0, 0, ARCHIVE_WARN),
            });
            match block {
                Ok((p, n, o, code)) => {
                    // The block stays valid until the next read.
                    put(buff, p);
                    put(size, n);
                    put(offset, o);
                    code
                }
                Err(code) => {
                    put(buff, std::ptr::null());
                    put(size, 0);
                    code
                }
            }
        })
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_data(a: *mut Archive, buff: *mut c_void, size: usize) -> isize {
    let fatal = ARCHIVE_FATAL as isize;
    with(a, fatal, |h| {
        if size == 0 {
            return 0;
        }
        // Upstream gets here by way of archive_read_data_block.
        let name = "archive_read_data_block";
        if h.base.check_magic(READ_MAGIC, state::DATA, name) == ARCHIVE_FATAL {
            return fatal;
        }
        if buff.is_null() || size > isize::MAX as usize {
            return fatal;
        }
        // SAFETY: the caller passes `size` writable bytes at `buff`.
        let dest = unsafe { std::slice::from_raw_parts_mut(buff.cast::<u8>(), size) };
        with_read(h, fatal, |r| r.read_data(&h.base, dest))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_data_skip(a: *mut Archive) -> c_int {
    checked!(
        archive_read_data_skip,
        a,
        READ_MAGIC,
        state::DATA | state::DATA_RECOVERY,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| r.read_data_skip(&h.base))
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_seek_data(a: *mut Archive, offset: i64, whence: c_int) -> i64 {
    checked!(
        archive_seek_data_block,
        a,
        READ_MAGIC,
        state::DATA,
        i64::from(ARCHIVE_FATAL),
        |h| with_read(h, i64::from(ARCHIVE_FATAL), |r| r.seek_data(&h.base, offset, whence))
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_data_into_fd(a: *mut Archive, fd: c_int) -> c_int {
    checked!(
        archive_read_data_into_fd,
        a,
        READ_MAGIC,
        state::DATA,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| read_data_into_fd::data_into_fd(r, &h.base, Fd(fd)))
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_next_header2(a: *mut Archive, entry: *mut ArchiveEntry) -> c_int {
    checked!(
        archive_read_next_header,
        a,
        READ_MAGIC,
        state::HEADER | state::DATA | state::DATA_RECOVERY,
        ARCHIVE_FATAL,
        |h| {
            // SAFETY: `entry` is NULL or a live entry the caller owns, which
            // nothing else uses during the call.
            match unsafe { entry.cast::<Entry>().as_mut() } {
                Some(entry) => h.read_next_header2(entry),
                None => ARCHIVE_FATAL,
            }
        }
    )
}

/// Reads the next header into the handle's own entry and returns it, even
/// when the header failed.
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_next_header(a: *mut Archive, entryp: *mut *mut ArchiveEntry) -> c_int {
    put(entryp, std::ptr::null_mut());
    let r = checked!(
        archive_read_next_header,
        a,
        READ_MAGIC,
        state::HEADER | state::DATA | state::DATA_RECOVERY,
        ARCHIVE_FATAL,
        |h| {
            // SAFETY: the handle's entry is a live `Box` leak, only used
            // through this pointer and the ones handed to the caller.
            match unsafe { h.read_entry().as_mut() } {
                Some(e) => h.read_next_header2(e),
                None => ARCHIVE_FATAL,
            }
        }
    );
    // The entry comes back even when the header does not.
    put(entryp, with(a, std::ptr::null_mut(), |h| h.read_entry().cast()));
    r
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_support_format_raw(a: *mut Archive) -> c_int {
    checked!(
        archive_read_support_format_raw,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| {
            raw::support(r).map_or_else(|e| h.base.raise(e), |status| status.code())
        })
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_support_format_empty(a: *mut Archive) -> c_int {
    checked!(
        archive_read_support_format_empty,
        a,
        READ_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| with_read(h, ARCHIVE_FATAL, |r| {
            empty::support(r).map_or_else(|e| h.base.raise(e), |status| status.code())
        })
    )
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::ffi::archive::{archive_error_string, archive_free};
    use std::ffi::CStr;

    pub(in crate::ffi) fn error(a: *mut Archive) -> Option<String> {
        let p = archive_error_string(a);
        // SAFETY: the library returns NULL or a NUL-terminated string.
        (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }

    #[test]
    fn support_functions_check_the_state_and_enable_what_is_ported() {
        let a = archive_read_new();
        assert_eq!(archive_read_support_filter_none(a), ARCHIVE_OK);
        assert_eq!(archive_read_support_compression_none(a), ARCHIVE_OK);
        assert_eq!(archive_read_support_filter_all(a), ARCHIVE_OK);
        assert_eq!(archive_read_support_compression_all(a), ARCHIVE_OK);
        assert_eq!(archive_read_support_format_all(a), ARCHIVE_OK);
        assert_eq!(error(a), None);
        // Nothing is ported yet to register by code; a bad code is reported.
        assert_eq!(archive_read_support_format_by_code(a, 0x7777_0000), ARCHIVE_FATAL);
        assert_eq!(error(a).as_deref(), Some("Invalid format code specified"));
        assert_eq!(archive_read_support_filter_by_code(a, 0), ARCHIVE_OK);
        assert_eq!(archive_read_support_filter_by_code(a, 99), ARCHIVE_FATAL);
        assert_eq!(archive_read_set_format(a, 0x7777_0000), ARCHIVE_FATAL);
        assert_eq!(archive_read_append_filter(a, 0), ARCHIVE_OK);
        assert_eq!(archive_free(a), ARCHIVE_OK);

        // Once the archive has left the NEW state, they fail.
        let a = archive_read_new();
        crate::ffi::archive::with(a, (), |h| h.base.state.set(state::HEADER));
        assert_eq!(archive_read_support_filter_all(a), ARCHIVE_FATAL);
        assert_eq!(
            error(a).as_deref(),
            Some("INTERNAL ERROR: Function 'archive_read_support_filter_all' invoked with archive structure in state 'header', should be in state 'new'")
        );
        assert_eq!(archive_free(a), ARCHIVE_OK);
        assert_eq!(archive_read_support_format_all(std::ptr::null_mut()), ARCHIVE_FATAL);
    }

    use crate::read::{Data, Format, Reader, Status};
    use crate::util::Error as Err_;

    /// A format that bids on anything, for tests that only open.
    struct Anything;

    impl Format for Anything {
        fn name(&self) -> &'static str {
            "anything"
        }

        fn bid(&mut self, _: &mut Reader<'_>, _: c_int) -> Result<c_int, Error> {
            Ok(1)
        }

        fn options(
            &mut self,
            _: &crate::archive::Base,
            key: &[u8],
            _: Option<&[u8]>,
        ) -> Option<Result<Status, Err_>> {
            Some(Ok(if key == b"flag" { Status::Ok } else { Status::Warn }))
        }

        fn read_header(&mut self, _: &mut Reader<'_>, _: &mut Entry) -> Result<Status, Err_> {
            Ok(Status::Eof)
        }

        fn read_data<'x>(&'x mut self, _: &'x mut Reader<'_>) -> Result<Data<'x>, Err_> {
            Ok(Data::Eof { offset: 0 })
        }
    }

    pub(in crate::ffi) fn register_anything(a: *mut Archive) {
        with(a, (), |h| {
            with_read(h, (), |r| {
                assert_eq!(r.register_format(Box::new(Anything)).unwrap(), Status::Ok);
            });
        });
    }

    /// Everything the chain will give, three bytes at a time at most.
    pub(in crate::ffi) fn drain(a: *mut Archive) -> Vec<u8> {
        let mut out = Vec::new();
        with(a, (), |h| {
            with_read(h, (), |r| {
                let mut rd = r.reader(&h.base);
                loop {
                    let n = {
                        let block = rd.peek_available(1).unwrap();
                        out.extend_from_slice(block);
                        block.len()
                    };
                    if n == 0 {
                        return;
                    }
                    rd.consume(n).unwrap();
                }
            });
        });
        out
    }

    /// One volume: a slice, how far it has been read and how often it was
    /// closed.
    struct Volume {
        data: &'static [u8],
        pos: usize,
        closed: usize,
    }

    fn volume(data: &'static [u8]) -> *mut c_void {
        Box::into_raw(Box::new(Volume { data, pos: 0, closed: 0 })).cast()
    }

    fn closed(volume: *mut c_void) -> usize {
        // SAFETY: a `volume()` pointer, leaked by the tests.
        unsafe { (*volume.cast::<Volume>()).closed }
    }

    unsafe extern "C" fn read_volume(
        _: *mut Archive,
        client_data: *mut c_void,
        buff: *mut *const c_void,
    ) -> isize {
        // SAFETY: the tests pass a `volume()` pointer that nothing else uses.
        let v = unsafe { &mut *client_data.cast::<Volume>() };
        let n = (v.data.len() - v.pos).min(3);
        // SAFETY: `buff` is the out pointer the library passes.
        unsafe { *buff = v.data[v.pos..].as_ptr().cast() };
        v.pos += n;
        n as isize
    }

    /// Like upstream, the core closes a volume when it moves on from it
    /// and again when the archive closes, so this must not free anything.
    unsafe extern "C" fn close_volume(_: *mut Archive, client_data: *mut c_void) -> c_int {
        // SAFETY: a `volume()` pointer that nothing else is using.
        unsafe { (*client_data.cast::<Volume>()).closed += 1 };
        ARCHIVE_OK
    }

    unsafe extern "C" fn no_data(_: *mut Archive, _: *mut c_void, _: *mut *const c_void) -> isize {
        -1
    }

    #[test]
    fn c_callbacks_read_and_close() {
        let a = archive_read_new();
        register_anything(a);
        assert_eq!(archive_read_set_read_callback(a, Some(read_volume)), ARCHIVE_OK);
        assert_eq!(archive_read_set_close_callback(a, Some(close_volume)), ARCHIVE_OK);
        let v = volume(b"hello, world");
        assert_eq!(archive_read_set_callback_data(a, v), ARCHIVE_OK);
        assert_eq!(archive_read_open1(a), ARCHIVE_OK);
        assert_eq!(with(a, 0, |h| h.base.state.get()), state::HEADER);
        assert_eq!(drain(a), b"hello, world");
        assert_eq!(closed(v), 0);
        assert_eq!(crate::ffi::archive::archive_read_close(a), ARCHIVE_OK);
        assert_eq!(closed(v), 1);
        assert_eq!(archive_free(a), ARCHIVE_OK);
        assert_eq!(closed(v), 1);
    }

    #[test]
    fn open_without_a_reader_is_fatal() {
        let a = archive_read_new();
        assert_eq!(archive_read_open1(a), ARCHIVE_FATAL);
        assert_eq!(
            error(a).as_deref(),
            Some("No reader function provided to archive_read_open")
        );
        assert_eq!(with(a, 0, |h| h.base.state.get()), state::FATAL);
        assert_eq!(archive_free(a), ARCHIVE_OK);
    }

    #[test]
    fn a_failing_reader_makes_open_fail() {
        let a = archive_read_new();
        register_anything(a);
        assert_eq!(archive_read_open(a, std::ptr::null_mut(), None, Some(no_data), None), ARCHIVE_FATAL);
        assert_eq!(with(a, 0, |h| h.base.state.get()), state::FATAL);
        assert_eq!(archive_free(a), ARCHIVE_OK);
    }

    #[test]
    fn callback_data_nodes_are_read_in_order() {
        let a = archive_read_new();
        register_anything(a);
        assert_eq!(archive_read_set_read_callback(a, Some(read_volume)), ARCHIVE_OK);
        assert_eq!(archive_read_set_close_callback(a, Some(close_volume)), ARCHIVE_OK);
        // Out-of-range indexes are refused.
        assert_eq!(archive_read_add_callback_data(a, volume(b""), 1), ARCHIVE_FATAL);
        assert_eq!(error(a).as_deref(), Some("Invalid index specified"));
        let (first, second, third) = (volume(b"first-"), volume(b"second"), volume(b"-third"));
        assert_eq!(archive_read_set_callback_data(a, second), ARCHIVE_OK);
        assert_eq!(archive_read_prepend_callback_data(a, first), ARCHIVE_OK);
        assert_eq!(archive_read_append_callback_data(a, third), ARCHIVE_OK);
        assert_eq!(archive_read_set_callback_data2(a, volume(b"-last"), 3), ARCHIVE_FATAL);
        assert_eq!(archive_read_open1(a), ARCHIVE_OK);
        assert_eq!(drain(a), b"first-second-third");
        assert_eq!(archive_free(a), ARCHIVE_OK);
        // Volumes are closed on moving on, and all of them on closing.
        assert_eq!([closed(first), closed(second), closed(third)], [2, 2, 1]);
    }

    static REENTRANT: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

    /// Asks the handle about itself from inside the close callback, which
    /// runs with the read state borrowed.
    unsafe extern "C" fn close_and_ask(a: *mut Archive, _: *mut c_void) -> c_int {
        use crate::ffi::archive::*;
        let answers = [
            i64::from(archive_filter_count(a)),
            i64::from(archive_filter_code(a, 0)),
            archive_filter_bytes(a, 0),
            archive_position_compressed(a),
            archive_read_header_position(a),
            i64::from(archive_filter_name(a, 0).is_null()),
        ];
        REENTRANT.store(
            i64::from(answers.iter().all(|&r| r == i64::from(ARCHIVE_FATAL) || r == 1)),
            std::sync::atomic::Ordering::SeqCst,
        );
        ARCHIVE_OK
    }

    #[test]
    fn getters_called_from_callbacks_fall_back_instead_of_panicking() {
        let a = archive_read_new();
        register_anything(a);
        assert_eq!(archive_read_set_read_callback(a, Some(read_volume)), ARCHIVE_OK);
        assert_eq!(archive_read_set_close_callback(a, Some(close_and_ask)), ARCHIVE_OK);
        assert_eq!(archive_read_set_callback_data(a, volume(b"data")), ARCHIVE_OK);
        assert_eq!(archive_read_open1(a), ARCHIVE_OK);
        // Outside a callback the getters work.
        assert_eq!(crate::ffi::archive::archive_filter_count(a), 1);
        assert_eq!(archive_free(a), ARCHIVE_OK);
        assert_eq!(REENTRANT.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn options_reach_formats_and_report_unknown_names() {
        let a = new_with_format();
        let opt = |m: &CStr, o: &CStr, v: Option<&CStr>| {
            archive_read_set_option(a, m.as_ptr(), o.as_ptr(), v.map_or(std::ptr::null(), CStr::as_ptr))
        };
        assert_eq!(opt(c"anything", c"flag", Some(c"1")), ARCHIVE_OK);
        assert_eq!(opt(c"", c"flag", None), ARCHIVE_OK);
        assert_eq!(opt(c"nomod", c"flag", None), crate::archive::ARCHIVE_FAILED);
        assert_eq!(error(a).as_deref(), Some("Unknown module name: `nomod'"));
        assert_eq!(archive_read_set_options(a, c"anything:flag,!flag,flag=2".as_ptr()), ARCHIVE_OK);
        assert_eq!(
            archive_read_set_options(a, c"anything:bad".as_ptr()),
            crate::archive::ARCHIVE_FAILED
        );
        assert_eq!(error(a).as_deref(), Some("Undefined option: `anything:bad'"));
        assert_eq!(archive_read_set_options(a, std::ptr::null()), ARCHIVE_OK);
        assert_eq!(
            archive_read_set_filter_option(a, c"gzip".as_ptr(), c"x".as_ptr(), std::ptr::null()),
            crate::archive::ARCHIVE_FAILED
        );
        assert_eq!(error(a).as_deref(), Some("Unknown module name: `gzip'"));
        assert_eq!(
            archive_read_set_format_option(a, std::ptr::null(), c"flag".as_ptr(), std::ptr::null()),
            ARCHIVE_OK
        );
        assert_eq!(archive_free(a), ARCHIVE_OK);
    }

    fn opened() -> *mut Archive {
        let a = new_with_format();
        assert_eq!(crate::ffi::read_open::archive_read_open_memory(a, b"x".as_ptr().cast(), 1), ARCHIVE_OK);
        a
    }

    fn new_with_format() -> *mut Archive {
        let a = archive_read_new();
        register_anything(a);
        a
    }

    unsafe extern "C" fn offer(_: *mut Archive, data: *mut c_void) -> *const c_char {
        data.cast::<c_char>().cast_const()
    }

    #[test]
    fn passphrases_are_listed_and_asked_for() {
        let a = new_with_format();
        assert_eq!(
            archive_read_add_passphrase(a, c"".as_ptr()),
            crate::archive::ARCHIVE_FAILED
        );
        assert_eq!(error(a).as_deref(), Some("Empty passphrase is unacceptable"));
        assert_eq!(archive_read_add_passphrase(a, c"one".as_ptr()), ARCHIVE_OK);
        assert_eq!(
            archive_read_set_passphrase_callback(a, c"two".as_ptr().cast_mut().cast(), Some(offer)),
            ARCHIVE_OK
        );
        let mut got = Vec::new();
        with(a, (), |h| {
            with_read(h, (), |r| {
                r.passphrases.reset();
                while let Some(p) = r.passphrases.next() {
                    got.push(String::from_utf8_lossy(&p).into_owned());
                    if got.len() > 5 {
                        break;
                    }
                }
            });
        });
        // The list first, then the callback's, once; then it is offered
        // again from the list.
        assert_eq!(got[..2], ["one", "two"]);
        assert_eq!(archive_free(a), ARCHIVE_OK);
    }

    #[test]
    fn data_functions_check_the_state_and_dispatch_to_the_format() {
        let a = new_with_format();
        let mut buf = [0u8; 8];
        let (mut p, mut n, mut off) = (std::ptr::null(), 1usize, 5i64);
        // Not in the data state yet.
        assert_eq!(archive_read_data_block(a, &mut p, &mut n, &mut off), ARCHIVE_FATAL);
        assert!(error(a).is_some_and(|e| e.contains("archive_read_data_block")));
        let a = opened();
        with(a, (), |h| h.base.state.set(state::DATA));
        assert_eq!(archive_read_data(a, buf.as_mut_ptr().cast(), 0), 0);
        assert_eq!(archive_read_data(a, buf.as_mut_ptr().cast(), buf.len()), 0);
        assert_eq!(
            archive_read_data_block(a, &mut p, &mut n, &mut off),
            crate::archive::ARCHIVE_EOF
        );
        assert_eq!((p.is_null(), n, off), (true, 0, 0));
        assert_eq!(archive_seek_data(a, 0, 0), i64::from(crate::archive::ARCHIVE_FAILED));
        assert_eq!(error(a).as_deref(), Some("Cannot seek data with this format"));
        // A bad whence is the format's to judge.
        assert_eq!(archive_seek_data(a, 0, 77), i64::from(crate::archive::ARCHIVE_FAILED));
        let a = opened();
        with(a, (), |h| h.base.state.set(state::DATA));
        assert_eq!(archive_read_data_skip(a), ARCHIVE_OK);
        assert_eq!(with(a, 0, |h| h.base.state.get()), state::HEADER);
        assert_eq!(archive_read_data_skip(a), ARCHIVE_FATAL);
        assert_eq!(archive_free(a), ARCHIVE_OK);
    }

    #[test]
    fn next_header_returns_the_handles_entry() {
        let a = opened();
        let mut e: *mut ArchiveEntry = std::ptr::null_mut();
        assert_eq!(archive_read_next_header(a, &mut e), crate::archive::ARCHIVE_EOF);
        assert!(!e.is_null());
        assert_eq!(with(a, 0, |h| h.base.state.get()), state::EOF);
        // Wrong state now.
        assert_eq!(archive_read_next_header(a, &mut e), ARCHIVE_FATAL);
        assert!(!e.is_null());
        assert_eq!(archive_free(a), ARCHIVE_OK);

        let a = opened();
        let own = crate::ffi::entry::archive_entry_new2(a);
        assert_eq!(archive_read_next_header2(a, own), crate::archive::ARCHIVE_EOF);
        assert_eq!(archive_read_next_header2(a, std::ptr::null_mut()), ARCHIVE_FATAL);
        crate::ffi::entry::archive_entry_free(own);
        assert_eq!(archive_free(a), ARCHIVE_OK);
    }

    #[test]
    fn raw_makes_one_entry_of_any_input() {
        let a = archive_read_new();
        assert_eq!(archive_read_support_format_raw(a), ARCHIVE_OK);
        let data = b"some raw bytes".repeat(10);
        assert_eq!(
            crate::ffi::read_open::archive_read_open_memory2(a, data.as_ptr().cast(), data.len(), 7),
            ARCHIVE_OK
        );
        let mut e: *mut ArchiveEntry = std::ptr::null_mut();
        assert_eq!(archive_read_next_header(a, &mut e), ARCHIVE_OK);
        let name = crate::ffi::entry::archive_entry_pathname(e);
        // SAFETY: the library returns a NUL-terminated string.
        assert_eq!(unsafe { CStr::from_ptr(name) }, c"data");
        assert_eq!(crate::ffi::entry::archive_entry_perm(e), 0o644);
        let mut buf = vec![0u8; 200];
        assert_eq!(archive_read_data(a, buf.as_mut_ptr().cast(), buf.len()), data.len() as isize);
        assert_eq!(&buf[..data.len()], &data[..]);
        assert_eq!(archive_read_next_header(a, &mut e), crate::archive::ARCHIVE_EOF);
        assert_eq!(crate::ffi::archive::archive_format(a), 0x90000);
        assert_eq!(archive_free(a), ARCHIVE_OK);
    }

    #[test]
    fn empty_input_has_no_entries() {
        let a = archive_read_new();
        assert_eq!(archive_read_support_format_all(a), ARCHIVE_OK);
        assert_eq!(archive_read_support_format_raw(a), ARCHIVE_OK);
        assert_eq!(crate::ffi::read_open::archive_read_open_memory(a, std::ptr::null(), 0), ARCHIVE_OK);
        let mut e: *mut ArchiveEntry = std::ptr::null_mut();
        assert_eq!(archive_read_next_header(a, &mut e), crate::archive::ARCHIVE_EOF);
        assert_eq!(crate::ffi::archive::archive_format(a), 0x60000);
        assert_eq!(archive_free(a), ARCHIVE_OK);
    }

    unsafe extern "C" fn null_buffer(_: *mut Archive, _: *mut c_void, _: *mut *const c_void) -> isize {
        3
    }

    #[test]
    fn a_reader_returning_bytes_without_a_buffer_is_fatal() {
        let a = archive_read_new();
        register_anything(a);
        assert_eq!(
            archive_read_open(a, std::ptr::null_mut(), None, Some(null_buffer), None),
            ARCHIVE_FATAL
        );
        assert_eq!(error(a).as_deref(), Some("Read callback returned a NULL buffer"));
        assert_eq!(archive_free(a), ARCHIVE_OK);
    }
}
