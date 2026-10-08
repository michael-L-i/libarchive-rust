//! The exported functions of archive_read.c and the files around it.

use super::archive::with;
use super::client::CClient;
use super::{
    ARCHIVE_FATAL, ARCHIVE_OK, Archive, archive_close_callback, archive_open_callback,
    archive_read_callback, archive_seek_callback, archive_skip_callback, archive_switch_callback,
    guard,
};
use crate::archive::{Handle, Kind, READ_MAGIC, state};
use crate::read::filter::{all as filter_all, by_code as filter_by_code, none as filter_none};
use crate::read::format::{all as format_all, by_code as format_by_code};
use crate::read::{self, Read};
use crate::{read_append_filter, read_set_format};
use crate::util::Error;
use std::ffi::{c_int, c_uint, c_void};

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

    use crate::read::{Data, Entry, Format, Reader};
    use crate::util::Error as Err_;

    /// A format that bids on anything, for tests that only open.
    struct Anything;

    impl Format for Anything {
        fn name(&self) -> &'static str {
            "anything"
        }

        fn bid(&mut self, _: &mut Reader<'_>, _: c_int) -> c_int {
            1
        }

        fn read_header(&mut self, _: &mut Reader<'_>, _: &mut Entry) -> Result<(), Err_> {
            Err(Err_::status(crate::archive::ARCHIVE_EOF))
        }

        fn read_data<'x>(&'x mut self, _: &'x mut Reader<'_>) -> Result<Data<'x>, Err_> {
            Ok(Data::Eof { offset: 0 })
        }
    }

    pub(in crate::ffi) fn register_anything(a: *mut Archive) {
        with(a, (), |h| {
            with_read(h, (), |r| r.register_format(Box::new(Anything)).unwrap());
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
                        let block = rd.read_ahead(1).unwrap();
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
}
