//! The C callbacks of `archive_read_open`, behind the read core's `Client`
//! trait. This is the one place client callbacks are called.

use super::{
    Archive, archive_close_callback, archive_open_callback, archive_read_callback,
    archive_seek_callback, archive_skip_callback, archive_switch_callback,
};
use crate::archive::*;
use crate::read::{Client, Whence, worse};
use crate::util::Error;
use std::ffi::{c_int, c_void};

/// What `archive_read_set_*_callback` and `archive_read_set_callback_data`
/// have collected before the archive is opened.
#[derive(Default)]
pub struct Callbacks {
    pub opener: archive_open_callback,
    pub reader: archive_read_callback,
    pub skipper: archive_skip_callback,
    pub seeker: archive_seek_callback,
    pub closer: archive_close_callback,
    pub switcher: archive_switch_callback,
    /// The client data of each node (volume).
    pub data: Vec<*mut c_void>,
}

/// A `Client` that calls the C callbacks.
pub struct CClient {
    /// The handle the callbacks are called with. It outlives the client,
    /// which the handle owns.
    archive: *mut Archive,
    callbacks: Callbacks,
    /// The block the reader callback returned last.
    block: (*const u8, usize),
}

/// The `ARCHIVE_*` status of a callback that returned `r`, for a callback
/// that has recorded its own error.
fn failure(r: i64) -> Error {
    Error::status(c_int::try_from(r).unwrap_or(ARCHIVE_FATAL))
}

fn status(r: c_int) -> Result<(), Error> {
    if r == ARCHIVE_OK {
        Ok(())
    } else {
        Err(failure(r.into()))
    }
}

impl CClient {
    /// A client for `callbacks`, calling them with `archive`. Needs a
    /// reader.
    ///
    /// # Safety
    ///
    /// `archive` must point to the handle that owns the client, and every
    /// callback in `callbacks` must be safe to call with it and its data, as
    /// the C caller promised by registering it.
    pub unsafe fn new(archive: *mut Archive, callbacks: Callbacks) -> CClient {
        CClient {
            archive,
            callbacks,
            block: (std::ptr::null(), 0),
        }
    }

    fn data(&self, node: usize) -> *mut c_void {
        self.callbacks
            .data
            .get(node)
            .copied()
            .unwrap_or(std::ptr::null_mut())
    }
}

fn whence_c(whence: Whence) -> c_int {
    match whence {
        Whence::Set => libc::SEEK_SET,
        Whence::Cur => libc::SEEK_CUR,
        Whence::End => libc::SEEK_END,
    }
}

impl Client for CClient {
    fn nodes(&self) -> usize {
        self.callbacks.data.len().max(1)
    }

    fn open(&mut self, node: usize) -> Result<(), Error> {
        let Some(opener) = self.callbacks.opener else {
            return Ok(());
        };
        // SAFETY: `new`'s contract.
        status(unsafe { opener(self.archive, self.data(node)) })
    }

    fn read(&mut self, node: usize) -> Result<(), Error> {
        let Some(reader) = self.callbacks.reader else {
            return Err(Error::status(ARCHIVE_FATAL));
        };
        let mut buff = std::ptr::null();
        // SAFETY: `new`'s contract.
        let n = unsafe { reader(self.archive, self.data(node), &mut buff) };
        match usize::try_from(n) {
            Ok(n) => {
                self.block = if buff.is_null() { (buff.cast(), 0) } else { (buff.cast(), n) };
                Ok(())
            }
            Err(_) => {
                self.block = (std::ptr::null(), 0);
                Err(Error::status(ARCHIVE_FATAL))
            }
        }
    }

    fn block(&self) -> &[u8] {
        let (ptr, len) = self.block;
        if ptr.is_null() {
            return &[];
        }
        // SAFETY: the reader callback promised `len` readable bytes at `ptr`
        // until its next call, and `read` replaces `block` before any next
        // call; `&self` keeps the client from calling it meanwhile.
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    fn can_skip(&self) -> bool {
        self.callbacks.skipper.is_some()
    }

    fn skip(&mut self, node: usize, request: i64) -> Result<i64, Error> {
        let Some(skipper) = self.callbacks.skipper else {
            return Ok(0);
        };
        // SAFETY: `new`'s contract.
        let skipped = unsafe { skipper(self.archive, self.data(node), request) };
        if skipped < 0 {
            return Err(failure(i64::from(ARCHIVE_FATAL)));
        }
        Ok(skipped)
    }

    fn can_seek(&self) -> bool {
        self.callbacks.seeker.is_some()
    }

    fn seek(&mut self, node: usize, offset: i64, whence: Whence) -> Result<i64, Error> {
        let Some(seeker) = self.callbacks.seeker else {
            return Err(Error::status(ARCHIVE_FAILED));
        };
        // SAFETY: `new`'s contract.
        let r = unsafe { seeker(self.archive, self.data(node), offset, whence_c(whence)) };
        if r < 0 { Err(failure(r)) } else { Ok(r) }
    }

    fn close(&mut self, node: usize) -> Result<(), Error> {
        let Some(closer) = self.callbacks.closer else {
            return Ok(());
        };
        // SAFETY: `new`'s contract.
        status(unsafe { closer(self.archive, self.data(node)) })
    }

    fn switch(&mut self, from: usize, to: usize) -> Result<(), Error> {
        let Some(switcher) = self.callbacks.switcher else {
            // Attempt to call close and open instead.
            let closed = self.close(from);
            let opened = self.open(to);
            return worse(closed, opened);
        };
        // SAFETY: `new`'s contract.
        status(unsafe { switcher(self.archive, self.data(from), self.data(to)) })
    }
}
