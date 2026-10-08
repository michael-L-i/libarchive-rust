//! Drives a decompression filter as the read core does: a stream read through
//! the filter and the raw format, its one entry's data read back.

use crate::archive::{ARCHIVE_OK, Base, READ_MAGIC};
use crate::entry::Entry;
use crate::read::format::raw;
use crate::read::{Client, Read, Status};
use crate::util::Error;

/// A client over `data` that hands out `block` bytes per read.
struct Blocks {
    data: Vec<u8>,
    pos: usize,
    block: usize,
    out: Vec<u8>,
}

impl Client for Blocks {
    fn read(&mut self, _a: &Base, _node: usize) -> Result<(), Error> {
        let end = self.pos.saturating_add(self.block).min(self.data.len());
        self.out = self.data.get(self.pos..end).unwrap_or_default().to_vec();
        self.pos = end;
        Ok(())
    }

    fn block(&self) -> &[u8] {
        &self.out
    }
}

/// The handle's error message, or the empty string.
fn message(a: &Base) -> String {
    a.error_string()
        .map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned())
}

/// What `data` decodes to through `support`'s filter, with the client
/// delivering `block` bytes at a time; or the error message the handle
/// reports.
pub fn decode(
    support: fn(&mut Read) -> Result<Status, Error>,
    data: &[u8],
    block: usize,
) -> Result<Vec<u8>, String> {
    decode_with_message(support, data, block).0
}

/// `decode`, and the message the handle holds once the stream is open. Upstream
/// keeps a message set while opening until the first header is read, which
/// clears it.
pub fn decode_with_message(
    support: fn(&mut Read) -> Result<Status, Error>,
    data: &[u8],
    block: usize,
) -> (Result<Vec<u8>, String>, String) {
    let a = Base::new(READ_MAGIC);
    let mut r = Read::default();
    assert_eq!(support(&mut r).expect("filter registers"), Status::Ok);
    assert_eq!(raw::support(&mut r).expect("raw format registers"), Status::Ok);
    let client = Blocks {
        data: data.to_vec(),
        pos: 0,
        block,
        out: Vec::new(),
    };
    let opened = r.open(&a, Box::new(client)) == ARCHIVE_OK;
    let open_message = message(&a);
    let result = if opened {
        read_all(&mut r, &a)
    } else {
        Err(open_message.clone())
    };
    (result, open_message)
}

/// Reads the one entry's data to the end.
fn read_all(r: &mut Read, a: &Base) -> Result<Vec<u8>, String> {
    let mut entry = Entry::new(None);
    if r.next_header2(a, &mut entry) != ARCHIVE_OK {
        return Err(message(a));
    }
    let mut out = Vec::new();
    let mut buf = vec![0; 1 << 16];
    loop {
        match r.read_data(a, &mut buf) {
            0 => return Ok(out),
            n if n < 0 => return Err(message(a)),
            n => out.extend_from_slice(buf.get(..n as usize).unwrap_or_default()),
        }
    }
}
