use crate::entry::{AE_IFREG, Entry};
use crate::read::{Data, Format, Reader, Status, format_code};
use crate::util::Error;
use std::ffi::c_int;

const EILSEQ: c_int = libc::EILSEQ;

/// A decimal or octal header field, space padded.
fn number(field: &[u8], radix: u32) -> Option<i64> {
    let text = std::str::from_utf8(field).ok()?.trim_end();
    i64::from_str_radix(text, radix).ok().filter(|n| *n >= 0)
}

#[derive(Default)]
pub struct Ar {
    started: bool,
    size: i64,
    remaining: i64,
    padding: i64,
}

impl Format for Ar {
    fn name(&self) -> &'static str {
        "ar"
    }

    // Peek, never consume; `?` passes read errors up. Short input is `None`.
    fn bid(&mut self, r: &mut Reader<'_>, _best_bid: c_int) -> Result<c_int, Error> {
        Ok(match r.read_ahead(8)? {
            Some(h) if h.starts_with(b"!<arch>\n") => 64,
            _ => 0,
        })
    }

    fn read_header(&mut self, r: &mut Reader<'_>, entry: &mut Entry) -> Result<Status, Error> {
        // Skip what the caller didn't read of the last entry.
        r.consume(std::mem::take(&mut self.remaining) + std::mem::take(&mut self.padding))?;
        if !self.started {
            r.consume(8)?;
            self.started = true;
        }

        // The handle does not borrow the reader, so it can be used while the
        // slice is held.
        let a = r.base();
        let Some(h) = r.read_ahead(60)? else {
            // Nothing at all is the end of the archive; part of a header is
            // a broken one.
            return if r.read_ahead(1)?.is_none() {
                Ok(Status::Eof)
            } else {
                Err(Error::fatal(EILSEQ, "Truncated ar archive"))
            };
        };
        let (Some(size), Some(mode), Some(mtime)) = (
            h.get(48..58).and_then(|f| number(f, 10)),
            h.get(40..48).and_then(|f| number(f, 8)),
            h.get(16..28).and_then(|f| number(f, 10)),
        ) else {
            return Err(Error::fatal(EILSEQ, "Bad number in ar header"));
        };
        if h.get(58..60) != Some(b"`\n") {
            return Err(Error::fatal(EILSEQ, "Incorrect file header signature"));
        }
        let name = h.get(..16).unwrap_or_default().trim_ascii_end();
        let nameless = name.is_empty();
        entry.set_pathname(name.strip_suffix(b"/").unwrap_or(name));
        a.set_format(format_code::AR, c"ar");

        entry.set_filetype(u32::from(AE_IFREG));
        entry.set_size(size);
        entry.set_perm(libc::mode_t::try_from(mode & 0o7777).unwrap_or(0o644));
        entry.set_mtime(mtime, 0);
        (self.size, self.remaining, self.padding) = (size, size, size & 1);
        r.consume(60)?;
        // A member that ends oddly is still usable: say so and carry on.
        Ok(if nameless {
            a.warn(EILSEQ, "ar member without a name")
        } else {
            Status::Ok
        })
    }

    fn read_data<'x>(&'x mut self, r: &'x mut Reader<'_>) -> Result<Data<'x>, Error> {
        if self.remaining == 0 {
            return Ok(Data::Eof { offset: self.size });
        }
        // The handle does not borrow the reader, so the slice can be returned
        // and still consumed: the core does it before the next call.
        let later = r.consume_later();
        let Some(data) = r.read_ahead(1)? else {
            return Err(Error::fatal(EILSEQ, "Truncated ar archive"));
        };
        let n = usize::try_from(self.remaining).map_or(data.len(), |left| left.min(data.len()));
        let offset = self.size - self.remaining;
        self.remaining -= i64::try_from(n).unwrap_or(0);
        later.consume(n);
        Ok(Data::Block {
            data: data.get(..n).unwrap_or_default(),
            offset,
        })
    }

    fn read_data_skip(&mut self, r: &mut Reader<'_>) -> Result<Status, Error> {
        r.consume(std::mem::take(&mut self.remaining))?;
        Ok(Status::Ok)
    }
}
