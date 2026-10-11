/*-
 * Copyright (c) 2007 Kai Wang
 * Copyright (c) 2007 Tim Kientzle
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Ported from libarchive/archive_write_set_format_ar.c.
use crate::archive::*;
use crate::entry::Entry;
use crate::util::Error;
use crate::write::{Format, Sink};
use std::ffi::{CStr, c_int};
pub struct Ar {
    bsd: bool,
    global: bool,
    remaining: u64,
    padding: bool,
    strtab: Option<Vec<u8>>,
    is_strtab: bool,
}
impl Ar {
    pub fn new(bsd: bool) -> Self {
        Self {
            bsd,
            global: false,
            remaining: 0,
            padding: false,
            strtab: None,
            is_strtab: false,
        }
    }
}
/// format_decimal and format_octal: left-justified in a field of spaces.
/// Whether the value fits; a field that doesn't is never written out.
fn format_number(out: &mut [u8], v: i64, octal: bool) -> bool {
    let s = if octal {
        format!("{v:o}")
    } else {
        v.to_string()
    };
    if v < 0 || s.len() > out.len() {
        return false;
    }
    out[..s.len()].copy_from_slice(s.as_bytes());
    true
}
impl Format for Ar {
    fn code(&self) -> c_int {
        if self.bsd { 0x70002 } else { 0x70001 }
    }
    fn name(&self) -> &'static CStr {
        if self.bsd {
            c"ar (BSD)"
        } else {
            c"ar (GNU/SVR4)"
        }
    }
    fn module(&self) -> &'static [u8] {
        b"ar"
    }
    fn header(&mut self, a: &Base, e: &mut Entry, sink: &mut dyn Sink) -> Result<c_int, Error> {
        // Upstream rejects a member by setting the error and returning
        // ARCHIVE_WARN, which leaves the previous member's byte counts in
        // place for the data and finish calls that follow.
        let warn = |errno: c_int, msg: &str| {
            a.set_error(errno, Some(msg.as_bytes()));
            Ok(ARCHIVE_WARN)
        };
        self.is_strtab = false;
        let mut size = e.size();
        // Reject files with empty name.
        let pathname = e
            .pathname()
            .map(|s| s.to_bytes().to_vec())
            .unwrap_or_default();
        if pathname.is_empty() {
            return warn(libc::EINVAL, "Invalid filename");
        }
        // If we are now at the beginning of the archive, we have to write
        // the ar global header first.
        if !self.global {
            sink.write(b"!<arch>\n")?;
            self.global = true;
        }
        let mut buff = [b' '; 60];
        buff[58..].copy_from_slice(b"`\n");
        let mut append = None;
        match pathname.as_slice() {
            // Archive symbol tables in GNU, GNU 64-bit and BSD format.
            b"/" | b"/SYM64/" | b"__.SYMDEF" => buff[..pathname.len()].copy_from_slice(&pathname),
            // The archive filename table: collect it in the next data
            // call. Only its ar_size field is set.
            b"//" => {
                self.is_strtab = true;
                buff[..2].copy_from_slice(b"//");
            }
            _ => {
                // A normal archive member: strip leading paths, if any.
                let filename = match pathname.iter().rposition(|&b| b == b'/') {
                    None => pathname.as_slice(),
                    // Reject filenames with trailing "/".
                    Some(i) if i + 1 == pathname.len() => {
                        return warn(libc::EINVAL, "Invalid filename");
                    }
                    Some(i) => &pathname[i + 1..],
                };
                if !self.bsd {
                    // SVR4/GNU variant use a "/" to mark then end of the
                    // filename, make it possible to have embedded spaces
                    // in the filename. So, the longest filename here
                    // (without extension) is actually 15 bytes.
                    if filename.len() <= 15 {
                        buff[..filename.len()].copy_from_slice(filename);
                        buff[filename.len()] = b'/';
                    } else {
                        // Longer names live in the string table, which
                        // should have been written before; the ar_name
                        // field holds "/" and the name's offset in it.
                        let Some(strtab) = self.strtab.as_deref() else {
                            return warn(libc::EINVAL, "Can't find string table");
                        };
                        // strstr: the table ends at its first NUL.
                        let strtab = strtab.split(|&b| b == 0).next().unwrap_or_default();
                        let se = [filename, b"/\n"].concat();
                        let Some(at) = strtab.windows(se.len()).position(|w| w == se) else {
                            return warn(libc::EINVAL, "Invalid string table");
                        };
                        buff[0] = b'/';
                        if !format_number(&mut buff[1..16], at as i64, false) {
                            return warn(libc::ERANGE, "string table offset too large");
                        }
                    }
                } else if filename.len() <= 16 && !filename.contains(&b' ') {
                    buff[..filename.len()].copy_from_slice(filename);
                } else {
                    // BSD variant: a name longer than 16 bytes or with
                    // embedded spaces is "#1/" and its length; the name
                    // follows the header and counts toward its size.
                    buff[..3].copy_from_slice(b"#1/");
                    if !format_number(&mut buff[3..16], filename.len() as i64, false) {
                        return warn(libc::ERANGE, "File name too long");
                    }
                    size = size.saturating_add(filename.len() as i64);
                    append = Some(filename.to_vec());
                }
            }
        }
        if !self.is_strtab {
            for (v, field, octal, msg) in [
                (e.mtime(), 16..28, false, "File modification time too large"),
                (e.uid(), 28..34, false, "Numeric user ID too large"),
                (e.gid(), 34..40, false, "Numeric group ID too large"),
                (i64::from(e.mode()), 40..48, true, "Numeric mode too large"),
            ] {
                if !format_number(&mut buff[field], v, octal) {
                    return warn(libc::ERANGE, msg);
                }
            }
            // Sanity Check: A non-pseudo archive member should always be
            // a regular file.
            let pseudo = matches!(pathname.as_slice(), b"/" | b"/SYM64/" | b"__.SYMDEF");
            if !pseudo && e.filetype() != 0o100000 {
                return warn(libc::EINVAL, "Regular file required for non-pseudo member");
            }
        }
        if !format_number(&mut buff[48..58], size, false) {
            return warn(libc::ERANGE, "File size out of range");
        }
        sink.write(&buff)?;
        self.remaining = size as u64;
        self.padding = size % 2 != 0;
        if let Some(name) = append {
            sink.write(&name)?;
            self.remaining -= name.len() as u64;
        }
        Ok(ARCHIVE_OK)
    }
    fn data(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<usize, Error> {
        let n = data.len().min(self.remaining as usize);
        if self.is_strtab {
            if self.strtab.is_some() {
                return Err(Error::new(
                    ARCHIVE_WARN,
                    libc::EINVAL,
                    "More than one string tables exist",
                ));
            }
            self.strtab = Some(data[..n].to_vec());
        }
        sink.write(&data[..n])?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn finish_entry(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if self.remaining != 0 {
            return Err(Error::new(
                ARCHIVE_WARN,
                -1,
                "Entry remaining bytes larger than 0",
            ));
        }
        // The padding stays set until the next member's header: a member
        // rejected with ARCHIVE_WARN pads again.
        if self.padding {
            sink.write(b"\n")?;
        }
        Ok(())
    }
    fn close(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        if !self.global {
            sink.write(b"!<arch>\n")?;
            self.global = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Output(Vec<u8>);
    impl Sink for Output {
        fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.0.extend_from_slice(data);
            Ok(())
        }
    }

    // As upstream: a rejected member is ARCHIVE_WARN with nothing written,
    // and its finish pads again for the odd-sized member before it.
    #[test]
    fn rejected_member_warns_and_repeats_the_previous_padding() {
        for bsd in [true, false] {
            let mut ar = Ar::new(bsd);
            let base = Base::new(WRITE_MAGIC);
            let mut out = Output(Vec::new());
            let mut e = Entry::new(None);
            e.set_pathname(b"t/a");
            e.set_filetype(0o100000);
            e.set_perm(0o644);
            e.set_size(1);
            e.set_mtime(1600000000, 0);
            assert_eq!(ar.header(&base, &mut e, &mut out), Ok(ARCHIVE_OK));
            assert_eq!(ar.data(b"x", &mut out), Ok(1));
            ar.finish_entry(&mut out).unwrap();
            let first = out.0.len();
            e.set_pathname(b"t/b");
            e.set_mtime(-1, 0);
            assert_eq!(ar.header(&base, &mut e, &mut out), Ok(ARCHIVE_WARN));
            assert_eq!(
                base.error_string().as_deref(),
                Some(b"File modification time too large".as_slice())
            );
            assert_eq!(ar.data(b"y", &mut out), Ok(0));
            ar.finish_entry(&mut out).unwrap();
            assert_eq!(&out.0[first..], b"\n");
            let name: &[u8] = if bsd {
                b"a               "
            } else {
                b"a/              "
            };
            assert_eq!(
                out.0,
                [
                    b"!<arch>\n".as_slice(),
                    name,
                    b"1600000000  0     0     100644  1         `\nx\n\n"
                ]
                .concat()
            );
        }
    }
}
