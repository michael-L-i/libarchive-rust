/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
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

// Ported from libarchive/archive_read_extract2.c.

//! `archive_read_extract2`: writing what a read handle reads to a
//! write-disk handle, with a progress callback.

use crate::archive::WRITE_DISK_MAGIC;
use crate::archive::{ARCHIVE_FATAL, ARCHIVE_OK, ARCHIVE_WARN, Base, Handle, Kind};
use crate::entry::Entry;
use crate::read::Data;
use crate::write_disk::WriteDisk;
use std::ffi::c_int;
use std::rc::Rc;

/// `struct archive_read_extract`: the write-disk handle
/// `archive_read_extract` writes with, and the progress callback.
pub struct Extract {
    pub disk: WriteDisk,
    pub base: Base,
    pub progress: Option<Rc<dyn Fn()>>,
}

impl Default for Extract {
    fn default() -> Self {
        Extract {
            disk: WriteDisk::default(),
            base: Base::new(WRITE_DISK_MAGIC),
            progress: None,
        }
    }
}

impl Extract {
    pub fn close(&mut self) -> c_int {
        self.disk.close(&self.base)
    }
}

impl Handle {
    /// `archive_read_extract_set_progress_callback`: `progress` runs after
    /// each block extraction writes.
    pub(crate) fn read_extract_set_progress_callback(&self, progress: Option<Rc<dyn Fn()>>) {
        if let Kind::Read(r) = &self.kind
            && let Ok(mut r) = r.try_borrow_mut()
        {
            r.extract.get_or_insert_with(Extract::default).progress = progress;
        }
    }

    /// Runs the C progress callback, which may call back into the handle:
    /// the read state isn't borrowed while it runs.
    pub(crate) fn read_extract_progress(&self) {
        let progress = match &self.kind {
            Kind::Read(r) => r
                .try_borrow()
                .ok()
                .and_then(|r| r.extract.as_ref()?.progress.clone()),
            _ => None,
        };
        if let Some(progress) = progress {
            progress();
        }
    }

    /// The first half of `archive_read_extract2`: sets up `dest` for this
    /// particular entry and writes its header. Returns the status, and
    /// whether to copy the data. The entry may be the handle's own, which
    /// the second half, `read_extract2_data`, reads with.
    pub(crate) fn read_extract2_header(&self, entry: &mut Entry, dest: &Handle) -> (c_int, bool) {
        let skip_file = match &self.kind {
            Kind::Read(r) => r.try_borrow().ok().and_then(|r| r.skip_file()),
            _ => None,
        };
        if let Some((dev, ino)) = skip_file {
            dest.write_disk_set_skip_file(dev, ino);
        }
        let r = dest.write_header(entry).max(ARCHIVE_WARN);
        if r != ARCHIVE_OK {
            // If _write_header failed, copy the error.
            self.base.copy_error(&dest.base);
        }
        (
            r,
            r == ARCHIVE_OK && (entry.size_is_set() == 0 || entry.size() > 0),
        )
    }

    /// The rest of `archive_read_extract2`: pours the data into the entry
    /// if `copy`, reading with the handle's own entry `own` and calling
    /// `progress` after each block, and finishes it. `r` is what
    /// `read_extract2_header` returned.
    pub(crate) fn read_extract2_data(
        &self,
        own: Option<&mut Entry>,
        dest: &Handle,
        (r, copy): (c_int, bool),
        progress: &mut dyn FnMut(),
    ) -> c_int {
        let r = if copy {
            self.copy_data(own, dest, progress)
        } else {
            r
        };
        let r2 = dest.write_finish_entry().max(ARCHIVE_WARN);
        // Use the first message.
        if r2 != ARCHIVE_OK && r == ARCHIVE_OK {
            self.base.copy_error(&dest.base);
        }
        // Use the worst error return.
        r.min(r2)
    }

    fn copy_data(
        &self,
        mut own: Option<&mut Entry>,
        dest: &Handle,
        progress: &mut dyn FnMut(),
    ) -> c_int {
        loop {
            let block = self.read_data_block(own.as_deref_mut(), |data| match data {
                Data::Block { data, offset } => Ok(dest.write_data_block(data, offset)),
                Data::Eof { .. } => Err(ARCHIVE_OK),
                Data::Warn { .. } => Err(ARCHIVE_WARN),
            });
            let written = match block {
                Ok(Ok(written)) => written,
                Ok(Err(r)) | Err(r) => return r,
            };
            let r = c_int::try_from(written)
                .unwrap_or(ARCHIVE_FATAL)
                .max(ARCHIVE_WARN);
            if r < ARCHIVE_OK {
                self.base.copy_error(&dest.base);
                return r;
            }
            progress();
        }
    }
}
