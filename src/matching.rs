/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_match.c.

use crate::archive::*;
use crate::entry::Entry;
use crate::pathmatch;
use crate::string::MString;
use crate::util::Error;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, c_char};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MTIME: i32 = 0x100;
pub const CTIME: i32 = 0x200;
pub const NEWER: i32 = 1;
pub const OLDER: i32 = 2;
pub const EQUAL: i32 = 0x10;
type Timestamp = (i64, i64);
#[derive(Default)]
struct Pattern {
    text: MString,
    matched: bool,
}
struct FileTime {
    flag: i32,
    mtime: Timestamp,
    ctime: Timestamp,
}
struct Limit {
    flag: i32,
    time: Timestamp,
}
pub struct Matching {
    pub recursive: bool,
    pub now: i64,
    inclusions: Vec<Pattern>,
    exclusions: Vec<Pattern>,
    next: Option<usize>,
    eof: bool,
    newer: [Option<Limit>; 2],
    older: [Option<Limit>; 2],
    files: BTreeMap<Vec<u8>, FileTime>,
    uids: BTreeSet<i64>,
    gids: BTreeSet<i64>,
    unames: Vec<Pattern>,
    gnames: Vec<Pattern>,
}
impl Default for Matching {
    fn default() -> Self {
        Self {
            recursive: true,
            now: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64),
            inclusions: Vec::new(),
            exclusions: Vec::new(),
            next: None,
            eof: false,
            newer: [None, None],
            older: [None, None],
            files: BTreeMap::new(),
            uids: BTreeSet::new(),
            gids: BTreeSet::new(),
            unames: Vec::new(),
            gnames: Vec::new(),
        }
    }
}
pub fn invalid(msg: &'static str) -> Error {
    Error::new(ARCHIVE_FAILED, libc::EINVAL, msg)
}
pub fn validate_time(flag: i32) -> Result<(), Error> {
    if flag & (!(MTIME | CTIME) & 0xff00) != 0 {
        return Err(invalid("Invalid time flag"));
    }
    if flag & (MTIME | CTIME) == 0 {
        return Err(invalid("No time flag"));
    }
    if flag & (!(NEWER | OLDER | EQUAL) & 0xff) != 0 {
        return Err(invalid("Invalid comparison flag"));
    }
    if flag & (NEWER | OLDER | EQUAL) == 0 {
        return Err(invalid("No comparison flag"));
    }
    Ok(())
}
impl Matching {
    pub fn pattern(&mut self, include: bool, mut text: MString) -> Result<(), Error> {
        // Upstream strips one trailing slash, including from a lone '/'.
        if let Ok(Some(s)) = text.get_mbs_c(None) {
            let b = s.to_bytes();
            if b.is_empty() {
                return Err(invalid("pattern is empty"));
            }
            if b.last() == Some(&b'/') {
                let b = b[..b.len() - 1].to_vec();
                text.copy_mbs(&b);
            }
        } else if let Ok(Some(w)) = text.get_wcs(None) {
            if w.is_empty() {
                return Err(invalid("pattern is empty"));
            }
            if w.last() == Some(&47) {
                let w = w[..w.len() - 1].to_vec();
                text.copy_wcs(&w);
            }
        } else if text.set == 0 {
            return Err(invalid("pattern is empty"));
        }
        let list = if include {
            &mut self.inclusions
        } else {
            &mut self.exclusions
        };
        list.try_reserve(1)
            .map_err(|_| Error::fatal(libc::ENOMEM, "No memory"))?;
        list.push(Pattern {
            text,
            matched: false,
        });
        Ok(())
    }
    pub fn patterns_file(&mut self, include: bool, path: &[u8], null: bool) -> Result<(), Error> {
        let bytes = std::fs::read(Path::new(std::ffi::OsStr::from_bytes(path))).map_err(|e| {
            Error::fatal(
                e.raw_os_error().unwrap_or(libc::EIO),
                format!("Failed to open '{}'", String::from_utf8_lossy(path)),
            )
        })?;
        for b in bytes.split(|&b| if null { b == 0 } else { b == 13 || b == 10 }) {
            if !b.is_empty() {
                let mut text = MString::default();
                text.copy_mbs(b);
                self.pattern(include, text)?;
            }
        }
        Ok(())
    }
    pub fn path_excluded(&mut self, a: &Base, e: &mut Entry) -> i32 {
        let pathname = e.pathname();
        let is_null = pathname.is_none();
        let path = pathname.map_or(&[][..], CStr::to_bytes);
        let flags = if self.recursive {
            pathmatch::NO_ANCHOR_END
        } else {
            0
        };
        let mut included = false;
        for p in &mut self.inclusions {
            let r = p
                .text
                .get_mbs_c(None)
                .ok()
                .flatten()
                .map_or(Ok(false), |b| {
                    if is_null && !b.to_bytes().is_empty() {
                        Ok(false)
                    } else {
                        pathmatch::matches(b.to_bytes(), path, flags)
                    }
                });
            match r {
                Ok(true) => {
                    p.matched = true;
                    included = true;
                }
                Ok(false) => {}
                Err(()) => {
                    a.state.set(state::FATAL);
                    return a.raise(Error::fatal(libc::EINVAL, "Failed to apply pattern"));
                }
            }
        }
        for p in &mut self.exclusions {
            let r = p
                .text
                .get_mbs_c(None)
                .ok()
                .flatten()
                .map_or(Ok(false), |b| {
                    pathmatch::matches(
                        b.to_bytes(),
                        path,
                        pathmatch::NO_ANCHOR_START | pathmatch::NO_ANCHOR_END,
                    )
                });
            match r {
                Ok(true) => return 1,
                Ok(false) => {}
                Err(()) => {
                    a.state.set(state::FATAL);
                    return a.raise(Error::fatal(libc::EINVAL, "Failed to apply pattern"));
                }
            }
        }
        i32::from(!included && !self.inclusions.is_empty())
    }
    pub fn unmatched(&self) -> i32 {
        self.inclusions
            .iter()
            .filter(|p| !p.matched)
            .count()
            .min(i32::MAX as usize) as i32
    }
    pub fn unmatched_next(&mut self, wide: bool) -> (i32, *const c_char, *const libc::wchar_t) {
        if self.eof {
            self.eof = false;
            return (ARCHIVE_EOF, std::ptr::null(), std::ptr::null());
        }
        if self.next.is_none() && self.unmatched() == 0 {
            return (ARCHIVE_EOF, std::ptr::null(), std::ptr::null());
        }
        let start = self.next.unwrap_or(0);
        let Some(index) = (start..self.inclusions.len()).find(|&i| !self.inclusions[i].matched)
        else {
            self.next = None;
            return (ARCHIVE_EOF, std::ptr::null(), std::ptr::null());
        };
        self.next = if index + 1 < self.inclusions.len() {
            Some(index + 1)
        } else {
            self.eof = true;
            None
        };
        let p = &mut self.inclusions[index].text;
        if wide {
            (
                ARCHIVE_OK,
                std::ptr::null(),
                p.get_wcs_z(None)
                    .ok()
                    .flatten()
                    .map_or([0 as libc::wchar_t].as_ptr(), |w| w.as_ptr()),
            )
        } else {
            (
                ARCHIVE_OK,
                p.get_mbs_c(None).ok().flatten().unwrap_or(c"").as_ptr(),
                std::ptr::null(),
            )
        }
    }
    pub fn include_time(
        &mut self,
        flag: i32,
        mtime: Timestamp,
        ctime: Timestamp,
    ) -> Result<(), Error> {
        validate_time(flag)?;
        for (i, bit, time) in [(0, MTIME, mtime), (1, CTIME, ctime)] {
            if flag & bit == 0 {
                continue;
            }
            let just_equal = flag & (NEWER | OLDER | EQUAL) == EQUAL;
            if flag & NEWER != 0 || just_equal {
                self.newer[i] = Some(Limit { flag, time });
            }
            if flag & OLDER != 0 || just_equal {
                self.older[i] = Some(Limit { flag, time });
            }
        }
        Ok(())
    }
    pub fn include_file_time(&mut self, flag: i32, path: &[u8]) -> Result<(), Error> {
        validate_time(flag)?;
        if path.is_empty() {
            return Err(invalid("pathname is empty"));
        }
        let m = std::fs::metadata(Path::new(std::ffi::OsStr::from_bytes(path))).map_err(|e| {
            Error::new(
                ARCHIVE_FAILED,
                e.raw_os_error().unwrap_or(libc::EIO),
                "Failed to stat()",
            )
        })?;
        self.include_time(
            flag,
            (m.mtime(), m.mtime_nsec()),
            (m.ctime(), m.ctime_nsec()),
        )
    }
    pub fn exclude_entry(&mut self, flag: i32, e: &mut Entry) -> Result<(), Error> {
        validate_time(flag)?;
        let path = e
            .pathname()
            .ok_or_else(|| invalid("pathname is NULL"))?
            .to_bytes()
            .to_vec();
        self.files.insert(
            path,
            FileTime {
                flag,
                mtime: (e.mtime(), e.mtime_nsec()),
                ctime: (e.ctime(), e.ctime_nsec()),
            },
        );
        Ok(())
    }
    pub fn time_excluded(&mut self, e: &mut Entry) -> i32 {
        let mtime = (e.mtime(), e.mtime_nsec());
        let ctime = if e.ctime_is_set() != 0 {
            (e.ctime(), e.ctime_nsec())
        } else {
            mtime
        };
        for (i, time) in [(0, mtime), (1, ctime)] {
            if self.newer[i]
                .as_ref()
                .is_some_and(|l| time < l.time || (time == l.time && l.flag & EQUAL == 0))
                || self.older[i]
                    .as_ref()
                    .is_some_and(|l| time > l.time || (time == l.time && l.flag & EQUAL == 0))
            {
                return 1;
            }
        }
        let ctime = (e.ctime(), e.ctime_nsec());
        let Some(path) = e.pathname() else {
            return 0;
        };
        let Some(f) = self.files.get(path.to_bytes()) else {
            return 0;
        };
        for (bit, time, reference) in [(MTIME, mtime, f.mtime), (CTIME, ctime, f.ctime)] {
            if f.flag & bit == 0 {
                continue;
            }
            if (time < reference && f.flag & OLDER != 0)
                || (time > reference && f.flag & NEWER != 0)
                || (time == reference && f.flag & EQUAL != 0)
            {
                return 1;
            }
        }
        0
    }
    pub fn include_id(&mut self, user: bool, id: i64) {
        if user {
            self.uids.insert(id);
        } else {
            self.gids.insert(id);
        }
    }
    pub fn include_owner(&mut self, user: bool, text: MString) {
        let list = if user {
            &mut self.unames
        } else {
            &mut self.gnames
        };
        list.push(Pattern {
            text,
            matched: false,
        });
    }
    pub fn owner_excluded(&mut self, e: &mut Entry) -> i32 {
        if (!self.uids.is_empty() && !self.uids.contains(&e.uid()))
            || (!self.gids.is_empty() && !self.gids.contains(&e.gid()))
        {
            return 1;
        }
        for (list, name) in [
            (
                &mut self.unames,
                e.uname().map(CStr::to_bytes).map(Vec::from),
            ),
            (
                &mut self.gnames,
                e.gname().map(CStr::to_bytes).map(Vec::from),
            ),
        ] {
            if list.is_empty() {
                continue;
            }
            let Some(name) = name.filter(|n| !n.is_empty()) else {
                return 1;
            };
            let Some(p) = list.iter_mut().find(|p| {
                p.text
                    .clone()
                    .get_mbs_c(None)
                    .ok()
                    .flatten()
                    .is_some_and(|s| s.to_bytes() == name)
            }) else {
                return 1;
            };
            p.matched = true;
        }
        0
    }
    pub fn excluded(&mut self, a: &Base, e: &mut Entry) -> i32 {
        let r = self.path_excluded(a, e);
        if r != 0 {
            return r;
        }
        let r = self.time_excluded(e);
        if r != 0 {
            return r;
        }
        self.owner_excluded(e)
    }
}
