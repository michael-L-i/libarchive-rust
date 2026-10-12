/*-
 * Copyright (c) 2011 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_read_support_format_7zip.c.

//! Parsing the 7-Zip header: numbers, digests, pack info, folders, coders,
//! substreams and the file list.
//!
//! Every count read from the header is bounded by what is left of the header
//! before it sizes an allocation, where each item needs at least one byte, so
//! a header can't ask for more memory than its own size. Allocations are
//! fallible.

use super::*;
use crate::time::ntfs_to_unix;

/// Why parsing failed: `Bad` is upstream's plain `-1`, `NoMem` the `-1`
/// with `errno` `ENOMEM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fail {
    Bad,
    NoMem,
}

pub(super) type P<T> = Result<T, Fail>;

/// `n` copies of `value`, or `NoMem`.
fn vec_of<T: Clone>(r: &Reader<'_>, n: usize, value: T) -> P<Vec<T>> {
    r.metadata(n.checked_mul(std::mem::size_of::<T>()).ok_or(Fail::NoMem)?)
        .map_err(|_| Fail::Bad)?;
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Fail::NoMem)?;
    v.resize(n, value);
    Ok(v)
}

/// What `read_Header` collects besides the entries.
#[derive(Default)]
pub(super) struct HeaderInfo {
    empty_stream_bools: Option<Vec<bool>>,
    empty_file_bools: Option<Vec<bool>>,
    anti_bools: Option<Vec<bool>>,
}

fn decode_codec_id(id: &[u8]) -> Option<i64> {
    id.iter().try_fold(0i64, |v, &b| {
        v.checked_mul(256).and_then(|v| v.checked_add(i64::from(b)))
    })
}

/// The first of `i` such that no bind pair has `inIndex == i`.
fn first_unbound_in_stream(
    r: &Reader<'_>,
    pairs: &[(usize, usize)],
    total: usize,
) -> P<Option<usize>> {
    let mut bound = vec_of(r, total, false)?;
    for &(in_index, _) in pairs {
        if let Some(b) = bound.get_mut(in_index) {
            *b = true;
        }
    }
    Ok(bound.iter().position(|&b| !b))
}

/// `folder_uncompressed_size`.
pub(super) fn folder_uncompressed_size(f: &Folder) -> i64 {
    let mut n = f.num_out_streams;
    while n > 0 {
        n -= 1;
        if !f.bind_pairs.iter().any(|&(_, out_index)| out_index == n) {
            return f.unpack_size.get(n).copied().unwrap_or(0);
        }
    }
    0
}

impl SevenZip {
    /// `header_bytes` for one byte.
    fn hb_u8(&mut self, r: &mut Reader<'_>) -> P<u8> {
        self.header_with(r, 1, |p| p.first().copied())
            .flatten()
            .ok_or(Fail::Bad)
    }

    /// `header_bytes` for a fixed number of bytes.
    fn hb_array<const N: usize>(&mut self, r: &mut Reader<'_>) -> P<[u8; N]> {
        self.header_with(r, N, |p| p.try_into().ok())
            .flatten()
            .ok_or(Fail::Bad)
    }

    /// Reads `n` bytes of the header, in pieces so a size from the header
    /// doesn't size a buffer.
    fn hb_vec(&mut self, r: &mut Reader<'_>, mut n: usize) -> P<Vec<u8>> {
        let mut out = Vec::new();
        while n > 0 {
            let b = n.min(UBUFF_SIZE);
            r.metadata(b).map_err(|_| Fail::Bad)?;
            let ok = self.header_with(r, b, |p| {
                out.try_reserve(b).ok()?;
                out.extend_from_slice(p);
                Some(())
            });
            ok.flatten().ok_or(Fail::Bad)?;
            n -= b;
        }
        Ok(out)
    }

    /// Skips `n` bytes of the header.
    fn hb_skip(&mut self, r: &mut Reader<'_>, mut n: usize) -> P<()> {
        while n > 0 {
            let b = n.min(UBUFF_SIZE);
            self.header_with(r, b, |_| ()).ok_or(Fail::Bad)?;
            n -= b;
        }
        Ok(())
    }

    fn parse_int64(&mut self, r: &mut Reader<'_>) -> P<i64> {
        let avail = self.hb_u8(r)?;
        let mut mask = 0x80u8;
        let mut v = 0u64;
        for i in 0..8 {
            if avail & mask != 0 {
                let b = self.hb_u8(r)?;
                v |= u64::from(b) << (8 * i);
                mask >>= 1;
                continue;
            }
            v += u64::from(avail & mask.wrapping_sub(1)) << (8 * i);
            break;
        }
        i64::try_from(v).map_err(|_| Fail::Bad)
    }

    /// `parse_7zip_size`.
    fn parse_size(&mut self, r: &mut Reader<'_>) -> P<usize> {
        let v = self.parse_int64(r)?;
        if v > UMAX_ENTRY {
            return Err(Fail::Bad);
        }
        usize::try_from(v).map_err(|_| Fail::Bad)
    }

    fn read_bools(&mut self, r: &mut Reader<'_>, num: usize) -> P<Vec<bool>> {
        let mut data = vec_of(r, num, false)?;
        let (mut mask, mut avail) = (0u8, 0u8);
        for d in &mut data {
            if mask == 0 {
                avail = self.hb_u8(r)?;
                mask = 0x80;
            }
            *d = avail & mask != 0;
            mask >>= 1;
        }
        Ok(data)
    }

    fn read_digests(&mut self, r: &mut Reader<'_>, num: usize) -> P<Digests> {
        if num == 0 {
            return Err(Fail::Bad);
        }
        // Read Bools.
        let defineds = if self.hb_u8(r)? == 0 {
            self.read_bools(r, num)?
        } else {
            // All are defined.
            vec_of(r, num, true)?
        };
        let mut digests = vec_of(r, num, 0u32)?;
        for (d, &defined) in digests.iter_mut().zip(&defineds) {
            if defined {
                *d = u32::from_le_bytes(self.hb_array(r)?);
            }
        }
        Ok(Digests { defineds, digests })
    }

    fn read_pack_info(&mut self, r: &mut Reader<'_>) -> P<PackInfo> {
        let mut pi = PackInfo {
            pos: self.parse_int64(r)?,
            ..PackInfo::default()
        };
        pi.num_pack_streams = self.parse_size(r)?;
        if pi.num_pack_streams == 0 {
            return Err(Fail::Bad);
        }

        // Read PackSizes[num].
        match self.hb_u8(r)? {
            // PackSizes[num] are not present.
            K_END => return Ok(pi),
            K_SIZE => {}
            _ => return Err(Fail::Bad),
        }
        // Each size takes at least a byte.
        if i64::try_from(pi.num_pack_streams).map_err(|_| Fail::Bad)? > self.header_bytes_remaining
        {
            return Err(Fail::Bad);
        }
        pi.sizes = vec_of(r, pi.num_pack_streams, 0)?;
        pi.positions = vec_of(r, pi.num_pack_streams, 0)?;
        for i in 0..pi.num_pack_streams {
            let size = self.parse_int64(r)?;
            if let Some(s) = pi.sizes.get_mut(i) {
                *s = size;
            }
        }

        // Read PackStreamDigests[num].
        match self.hb_u8(r)? {
            K_END => {
                // PackStreamDigests[num] are not present.
                pi.digest = Digests {
                    defineds: vec_of(r, pi.num_pack_streams, false)?,
                    digests: vec_of(r, pi.num_pack_streams, 0)?,
                };
                return Ok(pi);
            }
            K_CRC => {}
            _ => return Err(Fail::Bad),
        }
        pi.digest = self.read_digests(r, pi.num_pack_streams)?;

        // Must be marked by kEnd.
        if self.hb_u8(r)? != K_END {
            return Err(Fail::Bad);
        }
        Ok(pi)
    }

    fn read_folder(&mut self, r: &mut Reader<'_>) -> P<Folder> {
        let mut f = Folder::default();
        let mut in_streams_total = 0usize;
        let mut out_streams_total = 0usize;

        // Read NumCoders.
        let num_coders = self.parse_size(r)?;
        if num_coders > 4 {
            // Too many coders.
            return Err(Fail::Bad);
        }

        r.metadata(
            num_coders
                .checked_mul(std::mem::size_of::<Coder>())
                .ok_or(Fail::NoMem)?,
        )
        .map_err(|_| Fail::Bad)?;
        f.coders
            .try_reserve_exact(num_coders)
            .map_err(|_| Fail::NoMem)?;
        for _ in 0..num_coders {
            // 0:3 CodecIdSize
            // 4:  0 - IsSimple
            //     1 - Is not Simple
            // 5:  0 - No Attributes
            //     1 - There are Attributes;
            // 7:  Must be zero.
            let b = self.hb_u8(r)?;
            let codec_size = usize::from(b & 0xf);
            let simple = b & 0x10 == 0;
            let attr = b & 0x20 != 0;
            if b & 0x80 != 0 {
                return Err(Fail::Bad); // Not supported.
            }

            // Read Decompression Method IDs.
            let id = self.hb_vec(r, codec_size)?;
            let mut coder = Coder {
                codec: decode_codec_id(&id).ok_or(Fail::Bad)?,
                ..Coder::default()
            };

            if simple {
                coder.num_in_streams = 1;
                coder.num_out_streams = 1;
            } else {
                coder.num_in_streams = self.parse_size(r)?;
                coder.num_out_streams = self.parse_size(r)?;
            }

            if attr {
                let size = self.parse_size(r)?;
                coder.properties = self.hb_vec(r, size)?;
            }

            in_streams_total = in_streams_total
                .checked_add(coder.num_in_streams)
                .ok_or(Fail::Bad)?;
            out_streams_total = out_streams_total
                .checked_add(coder.num_out_streams)
                .ok_or(Fail::Bad)?;
            f.coders.push(coder);
        }

        if out_streams_total == 0 || in_streams_total < out_streams_total - 1 {
            return Err(Fail::Bad);
        }

        let num_bind_pairs = out_streams_total - 1;
        if u64::try_from(self.header_bytes_remaining).unwrap_or(0) < num_bind_pairs as u64 {
            return Err(Fail::Bad);
        }
        r.metadata(
            num_bind_pairs
                .checked_mul(std::mem::size_of::<(usize, usize)>())
                .ok_or(Fail::NoMem)?,
        )
        .map_err(|_| Fail::Bad)?;
        f.bind_pairs
            .try_reserve_exact(num_bind_pairs)
            .map_err(|_| Fail::NoMem)?;
        for _ in 0..num_bind_pairs {
            let in_index = self.parse_size(r)?;
            let out_index = self.parse_size(r)?;
            f.bind_pairs.push((in_index, out_index));
        }

        f.num_packed_streams = in_streams_total - num_bind_pairs;
        // packedStreams are not needed; parse/verify nonetheless.
        if f.num_packed_streams == 1 {
            if first_unbound_in_stream(r, &f.bind_pairs, in_streams_total)?.is_none() {
                return Err(Fail::Bad);
            }
        } else {
            for _ in 0..f.num_packed_streams {
                self.parse_size(r)?;
            }
        }
        f.num_in_streams = in_streams_total;
        f.num_out_streams = out_streams_total;

        Ok(f)
    }

    fn read_coders_info(&mut self, r: &mut Reader<'_>) -> P<Vec<Folder>> {
        if self.hb_u8(r)? != K_FOLDER {
            return Err(Fail::Bad);
        }

        // Read NumFolders.
        let num_folders = self.parse_size(r)?;
        // Each folder is encoded by at least one byte in the coders list
        // that follows, so a folder count larger than the bytes left in the
        // header cannot be honored and is rejected here before it is used to
        // size the folders allocation.
        if i64::try_from(num_folders).map_err(|_| Fail::Bad)? > self.header_bytes_remaining {
            return Err(Fail::Bad);
        }

        // Read External.
        let mut folders = Vec::new();
        match self.hb_u8(r)? {
            0 => {
                r.metadata(
                    num_folders
                        .checked_mul(std::mem::size_of::<Folder>())
                        .ok_or(Fail::NoMem)?,
                )
                .map_err(|_| Fail::Bad)?;
                folders
                    .try_reserve_exact(num_folders)
                    .map_err(|_| Fail::NoMem)?;
                for _ in 0..num_folders {
                    folders.push(self.read_folder(r)?);
                }
            }
            1 => {
                self.parse_size(r)?;
                if num_folders > 0 {
                    return Err(Fail::Bad);
                }
            }
            _ => return Err(Fail::Bad),
        }

        if self.hb_u8(r)? != K_CODERS_UNPACK_SIZE {
            return Err(Fail::Bad);
        }

        for folder in &mut folders {
            folder.unpack_size = vec_of(r, folder.num_out_streams, 0)?;
            for j in 0..folder.num_out_streams {
                let size = self.parse_int64(r)?;
                if let Some(s) = folder.unpack_size.get_mut(j) {
                    *s = size;
                }
            }
        }

        // Read CRCs.
        match self.hb_u8(r)? {
            K_END => return Ok(folders),
            K_CRC => {}
            _ => return Err(Fail::Bad),
        }
        let digest = self.read_digests(r, num_folders)?;
        for (f, (&defined, &d)) in folders
            .iter_mut()
            .zip(digest.defineds.iter().zip(&digest.digests))
        {
            f.digest_defined = defined;
            f.digest = d;
        }

        // Must be kEnd.
        if self.hb_u8(r)? != K_END {
            return Err(Fail::Bad);
        }
        Ok(folders)
    }

    fn read_substreams_info(
        &mut self,
        r: &mut Reader<'_>,
        folders: &mut [Folder],
    ) -> P<SubStreamInfo> {
        let mut ss = SubStreamInfo::default();

        for f in folders.iter_mut() {
            f.num_unpack_streams = 1;
        }

        let mut ty = self.hb_u8(r)?;
        let unpack_streams = if ty == K_NUM_UNPACK_STREAM {
            let mut unpack_streams = 0usize;
            for f in folders.iter_mut() {
                f.num_unpack_streams = self.parse_size(r)?;
                unpack_streams = unpack_streams
                    .checked_add(f.num_unpack_streams)
                    .ok_or(Fail::Bad)?;
            }
            ty = self.hb_u8(r)?;
            unpack_streams
        } else {
            folders.len()
        };

        if unpack_streams > UMAX_ENTRY as usize {
            return Err(Fail::Bad);
        }

        if ty != K_SIZE && folders.iter().any(|f| f.num_unpack_streams > 1) {
            return Err(Fail::Bad);
        }

        // Every stream beyond one per folder has its size in the header.
        let remaining = usize::try_from(self.header_bytes_remaining).unwrap_or(0);
        if unpack_streams > folders.len().saturating_add(remaining) {
            return Err(Fail::Bad);
        }

        ss.unpack_streams = unpack_streams;
        ss.unpack_sizes = vec_of(r, unpack_streams, 0)?;
        ss.digests_defined = vec_of(r, unpack_streams, false)?;
        ss.digests = vec_of(r, unpack_streams, 0)?;

        let mut usizes = 0usize;
        for f in folders.iter() {
            if f.num_unpack_streams == 0 {
                continue;
            }

            let mut sum = 0i64;
            if ty == K_SIZE {
                for _ in 1..f.num_unpack_streams {
                    let size = self.parse_int64(r)?;
                    *ss.unpack_sizes.get_mut(usizes).ok_or(Fail::Bad)? = size;
                    usizes += 1;
                    sum = sum.checked_add(size).ok_or(Fail::Bad)?;
                }
            }
            let size = folder_uncompressed_size(f);
            if size < sum {
                return Err(Fail::Bad);
            }
            *ss.unpack_sizes.get_mut(usizes).ok_or(Fail::Bad)? = size - sum;
            usizes += 1;
        }

        if ty == K_SIZE {
            ty = self.hb_u8(r)?;
        }

        let mut num_digests = 0usize;
        for f in folders.iter() {
            if f.num_unpack_streams != 1 || !f.digest_defined {
                num_digests = num_digests
                    .checked_add(f.num_unpack_streams)
                    .ok_or(Fail::NoMem)?;
            }
        }

        if ty == K_CRC {
            let tmp = self.read_digests(r, num_digests)?;
            let (mut at, mut di) = (0usize, 0usize);
            for f in folders.iter() {
                if f.num_unpack_streams == 1 && f.digest_defined {
                    *ss.digests_defined.get_mut(at).ok_or(Fail::Bad)? = true;
                    *ss.digests.get_mut(at).ok_or(Fail::Bad)? = f.digest;
                    at += 1;
                } else {
                    for _ in 0..f.num_unpack_streams {
                        *ss.digests_defined.get_mut(at).ok_or(Fail::Bad)? =
                            *tmp.defineds.get(di).ok_or(Fail::Bad)?;
                        *ss.digests.get_mut(at).ok_or(Fail::Bad)? =
                            *tmp.digests.get(di).ok_or(Fail::Bad)?;
                        at += 1;
                        di += 1;
                    }
                }
            }
            ty = self.hb_u8(r)?;
        }

        // Must be kEnd.
        if ty != K_END {
            return Err(Fail::Bad);
        }
        Ok(ss)
    }

    /// `read_StreamsInfo`. Fills `self.si`.
    pub(super) fn read_streams_info(&mut self, r: &mut Reader<'_>) -> P<()> {
        let mut si = StreamInfo::default();

        let mut p = self.hb_u8(r)?;
        if p == K_PACK_INFO {
            si.pi = self.read_pack_info(r)?;

            if si.pi.positions.is_empty() || si.pi.sizes.is_empty() {
                return Err(Fail::Bad);
            }
            // Calculate packed stream positions.
            let mut pack_pos = si.pi.pos;
            for (position, &size) in si.pi.positions.iter_mut().zip(&si.pi.sizes) {
                *position = pack_pos;
                pack_pos = pack_pos.checked_add(size).ok_or(Fail::Bad)?;
                if pack_pos > self.header_offset {
                    return Err(Fail::Bad);
                }
            }
            p = self.hb_u8(r)?;
        }
        if p == K_UNPACK_INFO {
            si.folders = self.read_coders_info(r)?;

            // Calculate packed stream indexes.
            let mut pack_index = 0usize;
            for f in &mut si.folders {
                f.pack_index = pack_index;
                pack_index = pack_index
                    .checked_add(f.num_packed_streams)
                    .filter(|&i| i <= si.pi.num_pack_streams)
                    .ok_or(Fail::Bad)?;
            }
            p = self.hb_u8(r)?;
        }

        if p == K_SUBSTREAMS_INFO {
            si.ss = self.read_substreams_info(r, &mut si.folders)?;
            p = self.hb_u8(r)?;
        }

        // Must be kEnd.
        if p != K_END {
            return Err(Fail::Bad);
        }
        self.si = si;
        Ok(())
    }

    /// Files without unpack streams must be described by the EmptyStream
    /// bitmap, which consumes one bit for every file entry in FilesInfo.
    fn files_info_numfiles_is_sane(&self) -> bool {
        if self.num_files <= self.si.ss.unpack_streams {
            return true;
        }
        let empty_stream_map_bytes = (self.num_files as u64).div_ceil(8);
        i64::try_from(empty_stream_map_bytes).is_ok_and(|b| b <= self.header_bytes_remaining)
    }

    /// `read_Header`: the header proper, after its id (which an encoded
    /// header has already had read).
    pub(super) fn read_header_info(
        &mut self,
        r: &mut Reader<'_>,
        h: &mut HeaderInfo,
        check_header_id: bool,
    ) -> P<()> {
        if check_header_id {
            // Read Header.
            if self.hb_u8(r)? != K_HEADER {
                return Err(Fail::Bad);
            }
        }

        // Read ArchiveProperties.
        let mut p = self.hb_u8(r)?;
        if p == K_ARCHIVE_PROPERTIES {
            loop {
                if self.hb_u8(r)? == K_END {
                    break;
                }
                let size = self.parse_int64(r)?;
                if size < 0 || self.header_bytes_remaining < size {
                    return Err(Fail::Bad);
                }

                // Skip the property data to keep header parsing aligned.
                self.hb_skip(r, size as usize)?;
            }
            p = self.hb_u8(r)?;
        }

        // Read MainStreamsInfo.
        if p == K_MAIN_STREAMS_INFO {
            self.read_streams_info(r)?;
            p = self.hb_u8(r)?;
        }
        if p == K_END {
            return Ok(());
        }

        // Read FilesInfo.
        if p != K_FILES_INFO {
            return Err(Fail::Bad);
        }

        self.num_files = self.parse_size(r)?;
        r.check_entries(self.num_files).map_err(|_| Fail::Bad)?;
        r.metadata(
            self.num_files
                .checked_mul(std::mem::size_of::<ZEntry>())
                .ok_or(Fail::NoMem)?,
        )
        .map_err(|_| Fail::Bad)?;
        if !self.files_info_numfiles_is_sane() {
            return Err(Fail::Bad);
        }

        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.num_files)
            .map_err(|_| Fail::NoMem)?;
        entries.resize(self.num_files, ZEntry::default());

        let mut empty_streams = 0usize;
        let mut attr_seen = false;
        loop {
            let ty = self.hb_u8(r)?;
            if ty == K_END {
                break;
            }

            let size = self.parse_int64(r)?;
            if self.header_bytes_remaining < size || size > (usize::MAX / 4) as i64 {
                return Err(Fail::Bad);
            }
            let mut ll = size as usize;

            match ty {
                K_EMPTY_STREAM => {
                    if h.empty_stream_bools.is_some() {
                        return Err(Fail::Bad);
                    }
                    let bools = self.read_bools(r, self.num_files)?;
                    empty_streams = bools.iter().filter(|&&b| b).count();
                    h.empty_stream_bools = Some(bools);
                }
                K_EMPTY_FILE | K_ANTI => {
                    if empty_streams == 0 {
                        // Unexcepted sequence. Skip this.
                        self.hb_skip(r, ll)?;
                        continue;
                    }
                    let slot = if ty == K_EMPTY_FILE {
                        &mut h.empty_file_bools
                    } else {
                        &mut h.anti_bools
                    };
                    if slot.is_some() {
                        return Err(Fail::Bad);
                    }
                    let bools = self.read_bools(r, empty_streams)?;
                    let slot = if ty == K_EMPTY_FILE {
                        &mut h.empty_file_bools
                    } else {
                        &mut h.anti_bools
                    };
                    *slot = Some(bools);
                }
                K_CTIME | K_ATIME | K_MTIME => self.read_times(r, ty, &mut entries)?,
                K_NAME => {
                    // Skip one byte.
                    self.hb_u8(r)?;
                    ll = ll.wrapping_sub(1);

                    if (ll & 1) != 0 || ll < self.num_files.saturating_mul(4) {
                        return Err(Fail::Bad);
                    }

                    if self.entry_names.is_some() {
                        return Err(Fail::Bad);
                    }
                    // Copy whole file names.
                    let names = self.hb_vec(r, ll)?;
                    let mut off = 0usize;
                    for e in &mut entries {
                        e.name_off = off;
                        // Find a terminator.
                        let mut end = off;
                        loop {
                            match names.get(end..end + 2) {
                                None => return Err(Fail::Bad), // Terminator not found
                                Some([0, 0]) => break,
                                Some(_) => end += 2,
                            }
                        }
                        e.name_len = end - off;
                        off = end + 2;
                    }
                    self.entry_names = Some(names);
                }
                K_ATTRIBUTES => {
                    let [all_are_defined, _] = self.hb_array::<2>(r)?;
                    if attr_seen {
                        return Err(Fail::Bad);
                    }
                    attr_seen = true;
                    let attr_bools = if all_are_defined == 0 {
                        Some(self.read_bools(r, self.num_files)?)
                    } else {
                        None
                    };
                    for (i, e) in entries.iter_mut().enumerate() {
                        if attr_bools.as_ref().is_none_or(|b| b.get(i) == Some(&true)) {
                            e.attr = u32::from_le_bytes(self.hb_array(r)?);
                        }
                    }
                }
                K_DUMMY if ll == 0 => {}
                _ => self.hb_skip(r, ll)?,
            }
        }

        self.setup_entries(h, &mut entries)?;
        self.entries = Some(entries);
        Ok(())
    }

    /// Set up entry's attributes and the folder each one's data is in.
    fn setup_entries(&mut self, h: &HeaderInfo, entries: &mut [ZEntry]) -> P<()> {
        let mut eindex = 0usize;
        let mut sindex = 0usize;
        let mut folder_index = 0usize;
        let mut index_in_folder = 0usize;
        for (i, e) in entries.iter_mut().enumerate() {
            if h.empty_stream_bools
                .as_ref()
                .is_none_or(|b| b.get(i) != Some(&true))
            {
                e.flg |= HAS_STREAM;
            }
            // The high 16 bits of attributes is a posix file mode.
            e.mode = e.attr >> 16;

            if e.attr & FILE_ATTRIBUTE_UNIX_EXTENSION == 0 {
                // Only windows permissions specified for this entry.
                // Translate to reasonable corresponding unix permissions.
                let readonly = e.attr & FILE_ATTRIBUTE_READONLY != 0;
                e.mode = if e.attr & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    // Read-only or read-write directory.
                    u32::from(AE_IFDIR) | if readonly { 0o555 } else { 0o755 }
                } else {
                    // Readonly file, or assume read-write file.
                    u32::from(AE_IFREG) | if readonly { 0o444 } else { 0o644 }
                };
            }

            if e.flg & HAS_STREAM != 0 {
                if sindex >= self.si.ss.unpack_streams {
                    return Err(Fail::Bad);
                }
                if e.mode == 0 {
                    e.mode = u32::from(AE_IFREG) | 0o666;
                }
                if self.si.ss.digests_defined.get(sindex) == Some(&true) {
                    e.flg |= CRC32_IS_SET;
                }
                e.ss_index = Some(sindex);
                sindex += 1;
            } else {
                let mut dir = true;
                if let Some(b) = &h.empty_file_bools {
                    dir = b.get(eindex) != Some(&true);
                    eindex += 1;
                }
                if e.mode == 0 {
                    e.mode = if dir {
                        u32::from(AE_IFDIR) | 0o777
                    } else {
                        u32::from(AE_IFREG) | 0o666
                    };
                } else if dir && e.mode & u32::from(AE_IFMT) != u32::from(AE_IFDIR) {
                    e.mode &= !u32::from(AE_IFMT);
                    e.mode |= u32::from(AE_IFDIR);
                }
                if e.mode & u32::from(AE_IFMT) == u32::from(AE_IFDIR) && e.name_len >= 2 {
                    let names = self.entry_names.as_mut().ok_or(Fail::Bad)?;
                    let end = e.name_off + e.name_len;
                    if names.get(end - 2..end) != Some(&[b'/', 0][..]) {
                        // The terminator after the name has room for it.
                        names
                            .get_mut(end..end + 2)
                            .ok_or(Fail::Bad)?
                            .copy_from_slice(&[b'/', 0]);
                        e.name_len += 2;
                    }
                }
                e.ss_index = None;
            }
            if e.attr & FILE_ATTRIBUTE_READONLY != 0 {
                e.mode &= !0o222; // Read only.
            }

            if e.flg & HAS_STREAM == 0 && index_in_folder == 0 {
                // The entry is an empty file or a directory file, those
                // both have no contents.
                e.folder_index = None;
                continue;
            }
            if index_in_folder == 0 {
                loop {
                    let folder = self.si.folders.get(folder_index).ok_or(Fail::Bad)?;
                    if folder.num_unpack_streams != 0 {
                        break;
                    }
                    folder_index += 1;
                }
            }
            e.folder_index = Some(folder_index);
            if e.flg & HAS_STREAM == 0 {
                continue;
            }
            index_in_folder += 1;
            let folder = self.si.folders.get(folder_index).ok_or(Fail::Bad)?;
            if index_in_folder >= folder.num_unpack_streams {
                folder_index += 1;
                index_in_folder = 0;
            }
        }
        Ok(())
    }

    fn read_times(&mut self, r: &mut Reader<'_>, ty: u8, entries: &mut [ZEntry]) -> P<()> {
        // Read allAreDefined.
        let all_are_defined = self.hb_u8(r)? != 0;

        let time_bools = if all_are_defined {
            None
        } else {
            Some(self.read_bools(r, self.num_files)?)
        };

        // Read external.
        if self.hb_u8(r)? != 0 {
            self.parse_size(r)?;
        }

        for (i, e) in entries.iter_mut().enumerate() {
            if time_bools.as_ref().is_some_and(|b| b.get(i) != Some(&true)) {
                continue;
            }
            let t = ntfs_to_unix(u64::from_le_bytes(self.hb_array(r)?));
            match ty {
                K_CTIME => {
                    e.ctime = t;
                    e.flg |= CTIME_IS_SET;
                }
                K_ATIME => {
                    e.atime = t;
                    e.flg |= ATIME_IS_SET;
                }
                _ => {
                    e.mtime = t;
                    e.flg |= MTIME_IS_SET;
                }
            }
        }
        Ok(())
    }

    /// `decode_encoded_header_info`.
    pub(super) fn decode_encoded_header_info(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let malformed = || Error::fatal(-1, "Malformed 7-Zip archive");
        if let Err(f) = self.read_streams_info(r) {
            return Err(match f {
                Fail::NoMem => Error::fatal(-1, "Couldn't allocate memory"),
                Fail::Bad => malformed(),
            });
        }

        if self.si.pi.num_pack_streams == 0 || self.si.folders.is_empty() {
            return Err(malformed());
        }

        let first = self.si.pi.sizes.first().copied().ok_or_else(malformed)?;
        let pi_end = self.si.pi.pos.checked_add(first).ok_or_else(malformed)?;

        if self.header_offset < pi_end {
            return Err(Error::fatal(-1, "Malformed Header offset"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod limit_tests {
    use super::*;
    use crate::archive::{ARCHIVE_OK, Base, READ_MAGIC};
    use crate::read::{Read, ReadLimits};
    use crate::read_open_memory::Memory;

    #[test]
    fn limits_pack_tables_fail_before_wire_sizes_are_parsed() {
        let input = [0, 3, K_SIZE, 1, 1, 1, K_END];
        let a = Base::new(READ_MAGIC);
        let mut read = Read::default();
        assert_eq!(
            read.set_limits(
                &a,
                ReadLimits {
                    metadata_bytes: Some(32),
                    ..ReadLimits::default()
                }
            ),
            ARCHIVE_OK
        );
        read.open_client(&a, Box::new(Memory::new(input, input.len())))
            .unwrap();
        let mut sevenzip = SevenZip {
            header_bytes_remaining: input.len() as i64,
            ..SevenZip::default()
        };
        let mut r = read.reader(&a);
        assert!(matches!(sevenzip.read_pack_info(&mut r), Err(Fail::Bad)));
        assert_eq!(r.budget.check().unwrap_err().errno, libc::EFBIG);
        assert_eq!(sevenzip.header_bytes_remaining, 4);
    }
}
