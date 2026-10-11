/*-
 * Copyright (c) 2003-2010 Tim Kientzle
 * Copyright (c) 2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_write_disk_posix.c.

//! HFS decmpfs encoding: independent 64 KiB zlib blocks and resource headers.
use crate::ffi::disk_sys::Target;
use std::io::{Read, Seek, SeekFrom, Write};

const FOOTER: [u8; 50] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1c, 0, 0x32, 0, 0,
    b'c', b'm', b'p', b'f', 0, 0, 0, 0x0a, 0, 1, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub fn compress(target: &Target, size: u64) -> std::io::Result<()> {
    // Bound optional metadata buffers; larger files retain their ordinary data fork.
    if size == 0 || size > 256 * 1024 * 1024 {
        return Ok(());
    }
    let mut file = target.compression_file()?;
    let count = size.div_ceil(65536) as usize;
    let mut resource = Vec::new();
    resource
        .try_reserve_exact(size as usize + count + 264 + count * 8 + 50)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
    resource.resize(264 + count * 8, 0);
    resource[260..264].copy_from_slice(&(count as u32).to_le_bytes());
    let mut header = Vec::from(*b"fpmc");
    header.extend_from_slice(&4u32.to_le_bytes());
    header.extend_from_slice(&size.to_le_bytes());
    let mut buffer = vec![0; 65536];
    let mut remaining = size;
    // Upstream's decmpfs_compression_level.
    let mut zlib = deflate::Deflate::new(5, 15, 8).ok_or(std::io::ErrorKind::InvalidInput)?;
    for block in 0..count {
        let len = remaining.min(65536) as usize;
        file.read_exact(&mut buffer[..len])?;
        remaining -= len as u64;
        let mut compressed = Vec::new();
        zlib.reset();
        zlib.compress(&buffer[..len], &mut compressed)
            .map_err(|_| std::io::Error::other("Failed to compress data"))?;
        let bytes = if compressed.len() > len {
            let mut raw = Vec::with_capacity(len + 1);
            raw.push(0xff);
            raw.extend_from_slice(&buffer[..len]);
            raw
        } else {
            compressed
        };
        if count == 1 && bytes.len() + 16 <= 3802 {
            header[4..8].copy_from_slice(&3u32.to_le_bytes());
            header.extend_from_slice(&bytes);
            target.xattr(c"com.apple.decmpfs", &header)?;
            file.set_len(0)?;
            if let Err(error) = target.flags(libc::UF_COMPRESSED, 0) {
                let _ = target.flags(0, libc::UF_COMPRESSED);
                let _ = target.remove_xattr(c"com.apple.decmpfs");
                file.seek(SeekFrom::Start(0))?;
                file.write_all(&buffer[..len])?;
                return Err(error);
            }
            return Ok(());
        }
        let offset = resource.len() - 260;
        let record = 264 + block * 8;
        resource[record..record + 4].copy_from_slice(&(offset as u32).to_le_bytes());
        resource[record + 4..record + 8].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        resource.extend_from_slice(&bytes);
    }
    let bytes = resource.len();
    resource.extend_from_slice(&FOOTER);
    let blocks = (resource.len() as u64) >> 12;
    if blocks + (blocks >> 7) > size >> 12 {
        return Ok(());
    }
    resource[0..4].copy_from_slice(&256u32.to_be_bytes());
    resource[4..8].copy_from_slice(&(bytes as u32).to_be_bytes());
    resource[8..12].copy_from_slice(&((bytes - 256) as u32).to_be_bytes());
    resource[12..16].copy_from_slice(&50u32.to_be_bytes());
    resource[256..260].copy_from_slice(&((bytes - 260) as u32).to_be_bytes());
    file.seek(SeekFrom::Start(0))?;
    target.xattr(c"com.apple.ResourceFork", &resource)?;
    target.xattr(c"com.apple.decmpfs", &header)?;
    file.set_len(0)?;
    if let Err(error) = target.flags(libc::UF_COMPRESSED, 0) {
        let _ = target.flags(0, libc::UF_COMPRESSED);
        let _ = target.remove_xattr(c"com.apple.decmpfs");
        let _ = target.remove_xattr(c"com.apple.ResourceFork");
        file.seek(SeekFrom::Start(0))?;
        for block in 0..count {
            let record = 264 + block * 8;
            let at = u32::from_le_bytes(
                resource[record..record + 4]
                    .try_into()
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EIO))?,
            ) as usize
                + 260;
            let len = u32::from_le_bytes(
                resource[record + 4..record + 8]
                    .try_into()
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EIO))?,
            ) as usize;
            let bytes = resource
                .get(at..at + len)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EIO))?;
            if bytes.first() == Some(&0xff) {
                file.write_all(&bytes[1..])?;
            } else {
                let output = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(bytes, 65536)
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EIO))?;
                file.write_all(&output)?;
            }
        }
        return Err(error);
    }
    Ok(())
}
