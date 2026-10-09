/*-
 * Copyright (c) 2009-2012 Michihiro NAKAJIMA
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

// Ported from libarchive/archive_write_set_format_iso9660.c.

use crate::util::Error;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Media {
    NoEmulation,
    Floppy1200,
    Floppy1440,
    Floppy2880,
    HardDisk,
}
pub(super) struct Boot {
    pub filename: Vec<u8>,
    pub catalog: Vec<u8>,
    pub info_table: bool,
    pub load_segment: u16,
    pub load_size: u16,
    pub media: Media,
    pub system_type: u8,
    pub platform_id: u8,
    pub identifier: Vec<u8>,
}

pub(super) fn catalog(
    boot_extent: u32,
    _boot_size: u64,
    options: &Boot,
) -> Result<[u8; 2048], Error> {
    let mut bytes = [0; 2048];
    bytes[0] = 1;
    bytes[1] = options.platform_id;
    let n = options.identifier.len().min(23);
    bytes[4..4 + n].copy_from_slice(&options.identifier[..n]);
    bytes[30..32].copy_from_slice(&[0x55, 0xaa]);
    let sum = bytes[..32].chunks_exact(2).fold(0u16, |sum, word| {
        sum.wrapping_add(u16::from_le_bytes([word[0], word[1]]))
    });
    bytes[28..30].copy_from_slice(&0u16.wrapping_sub(sum).to_le_bytes());
    bytes[32] = 0x88;
    bytes[33] = match options.media {
        Media::NoEmulation => 0,
        Media::Floppy1200 => 1,
        Media::Floppy1440 => 2,
        Media::Floppy2880 => 3,
        Media::HardDisk => 4,
    };
    let no_emulation = options.media == Media::NoEmulation;
    let segment = if no_emulation {
        options.load_segment
    } else {
        0
    };
    bytes[34..36].copy_from_slice(&segment.to_le_bytes());
    bytes[36] = options.system_type;
    let sectors = if no_emulation { options.load_size } else { 1 };
    bytes[38..40].copy_from_slice(&sectors.to_le_bytes());
    bytes[40..44].copy_from_slice(&boot_extent.to_le_bytes());
    Ok(bytes)
}

pub(super) fn patch_info_table(
    file: &mut File,
    offset: u64,
    extent: u32,
    size: u64,
    recorded_size: u64,
) -> Result<(), Error> {
    if size <= 64 {
        return Err(Error::fatal(
            libc::EINVAL,
            format!("Boot file({size}) is too small"),
        ));
    }
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::fatal(libc::EOVERFLOW, "Boot image offset overflow"))?;
    let recorded_size = u32::try_from(recorded_size).map_err(|_| {
        Error::fatal(
            libc::EOVERFLOW,
            "Boot image size exceeds its information table",
        )
    })?;
    if file.metadata().map_err(io)?.len() < end {
        return Err(Error::fatal(libc::EINVAL, "Truncated boot image"));
    }
    file.seek(SeekFrom::Start(offset + 64)).map_err(io)?;
    let mut remaining = size - 64;
    let mut buffer = [0u8; 4096];
    let mut sum = 0u32;
    while remaining != 0 {
        let n = remaining.min(buffer.len() as u64) as usize;
        buffer.fill(0);
        file.read_exact(&mut buffer[..n]).map_err(io)?;
        for word in buffer[..n.div_ceil(4) * 4].chunks_exact(4) {
            sum = sum.wrapping_add(u32::from_le_bytes(word.try_into().unwrap()));
        }
        remaining -= n as u64;
    }
    let mut table = [0; 56];
    table[..4].copy_from_slice(&16u32.to_le_bytes());
    table[4..8].copy_from_slice(&extent.to_le_bytes());
    table[8..12].copy_from_slice(&recorded_size.to_le_bytes());
    table[12..16].copy_from_slice(&sum.to_le_bytes());
    file.seek(SeekFrom::Start(offset + 8)).map_err(io)?;
    file.write_all(&table).map_err(io)
}
fn io(e: std::io::Error) -> Error {
    Error::fatal(e.raw_os_error().unwrap_or(libc::EIO), e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validation_checksum_and_initial_entry() {
        let mut b = Boot {
            filename: b"boot.img".to_vec(),
            catalog: b"boot.catalog".to_vec(),
            info_table: true,
            load_segment: 0x7c0,
            load_size: 4,
            media: Media::NoEmulation,
            system_type: 0,
            platform_id: 0,
            identifier: b"publisher".to_vec(),
        };
        for (media, code) in [
            (Media::NoEmulation, 0),
            (Media::Floppy1200, 1),
            (Media::Floppy1440, 2),
            (Media::Floppy2880, 3),
            (Media::HardDisk, 4),
        ] {
            b.media = media;
            let c = catalog(123, 128, &b).unwrap();
            assert_eq!(
                c[..32].chunks_exact(2).fold(0u16, |s, v| s
                    .wrapping_add(u16::from_le_bytes([v[0], v[1]]))),
                0
            );
            assert_eq!(&c[30..34], &[0x55, 0xaa, 0x88, code]);
            assert_eq!(&c[40..44], &123u32.to_le_bytes());
            assert_eq!(
                u16::from_le_bytes([c[38], c[39]]),
                if code == 0 { 4 } else { 1 }
            );
        }
    }
    #[test]
    fn information_table_checksums_partial_words_and_rejects_truncation() {
        let mut file = crate::write::temp_file().unwrap();
        file.write_all(&[0; 64]).unwrap();
        file.write_all(&[1, 2, 3, 4, 5]).unwrap();
        patch_info_table(&mut file, 0, 73, 69, 1200 * 1024).unwrap();
        let mut table = [0; 56];
        file.seek(SeekFrom::Start(8)).unwrap();
        file.read_exact(&mut table).unwrap();
        assert_eq!(&table[..4], &16u32.to_le_bytes());
        assert_eq!(&table[4..8], &73u32.to_le_bytes());
        assert_eq!(&table[8..12], &(1200u32 * 1024).to_le_bytes());
        assert_eq!(&table[12..16], &(0x04030201u32 + 5).to_le_bytes());
        assert!(table[16..].iter().all(|&b| b == 0));
        assert!(patch_info_table(&mut file, 0, 1, 64, 64).is_err());
        assert!(patch_info_table(&mut file, 0, 1, 70, 70).is_err());
        assert!(patch_info_table(&mut file, u64::MAX, 1, 69, 69).is_err());
    }
}
