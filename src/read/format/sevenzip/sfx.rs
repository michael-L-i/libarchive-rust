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

//! Finding the 7-Zip signature: at the start of the file, or after the
//! executable of a self-extracting (SFX) archive, PE (Windows) or ELF.

use super::*;
use crate::crc32::crc32;
use crate::read::Whence;

const SFX_MIN_ADDR: i64 = 0x27000;
const SFX_MAX_ADDR: i64 = 0x80000;
const SFX_MAX_OFFSET: i64 = SFX_MAX_ADDR - SFX_MIN_ADDR;
const SFX_MAX_SEEK: i64 = 0x800000;

// PE format.
const PE_DOS_HDR_LEN: usize = 0x40;
const PE_DOS_HDR_ELFANEW_OFFSET: usize = 0x3c;
const PE_COFF_HDR_LEN: usize = 0x18;
const PE_COFF_HDR_SEC_CNT_OFFSET: usize = 0x6;
const PE_COFF_HDR_OPT_SZ_OFFSET: usize = 0x14;
const PE_SEC_HDR_LEN: usize = 0x28;
const PE_SEC_HDR_RAW_ADDR_OFFSET: usize = 0x14;
const PE_SEC_HDR_RAW_SZ_OFFSET: usize = 0x10;

// ELF format.
/// `sizeof(Elf64_Ehdr)`.
const ELF_HDR_MIN_LEN: usize = 0x40;
const ELF_HDR_EI_CLASS_OFFSET: usize = 0x04;
const ELF_HDR_EI_DATA_OFFSET: usize = 0x05;

const ELF_MAGIC: &[u8; 4] = b"\x7F\x45LF";

fn le16(h: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(h.get(at..at + 2)?.try_into().ok()?))
}

fn le32(h: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(h.get(at..at + 4)?.try_into().ok()?))
}

/// The ELF fields, in the file's byte order.
#[derive(Clone, Copy)]
struct Dec {
    big_endian: bool,
}

impl Dec {
    fn u16(self, h: &[u8], at: usize) -> Option<u16> {
        let b: [u8; 2] = h.get(at..at + 2)?.try_into().ok()?;
        Some(if self.big_endian {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        })
    }

    fn u32(self, h: &[u8], at: usize) -> Option<u32> {
        let b: [u8; 4] = h.get(at..at + 4)?.try_into().ok()?;
        Some(if self.big_endian {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    }

    fn u64(self, h: &[u8], at: usize) -> Option<u64> {
        let b: [u8; 8] = h.get(at..at + 8)?.try_into().ok()?;
        Some(if self.big_endian {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        })
    }
}

/// Perform a seek to given position. If seeking is not supported, target
/// position is in front of current position, and compat is requested, try
/// to consume bytes until position is reached.
pub(super) fn seek_compat(
    r: &mut Reader<'_>,
    offset: i64,
    whence: Whence,
    compat: bool,
) -> Result<i64, Error> {
    if r.can_seek() {
        return r.seek(offset, whence);
    }
    let failed = Error::silent(ARCHIVE_FAILED);
    if !compat {
        return Err(failed);
    }
    match whence {
        Whence::Cur => r.consume(offset).map(|()| offset),
        Whence::Set => {
            let position = r.position();
            if position > offset {
                return Err(failed);
            }
            r.consume(offset - position).map(|()| offset - position)
        }
        Whence::End => Err(failed),
    }
}

/// `check_7zip_header_in_sfx`: how far to step if `p` (32 bytes) is not the
/// start of a 7-Zip header; 0 if it is.
fn check_7zip_header_in_sfx(p: &[u8]) -> usize {
    match p.get(5) {
        Some(0x1C) => {
            if p.get(..6) != Some(&SIGNATURE[..]) {
                return 6;
            }
            // Test the CRC because its extraction code has 7-Zip Magic Code,
            // so we should do this in order not to make a mis-detection.
            match (p.get(12..32), le32(p, 8)) {
                (Some(h), Some(crc)) if crc32(0, h) == crc => 0,
                _ => 6,
            }
        }
        Some(0x37) => 5,
        Some(0x7A) => 4,
        Some(0xBC) => 3,
        Some(0xAF) => 2,
        Some(0x27) => 1,
        _ => 6,
    }
}

/// `get_pe_sfx_offset`. `Err` is `ARCHIVE_FATAL`.
fn get_pe_sfx_offset(r: &mut Reader<'_>) -> Result<i64, ()> {
    // If encounter any weirdness, revert to old brute-force style search.
    let mut sfx_offset = SFX_MIN_ADDR;

    // Read Dos header to find e_lfanew.
    let h = r.read_ahead(PE_DOS_HDR_LEN).ok().flatten().ok_or(())?;
    let bytes = h.len() as i64;
    if h.first() != Some(&b'M') || h.get(1) != Some(&b'Z') {
        return Ok(sfx_offset);
    }
    let offset = i64::from(le32(h, PE_DOS_HDR_ELFANEW_OFFSET).ok_or(())?);
    if offset > SFX_MAX_SEEK {
        return Err(());
    }

    // Read COFF header to find opt header size and sec cnt.
    let mut h = h;
    let coff_end = offset + PE_COFF_HDR_LEN as i64;
    if bytes < coff_end {
        h = r.read_ahead(coff_end as usize).ok().flatten().ok_or(())?;
        let off = offset as usize;
        if h.get(off) != Some(&b'P') || h.get(off + 1) != Some(&b'E') {
            return Ok(sfx_offset);
        }
    }
    let off = offset as usize;
    let sec_cnt = le16(h, off + PE_COFF_HDR_SEC_CNT_OFFSET).ok_or(())?;
    let opt_hdr_sz = le16(h, off + PE_COFF_HDR_OPT_SZ_OFFSET).ok_or(())?;

    // Skip optional header.
    let mut offset = offset;
    if opt_hdr_sz != 0 {
        offset += PE_COFF_HDR_LEN as i64 + i64::from(opt_hdr_sz);
    } else {
        return Ok(sfx_offset);
    }

    let sec_end = offset + i64::from(sec_cnt) * PE_SEC_HDR_LEN as i64;
    if sec_end > SFX_MAX_SEEK {
        return Err(());
    }

    // Traverse sec table to find max raw offset (i.e., overlay).
    if bytes < sec_end {
        h = r.read_ahead(sec_end as usize).ok().flatten().ok_or(())?;
    }
    let mut max_offset = offset;
    let mut offset = offset as usize;
    for _ in 0..sec_cnt {
        let sec_end = i64::from(le32(h, offset + PE_SEC_HDR_RAW_SZ_OFFSET).ok_or(())?)
            + i64::from(le32(h, offset + PE_SEC_HDR_RAW_ADDR_OFFSET).ok_or(())?);
        if sec_end > max_offset {
            max_offset = sec_end;
        }
        offset += PE_SEC_HDR_LEN;
    }
    sfx_offset = max_offset;
    Ok(sfx_offset)
}

/// `get_elf_sfx_offset`. `Err` is `ARCHIVE_FATAL`.
fn get_elf_sfx_offset(r: &mut Reader<'_>, compat: bool) -> Result<i64, ()> {
    // If encounter any weirdness, revert to old brute-force style search.
    let mut sfx_offset = SFX_MIN_ADDR;
    let seek = |r: &mut Reader<'_>, offset: i64| {
        seek_compat(r, offset, Whence::Set, compat)
            .map(|_| ())
            .map_err(|_| ())
    };

    'search: {
        // Read Elf header to find bitness & endianness.
        let h = r.read_ahead(ELF_HDR_MIN_LEN).ok().flatten().ok_or(())?;
        if h.get(..4) != Some(&ELF_MAGIC[..]) {
            break 'search;
        }
        let format_64 = h.get(ELF_HDR_EI_CLASS_OFFSET) == Some(&0x2);
        let dec = Dec {
            big_endian: h.get(ELF_HDR_EI_DATA_OFFSET) == Some(&0x2),
        };

        // Read section header table info.
        let (e_shoff, e_shentsize, mut e_shnum, e_shstrndx);
        if format_64 {
            e_shoff = dec.u64(h, 0x28).ok_or(())?;
            e_shentsize = dec.u16(h, 0x3A).ok_or(())?;
            e_shnum = dec.u16(h, 0x3C).ok_or(())?;
            e_shstrndx = dec.u16(h, 0x3E).ok_or(())?;
            if e_shnum <= e_shstrndx || e_shentsize < 0x28 {
                break 'search;
            }
        } else {
            e_shoff = u64::from(dec.u32(h, 0x20).ok_or(())?);
            e_shentsize = dec.u16(h, 0x2E).ok_or(())?;
            e_shnum = dec.u16(h, 0x30).ok_or(())?;
            e_shstrndx = dec.u16(h, 0x32).ok_or(())?;
            if e_shnum <= e_shstrndx || e_shentsize < 0x18 {
                break 'search;
            }
        }

        let e_shoff = i64::try_from(e_shoff).map_err(|_| ())?;

        // Reading the section table to find strtab section.
        seek(r, e_shoff)?;
        let table = usize::from(e_shnum) * usize::from(e_shentsize);
        let request = table + if format_64 { 0x28 } else { 0x18 };
        if request > SFX_MAX_SEEK as usize {
            return Err(());
        }
        let h = r.read_ahead(request).ok().flatten().ok_or(())?;
        let at = usize::from(e_shstrndx) * usize::from(e_shentsize);
        let (strtab_offset, strtab_size) = if format_64 {
            (
                dec.u64(h, at + 0x18).ok_or(())?,
                dec.u64(h, at + 0x20).ok_or(())?,
            )
        } else {
            (
                u64::from(dec.u32(h, at + 0x10).ok_or(())?),
                u64::from(dec.u32(h, at + 0x14).ok_or(())?),
            )
        };
        let strtab_offset = i64::try_from(strtab_offset).map_err(|_| ())?;
        if strtab_size < 6 || strtab_size > SFX_MAX_SEEK as u64 {
            return Err(());
        }
        let strtab_size = strtab_size as usize;

        // Read the STRTAB section to find the .data offset.
        seek(r, strtab_offset)?;
        let h = r.read_ahead(strtab_size).ok().flatten().ok_or(())?;
        let Some(data_sym_offset) = h
            .get(..strtab_size)
            .ok_or(())?
            .windows(6)
            .position(|w| w == b".data\0")
        else {
            break 'search;
        };

        // Find the section with the .data name.
        seek(r, e_shoff)?;
        let h = r.read_ahead(table).ok().flatten().ok_or(())?;
        let mut sec_tbl_offset = 0usize;
        while e_shnum > 0 {
            let name_offset = dec.u32(h, sec_tbl_offset).ok_or(())?;
            if name_offset as usize == data_sym_offset {
                let sel_offset = if format_64 {
                    dec.u64(h, sec_tbl_offset + 0x18).ok_or(())? as i64
                } else {
                    i64::from(dec.u32(h, sec_tbl_offset + 0x10).ok_or(())?)
                };
                if sel_offset >= 0 {
                    sfx_offset = sel_offset;
                }
                break;
            }
            sec_tbl_offset += usize::from(e_shentsize);
            e_shnum -= 1;
        }
    }

    seek(r, 0)?;
    Ok(sfx_offset)
}

/// `get_data_offset`: where the 7-Zip signature header starts.
pub(super) fn get_data_offset(r: &mut Reader<'_>, compat: bool) -> Result<i64, Error> {
    let Some(h) = r.read_ahead(6).ok().flatten() else {
        return Err(Error::fatal(
            ARCHIVE_ERRNO_FILE_FORMAT,
            "Truncated 7-Zip file body",
        ));
    };

    // If first six bytes are the 7-Zip signature, return the offset right
    // now.
    if h.get(..6) == Some(&SIGNATURE[..]) {
        return Ok(0);
    }

    // It may be a 7-Zip SFX archive file. If first two bytes are 'M' and 'Z'
    // (PE, Windows) or first four bytes are "\x7F\x45LF" (ELF, Posix-like
    // systems), seek the 7-Zip signature. While get_pe_sfx_offset can be
    // performed without performing a seek, get_elf_sfx_offset requires one,
    // thus a performance difference between the two is expected.
    let sfx_offset = if h.starts_with(b"MZ") {
        get_pe_sfx_offset(r)
    } else if h.starts_with(ELF_MAGIC) {
        get_elf_sfx_offset(r, compat)
    } else {
        Err(())
    };
    if let Ok(sfx_offset) = sfx_offset
        && sfx_offset <= SFX_MAX_SEEK
        && let Some(offset) = scan_for_header(r, sfx_offset)
    {
        return Ok(offset);
    }
    Err(Error::fatal(
        ARCHIVE_ERRNO_FILE_FORMAT,
        "Couldn't find out 7-Zip header",
    ))
}

/// Looks for the signature header after `sfx_offset`.
fn scan_for_header(r: &mut Reader<'_>, sfx_offset: i64) -> Option<i64> {
    let max_readahead = sfx_offset + SFX_MAX_OFFSET;
    let mut offset = sfx_offset;
    let mut window = 4096i64;
    while offset + window <= max_readahead {
        let h = r.peek_available((offset + window) as usize).ok()?;
        let mut bytes_avail = h.len() as i64;
        if bytes_avail < offset + window {
            if bytes_avail >= offset + 32 {
                // Remaining bytes are less than window.
                window = bytes_avail - offset;
                continue;
            }
            return None;
        }
        bytes_avail = bytes_avail.min(max_readahead);
        while offset <= bytes_avail - 32 {
            let step = check_7zip_header_in_sfx(h.get(offset as usize..)?);
            if step == 0 {
                return Some(offset);
            }
            offset += step as i64;
        }
    }
    None
}
