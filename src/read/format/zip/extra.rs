/*-
 * Copyright (c) 2004-2013 Tim Kientzle
 * Copyright (c) 2011-2012,2014 Michihiro NAKAJIMA
 * Copyright (c) 2013 Konrad Kleine
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

// Ported from libarchive/archive_read_support_format_zip.c.

//! The entry record the zip reader keeps, and the extra fields that fill it.

use crate::archive::*;
use crate::entry::{AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFMT, AE_IFREG, Entry, Mode};
use crate::read::ARCHIVE_ERRNO_FILE_FORMAT;
use crate::string::{StringConv, conversion_from_charset};
use crate::time::ntfs_to_unix;
use crate::util::Error;
use std::sync::{Arc, PoisonError};

// Bits used in zip_flags.
pub(super) const ZIP_ENCRYPTED: u16 = 1 << 0;
/// Also called "Streaming bit".
pub(super) const ZIP_LENGTH_AT_END: u16 = 1 << 3;
pub(super) const ZIP_STRONG_ENCRYPTED: u16 = 1 << 6;
pub(super) const ZIP_UTF8_NAME: u16 = 1 << 11;
/// See "7.2 Single Password Symmetric Encryption Method"
/// in http://www.pkware.com/documents/casestudies/APPNOTE.TXT
pub(super) const ZIP_CENTRAL_DIRECTORY_ENCRYPTED: u16 = 1 << 13;

// Bits used in flags.
pub(super) const LA_USED_ZIP64: u8 = 1 << 0;
pub(super) const LA_FROM_CENTRAL_DIRECTORY: u8 = 1 << 1;
pub(super) const LA_MTIME_FROM_EXTRA: u8 = 1 << 2;
pub(super) const LA_ATIME_FROM_EXTRA: u8 = 1 << 3;
pub(super) const LA_CTIME_FROM_EXTRA: u8 = 1 << 4;
pub(super) const LA_NTFS_MTIME: u8 = 1 << 5;
pub(super) const LA_NTFS_ATIME: u8 = 1 << 6;
pub(super) const LA_NTFS_BTIME: u8 = 1 << 7;

/// Value used in compression method.
pub(super) const WINZIP_AES_ENCRYPTION: u8 = 99;
pub(super) const AES_VENDOR_AE_2: u32 = 0x0002;

/// The WinZip AES encryption extra field, which should be available when
/// the compression is 99.
#[derive(Clone, Copy, Default)]
pub(super) struct AesExtra {
    /// Vendor version: AE-1 is 0x0001, AE-2 is 0x0002.
    pub vendor: u32,
    /// AES encryption strength: 1 is 128 bits, 2 is 192 bits, 3 is 256 bits.
    pub strength: u32,
    /// Actual compression method.
    pub compression: u8,
}

/// `struct zip_entry`: what is known about one entry, from the central
/// directory and the local file header.
#[derive(Clone, Default)]
pub(super) struct ZipEntry {
    pub local_header_offset: i64,
    pub compressed_size: i64,
    pub uncompressed_size: i64,
    pub gid: i64,
    pub uid: i64,
    pub rsrcname: Option<Vec<u8>>,
    pub mtime: i64,
    pub atime: i64,
    pub ctime: i64,
    /// File creation time, from an NTFS extra field only.
    pub btime: i64,
    /// Nanosecond precision, from an NTFS extra field only.
    pub mtime_ns: u32,
    pub atime_ns: u32,
    pub btime_ns: u32,
    pub crc32: u32,
    pub mode: u16,
    /// From the GP flags field.
    pub zip_flags: u16,
    pub compression: u8,
    /// From "version written by".
    pub system: u8,
    /// Our extra markers.
    pub flags: u8,
    /// Used for the decryption check.
    pub decdat: u8,
    pub aes: AesExtra,
}

impl ZipEntry {
    /// `zip_entry_size_is_set`: true if this entry has declared a specific
    /// uncompressed size.
    pub fn size_is_set(&self) -> bool {
        self.zip_flags & ZIP_LENGTH_AT_END == 0
            || (self.uncompressed_size > 0 && self.uncompressed_size != 0xffff_ffff)
    }

    pub fn length_at_end(&self) -> bool {
        self.zip_flags & ZIP_LENGTH_AT_END != 0
    }

    /// The mode a Unix or MS-DOS "external file attributes" field gives.
    pub fn mode_from_attributes(&self, external_attributes: u32) -> u16 {
        if self.system == 3 {
            (external_attributes >> 16) as u16
        } else if self.system == 0 {
            // Interpret MSDOS directory bit
            let mut mode = if external_attributes & 0x10 == 0x10 {
                IFDIR | 0o775
            } else {
                IFREG | 0o664
            };
            if external_attributes & 0x01 == 0x01 {
                // Read-only bit; strip write permissions
                mode &= 0o555;
            }
            mode
        } else {
            0
        }
    }
}

/// A file type constant as the 16 bits a zip entry stores for the mode.
#[allow(clippy::unnecessary_cast, clippy::identity_op)] // mode_t is 16 bits on some platforms
const fn mode_bits(m: Mode) -> u16 {
    (m & 0xffff) as u16
}

pub(super) const IFMT: u16 = mode_bits(AE_IFMT);
pub(super) const IFREG: u16 = mode_bits(AE_IFREG);
pub(super) const IFDIR: u16 = mode_bits(AE_IFDIR);
pub(super) const IFLNK: u16 = mode_bits(AE_IFLNK);
pub(super) const IFIFO: u16 = mode_bits(AE_IFIFO);

pub(super) fn le16(p: &[u8], off: usize) -> u16 {
    off.checked_add(2)
        .and_then(|end| p.get(off..end))
        .and_then(|b| b.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

pub(super) fn le32(p: &[u8], off: usize) -> u32 {
    off.checked_add(4)
        .and_then(|end| p.get(off..end))
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

pub(super) fn le64(p: &[u8], off: usize) -> u64 {
    off.checked_add(8)
        .and_then(|end| p.get(off..end))
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

/// Interprets a raw 32-bit Unix timestamp, preferring the signed
/// (pre-1970-capable) reading unless it would land before 1960, in which
/// case the unsigned (post-2038-capable) reading is used instead.
/// See https://github.com/libarchive/libarchive/issues/3550.
fn to_time_t(raw: u32) -> i64 {
    const YEAR_1960_OFFSET: i32 = (10 * 365 + 3) * 24 * 60 * 60;
    let t = raw as i32;
    if t >= -YEAR_1960_OFFSET {
        i64::from(t)
    } else {
        i64::from(raw)
    }
}

fn failed(msg: impl Into<Vec<u8>>) -> Error {
    Error::new(ARCHIVE_FAILED, ARCHIVE_ERRNO_FILE_FORMAT, msg)
}

/// What `process_extra` needs from the reader besides the entry record.
pub(super) struct ExtraContext<'a> {
    pub a: &'a Base,
    /// The converter for UTF-8 names, made when first needed.
    pub sconv_utf8: &'a mut Option<Arc<StringConv>>,
    pub ignore_crc32: bool,
}

/// A time of the entry's, set from an extra field unless an NTFS field has
/// already given a more precise one.
fn set_time(ze: &mut ZipEntry, raw: u32, which: u8) {
    let t = to_time_t(raw);
    match which {
        LA_ATIME_FROM_EXTRA => {
            ze.atime = t;
            ze.atime_ns = 0;
        }
        _ => {
            ze.mtime = t;
            ze.mtime_ns = 0;
        }
    }
    ze.flags |= which;
}

/// `process_extra`: the extra data is stored as a list of
/// id1+size1+data1 + id2+size2+data2 ... triplets. id and size are 2 bytes
/// each. `entry` is the archive entry the Info-ZIP Unicode path replaces the
/// name of. `p` is the extra data, `extra_length` bytes long.
pub(super) fn process_extra(
    cx: &mut ExtraContext<'_>,
    mut entry: Option<&mut Entry>,
    p: &[u8],
    ze: &mut ZipEntry,
) -> Result<(), Error> {
    let extra_length = p.len();
    if extra_length == 0 {
        return Ok(());
    }

    if extra_length < 4 {
        // Some ZIP files may have trailing 0 bytes. Let's check they
        // are all 0 and ignore them instead of returning an error.
        //
        // This is not technically correct, but some ZIP files look
        // like this and other tools support those files - so let's
        // also  support them.
        if p.iter().any(|&b| b != 0) {
            return Err(failed(format!(
                "Too-small extra data: Need at least 4 bytes, but only found {extra_length} bytes"
            )));
        }
        return Ok(());
    }

    let mut offset = 0usize;
    while offset <= extra_length - 4 {
        let headerid = le16(p, offset);
        let mut datasize = usize::from(le16(p, offset + 2));

        offset += 4;
        if offset + datasize > extra_length {
            return Err(failed(format!(
                "Extra data overflow: Need {datasize} bytes but only found {} bytes",
                extra_length - offset
            )));
        }
        match headerid {
            0x0001 => {
                // Zip64 extended information extra field.
                ze.flags |= LA_USED_ZIP64;
                if ze.uncompressed_size == 0xffff_ffff {
                    ze.uncompressed_size = zip64_value(p, offset, datasize, "uncompressed size")?;
                    offset += 8;
                    datasize -= 8;
                }
                if ze.compressed_size == 0xffff_ffff {
                    ze.compressed_size = zip64_value(p, offset, datasize, "compressed size")?;
                    offset += 8;
                    datasize -= 8;
                }
                if ze.local_header_offset == 0xffff_ffff {
                    ze.local_header_offset =
                        zip64_value(p, offset, datasize, "local header offset")?;
                    offset += 8;
                    datasize -= 8;
                }
                // le32(p + offset) gives disk on which file starts, but we
                // don't handle multi-volume Zip files.
            }
            0x000a => {
                // NTFS Extra Field: 4 reserved bytes, then one or more
                // Tag(2)/Size(2)/Data(Size) attribute blocks. Only Tag 1
                // (size 24: Mtime, Atime, Ctime, each an 8-byte Windows
                // FILETIME) is defined; skip any other tag, per spec.
                // Unlike every other ZIP timestamp source, FILETIME has no
                // negative/pre-epoch ambiguity (it's unsigned ticks since
                // 1601), and it's 100ns-precision rather than 1-second, so
                // it also supplies mtime_ns/atime_ns. "Ctime" here is
                // Windows creation time, not POSIX ctime, so it maps to
                // btime.
                let mut sub_offset = offset;
                let mut sub_remaining = datasize;

                if sub_remaining >= 4 {
                    sub_offset += 4;
                    sub_remaining -= 4;

                    while sub_remaining >= 4 {
                        let tag = le16(p, sub_offset);
                        let size = usize::from(le16(p, sub_offset + 2));
                        sub_offset += 4;
                        sub_remaining -= 4;
                        if size > sub_remaining {
                            break;
                        }
                        if tag == 1 && size == 24 {
                            // A raw FILETIME of 0 marks a slot the writer
                            // didn't have a value for (see the matching
                            // comment in archive_write_set_format_zip.c);
                            // treat it as absent rather than decoding it as
                            // 1601-01-01.
                            let raw = le64(p, sub_offset);
                            if raw != 0 {
                                let (secs, nsecs) = ntfs_to_unix(raw);
                                ze.mtime = secs;
                                ze.mtime_ns = nsecs;
                                ze.flags |= LA_NTFS_MTIME | LA_MTIME_FROM_EXTRA;
                            }

                            let raw = le64(p, sub_offset + 8);
                            if raw != 0 {
                                let (secs, nsecs) = ntfs_to_unix(raw);
                                ze.atime = secs;
                                ze.atime_ns = nsecs;
                                ze.flags |= LA_NTFS_ATIME | LA_ATIME_FROM_EXTRA;
                            }

                            let raw = le64(p, sub_offset + 16);
                            if raw != 0 {
                                let (secs, nsecs) = ntfs_to_unix(raw);
                                ze.btime = secs;
                                ze.btime_ns = nsecs;
                                ze.flags |= LA_NTFS_BTIME;
                            }
                        }
                        sub_offset += size;
                        sub_remaining -= size;
                    }
                }
            }
            0x000d => {
                // PKWARE Unix Extra Field fixed metadata.
                if datasize >= 12 {
                    if ze.flags & LA_NTFS_ATIME == 0 {
                        set_time(ze, le32(p, offset), LA_ATIME_FROM_EXTRA);
                    }
                    if ze.flags & LA_NTFS_MTIME == 0 {
                        set_time(ze, le32(p, offset + 4), LA_MTIME_FROM_EXTRA);
                    }
                    ze.uid = i64::from(le16(p, offset + 8));
                    ze.gid = i64::from(le16(p, offset + 10));
                    // APPNOTE.TXT also defines additional data after this
                    // fixed metadata, depending on file type.
                }
            }
            0x5455 => 'arm: {
                // Extended time field "UT".
                if datasize == 0 {
                    return Err(failed("Incomplete extended time field"));
                }
                let flags = p.get(offset).copied().unwrap_or(0);
                offset += 1;
                datasize -= 1;
                // Flag bits indicate which dates are present.
                if flags & 0x01 != 0 {
                    if datasize < 4 {
                        break 'arm;
                    }
                    if ze.flags & LA_NTFS_MTIME == 0 {
                        set_time(ze, le32(p, offset), LA_MTIME_FROM_EXTRA);
                    }
                    offset += 4;
                    datasize -= 4;
                }
                if flags & 0x02 != 0 {
                    if datasize < 4 {
                        break 'arm;
                    }
                    if ze.flags & LA_NTFS_ATIME == 0 {
                        set_time(ze, le32(p, offset), LA_ATIME_FROM_EXTRA);
                    }
                    offset += 4;
                    datasize -= 4;
                }
                if flags & 0x04 != 0 {
                    if datasize < 4 {
                        break 'arm;
                    }
                    ze.ctime = to_time_t(le32(p, offset));
                    ze.flags |= LA_CTIME_FROM_EXTRA;
                    offset += 4;
                    datasize -= 4;
                }
            }
            0x5855 => {
                // Info-ZIP Unix Extra Field (old version) "UX".
                if datasize >= 8 {
                    if ze.flags & LA_NTFS_ATIME == 0 {
                        set_time(ze, le32(p, offset), LA_ATIME_FROM_EXTRA);
                    }
                    if ze.flags & LA_NTFS_MTIME == 0 {
                        set_time(ze, le32(p, offset + 4), LA_MTIME_FROM_EXTRA);
                    }
                }
                if datasize >= 12 {
                    ze.uid = i64::from(le16(p, offset + 8));
                    ze.gid = i64::from(le16(p, offset + 10));
                }
            }
            0x6c78 => 'arm: {
                // Experimental 'xl' field
                //
                // Introduced Dec 2013 to provide a way to include external
                // file attributes (and other fields that ordinarily appear
                // only in central directory) in local file header. This
                // provides file type and permission information necessary
                // to support full streaming extraction. Currently being
                // discussed with other Zip developers ... subject to change.
                //
                // Format:
                //  The field starts with a bitmap that specifies which
                //  additional fields are included. The bitmap is variable
                //  length and can be extended in the future.
                //
                //  n bytes - feature bitmap: first byte has low-order 7
                //    bits. If high-order bit is set, a subsequent byte
                //    holds the next 7 bits, etc.
                //
                //  if bitmap & 1, 2 byte "version made by"
                //  if bitmap & 2, 2 byte "internal file attributes"
                //  if bitmap & 4, 4 byte "external file attributes"
                //  if bitmap & 8, 2 byte comment length + n byte comment
                if datasize < 1 {
                    break 'arm;
                }
                let mut bitmap_last = p.get(offset).copied().unwrap_or(0);
                let bitmap = bitmap_last;
                offset += 1;
                datasize -= 1;

                // We only support first 7 bits of bitmap; skip rest.
                while bitmap_last & 0x80 != 0 && datasize >= 1 {
                    bitmap_last = p.get(offset).copied().unwrap_or(0);
                    offset += 1;
                    datasize -= 1;
                }

                if bitmap & 1 != 0 {
                    // 2 byte "version made by"
                    if datasize < 2 {
                        break 'arm;
                    }
                    ze.system = (le16(p, offset) >> 8) as u8;
                    offset += 2;
                    datasize -= 2;
                }
                if bitmap & 2 != 0 {
                    // 2 byte "internal file attributes", not used by
                    // libarchive at present.
                    if datasize < 2 {
                        break 'arm;
                    }
                    offset += 2;
                    datasize -= 2;
                }
                if bitmap & 4 != 0 {
                    // 4 byte "external file attributes"
                    if datasize < 4 {
                        break 'arm;
                    }
                    ze.mode = ze.mode_from_attributes(le32(p, offset));
                    offset += 4;
                    datasize -= 4;
                }
                if bitmap & 8 != 0 {
                    // 2 byte comment length + comment
                    if datasize < 2 {
                        break 'arm;
                    }
                    let comment_length = usize::from(le16(p, offset));
                    offset += 2;
                    datasize -= 2;

                    if datasize < comment_length {
                        break 'arm;
                    }
                    // Comment is not supported by libarchive
                    offset += comment_length;
                    datasize -= comment_length;
                }
            }
            0x7075 => 'arm: {
                // Info-ZIP Unicode Path Extra Field.
                let Some(entry) = entry.as_deref_mut() else {
                    break 'arm;
                };
                if datasize < 5 {
                    break 'arm;
                }
                offset += 5;
                datasize -= 5;

                // The path name in this field is always encoded in UTF-8.
                if cx.sconv_utf8.is_none() {
                    let made = {
                        let mut cache = cx.a.conv.lock().unwrap_or_else(PoisonError::into_inner);
                        conversion_from_charset(Some(&mut *cache), b"UTF-8", true)
                    };
                    match made {
                        Ok(sc) => *cx.sconv_utf8 = Some(sc),
                        Err(e) => {
                            // If the converter from UTF-8 is not available,
                            // then the path name from the main field will
                            // more likely be correct.
                            cx.a.set_error(e.errno, Some(&e.message));
                            break 'arm;
                        }
                    }
                }

                // Make sure the CRC32 of the filename matches.
                if !cx.ignore_crc32
                    && let Some(cp) = entry.pathname()
                {
                    let file_crc = crate::crc32::crc32(0, cp.to_bytes());
                    let utf_crc = le32(p, offset - 4);
                    if file_crc != utf_crc {
                        break 'arm;
                    }
                }

                // Ignore the error, and fall back to the path name from the
                // main field.
                let name = p.get(offset..offset + datasize).unwrap_or_default();
                let _ = entry.copy_pathname_l(name, cx.sconv_utf8.as_deref());
            }
            0x7855 => {
                // Info-ZIP Unix Extra Field (type 2) "Ux".
                if datasize >= 2 {
                    ze.uid = i64::from(le16(p, offset));
                }
                if datasize >= 4 {
                    ze.gid = i64::from(le16(p, offset + 2));
                }
            }
            0x7875 => {
                // Info-Zip Unix Extra Field (type 3) "ux".
                // TODO: support arbitrary uidsize/gidsize.
                if datasize >= 1 && p.get(offset) == Some(&1) {
                    // version=1
                    let mut uidsize = 0usize;
                    if datasize >= 4 {
                        // get a uid size.
                        uidsize = usize::from(p.get(offset + 1).copied().unwrap_or(0));
                        if uidsize == 2 {
                            ze.uid = i64::from(le16(p, offset + 2));
                        } else if uidsize == 4 && datasize >= 6 {
                            ze.uid = i64::from(le32(p, offset + 2));
                        }
                    }
                    if datasize >= 2 + uidsize + 3 {
                        // get a gid size.
                        let gidsize =
                            usize::from(p.get(offset + 2 + uidsize).copied().unwrap_or(0));
                        if gidsize == 2 {
                            ze.gid = i64::from(le16(p, offset + 2 + uidsize + 1));
                        } else if gidsize == 4 && datasize >= 2 + uidsize + 5 {
                            ze.gid = i64::from(le32(p, offset + 2 + uidsize + 1));
                        }
                    }
                }
            }
            0x9901 => {
                // WinZip AES extra data field.
                if datasize < 6 {
                    return Err(failed("Incomplete AES field"));
                }
                if p.get(offset + 2) == Some(&b'A') && p.get(offset + 3) == Some(&b'E') {
                    // Vendor version.
                    ze.aes.vendor = u32::from(le16(p, offset));
                    // AES encryption strength.
                    ze.aes.strength = u32::from(p.get(offset + 4).copied().unwrap_or(0));
                    // Actual compression method.
                    ze.aes.compression = p.get(offset + 5).copied().unwrap_or(0);
                }
            }
            _ => {}
        }
        offset += datasize;
    }
    Ok(())
}

/// A 64-bit value of the zip64 extra field, which must fit a signed 64-bit
/// integer.
fn zip64_value(p: &[u8], offset: usize, datasize: usize, what: &str) -> Result<i64, Error> {
    if datasize >= 8
        && let Ok(t) = i64::try_from(le64(p, offset))
    {
        return Ok(t);
    }
    Err(failed(format!("Malformed 64-bit {what}")))
}
