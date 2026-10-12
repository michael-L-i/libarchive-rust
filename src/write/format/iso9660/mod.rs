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

//! The ISO9660 writer. Upstream's sections map to submodules: `tree`
//! (isofile/isoent and the directory tree), `idr` (identifiers), `record`
//! (Directory Records and Rock Ridge), `descriptor` (volume descriptors,
//! path tables and the image layout), `boot` (El Torito) and `zisofs`.
//! Upstream's linked lists are vectors of arena indices (`FileId`,
//! `EntId`), except the path tables' `ptnext` chains, whose sharing between
//! lists after deep-directory relocation is part of the behavior.

use crate::archive::{
    ARCHIVE_ERRNO_MISC, ARCHIVE_FAILED, ARCHIVE_FATAL, ARCHIVE_OK, ARCHIVE_WARN, Base,
};
use crate::entry::{AE_IFLNK, AE_IFREG, Cache, Entry};
use crate::string::StringConv;
use crate::util::Error;
use crate::write::{Format, Sink};
use std::collections::BTreeMap;
use std::ffi::{CStr, c_int};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

mod boot;
mod descriptor;
mod idr;
mod record;
mod tree;
mod zisofs;

const LOGICAL_BLOCK_BITS: u32 = 11;
const LOGICAL_BLOCK_SIZE: usize = 2048;
const PATH_TABLE_BLOCK_SIZE: usize = 4096;

const SYSTEM_AREA_BLOCK: i32 = 16;
const PRIMARY_VOLUME_DESCRIPTOR_BLOCK: i32 = 1;
const SUPPLEMENTARY_VOLUME_DESCRIPTOR_BLOCK: i32 = 1;
const BOOT_RECORD_DESCRIPTOR_BLOCK: i32 = 1;
const VOLUME_DESCRIPTOR_SET_TERMINATOR_BLOCK: i32 = 1;
const NON_ISO_FILE_SYSTEM_INFORMATION_BLOCK: i32 = 1;
const RRIP_ER_BLOCK: i32 = 1;
const PADDING_BLOCK: i32 = 150;

const MULTI_EXTENT_SIZE: i64 = 1 << 32; // 4Gi bytes.
const MAX_DEPTH: i32 = 8;

/// The write buffer: file data on its way to the temporary file, then the
/// image on its way out.
const WB_BUFFMAX: usize = LOGICAL_BLOCK_SIZE * 32;

/// What `archive_write` hands `finish_entry` to pad an entry: `a->nulls`.
const NULLS: [u8; 1024] = [0; 1024];

type FileId = usize;
type EntId = usize;

/// One extent of a file's contents. A file over 4 GiB has more than one.
#[derive(Clone, Copy, Default)]
struct Content {
    offset_of_temp: i64,
    size: i64,
    blocks: i32,
    location: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Boot {
    No,
    Catalog,
    Image,
}

/// The RRIP 'ZF' fields of a file.
#[derive(Clone, Copy, Default)]
struct ZisofsHeader {
    header_size: u8,
    log2_bs: u8,
    uncompressed_size: u32,
}

/// `struct isofile`: an entry shared by the primary and Joliet trees.
struct IsoFile {
    hardlink_target: Option<FileId>,
    entry: Entry,
    // Used for making a directory tree.
    parentdir: Vec<u8>,
    basename: Vec<u8>,
    basename_utf16: Vec<u8>,
    symlink: Vec<u8>,
    /// The number of elements of its parent directory.
    dircnt: i32,
    /// `content` and the extents chained after it.
    content: Vec<Content>,
    /// `cur_content`: an index into `content`, `None` where upstream's
    /// pointer has run off the end of the chain.
    cur_content: Option<usize>,
    write_content: bool,
    boot: Boot,
    zisofs: ZisofsHeader,
}

#[derive(Clone, Copy, Default)]
struct DrLen {
    vd: i32,
    self_: i32,
    parent: i32,
    normal: i32,
}

/// An extra record: a block of Rock Ridge data that didn't fit its
/// Directory Record, reached through a "CE" entry.
struct ExtrRec {
    location: i32,
    offset: i32,
    buf: Box<[u8; LOGICAL_BLOCK_SIZE]>,
}

/// `struct isoent`: a node of the primary or the Joliet tree.
struct IsoEnt {
    file: FileId,
    parent: EntId,
    children: Vec<EntId>,
    /// `rbtree`: the children by basename.
    child_names: BTreeMap<Vec<u8>, EntId>,
    subdirs: Vec<EntId>,
    children_sorted: Vec<EntId>,
    ptnext: Option<EntId>,

    // Used for making a Directory Record.
    dir_number: i32,
    dr_len: DrLen,
    dir_location: u32,
    dir_block: i32,

    /// On primary, the ISO9660 file/directory name; on Joliet, the UCS2
    /// name, as a NUL-terminated buffer of upstream's allocation size.
    /// ext_off: offset of identifier extension.
    /// ext_len: length of identifier extension.
    /// id_len: byte size of identifier; on primary, this is ext_off +
    ///   ext_len + version length; on joliet, this is ext_off + ext_len.
    /// mb_len: length of multibyte-character of identifier; on primary,
    ///   mb_len and id_len are always the same.
    identifier: Option<Vec<u8>>,
    ext_off: i32,
    ext_len: i32,
    id_len: i32,
    mb_len: i32,

    // Used for making a Rockridge extension.
    rr_parent: Option<EntId>,
    rr_child: Option<EntId>,

    /// The extra records of this directory's entries.
    extr_rec_list: Vec<ExtrRec>,
    extr_rec_current: Option<usize>,

    r#virtual: bool,
    /// If set, this file type is a directory.
    dir: bool,
}

struct Hardlink {
    nlink: u32,
    /// The hardlink target first, then the files linked to it.
    file_list: Vec<FileId>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VddType {
    Primary,
    Joliet,
    Enhanced,
}

#[derive(Default)]
struct PathTable {
    first: Option<EntId>,
    last: Option<EntId>,
    sorted: Vec<EntId>,
    cnt: i32,
}

/// Which of the two trees.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Which {
    Primary,
    Joliet,
}

/// Used for making the Path Table Record.
struct Vdd {
    /// The root of entry tree. Joliet's is set when the tree is cloned.
    rootent: EntId,
    vdd_type: VddType,
    pathtbl: Vec<PathTable>,
    max_depth: i32,
    path_table_block: i32,
    path_table_size: i32,
    location_type_l_path_table: i32,
    location_type_m_path_table: i32,
    total_dir_block: i32,
}

impl Vdd {
    fn new(vdd_type: VddType) -> Self {
        Vdd {
            rootent: 0,
            vdd_type,
            pathtbl: Vec::new(),
            max_depth: 0,
            path_table_block: 0,
            path_table_size: 0,
            location_type_l_path_table: 0,
            location_type_m_path_table: 0,
            total_dir_block: 0,
        }
    }
}

/// Used for making zisofs.
struct Zisofs {
    detect_magic: bool,
    making: bool,
    allzero: bool,
    magic_buffer: [u8; 64],
    magic_cnt: i32,

    /// The block pointers, little-endian, in a buffer that only grows.
    block_pointers: Vec<u8>,
    block_pointers_cnt: i32,
    block_pointers_idx: i32,
    total_size: i64,
    block_offset: i64,

    /// The deflate stream once `stream_valid`, and its `total_in`.
    stream: Option<deflate::Deflate>,
    total_in: u64,
    remaining: i64,
    compression_level: i32,
}

/// 'El Torito' boot data.
struct ElTorito {
    // boot catalog file
    catalog_filename: Vec<u8>,
    catalog: Option<EntId>,
    // boot image file
    boot_filename: Vec<u8>,
    boot: Option<EntId>,

    platform_id: u8,
    id: Vec<u8>,
    media_type: u8,
    system_type: u8,
    boot_load_seg: u16,
    boot_load_size: u16,
}

const BOOT_PLATFORM_X86: u8 = 0;
const BOOT_MEDIA_NO_EMULATION: u8 = 0;
const BOOT_MEDIA_1_2M_DISKETTE: u8 = 1;
const BOOT_MEDIA_1_44M_DISKETTE: u8 = 2;
const BOOT_MEDIA_2_88M_DISKETTE: u8 = 3;
const BOOT_MEDIA_HARD_DISK: u8 = 4;
const BOOT_LOAD_SIZE: u16 = 4;

/// ISO writer options. Each flag says whether the option was given; the
/// values live with what they configure.
struct IsoOption {
    abstract_file: bool,
    application_id: bool,
    allow_vernum: bool,
    biblio_file: bool,
    boot: bool,
    boot_catalog: bool,
    boot_info_table: bool,
    boot_load_seg: bool,
    boot_load_size: bool,
    boot_type: u8,
    compression_level: bool,
    copyright_file: bool,
    iso_level: u8,
    joliet: u8,
    limit_depth: bool,
    limit_dirs: bool,
    pad: bool,
    publisher: bool,
    rr: u8,
    volume_id: bool,
    zisofs: bool,
}

const ABSTRACT_FILE_SIZE: usize = 37;
const APPLICATION_IDENTIFIER_SIZE: usize = 128;
const BIBLIO_FILE_SIZE: usize = 37;
const COPYRIGHT_FILE_SIZE: usize = 37;
const PUBLISHER_IDENTIFIER_SIZE: usize = 128;
const VOLUME_IDENTIFIER_SIZE: usize = 32;

const OPT_BOOT_TYPE_AUTO: u8 = 0; // auto detect
const OPT_BOOT_TYPE_NO_EMU: u8 = 1; // ``no emulation'' image
const OPT_BOOT_TYPE_FD: u8 = 2; // floppy disk image
const OPT_BOOT_TYPE_HARD_DISK: u8 = 3; // hard disk image

const OPT_JOLIET_DISABLE: u8 = 0; // Not generate Joliet Records.
const OPT_JOLIET_ENABLE: u8 = 1; // Generate Joliet Records.
const OPT_JOLIET_LONGNAME: u8 = 2; // Use long joliet filenames.

const OPT_RR_DISABLED: u8 = 0;
const OPT_RR_STRICT: u8 = 1;
const OPT_RR_USEFUL: u8 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum WbType {
    ToStream,
    ToTemp,
}

pub struct Iso9660 {
    /// The creation time of ISO image.
    birth_time: i64,
    /// A temporary file, which file contents save to until ISO image can
    /// be created.
    temp: Option<File>,

    cur_file: Option<FileId>,
    cur_dirent: EntId,
    cur_dirstr: Vec<u8>,
    bytes_remaining: u64,
    need_multi_extent: bool,

    // Temporary string buffers for the Joliet extension.
    utf16be: Vec<u8>,
    mbs: Vec<u8>,

    sconv_to_utf16be: Option<Arc<StringConv>>,
    sconv_from_utf16be: Option<Arc<StringConv>>,
    /// The archive's string conversions, for entries made here
    /// (`archive_entry_new2`) and for the UTF-16BE converters.
    conv: Option<Cache>,

    /// All isofiles, in creation order (`all_file_list` and the files
    /// upstream frees right away).
    files: Vec<IsoFile>,
    /// All isoents of both trees.
    ents: Vec<IsoEnt>,
    /// Files which have contents and are not a directory, a hardlinked
    /// file or a symlink file.
    data_file_list: Vec<FileId>,
    /// Used for managing to find hardlinking files.
    hardlinks: BTreeMap<Vec<u8>, Hardlink>,

    primary: Vdd,
    joliet: Vdd,

    // Used for making a Volume Descriptor.
    volume_space_size: i32,
    volume_sequence_number: i32,
    total_file_block: i32,
    volume_identifier: Vec<u8>,
    publisher_identifier: Vec<u8>,
    data_preparer_identifier: Vec<u8>,
    application_identifier: Vec<u8>,
    copyright_file_identifier: Vec<u8>,
    abstract_file_identifier: Vec<u8>,
    bibliographic_file_identifier: Vec<u8>,

    /// Used for making rockridge extensions.
    location_rrip_er: i32,

    zisofs: Zisofs,

    directories_too_deep: Option<EntId>,
    dircnt_max: i32,

    // Write buffer.
    wbuff: Vec<u8>,
    wbuff_remaining: usize,
    wbuff_type: WbType,
    wbuff_offset: i64,
    wbuff_written: i64,
    wbuff_tail: i64,

    el_torito: ElTorito,
    opt: IsoOption,
}

fn misc(msg: impl Into<Vec<u8>>) -> Error {
    Error::fatal(ARCHIVE_ERRNO_MISC, msg)
}

/// A pathname for a message, as printf shows a NULL `%s`.
fn shown(path: Option<&CStr>) -> Vec<u8> {
    path.map_or(b"(null)".to_vec(), |p| p.to_bytes().to_vec())
}

/// `strlen` of a NUL-terminated buffer, bounded by the buffer.
fn strlen(s: &[u8]) -> usize {
    s.iter().position(|&b| b == 0).unwrap_or(s.len())
}

fn temp_error(e: &std::io::Error) -> c_int {
    e.raw_os_error().unwrap_or(libc::EIO)
}

/// `write(2)` all of `b` to the temporary file.
fn write_to_temp(temp: &mut Option<File>, b: &[u8]) -> Result<(), Error> {
    if b.is_empty() {
        return Ok(());
    }
    let Some(f) = temp.as_mut() else {
        return Err(Error::fatal(libc::EBADF, "Can't write to temporary file"));
    };
    f.write_all(b)
        .map_err(|e| Error::fatal(temp_error(&e), "Can't write to temporary file"))
}

/// `lseek(2)`, whose failure upstream ignores.
fn temp_seek(temp: &mut Option<File>, off: i64) {
    if let (Some(f), Ok(off)) = (temp.as_mut(), u64::try_from(off)) {
        let _ = f.seek(SeekFrom::Start(off));
    }
}

/// `read(2)` from the temporary file: the count, or -1 and the errno.
fn temp_read(temp: &mut Option<File>, buf: &mut [u8]) -> Result<usize, (i64, c_int)> {
    let Some(f) = temp.as_mut() else {
        return Err((-1, libc::EBADF));
    };
    loop {
        match f.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err((-1, temp_error(&e))),
        }
    }
}

/// "Can't read temporary file(%jd)" for a read that returned `rs`.
fn read_error(rs: i64, errno: c_int) -> Error {
    Error::fatal(errno, format!("Can't read temporary file({rs})"))
}

impl Default for Iso9660 {
    /// `archive_write_set_format_iso9660`.
    fn default() -> Self {
        let mut iso9660 = Iso9660 {
            birth_time: 0,
            temp: None,
            cur_file: None,
            cur_dirent: 0,
            cur_dirstr: Vec::new(),
            bytes_remaining: 0,
            need_multi_extent: false,
            utf16be: Vec::new(),
            mbs: Vec::new(),
            sconv_to_utf16be: None,
            sconv_from_utf16be: None,
            conv: None,
            files: Vec::new(),
            ents: Vec::new(),
            data_file_list: Vec::new(),
            hardlinks: BTreeMap::new(),
            primary: Vdd::new(VddType::Primary),
            joliet: Vdd::new(VddType::Joliet),
            volume_space_size: 0,
            volume_sequence_number: 0,
            total_file_block: 0,
            // Init Identifiers used for PVD and SVD.
            volume_identifier: b"CDROM".to_vec(),
            publisher_identifier: Vec::new(),
            data_preparer_identifier: Vec::new(),
            application_identifier: crate::util::VERSION_STRING.to_bytes().to_vec(),
            copyright_file_identifier: Vec::new(),
            abstract_file_identifier: Vec::new(),
            bibliographic_file_identifier: Vec::new(),
            location_rrip_er: 0,
            zisofs: Zisofs {
                detect_magic: false,
                making: false,
                allzero: false,
                magic_buffer: [0; 64],
                magic_cnt: 0,
                block_pointers: Vec::new(),
                block_pointers_cnt: 0,
                block_pointers_idx: 0,
                total_size: 0,
                block_offset: 0,
                stream: None,
                total_in: 0,
                remaining: 0,
                compression_level: 9,
            },
            directories_too_deep: None,
            dircnt_max: 1,
            wbuff: vec![0; WB_BUFFMAX],
            wbuff_remaining: WB_BUFFMAX,
            wbuff_type: WbType::ToTemp,
            wbuff_offset: 0,
            wbuff_written: 0,
            wbuff_tail: 0,
            // Init El Torito bootable CD variables.
            el_torito: ElTorito {
                // Set default file name of boot catalog
                catalog_filename: b"boot.catalog".to_vec(),
                catalog: None,
                boot_filename: Vec::new(),
                boot: None,
                platform_id: BOOT_PLATFORM_X86,
                id: Vec::new(),
                media_type: 0,
                system_type: 0,
                boot_load_seg: 0,
                boot_load_size: BOOT_LOAD_SIZE,
            },
            // Set default value of iso9660 options.
            opt: IsoOption {
                abstract_file: false,
                application_id: false,
                allow_vernum: true,
                biblio_file: false,
                boot: false,
                boot_catalog: false,
                boot_info_table: false,
                boot_load_seg: false,
                boot_load_size: false,
                boot_type: OPT_BOOT_TYPE_AUTO,
                compression_level: false,
                copyright_file: false,
                iso_level: 1,
                joliet: OPT_JOLIET_ENABLE,
                limit_depth: true,
                limit_dirs: true,
                pad: true,
                publisher: false,
                rr: OPT_RR_USEFUL,
                volume_id: false,
                zisofs: false,
            },
        };
        // Create the root directory. Its pathname is empty, so making it
        // cannot fail.
        if let Ok(root) = iso9660.isoent_create_virtual_dir(b"") {
            iso9660.ents[root].parent = root;
            iso9660.primary.rootent = root;
            iso9660.cur_dirent = root;
        }
        iso9660
    }
}

/// get_str_opt(): a string option of at most `maxsize` bytes.
fn get_str_opt(
    s: &mut Vec<u8>,
    maxsize: usize,
    key: &[u8],
    value: Option<&[u8]>,
) -> Result<(), Error> {
    // Upstream's strlen() of a value the option parser left NULL (a
    // "!key") dereferences NULL; refuse it like an empty number.
    let Some(value) = value else {
        return Err(misc(
            [b"Invalid value(empty) for option ``", key, b"''"].concat(),
        ));
    };
    if value.len() > maxsize {
        let mut msg =
            format!("Value is longer than {maxsize} characters for option ``").into_bytes();
        msg.extend_from_slice(key);
        msg.extend_from_slice(b"''");
        return Err(misc(msg));
    }
    *s = value.to_vec();
    Ok(())
}

/// get_num_opt(): a decimal option between `low` and `high`.
fn get_num_opt(high: i32, low: i32, key: &[u8], value: Option<&[u8]>) -> Result<i32, Error> {
    let fail = |text: &str| {
        let (head, tail) = text.split_once("%s").unwrap_or((text, ""));
        misc([head.as_bytes(), key, tail.as_bytes()].concat())
    };
    let Some(mut p) = value else {
        return Err(fail("Invalid value(empty) for option ``%s''"));
    };
    let mut data: i32 = 0;
    let mut neg = false;
    if p.first() == Some(&b'-') {
        neg = true;
        p = &p[1..];
    }
    for &c in p {
        if c.is_ascii_digit() {
            data = data * 10 + i32::from(c - b'0');
        } else {
            return Err(fail("Invalid value for option ``%s''"));
        }
        if data > high {
            return Err(fail(&format!(
                "Invalid value(over {high}) for option ``%s''"
            )));
        }
        if data < low {
            return Err(fail(&format!(
                "Invalid value(under {low}) for option ``%s''"
            )));
        }
    }
    Ok(if neg { -data } else { data })
}

impl Iso9660 {
    /// iso9660_options(). `Ok(ARCHIVE_WARN)` tells the options supervisor
    /// we didn't handle the option.
    fn iso9660_options(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<c_int, Error> {
        let invalid_value = || {
            Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_MISC,
                [b"Invalid value for option ``", key, b"''"].concat(),
            )
        };
        match key {
            b"abstract-file" => {
                let r = get_str_opt(
                    &mut self.abstract_file_identifier,
                    ABSTRACT_FILE_SIZE,
                    key,
                    value,
                );
                self.opt.abstract_file = r.is_ok();
                r?;
            }
            b"application-id" => {
                let r = get_str_opt(
                    &mut self.application_identifier,
                    APPLICATION_IDENTIFIER_SIZE,
                    key,
                    value,
                );
                self.opt.application_id = r.is_ok();
                r?;
            }
            b"allow-vernum" => self.opt.allow_vernum = value.is_some(),
            b"biblio-file" => {
                let r = get_str_opt(
                    &mut self.bibliographic_file_identifier,
                    BIBLIO_FILE_SIZE,
                    key,
                    value,
                );
                self.opt.biblio_file = r.is_ok();
                r?;
            }
            b"boot" => match value {
                None => self.opt.boot = false,
                Some(v) => {
                    self.opt.boot = true;
                    self.el_torito.boot_filename = v.to_vec();
                }
            },
            b"boot-catalog" => {
                let r = get_str_opt(&mut self.el_torito.catalog_filename, 1024, key, value);
                self.opt.boot_catalog = r.is_ok();
                r?;
            }
            b"boot-info-table" => self.opt.boot_info_table = value.is_some(),
            b"boot-load-seg" => {
                self.opt.boot_load_seg = false;
                let Some(mut p) = value else {
                    return Err(invalid_value());
                };
                let mut seg: u32 = 0;
                if p.len() >= 2 && p[0] == b'0' && (p[1] == b'x' || p[1] == b'X') {
                    p = &p[2..];
                }
                for &c in p {
                    if seg != 0 {
                        seg <<= 4;
                    }
                    seg += match c {
                        b'A'..=b'F' => u32::from(c - b'A') + 0x0a,
                        b'a'..=b'f' => u32::from(c - b'a') + 0x0a,
                        b'0'..=b'9' => u32::from(c - b'0'),
                        _ => return Err(invalid_value()),
                    };
                    if seg > 0xffff {
                        return Err(misc(
                            [b"Invalid value(over 0xffff) for option ``", key, b"''"].concat(),
                        ));
                    }
                }
                self.el_torito.boot_load_seg = seg as u16;
                self.opt.boot_load_seg = true;
            }
            b"boot-load-size" => {
                let r = get_num_opt(0xffff, 1, key, value);
                self.opt.boot_load_size = r.is_ok();
                self.el_torito.boot_load_size = r? as u16;
            }
            b"boot-type" => {
                self.opt.boot_type = match value {
                    Some(b"no-emulation") => OPT_BOOT_TYPE_NO_EMU,
                    Some(b"fd") => OPT_BOOT_TYPE_FD,
                    Some(b"hard-disk") => OPT_BOOT_TYPE_HARD_DISK,
                    _ => return Err(invalid_value()),
                }
            }
            b"compression-level" => match value {
                Some(&[c]) if c.is_ascii_digit() => {
                    self.zisofs.compression_level = i32::from(c - b'0');
                    self.opt.compression_level = true;
                }
                _ => return Err(invalid_value()),
            },
            b"copyright-file" => {
                let r = get_str_opt(
                    &mut self.copyright_file_identifier,
                    COPYRIGHT_FILE_SIZE,
                    key,
                    value,
                );
                self.opt.copyright_file = r.is_ok();
                r?;
            }
            b"iso-level" => match value {
                Some(&[c @ b'1'..=b'4']) => self.opt.iso_level = c - b'0',
                _ => return Err(invalid_value()),
            },
            b"joliet" => {
                self.opt.joliet = match value {
                    None => OPT_JOLIET_DISABLE,
                    Some(b"1") => OPT_JOLIET_ENABLE,
                    Some(b"long") => OPT_JOLIET_LONGNAME,
                    _ => return Err(invalid_value()),
                }
            }
            b"limit-depth" => self.opt.limit_depth = value.is_some(),
            b"limit-dirs" => self.opt.limit_dirs = value.is_some(),
            b"pad" => self.opt.pad = value.is_some(),
            b"publisher" => {
                let r = get_str_opt(
                    &mut self.publisher_identifier,
                    PUBLISHER_IDENTIFIER_SIZE,
                    key,
                    value,
                );
                self.opt.publisher = r.is_ok();
                r?;
            }
            // Upstream also tests for "Rockridge", but under its switch on
            // the first letter, 'r', so that key is never recognized.
            b"rockridge" => {
                self.opt.rr = match value {
                    None => OPT_RR_DISABLED,
                    Some(b"1") | Some(b"useful") => OPT_RR_USEFUL,
                    Some(b"strict") => OPT_RR_STRICT,
                    _ => return Err(invalid_value()),
                }
            }
            b"volume-id" => {
                let r = get_str_opt(
                    &mut self.volume_identifier,
                    VOLUME_IDENTIFIER_SIZE,
                    key,
                    value,
                );
                self.opt.volume_id = r.is_ok();
                r?;
            }
            b"zisofs" => self.opt.zisofs = value.is_some(),
            // Note: The "warn" return is just to inform the options
            // supervisor that we didn't handle it. It will generate a
            // suitable error if no one used this option.
            _ => return Ok(ARCHIVE_WARN),
        }
        Ok(ARCHIVE_OK)
    }

    /// iso9660_write_header().
    fn iso9660_write_header(
        &mut self,
        a: &Base,
        entry: &Entry,
        out: &mut dyn Sink,
    ) -> Result<c_int, Error> {
        let mut ret = ARCHIVE_OK;

        self.cur_file = None;
        self.bytes_remaining = 0;
        self.need_multi_extent = false;
        if entry.filetype() == AE_IFLNK && self.opt.rr == OPT_RR_DISABLED {
            a.set_error(ARCHIVE_ERRNO_MISC, Some(b"Ignore symlink file"));
            return Ok(ARCHIVE_WARN);
        }
        if entry.filetype() == AE_IFREG && entry.size() >= MULTI_EXTENT_SIZE {
            if self.opt.iso_level < 3 {
                let msg =
                    format!("Ignore over {MULTI_EXTENT_SIZE} bytes file. This file too large");
                a.set_error(ARCHIVE_ERRNO_MISC, Some(msg.as_bytes()));
                return Ok(ARCHIVE_WARN);
            }
            self.need_multi_extent = true;
        }

        let file = self.isofile_new(Some(entry));
        let r = self.isofile_gen_utility_names(Some(a), file)?;
        ret = ret.min(r);

        // Ignore a path which looks like the top of directory name since we
        // have already made the root directory of an ISO image.
        if self.files[file].parentdir.is_empty() && self.files[file].basename.is_empty() {
            return Ok(r);
        }

        let mut isoent = self.isoent_new(file);
        if self.files[file].dircnt > self.dircnt_max {
            self.dircnt_max = self.files[file].dircnt;
        }

        // Add the current file into tree
        isoent = self.isoent_tree(isoent)?;

        // If there is the same file in tree and the current file is older
        // than the file in tree. So we don't need the current file data
        // anymore.
        if self.ents[isoent].file != file {
            return Ok(ARCHIVE_OK);
        }

        // Non regular files contents are unneeded to be saved to temporary
        // files.
        if self.files[file].entry.filetype() != AE_IFREG {
            return Ok(ret);
        }

        // Set the current file to cur_file to read its contents.
        self.cur_file = Some(file);

        if self.files[file].entry.nlink() > 1 {
            self.isofile_register_hardlink(file);
        }

        // Prepare to save the contents of the file.
        if self.temp.is_none() {
            self.temp = Some(
                crate::write::temp_file()
                    .map_err(|e| Error::fatal(e.errno, "Couldn't create temporary file"))?,
            );
        }

        // Save an offset of current file in temporary file.
        let offset = self.wb_offset();
        let f = &mut self.files[file];
        f.content[0].offset_of_temp = offset;
        f.cur_content = Some(0);
        self.zisofs_init(out, file)?;
        self.bytes_remaining = self.files[file].entry.size() as u64;

        Ok(ret)
    }

    /// The current file and its current extent.
    fn cur_content(&mut self) -> Result<&mut Content, Error> {
        self.cur_file
            .and_then(|f| {
                let file = self.files.get_mut(f)?;
                file.content.get_mut(file.cur_content?)
            })
            .ok_or_else(|| misc("No current file content"))
    }

    fn write_iso9660_data(&mut self, out: &mut dyn Sink, mut buff: &[u8]) -> Result<usize, Error> {
        let s = buff.len();
        if self.temp.is_none() {
            return Err(misc("Couldn't create temporary file"));
        }

        let mut ws = s as i64;
        let size = self.cur_content()?.size;
        if self.need_multi_extent && size + ws >= MULTI_EXTENT_SIZE - LOGICAL_BLOCK_SIZE as i64 {
            let ts = (MULTI_EXTENT_SIZE - LOGICAL_BLOCK_SIZE as i64 - size) as usize;
            let head = buff.get(..ts).ok_or_else(|| misc("Invalid extent size"))?;

            if self.zisofs.detect_magic {
                self.zisofs_check_magic(out, head)?;
            }

            if self.zisofs.making {
                self.zisofs_write_to_temp(out, head)?;
            } else {
                self.wb_write_to_temp(out, head)?;
                self.cur_content()?.size += ts as i64;
            }

            // Write padding.
            let size = self.cur_content()?.size;
            self.wb_write_padding_to_temp(out, size)?;

            // Compute the logical block number.
            let c = self.cur_content()?;
            c.blocks = ((c.size + LOGICAL_BLOCK_SIZE as i64 - 1) >> LOGICAL_BLOCK_BITS) as i32;

            // Make next extent.
            ws -= ts as i64;
            buff = &buff[ts..];
            // Make a content for next extent.
            let con = Content {
                offset_of_temp: self.wb_offset(),
                ..Content::default()
            };
            if let Some(f) = self.cur_file {
                let file = &mut self.files[f];
                file.content.push(con);
                file.cur_content = Some(file.content.len() - 1);
            }
            self.zisofs.block_offset = 0;
        }

        if self.zisofs.detect_magic {
            self.zisofs_check_magic(out, buff)?;
        }

        if self.zisofs.making {
            self.zisofs_write_to_temp(out, buff)?;
        } else {
            self.wb_write_to_temp(out, buff)?;
            self.cur_content()?.size += ws;
        }

        Ok(s)
    }

    fn iso9660_write_data(&mut self, out: &mut dyn Sink, buff: &[u8]) -> Result<usize, Error> {
        let Some(f) = self.cur_file else {
            return Ok(0);
        };
        if self.files[f].entry.filetype() != AE_IFREG {
            return Ok(0);
        }
        let s = (buff.len() as u64).min(self.bytes_remaining) as usize;
        if s == 0 {
            return Ok(0);
        }

        let r = self.write_iso9660_data(out, &buff[..s])?;
        self.bytes_remaining -= r as u64;
        Ok(r)
    }

    fn iso9660_finish_entry(&mut self, out: &mut dyn Sink) -> Result<(), Error> {
        let Some(f) = self.cur_file else {
            return Ok(());
        };
        if self.files[f].entry.filetype() != AE_IFREG {
            return Ok(());
        }
        if self.files[f].content[0].size == 0 {
            return Ok(());
        }

        // If there are unwritten data, write null data instead.
        while self.bytes_remaining > 0 {
            let s = self.bytes_remaining.min(NULLS.len() as u64) as usize;
            self.write_iso9660_data(out, &NULLS[..s])?;
            self.bytes_remaining -= s as u64;
        }

        if self.zisofs.making {
            self.zisofs_finish_entry(out)?;
        }

        // Write padding.
        let size = self.cur_content()?.size;
        self.wb_write_padding_to_temp(out, size)?;

        // Compute the logical block number.
        let c = self.cur_content()?;
        c.blocks = ((c.size + LOGICAL_BLOCK_SIZE as i64 - 1) >> LOGICAL_BLOCK_BITS) as i32;

        // Add the current file to data file list.
        self.data_file_list.push(f);

        Ok(())
    }

    fn iso9660_close(&mut self, a: Option<&Base>, out: &mut dyn Sink) -> Result<(), Error> {
        // Write remaining data out to the temporary file.
        if self.wbuff_remaining > 0 {
            self.wb_write_out(out)?;
        }

        // Preparations...
        self.birth_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);

        // Prepare a bootable ISO image.
        if self.opt.boot {
            // Find out the boot file entry.
            self.isoent_find_out_boot_file()?;
            // Reconvert the boot file from zisofs'ed form to plain form.
            self.zisofs_rewind_boot_file(out)?;
            // Write remaining data out to the temporary file.
            if self.wbuff_remaining > 0 {
                self.wb_write_out(out)?;
            }
            // Create the boot catalog.
            self.isoent_create_boot_catalog(a)?;
        }

        // Prepare joliet extensions.
        if self.opt.joliet != 0 {
            // Make a new tree for joliet.
            self.joliet.rootent = self.isoent_clone_tree(self.primary.rootent);
            // Make sure we have UTF-16BE converters. if there is no file
            // entry, converters are still uninitialized.
            self.make_utf16be_converters()?;
        }

        // Make Path Tables.
        self.isoent_make_path_table()?;

        // Calculate a total volume size and setup all locations of contents
        // of an iso9660 image.
        let mut blocks = SYSTEM_AREA_BLOCK
            + PRIMARY_VOLUME_DESCRIPTOR_BLOCK
            + VOLUME_DESCRIPTOR_SET_TERMINATOR_BLOCK
            + NON_ISO_FILE_SYSTEM_INFORMATION_BLOCK;
        if self.opt.boot {
            blocks += BOOT_RECORD_DESCRIPTOR_BLOCK;
        }
        if self.opt.joliet != 0 {
            blocks += SUPPLEMENTARY_VOLUME_DESCRIPTOR_BLOCK;
        }
        if self.opt.iso_level == 4 {
            blocks += SUPPLEMENTARY_VOLUME_DESCRIPTOR_BLOCK;
        }

        // Setup the locations of Path Table.
        self.primary.location_type_l_path_table = blocks;
        blocks = blocks.wrapping_add(self.primary.path_table_block);
        self.primary.location_type_m_path_table = blocks;
        blocks = blocks.wrapping_add(self.primary.path_table_block);
        if self.opt.joliet != 0 {
            self.joliet.location_type_l_path_table = blocks;
            blocks = blocks.wrapping_add(self.joliet.path_table_block);
            self.joliet.location_type_m_path_table = blocks;
            blocks = blocks.wrapping_add(self.joliet.path_table_block);
        }

        // Setup the locations of directories.
        self.isoent_setup_directory_location(blocks, Which::Primary)?;
        blocks = blocks.wrapping_add(self.primary.total_dir_block);
        if self.opt.joliet != 0 {
            self.isoent_setup_directory_location(blocks, Which::Joliet)?;
            blocks = blocks.wrapping_add(self.joliet.total_dir_block);
        }

        if self.opt.rr != 0 {
            self.location_rrip_er = blocks;
            blocks = blocks.wrapping_add(RRIP_ER_BLOCK);
        }

        // Setup the locations of all file contents.
        self.isoent_setup_file_location(blocks)?;
        blocks = blocks.wrapping_add(self.total_file_block);
        if self.opt.boot && self.opt.boot_info_table {
            self.setup_boot_information()?;
        }

        // Now we have a total volume size.
        self.volume_space_size = blocks;
        if self.opt.pad {
            self.volume_space_size = self.volume_space_size.wrapping_add(PADDING_BLOCK);
        }
        self.volume_sequence_number = 1;

        // Write an ISO 9660 image.
        self.write_image(out)
    }

    fn make_utf16be_converters(&mut self) -> Result<(), Error> {
        if self.sconv_to_utf16be.is_some() {
            return Ok(());
        }
        let conv = self.conv.clone();
        let mut guard = conv
            .as_ref()
            .map(|c| c.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        let to = crate::string::conversion_to_charset(guard.as_deref_mut(), b"UTF-16BE", true)
            .map_err(|e| Error::fatal(e.errno, e.message))?;
        let from = crate::string::conversion_from_charset(guard.as_deref_mut(), b"UTF-16BE", true)
            .map_err(|e| Error::fatal(e.errno, e.message))?;
        self.sconv_to_utf16be = Some(to);
        self.sconv_from_utf16be = Some(from);
        Ok(())
    }

    // Manage to write ISO-image data with wbuff to reduce calling
    // __archive_write_output() for performance.

    /// wb_buffptr(): where the next byte goes in `wbuff`.
    fn wb_buffptr(&self) -> usize {
        WB_BUFFMAX - self.wbuff_remaining
    }

    fn wb_offset(&self) -> i64 {
        self.wbuff_offset + (WB_BUFFMAX - self.wbuff_remaining) as i64
    }

    fn wb_write_out(&mut self, out: &mut dyn Sink) -> Result<(), Error> {
        let wsize = WB_BUFFMAX - self.wbuff_remaining;
        let nw = wsize % LOGICAL_BLOCK_SIZE;
        let r = if self.wbuff_type == WbType::ToStream {
            out.write(&self.wbuff[..wsize - nw])
        } else {
            write_to_temp(&mut self.temp, &self.wbuff[..wsize - nw])
        };
        // Increase the offset.
        self.wbuff_offset += (wsize - nw) as i64;
        if self.wbuff_offset > self.wbuff_written {
            self.wbuff_written = self.wbuff_offset;
        }
        self.wbuff_remaining = WB_BUFFMAX;
        if nw != 0 {
            self.wbuff_remaining -= nw;
            self.wbuff.copy_within(wsize - nw..wsize, 0);
        }
        r
    }

    fn wb_consume(&mut self, out: &mut dyn Sink, size: usize) -> Result<(), Error> {
        if size > self.wbuff_remaining || self.wbuff_remaining == 0 {
            return Err(misc(format!(
                "Internal Programming error: iso9660:wb_consume() size={size}, wbuff_remaining={}",
                self.wbuff_remaining
            )));
        }
        self.wbuff_remaining -= size;
        if self.wbuff_remaining < LOGICAL_BLOCK_SIZE {
            return self.wb_write_out(out);
        }
        Ok(())
    }

    fn wb_set_offset(&mut self, out: &mut dyn Sink, off: i64) -> Result<(), Error> {
        if self.wbuff_type != WbType::ToTemp {
            return Err(misc("Internal Programming error: iso9660:wb_set_offset()"));
        }

        let mut used = WB_BUFFMAX - self.wbuff_remaining;
        if self.wbuff_offset + used as i64 > self.wbuff_tail {
            self.wbuff_tail = self.wbuff_offset + used as i64;
        }
        if self.wbuff_offset < self.wbuff_written {
            write_to_temp(&mut self.temp, &self.wbuff[..used])?;
            self.wbuff_offset = self.wbuff_written;
            temp_seek(&mut self.temp, self.wbuff_offset);
            self.wbuff_remaining = WB_BUFFMAX;
            used = 0;
        }
        if off < self.wbuff_offset {
            // Write out waiting data.
            if used > 0 {
                self.wb_write_out(out)?;
            }
            temp_seek(&mut self.temp, off);
            self.wbuff_offset = off;
            self.wbuff_remaining = WB_BUFFMAX;
        } else if off <= self.wbuff_tail {
            // Upstream's remaining count wraps when `off` is past the
            // buffer, and its buffer pointer leaves the buffer.
            self.wbuff_remaining = usize::try_from(off - self.wbuff_offset)
                .ok()
                .and_then(|d| WB_BUFFMAX.checked_sub(d))
                .ok_or_else(|| misc("Internal Programming error: iso9660:wb_set_offset()"))?;
        } else {
            let mut ext_bytes = off - self.wbuff_tail;
            self.wbuff_remaining = usize::try_from(self.wbuff_tail - self.wbuff_offset)
                .ok()
                .and_then(|d| WB_BUFFMAX.checked_sub(d))
                .ok_or_else(|| misc("Internal Programming error: iso9660:wb_set_offset()"))?;
            while ext_bytes >= self.wbuff_remaining as i64 {
                let n = self.wbuff_remaining;
                self.write_null(out, n)?;
                ext_bytes -= self.wbuff_remaining as i64;
            }
            if ext_bytes > 0 {
                self.write_null(out, ext_bytes as usize)?;
            }
        }
        Ok(())
    }

    fn write_null(&mut self, out: &mut dyn Sink, mut size: usize) -> Result<(), Error> {
        let remaining = self.wbuff_remaining;
        let p = self.wb_buffptr();
        if size <= remaining {
            self.wbuff[p..p + size].fill(0);
            return self.wb_consume(out, size);
        }
        self.wbuff[p..].fill(0);
        self.wb_consume(out, remaining)?;
        size -= remaining;
        let old = p;
        let p = self.wb_buffptr();
        if old > p {
            self.wbuff[p..old].fill(0);
        }
        let remaining = self.wbuff_remaining;
        while size > 0 {
            let wsize = size.min(remaining);
            self.wb_consume(out, wsize)?;
            size -= wsize;
        }
        Ok(())
    }

    fn wb_write_to_temp(&mut self, out: &mut dyn Sink, buff: &[u8]) -> Result<(), Error> {
        let s = buff.len();
        let mut xp = 0;
        let mut xs = s;

        // If a written data size is big enough to use system-call and there
        // is no waiting data, this calls write_to_temp() in order to reduce
        // a extra memory copy.
        if self.wbuff_remaining == WB_BUFFMAX && s > 1024 * 16 {
            xs = s % LOGICAL_BLOCK_SIZE;
            self.wbuff_offset += (s - xs) as i64;
            write_to_temp(&mut self.temp, &buff[..s - xs])?;
            if xs == 0 {
                return Ok(());
            }
            xp += s - xs;
        }

        while xs > 0 {
            let size = xs.min(self.wbuff_remaining);
            let p = self.wb_buffptr();
            self.wbuff[p..p + size].copy_from_slice(&buff[xp..xp + size]);
            self.wb_consume(out, size)?;
            xs -= size;
            xp += size;
        }
        Ok(())
    }

    fn wb_write_padding_to_temp(&mut self, out: &mut dyn Sink, csize: i64) -> Result<(), Error> {
        let ns = csize.rem_euclid(LOGICAL_BLOCK_SIZE as i64) as usize;
        if ns != 0 {
            return self.write_null(out, LOGICAL_BLOCK_SIZE - ns);
        }
        Ok(())
    }
}

impl Format for Iso9660 {
    fn code(&self) -> c_int {
        0x40000
    }
    fn name(&self) -> &'static CStr {
        c"ISO9660"
    }
    fn module(&self) -> &'static [u8] {
        b"iso9660"
    }
    fn options(&mut self, _: &Base, key: &[u8], value: Option<&[u8]>) -> Result<c_int, Error> {
        self.iso9660_options(key, value)
    }
    fn header(&mut self, a: &Base, entry: &mut Entry, out: &mut dyn Sink) -> Result<c_int, Error> {
        self.conv.get_or_insert_with(|| a.conv.clone());
        self.iso9660_write_header(a, entry, out)
    }
    fn data(&mut self, data: &[u8], out: &mut dyn Sink) -> Result<usize, Error> {
        self.iso9660_write_data(out, data)
    }
    fn finish_entry(&mut self, out: &mut dyn Sink) -> Result<(), Error> {
        self.iso9660_finish_entry(out)
    }
    fn close_with_base(&mut self, a: &Base, out: &mut dyn Sink) -> Result<(), Error> {
        self.iso9660_close(Some(a), out)
    }
    fn close(&mut self, out: &mut dyn Sink) -> Result<(), Error> {
        self.iso9660_close(None, out)
    }
}

#[cfg(test)]
mod tests;
