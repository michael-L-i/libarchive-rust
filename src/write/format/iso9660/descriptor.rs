// Ported from libarchive/archive_write_set_format_iso9660.c: the volume
// descriptors, the character sets and numbers they use, the path tables,
// the directory and file descriptors, and the layout of the image.

use super::record::{DirRecType, RRIP_DESCRIPTOR, RRIP_ER_SIZE, RRIP_IDENTIFIER, RRIP_SOURCE};
use super::*;

/// Types of Volume Descriptor
const VDT_BOOT_RECORD: u8 = 0; // Boot Record Volume Descriptor
const VDT_PRIMARY: u8 = 1; // Primary Volume Descriptor
const VDT_SUPPLEMENTARY: u8 = 2; // Supplementary Volume Descriptor
const VDT_TERMINATOR: u8 = 255; // Volume Descriptor Set Terminator

/// Kinds of Volume Descriptor Character
#[derive(Clone, Copy, PartialEq, Eq)]
enum Vdc {
    Std,
    Lowercase,
    Ucs2,
    Ucs2Direct,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CharType {
    A,
    D,
}

#[rustfmt::skip]
const A_CHARACTERS_MAP: [u8; 0x80] = [
/*  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F          */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 00-0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 10-1F */
    1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,/* 20-2F */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,/* 30-3F */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,/* 40-4F */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,/* 50-5F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 60-6F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 70-7F */
];

#[rustfmt::skip]
const A1_CHARACTERS_MAP: [u8; 0x80] = [
/*  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F          */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 00-0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 10-1F */
    1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,/* 20-2F */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,/* 30-3F */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,/* 40-4F */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,/* 50-5F */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,/* 60-6F */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,/* 70-7F */
];

#[rustfmt::skip]
pub(super) const D_CHARACTERS_MAP: [u8; 0x80] = [
/*  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F          */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 00-0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 10-1F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 20-2F */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,/* 30-3F */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,/* 40-4F */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,/* 50-5F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 60-6F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 70-7F */
];

#[rustfmt::skip]
pub(super) const D1_CHARACTERS_MAP: [u8; 0x80] = [
/*  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F          */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 00-0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 10-1F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,/* 20-2F */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,/* 30-3F */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,/* 40-4F */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,/* 50-5F */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,/* 60-6F */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,/* 70-7F */
];

pub(super) fn joliet_allowed_char(high: u8, low: u8) -> bool {
    let utf16 = (u16::from(high) << 8) | u16::from(low);
    if utf16 <= 0x001F {
        return false;
    }
    // '*', '/', ':', ';', '?' and '\' are not allowed.
    !matches!(utf16, 0x002A | 0x002F | 0x003A | 0x003B | 0x003F | 0x005C)
}

// set_num_7xx(): the wider numbers, as the bytes they occupy; the 8-bit
// ones of ISO9660 Standard 7.1 are plain bytes.

/// Least significant byte first. ISO9660 Standard 7.2.1
pub(super) fn num_721(value: u16) -> [u8; 2] {
    value.to_le_bytes()
}

/// Most significant byte first. ISO9660 Standard 7.2.2
fn num_722(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

/// Both-byte orders. ISO9660 Standard 7.2.3
pub(super) fn num_723(value: u16) -> [u8; 4] {
    let mut p = [0; 4];
    p[..2].copy_from_slice(&value.to_le_bytes());
    p[2..].copy_from_slice(&value.to_be_bytes());
    p
}

/// Least significant byte first. ISO9660 Standard 7.3.1
pub(super) fn num_731(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// Most significant byte first. ISO9660 Standard 7.3.2
fn num_732(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

/// Both-byte orders. ISO9660 Standard 7.3.3
pub(super) fn num_733(value: u32) -> [u8; 8] {
    let mut p = [0; 8];
    p[..4].copy_from_slice(&value.to_le_bytes());
    p[4..].copy_from_slice(&value.to_be_bytes());
    p
}

fn set_digit(p: &mut [u8], mut value: i32) {
    for d in p.iter_mut().rev() {
        *d = (i32::from(b'0') + value % 10) as u8;
        value /= 10;
    }
}

/// get_tmfromtime(): the local time and its offset from UTC. Upstream's
/// `struct tm` stays uninitialized if localtime_r() fails; this is zero.
fn get_tmfromtime(t: i64) -> (crate::ffi::sys::Tm, i64) {
    crate::ffi::sys::localtime_gmtoff(t).unwrap_or((
        crate::ffi::sys::Tm {
            year: 0,
            mon: 0,
            mday: 0,
            hour: 0,
            min: 0,
            sec: 0,
        },
        0,
    ))
}

/// Date and Time Format. ISO9660 Standard 8.4.26.1
fn set_date_time(t: i64) -> [u8; 17] {
    let (tm, gmtoff) = get_tmfromtime(t);
    let mut p = [0; 17];
    set_digit(&mut p[0..4], tm.year + 1900);
    set_digit(&mut p[4..6], tm.mon + 1);
    set_digit(&mut p[6..8], tm.mday);
    set_digit(&mut p[8..10], tm.hour);
    set_digit(&mut p[10..12], tm.min);
    set_digit(&mut p[12..14], tm.sec);
    set_digit(&mut p[14..16], 0);
    p[16] = (gmtoff / (60 * 15)) as i8 as u8;
    p
}

fn set_date_time_null() -> [u8; 17] {
    let mut p = [b'0'; 17];
    p[16] = 0;
    p
}

pub(super) fn set_time_915(t: i64) -> [u8; 7] {
    let (tm, gmtoff) = get_tmfromtime(t);
    [
        tm.year as u8,
        (tm.mon + 1) as u8,
        tm.mday as u8,
        tm.hour as u8,
        tm.min as u8,
        tm.sec as u8,
        (gmtoff / (60 * 15)) as i8 as u8,
    ]
}

/// Get the System Identifier
fn get_system_identifier() -> Vec<u8> {
    let mut id = crate::ffi::sys::uname_sysname().unwrap_or_default();
    id.truncate(255);
    id
}

/// set_str(): `s` up to its NUL into `p`, characters outside `map`
/// uppercased or replaced by '_', the rest of `p` filled with `f`.
fn set_str(p: &mut [u8], s: Option<&[u8]>, f: u8, map: &[u8; 0x80]) {
    let s = s.unwrap_or_default();
    let s = &s[..strlen(s)];
    let n = s.len().min(p.len());
    for (d, &c) in p.iter_mut().zip(s) {
        *d = if c >= 0x80 || map[usize::from(c)] == 0 {
            // illegal character
            if c.is_ascii_lowercase() {
                // convert c from a-z to A-Z
                c - 0x20
            } else {
                0x5f
            }
        } else {
            c
        };
    }
    // If l isn't zero, fill p buffer by the character which indicated by f.
    p[n..].fill(f);
}

/// A field of a volume descriptor: upstream's `bp + from` to `bp + to`,
/// with `bp` one before the sector.
fn field(bp: &mut [u8; LOGICAL_BLOCK_SIZE], from: usize, to: usize) -> &mut [u8] {
    &mut bp[from - 1..to]
}

impl Iso9660 {
    fn set_str_utf16be(&mut self, p: &mut [u8], s: Option<&[u8]>, uf: u16, vdc: Vdc) {
        let s = s.unwrap_or(b"\0\0");
        let mut l = p.len();
        let onepad = l & 0x01 != 0;
        l &= !1;
        let size = if vdc == Vdc::Ucs2 {
            // A conversion that fails keeps what it converted.
            let _ = crate::string::strncpy_l(
                &mut self.utf16be,
                &s[..strlen(s)],
                self.sconv_to_utf16be.as_deref(),
            );
            let size = self.utf16be.len().min(l);
            p[..size].copy_from_slice(&self.utf16be[..size]);
            size
        } else {
            let units = s.chunks_exact(2).take_while(|u| u != &[0, 0]).count();
            let size = (units * 2).min(l);
            p[..size].copy_from_slice(&s[..size]);
            size
        };
        for i in (0..size).step_by(2) {
            if !joliet_allowed_char(p[i], p[i + 1]) {
                p[i..i + 2].copy_from_slice(&[0x00, 0x5F]); // '_'
            }
        }
        let mut i = size;
        while i + 2 <= l {
            p[i..i + 2].copy_from_slice(&uf.to_be_bytes());
            i += 2;
        }
        if onepad {
            p[l] = 0;
        }
    }

    /// set_str_a_characters_bp() and set_str_d_characters_bp().
    fn set_str_characters_bp(
        &mut self,
        bp: &mut [u8; LOGICAL_BLOCK_SIZE],
        from: usize,
        to: usize,
        s: Option<&[u8]>,
        vdc: Vdc,
        char_type: CharType,
    ) {
        let p = field(bp, from, to);
        match (vdc, char_type) {
            (Vdc::Std, CharType::A) => set_str(p, s, 0x20, &A_CHARACTERS_MAP),
            (Vdc::Lowercase, CharType::A) => set_str(p, s, 0x20, &A1_CHARACTERS_MAP),
            (Vdc::Std, CharType::D) => set_str(p, s, 0x20, &D_CHARACTERS_MAP),
            (Vdc::Lowercase, CharType::D) => set_str(p, s, 0x20, &D1_CHARACTERS_MAP),
            (Vdc::Ucs2 | Vdc::Ucs2Direct, _) => self.set_str_utf16be(p, s, 0x0020, vdc),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn set_file_identifier(
        &mut self,
        bp: &mut [u8; LOGICAL_BLOCK_SIZE],
        from: usize,
        to: usize,
        mut vdc: Vdc,
        which: Which,
        id: &[u8],
        label: &str,
        leading_under: bool,
        char_type: CharType,
    ) -> Result<(), Error> {
        if !id.is_empty() && leading_under && id[0] != b'_' {
            self.set_str_characters_bp(bp, from, to, Some(id), vdc, char_type);
        } else if !id.is_empty() {
            let ids = if leading_under { &id[1..] } else { id };
            let vdd = self.vdd(which);
            let joliet = vdd.vdd_type == VddType::Joliet;
            let Some(isoent) = self.isoent_find_entry(vdd.rootent, ids) else {
                let mut msg = format!("Not Found {label} `").into_bytes();
                msg.extend_from_slice(ids);
                msg.push(b'\'');
                return Err(misc(msg));
            };
            let e = &self.ents[isoent];
            let mut identifier = [0u8; 256];
            let len = ((e.ext_off + e.ext_len).max(0) as usize).min(if joliet { 254 } else { 255 });
            let src = e.identifier.as_deref().unwrap_or_default();
            let len = len.min(src.len());
            identifier[..len].copy_from_slice(&src[..len]);
            if joliet {
                vdc = Vdc::Ucs2Direct;
            }
            self.set_str_characters_bp(bp, from, to, Some(&identifier), vdc, char_type);
        } else {
            self.set_str_characters_bp(bp, from, to, None, vdc, char_type);
        }
        Ok(())
    }

    /// Copy a whole sector into the write buffer.
    pub(super) fn wb_put_block(
        &mut self,
        out: &mut dyn Sink,
        block: &[u8; LOGICAL_BLOCK_SIZE],
    ) -> Result<(), Error> {
        let p = self.wb_buffptr();
        self.wbuff
            .get_mut(p..p + LOGICAL_BLOCK_SIZE)
            .ok_or_else(|| misc("Internal Programming error: iso9660:write buffer"))?
            .copy_from_slice(block);
        self.wb_consume(out, LOGICAL_BLOCK_SIZE)
    }

    /// Write Volume Descriptor Set Terminator
    fn write_vd_terminator(&mut self, out: &mut dyn Sink) -> Result<(), Error> {
        let mut bp = [0u8; LOGICAL_BLOCK_SIZE];
        set_vd_bp(&mut bp, VDT_TERMINATOR, 1);
        self.wb_put_block(out, &bp)
    }

    /// Write Primary/Supplementary Volume Descriptor
    fn write_vd(
        &mut self,
        out: &mut dyn Sink,
        which: Which,
        vdd_type: VddType,
    ) -> Result<(), Error> {
        let volume_set_size: u16 = 1;
        let (vdt, vd_ver, fst_ver, vdc) = match vdd_type {
            VddType::Joliet => (VDT_SUPPLEMENTARY, 1, 1, Vdc::Ucs2),
            VddType::Enhanced => (VDT_SUPPLEMENTARY, 2, 2, Vdc::Lowercase),
            VddType::Primary => (VDT_PRIMARY, 1, 1, Vdc::Std),
        };

        let mut bp = [0u8; LOGICAL_BLOCK_SIZE];
        // Volume Descriptor Type
        set_vd_bp(&mut bp, vdt, vd_ver);
        // Unused Field: 8 to 8
        // System Identifier
        let identifier = get_system_identifier();
        self.set_str_characters_bp(&mut bp, 9, 40, Some(&identifier), vdc, CharType::A);
        // Volume Identifier
        let volume_identifier = self.volume_identifier.clone();
        self.set_str_characters_bp(&mut bp, 41, 72, Some(&volume_identifier), vdc, CharType::D);
        // Unused Field: 73 to 80
        // Volume Space Size
        field(&mut bp, 81, 88).copy_from_slice(&num_733(self.volume_space_size as u32));
        if vdd_type == VddType::Joliet {
            // Escape Sequences
            field(&mut bp, 89, 91).copy_from_slice(&[0x25, 0x2F, 0x45]); // UCS-2 Level 3
        }
        // Volume Set Size
        field(&mut bp, 121, 124).copy_from_slice(&num_723(volume_set_size));
        // Volume Sequence Number
        field(&mut bp, 125, 128).copy_from_slice(&num_723(self.volume_sequence_number as u16));
        // Logical Block Size
        field(&mut bp, 129, 132).copy_from_slice(&num_723(LOGICAL_BLOCK_SIZE as u16));
        let vdd = self.vdd(which);
        // Path Table Size
        field(&mut bp, 133, 140).copy_from_slice(&num_733(vdd.path_table_size as u32));
        // Location of Occurrence of Type L Path Table
        field(&mut bp, 141, 144).copy_from_slice(&num_731(vdd.location_type_l_path_table as u32));
        // Location of Optional Occurrence of Type L Path Table: 145 to 148
        // Location of Occurrence of Type M Path Table
        field(&mut bp, 149, 152).copy_from_slice(&num_732(vdd.location_type_m_path_table as u32));
        // Location of Optional Occurrence of Type M Path Table: 153 to 156
        // Directory Record for Root Directory(BP 157 to 190)
        let rootent = vdd.rootent;
        self.set_directory_record(
            Some((field(&mut bp, 157, 190), 190 - 157 + 1)),
            rootent,
            DirRecType::Vd,
            vdd_type,
        )?;
        // Volume Set Identifier
        self.set_str_characters_bp(&mut bp, 191, 318, Some(b""), vdc, CharType::D);
        // Publisher Identifier
        let id = self.publisher_identifier.clone();
        self.set_file_identifier(
            &mut bp,
            319,
            446,
            vdc,
            which,
            &id,
            "Publisher File",
            true,
            CharType::A,
        )?;
        // Data Preparer Identifier
        let id = self.data_preparer_identifier.clone();
        self.set_file_identifier(
            &mut bp,
            447,
            574,
            vdc,
            which,
            &id,
            "Data Preparer File",
            true,
            CharType::A,
        )?;
        // Application Identifier
        let id = self.application_identifier.clone();
        self.set_file_identifier(
            &mut bp,
            575,
            702,
            vdc,
            which,
            &id,
            "Application File",
            true,
            CharType::A,
        )?;
        // Copyright File Identifier
        let id = self.copyright_file_identifier.clone();
        self.set_file_identifier(
            &mut bp,
            703,
            739,
            vdc,
            which,
            &id,
            "Copyright File",
            false,
            CharType::D,
        )?;
        // Abstract File Identifier
        let id = self.abstract_file_identifier.clone();
        self.set_file_identifier(
            &mut bp,
            740,
            776,
            vdc,
            which,
            &id,
            "Abstract File",
            false,
            CharType::D,
        )?;
        // Bibliographic File Identifier
        let id = self.bibliographic_file_identifier.clone();
        self.set_file_identifier(
            &mut bp,
            777,
            813,
            vdc,
            which,
            &id,
            "Bibliongraphic File",
            false,
            CharType::D,
        )?;
        // Volume Creation Date and Time
        field(&mut bp, 814, 830).copy_from_slice(&set_date_time(self.birth_time));
        // Volume Modification Date and Time
        field(&mut bp, 831, 847).copy_from_slice(&set_date_time(self.birth_time));
        // Volume Expiration Date and Time(obsolete)
        field(&mut bp, 848, 864).copy_from_slice(&set_date_time_null());
        // Volume Effective Date and Time
        field(&mut bp, 865, 881).copy_from_slice(&set_date_time(self.birth_time));
        // File Structure Version
        bp[882 - 1] = fst_ver;
        // Reserved: 883
        // Application Use
        field(&mut bp, 884, 1395).fill(0x20);
        // Reserved: 1396 to the end

        self.wb_put_block(out, &bp)
    }

    /// Write Boot Record Volume Descriptor
    fn write_vd_boot_record(&mut self, out: &mut dyn Sink) -> Result<(), Error> {
        let mut bp = [0u8; LOGICAL_BLOCK_SIZE];
        // Volume Descriptor Type
        set_vd_bp(&mut bp, VDT_BOOT_RECORD, 1);
        // Boot System Identifier
        field(&mut bp, 8, 8 + 22).copy_from_slice(b"EL TORITO SPECIFICATION");
        // Absolute pointer to first sector of Boot Catalog
        let catalog = self
            .el_torito
            .catalog
            .ok_or_else(|| misc("Missing boot catalog"))?;
        let location = self.files[self.ents[catalog].file].content[0].location;
        field(&mut bp, 72, 75).copy_from_slice(&num_731(location));

        self.wb_put_block(out, &bp)
    }

    /// Make Non-ISO File System Information
    fn write_information_block(&mut self, out: &mut dyn Sink) -> Result<(), Error> {
        let info_size = LOGICAL_BLOCK_SIZE * NON_ISO_FILE_SYSTEM_INFORMATION_BLOCK as usize;

        if info_size > self.wbuff_remaining {
            self.wb_write_out(out)?;
        }
        let mut info = b"INFO ".to_vec();
        info.extend_from_slice(&crate::ffi::sys::ctime(self.birth_time).unwrap_or_default());
        info.extend_from_slice(crate::util::VERSION_STRING.to_bytes());
        let mut opt = false;
        // set_option_info()
        let mut set_option_info = |key: &str, value: OptValue| {
            info.push(if opt { b',' } else { b' ' });
            match value {
                OptValue::Flg(d) => {
                    if !d {
                        info.push(b'!');
                    }
                    info.extend_from_slice(key.as_bytes());
                }
                OptValue::Str(s) => {
                    info.extend_from_slice(key.as_bytes());
                    info.push(b'=');
                    info.extend_from_slice(&s[..strlen(s)]);
                }
                OptValue::Int(d) => info.extend_from_slice(format!("{key}={d}").as_bytes()),
                OptValue::Hex(d) => {
                    info.extend_from_slice(format!("{key}={:x}", d as u32).as_bytes())
                }
            }
            opt = true;
        };
        let o = &self.opt;
        if o.abstract_file {
            set_option_info(
                "abstract-file",
                OptValue::Str(&self.abstract_file_identifier),
            );
        }
        if o.application_id {
            set_option_info(
                "application-id",
                OptValue::Str(&self.application_identifier),
            );
        }
        if !o.allow_vernum {
            set_option_info("allow-vernum", OptValue::Flg(o.allow_vernum));
        }
        if o.biblio_file {
            set_option_info(
                "biblio-file",
                OptValue::Str(&self.bibliographic_file_identifier),
            );
        }
        if o.boot {
            set_option_info("boot", OptValue::Str(&self.el_torito.boot_filename));
        }
        if o.boot_catalog {
            set_option_info(
                "boot-catalog",
                OptValue::Str(&self.el_torito.catalog_filename),
            );
        }
        if o.boot_info_table {
            set_option_info("boot-info-table", OptValue::Flg(o.boot_info_table));
        }
        if o.boot_load_seg {
            set_option_info(
                "boot-load-seg",
                OptValue::Hex(i32::from(self.el_torito.boot_load_seg)),
            );
        }
        if o.boot_load_size {
            set_option_info(
                "boot-load-size",
                OptValue::Int(i32::from(self.el_torito.boot_load_size)),
            );
        }
        if o.boot_type != OPT_BOOT_TYPE_AUTO {
            let v: &[u8] = match o.boot_type {
                OPT_BOOT_TYPE_FD => b"fd",
                OPT_BOOT_TYPE_HARD_DISK => b"hard-disk",
                _ => b"no-emulation",
            };
            set_option_info("boot-type", OptValue::Str(v));
        }
        if o.compression_level {
            set_option_info(
                "compression-level",
                OptValue::Int(self.zisofs.compression_level),
            );
        }
        if o.copyright_file {
            set_option_info(
                "copyright-file",
                OptValue::Str(&self.copyright_file_identifier),
            );
        }
        if o.iso_level != 1 {
            set_option_info("iso-level", OptValue::Int(i32::from(o.iso_level)));
        }
        if o.joliet != OPT_JOLIET_ENABLE {
            if o.joliet == OPT_JOLIET_LONGNAME {
                set_option_info("joliet", OptValue::Str(b"long"));
            } else {
                set_option_info("joliet", OptValue::Flg(o.joliet != 0));
            }
        }
        if !o.limit_depth {
            set_option_info("limit-depth", OptValue::Flg(o.limit_depth));
        }
        if !o.limit_dirs {
            set_option_info("limit-dirs", OptValue::Flg(o.limit_dirs));
        }
        if !o.pad {
            set_option_info("pad", OptValue::Flg(o.pad));
        }
        if o.publisher {
            set_option_info("publisher", OptValue::Str(&self.publisher_identifier));
        }
        if o.rr != OPT_RR_USEFUL {
            if o.rr == OPT_RR_DISABLED {
                set_option_info("rockridge", OptValue::Flg(false));
            } else if o.rr == OPT_RR_STRICT {
                set_option_info("rockridge", OptValue::Str(b"strict"));
            }
        }
        if o.volume_id {
            set_option_info("volume-id", OptValue::Str(&self.volume_identifier));
        }
        if o.zisofs {
            set_option_info("zisofs", OptValue::Flg(o.zisofs));
        }

        // Upstream copies the first block of the text, which may be longer.
        info.resize(info.len().max(info_size), 0);
        let mut block = [0u8; LOGICAL_BLOCK_SIZE];
        block.copy_from_slice(&info[..info_size]);
        self.wb_put_block(out, &block)
    }

    fn write_rr_er(&mut self, out: &mut dyn Sink) -> Result<(), Error> {
        let mut p = [0u8; LOGICAL_BLOCK_SIZE];
        p[..8].copy_from_slice(&[
            b'E',
            b'R',
            RRIP_ER_SIZE as u8,
            0x01,
            RRIP_IDENTIFIER.len() as u8,
            RRIP_DESCRIPTOR.len() as u8,
            RRIP_SOURCE.len() as u8,
            0x01,
        ]);
        let text = [RRIP_IDENTIFIER, RRIP_DESCRIPTOR, RRIP_SOURCE].concat();
        p[8..8 + text.len()].copy_from_slice(&text);
        self.wb_put_block(out, &p)
    }

    pub(super) fn calculate_path_table_size(&mut self, which: Which) {
        let vdd = self.vdd(which);
        let mut size: i32 = 0;
        for pt in &vdd.pathtbl {
            if pt.cnt == 0 {
                break;
            }
            for &np in pt.sorted.iter().take(pt.cnt as usize) {
                let e = &self.ents[np];
                let mut len = if e.identifier.is_none() {
                    1 // root directory
                } else {
                    e.id_len
                };
                if len & 0x01 != 0 {
                    len += 1; // Padding Field
                }
                size = size.wrapping_add(8 + len);
            }
        }
        let vdd = self.vdd_mut(which);
        vdd.path_table_size = size;
        let ptbs = PATH_TABLE_BLOCK_SIZE as i32;
        vdd.path_table_block = ((size + ptbs - 1) / ptbs) * (ptbs / LOGICAL_BLOCK_SIZE as i32);
    }

    /// _write_path_table(): the records of one depth; returns their size.
    fn write_path_table_depth(
        &mut self,
        out: &mut dyn Sink,
        type_m: bool,
        depth: usize,
        which: Which,
    ) -> Result<i32, Error> {
        let pt = &self.vdd(which).pathtbl[depth];
        if pt.cnt == 0 {
            return Ok(0);
        }
        let ptbl: Vec<EntId> = pt.sorted.iter().take(pt.cnt as usize).copied().collect();
        if ptbl.len() != pt.cnt as usize {
            return Err(misc("Path table entries are not sorted"));
        }

        let mut wsize = 0;
        let mut wb = self.wb_buffptr();
        let mut wbremaining = self.wbuff_remaining;
        // Upstream's `(bp + 1) - wb`.
        let mut bp = 0;
        for np in ptbl {
            let e = &self.ents[np];
            let mut len = match &e.identifier {
                None => 1, // root directory
                Some(_) => e.id_len as usize,
            };
            if wbremaining - bp < len + 1 + 8 {
                self.wb_consume(out, bp)?;
                wb = self.wb_buffptr();
                wbremaining = self.wbuff_remaining;
                bp = 0;
            }
            let e = &self.ents[np];
            let mut rec = Vec::with_capacity(len + 9);
            // Length of Directory Identifier
            rec.push(len as u8);
            // Extended Attribute Record Length
            rec.push(0);
            // Location of Extent; Parent Directory Number
            let parent = self.ents[e.parent].dir_number as u16;
            if type_m {
                rec.extend_from_slice(&num_732(e.dir_location));
                rec.extend_from_slice(&num_722(parent));
            } else {
                rec.extend_from_slice(&num_731(e.dir_location));
                rec.extend_from_slice(&num_721(parent));
            }
            // Directory Identifier
            match &e.identifier {
                None => rec.push(0),
                Some(id) => {
                    rec.extend_from_slice(id.get(..len).ok_or_else(|| misc("Identifier too long"))?)
                }
            }
            if len & 0x01 != 0 {
                // Padding Field
                rec.push(0);
                len += 1;
            }
            let at = wb + bp;
            self.wbuff
                .get_mut(at..at + rec.len())
                .ok_or_else(|| misc("Internal Programming error: iso9660:write buffer"))?
                .copy_from_slice(&rec);
            wsize += 8 + len as i32;
            bp += 8 + len;
        }
        if bp > 0 {
            self.wb_consume(out, bp)?;
        }
        Ok(wsize)
    }

    /// write_path_table(): returns upstream's code, which is the size of
    /// the deepest level's records when the table fills its last block.
    fn write_path_table(
        &mut self,
        out: &mut dyn Sink,
        type_m: bool,
        which: Which,
    ) -> Result<i32, Error> {
        let mut r = ARCHIVE_OK;
        let mut path_table_size: usize = 0;
        for depth in 0..self.vdd(which).pathtbl.len() {
            r = self.write_path_table_depth(out, type_m, depth, which)?;
            path_table_size += r as usize;
        }

        // Write padding data.
        let path_table_size = path_table_size % PATH_TABLE_BLOCK_SIZE;
        if path_table_size > 0 {
            self.write_null(out, PATH_TABLE_BLOCK_SIZE - path_table_size)?;
            r = ARCHIVE_OK;
        }
        Ok(r)
    }

    pub(super) fn calculate_directory_descriptors(
        &mut self,
        which: Which,
        isoent: EntId,
        depth: i32,
    ) -> Result<i32, Error> {
        let vdd = self.vdd(which);
        let (vdd_type, max_depth) = (vdd.vdd_type, vdd.max_depth);
        let mut block = 1;
        let mut bs = self.get_dir_rec_size(isoent, DirRecType::Current, vdd_type)?;
        bs += self.get_dir_rec_size(isoent, DirRecType::Parent, vdd_type)?;

        if self.ents[isoent].children.is_empty()
            || (vdd_type != VddType::Joliet && self.opt.rr == 0 && depth + 1 >= max_depth)
        {
            return Ok(block);
        }

        for np in self.sorted_children(isoent)? {
            let mut file = self.ents[np].file;
            if let Some(target) = self.files[file].hardlink_target {
                file = target;
            }
            self.files[file].cur_content = Some(0);
            loop {
                let dr_l = self.get_dir_rec_size(np, DirRecType::Normal, vdd_type)?;
                if bs + dr_l > LOGICAL_BLOCK_SIZE as i32 {
                    block += 1;
                    bs = dr_l;
                } else {
                    bs += dr_l;
                }
                if !self.next_content(file) {
                    break;
                }
            }
        }
        Ok(block)
    }

    /// The `children.cnt` entries of `children_sorted`.
    fn sorted_children(&self, isoent: EntId) -> Result<Vec<EntId>, Error> {
        let e = &self.ents[isoent];
        let cnt = e.children.len();
        if e.children_sorted.len() < cnt {
            return Err(misc("Directory entries are not sorted"));
        }
        Ok(e.children_sorted[..cnt].to_vec())
    }

    /// `file->cur_content = file->cur_content->next`: false at the end.
    fn next_content(&mut self, file: FileId) -> bool {
        let f = &mut self.files[file];
        f.cur_content = f
            .cur_content
            .map(|c| c + 1)
            .filter(|&c| c < f.content.len());
        f.cur_content.is_some()
    }

    /// One Directory Record at `p` of the block that starts at `wb`, or 0
    /// if it doesn't fit there.
    fn write_directory_record(
        &mut self,
        p: usize,
        wb: usize,
        isoent: EntId,
        t: DirRecType,
        vdd_type: VddType,
    ) -> Result<usize, Error> {
        let n = LOGICAL_BLOCK_SIZE - (p - wb);
        let mut dr = [0u8; 256];
        let len = self.set_directory_record(Some((&mut dr, n)), isoent, t, vdd_type)? as usize;
        if len > 0 {
            if len > n {
                return Err(misc("Directory Record overflow"));
            }
            self.wbuff
                .get_mut(p..p + len)
                .ok_or_else(|| misc("Internal Programming error: iso9660:write buffer"))?
                .copy_from_slice(&dr[..len]);
        }
        Ok(len)
    }

    /// Zero the rest of the block at `wb` from `p` and hand it out.
    fn finish_directory_block(
        &mut self,
        out: &mut dyn Sink,
        p: usize,
        wb: usize,
    ) -> Result<(), Error> {
        self.wbuff
            .get_mut(p..wb + LOGICAL_BLOCK_SIZE)
            .ok_or_else(|| misc("Internal Programming error: iso9660:write buffer"))?
            .fill(0);
        self.wb_consume(out, LOGICAL_BLOCK_SIZE)
    }

    /// _write_directory_descriptors(): the directory blocks of `isoent`.
    fn write_directory_descriptors_one(
        &mut self,
        out: &mut dyn Sink,
        which: Which,
        isoent: EntId,
        depth: i32,
    ) -> Result<(), Error> {
        let vdd = self.vdd(which);
        let (vdd_type, max_depth) = (vdd.vdd_type, vdd.max_depth);

        let mut wb = self.wb_buffptr();
        let mut p = wb;
        p += self.write_directory_record(p, wb, isoent, DirRecType::Current, vdd_type)?;
        p += self.write_directory_record(p, wb, isoent, DirRecType::Parent, vdd_type)?;

        if self.ents[isoent].children.is_empty()
            || (vdd_type != VddType::Joliet && self.opt.rr == 0 && depth + 1 >= max_depth)
        {
            return self.finish_directory_block(out, p, wb);
        }

        for np in self.sorted_children(isoent)? {
            let mut file = self.ents[np].file;
            if let Some(target) = self.files[file].hardlink_target {
                file = target;
            }
            self.files[file].cur_content = Some(0);
            loop {
                let mut dr_l =
                    self.write_directory_record(p, wb, np, DirRecType::Normal, vdd_type)?;
                if dr_l == 0 {
                    self.finish_directory_block(out, p, wb)?;
                    wb = self.wb_buffptr();
                    p = wb;
                    dr_l = self.write_directory_record(p, wb, np, DirRecType::Normal, vdd_type)?;
                }
                p += dr_l;
                if !self.next_content(file) {
                    break;
                }
            }
        }
        self.finish_directory_block(out, p, wb)
    }

    fn write_directory_descriptors(
        &mut self,
        out: &mut dyn Sink,
        which: Which,
    ) -> Result<(), Error> {
        let vdd = self.vdd(which);
        let (vdd_type, max_depth) = (vdd.vdd_type, vdd.max_depth);
        for (np, depth) in self.walk_dirs(vdd.rootent, 0, |d| d + 1 < max_depth) {
            self.write_directory_descriptors_one(out, which, np, depth)?;
            if vdd_type != VddType::Joliet {
                // This extract record is used by SUSP,RRIP. Not for joliet.
                for i in 0..self.ents[np].extr_rec_list.len() {
                    let extr = &self.ents[np].extr_rec_list[i];
                    let mut block = [0u8; LOGICAL_BLOCK_SIZE];
                    let n = (extr.offset.max(0) as usize).min(LOGICAL_BLOCK_SIZE);
                    block[..n].copy_from_slice(&extr.buf[..n]);
                    self.wb_put_block(out, &block)?;
                }
            }
        }
        Ok(())
    }

    /// Read file contents from the temporary file, and write it.
    fn write_file_contents(
        &mut self,
        out: &mut dyn Sink,
        offset: i64,
        mut size: i64,
    ) -> Result<(), Error> {
        temp_seek(&mut self.temp, offset);

        while size > 0 {
            let wb = self.wb_buffptr();
            let rsize = (self.wbuff_remaining as i64).min(size) as usize;
            let rs = match temp_read(&mut self.temp, &mut self.wbuff[wb..wb + rsize]) {
                Ok(0) => return Err(read_error(0, 0)),
                Ok(rs) => rs,
                Err((rs, errno)) => return Err(read_error(rs, errno)),
            };
            size -= rs as i64;
            self.wb_consume(out, rs)?;
        }
        Ok(())
    }

    fn write_file_descriptors(&mut self, out: &mut dyn Sink) -> Result<(), Error> {
        let mut blocks: i64 = 0;
        let mut offset: i64 = 0;

        // Make the boot catalog contents, and write it.
        if self.el_torito.catalog.is_some() {
            self.make_boot_catalog(out)?;
        }

        // Write the boot file contents.
        if let Some(boot) = self.el_torito.boot {
            let content = self.files[self.ents[boot].file].content[0];
            blocks = i64::from(content.blocks);
            offset = content.offset_of_temp;
            if offset != 0 {
                self.write_file_contents(out, offset, blocks << LOGICAL_BLOCK_BITS)?;
                blocks = 0;
                offset = 0;
            }
        }

        // Write out all file contents.
        for f in self.data_file_list.clone() {
            if !self.files[f].write_content {
                continue;
            }

            let start = self.files[f].content[0].offset_of_temp;
            if offset + (blocks << LOGICAL_BLOCK_BITS) < start {
                if blocks > 0 {
                    self.write_file_contents(out, offset, blocks << LOGICAL_BLOCK_BITS)?;
                }
                blocks = 0;
                offset = start;
            }

            let file = &mut self.files[f];
            for c in &file.content {
                blocks += i64::from(c.blocks);
            }
            file.cur_content = None;
        }

        // Flush out remaining blocks.
        if blocks > 0 {
            self.write_file_contents(out, offset, blocks << LOGICAL_BLOCK_BITS)?;
        }

        Ok(())
    }

    /// The second half of iso9660_close(): write an ISO 9660 image.
    pub(super) fn write_image(&mut self, out: &mut dyn Sink) -> Result<(), Error> {
        // Upstream turns every failure from here on into ARCHIVE_FATAL.
        let fatal = |e: Error| Error {
            code: ARCHIVE_FATAL,
            ..e
        };

        // Switch to start using wbuff as file buffer.
        self.wbuff_remaining = WB_BUFFMAX;
        self.wbuff_type = WbType::ToStream;
        self.wbuff_offset = 0;
        self.wbuff_written = 0;
        self.wbuff_tail = 0;

        // Write The System Area
        self.write_null(out, SYSTEM_AREA_BLOCK as usize * LOGICAL_BLOCK_SIZE)
            .map_err(fatal)?;

        // Write Primary Volume Descriptor
        self.write_vd(out, Which::Primary, VddType::Primary)
            .map_err(fatal)?;

        if self.opt.boot {
            // Write Boot Record Volume Descriptor
            self.write_vd_boot_record(out).map_err(fatal)?;
        }

        if self.opt.iso_level == 4 {
            // Write Enhanced Volume Descriptor
            self.write_vd(out, Which::Primary, VddType::Enhanced)
                .map_err(fatal)?;
        }

        if self.opt.joliet != 0 {
            self.write_vd(out, Which::Joliet, VddType::Joliet)
                .map_err(fatal)?;
        }

        // Write Volume Descriptor Set Terminator
        self.write_vd_terminator(out).map_err(fatal)?;

        // Write Non-ISO File System Information
        self.write_information_block(out).map_err(fatal)?;

        // Write Type L and Type M Path Tables. A path table that fills its
        // last block exactly returns a nonzero size, which upstream takes
        // for a failure.
        let mut tables = vec![(false, Which::Primary), (true, Which::Primary)];
        if self.opt.joliet != 0 {
            tables.extend([(false, Which::Joliet), (true, Which::Joliet)]);
        }
        for (type_m, which) in tables {
            if self.write_path_table(out, type_m, which).map_err(fatal)? != ARCHIVE_OK {
                return Err(Error::silent(ARCHIVE_FATAL));
            }
        }

        // Write Directory Descriptors
        self.write_directory_descriptors(out, Which::Primary)
            .map_err(fatal)?;

        if self.opt.joliet != 0 {
            self.write_directory_descriptors(out, Which::Joliet)
                .map_err(fatal)?;
        }

        if self.opt.rr != 0 {
            // Write Rockridge ER(Extensions Reference)
            self.write_rr_er(out).map_err(fatal)?;
        }

        // Write File Descriptors
        self.write_file_descriptors(out).map_err(fatal)?;

        // Write Padding
        if self.opt.pad {
            self.write_null(out, PADDING_BLOCK as usize * LOGICAL_BLOCK_SIZE)
                .map_err(fatal)?;
        }

        if let Some(np) = self.directories_too_deep {
            let mut msg = shown(self.files[self.ents[np].file].entry.pathname());
            msg.extend_from_slice(b": Directories too deep");
            return Err(Error::new(ARCHIVE_WARN, ARCHIVE_ERRNO_MISC, msg));
        }

        // Write remaining data out.
        self.wb_write_out(out)
    }
}

/// An option recorded in the information block.
enum OptValue<'a> {
    Flg(bool),
    Str(&'a [u8]),
    Int(i32),
    Hex(i32),
}

fn set_vd_bp(bp: &mut [u8; LOGICAL_BLOCK_SIZE], vd_type: u8, ver: u8) {
    // Volume Descriptor Type
    bp[0] = vd_type;
    // Standard Identifier
    bp[1..6].copy_from_slice(b"CD001");
    // Volume Descriptor Version
    bp[6] = ver;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_map_to_the_character_sets() {
        let mut p = [0u8; 8];
        set_str(&mut p, Some(b"ab.c-1\xe9"), 0x20, &D_CHARACTERS_MAP);
        assert_eq!(&p, b"AB_C_1_ ");
        set_str(&mut p, Some(b"ab c"), b'x', &A_CHARACTERS_MAP);
        assert_eq!(&p, b"AB Cxxxx");
        set_str(&mut p, None, 0x20, &A1_CHARACTERS_MAP);
        assert_eq!(&p, b"        ");
    }

    #[test]
    fn numbers_and_dates() {
        assert_eq!(num_723(0x0102), [2, 1, 1, 2]);
        assert_eq!(num_733(0x01020304), [4, 3, 2, 1, 1, 2, 3, 4]);
        let mut d = [0u8; 4];
        set_digit(&mut d, 2026);
        assert_eq!(&d, b"2026");
        assert_eq!(&set_date_time_null(), b"0000000000000000\0");
        assert!(
            joliet_allowed_char(0, b'a')
                && !joliet_allowed_char(0, b'*')
                && !joliet_allowed_char(0, 0x1F)
        );
        assert!(joliet_allowed_char(0x30, 0x2A));
    }
}
