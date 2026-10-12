// Ported from libarchive/archive_write_set_format_iso9660.c: the extra_*
// functions, the Rock Ridge entries and the Directory Records.

use super::descriptor::{num_733, set_time_915};
use super::*;
use crate::entry::{AE_IFBLK, AE_IFCHR};

const RR_CE_SIZE: i32 = 28; // SUSP "CE" extension size
const DR_SAFETY: i32 = RR_CE_SIZE;
const DR_LIMIT: i32 = 254 - DR_SAFETY;

const FILE_FLAG_DIRECTORY: u8 = 0x02;
const FILE_FLAG_MULTI_EXTENT: u8 = 0x80;

pub(super) const RRIP_IDENTIFIER: &[u8] = b"RRIP_1991A";
pub(super) const RRIP_DESCRIPTOR: &[u8] =
    b"THE ROCK RIDGE INTERCHANGE PROTOCOL PROVIDES SUPPORT FOR POSIX FILE SYSTEM SEMANTICS";
pub(super) const RRIP_SOURCE: &[u8] = b"PLEASE CONTACT DISC PUBLISHER FOR SPECIFICATION SOURCE.  \
SEE PUBLISHER IDENTIFIER IN PRIMARY VOLUME DESCRIPTOR FOR CONTACT INFORMATION.";
pub(super) const RRIP_ER_SIZE: usize =
    8 + RRIP_IDENTIFIER.len() + RRIP_DESCRIPTOR.len() + RRIP_SOURCE.len();

// Flags(BP 5) of the Rockridge "RR" System Use Field
const RR_USE_PX: u8 = 0x01;
const RR_USE_PN: u8 = 0x02;
const RR_USE_SL: u8 = 0x04;
const RR_USE_NM: u8 = 0x08;
const RR_USE_CL: u8 = 0x10;
const RR_USE_PL: u8 = 0x20;
const RR_USE_RE: u8 = 0x40;
const RR_USE_TF: u8 = 0x80;

const TF_CREATION: u8 = 0x01; // Creation time recorded
const TF_MODIFY: u8 = 0x02; // Modification time recorded
const TF_ACCESS: u8 = 0x04; // Last Access time recorded
const TF_ATTRIBUTES: u8 = 0x08; // Last Attribute Change time recorded

/// Types of Directory Record
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DirRecType {
    /// Stored in Volume Descriptor.
    Vd,
    /// Stored as Current Directory.
    Current,
    /// Stored as Parent Directory.
    Parent,
    /// Stored as Child.
    Normal,
}

/// The buffer a Rock Ridge entry goes to: the Directory Record, or one of
/// the parent directory's extra records.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Buf {
    Dr,
    Extr(usize),
}

/// Upstream's `bp`: where its `bp[1]` is, or `None` when only calculating
/// sizes.
type Ptr = Option<(Buf, usize)>;

fn advance(bp: Ptr, n: i32) -> Ptr {
    bp.map(|(b, i)| (b, i + n as usize))
}

struct CtlExtrRec {
    use_extr: bool,
    bp: Ptr,
    isoent: EntId,
    ce_ptr: Ptr,
    cur_len: i32,
    dr_len: i32,
    limit: i32,
    extr_off: i32,
    extr_loc: i32,
}

impl CtlExtrRec {
    fn extra_space(&self) -> i32 {
        self.limit - self.cur_len
    }
}

/// Write SUSP "CE" System Use Entry.
///
///   "CE" Format:
///               len  ver
///    +----+----+----+----+-----------+-----------+
///    | 'C'| 'E'| 1C | 01 | LOCATION1 | LOCATION2 |
///    +----+----+----+----+-----------+-----------+
///    0    1    2    3    4          12          20
///    +-----------+
///    | LOCATION3 |
///    +-----------+
///   20          28
///   LOCATION1 : Location of Continuation of System Use Area.
///   LOCATION2 : Offset to Start of Continuation.
///   LOCATION3 : Length of the Continuation.
fn set_susp_ce(location: i32, offset: i32, size: i32) -> [u8; RR_CE_SIZE as usize] {
    let mut bp = [0; RR_CE_SIZE as usize];
    bp[..4].copy_from_slice(&[b'C', b'E', RR_CE_SIZE as u8, 1]);
    bp[4..12].copy_from_slice(&num_733(location as u32));
    bp[12..20].copy_from_slice(&num_733(offset as u32));
    bp[20..28].copy_from_slice(&num_733(size as u32));
    bp
}

/// An entry's header: the signature, its length and version 1.
fn su_entry(sig: &[u8; 2], length: i32) -> Vec<u8> {
    vec![sig[0], sig[1], length as u8, 1]
}

// The functions, which names are beginning with extra_, are used to control
// extra records. The maximum size of a Directory Record is 254. When a
// filename is very long, all of RRIP data of a file won't stored to the
// Directory Record and so remaining RRIP data store to an extra record
// instead.

fn extra_open_record(write: bool, dr_len: i32, isoent: EntId) -> (Ptr, CtlExtrRec) {
    let ctl = CtlExtrRec {
        use_extr: false,
        bp: write.then_some((Buf::Dr, 0)),
        isoent,
        ce_ptr: None,
        cur_len: dr_len,
        dr_len,
        limit: DR_LIMIT,
        extr_off: 0,
        extr_loc: 0,
    };
    (advance(ctl.bp, dr_len), ctl)
}

impl Iso9660 {
    /// Store `bytes` where `at` points, in the Directory Record `dr` or an
    /// extra record of the parent of `isoent`.
    fn rr_put(
        &mut self,
        dr: Option<&mut [u8]>,
        isoent: EntId,
        at: Ptr,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let Some((buf, i)) = at else {
            return Ok(());
        };
        let dst = match buf {
            Buf::Dr => dr.and_then(|d| d.get_mut(i..i + bytes.len())),
            Buf::Extr(r) => {
                let parent = self.ents[isoent].parent;
                self.ents[parent]
                    .extr_rec_list
                    .get_mut(r)
                    .and_then(|rec| rec.buf.get_mut(i..i + bytes.len()))
            }
        };
        dst.ok_or_else(|| misc("Directory Record overflow"))?
            .copy_from_slice(bytes);
        Ok(())
    }

    fn extra_close_record(
        &mut self,
        dr: Option<&mut [u8]>,
        ctl: &mut CtlExtrRec,
        ce_size: i32,
    ) -> Result<(), Error> {
        let mut dr = dr;
        let mut padding = 0;

        if ce_size > 0 {
            self.extra_tell_used_size(ctl, ce_size);
        }
        // Padding.
        if ctl.cur_len & 0x01 != 0 {
            ctl.cur_len += 1;
            if let Some((b, base)) = ctl.bp {
                let at = Some((b, base + ctl.cur_len as usize - 1));
                self.rr_put(dr.as_deref_mut(), ctl.isoent, at, &[0])?;
            }
            padding = 1;
        }
        if ctl.use_extr {
            if ctl.ce_ptr.is_some() {
                let ce = set_susp_ce(ctl.extr_loc, ctl.extr_off, ctl.cur_len - padding);
                self.rr_put(dr, ctl.isoent, ctl.ce_ptr, &ce)?;
            }
        } else {
            ctl.dr_len = ctl.cur_len;
        }
        Ok(())
    }

    fn extra_next_record(
        &mut self,
        mut dr: Option<&mut [u8]>,
        ctl: &mut CtlExtrRec,
        length: i32,
    ) -> Result<Ptr, Error> {
        let cur_len = ctl.cur_len; // save cur_len

        // Close the current extra record or Directory Record.
        self.extra_close_record(dr.as_deref_mut(), ctl, RR_CE_SIZE)?;

        // Get a next extra record.
        ctl.use_extr = true;
        if let Some((b, base)) = ctl.bp {
            // Storing data into an extra record.

            // Save the pointer where a CE extension will be stored to.
            ctl.ce_ptr = Some((b, base + cur_len as usize));
            let (rec, space, off, loc) = self.extra_get_record(ctl.isoent, true)?;
            ctl.limit = space;
            ctl.extr_off = off;
            ctl.extr_loc = loc;
            ctl.bp = Some((Buf::Extr(rec), off as usize));
        } else {
            // Calculating the size of an extra record.
            ctl.limit = self.extra_get_record(ctl.isoent, false)?.1;
        }
        ctl.cur_len = 0;
        // Check if an extra record is almost full. If so, get a next one.
        if ctl.extra_space() < length {
            self.extra_next_record(dr, ctl, length)?;
        }

        Ok(ctl.bp)
    }

    /// extra_get_record(): the extra record to continue in, with the
    /// space it leaves, its offset and its location. Writing takes the
    /// records calculating made, in order.
    fn extra_get_record(
        &mut self,
        isoent: EntId,
        write: bool,
    ) -> Result<(usize, i32, i32, i32), Error> {
        let parent = self.ents[isoent].parent;
        let isoent = &mut self.ents[parent];
        let full = |rec: &ExtrRec| DR_SAFETY > LOGICAL_BLOCK_SIZE as i32 - rec.offset;
        let rec = if write {
            // Storing data into an extra record.
            let missing = || misc("Missing extra record");
            let current = isoent.extr_rec_current.ok_or_else(missing)?;
            if full(isoent.extr_rec_list.get(current).ok_or_else(missing)?) {
                current + 1
            } else {
                current
            }
        } else {
            // Calculating the size of an extra record.
            match isoent.extr_rec_list.last() {
                Some(rec) if !full(rec) => isoent.extr_rec_list.len() - 1,
                _ => {
                    // Insert `rec` into the tail of isoent->extr_rec_list
                    isoent.extr_rec_list.push(ExtrRec {
                        location: 0,
                        offset: 0,
                        buf: Box::new([0; LOGICAL_BLOCK_SIZE]),
                    });
                    isoent.extr_rec_list.len() - 1
                }
            }
        };
        let r = isoent
            .extr_rec_list
            .get(rec)
            .ok_or_else(|| misc("Missing extra record"))?;
        let mut space = LOGICAL_BLOCK_SIZE as i32 - r.offset - DR_SAFETY;
        if space & 0x01 != 0 {
            space -= 1; // Keep padding space.
        }
        let (off, loc) = (r.offset, r.location);
        isoent.extr_rec_current = Some(rec);
        Ok((rec, space, off, loc))
    }

    fn extra_tell_used_size(&mut self, ctl: &mut CtlExtrRec, size: i32) {
        if ctl.use_extr {
            let parent = self.ents[ctl.isoent].parent;
            let isoent = &mut self.ents[parent];
            if let Some(rec) = isoent
                .extr_rec_current
                .and_then(|c| isoent.extr_rec_list.get_mut(c))
            {
                rec.offset += size;
            }
        }
        ctl.cur_len += size;
    }

    pub(super) fn extra_setup_location(&mut self, isoent: EntId, mut location: i32) -> i32 {
        let isoent = &mut self.ents[isoent];
        isoent.extr_rec_current = (!isoent.extr_rec_list.is_empty()).then_some(0);
        for rec in &mut isoent.extr_rec_list {
            rec.location = location;
            location = location.wrapping_add(1);
            rec.offset = 0;
        }
        isoent.extr_rec_list.len() as i32
    }

    /// The location of a file's current extent, as upstream's
    /// `file->cur_content->location`.
    fn cur_location(&self, file: FileId) -> Result<u32, Error> {
        let f = &self.files[file];
        f.cur_content
            .and_then(|c| f.content.get(c))
            .map(|c| c.location)
            .ok_or_else(|| misc("No current file content"))
    }

    /// Create the RRIP entries.
    fn set_directory_record_rr(
        &mut self,
        mut dr: Option<&mut [u8]>,
        dr_len: i32,
        isoent: EntId,
        t: DirRecType,
    ) -> Result<i32, Error> {
        let (mut bp, mut ctl) = extra_open_record(dr.is_some(), dr_len, isoent);
        let me = ctl.isoent;

        let (isoent, rr_parent, pxent) = if t == DirRecType::Parent {
            let rr_parent = self.ents[isoent].rr_parent;
            let parent = self.ents[isoent].parent;
            (rr_parent.unwrap_or(parent), rr_parent, parent)
        } else {
            (isoent, None, isoent)
        };
        let file = self.ents[isoent].file;
        let filetype = self.files[file].entry.filetype();

        let mut rr_flag;
        if t != DirRecType::Normal {
            rr_flag = RR_USE_PX | RR_USE_TF;
            if rr_parent.is_some() {
                rr_flag |= RR_USE_PL;
            }
        } else {
            rr_flag = RR_USE_PX | RR_USE_NM | RR_USE_TF;
            if filetype == AE_IFLNK {
                rr_flag |= RR_USE_SL;
            }
            if self.ents[isoent].rr_parent.is_some() {
                rr_flag |= RR_USE_RE;
            }
            if self.ents[isoent].rr_child.is_some() {
                rr_flag |= RR_USE_CL;
            }
            if filetype == AE_IFCHR || filetype == AE_IFBLK {
                rr_flag |= RR_USE_PN;
            }
        }

        let root = self.ents[isoent].parent == isoent;

        // Write "SP" System Use Entry.
        if t == DirRecType::Current && root {
            let length = 7;
            if bp.is_some() {
                // version, Check Bytes
                self.rr_put(
                    dr.as_deref_mut(),
                    me,
                    bp,
                    &[b'S', b'P', length as u8, 1, 0xBE, 0xEF, 0],
                )?;
                bp = advance(bp, length);
            }
            self.extra_tell_used_size(&mut ctl, length);
        }

        // Write "RR" System Use Entry.
        let length = 5;
        if ctl.extra_space() < length {
            bp = self.extra_next_record(dr.as_deref_mut(), &mut ctl, length)?;
        }
        if bp.is_some() {
            let mut e = su_entry(b"RR", length);
            e.push(rr_flag);
            self.rr_put(dr.as_deref_mut(), me, bp, &e)?;
            bp = advance(bp, length);
        }
        self.extra_tell_used_size(&mut ctl, length);

        // Write "NM" System Use Entry.
        if rr_flag & RR_USE_NM != 0 {
            //   "NM" Format:
            //     e.g. a basename is 'foo'
            //               len  ver  flg
            //    +----+----+----+----+----+----+----+----+
            //    | 'N'| 'M'| 08 | 01 | 00 | 'f'| 'o'| 'o'|
            //    +----+----+----+----+----+----+----+----+
            //    <----------------- len ----------------->
            let nm = self.files[file].basename.clone();
            let mut nm = &nm[..];
            while !nm.is_empty() {
                // We need at least six bytes (five header, one content)
                if ctl.extra_space() < 6 {
                    bp = self.extra_next_record(dr.as_deref_mut(), &mut ctl, 6)?;
                }
                // We can only fit 255 bytes in each NM record
                let mut reclen = ctl.extra_space().min(0xff) as usize;
                let mut nmmax = reclen - 5; // Record length is guaranteed to be >= 6
                if nmmax > nm.len() {
                    // ... but the name is shorter.
                    nmmax = nm.len();
                    reclen = nmmax + 5;
                }

                if bp.is_some() {
                    // Fill out the new record
                    let mut e = su_entry(b"NM", reclen as i32);
                    // continues in next NM record
                    e.push(u8::from(nm.len() > nmmax));
                    e.extend_from_slice(&nm[..nmmax]);
                    self.rr_put(dr.as_deref_mut(), me, bp, &e)?;
                    bp = advance(bp, reclen as i32);
                }

                nm = &nm[nmmax..];
                self.extra_tell_used_size(&mut ctl, reclen as i32);
            }
        }

        // Write "PX" System Use Entry.
        if rr_flag & RR_USE_PX != 0 {
            //   "PX" Format:
            //               len  ver
            //    +----+----+----+----+-----------+-----------+
            //    | 'P'| 'X'| 2C | 01 | FILE MODE |   LINKS   |
            //    +----+----+----+----+-----------+-----------+
            //    0    1    2    3    4          12          20
            //    +-----------+-----------+------------------+
            //    |  USER ID  | GROUP ID  |FILE SERIAL NUMBER|
            //    +-----------+-----------+------------------+
            //   20          28          36                 44
            let length = 44;
            if ctl.extra_space() < length {
                bp = self.extra_next_record(dr.as_deref_mut(), &mut ctl, length)?;
            }
            if bp.is_some() {
                let f = &self.files[file];
                let mut mode = u32::from(f.entry.mode());
                let uid = f.entry.uid();
                let gid = f.entry.gid();
                if self.opt.rr == OPT_RR_USEFUL {
                    // This action is similar to mkisofs -r option but our
                    // rockridge=useful option does not set a zero to uid
                    // and gid.
                    // set all read bit ON
                    mode |= 0o444;
                    if mode & 0o111 != 0 {
                        // set all exec bit ON
                        mode |= 0o111;
                    }
                    // clear all write bits.
                    mode &= !0o222;
                    // clear setuid,setgid,sticky bits.
                    mode &= !0o7000;
                }
                // File Serial Number
                let serial = if self.ents[pxent].dir {
                    self.ents[pxent].dir_location
                } else if let Some(target) = f.hardlink_target {
                    self.cur_location(target)?
                } else {
                    self.cur_location(file)?
                };

                let mut e = su_entry(b"PX", length);
                // file mode
                e.extend_from_slice(&num_733(mode));
                // file links (stat.st_nlink)
                e.extend_from_slice(&num_733(f.entry.nlink()));
                e.extend_from_slice(&num_733(uid as u32));
                e.extend_from_slice(&num_733(gid as u32));
                e.extend_from_slice(&num_733(serial));
                self.rr_put(dr.as_deref_mut(), me, bp, &e)?;
                bp = advance(bp, length);
            }
            self.extra_tell_used_size(&mut ctl, length);
        }

        // Write "SL" System Use Entry.
        if rr_flag & RR_USE_SL != 0 {
            //   "SL" Format:
            //     e.g. a symbolic name is 'foo/bar'
            //               len  ver  flg
            //    +----+----+----+----+----+------------+
            //    | 'S'| 'L'| 0F | 01 | 00 | components |
            //    +----+----+----+----+----+-----+------+
            //    0    1    2    3    4    5  ...|...  15
            //    <----------------- len --------+------>
            //    components :                   |
            //     cflg clen                     |
            //    +----+----+----+----+----+     |
            //    | 00 | 03 | 'f'| 'o'| 'o'| <---+
            //    +----+----+----+----+----+     |
            //    5    6    7    8    9   10     |
            //     cflg clen                     |
            //    +----+----+----+----+----+     |
            //    | 00 | 03 | 'b'| 'a'| 'r'| <---+
            //    +----+----+----+----+----+
            //   10   11   12   13   14   15
            //
            //    - cflg : flag of component
            //    - clen : length of component
            if ctl.extra_space() < 12 {
                bp = self.extra_next_record(dr.as_deref_mut(), &mut ctl, 12)?;
            }
            let symlink = self.files[file].symlink.clone();
            let at = |i: usize| symlink.get(i).copied().unwrap_or(0);
            let mut sl = 0;
            let mut sl_last = 0u8;
            loop {
                let slmax = ctl.extra_space().min(0xff);
                // The components, built where upstream builds them in place
                // after the five header bytes.
                let mut nc: Vec<u8> = Vec::new();
                let (mut cf, mut cl): (Option<usize>, Option<usize>) = (None, None);
                let mut sllen = 0;
                while at(sl) != 0 && sllen + 11 < slmax {
                    if sl_last == 0 && at(sl) == b'/' {
                        //     flg  len
                        //    +----+----+
                        //    | 08 | 00 | ROOT component.
                        //    +----+----+ ("/")
                        //
                        // Root component has to appear at the first
                        // component only.
                        cf = Some(nc.len());
                        nc.extend_from_slice(&[0x08, 0]); // ROOT
                        sllen += 2;
                        sl += 1;
                        sl_last = b'/';
                        cl = None;
                        continue;
                    }
                    if ((sl_last == 0 || sl_last == b'/')
                        && at(sl) == b'.'
                        && at(sl + 1) == b'.'
                        && (at(sl + 2) == b'/' || at(sl + 2) == 0))
                        || (at(sl) == b'/'
                            && at(sl + 1) == b'.'
                            && at(sl + 2) == b'.'
                            && (at(sl + 3) == b'/' || at(sl + 3) == 0))
                    {
                        //     flg  len
                        //    +----+----+
                        //    | 04 | 00 | PARENT component.
                        //    +----+----+ ("..")
                        cf = Some(nc.len());
                        nc.extend_from_slice(&[0x04, 0]); // PARENT
                        sllen += 2;
                        // skip "/.." or ".."
                        sl += if at(sl) == b'/' { 3 } else { 2 };
                        sl_last = b'.';
                        cl = None;
                        continue;
                    }
                    if ((sl_last == 0 || sl_last == b'/')
                        && at(sl) == b'.'
                        && (at(sl + 1) == b'/' || at(sl + 1) == 0))
                        || (at(sl) == b'/'
                            && at(sl + 1) == b'.'
                            && (at(sl + 2) == b'/' || at(sl + 2) == 0))
                    {
                        //     flg  len
                        //    +----+----+
                        //    | 02 | 00 | CURRENT component.
                        //    +----+----+ (".")
                        cf = Some(nc.len());
                        nc.extend_from_slice(&[0x02, 0]); // CURRENT
                        sllen += 2;
                        // skip "/." or "."
                        sl += if at(sl) == b'/' { 2 } else { 1 };
                        sl_last = b'.';
                        cl = None;
                        continue;
                    }
                    if at(sl) == b'/' || cl.is_none() {
                        cf = Some(nc.len());
                        cl = Some(nc.len() + 1);
                        nc.extend_from_slice(&[0, 0]);
                        sllen += 2;
                        if at(sl) == b'/' {
                            sl_last = at(sl);
                            sl += 1;
                            continue;
                        }
                    }
                    sl_last = at(sl);
                    sl += 1;
                    nc.push(sl_last);
                    if let Some(len) = cl.and_then(|cl| nc.get_mut(cl)) {
                        *len = len.wrapping_add(1);
                    }
                    sllen += 1;
                }
                let length = 5 + sllen;
                let more = at(sl) != 0;
                if bp.is_some() {
                    if more {
                        // Mark flg as CONTINUE component. Upstream writes
                        // through a null pointer when this record has room
                        // for no component.
                        let flag = cf
                            .and_then(|cf| nc.get_mut(cf))
                            .ok_or_else(|| misc("No room for a symbolic link component"))?;
                        *flag |= 0x01;
                    }
                    //               len  ver  flg
                    //    +----+----+----+----+----+-
                    //    | 'S'| 'L'| XX | 01 | 01 |
                    //    +----+----+----+----+----+-
                    //                           ^
                    //           continues in next "SL"
                    let mut e = su_entry(b"SL", length);
                    e.push(u8::from(more));
                    e.extend_from_slice(&nc);
                    self.rr_put(dr.as_deref_mut(), me, bp, &e)?;
                    bp = advance(bp, length);
                }
                self.extra_tell_used_size(&mut ctl, length);
                if !more {
                    break;
                }
                if ctl.extra_space() < 11 {
                    bp = self.extra_next_record(dr.as_deref_mut(), &mut ctl, 11)?;
                }
            }
        }

        // Write "TF" System Use Entry.
        if rr_flag & RR_USE_TF != 0 {
            //   "TF" Format:
            //               len  ver
            //    +----+----+----+----+-----+-------------+
            //    | 'T'| 'F'| XX | 01 |FLAGS| TIME STAMPS |
            //    +----+----+----+----+-----+-------------+
            //    0    1    2    3    4     5            XX
            //    TIME STAMPS : ISO 9660 Standard 9.1.5.
            //                  If TF_LONG_FORM FLAGS is set,
            //                  use ISO9660 Standard 8.4.26.1.
            let e = &self.files[file].entry;
            let mut times = Vec::new();
            let mut tf_flags = 0;
            if e.birthtime_is_set() != 0 && e.birthtime() <= e.mtime() {
                times.push(e.birthtime());
                tf_flags |= TF_CREATION;
            }
            if e.mtime_is_set() != 0 {
                times.push(e.mtime());
                tf_flags |= TF_MODIFY;
            }
            if e.atime_is_set() != 0 {
                times.push(e.atime());
                tf_flags |= TF_ACCESS;
            }
            if e.ctime_is_set() != 0 {
                times.push(e.ctime());
                tf_flags |= TF_ATTRIBUTES;
            }
            let length = 5 + 7 * times.len() as i32;
            if ctl.extra_space() < length {
                bp = self.extra_next_record(dr.as_deref_mut(), &mut ctl, length)?;
            }
            if bp.is_some() {
                let mut e = su_entry(b"TF", length);
                e.push(tf_flags);
                for t in times {
                    e.extend_from_slice(&set_time_915(t));
                }
                self.rr_put(dr.as_deref_mut(), me, bp, &e)?;
                bp = advance(bp, length);
            }
            self.extra_tell_used_size(&mut ctl, length);
        }

        // Write "RE" System Use Entry.
        if rr_flag & RR_USE_RE != 0 {
            //   "RE" Format:
            //               len  ver
            //    +----+----+----+----+
            //    | 'R'| 'E'| 04 | 01 |
            //    +----+----+----+----+
            //    0    1    2    3    4
            let length = 4;
            if ctl.extra_space() < length {
                bp = self.extra_next_record(dr.as_deref_mut(), &mut ctl, length)?;
            }
            if bp.is_some() {
                self.rr_put(dr.as_deref_mut(), me, bp, &su_entry(b"RE", length))?;
                bp = advance(bp, length);
            }
            self.extra_tell_used_size(&mut ctl, length);
        }

        // Write "PL" System Use Entry.
        if let Some(rr_parent) = rr_parent.filter(|_| rr_flag & RR_USE_PL != 0) {
            //   "PL" Format:
            //               len  ver
            //    +----+----+----+----+------------+
            //    | 'P'| 'L'| 0C | 01 | *LOCATION  |
            //    +----+----+----+----+------------+
            //    0    1    2    3    4           12
            //    *LOCATION: location of parent directory
            let length = 12;
            if ctl.extra_space() < length {
                bp = self.extra_next_record(dr.as_deref_mut(), &mut ctl, length)?;
            }
            if bp.is_some() {
                let mut e = su_entry(b"PL", length);
                e.extend_from_slice(&num_733(self.ents[rr_parent].dir_location));
                self.rr_put(dr.as_deref_mut(), me, bp, &e)?;
                bp = advance(bp, length);
            }
            self.extra_tell_used_size(&mut ctl, length);
        }

        // Write "CL" System Use Entry.
        if let Some(rr_child) = self.ents[isoent]
            .rr_child
            .filter(|_| rr_flag & RR_USE_CL != 0)
        {
            //   "CL" Format:
            //               len  ver
            //    +----+----+----+----+------------+
            //    | 'C'| 'L'| 0C | 01 | *LOCATION  |
            //    +----+----+----+----+------------+
            //    0    1    2    3    4           12
            //    *LOCATION: location of child directory
            let length = 12;
            if ctl.extra_space() < length {
                bp = self.extra_next_record(dr.as_deref_mut(), &mut ctl, length)?;
            }
            if bp.is_some() {
                let mut e = su_entry(b"CL", length);
                e.extend_from_slice(&num_733(self.ents[rr_child].dir_location));
                self.rr_put(dr.as_deref_mut(), me, bp, &e)?;
                bp = advance(bp, length);
            }
            self.extra_tell_used_size(&mut ctl, length);
        }

        // Write "PN" System Use Entry.
        if rr_flag & RR_USE_PN != 0 {
            //   "PN" Format:
            //               len  ver
            //    +----+----+----+----+------------+------------+
            //    | 'P'| 'N'| 14 | 01 | dev_t high | dev_t low  |
            //    +----+----+----+----+------------+------------+
            //    0    1    2    3    4           12           20
            let length = 20;
            if ctl.extra_space() < length {
                bp = self.extra_next_record(dr.as_deref_mut(), &mut ctl, length)?;
            }
            if bp.is_some() {
                let dev = self.files[file].entry.rdev() as u64;
                let mut e = su_entry(b"PN", length);
                e.extend_from_slice(&num_733((dev >> 32) as u32));
                e.extend_from_slice(&num_733((dev & 0xFFFFFFFF) as u32));
                self.rr_put(dr.as_deref_mut(), me, bp, &e)?;
                bp = advance(bp, length);
            }
            self.extra_tell_used_size(&mut ctl, length);
        }

        // Write "ZF" System Use Entry.
        let zisofs = self.files[file].zisofs;
        if zisofs.header_size != 0 {
            //   "ZF" Format:
            //               len  ver
            //    +----+----+----+----+----+----+-------------+
            //    | 'Z'| 'F'| 10 | 01 | 'p'| 'z'| Header Size |
            //    +----+----+----+----+----+----+-------------+
            //    0    1    2    3    4    5    6             7
            //    +--------------------+-------------------+
            //    | Log2 of block Size | Uncompressed Size |
            //    +--------------------+-------------------+
            //    7                    8                   16
            let length = 16;
            if ctl.extra_space() < length {
                bp = self.extra_next_record(dr.as_deref_mut(), &mut ctl, length)?;
            }
            if bp.is_some() {
                let mut e = su_entry(b"ZF", length);
                e.extend_from_slice(&[b'p', b'z', zisofs.header_size, zisofs.log2_bs]);
                e.extend_from_slice(&num_733(zisofs.uncompressed_size));
                self.rr_put(dr.as_deref_mut(), me, bp, &e)?;
                bp = advance(bp, length);
            }
            self.extra_tell_used_size(&mut ctl, length);
        }

        // Write "CE" System Use Entry.
        if t == DirRecType::Current && root {
            let length = RR_CE_SIZE;
            if bp.is_some() {
                let ce = set_susp_ce(self.location_rrip_er, 0, RRIP_ER_SIZE as i32);
                self.rr_put(dr.as_deref_mut(), me, bp, &ce)?;
            }
            self.extra_tell_used_size(&mut ctl, length);
        }

        self.extra_close_record(dr, &mut ctl, 0)?;

        Ok(ctl.dr_len)
    }

    /// Write data of a Directory Record or calculate writing bytes itself.
    /// If parameter `p' is None, calculates the size of writing data, which
    /// a Directory Record needs to write, then it saved and return the
    /// calculated size. Otherwise `p` holds the buffer and the space left
    /// for the record, and this returns zero if the saved size needs more.
    ///
    /// This format of the Directory Record is according to ISO9660
    /// Standard 9.1
    pub(super) fn set_directory_record(
        &mut self,
        p: Option<(&mut [u8], usize)>,
        isoent: EntId,
        t: DirRecType,
        vdd_type: VddType,
    ) -> Result<i32, Error> {
        if let Some((_, n)) = &p {
            // Check whether a write buffer size is less than the saved size
            // which is needed to write this Directory Record.
            let saved = self.ents[isoent].dr_len;
            let dr_len = match t {
                DirRecType::Vd => saved.vd,
                DirRecType::Current => saved.self_,
                DirRecType::Parent => saved.parent,
                DirRecType::Normal => saved.normal,
            };
            if dr_len as usize > *n {
                return Ok(0); // Needs more buffer size.
            }
        }

        let e = &self.ents[isoent];
        let fi_len = if t == DirRecType::Normal && e.identifier.is_some() {
            e.id_len
        } else {
            1
        };

        let mut dr = p.map(|(b, _)| b);
        if let Some(bp) = dr.as_deref_mut() {
            let xisoent = if t == DirRecType::Parent {
                e.parent
            } else {
                isoent
            };
            let mut file = e.file;
            if let Some(target) = self.files[file].hardlink_target {
                file = target;
            }
            let xe = &self.ents[xisoent];
            let f = &self.files[file];
            let content = f.cur_content.and_then(|c| f.content.get(c));
            let missing = || misc("No current file content");
            // Make a file flag.
            let (flag, location, size) = if xe.dir {
                (
                    FILE_FLAG_DIRECTORY,
                    xe.dir_location,
                    (xe.dir_block as u32).wrapping_mul(LOGICAL_BLOCK_SIZE as u32),
                )
            } else {
                let c = content.ok_or_else(missing)?;
                let multi = f.cur_content.is_some_and(|i| i + 1 < f.content.len());
                let flag = if multi { FILE_FLAG_MULTI_EXTENT } else { 0 };
                (flag, c.location, c.size as u32)
            };

            let mut rec = [0u8; 33];
            // Extended Attribute Record Length
            rec[1] = 0;
            // Location of Extent
            rec[2..10].copy_from_slice(&num_733(location));
            // Data Length
            rec[10..18].copy_from_slice(&num_733(size));
            // Recording Date and Time
            // NOTE:
            //  If a file type is symbolic link, you are seeing this field
            //  value is different from a value mkisofs makes. libarchive
            //  uses lstat to get this one, but it seems mkisofs uses stat
            //  to get.
            rec[18..25].copy_from_slice(&set_time_915(self.files[xe.file].entry.mtime()));
            // File Flags
            rec[25] = flag;
            // File Unit Size, Interleave Gap Size
            rec[26] = 0;
            rec[27] = 0;
            // Volume Sequence Number
            rec[28..32].copy_from_slice(&descriptor::num_723(self.volume_sequence_number as u16));
            // Length of File Identifier
            rec[32] = fi_len as u8;
            let overflow = || misc("Directory Record overflow");
            bp.get_mut(..33).ok_or_else(overflow)?.copy_from_slice(&rec);
            // File Identifier
            let id = bp.get_mut(33..33 + fi_len as usize).ok_or_else(overflow)?;
            match t {
                DirRecType::Vd | DirRecType::Current => id[0] = 0,
                DirRecType::Parent => id[0] = 1,
                DirRecType::Normal => match &e.identifier {
                    Some(ident) => {
                        id.copy_from_slice(ident.get(..fi_len as usize).ok_or_else(overflow)?)
                    }
                    None => id[0] = 0,
                },
            }
        }
        let mut dr_len = 33 + fi_len;
        // Padding Field
        if dr_len & 0x01 != 0 {
            dr_len += 1;
            if let Some(bp) = dr.as_deref_mut() {
                *bp.get_mut(dr_len as usize - 1)
                    .ok_or_else(|| misc("Directory Record overflow"))? = 0;
            }
        }

        // Volume Descriptor does not record extension.
        if t == DirRecType::Vd {
            match dr.as_deref_mut() {
                // Length of Directory Record
                Some(bp) => bp[0] = dr_len as u8,
                None => self.ents[isoent].dr_len.vd = dr_len,
            }
            return Ok(dr_len);
        }

        // Rockridge
        if self.opt.rr != 0 && vdd_type != VddType::Joliet {
            dr_len = self.set_directory_record_rr(dr.as_deref_mut(), dr_len, isoent, t)?;
        }

        match dr {
            // Length of Directory Record
            Some(bp) => bp[0] = dr_len as u8,
            None => {
                // Save the size which is needed to write this Directory
                // Record.
                let saved = &mut self.ents[isoent].dr_len;
                match t {
                    DirRecType::Vd => {}
                    DirRecType::Current => saved.self_ = dr_len,
                    DirRecType::Parent => saved.parent = dr_len,
                    DirRecType::Normal => saved.normal = dr_len,
                }
            }
        }

        Ok(dr_len)
    }

    /// Calculate the size of a directory record.
    pub(super) fn get_dir_rec_size(
        &mut self,
        isoent: EntId,
        t: DirRecType,
        vdd_type: VddType,
    ) -> Result<i32, Error> {
        self.set_directory_record(None, isoent, t, vdd_type)
    }
}
