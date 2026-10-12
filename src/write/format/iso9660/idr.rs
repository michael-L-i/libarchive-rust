// Ported from libarchive/archive_write_set_format_iso9660.c: the idr_*
// functions, which resolve duplicated filenames and unreceivable filenames
// to generate ISO9660/Joliet Identifiers, and the tree traversal that uses
// them.

use super::descriptor::{D_CHARACTERS_MAP, D1_CHARACTERS_MAP, joliet_allowed_char};
use super::*;
use crate::rb::RbTree;

const MAX_JOLIET_ID_NUM: i32 = 46656; // 3 base 36 digits

/// One entry being named.
struct IdrEnt {
    isoent: EntId,
    /// The entry already in the tree whose name this one collided with.
    avail: Option<usize>,
    noff: i32,
    rename_num: i32,
}

/// IDentifier Resolver. Upstream keeps a weight per entry and the longest
/// name allowed; neither is ever read.
struct Idr {
    idrent_pool: Vec<IdrEnt>,
    rbtree: RbTree,
    wait_list: Vec<usize>,
    num_size: i32,
    null_size: i32,
    char_map: [u8; 0x80],
}

type Compare = fn(&IsoEnt, &IsoEnt) -> i32;

fn idr_relaxed_filenames(map: &mut [u8; 0x80]) {
    for i in (0x21..=0x2F)
        .chain(0x3A..=0x41)
        .chain(0x5B..=0x5E)
        .chain(0x7B..=0x7E)
    {
        map[i] = 1;
    }
    map[0x60] = 1;
}

fn idr_set_num(p: &mut [u8], num: i32) {
    const XDIG: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let num = num as usize % (36 * 36 * 36);
    p[0] = XDIG[num / (36 * 36)];
    p[1] = XDIG[num % (36 * 36) / 36];
    p[2] = XDIG[num % 36];
}

fn idr_set_num_beutf16(p: &mut [u8], num: i32) {
    let mut digits = [0; 3];
    idr_set_num(&mut digits, num);
    p[..6].copy_from_slice(&[0, digits[0], 0, digits[1], 0, digits[2]]);
}

/// An identifier as far as it goes, for comparisons.
fn ident(e: &IsoEnt) -> &[u8] {
    e.identifier.as_deref().unwrap_or_default()
}

fn byte(s: &[u8], i: i32) -> i32 {
    s.get(i as usize).copied().map_or(0, i32::from)
}

/// memcmp() of `l` bytes from `i1` and `i2`.
fn memcmp(s1: &[u8], i1: i32, s2: &[u8], i2: i32, l: i32) -> i32 {
    (0..l)
        .map(|k| byte(s1, i1 + k) - byte(s2, i2 + k))
        .find(|&d| d != 0)
        .unwrap_or(0)
}

/// The first byte of `s[from..to]` that isn't `pad`, as upstream compares
/// the tail of the longer of two names.
fn unpadded(s: &[u8], from: i32, to: i32, pad: i32) -> Option<i32> {
    (from..to).map(|i| byte(s, i)).find(|&c| c != pad)
}

/// This comparing rule is according to ISO9660 Standard 9.3
fn isoent_cmp_iso9660_identifier(p1: &IsoEnt, p2: &IsoEnt) -> i32 {
    isoent_cmp_identifier(p1, p2, 0x20, 1)
}

fn isoent_cmp_joliet_identifier(p1: &IsoEnt, p2: &IsoEnt) -> i32 {
    isoent_cmp_identifier(p1, p2, 0, 2)
}

/// The two comparisons differ in the padding byte and in how long an
/// extension is that holds only the dot.
fn isoent_cmp_identifier(p1: &IsoEnt, p2: &IsoEnt, pad: i32, dot_len: i32) -> i32 {
    let (s1, s2) = (ident(p1), ident(p2));

    // Compare File Name
    let l = p1.ext_off.min(p2.ext_off);
    let cmp = memcmp(s1, 0, s2, 0, l);
    if cmp != 0 {
        return cmp;
    }
    if p1.ext_off < p2.ext_off {
        if let Some(c) = unpadded(s2, l, p2.ext_off, pad) {
            return pad - c;
        }
    } else if p1.ext_off > p2.ext_off
        && let Some(c) = unpadded(s1, l, p1.ext_off, pad)
    {
        return c - pad;
    }
    // Compare File Name Extension
    if p1.ext_len == 0 && p2.ext_len == 0 {
        return 0;
    }
    if p1.ext_len == dot_len && p2.ext_len == dot_len {
        return 0;
    }
    if p1.ext_len <= dot_len {
        return -1;
    }
    if p2.ext_len <= dot_len {
        return 1;
    }
    let l = p1.ext_len.min(p2.ext_len);
    if l > 1 {
        let cmp = memcmp(s1, p1.ext_off, s2, p2.ext_off, l);
        if cmp != 0 {
            return cmp;
        }
    }
    if p1.ext_len < p2.ext_len {
        if let Some(c) = unpadded(s2, p2.ext_off + l, p2.ext_off + p2.ext_len, pad) {
            return pad - c;
        }
    } else if p1.ext_len > p2.ext_len
        && let Some(c) = unpadded(s1, p1.ext_off + l, p1.ext_off + p1.ext_len, pad)
    {
        return c - pad;
    }
    // Compare File Version Number
    // No operation. The File Version Number is always one.
    0
}

impl Idr {
    fn idr_start(&mut self, cnt: usize, num_size: i32, null_size: i32) -> Result<(), Error> {
        self.idrent_pool.clear();
        self.idrent_pool
            .try_reserve(cnt)
            .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate memory"))?;
        self.rbtree =
            RbTree::new(cnt).map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate memory"))?;
        self.wait_list.clear();
        self.num_size = num_size;
        self.null_size = null_size;
        Ok(())
    }

    fn idr_register(&mut self, ents: &[IsoEnt], cmp: Compare, isoent: EntId, noff: i32) {
        let id = self.idrent_pool.len();
        self.idrent_pool.push(IdrEnt {
            isoent,
            avail: None,
            noff,
            rename_num: 0,
        });
        let pool = &self.idrent_pool;
        let diff = |n: usize| cmp(&ents[isoent], &ents[pool[n].isoent]);
        if !self.rbtree.insert_node(id, diff)
            && let Some(n) = self.rbtree.find_node(diff)
        {
            // this `idrent' needs to rename.
            self.idrent_pool[id].avail = Some(n);
            self.wait_list.push(id);
        }
    }
}

impl Iso9660 {
    fn idr_init(&self, which: Which) -> Idr {
        let mut char_map = [0; 0x80];
        if self.vdd(which).vdd_type != VddType::Joliet {
            if self.opt.iso_level <= 3 {
                char_map = D_CHARACTERS_MAP;
            } else {
                char_map = D1_CHARACTERS_MAP;
                idr_relaxed_filenames(&mut char_map);
            }
        }
        Idr {
            idrent_pool: Vec::new(),
            rbtree: RbTree::default(),
            wait_list: Vec::new(),
            num_size: 0,
            null_size: 0,
            char_map,
        }
    }

    /// idr_extend_identifier(): extend the filename; foo.c --> foo___.c
    fn idr_extend_identifier(
        &mut self,
        wnp: &IdrEnt,
        numsize: i32,
        nullsize: i32,
    ) -> Result<(), Error> {
        let e = &mut self.ents[wnp.isoent];
        if wnp.noff + numsize != e.ext_off {
            let (src, dst) = (e.ext_off as usize, (wnp.noff + numsize) as usize);
            let n = (e.ext_len + nullsize) as usize;
            let id = e
                .identifier
                .as_mut()
                .ok_or_else(|| misc("Missing identifier"))?;
            if src.max(dst).checked_add(n).is_none_or(|end| end > id.len()) {
                return Err(misc("Identifier too long"));
            }
            id.copy_within(src..src + n, dst);
            e.ext_off = wnp.noff + numsize;
            e.id_len = e.ext_off + e.ext_len;
        }
        Ok(())
    }

    /// idr_resolve(): number the entries whose identifiers collided until
    /// each is unique. Fails with -ERANGE when a name runs out of numbers.
    fn idr_resolve(
        &mut self,
        idr: &mut Idr,
        cmp: Compare,
        fsetnum: fn(&mut [u8], i32),
    ) -> Result<(), Error> {
        let wait_list = std::mem::take(&mut idr.wait_list);
        for &n in &wait_list {
            let wnp = &idr.idrent_pool[n];
            self.idr_extend_identifier(wnp, idr.num_size, idr.null_size)?;
            let (isoent, noff) = (wnp.isoent, wnp.noff as usize);
            let avail = wnp.avail.ok_or_else(|| misc("Missing identifier"))?;
            loop {
                let num = &mut idr.idrent_pool[avail].rename_num;
                if *num >= MAX_JOLIET_ID_NUM {
                    return Err(Error::fatal(
                        libc::ERANGE,
                        "Too many duplicated identifiers",
                    ));
                }
                let id = self.ents[isoent]
                    .identifier
                    .as_mut()
                    .ok_or_else(|| misc("Missing identifier"))?;
                let p = id
                    .get_mut(noff..)
                    .filter(|p| p.len() >= idr.num_size as usize)
                    .ok_or_else(|| misc("Identifier too long"))?;
                fsetnum(p, *num);
                *num += 1;
                let (ents, pool) = (&self.ents, &idr.idrent_pool);
                if idr
                    .rbtree
                    .insert_node(n, |t| cmp(&ents[isoent], &ents[pool[t].isoent]))
                {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Generate ISO9660 Identifier.
    fn isoent_gen_iso9660_identifier(&mut self, isoent: EntId, idr: &mut Idr) -> Result<(), Error> {
        const NUM_SIZE: i32 = 3;
        const DOT_SIZE: usize = 1;
        const VERSION_SIZE: usize = 2;
        const NULL_SIZE: i32 = 1;

        if self.ents[isoent].children.is_empty() {
            return Ok(());
        }

        let char_map = idr.char_map;
        let (allow_ldots, allow_multidot, allow_period, allow_vernum);
        let (fnmax, ffmax, dnmax): (usize, usize, usize);
        if self.opt.iso_level <= 3 {
            allow_ldots = false;
            allow_multidot = false;
            allow_period = true;
            allow_vernum = self.opt.allow_vernum;
            if self.opt.iso_level == 1 {
                fnmax = 8;
                ffmax = 12; // fnmax + '.' + 3
                dnmax = 8;
            } else {
                fnmax = 30;
                ffmax = 31;
                dnmax = 31;
            }
        } else {
            allow_ldots = true;
            allow_multidot = true;
            allow_period = false;
            allow_vernum = false;
            if self.opt.rr != 0 {
                // MDR : The maximum size of Directory Record(254).
                // DRL : A Directory Record Length(33).
                // CE  : A size of SUSP CE System Use Entry(28).
                // MDR - DRL - CE = 254 - 33 - 28 = 193.
                (fnmax, ffmax, dnmax) = (193, 193, 193);
            } else {
                // XA  : CD-ROM XA System Use Extension Information(14).
                // MDR - DRL - XA = 254 - 33 -14 = 207.
                (fnmax, ffmax, dnmax) = (207, 207, 207);
            }
        }

        let children = self.ents[isoent].children.clone();
        idr.idr_start(children.len(), NUM_SIZE, NULL_SIZE)?;

        for &np in &children {
            let basename = &self.files[self.ents[np].file].basename;
            let l = basename.len();
            let mut p =
                vec![0u8; l + NUM_SIZE as usize + DOT_SIZE + VERSION_SIZE + NULL_SIZE as usize];
            p[..l].copy_from_slice(basename);

            let (mut dot, mut xdot) = (None, None);
            let mut i = 0;
            // If there is a '.' character at the first byte, it has to be
            // replaced by '_' character.
            if !allow_ldots && p[0] == b'.' {
                p[0] = b'_';
                i = 1;
            }
            while p[i] != 0 {
                let c = p[i];
                if c & 0x80 != 0 {
                    p[i] = b'_';
                } else if char_map[usize::from(c)] != 0 {
                    // if iso-level is '4', a character '.' is allowed by
                    // char_map.
                    if c == b'.' {
                        xdot = dot;
                        dot = Some(i);
                    }
                } else if c.is_ascii_lowercase() {
                    p[i] = c - (b'a' - b'A');
                } else {
                    if c == b'.' {
                        xdot = dot;
                        dot = Some(i);
                    }
                    if !(c == b'.' && allow_multidot) {
                        p[i] = b'_';
                    }
                }
                i += 1;
            }
            let ext_off = match dot {
                None => {
                    let nammax = if self.ents[np].dir { dnmax } else { fnmax };
                    if l > nammax {
                        p[nammax] = 0;
                        nammax
                    } else {
                        l
                    }
                }
                Some(dot) => {
                    p[dot] = b'.';
                    let mut ext_off = dot;
                    if self.opt.iso_level == 1 {
                        if dot <= 8 {
                            if strlen(&p[dot..]) > 4 {
                                // A length of a file extension must be less
                                // than 4
                                p[dot + 4] = 0;
                            }
                        } else {
                            p.copy_within(dot..dot + 4, 8);
                            p[12] = 0;
                            ext_off = 8;
                        }
                    } else if self.ents[np].dir {
                        if l > dnmax {
                            p[dnmax] = 0;
                            ext_off = ext_off.min(dnmax);
                        }
                    } else if l > ffmax {
                        let mut extlen = strlen(&p[dot..]);
                        let xdoff = xdot.unwrap_or(0);

                        if extlen > 1 && xdoff < fnmax - 1 {
                            if extlen > ffmax {
                                extlen = ffmax;
                            }
                            let mut off = ffmax - extlen;
                            if off == 0 {
                                // A dot('.') character doesn't place to the
                                // first byte of identifier.
                                off += 1;
                                extlen -= 1;
                            }
                            p.copy_within(dot..dot + extlen, off);
                            p[ffmax] = 0;
                            ext_off = off;
                        } else {
                            p[fnmax] = 0;
                            ext_off = fnmax;
                        }
                    }
                    ext_off
                }
            };
            // Save an offset of a file name extension to sort files.
            let e = &mut self.ents[np];
            e.ext_off = ext_off as i32;
            e.ext_len = strlen(&p[ext_off..]) as i32;
            e.id_len = e.ext_off + e.ext_len;
            let l = e.id_len;
            e.identifier = Some(p);

            // Make an offset of the number which is used to be set
            // hexadecimal number to avoid duplicate identifier.
            let ext_off = ext_off as i32;
            let ffmax = ffmax as i32;
            let noff = if self.opt.iso_level == 1 {
                ext_off.min(5)
            } else {
                let noff = if l == ffmax {
                    ext_off - 3
                } else if l == ffmax - 1 {
                    ext_off - 2
                } else if l == ffmax - 2 {
                    ext_off - 1
                } else {
                    ext_off
                };
                noff.max(0)
            };
            // Register entry to the identifier resolver.
            idr.idr_register(&self.ents, isoent_cmp_iso9660_identifier, np, noff);
        }

        // Resolve duplicate identifier.
        self.idr_resolve(idr, isoent_cmp_iso9660_identifier, idr_set_num)?;

        // Add a period and a version number to identifiers.
        for &np in &children {
            let e = &mut self.ents[np];
            if !e.dir && e.rr_child.is_none() {
                let id = e
                    .identifier
                    .as_mut()
                    .ok_or_else(|| misc("Missing identifier"))?;
                let mut p = (e.ext_off + e.ext_len) as usize;
                let mut put = |i: usize, c: u8| {
                    id.get_mut(i)
                        .map(|b| *b = c)
                        .ok_or_else(|| misc("Identifier too long"))
                };
                if e.ext_len == 0 && allow_period {
                    put(p, b'.')?;
                    p += 1;
                    e.ext_len = 1;
                }
                if e.ext_len == 1 && !allow_period {
                    p -= 1;
                    put(p, 0)?;
                    e.ext_len = 0;
                }
                e.id_len = e.ext_off + e.ext_len;
                if allow_vernum {
                    put(p, b';')?;
                    put(p + 1, b'1')?;
                    p += 2;
                    e.id_len += 2;
                }
                put(p, 0)?;
            } else {
                e.id_len = e.ext_off + e.ext_len;
            }
            e.mb_len = e.id_len;
        }
        Ok(())
    }

    /// Generate Joliet Identifier.
    fn isoent_gen_joliet_identifier(&mut self, isoent: EntId, idr: &mut Idr) -> Result<(), Error> {
        const NUM_SIZE: i32 = 6;
        const NULL_SIZE: i32 = 2;

        if self.ents[isoent].children.is_empty() {
            return Ok(());
        }

        let ffmax: usize = if self.opt.joliet == OPT_JOLIET_LONGNAME {
            206
        } else {
            128
        };

        let children = self.ents[isoent].children.clone();
        idr.idr_start(children.len(), NUM_SIZE, NULL_SIZE)?;

        let mut parent_len: i64 = 1;
        let mut np = isoent;
        while self.ents[np].parent != np {
            parent_len += i64::from(self.ents[np].mb_len) + 1;
            np = self.ents[np].parent;
        }

        for &np in &children {
            let file = &self.files[self.ents[np].file];
            let l = file.basename_utf16.len().min(ffmax);

            let mut p = vec![0u8; l + NUM_SIZE as usize + NULL_SIZE as usize];
            p[..l].copy_from_slice(&file.basename_utf16[..l]);

            let mut dot = l;
            let mut i = 0;
            while i < l {
                if !joliet_allowed_char(p[i], p[i + 1]) {
                    p[i..i + 2].copy_from_slice(&[0x00, 0x5F]); // '_'
                } else if p[i] == 0 && p[i + 1] == 0x2E {
                    // '.'
                    dot = i;
                }
                i += 2;
            }
            let ext_off = dot as i32;

            // Get a length of MBS of a full-pathname.
            let mb_len = if file.basename_utf16.len() > ffmax {
                // A conversion that fails keeps what it converted.
                let _ = crate::string::strncpy_l(
                    &mut self.mbs,
                    &p[..l],
                    self.sconv_from_utf16be.as_deref(),
                );
                self.mbs.len() as i32
            } else {
                file.basename.len() as i32
            };

            // If a length of full-pathname is longer than 240 bytes, it
            // violates Joliet extensions regulation.
            if parent_len > 240 || mb_len > 240 || parent_len + i64::from(mb_len) > 240 {
                let mut msg =
                    b"The regulation of Joliet extensions; A length of a full-pathname of `"
                        .to_vec();
                msg.extend_from_slice(&shown(self.files[self.ents[np].file].entry.pathname()));
                msg.extend_from_slice(
                    format!("' is longer than 240 bytes, (p={parent_len}, b={mb_len})").as_bytes(),
                );
                return Err(misc(msg));
            }

            let e = &mut self.ents[np];
            e.identifier = Some(p);
            e.ext_off = ext_off;
            e.ext_len = l as i32 - ext_off;
            e.id_len = l as i32;
            e.mb_len = mb_len;

            // Make an offset of the number which is used to be set
            // hexadecimal number to avoid duplicate identifier.
            let noff = if l == ffmax {
                ext_off - 6
            } else if l == ffmax - 2 {
                ext_off - 4
            } else if l == ffmax - 4 {
                ext_off - 2
            } else {
                ext_off
            };
            // Register entry to the identifier resolver.
            idr.idr_register(&self.ents, isoent_cmp_joliet_identifier, np, noff.max(0));
        }

        // Resolve duplicate identifier with Joliet Volume.
        self.idr_resolve(idr, isoent_cmp_joliet_identifier, idr_set_num_beutf16)
    }

    fn isoent_make_sorted_files(&mut self, isoent: EntId, idr: &Idr) {
        self.ents[isoent].children_sorted = idr
            .rbtree
            .in_order()
            .into_iter()
            .map(|n| idr.idrent_pool[n].isoent)
            .collect();
    }

    /// - Generate ISO9660 and Joliet identifiers from basenames.
    /// - Sort files by each directory.
    pub(super) fn isoent_traverse_tree(&mut self, which: Which) -> Result<(), Error> {
        let mut idr = self.idr_init(which);
        let vdd = self.vdd(which);
        let (vdd_type, max_depth) = (vdd.vdd_type, vdd.max_depth);
        for (np, depth) in self.walk_dirs(vdd.rootent, 0, |d| d + 1 < max_depth) {
            let birth_time = self.birth_time;
            let e = &mut self.files[self.ents[np].file].entry;
            if self.ents[np].r#virtual && e.mtime_is_set() == 0 {
                // Set properly times to virtual directory
                e.set_mtime(birth_time, 0);
                e.set_atime(birth_time, 0);
                e.set_ctime(birth_time, 0);
            }
            if self.ents[np].children.is_empty() {
                continue;
            }
            if vdd_type != VddType::Joliet && self.opt.rr == 0 && depth + 1 >= max_depth {
                self.directories_too_deep = Some(np);
            } else {
                // Generate Identifier
                if vdd_type == VddType::Joliet {
                    self.isoent_gen_joliet_identifier(np, &mut idr)?;
                } else {
                    self.isoent_gen_iso9660_identifier(np, &mut idr)?;
                }
                self.isoent_make_sorted_files(np, &idr);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_numbers_are_base_36() {
        let mut p = [0; 3];
        idr_set_num(&mut p, 0);
        assert_eq!(&p, b"000");
        idr_set_num(&mut p, 35);
        assert_eq!(&p, b"00Z");
        idr_set_num(&mut p, 36 * 36 * 36 - 1);
        assert_eq!(&p, b"ZZZ");
        let mut w = [0; 6];
        idr_set_num_beutf16(&mut w, 37);
        assert_eq!(&w, &[0, b'0', 0, b'1', 0, b'1']);
    }
}
