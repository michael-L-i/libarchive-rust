// Ported from libarchive/archive_write_set_format_iso9660.c: the isofile
// and isoent functions, the directory tree, locations, deep-directory
// relocation and path tables.

use super::*;
use crate::entry::AE_IFDIR;

/// NAME_MAX: the longest path component isoent_tree() and
/// isoent_find_entry() take.
const NAME_MAX: usize = 255;

/// get_path_component(): the length of the first component of `fn_`, 0
/// at its end, or -1 if the component is longer than NAME_MAX.
fn get_path_component(fn_: &[u8]) -> isize {
    let l = match fn_.iter().position(|&b| b == b'/') {
        Some(p) => p,
        None => {
            if fn_.is_empty() {
                return 0;
            }
            fn_.len()
        }
    };
    if l > NAME_MAX {
        return -1;
    }
    l as isize
}

/// isofile_gen_utility_names()'s cleanup of a pathname: remove leading
/// '/', '../' and './' elements, "/", "/." and "/.." elements from the
/// tail, and '//', '/./' and 'dir/..' inside. Done as upstream does it, in
/// place on a NUL-terminated buffer; the result ends at the first NUL.
fn cleanup_pathname(pathname: &[u8]) -> Vec<u8> {
    let mut s = pathname.to_vec();
    s.push(0);
    let at = |s: &[u8], i: usize| s.get(i).copied().unwrap_or(0);
    let mut len = pathname.len();

    // Remove leading '/', '../' and './' elements
    let mut p = 0;
    while at(&s, p) != 0 {
        if at(&s, p) == b'/' {
            p += 1;
            len -= 1;
        } else if at(&s, p) != b'.' {
            break;
        } else if at(&s, p + 1) == b'.' && at(&s, p + 2) == b'/' {
            p += 3;
            len -= 3;
        } else if at(&s, p + 1) == b'/' || (at(&s, p + 1) == b'.' && at(&s, p + 2) == 0) {
            p += 2;
            len -= 2;
        } else if at(&s, p + 1) == 0 {
            p += 1;
            len -= 1;
        } else {
            break;
        }
    }
    s.drain(..p);

    // Remove "/","/." and "/.." elements from tail.
    while len > 0 {
        let ll = len;
        if len > 0 && s[len - 1] == b'/' {
            s[len - 1] = 0;
            len -= 1;
        }
        if len > 1 && s[len - 2] == b'/' && s[len - 1] == b'.' {
            s[len - 2] = 0;
            len -= 2;
        }
        if len > 2 && s[len - 3] == b'/' && s[len - 2] == b'.' && s[len - 1] == b'.' {
            s[len - 3] = 0;
            len -= 3;
        }
        if ll == len {
            break;
        }
    }

    let mut p = 0;
    while at(&s, p) != 0 {
        if at(&s, p) == b'/' {
            if at(&s, p + 1) == b'/' {
                // Convert '//' --> '/'
                s.remove(p);
            } else if at(&s, p + 1) == b'.' && at(&s, p + 2) == b'/' {
                // Convert '/./' --> '/'
                s.drain(p..p + 2);
            } else if at(&s, p + 1) == b'.' && at(&s, p + 2) == b'.' && at(&s, p + 3) == b'/' {
                // Convert 'dir/dir1/../dir2/' --> 'dir/dir2/'
                let mut off = 4;
                while at(&s, p + off) == b'/' {
                    off += 1;
                }
                let rp = s[..p].iter().rposition(|&b| b == b'/');
                match rp {
                    Some(rp) if rp > 0 => {
                        s.drain(rp + 1..p + off);
                        p = rp;
                    }
                    _ => {
                        s.drain(..p + off);
                        p = 0;
                    }
                }
            } else {
                p += 1;
            }
        } else if p == 0 && at(&s, 0) == b'.' && at(&s, 1) == b'.' && at(&s, 2) == b'/' {
            let mut off = 3;
            while at(&s, off) == b'/' {
                off += 1;
            }
            s.drain(..off);
            p = 0;
        } else {
            p += 1;
        }
    }
    s.truncate(strlen(&s));
    s
}

impl Iso9660 {
    pub(super) fn isofile_new(&mut self, entry: Option<&Entry>) -> FileId {
        let entry = match entry {
            Some(e) => e.clone_entry(),
            None => Entry::new(self.conv.clone()),
        };
        self.files.push(IsoFile {
            hardlink_target: None,
            entry,
            parentdir: Vec::new(),
            basename: Vec::new(),
            basename_utf16: Vec::new(),
            symlink: Vec::new(),
            dircnt: 0,
            content: vec![Content::default()],
            cur_content: Some(0),
            write_content: false,
            boot: Boot::No,
            zisofs: ZisofsHeader::default(),
        });
        self.files.len() - 1
    }

    /// Generate a parent directory name and a base name from a pathname.
    /// `a` takes the warning about a name that won't convert to UTF-16BE.
    pub(super) fn isofile_gen_utility_names(
        &mut self,
        a: Option<&Base>,
        file: FileId,
    ) -> Result<c_int, Error> {
        let mut ret = ARCHIVE_OK;
        let f = &mut self.files[file];
        f.parentdir.clear();
        f.basename.clear();
        f.basename_utf16.clear();
        f.symlink.clear();

        let pathname = match f.entry.pathname() {
            Some(p) if !p.to_bytes().is_empty() => p.to_bytes().to_vec(),
            _ => {
                // virtual root
                f.dircnt = 0;
                return Ok(ret);
            }
        };

        // Make a UTF-16BE basename if Joliet extension enabled.
        if self.opt.joliet != 0 {
            self.make_utf16be_converters()?;
            let conv = self.sconv_to_utf16be.clone();
            let f = &mut self.files[file];

            // Convert a filename to UTF-16BE.
            let (u16, converted) = f.entry.pathname_l(conv.as_deref());
            let u16 = u16.unwrap_or_default().to_vec();
            if !converted {
                if let Some(a) = a {
                    a.set_error(
                        ARCHIVE_ERRNO_MISC,
                        Some(b"A filename cannot be converted to UTF-16BE;You should disable making Joliet extension"),
                    );
                }
                ret = ARCHIVE_WARN;
            }

            // Make sure a path separator is not in the last; Remove
            // trailing '/'.
            let mut u16len = u16.len();
            while u16len >= 2 && u16[u16len - 2] == 0 && u16[u16len - 1] == b'/' {
                u16len -= 2;
            }

            // Find a basename in UTF-16BE.
            let units = u16len >> 1;
            let (mut ulast, mut ulen_last) = (0, units);
            for i in 0..units {
                if u16[2 * i] == 0 && u16[2 * i + 1] == b'/' {
                    ulast = 2 * i + 2;
                    ulen_last = units - i - 1;
                }
            }
            f.basename_utf16 = u16[ulast..ulast + 2 * ulen_last].to_vec();
        }

        let f = &mut self.files[file];
        let dirname = cleanup_pathname(&pathname);

        if f.entry.filetype() == AE_IFLNK {
            // Convert symlink name too.
            f.symlink = f
                .entry
                .symlink()
                .map(|s| s.to_bytes().to_vec())
                .unwrap_or_default();
        }

        // - Count up directory elements.
        // - Find out the position which points the last position of path
        //   separator('/').
        let mut slash = None;
        f.dircnt = 0;
        for (i, &c) in dirname.iter().enumerate() {
            if c == b'/' {
                slash = Some(i);
                f.dircnt += 1;
            }
        }
        match slash {
            None => {
                // The pathname doesn't have a parent directory.
                f.basename = dirname;
            }
            Some(slash) => {
                // Make a basename from dirname and slash
                f.basename = dirname[slash + 1..].to_vec();
                f.parentdir = dirname[..slash].to_vec();
                if f.entry.filetype() == AE_IFDIR {
                    f.dircnt += 1;
                }
            }
        }
        Ok(ret)
    }

    /// Register a entry to get a hardlink target.
    pub(super) fn isofile_register_hardlink(&mut self, file: FileId) {
        let f = &mut self.files[file];
        f.entry.set_nlink(1);
        match f.entry.hardlink().map(|p| p.to_bytes().to_vec()) {
            None => {
                // This `file` is a hardlink target. A hardlink target
                // must be the first position. A second target of the same
                // name is not inserted.
                let key = f
                    .entry
                    .pathname()
                    .map(|p| p.to_bytes().to_vec())
                    .unwrap_or_default();
                self.hardlinks.entry(key).or_insert(Hardlink {
                    nlink: 1,
                    file_list: vec![file],
                });
            }
            Some(pathname) => {
                if let Some(hl) = self.hardlinks.get_mut(&pathname) {
                    // Insert `file` entry into the tail.
                    hl.file_list.push(file);
                    hl.nlink = hl.nlink.wrapping_add(1);
                }
                f.entry.unset_size();
            }
        }
    }

    /// Hardlinked files have to have the same location of extent. We have
    /// to find out hardlink target entries for the entries which have a
    /// hardlink target name.
    pub(super) fn isofile_connect_hardlink_files(&mut self) {
        for hl in self.hardlinks.values() {
            // The first entry must be a hardlink target.
            let target = hl.file_list[0];
            self.files[target].entry.set_nlink(hl.nlink);
            // Set a hardlink target to reference entries.
            for &nf in &hl.file_list[1..] {
                self.files[nf].hardlink_target = Some(target);
                self.files[nf].entry.set_nlink(hl.nlink);
            }
        }
    }

    pub(super) fn isoent_new(&mut self, file: FileId) -> EntId {
        let id = self.ents.len();
        let dir = self.files[file].entry.filetype() == AE_IFDIR;
        self.ents.push(IsoEnt {
            file,
            parent: id,
            children: Vec::new(),
            child_names: BTreeMap::new(),
            subdirs: Vec::new(),
            children_sorted: Vec::new(),
            ptnext: None,
            dir_number: 0,
            dr_len: DrLen::default(),
            dir_location: 0,
            dir_block: 0,
            identifier: None,
            ext_off: 0,
            ext_len: 0,
            id_len: 0,
            mb_len: 0,
            rr_parent: None,
            rr_child: None,
            extr_rec_list: Vec::new(),
            extr_rec_current: None,
            r#virtual: false,
            dir,
        });
        id
    }

    pub(super) fn isoent_create_virtual_dir(&mut self, pathname: &[u8]) -> Result<EntId, Error> {
        let file = self.isofile_new(None);
        let (uid, gid) = crate::ffi::sys::user_ids();
        let e = &mut self.files[file].entry;
        e.set_pathname(pathname);
        e.unset_mtime();
        e.unset_atime();
        e.unset_ctime();
        e.set_uid(uid.into());
        e.set_gid(gid.into());
        e.set_mode(0o555 | AE_IFDIR);
        e.set_nlink(2);
        self.isofile_gen_utility_names(None, file)?;

        let isoent = self.isoent_new(file);
        self.ents[isoent].dir = true;
        self.ents[isoent].r#virtual = true;
        Ok(isoent)
    }

    pub(super) fn isoent_add_child_head(&mut self, parent: EntId, child: EntId) -> bool {
        let name = self.files[self.ents[child].file].basename.clone();
        if self.ents[parent].child_names.contains_key(&name) {
            return false;
        }
        self.ents[parent].child_names.insert(name, child);
        self.ents[parent].children.insert(0, child);
        self.ents[child].parent = parent;

        // Add a child to a sub-directory chain
        if self.ents[child].dir {
            self.ents[parent].subdirs.insert(0, child);
        }
        true
    }

    pub(super) fn isoent_add_child_tail(&mut self, parent: EntId, child: EntId) -> bool {
        let name = self.files[self.ents[child].file].basename.clone();
        if self.ents[parent].child_names.contains_key(&name) {
            return false;
        }
        self.ents[parent].child_names.insert(name, child);
        self.ents[parent].children.push(child);
        self.ents[child].parent = parent;

        // Add a child to a sub-directory chain
        if self.ents[child].dir {
            self.ents[parent].subdirs.push(child);
        }
        true
    }

    /// isoent_remove_child(). Upstream looks for the child after the first
    /// entry of each chain, and runs off the end of a chain the child heads.
    fn isoent_remove_child(&mut self, parent: EntId, child: EntId) -> Result<(), Error> {
        let lost = || misc("Can't remove an entry from its directory");
        let p = &mut self.ents[parent];
        // Remove a child entry from children chain.
        let i = p
            .children
            .iter()
            .skip(1)
            .position(|&e| e == child)
            .ok_or_else(lost)?;
        p.children.remove(i + 1);

        if self.ents[child].dir {
            // Remove a child entry from sub-directory chain.
            let p = &mut self.ents[parent];
            let i = p
                .subdirs
                .iter()
                .skip(1)
                .position(|&e| e == child)
                .ok_or_else(lost)?;
            p.subdirs.remove(i + 1);
        }

        let name = &self.files[self.ents[child].file].basename;
        self.ents[parent].child_names.remove(name);
        Ok(())
    }

    /// isoent_clone_tree(): a copy of the tree under `root`, sharing its
    /// isofiles. Returns the new root.
    pub(super) fn isoent_clone_tree(&mut self, root: EntId) -> EntId {
        let xroot = self.isoent_new(self.ents[root].file);
        self.ents[xroot].parent = xroot;
        // Depth first along `children`, as upstream walks it.
        let mut stack = vec![(root, xroot)];
        while let Some((np, newent)) = stack.pop() {
            if !self.ents[np].dir {
                continue;
            }
            let mut kids = Vec::with_capacity(self.ents[np].children.len());
            for &child in &self.ents[np].children.clone() {
                let c = self.isoent_new(self.ents[child].file);
                self.isoent_add_child_tail(newent, c);
                kids.push((child, c));
            }
            stack.extend(kids.into_iter().rev());
        }
        xroot
    }

    /// The directories under `root` in the order upstream's walks visit
    /// them: depth first along the `subdirs` chains, starting at `depth`
    /// and entering a directory's subdirectories while `enter(depth)`.
    pub(super) fn walk_dirs(
        &self,
        root: EntId,
        depth: i32,
        enter: impl Fn(i32) -> bool,
    ) -> Vec<(EntId, i32)> {
        let mut out = Vec::new();
        let mut stack = vec![(root, depth)];
        while let Some((np, depth)) = stack.pop() {
            out.push((np, depth));
            if enter(depth) {
                stack.extend(self.ents[np].subdirs.iter().rev().map(|&d| (d, depth + 1)));
            }
        }
        out
    }

    pub(super) fn vdd(&self, which: Which) -> &Vdd {
        match which {
            Which::Primary => &self.primary,
            Which::Joliet => &self.joliet,
        }
    }

    pub(super) fn vdd_mut(&mut self, which: Which) -> &mut Vdd {
        match which {
            Which::Primary => &mut self.primary,
            Which::Joliet => &mut self.joliet,
        }
    }

    /// Setup directory locations.
    pub(super) fn isoent_setup_directory_location(
        &mut self,
        mut location: i32,
        which: Which,
    ) -> Result<(), Error> {
        let vdd = self.vdd(which);
        let max_depth = vdd.max_depth;
        let dirs = self.walk_dirs(vdd.rootent, 0, |d| d + 1 < max_depth);
        self.vdd_mut(which).total_dir_block = 0;
        for (np, depth) in dirs {
            let dir_block = self.calculate_directory_descriptors(which, np, depth)?;
            self.ents[np].dir_block = dir_block;
            let vdd = self.vdd_mut(which);
            vdd.total_dir_block = vdd.total_dir_block.wrapping_add(dir_block);
            self.ents[np].dir_location = location as u32;
            location = location.wrapping_add(dir_block);
            let block = self.extra_setup_location(np, location);
            let vdd = self.vdd_mut(which);
            vdd.total_dir_block = vdd.total_dir_block.wrapping_add(block);
            location = location.wrapping_add(block);
        }
        Ok(())
    }

    fn isoent_file_location(&mut self, isoent: EntId, symlocation: &mut i32) -> Result<(), Error> {
        let cnt = self.ents[isoent].children.len();
        for n in 0..cnt {
            let np = *self.ents[isoent]
                .children_sorted
                .get(n)
                .ok_or_else(|| misc("Directory entries are not sorted"))?;
            if self.ents[np].dir {
                continue;
            }
            if Some(np) == self.el_torito.boot {
                continue;
            }
            let file = &mut self.files[self.ents[np].file];
            if file.boot != Boot::No || file.hardlink_target.is_some() {
                continue;
            }
            if file.entry.filetype() == AE_IFLNK || file.content[0].size == 0 {
                // Do not point a valid location. Make sure entry is not
                // hardlink file.
                file.content[0].location = *symlocation as u32;
                *symlocation = symlocation.wrapping_sub(1);
                continue;
            }

            file.write_content = true;
        }
        Ok(())
    }

    /// Setup file locations.
    pub(super) fn isoent_setup_file_location(&mut self, mut location: i32) -> Result<(), Error> {
        self.total_file_block = 0;
        if let Some(isoent) = self.el_torito.catalog {
            let file = &mut self.files[self.ents[isoent].file];
            file.content[0].location = location as u32;
            let block = (file
                .entry
                .size()
                .wrapping_add(LOGICAL_BLOCK_SIZE as i64 - 1)
                >> LOGICAL_BLOCK_BITS) as i32;
            location = location.wrapping_add(block);
            self.total_file_block = self.total_file_block.wrapping_add(block);
        }
        if let Some(isoent) = self.el_torito.boot {
            let media_type = self.el_torito.media_type;
            let file = &mut self.files[self.ents[isoent].file];
            file.content[0].location = location as u32;
            let mut size = boot::fd_boot_image_size(media_type) as u64;
            if size == 0 {
                size = file.entry.size() as u64;
            }
            let block = ((size >> LOGICAL_BLOCK_BITS)
                + u64::from(size & (LOGICAL_BLOCK_SIZE as u64 - 1) != 0))
                as i32;
            location = location.wrapping_add(block);
            self.total_file_block = self.total_file_block.wrapping_add(block);
            file.content[0].blocks = block;
        }

        let mut symlocation = -16;
        let (joliet, root) = if self.opt.rr == 0 && self.opt.joliet != 0 {
            (true, self.joliet.rootent)
        } else {
            (false, self.primary.rootent)
        };
        let (rr, max_depth) = (self.opt.rr, self.primary.max_depth);
        let dirs = self.walk_dirs(root, 0, |depth| {
            joliet
                || (rr == OPT_RR_DISABLED && depth + 2 < max_depth)
                || (rr != OPT_RR_DISABLED && depth + 1 < max_depth)
        });
        for (np, _) in dirs {
            self.isoent_file_location(np, &mut symlocation)?;
        }

        let mut total_block: i32 = 0;
        for &f in &self.data_file_list {
            let file = &mut self.files[f];
            if !file.write_content {
                continue;
            }
            for c in &mut file.content {
                c.location = location as u32;
                location = location.wrapping_add(c.blocks);
                total_block = total_block.wrapping_add(c.blocks);
            }
            file.cur_content = None;
        }
        self.total_file_block = self.total_file_block.wrapping_add(total_block);
        Ok(())
    }

    /// The error isoent_tree() fails with for two entries of one name.
    fn isoent_same_entry(&mut self, np: Option<EntId>, isoent: EntId) -> Result<EntId, Error> {
        let np = np.ok_or_else(|| misc("Can't find the duplicate entry"))?;
        // We have already has the entry the filename of which is the same.
        let (f1, f2) = (self.ents[np].file, self.ents[isoent].file);

        // If the file type of entries is different, we cannot handle it.
        if self.files[f1].entry.filetype() != self.files[f2].entry.filetype() {
            let path = shown(self.files[f1].entry.pathname());
            return Err(Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_MISC,
                [
                    b"Found duplicate entries `",
                    &path[..],
                    b"' and its file type is different",
                ]
                .concat(),
            ));
        }

        // Swap file entries.
        self.ents[np].file = f2;
        self.ents[isoent].file = f1;
        self.ents[np].r#virtual = false;
        Ok(np)
    }

    /// Add a new entry into the tree. Returns the entry the tree now holds
    /// for it: `isoent`, or the entry of the same name it replaced.
    pub(super) fn isoent_tree(&mut self, isoent: EntId) -> Result<EntId, Error> {
        let file = self.ents[isoent].file;
        let parentdir = self.files[file].parentdir.clone();
        let basename = self.files[file].basename.clone();
        let mut dent = self.primary.rootent;

        // If the path of the parent directory of `isoent' entry is the
        // same as the path of `cur_dirent', add isoent to `cur_dirent'.
        if self.cur_dirstr == parentdir {
            if !self.isoent_add_child_tail(self.cur_dirent, isoent) {
                let np = self.isoent_find_child(self.cur_dirent, &basename);
                return self.isoent_same_entry(np, isoent);
            }
            return Ok(isoent);
        }

        let too_small = || misc("A name buffer is too small");
        let mut fn_ = 0;
        let mut l;
        loop {
            l = get_path_component(&parentdir[fn_..]);
            if l == 0 {
                break;
            }
            if l < 0 {
                return Err(too_small());
            }
            let l = l as usize;
            let Some(np) = self.isoent_find_child(dent, &parentdir[fn_..fn_ + l]) else {
                break;
            };

            // Find next subdirectory.
            if !self.ents[np].dir {
                // NOT Directory!
                let path = shown(self.files[self.ents[np].file].entry.pathname());
                let this = shown(self.files[file].entry.pathname());
                return Err(Error::new(
                    ARCHIVE_FAILED,
                    ARCHIVE_ERRNO_MISC,
                    [
                        b"`",
                        &path[..],
                        b"' is not directory, we cannot insert `",
                        &this[..],
                        b"' ",
                    ]
                    .concat(),
                ));
            }
            fn_ += l;
            if parentdir.get(fn_) == Some(&b'/') {
                fn_ += 1;
            }
            dent = np;
        }

        // Create virtual parent directories.
        while fn_ < parentdir.len() {
            let mut name = parentdir[..fn_ + l as usize].to_vec();
            if name.last() == Some(&b'/') {
                name.pop();
            }
            let vp = self.isoent_create_virtual_dir(&name)?;
            let dircnt = self.files[self.ents[vp].file].dircnt;
            if dircnt > self.dircnt_max {
                self.dircnt_max = dircnt;
            }
            self.isoent_add_child_tail(dent, vp);

            fn_ += l as usize;
            if parentdir.get(fn_) == Some(&b'/') {
                fn_ += 1;
            }
            l = get_path_component(&parentdir[fn_..]);
            if l < 0 {
                return Err(too_small());
            }
            dent = vp;
        }

        // Found out the parent directory where isoent can be inserted.
        self.cur_dirent = dent;
        let d = &self.files[self.ents[dent].file];
        let mut dirstr = Vec::with_capacity(d.parentdir.len() + d.basename.len() + 2);
        if !d.parentdir.is_empty() {
            dirstr.extend_from_slice(&d.parentdir);
            dirstr.push(b'/');
        }
        dirstr.extend_from_slice(&d.basename);
        self.cur_dirstr = dirstr;

        if !self.isoent_add_child_tail(dent, isoent) {
            let np = self.isoent_find_child(dent, &basename);
            return self.isoent_same_entry(np, isoent);
        }
        Ok(isoent)
    }

    /// Find a entry from `isoent'
    pub(super) fn isoent_find_child(&self, isoent: EntId, child_name: &[u8]) -> Option<EntId> {
        self.ents[isoent].child_names.get(child_name).copied()
    }

    /// Find a entry full-path of which is specified by `fn_` parameter, in
    /// the tree. Upstream leaves its name buffer unset for a component too
    /// long for it and goes on; this stops there.
    pub(super) fn isoent_find_entry(&self, rootent: EntId, fn_: &[u8]) -> Option<EntId> {
        let mut isoent = rootent;
        let mut fn_ = fn_;
        loop {
            let l = get_path_component(fn_);
            if l <= 0 {
                return None;
            }
            let name = &fn_[..l as usize];
            fn_ = &fn_[l as usize..];
            if fn_.first() == Some(&b'/') {
                fn_ = &fn_[1..];
            }

            let np = self.isoent_find_child(isoent, name)?;
            if fn_.is_empty() {
                // We found out the entry
                return Some(np);
            }

            // Try sub directory.
            isoent = np;
            if !self.ents[isoent].dir {
                // Not Directory
                return None;
            }
        }
    }

    fn path_table_add_entry(&mut self, which: Which, depth: i32, ent: EntId) -> Result<(), Error> {
        self.ents[ent].ptnext = None;
        let pt = usize::try_from(depth)
            .ok()
            .and_then(|d| self.vdd_mut(which).pathtbl.get_mut(d))
            .ok_or_else(|| misc("Path table depth out of range"))?;
        let last = pt.last.replace(ent);
        if pt.first.is_none() {
            pt.first = Some(ent);
        }
        pt.cnt += 1;
        if let Some(last) = last {
            self.ents[last].ptnext = Some(ent);
        }
        Ok(())
    }

    /// Collect directory entries into path_table by a directory depth.
    fn isoent_collect_dirs(
        &mut self,
        which: Which,
        rootent: Option<EntId>,
        depth: i32,
    ) -> Result<(), Error> {
        let vdd = self.vdd(which);
        let max_depth = vdd.max_depth;
        let root = rootent.unwrap_or(vdd.rootent);
        for (np, depth) in self.walk_dirs(root, depth, |d| d + 1 < max_depth) {
            // Register current directory to pathtable.
            self.path_table_add_entry(which, depth, np)?;
        }
        Ok(())
    }

    /// The entry whose number of levels in a directory hierarchy is large
    /// than eight relocate to rr_move directory.
    fn isoent_rr_move_dir(
        &mut self,
        rr_moved: &mut Option<EntId>,
        curent: EntId,
    ) -> Result<EntId, Error> {
        let rrmoved = match *rr_moved {
            Some(r) => r,
            None => {
                let rootent = self.primary.rootent;
                // There isn't rr_move entry. Create rr_move entry and
                // insert it into the root entry.
                let rrmoved = self.isoent_create_virtual_dir(b"rr_moved")?;
                // Add "rr_moved" entry to the root entry.
                self.isoent_add_child_head(rootent, rrmoved);
                let root = &mut self.files[self.ents[rootent].file].entry;
                root.set_nlink(root.nlink().wrapping_add(1));
                // Register "rr_moved" entry to second level pathtable.
                self.path_table_add_entry(Which::Primary, 1, rrmoved)?;
                // Save rr_moved.
                *rr_moved = Some(rrmoved);
                rrmoved
            }
        };
        // Make a clone of curent which is going to be relocated to
        // rr_moved.
        let mvent = self.isoent_new(self.ents[curent].file);

        // linking.. and use for creating "CL", "PL" and "RE"
        self.ents[mvent].rr_parent = Some(self.ents[curent].parent);
        self.ents[curent].rr_child = Some(mvent);

        // Move subdirectories from the curent to mvent
        let children = std::mem::take(&mut self.ents[curent].children);
        for &np in &children {
            self.ents[np].parent = mvent;
        }
        self.ents[mvent].children = children;
        self.ents[mvent].subdirs = std::mem::take(&mut self.ents[curent].subdirs);

        // The mvent becomes a child of the rr_moved entry.
        if !self.isoent_add_child_tail(rrmoved, mvent) {
            return Err(misc("Unable to insert rr_moved entry"));
        }
        let e = &mut self.files[self.ents[rrmoved].file].entry;
        e.set_nlink(e.nlink().wrapping_add(1));

        // This entry which relocated to the rr_moved directory has to set
        // the flag as a file. See also RRIP 4.1.5.1 Description of the "CL"
        // System Use Entry.
        self.ents[curent].dir = false;

        Ok(mvent)
    }

    fn isoent_rr_move(&mut self) -> Result<(), Error> {
        let depth = (MAX_DEPTH - 1) as usize;
        // There aren't level 8 directories reaching a deeper level.
        if self.primary.pathtbl.get(depth).is_none_or(|pt| pt.cnt == 0) {
            return Ok(());
        }

        let rootent = self.primary.rootent;
        // If "rr_moved" directory is already existing, we have to use it.
        let mut rr_moved = self.isoent_find_child(rootent, b"rr_moved");
        if let Some(r) = rr_moved {
            if !self.ents[r].dir {
                return Err(misc(
                    "Unable to relocate directories into rr_moved: the existing entry is not a directory",
                ));
            }
            if self.ents[rootent].children.first() != Some(&r) {
                // It's necessary that rr_move is the first entry of the
                // root.
                // Remove "rr_moved" entry from children chain.
                self.isoent_remove_child(rootent, r)?;

                // Add "rr_moved" entry to the head of children chain.
                self.isoent_add_child_head(rootent, r);
            }
        }

        // Check level 8 path_table. If find out sub directory entries, that
        // entries move to rr_move.
        let mut np = self.primary.pathtbl[depth].first;
        while np.is_some() {
            let last = self.primary.pathtbl[depth].last;
            while let Some(n) = np {
                if self.ents[n].dir {
                    for mvent in self.ents[n].subdirs.clone() {
                        let newent = self.isoent_rr_move_dir(&mut rr_moved, mvent)?;
                        self.isoent_collect_dirs(Which::Primary, Some(newent), 2)?;
                    }
                }
                np = self.ents[n].ptnext;
            }
            // If new entries are added to level 8 path_talbe, its sub
            // directory entries move to rr_move too.
            np = last.and_then(|l| self.ents[l].ptnext);
        }

        Ok(())
    }

    /// _compare_path_table(): this comparing rule is according to ISO9660
    /// Standard 6.9.1
    fn compare_path_table(&self, p1: EntId, p2: EntId, joliet: bool) -> i32 {
        let (e1, e2) = (&self.ents[p1], &self.ents[p2]);
        // Compare parent directory number
        let cmp = self.ents[e1.parent].dir_number - self.ents[e2.parent].dir_number;
        if cmp != 0 {
            return cmp;
        }

        // Compare identifier
        let s1 = e1.identifier.as_deref().unwrap_or_default();
        let s2 = e2.identifier.as_deref().unwrap_or_default();
        let byte = |s: &[u8], i: i32| s.get(i as usize).copied().map_or(0, i32::from);
        let l = e1.ext_off.min(e2.ext_off);
        for i in 0..l {
            let (c1, c2) = (byte(s1, i), byte(s2, i));
            if c1 != c2 {
                return c1 - c2;
            }
            // strncmp() stops at a NUL; memcmp() does not.
            if !joliet && c1 == 0 {
                return 0;
            }
        }
        let pad = if joliet { 0 } else { 0x20 };
        if e1.ext_off < e2.ext_off {
            for i in l..e2.ext_off {
                let c = byte(s2, i);
                if c != pad {
                    return pad - c;
                }
            }
        } else if e1.ext_off > e2.ext_off {
            for i in l..e1.ext_off {
                let c = byte(s1, i);
                if c != pad {
                    return c - pad;
                }
            }
        }
        0
    }

    /// Sort directory entries in path_table and assign directory number to
    /// each entries.
    fn isoent_make_path_table_2(
        &mut self,
        which: Which,
        depth: usize,
        dir_number: &mut i32,
    ) -> Result<(), Error> {
        let vdd = self.vdd(which);
        let pt = &vdd.pathtbl[depth];
        let cnt = pt.cnt as usize;
        let joliet = vdd.vdd_type == VddType::Joliet;
        if cnt == 0 {
            self.vdd_mut(which).pathtbl[depth].sorted = Vec::new();
            return Ok(());
        }
        // Upstream copies the chain into an array of `cnt` entries; a
        // chain of another length would overrun it or leave it partly
        // unset.
        let mut enttbl = Vec::new();
        enttbl
            .try_reserve_exact(cnt)
            .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate memory"))?;
        let mut np = pt.first;
        while let Some(n) = np {
            if enttbl.len() == cnt {
                return Err(misc("Path table chain is longer than its count"));
            }
            enttbl.push(n);
            np = self.ents[n].ptnext;
        }
        if enttbl.len() != cnt {
            return Err(misc("Path table chain is shorter than its count"));
        }

        qsort::qsort(&mut enttbl, &mut |p1, p2| {
            self.compare_path_table(p1, p2, joliet)
        });
        for &n in &enttbl {
            self.ents[n].dir_number = *dir_number;
            *dir_number = dir_number.wrapping_add(1);
        }
        self.vdd_mut(which).pathtbl[depth].sorted = enttbl;
        Ok(())
    }

    fn isoent_alloc_path_table(&mut self, which: Which, max_depth: i32) -> Result<(), Error> {
        let n = usize::try_from(max_depth).unwrap_or(0);
        let mut pathtbl = Vec::new();
        pathtbl
            .try_reserve_exact(n)
            .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate memory"))?;
        pathtbl.resize_with(n, PathTable::default);
        let vdd = self.vdd_mut(which);
        vdd.pathtbl = pathtbl;
        vdd.max_depth = max_depth;
        Ok(())
    }

    /// Make Path Tables
    pub(super) fn isoent_make_path_table(&mut self) -> Result<(), Error> {
        // Init Path Table.
        if self.dircnt_max >= MAX_DEPTH && (!self.opt.limit_depth || self.opt.iso_level == 4) {
            self.isoent_alloc_path_table(Which::Primary, self.dircnt_max.saturating_add(1))?;
        } else {
            // The number of levels in the hierarchy cannot exceed eight.
            self.isoent_alloc_path_table(Which::Primary, MAX_DEPTH)?;
        }
        if self.opt.joliet != 0 {
            self.isoent_alloc_path_table(Which::Joliet, self.dircnt_max.saturating_add(1))?;
        }

        // Step 0.
        // - Collect directories for primary and joliet.
        self.isoent_collect_dirs(Which::Primary, None, 0)?;
        if self.opt.joliet != 0 {
            self.isoent_collect_dirs(Which::Joliet, None, 0)?;
        }
        // Rockridge; move deeper depth directories to rr_moved.
        if self.opt.rr != 0 {
            self.isoent_rr_move()?;
        }

        // Update nlink.
        self.isofile_connect_hardlink_files();

        // Step 1.
        // - Renew a value of the depth of that directories.
        // - Resolve hardlinks.
        // - Convert pathnames to ISO9660 name or UCS2(joliet).
        // - Sort files by each directory.
        self.isoent_traverse_tree(Which::Primary)?;
        if self.opt.joliet != 0 {
            self.isoent_traverse_tree(Which::Joliet)?;
        }

        // Step 2.
        // - Sort directories.
        // - Assign all directory number.
        let mut dir_number = 1;
        for depth in 0..self.primary.pathtbl.len() {
            self.isoent_make_path_table_2(Which::Primary, depth, &mut dir_number)?;
        }
        if self.opt.joliet != 0 {
            dir_number = 1;
            for depth in 0..self.joliet.pathtbl.len() {
                self.isoent_make_path_table_2(Which::Joliet, depth, &mut dir_number)?;
            }
        }
        if self.opt.limit_dirs && dir_number > 0xffff {
            // Maximum number of directories is 65535(0xffff) doe to
            // size(16bit) of Parent Directory Number of the Path Table. See
            // also ISO9660 Standard 9.4.
            return Err(misc(format!(
                "Too many directories({dir_number}) over 65535"
            )));
        }

        // Get the size of the Path Table.
        self.calculate_path_table_size(Which::Primary);
        if self.opt.joliet != 0 {
            self.calculate_path_table_size(Which::Joliet);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pathname_cleanup_matches_upstream() {
        for (input, expect) in [
            (&b"./a/b/"[..], &b"a/b"[..]),
            (b"/../a//b/./c/..", b"a/b/c"),
            (b"a/./b", b"a/b"),
            (b"a/b/../c", b"a/c"),
            (b"a/../../b", b"b"),
            (b"../x", b"x"),
            (b"..", b""),
            (b".", b""),
            (b"./", b""),
            (b"a/..b", b"a/..b"),
            (b"dir/sub/.", b"dir/sub"),
            (b"a//../b", b"b"),
        ] {
            assert_eq!(
                cleanup_pathname(input),
                expect,
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn path_components_stop_at_name_max() {
        assert_eq!(get_path_component(b"abc/def"), 3);
        assert_eq!(get_path_component(b"abc"), 3);
        assert_eq!(get_path_component(b""), 0);
        assert_eq!(get_path_component(b"/x"), 0);
        assert_eq!(get_path_component(&[b'x'; 255]), 255);
        assert_eq!(get_path_component(&[b'x'; 256]), -1);
    }
}
