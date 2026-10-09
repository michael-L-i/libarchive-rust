//! The table of contents: the XML is read with the `xml` crate and its
//! elements, attributes and text drive the same state machine that upstream's
//! `xml_start`, `xml_end` and `xml_data` implement.

use super::{CKSUM_MD5, CKSUM_NONE, CKSUM_SHA1, CKSUM_SHA256, CKSUM_SHA512};
use super::{Enc, SumVal};
use crate::archive::*;
use crate::entry::{AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFMT, AE_IFREG};
use crate::entry::{AE_IFSOCK, Dev, Mode};
use crate::time::days_from_civil;
use crate::util::Error;
use std::collections::HashMap;
use std::io::{self, BufReader};
use xml::reader::{ParserConfig, XmlEvent};

pub(super) const HAS_DATA: u32 = 0x00001;
pub(super) const HAS_PATHNAME: u32 = 0x00002;
const HAS_SYMLINK: u32 = 0x00004;
const HAS_TIME: u32 = 0x00008;
const HAS_UID: u32 = 0x00010;
const HAS_GID: u32 = 0x00020;
const HAS_MODE: u32 = 0x00040;
pub(super) const HAS_TYPE: u32 = 0x00080;
pub(super) const HAS_DEV: u32 = 0x00100;
pub(super) const HAS_DEVMAJOR: u32 = 0x00200;
pub(super) const HAS_DEVMINOR: u32 = 0x00400;
const HAS_INO: u32 = 0x00800;
const HAS_FFLAGS: u32 = 0x01000;
const HAS_XATTR: u32 = 0x02000;
const HAS_ACL: u32 = 0x04000;
pub(super) const HAS_CTIME: u32 = 0x08000;
pub(super) const HAS_MTIME: u32 = 0x10000;
pub(super) const HAS_ATIME: u32 = 0x20000;

/// The deepest nesting of elements libxml2 parses without its huge option.
const MAX_DEPTH: usize = 256;
/// libxml2's limits on a text node or attribute value, and on a name, without
/// its huge option.
const MAX_TEXT: usize = 10_000_000;
const MAX_NAME: usize = 50_000;
/// The most files and extended attributes a TOC may have. Upstream has no
/// limit.
const MAX_ITEMS: usize = 1 << 20;
/// The longest pathname that is built. Upstream has no limit.
const MAX_PATHNAME: usize = 1 << 20;

pub(super) struct Xattr {
    pub name: Option<Vec<u8>>,
    id: u64,
    pub length: u64,
    pub offset: u64,
    pub size: u64,
    pub encoding: Enc,
    pub a_sum: SumVal,
    pub e_sum: SumVal,
}

pub(super) struct XarFile {
    parent: Option<usize>,
    hdnext: Option<usize>,
    pub subdirs: i32,

    pub has: u32,

    id: u64,
    pub length: u64,
    pub offset: u64,
    pub size: u64,
    pub encoding: Enc,
    pub a_sum: SumVal,
    pub e_sum: SumVal,
    pub pathname: Vec<u8>,
    pub symlink: Vec<u8>,
    pub ctime: i64,
    pub mtime: i64,
    pub atime: i64,
    pub uname: Vec<u8>,
    pub uid: i64,
    pub gname: Vec<u8>,
    pub gid: i64,
    pub mode: Mode,
    pub dev: Dev,
    pub devmajor: Dev,
    pub devminor: Dev,
    pub ino64: i64,
    pub fflags_text: Vec<u8>,
    link: u32,
    pub nlink: u32,
    pub hardlink: Vec<u8>,
    pub xattrs: Vec<Xattr>,
}

impl XarFile {
    fn new(id: u64, parent: Option<usize>) -> XarFile {
        XarFile {
            parent,
            hdnext: None,
            subdirs: 0,
            has: 0,
            id,
            length: 0,
            offset: 0,
            size: 0,
            encoding: Enc::None,
            a_sum: SumVal::default(),
            e_sum: SumVal::default(),
            pathname: Vec::new(),
            symlink: Vec::new(),
            ctime: 0,
            mtime: 0,
            atime: 0,
            uname: Vec::new(),
            uid: 0,
            gname: Vec::new(),
            gid: 0,
            mode: 0o777 | AE_IFREG,
            dev: 0,
            devmajor: 0,
            devminor: 0,
            ino64: 0,
            fflags_text: Vec::new(),
            link: 0,
            nlink: 1,
            hardlink: Vec::new(),
            xattrs: Vec::new(),
        }
    }
}

/// Hardlinked files that name a link id.
struct Hdlink {
    cnt: i32,
    files: Option<usize>,
}

/// Where the parser is: upstream's `enum xmlstatus`, except that the
/// states of the flag elements are one state holding the element.
#[derive(Clone, Copy, Default, PartialEq)]
enum Sts {
    #[default]
    Init,
    Xar,
    Toc,
    TocCreationTime,
    TocChecksum,
    TocChecksumOffset,
    TocChecksumSize,
    TocFile,
    FileData,
    FileDataLength,
    FileDataOffset,
    FileDataSize,
    FileDataEncoding,
    FileDataAChecksum,
    FileDataEChecksum,
    FileDataContent,
    FileEa,
    FileEaLength,
    FileEaOffset,
    FileEaSize,
    FileEaEncoding,
    FileEaAChecksum,
    FileEaEChecksum,
    FileEaName,
    FileEaFstype,
    FileCtime,
    FileMtime,
    FileAtime,
    FileGroup,
    FileGid,
    FileUser,
    FileUid,
    FileMode,
    FileDevice,
    FileDeviceMajor,
    FileDeviceMinor,
    FileDeviceno,
    FileInode,
    FileLink,
    FileType,
    FileName,
    FileAcl,
    FileAclDefault,
    FileAclAccess,
    FileAclAppleExtended,
    /// BSD file flags.
    FileFlags,
    FileFlag(&'static str),
    /// Linux file flags.
    FileExt2,
    FileExt2Flag(&'static str),
    Unknown,
}

use Sts::*;

/// The elements that can start in each state: the parent, the element and
/// the state inside it. The end of an element returns to its parent.
const EDGES: &[(Sts, &str, Sts)] = &[
    (Init, "xar", Xar),
    (Xar, "toc", Toc),
    (Toc, "creation-time", TocCreationTime),
    (Toc, "checksum", TocChecksum),
    (Toc, "file", TocFile),
    (TocChecksum, "offset", TocChecksumOffset),
    (TocChecksum, "size", TocChecksumSize),
    (TocFile, "file", TocFile),
    (TocFile, "data", FileData),
    (TocFile, "ea", FileEa),
    (TocFile, "ctime", FileCtime),
    (TocFile, "mtime", FileMtime),
    (TocFile, "atime", FileAtime),
    (TocFile, "group", FileGroup),
    (TocFile, "gid", FileGid),
    (TocFile, "user", FileUser),
    (TocFile, "uid", FileUid),
    (TocFile, "mode", FileMode),
    (TocFile, "device", FileDevice),
    (TocFile, "deviceno", FileDeviceno),
    (TocFile, "inode", FileInode),
    (TocFile, "link", FileLink),
    (TocFile, "type", FileType),
    (TocFile, "name", FileName),
    (TocFile, "acl", FileAcl),
    (TocFile, "flags", FileFlags),
    (TocFile, "ext2", FileExt2),
    (FileData, "length", FileDataLength),
    (FileData, "offset", FileDataOffset),
    (FileData, "size", FileDataSize),
    (FileData, "encoding", FileDataEncoding),
    (FileData, "archived-checksum", FileDataAChecksum),
    (FileData, "extracted-checksum", FileDataEChecksum),
    (FileData, "content", FileDataContent),
    (FileDevice, "major", FileDeviceMajor),
    (FileDevice, "minor", FileDeviceMinor),
    (FileEa, "length", FileEaLength),
    (FileEa, "offset", FileEaOffset),
    (FileEa, "size", FileEaSize),
    (FileEa, "encoding", FileEaEncoding),
    (FileEa, "archived-checksum", FileEaAChecksum),
    (FileEa, "extracted-checksum", FileEaEChecksum),
    (FileEa, "name", FileEaName),
    (FileEa, "fstype", FileEaFstype),
    (FileAcl, "appleextended", FileAclAppleExtended),
    (FileAcl, "default", FileAclDefault),
    (FileAcl, "access", FileAclAccess),
];

/// The BSD file flags: element and the name of the flag.
const FLAGS: &[(&str, &str)] = &[
    ("UserNoDump", "nodump"),
    ("UserImmutable", "uimmutable"),
    ("UserAppend", "uappend"),
    ("UserOpaque", "opaque"),
    ("UserNoUnlink", "nouunlink"),
    ("SystemArchived", "archived"),
    ("SystemImmutable", "simmutable"),
    ("SystemAppend", "sappend"),
    ("SystemNoUnlink", "nosunlink"),
    ("SystemSnapshot", "snapshot"),
];

/// The Linux file flags.
const EXT2: &[(&str, &str)] = &[
    ("SecureDeletion", "securedeletion"),
    ("Undelete", "nouunlink"),
    ("Compress", "compress"),
    ("Synchronous", "sync"),
    ("Immutable", "simmutable"),
    ("AppendOnly", "sappend"),
    ("NoDump", "nodump"),
    ("NoAtime", "noatime"),
    ("CompDirty", "compdirty"),
    ("CompBlock", "comprblk"),
    ("NoCompBlock", "nocomprblk"),
    ("CompError", "comperr"),
    ("BTree", "btree"),
    ("HashIndexed", "hashidx"),
    ("iMagic", "imagic"),
    ("Journaled", "journal"),
    ("NoTail", "notail"),
    ("DirSync", "dirsync"),
    ("TopDir", "topdir"),
    ("Reserved", "reserved"),
];

fn key(files: &[XarFile], i: usize) -> u64 {
    files.get(i).map_or(0, |f| f.id)
}

/// A failure that upstream reports without a message.
fn failed() -> Error {
    Error::silent(ARCHIVE_FATAL)
}

#[derive(Default)]
pub(super) struct Toc {
    sts: Sts,
    sts_unknown: Sts,
    unknown_tags: Vec<String>,
    base64text: bool,

    pub chksum_offset: u64,
    pub chksum_size: u64,

    files: Vec<XarFile>,
    /// A heap of files by id.
    queue: Vec<usize>,
    /// The file being read.
    file: Option<usize>,
    /// The extended attribute being read, of `file`.
    xattr: Option<usize>,
    /// The number of files and extended attributes.
    items: usize,
    /// The originals of hardlinks, as a list linked by `hdnext`.
    hdlink_orgs: Option<usize>,
    hdlinks: HashMap<u32, Hdlink>,
}

impl Toc {
    /// `xml2_read_toc`: reads the XML from `source` and fills in the files.
    pub fn parse(&mut self, source: impl io::Read) -> Result<(), Error> {
        let mut reader = ParserConfig::new()
            .ignore_comments(false)
            .allow_multiple_root_elements(false)
            .max_data_length(MAX_TEXT)
            .max_attribute_length(MAX_TEXT)
            .max_name_length(MAX_NAME)
            .create_reader(BufReader::new(source));
        let mut depth = 0usize;
        loop {
            match reader.next() {
                Ok(XmlEvent::StartElement {
                    name, attributes, ..
                }) => {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Err(xml_error(
                            "Excessive depth in document: 256 use XML_PARSE_HUGE option\n",
                        ));
                    }
                    let attrs: Vec<(&str, &str)> = attributes
                        .iter()
                        .map(|a| (a.name.local_name.as_str(), a.value.as_str()))
                        .collect();
                    self.start(&name.local_name, &attrs)?;
                }
                Ok(XmlEvent::EndElement { name }) => {
                    depth = depth.saturating_sub(1);
                    self.end(&name.local_name);
                }
                // Only text that is not blank is a text node to libxml2's
                // reader. CDATA sections are another kind of node.
                Ok(XmlEvent::Characters(text)) => self.data(text.as_bytes())?,
                Ok(XmlEvent::EndDocument) => return Ok(()),
                Ok(_) => {}
                Err(e) => return Err(xml_error(&e.to_string())),
            }
        }
    }

    fn cur(&mut self) -> Option<&mut XarFile> {
        self.files.get_mut(self.file?)
    }

    /// `heap_add_entry`.
    fn heap_add(&mut self, idx: usize) {
        let Toc { files, queue, .. } = self;
        let id = key(files, idx);
        // Start with hole at end, walk it up tree to find insertion point.
        let mut hole = queue.len();
        queue.push(idx);
        while hole > 0 {
            let parent = (hole - 1) / 2;
            if id >= queue.get(parent).map_or(0, |&f| key(files, f)) {
                break;
            }
            // Move parent into hole <==> move hole up tree.
            queue.swap(hole, parent);
            hole = parent;
        }
    }

    /// `heap_get_entry`: the file with the lowest id.
    fn heap_get(&mut self) -> Option<usize> {
        let Toc { files, queue, .. } = self;
        // The first file in the list is the earliest; we'll return this.
        let r = *queue.first()?;
        // Move the last item in the heap to the root of the tree.
        let last = queue.pop()?;
        if let Some(first) = queue.first_mut() {
            *first = last;
        }
        // Rebalance the heap.
        let key = |q: &[usize], i: usize| q.get(i).map_or(0, |&f| key(files, f));
        let mut a = 0; // Starting element and its heap key
        let a_id = key(queue, a);
        loop {
            let mut b = a + a + 1; // First child
            if b >= queue.len() {
                return Some(r);
            }
            let mut b_id = key(queue, b);
            let c = b + 1; // Use second child if it is smaller.
            if c < queue.len() {
                let c_id = key(queue, c);
                if c_id < b_id {
                    b = c;
                    b_id = c_id;
                }
            }
            if a_id <= b_id {
                return Some(r);
            }
            queue.swap(a, b);
            a = b;
        }
    }

    /// The next file by id.
    pub fn next_file(&mut self) -> Option<XarFile> {
        let idx = self.heap_get()?;
        Some(std::mem::replace(
            self.files.get_mut(idx)?,
            XarFile::new(0, None),
        ))
    }

    /// Connect hardlinked files.
    pub fn connect_hardlinks(&mut self) {
        let mut originals = Vec::new();
        let mut next = self.hdlink_orgs;
        while let Some(i) = next.filter(|_| originals.len() < self.files.len()) {
            originals.push(i);
            next = self.files.get(i).and_then(|f| f.hdnext);
        }
        for i in originals {
            let Some(file) = self.files.get(i) else {
                continue;
            };
            let Some(hdlink) = u32::try_from(file.id)
                .ok()
                .and_then(|id| self.hdlinks.remove(&id))
            else {
                continue;
            };
            let pathname = file.pathname.clone();
            let nlink = hdlink.cnt + 1;
            if let Some(f) = self.files.get_mut(i) {
                f.nlink = nlink as u32;
            }
            let mut next = hdlink.files;
            let mut left = self.files.len();
            while let Some(f2) = next
                .and_then(|j| self.files.get_mut(j))
                .filter(|_| left > 0)
            {
                f2.nlink = nlink as u32;
                f2.hardlink.clone_from(&pathname);
                next = f2.hdnext;
                left -= 1;
            }
        }
    }

    fn unknown_start(&mut self, name: &str) {
        if self.unknown_tags.is_empty() {
            self.sts_unknown = self.sts;
            self.sts = Unknown;
        }
        self.unknown_tags.push(name.to_owned());
    }

    fn unknown_end(&mut self, name: &str) {
        if self.unknown_tags.last().is_some_and(|t| t == name) {
            self.unknown_tags.pop();
            if self.unknown_tags.is_empty() {
                self.sts = self.sts_unknown;
            }
        }
    }

    fn count_item(&mut self) -> Result<(), Error> {
        self.items += 1;
        if self.items > MAX_ITEMS {
            return Err(Error::fatal(
                libc::ENOMEM,
                "Rejecting malformed xar archive: too many files",
            ));
        }
        Ok(())
    }

    /// `file_new`.
    fn file_new(&mut self, attrs: &[(&str, &str)]) -> Result<(), Error> {
        self.xattr = None;
        let mut id = 0;
        for &(name, value) in attrs {
            if name == "id" {
                id = atou64(value.as_bytes(), 10).ok_or_else(failed)?;
            }
        }
        self.count_item()?;
        self.files.push(XarFile::new(id, self.file));
        self.file = self.files.len().checked_sub(1);
        if let Some(idx) = self.file {
            self.heap_add(idx);
        }
        Ok(())
    }

    /// `xattr_new`.
    fn xattr_new(&mut self, attrs: &[(&str, &str)]) -> Result<(), Error> {
        let mut id = 0;
        for &(name, value) in attrs {
            if name == "id" {
                id = atou64(value.as_bytes(), 10).ok_or_else(failed)?;
            }
        }
        self.count_item()?;
        let Some(file) = self.cur() else {
            return Ok(());
        };
        // Chain to xattr list.
        let pos = file
            .xattrs
            .iter()
            .position(|x| id < x.id)
            .unwrap_or(file.xattrs.len());
        file.xattrs.insert(
            pos,
            Xattr {
                name: None,
                id,
                length: 0,
                offset: 0,
                size: 0,
                encoding: Enc::None,
                a_sum: SumVal::default(),
                e_sum: SumVal::default(),
            },
        );
        self.xattr = Some(pos);
        Ok(())
    }

    /// The `link` attributes of a `type` element.
    fn type_links(&mut self, attrs: &[(&str, &str)]) -> Result<(), Error> {
        for &(name, value) in attrs {
            if name != "link" {
                continue;
            }
            let Some(idx) = self.file else { continue };
            let Some(file) = self.files.get(idx) else {
                continue;
            };
            if file.hdnext.is_some() || file.link != 0 || self.hdlink_orgs == self.file {
                return Err(Error::fatal(
                    ARCHIVE_ERRNO_MISC,
                    "File with multiple link attributes",
                ));
            }
            if value == "original" {
                let orgs = self.hdlink_orgs.replace(idx);
                if let Some(file) = self.files.get_mut(idx) {
                    file.hdnext = orgs;
                }
            } else {
                let val = atou64(value.as_bytes(), 10).ok_or_else(failed)?;
                let link = u32::try_from(val).map_err(|_| failed())?;
                if let Some(file) = self.files.get_mut(idx) {
                    file.link = link;
                }
                if link > 0 {
                    self.add_link(idx, link);
                }
            }
        }
        Ok(())
    }

    /// `add_link`.
    fn add_link(&mut self, idx: usize, link: u32) {
        let hdnext = match self.hdlinks.get_mut(&link) {
            Some(hdlink) => {
                hdlink.cnt += 1;
                hdlink.files.replace(idx)
            }
            None => {
                self.hdlinks.insert(
                    link,
                    Hdlink {
                        cnt: 1,
                        files: Some(idx),
                    },
                );
                None
            }
        };
        if let Some(file) = self.files.get_mut(idx) {
            file.hdnext = hdnext;
        }
    }

    /// Adds a flag to the text of the flags of the file.
    fn add_flag(&mut self, flag: &str, bsd: bool) {
        if let Some(file) = self.cur() {
            if bsd {
                file.has |= HAS_FFLAGS;
            }
            if !file.fflags_text.is_empty() {
                file.fflags_text.push(b',');
            }
            file.fflags_text.extend_from_slice(flag.as_bytes());
        }
    }

    /// `xml_start`.
    fn start(&mut self, name: &str, attrs: &[(&str, &str)]) -> Result<(), Error> {
        self.base64text = false;
        let flag = |table: &'static [(&'static str, &'static str)]| {
            table.iter().find(|(element, _)| *element == name)
        };
        let next = match self.sts {
            FileFlags => flag(FLAGS).map(|&(element, text)| {
                self.add_flag(text, true);
                FileFlag(element)
            }),
            FileExt2 => flag(EXT2).map(|&(element, text)| {
                self.add_flag(text, false);
                FileExt2Flag(element)
            }),
            sts => EDGES
                .iter()
                .find(|&&(parent, element, _)| parent == sts && element == name)
                .map(|&(_, _, child)| child),
        };
        let Some(next) = next else {
            self.unknown_start(name);
            return Ok(());
        };
        match next {
            TocFile => self.file_new(attrs)?,
            FileEa => self.xattr_new(attrs)?,
            FileType => self.type_links(attrs)?,
            FileName => {
                self.base64text = attrs
                    .iter()
                    .any(|&(name, value)| name == "enctype" && value == "base64");
            }
            FileDataEncoding => {
                if let Some(file) = self.cur() {
                    file.encoding = getencoding(attrs);
                }
            }
            FileDataAChecksum => {
                if let Some(file) = self.cur() {
                    file.a_sum.alg = getsumalgorithm(attrs);
                }
            }
            FileDataEChecksum => {
                if let Some(file) = self.cur() {
                    file.e_sum.alg = getsumalgorithm(attrs);
                }
            }
            FileEaEncoding => {
                if let Some(xattr) = self.xattr_mut() {
                    xattr.encoding = getencoding(attrs);
                }
            }
            _ => {}
        }
        self.sts = next;
        Ok(())
    }

    fn xattr_mut(&mut self) -> Option<&mut Xattr> {
        let i = self.xattr?;
        self.cur()?.xattrs.get_mut(i)
    }

    /// `xml_end`.
    fn end(&mut self, name: &str) {
        match self.sts {
            Init => {}
            Unknown => self.unknown_end(name),
            TocFile => {
                if name == "file" {
                    let Some(file) = self.cur() else { return };
                    let (parent, is_dir) = (file.parent, file.mode & AE_IFMT == AE_IFDIR);
                    if is_dir && let Some(p) = parent.and_then(|p| self.files.get_mut(p)) {
                        p.subdirs += 1;
                    }
                    self.file = parent;
                    if self.file.is_none() {
                        self.sts = Toc;
                    }
                }
            }
            FileFlag(element) => {
                if name == element {
                    self.sts = FileFlags;
                }
            }
            FileExt2Flag(element) => {
                if name == element {
                    self.sts = FileExt2;
                }
            }
            sts => {
                let up = EDGES
                    .iter()
                    .find(|&&(_, element, child)| child == sts && element == name);
                if let Some(&(parent, _, _)) = up {
                    self.sts = parent;
                    if sts == FileEa {
                        self.xattr = None;
                    }
                }
            }
        }
    }

    /// `xml_data`: the text of an element.
    #[allow(clippy::unnecessary_cast)] // dev_t and mode_t vary by platform
    fn data(&mut self, s: &[u8]) -> Result<(), Error> {
        match self.sts {
            TocChecksumOffset => self.chksum_offset = atou64(s, 10).ok_or_else(failed)?,
            TocChecksumSize => self.chksum_size = atou64(s, 10).ok_or_else(failed)?,
            _ => {}
        }
        let sts = self.sts;
        let base64 = self.base64text;
        let Some(idx) = self.file else {
            return Ok(());
        };
        let parent_path = match sts {
            FileName => self
                .files
                .get(idx)
                .and_then(|f| f.parent)
                .and_then(|p| self.files.get(p))
                .map(|p| p.pathname.clone()),
            _ => None,
        };
        // The extended attribute of the file, for the states inside one.
        let xattr = self.xattr;
        let Some(file) = self.files.get_mut(idx) else {
            return Ok(());
        };
        let num = |base| atou64(s, base).ok_or_else(failed);
        match sts {
            FileName => {
                if file.has & HAS_PATHNAME != 0 {
                    return Ok(());
                }
                if let Some(parent) = parent_path {
                    file.pathname.extend_from_slice(&parent);
                    file.pathname.push(b'/');
                }
                file.has |= HAS_PATHNAME;
                if base64 {
                    strappend_base64(&mut file.pathname, s);
                } else {
                    strncat(&mut file.pathname, s);
                }
                if file.pathname.len() > MAX_PATHNAME {
                    return Err(Error::fatal(
                        libc::ENOMEM,
                        "Rejecting malformed xar archive: pathname exceeds 1 megabyte",
                    ));
                }
            }
            FileLink => {
                file.has |= HAS_SYMLINK;
                strncpy(&mut file.symlink, s);
            }
            FileType => {
                let types: [(&[u8], Mode); 8] = [
                    (b"file", AE_IFREG),
                    (b"hardlink", AE_IFREG),
                    (b"directory", AE_IFDIR),
                    (b"symlink", AE_IFLNK),
                    (b"character special", AE_IFCHR),
                    (b"block special", AE_IFBLK),
                    (b"socket", AE_IFSOCK),
                    (b"fifo", AE_IFIFO),
                ];
                if let Some(&(_, ty)) = types.iter().find(|(text, _)| *text == s) {
                    file.mode = (file.mode & !AE_IFMT) | ty;
                }
                file.has |= HAS_TYPE;
            }
            FileInode => {
                let val = num(10)?;
                file.has |= HAS_INO;
                file.ino64 = i64::try_from(val).map_err(|_| failed())?;
            }
            FileDeviceMajor | FileDeviceMinor | FileDeviceno => {
                let val = num(10)?;
                let dev = val as Dev;
                if dev as u64 != val {
                    return Err(failed());
                }
                match sts {
                    FileDeviceMajor => {
                        file.has |= HAS_DEVMAJOR;
                        file.devmajor = dev;
                    }
                    FileDeviceMinor => {
                        file.has |= HAS_DEVMINOR;
                        file.devminor = dev;
                    }
                    _ => {
                        file.has |= HAS_DEV;
                        file.dev = dev;
                    }
                }
            }
            FileMode => {
                let val = num(8)?;
                let mode = val as Mode;
                if u64::from(mode) != val {
                    return Err(failed());
                }
                file.has |= HAS_MODE;
                file.mode = (file.mode & AE_IFMT) | (mode & !AE_IFMT);
            }
            FileGroup => {
                file.has |= HAS_GID;
                strncpy(&mut file.gname, s);
            }
            FileGid => {
                let val = num(10)?;
                file.has |= HAS_GID;
                file.gid = i64::try_from(val).map_err(|_| failed())?;
            }
            FileUser => {
                file.has |= HAS_UID;
                strncpy(&mut file.uname, s);
            }
            FileUid => {
                let val = num(10)?;
                file.has |= HAS_UID;
                file.uid = i64::try_from(val).map_err(|_| failed())?;
            }
            FileCtime => {
                file.has |= HAS_TIME | HAS_CTIME;
                file.ctime = parse_time(s);
            }
            FileMtime => {
                file.has |= HAS_TIME | HAS_MTIME;
                file.mtime = parse_time(s);
            }
            FileAtime => {
                file.has |= HAS_TIME | HAS_ATIME;
                file.atime = parse_time(s);
            }
            FileDataLength => {
                file.length = num(10)?;
                file.has |= HAS_DATA;
            }
            FileDataOffset => {
                file.offset = num(10)?;
                file.has |= HAS_DATA;
            }
            FileDataSize => {
                file.size = num(10)?;
                file.has |= HAS_DATA;
            }
            FileDataAChecksum => atohex(&mut file.a_sum, s),
            FileDataEChecksum => atohex(&mut file.e_sum, s),
            FileEaLength | FileEaOffset | FileEaSize | FileEaAChecksum | FileEaEChecksum
            | FileEaName | FileEaFstype => {
                let val = match sts {
                    FileEaLength | FileEaOffset | FileEaSize => num(10)?,
                    _ => 0,
                };
                file.has |= HAS_XATTR;
                let Some(x) = xattr.and_then(|i| file.xattrs.get_mut(i)) else {
                    return Ok(());
                };
                match sts {
                    FileEaLength => x.length = val,
                    FileEaOffset => x.offset = val,
                    FileEaSize => x.size = val,
                    FileEaAChecksum => atohex(&mut x.a_sum, s),
                    FileEaEChecksum => atohex(&mut x.e_sum, s),
                    FileEaName => {
                        let mut name = Vec::new();
                        strncat(&mut name, s);
                        x.name = Some(name);
                    }
                    _ => {}
                }
            }
            FileAclDefault | FileAclAccess | FileAclAppleExtended => {
                file.has |= HAS_ACL;
                // TODO
            }
            _ => {}
        }
        Ok(())
    }
}

fn xml_error(msg: &str) -> Error {
    Error::fatal(ARCHIVE_ERRNO_MISC, format!("XML Parsing error: {msg}"))
}

fn getencoding(attrs: &[(&str, &str)]) -> Enc {
    let mut encoding = Enc::None;
    for &(name, value) in attrs {
        if name == "style" {
            match value {
                "application/octet-stream" => encoding = Enc::None,
                "application/x-gzip" => encoding = Enc::Gzip,
                "application/x-bzip2" => encoding = Enc::Bzip2,
                "application/x-lzma" => encoding = Enc::Lzma,
                "application/x-xz" => encoding = Enc::Xz,
                _ => {}
            }
        }
    }
    encoding
}

fn getsumalgorithm(attrs: &[(&str, &str)]) -> u32 {
    let mut alg = CKSUM_NONE;
    for &(name, value) in attrs {
        if name == "style" {
            for (style, sum) in [
                ("sha1", CKSUM_SHA1),
                ("sha256", CKSUM_SHA256),
                ("sha512", CKSUM_SHA512),
                ("md5", CKSUM_MD5),
            ] {
                if value.eq_ignore_ascii_case(style) {
                    alg = sum;
                }
            }
        }
    }
    alg
}

/// `archive_strncat`: appends up to the first NUL.
fn strncat(dest: &mut Vec<u8>, s: &[u8]) {
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    dest.extend_from_slice(s.get(..end).unwrap_or_default());
}

/// `archive_strncpy`.
fn strncpy(dest: &mut Vec<u8>, s: &[u8]) {
    dest.clear();
    strncat(dest, s);
}

/// Note that this implementation does not (and should not!) obey
/// locale settings; you cannot simply substitute strtol here, since
/// it does obey locale.
///
/// Reads digits up to the first byte that is not one. `None` if the number
/// overflows.
fn atou64(p: &[u8], base: u64) -> Option<u64> {
    let mut l: u64 = 0;
    for &c in p {
        let digit = u64::from(c.wrapping_sub(b'0'));
        if digit >= base {
            break;
        }
        l = l.checked_mul(base)?.checked_add(digit)?;
    }
    Some(l)
}

/// Reads the hexadecimal digits in `p` into the value of the checksum, as
/// many as it holds. The length is `usize::MAX` if a digit is not one.
fn atohex(sum: &mut SumVal, p: &[u8]) {
    let hex = |c: u8| char::from(c).to_digit(16).map(|d| d as u8);
    let mut n = 0;
    for pair in p.chunks_exact(2) {
        let Some(slot) = sum.val.get_mut(n) else {
            break;
        };
        let &[hi, lo] = pair else { break };
        let (Some(hi), Some(lo)) = (hex(hi), hex(lo)) else {
            sum.len = usize::MAX;
            return;
        };
        *slot = hi << 4 | lo;
        n += 1;
    }
    sum.len = n;
}

fn base64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Appends the decoded base64 text, up to the first byte that is not base64.
/// A last character on its own is dropped. The decoded bytes are appended in
/// pieces, each up to its first NUL.
fn strappend_base64(dest: &mut Vec<u8>, s: &[u8]) {
    let mut buff = Vec::new();
    let mut chars = s.iter().map(|&c| base64_value(c));
    let mut left = s.len();
    while left > 1 {
        let (Some(Some(c0)), Some(Some(c1))) = (chars.next(), chars.next()) else {
            break;
        };
        let mut n = c0 << 18 | c1 << 12;
        buff.push((n >> 16) as u8);
        left -= 2;
        if left > 0 {
            let Some(Some(c)) = chars.next() else { break };
            n |= c << 6;
            buff.push((n >> 8) as u8);
            left -= 1;
        }
        if left > 0 {
            let Some(Some(c)) = chars.next() else { break };
            n |= c;
            buff.push(n as u8);
            left -= 1;
        }
        if buff.len() + 3 >= 256 {
            strncat(dest, &buff);
            buff.clear();
        }
    }
    if !buff.is_empty() {
        strncat(dest, &buff);
    }
}

/// Parses `YYYY-MM-DDThh:mm:ss` and one more byte, as UTC. 0 for anything
/// else.
fn parse_time(p: &[u8]) -> i64 {
    let field = |at: usize, min: u64, max: u64| {
        let v = atou64(p.get(at..at + 2)?, 10)?;
        (min..=max).contains(&v).then_some(v as i64)
    };
    let sep = |at: usize, c: u8| (p.get(at) == Some(&c)).then_some(());
    let parse = || {
        if p.len() != 20 {
            return None;
        }
        let year = atou64(p.get(..4)?, 10)?;
        if year < 1900 {
            return None;
        }
        sep(4, b'-')?;
        let mon = field(5, 1, 12)?;
        sep(7, b'-')?;
        let mday = field(8, 1, 31)?;
        sep(10, b'T')?;
        let hour = field(11, 0, 23)?;
        sep(13, b':')?;
        let min = field(14, 0, 59)?;
        sep(16, b':')?;
        let sec = field(17, 0, 60)?;
        // timegm() normalizes the fields, so day 31 of a 30-day month is the
        // next month's first day, and second 60 is the next minute.
        let days = days_from_civil(year as i64, mon, 1) + mday - 1;
        Some(days * 86400 + hour * 3600 + min * 60 + sec)
    };
    parse().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::super::MAX_SUM_SIZE;
    use super::*;

    #[test]
    fn numbers_stop_at_the_first_other_byte() {
        assert_eq!(atou64(b"1234567890", 10), Some(1234567890));
        assert_eq!(atou64(b"12ab", 10), Some(12));
        assert_eq!(atou64(b"", 10), Some(0));
        assert_eq!(atou64(b"0755", 8), Some(0o755));
        assert_eq!(atou64(b"789", 8), Some(7));
        assert_eq!(atou64(b"18446744073709551615", 10), Some(u64::MAX));
        assert_eq!(atou64(b"18446744073709551616", 10), None);
        assert_eq!(atou64(b"\xff1", 10), Some(0));
    }

    #[test]
    fn times() {
        assert_eq!(parse_time(b"1970-01-02T00:00:01Z"), 86401);
        assert_eq!(parse_time(b"1970-01-02T00:00:123"), 86412);
        assert_eq!(parse_time(b"1970-01-02T00:00:01"), 0);
        assert_eq!(parse_time(b"1899-12-31T23:59:59Z"), 0);
        // Normalized like timegm().
        assert_eq!(
            parse_time(b"2001-02-31T00:00:60Z"),
            parse_time(b"2001-03-03T00:01:00Z")
        );
        assert_ne!(parse_time(b"2001-02-31T00:00:60Z"), 0);
    }

    #[test]
    fn base64_names() {
        let decode = |s: &[u8]| {
            let mut v = Vec::new();
            strappend_base64(&mut v, s);
            v
        };
        assert_eq!(decode(b"YWJj"), b"abc");
        assert_eq!(decode(b"YWJjA"), b"abc");
        assert_eq!(decode(b"YWJjZA=="), b"abcd");
        assert_eq!(decode(b"YW=j"), b"a");
        assert_eq!(decode(b"YWJ\0j"), b"ab");
    }

    #[test]
    fn checksum_digits() {
        let mut sum = SumVal::default();
        atohex(&mut sum, b"00ff1A9");
        assert_eq!((sum.len, &sum.val[..3]), (3, [0, 255, 26].as_slice()));
        atohex(&mut sum, b"0g");
        assert_eq!(sum.len, usize::MAX);
        atohex(&mut sum, &b"ab".repeat(70));
        assert_eq!(sum.len, MAX_SUM_SIZE);
    }

    fn toc(xml: &str) -> Result<Toc, Error> {
        let mut toc = Toc::default();
        toc.parse(xml.as_bytes())?;
        toc.connect_hardlinks();
        Ok(toc)
    }

    #[test]
    fn files_come_out_by_id_with_their_directories() {
        let mut toc = toc("<xar><toc>\
            <file id='3'><name>c</name><type>file</type></file>\
            <file id='1'><name>a</name><type>directory</type>\
              <file id='2'><name>b</name><type>directory</type></file>\
              <file id='4'><name>d</name>\
                <type link='original'>file</type></file>\
            </file>\
            <file id='5'><name>e</name><type link='4'>hardlink</type></file>\
            </toc></xar>")
        .unwrap();
        let mut names = Vec::new();
        while let Some(f) = toc.next_file() {
            names.push((f.pathname, f.subdirs, f.nlink, f.hardlink));
        }
        assert_eq!(
            names,
            [
                (b"a".to_vec(), 1, 1, vec![]),
                (b"a/b".to_vec(), 0, 1, vec![]),
                (b"c".to_vec(), 0, 1, vec![]),
                (b"a/d".to_vec(), 0, 2, vec![]),
                (b"e".to_vec(), 0, 2, b"a/d".to_vec()),
            ]
        );
    }

    #[test]
    fn xml_errors_and_limits() {
        assert!(toc("<xar><toc></xar>").is_err());
        assert!(toc("").is_err());
        assert!(toc("<xar/><xar/>").is_err());
        let deep = "<a>".repeat(257);
        let e = toc(&deep).err().map(|e| e.msg);
        assert_eq!(
            e.as_deref(),
            Some(
                &b"XML Parsing error: Excessive depth in document: 256 use XML_PARSE_HUGE option\n"
                    [..]
            )
        );
        let e = toc("<xar><toc><file id='1'><type link='1'/><type link='2'/>");
        assert!(e.is_err());
    }
}
