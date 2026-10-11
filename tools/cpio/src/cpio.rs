/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2003-2007 Tim Kientzle
 * All rights reserved.
 */

// Ported from cpio/cpio.c and cpio/cpio.h.

//! bsdcpio: copies files into (-o) and out of (-i, -t) archives, and from
//! one place on disk to another (-p).

#![deny(unsafe_code)]

mod cmdline;

use cmdline::{State, owner_parse, parse_int};
use libarchive_fe::lafe_err::{lafe_errc, lafe_getprogname, lafe_setprogname, lafe_warnc};
use libarchive_fe::lafe_explicit_bzero::explicit_bzero;
use libarchive_fe::line_reader::LineReader;
use libarchive_fe::passphrase::lafe_readpassphrase;
use libarchive_fe::sys;
use libarchive_rust::{
    AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFREG, ARCHIVE_EXTRACT_ACL, ARCHIVE_EXTRACT_FFLAGS,
    ARCHIVE_EXTRACT_NO_AUTODIR, ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER, ARCHIVE_EXTRACT_OWNER,
    ARCHIVE_EXTRACT_PERM, ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS, ARCHIVE_EXTRACT_SECURE_NODOTDOT,
    ARCHIVE_EXTRACT_SECURE_SYMLINKS, ARCHIVE_EXTRACT_TIME, Archive, ArchiveEntry,
    ArchiveEntryLinkresolver, ArchiveMatch, ArchiveRead, ArchiveReadDisk, ArchiveWrite,
    ArchiveWriteDisk, Status, version_details,
};
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString, c_int};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

/// Fixed size of uname/gname caches.
const NAME_CACHE_SIZE: usize = 101;

/// config.h's, which upstream's CMakeLists.txt makes from build/version.
const BSDCPIO_VERSION_STRING: &str = "3.9.0";

// Fake short equivalents for long options that otherwise lack them. An
// option is the byte of its short form or one of these.
const OPTION_B64ENCODE: u8 = 1;
const OPTION_GRZIP: u8 = 2;
const OPTION_INSECURE: u8 = 3;
const OPTION_LRZIP: u8 = 4;
const OPTION_LZ4: u8 = 5;
const OPTION_LZMA: u8 = 6;
const OPTION_LZOP: u8 = 7;
const OPTION_PASSPHRASE: u8 = 8;
const OPTION_NO_PRESERVE_OWNER: u8 = 9;
const OPTION_PRESERVE_OWNER: u8 = 10;
const OPTION_QUIET: u8 = 11;
const OPTION_UUENCODE: u8 = 12;
const OPTION_VERSION: u8 = 13;
const OPTION_ZSTD: u8 = 14;

/// A cache of the names of ids: slot `id % NAME_CACHE_SIZE` holds the
/// last id looked up there, and its name.
struct NameCache(Vec<Option<(u32, Vec<u8>)>>);

impl NameCache {
    fn new() -> Self {
        NameCache(vec![None; NAME_CACHE_SIZE])
    }
}

/// `cpio->archive`: what -o mode writes an archive with and -p mode
/// writes the files to.
enum Output {
    Archive(ArchiveWrite),
    Disk(ArchiveWriteDisk),
}

impl Output {
    fn archive(&self) -> &Archive {
        match self {
            Output::Archive(a) => a,
            Output::Disk(a) => a,
        }
    }

    fn header(&mut self, entry: &mut ArchiveEntry) -> Status {
        match self {
            Output::Archive(a) => a.header(entry),
            Output::Disk(a) => a.header(entry),
        }
    }

    fn data(&mut self, buf: &[u8]) -> Result<usize, Status> {
        match self {
            Output::Archive(a) => a.data(buf),
            Output::Disk(a) => a.data(buf),
        }
    }

    fn close(&mut self) -> Status {
        match self {
            Output::Archive(a) => a.close(),
            Output::Disk(a) => a.close(),
        }
    }
}

/// `struct cpio`: the internal state for the "cpio" program.
struct Cpio {
    // Option parsing
    argument: Option<Vec<u8>>,
    getopt_state: State,
    /// What is left of the word being parsed.
    getopt_word: Vec<u8>,
    /// The words of the command line not parsed yet, the program name
    /// first.
    argv: VecDeque<Vec<u8>>,

    // Options
    /// --uuencode
    add_filter: u8,
    filename: Option<Vec<u8>>,
    /// -i -o -p
    mode: u8,
    /// -j, -y, or -z
    compress: u8,
    /// -H format
    format: Option<Vec<u8>>,
    /// -b block_size
    bytes_per_block: c_int,
    /// -v
    verbose: u32,
    /// -V
    dot: u32,
    /// --quiet
    quiet: bool,
    /// Flags for extract operation
    extract_flags: c_int,
    /// -A, only relevant for -o
    option_append: bool,
    /// -a
    option_atime_restore: bool,
    /// -L
    option_follow_links: bool,
    /// -l
    option_link: bool,
    /// -t
    option_list: bool,
    /// --null
    option_null: bool,
    /// -n
    option_numeric_uid_gid: bool,
    /// -6
    option_pwb: bool,
    /// -r
    option_rename: bool,
    /// The target directory of -p mode, with a trailing '/'.
    destdir: Option<Vec<u8>>,
    uid_override: Option<i32>,
    uname_override: Option<Vec<u8>>,
    gid_override: Option<i32>,
    gname_override: Option<Vec<u8>>,
    passphrase: Option<Vec<u8>>,

    // Miscellaneous state information
    archive: Option<Output>,
    archive_read_disk: ArchiveReadDisk,
    /// Value returned by main()
    return_value: c_int,
    linkresolver: Option<ArchiveEntryLinkresolver>,

    uname_cache: NameCache,
    gname_cache: NameCache,
    /// The time `list_item_verbose` compares to, once it has looked.
    now: i64,

    // Work data.
    matching: ArchiveMatch,
}

/// `archive_error_string(a)` as printf's "%s" shows it.
fn error_string(a: &Archive) -> Vec<u8> {
    a.error_string().as_deref().unwrap_or(b"(null)").to_vec()
}

/// `fprintf(stderr, ...)`, which is unbuffered.
fn eprint(msg: impl AsRef<[u8]>) {
    let _ = io::stderr().write_all(msg.as_ref());
}

fn path(name: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(name))
}

/// "N blocks" to standard error, of the bytes `a` processed.
fn print_blocks(a: &Archive) {
    let blocks = (a.filter_bytes(0) + 511) / 512;
    let s = if blocks == 1 { "block" } else { "blocks" };
    eprint(format!("{blocks} {s}\n"));
}

fn usage() -> ! {
    let p = lafe_getprogname();
    let msg = [
        b"Brief Usage:\n  List:    ".as_slice(),
        &p,
        b" -it < archive\n  Extract: ",
        &p,
        b" -i < archive\n  Create:  ",
        &p,
        b" -o < filenames > archive\n  Help:    ",
        &p,
        b" --help\n",
    ];
    eprint(msg.concat());
    exit(1)
}

const LONG_HELP_MSG: &str = concat!(
    "First option must be a mode specifier:\n",
    "  -i Input  -o Output  -p Pass\n",
    "Common Options:\n",
    "  -v Verbose filenames     -V  one dot per file\n",
    "Create: %p -o [options]  < [list of files] > [archive]\n",
    "  -J,-y,-z,--lzma  Compress archive with xz/bzip2/gzip/lzma\n",
    "  --format {pwb|bin|odc|newc|ustar}  Select archive format\n",
    "List: %p -it < [archive]\n",
    "Extract: %p -i [options] < [archive]\n",
);

/// Note that the word 'bsdcpio' will always appear in the first line
/// of output.
///
/// In particular, /bin/sh scripts that need to test for the presence
/// of bsdcpio can use the following template:
///
/// ```sh
/// if (cpio --help 2>&1 | grep bsdcpio >/dev/null 2>&1 ) then \
///          echo bsdcpio; else echo not bsdcpio; fi
/// ```
fn long_help() -> ! {
    let prog = lafe_getprogname();

    let p = if prog != b"bsdcpio" { "(bsdcpio)" } else { "" };
    let mut out = [
        prog.as_slice(),
        p.as_bytes(),
        b": manipulate archive files\n",
    ]
    .concat();

    let mut rest = LONG_HELP_MSG.as_bytes();
    while let Some((&c, tail)) = rest.split_first() {
        rest = tail;
        if c == b'%' && rest.first() == Some(&b'p') {
            out.extend_from_slice(&prog);
            rest = &rest[1..];
        } else {
            out.push(c);
        }
    }
    let _ = io::stdout().write_all(&out);
    version()
}

fn version() -> ! {
    let details = version_details();
    let _ = writeln!(
        io::stdout(),
        "bsdcpio {BSDCPIO_VERSION_STRING} - {details} "
    );
    exit(0)
}

/// `passphrase_callback`: asks the terminal for a passphrase.
fn passphrase_callback() -> Option<Vec<u8>> {
    const PPBUFF_SIZE: usize = 1024;
    let mut buf = vec![0; PPBUFF_SIZE];
    // lafe_readpassphrase exits on any error but EINTR, which it returns
    // as None.
    let p = lafe_readpassphrase("Enter passphrase:", &mut buf).map(<[u8]>::to_vec);
    explicit_bzero(&mut buf);
    p
}

fn remove_leading_slash(p: &[u8]) -> &[u8] {
    let at = |i: usize| p.get(i).copied().unwrap_or(0);
    let is_sep = |c: u8| c == b'/' || c == b'\\';
    let mut i = 0;

    // Remove leading "//./" or "//?/" or "//?/UNC/"
    // (absolute path prefixes used by Windows API)
    if is_sep(at(0)) && is_sep(at(1)) && matches!(at(2), b'.' | b'?') && is_sep(at(3)) {
        if at(2) == b'?'
            && p.get(4..7)
                .is_some_and(|unc| unc.eq_ignore_ascii_case(b"UNC"))
            && is_sep(at(7))
        {
            i += 8;
        } else {
            i += 4;
        }
    }
    loop {
        let rp = i;
        // Remove leading drive letter from archives created
        // on Windows.
        if at(i).is_ascii_alphabetic() && at(i + 1) == b':' {
            i += 2;
        }
        // Remove leading "/../", "//", etc.
        while is_sep(at(i)) {
            if at(i + 1) == b'.' && at(i + 2) == b'.' && is_sep(at(i + 3)) {
                i += 3; // Remove "/..", leave "/" for next pass.
            } else {
                i += 1; // Remove "/".
            }
        }
        if rp == i {
            return &p[i..];
        }
    }
}

/// Prompt for a new name for this entry. The entry is left as it is if
/// there is no terminal or the answer is '.', and has no name if the
/// entry should not be copied. This implements the semantics defined in
/// POSIX.1-1996, which specifies that an input of '.' means the name
/// should be unchanged. GNU cpio treats '.' as a literal new name.
fn cpio_rename(entry: &mut ArchiveEntry) {
    let Ok(mut t) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
        return;
    };
    let name = entry.pathname().unwrap_or(b"(null)");
    let _ = t.write_all(&[name, b" (Enter/./(new name))? "].concat());

    let mut buff = Vec::new();
    // End-of-file is a blank line.
    let _ = BufReader::new(t).read_until(b'\n', &mut buff);
    // The line is a C string.
    if let Some(nul) = buff.iter().position(|&c| c == 0) {
        buff.truncate(nul);
    }
    let blank = buff
        .iter()
        .take_while(|&&c| c == b' ' || c == b'\t')
        .count();
    let p = &buff[blank..];
    let ret = match p.first() {
        // Empty line.
        None | Some(b'\n') => None,
        // Single period preserves original name.
        Some(b'.') if p.get(1) == Some(&b'\n') => return,
        // Trim the final newline.
        Some(_) => Some(p.strip_suffix(b"\n").unwrap_or(p)),
    };
    entry.set_pathname(ret);
}

/// Lookup uname/gname from uid/gid, as a number if there is no match.
fn lookup_name(cache: &mut NameCache, lookup_fn: fn(u32) -> Option<Vec<u8>>, id: u32) -> &[u8] {
    let slot = &mut cache.0[id as usize % NAME_CACHE_SIZE];
    if slot.as_ref().is_some_and(|(cached, _)| *cached != id) {
        *slot = None;
    }
    // If lookup failed, format it as a number.
    let lookup = || lookup_fn(id).unwrap_or_else(|| id.to_string().into_bytes());
    &slot.get_or_insert_with(|| (id, lookup())).1
}

fn lookup_uname(cache: &mut NameCache, uid: u32) -> &[u8] {
    lookup_name(cache, lookup_uname_helper, uid)
}

fn lookup_uname_helper(id: u32) -> Option<Vec<u8>> {
    sys::getpwuid(id).unwrap_or_else(|errno| {
        lafe_warnc(errno, format!("getpwuid({id}) failed"));
        None
    })
}

fn lookup_gname(cache: &mut NameCache, gid: u32) -> &[u8] {
    lookup_name(cache, lookup_gname_helper, gid)
}

fn lookup_gname_helper(id: u32) -> Option<Vec<u8>> {
    sys::getgrgid(id).unwrap_or_else(|errno| {
        lafe_warnc(errno, format!("getgrgid({id}) failed"));
        None
    })
}

/// `lafe_errc(1, ...)`, after the output so far is written, as exiting
/// flushes standard output in C.
fn errc_flushing(out: &mut impl Write, errno: c_int, msg: impl AsRef<[u8]>) -> ! {
    let _ = out.flush();
    lafe_errc(1, errno, msg)
}

/// Appends `s` to `out` as printf's "%-{width}s" shows it.
fn ljust(out: &mut Vec<u8>, s: &[u8], width: usize) {
    out.extend_from_slice(s);
    out.resize(out.len() + width.saturating_sub(s.len()), b' ');
}

/// Appends `s` to `out` as printf's "%{width}s" shows it.
fn rjust(out: &mut Vec<u8>, s: &[u8], width: usize) {
    out.resize(out.len() + width.saturating_sub(s.len()), b' ');
    out.extend_from_slice(s);
}

impl Cpio {
    fn new(argv: VecDeque<Vec<u8>>) -> Cpio {
        let mut extract_flags = ARCHIVE_EXTRACT_NO_AUTODIR
            | ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER
            | ARCHIVE_EXTRACT_SECURE_SYMLINKS
            | ARCHIVE_EXTRACT_SECURE_NODOTDOT
            | ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS
            | ARCHIVE_EXTRACT_PERM
            | ARCHIVE_EXTRACT_FFLAGS
            | ARCHIVE_EXTRACT_ACL;
        if sys::geteuid() == 0 {
            extract_flags |= ARCHIVE_EXTRACT_OWNER;
        }
        Cpio {
            argument: None,
            getopt_state: State::Start,
            getopt_word: Vec::new(),
            argv,
            add_filter: 0,
            filename: None,
            mode: 0,
            compress: 0,
            format: None,
            bytes_per_block: 512,
            verbose: 0,
            dot: 0,
            quiet: false,
            extract_flags,
            option_append: false,
            option_atime_restore: false,
            option_follow_links: false,
            option_link: false,
            option_list: false,
            option_null: false,
            option_numeric_uid_gid: false,
            option_pwb: false,
            option_rename: false,
            destdir: None,
            uid_override: None,
            uname_override: None,
            gid_override: None,
            gname_override: None,
            passphrase: None,
            archive: None,
            archive_read_disk: ArchiveReadDisk::new(),
            return_value: 0,
            linkresolver: None,
            uname_cache: NameCache::new(),
            gname_cache: NameCache::new(),
            now: 0,
            matching: ArchiveMatch::new(),
        }
    }

    /// `cpio->archive`, which -o and -p mode open before writing.
    fn output(&mut self) -> &mut Output {
        self.archive
            .as_mut()
            .expect("opened by mode_out or mode_pass")
    }

    /// `cpio->archive` as the `struct archive` it is.
    fn output_archive(&self) -> &Archive {
        self.archive
            .as_ref()
            .expect("opened by mode_out or mode_pass")
            .archive()
    }

    fn mode_out(&mut self) {
        if self.option_append {
            lafe_errc(1, 0, "Append mode not yet supported");
        }

        self.set_up_read_disk();

        let mut a = ArchiveWrite::new();
        let r = match self.compress {
            OPTION_GRZIP => a.add_filter_grzip(),
            b'J' => a.add_filter_xz(),
            OPTION_LRZIP => a.add_filter_lrzip(),
            OPTION_LZ4 => a.add_filter_lz4(),
            OPTION_LZMA => a.add_filter_lzma(),
            OPTION_LZOP => a.add_filter_lzop(),
            OPTION_ZSTD => a.add_filter_zstd(),
            b'j' | b'y' => a.add_filter_bzip2(),
            b'z' => a.add_filter_gzip(),
            b'Z' => a.add_filter_compress(),
            _ => a.add_filter_none(),
        };
        if r < Status::Warn {
            lafe_errc(1, 0, "Requested compression not available");
        }
        let r = match self.add_filter {
            OPTION_B64ENCODE => a.add_filter_b64encode(),
            OPTION_UUENCODE => a.add_filter_uuencode(),
            _ => Status::Ok,
        };
        if r < Status::Warn {
            lafe_errc(1, 0, "Requested filter not available");
        }
        // The format is set by now: main defaults it.
        let r = a.set_format_by_name(self.format.as_deref().unwrap_or_default());
        if r != Status::Ok {
            lafe_errc(1, 0, error_string(&a));
        }
        a.set_bytes_per_block(self.bytes_per_block);
        let mut linkresolver = ArchiveEntryLinkresolver::new();
        linkresolver.set_strategy(a.format());
        self.linkresolver = Some(linkresolver);
        let r = match &self.passphrase {
            Some(passphrase) => a.set_passphrase(passphrase),
            None => a.set_passphrase_callback(passphrase_callback),
        };
        if r != Status::Ok {
            lafe_errc(1, 0, error_string(&a));
        }

        // The main loop: Copy each file into the output archive.
        let r = a.open_filename(self.filename.as_deref().map(path));
        if r != Status::Ok {
            lafe_errc(1, 0, error_string(&a));
        }
        self.archive = Some(Output::Archive(a));
        let mut lr = LineReader::new(Path::new("-"), self.option_null);
        while let Some(p) = lr.next() {
            self.file_to_archive(p);
        }

        // The hardlink detection may have queued up a couple of entries
        // that can now be flushed.
        loop {
            let mut entry = None;
            if let Some(linkresolver) = &mut self.linkresolver {
                linkresolver.linkify(&mut entry);
            }
            let Some(mut entry) = entry else { break };
            self.entry_to_archive(&mut entry);
        }

        let r = self.output().close();
        if self.dot > 0 {
            eprint("\n");
        }
        let a = self.output_archive();
        if r != Status::Ok {
            lafe_errc(1, 0, error_string(a));
        }

        if !self.quiet {
            print_blocks(a);
        }
    }

    /// Sets up the disk reader that -o and -p mode make entries with.
    fn set_up_read_disk(&mut self) {
        if self.option_follow_links {
            self.archive_read_disk.set_symlink_logical();
        } else {
            self.archive_read_disk.set_symlink_physical();
        }
        self.archive_read_disk.set_standard_lookup();
    }

    /// This is used by both out mode (to copy objects from disk into
    /// an archive) and pass mode (to copy objects from disk to
    /// an archive_write_disk "archive").
    fn file_to_archive(&mut self, srcpath: &[u8]) {
        // Create an archive_entry describing the source file.
        let mut entry = ArchiveEntry::new();
        entry.copy_sourcepath(Some(srcpath));
        let r = self.archive_read_disk.entry_from_file(&mut entry, None);
        if r < Status::Failed {
            lafe_errc(1, 0, error_string(&self.archive_read_disk));
        }
        if r < Status::Ok {
            lafe_warnc(0, error_string(&self.archive_read_disk));
        }
        if r <= Status::Failed {
            self.return_value = 1;
            return;
        }

        if let Some(uid) = self.uid_override {
            entry.set_uid(uid.into());
            entry.set_uname(None);
        }
        if self.uname_override.is_some() {
            entry.set_uname(self.uname_override.as_deref());
        }
        if let Some(gid) = self.gid_override {
            entry.set_gid(gid.into());
            entry.set_gname(None);
        }
        if self.gname_override.is_some() {
            entry.set_gname(self.gname_override.as_deref());
        }

        // Generate a destination path for this entry.
        // "destination path" is the name to which it will be copied in
        // pass mode or the name that will go into the archive in
        // output mode.
        if let Some(destdir) = &self.destdir {
            let destpath = [destdir, remove_leading_slash(srcpath)].concat();
            entry.set_pathname(Some(&destpath));
        } else {
            entry.set_pathname(Some(srcpath));
        }
        if self.option_rename {
            cpio_rename(&mut entry);
        }

        if entry.pathname().is_none() {
            return;
        }

        // If we're trying to preserve hardlinks, match them here.
        let is_dir = entry.filetype() == AE_IFDIR;
        let mut entry = Some(entry);
        let mut spare = None;
        if !is_dir && let Some(linkresolver) = &mut self.linkresolver {
            spare = linkresolver.linkify(&mut entry);
        }

        if let Some(mut entry) = entry {
            self.entry_to_archive(&mut entry);
            if let Some(mut spare) = spare {
                self.entry_to_archive(&mut spare);
            }
        }
    }

    fn entry_to_archive(&mut self, entry: &mut ArchiveEntry) {
        let destpath = entry.pathname().unwrap_or(b"(null)").to_vec();
        let srcpath = entry.sourcepath().unwrap_or_default().to_vec();

        // Print out the destination name to the user.
        if self.verbose > 0 {
            eprint(&destpath);
        }
        if self.dot > 0 {
            eprint(".");
        }

        // Option_link only makes sense in pass mode and for
        // regular files. Also note: if a link operation fails
        // because of cross-device restrictions, we'll fall back
        // to copy mode for that entry.
        //
        // TODO: Test other cpio implementations to see if they
        // hard-link anything other than regular files here.
        if self.option_link && entry.filetype() == AE_IFREG {
            // Save the original entry in case we need it later.
            let mut t = entry.clone();
            // Note: link(2) doesn't create parent directories,
            // so we use archive_write_header() instead as a
            // convenience.
            t.set_hardlink(Some(&srcpath));
            // This is a straight link that carries no data.
            t.set_size(0);
            let r = self.output().header(&mut t);
            let a = self.output_archive();
            let errno = a.errno();
            if r != Status::Ok {
                lafe_warnc(errno, error_string(a));
            }
            if r == Status::Fatal {
                exit(1);
            }
            if r != Status::Ok && errno == libc::EXDEV {
                // Cross-device link: Just fall through and use
                // the original entry to copy the file over.
                lafe_warnc(0, "Copying file instead");
            } else {
                if r != Status::Ok {
                    self.return_value = 1;
                }
                return;
            }
        }

        'cleanup: {
            // Make sure we can open the file (if necessary) before
            // trying to write the header.
            let mut fd = None;
            if entry.filetype() == AE_IFREG {
                if entry.size() > 0 {
                    match File::open(path(&srcpath)) {
                        Ok(f) => fd = Some(f),
                        Err(e) => {
                            let errno = e.raw_os_error().unwrap_or(0);
                            lafe_warnc(
                                errno,
                                [srcpath.as_slice(), b": could not open file"].concat(),
                            );
                            break 'cleanup;
                        }
                    }
                }
            } else {
                entry.set_size(0);
            }

            let r = self.output().header(entry);

            if r != Status::Ok {
                let a = self.output_archive();
                lafe_warnc(
                    a.errno(),
                    [srcpath.as_slice(), b": ", &error_string(a)].concat(),
                );
            }

            if r == Status::Fatal {
                exit(1);
            }

            if r >= Status::Warn
                && entry.size() > 0
                && let Some(f) = &mut fd
            {
                let mut buff = [0u8; 16384];
                while let Ok(bytes_read @ 1..) = f.read(&mut buff) {
                    match self.output().data(&buff[..bytes_read]) {
                        Err(_) => {
                            let a = self.output_archive();
                            lafe_errc(1, a.errno(), error_string(a));
                        }
                        Ok(bytes_write) if bytes_write < bytes_read => {
                            lafe_warnc(
                                0,
                                "Truncated write; file may have grown while being archived",
                            );
                        }
                        Ok(_) => {}
                    }
                }
            }

            self.restore_time(entry, &srcpath, fd);
        }

        if self.verbose > 0 {
            eprint("\n");
        }
    }

    /// Restores the access time `fd` (or else the file `name`) had, which
    /// reading it changed.
    fn restore_time(&self, entry: &ArchiveEntry, name: &[u8], fd: Option<File>) {
        if !self.option_atime_restore {
            return;
        }

        let mtime = (entry.mtime(), entry.mtime_nsec() / 1000);
        let atime = (entry.atime(), entry.atime_nsec() / 1000);

        if let Some(f) = &fd
            && sys::futimes(f.as_fd(), atime, mtime).is_ok()
        {
            return;
        }
        // Some platform cannot restore access times if the file descriptor
        // is still opened.
        drop(fd);

        if let Err(errno) = sys::lutimes(path(name), atime, mtime) {
            lafe_warnc(errno, [b"Can't update time for ".as_slice(), name].concat());
        }
    }

    /// Opens the archive -i and -t mode read.
    fn open_reader(&self) -> ArchiveRead {
        let mut a = ArchiveRead::new();
        a.support_filter_all();
        a.support_format_all();
        if self.option_pwb {
            a.set_options(b"pwb");
        }
        let r = match &self.passphrase {
            Some(passphrase) => a.add_passphrase(passphrase),
            None => a.set_passphrase_callback(passphrase_callback),
        };
        if r != Status::Ok {
            lafe_errc(1, 0, error_string(&a));
        }

        let filename = self.filename.as_deref().map(path);
        if a.open_filename(filename, self.bytes_per_block as usize) != Status::Ok {
            lafe_errc(1, a.errno(), error_string(&a));
        }
        a
    }

    fn mode_in(&mut self) -> ! {
        let mut ext = ArchiveWriteDisk::new();
        let r = ext.set_options(self.extract_flags);
        if r != Status::Ok {
            lafe_errc(1, 0, error_string(&ext));
        }
        let mut a = self.open_reader();
        loop {
            match a.next_header() {
                Status::Eof => break,
                Status::Ok => {}
                _ => lafe_errc(1, a.errno(), error_string(&a)),
            }
            let entry = a.entry();
            match self.matching.path_excluded(entry) {
                Err(_) => lafe_errc(1, 0, error_string(&self.matching)),
                Ok(true) => continue,
                Ok(false) => {}
            }
            if self.option_rename {
                cpio_rename(entry);
            }
            let Some(destpath) = entry.pathname() else {
                continue;
            };
            if self.verbose > 0 {
                eprint([destpath, b"\n"].concat());
            }
            if self.dot > 0 {
                eprint(".");
            }
            if let Some(uid) = self.uid_override {
                entry.set_uid(uid.into());
            }
            if self.uname_override.is_some() {
                entry.set_uname(self.uname_override.as_deref());
            }
            if let Some(gid) = self.gid_override {
                entry.set_gid(gid.into());
            }
            if self.gname_override.is_some() {
                entry.set_gname(self.gname_override.as_deref());
            }
            let r = ext.header(entry);
            if r != Status::Ok {
                let pathname = entry.pathname().unwrap_or(b"(null)");
                eprint([pathname, b": ", &error_string(&ext), b"\n"].concat());
                self.return_value = 1;
            } else if (!entry.size_is_set() || entry.size() > 0) && !extract_data(&mut a, &mut ext)
            {
                self.return_value = 1;
            }
        }
        let r = a.close();
        if self.dot > 0 {
            eprint("\n");
        }
        if r != Status::Ok {
            lafe_errc(1, 0, error_string(&a));
        }
        let r = ext.close();
        if r != Status::Ok {
            lafe_errc(1, 0, error_string(&ext));
        }
        if !self.quiet {
            print_blocks(&a);
        }
        exit(self.return_value)
    }

    fn mode_list(&mut self) -> ! {
        let mut a = self.open_reader();
        // Upstream's standard output is fully buffered, and flushed when it
        // exits.
        let mut out = BufWriter::new(io::stdout());
        loop {
            match a.next_header() {
                Status::Eof => break,
                Status::Ok => {}
                _ => errc_flushing(&mut out, a.errno(), error_string(&a)),
            }
            let entry = a.entry();
            match self.matching.path_excluded(entry) {
                Err(_) => errc_flushing(&mut out, 0, error_string(&self.matching)),
                Ok(true) => continue,
                Ok(false) => {}
            }
            if self.verbose > 0 {
                self.list_item_verbose(&mut out, entry);
            } else {
                let pathname = entry.pathname().unwrap_or(b"(null)");
                let _ = out.write_all(&[pathname, b"\n"].concat());
            }
        }
        let _ = out.flush();
        let r = a.close();
        if r != Status::Ok {
            lafe_errc(1, 0, error_string(&a));
        }
        if !self.quiet {
            print_blocks(&a);
        }
        exit(0)
    }

    /// Display information about the current file.
    ///
    /// The format here roughly duplicates the output of 'ls -l'.
    /// This is based on SUSv2, where 'tar tv' is documented as
    /// listing additional information in an "unspecified format,"
    /// and 'pax -l' is documented as using the same format as 'ls -l'.
    fn list_item_verbose(&mut self, out: &mut impl Write, entry: &mut ArchiveEntry) {
        if self.now == 0 {
            let now = SystemTime::now().duration_since(UNIX_EPOCH);
            self.now = now.map_or(0, |d| d.as_secs() as i64);
        }

        let mut line = entry.strmode().to_vec();
        let _ = write!(line, "{:3} ", entry.nlink());
        if self.option_numeric_uid_gid {
            // Format numeric uid/gid for display.
            let _ = write!(line, "{:<8} {:<8}", entry.uid(), entry.gid());
        } else {
            // Use uname if it's present, else lookup name from uid.
            if let Some(uname) = entry.uname() {
                ljust(&mut line, uname, 8);
            } else {
                let uname = lookup_uname(&mut self.uname_cache, entry.uid() as u32);
                ljust(&mut line, uname, 8);
            }
            line.push(b' ');
            // Use gname if it's present, else lookup name from gid.
            if let Some(gname) = entry.gname() {
                ljust(&mut line, gname, 8);
            } else {
                let gname = lookup_gname(&mut self.gname_cache, entry.gid() as u32);
                ljust(&mut line, gname, 8);
            }
        }
        line.push(b' ');

        // Print device number or file size.
        if matches!(entry.filetype(), AE_IFCHR | AE_IFBLK) {
            let size = format!("{},{}", entry.rdevmajor(), entry.rdevminor());
            let _ = write!(line, "{size:>8}");
        } else {
            let _ = write!(line, "{:>8}", entry.size());
        }
        line.push(b' ');

        // Format the time using 'ls -l' conventions.
        let mtime = entry.mtime();
        let age = mtime as f64 - self.now as f64;
        let half_year = 365.0 * 86400.0 / 2.0;
        let fmt = if !(-half_year..=half_year).contains(&age) {
            c"%b %e  %Y"
        } else {
            c"%b %e %H:%M"
        };
        let date = sys::strftime_local(fmt, mtime);
        if date.is_empty() {
            rjust(&mut line, b"invalid mtime", 12);
        } else {
            rjust(&mut line, &date, 12);
        }
        line.push(b' ');
        line.extend_from_slice(entry.pathname().unwrap_or(b"(null)"));

        // Extra information for links.
        if let Some(hardlink) = entry.hardlink() {
            // Hard link
            line.extend_from_slice(b" link to ");
            line.extend_from_slice(hardlink);
        } else if let Some(symlink) = entry.symlink() {
            // Symbolic link
            line.extend_from_slice(b" -> ");
            line.extend_from_slice(symlink);
        }
        line.push(b'\n');
        let _ = out.write_all(&line);
    }

    fn mode_pass(&mut self, destdir: &[u8]) {
        // Ensure target dir has a trailing '/' to simplify path surgery.
        let mut destdir = destdir.to_vec();
        if destdir.last() != Some(&b'/') {
            destdir.push(b'/');
        }
        self.destdir = Some(destdir);

        let mut a = ArchiveWriteDisk::new();
        let r = a.set_options(self.extract_flags);
        if r != Status::Ok {
            lafe_errc(1, 0, error_string(&a));
        }
        self.linkresolver = Some(ArchiveEntryLinkresolver::new());
        a.set_standard_lookup();
        self.archive = Some(Output::Disk(a));

        self.set_up_read_disk();

        let mut lr = LineReader::new(Path::new("-"), self.option_null);
        while let Some(p) = lr.next() {
            self.file_to_archive(p);
        }

        self.linkresolver = None;
        let r = self.output().close();
        if self.dot > 0 {
            eprint("\n");
        }
        let a = self.output_archive();
        if r != Status::Ok {
            lafe_errc(1, 0, error_string(a));
        }

        if !self.quiet {
            print_blocks(a);
        }
    }
}

/// Exits if there's a fatal error. Returns whether everything is kosher.
fn extract_data(ar: &mut ArchiveRead, aw: &mut ArchiveWriteDisk) -> bool {
    loop {
        let (r, block, offset) = ar.data_block();
        if r == Status::Eof {
            return true;
        }
        if r != Status::Ok {
            lafe_warnc(ar.errno(), error_string(ar));
            exit(1);
        }
        if aw.data_block(block, offset) != Ok(0) {
            lafe_warnc(aw.errno(), error_string(aw));
            return false;
        }
    }
}

fn main() {
    // Ignore SIGPIPE signals: Rust programs start so.
    // Do not ignore SIGCHLD.
    sys::default_signal(libc::SIGCHLD);

    let argv: VecDeque<_> = std::env::args_os().map(OsString::into_vec).collect();
    // Set lafe_progname before calling lafe_warnc.
    lafe_setprogname(argv.front().map(|a| OsStr::from_bytes(a)), "bsdcpio");

    if !sys::setlocale_all() {
        lafe_warnc(0, "Failed to set default locale");
    }

    let mut cpio = Cpio::new(argv);

    while let Some(opt) = cpio.getopt() {
        let argument = cpio.argument.take().unwrap_or_default();
        match opt {
            b'0' => cpio.option_null = true, // GNU convention: --null, -0
            b'6' => cpio.option_pwb = true,  // in/out: assume/create 6th edition (PWB) format
            b'7' => cpio.format = Some(b"bin".to_vec()), // out: create archive using 7th Edition binary format
            b'A' => cpio.option_append = true,           // NetBSD/OpenBSD
            b'a' => cpio.option_atime_restore = true,    // POSIX 1997
            b'B' => cpio.bytes_per_block = 5120,         // POSIX 1997
            OPTION_B64ENCODE | OPTION_UUENCODE => cpio.add_filter = opt,
            b'C' => {
                // NetBSD/OpenBSD
                match parse_int(&argument).filter(|&t| t > 0) {
                    Some(t) => cpio.bytes_per_block = t,
                    None => lafe_errc(1, 0, [b"Invalid blocksize: ", argument.as_slice()].concat()),
                }
            }
            b'c' => cpio.format = Some(b"odc".to_vec()), // POSIX 1997
            b'd' => cpio.extract_flags &= !ARCHIVE_EXTRACT_NO_AUTODIR, // POSIX 1997
            b'E' => {
                // NetBSD/OpenBSD
                let r = cpio
                    .matching
                    .include_pattern_from_file(path(&argument), cpio.option_null);
                if r != Status::Ok {
                    lafe_errc(1, 0, error_string(&cpio.matching));
                }
            }
            b'F' | b'I' | b'O' => cpio.filename = Some(argument), // NetBSD/OpenBSD/GNU cpio
            b'f' => {
                // POSIX 1997
                if cpio.matching.exclude_pattern(&argument) != Status::Ok {
                    lafe_errc(1, 0, error_string(&cpio.matching));
                }
            }
            b'H' => cpio.format = Some(argument), // GNU cpio (also --format)
            b'h' => long_help(),
            b'i' | b'o' | b'p' => {
                // POSIX 1997
                if cpio.mode != 0 && cpio.mode != opt {
                    let msg = format!(
                        "Cannot use both -{} and -{}",
                        opt as char, cpio.mode as char
                    );
                    lafe_errc(1, 0, msg);
                }
                cpio.mode = opt;
                if opt == b'p' {
                    cpio.extract_flags &= !ARCHIVE_EXTRACT_SECURE_NODOTDOT;
                    cpio.extract_flags &= !ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS;
                }
            }
            OPTION_GRZIP | b'J' | b'j' | OPTION_LRZIP | OPTION_LZ4 | OPTION_LZMA | OPTION_LZOP
            | OPTION_ZSTD | b'y' | b'Z' | b'z' => cpio.compress = opt,
            OPTION_INSECURE => {
                cpio.extract_flags &= !ARCHIVE_EXTRACT_SECURE_SYMLINKS;
                cpio.extract_flags &= !ARCHIVE_EXTRACT_SECURE_NODOTDOT;
                cpio.extract_flags &= !ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS;
            }
            b'L' => cpio.option_follow_links = true, // GNU cpio
            b'l' => cpio.option_link = true,         // POSIX 1997
            b'm' => cpio.extract_flags |= ARCHIVE_EXTRACT_TIME, // POSIX 1997
            b'n' => cpio.option_numeric_uid_gid = true, // GNU cpio
            OPTION_NO_PRESERVE_OWNER => cpio.extract_flags &= !ARCHIVE_EXTRACT_OWNER, // GNU cpio
            OPTION_PASSPHRASE => cpio.passphrase = Some(argument),
            OPTION_PRESERVE_OWNER => cpio.extract_flags |= ARCHIVE_EXTRACT_OWNER,
            OPTION_QUIET => cpio.quiet = true, // GNU cpio
            b'R' => {
                // GNU cpio, also --owner
                let owner = owner_parse(&argument).unwrap_or_else(|errmsg| {
                    lafe_warnc(0, errmsg);
                    usage()
                });
                if owner.uid.is_some() {
                    cpio.uid_override = owner.uid;
                }
                if owner.uname.is_some() {
                    cpio.uname_override = owner.uname;
                }
                if owner.gid.is_some() {
                    cpio.gid_override = owner.gid;
                }
                if owner.gname.is_some() {
                    cpio.gname_override = owner.gname;
                }
            }
            b'r' => cpio.option_rename = true, // POSIX 1997
            b't' => cpio.option_list = true,   // POSIX 1997
            b'u' => cpio.extract_flags &= !ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER, // POSIX 1997
            b'v' => cpio.verbose += 1,         // POSIX 1997
            b'V' => cpio.dot += 1,             // GNU cpio
            OPTION_VERSION => version(),       // GNU convention
            // cpio_getopt() handles -W specially, so it's not available here.
            _ => usage(),
        }
    }

    // Sanity-check args, error out on nonsensical combinations.
    // -t implies -i if no mode was specified.
    if cpio.option_list && cpio.mode == 0 {
        cpio.mode = b'i';
    }
    // -t requires -i
    if cpio.option_list && cpio.mode != b'i' {
        lafe_errc(1, 0, "Option -t requires -i");
    }
    // -n requires -it
    if cpio.option_numeric_uid_gid && !cpio.option_list {
        lafe_errc(1, 0, "Option -n requires -it");
    }
    // Can only specify format when writing
    if cpio.format.is_some() && cpio.mode != b'o' {
        lafe_errc(1, 0, "Option --format requires -o");
    }
    // -l requires -p
    if cpio.option_link && cpio.mode != b'p' {
        lafe_errc(1, 0, "Option -l requires -p");
    }
    // -v overrides -V
    if cpio.dot > 0 && cpio.verbose > 0 {
        cpio.dot = 0;
    }
    // TODO: Flag other nonsensical combinations.

    match cpio.mode {
        b'o' => {
            if cpio.format.is_none() {
                let default: &[u8] = if cpio.option_pwb { b"pwb" } else { b"cpio" };
                cpio.format = Some(default.to_vec());
            }
            if !cpio.argv.is_empty() {
                let msg = format!(
                    "Too many arguments for -o mode (got {}, expected 0)",
                    cpio.argv.len()
                );
                lafe_errc(1, 0, msg);
            }
            cpio.mode_out();
        }
        b'i' => {
            while let Some(pattern) = cpio.argv.pop_front() {
                if cpio.matching.include_pattern(&pattern) != Status::Ok {
                    lafe_errc(1, 0, error_string(&cpio.matching));
                }
            }
            if cpio.option_list {
                cpio.mode_list();
            } else {
                cpio.mode_in();
            }
        }
        b'p' => {
            let Some(destdir) = cpio.argv.front().filter(|d| !d.is_empty()).cloned() else {
                lafe_errc(1, 0, "-p mode requires a target directory");
            };
            if cpio.argv.len() > 1 {
                let msg = format!(
                    "Too many arguments for -p mode (got {}, expected 1)",
                    cpio.argv.len()
                );
                lafe_errc(1, 0, msg);
            }
            cpio.mode_pass(&destdir);
        }
        _ => lafe_errc(1, 0, "Must specify one of -i, -o, or -p"),
    }

    exit(cpio.return_value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_slashes_drives_and_dotdots_are_removed() {
        for (path, kept) in [
            ("a/b", "a/b"),
            ("/a", "a"),
            ("///a//b", "a//b"),
            ("/../a", "a"),
            ("/../../a", "a"),
            ("..a", "..a"),
            ("/..", ".."),
            ("c:/a", "a"),
            ("c:\\a", "a"),
            ("c:", ""),
            ("/c:/a", "a"),
            ("//./a", "a"),
            ("//?/a", "a"),
            ("\\\\?\\UNC\\a", "a"),
            ("//?/unc/a", "a"),
            ("//?/UNCa", "UNCa"),
            ("", ""),
        ] {
            assert_eq!(
                remove_leading_slash(path.as_bytes()),
                kept.as_bytes(),
                "{path}"
            );
        }
    }

    #[test]
    fn names_are_cached_by_slot() {
        fn name(id: u32) -> Option<Vec<u8>> {
            (id != 7).then(|| format!("n{id}").into_bytes())
        }
        let mut cache = NameCache::new();
        assert_eq!(lookup_name(&mut cache, name, 3), b"n3");
        assert_eq!(
            lookup_name(&mut cache, name, 7),
            b"7",
            "numbers stand in for names"
        );
        // 104 shares 3's slot, and evicts it.
        assert_eq!(
            lookup_name(&mut cache, name, 3 + NAME_CACHE_SIZE as u32),
            b"n104"
        );
        assert_eq!(cache.0[3].as_ref().map(|s| s.0), Some(104));
    }

    #[test]
    fn fields_are_padded_in_bytes() {
        let padded = |f: fn(&mut Vec<u8>, &[u8], usize), s: &[u8], width| {
            let mut out = b">".to_vec();
            f(&mut out, s, width);
            out
        };
        assert_eq!(padded(ljust, b"ab", 4), b">ab  ");
        assert_eq!(padded(ljust, b"abcdef", 4), b">abcdef");
        assert_eq!(padded(rjust, b"ab", 4), b">  ab");
        assert_eq!(padded(rjust, "é".as_bytes(), 4), ">  é".as_bytes());
    }
}
