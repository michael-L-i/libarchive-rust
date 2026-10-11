/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2003-2008 Tim Kientzle
 * All rights reserved.
 */

// Ported from tar/bsdtar.c and tar/bsdtar.h.

//! bsdtar: creates, lists, updates and extracts archives.

#![deny(unsafe_code)]

mod cmdline;
mod creation_set;
mod read;
mod subst;
mod util;
mod write;

use creation_set::CreationSet;
use libarchive_fe::lafe_err::{lafe_errc, lafe_getprogname, lafe_setprogname, lafe_warnc};
use libarchive_fe::lafe_setmode::{SetMode, lafe_setmode};
use libarchive_fe::sys;
use libarchive_rust::*;
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString, c_int};
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use subst::{Substitution, add_substitution};

const DEFAULT_BYTES_PER_BLOCK: c_int = 20 * 512;
const ENV_READER_OPTIONS: &str = "TAR_READER_OPTIONS";
const ENV_WRITER_OPTIONS: &str = "TAR_WRITER_OPTIONS";
const IGNORE_WRONG_MODULE_NAME: &[u8] = b"__ignore_wrong_module_name__,";

/// config.h's, which upstream's CMakeLists.txt makes from build/version.
const BSDTAR_VERSION_STRING: &str = "3.9.0";

/// The default tape: `<paths.h>`'s on macOS, else bsdtar's own.
#[cfg(target_vendor = "apple")]
const PATH_DEFTAPE: &str = "/dev/nrst0";
#[cfg(target_os = "linux")]
const PATH_DEFTAPE: &str = "/dev/st0";
#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
const PATH_DEFTAPE: &str = "/dev/tape";

const PATH_STDIO: &[u8] = b"-";

/// The internal state for the "bsdtar" program.
///
/// Keeping all of the state in a structure like this simplifies memory leak
/// testing (at exit, anything left on the heap is suspect). A pointer to
/// this structure is passed to most bsdtar internal functions.
#[derive(Default)]
pub struct Bsdtar {
    // Options
    /// -f filename; `None` is standard input or output.
    filename: Option<Vec<u8>>,
    /// -C dir
    pending_chdir: Option<Vec<u8>>,
    /// -T file
    names_from_file: Option<Vec<u8>>,
    /// -b block_size
    bytes_per_block: c_int,
    /// See -b handling.
    bytes_in_last_block: c_int,
    /// -v
    verbose: c_int,
    /// Bitfield of boolean options
    flags: u32,
    /// Flags for extract operation
    extract_flags: c_int,
    /// Flags for read disk operation
    readdisk_flags: c_int,
    /// Remove this many leading dirs
    strip_components: c_int,
    /// --gid
    gid: c_int,
    /// --gname
    gname: Option<Vec<u8>>,
    /// --uid
    uid: c_int,
    /// --uname
    uname: Option<Vec<u8>>,
    /// --mode
    file_mode: Option<SetMode>,
    /// --passphrase
    passphrase: Option<Vec<u8>>,
    /// Program mode: 'c', 't', 'r', 'u', 'x'
    mode: u8,
    /// H or L, per BSD conventions
    symlink_mode: u8,
    /// --options
    option_options: Option<Vec<u8>>,
    /// show day before month in -tv output
    day_first: bool,
    /// --mtime exists
    has_mtime: bool,
    /// --clamp-mtime
    clamp_mtime: bool,
    /// --mtime
    mtime: i64,
    cset: CreationSet,

    // Option parser state
    getopt_state: cmdline::State,
    getopt_word: Vec<u8>,

    // Miscellaneous state information
    /// The words of the command line not parsed yet.
    argv: VecDeque<Vec<u8>>,
    argument: Option<Vec<u8>>,
    /// For 'list_item' in read.c
    gs_width: usize,
    /// for 'list_item' in read.c
    u_width: usize,
    /// Value returned by main()
    return_value: c_int,
    /// Already displayed warning
    warned_lead_slash: bool,

    matching: ArchiveMatch,
    substitution: Option<Substitution>,
}

// Options for flags bitfield
const OPTFLAG_AUTO_COMPRESS: u32 = 0x00000001; // -a
const OPTFLAG_ABSOLUTE_PATHS: u32 = 0x00000002; // -P
const OPTFLAG_CHROOT: u32 = 0x00000004; // --chroot
const OPTFLAG_FAST_READ: u32 = 0x00000008; // --fast-read
const OPTFLAG_IGNORE_ZEROS: u32 = 0x00000010; // --ignore-zeros
const OPTFLAG_INTERACTIVE: u32 = 0x00000020; // -w
const OPTFLAG_NO_OWNER: u32 = 0x00000040; // -o
const OPTFLAG_NO_SUBDIRS: u32 = 0x00000080; // -n
const OPTFLAG_NULL: u32 = 0x00000100; // --null
const OPTFLAG_NUMERIC_OWNER: u32 = 0x00000200; // --numeric-owner
const OPTFLAG_O: u32 = 0x00000400; // -o
const OPTFLAG_STDOUT: u32 = 0x00000800; // -O
const OPTFLAG_TOTALS: u32 = 0x00001000; // --totals
const OPTFLAG_UNLINK_FIRST: u32 = 0x00002000; // -U
const OPTFLAG_WARN_LINKS: u32 = 0x00004000; // --check-links
const OPTFLAG_NO_XATTRS: u32 = 0x00008000; // --no-xattrs
const OPTFLAG_XATTRS: u32 = 0x00010000; // --xattrs
const OPTFLAG_NO_ACLS: u32 = 0x00020000; // --no-acls
const OPTFLAG_ACLS: u32 = 0x00040000; // --acls
const OPTFLAG_NO_FFLAGS: u32 = 0x00080000; // --no-fflags
const OPTFLAG_FFLAGS: u32 = 0x00100000; // --fflags
const OPTFLAG_NO_MAC_METADATA: u32 = 0x00200000; // --no-mac-metadata
const OPTFLAG_MAC_METADATA: u32 = 0x00400000; // --mac-metadata
const OPTFLAG_NO_READ_SPARSE: u32 = 0x00800000; // --no-read-sparse
const OPTFLAG_READ_SPARSE: u32 = 0x01000000; // --read-sparse

/// Fake short equivalents for long options that otherwise lack them: the
/// characters from 256 on, as upstream's enum numbers them (which matters
/// where `%c` prints one).
macro_rules! long_options {
    ($($name:ident = $code:literal,)*) => {$(
        const $name: char = match char::from_u32($code) {
            Some(c) => c,
            None => panic!(),
        };
    )*};
}

long_options! {
    OPTION_ACLS = 256,
    OPTION_B64ENCODE = 257,
    OPTION_CHECK_LINKS = 258,
    OPTION_CHROOT = 259,
    OPTION_CLEAR_NOCHANGE_FFLAGS = 260,
    OPTION_EXCLUDE = 261,
    OPTION_EXCLUDE_VCS = 262,
    OPTION_FFLAGS = 263,
    OPTION_FORMAT = 264,
    OPTION_GID = 265,
    OPTION_GNAME = 266,
    OPTION_GROUP = 267,
    OPTION_GRZIP = 268,
    OPTION_HELP = 269,
    OPTION_HFS_COMPRESSION = 270,
    OPTION_IGNORE_ZEROS = 271,
    OPTION_INCLUDE = 272,
    OPTION_KEEP_NEWER_FILES = 273,
    OPTION_LRZIP = 274,
    OPTION_LZ4 = 275,
    OPTION_LZIP = 276,
    OPTION_LZMA = 277,
    OPTION_LZOP = 278,
    OPTION_MAC_METADATA = 279,
    OPTION_NEWER_CTIME = 280,
    OPTION_NEWER_CTIME_THAN = 281,
    OPTION_NEWER_MTIME = 282,
    OPTION_NEWER_MTIME_THAN = 283,
    OPTION_NODUMP = 284,
    OPTION_NOPRESERVE_HFS_COMPRESSION = 285,
    OPTION_NO_ACLS = 286,
    OPTION_NO_FFLAGS = 287,
    OPTION_NO_MAC_METADATA = 288,
    OPTION_NO_READ_SPARSE = 289,
    OPTION_NO_SAFE_WRITES = 290,
    OPTION_NO_SAME_OWNER = 291,
    OPTION_NO_SAME_PERMISSIONS = 292,
    OPTION_NO_XATTRS = 293,
    OPTION_NULL = 294,
    OPTION_NUMERIC_OWNER = 295,
    OPTION_OLDER_CTIME = 296,
    OPTION_OLDER_CTIME_THAN = 297,
    OPTION_OLDER_MTIME = 298,
    OPTION_OLDER_MTIME_THAN = 299,
    OPTION_ONE_FILE_SYSTEM = 300,
    OPTION_OPTIONS = 301,
    OPTION_OWNER = 302,
    OPTION_PASSPHRASE = 303,
    OPTION_POSIX = 304,
    OPTION_READ_SPARSE = 305,
    OPTION_SAFE_WRITES = 306,
    OPTION_SAME_OWNER = 307,
    OPTION_STRIP_COMPONENTS = 308,
    OPTION_TOTALS = 309,
    OPTION_UID = 310,
    OPTION_UNAME = 311,
    OPTION_USE_COMPRESS_PROGRAM = 312,
    OPTION_UUENCODE = 313,
    OPTION_VERSION = 314,
    OPTION_XATTRS = 315,
    OPTION_ZSTD = 316,
    OPTION_MTIME = 317,
    OPTION_CLAMP_MTIME = 318,
    OPTION_MODE = 319,
}

/// An option as C's `%c` prints it: its low byte.
fn byte(opt: char) -> u8 {
    opt as u32 as u8
}

static SIGINFO_OCCURRED: AtomicBool = AtomicBool::new(false);

extern "C" fn siginfo_handler(_sig: c_int) {
    SIGINFO_OCCURRED.store(true, Ordering::Relaxed);
}

/// Whether a SIGINFO or SIGUSR1 came since the last call.
fn need_report() -> bool {
    SIGINFO_OCCURRED.swap(false, Ordering::Relaxed)
}

/// A basic set of security flags to request from libarchive.
const SECURITY: c_int = ARCHIVE_EXTRACT_SECURE_SYMLINKS | ARCHIVE_EXTRACT_SECURE_NODOTDOT;

const VCS_FILES: &[&[u8]] = &[
    // CVS
    b"CVS",
    b".cvsignore",
    // RCS
    b"RCS",
    // SCCS
    b"SCCS",
    // SVN
    b".svn",
    // git
    b".git",
    b".gitignore",
    b".gitattributes",
    b".gitmodules",
    // Arch
    b".arch-ids",
    b"{arch}",
    b"=RELEASE-ID",
    b"=meta-update",
    b"=update",
    // Bazaar
    b".bzr",
    b".bzrignore",
    b".bzrtags",
    // Mercurial
    b".hg",
    b".hgignore",
    b".hgtags",
    // darcs
    b"_darcs",
];

/// `strtol(arg, &end, 10)`, if all of `arg` is the number.
fn number(arg: &[u8]) -> Option<i64> {
    let (l, end) = sys::strtol(arg, 10);
    (!arg.is_empty() && end == arg.len()).then_some(l)
}

/// The argument of the option just parsed. getopt gives one to every
/// option that requires it.
fn argument(bsdtar: &Bsdtar) -> Vec<u8> {
    bsdtar.argument.clone().unwrap_or_default()
}

/// Checks the match calls of the options that select by time.
fn match_time(bsdtar: &Bsdtar, r: Status) {
    if r != Status::Ok {
        lafe_errc(1, 0, util::error_string(&bsdtar.matching));
    }
}

fn main() {
    let mut bsdtar = Bsdtar {
        gid: -1,
        uid: -1,
        ..Bsdtar::default()
    };
    let mut compression = '\0';
    let mut compression2 = '\0';
    let mut compression_name: &[u8] = b"";
    let mut compression2_name: &[u8] = b"";
    let mut compress_program = None;
    let mut possible_help_request = false;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);

    // Set up signal handling.
    #[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
    sys::catch(libc::SIGINFO, siginfo_handler);
    // ... and treat SIGUSR1 the same way as SIGINFO.
    sys::catch(libc::SIGUSR1, siginfo_handler);
    // Rust programs start with SIGPIPE ignored, as bsdtar wants it.
    // Do not ignore SIGCHLD.
    sys::default_signal(libc::SIGCHLD);

    sys::atexit(util::flush_stdout);

    // Set lafe_progname before calling lafe_warnc.
    let argv: VecDeque<_> = std::env::args_os().map(OsString::into_vec).collect();
    lafe_setprogname(argv.front().map(|a| OsStr::from_bytes(a)), "bsdtar");

    if !sys::setlocale_all() {
        lafe_warnc(0, "Failed to set default locale");
    }
    #[cfg(target_vendor = "apple")]
    {
        bsdtar.day_first = sys::nl_langinfo(libc::D_MD_ORDER).first() == Some(&b'd');
    }

    // Look up uid of current user for future reference
    let user_uid = sys::geteuid();

    // Default: open tape drive.
    bsdtar.filename = Some(match std::env::var_os("TAPE") {
        Some(tape) => tape.into_vec(),
        None if Path::new(PATH_DEFTAPE).exists() => PATH_DEFTAPE.into(),
        None => PATH_STDIO.to_vec(),
    });

    // Default block size settings.
    bsdtar.bytes_per_block = DEFAULT_BYTES_PER_BLOCK;
    // Allow library to default this unless user specifies -b.
    bsdtar.bytes_in_last_block = -1;

    // Default: preserve mod time on extract
    bsdtar.extract_flags = ARCHIVE_EXTRACT_TIME;

    // Default: Perform basic security checks.
    bsdtar.extract_flags |= SECURITY;

    // On POSIX systems, assume --same-owner and -p when run by the root
    // user.
    if user_uid == 0 {
        // --same-owner
        bsdtar.extract_flags |= ARCHIVE_EXTRACT_OWNER;
        // -p
        bsdtar.extract_flags |= ARCHIVE_EXTRACT_PERM;
        bsdtar.extract_flags |= ARCHIVE_EXTRACT_ACL;
        bsdtar.extract_flags |= ARCHIVE_EXTRACT_XATTR;
        bsdtar.extract_flags |= ARCHIVE_EXTRACT_FFLAGS;
        bsdtar.extract_flags |= ARCHIVE_EXTRACT_MAC_METADATA;
    }

    // Enable Mac OS "copyfile()" extension by default. This has no effect
    // on other platforms.
    bsdtar.readdisk_flags |= ARCHIVE_READDISK_MAC_COPYFILE;
    #[cfg(target_vendor = "apple")]
    {
        if std::env::var_os("COPYFILE_DISABLE").is_some() {
            bsdtar.readdisk_flags &= !ARCHIVE_READDISK_MAC_COPYFILE;
        }
        // On Mac OS ACLs are archived with copyfile() (--mac-metadata).
        // Translation to NFSv4 ACLs has to be requested explicitly with
        // --acls
        bsdtar.readdisk_flags |= ARCHIVE_READDISK_NO_ACL;
    }

    bsdtar.argv = argv;

    // Comments following each option indicate where that option
    // originated: SUSv2, POSIX, GNU tar, star, etc. If there's no such
    // comment, then I don't know of anyone else who implements that option.
    while let Some(opt) = bsdtar.getopt() {
        match opt {
            // GNU tar
            'a' => bsdtar.flags |= OPTFLAG_AUTO_COMPRESS,
            // GNU tar
            OPTION_ACLS => {
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_ACL;
                bsdtar.readdisk_flags &= !ARCHIVE_READDISK_NO_ACL;
                bsdtar.flags |= OPTFLAG_ACLS;
            }
            // GNU tar: libarchive doesn't need this; just ignore it.
            'B' => {}
            // SUSv2
            'b' => {
                let l = number(&argument(&bsdtar)).filter(|l| (1..=8192).contains(l));
                let Some(l) = l else {
                    lafe_errc(1, 0, "Invalid or out of range (1..8192) argument to -b");
                };
                bsdtar.bytes_per_block = 512 * l as c_int;
                // Explicit -b forces last block size.
                bsdtar.bytes_in_last_block = bsdtar.bytes_per_block;
            }
            OPTION_B64ENCODE => {
                if compression2 != '\0' {
                    lafe_errc(1, 0, "Can't specify both --uuencode and --b64encode");
                }
                compression2 = opt;
                compression2_name = b"b64encode";
            }
            // GNU tar
            'C' => {
                let dir = argument(&bsdtar);
                if dir.is_empty() {
                    lafe_errc(1, 0, "Meaningless option: -C ''");
                }
                util::set_chdir(&mut bsdtar, &dir);
            }
            // SUSv2
            'c' => set_mode(&mut bsdtar, opt),
            // GNU tar
            OPTION_CHECK_LINKS => bsdtar.flags |= OPTFLAG_WARN_LINKS,
            // NetBSD
            OPTION_CHROOT => bsdtar.flags |= OPTFLAG_CHROOT,
            OPTION_CLEAR_NOCHANGE_FFLAGS => {
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_CLEAR_NOCHANGE_FFLAGS;
            }
            // GNU tar
            OPTION_EXCLUDE => {
                let pattern = argument(&bsdtar);
                if bsdtar.matching.exclude_pattern(&pattern) != Status::Ok {
                    lafe_errc(1, 0, [b"Couldn't exclude ".as_slice(), &pattern].concat());
                }
            }
            // GNU tar
            OPTION_EXCLUDE_VCS => {
                for vcs_file in VCS_FILES {
                    if bsdtar.matching.exclude_pattern(vcs_file) != Status::Ok {
                        lafe_errc(1, 0, [b"Couldn't exclude ".as_slice(), vcs_file].concat());
                    }
                }
            }
            OPTION_FFLAGS => {
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_FFLAGS;
                bsdtar.readdisk_flags &= !ARCHIVE_READDISK_NO_FFLAGS;
                bsdtar.flags |= OPTFLAG_FFLAGS;
            }
            // GNU tar, others
            OPTION_FORMAT => bsdtar.cset.set_format(&argument(&bsdtar)),
            // SUSv2
            'f' => bsdtar.filename = bsdtar.argument.clone(),
            // cpio
            OPTION_GID => {
                let l = number(&argument(&bsdtar)).filter(|l| (0..c_int::MAX.into()).contains(l));
                let Some(l) = l else {
                    lafe_errc(1, 0, "Invalid argument to --gid");
                };
                bsdtar.gid = l as c_int;
            }
            // cpio
            OPTION_GNAME => bsdtar.gname = bsdtar.argument.clone(),
            // GNU tar
            OPTION_GROUP => {
                let (name, id) = owner(&argument(&bsdtar), b"--group");
                bsdtar.gname = Some(name);
                if let Some(id) = id {
                    bsdtar.gid = id;
                }
            }
            OPTION_GRZIP => set_compression(&mut compression, opt, &mut compression_name, b"grzip"),
            // BSD convention
            'H' => bsdtar.symlink_mode = b'H',
            // Linux Standards Base, gtar; synonym for -L
            'h' => {
                bsdtar.symlink_mode = b'L';
                // Hack: -h by itself is the "help" command.
                possible_help_request = true;
            }
            // GNU tar, others
            OPTION_HELP => long_help(),
            // Mac OS X v10.6 or later
            OPTION_HFS_COMPRESSION => {
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_HFS_COMPRESSION_FORCED;
            }
            OPTION_IGNORE_ZEROS => bsdtar.flags |= OPTFLAG_IGNORE_ZEROS,
            // GNU tar
            'I' => {
                // TODO: Allow 'names' to come from an archive, not just a
                // text file. Design a good UI for allowing names and
                // mode/owner to be read from an archive, with contents
                // coming from disk. This can be used to "refresh" an
                // archive or to design archives with special permissions
                // without having to create those permissions on disk.
                bsdtar.names_from_file = bsdtar.argument.clone();
            }
            OPTION_INCLUDE => {
                // No one else has the @archive extension, so no one else
                // needs this to filter entries when transforming archives.
                let pattern = argument(&bsdtar);
                if bsdtar.matching.include_pattern(&pattern) != Status::Ok {
                    let msg = [b"Failed to add ".as_slice(), &pattern, b" to inclusion list"];
                    lafe_errc(1, 0, msg.concat());
                }
            }
            // GNU tar
            'j' => set_compression(&mut compression, opt, &mut compression_name, b"bzip2"),
            // GNU tar 1.21 and later
            'J' => set_compression(&mut compression, opt, &mut compression_name, b"xz"),
            // GNU tar
            'k' => bsdtar.extract_flags |= ARCHIVE_EXTRACT_NO_OVERWRITE,
            // GNU tar
            OPTION_KEEP_NEWER_FILES => {
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER;
            }
            // BSD convention
            'L' => bsdtar.symlink_mode = b'L',
            // SUSv2 and GNU tar beginning with 1.16; GNU tar 1.13 used -l
            // for --one-file-system
            'l' => bsdtar.flags |= OPTFLAG_WARN_LINKS,
            OPTION_LRZIP | OPTION_LZ4
            // GNU tar beginning with 1.23
            | OPTION_LZIP
            // GNU tar beginning with 1.20
            | OPTION_LZMA
            // GNU tar beginning with 1.21
            | OPTION_LZOP
            | OPTION_ZSTD => {
                let name: &[u8] = match opt {
                    OPTION_LRZIP => b"lrzip",
                    OPTION_LZ4 => b"lz4",
                    OPTION_LZIP => b"lzip",
                    OPTION_LZMA => b"lzma",
                    OPTION_LZOP => b"lzop",
                    _ => b"zstd",
                };
                set_compression(&mut compression, opt, &mut compression_name, name);
            }
            // SUSv2
            'm' => bsdtar.extract_flags &= !ARCHIVE_EXTRACT_TIME,
            // Mac OS X
            OPTION_MAC_METADATA => {
                bsdtar.readdisk_flags |= ARCHIVE_READDISK_MAC_COPYFILE;
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_MAC_METADATA;
                bsdtar.flags |= OPTFLAG_MAC_METADATA;
            }
            // GNU tar
            OPTION_MODE => {
                let mode = argument(&bsdtar);
                bsdtar.file_mode = lafe_setmode(&mode);
                if bsdtar.file_mode.is_none() {
                    lafe_errc(1, 0, [b"Invalid file mode: ".as_slice(), &mode].concat());
                }
            }
            // GNU tar
            'n' => bsdtar.flags |= OPTFLAG_NO_SUBDIRS,
            // Selecting files by time:
            //    --newer-?time='date' Only files newer than 'date'
            //    --newer-?time-than='file' Only files newer than time
            //         on specified file (useful for incremental backups)
            // GNU tar
            OPTION_NEWER_CTIME => {
                let flag = ARCHIVE_MATCH_CTIME | ARCHIVE_MATCH_NEWER;
                let r = bsdtar.matching.include_date(flag, &argument(&bsdtar));
                match_time(&bsdtar, r);
            }
            OPTION_NEWER_CTIME_THAN => {
                let flag = ARCHIVE_MATCH_CTIME | ARCHIVE_MATCH_NEWER;
                let r = include_file_time(&mut bsdtar, flag);
                match_time(&bsdtar, r);
            }
            // GNU tar
            OPTION_NEWER_MTIME => {
                let flag = ARCHIVE_MATCH_MTIME | ARCHIVE_MATCH_NEWER;
                let r = bsdtar.matching.include_date(flag, &argument(&bsdtar));
                match_time(&bsdtar, r);
            }
            OPTION_NEWER_MTIME_THAN => {
                let flag = ARCHIVE_MATCH_MTIME | ARCHIVE_MATCH_NEWER;
                let r = include_file_time(&mut bsdtar, flag);
                match_time(&bsdtar, r);
            }
            // star
            OPTION_NODUMP => bsdtar.readdisk_flags |= ARCHIVE_READDISK_HONOR_NODUMP,
            // Mac OS X v10.6 or later
            OPTION_NOPRESERVE_HFS_COMPRESSION => {
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_NO_HFS_COMPRESSION;
            }
            // GNU tar
            OPTION_NO_ACLS => {
                bsdtar.extract_flags &= !ARCHIVE_EXTRACT_ACL;
                bsdtar.readdisk_flags |= ARCHIVE_READDISK_NO_ACL;
                bsdtar.flags |= OPTFLAG_NO_ACLS;
            }
            OPTION_NO_FFLAGS => {
                bsdtar.extract_flags &= !ARCHIVE_EXTRACT_FFLAGS;
                bsdtar.readdisk_flags |= ARCHIVE_READDISK_NO_FFLAGS;
                bsdtar.flags |= OPTFLAG_NO_FFLAGS;
            }
            // Mac OS X
            OPTION_NO_MAC_METADATA => {
                bsdtar.readdisk_flags &= !ARCHIVE_READDISK_MAC_COPYFILE;
                bsdtar.extract_flags &= !ARCHIVE_EXTRACT_MAC_METADATA;
                bsdtar.flags |= OPTFLAG_NO_MAC_METADATA;
            }
            OPTION_NO_READ_SPARSE => {
                bsdtar.readdisk_flags |= ARCHIVE_READDISK_NO_SPARSE;
                bsdtar.flags |= OPTFLAG_NO_READ_SPARSE;
            }
            OPTION_NO_SAFE_WRITES => bsdtar.extract_flags &= !ARCHIVE_EXTRACT_SAFE_WRITES,
            // GNU tar
            OPTION_NO_SAME_OWNER => bsdtar.extract_flags &= !ARCHIVE_EXTRACT_OWNER,
            // GNU tar
            OPTION_NO_SAME_PERMISSIONS => {
                bsdtar.extract_flags &= !ARCHIVE_EXTRACT_PERM;
                bsdtar.extract_flags &= !ARCHIVE_EXTRACT_ACL;
                bsdtar.extract_flags &= !ARCHIVE_EXTRACT_XATTR;
                bsdtar.extract_flags &= !ARCHIVE_EXTRACT_FFLAGS;
                bsdtar.extract_flags &= !ARCHIVE_EXTRACT_MAC_METADATA;
            }
            // GNU tar
            OPTION_NO_XATTRS => {
                bsdtar.extract_flags &= !ARCHIVE_EXTRACT_XATTR;
                bsdtar.readdisk_flags |= ARCHIVE_READDISK_NO_XATTR;
                bsdtar.flags |= OPTFLAG_NO_XATTRS;
            }
            // GNU tar
            OPTION_NULL => bsdtar.flags |= OPTFLAG_NULL,
            // GNU tar
            OPTION_NUMERIC_OWNER => {
                bsdtar.uname = Some(Vec::new());
                bsdtar.gname = Some(Vec::new());
                bsdtar.flags |= OPTFLAG_NUMERIC_OWNER;
            }
            // GNU tar
            'O' => bsdtar.flags |= OPTFLAG_STDOUT,
            // SUSv2 and GNU conflict here, but not fatally
            'o' => bsdtar.flags |= OPTFLAG_O,
            // Selecting files by time:
            //    --older-?time='date' Only files older than 'date'
            //    --older-?time-than='file' Only files older than time
            //         on specified file
            OPTION_OLDER_CTIME => {
                let flag = ARCHIVE_MATCH_CTIME | ARCHIVE_MATCH_OLDER;
                let r = bsdtar.matching.include_date(flag, &argument(&bsdtar));
                match_time(&bsdtar, r);
            }
            OPTION_OLDER_CTIME_THAN => {
                let flag = ARCHIVE_MATCH_CTIME | ARCHIVE_MATCH_OLDER;
                let r = include_file_time(&mut bsdtar, flag);
                match_time(&bsdtar, r);
            }
            OPTION_OLDER_MTIME => {
                let flag = ARCHIVE_MATCH_MTIME | ARCHIVE_MATCH_OLDER;
                let r = bsdtar.matching.include_date(flag, &argument(&bsdtar));
                match_time(&bsdtar, r);
            }
            OPTION_OLDER_MTIME_THAN => {
                let flag = ARCHIVE_MATCH_MTIME | ARCHIVE_MATCH_OLDER;
                let r = include_file_time(&mut bsdtar, flag);
                match_time(&bsdtar, r);
            }
            // GNU tar
            OPTION_ONE_FILE_SYSTEM => {
                bsdtar.readdisk_flags |= ARCHIVE_READDISK_NO_TRAVERSE_MOUNTS;
            }
            OPTION_OPTIONS => {
                if let Some(previous) = &bsdtar.option_options {
                    let msg = [
                        b"Ignoring previous option '".as_slice(),
                        previous,
                        b"', separate multiple options with commas",
                    ];
                    lafe_warnc(0, msg.concat());
                }
                bsdtar.option_options = bsdtar.argument.clone();
            }
            // GNU tar
            OPTION_OWNER => {
                let (name, id) = owner(&argument(&bsdtar), b"--owner");
                bsdtar.uname = Some(name);
                if let Some(id) = id {
                    bsdtar.uid = id;
                }
            }
            // GNU tar
            OPTION_MTIME => {
                bsdtar.has_mtime = true;
                bsdtar.mtime = parse_date(now, &argument(&bsdtar));
                if bsdtar.mtime == -1 {
                    lafe_errc(1, 0, "Invalid argument to --mtime (bad date string)");
                }
            }
            // GNU tar
            OPTION_CLAMP_MTIME => bsdtar.clamp_mtime = true,
            // GNU tar
            'P' => {
                bsdtar.extract_flags &= !SECURITY;
                bsdtar.flags |= OPTFLAG_ABSOLUTE_PATHS;
            }
            // GNU tar, star
            'p' => {
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_PERM;
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_ACL;
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_XATTR;
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_FFLAGS;
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_MAC_METADATA;
            }
            OPTION_PASSPHRASE => bsdtar.passphrase = bsdtar.argument.clone(),
            // GNU tar
            OPTION_POSIX => bsdtar.cset.set_format(b"pax"),
            // FreeBSD GNU tar --fast-read, NetBSD -q
            'q' => bsdtar.flags |= OPTFLAG_FAST_READ,
            // SUSv2
            'r' => set_mode(&mut bsdtar, opt),
            OPTION_READ_SPARSE => {
                bsdtar.readdisk_flags &= !ARCHIVE_READDISK_NO_SPARSE;
                bsdtar.flags |= OPTFLAG_READ_SPARSE;
            }
            // NetBSD pax-as-tar
            'S' => bsdtar.extract_flags |= ARCHIVE_EXTRACT_SPARSE,
            // NetBSD pax-as-tar
            's' => {
                let rule = argument(&bsdtar);
                add_substitution(&mut bsdtar, &rule);
            }
            OPTION_SAFE_WRITES => bsdtar.extract_flags |= ARCHIVE_EXTRACT_SAFE_WRITES,
            // GNU tar
            OPTION_SAME_OWNER => bsdtar.extract_flags |= ARCHIVE_EXTRACT_OWNER,
            // GNU tar 1.15
            OPTION_STRIP_COMPONENTS => {
                let l = number(&argument(&bsdtar)).filter(|l| (0..=100000).contains(l));
                let Some(l) = l else {
                    lafe_errc(1, 0, "Invalid argument to --strip-components");
                };
                bsdtar.strip_components = l as c_int;
            }
            // GNU tar
            'T' => {
                if bsdtar.names_from_file.is_some() {
                    lafe_errc(1, 0, "Multiple --files-from/-T options are not supported");
                }
                bsdtar.names_from_file = bsdtar.argument.clone();
            }
            // SUSv2
            't' => {
                set_mode(&mut bsdtar, opt);
                bsdtar.verbose += 1;
            }
            // GNU tar
            OPTION_TOTALS => bsdtar.flags |= OPTFLAG_TOTALS,
            // GNU tar
            'U' => {
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_UNLINK;
                bsdtar.flags |= OPTFLAG_UNLINK_FIRST;
            }
            // SUSv2
            'u' => set_mode(&mut bsdtar, opt),
            // cpio
            OPTION_UID => {
                let l = number(&argument(&bsdtar)).filter(|l| (0..c_int::MAX.into()).contains(l));
                let Some(l) = l else {
                    lafe_errc(1, 0, "Invalid argument to --uid");
                };
                bsdtar.uid = l as c_int;
            }
            // cpio
            OPTION_UNAME => bsdtar.uname = bsdtar.argument.clone(),
            OPTION_UUENCODE => {
                if compression2 != '\0' {
                    lafe_errc(1, 0, "Can't specify both --uuencode and --b64encode");
                }
                compression2 = opt;
                compression2_name = b"uuencode";
            }
            // SUSv2
            'v' => bsdtar.verbose += 1,
            // GNU convention
            OPTION_VERSION => version(),
            // SUSv2
            'w' => bsdtar.flags |= OPTFLAG_INTERACTIVE,
            // GNU tar
            'X' => {
                let file = argument(&bsdtar);
                let r = bsdtar.matching.exclude_pattern_from_file(util::path(&file), false);
                if r != Status::Ok {
                    lafe_errc(1, 0, util::error_string(&bsdtar.matching));
                }
            }
            // SUSv2
            'x' => set_mode(&mut bsdtar, opt),
            // GNU tar
            OPTION_XATTRS => {
                bsdtar.extract_flags |= ARCHIVE_EXTRACT_XATTR;
                bsdtar.readdisk_flags &= !ARCHIVE_READDISK_NO_XATTR;
                bsdtar.flags |= OPTFLAG_XATTRS;
            }
            // FreeBSD version of GNU tar
            'y' => set_compression(&mut compression, opt, &mut compression_name, b"bzip2"),
            // GNU tar
            'Z' => set_compression(&mut compression, opt, &mut compression_name, b"compress"),
            // GNU tar, star, many others
            'z' => set_compression(&mut compression, opt, &mut compression_name, b"gzip"),
            OPTION_USE_COMPRESS_PROGRAM => compress_program = bsdtar.argument.clone(),
            _ => usage(),
        }
    }

    // Sanity-check options.

    // If no "real" mode was specified, treat -h as --help.
    if bsdtar.mode == 0 && possible_help_request {
        long_help();
    }

    // Otherwise, a mode is required.
    if bsdtar.mode == 0 {
        lafe_errc(1, 0, "Must specify one of -c, -r, -t, -u, -x");
    }

    // Check boolean options only permitted in certain modes.
    if bsdtar.flags & OPTFLAG_AUTO_COMPRESS != 0 {
        only_mode(&bsdtar, b"-a", b"cx");
        if bsdtar.mode == b'x' {
            bsdtar.flags &= !OPTFLAG_AUTO_COMPRESS;
            lafe_warnc(0, "Ignoring option -a in mode -x");
        }
    }
    if bsdtar.readdisk_flags & ARCHIVE_READDISK_NO_TRAVERSE_MOUNTS != 0 {
        only_mode(&bsdtar, b"--one-file-system", b"cru");
    }
    if bsdtar.flags & OPTFLAG_FAST_READ != 0 {
        only_mode(&bsdtar, b"--fast-read", b"xt");
    }
    if bsdtar.extract_flags & ARCHIVE_EXTRACT_HFS_COMPRESSION_FORCED != 0 {
        only_mode(&bsdtar, b"--hfsCompression", b"x");
    }
    if bsdtar.extract_flags & ARCHIVE_EXTRACT_NO_HFS_COMPRESSION != 0 {
        only_mode(&bsdtar, b"--nopreserveHFSCompression", b"x");
    }
    if bsdtar.readdisk_flags & ARCHIVE_READDISK_HONOR_NODUMP != 0 {
        only_mode(&bsdtar, b"--nodump", b"cru");
    }
    for (flag, opt) in [
        (OPTFLAG_ACLS, b"--acls".as_slice()),
        (OPTFLAG_NO_ACLS, b"--no-acls"),
        (OPTFLAG_XATTRS, b"--xattrs"),
        (OPTFLAG_NO_XATTRS, b"--no-xattrs"),
        (OPTFLAG_FFLAGS, b"--fflags"),
        (OPTFLAG_NO_FFLAGS, b"--no-fflags"),
        (OPTFLAG_MAC_METADATA, b"--mac-metadata"),
        (OPTFLAG_NO_MAC_METADATA, b"--no-mac-metadata"),
    ] {
        if bsdtar.flags & flag != 0 {
            only_mode(&bsdtar, opt, b"crux");
        }
    }
    if bsdtar.flags & OPTFLAG_O != 0 {
        match bsdtar.mode {
            b'c' => {
                // In GNU tar, -o means "old format." The "ustar" format is
                // the closest thing supported by libarchive.
                bsdtar.cset.set_format(b"ustar");
                // TODO: bsdtar.create_format = "v7";
            }
            b'x' => {
                // POSIX-compatible behavior.
                bsdtar.flags |= OPTFLAG_NO_OWNER;
                bsdtar.extract_flags &= !ARCHIVE_EXTRACT_OWNER;
            }
            _ => only_mode(&bsdtar, b"-o", b"xc"),
        }
    }
    if bsdtar.flags & OPTFLAG_STDOUT != 0 {
        only_mode(&bsdtar, b"-O", b"xt");
    }
    if bsdtar.flags & OPTFLAG_UNLINK_FIRST != 0 {
        only_mode(&bsdtar, b"-U", b"x");
    }
    if bsdtar.flags & OPTFLAG_WARN_LINKS != 0 {
        only_mode(&bsdtar, b"--check-links", b"cr");
    }

    if bsdtar.flags & OPTFLAG_AUTO_COMPRESS != 0 {
        let filename = bsdtar.filename.clone().unwrap_or_default();
        if bsdtar.cset.auto_compress(&filename) {
            // Ignore specified compressions if auto-compress works.
            compression = '\0';
            compression2 = '\0';
        }
    }
    // Check other parameters only permitted in certain modes.
    if let Some(compress_program) = &compress_program {
        only_mode(&bsdtar, b"--use-compress-program", b"cxt");
        bsdtar.cset.add_filter_program(compress_program);
        // Ignore specified compressions.
        compression = '\0';
        compression2 = '\0';
    }
    if compression != '\0' {
        let buff = match compression {
            'J' | 'j' | 'y' | 'Z' | 'z' => vec![b'-', byte(compression)],
            _ => [b"--", compression_name].concat(),
        };
        only_mode(&bsdtar, &buff, b"cxt");
        bsdtar.cset.add_filter(compression_name);
    }
    if compression2 != '\0' {
        only_mode(&bsdtar, &[b"--", compression2_name].concat(), b"cxt");
        bsdtar.cset.add_filter(compression2_name);
    }
    if bsdtar.cset.get_format().is_some() {
        only_mode(&bsdtar, b"--format", b"cru");
    }
    if bsdtar.symlink_mode != 0 {
        only_mode(&bsdtar, &[b'-', bsdtar.symlink_mode], b"cru");
    }

    if !bsdtar.has_mtime && bsdtar.clamp_mtime {
        lafe_errc(1, 0, "--clamp-mtime is not valid without --mtime <date>");
    }

    // When creating an archive from a directory tree, the directory walking
    // code will already avoid entering directories when recursive inclusion
    // of directory content is disabled, therefore changing the matching
    // behavior has no effect for creation modes. It is relevant for
    // extraction or listing.
    let recursion = bsdtar.flags & OPTFLAG_NO_SUBDIRS == 0;
    bsdtar.matching.set_inclusion_recursion(recursion);

    // Filename "-" implies stdio.
    if bsdtar.filename.as_deref() == Some(PATH_STDIO) {
        bsdtar.filename = None;
    }

    match bsdtar.mode {
        b'c' => write::tar_mode_c(&mut bsdtar),
        b'r' => write::tar_mode_r(&mut bsdtar),
        b't' => read::tar_mode_t(&mut bsdtar),
        b'u' => write::tar_mode_u(&mut bsdtar),
        b'x' => read::tar_mode_x(&mut bsdtar),
        _ => {}
    }

    if bsdtar.return_value != 0 {
        lafe_warnc(0, "Error exit delayed from previous errors");
    }
    exit(bsdtar.return_value);
}

/// Records the compression option `opt`, unless there is one already.
fn set_compression(
    compression: &mut char,
    opt: char,
    name: &mut &[u8],
    compression_name: &'static [u8],
) {
    if *compression != '\0' {
        let msg = [
            b"Can't specify both -".as_slice(),
            &[byte(opt)],
            b" and -",
            &[byte(*compression)],
        ];
        lafe_errc(1, 0, msg.concat());
    }
    *compression = opt;
    *name = compression_name;
}

/// The name and the id of `--owner` or `--group` (`option`): "name", "id",
/// or "name:id". A number alone is an id with an empty name.
fn owner(arg: &[u8], option: &[u8]) -> (Vec<u8>, Option<c_int>) {
    let invalid = |why: &[u8]| -> ! {
        lafe_errc(
            1,
            0,
            [b"Invalid argument to ", option, b" (", why, b")"].concat(),
        )
    };
    if let Some(colon) = arg.iter().position(|&c| c == b':') {
        let id = &arg[colon + 1..];
        if id.is_empty() {
            invalid(b"missing id after :");
        }
        match number(id).filter(|l| (0..c_int::MAX.into()).contains(l)) {
            Some(l) => (arg[..colon].to_vec(), Some(l as c_int)),
            None => invalid(&[id, b" is not a number"].concat()),
        }
    } else {
        match number(arg).filter(|l| (0..c_int::MAX.into()).contains(l)) {
            Some(l) => (Vec::new(), Some(l as c_int)),
            None => (arg.to_vec(), None),
        }
    }
}

/// `archive_match_include_file_time` with the option's argument.
fn include_file_time(bsdtar: &mut Bsdtar, flag: c_int) -> Status {
    let file = argument(bsdtar);
    bsdtar.matching.include_file_time(flag, util::path(&file))
}

fn set_mode(bsdtar: &mut Bsdtar, opt: char) {
    if bsdtar.mode != 0 && bsdtar.mode != byte(opt) {
        let msg = [
            b"Can't specify both -",
            &[byte(opt)][..],
            b" and -",
            &[bsdtar.mode],
        ];
        lafe_errc(1, 0, msg.concat());
    }
    bsdtar.mode = byte(opt);
}

/// Verify that the mode is correct.
fn only_mode(bsdtar: &Bsdtar, opt: &[u8], valid_modes: &[u8]) {
    if !valid_modes.contains(&bsdtar.mode) {
        let msg = [
            b"Option ".as_slice(),
            opt,
            b" is not permitted in mode -",
            &[bsdtar.mode],
        ];
        lafe_errc(1, 0, msg.concat());
    }
}

fn usage() -> ! {
    let p = lafe_getprogname();
    let msg = [
        b"Usage:\n".as_slice(),
        b"  List:    ",
        &p,
        b" -tf <archive-filename>\n",
        b"  Extract: ",
        &p,
        b" -xf <archive-filename>\n",
        b"  Create:  ",
        &p,
        b" -cf <archive-filename> [filenames...]\n",
        b"  Help:    ",
        &p,
        b" --help\n",
    ];
    let _ = io::stderr().write_all(&msg.concat());
    exit(1)
}

fn version() -> ! {
    let details = version_details();
    let _ = writeln!(util::Stdout, "bsdtar {BSDTAR_VERSION_STRING} - {details} ");
    exit(0)
}

fn long_help_msg() -> String {
    [
        "First option must be a mode specifier:\n",
        "  -c Create  -r Add/Replace  -t List  -u Update  -x Extract\n",
        "Common Options:\n",
        "  -b #  Use # 512-byte records per I/O block\n",
        "  -f <filename>  Location of archive (default ",
        PATH_DEFTAPE,
        ")\n",
        "  -v    Verbose\n",
        "  -w    Interactive\n",
        "Create: %p -c [options] [<file> | <dir> | @<archive> | -C <dir> ]\n",
        "  <file>, <dir>  add these items to archive\n",
        "  -z, -j, -J, --lzma  Compress archive with gzip/bzip2/xz/lzma\n",
        "  --format {ustar|pax|cpio|shar}  Select archive format\n",
        "  --exclude <pattern>  Skip files that match pattern\n",
        "  --mtime <date>  Set modification times for added files\n",
        "  --clamp-mtime   Only set modification times for files newer than --mtime\n",
        "  -C <dir>  Change to <dir> before processing remaining files\n",
        "  @<archive>  Add entries from <archive> to output\n",
        "List: %p -t [options] [<patterns>]\n",
        "  <patterns>  If specified, list only entries that match\n",
        "Extract: %p -x [options] [<patterns>]\n",
        "  <patterns>  If specified, extract only entries that match\n",
        "  -k    Keep (don't overwrite) existing files\n",
        "  -m    Don't restore modification times\n",
        "  -O    Write entries to stdout, don't restore to disk\n",
        "  -p    Restore permissions (including ACLs, owner, file flags)\n",
    ]
    .concat()
}

/// Note that the word 'bsdtar' will always appear in the first line of
/// output.
///
/// In particular, /bin/sh scripts that need to test for the presence of
/// bsdtar can use the following template:
///
/// if (tar --help 2>&1 | grep bsdtar >/dev/null 2>&1 ) then \
///          echo bsdtar; else echo not bsdtar; fi
fn long_help() -> ! {
    let prog = lafe_getprogname();
    let p: &[u8] = if prog != b"bsdtar" { b"(bsdtar)" } else { b"" };
    let mut out = [&prog, p, b": manipulate archive files\n"].concat();
    for (i, part) in long_help_msg().split("%p").enumerate() {
        if i > 0 {
            out.extend_from_slice(&prog);
        }
        out.extend_from_slice(part.as_bytes());
    }
    let _ = util::Stdout.write_all(&out);
    version()
}
