//! `archive_read_*`: reading an archive.
//!
//! The `impl Handle` block is the C functions' behavior after argument
//! conversion: the state checks upstream makes (with the names it uses in
//! its messages) and the call into the reader. `ffi` exports it and
//! `ArchiveRead` wraps it.

use super::{Archive, ArchiveEntry, ArchiveWriteDisk, Status};
use crate::archive::{ARCHIVE_EOF, ARCHIVE_FATAL, ARCHIVE_OK, ARCHIVE_WARN, Base, Handle, Kind};
use crate::archive::{READ_MAGIC, state};
use crate::entry::Entry;
use crate::ffi::sys::Fd;
use crate::read::filter::{
    all as filter_all, by_code as filter_by_code, bzip2 as filter_bzip2, compress, grzip, gzip,
    lrzip, lz4 as filter_lz4, lzop, none as filter_none, program, rpm, uu as filter_uu,
    xz as filter_xz, zstd as filter_zstd,
};
use crate::read::format::{
    all as format_all, ar, by_code as format_by_code, cab, cpio, empty, iso9660, lha, mtree, rar,
    rar5, raw, sevenzip, tar, warc, xar, zip,
};
use crate::read::{self, Client, Data, Read};
use crate::read_add_passphrase::PassphraseCallback;
use crate::read_open_fd::ReadFd;
use crate::read_open_filename::Filenames;
use crate::read_open_memory::Memory;
use crate::string::until_nul;
use crate::util::Error;
use crate::{options, read_append_filter, read_data_into_fd, read_set_format, read_set_options};
use std::ffi::c_int;
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// A registration's code: its status, or its failure, recorded.
fn code(a: &Base, result: Result<read::Status, Error>) -> c_int {
    result.map_or_else(|e| a.raise(e), read::Status::code)
}

impl Handle {
    /// Runs `f` on the read state. A client callback that calls back into
    /// its own handle finds the state in use and gets `fallback`.
    pub(crate) fn with_read<T>(&self, fallback: T, f: impl FnOnce(&mut Read) -> T) -> T {
        match &self.kind {
            Kind::Read(r) => r.try_borrow_mut().map_or(fallback, |mut r| f(&mut r)),
            _ => fallback,
        }
    }

    /// `f` on the read state, after `archive_check_magic(a,
    /// ARCHIVE_READ_MAGIC, states, func)`.
    pub(crate) fn read_checked<T: Copy>(
        &self,
        func: &str,
        states: u32,
        fallback: T,
        f: impl FnOnce(&mut Read, &Base) -> T,
    ) -> T {
        self.checked(READ_MAGIC, states, func, fallback, || {
            self.with_read(fallback, |r| f(r, &self.base))
        })
    }

    /// An `archive_read_support_filter_X` (`func`): registers the bidder.
    pub(crate) fn read_support_filter(&self, func: &str, support: filter_all::Support) -> c_int {
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, |r, a| {
            code(a, support(r, a))
        })
    }

    /// An `archive_read_support_format_X` (`func`): registers the reader.
    pub(crate) fn read_support_format(&self, func: &str, support: format_all::Support) -> c_int {
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, |r, a| code(a, support(r)))
    }

    pub(crate) fn read_support_filter_none(&self) -> c_int {
        let func = "archive_read_support_filter_none";
        self.checked(
            READ_MAGIC,
            state::NEW,
            func,
            ARCHIVE_FATAL,
            filter_none::support,
        )
    }

    pub(crate) fn read_support_filter_all(&self) -> c_int {
        let func = "archive_read_support_filter_all";
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, filter_all::support)
    }

    pub(crate) fn read_support_format_all(&self) -> c_int {
        let func = "archive_read_support_format_all";
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, format_all::support)
    }

    pub(crate) fn read_support_filter_by_code(&self, filter: c_int) -> c_int {
        let func = "archive_read_support_filter_by_code";
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, |r, a| {
            filter_by_code::support(r, a, filter)
        })
    }

    pub(crate) fn read_support_format_by_code(&self, format: c_int) -> c_int {
        let func = "archive_read_support_format_by_code";
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, |r, a| {
            format_by_code::support(r, a, format)
        })
    }

    /// `archive_read_set_format`. Upstream's first check is the one in
    /// `archive_read_support_format_by_code`.
    pub(crate) fn read_set_format(&self, format: c_int) -> c_int {
        let func = "archive_read_support_format_by_code";
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, |r, a| {
            read_set_format::set_format(r, a, format)
        })
    }

    pub(crate) fn read_append_filter(&self, filter: c_int) -> c_int {
        let func = "archive_read_append_filter";
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, |r, a| {
            read_append_filter::append_filter(r, a, filter)
        })
    }

    /// The program filters: `f` gets the command and the signature (empty
    /// for none). Upstream names `__archive_read_register_bidder` in the
    /// state check, because that is the first function to check. A NULL
    /// command crashes upstream; it fails here.
    fn read_program(
        &self,
        cmd: Option<&[u8]>,
        signature: &[u8],
        f: impl FnOnce(&mut Read, &Base, &[u8], &[u8]) -> c_int,
    ) -> c_int {
        let func = "__archive_read_register_bidder";
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, |r, a| match cmd {
            Some(cmd) => f(r, a, cmd, signature),
            None => ARCHIVE_FATAL,
        })
    }

    pub(crate) fn read_support_filter_program_signature(
        &self,
        cmd: Option<&[u8]>,
        signature: &[u8],
    ) -> c_int {
        self.read_program(cmd, signature, |r, a, cmd, signature| {
            code(a, program::support(r, cmd, signature))
        })
    }

    pub(crate) fn read_append_filter_program_signature(
        &self,
        cmd: Option<&[u8]>,
        signature: &[u8],
    ) -> c_int {
        self.read_program(cmd, signature, read_append_filter::append_filter_program)
    }

    /// `archive_read_open1` for a native client, after the state check that
    /// the first `archive_read_set_*_callback` call upstream makes (`func`).
    pub(crate) fn read_open(&self, func: &str, client: Box<dyn Client>) -> c_int {
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, |r, a| r.open(a, client))
    }

    /// `archive_read_open_filenames`: the files one after another, as one
    /// stream; `None` is standard input.
    pub(crate) fn read_open_filenames(
        &self,
        names: Vec<Option<Vec<u8>>>,
        block_size: usize,
    ) -> c_int {
        self.base.clear_error();
        let client = Filenames::new(names, block_size);
        self.read_open("archive_read_add_callback_data", Box::new(client))
    }

    pub(crate) fn read_open_fd(&self, fd: Fd, block_size: usize) -> c_int {
        self.base.clear_error();
        match ReadFd::new(fd, block_size) {
            Ok((client, skip_file)) => {
                self.with_read((), |r| r.skip_file = skip_file.or(r.skip_file));
                self.read_open("archive_read_set_read_callback", Box::new(client))
            }
            Err(e) => self.base.raise(e),
        }
    }

    /// `archive_read_open_memory2`: reads `data`, at most `read_size` bytes
    /// at a time.
    pub(crate) fn read_open_memory(
        &self,
        data: impl AsRef<[u8]> + 'static,
        read_size: usize,
    ) -> c_int {
        let client = Memory::new(data, read_size);
        self.read_open("archive_read_set_open_callback", Box::new(client))
    }

    /// `archive_read_data_block`: gives the next block of the entry's data
    /// to `f`. `entry` is the handle's own (`a->entry`). `Err` is the
    /// status, recorded.
    pub(crate) fn read_data_block<R>(
        &self,
        entry: Option<&mut Entry>,
        f: impl FnOnce(Data<'_>) -> R,
    ) -> Result<R, c_int> {
        let func = "archive_read_data_block";
        self.checked(READ_MAGIC, state::DATA, func, Err(ARCHIVE_FATAL), || {
            self.with_read(Err(ARCHIVE_FATAL), |r| {
                r.read_data_block(&self.base, entry, f)
            })
        })
    }

    /// `archive_read_data`: the byte count or a negative status.
    pub(crate) fn read_data(&self, entry: Option<&mut Entry>, dest: &mut [u8]) -> isize {
        // Upstream's loop doesn't run, so nothing is checked.
        if dest.is_empty() {
            return 0;
        }
        // Upstream gets here by way of archive_read_data_block.
        let func = "archive_read_data_block";
        self.read_checked(func, state::DATA, ARCHIVE_FATAL as isize, |r, a| {
            r.read_data(a, entry, dest)
        })
    }

    pub(crate) fn read_data_skip(&self, entry: Option<&mut Entry>) -> c_int {
        let func = "archive_read_data_skip";
        let states = state::DATA | state::DATA_RECOVERY;
        self.read_checked(func, states, ARCHIVE_FATAL, |r, a| {
            r.read_data_skip(a, entry)
        })
    }

    pub(crate) fn read_data_into_fd(&self, entry: Option<&mut Entry>, fd: Fd) -> c_int {
        let func = "archive_read_data_into_fd";
        self.read_checked(func, state::DATA, ARCHIVE_FATAL, |r, a| {
            read_data_into_fd::data_into_fd(r, a, entry, fd)
        })
    }

    pub(crate) fn read_set_format_option(
        &self,
        m: Option<&[u8]>,
        o: Option<&[u8]>,
        v: Option<&[u8]>,
    ) -> c_int {
        let func = "archive_read_set_format_option";
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, |r, a| {
            options::set_option(a, m, o, v, &mut |m, o, v| r.set_format_option(a, m, o, v))
        })
    }

    pub(crate) fn read_set_filter_option(
        &self,
        m: Option<&[u8]>,
        o: Option<&[u8]>,
        v: Option<&[u8]>,
    ) -> c_int {
        let func = "archive_read_set_filter_option";
        self.checked(READ_MAGIC, state::NEW, func, ARCHIVE_FATAL, || {
            options::set_option(&self.base, m, o, v, &mut |m, _, _| {
                read_set_options::set_filter_option(m)
            })
        })
    }

    pub(crate) fn read_set_option(
        &self,
        m: Option<&[u8]>,
        o: Option<&[u8]>,
        v: Option<&[u8]>,
    ) -> c_int {
        let func = "archive_read_set_option";
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, |r, a| {
            options::set_option(a, m, o, v, &mut |m, o, v| r.set_option(a, m, o, v))
        })
    }

    pub(crate) fn read_set_options(&self, opts: &[u8]) -> c_int {
        let func = "archive_read_set_options";
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, |r, a| {
            options::set_options(a, opts, &mut |m, o, v| r.set_option(a, m, o, v))
        })
    }

    pub(crate) fn read_add_passphrase(&self, passphrase: &[u8]) -> c_int {
        let func = "archive_read_add_passphrase";
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, |r, a| {
            match r.passphrases.add(passphrase) {
                Ok(()) => ARCHIVE_OK,
                Err(e) => a.raise(e),
            }
        })
    }

    pub(crate) fn read_set_passphrase_callback(
        &self,
        callback: Option<PassphraseCallback>,
    ) -> c_int {
        let func = "archive_read_set_passphrase_callback";
        self.read_checked(func, state::NEW, ARCHIVE_FATAL, |r, _| {
            r.passphrases.set_callback(callback);
            ARCHIVE_OK
        })
    }

    pub(crate) fn read_header_position(&self) -> i64 {
        let func = "archive_read_header_position";
        let fatal = i64::from(ARCHIVE_FATAL);
        self.checked(READ_MAGIC, state::ANY, func, fatal, || {
            self.header_position()
        })
    }
}

/// `ArchiveRead::extract_set_progress_callback`'s callback.
type Progress = Box<dyn FnMut(&Archive, &mut ArchiveEntry)>;

/// A handle that reads an archive: `archive_read_new`.
pub struct ArchiveRead {
    a: Archive,
    /// The handle's own entry (upstream's `a->entry`), which `next_header`
    /// reads into.
    entry: ArchiveEntry,
    /// The copy of the block `data_block` hands out.
    block: Vec<u8>,
    /// What `open_fd` was given, kept open while the handle may read it.
    fds: Vec<Box<dyn AsFd>>,
    /// The progress callback of `extract2`.
    progress: Option<Progress>,
}

/// The `archive_read_support_*` methods that register one filter or
/// format: `check` is the function name upstream's state check reports.
macro_rules! support {
    ($($method:ident: $check:literal => $how:ident($support:path);)*) => {$(
        #[doc = concat!("`archive_read_", stringify!($method), "`.")]
        pub fn $method(&mut self) -> Status {
            Status::from_code(self.a.h.$how($check, $support))
        }
    )*};
}

impl ArchiveRead {
    /// `archive_read_new`.
    pub fn new() -> Self {
        let h = read::new();
        // Like archive_entry_new2: the entry converts text with the
        // handle's conversions.
        let entry = ArchiveEntry(Box::new(Entry::new(Some(h.base.conv.clone()))));
        ArchiveRead {
            a: Archive { h },
            entry,
            block: Vec::new(),
            fds: Vec::new(),
            progress: None,
        }
    }

    support! {
        support_filter_bzip2: "archive_read_support_filter_bzip2"
            => read_support_filter(filter_bzip2::support);
        support_filter_compress: "archive_read_support_filter_compress"
            => read_support_filter(compress::support);
        support_filter_grzip: "__archive_read_register_bidder"
            => read_support_filter(grzip::support);
        support_filter_gzip: "archive_read_support_filter_gzip"
            => read_support_filter(gzip::support);
        support_filter_lrzip: "__archive_read_register_bidder"
            => read_support_filter(lrzip::support);
        support_filter_lz4: "archive_read_support_filter_lz4"
            => read_support_filter(filter_lz4::support);
        support_filter_lzip: "archive_read_support_filter_lzip"
            => read_support_filter(filter_xz::support_lzip);
        support_filter_lzma: "archive_read_support_filter_lzma"
            => read_support_filter(filter_xz::support_lzma);
        support_filter_lzop: "__archive_read_register_bidder"
            => read_support_filter(lzop::support);
        support_filter_rpm: "archive_read_support_filter_rpm"
            => read_support_filter(rpm::support);
        support_filter_uu: "archive_read_support_filter_uu"
            => read_support_filter(filter_uu::support);
        support_filter_xz: "archive_read_support_filter_xz"
            => read_support_filter(filter_xz::support_xz);
        support_filter_zstd: "archive_read_support_filter_zstd"
            => read_support_filter(filter_zstd::support);
        support_format_7zip: "archive_read_support_format_7zip"
            => read_support_format(sevenzip::support);
        support_format_ar: "archive_read_support_format_ar"
            => read_support_format(ar::support);
        support_format_cab: "archive_read_support_format_cab"
            => read_support_format(cab::support);
        support_format_cpio: "archive_read_support_format_cpio"
            => read_support_format(cpio::support);
        support_format_empty: "archive_read_support_format_empty"
            => read_support_format(empty::support);
        support_format_gnutar: "archive_read_support_format_gnutar"
            => read_support_format(tar::support);
        support_format_iso9660: "archive_read_support_format_iso9660"
            => read_support_format(iso9660::support);
        support_format_lha: "archive_read_support_format_lha"
            => read_support_format(lha::support);
        support_format_mtree: "archive_read_support_format_mtree"
            => read_support_format(mtree::support);
        support_format_rar: "archive_read_support_format_rar"
            => read_support_format(rar::support);
        support_format_rar5: "archive_read_support_format_rar5"
            => read_support_format(rar5::support);
        support_format_raw: "archive_read_support_format_raw"
            => read_support_format(raw::support);
        support_format_tar: "archive_read_support_format_tar"
            => read_support_format(tar::support);
        support_format_warc: "archive_read_support_format_warc"
            => read_support_format(warc::support);
        support_format_xar: "archive_read_support_format_xar"
            => read_support_format(xar::support);
        support_format_zip: "archive_read_support_format_zip"
            => read_support_format(zip::support);
        // Upstream checks the state under the name of the combined export.
        support_format_zip_streamable: "archive_read_support_format_zip"
            => read_support_format(zip::support_streamable);
        support_format_zip_seekable: "archive_read_support_format_zip_seekable"
            => read_support_format(zip::support_seekable);
    }

    /// `archive_read_support_filter_none`.
    pub fn support_filter_none(&mut self) -> Status {
        Status::from_code(self.a.h.read_support_filter_none())
    }

    /// `archive_read_support_filter_all`: every filter there is a reader
    /// for, external programs included.
    pub fn support_filter_all(&mut self) -> Status {
        Status::from_code(self.a.h.read_support_filter_all())
    }

    /// `archive_read_support_format_all`.
    pub fn support_format_all(&mut self) -> Status {
        Status::from_code(self.a.h.read_support_format_all())
    }

    /// `archive_read_support_filter_by_code`: an `ARCHIVE_FILTER_*` code.
    pub fn support_filter_by_code(&mut self, filter: c_int) -> Status {
        Status::from_code(self.a.h.read_support_filter_by_code(filter))
    }

    /// `archive_read_support_format_by_code`: an `ARCHIVE_FORMAT_*` code.
    pub fn support_format_by_code(&mut self, format: c_int) -> Status {
        Status::from_code(self.a.h.read_support_format_by_code(format))
    }

    /// `archive_read_support_filter_program`: decompresses with `cmd`.
    pub fn support_filter_program(&mut self, cmd: &[u8]) -> Status {
        self.support_filter_program_signature(cmd, &[])
    }

    /// `archive_read_support_filter_program_signature`: decompresses data
    /// that starts with `signature` with `cmd`.
    pub fn support_filter_program_signature(&mut self, cmd: &[u8], signature: &[u8]) -> Status {
        let cmd = Some(until_nul(cmd));
        Status::from_code(
            self.a
                .h
                .read_support_filter_program_signature(cmd, signature),
        )
    }

    /// `archive_read_set_format`: reads only the `ARCHIVE_FORMAT_*` format
    /// `format`, without bidding.
    pub fn set_format(&mut self, format: c_int) -> Status {
        Status::from_code(self.a.h.read_set_format(format))
    }

    /// `archive_read_append_filter`: decompresses with the
    /// `ARCHIVE_FILTER_*` filter `filter`, without bidding.
    pub fn append_filter(&mut self, filter: c_int) -> Status {
        Status::from_code(self.a.h.read_append_filter(filter))
    }

    /// `archive_read_append_filter_program`.
    pub fn append_filter_program(&mut self, cmd: &[u8]) -> Status {
        self.append_filter_program_signature(cmd, &[])
    }

    /// `archive_read_append_filter_program_signature`.
    pub fn append_filter_program_signature(&mut self, cmd: &[u8], signature: &[u8]) -> Status {
        let cmd = Some(until_nul(cmd));
        Status::from_code(
            self.a
                .h
                .read_append_filter_program_signature(cmd, signature),
        )
    }

    /// `archive_read_set_format_option`: `None` for a NULL argument.
    pub fn set_format_option(
        &mut self,
        module: Option<&[u8]>,
        option: Option<&[u8]>,
        value: Option<&[u8]>,
    ) -> Status {
        let [m, o, v] = [module, option, value].map(|s| s.map(until_nul));
        Status::from_code(self.a.h.read_set_format_option(m, o, v))
    }

    /// `archive_read_set_filter_option`.
    pub fn set_filter_option(
        &mut self,
        module: Option<&[u8]>,
        option: Option<&[u8]>,
        value: Option<&[u8]>,
    ) -> Status {
        let [m, o, v] = [module, option, value].map(|s| s.map(until_nul));
        Status::from_code(self.a.h.read_set_filter_option(m, o, v))
    }

    /// `archive_read_set_option`.
    pub fn set_option(
        &mut self,
        module: Option<&[u8]>,
        option: Option<&[u8]>,
        value: Option<&[u8]>,
    ) -> Status {
        let [m, o, v] = [module, option, value].map(|s| s.map(until_nul));
        Status::from_code(self.a.h.read_set_option(m, o, v))
    }

    /// `archive_read_set_options`: a comma-separated list of
    /// `module:option=value`.
    pub fn set_options(&mut self, options: &[u8]) -> Status {
        Status::from_code(self.a.h.read_set_options(until_nul(options)))
    }

    /// `archive_read_add_passphrase`: a passphrase to try on encrypted
    /// entries.
    pub fn add_passphrase(&mut self, passphrase: &[u8]) -> Status {
        Status::from_code(self.a.h.read_add_passphrase(until_nul(passphrase)))
    }

    /// `archive_read_set_passphrase_callback`: asked for a passphrase when
    /// those added don't work; `None` gives up.
    pub fn set_passphrase_callback(
        &mut self,
        callback: impl FnMut() -> Option<Vec<u8>> + 'static,
    ) -> Status {
        let callback: PassphraseCallback = Box::new(callback);
        Status::from_code(self.a.h.read_set_passphrase_callback(Some(callback)))
    }

    /// `archive_read_open_filename`: `None`, or an empty name, is standard
    /// input.
    pub fn open_filename(&mut self, filename: Option<&Path>, block_size: usize) -> Status {
        let name = filename.map(|p| until_nul(p.as_os_str().as_bytes()));
        let names = vec![name.filter(|n| !n.is_empty()).map(<[u8]>::to_vec)];
        Status::from_code(self.a.h.read_open_filenames(names, block_size))
    }

    /// `archive_read_open_fd`. The handle keeps `fd` (a `File`, `Stdin`,
    /// or an `Rc` or `Arc` the caller shares) until it is dropped; upstream
    /// leaves the descriptor open, and so does a shared owner.
    pub fn open_fd(&mut self, fd: impl AsFd + 'static, block_size: usize) -> Status {
        let raw = Fd(fd.as_fd().as_raw_fd());
        // Kept even if the open fails: a client may be reading it.
        self.fds.push(Box::new(fd));
        Status::from_code(self.a.h.read_open_fd(raw, block_size))
    }

    /// Sets opt-in processing budgets before opening the archive.
    /// See [`crate::ReadLimits`] for accounting and decoder coverage.
    pub fn set_limits(&mut self, limits: read::ReadLimits) -> Status {
        Status::from_code(self.h.read_checked(
            "archive_read_set_limits",
            state::NEW,
            ARCHIVE_FATAL,
            |r, a| r.set_limits(a, limits),
        ))
    }

    /// `archive_read_open_memory`: reads the archive in `data`.
    pub fn open_memory(&mut self, data: impl AsRef<[u8]> + 'static) -> Status {
        let size = data.as_ref().len();
        Status::from_code(self.a.h.read_open_memory(data, size))
    }

    /// `archive_read_next_header`: reads the next header into the handle's
    /// own entry, `entry()`. `Eof` at the end of the archive.
    pub fn next_header(&mut self) -> Status {
        Status::from_code(self.a.h.read_next_header2(&mut self.entry.0))
    }

    /// The entry `next_header` reads into (C's `*entryp`).
    pub fn entry(&mut self) -> &mut ArchiveEntry {
        &mut self.entry
    }

    /// `archive_read_next_header2`: reads the next header into `entry`.
    pub fn next_header2(&mut self, entry: &mut ArchiveEntry) -> Status {
        Status::from_code(self.a.h.read_next_header2(&mut entry.0))
    }

    /// `archive_read_data`: reads the entry's data into `buf`, with the
    /// holes of a sparse file as zeros. `Ok(0)` at the end of the data.
    pub fn data(&mut self, buf: &mut [u8]) -> Result<usize, Status> {
        Status::from_size(self.a.h.read_data(Some(&mut self.entry.0), buf))
    }

    /// `archive_read_data_block`: the next block of the entry's data and
    /// its offset in the entry. The block is empty unless the status is
    /// `Ok`; `Eof` comes with the offset of the end. The block is a copy,
    /// valid until the next call.
    pub fn data_block(&mut self) -> (Status, &[u8], i64) {
        let block = &mut self.block;
        block.clear();
        let a = &self.a.h.base;
        let r = self
            .a
            .h
            .read_data_block(Some(&mut self.entry.0), |d| match d {
                Data::Block { data, offset } => {
                    if block.try_reserve_exact(data.len()).is_err() {
                        a.state.set(state::FATAL);
                        return (
                            a.raise(Error::fatal(libc::ENOMEM, "No memory for archive data")),
                            offset,
                        );
                    }
                    block.extend_from_slice(data);
                    (ARCHIVE_OK, offset)
                }
                Data::Eof { offset } => (ARCHIVE_EOF, offset),
                Data::Warn { offset } => (ARCHIVE_WARN, offset),
            });
        let (code, offset) = r.unwrap_or_else(|code| (code, 0));
        (Status::from_code(code), &self.block, offset)
    }

    /// `archive_read_data_skip`: skips the rest of the entry's data.
    pub fn data_skip(&mut self) -> Status {
        Status::from_code(self.a.h.read_data_skip(Some(&mut self.entry.0)))
    }

    /// `archive_read_data_into_fd`: writes the rest of the entry's data to
    /// `fd`, seeking over holes if it can.
    pub fn data_into_fd(&mut self, fd: impl AsFd) -> Status {
        let fd = Fd(fd.as_fd().as_raw_fd());
        Status::from_code(self.a.h.read_data_into_fd(Some(&mut self.entry.0), fd))
    }

    /// `archive_read_extract2`: writes `entry` and the rest of its data to
    /// `dest`. To extract what `next_header` read, read it with
    /// `next_header2` into an entry of your own: the handle's own entry
    /// can't be lent to a call on the handle.
    pub fn extract2(&mut self, entry: &mut ArchiveEntry, dest: &mut ArchiveWriteDisk) -> Status {
        let header = self.a.h.read_extract2_header(&mut entry.0, &dest.h);
        let own = Some(&mut *self.entry.0);
        let a = &self.a;
        let mut progress = || {
            if let Some(progress) = &mut self.progress {
                progress(a, entry);
            }
        };
        Status::from_code(a.h.read_extract2_data(own, &dest.h, header, &mut progress))
    }

    /// `archive_read_extract_set_progress_callback`: `progress` runs after
    /// each block `extract2` writes, with this handle and the entry being
    /// extracted, which C's client data would point to.
    pub fn extract_set_progress_callback(
        &mut self,
        progress: impl FnMut(&Archive, &mut ArchiveEntry) + 'static,
    ) {
        self.progress = Some(Box::new(progress));
    }

    /// `archive_read_header_position`: the offset of the last header in
    /// the decompressed stream.
    pub fn header_position(&self) -> i64 {
        self.a.h.read_header_position()
    }

    /// `archive_read_close`.
    pub fn close(&mut self) -> Status {
        Status::from_code(self.a.h.close())
    }
}

impl Default for ArchiveRead {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for ArchiveRead {
    type Target = Archive;

    fn deref(&self) -> &Archive {
        &self.a
    }
}

impl DerefMut for ArchiveRead {
    fn deref_mut(&mut self) -> &mut Archive {
        &mut self.a
    }
}

#[cfg(test)]
mod resource_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read as _, Seek, Write};
    use std::rc::Rc;

    fn reader() -> ArchiveRead {
        let mut a = ArchiveRead::new();
        assert_eq!(a.support_filter_all(), Status::Ok);
        assert_eq!(a.support_format_empty(), Status::Ok);
        assert_eq!(a.support_format_raw(), Status::Ok);
        a
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        out.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
        out.extend(crc32fast::hash(data).to_le_bytes());
        out.extend((data.len() as u32).to_le_bytes());
        out
    }

    fn error(a: &Archive) -> String {
        let msg = a.error_string();
        msg.map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned())
    }

    fn temp_file(tag: &str, data: &[u8]) -> (std::path::PathBuf, File) {
        let name = format!("api-read-{tag}-{}", std::process::id());
        let path = std::env::temp_dir().join(name);
        let mut f = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.write_all(data).unwrap();
        f.rewind().unwrap();
        (path, f)
    }

    #[test]
    fn reads_a_compressed_stream_as_one_raw_entry() {
        let mut a = reader();
        assert_eq!(a.open_memory(gzip(b"hello, world\n")), Status::Ok);
        assert_eq!(a.next_header(), Status::Ok);
        assert_eq!(a.entry().pathname(), Some(b"data".as_slice()));
        assert_eq!(a.header_position(), 0);
        assert_eq!(a.format_name().as_deref(), Some(b"raw".as_slice()));
        assert_eq!(a.filter_count(), 2);
        assert_eq!(a.filter_name(0).as_deref(), Some(b"gzip".as_slice()));
        assert_eq!(a.filter_code(0), 1);
        let mut buf = [0; 64];
        assert_eq!(a.data(&mut buf), Ok(13));
        assert_eq!(&buf[..13], b"hello, world\n");
        assert_eq!(a.data(&mut buf), Ok(0));
        assert_eq!(a.filter_bytes(0), 13);
        assert_eq!(a.next_header(), Status::Eof);
        assert_eq!(a.file_count(), 1);
        assert_eq!(a.close(), Status::Ok);
    }

    #[test]
    fn data_comes_in_blocks_with_offsets() {
        let mut a = reader();
        assert_eq!(a.open_memory(b"0123456789".as_slice()), Status::Ok);
        let mut entry = ArchiveEntry::new();
        assert_eq!(a.next_header2(&mut entry), Status::Ok);
        assert_eq!(entry.pathname(), Some(b"data".as_slice()));
        assert_eq!(a.data_block(), (Status::Ok, b"0123456789".as_slice(), 0));
        assert_eq!(a.data_block(), (Status::Eof, b"".as_slice(), 10));
        assert_eq!(a.next_header2(&mut entry), Status::Eof);
    }

    #[test]
    fn an_empty_input_has_no_entries() {
        let mut a = reader();
        assert_eq!(a.open_memory(Vec::new()), Status::Ok);
        assert_eq!(a.next_header(), Status::Eof);
        assert_eq!(a.format_name().as_deref(), Some(b"Empty file".as_slice()));
    }

    #[test]
    fn data_into_fd_and_skip() {
        let (path, out) = temp_file("out", b"");
        let mut a = reader();
        assert_eq!(a.open_memory(gzip(b"copied")), Status::Ok);
        assert_eq!(a.next_header(), Status::Ok);
        assert_eq!(a.data_into_fd(&out), Status::Ok);
        assert_eq!(std::fs::read(&path).unwrap(), b"copied");
        std::fs::remove_file(path).unwrap();

        let mut a = reader();
        assert_eq!(a.open_memory(b"skipped".as_slice()), Status::Ok);
        assert_eq!(a.next_header(), Status::Ok);
        assert_eq!(a.data_skip(), Status::Ok);
        assert_eq!(a.next_header(), Status::Eof);
    }

    #[test]
    fn opens_files_and_descriptors() {
        let (path, f) = temp_file("in", &gzip(b"on disk"));
        let mut a = reader();
        assert_eq!(a.open_filename(Some(&path), 10240), Status::Ok);
        assert_eq!(a.next_header(), Status::Ok);
        let mut buf = [0; 16];
        assert_eq!(a.data(&mut buf), Ok(7));
        drop(a);

        // A shared descriptor stays open for its other owner.
        let f = Rc::new(f);
        let mut a = reader();
        assert_eq!(a.open_fd(Rc::clone(&f), 10240), Status::Ok);
        assert_eq!(a.next_header(), Status::Ok);
        assert_eq!(a.data(&mut buf), Ok(7));
        drop(a);
        (&*f).rewind().unwrap();
        let mut back = Vec::new();
        (&*f).read_to_end(&mut back).unwrap();
        assert_eq!(back, gzip(b"on disk"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_missing_file_fails_to_open() {
        let mut a = reader();
        let path = Path::new("/nonexistent/api-read-test");
        assert_eq!(a.open_filename(Some(path), 10240), Status::Fatal);
        assert_eq!(a.errno(), libc::ENOENT);
        assert_eq!(error(&a), "Failed to open '/nonexistent/api-read-test'");
        a.clear_error();
        assert_eq!((a.errno(), a.error_string().is_none()), (0, true));
    }

    #[test]
    fn calls_follow_the_state_machine() {
        let mut a = reader();
        assert_eq!(a.next_header(), Status::Fatal);
        assert_eq!(
            error(&a),
            "INTERNAL ERROR: Function 'archive_read_next_header' invoked with archive structure in state 'new', should be in state 'header/data/data_recovery'"
        );
        // A fatal handle keeps its first error.
        assert_eq!(a.support_format_tar(), Status::Fatal);
        assert!(error(&a).contains("archive_read_next_header"));

        let mut a = reader();
        assert_eq!(a.open_memory(b"x".as_slice()), Status::Ok);
        assert_eq!(a.support_format_zip(), Status::Fatal);
        assert_eq!(
            error(&a),
            "INTERNAL ERROR: Function 'archive_read_support_format_zip' invoked with archive structure in state 'header', should be in state 'new'"
        );
    }

    #[test]
    fn options_and_passphrases() {
        let mut a = ArchiveRead::new();
        assert_eq!(a.support_format_zip(), Status::Ok);
        assert_eq!(a.add_passphrase(b""), Status::Failed);
        assert_eq!(error(&a), "Empty passphrase is unacceptable");
        assert_eq!(a.add_passphrase(b"secret"), Status::Ok);
        assert_eq!(a.set_passphrase_callback(|| None), Status::Ok);
        let module = Some(b"zip".as_slice());
        let hdrcharset = Some(b"hdrcharset".as_slice());
        assert_eq!(
            a.set_format_option(module, hdrcharset, Some(b"UTF-8")),
            Status::Ok
        );
        assert_eq!(
            a.set_option(None, Some(b"nonsense"), Some(b"1")),
            Status::Failed
        );
        assert_eq!(error(&a), "Undefined option: `nonsense=1'");
        assert_eq!(a.set_options(b"zip:ignorecrc32"), Status::Ok);
    }
}
