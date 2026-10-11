//! `archive_write_*`: writing an archive.

use super::{Archive, ArchiveEntry, Status};
use crate::archive::{
    ARCHIVE_ERRNO_MISC, ARCHIVE_FAILED, ARCHIVE_FATAL, ARCHIVE_OK, ARCHIVE_WARN, Base, Handle,
    Kind, WRITE_MAGIC, state,
};
use crate::options;
use crate::read::filter_code;
use crate::string::until_nul;
use crate::util::Error;
use crate::write::format::{
    ar::Ar, cpio::Cpio, iso9660::Iso9660, mtree::Mtree, raw::Raw, sevenzip::SevenZip, shar::Shar,
    tar::Tar, warc::Warc, xar::Xar, zip::Zip,
};
use crate::write::{Format, Write, filter};
use std::cell::RefCell;
use std::ffi::c_int;
use std::ops::{Deref, DerefMut};

/// An `archive_write_set_format_X` function: the name its state check
/// reports, and the format it sets.
#[derive(Clone, Copy)]
pub(crate) struct SetFormat(&'static str, fn() -> Box<dyn Format>);

macro_rules! set_formats {
    ($($name:ident: $func:literal => $format:expr;)*) => {
        impl SetFormat {$(
            pub(crate) const $name: SetFormat = SetFormat($func, || Box::new($format));
        )*}
    };
}

set_formats! {
    SEVENZIP: "archive_write_set_format_7zip" => SevenZip::default();
    AR_BSD: "archive_write_set_format_ar_bsd" => Ar::new(true);
    AR_SVR4: "archive_write_set_format_ar_svr4" => Ar::new(false);
    CPIO_BIN: "archive_write_set_format_cpio_binary" => Cpio::new(0x10002);
    CPIO_NEWC: "archive_write_set_format_cpio_newc" => Cpio::new(0x10004);
    // archive_write_set_format_cpio is this one.
    CPIO_ODC: "archive_write_set_format_cpio_odc" => Cpio::new(0x10001);
    CPIO_PWB: "archive_write_set_format_cpio_binary" => Cpio::new(0x10006);
    GNUTAR: "archive_write_set_format_gnutar" => Tar::new(0x30004);
    ISO9660: "archive_write_set_format_iso9660" => Iso9660::default();
    MTREE: "archive_write_set_format_mtree" => Mtree::new(false);
    MTREE_CLASSIC: "archive_write_set_format_mtree_classic" => Mtree::new(true);
    PAX: "archive_write_set_format_pax" => Tar::new(0x30002);
    PAX_RESTRICTED: "archive_write_set_format_pax_restricted" => Tar::new(0x30003);
    RAW: "archive_write_set_format_raw" => Raw::default();
    SHAR: "archive_write_set_format_shar" => Shar::new(false);
    SHAR_DUMP: "archive_write_set_format_shar" => Shar::new(true);
    USTAR: "archive_write_set_format_ustar" => Tar::new(0x30001);
    V7TAR: "archive_write_set_format_v7tar" => Tar::new(0x30000);
    WARC: "archive_write_set_format_warc" => Warc::default();
    XAR: "archive_write_set_format_xar" => Xar::default();
    ZIP: "archive_write_set_format_zip" => Zip::default();
}

/// `archive_write_set_format`'s table.
const FORMAT_CODES: [(c_int, SetFormat); 20] = [
    (0xe0000, SetFormat::SEVENZIP),
    (0x10000, SetFormat::CPIO_ODC),
    (0x10002, SetFormat::CPIO_BIN),
    (0x10006, SetFormat::CPIO_PWB),
    (0x10001, SetFormat::CPIO_ODC),
    (0x10004, SetFormat::CPIO_NEWC),
    (0x40000, SetFormat::ISO9660),
    (0x80000, SetFormat::MTREE),
    (0x90000, SetFormat::RAW),
    (0x20000, SetFormat::SHAR),
    (0x20001, SetFormat::SHAR),
    (0x20002, SetFormat::SHAR_DUMP),
    (0x30000, SetFormat::PAX_RESTRICTED),
    (0x30004, SetFormat::GNUTAR),
    (0x30002, SetFormat::PAX),
    (0x30003, SetFormat::PAX_RESTRICTED),
    (0x30001, SetFormat::USTAR),
    (0xf0000, SetFormat::WARC),
    (0xa0000, SetFormat::XAR),
    (0x50000, SetFormat::ZIP),
];

/// `archive_write_set_format_by_name`'s table.
const FORMAT_NAMES: [(&[u8], SetFormat); 31] = [
    (b"7zip", SetFormat::SEVENZIP),
    (b"ar", SetFormat::AR_BSD),
    (b"arbsd", SetFormat::AR_BSD),
    (b"argnu", SetFormat::AR_SVR4),
    (b"arsvr4", SetFormat::AR_SVR4),
    (b"bin", SetFormat::CPIO_BIN),
    (b"bsdtar", SetFormat::PAX_RESTRICTED),
    (b"cd9660", SetFormat::ISO9660),
    (b"cpio", SetFormat::CPIO_ODC),
    (b"gnutar", SetFormat::GNUTAR),
    (b"iso", SetFormat::ISO9660),
    (b"iso9660", SetFormat::ISO9660),
    (b"mtree", SetFormat::MTREE),
    (b"mtree-classic", SetFormat::MTREE_CLASSIC),
    (b"newc", SetFormat::CPIO_NEWC),
    (b"odc", SetFormat::CPIO_ODC),
    (b"oldtar", SetFormat::V7TAR),
    (b"pax", SetFormat::PAX),
    (b"paxr", SetFormat::PAX_RESTRICTED),
    (b"posix", SetFormat::PAX),
    (b"pwb", SetFormat::CPIO_PWB),
    (b"raw", SetFormat::RAW),
    (b"rpax", SetFormat::PAX_RESTRICTED),
    (b"shar", SetFormat::SHAR),
    (b"shardump", SetFormat::SHAR_DUMP),
    (b"ustar", SetFormat::USTAR),
    (b"v7tar", SetFormat::V7TAR),
    (b"v7", SetFormat::V7TAR),
    (b"warc", SetFormat::WARC),
    (b"xar", SetFormat::XAR),
    (b"zip", SetFormat::ZIP),
];

/// An `archive_write_add_filter_X` function, other than
/// `archive_write_add_filter_none`: the name its state check reports, and
/// the code of the filter it adds.
#[derive(Clone, Copy)]
pub(crate) struct AddFilter(&'static str, c_int);

macro_rules! add_filters {
    ($($name:ident: $func:literal => $code:expr;)*) => {
        impl AddFilter {$(
            pub(crate) const $name: AddFilter = AddFilter($func, $code);
        )*}
    };
}

add_filters! {
    B64ENCODE: "archive_write_add_filter_b64encode" => 15;
    BZIP2: "archive_write_add_filter_bzip2" => filter_code::BZIP2;
    COMPRESS: "archive_write_add_filter_compress" => filter_code::COMPRESS;
    GRZIP: "archive_write_add_filter_grzip" => filter_code::GRZIP;
    GZIP: "archive_write_add_filter_gzip" => filter_code::GZIP;
    LRZIP: "archive_write_add_filter_lrzip" => filter_code::LRZIP;
    LZ4: "archive_write_add_filter_lz4" => filter_code::LZ4;
    LZIP: "archive_write_add_filter_lzip" => filter_code::LZIP;
    LZMA: "archive_write_add_filter_lzma" => filter_code::LZMA;
    LZOP: "archive_write_add_filter_lzop" => filter_code::LZOP;
    UUENCODE: "archive_write_add_filter_uuencode" => filter_code::UU;
    XZ: "archive_write_add_filter_xz" => filter_code::XZ;
    ZSTD: "archive_write_add_filter_zstd" => filter_code::ZSTD;
}

/// `archive_write_add_filter`'s table, but for `ARCHIVE_FILTER_NONE`.
const FILTER_CODES: [AddFilter; 12] = [
    AddFilter::GZIP,
    AddFilter::BZIP2,
    AddFilter::COMPRESS,
    AddFilter::GRZIP,
    AddFilter::LRZIP,
    AddFilter::LZ4,
    AddFilter::LZIP,
    AddFilter::LZMA,
    AddFilter::LZOP,
    AddFilter::UUENCODE,
    AddFilter::XZ,
    AddFilter::ZSTD,
];

/// `archive_write_add_filter_by_name`'s table.
const FILTER_NAMES: [(&[u8], AddFilter); 13] = [
    (b"b64encode", AddFilter::B64ENCODE),
    (b"bzip2", AddFilter::BZIP2),
    (b"compress", AddFilter::COMPRESS),
    (b"grzip", AddFilter::GRZIP),
    (b"gzip", AddFilter::GZIP),
    (b"lrzip", AddFilter::LRZIP),
    (b"lz4", AddFilter::LZ4),
    (b"lzip", AddFilter::LZIP),
    (b"lzma", AddFilter::LZMA),
    (b"lzop", AddFilter::LZOP),
    (b"uuencode", AddFilter::UUENCODE),
    (b"xz", AddFilter::XZ),
    (b"zstd", AddFilter::ZSTD),
];

impl Handle {
    /// `f` on the write state, after `archive_check_magic(a,
    /// ARCHIVE_WRITE_MAGIC, states, func)`.
    pub(crate) fn write_checked<T: Copy>(
        &self,
        func: &str,
        states: u32,
        fallback: T,
        f: impl FnOnce(&Base, &mut Write) -> T,
    ) -> T {
        self.checked(WRITE_MAGIC, states, func, fallback, || match &self.kind {
            Kind::Write(w) => w
                .try_borrow_mut()
                .map_or(fallback, |mut w| f(&self.base, &mut w)),
            _ => fallback,
        })
    }

    pub(crate) fn write_set_bytes_per_block(&self, n: c_int) -> c_int {
        let func = "archive_write_set_bytes_per_block";
        self.write_checked(func, state::NEW, ARCHIVE_FATAL, |_, w| {
            if n >= 0 {
                w.bytes_per_block = n;
            }
            ARCHIVE_OK
        })
    }

    pub(crate) fn write_set_bytes_in_last_block(&self, n: c_int) -> c_int {
        let func = "archive_write_set_bytes_in_last_block";
        self.write_checked(func, state::ANY, ARCHIVE_FATAL, |_, w| {
            w.bytes_in_last_block = n;
            ARCHIVE_OK
        })
    }

    /// An `archive_write_set_format_X`: replaces the format to write.
    pub(crate) fn write_set_format_x(&self, SetFormat(func, format): SetFormat) -> c_int {
        self.write_checked(func, state::NEW, ARCHIVE_FATAL, |a, w| {
            w.set_format(a, format())
        })
    }

    /// `archive_write_set_format`: the format of an `ARCHIVE_FORMAT_*`
    /// code.
    pub(crate) fn write_set_format(&self, code: c_int) -> c_int {
        match FORMAT_CODES.iter().find(|(c, _)| *c == code) {
            Some(&(_, set)) => self.write_set_format_x(set),
            None => self
                .base
                .raise(Error::fatal(libc::EINVAL, "No such format")),
        }
    }

    pub(crate) fn write_set_format_by_name(&self, name: &[u8]) -> c_int {
        match FORMAT_NAMES.iter().find(|(n, _)| *n == name) {
            Some(&(_, set)) => self.write_set_format_x(set),
            None => self.no_such(b"No such format '", name),
        }
    }

    /// `archive_write_set_format_filter_by_ext_def`: the format and filter
    /// the suffix of `name`, or failing that of `default`, stands for, as
    /// upstream's table has them. `archive_write_set_format_filter_by_ext`
    /// has no default.
    pub(crate) fn write_set_format_filter_by_ext(
        &self,
        name: Option<&[u8]>,
        default: Option<&[u8]>,
    ) -> c_int {
        use filter_code::{BZIP2, GZIP, NONE, XZ, ZSTD};
        const EXTENSIONS: [(&[u8], SetFormat, c_int); 13] = [
            (b".7z", SetFormat::SEVENZIP, NONE),
            (b".zip", SetFormat::ZIP, NONE),
            (b".jar", SetFormat::ZIP, NONE),
            (b".cpio", SetFormat::CPIO_ODC, NONE),
            (b".iso", SetFormat::ISO9660, NONE),
            (b".a", SetFormat::AR_SVR4, NONE),
            (b".ar", SetFormat::AR_SVR4, NONE),
            (b".tar", SetFormat::PAX_RESTRICTED, NONE),
            (b".tgz", SetFormat::PAX_RESTRICTED, GZIP),
            (b".tar.gz", SetFormat::PAX_RESTRICTED, GZIP),
            (b".tar.bz2", SetFormat::PAX_RESTRICTED, BZIP2),
            (b".tar.xz", SetFormat::PAX_RESTRICTED, XZ),
            (b".tar.zst", SetFormat::PAX_RESTRICTED, ZSTD),
        ];
        let by_ext = |name: Option<&[u8]>| {
            let name = name?;
            EXTENSIONS.iter().find(|(s, ..)| name.ends_with(s))
        };
        match by_ext(name).or_else(|| by_ext(default)) {
            Some(&(_, set, filter)) => match self.write_set_format_x(set) {
                ARCHIVE_OK => self.write_add_filter(filter),
                r => r,
            },
            None => self.no_such(b"No such format '", name.unwrap_or_default()),
        }
    }

    /// The failure of a lookup by name: upstream makes the handle fatal.
    fn no_such(&self, what: &[u8], name: &[u8]) -> c_int {
        self.base.state.set(state::FATAL);
        let msg = [what, name, b"'"].concat();
        self.base.raise(Error::fatal(libc::EINVAL, msg))
    }

    /// An `archive_write_add_filter_X`: adds its filter after those added
    /// before.
    pub(crate) fn write_add_filter_x(&self, AddFilter(func, code): AddFilter) -> c_int {
        self.write_checked(func, state::NEW, ARCHIVE_FATAL, |a, w| {
            let filter = match filter::by_code(code) {
                Ok(filter) => filter,
                Err(e) => return a.raise(e),
            };
            let r = match code {
                // These always use an external program, so they return
                // "warn" to inform of the fact.
                filter_code::LRZIP | filter_code::LZOP | filter_code::GRZIP => {
                    let name = filter.name().to_string_lossy();
                    let msg = format!("Using external {name} program for {name} compression");
                    a.set_error(ARCHIVE_ERRNO_MISC, Some(msg.as_bytes()));
                    ARCHIVE_WARN
                }
                _ => ARCHIVE_OK,
            };
            w.add_filter(filter);
            r
        })
    }

    /// `archive_write_add_filter`: the filter of an `ARCHIVE_FILTER_*`
    /// code.
    pub(crate) fn write_add_filter(&self, code: c_int) -> c_int {
        if code == filter_code::NONE {
            // archive_write_add_filter_none does nothing.
            return ARCHIVE_OK;
        }
        match FILTER_CODES.iter().find(|add| add.1 == code) {
            Some(&add) => self.write_add_filter_x(add),
            None => self
                .base
                .raise(Error::fatal(libc::EINVAL, "No such filter")),
        }
    }

    pub(crate) fn write_add_filter_by_name(&self, name: &[u8]) -> c_int {
        match FILTER_NAMES.iter().find(|(n, _)| *n == name) {
            Some(&(_, add)) => self.write_add_filter_x(add),
            None => self.no_such(b"No such filter '", name),
        }
    }

    /// `archive_write_add_filter_program`. A NULL command crashes upstream;
    /// it fails here.
    pub(crate) fn write_add_filter_program(&self, cmd: Option<&[u8]>) -> c_int {
        let func = "archive_write_add_filter_program";
        self.write_checked(func, state::NEW, ARCHIVE_FATAL, |a, w| {
            match cmd.map(filter::program) {
                Some(Ok(f)) => w.add_filter(f),
                Some(Err(e)) => a.raise(e),
                None => ARCHIVE_FATAL,
            }
        })
    }

    pub(crate) fn write_set_format_option(
        &self,
        m: Option<&[u8]>,
        o: Option<&[u8]>,
        v: Option<&[u8]>,
    ) -> c_int {
        let func = "archive_write_set_format_option";
        self.write_checked(func, state::NEW, ARCHIVE_FATAL, |a, w| {
            options::set_option(a, m, o, v, &mut |m, o, v| w.option(a, m, o, v, true, false))
        })
    }

    pub(crate) fn write_set_filter_option(
        &self,
        m: Option<&[u8]>,
        o: Option<&[u8]>,
        v: Option<&[u8]>,
    ) -> c_int {
        let func = "archive_write_set_filter_option";
        self.write_checked(func, state::NEW, ARCHIVE_FATAL, |a, w| {
            options::set_option(a, m, o, v, &mut |m, o, v| w.option(a, m, o, v, false, true))
        })
    }

    pub(crate) fn write_set_option(
        &self,
        m: Option<&[u8]>,
        o: Option<&[u8]>,
        v: Option<&[u8]>,
    ) -> c_int {
        let func = "archive_write_set_option";
        self.write_checked(func, state::NEW, ARCHIVE_FATAL, |a, w| {
            options::set_option(a, m, o, v, &mut |m, o, v| w.option(a, m, o, v, true, true))
        })
    }

    pub(crate) fn write_set_options(&self, opts: &[u8]) -> c_int {
        let func = "archive_write_set_options";
        self.write_checked(func, state::NEW, ARCHIVE_FATAL, |a, w| {
            options::set_options(a, opts, &mut |m, o, v| w.option(a, m, o, v, true, true))
        })
    }

    pub(crate) fn write_set_passphrase(&self, p: Option<&[u8]>) -> c_int {
        let func = "archive_write_set_passphrase";
        self.write_checked(func, state::NEW, ARCHIVE_FATAL, |a, w| match p {
            Some(p) if !p.is_empty() => {
                w.passphrase = Some(p.to_vec());
                ARCHIVE_OK
            }
            _ => a.raise(Error::new(
                ARCHIVE_FAILED,
                ARCHIVE_ERRNO_MISC,
                "Empty passphrase is unacceptable",
            )),
        })
    }

    pub(crate) fn write_set_passphrase_callback(
        &self,
        callback: Option<Box<dyn FnMut() -> Option<Vec<u8>>>>,
    ) -> c_int {
        let func = "archive_write_set_passphrase_callback";
        self.write_checked(func, state::NEW, ARCHIVE_FATAL, |_, w| {
            w.passphrase_callback = callback;
            ARCHIVE_OK
        })
    }
}

/// `archive_write_new`.
pub(crate) fn new() -> Handle {
    Handle {
        base: Base::new(WRITE_MAGIC),
        kind: Kind::Write(RefCell::new(Write::default())),
    }
}

/// A handle that writes an archive: `archive_write_new`.
pub struct ArchiveWrite {
    a: Archive,
}

/// The `archive_write_set_format_X` methods.
macro_rules! set_format {
    ($($method:ident => $set:ident;)*) => {$(
        #[doc = concat!("`archive_write_", stringify!($method), "`.")]
        pub fn $method(&mut self) -> Status {
            Status::from_code(self.a.h.write_set_format_x(SetFormat::$set))
        }
    )*};
}

/// The `archive_write_add_filter_X` methods.
macro_rules! add_filter {
    ($($method:ident => $add:ident;)*) => {$(
        #[doc = concat!("`archive_write_", stringify!($method), "`.")]
        pub fn $method(&mut self) -> Status {
            Status::from_code(self.a.h.write_add_filter_x(AddFilter::$add))
        }
    )*};
}

impl ArchiveWrite {
    /// `archive_write_new`.
    pub fn new() -> Self {
        ArchiveWrite {
            a: Archive { h: new() },
        }
    }

    /// `archive_write_set_bytes_per_block`: the size of the writes to the
    /// output; 0 writes as soon as there is data.
    pub fn set_bytes_per_block(&mut self, n: c_int) -> Status {
        Status::from_code(self.a.h.write_set_bytes_per_block(n))
    }

    /// `archive_write_set_bytes_in_last_block`: pads the last block to a
    /// multiple of `n`.
    pub fn set_bytes_in_last_block(&mut self, n: c_int) -> Status {
        Status::from_code(self.a.h.write_set_bytes_in_last_block(n))
    }

    /// `archive_write_set_format`: the format of the `ARCHIVE_FORMAT_*`
    /// code `code`.
    pub fn set_format(&mut self, code: c_int) -> Status {
        Status::from_code(self.a.h.write_set_format(code))
    }

    /// `archive_write_set_format_by_name`: "ustar", "zip" and so on.
    pub fn set_format_by_name(&mut self, name: &[u8]) -> Status {
        Status::from_code(self.a.h.write_set_format_by_name(until_nul(name)))
    }

    /// `archive_write_set_format_filter_by_ext`: the format and filter the
    /// suffix of `filename` stands for (".tar.gz" and so on).
    pub fn set_format_filter_by_ext(&mut self, filename: &[u8]) -> Status {
        let name = Some(until_nul(filename));
        Status::from_code(self.a.h.write_set_format_filter_by_ext(name, None))
    }

    /// `archive_write_set_format_filter_by_ext_def`: as
    /// `set_format_filter_by_ext`, trying `default` if `filename`'s suffix
    /// stands for nothing.
    pub fn set_format_filter_by_ext_def(&mut self, filename: &[u8], default: &[u8]) -> Status {
        let [name, default] = [filename, default].map(|s| Some(until_nul(s)));
        Status::from_code(self.a.h.write_set_format_filter_by_ext(name, default))
    }

    set_format! {
        set_format_7zip => SEVENZIP;
        set_format_ar_bsd => AR_BSD;
        set_format_ar_svr4 => AR_SVR4;
        set_format_cpio => CPIO_ODC;
        set_format_cpio_bin => CPIO_BIN;
        set_format_cpio_newc => CPIO_NEWC;
        set_format_cpio_odc => CPIO_ODC;
        set_format_cpio_pwb => CPIO_PWB;
        set_format_gnutar => GNUTAR;
        set_format_iso9660 => ISO9660;
        set_format_mtree => MTREE;
        set_format_mtree_classic => MTREE_CLASSIC;
        set_format_pax => PAX;
        set_format_pax_restricted => PAX_RESTRICTED;
        set_format_raw => RAW;
        set_format_shar => SHAR;
        set_format_shar_dump => SHAR_DUMP;
        set_format_ustar => USTAR;
        set_format_v7tar => V7TAR;
        set_format_warc => WARC;
        set_format_xar => XAR;
        set_format_zip => ZIP;
    }

    /// `archive_write_add_filter`: the filter of the `ARCHIVE_FILTER_*`
    /// code `code`.
    pub fn add_filter(&mut self, code: c_int) -> Status {
        Status::from_code(self.a.h.write_add_filter(code))
    }

    /// `archive_write_add_filter_by_name`: "gzip", "xz" and so on.
    pub fn add_filter_by_name(&mut self, name: &[u8]) -> Status {
        Status::from_code(self.a.h.write_add_filter_by_name(until_nul(name)))
    }

    /// `archive_write_add_filter_program`: compresses with `cmd`.
    pub fn add_filter_program(&mut self, cmd: &[u8]) -> Status {
        Status::from_code(self.a.h.write_add_filter_program(Some(until_nul(cmd))))
    }

    /// `archive_write_add_filter_none`: does nothing.
    pub fn add_filter_none(&mut self) -> Status {
        Status::Ok
    }

    add_filter! {
        add_filter_b64encode => B64ENCODE;
        add_filter_bzip2 => BZIP2;
        add_filter_compress => COMPRESS;
        add_filter_grzip => GRZIP;
        add_filter_gzip => GZIP;
        add_filter_lrzip => LRZIP;
        add_filter_lz4 => LZ4;
        add_filter_lzip => LZIP;
        add_filter_lzma => LZMA;
        add_filter_lzop => LZOP;
        add_filter_uuencode => UUENCODE;
        add_filter_xz => XZ;
        add_filter_zstd => ZSTD;
    }

    /// `archive_write_set_format_option`: `None` for a NULL argument.
    pub fn set_format_option(
        &mut self,
        module: Option<&[u8]>,
        option: Option<&[u8]>,
        value: Option<&[u8]>,
    ) -> Status {
        let [m, o, v] = [module, option, value].map(|s| s.map(until_nul));
        Status::from_code(self.a.h.write_set_format_option(m, o, v))
    }

    /// `archive_write_set_filter_option`.
    pub fn set_filter_option(
        &mut self,
        module: Option<&[u8]>,
        option: Option<&[u8]>,
        value: Option<&[u8]>,
    ) -> Status {
        let [m, o, v] = [module, option, value].map(|s| s.map(until_nul));
        Status::from_code(self.a.h.write_set_filter_option(m, o, v))
    }

    /// `archive_write_set_option`.
    pub fn set_option(
        &mut self,
        module: Option<&[u8]>,
        option: Option<&[u8]>,
        value: Option<&[u8]>,
    ) -> Status {
        let [m, o, v] = [module, option, value].map(|s| s.map(until_nul));
        Status::from_code(self.a.h.write_set_option(m, o, v))
    }

    /// `archive_write_set_options`: a comma-separated list of
    /// `module:option=value`.
    pub fn set_options(&mut self, options: &[u8]) -> Status {
        Status::from_code(self.a.h.write_set_options(until_nul(options)))
    }

    /// `archive_write_set_passphrase`: the passphrase of a format that
    /// encrypts.
    pub fn set_passphrase(&mut self, passphrase: &[u8]) -> Status {
        let p = Some(until_nul(passphrase));
        Status::from_code(self.a.h.write_set_passphrase(p))
    }

    /// `archive_write_set_passphrase_callback`: asked for the passphrase
    /// when none was set and the format needs one.
    pub fn set_passphrase_callback(
        &mut self,
        callback: impl FnMut() -> Option<Vec<u8>> + 'static,
    ) -> Status {
        let callback = Some(Box::new(callback) as Box<dyn FnMut() -> Option<Vec<u8>>>);
        Status::from_code(self.a.h.write_set_passphrase_callback(callback))
    }

    /// `archive_write_header`.
    pub fn header(&mut self, entry: &mut ArchiveEntry) -> Status {
        Status::from_code(self.a.h.write_header(&mut entry.0))
    }

    /// `archive_write_data`: the entry's data, after its header.
    pub fn data(&mut self, buf: &[u8]) -> Result<usize, Status> {
        Status::from_size(self.a.h.write_data(buf))
    }

    /// `archive_write_finish_entry`.
    pub fn finish_entry(&mut self) -> Status {
        Status::from_code(self.a.h.write_finish_entry())
    }

    /// `archive_write_close`: writes the end of the archive and flushes it.
    pub fn close(&mut self) -> Status {
        Status::from_code(self.a.h.close())
    }
}

impl Default for ArchiveWrite {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for ArchiveWrite {
    type Target = Archive;

    fn deref(&self) -> &Archive {
        &self.a
    }
}

impl DerefMut for ArchiveWrite {
    fn deref_mut(&mut self) -> &mut Archive {
        &mut self.a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(a: &Archive) -> String {
        let msg = a.error_string();
        msg.map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned())
    }

    #[test]
    fn setters_check_the_state() {
        let mut a = ArchiveWrite::new();
        assert_eq!(a.set_bytes_per_block(10240), Status::Ok);
        assert_eq!(a.set_bytes_in_last_block(1), Status::Ok);
        assert_eq!(a.header(&mut ArchiveEntry::new()), Status::Fatal);
        assert_eq!(a.set_bytes_per_block(512), Status::Fatal);
    }

    #[test]
    fn formats_by_setter_code_name_and_extension() {
        let mut a = ArchiveWrite::new();
        assert_eq!(a.set_format_pax_restricted(), Status::Ok);
        assert_eq!(a.format(), 0x30003);
        assert_eq!(a.set_format(0x10000), Status::Ok);
        assert_eq!(a.format_name().as_deref(), Some(b"POSIX cpio".as_slice()));
        assert_eq!(a.set_format_by_name(b"zip"), Status::Ok);
        assert_eq!(a.format(), 0x50000);
        assert_eq!(a.set_format_filter_by_ext(b"x.tar.xz"), Status::Ok);
        assert_eq!((a.format(), a.filter_code(0)), (0x30003, 6));
        assert_eq!(a.set_format(0x70000), Status::Fatal);
        assert_eq!(error(&a), "No such format");
        assert_eq!(a.set_format_ustar(), Status::Ok);
        assert_eq!(a.set_format_by_name(b"tarball"), Status::Fatal);
        assert_eq!(error(&a), "No such format 'tarball'");
        // That made the handle fatal.
        assert_eq!(a.set_format_ustar(), Status::Fatal);

        let mut a = ArchiveWrite::new();
        assert_eq!(a.set_format_filter_by_ext_def(b"x.txt", b".7z"), Status::Ok);
        assert_eq!(a.format(), 0xe0000);
        assert_eq!(a.set_format_filter_by_ext(b"x.txt"), Status::Fatal);
        assert_eq!(error(&a), "No such format 'x.txt'");
    }

    #[test]
    fn filters_by_setter_code_and_name() {
        let mut a = ArchiveWrite::new();
        assert_eq!(a.add_filter_none(), Status::Ok);
        assert_eq!(a.add_filter_gzip(), Status::Ok);
        assert_eq!(a.add_filter(2), Status::Ok);
        assert_eq!(a.add_filter_by_name(b"uuencode"), Status::Ok);
        assert_eq!(a.add_filter_lzop(), Status::Warn);
        assert_eq!(
            error(&a),
            "Using external lzop program for lzop compression"
        );
        assert_eq!(a.add_filter_program(b"cat"), Status::Ok);
        let codes: Vec<_> = (0..5).map(|n| a.filter_code(n)).collect();
        assert_eq!(codes, [1, 2, 7, 11, 4]);
        assert_eq!(a.add_filter(15), Status::Fatal);
        assert_eq!(error(&a), "No such filter");
        assert_eq!(a.add_filter_by_name(b"zip"), Status::Fatal);
        assert_eq!(error(&a), "No such filter 'zip'");
        assert_eq!(a.add_filter_xz(), Status::Fatal);
    }

    #[test]
    fn options_and_passphrases() {
        let mut a = ArchiveWrite::new();
        assert_eq!(a.set_format_zip(), Status::Ok);
        assert_eq!(a.add_filter_gzip(), Status::Ok);
        let zip = Some(b"zip".as_slice());
        let compression = Some(b"compression".as_slice());
        assert_eq!(
            a.set_format_option(zip, compression, Some(b"store")),
            Status::Ok
        );
        assert_eq!(
            a.set_filter_option(Some(b"gzip"), Some(b"compression-level"), Some(b"9")),
            Status::Ok
        );
        assert_eq!(
            a.set_option(None, Some(b"nonsense"), Some(b"1")),
            Status::Failed
        );
        assert_eq!(error(&a), "Undefined option: `nonsense=1'");
        assert_eq!(a.set_options(b"zip:encryption=zipcrypt"), Status::Ok);
        assert_eq!(a.set_passphrase(b""), Status::Failed);
        assert_eq!(error(&a), "Empty passphrase is unacceptable");
        assert_eq!(a.set_passphrase(b"secret"), Status::Ok);
        assert_eq!(a.set_passphrase_callback(|| None), Status::Ok);
    }
}
