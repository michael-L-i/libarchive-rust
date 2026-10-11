//! Archive writer lifecycle and output clients.
use super::archive::with;
use super::{
    Archive, ArchiveEntry, archive_close_callback, archive_free_callback, archive_open_callback,
    archive_write_callback, guard,
};
use crate::api::write::SetFormat;
use crate::archive::*;
use crate::util::Error;
use crate::write::{Sink, Write};
use std::ffi::{CStr, c_char, c_int, c_void};
use std::io::Write as IoWrite;
use std::os::unix::ffi::OsStrExt;

fn writer<T>(h: &Handle, fallback: T, f: impl FnOnce(&mut Write) -> T) -> T {
    match &h.kind {
        Kind::Write(w) => w.try_borrow_mut().map_or(fallback, |mut w| f(&mut w)),
        _ => fallback,
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_new() -> *mut Archive {
    guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(crate::api::write::new())).cast()
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_bytes_per_block(a: *mut Archive, n: c_int) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.write_set_bytes_per_block(n))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_get_bytes_per_block(a: *mut Archive) -> c_int {
    checked!(
        archive_write_get_bytes_per_block,
        a,
        WRITE_MAGIC,
        state::ANY,
        ARCHIVE_FATAL,
        |h| writer(h, ARCHIVE_FATAL, |w| w.bytes_per_block)
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_bytes_in_last_block(a: *mut Archive, n: c_int) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.write_set_bytes_in_last_block(n))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_get_bytes_in_last_block(a: *mut Archive) -> c_int {
    checked!(
        archive_write_get_bytes_in_last_block,
        a,
        WRITE_MAGIC,
        state::ANY,
        ARCHIVE_FATAL,
        |h| writer(h, ARCHIVE_FATAL, |w| w.bytes_in_last_block)
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_skip_file(a: *mut Archive, d: i64, i: i64) -> c_int {
    checked!(
        archive_write_set_skip_file,
        a,
        WRITE_MAGIC,
        state::ANY,
        ARCHIVE_FATAL,
        |h| writer(h, ARCHIVE_FATAL, |w| {
            w.skip_file = Some((d, i));
            ARCHIVE_OK
        })
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_header(a: *mut Archive, e: *mut ArchiveEntry) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        // SAFETY: caller supplies NULL or a live entry, exclusively for this call.
        let Some(e) = (unsafe { e.cast::<crate::entry::Entry>().as_mut() }) else {
            return ARCHIVE_FATAL;
        };
        h.write_header(e)
    })
}

struct Memory {
    ptr: *mut u8,
    len: usize,
    used: usize,
    used_ptr: *mut usize,
}
impl Sink for Memory {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }
        if data.len() > self.len - self.used {
            return Err(Error::fatal(libc::ENOMEM, "Buffer exhausted"));
        }
        // SAFETY: caller's output region stays writable for the writer lifetime; bounds checked above.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(self.used), data.len());
        }
        self.used += data.len();
        // SAFETY: optional used pointer is writable throughout the archive lifetime.
        if let Some(p) = unsafe { self.used_ptr.as_mut() } {
            *p = self.used;
        }
        Ok(())
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_open_memory(
    a: *mut Archive,
    buffer: *mut c_void,
    len: usize,
    used: *mut usize,
) -> c_int {
    checked!(
        archive_write_open_memory,
        a,
        WRITE_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| writer(h, ARCHIVE_FATAL, |w| {
            if len > isize::MAX as usize || (buffer.is_null() && len != 0) {
                return h
                    .base
                    .raise(Error::fatal(libc::EINVAL, "Invalid memory block"));
            }
            // SAFETY: caller promises a writable optional size pointer.
            if let Some(p) = unsafe { used.as_mut() } {
                *p = 0;
            }
            if w.bytes_in_last_block == -1 {
                w.bytes_in_last_block = 1;
            }
            w.open(
                &h.base,
                Box::new(Memory {
                    ptr: buffer.cast(),
                    len,
                    used: 0,
                    used_ptr: used,
                }),
            )
        })
    )
}

struct Callbacks {
    a: *mut Archive,
    data: *mut c_void,
    open: archive_open_callback,
    write: archive_write_callback,
    close: archive_close_callback,
    free: archive_free_callback,
}
impl Sink for Callbacks {
    fn open(&mut self) -> Result<c_int, Error> {
        // SAFETY: registered callback and client_data are supplied by C caller and live for this writer.
        let r = self
            .open
            .map_or(ARCHIVE_OK, |f| unsafe { f(self.a, self.data) });
        if r < ARCHIVE_WARN {
            Err(Error::silent(r))
        } else {
            Ok(r)
        }
    }
    fn write(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        let Some(f) = self.write else {
            return Err(Error::fatal(-1, "No write callback"));
        };
        while !bytes.is_empty() {
            // SAFETY: callback may read bytes during this call; registration promises correct ABI.
            let n = unsafe { f(self.a, self.data, bytes.as_ptr().cast(), bytes.len()) };
            if n <= 0 {
                return Err(Error::silent(ARCHIVE_FATAL));
            }
            let n = n as usize;
            if n > bytes.len() {
                return Err(Error::fatal(-1, "write overrun"));
            }
            bytes = &bytes[n..];
        }
        Ok(())
    }
    fn close(&mut self) -> Result<(), Error> {
        if let Some(f) = self.close.take() {
            // SAFETY: registered callback's client data remains valid until free.
            unsafe { f(self.a, self.data) };
        }
        Ok(())
    }
    fn free(&mut self) {
        if let Some(f) = self.free.take() {
            // SAFETY: free callback owns the caller's client data and runs once.
            unsafe { f(self.a, self.data) };
        }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_open2(
    a: *mut Archive,
    data: *mut c_void,
    open: archive_open_callback,
    write: archive_write_callback,
    close: archive_close_callback,
    free: archive_free_callback,
) -> c_int {
    checked!(
        archive_write_open,
        a,
        WRITE_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| writer(h, ARCHIVE_FATAL, |w| w.open(
            &h.base,
            Box::new(Callbacks {
                a,
                data,
                open,
                write,
                close,
                free
            })
        ))
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_open(
    a: *mut Archive,
    data: *mut c_void,
    open: archive_open_callback,
    write: archive_write_callback,
    close: archive_close_callback,
) -> c_int {
    archive_write_open2(a, data, open, write, close, None)
}

struct FileSink(std::fs::File);
impl Sink for FileSink {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.0
            .write_all(data)
            .map_err(|e| Error::fatal(e.raw_os_error().unwrap_or(libc::EIO), "Write error"))
    }
}
struct FdSink(super::sys::Fd);
impl Sink for FdSink {
    fn write(&mut self, mut data: &[u8]) -> Result<(), Error> {
        while !data.is_empty() {
            match self.0.write(data) {
                Ok(0) => return Err(Error::fatal(libc::EIO, "Write error")),
                Ok(n) => data = &data[n..],
                Err(libc::EINTR) => {}
                Err(e) => return Err(Error::fatal(e, "Write error")),
            }
        }
        Ok(())
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_open_fd(a: *mut Archive, fd: c_int) -> c_int {
    checked!(
        archive_write_open_fd,
        a,
        WRITE_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| writer(h, ARCHIVE_FATAL, |w| w
            .open(&h.base, Box::new(FdSink(super::sys::Fd(fd)))))
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_open_filename(a: *mut Archive, name: *const c_char) -> c_int {
    if name.is_null() {
        return archive_write_open_fd(a, 1);
    }
    checked!(
        archive_write_open_filename,
        a,
        WRITE_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| {
            // SAFETY: name is a NUL terminated filename supplied by caller.
            let name = unsafe { CStr::from_ptr(name) }.to_bytes();
            if name.is_empty() {
                return archive_write_open_fd(a, 1);
            }
            let path = std::ffi::OsStr::from_bytes(name);
            match std::fs::File::create(path) {
                Ok(f) => writer(h, ARCHIVE_FATAL, |w| {
                    if w.bytes_in_last_block == -1 {
                        w.bytes_in_last_block = 1;
                    }
                    use std::os::fd::AsRawFd;
                    if let Ok(st) = super::sys::Fd(f.as_raw_fd()).fstat() {
                        w.skip_file = Some((st.dev, st.ino));
                    }
                    w.open(&h.base, Box::new(FileSink(f)))
                }),
                Err(e) => h.base.raise(Error::fatal(
                    e.raw_os_error().unwrap_or(libc::EIO),
                    [b"Failed to open '".as_slice(), name, b"'"].concat(),
                )),
            }
        }
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_open_file(a: *mut Archive, name: *const c_char) -> c_int {
    archive_write_open_filename(a, name)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_passphrase(a: *mut Archive, p: *const c_char) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.write_set_passphrase(cbytes(p)))
}

pub(super) fn cbytes<'a>(p: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller supplies NULL or a NUL terminated string.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes())
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_option(
    a: *mut Archive,
    m: *const c_char,
    k: *const c_char,
    v: *const c_char,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.write_set_format_option(cbytes(m), cbytes(k), cbytes(v))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_filter_option(
    a: *mut Archive,
    m: *const c_char,
    k: *const c_char,
    v: *const c_char,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.write_set_filter_option(cbytes(m), cbytes(k), cbytes(v))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_option(
    a: *mut Archive,
    m: *const c_char,
    k: *const c_char,
    v: *const c_char,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.write_set_option(cbytes(m), cbytes(k), cbytes(v))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_options(a: *mut Archive, opts: *const c_char) -> c_int {
    let opts = cbytes(opts).unwrap_or_default();
    with(a, ARCHIVE_FATAL, |h| h.write_set_options(opts))
}

/// The `archive_write_set_format_X` exports.
macro_rules! set_format {
    ($($export:ident => $set:ident,)*) => {$(
        #[unsafe(no_mangle)]
        pub extern "C" fn $export(a: *mut Archive) -> c_int {
            with(a, ARCHIVE_FATAL, |h| h.write_set_format_x(SetFormat::$set))
        }
    )*};
}
set_format! {
    archive_write_set_format_7zip => SEVENZIP,
    archive_write_set_format_ar_bsd => AR_BSD,
    archive_write_set_format_ar_svr4 => AR_SVR4,
    archive_write_set_format_cpio => CPIO_ODC,
    archive_write_set_format_cpio_bin => CPIO_BIN,
    archive_write_set_format_cpio_newc => CPIO_NEWC,
    archive_write_set_format_cpio_odc => CPIO_ODC,
    archive_write_set_format_cpio_pwb => CPIO_PWB,
    archive_write_set_format_gnutar => GNUTAR,
    archive_write_set_format_iso9660 => ISO9660,
    archive_write_set_format_mtree => MTREE,
    archive_write_set_format_mtree_classic => MTREE_CLASSIC,
    archive_write_set_format_pax => PAX,
    archive_write_set_format_pax_restricted => PAX_RESTRICTED,
    archive_write_set_format_raw => RAW,
    archive_write_set_format_shar => SHAR,
    archive_write_set_format_shar_dump => SHAR_DUMP,
    archive_write_set_format_ustar => USTAR,
    archive_write_set_format_v7tar => V7TAR,
    archive_write_set_format_warc => WARC,
    archive_write_set_format_xar => XAR,
    archive_write_set_format_zip => ZIP,
}
fn zip_compression(a: *mut Archive, name: &[u8], function: &str) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        if h.base.check_magic(
            WRITE_MAGIC,
            state::NEW | state::HEADER | state::DATA,
            function,
        ) == ARCHIVE_FATAL
        {
            return ARCHIVE_FATAL;
        }
        if h.base.format.get() != 0x50000 {
            return h.base.raise(Error::fatal(
                -1,
                [
                    b"Can only use ".as_slice(),
                    function.as_bytes(),
                    b" with zip format",
                ]
                .concat(),
            ));
        }
        writer(h, ARCHIVE_FATAL, |w| {
            w.option(
                &h.base,
                Some(b"zip"),
                b"compression",
                Some(name),
                true,
                false,
            )
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_zip_set_compression_deflate(a: *mut Archive) -> c_int {
    zip_compression(a, b"deflate", "archive_write_zip_set_compression_deflate")
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_zip_set_compression_store(a: *mut Archive) -> c_int {
    zip_compression(a, b"store", "archive_write_zip_set_compression_store")
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_zip_set_compression_bzip2(a: *mut Archive) -> c_int {
    zip_compression(a, b"bzip2", "archive_write_zip_set_compression_bzip2")
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_zip_set_compression_lzma(a: *mut Archive) -> c_int {
    zip_compression(a, b"lzma", "archive_write_zip_set_compression_lzma")
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_zip_set_compression_xz(a: *mut Archive) -> c_int {
    zip_compression(a, b"xz", "archive_write_zip_set_compression_xz")
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_zip_set_compression_zstd(a: *mut Archive) -> c_int {
    zip_compression(a, b"zstd", "archive_write_zip_set_compression_zstd")
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_passphrase_callback(
    a: *mut Archive,
    data: *mut c_void,
    cb: super::archive_passphrase_callback,
) -> c_int {
    let callback = cb.map(|cb| {
        Box::new(move || {
            // SAFETY: callback registered by caller owns a live NUL terminated return value for this call.
            let p = unsafe { cb(a, data) };
            cbytes(p).map(<[u8]>::to_vec)
        }) as Box<dyn FnMut() -> Option<Vec<u8>>>
    });
    with(a, ARCHIVE_FATAL, |h| {
        h.write_set_passphrase_callback(callback)
    })
}

struct CStream(*mut libc::FILE);
impl Sink for CStream {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        // SAFETY: caller provides a live FILE stream, and data is readable for this call.
        let n = unsafe { libc::fwrite(data.as_ptr().cast(), 1, data.len(), self.0) };
        if n != data.len() {
            Err(Error::fatal(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
                "Write error",
            ))
        } else {
            Ok(())
        }
    }
    fn close(&mut self) -> Result<(), Error> {
        // SAFETY: caller keeps the FILE stream alive; flushing does not transfer ownership.
        if unsafe { libc::fflush(self.0) } != 0 {
            return Err(Error::fatal(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
                "Write error",
            ));
        }
        Ok(())
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_open_FILE(a: *mut Archive, file: *mut libc::FILE) -> c_int {
    checked!(
        archive_write_open_FILE,
        a,
        WRITE_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| writer(h, ARCHIVE_FATAL, |w| {
            if file.is_null() {
                return h
                    .base
                    .raise(Error::fatal(libc::EINVAL, "Invalid FILE pointer"));
            }
            // SAFETY: caller's stream is live and fileno only queries its descriptor.
            let fd = unsafe { libc::fileno(file) };
            if let Ok(st) = super::sys::Fd(fd).fstat() {
                if st.mode & 0o170000 == 0o100000 {
                    w.skip_file = Some((st.dev, st.ino));
                }
                if w.bytes_in_last_block < 0 {
                    w.bytes_in_last_block =
                        if matches!(st.mode & 0o170000, 0o020000 | 0o060000 | 0o010000) {
                            0
                        } else {
                            1
                        };
                }
            }
            w.open(&h.base, Box::new(CStream(file)))
        })
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_open_filename_w(
    a: *mut Archive,
    name: *const libc::wchar_t,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        if h.base
            .check_magic(WRITE_MAGIC, state::NEW, "archive_write_open_filename_w")
            == ARCHIVE_FATAL
        {
            return ARCHIVE_FATAL;
        }
        let mut wide = Vec::new();
        if !name.is_null() {
            // SAFETY: caller provides a NUL terminated wide filename.
            while let Some(&c) = (unsafe { name.add(wide.len()).as_ref() }).filter(|&&c| c != 0) {
                wide.push(c);
            }
        }
        if wide.is_empty() {
            return archive_write_open_filename(a, std::ptr::null());
        }
        let mut text = crate::string::MString::default();
        text.copy_wcs(&wide);
        let filename = match text.get_mbs(None) {
            Ok(Some(s)) => s.to_vec(),
            _ => {
                return h.base.raise(Error::fatal(
                    libc::EINVAL,
                    "Failed to convert a wide-character filename to a multi-byte filename",
                ));
            }
        };
        let filename = match std::ffi::CString::new(filename) {
            Ok(s) => s,
            Err(_) => return h.base.raise(Error::fatal(libc::EINVAL, "Invalid filename")),
        };
        archive_write_open_filename(a, filename.as_ptr())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format(a: *mut Archive, code: c_int) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.write_set_format(code))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_by_name(a: *mut Archive, name: *const c_char) -> c_int {
    let name = cbytes(name).unwrap_or_default();
    with(a, ARCHIVE_FATAL, |h| h.write_set_format_by_name(name))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_filter_by_ext(
    a: *mut Archive,
    name: *const c_char,
) -> c_int {
    archive_write_set_format_filter_by_ext_def(a, name, std::ptr::null())
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_filter_by_ext_def(
    a: *mut Archive,
    name: *const c_char,
    default: *const c_char,
) -> c_int {
    let (name, default) = (cbytes(name), cbytes(default));
    with(a, ARCHIVE_FATAL, |h| {
        h.write_set_format_filter_by_ext(name, default)
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{archive::*, entry::*, read::*, read_open::*};
    unsafe extern "C" fn fail_open(_: *mut Archive, _: *mut c_void) -> c_int {
        ARCHIVE_FATAL
    }
    unsafe extern "C" fn count_free(_: *mut Archive, p: *mut c_void) -> c_int {
        // SAFETY: the test registers its live counter pointer.
        unsafe {
            *p.cast::<usize>() += 1;
        }
        ARCHIVE_OK
    }
    #[test]
    fn failed_open_releases_client_data_once() {
        let a = archive_write_new();
        let mut freed = 0usize;
        assert_eq!(
            archive_write_open2(
                a,
                (&mut freed as *mut usize).cast(),
                Some(fail_open),
                None,
                None,
                Some(count_free)
            ),
            ARCHIVE_FATAL
        );
        assert_eq!(freed, 1);
        assert_eq!(super::super::archive::archive_free(a), ARCHIVE_OK);
        assert_eq!(freed, 1);
    }
    #[test]
    fn empty_memory_sink_accepts_null_output() {
        let mut sink = Memory {
            ptr: std::ptr::null_mut(),
            len: 0,
            used: 0,
            used_ptr: std::ptr::null_mut(),
        };
        assert_eq!(sink.write(&[]), Ok(()));
    }
    #[test]
    fn raw_memory_writer_delays_blocks_and_finishes_exactly() {
        let a = archive_write_new();
        let mut buf = [0; 100];
        let mut used = 0;
        assert_eq!(archive_write_set_format_raw(a), ARCHIVE_OK);
        assert_eq!(
            archive_write_open_memory(a, buf.as_mut_ptr().cast(), buf.len(), &mut used),
            ARCHIVE_OK
        );
        let mut entry = crate::entry::Entry::new(None);
        entry.set_filetype(0o100000);
        assert_eq!(
            archive_write_header(a, (&mut entry as *mut crate::entry::Entry).cast()),
            ARCHIVE_OK
        );
        assert_eq!(
            super::super::archive::archive_write_data(a, b"abc".as_ptr().cast(), 3),
            3
        );
        assert_eq!(used, 0);
        assert_eq!(super::super::archive::archive_write_close(a), ARCHIVE_OK);
        assert_eq!(used, 3);
        assert_eq!(&buf[..used], b"abc");
        assert_eq!(super::super::archive::archive_free(a), ARCHIVE_OK);
    }
    #[test]
    fn sevenzip_basic_codecs_metadata_and_entry_order() {
        // The upstream file's unregister test uses internal struct layout, so its
        // basic tests are excluded by the public ABI oracle build.
        for codec in [
            c"copy", c"deflate", c"bzip2", c"lzma1", c"lzma2", c"ppmd", c"zstd",
        ] {
            let a = archive_write_new();
            assert_eq!(archive_write_set_format_7zip(a), ARCHIVE_OK);
            assert_eq!(
                archive_write_set_format_option(
                    a,
                    c"7zip".as_ptr(),
                    c"compression".as_ptr(),
                    codec.as_ptr()
                ),
                ARCHIVE_OK
            );
            let mut output = vec![0u8; 2048];
            let mut used = 0;
            assert_eq!(
                archive_write_open_memory(a, output.as_mut_ptr().cast(), output.len(), &mut used),
                ARCHIVE_OK
            );
            for (name, mode, size, symlink) in [
                (c"empty", 0o100444, 0, None),
                (c"data", 0o100755, 8, None),
                (c"link", 0o120755, 0, Some(c"data")),
                (c"dir/sub", 0o40755, 512, None),
                (c"dir", 0o40755, 512, None),
            ] {
                let e = archive_entry_new();
                archive_entry_set_pathname(e, name.as_ptr());
                archive_entry_set_mode(e, mode);
                archive_entry_set_size(e, size);
                archive_entry_set_mtime(e, 1, 100);
                archive_entry_set_atime(e, 2, 0);
                if let Some(s) = symlink {
                    archive_entry_set_symlink(e, s.as_ptr());
                }
                assert_eq!(archive_write_header(a, e), ARCHIVE_OK);
                if size == 8 {
                    assert_eq!(archive_write_data(a, b"abc".as_ptr().cast(), 3), 3);
                }
                archive_entry_free(e);
            }
            assert_eq!(archive_write_close(a), ARCHIVE_OK);
            assert_eq!(archive_write_free(a), ARCHIVE_OK);
            let r = archive_read_new();
            assert_eq!(archive_read_support_format_7zip(r), ARCHIVE_OK);
            assert_eq!(
                archive_read_open_memory(r, output.as_ptr().cast(), used),
                ARCHIVE_OK
            );
            for (name, mode, size) in [
                (c"data", 0o100755, 8),
                (c"link", 0o120755, 0),
                (c"empty", 0o100444, 0),
                (c"dir/sub/", 0o40755, 0),
                (c"dir/", 0o40755, 0),
            ] {
                let mut e = std::ptr::null_mut();
                assert_eq!(
                    archive_read_next_header(r, &mut e),
                    ARCHIVE_OK,
                    "codec {codec:?}"
                );
                // SAFETY: the entry getter returns a NUL-terminated pathname owned by e.
                assert_eq!(unsafe { CStr::from_ptr(archive_entry_pathname(e)) }, name);
                assert_eq!(archive_entry_mode(e), mode);
                assert_eq!(archive_entry_size(e), size);
                assert_eq!(archive_entry_mtime(e), 1);
                assert_eq!(archive_entry_mtime_nsec(e), 100);
                assert_eq!(archive_entry_atime(e), 2);
                if size == 8 {
                    let mut b = [0; 8];
                    assert_eq!(archive_read_data(r, b.as_mut_ptr().cast(), b.len()), 8);
                    assert_eq!(&b, b"abc\0\0\0\0\0");
                }
                if mode == 0o120755 {
                    // SAFETY: symlink metadata is a NUL-terminated string owned by e.
                    assert_eq!(unsafe { CStr::from_ptr(archive_entry_symlink(e)) }, c"data");
                }
            }
            assert_eq!(archive_read_free(r), ARCHIVE_OK);
        }
    }
}
