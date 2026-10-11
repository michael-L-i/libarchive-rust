//! Archive writer lifecycle and output clients.
use super::archive::with;
use super::{
    Archive, ArchiveEntry, archive_close_callback, archive_free_callback, archive_open_callback,
    archive_write_callback, guard,
};
use crate::archive::*;
use crate::util::Error;
use crate::write::{Sink, Write};
use std::ffi::{CStr, c_char, c_int, c_void};
use std::io::Write as IoWrite;
use std::os::unix::ffi::OsStrExt;

pub(crate) fn with_writer(a: *mut Archive, f: impl FnOnce(&Base, &mut Write) -> c_int) -> c_int {
    checked!(
        archive_write_add_filter,
        a,
        WRITE_MAGIC,
        state::NEW,
        ARCHIVE_FATAL,
        |h| match &h.kind {
            Kind::Write(w) => w
                .try_borrow_mut()
                .map_or(ARCHIVE_FATAL, |mut w| f(&h.base, &mut w)),
            _ => ARCHIVE_FATAL,
        }
    )
}
pub(crate) fn with_writer_named(
    a: *mut Archive,
    name: &str,
    f: impl FnOnce(&Base, &mut Write) -> c_int,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        if h.base.check_magic(WRITE_MAGIC, state::NEW, name) == ARCHIVE_FATAL {
            return ARCHIVE_FATAL;
        }
        writer(h, ARCHIVE_FATAL, |w| f(&h.base, w))
    })
}
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
pub extern "C" fn archive_write_set_format_raw(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_raw", |b, w| {
        w.set_format(b, Box::new(crate::write::format::raw::Raw::default()))
    })
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
    with_writer_named(a, "archive_write_set_passphrase", |b, w| {
        if p.is_null() {
            return b.raise(Error::new(ARCHIVE_FAILED, -1, "Empty passphrase"));
        }
        // SAFETY: caller provides NUL terminated passphrase.
        let p = unsafe { CStr::from_ptr(p) }.to_bytes();
        if p.is_empty() {
            return b.raise(Error::new(ARCHIVE_FAILED, -1, "Empty passphrase"));
        }
        w.passphrase = Some(p.to_vec());
        ARCHIVE_OK
    })
}

fn cbytes<'a>(p: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller supplies NULL or a NUL terminated option string.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes())
}
fn set_option(
    a: *mut Archive,
    module: *const c_char,
    key: *const c_char,
    value: *const c_char,
    formats: bool,
    filters: bool,
) -> c_int {
    let name = match (formats, filters) {
        (true, false) => "archive_write_set_format_option",
        (false, true) => "archive_write_set_filter_option",
        _ => "archive_write_set_option",
    };
    with_writer_named(a, name, |b, w| {
        crate::options::set_option(
            b,
            cbytes(module),
            cbytes(key),
            cbytes(value),
            &mut |m, k, v| w.option(b, m, k, v, formats, filters),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_option(
    a: *mut Archive,
    m: *const c_char,
    k: *const c_char,
    v: *const c_char,
) -> c_int {
    set_option(a, m, k, v, true, false)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_filter_option(
    a: *mut Archive,
    m: *const c_char,
    k: *const c_char,
    v: *const c_char,
) -> c_int {
    set_option(a, m, k, v, false, true)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_option(
    a: *mut Archive,
    m: *const c_char,
    k: *const c_char,
    v: *const c_char,
) -> c_int {
    set_option(a, m, k, v, true, true)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_options(a: *mut Archive, opts: *const c_char) -> c_int {
    with_writer_named(a, "archive_write_set_options", |b, w| {
        crate::options::set_options(b, cbytes(opts).unwrap_or_default(), &mut |m, k, v| {
            w.option(b, m, k, v, true, true)
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_v7tar(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_v7tar", |b, w| {
        w.set_format(b, Box::new(crate::write::format::tar::Tar::new(0x30000)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_ustar(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_ustar", |b, w| {
        w.set_format(b, Box::new(crate::write::format::tar::Tar::new(0x30001)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_pax(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_pax", |b, w| {
        w.set_format(b, Box::new(crate::write::format::tar::Tar::new(0x30002)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_pax_restricted(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_pax_restricted", |b, w| {
        w.set_format(b, Box::new(crate::write::format::tar::Tar::new(0x30003)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_gnutar(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_gnutar", |b, w| {
        w.set_format(b, Box::new(crate::write::format::tar::Tar::new(0x30004)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_ar_bsd(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_ar_bsd", |b, w| {
        w.set_format(b, Box::new(crate::write::format::ar::Ar::new(true)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_ar_svr4(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_ar_svr4", |b, w| {
        w.set_format(b, Box::new(crate::write::format::ar::Ar::new(false)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_cpio(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_cpio", |b, w| {
        w.set_format(b, Box::new(crate::write::format::cpio::Cpio::new(0x10001)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_cpio_odc(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_cpio_odc", |b, w| {
        w.set_format(b, Box::new(crate::write::format::cpio::Cpio::new(0x10001)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_cpio_newc(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_cpio_newc", |b, w| {
        w.set_format(b, Box::new(crate::write::format::cpio::Cpio::new(0x10004)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_cpio_bin(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_cpio_bin", |b, w| {
        w.set_format(b, Box::new(crate::write::format::cpio::Cpio::new(0x10002)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_cpio_pwb(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_cpio_pwb", |b, w| {
        w.set_format(b, Box::new(crate::write::format::cpio::Cpio::new(0x10006)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_xar(a: *mut Archive) -> c_int {
    with_writer(a, |b, w| {
        w.set_format(b, Box::new(crate::write::format::xar::Xar::default()))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_zip(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_zip", |b, w| {
        w.set_format(b, Box::new(crate::write::format::zip::Zip::default()))
    })
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
    with_writer_named(a, "archive_write_set_passphrase_callback", |_, w| {
        w.passphrase_callback = cb.map(|cb| {
            Box::new(move || {
                // SAFETY: callback registered by caller owns a live NUL terminated return value for this call.
                let p = unsafe { cb(a, data) };
                cbytes(p).map(<[u8]>::to_vec)
            }) as Box<dyn FnMut() -> Option<Vec<u8>>>
        });
        ARCHIVE_OK
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_warc(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_warc", |b, w| {
        w.set_format(b, Box::new(crate::write::format::warc::Warc::default()))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_shar(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_shar", |b, w| {
        w.set_format(b, Box::new(crate::write::format::shar::Shar::new(false)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_shar_dump(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_shar_dump", |b, w| {
        w.set_format(b, Box::new(crate::write::format::shar::Shar::new(true)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_mtree(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_mtree", |b, w| {
        w.set_format(b, Box::new(crate::write::format::mtree::Mtree::new(false)))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_mtree_classic(a: *mut Archive) -> c_int {
    with_writer_named(a, "archive_write_set_format_mtree_classic", |b, w| {
        w.set_format(b, Box::new(crate::write::format::mtree::Mtree::new(true)))
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

unsafe extern "C" {
    #[link_name = "archive_write_set_format_iso9660"]
    fn set_iso(a: *mut Archive) -> c_int;
    #[link_name = "archive_write_set_format_xar"]
    fn set_xar(a: *mut Archive) -> c_int;
}
fn large_format(a: *mut Archive, iso: bool) -> c_int {
    // SAFETY: these are the library's public setters, with the same live archive pointer contract.
    unsafe { if iso { set_iso(a) } else { set_xar(a) } }
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format(a: *mut Archive, code: c_int) -> c_int {
    match code {
        0xe0000 => super::write_format_large::archive_write_set_format_7zip(a),
        0x10000 | 0x10001 => archive_write_set_format_cpio_odc(a),
        0x10002 => archive_write_set_format_cpio_bin(a),
        0x10004 => archive_write_set_format_cpio_newc(a),
        0x10006 => archive_write_set_format_cpio_pwb(a),
        0x40000 => large_format(a, true),
        0x80000 => archive_write_set_format_mtree(a),
        0x90000 => archive_write_set_format_raw(a),
        0x20000 | 0x20001 => archive_write_set_format_shar(a),
        0x20002 => archive_write_set_format_shar_dump(a),
        0x30000 | 0x30003 => archive_write_set_format_pax_restricted(a),
        0x30001 => archive_write_set_format_ustar(a),
        0x30002 => archive_write_set_format_pax(a),
        0x30004 => archive_write_set_format_gnutar(a),
        0xf0000 => archive_write_set_format_warc(a),
        0xa0000 => large_format(a, false),
        0x50000 => archive_write_set_format_zip(a),
        _ => with(a, ARCHIVE_FATAL, |h| {
            h.base.raise(Error::fatal(libc::EINVAL, "No such format"))
        }),
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_by_name(a: *mut Archive, name: *const c_char) -> c_int {
    let name = cbytes(name).unwrap_or_default();
    match name {
        b"7zip" => super::write_format_large::archive_write_set_format_7zip(a),
        b"ar" | b"arbsd" => archive_write_set_format_ar_bsd(a),
        b"argnu" | b"arsvr4" => archive_write_set_format_ar_svr4(a),
        b"bin" => archive_write_set_format_cpio_bin(a),
        b"cpio" | b"odc" => archive_write_set_format_cpio_odc(a),
        b"newc" => archive_write_set_format_cpio_newc(a),
        b"pwb" => archive_write_set_format_cpio_pwb(a),
        b"cd9660" | b"iso" | b"iso9660" => large_format(a, true),
        b"mtree" => archive_write_set_format_mtree(a),
        b"mtree-classic" => archive_write_set_format_mtree_classic(a),
        b"raw" => archive_write_set_format_raw(a),
        b"shar" => archive_write_set_format_shar(a),
        b"shardump" => archive_write_set_format_shar_dump(a),
        b"oldtar" | b"v7tar" | b"v7" => archive_write_set_format_v7tar(a),
        b"ustar" => archive_write_set_format_ustar(a),
        b"gnutar" => archive_write_set_format_gnutar(a),
        b"pax" | b"posix" => archive_write_set_format_pax(a),
        b"paxr" | b"rpax" | b"bsdtar" => archive_write_set_format_pax_restricted(a),
        b"warc" => archive_write_set_format_warc(a),
        b"xar" => large_format(a, false),
        b"zip" => archive_write_set_format_zip(a),
        _ => with(a, ARCHIVE_FATAL, |h| {
            h.base.state.set(state::FATAL);
            h.base.raise(Error::fatal(
                libc::EINVAL,
                [b"No such format '".as_slice(), name, b"'"].concat(),
            ))
        }),
    }
}
fn extension(name: &[u8]) -> Option<(c_int, c_int)> {
    for (suffix, format, filter) in [
        (b".7z".as_slice(), 0xe0000, 0),
        (b".zip", 0x50000, 0),
        (b".jar", 0x50000, 0),
        (b".cpio", 0x10001, 0),
        (b".iso", 0x40000, 0),
        (b".a", 0x70001, 0),
        (b".ar", 0x70001, 0),
        (b".tar", 0x30003, 0),
        (b".tgz", 0x30003, 1),
        (b".tar.gz", 0x30003, 1),
        (b".tar.bz2", 0x30003, 2),
        (b".tar.xz", 0x30003, 6),
        (b".tar.zst", 0x30003, 14),
    ] {
        if name.ends_with(suffix) {
            return Some((format, filter));
        }
    }
    None
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
    let route = cbytes(name)
        .and_then(extension)
        .or_else(|| cbytes(default).and_then(extension));
    let Some((format, filter)) = route else {
        return with(a, ARCHIVE_FATAL, |h| {
            h.base.state.set(state::FATAL);
            h.base.raise(Error::fatal(
                libc::EINVAL,
                [
                    b"No such format '".as_slice(),
                    cbytes(name).unwrap_or_default(),
                    b"'",
                ]
                .concat(),
            ))
        });
    };
    let r = if format == 0x70001 {
        archive_write_set_format_ar_svr4(a)
    } else {
        archive_write_set_format(a, format)
    };
    if r != ARCHIVE_OK {
        return r;
    }
    super::write_filter::archive_write_add_filter(a, filter)
}
#[cfg(test)]
mod tests {
    use super::*;
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
}
