//! Safe wrappers over the file-descriptor and `FILE *` calls the read
//! clients make. All `unsafe` for that lives here.

use std::ffi::c_int;

/// What `fstat` reports that the clients use.
#[derive(Clone, Copy, Debug)]
pub struct Stat {
    pub mode: u32,
    pub dev: i64,
    pub ino: i64,
    pub size: i64,
}

impl Stat {
    fn kind(&self) -> u32 {
        self.mode & u32::from(libc::S_IFMT)
    }

    pub fn is_reg(&self) -> bool {
        self.kind() == u32::from(libc::S_IFREG)
    }

    pub fn is_blk(&self) -> bool {
        self.kind() == u32::from(libc::S_IFBLK)
    }
}

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A file descriptor somebody else owns: the C caller's, or the standard
/// input. `Fd` does not close it. A bad descriptor makes calls fail with
/// `EBADF`, never misbehave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fd(pub c_int);

impl Fd {
    /// `fstat`, or the errno.
    pub fn fstat(self) -> Result<Stat, c_int> {
        // SAFETY: `st` is a valid, writable `stat` for fstat to fill; an
        // invalid descriptor makes the call fail.
        let st = unsafe {
            let mut st = std::mem::zeroed::<libc::stat>();
            if libc::fstat(self.0, &mut st) != 0 {
                return Err(errno());
            }
            st
        };
        Ok(Stat {
            mode: u32::from(st.st_mode),
            dev: st.st_dev as i64,
            ino: st.st_ino as i64,
            size: st.st_size,
        })
    }

    /// `read`, or the errno. `EINTR` is the caller's to retry.
    pub fn read(self, buf: &mut [u8]) -> Result<usize, c_int> {
        // SAFETY: `buf` is valid for writes of its length.
        let n = unsafe { libc::read(self.0, buf.as_mut_ptr().cast(), buf.len()) };
        usize::try_from(n).map_err(|_| errno())
    }

    /// `write`, or the errno.
    pub fn write(self, buf: &[u8]) -> Result<usize, c_int> {
        // SAFETY: `buf` is valid for reads of its length.
        let n = unsafe { libc::write(self.0, buf.as_ptr().cast(), buf.len()) };
        usize::try_from(n).map_err(|_| errno())
    }

    /// `lseek` (`whence` is `libc::SEEK_*`), or the errno.
    pub fn lseek(self, offset: i64, whence: c_int) -> Result<i64, c_int> {
        let offset = libc::off_t::try_from(offset).map_err(|_| libc::EOVERFLOW)?;
        // SAFETY: lseek has no memory-safety requirements.
        let r = unsafe { libc::lseek(self.0, offset, whence) };
        if r < 0 { Err(errno()) } else { Ok(r as i64) }
    }
}

/// A `FILE *` the C caller passed to `archive_read_open_FILE`.
pub struct CFile(*mut libc::FILE);

impl CFile {
    /// # Safety
    ///
    /// `file` must be a valid open `FILE *` that stays valid, and is not
    /// used by anyone else, until the `CFile` is dropped.
    pub unsafe fn new(file: *mut libc::FILE) -> CFile {
        CFile(file)
    }

    /// The descriptor behind the stream, if it has one.
    pub fn fd(&self) -> Option<Fd> {
        // SAFETY: `self.0` is a valid FILE (see `new`).
        let fd = unsafe { libc::fileno(self.0) };
        (fd >= 0).then_some(Fd(fd))
    }

    /// `fread`: the bytes read, and whether the stream is in error.
    pub fn read(&mut self, buf: &mut [u8]) -> (usize, Option<c_int>) {
        // SAFETY: `buf` is valid for writes of its length; `self.0` is a
        // valid FILE.
        let n = unsafe { libc::fread(buf.as_mut_ptr().cast(), 1, buf.len(), self.0) };
        // SAFETY: as above.
        let failed = n < buf.len() && unsafe { libc::ferror(self.0) } != 0;
        (n, failed.then(errno))
    }

    /// `ftello`, or the errno.
    pub fn tell(&mut self) -> Result<i64, c_int> {
        // SAFETY: `self.0` is a valid FILE.
        let r = unsafe { libc::ftello(self.0) };
        if r < 0 { Err(errno()) } else { Ok(r as i64) }
    }

    /// `fseeko` (`whence` is `libc::SEEK_*`), or the errno.
    pub fn seek(&mut self, offset: i64, whence: c_int) -> Result<(), c_int> {
        let offset = libc::off_t::try_from(offset).map_err(|_| libc::EOVERFLOW)?;
        // SAFETY: `self.0` is a valid FILE.
        if unsafe { libc::fseeko(self.0, offset, whence) } == 0 {
            Ok(())
        } else {
            Err(errno())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    #[test]
    fn fd_reads_seeks_and_stats() {
        let mut f = tempfile_with(b"hello world");
        f.flush().unwrap();
        let fd = Fd(f.as_raw_fd());
        let st = fd.fstat().unwrap();
        assert!(st.is_reg() && !st.is_blk());
        assert_eq!(st.size, 11);
        let mut buf = [0; 5];
        assert_eq!(fd.lseek(6, libc::SEEK_SET), Ok(6));
        assert_eq!(fd.read(&mut buf), Ok(5));
        assert_eq!(&buf, b"world");
        assert_eq!(fd.read(&mut buf), Ok(0));
        assert_eq!(fd.lseek(-5, libc::SEEK_END), Ok(6));
        assert_eq!(fd.lseek(-100, libc::SEEK_SET), Err(libc::EINVAL));
    }

    #[test]
    fn bad_descriptors_fail_cleanly() {
        let fd = Fd(-1);
        assert_eq!(fd.fstat().unwrap_err(), libc::EBADF);
        assert_eq!(fd.read(&mut [0; 1]), Err(libc::EBADF));
        assert_eq!(fd.write(b"x"), Err(libc::EBADF));
        assert_eq!(fd.lseek(0, libc::SEEK_CUR), Err(libc::EBADF));
    }

    fn tempfile_with(data: &[u8]) -> std::fs::File {
        let path = std::env::temp_dir().join(format!(
            "archive-sys-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, data).unwrap();
        let f = std::fs::File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        f
    }
}
