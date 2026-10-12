//! Filesystem and account calls used by disk traversal and extraction.

use crate::entry::Entry;
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub fn path_c(path: &Path) -> std::io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))
}
fn result(code: libc::c_int) -> std::io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
pub fn stat(path: &Path, fd: libc::c_int, follow: bool) -> std::io::Result<libc::stat> {
    let mut st = super::entry::zeroed_stat();
    let path = path_c(path)?;
    // SAFETY: the CString and writable stat remain live for the call.
    let code = unsafe {
        if fd >= 0 {
            libc::fstat(fd, &mut st)
        } else if follow {
            libc::stat(path.as_ptr(), &mut st)
        } else {
            libc::lstat(path.as_ptr(), &mut st)
        }
    };
    result(code)?;
    Ok(st)
}
/// Opens `path` for reading, following symlinks, with `flags` added.
#[cfg(any(
    test,
    target_os = "linux",
    not(any(target_vendor = "apple", target_os = "linux"))
))]
pub fn open_read(path: &Path, flags: libc::c_int) -> std::io::Result<File> {
    let path = path_c(path)?;
    // SAFETY: the path is terminated; a successful open returns a new descriptor.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: nothing else owns the descriptor open just returned.
    Ok(unsafe { File::from_raw_fd(fd) })
}
/// A pathname relative to a directory kept open by the disk walker.
#[derive(Clone)]
pub struct ReadPath {
    parent: std::rc::Rc<File>,
    name: CString,
    link: Option<std::rc::Rc<File>>,
    #[cfg(target_os = "linux")]
    metadata: Option<std::rc::Rc<File>>,
}
impl ReadPath {
    pub fn initial_dir() -> std::io::Result<std::rc::Rc<File>> {
        open_dir(libc::AT_FDCWD, c".", true).map(std::rc::Rc::new)
    }
    pub fn root(initial: std::rc::Rc<File>, path: &Path) -> std::io::Result<Self> {
        let bytes = path.as_os_str().as_bytes();
        let (parent, name) = match bytes.iter().rposition(|&b| b == b'/') {
            Some(n) => (&bytes[..n.max(1)], &bytes[n + 1..]),
            None => (&b"."[..], bytes),
        };
        let parent =
            CString::new(parent).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let parent = std::rc::Rc::new(open_dir(initial.as_raw_fd(), &parent, true)?);
        Self::child(parent, if bytes == b"/" { b"." } else { name })
    }
    pub fn child(parent: std::rc::Rc<File>, name: &[u8]) -> std::io::Result<Self> {
        Ok(Self {
            parent,
            link: None,
            #[cfg(target_os = "linux")]
            metadata: None,
            name: CString::new(name)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?,
        })
    }
    pub fn pin_link(&mut self, expected: &libc::stat) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        let flags = libc::O_PATH;
        #[cfg(target_vendor = "apple")]
        let flags = libc::O_SYMLINK;
        #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
        let flags = libc::O_NONBLOCK;
        self.link = Some(std::rc::Rc::new(self.open(flags, false, expected)?));
        Ok(())
    }
    pub fn stat(&self, follow: bool) -> std::io::Result<libc::stat> {
        if !follow && let Some(link) = &self.link {
            return fstat(link);
        }
        stat_at(&self.parent, &self.name, follow)
    }
    #[cfg(target_vendor = "apple")]
    pub fn link_file(&self) -> Option<&File> {
        self.link.as_deref()
    }
    pub fn parent(&self) -> &File {
        &self.parent
    }
    pub fn directory(
        &self,
        follow: bool,
        expected: &libc::stat,
    ) -> std::io::Result<std::rc::Rc<File>> {
        let file = open_dir(self.parent.as_raw_fd(), &self.name, follow)?;
        same_file(expected, &fstat(&file)?)?;
        Ok(std::rc::Rc::new(file))
    }
    pub fn open(
        &self,
        flags: libc::c_int,
        follow: bool,
        expected: &libc::stat,
    ) -> std::io::Result<File> {
        #[cfg(target_vendor = "apple")]
        let follow = follow || flags & libc::O_SYMLINK != 0;
        // SAFETY: the parent descriptor and terminated name remain live.
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_CLOEXEC
                    | flags
                    | if follow { 0 } else { libc::O_NOFOLLOW },
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat returned a uniquely owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        same_file(expected, &fstat(&file)?)?;
        Ok(file)
    }
    pub fn read_link(&self, expected: &libc::stat) -> std::io::Result<PathBuf> {
        same_file(expected, &self.stat(false)?)?;
        let mut bytes = vec![0u8; 256];
        loop {
            // SAFETY: live parent/name and writable buffer of the supplied length.
            let n = unsafe {
                #[cfg(target_os = "linux")]
                {
                    libc::readlinkat(
                        self.link
                            .as_ref()
                            .map_or(self.parent.as_raw_fd(), |f| f.as_raw_fd()),
                        if self.link.is_some() {
                            c"".as_ptr()
                        } else {
                            self.name.as_ptr()
                        },
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                    )
                }
                #[cfg(target_vendor = "apple")]
                {
                    match &self.link {
                        Some(link) => libc::freadlink(
                            link.as_raw_fd(),
                            bytes.as_mut_ptr().cast(),
                            bytes.len(),
                        ) as isize,
                        None => libc::readlinkat(
                            self.parent.as_raw_fd(),
                            self.name.as_ptr(),
                            bytes.as_mut_ptr().cast(),
                            bytes.len(),
                        ),
                    }
                }
                #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
                {
                    libc::readlinkat(
                        self.parent.as_raw_fd(),
                        self.name.as_ptr(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                    )
                }
            };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if (n as usize) < bytes.len() {
                same_file(expected, &self.stat(false)?)?;
                bytes.truncate(n as usize);
                return Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes)));
            }
            if bytes.len() >= 1024 * 1024 {
                return Err(std::io::Error::from_raw_os_error(libc::ENOMEM));
            }
            bytes.resize(bytes.len() * 2, 0);
        }
    }
    #[cfg(target_os = "linux")]
    pub fn pin_metadata(&mut self, expected: &libc::stat, follow: bool) -> std::io::Result<()> {
        if expected.st_mode & libc::S_IFMT != libc::S_IFLNK {
            self.metadata = Some(std::rc::Rc::new(self.open(
                libc::O_PATH,
                follow,
                expected,
            )?));
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub fn metadata_path(&self) -> PathBuf {
        if let Some(file) = &self.metadata {
            return PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        }
        PathBuf::from(format!("/proc/self/fd/{}", self.parent.as_raw_fd()))
            .join(std::ffi::OsStr::from_bytes(self.name.to_bytes()))
    }
    #[cfg(target_os = "linux")]
    pub fn metadata_follows(&self) -> bool {
        self.metadata.is_some()
    }
    #[cfg(target_os = "linux")]
    pub fn verify_name(&self, expected: &libc::stat, follow: bool) -> std::io::Result<()> {
        same_file(expected, &stat_at(&self.parent, &self.name, follow)?)
    }
}
fn same_file(expected: &libc::stat, actual: &libc::stat) -> std::io::Result<()> {
    if (
        expected.st_dev,
        expected.st_ino,
        expected.st_mode & libc::S_IFMT,
    ) == (actual.st_dev, actual.st_ino, actual.st_mode & libc::S_IFMT)
    {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(libc::ESTALE))
    }
}

/// A native readdir stream opened relative to the pinned directory.
pub struct ReadDir(*mut libc::DIR);
impl ReadDir {
    pub fn open(parent: &File) -> std::io::Result<(Self, File)> {
        // SAFETY: live parent and literal terminated name; successful open owns a descriptor.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful openat returned a uniquely owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        let iter = file.try_clone()?;
        use std::os::fd::IntoRawFd;
        let fd = iter.into_raw_fd();
        // SAFETY: fd is uniquely owned; success transfers ownership to DIR.
        let dir = unsafe { libc::fdopendir(fd) };
        if dir.is_null() {
            let e = std::io::Error::last_os_error();
            // SAFETY: fdopendir failed and did not consume the descriptor.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Ok((Self(dir), file))
    }
}
impl Iterator for ReadDir {
    type Item = std::io::Result<std::ffi::OsString>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            #[cfg(target_os = "linux")]
            // SAFETY: errno belongs to this thread.
            unsafe {
                *libc::__errno_location() = 0;
            }
            #[cfg(target_vendor = "apple")]
            // SAFETY: errno belongs to this thread.
            unsafe {
                *libc::__error() = 0;
            }
            // SAFETY: DIR is live; readdir's storage is copied before the next call.
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    None
                } else {
                    Some(Err(error))
                };
            }
            // SAFETY: readdir returned a live dirent with a terminated d_name.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            return Some(Ok(std::ffi::OsStr::from_bytes(name).to_owned()));
        }
    }
}
impl Drop for ReadDir {
    fn drop(&mut self) {
        // SAFETY: this stream uniquely owns the DIR and its descriptor.
        unsafe { libc::closedir(self.0) };
    }
}

/// Upstream's close_and_restore_time: puts back the access and
/// modification times, each (seconds, nanoseconds), of what `file` is.
pub fn restore_times(file: &File, atime: (i64, i64), mtime: (i64, i64)) -> std::io::Result<()> {
    let times = [atime, mtime].map(|(tv_sec, tv_nsec)| libc::timespec {
        tv_sec: tv_sec as _,
        tv_nsec: tv_nsec as _,
    });
    // SAFETY: live descriptor and two timespecs that outlive the call.
    result(unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) })
}
pub fn name(id: i64, group: bool) -> Option<CString> {
    let mut buffer = vec![0u8; 16384];
    if group {
        // SAFETY: group is a plain C struct initialized by getgrgid_r.
        let mut record: libc::group = unsafe { std::mem::zeroed() };
        let mut out = std::ptr::null_mut();
        // SAFETY: record, output pointer and buffer are valid for writes.
        let code = unsafe {
            libc::getgrgid_r(
                id as _,
                &mut record,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut out,
            )
        };
        if code != 0 || out.is_null() || record.gr_name.is_null() {
            return None;
        }
        // SAFETY: successful getgrgid_r puts a NUL-terminated name in buffer.
        Some(unsafe { CStr::from_ptr(record.gr_name) }.to_owned())
    } else {
        // SAFETY: passwd is a plain C struct initialized by getpwuid_r.
        let mut record: libc::passwd = unsafe { std::mem::zeroed() };
        let mut out = std::ptr::null_mut();
        // SAFETY: record, output pointer and buffer are valid for writes.
        let code = unsafe {
            libc::getpwuid_r(
                id as _,
                &mut record,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut out,
            )
        };
        if code != 0 || out.is_null() || record.pw_name.is_null() {
            return None;
        }
        // SAFETY: successful getpwuid_r puts a NUL-terminated name in buffer.
        Some(unsafe { CStr::from_ptr(record.pw_name) }.to_owned())
    }
}
pub fn id(name: &CStr, fallback: i64, group: bool) -> i64 {
    let mut buffer = vec![0u8; 16384];
    if group {
        // SAFETY: group is a plain C struct initialized by getgrnam_r.
        let mut record: libc::group = unsafe { std::mem::zeroed() };
        let mut out = std::ptr::null_mut();
        // SAFETY: name is terminated; all destinations are valid for writes.
        let code = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &mut record,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut out,
            )
        };
        if code == 0 && !out.is_null() {
            record.gr_gid.into()
        } else {
            fallback
        }
    } else {
        // SAFETY: passwd is a plain C struct initialized by getpwnam_r.
        let mut record: libc::passwd = unsafe { std::mem::zeroed() };
        let mut out = std::ptr::null_mut();
        // SAFETY: name is terminated; all destinations are valid for writes.
        let code = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                &mut record,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut out,
            )
        };
        if code == 0 && !out.is_null() {
            record.pw_uid.into()
        } else {
            fallback
        }
    }
}

/// Upstream's Darwin `setup_xattrs`: adds `path`'s extended attributes
/// (its target's when `follow`), skipping any it can't read. A failure to
/// list them comes back with upstream's message for it.
#[cfg(all(test, target_vendor = "apple"))]
pub fn read_xattrs(
    path: &Path,
    entry: &mut Entry,
    follow: bool,
) -> Result<(), (std::io::Error, &'static str)> {
    read_xattrs_fd(path, entry, follow, None)
}
#[cfg(target_vendor = "apple")]
pub fn read_xattrs_fd(
    path: &Path,
    entry: &mut Entry,
    follow: bool,
    fd: Option<libc::c_int>,
) -> Result<(), (std::io::Error, &'static str)> {
    let path = path_c(path).map_err(|e| (e, "Couldn't list extended attributes"))?;
    let flags = if follow { 0 } else { libc::XATTR_NOFOLLOW };
    // SAFETY: querying length does not write through the NULL buffer.
    let count = unsafe {
        match fd {
            Some(fd) => libc::flistxattr(fd, std::ptr::null_mut(), 0, 0),
            None => libc::listxattr(path.as_ptr(), std::ptr::null_mut(), 0, flags),
        }
    };
    if count < 0 {
        let e = std::io::Error::last_os_error();
        if [libc::ENOTSUP, libc::ENOSYS].contains(&e.raw_os_error().unwrap_or(0)) {
            return Ok(());
        }
        return Err((e, "Couldn't list extended attributes"));
    }
    if count > 1024 * 1024 {
        let e = std::io::Error::from_raw_os_error(libc::ENOMEM);
        return Err((e, "Couldn't list extended attributes"));
    }
    let mut names = vec![0u8; count as usize];
    // SAFETY: buffer is writable for its full size.
    let count = unsafe {
        match fd {
            Some(fd) => libc::flistxattr(fd, names.as_mut_ptr().cast(), names.len(), 0),
            None => libc::listxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len(), flags),
        }
    };
    if count < 0 {
        let e = std::io::Error::last_os_error();
        return Err((e, "Couldn't retrieve extended attributes"));
    }
    names.truncate(count as usize);
    for name in names.split(|&b| b == 0).filter(|n| !n.is_empty()) {
        let Ok(name) = CString::new(name) else {
            continue;
        };
        // SAFETY: query with no destination only reports value length.
        let len = unsafe {
            match fd {
                Some(fd) => libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0, 0, 0),
                None => libc::getxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    std::ptr::null_mut(),
                    0,
                    0,
                    flags,
                ),
            }
        };
        // Upstream skips an attribute it can't read; a value too large to
        // trust is skipped too.
        if !(0..=16 * 1024 * 1024).contains(&len) {
            continue;
        }
        let mut value = vec![0; len as usize];
        // SAFETY: both C strings and writable value remain live.
        let len = unsafe {
            match fd {
                Some(fd) => libc::fgetxattr(
                    fd,
                    name.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                    0,
                    0,
                ),
                None => libc::getxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                    0,
                    flags,
                ),
            }
        };
        if len >= 0 {
            value.truncate(len as usize);
            entry.xattr_add(&name, &value);
        }
    }
    Ok(())
}
#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
pub fn read_xattrs(
    _path: &Path,
    _entry: &mut Entry,
    _follow: bool,
) -> Result<(), (std::io::Error, &'static str)> {
    Ok(())
}

/// Linux inode flags (`<linux/fs.h>`) that upstream names.
#[cfg(target_os = "linux")]
pub const FS_IMMUTABLE_FL: u32 = 0x10;
#[cfg(target_os = "linux")]
pub const FS_APPEND_FL: u32 = 0x20;
#[cfg(target_os = "linux")]
pub const FS_NODUMP_FL: u32 = 0x40;
#[cfg(target_os = "linux")]
pub const FS_JOURNAL_DATA_FL: u32 = 0x4000;

/// FS_IOC_GETFLAGS: the inode flags of the regular file or directory
/// `fd` is open on. Anything else that a race put under a name opened for
/// its flags gets no ioctl, which a device's driver would take, and fails
/// with ENOTTY, as a file without flags does.
#[cfg(target_os = "linux")]
pub fn get_flags(fd: libc::c_int) -> std::io::Result<u32> {
    let mut st = super::entry::zeroed_stat();
    // SAFETY: writable stat; a descriptor that isn't open only fails.
    result(unsafe { libc::fstat(fd, &mut st) })?;
    if ![libc::S_IFREG, libc::S_IFDIR].contains(&(st.st_mode & libc::S_IFMT)) {
        return Err(std::io::Error::from_raw_os_error(libc::ENOTTY));
    }
    let mut flags: libc::c_int = 0;
    // SAFETY: the ioctl writes one int, to `flags`, which outlives the
    // call; a descriptor that isn't open only fails.
    result(unsafe { libc::ioctl(fd, libc::FS_IOC_GETFLAGS, &mut flags) })?;
    Ok(flags as u32)
}
#[cfg(target_os = "linux")]
fn set_flags(fd: libc::c_int, flags: u32) -> std::io::Result<()> {
    let flags = flags as libc::c_int;
    // SAFETY: the ioctl reads one int, from `flags`, which outlives the
    // call; a descriptor that isn't open only fails.
    result(unsafe { libc::ioctl(fd, libc::FS_IOC_SETFLAGS, &flags) })
}

/// What Linux extended attributes are read from: a descriptor, or a path
/// and whether to follow a symlink there.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub enum Source<'a> {
    Fd(libc::c_int),
    Path(&'a CStr, bool),
}
#[cfg(target_os = "linux")]
fn xattr_size(n: isize) -> std::io::Result<usize> {
    usize::try_from(n).map_err(|_| std::io::Error::last_os_error())
}
#[cfg(target_os = "linux")]
impl Source<'_> {
    /// flistxattr, listxattr or llistxattr: the names into `buf`, or with
    /// an empty `buf` the size they need.
    pub fn list(self, buf: &mut [u8]) -> std::io::Result<usize> {
        let ptr = if buf.is_empty() {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr().cast()
        };
        // SAFETY: `ptr` is NULL with a length of 0, or `buf`, writable for
        // its length; the path is terminated.
        xattr_size(unsafe {
            match self {
                Source::Fd(fd) => libc::flistxattr(fd, ptr, buf.len()),
                Source::Path(p, true) => libc::listxattr(p.as_ptr(), ptr, buf.len()),
                Source::Path(p, false) => libc::llistxattr(p.as_ptr(), ptr, buf.len()),
            }
        })
    }
    /// fgetxattr, getxattr or lgetxattr: the value of `name` into `buf`,
    /// or with an empty `buf` its size.
    pub fn get(self, name: &CStr, buf: &mut [u8]) -> std::io::Result<usize> {
        let ptr = if buf.is_empty() {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr().cast()
        };
        let name = name.as_ptr();
        // SAFETY: `ptr` is NULL with a length of 0, or `buf`, writable for
        // its length; the name and path are terminated.
        xattr_size(unsafe {
            match self {
                Source::Fd(fd) => libc::fgetxattr(fd, name, ptr, buf.len()),
                Source::Path(p, true) => libc::getxattr(p.as_ptr(), name, ptr, buf.len()),
                Source::Path(p, false) => libc::lgetxattr(p.as_ptr(), name, ptr, buf.len()),
            }
        })
    }
    /// fstat, stat or lstat.
    pub fn stat(self) -> std::io::Result<libc::stat> {
        let mut st = super::entry::zeroed_stat();
        // SAFETY: the path is terminated and `st` writable.
        result(unsafe {
            match self {
                Source::Fd(fd) => libc::fstat(fd, &mut st),
                Source::Path(p, true) => libc::stat(p.as_ptr(), &mut st),
                Source::Path(p, false) => libc::lstat(p.as_ptr(), &mut st),
            }
        })?;
        Ok(st)
    }
}

/// lseek on a descriptor.
#[cfg(target_os = "linux")]
pub fn seek(fd: libc::c_int, offset: i64, whence: libc::c_int) -> std::io::Result<i64> {
    // SAFETY: lseek takes no pointers; a descriptor that isn't open fails.
    let at = unsafe { libc::lseek(fd, offset, whence) };
    if at < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(at)
}

/// The extents one FS_IOC_FIEMAP call returns: as many as fit in
/// upstream's 4096-byte buffer.
#[cfg(target_os = "linux")]
const FIEMAP_EXTENTS: usize = (4096 - 32) / 56;
#[cfg(target_os = "linux")]
pub const FIEMAP_FLAG_SYNC: u32 = 0x1;
#[cfg(target_os = "linux")]
pub const FIEMAP_EXTENT_LAST: u32 = 0x1;
#[cfg(target_os = "linux")]
pub const FIEMAP_EXTENT_UNWRITTEN: u32 = 0x800;

/// `<linux/fiemap.h>`'s struct fiemap_extent.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FiemapExtent {
    pub fe_logical: u64,
    pub fe_physical: u64,
    pub fe_length: u64,
    fe_reserved64: [u64; 2],
    pub fe_flags: u32,
    fe_reserved: [u32; 3],
}

/// `<linux/fiemap.h>`'s struct fiemap, with room for its extents.
#[cfg(target_os = "linux")]
#[repr(C)]
pub struct Fiemap {
    pub fm_start: u64,
    fm_length: u64,
    fm_flags: u32,
    fm_mapped_extents: u32,
    fm_extent_count: u32,
    fm_reserved: u32,
    fm_extents: [FiemapExtent; FIEMAP_EXTENTS],
}
#[cfg(target_os = "linux")]
impl Fiemap {
    /// Upstream's request: every extent from the start, synced first.
    pub fn new() -> Self {
        Fiemap {
            fm_start: 0,
            fm_length: !0,
            fm_flags: FIEMAP_FLAG_SYNC,
            fm_mapped_extents: 0,
            fm_extent_count: FIEMAP_EXTENTS as u32,
            fm_reserved: 0,
            fm_extents: [FiemapExtent::default(); FIEMAP_EXTENTS],
        }
    }
    /// FS_IOC_FIEMAP on `fd` (struct fiemap is 32 bytes before its extents).
    pub fn map(&mut self, fd: libc::c_int) -> std::io::Result<()> {
        const FS_IOC_FIEMAP: libc::Ioctl = libc::_IOWR::<[u64; 4]>(b'f' as u32, 11);
        self.fm_extent_count = FIEMAP_EXTENTS as u32;
        self.fm_mapped_extents = 0;
        // SAFETY: `self` is a struct fiemap whose fm_extent_count is the
        // length of its extent array, which bounds what the kernel writes.
        result(unsafe { libc::ioctl(fd, FS_IOC_FIEMAP, self as *mut Self) })
    }
    /// The extents the last call mapped.
    pub fn extents(&self) -> &[FiemapExtent] {
        let n = (self.fm_mapped_extents as usize).min(FIEMAP_EXTENTS);
        self.fm_extents.get(..n).unwrap_or_default()
    }
}

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Component;

// Darwin 21 (macOS 12) and later have the verified O_NOFOLLOW_ANY behavior.
// Unknown versions stay on the component walker; old kernels may ignore new flags.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn supports_nofollow_any() -> bool {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        // SAFETY: utsname consists entirely of fixed-size character arrays; zero is valid.
        let mut info: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY: info is a live, correctly sized writable utsname; uname retains no pointer.
        if unsafe { libc::uname(&mut info) } != 0 {
            return false;
        }
        let release = info.release.map(|c| c as u8);
        let Some(end) = release.iter().position(|&c| c == b'.') else {
            return false;
        };
        let digits = &release[..end];
        digits.iter().all(u8::is_ascii_digit)
            && std::str::from_utf8(digits)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|major| major >= 21)
    })
}

/// Upstream's la_opendirat: a directory opened only to look names up in it.
fn open_dir(dir: libc::c_int, name: &CStr, follow: bool) -> std::io::Result<File> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let search = libc::O_PATH;
    #[cfg(target_vendor = "apple")]
    let search = libc::O_SEARCH;
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    let search = libc::O_RDONLY;
    let nofollow = if follow { 0 } else { libc::O_NOFOLLOW };
    // SAFETY: dir is AT_FDCWD or a live descriptor and name is terminated.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            search | libc::O_DIRECTORY | libc::O_CLOEXEC | nofollow,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub fn fstat(file: &File) -> std::io::Result<libc::stat> {
    let mut st = super::entry::zeroed_stat();
    // SAFETY: live descriptor and writable stat.
    result(unsafe { libc::fstat(file.as_raw_fd(), &mut st) })?;
    Ok(st)
}
fn stat_at(dir: &File, name: &CStr, follow: bool) -> std::io::Result<libc::stat> {
    let mut st = super::entry::zeroed_stat();
    let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
    // SAFETY: live descriptor, terminated name and writable stat.
    result(unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, flags) })?;
    Ok(st)
}

/// Why `check_symlinks` refused a path: upstream's status, errno and
/// message, which goes before the path.
pub type SymlinkError = (libc::c_int, libc::c_int, &'static str);

/// Upstream's check_symlinks_fsobj, the variant with openat: walks `path`
/// (cleaned up) and refuses a symlink along it, or removes it: the last
/// element, unless it is a hardlink's target (`linkname`), and any other
/// with `unlink`. Without `secure` it follows a symlink to a directory.
pub fn check_symlinks(
    path: &[u8],
    unlink: bool,
    secure: bool,
    linkname: bool,
) -> Result<(), SymlinkError> {
    use crate::archive::{ARCHIVE_FAILED, ARCHIVE_FATAL};
    let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
    if path.is_empty() {
        return Ok(());
    }
    let mut dir = open_dir(libc::AT_FDCWD, c".", true)
        .map_err(|e| (ARCHIVE_FATAL, errno(e), "Could not open "))?;
    let mut head = 0;
    let mut tail = usize::from(path.starts_with(b"/"));
    loop {
        while path.get(tail) == Some(&b'/') {
            tail += 1;
        }
        while path.get(tail).is_some_and(|&b| b != b'/') {
            tail += 1;
        }
        let last = tail + 1 >= path.len();
        let Ok(segment) = CString::new(path.get(head..tail).unwrap_or_default()) else {
            return Err((ARCHIVE_FAILED, libc::EINVAL, "Could not stat "));
        };
        match stat_at(&dir, &segment, false) {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
            Err(e) => return Err((ARCHIVE_FAILED, errno(e), "Could not stat ")),
            Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFDIR => {
                if !last {
                    dir = open_dir(dir.as_raw_fd(), &segment, false)
                        .map_err(|e| (ARCHIVE_FATAL, errno(e), "Could not chdir "))?;
                    head = tail + 1;
                }
            }
            Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFLNK => {
                // Hardlinks to symlinks are safe: linkat does not follow them.
                if last && linkname {
                    return Ok(());
                }
                if last || unlink {
                    // SAFETY: live descriptor and terminated name.
                    if unsafe { libc::unlinkat(dir.as_raw_fd(), segment.as_ptr(), 0) } != 0 {
                        return Err(if last {
                            let e = std::io::Error::last_os_error();
                            (ARCHIVE_FAILED, errno(e), "Could not remove symlink ")
                        } else {
                            (
                                ARCHIVE_FAILED,
                                libc::EIO,
                                "Cannot remove intervening symlink ",
                            )
                        });
                    }
                    if last {
                        return Ok(());
                    }
                } else if !secure {
                    // Follow a symlink to a directory; hardlinks over symlinks need it.
                    match stat_at(&dir, &segment, true) {
                        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
                        Err(e) => return Err((ARCHIVE_FAILED, errno(e), "Could not stat ")),
                        Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFDIR => {
                            dir = open_dir(dir.as_raw_fd(), &segment, true)
                                .map_err(|e| (ARCHIVE_FATAL, errno(e), "Could not chdir "))?;
                            head = tail + 1;
                        }
                        Ok(_) => {
                            return Err((
                                ARCHIVE_FAILED,
                                libc::ELOOP,
                                "Cannot extract through symlink ",
                            ));
                        }
                    }
                } else {
                    return Err((
                        ARCHIVE_FAILED,
                        libc::ELOOP,
                        "Cannot extract through symlink ",
                    ));
                }
            }
            Ok(_) => {}
        }
        if last {
            return Ok(());
        }
        tail += 1;
    }
}

/// What upstream's create_dir reports, for the directory it names.
#[derive(Debug)]
pub enum DirError {
    /// "Can't create directory": a non-directory is in the way under
    /// NO_OVERWRITE.
    Exists,
    /// "...: Conflicting file cannot be removed".
    Conflict(std::io::Error),
    /// "Can't test directory".
    Test(std::io::Error),
    /// "Failed to create dir".
    Mkdir(std::io::Error),
}

/// Upstream's create_dir for an entry's parent `path` (cleaned up): makes
/// each missing directory, first removing a non-directory in its place.
/// Like upstream it follows symlinks, except with `secure`, where
/// check_symlinks has already removed or refused them. New directories get
/// upstream's mode, (0777 & ~umask | 0700) & 0775: its fixup to the final
/// mode never applies (see NOTES.md).
pub fn create_dir(
    path: &Path,
    secure: bool,
    no_overwrite: bool,
    umask: u32,
) -> Result<(), (PathBuf, DirError)> {
    let mode = ((0o777 & !umask) | 0o700) & 0o775;
    let test = |e| (path.to_path_buf(), DirError::Test(e));
    let start = if path.is_absolute() { c"/" } else { c"." };
    let mut dir = open_dir(libc::AT_FDCWD, start, true).map_err(test)?;
    let components: Vec<_> = path.components().collect();
    let mut prefix = PathBuf::new();
    for (i, component) in components.iter().enumerate() {
        prefix.push(component);
        let name = match component {
            Component::Normal(name) => CString::new(name.as_bytes())
                .map_err(|_| test(std::io::Error::from_raw_os_error(libc::EINVAL)))?,
            Component::ParentDir => c"..".to_owned(),
            _ => continue,
        };
        let missing = *component != Component::ParentDir
            && match stat_at(&dir, &name, !secure) {
                Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFDIR => false,
                Ok(_) if no_overwrite => return Err((prefix, DirError::Exists)),
                Ok(_) => {
                    // SAFETY: live descriptor and terminated name.
                    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                        let e = std::io::Error::last_os_error();
                        return Err((prefix, DirError::Conflict(e)));
                    }
                    true
                }
                Err(e) if [Some(libc::ENOENT), Some(libc::ENOTDIR)].contains(&e.raw_os_error()) => {
                    true
                }
                Err(e) => return Err(test(e)),
            };
        // SAFETY: live descriptor and terminated name.
        if missing && unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode as _) } != 0 {
            let e = std::io::Error::last_os_error();
            // Without this check, a/b/../b/c/d fails at the second visit to b.
            let errno = match (e.raw_os_error(), stat_at(&dir, &name, true)) {
                (Some(libc::EEXIST), Ok(st)) if st.st_mode & libc::S_IFMT == libc::S_IFDIR => None,
                (Some(libc::EEXIST), Ok(_)) => Some(libc::ENOTDIR),
                (Some(libc::EEXIST), Err(_)) => Some(libc::EEXIST),
                (errno, _) => Some(errno.unwrap_or(libc::EIO)),
            };
            if let Some(errno) = errno {
                let e = std::io::Error::from_raw_os_error(errno);
                return Err((prefix, DirError::Mkdir(e)));
            }
        }
        match open_dir(dir.as_raw_fd(), &name, !secure) {
            Ok(next) => dir = next,
            // Upstream stops here too; creating the entry fails the same way.
            Err(_) if i + 1 == components.len() => return Ok(()),
            Err(e) => return Err(test(e)),
        }
    }
    Ok(())
}

/// Holds the destination directory open so renames cannot redirect extraction.
pub struct Target {
    parent: File,
    name: CString,
    live: Option<File>,
}
impl Target {
    pub fn retain_file(&mut self, file: File) {
        self.live = Some(file);
    }
    /// Whether metadata goes through a descriptor kept open for it.
    pub fn is_open(&self) -> bool {
        self.live.is_some()
    }
    /// Opens the entry for its fixup at close: never a symlink, never
    /// waiting on a FIFO.
    pub fn fixup_file(&self, directory: bool) -> std::io::Result<File> {
        let directory = if directory { libc::O_DIRECTORY } else { 0 };
        // SAFETY: live parent/name; openat returns a new owned descriptor.
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | directory,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful open returns a uniquely owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    pub fn directory_file(&self) -> std::io::Result<File> {
        // SAFETY: live parent/name; directory-only open never follows a final symlink.
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful open returns a uniquely owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    pub fn prepare(path: &Path, secure: bool) -> std::io::Result<Self> {
        let mut components = path.components();
        let last = components
            .next_back()
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let name = if last == Component::RootDir {
            c".".to_owned()
        } else {
            CString::new(last.as_os_str().as_bytes())
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?
        };
        let start = if path.is_absolute() { c"/" } else { c"." };
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if supports_nofollow_any() {
            use std::os::unix::fs::OpenOptionsExt;
            let path = components.as_path();
            let path = if path.as_os_str().is_empty() {
                Path::new(if last == Component::RootDir { "/" } else { "." })
            } else {
                path
            };
            // O_SEARCH: like upstream's paths, this needs only search
            // permission on the parent.
            let nofollow = if secure { libc::O_NOFOLLOW_ANY } else { 0 };
            if let Ok(parent) = File::options()
                .read(true)
                .custom_flags(libc::O_SEARCH | nofollow)
                .open(path)
            {
                return Ok(Self {
                    parent,
                    name,
                    live: None,
                });
            }
        }
        let mut parent = open_dir(libc::AT_FDCWD, start, true)?;
        for component in components {
            if matches!(component, Component::CurDir | Component::RootDir) {
                continue;
            }
            let part = CString::new(component.as_os_str().as_bytes())
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
            parent = open_dir(parent.as_raw_fd(), &part, !secure)?;
        }
        Ok(Self {
            parent,
            name,
            live: None,
        })
    }
    /// The stat of the entry: through its descriptor when one is held, as
    /// upstream's lazy_stat, otherwise of the name without following it.
    pub fn stat(&self) -> std::io::Result<libc::stat> {
        if let Some(file) = &self.live {
            return fstat(file);
        }
        stat_at(&self.parent, &self.name, false)
    }
    /// The stat of what a symlink here points to.
    pub fn stat_follow(&self) -> std::io::Result<libc::stat> {
        stat_at(&self.parent, &self.name, true)
    }
    pub fn remove(&self, directory: bool) -> std::io::Result<()> {
        // SAFETY: parent/name designate a directory entry; no borrowed memory is modified.
        result(unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                if directory { libc::AT_REMOVEDIR } else { 0 },
            )
        })
    }
    pub fn mkdir(&self, mode: u32) -> std::io::Result<()> {
        // SAFETY: valid live descriptor and terminated name.
        result(unsafe { libc::mkdirat(self.parent.as_raw_fd(), self.name.as_ptr(), mode as _) })
    }
    pub fn open(&self, mode: u32, exclusive: bool) -> std::io::Result<File> {
        // SAFETY: openat returns a new owned descriptor; O_NOFOLLOW rejects final symlinks.
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | if exclusive {
                        libc::O_EXCL
                    } else {
                        libc::O_TRUNC
                    }
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fd is successfully opened and uniquely owned.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    pub fn symlink(&self, path: &Path) -> std::io::Result<()> {
        let path = path_c(path)?;
        // SAFETY: both strings and parent descriptor remain live.
        result(unsafe {
            libc::symlinkat(path.as_ptr(), self.parent.as_raw_fd(), self.name.as_ptr())
        })
    }
    pub fn hardlink(&self, source: &Target) -> std::io::Result<()> {
        // linkat without AT_SYMLINK_FOLLOW links a symlink itself.
        // SAFETY: live source/dest parent fds and names; no pointer is retained.
        result(unsafe {
            libc::linkat(
                source.parent.as_raw_fd(),
                source.name.as_ptr(),
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                0,
            )
        })
    }
    // Mode, owner and times go through the entry's descriptor when one is
    // held, as upstream's fchmod, fchown and futimens; otherwise they act on
    // the name without following it, as lchmod, lchown and lutimes.
    pub fn chmod(&self, mode: u32) -> std::io::Result<()> {
        if let Some(file) = &self.live {
            // SAFETY: live descriptor; fchmod takes no pointers.
            return result(unsafe { libc::fchmod(file.as_raw_fd(), mode as _) });
        }
        // SAFETY: live parent/name, and no follow prevents replacing another target.
        result(unsafe {
            libc::fchmodat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                mode as _,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })
    }
    pub fn owner(&self, uid: i64, gid: i64) -> std::io::Result<()> {
        if let Some(file) = &self.live {
            // SAFETY: live descriptor; fchown takes no pointers.
            return result(unsafe { libc::fchown(file.as_raw_fd(), uid as _, gid as _) });
        }
        // SAFETY: live parent/name with final symlink not followed.
        result(unsafe {
            libc::fchownat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                uid as _,
                gid as _,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })
    }
    /// Sets the access and modification times, each (seconds, nanoseconds).
    pub fn times(&self, atime: (i64, i64), mtime: (i64, i64)) -> std::io::Result<()> {
        let times = [atime, mtime].map(|(tv_sec, tv_nsec)| libc::timespec {
            tv_sec: tv_sec as _,
            tv_nsec: tv_nsec as _,
        });
        if let Some(file) = &self.live {
            // SAFETY: live descriptor and two timespecs that outlive the call.
            return result(unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) });
        }
        // SAFETY: two writable-by-value timespecs, live descriptor and name.
        result(unsafe {
            libc::utimensat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })
    }
    pub fn special(&self, mode: u32, dev: u64) -> std::io::Result<()> {
        // SAFETY: live parent descriptor and terminated name.
        result(unsafe {
            libc::mknodat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                mode as _,
                dev as _,
            )
        })
    }
}

pub fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// Upstream's __archive_get_umask. Linux reports it in /proc/self/status
/// (since 4.7), which upstream reads rather than set the umask while other
/// threads may be creating files.
pub fn umask() -> u32 {
    #[cfg(target_os = "linux")]
    if let Ok(status) = std::fs::read("/proc/self/status")
        && let Some(mask) = status.split(|&b| b == b'\n').find_map(|line| {
            let digits = line.strip_prefix(b"Umask:")?.trim_ascii_start();
            let end = digits
                .iter()
                .position(|b| !(b'0'..=b'7').contains(b))
                .unwrap_or(digits.len());
            u32::from_str_radix(std::str::from_utf8(digits.get(..end)?).ok()?, 8).ok()
        })
    {
        return mask;
    }
    // SAFETY: umask has no pointer arguments; restore immediately, as upstream does.
    unsafe {
        let mask = libc::umask(0);
        libc::umask(mask);
        u32::from(mask)
    }
}

#[cfg(target_vendor = "apple")]
unsafe extern "C" {
    fn copyfile(
        from: *const libc::c_char,
        to: *const libc::c_char,
        state: *mut std::ffi::c_void,
        flags: u32,
    ) -> libc::c_int;
    fn fcopyfile(
        from: libc::c_int,
        to: libc::c_int,
        state: *mut std::ffi::c_void,
        flags: u32,
    ) -> libc::c_int;
}
#[cfg(target_vendor = "apple")]
fn temporary() -> std::io::Result<File> {
    let mut name = crate::ffi::util::get_tempdir()
        .join("libarchive-metadata.XXXXXX")
        .as_os_str()
        .as_bytes()
        .to_vec();
    name.push(0);
    // SAFETY: mkstemp receives writable NUL-terminated template, returns a unique owned fd.
    let fd = unsafe { libc::mkstemp(name.as_mut_ptr().cast()) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: name is still NUL-terminated; unlink removes exactly our newly created temporary file.
    unsafe { libc::unlink(name.as_ptr().cast()) };
    // SAFETY: successful mkstemp returned an owned file descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
#[cfg(target_vendor = "apple")]
pub fn pack_mac_metadata(
    path: &Path,
    entry: &mut Entry,
    fd: Option<libc::c_int>,
) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let path = path_c(path)?;
    // SAFETY: live pathname or descriptor; NULL destination only queries metadata.
    let check = unsafe {
        match fd {
            Some(fd) => {
                let count = libc::flistxattr(fd, std::ptr::null_mut(), 0, 0);
                if count < 0 {
                    -1
                } else {
                    libc::c_int::from(count > 0 || super::disk_acl::has_acl(fd))
                }
            }
            None => copyfile(
                path.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                (1 << 16) | 1 | 4,
            ),
        }
    };
    if check == 0 {
        return Ok(());
    }
    if check < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: valid string, descriptor uniquely owned on success; O_SYMLINK avoids target following.
    let fd = unsafe {
        match fd {
            Some(fd) => libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0),
            None => libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC,
            ),
        }
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is successfully opened and uniquely owned.
    let source = unsafe { File::from_raw_fd(fd) };
    let mut tmp = temporary()?;
    // SAFETY: descriptors remain live throughout native copyfile metadata packing.
    result(unsafe {
        fcopyfile(
            source.as_raw_fd(),
            tmp.as_raw_fd(),
            std::ptr::null_mut(),
            (1 << 22) | 1 | 4,
        )
    })?;
    let size = tmp.metadata()?.len();
    if size > 16 * 1024 * 1024 {
        return Err(std::io::Error::from_raw_os_error(libc::ENOMEM));
    }
    if size > 0 {
        let mut bytes = Vec::with_capacity(size as usize);
        tmp.seek(SeekFrom::Start(0))?;
        tmp.read_to_end(&mut bytes)?;
        entry.copy_mac_metadata(&bytes);
    }
    Ok(())
}
#[cfg(not(target_vendor = "apple"))]
pub fn pack_mac_metadata(
    _path: &Path,
    _entry: &mut Entry,
    _fd: Option<libc::c_int>,
) -> std::io::Result<()> {
    Ok(())
}

impl Target {
    #[cfg(target_vendor = "apple")]
    pub fn metadata_file(&self) -> std::io::Result<File> {
        if let Some(file) = &self.live {
            return file.try_clone();
        }
        // O_NONBLOCK: opening a FIFO for reading would otherwise wait for a
        // writer; it changes nothing for other file types.
        // SAFETY: valid descriptor/name; O_SYMLINK opens link itself, never its target.
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_RDONLY | libc::O_SYMLINK | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: opened descriptor is uniquely owned.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    #[cfg(target_vendor = "apple")]
    pub fn unpack_mac_metadata(&self, data: &[u8]) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        let mut tmp = temporary()?;
        tmp.write_all(data)?;
        tmp.seek(SeekFrom::Start(0))?;
        let dest = self.metadata_file()?;
        // SAFETY: live descriptors and NULL state per fcopyfile API; only metadata is copied.
        result(unsafe {
            fcopyfile(
                tmp.as_raw_fd(),
                dest.as_raw_fd(),
                std::ptr::null_mut(),
                (1 << 23) | 1 | 4,
            )
        })
    }
    #[cfg(not(target_vendor = "apple"))]
    pub fn unpack_mac_metadata(&self, _data: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    #[cfg(target_vendor = "apple")]
    pub fn flags(&self, set: u32, clear: u32) -> std::io::Result<()> {
        if set | clear == 0 {
            return Ok(());
        }
        let file = self.metadata_file()?;
        let mut flags = (self.stat()?.st_flags & !clear) | set;
        // Only the super-user may change SF_* flags.
        if euid() != 0 {
            flags &= !(libc::SF_APPEND | libc::SF_ARCHIVED | libc::SF_IMMUTABLE | 0x0010_0000);
        }
        // SAFETY: live file descriptor; fchflags does not access borrowed memory.
        result(unsafe { libc::fchflags(file.as_raw_fd(), flags) })
    }
    /// Upstream's Linux set_fflags_platform, past its file type check:
    /// changes the flags through the entry's descriptor or one opened here
    /// (if that fails there is nothing to do), keeping the flags only root
    /// may change as they are if setting them is refused.
    #[cfg(target_os = "linux")]
    pub fn flags(&self, set: u32, clear: u32) -> std::io::Result<()> {
        const SF_MASK: u32 = FS_IMMUTABLE_FL | FS_APPEND_FL | FS_JOURNAL_DATA_FL;
        if set | clear == 0 {
            return Ok(());
        }
        let opened;
        let fd = match &self.live {
            Some(file) => file.as_raw_fd(),
            None => match self.fixup_file(false) {
                Ok(file) => {
                    opened = file;
                    opened.as_raw_fd()
                }
                Err(_) => return Ok(()),
            },
        };
        let old = get_flags(fd)?;
        let new = (old & !clear) | set;
        match set_flags(fd, new) {
            // If we couldn't set all the flags, try again with a subset.
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                set_flags(fd, (new & !SF_MASK) | (old & SF_MASK))
            }
            r => r,
        }
    }
    #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
    pub fn flags(&self, _set: u32, _clear: u32) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Target {
    /// Sets an extended attribute through the entry's descriptor, or else
    /// by its name without following a symlink there, as upstream's
    /// fsetxattr and lsetxattr. An ACL's attribute too, which libacl's
    /// acl_set_file sets following one: only a symlink swapped in after
    /// the entry was made could be followed, and the kernel keeps no ACLs
    /// on symlinks.
    pub fn xattr(&self, name: &CStr, value: &[u8]) -> std::io::Result<()> {
        if let Some(file) = &self.live {
            // SAFETY: live descriptor, terminated name, and a value
            // readable for its length; the kernel copies it.
            return result(unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            });
        }
        // The calls that take only a path reach the entry through the
        // parent held open for it.
        let mut path = format!("/proc/self/fd/{}/", self.parent.as_raw_fd()).into_bytes();
        path.extend_from_slice(self.name.as_bytes());
        let path =
            CString::new(path).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        // SAFETY: terminated path and name, and a value readable for its
        // length; the kernel copies it.
        result(unsafe {
            libc::lsetxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        })
    }
}

impl Target {
    #[cfg(target_vendor = "apple")]
    pub fn compression_file(&self) -> std::io::Result<File> {
        // SAFETY: live parent descriptor/name; opens existing file without following symlinks.
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful open returns uniquely owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    #[cfg(target_vendor = "apple")]
    pub fn xattr(&self, name: &CStr, value: &[u8]) -> std::io::Result<()> {
        let file = self.metadata_file()?;
        // SAFETY: name/value buffers and fd remain live; fsetxattr copies the value.
        result(unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                0,
            )
        })
    }
}
impl Target {
    #[cfg(target_vendor = "apple")]
    pub fn sibling(&self, name: &[u8]) -> std::io::Result<Self> {
        if name.is_empty() || name.contains(&b'/') {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(Self {
            parent: self.parent.try_clone()?,
            live: None,
            name: CString::new(name)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?,
        })
    }
    #[cfg(target_vendor = "apple")]
    pub fn read_file(&self) -> std::io::Result<File> {
        // O_NONBLOCK: a FIFO has no writer to wait for.
        // SAFETY: live parent/name; final symlink not followed.
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: descriptor returned by openat is uniquely owned.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
impl Target {
    pub fn xattr(&self, _name: &CStr, _value: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
}
impl Target {
    pub fn atomic_file(&self, mode: u32) -> std::io::Result<(Self, File)> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        for _ in 0..100 {
            let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let name = CString::new(format!(".libarchive-{}-{serial}", std::process::id()))
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
            // SAFETY: parent/name live; O_EXCL returns a uniquely owned new file descriptor.
            let fd = unsafe {
                libc::openat(
                    self.parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    mode as libc::c_uint,
                )
            };
            if fd < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                return Err(e);
            }
            // SAFETY: descriptor belongs uniquely to the newly created temporary file.
            let file = unsafe { File::from_raw_fd(fd) };
            let parent = match self.parent.try_clone() {
                Ok(parent) => parent,
                Err(e) => {
                    // SAFETY: cleanup removes the exact file just created by this call.
                    unsafe { libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), 0) };
                    return Err(e);
                }
            };
            return Ok((
                Self {
                    parent,
                    name,
                    live: None,
                },
                file,
            ));
        }
        Err(std::io::Error::from_raw_os_error(libc::EEXIST))
    }
    pub fn rename_to(&self, target: &Self) -> std::io::Result<()> {
        // SAFETY: both descriptors and names are valid and retained throughout call.
        result(unsafe {
            libc::renameat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                target.parent.as_raw_fd(),
                target.name.as_ptr(),
            )
        })
    }
}

/// What upstream's setup_current_filesystem learns of a file system:
/// whether it is remote and synthetic (1, 0, or -1 for unknown), whether
/// it is mounted noatime, and the size of the blocks its files are read in.
#[derive(Clone, Copy)]
pub struct Filesystem {
    pub remote: libc::c_int,
    pub synthetic: libc::c_int,
    pub noatime: bool,
    pub block_size: usize,
}

#[cfg(all(test, target_vendor = "apple"))]
pub fn filesystem(path: &Path, follow: bool) -> Result<Filesystem, (std::io::Error, &'static str)> {
    let inspect =
        if follow || std::fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_symlink()) {
            path
        } else {
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
        };
    let failed = |e| (e, "statfs failed");
    let file = open_read(inspect, libc::O_NONBLOCK).map_err(failed)?;
    filesystem_fd(&file)
}
#[cfg(target_vendor = "apple")]
pub fn filesystem_fd(file: &File) -> Result<Filesystem, (std::io::Error, &'static str)> {
    let failed = |e| (e, "statfs failed");
    // SAFETY: statfs is a plain C struct with integer and byte-array fields.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: live pathname and writable statfs destination.
    result(unsafe { libc::fstatfs(file.as_raw_fd(), &mut st) }).map_err(failed)?;
    Ok(Filesystem {
        remote: libc::c_int::from(st.f_flags & libc::MNT_LOCAL as u32 == 0),
        synthetic: -1,
        noatime: st.f_flags & libc::MNT_NOATIME as u32 != 0,
        block_size: 64 * 1024,
    })
}

/// Upstream's Linux setup_current_filesystem for `path`: the directory
/// being read, or with `target` a symlink's target on another file
/// system, which upstream opens (with O_NONBLOCK here, so that a FIFO
/// can't hang the walk).
#[cfg(all(test, target_os = "linux"))]
pub fn filesystem(path: &Path, target: bool) -> Result<Filesystem, (std::io::Error, &'static str)> {
    let file = if target {
        Some(open_read(path, libc::O_NONBLOCK).map_err(|e| (e, "openat failed"))?)
    } else {
        None
    };
    let fd = file.as_ref().map(AsRawFd::as_raw_fd);
    filesystem_impl(path, fd)
}
#[cfg(target_os = "linux")]
pub fn filesystem_fd(file: &File) -> Result<Filesystem, (std::io::Error, &'static str)> {
    filesystem_impl(Path::new("."), Some(file.as_raw_fd()))
}
#[cfg(target_os = "linux")]
fn filesystem_impl(
    path: &Path,
    fd: Option<libc::c_int>,
) -> Result<Filesystem, (std::io::Error, &'static str)> {
    const AFS_SUPER_MAGIC: u32 = 0x5346_414f;
    const CIFS_SUPER_MAGIC: u32 = 0xff53_4d42;
    const CODA_SUPER_MAGIC: u32 = 0x7375_7245;
    const NCP_SUPER_MAGIC: u32 = 0x564c;
    const NFS_SUPER_MAGIC: u32 = 0x6969;
    const SMB_SUPER_MAGIC: u32 = 0x517b;
    const DEVFS_SUPER_MAGIC: u32 = 0x1373;
    const PROC_SUPER_MAGIC: u32 = 0x9fa0;
    const USBDEVICE_SUPER_MAGIC: u32 = 0x9fa2;
    let failed = |e| (e, "statfs failed");
    let path = path_c(path).map_err(failed)?;
    // SAFETY: statvfs and statfs are plain C structs of integers.
    let (mut vfs, mut sfs): (libc::statvfs, libc::statfs) = unsafe { std::mem::zeroed() };
    // SAFETY: live descriptor or terminated path, and writable structs.
    let vr = result(unsafe {
        match fd {
            Some(fd) => libc::fstatvfs(fd, &mut vfs),
            None => libc::statvfs(path.as_ptr(), &mut vfs),
        }
    });
    // SAFETY: as above.
    result(unsafe {
        match fd {
            Some(fd) => libc::fstatfs(fd, &mut sfs),
            None => libc::statfs(path.as_ptr(), &mut sfs),
        }
    })
    .map_err(failed)?;
    // Upstream's get_xfer_size. errno is cleared first: a name the file
    // system has no value for gives -1 and leaves it alone.
    // SAFETY: errno is this thread's own.
    unsafe { *libc::__errno_location() = 0 };
    let sizes = [
        libc::_PC_REC_INCR_XFER_SIZE,
        libc::_PC_REC_MAX_XFER_SIZE,
        libc::_PC_REC_MIN_XFER_SIZE,
        libc::_PC_REC_XFER_ALIGN,
    ]
    .map(|name| {
        // SAFETY: live descriptor or terminated path; no pointer is kept.
        unsafe {
            match fd {
                Some(fd) => libc::fpathconf(fd, name),
                None => libc::pathconf(path.as_ptr(), name),
            }
        }
    });
    let errno = std::io::Error::last_os_error();
    vr.map_err(failed)?;
    let [incr, max, min, align] = match sizes {
        [.., -1] if errno.raw_os_error() == Some(libc::EINVAL) => {
            // pathconf(_PC_REC_*) operations are not supported.
            let size = |n: libc::c_ulong| if n > 0 { n as libc::c_long } else { -1 };
            [size(vfs.f_bsize), -1, size(vfs.f_bsize), size(vfs.f_frsize)]
        }
        [.., -1] => return Err(failed(errno)),
        sizes => sizes,
    };
    let (remote, synthetic) = match sfs.f_type as u32 {
        AFS_SUPER_MAGIC | CIFS_SUPER_MAGIC | CODA_SUPER_MAGIC | NCP_SUPER_MAGIC
        | NFS_SUPER_MAGIC | SMB_SUPER_MAGIC => (1, 0),
        DEVFS_SUPER_MAGIC | PROC_SUPER_MAGIC | USBDEVICE_SUPER_MAGIC => (0, 1),
        _ => (0, 0),
    };
    Ok(Filesystem {
        remote,
        synthetic,
        noatime: vfs.f_flag & libc::ST_NOATIME != 0,
        block_size: read_block_size(incr, max, min, align),
    })
}

/// The size of upstream's read buffer for a file system with these
/// transfer sizes (setup_suitable_read_buffer): the maximum, or else the
/// minimum grown by the increment to at least 64 KiB. Where upstream would
/// grow it forever or read nothing, it is 64 KiB; it is at most 16 MiB.
#[cfg(target_os = "linux")]
fn read_block_size(
    incr: libc::c_long,
    max: libc::c_long,
    min: libc::c_long,
    align: libc::c_long,
) -> usize {
    const MIN: libc::c_long = 64 * 1024;
    let align = if align == -1 { 4096 } else { align };
    let size = if max != -1 {
        max
    } else {
        let (mut size, incr) = if min < 0 {
            (align, align)
        } else {
            (min, if incr < 0 { min } else { incr })
        };
        if size < MIN && incr <= 0 {
            return MIN as usize;
        }
        while size < MIN {
            size = size.saturating_add(incr);
        }
        size
    };
    match usize::try_from(size) {
        Ok(0) | Err(_) => MIN as usize,
        Ok(size) => size.min(16 * 1024 * 1024),
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
pub fn filesystem(
    _path: &Path,
    _follow: bool,
) -> Result<Filesystem, (std::io::Error, &'static str)> {
    Ok(Filesystem {
        remote: -1,
        synthetic: -1,
        noatime: false,
        block_size: 64 * 1024,
    })
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
pub fn filesystem_fd(_file: &File) -> Result<Filesystem, (std::io::Error, &'static str)> {
    filesystem(Path::new("."), false)
}

#[cfg(not(target_os = "linux"))]
pub fn sparse(
    path: &Path,
    follow: bool,
    size: i64,
    fd: Option<libc::c_int>,
) -> std::io::Result<Vec<(i64, i64)>> {
    if size <= 0 {
        return Ok(Vec::new());
    }
    let path = path_c(path)?;
    // SAFETY: live pathname; successful descriptor is newly owned.
    let fd = unsafe {
        match fd {
            Some(fd) => libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0),
            None => libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | if follow { 0 } else { libc::O_NOFOLLOW },
            ),
        }
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd belongs uniquely to this call.
    let file = unsafe { File::from_raw_fd(fd) };
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < size {
        // SAFETY: live descriptor, scalar offset and whence.
        let data = unsafe { libc::lseek(file.as_raw_fd(), offset, libc::SEEK_DATA) };
        if data < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            return Ok(Vec::new());
        }
        // SAFETY: live descriptor and scalar parameters.
        let hole = unsafe { libc::lseek(file.as_raw_fd(), data, libc::SEEK_HOLE) };
        if hole <= data {
            return Ok(Vec::new());
        }
        if out.len() >= 1024 * 1024 {
            return Err(std::io::Error::from_raw_os_error(libc::ENOMEM));
        }
        out.push((data, hole.min(size) - data));
        offset = hole;
    }
    if out.is_empty() {
        out.push((0, 0));
    }
    Ok(out)
}
impl Target {
    #[cfg(target_vendor = "apple")]
    pub fn remove_xattr(&self, name: &CStr) -> std::io::Result<()> {
        let file = self.metadata_file()?;
        // SAFETY: live name and file descriptor; native call does not retain either.
        result(unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr(), 0) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            // Tests run in parallel and the clock has microsecond
            // resolution, so a counter keeps the names apart.
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("libarchive-parent-{}-{unique}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            Self(std::fs::canonicalize(root).unwrap())
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn target_parent_preserves_path_components() {
        use std::os::unix::fs::MetadataExt;
        let root = Directory::new();
        std::fs::create_dir(root.0.join("dir")).unwrap();
        for (path, parent, name) in [
            (
                std::path::PathBuf::from("/"),
                std::path::PathBuf::from("/"),
                ".",
            ),
            (
                std::path::PathBuf::from("."),
                std::path::PathBuf::from("."),
                ".",
            ),
            (
                std::path::PathBuf::from("file"),
                std::path::PathBuf::from("."),
                "file",
            ),
            (root.0.join("dir//file"), root.0.join("dir"), "file"),
            (root.0.join("dir/./file"), root.0.join("dir"), "file"),
            (root.0.join("dir/../file"), root.0.join("dir/.."), "file"),
            (root.0.join("dir/.."), root.0.join("dir"), ".."),
            (root.0.join("dir/"), root.0.clone(), "dir"),
        ] {
            let target = Target::prepare(&path, true).unwrap();
            let actual = target.parent.metadata().unwrap();
            let expected = std::fs::metadata(parent).unwrap();
            assert_eq!(
                (actual.dev(), actual.ino()),
                (expected.dev(), expected.ino()),
                "{path:?}"
            );
            assert_eq!(target.name.to_bytes(), name.as_bytes(), "{path:?}");
        }
    }

    #[test]
    fn target_parent_keeps_symlink_and_autodir_rules() {
        use std::io::Write;
        let root = Directory::new();
        let outside = root.0.join("outside");
        std::fs::create_dir(&outside).unwrap();
        let link = root.0.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let path = link.join("file");
        assert!(Target::prepare(&path, true).is_err());
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        Target::prepare(&path, false)
            .unwrap()
            .open(0o600, true)
            .unwrap()
            .write_all(b"followed")
            .unwrap();
        assert_eq!(std::fs::read(outside.join("file")).unwrap(), b"followed");
        let missing = root.0.join("missing/nested/file");
        assert!(Target::prepare(&missing, true).is_err());
        assert!(!root.0.join("missing").exists());
        create_dir(missing.parent().unwrap(), true, false, umask()).unwrap();
        assert!(Target::prepare(&missing, true).is_ok());
    }

    #[test]
    fn target_parent_needs_only_search_permission() {
        use std::os::unix::fs::PermissionsExt;
        let root = Directory::new();
        let parent = root.0.join("parent");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o333)).unwrap();
        for (secure, name) in [(true, "secure"), (false, "plain")] {
            let result =
                Target::prepare(&parent.join(name), secure).and_then(|t| t.open(0o600, true));
            assert!(result.is_ok(), "{secure}: {result:?}");
        }
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(parent.join("secure").exists() && parent.join("plain").exists());
    }

    #[test]
    fn held_descriptor_takes_mode_owner_and_times() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = Directory::new();
        let path = root.0.join("file");
        std::fs::write(&path, b"original").unwrap();
        let mut target = Target::prepare(&path, true).unwrap();
        target.retain_file(target.fixup_file(false).unwrap());
        // Replaced by name after the descriptor was checked.
        std::fs::rename(&path, root.0.join("moved")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        target.chmod(0o600).unwrap();
        target
            .times((1_000_000_000, 0), (1_000_000_000, 0))
            .unwrap();
        let st = std::fs::metadata(&path).unwrap();
        target.owner(st.uid().into(), st.gid().into()).unwrap();
        assert_eq!(
            target.stat().unwrap().st_ino,
            std::fs::metadata(root.0.join("moved")).unwrap().ino()
        );
        let moved = std::fs::metadata(root.0.join("moved")).unwrap();
        assert_eq!(
            (moved.mode() & 0o777, moved.mtime()),
            (0o600, 1_000_000_000)
        );
        assert_eq!(st.mode() & 0o777, 0o644);
        assert_ne!(st.mtime(), 1_000_000_000);
    }

    #[test]
    fn check_symlinks_refuses_or_removes_symlinks_as_upstream_does() {
        use crate::archive::ARCHIVE_FAILED;
        let root = Directory::new();
        let bytes = |p: &std::path::Path| p.as_os_str().as_bytes().to_vec();
        std::fs::create_dir(root.0.join("dir")).unwrap();
        std::fs::write(root.0.join("file"), b"").unwrap();
        let link = root.0.join("link");
        std::os::unix::fs::symlink(root.0.join("dir"), &link).unwrap();
        let through = bytes(&link.join("x"));
        let refused = Err((
            ARCHIVE_FAILED,
            libc::ELOOP,
            "Cannot extract through symlink ",
        ));
        assert_eq!(check_symlinks(&through, false, true, false), refused);
        // Without SECURE_SYMLINKS a symlink to a directory is followed.
        assert_eq!(check_symlinks(&through, false, false, false), Ok(()));
        std::os::unix::fs::symlink(root.0.join("file"), root.0.join("filelink")).unwrap();
        let to_file = bytes(&root.0.join("filelink/x"));
        assert_eq!(check_symlinks(&to_file, false, false, false), refused);
        let in_file = bytes(&root.0.join("file/x"));
        let not_dir = Err((ARCHIVE_FAILED, libc::ENOTDIR, "Could not stat "));
        assert_eq!(check_symlinks(&in_file, false, true, false), not_dir);
        // A hardlink may point at a symlink; any other last symlink goes.
        assert_eq!(check_symlinks(&bytes(&link), false, true, true), Ok(()));
        assert!(link.exists());
        assert_eq!(check_symlinks(&bytes(&link), false, true, false), Ok(()));
        assert!(std::fs::symlink_metadata(&link).is_err());
        std::os::unix::fs::symlink(root.0.join("dir"), &link).unwrap();
        assert_eq!(check_symlinks(&through, true, true, false), Ok(()));
        assert!(std::fs::symlink_metadata(&link).is_err());
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn target_parent_accepts_searchable_ancestors_without_read_permission() {
        use std::os::unix::fs::PermissionsExt;
        if !supports_nofollow_any() {
            return;
        }
        struct Restore(File);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = self
                    .0
                    .set_permissions(std::fs::Permissions::from_mode(0o700));
            }
        }
        let root = Directory::new();
        let ancestor = root.0.join("ancestor");
        std::fs::create_dir(&ancestor).unwrap();
        std::fs::create_dir(ancestor.join("parent")).unwrap();
        let restore = Restore(File::open(&ancestor).unwrap());
        restore
            .0
            .set_permissions(std::fs::Permissions::from_mode(0o111))
            .unwrap();
        let target = Target::prepare(&ancestor.join("parent/file"), true).unwrap();
        target.open(0o600, true).unwrap();
        assert!(ancestor.join("parent/file").exists());
    }

    #[test]
    fn exclusive_open_preserves_existing_file_and_symlink() {
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "libarchive-exclusive-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let _cleanup = Cleanup(root.clone());
        let path = root.join("file");
        std::fs::write(&path, b"keep").unwrap();
        let target = Target::prepare(&path, true).unwrap();
        assert_eq!(
            target.open(0o600, true).unwrap_err().raw_os_error(),
            Some(libc::EEXIST)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("missing", &path).unwrap();
        assert_eq!(
            target.open(0o600, true).unwrap_err().raw_os_error(),
            Some(libc::EEXIST)
        );
        assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
        assert!(!root.join("missing").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retained_target_survives_concurrent_leaf_symlink_replacement() {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        let root = Directory::new();
        let path = root.0.join("file");
        let moved = root.0.join("moved");
        let outside = root.0.join("outside");
        std::fs::write(&outside, b"outside").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o644)).unwrap();
        let original_outside = std::fs::metadata(&outside).unwrap();
        let mut target = Target::prepare(&path, true).unwrap();
        let mut file = target.open(0o600, true).unwrap();
        target.retain_file(file.try_clone().unwrap());
        let (start, started) = std::sync::mpsc::channel();
        let (done, finished) = std::sync::mpsc::channel();
        let replacement = path.clone();
        let destination = outside.clone();
        let worker = std::thread::spawn(move || {
            started.recv().unwrap();
            std::fs::rename(&replacement, &moved).unwrap();
            symlink(destination, replacement).unwrap();
            done.send(()).unwrap();
            moved
        });
        start.send(()).unwrap();
        finished.recv().unwrap();
        file.write_all(b"original").unwrap();
        let attr = c"user.libarchive-race";
        target.xattr(attr, b"original").unwrap();
        target.chmod(0o400).unwrap();
        target
            .times((1_000_000_000, 0), (1_000_000_000, 0))
            .unwrap();
        target
            .owner(original_outside.uid().into(), original_outside.gid().into())
            .unwrap();
        let moved = worker.join().unwrap();
        assert_eq!(std::fs::read(&moved).unwrap(), b"original");
        let original = std::fs::metadata(&moved).unwrap();
        assert_eq!(
            (original.mode() & 0o777, original.mtime()),
            (0o400, 1_000_000_000)
        );
        assert_eq!(target.stat().unwrap().st_ino, original.ino());
        assert!(std::fs::symlink_metadata(path).unwrap().is_symlink());
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
        let after = std::fs::metadata(&outside).unwrap();
        assert_eq!(
            (after.mode(), after.mtime(), after.uid(), after.gid()),
            (
                original_outside.mode(),
                original_outside.mtime(),
                original_outside.uid(),
                original_outside.gid()
            )
        );
    }

    #[test]
    fn secured_target_stays_in_opened_parent_after_symlink_swap() {
        use std::io::Write;
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("libarchive-disk-{}-{unique}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        std::fs::create_dir(root.join("parent")).unwrap();
        std::fs::create_dir(root.join("outside")).unwrap();
        let target = Target::prepare(&root.join("parent/file"), true).unwrap();
        let replaced = root.clone();
        let worker = std::thread::spawn(move || {
            std::fs::rename(replaced.join("parent"), replaced.join("original")).unwrap();
            std::os::unix::fs::symlink(replaced.join("outside"), replaced.join("parent")).unwrap();
        });
        worker.join().unwrap();
        target
            .open(0o600, false)
            .unwrap()
            .write_all(b"safe")
            .unwrap();
        assert_eq!(std::fs::read(root.join("original/file")).unwrap(), b"safe");
        assert!(!root.join("outside/file").exists());
        assert!(Target::prepare(&root.join("parent/other"), true).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
