//! Filesystem and account calls used by disk traversal and extraction.

use crate::entry::Entry;
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

fn path_c(path: &Path) -> std::io::Result<CString> {
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
pub fn restore_times(path: &Path, entry: &Entry) -> std::io::Result<()> {
    let path = path_c(path)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let times = [
        libc::timespec {
            tv_sec: if entry.atime_is_set() != 0 {
                entry.atime()
            } else {
                now.as_secs() as i64
            },
            tv_nsec: if entry.atime_is_set() != 0 {
                entry.atime_nsec() as _
            } else {
                now.subsec_nanos() as _
            },
        },
        libc::timespec {
            tv_sec: if entry.mtime_is_set() != 0 {
                entry.mtime()
            } else {
                now.as_secs() as i64
            },
            tv_nsec: if entry.mtime_is_set() != 0 {
                entry.mtime_nsec() as _
            } else {
                now.subsec_nanos() as _
            },
        },
    ];
    // SAFETY: the pathname and two timespec values are live, properly sized.
    result(unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })
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

#[cfg(target_vendor = "apple")]
pub fn read_xattrs(path: &Path, entry: &mut Entry) -> std::io::Result<()> {
    let path = path_c(path)?;
    // SAFETY: querying length does not write through the NULL buffer.
    let count =
        unsafe { libc::listxattr(path.as_ptr(), std::ptr::null_mut(), 0, libc::XATTR_NOFOLLOW) };
    if count < 0 {
        let e = std::io::Error::last_os_error();
        if [libc::ENOTSUP, libc::EPERM].contains(&e.raw_os_error().unwrap_or(0)) {
            return Ok(());
        }
        return Err(e);
    }
    if count > 1024 * 1024 {
        return Err(std::io::Error::from_raw_os_error(libc::ENOMEM));
    }
    let mut names = vec![0u8; count as usize];
    // SAFETY: buffer is writable for its full size.
    let count = unsafe {
        libc::listxattr(
            path.as_ptr(),
            names.as_mut_ptr().cast(),
            names.len(),
            libc::XATTR_NOFOLLOW,
        )
    };
    if count < 0 {
        return Err(std::io::Error::last_os_error());
    }
    names.truncate(count as usize);
    for name in names.split(|&b| b == 0).filter(|n| !n.is_empty()) {
        let name =
            CString::new(name).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        // SAFETY: query with no destination only reports value length.
        let len = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                std::ptr::null_mut(),
                0,
                0,
                libc::XATTR_NOFOLLOW,
            )
        };
        if len < 0 {
            continue;
        }
        if len > 16 * 1024 * 1024 {
            return Err(std::io::Error::from_raw_os_error(libc::ENOMEM));
        }
        let mut value = vec![0; len as usize];
        // SAFETY: both C strings and writable value remain live.
        let len = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        };
        if len >= 0 {
            value.truncate(len as usize);
            entry.xattr_add(&name, &value);
        }
    }
    Ok(())
}
#[cfg(not(target_vendor = "apple"))]
pub fn read_xattrs(_path: &Path, _entry: &mut Entry) -> std::io::Result<()> {
    Ok(())
}

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Component;

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
    pub fn prepare(
        path: &Path,
        secure: bool,
        unlink: bool,
        autodir: bool,
    ) -> std::io::Result<Self> {
        let mut components: Vec<_> = path.components().collect();
        let last = components
            .pop()
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let name = if last == Component::RootDir {
            c".".to_owned()
        } else {
            CString::new(last.as_os_str().as_bytes())
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?
        };
        let start = if path.is_absolute() { c"/" } else { c"." };
        // SAFETY: start is a terminated path, and open returns a new owned fd.
        let fd = unsafe {
            libc::open(
                start.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fd is a successfully opened, uniquely owned descriptor.
        let mut parent = unsafe { File::from_raw_fd(fd) };
        for component in components {
            if component == Component::RootDir || component == Component::CurDir {
                continue;
            }
            let part = CString::new(component.as_os_str().as_bytes())
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
            let flags = libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_CLOEXEC
                | if secure { libc::O_NOFOLLOW } else { 0 };
            // SAFETY: parent fd and component name are live.
            let mut fd = unsafe { libc::openat(parent.as_raw_fd(), part.as_ptr(), flags) };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                if secure && unlink {
                    let mut st = super::entry::zeroed_stat();
                    // SAFETY: writable stat and parent/name are valid.
                    if unsafe {
                        libc::fstatat(
                            parent.as_raw_fd(),
                            part.as_ptr(),
                            &mut st,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    } == 0
                        && st.st_mode & libc::S_IFMT == libc::S_IFLNK
                    {
                        // SAFETY: unlinkat uses the live parent and component.
                        result(unsafe { libc::unlinkat(parent.as_raw_fd(), part.as_ptr(), 0) })?;
                    } else if error.raw_os_error() != Some(libc::ENOENT) {
                        return Err(error);
                    }
                } else if error.raw_os_error() != Some(libc::ENOENT) {
                    return Err(error);
                }
                if !autodir {
                    return Err(error);
                }
                // SAFETY: mkdirat uses a valid parent descriptor and path.
                let code = unsafe { libc::mkdirat(parent.as_raw_fd(), part.as_ptr(), 0o777) };
                if code != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
                {
                    return Err(std::io::Error::last_os_error());
                }
                // SAFETY: retry opens the newly created directory, never a symlink when secure.
                fd = unsafe { libc::openat(parent.as_raw_fd(), part.as_ptr(), flags) };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // SAFETY: the new descriptor is uniquely owned by this File.
            parent = unsafe { File::from_raw_fd(fd) };
        }
        Ok(Self {
            parent,
            name,
            live: None,
        })
    }
    pub fn stat(&self) -> std::io::Result<libc::stat> {
        let mut st = super::entry::zeroed_stat();
        // SAFETY: output and fd/name remain live throughout call.
        result(unsafe {
            libc::fstatat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })?;
        Ok(st)
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
    pub fn open(&self, mode: u32) -> std::io::Result<File> {
        // SAFETY: openat returns a new owned descriptor; O_NOFOLLOW rejects final symlinks.
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC | libc::O_NOFOLLOW,
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
    pub fn hardlink(&self, source: &Target, secure: bool) -> std::io::Result<()> {
        if secure && source.stat()?.st_mode & libc::S_IFMT == libc::S_IFLNK {
            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
        }
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
    pub fn chmod(&self, mode: u32) -> std::io::Result<()> {
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
    pub fn times(&self, entry: &Entry) -> std::io::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let times = [
            libc::timespec {
                tv_sec: if entry.atime_is_set() != 0 {
                    entry.atime()
                } else {
                    now.as_secs() as _
                },
                tv_nsec: if entry.atime_is_set() != 0 {
                    entry.atime_nsec() as _
                } else {
                    now.subsec_nanos() as _
                },
            },
            libc::timespec {
                tv_sec: if entry.mtime_is_set() != 0 {
                    entry.mtime()
                } else {
                    now.as_secs() as _
                },
                tv_nsec: if entry.mtime_is_set() != 0 {
                    entry.mtime_nsec() as _
                } else {
                    now.subsec_nanos() as _
                },
            },
        ];
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

pub fn umask() -> u32 {
    // SAFETY: umask has no pointer arguments; restore immediately, as upstream does.
    unsafe {
        let mask = libc::umask(0);
        libc::umask(mask);
        u32::from(mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let target = Target::prepare(&root.join("parent/file"), true, false, false).unwrap();
        std::fs::rename(root.join("parent"), root.join("original")).unwrap();
        std::os::unix::fs::symlink(root.join("outside"), root.join("parent")).unwrap();
        target.open(0o600).unwrap().write_all(b"safe").unwrap();
        assert_eq!(std::fs::read(root.join("original/file")).unwrap(), b"safe");
        assert!(!root.join("outside/file").exists());
        assert!(Target::prepare(&root.join("parent/other"), true, false, false).is_err());
        std::fs::remove_dir_all(root).unwrap();
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
    let mut name = std::env::temp_dir()
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
pub fn pack_mac_metadata(path: &Path, entry: &mut Entry) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let path = path_c(path)?;
    // SAFETY: live pathname; COPYFILE_CHECK reports metadata without writing to NULL destination.
    let check = unsafe {
        copyfile(
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            (1 << 16) | 1 | 4,
        )
    };
    if check == 0 {
        return Ok(());
    }
    if check < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: valid string, descriptor uniquely owned on success; O_SYMLINK avoids target following.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC,
        )
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
pub fn pack_mac_metadata(_path: &Path, _entry: &mut Entry) -> std::io::Result<()> {
    Ok(())
}

impl Target {
    #[cfg(target_vendor = "apple")]
    pub fn metadata_file(&self) -> std::io::Result<File> {
        if let Some(file) = &self.live {
            return file.try_clone();
        }
        // SAFETY: valid descriptor/name; O_SYMLINK opens link itself, never its target.
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC,
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
        let st = self.stat()?;
        // SAFETY: live file descriptor; fchflags does not access borrowed memory.
        result(unsafe { libc::fchflags(file.as_raw_fd(), (st.st_flags | set) & !clear) })
    }
    #[cfg(not(target_vendor = "apple"))]
    pub fn flags(&self, _set: u32, _clear: u32) -> std::io::Result<()> {
        Ok(())
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
    pub fn read_file(&self) -> std::io::Result<File> {
        // SAFETY: live parent/name; final symlink not followed.
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: descriptor returned by openat is uniquely owned.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

impl Target {
    pub fn write_xattrs(&self, entry: &Entry) -> std::io::Result<()> {
        #[cfg(target_vendor = "apple")]
        for attr in &entry.xattrs {
            self.xattr(&attr.name, &attr.value)?;
        }
        #[cfg(not(target_vendor = "apple"))]
        let _ = entry;
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

#[cfg(target_vendor = "apple")]
pub fn filesystem(path: &Path, follow: bool) -> std::io::Result<(libc::c_int, libc::c_int)> {
    let inspect =
        if follow || std::fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_symlink()) {
            path
        } else {
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
        };
    let path = path_c(inspect)?;
    // SAFETY: statfs is a plain C struct with integer and byte-array fields.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: live pathname and writable statfs destination.
    result(unsafe { libc::statfs(path.as_ptr(), &mut st) })?;
    Ok((
        libc::c_int::from(st.f_flags & libc::MNT_LOCAL as u32 == 0),
        -1,
    ))
}
#[cfg(not(target_vendor = "apple"))]
pub fn filesystem(_path: &Path, _follow: bool) -> std::io::Result<(libc::c_int, libc::c_int)> {
    Ok((-1, -1))
}

pub fn sparse(path: &Path, follow: bool, size: i64) -> std::io::Result<Vec<(i64, i64)>> {
    if size <= 0 {
        return Ok(Vec::new());
    }
    let path = path_c(path)?;
    // SAFETY: live pathname; successful descriptor is newly owned.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | if follow { 0 } else { libc::O_NOFOLLOW },
        )
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
