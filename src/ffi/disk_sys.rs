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
#[cfg(target_vendor = "apple")]
pub fn write_xattrs(path: &Path, entry: &Entry) -> std::io::Result<()> {
    let path = path_c(path)?;
    for attr in &entry.xattrs {
        // SAFETY: the path, attribute name, and value are live for the call.
        result(unsafe {
            libc::setxattr(
                path.as_ptr(),
                attr.name.as_ptr(),
                attr.value.as_ptr().cast(),
                attr.value.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        })?;
    }
    Ok(())
}
#[cfg(not(target_vendor = "apple"))]
pub fn read_xattrs(_path: &Path, _entry: &mut Entry) -> std::io::Result<()> {
    Ok(())
}
#[cfg(not(target_vendor = "apple"))]
pub fn write_xattrs(_path: &Path, _entry: &Entry) -> std::io::Result<()> {
    Ok(())
}

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Component;

/// Holds the destination directory open so renames cannot redirect extraction.
pub struct Target {
    parent: File,
    name: CString,
}
impl Target {
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
        Ok(Self { parent, name })
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
