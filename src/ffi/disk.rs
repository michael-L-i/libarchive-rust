//! The C ABI of disk traversal, disk extraction, and lookup callbacks.

use super::archive::with;
use super::{Archive, ArchiveEntry, guard};
use crate::api::read_disk::DiskMatcher;
use crate::archive::{self, ARCHIVE_FATAL, ARCHIVE_OK, Base, Handle, Kind};
use crate::entry::Entry;
use crate::read_disk::{ExcludedCallback, MetadataFilter};
use crate::{read_disk, write_disk};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::rc::Rc;

pub type Cleanup = Option<unsafe extern "C" fn(*mut c_void)>;
pub type ReadLookup = Option<unsafe extern "C" fn(*mut c_void, i64) -> *const c_char>;
pub type WriteLookup = Option<unsafe extern "C" fn(*mut c_void, *const c_char, i64) -> i64>;

const LOOKUP_CACHE_SIZE: usize = 127;

struct CachedName {
    id: libc::id_t,
    group: bool,
    name: Option<CString>,
}

#[derive(Default)]
pub struct NameLookup {
    data: *mut c_void,
    callback: ReadLookup,
    cleanup: Cleanup,
    pub standard: bool,
    value: Option<CString>,
    cache: Vec<Option<CachedName>>,
}
impl NameLookup {
    /// The lookup in the system's user and group databases.
    pub fn standard() -> Self {
        let mut lookup = NameLookup::default();
        lookup.standard = true;
        lookup
    }
    pub fn lookup(&mut self, id: i64, group: bool) -> Option<&CStr> {
        if self.standard {
            // Match the uid_t/gid_t conversion in the system lookup and upstream cache.
            let key = id as libc::id_t;
            if self.cache.is_empty() {
                self.cache.resize_with(LOOKUP_CACHE_SIZE, || None);
            }
            let slot = key as usize % LOOKUP_CACHE_SIZE;
            let cached = &mut self.cache[slot];
            if cached
                .as_ref()
                .is_none_or(|c| c.id != key || c.group != group)
            {
                *cached = Some(CachedName {
                    id: key,
                    group,
                    name: super::disk_sys::name(id, group),
                });
            }
            return cached.as_ref().and_then(|c| c.name.as_deref());
        }
        self.value = if let Some(cb) = self.callback {
            // SAFETY: the setter registers this callback/data for the lookup's lifetime.
            let name = unsafe { cb(self.data, id) };
            // SAFETY: a non-NULL callback result is a NUL-terminated string.
            (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) }.to_owned())
        } else {
            None
        };
        self.value.as_deref()
    }
}
impl Drop for NameLookup {
    fn drop(&mut self) {
        if let Some(cb) = self.cleanup
            && !self.data.is_null()
        {
            // SAFETY: registered cleanup is called once, after the final lookup.
            unsafe { cb(self.data) };
        }
    }
}
#[derive(Default)]
pub struct IdLookup {
    data: *mut c_void,
    callback: WriteLookup,
    cleanup: Cleanup,
    pub standard: bool,
}
impl IdLookup {
    /// The lookup in the system's user and group databases.
    pub fn standard() -> Self {
        IdLookup {
            standard: true,
            ..IdLookup::default()
        }
    }
    pub fn lookup(&mut self, name: Option<&CStr>, fallback: i64, group: bool) -> i64 {
        let Some(name) = name else {
            return fallback;
        };
        if self.standard {
            return super::disk_sys::id(name, fallback, group);
        }
        if let Some(cb) = self.callback {
            // SAFETY: registered callback/data and the live C string remain valid.
            unsafe { cb(self.data, name.as_ptr(), fallback) }
        } else {
            fallback
        }
    }
}
impl Drop for IdLookup {
    fn drop(&mut self) {
        if let Some(cb) = self.cleanup
            && !self.data.is_null()
        {
            // SAFETY: cleanup is registered by caller and called once.
            unsafe { cb(self.data) };
        }
    }
}

fn read<T: Copy>(
    a: *mut Archive,
    fallback: T,
    f: impl FnOnce(&Base, &mut read_disk::ReadDisk) -> T,
) -> T {
    with(a, fallback, |h| h.with_read_disk(fallback, f))
}
fn write<T: Copy>(
    a: *mut Archive,
    fallback: T,
    f: impl FnOnce(&Base, &mut write_disk::WriteDisk) -> T,
) -> T {
    with(a, fallback, |h| h.with_write_disk(fallback, f))
}
fn cstr<'a>(p: *const c_char) -> Option<&'a CStr> {
    // SAFETY: API caller supplies NULL or a NUL-terminated string.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_write_disk_new() -> *mut Archive {
    guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(crate::api::write_disk::new())).cast()
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_new() -> *mut Archive {
    guard(std::ptr::null_mut(), || {
        let h = crate::api::read_disk::new();
        let entry = Box::into_raw(Box::new(Entry::new(None)));
        h.with_read_disk((), |_, d| d.entry = entry);
        Box::into_raw(Box::new(h)).cast()
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_disk_set_options(a: *mut Archive, flags: c_int) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.write_disk_set_options(flags))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_disk_set_skip_file(a: *mut Archive, dev: i64, ino: i64) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.write_disk_set_skip_file(dev, ino))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_disk_set_standard_lookup(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, Handle::write_disk_set_standard_lookup)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_disk_set_group_lookup(
    a: *mut Archive,
    data: *mut c_void,
    callback: WriteLookup,
    cleanup: Cleanup,
) -> c_int {
    write(a, ARCHIVE_FATAL, |_, d| {
        d.group = IdLookup {
            data,
            callback,
            cleanup,
            standard: false,
        };
        ARCHIVE_OK
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_disk_set_user_lookup(
    a: *mut Archive,
    data: *mut c_void,
    callback: WriteLookup,
    cleanup: Cleanup,
) -> c_int {
    write(a, ARCHIVE_FATAL, |_, d| {
        d.user = IdLookup {
            data,
            callback,
            cleanup,
            standard: false,
        };
        ARCHIVE_OK
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_disk_gid(a: *mut Archive, name: *const c_char, id: i64) -> i64 {
    write(a, id, |_, d| d.group.lookup(cstr(name), id, true))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_disk_uid(a: *mut Archive, name: *const c_char, id: i64) -> i64 {
    write(a, id, |_, d| d.user.lookup(cstr(name), id, false))
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_set_symlink_logical(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.read_disk_set_symlinks(1))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_set_symlink_physical(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.read_disk_set_symlinks(0))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_set_symlink_hybrid(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.read_disk_set_symlinks(2))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_open(a: *mut Archive, path: *const c_char) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        cstr(path).map_or(ARCHIVE_FATAL, |p| h.read_disk_open(p.to_bytes()))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_open_w(a: *mut Archive, path: *const libc::wchar_t) -> c_int {
    guard(ARCHIVE_FATAL, || {
        if path.is_null() {
            return ARCHIVE_FATAL;
        }
        // SAFETY: caller supplies a NUL-terminated wchar_t string.
        let len = (0..).take_while(|&i| unsafe { *path.add(i) } != 0).count();
        // SAFETY: the characters before the terminator are readable.
        let wide = unsafe { std::slice::from_raw_parts(path, len) };
        let mut bytes = Vec::new();
        for &ch in wide {
            let Some(ch) = char::from_u32(ch as u32) else {
                return ARCHIVE_FATAL;
            };
            let mut b = [0; 4];
            bytes.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
        }
        with(a, ARCHIVE_FATAL, |h| h.read_disk_open(&bytes))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_descend(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, Handle::read_disk_descend)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_can_descend(a: *mut Archive) -> c_int {
    with(a, 0, |h| c_int::from(h.base.disk_can_descend.get()))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_current_filesystem(a: *mut Archive) -> c_int {
    with(a, -1, |h| h.base.disk_filesystem.get())
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_current_filesystem_is_synthetic(a: *mut Archive) -> c_int {
    with(a, -1, |h| h.base.disk_synthetic.get())
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_current_filesystem_is_remote(a: *mut Archive) -> c_int {
    with(a, -1, |h| h.base.disk_remote.get())
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_set_behavior(a: *mut Archive, flags: c_int) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.read_disk_set_behavior(flags))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_set_atime_restored(a: *mut Archive) -> c_int {
    read(a, ARCHIVE_FATAL, |_, d| {
        d.behavior |= 1;
        ARCHIVE_OK
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_set_standard_lookup(a: *mut Archive) -> c_int {
    with(a, ARCHIVE_FATAL, Handle::read_disk_set_standard_lookup)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_set_gname_lookup(
    a: *mut Archive,
    data: *mut c_void,
    callback: ReadLookup,
    cleanup: Cleanup,
) -> c_int {
    read(a, ARCHIVE_FATAL, |_, d| {
        d.group = NameLookup {
            data,
            callback,
            cleanup,
            standard: false,
            value: None,
            cache: Vec::new(),
        };
        ARCHIVE_OK
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_set_uname_lookup(
    a: *mut Archive,
    data: *mut c_void,
    callback: ReadLookup,
    cleanup: Cleanup,
) -> c_int {
    read(a, ARCHIVE_FATAL, |_, d| {
        d.user = NameLookup {
            data,
            callback,
            cleanup,
            standard: false,
            value: None,
            cache: Vec::new(),
        };
        ARCHIVE_OK
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_gname(a: *mut Archive, id: i64) -> *const c_char {
    read(a, std::ptr::null(), |_, d| {
        d.group
            .lookup(id, true)
            .map_or(std::ptr::null(), CStr::as_ptr)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_uname(a: *mut Archive, id: i64) -> *const c_char {
    read(a, std::ptr::null(), |_, d| {
        d.user
            .lookup(id, false)
            .map_or(std::ptr::null(), CStr::as_ptr)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_entry_from_file(
    a: *mut Archive,
    entry: *mut ArchiveEntry,
    fd: c_int,
    st: *const libc::stat,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        // SAFETY: entry is NULL or live and exclusively borrowed during call.
        let Some(entry) = (unsafe { entry.cast::<Entry>().as_mut() }) else {
            return ARCHIVE_FATAL;
        };
        // SAFETY: optional stat pointer is readable during call.
        let st = unsafe { st.as_ref() };
        h.read_disk_entry_from_file(entry, fd, st)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_set_metadata_filter_callback(
    a: *mut Archive,
    callback: Option<unsafe extern "C" fn(*mut Archive, *mut c_void, *mut ArchiveEntry) -> c_int>,
    data: *mut c_void,
) -> c_int {
    let filter = callback.map(|callback| -> MetadataFilter {
        // SAFETY: the caller registered the callback to be called with
        // `data`; the entry is live for the call.
        Box::new(move |_, entry| unsafe { callback(a, data, (entry as *mut Entry).cast()) != 0 })
    });
    with(a, ARCHIVE_FATAL, |h| {
        h.read_disk_set_metadata_filter_callback(filter)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_disk_set_matching(
    a: *mut Archive,
    matching: *mut Archive,
    excluded: Option<unsafe extern "C" fn(*mut Archive, *mut c_void, *mut ArchiveEntry)>,
    data: *mut c_void,
) -> c_int {
    let matching = if matching.is_null() {
        None
    } else {
        let Some(m) = super::matching::MatchingHandle::new(matching) else {
            return ARCHIVE_FATAL;
        };
        Some(DiskMatcher::Lent(m))
    };
    let excluded = excluded.map(|excluded| -> ExcludedCallback {
        // SAFETY: the caller registered the callback to be called with
        // `data`; the entry is live for the call.
        Box::new(move |_, entry| unsafe { excluded(a, data, (entry as *mut Entry).cast()) })
    });
    with(a, ARCHIVE_FATAL, |h| {
        h.read_disk_set_matching(matching, excluded)
    })
}

pub type Progress = Option<unsafe extern "C" fn(*mut c_void)>;
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_extract_set_progress_callback(
    a: *mut Archive,
    progress: Progress,
    data: *mut c_void,
) {
    with(a, (), |h| {
        h.read_extract_set_progress_callback(progress.map(|progress| -> Rc<dyn Fn()> {
            // SAFETY: the caller registered the callback to be called with
            // `data`.
            Rc::new(move || unsafe { progress(data) })
        }));
    });
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_extract(
    a: *mut Archive,
    entry: *mut ArchiveEntry,
    flags: c_int,
) -> c_int {
    guard(ARCHIVE_FATAL, || {
        let mut result = with(a, ARCHIVE_FATAL, |h| {
            let Kind::Read(r) = &h.kind else {
                return ARCHIVE_FATAL;
            };
            // SAFETY: entry is a live caller-supplied entry or NULL, and
            // nothing else refers to it during the call; the header sets its
            // size as upstream's does.
            let Some(entry) = (unsafe { entry.cast::<Entry>().as_mut() }) else {
                return ARCHIVE_FATAL;
            };
            let mut r = r.borrow_mut();
            let skip = r.skip_file();
            let e = r.extract.get_or_insert_with(Default::default);
            e.disk.options = flags;
            e.disk.skip_file = skip;
            let code = e.disk.header(&e.base, entry);
            if code < 0 {
                h.base.copy_error(&e.base);
            }
            code.max(archive::ARCHIVE_WARN)
        });
        // SAFETY: caller's entry remains live for extraction.
        let copy = unsafe { entry.cast::<Entry>().as_ref() }
            .is_some_and(|e| e.size_is_set() == 0 || e.size() > 0);
        if result == ARCHIVE_OK && copy {
            loop {
                let mut data = std::ptr::null();
                let mut size = 0;
                let mut offset = 0;
                let code =
                    super::read::archive_read_data_block(a, &mut data, &mut size, &mut offset);
                if code == archive::ARCHIVE_EOF {
                    break;
                }
                if code != ARCHIVE_OK {
                    result = code;
                    break;
                }
                let code = with(a, ARCHIVE_FATAL, |h| {
                    let Kind::Read(r) = &h.kind else {
                        return ARCHIVE_FATAL;
                    };
                    let mut r = r.borrow_mut();
                    let Some(e) = &mut r.extract else {
                        return ARCHIVE_FATAL;
                    };
                    let Some(bytes) = super::archive::bytes(data, size) else {
                        return ARCHIVE_FATAL;
                    };
                    let code = e.disk.data_block(&e.base, bytes, offset);
                    if code < 0 {
                        h.base.copy_error(&e.base);
                    }
                    code.max(archive::ARCHIVE_WARN)
                });
                if code < 0 {
                    result = code;
                    break;
                }
                with(a, (), Handle::read_extract_progress);
            }
        }
        let finish = with(a, ARCHIVE_FATAL, |h| {
            let Kind::Read(r) = &h.kind else {
                return ARCHIVE_FATAL;
            };
            let mut r = r.borrow_mut();
            let Some(e) = &mut r.extract else {
                return ARCHIVE_FATAL;
            };
            let code = e.disk.finish_entry(&e.base).max(archive::ARCHIVE_WARN);
            if code < 0 && result == ARCHIVE_OK {
                h.base.copy_error(&e.base);
            }
            code
        });
        result.min(finish)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_read_extract2(
    a: *mut Archive,
    entry: *mut ArchiveEntry,
    dest: *mut Archive,
) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        with(dest, ARCHIVE_FATAL, |d| {
            // SAFETY: `entry` is NULL or a live entry the caller owns. It may
            // be the handle's own entry, so this reference ends before
            // `own_entry` makes another.
            let (r, copy) = match unsafe { entry.cast::<Entry>().as_mut() } {
                Some(e) => h.read_extract2_header(e, d),
                // A NULL entry crashes upstream; it fails here.
                None => (ARCHIVE_FATAL, false),
            };
            let own = super::read::own_entry(h);
            h.read_extract2_data(own, d, (r, copy), &mut || h.read_extract_progress())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    fn directory(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("libarchive-{name}-{}-{unique}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::canonicalize(path).unwrap()
    }
    #[test]
    fn filename_extraction_refuses_to_overwrite_its_input() {
        use crate::ffi::{archive::archive_free, read::*, read_open::*};
        for separate_disk in [false, true] {
            let root = directory("extract-self");
            let path = root.join("input.archive");
            let original = b"archive input must remain unchanged";
            std::fs::write(&path, original).unwrap();
            let name = CString::new(path.as_os_str().as_bytes()).unwrap();
            let reader = archive_read_new();
            assert_eq!(archive_read_support_format_raw(reader), ARCHIVE_OK);
            assert_eq!(
                archive_read_open_filename(reader, name.as_ptr(), 7),
                ARCHIVE_OK
            );
            let mut entry = std::ptr::null_mut();
            assert_eq!(archive_read_next_header(reader, &mut entry), ARCHIVE_OK);
            // SAFETY: next_header returns this reader's live Entry.
            unsafe { &mut *entry.cast::<Entry>() }.set_pathname(path.as_os_str().as_bytes());
            let result = if separate_disk {
                let disk = archive_write_disk_new();
                let result = archive_read_extract2(reader, entry, disk);
                assert_eq!(archive_free(disk), ARCHIVE_OK);
                result
            } else {
                archive_read_extract(reader, entry, 0)
            };
            assert_eq!(result, archive::ARCHIVE_WARN);
            assert_eq!(std::fs::read(&path).unwrap(), original);
            assert_eq!(archive_free(reader), ARCHIVE_OK);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn safe_writes_replace_only_the_destination_link() {
        let root = directory("atomic");
        let path = root.join("file");
        std::fs::write(&path, b"old").unwrap();
        std::fs::hard_link(&path, root.join("other")).unwrap();
        let mut entry = Entry::new(None);
        entry.set_pathname(path.as_os_str().as_bytes());
        entry.set_mode(libc::S_IFREG | 0o600);
        entry.set_size(3);
        let base = Base::new(archive::WRITE_DISK_MAGIC);
        let mut disk = write_disk::WriteDisk::default();
        disk.options = 0x40000;
        assert_eq!(disk.header(&base, &mut entry), 0);
        assert_eq!(disk.data(&base, b"new"), 3);
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
        assert_eq!(disk.finish_entry(&base), 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::read(root.join("other")).unwrap(), b"old");
        assert_eq!(disk.close(&base), 0);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn standard_name_cache_preserves_collisions_misses_and_native_id_aliases() {
        use std::os::unix::fs::MetadataExt;
        let root = directory("names");
        let metadata = std::fs::metadata(&root).unwrap();
        let mut cached = NameLookup {
            standard: true,
            data: std::ptr::null_mut(),
            callback: None,
            cleanup: None,
            value: None,
            cache: Vec::new(),
        };
        for (group, base) in [
            (false, i64::from(metadata.uid())),
            (true, i64::from(metadata.gid())),
        ] {
            for id in [
                base,
                base,
                base + 127,
                base + (1 << 32),
                0x7fff_fff0,
                0x7fff_fff0,
                base,
            ] {
                let expected = super::super::disk_sys::name(id, group);
                assert_eq!(cached.lookup(id, group).map(CStr::to_owned), expected);
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cached_filesystem_flags_match_physical_walk() {
        let root = directory("statfs");
        std::fs::create_dir(root.join("dir")).unwrap();
        std::fs::write(root.join("dir/file"), b"x").unwrap();
        std::os::unix::fs::symlink("/", root.join("dir/link")).unwrap();
        let disk = archive_read_disk_new();
        let path = CString::new(root.as_os_str().as_bytes()).unwrap();
        assert_eq!(archive_read_disk_open(disk, path.as_ptr()), 0);
        let mut entry = Entry::new(None);
        let ptr = (&mut entry as *mut Entry).cast();
        let mut count = 0;
        while super::super::read::archive_read_next_header2(disk, ptr) == 0 {
            count += 1;
            let path = PathBuf::from(std::ffi::OsStr::from_bytes(
                entry.pathname().unwrap().to_bytes(),
            ));
            let fs = super::super::disk_sys::filesystem(&path, false).unwrap();
            assert_eq!(
                archive_read_disk_current_filesystem_is_remote(disk),
                fs.remote
            );
            assert_eq!(
                archive_read_disk_current_filesystem_is_synthetic(disk),
                fs.synthetic
            );
            if archive_read_disk_can_descend(disk) != 0 {
                assert_eq!(archive_read_disk_descend(disk), 0);
            }
        }
        assert_eq!(count, 4);
        assert_eq!(super::super::archive::archive_read_free(disk), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    unsafe extern "C" fn descend_filter(
        a: *mut Archive,
        _data: *mut c_void,
        _entry: *mut ArchiveEntry,
    ) -> c_int {
        if archive_read_disk_can_descend(a) != 0 {
            assert_eq!(archive_read_disk_descend(a), 0);
            0
        } else {
            1
        }
    }
    #[test]
    fn metadata_callback_can_descend_while_filtering_directories() {
        let root = directory("walk");
        std::fs::create_dir(root.join("dir")).unwrap();
        std::fs::write(root.join("dir/file"), b"data").unwrap();
        let disk = archive_read_disk_new();
        let path = CString::new(root.as_os_str().as_bytes()).unwrap();
        assert_eq!(archive_read_disk_open(disk, path.as_ptr()), 0);
        assert_eq!(
            archive_read_disk_set_metadata_filter_callback(
                disk,
                Some(descend_filter),
                std::ptr::null_mut()
            ),
            0
        );
        let mut entry = Entry::new(None);
        let ptr = (&mut entry as *mut Entry).cast();
        assert_eq!(super::super::read::archive_read_next_header2(disk, ptr), 0);
        assert_eq!(
            entry.pathname().unwrap().to_bytes(),
            root.join("dir/file").as_os_str().as_bytes()
        );
        let mut data = [0; 4];
        assert_eq!(
            super::super::read::archive_read_data(disk, data.as_mut_ptr().cast(), 4),
            4
        );
        assert_eq!(&data, b"data");
        assert_eq!(
            super::super::read::archive_read_next_header2(disk, ptr),
            archive::ARCHIVE_EOF
        );
        assert_eq!(super::super::archive::archive_read_free(disk), 0);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn logical_walk_does_not_recurse_into_ancestor_symlinks() {
        let root = directory("cycle");
        std::fs::create_dir(root.join("dir")).unwrap();
        std::os::unix::fs::symlink(&root, root.join("dir/link")).unwrap();
        let disk = archive_read_disk_new();
        let path = CString::new(root.as_os_str().as_bytes()).unwrap();
        assert_eq!(archive_read_disk_set_symlink_logical(disk), 0);
        assert_eq!(archive_read_disk_open(disk, path.as_ptr()), 0);
        let mut entry = Entry::new(None);
        let ptr = (&mut entry as *mut Entry).cast();
        let mut count = 0;
        while super::super::read::archive_read_next_header2(disk, ptr) == 0 {
            count += 1;
            assert!(count <= 3);
            if archive_read_disk_can_descend(disk) != 0 {
                assert_eq!(archive_read_disk_descend(disk), 0);
            }
        }
        assert_eq!(count, 3);
        assert_eq!(entry.filetype(), 0);
        assert_eq!(super::super::archive::archive_read_free(disk), 0);
        std::fs::remove_dir_all(root).unwrap();
    }
}
