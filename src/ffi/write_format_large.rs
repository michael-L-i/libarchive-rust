//! ISO9660 and 7-Zip format registration.
use super::{Archive, write::with_writer};
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_format_7zip(a: *mut Archive) -> i32 {
    with_writer(a, |base, w| {
        w.set_format(
            base,
            Box::new(crate::write::format::sevenzip::SevenZip::default()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ARCHIVE_OK;
    use crate::ffi::{archive::*, entry::*, read::*, read_open::*, write::*};
    use std::ffi::CStr;
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
