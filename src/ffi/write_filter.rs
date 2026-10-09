//! Compression filter exports.
use std::ffi::CStr;
fn string<'a>(p: *const c_char) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    // SAFETY: filter names and commands are caller-provided NUL-terminated strings.
    Some(unsafe { CStr::from_ptr(p) }.to_bytes())
}
use super::write::with_writer;
use super::{Archive, guard};
use crate::archive::{ARCHIVE_FATAL, ARCHIVE_OK, ARCHIVE_WARN};
use crate::read::filter_code;
use crate::write::filter;
use std::ffi::{c_char, c_int};
fn add(a: *mut Archive, code: c_int) -> c_int {
    with_writer(a, |base, w| {
        if code == filter_code::NONE {
            return ARCHIVE_OK;
        }
        match filter::by_code(code) {
            Ok(f) => {
                let r = w.add_filter(f);
                if r == ARCHIVE_OK
                    && matches!(
                        code,
                        filter_code::LRZIP | filter_code::LZOP | filter_code::GRZIP
                    )
                {
                    let _ = base.warn(
                        -1,
                        format!(
                            "Using external {} program for {} compression",
                            match code {
                                filter_code::LRZIP => "lrzip",
                                filter_code::LZOP => "lzop",
                                _ => "grzip",
                            },
                            match code {
                                filter_code::LRZIP => "lrzip",
                                filter_code::LZOP => "lzop",
                                _ => "grzip",
                            }
                        ),
                    );
                    ARCHIVE_WARN
                } else {
                    r
                }
            }
            Err(e) => base.raise(e),
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter(a: *mut Archive, code: c_int) -> c_int {
    if code == 15 || matches!(code, filter_code::PROGRAM | filter_code::RPM) {
        return with_writer(a, |base, _| {
            base.raise(crate::util::Error::fatal(libc::EINVAL, "No such filter"))
        });
    }
    add(a, code)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_by_name(a: *mut Archive, name: *const c_char) -> c_int {
    guard(ARCHIVE_FATAL, || {
        with_writer(a, |base, w| {
            let Some(name) = string(name) else {
                return ARCHIVE_FATAL;
            };
            match filter::by_name(name) {
                Ok(f) => {
                    let code = f.code();
                    let result = w.add_filter(f);
                    if matches!(
                        code,
                        filter_code::LRZIP | filter_code::LZOP | filter_code::GRZIP
                    ) {
                        let name = match code {
                            filter_code::LRZIP => "lrzip",
                            filter_code::LZOP => "lzop",
                            _ => "grzip",
                        };
                        base.set_error(
                            -1,
                            Some(
                                format!("Using external {name} program for {name} compression")
                                    .as_bytes(),
                            ),
                        );
                        ARCHIVE_WARN
                    } else {
                        result
                    }
                }
                Err(e) => {
                    base.state.set(crate::archive::state::FATAL);
                    base.raise(e)
                }
            }
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_program(a: *mut Archive, cmd: *const c_char) -> c_int {
    guard(ARCHIVE_FATAL, || {
        with_writer(a, |base, w| {
            let Some(cmd) = string(cmd) else {
                return ARCHIVE_FATAL;
            };
            match filter::program(cmd) {
                Ok(f) => w.add_filter(f),
                Err(e) => base.raise(e),
            }
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_b64encode(a: *mut Archive) -> c_int {
    add(a, 15)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_bzip2(a: *mut Archive) -> c_int {
    add(a, filter_code::BZIP2)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_compress(a: *mut Archive) -> c_int {
    add(a, filter_code::COMPRESS)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_grzip(a: *mut Archive) -> c_int {
    add(a, filter_code::GRZIP)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_gzip(a: *mut Archive) -> c_int {
    add(a, filter_code::GZIP)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_lrzip(a: *mut Archive) -> c_int {
    add(a, filter_code::LRZIP)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_lz4(a: *mut Archive) -> c_int {
    add(a, filter_code::LZ4)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_lzip(a: *mut Archive) -> c_int {
    add(a, filter_code::LZIP)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_lzma(a: *mut Archive) -> c_int {
    add(a, filter_code::LZMA)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_lzop(a: *mut Archive) -> c_int {
    add(a, filter_code::LZOP)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_none(a: *mut Archive) -> c_int {
    add(a, filter_code::NONE)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_uuencode(a: *mut Archive) -> c_int {
    add(a, filter_code::UU)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_xz(a: *mut Archive) -> c_int {
    add(a, filter_code::XZ)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_zstd(a: *mut Archive) -> c_int {
    add(a, filter_code::ZSTD)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_compression_bzip2(a: *mut Archive) -> c_int {
    archive_write_add_filter_bzip2(a)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_compression_compress(a: *mut Archive) -> c_int {
    archive_write_add_filter_compress(a)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_compression_gzip(a: *mut Archive) -> c_int {
    archive_write_add_filter_gzip(a)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_compression_lzip(a: *mut Archive) -> c_int {
    archive_write_add_filter_lzip(a)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_compression_lzma(a: *mut Archive) -> c_int {
    archive_write_add_filter_lzma(a)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_compression_none(a: *mut Archive) -> c_int {
    archive_write_add_filter_none(a)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_compression_xz(a: *mut Archive) -> c_int {
    archive_write_add_filter_xz(a)
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_set_compression_program(
    a: *mut Archive,
    cmd: *const c_char,
) -> c_int {
    archive_write_add_filter_program(a, cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::archive::{
        archive_filter_name, archive_read_free, archive_write_close, archive_write_data,
        archive_write_free,
    };
    use crate::ffi::read_open::archive_read_open_memory;
    use crate::ffi::{entry::*, read::*, write::*};
    use std::ffi::c_void;
    #[test]
    fn write_filters_round_trip_chunk_boundaries_and_chains() {
        let payload: Vec<u8> = (0..150_000)
            .map(|i| ((i * 17 + i / 97) % 256) as u8)
            .collect();
        for code in [
            filter_code::GZIP,
            filter_code::BZIP2,
            filter_code::XZ,
            filter_code::LZMA,
            filter_code::LZIP,
            filter_code::LZ4,
            filter_code::ZSTD,
            filter_code::COMPRESS,
            filter_code::UU,
            15,
            filter_code::PROGRAM,
        ] {
            let a = archive_write_new();
            assert_eq!(archive_write_set_format_raw(a), ARCHIVE_OK);
            assert_eq!(archive_write_set_bytes_per_block(a, 0), ARCHIVE_OK);
            assert_eq!(
                if code == filter_code::PROGRAM {
                    archive_write_add_filter_program(a, c"cat".as_ptr())
                } else {
                    add(a, code)
                },
                ARCHIVE_OK
            );
            if code == filter_code::GZIP {
                assert_eq!(archive_write_add_filter_b64encode(a), ARCHIVE_OK);
            }
            let mut output = vec![0u8; 1024 * 1024];
            let mut used = 0;
            assert_eq!(
                archive_write_open_memory(a, output.as_mut_ptr().cast(), output.len(), &mut used),
                ARCHIVE_OK
            );
            let entry = archive_entry_new();
            archive_entry_set_filetype(entry, 0o100000);
            archive_entry_set_size(entry, payload.len() as i64);
            archive_entry_set_pathname(entry, c"data".as_ptr());
            assert_eq!(archive_write_header(a, entry), ARCHIVE_OK);
            for part in payload.chunks(73) {
                assert_eq!(
                    archive_write_data(a, part.as_ptr().cast::<c_void>(), part.len()),
                    part.len() as isize,
                    "filter {code}"
                );
            }
            assert_eq!(archive_write_close(a), ARCHIVE_OK, "filter {code}");
            assert!(!archive_filter_name(a, 0).is_null());
            assert_eq!(archive_write_free(a), ARCHIVE_OK);
            archive_entry_free(entry);
            let r = archive_read_new();
            assert_eq!(archive_read_support_filter_all(r), ARCHIVE_OK);
            assert_eq!(archive_read_support_format_raw(r), ARCHIVE_OK);
            assert_eq!(
                archive_read_open_memory(r, output.as_ptr().cast(), used),
                ARCHIVE_OK,
                "filter {code}"
            );
            let mut e = std::ptr::null_mut();
            assert_eq!(
                archive_read_next_header(r, &mut e),
                ARCHIVE_OK,
                "filter {code}"
            );
            let mut got = Vec::new();
            let mut buf = [0; 4096];
            loop {
                let n = archive_read_data(r, buf.as_mut_ptr().cast(), buf.len());
                assert!(n >= 0, "filter {code}: error {n}");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n as usize]);
            }
            assert_eq!(got, payload, "filter {code}");
            assert_eq!(archive_read_free(r), ARCHIVE_OK);
        }
    }
}
