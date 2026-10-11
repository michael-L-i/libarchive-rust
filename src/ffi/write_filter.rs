//! Compression filter exports.
use super::archive::with;
use super::write::cbytes;
use super::{ARCHIVE_FATAL, ARCHIVE_OK, Archive};
use crate::api::write::AddFilter;
use std::ffi::{c_char, c_int};

#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter(a: *mut Archive, code: c_int) -> c_int {
    with(a, ARCHIVE_FATAL, |h| h.write_add_filter(code))
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_by_name(a: *mut Archive, name: *const c_char) -> c_int {
    // A NULL name crashes upstream; it fails here.
    with(a, ARCHIVE_FATAL, |h| {
        cbytes(name).map_or(ARCHIVE_FATAL, |name| h.write_add_filter_by_name(name))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_program(a: *mut Archive, cmd: *const c_char) -> c_int {
    with(a, ARCHIVE_FATAL, |h| {
        h.write_add_filter_program(cbytes(cmd))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn archive_write_add_filter_none(_: *mut Archive) -> c_int {
    ARCHIVE_OK
}

/// The other `archive_write_add_filter_X` exports.
macro_rules! add_filter {
    ($($export:ident => $add:ident,)*) => {$(
        #[unsafe(no_mangle)]
        pub extern "C" fn $export(a: *mut Archive) -> c_int {
            with(a, ARCHIVE_FATAL, |h| h.write_add_filter_x(AddFilter::$add))
        }
    )*};
}
add_filter! {
    archive_write_add_filter_b64encode => B64ENCODE,
    archive_write_add_filter_bzip2 => BZIP2,
    archive_write_add_filter_compress => COMPRESS,
    archive_write_add_filter_grzip => GRZIP,
    archive_write_add_filter_gzip => GZIP,
    archive_write_add_filter_lrzip => LRZIP,
    archive_write_add_filter_lz4 => LZ4,
    archive_write_add_filter_lzip => LZIP,
    archive_write_add_filter_lzma => LZMA,
    archive_write_add_filter_lzop => LZOP,
    archive_write_add_filter_uuencode => UUENCODE,
    archive_write_add_filter_xz => XZ,
    archive_write_add_filter_zstd => ZSTD,
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
    use crate::read::filter_code;
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
                match code {
                    filter_code::PROGRAM => archive_write_add_filter_program(a, c"cat".as_ptr()),
                    15 => archive_write_add_filter_b64encode(a),
                    _ => archive_write_add_filter(a, code),
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
