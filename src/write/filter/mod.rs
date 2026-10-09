//! Write filters. Each encoder drains bounded output into the following sink.
use super::{Filter, Sink};
use crate::archive::{ARCHIVE_FAILED, ARCHIVE_OK, ARCHIVE_WARN};
use crate::read::filter_code;
use crate::util::Error;
use std::ffi::CStr;
mod bzip2;
mod compress;
mod gzip;
mod lz4;
mod program;
mod uuencode;
mod xz;
mod zstd;

pub fn by_code(code: i32) -> Result<Box<dyn Filter>, Error> {
    Ok(match code {
        filter_code::NONE => Box::new(NoneFilter),
        filter_code::GZIP => Box::new(gzip::Gzip::default()),
        filter_code::BZIP2 => Box::new(bzip2::Bzip2::default()),
        filter_code::XZ | filter_code::LZMA | filter_code::LZIP => Box::new(xz::Encoder::new(code)),
        filter_code::LZ4 => Box::new(lz4::Lz4::default()),
        filter_code::ZSTD => Box::new(zstd::Zstd::default()),
        filter_code::COMPRESS => Box::new(compress::Compress::default()),
        filter_code::UU | 15 => Box::new(uuencode::Encode::new(code)),
        filter_code::LRZIP | filter_code::LZOP | filter_code::GRZIP => {
            Box::new(program::Program::external(code))
        }
        _ => return Err(Error::fatal(libc::EINVAL, "No such filter")),
    })
}
pub fn by_name(name: &[u8]) -> Result<Box<dyn Filter>, Error> {
    let code = match name {
        b"gzip" => filter_code::GZIP,
        b"bzip2" => filter_code::BZIP2,
        b"xz" => filter_code::XZ,
        b"lzma" => filter_code::LZMA,
        b"lzip" => filter_code::LZIP,
        b"lz4" => filter_code::LZ4,
        b"zstd" => filter_code::ZSTD,
        b"compress" => filter_code::COMPRESS,
        b"uuencode" => filter_code::UU,
        b"b64encode" => 15,
        b"lrzip" => filter_code::LRZIP,
        b"lzop" => filter_code::LZOP,
        b"grzip" => filter_code::GRZIP,
        _ => {
            return Err(Error::fatal(
                libc::EINVAL,
                [b"No such filter '".as_slice(), name, b"'"].concat(),
            ));
        }
    };
    by_code(code)
}
pub fn program(command: &[u8]) -> Result<Box<dyn Filter>, Error> {
    Ok(Box::new(program::Program::new(command)?))
}
struct NoneFilter;
impl Filter for NoneFilter {
    fn code(&self) -> i32 {
        filter_code::NONE
    }
    fn name(&self) -> &CStr {
        c"none"
    }
    fn write(&mut self, input: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        sink.write(input)
    }
    fn close(&mut self, _: &mut dyn Sink) -> Result<(), Error> {
        Ok(())
    }
}
fn invalid(message: &str) -> Error {
    Error::new(ARCHIVE_FAILED, -1, message.as_bytes())
}
fn io_error(e: std::io::Error) -> Error {
    Error::fatal(e.raw_os_error().unwrap_or(libc::EIO), e.to_string())
}
fn digit(value: Option<&[u8]>, min: u8, max: u8, msg: &str) -> Result<u8, Error> {
    match value {
        Some([b]) if *b >= b'0' + min && *b <= b'0' + max => Ok(*b - b'0'),
        _ => Err(invalid(msg)),
    }
}
fn number(value: Option<&[u8]>, msg: &str) -> Result<i64, Error> {
    value
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| invalid(msg))
}
