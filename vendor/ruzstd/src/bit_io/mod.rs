//! Encoding agnostic ways to read and write binary data

mod bit_reader;
mod bit_reader_reverse;
#[cfg(any(test, feature = "fuzz_exports"))]
mod bit_writer;

pub(crate) use bit_reader::*;
pub(crate) use bit_reader_reverse::*;
#[cfg(any(test, feature = "fuzz_exports"))]
pub(crate) use bit_writer::*;
