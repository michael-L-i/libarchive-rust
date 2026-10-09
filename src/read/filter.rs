//! Decompression filters: `archive_read_support_filter_X.c` is
//! `filter/X.rs`, which exports `support`, the registration function.

pub mod all;
pub mod by_code;
pub mod bzip2;
pub mod compress;
pub mod grzip;
pub mod gzip;
pub mod lrzip;
pub mod lz4;
pub mod lzop;
pub mod none;
pub mod program;
pub mod rpm;
#[cfg(test)]
pub(crate) mod testing;
pub mod uu;
pub mod xz;
pub mod zstd;
