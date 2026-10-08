//! Decompression filters: `archive_read_support_filter_X.c` is
//! `filter/X.rs`, which exports `support`, the registration function.

pub mod all;
pub mod by_code;
pub mod compress;
pub mod gzip;
pub mod none;
pub mod rpm;
pub mod uu;
pub mod xz;
#[cfg(test)]
mod testing;
