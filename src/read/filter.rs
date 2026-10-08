//! Decompression filters: `archive_read_support_filter_X.c` is
//! `filter/X.rs`, which exports `support`, the registration function.

pub mod all;
pub mod by_code;
pub mod compress;
pub mod none;
pub mod uu;
#[cfg(test)]
mod testing;
