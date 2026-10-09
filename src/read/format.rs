//! Format readers: `archive_read_support_format_X.c` is `format/X.rs`, which
//! exports `support`, the registration function.

pub mod all;
pub mod ar;
pub mod by_code;
pub mod cab;
pub mod cpio;
pub mod empty;
pub mod iso9660;
pub mod mtree;
pub mod raw;
pub mod warc;
