//! Format readers: `archive_read_support_format_X.c` is `format/X.rs`, which
//! exports `support`, the registration function.

pub mod all;
pub mod by_code;
pub mod empty;
pub mod raw;
pub mod warc;
