//! Decompression filters: `archive_read_support_filter_X.c` is
//! `filter/X.rs`, which exports `support`, the registration function.

pub mod all;
pub mod bzip2;
pub mod by_code;
pub mod compress;
pub mod grzip;
pub mod gzip;
pub mod lrzip;
pub mod lz4;
pub mod lzop;
pub mod none;
pub mod program;
pub mod rpm;
pub mod uu;
pub mod xz;
#[cfg(test)]
mod testing;

/// What `bidder` bids on a stream of `data`.
#[cfg(test)]
fn bid(bidder: &mut dyn crate::read::FilterBidder, data: &[u8]) -> std::ffi::c_int {
    use crate::archive::{ARCHIVE_OK, Base, READ_MAGIC};
    use crate::read::{Read, Status, format::raw};
    use crate::read_open_memory::Memory;
    let (mut r, a) = (Read::default(), Base::new(READ_MAGIC));
    assert_eq!(raw::support(&mut r), Ok(Status::Ok));
    assert_eq!(r.open(&a, Box::new(Memory::new(data.to_vec(), 4096))), ARCHIVE_OK);
    bidder.bid(&mut r.reader(&a)).unwrap()
}
