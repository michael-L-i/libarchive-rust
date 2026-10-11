//! Structures and utilities used for compressing/encoding data into the Zstandard format.
//!
//! The compressor is a port of libzstd 1.5.7's: its compression level
//! parameters, the fast, double fast, greedy, lazy and lazy2 block
//! compressors, block splitting, and the Huffman and FSE entropy stages.

mod double_fast;
mod fast;
mod frame_compressor;
mod fse;
mod huf;
mod lazy;
mod literals;
mod match_state;
mod params;
mod pre_split;
mod sequences;

pub use frame_compressor::{FrameCompressor, StreamCompressor};

use crate::io::{Read, Write};
use alloc::vec::Vec;

/// Convenience function to compress some source into a target without reusing any resources of the compressor
/// ```rust
/// use ruzstd::encoding::{compress, CompressionLevel};
/// let data: &[u8] = &[0,0,0,0,0,0,0,0,0,0,0,0];
/// let mut target = Vec::new();
/// compress(data, &mut target, CompressionLevel::Fastest);
/// ```
pub fn compress<R: Read, W: Write>(source: R, target: W, level: CompressionLevel) {
    let mut frame_enc = FrameCompressor::new(level);
    frame_enc.set_source(source);
    frame_enc.set_drain(target);
    frame_enc.compress();
}

/// Convenience function to compress some source into a Vec without reusing any resources of the compressor
/// ```rust
/// use ruzstd::encoding::{compress_to_vec, CompressionLevel};
/// let data: &[u8] = &[0,0,0,0,0,0,0,0,0,0,0,0];
/// let compressed = compress_to_vec(data, CompressionLevel::Fastest);
/// ```
pub fn compress_to_vec<R: Read>(source: R, level: CompressionLevel) -> Vec<u8> {
    let mut vec = Vec::new();
    compress(source, &mut vec, level);
    vec
}

/// The compression mode used impacts the speed of compression,
/// and resulting compression ratios. Faster compression will result
/// in worse compression ratios, and vice versa.
#[derive(Copy, Clone, Debug)]
pub enum CompressionLevel {
    /// This level does not compress the data at all, and simply wraps
    /// it in a Zstandard frame.
    Uncompressed,
    /// Zstd compression level 1.
    Fastest,
    /// Zstd compression level 3, the one used by the official compressor
    /// when no level is specified.
    Default,
    /// Zstd compression level 7.
    Better,
    /// Zstd compression level 11.
    Best,
    /// A zstd compression level, with zstd's meaning: up to 22, 0 for the
    /// default (3), and negative levels trade ratio for speed. Levels above
    /// 12 keep their window and table sizes but search like level 12, with
    /// the lazy2 strategy.
    Level(i32),
}
