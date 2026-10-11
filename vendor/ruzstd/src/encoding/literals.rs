//! The literals section, ported from libzstd 1.5.7
//! (`zstd_compress_literals.c` and `HUF_compress_internal()`).

use super::fse::histogram;
use super::huf::{self, HufCTable};
use super::params::Strategy;

/// `ZSTD_hufCTables_t`. Without dictionaries libzstd's repeat mode is only
/// ever "none" or "check": `reusable` is the latter.
#[derive(Clone, Default)]
pub(crate) struct HufState {
    table: HufCTable,
    reusable: bool,
}

const SET_BASIC: u32 = 0;
const SET_RLE: u32 = 1;
const SET_COMPRESSED: u32 = 2;
const SET_REPEAT: u32 = 3;

/// `ZSTD_minGain()`: the saving a compressed block or literals section
/// needs over its raw size.
pub(crate) fn min_gain(src_size: usize) -> usize {
    (src_size >> 6) + 2
}

/// `ZSTD_noCompressLiterals()`.
fn raw_literals(dst: &mut [u8], src: &[u8]) -> Option<usize> {
    let fl_size = literals_header(dst, SET_BASIC, src.len())?;
    dst.get_mut(fl_size..fl_size + src.len())?
        .copy_from_slice(src);
    Some(fl_size + src.len())
}

/// `ZSTD_compressRleLiteralsBlock()`.
fn rle_literals(dst: &mut [u8], src: &[u8]) -> Option<usize> {
    let fl_size = literals_header(dst, SET_RLE, src.len())?;
    *dst.get_mut(fl_size)? = src[0];
    Some(fl_size + 1)
}

/// The 1-3 byte header of raw and RLE literals.
fn literals_header(dst: &mut [u8], kind: u32, size: usize) -> Option<usize> {
    let fl_size = 1 + usize::from(size > 31) + usize::from(size > 4095);
    let size = size as u32;
    let header = match fl_size {
        1 => kind + (size << 3),
        2 => kind + (1 << 2) + (size << 4),
        _ => kind + (3 << 2) + (size << 4),
    };
    dst.get_mut(..fl_size)?
        .copy_from_slice(&header.to_le_bytes()[..fl_size]);
    Some(fl_size)
}

/// `ZSTD_compressLiterals()`: writes the literals section to `dst` and the
/// Huffman table state for the next block to `next`. `None` means `dst` is
/// too small.
pub(crate) fn compress_literals(
    dst: &mut [u8],
    src: &[u8],
    prev: &HufState,
    next: &mut HufState,
    strategy: Strategy,
    disable_compression: bool,
    suspect_uncompressible: bool,
) -> Option<usize> {
    let lh_size = 3 + usize::from(src.len() >= 1024) + usize::from(src.len() >= 16 * 1024);
    let single_stream = src.len() < 256;
    next.clone_from(prev);
    // ZSTD_minLiteralsToCompress(): btultra2 needs 8 bytes, then 2x larger
    // for each faster strategy, up to 64.
    let min_literals = 8 << (9 - strategy as usize).min(3);
    if disable_compression || src.len() < min_literals {
        return raw_literals(dst, src);
    }
    if dst.len() < lh_size + 1 {
        return None;
    }
    let prefer_repeat = strategy < Strategy::Lazy && src.len() <= 1024;
    let (c_lit_size, h_type) = compress_huf(
        &mut dst[lh_size..],
        src,
        single_stream,
        next,
        prefer_repeat,
        suspect_uncompressible,
    );
    if c_lit_size == 0 || c_lit_size >= src.len() - min_gain(src.len()) {
        next.clone_from(prev);
        return raw_literals(dst, src);
    }
    if c_lit_size == 1 {
        // A single-symbol alphabet. A one-byte stream would need fewer than
        // eight literals and a table, so confirm the bytes are identical.
        if src.len() >= 8 || src.iter().all(|&b| b == src[0]) {
            next.clone_from(prev);
            return rle_literals(dst, src);
        }
    }
    if h_type == SET_COMPRESSED {
        next.reusable = true;
    }
    let (size, c_size) = (src.len() as u32, c_lit_size as u32);
    match lh_size {
        3 => {
            let lhc = h_type + (u32::from(!single_stream) << 2) + (size << 4) + (c_size << 14);
            dst[..3].copy_from_slice(&lhc.to_le_bytes()[..3]);
        }
        4 => {
            let lhc = h_type + (2 << 2) + (size << 4) + (c_size << 18);
            dst[..4].copy_from_slice(&lhc.to_le_bytes());
        }
        _ => {
            let lhc = h_type + (3 << 2) + (size << 4) + (c_size << 22);
            dst[..4].copy_from_slice(&lhc.to_le_bytes());
            dst[4] = (c_lit_size >> 10) as u8;
        }
    }
    Some(lh_size + c_lit_size)
}

/// `HUF_compress_internal()` with libzstd's literal flags: returns the
/// compressed size (0 if not worth it or on libzstd's errors, 1 for a single
/// symbol) and the literals type. `state` holds the previous table on entry
/// and the table to keep on return.
fn compress_huf(
    dst: &mut [u8],
    src: &[u8],
    single_stream: bool,
    state: &mut HufState,
    prefer_repeat: bool,
    suspect_uncompressible: bool,
) -> (usize, u32) {
    const SAMPLE_SIZE: usize = 4096;
    const SAMPLE_RATIO: usize = 10;
    if dst.is_empty() {
        return (0, SET_COMPRESSED);
    }
    let mut count = [0u32; 256];
    // If uncompressible data is suspected, sample both ends first.
    if suspect_uncompressible && src.len() >= SAMPLE_SIZE * SAMPLE_RATIO {
        let largest_begin = histogram(&mut count, &mut 255, &src[..SAMPLE_SIZE]);
        let largest_end = histogram(&mut count, &mut 255, &src[src.len() - SAMPLE_SIZE..]);
        if largest_begin + largest_end <= ((2 * SAMPLE_SIZE as u32) >> 7) + 4 {
            return (0, SET_COMPRESSED);
        }
    }
    let mut max_symbol = 255;
    let largest = histogram(&mut count, &mut max_symbol, src) as usize;
    if largest == src.len() {
        dst[0] = src[0];
        return (1, SET_COMPRESSED);
    }
    if largest <= (src.len() >> 7) + 4 {
        return (0, SET_COMPRESSED);
    }
    let count = &count[..=max_symbol as usize];
    if state.reusable && !state.table.validate(count) {
        state.reusable = false;
    }
    let reuse = |state: &HufState, dst: &mut [u8]| {
        (
            checked_size(state.table.compress(dst, src, !single_stream), src.len()),
            SET_REPEAT,
        )
    };
    if prefer_repeat && state.reusable {
        return reuse(state, dst);
    }
    let mut table = HufCTable::default();
    table.build(count, huf::optimal_table_log(src.len(), max_symbol));
    let Some(h_size) = table.write(dst) else {
        return (0, SET_COMPRESSED);
    };
    if state.reusable {
        let old_size = state.table.estimate(count);
        let new_size = table.estimate(count);
        if old_size <= h_size + new_size || h_size + 12 >= src.len() {
            return reuse(state, dst);
        }
    }
    if h_size + 12 >= src.len() {
        return (0, SET_COMPRESSED);
    }
    let size = table.compress(&mut dst[h_size..], src, !single_stream);
    state.table = table;
    state.reusable = false;
    (
        checked_size(if size == 0 { 0 } else { h_size + size }, src.len()),
        SET_COMPRESSED,
    )
}

/// `HUF_compressCTable_internal()`'s check: 0 unless it saves two bytes.
fn checked_size(size: usize, src_size: usize) -> usize {
    if size == 0 || size >= src_size - 1 {
        0
    } else {
        size
    }
}
