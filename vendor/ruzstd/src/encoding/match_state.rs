//! The match finders' shared state and helpers, ported from libzstd 1.5.7
//! (`ZSTD_MatchState_t` and `zstd_compress_internal.h`).
//!
//! Positions are libzstd's 32-bit indices. The frame's input is kept in one
//! contiguous buffer, so libzstd's external-dictionary segment never arises;
//! `base` is the index of the buffer's first byte.

use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryInto;

use super::params::{CParams, Strategy};

/// `ZSTD_WINDOW_START_INDEX`: the frame's first byte.
pub(crate) const WINDOW_START_INDEX: u32 = 2;
/// `ZSTD_CURRENT_MAX` on 64-bit targets: indices are corrected beyond it.
pub(crate) const CURRENT_MAX: u32 = 3500 << 20;
/// `HASH_READ_SIZE`.
pub(crate) const HASH_READ_SIZE: usize = 8;
/// `kSearchStrength`.
pub(crate) const SEARCH_STRENGTH: u32 = 8;

pub(crate) struct MatchState {
    pub params: CParams,
    /// Index of the buffer's first byte.
    pub base: u32,
    /// libzstd's `dictLimit`: the lowest index matches may refer to.
    pub dict_limit: u32,
    /// The long table for double fast, the row table for the lazy search.
    pub hash_table: Vec<u32>,
    /// The short table for double fast.
    pub chain_table: Vec<u32>,
    /// The row search's tags.
    pub tag_table: Vec<u8>,
    /// The next index the lazy search inserts.
    pub next_to_update: u32,
    pub lazy_skipping: bool,
}

impl MatchState {
    pub(crate) fn new(params: CParams) -> Self {
        let tables = |log: u32| vec![0u32; 1 << log];
        let (hash_table, chain_table, tag_table) = match params.strategy {
            Strategy::Fast => (tables(params.hash_log), Vec::new(), Vec::new()),
            Strategy::DFast => (
                tables(params.hash_log),
                tables(params.chain_log),
                Vec::new(),
            ),
            _ => (
                tables(params.hash_log),
                Vec::new(),
                vec![0u8; 1 << params.hash_log],
            ),
        };
        Self {
            params,
            base: WINDOW_START_INDEX,
            dict_limit: WINDOW_START_INDEX,
            hash_table,
            chain_table,
            tag_table,
            next_to_update: WINDOW_START_INDEX,
            lazy_skipping: false,
        }
    }

    /// `ZSTD_getLowestPrefixIndex()`.
    #[inline(always)]
    pub(crate) fn lowest_prefix_index(&self, curr: u32) -> u32 {
        let max_distance = 1u32 << self.params.window_log;
        if curr - self.dict_limit > max_distance {
            curr - max_distance
        } else {
            self.dict_limit
        }
    }

    /// `ZSTD_window_enforceMaxDist()` for a block starting at `block_start`,
    /// and the lower bound for table updates that follows it.
    pub(crate) fn enforce_max_dist(&mut self, block_start: u32) {
        let max_dist = 1u32 << self.params.window_log;
        if block_start > max_dist {
            self.dict_limit = self.dict_limit.max(block_start - max_dist);
        }
        self.next_to_update = self.next_to_update.max(self.dict_limit);
    }

    /// `ZSTD_window_correctOverflow()` and `ZSTD_reduceIndex()`: lower every
    /// index by a multiple of the table cycle, keeping at least a window
    /// below `curr`. Returns the correction.
    pub(crate) fn correct_overflow(&mut self, curr: u32) -> u32 {
        let cycle_size = 1u32 << self.params.chain_log;
        let max_dist = 1u32 << self.params.window_log;
        let current_cycle = curr & (cycle_size - 1);
        // Ensure new_current - max_dist >= WINDOW_START_INDEX.
        let cycle_correction = if current_cycle < WINDOW_START_INDEX {
            cycle_size.max(WINDOW_START_INDEX)
        } else {
            0
        };
        let new_current = current_cycle + cycle_correction + max_dist.max(cycle_size);
        let correction = curr - new_current;
        // ZSTD_reduceTable(): indices below the corrected window start
        // become 0, below every window.
        let reduce = |index: u32| {
            index
                .checked_sub(correction)
                .filter(|&i| i >= WINDOW_START_INDEX)
        };
        self.base -= correction;
        self.dict_limit = reduce(self.dict_limit).unwrap_or(WINDOW_START_INDEX);
        self.next_to_update = self.next_to_update.saturating_sub(correction);
        for table in [&mut self.hash_table, &mut self.chain_table] {
            for index in table.iter_mut() {
                *index = reduce(*index).unwrap_or(0);
            }
        }
        correction
    }
}

#[inline(always)]
pub(crate) fn read16(src: &[u8], pos: usize) -> u16 {
    src[pos..pos + 2].try_into().map_or(0, u16::from_le_bytes)
}

#[inline(always)]
pub(crate) fn read32(src: &[u8], pos: usize) -> u32 {
    src[pos..pos + 4].try_into().map_or(0, u32::from_le_bytes)
}

#[inline(always)]
pub(crate) fn read64(src: &[u8], pos: usize) -> u64 {
    src[pos..pos + 8].try_into().map_or(0, u64::from_le_bytes)
}

/// `ZSTD_hashPtr()` for the `MLS` bytes at `pos`, of `bits` bits.
#[inline(always)]
pub(crate) fn hash<const MLS: u32>(src: &[u8], pos: usize, bits: u32) -> usize {
    hash_value::<MLS>(read64(src, pos), bits)
}

/// `ZSTD_hashPtr()` for the low `MLS` bytes of `value`, the bytes at a
/// position read little-endian.
#[inline(always)]
pub(crate) fn hash_value<const MLS: u32>(value: u64, bits: u32) -> usize {
    const PRIME4: u32 = 2654435761;
    const PRIME5: u64 = 889523592379;
    const PRIME6: u64 = 227718039650203;
    const PRIME7: u64 = 58295818150454627;
    const PRIME8: u64 = 0xCF1BBCDCB7A56463;
    match MLS {
        5 => ((value << 24).wrapping_mul(PRIME5) >> (64 - bits)) as usize,
        6 => ((value << 16).wrapping_mul(PRIME6) >> (64 - bits)) as usize,
        7 => ((value << 8).wrapping_mul(PRIME7) >> (64 - bits)) as usize,
        8 => (value.wrapping_mul(PRIME8) >> (64 - bits)) as usize,
        _ => ((value as u32).wrapping_mul(PRIME4) >> (32 - bits)) as usize,
    }
}

/// The index of `hash` in `table`. Hashes are below the table size, a power
/// of two; the mask lets the compiler see that.
#[inline(always)]
pub(crate) fn slot(table: &[u32], hash: usize) -> usize {
    hash & (table.len() - 1)
}

/// `ZSTD_count()`: the length of the common prefix of `src[pos..]` and
/// `src[at..]`, with `at < pos`.
#[inline(always)]
pub(crate) fn count(src: &[u8], mut pos: usize, mut at: usize) -> usize {
    let start = pos;
    let end = src.len();
    while pos + 8 <= end {
        let diff = read64(src, at) ^ read64(src, pos);
        if diff != 0 {
            return pos - start + (diff.trailing_zeros() >> 3) as usize;
        }
        pos += 8;
        at += 8;
    }
    if pos + 4 <= end && read32(src, at) == read32(src, pos) {
        pos += 4;
        at += 4;
    }
    if pos + 2 <= end && read16(src, at) == read16(src, pos) {
        pos += 2;
        at += 2;
    }
    if pos < end && src[at] == src[pos] {
        pos += 1;
    }
    pos - start
}
