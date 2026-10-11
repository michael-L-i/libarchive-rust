//! The greedy, lazy and lazy2 block compressors (levels 5 and up), ported
//! from libzstd 1.5.7 (`ZSTD_compressBlock_lazy_generic()` with the
//! row-based match finder `ZSTD_RowFindBestMatch()`, in `zstd_lazy.c`).
//!
//! libzstd prefetches rows through a cache of hashes computed eight
//! positions ahead. Safe Rust has no prefetch, so hashes are computed when
//! they are used; the cache's bound on the searched positions is kept.

use core::convert::TryInto;

use super::fse::highbit32;
use super::match_state::{count, read32, read64, MatchState, SEARCH_STRENGTH};
use super::params::Strategy;
use super::sequences::SeqStore;

const ROW_HASH_TAG_BITS: u32 = 8;
const ROW_HASH_CACHE_SIZE: usize = 8;
/// `kLazySkippingStep`.
const LAZY_SKIPPING_STEP: usize = 8;
/// libzstd's offset code before any match is found.
const NO_OFFSET: u32 = 999_999_999;

/// `ZSTD_bitmix()`.
const fn bitmix(mut val: u64, len: u64) -> u64 {
    val ^= val.rotate_right(49) ^ val.rotate_right(24);
    val = val.wrapping_mul(0x9FB21C651E98DF25);
    val ^= (val >> 35) + len;
    val = val.wrapping_mul(0x9FB21C651E98DF25);
    val ^ (val >> 28)
}

/// The salt `ZSTD_advanceHashSalt()` gives a new context's first frame.
const HASH_SALT: u64 = bitmix(0, 8) ^ bitmix(0, 4);

/// Find the sequences of the block `src[start..]`; `src[..start]` is the
/// window. Returns where the last literals start.
pub(crate) fn compress_block(
    ms: &mut MatchState,
    store: &mut SeqStore,
    rep: &[u32; 3],
    src: &[u8],
    start: usize,
) -> usize {
    let depth = match ms.params.strategy {
        Strategy::Greedy => 0,
        Strategy::Lazy => 1,
        _ => 2,
    };
    let mls = ms.params.min_match.clamp(4, 6);
    let row_log = ms.params.search_log.clamp(4, 6);
    match (mls, row_log) {
        (4, 4) => lazy::<4, 4>(ms, store, rep, src, start, depth),
        (4, 5) => lazy::<4, 5>(ms, store, rep, src, start, depth),
        (4, _) => lazy::<4, 6>(ms, store, rep, src, start, depth),
        (5, 4) => lazy::<5, 4>(ms, store, rep, src, start, depth),
        (5, 5) => lazy::<5, 5>(ms, store, rep, src, start, depth),
        (5, _) => lazy::<5, 6>(ms, store, rep, src, start, depth),
        (_, 4) => lazy::<6, 4>(ms, store, rep, src, start, depth),
        (_, 5) => lazy::<6, 5>(ms, store, rep, src, start, depth),
        _ => lazy::<6, 6>(ms, store, rep, src, start, depth),
    }
}

/// `ZSTD_hashPtrSalted()` for the row tables: the row in the high bits,
/// the tag in the low 8.
#[inline(always)]
fn row_hash<const MLS: u32>(src: &[u8], pos: usize, bits: u32) -> u32 {
    const PRIME4: u32 = 2654435761;
    const PRIME5: u64 = 889523592379;
    const PRIME6: u64 = 227718039650203;
    match MLS {
        4 => (read32(src, pos).wrapping_mul(PRIME4) ^ HASH_SALT as u32) >> (32 - bits),
        5 => ((((read64(src, pos) << 24).wrapping_mul(PRIME5)) ^ HASH_SALT) >> (64 - bits)) as u32,
        _ => ((((read64(src, pos) << 16).wrapping_mul(PRIME6)) ^ HASH_SALT) >> (64 - bits)) as u32,
    }
}

/// The row search's tables for one block.
struct Rows<'a, const MLS: u32, const ROW_LOG: u32> {
    src: &'a [u8],
    base: u32,
    hash_bits: u32,
    entries: &'a mut [u32],
    tags: &'a mut [u8],
}

impl<const MLS: u32, const ROW_LOG: u32> Rows<'_, MLS, ROW_LOG> {
    const ENTRIES: usize = 1 << ROW_LOG;
    const MASK: u32 = (1 << ROW_LOG) - 1;

    #[inline(always)]
    fn hash(&self, pos: usize) -> u32 {
        row_hash::<MLS>(self.src, pos, self.hash_bits)
    }

    /// `ZSTD_row_nextIndex()`: rows are circular buffers whose head, the
    /// newest entry, is stored in tag 0, cycling backwards through 1..ENTRIES.
    #[inline(always)]
    fn insert(&mut self, hash: u32, index: u32) {
        let row = ((hash >> ROW_HASH_TAG_BITS) << ROW_LOG) as usize;
        let head = &mut self.tags[row];
        let mut next = u32::from(*head).wrapping_sub(1) & Self::MASK;
        if next == 0 {
            next = Self::MASK;
        }
        *head = next as u8;
        self.tags[row + next as usize] = hash as u8;
        self.entries[row + next as usize] = index;
    }

    /// `ZSTD_row_update_internalImpl()`.
    fn insert_range(&mut self, start: u32, end: u32) {
        for index in start..end {
            let hash = self.hash((index - self.base) as usize);
            self.insert(hash, index);
        }
    }

    /// `ZSTD_row_getMatchMask()` (its SWAR variant): bit i is set when the
    /// tag i positions after the head matches.
    #[inline(always)]
    fn match_mask(&self, row: usize, tag: u8, head: u32) -> u64 {
        const X01: u64 = 0x0101_0101_0101_0101;
        const X80: u64 = X01 << 7;
        const EXTRACT: u64 = (u64::MAX / 0x7F) >> 8;
        let splat = u64::from(tag) * X01;
        let mut matches = 0u64;
        for chunk in self.tags[row..row + Self::ENTRIES].rchunks_exact(8) {
            let chunk = chunk.try_into().map_or(0, u64::from_le_bytes) ^ splat;
            let nonzero = (((chunk | X80) - X01) | chunk) & X80;
            matches = (matches << 8) | (nonzero.wrapping_mul(EXTRACT) >> 56);
        }
        let matches = !matches;
        match Self::ENTRIES {
            16 => u64::from((matches as u16).rotate_right(head)),
            32 => u64::from((matches as u32).rotate_right(head)),
            _ => matches.rotate_right(head),
        }
    }
}

/// `ZSTD_RowFindBestMatch()`: the longest match for `ip` among the row's
/// candidates, as (length, offset code). Inserts `ip` and the positions
/// before it.
fn find_best_match<const MLS: u32, const ROW_LOG: u32>(
    ms: &mut MatchState,
    src: &[u8],
    ip: usize,
) -> (usize, u32) {
    let base = ms.base;
    let curr = base + ip as u32;
    let low_limit = ms.lowest_prefix_index(curr);
    let mut attempts = 1u32 << ms.params.search_log.min(ROW_LOG);
    let lazy_skipping = ms.lazy_skipping;
    let mut next_to_update = ms.next_to_update;
    let mut rows = Rows::<MLS, ROW_LOG> {
        src,
        base,
        hash_bits: ms.params.hash_log - ROW_LOG + ROW_HASH_TAG_BITS,
        entries: &mut ms.hash_table,
        tags: &mut ms.tag_table,
    };

    if !lazy_skipping {
        // ZSTD_row_update_internal(): after a long match, only insert its
        // first and last positions.
        if curr - next_to_update > 384 {
            rows.insert_range(next_to_update, next_to_update + 96);
            next_to_update = curr - 32;
        }
        rows.insert_range(next_to_update, curr);
    }
    // Lazy skipping stops inserting every position.
    next_to_update = curr;

    let hash = rows.hash(ip);
    let row = ((hash >> ROW_HASH_TAG_BITS) << ROW_LOG) as usize;
    let tag = hash as u8;
    let head = u32::from(rows.tags[row]) & Rows::<MLS, ROW_LOG>::MASK;
    let mut matches = rows.match_mask(row, tag, head);
    let mut candidates = [0u32; 64];
    let mut found = 0;
    while matches > 0 && attempts > 0 {
        let pos = (head + matches.trailing_zeros()) & Rows::<MLS, ROW_LOG>::MASK;
        matches &= matches - 1;
        if pos == 0 {
            continue;
        }
        let index = rows.entries[row + pos as usize];
        if index < low_limit {
            break;
        }
        candidates[found] = index;
        found += 1;
        attempts -= 1;
    }
    // Insert ip too, saving an iteration of the next update.
    rows.insert(hash, next_to_update);
    ms.next_to_update = next_to_update + 1;

    let mut ml = 3;
    let mut off_base = NO_OFFSET;
    for &index in &candidates[..found] {
        debug_assert!(index < curr);
        let m = (index - base) as usize;
        // Read 4 bytes ending where a longer match would.
        if read32(src, m + ml - 3) == read32(src, ip + ml - 3) {
            let length = count(src, ip, m);
            if length > ml {
                ml = length;
                off_base = curr - index + 3;
                if ip + length == src.len() {
                    break;
                }
            }
        }
    }
    (ml, off_base)
}

/// `ZSTD_compressBlock_lazy_generic()`: with `depth` 1 or 2, a match is
/// stored only if the next one or two positions do not yield a better one.
fn lazy<const MLS: u32, const ROW_LOG: u32>(
    ms: &mut MatchState,
    store: &mut SeqStore,
    rep: &[u32; 3],
    src: &[u8],
    istart: usize,
    depth: u32,
) -> usize {
    let iend = src.len();
    let ilimit = iend.saturating_sub(8 + ROW_HASH_CACHE_SIZE);
    let base = ms.base;
    let prefix_lowest = (ms.dict_limit - base) as usize;
    let mut anchor = istart;
    let mut ip = istart + usize::from(istart == prefix_lowest);
    let (mut offset_1, mut offset_2) = (rep[0], rep[1]);
    let curr = base + ip as u32;
    let max_rep = curr - ms.lowest_prefix_index(curr);
    if offset_2 > max_rep {
        offset_2 = 0;
    }
    if offset_1 > max_rep {
        offset_1 = 0;
    }
    ms.lazy_skipping = false;
    // A repeat offset match at pos.
    let repeat_at = |pos: usize, offset: u32| {
        offset > 0 && read32(src, pos) == read32(src, pos - offset as usize)
    };

    while ip < ilimit {
        let mut length = 0;
        let mut off_base = 1;
        let mut start = ip + 1;

        // Check the repeat offset at ip + 1, then search ip.
        let mut store_now = false;
        if repeat_at(ip + 1, offset_1) {
            length = count(src, ip + 1 + 4, ip + 1 + 4 - offset_1 as usize) + 4;
            store_now = depth == 0;
        }
        if !store_now {
            let (ml2, offset_found) = find_best_match::<MLS, ROW_LOG>(ms, src, ip);
            if ml2 > length {
                length = ml2;
                start = ip;
                off_base = offset_found;
            }
            if length < 4 {
                // Jump faster over incompressible sections. Beyond 8 bytes
                // per step, stop inserting every position into the table.
                let step = ((ip - anchor) >> SEARCH_STRENGTH) + 1;
                ip += step;
                ms.lazy_skipping = step > LAZY_SKIPPING_STEP;
                continue;
            }

            // Look for a better match at the next positions.
            while depth >= 1 && ip < ilimit {
                ip += 1;
                if repeat_at(ip, offset_1) {
                    let ml_rep = count(src, ip + 4, ip + 4 - offset_1 as usize) + 4;
                    let gain2 = (ml_rep * 3) as i32;
                    let gain1 = (length * 3) as i32 - highbit32(off_base) as i32 + 1;
                    if gain2 > gain1 {
                        length = ml_rep;
                        off_base = 1;
                        start = ip;
                    }
                }
                let (ml2, offset_found) = find_best_match::<MLS, ROW_LOG>(ms, src, ip);
                let gain2 = (ml2 * 4) as i32 - highbit32(offset_found) as i32;
                let gain1 = (length * 4) as i32 - highbit32(off_base) as i32 + 4;
                if ml2 >= 4 && gain2 > gain1 {
                    length = ml2;
                    off_base = offset_found;
                    start = ip;
                    continue;
                }
                if depth == 2 && ip < ilimit {
                    ip += 1;
                    if repeat_at(ip, offset_1) {
                        let ml_rep = count(src, ip + 4, ip + 4 - offset_1 as usize) + 4;
                        let gain2 = (ml_rep * 4) as i32;
                        let gain1 = (length * 4) as i32 - highbit32(off_base) as i32 + 1;
                        if gain2 > gain1 {
                            length = ml_rep;
                            off_base = 1;
                            start = ip;
                        }
                    }
                    let (ml2, offset_found) = find_best_match::<MLS, ROW_LOG>(ms, src, ip);
                    let gain2 = (ml2 * 4) as i32 - highbit32(offset_found) as i32;
                    let gain1 = (length * 4) as i32 - highbit32(off_base) as i32 + 7;
                    if ml2 >= 4 && gain2 > gain1 {
                        length = ml2;
                        off_base = offset_found;
                        start = ip;
                        continue;
                    }
                }
                break;
            }

            // Catch up: extend a new offset's match backwards.
            if off_base > 3 {
                let offset = off_base - 3;
                while start > anchor
                    && start - offset as usize > prefix_lowest
                    && src[start - 1] == src[start - 1 - offset as usize]
                {
                    start -= 1;
                    length += 1;
                }
                offset_2 = offset_1;
                offset_1 = offset;
            }
        }

        store.store(src, anchor, start, offset_1, length);
        ip = start + length;
        anchor = ip;
        ms.lazy_skipping = false;

        // Check immediate repeat offsets.
        while ip <= ilimit && repeat_at(ip, offset_2) {
            let length = count(src, ip + 4, ip + 4 - offset_2 as usize) + 4;
            core::mem::swap(&mut offset_1, &mut offset_2);
            store.store(src, anchor, ip, offset_1, length);
            ip += length;
            anchor = ip;
        }
    }
    anchor
}
