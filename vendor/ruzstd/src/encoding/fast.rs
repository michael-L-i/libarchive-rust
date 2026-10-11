//! The fast block compressor (levels 1-2 and negative levels), ported from
//! libzstd 1.5.7 (`ZSTD_compressBlock_fast_noDict_generic()` in `zstd_fast.c`).

use super::match_state::{count, hash, read32, slot, MatchState, HASH_READ_SIZE, SEARCH_STRENGTH};
use super::sequences::SeqStore;

/// Find the sequences of the block `src[start..]`; `src[..start]` is the
/// window. Returns where the last literals start.
pub(crate) fn compress_block(
    ms: &mut MatchState,
    store: &mut SeqStore,
    rep: &[u32; 3],
    src: &[u8],
    start: usize,
) -> usize {
    match ms.params.min_match {
        5 => fast::<5>(ms, store, rep, src, start),
        6 => fast::<6>(ms, store, rep, src, start),
        7.. => fast::<7>(ms, store, rep, src, start),
        _ => fast::<4>(ms, store, rep, src, start),
    }
}

/// libzstd interleaves the hash, table lookup and match check of the next
/// few positions, ip0 to ip3, and checks the repeat offset at ip2.
fn fast<const MLS: u32>(
    ms: &mut MatchState,
    store: &mut SeqStore,
    rep: &[u32; 3],
    src: &[u8],
    istart: usize,
) -> usize {
    const STEP_INCR: usize = 1 << (SEARCH_STRENGTH - 1);
    let hlog = ms.params.hash_log;
    let target_length = ms.params.target_length as usize;
    let step_size = target_length + usize::from(target_length == 0) + 1;
    let base = ms.base;
    let iend = src.len();
    let prefix_start_index = ms.lowest_prefix_index(base + iend as u32);
    let prefix_start = (prefix_start_index - base) as usize;
    let ilimit = iend.saturating_sub(HASH_READ_SIZE);
    let index = |pos: usize| base + pos as u32;

    let mut anchor = istart;
    let mut ip0 = istart + usize::from(istart == prefix_start);
    let (mut rep1, mut rep2) = (rep[0], rep[1]);
    let curr = index(ip0);
    let max_rep = curr - ms.lowest_prefix_index(curr);
    if rep2 > max_rep {
        rep2 = 0;
    }
    if rep1 > max_rep {
        rep1 = 0;
    }
    let table = &mut ms.hash_table[..];
    let found = |pos: usize, match_index: u32| {
        debug_assert!(match_index < index(pos));
        match_index >= prefix_start_index
            && read32(src, (match_index - base) as usize) == read32(src, pos)
    };

    loop {
        let mut step = step_size;
        let mut next_step = ip0 + STEP_INCR;
        let mut ip1 = ip0 + 1;
        let mut ip2 = ip0 + step;
        let mut ip3 = ip2 + 1;
        if ip3 >= ilimit {
            break;
        }
        let mut hash0 = hash::<MLS>(src, ip0, hlog);
        let mut hash1 = hash::<MLS>(src, ip1, hlog);
        let mut match_index = table[slot(table, hash0)];
        let mut current0;

        // Search: ends with a repeat offset match or a table match at ip0.
        let repeat = loop {
            let rval = read32(src, ip2 - rep1 as usize);
            current0 = index(ip0);
            table[slot(table, hash0)] = current0;
            if read32(src, ip2) == rval && rep1 > 0 {
                ip0 = ip2;
                table[slot(table, hash1)] = index(ip1);
                break true;
            }
            if found(ip0, match_index) {
                table[slot(table, hash1)] = index(ip1);
                break false;
            }
            match_index = table[slot(table, hash1)];
            hash0 = hash1;
            hash1 = hash::<MLS>(src, ip2, hlog);
            ip0 = ip1;
            ip1 = ip2;
            ip2 = ip3;
            current0 = index(ip0);
            table[slot(table, hash0)] = current0;
            if found(ip0, match_index) {
                // Write the next entry only if the search resumes beyond it.
                if step <= 4 {
                    table[slot(table, hash1)] = index(ip1);
                }
                break false;
            }
            match_index = table[slot(table, hash1)];
            hash0 = hash1;
            hash1 = hash::<MLS>(src, ip2, hlog);
            ip0 = ip1;
            ip1 = ip2;
            ip2 = ip0 + step;
            ip3 = ip1 + step;
            if ip2 >= next_step {
                step += 1;
                next_step += STEP_INCR;
            }
            if ip3 >= ilimit {
                return anchor;
            }
        };

        let (mut match0, mut length);
        if repeat {
            match0 = ip0 - rep1 as usize;
            length = usize::from(src[ip0 - 1] == src[match0 - 1]);
            ip0 -= length;
            match0 -= length;
            length += 4;
        } else {
            match0 = (match_index - base) as usize;
            rep2 = rep1;
            rep1 = (ip0 - match0) as u32;
            length = 4;
            // Count the backwards match length.
            while ip0 > anchor && match0 > prefix_start && src[ip0 - 1] == src[match0 - 1] {
                ip0 -= 1;
                match0 -= 1;
                length += 1;
            }
        }
        length += count(src, ip0 + length, match0 + length);
        store.store(src, anchor, ip0, rep1, length);
        ip0 += length;
        anchor = ip0;

        // Fill the table and check for immediate repeat offsets.
        if ip0 <= ilimit {
            let pos = (current0 - base) as usize + 2;
            table[slot(table, hash::<MLS>(src, pos, hlog))] = current0 + 2;
            table[slot(table, hash::<MLS>(src, ip0 - 2, hlog))] = index(ip0 - 2);
            if rep2 > 0 {
                while ip0 <= ilimit && read32(src, ip0) == read32(src, ip0 - rep2 as usize) {
                    let length = count(src, ip0 + 4, ip0 + 4 - rep2 as usize) + 4;
                    core::mem::swap(&mut rep1, &mut rep2);
                    table[slot(table, hash::<MLS>(src, ip0, hlog))] = index(ip0);
                    store.store(src, anchor, ip0, rep1, length);
                    ip0 += length;
                    anchor = ip0;
                }
            }
        }
    }
    anchor
}
