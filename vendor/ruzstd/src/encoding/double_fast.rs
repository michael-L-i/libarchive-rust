//! The double fast block compressor (levels 3-4), ported from libzstd 1.5.7
//! (`ZSTD_compressBlock_doubleFast_noDict_generic()` in
//! `zstd_double_fast.c`).

use super::match_state::{
    count, hash, hash_value, read32, read64, slot, MatchState, HASH_READ_SIZE, SEARCH_STRENGTH,
};
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
        5 => double_fast::<5>(ms, store, rep, src, start),
        6 => double_fast::<6>(ms, store, rep, src, start),
        7.. => double_fast::<7>(ms, store, rep, src, start),
        _ => double_fast::<4>(ms, store, rep, src, start),
    }
}

/// A long table of 8-byte hashes and a short table of `MLS`-byte hashes.
/// Short matches are extended with a long match at the next position if
/// that one is longer.
fn double_fast<const MLS: u32>(
    ms: &mut MatchState,
    store: &mut SeqStore,
    rep: &[u32; 3],
    src: &[u8],
    istart: usize,
) -> usize {
    const STEP_INCR: usize = 1 << SEARCH_STRENGTH;
    let hbits_long = ms.params.hash_log;
    let hbits_short = ms.params.chain_log;
    let base = ms.base;
    let iend = src.len();
    let prefix_lowest_index = ms.lowest_prefix_index(base + iend as u32);
    let prefix_lowest = (prefix_lowest_index - base) as usize;
    let ilimit = iend.saturating_sub(HASH_READ_SIZE);
    let index = |pos: usize| base + pos as u32;

    let mut anchor = istart;
    let mut ip = istart + usize::from(istart == prefix_lowest);
    let (mut offset_1, mut offset_2) = (rep[0], rep[1]);
    let curr = index(ip);
    let max_rep = curr - ms.lowest_prefix_index(curr);
    if offset_2 > max_rep {
        offset_2 = 0;
    }
    if offset_1 > max_rep {
        offset_1 = 0;
    }
    let hash_long = &mut ms.hash_table[..];
    let hash_small = &mut ms.chain_table[..];
    // ZSTD_selectAddr(): the position of a candidate if it is in the window,
    // else the start of the buffer, whose bytes are compared but ignored.
    let candidate = |match_index: u32| {
        let valid = match_index >= prefix_lowest_index;
        (
            if valid {
                (match_index - base) as usize
            } else {
                0
            },
            valid,
        )
    };

    // One iteration per match found and stored.
    loop {
        let mut step = 1;
        let mut next_step = ip + STEP_INCR;
        let mut ip1 = ip + step;
        if ip1 > ilimit {
            return anchor;
        }
        // The bytes at ip, read once for both hashes and every comparison.
        let mut bytes = read64(src, ip);
        let mut hl0 = hash_value::<8>(bytes, hbits_long);
        let mut idxl0 = hash_long[slot(hash_long, hl0)];
        let mut curr;

        // One iteration per position searched: ends with the length of a
        // stored repeat offset match, or of a match at ip to store.
        let (length, found) = loop {
            let hs0 = hash_value::<MLS>(bytes, hbits_short);
            let idxs0 = hash_small[slot(hash_small, hs0)];
            curr = index(ip);
            hash_long[slot(hash_long, hl0)] = curr;
            hash_small[slot(hash_small, hs0)] = curr;

            // Check the repeat offset at ip + 1.
            if (offset_1 > 0) & (read32(src, ip + 1 - offset_1 as usize) == (bytes >> 8) as u32) {
                let length = count(src, ip + 1 + 4, ip + 1 + 4 - offset_1 as usize) + 4;
                ip += 1;
                store.store(src, anchor, ip, offset_1, length);
                break (length, None);
            }

            let bytes1 = read64(src, ip1);
            let hl1 = hash_value::<8>(bytes1, hbits_long);
            // Check the long match at ip.
            let (mut m, valid) = candidate(idxl0);
            if (read64(src, m) == bytes) & valid {
                let mut length = count(src, ip + 8, m + 8) + 8;
                let offset = (ip - m) as u32;
                while ip > anchor && m > prefix_lowest && src[ip - 1] == src[m - 1] {
                    ip -= 1;
                    m -= 1;
                    length += 1;
                }
                break (length, Some((offset, hl1)));
            }
            let idxl1 = hash_long[slot(hash_long, hl1)];

            // Check the short match at ip, then a long match at ip1.
            let (mut m, valid) = candidate(idxs0);
            if (read32(src, m) == bytes as u32) & valid {
                let mut length = count(src, ip + 4, m + 4) + 4;
                let mut offset = (ip - m) as u32;
                let (l1, valid) = candidate(idxl1);
                if valid && idxl1 > prefix_lowest_index && read64(src, l1) == bytes1 {
                    let l1len = count(src, ip1 + 8, l1 + 8) + 8;
                    if l1len > length {
                        ip = ip1;
                        length = l1len;
                        offset = (ip - l1) as u32;
                        m = l1;
                    }
                }
                while ip > anchor && m > prefix_lowest && src[ip - 1] == src[m - 1] {
                    ip -= 1;
                    m -= 1;
                    length += 1;
                }
                break (length, Some((offset, hl1)));
            }

            if ip1 >= next_step {
                step += 1;
                next_step += STEP_INCR;
            }
            ip = ip1;
            ip1 += step;
            hl0 = hl1;
            idxl0 = idxl1;
            bytes = bytes1;
            if ip1 > ilimit {
                return anchor;
            }
        };

        if let Some((offset, hl1)) = found {
            offset_2 = offset_1;
            offset_1 = offset;
            // ip1 is below the next search position only while the step is
            // less than the minimum match length.
            if step < 4 {
                hash_long[slot(hash_long, hl1)] = index(ip1);
            }
            store.store(src, anchor, ip, offset, length);
        }
        ip += length;
        anchor = ip;

        if ip <= ilimit {
            // Complementary insertion.
            let insert = curr + 2;
            let pos = (insert - base) as usize;
            hash_long[slot(hash_long, hash::<8>(src, pos, hbits_long))] = insert;
            hash_long[slot(hash_long, hash::<8>(src, ip - 2, hbits_long))] = index(ip - 2);
            hash_small[slot(hash_small, hash::<MLS>(src, pos, hbits_short))] = insert;
            hash_small[slot(hash_small, hash::<MLS>(src, ip - 1, hbits_short))] = index(ip - 1);

            // Check immediate repeat offsets.
            while ip <= ilimit
                && offset_2 > 0
                && read32(src, ip) == read32(src, ip - offset_2 as usize)
            {
                let length = count(src, ip + 4, ip + 4 - offset_2 as usize) + 4;
                core::mem::swap(&mut offset_1, &mut offset_2);
                hash_small[slot(hash_small, hash::<MLS>(src, ip, hbits_short))] = index(ip);
                hash_long[slot(hash_long, hash::<8>(src, ip, hbits_long))] = index(ip);
                store.store(src, anchor, ip, offset_1, length);
                ip += length;
                anchor = ip;
            }
        }
    }
}
