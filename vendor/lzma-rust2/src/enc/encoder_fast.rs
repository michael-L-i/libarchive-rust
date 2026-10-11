//! Fast-mode optimum, ported from liblzma 5.8.4
//! (`lzma/lzma_encoder_optimum_fast.c`; Igor Pavlov; 0BSD).

use super::encoder::{LzmaEncoder, MATCH_LEN_MAX};
use crate::{
    REPS,
    lz::{Mf, memcmplen},
};

#[inline(always)]
fn change_pair(small_dist: u32, big_dist: u32) -> bool {
    (big_dist >> 7) > small_dist
}

impl LzmaEncoder {
    /// Returns the next symbol as (back, len) (`lzma_lzma_optimum_fast()`).
    pub(crate) fn optimum_fast(&mut self, mf: &mut Mf) -> (u32, u32) {
        let nice_len = mf.nice_len;

        let (mut len_main, mut matches_count) = if mf.read_ahead == 0 {
            mf.find(&mut self.matches)
        } else {
            debug_assert_eq!(mf.read_ahead, 1);
            (self.longest_match_length, self.matches_count)
        };

        let buf = mf.read_pos as usize - 1;
        let buf_avail = (mf.avail() + 1).min(MATCH_LEN_MAX);

        if buf_avail < 2 {
            // There's not enough input left to encode a match.
            return (u32::MAX, 1);
        }

        // Look for repeated matches; scan the previous four match distances
        let mut rep_len = 0;
        let mut rep_index = 0;

        for i in 0..REPS {
            // Pointer to the beginning of the match candidate
            let buf_back = buf - self.reps[i] as usize - 1;

            // If the first two bytes (2 == MATCH_LEN_MIN) do not match,
            // this rep is not useful.
            if mf.buffer[buf..buf + 2] != mf.buffer[buf_back..buf_back + 2] {
                continue;
            }

            // The first two bytes matched.
            // Calculate the length of the match.
            let len = memcmplen(&mf.buffer, buf, buf_back, 2, buf_avail);

            // If we have found a repeated match that is at least
            // nice_len long, return it immediately.
            if len >= nice_len {
                mf.skip(len - 1);
                return (i as u32, len);
            }

            if len > rep_len {
                rep_index = i as u32;
                rep_len = len;
            }
        }

        // We didn't find a long enough repeated match. Encode it as a normal
        // match if the match length is at least nice_len.
        if len_main >= nice_len {
            let back = self.matches[matches_count as usize - 1].dist + REPS as u32;
            mf.skip(len_main - 1);
            return (back, len_main);
        }

        let mut back_main = 0;
        if len_main >= 2 {
            back_main = self.matches[matches_count as usize - 1].dist;

            while matches_count > 1 && len_main == self.matches[matches_count as usize - 2].len + 1
            {
                if !change_pair(self.matches[matches_count as usize - 2].dist, back_main) {
                    break;
                }
                matches_count -= 1;
                len_main = self.matches[matches_count as usize - 1].len;
                back_main = self.matches[matches_count as usize - 1].dist;
            }

            if len_main == 2 && back_main >= 0x80 {
                len_main = 1;
            }
        }

        if rep_len >= 2
            && (rep_len + 1 >= len_main
                || (rep_len + 2 >= len_main && back_main > 1 << 9)
                || (rep_len + 3 >= len_main && back_main > 1 << 15))
        {
            mf.skip(rep_len - 1);
            return (rep_index, rep_len);
        }

        if len_main < 2 || buf_avail <= 2 {
            return (u32::MAX, 1);
        }

        // Get the matches for the next byte. If we find a better match,
        // the current byte is encoded as a literal.
        let (longest, count) = mf.find(&mut self.matches);
        self.longest_match_length = longest;
        self.matches_count = count;

        if longest >= 2 {
            let new_dist = self.matches[count as usize - 1].dist;
            if (longest >= len_main && new_dist < back_main)
                || (longest == len_main + 1 && !change_pair(back_main, new_dist))
                || longest > len_main + 1
                || (longest + 1 >= len_main && len_main >= 3 && change_pair(new_dist, back_main))
            {
                return (u32::MAX, 1);
            }
        }

        // The dictionary could not have been moved between the find calls,
        // so the next byte is simply at buf + 1.
        let buf = buf + 1;
        let limit = 2.max(len_main - 1) as usize;

        for &rep in &self.reps {
            let back = buf - rep as usize - 1;
            if mf.buffer[buf..buf + limit] == mf.buffer[back..back + limit] {
                return (u32::MAX, 1);
            }
        }

        mf.skip(len_main - 2);
        (back_main + REPS as u32, len_main)
    }
}
