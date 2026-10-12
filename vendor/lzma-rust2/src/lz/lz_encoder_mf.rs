//! Match finders, ported from liblzma 5.8.4 (`lz/lz_encoder_mf.c`,
//! `lz/lz_encoder_hash.h`, `common/memcmplen.h`; Igor Pavlov, Lasse Collin;
//! 0BSD).

use super::lz_encoder::{Action, HASH_2_SIZE, MEMCMPLEN_EXTRA, Match, Mf, MfType, Run};

const HASH_2_MASK: u32 = HASH_2_SIZE as u32 - 1;
const HASH_3_MASK: u32 = (1 << 16) - 1;

/// Hash value to indicate unused element in the hash. Since we start the
/// positions from dict_size + 1, zero is always too far to qualify
/// as usable match position.
const EMPTY_HASH_VALUE: u32 = 0;

/// Normalization must be done when `offset + read_pos` reaches this.
const MUST_NORMALIZE_POS: u32 = u32::MAX;

#[inline(always)]
fn read_u64(buf: &[u8], pos: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&buf[pos..pos + 8]);
    u64::from_le_bytes(word)
}

/// Finds out how many equal bytes `buf[a..]` and `buf[b..]` have, assuming
/// the first `len` bytes match and comparing at most `limit` bytes. Up to
/// `MEMCMPLEN_EXTRA` bytes may be read past the limit.
#[inline(always)]
pub(crate) fn memcmplen(buf: &[u8], a: usize, b: usize, mut len: u32, limit: u32) -> u32 {
    debug_assert!(len <= limit);
    // Words starting below the limit end within these slices.
    let end = limit as usize + MEMCMPLEN_EXTRA as usize - 1;
    let (a, b) = (&buf[a..a + end], &buf[b..b + end]);
    while len < limit {
        let x = read_u64(a, len as usize) ^ read_u64(b, len as usize);
        if x != 0 {
            len += x.trailing_zeros() >> 3;
            return len.min(limit);
        }
        len += 8;
    }
    limit
}

/// The CRC32 table used for hashing.
static HASH_TABLE: [u32; 256] = {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut r = i as u32;
        let mut j = 0;
        while j < 8 {
            r = if r & 1 != 0 {
                (r >> 1) ^ 0xEDB8_8320
            } else {
                r >> 1
            };
            j += 1;
        }
        table[i] = r;
        i += 1;
    }
    table
};

/// Returns (hash_2_value, hash_3_value, temp ^ (cur[2] << 8)).
#[inline(always)]
fn hash_23(cur: &[u8]) -> (usize, usize, u32) {
    let temp = HASH_TABLE[cur[0] as usize] ^ u32::from(cur[1]);
    let temp3 = temp ^ (u32::from(cur[2]) << 8);
    (
        (temp & HASH_2_MASK) as usize,
        (temp3 & HASH_3_MASK) as usize,
        temp3,
    )
}

/// Returns (hash_2_value, hash_3_value, hash_value) as in `hash_4_calc()`.
#[inline(always)]
fn hash_4(cur: &[u8], hash_mask: u32) -> (usize, usize, usize) {
    let (h2, h3, temp3) = hash_23(cur);
    let h4 = (temp3 ^ (HASH_TABLE[cur[3] as usize] << 5)) & hash_mask;
    (h2, h3, h4 as usize)
}

/// Index of the son entry of the position `delta` bytes before `cyclic_pos`.
#[inline(always)]
fn cyclic_index(cyclic_pos: u32, delta: u32, cyclic_size: u32) -> usize {
    cyclic_pos
        .wrapping_sub(delta)
        .wrapping_add(if delta > cyclic_pos { cyclic_size } else { 0 }) as usize
}

/// Builds the search parameters for the current position, borrowing only
/// the buffer so that `son` stays available for writing.
macro_rules! search {
    ($mf:expr, $len_limit:expr) => {
        Search {
            len_limit: $len_limit,
            pos: $mf.read_pos.wrapping_add($mf.offset),
            buf: &$mf.buffer,
            cur: $mf.read_pos as usize,
            depth: $mf.depth,
            cyclic_pos: $mf.cyclic_pos,
            cyclic_size: $mf.cyclic_size,
        }
    };
}

/// Search parameters shared by the hash chain and binary tree loops.
struct Search<'a> {
    len_limit: u32,
    pos: u32,
    buf: &'a [u8],
    cur: usize,
    depth: u32,
    cyclic_pos: u32,
    cyclic_size: u32,
}

fn hc_find_func(
    s: &Search,
    son: &mut [u32],
    mut cur_match: u32,
    matches: &mut [Match],
    mut count: usize,
    mut len_best: u32,
) -> usize {
    let Search {
        len_limit,
        pos,
        buf,
        cur,
        mut depth,
        cyclic_pos,
        cyclic_size,
    } = *s;
    son[cyclic_pos as usize] = cur_match;

    loop {
        let delta = pos.wrapping_sub(cur_match);
        if depth == 0 || delta >= cyclic_size {
            return count;
        }
        depth -= 1;

        let pb = cur - delta as usize;
        cur_match = son[cyclic_index(cyclic_pos, delta, cyclic_size)];

        if buf[pb + len_best as usize] == buf[cur + len_best as usize] && buf[pb] == buf[cur] {
            let len = memcmplen(buf, pb, cur, 1, len_limit);
            if len_best < len {
                len_best = len;
                matches[count] = Match {
                    len,
                    dist: delta - 1,
                };
                count += 1;
                if len == len_limit {
                    return count;
                }
            }
        }
    }
}

fn bt_find_func(
    s: &Search,
    son: &mut [u32],
    mut cur_match: u32,
    matches: &mut [Match],
    mut count: usize,
    mut len_best: u32,
) -> usize {
    let Search {
        len_limit,
        pos,
        buf,
        cur,
        mut depth,
        cyclic_pos,
        cyclic_size,
    } = *s;
    let mut ptr0 = (cyclic_pos as usize) * 2 + 1;
    let mut ptr1 = (cyclic_pos as usize) * 2;
    let mut len0 = 0;
    let mut len1 = 0;

    loop {
        let delta = pos.wrapping_sub(cur_match);
        if depth == 0 || delta >= cyclic_size {
            son[ptr0] = EMPTY_HASH_VALUE;
            son[ptr1] = EMPTY_HASH_VALUE;
            return count;
        }
        depth -= 1;

        let pair = cyclic_index(cyclic_pos, delta, cyclic_size) * 2;
        let pb = cur - delta as usize;
        let mut len = len0.min(len1);

        if buf[pb + len as usize] == buf[cur + len as usize] {
            len = memcmplen(buf, pb, cur, len + 1, len_limit);
            if len_best < len {
                len_best = len;
                matches[count] = Match {
                    len,
                    dist: delta - 1,
                };
                count += 1;
                if len == len_limit {
                    son[ptr1] = son[pair];
                    son[ptr0] = son[pair + 1];
                    return count;
                }
            }
        }

        if buf[pb + len as usize] < buf[cur + len as usize] {
            son[ptr1] = cur_match;
            ptr1 = pair + 1;
            cur_match = son[ptr1];
            len1 = len;
        } else {
            son[ptr0] = cur_match;
            ptr0 = pair;
            cur_match = son[ptr0];
            len0 = len;
        }
    }
}

/// Like `bt_find_func()` without collecting matches. Inside a long repeat,
/// the first node of consecutive positions is usually at the same
/// distance and reaches `len_limit`. When it does, the repeat is measured
/// up to `run_limit` bytes into `run`, and the next positions it covers
/// take `len_limit` at that node without comparing bytes.
fn bt_skip_func(s: &Search, son: &mut [u32], mut cur_match: u32, run: &mut Run, run_limit: u32) {
    let Search {
        len_limit,
        pos,
        buf,
        cur,
        mut depth,
        cyclic_pos,
        cyclic_size,
    } = *s;
    let mut ptr0 = (cyclic_pos as usize) * 2 + 1;
    let mut ptr1 = (cyclic_pos as usize) * 2;
    let mut len0 = 0;
    let mut len1 = 0;

    let delta = pos.wrapping_sub(cur_match);
    let done = pos.wrapping_sub(run.start);
    if delta == run.delta && done < run.len && run.len - done >= len_limit && depth != 0 {
        let pair = cyclic_index(cyclic_pos, delta, cyclic_size) * 2;
        debug_assert_eq!(
            buf[cur - delta as usize..][..len_limit as usize],
            buf[cur..][..len_limit as usize]
        );
        son[ptr1] = son[pair];
        son[ptr0] = son[pair + 1];
        return;
    }

    loop {
        let delta = pos.wrapping_sub(cur_match);
        if depth == 0 || delta >= cyclic_size {
            son[ptr0] = EMPTY_HASH_VALUE;
            son[ptr1] = EMPTY_HASH_VALUE;
            return;
        }
        depth -= 1;

        let pair = cyclic_index(cyclic_pos, delta, cyclic_size) * 2;
        let pb = cur - delta as usize;
        let mut len = len0.min(len1);

        if buf[pb + len as usize] == buf[cur + len as usize] {
            len = memcmplen(buf, pb, cur, len + 1, len_limit);
            if len == len_limit {
                if depth + 1 == s.depth {
                    *run = Run {
                        delta,
                        start: pos,
                        len: memcmplen(buf, pb, cur, len_limit, run_limit),
                    };
                }
                son[ptr1] = son[pair];
                son[ptr0] = son[pair + 1];
                return;
            }
        }

        if buf[pb + len as usize] < buf[cur + len as usize] {
            son[ptr1] = cur_match;
            ptr1 = pair + 1;
            cur_match = son[ptr1];
            len1 = len;
        } else {
            son[ptr0] = cur_match;
            ptr0 = pair;
            cur_match = son[ptr0];
            len0 = len;
        }
    }
}

impl Mf {
    /// Finds matches starting from the current byte (`lzma_mf_find()`).
    /// Returns the length of the longest match and the number of matches.
    pub(crate) fn find(&mut self, matches: &mut [Match]) -> (u32, u32) {
        let count = match self.kind {
            MfType::Hc3 => self.hc3_find(matches),
            MfType::Hc4 => self.hc4_find(matches),
            MfType::Bt4 => self.bt4_find(matches),
        };

        // Length of the longest match; assume that no matches were found
        // and thus the maximum length is zero.
        let mut len_best = 0;
        if count > 0 {
            #[cfg(debug_assertions)]
            for m in &matches[..count] {
                let cur = self.read_pos as usize - 1;
                let back = cur - m.dist as usize - 1;
                debug_assert!(m.len <= self.nice_len && m.dist < self.read_pos);
                debug_assert_eq!(
                    self.buffer[cur..cur + m.len as usize],
                    self.buffer[back..back + m.len as usize]
                );
            }

            // The last used element in the array contains
            // the longest match.
            len_best = matches[count - 1].len;

            // If a match of maximum search length was found, try to
            // extend the match to maximum possible length.
            if len_best == self.nice_len {
                // The limit for the match length is either the
                // maximum match length supported by the LZ-based
                // encoder or the number of bytes left in the
                // dictionary, whichever is smaller.
                let limit = (self.avail() + 1).min(self.match_len_max);
                // The byte we just ran through the match finder and the
                // beginning of the match.
                let p1 = self.read_pos as usize - 1;
                let p2 = p1 - matches[count - 1].dist as usize - 1;
                len_best = memcmplen(&self.buffer, p1, p2, len_best, limit);
            }
        }

        // Finally update the read position to indicate that match finder was
        // run for this dictionary offset.
        self.read_ahead += 1;
        (len_best, count as u32)
    }

    /// Runs the match finder's skip function without touching read_ahead.
    pub(crate) fn skip_raw(&mut self, amount: u32) {
        match self.kind {
            MfType::Hc3 => self.hc3_skip(amount),
            MfType::Hc4 => self.hc4_skip(amount),
            MfType::Bt4 => self.bt4_skip(amount),
        }
    }

    /// Normalizes hash values: drops those that indicate distance greater
    /// than the dictionary size, making space for new values.
    #[cold]
    fn normalize(&mut self) {
        debug_assert_eq!(self.read_pos.wrapping_add(self.offset), MUST_NORMALIZE_POS);
        let subvalue = MUST_NORMALIZE_POS - self.cyclic_size;
        for table in [
            &mut self.hash2,
            &mut self.hash3,
            &mut self.hash,
            &mut self.son,
        ] {
            for v in table.iter_mut() {
                *v = if *v <= subvalue {
                    EMPTY_HASH_VALUE
                } else {
                    *v - subvalue
                };
            }
        }
        self.offset -= subvalue;
        self.run = Run::default();
    }

    /// Marks the current byte as processed from point of view of the match
    /// finder.
    #[inline(always)]
    fn move_pos(&mut self) {
        self.cyclic_pos += 1;
        if self.cyclic_pos == self.cyclic_size {
            self.cyclic_pos = 0;
        }
        self.read_pos += 1;
        debug_assert!(self.read_pos <= self.write_pos);
        if self.read_pos.wrapping_add(self.offset) == MUST_NORMALIZE_POS {
            self.normalize();
        }
    }

    /// When flushing, we cannot run the match finder unless there is nice_len
    /// bytes available in the dictionary. Instead, we skip running the match
    /// finder (indicating that no match was found), and count how many bytes
    /// we have ignored this way.
    ///
    /// When new data is given after the flushing was completed, the match
    /// finder is restarted by rewinding read_pos backwards by pending. Then
    /// the missed bytes are added to the hash using the match finder's skip
    /// function. Due to this rewinding, we don't touch cyclic_pos or test for
    /// normalization.
    #[inline(always)]
    fn move_pending(&mut self) {
        self.read_pos += 1;
        debug_assert!(self.read_pos <= self.write_pos);
        self.pending += 1;
    }

    /// Calculates len_limit and determines if there is enough input to run
    /// the actual match finder code (`header()`). Returns `None` after
    /// moving past the byte otherwise.
    #[inline(always)]
    fn header(&mut self, is_bt: bool, len_min: u32) -> Option<u32> {
        let avail = self.avail();
        if self.nice_len <= avail {
            Some(self.nice_len)
        } else if avail < len_min || (is_bt && self.action == Action::SyncFlush) {
            debug_assert!(self.action != Action::Run);
            self.move_pending();
            None
        } else {
            Some(avail)
        }
    }

    fn hc3_find(&mut self, matches: &mut [Match]) -> usize {
        let Some(len_limit) = self.header(false, 3) else {
            return 0;
        };
        let pos = self.read_pos.wrapping_add(self.offset);
        let cur = self.read_pos as usize;
        let (h2, _, temp3) = hash_23(&self.buffer[cur..cur + 3]);
        let hv = (temp3 & self.hash_mask) as usize;

        let delta2 = pos.wrapping_sub(self.hash2[h2]);
        let cur_match = self.hash[hv];
        self.hash2[h2] = pos;
        self.hash[hv] = pos;

        let mut len_best = 2;
        let mut count = 0;
        if delta2 < self.cyclic_size && self.buffer[cur - delta2 as usize] == self.buffer[cur] {
            len_best = memcmplen(
                &self.buffer,
                cur - delta2 as usize,
                cur,
                len_best,
                len_limit,
            );
            matches[0] = Match {
                len: len_best,
                dist: delta2 - 1,
            };
            count = 1;
            if len_best == len_limit {
                self.son[self.cyclic_pos as usize] = cur_match;
                self.move_pos();
                return 1;
            }
        }

        let s = search!(self, len_limit);
        let count = hc_find_func(&s, &mut self.son, cur_match, matches, count, len_best);
        self.move_pos();
        count
    }

    fn hc3_skip(&mut self, mut amount: u32) {
        loop {
            if self.avail() < 3 {
                self.move_pending();
            } else {
                let pos = self.read_pos.wrapping_add(self.offset);
                let cur = self.read_pos as usize;
                let (h2, _, temp3) = hash_23(&self.buffer[cur..cur + 3]);
                let hv = (temp3 & self.hash_mask) as usize;
                let cur_match = self.hash[hv];
                self.hash2[h2] = pos;
                self.hash[hv] = pos;
                self.son[self.cyclic_pos as usize] = cur_match;
                self.move_pos();
            }
            amount -= 1;
            if amount == 0 {
                return;
            }
        }
    }

    /// The hash lookups shared by HC4 and BT4: returns the matches found
    /// from the two- and three-byte hashes, the length of the longest one
    /// and the head of the four-byte hash chain or tree.
    #[inline(always)]
    fn hash4_find(&mut self, len_limit: u32, matches: &mut [Match]) -> (usize, u32, u32) {
        let pos = self.read_pos.wrapping_add(self.offset);
        let cur = self.read_pos as usize;
        let (hash2, hash3, cur_match) = self.hash4_update(pos, cur);
        let mut delta2 = pos.wrapping_sub(hash2);
        let delta3 = pos.wrapping_sub(hash3);

        let mut len_best = 1;
        let mut count = 0;
        if delta2 < self.cyclic_size && self.buffer[cur - delta2 as usize] == self.buffer[cur] {
            len_best = 2;
            matches[0] = Match {
                len: 2,
                dist: delta2 - 1,
            };
            count = 1;
        }
        if delta2 != delta3
            && delta3 < self.cyclic_size
            && self.buffer[cur - delta3 as usize] == self.buffer[cur]
        {
            len_best = 3;
            matches[count].dist = delta3 - 1;
            count += 1;
            delta2 = delta3;
        }
        if count != 0 {
            len_best = memcmplen(
                &self.buffer,
                cur,
                cur - delta2 as usize,
                len_best,
                len_limit,
            );
            matches[count - 1].len = len_best;
        }
        (count, len_best, cur_match)
    }

    #[inline(always)]
    fn hash4_skip(&mut self) -> u32 {
        let pos = self.read_pos.wrapping_add(self.offset);
        self.hash4_update(pos, self.read_pos as usize).2
    }

    /// Stores the current position in the hash tables, returning their
    /// previous values (`hash_4_calc()` and the table updates).
    ///
    /// Searching the chain or tree doesn't change the hash tables, so the
    /// next position's chain head is loaded right after the update, and its
    /// cache miss overlaps the search. With five bytes available, its hash
    /// input is final: refills, window moves and rewinds after a sync flush
    /// keep it. Normalization rewrites the tables, so no hint is kept
    /// across it.
    #[inline(always)]
    fn hash4_update(&mut self, pos: u32, cur: usize) -> (u32, u32, u32) {
        let (h2, h3, hv, head) = match self.hash4_hint.take() {
            Some((hint_pos, h2, h3, hv, head)) if hint_pos == pos => {
                debug_assert_eq!(head, self.hash[hv]);
                (h2, h3, hv, head)
            }
            _ => {
                let (h2, h3, hv) = hash_4(&self.buffer[cur..cur + 4], self.hash_mask);
                (h2, h3, hv, self.hash[hv])
            }
        };
        let old = (self.hash2[h2], self.hash3[h3], head);
        self.hash2[h2] = pos;
        self.hash3[h3] = pos;
        self.hash[hv] = pos;

        if self.avail() >= 5 && pos + 1 != MUST_NORMALIZE_POS {
            let (h2, h3, hv) = hash_4(&self.buffer[cur + 1..cur + 5], self.hash_mask);
            self.hash4_hint = Some((pos + 1, h2, h3, hv, self.hash[hv]));
        }
        old
    }

    fn hc4_find(&mut self, matches: &mut [Match]) -> usize {
        let Some(len_limit) = self.header(false, 4) else {
            return 0;
        };
        let (count, mut len_best, cur_match) = self.hash4_find(len_limit, matches);
        if count != 0 && len_best == len_limit {
            self.son[self.cyclic_pos as usize] = cur_match;
            self.move_pos();
            return count;
        }
        if len_best < 3 {
            len_best = 3;
        }
        let s = search!(self, len_limit);
        let count = hc_find_func(&s, &mut self.son, cur_match, matches, count, len_best);
        self.move_pos();
        count
    }

    fn hc4_skip(&mut self, mut amount: u32) {
        loop {
            if self.avail() < 4 {
                self.move_pending();
            } else {
                let cur_match = self.hash4_skip();
                self.son[self.cyclic_pos as usize] = cur_match;
                self.move_pos();
            }
            amount -= 1;
            if amount == 0 {
                return;
            }
        }
    }

    fn bt4_find(&mut self, matches: &mut [Match]) -> usize {
        let Some(len_limit) = self.header(true, 4) else {
            return 0;
        };
        let (count, mut len_best, cur_match) = self.hash4_find(len_limit, matches);
        if count != 0 && len_best == len_limit {
            let s = search!(self, len_limit);
            bt_skip_func(&s, &mut self.son, cur_match, &mut self.run, len_limit);
            self.move_pos();
            return count;
        }
        if len_best < 3 {
            len_best = 3;
        }
        let s = search!(self, len_limit);
        let count = bt_find_func(&s, &mut self.son, cur_match, matches, count, len_best);
        self.move_pos();
        count
    }

    fn bt4_skip(&mut self, mut amount: u32) {
        loop {
            if let Some(len_limit) = self.header(true, 4) {
                // Proving the repeat for the remaining positions of this
                // skip is enough.
                let run_limit = (len_limit + amount - 1).min(self.avail());
                let cur_match = self.hash4_skip();
                let s = search!(self, len_limit);
                bt_skip_func(&s, &mut self.son, cur_match, &mut self.run, run_limit);
                self.move_pos();
            }
            amount -= 1;
            if amount == 0 {
                return;
            }
        }
    }
}
