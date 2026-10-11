//! Normal-mode optimum parser, ported from liblzma 5.8.4
//! (`lzma/lzma_encoder_optimum_normal.c`; Igor Pavlov; 0BSD).

use super::{
    encoder::{
        DIST_SLOT_BITS, LengthEncoder, LzmaEncoder, MATCH_LEN_MAX, MATCH_LEN_MIN, OPTS, Optimal,
        get_dist_slot, get_dist_state,
    },
    range_enc::{
        INFINITY_PRICE, bit_0_price, bit_1_price, bit_price, bittree_price, bittree_reverse_price,
        direct_price,
    },
};
use crate::{
    ALIGN_BITS, ALIGN_MASK, ALIGN_SIZE, DIST_MODEL_END, DIST_MODEL_START, DIST_STATES,
    FULL_DISTANCES, REPS,
    lz::{Mf, memcmplen},
    state::State,
};

/// Tests if the first two bytes at `a` and `b` differ.
#[inline(always)]
fn not_equal_16(buf: &[u8], a: usize, b: usize) -> bool {
    buf[a..a + 2] != buf[b..b + 2]
}

#[inline(always)]
fn get_len_price(lencoder: &LengthEncoder, len: u32, pos_state: usize) -> u32 {
    // NOTE: Unlike the other price tables, length prices are updated
    // in encoder.rs
    lencoder.prices[pos_state][(len - MATCH_LEN_MIN) as usize]
}

#[inline(always)]
fn make_literal(optimal: &mut Optimal) {
    optimal.back_prev = u32::MAX;
    optimal.prev_1_is_literal = false;
}

#[inline(always)]
fn make_short_rep(optimal: &mut Optimal) {
    optimal.back_prev = 0;
    optimal.prev_1_is_literal = false;
}

impl LzmaEncoder {
    fn get_literal_price(
        &self,
        pos: u32,
        prev_byte: u8,
        match_mode: bool,
        match_byte: u8,
        symbol: u8,
    ) -> u32 {
        let base = self.literal_subcoder(pos, prev_byte);
        let subcoder = &self.literal[base..base + 0x300];

        if !match_mode {
            return bittree_price(subcoder, 8, u32::from(symbol));
        }
        let mut price = 0;
        let mut offset = 0x100;
        let mut match_byte = u32::from(match_byte);
        let mut symbol = u32::from(symbol) + (1 << 8);
        loop {
            match_byte <<= 1;
            let match_bit = match_byte & offset;
            let subcoder_index = offset + match_bit + (symbol >> 8);
            let bit = (symbol >> 7) & 1;
            price += bit_price(subcoder[subcoder_index as usize], bit);
            symbol <<= 1;
            offset &= !(match_byte ^ symbol);
            if symbol >= 1 << 16 {
                return price;
            }
        }
    }

    #[inline(always)]
    fn get_short_rep_price(&self, state: State, pos_state: usize) -> u32 {
        let state = state.get() as usize;
        bit_0_price(self.is_rep0[state]) + bit_0_price(self.is_rep0_long[state][pos_state])
    }

    #[inline(always)]
    fn get_pure_rep_price(&self, rep_index: usize, state: State, pos_state: usize) -> u32 {
        let state = state.get() as usize;
        if rep_index == 0 {
            bit_0_price(self.is_rep0[state]) + bit_1_price(self.is_rep0_long[state][pos_state])
        } else {
            let mut price = bit_1_price(self.is_rep0[state]);
            if rep_index == 1 {
                price += bit_0_price(self.is_rep1[state]);
            } else {
                price += bit_1_price(self.is_rep1[state]);
                price += bit_price(self.is_rep2[state], rep_index as u32 - 2);
            }
            price
        }
    }

    #[inline(always)]
    fn get_rep_price(&self, rep_index: usize, len: u32, state: State, pos_state: usize) -> u32 {
        get_len_price(&self.rep_len_encoder, len, pos_state)
            + self.get_pure_rep_price(rep_index, state, pos_state)
    }

    #[inline(always)]
    fn get_dist_len_price(&self, dist: u32, len: u32, pos_state: usize) -> u32 {
        let dist_state = get_dist_state(len);
        let price = if dist < FULL_DISTANCES as u32 {
            self.dist_prices[dist_state][dist as usize]
        } else {
            let dist_slot = get_dist_slot(dist);
            self.dist_slot_prices[dist_state][dist_slot as usize]
                + self.align_prices[(dist & ALIGN_MASK as u32) as usize]
        };
        price + get_len_price(&self.match_len_encoder, len, pos_state)
    }

    fn fill_dist_prices(&mut self) {
        for dist_state in 0..DIST_STATES {
            let dist_slot_prices = &mut self.dist_slot_prices[dist_state];

            // Price to encode the dist_slot.
            for dist_slot in 0..self.dist_table_size {
                dist_slot_prices[dist_slot as usize] =
                    bittree_price(&self.dist_slot[dist_state], DIST_SLOT_BITS, dist_slot);
            }

            // For matches with distance >= FULL_DISTANCES, add the price
            // of the direct bits part of the match distance. (Align bits
            // are handled by fill_align_prices()).
            for dist_slot in DIST_MODEL_END as u32..self.dist_table_size {
                dist_slot_prices[dist_slot as usize] +=
                    direct_price(((dist_slot >> 1) - 1) - ALIGN_BITS as u32);
            }

            // Distances in the range [0, 3] are fully encoded with
            // dist_slot, so they are used for dist_prices as is.
            self.dist_prices[dist_state][..DIST_MODEL_START]
                .copy_from_slice(&dist_slot_prices[..DIST_MODEL_START]);
        }

        // Distances in the range [4, 127] depend on dist_slot and
        // dist_special. We do this in a loop separate from the above
        // loop to avoid redundant calls to get_dist_slot().
        for i in DIST_MODEL_START as u32..FULL_DISTANCES as u32 {
            let dist_slot = get_dist_slot(i);
            let footer_bits = (dist_slot >> 1) - 1;
            let base = (2 | (dist_slot & 1)) << footer_bits;
            let price = bittree_reverse_price(
                &self.dist_special,
                (base - dist_slot) as usize,
                footer_bits,
                i - base,
            );
            for dist_state in 0..DIST_STATES {
                self.dist_prices[dist_state][i as usize] =
                    price + self.dist_slot_prices[dist_state][dist_slot as usize];
            }
        }

        self.match_price_count = 0;
    }

    fn fill_align_prices(&mut self) {
        for i in 0..ALIGN_SIZE as u32 {
            self.align_prices[i as usize] =
                bittree_reverse_price(&self.dist_align, 1, ALIGN_BITS as u32, i);
        }
        self.align_price_count = 0;
    }

    /// Converts the optimum path ending at `cur` into a list of pending
    /// symbols and returns the first one as (back, len).
    fn backward(&mut self, mut cur: u32) -> (u32, u32) {
        let opts = &mut self.opts;
        self.opts_end_index = cur;

        let mut pos_mem = opts[cur as usize].pos_prev;
        let mut back_mem = opts[cur as usize].back_prev;

        loop {
            if opts[cur as usize].prev_1_is_literal {
                make_literal(&mut opts[pos_mem as usize]);
                opts[pos_mem as usize].pos_prev = pos_mem - 1;

                if opts[cur as usize].prev_2 {
                    let (pos_prev_2, back_prev_2) = (
                        opts[cur as usize].pos_prev_2,
                        opts[cur as usize].back_prev_2,
                    );
                    let prev = &mut opts[pos_mem as usize - 1];
                    prev.prev_1_is_literal = false;
                    prev.pos_prev = pos_prev_2;
                    prev.back_prev = back_prev_2;
                }
            }

            let pos_prev = pos_mem;
            let back_cur = back_mem;

            back_mem = opts[pos_prev as usize].back_prev;
            pos_mem = opts[pos_prev as usize].pos_prev;

            opts[pos_prev as usize].back_prev = back_cur;
            opts[pos_prev as usize].pos_prev = cur;
            cur = pos_prev;
            if cur == 0 {
                break;
            }
        }

        self.opts_current_index = opts[0].pos_prev;
        (opts[0].back_prev, opts[0].pos_prev)
    }

    /// Returns the end of the price list, or u32::MAX with the symbol to
    /// encode when it is decided without the optimum loop.
    #[inline(always)]
    fn helper1(&mut self, mf: &mut Mf, position: u32) -> (u32, u32, u32) {
        const DONE: u32 = u32::MAX;
        let nice_len = mf.nice_len;

        let (len_main, matches_count) = if mf.read_ahead == 0 {
            mf.find(&mut self.matches)
        } else {
            debug_assert_eq!(mf.read_ahead, 1);
            (self.longest_match_length, self.matches_count)
        };

        let buf_avail = (mf.avail() + 1).min(MATCH_LEN_MAX);
        if buf_avail < 2 {
            return (u32::MAX, 1, DONE);
        }

        let buffer = &mf.buffer;
        let buf = mf.read_pos as usize - 1;
        let mut rep_lens = [0; REPS];
        let mut rep_max_index = 0;

        for i in 0..REPS {
            let buf_back = buf - self.reps[i] as usize - 1;
            if not_equal_16(buffer, buf, buf_back) {
                rep_lens[i] = 0;
                continue;
            }
            rep_lens[i] = memcmplen(buffer, buf, buf_back, 2, buf_avail);
            if rep_lens[i] > rep_lens[rep_max_index] {
                rep_max_index = i;
            }
        }

        if rep_lens[rep_max_index] >= nice_len {
            let len = rep_lens[rep_max_index];
            mf.skip(len - 1);
            return (rep_max_index as u32, len, DONE);
        }

        if len_main >= nice_len {
            let back = self.matches[matches_count as usize - 1].dist + REPS as u32;
            mf.skip(len_main - 1);
            return (back, len_main, DONE);
        }

        let current_byte = buffer[buf];
        let match_byte = buffer[buf - self.reps[0] as usize - 1];

        if len_main < 2 && current_byte != match_byte && rep_lens[rep_max_index] < 2 {
            return (u32::MAX, 1, DONE);
        }

        let state = self.state;
        self.opts[0].state = state;
        let pos_state = (position & self.pos_mask) as usize;
        let is_match = self.is_match[state.get() as usize][pos_state];

        self.opts[1].price = bit_0_price(is_match)
            + self.get_literal_price(
                position,
                buffer[buf - 1],
                !state.is_literal(),
                match_byte,
                current_byte,
            );
        make_literal(&mut self.opts[1]);

        let match_price = bit_1_price(is_match);
        let rep_match_price = match_price + bit_1_price(self.is_rep[state.get() as usize]);

        if match_byte == current_byte {
            let short_rep_price = rep_match_price + self.get_short_rep_price(state, pos_state);
            if short_rep_price < self.opts[1].price {
                self.opts[1].price = short_rep_price;
                make_short_rep(&mut self.opts[1]);
            }
        }

        let len_end = len_main.max(rep_lens[rep_max_index]);
        if len_end < 2 {
            return (self.opts[1].back_prev, 1, DONE);
        }

        self.opts[1].pos_prev = 0;
        self.opts[0].backs = self.reps;

        for opt in &mut self.opts[2..=len_end as usize] {
            opt.price = INFINITY_PRICE;
        }

        for (i, &rep_len) in rep_lens.iter().enumerate() {
            if rep_len < 2 {
                continue;
            }
            let price = rep_match_price + self.get_pure_rep_price(i, state, pos_state);
            for len in (2..=rep_len).rev() {
                let cur_and_len_price =
                    price + get_len_price(&self.rep_len_encoder, len, pos_state);
                let opt = &mut self.opts[len as usize];
                if cur_and_len_price < opt.price {
                    opt.price = cur_and_len_price;
                    opt.pos_prev = 0;
                    opt.back_prev = i as u32;
                    opt.prev_1_is_literal = false;
                }
            }
        }

        let normal_match_price = match_price + bit_0_price(self.is_rep[state.get() as usize]);

        let mut len = if rep_lens[0] >= 2 { rep_lens[0] + 1 } else { 2 };
        if len <= len_main {
            let mut i = 0;
            while len > self.matches[i].len {
                i += 1;
            }
            loop {
                let dist = self.matches[i].dist;
                let cur_and_len_price =
                    normal_match_price + self.get_dist_len_price(dist, len, pos_state);
                let opt = &mut self.opts[len as usize];
                if cur_and_len_price < opt.price {
                    opt.price = cur_and_len_price;
                    opt.pos_prev = 0;
                    opt.back_prev = dist + REPS as u32;
                    opt.prev_1_is_literal = false;
                }
                if len == self.matches[i].len {
                    i += 1;
                    if i == matches_count as usize {
                        break;
                    }
                }
                len += 1;
            }
        }

        (0, 0, len_end)
    }

    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn helper2(
        &mut self,
        reps: &mut [u32; REPS],
        buffer: &[u8],
        buf: usize,
        mut len_end: u32,
        position: u32,
        cur: u32,
        nice_len: u32,
        buf_avail_full: u32,
    ) -> u32 {
        let mut matches_count = self.matches_count as usize;
        let mut new_len = self.longest_match_length;
        let cur_opt = self.opts[cur as usize];
        let mut pos_prev = cur_opt.pos_prev;
        let mut state;

        if cur_opt.prev_1_is_literal {
            pos_prev -= 1;
            if cur_opt.prev_2 {
                state = self.opts[cur_opt.pos_prev_2 as usize].state;
                if cur_opt.back_prev_2 < REPS as u32 {
                    state.update_long_rep();
                } else {
                    state.update_match();
                }
            } else {
                state = self.opts[pos_prev as usize].state;
            }
            state.update_literal();
        } else {
            state = self.opts[pos_prev as usize].state;
        }

        if pos_prev == cur - 1 {
            if cur_opt.back_prev == 0 {
                state.update_short_rep();
            } else {
                state.update_literal();
            }
        } else {
            let pos;
            if cur_opt.prev_1_is_literal && cur_opt.prev_2 {
                pos_prev = cur_opt.pos_prev_2;
                pos = cur_opt.back_prev_2;
                state.update_long_rep();
            } else {
                pos = cur_opt.back_prev;
                if pos < REPS as u32 {
                    state.update_long_rep();
                } else {
                    state.update_match();
                }
            }

            let backs = self.opts[pos_prev as usize].backs;
            if pos < REPS as u32 {
                let pos = pos as usize;
                reps[0] = backs[pos];
                reps[1..=pos].copy_from_slice(&backs[..pos]);
                reps[pos + 1..].copy_from_slice(&backs[pos + 1..]);
            } else {
                reps[0] = pos - REPS as u32;
                reps[1..].copy_from_slice(&backs[..REPS - 1]);
            }
        }

        self.opts[cur as usize].state = state;
        self.opts[cur as usize].backs = *reps;

        let cur_price = cur_opt.price;
        let current_byte = buffer[buf];
        let match_byte = buffer[buf - reps[0] as usize - 1];
        let pos_state = (position & self.pos_mask) as usize;
        let state_index = state.get() as usize;

        let cur_and_1_price = cur_price
            + bit_0_price(self.is_match[state_index][pos_state])
            + self.get_literal_price(
                position,
                buffer[buf - 1],
                !state.is_literal(),
                match_byte,
                current_byte,
            );

        let mut next_is_literal = false;
        let next = cur as usize + 1;

        if cur_and_1_price < self.opts[next].price {
            self.opts[next].price = cur_and_1_price;
            self.opts[next].pos_prev = cur;
            make_literal(&mut self.opts[next]);
            next_is_literal = true;
        }

        let match_price = cur_price + bit_1_price(self.is_match[state_index][pos_state]);
        let rep_match_price = match_price + bit_1_price(self.is_rep[state_index]);

        if match_byte == current_byte
            && !(self.opts[next].pos_prev < cur && self.opts[next].back_prev == 0)
        {
            let short_rep_price = rep_match_price + self.get_short_rep_price(state, pos_state);
            if short_rep_price <= self.opts[next].price {
                self.opts[next].price = short_rep_price;
                self.opts[next].pos_prev = cur;
                make_short_rep(&mut self.opts[next]);
                next_is_literal = true;
            }
        }

        if buf_avail_full < 2 {
            return len_end;
        }

        let buf_avail = buf_avail_full.min(nice_len);

        if !next_is_literal && match_byte != current_byte {
            // speed optimization
            // try literal + rep0
            let buf_back = buf - reps[0] as usize - 1;
            let limit = buf_avail_full.min(nice_len + 1);
            let len_test = memcmplen(buffer, buf, buf_back, 1, limit) - 1;

            if len_test >= 2 {
                let mut state_2 = state;
                state_2.update_literal();
                let state_2_index = state_2.get() as usize;
                let pos_state_next = ((position + 1) & self.pos_mask) as usize;
                let next_rep_match_price = cur_and_1_price
                    + bit_1_price(self.is_match[state_2_index][pos_state_next])
                    + bit_1_price(self.is_rep[state_2_index]);

                let offset = cur + 1 + len_test;
                while len_end < offset {
                    len_end += 1;
                    self.opts[len_end as usize].price = INFINITY_PRICE;
                }

                let cur_and_len_price =
                    next_rep_match_price + self.get_rep_price(0, len_test, state_2, pos_state_next);

                let opt = &mut self.opts[offset as usize];
                if cur_and_len_price < opt.price {
                    opt.price = cur_and_len_price;
                    opt.pos_prev = cur + 1;
                    opt.back_prev = 0;
                    opt.prev_1_is_literal = true;
                    opt.prev_2 = false;
                }
            }
        }

        let mut start_len = 2; // speed optimization

        for (rep_index, &rep) in reps.iter().enumerate() {
            let buf_back = buf - rep as usize - 1;
            if not_equal_16(buffer, buf, buf_back) {
                continue;
            }

            let len_test = memcmplen(buffer, buf, buf_back, 2, buf_avail);
            while len_end < cur + len_test {
                len_end += 1;
                self.opts[len_end as usize].price = INFINITY_PRICE;
            }

            let price = rep_match_price + self.get_pure_rep_price(rep_index, state, pos_state);

            for len in (2..=len_test).rev() {
                let cur_and_len_price =
                    price + get_len_price(&self.rep_len_encoder, len, pos_state);
                let opt = &mut self.opts[(cur + len) as usize];
                if cur_and_len_price < opt.price {
                    opt.price = cur_and_len_price;
                    opt.pos_prev = cur;
                    opt.back_prev = rep_index as u32;
                    opt.prev_1_is_literal = false;
                }
            }

            if rep_index == 0 {
                start_len = len_test + 1;
            }

            let mut len_test_2 = len_test + 1;
            let limit = buf_avail_full.min(len_test_2 + nice_len);
            // NOTE: len_test_2 may be greater than limit so the call to
            // memcmplen() must be done conditionally.
            if len_test_2 < limit {
                len_test_2 = memcmplen(buffer, buf, buf_back, len_test_2, limit);
            }
            len_test_2 -= len_test + 1;

            if len_test_2 >= 2 {
                let mut state_2 = state;
                state_2.update_long_rep();
                let mut pos_state_next = ((position + len_test) & self.pos_mask) as usize;

                let cur_and_len_literal_price = price
                    + get_len_price(&self.rep_len_encoder, len_test, pos_state)
                    + bit_0_price(self.is_match[state_2.get() as usize][pos_state_next])
                    + self.get_literal_price(
                        position + len_test,
                        buffer[buf + len_test as usize - 1],
                        true,
                        buffer[buf_back + len_test as usize],
                        buffer[buf + len_test as usize],
                    );

                state_2.update_literal();
                pos_state_next = ((position + len_test + 1) & self.pos_mask) as usize;

                let next_rep_match_price = cur_and_len_literal_price
                    + bit_1_price(self.is_match[state_2.get() as usize][pos_state_next])
                    + bit_1_price(self.is_rep[state_2.get() as usize]);

                let offset = cur + len_test + 1 + len_test_2;
                while len_end < offset {
                    len_end += 1;
                    self.opts[len_end as usize].price = INFINITY_PRICE;
                }

                let cur_and_len_price = next_rep_match_price
                    + self.get_rep_price(0, len_test_2, state_2, pos_state_next);

                let opt = &mut self.opts[offset as usize];
                if cur_and_len_price < opt.price {
                    opt.price = cur_and_len_price;
                    opt.pos_prev = cur + len_test + 1;
                    opt.back_prev = 0;
                    opt.prev_1_is_literal = true;
                    opt.prev_2 = true;
                    opt.pos_prev_2 = cur;
                    opt.back_prev_2 = rep_index as u32;
                }
            }
        }

        if new_len > buf_avail {
            new_len = buf_avail;
            matches_count = 0;
            while new_len > self.matches[matches_count].len {
                matches_count += 1;
            }
            self.matches[matches_count].len = new_len;
            matches_count += 1;
        }

        if new_len >= start_len {
            let normal_match_price = match_price + bit_0_price(self.is_rep[state_index]);

            while len_end < cur + new_len {
                len_end += 1;
                self.opts[len_end as usize].price = INFINITY_PRICE;
            }

            let mut i = 0;
            while start_len > self.matches[i].len {
                i += 1;
            }

            let mut len_test = start_len;
            loop {
                let cur_back = self.matches[i].dist;
                let mut cur_and_len_price =
                    normal_match_price + self.get_dist_len_price(cur_back, len_test, pos_state);

                let opt = &mut self.opts[(cur + len_test) as usize];
                if cur_and_len_price < opt.price {
                    opt.price = cur_and_len_price;
                    opt.pos_prev = cur;
                    opt.back_prev = cur_back + REPS as u32;
                    opt.prev_1_is_literal = false;
                }

                if len_test == self.matches[i].len {
                    // Try Match + Literal + Rep0
                    let buf_back = buf - cur_back as usize - 1;
                    let mut len_test_2 = len_test + 1;
                    let limit = buf_avail_full.min(len_test_2 + nice_len);

                    // NOTE: len_test_2 may be greater than limit
                    // so the call to memcmplen() must be
                    // done conditionally.
                    if len_test_2 < limit {
                        len_test_2 = memcmplen(buffer, buf, buf_back, len_test_2, limit);
                    }
                    len_test_2 -= len_test + 1;

                    if len_test_2 >= 2 {
                        let mut state_2 = state;
                        state_2.update_match();
                        let mut pos_state_next = ((position + len_test) & self.pos_mask) as usize;

                        let cur_and_len_literal_price = cur_and_len_price
                            + bit_0_price(self.is_match[state_2.get() as usize][pos_state_next])
                            + self.get_literal_price(
                                position + len_test,
                                buffer[buf + len_test as usize - 1],
                                true,
                                buffer[buf_back + len_test as usize],
                                buffer[buf + len_test as usize],
                            );

                        state_2.update_literal();
                        pos_state_next = (pos_state_next + 1) & self.pos_mask as usize;

                        let next_rep_match_price = cur_and_len_literal_price
                            + bit_1_price(self.is_match[state_2.get() as usize][pos_state_next])
                            + bit_1_price(self.is_rep[state_2.get() as usize]);

                        let offset = cur + len_test + 1 + len_test_2;
                        while len_end < offset {
                            len_end += 1;
                            self.opts[len_end as usize].price = INFINITY_PRICE;
                        }

                        cur_and_len_price = next_rep_match_price
                            + self.get_rep_price(0, len_test_2, state_2, pos_state_next);

                        let opt = &mut self.opts[offset as usize];
                        if cur_and_len_price < opt.price {
                            opt.price = cur_and_len_price;
                            opt.pos_prev = cur + len_test + 1;
                            opt.back_prev = 0;
                            opt.prev_1_is_literal = true;
                            opt.prev_2 = true;
                            opt.pos_prev_2 = cur;
                            opt.back_prev_2 = cur_back + REPS as u32;
                        }
                    }

                    i += 1;
                    if i == matches_count {
                        break;
                    }
                }
                len_test += 1;
            }
        }

        len_end
    }

    /// Returns the next symbol as (back, len) (`lzma_lzma_optimum_normal()`).
    pub(crate) fn optimum_normal(&mut self, mf: &mut Mf, position: u32) -> (u32, u32) {
        // If we have symbols pending, return the next pending symbol.
        if self.opts_end_index != self.opts_current_index {
            debug_assert!(mf.read_ahead > 0);
            let opt = &self.opts[self.opts_current_index as usize];
            let len = opt.pos_prev - self.opts_current_index;
            let back = opt.back_prev;
            self.opts_current_index = opt.pos_prev;
            return (back, len);
        }

        // Update the price tables. In LZMA SDK <= 4.60 (and possibly later)
        // this was done in both initialization function and in the main loop.
        // In liblzma they were moved into this single place.
        if mf.read_ahead == 0 {
            if self.match_price_count >= 1 << 7 {
                self.fill_dist_prices();
            }
            if self.align_price_count >= ALIGN_SIZE as u32 {
                self.fill_align_prices();
            }
        }

        let (back, len, mut len_end) = self.helper1(mf, position);
        if len_end == u32::MAX {
            return (back, len);
        }

        let mut reps = self.reps;
        let mut cur = 1;
        while cur < len_end {
            debug_assert!((cur as usize) < OPTS);
            let (longest, count) = mf.find(&mut self.matches);
            self.longest_match_length = longest;
            self.matches_count = count;
            if longest >= mf.nice_len {
                break;
            }
            let buf_avail_full = (mf.avail() + 1).min(OPTS as u32 - 1 - cur);
            len_end = self.helper2(
                &mut reps,
                &mf.buffer,
                mf.read_pos as usize - 1,
                len_end,
                position + cur,
                cur,
                mf.nice_len,
                buf_avail_full,
            );
            cur += 1;
        }

        self.backward(cur)
    }
}
