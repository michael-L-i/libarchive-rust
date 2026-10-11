//! LZMA encoder, ported from liblzma 5.8.4 (`lzma/lzma_encoder.c`,
//! `lzma/lzma_encoder_private.h`, `lzma/lzma_common.h`; Igor Pavlov,
//! Lasse Collin; 0BSD).

use alloc::{vec, vec::Vec};

use super::{LzmaOptions, range_enc::RangeEncoder};
use crate::{
    ALIGN_BITS, ALIGN_MASK, ALIGN_SIZE, DIST_MODEL_END, DIST_MODEL_START, DIST_SLOTS, DIST_STATES,
    FULL_DISTANCES, POS_STATES_MAX, PROB_INIT, REPS,
    lz::{Action, LzOptions, Match, Mf, MfType, is_enc_dict_size_valid},
    state::{STATES, State},
};

/// The mode to use when encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeMode {
    /// Fast mode (lower quality but faster).
    Fast,
    /// Normal mode (higher quality but slower).
    Normal,
}

/// Number of entries in the optimum array.
pub(crate) const OPTS: usize = 1 << 12;

/// Number of bytes that a single encoding loop in `encode()` can consume
/// from the dictionary. This limit comes from the optimum functions.
pub(crate) const LOOP_INPUT_MAX: u32 = OPTS as u32 + 1;

/// Maximum number of bytes of actual data per LZMA2 chunk (no headers).
pub(crate) const LZMA2_CHUNK_MAX: u32 = 1 << 16;

pub(crate) const MATCH_LEN_MIN: u32 = 2;
pub(crate) const LEN_LOW_BITS: u32 = 3;
pub(crate) const LEN_LOW_SYMBOLS: u32 = 1 << LEN_LOW_BITS;
pub(crate) const LEN_MID_BITS: u32 = 3;
pub(crate) const LEN_MID_SYMBOLS: u32 = 1 << LEN_MID_BITS;
pub(crate) const LEN_HIGH_BITS: u32 = 8;
pub(crate) const LEN_HIGH_SYMBOLS: u32 = 1 << LEN_HIGH_BITS;
pub(crate) const LEN_SYMBOLS: usize =
    (LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS + LEN_HIGH_SYMBOLS) as usize;
pub(crate) const MATCH_LEN_MAX: u32 = MATCH_LEN_MIN + LEN_SYMBOLS as u32 - 1;
pub(crate) const DIST_SLOT_BITS: u32 = 6;
const LITERAL_CODER_SIZE: usize = 0x300;

/// Index of the probability array for match distances of length `len`.
#[inline(always)]
pub(crate) fn get_dist_state(len: u32) -> usize {
    if len < DIST_STATES as u32 + MATCH_LEN_MIN {
        (len - MATCH_LEN_MIN) as usize
    } else {
        DIST_STATES - 1
    }
}

/// The highest two bits of a match distance (distance slot), as in
/// `fastpos.h`.
#[inline(always)]
pub(crate) fn get_dist_slot(dist: u32) -> u32 {
    if dist <= 4 {
        dist
    } else {
        let i = 31 - dist.leading_zeros();
        (i + i) + ((dist >> (i - 1)) & 1)
    }
}

pub(crate) struct LengthEncoder {
    pub(crate) choice: u16,
    pub(crate) choice2: u16,
    pub(crate) low: [[u16; LEN_LOW_SYMBOLS as usize]; POS_STATES_MAX],
    pub(crate) mid: [[u16; LEN_MID_SYMBOLS as usize]; POS_STATES_MAX],
    pub(crate) high: [u16; LEN_HIGH_SYMBOLS as usize],
    pub(crate) prices: [[u32; LEN_SYMBOLS]; POS_STATES_MAX],
    pub(crate) table_size: u32,
    counters: [u32; POS_STATES_MAX],
}

impl LengthEncoder {
    fn new(table_size: u32) -> Self {
        Self {
            choice: PROB_INIT,
            choice2: PROB_INIT,
            low: [[PROB_INIT; LEN_LOW_SYMBOLS as usize]; POS_STATES_MAX],
            mid: [[PROB_INIT; LEN_MID_SYMBOLS as usize]; POS_STATES_MAX],
            high: [PROB_INIT; LEN_HIGH_SYMBOLS as usize],
            prices: [[0; LEN_SYMBOLS]; POS_STATES_MAX],
            table_size,
            counters: [0; POS_STATES_MAX],
        }
    }

    fn update_prices(&mut self, pos_state: usize) {
        use super::range_enc::{bit_0_price, bit_1_price, bittree_price};
        let table_size = self.table_size;
        self.counters[pos_state] = table_size;

        let a0 = bit_0_price(self.choice);
        let a1 = bit_1_price(self.choice);
        let b0 = a1 + bit_0_price(self.choice2);
        let b1 = a1 + bit_1_price(self.choice2);
        let prices = &mut self.prices[pos_state];

        let mut i = 0;
        while i < table_size && i < LEN_LOW_SYMBOLS {
            prices[i as usize] = a0 + bittree_price(&self.low[pos_state], LEN_LOW_BITS, i);
            i += 1;
        }
        while i < table_size && i < LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS {
            prices[i as usize] =
                b0 + bittree_price(&self.mid[pos_state], LEN_MID_BITS, i - LEN_LOW_SYMBOLS);
            i += 1;
        }
        while i < table_size {
            prices[i as usize] = b1
                + bittree_price(
                    &self.high,
                    LEN_HIGH_BITS,
                    i - LEN_LOW_SYMBOLS - LEN_MID_SYMBOLS,
                );
            i += 1;
        }
    }

    fn reset(&mut self, num_pos_states: usize, fast_mode: bool) {
        let table_size = self.table_size;
        *self = Self::new(table_size);
        if !fast_mode {
            for pos_state in 0..num_pos_states {
                self.update_prices(pos_state);
            }
        }
    }

    #[inline(always)]
    fn encode(&mut self, rc: &mut RangeEncoder, pos_state: usize, len: u32, fast_mode: bool) {
        // Only getoptimum uses the prices so don't update the table when
        // in fast mode. liblzma queues the bits of a symbol and updates
        // the probabilities only after the symbol, so the prices are those
        // from before encoding this length.
        if !fast_mode {
            self.counters[pos_state] -= 1;
            if self.counters[pos_state] == 0 {
                self.update_prices(pos_state);
            }
        }

        debug_assert!(len <= MATCH_LEN_MAX);
        let mut len = len - MATCH_LEN_MIN;
        if len < LEN_LOW_SYMBOLS {
            rc.bit(&mut self.choice, 0);
            rc.bittree(&mut self.low[pos_state], LEN_LOW_BITS, len);
        } else {
            rc.bit(&mut self.choice, 1);
            len -= LEN_LOW_SYMBOLS;
            if len < LEN_MID_SYMBOLS {
                rc.bit(&mut self.choice2, 0);
                rc.bittree(&mut self.mid[pos_state], LEN_MID_BITS, len);
            } else {
                rc.bit(&mut self.choice2, 1);
                len -= LEN_MID_SYMBOLS;
                rc.bittree(&mut self.high, LEN_HIGH_BITS, len);
            }
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Optimal {
    pub(crate) state: State,
    pub(crate) prev_1_is_literal: bool,
    pub(crate) prev_2: bool,
    pub(crate) pos_prev_2: u32,
    pub(crate) back_prev_2: u32,
    pub(crate) price: u32,
    pub(crate) pos_prev: u32,
    pub(crate) back_prev: u32,
    pub(crate) backs: [u32; REPS],
}

/// `lzma_lzma1_encoder`
pub(crate) struct LzmaEncoder {
    pub(crate) rc: RangeEncoder,
    /// Uncompressed size (doesn't include possible preset dictionary)
    pub(crate) uncomp_size: u64,
    pub(crate) state: State,
    /// The four most recent match distances
    pub(crate) reps: [u32; REPS],
    pub(crate) matches: [Match; MATCH_LEN_MAX as usize + 1],
    pub(crate) matches_count: u32,
    /// The length of the longest match between calls to the optimum
    /// functions.
    pub(crate) longest_match_length: u32,
    pub(crate) fast_mode: bool,
    /// True if the encoder has been initialized by encoding the first
    /// byte as a literal.
    is_initialized: bool,
    use_eopm: bool,
    pub(crate) pos_mask: u32,
    pub(crate) literal_context_bits: u32,
    pub(crate) literal_mask: u32,
    lc: u32,
    lp: u32,
    pb: u32,
    pub(crate) literal: Vec<u16>,
    pub(crate) is_match: [[u16; POS_STATES_MAX]; STATES],
    pub(crate) is_rep: [u16; STATES],
    pub(crate) is_rep0: [u16; STATES],
    pub(crate) is_rep1: [u16; STATES],
    pub(crate) is_rep2: [u16; STATES],
    pub(crate) is_rep0_long: [[u16; POS_STATES_MAX]; STATES],
    pub(crate) dist_slot: [[u16; DIST_SLOTS]; DIST_STATES],
    pub(crate) dist_special: [u16; FULL_DISTANCES - DIST_MODEL_END],
    pub(crate) dist_align: [u16; ALIGN_SIZE],
    pub(crate) match_len_encoder: LengthEncoder,
    pub(crate) rep_len_encoder: LengthEncoder,
    pub(crate) dist_slot_prices: [[u32; DIST_SLOTS]; DIST_STATES],
    pub(crate) dist_prices: [[u32; FULL_DISTANCES]; DIST_STATES],
    pub(crate) dist_table_size: u32,
    pub(crate) match_price_count: u32,
    pub(crate) align_prices: [u32; ALIGN_SIZE],
    pub(crate) align_price_count: u32,
    pub(crate) opts_end_index: u32,
    pub(crate) opts_current_index: u32,
    pub(crate) opts: Vec<Optimal>,
}

/// Options adjusted as liblzma's encoder sees them, with out-of-range
/// values clamped.
pub(crate) struct Settings {
    pub(crate) dict_size: u32,
    pub(crate) nice_len: u32,
    pub(crate) lc: u32,
    pub(crate) lp: u32,
    pub(crate) pb: u32,
}

impl Settings {
    pub(crate) fn new(options: &LzmaOptions) -> Self {
        let dict_size = options
            .dict_size
            .clamp(crate::DICT_SIZE_MIN, (1 << 30) + (1 << 29));
        debug_assert!(is_enc_dict_size_valid(dict_size));
        Self {
            dict_size,
            // The encoder ensures that nice_len is big enough for the
            // selected match finder.
            nice_len: options
                .nice_len
                .clamp(MATCH_LEN_MIN, MATCH_LEN_MAX)
                .max(options.mf.hash_bytes()),
            lc: options.lc.min(8),
            lp: options.lp.min(4),
            pb: options.pb.min(4),
        }
    }

    /// The LZ encoder options for LZMA (`set_lz_options()`), with
    /// `before_size` raised to keep LZMA2's uncompressed chunks available.
    pub(crate) fn lz_options<'a>(&self, options: &'a LzmaOptions, lzma2: bool) -> LzOptions<'a> {
        let mut before_size = OPTS as u32;
        if lzma2 && before_size + self.dict_size < LZMA2_CHUNK_MAX {
            before_size = LZMA2_CHUNK_MAX - self.dict_size;
        }
        LzOptions {
            before_size,
            dict_size: self.dict_size,
            after_size: LOOP_INPUT_MAX,
            match_len_max: MATCH_LEN_MAX,
            nice_len: self.nice_len,
            match_finder: options.mf,
            depth: options.depth_limit.max(0) as u32,
            preset_dict: options.preset_dict.as_deref(),
        }
    }
}

impl LzmaEncoder {
    /// `lzma_lzma_encoder_create()`: LZMA1 streams end with an end of
    /// payload marker if `use_eopm`; LZMA2 never uses one.
    pub(crate) fn new(options: &LzmaOptions, settings: &Settings, use_eopm: bool) -> Self {
        let fast_mode = options.mode == EncodeMode::Fast;
        // Round the dictionary size up to next 2^n.
        let log_size = 32 - (settings.dict_size - 1).leading_zeros();
        // Length encoders' price table size
        let table_size = settings.nice_len + 1 - MATCH_LEN_MIN;
        let mut e = Self {
            rc: RangeEncoder::new(Vec::new()),
            uncomp_size: 0,
            state: State::new(),
            reps: [0; REPS],
            matches: [Match::default(); MATCH_LEN_MAX as usize + 1],
            matches_count: 0,
            longest_match_length: 0,
            fast_mode,
            // We don't need to write the first byte as literal if there is
            // a non-empty preset dictionary.
            is_initialized: options.preset_dict.as_ref().is_some_and(|d| !d.is_empty()),
            use_eopm,
            pos_mask: 0,
            literal_context_bits: 0,
            literal_mask: 0,
            lc: settings.lc,
            lp: settings.lp,
            pb: settings.pb,
            literal: vec![PROB_INIT; LITERAL_CODER_SIZE << (settings.lc + settings.lp)],
            is_match: [[PROB_INIT; POS_STATES_MAX]; STATES],
            is_rep: [PROB_INIT; STATES],
            is_rep0: [PROB_INIT; STATES],
            is_rep1: [PROB_INIT; STATES],
            is_rep2: [PROB_INIT; STATES],
            is_rep0_long: [[PROB_INIT; POS_STATES_MAX]; STATES],
            dist_slot: [[PROB_INIT; DIST_SLOTS]; DIST_STATES],
            dist_special: [PROB_INIT; FULL_DISTANCES - DIST_MODEL_END],
            dist_align: [PROB_INIT; ALIGN_SIZE],
            match_len_encoder: LengthEncoder::new(table_size),
            rep_len_encoder: LengthEncoder::new(table_size),
            dist_slot_prices: [[0; DIST_SLOTS]; DIST_STATES],
            dist_prices: [[0; FULL_DISTANCES]; DIST_STATES],
            dist_table_size: log_size * 2,
            match_price_count: 0,
            align_prices: [0; ALIGN_SIZE],
            align_price_count: 0,
            opts_end_index: 0,
            opts_current_index: 0,
            opts: if fast_mode {
                Vec::new()
            } else {
                vec![Optimal::default(); OPTS]
            },
        };
        e.reset();
        e
    }

    /// `lzma_lzma_encoder_reset()`
    pub(crate) fn reset(&mut self) {
        self.pos_mask = (1 << self.pb) - 1;
        self.literal_context_bits = self.lc;
        self.literal_mask = (0x100 << self.lp) - (0x100 >> self.lc);

        self.rc.reset();
        self.state = State::new();
        self.reps = [0; REPS];
        self.literal.fill(PROB_INIT);
        self.is_match = [[PROB_INIT; POS_STATES_MAX]; STATES];
        self.is_rep0_long = [[PROB_INIT; POS_STATES_MAX]; STATES];
        self.is_rep = [PROB_INIT; STATES];
        self.is_rep0 = [PROB_INIT; STATES];
        self.is_rep1 = [PROB_INIT; STATES];
        self.is_rep2 = [PROB_INIT; STATES];
        self.dist_special = [PROB_INIT; FULL_DISTANCES - DIST_MODEL_END];
        self.dist_slot = [[PROB_INIT; DIST_SLOTS]; DIST_STATES];
        self.dist_align = [PROB_INIT; ALIGN_SIZE];

        let num_pos_states = 1 << self.pb;
        self.match_len_encoder.reset(num_pos_states, self.fast_mode);
        self.rep_len_encoder.reset(num_pos_states, self.fast_mode);

        // Price counts are incremented every time appropriate probabilities
        // are changed. price counts are set to zero when the price tables
        // are updated, which is done when the appropriate price counts have
        // big enough value, and read_ahead == 0 which happens at least
        // every OPTS (a few thousand) possible price count increments.
        //
        // By resetting price counts to u32::MAX / 2, we make sure that the
        // price tables will be initialized before they will be used.
        self.match_price_count = u32::MAX / 2;
        self.align_price_count = u32::MAX / 2;

        self.opts_end_index = 0;
        self.opts_current_index = 0;
    }

    /// The properties byte (`lzma_lzma_lclppb_encode()`).
    pub(crate) fn lclppb(&self) -> u8 {
        ((self.pb * 5 + self.lp) * 9 + self.lc) as u8
    }

    /// Index of the literal coder for the next literal byte. The choice
    /// depends on the lowest literal_pos_bits bits of the position of the
    /// current byte and the highest literal_context_bits bits of the
    /// previous byte.
    #[inline(always)]
    pub(crate) fn literal_subcoder(&self, pos: u32, prev_byte: u8) -> usize {
        3 * ((((pos << 8) + u32::from(prev_byte)) & self.literal_mask) << self.literal_context_bits)
            as usize
    }

    fn literal(&mut self, mf: &Mf, position: u32) {
        // Locate the literal byte to be encoded and the subcoder.
        let at = (mf.read_pos - mf.read_ahead) as usize;
        let cur_byte = mf.buffer[at];
        let base = self.literal_subcoder(position, mf.buffer[at - 1]);
        let subcoder = &mut self.literal[base..base + LITERAL_CODER_SIZE];

        if self.state.is_literal() {
            // Previous LZMA-symbol was a literal. Encode a normal
            // literal without a match byte.
            self.state.update_literal();
            self.rc.bittree(subcoder, 8, u32::from(cur_byte));
        } else {
            // Previous LZMA-symbol was a match. Use the last byte of
            // the match as a "match byte". That is, compare the bits
            // of the current literal and the match byte.
            self.state.update_literal();
            let mut match_byte = u32::from(mf.buffer[at - self.reps[0] as usize - 1]);
            let mut offset = 0x100;
            let mut symbol = u32::from(cur_byte) + (1 << 8);
            loop {
                match_byte <<= 1;
                let match_bit = match_byte & offset;
                let subcoder_index = offset + match_bit + (symbol >> 8);
                let bit = (symbol >> 7) & 1;
                self.rc.bit(&mut subcoder[subcoder_index as usize], bit);
                symbol <<= 1;
                offset &= !(match_byte ^ symbol);
                if symbol >= 1 << 16 {
                    break;
                }
            }
        }
    }

    fn match_(&mut self, pos_state: usize, distance: u32, len: u32) {
        self.state.update_match();
        self.match_len_encoder
            .encode(&mut self.rc, pos_state, len, self.fast_mode);

        let dist_slot = get_dist_slot(distance);
        let dist_state = get_dist_state(len);
        self.rc
            .bittree(&mut self.dist_slot[dist_state], DIST_SLOT_BITS, dist_slot);

        if dist_slot >= DIST_MODEL_START as u32 {
            let footer_bits = (dist_slot >> 1) - 1;
            let base = (2 | (dist_slot & 1)) << footer_bits;
            let dist_reduced = distance - base;

            if dist_slot < DIST_MODEL_END as u32 {
                // Careful here: base - dist_slot - 1 can be -1, but
                // the reverse bittree starts at probs[1], not probs[0].
                self.rc.bittree_reverse(
                    &mut self.dist_special,
                    (base - dist_slot) as usize,
                    footer_bits,
                    dist_reduced,
                );
            } else {
                self.rc
                    .direct(dist_reduced >> ALIGN_BITS, footer_bits - ALIGN_BITS as u32);
                self.rc.bittree_reverse(
                    &mut self.dist_align,
                    1,
                    ALIGN_BITS as u32,
                    dist_reduced & ALIGN_MASK as u32,
                );
                self.align_price_count = self.align_price_count.wrapping_add(1);
            }
        }

        self.reps[3] = self.reps[2];
        self.reps[2] = self.reps[1];
        self.reps[1] = self.reps[0];
        self.reps[0] = distance;
        self.match_price_count = self.match_price_count.wrapping_add(1);
    }

    fn rep_match(&mut self, pos_state: usize, rep: u32, len: u32) {
        let state = self.state.get() as usize;
        if rep == 0 {
            self.rc.bit(&mut self.is_rep0[state], 0);
            self.rc.bit(
                &mut self.is_rep0_long[state][pos_state],
                u32::from(len != 1),
            );
        } else {
            let distance = self.reps[rep as usize];
            self.rc.bit(&mut self.is_rep0[state], 1);
            if rep == 1 {
                self.rc.bit(&mut self.is_rep1[state], 0);
            } else {
                self.rc.bit(&mut self.is_rep1[state], 1);
                self.rc.bit(&mut self.is_rep2[state], rep - 2);
                if rep == 3 {
                    self.reps[3] = self.reps[2];
                }
                self.reps[2] = self.reps[1];
            }
            self.reps[1] = self.reps[0];
            self.reps[0] = distance;
        }

        if len == 1 {
            self.state.update_short_rep();
        } else {
            self.rep_len_encoder
                .encode(&mut self.rc, pos_state, len, self.fast_mode);
            self.state.update_long_rep();
        }
    }

    fn encode_symbol(&mut self, mf: &mut Mf, back: u32, len: u32, position: u32) {
        let pos_state = (position & self.pos_mask) as usize;
        let state = self.state.get() as usize;

        if back == u32::MAX {
            // Literal i.e. eight-bit byte
            debug_assert_eq!(len, 1);
            self.rc.bit(&mut self.is_match[state][pos_state], 0);
            self.literal(mf, position);
        } else {
            // Some type of match
            self.rc.bit(&mut self.is_match[state][pos_state], 1);
            if back < REPS as u32 {
                // It's a repeated match i.e. the same distance
                // has been used earlier.
                self.rc.bit(&mut self.is_rep[state], 1);
                self.rep_match(pos_state, back, len);
            } else {
                // Normal match
                self.rc.bit(&mut self.is_rep[state], 0);
                self.match_(pos_state, back - REPS as u32, len);
            }
        }

        debug_assert!(mf.read_ahead >= len);
        mf.read_ahead -= len;
    }

    fn encode_init(&mut self, mf: &mut Mf) -> bool {
        debug_assert_eq!(self.uncomp_size, 0);
        if mf.read_pos == mf.read_limit {
            if mf.action == Action::Run {
                return false; // We cannot do anything.
            }
            // We are finishing (we cannot get here when flushing).
            debug_assert_eq!(mf.write_pos, mf.read_pos);
            debug_assert_eq!(mf.action, Action::Finish);
        } else {
            // Do the actual initialization. The first LZMA symbol must
            // always be a literal.
            mf.skip(1);
            mf.read_ahead = 0;
            self.rc.bit(&mut self.is_match[0][0], 0);
            let byte = u32::from(mf.buffer[0]);
            self.rc
                .bittree(&mut self.literal[..LITERAL_CODER_SIZE], 8, byte);
            self.uncomp_size += 1;
        }

        // Initialization is done (except if empty file).
        self.is_initialized = true;
        true
    }

    fn encode_eopm(&mut self, position: u32) {
        let pos_state = (position & self.pos_mask) as usize;
        let state = self.state.get() as usize;
        self.rc.bit(&mut self.is_match[state][pos_state], 1);
        self.rc.bit(&mut self.is_rep[state], 0);
        self.match_(pos_state, u32::MAX, MATCH_LEN_MIN);
    }

    /// Encodes until more input is needed, returning false, or until the
    /// LZMA1 stream or LZMA2 chunk is finished and flushed, returning true
    /// (`lzma_lzma_encode()`). An LZMA2 chunk ends before `read_pos -
    /// read_ahead` reaches `limit`, or before the compressed data could get
    /// too big.
    pub(crate) fn encode(&mut self, mf: &mut Mf, limit: Option<u32>) -> bool {
        // Initialize the stream if no data has been encoded yet.
        if !self.is_initialized && !self.encode_init(mf) {
            return false;
        }

        loop {
            // With LZMA2 we need to take care that compressed size of
            // a chunk doesn't get too big.
            if limit.is_some_and(|limit| {
                mf.read_pos - mf.read_ahead >= limit
                    || self.rc.out.len() as u64 + self.rc.pending()
                        >= u64::from(LZMA2_CHUNK_MAX - LOOP_INPUT_MAX)
            }) {
                break;
            }

            // Check that there is some input to process.
            if mf.read_pos >= mf.read_limit {
                if mf.action == Action::Run {
                    return false;
                }
                if mf.read_ahead == 0 {
                    break;
                }
            }

            // Get optimal match (repeat position and length).
            // Value ranges for back:
            //   - [0, REPS): repeated match
            //   - [REPS, u32::MAX): match at (back - REPS)
            //   - u32::MAX: not a match but a literal
            // Value ranges for len: [MATCH_LEN_MIN, MATCH_LEN_MAX]
            let position = self.uncomp_size as u32;
            let (back, len) = if self.fast_mode {
                self.optimum_fast(mf)
            } else {
                self.optimum_normal(mf, position)
            };
            self.encode_symbol(mf, back, len, position);
            self.uncomp_size += u64::from(len);
        }

        // LZMA2 doesn't use EOPM at LZMA level.
        if self.use_eopm {
            self.encode_eopm(self.uncomp_size as u32);
        }

        // Flush the remaining bytes from the range encoder.
        self.rc.flush();
        true
    }
}

/// Builds the window and match finder for `options`.
pub(crate) fn new_mf(options: &LzmaOptions, settings: &Settings, lzma2: bool) -> Mf {
    Mf::new(&settings.lz_options(options, lzma2))
}

impl MfType {
    pub(crate) fn mem_usage(self, options: &LzmaOptions) -> u64 {
        crate::lz::memusage(&Settings::new(options).lz_options(options, true))
    }
}
