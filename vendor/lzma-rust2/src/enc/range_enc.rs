//! Range encoder and probability prices, ported from liblzma 5.8.4
//! (`rangecoder/range_encoder.h`, `rangecoder/price.h`; Igor Pavlov,
//! Lasse Collin; 0BSD).
//!
//! liblzma queues the bits of a symbol and encodes them when output space
//! is available. Output goes to a `Vec` here, so bits are encoded at once;
//! normalization still happens before each bit, as in `rc_encode()`, so
//! `pending()` sees the same state between symbols.

use alloc::vec::Vec;

use crate::{BIT_MODEL_TOTAL, BIT_MODEL_TOTAL_BITS, MOVE_BITS, SHIFT_BITS, TOP_VALUE};

const MOVE_REDUCING_BITS: u32 = 4;
const BIT_PRICE_SHIFT_BITS: u32 = 4;

pub(crate) const INFINITY_PRICE: u32 = 1 << 30;

/// Lookup table for the price functions (`price_tablegen.c`).
static PRICES: [u8; (BIT_MODEL_TOTAL >> MOVE_REDUCING_BITS) as usize] = {
    let mut prices = [0; (BIT_MODEL_TOTAL >> MOVE_REDUCING_BITS) as usize];
    let mut i = (1 << MOVE_REDUCING_BITS) / 2;
    while i < BIT_MODEL_TOTAL {
        let mut w = i;
        let mut bit_count = 0;
        let mut j = 0;
        while j < BIT_PRICE_SHIFT_BITS {
            w *= w;
            bit_count <<= 1;
            while w >= 1 << 16 {
                w >>= 1;
                bit_count += 1;
            }
            j += 1;
        }
        prices[(i >> MOVE_REDUCING_BITS) as usize] =
            ((BIT_MODEL_TOTAL_BITS << BIT_PRICE_SHIFT_BITS) - 15 - bit_count) as u8;
        i += 1 << MOVE_REDUCING_BITS;
    }
    prices
};

#[inline(always)]
pub(crate) fn bit_price(prob: u16, bit: u32) -> u32 {
    let i =
        (u32::from(prob) ^ (0u32.wrapping_sub(bit) & (BIT_MODEL_TOTAL - 1))) >> MOVE_REDUCING_BITS;
    u32::from(PRICES[i as usize])
}

#[inline(always)]
pub(crate) fn bit_0_price(prob: u16) -> u32 {
    u32::from(PRICES[(prob >> MOVE_REDUCING_BITS) as usize])
}

#[inline(always)]
pub(crate) fn bit_1_price(prob: u16) -> u32 {
    u32::from(PRICES[((u32::from(prob) ^ (BIT_MODEL_TOTAL - 1)) >> MOVE_REDUCING_BITS) as usize])
}

#[inline(always)]
pub(crate) fn bittree_price(probs: &[u16], bit_levels: u32, symbol: u32) -> u32 {
    let mut price = 0;
    let mut symbol = symbol + (1 << bit_levels);
    loop {
        let bit = symbol & 1;
        symbol >>= 1;
        price += bit_price(probs[symbol as usize], bit);
        if symbol == 1 {
            return price;
        }
    }
}

/// `rc_bittree_reverse_price()` with the tree at `probs[base - 1 + 1..]`.
#[inline(always)]
pub(crate) fn bittree_reverse_price(
    probs: &[u16],
    base: usize,
    bit_levels: u32,
    mut symbol: u32,
) -> u32 {
    let mut price = 0;
    let mut model_index = 1;
    for _ in 0..bit_levels {
        let bit = symbol & 1;
        symbol >>= 1;
        price += bit_price(probs[base + model_index - 1], bit);
        model_index = (model_index << 1) + bit as usize;
    }
    price
}

#[inline(always)]
pub(crate) fn direct_price(bits: u32) -> u32 {
    bits << BIT_PRICE_SHIFT_BITS
}

pub(crate) struct RangeEncoder {
    low: u64,
    cache_size: u64,
    range: u32,
    cache: u8,
    /// Encoded bytes.
    pub(crate) out: Vec<u8>,
}

impl RangeEncoder {
    pub(crate) fn new(out: Vec<u8>) -> Self {
        Self {
            low: 0,
            cache_size: 1,
            range: u32::MAX,
            cache: 0,
            out,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.low = 0;
        self.cache_size = 1;
        self.range = u32::MAX;
        self.cache = 0;
    }

    /// Bytes that may still be output for the symbols encoded so far.
    #[inline(always)]
    pub(crate) fn pending(&self) -> u64 {
        self.cache_size + 5 - 1
    }

    fn shift_low(&mut self) {
        if (self.low as u32) < 0xFF00_0000 || (self.low >> 32) != 0 {
            let carry = (self.low >> 32) as u8;
            let mut byte = self.cache;
            loop {
                self.out.push(byte.wrapping_add(carry));
                byte = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = (self.low >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00FF_FFFF) << SHIFT_BITS;
    }

    #[inline(always)]
    fn normalize(&mut self) {
        if self.range < TOP_VALUE {
            self.shift_low();
            self.range <<= SHIFT_BITS;
        }
    }

    #[inline(always)]
    pub(crate) fn bit(&mut self, prob: &mut u16, bit: u32) {
        self.normalize();
        let p = u32::from(*prob);
        let bound = (self.range >> BIT_MODEL_TOTAL_BITS) * p;
        if bit == 0 {
            self.range = bound;
            *prob = (p + ((BIT_MODEL_TOTAL - p) >> MOVE_BITS)) as u16;
        } else {
            self.low += u64::from(bound);
            self.range -= bound;
            *prob = (p - (p >> MOVE_BITS)) as u16;
        }
    }

    #[inline(always)]
    pub(crate) fn bittree(&mut self, probs: &mut [u16], mut bit_count: u32, symbol: u32) {
        let mut model_index = 1;
        loop {
            bit_count -= 1;
            let bit = (symbol >> bit_count) & 1;
            self.bit(&mut probs[model_index], bit);
            model_index = (model_index << 1) + bit as usize;
            if bit_count == 0 {
                return;
            }
        }
    }

    /// `rc_bittree_reverse()` with the tree at `probs[base - 1 + 1..]`.
    #[inline(always)]
    pub(crate) fn bittree_reverse(
        &mut self,
        probs: &mut [u16],
        base: usize,
        bit_count: u32,
        mut symbol: u32,
    ) {
        let mut model_index = 1;
        for _ in 0..bit_count {
            let bit = symbol & 1;
            symbol >>= 1;
            self.bit(&mut probs[base + model_index - 1], bit);
            model_index = (model_index << 1) + bit as usize;
        }
    }

    pub(crate) fn direct(&mut self, value: u32, mut bit_count: u32) {
        loop {
            self.normalize();
            bit_count -= 1;
            self.range >>= 1;
            if (value >> bit_count) & 1 != 0 {
                self.low += u64::from(self.range);
            }
            if bit_count == 0 {
                return;
            }
        }
    }

    /// Flushes the last five bytes and resets the encoder.
    pub(crate) fn flush(&mut self) {
        self.normalize();
        for _ in 0..5 {
            self.shift_low();
        }
        self.reset();
    }
}
