//! FSE table construction and encoding, the bit stream writer and byte
//! histograms, ported from libzstd 1.5.7 (`fse_compress.c`, `bitstream.h`,
//! `hist.c`).

pub(crate) const MIN_TABLE_LOG: u32 = 5;
/// The largest table zstd uses: literal and match length codes.
const MAX_TABLE_LOG: u32 = 9;
/// Room for the largest alphabet, 53 match length codes, rounded up to a
/// power of two so that masked symbols index it without bounds checks.
const MAX_SYMBOLS: usize = 64;

pub(crate) fn highbit32(value: u32) -> u32 {
    debug_assert!(value != 0);
    31 - value.leading_zeros()
}

/// `BIT_CStream_t`: bits are appended from the low end of a 64-bit container
/// and flushed as little-endian bytes. Writing past the end of `out` is
/// detected when the stream is closed, as in libzstd.
pub(crate) struct BitStream<'a> {
    out: &'a mut [u8],
    pos: usize,
    end: usize,
    container: u64,
    nbits: u32,
}

impl<'a> BitStream<'a> {
    /// `None` when `out` cannot hold a single container.
    pub(crate) fn new(out: &'a mut [u8]) -> Option<Self> {
        let end = out.len().checked_sub(8).filter(|&end| end > 0)?;
        Some(Self {
            out,
            pos: 0,
            end,
            container: 0,
            nbits: 0,
        })
    }

    /// Append the low `nbits` bits of `value`.
    #[inline(always)]
    pub(crate) fn add(&mut self, value: u64, nbits: u32) {
        debug_assert!(nbits < 64 && self.nbits + nbits < 64);
        self.container |= (value & ((1u64 << nbits) - 1)) << self.nbits;
        self.nbits += nbits;
    }

    #[inline(always)]
    pub(crate) fn flush(&mut self) {
        let bytes = (self.nbits >> 3) as usize;
        if let Some(window) = self.out.get_mut(self.pos..self.pos + 8) {
            window.copy_from_slice(&self.container.to_le_bytes());
        }
        self.pos = (self.pos + bytes).min(self.end);
        self.nbits &= 7;
        self.container >>= bytes * 8;
    }

    /// Add the end mark and return the stream size, or 0 on overflow.
    pub(crate) fn close(mut self) -> usize {
        self.add(1, 1);
        self.flush();
        if self.pos >= self.end {
            return 0;
        }
        self.pos + usize::from(self.nbits > 0)
    }
}

/// `FSE_symbolCompressionTransform`.
#[derive(Copy, Clone, Default, Debug)]
struct SymbolTransform {
    delta_find_state: i32,
    delta_nb_bits: u32,
}

/// `FSE_CTable`, sized for the largest zstd alphabet and table.
#[derive(Clone, Debug)]
pub(crate) struct FseCTable {
    log: u32,
    max_symbol: u32,
    states: [u16; 1 << MAX_TABLE_LOG],
    transforms: [SymbolTransform; MAX_SYMBOLS],
}

impl Default for FseCTable {
    fn default() -> Self {
        Self {
            log: 0,
            max_symbol: 0,
            states: [0; 1 << MAX_TABLE_LOG],
            transforms: [SymbolTransform::default(); MAX_SYMBOLS],
        }
    }
}

impl FseCTable {
    /// `FSE_buildCTable_wksp()`.
    pub(crate) fn build(&mut self, norm: &[i16], log: u32) {
        let size = 1usize << log;
        let mask = size - 1;
        let step = (size >> 1) + (size >> 3) + 3;
        let mut cumul = [0u16; MAX_SYMBOLS + 1];
        let mut symbols = [0u8; 1 << MAX_TABLE_LOG];
        let mut high_threshold = size - 1;
        self.log = log;
        self.max_symbol = norm.len() as u32 - 1;

        // Low probability symbols take the last cells.
        for (s, &n) in norm.iter().enumerate() {
            if n == -1 {
                cumul[s + 1] = cumul[s] + 1;
                symbols[high_threshold] = s as u8;
                high_threshold = high_threshold.wrapping_sub(1);
            } else {
                cumul[s + 1] = cumul[s] + n as u16;
            }
        }
        // Spread the remaining symbols.
        let mut position = 0;
        for (s, &n) in norm.iter().enumerate() {
            for _ in 0..n.max(0) {
                symbols[position] = s as u8;
                position = (position + step) & mask;
                while position > high_threshold {
                    position = (position + step) & mask;
                }
            }
        }
        debug_assert_eq!(position, 0);
        for (u, &s) in symbols[..size].iter().enumerate() {
            let slot = &mut cumul[s as usize];
            self.states[*slot as usize] = (size + u) as u16;
            *slot += 1;
        }

        let mut total = 0i32;
        for (t, &n) in self.transforms.iter_mut().zip(norm) {
            *t = match n {
                0 => SymbolTransform {
                    delta_find_state: 0,
                    delta_nb_bits: ((log + 1) << 16) - (1 << log),
                },
                -1 | 1 => {
                    total += 1;
                    SymbolTransform {
                        delta_find_state: total - 2,
                        delta_nb_bits: (log << 16) - (1 << log),
                    }
                }
                _ => {
                    let max_bits_out = log - highbit32(n as u32 - 1);
                    let min_state_plus = (n as u32) << max_bits_out;
                    total += i32::from(n);
                    SymbolTransform {
                        delta_find_state: total - 2 * i32::from(n),
                        delta_nb_bits: (max_bits_out << 16) - min_state_plus,
                    }
                }
            };
        }
    }

    /// `FSE_buildCTable_rle()`.
    pub(crate) fn build_rle(&mut self, symbol: u8) {
        self.log = 0;
        self.max_symbol = u32::from(symbol);
        self.states[0] = 0;
        self.states[1] = 0;
        self.transforms[symbol as usize] = SymbolTransform::default();
    }

    /// `FSE_initCState2()`: the state after encoding `symbol` first.
    #[inline(always)]
    pub(crate) fn start(&self, symbol: u8) -> u32 {
        let t = self.transform(symbol);
        let nb_bits_out = (t.delta_nb_bits + (1 << 15)) >> 16;
        let value = (nb_bits_out << 16).wrapping_sub(t.delta_nb_bits);
        self.state(value >> nb_bits_out, t)
    }

    /// `FSE_encodeSymbol()`.
    #[inline(always)]
    pub(crate) fn encode(&self, bits: &mut BitStream<'_>, state: &mut u32, symbol: u8) {
        let t = self.transform(symbol);
        let nb_bits_out = (*state + t.delta_nb_bits) >> 16;
        bits.add(u64::from(*state), nb_bits_out);
        *state = self.state(*state >> nb_bits_out, t);
    }

    // Symbols and states of a valid table are in range: the masks only let
    // the compiler see that.
    #[inline(always)]
    fn transform(&self, symbol: u8) -> SymbolTransform {
        self.transforms[symbol as usize & (MAX_SYMBOLS - 1)]
    }

    #[inline(always)]
    fn state(&self, high: u32, t: SymbolTransform) -> u32 {
        let index = (high as i32 + t.delta_find_state) as usize;
        u32::from(self.states[index & ((1 << MAX_TABLE_LOG) - 1)])
    }

    /// `FSE_flushCState()`.
    pub(crate) fn finish(&self, bits: &mut BitStream<'_>, state: u32) {
        bits.add(u64::from(state), self.log);
        bits.flush();
    }

    /// `ZSTD_fseBitCost()`: the cost in bits of `count` using this table, or
    /// `None` if a counted symbol has no state.
    pub(crate) fn bit_cost(&self, count: &[u32]) -> Option<usize> {
        const ACCURACY_LOG: u32 = 8;
        if (self.max_symbol as usize) + 1 < count.len() {
            return None;
        }
        let size = 1u32 << self.log;
        let mut cost = 0usize;
        for (&c, t) in count.iter().zip(&self.transforms) {
            if c == 0 {
                continue;
            }
            // FSE_bitCost()
            let min_nb_bits = t.delta_nb_bits >> 16;
            let threshold = (min_nb_bits + 1) << 16;
            let delta = threshold - (t.delta_nb_bits + size);
            let normalized = (delta << ACCURACY_LOG) >> self.log;
            let bit_cost = (min_nb_bits + 1) * (1 << ACCURACY_LOG) - normalized;
            if bit_cost >= (self.log + 1) << ACCURACY_LOG {
                return None;
            }
            cost += c as usize * bit_cost as usize;
        }
        Some(cost >> ACCURACY_LOG)
    }
}

/// `FSE_minTableLog()`.
fn min_table_log(total: usize, max_symbol: u32) -> u32 {
    let min_bits_src = highbit32(total as u32) + 1;
    let min_bits_symbols = highbit32(max_symbol.max(1)) + 2;
    min_bits_src.min(min_bits_symbols)
}

/// `FSE_optimalTableLog_internal()`.
pub(crate) fn optimal_table_log(max_log: u32, total: usize, max_symbol: u32, minus: u32) -> u32 {
    debug_assert!(total > 1);
    let max_bits_src = highbit32(total as u32 - 1).wrapping_sub(minus);
    let mut log = max_log;
    if max_bits_src < log {
        log = max_bits_src;
    }
    log = log.max(min_table_log(total, max_symbol));
    log.clamp(MIN_TABLE_LOG, 12)
}

/// `FSE_normalizeCount()`: scale `count` (summing to `total`) to `1 << log`.
/// `None` signals libzstd's normalization error.
pub(crate) fn normalize_count(
    norm: &mut [i16],
    log: u32,
    count: &[u32],
    total: usize,
    low_prob_count: bool,
) -> Option<()> {
    const RTB_TABLE: [u64; 8] = [0, 473195, 504333, 520860, 550000, 700000, 750000, 830000];
    debug_assert!(log >= min_table_log(total, count.len() as u32 - 1));
    let low_prob: i16 = if low_prob_count { -1 } else { 1 };
    let scale = 62 - u64::from(log);
    let step = (1u64 << 62) / total as u64;
    let v_step = 1u64 << (scale - 20);
    let mut still_to_distribute = 1i32 << log;
    let mut largest = 0;
    let mut largest_p = 0i16;
    let low_threshold = (total >> log) as u32;
    for (s, (&c, n)) in count.iter().zip(norm.iter_mut()).enumerate() {
        if c as usize == total {
            // RLE: the caller encodes it separately.
            return Some(());
        }
        if c == 0 {
            *n = 0;
        } else if c <= low_threshold {
            *n = low_prob;
            still_to_distribute -= 1;
        } else {
            let mut proba = ((u64::from(c) * step) >> scale) as i16;
            if proba < 8 {
                let rest_to_beat = v_step * RTB_TABLE[proba as usize];
                proba += i16::from(u64::from(c) * step - ((proba as u64) << scale) > rest_to_beat);
            }
            if proba > largest_p {
                largest_p = proba;
                largest = s;
            }
            *n = proba;
            still_to_distribute -= i32::from(proba);
        }
    }
    if -still_to_distribute >= i32::from(norm[largest] >> 1) {
        // Corner case: use the secondary method.
        normalize_m2(norm, log, count, total, low_prob)
    } else {
        norm[largest] += still_to_distribute as i16;
        Some(())
    }
}

/// `FSE_normalizeM2()`.
fn normalize_m2(
    norm: &mut [i16],
    log: u32,
    count: &[u32],
    mut total: usize,
    low_prob: i16,
) -> Option<()> {
    const NOT_YET_ASSIGNED: i16 = -2;
    let mut distributed = 0u32;
    let low_threshold = (total >> log) as u32;
    let mut low_one = ((total * 3) >> (log + 1)) as u32;
    for (&c, n) in count.iter().zip(norm.iter_mut()) {
        if c == 0 {
            *n = 0;
        } else if c <= low_threshold {
            *n = low_prob;
            distributed += 1;
            total -= c as usize;
        } else if c <= low_one {
            *n = 1;
            distributed += 1;
            total -= c as usize;
        } else {
            *n = NOT_YET_ASSIGNED;
        }
    }
    let mut to_distribute = (1u32 << log) - distributed;
    if to_distribute == 0 {
        return Some(());
    }
    if (total as u64 / u64::from(to_distribute)) > u64::from(low_one) {
        // Risk of rounding to zero.
        low_one = ((total * 3) / (to_distribute as usize * 2)) as u32;
        for (&c, n) in count.iter().zip(norm.iter_mut()) {
            if *n == NOT_YET_ASSIGNED && c <= low_one {
                *n = 1;
                distributed += 1;
                total -= c as usize;
            }
        }
        to_distribute = (1u32 << log) - distributed;
    }
    if distributed as usize == count.len() {
        // All values are pretty poor: give the remaining points to the max.
        let (max_v, _) =
            count.iter().enumerate().fold(
                (0, 0),
                |best, (s, &c)| if c > best.1 { (s, c) } else { best },
            );
        norm[max_v] += to_distribute as i16;
        return Some(());
    }
    if total == 0 {
        // All symbols were low enough for the low_one or low_threshold.
        let mut s = 0;
        while to_distribute > 0 {
            if norm[s] > 0 {
                to_distribute -= 1;
                norm[s] += 1;
            }
            s = (s + 1) % count.len();
        }
        return Some(());
    }
    let v_step_log = 62 - u64::from(log);
    let mid = (1u64 << (v_step_log - 1)) - 1;
    let r_step = ((1u64 << v_step_log) * u64::from(to_distribute) + mid) / total as u64;
    let mut tmp_total = mid;
    for (&c, n) in count.iter().zip(norm.iter_mut()) {
        if *n == NOT_YET_ASSIGNED {
            let end = tmp_total + u64::from(c) * r_step;
            let weight = (end >> v_step_log) as u32 - (tmp_total >> v_step_log) as u32;
            if weight < 1 {
                return None;
            }
            *n = weight as i16;
            tmp_total = end;
        }
    }
    Some(())
}

/// `FSE_writeNCount()`: the table description. Returns its size, or `None`
/// if `out` is too small.
pub(crate) fn write_ncount(out: &mut [u8], norm: &[i16], log: u32) -> Option<usize> {
    let table_size = 1i32 << log;
    let mut pos = 0;
    let mut bit_stream = log - MIN_TABLE_LOG;
    let mut bit_count = 4;
    let mut remaining = table_size + 1;
    let mut threshold = table_size;
    let mut nb_bits = log as i32 + 1;
    let mut symbol = 0;
    let mut previous_is_0 = false;
    let mut emit = |pos: &mut usize, bit_stream: &mut u32, bit_count: &mut i32| -> Option<()> {
        out.get_mut(*pos..*pos + 2)?
            .copy_from_slice(&(*bit_stream as u16).to_le_bytes());
        *pos += 2;
        *bit_stream >>= 16;
        *bit_count -= 16;
        Some(())
    };
    while symbol < norm.len() && remaining > 1 {
        if previous_is_0 {
            let mut start = symbol;
            while symbol < norm.len() && norm[symbol] == 0 {
                symbol += 1;
            }
            if symbol == norm.len() {
                break;
            }
            while symbol >= start + 24 {
                start += 24;
                bit_stream += 0xFFFF << bit_count;
                bit_count += 16;
                emit(&mut pos, &mut bit_stream, &mut bit_count)?;
            }
            while symbol >= start + 3 {
                start += 3;
                bit_stream += 3 << bit_count;
                bit_count += 2;
            }
            bit_stream += ((symbol - start) as u32) << bit_count;
            bit_count += 2;
            if bit_count > 16 {
                emit(&mut pos, &mut bit_stream, &mut bit_count)?;
            }
        }
        let mut count = i32::from(norm[symbol]);
        symbol += 1;
        let max = (2 * threshold - 1) - remaining;
        remaining -= count.abs();
        count += 1;
        if count >= threshold {
            count += max;
        }
        bit_stream += (count as u32) << bit_count;
        bit_count += nb_bits;
        bit_count -= i32::from(count < max);
        previous_is_0 = count == 1;
        debug_assert!(remaining >= 1);
        while remaining < threshold {
            nb_bits -= 1;
            threshold >>= 1;
        }
        if bit_count > 16 {
            emit(&mut pos, &mut bit_stream, &mut bit_count)?;
        }
    }
    debug_assert_eq!(remaining, 1);
    out.get_mut(pos..pos + 2)?
        .copy_from_slice(&(bit_stream as u16).to_le_bytes());
    Some(pos + (bit_count as usize).div_ceil(8))
}

/// `HIST_count_wksp()`: returns the largest count and trims `max_symbol` to
/// the largest present symbol. Large inputs are counted into four tables,
/// as libzstd does, so that runs of a byte do not serialize on one counter.
pub(crate) fn histogram(count: &mut [u32], max_symbol: &mut u32, src: &[u8]) -> u32 {
    count.fill(0);
    if src.len() < 1500 {
        for &b in src {
            count[b as usize] += 1;
        }
    } else {
        // HIST_count_parallel_wksp(): 16 bytes per iteration.
        let mut counts = [[0u32; 256]; 4];
        let mut words = src.chunks_exact(16);
        for chunk in &mut words {
            for word in chunk.chunks_exact(4) {
                let word = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
                counts[0][word as u8 as usize] += 1;
                counts[1][(word >> 8) as u8 as usize] += 1;
                counts[2][(word >> 16) as u8 as usize] += 1;
                counts[3][(word >> 24) as usize] += 1;
            }
        }
        for &b in words.remainder() {
            counts[0][b as usize] += 1;
        }
        for (s, c) in count.iter_mut().enumerate() {
            *c = counts[0][s] + counts[1][s] + counts[2][s] + counts[3][s];
        }
    }
    while *max_symbol > 0 && count[*max_symbol as usize] == 0 {
        *max_symbol -= 1;
    }
    count[..=*max_symbol as usize]
        .iter()
        .copied()
        .max()
        .unwrap_or(0)
}

/// `FSE_compress_usingCTable()` with two interleaved states, as used for
/// Huffman weights. Returns 0 if the result does not fit.
pub(crate) fn compress_using_ctable(out: &mut [u8], src: &[u8], table: &FseCTable) -> usize {
    if src.len() <= 2 {
        return 0;
    }
    let Some(mut bits) = BitStream::new(out) else {
        return 0;
    };
    let mut symbols = src.iter().rev().copied();
    let mut next = || symbols.next().unwrap_or(0);
    let (mut state1, mut state2);
    let mut n = src.len();
    if n & 1 == 1 {
        state1 = table.start(next());
        state2 = table.start(next());
        table.encode(&mut bits, &mut state1, next());
        bits.flush();
        n -= 3;
    } else {
        state2 = table.start(next());
        state1 = table.start(next());
        n -= 2;
    }
    if n & 2 == 2 {
        table.encode(&mut bits, &mut state2, next());
        table.encode(&mut bits, &mut state1, next());
        bits.flush();
        n -= 2;
    }
    while n > 0 {
        table.encode(&mut bits, &mut state2, next());
        table.encode(&mut bits, &mut state1, next());
        table.encode(&mut bits, &mut state2, next());
        table.encode(&mut bits, &mut state1, next());
        bits.flush();
        n -= 4;
    }
    table.finish(&mut bits, state2);
    table.finish(&mut bits, state1);
    bits.close()
}
