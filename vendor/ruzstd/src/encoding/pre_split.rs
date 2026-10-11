//! Splitting full blocks where their statistics change, ported from
//! libzstd 1.5.7 (`zstd_preSplit.c` and `ZSTD_optimalBlockSize()`).

use super::params::Strategy;

const FULL_BLOCK: usize = 128 * 1024;
const THRESHOLD_PENALTY_RATE: u64 = 16;
const THRESHOLD_BASE: u64 = THRESHOLD_PENALTY_RATE - 2;
const THRESHOLD_PENALTY: u64 = 3;
const HASH_LOG_MAX: u32 = 10;
const CHUNK_SIZE: usize = 8 << 10;
const SEGMENT_SIZE: usize = 512;

struct Fingerprint {
    events: [u32; 1 << HASH_LOG_MAX],
    nb_events: u64,
}

impl Fingerprint {
    fn new() -> Self {
        Self {
            events: [0; 1 << HASH_LOG_MAX],
            nb_events: 0,
        }
    }

    /// `recordFingerprint_generic()`: hashes of 2-byte strings every
    /// `rate` bytes; a hash of 8 bits is the first byte.
    fn record(&mut self, src: &[u8], rate: usize, hash_log: u32) {
        self.events[..1 << hash_log].fill(0);
        let limit = src.len() - 1;
        for pair in src.windows(2).step_by(rate) {
            let hash = if hash_log == 8 {
                u32::from(pair[0])
            } else {
                u32::from(u16::from_le_bytes([pair[0], pair[1]])).wrapping_mul(0x9e3779b9)
                    >> (32 - hash_log)
            };
            self.events[hash as usize] += 1;
        }
        self.nb_events = (limit / rate) as u64;
    }

    /// `fpDistance()`.
    fn distance(&self, other: &Self, hash_log: u32) -> u64 {
        self.events[..1 << hash_log]
            .iter()
            .zip(&other.events)
            .map(|(&a, &b)| {
                (i64::from(a) * other.nb_events as i64 - i64::from(b) * self.nb_events as i64)
                    .unsigned_abs()
            })
            .sum()
    }

    /// `compareFingerprints()`: whether `new` is "too different".
    fn differs(&self, new: &Self, penalty: u64, hash_log: u32) -> bool {
        let p50 = self.nb_events * new.nb_events;
        let deviation = self.distance(new, hash_log);
        let threshold = p50 * (THRESHOLD_BASE + penalty) / THRESHOLD_PENALTY_RATE;
        deviation >= threshold
    }
}

/// `ZSTD_optimalBlockSize()`: the size of the next block of `src`, given the
/// maximum block size. Only full 128 KiB blocks are split, and only after
/// the frame has saved at least 3 bytes so far.
pub(crate) fn block_size(src: &[u8], max: usize, strategy: Strategy, savings: i64) -> usize {
    if src.len() < FULL_BLOCK || max < FULL_BLOCK {
        return src.len().min(max);
    }
    if savings < 3 {
        return FULL_BLOCK;
    }
    let block = &src[..FULL_BLOCK];
    // splitLevels[] by strategy: fast samples the borders, then faster
    // strategies sample chunks more sparsely.
    match strategy {
        Strategy::Fast => split_from_borders(block),
        Strategy::DFast => split_by_chunks(block, 43, 8),
        Strategy::Greedy | Strategy::Lazy => split_by_chunks(block, 11, 9),
        Strategy::Lazy2 => split_by_chunks(block, 5, 10),
    }
}

/// `ZSTD_splitBlock_byChunks()`: split before the first 8 KiB chunk that
/// differs from all the chunks before it.
fn split_by_chunks(block: &[u8], rate: usize, hash_log: u32) -> usize {
    let mut past = Fingerprint::new();
    let mut new = Fingerprint::new();
    let mut penalty = THRESHOLD_PENALTY;
    past.record(&block[..CHUNK_SIZE], rate, hash_log);
    for pos in (CHUNK_SIZE..block.len()).step_by(CHUNK_SIZE) {
        new.record(&block[pos..pos + CHUNK_SIZE], rate, hash_log);
        if past.differs(&new, penalty, hash_log) {
            return pos;
        }
        for (a, &b) in past.events.iter_mut().zip(&new.events) {
            *a += b;
        }
        past.nb_events += new.nb_events;
        penalty = penalty.saturating_sub(1);
    }
    block.len()
}

/// `ZSTD_splitBlock_fromBorders()`: compare byte histograms of both ends
/// and the middle, and split at a quarter, half or three quarters.
fn split_from_borders(block: &[u8]) -> usize {
    let histogram = |segment: &[u8]| {
        let mut fp = Fingerprint::new();
        for &b in segment {
            fp.events[b as usize] += 1;
        }
        fp.nb_events = SEGMENT_SIZE as u64;
        fp
    };
    let begin = histogram(&block[..SEGMENT_SIZE]);
    let end = histogram(&block[block.len() - SEGMENT_SIZE..]);
    if !begin.differs(&end, 0, 8) {
        return block.len();
    }
    let middle_start = block.len() / 2 - SEGMENT_SIZE / 2;
    let middle = histogram(&block[middle_start..middle_start + SEGMENT_SIZE]);
    let from_begin = begin.distance(&middle, 8);
    let from_end = end.distance(&middle, 8);
    let min_distance = (SEGMENT_SIZE * SEGMENT_SIZE / 3) as u64;
    if from_begin.abs_diff(from_end) < min_distance {
        return 64 * 1024;
    }
    if from_begin > from_end {
        32 * 1024
    } else {
        96 * 1024
    }
}
