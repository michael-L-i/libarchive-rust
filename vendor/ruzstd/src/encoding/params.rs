//! Compression parameters, ported from libzstd 1.5.7 (`clevels.h`, `ZSTD_getCParams`).

/// Block compressors, in libzstd's order. libzstd's binary-tree and optimal
/// parsers (`btlazy2` and above) are not ported: levels that select them use
/// [`Strategy::Lazy2`] with the level's own window, table and search sizes.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Strategy {
    Fast = 1,
    DFast,
    Greedy,
    Lazy,
    Lazy2,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct CParams {
    pub window_log: u32,
    pub chain_log: u32,
    pub hash_log: u32,
    pub search_log: u32,
    pub min_match: u32,
    pub target_length: u32,
    pub strategy: Strategy,
}

pub(crate) const MAX_LEVEL: i32 = 22;
pub(crate) const MIN_LEVEL: i32 = -(1 << 17);
pub(crate) const DEFAULT_LEVEL: i32 = 3;

/// `ZSTD_defaultCParameters[0]`: the row libzstd uses when the source size is
/// unknown, as it is for every streamed frame. Entries 13-22 keep libzstd's
/// parameters; only their strategy is capped at lazy2.
#[rustfmt::skip]
const TABLE: [(u32, u32, u32, u32, u32, u32, Strategy); 23] = {
    use Strategy::*;
    [
        // W,  C,  H,  S,  L,  TL, strategy
        (19, 12, 13, 1, 6, 1, Fast), // base for negative levels
        (19, 13, 14, 1, 7, 0, Fast),
        (20, 15, 16, 1, 6, 0, Fast),
        (21, 16, 17, 1, 5, 0, DFast),
        (21, 18, 18, 1, 5, 0, DFast),
        (21, 18, 19, 3, 5, 2, Greedy),
        (21, 18, 19, 3, 5, 4, Lazy),
        (21, 19, 20, 4, 5, 8, Lazy),
        (21, 19, 20, 4, 5, 16, Lazy2),
        (22, 20, 21, 4, 5, 16, Lazy2),
        (22, 21, 22, 5, 5, 16, Lazy2),
        (22, 21, 22, 6, 5, 16, Lazy2),
        (22, 22, 23, 6, 5, 32, Lazy2),
        (22, 22, 22, 4, 5, 32, Lazy2), // btlazy2
        (22, 22, 23, 5, 5, 32, Lazy2), // btlazy2
        (22, 23, 23, 6, 5, 32, Lazy2), // btlazy2
        (22, 22, 22, 5, 5, 48, Lazy2), // btopt
        (23, 23, 22, 5, 4, 64, Lazy2), // btopt
        (23, 23, 22, 6, 3, 64, Lazy2), // btultra
        (23, 24, 22, 7, 3, 256, Lazy2), // btultra2
        (25, 25, 23, 7, 3, 256, Lazy2), // btultra2
        (26, 26, 24, 7, 3, 512, Lazy2), // btultra2
        (27, 27, 25, 9, 3, 999, Lazy2), // btultra2
    ]
};

impl CParams {
    /// `ZSTD_getCParams(level, ZSTD_CONTENTSIZE_UNKNOWN, 0)`.
    pub(crate) fn for_level(level: i32) -> Self {
        let row = match level {
            0 => DEFAULT_LEVEL,
            ..0 => 0,
            _ => level.min(MAX_LEVEL),
        };
        let (window_log, chain_log, hash_log, search_log, min_match, target_length, strategy) =
            TABLE[row as usize];
        let mut params = CParams {
            window_log,
            chain_log,
            hash_log,
            search_log,
            min_match,
            target_length,
            strategy,
        };
        if level < 0 {
            // Acceleration factor.
            params.target_length = level.max(MIN_LEVEL).unsigned_abs();
        }
        params
    }

    /// `ZSTD_literalsCompressionIsDisabled()` in its automatic mode:
    /// negative levels store literals raw.
    pub(crate) fn literals_compression_disabled(&self) -> bool {
        self.strategy == Strategy::Fast && self.target_length > 0
    }
}
