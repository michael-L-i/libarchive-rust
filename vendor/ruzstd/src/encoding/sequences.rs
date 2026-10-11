//! Block entropy coding: the sequence store, sequence codes and their FSE
//! tables, ported from libzstd 1.5.7 (`zstd_compress_sequences.c` and
//! `ZSTD_entropyCompressSeqStore()` in `zstd_compress.c`).

use alloc::vec;
use alloc::vec::Vec;

use super::fse::{self, highbit32, BitStream, FseCTable};
use super::literals::{compress_literals, HufState};
use super::params::{CParams, Strategy};

const MIN_MATCH: u32 = 3;
const MAX_LL: u32 = 35;
const MAX_ML: u32 = 52;
const MAX_OFF: u32 = 31;
const DEFAULT_MAX_OFF: u32 = 28;
const LL_FSE_LOG: u32 = 9;
const ML_FSE_LOG: u32 = 9;
const OFF_FSE_LOG: u32 = 8;
const LONG_NB_SEQ: usize = 0x7F00;

#[rustfmt::skip]
const LL_BITS: [u8; MAX_LL as usize + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16,
];
#[rustfmt::skip]
const LL_DEFAULT_NORM: [i16; MAX_LL as usize + 1] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
const LL_DEFAULT_NORM_LOG: u32 = 6;
#[rustfmt::skip]
const ML_BITS: [u8; MAX_ML as usize + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];
#[rustfmt::skip]
const ML_DEFAULT_NORM: [i16; MAX_ML as usize + 1] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
    -1, -1, -1, -1, -1,
];
const ML_DEFAULT_NORM_LOG: u32 = 6;
#[rustfmt::skip]
const OF_DEFAULT_NORM: [i16; DEFAULT_MAX_OFF as usize + 1] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
const OF_DEFAULT_NORM_LOG: u32 = 5;

/// A match as found by the block compressors: `lit_len` literals, then
/// `match_len` bytes copied from `offset` bytes back.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Seq {
    pub lit_len: u32,
    pub offset: u32,
    pub match_len: u32,
}

/// `SeqStore_t`: one block's literals and sequences. Unlike libzstd's, its
/// offsets are actual distances; repeat codes are assigned when the block
/// is entropy coded, from the exact repeat offset history.
pub(crate) struct SeqStore {
    /// Literals are copied 16 bytes at a time, as libzstd's wildcopy does:
    /// the buffer has that much room past the largest block.
    lits: Vec<u8>,
    lit_len: usize,
    pub seqs: Vec<Seq>,
}

impl SeqStore {
    pub(crate) fn new(max_block_size: usize) -> Self {
        Self {
            lits: vec![0; max_block_size + 16],
            lit_len: 0,
            seqs: Vec::with_capacity(max_block_size / MIN_MATCH as usize),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.lit_len = 0;
        self.seqs.clear();
    }

    pub(crate) fn literals(&self) -> &[u8] {
        &self.lits[..self.lit_len]
    }

    /// `ZSTD_storeSeq()`: `src[anchor..pos]` are the literals.
    #[inline(always)]
    pub(crate) fn store(&mut self, src: &[u8], anchor: usize, pos: usize, offset: u32, len: usize) {
        self.store_literals(src, anchor, pos);
        self.seqs.push(Seq {
            lit_len: (pos - anchor) as u32,
            offset,
            match_len: len as u32,
        });
    }

    /// `ZSTD_storeLastLiterals()`.
    pub(crate) fn store_last_literals(&mut self, src: &[u8], anchor: usize) {
        self.store_literals(src, anchor, src.len());
    }

    #[inline(always)]
    fn store_literals(&mut self, src: &[u8], anchor: usize, pos: usize) {
        let at = self.lit_len;
        let len = pos - anchor;
        if len <= 16 && anchor + 16 <= src.len() {
            self.lits[at..at + 16].copy_from_slice(&src[anchor..anchor + 16]);
        } else {
            self.lits[at..at + len].copy_from_slice(&src[anchor..pos]);
        }
        self.lit_len = at + len;
    }
}

/// `ZSTD_updateRep()` from an actual offset: returns the offset code
/// ("offBase": 1-3 for repeat offsets, offset + 3 otherwise), preferring the
/// repeat codes whenever `offset` equals one. Without branches: whether an
/// offset repeats is unpredictable.
#[inline(always)]
fn off_base(rep: &mut [u32; 3], offset: u32, ll0: bool) -> u32 {
    let [rep0, rep1, rep2] = *rep;
    // After no literals, the codes stand for the next repeat offsets.
    let (code1, code2, code3) = if ll0 {
        (rep1, rep2, rep0.wrapping_sub(1))
    } else {
        (rep0, rep1, rep2)
    };
    let code = if offset == code1 {
        1
    } else if offset == code2 {
        2
    } else if offset == code3 {
        3
    } else {
        offset + 3
    };
    // The offset moves to the front; repeat code 0 (rep0 again) keeps the
    // order and repeat codes 0 and 1 keep rep2.
    let rep_code = code - 1 + u32::from(ll0);
    *rep = [
        offset,
        if rep_code == 0 { rep1 } else { rep0 },
        if rep_code <= 1 { rep2 } else { rep1 },
    ];
    code
}

/// `ZSTD_LLcode()`.
fn ll_code(lit_len: u32) -> u8 {
    #[rustfmt::skip]
    const CODES: [u8; 64] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21,
        22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23,
        24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    ];
    match CODES.get(lit_len as usize) {
        Some(&code) => code,
        None => (highbit32(lit_len) + 19) as u8,
    }
}

/// `ZSTD_MLcode()`.
fn ml_code(ml_base: u32) -> u8 {
    #[rustfmt::skip]
    const CODES: [u8; 128] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        32, 32, 33, 33, 34, 34, 35, 35, 36, 36, 36, 36, 37, 37, 37, 37,
        38, 38, 38, 38, 38, 38, 38, 38, 39, 39, 39, 39, 39, 39, 39, 39,
        40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
        41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
        42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
        42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
    ];
    match CODES.get(ml_base as usize) {
        Some(&code) => code,
        None => (highbit32(ml_base) + 36) as u8,
    }
}

/// One of the three FSE tables (`ZSTD_fseCTables_t`), with libzstd's repeat
/// mode: without dictionaries it is only ever "none" or "check".
#[derive(Clone, Default)]
struct FseState {
    table: FseCTable,
    reusable: bool,
}

/// `ZSTD_entropyCTables_t`: the tables a block leaves for the next one.
#[derive(Clone, Default)]
pub(crate) struct Entropy {
    huf: HufState,
    ll: FseState,
    of: FseState,
    ml: FseState,
}

/// Sequence codes and per-symbol counts, kept to avoid reallocating.
#[derive(Default)]
pub(crate) struct Scratch {
    ll_codes: Vec<u8>,
    ml_codes: Vec<u8>,
    of_codes: Vec<u8>,
    // (lit_len, ml_base, off_base)
    values: Vec<(u32, u32, u32)>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum EncodingType {
    Basic = 0,
    Rle = 1,
    Compressed = 2,
    Repeat = 3,
}

/// `ZSTD_entropyCompressSeqStore()`: the compressed block body, or `None` if
/// the block should be stored raw instead. `rep` is updated as the decoder
/// will update it.
pub(crate) fn compress_block(
    dst: &mut [u8],
    store: &SeqStore,
    scratch: &mut Scratch,
    prev: &Entropy,
    next: &mut Entropy,
    rep: &mut [u32; 3],
    params: &CParams,
) -> Option<usize> {
    let strategy = params.strategy;
    let literals = store.literals();
    let nb_seq = store.seqs.len();
    // Base suspicion of uncompressibility on the ratio of literals to
    // sequences.
    let suspect = nb_seq == 0 || literals.len() / nb_seq >= 20;
    let mut op = compress_literals(
        dst,
        literals,
        &prev.huf,
        &mut next.huf,
        strategy,
        params.literals_compression_disabled(),
        suspect,
    )?;

    // Sequences header.
    let header = dst.get_mut(op..op + 4)?;
    if nb_seq < 128 {
        header[0] = nb_seq as u8;
        op += 1;
    } else if nb_seq < LONG_NB_SEQ {
        header[0] = ((nb_seq >> 8) + 0x80) as u8;
        header[1] = nb_seq as u8;
        op += 2;
    } else {
        header[0] = 0xFF;
        header[1..3].copy_from_slice(&((nb_seq - LONG_NB_SEQ) as u16).to_le_bytes());
        op += 3;
    }
    if nb_seq == 0 {
        // Copy the old tables over as if they were repeated.
        next.ll.clone_from(&prev.ll);
        next.of.clone_from(&prev.of);
        next.ml.clone_from(&prev.ml);
        return Some(op);
    }
    let seq_head = op;
    op += 1;

    // ZSTD_seqToCodes()
    scratch.values.resize(nb_seq, (0, 0, 0));
    scratch.ll_codes.resize(nb_seq, 0);
    scratch.ml_codes.resize(nb_seq, 0);
    scratch.of_codes.resize(nb_seq, 0);
    let (values, ll_codes, ml_codes, of_codes) = (
        &mut scratch.values[..nb_seq],
        &mut scratch.ll_codes[..nb_seq],
        &mut scratch.ml_codes[..nb_seq],
        &mut scratch.of_codes[..nb_seq],
    );
    let mut reps = *rep;
    for (i, seq) in store.seqs.iter().enumerate() {
        let off_base = off_base(&mut reps, seq.offset, seq.lit_len == 0);
        let ml_base = seq.match_len - MIN_MATCH;
        values[i] = (seq.lit_len, ml_base, off_base);
        ll_codes[i] = ll_code(seq.lit_len);
        ml_codes[i] = ml_code(ml_base);
        of_codes[i] = highbit32(off_base) as u8;
    }
    *rep = reps;

    // ZSTD_buildSequencesStatistics()
    let mut last_count_size = 0;
    let mut types = [EncodingType::Basic; 3];
    let kinds = [
        (
            &scratch.ll_codes,
            &prev.ll,
            &mut next.ll,
            MAX_LL,
            LL_FSE_LOG,
            &LL_DEFAULT_NORM[..],
            LL_DEFAULT_NORM_LOG,
        ),
        (
            &scratch.of_codes,
            &prev.of,
            &mut next.of,
            MAX_OFF,
            OFF_FSE_LOG,
            &OF_DEFAULT_NORM[..],
            OF_DEFAULT_NORM_LOG,
        ),
        (
            &scratch.ml_codes,
            &prev.ml,
            &mut next.ml,
            MAX_ML,
            ML_FSE_LOG,
            &ML_DEFAULT_NORM[..],
            ML_DEFAULT_NORM_LOG,
        ),
    ];
    for (kind, (codes, prev, next, max, fse_log, default_norm, default_log)) in
        IntoIterator::into_iter(kinds).enumerate()
    {
        let mut count = [0u32; MAX_ML as usize + 1];
        let mut max = max;
        let most_frequent = fse::histogram(&mut count[..=max as usize], &mut max, codes);
        let count = &mut count[..=max as usize];
        // Offset codes above the predefined table's need their own table.
        let default_allowed = max < default_norm.len() as u32;
        next.reusable = prev.reusable;
        let kind_type = select_encoding_type(
            &mut next.reusable,
            count,
            most_frequent as usize,
            nb_seq,
            fse_log,
            &prev.table,
            default_norm,
            default_log,
            default_allowed,
            strategy,
        );
        let count_size = match kind_type {
            EncodingType::Rle => {
                next.table.build_rle(max as u8);
                *dst.get_mut(op)? = codes[0];
                1
            }
            EncodingType::Repeat => {
                next.table.clone_from(&prev.table);
                0
            }
            EncodingType::Basic => {
                next.table.build(default_norm, default_log);
                0
            }
            EncodingType::Compressed => {
                // The last symbol is the initial state: it costs no bits.
                let mut total = nb_seq;
                let log = fse::optimal_table_log(fse_log, nb_seq, max, 2);
                let last = codes[nb_seq - 1] as usize;
                if count[last] > 1 {
                    count[last] -= 1;
                    total -= 1;
                }
                let mut norm = [0i16; MAX_ML as usize + 1];
                let norm = &mut norm[..count.len()];
                fse::normalize_count(norm, log, count, total, total >= 2048)?;
                let size = fse::write_ncount(dst.get_mut(op..)?, norm, log)?;
                next.table.build(norm, log);
                last_count_size = size;
                size
            }
        };
        types[kind] = kind_type;
        op += count_size;
    }
    dst[seq_head] = ((types[0] as u8) << 6) + ((types[1] as u8) << 4) + ((types[2] as u8) << 2);

    let stream_size = encode_sequences(dst.get_mut(op..)?, scratch, next)?;
    // zstd 1.3.4 and earlier reject an FSE table description followed by a
    // bitstream shorter than four bytes in total: store the block raw.
    if last_count_size != 0 && last_count_size + stream_size < 4 {
        return None;
    }
    Some(op + stream_size)
}

/// `ZSTD_selectEncodingType()`.
#[allow(clippy::too_many_arguments)]
fn select_encoding_type(
    reusable: &mut bool,
    count: &[u32],
    most_frequent: usize,
    nb_seq: usize,
    fse_log: u32,
    prev_table: &FseCTable,
    default_norm: &[i16],
    default_log: u32,
    default_allowed: bool,
    strategy: Strategy,
) -> EncodingType {
    if most_frequent == nb_seq {
        *reusable = false;
        // Prefer set_basic over set_rle when there are 2 or fewer symbols,
        // since RLE uses 1 byte, but set_basic uses 5-6 bits per symbol.
        return if default_allowed && nb_seq <= 2 {
            EncodingType::Basic
        } else {
            EncodingType::Rle
        };
    }
    if strategy < Strategy::Lazy {
        if default_allowed {
            let mult = 10 - strategy as usize;
            let dynamic_fse_nb_seq_min = ((1usize << default_log) * mult) >> 3;
            if nb_seq < dynamic_fse_nb_seq_min || most_frequent < nb_seq >> (default_log - 1) {
                *reusable = false;
                return EncodingType::Basic;
            }
        }
    } else {
        let basic_cost = if default_allowed {
            cross_entropy_cost(default_norm, default_log, count)
        } else {
            usize::MAX
        };
        let repeat_cost = if *reusable {
            prev_table.bit_cost(count).unwrap_or(usize::MAX)
        } else {
            usize::MAX
        };
        let max = count.len() as u32 - 1;
        let ncount_cost = ncount_cost(count, max, nb_seq, fse_log).unwrap_or(usize::MAX >> 4);
        let compressed_cost = (ncount_cost << 3) + entropy_cost(count, nb_seq);
        if basic_cost <= repeat_cost && basic_cost <= compressed_cost {
            *reusable = false;
            return EncodingType::Basic;
        }
        if repeat_cost <= compressed_cost {
            return EncodingType::Repeat;
        }
    }
    *reusable = true;
    EncodingType::Compressed
}

/// `-log2(x / 256)` scaled by 256, for x in 0..256 (0 for x = 0).
#[rustfmt::skip]
const INVERSE_PROBABILITY_LOG256: [u32; 256] = [
    0, 2048, 1792, 1642, 1536, 1453, 1386, 1329, 1280, 1236, 1197, 1162,
    1130, 1100, 1073, 1047, 1024, 1001, 980, 960, 941, 923, 906, 889,
    874, 859, 844, 830, 817, 804, 791, 779, 768, 756, 745, 734,
    724, 714, 704, 694, 685, 676, 667, 658, 650, 642, 633, 626,
    618, 610, 603, 595, 588, 581, 574, 567, 561, 554, 548, 542,
    535, 529, 523, 517, 512, 506, 500, 495, 489, 484, 478, 473,
    468, 463, 458, 453, 448, 443, 438, 434, 429, 424, 420, 415,
    411, 407, 402, 398, 394, 390, 386, 382, 377, 373, 370, 366,
    362, 358, 354, 350, 347, 343, 339, 336, 332, 329, 325, 322,
    318, 315, 311, 308, 305, 302, 298, 295, 292, 289, 286, 282,
    279, 276, 273, 270, 267, 264, 261, 258, 256, 253, 250, 247,
    244, 241, 239, 236, 233, 230, 228, 225, 222, 220, 217, 215,
    212, 209, 207, 204, 202, 199, 197, 194, 192, 190, 187, 185,
    182, 180, 178, 175, 173, 171, 168, 166, 164, 162, 159, 157,
    155, 153, 151, 149, 146, 144, 142, 140, 138, 136, 134, 132,
    130, 128, 126, 123, 121, 119, 117, 115, 114, 112, 110, 108,
    106, 104, 102, 100, 98, 96, 94, 93, 91, 89, 87, 85,
    83, 82, 80, 78, 76, 74, 73, 71, 69, 67, 66, 64,
    62, 61, 59, 57, 55, 54, 52, 50, 49, 47, 46, 44,
    42, 41, 39, 37, 36, 34, 33, 31, 30, 28, 26, 25,
    23, 22, 20, 19, 17, 16, 14, 13, 11, 10, 8, 7,
    5, 4, 2, 1,
];

/// `ZSTD_NCountCost()`: the size in bytes of a new table's description.
fn ncount_cost(count: &[u32], max: u32, nb_seq: usize, fse_log: u32) -> Option<usize> {
    let mut buf = [0u8; 512];
    let mut norm = [0i16; MAX_ML as usize + 1];
    let norm = &mut norm[..count.len()];
    let log = fse::optimal_table_log(fse_log, nb_seq, max, 2);
    fse::normalize_count(norm, log, count, nb_seq, nb_seq >= 2048)?;
    fse::write_ncount(&mut buf, norm, log)
}

/// `ZSTD_entropyCost()`: the entropy bound in bits.
fn entropy_cost(count: &[u32], total: usize) -> usize {
    let mut cost = 0usize;
    for &c in count {
        let mut norm = (256 * c as usize) / total;
        if c != 0 && norm == 0 {
            norm = 1;
        }
        cost += c as usize * INVERSE_PROBABILITY_LOG256[norm] as usize;
    }
    cost >> 8
}

/// `ZSTD_crossEntropyCost()`: the cost in bits of `count` coded with the
/// distribution `norm`.
fn cross_entropy_cost(norm: &[i16], log: u32, count: &[u32]) -> usize {
    let shift = 8 - log;
    let mut cost = 0usize;
    for (&c, &n) in count.iter().zip(norm) {
        let norm_acc = if n != -1 { n as u32 } else { 1 };
        cost += c as usize * INVERSE_PROBABILITY_LOG256[(norm_acc << shift) as usize] as usize;
    }
    cost >> 8
}

/// `ZSTD_encodeSequences()`. Returns the bitstream size, or `None` if it
/// does not fit.
fn encode_sequences(dst: &mut [u8], scratch: &Scratch, tables: &Entropy) -> Option<usize> {
    let (ll, of, ml) = (&tables.ll.table, &tables.of.table, &tables.ml.table);
    let mut bits = BitStream::new(dst)?;
    let n = scratch.values.len();
    let last = n - 1;
    let (ll_codes, ml_codes, of_codes) = (
        &scratch.ll_codes[..n],
        &scratch.ml_codes[..n],
        &scratch.of_codes[..n],
    );
    // The last sequence's codes set the initial states.
    let mut ml_state = ml.start(ml_codes[last]);
    let mut of_state = of.start(of_codes[last]);
    let mut ll_state = ll.start(ll_codes[last]);
    let (lit_len, ml_base, off_base) = scratch.values[last];
    bits.add(
        u64::from(lit_len),
        u32::from(LL_BITS[ll_codes[last] as usize]),
    );
    bits.add(
        u64::from(ml_base),
        u32::from(ML_BITS[ml_codes[last] as usize]),
    );
    bits.add(u64::from(off_base), u32::from(of_codes[last]));
    bits.flush();
    for i in (0..last).rev() {
        let (llc, mlc, ofc) = (ll_codes[i], ml_codes[i], of_codes[i]);
        let ll_bits = u32::from(LL_BITS[llc as usize]);
        let ml_bits = u32::from(ML_BITS[mlc as usize]);
        let of_bits = u32::from(ofc);
        let (lit_len, ml_base, off_base) = scratch.values[i];
        of.encode(&mut bits, &mut of_state, ofc);
        ml.encode(&mut bits, &mut ml_state, mlc);
        ll.encode(&mut bits, &mut ll_state, llc);
        if of_bits + ml_bits + ll_bits >= 64 - 7 - (LL_FSE_LOG + ML_FSE_LOG + OFF_FSE_LOG) {
            bits.flush();
        }
        bits.add(u64::from(lit_len), ll_bits);
        bits.add(u64::from(ml_base), ml_bits);
        if of_bits + ml_bits + ll_bits > 56 {
            bits.flush();
        }
        bits.add(u64::from(off_base), of_bits);
        bits.flush();
    }
    ml.finish(&mut bits, ml_state);
    of.finish(&mut bits, of_state);
    ll.finish(&mut bits, ll_state);
    match bits.close() {
        0 => None,
        size => Some(size),
    }
}
