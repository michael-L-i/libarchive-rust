use super::super::blocks::sequence_section::ModeType;
use super::super::blocks::sequence_section::SequencesHeader;
use super::decode_buffer::BlockTarget;
use super::scratch::FSEScratch;
use super::sequence_execution::{copy_far, copy_literals, copy_match, resolve_offset, Far};
use crate::bit_io::BitReaderReversed;
use crate::blocks::sequence_section::{
    MAX_LITERAL_LENGTH_CODE, MAX_MATCH_LENGTH_CODE, MAX_OFFSET_CODE,
};
use crate::common::MAX_BLOCK_SIZE;
use crate::decoding::errors::{
    DecodeSequenceError, DecompressBlockError, ExecuteSequencesError, FSEDecoderError,
};
use crate::fse::FSETable;

/// A decoding table entry for one sequence field (`ZSTD_seqSymbol`): the
/// value's base and extra bits, and the FSE transition to the next state,
/// packed so one load reads it.
#[derive(Clone, Copy, Default)]
pub(crate) struct SeqSymbol(u64);

impl SeqSymbol {
    fn new(base: u32, next: u16, state_bits: u8, extra_bits: u8) -> Self {
        SeqSymbol(
            u64::from(base)
                | u64::from(next) << 32
                | u64::from(state_bits) << 48
                | u64::from(extra_bits) << 56,
        )
    }

    #[inline(always)]
    fn base(self) -> u32 {
        self.0 as u32
    }

    #[inline(always)]
    fn next(self) -> usize {
        usize::from((self.0 >> 32) as u16)
    }

    #[inline(always)]
    fn state_bits(self) -> u8 {
        (self.0 >> 48) as u8
    }

    #[inline(always)]
    fn extra_bits(self) -> u8 {
        (self.0 >> 56) as u8
    }
}

/// The sequence tables. Accuracy logs are at most 9 for lengths and 8 for
/// offsets, so states are masked to the table sizes for free bounds checks.
pub(crate) struct SeqTables {
    ll: [SeqSymbol; 512],
    ml: [SeqSymbol; 512],
    of: [SeqSymbol; 256],
}

impl Default for SeqTables {
    fn default() -> Self {
        SeqTables {
            ll: [SeqSymbol::default(); 512],
            ml: [SeqSymbol::default(); 512],
            of: [SeqSymbol::default(); 256],
        }
    }
}

/// Fills `out` from an FSE table, or with the one entry of an RLE mode.
fn derive(table: &FSETable, rle: Option<u8>, lookup: fn(u8) -> (u32, u8), out: &mut [SeqSymbol]) {
    match rle {
        Some(code) => {
            let (base, extra_bits) = lookup(code);
            out[0] = SeqSymbol::new(base, 0, 0, extra_bits);
        }
        None => {
            for (symbol, entry) in out.iter_mut().zip(&table.decode) {
                let (base, extra_bits) = lookup(entry.symbol);
                // Tables have at most 512 states.
                let next = entry.base_line as u16;
                *symbol = SeqSymbol::new(base, next, entry.num_bits, extra_bits);
            }
        }
    }
}

/// An offset code's value base and extra bits. Tables and RLE modes only
/// hold codes up to [MAX_OFFSET_CODE].
fn lookup_of_code(code: u8) -> (u32, u8) {
    debug_assert!(code <= MAX_OFFSET_CODE);
    (1 << (code & 31), code)
}

/// Rebuilds the sequence tables from the FSE tables and RLE modes.
pub(crate) fn derive_tables(scratch: &mut FSEScratch) {
    derive(
        &scratch.literal_lengths,
        scratch.ll_rle,
        lookup_ll_code,
        &mut scratch.symbols.ll[..],
    );
    derive(
        &scratch.match_lengths,
        scratch.ml_rle,
        lookup_ml_code,
        &mut scratch.symbols.ml[..],
    );
    derive(
        &scratch.offsets,
        scratch.of_rle,
        lookup_of_code,
        &mut scratch.symbols.of[..],
    );
}

/// The first state of a table: none for an RLE mode.
fn init_state(
    table: &FSETable,
    rle: Option<u8>,
    br: &mut BitReaderReversed<'_>,
) -> Result<usize, FSEDecoderError> {
    if rle.is_some() {
        return Ok(0);
    }
    if table.accuracy_log == 0 {
        return Err(FSEDecoderError::TableIsUninitialized);
    }
    Ok(br.get_bits(table.accuracy_log) as usize)
}

/// Decodes the sequence section and executes each sequence as it is
/// decoded, after `ZSTD_decompressSequences_body`: the block is written into
/// `target` and its length returned, with how much of it counts towards the
/// dictionary limit. On error the history and the offsets are unchanged.
///
/// `literals` holds the literals section, `literals_len` bytes, followed by
/// [SLACK](super::decode_buffer::SLACK) readable bytes for chunked copies.
pub(crate) fn decode_sequences(
    section: &SequencesHeader,
    source: &[u8],
    scratch: &mut FSEScratch,
    literals: &[u8],
    literals_len: usize,
    offset_hist: &mut [u32; 3],
    target: BlockTarget<'_>,
) -> Result<(usize, u64), DecompressBlockError> {
    let bytes_read = maybe_update_fse_tables(section, source, scratch)?;

    vprintln!("Updating tables used {} bytes", bytes_read);

    let (mut br, [mut ll, mut of, mut ml]) = start_bit_stream(&source[bytes_read..], scratch)?;
    let tables = &*scratch.symbols;

    let BlockTarget {
        buf,
        start,
        segment,
        old,
        history,
        dict,
        dict_counter,
        window_size,
    } = target;
    let end = start + MAX_BLOCK_SIZE as usize;
    // Matches reaching back no further than `low` copy within the segment.
    let low = if history <= start - segment {
        start - history
    } else {
        segment
    };
    let far = Far {
        start,
        segment,
        old,
        history,
        dict,
        counter: dict_counter,
        window_size,
    };
    let mut op = start;
    let mut lit = 0;
    let mut offsets = *offset_hist;
    let mut uncounted = 0;
    let mut remaining = section.num_sequences;

    while remaining != 0 {
        remaining -= 1;
        let lls = tables.ll[ll & 511];
        let mls = tables.ml[ml & 511];
        let ofs = tables.of[of & 255];
        let [value, match_len, lit_len] = if remaining != 0 && br.has_fast_sequence() {
            // After a refill at least 56 bits are available: enough for all
            // fields unless the extra bits are long, which need a second.
            br.refill_sequence();
            let obits = br.read_sequence_bits(ofs.extra_bits());
            let ml_add = br.read_sequence_bits(mls.extra_bits());
            if ofs.extra_bits() + mls.extra_bits() + lls.extra_bits() > 30 {
                br.refill_sequence();
            }
            let ll_add = br.read_sequence_bits(lls.extra_bits());
            ll = lls.next() + br.read_sequence_bits(lls.state_bits()) as usize;
            ml = mls.next() + br.read_sequence_bits(mls.state_bits()) as usize;
            of = ofs.next() + br.read_sequence_bits(ofs.state_bits()) as usize;
            [
                ofs.base() + obits as u32,
                mls.base() + ml_add as u32,
                lls.base() + ll_add as u32,
            ]
        } else {
            let values;
            (br, [ll, ml, of], values) =
                decode_tail(br, [lls, mls, ofs], remaining == 0, [ll, ml, of])?;
            values
        };
        let (lit_len, match_len) = (lit_len as usize, match_len as usize);

        if lit_len > literals_len - lit {
            return Err(ExecuteSequencesError::NotEnoughBytesForSequence {
                wanted: lit + lit_len,
                have: literals_len,
            }
            .into());
        }
        if lit_len + match_len > end - op {
            return Err(DecompressBlockError::BlockTooLarge);
        }
        copy_literals(buf, op, literals, lit, lit_len);
        op += lit_len;
        lit += lit_len;

        let offset = resolve_offset(value, lit_len == 0, &mut offsets) as usize;
        // Zero falls through to `copy_far`, which rejects it.
        if offset.wrapping_sub(1) < op - low {
            copy_match(buf, op, offset, match_len);
        } else {
            uncounted += copy_far(buf, op, offset, match_len, &far, uncounted)?;
        }
        op += match_len;
    }

    let rest = literals_len - lit;
    if rest > end - op {
        return Err(DecompressBlockError::BlockTooLarge);
    }
    buf[op..op + rest].copy_from_slice(&literals[lit..literals_len]);
    op += rest;

    if br.bits_remaining() != 0 {
        return Err(if br.bits_remaining() < 0 {
            DecodeSequenceError::NotEnoughBytesForNumSequences
        } else {
            DecodeSequenceError::ExtraBits {
                bits_remaining: br.bits_remaining(),
            }
        }
        .into());
    }
    *offset_hist = offsets;
    let len = op - start;
    Ok((len, len as u64 - uncounted))
}

/// Skips the bit stream's padding and reads the initial LL, OF and ML states.
/// The reader is returned by value, so the caller's copy can stay in registers.
#[inline(never)]
fn start_bit_stream<'s>(
    bit_stream: &'s [u8],
    scratch: &FSEScratch,
) -> Result<(BitReaderReversed<'s>, [usize; 3]), DecodeSequenceError> {
    let mut br = BitReaderReversed::new(bit_stream);

    //skip the 0 padding at the end of the last byte of the bit stream and throw away the first 1 found
    let mut skipped_bits = 0;
    loop {
        let val = br.get_bits(1);
        skipped_bits += 1;
        if val == 1 || skipped_bits > 8 {
            break;
        }
    }
    if skipped_bits > 8 {
        //if more than 7 bits are 0, this is not the correct end of the bitstream. Either a bug or corrupted data
        return Err(DecodeSequenceError::ExtraPadding { skipped_bits });
    }

    let ll = init_state(&scratch.literal_lengths, scratch.ll_rle, &mut br)?;
    let of = init_state(&scratch.offsets, scratch.of_rle, &mut br)?;
    let ml = init_state(&scratch.match_lengths, scratch.ml_rle, &mut br)?;
    Ok((br, [ll, of, ml]))
}

/// Decodes a sequence with the general bit reader, near the end of the
/// stream or for the last sequence, which keeps its states. Everything is
/// passed by value so the caller's state can stay in registers.
#[cold]
#[inline(never)]
fn decode_tail<'s>(
    mut br: BitReaderReversed<'s>,
    [lls, mls, ofs]: [SeqSymbol; 3],
    last: bool,
    mut states: [usize; 3],
) -> Result<(BitReaderReversed<'s>, [usize; 3], [u32; 3]), DecodeSequenceError> {
    let (obits, ml_add, ll_add) =
        br.get_bits_triple(ofs.extra_bits(), mls.extra_bits(), lls.extra_bits());
    if !last {
        states = [
            lls.next() + br.get_bits(lls.state_bits()) as usize,
            mls.next() + br.get_bits(mls.state_bits()) as usize,
            ofs.next() + br.get_bits(ofs.state_bits()) as usize,
        ];
    }
    if br.bits_remaining() < 0 {
        return Err(DecodeSequenceError::NotEnoughBytesForNumSequences);
    }
    let values = [
        ofs.base() + obits as u32,
        mls.base() + ml_add as u32,
        lls.base() + ll_add as u32,
    ];
    Ok((br, states, values))
}

/// Look up the provided state value from a literal length table predefined
/// by the Zstandard reference document. Returns a tuple of (value, number of bits).
///
/// <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#appendix-a---decoding-tables-for-predefined-codes>
fn lookup_ll_code(code: u8) -> (u32, u8) {
    match code {
        0..=15 => (u32::from(code), 0),
        16 => (16, 1),
        17 => (18, 1),
        18 => (20, 1),
        19 => (22, 1),
        20 => (24, 2),
        21 => (28, 2),
        22 => (32, 3),
        23 => (40, 3),
        24 => (48, 4),
        25 => (64, 6),
        26 => (128, 7),
        27 => (256, 8),
        28 => (512, 9),
        29 => (1024, 10),
        30 => (2048, 11),
        31 => (4096, 12),
        32 => (8192, 13),
        33 => (16384, 14),
        34 => (32768, 15),
        35 => (65536, 16),
        _ => unreachable!("Illegal literal length code was: {}", code),
    }
}

/// Look up the provided state value from a match length table predefined
/// by the Zstandard reference document. Returns a tuple of (value, number of bits).
///
/// <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#appendix-a---decoding-tables-for-predefined-codes>
fn lookup_ml_code(code: u8) -> (u32, u8) {
    match code {
        0..=31 => (u32::from(code) + 3, 0),
        32 => (35, 1),
        33 => (37, 1),
        34 => (39, 1),
        35 => (41, 1),
        36 => (43, 2),
        37 => (47, 2),
        38 => (51, 3),
        39 => (59, 3),
        40 => (67, 4),
        41 => (83, 4),
        42 => (99, 5),
        43 => (131, 7),
        44 => (259, 8),
        45 => (515, 9),
        46 => (1027, 10),
        47 => (2051, 11),
        48 => (4099, 12),
        49 => (8195, 13),
        50 => (16387, 14),
        51 => (32771, 15),
        52 => (65539, 16),
        _ => unreachable!("Illegal match length code was: {}", code),
    }
}

// This info is buried in the symbol compression mode table
/// "The maximum allowed accuracy log for literals length and match length tables is 9"
pub const LL_MAX_LOG: u8 = 9;
/// "The maximum allowed accuracy log for literals length and match length tables is 9"
pub const ML_MAX_LOG: u8 = 9;
/// "The maximum accuracy log for the offset table is 8."
pub const OF_MAX_LOG: u8 = 8;

fn maybe_update_fse_tables(
    section: &SequencesHeader,
    source: &[u8],
    scratch: &mut FSEScratch,
) -> Result<usize, DecodeSequenceError> {
    let modes = section
        .modes
        .ok_or(DecodeSequenceError::MissingCompressionMode)?;

    let mut bytes_read = 0;

    match modes.ll_mode() {
        ModeType::FSECompressed => {
            let bytes = scratch.literal_lengths.build_decoder(source, LL_MAX_LOG)?;
            bytes_read += bytes;

            vprintln!("Updating ll table");
            vprintln!("Used bytes: {}", bytes);
            scratch.ll_rle = None;
        }
        ModeType::RLE => {
            vprintln!("Use RLE ll table");
            if source.is_empty() {
                return Err(DecodeSequenceError::MissingByteForRleLlTable);
            }
            bytes_read += 1;
            if source[0] > MAX_LITERAL_LENGTH_CODE {
                return Err(DecodeSequenceError::MissingByteForRleMlTable);
            }
            scratch.ll_rle = Some(source[0]);
        }
        ModeType::Predefined => {
            vprintln!("Use predefined ll table");
            scratch.literal_lengths.build_from_probabilities(
                LL_DEFAULT_ACC_LOG,
                &LITERALS_LENGTH_DEFAULT_DISTRIBUTION,
            )?;
            scratch.ll_rle = None;
        }
        ModeType::Repeat => {
            vprintln!("Repeat ll table");
            /* Nothing to do */
        }
    };
    if !matches!(modes.ll_mode(), ModeType::Repeat) {
        derive(
            &scratch.literal_lengths,
            scratch.ll_rle,
            lookup_ll_code,
            &mut scratch.symbols.ll[..],
        );
    }

    let of_source = &source[bytes_read..];

    match modes.of_mode() {
        ModeType::FSECompressed => {
            let bytes = scratch.offsets.build_decoder(of_source, OF_MAX_LOG)?;
            vprintln!("Updating of table");
            vprintln!("Used bytes: {}", bytes);
            bytes_read += bytes;
            scratch.of_rle = None;
        }
        ModeType::RLE => {
            vprintln!("Use RLE of table");
            if of_source.is_empty() {
                return Err(DecodeSequenceError::MissingByteForRleOfTable);
            }
            bytes_read += 1;
            if of_source[0] > MAX_OFFSET_CODE {
                return Err(DecodeSequenceError::MissingByteForRleMlTable);
            }
            scratch.of_rle = Some(of_source[0]);
        }
        ModeType::Predefined => {
            vprintln!("Use predefined of table");
            scratch
                .offsets
                .build_from_probabilities(OF_DEFAULT_ACC_LOG, &OFFSET_DEFAULT_DISTRIBUTION)?;
            scratch.of_rle = None;
        }
        ModeType::Repeat => {
            vprintln!("Repeat of table");
            /* Nothing to do */
        }
    };
    if !matches!(modes.of_mode(), ModeType::Repeat) {
        derive(
            &scratch.offsets,
            scratch.of_rle,
            lookup_of_code,
            &mut scratch.symbols.of[..],
        );
    }

    let ml_source = &source[bytes_read..];

    match modes.ml_mode() {
        ModeType::FSECompressed => {
            let bytes = scratch.match_lengths.build_decoder(ml_source, ML_MAX_LOG)?;
            bytes_read += bytes;
            vprintln!("Updating ml table");
            vprintln!("Used bytes: {}", bytes);
            scratch.ml_rle = None;
        }
        ModeType::RLE => {
            vprintln!("Use RLE ml table");
            if ml_source.is_empty() {
                return Err(DecodeSequenceError::MissingByteForRleMlTable);
            }
            bytes_read += 1;
            if ml_source[0] > MAX_MATCH_LENGTH_CODE {
                return Err(DecodeSequenceError::MissingByteForRleMlTable);
            }
            scratch.ml_rle = Some(ml_source[0]);
        }
        ModeType::Predefined => {
            vprintln!("Use predefined ml table");
            scratch
                .match_lengths
                .build_from_probabilities(ML_DEFAULT_ACC_LOG, &MATCH_LENGTH_DEFAULT_DISTRIBUTION)?;
            scratch.ml_rle = None;
        }
        ModeType::Repeat => {
            vprintln!("Repeat ml table");
            /* Nothing to do */
        }
    };
    if !matches!(modes.ml_mode(), ModeType::Repeat) {
        derive(
            &scratch.match_lengths,
            scratch.ml_rle,
            lookup_ml_code,
            &mut scratch.symbols.ml[..],
        );
    }

    Ok(bytes_read)
}

// The default Literal Length decoding table uses an accuracy logarithm of 6 bits.
const LL_DEFAULT_ACC_LOG: u8 = 6;
/// If [ModeType::Predefined] is selected for a symbol type, its FSE decoding
/// table is generated using a predefined distribution table.
///
/// https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#literals-length
const LITERALS_LENGTH_DEFAULT_DISTRIBUTION: [i32; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];

// The default Match Length decoding table uses an accuracy logarithm of 6 bits.
const ML_DEFAULT_ACC_LOG: u8 = 6;
/// If [ModeType::Predefined] is selected for a symbol type, its FSE decoding
/// table is generated using a predefined distribution table.
///
/// https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#match-length
const MATCH_LENGTH_DEFAULT_DISTRIBUTION: [i32; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];

// The default Match Length decoding table uses an accuracy logarithm of 5 bits.
const OF_DEFAULT_ACC_LOG: u8 = 5;
/// If [ModeType::Predefined] is selected for a symbol type, its FSE decoding
/// table is generated using a predefined distribution table.
///
/// https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#match-length
const OFFSET_DEFAULT_DISTRIBUTION: [i32; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

#[test]
fn test_ll_default() {
    let mut table = crate::fse::FSETable::new(MAX_LITERAL_LENGTH_CODE);
    table
        .build_from_probabilities(LL_DEFAULT_ACC_LOG, &LITERALS_LENGTH_DEFAULT_DISTRIBUTION)
        .unwrap();

    #[cfg(feature = "std")]
    for idx in 0..table.decode.len() {
        std::println!(
            "{:3}: {:3} {:3} {:3}",
            idx,
            table.decode[idx].symbol,
            table.decode[idx].num_bits,
            table.decode[idx].base_line
        );
    }

    assert!(table.decode.len() == 64);

    //just test a few values. TODO test all values
    assert!(table.decode[0].symbol == 0);
    assert!(table.decode[0].num_bits == 4);
    assert!(table.decode[0].base_line == 0);

    assert!(table.decode[19].symbol == 27);
    assert!(table.decode[19].num_bits == 6);
    assert!(table.decode[19].base_line == 0);

    assert!(table.decode[39].symbol == 25);
    assert!(table.decode[39].num_bits == 4);
    assert!(table.decode[39].base_line == 16);

    assert!(table.decode[60].symbol == 35);
    assert!(table.decode[60].num_bits == 6);
    assert!(table.decode[60].base_line == 0);

    assert!(table.decode[59].symbol == 24);
    assert!(table.decode[59].num_bits == 5);
    assert!(table.decode[59].base_line == 32);
}
