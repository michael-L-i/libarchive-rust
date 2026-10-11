use super::super::blocks::sequence_section::ModeType;
use super::super::blocks::sequence_section::Sequence;
use super::super::blocks::sequence_section::SequencesHeader;
use super::scratch::FSEScratch;
use crate::bit_io::BitReaderReversed;
use crate::blocks::sequence_section::{
    MAX_LITERAL_LENGTH_CODE, MAX_MATCH_LENGTH_CODE, MAX_OFFSET_CODE,
};
use crate::decoding::errors::DecodeSequenceError;
use crate::fse::FSEDecoder;
use alloc::vec::Vec;

/// Decode the provided source as a series of sequences into the supplied `target`.
pub fn decode_sequences(
    section: &SequencesHeader,
    source: &[u8],
    scratch: &mut FSEScratch,
    target: &mut Vec<Sequence>,
) -> Result<(), DecodeSequenceError> {
    let bytes_read = maybe_update_fse_tables(section, source, scratch)?;

    vprintln!("Updating tables used {} bytes", bytes_read);

    let bit_stream = &source[bytes_read..];

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

    if scratch.ll_rle.is_some() || scratch.ml_rle.is_some() || scratch.of_rle.is_some() {
        decode_sequences_with_rle::<true>(section, &mut br, scratch, target)
    } else if (section.num_sequences as usize)
        < scratch.literal_lengths.decode.len() + scratch.match_lengths.decode.len()
    {
        // Small sequence counts don't amortize building both length tables.
        decode_sequences_with_rle::<false>(section, &mut br, scratch, target)
    } else {
        decode_sequences_without_rle(section, &mut br, scratch, target)
    }
}

fn decode_sequences_with_rle<const WITH_RLE: bool>(
    section: &SequencesHeader,
    br: &mut BitReaderReversed<'_>,
    scratch: &FSEScratch,
    target: &mut Vec<Sequence>,
) -> Result<(), DecodeSequenceError> {
    let ll_rle = if WITH_RLE { scratch.ll_rle } else { None };
    let ml_rle = if WITH_RLE { scratch.ml_rle } else { None };
    let of_rle = if WITH_RLE { scratch.of_rle } else { None };

    let mut ll_dec = FSEDecoder::new(&scratch.literal_lengths);
    let mut ml_dec = FSEDecoder::new(&scratch.match_lengths);
    let mut of_dec = FSEDecoder::new(&scratch.offsets);

    if ll_rle.is_none() {
        ll_dec.init_state(br)?;
    }
    if of_rle.is_none() {
        of_dec.init_state(br)?;
    }
    if ml_rle.is_none() {
        ml_dec.init_state(br)?;
    }

    target.clear();
    target.reserve(section.num_sequences as usize);

    for _seq_idx in 0..section.num_sequences {
        //get the codes from either the RLE byte or from the decoder
        let ll_code = if let Some(ll_rle) = ll_rle {
            ll_rle
        } else {
            ll_dec.decode_symbol()
        };
        let ml_code = if let Some(ml_rle) = ml_rle {
            ml_rle
        } else {
            ml_dec.decode_symbol()
        };
        let of_code = if let Some(of_rle) = of_rle {
            of_rle
        } else {
            of_dec.decode_symbol()
        };

        let (ll_value, ll_num_bits) = lookup_ll_code(ll_code);
        let (ml_value, ml_num_bits) = lookup_ml_code(ml_code);

        //println!("Sequence: {}", i);
        //println!("of stat: {}", of_dec.state);
        //println!("of Code: {}", of_code);
        //println!("ll stat: {}", ll_dec.state);
        //println!("ll bits: {}", ll_num_bits);
        //println!("ll Code: {}", ll_value);
        //println!("ml stat: {}", ml_dec.state);
        //println!("ml bits: {}", ml_num_bits);
        //println!("ml Code: {}", ml_value);
        //println!("");

        if of_code > MAX_OFFSET_CODE {
            return Err(DecodeSequenceError::UnsupportedOffset {
                offset_code: of_code,
            });
        }

        let (obits, ml_add, ll_add) = br.get_bits_triple(of_code, ml_num_bits, ll_num_bits);
        let offset = obits as u32 + (1u32 << of_code);

        if offset == 0 {
            return Err(DecodeSequenceError::ZeroOffset);
        }

        target.push(Sequence {
            ll: ll_value + ll_add as u32,
            ml: ml_value + ml_add as u32,
            of: offset,
        });

        if target.len() < section.num_sequences as usize {
            //println!(
            //    "Bits left: {} ({} bytes)",
            //    br.bits_remaining(),
            //    br.bits_remaining() / 8,
            //);
            if ll_rle.is_none() {
                ll_dec.update_state(br);
            }
            if ml_rle.is_none() {
                ml_dec.update_state(br);
            }
            if of_rle.is_none() {
                of_dec.update_state(br);
            }
        }

        if br.bits_remaining() < 0 {
            return Err(DecodeSequenceError::NotEnoughBytesForNumSequences);
        }
    }

    if br.bits_remaining() > 0 {
        Err(DecodeSequenceError::ExtraBits {
            bits_remaining: br.bits_remaining(),
        })
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct LengthState {
    base: u32,
    next_base: u16,
    state_bits: u8,
    extra_bits: u8,
}

impl LengthState {
    fn new(entry: crate::fse::Entry, lookup: fn(u8) -> (u32, u8)) -> Self {
        let (base, extra_bits) = lookup(entry.symbol);
        debug_assert!(entry.base_line <= u32::from(u16::MAX));
        Self {
            base,
            // Sequence length FSE tables have at most 512 states.
            next_base: entry.base_line as u16,
            state_bits: entry.num_bits,
            extra_bits,
        }
    }
}

fn decode_sequences_without_rle(
    section: &SequencesHeader,
    br: &mut BitReaderReversed<'_>,
    scratch: &mut FSEScratch,
    target: &mut Vec<Sequence>,
) -> Result<(), DecodeSequenceError> {
    let mut ll_dec = FSEDecoder::new(&scratch.literal_lengths);
    let mut ml_dec = FSEDecoder::new(&scratch.match_lengths);
    let mut of_dec = FSEDecoder::new(&scratch.offsets);

    ll_dec.init_state(br)?;
    of_dec.init_state(br)?;
    ml_dec.init_state(br)?;

    scratch.ll_states.clear();
    scratch.ll_states.extend(
        scratch
            .literal_lengths
            .decode
            .iter()
            .copied()
            .map(|entry| LengthState::new(entry, lookup_ll_code)),
    );
    scratch.ml_states.clear();
    scratch.ml_states.extend(
        scratch
            .match_lengths
            .decode
            .iter()
            .copied()
            .map(|entry| LengthState::new(entry, lookup_ml_code)),
    );
    let mut ll_state = LengthState::new(ll_dec.state, lookup_ll_code);
    let mut ml_state = LengthState::new(ml_dec.state, lookup_ml_code);

    target.clear();
    target.reserve(section.num_sequences as usize);

    while target.len() + 1 < section.num_sequences as usize && br.has_fast_sequence() {
        let of_code = of_dec.decode_symbol();
        if of_code > MAX_OFFSET_CODE {
            return Err(DecodeSequenceError::UnsupportedOffset {
                offset_code: of_code,
            });
        }
        let extra_bits = of_code + ml_state.extra_bits + ll_state.extra_bits;
        let state_bits = ll_state.state_bits + ml_state.state_bits + of_dec.state.num_bits;
        br.refill_sequence();
        let [obits, ml_add, ll_add, ll_next, ml_next, of_next] = if extra_bits + state_bits <= 56 {
            br.read_sequence_fields([
                of_code,
                ml_state.extra_bits,
                ll_state.extra_bits,
                ll_state.state_bits,
                ml_state.state_bits,
                of_dec.state.num_bits,
            ])
        } else {
            let (obits, ml_add, ll_add) = if extra_bits <= 56 {
                let values = br.peek_bits_triple(
                    extra_bits,
                    of_code,
                    ml_state.extra_bits,
                    ll_state.extra_bits,
                );
                br.consume(extra_bits);
                values
            } else {
                let offset = br.read_sequence_bits(of_code);
                br.refill_sequence();
                (
                    offset,
                    br.read_sequence_bits(ml_state.extra_bits),
                    br.read_sequence_bits(ll_state.extra_bits),
                )
            };
            br.refill_sequence();
            [
                obits,
                ml_add,
                ll_add,
                br.read_sequence_bits(ll_state.state_bits),
                br.read_sequence_bits(ml_state.state_bits),
                br.read_sequence_bits(of_dec.state.num_bits),
            ]
        };
        target.push(Sequence {
            ll: ll_state.base + ll_add as u32,
            ml: ml_state.base + ml_add as u32,
            of: (1u32 << of_code) + obits as u32,
        });
        ll_state = scratch.ll_states[usize::from(ll_state.next_base) + ll_next as usize];
        ml_state = scratch.ml_states[usize::from(ml_state.next_base) + ml_next as usize];
        of_dec.state = scratch.offsets.decode[of_dec.state.base_line as usize + of_next as usize];
    }

    for _seq_idx in target.len()..section.num_sequences as usize {
        let of_code = of_dec.decode_symbol();
        let ll_value = ll_state.base;
        let ml_value = ml_state.base;
        let ll_num_bits = ll_state.extra_bits;
        let ml_num_bits = ml_state.extra_bits;

        if of_code > MAX_OFFSET_CODE {
            return Err(DecodeSequenceError::UnsupportedOffset {
                offset_code: of_code,
            });
        }

        let (obits, ml_add, ll_add) = br.get_bits_triple(of_code, ml_num_bits, ll_num_bits);
        let offset = obits as u32 + (1u32 << of_code);

        if offset == 0 {
            return Err(DecodeSequenceError::ZeroOffset);
        }

        target.push(Sequence {
            ll: ll_value + ll_add as u32,
            ml: ml_value + ml_add as u32,
            of: offset,
        });

        if target.len() < section.num_sequences as usize {
            //println!(
            //    "Bits left: {} ({} bytes)",
            //    br.bits_remaining(),
            //    br.bits_remaining() / 8,
            //);
            let ll_add = br.get_bits(ll_state.state_bits);
            ll_state = scratch.ll_states[usize::from(ll_state.next_base) + ll_add as usize];
            let ml_add = br.get_bits(ml_state.state_bits);
            ml_state = scratch.ml_states[usize::from(ml_state.next_base) + ml_add as usize];
            of_dec.update_state(br);
        }

        if br.bits_remaining() < 0 {
            return Err(DecodeSequenceError::NotEnoughBytesForNumSequences);
        }
    }

    if br.bits_remaining() > 0 {
        Err(DecodeSequenceError::ExtraBits {
            bits_remaining: br.bits_remaining(),
        })
    } else {
        Ok(())
    }
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
                &Vec::from(&LITERALS_LENGTH_DEFAULT_DISTRIBUTION[..]),
            )?;
            scratch.ll_rle = None;
        }
        ModeType::Repeat => {
            vprintln!("Repeat ll table");
            /* Nothing to do */
        }
    };

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
            scratch.offsets.build_from_probabilities(
                OF_DEFAULT_ACC_LOG,
                &Vec::from(&OFFSET_DEFAULT_DISTRIBUTION[..]),
            )?;
            scratch.of_rle = None;
        }
        ModeType::Repeat => {
            vprintln!("Repeat of table");
            /* Nothing to do */
        }
    };

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
            scratch.match_lengths.build_from_probabilities(
                ML_DEFAULT_ACC_LOG,
                &Vec::from(&MATCH_LENGTH_DEFAULT_DISTRIBUTION[..]),
            )?;
            scratch.ml_rle = None;
        }
        ModeType::Repeat => {
            vprintln!("Repeat ml table");
            /* Nothing to do */
        }
    };

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
        .build_from_probabilities(
            LL_DEFAULT_ACC_LOG,
            &Vec::from(&LITERALS_LENGTH_DEFAULT_DISTRIBUTION[..]),
        )
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

#[test]
fn guarded_sequence_decoder_matches_general_states_and_errors() {
    for layout in 0..3 {
        let mut scratch = FSEScratch::new();
        let (mut ll, mut ml, mut of) = (
            Vec::from(LITERALS_LENGTH_DEFAULT_DISTRIBUTION),
            Vec::from(MATCH_LENGTH_DEFAULT_DISTRIBUTION),
            Vec::from(OFFSET_DEFAULT_DISTRIBUTION),
        );
        if layout != 0 {
            ll.fill(0);
            ml.fill(0);
            of.resize(32, 0);
            of.fill(0);
            ll[if layout == 1 { 35 } else { 0 }] = 64;
            ml[if layout == 1 { 52 } else { 0 }] = 64;
            of[if layout == 1 { 31 } else { 0 }] = 32;
        }
        scratch
            .literal_lengths
            .build_from_probabilities(6, &ll)
            .unwrap();
        scratch
            .match_lengths
            .build_from_probabilities(6, &ml)
            .unwrap();
        scratch.offsets.build_from_probabilities(5, &of).unwrap();
        for len in (0..80).chain([96, 128, 257]) {
            for seed in 0..8 {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i * 73 + seed * 41 + len * 17) as u8)
                    .collect();
                for num_sequences in [1, 128, 512] {
                    let section = SequencesHeader {
                        num_sequences,
                        modes: None,
                    };
                    let mut fast_reader = BitReaderReversed::new(&data);
                    let mut general_reader = BitReaderReversed::new(&data);
                    fast_reader.get_bits(seed as u8);
                    general_reader.get_bits(seed as u8);
                    let mut fast = Vec::new();
                    let mut general = Vec::new();
                    let result = decode_sequences_without_rle(
                        &section,
                        &mut fast_reader,
                        &mut scratch,
                        &mut fast,
                    );
                    let expected = decode_sequences_with_rle::<false>(
                        &section,
                        &mut general_reader,
                        &scratch,
                        &mut general,
                    );
                    assert_eq!(alloc::format!("{result:?}"), alloc::format!("{expected:?}"));
                    assert_eq!(
                        fast_reader.bits_remaining(),
                        general_reader.bits_remaining()
                    );
                    assert_eq!(fast.len(), general.len());
                    for (a, b) in fast.iter().zip(&general) {
                        assert_eq!((a.ll, a.ml, a.of), (b.ll, b.ml, b.of));
                    }
                }
            }
        }
    }
}
