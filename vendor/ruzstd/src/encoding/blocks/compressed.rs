use alloc::vec::Vec;

use crate::{
    bit_io::BitWriter,
    encoding::frame_compressor::CompressState,
    encoding::{Matcher, Sequence},
    fse::fse_encoder::{build_table_from_data, FSETable, State},
    huff0::huff0_encoder,
};

/// A block of [`crate::common::BlockType::Compressed`]
pub fn compress_block<M: Matcher>(state: &mut CompressState<M>, output: &mut Vec<u8>) {
    let mut literals_vec = Vec::new();
    let mut sequences = Vec::new();
    state.matcher.start_matching(|seq| {
        match seq {
            Sequence::Literals { literals } => literals_vec.extend_from_slice(literals),
            Sequence::Triple {
                literals,
                offset,
                match_len,
            } => {
                literals_vec.extend_from_slice(literals);
                sequences.push(crate::blocks::sequence_section::Sequence {
                    ll: literals.len() as u32,
                    ml: match_len as u32,
                    of: (offset + 3) as u32, // TODO make use of the offset history
                });
            }
        }
    });

    // literals section

    let mut writer = BitWriter::from(output);
    if literals_vec.len() > 1024 {
        if let Some(table) =
            compress_literals(&literals_vec, state.last_huff_table.as_ref(), &mut writer)
        {
            state.last_huff_table.replace(table);
        }
    } else {
        raw_literals(&literals_vec, &mut writer);
    }

    // sequences section

    if sequences.is_empty() {
        writer.write_bits(0u8, 8);
    } else {
        encode_seqnum(sequences.len(), &mut writer);

        // Choose the tables
        // TODO store previously used tables
        let ll_mode = choose_table(
            state.fse_tables.ll_previous.as_ref(),
            &state.fse_tables.ll_default,
            sequences.iter().map(|seq| encode_literal_length(seq.ll).0),
            9,
        );
        let ml_mode = choose_table(
            state.fse_tables.ml_previous.as_ref(),
            &state.fse_tables.ml_default,
            sequences.iter().map(|seq| encode_match_len(seq.ml).0),
            9,
        );
        let of_mode = choose_table(
            state.fse_tables.of_previous.as_ref(),
            &state.fse_tables.of_default,
            sequences.iter().map(|seq| encode_offset(seq.of).0),
            8,
        );

        writer.write_bits(encode_fse_table_modes(&ll_mode, &ml_mode, &of_mode), 8);

        encode_table(&ll_mode, &mut writer);
        encode_table(&of_mode, &mut writer);
        encode_table(&ml_mode, &mut writer);

        encode_sequences(
            &sequences,
            &mut writer,
            ll_mode.as_ref(),
            ml_mode.as_ref(),
            of_mode.as_ref(),
        );

        if let FseTableMode::Encoded(table) = ll_mode {
            state.fse_tables.ll_previous = Some(table)
        }
        if let FseTableMode::Encoded(table) = ml_mode {
            state.fse_tables.ml_previous = Some(table)
        }
        if let FseTableMode::Encoded(table) = of_mode {
            state.fse_tables.of_previous = Some(table)
        }
    }
    writer.flush();
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
enum FseTableMode<'a> {
    Predefined(&'a FSETable),
    Encoded(FSETable),
    RepeateLast(&'a FSETable),
}

impl FseTableMode<'_> {
    pub fn as_ref(&self) -> &FSETable {
        match self {
            Self::Predefined(t) => t,
            Self::RepeateLast(t) => t,
            Self::Encoded(t) => t,
        }
    }
}

fn choose_table<'a>(
    previous: Option<&'a FSETable>,
    default_table: &'a FSETable,
    data: impl Iterator<Item = u8>,
    max_log: u8,
) -> FseTableMode<'a> {
    // TODO check if the new table is better than the predefined and previous table
    let use_new_table = true;
    let use_previous_table = false;
    if use_previous_table {
        FseTableMode::RepeateLast(previous.unwrap())
    } else if use_new_table {
        FseTableMode::Encoded(build_table_from_data(data, max_log, true))
    } else {
        FseTableMode::Predefined(default_table)
    }
}

fn encode_table(mode: &FseTableMode<'_>, writer: &mut BitWriter<&mut Vec<u8>>) {
    match mode {
        FseTableMode::Predefined(_) => {}
        FseTableMode::RepeateLast(_) => {}
        FseTableMode::Encoded(table) => table.write_table(writer),
    }
}

fn encode_fse_table_modes(
    ll_mode: &FseTableMode<'_>,
    ml_mode: &FseTableMode<'_>,
    of_mode: &FseTableMode<'_>,
) -> u8 {
    fn mode_to_bits(mode: &FseTableMode<'_>) -> u8 {
        match mode {
            FseTableMode::Predefined(_) => 0,
            FseTableMode::Encoded(_) => 2,
            FseTableMode::RepeateLast(_) => 3,
        }
    }
    mode_to_bits(ll_mode) << 6 | mode_to_bits(of_mode) << 4 | mode_to_bits(ml_mode) << 2
}

fn encode_sequences(
    sequences: &[crate::blocks::sequence_section::Sequence],
    writer: &mut BitWriter<&mut Vec<u8>>,
    ll_table: &FSETable,
    ml_table: &FSETable,
    of_table: &FSETable,
) {
    // Custom matchers can reach the legacy code-52 encoding defect. Preserve
    // that path's exact behavior; the archive matcher caps lengths at 65538.
    if writer.misaligned() != 0 || sequences.iter().any(|s| s.ml > 65538) {
        return encode_sequences_legacy(sequences, writer, ll_table, ml_table, of_table);
    }
    writer.with_aligned_vec(|output| {
        // Each sequence contributes at most 26 state bits and 16 + 16 + 31
        // extra bits. Final states, the end marker and the last store fit in
        // the remaining 24 bytes. Only initialized, bounds-checked storage is used.
        let mut bits = SequenceBits::new(output, sequences.len() * 12 + 24);
        let sequence = sequences[sequences.len() - 1];
        let (ll_code, ll_extra, ll_width) = encode_literal_length(sequence.ll);
        let (of_code, of_extra, of_width) = encode_offset(sequence.of);
        let (ml_code, ml_extra, ml_width) = encode_match_len(sequence.ml);
        let mut ll_state: &State = ll_table.start_state(ll_code);
        let mut ml_state: &State = ml_table.start_state(ml_code);
        let mut of_state: &State = of_table.start_state(of_code);
        bits.add(ll_extra as u64, ll_width);
        bits.flush();
        bits.add(
            ml_extra as u64 | (of_extra as u64) << ml_width,
            ml_width + of_width,
        );
        bits.flush();

        // Emit the same fields in reverse sequence order, grouping them into
        // two bounded accumulator writes instead of checking space per field.
        for sequence in sequences[..sequences.len() - 1].iter().rev() {
            let (ll_code, ll_extra, ll_width) = encode_literal_length(sequence.ll);
            let (of_code, of_extra, of_width) = encode_offset(sequence.of);
            let (ml_code, ml_extra, ml_width) = encode_match_len(sequence.ml);
            let of_next = of_table.next_state(of_code, of_state.index);
            let ml_next = ml_table.next_state(ml_code, ml_state.index);
            let ll_next = ll_table.next_state(ll_code, ll_state.index);
            let of_width_state = of_next.num_bits as usize;
            let ml_width_state = ml_next.num_bits as usize;
            let state_width = of_width_state + ml_width_state + ll_next.num_bits as usize;
            let state_bits = (of_state.index - of_next.baseline) as u64
                | ((ml_state.index - ml_next.baseline) as u64) << of_width_state
                | ((ll_state.index - ll_next.baseline) as u64) << (of_width_state + ml_width_state);
            bits.add(
                state_bits | (ll_extra as u64) << state_width,
                state_width + ll_width,
            );
            bits.flush();
            bits.add(
                ml_extra as u64 | (of_extra as u64) << ml_width,
                ml_width + of_width,
            );
            bits.flush();
            of_state = of_next;
            ml_state = ml_next;
            ll_state = ll_next;
        }
        bits.add(ml_state.index as u64, ml_table.table_size.ilog2() as usize);
        bits.add(of_state.index as u64, of_table.table_size.ilog2() as usize);
        bits.add(ll_state.index as u64, ll_table.table_size.ilog2() as usize);
        bits.finish();
    });
}

fn encode_sequences_legacy(
    sequences: &[crate::blocks::sequence_section::Sequence],
    writer: &mut BitWriter<&mut Vec<u8>>,
    ll_table: &FSETable,
    ml_table: &FSETable,
    of_table: &FSETable,
) {
    let sequence = sequences[sequences.len() - 1];
    let (ll_code, ll_add_bits, ll_num_bits) = encode_literal_length(sequence.ll);
    let (of_code, of_add_bits, of_num_bits) = encode_offset(sequence.of);
    let (ml_code, ml_add_bits, ml_num_bits) = encode_match_len(sequence.ml);
    let mut ll_state: &State = ll_table.start_state(ll_code);
    let mut ml_state: &State = ml_table.start_state(ml_code);
    let mut of_state: &State = of_table.start_state(of_code);

    writer.write_bits(ll_add_bits, ll_num_bits);
    writer.write_bits(ml_add_bits, ml_num_bits);
    writer.write_bits(of_add_bits, of_num_bits);

    // encode backwards so the decoder reads the first sequence first
    if sequences.len() > 1 {
        for sequence in (0..=sequences.len() - 2).rev() {
            let sequence = sequences[sequence];
            let (ll_code, ll_add_bits, ll_num_bits) = encode_literal_length(sequence.ll);
            let (of_code, of_add_bits, of_num_bits) = encode_offset(sequence.of);
            let (ml_code, ml_add_bits, ml_num_bits) = encode_match_len(sequence.ml);

            let of_next = of_table.next_state(of_code, of_state.index);
            let ml_next = ml_table.next_state(ml_code, ml_state.index);
            let ll_next = ll_table.next_state(ll_code, ll_state.index);
            let of_bits = of_next.num_bits as usize;
            let ml_bits = ml_next.num_bits as usize;
            // Table accuracy logs bound the combined fields to 8 + 9 + 9 bits.
            let bits = (of_state.index - of_next.baseline) as u64
                | ((ml_state.index - ml_next.baseline) as u64) << of_bits
                | ((ll_state.index - ll_next.baseline) as u64) << (of_bits + ml_bits);
            writer.write_bits(bits, of_bits + ml_bits + ll_next.num_bits as usize);
            of_state = of_next;
            ml_state = ml_next;
            ll_state = ll_next;

            writer.write_bits(ll_add_bits, ll_num_bits);
            writer.write_bits(ml_add_bits, ml_num_bits);
            writer.write_bits(of_add_bits, of_num_bits);
        }
    }
    writer.write_bits(ml_state.index as u64, ml_table.table_size.ilog2() as usize);
    writer.write_bits(of_state.index as u64, of_table.table_size.ilog2() as usize);
    writer.write_bits(ll_state.index as u64, ll_table.table_size.ilog2() as usize);

    let bits_to_fill = writer.misaligned();
    if bits_to_fill == 0 {
        writer.write_bits(1u32, 8);
    } else {
        writer.write_bits(1u32, bits_to_fill);
    }
}

struct SequenceBits<'a> {
    output: &'a mut Vec<u8>,
    position: usize,
    partial: u64,
    width: usize,
}

impl<'a> SequenceBits<'a> {
    fn new(output: &'a mut Vec<u8>, capacity: usize) -> Self {
        let position = output.len();
        output.resize(position + capacity, 0);
        Self {
            output,
            position,
            partial: 0,
            width: 0,
        }
    }

    #[inline(always)]
    fn add(&mut self, value: u64, width: usize) {
        debug_assert!(self.width + width < 64);
        debug_assert_eq!(value >> width, 0);
        self.partial |= value << self.width;
        self.width += width;
    }

    #[inline(always)]
    fn flush(&mut self) {
        self.output[self.position..self.position + 8].copy_from_slice(&self.partial.to_le_bytes());
        let bytes = self.width / 8;
        self.position += bytes;
        self.partial >>= bytes * 8;
        self.width &= 7;
    }

    fn finish(mut self) {
        self.add(1, 1);
        self.flush();
        self.output
            .truncate(self.position + usize::from(self.width != 0));
    }
}

fn encode_seqnum(seqnum: usize, writer: &mut BitWriter<impl AsMut<Vec<u8>>>) {
    const UPPER_LIMIT: usize = 0xFFFF + 0x7F00;
    match seqnum {
        1..=127 => writer.write_bits(seqnum as u32, 8),
        128..=0x7FFF => {
            let upper = ((seqnum >> 8) | 0x80) as u8;
            let lower = seqnum as u8;
            writer.write_bits(upper, 8);
            writer.write_bits(lower, 8);
        }
        0x8000..=UPPER_LIMIT => {
            let encode = seqnum - 0x7F00;
            let upper = (encode >> 8) as u8;
            let lower = encode as u8;
            writer.write_bits(255u8, 8);
            writer.write_bits(upper, 8);
            writer.write_bits(lower, 8);
        }
        _ => unreachable!(),
    }
}

fn encode_literal_length(len: u32) -> (u8, u32, usize) {
    match len {
        0..=15 => (len as u8, 0, 0),
        16..=17 => (16, len - 16, 1),
        18..=19 => (17, len - 18, 1),
        20..=21 => (18, len - 20, 1),
        22..=23 => (19, len - 22, 1),
        24..=27 => (20, len - 24, 2),
        28..=31 => (21, len - 28, 2),
        32..=39 => (22, len - 32, 3),
        40..=47 => (23, len - 40, 3),
        48..=63 => (24, len - 48, 4),
        64..=127 => (25, len - 64, 6),
        128..=255 => (26, len - 128, 7),
        256..=511 => (27, len - 256, 8),
        512..=1023 => (28, len - 512, 9),
        1024..=2047 => (29, len - 1024, 10),
        2048..=4095 => (30, len - 2048, 11),
        4096..=8191 => (31, len - 4096, 12),
        8192..=16383 => (32, len - 8192, 13),
        16384..=32767 => (33, len - 16384, 14),
        32768..=65535 => (34, len - 32768, 15),
        65536..=131071 => (35, len - 65536, 16),
        131072.. => unreachable!(),
    }
}

fn encode_match_len(len: u32) -> (u8, u32, usize) {
    match len {
        0..=2 => unreachable!(),
        3..=34 => (len as u8 - 3, 0, 0),
        35..=36 => (32, len - 35, 1),
        37..=38 => (33, len - 37, 1),
        39..=40 => (34, len - 39, 1),
        41..=42 => (35, len - 41, 1),
        43..=46 => (36, len - 43, 2),
        47..=50 => (37, len - 47, 2),
        51..=58 => (38, len - 51, 3),
        59..=66 => (39, len - 59, 3),
        67..=82 => (40, len - 67, 4),
        83..=98 => (41, len - 83, 4),
        99..=130 => (42, len - 99, 5),
        131..=258 => (43, len - 131, 7),
        259..=514 => (44, len - 259, 8),
        515..=1026 => (45, len - 515, 9),
        1027..=2050 => (46, len - 1027, 10),
        2051..=4098 => (47, len - 2051, 11),
        4099..=8194 => (48, len - 4099, 12),
        8195..=16386 => (49, len - 8195, 13),
        16387..=32770 => (50, len - 16387, 14),
        32771..=65538 => (51, len - 32771, 15),
        65539..=131074 => (52, len - 32771, 16),
        131075.. => unreachable!(),
    }
}

fn encode_offset(len: u32) -> (u8, u32, usize) {
    let log = len.ilog2();
    let lower = len & ((1 << log) - 1);
    (log as u8, lower, log as usize)
}

fn raw_literals(literals: &[u8], writer: &mut BitWriter<&mut Vec<u8>>) {
    writer.write_bits(0u8, 2);
    writer.write_bits(0b11u8, 2);
    writer.write_bits(literals.len() as u32, 20);
    writer.append_bytes(literals);
}

fn compress_literals(
    literals: &[u8],
    last_table: Option<&huff0_encoder::HuffmanTable>,
    writer: &mut BitWriter<&mut Vec<u8>>,
) -> Option<huff0_encoder::HuffmanTable> {
    let reset_idx = writer.index();

    let mut counts = [0usize; 256];
    for &symbol in literals {
        counts[symbol as usize] += 1;
    }
    let symbols = counts
        .iter()
        .rposition(|&count| count != 0)
        .map_or(0, |i| i + 1);
    let new_encoder_table = huff0_encoder::HuffmanTable::build_from_counts(&counts[..symbols]);

    let (encoder_table, new_table) = if let Some(_table) = last_table {
        if let Some(diff) = _table.can_encode(&new_encoder_table) {
            // TODO this is a very simple heuristic, maybe we should try to do better
            if diff > 5 {
                (&new_encoder_table, true)
            } else {
                (_table, false)
            }
        } else {
            (&new_encoder_table, true)
        }
    } else {
        (&new_encoder_table, true)
    };

    // Even without the header, table, jump table and stream padding, this
    // payload cannot beat raw literals. Avoid encoding it only to discard it.
    if encoder_table.encoded_bits(&counts) >= literals.len() * 8 {
        raw_literals(literals, writer);
        return None;
    }

    if new_table {
        writer.write_bits(2u8, 2); // compressed literals type
    } else {
        writer.write_bits(3u8, 2); // treeless compressed literals type
    }

    let (size_format, size_bits) = match literals.len() {
        0..6 => (0b00u8, 10),
        6..1024 => (0b01, 10),
        1024..16384 => (0b10, 14),
        16384..262144 => (0b11, 18),
        _ => unimplemented!("too many literals"),
    };

    writer.write_bits(size_format, 2);
    writer.write_bits(literals.len() as u32, size_bits);
    let size_index = writer.index();
    writer.write_bits(0u32, size_bits);
    let index_before = writer.index();
    let mut encoder = huff0_encoder::HuffmanEncoder::new(encoder_table, writer);
    if size_format == 0 {
        encoder.encode(literals, new_table)
    } else {
        encoder.encode4x(literals, new_table)
    };
    let encoded_len = (writer.index() - index_before) / 8;
    writer.change_bits(size_index, encoded_len as u64, size_bits);
    let total_len = (writer.index() - reset_idx) / 8;

    // If encoded len is bigger than the raw literals we are better off just writing the raw literals here
    if total_len >= literals.len() {
        writer.reset_to(reset_idx);
        raw_literals(literals, writer);
        None
    } else if new_table {
        Some(new_encoder_table)
    } else {
        None
    }
}

#[cfg(test)]
mod sequence_bits_tests {
    use super::*;
    use crate::blocks::sequence_section::Sequence;

    #[test]
    fn bounded_writer_matches_legacy_fields_and_marker() {
        for skewed in [false, true] {
            let table = |symbols: u8, rare: u8, log| {
                build_table_from_data(
                    (0..symbols).flat_map(|s| {
                        core::iter::repeat_n(s, if skewed && s != rare { 16 } else { 1 })
                    }),
                    log,
                    true,
                )
            };
            let ll = table(36, 35, 9);
            let ml = table(53, 51, 9);
            let of = table(32, 31, 8);
            if skewed {
                assert_eq!((ll.acc_log(), ml.acc_log(), of.acc_log()), (9, 9, 8));
            }
            let mut seed = 0x39128391u32;
            for count in [1, 2, 3, 7, 8, 31, 128, 4096] {
                for trial in 0..16 {
                    let mut seq = Vec::new();
                    for _ in 0..count {
                        seed ^= seed << 13;
                        seed ^= seed >> 17;
                        seed ^= seed << 5;
                        seq.push(Sequence {
                            ll: seed & 131071,
                            ml: 3 + (seed.rotate_left(11) % 65536),
                            of: seed.rotate_left(23).max(4),
                        });
                    }
                    seq[0] = Sequence {
                        ll: 131071,
                        ml: 65538,
                        of: u32::MAX,
                    };
                    // Also preserve legacy custom matcher behavior past code51.
                    if trial == 15 {
                        seq[0].ml = 131074;
                    }
                    let mut actual = alloc::vec![0xab; trial];
                    let mut expected = actual.clone();
                    let mut writer = BitWriter::from(&mut actual);
                    if trial == 14 {
                        writer.write_bits(1u8, 1);
                    }
                    encode_sequences(&seq, &mut writer, &ll, &ml, &of);
                    writer.flush();
                    let mut writer = BitWriter::from(&mut expected);
                    if trial == 14 {
                        writer.write_bits(1u8, 1);
                    }
                    encode_sequences_legacy(&seq, &mut writer, &ll, &ml, &of);
                    writer.flush();
                    assert_eq!(actual, expected, "count={count}, trial={trial}");
                }
            }
        }
    }
}
