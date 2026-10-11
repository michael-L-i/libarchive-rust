//! This module contains the decompress_literals function, used to take a
//! parsed literals header and a source and decompress it.

use super::super::blocks::literals_section::{LiteralsSection, LiteralsSectionType};
use super::scratch::HuffmanScratch;
use crate::bit_io::BitReaderReversed;
use crate::decoding::errors::DecompressLiteralsError;
use crate::huff0::{HuffmanDecoder, HuffmanTable};

use alloc::vec::Vec;
use core::convert::TryInto;

const FAST_MAX_REGEN: usize = 128 * 1024;

/// Decode and decompress the provided literals section into `target`, returning the number of bytes read.
pub fn decode_literals(
    section: &LiteralsSection,
    scratch: &mut HuffmanScratch,
    source: &[u8],
    target: &mut Vec<u8>,
) -> Result<u32, DecompressLiteralsError> {
    match section.ls_type {
        LiteralsSectionType::Raw => {
            target.extend(&source[0..section.regenerated_size as usize]);
            Ok(section.regenerated_size)
        }
        LiteralsSectionType::RLE => {
            target.resize(target.len() + section.regenerated_size as usize, source[0]);
            Ok(1)
        }
        LiteralsSectionType::Compressed | LiteralsSectionType::Treeless => {
            let bytes_read = decompress_literals::<false>(section, scratch, source, target)?;

            //return sum of used bytes
            Ok(bytes_read)
        }
    }
}

/// Decompress the provided literals section and source into the provided `target`.
/// This function is used when the literals section is `Compressed` or `Treeless`
///
/// Returns the number of bytes read.
fn decompress_literals<const FORCE_SERIAL: bool>(
    section: &LiteralsSection,
    scratch: &mut HuffmanScratch,
    source: &[u8],
    target: &mut Vec<u8>,
) -> Result<u32, DecompressLiteralsError> {
    use DecompressLiteralsError as err;

    let compressed_size = section.compressed_size.ok_or(err::MissingCompressedSize)? as usize;
    let num_streams = section.num_streams.ok_or(err::MissingNumStreams)?;

    target.reserve(section.regenerated_size as usize);
    let source = &source[0..compressed_size];
    let mut bytes_read = 0;

    match section.ls_type {
        LiteralsSectionType::Compressed => {
            //read Huffman tree description
            bytes_read += scratch.table.build_decoder(source)?;
            vprintln!("Built huffman table using {} bytes", bytes_read);
        }
        LiteralsSectionType::Treeless if scratch.table.max_num_bits == 0 => {
            return Err(err::UninitializedHuffmanTable);
        }

        _ => { /* nothing to do, huffman tree has been provided by previous block */ }
    }

    let source = &source[bytes_read as usize..];

    if num_streams == 4 {
        //build jumptable
        if source.len() < 6 {
            return Err(err::MissingBytesForJumpHeader { got: source.len() });
        }
        let jump1 = source[0] as usize + ((source[1] as usize) << 8);
        let jump2 = jump1 + source[2] as usize + ((source[3] as usize) << 8);
        let jump3 = jump2 + source[4] as usize + ((source[5] as usize) << 8);
        bytes_read += 6;
        let source = &source[6..];

        if source.len() < jump3 {
            return Err(err::MissingBytesForLiterals {
                got: source.len(),
                needed: jump3,
            });
        }

        //decode 4 streams
        let stream1 = &source[..jump1];
        let stream2 = &source[jump1..jump2];
        let stream3 = &source[jump2..jump3];
        let stream4 = &source[jump3..];

        let streams = [stream1, stream2, stream3, stream4];
        if FORCE_SERIAL
            || !decode_4_fast(
                &scratch.table,
                &streams,
                section.regenerated_size as usize,
                target,
            )
        {
            for stream in &[stream1, stream2, stream3, stream4] {
                let mut decoder = HuffmanDecoder::new(&scratch.table);
                let mut br = BitReaderReversed::new(stream);
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
                    return Err(DecompressLiteralsError::ExtraPadding { skipped_bits });
                }
                decoder.init_state(&mut br);

                while br.bits_remaining() > -(scratch.table.max_num_bits as isize) {
                    target.push(decoder.decode_symbol());
                    decoder.next_state(&mut br);
                }
                if br.bits_remaining() != -(scratch.table.max_num_bits as isize) {
                    return Err(DecompressLiteralsError::BitstreamReadMismatch {
                        read_til: br.bits_remaining(),
                        expected: -(scratch.table.max_num_bits as isize),
                    });
                }
            }
        }

        bytes_read += source.len() as u32;
    } else {
        //just decode the one stream
        assert!(num_streams == 1);
        let mut decoder = HuffmanDecoder::new(&scratch.table);
        let mut br = BitReaderReversed::new(source);
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
            return Err(DecompressLiteralsError::ExtraPadding { skipped_bits });
        }
        decoder.init_state(&mut br);
        while br.bits_remaining() > -(scratch.table.max_num_bits as isize) {
            target.push(decoder.decode_symbol());
            decoder.next_state(&mut br);
        }
        bytes_read += source.len() as u32;
    }

    if target.len() != section.regenerated_size as usize {
        return Err(DecompressLiteralsError::DecodedLiteralCountMismatch {
            decoded: target.len(),
            expected: section.regenerated_size as usize,
        });
    }

    Ok(bytes_read)
}

/// Skips a stream's padding exactly as in the serial path; None on bad padding.
fn skip_padding(stream: &[u8]) -> Option<BitReaderReversed<'_>> {
    let mut br = BitReaderReversed::new(stream);
    let mut skipped = 0u32;
    loop {
        let v = br.get_bits(1);
        skipped += 1;
        if v == 1 || skipped > 8 {
            break;
        }
    }
    (skipped <= 8).then_some(br)
}

struct Lane<'t, 's> {
    dec: HuffmanDecoder<'t>,
    br: BitReaderReversed<'s>,
}

impl<'t, 's> Lane<'t, 's> {
    /// The initial state, read after the padding.
    fn new(table: &'t HuffmanTable, mut br: BitReaderReversed<'s>) -> Self {
        let mut dec = HuffmanDecoder::new(table);
        dec.init_state(&mut br);
        Lane { dec, br }
    }

    #[inline(always)]
    fn step(&mut self, out: &mut u8) {
        *out = self.dec.decode_symbol();
        self.dec.next_state(&mut self.br);
    }

    /// The last symbol of a lane. Checks the serial loop condition before
    /// it and the serial terminal condition after it.
    #[inline(always)]
    fn finish(&mut self, out: &mut u8, neg_max: isize) -> bool {
        if self.br.bits_remaining() <= neg_max {
            return false;
        }
        self.step(out);
        self.br.bits_remaining() == neg_max
    }
}

/// Speculative canonical-layout decode. On `false`, `target` is empty again.
/// It never produces an error.
fn decode_4_fast(
    table: &HuffmanTable,
    streams: &[&[u8]; 4],
    regen: usize,
    target: &mut Vec<u8>,
) -> bool {
    if !target.is_empty()
        || regen == 0
        || regen > FAST_MAX_REGEN
        || streams.iter().any(|stream| stream.len() > FAST_MAX_REGEN)
        || !table.fast_decode_ok()
    {
        return false;
    }
    let chunk = regen.div_ceil(4);
    let last = match regen.checked_sub(3 * chunk) {
        Some(n) if n > 0 => n,
        _ => return false, // irregular/tiny: let serial handle it
    };
    let (Some(r0), Some(r1), Some(r2), Some(r3)) = (
        skip_padding(streams[0]),
        skip_padding(streams[1]),
        skip_padding(streams[2]),
        skip_padding(streams[3]),
    ) else {
        return false; // target untouched
    };
    let mut readers = [r0, r1, r2, r3];

    target.resize(regen, 0); // within the earlier reserve(regen)
    let (o0, rest) = target.split_at_mut(chunk);
    let (o1, rest) = rest.split_at_mut(chunk);
    let (o2, o3) = rest.split_at_mut(chunk);
    let (n4, n3) = (last - 1, chunk - 1);
    let done = decode_words(table, streams, &mut readers, [o0, o1, o2, o3], n4);
    let [r0, r1, r2, r3] = readers;
    let (mut l0, mut l1, mut l2, mut l3) = (
        Lane::new(table, r0),
        Lane::new(table, r1),
        Lane::new(table, r2),
        Lane::new(table, r3),
    );

    // Four independent dependency chains per iteration.
    for (((a, b), c), d) in o0[done..n4]
        .iter_mut()
        .zip(o1[done..n4].iter_mut())
        .zip(o2[done..n4].iter_mut())
        .zip(o3[done..n4].iter_mut())
    {
        l0.step(a);
        l1.step(b);
        l2.step(c);
        l3.step(d);
    }
    for ((a, b), c) in o0[n4..n3]
        .iter_mut()
        .zip(o1[n4..n3].iter_mut())
        .zip(o2[n4..n3].iter_mut())
    {
        l0.step(a);
        l1.step(b);
        l2.step(c);
    }

    let m = -(table.max_num_bits as isize);
    let ok = l0.finish(&mut o0[n3], m)
        && l1.finish(&mut o1[n3], m)
        && l2.finish(&mut o2[n3], m)
        && l3.finish(&mut o3[n4], m);
    if !ok {
        target.clear();
    }
    ok
}

/// Decodes the start of the four lanes a word at a time, after libzstd's
/// `HUF_decompress4X1_usingDTable_internal_fast_c_loop`: the next 11 bits
/// index a table, and each lane reloads a whole word after five symbols, at
/// most 55 bits. A word loaded after consuming at most 7 bits of its first
/// byte holds 56, so every lane runs while its word starts at least 7 bytes
/// into its stream. Decodes the same number of symbols, a multiple of five
/// and at most `limit`, into each output, returns it and leaves the readers
/// after them; the symbols are those the serial decoder would produce.
fn decode_words<'s>(
    table: &HuffmanTable,
    streams: &[&'s [u8]; 4],
    readers: &mut [BitReaderReversed<'s>; 4],
    [o0, o1, o2, o3]: [&mut [u8]; 4],
    limit: usize,
) -> usize {
    const SYMBOLS: usize = 5;
    let (Some(w0), Some(w1), Some(w2), Some(w3)) = (
        readers[0].to_word(),
        readers[1].to_word(),
        readers[2].to_word(),
        readers[3].to_word(),
    ) else {
        return 0;
    };
    let mut words = [w0, w1, w2, w3];
    let lookup = table.word_table();
    let mut done = 0;
    for (((a, b), c), d) in o0[..limit]
        .chunks_exact_mut(SYMBOLS)
        .zip(o1[..limit].chunks_exact_mut(SYMBOLS))
        .zip(o2[..limit].chunks_exact_mut(SYMBOLS))
        .zip(o3[..limit].chunks_exact_mut(SYMBOLS))
    {
        if words.iter().any(|&(index, _)| index < 7) {
            break;
        }
        for i in 0..SYMBOLS {
            a[i] = word_symbol(&lookup, &mut words[0].1);
            b[i] = word_symbol(&lookup, &mut words[1].1);
            c[i] = word_symbol(&lookup, &mut words[2].1);
            d[i] = word_symbol(&lookup, &mut words[3].1);
        }
        for ((index, word), stream) in words.iter_mut().zip(streams) {
            let consumed = word.trailing_zeros();
            *index -= (consumed >> 3) as usize;
            let next = u64::from_le_bytes(stream[*index..*index + 8].try_into().unwrap());
            *word = (next | 1) << (consumed & 7);
        }
        done += SYMBOLS;
    }
    for ((reader, (index, word)), stream) in readers.iter_mut().zip(words).zip(streams) {
        *reader = BitReaderReversed::from_word(stream, index, word);
    }
    done
}

/// Decodes the symbol at the top of `word` and shifts its code out.
#[inline(always)]
fn word_symbol(lookup: &[u16; 1 << 11], word: &mut u64) -> u8 {
    let entry = lookup[(*word >> 53) as usize];
    *word <<= entry & 63;
    (entry >> 8) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bit_io::BitWriter;
    use crate::huff0::huff0_encoder::{HuffmanEncoder, HuffmanTable as EncoderTable};
    use alloc::{format, vec};

    fn encode(parts: [&[u8]; 4]) -> (HuffmanTable, Vec<u8>, Vec<u8>) {
        let data = parts.concat();
        let table = EncoderTable::build_from_data(&data);
        let mut writer = BitWriter::new();
        HuffmanEncoder::new(&table, &mut writer).encode(&data, true);
        let encoded = writer.dump();
        let mut decoder = HuffmanTable::new();
        let table_bytes = decoder.build_decoder(&encoded).unwrap() as usize;
        let mut streams = Vec::new();
        for part in parts {
            let mut writer = BitWriter::new();
            HuffmanEncoder::new(&table, &mut writer).encode(part, false);
            streams.push(writer.dump());
        }
        let mut body = Vec::new();
        for stream in &streams[..3] {
            body.extend_from_slice(&(stream.len() as u16).to_le_bytes());
        }
        for stream in streams {
            body.extend_from_slice(&stream);
        }
        (decoder, body, encoded[..table_bytes].to_vec())
    }

    fn streams(body: &[u8]) -> [&[u8]; 4] {
        let first = u16::from_le_bytes([body[0], body[1]]) as usize;
        let second = first + u16::from_le_bytes([body[2], body[3]]) as usize;
        let third = second + u16::from_le_bytes([body[4], body[5]]) as usize;
        let data = &body[6..];
        [
            &data[..first],
            &data[first..second],
            &data[second..third],
            &data[third..],
        ]
    }

    fn compare(table: Option<&HuffmanTable>, body: &[u8], size: usize, prefix: &[u8]) -> Vec<u8> {
        let section = LiteralsSection {
            ls_type: if table.is_some() {
                LiteralsSectionType::Treeless
            } else {
                LiteralsSectionType::Compressed
            },
            regenerated_size: size as u32,
            compressed_size: Some(body.len() as u32),
            num_streams: Some(4),
        };
        let mut fast = HuffmanScratch::new();
        if let Some(table) = table {
            fast.table.reinit_from(table);
        }
        let mut serial = HuffmanScratch::new();
        if let Some(table) = table {
            serial.table.reinit_from(table);
        }
        let mut actual = prefix.to_vec();
        let mut expected = prefix.to_vec();
        let a = decompress_literals::<false>(&section, &mut fast, body, &mut actual);
        let b = decompress_literals::<true>(&section, &mut serial, body, &mut expected);
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
        assert_eq!(actual, expected);
        assert_eq!(actual.capacity(), expected.capacity());
        actual
    }

    #[test]
    fn four_lane_literals_match_serial_and_preserve_errors() {
        for size in [12usize, 31, 32, 33, 64, 127, 256, 257, 1024, 4096, 131072] {
            let data: Vec<_> = (0..size)
                .map(|i| {
                    if i % 5 == 0 {
                        (i * 37) as u8
                    } else {
                        (i % 7) as u8
                    }
                })
                .collect();
            let chunk = size.div_ceil(4);
            let (table, body, description) = encode([
                &data[..chunk],
                &data[chunk..chunk * 2],
                &data[chunk * 2..chunk * 3],
                &data[chunk * 3..],
            ]);
            let mut output = Vec::new();
            assert!(decode_4_fast(&table, &streams(&body), size, &mut output));
            assert_eq!(output, data);
            assert_eq!(compare(Some(&table), &body, size, &[]), data);
            let mut compressed = description;
            compressed.extend_from_slice(&body);
            assert_eq!(compare(None, &compressed, size, &[]), data);
            compare(None, &compressed[..1], size, &[]);
            for expected in [size - 1, size, size + 1] {
                for prefix in [&[][..], &[91, 92][..]] {
                    compare(Some(&table), &body, expected, prefix);
                }
            }
            for cut in [0, 5, 6, body.len() / 2, body.len() - 1] {
                compare(Some(&table), &body[..cut], size, &[]);
            }
            for position in [0, 2, 4, 6, body.len() / 2, body.len() - 1] {
                for mask in [1, 128, 255] {
                    let mut damaged = body.clone();
                    damaged[position] ^= mask;
                    compare(Some(&table), &damaged, size, &[]);
                }
            }
            let mut at = 6;
            for lane in streams(&body) {
                at += lane.len();
                let mut damaged = body.clone();
                damaged[at - 1] = 0;
                compare(Some(&table), &damaged, size, &[]);
            }
        }
    }

    #[test]
    fn irregular_literal_layout_and_public_state_use_serial_fallback() {
        let data: Vec<_> = (0..256).map(|i| (i % 13) as u8).collect();
        let (mut table, body, _) =
            encode([&data[..63], &data[63..128], &data[128..193], &data[193..]]);
        let mut output = Vec::new();
        assert!(!decode_4_fast(
            &table,
            &streams(&body),
            data.len(),
            &mut output
        ));
        assert!(output.is_empty());
        assert_eq!(compare(Some(&table), &body, data.len(), &[]), data);
        for size in [0, 1, 2, 3, 4, 5, 6, 131073] {
            compare(Some(&table), &body, size, &[]);
        }
        output = vec![1, 2, 3];
        assert!(!decode_4_fast(
            &table,
            &streams(&body),
            data.len(),
            &mut output
        ));
        assert_eq!(output, [1, 2, 3]);
        let (tiny_table, tiny_body, _) = encode([&data[..2], &data[2..4], &data[4..6], &[]]);
        assert_eq!(compare(Some(&tiny_table), &tiny_body, 6, &[]), data[..6]);
        output.clear();
        table.max_num_bits = 0;
        assert!(!decode_4_fast(
            &table,
            &streams(&body),
            data.len(),
            &mut output
        ));
        assert!(output.is_empty());
    }
}
