use super::scratch::DecoderScratch;
use crate::decoding::errors::ExecuteSequencesError;

/// Take the provided decoder and execute the sequences stored within
pub fn execute_sequences(scratch: &mut DecoderScratch) -> Result<(), ExecuteSequencesError> {
    if scratch.sequences.len() >= 32 && execute_block(scratch) {
        return Ok(());
    }
    execute_sequences_general(scratch)
}

fn execute_sequences_general(scratch: &mut DecoderScratch) -> Result<(), ExecuteSequencesError> {
    let mut literals_copy_counter = 0;
    let old_buffer_size = scratch.buffer.len();
    let mut seq_sum = 0;

    for idx in 0..scratch.sequences.len() {
        let seq = scratch.sequences[idx];

        if seq.ll > 0 {
            let high = literals_copy_counter + seq.ll as usize;
            if high > scratch.literals_buffer.len() {
                return Err(ExecuteSequencesError::NotEnoughBytesForSequence {
                    wanted: high,
                    have: scratch.literals_buffer.len(),
                });
            }
            let literals = &scratch.literals_buffer[literals_copy_counter..high];
            literals_copy_counter += seq.ll as usize;

            scratch.buffer.push(literals);
        }

        let actual_offset = do_offset_history(seq.of, seq.ll, &mut scratch.offset_hist);
        if actual_offset == 0 {
            return Err(ExecuteSequencesError::ZeroOffset);
        }
        if seq.ml > 0 {
            scratch
                .buffer
                .repeat(actual_offset as usize, seq.ml as usize)?;
        }

        seq_sum += seq.ml;
        seq_sum += seq.ll;
    }
    if literals_copy_counter < scratch.literals_buffer.len() {
        let rest_literals = &scratch.literals_buffer[literals_copy_counter..];
        scratch.buffer.push(rest_literals);
        seq_sum += rest_literals.len() as u32;
    }

    let diff = scratch.buffer.len() - old_buffer_size;
    assert!(
        seq_sum as usize == diff,
        "Seq_sum: {} is different from the difference in buffersize: {}",
        seq_sum,
        diff
    );
    Ok(())
}

// Stage an ordinary block contiguously, then append it to the history once. Failure
// leaves the history and offsets untouched so the general executor retains its
// error ordering and partial-output behavior, including dictionary matches.
fn execute_block(scratch: &mut DecoderScratch) -> bool {
    const BLOCK_SIZE: usize = 128 * 1024;
    const COPY_SIZE: usize = 16;
    let output = &mut scratch.sequence_output;
    output.resize(BLOCK_SIZE + COPY_SIZE, 0);
    let (history1, history2) = scratch.buffer.history_slices();
    let history_len = history1.len() + history2.len();
    let literals = &scratch.literals_buffer;
    let mut offsets = scratch.offset_hist;
    let mut written = 0usize;
    let mut literal_pos = 0usize;

    for seq in &scratch.sequences {
        let ll = seq.ll as usize;
        let ml = seq.ml as usize;
        let Some(literal_end) = literal_pos.checked_add(ll) else {
            return false;
        };
        let Some(match_start) = written.checked_add(ll) else {
            return false;
        };
        let Some(end) = match_start.checked_add(ml) else {
            return false;
        };
        if literal_end > literals.len() || end > BLOCK_SIZE {
            return false;
        }
        if ll != 0 {
            if ll <= COPY_SIZE && literals.len() - literal_pos >= COPY_SIZE {
                output[written..written + COPY_SIZE]
                    .copy_from_slice(&literals[literal_pos..literal_pos + COPY_SIZE]);
            } else {
                output[written..match_start].copy_from_slice(&literals[literal_pos..literal_end]);
            }
        }
        literal_pos = literal_end;
        written = match_start;
        let offset = do_offset_history(seq.of, seq.ll, &mut offsets) as usize;
        if offset == 0 || offset > history_len + written {
            return false;
        }

        if offset > written {
            let mut source = history_len - (offset - written);
            let mut remaining = ml.min(history_len - source);
            if source < history1.len() {
                let count = remaining.min(history1.len() - source);
                copy_history(output, written, history1, source, count);
                written += count;
                remaining -= count;
                source = 0;
            } else {
                source -= history1.len();
            }
            if remaining != 0 {
                copy_history(output, written, history2, source, remaining);
                written += remaining;
            }
        }
        if written < end {
            let source = written - offset;
            let length = end - written;
            if length <= COPY_SIZE && offset >= COPY_SIZE {
                output.copy_within(source..source + COPY_SIZE, written);
            } else {
                while written < end {
                    let count = (end - written).min(written - source);
                    output.copy_within(source..source + count, written);
                    written += count;
                }
            }
        }
        written = end;
    }
    let rest = &literals[literal_pos..];
    if rest.len() > BLOCK_SIZE - written {
        return false;
    }
    output[written..written + rest.len()].copy_from_slice(rest);
    written += rest.len();
    scratch.buffer.push(&output[..written]);
    scratch.offset_hist = offsets;
    true
}

#[inline(always)]
fn copy_history(output: &mut [u8], dest: usize, history: &[u8], source: usize, length: usize) {
    if length <= 16 && history.len() - source >= 16 {
        output[dest..dest + 16].copy_from_slice(&history[source..source + 16]);
    } else {
        output[dest..dest + length].copy_from_slice(&history[source..source + length]);
    }
}

/// Update the most recently used offsets to reflect the provided offset value, and return the
/// "actual" offset needed because offsets are not stored in a raw way, some transformations are needed
/// before you get a functional number.
fn do_offset_history(offset_value: u32, lit_len: u32, scratch: &mut [u32; 3]) -> u32 {
    let actual_offset = if lit_len > 0 {
        match offset_value {
            1..=3 => scratch[offset_value as usize - 1],
            _ => {
                //new offset
                offset_value - 3
            }
        }
    } else {
        match offset_value {
            1..=2 => scratch[offset_value as usize],
            3 => scratch[0] - 1,
            _ => {
                //new offset
                offset_value - 3
            }
        }
    };

    //update history
    if lit_len > 0 {
        match offset_value {
            1 => {
                //nothing
            }
            2 => {
                scratch[1] = scratch[0];
                scratch[0] = actual_offset;
            }
            _ => {
                scratch[2] = scratch[1];
                scratch[1] = scratch[0];
                scratch[0] = actual_offset;
            }
        }
    } else {
        match offset_value {
            1 => {
                scratch[1] = scratch[0];
                scratch[0] = actual_offset;
            }
            2 => {
                scratch[2] = scratch[1];
                scratch[1] = scratch[0];
                scratch[0] = actual_offset;
            }
            _ => {
                scratch[2] = scratch[1];
                scratch[1] = scratch[0];
                scratch[0] = actual_offset;
            }
        }
    }

    actual_offset
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocks::sequence_section::Sequence;
    use alloc::{format, vec};

    fn workspace(prefix: usize) -> DecoderScratch {
        let mut scratch = DecoderScratch::new(128);
        scratch.buffer.reset(128);
        scratch.buffer.push(&vec![0; prefix]);
        scratch.buffer.read_all(&mut vec![0; prefix]).unwrap();
        scratch.buffer.push(
            &(0..96)
                .map(|n| (n * 37) as u8)
                .collect::<alloc::vec::Vec<_>>(),
        );
        scratch.literals_buffer = (0..6000).map(|n| (n * 19) as u8).collect();
        scratch
    }

    fn compare(prefix: usize, sequences: &[Sequence], dictionary: bool) {
        let mut fast = workspace(prefix);
        let mut general = workspace(prefix);
        for scratch in [&mut fast, &mut general] {
            scratch.sequences.extend_from_slice(sequences);
            if dictionary {
                scratch.buffer.dict_content = vec![0x63; 1024];
            }
        }
        let expected = execute_sequences_general(&mut general);
        let actual = execute_sequences(&mut fast);
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
        assert_eq!(fast.offset_hist, general.offset_hist);
        assert_eq!(fast.buffer.drain(), general.buffer.drain());
    }

    #[test]
    fn staged_blocks_match_general_execution() {
        for seed in 0..64usize {
            let mut sequences = alloc::vec::Vec::new();
            let mut available = 96;
            for i in 0..128 {
                let ll = (i * 17 + seed * 13) % 37;
                let ml = 3 + (i * 31 + seed * 7) % 127;
                available += ll;
                let offsets = [1, 2, 3, 7, 15, 16, 17, available, available / 2];
                let offset = offsets[(i + seed) % offsets.len()];
                sequences.push(Sequence {
                    ll: ll as u32,
                    ml: ml as u32,
                    of: if seed % 2 == 1 && i % 4 != 0 {
                        1 + (i % 3) as u32
                    } else {
                        offset as u32 + 3
                    },
                });
                available += ml;
            }
            for prefix in [0, 65, 125, 127] {
                compare(prefix, &sequences, false);
            }
        }
    }

    #[test]
    fn staged_blocks_preserve_fallback_state_and_errors() {
        for failing_index in [0, 1, 31, 32, 63] {
            for failure in [
                Sequence {
                    ll: 6001,
                    ml: 3,
                    of: 4,
                },
                Sequence {
                    ll: 0,
                    ml: 3,
                    of: 3,
                },
                Sequence {
                    ll: 1,
                    ml: 3,
                    of: 100000,
                },
                Sequence {
                    ll: 1,
                    ml: 131073,
                    of: 4,
                },
                Sequence {
                    ll: 0,
                    ml: 300,
                    of: 900,
                },
            ] {
                let mut sequences = vec![
                    Sequence {
                        ll: 1,
                        ml: 3,
                        of: 4
                    };
                    64
                ];
                sequences[failing_index] = failure;
                for dictionary in [false, true] {
                    compare(125, &sequences, dictionary);
                }
            }
        }
    }
}
