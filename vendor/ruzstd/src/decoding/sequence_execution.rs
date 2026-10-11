//! The copies that execute a sequence, after `ZSTD_execSequence`. A block is
//! decoded into a ring with slack after it (see
//! [DecodeBuffer](super::decode_buffer::DecodeBuffer)), so copies move whole
//! 16-byte chunks, then 64-byte steps, and may write up to 63 bytes past
//! their end. Those bytes are overwritten by the next copy or lie beyond the
//! block.

use crate::decoding::errors::{DecodeBufferError, ExecuteSequencesError};
use core::ops::Range;

const CHUNK: usize = 16;
/// Longer runs continue in wider steps.
const WIDE: usize = 64;

/// Copies `len` literals from `literals[from..]`, which has slack after the
/// literals, to `buf[op..]`.
#[inline(always)]
pub(crate) fn copy_literals(buf: &mut [u8], op: usize, literals: &[u8], from: usize, len: usize) {
    buf[op..op + CHUNK].copy_from_slice(&literals[from..from + CHUNK]);
    let mut done = CHUNK;
    while done < len {
        buf[op + done..op + done + WIDE].copy_from_slice(&literals[from + done..from + done + WIDE]);
        done += WIDE;
    }
}

/// Copies a match of `len` bytes from `offset` back, within the segment.
#[inline(always)]
pub(crate) fn copy_match(buf: &mut [u8], op: usize, offset: usize, len: usize) {
    let from = op - offset;
    if offset < CHUNK {
        return copy_short_offset(buf, op, offset, len);
    }
    // Each chunk ends at or before the one it is copied to.
    buf.copy_within(from..from + CHUNK, op);
    let mut done = CHUNK;
    if offset >= WIDE {
        while done < len {
            buf.copy_within(from + done..from + done + WIDE, op + done);
            done += WIDE;
        }
    } else {
        while done < len {
            buf.copy_within(from + done..from + done + CHUNK, op + done);
            done += CHUNK;
        }
    }
}

/// A match closer than a chunk repeats its last `offset` bytes. Spread them
/// over a chunk, then copy chunks from a whole number of periods back.
#[inline(never)]
fn copy_short_offset(buf: &mut [u8], op: usize, offset: usize, len: usize) {
    // The smallest multiple of each offset that is at least a chunk.
    const PERIOD: [u8; CHUNK] = [0, 16, 16, 18, 16, 20, 18, 21, 16, 18, 20, 22, 24, 26, 28, 30];
    let mut pattern = [0; CHUNK];
    pattern.copy_from_slice(&buf[op - offset..op - offset + CHUNK]);
    for i in offset..CHUNK {
        pattern[i] = pattern[i - offset];
    }
    buf[op..op + CHUNK].copy_from_slice(&pattern);
    let period = usize::from(PERIOD[offset]);
    let mut done = CHUNK;
    while done < len {
        let from = op + done - period;
        buf.copy_within(from..from + CHUNK, op + done);
        done += CHUNK;
    }
}

/// The history a block's matches may reach outside its own segment.
pub(crate) struct Far<'a> {
    pub start: usize,
    pub segment: usize,
    pub old: Range<usize>,
    pub history: usize,
    pub dict: &'a [u8],
    /// The output counted towards the dictionary limit before the block.
    pub counter: u64,
    pub window_size: usize,
}

/// Copies a match that reaches back past the segment, into the older segment
/// or the dictionary, or rejects its offset. `uncounted` is how much of the
/// block so far does not count towards the dictionary limit; returns how much
/// of this match does not.
#[cold]
#[inline(never)]
pub(crate) fn copy_far(
    buf: &mut [u8],
    op: usize,
    offset: usize,
    len: usize,
    far: &Far<'_>,
    uncounted: u64,
) -> Result<u64, ExecuteSequencesError> {
    if offset == 0 {
        return Err(ExecuteSequencesError::ZeroOffset);
    }
    let reach = far.history + (op - far.start);
    if offset <= reach {
        let in_segment = op - far.segment;
        if offset <= in_segment {
            copy_match(buf, op, offset, len);
            return Ok(0);
        }
        // The older segment's end is followed by the segment's start.
        let back = offset - in_segment;
        let from = far.old.end - back;
        let n = back.min(len);
        buf.copy_within(from..from + n, op);
        if len > n {
            copy_match(buf, op + n, offset, len - n);
        }
        return Ok(0);
    }
    // Only output up to a window long may refer to the dictionary.
    let counter = far.counter + (op - far.start) as u64 - uncounted;
    if counter > far.window_size as u64 {
        return Err(DecodeBufferError::OffsetTooBig {
            offset,
            buf_len: reach,
        }
        .into());
    }
    let from_dict = offset - reach;
    if from_dict > far.dict.len() {
        return Err(DecodeBufferError::NotEnoughBytesInDictionary {
            got: far.dict.len(),
            need: from_dict,
        }
        .into());
    }
    let dict = &far.dict[far.dict.len() - from_dict..];
    if from_dict < len {
        buf[op..op + from_dict].copy_from_slice(dict);
        // The rest starts at the oldest byte of the history.
        copy_far(buf, op + from_dict, offset, len - from_dict, far, uncounted)?;
        Ok(0)
    } else {
        // A match entirely within the dictionary is not counted.
        buf[op..op + len].copy_from_slice(&dict[..len]);
        Ok(len as u64)
    }
}

/// Resolves an offset value to an offset, updating the most recent offsets.
/// Values 1-3 repeat a recent offset; after no literals they shift by one,
/// and the shifted 3 is the most recent offset minus one.
///
/// <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#repeat-offsets>
#[inline(always)]
pub(crate) fn resolve_offset(value: u32, no_literals: bool, recent: &mut [u32; 3]) -> u32 {
    if value > 3 {
        let offset = value - 3;
        *recent = [offset, recent[0], recent[1]];
        return offset;
    }
    // Values start at 1; a zero from a table left by an earlier error wraps.
    let index = (value as usize + usize::from(no_literals)).wrapping_sub(1);
    let offset = match index {
        0 => return recent[0],
        1 => recent[1],
        2 => recent[2],
        _ => recent[0].wrapping_sub(1),
    };
    if index != 1 {
        recent[2] = recent[1];
    }
    recent[1] = recent[0];
    recent[0] = offset;
    offset
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoding::decode_buffer::SLACK;
    use alloc::vec;
    use alloc::vec::Vec;

    /// LZ77 semantics, one byte at a time.
    fn reference(history: &[u8], offset: usize, len: usize) -> Vec<u8> {
        let mut out = history.to_vec();
        for _ in 0..len {
            out.push(out[out.len() - offset]);
        }
        out.split_off(history.len())
    }

    #[test]
    fn chunked_matches_repeat_like_byte_copies() {
        let history: Vec<u8> = (0..300u32).map(|i| (i * 73 % 251) as u8).collect();
        for offset in 1..=70 {
            for len in (3..=80).chain([127, 128, 129, 1000, 4099]) {
                let mut buf = history.clone();
                buf.resize(history.len() + len + SLACK, 0xAA);
                copy_match(&mut buf, history.len(), offset, len);
                assert_eq!(
                    buf[history.len()..history.len() + len],
                    reference(&history, offset, len),
                    "offset {offset} len {len}"
                );
                assert_eq!(buf[..history.len()], history);
            }
        }
    }

    #[test]
    fn chunked_literals_copy_exactly() {
        let literals: Vec<u8> = (0..200u8).chain([0; SLACK]).collect();
        for from in [0, 1, 15, 16, 17, 100] {
            for len in 0..=100.min(200 - from) {
                let mut buf = vec![0xAA; 10 + len + SLACK];
                copy_literals(&mut buf, 10, &literals, from, len);
                assert_eq!(buf[10..10 + len], literals[from..from + len]);
                assert_eq!(buf[..10], [0xAA; 10]);
            }
        }
    }

    #[test]
    fn far_matches_join_the_older_segment_to_the_segment() {
        // Logical history: the older segment's bytes, then the segment's.
        let size = 400;
        let old = 300..380;
        let segment = 0;
        for start in [0usize, 5, 40] {
            let mut buf = vec![0u8; size];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i * 31 % 253) as u8;
            }
            let logical: Vec<u8> = buf[old.clone()]
                .iter()
                .chain(&buf[segment..start])
                .copied()
                .collect();
            for offset in 1..=logical.len() {
                for len in [1, 3, 16, 17, 40, 100] {
                    let mut work = buf.clone();
                    let far = Far {
                        start,
                        segment,
                        old: old.clone(),
                        history: logical.len(),
                        dict: &[],
                        counter: 0,
                        window_size: 1000,
                    };
                    copy_far(&mut work, start, offset, len, &far, 0).unwrap();
                    assert_eq!(
                        work[start..start + len],
                        reference(&logical, offset, len),
                        "start {start} offset {offset} len {len}"
                    );
                }
            }
            let far = Far {
                start,
                segment,
                old: old.clone(),
                history: logical.len(),
                dict: &[],
                counter: 0,
                window_size: 1000,
            };
            let mut work = buf.clone();
            assert!(copy_far(&mut work, start, logical.len() + 1, 3, &far, 0).is_err());
            assert!(copy_far(&mut work, start, 0, 3, &far, 0).is_err());
        }
    }

    #[test]
    fn far_matches_continue_from_the_dictionary() {
        let dict: Vec<u8> = (100..140).collect();
        let history = [1u8, 2, 3, 4, 5];
        for offset in 6..=45 {
            for len in [1, 3, 20, 60] {
                let mut buf = vec![0u8; 200];
                buf[..5].copy_from_slice(&history);
                let far = Far {
                    start: 5,
                    segment: 0,
                    old: 0..0,
                    history: 5,
                    dict: &dict,
                    counter: 5,
                    window_size: 1000,
                };
                let uncounted = copy_far(&mut buf, 5, offset, len, &far, 0).unwrap();
                let logical: Vec<u8> = dict.iter().chain(&history).copied().collect();
                assert_eq!(buf[5..5 + len], reference(&logical, offset, len));
                let from_dict = offset - 5;
                assert_eq!(uncounted, if from_dict >= len { len as u64 } else { 0 });
            }
        }
        let far = Far {
            start: 5,
            segment: 0,
            old: 0..0,
            history: 5,
            dict: &dict,
            counter: 1001,
            window_size: 1000,
        };
        assert!(copy_far(&mut [0; 100], 5, 6, 3, &far, 0).is_err());
        let far = Far { counter: 5, ..far };
        assert!(copy_far(&mut [0; 100], 5, 46, 3, &far, 0).is_err());
    }

    #[test]
    fn repeat_offsets_follow_the_format() {
        let start = [11, 22, 33];
        let cases = [
            (1, false, 11, [11, 22, 33]),
            (2, false, 22, [22, 11, 33]),
            (3, false, 33, [33, 11, 22]),
            (1, true, 22, [22, 11, 33]),
            (2, true, 33, [33, 11, 22]),
            (3, true, 10, [10, 11, 22]),
            (4, false, 1, [1, 11, 22]),
            (4, true, 1, [1, 11, 22]),
            (1000, true, 997, [997, 11, 22]),
        ];
        for (value, no_literals, offset, recent) in cases {
            let mut state = start;
            assert_eq!(resolve_offset(value, no_literals, &mut state), offset);
            assert_eq!(state, recent);
        }
    }
}
