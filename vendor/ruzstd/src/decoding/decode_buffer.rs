use crate::common::MAX_BLOCK_SIZE;
use crate::decoding::errors::DecodeBufferError;
use crate::io::{Error, Read, Write};
use alloc::vec::Vec;
#[cfg(feature = "hash")]
use core::hash::Hasher;
use core::ops::Range;

/// How far a block's copies may write past its end: they move 16-byte chunks
/// and 64-byte steps.
pub(crate) const SLACK: usize = 64;
/// The room a block is decoded into: its largest output plus the copy slack.
pub(crate) const BLOCK_ROOM: usize = MAX_BLOCK_SIZE as usize + SLACK;

/// The decoded output of a frame that has not been collected yet, which is
/// also the history matches copy from.
///
/// The buffer is a ring of blocks: each block is decoded into contiguous
/// memory with slack after it, so copies can move fixed-size chunks. When a
/// block no longer fits before the end of the ring, decoding continues at its
/// start, and the data is then two segments: `old` (the older bytes, before
/// the end of the ring) and `new`. Collected bytes stay in place until the
/// next block is decoded.
///
/// The ring is sized once from the window: it holds the window, one block of
/// collectable output and the block being decoded, plus the room lost when a
/// block does not fit before the end. Callers that collect less often make it
/// grow.
pub struct DecodeBuffer {
    /// The ring; `buf.len()` is how much of it has been touched so far.
    buf: Vec<u8>,
    size: usize,
    old: Range<usize>,
    new: Range<usize>,
    pub dict_content: Vec<u8>,

    pub window_size: usize,
    total_output_counter: u64,
    #[cfg(feature = "hash")]
    pub hash: twox_hash::XxHash64,
}

/// What a block decodes into: the ring, the place the block starts and the
/// history before it.
pub(crate) struct BlockTarget<'a> {
    pub buf: &'a mut [u8],
    /// Where the block starts, at the end of `new`.
    pub start: usize,
    /// The start of the segment the block extends.
    pub segment: usize,
    /// The older segment, empty unless the ring wrapped.
    pub old: Range<usize>,
    /// How many bytes before the block matches may reach.
    pub history: usize,
    pub dict: &'a [u8],
    /// Whether the dictionary may be used, at the start of the block: the
    /// output counted so far is within the window.
    pub dict_counter: u64,
    pub window_size: usize,
}

impl Read for DecodeBuffer {
    fn read(&mut self, target: &mut [u8]) -> Result<usize, Error> {
        let max_amount = self.can_drain_to_window_size().unwrap_or(0);
        let amount = max_amount.min(target.len());
        self.copy_out(&mut target[..amount]);
        Ok(amount)
    }
}

impl DecodeBuffer {
    pub fn new(window_size: usize) -> DecodeBuffer {
        DecodeBuffer {
            buf: Vec::new(),
            size: 0,
            old: 0..0,
            new: 0..0,
            dict_content: Vec::new(),
            window_size,
            total_output_counter: 0,
            #[cfg(feature = "hash")]
            hash: twox_hash::XxHash64::with_seed(0),
        }
    }

    /// Empties the buffer for a frame with this window. The ring is kept if it
    /// is large enough, else allocated when the first block is decoded.
    pub fn reset(&mut self, window_size: usize) {
        self.window_size = window_size;
        self.old = 0..0;
        self.new = 0..0;
        if self.size < ring_size(window_size).unwrap_or(usize::MAX) {
            self.buf = Vec::new();
            self.size = 0;
        }
        self.dict_content.clear();
        self.total_output_counter = 0;
        #[cfg(feature = "hash")]
        {
            self.hash = twox_hash::XxHash64::with_seed(0);
        }
    }

    pub fn len(&self) -> usize {
        self.old.len() + self.new.len()
    }

    /// Ensures contiguous room for a block after the data, wrapping to the
    /// start of the ring or growing it as needed.
    pub(crate) fn reserve_block(&mut self) -> Result<(), DecodeBufferError> {
        let fits = if self.old.is_empty() {
            if self.new.end + BLOCK_ROOM <= self.size {
                true
            } else if BLOCK_ROOM <= self.new.start {
                self.old = self.new.clone();
                self.new = 0..0;
                true
            } else {
                false
            }
        } else {
            self.new.end + BLOCK_ROOM <= self.old.start
        };
        if !fits {
            self.grow()?;
        }
        let end = self.new.end + BLOCK_ROOM;
        if self.buf.len() < end {
            self.buf.resize(end, 0);
        }
        Ok(())
    }

    #[cold]
    fn grow(&mut self) -> Result<(), DecodeBufferError> {
        let len = self.len();
        let size = ring_size(self.window_size)
            .and_then(|ring| ring.max(self.size.checked_mul(2)?).checked_add(len))
            .ok_or(DecodeBufferError::OutOfMemory)?;
        let mut buf = Vec::new();
        buf.try_reserve_exact(size)
            .map_err(|_| DecodeBufferError::OutOfMemory)?;
        buf.extend_from_slice(&self.buf[self.old.clone()]);
        buf.extend_from_slice(&self.buf[self.new.clone()]);
        self.buf = buf;
        self.size = size;
        self.old = 0..0;
        self.new = 0..len;
        Ok(())
    }

    /// The reserved block and its history. Matches may reach at most a
    /// window back from the block, as long as the bytes are uncollected.
    pub(crate) fn block_target(&mut self) -> BlockTarget<'_> {
        BlockTarget {
            start: self.new.end,
            segment: self.new.start,
            old: self.old.clone(),
            history: self.len().min(self.window_size),
            dict: &self.dict_content,
            dict_counter: self.total_output_counter,
            window_size: self.window_size,
            buf: &mut self.buf,
        }
    }

    /// Fills `len` bytes of the reserved block with `byte`, for an RLE block.
    pub(crate) fn fill_block(&mut self, byte: u8, len: usize) {
        let start = self.new.end;
        self.buf[start..start + len].fill(byte);
        self.commit_block(len, 0);
    }

    /// Reads `len` bytes into the reserved block, for a raw block. A failed
    /// read adds nothing.
    pub(crate) fn read_block<R: Read>(&mut self, mut read: R, len: usize) -> Result<(), Error> {
        let start = self.new.end;
        read.read_exact(&mut self.buf[start..start + len])?;
        self.commit_block(len, 0);
        Ok(())
    }

    /// Adds the first `len` bytes of the reserved block to the data.
    /// `counted` is how many count towards the dictionary limit.
    pub(crate) fn commit_block(&mut self, len: usize, counted: u64) {
        let start = self.new.end;
        #[cfg(feature = "hash")]
        self.hash.write(&self.buf[start..start + len]);
        self.new.end = start + len;
        self.total_output_counter += counted;
    }

    /// Check if and how many bytes can currently be drawn from the buffer
    pub fn can_drain_to_window_size(&self) -> Option<usize> {
        let len = self.len();
        if len > self.window_size {
            Some(len - self.window_size)
        } else {
            None
        }
    }

    //How many bytes can be drained if the window_size does not have to be maintained
    pub fn can_drain(&self) -> usize {
        self.len()
    }

    /// Drain as much as possible while retaining enough so that decoding si still possible with the required window_size
    /// At best call only if can_drain_to_window_size reports a 'high' number of bytes to reduce allocations
    pub fn drain_to_window_size(&mut self) -> Option<Vec<u8>> {
        let can_drain = self.can_drain_to_window_size()?;
        let mut vec = alloc::vec![0; can_drain];
        self.copy_out(&mut vec);
        Some(vec)
    }

    pub fn drain_to_window_size_writer(&mut self, mut sink: impl Write) -> Result<usize, Error> {
        match self.can_drain_to_window_size() {
            None => Ok(0),
            Some(can_drain) => self.drain_to(can_drain, |buf| write_all_bytes(&mut sink, buf)),
        }
    }

    /// drain the buffer completely
    pub fn drain(&mut self) -> Vec<u8> {
        let mut vec = alloc::vec![0; self.len()];
        self.copy_out(&mut vec);
        vec
    }

    pub fn drain_to_writer(&mut self, mut sink: impl Write) -> Result<usize, Error> {
        let write_limit = self.len();
        self.drain_to(write_limit, |buf| write_all_bytes(&mut sink, buf))
    }

    pub fn read_all(&mut self, target: &mut [u8]) -> Result<usize, Error> {
        let amount = self.len().min(target.len());
        self.copy_out(&mut target[..amount]);
        Ok(amount)
    }

    /// Moves the first `target.len()` bytes, which must exist, to `target`.
    fn copy_out(&mut self, target: &mut [u8]) {
        let first = if self.old.is_empty() {
            &self.new
        } else {
            &self.old
        };
        let n1 = first.len().min(target.len());
        let (t1, t2) = target.split_at_mut(n1);
        t1.copy_from_slice(&self.buf[first.start..first.start + n1]);
        t2.copy_from_slice(&self.buf[self.new.start..self.new.start + t2.len()]);
        self.drop_first_n(target.len());
    }

    /// Advance past the first `amount` bytes, which must exist.
    fn drop_first_n(&mut self, amount: usize) {
        let from_old = amount.min(self.old.len());
        self.old.start += from_old;
        if self.old.is_empty() {
            self.old = 0..0;
        }
        self.new.start += amount - from_old;
        if self.old.is_empty() && self.new.is_empty() {
            self.new = 0..0;
        }
    }

    /// Semantics of write_bytes:
    /// Should dump as many of the provided bytes as possible to whatever sink until no bytes are left or an error is encountered
    /// Return how many bytes have actually been dumped to the sink.
    fn drain_to(
        &mut self,
        amount: usize,
        mut write_bytes: impl FnMut(&[u8]) -> (usize, Result<(), Error>),
    ) -> Result<usize, Error> {
        if amount == 0 {
            return Ok(0);
        }
        let (slice1, slice2) = if self.old.is_empty() {
            (&self.buf[self.new.clone()], &[][..])
        } else {
            (&self.buf[self.old.clone()], &self.buf[self.new.clone()])
        };
        let n1 = slice1.len().min(amount);
        let n2 = slice2.len().min(amount - n1);

        let (mut written, mut result) = write_bytes(&slice1[..n1]);
        // Only if the first call to write_bytes was not a partial write we can continue with slice2
        // Partial writes SHOULD never happen without an error, but lets just protect against it anyways.
        if result.is_ok() && written == n1 && n2 != 0 {
            let (written2, result2) = write_bytes(&slice2[..n2]);
            written += written2;
            result = result2;
        }
        self.drop_first_n(written);
        result.map(|()| written)
    }
}

/// The ring for a window: the window, one block of collectable output and
/// two blocks' room, so the next block always fits before the oldest byte
/// still needed, whether or not it wraps.
fn ring_size(window_size: usize) -> Option<usize> {
    window_size.checked_add(MAX_BLOCK_SIZE as usize + 2 * BLOCK_ROOM)
}

/// Like Write::write_all but returns partial write length even on error
fn write_all_bytes(mut sink: impl Write, buf: &[u8]) -> (usize, Result<(), Error>) {
    let mut written = 0;
    while written < buf.len() {
        match sink.write(&buf[written..]) {
            Ok(0) => return (written, Ok(())),
            Ok(w) => written += w,
            Err(e) => return (written, Err(e)),
        }
    }
    (written, Ok(()))
}

#[cfg(test)]
mod tests {
    use super::{DecodeBuffer, BLOCK_ROOM};
    use crate::io::{Error, ErrorKind, Write};

    extern crate std;
    use alloc::vec;
    use alloc::vec::Vec;

    fn push(buffer: &mut DecodeBuffer, data: &[u8]) {
        buffer.reserve_block().unwrap();
        let target = buffer.block_target();
        target.buf[target.start..target.start + data.len()].copy_from_slice(data);
        buffer.commit_block(data.len(), data.len() as u64);
    }

    #[test]
    fn ring_wraps_without_growing_and_keeps_the_window() {
        let window = 1000;
        let mut buffer = DecodeBuffer::new(window);
        buffer.reset(window);
        let mut expected = Vec::new();
        let mut collected = Vec::new();
        let mut sizes = [131_072usize, 5, 70_000, 131_071, 0, 1].iter().cycle();
        for i in 0..200u32 {
            let size = *sizes.next().unwrap();
            let data: Vec<u8> = (0..size).map(|n| (n as u32 * 7 + i) as u8).collect();
            push(&mut buffer, &data);
            expected.extend_from_slice(&data);
            assert_eq!(buffer.size, super::ring_size(window).unwrap());
            let mut out = vec![0; buffer.can_drain_to_window_size().unwrap_or(0)];
            std::io::Read::read_exact(&mut buffer, &mut out).unwrap();
            collected.extend_from_slice(&out);
            assert_eq!(buffer.len(), window.min(expected.len()));
            assert_eq!(buffer.block_target().history, buffer.len());
        }
        collected.extend_from_slice(&buffer.drain());
        assert_eq!(collected, expected);
    }

    #[test]
    fn uncollected_output_grows_the_ring() {
        let mut buffer = DecodeBuffer::new(100);
        buffer.reset(100);
        let mut expected = Vec::new();
        for i in 0..40u8 {
            let data = vec![i; 100_000];
            push(&mut buffer, &data);
            expected.extend_from_slice(&data);
            buffer.reserve_block().unwrap();
            let target = buffer.block_target();
            assert!(target.start + BLOCK_ROOM <= target.buf.len());
            assert_eq!(target.history, 100);
        }
        assert_eq!(buffer.drain(), expected);
    }

    #[test]
    fn short_writer() {
        struct ShortWriter {
            buf: Vec<u8>,
            write_len: usize,
        }

        impl Write for ShortWriter {
            fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, Error> {
                if buf.len() > self.write_len {
                    self.buf.extend_from_slice(&buf[..self.write_len]);
                    Ok(self.write_len)
                } else {
                    self.buf.extend_from_slice(buf);
                    Ok(buf.len())
                }
            }

            fn flush(&mut self) -> std::result::Result<(), Error> {
                Ok(())
            }
        }

        let mut short_writer = ShortWriter {
            buf: vec![],
            write_len: 10,
        };

        let mut decode_buf = DecodeBuffer::new(100);
        push(&mut decode_buf, &[7; 100]);
        let repeats = 1000;
        for _ in 0..repeats {
            assert_eq!(decode_buf.len(), 100);
            push(&mut decode_buf, &[9; 50]);
            assert_eq!(decode_buf.len(), 150);
            decode_buf
                .drain_to_window_size_writer(&mut short_writer)
                .unwrap();
            assert_eq!(decode_buf.len(), 100);
        }

        assert_eq!(short_writer.buf.len(), repeats * 50);
        decode_buf.drain_to_writer(&mut short_writer).unwrap();
        assert_eq!(short_writer.buf.len(), repeats * 50 + 100);
    }

    #[test]
    fn wouldblock_writer() {
        struct WouldblockWriter {
            buf: Vec<u8>,
            last_blocked: usize,
            block_every: usize,
        }

        impl Write for WouldblockWriter {
            fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, Error> {
                if self.last_blocked < self.block_every {
                    self.buf.extend_from_slice(buf);
                    self.last_blocked += 1;
                    Ok(buf.len())
                } else {
                    self.last_blocked = 0;
                    Err(Error::from(ErrorKind::WouldBlock))
                }
            }

            fn flush(&mut self) -> std::result::Result<(), Error> {
                Ok(())
            }
        }

        let mut short_writer = WouldblockWriter {
            buf: vec![],
            last_blocked: 0,
            block_every: 5,
        };

        let mut decode_buf = DecodeBuffer::new(100);
        push(&mut decode_buf, &[7; 100]);
        let repeats = 1000;
        for _ in 0..repeats {
            assert_eq!(decode_buf.len(), 100);
            push(&mut decode_buf, &[9; 50]);
            assert_eq!(decode_buf.len(), 150);
            loop {
                match decode_buf.drain_to_window_size_writer(&mut short_writer) {
                    Ok(written) => {
                        if written == 0 {
                            break;
                        }
                    }
                    Err(e) => {
                        if e.kind() == ErrorKind::WouldBlock {
                            continue;
                        } else {
                            panic!("Unexpected error {:?}", e);
                        }
                    }
                }
            }
            assert_eq!(decode_buf.len(), 100);
        }

        assert_eq!(short_writer.buf.len(), repeats * 50);
        loop {
            match decode_buf.drain_to_writer(&mut short_writer) {
                Ok(written) => {
                    if written == 0 {
                        break;
                    }
                }
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock {
                        continue;
                    } else {
                        panic!("Unexpected error {:?}", e);
                    }
                }
            }
        }
        assert_eq!(short_writer.buf.len(), repeats * 50 + 100);
    }
}
