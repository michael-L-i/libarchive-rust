//! The LZ decompressor: block headers, Huffman tables and the symbol loop.

use super::*;

const HUFF_BC: usize = 20;
const HUFF_NC: usize = 306;
const HUFF_DC: usize = 64;
const HUFF_LDC: usize = 16;
const HUFF_RC: usize = 44;
const HUFF_TABLE_SIZE: usize = HUFF_NC + HUFF_DC + HUFF_RC + HUFF_LDC;

/// Where the bit reader is in the block.
#[derive(Clone, Copy, Default)]
pub(super) struct BitPos {
    /// Current bit pointer inside current byte.
    bit_addr: i32,
    /// Current byte pointer.
    in_addr: i64,
}

/// Reads bits from a block. `p` is the block with at least 4 more bytes
/// after it, which the 32-bit reads look into.
pub(super) struct BitReader<'p> {
    p: &'p [u8],
    block_size: i64,
    pos: BitPos,
}

impl<'p> BitReader<'p> {
    fn new(p: &'p [u8], block_size: i64, pos: BitPos) -> Self {
        BitReader { p, block_size, pos }
    }

    /// The byte at `i` in the block; bytes past the end are zero.
    fn at(&self, i: i64) -> u8 {
        usize::try_from(i)
            .ok()
            .and_then(|i| self.p.get(i))
            .copied()
            .unwrap_or(0)
    }

    /// The byte `i` bytes after the current one.
    fn byte(&self, i: i64) -> u32 {
        u32::from(self.at(self.pos.in_addr + i))
    }

    fn read_bits_32(&self, a: &Base) -> Option<u32> {
        if self.pos.in_addr >= self.block_size {
            a.set_error(
                ARCHIVE_ERRNO_PROGRAMMER,
                Some(b"Premature end of stream during extraction of data (#1)"),
            );
            return None;
        }

        let mut bits = self.byte(0) << 24 | self.byte(1) << 16 | self.byte(2) << 8 | self.byte(3);
        bits <<= self.pos.bit_addr;
        bits |= self.byte(4) >> (8 - self.pos.bit_addr);
        Some(bits)
    }

    pub(super) fn read_bits_16(&self, a: &Base) -> Option<u16> {
        if self.pos.in_addr >= self.block_size {
            a.set_error(
                ARCHIVE_ERRNO_PROGRAMMER,
                Some(b"Premature end of stream during extraction of data (#2)"),
            );
            return None;
        }

        let bits =
            (self.byte(0) << 16 | self.byte(1) << 8 | self.byte(2)) >> (8 - self.pos.bit_addr);
        Some((bits & 0xffff) as u16)
    }

    pub(super) fn skip_bits(&mut self, bits: u32) {
        let new_bits = self.pos.bit_addr + bits as i32;
        self.pos.in_addr += i64::from(new_bits >> 3);
        self.pos.bit_addr = new_bits & 7;
    }

    /// Reads and consumes `n` bits, up to 16.
    pub(super) fn read_consume_bits(&mut self, a: &Base, n: u32) -> Option<u32> {
        if n == 0 || n > 16 {
            // This is a programmer error and should never happen in runtime.
            return None;
        }

        let v = u32::from(self.read_bits_16(a)?) >> (16 - n);
        self.skip_bits(n);
        Some(v)
    }
}

pub(super) struct DecodeTable {
    size: u32,
    decode_len: [i32; 16],
    decode_pos: [u32; 16],
    quick_bits: u32,
    quick_len: [u8; 1 << 10],
    quick_num: [u16; 1 << 10],
    decode_num: [u16; HUFF_NC],
}

impl Default for DecodeTable {
    fn default() -> Self {
        DecodeTable {
            size: 0,
            decode_len: [0; 16],
            decode_pos: [0; 16],
            quick_bits: 0,
            quick_len: [0; 1 << 10],
            quick_num: [0; 1 << 10],
            decode_num: [0; HUFF_NC],
        }
    }
}

impl DecodeTable {
    /// Builds the table for the code lengths of `size` symbols. False if the
    /// lengths are over-subscribed; the table is then left half built, as
    /// upstream leaves it.
    fn create(&mut self, bit_length: &[u8], size: usize) -> bool {
        let mut lc = [0i32; 16];
        self.decode_num = [0; HUFF_NC];
        self.size = size as u32;
        self.quick_bits = if size == HUFF_NC { 10 } else { 7 };

        let lengths = bit_length.get(..size).unwrap_or(bit_length);
        for &len in lengths {
            lc[usize::from(len & 15)] += 1;
        }

        lc[0] = 0;
        self.decode_pos[0] = 0;
        self.decode_len[0] = 0;

        let mut upper_limit = 0i32;
        for i in 1..16 {
            upper_limit += lc[i];

            self.decode_len[i] = upper_limit << (16 - i);
            self.decode_pos[i] = self.decode_pos[i - 1] + lc[i - 1] as u32;

            upper_limit <<= 1;
        }

        // Verify the code-length distribution is not over-subscribed.
        // After the loop above, upper_limit == sum(lc[i] * 2^(16-i)).
        // For a valid prefix-free code this must be <= 2^16 = 65536.
        // An over-subscribed table (> 65536) cannot produce a valid
        // decode table and must be rejected.
        if upper_limit > 65536 {
            return false;
        }

        let mut decode_pos_clone = self.decode_pos;
        for (i, &len) in lengths.iter().enumerate() {
            let clen = usize::from(len & 15);
            if clen > 0 {
                let last_pos = decode_pos_clone[clen] as usize;
                if let Some(num) = self.decode_num.get_mut(last_pos) {
                    *num = i as u16;
                }
                decode_pos_clone[clen] += 1;
            }
        }

        let quick_data_size = 1usize << self.quick_bits;
        let mut cur_len = 1usize;
        for code in 0..quick_data_size {
            let bit_field = (code << (16 - self.quick_bits)) as i32;

            while cur_len < self.decode_len.len() && bit_field >= self.decode_len[cur_len] {
                cur_len += 1;
            }

            self.quick_len[code] = cur_len as u8;

            let mut dist = bit_field - self.decode_len[cur_len - 1];
            dist >>= 16 - cur_len;

            let pos = i64::from(self.decode_pos[cur_len & 15]) + i64::from(dist);
            self.quick_num[code] = if cur_len < self.decode_pos.len() && pos < size as i64 {
                usize::try_from(pos)
                    .ok()
                    .and_then(|p| self.decode_num.get(p))
                    .copied()
                    .unwrap_or(0)
            } else {
                0
            };
        }

        true
    }

    fn decode_number(&self, a: &Base, br: &mut BitReader<'_>) -> Option<u16> {
        let bitfield = i32::from(br.read_bits_16(a)? & 0xfffe);
        let quick_bits = self.quick_bits as usize;

        if bitfield < self.decode_len[quick_bits] {
            let code = (bitfield >> (16 - quick_bits)) as usize;
            br.skip_bits(u32::from(self.quick_len.get(code).copied().unwrap_or(0)));
            return self.quick_num.get(code).copied();
        }

        let mut bits = 15;
        for i in quick_bits + 1..15 {
            if bitfield < self.decode_len[i] {
                bits = i;
                break;
            }
        }

        br.skip_bits(bits as u32);

        let dist = (bitfield - self.decode_len[bits - 1]) >> (16 - bits);
        let mut pos = self.decode_pos[bits].wrapping_add(dist as u32);

        if pos >= self.size {
            pos = 0;
        }

        self.decode_num.get(pos as usize).copied()
    }
}

/// Parses the block header, verifies its CRC byte, and gives the block size
/// and the header's flags byte.
pub(super) fn parse_block_header(p: &[u8]) -> Res<(i64, u8)> {
    let byte = |i: usize| p.get(i).copied().unwrap_or(0);
    let flags = byte(0);
    let cksum = byte(1);
    let byte_count = (flags >> 3) & 7;

    if byte_count > 2 {
        return Err(failed(
            ARCHIVE_ERRNO_FILE_FORMAT,
            format!("Unsupported block header size (was {byte_count}, max is 2)"),
        ));
    }

    // This should probably use bit reader interface in order to be more
    // future-proof.
    let block_size = match byte_count {
        // 1-byte block size
        0 => i64::from(byte(2)),
        // 2-byte block size
        1 => i64::from(byte(2)) | i64::from(byte(3)) << 8,
        // 3-byte block size
        _ => i64::from(byte(2)) | i64::from(byte(3)) << 8 | i64::from(byte(4)) << 16,
    };

    // Verify the block header checksum. 0x5A is a magic value and is always
    // constant.
    let calculated_cksum =
        0x5A ^ flags ^ (block_size as u8) ^ ((block_size >> 8) as u8) ^ ((block_size >> 16) as u8);

    if calculated_cksum != cksum {
        return Err(failed(
            ARCHIVE_ERRNO_FILE_FORMAT,
            format!("Block checksum error: got 0x{cksum:x}, expected 0x{calculated_cksum:x}"),
        ));
    }

    Ok((block_size, flags))
}

impl Rar5 {
    /// Decodes the block `p` (with at least 4 bytes after it), or what is
    /// left of it: its tables first if it is new.
    pub(super) fn decode_block(&mut self, a: &Base, p: &[u8], new_block: bool) -> Res<()> {
        let mut br = BitReader::new(p, self.cstate.cur_block_size, self.bits);
        let mut ret = Ok(());
        if new_block && self.last_block_flags >> 7 != 0 {
            // Load Huffman tables.
            ret = self.parse_tables(a, &mut br);
        }
        if ret.is_ok() {
            ret = self.do_uncompress_block(a, &mut br);
        }
        self.bits = br.pos;
        ret
    }

    /// Reads and parses Huffman tables from the beginning of the block.
    fn parse_tables(&mut self, a: &Base, br: &mut BitReader<'_>) -> Res<()> {
        const ESCAPE: u32 = 15;

        let mut bit_length = [0u8; HUFF_BC];
        let mut table = [0u8; HUFF_TABLE_SIZE];
        let mut nibble_mask = 0xF0u8;
        let mut nibble_shift = 4u8;

        // The data for table generation is compressed using a simple
        // RLE-like algorithm when storing zeroes, so we need to unpack it
        // first.
        let mut w = 0;
        let mut i: i64 = 0;
        while w < HUFF_BC {
            if i >= self.cstate.cur_block_size {
                // Truncated data, can't continue.
                a.set_error(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    Some(b"Truncated data in huffman tables"),
                );
                return Err(Stop::Err(Error::silent(ARCHIVE_FAILED)));
            }

            let mut value = (br.at(i) & nibble_mask) >> nibble_shift;

            if nibble_mask == 0x0F {
                i += 1;
            }

            nibble_mask ^= 0xFF;
            nibble_shift ^= 4;

            // Values smaller than 15 is data, so we write it directly. Value
            // 15 is a flag telling us that we need to unpack more bytes.
            if u32::from(value) == ESCAPE {
                value = (br.at(i) & nibble_mask) >> nibble_shift;
                if nibble_mask == 0x0F {
                    i += 1;
                }
                nibble_mask ^= 0xFF;
                nibble_shift ^= 4;

                if value == 0 {
                    // We sometimes need to write the actual value of 15, so
                    // this case handles that.
                    bit_length[w] = ESCAPE as u8;
                    w += 1;
                } else {
                    // Fill zeroes.
                    for _ in 0..value + 2 {
                        if w >= HUFF_BC {
                            break;
                        }
                        bit_length[w] = 0;
                        w += 1;
                    }
                }
            } else {
                bit_length[w] = value;
                w += 1;
            }
        }

        br.pos.in_addr = i;
        br.pos.bit_addr = i32::from(nibble_shift ^ 4);

        let c = &mut self.cstate;
        let table_error = |msg: &'static str| {
            a.set_error(ARCHIVE_ERRNO_FILE_FORMAT, Some(msg.as_bytes()));
            Stop::Err(Error::silent(ARCHIVE_FAILED))
        };
        if !c.bd.create(&bit_length, HUFF_BC) {
            return Err(table_error("Decoding huffman tables failed"));
        }

        let mut i = 0;
        while i < HUFF_TABLE_SIZE {
            let Some(num) = c.bd.decode_number(a, br) else {
                return Err(table_error("Decoding huffman tables failed"));
            };

            if num < 16 {
                // 0..15: store directly
                table[i] = num as u8;
                i += 1;
            } else {
                let Some(mut n) = br.read_bits_16(a) else {
                    return Err(silent_fatal());
                };

                if num == 16 || num == 18 {
                    n >>= 13;
                    n += 3;
                    br.skip_bits(3);
                } else {
                    n >>= 9;
                    n += 11;
                    br.skip_bits(7);
                }

                if num < 18 {
                    // 16..17: repeat previous code
                    if i == 0 {
                        return Err(table_error("Unexpected error when decoding huffman tables"));
                    }
                    for _ in 0..n {
                        if i >= HUFF_TABLE_SIZE {
                            break;
                        }
                        table[i] = table[i - 1];
                        i += 1;
                    }
                } else {
                    // other codes: fill with zeroes `n` times
                    for _ in 0..n {
                        if i >= HUFF_TABLE_SIZE {
                            break;
                        }
                        table[i] = 0;
                        i += 1;
                    }
                }
            }
        }

        let (literals, rest) = table.split_at(HUFF_NC);
        let (distances, rest) = rest.split_at(HUFF_DC);
        let (lower, repeating) = rest.split_at(HUFF_LDC);

        if !c.ld.create(literals, HUFF_NC) {
            return Err(table_error("Failed to create literal table"));
        }
        if !c.dd.create(distances, HUFF_DC) {
            return Err(table_error("Failed to create distance table"));
        }
        if !c.ldd.create(lower, HUFF_LDC) {
            return Err(table_error(
                "Failed to create lower bits of distances table",
            ));
        }
        if !c.rd.create(repeating, HUFF_RC) {
            return Err(table_error("Failed to create repeating distances table"));
        }

        Ok(())
    }

    /// The failure of a block that is corrupt: fatal in a solid archive,
    /// where the window is now unusable for the files that follow.
    fn block_error(&self, errno: c_int, msg: Option<&str>) -> Stop {
        let code = if self.main.solid {
            ARCHIVE_FATAL
        } else {
            ARCHIVE_FAILED
        };
        Stop::Err(match msg {
            Some(msg) => Error::new(code, errno, msg),
            None => Error::silent(code),
        })
    }

    fn decode_code_length(a: &Base, br: &mut BitReader<'_>, code: u16) -> Option<i32> {
        let code = i32::from(code);
        let (lbits, mut length) = if code < 8 {
            (0, 2 + code)
        } else {
            let lbits = code / 4 - 1;
            (lbits, 2 + ((4 | (code & 3)) << lbits))
        };

        if lbits > 0 {
            length += br.read_consume_bits(a, lbits as u32)? as i32;
        }

        Some(length)
    }

    fn copy_string(&mut self, a: &Base, len: i32, dist: i32) -> Res<()> {
        let c = &mut self.cstate;
        let cmask = c.window_mask as u64;
        let write_ptr = c.write_ptr.wrapping_add(c.solid_offset) as u64;

        if c.window.is_empty() {
            return Err(silent_fatal());
        }

        if c.write_ptr > self.file.unpacked_size
            || i64::from(len) > self.file.unpacked_size - c.write_ptr
        {
            a.set_error(
                ARCHIVE_ERRNO_FILE_FORMAT,
                Some(b"Uncompressed data exceeds declared size"),
            );
            return Err(self.block_error(ARCHIVE_ERRNO_FILE_FORMAT, None));
        }

        // The unpacker spends most of the time in this function.
        //
        // Just remember that this loop treats buffers that overlap
        // differently than buffers that do not overlap. This is why a simple
        // memmove will not do for those.
        let len = len as usize;
        let src = write_ptr.wrapping_sub(dist as i64 as u64);
        let (w, s) = ((write_ptr & cmask) as usize, (src & cmask) as usize);
        let window_size = cmask as usize + 1;
        if w + len <= window_size && s + len <= window_size && (s + len <= w || w + len <= s) {
            c.window.copy_within(s..s + len, w);
        } else {
            for i in 0..len as u64 {
                let write_idx = (write_ptr.wrapping_add(i) & cmask) as usize;
                let read_idx = (src.wrapping_add(i) & cmask) as usize;
                let b = c.window.get(read_idx).copied();
                if let (Some(b), Some(dst)) = (b, c.window.get_mut(write_idx)) {
                    *dst = b;
                }
            }
        }

        c.write_ptr += len as i64;
        Ok(())
    }

    pub(super) fn do_uncompress_block(&mut self, a: &Base, br: &mut BitReader<'_>) -> Res<()> {
        let cmask = self.cstate.window_mask;
        let bit_size = 1 + i32::from(self.last_block_flags & 7);

        loop {
            let c = &mut self.cstate;
            if c.write_ptr - c.last_write_ptr > (c.window_size >> 1) {
                // Don't allow growing data by more than half of the window
                // size at a time. In such case, break the loop; next call to
                // this function will continue processing from this moment.
                break;
            }

            if br.pos.in_addr > br.block_size - 1
                || (br.pos.in_addr == br.block_size - 1 && br.pos.bit_addr >= bit_size)
            {
                // If the program counter is here, it means the function has
                // finished processing the block.
                c.block_parsing_finished = true;
                break;
            }

            // Decode the next literal.
            let Some(num) = c.ld.decode_number(a, br) else {
                return Err(Stop::Eof);
            };

            // Num holds a decompression literal, or 'command code'.
            //
            // - Values lower than 256 are just bytes. Those codes can be
            //   stored in the output buffer directly.
            //
            // - Code 256 defines a new filter, which is later used to
            //   transform the data block accordingly to the filter type. The
            //   data block needs to be fully uncompressed first.
            //
            // - Code bigger than 257 and smaller than 262 define a
            //   repetition pattern that should be copied from an already
            //   uncompressed chunk of data.
            if num < 256 {
                // Directly store the byte. A literal write emits one byte;
                // copy_string() checks len.
                if c.write_ptr >= self.file.unpacked_size {
                    a.set_error(
                        ARCHIVE_ERRNO_FILE_FORMAT,
                        Some(b"Uncompressed data exceeds declared size"),
                    );
                    return Err(self.block_error(ARCHIVE_ERRNO_FILE_FORMAT, None));
                }

                let write_idx = c.solid_offset.wrapping_add(c.write_ptr) & cmask;
                c.write_ptr += 1;

                if let Some(b) = c.window.get_mut(write_idx as usize) {
                    *b = num as u8;
                }
            } else if num >= 262 {
                let Some(mut len) = Self::decode_code_length(a, br, num - 262) else {
                    return Err(self.fail_decode(a, "Failed to decode the code length"));
                };
                let Some(dist_slot) = c.dd.decode_number(a, br) else {
                    return Err(self.fail_decode(a, "Failed to decode the distance slot"));
                };

                let mut dbits = 0;
                let mut dist: i32 = 1;
                if dist_slot < 4 {
                    dist += i32::from(dist_slot);
                } else {
                    dbits = u32::from(dist_slot) / 2 - 1;

                    // Wrapping, as the C int conversion of the unsigned sum.
                    dist =
                        (dist as u32).wrapping_add(u32::from(2 | (dist_slot & 1)) << dbits) as i32;
                }

                if dbits > 0 {
                    if dbits >= 4 {
                        if dbits > 4 {
                            // Return EOF if we can't read more data.
                            let Some(bits) = br.read_bits_32(a) else {
                                return Err(silent_fatal());
                            };

                            br.skip_bits(dbits - 4);
                            let add = (bits >> (36 - dbits)) << 4;
                            dist = (dist as u32).wrapping_add(add) as i32;
                        }

                        let Some(low_dist) = c.ldd.decode_number(a, br) else {
                            return Err(self.fail_decode(a, "Failed to decode the distance slot"));
                        };

                        if dist >= i32::MAX - i32::from(low_dist) - 1 {
                            // This only happens in invalid archives.
                            a.set_error(
                                ARCHIVE_ERRNO_FILE_FORMAT,
                                Some(b"Distance pointer overflow"),
                            );
                            return Err(self.block_error(ARCHIVE_ERRNO_FILE_FORMAT, None));
                        }

                        dist += i32::from(low_dist);
                    } else {
                        // dbits is one of [0,1,2,3]. Return EOF if we can't
                        // read more data.
                        let Some(add) = br.read_consume_bits(a, dbits) else {
                            return Err(silent_fatal());
                        };

                        dist += add as i32;
                    }
                }

                if dist > 0x100 {
                    len += 1;

                    if dist > 0x2000 {
                        len += 1;

                        if dist > 0x40000 {
                            len += 1;
                        }
                    }
                }

                let q = &mut c.dist_cache;
                *q = [dist, q[0], q[1], q[2]];
                c.last_len = len;

                self.copy_string(a, len, dist)?;
            } else if num == 256 {
                // Create a filter.
                self.parse_filter(a, br)?;
            } else if num == 257 {
                if c.last_len != 0 {
                    let (len, dist) = (c.last_len, c.dist_cache[0]);
                    self.copy_string(a, len, dist)?;
                }
            } else {
                // num < 262
                let idx = usize::from(num - 258);
                let q = &mut c.dist_cache;
                let dist = q[idx];
                q.copy_within(0..idx, 1);
                q[0] = dist;

                let Some(len_slot) = c.rd.decode_number(a, br) else {
                    return Err(self.block_error(ARCHIVE_ERRNO_FILE_FORMAT, None));
                };

                let Some(len) = Self::decode_code_length(a, br, len_slot) else {
                    return Err(self.block_error(ARCHIVE_ERRNO_FILE_FORMAT, None));
                };

                c.last_len = len;

                self.copy_string(a, len, dist)?;
            }
        }

        Ok(())
    }

    /// The failure of a decode step that left its own message, replaced by
    /// `msg`.
    fn fail_decode(&self, a: &Base, msg: &str) -> Stop {
        a.set_error(ARCHIVE_ERRNO_PROGRAMMER, Some(msg.as_bytes()));
        self.block_error(ARCHIVE_ERRNO_PROGRAMMER, None)
    }
}
