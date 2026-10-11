//! Core decompression functionality.
//!
//! # Using decompress with a wrapping buffer
//!
//! [`decompress`] and [`decompress_with_limit`] can be used with a wrapping buffer.
//!
//! To decompress with a wrapping buffer you must:
//! - not pass `TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF` flag
//! - pass an output buffer with a size of a power of 2
//! - pass an output buffer  with a size greater or equal to the decompression window
//!   (which cannot be more than 32KiB, so 32KiB is a safe size)
//! - pass the same buffer on each call without modification
//!
//! You must process return values so that:
//! - next call pass the input buffer without the first input bytes read skipped
//! - next call pass the same output buffer
//! - next call pass an out_pos incremented by the number of bytes output (wrapping to 0 if needed)
//! - do a next call only if return status is `NeedsMoreInput` or `NeedsMoreInput`
//!
//! [`decompress`] will write to any byte after `out_pos` in the output buffer, but will not
//! wrap around. This means that all bytes after `out_pos` must be saved while the ones before
//! do not have to.
//!
//! [`decompress_with_limit`] will write to any byte after `out_pos` but not more than `out_max`
//! and will not wrap around. This means that you can use the buffer as a ring buffer for your
//! application usage, as long as you keep track of the number of disposable bytes.

use super::*;
use crate::shared::{update_adler32, HUFFMAN_LENGTH_ORDER};
use ::core::cell::Cell;

use ::core::cmp;
use ::core::convert::TryInto;

use self::output_buffer::{InputWrapper, OutputBuffer};

#[cfg(feature = "serde")]
use crate::serde::big_array::BigArray;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const TINFL_LZ_DICT_SIZE: usize = 32_768;

/// Number of low bit buffer bits that index each main decode table. Longer
/// codes continue in subtables.
const LITLEN_TABLE_BITS: u32 = 11;
const DIST_TABLE_BITS: u32 = 8;
const HUFFLEN_TABLE_BITS: u32 = 7;
/// Main table plus the most subtable space a complete code can need, as
/// computed by zlib's `enough` for 288 symbols and 11 bits, and for 32
/// symbols and 8 bits, both with codes of up to 15 bits.
const LITLEN_TABLE_SIZE: usize = 2342;
const DIST_TABLE_SIZE: usize = 402;
const HUFFLEN_TABLE_SIZE: usize = 1 << HUFFLEN_TABLE_BITS;

// Decode table entries, after libdeflate's. Bits 0-7 hold the bits decoding
// the entry consumes: the codeword length plus a length's or distance's extra
// bits, or for a subtable pointer the main table bits. Bits 8-11 hold the
// codeword length (in a subtable, the bits past the main table; for a
// pointer, the subtable bits). Bits 16 and up hold the literal, the base, the
// code length symbol or the subtable start. Literal/length entries other than
// literals keep their symbol minus 256 in bits 25-29.
/// A subtable pointer, the end of block or an invalid symbol.
const ENTRY_EXCEPTIONAL: u32 = 1 << 15;
const ENTRY_SUBTABLE: u32 = 1 << 14;
const ENTRY_END_OF_BLOCK: u32 = 1 << 13;
const ENTRY_LITERAL: u32 = 1 << 31;
/// Fills the codespace an incomplete code leaves unused: a one-bit invalid
/// literal/length (symbol 286) or distance, as miniz has always decoded it.
const INVALID_ENTRY: u32 = ENTRY_EXCEPTIONAL | 30 << 25 | 1 << 8 | 1;

/// The parts of each symbol's entry that do not depend on its code.
const LITLEN_ENTRIES: [u32; MAX_HUFF_SYMBOLS_0] = {
    let mut entries = [0; MAX_HUFF_SYMBOLS_0];
    let mut symbol = 0;
    while symbol < MAX_HUFF_SYMBOLS_0 {
        entries[symbol] = if symbol < 256 {
            ENTRY_LITERAL | (symbol as u32) << 16
        } else if symbol == 256 {
            ENTRY_EXCEPTIONAL | ENTRY_END_OF_BLOCK
        } else if symbol < 286 {
            let i = symbol - 257;
            (LENGTH_BASE[i] as u32) << 16 | ((symbol - 256) as u32) << 25 | LENGTH_EXTRA[i] as u32
        } else {
            // 286 and 287 only occur in the fixed code and are invalid.
            ENTRY_EXCEPTIONAL | ((symbol - 256) as u32) << 25
        };
        symbol += 1;
    }
    entries
};
const DIST_ENTRIES: [u32; MAX_HUFF_SYMBOLS_1] = {
    let mut entries = [ENTRY_EXCEPTIONAL; MAX_HUFF_SYMBOLS_1];
    let mut symbol = 0;
    while symbol < 30 {
        entries[symbol] = (DIST_BASE[symbol] as u32) << 16
            | num_extra_bits_for_distance_code(symbol as u8) as u32;
        symbol += 1;
    }
    entries
};
const HUFFLEN_ENTRIES: [u32; MAX_HUFF_SYMBOLS_2] = {
    let mut entries = [0; MAX_HUFF_SYMBOLS_2];
    let mut symbol = 0;
    while symbol < MAX_HUFF_SYMBOLS_2 {
        entries[symbol] = (symbol as u32) << 16;
        symbol += 1;
    }
    entries
};

/// The literal/length symbol of a resolved entry.
#[inline]
const fn litlen_symbol(entry: u32) -> u32 {
    if entry & ENTRY_LITERAL != 0 {
        (entry >> 16) & 0xff
    } else {
        256 + ((entry >> 25) & 31)
    }
}

/// Looks up the code at the bottom of `bit_buf`, resolving any subtable, and
/// returns its entry and full codeword length. Bits past the buffered ones
/// must be zero; the entry is then right whenever its length is buffered.
#[inline]
fn lookup(table: &[u32], table_bits: u32, bit_buf: BitBuffer) -> (u32, u32) {
    let index = (bit_buf & ((1 << table_bits) - 1)) as usize;
    let entry = table.get(index).copied().unwrap_or(INVALID_ENTRY);
    if entry & ENTRY_SUBTABLE == 0 {
        return (entry, (entry >> 8) & 15);
    }
    let sub_bits = (entry >> 8) & 15;
    let index = (entry >> 16) as usize + ((bit_buf >> table_bits) & ((1 << sub_bits) - 1)) as usize;
    let entry = table.get(index).copied().unwrap_or(INVALID_ENTRY);
    (entry, table_bits + ((entry >> 8) & 15))
}

/// Builds the decode table of the canonical code `code_sizes`, whose
/// per-length `counts` are validated: the code is `complete`, or else has at
/// most one codeword, of length 1. Uses libdeflate's method: a codeword no
/// longer than the main table is stored once while the table is as long as
/// the codeword, then replicated by doubling the table.
fn build_table(
    table: &mut [u32],
    table_bits: u32,
    code_sizes: &[u8],
    counts: &[u16; 16],
    entries: &[u32],
    complete: bool,
) -> Option<()> {
    // Sort the symbols by codeword length, then by symbol: codeword order.
    let mut offsets = [0u16; 16];
    for len in 1..15 {
        offsets[len + 1] = offsets[len] + counts[len];
    }
    let mut sorted = [0u16; MAX_HUFF_SYMBOLS_0];
    for (symbol, &len) in code_sizes.iter().enumerate() {
        if len != 0 {
            let offset = offsets.get_mut(usize::from(len))?;
            *sorted.get_mut(usize::from(*offset))? = symbol as u16;
            *offset += 1;
        }
    }
    let mut sorted = sorted.iter().map(|&symbol| usize::from(symbol));
    let mut next_entry = |len: u32| Some(entries.get(sorted.next()?)? + (len << 8) + len);

    let main = table.get_mut(..1 << table_bits)?;
    if !complete {
        main.fill(INVALID_ENTRY);
        if counts[1] == 1 {
            let entry = next_entry(1)?;
            main.iter_mut().step_by(2).for_each(|e| *e = entry);
        }
        return Some(());
    }

    // `codeword` is bit-reversed, as codes are read from the low bits up.
    let mut codeword = 0usize;
    let mut len = 1;
    while counts[len as usize] == 0 {
        len += 1;
    }
    let mut count = counts[len as usize];
    let mut table_end = 1usize << len;
    while len <= table_bits {
        loop {
            *main.get_mut(codeword)? = next_entry(len)?;
            if codeword == table_end - 1 {
                // The last codeword, all ones.
                while table_end < main.len() {
                    main.copy_within(..table_end, table_end);
                    table_end <<= 1;
                }
                return Some(());
            }
            // Increment the codeword in canonical (reversed) bit order.
            let bit = 1 << (usize::BITS - 1 - (codeword ^ (table_end - 1)).leading_zeros());
            codeword = (codeword & (bit - 1)) | bit;
            count -= 1;
            if count == 0 {
                break;
            }
        }
        loop {
            len += 1;
            if len <= table_bits {
                main.copy_within(..table_end, table_end);
                table_end <<= 1;
            }
            count = *counts.get(len as usize)?;
            if count != 0 {
                break;
            }
        }
    }

    // Longer codewords go to subtables, each sized to hold every codeword
    // sharing its main table prefix.
    let main_mask = (1 << table_bits) - 1;
    table_end = 1 << table_bits;
    let mut prefix = usize::MAX;
    let mut start = 0;
    loop {
        if codeword & main_mask != prefix {
            prefix = codeword & main_mask;
            start = table_end;
            let mut sub_bits = len - table_bits;
            let mut used = u32::from(count);
            while used < 1 << sub_bits {
                sub_bits += 1;
                used = (used << 1) + u32::from(*counts.get((table_bits + sub_bits) as usize)?);
            }
            table_end = start + (1 << sub_bits);
            *table.get_mut(prefix)? = (start as u32) << 16
                | ENTRY_EXCEPTIONAL
                | ENTRY_SUBTABLE
                | sub_bits << 8
                | table_bits;
        }
        let entry = next_entry(len - table_bits)?;
        let stride = 1 << (len - table_bits);
        for slot in table
            .get_mut(start + (codeword >> table_bits)..table_end)?
            .iter_mut()
            .step_by(stride)
        {
            *slot = entry;
        }
        if codeword == (1 << len) - 1 {
            return Some(());
        }
        let bit = 1 << (usize::BITS - 1 - (codeword ^ ((1 << len) - 1)).leading_zeros());
        codeword = (codeword & (bit - 1)) | bit;
        count -= 1;
        while count == 0 {
            len += 1;
            count = *counts.get(len as usize)?;
        }
    }
}

/// The number of huffman tables used.
const MAX_HUFF_TABLES: usize = 3;
/// The length of the first (literal/length) huffman table.
const MAX_HUFF_SYMBOLS_0: usize = 288;
/// The length of the second (distance) huffman table.
const MAX_HUFF_SYMBOLS_1: usize = 32;
/// The length of the last (huffman code length) huffman table.
const MAX_HUFF_SYMBOLS_2: usize = 19;
const LITLEN_TABLE: usize = 0;
const DIST_TABLE: usize = 1;
const HUFFLEN_TABLE: usize = 2;
const LEN_CODES_SIZE: usize = 512;
const LEN_CODES_MASK: usize = LEN_CODES_SIZE - 1;

/// Flags to [`decompress()`] to control how inflation works.
///
/// These define bits for a bitmask argument.
pub mod inflate_flags {
    /// Should we try to parse a zlib header?
    ///
    /// If unset, the function will expect an RFC1951 deflate stream.  If set, it will expect a
    /// RFC1950 zlib wrapper around the deflate stream.
    pub const TINFL_FLAG_PARSE_ZLIB_HEADER: u32 = 1;

    /// There will be more input that hasn't been given to the decompressor yet.
    ///
    /// This is useful when you want to decompress what you have so far,
    /// even if you know there is probably more input that hasn't gotten here yet (_e.g._, over a
    /// network connection).  When [`decompress()`][super::decompress] reaches the end of the input
    /// without finding the end of the compressed stream, it will return
    /// [`TINFLStatus::NeedsMoreInput`][super::TINFLStatus::NeedsMoreInput] if this is set,
    /// indicating that you should get more data before calling again.  If not set, it will return
    /// [`TINFLStatus::FailedCannotMakeProgress`][super::TINFLStatus::FailedCannotMakeProgress]
    /// suggesting the stream is corrupt, since you claimed it was all there.
    pub const TINFL_FLAG_HAS_MORE_INPUT: u32 = 2;

    /// The output buffer should not wrap around.
    pub const TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF: u32 = 4;

    /// Calculate the adler32 checksum of the output data even if we're not inflating a zlib stream.
    ///
    /// If [`TINFL_FLAG_IGNORE_ADLER32`] is specified, it will override this.
    ///
    /// NOTE: Enabling/disabling this between calls to decompress will result in an incorrect
    /// checksum.
    pub const TINFL_FLAG_COMPUTE_ADLER32: u32 = 8;

    /// Ignore adler32 checksum even if we are inflating a zlib stream.
    ///
    /// Overrides [`TINFL_FLAG_COMPUTE_ADLER32`] if both are enabled.
    ///
    /// NOTE: This flag does not exist in miniz as it does not support this and is a
    /// custom addition for miniz_oxide.
    ///
    /// NOTE: Should not be changed from enabled to disabled after decompression has started,
    /// this will result in checksum failure (outside the unlikely event where the checksum happens
    /// to match anyway).
    pub const TINFL_FLAG_IGNORE_ADLER32: u32 = 64;

    /// Return [`TINFLStatus::BlockBoundary`][super::TINFLStatus::BlockBoundary]
    /// on reaching the boundary between deflate blocks. Calling [`decompress()`][super::decompress]
    /// again will resume decompression of the next block.
    #[cfg(feature = "block-boundary")]
    pub const TINFL_FLAG_STOP_ON_BLOCK_BOUNDARY: u32 = 128;
}

use self::inflate_flags::*;

const MIN_TABLE_SIZES: [u16; 3] = [257, 1, 4];

#[cfg(target_pointer_width = "64")]
type BitBuffer = u64;

#[cfg(not(target_pointer_width = "64"))]
type BitBuffer = u32;

/*
enum HuffmanTableType {
    LiteralLength = 0,
    Dist = 1,
    Huffman = 2,
}*/

/// Minimal data representing the [`DecompressorOxide`] state when it is between deflate blocks
/// (i.e. [`decompress()`] has returned [`TINFLStatus::BlockBoundary`]).
/// This can be serialized along with the last 32KiB of the output buffer, then passed to
/// [`DecompressorOxide::from_block_boundary_state()`] to resume decompression from the same point.
///
/// The Zlib/Adler32 fields can be ignored if you aren't using those features
/// ([`TINFL_FLAG_PARSE_ZLIB_HEADER`], [`TINFL_FLAG_COMPUTE_ADLER32`]).
/// When deserializing, you can reconstruct `bit_buf` from the previous byte in the input file
/// (if you still have access to it), so `num_bits` is the only field that is always required.
#[derive(Clone)]
#[cfg(feature = "block-boundary")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlockBoundaryState {
    /// The number of bits from the last byte of input consumed,
    /// that are needed for decoding the next deflate block.
    /// Value is in range `0..=7`
    pub num_bits: u8,

    /// The `num_bits` MSBs from the last byte of input consumed,
    /// that are needed for decoding the next deflate block.
    /// Stored in the LSBs of this field.
    pub bit_buf: u8,

    /// Zlib CMF
    pub z_header0: u32,
    /// Zlib FLG
    pub z_header1: u32,
    /// Adler32 checksum of the data decompressed so far
    pub check_adler32: u32,
}

#[cfg(feature = "block-boundary")]
impl Default for BlockBoundaryState {
    fn default() -> Self {
        BlockBoundaryState {
            num_bits: 0,
            bit_buf: 0,
            z_header0: 0,
            z_header1: 0,
            check_adler32: 1,
        }
    }
}

/// Main decompression struct.
///
#[cfg_attr(not(feature = "rustc-dep-of-std"), derive(Clone))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DecompressorOxide {
    /// Current state of the decompressor.
    state: core::State,
    /// Number of bits in the bit buffer.
    num_bits: u32,
    /// Zlib CMF
    z_header0: u32,
    /// Zlib FLG
    z_header1: u32,
    /// Adler32 checksum from the zlib header.
    z_adler32: u32,
    /// 1 if the current block is the last block, 0 otherwise.
    finish: u8,
    /// The type of the current block.
    /// or if in a dynamic block, which huffman table we are currently
    // initializing.
    block_type: u8,
    /// 1 if the adler32 value should be checked.
    check_adler32: u32,
    /// Last match distance.
    dist: u32,
    /// Variable used for match length, symbols, and a number of other things.
    counter: u32,
    /// Number of extra bits for the last length or distance code.
    num_extra: u8,
    /// Number of entries in each huffman table.
    table_sizes: [u16; MAX_HUFF_TABLES],
    /// Buffer of input data.
    bit_buf: BitBuffer,
    /// Decode tables.
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    litlen_table: [u32; LITLEN_TABLE_SIZE],
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    dist_table: [u32; DIST_TABLE_SIZE],
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    huff_table: [u32; HUFFLEN_TABLE_SIZE],

    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    code_size_literal: [u8; MAX_HUFF_SYMBOLS_0],
    code_size_dist: [u8; MAX_HUFF_SYMBOLS_1],
    code_size_huffman: [u8; MAX_HUFF_SYMBOLS_2],
    /// Raw block header.
    raw_header: [u8; 4],
    /// Huffman length codes.
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    // MAX_HUFF_SYMBOLS_0 + MAX_HUFF_SYMBOLS_1 + 137
    // Extended to 512 to allow masking to help evade bounds checks.
    len_codes: [u8; LEN_CODES_SIZE],
}

impl DecompressorOxide {
    /// Create a new tinfl_decompressor with all fields set to 0.
    pub fn new() -> DecompressorOxide {
        DecompressorOxide::default()
    }

    /// Set the current state to `Start`.
    #[inline]
    pub fn init(&mut self) {
        // The rest of the data is reset or overwritten when used.
        self.state = core::State::Start;
    }

    /// Returns the adler32 checksum of the currently decompressed data.
    /// Note: Will return Some(1) if decompressing zlib but ignoring adler32.
    #[inline]
    #[cfg(not(feature = "rustc-dep-of-std"))]
    pub fn adler32(&self) -> Option<u32> {
        if self.state != State::Start && !self.state.is_failure() && self.z_header0 != 0 {
            Some(self.check_adler32)
        } else {
            None
        }
    }

    /// Returns the adler32 that was read from the zlib header if it exists.
    #[inline]
    #[cfg(not(feature = "rustc-dep-of-std"))]
    pub fn adler32_header(&self) -> Option<u32> {
        if self.state != State::Start && self.state != State::BadZlibHeader && self.z_header0 != 0 {
            Some(self.z_adler32)
        } else {
            None
        }
    }

    /// Looks up the code at the bottom of `bit_buf` in the given table.
    #[inline]
    fn lookup(&self, table: usize, bit_buf: BitBuffer) -> (u32, u32) {
        match table {
            LITLEN_TABLE => lookup(&self.litlen_table, LITLEN_TABLE_BITS, bit_buf),
            DIST_TABLE => lookup(&self.dist_table, DIST_TABLE_BITS, bit_buf),
            _ => lookup(&self.huff_table, HUFFLEN_TABLE_BITS, bit_buf),
        }
    }

    // Get zlib header for tests
    // Only for tests for now, may provide a proper function for this for later.
    #[cfg(all(test, feature = "with-alloc"))]
    pub(crate) const fn zlib_header(&self) -> (u32, u32) {
        (self.z_header0, self.z_header1)
    }

    /*fn code_size_table(&mut self, table_num: u8) -> &mut [u8] {
        match table_num {
            0 => &mut self.code_size_literal,
            1 => &mut self.code_size_dist,
            _ => &mut self.code_size_huffman,
        }
    }*/

    /// Returns the current [`BlockBoundaryState`]. Should only be called when
    /// [`decompress()`] has returned [`TINFLStatus::BlockBoundary`];
    /// otherwise this will return `None`.
    #[cfg(feature = "block-boundary")]
    pub fn block_boundary_state(&self) -> Option<BlockBoundaryState> {
        if self.state == core::State::ReadBlockHeader {
            // If we're in this state, undo_bytes should have emptied
            // bit_buf of any whole bytes
            assert!(self.num_bits < 8);

            Some(BlockBoundaryState {
                num_bits: self.num_bits as u8,
                bit_buf: self.bit_buf as u8,
                z_header0: self.z_header0,
                z_header1: self.z_header1,
                check_adler32: self.check_adler32,
            })
        } else {
            None
        }
    }

    /// Creates a new `DecompressorOxide` from the state returned by
    /// `block_boundary_state()`.
    ///
    /// When calling [`decompress()`], the 32KiB of `out` preceding `out_pos` must be
    /// initialized with the same data that it contained when `block_boundary_state()`
    /// was called.
    #[cfg(feature = "block-boundary")]
    pub fn from_block_boundary_state(st: &BlockBoundaryState) -> Self {
        DecompressorOxide {
            state: core::State::ReadBlockHeader,
            num_bits: st.num_bits as u32,
            bit_buf: st.bit_buf as BitBuffer,
            z_header0: st.z_header0,
            z_header1: st.z_header1,
            z_adler32: 1,
            check_adler32: st.check_adler32,
            ..DecompressorOxide::default()
        }
    }
}

impl Default for DecompressorOxide {
    /// Create a new tinfl_decompressor with all fields set to 0.
    #[inline(always)]
    fn default() -> Self {
        DecompressorOxide {
            state: core::State::Start,
            num_bits: 0,
            z_header0: 0,
            z_header1: 0,
            z_adler32: 0,
            finish: 0,
            block_type: 0,
            check_adler32: 0,
            dist: 0,
            counter: 0,
            num_extra: 0,
            table_sizes: [0; MAX_HUFF_TABLES],
            bit_buf: 0,
            litlen_table: [0; LITLEN_TABLE_SIZE],
            dist_table: [0; DIST_TABLE_SIZE],
            huff_table: [0; HUFFLEN_TABLE_SIZE],
            code_size_literal: [0; MAX_HUFF_SYMBOLS_0],
            code_size_dist: [0; MAX_HUFF_SYMBOLS_1],
            code_size_huffman: [0; MAX_HUFF_SYMBOLS_2],
            raw_header: [0; 4],
            len_codes: [0; LEN_CODES_SIZE],
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
enum State {
    Start = 0,
    ReadZlibCmf,
    ReadZlibFlg,
    ReadBlockHeader,
    BlockTypeNoCompression,
    RawHeader,
    RawMemcpy1,
    RawMemcpy2,
    ReadTableSizes,
    ReadHufflenTableCodeSize,
    ReadLitlenDistTablesCodeSize,
    ReadExtraBitsCodeSize,
    DecodeLitlen,
    WriteSymbol,
    ReadExtraBitsLitlen,
    DecodeDistance,
    ReadExtraBitsDistance,
    RawReadFirstByte,
    RawStoreFirstByte,
    WriteLenBytesToEnd,
    BlockDone,
    HuffDecodeOuterLoop1,
    HuffDecodeOuterLoop2,
    ReadAdler32,

    DoneForever,

    // Failure states.
    BlockTypeUnexpected,
    BadCodeSizeSum,
    BadDistOrLiteralTableLength,
    BadTotalSymbols,
    BadZlibHeader,
    DistanceOutOfBounds,
    BadRawLength,
    BadCodeSizeDistPrevLookup,
    InvalidLitlen,
    InvalidDist,
}

impl State {
    #[cfg(not(feature = "rustc-dep-of-std"))]
    const fn is_failure(self) -> bool {
        matches!(
            self,
            BlockTypeUnexpected
                | BadCodeSizeSum
                | BadDistOrLiteralTableLength
                | BadTotalSymbols
                | BadZlibHeader
                | DistanceOutOfBounds
                | BadRawLength
                | BadCodeSizeDistPrevLookup
                | InvalidLitlen
                | InvalidDist
        )
    }
}

use self::State::*;

// # Optimization
// We add a extra value at the end and make the tables 32 elements long
// so we can use a mask to avoid bounds checks.
// The invalid values are set to something high enough to avoid underflowing
// the match length.
/// Base length for each length code.
///
/// The base is used together with the value of the extra bits to decode the actual
/// length/distance values in a match.
#[rustfmt::skip]
const LENGTH_BASE: [u16; 32] = [
    3,  4,  5,  6,  7,  8,  9,  10,  11,  13,  15,  17,  19,  23,  27,  31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 512, 512, 512
];

/// Number of extra bits for each length code.
#[rustfmt::skip]
const LENGTH_EXTRA: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 0, 0, 0
];

/// Base length for each distance code.
#[rustfmt::skip]
const DIST_BASE: [u16; 30] = [
    1,    2,    3,    4,    5,    7,      9,      13,     17,     25,    33,
    49,   65,   97,   129,  193,  257,    385,    513,    769,    1025,  1537,
    2049, 3073, 4097, 6145, 8193, 12_289, 16_385, 24_577
];

/// Get the number of extra bits used for a distance code.
/// (Code numbers above `NUM_DISTANCE_CODES` will give some garbage
/// value.)
#[inline(always)]
const fn num_extra_bits_for_distance_code(code: u8) -> u8 {
    // TODO: Need to verify that this is faster on all platforms.
    // This can be easily calculated without a lookup.
    let c = code >> 1;
    c.saturating_sub(1)
}

/// The mask used when indexing the base/extra arrays.
const BASE_EXTRA_MASK: usize = 32 - 1;

/// Read an le u16 value from the slice iterator.
///
/// # Panics
/// Panics if there are less than two bytes left.
#[inline]
fn read_u16_le(iter: &mut InputWrapper) -> u16 {
    let ret = {
        let two_bytes = iter.as_slice()[..2].try_into().unwrap_or_default();
        u16::from_le_bytes(two_bytes)
    };
    iter.advance(2);
    ret
}

/// Ensure that there is data in the bit buffer.
///
/// On 64-bit platform, we use a 64-bit value so this will
/// result in there being at least 32 bits in the bit buffer.
/// This function assumes that there is at least 4 bytes left in the input buffer.
#[inline(always)]
#[cfg(target_pointer_width = "64")]
fn fill_bit_buffer(l: &mut LocalVars, in_iter: &mut InputWrapper) {
    // Read four bytes into the buffer at once.
    if l.num_bits < 30 {
        l.bit_buf |= BitBuffer::from(in_iter.read_u32_le()) << l.num_bits;
        l.num_bits += 32;
    }
}

/// Same as previous, but for non-64-bit platforms.
/// Ensures at least 16 bits are present, requires at least 2 bytes in the in buffer.
#[inline(always)]
#[cfg(not(target_pointer_width = "64"))]
fn fill_bit_buffer(l: &mut LocalVars, in_iter: &mut InputWrapper) {
    // If the buffer is 32-bit wide, read 2 bytes instead.
    if l.num_bits < 15 {
        l.bit_buf |= BitBuffer::from(read_u16_le(in_iter)) << l.num_bits;
        l.num_bits += 16;
    }
}

/// Check that the zlib header is correct and that there is enough space in the buffer
/// for the window size specified in the header.
///
/// See https://tools.ietf.org/html/rfc1950
#[inline]
const fn validate_zlib_header(cmf: u32, flg: u32, flags: u32, mask: usize) -> Action {
    let mut failed =
    // cmf + flg should be divisible by 31.
        (((cmf * 256) + flg) % 31 != 0) ||
    // If this flag is set, a dictionary was used for this zlib compressed data.
    // This is currently not supported by miniz or miniz-oxide
        ((flg & 0b0010_0000) != 0) ||
    // Compression method. Only 8(DEFLATE) is defined by the standard.
        ((cmf & 15) != 8);

    let window_size = 1 << ((cmf >> 4) + 8);
    if (flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF) == 0 {
        // Bail if the buffer is wrapping and the window size is larger than the buffer.
        failed |= (mask + 1) < window_size;
    }

    // Zlib doesn't allow window sizes above 32 * 1024.
    failed |= window_size > 32_768;

    if failed {
        Action::Jump(BadZlibHeader)
    } else {
        Action::Jump(ReadBlockHeader)
    }
}

enum Action {
    None,
    Jump(State),
    End(TINFLStatus),
}

/// Try to decode the next huffman code, and pass its decode table entry to `f`
/// if successful.
///
/// # Returns
/// The specified action returned from `f` on success,
/// `Action::End` if there are not enough data left to decode a symbol.
fn decode_huffman_code<F>(
    r: &mut DecompressorOxide,
    l: &mut LocalVars,
    table: usize,
    flags: u32,
    in_iter: &mut InputWrapper,
    f: F,
) -> Action
where
    F: FnOnce(&mut DecompressorOxide, &mut LocalVars, u32) -> Action,
{
    // As the huffman codes can be up to 15 bits long we need at least 15 bits
    // ready in the bit buffer to start decoding the next huffman code.
    if l.num_bits < 15 {
        // First, make sure there is enough data in the bit buffer to decode a huffman code.
        if in_iter.bytes_left() < 2 {
            // If there is less than 2 bytes left in the input buffer, we try to look up
            // the huffman code with what's available, and return if that doesn't succeed.
            // Original explanation in miniz:
            // /* TINFL_HUFF_BITBUF_FILL() is only used rarely, when the number of bytes
            //  * remaining in the input buffer falls below 2. */
            // /* It reads just enough bytes from the input stream that are needed to decode
            //  * the next Huffman code (and absolutely no more). It works by trying to fully
            //  * decode a */
            // /* Huffman code by using whatever bits are currently present in the bit buffer.
            //  * If this fails, it reads another byte, and tries again until it succeeds or
            //  * until the */
            // /* bit buffer contains >=15 bits (deflate's max. Huffman code size). */
            loop {
                if r.lookup(table, l.bit_buf).1 <= l.num_bits {
                    break;
                }

                // TODO: miniz jumps straight to here after getting here again after failing to read
                // a byte.
                // Doing that lets miniz avoid re-doing the lookup that that was done in the
                // previous call.
                let mut byte = 0;
                if let a @ Action::End(_) = read_byte(in_iter, flags, |b| {
                    byte = b;
                    Action::None
                }) {
                    return a;
                };

                // Do this outside closure for now to avoid borrowing r.
                l.bit_buf |= BitBuffer::from(byte) << l.num_bits;
                l.num_bits += 8;

                if l.num_bits >= 15 {
                    break;
                }
            }
        } else {
            // There is enough data in the input buffer, so read the next two bytes
            // and add them to the bit buffer.
            // Unwrapping here is fine since we just checked that there are at least two
            // bytes left.
            l.bit_buf |= BitBuffer::from(read_u16_le(in_iter)) << l.num_bits;
            l.num_bits += 16;
        }
    }

    // We now have at least 15 bits in the input buffer.
    let (entry, code_len) = r.lookup(table, l.bit_buf);
    l.bit_buf >>= code_len;
    l.num_bits -= code_len;
    f(r, l, entry)
}

/// Try to read one byte from `in_iter` and call `f` with the read byte as an argument,
/// returning the result.
/// If reading fails, `Action::End is returned`
#[inline]
fn read_byte<F>(in_iter: &mut InputWrapper, flags: u32, f: F) -> Action
where
    F: FnOnce(u8) -> Action,
{
    match in_iter.read_byte() {
        None => end_of_input(flags),
        Some(byte) => f(byte),
    }
}

// TODO: `l: &mut LocalVars` may be slow similar to decompress_fast (even with inline(always))
/// Try to read `amount` number of bits from `in_iter` and call the function `f` with the bits as an
/// an argument after reading, returning the result of that function, or `Action::End` if there are
/// not enough bytes left.
#[inline]
#[allow(clippy::while_immutable_condition)]
fn read_bits<F>(
    l: &mut LocalVars,
    amount: u32,
    in_iter: &mut InputWrapper,
    flags: u32,
    f: F,
) -> Action
where
    F: FnOnce(&mut LocalVars, BitBuffer) -> Action,
{
    // Clippy gives a false positive warning here due to the closure.
    // Read enough bytes from the input iterator to cover the number of bits we want.
    while l.num_bits < amount {
        let action = read_byte(in_iter, flags, |byte| {
            l.bit_buf |= BitBuffer::from(byte) << l.num_bits;
            l.num_bits += 8;
            Action::None
        });

        // If there are not enough bytes in the input iterator, return and signal that we need more.
        if !matches!(action, Action::None) {
            return action;
        }
    }

    let bits = l.bit_buf & ((1 << amount) - 1);
    l.bit_buf >>= amount;
    l.num_bits -= amount;
    f(l, bits)
}

#[inline]
fn pad_to_bytes<F>(l: &mut LocalVars, in_iter: &mut InputWrapper, flags: u32, f: F) -> Action
where
    F: FnOnce(&mut LocalVars) -> Action,
{
    let num_bits = l.num_bits & 7;
    read_bits(l, num_bits, in_iter, flags, |l, _| f(l))
}

#[inline]
const fn end_of_input(flags: u32) -> Action {
    Action::End(if flags & TINFL_FLAG_HAS_MORE_INPUT != 0 {
        TINFLStatus::NeedsMoreInput
    } else {
        TINFLStatus::FailedCannotMakeProgress
    })
}

#[inline]
fn undo_bytes(l: &mut LocalVars, max: u32) -> u32 {
    let res = cmp::min(l.num_bits >> 3, max);
    l.num_bits -= res << 3;
    res
}

fn start_static_table(r: &mut DecompressorOxide) {
    r.table_sizes[LITLEN_TABLE] = 288;
    r.table_sizes[DIST_TABLE] = 32;
    r.code_size_literal[0..144].fill(8);
    r.code_size_literal[144..256].fill(9);
    r.code_size_literal[256..280].fill(7);
    r.code_size_literal[280..288].fill(8);
    r.code_size_dist[0..32].fill(5);
}

fn init_tree(r: &mut DecompressorOxide, l: &mut LocalVars) -> Option<Action> {
    loop {
        let bt = r.block_type as usize;

        let (code_sizes, table, table_bits, entries): (&[u8], &mut [u32], _, &[u32]) = match bt {
            LITLEN_TABLE => (
                &r.code_size_literal,
                &mut r.litlen_table,
                LITLEN_TABLE_BITS,
                &LITLEN_ENTRIES,
            ),
            DIST_TABLE => (
                &r.code_size_dist,
                &mut r.dist_table,
                DIST_TABLE_BITS,
                &DIST_ENTRIES,
            ),
            HUFFLEN_TABLE => (
                &r.code_size_huffman,
                &mut r.huff_table,
                HUFFLEN_TABLE_BITS,
                &HUFFLEN_ENTRIES,
            ),
            _ => return None,
        };

        let mut total_symbols = [0u16; 16];

        let table_size = r.table_sizes[bt] as usize;
        if table_size > code_sizes.len() {
            return None;
        }
        let code_sizes = &code_sizes[..table_size];

        for &code_size in code_sizes {
            let cs = code_size as usize;
            // Code sizes are limited to max 15 according to the
            // deflate spec.
            // If it is larger than this, something has gone wrong...
            if cs >= total_symbols.len() {
                return None;
            }
            total_symbols[cs] += 1;
        }

        let mut total = 0u32;
        let mut max_code_len = 0u32;
        // Count up the total number of used lengths and check that the table
        // is not over-subscribed at any step (matching zlib's inftrees.c).
        {
            let mut left = 1i32;
            for (i, &ts) in total_symbols.iter().enumerate().skip(1) {
                if ts > 0 {
                    max_code_len = i as u32;
                }
                total += u32::from(ts);
                total <<= 1;

                left <<= 1;
                left -= i32::from(ts);
                if left < 0 {
                    // Over-subscribed: too many codes for the available bit space.
                    return Some(Action::Jump(BadTotalSymbols));
                }
            }
        }

        // A complete Huffman code has total == 65536 (2^16 after left-shifting
        // through all 15 possible code lengths). If total != 65536 the code is
        // incomplete (unused bit patterns remain).
        //
        // Per RFC 1951 and zlib's inftrees.c:
        // - Code length (hufflen) tables must always be complete.
        // - Literal/length and distance tables may be incomplete when
        //   max_code_len <= 1: either all symbols are unused (max_code_len == 0,
        //   e.g. a distance table with no backreferences) or a single symbol is
        //   encoded with a 1-bit code (e.g. an EOB-only litlen table).
        //   Tables with max_code_len > 1 that are incomplete are rejected, as
        //   they have multi-bit codes that don't form a valid prefix code.
        if total != 65_536 && (bt == HUFFLEN_TABLE || max_code_len > 1) {
            return Some(Action::Jump(BadTotalSymbols));
        }

        build_table(
            table,
            table_bits,
            code_sizes,
            &total_symbols,
            entries,
            total == 65_536,
        )?;

        if r.block_type == HUFFLEN_TABLE as u8 {
            l.counter = 0;
            return Some(Action::Jump(ReadLitlenDistTablesCodeSize));
        }

        if r.block_type == LITLEN_TABLE as u8 {
            break;
        }
        r.block_type -= 1;
    }

    l.counter = 0;

    Some(Action::Jump(DecodeLitlen))
}

// A helper macro for generating the state machine.
//
// As Rust doesn't have fallthrough on matches, we have to return to the match statement
// and jump for each state change. (Which would ideally be optimized away, but often isn't.)
macro_rules! generate_state {
    ($state: ident, $state_machine: tt, $f: expr) => {
        loop {
            match $f {
                Action::None => continue,
                Action::Jump(new_state) => {
                    $state = new_state;
                    continue $state_machine;
                },
                Action::End(result) => break $state_machine result,
            }
        }
    };
}

#[derive(Copy, Clone)]
struct LocalVars {
    pub bit_buf: BitBuffer,
    pub num_bits: u32,
    pub dist: u32,
    pub counter: u32,
    pub num_extra: u8,
}

#[inline]
fn transfer(
    out_slice: &mut [u8],
    mut source_pos: usize,
    mut out_pos: usize,
    match_len: usize,
    out_buf_size_mask: usize,
) {
    // special case that comes up surprisingly often. in the case that `source_pos`
    // is 1 less than `out_pos`, we can say that the entire range will be the same
    // value and optimize this to be a simple `memset`
    let source_diff = if source_pos > out_pos {
        source_pos - out_pos
    } else {
        out_pos - source_pos
    };

    // The last 3 bytes can wrap as those are dealt with separately at the end.
    // Use wrapping_sub rather than saturating for performance reasons here as
    // if source_pos + match_len  is < 3 we just want to jump to the end
    // condition anyhow.
    let not_wrapping = (out_buf_size_mask == usize::MAX)
        || ((source_pos + match_len).wrapping_sub(3) < out_slice.len());

    let end_pos = ((match_len >> 2) * 4) + out_pos;
    if not_wrapping && source_diff == 1 && out_pos > source_pos {
        let end = (match_len >> 2) * 4 + out_pos;
        let init = out_slice[out_pos - 1];
        out_slice[out_pos..end].fill(init);
        out_pos = end;
        source_pos = end - 1;
    // if the difference between `source_pos` and `out_pos` is greater than 3,
    // and we are not wrapping, we
    // can do slightly better than the naive case by copying everything at once
    } else if not_wrapping && out_pos > source_pos && (out_pos - source_pos >= 4) {
        let end_pos = cmp::min(end_pos, out_slice.len().saturating_sub(3));
        // Each chunk reads completed history: its width does not exceed
        // the match distance. Leave the existing four-byte/tail handling.
        if source_diff >= 64 {
            while end_pos.saturating_sub(out_pos) >= 64 {
                out_slice.copy_within(source_pos..source_pos + 64, out_pos);
                source_pos += 64;
                out_pos += 64;
            }
        }
        if source_diff >= 32 {
            while end_pos.saturating_sub(out_pos) >= 32 {
                out_slice.copy_within(source_pos..source_pos + 32, out_pos);
                source_pos += 32;
                out_pos += 32;
            }
        }
        if source_diff >= 16 {
            while end_pos.saturating_sub(out_pos) >= 16 {
                out_slice.copy_within(source_pos..source_pos + 16, out_pos);
                source_pos += 16;
                out_pos += 16;
            }
        }
        while out_pos < end_pos {
            out_slice.copy_within(source_pos..=source_pos + 3, out_pos);
            source_pos += 4;
            out_pos += 4;
        }
    } else {
        let end_pos = cmp::min(end_pos, out_slice.len().saturating_sub(3));
        while out_pos < end_pos {
            // Placing these assertions moves some bounds check before the accesses which
            // makes the compiler able to optimize better.
            // Ideally we would find a safe way to remove them entirely.
            assert!(out_pos + 3 < out_slice.len());
            assert!((source_pos + 3) & out_buf_size_mask < out_slice.len());

            out_slice[out_pos] = out_slice[source_pos & out_buf_size_mask];
            out_slice[out_pos + 1] = out_slice[(source_pos + 1) & out_buf_size_mask];
            out_slice[out_pos + 2] = out_slice[(source_pos + 2) & out_buf_size_mask];
            out_slice[out_pos + 3] = out_slice[(source_pos + 3) & out_buf_size_mask];
            source_pos += 4;
            out_pos += 4;
        }
    }

    match match_len & 3 {
        0 => (),
        1 => out_slice[out_pos] = out_slice[source_pos & out_buf_size_mask],
        2 => {
            assert!(out_pos + 1 < out_slice.len());
            assert!((source_pos + 1) & out_buf_size_mask < out_slice.len());
            out_slice[out_pos] = out_slice[source_pos & out_buf_size_mask];
            out_slice[out_pos + 1] = out_slice[(source_pos + 1) & out_buf_size_mask];
        }
        3 => {
            assert!(out_pos + 2 < out_slice.len());
            assert!((source_pos + 2) & out_buf_size_mask < out_slice.len());
            out_slice[out_pos] = out_slice[source_pos & out_buf_size_mask];
            out_slice[out_pos + 1] = out_slice[(source_pos + 1) & out_buf_size_mask];
            out_slice[out_pos + 2] = out_slice[(source_pos + 2) & out_buf_size_mask];
        }
        _ => unreachable!(),
    }
}

#[inline]
fn copy_disjoint(dst: &mut [u8], src: &[u8]) {
    let len = src.len();
    // Both ranges are disjoint and exactly the match length. Repeated writes
    // in the head/tail overlap use the same source bytes.
    if (4..=8).contains(&len) {
        dst[..4].copy_from_slice(&src[..4]);
        dst[len - 4..].copy_from_slice(&src[len - 4..]);
    } else if (9..=16).contains(&len) {
        dst[..8].copy_from_slice(&src[..8]);
        dst[len - 8..].copy_from_slice(&src[len - 8..]);
    } else if (17..=32).contains(&len) {
        dst[..16].copy_from_slice(&src[..16]);
        dst[len - 16..].copy_from_slice(&src[len - 16..]);
    } else {
        dst.copy_from_slice(src);
    }
}

/// Presumes that there is at least match_len bytes in output left.
#[inline]
fn apply_match(
    out_slice: &mut [u8],
    out_pos: usize,
    dist: usize,
    match_len: usize,
    out_buf_size_mask: usize,
) {
    debug_assert!(out_pos.checked_add(match_len).unwrap() <= out_slice.len());

    let source_pos = out_pos.wrapping_sub(dist) & out_buf_size_mask;

    if match_len == 3 {
        let out_slice = Cell::from_mut(out_slice).as_slice_of_cells();
        if let Some(dst) = out_slice.get(out_pos..out_pos + 3) {
            // Moving bounds checks before any memory mutation allows the optimizer
            // combine them together.
            let src = out_slice
                .get(source_pos)
                .zip(out_slice.get((source_pos + 1) & out_buf_size_mask))
                .zip(out_slice.get((source_pos + 2) & out_buf_size_mask));
            if let Some(((a, b), c)) = src {
                // For correctness, the memory reads and writes have to be interleaved.
                // Cells make it possible for read and write references to overlap.
                dst[0].set(a.get());
                dst[1].set(b.get());
                dst[2].set(c.get());
            }
        }
        return;
    }

    if cfg!(not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64"
    ))) {
        // Other targets retain the scalar copy path. AArch64 uses the same
        // safe bulk copies as x86 for nonoverlapping, contiguous matches.
        transfer(out_slice, source_pos, out_pos, match_len, out_buf_size_mask);
        return;
    }

    if source_pos >= out_pos && (source_pos - out_pos) < match_len {
        transfer(out_slice, source_pos, out_pos, match_len, out_buf_size_mask);
    } else if match_len <= dist && source_pos + match_len < out_slice.len() {
        // Destination and source segments does not intersect and source does not wrap.
        // TODO: An invalid before start of data wrapping match reached here before
        // it was fixed (it wrapped around and ended overlapping again)- need
        // to check that we are not wrapping here.
        if source_pos < out_pos {
            let (from_slice, to_slice) = out_slice.split_at_mut(out_pos);
            copy_disjoint(
                &mut to_slice[..match_len],
                &from_slice[source_pos..source_pos + match_len],
            );
        } else {
            let (to_slice, from_slice) = out_slice.split_at_mut(source_pos);
            copy_disjoint(
                &mut to_slice[out_pos..out_pos + match_len],
                &from_slice[..match_len],
            );
        }
    } else {
        transfer(out_slice, source_pos, out_pos, match_len, out_buf_size_mask);
    }
}

/// Input bytes the fast loop needs at the top of an iteration: two eight-byte
/// refills, the second at most seven bytes past the first. Callers provide
/// eight more for the refill before the first iteration.
const FAST_INPUT_MARGIN: usize = 24;
/// Output bytes one fast loop iteration can write: two literals and a match.
const FAST_OUTPUT_MARGIN: usize = 2 + 258;

/// Adds the whole bytes at `window[*used..]` that fit to the bit buffer,
/// leaving 56 to 63 bits. The low byte of `bits_left` counts them; the bits
/// above them hold the input that follows, and the bits of `bits_left` above
/// its low byte are ignored.
#[inline(always)]
fn refill(
    bit_buf: &mut u64,
    bits_left: &mut u32,
    window: &[u8; FAST_INPUT_MARGIN],
    used: &mut usize,
) {
    let bytes: [u8; 8] = window[*used..*used + 8].try_into().unwrap_or_default();
    *bit_buf |= u64::from_le_bytes(bytes).wrapping_shl(*bits_left);
    *used += 7 - ((*bits_left as usize >> 3) & 7);
    *bits_left |= 56;
}

/// Removes the bits of `entry` from the bit buffer.
#[inline(always)]
fn consume(bit_buf: &mut u64, bits_left: &mut u32, entry: u32) {
    *bit_buf = bit_buf.wrapping_shr(entry);
    *bits_left = bits_left.wrapping_sub(entry);
}

/// The low `n % 64` bits of `bit_buf`.
#[inline(always)]
fn low_bits(bit_buf: u64, n: u32) -> usize {
    (bit_buf & (1u64.wrapping_shl(n) - 1)) as usize
}

/// The extra bits of a length or distance entry, consumed from `saved`
/// together with the codeword.
#[inline(always)]
fn extra_bits(saved: u64, entry: u32) -> usize {
    low_bits(saved, entry) >> ((entry >> 8) & 15)
}

/// The state a literal/length entry that ends decoding leads to.
#[inline]
fn litlen_exit(entry: u32) -> (TINFLStatus, State) {
    if entry & ENTRY_END_OF_BLOCK != 0 {
        (TINFLStatus::Done, BlockDone)
    } else {
        (TINFLStatus::Failed, InvalidLitlen)
    }
}

// Called only for disjoint, exact-length slices between three and 32 bytes.
#[inline(always)]
fn copy_short_disjoint(dst: &mut [u8], src: &[u8]) {
    let len = src.len();
    let dst = &mut dst[..len];
    if len <= 4 {
        dst[..2].copy_from_slice(&src[..2]);
        dst[len - 2..].copy_from_slice(&src[len - 2..]);
    } else if len <= 8 {
        dst[..4].copy_from_slice(&src[..4]);
        dst[len - 4..].copy_from_slice(&src[len - 4..]);
    } else if len <= 16 {
        dst[..8].copy_from_slice(&src[..8]);
        dst[len - 8..].copy_from_slice(&src[len - 8..]);
    } else {
        dst[..16].copy_from_slice(&src[..16]);
        dst[len - 16..].copy_from_slice(&src[len - 16..]);
    }
}

/// Copies a match whose source lies wholly before `pos`, overlapping the
/// destination byte by byte as LZ77 requires.
#[inline(always)]
fn copy_match(out: &mut [u8], pos: usize, dist: usize, len: usize) {
    let source = pos - dist;
    if dist < len {
        transfer(out, source, pos, len, usize::MAX);
        return;
    }
    let (history, output) = out.split_at_mut(pos);
    let source = &history[source..source + len];
    if len <= 32 {
        copy_short_disjoint(output, source);
    } else {
        output[..len].copy_from_slice(source);
    }
}

/// Fast inner decompression loop, run while the input and output have room
/// for an iteration without bounds checks: up to three literals, or two and a
/// match. It decodes through libdeflate-style tables whose entries carry each
/// symbol's literal or base and extra bit count, keeps 56 or more bits
/// buffered with branchless eight-byte refills, and looks up each next
/// literal/length entry before refilling. It stops at a symbol boundary with
/// the bit position, output and state the state machine would reach.
fn decompress_fast(
    r: &mut DecompressorOxide,
    in_iter: &mut InputWrapper,
    out_buf: &mut OutputBuffer,
    flags: u32,
    local_vars: &mut LocalVars,
    out_buf_size_mask: usize,
) -> (TINFLStatus, State) {
    let input = in_iter.as_slice();
    let mut pos = out_buf.position();
    let out_end = pos + out_buf.bytes_left();
    let out = out_buf.get_mut();
    let (Some(in_limit), Some(out_limit)) = (
        input.len().checked_sub(FAST_INPUT_MARGIN),
        cmp::min(out_end, out.len()).checked_sub(FAST_OUTPUT_MARGIN),
    ) else {
        return (TINFLStatus::Done, DecodeLitlen);
    };
    let litlen = &r.litlen_table;
    let dists = &r.dist_table;
    let litlen_mask = (1 << LITLEN_TABLE_BITS) - 1;
    let dist_mask = (1 << DIST_TABLE_BITS) - 1;
    // A no-op where BitBuffer is u64; other targets buffer 32 bits.
    #[allow(clippy::useless_conversion)]
    let mut bit_buf = u64::from(local_vars.bit_buf);
    let mut bits_left = local_vars.num_bits;
    let mut in_pos = 0;
    if let Some(window) = input.first_chunk() {
        refill(&mut bit_buf, &mut bits_left, window, &mut in_pos);
    }
    let mut entry = litlen[(bit_buf & litlen_mask) as usize];

    // Each iteration starts with 56 or more bits buffered and `entry` looked
    // up from them.
    let (status, state) = loop {
        if in_pos > in_limit || pos > out_limit {
            break (TINFLStatus::Done, DecodeLitlen);
        }
        let Some(window) = input[in_pos..].first_chunk() else {
            break (TINFLStatus::Done, DecodeLitlen);
        };
        let mut used = 0;
        let exit = 'iteration: {
            let dst: &mut [u8; FAST_OUTPUT_MARGIN] = match out[pos..].first_chunk_mut() {
                Some(dst) => dst,
                None => break 'iteration Some((TINFLStatus::Done, DecodeLitlen)),
            };
            let mut saved = bit_buf;
            consume(&mut bit_buf, &mut bits_left, entry);
            let mut written = 0;
            if entry & ENTRY_LITERAL != 0 {
                // The bits buffered cover two more literals and a length.
                dst[0] = (entry >> 16) as u8;
                entry = litlen[(bit_buf & litlen_mask) as usize];
                saved = bit_buf;
                consume(&mut bit_buf, &mut bits_left, entry);
                written = 1;
                if entry & ENTRY_LITERAL != 0 {
                    dst[1] = (entry >> 16) as u8;
                    entry = litlen[(bit_buf & litlen_mask) as usize];
                    saved = bit_buf;
                    consume(&mut bit_buf, &mut bits_left, entry);
                    written = 2;
                    if entry & ENTRY_LITERAL != 0 {
                        dst[2] = (entry >> 16) as u8;
                        entry = litlen[(bit_buf & litlen_mask) as usize];
                        refill(&mut bit_buf, &mut bits_left, window, &mut used);
                        pos += 3;
                        break 'iteration None;
                    }
                }
            }
            pos += written;
            if entry & ENTRY_EXCEPTIONAL != 0 {
                if entry & ENTRY_SUBTABLE == 0 {
                    break 'iteration Some(litlen_exit(entry));
                }
                let index = (entry >> 16) as usize + low_bits(bit_buf, entry >> 8);
                entry = litlen.get(index).copied().unwrap_or(INVALID_ENTRY);
                saved = bit_buf;
                consume(&mut bit_buf, &mut bits_left, entry);
                if entry & ENTRY_LITERAL != 0 {
                    dst[written] = (entry >> 16) as u8;
                    entry = litlen[(bit_buf & litlen_mask) as usize];
                    refill(&mut bit_buf, &mut bits_left, window, &mut used);
                    pos += 1;
                    break 'iteration None;
                }
                if entry & ENTRY_EXCEPTIONAL != 0 {
                    break 'iteration Some(litlen_exit(entry));
                }
            }
            let len = ((entry >> 16) & 0x1ff) as usize + extra_bits(saved, entry);

            // Up to 42 bits are gone; 14 or more remain, of which a distance
            // needs up to 28. Refill as needed to also look up the next
            // literal/length entry once it is consumed.
            let mut dist_entry = dists[(bit_buf & dist_mask) as usize];
            if dist_entry & ENTRY_EXCEPTIONAL != 0 {
                if dist_entry & ENTRY_SUBTABLE != 0 {
                    if (bits_left & 0xff) < 28 + LITLEN_TABLE_BITS {
                        refill(&mut bit_buf, &mut bits_left, window, &mut used);
                    }
                    consume(&mut bit_buf, &mut bits_left, dist_entry);
                    let index = (dist_entry >> 16) as usize + low_bits(bit_buf, dist_entry >> 8);
                    dist_entry = dists.get(index).copied().unwrap_or(INVALID_ENTRY);
                }
                if dist_entry & ENTRY_EXCEPTIONAL != 0 {
                    consume(&mut bit_buf, &mut bits_left, dist_entry);
                    break 'iteration Some((TINFLStatus::Failed, InvalidDist));
                }
            } else if (bits_left & 0xff) < 21 + LITLEN_TABLE_BITS {
                refill(&mut bit_buf, &mut bits_left, window, &mut used);
            }
            saved = bit_buf;
            consume(&mut bit_buf, &mut bits_left, dist_entry);
            let dist = (dist_entry >> 16) as usize + extra_bits(saved, dist_entry);
            entry = litlen[(bit_buf & litlen_mask) as usize];
            refill(&mut bit_buf, &mut bits_left, window, &mut used);

            if dist <= pos {
                copy_match(out, pos, dist, len);
            } else if flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF != 0 || dist > out.len() {
                // We encountered a distance that refers a position before
                // the start of the decoded data, so we can't continue.
                break 'iteration Some((TINFLStatus::Failed, DistanceOutOfBounds));
            } else {
                apply_match(out, pos, dist, len, out_buf_size_mask);
            }
            pos += len;
            None
        };
        in_pos += used;
        if let Some(exit) = exit {
            break exit;
        }
    };

    // Return the whole bytes still buffered to the input, so the bit buffer
    // holds no more than the state machine's.
    let bits_left = bits_left & 0xff;
    let unused = cmp::min(bits_left as usize >> 3, in_pos);
    let bits_left = bits_left - 8 * unused as u32;
    in_iter.advance(in_pos - unused);
    out_buf.set_position(pos);
    local_vars.bit_buf = (bit_buf & ((1 << bits_left) - 1)) as BitBuffer;
    local_vars.num_bits = bits_left;
    (status, state)
}

/// Main decompression function. Keeps decompressing data from `in_buf` until the `in_buf` is
/// empty, `out` is full, the end of the deflate stream is hit, or there is an error in the
/// deflate stream.
///
/// # Arguments
///
/// `r` is a [`DecompressorOxide`] struct with the state of this stream.
///
/// `in_buf` is a reference to the compressed data that is to be decompressed. The decompressor will
/// start at the first byte of this buffer.
///
/// `out` is a reference to the buffer that will store the decompressed data, and that
/// stores previously decompressed data if any.
///
/// * The offset given by `out_pos` indicates where in the output buffer slice writing should start.
/// * If [`TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF`] is not set, the output buffer is used in a
///   wrapping manner, and it's size is required to be a power of 2.
/// * The decompression function normally needs access to 32KiB of the previously decompressed data
///   (or to the beginning of the decompressed data if less than 32KiB has been decompressed.)
///     - If this data is not available, decompression may fail.
///     - Some deflate compressors allow specifying a window size which limits match distances to
///       less than this, or alternatively an RLE mode where matches will only refer to the previous byte
///       and thus allows a smaller output buffer. The window size can be specified in the zlib
///       header structure, however, the header data should not be relied on to be correct.
///
/// `flags` indicates settings and status to the decompression function.
/// * The [`TINFL_FLAG_HAS_MORE_INPUT`] has to be specified if more compressed data is to be provided
///   in a subsequent call to this function.
/// * See the the [`inflate_flags`] module for details on other flags.
///
/// # Returns
///
/// Returns a tuple containing the status of the compressor, the number of input bytes read, and the
/// number of bytes output to `out`.
pub fn decompress(
    r: &mut DecompressorOxide,
    in_buf: &[u8],
    out: &mut [u8],
    out_pos: usize,
    flags: u32,
) -> (TINFLStatus, usize, usize) {
    decompress_with_limit(r, in_buf, out, out_pos, usize::MAX, flags)
}

/// Same as [`decompress()`] with a maximum decompressed byte count.
///
/// By default [`decompress()`] decompress untill end of `out` buffer if possible.
/// `decompress_with_limit` will stop when `out_max` bytes have been decompressed,
/// or when `out` buffer is full, whichever comes first.
///
/// This is especially useful when using a wrapping output buffer. This helps keeping
/// some data that has not yet been consumed in the buffer while decompressing new bytes.
///
/// `out_max` is the maximum number of *bytes* that decompress will write
pub fn decompress_with_limit(
    r: &mut DecompressorOxide,
    in_buf: &[u8],
    out: &mut [u8],
    out_pos: usize,
    out_max: usize,
    flags: u32,
) -> (TINFLStatus, usize, usize) {
    let out_buf_size_mask = if flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF != 0 {
        usize::MAX
    } else {
        // In the case of zero len, any attempt to write would produce HasMoreOutput,
        // so to gracefully process the case of there really being no output,
        // set the mask to all zeros.
        out.len().saturating_sub(1)
    };

    // Ensure the output buffer's size is a power of 2, unless the output buffer
    // is large enough to hold the entire output file (in which case it doesn't
    // matter).
    // Also make sure that the output buffer position is not past the end of the output buffer.
    if (out_buf_size_mask.wrapping_add(1) & out_buf_size_mask) != 0 || out_pos > out.len() {
        return (TINFLStatus::BadParam, 0, 0);
    }

    let mut in_iter = InputWrapper::from_slice(in_buf);

    let mut state = r.state;

    let mut out_buf = OutputBuffer::from_slice_pos_and_max(out, out_pos, out_max);

    // Make a local copy of the important variables here so we can work with them on the stack.
    let mut l = LocalVars {
        bit_buf: r.bit_buf,
        num_bits: r.num_bits,
        dist: r.dist,
        counter: r.counter,
        num_extra: r.num_extra,
    };

    let mut status = 'state_machine: loop {
        match state {
            Start => generate_state!(state, 'state_machine, {
                l.bit_buf = 0;
                l.num_bits = 0;
                l.dist = 0;
                l.counter = 0;
                l.num_extra = 0;
                r.z_header0 = 0;
                r.z_header1 = 0;
                r.z_adler32 = 1;
                r.check_adler32 = 1;
                if flags & TINFL_FLAG_PARSE_ZLIB_HEADER != 0 {
                    Action::Jump(State::ReadZlibCmf)
                } else {
                    Action::Jump(State::ReadBlockHeader)
                }
            }),

            ReadZlibCmf => generate_state!(state, 'state_machine, {
                read_byte(&mut in_iter, flags, |cmf| {
                    r.z_header0 = u32::from(cmf);
                    Action::Jump(State::ReadZlibFlg)
                })
            }),

            ReadZlibFlg => generate_state!(state, 'state_machine, {
                read_byte(&mut in_iter, flags, |flg| {
                    r.z_header1 = u32::from(flg);
                    validate_zlib_header(r.z_header0, r.z_header1, flags, out_buf_size_mask)
                })
            }),

            // Read the block header and jump to the relevant section depending on the block type.
            ReadBlockHeader => generate_state!(state, 'state_machine, {
                read_bits(&mut l, 3, &mut in_iter, flags, |l, bits| {
                    r.finish = (bits & 1) as u8;
                    r.block_type = ((bits >> 1) & 3) as u8;
                    match r.block_type {
                        0 => Action::Jump(BlockTypeNoCompression),
                        1 => {
                            start_static_table(r);
                            init_tree(r, l).unwrap_or(Action::End(TINFLStatus::Failed))
                        },
                        2 => {
                            l.counter = 0;
                            Action::Jump(ReadTableSizes)
                        },
                        3 => Action::Jump(BlockTypeUnexpected),
                        _ => unreachable!()
                    }
                })
            }),

            // Raw/Stored/uncompressed block.
            BlockTypeNoCompression => generate_state!(state, 'state_machine, {
                pad_to_bytes(&mut l, &mut in_iter, flags, |l| {
                    l.counter = 0;
                    Action::Jump(RawHeader)
                })
            }),

            // Check that the raw block header is correct.
            RawHeader => generate_state!(state, 'state_machine, {
                if l.counter < 4 {
                    // Read block length and block length check.
                    if l.num_bits != 0 {
                        read_bits(&mut l, 8, &mut in_iter, flags, |l, bits| {
                            r.raw_header[l.counter as usize] = bits as u8;
                            l.counter += 1;
                            Action::None
                        })
                    } else {
                        read_byte(&mut in_iter, flags, |byte| {
                            r.raw_header[l.counter as usize] = byte;
                            l.counter += 1;
                            Action::None
                        })
                    }
                } else {
                    // Check if the length value of a raw block is correct.
                    // The 2 first (2-byte) words in a raw header are the length and the
                    // ones complement of the length.
                    let length = u16::from(r.raw_header[0]) | (u16::from(r.raw_header[1]) << 8);
                    let check = u16::from(r.raw_header[2]) | (u16::from(r.raw_header[3]) << 8);
                    let valid = length == !check;
                    l.counter = length.into();

                    if !valid {
                        Action::Jump(BadRawLength)
                    } else if l.counter == 0 {
                        // Empty raw block. Sometimes used for synchronization.
                        Action::Jump(BlockDone)
                    } else if l.num_bits != 0 {
                        // There is some data in the bit buffer, so we need to write that first.
                        Action::Jump(RawReadFirstByte)
                    } else {
                        // The bit buffer is empty, so memcpy the rest of the uncompressed data from
                        // the block.
                        Action::Jump(RawMemcpy1)
                    }
                }
            }),

            // Read the byte from the bit buffer.
            RawReadFirstByte => generate_state!(state, 'state_machine, {
                read_bits(&mut l, 8, &mut in_iter, flags, |l, bits| {
                    l.dist = bits as u32;
                    Action::Jump(RawStoreFirstByte)
                })
            }),

            // Write the byte we just read to the output buffer.
            RawStoreFirstByte => generate_state!(state, 'state_machine, {
                if out_buf.bytes_left() == 0 {
                    Action::End(TINFLStatus::HasMoreOutput)
                } else {
                    out_buf.write_byte(l.dist as u8);
                    l.counter -= 1;
                    if l.counter == 0 || l.num_bits == 0 {
                        Action::Jump(RawMemcpy1)
                    } else {
                        // There is still some data left in the bit buffer that needs to be output.
                        // TODO: Changed this to jump to `RawReadfirstbyte` rather than
                        // `RawStoreFirstByte` as that seemed to be the correct path, but this
                        // needs testing.
                        Action::Jump(RawReadFirstByte)
                    }
                }
            }),

            RawMemcpy1 => generate_state!(state, 'state_machine, {
                if l.counter == 0 {
                    Action::Jump(BlockDone)
                } else if out_buf.bytes_left() == 0 {
                    Action::End(TINFLStatus::HasMoreOutput)
                } else {
                    Action::Jump(RawMemcpy2)
                }
            }),

            RawMemcpy2 => generate_state!(state, 'state_machine, {
                if in_iter.bytes_left() > 0 {
                    // Copy as many raw bytes as possible from the input to the output using memcpy.
                    // Raw block lengths are limited to 64 * 1024, so casting through usize and u32
                    // is not an issue.
                    let space_left = out_buf.bytes_left();
                    let bytes_to_copy = cmp::min(cmp::min(
                        space_left,
                        in_iter.bytes_left()),
                        l.counter as usize
                    );

                    out_buf.write_slice(&in_iter.as_slice()[..bytes_to_copy]);

                    in_iter.advance(bytes_to_copy);
                    l.counter -= bytes_to_copy as u32;
                    Action::Jump(RawMemcpy1)
                } else {
                    end_of_input(flags)
                }
            }),

            // Read how many huffman codes/symbols are used for each table.
            ReadTableSizes => generate_state!(state, 'state_machine, {
                if l.counter < 3 {
                    let num_bits = [5, 5, 4][l.counter as usize];
                    read_bits(&mut l, num_bits, &mut in_iter, flags, |l, bits| {
                        r.table_sizes[l.counter as usize] =
                            bits as u16 + MIN_TABLE_SIZES[l.counter as usize];
                        l.counter += 1;
                        Action::None
                    })
                } else {
                    r.code_size_huffman.fill(0);
                    l.counter = 0;
                    // Check that the litlen and distance are within spec.
                    // litlen table should be <=286 acc to the RFC and
                    // additionally zlib rejects dist table sizes larger than 30.
                    // NOTE this the final sizes after adding back predefined values, not
                    // raw value in the data.
                    // See miniz_oxide issue #130 and https://github.com/madler/zlib/issues/82.
                    if r.table_sizes[LITLEN_TABLE] <= 286 && r.table_sizes[DIST_TABLE] <= 30 {
                        Action::Jump(ReadHufflenTableCodeSize)
                    }
                    else {
                        Action::Jump(BadDistOrLiteralTableLength)
                    }
                }
            }),

            // Read the 3-bit lengths of the huffman codes describing the huffman code lengths used
            // to decode the lengths of the main tables.
            ReadHufflenTableCodeSize => generate_state!(state, 'state_machine, {
                if l.counter < r.table_sizes[HUFFLEN_TABLE].into() {
                    read_bits(&mut l, 3, &mut in_iter, flags, |l, bits| {
                        // These lengths are not stored in a normal ascending order, but rather one
                        // specified by the deflate specification intended to put the most used
                        // values at the front as trailing zero lengths do not have to be stored.
                        r.code_size_huffman[HUFFMAN_LENGTH_ORDER[l.counter as usize] as usize] =
                                bits as u8;
                        l.counter += 1;
                        Action::None
                    })
                } else {
                    r.table_sizes[HUFFLEN_TABLE] = MAX_HUFF_SYMBOLS_2 as u16;
                    init_tree(r, &mut l).unwrap_or(Action::End(TINFLStatus::Failed))
                }
            }),

            ReadLitlenDistTablesCodeSize => generate_state!(state, 'state_machine, {
                if l.counter < u32::from(r.table_sizes[LITLEN_TABLE]) + u32::from(r.table_sizes[DIST_TABLE]) {
                    decode_huffman_code(
                        r, &mut l, HUFFLEN_TABLE,
                        flags, &mut in_iter, |r, l, entry| {
                            l.dist = entry >> 16;
                            if l.dist < 16 {
                                r.len_codes[l.counter as usize & LEN_CODES_MASK] = l.dist as u8;
                                l.counter += 1;
                                Action::None
                            } else if l.dist == 16 && l.counter == 0 {
                                Action::Jump(BadCodeSizeDistPrevLookup)
                            } else {
                                // Last value is a dummy to allow mask.
                                l.num_extra = [2, 3, 7, 0][(l.dist as usize - 16) & 3];
                                Action::Jump(ReadExtraBitsCodeSize)
                            }
                        }
                    )
                } else if l.counter != u32::from(r.table_sizes[LITLEN_TABLE]) + u32::from(r.table_sizes[DIST_TABLE]) {
                    Action::Jump(BadCodeSizeSum)
                } else {

                    r.code_size_literal[..r.table_sizes[LITLEN_TABLE] as usize]
                        .copy_from_slice(&r.len_codes[..r.table_sizes[LITLEN_TABLE] as usize & LEN_CODES_MASK]);

                    let dist_table_start = r.table_sizes[LITLEN_TABLE] as usize;
                    debug_assert!(dist_table_start < r.len_codes.len());
                    let dist_table_end = (r.table_sizes[LITLEN_TABLE] +
                                          r.table_sizes[DIST_TABLE]) as usize;
                    let code_size_dist_end = r.table_sizes[DIST_TABLE] as usize;
                    debug_assert!(dist_table_end < r.len_codes.len());
                    debug_assert!(code_size_dist_end < r.code_size_dist.len());
                    let dist_table_start = dist_table_start & LEN_CODES_MASK;
                    let dist_table_end = dist_table_end & LEN_CODES_MASK;
                    r.code_size_dist[..code_size_dist_end & (MAX_HUFF_SYMBOLS_1 - 1)]
                        .copy_from_slice(&r.len_codes[dist_table_start..dist_table_end]);

                    r.block_type -= 1;
                    init_tree(r, &mut l).unwrap_or(Action::End(TINFLStatus::Failed))
                }
            }),

            ReadExtraBitsCodeSize => generate_state!(state, 'state_machine, {
                let num_extra = l.num_extra.into();
                read_bits(&mut l, num_extra, &mut in_iter, flags, |l, mut extra_bits| {
                    // Mask to avoid a bounds check.
                    // We can use 2 since the 2 first values are the same.
                    extra_bits += [3, 3, 11][(l.dist as usize - 16) & 2];
                    let val = if l.dist == 16 {
                        debug_assert!(l.counter as usize - 1 < r.len_codes.len());
                        r.len_codes[(l.counter as usize - 1) & LEN_CODES_MASK]
                    } else {
                        0
                    };

                    let fill_start = l.counter as usize;
                    let fill_end = l.counter as usize + extra_bits as usize;
                    debug_assert!(fill_start < r.len_codes.len());
                    debug_assert!(fill_end < r.len_codes.len());

                    r.len_codes[
                            fill_start & LEN_CODES_MASK..fill_end & LEN_CODES_MASK
                        ].fill(val);
                    l.counter += extra_bits as u32;
                    Action::Jump(ReadLitlenDistTablesCodeSize)
                })
            }),

            DecodeLitlen => generate_state!(state, 'state_machine, {
                if in_iter.bytes_left() < 4 || out_buf.bytes_left() < 2 {
                    // See if we can decode a literal with the data we have left.
                    // Jumps to next state (WriteSymbol) if successful.
                    decode_huffman_code(
                        r,
                        &mut l,
                        LITLEN_TABLE,
                        flags,
                        &mut in_iter,
                        |_r, l, entry| {
                            l.counter = litlen_symbol(entry);
                            Action::Jump(WriteSymbol)
                        },
                    )
                } else if
                // If there is enough space, use the fast inner decompression
                // function.
                    out_buf.bytes_left() >= FAST_OUTPUT_MARGIN &&
                    in_iter.bytes_left() >= FAST_INPUT_MARGIN + 8
                {
                    let (status, new_state) = decompress_fast(
                        r,
                        &mut in_iter,
                        &mut out_buf,
                        flags,
                        &mut l,
                        out_buf_size_mask,
                    );

                    state = new_state;
                    if status == TINFLStatus::Done {
                        Action::Jump(new_state)
                    } else {
                        Action::End(status)
                    }
                } else {
                    fill_bit_buffer(&mut l, &mut in_iter);

                    let (entry, code_len) = r.lookup(LITLEN_TABLE, l.bit_buf);

                    l.counter = litlen_symbol(entry);
                    l.bit_buf >>= code_len;
                    l.num_bits -= code_len;

                    if (l.counter & 256) != 0 {
                        // The symbol is not a literal.
                        Action::Jump(HuffDecodeOuterLoop1)
                    } else {
                        // If we have a 32-bit buffer we need to read another two bytes now
                        // to have enough bits to keep going.
                        if cfg!(not(target_pointer_width = "64")) {
                            fill_bit_buffer(&mut l, &mut in_iter);
                        }

                        let (entry, code_len) = r.lookup(LITLEN_TABLE, l.bit_buf);
                        let symbol = litlen_symbol(entry);

                            l.bit_buf >>= code_len;
                            l.num_bits -= code_len;
                            // The previous symbol was a literal, so write it directly and check
                            // the next one.
                            out_buf.write_byte(l.counter as u8);
                            if (symbol & 256) != 0 {
                                l.counter = symbol;
                                // The symbol is a length value.
                                Action::Jump(HuffDecodeOuterLoop1)
                            } else {
                                // The symbol is a literal, so write it directly and continue.
                                out_buf.write_byte(symbol as u8);
                                Action::None
                            }

                    }

                }
            }),

            WriteSymbol => generate_state!(state, 'state_machine, {
                if l.counter >= 256 {
                    Action::Jump(HuffDecodeOuterLoop1)
                } else if out_buf.bytes_left() > 0 {
                    out_buf.write_byte(l.counter as u8);
                    Action::Jump(DecodeLitlen)
                } else {
                    Action::End(TINFLStatus::HasMoreOutput)
                }
            }),

            HuffDecodeOuterLoop1 => generate_state!(state, 'state_machine, {
                // Mask the top bits since they may contain length info.
                l.counter &= 511;

                if l.counter
                    == 256 {
                    // We hit the end of block symbol.
                    Action::Jump(BlockDone)
                } else if l.counter > 285 {
                    // Invalid code.
                    // We already verified earlier that the code is > 256.
                    Action::Jump(InvalidLitlen)
                } else {
                    // # Optimization
                    // Mask the value to avoid bounds checks
                    // We could use get_unchecked later if can statically verify that
                    // this will never go out of bounds.
                    l.num_extra =
                        LENGTH_EXTRA[(l.counter - 257) as usize & BASE_EXTRA_MASK];
                    l.counter = u32::from(LENGTH_BASE[(l.counter - 257) as usize & BASE_EXTRA_MASK]);
                    // Length and distance codes have a number of extra bits depending on
                    // the base, which together with the base gives us the exact value.
                    if l.num_extra != 0 {
                        Action::Jump(ReadExtraBitsLitlen)
                    } else {
                        Action::Jump(DecodeDistance)
                    }
                }
            }),

            ReadExtraBitsLitlen => generate_state!(state, 'state_machine, {
                let num_extra = l.num_extra.into();
                read_bits(&mut l, num_extra, &mut in_iter, flags, |l, extra_bits| {
                    l.counter += extra_bits as u32;
                    Action::Jump(DecodeDistance)
                })
            }),

            DecodeDistance => generate_state!(state, 'state_machine, {
                // Try to read a huffman code from the input buffer and look up what
                // length code the decoded symbol refers to.
                decode_huffman_code(r, &mut l, DIST_TABLE, flags, &mut in_iter, |_r, l, entry| {
                    if entry & ENTRY_EXCEPTIONAL != 0 {
                        // Invalid distance code.
                        return Action::Jump(InvalidDist)
                    }
                    l.num_extra = ((entry & 0xff) - ((entry >> 8) & 15)) as u8;
                    l.dist = entry >> 16;
                    if l.num_extra != 0 {
                        // ReadEXTRA_BITS_DISTACNE
                        Action::Jump(ReadExtraBitsDistance)
                    } else {
                        Action::Jump(HuffDecodeOuterLoop2)
                    }
                })
            }),

            ReadExtraBitsDistance => generate_state!(state, 'state_machine, {
                let num_extra = l.num_extra.into();
                read_bits(&mut l, num_extra, &mut in_iter, flags, |l, extra_bits| {
                    l.dist += extra_bits as u32;
                    Action::Jump(HuffDecodeOuterLoop2)
                })
            }),

            HuffDecodeOuterLoop2 => generate_state!(state, 'state_machine, {
                if (l.dist as usize > out_buf.position() &&
                    (flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF != 0)) || (l.dist as usize > out_buf.get_ref().len())
                {
                    // We encountered a distance that refers a position before
                    // the start of the decoded data, so we can't continue.
                    Action::Jump(DistanceOutOfBounds)
                } else {
                    let out_pos = out_buf.position();
                    let source_pos = out_buf.position()
                        .wrapping_sub(l.dist as usize) & out_buf_size_mask;

                    let out_len = out_buf.bytes_left();
                    let match_end_pos = out_buf.position() + l.counter as usize;

                    if match_end_pos > out_len ||
                        // miniz doesn't do this check here. Not sure how it makes sure
                        // that this case doesn't happen.
                        (source_pos >= out_pos && (source_pos - out_pos) < l.counter as usize)
                    {
                        // Not enough space for all of the data in the output buffer,
                        // so copy what we have space for.
                        if l.counter == 0 {
                            Action::Jump(DecodeLitlen)
                        } else {
                            Action::Jump(WriteLenBytesToEnd)
                        }
                    } else {
                        apply_match(
                            out_buf.get_mut(),
                            out_pos,
                            l.dist as usize,
                            l.counter as usize,
                            out_buf_size_mask
                        );
                        out_buf.set_position(out_pos + l.counter as usize);
                        Action::Jump(DecodeLitlen)
                    }
                }
            }),

            WriteLenBytesToEnd => generate_state!(state, 'state_machine, {
                if out_buf.bytes_left() > 0 {
                    let out_pos = out_buf.position();
                    let source_pos = out_buf.position()
                        .wrapping_sub(l.dist as usize) & out_buf_size_mask;


                    let len = cmp::min(out_buf.bytes_left(), l.counter as usize);

                    transfer(out_buf.get_mut(), source_pos, out_pos, len, out_buf_size_mask);

                    out_buf.set_position(out_pos + len);
                    l.counter -= len as u32;
                    if l.counter == 0 {
                        Action::Jump(DecodeLitlen)
                    } else {
                        Action::None
                    }
                } else {
                    Action::End(TINFLStatus::HasMoreOutput)
                }
            }),

            BlockDone => generate_state!(state, 'state_machine, {
                // End once we've read the last block.
                if r.finish != 0 {
                    pad_to_bytes(&mut l, &mut in_iter, flags, |_| Action::None);

                    let in_consumed = in_buf.len() - in_iter.bytes_left();
                    let undo = undo_bytes(&mut l, in_consumed as u32) as usize;
                    in_iter = InputWrapper::from_slice(in_buf[in_consumed - undo..].iter().as_slice());

                    l.bit_buf &= ((1 as BitBuffer) << l.num_bits) - 1;
                    debug_assert_eq!(l.num_bits, 0);

                    if flags & TINFL_FLAG_PARSE_ZLIB_HEADER != 0 {
                        l.counter = 0;
                        Action::Jump(ReadAdler32)
                    } else {
                        Action::Jump(DoneForever)
                    }
                } else {
                    #[cfg(feature = "block-boundary")]
                    if flags & TINFL_FLAG_STOP_ON_BLOCK_BOUNDARY != 0 {
                        Action::End(TINFLStatus::BlockBoundary)
                    } else {
                        Action::Jump(ReadBlockHeader)
                    }
                    #[cfg(not(feature = "block-boundary"))]
                    {
                        Action::Jump(ReadBlockHeader)
                    }
                }
            }),

            ReadAdler32 => generate_state!(state, 'state_machine, {
                if l.counter < 4 {
                    if l.num_bits != 0 {
                        read_bits(&mut l, 8, &mut in_iter, flags, |l, bits| {
                            r.z_adler32 <<= 8;
                            r.z_adler32 |= bits as u32;
                            l.counter += 1;
                            Action::None
                        })
                    } else {
                        read_byte(&mut in_iter, flags, |byte| {
                            r.z_adler32 <<= 8;
                            r.z_adler32 |= u32::from(byte);
                            l.counter += 1;
                            Action::None
                        })
                    }
                } else {
                    Action::Jump(DoneForever)
                }
            }),

            // We are done.
            DoneForever => break TINFLStatus::Done,

            // Anything else indicates failure.
            // BadZlibHeader | BadRawLength | BadDistOrLiteralTableLength | BlockTypeUnexpected |
            // DistanceOutOfBounds |
            // BadTotalSymbols | BadCodeSizeDistPrevLookup | BadCodeSizeSum | InvalidLitlen |
            // InvalidDist | InvalidCodeLen
            _ => break TINFLStatus::Failed,
        };
    };

    let in_undo = if status != TINFLStatus::NeedsMoreInput
        && status != TINFLStatus::FailedCannotMakeProgress
    {
        undo_bytes(&mut l, (in_buf.len() - in_iter.bytes_left()) as u32) as usize
    } else {
        0
    };

    // If we're returning after completing a block, prepare for the next block when called again.
    #[cfg(feature = "block-boundary")]
    if status == TINFLStatus::BlockBoundary {
        state = State::ReadBlockHeader;
    }

    // Make sure HasMoreOutput overrides NeedsMoreInput if the output buffer is full.
    // (Unless the missing input is the adler32 value in which case we don't need to write anything.)
    // TODO: May want to see if we can do this in a better way.
    if status == TINFLStatus::NeedsMoreInput
        && out_buf.bytes_left() == 0
        && state != State::ReadAdler32
    {
        status = TINFLStatus::HasMoreOutput
    }

    r.state = state;
    r.bit_buf = l.bit_buf;
    r.num_bits = l.num_bits;
    r.dist = l.dist;
    r.counter = l.counter;
    r.num_extra = l.num_extra;

    r.bit_buf &= ((1 as BitBuffer) << r.num_bits) - 1;

    // If this is a zlib stream, and update the adler32 checksum with the decompressed bytes if
    // requested.
    let need_adler = if (flags & TINFL_FLAG_IGNORE_ADLER32) == 0 {
        flags & (TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_COMPUTE_ADLER32) != 0
    } else {
        // If TINFL_FLAG_IGNORE_ADLER32 is enabled, ignore the checksum.
        false
    };
    if need_adler && status as i32 >= 0 {
        let out_buf_pos = out_buf.position();
        r.check_adler32 = update_adler32(r.check_adler32, &out_buf.get_ref()[out_pos..out_buf_pos]);

        // disabled so that random input from fuzzer would not be rejected early,
        // before it has a chance to reach interesting parts of code
        if !cfg!(fuzzing) {
            // Once we are done, check if the checksum matches with the one provided in the zlib header.
            if status == TINFLStatus::Done
                && flags & TINFL_FLAG_PARSE_ZLIB_HEADER != 0
                && r.check_adler32 != r.z_adler32
            {
                status = TINFLStatus::Adler32Mismatch;
            }
        }
    }

    (
        status,
        in_buf.len() - in_iter.bytes_left() - in_undo,
        out_buf.position() - out_pos,
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn short_disjoint_copies_preserve_surrounding_bytes() {
        for len in 3..=32 {
            for source in 0..10 {
                for dist in [len, len + 1, 64] {
                    let position = source + dist;
                    let mut actual = [0u8; 160];
                    for (i, byte) in actual.iter_mut().enumerate() {
                        *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
                    }
                    let mut expected = actual;
                    for i in 0..len {
                        expected[position + i] = expected[source + i];
                    }
                    let (history, output) = actual.split_at_mut(position);
                    copy_short_disjoint(&mut output[..len], &history[source..source + len]);
                    assert_eq!(actual, expected, "len={len} source={source} dist={dist}");
                }
            }
        }
    }

    #[test]
    fn decode_tables_match_canonical_codes() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut random = |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as usize % n
        };
        for round in 0..300 {
            let (symbols, bits, entries): (usize, u32, &[u32]) = match round % 3 {
                0 => (286, LITLEN_TABLE_BITS, &LITLEN_ENTRIES),
                1 => (30, DIST_TABLE_BITS, &DIST_ENTRIES),
                _ => (19, HUFFLEN_TABLE_BITS, &HUFFLEN_ENTRIES),
            };
            let max_len = if bits == HUFFLEN_TABLE_BITS { 7 } else { 15 };
            // Split random leaves of a code tree, mostly the deepest one, to
            // get complete codes with long codewords; occasionally keep a
            // single 1-bit codeword or none, which only literal/length and
            // distance codes may have.
            let mut sizes = alloc::vec![0u8; symbols];
            let used = match random(20) {
                0 if bits != HUFFLEN_TABLE_BITS => 0,
                1 if bits != HUFFLEN_TABLE_BITS => 1,
                _ => 2 + random(symbols - 1),
            };
            let mut leaves = alloc::vec![if used == 1 { 1u8 } else { 0 }];
            while used > 1 && leaves.len() < used {
                let i = if random(4) == 0 {
                    random(leaves.len())
                } else {
                    (0..leaves.len()).max_by_key(|&i| leaves[i]).unwrap()
                };
                if leaves[i] < max_len {
                    leaves[i] += 1;
                    leaves.push(leaves[i]);
                } else if leaves.iter().all(|&l| l == max_len) {
                    break;
                }
            }
            for &len in leaves.iter().take(used) {
                let mut symbol = random(symbols);
                while sizes[symbol] != 0 {
                    symbol = (symbol + 1) % symbols;
                }
                sizes[symbol] = len;
            }
            let mut counts = [0u16; 16];
            sizes.iter().for_each(|&l| counts[l as usize] += 1);
            let complete = (1..16)
                .map(|l| u32::from(counts[l]) << (16 - l))
                .sum::<u32>()
                == 65536;
            let mut table = alloc::vec![0u32; LITLEN_TABLE_SIZE];
            build_table(&mut table, bits, &sizes, &counts, entries, complete).unwrap();

            // Canonical codewords, most significant bit first (RFC 1951).
            let mut next = [0u32; 16];
            let mut code = 0;
            for len in 1..16 {
                code = (code + u32::from(counts[len - 1]) * u32::from(len > 1)) << 1;
                next[len] = code;
            }
            let mut reference = alloc::vec![(INVALID_ENTRY, 1); 1 << 15];
            for (symbol, &len) in sizes.iter().enumerate() {
                if len == 0 {
                    continue;
                }
                let codeword = next[len as usize];
                next[len as usize] += 1;
                let reversed = (codeword.reverse_bits() >> (32 - len)) as usize;
                for slot in reference.iter_mut().skip(reversed).step_by(1 << len) {
                    *slot = (entries[symbol], u32::from(len));
                }
            }
            for (bit_buf, &(entry, len)) in reference.iter().enumerate() {
                let (actual, actual_len) = lookup(&table, bits, bit_buf as BitBuffer);
                assert_eq!(actual_len, len, "round {round} bits {bit_buf:#x}");
                // Entries agree apart from their codeword length fields,
                // which subtables count from the end of the main table.
                assert_eq!(
                    actual & !0xfff,
                    entry & !0xfff,
                    "round {round} bits {bit_buf:#x}"
                );
                let extra = (entry & 0xff).wrapping_sub((entry >> 8) & 15) & 0xff;
                let code_part = if actual_len > bits && len > bits {
                    len - bits
                } else {
                    len
                };
                if entry != INVALID_ENTRY {
                    assert_eq!(actual & 0xfff, code_part << 8 | (code_part + extra));
                }
            }
        }
    }

    //TODO: Fix these.

    fn tinfl_decompress_oxide<'i>(
        r: &mut DecompressorOxide,
        input_buffer: &'i [u8],
        output_buffer: &mut [u8],
        flags: u32,
    ) -> (TINFLStatus, &'i [u8], usize) {
        let (status, in_pos, out_pos) = decompress(r, input_buffer, output_buffer, 0, flags);
        (status, &input_buffer[in_pos..], out_pos)
    }

    #[test]
    fn decompress_zlib() {
        let encoded = [
            120, 156, 243, 72, 205, 201, 201, 215, 81, 168, 202, 201, 76, 82, 4, 0, 27, 101, 4, 19,
        ];
        let flags = TINFL_FLAG_COMPUTE_ADLER32 | TINFL_FLAG_PARSE_ZLIB_HEADER;

        let mut b = DecompressorOxide::new();
        const LEN: usize = 32;
        let mut b_buf = [0; LEN];

        // This should fail with the out buffer being to small.
        let b_status = tinfl_decompress_oxide(&mut b, &encoded[..], &mut b_buf, flags);

        assert!(b_status.0 == TINFLStatus::Failed);

        let flags = flags | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;

        b = DecompressorOxide::new();

        // With TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF set this should no longer fail.
        let b_status = tinfl_decompress_oxide(&mut b, &encoded[..], &mut b_buf, flags);

        assert_eq!(b_buf[..b_status.2], b"Hello, zlib!"[..]);
        assert!(b_status.0 == TINFLStatus::Done);
    }

    #[cfg(feature = "with-alloc")]
    #[test]
    fn raw_block() {
        const LEN: usize = 64;

        let text = b"Hello, zlib!";
        let encoded = {
            let len = text.len();
            let notlen = !len;
            let mut encoded = vec![
                1,
                len as u8,
                (len >> 8) as u8,
                notlen as u8,
                (notlen >> 8) as u8,
            ];
            encoded.extend_from_slice(&text[..]);
            encoded
        };

        //let flags = TINFL_FLAG_COMPUTE_ADLER32 | TINFL_FLAG_PARSE_ZLIB_HEADER |
        let flags = TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;

        let mut b = DecompressorOxide::new();

        let mut b_buf = [0; LEN];

        let b_status = tinfl_decompress_oxide(&mut b, &encoded[..], &mut b_buf, flags);
        assert_eq!(b_buf[..b_status.2], text[..]);
        assert_eq!(b_status.0, TINFLStatus::Done);
    }

    fn litlen_lookup(d: &DecompressorOxide, bit_buf: BitBuffer) -> (u32, u32) {
        let (entry, len) = d.lookup(LITLEN_TABLE, bit_buf);
        (litlen_symbol(entry), len)
    }

    fn dist_lookup(d: &DecompressorOxide, bit_buf: BitBuffer) -> (u32, u32, u32) {
        let (entry, len) = d.lookup(DIST_TABLE, bit_buf);
        (entry >> 16, (entry & 0xff) - len, len)
    }

    #[test]
    fn fixed_table_lookup() {
        let mut d = DecompressorOxide::new();
        d.block_type = 1;
        start_static_table(&mut d);
        let mut l = LocalVars {
            bit_buf: d.bit_buf,
            num_bits: d.num_bits,
            dist: d.dist,
            counter: d.counter,
            num_extra: d.num_extra,
        };
        init_tree(&mut d, &mut l).unwrap();
        assert_eq!(litlen_lookup(&d, 0b00001100), (0, 8));
        assert_eq!(litlen_lookup(&d, 0b00011110), (72, 8));
        assert_eq!(litlen_lookup(&d, 0b01011110), (74, 8));
        assert_eq!(litlen_lookup(&d, 0b11111101), (143, 8));
        assert_eq!(litlen_lookup(&d, 0b000010011), (144, 9));
        assert_eq!(litlen_lookup(&d, 0b111111111), (255, 9));
        assert_eq!(litlen_lookup(&d, 0b00000000), (256, 7));
        assert_eq!(litlen_lookup(&d, 0b1110100), (279, 7));
        assert_eq!(litlen_lookup(&d, 0b00000011), (280, 8));
        assert_eq!(litlen_lookup(&d, 0b11100011), (287, 8));

        // Symbols 0 and 5: bases 1 and 7, with 0 and 1 extra bits.
        assert_eq!(dist_lookup(&d, 0), (1, 0, 5));
        assert_eq!(dist_lookup(&d, 20), (7, 1, 5));
    }

    // Only run this test with alloc enabled as it uses a larger buffer.
    #[cfg(feature = "with-alloc")]
    fn check_result(input: &[u8], expected_status: TINFLStatus, expected_state: State, zlib: bool) {
        let mut r = DecompressorOxide::default();
        let mut output_buf = vec![0; 1024 * 32];
        let flags = if zlib {
            inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
        } else {
            0
        } | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF
            | TINFL_FLAG_HAS_MORE_INPUT;
        let (d_status, _in_bytes, _out_bytes) =
            decompress(&mut r, input, &mut output_buf, 0, flags);
        assert_eq!(expected_status, d_status);
        assert_eq!(expected_state, r.state);
    }

    #[cfg(feature = "with-alloc")]
    #[test]
    fn bogus_input() {
        use self::check_result as cr;
        const F: TINFLStatus = TINFLStatus::Failed;
        const OK: TINFLStatus = TINFLStatus::Done;
        // Bad CM.
        cr(&[0x77, 0x85], F, State::BadZlibHeader, true);
        // Bad window size (but check is correct).
        cr(&[0x88, 0x98], F, State::BadZlibHeader, true);
        // Bad check bits.
        cr(&[0x78, 0x98], F, State::BadZlibHeader, true);

        // Too many code lengths. (From inflate library issues)
        cr(
            b"M\xff\xffM*\xad\xad\xad\xad\xad\xad\xad\xcd\xcd\xcdM",
            F,
            State::BadDistOrLiteralTableLength,
            false,
        );

        // Bad CLEN (also from inflate library issues)
        cr(
            b"\xdd\xff\xff*M\x94ffffffffff",
            F,
            State::BadDistOrLiteralTableLength,
            false,
        );

        // Port of inflate coverage tests from zlib-ng
        // https://github.com/Dead2/zlib-ng/blob/develop/test/infcover.c
        let c = |a, b, c| cr(a, b, c, false);

        // Invalid uncompressed/raw block length.
        c(&[0, 0, 0, 0, 0], F, State::BadRawLength);
        // Ok empty uncompressed block.
        c(&[3, 0], OK, State::DoneForever);
        // Invalid block type.
        c(&[6], F, State::BlockTypeUnexpected);
        // Ok uncompressed block.
        c(&[1, 1, 0, 0xfe, 0xff, 0], OK, State::DoneForever);
        // Too many litlens, we handle this later than zlib, so this test won't
        // give the same result.
        //        c(&[0xfc, 0, 0], F, State::BadTotalSymbols);
        // Invalid set of code lengths - TODO Check if this is the correct error for this.
        c(&[4, 0, 0xfe, 0xff], F, State::BadTotalSymbols);
        // Invalid repeat in list of code lengths.
        // (Try to repeat a non-existent code.)
        c(&[4, 0, 0x24, 0x49, 0], F, State::BadCodeSizeDistPrevLookup);
        // Missing end of block code (should we have a separate error for this?) - fails on further input
        //    c(&[4, 0, 0x24, 0xe9, 0xff, 0x6d], F, State::BadTotalSymbols);
        // Invalid set of literals/lengths
        c(
            &[
                4, 0x80, 0x49, 0x92, 0x24, 0x49, 0x92, 0x24, 0x71, 0xff, 0xff, 0x93, 0x11, 0,
            ],
            F,
            State::BadTotalSymbols,
        );
        // Invalid set of distances _ needsmoreinput
        // c(&[4, 0x80, 0x49, 0x92, 0x24, 0x49, 0x92, 0x24, 0x0f, 0xb4, 0xff, 0xff, 0xc3, 0x84], F, State::BadTotalSymbols);
        // Invalid distance code
        c(&[2, 0x7e, 0xff, 0xff], F, State::InvalidDist);

        // Distance refers to position before the start
        c(
            &[0x0c, 0xc0, 0x81, 0, 0, 0, 0, 0, 0x90, 0xff, 0x6b, 0x4, 0],
            F,
            State::DistanceOutOfBounds,
        );

        // Trailer
        // Bad gzip trailer checksum GZip header not handled by miniz_oxide
        //cr(&[0x1f, 0x8b, 0x08 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0x03, 0, 0, 0, 0, 0x01], F, State::BadCRC, false)
        // Bad gzip trailer length
        //cr(&[0x1f, 0x8b, 0x08 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0x01], F, State::BadCRC, false)
    }

    #[test]
    fn empty_output_buffer_non_wrapping() {
        let encoded = [
            120, 156, 243, 72, 205, 201, 201, 215, 81, 168, 202, 201, 76, 82, 4, 0, 27, 101, 4, 19,
        ];
        let flags = TINFL_FLAG_COMPUTE_ADLER32
            | TINFL_FLAG_PARSE_ZLIB_HEADER
            | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
        let mut r = DecompressorOxide::new();
        let mut output_buf: [u8; 0] = [];
        // Check that we handle an empty buffer properly and not panicking.
        // https://github.com/Frommi/miniz_oxide/issues/23
        let res = decompress(&mut r, &encoded, &mut output_buf, 0, flags);
        assert!(res == (TINFLStatus::HasMoreOutput, 4, 0));
    }

    #[test]
    fn empty_output_buffer_wrapping() {
        let encoded = [
            0x73, 0x49, 0x4d, 0xcb, 0x49, 0x2c, 0x49, 0x55, 0x00, 0x11, 0x00,
        ];
        let flags = TINFL_FLAG_COMPUTE_ADLER32;
        let mut r = DecompressorOxide::new();
        let mut output_buf: [u8; 0] = [];
        // Check that we handle an empty buffer properly and not panicking.
        // https://github.com/Frommi/miniz_oxide/issues/23
        let res = decompress(&mut r, &encoded, &mut output_buf, 0, flags);
        assert!(res == (TINFLStatus::HasMoreOutput, 2, 0));
    }

    #[test]
    fn dist_extra_bits() {
        use self::num_extra_bits_for_distance_code;
        // Number of extra bits for each distance code.
        const DIST_EXTRA: [u8; 29] = [
            0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12,
            12, 13,
        ];

        for (i, &dist) in DIST_EXTRA.iter().enumerate() {
            assert_eq!(dist, num_extra_bits_for_distance_code(i as u8));
        }
    }

    #[test]
    fn check_tree() {
        let mut r = DecompressorOxide::new();
        let mut l = LocalVars {
            bit_buf: 0,
            num_bits: 0,
            dist: 0,
            counter: 0,
            num_extra: 0,
        };

        r.code_size_huffman[0] = 1;
        r.code_size_huffman[1] = 1;
        //r.code_size_huffman[2] = 3;
        //r.code_size_huffman[3] = 3;
        //r.code_size_huffman[1] = 4;
        r.block_type = HUFFLEN_TABLE as u8;
        r.table_sizes[HUFFLEN_TABLE] = 4;
        let res = init_tree(&mut r, &mut l).unwrap();

        let status = match res {
            Action::Jump(s) => s,
            _ => {
                //println!("issue");
                return;
            }
        };
        //println!("status {:?}", status);
        assert!(status != BadTotalSymbols);
    }

    #[cfg(feature = "with-alloc")]
    #[test]
    fn bulk_matches_preserve_wrapping_and_overlap_bytes() {
        for size in [8usize, 16, 32, 33, 64, 100, 128, 1000, 32768] {
            for out_pos in [0, 1, 3, 7, size / 2, size.saturating_sub(258), size - 1] {
                for dist in [
                    1usize, 2, 3, 4, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, size,
                ] {
                    if dist > size {
                        continue;
                    }
                    for length in [
                        0usize, 1, 2, 3, 4, 5, 7, 8, 9, 10, 15, 16, 17, 18, 24, 30, 31, 32, 33,
                        127, 128, 129, 47, 48, 49, 63, 64, 65, 255, 256, 257, 258,
                    ] {
                        if length > size - out_pos {
                            continue;
                        }
                        for mask in [size - 1, usize::MAX] {
                            if mask != usize::MAX && !size.is_power_of_two() {
                                continue;
                            }
                            if mask == usize::MAX && dist > out_pos {
                                continue;
                            }
                            let mut expected: alloc::vec::Vec<u8> =
                                (0..size).map(|i| (i * 73 + dist * 19) as u8).collect();
                            let mut actual = expected.clone();
                            let mut copied = expected.clone();
                            for i in 0..length {
                                expected[out_pos + i] =
                                    expected[(out_pos + i).wrapping_sub(dist) & mask];
                            }
                            apply_match(&mut actual, out_pos, dist, length, mask);
                            transfer(
                                &mut copied,
                                out_pos.wrapping_sub(dist) & mask,
                                out_pos,
                                length,
                                mask,
                            );
                            assert_eq!(copied, expected);
                            assert_eq!(
                                actual, expected,
                                "size={size} out={out_pos} distance={dist} length={length} mask={mask}"
                            );
                        }
                    }
                }
            }
        }
    }
}
