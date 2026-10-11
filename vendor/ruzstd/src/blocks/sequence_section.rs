//! Utilities and representations for the second half of a block, the sequence section.
//! This section copies literals from the literals section into the decompressed output.

use crate::decoding::errors::SequencesHeaderParseError;

pub(crate) const MAX_LITERAL_LENGTH_CODE: u8 = 35;
pub(crate) const MAX_MATCH_LENGTH_CODE: u8 = 52;
pub(crate) const MAX_OFFSET_CODE: u8 = 31;

pub struct SequencesHeader {
    pub num_sequences: u32,
    pub modes: Option<CompressionModes>,
}

/// This byte defines the compression mode of each symbol type
#[derive(Copy, Clone)]
pub struct CompressionModes(u8);
/// The compression mode used for symbol compression
pub enum ModeType {
    /// A predefined FSE distribution table is used, and no distribution table
    /// will be present.
    Predefined,
    /// The table consists of a single byte, which contains the symbol's value.
    #[allow(clippy::upper_case_acronyms)]
    RLE,
    /// Standard FSE compression, a distribution table will be present. This
    /// mode should not be used when only one symbol is present.
    FSECompressed,
    /// The table used in the previous compressed block with at least one sequence
    /// will be used again. If this is the first block, the table in the dictionary will
    /// be used.
    Repeat,
}

impl CompressionModes {
    /// Deserialize a two bit mode value into a [ModeType]
    pub fn decode_mode(m: u8) -> ModeType {
        match m {
            0 => ModeType::Predefined,
            1 => ModeType::RLE,
            2 => ModeType::FSECompressed,
            3 => ModeType::Repeat,
            _ => panic!("This can never happen"),
        }
    }
    /// Read the compression mode of the literal lengths field.
    pub fn ll_mode(self) -> ModeType {
        Self::decode_mode(self.0 >> 6)
    }

    /// Read the compression mode of the offset value field.
    pub fn of_mode(self) -> ModeType {
        Self::decode_mode((self.0 >> 4) & 0x3)
    }

    /// Read the compression mode of the match lengths field.
    pub fn ml_mode(self) -> ModeType {
        Self::decode_mode((self.0 >> 2) & 0x3)
    }
}

impl Default for SequencesHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl SequencesHeader {
    /// Create a new [SequencesHeader].
    pub fn new() -> SequencesHeader {
        SequencesHeader {
            num_sequences: 0,
            modes: None,
        }
    }

    /// Attempt to deserialize the provided buffer into `self`, returning the number of bytes read.
    pub fn parse_from_header(&mut self, source: &[u8]) -> Result<u8, SequencesHeaderParseError> {
        let mut bytes_read = 0;
        if source.is_empty() {
            return Err(SequencesHeaderParseError::NotEnoughBytes {
                need_at_least: 1,
                got: 0,
            });
        }

        match source[0] {
            0 => {
                self.num_sequences = 0;
                bytes_read += 1;
            }
            1..=127 => {
                if source.len() < 2 {
                    return Err(SequencesHeaderParseError::NotEnoughBytes {
                        need_at_least: 2,
                        got: source.len(),
                    });
                }
                self.num_sequences = u32::from(source[0]);
                self.modes = Some(CompressionModes(source[1]));
                bytes_read += 2;
            }
            128..=254 => {
                if source.len() < 2 {
                    return Err(SequencesHeaderParseError::NotEnoughBytes {
                        need_at_least: 2,
                        got: source.len(),
                    });
                }
                self.num_sequences = ((u32::from(source[0]) - 128) << 8) + u32::from(source[1]);
                bytes_read += 2;
                if self.num_sequences != 0 {
                    if source.len() < 3 {
                        return Err(SequencesHeaderParseError::NotEnoughBytes {
                            need_at_least: 3,
                            got: source.len(),
                        });
                    }
                    self.modes = Some(CompressionModes(source[2]));
                    bytes_read += 1;
                }
            }
            255 => {
                if source.len() < 4 {
                    return Err(SequencesHeaderParseError::NotEnoughBytes {
                        need_at_least: 4,
                        got: source.len(),
                    });
                }
                self.num_sequences = u32::from(source[1]) + (u32::from(source[2]) << 8) + 0x7F00;
                self.modes = Some(CompressionModes(source[3]));
                bytes_read += 4;
            }
        }

        Ok(bytes_read)
    }
}
