/// Huffman Decoder with lookup table optimization
///
/// Uses a two-level lookup table for fast decoding:
/// - Primary table: first 10 bits (handles most codes)
/// - Secondary table: remaining bits for longer codes

use super::codebook::CodeBook;
use super::error::{GzipError, Result};

/// Number of bits for primary lookup (handles codes up to 10 bits)
const PRIMARY_BITS: u32 = 10;

/// Packed decode result: symbol (9 bits) + code_length (4 bits) + extra_bits (4 bits) + value (15 bits)
#[derive(Clone, Copy, Default)]
pub struct DecodeResult(u32);

impl DecodeResult {
    /// Create a new decode result
    pub fn new(symbol: u32, code_length: u32, extra_bits: u32, base_value: u32) -> Self {
        // Pack: [extra_bits:4][base_value:15][code_length:4][symbol:9]
        Self((extra_bits << 28) | (base_value << 13) | (code_length << 9) | symbol)
    }

    /// Get the decoded symbol
    #[inline]
    pub fn symbol(&self) -> u32 {
        self.0 & 0x1FF
    }

    /// Get the code length in bits
    #[inline]
    pub fn code_length(&self) -> u32 {
        (self.0 >> 9) & 0xF
    }

    /// Get number of extra bits to read
    #[inline]
    pub fn extra_bits(&self) -> u32 {
        (self.0 >> 28) & 0xF
    }

    /// Get base value (before adding extra bits)
    #[inline]
    pub fn base_value(&self) -> u32 {
        (self.0 >> 13) & 0x7FFF
    }
}

/// Huffman decoder with two-level lookup table
pub struct HuffmanDecoder {
    /// Primary lookup table (indexed by reversed bit code)
    lookup: Vec<DecodeResult>,
    /// Mask for primary lookup
    primary_mask: u32,
    /// Mask for secondary lookup
    secondary_mask: u32,
}

impl HuffmanDecoder {
    /// Create an uninitialized decoder
    pub fn new() -> Self {
        Self {
            lookup: Vec::new(),
            primary_mask: 0,
            secondary_mask: 0,
        }
    }

    /// Initialize the decoder from a codebook
    ///
    /// `extra_table` provides (extra_bits, base_value) for length/distance symbols
    pub fn init(&mut self, codebook: &CodeBook, extra_table: &[(u32, u32); 32]) {
        self.lookup.clear();

        let max_bits = codebook.max_length;
        if max_bits == 0 {
            return;
        }

        // Determine table sizes
        let primary_bits = PRIMARY_BITS.min(max_bits);
        let secondary_bits = if max_bits > PRIMARY_BITS {
            max_bits - PRIMARY_BITS
        } else {
            0
        };

        self.primary_mask = (1 << primary_bits) - 1;
        self.secondary_mask = if secondary_bits > 0 {
            (1 << secondary_bits) - 1
        } else {
            0
        };

        // Count two-step codes for secondary table sizing
        let two_step_count = if secondary_bits > 0 {
            codebook
                .codes
                .iter()
                .filter(|(_, len)| *len > PRIMARY_BITS)
                .count()
        } else {
            0
        };

        // Allocate lookup table
        let primary_size = 1 << primary_bits;
        let secondary_size = two_step_count << secondary_bits;
        self.lookup
            .resize(primary_size + secondary_size, DecodeResult::default());

        let mut next_secondary = primary_size;

        // Populate the lookup table
        for (symbol, &(code, len)) in codebook.codes.iter().enumerate() {
            if len == 0 {
                continue;
            }

            // Get extra bits and base value for this symbol
            let (extra, base) = extra_table[symbol & 0x1F];
            let result = DecodeResult::new(symbol as u32, len, extra, base);

            // Reverse bit order for lookup (DEFLATE reads LSB first)
            let reversed = reverse_bits(code, len);

            if len <= primary_bits {
                // Single-step lookup: fill all entries with this prefix
                let fill_count = 1 << (primary_bits - len);
                for i in 0..fill_count {
                    let index = reversed | (i << len);
                    self.lookup[index as usize] = result;
                }
            } else {
                // Two-step lookup
                let primary_index = (reversed & self.primary_mask) as usize;

                // Check if we need to allocate secondary table
                let secondary_base = if self.lookup[primary_index].code_length() == 0 {
                    // First time seeing this primary index
                    let base = next_secondary;
                    next_secondary += 1 << secondary_bits;
                    // Store pointer to secondary table (use base_value field)
                    self.lookup[primary_index] = DecodeResult::new(0, len, 0, base as u32);
                    base
                } else {
                    self.lookup[primary_index].base_value() as usize
                };

                // Fill secondary table entries
                let secondary_code = reversed >> PRIMARY_BITS;
                let secondary_len = len - PRIMARY_BITS;
                let fill_count = 1 << (secondary_bits - secondary_len);

                for i in 0..fill_count {
                    let index = secondary_base + (secondary_code | (i << secondary_len)) as usize;
                    self.lookup[index] = result;
                }
            }
        }

        self.lookup.truncate(next_secondary);
    }

    /// Decode a symbol from the given bits
    ///
    /// `bits` should contain at least `max_length` bits, LSB-aligned
    #[inline]
    pub fn decode(&self, bits: u32) -> Result<DecodeResult> {
        let primary = self.lookup[(bits & self.primary_mask) as usize];

        match primary.code_length() {
            0 => Err(GzipError::HuffmanCodeNotFound),
            1..=PRIMARY_BITS => Ok(primary),
            _ => {
                // Two-step lookup
                let secondary_base = primary.base_value() as usize;
                let secondary_index = (bits >> PRIMARY_BITS) & self.secondary_mask;
                Ok(self.lookup[secondary_base + secondary_index as usize])
            }
        }
    }
}

impl Default for HuffmanDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Reverse the bit order of a value
#[inline]
fn reverse_bits(mut value: u32, num_bits: u32) -> u32 {
    let mut result = 0;
    for _ in 0..num_bits {
        result = (result << 1) | (value & 1);
        value >>= 1;
    }
    result
}

/// Extra bits and base values for literal/length codes 257-285
/// Index 0-28 corresponds to codes 257-285 (mapped via symbol & 0x1F after subtracting 256)
pub const LENGTH_EXTRA: [(u32, u32); 32] = [
    (0, 3),    // 257
    (0, 4),    // 258
    (0, 5),    // 259
    (0, 6),    // 260
    (0, 7),    // 261
    (0, 8),    // 262
    (0, 9),    // 263
    (0, 10),   // 264
    (1, 11),   // 265
    (1, 13),   // 266
    (1, 15),   // 267
    (1, 17),   // 268
    (2, 19),   // 269
    (2, 23),   // 270
    (2, 27),   // 271
    (2, 31),   // 272
    (3, 35),   // 273
    (3, 43),   // 274
    (3, 51),   // 275
    (3, 59),   // 276
    (4, 67),   // 277
    (4, 83),   // 278
    (4, 99),   // 279
    (4, 115),  // 280
    (5, 131),  // 281
    (5, 163),  // 282
    (5, 195),  // 283
    (5, 227),  // 284
    (0, 258),  // 285
    (0, 0),    // padding
    (0, 0),    // padding
    (0, 0),    // padding
];

/// Extra bits and base values for distance codes 0-29
pub const DISTANCE_EXTRA: [(u32, u32); 32] = [
    (0, 1),      // 0
    (0, 2),      // 1
    (0, 3),      // 2
    (0, 4),      // 3
    (1, 5),      // 4
    (1, 7),      // 5
    (2, 9),      // 6
    (2, 13),     // 7
    (3, 17),     // 8
    (3, 25),     // 9
    (4, 33),     // 10
    (4, 49),     // 11
    (5, 65),     // 12
    (5, 97),     // 13
    (6, 129),    // 14
    (6, 193),    // 15
    (7, 257),    // 16
    (7, 385),    // 17
    (8, 513),    // 18
    (8, 769),    // 19
    (9, 1025),   // 20
    (9, 1537),   // 21
    (10, 2049),  // 22
    (10, 3073),  // 23
    (11, 4097),  // 24
    (11, 6145),  // 25
    (12, 8193),  // 26
    (12, 12289), // 27
    (13, 16385), // 28
    (13, 24577), // 29
    (0, 0),      // padding
    (0, 0),      // padding
];

/// No-op extra table for literals (symbols 0-255)
pub const NO_EXTRA: [(u32, u32); 32] = [(0, 0); 32];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_bits() {
        assert_eq!(reverse_bits(0b101, 3), 0b101);
        assert_eq!(reverse_bits(0b100, 3), 0b001);
        assert_eq!(reverse_bits(0b110, 3), 0b011);
    }

    #[test]
    fn test_decode_result_packing() {
        let result = DecodeResult::new(42, 7, 3, 100);
        assert_eq!(result.symbol(), 42);
        assert_eq!(result.code_length(), 7);
        assert_eq!(result.extra_bits(), 3);
        assert_eq!(result.base_value(), 100);
    }
}
