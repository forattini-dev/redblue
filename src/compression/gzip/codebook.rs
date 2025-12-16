//! Huffman CodeBook construction (RFC 1951 Section 3.2.2)
//!
//! Builds canonical Huffman codes from a list of code lengths.
//! The algorithm follows the exact specification in RFC 1951.

#![allow(clippy::needless_range_loop)]

use super::error::{GzipError, Result};

/// Maximum code length allowed by DEFLATE
pub const MAX_CODE_LENGTH: u32 = 15;

/// Maximum literal/length symbols
pub const MAX_LL_SYMBOLS: usize = 288;

/// Maximum distance symbols
pub const MAX_DIST_SYMBOLS: usize = 32;

/// A Huffman codebook mapping symbols to (code, length) pairs
pub struct CodeBook {
    /// (huffman_code, bit_length) for each symbol
    pub codes: Vec<(u32, u32)>,
    /// Maximum code length in this codebook
    pub max_length: u32,
}

impl CodeBook {
    /// Build a codebook from code lengths
    ///
    /// Follows RFC 1951 Section 3.2.2:
    /// 1. Count codes for each bit length
    /// 2. Find numerical value of smallest code for each length
    /// 3. Assign codes to symbols
    pub fn from_lengths(lengths: &[u32]) -> Result<Self> {
        if lengths.is_empty() || lengths.len() > MAX_LL_SYMBOLS + 1 {
            return Err(GzipError::InvalidCodeLengths);
        }

        // Find maximum length
        let max_length = *lengths.iter().max().unwrap_or(&0);
        if max_length > MAX_CODE_LENGTH {
            return Err(GzipError::InvalidCodeLengths);
        }

        if max_length == 0 {
            // All lengths are 0 - empty codebook
            return Ok(Self {
                codes: lengths.iter().map(|_| (0, 0)).collect(),
                max_length: 0,
            });
        }

        // Step 1: Count codes for each bit length
        let mut bl_count = [0u32; MAX_CODE_LENGTH as usize + 1];
        for &len in lengths {
            bl_count[len as usize] += 1;
        }

        // Step 2: Find smallest code value for each bit length
        let mut next_code = [0u32; MAX_CODE_LENGTH as usize + 1];
        let mut code = 0u32;
        bl_count[0] = 0; // Codes of length 0 don't exist

        for bits in 1..=max_length as usize {
            code = (code + bl_count[bits - 1]) << 1;
            next_code[bits] = code;
        }

        // Step 3: Assign codes to symbols
        let mut codes = Vec::with_capacity(lengths.len());
        for &len in lengths {
            if len == 0 {
                codes.push((0, 0));
            } else {
                let code = next_code[len as usize];
                next_code[len as usize] += 1;
                codes.push((code, len));
            }
        }

        Ok(Self { codes, max_length })
    }

    /// Build the fixed literal/length codebook (RFC 1951 Section 3.2.6)
    ///
    /// Lit Value    Bits   Codes
    /// ---------    ----   -----
    ///   0 - 143     8     00110000 through 10111111
    /// 144 - 255     9     110010000 through 111111111
    /// 256 - 279     7     0000000 through 0010111
    /// 280 - 287     8     11000000 through 11000111
    pub fn fixed_literal_length() -> Self {
        let mut lengths = [0u32; 288];

        // 0-143: 8 bits
        for i in 0..=143 {
            lengths[i] = 8;
        }
        // 144-255: 9 bits
        for i in 144..=255 {
            lengths[i] = 9;
        }
        // 256-279: 7 bits
        for i in 256..=279 {
            lengths[i] = 7;
        }
        // 280-287: 8 bits
        for i in 280..=287 {
            lengths[i] = 8;
        }

        Self::from_lengths(&lengths).expect("Fixed LL codebook should always be valid")
    }

    /// Build the fixed distance codebook (RFC 1951 Section 3.2.6)
    ///
    /// All 30 distance codes use 5 bits
    pub fn fixed_distance() -> Self {
        let lengths = [5u32; 30];
        Self::from_lengths(&lengths).expect("Fixed distance codebook should always be valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_ll_codebook() {
        let cb = CodeBook::fixed_literal_length();
        assert_eq!(cb.codes.len(), 288);
        assert_eq!(cb.max_length, 9);

        // Check some known values
        assert_eq!(cb.codes[0].1, 8); // Literal 0: 8 bits
        assert_eq!(cb.codes[144].1, 9); // Literal 144: 9 bits
        assert_eq!(cb.codes[256].1, 7); // End of block: 7 bits
        assert_eq!(cb.codes[280].1, 8); // Length code: 8 bits
    }

    #[test]
    fn test_fixed_dist_codebook() {
        let cb = CodeBook::fixed_distance();
        assert_eq!(cb.codes.len(), 30);
        assert_eq!(cb.max_length, 5);

        // All distance codes are 5 bits
        for (_, len) in &cb.codes {
            assert_eq!(*len, 5);
        }
    }

    #[test]
    fn test_custom_codebook() {
        // Simple example: symbols with lengths [2, 1, 3, 3]
        // Should produce:
        // Symbol 0: 10 (2 bits)
        // Symbol 1: 0 (1 bit)
        // Symbol 2: 110 (3 bits)
        // Symbol 3: 111 (3 bits)
        let lengths = [2, 1, 3, 3];
        let cb = CodeBook::from_lengths(&lengths).unwrap();

        assert_eq!(cb.codes[0], (0b10, 2));
        assert_eq!(cb.codes[1], (0b0, 1));
        assert_eq!(cb.codes[2], (0b110, 3));
        assert_eq!(cb.codes[3], (0b111, 3));
    }
}
