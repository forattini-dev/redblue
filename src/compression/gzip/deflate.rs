/// DEFLATE Decompression (RFC 1951)
///
/// Implements the DEFLATE compression algorithm used in gzip, zlib, and PNG.
/// Supports all three block types:
/// - Type 0: Stored (uncompressed)
/// - Type 1: Fixed Huffman codes
/// - Type 2: Dynamic Huffman codes

use std::io::Read;

use super::bitread::BitReader;
use super::codebook::CodeBook;
use super::error::{GzipError, Result};
use super::huffman::{HuffmanDecoder, DISTANCE_EXTRA, LENGTH_EXTRA, NO_EXTRA};
use super::window::SlidingWindow;

/// End of block marker (symbol 256)
const END_OF_BLOCK: u32 = 256;

/// Order for reading code length code lengths (RFC 1951 Section 3.2.7)
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// DEFLATE decompressor
pub struct Deflate<R> {
    reader: BitReader<R>,
    window: SlidingWindow,
    /// Literal/length decoder for current block
    ll_decoder: HuffmanDecoder,
    /// Distance decoder for current block
    dist_decoder: HuffmanDecoder,
    /// Fixed literal/length codebook (cached)
    fixed_ll: Option<CodeBook>,
    /// Fixed distance codebook (cached)
    fixed_dist: Option<CodeBook>,
    /// Output buffer
    output: Vec<u8>,
    /// True if last block has been processed
    finished: bool,
}

impl<R: Read> Deflate<R> {
    /// Create a new DEFLATE decompressor
    pub fn new(reader: R) -> Self {
        Self {
            reader: BitReader::new(reader),
            window: SlidingWindow::new(),
            ll_decoder: HuffmanDecoder::new(),
            dist_decoder: HuffmanDecoder::new(),
            fixed_ll: None,
            fixed_dist: None,
            output: Vec::new(),
            finished: false,
        }
    }

    /// Decompress all data and return the result
    pub fn decompress(mut self) -> Result<Vec<u8>> {
        while !self.finished {
            self.decode_block()?;
        }
        Ok(self.output)
    }

    /// Decompress all data and return the result along with remaining bytes
    /// This is needed for gzip which has a footer after the DEFLATE stream
    pub fn decompress_with_remainder(mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        while !self.finished {
            self.decode_block()?;
        }
        // Align to byte boundary and get remaining buffered data
        self.reader.byte_align();
        let mut remainder = Vec::new();
        let _ = std::io::Read::read_to_end(&mut self.reader, &mut remainder);
        Ok((self.output, remainder))
    }

    /// Decode a single DEFLATE block
    fn decode_block(&mut self) -> Result<()> {
        // Read block header
        let bfinal = self.reader.read_bits(1)?;
        let btype = self.reader.read_bits(2)?;

        self.finished = bfinal == 1;

        match btype {
            0 => self.decode_stored_block(),
            1 => self.decode_fixed_block(),
            2 => self.decode_dynamic_block(),
            _ => Err(GzipError::InvalidBlockType),
        }
    }

    /// Decode a stored (uncompressed) block (type 0)
    fn decode_stored_block(&mut self) -> Result<()> {
        // Align to byte boundary
        self.reader.byte_align();

        // Read length and complement
        let len = self.reader.read_bits(16)? as u16;
        let nlen = self.reader.read_bits(16)? as u16;

        // Verify length
        if len != !nlen {
            return Err(GzipError::StoredLengthMismatch);
        }

        // Read literal data
        let mut buf = vec![0u8; len as usize];
        self.reader.read_exact(&mut buf)?;

        // Output and update window
        self.output.extend_from_slice(&buf);
        self.window.write_slice(&buf);

        Ok(())
    }

    /// Decode a block with fixed Huffman codes (type 1)
    fn decode_fixed_block(&mut self) -> Result<()> {
        // Build fixed codebooks if not cached
        if self.fixed_ll.is_none() {
            self.fixed_ll = Some(CodeBook::fixed_literal_length());
            self.fixed_dist = Some(CodeBook::fixed_distance());
        }

        // Initialize decoders
        self.ll_decoder
            .init(self.fixed_ll.as_ref().unwrap(), &NO_EXTRA);
        self.dist_decoder
            .init(self.fixed_dist.as_ref().unwrap(), &NO_EXTRA);

        self.decode_huffman_block()
    }

    /// Decode a block with dynamic Huffman codes (type 2)
    fn decode_dynamic_block(&mut self) -> Result<()> {
        // Read code counts
        let hlit = self.reader.read_bits(5)? as usize + 257; // literal/length codes
        let hdist = self.reader.read_bits(5)? as usize + 1; // distance codes
        let hclen = self.reader.read_bits(4)? as usize + 4; // code length codes

        // Read code length code lengths
        let mut cl_lengths = [0u32; 19];
        for i in 0..hclen {
            cl_lengths[CODE_LENGTH_ORDER[i]] = self.reader.read_bits(3)?;
        }

        // Build code length codebook
        let cl_codebook = CodeBook::from_lengths(&cl_lengths)?;
        let mut cl_decoder = HuffmanDecoder::new();
        cl_decoder.init(&cl_codebook, &NO_EXTRA);

        // Decode literal/length and distance code lengths
        let total_codes = hlit + hdist;
        let mut lengths = Vec::with_capacity(total_codes);

        while lengths.len() < total_codes {
            let bits = self.reader.peek_bits()?;
            let result = cl_decoder.decode(bits)?;
            self.reader.consume(result.code_length());

            let symbol = result.symbol();

            match symbol {
                0..=15 => {
                    // Literal code length
                    lengths.push(symbol);
                }
                16 => {
                    // Copy previous length 3-6 times
                    if lengths.is_empty() {
                        return Err(GzipError::InvalidDynamicCodebook);
                    }
                    let repeat = 3 + self.reader.read_bits(2)? as usize;
                    let prev = *lengths.last().unwrap();
                    for _ in 0..repeat {
                        lengths.push(prev);
                    }
                }
                17 => {
                    // Repeat zero 3-10 times
                    let repeat = 3 + self.reader.read_bits(3)? as usize;
                    for _ in 0..repeat {
                        lengths.push(0);
                    }
                }
                18 => {
                    // Repeat zero 11-138 times
                    let repeat = 11 + self.reader.read_bits(7)? as usize;
                    for _ in 0..repeat {
                        lengths.push(0);
                    }
                }
                _ => return Err(GzipError::InvalidDynamicCodebook),
            }
        }

        // Split into literal/length and distance code lengths
        let ll_lengths: Vec<u32> = lengths[..hlit].to_vec();
        let dist_lengths: Vec<u32> = lengths[hlit..].to_vec();

        // Build codebooks
        let ll_codebook = CodeBook::from_lengths(&ll_lengths)?;
        let dist_codebook = CodeBook::from_lengths(&dist_lengths)?;

        // Initialize decoders
        self.ll_decoder.init(&ll_codebook, &NO_EXTRA);
        self.dist_decoder.init(&dist_codebook, &NO_EXTRA);

        self.decode_huffman_block()
    }

    /// Decode compressed data using Huffman codes
    fn decode_huffman_block(&mut self) -> Result<()> {
        loop {
            // Decode literal/length symbol
            let bits = self.reader.peek_bits()?;
            let ll_result = self.ll_decoder.decode(bits)?;
            self.reader.consume(ll_result.code_length());

            let symbol = ll_result.symbol();

            if symbol < 256 {
                // Literal byte
                let byte = symbol as u8;
                self.output.push(byte);
                self.window.write_byte(byte);
            } else if symbol == END_OF_BLOCK {
                // End of block
                break;
            } else {
                // Length code (257-285)
                let length = self.decode_length(symbol)?;

                // Decode distance
                let dist_bits = self.reader.peek_bits()?;
                let dist_result = self.dist_decoder.decode(dist_bits)?;
                self.reader.consume(dist_result.code_length());

                let distance = self.decode_distance(dist_result.symbol())?;

                // Validate distance
                if !self.window.is_valid_distance(distance) {
                    return Err(GzipError::DistanceTooFar);
                }

                // Copy from history
                self.window
                    .copy_from_back(distance, length, &mut self.output);
            }
        }

        Ok(())
    }

    /// Decode length from symbol (257-285) and extra bits
    fn decode_length(&mut self, symbol: u32) -> Result<usize> {
        if symbol < 257 || symbol > 285 {
            return Err(GzipError::HuffmanCodeNotFound);
        }

        let index = (symbol - 257) as usize;
        let (extra_bits, base_value) = LENGTH_EXTRA[index];

        let extra = if extra_bits > 0 {
            self.reader.read_bits(extra_bits)?
        } else {
            0
        };

        Ok((base_value + extra) as usize)
    }

    /// Decode distance from symbol (0-29) and extra bits
    fn decode_distance(&mut self, symbol: u32) -> Result<usize> {
        if symbol > 29 {
            return Err(GzipError::HuffmanCodeNotFound);
        }

        let (extra_bits, base_value) = DISTANCE_EXTRA[symbol as usize];

        let extra = if extra_bits > 0 {
            self.reader.read_bits(extra_bits)?
        } else {
            0
        };

        Ok((base_value + extra) as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_block() {
        // DEFLATE stored block: bfinal=1, btype=00, len=5, nlen=!5, "Hello"
        // Binary: 1 00 (aligned) 05 00 FA FF H e l l o
        let data = [
            0b00000001, // bfinal=1, btype=00
            0x05,
            0x00, // len=5
            0xFA,
            0xFF, // nlen=!5
            b'H',
            b'e',
            b'l',
            b'l',
            b'o',
        ];

        let deflate = Deflate::new(&data[..]);
        let result = deflate.decompress().unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_fixed_block_hello() {
        // DEFLATE data from gzip of "Hello, World!\n"
        // This is just the DEFLATE portion (bytes 10 to len-8 from Python gzip)
        // Block type is fixed Huffman (bfinal=1, btype=01)
        let deflate_data: &[u8] = &[
            0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0xe4,
            0x02, 0x00,
        ];

        let deflate = Deflate::new(deflate_data);
        let result = deflate.decompress().unwrap();
        assert_eq!(result, b"Hello, World!\n");
    }
}
