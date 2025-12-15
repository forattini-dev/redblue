/// Gzip Decompression (RFC 1952)
///
/// Complete gzip implementation from scratch:
/// - RFC 1952: GZIP file format
/// - RFC 1951: DEFLATE compression
/// - IEEE 802.3: CRC32 checksum
///
/// Zero external dependencies - all implementations use only Rust std.
mod bitread;
mod codebook;
mod deflate;
pub mod error;
mod huffman;
mod window;

use std::io::Read;

use deflate::Deflate;
pub use error::{GzipError, Result};

/// Gzip magic bytes (0x1f 0x8b)
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// DEFLATE compression method
const CM_DEFLATE: u8 = 8;

/// Gzip header flags
mod flags {
    pub const FTEXT: u8 = 0b00000001;
    pub const FHCRC: u8 = 0b00000010;
    pub const FEXTRA: u8 = 0b00000100;
    pub const FNAME: u8 = 0b00001000;
    pub const FCOMMENT: u8 = 0b00010000;
    pub const RESERVED: u8 = 0b11100000;
}

/// Gzip file header information
#[derive(Debug, Default)]
pub struct GzipHeader {
    /// Modification time (Unix timestamp)
    pub mtime: u32,
    /// Extra flags
    pub xfl: u8,
    /// Operating system
    pub os: u8,
    /// Original filename (if present)
    pub filename: Option<String>,
    /// Comment (if present)
    pub comment: Option<String>,
}

/// Gzip decoder - decompresses gzip streams
pub struct GzipDecoder<R> {
    inner: R,
    header: Option<GzipHeader>,
}

impl<R: Read> GzipDecoder<R> {
    /// Create a new gzip decoder
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            header: None,
        }
    }

    /// Decompress the gzip stream and return the uncompressed data
    pub fn decompress(mut self) -> Result<Vec<u8>> {
        // Parse header
        let header = self.parse_header()?;
        self.header = Some(header);

        // Create DEFLATE decompressor with remaining data
        let deflate = Deflate::new(&mut self.inner);
        let (decompressed, remainder) = deflate.decompress_with_remainder()?;

        // Parse footer and verify using the remainder bytes
        self.verify_footer_from_bytes(&decompressed, &remainder)?;

        Ok(decompressed)
    }

    /// Get the parsed header (available after decompress)
    pub fn header(&self) -> Option<&GzipHeader> {
        self.header.as_ref()
    }

    /// Parse the gzip header
    fn parse_header(&mut self) -> Result<GzipHeader> {
        let mut buf = [0u8; 10];
        self.inner.read_exact(&mut buf)?;

        // Check magic bytes
        if buf[0] != GZIP_MAGIC[0] || buf[1] != GZIP_MAGIC[1] {
            return Err(GzipError::InvalidMagic);
        }

        // Check compression method
        let cm = buf[2];
        if cm != CM_DEFLATE {
            return Err(GzipError::UnsupportedMethod(cm));
        }

        // Check flags
        let flg = buf[3];
        if flg & flags::RESERVED != 0 {
            return Err(GzipError::ReservedFlags);
        }

        // Parse fixed fields
        let mtime = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let xfl = buf[8];
        let os = buf[9];

        let mut header = GzipHeader {
            mtime,
            xfl,
            os,
            filename: None,
            comment: None,
        };

        // Parse optional extra field
        if flg & flags::FEXTRA != 0 {
            let mut len_buf = [0u8; 2];
            self.inner.read_exact(&mut len_buf)?;
            let xlen = u16::from_le_bytes(len_buf) as usize;
            let mut extra = vec![0u8; xlen];
            self.inner.read_exact(&mut extra)?;
        }

        // Parse optional filename
        if flg & flags::FNAME != 0 {
            header.filename = Some(self.read_null_string()?);
        }

        // Parse optional comment
        if flg & flags::FCOMMENT != 0 {
            header.comment = Some(self.read_null_string()?);
        }

        // Skip optional header CRC16
        if flg & flags::FHCRC != 0 {
            let mut crc_buf = [0u8; 2];
            self.inner.read_exact(&mut crc_buf)?;
        }

        Ok(header)
    }

    /// Read a null-terminated string
    fn read_null_string(&mut self) -> Result<String> {
        let mut bytes = Vec::new();
        let mut buf = [0u8; 1];

        loop {
            self.inner.read_exact(&mut buf)?;
            if buf[0] == 0 {
                break;
            }
            bytes.push(buf[0]);
        }

        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Parse footer from remainder bytes and verify CRC32 and size
    fn verify_footer_from_bytes(&self, data: &[u8], remainder: &[u8]) -> Result<()> {
        // Footer is 8 bytes: CRC32 (4) + ISIZE (4)
        if remainder.len() < 8 {
            return Err(GzipError::InvalidFooter);
        }

        // Parse expected values from the last 8 bytes of remainder
        let footer_start = remainder.len() - 8;
        let footer = &remainder[footer_start..];
        let expected_crc = u32::from_le_bytes([footer[0], footer[1], footer[2], footer[3]]);
        let expected_size = u32::from_le_bytes([footer[4], footer[5], footer[6], footer[7]]);

        // Calculate actual CRC32
        let actual_crc = crate::compression::crc32(data);

        // Verify CRC32
        if actual_crc != expected_crc {
            return Err(GzipError::ChecksumMismatch {
                expected: expected_crc,
                got: actual_crc,
            });
        }

        // Verify size (modulo 2^32)
        let actual_size = (data.len() as u64 % (1u64 << 32)) as u32;
        if actual_size != expected_size {
            return Err(GzipError::SizeMismatch {
                expected: expected_size,
                got: actual_size,
            });
        }

        Ok(())
    }
}

/// Convenience function to decompress gzip data
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    GzipDecoder::new(data).decompress()
}

/// Decompress raw DEFLATE data (without gzip wrapper)
///
/// This is useful for ZIP files and other formats that use raw DEFLATE compression
/// without the gzip header/footer.
pub fn decompress_flate(data: &[u8]) -> Result<Vec<u8>> {
    let deflate = Deflate::new(data);
    deflate.decompress()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompress_hello() {
        // "Hello, World!\n" compressed with Python: gzip.compress(b'Hello, World!\n')
        let compressed: &[u8] = &[
            0x1f, 0x8b, 0x08, 0x00, 0xae, 0xc7, 0x36, 0x69, 0x02, 0xff, 0xf3, 0x48, 0xcd, 0xc9,
            0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0xe4, 0x02, 0x00, 0x84, 0x9e,
            0xe8, 0xb4, 0x0e, 0x00, 0x00, 0x00,
        ];

        let result = decompress(compressed).unwrap();
        assert_eq!(result, b"Hello, World!\n");
    }

    #[test]
    fn test_invalid_magic() {
        // Need at least 10 bytes for header parsing before magic check
        let data = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = decompress(&data);
        assert!(matches!(result, Err(GzipError::InvalidMagic)));
    }

    #[test]
    fn test_unsupported_method() {
        // Need at least 10 bytes for header parsing
        let data = [0x1f, 0x8b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = decompress(&data);
        assert!(matches!(result, Err(GzipError::UnsupportedMethod(0))));
    }
}
