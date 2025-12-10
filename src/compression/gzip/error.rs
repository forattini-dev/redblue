/// Gzip decompression error types (RFC 1952 / RFC 1951)

use std::fmt::{self, Display};
use std::io::ErrorKind;

/// Errors that can occur during gzip decompression
#[derive(Debug)]
pub enum GzipError {
    /// Standard I/O error
    Io(ErrorKind),
    /// Input stream is empty
    EmptyInput,
    /// Invalid gzip magic bytes (expected 0x1f 0x8b)
    InvalidMagic,
    /// Unsupported compression method (only DEFLATE/8 supported)
    UnsupportedMethod(u8),
    /// Reserved flags are set in header
    ReservedFlags,
    /// Invalid DEFLATE block type
    InvalidBlockType,
    /// Block type 0 length mismatch (len != ~nlen)
    StoredLengthMismatch,
    /// Invalid Huffman code lengths
    InvalidCodeLengths,
    /// Huffman code not found in decoder
    HuffmanCodeNotFound,
    /// Back-reference distance exceeds available history
    DistanceTooFar,
    /// End of block marker not found
    UnexpectedEnd,
    /// Dynamic codebook read error
    InvalidDynamicCodebook,
    /// CRC32 checksum mismatch
    ChecksumMismatch { expected: u32, got: u32 },
    /// Uncompressed size mismatch
    SizeMismatch { expected: u32, got: u32 },
    /// Invalid or missing gzip footer
    InvalidFooter,
}

impl From<std::io::Error> for GzipError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}

impl From<GzipError> for std::io::Error {
    fn from(e: GzipError) -> Self {
        match e {
            GzipError::Io(kind) => Self::from(kind),
            _ => Self::new(ErrorKind::InvalidData, e),
        }
    }
}

impl std::error::Error for GzipError {}

impl Display for GzipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(f, "I/O error: {:?}", kind),
            Self::EmptyInput => write!(f, "Input stream is empty"),
            Self::InvalidMagic => write!(f, "Invalid gzip magic bytes"),
            Self::UnsupportedMethod(m) => write!(f, "Unsupported compression method: {}", m),
            Self::ReservedFlags => write!(f, "Reserved flags are set"),
            Self::InvalidBlockType => write!(f, "Invalid DEFLATE block type"),
            Self::StoredLengthMismatch => write!(f, "Stored block length mismatch"),
            Self::InvalidCodeLengths => write!(f, "Invalid Huffman code lengths"),
            Self::HuffmanCodeNotFound => write!(f, "Huffman code not found"),
            Self::DistanceTooFar => write!(f, "Back-reference distance too far"),
            Self::UnexpectedEnd => write!(f, "Unexpected end of stream"),
            Self::InvalidDynamicCodebook => write!(f, "Invalid dynamic codebook"),
            Self::ChecksumMismatch { expected, got } => {
                write!(f, "CRC32 mismatch: expected {:08x}, got {:08x}", expected, got)
            }
            Self::SizeMismatch { expected, got } => {
                write!(f, "Size mismatch: expected {}, got {}", expected, got)
            }
            Self::InvalidFooter => write!(f, "Invalid or missing gzip footer"),
        }
    }
}

/// Result type for gzip operations
pub type Result<T> = std::result::Result<T, GzipError>;
