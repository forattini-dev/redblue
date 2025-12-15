/// Compression module - Native implementations for data compression/decompression
///
/// Implements:
/// - CRC32 checksum (IEEE 802.3 polynomial)
/// - Gzip decompression (RFC 1952)
/// - DEFLATE decompression (RFC 1951)
/// - TAR archive parsing (USTAR)
///
/// Zero external dependencies - all implementations from scratch using RFC specifications.
pub mod crc32;
pub mod gzip;
pub mod tar;
pub mod zip;

pub use crc32::{crc32, Crc32};
pub use gzip::{decompress as gzip_decompress, GzipDecoder};
pub use tar::TarReader;
