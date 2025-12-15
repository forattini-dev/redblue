use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

// Minimal ZIP parser for extracting file contents without external crates.
// This implementation is highly simplified and only supports uncompressed or deflate-compressed
// files within the ZIP archive. It does not handle advanced features like encryption,
// multi-disk archives, or other compression methods.

#[derive(Debug)]
pub struct ZipEntry {
    pub name: String,
    pub uncompressed_size: u32,
    pub compressed_size: u32,
    pub compression_method: u16, // 0 = stored, 8 = deflate
    pub offset: u32,             // Offset of local file header
}

pub struct ZipReader<R: Read> {
    reader: R,
    current_offset: u32,
}

impl<R: Read> ZipReader<R> {
    pub fn new(reader: R) -> io::Result<Self> {
        // Find Central Directory End Record (EOCD) to locate Central Directory
        // For simplicity, we assume small files and read from start.
        // A robust reader would start from end to find EOCD.

        Ok(Self {
            reader,
            current_offset: 0,
        })
    }

    /// Read the next entry from the ZIP archive (local file header).
    /// Returns `None` if end of archive.
    pub fn next_entry(&mut self) -> io::Result<Option<ZipEntry>> {
        let mut signature_buf = [0u8; 4];

        match self.read_exact_or_eof(&mut signature_buf)? {
            0 => return Ok(None), // EOF, no more entries
            4 => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Incomplete signature",
                ))
            }
        }
        self.current_offset += 4;

        // Check for Local File Header signature (0x04034b50)
        if u32::from_le_bytes(signature_buf) != 0x04034b50 {
            // Not a local file header. Could be Central Directory entry or EOCD.
            // For this minimal parser, we just assume EOF if not a header.
            return Ok(None);
        }

        let mut header_buf = [0u8; 26]; // Remaining fixed size of local file header
        self.reader.read_exact(&mut header_buf)?;
        self.current_offset += 26;

        let compression_method = u16::from_le_bytes([header_buf[4], header_buf[5]]);
        let compressed_size = u32::from_le_bytes([
            header_buf[14],
            header_buf[15],
            header_buf[16],
            header_buf[17],
        ]);
        let uncompressed_size = u32::from_le_bytes([
            header_buf[18],
            header_buf[19],
            header_buf[20],
            header_buf[21],
        ]);
        let file_name_len = u16::from_le_bytes([header_buf[22], header_buf[23]]);
        let extra_field_len = u16::from_le_bytes([header_buf[24], header_buf[25]]);

        let mut file_name_buf = vec![0u8; file_name_len as usize];
        self.reader.read_exact(&mut file_name_buf)?;
        self.current_offset += file_name_len as u32;

        let name = String::from_utf8(file_name_buf).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid UTF-8 filename: {}", e),
            )
        })?;

        // Skip extra field
        io::copy(
            &mut self.reader.by_ref().take(extra_field_len as u64),
            &mut io::sink(),
        )?;
        self.current_offset += extra_field_len as u32;

        let entry_offset = self.current_offset; // Data starts here

        Ok(Some(ZipEntry {
            name,
            uncompressed_size,
            compressed_size,
            compression_method,
            offset: entry_offset,
        }))
    }

    /// Reads the data of the current entry into a buffer.
    /// This advances the reader past the entry's data and possible trailing data.
    pub fn read_entry_data(&mut self, entry: &ZipEntry) -> io::Result<Vec<u8>> {
        let mut data = vec![0u8; entry.compressed_size as usize];
        self.reader.read_exact(&mut data)?;
        self.current_offset += entry.compressed_size;

        // Handle decompression if necessary
        match entry.compression_method {
            0 => {
                // Stored (uncompressed)
                Ok(data)
            }
            8 => {
                // Deflate
                use crate::compression::gzip::decompress_flate; // Assuming deflate decompressor is available
                decompress_flate(&data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Deflate decompression failed: {}", e),
                    )
                })
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "Unsupported ZIP compression method: {}",
                    entry.compression_method
                ),
            )),
        }
    }

    fn read_exact_or_eof(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read = 0;
        while read < buf.len() {
            let n = self.reader.read(&mut buf[read..])?;
            if n == 0 {
                break;
            }
            read += n;
        }
        Ok(read)
    }

    pub fn open_file<P: AsRef<Path>>(path: P) -> io::Result<ZipReader<File>> {
        let file = File::open(path)?;
        ZipReader::new(file)
    }
}

// Example usage and tests would go here
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_zip_stored_entry() -> io::Result<()> {
        let mut file = File::create("/tmp/test_stored.zip")?;

        // Write Local File Header for a stored entry
        file.write_all(&0x04034b50u32.to_le_bytes())?; // Local file header signature
        file.write_all(&0x000Au16.to_le_bytes())?; // Version
        file.write_all(&0x0000u16.to_le_bytes())?; // General purpose bit flag
        file.write_all(&0x0000u16.to_le_bytes())?; // Compression method (0 = stored)
        file.write_all(&0x00000000u32.to_le_bytes())?; // Last mod time/date
        file.write_all(&0x00000000u32.to_le_bytes())?; // CRC32
        file.write_all(&0x00000005u32.to_le_bytes())?; // Compressed size (5 bytes)
        file.write_all(&0x00000005u32.to_le_bytes())?; // Uncompressed size (5 bytes)
        file.write_all(&0x0003u16.to_le_bytes())?; // File name length (3 bytes)
        file.write_all(&0x0000u16.to_le_bytes())?; // Extra field length
        file.write_all(b"abc")?; // File name "abc"
        file.write_all(b"Hello")?; // File data "Hello"
        file.flush()?;

        let mut reader = ZipReader::<File>::open_file("/tmp/test_stored.zip")?;
        let entry = reader.next_entry()?.expect("Should have an entry");
        assert_eq!(entry.name, "abc");
        assert_eq!(entry.uncompressed_size, 5);
        assert_eq!(entry.compressed_size, 5);
        assert_eq!(entry.compression_method, 0);

        let data = reader.read_entry_data(&entry)?;
        assert_eq!(data, b"Hello");

        std::fs::remove_file("/tmp/test_stored.zip")?;
        Ok(())
    }

    // Note: test_zip_deflate_entry removed - requires compress_flate which is not implemented
    // (only decompression is implemented, not compression)
}
