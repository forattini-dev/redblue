use std::cmp::min;
use std::io::{self, Read};

pub struct TarEntry {
    pub name: String,
    pub size: u64,
    pub type_flag: u8,
    pub data_offset: u64,
}

pub struct TarReader<R: Read> {
    reader: R,
    current_offset: u64,
}

impl<R: Read> TarReader<R> {
    pub fn new(reader: R) -> Self {
        TarReader {
            reader,
            current_offset: 0,
        }
    }

    /// Read the next entry from the tar archive.
    /// Returns None if end of archive.
    pub fn next_entry(&mut self) -> io::Result<Option<TarEntry>> {
        let mut header = [0u8; 512];

        // Read header block
        match self.read_exact_or_eof(&mut header)? {
            0 => return Ok(None), // EOF
            512 => {}
            n => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("Incomplete header, read {} bytes", n),
                ))
            }
        }
        self.current_offset += 512;

        // Check for empty block (end of archive is two zero blocks)
        if header.iter().all(|&b| b == 0) {
            // Read second block to confirm
            match self.read_exact_or_eof(&mut header)? {
                0 => return Ok(None),
                512 => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Incomplete second zero block",
                    ))
                }
            }
            self.current_offset += 512;
            return Ok(None);
        }

        // Parse header
        // Name: 0..100
        let name = self.parse_string(&header[0..100]);
        // Size: 124..136 (12 bytes octal)
        let size = self.parse_octal(&header[124..136])?;
        // Type: 156 (1 byte)
        let type_flag = header[156];
        // Magic: 257..263 ("ustar\0" or "ustar  \0")

        // Prefix: 345..500
        let prefix = self.parse_string(&header[345..500]);

        let full_name = if !prefix.is_empty() {
            format!("{}/{}", prefix, name)
        } else {
            name
        };

        // Skip data to get to next header?
        // No, the caller is expected to read the data if they want it.
        // But if they just call next_entry, we must skip.
        // For this API, let's assume we return an Entry object that allows reading.
        // But we are implementing a simple scanner first.

        // To properly support "next_entry", we need to consume the data of the current entry.
        // Since we don't have Seek (R: Read), we must skip bytes.

        Ok(Some(TarEntry {
            name: full_name,
            size,
            type_flag,
            data_offset: self.current_offset,
        }))
    }

    /// Skip the data of the current entry to prepare for next_entry.
    pub fn skip_data(&mut self, size: u64) -> io::Result<()> {
        let padding = (512 - (size % 512)) % 512;
        let total_skip = size + padding;

        io::copy(&mut self.reader.by_ref().take(total_skip), &mut io::sink())?;
        self.current_offset += total_skip;
        Ok(())
    }

    /// Read data of current entry.
    pub fn read_data(&mut self, size: u64, output: &mut [u8]) -> io::Result<()> {
        let to_read = min(size as usize, output.len());
        self.reader.read_exact(&mut output[..to_read])?;

        // We still need to handle the rest of the data + padding if we want to advance.
        // This method assumes the user reads *some* data.
        // The responsibility of advancing to the next boundary lies with the user calling skip_data
        // or we track state.
        // For simplicity: `next_entry` assumes we are at a header boundary.
        // So the user MUST read exactly `size + padding` bytes OR call `skip_data`.
        // This is tricky with just `next_entry`.
        // Let's change `next_entry` to automatically skip previous data if not consumed?
        // Requires storing state.
        Ok(())
    }

    fn parse_string(&self, bytes: &[u8]) -> String {
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[0..len]).to_string()
    }

    fn parse_octal(&self, bytes: &[u8]) -> io::Result<u64> {
        let s = self.parse_string(bytes);
        let s = s.trim();
        if s.is_empty() {
            return Ok(0);
        }
        u64::from_str_radix(s, 8).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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
}
