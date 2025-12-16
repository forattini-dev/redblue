/// Bit-level reader for DEFLATE decompression (RFC 1951)
///
/// DEFLATE streams pack data at the bit level, reading LSB first within each byte.
/// This reader provides efficient bit-level access with buffering.
use std::io::Read;

const BUFFER_SIZE: usize = 16 * 1024; // 16KB buffer

/// Bit-level reader that wraps a byte stream
pub struct BitReader<R> {
    inner: R,
    buffer: Vec<u8>,
    buf_start: usize,
    buf_end: usize,
    bit_offset: u32, // 0-7, bits consumed in current byte
}

impl<R: Read> BitReader<R> {
    /// Create a new BitReader wrapping the given reader
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: vec![0u8; BUFFER_SIZE],
            buf_start: 0,
            buf_end: 0,
            bit_offset: 0,
        }
    }

    /// Get the current buffer slice
    #[inline]
    fn buf(&self) -> &[u8] {
        &self.buffer[self.buf_start..self.buf_end]
    }

    /// Number of bytes available in buffer
    #[inline]
    fn buf_len(&self) -> usize {
        self.buf_end - self.buf_start
    }

    /// Number of bits available (accounting for bit offset)
    #[inline]
    fn bits_available(&self) -> usize {
        self.buf_len() * 8 - self.bit_offset as usize
    }

    /// Refill the buffer from the underlying reader
    fn refill(&mut self) -> std::io::Result<usize> {
        // Move remaining data to start of buffer
        if self.buf_start > 0 {
            self.buffer.copy_within(self.buf_start..self.buf_end, 0);
            self.buf_end -= self.buf_start;
            self.buf_start = 0;
        }

        // Read more data
        let n = self.inner.read(&mut self.buffer[self.buf_end..])?;
        self.buf_end += n;
        Ok(n)
    }

    /// Ensure at least `n` bytes are available in buffer
    fn ensure_bytes(&mut self, n: usize) -> std::io::Result<()> {
        while self.buf_len() < n {
            if self.refill()? == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
        }
        Ok(())
    }

    /// Peek at least 24 bits without consuming them
    /// Returns bits in LSB-first order, right-aligned
    #[inline]
    pub fn peek_bits(&mut self) -> std::io::Result<u32> {
        // Try to get 4 bytes, but handle end of stream gracefully
        let available = self.buf_len();
        if available < 4 {
            // Try to refill
            let _ = self.refill();
        }

        let available = self.buf_len();
        if available == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }

        // Read up to 4 bytes from buffer as little-endian
        let bytes = &self.buffer[self.buf_start..self.buf_end];
        let bits = match available {
            1 => bytes[0] as u32,
            2 => u16::from_le_bytes([bytes[0], bytes[1]]) as u32,
            3 => (bytes[0] as u32) | ((bytes[1] as u32) << 8) | ((bytes[2] as u32) << 16),
            _ => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        };

        // Shift right by bit_offset to get the current position
        Ok(bits >> self.bit_offset)
    }

    /// Consume n bits (advance the read position)
    #[inline]
    pub fn consume(&mut self, n: u32) {
        debug_assert!(self.bits_available() >= n as usize);
        self.bit_offset += n;
        self.buf_start += (self.bit_offset / 8) as usize;
        self.bit_offset %= 8;
    }

    /// Read n bits and consume them (n <= 24)
    #[inline]
    pub fn read_bits(&mut self, n: u32) -> std::io::Result<u32> {
        debug_assert!(n <= 24);
        let bits = self.peek_bits()?;
        self.consume(n);
        Ok(bits & ((1 << n) - 1))
    }

    /// Align to byte boundary (skip remaining bits in current byte)
    pub fn byte_align(&mut self) {
        if self.bit_offset > 0 {
            self.buf_start += 1;
            self.bit_offset = 0;
        }
    }

    /// Check if there's more data available
    pub fn has_data(&mut self) -> std::io::Result<bool> {
        if self.buf_len() > 0 {
            return Ok(true);
        }
        Ok(self.refill()? > 0)
    }

    /// Read a null-terminated string (for gzip header fields)
    pub fn read_null_string(&mut self) -> std::io::Result<Vec<u8>> {
        self.byte_align();
        let mut result = Vec::new();

        loop {
            // Ensure we have at least one byte
            if self.buf_len() == 0 && self.refill()? == 0 {
                return Ok(result);
            }

            // Search for null terminator in buffer
            if let Some(pos) = self.buf().iter().position(|&b| b == 0) {
                result.extend_from_slice(&self.buffer[self.buf_start..self.buf_start + pos + 1]);
                self.buf_start += pos + 1;
                return Ok(result);
            }

            // No null found, consume entire buffer and continue
            result.extend_from_slice(self.buf());
            self.buf_start = self.buf_end;
        }
    }
}

impl<R: Read> Read for BitReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.byte_align();

        // First read from our buffer
        let from_buf = buf.len().min(self.buf_len());
        buf[..from_buf].copy_from_slice(&self.buffer[self.buf_start..self.buf_start + from_buf]);
        self.buf_start += from_buf;

        // Then read directly from inner reader if needed
        if from_buf < buf.len() {
            let from_inner = self.inner.read(&mut buf[from_buf..])?;
            Ok(from_buf + from_inner)
        } else {
            Ok(from_buf)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_bits() {
        // Test data: 0xAB = 10101011, 0xCD = 11001101, plus padding for peek_bits
        let data = vec![0xAB, 0xCD, 0xEF, 0x12, 0x00, 0x00, 0x00, 0x00];
        let mut reader = BitReader::new(&data[..]);

        // Read 4 bits: should get 0b1011 = 11 (LSB first)
        assert_eq!(reader.read_bits(4).unwrap(), 0b1011);

        // Read 4 more bits: should get 0b1010 = 10
        assert_eq!(reader.read_bits(4).unwrap(), 0b1010);

        // Read 8 bits: should get 0xCD = 205
        assert_eq!(reader.read_bits(8).unwrap(), 0xCD);
    }

    #[test]
    fn test_byte_align() {
        let data = vec![0xFF, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = BitReader::new(&data[..]);

        // Read 3 bits
        reader.read_bits(3).unwrap();

        // Align to byte boundary
        reader.byte_align();

        // Next read should be from second byte
        assert_eq!(reader.read_bits(8).unwrap(), 0x00);
    }
}
