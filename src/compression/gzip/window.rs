/// Sliding Window Buffer for DEFLATE decompression (RFC 1951)
///
/// Maintains a 32KB circular buffer of decompressed data for LZ77 back-references.
/// The DEFLATE algorithm uses (length, distance) pairs to reference previously
/// decompressed bytes.

/// Window size for DEFLATE (32KB as per RFC 1951)
const WINDOW_SIZE: usize = 32 * 1024;

/// Sliding window buffer for maintaining decompression history
pub struct SlidingWindow {
    /// Circular buffer holding decompressed data
    buffer: Vec<u8>,
    /// Current write position in the buffer
    pos: usize,
    /// Total bytes written (for tracking available history)
    total_written: usize,
}

impl SlidingWindow {
    /// Create a new sliding window
    pub fn new() -> Self {
        Self {
            buffer: vec![0u8; WINDOW_SIZE],
            pos: 0,
            total_written: 0,
        }
    }

    /// Write a single byte to the window
    #[inline]
    pub fn write_byte(&mut self, byte: u8) {
        self.buffer[self.pos] = byte;
        self.pos = (self.pos + 1) % WINDOW_SIZE;
        self.total_written += 1;
    }

    /// Write multiple bytes to the window
    pub fn write_slice(&mut self, data: &[u8]) {
        for &byte in data {
            self.write_byte(byte);
        }
    }

    /// Copy `length` bytes from `distance` bytes back in the history
    ///
    /// This is the core LZ77 operation - referencing previously decompressed data.
    /// Note: distance=1 means the byte immediately before the current position.
    ///
    /// Returns the copied bytes for output.
    #[inline]
    pub fn copy_from_back(&mut self, distance: usize, length: usize, output: &mut Vec<u8>) {
        // Calculate source position (wrap around if needed)
        let mut src = if distance <= self.pos {
            self.pos - distance
        } else {
            WINDOW_SIZE - (distance - self.pos)
        };

        // Copy byte by byte (handles overlapping copies correctly)
        // For example: distance=1, length=5 should produce 5 copies of the same byte
        for _ in 0..length {
            let byte = self.buffer[src];
            output.push(byte);
            self.write_byte(byte);
            src = (src + 1) % WINDOW_SIZE;
        }
    }

    /// Get the number of bytes available in history
    #[inline]
    pub fn available_history(&self) -> usize {
        self.total_written.min(WINDOW_SIZE)
    }

    /// Check if a back-reference is valid
    #[inline]
    pub fn is_valid_distance(&self, distance: usize) -> bool {
        distance > 0 && distance <= self.available_history()
    }
}

impl Default for SlidingWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_copy() {
        let mut window = SlidingWindow::new();
        let mut output = Vec::new();

        // Write "ABCD"
        window.write_slice(b"ABCD");

        // Copy 2 bytes from distance 4 (should copy "AB")
        window.copy_from_back(4, 2, &mut output);
        assert_eq!(output, b"AB");
    }

    #[test]
    fn test_run_length_encoding() {
        let mut window = SlidingWindow::new();
        let mut output = Vec::new();

        // Write single byte
        window.write_byte(b'X');

        // Copy with distance 1, length 5 (should produce "XXXXX")
        window.copy_from_back(1, 5, &mut output);
        assert_eq!(output, b"XXXXX");
    }

    #[test]
    fn test_available_history() {
        let mut window = SlidingWindow::new();

        assert_eq!(window.available_history(), 0);

        window.write_slice(b"Hello");
        assert_eq!(window.available_history(), 5);

        assert!(window.is_valid_distance(5));
        assert!(!window.is_valid_distance(6));
        assert!(!window.is_valid_distance(0));
    }
}
