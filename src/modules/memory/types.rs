//! Data type interpretation for hex editing
//!
//! Provides interpretation of raw bytes as various data types:
//! - Integers (8/16/32/64-bit, signed/unsigned, little/big endian)
//! - Floating point (f32, f64)
//! - Strings (ASCII, UTF-8, UTF-16)
//! - Timestamps (Unix epoch)

use std::time::{Duration, UNIX_EPOCH};

/// Byte order for multi-byte values
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Default for Endian {
    fn default() -> Self {
        Self::Little
    }
}

/// Interpreted data value
#[derive(Clone, Debug)]
pub enum DataValue {
    U8(u8),
    I8(i8),
    U16(u16),
    I16(i16),
    U32(u32),
    I32(i32),
    U64(u64),
    I64(i64),
    F32(f32),
    F64(f64),
    Ascii(String),
    Utf8(String),
    Utf16(String),
    Timestamp(String),
    Binary(Vec<u8>),
}

impl std::fmt::Display for DataValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::U8(v) => write!(f, "{} (0x{:02X})", v, v),
            Self::I8(v) => write!(f, "{}", v),
            Self::U16(v) => write!(f, "{} (0x{:04X})", v, v),
            Self::I16(v) => write!(f, "{}", v),
            Self::U32(v) => write!(f, "{} (0x{:08X})", v, v),
            Self::I32(v) => write!(f, "{}", v),
            Self::U64(v) => write!(f, "{} (0x{:016X})", v, v),
            Self::I64(v) => write!(f, "{}", v),
            Self::F32(v) => write!(f, "{}", v),
            Self::F64(v) => write!(f, "{}", v),
            Self::Ascii(s) | Self::Utf8(s) | Self::Utf16(s) => write!(f, "\"{}\"", s),
            Self::Timestamp(s) => write!(f, "{}", s),
            Self::Binary(b) => {
                write!(f, "[")?;
                for (i, byte) in b.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{:02X}", byte)?;
                }
                write!(f, "]")
            }
        }
    }
}

/// Data type interpreter
pub struct DataInterpreter {
    endian: Endian,
}

impl DataInterpreter {
    /// Create with default endianness (little)
    pub fn new() -> Self {
        Self {
            endian: Endian::Little,
        }
    }

    /// Create with specified endianness
    pub fn with_endian(endian: Endian) -> Self {
        Self { endian }
    }

    /// Set endianness
    pub fn set_endian(&mut self, endian: Endian) {
        self.endian = endian;
    }

    /// Get current endianness
    pub fn endian(&self) -> Endian {
        self.endian
    }

    /// Read unsigned 8-bit integer
    pub fn read_u8(&self, data: &[u8]) -> Option<u8> {
        data.first().copied()
    }

    /// Read signed 8-bit integer
    pub fn read_i8(&self, data: &[u8]) -> Option<i8> {
        data.first().map(|&b| b as i8)
    }

    /// Read unsigned 16-bit integer
    pub fn read_u16(&self, data: &[u8]) -> Option<u16> {
        if data.len() < 2 {
            return None;
        }
        let bytes: [u8; 2] = [data[0], data[1]];
        Some(match self.endian {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        })
    }

    /// Read signed 16-bit integer
    pub fn read_i16(&self, data: &[u8]) -> Option<i16> {
        self.read_u16(data).map(|v| v as i16)
    }

    /// Read unsigned 32-bit integer
    pub fn read_u32(&self, data: &[u8]) -> Option<u32> {
        if data.len() < 4 {
            return None;
        }
        let bytes: [u8; 4] = [data[0], data[1], data[2], data[3]];
        Some(match self.endian {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        })
    }

    /// Read signed 32-bit integer
    pub fn read_i32(&self, data: &[u8]) -> Option<i32> {
        self.read_u32(data).map(|v| v as i32)
    }

    /// Read unsigned 64-bit integer
    pub fn read_u64(&self, data: &[u8]) -> Option<u64> {
        if data.len() < 8 {
            return None;
        }
        let bytes: [u8; 8] = [
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ];
        Some(match self.endian {
            Endian::Little => u64::from_le_bytes(bytes),
            Endian::Big => u64::from_be_bytes(bytes),
        })
    }

    /// Read signed 64-bit integer
    pub fn read_i64(&self, data: &[u8]) -> Option<i64> {
        self.read_u64(data).map(|v| v as i64)
    }

    /// Read 32-bit float
    pub fn read_f32(&self, data: &[u8]) -> Option<f32> {
        if data.len() < 4 {
            return None;
        }
        let bytes: [u8; 4] = [data[0], data[1], data[2], data[3]];
        Some(match self.endian {
            Endian::Little => f32::from_le_bytes(bytes),
            Endian::Big => f32::from_be_bytes(bytes),
        })
    }

    /// Read 64-bit float
    pub fn read_f64(&self, data: &[u8]) -> Option<f64> {
        if data.len() < 8 {
            return None;
        }
        let bytes: [u8; 8] = [
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ];
        Some(match self.endian {
            Endian::Little => f64::from_le_bytes(bytes),
            Endian::Big => f64::from_be_bytes(bytes),
        })
    }

    /// Read ASCII string (stop at null or non-printable)
    pub fn read_ascii(&self, data: &[u8], max_len: usize) -> String {
        let len = data.len().min(max_len);
        let mut result = String::new();

        for &byte in &data[..len] {
            if byte == 0 {
                break;
            }
            if byte.is_ascii_graphic() || byte == b' ' {
                result.push(byte as char);
            } else {
                break;
            }
        }

        result
    }

    /// Read UTF-8 string
    pub fn read_utf8(&self, data: &[u8], max_len: usize) -> Option<String> {
        let len = data.len().min(max_len);
        let mut end = 0;

        // Find null terminator or end
        for (i, &byte) in data[..len].iter().enumerate() {
            if byte == 0 {
                break;
            }
            end = i + 1;
        }

        std::str::from_utf8(&data[..end])
            .ok()
            .map(|s| s.to_string())
    }

    /// Read UTF-16 string
    pub fn read_utf16(&self, data: &[u8], max_chars: usize) -> Option<String> {
        if data.len() < 2 {
            return None;
        }

        let mut chars = Vec::new();
        let mut i = 0;

        while i + 1 < data.len() && chars.len() < max_chars {
            let code = match self.endian {
                Endian::Little => u16::from_le_bytes([data[i], data[i + 1]]),
                Endian::Big => u16::from_be_bytes([data[i], data[i + 1]]),
            };

            if code == 0 {
                break;
            }

            chars.push(code);
            i += 2;
        }

        String::from_utf16(&chars).ok()
    }

    /// Interpret as Unix timestamp (32-bit)
    pub fn read_timestamp32(&self, data: &[u8]) -> Option<String> {
        let secs = self.read_u32(data)? as u64;
        self.format_timestamp(secs)
    }

    /// Interpret as Unix timestamp (64-bit)
    pub fn read_timestamp64(&self, data: &[u8]) -> Option<String> {
        let secs = self.read_u64(data)?;
        self.format_timestamp(secs)
    }

    fn format_timestamp(&self, secs: u64) -> Option<String> {
        let datetime = UNIX_EPOCH.checked_add(Duration::from_secs(secs))?;
        let duration = datetime.duration_since(UNIX_EPOCH).ok()?;

        // Simple formatting without external crates
        let total_secs = duration.as_secs();
        let days = total_secs / 86400;
        let years = 1970 + (days / 365); // Approximate
        let remaining_days = days % 365;
        let months = remaining_days / 30;
        let day = remaining_days % 30 + 1;

        let day_secs = total_secs % 86400;
        let hours = day_secs / 3600;
        let minutes = (day_secs % 3600) / 60;
        let seconds = day_secs % 60;

        Some(format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            years,
            months + 1,
            day,
            hours,
            minutes,
            seconds
        ))
    }

    /// Get all interpretations of data at offset
    pub fn interpret_all(&self, data: &[u8]) -> Vec<(&'static str, DataValue)> {
        let mut results = Vec::new();

        // Integer types
        if let Some(v) = self.read_u8(data) {
            results.push(("u8", DataValue::U8(v)));
            results.push(("i8", DataValue::I8(v as i8)));
        }

        if let Some(v) = self.read_u16(data) {
            results.push(("u16", DataValue::U16(v)));
            results.push(("i16", DataValue::I16(v as i16)));
        }

        if let Some(v) = self.read_u32(data) {
            results.push(("u32", DataValue::U32(v)));
            results.push(("i32", DataValue::I32(v as i32)));
        }

        if let Some(v) = self.read_u64(data) {
            results.push(("u64", DataValue::U64(v)));
            results.push(("i64", DataValue::I64(v as i64)));
        }

        // Floating point
        if let Some(v) = self.read_f32(data) {
            if v.is_finite() {
                results.push(("f32", DataValue::F32(v)));
            }
        }

        if let Some(v) = self.read_f64(data) {
            if v.is_finite() {
                results.push(("f64", DataValue::F64(v)));
            }
        }

        // Strings
        let ascii = self.read_ascii(data, 64);
        if !ascii.is_empty() {
            results.push(("ASCII", DataValue::Ascii(ascii)));
        }

        if let Some(utf8) = self.read_utf8(data, 64) {
            if !utf8.is_empty() {
                results.push(("UTF-8", DataValue::Utf8(utf8)));
            }
        }

        if let Some(utf16) = self.read_utf16(data, 32) {
            if !utf16.is_empty() {
                results.push(("UTF-16", DataValue::Utf16(utf16)));
            }
        }

        // Timestamps
        if let Some(ts) = self.read_timestamp32(data) {
            // Only show if it looks like a reasonable timestamp (1970-2100)
            if let Some(v) = self.read_u32(data) {
                if v > 0 && v < 4_102_444_800 {
                    // Before year 2100
                    results.push(("timestamp32", DataValue::Timestamp(ts)));
                }
            }
        }

        results
    }

    /// Write unsigned 8-bit integer
    pub fn write_u8(&self, value: u8) -> Vec<u8> {
        vec![value]
    }

    /// Write unsigned 16-bit integer
    pub fn write_u16(&self, value: u16) -> Vec<u8> {
        match self.endian {
            Endian::Little => value.to_le_bytes().to_vec(),
            Endian::Big => value.to_be_bytes().to_vec(),
        }
    }

    /// Write unsigned 32-bit integer
    pub fn write_u32(&self, value: u32) -> Vec<u8> {
        match self.endian {
            Endian::Little => value.to_le_bytes().to_vec(),
            Endian::Big => value.to_be_bytes().to_vec(),
        }
    }

    /// Write unsigned 64-bit integer
    pub fn write_u64(&self, value: u64) -> Vec<u8> {
        match self.endian {
            Endian::Little => value.to_le_bytes().to_vec(),
            Endian::Big => value.to_be_bytes().to_vec(),
        }
    }

    /// Write 32-bit float
    pub fn write_f32(&self, value: f32) -> Vec<u8> {
        match self.endian {
            Endian::Little => value.to_le_bytes().to_vec(),
            Endian::Big => value.to_be_bytes().to_vec(),
        }
    }

    /// Write 64-bit float
    pub fn write_f64(&self, value: f64) -> Vec<u8> {
        match self.endian {
            Endian::Little => value.to_le_bytes().to_vec(),
            Endian::Big => value.to_be_bytes().to_vec(),
        }
    }
}

impl Default for DataInterpreter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integers() {
        let interp = DataInterpreter::new();

        assert_eq!(interp.read_u8(&[0x41]), Some(0x41));
        assert_eq!(interp.read_i8(&[0xFF]), Some(-1));

        // Little endian
        assert_eq!(interp.read_u16(&[0x01, 0x02]), Some(0x0201));
        assert_eq!(interp.read_u32(&[0x01, 0x02, 0x03, 0x04]), Some(0x04030201));

        // Big endian
        let be = DataInterpreter::with_endian(Endian::Big);
        assert_eq!(be.read_u16(&[0x01, 0x02]), Some(0x0102));
        assert_eq!(be.read_u32(&[0x01, 0x02, 0x03, 0x04]), Some(0x01020304));
    }

    #[test]
    fn test_floats() {
        let interp = DataInterpreter::new();

        let f32_bytes = 3.14f32.to_le_bytes();
        let result = interp.read_f32(&f32_bytes).unwrap();
        assert!((result - 3.14).abs() < 0.001);

        let f64_bytes = 2.71828f64.to_le_bytes();
        let result = interp.read_f64(&f64_bytes).unwrap();
        assert!((result - 2.71828).abs() < 0.00001);
    }

    #[test]
    fn test_strings() {
        let interp = DataInterpreter::new();

        let ascii = interp.read_ascii(b"Hello\x00World", 64);
        assert_eq!(ascii, "Hello");

        let utf8 = interp.read_utf8(b"Test\x00", 64);
        assert_eq!(utf8, Some("Test".to_string()));
    }

    #[test]
    fn test_write() {
        let interp = DataInterpreter::new();

        assert_eq!(interp.write_u16(0x1234), vec![0x34, 0x12]);
        assert_eq!(interp.write_u32(0x12345678), vec![0x78, 0x56, 0x34, 0x12]);

        let be = DataInterpreter::with_endian(Endian::Big);
        assert_eq!(be.write_u16(0x1234), vec![0x12, 0x34]);
    }
}
