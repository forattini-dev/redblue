//! Hex view formatting and rendering
//!
//! Provides configurable hex dump display with:
//! - Offset column (hex/decimal)
//! - Hex bytes with grouping (1, 2, 4, 8 bytes)
//! - ASCII sidebar with printable character mapping
//! - Color highlighting for modified bytes

use super::buffer::PagedBuffer;

/// Offset display format
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OffsetFormat {
    Hex,
    Decimal,
}

/// View configuration
#[derive(Clone, Debug)]
pub struct ViewSettings {
    /// Bytes per line (8, 16, 32)
    pub bytes_per_line: usize,

    /// Byte grouping (1, 2, 4, 8)
    pub group_size: usize,

    /// Show ASCII panel
    pub show_ascii: bool,

    /// Show offset column
    pub show_offset: bool,

    /// Offset format (hex, decimal)
    pub offset_format: OffsetFormat,

    /// Address width (4, 8, 16 hex digits)
    pub address_width: usize,

    /// Uppercase hex
    pub uppercase: bool,

    /// Use colors for terminal output
    pub use_colors: bool,
}

impl Default for ViewSettings {
    fn default() -> Self {
        Self {
            bytes_per_line: 16,
            group_size: 1,
            show_ascii: true,
            show_offset: true,
            offset_format: OffsetFormat::Hex,
            address_width: 8,
            uppercase: true,
            use_colors: true,
        }
    }
}

impl ViewSettings {
    /// Create minimal settings (no colors, no ASCII)
    pub fn minimal() -> Self {
        Self {
            bytes_per_line: 16,
            group_size: 1,
            show_ascii: false,
            show_offset: true,
            offset_format: OffsetFormat::Hex,
            address_width: 8,
            uppercase: true,
            use_colors: false,
        }
    }

    /// Create compact settings (8 bytes per line)
    pub fn compact() -> Self {
        Self {
            bytes_per_line: 8,
            group_size: 1,
            show_ascii: true,
            show_offset: true,
            offset_format: OffsetFormat::Hex,
            address_width: 8,
            uppercase: true,
            use_colors: true,
        }
    }

    /// Create wide settings (32 bytes per line)
    pub fn wide() -> Self {
        Self {
            bytes_per_line: 32,
            group_size: 2,
            show_ascii: true,
            show_offset: true,
            offset_format: OffsetFormat::Hex,
            address_width: 8,
            uppercase: true,
            use_colors: true,
        }
    }
}

/// Hex view renderer
pub struct HexView {
    settings: ViewSettings,
}

impl HexView {
    /// Create a new hex view with default settings
    pub fn new() -> Self {
        Self {
            settings: ViewSettings::default(),
        }
    }

    /// Create with custom settings
    pub fn with_settings(settings: ViewSettings) -> Self {
        Self { settings }
    }

    /// Get current settings
    pub fn settings(&self) -> &ViewSettings {
        &self.settings
    }

    /// Set settings
    pub fn set_settings(&mut self, settings: ViewSettings) {
        self.settings = settings;
    }

    /// Render hex view for a range of bytes
    pub fn render(&self, buffer: &mut PagedBuffer, offset: u64, lines: usize) -> String {
        let mut output = String::new();

        for line in 0..lines {
            let line_offset = offset + (line * self.settings.bytes_per_line) as u64;
            if line_offset >= buffer.size() {
                break;
            }

            // Offset column
            if self.settings.show_offset {
                output.push_str(&self.format_offset(line_offset));
                output.push_str("  ");
            }

            // Read line bytes
            let remaining = (buffer.size() - line_offset) as usize;
            let line_len = remaining.min(self.settings.bytes_per_line);
            let bytes = buffer.read(line_offset, line_len).unwrap_or_default();

            // Hex bytes with grouping
            output.push_str(&self.format_hex_bytes(&bytes));

            // ASCII panel
            if self.settings.show_ascii {
                output.push_str("  |");
                output.push_str(&self.format_ascii(&bytes));
                output.push('|');
            }

            output.push('\n');
        }

        output
    }

    /// Render hex view for raw bytes (without buffer)
    pub fn render_bytes(&self, bytes: &[u8], base_offset: u64) -> String {
        let mut output = String::new();
        let bpl = self.settings.bytes_per_line;

        for (line_idx, chunk) in bytes.chunks(bpl).enumerate() {
            let line_offset = base_offset + (line_idx * bpl) as u64;

            // Offset column
            if self.settings.show_offset {
                output.push_str(&self.format_offset(line_offset));
                output.push_str("  ");
            }

            // Hex bytes with grouping
            output.push_str(&self.format_hex_bytes(chunk));

            // ASCII panel
            if self.settings.show_ascii {
                output.push_str("  |");
                output.push_str(&self.format_ascii(chunk));
                output.push('|');
            }

            output.push('\n');
        }

        output
    }

    /// Format offset as hex or decimal
    fn format_offset(&self, offset: u64) -> String {
        match self.settings.offset_format {
            OffsetFormat::Hex => {
                if self.settings.uppercase {
                    format!("{:0width$X}", offset, width = self.settings.address_width)
                } else {
                    format!("{:0width$x}", offset, width = self.settings.address_width)
                }
            }
            OffsetFormat::Decimal => {
                format!("{:width$}", offset, width = self.settings.address_width)
            }
        }
    }

    /// Format bytes as hex with grouping
    fn format_hex_bytes(&self, bytes: &[u8]) -> String {
        let mut hex = String::new();
        let group_size = self.settings.group_size;

        for (i, byte) in bytes.iter().enumerate() {
            // Add space between groups
            if i > 0 && i % group_size == 0 {
                hex.push(' ');
            }

            // Add extra space in the middle (between halves)
            if i == self.settings.bytes_per_line / 2 && i > 0 {
                hex.push(' ');
            }

            if self.settings.uppercase {
                hex.push_str(&format!("{:02X}", byte));
            } else {
                hex.push_str(&format!("{:02x}", byte));
            }
        }

        // Pad incomplete lines
        let expected = self.settings.bytes_per_line;
        let missing = expected.saturating_sub(bytes.len());

        for i in 0..missing {
            let pos = bytes.len() + i;

            if pos > 0 && pos % group_size == 0 {
                hex.push(' ');
            }

            if pos == expected / 2 && pos > 0 {
                hex.push(' ');
            }

            hex.push_str("  ");
        }

        hex
    }

    /// Format bytes as ASCII (printable characters only)
    fn format_ascii(&self, bytes: &[u8]) -> String {
        let mut ascii: String = bytes
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();

        // Pad incomplete lines
        let missing = self.settings.bytes_per_line.saturating_sub(bytes.len());
        for _ in 0..missing {
            ascii.push(' ');
        }

        ascii
    }

    /// Format a single line of hex output
    pub fn format_line(&self, offset: u64, bytes: &[u8]) -> String {
        let mut output = String::new();

        if self.settings.show_offset {
            output.push_str(&self.format_offset(offset));
            output.push_str("  ");
        }

        output.push_str(&self.format_hex_bytes(bytes));

        if self.settings.show_ascii {
            output.push_str("  |");
            output.push_str(&self.format_ascii(bytes));
            output.push('|');
        }

        output
    }
}

impl Default for HexView {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse hex string to bytes
pub fn parse_hex(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim().replace(' ', "").replace('\n', "");

    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);

    for chunk in hex.as_bytes().chunks(2) {
        let s = std::str::from_utf8(chunk).map_err(|_| "Invalid UTF-8")?;
        let byte = u8::from_str_radix(s, 16).map_err(|_| format!("Invalid hex byte: {}", s))?;
        bytes.push(byte);
    }

    Ok(bytes)
}

/// Format bytes as hex string
pub fn to_hex(bytes: &[u8], uppercase: bool) -> String {
    bytes
        .iter()
        .map(|b| {
            if uppercase {
                format!("{:02X}", b)
            } else {
                format!("{:02x}", b)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_view_basic() {
        let view = HexView::new();
        let bytes = b"Hello, World!";
        let output = view.format_line(0, bytes);

        assert!(output.contains("48 65 6C 6C")); // "Hell" in hex
        assert!(output.contains("|Hello, World!|"));
    }

    #[test]
    fn test_hex_view_offset() {
        let view = HexView::new();
        let bytes = &[0x41, 0x42, 0x43];
        let output = view.format_line(0x100, bytes);

        assert!(output.starts_with("00000100"));
    }

    #[test]
    fn test_parse_hex() {
        let result = parse_hex("41 42 43").unwrap();
        assert_eq!(result, vec![0x41, 0x42, 0x43]);

        let result = parse_hex("ABCDEF").unwrap();
        assert_eq!(result, vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn test_to_hex() {
        let hex = to_hex(&[0x41, 0x42, 0x43], true);
        assert_eq!(hex, "41 42 43");

        let hex = to_hex(&[0xAB, 0xCD], false);
        assert_eq!(hex, "ab cd");
    }
}
