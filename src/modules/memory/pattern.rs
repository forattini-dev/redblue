//! Pattern/AOB (Array of Bytes) signature scanner
//!
//! Supports patterns like:
//! - "48 8B 05 ?? ?? ?? ??" - with wildcards
//! - "488B05????????" - compact format
//! - "48 8B 05 ** ** ** **" - alternative wildcard
//!
//! Used for finding code signatures, function addresses, etc.

use super::maps::MemoryRegion;
use super::process::ProcessMemory;

/// A byte pattern element
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternByte {
    /// Exact byte match
    Exact(u8),
    /// Wildcard (matches any byte)
    Wildcard,
}

/// A compiled byte pattern
#[derive(Debug, Clone)]
pub struct Pattern {
    bytes: Vec<PatternByte>,
    /// Human-readable representation
    original: String,
}

impl Pattern {
    /// Parse a pattern string
    ///
    /// Supports formats:
    /// - "48 8B 05 ?? ?? ?? ??" (space-separated, ?? for wildcard)
    /// - "48 8B 05 ** ** ** **" (space-separated, ** for wildcard)
    /// - "488B05????????" (compact, ? for wildcard)
    /// - "48 8B 05 .. .. .. .." (space-separated, .. for wildcard)
    pub fn parse(pattern: &str) -> Result<Self, String> {
        let original = pattern.to_string();
        let pattern = pattern.trim();

        // Check if it's compact format (no spaces)
        let bytes = if pattern.contains(' ') {
            Self::parse_spaced(pattern)?
        } else {
            Self::parse_compact(pattern)?
        };

        if bytes.is_empty() {
            return Err("Empty pattern".into());
        }

        Ok(Self { bytes, original })
    }

    fn parse_spaced(pattern: &str) -> Result<Vec<PatternByte>, String> {
        let mut bytes = Vec::new();

        for part in pattern.split_whitespace() {
            let part = part.trim();

            if part == "??" || part == "**" || part == ".." || part == "?" {
                bytes.push(PatternByte::Wildcard);
            } else if part.len() == 2 {
                let byte = u8::from_str_radix(part, 16)
                    .map_err(|_| format!("Invalid hex byte: {}", part))?;
                bytes.push(PatternByte::Exact(byte));
            } else {
                return Err(format!("Invalid pattern element: {}", part));
            }
        }

        Ok(bytes)
    }

    fn parse_compact(pattern: &str) -> Result<Vec<PatternByte>, String> {
        let pattern = pattern.trim();
        let mut bytes = Vec::new();
        let mut chars = pattern.chars().peekable();

        while let Some(c1) = chars.next() {
            let c2 = chars.next().ok_or("Odd number of characters in pattern")?;

            if c1 == '?' && c2 == '?' {
                bytes.push(PatternByte::Wildcard);
            } else if c1 == '*' && c2 == '*' {
                bytes.push(PatternByte::Wildcard);
            } else if c1 == '.' && c2 == '.' {
                bytes.push(PatternByte::Wildcard);
            } else {
                let hex = format!("{}{}", c1, c2);
                let byte = u8::from_str_radix(&hex, 16)
                    .map_err(|_| format!("Invalid hex byte: {}", hex))?;
                bytes.push(PatternByte::Exact(byte));
            }
        }

        Ok(bytes)
    }

    /// Pattern length in bytes
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if pattern is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Check if data matches the pattern at the given offset
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.len() > data.len() {
            return false;
        }

        for (i, pat_byte) in self.bytes.iter().enumerate() {
            match pat_byte {
                PatternByte::Exact(b) => {
                    if data[offset + i] != *b {
                        return false;
                    }
                }
                PatternByte::Wildcard => {
                    // Matches anything
                }
            }
        }

        true
    }

    /// Get the bytes matched at an offset (for display)
    pub fn extract_matched(&self, data: &[u8], offset: usize) -> Option<Vec<u8>> {
        if offset + self.len() > data.len() {
            return None;
        }
        Some(data[offset..offset + self.len()].to_vec())
    }
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.original)
    }
}

/// Pattern scan result
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Address where pattern was found
    pub address: usize,
    /// The actual bytes matched
    pub matched_bytes: Vec<u8>,
    /// Region info
    pub region_name: String,
}

impl PatternMatch {
    /// Format matched bytes as hex string
    pub fn bytes_hex(&self) -> String {
        self.matched_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Pattern scanner
pub struct PatternScanner;

impl PatternScanner {
    /// Scan for a pattern in all provided regions
    pub fn scan(
        proc: &mut ProcessMemory,
        regions: &[MemoryRegion],
        pattern: &Pattern,
        max_results: Option<usize>,
    ) -> Result<Vec<PatternMatch>, String> {
        let mut results = Vec::new();
        let max = max_results.unwrap_or(usize::MAX);

        for region in regions {
            if !region.is_readable() {
                continue;
            }

            // Read region data
            let data = match proc.read_bytes(region.start, region.size()) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Scan for pattern
            for offset in 0..data.len().saturating_sub(pattern.len()) {
                if pattern.matches(&data, offset) {
                    let address = region.start + offset;
                    let matched_bytes = pattern.extract_matched(&data, offset).unwrap_or_default();

                    results.push(PatternMatch {
                        address,
                        matched_bytes,
                        region_name: region.name(),
                    });

                    if results.len() >= max {
                        return Ok(results);
                    }
                }
            }
        }

        Ok(results)
    }

    /// Scan for multiple patterns at once
    pub fn scan_multiple(
        proc: &mut ProcessMemory,
        regions: &[MemoryRegion],
        patterns: &[Pattern],
        max_per_pattern: Option<usize>,
    ) -> Result<Vec<(usize, Vec<PatternMatch>)>, String> {
        let mut all_results = Vec::new();

        for (idx, pattern) in patterns.iter().enumerate() {
            let results = Self::scan(proc, regions, pattern, max_per_pattern)?;
            all_results.push((idx, results));
        }

        Ok(all_results)
    }

    /// Find a pattern and return the first match
    pub fn find_first(
        proc: &mut ProcessMemory,
        regions: &[MemoryRegion],
        pattern: &Pattern,
    ) -> Result<Option<PatternMatch>, String> {
        let results = Self::scan(proc, regions, pattern, Some(1))?;
        Ok(results.into_iter().next())
    }
}

/// Helper to create a pattern that matches a string (for finding strings in memory)
pub fn string_pattern(s: &str) -> Pattern {
    let bytes: Vec<PatternByte> = s.bytes().map(PatternByte::Exact).collect();
    Pattern {
        bytes,
        original: format!("\"{}\"", s),
    }
}

/// Helper to create a pattern from raw bytes
pub fn bytes_pattern(bytes: &[u8]) -> Pattern {
    let pat_bytes: Vec<PatternByte> = bytes.iter().map(|&b| PatternByte::Exact(b)).collect();
    let original = bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");
    Pattern {
        bytes: pat_bytes,
        original,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_parse_spaced() {
        let pat = Pattern::parse("48 8B 05 ?? ?? ?? ??").unwrap();
        assert_eq!(pat.len(), 7);
        assert_eq!(pat.bytes[0], PatternByte::Exact(0x48));
        assert_eq!(pat.bytes[3], PatternByte::Wildcard);
    }

    #[test]
    fn test_pattern_parse_compact() {
        let pat = Pattern::parse("488B05????????").unwrap();
        assert_eq!(pat.len(), 7);
        assert_eq!(pat.bytes[0], PatternByte::Exact(0x48));
        assert_eq!(pat.bytes[3], PatternByte::Wildcard);
    }

    #[test]
    fn test_pattern_matches() {
        let pat = Pattern::parse("48 8B ?? 12").unwrap();
        let data = [0x48, 0x8B, 0xFF, 0x12, 0x00];

        assert!(pat.matches(&data, 0));
        assert!(!pat.matches(&data, 1));
    }

    #[test]
    fn test_string_pattern() {
        let pat = string_pattern("Hello");
        let data = b"xxxHelloyyy";

        assert!(pat.matches(data, 3));
        assert!(!pat.matches(data, 0));
    }
}
