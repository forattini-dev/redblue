//! Memory value scanner - Cheat Engine style
//!
//! Supports scanning for:
//! - Exact values (i8, i16, i32, i64, u8, u16, u32, u64, f32, f64)
//! - Value ranges (min..max)
//! - Changed/unchanged values
//! - Increased/decreased values

use super::maps::MemoryRegion;
use super::process::ProcessMemory;

/// Supported value types for scanning
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
}

impl ValueType {
    pub fn size(&self) -> usize {
        match self {
            ValueType::I8 | ValueType::U8 => 1,
            ValueType::I16 | ValueType::U16 => 2,
            ValueType::I32 | ValueType::U32 | ValueType::F32 => 4,
            ValueType::I64 | ValueType::U64 | ValueType::F64 => 8,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ValueType::I8 => "i8",
            ValueType::I16 => "i16",
            ValueType::I32 => "i32",
            ValueType::I64 => "i64",
            ValueType::U8 => "u8",
            ValueType::U16 => "u16",
            ValueType::U32 => "u32",
            ValueType::U64 => "u64",
            ValueType::F32 => "f32",
            ValueType::F64 => "f64",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "i8" | "int8" | "byte" => Some(ValueType::I8),
            "i16" | "int16" | "short" => Some(ValueType::I16),
            "i32" | "int32" | "int" => Some(ValueType::I32),
            "i64" | "int64" | "long" => Some(ValueType::I64),
            "u8" | "uint8" | "ubyte" => Some(ValueType::U8),
            "u16" | "uint16" | "ushort" => Some(ValueType::U16),
            "u32" | "uint32" | "uint" => Some(ValueType::U32),
            "u64" | "uint64" | "ulong" => Some(ValueType::U64),
            "f32" | "float" => Some(ValueType::F32),
            "f64" | "double" => Some(ValueType::F64),
            _ => None,
        }
    }
}

/// A scan result: address and current value
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub address: usize,
    pub value: ScanValue,
}

/// Value container for different types
#[derive(Debug, Clone, Copy)]
pub enum ScanValue {
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    F32(f32),
    F64(f64),
}

impl ScanValue {
    pub fn as_i64(&self) -> i64 {
        match self {
            ScanValue::I8(v) => *v as i64,
            ScanValue::I16(v) => *v as i64,
            ScanValue::I32(v) => *v as i64,
            ScanValue::I64(v) => *v,
            ScanValue::U8(v) => *v as i64,
            ScanValue::U16(v) => *v as i64,
            ScanValue::U32(v) => *v as i64,
            ScanValue::U64(v) => *v as i64,
            ScanValue::F32(v) => *v as i64,
            ScanValue::F64(v) => *v as i64,
        }
    }

    pub fn as_f64(&self) -> f64 {
        match self {
            ScanValue::I8(v) => *v as f64,
            ScanValue::I16(v) => *v as f64,
            ScanValue::I32(v) => *v as f64,
            ScanValue::I64(v) => *v as f64,
            ScanValue::U8(v) => *v as f64,
            ScanValue::U16(v) => *v as f64,
            ScanValue::U32(v) => *v as f64,
            ScanValue::U64(v) => *v as f64,
            ScanValue::F32(v) => *v as f64,
            ScanValue::F64(v) => *v,
        }
    }
}

impl std::fmt::Display for ScanValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanValue::I8(v) => write!(f, "{}", v),
            ScanValue::I16(v) => write!(f, "{}", v),
            ScanValue::I32(v) => write!(f, "{}", v),
            ScanValue::I64(v) => write!(f, "{}", v),
            ScanValue::U8(v) => write!(f, "{}", v),
            ScanValue::U16(v) => write!(f, "{}", v),
            ScanValue::U32(v) => write!(f, "{}", v),
            ScanValue::U64(v) => write!(f, "{}", v),
            ScanValue::F32(v) => write!(f, "{:.6}", v),
            ScanValue::F64(v) => write!(f, "{:.6}", v),
        }
    }
}

/// Scan type for filtering
#[derive(Debug, Clone)]
pub enum ScanType {
    /// Exact value match
    Exact(i64),
    /// Exact float value (with epsilon)
    ExactFloat(f64, f64), // value, epsilon
    /// Value in range [min, max]
    Range(i64, i64),
    /// Value greater than
    GreaterThan(i64),
    /// Value less than
    LessThan(i64),
    /// Unknown initial scan (stores all values)
    Unknown,
}

/// Memory scanner for finding values
pub struct Scanner {
    value_type: ValueType,
    results: Vec<ScanResult>,
    scan_count: usize,
}

impl Scanner {
    pub fn new(value_type: ValueType) -> Self {
        Self {
            value_type,
            results: Vec::new(),
            scan_count: 0,
        }
    }

    /// Get current results
    pub fn results(&self) -> &[ScanResult] {
        &self.results
    }

    /// Number of results
    pub fn count(&self) -> usize {
        self.results.len()
    }

    /// Number of scans performed
    pub fn scan_count(&self) -> usize {
        self.scan_count
    }

    /// Reset scanner
    pub fn reset(&mut self) {
        self.results.clear();
        self.scan_count = 0;
    }

    /// First scan - scan all readable regions
    pub fn first_scan(
        &mut self,
        proc: &mut ProcessMemory,
        regions: &[MemoryRegion],
        scan_type: ScanType,
    ) -> Result<usize, String> {
        self.results.clear();
        self.scan_count = 1;

        let value_size = self.value_type.size();

        for region in regions {
            if !region.is_readable() {
                continue;
            }

            // Read entire region
            let data = match proc.read_bytes(region.start, region.size()) {
                Ok(d) => d,
                Err(_) => continue, // Skip unreadable regions
            };

            // Scan through the data
            let mut offset = 0;
            while offset + value_size <= data.len() {
                let addr = region.start + offset;
                let slice = &data[offset..offset + value_size];

                if let Some(value) = self.read_value(slice) {
                    if self.matches(&value, &scan_type) {
                        self.results.push(ScanResult {
                            address: addr,
                            value,
                        });
                    }
                }

                offset += 1; // Scan at every byte offset for thoroughness
            }
        }

        Ok(self.results.len())
    }

    /// Next scan - filter existing results
    pub fn next_scan(
        &mut self,
        proc: &mut ProcessMemory,
        scan_type: ScanType,
    ) -> Result<usize, String> {
        if self.results.is_empty() {
            return Err("No previous scan results. Run first_scan first.".into());
        }

        self.scan_count += 1;
        let value_size = self.value_type.size();

        let mut new_results = Vec::new();

        for result in &self.results {
            // Read current value at this address
            let data = match proc.read_bytes(result.address, value_size) {
                Ok(d) => d,
                Err(_) => continue, // Address no longer readable
            };

            if let Some(value) = self.read_value(&data) {
                // Check if it matches the new scan criteria
                let matches = match &scan_type {
                    ScanType::Exact(target) => value.as_i64() == *target,
                    ScanType::ExactFloat(target, eps) => (value.as_f64() - target).abs() < *eps,
                    ScanType::Range(min, max) => {
                        let v = value.as_i64();
                        v >= *min && v <= *max
                    }
                    ScanType::GreaterThan(target) => value.as_i64() > *target,
                    ScanType::LessThan(target) => value.as_i64() < *target,
                    ScanType::Unknown => true,
                };

                if matches {
                    new_results.push(ScanResult {
                        address: result.address,
                        value,
                    });
                }
            }
        }

        self.results = new_results;
        Ok(self.results.len())
    }

    /// Scan for changed values (compared to last scan)
    pub fn scan_changed(&mut self, proc: &mut ProcessMemory) -> Result<usize, String> {
        if self.results.is_empty() {
            return Err("No previous scan results.".into());
        }

        self.scan_count += 1;
        let value_size = self.value_type.size();
        let mut new_results = Vec::new();

        for result in &self.results {
            let data = match proc.read_bytes(result.address, value_size) {
                Ok(d) => d,
                Err(_) => continue,
            };

            if let Some(value) = self.read_value(&data) {
                // Check if value changed
                if value.as_i64() != result.value.as_i64() {
                    new_results.push(ScanResult {
                        address: result.address,
                        value,
                    });
                }
            }
        }

        self.results = new_results;
        Ok(self.results.len())
    }

    /// Scan for unchanged values
    pub fn scan_unchanged(&mut self, proc: &mut ProcessMemory) -> Result<usize, String> {
        if self.results.is_empty() {
            return Err("No previous scan results.".into());
        }

        self.scan_count += 1;
        let value_size = self.value_type.size();
        let mut new_results = Vec::new();

        for result in &self.results {
            let data = match proc.read_bytes(result.address, value_size) {
                Ok(d) => d,
                Err(_) => continue,
            };

            if let Some(value) = self.read_value(&data) {
                if value.as_i64() == result.value.as_i64() {
                    new_results.push(ScanResult {
                        address: result.address,
                        value,
                    });
                }
            }
        }

        self.results = new_results;
        Ok(self.results.len())
    }

    /// Scan for increased values
    pub fn scan_increased(&mut self, proc: &mut ProcessMemory) -> Result<usize, String> {
        if self.results.is_empty() {
            return Err("No previous scan results.".into());
        }

        self.scan_count += 1;
        let value_size = self.value_type.size();
        let mut new_results = Vec::new();

        for result in &self.results {
            let data = match proc.read_bytes(result.address, value_size) {
                Ok(d) => d,
                Err(_) => continue,
            };

            if let Some(value) = self.read_value(&data) {
                if value.as_i64() > result.value.as_i64() {
                    new_results.push(ScanResult {
                        address: result.address,
                        value,
                    });
                }
            }
        }

        self.results = new_results;
        Ok(self.results.len())
    }

    /// Scan for decreased values
    pub fn scan_decreased(&mut self, proc: &mut ProcessMemory) -> Result<usize, String> {
        if self.results.is_empty() {
            return Err("No previous scan results.".into());
        }

        self.scan_count += 1;
        let value_size = self.value_type.size();
        let mut new_results = Vec::new();

        for result in &self.results {
            let data = match proc.read_bytes(result.address, value_size) {
                Ok(d) => d,
                Err(_) => continue,
            };

            if let Some(value) = self.read_value(&data) {
                if value.as_i64() < result.value.as_i64() {
                    new_results.push(ScanResult {
                        address: result.address,
                        value,
                    });
                }
            }
        }

        self.results = new_results;
        Ok(self.results.len())
    }

    /// Refresh all current results with their current values
    pub fn refresh(&mut self, proc: &mut ProcessMemory) -> Result<(), String> {
        let value_type = self.value_type;
        let value_size = value_type.size();

        for result in &mut self.results {
            let data = match proc.read_bytes(result.address, value_size) {
                Ok(d) => d,
                Err(_) => continue,
            };

            if let Some(value) = Self::read_value_static(value_type, &data) {
                result.value = value;
            }
        }

        Ok(())
    }

    fn read_value_static(value_type: ValueType, data: &[u8]) -> Option<ScanValue> {
        if data.len() < value_type.size() {
            return None;
        }

        Some(match value_type {
            ValueType::I8 => ScanValue::I8(i8::from_ne_bytes([data[0]])),
            ValueType::I16 => ScanValue::I16(i16::from_ne_bytes([data[0], data[1]])),
            ValueType::I32 => {
                ScanValue::I32(i32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
            }
            ValueType::I64 => ScanValue::I64(i64::from_ne_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])),
            ValueType::U8 => ScanValue::U8(data[0]),
            ValueType::U16 => ScanValue::U16(u16::from_ne_bytes([data[0], data[1]])),
            ValueType::U32 => {
                ScanValue::U32(u32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
            }
            ValueType::U64 => ScanValue::U64(u64::from_ne_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])),
            ValueType::F32 => {
                ScanValue::F32(f32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
            }
            ValueType::F64 => ScanValue::F64(f64::from_ne_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])),
        })
    }

    fn read_value(&self, data: &[u8]) -> Option<ScanValue> {
        if data.len() < self.value_type.size() {
            return None;
        }

        Some(match self.value_type {
            ValueType::I8 => ScanValue::I8(i8::from_ne_bytes([data[0]])),
            ValueType::I16 => ScanValue::I16(i16::from_ne_bytes([data[0], data[1]])),
            ValueType::I32 => {
                ScanValue::I32(i32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
            }
            ValueType::I64 => ScanValue::I64(i64::from_ne_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])),
            ValueType::U8 => ScanValue::U8(data[0]),
            ValueType::U16 => ScanValue::U16(u16::from_ne_bytes([data[0], data[1]])),
            ValueType::U32 => {
                ScanValue::U32(u32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
            }
            ValueType::U64 => ScanValue::U64(u64::from_ne_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])),
            ValueType::F32 => {
                ScanValue::F32(f32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
            }
            ValueType::F64 => ScanValue::F64(f64::from_ne_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])),
        })
    }

    fn matches(&self, value: &ScanValue, scan_type: &ScanType) -> bool {
        match scan_type {
            ScanType::Exact(target) => value.as_i64() == *target,
            ScanType::ExactFloat(target, eps) => (value.as_f64() - target).abs() < *eps,
            ScanType::Range(min, max) => {
                let v = value.as_i64();
                v >= *min && v <= *max
            }
            ScanType::GreaterThan(target) => value.as_i64() > *target,
            ScanType::LessThan(target) => value.as_i64() < *target,
            ScanType::Unknown => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_type_size() {
        assert_eq!(ValueType::I8.size(), 1);
        assert_eq!(ValueType::I32.size(), 4);
        assert_eq!(ValueType::F64.size(), 8);
    }

    #[test]
    fn test_value_type_from_str() {
        assert_eq!(ValueType::from_str("i32"), Some(ValueType::I32));
        assert_eq!(ValueType::from_str("int"), Some(ValueType::I32));
        assert_eq!(ValueType::from_str("float"), Some(ValueType::F32));
        assert_eq!(ValueType::from_str("invalid"), None);
    }
}
