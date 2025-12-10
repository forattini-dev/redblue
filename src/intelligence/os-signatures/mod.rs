/// OS Fingerprint Signature Database
///
/// Modular TCP/IP stack fingerprint database for OS detection.
/// Organized by OS family for easier maintenance and expansion.
///
/// ## ID Ranges:
/// - 1000-1999: Linux (kernel, distributions, embedded)
/// - 2000-2999: Windows (server, desktop, embedded)
/// - 3000-3999: macOS/Apple (macOS, iOS, tvOS, etc.)
/// - 4000-4999: BSD/Unix (FreeBSD, OpenBSD, Solaris, AIX)
/// - 5000-5999: Network devices (Cisco, Juniper, Fortinet, etc.)
/// - 6000-6999: Reserved for IoT/embedded
/// - 7000-7999: Reserved for future use
///
/// ## Usage:
/// ```rust
/// use crate::intelligence::os_signatures::{OsSignatureDb, OsSignature};
///
/// let db = OsSignatureDb::new();
/// println!("Loaded {} OS signatures", db.len());
///
/// // Find matches for observed TCP/IP parameters
/// let matches = db.find_matches(64, 65535, Some(1460), Some(7), "MSNWT");
/// for (sig, score) in matches {
///     println!("{}: {:.1}% confidence", sig.name, score * 100.0);
/// }
/// ```

mod types;
mod linux;
mod windows;
mod macos;
mod bsd;
mod network;

pub use types::*;

use std::collections::HashMap;

/// OS Signature Database with indexing for fast lookups
pub struct OsSignatureDb {
    /// All signatures
    signatures: Vec<OsSignature>,

    /// Index by initial TTL value
    by_ttl: HashMap<u8, Vec<usize>>,

    /// Index by OS family
    by_family: HashMap<String, Vec<usize>>,

    /// Index by device type
    by_device: HashMap<DeviceType, Vec<usize>>,

    /// Index by vendor
    by_vendor: HashMap<String, Vec<usize>>,
}

impl OsSignatureDb {
    /// Create a new database with all built-in signatures
    pub fn new() -> Self {
        let mut db = Self {
            signatures: Vec::with_capacity(500),
            by_ttl: HashMap::new(),
            by_family: HashMap::new(),
            by_device: HashMap::new(),
            by_vendor: HashMap::new(),
        };

        // Load all signature modules
        db.load_signatures(linux::signatures());
        db.load_signatures(windows::signatures());
        db.load_signatures(macos::signatures());
        db.load_signatures(bsd::signatures());
        db.load_signatures(network::signatures());

        db
    }

    /// Create an empty database (for custom signatures only)
    pub fn empty() -> Self {
        Self {
            signatures: Vec::new(),
            by_ttl: HashMap::new(),
            by_family: HashMap::new(),
            by_device: HashMap::new(),
            by_vendor: HashMap::new(),
        }
    }

    fn load_signatures(&mut self, sigs: Vec<OsSignature>) {
        for sig in sigs {
            self.add_signature(sig);
        }
    }

    /// Add a single signature to the database
    pub fn add_signature(&mut self, sig: OsSignature) {
        let idx = self.signatures.len();

        // Index by TTL
        if let Some(ttl) = sig.ttl.get_initial_ttl() {
            self.by_ttl.entry(ttl).or_default().push(idx);
        }

        // Index by family
        if !sig.os_family.is_empty() {
            self.by_family
                .entry(sig.os_family.clone())
                .or_default()
                .push(idx);
        }

        // Index by device type
        self.by_device
            .entry(sig.device_type.clone())
            .or_default()
            .push(idx);

        // Index by vendor
        if !sig.vendor.is_empty() {
            self.by_vendor
                .entry(sig.vendor.to_lowercase())
                .or_default()
                .push(idx);
        }

        self.signatures.push(sig);
    }

    /// Get total number of signatures
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Check if database is empty
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Get a signature by ID
    pub fn get(&self, id: u32) -> Option<&OsSignature> {
        self.signatures.iter().find(|s| s.id == id)
    }

    /// Get all signatures for a specific TTL
    pub fn by_ttl(&self, ttl: u8) -> Vec<&OsSignature> {
        // Try common initial TTLs
        let initial_ttl = Self::estimate_initial_ttl(ttl);

        self.by_ttl
            .get(&initial_ttl)
            .map(|indices| indices.iter().map(|&i| &self.signatures[i]).collect())
            .unwrap_or_default()
    }

    /// Get all signatures for a specific OS family
    pub fn by_family(&self, family: &str) -> Vec<&OsSignature> {
        self.by_family
            .get(family)
            .map(|indices| indices.iter().map(|&i| &self.signatures[i]).collect())
            .unwrap_or_default()
    }

    /// Get all signatures for a specific device type
    pub fn by_device_type(&self, device: &DeviceType) -> Vec<&OsSignature> {
        self.by_device
            .get(device)
            .map(|indices| indices.iter().map(|&i| &self.signatures[i]).collect())
            .unwrap_or_default()
    }

    /// Get all signatures for a specific vendor (case-insensitive)
    pub fn by_vendor(&self, vendor: &str) -> Vec<&OsSignature> {
        self.by_vendor
            .get(&vendor.to_lowercase())
            .map(|indices| indices.iter().map(|&i| &self.signatures[i]).collect())
            .unwrap_or_default()
    }

    /// Estimate initial TTL from observed value
    fn estimate_initial_ttl(observed: u8) -> u8 {
        // Common initial TTL values and their thresholds
        match observed {
            0..=32 => 32,     // Very old Windows 95
            33..=64 => 64,    // Linux, macOS, BSD, most modern
            65..=128 => 128,  // Windows
            129..=255 => 255, // Solaris, Cisco IOS, network devices
        }
    }

    /// Find matching signatures based on observed TCP/IP parameters
    ///
    /// Returns a list of (signature, match_score) sorted by score descending.
    /// Score is 0.0 to 1.0 where 1.0 is a perfect match.
    pub fn find_matches(
        &self,
        ttl: u8,
        window_size: u16,
        mss: Option<u16>,
        window_scale: Option<u8>,
        tcp_options: &str,
    ) -> Vec<(&OsSignature, f32)> {
        let mut matches: Vec<(&OsSignature, f32)> = Vec::new();

        for sig in &self.signatures {
            let score = self.calculate_match_score(sig, ttl, window_size, mss, window_scale, tcp_options);
            if score > 0.3 {
                // Minimum threshold
                matches.push((sig, score));
            }
        }

        // Sort by score descending
        matches.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Limit results
        matches.truncate(10);
        matches
    }

    /// Calculate match score for a signature against observed parameters
    fn calculate_match_score(
        &self,
        sig: &OsSignature,
        ttl: u8,
        window_size: u16,
        mss: Option<u16>,
        window_scale: Option<u8>,
        tcp_options: &str,
    ) -> f32 {
        let mut score = 0.0f32;
        let mut max_score = 0.0f32;

        // TTL matching (weight: 25%)
        max_score += 0.25;
        if sig.ttl.matches(ttl) {
            score += 0.25;
        }

        // Window size matching (weight: 20%)
        max_score += 0.20;
        if sig.window_size.matches(window_size) {
            score += 0.20;
        }

        // MSS matching (weight: 15%)
        max_score += 0.15;
        if sig.mss.matches(mss) {
            score += 0.15;
        }

        // Window scale matching (weight: 15%)
        max_score += 0.15;
        match (&sig.window_scale, window_scale) {
            (Some(expected), Some(observed)) if *expected == observed => score += 0.15,
            (Some(_), Some(_)) => score += 0.05, // Partial match
            (None, None) => score += 0.15,       // Both absent
            _ => {}
        }

        // TCP options pattern matching (weight: 20%)
        max_score += 0.20;
        if sig.tcp_options.matches(tcp_options) {
            score += 0.20;
        } else if !tcp_options.is_empty() {
            // Partial credit for having some options match
            let pattern_chars: std::collections::HashSet<char> =
                sig.tcp_options.pattern.chars().collect();
            let observed_chars: std::collections::HashSet<char> = tcp_options.chars().collect();
            let common = pattern_chars.intersection(&observed_chars).count();
            let total = pattern_chars.len().max(1);
            score += 0.20 * (common as f32 / total as f32) * 0.5; // Half credit for partial match
        }

        // DF bit matching (weight: 5%)
        if sig.df_bit.is_some() {
            max_score += 0.05;
            // Note: We don't have DF bit in parameters, would need raw packet
        }

        // Normalize score and apply confidence weight
        let normalized = if max_score > 0.0 {
            score / max_score
        } else {
            0.0
        };

        normalized * sig.confidence_weight
    }

    /// Find best match for observed parameters
    pub fn best_match(
        &self,
        ttl: u8,
        window_size: u16,
        mss: Option<u16>,
        window_scale: Option<u8>,
        tcp_options: &str,
    ) -> Option<(&OsSignature, f32)> {
        self.find_matches(ttl, window_size, mss, window_scale, tcp_options)
            .into_iter()
            .next()
    }

    /// Get statistics about the database
    pub fn stats(&self) -> DbStats {
        let mut families: HashMap<String, usize> = HashMap::new();
        let mut devices: HashMap<DeviceType, usize> = HashMap::new();

        for sig in &self.signatures {
            *families.entry(sig.os_family.clone()).or_default() += 1;
            *devices.entry(sig.device_type.clone()).or_default() += 1;
        }

        DbStats {
            total_signatures: self.signatures.len(),
            unique_families: families.len(),
            unique_vendors: self.by_vendor.len(),
            by_family: families,
            by_device_type: devices,
        }
    }

    /// Iterator over all signatures
    pub fn iter(&self) -> impl Iterator<Item = &OsSignature> {
        self.signatures.iter()
    }

    /// Get a reference to all signatures (for compatibility)
    pub fn signatures(&self) -> &[OsSignature] {
        &self.signatures
    }
}

impl Default for OsSignatureDb {
    fn default() -> Self {
        Self::new()
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DbStats {
    pub total_signatures: usize,
    pub unique_families: usize,
    pub unique_vendors: usize,
    pub by_family: HashMap<String, usize>,
    pub by_device_type: HashMap<DeviceType, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_creation() {
        let db = OsSignatureDb::new();
        assert!(db.len() >= 200, "Expected at least 200 signatures, got {}", db.len());
    }

    #[test]
    fn test_unique_ids() {
        let db = OsSignatureDb::new();
        let mut ids: Vec<u32> = db.iter().map(|s| s.id).collect();
        ids.sort();
        let unique_count = ids.len();
        ids.dedup();
        assert_eq!(unique_count, ids.len(), "Duplicate signature IDs found in database");
    }

    #[test]
    fn test_get_by_id() {
        let db = OsSignatureDb::new();

        // Linux kernel
        let linux = db.get(1000);
        assert!(linux.is_some());
        assert!(linux.unwrap().name.contains("Linux"));

        // Windows Server
        let windows = db.get(2000);
        assert!(windows.is_some());
        assert!(windows.unwrap().name.contains("Windows"));
    }

    #[test]
    fn test_find_linux_by_ttl() {
        let db = OsSignatureDb::new();
        let matches = db.by_ttl(64);
        assert!(!matches.is_empty());

        // Should include Linux and macOS (both use TTL 64)
        let has_linux = matches.iter().any(|s| s.os_family == "Linux");
        assert!(has_linux, "TTL 64 should include Linux signatures");
    }

    #[test]
    fn test_find_windows_by_ttl() {
        let db = OsSignatureDb::new();
        let matches = db.by_ttl(128);
        assert!(!matches.is_empty());

        let has_windows = matches.iter().any(|s| s.os_family == "Windows");
        assert!(has_windows, "TTL 128 should include Windows signatures");
    }

    #[test]
    fn test_find_by_family() {
        let db = OsSignatureDb::new();

        let linux = db.by_family("Linux");
        assert!(linux.len() >= 30, "Expected many Linux signatures");

        let windows = db.by_family("Windows");
        assert!(windows.len() >= 20, "Expected many Windows signatures");

        let bsd = db.by_family("BSD");
        assert!(bsd.len() >= 10, "Expected BSD signatures");
    }

    #[test]
    fn test_find_by_vendor() {
        let db = OsSignatureDb::new();

        let cisco = db.by_vendor("Cisco");
        assert!(!cisco.is_empty(), "Expected Cisco signatures");

        let microsoft = db.by_vendor("microsoft");
        assert!(!microsoft.is_empty(), "Expected Microsoft signatures (case-insensitive)");
    }

    #[test]
    fn test_find_matches_linux() {
        let db = OsSignatureDb::new();

        // Typical modern Linux parameters
        let matches = db.find_matches(64, 65535, Some(1460), Some(7), "MSNWT");
        assert!(!matches.is_empty());

        // Top matches should include Linux
        let top_match = &matches[0];
        assert!(
            top_match.0.os_family == "Linux" || top_match.0.os_family == "macOS",
            "Top match should be Linux or macOS, got {}",
            top_match.0.os_family
        );
    }

    #[test]
    fn test_find_matches_windows() {
        let db = OsSignatureDb::new();

        // Typical Windows parameters
        let matches = db.find_matches(128, 65535, Some(1460), Some(8), "MNWST");
        assert!(!matches.is_empty());

        let top_match = &matches[0];
        assert!(
            top_match.0.os_family == "Windows",
            "Top match should be Windows, got {}",
            top_match.0.os_family
        );
    }

    #[test]
    fn test_database_stats() {
        let db = OsSignatureDb::new();
        let stats = db.stats();

        assert!(stats.total_signatures >= 200);
        assert!(stats.unique_families >= 5);
        assert!(stats.unique_vendors >= 20);

        // Check we have diverse device types
        assert!(stats.by_device_type.len() >= 5);
    }

    #[test]
    fn test_best_match() {
        let db = OsSignatureDb::new();

        // Should find a match
        let result = db.best_match(64, 29200, Some(1460), Some(7), "MSNWT");
        assert!(result.is_some());

        let (sig, score) = result.unwrap();
        assert!(score > 0.5, "Best match should have score > 0.5");
        assert!(!sig.name.is_empty());
    }

    #[test]
    fn test_empty_database() {
        let db = OsSignatureDb::empty();
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());
    }
}
