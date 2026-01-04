//! Entropy Analysis
//!
//! Shannon entropy calculation and randomness analysis for data classification.

/// Shannon entropy calculator
pub struct EntropyAnalyzer;

impl Default for EntropyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyAnalyzer {
    /// Create new entropy analyzer
    pub fn new() -> Self {
        Self
    }

    /// Calculate Shannon entropy (bits per byte)
    ///
    /// Returns a value between 0.0 (completely uniform) and 8.0 (maximum entropy/random)
    pub fn calculate(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        // Count byte frequencies
        let mut counts = [0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Analyze data and return detailed entropy results
    pub fn analyze(&self, data: &[u8]) -> EntropyResult {
        let entropy = self.calculate(data);
        let classification = self.classify(entropy);
        let byte_distribution = self.byte_distribution(data);
        let unique_bytes = byte_distribution.iter().filter(|&&c| c > 0).count();

        EntropyResult {
            entropy,
            entropy_percent: entropy / 8.0 * 100.0,
            classification,
            unique_bytes,
            total_bytes: data.len(),
            is_likely_compressed: entropy > 7.5,
            is_likely_encrypted: entropy > 7.8,
            is_likely_text: entropy < 5.0 && entropy > 2.0,
            byte_distribution,
        }
    }

    /// Classify entropy level
    fn classify(&self, entropy: f64) -> EntropyClassification {
        if entropy < 1.0 {
            EntropyClassification::VeryLow
        } else if entropy < 3.0 {
            EntropyClassification::Low
        } else if entropy < 5.0 {
            EntropyClassification::Medium
        } else if entropy < 7.0 {
            EntropyClassification::High
        } else if entropy < 7.8 {
            EntropyClassification::VeryHigh
        } else {
            EntropyClassification::Maximum
        }
    }

    /// Get byte distribution
    fn byte_distribution(&self, data: &[u8]) -> [u64; 256] {
        let mut counts = [0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        counts
    }

    /// Calculate chi-squared statistic against uniform distribution
    pub fn chi_squared(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let expected = data.len() as f64 / 256.0;
        let mut chi_sq = 0.0;

        for &count in &counts {
            let diff = count as f64 - expected;
            chi_sq += (diff * diff) / expected;
        }

        chi_sq
    }

    /// Calculate entropy for a sliding window across data
    pub fn windowed_entropy(&self, data: &[u8], window_size: usize) -> Vec<(usize, f64)> {
        if data.len() < window_size {
            return vec![(0, self.calculate(data))];
        }

        let mut results = Vec::with_capacity(data.len() - window_size + 1);
        for i in 0..=(data.len() - window_size) {
            let window = &data[i..i + window_size];
            results.push((i, self.calculate(window)));
        }
        results
    }

    /// Find regions of high/low entropy
    pub fn find_entropy_regions(
        &self,
        data: &[u8],
        window_size: usize,
        threshold: f64,
    ) -> Vec<EntropyRegion> {
        let windowed = self.windowed_entropy(data, window_size);
        let mut regions = Vec::new();
        let mut current_region: Option<EntropyRegion> = None;

        for (offset, entropy) in windowed {
            let is_high = entropy >= threshold;

            match &mut current_region {
                Some(region) if region.is_high_entropy == is_high => {
                    region.end = offset + window_size;
                    region.max_entropy = region.max_entropy.max(entropy);
                    region.min_entropy = region.min_entropy.min(entropy);
                }
                Some(region) => {
                    regions.push(region.clone());
                    current_region = Some(EntropyRegion {
                        start: offset,
                        end: offset + window_size,
                        is_high_entropy: is_high,
                        avg_entropy: entropy,
                        max_entropy: entropy,
                        min_entropy: entropy,
                    });
                }
                None => {
                    current_region = Some(EntropyRegion {
                        start: offset,
                        end: offset + window_size,
                        is_high_entropy: is_high,
                        avg_entropy: entropy,
                        max_entropy: entropy,
                        min_entropy: entropy,
                    });
                }
            }
        }

        if let Some(region) = current_region {
            regions.push(region);
        }

        regions
    }
}

/// Classification of entropy levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyClassification {
    /// < 1.0 bits/byte - very uniform data
    VeryLow,
    /// 1.0 - 3.0 bits/byte - low entropy (sparse data)
    Low,
    /// 3.0 - 5.0 bits/byte - typical text
    Medium,
    /// 5.0 - 7.0 bits/byte - binary data
    High,
    /// 7.0 - 7.8 bits/byte - compressed data
    VeryHigh,
    /// > 7.8 bits/byte - encrypted/random data
    Maximum,
}

impl std::fmt::Display for EntropyClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::VeryLow => "Very Low (uniform/sparse)",
            Self::Low => "Low (repetitive)",
            Self::Medium => "Medium (text-like)",
            Self::High => "High (binary)",
            Self::VeryHigh => "Very High (compressed)",
            Self::Maximum => "Maximum (encrypted/random)",
        };
        write!(f, "{}", s)
    }
}

/// Result of entropy analysis
#[derive(Debug, Clone)]
pub struct EntropyResult {
    /// Shannon entropy in bits per byte (0.0 - 8.0)
    pub entropy: f64,
    /// Entropy as percentage of maximum
    pub entropy_percent: f64,
    /// Classification of entropy level
    pub classification: EntropyClassification,
    /// Number of unique byte values
    pub unique_bytes: usize,
    /// Total bytes analyzed
    pub total_bytes: usize,
    /// Whether data is likely compressed
    pub is_likely_compressed: bool,
    /// Whether data is likely encrypted
    pub is_likely_encrypted: bool,
    /// Whether data is likely text
    pub is_likely_text: bool,
    /// Distribution of each byte value
    pub byte_distribution: [u64; 256],
}

/// A region of data with consistent entropy characteristics
#[derive(Debug, Clone)]
pub struct EntropyRegion {
    pub start: usize,
    pub end: usize,
    pub is_high_entropy: bool,
    pub avg_entropy: f64,
    pub max_entropy: f64,
    pub min_entropy: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_uniform() {
        let analyzer = EntropyAnalyzer::new();

        // All same byte - entropy should be 0
        let data = vec![0u8; 100];
        let result = analyzer.analyze(&data);
        assert!(result.entropy < 0.1);
        assert_eq!(result.classification, EntropyClassification::VeryLow);
    }

    #[test]
    fn test_entropy_text() {
        let analyzer = EntropyAnalyzer::new();

        // English text has moderate entropy
        let data =
            b"The quick brown fox jumps over the lazy dog. This is a test of entropy calculation.";
        let result = analyzer.analyze(data);
        assert!(result.entropy > 3.0 && result.entropy < 6.0);
        assert!(result.is_likely_text);
    }

    #[test]
    fn test_entropy_high() {
        let analyzer = EntropyAnalyzer::new();

        // All different bytes - maximum entropy
        let data: Vec<u8> = (0..=255).collect();
        let result = analyzer.analyze(&data);
        assert!(result.entropy > 7.9);
        assert_eq!(result.classification, EntropyClassification::Maximum);
    }

    #[test]
    fn test_windowed_entropy() {
        let analyzer = EntropyAnalyzer::new();

        // Mix of low and high entropy regions
        let mut data = vec![0u8; 100];
        data.extend((0..=255).collect::<Vec<u8>>());
        data.extend(vec![0u8; 100]);

        let regions = analyzer.find_entropy_regions(&data, 50, 5.0);
        assert!(regions.len() >= 2);
    }
}
