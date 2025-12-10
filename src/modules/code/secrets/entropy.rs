/// Entropy Analysis Module
///
/// Calculates Shannon entropy to detect high-entropy strings
/// that might be secrets (API keys, tokens, etc.)

use std::collections::HashMap;

/// Entropy analyzer for detecting random/secret-like strings
pub struct EntropyAnalyzer {
    /// Minimum entropy threshold for secrets
    pub threshold: f64,
    /// Minimum string length to analyze
    pub min_length: usize,
    /// Character sets for different entropy calculations
    pub charsets: Vec<CharSet>,
}

/// Predefined character sets for entropy calculation
#[derive(Debug, Clone)]
pub struct CharSet {
    pub name: &'static str,
    pub chars: &'static str,
    pub max_entropy: f64,
}

impl EntropyAnalyzer {
    pub fn new(threshold: f64) -> Self {
        Self {
            threshold,
            min_length: 8,
            charsets: vec![
                CharSet {
                    name: "hex",
                    chars: "0123456789abcdefABCDEF",
                    max_entropy: 4.0, // log2(16)
                },
                CharSet {
                    name: "base64",
                    chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
                    max_entropy: 6.0, // log2(64)
                },
                CharSet {
                    name: "alphanumeric",
                    chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    max_entropy: 5.95, // log2(62)
                },
                CharSet {
                    name: "printable",
                    chars: "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
                    max_entropy: 6.55, // log2(94)
                },
            ],
        }
    }

    /// Calculate Shannon entropy of a string
    pub fn shannon_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut char_counts: HashMap<char, usize> = HashMap::new();
        let len = s.len() as f64;

        for c in s.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }

        let mut entropy = 0.0;
        for &count in char_counts.values() {
            let p = count as f64 / len;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Calculate normalized entropy (0.0 - 1.0)
    pub fn normalized_entropy(&self, s: &str) -> f64 {
        let entropy = self.shannon_entropy(s);
        let max_entropy = (s.chars().collect::<std::collections::HashSet<_>>().len() as f64).log2();

        if max_entropy > 0.0 {
            entropy / max_entropy
        } else {
            0.0
        }
    }

    /// Check if string has high entropy
    pub fn is_high_entropy(&self, s: &str) -> bool {
        if s.len() < self.min_length {
            return false;
        }

        let entropy = self.shannon_entropy(s);
        entropy >= self.threshold
    }

    /// Analyze string and return entropy details
    pub fn analyze(&self, s: &str) -> EntropyResult {
        let entropy = self.shannon_entropy(s);
        let normalized = self.normalized_entropy(s);

        // Determine best matching charset
        let charset = self.detect_charset(s);

        // Calculate charset-relative entropy
        let relative_entropy = if let Some(ref cs) = charset {
            entropy / cs.max_entropy
        } else {
            normalized
        };

        EntropyResult {
            value: s.to_string(),
            entropy,
            normalized_entropy: normalized,
            relative_entropy,
            is_high_entropy: entropy >= self.threshold,
            charset: charset.map(|c| c.name.to_string()),
            unique_chars: s.chars().collect::<std::collections::HashSet<_>>().len(),
            total_chars: s.len(),
        }
    }

    /// Detect which charset a string belongs to
    fn detect_charset(&self, s: &str) -> Option<CharSet> {
        for charset in &self.charsets {
            if s.chars().all(|c| charset.chars.contains(c)) {
                return Some(charset.clone());
            }
        }
        None
    }

    /// Find high-entropy substrings in text
    pub fn find_high_entropy_strings(&self, text: &str) -> Vec<EntropyResult> {
        let mut results = Vec::new();

        // Split on common delimiters
        let delimiters = [' ', '\n', '\t', '\'', '"', '`', '=', ':', ';', ',', '(', ')', '[', ']', '{', '}'];

        for word in text.split(|c| delimiters.contains(&c)) {
            let trimmed = word.trim();
            if trimmed.len() >= self.min_length {
                let result = self.analyze(trimmed);
                if result.is_high_entropy {
                    results.push(result);
                }
            }
        }

        results
    }

    /// Calculate entropy for different sections of a string
    pub fn sliding_window_entropy(&self, s: &str, window_size: usize) -> Vec<(usize, f64)> {
        let mut results = Vec::new();

        if s.len() < window_size {
            return results;
        }

        let chars: Vec<char> = s.chars().collect();
        for i in 0..=chars.len() - window_size {
            let window: String = chars[i..i + window_size].iter().collect();
            let entropy = self.shannon_entropy(&window);
            results.push((i, entropy));
        }

        results
    }

    /// Check if string looks like a secret based on patterns
    pub fn looks_like_secret(&self, s: &str) -> SecretLikelihood {
        let entropy = self.shannon_entropy(s);
        let normalized = self.normalized_entropy(s);
        let len = s.len();

        // Short strings are less likely to be secrets
        if len < 8 {
            return SecretLikelihood::Unlikely;
        }

        // Very high entropy is suspicious
        if entropy >= 4.5 && len >= 20 {
            return SecretLikelihood::HighlyLikely;
        }

        // High entropy
        if entropy >= 4.0 && len >= 16 {
            return SecretLikelihood::Likely;
        }

        // Moderate entropy
        if entropy >= 3.5 && len >= 12 {
            return SecretLikelihood::Possible;
        }

        // Low entropy or short
        SecretLikelihood::Unlikely
    }

    /// Check if string is likely base64 encoded
    pub fn is_base64_like(&self, s: &str) -> bool {
        if s.len() < 4 {
            return false;
        }

        // Must only contain base64 characters
        let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        if !s.chars().all(|c| base64_chars.contains(c)) {
            return false;
        }

        // Check for proper padding
        let padding_count = s.chars().filter(|c| *c == '=').count();
        if padding_count > 2 {
            return false;
        }

        // Padding should only be at the end
        if s.contains('=') && !s.ends_with('=') {
            return false;
        }

        // Length should be divisible by 4 (for proper base64)
        s.len() % 4 == 0 || padding_count == 0
    }

    /// Check if string is likely hex encoded
    pub fn is_hex_like(&self, s: &str) -> bool {
        if s.len() < 8 {
            return false;
        }

        // Must only contain hex characters
        s.chars().all(|c| c.is_ascii_hexdigit())
            // Usually even length for hex
            && s.len() % 2 == 0
    }
}

impl Default for EntropyAnalyzer {
    fn default() -> Self {
        Self::new(4.0) // Default threshold
    }
}

/// Result of entropy analysis
#[derive(Debug, Clone)]
pub struct EntropyResult {
    /// The analyzed string
    pub value: String,
    /// Shannon entropy value
    pub entropy: f64,
    /// Normalized entropy (0.0 - 1.0)
    pub normalized_entropy: f64,
    /// Entropy relative to detected charset
    pub relative_entropy: f64,
    /// Whether this is considered high entropy
    pub is_high_entropy: bool,
    /// Detected character set
    pub charset: Option<String>,
    /// Number of unique characters
    pub unique_chars: usize,
    /// Total characters
    pub total_chars: usize,
}

impl EntropyResult {
    /// Get a human-readable description
    pub fn description(&self) -> String {
        let level = if self.entropy >= 5.0 {
            "very high"
        } else if self.entropy >= 4.0 {
            "high"
        } else if self.entropy >= 3.0 {
            "moderate"
        } else {
            "low"
        };

        format!(
            "Entropy: {:.2} ({}) - {} unique chars in {} total",
            self.entropy, level, self.unique_chars, self.total_chars
        )
    }
}

/// Likelihood that a string is a secret
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretLikelihood {
    Unlikely,
    Possible,
    Likely,
    HighlyLikely,
}

impl std::fmt::Display for SecretLikelihood {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unlikely => write!(f, "Unlikely"),
            Self::Possible => write!(f, "Possible"),
            Self::Likely => write!(f, "Likely"),
            Self::HighlyLikely => write!(f, "Highly Likely"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy() {
        let analyzer = EntropyAnalyzer::default();

        // Low entropy (repeated characters)
        let low = analyzer.shannon_entropy("aaaaaaaaaa");
        assert!(low < 1.0);

        // High entropy (random-looking)
        let high = analyzer.shannon_entropy("aB3kL9xQ2pM7wE4y");
        assert!(high > 3.5);
    }

    #[test]
    fn test_is_high_entropy() {
        let analyzer = EntropyAnalyzer::new(4.0);

        // Low entropy string
        assert!(!analyzer.is_high_entropy("password123"));

        // High entropy string (like an API key)
        assert!(analyzer.is_high_entropy("aB3kL9xQ2pM7wE4yJ8nR5tH0"));
    }

    #[test]
    fn test_is_base64_like() {
        let analyzer = EntropyAnalyzer::default();

        assert!(analyzer.is_base64_like("SGVsbG8gV29ybGQ="));
        assert!(analyzer.is_base64_like("dGVzdGluZw=="));
        assert!(!analyzer.is_base64_like("hello world"));
        assert!(!analyzer.is_base64_like("test@#$"));
    }

    #[test]
    fn test_is_hex_like() {
        let analyzer = EntropyAnalyzer::default();

        assert!(analyzer.is_hex_like("deadbeef12345678"));
        assert!(analyzer.is_hex_like("ABCDEF0123456789"));
        assert!(!analyzer.is_hex_like("not-hex"));
        assert!(!analyzer.is_hex_like("ghijkl")); // Invalid hex chars
    }

    #[test]
    fn test_looks_like_secret() {
        let analyzer = EntropyAnalyzer::default();

        // Should look like a secret
        let likely = analyzer.looks_like_secret("ghp_xK4mL9bN3pR7wE2yJ8nQ5tH0zS6vU1cA");
        assert!(likely == SecretLikelihood::HighlyLikely || likely == SecretLikelihood::Likely);

        // Should not look like a secret
        let unlikely = analyzer.looks_like_secret("hello");
        assert_eq!(unlikely, SecretLikelihood::Unlikely);
    }
}
