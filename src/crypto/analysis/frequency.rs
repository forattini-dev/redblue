//! Frequency Analysis
//!
//! Character and pattern frequency analysis for cryptanalysis.

use std::collections::HashMap;

/// Reference frequency tables for various languages
pub struct LanguageFrequency {
    /// Language name
    pub name: &'static str,
    /// Letter frequencies (a-z)
    pub letters: [f64; 26],
    /// Index of Coincidence
    pub ioc: f64,
}

/// English letter frequencies
pub const ENGLISH: LanguageFrequency = LanguageFrequency {
    name: "English",
    letters: [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
        0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
        0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
    ],
    ioc: 0.0667,
};

/// German letter frequencies
pub const GERMAN: LanguageFrequency = LanguageFrequency {
    name: "German",
    letters: [
        0.06516, 0.01886, 0.02732, 0.05076, 0.16396, 0.01656, 0.03009, 0.04577, 0.06550, 0.00268,
        0.01417, 0.03437, 0.02534, 0.09776, 0.02594, 0.00670, 0.00018, 0.07003, 0.07270, 0.06154,
        0.04166, 0.00846, 0.01921, 0.00034, 0.00039, 0.01134,
    ],
    ioc: 0.0762,
};

/// French letter frequencies
pub const FRENCH: LanguageFrequency = LanguageFrequency {
    name: "French",
    letters: [
        0.07636, 0.00901, 0.03260, 0.03669, 0.14715, 0.01066, 0.00866, 0.00737, 0.07529, 0.00613,
        0.00074, 0.05456, 0.02968, 0.07095, 0.05796, 0.02521, 0.01362, 0.06693, 0.07948, 0.07244,
        0.06311, 0.01838, 0.00049, 0.00427, 0.00128, 0.00326,
    ],
    ioc: 0.0778,
};

/// Analysis result for frequency analysis
#[derive(Debug, Clone)]
pub struct FrequencyResult {
    /// Character frequencies (normalized)
    pub frequencies: HashMap<char, f64>,
    /// Index of Coincidence
    pub ioc: f64,
    /// Chi-squared scores against reference languages
    pub chi_squared: Vec<(String, f64)>,
    /// Most likely language
    pub likely_language: String,
    /// Most frequent characters
    pub top_chars: Vec<(char, f64)>,
    /// Bigram frequencies
    pub bigrams: Vec<(String, f64)>,
}

/// Frequency analyzer
pub struct FrequencyAnalyzer {
    languages: Vec<&'static LanguageFrequency>,
}

impl Default for FrequencyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl FrequencyAnalyzer {
    /// Create new frequency analyzer
    pub fn new() -> Self {
        Self {
            languages: vec![&ENGLISH, &GERMAN, &FRENCH],
        }
    }

    /// Analyze text frequencies
    pub fn analyze(&self, text: &str) -> FrequencyResult {
        let mut freq: HashMap<char, f64> = HashMap::new();
        let mut total = 0.0;

        // Count letter frequencies
        for c in text.chars() {
            if c.is_ascii_alphabetic() {
                let c = c.to_ascii_lowercase();
                *freq.entry(c).or_insert(0.0) += 1.0;
                total += 1.0;
            }
        }

        // Normalize
        if total > 0.0 {
            for v in freq.values_mut() {
                *v /= total;
            }
        }

        // Calculate Index of Coincidence
        let ioc = self.calculate_ioc(text);

        // Calculate chi-squared against languages
        let mut chi_squared: Vec<(String, f64)> = self
            .languages
            .iter()
            .map(|lang| {
                (
                    lang.name.to_string(),
                    self.chi_squared(&freq, &lang.letters),
                )
            })
            .collect();

        chi_squared.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        let likely_language = chi_squared.first().map(|x| x.0.clone()).unwrap_or_default();

        // Top characters
        let mut top_chars: Vec<(char, f64)> = freq.clone().into_iter().collect();
        top_chars.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        top_chars.truncate(10);

        // Bigram analysis
        let bigrams = self.analyze_bigrams(text);

        FrequencyResult {
            frequencies: freq,
            ioc,
            chi_squared,
            likely_language,
            top_chars,
            bigrams,
        }
    }

    /// Calculate Index of Coincidence
    pub fn calculate_ioc(&self, text: &str) -> f64 {
        let mut freq = [0u64; 26];
        let mut n = 0u64;

        for c in text.chars() {
            if c.is_ascii_alphabetic() {
                freq[(c.to_ascii_lowercase() as u8 - b'a') as usize] += 1;
                n += 1;
            }
        }

        if n <= 1 {
            return 0.0;
        }

        let sum: u64 = freq.iter().map(|&f| f * f.saturating_sub(1)).sum();
        sum as f64 / (n * (n - 1)) as f64
    }

    /// Calculate chi-squared against reference frequencies
    fn chi_squared(&self, observed: &HashMap<char, f64>, expected: &[f64; 26]) -> f64 {
        let mut chi = 0.0;

        for i in 0..26 {
            let c = (b'a' + i as u8) as char;
            let obs = observed.get(&c).copied().unwrap_or(0.0);
            let exp = expected[i];

            if exp > 0.0 {
                chi += (obs - exp).powi(2) / exp;
            }
        }

        chi
    }

    /// Analyze bigram frequencies
    fn analyze_bigrams(&self, text: &str) -> Vec<(String, f64)> {
        let mut bigrams: HashMap<String, f64> = HashMap::new();
        let mut total = 0.0;

        let chars: Vec<char> = text
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .map(|c| c.to_ascii_lowercase())
            .collect();

        for window in chars.windows(2) {
            let bigram: String = window.iter().collect();
            *bigrams.entry(bigram).or_insert(0.0) += 1.0;
            total += 1.0;
        }

        // Normalize and sort
        let mut result: Vec<(String, f64)> = bigrams
            .into_iter()
            .map(|(k, v)| (k, if total > 0.0 { v / total } else { 0.0 }))
            .collect();

        result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        result.truncate(20);
        result
    }

    /// Detect if text is likely encrypted vs plaintext
    pub fn is_likely_encrypted(&self, text: &str) -> bool {
        let result = self.analyze(text);

        // Random data has IoC around 0.038
        // English text has IoC around 0.067
        // Threshold between them
        result.ioc < 0.05
    }

    /// Detect probable cipher type based on analysis
    pub fn detect_cipher_type(&self, text: &str) -> String {
        let ioc = self.calculate_ioc(text);

        if ioc > 0.06 {
            // Near-English IoC suggests monoalphabetic substitution
            "Monoalphabetic substitution (Caesar, Atbash, simple substitution)".to_string()
        } else if ioc > 0.04 {
            // Lower IoC suggests polyalphabetic substitution
            "Polyalphabetic substitution (Vigenère, Beaufort)".to_string()
        } else {
            // Very low IoC suggests transposition or modern cipher
            "Transposition cipher or modern encryption".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioc_english() {
        let analyzer = FrequencyAnalyzer::new();
        // Use a realistic text sample with repeated letters
        let text = "It is a truth universally acknowledged that a single man \
                    in possession of a good fortune must be in want of a wife. \
                    However little known the feelings or views of such a man \
                    may be on his first entering a neighbourhood, this truth \
                    is so well fixed in the minds of the surrounding families \
                    that he is considered as the rightful property of some one \
                    or other of their daughters.";
        let ioc = analyzer.calculate_ioc(text);

        // IoC should be positive and non-trivial
        assert!(
            ioc > 0.02,
            "IoC {} should be positive for English text",
            ioc
        );
    }

    #[test]
    fn test_analyze_english() {
        let analyzer = FrequencyAnalyzer::new();
        let text = "The quick brown fox jumps over the lazy dog and the five boxing wizards";
        let result = analyzer.analyze(text);

        // E should be among most frequent
        assert!(result.top_chars.iter().any(|(c, _)| *c == 'e' || *c == 'o'));
        assert_eq!(result.likely_language, "English");
    }

    #[test]
    fn test_detect_cipher() {
        let analyzer = FrequencyAnalyzer::new();

        // Verify the function returns a non-empty string for any input
        let plain = "The quick brown fox jumps over the lazy dog repeatedly";
        let cipher_type = analyzer.detect_cipher_type(plain);
        assert!(!cipher_type.is_empty());

        // Random-ish input should also produce a result
        let encrypted = "xkcd qrst uvwx yzab cdef ghij klmn opqr";
        let cipher_type = analyzer.detect_cipher_type(encrypted);
        assert!(!cipher_type.is_empty());
    }
}
