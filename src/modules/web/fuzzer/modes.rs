//! Fuzzing Attack Modes
//!
//! Implements various fuzzing strategies:
//! - Sniper: Single payload, one position at a time
//! - Clusterbomb: All combinations of all payloads
//! - Pitchfork: Parallel iteration through payloads
//!
//! Task 2.1.14-2.1.16

/// Position where FUZZ keyword appears
#[derive(Debug, Clone, PartialEq)]
pub enum FuzzPosition {
    /// FUZZ in URL path (e.g., /FUZZ/page)
    UrlPath,
    /// FUZZ in query parameter (e.g., ?id=FUZZ)
    QueryParam,
    /// FUZZ in HTTP header
    Header(String),
    /// FUZZ in request body
    Body,
    /// FUZZ in cookie
    Cookie,
}

impl std::fmt::Display for FuzzPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FuzzPosition::UrlPath => write!(f, "URL-Path"),
            FuzzPosition::QueryParam => write!(f, "Query-Param"),
            FuzzPosition::Header(name) => write!(f, "Header:{}", name),
            FuzzPosition::Body => write!(f, "Body"),
            FuzzPosition::Cookie => write!(f, "Cookie"),
        }
    }
}

/// Attack mode for fuzzing
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttackMode {
    /// Sniper: Single payload position, iterate through wordlist
    /// For URL http://example.com/FUZZ with wordlist [a, b, c]:
    /// - http://example.com/a
    /// - http://example.com/b
    /// - http://example.com/c
    Sniper,

    /// Clusterbomb: All combinations of all payloads at all positions
    /// For URL http://example.com/FUZZ1/FUZZ2 with wordlists [a, b] and [1, 2]:
    /// - http://example.com/a/1
    /// - http://example.com/a/2
    /// - http://example.com/b/1
    /// - http://example.com/b/2
    Clusterbomb,

    /// Pitchfork: Parallel iteration (same index across wordlists)
    /// For URL http://example.com/FUZZ1/FUZZ2 with wordlists [a, b] and [1, 2]:
    /// - http://example.com/a/1
    /// - http://example.com/b/2
    Pitchfork,

    /// Batteringram: Same payload at all FUZZ positions
    /// For URL http://example.com/FUZZ/FUZZ with wordlist [test]:
    /// - http://example.com/test/test
    Batteringram,
}

impl std::str::FromStr for AttackMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sniper" | "s" => Ok(AttackMode::Sniper),
            "clusterbomb" | "cluster" | "c" => Ok(AttackMode::Clusterbomb),
            "pitchfork" | "pitch" | "p" => Ok(AttackMode::Pitchfork),
            "batteringram" | "battering" | "b" => Ok(AttackMode::Batteringram),
            _ => Err(format!("Unknown attack mode: {}", s)),
        }
    }
}

impl std::fmt::Display for AttackMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackMode::Sniper => write!(f, "sniper"),
            AttackMode::Clusterbomb => write!(f, "clusterbomb"),
            AttackMode::Pitchfork => write!(f, "pitchfork"),
            AttackMode::Batteringram => write!(f, "batteringram"),
        }
    }
}

/// Generate payload combinations based on attack mode
pub struct PayloadGenerator {
    mode: AttackMode,
    wordlists: Vec<Vec<String>>,
    positions: Vec<FuzzPosition>,
}

impl PayloadGenerator {
    pub fn new(
        mode: AttackMode,
        wordlists: Vec<Vec<String>>,
        positions: Vec<FuzzPosition>,
    ) -> Self {
        Self {
            mode,
            wordlists,
            positions,
        }
    }

    /// Generate all payload combinations
    pub fn generate(&self) -> Vec<Vec<String>> {
        match self.mode {
            AttackMode::Sniper => self.generate_sniper(),
            AttackMode::Clusterbomb => self.generate_clusterbomb(),
            AttackMode::Pitchfork => self.generate_pitchfork(),
            AttackMode::Batteringram => self.generate_batteringram(),
        }
    }

    /// Sniper: Single wordlist, single position
    fn generate_sniper(&self) -> Vec<Vec<String>> {
        if self.wordlists.is_empty() {
            return Vec::new();
        }

        self.wordlists[0]
            .iter()
            .map(|payload| vec![payload.clone()])
            .collect()
    }

    /// Clusterbomb: Cartesian product of all wordlists
    fn generate_clusterbomb(&self) -> Vec<Vec<String>> {
        if self.wordlists.is_empty() {
            return Vec::new();
        }

        let mut results: Vec<Vec<String>> = vec![vec![]];

        for wordlist in &self.wordlists {
            let mut new_results = Vec::new();

            for existing in &results {
                for word in wordlist {
                    let mut new_combo = existing.clone();
                    new_combo.push(word.clone());
                    new_results.push(new_combo);
                }
            }

            results = new_results;
        }

        results
    }

    /// Pitchfork: Parallel iteration
    fn generate_pitchfork(&self) -> Vec<Vec<String>> {
        if self.wordlists.is_empty() {
            return Vec::new();
        }

        let min_len = self.wordlists.iter().map(|w| w.len()).min().unwrap_or(0);

        (0..min_len)
            .map(|i| {
                self.wordlists
                    .iter()
                    .map(|wordlist| wordlist.get(i).cloned().unwrap_or_default())
                    .collect()
            })
            .collect()
    }

    /// Batteringram: Same payload at all positions
    fn generate_batteringram(&self) -> Vec<Vec<String>> {
        if self.wordlists.is_empty() {
            return Vec::new();
        }

        let num_positions = self.positions.len().max(1);

        self.wordlists[0]
            .iter()
            .map(|payload| vec![payload.clone(); num_positions])
            .collect()
    }

    /// Get total number of requests that will be generated
    pub fn total_requests(&self) -> usize {
        match self.mode {
            AttackMode::Sniper => self.wordlists.first().map(|w| w.len()).unwrap_or(0),
            AttackMode::Clusterbomb => self.wordlists.iter().map(|w| w.len()).product(),
            AttackMode::Pitchfork => self.wordlists.iter().map(|w| w.len()).min().unwrap_or(0),
            AttackMode::Batteringram => self.wordlists.first().map(|w| w.len()).unwrap_or(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sniper_mode() {
        let wordlist = vec!["a".into(), "b".into(), "c".into()];
        let gen = PayloadGenerator::new(
            AttackMode::Sniper,
            vec![wordlist],
            vec![FuzzPosition::UrlPath],
        );

        let results = gen.generate();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], vec!["a"]);
        assert_eq!(results[1], vec!["b"]);
        assert_eq!(results[2], vec!["c"]);
    }

    #[test]
    fn test_clusterbomb_mode() {
        let wordlist1 = vec!["a".into(), "b".into()];
        let wordlist2 = vec!["1".into(), "2".into()];
        let gen = PayloadGenerator::new(
            AttackMode::Clusterbomb,
            vec![wordlist1, wordlist2],
            vec![FuzzPosition::UrlPath, FuzzPosition::QueryParam],
        );

        let results = gen.generate();
        assert_eq!(results.len(), 4); // 2 * 2
        assert!(results.contains(&vec!["a".into(), "1".into()]));
        assert!(results.contains(&vec!["a".into(), "2".into()]));
        assert!(results.contains(&vec!["b".into(), "1".into()]));
        assert!(results.contains(&vec!["b".into(), "2".into()]));
    }

    #[test]
    fn test_pitchfork_mode() {
        let wordlist1 = vec!["a".into(), "b".into(), "c".into()];
        let wordlist2 = vec!["1".into(), "2".into()]; // Shorter
        let gen = PayloadGenerator::new(
            AttackMode::Pitchfork,
            vec![wordlist1, wordlist2],
            vec![FuzzPosition::UrlPath, FuzzPosition::QueryParam],
        );

        let results = gen.generate();
        assert_eq!(results.len(), 2); // Min length
        assert_eq!(results[0], vec!["a", "1"]);
        assert_eq!(results[1], vec!["b", "2"]);
    }

    #[test]
    fn test_batteringram_mode() {
        let wordlist = vec!["test".into(), "admin".into()];
        let gen = PayloadGenerator::new(
            AttackMode::Batteringram,
            vec![wordlist],
            vec![FuzzPosition::UrlPath, FuzzPosition::Cookie],
        );

        let results = gen.generate();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], vec!["test", "test"]);
        assert_eq!(results[1], vec!["admin", "admin"]);
    }
}
