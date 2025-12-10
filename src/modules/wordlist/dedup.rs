use std::collections::HashSet;

pub struct Deduplicator;

impl Deduplicator {
    /// Deduplicates a vector of strings while preserving order of first occurrence.
    pub fn deduplicate(words: Vec<String>) -> Vec<String> {
        let mut seen = HashSet::new();
        words.into_iter().filter(|w| seen.insert(w.clone())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup() {
        let words = vec!["a".to_string(), "b".to_string(), "a".to_string(), "c".to_string()];
        let deduped = Deduplicator::deduplicate(words);
        assert_eq!(deduped, vec!["a", "b", "c"]);
    }
}
