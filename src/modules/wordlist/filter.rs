pub struct Filter;

impl Filter {
    pub fn by_length(words: Vec<String>, min: Option<usize>, max: Option<usize>) -> Vec<String> {
        words.into_iter().filter(|w| {
            let len = w.len();
            if let Some(min_len) = min {
                if len < min_len { return false; }
            }
            if let Some(max_len) = max {
                if len > max_len { return false; }
            }
            true
        }).collect()
    }
    
    /// Filters words that contain the given pattern.
    /// If `inverse` is true, keeps words that do NOT contain the pattern.
    pub fn by_pattern(words: Vec<String>, pattern: &str, inverse: bool) -> Vec<String> {
        words.into_iter().filter(|w| {
            let contains = w.contains(pattern);
            if inverse {
                !contains
            } else {
                contains
            }
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_len() {
        let words = vec!["a".to_string(), "ab".to_string(), "abc".to_string()];
        let res = Filter::by_length(words.clone(), Some(2), None);
        assert_eq!(res, vec!["ab", "abc"]);
        
        let res = Filter::by_length(words, None, Some(1));
        assert_eq!(res, vec!["a"]);
    }
    
    #[test]
    fn test_filter_pattern() {
        let words = vec!["apple".to_string(), "banana".to_string()];
        let res = Filter::by_pattern(words.clone(), "app", false);
        assert_eq!(res, vec!["apple"]);
        
        let res = Filter::by_pattern(words, "app", true);
        assert_eq!(res, vec!["banana"]);
    }
}
