use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct WordlistStats {
    pub line_count: usize,
    pub unique_count: usize,
    pub avg_length: f64,
    pub min_length: usize,
    pub max_length: usize,
    pub charset: String,
}

pub struct Analyzer;

impl Analyzer {
    pub fn analyze(words: &[String]) -> WordlistStats {
        let line_count = words.len();
        if line_count == 0 {
            return WordlistStats::default();
        }

        let mut total_len = 0;
        let mut min_len = usize::MAX;
        let mut max_len = 0;
        let mut unique = HashSet::new();
        
        // Charset detection
        let mut has_lower = false;
        let mut has_upper = false;
        let mut has_digit = false;
        let mut has_symbol = false;

        for w in words {
            let len = w.len();
            total_len += len;
            if len < min_len { min_len = len; }
            if len > max_len { max_len = len; }
            unique.insert(w);
            
            for c in w.chars() {
                if c.is_ascii_lowercase() { has_lower = true; }
                else if c.is_ascii_uppercase() { has_upper = true; }
                else if c.is_ascii_digit() { has_digit = true; }
                else { has_symbol = true; }
            }
        }

        let mut charset = Vec::new();
        if has_lower { charset.push("lower"); }
        if has_upper { charset.push("upper"); }
        if has_digit { charset.push("digit"); }
        if has_symbol { charset.push("symbol"); }

        WordlistStats {
            line_count,
            unique_count: unique.len(),
            avg_length: total_len as f64 / line_count as f64,
            min_length: if min_len == usize::MAX { 0 } else { min_len },
            max_length: max_len,
            charset: charset.join(","),
        }
    }
}
