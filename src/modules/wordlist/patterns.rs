pub struct PatternGenerator {
    pattern: String,
    charsets: Vec<Vec<char>>,
    indices: Vec<usize>,
    done: bool,
}

impl PatternGenerator {
    pub fn new(pattern: &str) -> Self {
        let mut charsets = Vec::new();
        let mut chars = pattern.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '?' {
                if let Some(&modifier) = chars.peek() {
                    match modifier {
                        'l' => {
                            charsets.push(('a'..='z').collect());
                            chars.next();
                        }
                        'u' => {
                            charsets.push(('A'..='Z').collect());
                            chars.next();
                        }
                        'd' => {
                            charsets.push(('0'..='9').collect());
                            chars.next();
                        }
                        's' => {
                            // Special characters
                            let symbols = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
                            charsets.push(symbols.chars().collect());
                            chars.next();
                        }
                        'a' => {
                            // ?l?u?d?s
                            let mut all: Vec<char> = ('a'..='z').collect();
                            all.extend('A'..='Z');
                            all.extend('0'..='9');
                            let symbols = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
                            all.extend(symbols.chars());
                            charsets.push(all);
                            chars.next();
                        }
                        _ => {
                            // Unknown modifier, treat '?' as literal?
                            // Or treat '?' and modifier as literals?
                            // Hashcat treats ? without valid modifier as literal ? if strictly interpreted,
                            // but usually it expects escaping.
                            // Let's treat it as literal '?' for now if modifier is invalid?
                            // No, let's treat it as just the literal char.
                            charsets.push(vec![c]);
                            // Don't consume the next char if it wasn't a modifier?
                            // Actually, let's assume valid masks for now.
                        }
                    }
                } else {
                    // Trailing '?'
                    charsets.push(vec!['?']);
                }
            } else {
                charsets.push(vec![c]);
            }
        }

        let len = charsets.len();
        PatternGenerator {
            pattern: pattern.to_string(),
            charsets,
            indices: vec![0; len],
            done: len == 0,
        }
    }
}

impl Iterator for PatternGenerator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if self.charsets.is_empty() {
            self.done = true;
            return Some(String::new());
        }

        let mut result = String::with_capacity(self.charsets.len());
        for (i, charset) in self.charsets.iter().enumerate() {
            result.push(charset[self.indices[i]]);
        }

        // Increment indices
        let mut i = self.charsets.len();
        while i > 0 {
            i -= 1;
            self.indices[i] += 1;
            if self.indices[i] < self.charsets[i].len() {
                // No carry, we are done incrementing
                return Some(result);
            } else {
                // Carry
                self.indices[i] = 0;
            }
        }

        // If we wrapped around the first charset, we are done
        self.done = true;
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digits() {
        let gen = PatternGenerator::new("?d?d"); // 00 to 99
        assert_eq!(gen.count(), 100);
    }

    #[test]
    fn test_literal_mixed() {
        let mut gen = PatternGenerator::new("a?d");
        assert_eq!(gen.next().unwrap(), "a0");
        assert_eq!(gen.last().unwrap(), "a9");
    }

    #[test]
    fn test_all_mask() {
        // Just verify it compiles and runs for a small subset
        let mut gen = PatternGenerator::new("?l");
        assert_eq!(gen.count(), 26);
    }
}
