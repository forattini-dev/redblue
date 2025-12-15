pub struct RuleEngine;

impl RuleEngine {
    pub fn apply(word: &str, rule: &str) -> String {
        let mut result = word.to_string();
        let mut chars = rule.chars().peekable();

        while let Some(cmd) = chars.next() {
            match cmd {
                ':' => { /* No-op */ }
                'l' => {
                    result = result.to_lowercase();
                }
                'u' => {
                    result = result.to_uppercase();
                }
                'c' => {
                    // Capitalize (first char upper, rest lower? or just first char upper?)
                    // Hashcat 'c' is "Capitalize": lowercase all, then uppercase first.
                    // Wait, hashcat 'c' is "Capitalize". 'C' is "Lowercase first".
                    // Let's implement standard Capitalize: Uppercase first, leave rest?
                    // Or "Titlecase"?
                    // Hashcat: "c" -> Capitalize (First char to upper, rest unmodified? No, usually Title case involves lowercasing the rest).
                    // Hashcat wiki says: "c - Capitalize".
                    // Testing hashcat: 'password' -> 'Password'. 'PASSWORD' -> 'PASSWORD'.
                    // So it just uppercases the first letter.
                    if let Some(first) = result.chars().next() {
                        let mut new_string = String::new();
                        new_string.push(first.to_uppercase().next().unwrap());
                        new_string.push_str(&result[1..]);
                        result = new_string;
                    }
                }
                'r' => {
                    result = result.chars().rev().collect();
                }
                'd' => {
                    result = format!("{}{}", result, result);
                }
                '$' => {
                    if let Some(c) = chars.next() {
                        result.push(c);
                    }
                }
                '^' => {
                    if let Some(c) = chars.next() {
                        result = format!("{}{}", c, result);
                    }
                }
                _ => {
                    // Unknown rule or unsupported
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules() {
        assert_eq!(RuleEngine::apply("password", ":"), "password");
        assert_eq!(RuleEngine::apply("Password", "l"), "password");
        assert_eq!(RuleEngine::apply("password", "u"), "PASSWORD");
        assert_eq!(RuleEngine::apply("password", "c"), "Password");
        assert_eq!(RuleEngine::apply("password", "r"), "drowssap");
        assert_eq!(RuleEngine::apply("abc", "d"), "abcabc");
        assert_eq!(RuleEngine::apply("pass", "$1"), "pass1");
        assert_eq!(RuleEngine::apply("pass", "^!"), "!pass");

        // Chained
        assert_eq!(RuleEngine::apply("pass", "$1^!"), "!pass1");
        assert_eq!(RuleEngine::apply("pass", "r$1"), "ssap1");
    }
}
