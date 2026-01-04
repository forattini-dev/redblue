/// Password Mutation Rule Engine
///
/// Implements 30+ mutation operations compatible with hashcat/john rule syntax.
/// Rules are applied to wordlist candidates to generate password variations.
///
/// Common rules:
/// - l: lowercase all
/// - u: uppercase all
/// - c: capitalize first letter
/// - $X: append character X
/// - ^X: prepend character X
/// - d: duplicate word
/// - r: reverse word
/// - sXY: replace X with Y
/// - @X: purge character X
use std::fmt;

/// A single rule command
#[derive(Debug, Clone, PartialEq)]
pub enum Rule {
    // Case operations
    Lowercase,           // l - lowercase all
    Uppercase,           // u - uppercase all
    Capitalize,          // c - capitalize first, lowercase rest
    InvertCapitalize,    // C - lowercase first, uppercase rest
    ToggleCase,          // t - toggle case of all
    ToggleCaseAt(usize), // TN - toggle case at position N

    // Character append/prepend
    Append(char),          // $X - append character
    Prepend(char),         // ^X - prepend character
    AppendString(String),  // AX"STR" - append string
    PrependString(String), // insert at 0

    // Delete operations
    DeleteFirst,               // [ - delete first character
    DeleteLast,                // ] - delete last character
    DeleteAt(usize),           // DN - delete character at position N
    DeleteRange(usize, usize), // xNM extract (can be used for delete)

    // Duplicate operations
    Duplicate,             // d - duplicate entire word
    DuplicateN(usize),     // pN - duplicate word N times
    DuplicateFirst(usize), // zN - duplicate first char N times
    DuplicateLast(usize),  // ZN - duplicate last char N times
    DuplicateAll,          // q - duplicate every character
    Reflect,               // f - append reversed string

    // Rotation
    RotateLeft,  // { - rotate left (move first to end)
    RotateRight, // } - rotate right (move last to start)

    // Reverse
    Reverse, // r - reverse entire string

    // Replace/Substitute
    Replace(char, char), // sXY - replace all X with Y
    Purge(char),         // @X - remove all occurrences of X

    // Insert
    InsertAt(usize, char),  // iNX - insert char X at position N
    Overwrite(usize, char), // oNX - overwrite char at N with X

    // Swap
    SwapFirst,            // k - swap first two characters
    SwapLast,             // K - swap last two characters
    SwapAt(usize, usize), // *NM - swap chars at positions N and M

    // Extract
    Extract(usize, usize), // xNM - extract substring from N, length M
    Omit(usize, usize),    // ONM - omit M chars starting at N

    // Truncate
    TruncateAt(usize), // 'N - truncate at position N

    // Memory operations (for chained rules)
    Memorize,      // M - memorize current state
    AppendMemory,  // 4 - append memorized
    PrependMemory, // 6 - prepend memorized

    // Rejection filters (return None if condition not met)
    RejectLessThan(usize),    // <N - reject if length < N
    RejectGreaterThan(usize), // >N - reject if length > N
    RejectContains(char),     // !X - reject if contains X
    RejectNotContains(char),  // /X - reject if doesn't contain X
    RejectEquals(String),     // (STR - reject if equals STR

    // No-op
    Noop, // : - do nothing (used for testing)
}

impl Rule {
    /// Parse a rule from hashcat/john syntax
    pub fn parse(input: &str) -> Option<Self> {
        let mut chars = input.chars();
        let cmd = chars.next()?;

        match cmd {
            // Case operations
            'l' => Some(Rule::Lowercase),
            'u' => Some(Rule::Uppercase),
            'c' => Some(Rule::Capitalize),
            'C' => Some(Rule::InvertCapitalize),
            't' => Some(Rule::ToggleCase),
            'T' => {
                let n = parse_position(&mut chars)?;
                Some(Rule::ToggleCaseAt(n))
            }

            // Append/Prepend
            '$' => {
                let c = chars.next()?;
                Some(Rule::Append(c))
            }
            '^' => {
                let c = chars.next()?;
                Some(Rule::Prepend(c))
            }

            // Delete
            '[' => Some(Rule::DeleteFirst),
            ']' => Some(Rule::DeleteLast),
            'D' => {
                let n = parse_position(&mut chars)?;
                Some(Rule::DeleteAt(n))
            }

            // Duplicate
            'd' => Some(Rule::Duplicate),
            'p' => {
                let n = parse_position(&mut chars)?;
                Some(Rule::DuplicateN(n))
            }
            'z' => {
                let n = parse_position(&mut chars)?;
                Some(Rule::DuplicateFirst(n))
            }
            'Z' => {
                let n = parse_position(&mut chars)?;
                Some(Rule::DuplicateLast(n))
            }
            'q' => Some(Rule::DuplicateAll),
            'f' => Some(Rule::Reflect),

            // Rotation
            '{' => Some(Rule::RotateLeft),
            '}' => Some(Rule::RotateRight),

            // Reverse
            'r' => Some(Rule::Reverse),

            // Replace
            's' => {
                let x = chars.next()?;
                let y = chars.next()?;
                Some(Rule::Replace(x, y))
            }
            '@' => {
                let x = chars.next()?;
                Some(Rule::Purge(x))
            }

            // Insert/Overwrite
            'i' => {
                let n = parse_position(&mut chars)?;
                let x = chars.next()?;
                Some(Rule::InsertAt(n, x))
            }
            'o' => {
                let n = parse_position(&mut chars)?;
                let x = chars.next()?;
                Some(Rule::Overwrite(n, x))
            }

            // Swap
            'k' => Some(Rule::SwapFirst),
            'K' => Some(Rule::SwapLast),
            '*' => {
                let n = parse_position(&mut chars)?;
                let m = parse_position(&mut chars)?;
                Some(Rule::SwapAt(n, m))
            }

            // Extract/Omit
            'x' => {
                let n = parse_position(&mut chars)?;
                let m = parse_position(&mut chars)?;
                Some(Rule::Extract(n, m))
            }
            'O' => {
                let n = parse_position(&mut chars)?;
                let m = parse_position(&mut chars)?;
                Some(Rule::Omit(n, m))
            }

            // Truncate
            '\'' => {
                let n = parse_position(&mut chars)?;
                Some(Rule::TruncateAt(n))
            }

            // Memory
            'M' => Some(Rule::Memorize),
            '4' => Some(Rule::AppendMemory),
            '6' => Some(Rule::PrependMemory),

            // Rejection
            '<' => {
                let n = parse_position(&mut chars)?;
                Some(Rule::RejectLessThan(n))
            }
            '>' => {
                let n = parse_position(&mut chars)?;
                Some(Rule::RejectGreaterThan(n))
            }
            '!' => {
                let x = chars.next()?;
                Some(Rule::RejectContains(x))
            }
            '/' => {
                let x = chars.next()?;
                Some(Rule::RejectNotContains(x))
            }

            // No-op
            ':' => Some(Rule::Noop),

            _ => None,
        }
    }

    /// Apply rule to a word, returning mutated result or None if rejected
    pub fn apply(&self, word: &str, memory: &mut Option<String>) -> Option<String> {
        match self {
            Rule::Lowercase => Some(word.to_lowercase()),
            Rule::Uppercase => Some(word.to_uppercase()),
            Rule::Capitalize => {
                let mut result = word.to_lowercase();
                if let Some(c) = result.get_mut(0..1) {
                    c.make_ascii_uppercase();
                }
                Some(result)
            }
            Rule::InvertCapitalize => {
                let mut result = word.to_uppercase();
                if let Some(c) = result.get_mut(0..1) {
                    c.make_ascii_lowercase();
                }
                Some(result)
            }
            Rule::ToggleCase => Some(
                word.chars()
                    .map(|c| {
                        if c.is_lowercase() {
                            c.to_uppercase().next().unwrap_or(c)
                        } else {
                            c.to_lowercase().next().unwrap_or(c)
                        }
                    })
                    .collect(),
            ),
            Rule::ToggleCaseAt(n) => {
                let mut chars: Vec<char> = word.chars().collect();
                if *n < chars.len() {
                    chars[*n] = if chars[*n].is_lowercase() {
                        chars[*n].to_uppercase().next().unwrap_or(chars[*n])
                    } else {
                        chars[*n].to_lowercase().next().unwrap_or(chars[*n])
                    };
                }
                Some(chars.into_iter().collect())
            }

            Rule::Append(c) => Some(format!("{}{}", word, c)),
            Rule::Prepend(c) => Some(format!("{}{}", c, word)),
            Rule::AppendString(s) => Some(format!("{}{}", word, s)),
            Rule::PrependString(s) => Some(format!("{}{}", s, word)),

            Rule::DeleteFirst => {
                if word.is_empty() {
                    Some(String::new())
                } else {
                    Some(word[1..].to_string())
                }
            }
            Rule::DeleteLast => {
                if word.is_empty() {
                    Some(String::new())
                } else {
                    Some(word[..word.len() - 1].to_string())
                }
            }
            Rule::DeleteAt(n) => {
                let chars: Vec<char> = word.chars().collect();
                if *n < chars.len() {
                    let mut result: Vec<char> = chars.clone();
                    result.remove(*n);
                    Some(result.into_iter().collect())
                } else {
                    Some(word.to_string())
                }
            }
            Rule::DeleteRange(start, len) => {
                let chars: Vec<char> = word.chars().collect();
                if *start < chars.len() {
                    let end = (*start + *len).min(chars.len());
                    let result: String = chars[..(*start)]
                        .iter()
                        .chain(chars[end..].iter())
                        .collect();
                    Some(result)
                } else {
                    Some(word.to_string())
                }
            }

            Rule::Duplicate => Some(format!("{}{}", word, word)),
            Rule::DuplicateN(n) => Some(word.repeat(*n)),
            Rule::DuplicateFirst(n) => {
                if let Some(c) = word.chars().next() {
                    let prefix: String = std::iter::repeat(c).take(*n).collect();
                    Some(format!("{}{}", prefix, word))
                } else {
                    Some(word.to_string())
                }
            }
            Rule::DuplicateLast(n) => {
                if let Some(c) = word.chars().last() {
                    let suffix: String = std::iter::repeat(c).take(*n).collect();
                    Some(format!("{}{}", word, suffix))
                } else {
                    Some(word.to_string())
                }
            }
            Rule::DuplicateAll => Some(word.chars().flat_map(|c| [c, c]).collect()),
            Rule::Reflect => {
                let reversed: String = word.chars().rev().collect();
                Some(format!("{}{}", word, reversed))
            }

            Rule::RotateLeft => {
                if word.is_empty() {
                    Some(String::new())
                } else {
                    let first = word.chars().next().unwrap();
                    Some(format!("{}{}", &word[first.len_utf8()..], first))
                }
            }
            Rule::RotateRight => {
                if word.is_empty() {
                    Some(String::new())
                } else {
                    let last = word.chars().last().unwrap();
                    let end_pos = word.len() - last.len_utf8();
                    Some(format!("{}{}", last, &word[..end_pos]))
                }
            }

            Rule::Reverse => Some(word.chars().rev().collect()),

            Rule::Replace(x, y) => Some(word.replace(*x, &y.to_string())),
            Rule::Purge(x) => Some(word.replace(*x, "")),

            Rule::InsertAt(n, x) => {
                let chars: Vec<char> = word.chars().collect();
                if *n <= chars.len() {
                    let mut result: Vec<char> = chars;
                    result.insert(*n, *x);
                    Some(result.into_iter().collect())
                } else {
                    Some(format!("{}{}", word, x))
                }
            }
            Rule::Overwrite(n, x) => {
                let mut chars: Vec<char> = word.chars().collect();
                if *n < chars.len() {
                    chars[*n] = *x;
                }
                Some(chars.into_iter().collect())
            }

            Rule::SwapFirst => {
                let mut chars: Vec<char> = word.chars().collect();
                if chars.len() >= 2 {
                    chars.swap(0, 1);
                }
                Some(chars.into_iter().collect())
            }
            Rule::SwapLast => {
                let mut chars: Vec<char> = word.chars().collect();
                let len = chars.len();
                if len >= 2 {
                    chars.swap(len - 2, len - 1);
                }
                Some(chars.into_iter().collect())
            }
            Rule::SwapAt(n, m) => {
                let mut chars: Vec<char> = word.chars().collect();
                if *n < chars.len() && *m < chars.len() {
                    chars.swap(*n, *m);
                }
                Some(chars.into_iter().collect())
            }

            Rule::Extract(n, m) => {
                let chars: Vec<char> = word.chars().collect();
                if *n < chars.len() {
                    let end = (*n + *m).min(chars.len());
                    Some(chars[*n..end].iter().collect())
                } else {
                    Some(String::new())
                }
            }
            Rule::Omit(n, m) => {
                let chars: Vec<char> = word.chars().collect();
                if *n < chars.len() {
                    let end = (*n + *m).min(chars.len());
                    let result: String = chars[..(*n)].iter().chain(chars[end..].iter()).collect();
                    Some(result)
                } else {
                    Some(word.to_string())
                }
            }

            Rule::TruncateAt(n) => {
                let chars: Vec<char> = word.chars().collect();
                let end = (*n).min(chars.len());
                Some(chars[..end].iter().collect())
            }

            Rule::Memorize => {
                *memory = Some(word.to_string());
                Some(word.to_string())
            }
            Rule::AppendMemory => {
                if let Some(mem) = memory {
                    Some(format!("{}{}", word, mem))
                } else {
                    Some(word.to_string())
                }
            }
            Rule::PrependMemory => {
                if let Some(mem) = memory {
                    Some(format!("{}{}", mem, word))
                } else {
                    Some(word.to_string())
                }
            }

            Rule::RejectLessThan(n) => {
                if word.len() < *n {
                    None
                } else {
                    Some(word.to_string())
                }
            }
            Rule::RejectGreaterThan(n) => {
                if word.len() > *n {
                    None
                } else {
                    Some(word.to_string())
                }
            }
            Rule::RejectContains(x) => {
                if word.contains(*x) {
                    None
                } else {
                    Some(word.to_string())
                }
            }
            Rule::RejectNotContains(x) => {
                if !word.contains(*x) {
                    None
                } else {
                    Some(word.to_string())
                }
            }
            Rule::RejectEquals(s) => {
                if word == s {
                    None
                } else {
                    Some(word.to_string())
                }
            }

            Rule::Noop => Some(word.to_string()),
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rule::Lowercase => write!(f, "l"),
            Rule::Uppercase => write!(f, "u"),
            Rule::Capitalize => write!(f, "c"),
            Rule::InvertCapitalize => write!(f, "C"),
            Rule::ToggleCase => write!(f, "t"),
            Rule::ToggleCaseAt(n) => write!(f, "T{}", encode_position(*n)),
            Rule::Append(c) => write!(f, "${}", c),
            Rule::Prepend(c) => write!(f, "^{}", c),
            Rule::AppendString(s) => write!(f, "A\"{}\"", s),
            Rule::PrependString(s) => write!(f, "0\"{}\"", s),
            Rule::DeleteFirst => write!(f, "["),
            Rule::DeleteLast => write!(f, "]"),
            Rule::DeleteAt(n) => write!(f, "D{}", encode_position(*n)),
            Rule::DeleteRange(s, l) => write!(f, "x{}{}", encode_position(*s), encode_position(*l)),
            Rule::Duplicate => write!(f, "d"),
            Rule::DuplicateN(n) => write!(f, "p{}", encode_position(*n)),
            Rule::DuplicateFirst(n) => write!(f, "z{}", encode_position(*n)),
            Rule::DuplicateLast(n) => write!(f, "Z{}", encode_position(*n)),
            Rule::DuplicateAll => write!(f, "q"),
            Rule::Reflect => write!(f, "f"),
            Rule::RotateLeft => write!(f, "{{"),
            Rule::RotateRight => write!(f, "}}"),
            Rule::Reverse => write!(f, "r"),
            Rule::Replace(x, y) => write!(f, "s{}{}", x, y),
            Rule::Purge(x) => write!(f, "@{}", x),
            Rule::InsertAt(n, x) => write!(f, "i{}{}", encode_position(*n), x),
            Rule::Overwrite(n, x) => write!(f, "o{}{}", encode_position(*n), x),
            Rule::SwapFirst => write!(f, "k"),
            Rule::SwapLast => write!(f, "K"),
            Rule::SwapAt(n, m) => write!(f, "*{}{}", encode_position(*n), encode_position(*m)),
            Rule::Extract(n, m) => write!(f, "x{}{}", encode_position(*n), encode_position(*m)),
            Rule::Omit(n, m) => write!(f, "O{}{}", encode_position(*n), encode_position(*m)),
            Rule::TruncateAt(n) => write!(f, "'{}", encode_position(*n)),
            Rule::Memorize => write!(f, "M"),
            Rule::AppendMemory => write!(f, "4"),
            Rule::PrependMemory => write!(f, "6"),
            Rule::RejectLessThan(n) => write!(f, "<{}", encode_position(*n)),
            Rule::RejectGreaterThan(n) => write!(f, ">{}", encode_position(*n)),
            Rule::RejectContains(x) => write!(f, "!{}", x),
            Rule::RejectNotContains(x) => write!(f, "/{}", x),
            Rule::RejectEquals(s) => write!(f, "({})", s),
            Rule::Noop => write!(f, ":"),
        }
    }
}

/// Parse position value (0-9, A-Z for 10-35)
fn parse_position(chars: &mut std::str::Chars) -> Option<usize> {
    let c = chars.next()?;
    if c.is_ascii_digit() {
        Some((c as usize) - ('0' as usize))
    } else if c.is_ascii_uppercase() {
        Some((c as usize) - ('A' as usize) + 10)
    } else {
        None
    }
}

/// Encode position value to single char
fn encode_position(n: usize) -> char {
    if n < 10 {
        (b'0' + n as u8) as char
    } else if n < 36 {
        (b'A' + (n - 10) as u8) as char
    } else {
        'Z'
    }
}

/// Rule engine for chained rule application
pub struct RuleEngine {
    rules: Vec<Vec<Rule>>, // Each inner vec is a rule chain
}

impl RuleEngine {
    /// Create new rule engine
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule chain from string (space-separated commands)
    pub fn add_chain(&mut self, rule_string: &str) {
        let mut chain = Vec::new();
        let mut current = String::new();

        for c in rule_string.chars() {
            if c.is_whitespace() && !current.is_empty() {
                if let Some(rule) = Rule::parse(&current) {
                    chain.push(rule);
                }
                current.clear();
            } else if !c.is_whitespace() {
                current.push(c);
            }
        }

        // Handle last rule
        if !current.is_empty() {
            if let Some(rule) = Rule::parse(&current) {
                chain.push(rule);
            }
        }

        if !chain.is_empty() {
            self.rules.push(chain);
        }
    }

    /// Add a single rule
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(vec![rule]);
    }

    /// Add common rule presets
    pub fn add_preset(&mut self, preset: &str) {
        match preset {
            "best64" => {
                // Common password mutations
                self.add_chain(":"); // noop
                self.add_chain("l"); // lowercase
                self.add_chain("u"); // uppercase
                self.add_chain("c"); // capitalize
                self.add_chain("$1"); // append 1
                self.add_chain("$!"); // append !
                self.add_chain("$@"); // append @
                self.add_chain("^1"); // prepend 1
                self.add_chain("d"); // duplicate
                self.add_chain("r"); // reverse
                self.add_chain("$1 $2 $3"); // append 123
                self.add_chain("c $1"); // capitalize + 1
                self.add_chain("c $!"); // capitalize + !
                self.add_chain("c $1 $2 $3"); // capitalize + 123
                self.add_chain("$2 $0 $2 $0"); // append 2020
                self.add_chain("$2 $0 $2 $1"); // append 2021
                self.add_chain("$2 $0 $2 $2"); // append 2022
                self.add_chain("$2 $0 $2 $3"); // append 2023
                self.add_chain("$2 $0 $2 $4"); // append 2024
                self.add_chain("se3 ss$ sa@"); // leetspeak
            }
            "toggles" => {
                for i in 0..8 {
                    self.rules.push(vec![Rule::ToggleCaseAt(i)]);
                }
            }
            "append_numbers" => {
                for i in 0..=9 {
                    self.rules
                        .push(vec![Rule::Append(char::from_digit(i, 10).unwrap())]);
                }
                for year in 2015..=2025 {
                    let y = year.to_string();
                    let rules: Vec<Rule> = y.chars().map(|c| Rule::Append(c)).collect();
                    self.rules.push(rules);
                }
            }
            "append_symbols" => {
                for c in "!@#$%^&*()_+-=[]{}|;':\",./<>?".chars() {
                    self.rules.push(vec![Rule::Append(c)]);
                }
            }
            _ => {}
        }
    }

    /// Generate all mutations for a word
    pub fn generate(&self, word: &str) -> Vec<String> {
        let mut results = Vec::new();

        for chain in &self.rules {
            let mut memory: Option<String> = None;
            let mut current = word.to_string();
            let mut valid = true;

            for rule in chain {
                match rule.apply(&current, &mut memory) {
                    Some(result) => current = result,
                    None => {
                        valid = false;
                        break;
                    }
                }
            }

            if valid {
                results.push(current);
            }
        }

        results
    }

    /// Get number of rule chains
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Apply rules to a word (convenience function)
pub fn apply_rules(word: &str, rule_strings: &[&str]) -> Vec<String> {
    let mut engine = RuleEngine::new();
    for rule_str in rule_strings {
        engine.add_chain(rule_str);
    }
    engine.generate(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lowercase() {
        let mut mem = None;
        assert_eq!(
            Rule::Lowercase.apply("HELLO", &mut mem),
            Some("hello".to_string())
        );
    }

    #[test]
    fn test_uppercase() {
        let mut mem = None;
        assert_eq!(
            Rule::Uppercase.apply("hello", &mut mem),
            Some("HELLO".to_string())
        );
    }

    #[test]
    fn test_capitalize() {
        let mut mem = None;
        assert_eq!(
            Rule::Capitalize.apply("hELLO", &mut mem),
            Some("Hello".to_string())
        );
    }

    #[test]
    fn test_append() {
        let mut mem = None;
        assert_eq!(
            Rule::Append('1').apply("pass", &mut mem),
            Some("pass1".to_string())
        );
    }

    #[test]
    fn test_prepend() {
        let mut mem = None;
        assert_eq!(
            Rule::Prepend('!').apply("pass", &mut mem),
            Some("!pass".to_string())
        );
    }

    #[test]
    fn test_duplicate() {
        let mut mem = None;
        assert_eq!(
            Rule::Duplicate.apply("ab", &mut mem),
            Some("abab".to_string())
        );
    }

    #[test]
    fn test_reverse() {
        let mut mem = None;
        assert_eq!(
            Rule::Reverse.apply("hello", &mut mem),
            Some("olleh".to_string())
        );
    }

    #[test]
    fn test_replace() {
        let mut mem = None;
        assert_eq!(
            Rule::Replace('e', '3').apply("hello", &mut mem),
            Some("h3llo".to_string())
        );
    }

    #[test]
    fn test_parse_rules() {
        assert_eq!(Rule::parse("l"), Some(Rule::Lowercase));
        assert_eq!(Rule::parse("$1"), Some(Rule::Append('1')));
        assert_eq!(Rule::parse("^!"), Some(Rule::Prepend('!')));
        assert_eq!(Rule::parse("sae"), Some(Rule::Replace('a', 'e')));
    }

    #[test]
    fn test_rule_chain() {
        let results = apply_rules("password", &["l", "c $1", "u $!"]);
        assert!(results.contains(&"password".to_string()));
        assert!(results.contains(&"Password1".to_string()));
        assert!(results.contains(&"PASSWORD!".to_string()));
    }

    #[test]
    fn test_rejection() {
        let mut mem = None;
        assert_eq!(Rule::RejectLessThan(5).apply("hi", &mut mem), None);
        assert_eq!(
            Rule::RejectLessThan(5).apply("hello", &mut mem),
            Some("hello".to_string())
        );
    }

    #[test]
    fn test_memory() {
        let mut mem = None;
        let word = "test";
        Rule::Memorize.apply(word, &mut mem);
        assert_eq!(mem, Some("test".to_string()));
        assert_eq!(
            Rule::AppendMemory.apply("new", &mut mem),
            Some("newtest".to_string())
        );
    }
}
