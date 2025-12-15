pub struct Mutator;

impl Mutator {
    pub fn capitalize(word: &str) -> String {
        let mut chars = word.chars();
        match chars.next() {
            None => String::new(),
            Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
        }
    }

    pub fn l33t(word: &str) -> String {
        // Simple 1337 conversion
        word.replace('a', "4")
            .replace('e', "3")
            .replace('i', "1")
            .replace('o', "0")
            .replace('s', "5")
            .replace('t', "7")
    }

    // Returns a list of mutated variants
    pub fn common_mutations(word: &str) -> Vec<String> {
        let mut variants = Vec::new();
        variants.push(word.to_string());

        let cap = Mutator::capitalize(word);
        if cap != word {
            variants.push(cap);
        }

        let upper = word.to_uppercase();
        if upper != word {
            variants.push(upper);
        }

        let leet = Mutator::l33t(word);
        if leet != word {
            variants.push(leet);
        }

        variants
    }

    pub fn append_numbers(word: &str, count: usize) -> Vec<String> {
        let mut variants = Vec::new();
        for i in 0..=count {
            variants.push(format!("{}{}", word, i));
        }
        variants
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutations() {
        assert_eq!(Mutator::capitalize("test"), "Test");
        assert_eq!(Mutator::l33t("password"), "p455w0rd");

        let common = Mutator::common_mutations("test");
        assert!(common.contains(&"Test".to_string()));
        assert!(common.contains(&"TEST".to_string()));
        assert!(common.contains(&"7357".to_string())); // t3st -> 7357? No, wait.
                                                       // t -> t, e -> 3, s -> 5, t -> 7.
                                                       // test -> 7357.
                                                       // My l33t implementation:
                                                       // t -> 7? yes.
                                                       // e -> 3? yes.
                                                       // s -> 5? yes.
        assert!(common.contains(&"7357".to_string()));
    }
}
