use std::collections::HashSet;

pub struct EmailPermutator;

impl EmailPermutator {
    /// Generates common email address permutations for a given first name, last name, and domain.
    pub fn generate_permutations(first_name: &str, last_name: &str, domain: &str) -> Vec<String> {
        let mut permutations = HashSet::new();

        let f = first_name.to_lowercase();
        let l = last_name.to_lowercase();
        let d = domain.to_lowercase();

        // Common patterns
        permutations.insert(format!("{}.{}@{}", f, l, d));
        permutations.insert(format!("{}{}@{}", f, l, d));
        permutations.insert(format!("{}_{}@{}", f, l, d));
        permutations.insert(format!("{}@{}", f, d));
        permutations.insert(format!("{}@{}", l, d));

        // Initials
        if let Some(f_char) = f.chars().next() {
            permutations.insert(format!("{}{}@{}", f_char, l, d));
            if let Some(l_char) = l.chars().next() {
                permutations.insert(format!("{}.{}@{}", f_char, l_char, d));
                permutations.insert(format!("{}{}@{}", f_char, l_char, d));
            }
        }

        // More complex (less common, but still used)
        permutations.insert(format!("{}-{}@{}", f, l, d));
        permutations.insert(format!(
            "{}.{}.{}@{}",
            f.chars().next().unwrap_or(' '),
            l.chars().next().unwrap_or(' '),
            l,
            d
        )); // f.l.last@domain

        permutations.into_iter().collect()
    }

    /// Generates permutations given a full name (e.g., "John Doe") and a domain.
    pub fn generate_from_full_name(full_name: &str, domain: &str) -> Vec<String> {
        let parts: Vec<&str> = full_name.split_whitespace().collect();
        if parts.len() == 2 {
            Self::generate_permutations(parts[0], parts[1], domain)
        } else if parts.len() == 1 {
            // Assume single name can be first or last
            let mut permutations = HashSet::new();
            let name = parts[0].to_lowercase();
            let d = domain.to_lowercase();

            permutations.insert(format!("{}@{}", name, d));
            permutations.insert(format!("{}1@{}", name, d)); // name1@domain

            permutations.into_iter().collect()
        } else {
            Vec::new() // Cannot parse complex names
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_permutations() {
        let perms = EmailPermutator::generate_permutations("John", "Doe", "example.com");
        assert!(perms.contains(&"john.doe@example.com".to_string()));
        assert!(perms.contains(&"johndoe@example.com".to_string()));
        assert!(perms.contains(&"john@example.com".to_string()));
        assert!(perms.contains(&"jdoe@example.com".to_string()));
        assert!(perms.contains(&"j.d@example.com".to_string()));
    }

    #[test]
    fn test_generate_from_full_name() {
        let perms = EmailPermutator::generate_from_full_name("Mary Smith", "test.org");
        assert!(perms.contains(&"mary.smith@test.org".to_string()));
        assert!(perms.contains(&"msmith@test.org".to_string()));
    }
}
