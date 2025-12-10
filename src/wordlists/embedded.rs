/// Embedded wordlists - compiled into the binary
/// These provide offline functionality and cover common use cases
/// Total size: ~7KB
use std::collections::HashMap;

/// Lazy-loaded embedded wordlists
pub fn get_embedded_wordlists() -> HashMap<&'static str, &'static str> {
    let mut wordlists = HashMap::new();

    // Subdomains (~2KB) - Top 100 most common subdomains
    wordlists.insert(
        "subdomains-top100",
        include_str!("embedded/subdomains-top100.txt"),
    );

    // Directories (~3KB) - Common web directories and paths
    wordlists.insert(
        "directories-common",
        include_str!("embedded/directories-common.txt"),
    );

    // Files (~1KB) - Common web files
    wordlists.insert("files-common", include_str!("embedded/files-common.txt"));

    // Parameters (~1KB) - Common GET/POST parameters
    wordlists.insert(
        "web-parameters",
        include_str!("embedded/web-parameters.txt"),
    );

    wordlists
}

/// Get an embedded wordlist by name
pub fn get_embedded(name: &str) -> Option<Vec<String>> {
    let wordlists = get_embedded_wordlists();

    wordlists.get(name).map(|content| {
        content
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|s| s.trim().to_string())
            .collect()
    })
}

/// List all available embedded wordlists
pub fn list_embedded() -> Vec<(&'static str, usize)> {
    let wordlists = get_embedded_wordlists();

    wordlists
        .iter()
        .map(|(name, content)| {
            let line_count = content
                .lines()
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .count();
            (*name, line_count)
        })
        .collect()
}

/// Check if a wordlist name is embedded
pub fn is_embedded(name: &str) -> bool {
    let wordlists = get_embedded_wordlists();
    wordlists.contains_key(name)
}

/// Get wordlist info (name, line count, size)
pub fn get_info(name: &str) -> Option<(String, usize, usize)> {
    let wordlists = get_embedded_wordlists();

    wordlists.get(name).map(|content| {
        let line_count = content
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .count();
        let size_bytes = content.len();
        (name.to_string(), line_count, size_bytes)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_wordlists_exist() {
        let wordlists = get_embedded_wordlists();
        assert_eq!(wordlists.len(), 4);
        assert!(wordlists.contains_key("subdomains-top100"));
        assert!(wordlists.contains_key("directories-common"));
        assert!(wordlists.contains_key("files-common"));
        assert!(wordlists.contains_key("web-parameters"));
    }

    #[test]
    fn test_get_embedded() {
        let subdomains = get_embedded("subdomains-top100").unwrap();
        assert!(!subdomains.is_empty());
        assert!(subdomains.contains(&"www".to_string()));
        assert!(subdomains.contains(&"api".to_string()));
    }

    #[test]
    fn test_list_embedded() {
        let list = list_embedded();
        assert_eq!(list.len(), 4);

        for (name, count) in list {
            assert!(count > 0, "Wordlist {} should have entries", name);
        }
    }

    #[test]
    fn test_is_embedded() {
        assert!(is_embedded("subdomains-top100"));
        assert!(is_embedded("directories-common"));
        assert!(!is_embedded("non-existent"));
    }
}
