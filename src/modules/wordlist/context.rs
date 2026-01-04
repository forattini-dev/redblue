//! Context Resolution - Automatic wordlist context detection.
//!
//! Analyzes URLs, targets, and scan types to determine appropriate wordlist context.

use super::manager::{WordlistContext, WordlistSize};

/// Context resolver for automatic wordlist selection
pub struct ContextResolver;

impl ContextResolver {
    /// Detect wordlist context from URL or target string
    pub fn detect_from_target(target: &str) -> WordlistContext {
        let lower = target.to_lowercase();

        // Check for URL patterns
        if lower.starts_with("http://") || lower.starts_with("https://") {
            return Self::detect_from_url(&lower);
        }

        // Check for domain patterns (subdomain enumeration)
        if lower.contains('.') && !lower.contains('/') && !lower.contains(':') {
            // Looks like a domain
            return WordlistContext::Subdomains;
        }

        // Check for IP:port patterns (directory fuzzing)
        if lower.contains(':') && lower.chars().filter(|c| *c == ':').count() == 1 {
            return WordlistContext::Directories;
        }

        // Default based on content
        if lower.ends_with('/') || lower.contains("/fuzz") || lower.contains("/FUZZ") {
            return WordlistContext::Directories;
        }

        WordlistContext::Directories
    }

    /// Detect context from URL
    fn detect_from_url(url: &str) -> WordlistContext {
        // Check for parameter fuzzing indicators
        if url.contains("?") || url.contains("FUZZ=") || url.contains("=FUZZ") {
            return WordlistContext::Parameters;
        }

        // Check path for file vs directory indicators
        let path = url
            .split("://")
            .nth(1)
            .unwrap_or("")
            .split('?')
            .next()
            .unwrap_or("");

        if let Some(last_segment) = path.split('/').last() {
            // If last segment has extension, likely file fuzzing
            if last_segment.contains('.') && !last_segment.starts_with('.') {
                return WordlistContext::Files;
            }
            // If last segment is FUZZ, directory fuzzing
            if last_segment == "FUZZ" || last_segment == "fuzz" {
                return WordlistContext::Directories;
            }
        }

        // Check for login/auth endpoints (user/password fuzzing)
        if url.contains("/login")
            || url.contains("/auth")
            || url.contains("/signin")
            || url.contains("/admin")
        {
            // Could be either username or password fuzzing
            // Default to directories for general fuzzing
            return WordlistContext::Directories;
        }

        WordlistContext::Directories
    }

    /// Detect context from scan type string
    pub fn detect_from_scan_type(scan_type: &str) -> WordlistContext {
        match scan_type.to_lowercase().as_str() {
            "dir" | "directory" | "dirbust" | "dirb" => WordlistContext::Directories,
            "file" | "files" | "filefuzz" => WordlistContext::Files,
            "sub" | "subdomain" | "subdomains" | "dns" => WordlistContext::Subdomains,
            "param" | "params" | "parameter" | "parameters" => WordlistContext::Parameters,
            "pass" | "password" | "passwords" | "brute" => WordlistContext::Passwords,
            "user" | "username" | "usernames" | "enum" => WordlistContext::Usernames,
            _ => WordlistContext::Directories,
        }
    }

    /// Suggest optimal wordlist size based on target characteristics
    pub fn suggest_size(target: &str, time_budget_secs: Option<u64>) -> WordlistSize {
        let base_rate = 100; // Assumed requests per second

        if let Some(budget) = time_budget_secs {
            // Calculate max words based on time budget
            let max_words = budget * base_rate;

            return match max_words {
                0..=1_000 => WordlistSize::Small,
                1_001..=50_000 => WordlistSize::Medium,
                50_001..=500_000 => WordlistSize::Large,
                _ => WordlistSize::Huge,
            };
        }

        // Default logic based on target
        let target_lower = target.to_lowercase();

        // Internal/local targets can use larger wordlists
        if target_lower.contains("localhost")
            || target_lower.contains("127.0.0.1")
            || target_lower.starts_with("192.168.")
            || target_lower.starts_with("10.")
        {
            return WordlistSize::Large;
        }

        // External targets default to medium
        WordlistSize::Medium
    }

    /// Get recommended wordlist paths for a context
    pub fn recommended_wordlists(context: &WordlistContext) -> Vec<&'static str> {
        match context {
            WordlistContext::Directories => vec![
                "Discovery/Web-Content/common.txt",
                "Discovery/Web-Content/raft-medium-directories.txt",
                "Discovery/Web-Content/directory-list-2.3-medium.txt",
            ],
            WordlistContext::Files => vec![
                "Discovery/Web-Content/raft-medium-files.txt",
                "Discovery/Web-Content/raft-large-files.txt",
            ],
            WordlistContext::Subdomains => vec![
                "Discovery/DNS/subdomains-top1million-5000.txt",
                "Discovery/DNS/subdomains-top1million-20000.txt",
                "Discovery/DNS/subdomains-top1million-110000.txt",
            ],
            WordlistContext::Parameters => vec![
                "Discovery/Web-Content/burp-parameter-names.txt",
                "Fuzzing/LFI/LFI-Jhaddix.txt",
            ],
            WordlistContext::Passwords => vec![
                "Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
                "Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
                "Passwords/Leaked-Databases/rockyou.txt",
            ],
            WordlistContext::Usernames => vec![
                "Usernames/Names/names.txt",
                "Usernames/top-usernames-shortlist.txt",
            ],
            WordlistContext::VHosts => vec![
                "Discovery/DNS/subdomains-top1million-5000.txt",
                "Discovery/DNS/namelist.txt",
            ],
            WordlistContext::Custom(_) => vec![],
        }
    }

    /// Detect if target looks like it requires auth (for context hints)
    pub fn requires_auth(target: &str) -> bool {
        let lower = target.to_lowercase();
        lower.contains("/admin")
            || lower.contains("/login")
            || lower.contains("/auth")
            || lower.contains("/secure")
            || lower.contains("/protected")
            || lower.contains("/private")
            || lower.contains("/dashboard")
            || lower.contains("/panel")
    }

    /// Get context-specific extensions to try
    pub fn context_extensions(context: &WordlistContext) -> Vec<&'static str> {
        match context {
            WordlistContext::Directories => vec!["", "/"],
            WordlistContext::Files => vec![
                ".php", ".asp", ".aspx", ".jsp", ".html", ".htm", ".js", ".json", ".xml", ".txt",
                ".bak", ".old", ".sql", ".zip", ".tar.gz", ".config", ".env",
            ],
            WordlistContext::Subdomains => vec![],
            WordlistContext::Parameters => vec![],
            WordlistContext::Passwords => vec![],
            WordlistContext::Usernames => vec![],
            WordlistContext::VHosts => vec![],
            WordlistContext::Custom(_) => vec![],
        }
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_from_url_directory() {
        assert!(matches!(
            ContextResolver::detect_from_target("http://example.com/FUZZ"),
            WordlistContext::Directories
        ));
        assert!(matches!(
            ContextResolver::detect_from_target("https://example.com/admin/FUZZ"),
            WordlistContext::Directories
        ));
    }

    #[test]
    fn test_detect_from_url_parameters() {
        assert!(matches!(
            ContextResolver::detect_from_target("http://example.com/search?q=FUZZ"),
            WordlistContext::Parameters
        ));
        assert!(matches!(
            ContextResolver::detect_from_target("http://example.com/api?FUZZ=value"),
            WordlistContext::Parameters
        ));
    }

    #[test]
    fn test_detect_domain_subdomain() {
        assert!(matches!(
            ContextResolver::detect_from_target("example.com"),
            WordlistContext::Subdomains
        ));
        assert!(matches!(
            ContextResolver::detect_from_target("test.example.com"),
            WordlistContext::Subdomains
        ));
    }

    #[test]
    fn test_detect_from_scan_type() {
        assert!(matches!(
            ContextResolver::detect_from_scan_type("dir"),
            WordlistContext::Directories
        ));
        assert!(matches!(
            ContextResolver::detect_from_scan_type("subdomain"),
            WordlistContext::Subdomains
        ));
        assert!(matches!(
            ContextResolver::detect_from_scan_type("brute"),
            WordlistContext::Passwords
        ));
    }

    #[test]
    fn test_suggest_size_by_time() {
        assert_eq!(
            ContextResolver::suggest_size("http://example.com", Some(5)),
            WordlistSize::Small
        );
        assert_eq!(
            ContextResolver::suggest_size("http://example.com", Some(300)),
            WordlistSize::Medium
        );
        assert_eq!(
            ContextResolver::suggest_size("http://example.com", Some(3600)),
            WordlistSize::Large
        );
    }

    #[test]
    fn test_suggest_size_local() {
        assert_eq!(
            ContextResolver::suggest_size("http://localhost/FUZZ", None),
            WordlistSize::Large
        );
        assert_eq!(
            ContextResolver::suggest_size("http://192.168.1.1/FUZZ", None),
            WordlistSize::Large
        );
    }

    #[test]
    fn test_requires_auth() {
        assert!(ContextResolver::requires_auth("http://example.com/admin"));
        assert!(ContextResolver::requires_auth("http://example.com/login"));
        assert!(!ContextResolver::requires_auth("http://example.com/public"));
    }

    #[test]
    fn test_context_extensions() {
        let file_exts = ContextResolver::context_extensions(&WordlistContext::Files);
        assert!(file_exts.contains(&".php"));
        assert!(file_exts.contains(&".bak"));

        let dir_exts = ContextResolver::context_extensions(&WordlistContext::Directories);
        assert!(dir_exts.contains(&"/"));
    }
}
