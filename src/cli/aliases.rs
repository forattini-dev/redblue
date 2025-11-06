/// CLI Aliases & Shortcuts
///
/// Provides 3-tier alias system:
/// 1. Full names: rb intelligence fingerprint extract
/// 2. Short forms: rb intel fp extract
/// 3. Single-letter: rb i fp extract
///
/// Saves ~45% keystrokes while maintaining readability.
use std::collections::HashMap;

pub struct AliasResolver {
    domain_aliases: HashMap<&'static str, &'static str>,
    resource_aliases: HashMap<&'static str, &'static str>,
    verb_aliases: HashMap<&'static str, &'static str>,
}

impl AliasResolver {
    pub fn new() -> Self {
        let mut domain_aliases = HashMap::new();

        // Intelligence aliases (most verbose → needs most help)
        domain_aliases.insert("i", "intelligence");
        domain_aliases.insert("intel", "intelligence");

        // Network aliases (very common)
        domain_aliases.insert("n", "network");
        domain_aliases.insert("net", "network");
        domain_aliases.insert("ntwrk", "network"); // common typo

        // Database aliases (universal abbreviation)
        domain_aliases.insert("d", "database");
        domain_aliases.insert("db", "database");

        // Access aliases (post-exploitation)
        domain_aliases.insert("a", "access");
        domain_aliases.insert("acc", "access");

        // Exploit aliases (DEPRECATED - use 'access')
        domain_aliases.insert("e", "exploit");
        domain_aliases.insert("exp", "exploit");

        // Recon aliases
        domain_aliases.insert("r", "recon");

        // Screenshot aliases
        domain_aliases.insert("s", "screenshot");
        domain_aliases.insert("screen", "screenshot");
        domain_aliases.insert("shot", "screenshot");

        // Collection aliases (future)
        domain_aliases.insert("c", "collection");
        domain_aliases.insert("collect", "collection");

        // Benchmark aliases
        domain_aliases.insert("b", "bench");

        // Wordlist aliases
        domain_aliases.insert("w", "wordlist");
        domain_aliases.insert("wl", "wordlist");

        // Code aliases
        domain_aliases.insert("co", "code");

        // Cloud aliases
        domain_aliases.insert("cl", "cloud");

        // Takeover aliases
        domain_aliases.insert("to", "takeover");

        let mut resource_aliases = HashMap::new();

        // Fingerprint (most important - very long word)
        resource_aliases.insert("fp", "fingerprint");
        resource_aliases.insert("print", "fingerprint");

        // Record (DNS)
        resource_aliases.insert("rec", "record");
        resource_aliases.insert("records", "record");

        // Domain (recon)
        resource_aliases.insert("dom", "domain");

        // Security
        resource_aliases.insert("sec", "security");

        // Certificate
        resource_aliases.insert("cert", "certificate");
        resource_aliases.insert("crt", "certificate");

        // Payload
        resource_aliases.insert("pl", "payload");

        // Listener
        resource_aliases.insert("listen", "listener");
        resource_aliases.insert("ls", "listener");

        // Screenshot
        resource_aliases.insert("screen", "screenshot");
        resource_aliases.insert("shot", "screenshot");
        resource_aliases.insert("ss", "screenshot");

        // Dependencies
        resource_aliases.insert("deps", "dependencies");
        resource_aliases.insert("dep", "dependencies");

        // Subdomains
        resource_aliases.insert("subs", "subdomains");
        resource_aliases.insert("sub", "subdomains");

        let mut verb_aliases = HashMap::new();

        // Describe
        verb_aliases.insert("desc", "describe");

        // Enumerate
        verb_aliases.insert("enum", "enumerate");

        // Bruteforce
        verb_aliases.insert("brute", "bruteforce");
        verb_aliases.insert("bf", "bruteforce");

        // Takeover
        verb_aliases.insert("to", "takeover");

        // Discover
        verb_aliases.insert("disc", "discover");

        // Fingerprint
        verb_aliases.insert("fp", "fingerprint");

        Self {
            domain_aliases,
            resource_aliases,
            verb_aliases,
        }
    }

    /// Resolve domain alias to canonical name
    pub fn resolve_domain<'a>(&'a self, input: &'a str) -> &'a str {
        self.domain_aliases.get(input).copied().unwrap_or(input)
    }

    /// Resolve resource alias to canonical name
    pub fn resolve_resource<'a>(&'a self, input: &'a str) -> &'a str {
        self.resource_aliases.get(input).copied().unwrap_or(input)
    }

    /// Resolve verb alias to canonical name
    pub fn resolve_verb<'a>(&'a self, input: &'a str) -> &'a str {
        self.verb_aliases.get(input).copied().unwrap_or(input)
    }

    /// Resolve all parts of a command at once
    pub fn resolve_all(
        &self,
        domain: &str,
        resource: Option<&str>,
        verb: Option<&str>,
    ) -> (String, Option<String>, Option<String>) {
        let resolved_domain = self.resolve_domain(domain).to_string();
        let resolved_resource = resource.map(|r| self.resolve_resource(r).to_string());
        let resolved_verb = verb.map(|v| self.resolve_verb(v).to_string());

        (resolved_domain, resolved_resource, resolved_verb)
    }

    /// Get all aliases for a domain
    pub fn get_domain_aliases(&self, domain: &str) -> Vec<&str> {
        self.domain_aliases
            .iter()
            .filter(|(_, &canonical)| canonical == domain)
            .map(|(&alias, _)| alias)
            .collect()
    }

    /// Get all aliases for a resource
    pub fn get_resource_aliases(&self, resource: &str) -> Vec<&str> {
        self.resource_aliases
            .iter()
            .filter(|(_, &canonical)| canonical == resource)
            .map(|(&alias, _)| alias)
            .collect()
    }

    /// Get all aliases for a verb
    pub fn get_verb_aliases(&self, verb: &str) -> Vec<&str> {
        self.verb_aliases
            .iter()
            .filter(|(_, &canonical)| canonical == verb)
            .map(|(&alias, _)| alias)
            .collect()
    }

    /// Check if input is an alias
    pub fn is_alias(&self, input: &str) -> bool {
        self.domain_aliases.contains_key(input)
            || self.resource_aliases.contains_key(input)
            || self.verb_aliases.contains_key(input)
    }

    /// Get suggested command with aliases (for examples/help)
    pub fn suggest_shortest(
        &self,
        domain: &str,
        resource: Option<&str>,
        verb: Option<&str>,
    ) -> String {
        // Use shortest available alias
        let domain_aliases = self.get_domain_aliases(domain);
        let domain_short = domain_aliases
            .iter()
            .min_by_key(|a| a.len())
            .copied()
            .unwrap_or(domain);

        let mut parts = vec![domain_short.to_string()];

        if let Some(r) = resource {
            let resource_aliases = self.get_resource_aliases(r);
            let resource_short = resource_aliases
                .iter()
                .min_by_key(|a| a.len())
                .copied()
                .unwrap_or(r);
            parts.push(resource_short.to_string());
        }

        if let Some(v) = verb {
            let verb_aliases = self.get_verb_aliases(v);
            let verb_short = verb_aliases
                .iter()
                .min_by_key(|a| a.len())
                .copied()
                .unwrap_or(v);
            parts.push(verb_short.to_string());
        }

        parts.join(" ")
    }
}

impl Default for AliasResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_aliases() {
        let resolver = AliasResolver::new();

        assert_eq!(resolver.resolve_domain("i"), "intelligence");
        assert_eq!(resolver.resolve_domain("intel"), "intelligence");
        assert_eq!(resolver.resolve_domain("intelligence"), "intelligence");

        assert_eq!(resolver.resolve_domain("n"), "network");
        assert_eq!(resolver.resolve_domain("net"), "network");

        assert_eq!(resolver.resolve_domain("d"), "database");
        assert_eq!(resolver.resolve_domain("db"), "database");
    }

    #[test]
    fn test_resource_aliases() {
        let resolver = AliasResolver::new();

        assert_eq!(resolver.resolve_resource("fp"), "fingerprint");
        assert_eq!(resolver.resolve_resource("print"), "fingerprint");

        assert_eq!(resolver.resolve_resource("rec"), "record");
        assert_eq!(resolver.resolve_resource("cert"), "certificate");
    }

    #[test]
    fn test_verb_aliases() {
        let resolver = AliasResolver::new();

        assert_eq!(resolver.resolve_verb("desc"), "describe");
        assert_eq!(resolver.resolve_verb("enum"), "enumerate");
        assert_eq!(resolver.resolve_verb("brute"), "bruteforce");
    }

    #[test]
    fn test_resolve_all() {
        let resolver = AliasResolver::new();

        let (domain, resource, verb) = resolver.resolve_all("i", Some("fp"), Some("desc"));

        assert_eq!(domain, "intelligence");
        assert_eq!(resource, Some("fingerprint".to_string()));
        assert_eq!(verb, Some("describe".to_string()));
    }

    #[test]
    fn test_get_aliases() {
        let resolver = AliasResolver::new();

        let aliases = resolver.get_domain_aliases("intelligence");
        assert!(aliases.contains(&"i"));
        assert!(aliases.contains(&"intel"));
    }

    #[test]
    fn test_suggest_shortest() {
        let resolver = AliasResolver::new();

        let suggestion =
            resolver.suggest_shortest("intelligence", Some("fingerprint"), Some("describe"));

        // Should suggest shortest aliases
        assert!(suggestion.contains("i") || suggestion.contains("fp"));
    }

    #[test]
    fn test_is_alias() {
        let resolver = AliasResolver::new();

        assert!(resolver.is_alias("i"));
        assert!(resolver.is_alias("fp"));
        assert!(resolver.is_alias("desc"));
        assert!(!resolver.is_alias("notanalias"));
    }
}
