//! DNS Hijacking Rules Engine
//!
//! Implements pattern matching and actions for DNS hijacking.

use std::net::IpAddr;

/// DNS hijacking rule
#[derive(Debug, Clone)]
pub struct DnsRule {
    /// Pattern to match (supports wildcards)
    pub pattern: String,
    /// Record type to match (None = any)
    pub record_type: Option<u16>,
    /// Action to take
    pub action: RuleAction,
    /// Rule priority (higher = checked first)
    pub priority: u32,
    /// Rule enabled
    pub enabled: bool,
}

/// Action to take when a rule matches
#[derive(Debug, Clone)]
pub enum RuleAction {
    /// Override with specific IP address
    Override(IpAddr),
    /// Block the domain (return NXDOMAIN)
    Block,
    /// Redirect to different domain
    Redirect(String),
    /// Forward to specific upstream server
    Forward(String),
    /// Allow (bypass other rules, forward to default upstream)
    Allow,
}

/// Result of rule matching
#[derive(Debug, Clone)]
pub enum RuleMatch {
    /// No rule matched
    None,
    /// Override response with this IP
    Override(IpAddr),
    /// Block (NXDOMAIN)
    Block,
    /// Redirect to different domain
    Redirect(String),
    /// Forward to specific upstream
    Forward(String),
    /// Allow (use default upstream)
    Allow,
}

impl DnsRule {
    /// Create new rule
    pub fn new(pattern: &str, action: RuleAction) -> Self {
        Self {
            pattern: pattern.to_lowercase(),
            record_type: None,
            action,
            priority: 100,
            enabled: true,
        }
    }

    /// Create A record override rule
    pub fn override_a(pattern: &str, ip: &str) -> Self {
        let ip: IpAddr = ip.parse().expect("Invalid IP address");
        Self::new(pattern, RuleAction::Override(ip)).with_record_type(1) // A record
    }

    /// Create AAAA record override rule
    pub fn override_aaaa(pattern: &str, ip: &str) -> Self {
        let ip: IpAddr = ip.parse().expect("Invalid IPv6 address");
        Self::new(pattern, RuleAction::Override(ip)).with_record_type(28) // AAAA record
    }

    /// Create block rule
    pub fn block(pattern: &str) -> Self {
        Self::new(pattern, RuleAction::Block)
    }

    /// Create redirect rule
    pub fn redirect(pattern: &str, target: &str) -> Self {
        Self::new(pattern, RuleAction::Redirect(target.to_string()))
    }

    /// Create forward rule
    pub fn forward(pattern: &str, upstream: &str) -> Self {
        Self::new(pattern, RuleAction::Forward(upstream.to_string()))
    }

    /// Create allow rule (bypass other rules)
    pub fn allow(pattern: &str) -> Self {
        Self::new(pattern, RuleAction::Allow).with_priority(200) // Higher priority
    }

    /// Set record type filter
    pub fn with_record_type(mut self, rtype: u16) -> Self {
        self.record_type = Some(rtype);
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Enable/disable rule
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Check if domain matches this rule's pattern
    pub fn matches(&self, domain: &str, qtype: u16) -> bool {
        if !self.enabled {
            return false;
        }

        // Check record type if specified
        if let Some(rt) = self.record_type {
            if rt != qtype {
                return false;
            }
        }

        // Check pattern match
        pattern_matches(&self.pattern, &domain.to_lowercase())
    }

    /// Get action for this rule
    pub fn get_action(&self) -> RuleMatch {
        match &self.action {
            RuleAction::Override(ip) => RuleMatch::Override(*ip),
            RuleAction::Block => RuleMatch::Block,
            RuleAction::Redirect(target) => RuleMatch::Redirect(target.clone()),
            RuleAction::Forward(upstream) => RuleMatch::Forward(upstream.clone()),
            RuleAction::Allow => RuleMatch::Allow,
        }
    }
}

/// DNS rules engine
#[derive(Debug, Clone)]
pub struct RulesEngine {
    rules: Vec<DnsRule>,
}

impl RulesEngine {
    /// Create new rules engine
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: DnsRule) {
        self.rules.push(rule);
        // Sort by priority (highest first)
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Add multiple rules
    pub fn add_rules(&mut self, rules: Vec<DnsRule>) {
        for rule in rules {
            self.add_rule(rule);
        }
    }

    /// Remove rules matching pattern
    pub fn remove_pattern(&mut self, pattern: &str) {
        self.rules.retain(|r| r.pattern != pattern);
    }

    /// Clear all rules
    pub fn clear(&mut self) {
        self.rules.clear();
    }

    /// Match domain against rules
    pub fn match_domain(&self, domain: &str, qtype: u16) -> RuleMatch {
        for rule in &self.rules {
            if rule.matches(domain, qtype) {
                return rule.get_action();
            }
        }
        RuleMatch::None
    }

    /// Get number of rules
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Get all rules
    pub fn rules(&self) -> &[DnsRule] {
        &self.rules
    }
}

impl Default for RulesEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if domain matches pattern (supports wildcards)
///
/// Patterns:
/// - `example.com` - exact match
/// - `*.example.com` - matches any subdomain of example.com
/// - `*` - matches everything
fn pattern_matches(pattern: &str, domain: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.starts_with("*.") {
        // Wildcard pattern: *.example.com
        let suffix = &pattern[2..]; // Remove "*."

        // Check if domain ends with the suffix
        if domain == suffix {
            return true; // *.example.com matches example.com
        }

        if domain.ends_with(suffix) {
            // Make sure it's a proper subdomain (has a dot before suffix)
            let prefix_len = domain.len() - suffix.len();
            if prefix_len > 0 {
                let before_suffix = &domain[..prefix_len];
                return before_suffix.ends_with('.');
            }
        }
        return false;
    }

    // Exact match
    domain == pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_exact_match() {
        assert!(pattern_matches("example.com", "example.com"));
        assert!(!pattern_matches("example.com", "sub.example.com"));
        assert!(!pattern_matches("example.com", "example.org"));
    }

    #[test]
    fn test_pattern_wildcard() {
        assert!(pattern_matches("*.example.com", "sub.example.com"));
        assert!(pattern_matches("*.example.com", "a.b.example.com"));
        assert!(pattern_matches("*.example.com", "example.com"));
        assert!(!pattern_matches("*.example.com", "example.org"));
        assert!(!pattern_matches("*.example.com", "notexample.com"));
    }

    #[test]
    fn test_pattern_star() {
        assert!(pattern_matches("*", "anything.com"));
        assert!(pattern_matches("*", "example.com"));
    }

    #[test]
    fn test_rules_engine() {
        let mut engine = RulesEngine::new();

        engine.add_rule(DnsRule::override_a("target.com", "10.0.0.1"));
        engine.add_rule(DnsRule::block("*.ads.com"));
        engine.add_rule(DnsRule::allow("safe.ads.com").with_priority(150));

        // Override
        match engine.match_domain("target.com", 1) {
            RuleMatch::Override(ip) => assert_eq!(ip.to_string(), "10.0.0.1"),
            _ => panic!("Expected override"),
        }

        // Block
        match engine.match_domain("tracker.ads.com", 1) {
            RuleMatch::Block => {}
            _ => panic!("Expected block"),
        }

        // Allow (higher priority)
        match engine.match_domain("safe.ads.com", 1) {
            RuleMatch::Allow => {}
            _ => panic!("Expected allow"),
        }

        // No match
        match engine.match_domain("google.com", 1) {
            RuleMatch::None => {}
            _ => panic!("Expected none"),
        }
    }
}
