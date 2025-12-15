//! Access Control Lists (ACL) for Proxy
//!
//! Implements rule-based traffic filtering inspired by shadowsocks-rust ACL
//! and OpenWrt-nikki access control patterns.
//!
//! # Rule Types
//!
//! - **IP-based**: Match by source/destination IP address or CIDR
//! - **Domain-based**: Match by domain name patterns (wildcards supported)
//! - **Port-based**: Match by destination port
//! - **Process-based**: Match by PID or process name (Linux only)
//!
//! # Example
//!
//! ```rust
//! use redblue::modules::proxy::acl::{AccessControl, Rule, Action};
//!
//! let mut acl = AccessControl::new(Action::Proxy); // Default: proxy all
//!
//! // Bypass local networks
//! acl.add_rule(Rule::cidr("10.0.0.0/8", Action::Bypass));
//! acl.add_rule(Rule::cidr("192.168.0.0/16", Action::Bypass));
//!
//! // Bypass specific domains
//! acl.add_rule(Rule::domain("*.local", Action::Bypass));
//!
//! // Block malicious domains
//! acl.add_rule(Rule::domain("*.malware.com", Action::Block));
//! ```

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::Address;

/// Action to take for a matched rule
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Proxy the connection (default for most proxies)
    Proxy,
    /// Bypass proxy (direct connection)
    Bypass,
    /// Block the connection
    Block,
}

/// Rule types for access control
#[derive(Debug, Clone)]
pub enum Rule {
    /// Match by IP address
    Ip { addr: IpAddr, action: Action },
    /// Match by CIDR range
    Cidr {
        network: IpAddr,
        prefix_len: u8,
        action: Action,
    },
    /// Match by domain pattern (supports wildcards)
    Domain { pattern: String, action: Action },
    /// Match by destination port
    Port { port: u16, action: Action },
    /// Match by port range
    PortRange {
        start: u16,
        end: u16,
        action: Action,
    },
    /// Match by process ID (Linux only)
    Pid { pid: u32, action: Action },
    /// Match by process name (Linux only)
    ProcessName { name: String, action: Action },
}

impl Rule {
    /// Create IP rule
    pub fn ip(addr: IpAddr, action: Action) -> Self {
        Self::Ip { addr, action }
    }

    /// Create CIDR rule
    pub fn cidr(cidr: &str, action: Action) -> Self {
        let parts: Vec<&str> = cidr.split('/').collect();
        let network: IpAddr = parts[0].parse().expect("Invalid IP address");
        let prefix_len: u8 = parts
            .get(1)
            .map(|p| p.parse().unwrap())
            .unwrap_or(if network.is_ipv4() { 32 } else { 128 });
        Self::Cidr {
            network,
            prefix_len,
            action,
        }
    }

    /// Create domain pattern rule
    pub fn domain(pattern: &str, action: Action) -> Self {
        Self::Domain {
            pattern: pattern.to_lowercase(),
            action,
        }
    }

    /// Create port rule
    pub fn port(port: u16, action: Action) -> Self {
        Self::Port { port, action }
    }

    /// Create port range rule
    pub fn port_range(start: u16, end: u16, action: Action) -> Self {
        Self::PortRange { start, end, action }
    }

    /// Create PID rule
    pub fn pid(pid: u32, action: Action) -> Self {
        Self::Pid { pid, action }
    }

    /// Create process name rule
    pub fn process_name(name: &str, action: Action) -> Self {
        Self::ProcessName {
            name: name.to_string(),
            action,
        }
    }

    /// Get the action for this rule
    pub fn action(&self) -> Action {
        match self {
            Self::Ip { action, .. } => *action,
            Self::Cidr { action, .. } => *action,
            Self::Domain { action, .. } => *action,
            Self::Port { action, .. } => *action,
            Self::PortRange { action, .. } => *action,
            Self::Pid { action, .. } => *action,
            Self::ProcessName { action, .. } => *action,
        }
    }
}

/// Access Control List manager
#[derive(Debug)]
pub struct AccessControl {
    /// Rules in order of priority (first match wins)
    rules: Vec<Rule>,
    /// Default action if no rule matches
    default_action: Action,
    /// Reserved IP ranges (always bypassed)
    bypass_reserved: bool,
    /// Blocked ports (quick lookup)
    blocked_ports: HashSet<u16>,
}

impl AccessControl {
    /// Create new ACL with default action
    pub fn new(default_action: Action) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
            bypass_reserved: true,
            blocked_ports: HashSet::new(),
        }
    }

    /// Set whether to bypass reserved IP ranges
    pub fn set_bypass_reserved(&mut self, bypass: bool) {
        self.bypass_reserved = bypass;
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: Rule) {
        // Track blocked ports for quick lookup
        if let Rule::Port {
            port,
            action: Action::Block,
        } = &rule
        {
            self.blocked_ports.insert(*port);
        }
        self.rules.push(rule);
    }

    /// Add rules for RFC 1918 private networks
    pub fn add_private_networks(&mut self, action: Action) {
        self.add_rule(Rule::cidr("10.0.0.0/8", action));
        self.add_rule(Rule::cidr("172.16.0.0/12", action));
        self.add_rule(Rule::cidr("192.168.0.0/16", action));
    }

    /// Add rules for localhost
    pub fn add_localhost(&mut self, action: Action) {
        self.add_rule(Rule::cidr("127.0.0.0/8", action));
        self.add_rule(Rule::cidr("::1/128", action));
    }

    /// Add rules for link-local addresses
    pub fn add_link_local(&mut self, action: Action) {
        self.add_rule(Rule::cidr("169.254.0.0/16", action));
        self.add_rule(Rule::cidr("fe80::/10", action));
    }

    /// Add rules for multicast addresses
    pub fn add_multicast(&mut self, action: Action) {
        self.add_rule(Rule::cidr("224.0.0.0/4", action));
        self.add_rule(Rule::cidr("ff00::/8", action));
    }

    /// Add standard bypass rules (private, localhost, link-local, multicast)
    pub fn add_standard_bypass(&mut self) {
        self.add_private_networks(Action::Bypass);
        self.add_localhost(Action::Bypass);
        self.add_link_local(Action::Bypass);
        self.add_multicast(Action::Bypass);
    }

    /// Check if IP is in reserved range
    fn is_reserved_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_loopback()
                    || ipv4.is_private()
                    || ipv4.is_link_local()
                    || ipv4.is_multicast()
                    || ipv4.is_broadcast()
                    || ipv4.is_unspecified()
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback()
                    || ipv6.is_multicast()
                    || ipv6.is_unspecified()
                    || is_ipv6_unique_local(ipv6)
                    || is_ipv6_link_local(ipv6)
            }
        }
    }

    /// Match IP against CIDR
    fn match_cidr(&self, ip: &IpAddr, network: &IpAddr, prefix_len: u8) -> bool {
        match (ip, network) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let ip_bits = u32::from(*ip);
                let net_bits = u32::from(*net);
                let mask = if prefix_len >= 32 {
                    u32::MAX
                } else {
                    u32::MAX << (32 - prefix_len)
                };
                (ip_bits & mask) == (net_bits & mask)
            }
            (IpAddr::V6(ip), IpAddr::V6(net)) => {
                let ip_bits = u128::from(*ip);
                let net_bits = u128::from(*net);
                let mask = if prefix_len >= 128 {
                    u128::MAX
                } else {
                    u128::MAX << (128 - prefix_len)
                };
                (ip_bits & mask) == (net_bits & mask)
            }
            _ => false,
        }
    }

    /// Match domain against pattern (supports * and ? wildcards)
    fn match_domain(&self, domain: &str, pattern: &str) -> bool {
        let domain = domain.to_lowercase();
        let pattern = pattern.to_lowercase();

        // Handle leading wildcard (*.example.com matches sub.example.com)
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            return domain == suffix || domain.ends_with(&format!(".{}", suffix));
        }

        // Handle trailing wildcard (example.* matches example.com, example.org)
        if pattern.ends_with(".*") {
            let prefix = &pattern[..pattern.len() - 2];
            return domain.starts_with(prefix);
        }

        // Exact match or simple wildcard
        if pattern.contains('*') || pattern.contains('?') {
            wildcard_match(&domain, &pattern)
        } else {
            domain == pattern
        }
    }

    /// Evaluate rules for a connection
    pub fn evaluate(
        &self,
        src_addr: Option<&SocketAddr>,
        dst_addr: &Address,
        process_info: Option<(&u32, &str)>,
    ) -> Action {
        // Check reserved IPs first if enabled
        if self.bypass_reserved {
            match dst_addr {
                Address::Socket(addr) => {
                    if self.is_reserved_ip(&addr.ip()) {
                        return Action::Bypass;
                    }
                }
                _ => {}
            }
        }

        // Check blocked ports (quick path)
        if self.blocked_ports.contains(&dst_addr.port()) {
            return Action::Block;
        }

        // Evaluate rules in order
        for rule in &self.rules {
            let matched = match rule {
                Rule::Ip { addr, .. } => match dst_addr {
                    Address::Socket(dst) => dst.ip() == *addr,
                    _ => false,
                },
                Rule::Cidr {
                    network,
                    prefix_len,
                    ..
                } => match dst_addr {
                    Address::Socket(dst) => self.match_cidr(&dst.ip(), network, *prefix_len),
                    _ => false,
                },
                Rule::Domain { pattern, .. } => match dst_addr {
                    Address::Domain(domain, _) => self.match_domain(domain, pattern),
                    _ => false,
                },
                Rule::Port { port, .. } => dst_addr.port() == *port,
                Rule::PortRange { start, end, .. } => {
                    let p = dst_addr.port();
                    p >= *start && p <= *end
                }
                Rule::Pid { pid, .. } => process_info.map(|(p, _)| p == pid).unwrap_or(false),
                Rule::ProcessName { name, .. } => process_info
                    .map(|(_, n)| n.contains(name.as_str()))
                    .unwrap_or(false),
            };

            if matched {
                return rule.action();
            }
        }

        self.default_action
    }

    /// Quick check if address should be blocked
    pub fn is_blocked(&self, dst_addr: &Address) -> bool {
        self.evaluate(None, dst_addr, None) == Action::Block
    }

    /// Quick check if address should bypass proxy
    pub fn should_bypass(&self, dst_addr: &Address) -> bool {
        self.evaluate(None, dst_addr, None) == Action::Bypass
    }
}

impl Default for AccessControl {
    fn default() -> Self {
        let mut acl = Self::new(Action::Proxy);
        acl.add_standard_bypass();
        acl
    }
}

/// Simple wildcard pattern matching
fn wildcard_match(text: &str, pattern: &str) -> bool {
    let text_chars: Vec<char> = text.chars().collect();
    let pattern_chars: Vec<char> = pattern.chars().collect();

    let mut ti = 0;
    let mut pi = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while ti < text_chars.len() {
        if pi < pattern_chars.len()
            && (pattern_chars[pi] == '?' || pattern_chars[pi] == text_chars[ti])
        {
            ti += 1;
            pi += 1;
        } else if pi < pattern_chars.len() && pattern_chars[pi] == '*' {
            star_idx = Some(pi);
            match_idx = ti;
            pi += 1;
        } else if let Some(idx) = star_idx {
            pi = idx + 1;
            match_idx += 1;
            ti = match_idx;
        } else {
            return false;
        }
    }

    while pi < pattern_chars.len() && pattern_chars[pi] == '*' {
        pi += 1;
    }

    pi == pattern_chars.len()
}

/// Check if IPv6 address is unique local (fc00::/7)
fn is_ipv6_unique_local(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

/// Check if IPv6 address is link local (fe80::/10)
fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_match() {
        assert!(wildcard_match("example.com", "example.com"));
        assert!(wildcard_match("example.com", "*.com"));
        assert!(wildcard_match("sub.example.com", "*.example.com"));
        assert!(wildcard_match("example.com", "example.*"));
        assert!(wildcard_match("test", "t?st"));
        assert!(!wildcard_match("example.org", "*.com"));
    }

    #[test]
    fn test_cidr_matching() {
        let acl = AccessControl::new(Action::Proxy);

        // IPv4
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let net: IpAddr = "192.168.0.0".parse().unwrap();
        assert!(acl.match_cidr(&ip, &net, 16));
        assert!(!acl.match_cidr(&ip, &net, 24));

        // IPv6
        let ip6: IpAddr = "2001:db8::1".parse().unwrap();
        let net6: IpAddr = "2001:db8::".parse().unwrap();
        assert!(acl.match_cidr(&ip6, &net6, 32));
    }

    #[test]
    fn test_domain_matching() {
        let acl = AccessControl::new(Action::Proxy);

        assert!(acl.match_domain("sub.example.com", "*.example.com"));
        assert!(acl.match_domain("example.com", "*.example.com"));
        assert!(!acl.match_domain("notexample.com", "*.example.com"));
    }

    #[test]
    fn test_acl_evaluation() {
        let mut acl = AccessControl::new(Action::Proxy);
        acl.add_rule(Rule::cidr("192.168.0.0/16", Action::Bypass));
        acl.add_rule(Rule::domain("*.blocked.com", Action::Block));
        acl.add_rule(Rule::port(22, Action::Block));

        // Test private IP bypass
        let private = Address::from_socket("192.168.1.1:80".parse().unwrap());
        assert_eq!(acl.evaluate(None, &private, None), Action::Bypass);

        // Test blocked domain
        let blocked = Address::from_domain("sub.blocked.com", 80);
        assert_eq!(acl.evaluate(None, &blocked, None), Action::Block);

        // Test blocked port
        let ssh = Address::from_socket("8.8.8.8:22".parse().unwrap());
        assert_eq!(acl.evaluate(None, &ssh, None), Action::Block);

        // Test normal traffic
        let normal = Address::from_socket("8.8.8.8:443".parse().unwrap());
        assert_eq!(acl.evaluate(None, &normal, None), Action::Proxy);
    }

    #[test]
    fn test_reserved_ip_detection() {
        let acl = AccessControl::new(Action::Proxy);

        assert!(acl.is_reserved_ip(&"127.0.0.1".parse().unwrap()));
        assert!(acl.is_reserved_ip(&"192.168.1.1".parse().unwrap()));
        assert!(acl.is_reserved_ip(&"10.0.0.1".parse().unwrap()));
        assert!(acl.is_reserved_ip(&"::1".parse().unwrap()));
        assert!(!acl.is_reserved_ip(&"8.8.8.8".parse().unwrap()));
    }
}
