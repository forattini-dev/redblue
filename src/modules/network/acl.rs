/// Access Control List (ACL) for network connections
///
/// Implements IP-based allow/deny rules for incoming connections.
///
/// Features:
/// - IP address matching
/// - CIDR subnet matching
/// - Allow list (whitelist)
/// - Deny list (blacklist)
///
/// Replaces: ncat --allow / --deny
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// ACL rule type
#[derive(Debug, Clone, PartialEq)]
pub enum AclRule {
    AllowIp(IpAddr),
    AllowCidr(IpAddr, u8), // IP + prefix length
    DenyIp(IpAddr),
    DenyCidr(IpAddr, u8),
}

/// Access Control List
#[derive(Debug, Clone)]
pub struct Acl {
    rules: Vec<AclRule>,
    default_allow: bool, // If true, allow all by default (blacklist mode)
}

impl Acl {
    /// Create new ACL with default policy
    pub fn new(default_allow: bool) -> Self {
        Self {
            rules: Vec::new(),
            default_allow,
        }
    }

    /// Create ACL in whitelist mode (deny by default)
    pub fn whitelist() -> Self {
        Self::new(false)
    }

    /// Create ACL in blacklist mode (allow by default)
    pub fn blacklist() -> Self {
        Self::new(true)
    }

    /// Add allow rule for single IP
    pub fn allow_ip(&mut self, ip: IpAddr) {
        self.rules.push(AclRule::AllowIp(ip));
    }

    /// Add allow rule for CIDR subnet
    pub fn allow_cidr(&mut self, ip: IpAddr, prefix_len: u8) {
        self.rules.push(AclRule::AllowCidr(ip, prefix_len));
    }

    /// Add deny rule for single IP
    pub fn deny_ip(&mut self, ip: IpAddr) {
        self.rules.push(AclRule::DenyIp(ip));
    }

    /// Add deny rule for CIDR subnet
    pub fn deny_cidr(&mut self, ip: IpAddr, prefix_len: u8) {
        self.rules.push(AclRule::DenyCidr(ip, prefix_len));
    }

    /// Check if an IP address is allowed
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        // Process rules in order
        for rule in &self.rules {
            match rule {
                AclRule::AllowIp(allowed_ip) => {
                    if ip == *allowed_ip {
                        return true;
                    }
                }
                AclRule::AllowCidr(network, prefix_len) => {
                    if Self::matches_cidr(ip, *network, *prefix_len) {
                        return true;
                    }
                }
                AclRule::DenyIp(denied_ip) => {
                    if ip == *denied_ip {
                        return false;
                    }
                }
                AclRule::DenyCidr(network, prefix_len) => {
                    if Self::matches_cidr(ip, *network, *prefix_len) {
                        return false;
                    }
                }
            }
        }

        // If no rule matched, use default policy
        self.default_allow
    }

    /// Check if IP matches CIDR subnet
    fn matches_cidr(ip: IpAddr, network: IpAddr, prefix_len: u8) -> bool {
        match (ip, network) {
            (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
                Self::matches_cidr_v4(ip4, net4, prefix_len)
            }
            (IpAddr::V6(ip6), IpAddr::V6(net6)) => {
                Self::matches_cidr_v6(ip6, net6, prefix_len)
            }
            _ => false, // IPv4 vs IPv6 mismatch
        }
    }

    /// Check IPv4 CIDR match
    fn matches_cidr_v4(ip: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
        if prefix_len > 32 {
            return false;
        }

        let ip_bits = u32::from(ip);
        let net_bits = u32::from(network);

        if prefix_len == 0 {
            return true; // 0.0.0.0/0 matches everything
        }

        let mask = !0u32 << (32 - prefix_len);
        (ip_bits & mask) == (net_bits & mask)
    }

    /// Check IPv6 CIDR match
    fn matches_cidr_v6(ip: Ipv6Addr, network: Ipv6Addr, prefix_len: u8) -> bool {
        if prefix_len > 128 {
            return false;
        }

        let ip_bits = u128::from(ip);
        let net_bits = u128::from(network);

        if prefix_len == 0 {
            return true; // ::/0 matches everything
        }

        let mask = !0u128 << (128 - prefix_len);
        (ip_bits & mask) == (net_bits & mask)
    }

    /// Parse CIDR string (e.g., "192.168.1.0/24")
    pub fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
        let parts: Vec<&str> = s.split('/').collect();

        if parts.len() != 2 {
            return Err(format!("Invalid CIDR format: {}", s));
        }

        let ip: IpAddr = parts[0]
            .parse()
            .map_err(|_| format!("Invalid IP address: {}", parts[0]))?;

        let prefix_len: u8 = parts[1]
            .parse()
            .map_err(|_| format!("Invalid prefix length: {}", parts[1]))?;

        // Validate prefix length
        match ip {
            IpAddr::V4(_) if prefix_len > 32 => {
                return Err(format!("IPv4 prefix length cannot exceed 32: {}", prefix_len))
            }
            IpAddr::V6(_) if prefix_len > 128 => {
                return Err(format!("IPv6 prefix length cannot exceed 128: {}", prefix_len))
            }
            _ => {}
        }

        Ok((ip, prefix_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_whitelist_mode() {
        let mut acl = Acl::whitelist();
        let ip = IpAddr::from_str("192.168.1.100").unwrap();
        let other_ip = IpAddr::from_str("10.0.0.1").unwrap();

        // By default, deny all
        assert!(!acl.is_allowed(ip));
        assert!(!acl.is_allowed(other_ip));

        // Add allow rule
        acl.allow_ip(ip);
        assert!(acl.is_allowed(ip));
        assert!(!acl.is_allowed(other_ip));
    }

    #[test]
    fn test_blacklist_mode() {
        let mut acl = Acl::blacklist();
        let ip = IpAddr::from_str("192.168.1.100").unwrap();
        let other_ip = IpAddr::from_str("10.0.0.1").unwrap();

        // By default, allow all
        assert!(acl.is_allowed(ip));
        assert!(acl.is_allowed(other_ip));

        // Add deny rule
        acl.deny_ip(ip);
        assert!(!acl.is_allowed(ip));
        assert!(acl.is_allowed(other_ip));
    }

    #[test]
    fn test_cidr_matching() {
        let mut acl = Acl::whitelist();

        // Allow 192.168.1.0/24
        let network = IpAddr::from_str("192.168.1.0").unwrap();
        acl.allow_cidr(network, 24);

        // Should match
        assert!(acl.is_allowed(IpAddr::from_str("192.168.1.1").unwrap()));
        assert!(acl.is_allowed(IpAddr::from_str("192.168.1.100").unwrap()));
        assert!(acl.is_allowed(IpAddr::from_str("192.168.1.255").unwrap()));

        // Should not match
        assert!(!acl.is_allowed(IpAddr::from_str("192.168.2.1").unwrap()));
        assert!(!acl.is_allowed(IpAddr::from_str("10.0.0.1").unwrap()));
    }

    #[test]
    fn test_parse_cidr() {
        let (ip, prefix) = Acl::parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ip, IpAddr::from_str("192.168.1.0").unwrap());
        assert_eq!(prefix, 24);

        let (ip, prefix) = Acl::parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(ip, IpAddr::from_str("10.0.0.0").unwrap());
        assert_eq!(prefix, 8);

        // Invalid CIDR
        assert!(Acl::parse_cidr("invalid").is_err());
        assert!(Acl::parse_cidr("192.168.1.0").is_err());
        assert!(Acl::parse_cidr("192.168.1.0/33").is_err());
    }

    #[test]
    fn test_deny_priority() {
        let mut acl = Acl::whitelist();

        // Allow 192.168.1.0/24
        acl.allow_cidr(IpAddr::from_str("192.168.1.0").unwrap(), 24);

        // Deny specific IP within allowed range
        acl.deny_ip(IpAddr::from_str("192.168.1.100").unwrap());

        // Should allow most IPs in range
        assert!(acl.is_allowed(IpAddr::from_str("192.168.1.1").unwrap()));
        assert!(acl.is_allowed(IpAddr::from_str("192.168.1.50").unwrap()));

        // Should deny specific IP (deny rule comes after allow)
        assert!(!acl.is_allowed(IpAddr::from_str("192.168.1.100").unwrap()));
    }
}
