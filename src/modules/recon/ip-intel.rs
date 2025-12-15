/// IP Intelligence Module
/// Provides bogon detection, IP classification, and basic IP information
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IPv4 Bogon Ranges (RFC reserved ranges that should not appear on the public internet)
const IPV4_BOGONS: &[(&str, &str, u32, u32)] = &[
    (
        "0.0.0.0/8",
        "This Network (RFC 1122)",
        0x00000000,
        0x00FFFFFF,
    ),
    (
        "10.0.0.0/8",
        "Private-Use (RFC 1918)",
        0x0A000000,
        0x0AFFFFFF,
    ),
    (
        "100.64.0.0/10",
        "Carrier-Grade NAT (RFC 6598)",
        0x64400000,
        0x647FFFFF,
    ),
    ("127.0.0.0/8", "Loopback (RFC 1122)", 0x7F000000, 0x7FFFFFFF),
    (
        "169.254.0.0/16",
        "Link-Local (RFC 3927)",
        0xA9FE0000,
        0xA9FEFFFF,
    ),
    (
        "172.16.0.0/12",
        "Private-Use (RFC 1918)",
        0xAC100000,
        0xAC1FFFFF,
    ),
    (
        "192.0.0.0/24",
        "IETF Protocol Assignments (RFC 6890)",
        0xC0000000,
        0xC00000FF,
    ),
    (
        "192.0.2.0/24",
        "Documentation TEST-NET-1 (RFC 5737)",
        0xC0000200,
        0xC00002FF,
    ),
    (
        "192.168.0.0/16",
        "Private-Use (RFC 1918)",
        0xC0A80000,
        0xC0A8FFFF,
    ),
    (
        "198.18.0.0/15",
        "Benchmarking (RFC 2544)",
        0xC6120000,
        0xC613FFFF,
    ),
    (
        "198.51.100.0/24",
        "Documentation TEST-NET-2 (RFC 5737)",
        0xC6336400,
        0xC63364FF,
    ),
    (
        "203.0.113.0/24",
        "Documentation TEST-NET-3 (RFC 5737)",
        0xCB007100,
        0xCB0071FF,
    ),
    (
        "224.0.0.0/4",
        "Multicast (RFC 5771)",
        0xE0000000,
        0xEFFFFFFF,
    ),
    ("240.0.0.0/4", "Reserved (RFC 1112)", 0xF0000000, 0xFFFFFFFF),
];

/// IPv6 Bogon Prefixes
const IPV6_BOGONS: &[(&str, &str)] = &[
    ("::/128", "Unspecified Address"),
    ("::1/128", "Loopback Address"),
    ("::ffff:0:0/96", "IPv4-mapped Address"),
    ("64:ff9b::/96", "IPv4-IPv6 Translation"),
    ("100::/64", "Discard-Only (RFC 6666)"),
    ("2001::/32", "Teredo"),
    ("2001:2::/48", "Benchmarking (RFC 5180)"),
    ("2001:db8::/32", "Documentation (RFC 3849)"),
    ("2001:10::/28", "ORCHID (RFC 4843)"),
    ("2002::/16", "6to4"),
    ("fc00::/7", "Unique-Local (RFC 4193)"),
    ("fe80::/10", "Link-Local (RFC 4291)"),
    ("ff00::/8", "Multicast (RFC 4291)"),
];

/// IP Intelligence Result
#[derive(Debug, Clone)]
pub struct IpIntelResult {
    pub ip: String,
    pub version: IpVersion,
    pub is_bogon: bool,
    pub bogon_reason: Option<String>,
    pub classification: IpClassification,
    pub reverse_dns: Option<String>,
    pub asn: Option<AsnInfo>,
    pub geolocation: Option<GeoInfo>,
}

/// IP Version
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
}

impl std::fmt::Display for IpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpVersion::V4 => write!(f, "IPv4"),
            IpVersion::V6 => write!(f, "IPv6"),
        }
    }
}

/// IP Classification
#[derive(Debug, Clone, PartialEq)]
pub enum IpClassification {
    /// Globally routable public IP
    Public,
    /// Private network (RFC 1918)
    Private,
    /// Reserved for special use
    Reserved,
    /// Loopback address
    Loopback,
    /// Link-local address
    LinkLocal,
    /// Multicast address
    Multicast,
    /// Documentation/test address
    Documentation,
    /// Carrier-grade NAT
    CarrierGradeNat,
    /// Benchmarking
    Benchmarking,
    /// Unknown/unclassified
    Unknown,
}

impl std::fmt::Display for IpClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpClassification::Public => write!(f, "Public (Globally Routable)"),
            IpClassification::Private => write!(f, "Private (RFC 1918)"),
            IpClassification::Reserved => write!(f, "Reserved"),
            IpClassification::Loopback => write!(f, "Loopback"),
            IpClassification::LinkLocal => write!(f, "Link-Local"),
            IpClassification::Multicast => write!(f, "Multicast"),
            IpClassification::Documentation => write!(f, "Documentation/Test"),
            IpClassification::CarrierGradeNat => write!(f, "Carrier-Grade NAT (RFC 6598)"),
            IpClassification::Benchmarking => write!(f, "Benchmarking"),
            IpClassification::Unknown => write!(f, "Unknown"),
        }
    }
}

/// ASN Information (placeholder for future enhancement)
#[derive(Debug, Clone)]
pub struct AsnInfo {
    pub asn: u32,
    pub name: String,
    pub country: Option<String>,
}

/// Geolocation Information (placeholder for future enhancement)
#[derive(Debug, Clone)]
pub struct GeoInfo {
    pub country: String,
    pub country_code: String,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// IP Intelligence Client
pub struct IpIntel;

impl IpIntel {
    pub fn new() -> Self {
        Self
    }

    /// Analyze an IP address
    pub fn analyze(&self, ip_str: &str) -> Result<IpIntelResult, String> {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| format!("Invalid IP address: {}", ip_str))?;

        let (version, is_bogon, bogon_reason, classification) = match ip {
            IpAddr::V4(ipv4) => {
                let (bogon, reason) = self.check_ipv4_bogon(ipv4);
                let class = self.classify_ipv4(ipv4);
                (IpVersion::V4, bogon, reason, class)
            }
            IpAddr::V6(ipv6) => {
                let (bogon, reason) = self.check_ipv6_bogon(ipv6);
                let class = self.classify_ipv6(ipv6);
                (IpVersion::V6, bogon, reason, class)
            }
        };

        Ok(IpIntelResult {
            ip: ip_str.to_string(),
            version,
            is_bogon,
            bogon_reason,
            classification,
            reverse_dns: None, // Could be enhanced with actual rDNS lookup
            asn: None,         // Could be enhanced with ASN lookup
            geolocation: None, // Could be enhanced with GeoIP
        })
    }

    /// Check if IPv4 is a bogon
    fn check_ipv4_bogon(&self, ip: Ipv4Addr) -> (bool, Option<String>) {
        let ip_u32 = u32::from(ip);

        for (cidr, description, start, end) in IPV4_BOGONS {
            if ip_u32 >= *start && ip_u32 <= *end {
                return (true, Some(format!("{} - {}", cidr, description)));
            }
        }

        (false, None)
    }

    /// Check if IPv6 is a bogon
    fn check_ipv6_bogon(&self, ip: Ipv6Addr) -> (bool, Option<String>) {
        let segments = ip.segments();

        // Check specific patterns
        // Unspecified
        if ip.is_unspecified() {
            return (true, Some("::/128 - Unspecified Address".to_string()));
        }

        // Loopback
        if ip.is_loopback() {
            return (true, Some("::1/128 - Loopback Address".to_string()));
        }

        // Link-local (fe80::/10)
        if (segments[0] & 0xffc0) == 0xfe80 {
            return (true, Some("fe80::/10 - Link-Local".to_string()));
        }

        // Unique-local (fc00::/7)
        if (segments[0] & 0xfe00) == 0xfc00 {
            return (true, Some("fc00::/7 - Unique-Local (RFC 4193)".to_string()));
        }

        // Multicast (ff00::/8)
        if (segments[0] & 0xff00) == 0xff00 {
            return (true, Some("ff00::/8 - Multicast".to_string()));
        }

        // Documentation (2001:db8::/32)
        if segments[0] == 0x2001 && segments[1] == 0x0db8 {
            return (
                true,
                Some("2001:db8::/32 - Documentation (RFC 3849)".to_string()),
            );
        }

        // Teredo (2001::/32)
        if segments[0] == 0x2001 && segments[1] == 0x0000 {
            return (true, Some("2001::/32 - Teredo".to_string()));
        }

        // 6to4 (2002::/16)
        if segments[0] == 0x2002 {
            return (true, Some("2002::/16 - 6to4".to_string()));
        }

        // Discard (100::/64)
        if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
            return (true, Some("100::/64 - Discard-Only (RFC 6666)".to_string()));
        }

        (false, None)
    }

    /// Classify IPv4 address
    fn classify_ipv4(&self, ip: Ipv4Addr) -> IpClassification {
        if ip.is_loopback() {
            return IpClassification::Loopback;
        }
        if ip.is_private() {
            return IpClassification::Private;
        }
        if ip.is_link_local() {
            return IpClassification::LinkLocal;
        }
        if ip.is_multicast() {
            return IpClassification::Multicast;
        }
        if ip.is_broadcast() {
            return IpClassification::Reserved;
        }
        if ip.is_documentation() {
            return IpClassification::Documentation;
        }
        if ip.is_unspecified() {
            return IpClassification::Reserved;
        }

        // Check for specific ranges
        let octets = ip.octets();

        // Carrier-grade NAT (100.64.0.0/10)
        if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
            return IpClassification::CarrierGradeNat;
        }

        // Benchmarking (198.18.0.0/15)
        if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
            return IpClassification::Benchmarking;
        }

        // Reserved (240.0.0.0/4)
        if octets[0] >= 240 {
            return IpClassification::Reserved;
        }

        // Class E (experimental) 240-255
        if octets[0] >= 240 {
            return IpClassification::Reserved;
        }

        IpClassification::Public
    }

    /// Classify IPv6 address
    fn classify_ipv6(&self, ip: Ipv6Addr) -> IpClassification {
        if ip.is_loopback() {
            return IpClassification::Loopback;
        }
        if ip.is_unspecified() {
            return IpClassification::Reserved;
        }
        if ip.is_multicast() {
            return IpClassification::Multicast;
        }

        let segments = ip.segments();

        // Link-local (fe80::/10)
        if (segments[0] & 0xffc0) == 0xfe80 {
            return IpClassification::LinkLocal;
        }

        // Unique-local (fc00::/7) - equivalent to private
        if (segments[0] & 0xfe00) == 0xfc00 {
            return IpClassification::Private;
        }

        // Documentation (2001:db8::/32)
        if segments[0] == 0x2001 && segments[1] == 0x0db8 {
            return IpClassification::Documentation;
        }

        // Global unicast (2000::/3)
        if (segments[0] & 0xe000) == 0x2000 {
            return IpClassification::Public;
        }

        IpClassification::Unknown
    }

    /// Get all bogon ranges (for display purposes)
    pub fn get_ipv4_bogon_ranges() -> Vec<(&'static str, &'static str)> {
        IPV4_BOGONS
            .iter()
            .map(|(cidr, desc, _, _)| (*cidr, *desc))
            .collect()
    }

    /// Get all IPv6 bogon ranges (for display purposes)
    pub fn get_ipv6_bogon_ranges() -> Vec<(&'static str, &'static str)> {
        IPV6_BOGONS.to_vec()
    }
}

impl Default for IpIntel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bogon_detection_private() {
        let intel = IpIntel::new();
        let result = intel.analyze("10.0.0.1").unwrap();
        assert!(result.is_bogon);
        assert_eq!(result.classification, IpClassification::Private);
    }

    #[test]
    fn test_bogon_detection_loopback() {
        let intel = IpIntel::new();
        let result = intel.analyze("127.0.0.1").unwrap();
        assert!(result.is_bogon);
        assert_eq!(result.classification, IpClassification::Loopback);
    }

    #[test]
    fn test_public_ip() {
        let intel = IpIntel::new();
        let result = intel.analyze("8.8.8.8").unwrap();
        assert!(!result.is_bogon);
        assert_eq!(result.classification, IpClassification::Public);
    }

    #[test]
    fn test_cgnat() {
        let intel = IpIntel::new();
        let result = intel.analyze("100.64.0.1").unwrap();
        assert!(result.is_bogon);
        assert_eq!(result.classification, IpClassification::CarrierGradeNat);
    }

    #[test]
    fn test_ipv6_loopback() {
        let intel = IpIntel::new();
        let result = intel.analyze("::1").unwrap();
        assert!(result.is_bogon);
        assert_eq!(result.classification, IpClassification::Loopback);
    }

    #[test]
    fn test_ipv6_public() {
        let intel = IpIntel::new();
        let result = intel.analyze("2607:f8b0:4004:800::200e").unwrap();
        assert!(!result.is_bogon);
        assert_eq!(result.classification, IpClassification::Public);
    }
}
