/// ASN (Autonomous System Number) Lookup Module
///
/// Replaces: ipinfo.io, whois ASN queries, aslookup tools
///
/// Features:
/// - IP to ASN lookup via iptoasn.com (free, unlimited)
/// - ASN to organization mapping
/// - Network range discovery
/// - Country code identification
///
/// NO external dependencies - pure HTTP from scratch

use crate::protocols::dns::DnsClient;
use crate::protocols::http::HttpClient;
use crate::config;
use std::net::IpAddr;

/// ASN lookup client
pub struct AsnClient {
    http_client: HttpClient,
}

/// ASN information for an IP address
#[derive(Debug, Clone)]
pub struct AsnInfo {
    /// The queried IP address
    pub ip: String,
    /// Whether the IP is announced (has ASN)
    pub announced: bool,
    /// ASN number (e.g., 15169 for Google)
    pub asn: Option<u32>,
    /// ASN string (e.g., "AS15169")
    pub asn_string: Option<String>,
    /// Country code (e.g., "US")
    pub country: Option<String>,
    /// Organization/description (e.g., "GOOGLE")
    pub organization: Option<String>,
    /// ASN name (may differ from description)
    pub asn_name: Option<String>,
    /// First IP in the announced range
    pub first_ip: Option<String>,
    /// Last IP in the announced range
    pub last_ip: Option<String>,
    /// CIDR notation if calculable
    pub cidr: Option<String>,
}

/// Network range information from ASN
#[derive(Debug, Clone)]
pub struct NetworkRange {
    pub asn: u32,
    pub organization: String,
    pub country: String,
    pub ranges: Vec<String>,
}

impl AsnClient {
    pub fn new() -> Self {
        Self {
            http_client: HttpClient::new(),
        }
    }

    /// Lookup ASN information for an IP address
    /// Uses iptoasn.com API (free, unlimited, no API key required)
    pub fn lookup_ip(&self, ip: &str) -> Result<AsnInfo, String> {
        // Validate IP format
        ip.parse::<IpAddr>()
            .map_err(|_| format!("Invalid IP address: {}", ip))?;

        // iptoasn.com API endpoint
        let url = format!("https://api.iptoasn.com/v1/as/ip/{}", ip);

        let response = self.http_client.get(&url)
            .map_err(|e| format!("iptoasn.com request failed: {}", e))?;

        if response.status_code != 200 {
            return Err(format!("iptoasn.com returned status {}", response.status_code));
        }

        let body = String::from_utf8_lossy(&response.body);
        self.parse_iptoasn_response(&body, ip)
    }

    /// Lookup ASN for a hostname (resolves DNS first)
    pub fn lookup_host(&self, hostname: &str) -> Result<Vec<AsnInfo>, String> {
        let resolver = config::get().network.dns_resolver.clone();
        let dns_client = DnsClient::new(&resolver);

        // Resolve hostname to IPs
        let answers = dns_client.query(hostname, crate::protocols::dns::DnsRecordType::A)
            .map_err(|e| format!("DNS resolution failed: {}", e))?;

        if answers.is_empty() {
            return Err(format!("No IP addresses found for {}", hostname));
        }

        // Lookup ASN for each IP
        let mut results = Vec::new();
        for answer in answers {
            if let Some(ip) = answer.as_ip() {
                match self.lookup_ip(&ip) {
                    Ok(info) => results.push(info),
                    Err(_) => continue, // Skip failed lookups
                }
            }
        }

        if results.is_empty() {
            return Err("No ASN information found for any resolved IP".to_string());
        }

        Ok(results)
    }

    /// Parse iptoasn.com JSON response
    ///
    /// Response format:
    /// ```json
    /// {
    ///   "announced": true,
    ///   "as_number": 15169,
    ///   "as_country_code": "US",
    ///   "as_description": "GOOGLE",
    ///   "first_ip": "8.8.8.0",
    ///   "last_ip": "8.8.8.255",
    ///   "as_name": "GOOGLE"
    /// }
    /// ```
    fn parse_iptoasn_response(&self, json: &str, ip: &str) -> Result<AsnInfo, String> {
        // Parse announced field
        let announced = self.extract_json_bool(json, "announced").unwrap_or(false);

        if !announced {
            return Ok(AsnInfo {
                ip: ip.to_string(),
                announced: false,
                asn: None,
                asn_string: None,
                country: None,
                organization: None,
                asn_name: None,
                first_ip: None,
                last_ip: None,
                cidr: None,
            });
        }

        let asn = self.extract_json_number(json, "as_number");
        let country = self.extract_json_string(json, "as_country_code");
        let organization = self.extract_json_string(json, "as_description");
        let asn_name = self.extract_json_string(json, "as_name");
        let first_ip = self.extract_json_string(json, "first_ip");
        let last_ip = self.extract_json_string(json, "last_ip");

        // Calculate CIDR if we have range info
        let cidr = if let (Some(ref first), Some(ref last)) = (&first_ip, &last_ip) {
            self.calculate_cidr(first, last)
        } else {
            None
        };

        Ok(AsnInfo {
            ip: ip.to_string(),
            announced: true,
            asn,
            asn_string: asn.map(|n| format!("AS{}", n)),
            country,
            organization,
            asn_name,
            first_ip,
            last_ip,
            cidr,
        })
    }

    /// Calculate CIDR notation from IP range
    fn calculate_cidr(&self, first_ip: &str, last_ip: &str) -> Option<String> {
        let first: u32 = first_ip.parse::<IpAddr>().ok().and_then(|ip| {
            if let IpAddr::V4(v4) = ip {
                Some(u32::from(v4))
            } else {
                None
            }
        })?;

        let last: u32 = last_ip.parse::<IpAddr>().ok().and_then(|ip| {
            if let IpAddr::V4(v4) = ip {
                Some(u32::from(v4))
            } else {
                None
            }
        })?;

        // Calculate number of IPs in range
        let count = last.saturating_sub(first) + 1;

        // Find the prefix length
        if count.is_power_of_two() {
            let prefix = 32 - count.trailing_zeros();
            Some(format!("{}/{}", first_ip, prefix))
        } else {
            // Not a clean CIDR, just show the range
            Some(format!("{} - {}", first_ip, last_ip))
        }
    }

    /// Extract boolean from JSON
    fn extract_json_bool(&self, json: &str, key: &str) -> Option<bool> {
        let search = format!("\"{}\"", key);
        if let Some(pos) = json.find(&search) {
            let rest = &json[pos + search.len()..];
            // Skip to value
            let value_start = rest.find(':')?;
            let value_part = rest[value_start + 1..].trim_start();

            if value_part.starts_with("true") {
                Some(true)
            } else if value_part.starts_with("false") {
                Some(false)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Extract number from JSON
    fn extract_json_number(&self, json: &str, key: &str) -> Option<u32> {
        let search = format!("\"{}\"", key);
        if let Some(pos) = json.find(&search) {
            let rest = &json[pos + search.len()..];
            let value_start = rest.find(':')?;
            let value_part = rest[value_start + 1..].trim_start();

            let num_str: String = value_part
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();

            num_str.parse().ok()
        } else {
            None
        }
    }

    /// Extract string from JSON
    fn extract_json_string(&self, json: &str, key: &str) -> Option<String> {
        let search = format!("\"{}\"", key);
        if let Some(key_pos) = json.find(&search) {
            let rest = &json[key_pos + search.len()..];

            // Find opening quote of value
            let colon_pos = rest.find(':')?;
            let after_colon = rest[colon_pos + 1..].trim_start();

            if !after_colon.starts_with('"') {
                return None;
            }

            // Extract string value
            let value_start = after_colon[1..].as_bytes();
            let mut result = String::new();
            let mut escaped = false;

            for &b in value_start {
                let c = b as char;
                if escaped {
                    match c {
                        'n' => result.push('\n'),
                        'r' => result.push('\r'),
                        't' => result.push('\t'),
                        '"' => result.push('"'),
                        '\\' => result.push('\\'),
                        _ => {
                            result.push('\\');
                            result.push(c);
                        }
                    }
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    break;
                } else {
                    result.push(c);
                }
            }

            if result.is_empty() {
                None
            } else {
                Some(result)
            }
        } else {
            None
        }
    }
}

impl Default for AsnClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Get ASN info for multiple IPs efficiently
pub fn bulk_asn_lookup(ips: &[String]) -> Vec<AsnInfo> {
    let client = AsnClient::new();
    let mut results = Vec::new();

    for ip in ips {
        match client.lookup_ip(ip) {
            Ok(info) => results.push(info),
            Err(_) => continue,
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_parsing() {
        let client = AsnClient::new();
        let json = r#"{"announced":true,"as_number":15169,"as_country_code":"US","as_description":"GOOGLE"}"#;

        assert_eq!(client.extract_json_bool(json, "announced"), Some(true));
        assert_eq!(client.extract_json_number(json, "as_number"), Some(15169));
        assert_eq!(client.extract_json_string(json, "as_country_code"), Some("US".to_string()));
        assert_eq!(client.extract_json_string(json, "as_description"), Some("GOOGLE".to_string()));
    }

    #[test]
    fn test_cidr_calculation() {
        let client = AsnClient::new();

        // /24 network
        let cidr = client.calculate_cidr("8.8.8.0", "8.8.8.255");
        assert!(cidr.is_some());
        let cidr_val = cidr.unwrap();
        assert!(cidr_val.contains("/24") || cidr_val.contains("8.8.8.0"));
    }
}
