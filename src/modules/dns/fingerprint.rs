/// DNS Fingerprinting & Intelligence Analysis
///
/// Extract intelligence from DNS responses:
/// - Response timing analysis
/// - Open resolver detection
/// - Wildcard DNS detection
/// - CDN detection via CNAME chains
///
/// Note: This is a simplified version that works with our current DNS client.
/// Full fingerprinting (server software detection, censorship detection) will
/// require parsing raw DNS packets to access flags, TTL, and other metadata.
use crate::protocols::dns::{DnsClient, DnsRecordType};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct DNSIntelligence {
    pub response_time: Duration,
    pub answers_count: usize,
    pub query_successful: bool,
}

impl DNSIntelligence {
    /// Analyze DNS server response characteristics
    pub fn analyze(server: &str, domain: &str, record_type: DnsRecordType) -> Self {
        let client = DnsClient::new(server);
        let start = Instant::now();

        let result = client.query(domain, record_type);
        let response_time = start.elapsed();

        match result {
            Ok(answers) => DNSIntelligence {
                response_time,
                answers_count: answers.len(),
                query_successful: true,
            },
            Err(_) => DNSIntelligence {
                response_time,
                answers_count: 0,
                query_successful: false,
            },
        }
    }

    /// Test if DNS server is an open resolver
    /// An open resolver responds to queries for domains it's not authoritative for
    pub fn is_open_resolver(server: &str) -> bool {
        let client = DnsClient::new(server);

        // Try to resolve a well-known external domain
        match client.query("google.com", DnsRecordType::A) {
            Ok(answers) => !answers.is_empty(),
            Err(_) => false,
        }
    }

    /// Detect wildcard DNS (returns IP for any subdomain)
    pub fn has_wildcard_dns(domain: &str, server: &str) -> bool {
        let client = DnsClient::new(server);

        // Generate a random subdomain that shouldn't exist
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let random_subdomain = format!("nonexistent-test-{}.{}", timestamp, domain);

        // If a non-existent subdomain resolves, wildcard DNS is in use
        match client.query(&random_subdomain, DnsRecordType::A) {
            Ok(answers) => !answers.is_empty(),
            Err(_) => false,
        }
    }

    /// Detect CDN by analyzing CNAME records
    pub fn detect_cdn(domain: &str, server: &str) -> Option<String> {
        let client = DnsClient::new(server);

        // Try to get CNAME record
        let answers = client.query(domain, DnsRecordType::CNAME).ok()?;

        if answers.is_empty() {
            return None;
        }

        // Check first answer for known CDN patterns
        // In a real implementation, we'd parse the RDATA properly
        // For now, we return a placeholder
        Some("CDN detection requires full DNS packet parsing".to_string())
    }

    /// Estimate geographic proximity based on response time
    pub fn estimate_distance(&self) -> DistanceEstimate {
        let ms = self.response_time.as_millis();

        if ms < 10 {
            DistanceEstimate::VeryClose // Same region/datacenter
        } else if ms < 50 {
            DistanceEstimate::SameCountry // Same country
        } else if ms < 150 {
            DistanceEstimate::SameContinent // Same continent
        } else {
            DistanceEstimate::Remote // Different continent
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum DistanceEstimate {
    VeryClose,     // < 10ms
    SameCountry,   // 10-50ms
    SameContinent, // 50-150ms
    Remote,        // > 150ms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distance_estimate() {
        let intel = DNSIntelligence {
            response_time: Duration::from_millis(5),
            answers_count: 1,
            query_successful: true,
        };
        assert_eq!(intel.estimate_distance(), DistanceEstimate::VeryClose);

        let intel2 = DNSIntelligence {
            response_time: Duration::from_millis(100),
            answers_count: 1,
            query_successful: true,
        };
        assert_eq!(intel2.estimate_distance(), DistanceEstimate::SameContinent);
    }

    #[test]
    fn test_analyze_google_dns() {
        // Test with Google DNS (8.8.8.8)
        let intel = DNSIntelligence::analyze("8.8.8.8", "google.com", DnsRecordType::A);

        assert!(intel.query_successful);
        assert!(intel.answers_count > 0);
        assert!(intel.response_time.as_millis() < 1000); // Should respond within 1s
    }

    #[test]
    fn test_open_resolver() {
        // Google DNS should be an open resolver
        assert!(DNSIntelligence::is_open_resolver("8.8.8.8"));
    }
}
