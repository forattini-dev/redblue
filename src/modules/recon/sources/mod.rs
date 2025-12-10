/// Subdomain Data Source Abstraction Layer
///
/// This module provides a unified interface for multiple subdomain enumeration
/// data sources, enabling extensible passive and active reconnaissance.
///
/// Implements task 1.2.1: Create data source abstraction interface
///
/// Sources are categorized as:
/// - Passive: No direct target interaction (CT logs, Wayback, DNS DBs)
/// - Active: Direct target interaction (DNS bruteforce, zone transfers)
///
/// NO external dependencies - all implemented from scratch

use std::collections::HashSet;
use std::time::Duration;

/// Result from a subdomain data source query
#[derive(Debug, Clone)]
pub struct SubdomainRecord {
    /// The discovered subdomain
    pub subdomain: String,
    /// IP addresses if resolved
    pub ips: Vec<String>,
    /// Source that discovered this subdomain
    pub source: SourceType,
    /// When the record was discovered (optional)
    pub discovered_at: Option<String>,
    /// Additional metadata from the source
    pub metadata: RecordMetadata,
}

/// Source type classification
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourceType {
    /// Certificate Transparency logs (crt.sh, certspotter, censys)
    CertificateTransparency(String), // provider name
    /// Passive DNS databases (VirusTotal, SecurityTrails, etc.)
    PassiveDns(String),
    /// Web archives (Wayback Machine, Common Crawl)
    WebArchive(String),
    /// Search engine indexes (Google, Bing)
    SearchEngine(String),
    /// Code repositories (GitHub, GitLab)
    CodeRepository(String),
    /// Threat intelligence feeds
    ThreatIntel(String),
    /// DNS bruteforce
    DnsBruteforce,
    /// Zone transfer (AXFR)
    ZoneTransfer,
    /// Manual entry
    Manual,
}

impl std::fmt::Display for SourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceType::CertificateTransparency(p) => write!(f, "CT:{}", p),
            SourceType::PassiveDns(p) => write!(f, "PDNS:{}", p),
            SourceType::WebArchive(p) => write!(f, "Archive:{}", p),
            SourceType::SearchEngine(p) => write!(f, "Search:{}", p),
            SourceType::CodeRepository(p) => write!(f, "Code:{}", p),
            SourceType::ThreatIntel(p) => write!(f, "Intel:{}", p),
            SourceType::DnsBruteforce => write!(f, "DNS-BF"),
            SourceType::ZoneTransfer => write!(f, "AXFR"),
            SourceType::Manual => write!(f, "Manual"),
        }
    }
}

/// Additional metadata from data sources
#[derive(Debug, Clone, Default)]
pub struct RecordMetadata {
    /// Certificate info if from CT logs
    pub cert_issuer: Option<String>,
    pub cert_not_before: Option<String>,
    pub cert_not_after: Option<String>,
    /// Archive snapshot date
    pub archive_date: Option<String>,
    /// HTTP status if from web archive
    pub http_status: Option<u16>,
    /// Additional tags
    pub tags: Vec<String>,
}

/// Source category for filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCategory {
    /// No direct target interaction
    Passive,
    /// Direct target interaction
    Active,
    /// All sources
    All,
}

/// Configuration for a data source
#[derive(Debug, Clone)]
pub struct SourceConfig {
    /// Whether this source is enabled
    pub enabled: bool,
    /// API key if required
    pub api_key: Option<String>,
    /// Rate limit (requests per minute)
    pub rate_limit: Option<u32>,
    /// Request timeout
    pub timeout: Duration,
    /// Custom endpoint URL (for self-hosted instances)
    pub custom_url: Option<String>,
}

impl Default for SourceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            api_key: None,
            rate_limit: None,
            timeout: Duration::from_secs(30),
            custom_url: None,
        }
    }
}

/// Trait for subdomain data sources
///
/// Each source implements this trait to provide subdomain enumeration
pub trait SubdomainSource: Send + Sync {
    /// Unique identifier for this source
    fn name(&self) -> &str;

    /// Human-readable description
    fn description(&self) -> &str;

    /// Source category (passive/active)
    fn category(&self) -> SourceCategory;

    /// Whether an API key is required
    fn requires_api_key(&self) -> bool;

    /// Query the source for subdomains
    fn query(&self, domain: &str) -> Result<Vec<SubdomainRecord>, SourceError>;

    /// Check if the source is available/configured
    fn is_available(&self) -> bool {
        true
    }

    /// Get the source type
    fn source_type(&self) -> SourceType;
}

/// Error types for data sources
#[derive(Debug)]
pub enum SourceError {
    /// Network/connection error
    NetworkError(String),
    /// Rate limited by the source
    RateLimited(Duration),
    /// Invalid API key or authentication
    AuthenticationError(String),
    /// Source returned invalid data
    ParseError(String),
    /// Source is temporarily unavailable
    Unavailable(String),
    /// Request timed out
    Timeout,
    /// API key required but not configured
    ApiKeyRequired,
    /// Generic error
    Other(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceError::NetworkError(e) => write!(f, "Network error: {}", e),
            SourceError::RateLimited(d) => write!(f, "Rate limited, retry after {:?}", d),
            SourceError::AuthenticationError(e) => write!(f, "Authentication error: {}", e),
            SourceError::ParseError(e) => write!(f, "Parse error: {}", e),
            SourceError::Unavailable(e) => write!(f, "Source unavailable: {}", e),
            SourceError::Timeout => write!(f, "Request timed out"),
            SourceError::ApiKeyRequired => write!(f, "API key required"),
            SourceError::Other(e) => write!(f, "{}", e),
        }
    }
}

/// Aggregated results from multiple sources
#[derive(Debug, Default)]
pub struct AggregatedResults {
    /// All discovered subdomains (deduplicated)
    pub subdomains: HashSet<String>,
    /// Full records with metadata
    pub records: Vec<SubdomainRecord>,
    /// Source statistics
    pub source_stats: Vec<SourceStats>,
    /// Errors encountered
    pub errors: Vec<(String, SourceError)>,
}

/// Statistics for a single source query
#[derive(Debug, Clone)]
pub struct SourceStats {
    pub source_name: String,
    pub source_type: SourceType,
    pub subdomains_found: usize,
    pub duration_ms: u64,
    pub success: bool,
    pub error: Option<String>,
}

impl AggregatedResults {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add results from a source
    pub fn add_results(&mut self, records: Vec<SubdomainRecord>, stats: SourceStats) {
        for record in records {
            self.subdomains.insert(record.subdomain.clone());
            self.records.push(record);
        }
        self.source_stats.push(stats);
    }

    /// Add an error
    pub fn add_error(&mut self, source_name: &str, error: SourceError) {
        self.errors.push((source_name.to_string(), error));
    }

    /// Get unique subdomain count
    pub fn unique_count(&self) -> usize {
        self.subdomains.len()
    }

    /// Get sorted list of subdomains
    pub fn sorted_subdomains(&self) -> Vec<String> {
        let mut subs: Vec<String> = self.subdomains.iter().cloned().collect();
        subs.sort();
        subs
    }

    /// Merge with another result set
    pub fn merge(&mut self, other: AggregatedResults) {
        for sub in other.subdomains {
            self.subdomains.insert(sub);
        }
        self.records.extend(other.records);
        self.source_stats.extend(other.source_stats);
        self.errors.extend(other.errors);
    }
}

// Source implementations
pub mod crtsh;
pub mod certspotter;
pub mod hackertarget;
pub mod wayback;
pub mod alienvault;
pub mod urlscan;
pub mod rapiddns;
pub mod dnsdumpster;
pub mod threatcrowd;
pub mod bufferover;
pub mod commoncrawl;
pub mod github;
pub mod shodan;

// Re-export sources
pub use crtsh::CrtShSource;
pub use certspotter::CertSpotterSource;
pub use hackertarget::HackerTargetSource;
pub use wayback::WaybackSource;
pub use alienvault::AlienVaultSource;
pub use urlscan::UrlScanSource;
pub use rapiddns::RapidDnsSource;
pub use dnsdumpster::DnsDumpsterSource;
pub use threatcrowd::ThreatCrowdSource;
pub use bufferover::BufferOverSource;
pub use commoncrawl::CommonCrawlSource;
pub use github::GitHubSource;
pub use shodan::ShodanSource;

/// Create all available sources with default configuration
pub fn create_all_sources() -> Vec<Box<dyn SubdomainSource>> {
    vec![
        // Certificate Transparency sources
        Box::new(CrtShSource::new()),
        Box::new(CertSpotterSource::new()),
        // Passive DNS sources
        Box::new(HackerTargetSource::new()),
        Box::new(RapidDnsSource::new()),
        Box::new(DnsDumpsterSource::new()),
        Box::new(BufferOverSource::new()),
        Box::new(UrlScanSource::new()),
        // Web archive sources
        Box::new(WaybackSource::new()),
        Box::new(CommonCrawlSource::new()),
        // Threat intelligence sources
        Box::new(AlienVaultSource::new()),
        Box::new(ThreatCrowdSource::new()),
        // Code repository sources
        Box::new(GitHubSource::new()),
        // API-key required (will be skipped if no key)
        Box::new(ShodanSource::new()),
    ]
}

/// Create only passive sources
pub fn create_passive_sources() -> Vec<Box<dyn SubdomainSource>> {
    create_all_sources()
        .into_iter()
        .filter(|s| s.category() == SourceCategory::Passive)
        .collect()
}

/// Query multiple sources in parallel and aggregate results
pub fn query_all_sources(
    domain: &str,
    sources: &[Box<dyn SubdomainSource>],
    category_filter: SourceCategory,
) -> AggregatedResults {
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    let results = Arc::new(Mutex::new(AggregatedResults::new()));
    let mut handles = vec![];

    for source in sources.iter() {
        // Filter by category
        if category_filter != SourceCategory::All && source.category() != category_filter {
            continue;
        }

        // Check availability
        if !source.is_available() {
            if let Ok(mut r) = results.lock() {
                r.add_error(source.name(), SourceError::Unavailable("Not configured".into()));
            }
            continue;
        }

        let domain = domain.to_string();
        let source_name = source.name().to_string();
        let source_type = source.source_type();
        let results = Arc::clone(&results);

        // Note: We can't move the source into the thread since it's behind a reference.
        // In a real impl, we'd clone or use Arc<dyn SubdomainSource>
        // For now, query sequentially
        let start = Instant::now();
        let query_result = source.query(&domain);
        let duration_ms = start.elapsed().as_millis() as u64;

        match query_result {
            Ok(records) => {
                let stats = SourceStats {
                    source_name: source_name.clone(),
                    source_type,
                    subdomains_found: records.len(),
                    duration_ms,
                    success: true,
                    error: None,
                };
                if let Ok(mut r) = results.lock() {
                    r.add_results(records, stats);
                }
            }
            Err(e) => {
                let stats = SourceStats {
                    source_name: source_name.clone(),
                    source_type,
                    subdomains_found: 0,
                    duration_ms,
                    success: false,
                    error: Some(e.to_string()),
                };
                if let Ok(mut r) = results.lock() {
                    r.source_stats.push(stats);
                    r.add_error(&source_name, e);
                }
            }
        }
    }

    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }

    Arc::try_unwrap(results)
        .unwrap_or_else(|arc| (*arc.lock().unwrap()).clone())
}

impl Clone for AggregatedResults {
    fn clone(&self) -> Self {
        Self {
            subdomains: self.subdomains.clone(),
            records: self.records.clone(),
            source_stats: self.source_stats.clone(),
            errors: self.errors.iter().map(|(s, e)| (s.clone(), SourceError::Other(e.to_string()))).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_type_display() {
        let ct = SourceType::CertificateTransparency("crt.sh".into());
        assert_eq!(format!("{}", ct), "CT:crt.sh");

        let pdns = SourceType::PassiveDns("virustotal".into());
        assert_eq!(format!("{}", pdns), "PDNS:virustotal");
    }

    #[test]
    fn test_aggregated_results() {
        let mut results = AggregatedResults::new();

        let record = SubdomainRecord {
            subdomain: "www.example.com".into(),
            ips: vec!["1.2.3.4".into()],
            source: SourceType::CertificateTransparency("crt.sh".into()),
            discovered_at: None,
            metadata: RecordMetadata::default(),
        };

        let stats = SourceStats {
            source_name: "crt.sh".into(),
            source_type: SourceType::CertificateTransparency("crt.sh".into()),
            subdomains_found: 1,
            duration_ms: 100,
            success: true,
            error: None,
        };

        results.add_results(vec![record], stats);
        assert_eq!(results.unique_count(), 1);
    }
}
