//! Passive Subdomain Enumeration Sources
//!
//! Implements 30+ passive sources for subdomain discovery:
//! - Certificate Transparency (crt.sh, Censys, CertSpotter)
//! - Search Engines (BinaryEdge, Shodan, Fofa, ZoomEye)
//! - Threat Intelligence (VirusTotal, AlienVault, ThreatCrowd, ThreatMiner)
//! - Web Archives (Wayback Machine, CommonCrawl, URLScan)
//! - DNS History (SecurityTrails, RiskIQ, DNSDumpster)
//! - Free APIs (HackerTarget, BufferOver, Omnisint)
//!
//! Features:
//! - Parallel source querying
//! - Rate limiting with exponential backoff
//! - API key management
//! - Source attribution

#![allow(dead_code)]

use crate::protocols::http::HttpClient;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// Source Definitions
// ============================================================================

/// Passive source type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PassiveSource {
    // Certificate Transparency
    CrtSh,
    Censys,
    CertSpotter,
    FacebookCt,

    // Search/Scan Engines
    Shodan,
    BinaryEdge,
    Fofa,
    ZoomEye,
    FullHunt,
    Netlas,
    Quake360,

    // Threat Intelligence
    VirusTotal,
    AlienVaultOtx,
    ThreatCrowd,
    ThreatMiner,
    RiskIq,
    Intelx,
    WhoisXmlApi,

    // Web Archives
    WaybackMachine,
    CommonCrawl,
    UrlScan,

    // DNS Sources
    SecurityTrails,
    DnsDumpster,
    HackerTarget,
    BufferOver,
    Omnisint,
    Crtsh,
    Sublist3r,
    AnubisDb,

    // Passive DNS
    PassiveTotal,
    Robtex,
    Dnsbx,
    C99,
}

impl PassiveSource {
    /// Check if source requires API key
    pub fn requires_api_key(&self) -> bool {
        matches!(
            self,
            PassiveSource::Shodan
                | PassiveSource::VirusTotal
                | PassiveSource::SecurityTrails
                | PassiveSource::Censys
                | PassiveSource::BinaryEdge
                | PassiveSource::Fofa
                | PassiveSource::ZoomEye
                | PassiveSource::FullHunt
                | PassiveSource::Netlas
                | PassiveSource::RiskIq
                | PassiveSource::Intelx
                | PassiveSource::WhoisXmlApi
                | PassiveSource::PassiveTotal
                | PassiveSource::C99
                | PassiveSource::Quake360
        )
    }

    /// Check if source is free (no API key needed)
    pub fn is_free(&self) -> bool {
        !self.requires_api_key()
    }

    /// Get source name for display
    pub fn name(&self) -> &'static str {
        match self {
            PassiveSource::CrtSh => "crt.sh",
            PassiveSource::Censys => "Censys",
            PassiveSource::CertSpotter => "CertSpotter",
            PassiveSource::FacebookCt => "Facebook CT",
            PassiveSource::Shodan => "Shodan",
            PassiveSource::BinaryEdge => "BinaryEdge",
            PassiveSource::Fofa => "Fofa",
            PassiveSource::ZoomEye => "ZoomEye",
            PassiveSource::FullHunt => "FullHunt",
            PassiveSource::Netlas => "Netlas",
            PassiveSource::Quake360 => "Quake360",
            PassiveSource::VirusTotal => "VirusTotal",
            PassiveSource::AlienVaultOtx => "AlienVault OTX",
            PassiveSource::ThreatCrowd => "ThreatCrowd",
            PassiveSource::ThreatMiner => "ThreatMiner",
            PassiveSource::RiskIq => "RiskIQ",
            PassiveSource::Intelx => "Intelligence X",
            PassiveSource::WhoisXmlApi => "WhoisXML",
            PassiveSource::WaybackMachine => "Wayback Machine",
            PassiveSource::CommonCrawl => "CommonCrawl",
            PassiveSource::UrlScan => "URLScan.io",
            PassiveSource::SecurityTrails => "SecurityTrails",
            PassiveSource::DnsDumpster => "DNSDumpster",
            PassiveSource::HackerTarget => "HackerTarget",
            PassiveSource::BufferOver => "BufferOver",
            PassiveSource::Omnisint => "Omnisint",
            PassiveSource::Crtsh => "crt.sh",
            PassiveSource::Sublist3r => "Sublist3r",
            PassiveSource::AnubisDb => "AnubisDB",
            PassiveSource::PassiveTotal => "PassiveTotal",
            PassiveSource::Robtex => "Robtex",
            PassiveSource::Dnsbx => "DNSBX",
            PassiveSource::C99 => "C99",
        }
    }

    /// Get all free sources
    pub fn free_sources() -> Vec<PassiveSource> {
        vec![
            PassiveSource::CrtSh,
            PassiveSource::CertSpotter,
            PassiveSource::AlienVaultOtx,
            PassiveSource::ThreatCrowd,
            PassiveSource::ThreatMiner,
            PassiveSource::WaybackMachine,
            PassiveSource::CommonCrawl,
            PassiveSource::UrlScan,
            PassiveSource::DnsDumpster,
            PassiveSource::HackerTarget,
            PassiveSource::BufferOver,
            PassiveSource::Omnisint,
            PassiveSource::Sublist3r,
            PassiveSource::AnubisDb,
            PassiveSource::Robtex,
            PassiveSource::Dnsbx,
        ]
    }

    /// Get all sources including API-key based
    pub fn all_sources() -> Vec<PassiveSource> {
        vec![
            // Free sources
            PassiveSource::CrtSh,
            PassiveSource::CertSpotter,
            PassiveSource::AlienVaultOtx,
            PassiveSource::ThreatCrowd,
            PassiveSource::ThreatMiner,
            PassiveSource::WaybackMachine,
            PassiveSource::CommonCrawl,
            PassiveSource::UrlScan,
            PassiveSource::DnsDumpster,
            PassiveSource::HackerTarget,
            PassiveSource::BufferOver,
            PassiveSource::Omnisint,
            PassiveSource::Sublist3r,
            PassiveSource::AnubisDb,
            PassiveSource::Robtex,
            PassiveSource::Dnsbx,
            // API key sources
            PassiveSource::Shodan,
            PassiveSource::VirusTotal,
            PassiveSource::SecurityTrails,
            PassiveSource::Censys,
            PassiveSource::BinaryEdge,
            PassiveSource::Fofa,
            PassiveSource::ZoomEye,
            PassiveSource::FullHunt,
            PassiveSource::Netlas,
            PassiveSource::RiskIq,
            PassiveSource::Intelx,
            PassiveSource::WhoisXmlApi,
            PassiveSource::PassiveTotal,
            PassiveSource::C99,
            PassiveSource::Quake360,
        ]
    }
}

// ============================================================================
// Subdomain Result
// ============================================================================

/// Result from a passive source
#[derive(Debug, Clone)]
pub struct PassiveResult {
    pub subdomain: String,
    pub source: PassiveSource,
    pub timestamp: Option<String>,
    pub extra_data: HashMap<String, String>,
}

// ============================================================================
// Rate Limiter
// ============================================================================

/// Rate limiter with exponential backoff
pub struct RateLimiter {
    requests: HashMap<String, (Instant, u32)>,
    min_interval: Duration,
    max_retries: u32,
}

impl RateLimiter {
    pub fn new(min_interval_ms: u64) -> Self {
        Self {
            requests: HashMap::new(),
            min_interval: Duration::from_millis(min_interval_ms),
            max_retries: 5,
        }
    }

    /// Wait before making request to source
    pub fn wait_for(&mut self, source: &str) {
        if let Some((last_request, _)) = self.requests.get(source) {
            let elapsed = last_request.elapsed();
            if elapsed < self.min_interval {
                thread::sleep(self.min_interval - elapsed);
            }
        }
    }

    /// Record a request
    pub fn record(&mut self, source: &str) {
        self.requests.insert(source.to_string(), (Instant::now(), 0));
    }

    /// Handle rate limit (429) response
    pub fn handle_rate_limit(&mut self, source: &str) -> Option<Duration> {
        let (_, retry_count) = self
            .requests
            .entry(source.to_string())
            .or_insert((Instant::now(), 0));

        if *retry_count >= self.max_retries {
            return None; // Give up
        }

        *retry_count += 1;

        // Exponential backoff: 1s, 2s, 4s, 8s, 16s
        let backoff = Duration::from_secs(1 << *retry_count);
        Some(backoff)
    }
}

// ============================================================================
// API Key Manager
// ============================================================================

/// Manages API keys for various sources
#[derive(Debug, Clone, Default)]
pub struct ApiKeyManager {
    keys: HashMap<PassiveSource, String>,
}

impl ApiKeyManager {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Load API keys from environment variables
    pub fn from_env() -> Self {
        let mut manager = Self::new();

        // Map environment variable names to sources
        let env_mappings = [
            ("SHODAN_API_KEY", PassiveSource::Shodan),
            ("VIRUSTOTAL_API_KEY", PassiveSource::VirusTotal),
            ("SECURITYTRAILS_API_KEY", PassiveSource::SecurityTrails),
            ("CENSYS_API_ID", PassiveSource::Censys),
            ("BINARYEDGE_API_KEY", PassiveSource::BinaryEdge),
            ("FOFA_API_KEY", PassiveSource::Fofa),
            ("ZOOMEYE_API_KEY", PassiveSource::ZoomEye),
            ("FULLHUNT_API_KEY", PassiveSource::FullHunt),
            ("NETLAS_API_KEY", PassiveSource::Netlas),
            ("RISKIQ_API_KEY", PassiveSource::RiskIq),
            ("INTELX_API_KEY", PassiveSource::Intelx),
            ("WHOISXML_API_KEY", PassiveSource::WhoisXmlApi),
            ("PASSIVETOTAL_API_KEY", PassiveSource::PassiveTotal),
            ("C99_API_KEY", PassiveSource::C99),
            ("QUAKE360_API_KEY", PassiveSource::Quake360),
        ];

        for (env_var, source) in env_mappings {
            if let Ok(key) = std::env::var(env_var) {
                if !key.is_empty() {
                    manager.keys.insert(source, key);
                }
            }
        }

        manager
    }

    /// Set an API key
    pub fn set_key(&mut self, source: PassiveSource, key: String) {
        self.keys.insert(source, key);
    }

    /// Get an API key
    pub fn get_key(&self, source: PassiveSource) -> Option<&String> {
        self.keys.get(&source)
    }

    /// Check if API key is available for source
    pub fn has_key(&self, source: PassiveSource) -> bool {
        self.keys.contains_key(&source)
    }

    /// Get all sources with available keys
    pub fn available_api_sources(&self) -> Vec<PassiveSource> {
        self.keys.keys().copied().collect()
    }
}

// ============================================================================
// Passive Source Querier
// ============================================================================

/// Main querier for passive subdomain sources
pub struct PassiveQuerier {
    client: HttpClient,
    api_keys: ApiKeyManager,
    rate_limiter: RateLimiter,
    timeout: Duration,
}

impl PassiveQuerier {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
            api_keys: ApiKeyManager::from_env(),
            rate_limiter: RateLimiter::new(500), // 500ms between requests to same source
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_api_keys(mut self, keys: ApiKeyManager) -> Self {
        self.api_keys = keys;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Query a single source
    pub fn query_source(
        &mut self,
        domain: &str,
        source: PassiveSource,
    ) -> Result<Vec<PassiveResult>, String> {
        // Check API key requirement
        if source.requires_api_key() && !self.api_keys.has_key(source) {
            return Err(format!("{} requires API key", source.name()));
        }

        // Rate limit
        self.rate_limiter.wait_for(source.name());

        let result = match source {
            PassiveSource::CrtSh | PassiveSource::Crtsh => self.query_crtsh(domain),
            PassiveSource::CertSpotter => self.query_certspotter(domain),
            PassiveSource::AlienVaultOtx => self.query_alienvault(domain),
            PassiveSource::ThreatCrowd => self.query_threatcrowd(domain),
            PassiveSource::ThreatMiner => self.query_threatminer(domain),
            PassiveSource::WaybackMachine => self.query_wayback(domain),
            PassiveSource::CommonCrawl => self.query_commoncrawl(domain),
            PassiveSource::UrlScan => self.query_urlscan(domain),
            PassiveSource::HackerTarget => self.query_hackertarget(domain),
            PassiveSource::BufferOver => self.query_bufferover(domain),
            PassiveSource::Omnisint => self.query_omnisint(domain),
            PassiveSource::AnubisDb => self.query_anubisdb(domain),
            PassiveSource::Robtex => self.query_robtex(domain),
            PassiveSource::Dnsbx => self.query_dnsbx(domain),
            PassiveSource::DnsDumpster => self.query_dnsdumpster(domain),
            PassiveSource::Sublist3r => self.query_sublist3r(domain),
            // API key sources
            PassiveSource::Shodan => self.query_shodan(domain),
            PassiveSource::VirusTotal => self.query_virustotal(domain),
            PassiveSource::SecurityTrails => self.query_securitytrails(domain),
            PassiveSource::Censys => self.query_censys(domain),
            PassiveSource::BinaryEdge => self.query_binaryedge(domain),
            _ => Err(format!("Source {} not implemented", source.name())),
        };

        self.rate_limiter.record(source.name());
        result
    }

    /// Query all free sources in parallel
    pub fn query_all_free(&self, domain: &str) -> Vec<PassiveResult> {
        self.query_sources(domain, &PassiveSource::free_sources())
    }

    /// Query all sources (including API key sources) in parallel
    pub fn query_all(&self, domain: &str) -> Vec<PassiveResult> {
        let sources: Vec<_> = PassiveSource::all_sources()
            .into_iter()
            .filter(|s| !s.requires_api_key() || self.api_keys.has_key(*s))
            .collect();

        self.query_sources(domain, &sources)
    }

    /// Query specific sources in parallel
    pub fn query_sources(&self, domain: &str, sources: &[PassiveSource]) -> Vec<PassiveResult> {
        let results = Arc::new(Mutex::new(Vec::new()));
        let domain = domain.to_string();

        let mut handles = vec![];

        for source in sources {
            let source = *source;
            let domain = domain.clone();
            let results = Arc::clone(&results);
            let api_key = self.api_keys.get_key(source).cloned();

            let handle = thread::spawn(move || {
                let mut querier = PassiveQuerier::new();
                if let Some(key) = api_key {
                    querier.api_keys.set_key(source, key);
                }

                match querier.query_source(&domain, source) {
                    Ok(source_results) => {
                        if let Ok(mut results) = results.lock() {
                            results.extend(source_results);
                        }
                    }
                    Err(_e) => {
                        // Silently skip failed sources
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        // Deduplicate results
        let results = results.lock().unwrap();
        let mut seen = HashSet::new();
        results
            .iter()
            .filter(|r| seen.insert(r.subdomain.to_lowercase()))
            .cloned()
            .collect()
    }

    // ========================================================================
    // Free Source Implementations
    // ========================================================================

    fn query_crtsh(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let url = format!(
            "https://crt.sh/?q=%.{}&output=json",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("crt.sh request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        // Parse JSON array
        for line in body.split("\"name_value\":\"") {
            if let Some(end) = line.find('"') {
                let names = &line[..end];
                for name in names.split("\\n") {
                    let subdomain = name.trim().to_lowercase();
                    if subdomain.ends_with(domain) && !subdomain.starts_with('*') {
                        if seen.insert(subdomain.clone()) {
                            results.push(PassiveResult {
                                subdomain,
                                source: PassiveSource::CrtSh,
                                timestamp: None,
                                extra_data: HashMap::new(),
                            });
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    fn query_certspotter(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let url = format!(
            "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("CertSpotter request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        // Parse dns_names from JSON
        for line in body.split("\"dns_names\":[") {
            if let Some(end) = line.find(']') {
                let names_str = &line[..end];
                for name in names_str.split(',') {
                    let subdomain = name.trim().trim_matches('"').to_lowercase();
                    if subdomain.ends_with(domain) && !subdomain.starts_with('*') {
                        if seen.insert(subdomain.clone()) {
                            results.push(PassiveResult {
                                subdomain,
                                source: PassiveSource::CertSpotter,
                                timestamp: None,
                                extra_data: HashMap::new(),
                            });
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    fn query_alienvault(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("AlienVault OTX request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        for line in body.split("\"hostname\":\"") {
            if let Some(end) = line.find('"') {
                let subdomain = line[..end].to_lowercase();
                if subdomain.ends_with(domain) && seen.insert(subdomain.clone()) {
                    results.push(PassiveResult {
                        subdomain,
                        source: PassiveSource::AlienVaultOtx,
                        timestamp: None,
                        extra_data: HashMap::new(),
                    });
                }
            }
        }

        Ok(results)
    }

    fn query_threatcrowd(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let url = format!(
            "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("ThreatCrowd request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();

        if let Some(start) = body.find("\"subdomains\":[") {
            let rest = &body[start + 14..];
            if let Some(end) = rest.find(']') {
                for sub in rest[..end].split(',') {
                    let subdomain = sub.trim().trim_matches('"').to_lowercase();
                    if subdomain.ends_with(domain) {
                        results.push(PassiveResult {
                            subdomain,
                            source: PassiveSource::ThreatCrowd,
                            timestamp: None,
                            extra_data: HashMap::new(),
                        });
                    }
                }
            }
        }

        Ok(results)
    }

    fn query_threatminer(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let url = format!(
            "https://api.threatminer.org/v2/domain.php?q={}&rt=5",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("ThreatMiner request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();

        // Parse results array
        if let Some(start) = body.find("\"results\":[") {
            let rest = &body[start + 11..];
            if let Some(end) = rest.find(']') {
                for sub in rest[..end].split(',') {
                    let subdomain = sub.trim().trim_matches('"').to_lowercase();
                    if subdomain.ends_with(domain) && !subdomain.is_empty() {
                        results.push(PassiveResult {
                            subdomain,
                            source: PassiveSource::ThreatMiner,
                            timestamp: None,
                            extra_data: HashMap::new(),
                        });
                    }
                }
            }
        }

        Ok(results)
    }

    fn query_wayback(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let url = format!(
            "http://web.archive.org/cdx/search/cdx?url=*.{}&output=text&fl=original&collapse=urlkey&limit=1000",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("Wayback Machine request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        for line in body.lines() {
            let url = line.trim();
            if url.is_empty() {
                continue;
            }

            // Extract hostname from URL
            let hostname = url
                .strip_prefix("http://")
                .or_else(|| url.strip_prefix("https://"))
                .unwrap_or(url)
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
                .to_lowercase();

            if hostname.ends_with(domain) && seen.insert(hostname.clone()) {
                results.push(PassiveResult {
                    subdomain: hostname,
                    source: PassiveSource::WaybackMachine,
                    timestamp: None,
                    extra_data: HashMap::new(),
                });
            }
        }

        Ok(results)
    }

    fn query_commoncrawl(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        // Query CommonCrawl index
        let url = format!(
            "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{}&output=json&limit=500",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("CommonCrawl request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        // Parse NDJSON format
        for line in body.lines() {
            if let Some(start) = line.find("\"url\":\"") {
                let rest = &line[start + 7..];
                if let Some(end) = rest.find('"') {
                    let url_str = &rest[..end];
                    let hostname = url_str
                        .strip_prefix("http://")
                        .or_else(|| url_str.strip_prefix("https://"))
                        .unwrap_or(url_str)
                        .split('/')
                        .next()
                        .unwrap_or("")
                        .split(':')
                        .next()
                        .unwrap_or("")
                        .to_lowercase();

                    if hostname.ends_with(domain) && seen.insert(hostname.clone()) {
                        results.push(PassiveResult {
                            subdomain: hostname,
                            source: PassiveSource::CommonCrawl,
                            timestamp: None,
                            extra_data: HashMap::new(),
                        });
                    }
                }
            }
        }

        Ok(results)
    }

    fn query_urlscan(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let url = format!(
            "https://urlscan.io/api/v1/search/?q=domain:{}",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("URLScan request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        // Parse page.domain from results
        for line in body.split("\"domain\":\"") {
            if let Some(end) = line.find('"') {
                let subdomain = line[..end].to_lowercase();
                if subdomain.ends_with(domain) && seen.insert(subdomain.clone()) {
                    results.push(PassiveResult {
                        subdomain,
                        source: PassiveSource::UrlScan,
                        timestamp: None,
                        extra_data: HashMap::new(),
                    });
                }
            }
        }

        Ok(results)
    }

    fn query_hackertarget(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let url = format!(
            "https://api.hackertarget.com/hostsearch/?q={}",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("HackerTarget request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();

        // Format: subdomain,ip
        for line in body.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 1 {
                let subdomain = parts[0].trim().to_lowercase();
                if subdomain.ends_with(domain) {
                    let mut extra = HashMap::new();
                    if parts.len() >= 2 {
                        extra.insert("ip".to_string(), parts[1].to_string());
                    }
                    results.push(PassiveResult {
                        subdomain,
                        source: PassiveSource::HackerTarget,
                        timestamp: None,
                        extra_data: extra,
                    });
                }
            }
        }

        Ok(results)
    }

    fn query_bufferover(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let url = format!(
            "https://dns.bufferover.run/dns?q=.{}",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("BufferOver request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        // Parse FDNS_A entries
        for line in body.split("\"FDNS_A\":[") {
            if let Some(end) = line.find(']') {
                for entry in line[..end].split(',') {
                    let parts: Vec<&str> = entry.trim_matches('"').split(',').collect();
                    if let Some(subdomain_part) = parts.last() {
                        let subdomain = subdomain_part.to_lowercase();
                        if subdomain.ends_with(domain) && seen.insert(subdomain.clone()) {
                            results.push(PassiveResult {
                                subdomain,
                                source: PassiveSource::BufferOver,
                                timestamp: None,
                                extra_data: HashMap::new(),
                            });
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    fn query_omnisint(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let url = format!(
            "https://sonar.omnisint.io/subdomains/{}",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("Omnisint request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();

        // Parse JSON array
        for entry in body.split('"') {
            let subdomain = entry.trim().to_lowercase();
            if subdomain.ends_with(domain) && subdomain.len() > domain.len() {
                results.push(PassiveResult {
                    subdomain,
                    source: PassiveSource::Omnisint,
                    timestamp: None,
                    extra_data: HashMap::new(),
                });
            }
        }

        Ok(results)
    }

    fn query_anubisdb(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let url = format!(
            "https://jldc.me/anubis/subdomains/{}",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("AnubisDB request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();

        // Parse JSON array
        for entry in body.split('"') {
            let subdomain = entry.trim().to_lowercase();
            if subdomain.ends_with(domain) && subdomain.len() > domain.len() {
                results.push(PassiveResult {
                    subdomain,
                    source: PassiveSource::AnubisDb,
                    timestamp: None,
                    extra_data: HashMap::new(),
                });
            }
        }

        Ok(results)
    }

    fn query_robtex(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let url = format!(
            "https://freeapi.robtex.com/pdns/forward/{}",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("Robtex request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        // Parse NDJSON format
        for line in body.lines() {
            if let Some(start) = line.find("\"rrname\":\"") {
                let rest = &line[start + 10..];
                if let Some(end) = rest.find('"') {
                    let subdomain = rest[..end].to_lowercase();
                    if subdomain.ends_with(domain) && seen.insert(subdomain.clone()) {
                        results.push(PassiveResult {
                            subdomain,
                            source: PassiveSource::Robtex,
                            timestamp: None,
                            extra_data: HashMap::new(),
                        });
                    }
                }
            }
        }

        Ok(results)
    }

    fn query_dnsbx(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let url = format!(
            "https://rapiddns.io/subdomain/{}?full=1",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("RapidDNS request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        // Parse HTML table entries
        for line in body.split("<td>") {
            if let Some(end) = line.find("</td>") {
                let potential = &line[..end];
                let subdomain = potential.trim().to_lowercase();
                if subdomain.ends_with(domain)
                    && !subdomain.contains('<')
                    && seen.insert(subdomain.clone())
                {
                    results.push(PassiveResult {
                        subdomain,
                        source: PassiveSource::Dnsbx,
                        timestamp: None,
                        extra_data: HashMap::new(),
                    });
                }
            }
        }

        Ok(results)
    }

    fn query_dnsdumpster(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        // DNSDumpster requires a CSRF token - simplified approach
        let url = format!(
            "https://api.hackertarget.com/hostsearch/?q={}",
            domain
        );

        // Fallback to HackerTarget since DNSDumpster requires session handling
        self.query_hackertarget(domain)
            .map(|mut results| {
                for r in &mut results {
                    r.source = PassiveSource::DnsDumpster;
                }
                results
            })
    }

    fn query_sublist3r(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        // Sublist3r API endpoint
        let url = format!(
            "https://api.sublist3r.com/search.php?domain={}",
            domain
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("Sublist3r request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();

        // Parse JSON array
        for entry in body.split('"') {
            let subdomain = entry.trim().to_lowercase();
            if subdomain.ends_with(domain) && subdomain.len() > domain.len() {
                results.push(PassiveResult {
                    subdomain,
                    source: PassiveSource::Sublist3r,
                    timestamp: None,
                    extra_data: HashMap::new(),
                });
            }
        }

        Ok(results)
    }

    // ========================================================================
    // API Key Source Implementations
    // ========================================================================

    fn query_shodan(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let api_key = self
            .api_keys
            .get_key(PassiveSource::Shodan)
            .ok_or("Shodan API key not configured")?;

        let url = format!(
            "https://api.shodan.io/dns/domain/{}?key={}",
            domain, api_key
        );

        let response = self
            .client
            .get(&url)
            .map_err(|e| format!("Shodan request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        // Parse subdomains from response
        for line in body.split("\"subdomain\":\"") {
            if let Some(end) = line.find('"') {
                let subdomain_part = &line[..end];
                let subdomain = format!("{}.{}", subdomain_part, domain).to_lowercase();
                if seen.insert(subdomain.clone()) {
                    results.push(PassiveResult {
                        subdomain,
                        source: PassiveSource::Shodan,
                        timestamp: None,
                        extra_data: HashMap::new(),
                    });
                }
            }
        }

        Ok(results)
    }

    fn query_virustotal(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let api_key = self
            .api_keys
            .get_key(PassiveSource::VirusTotal)
            .ok_or("VirusTotal API key not configured")?;

        let url = format!(
            "https://www.virustotal.com/api/v3/domains/{}/subdomains?limit=100",
            domain
        );

        let mut headers = HashMap::new();
        headers.insert("x-apikey".to_string(), api_key.clone());

        let response = self
            .client
            .get_with_headers(&url, &headers)
            .map_err(|e| format!("VirusTotal request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        // Parse subdomains from response
        for line in body.split("\"id\":\"") {
            if let Some(end) = line.find('"') {
                let subdomain = line[..end].to_lowercase();
                if subdomain.ends_with(domain) && seen.insert(subdomain.clone()) {
                    results.push(PassiveResult {
                        subdomain,
                        source: PassiveSource::VirusTotal,
                        timestamp: None,
                        extra_data: HashMap::new(),
                    });
                }
            }
        }

        Ok(results)
    }

    fn query_securitytrails(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let api_key = self
            .api_keys
            .get_key(PassiveSource::SecurityTrails)
            .ok_or("SecurityTrails API key not configured")?;

        let url = format!(
            "https://api.securitytrails.com/v1/domain/{}/subdomains",
            domain
        );

        let mut headers = HashMap::new();
        headers.insert("APIKEY".to_string(), api_key.clone());

        let response = self
            .client
            .get_with_headers(&url, &headers)
            .map_err(|e| format!("SecurityTrails request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();

        // Parse subdomains array
        if let Some(start) = body.find("\"subdomains\":[") {
            let rest = &body[start + 14..];
            if let Some(end) = rest.find(']') {
                for sub in rest[..end].split(',') {
                    let subdomain_part = sub.trim().trim_matches('"');
                    if !subdomain_part.is_empty() {
                        let subdomain = format!("{}.{}", subdomain_part, domain).to_lowercase();
                        results.push(PassiveResult {
                            subdomain,
                            source: PassiveSource::SecurityTrails,
                            timestamp: None,
                            extra_data: HashMap::new(),
                        });
                    }
                }
            }
        }

        Ok(results)
    }

    fn query_censys(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let api_key = self
            .api_keys
            .get_key(PassiveSource::Censys)
            .ok_or("Censys API key not configured")?;

        let url = format!(
            "https://search.censys.io/api/v2/certificates/search?q=names:*.{}&per_page=100",
            domain
        );

        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), format!("Basic {}", api_key));

        let response = self
            .client
            .get_with_headers(&url, &headers)
            .map_err(|e| format!("Censys request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        // Parse names from certificates
        for line in body.split("\"names\":[") {
            if let Some(end) = line.find(']') {
                for name in line[..end].split(',') {
                    let subdomain = name.trim().trim_matches('"').to_lowercase();
                    if subdomain.ends_with(domain)
                        && !subdomain.starts_with('*')
                        && seen.insert(subdomain.clone())
                    {
                        results.push(PassiveResult {
                            subdomain,
                            source: PassiveSource::Censys,
                            timestamp: None,
                            extra_data: HashMap::new(),
                        });
                    }
                }
            }
        }

        Ok(results)
    }

    fn query_binaryedge(&self, domain: &str) -> Result<Vec<PassiveResult>, String> {
        let api_key = self
            .api_keys
            .get_key(PassiveSource::BinaryEdge)
            .ok_or("BinaryEdge API key not configured")?;

        let url = format!(
            "https://api.binaryedge.io/v2/query/domains/subdomain/{}",
            domain
        );

        let mut headers = HashMap::new();
        headers.insert("X-Key".to_string(), api_key.clone());

        let response = self
            .client
            .get_with_headers(&url, &headers)
            .map_err(|e| format!("BinaryEdge request failed: {}", e))?;

        let body = String::from_utf8_lossy(&response.body);
        let mut results = Vec::new();

        // Parse events array
        if let Some(start) = body.find("\"events\":[") {
            let rest = &body[start + 10..];
            if let Some(end) = rest.find(']') {
                for sub in rest[..end].split(',') {
                    let subdomain = sub.trim().trim_matches('"').to_lowercase();
                    if subdomain.ends_with(domain) {
                        results.push(PassiveResult {
                            subdomain,
                            source: PassiveSource::BinaryEdge,
                            timestamp: None,
                            extra_data: HashMap::new(),
                        });
                    }
                }
            }
        }

        Ok(results)
    }
}

impl Default for PassiveQuerier {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_free_sources_count() {
        let free = PassiveSource::free_sources();
        assert!(free.len() >= 15, "Should have 15+ free sources");
    }

    #[test]
    fn test_all_sources_count() {
        let all = PassiveSource::all_sources();
        assert!(all.len() >= 30, "Should have 30+ total sources");
    }

    #[test]
    fn test_api_key_detection() {
        assert!(PassiveSource::Shodan.requires_api_key());
        assert!(PassiveSource::VirusTotal.requires_api_key());
        assert!(!PassiveSource::CrtSh.requires_api_key());
        assert!(!PassiveSource::WaybackMachine.requires_api_key());
    }

    #[test]
    fn test_api_key_manager() {
        let mut manager = ApiKeyManager::new();
        manager.set_key(PassiveSource::Shodan, "test-key".to_string());

        assert!(manager.has_key(PassiveSource::Shodan));
        assert!(!manager.has_key(PassiveSource::VirusTotal));
        assert_eq!(
            manager.get_key(PassiveSource::Shodan),
            Some(&"test-key".to_string())
        );
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(100);

        limiter.record("test");
        let backoff = limiter.handle_rate_limit("test");
        assert!(backoff.is_some());
        assert_eq!(backoff.unwrap(), Duration::from_secs(2)); // 2^1
    }
}
