/// Subdomain Enumeration Module
///
/// Replaces: amass, subfinder, assetfinder, crt.sh
///
/// Features:
/// - Certificate Transparency log enumeration (crt.sh)
/// - DNS bruteforce with wordlists
/// - Multi-threaded enumeration
/// - Passive enumeration from public sources
///
/// NO external dependencies - all implemented from scratch
use crate::config;
use crate::modules::tls::ct_logs::CTLogsClient;
use crate::protocols::dns::DnsClient;
use crate::protocols::http::HttpClient;
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread;

/// Subdomain enumeration result
#[derive(Debug, Clone)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub ips: Vec<String>,
    pub source: EnumerationSource,
}

/// Enumeration source
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum EnumerationSource {
    CertificateTransparency,
    DnsBruteforce,
    VirusTotal,
    SecurityTrails,
    HackerTarget,
    Manual,
}

impl std::fmt::Display for EnumerationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnumerationSource::CertificateTransparency => write!(f, "CT-Logs"),
            EnumerationSource::DnsBruteforce => write!(f, "DNS-BF"),
            EnumerationSource::VirusTotal => write!(f, "VirusTotal"),
            EnumerationSource::SecurityTrails => write!(f, "SecurityTrails"),
            EnumerationSource::HackerTarget => write!(f, "HackerTarget"),
            EnumerationSource::Manual => write!(f, "Manual"),
        }
    }
}

/// Subdomain enumerator
pub struct SubdomainEnumerator {
    domain: String,
    wordlist: Vec<String>,
    threads: usize,
    timeout_ms: u64,
}

impl SubdomainEnumerator {
    pub fn new(domain: &str) -> Self {
        let cfg = config::get();
        Self {
            domain: domain.to_string(),
            wordlist: get_default_wordlist(),
            threads: 10,
            timeout_ms: cfg.network.dns_timeout_ms,
        }
    }

    pub fn with_wordlist(mut self, wordlist: Vec<String>) -> Self {
        self.wordlist = wordlist;
        self
    }

    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads;
        self
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Run all enumeration methods with recursive queue-based discovery
    ///
    /// This implements a RECURSIVE approach where:
    /// 1. Initial passive sources populate the queue
    /// 2. Each new subdomain discovered triggers more enumeration
    /// 3. New certificates, DNS records, etc. can reveal more subdomains
    /// 4. Process continues until no new discoveries are made
    pub fn enumerate_all(&self) -> Result<Vec<SubdomainResult>, String> {
        // Discovery queue - holds subdomains to process
        let mut queue: VecDeque<String> = VecDeque::new();

        // All discovered subdomains (deduplication)
        let mut all_found: HashSet<String> = HashSet::new();

        // Final results
        let mut results: Vec<SubdomainResult> = Vec::new();

        // ==== PHASE 1: Initial Passive Sources ====
        println!("🔍 [Phase 1] Passive Reconnaissance");

        // 1.1 Certificate Transparency logs
        println!("  ├─ Querying Certificate Transparency logs...");
        match self.enumerate_ct_logs() {
            Ok(ct_results) => {
                let count = ct_results.len();
                println!("  │  ✅ Found {} subdomains from CT logs", count);
                for result in ct_results {
                    if all_found.insert(result.subdomain.clone()) {
                        queue.push_back(result.subdomain.clone());
                        results.push(result);
                    }
                }
            }
            Err(e) => println!("  │  ⚠️  CT logs failed: {}", e),
        }

        // 1.2 HackerTarget API
        println!("  ├─ Querying HackerTarget API...");
        match self.enumerate_hackertarget() {
            Ok(ht_results) => {
                let count = ht_results.len();
                println!("  │  ✅ Found {} subdomains from HackerTarget", count);
                for result in ht_results {
                    if all_found.insert(result.subdomain.clone()) {
                        queue.push_back(result.subdomain.clone());
                        results.push(result);
                    }
                }
            }
            Err(e) => println!("  │  ⚠️  HackerTarget failed: {}", e),
        }

        println!(
            "  └─ Phase 1 complete: {} unique subdomains discovered\n",
            all_found.len()
        );

        // ==== PHASE 2: Recursive Discovery Queue ====
        println!("🔄 [Phase 2] Recursive Discovery (queue-based)");

        let mut iteration = 0;
        let max_iterations = 3; // Prevent infinite loops

        while !queue.is_empty() && iteration < max_iterations {
            iteration += 1;
            let queue_size = queue.len();
            println!(
                "  ├─ Iteration {}: Processing {} subdomains from queue",
                iteration, queue_size
            );

            // Process current queue batch
            let current_batch: Vec<String> = queue.drain(..).collect();

            // Extract base names for permutation
            let base_names: Vec<String> = current_batch
                .iter()
                .map(|subdomain| {
                    subdomain
                        .strip_suffix(&format!(".{}", self.domain))
                        .unwrap_or(subdomain)
                        .to_string()
                })
                .collect();

            // Generate permutations
            let permutations = self.generate_permutations(&base_names);
            println!("  │  ├─ Generated {} permutations", permutations.len());

            // DNS bruteforce permutations
            match self.enumerate_dns_bruteforce_with_wordlist(&permutations) {
                Ok(perm_results) => {
                    let new_count = perm_results.len();
                    if new_count > 0 {
                        println!(
                            "  │  ├─ ✅ Permutations revealed {} NEW subdomains!",
                            new_count
                        );
                        for result in perm_results {
                            if all_found.insert(result.subdomain.clone()) {
                                queue.push_back(result.subdomain.clone()); // ← RECURSIVE: new finds go back to queue!
                                results.push(result);
                            }
                        }
                    } else {
                        println!("  │  ├─ No new subdomains from permutations");
                    }
                }
                Err(e) => println!("  │  ├─ ⚠️  Permutation bruteforce failed: {}", e),
            }
        }

        if iteration >= max_iterations {
            println!("  └─ Stopped at max iterations ({})\n", max_iterations);
        } else {
            println!("  └─ Queue exhausted: no more new discoveries\n");
        }

        // ==== PHASE 3: Final Wordlist Bruteforce ====
        println!("🔍 [Phase 3] Comprehensive DNS Bruteforce");
        println!(
            "  ├─ Using SecLists wordlist ({} entries)",
            self.wordlist.len()
        );

        match self.enumerate_dns_bruteforce_with_wordlist(&self.wordlist) {
            Ok(dns_results) => {
                let new_count = dns_results
                    .iter()
                    .filter(|r| all_found.insert(r.subdomain.clone()))
                    .count();
                println!(
                    "  └─ ✅ Found {} NEW subdomains via DNS bruteforce",
                    new_count
                );

                for result in dns_results {
                    if all_found.contains(&result.subdomain) {
                        results.push(result);
                    }
                }
            }
            Err(e) => println!("  └─ ⚠️  DNS bruteforce failed: {}", e),
        }

        // ==== FINAL: Deduplicate and Sort ====
        let mut seen = HashSet::new();
        results.retain(|r| seen.insert(r.subdomain.clone()));
        results.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));

        println!("\n✅ Total unique subdomains discovered: {}", results.len());
        Ok(results)
    }

    /// Enumerate via HackerTarget API (passive, free, no key required)
    pub fn enumerate_hackertarget(&self) -> Result<Vec<SubdomainResult>, String> {
        let mut results = Vec::new();

        // HackerTarget provides free subdomain enumeration
        let url = format!("https://api.hackertarget.com/hostsearch/?q={}", self.domain);
        let http_client = HttpClient::new();

        match http_client.get(&url) {
            Ok(response) => {
                let body_str = String::from_utf8_lossy(&response.body);

                // Format: subdomain.domain.com,IP
                for line in body_str.lines() {
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 2 {
                        let subdomain = parts[0].trim().to_lowercase();
                        let ip = parts[1].trim().to_string();

                        if subdomain.ends_with(&self.domain) {
                            results.push(SubdomainResult {
                                subdomain,
                                ips: vec![ip],
                                source: EnumerationSource::HackerTarget,
                            });
                        }
                    }
                }
            }
            Err(e) => return Err(format!("HackerTarget query failed: {}", e)),
        }

        Ok(results)
    }

    /// Generate subdomain permutations (altdns-style)
    /// Creates variations like: dev-api, api-dev, dev-staging, etc.
    fn generate_permutations(&self, base_subdomains: &[String]) -> Vec<String> {
        let mut permutations = HashSet::new();

        // Common words for permutation
        let words = vec![
            "dev",
            "stage",
            "staging",
            "prod",
            "production",
            "test",
            "testing",
            "qa",
            "uat",
            "demo",
            "sandbox",
            "temp",
            "tmp",
            "backup",
            "old",
            "new",
            "v1",
            "v2",
            "v3",
            "api",
            "app",
            "web",
            "admin",
            "portal",
            "internal",
        ];

        // Generate permutations for found subdomains
        for subdomain in base_subdomains.iter().take(20) {
            // Limit to top 20 to avoid explosion
            for word in &words {
                // prefix-subdomain (dev-api)
                permutations.insert(format!("{}-{}", word, subdomain));
                // subdomain-suffix (api-dev)
                permutations.insert(format!("{}-{}", subdomain, word));
                // prefix.subdomain (dev.api)
                permutations.insert(format!("{}.{}", word, subdomain));
                // subdomain.suffix (api.dev)
                permutations.insert(format!("{}.{}", subdomain, word));
            }
        }

        permutations.into_iter().collect()
    }

    /// Enumerate subdomains from Certificate Transparency logs
    pub fn enumerate_ct_logs(&self) -> Result<Vec<SubdomainResult>, String> {
        let mut results = Vec::new();

        // Use our dedicated CT logs client
        let ct_client = CTLogsClient::new();

        // Query crt.sh for subdomains
        let subdomains = ct_client.query_subdomains(&self.domain)?;

        for subdomain in subdomains {
            // Resolve each subdomain to get IPs
            let ips = self.resolve_domain(&subdomain);

            results.push(SubdomainResult {
                subdomain,
                ips,
                source: EnumerationSource::CertificateTransparency,
            });
        }

        Ok(results)
    }

    /// Enumerate subdomains via DNS bruteforce
    pub fn enumerate_dns_bruteforce(&self) -> Result<Vec<SubdomainResult>, String> {
        let results = Arc::new(Mutex::new(Vec::new()));
        let resolver_addr = config::get().network.dns_resolver.clone();
        let dns_timeout = self.timeout_ms;
        let wordlist_chunks = self.chunk_wordlist(self.threads);

        let mut handles = vec![];

        for chunk in wordlist_chunks {
            let domain = self.domain.clone();
            let results = Arc::clone(&results);
            let resolver_addr = resolver_addr.clone();

            let handle = thread::spawn(move || {
                let dns_client = DnsClient::new(&resolver_addr).with_timeout(dns_timeout);

                for prefix in chunk {
                    let subdomain = format!("{}.{}", prefix, domain);

                    // Try to resolve the subdomain
                    match dns_client.query(&subdomain, crate::protocols::dns::DnsRecordType::A) {
                        Ok(answers) => {
                            if !answers.is_empty() {
                                // Extract IP addresses from DNS answers
                                let ips: Vec<String> =
                                    answers.iter().filter_map(|answer| answer.as_ip()).collect();

                                if !ips.is_empty() {
                                    let result = SubdomainResult {
                                        subdomain: subdomain.clone(),
                                        ips,
                                        source: EnumerationSource::DnsBruteforce,
                                    };

                                    if let Ok(mut results) = results.lock() {
                                        results.push(result);
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            // Subdomain doesn't exist, continue
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().map_err(|_| "Thread panicked")?;
        }

        let results = results.lock().unwrap().clone();
        Ok(results)
    }

    /// Enumerate subdomains via DNS bruteforce with custom wordlist
    pub fn enumerate_dns_bruteforce_with_wordlist(
        &self,
        wordlist: &[String],
    ) -> Result<Vec<SubdomainResult>, String> {
        let results = Arc::new(Mutex::new(Vec::new()));
        let resolver_addr = config::get().network.dns_resolver.clone();
        let dns_timeout = self.timeout_ms;

        // Split wordlist into chunks for threading
        let chunk_size = (wordlist.len() + self.threads - 1) / self.threads;
        let mut chunks = Vec::new();

        for i in 0..self.threads {
            let start = i * chunk_size;
            let end = std::cmp::min(start + chunk_size, wordlist.len());

            if start < wordlist.len() {
                chunks.push(wordlist[start..end].to_vec());
            }
        }

        let mut handles = vec![];

        for chunk in chunks {
            let domain = self.domain.clone();
            let results = Arc::clone(&results);
            let resolver_addr = resolver_addr.clone();

            let handle = thread::spawn(move || {
                let dns_client = DnsClient::new(&resolver_addr).with_timeout(dns_timeout);

                for prefix in chunk {
                    let subdomain = format!("{}.{}", prefix, domain);

                    // Try to resolve the subdomain
                    match dns_client.query(&subdomain, crate::protocols::dns::DnsRecordType::A) {
                        Ok(answers) => {
                            if !answers.is_empty() {
                                // Extract IP addresses from DNS answers
                                let ips: Vec<String> =
                                    answers.iter().filter_map(|answer| answer.as_ip()).collect();

                                if !ips.is_empty() {
                                    let result = SubdomainResult {
                                        subdomain: subdomain.clone(),
                                        ips,
                                        source: EnumerationSource::DnsBruteforce,
                                    };

                                    if let Ok(mut results) = results.lock() {
                                        results.push(result);
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            // Silently skip failed resolutions
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().map_err(|_| "Thread panicked")?;
        }

        let results = results.lock().unwrap().clone();
        Ok(results)
    }

    /// Resolve domain to IP addresses
    fn resolve_domain(&self, domain: &str) -> Vec<String> {
        let resolver_addr = config::get().network.dns_resolver.clone();
        let dns_client = DnsClient::new(&resolver_addr).with_timeout(self.timeout_ms);

        match dns_client.query(domain, crate::protocols::dns::DnsRecordType::A) {
            Ok(answers) => answers.iter().filter_map(|answer| answer.as_ip()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Split wordlist into chunks for multi-threading
    fn chunk_wordlist(&self, num_chunks: usize) -> Vec<Vec<String>> {
        let chunk_size = (self.wordlist.len() + num_chunks - 1) / num_chunks;
        let mut chunks = Vec::new();

        for i in 0..num_chunks {
            let start = i * chunk_size;
            let end = std::cmp::min(start + chunk_size, self.wordlist.len());

            if start < self.wordlist.len() {
                chunks.push(self.wordlist[start..end].to_vec());
            }
        }

        chunks
    }

    /// Deduplicate results
    #[cfg_attr(not(test), allow(dead_code))]
    fn deduplicate_results(&self, results: Vec<SubdomainResult>) -> Vec<SubdomainResult> {
        let mut seen = HashSet::new();
        let mut unique = Vec::new();

        for result in results {
            if seen.insert(result.subdomain.clone()) {
                unique.push(result);
            }
        }

        // Sort by subdomain name
        unique.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));
        unique
    }
}

/// Default wordlist for subdomain bruteforce
/// Tries to load SecLists-5k.txt, falls back to embedded list
fn get_default_wordlist() -> Vec<String> {
    use std::fs;
    use std::path::Path;

    // Try to load SecLists wordlist
    let wordlist_paths = vec![
        "wordlists/subdomains-5k.txt",
        "/home/cyber/Work/FF/security/wordlists/subdomains-5k.txt",
        "./wordlists/subdomains-5k.txt",
    ];

    for path in wordlist_paths {
        if Path::new(path).exists() {
            if let Ok(content) = fs::read_to_string(path) {
                let entries: Vec<String> = content
                    .lines()
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .collect();

                if !entries.is_empty() {
                    return entries;
                }
            }
        }
    }

    // Fallback to embedded wordlist if file not found
    vec![
        // CRITICAL - Top 50 most common (99% coverage)
        "www",
        "mail",
        "remote",
        "blog",
        "webmail",
        "server",
        "ns1",
        "ns2",
        "smtp",
        "secure",
        "vpn",
        "m",
        "shop",
        "ftp",
        "mail2",
        "test",
        "portal",
        "ns",
        "ww1",
        "host",
        "support",
        "dev",
        "web",
        "bbs",
        "ww42",
        "mx",
        "email",
        "cloud",
        "1",
        "mail1",
        "2",
        "forum",
        "owa",
        "www2",
        "gw",
        "admin",
        "store",
        "mx1",
        "cdn",
        "api",
        "exchange",
        "app",
        "gov",
        "2tty",
        "vps",
        "govyty",
        "hgfgdf",
        "news",
        "1rer",
        "lkjkui",
        // Development & Testing (HIGH PRIORITY)
        "dev",
        "development",
        "test",
        "testing",
        "stage",
        "staging",
        "qa",
        "uat",
        "demo",
        "sandbox",
        "preview",
        "beta",
        "alpha",
        "gamma",
        "delta",
        "preprod",
        "pre-prod",
        "acceptance",
        "integration",
        "ci",
        "cd",
        "build",
        "jenkins",
        "gitlab",
        "github",
        // APIs & Services (HIGH VALUE)
        "api",
        "api-dev",
        "api-prod",
        "api-staging",
        "api1",
        "api2",
        "api3",
        "rest",
        "graphql",
        "ws",
        "websocket",
        "rpc",
        "grpc",
        "service",
        "services",
        "microservice",
        "gateway",
        "proxy",
        "reverse-proxy",
        "load-balancer",
        "lb",
        // Admin & Internal (CRITICAL FOR SECURITY)
        "admin",
        "administrator",
        "root",
        "sys",
        "system",
        "internal",
        "intranet",
        "corp",
        "corporate",
        "cpanel",
        "plesk",
        "whm",
        "webmin",
        "phpmyadmin",
        "adminer",
        "dashboard",
        "panel",
        "control",
        "manage",
        "management",
        "console",
        // Cloud & Infrastructure (AWS, Azure, GCP)
        "s3",
        "aws",
        "ec2",
        "rds",
        "elb",
        "cloudfront",
        "lambda",
        "azure",
        "blob",
        "gcp",
        "cloud",
        "bucket",
        "storage",
        "backup",
        "backups",
        "archive",
        "cdn",
        "cdn1",
        "cdn2",
        "static",
        "assets",
        "media",
        "files",
        "uploads",
        "download",
        "downloads",
        // Database & Cache
        "db",
        "database",
        "mysql",
        "postgres",
        "mongo",
        "redis",
        "memcache",
        "elasticsearch",
        "es",
        "kibana",
        "grafana",
        "prometheus",
        "influx",
        "cassandra",
        "neo4j",
        "sql",
        // Monitoring & Logging
        "monitor",
        "monitoring",
        "metrics",
        "logs",
        "logging",
        "sentry",
        "splunk",
        "elk",
        "datadog",
        "newrelic",
        "status",
        "health",
        "uptime",
        "pingdom",
        // CI/CD & DevOps
        "jenkins",
        "bamboo",
        "teamcity",
        "travis",
        "circleci",
        "drone",
        "gitlab-ci",
        "actions",
        "docker",
        "kubernetes",
        "k8s",
        "rancher",
        "portainer",
        "registry",
        "artifactory",
        "nexus",
        // Email & Communication
        "mail",
        "smtp",
        "pop",
        "pop3",
        "imap",
        "webmail",
        "email",
        "newsletter",
        "mailman",
        "listserv",
        "mx",
        "mx1",
        "mx2",
        "mx3",
        "autoconfig",
        "autodiscover",
        "exchange",
        "owa",
        // CRM & Business
        "crm",
        "erp",
        "hr",
        "helpdesk",
        "support",
        "ticket",
        "tickets",
        "jira",
        "confluence",
        "wiki",
        "docs",
        "documentation",
        "kb",
        "knowledgebase",
        "faq",
        // E-commerce & Payment
        "shop",
        "store",
        "cart",
        "checkout",
        "payment",
        "pay",
        "billing",
        "invoice",
        "order",
        "orders",
        "product",
        "products",
        "catalog",
        "inventory",
        // Mobile & Apps
        "m",
        "mobile",
        "android",
        "ios",
        "app",
        "apps",
        "play",
        "appstore",
        // Security & Auth
        "sso",
        "oauth",
        "auth",
        "login",
        "signin",
        "signup",
        "register",
        "account",
        "accounts",
        "identity",
        "idp",
        "saml",
        "ldap",
        "ad",
        "activedirectory",
        "vpn",
        "firewall",
        "waf",
        // Content & Media
        "blog",
        "news",
        "press",
        "media",
        "video",
        "videos",
        "images",
        "img",
        "photos",
        "gallery",
        "stream",
        "streaming",
        "podcast",
        "radio",
        // Regional & Language
        "us",
        "eu",
        "asia",
        "apac",
        "emea",
        "uk",
        "de",
        "fr",
        "es",
        "it",
        "jp",
        "cn",
        "br",
        "au",
        "ca",
        "in",
        "en",
        "www-en",
        "www-de",
        "www-fr",
        // Versions & Environments
        "v1",
        "v2",
        "v3",
        "v4",
        "version1",
        "version2",
        "old",
        "new",
        "legacy",
        "next",
        "prod",
        "production",
        "live",
        // Network & Infrastructure
        "ns",
        "ns1",
        "ns2",
        "ns3",
        "ns4",
        "dns",
        "dns1",
        "dns2",
        "router",
        "switch",
        "gateway",
        "firewall",
        "proxy",
        "cache",
        "lb",
        "loadbalancer",
        // Misc Common
        "www1",
        "www2",
        "www3",
        "ftp",
        "sftp",
        "ssh",
        "telnet",
        "cpanel",
        "forum",
        "forums",
        "community",
        "social",
        "chat",
        "irc",
        "slack",
        "teams",
        "meet",
        "zoom",
        "calendar",
        "booking",
        "reserve",
        "reservation",
        "events",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Load wordlist from file
pub fn load_wordlist_from_file(path: &str) -> Result<Vec<String>, String> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(path).map_err(|e| format!("Failed to open wordlist file: {}", e))?;

    let reader = BufReader::new(file);
    let mut wordlist = Vec::new();

    for line in reader.lines() {
        if let Ok(word) = line {
            let trimmed = word.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                wordlist.push(trimmed.to_lowercase());
            }
        }
    }

    Ok(wordlist)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_wordlist() {
        let wordlist = get_default_wordlist();
        assert!(wordlist.len() > 50);
        assert!(wordlist.contains(&"www".to_string()));
        assert!(wordlist.contains(&"mail".to_string()));
    }

    #[test]
    fn test_chunk_wordlist() {
        let enumerator = SubdomainEnumerator::new("example.com");
        let chunks = enumerator.chunk_wordlist(4);

        assert!(chunks.len() <= 4);

        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, enumerator.wordlist.len());
    }

    #[test]
    fn test_deduplicate() {
        let enumerator = SubdomainEnumerator::new("example.com");

        let results = vec![
            SubdomainResult {
                subdomain: "www.example.com".to_string(),
                ips: vec!["1.2.3.4".to_string()],
                source: EnumerationSource::DnsBruteforce,
            },
            SubdomainResult {
                subdomain: "www.example.com".to_string(),
                ips: vec!["1.2.3.5".to_string()],
                source: EnumerationSource::CertificateTransparency,
            },
            SubdomainResult {
                subdomain: "mail.example.com".to_string(),
                ips: vec!["1.2.3.6".to_string()],
                source: EnumerationSource::DnsBruteforce,
            },
        ];

        let unique = enumerator.deduplicate_results(results);
        assert_eq!(unique.len(), 2);
    }
}
