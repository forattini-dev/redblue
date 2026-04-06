/// Subdomain Enumeration Module
///
/// Replaces: amass, subfinder, assetfinder, crt.sh
///
/// Features:
/// - Certificate Transparency log enumeration (crt.sh)
/// - DNS bruteforce with wordlists
/// - Multi-threaded enumeration
/// - Passive enumeration from public sources
/// - Automatic graph population (Host, Domain nodes)
///
/// NO external dependencies - all implemented from scratch
use crate::config;
use crate::modules::recon::crtsh::CrtShClient;
use crate::protocols::dns::{DnsClient, DnsRecordType};
use crate::protocols::http::HttpClient;
use crate::storage::engine::emitter::GraphEmitter;
use crate::synergy::events::{emit, EntityRef, Event, EventType};
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread;

macro_rules! progressln {
    ($($arg:tt)*) => {
        eprintln!($($arg)*)
    };
}

/// Subdomain enumeration result
#[derive(Debug, Clone)]
pub struct SubdomainResult {
  pub subdomain: String,
  pub ips: Vec<String>,
  pub cname_chain: Vec<String>,
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
  AlienVaultOtx,
  ThreatCrowd,
  WaybackMachine,
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
      EnumerationSource::AlienVaultOtx => write!(f, "OTX"),
      EnumerationSource::ThreatCrowd => write!(f, "ThreatCrowd"),
      EnumerationSource::WaybackMachine => write!(f, "Wayback"),
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
  filter_wildcards: bool,
  wildcard_ips: HashSet<String>,
}

impl SubdomainEnumerator {
  pub fn new(domain: &str) -> Self {
    let cfg = config::get();
    Self {
      domain: domain.to_string(),
      wordlist: get_default_wordlist(),
      threads: 10,
      timeout_ms: cfg.network.dns_timeout_ms,
      filter_wildcards: true,
      wildcard_ips: HashSet::new(),
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

  pub fn with_wildcard_filtering(mut self, enabled: bool) -> Self {
    self.filter_wildcards = enabled;
    self
  }

  /// Detect wildcard IPs by probing random non-existent subdomains.
  /// This needs to be called before actual enumeration if filtering is desired.
  pub fn detect_wildcard_ips(&mut self) {
    if !self.filter_wildcards {
      return;
    }

    let resolver_addr = config::get().network.dns_resolver.clone();
    let client = DnsClient::new(&resolver_addr).with_timeout(self.timeout_ms);

    for i in 0..3 {
      // Probe a few times
      // Simple pseudo-random string using time and loop counter
      let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(i as u64);
      let rand_prefix: String = (0..10)
        .enumerate()
        .map(|(j, _)| {
          // Simple LCG-style random
          let v = (seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(j as u64)) as u8;
          ((v % 26) + b'a') as char
        })
        .collect();
      let probe_domain = format!("{}.{}", rand_prefix, self.domain);
      for ip in query_ip_records(&client, &probe_domain) {
        self.wildcard_ips.insert(ip);
      }
    }
  }

  /// Filters a list of SubdomainResults, removing those that resolve to known wildcard IPs.
  fn filter_wildcard_results(&self, results: Vec<SubdomainResult>) -> Vec<SubdomainResult> {
    if self.wildcard_ips.is_empty() {
      return results;
    }

    results
      .into_iter()
      .filter(|res| {
        // Keep result if it has no IPs or if none of its IPs are wildcard IPs
        res.ips.is_empty() || !res.ips.iter().any(|ip| self.wildcard_ips.contains(ip))
      })
      .collect()
  }

  /// Run all enumeration methods with recursive queue-based discovery
  ///
  /// This implements a RECURSIVE approach where:
  /// 1. Initial passive sources populate the queue
  /// 2. Each new subdomain discovered triggers more enumeration
  /// 3. New certificates, DNS records, etc. can reveal more subdomains
  /// 4. Process continues until no new discoveries are made
  pub fn enumerate_all(&mut self) -> Result<Vec<SubdomainResult>, String> {
    // Discovery queue - holds subdomains to process
    let mut queue: VecDeque<String> = VecDeque::new();

    // All discovered subdomains (deduplication)
    let mut all_found: HashSet<String> = HashSet::new();

    // Final results
    let mut results: Vec<SubdomainResult> = Vec::new();

    // Detect wildcard IPs before starting enumeration
    self.detect_wildcard_ips();
    if !self.wildcard_ips.is_empty() {
      progressln!("  ℹ️ Wildcard IPs detected: {:?}", self.wildcard_ips);
    }

    // ==== PHASE 1: Initial Passive Sources ====
    progressln!("🔍 [Phase 1] Passive Reconnaissance");

    // 1.1 Certificate Transparency logs
    progressln!("  ├─ Querying Certificate Transparency logs...");
    match self.enumerate_ct_logs() {
      Ok(ct_results) => {
        let filtered_results = self.filter_wildcard_results(ct_results);
        let count = filtered_results.len();
        progressln!("  │  ✅ Found {} subdomains from CT logs", count);
        for result in filtered_results {
          if all_found.insert(result.subdomain.clone()) {
            queue.push_back(result.subdomain.clone());
            results.push(result);
          }
        }
      }
      Err(e) => progressln!("  │  ⚠️  CT logs failed: {}", e),
    }

    // 1.2 HackerTarget API
    progressln!("  ├─ Querying HackerTarget API...");
    match self.enumerate_hackertarget() {
      Ok(ht_results) => {
        let filtered_results = self.filter_wildcard_results(ht_results);
        let count = filtered_results.len();
        progressln!("  │  ✅ Found {} subdomains from HackerTarget", count);
        for result in filtered_results {
          if all_found.insert(result.subdomain.clone()) {
            queue.push_back(result.subdomain.clone());
            results.push(result);
          }
        }
      }
      Err(e) => progressln!("  │  ⚠️  HackerTarget failed: {}", e),
    }

    // 1.3 AlienVault OTX
    progressln!("  ├─ Querying AlienVault OTX...");
    match self.enumerate_alienvault_otx() {
      Ok(otx_results) => {
        let filtered_results = self.filter_wildcard_results(otx_results);
        let new_count = filtered_results
          .iter()
          .filter(|r| !all_found.contains(&r.subdomain))
          .count();
        progressln!("  │  ✅ Found {} new subdomains from OTX", new_count);
        for result in filtered_results {
          if all_found.insert(result.subdomain.clone()) {
            queue.push_back(result.subdomain.clone());
            results.push(result);
          }
        }
      }
      Err(e) => progressln!("  │  ⚠️  AlienVault OTX failed: {}", e),
    }

    // 1.4 ThreatCrowd
    progressln!("  ├─ Querying ThreatCrowd...");
    match self.enumerate_threatcrowd() {
      Ok(tc_results) => {
        let filtered_results = self.filter_wildcard_results(tc_results);
        let new_count = filtered_results
          .iter()
          .filter(|r| !all_found.contains(&r.subdomain))
          .count();
        progressln!(
          "  │  ✅ Found {} new subdomains from ThreatCrowd",
          new_count
        );
        for result in filtered_results {
          if all_found.insert(result.subdomain.clone()) {
            queue.push_back(result.subdomain.clone());
            results.push(result);
          }
        }
      }
      Err(e) => progressln!("  │  ⚠️  ThreatCrowd failed: {}", e),
    }

    // 1.5 Wayback Machine
    progressln!("  ├─ Querying Wayback Machine...");
    match self.enumerate_wayback() {
      Ok(wb_results) => {
        let filtered_results = self.filter_wildcard_results(wb_results);
        let new_count = filtered_results
          .iter()
          .filter(|r| !all_found.contains(&r.subdomain))
          .count();
        progressln!("  │  ✅ Found {} new subdomains from Wayback", new_count);
        for result in filtered_results {
          if all_found.insert(result.subdomain.clone()) {
            queue.push_back(result.subdomain.clone());
            results.push(result);
          }
        }
      }
      Err(e) => progressln!("  │  ⚠️  Wayback Machine failed: {}", e),
    }

    progressln!(
      "  └─ Phase 1 complete: {} unique subdomains discovered\n",
      all_found.len()
    );

    // ==== PHASE 2: Recursive Discovery Queue ====
    progressln!("🔄 [Phase 2] Recursive Discovery (queue-based)");

    let mut iteration = 0;
    let max_iterations = 3; // Prevent infinite loops

    while !queue.is_empty() && iteration < max_iterations {
      iteration += 1;
      let queue_size = queue.len();
      progressln!(
        "  ├─ Iteration {}: Processing {} subdomains from queue",
        iteration,
        queue_size
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
      progressln!("  │  ├─ Generated {} permutations", permutations.len());

      // DNS bruteforce permutations
      match self.enumerate_dns_bruteforce_with_wordlist(&permutations) {
        Ok(perm_results) => {
          let filtered_results = self.filter_wildcard_results(perm_results);
          let new_count = filtered_results.len();
          if new_count > 0 {
            progressln!(
              "  │  ├─ ✅ Permutations revealed {} NEW subdomains!",
              new_count
            );
            for result in filtered_results {
              if all_found.insert(result.subdomain.clone()) {
                queue.push_back(result.subdomain.clone()); // ← RECURSIVE: new finds go back to queue!
                results.push(result);
              }
            }
          } else {
            progressln!("  │  ├─ No new subdomains from permutations");
          }
        }
        Err(e) => progressln!("  │  ├─ ⚠️  Permutation bruteforce failed: {}", e),
      }
    }

    if iteration >= max_iterations {
      progressln!("  └─ Stopped at max iterations ({})\n", max_iterations);
    } else {
      progressln!("  └─ Queue exhausted: no more new discoveries\n");
    }

    // ==== PHASE 3: Final Wordlist Bruteforce ====
    progressln!("🔍 [Phase 3] Comprehensive DNS Bruteforce");
    progressln!(
      "  ├─ Using SecLists wordlist ({} entries)",
      self.wordlist.len()
    );

    match self.enumerate_dns_bruteforce_with_wordlist(&self.wordlist) {
      Ok(dns_results) => {
        let filtered_results = self.filter_wildcard_results(dns_results);
        let new_count = filtered_results
          .iter()
          .filter(|r| all_found.insert(r.subdomain.clone()))
          .count();
        progressln!(
          "  └─ ✅ Found {} NEW subdomains via DNS bruteforce",
          new_count
        );

        for result in filtered_results {
          if all_found.contains(&result.subdomain) {
            results.push(result);
          }
        }
      }
      Err(e) => progressln!("  └─ ⚠️  DNS bruteforce failed: {}", e),
    }

    // ==== FINAL: Deduplicate and Sort ====
    let mut seen = HashSet::new();
    results.retain(|r| seen.insert(r.subdomain.clone()));
    results.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));

    progressln!("\n✅ Total unique subdomains discovered: {}", results.len());

    // Emit synergy events for cross-module integration
    emit_subdomain_events(&self.domain, &results);

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
                cname_chain: vec![],
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

  /// Enumerate via AlienVault OTX (passive DNS data, no API key for basic access)
  pub fn enumerate_alienvault_otx(&self) -> Result<Vec<SubdomainResult>, String> {
    let mut results = Vec::new();

    // AlienVault OTX provides passive DNS data
    let url = format!(
      "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
      self.domain
    );
    let http_client = HttpClient::new();

    match http_client.get(&url) {
      Ok(response) => {
        let body_str = String::from_utf8_lossy(&response.body);

        // Parse JSON response to extract subdomains
        // Format: {"passive_dns": [{"hostname": "subdomain.domain.com", "address": "1.2.3.4", ...}]}
        let mut seen = HashSet::new();
        for line in body_str.split("\"hostname\":\"") {
          if let Some(end) = line.find('"') {
            let hostname = line[..end].to_lowercase();
            if hostname.ends_with(&self.domain) && seen.insert(hostname.clone()) {
              // Try to extract IP address
              let mut ip = String::new();
              if let Some(addr_start) = line.find("\"address\":\"") {
                let addr_part = &line[addr_start + 11..];
                if let Some(addr_end) = addr_part.find('"') {
                  ip = addr_part[..addr_end].to_string();
                }
              }

              results.push(SubdomainResult {
                subdomain: hostname,
                ips: if ip.is_empty() { vec![] } else { vec![ip] },
                cname_chain: vec![],
                source: EnumerationSource::AlienVaultOtx,
              });
            }
          }
        }
      }
      Err(e) => return Err(format!("AlienVault OTX query failed: {}", e)),
    }

    Ok(results)
  }

  /// Enumerate via ThreatCrowd (free, no API key required)
  pub fn enumerate_threatcrowd(&self) -> Result<Vec<SubdomainResult>, String> {
    let mut results = Vec::new();

    // ThreatCrowd provides subdomain data
    let url = format!(
      "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}",
      self.domain
    );
    let http_client = HttpClient::new();

    match http_client.get(&url) {
      Ok(response) => {
        let body_str = String::from_utf8_lossy(&response.body);

        // Parse JSON response: {"subdomains": ["sub1.domain.com", "sub2.domain.com"]}
        if let Some(start) = body_str.find("\"subdomains\":[") {
          let rest = &body_str[start + 14..];
          if let Some(end) = rest.find(']') {
            let subs_str = &rest[..end];
            for sub in subs_str.split(',') {
              let subdomain = sub.trim().trim_matches('"').to_lowercase();
              if !subdomain.is_empty() && subdomain.ends_with(&self.domain) {
                // Resolve IPs and CNAME
                let (ips, cname_chain) = self.resolve_with_cname_chain(&subdomain);
                results.push(SubdomainResult {
                  subdomain,
                  ips,
                  cname_chain,
                  source: EnumerationSource::ThreatCrowd,
                });
              }
            }
          }
        }
      }
      Err(e) => return Err(format!("ThreatCrowd query failed: {}", e)),
    }

    Ok(results)
  }

  /// Enumerate via Wayback Machine (archive.org CDX API)
  pub fn enumerate_wayback(&self) -> Result<Vec<SubdomainResult>, String> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();

    // Wayback Machine CDX API to find archived URLs
    let url = format!(
            "http://web.archive.org/cdx/search/cdx?url=*.{}&output=text&fl=original&collapse=urlkey&limit=500",
            self.domain
        );
    let http_client = HttpClient::new();

    match http_client.get(&url) {
      Ok(response) => {
        let body_str = String::from_utf8_lossy(&response.body);

        // Each line is a URL, extract subdomain from it
        for line in body_str.lines() {
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
            .unwrap_or("");

          // Remove port if present
          let subdomain = hostname.split(':').next().unwrap_or("").to_lowercase();

          if !subdomain.is_empty()
            && subdomain.ends_with(&self.domain)
            && seen.insert(subdomain.clone())
          {
            // Resolve IPs and CNAME
            let (ips, cname_chain) = self.resolve_with_cname_chain(&subdomain);
            results.push(SubdomainResult {
              subdomain,
              ips,
              cname_chain,
              source: EnumerationSource::WaybackMachine,
            });
          }
        }
      }
      Err(e) => return Err(format!("Wayback Machine query failed: {}", e)),
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

  /// Enumerate subdomains from Certificate Transparency logs (crt.sh)
  pub fn enumerate_ct_logs(&self) -> Result<Vec<SubdomainResult>, String> {
    let crtsh_client = CrtShClient::new();

    match crtsh_client.query_subdomains(&self.domain) {
      Ok(subdomains) => {
        let results: Vec<SubdomainResult> = subdomains
          .into_iter()
          .map(|subdomain| {
            // Resolve IPs and follow CNAME chain for each subdomain
            let (ips, cname_chain) = self.resolve_with_cname_chain(&subdomain);
            SubdomainResult {
              subdomain,
              ips,
              cname_chain,
              source: EnumerationSource::CertificateTransparency,
            }
          })
          .collect();

        Ok(results)
      }
      Err(e) => Err(format!("crt.sh query failed: {}", e)),
    }
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
      let wildcard_ips_filter = self.wildcard_ips.clone(); // Clone for thread

      let handle = thread::spawn(move || {
        for prefix in chunk {
          let subdomain = format!("{}.{}", prefix, domain);

          let (ips, cname_chain) = resolve_candidate_for(&resolver_addr, dns_timeout, &subdomain);

          if !ips.is_empty() {
            // Apply wildcard filtering
            if !wildcard_ips_filter.is_empty()
              && ips.iter().any(|ip| wildcard_ips_filter.contains(ip))
            {
              continue; // Skip if any IP matches a wildcard IP
            }

            let result = SubdomainResult {
              subdomain: subdomain.clone(),
              ips,
              cname_chain,
              source: EnumerationSource::DnsBruteforce,
            };

            if let Ok(mut results) = results.lock() {
              results.push(result);
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
    let chunk_size = wordlist.len().div_ceil(self.threads);
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
      let wildcard_ips_filter = self.wildcard_ips.clone(); // Clone for thread

      let handle = thread::spawn(move || {
        for prefix in chunk {
          let subdomain = format!("{}.{}", prefix, domain);

          let (ips, cname_chain) = resolve_candidate_for(&resolver_addr, dns_timeout, &subdomain);

          if !ips.is_empty() {
            // Apply wildcard filtering
            if !wildcard_ips_filter.is_empty()
              && ips.iter().any(|ip| wildcard_ips_filter.contains(ip))
            {
              continue; // Skip if any IP matches a wildcard IP
            }

            let result = SubdomainResult {
              subdomain: subdomain.clone(),
              ips,
              cname_chain,
              source: EnumerationSource::DnsBruteforce,
            };

            if let Ok(mut results) = results.lock() {
              results.push(result);
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

  /// Re-resolve discovered subdomains and keep only the ones that currently
  /// return at least one A or AAAA record.
  pub fn validate_results(&self, results: Vec<SubdomainResult>) -> Vec<SubdomainResult> {
    if results.is_empty() {
      return Vec::new();
    }

    let resolver_addr = config::get().network.dns_resolver.clone();
    let timeout_ms = self.timeout_ms;
    let worker_count = self.threads.max(1);
    let chunk_size = results.len().div_ceil(worker_count);
    let validated = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for chunk in results.chunks(chunk_size.max(1)) {
      let chunk = chunk.to_vec();
      let resolver_addr = resolver_addr.clone();
      let validated = Arc::clone(&validated);

      let handle = thread::spawn(move || {
        let mut local = Vec::new();
        for mut result in chunk {
          let (ips, cname_chain) =
            resolve_with_cname_chain_for(&resolver_addr, timeout_ms, &result.subdomain);
          if ips.is_empty() {
            continue;
          }
          result.ips = ips;
          result.cname_chain = cname_chain;
          local.push(result);
        }

        if let Ok(mut validated) = validated.lock() {
          validated.extend(local);
        }
      });

      handles.push(handle);
    }

    for handle in handles {
      let _ = handle.join();
    }

    let mut validated = validated.lock().unwrap().clone();
    validated.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));
    validated
  }

  /// Resolve domain to IP addresses
  fn resolve_domain(&self, domain: &str) -> Vec<String> {
    let resolver_addr = config::get().network.dns_resolver.clone();
    let dns_client = DnsClient::new(&resolver_addr).with_timeout(self.timeout_ms);
    query_ip_records(&dns_client, domain)
  }

  /// Resolve domain with CNAME chain following
  /// Returns (final_ips, cname_chain)
  fn resolve_with_cname_chain(&self, domain: &str) -> (Vec<String>, Vec<String>) {
    let resolver_addr = config::get().network.dns_resolver.clone();
    resolve_with_cname_chain_for(&resolver_addr, self.timeout_ms, domain)
  }

  /// Split wordlist into chunks for multi-threading
  fn chunk_wordlist(&self, num_chunks: usize) -> Vec<Vec<String>> {
    let chunk_size = self.wordlist.len().div_ceil(num_chunks);
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

  /// Emit enumeration results to the intelligence graph
  ///
  /// This method populates the graph with:
  /// - Domain nodes for the target domain and subdomains
  /// - Host nodes for resolved IP addresses
  /// - Domain-to-Host edges for DNS resolution relationships
  /// - Domain-to-Domain edges for parent-child relationships
  ///
  /// # Arguments
  /// * `results` - Enumeration results to emit
  /// * `emitter` - Optional emitter (uses global if None)
  pub fn emit_to_graph(&self, results: &[SubdomainResult], emitter: Option<&GraphEmitter>) {
    let global_emitter;
    let emitter = match emitter {
      Some(e) => e,
      None => {
        global_emitter = GraphEmitter::global();
        &*global_emitter
      }
    };

    // Emit parent domain
    emitter.emit_domain(&self.domain, None);

    for result in results {
      // Emit subdomain linked to parent
      let parent = if result.subdomain != self.domain {
        Some(self.domain.as_str())
      } else {
        None
      };
      emitter.emit_domain(&result.subdomain, parent);

      // Emit hosts and link to domain
      for ip in &result.ips {
        emitter.emit_domain_host(&result.subdomain, ip);
      }

      // Emit CNAME chain as related domains
      for cname in &result.cname_chain {
        emitter.emit_domain(cname, Some(&result.subdomain));
      }
    }
  }

  /// Enumerate all and automatically emit to graph
  ///
  /// Combines `enumerate_all()` with `emit_to_graph()` for convenience.
  pub fn enumerate_all_with_graph(&mut self) -> Result<Vec<SubdomainResult>, String> {
    let results = self.enumerate_all()?;
    self.emit_to_graph(&results, None);
    Ok(results)
  }
}

fn query_ip_records(client: &DnsClient, domain: &str) -> Vec<String> {
  let mut seen = HashSet::new();
  let mut ips = Vec::new();

  for record_type in [DnsRecordType::A, DnsRecordType::AAAA] {
    if let Ok(answers) = client.query(domain, record_type) {
      for answer in answers {
        if let Some(ip) = answer.as_ip() {
          if seen.insert(ip.clone()) {
            ips.push(ip);
          }
        }
      }
    }
  }

  ips
}

fn resolve_with_cname_chain_for(
  resolver_addr: &str,
  timeout_ms: u64,
  domain: &str,
) -> (Vec<String>, Vec<String>) {
  let dns_client = DnsClient::new(resolver_addr).with_timeout(timeout_ms);
  let mut cname_chain: Vec<String> = Vec::new();
  let mut current_domain = domain.to_string();
  let mut visited: HashSet<String> = HashSet::new();
  let max_cname_depth = 10;

  for _ in 0..max_cname_depth {
    if visited.contains(&current_domain) {
      break;
    }
    visited.insert(current_domain.clone());

    match dns_client.query(&current_domain, DnsRecordType::CNAME) {
      Ok(answers) => {
        let cnames: Vec<String> = answers
          .iter()
          .filter_map(|answer| answer.as_cname())
          .collect();

        if cnames.is_empty() {
          break;
        }

        let next_cname = cnames[0].clone();
        cname_chain.push(next_cname.clone());
        current_domain = next_cname;
      }
      Err(_) => break,
    }
  }

  let ips = query_ip_records(&dns_client, &current_domain);
  (ips, cname_chain)
}

fn resolve_candidate_for(
  resolver_addr: &str,
  timeout_ms: u64,
  domain: &str,
) -> (Vec<String>, Vec<String>) {
  let dns_client = DnsClient::new(resolver_addr).with_timeout(timeout_ms);
  let direct_ips = query_ip_records(&dns_client, domain);
  if !direct_ips.is_empty() {
    return (direct_ips, Vec::new());
  }

  resolve_with_cname_chain_for(resolver_addr, timeout_ms, domain)
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

/// Emit synergy events for discovered subdomains
///
/// This enables cross-module integration where other modules can subscribe
/// to subdomain discoveries and trigger automated actions:
/// - Port scanning on newly discovered hosts
/// - TLS certificate analysis on new domains
/// - Web crawling for discovered subdomains
fn emit_subdomain_events(parent_domain: &str, results: &[SubdomainResult]) {
  for result in results {
    // Emit subdomain discovery event (using host entity type for domains)
    let event = Event::new(EventType::Discovery, "recon::subdomain")
      .with_entity(EntityRef::host(&result.subdomain).with_label("subdomain"))
      .with_data("parent_domain", parent_domain)
      .with_data("source", &result.source.to_string())
      .with_data("subdomain", &result.subdomain);

    emit(event);

    // Emit host discovery events for each resolved IP
    for ip in &result.ips {
      let host_event = Event::new(EventType::Discovery, "recon::subdomain")
        .with_entity(EntityRef::host(ip))
        .with_data("resolved_from", &result.subdomain)
        .with_data("ip", ip);

      emit(host_event);
    }

    // Emit CNAME chain as additional discovery data
    if !result.cname_chain.is_empty() {
      let cname_event = Event::new(EventType::Discovery, "recon::subdomain")
        .with_entity(EntityRef::host(&result.subdomain).with_label("cname"))
        .with_data("cname_chain", &result.cname_chain.join(" -> "))
        .with_data(
          "final_cname",
          result.cname_chain.last().unwrap_or(&String::new()),
        );

      emit(cname_event);
    }
  }
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
        cname_chain: vec![],
        source: EnumerationSource::DnsBruteforce,
      },
      SubdomainResult {
        subdomain: "www.example.com".to_string(),
        ips: vec!["1.2.3.5".to_string()],
        cname_chain: vec![],
        source: EnumerationSource::CertificateTransparency,
      },
      SubdomainResult {
        subdomain: "mail.example.com".to_string(),
        ips: vec!["1.2.3.6".to_string()],
        cname_chain: vec![],
        source: EnumerationSource::DnsBruteforce,
      },
    ];

    let unique = enumerator.deduplicate_results(results);
    assert_eq!(unique.len(), 2);
  }
}
