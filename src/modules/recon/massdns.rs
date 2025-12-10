/// Mass DNS Bruteforce Module
///
/// High-performance subdomain enumeration via DNS bruteforce:
/// - Multi-threaded DNS resolution
/// - Wordlist-based subdomain discovery
/// - Wildcard detection and filtering
/// - Rate limiting to avoid detection
///
/// NO external dependencies - pure Rust std implementation
use crate::protocols::dns::{DnsClient, DnsRecordType};
use std::collections::HashSet;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Resolved subdomain with DNS data
#[derive(Debug, Clone)]
pub struct ResolvedSubdomain {
    pub subdomain: String,
    pub ips: Vec<String>,
    pub cname: Option<String>,
    pub resolve_time_ms: u64,
}

/// Mass DNS bruteforce configuration
#[derive(Debug, Clone)]
pub struct MassDnsConfig {
    /// Number of worker threads
    pub threads: usize,
    /// Timeout for each DNS query
    pub timeout: Duration,
    /// Delay between queries (rate limiting)
    pub delay: Duration,
    /// DNS resolvers to use
    pub resolvers: Vec<String>,
    /// Maximum retries for failed queries
    pub retries: usize,
    /// Enable wildcard detection and filtering
    pub filter_wildcards: bool,
}

impl Default for MassDnsConfig {
    fn default() -> Self {
        Self {
            threads: 10,
            timeout: Duration::from_secs(2),
            delay: Duration::from_millis(10),
            resolvers: vec![
                "8.8.8.8".to_string(),
                "1.1.1.1".to_string(),
                "9.9.9.9".to_string(),
            ],
            retries: 2,
            filter_wildcards: true,
        }
    }
}

/// Mass DNS scan result
#[derive(Debug)]
pub struct MassDnsResult {
    pub domain: String,
    pub resolved: Vec<ResolvedSubdomain>,
    pub total_attempts: usize,
    pub wildcard_detected: bool,
    pub wildcard_ips: Vec<String>,
    pub duration_ms: u64,
    pub errors: Vec<String>,
}

/// Mass DNS bruteforce scanner
pub struct MassDnsScanner {
    config: MassDnsConfig,
}

impl MassDnsScanner {
    pub fn new() -> Self {
        Self {
            config: MassDnsConfig::default(),
        }
    }

    pub fn with_config(config: MassDnsConfig) -> Self {
        Self { config }
    }

    /// Set number of threads
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.config.threads = threads.max(1).min(100); // Cap between 1 and 100
        self
    }

    /// Set custom resolvers
    pub fn with_resolvers(mut self, resolvers: Vec<String>) -> Self {
        if !resolvers.is_empty() {
            self.config.resolvers = resolvers;
        }
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Set rate limit delay
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.config.delay = delay;
        self
    }

    /// Enable/disable wildcard filtering
    pub fn with_wildcard_filter(mut self, enabled: bool) -> Self {
        self.config.filter_wildcards = enabled;
        self
    }

    /// Run mass DNS bruteforce with a wordlist
    pub fn bruteforce(
        &self,
        domain: &str,
        wordlist: &[String],
    ) -> Result<MassDnsResult, String> {
        let start = Instant::now();
        let total_attempts = wordlist.len();

        // Step 1: Detect wildcard DNS
        let (wildcard_detected, wildcard_ips) = if self.config.filter_wildcards {
            self.detect_wildcard(domain)
        } else {
            (false, Vec::new())
        };

        // Step 2: Create work queue
        let work_queue: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(
            wordlist.iter().cloned().collect()
        ));

        // Step 3: Results channel
        let (tx, rx) = channel::<ResolvedSubdomain>();

        // Step 4: Error collection
        let errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        // Step 5: Spawn worker threads
        let mut handles = Vec::new();
        let domain = domain.to_string();
        let config = self.config.clone();
        let wildcard_ips_clone = wildcard_ips.clone();

        for thread_id in 0..self.config.threads {
            let queue = Arc::clone(&work_queue);
            let tx = tx.clone();
            let errors = Arc::clone(&errors);
            let domain = domain.clone();
            let config = config.clone();
            let wildcard_ips = wildcard_ips_clone.clone();
            let resolver = config.resolvers[thread_id % config.resolvers.len()].clone();

            let handle = thread::spawn(move || {
                let client = DnsClient::new(&resolver)
                    .with_timeout(config.timeout.as_millis() as u64);

                loop {
                    // Get next word from queue
                    let word = {
                        let mut queue = queue.lock().unwrap();
                        queue.pop()
                    };

                    let word = match word {
                        Some(w) => w,
                        None => break, // Queue empty, exit
                    };

                    // Build subdomain
                    let subdomain = format!("{}.{}", word, domain);

                    // Resolve with retries
                    let start = Instant::now();
                    let mut ips = Vec::new();
                    let mut cname = None;

                    for _ in 0..=config.retries {
                        match client.query(&subdomain, DnsRecordType::A) {
                            Ok(answers) => {
                                // Extract IP addresses from A records using as_ip()
                                for answer in answers {
                                    if let Some(ip) = answer.as_ip() {
                                        ips.push(ip);
                                    }
                                }
                                break;
                            }
                            Err(e) => {
                                if e.contains("NXDOMAIN") || e.contains("no answers") {
                                    // Domain doesn't exist, no need to retry
                                    break;
                                }
                                // Retry on timeout or other errors
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                    }

                    // Try CNAME if no A records
                    if ips.is_empty() {
                        if let Ok(answers) = client.query(&subdomain, DnsRecordType::CNAME) {
                            for answer in &answers {
                                // Extract CNAME target from data
                                if let crate::protocols::dns::DnsRdata::CNAME(target) = &answer.data {
                                    cname = Some(target.clone());
                                    // Try to resolve CNAME target
                                    if let Ok(a_answers) = client.query(target, DnsRecordType::A) {
                                        for a_answer in a_answers {
                                            if let Some(ip) = a_answer.as_ip() {
                                                ips.push(ip);
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }

                    let resolve_time = start.elapsed().as_millis() as u64;

                    // Skip if no results
                    if ips.is_empty() && cname.is_none() {
                        continue;
                    }

                    // Filter wildcards
                    if config.filter_wildcards && !wildcard_ips.is_empty() {
                        // Check if all IPs are wildcard IPs
                        let is_wildcard = ips.iter().all(|ip| wildcard_ips.contains(ip));
                        if is_wildcard && cname.is_none() {
                            continue;
                        }
                    }

                    // Send result
                    let _ = tx.send(ResolvedSubdomain {
                        subdomain,
                        ips,
                        cname,
                        resolve_time_ms: resolve_time,
                    });

                    // Rate limiting
                    if !config.delay.is_zero() {
                        thread::sleep(config.delay);
                    }
                }
            });

            handles.push(handle);
        }

        // Drop sender to allow receiver to complete
        drop(tx);

        // Collect results
        let mut resolved: Vec<ResolvedSubdomain> = rx.iter().collect();

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        // Sort by subdomain
        resolved.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));

        // Deduplicate
        let mut seen = HashSet::new();
        resolved.retain(|r| seen.insert(r.subdomain.clone()));

        let duration_ms = start.elapsed().as_millis() as u64;
        let errors = Arc::try_unwrap(errors)
            .unwrap_or_else(|e| e.lock().unwrap().clone().into())
            .into_inner()
            .unwrap();

        Ok(MassDnsResult {
            domain: domain.to_string(),
            resolved,
            total_attempts,
            wildcard_detected,
            wildcard_ips,
            duration_ms,
            errors,
        })
    }

    /// Detect wildcard DNS by querying random non-existent subdomains
    fn detect_wildcard(&self, domain: &str) -> (bool, Vec<String>) {
        let resolver = &self.config.resolvers[0];
        let client = DnsClient::new(resolver)
            .with_timeout(self.config.timeout.as_millis() as u64);

        // Generate random subdomain names that shouldn't exist
        let random_subdomains = [
            format!("wildcard-test-{}.{}", random_string(16), domain),
            format!("nonexistent-{}.{}", random_string(12), domain),
            format!("randomxyz-{}.{}", random_string(10), domain),
        ];

        let mut wildcard_ips: HashSet<String> = HashSet::new();
        let mut resolved_count = 0;

        for subdomain in &random_subdomains {
            if let Ok(answers) = client.query(subdomain, DnsRecordType::A) {
                if !answers.is_empty() {
                    resolved_count += 1;
                    for answer in answers {
                        if let Some(ip) = answer.as_ip() {
                            wildcard_ips.insert(ip);
                        }
                    }
                }
            }
        }

        // If 2+ random subdomains resolve to the same IPs, it's a wildcard
        let is_wildcard = resolved_count >= 2 && !wildcard_ips.is_empty();

        (is_wildcard, wildcard_ips.into_iter().collect())
    }
}

impl Default for MassDnsScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a random alphanumeric string
fn random_string(len: usize) -> String {
    use std::time::SystemTime;

    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let mut result = String::with_capacity(len);
    let mut state = seed;

    for _ in 0..len {
        // Simple LCG random number generator
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let idx = (state >> 32) as usize % chars.len();
        result.push(chars[idx]);
    }

    result
}

/// Built-in common subdomain wordlist
pub fn common_subdomains() -> Vec<String> {
    vec![
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
        "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
        "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
        "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
        "web", "media", "email", "images", "img", "www1", "intranet", "portal", "video",
        "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns", "search",
        "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1", "sites",
        "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover", "info",
        "apps", "download", "remote", "db", "forums", "store", "relay", "files", "newsletter",
        "app", "live", "owa", "en", "start", "sms", "office", "exchange", "ipv4", "mail3",
        "help", "blogs", "helpdesk", "web1", "home", "library", "ftp2", "ntp", "monitor",
        "login", "service", "correo", "www4", "moodle", "it", "gateway", "gw", "i",
        "stat", "stage", "ldap", "tv", "ssl", "web2", "ns5", "upload", "nagios", "smtp2",
        "online", "ad", "survey", "data", "radio", "extranet", "test2", "mssql", "dns3",
        "jobs", "services", "panel", "irc", "hosting", "cloud", "de", "gmail", "s",
        "bbs", "cs", "ww", "mrtg", "git", "image", "members", "poczta", "s1", "meet",
        "preview", "fr", "cloudflare-resolve-to", "dev2", "photo", "jabber", "legacy",
        "go", "es", "ssh", "redmine", "partner", "vps", "server1", "sv", "ns6", "webmail2",
        "av", "community", "cacti", "time", "sftp", "lib", "facebook", "www5", "smtp1",
        "feeds", "w", "games", "ts", "alumni", "dl", "s2", "phpmyadmin", "archive",
        "cn", "tools", "stream", "projects", "elearning", "im", "iphone", "control",
        "voip", "test1", "ws", "rss", "sp", "wwww", "vpn2", "jira", "list", "connect",
        "gallery", "billing", "mailer", "update", "pda", "game", "ns0", "testing", "sandbox",
        "job", "events", "dialin", "ml", "fb", "videos", "music", "a", "partners",
        "mailhost", "downloads", "reports", "ca", "router", "speedtest", "local", "training",
        "edu", "bugs", "manage", "s3", "status", "host2", "ww2", "marketing", "conference",
        "content", "network-ede", "external", "accounts", "in", "pgsql", "oc", "jenkins",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Load wordlist from file
pub fn load_wordlist(path: &str) -> Result<Vec<String>, String> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(path).map_err(|e| format!("Failed to open wordlist: {}", e))?;
    let reader = BufReader::new(file);

    let words: Vec<String> = reader
        .lines()
        .filter_map(|line| line.ok())
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    if words.is_empty() {
        return Err("Wordlist is empty".to_string());
    }

    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_string() {
        let s1 = random_string(10);
        let s2 = random_string(10);

        assert_eq!(s1.len(), 10);
        assert_eq!(s2.len(), 10);
        // Note: These could be equal by chance, but very unlikely
        // Just ensure they're valid alphanumeric
        assert!(s1.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_common_subdomains() {
        let wordlist = common_subdomains();
        assert!(!wordlist.is_empty());
        assert!(wordlist.contains(&"www".to_string()));
        assert!(wordlist.contains(&"mail".to_string()));
        assert!(wordlist.contains(&"api".to_string()));
    }

    #[test]
    fn test_config_defaults() {
        let config = MassDnsConfig::default();
        assert_eq!(config.threads, 10);
        assert_eq!(config.retries, 2);
        assert!(config.filter_wildcards);
        assert!(!config.resolvers.is_empty());
    }

    #[test]
    fn test_scanner_builder() {
        let scanner = MassDnsScanner::new()
            .with_threads(20)
            .with_timeout(Duration::from_secs(5))
            .with_delay(Duration::from_millis(50));

        assert_eq!(scanner.config.threads, 20);
        assert_eq!(scanner.config.timeout, Duration::from_secs(5));
        assert_eq!(scanner.config.delay, Duration::from_millis(50));
    }
}
