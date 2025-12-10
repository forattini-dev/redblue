use crate::protocols::dns::{DnsClient, DnsRecordType};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::collections::HashSet;
use crate::cli::output::ProgressBar; // Import ProgressBar

#[derive(Debug, Clone)]
pub struct BruteforceResult {
    pub subdomain: String,
    pub ips: Vec<String>,
    pub cnames: Vec<String>,
    pub resolved_by: String,
    pub latency: Duration,
}

#[derive(Debug, Clone)]
struct ResolverState {
    addr: String,
    failures: usize,
    active: bool,
}

pub struct SubdomainBruteforcer {
    domain: String,
    resolvers: Arc<Mutex<Vec<ResolverState>>>,
    wordlist: Vec<String>,
    threads: usize,
    wildcard_detection: bool,
    wildcard_ips: HashSet<String>,
    retries: usize,
}

impl SubdomainBruteforcer {
    pub fn new(domain: &str, wordlist: Vec<String>) -> Self {
        let default_resolvers = vec![
            "8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53",
            "208.67.222.222:53", "8.8.4.4:53"
        ];
        
        let states = default_resolvers.iter()
            .map(|r| ResolverState { addr: r.to_string(), failures: 0, active: true })
            .collect();

        Self {
            domain: domain.to_string(),
            wordlist,
            resolvers: Arc::new(Mutex::new(states)),
            threads: 20,
            wildcard_detection: true,
            wildcard_ips: HashSet::new(),
            retries: 2,
        }
    }

    pub fn with_resolvers(mut self, resolvers: Vec<String>) -> Self {
        let states = resolvers.iter()
            .map(|r| ResolverState { addr: r.to_string(), failures: 0, active: true })
            .collect();
        self.resolvers = Arc::new(Mutex::new(states));
        self
    }

    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads;
        self
    }

    pub fn with_wildcard_detection(mut self, enabled: bool) -> Self {
        self.wildcard_detection = enabled;
        self
    }

    /// Initialize wildcard detection
    pub fn detect_wildcards(&mut self) -> Result<(), String> {
        if !self.wildcard_detection {
            return Ok(());
        }

        // Generate random prefix using system time as PRNG seed
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let rand_prefix: String = (0..10).enumerate().map(|(i, _)| {
            let x = seed.wrapping_mul(6364136223846793005u64).wrapping_add(i as u64 * 1442695040888963407u64);
            ((x >> 32) as u8 % 26 + b'a') as char
        }).collect();
        let probe_domain = format!("{}.{}", rand_prefix, self.domain);
        
        // Try to resolve a random subdomain
        let resolvers = self.resolvers.lock().unwrap();
        if let Some(resolver) = resolvers.first() {
            let client = DnsClient::new(&resolver.addr);
            if let Ok(answers) = client.query(&probe_domain, DnsRecordType::A) {
                for ans in answers {
                    if let Some(ip) = ans.as_ip() {
                        self.wildcard_ips.insert(ip);
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Get a healthy resolver round-robin
    fn get_resolver(&self, index: usize) -> Option<String> {
        let mut resolvers = self.resolvers.lock().unwrap();
        let count = resolvers.len();
        if count == 0 { return None; }
        
        // Simple attempt to find an active one starting from index
        for i in 0..count {
            let idx = (index + i) % count;
            if resolvers[idx].active {
                return Some(resolvers[idx].addr.clone());
            }
        }
        None
    }

    /// Report resolver failure
    fn report_failure(&self, addr: &str) {
        let mut resolvers = self.resolvers.lock().unwrap();
        if let Some(res) = resolvers.iter_mut().find(|r| r.addr == addr) {
            res.failures += 1;
            if res.failures > 5 {
                res.active = false;
            }
        }
    }

    /// Run the bruteforce enumeration
    pub fn run(&self, progress_bar: Arc<ProgressBar>) -> Vec<BruteforceResult> {
        let results = Arc::new(Mutex::new(Vec::new()));
        let wordlist = self.wordlist.clone();
        let chunk_size = (wordlist.len() + self.threads - 1) / self.threads;
        let chunks: Vec<Vec<String>> = wordlist.chunks(chunk_size).map(|c| c.to_vec()).collect();
        
        let wildcard_ips = self.wildcard_ips.clone();
        let domain = self.domain.clone();
        let retries = self.retries;

        // We need self to be cloneable or wrapped, but it has Arc inside.
        // We can't clone self into threads easily if we want to share the `resolvers` logic method.
        // So we clone the Arcs.
        let resolvers_arc = self.resolvers.clone();

        let mut handles = vec![];

        for (thread_idx, chunk) in chunks.into_iter().enumerate() {
            let results = Arc::clone(&results);
            let wildcard_ips = wildcard_ips.clone();
            let domain = domain.clone();
            let resolvers_arc = resolvers_arc.clone();
            let progress_bar = Arc::clone(&progress_bar);

            let handle = thread::spawn(move || {
                // Helper to get resolver inside thread
                let get_res = |idx: usize| -> Option<String> {
                    let mut resolvers = resolvers_arc.lock().unwrap();
                    let count = resolvers.len();
                    for i in 0..count {
                        let idx = (idx + i) % count;
                        if resolvers[idx].active {
                            return Some(resolvers[idx].addr.clone());
                        }
                    }
                    None
                };

                let report_fail = |addr: &str| {
                    let mut resolvers = resolvers_arc.lock().unwrap();
                    if let Some(res) = resolvers.iter_mut().find(|r| r.addr == addr) {
                        res.failures += 1;
                        if res.failures > 5 {
                            res.active = false;
                        }
                    }
                };

                for (i, prefix) in chunk.iter().enumerate() {
                    let subdomain = format!("{}.{}", prefix, domain);
                    let mut attempts = 0;
                    
                    while attempts <= retries {
                        if let Some(resolver) = get_res(thread_idx + i + attempts) {
                            let client = DnsClient::new(&resolver);
                            let start = Instant::now();
                            
                            match client.query(&subdomain, DnsRecordType::A) {
                                Ok(answers) => {
                                    let mut ips = Vec::new();
                                    let mut cnames = Vec::new();
                                    
                                    for ans in answers {
                                        if let Some(ip) = ans.as_ip() {
                                            if !wildcard_ips.contains(&ip) {
                                                ips.push(ip);
                                            }
                                        }
                                    }
                                    
                                    if !ips.is_empty() {
                                        let result = BruteforceResult {
                                            subdomain: subdomain.clone(),
                                            ips,
                                            cnames,
                                            resolved_by: resolver.clone(),
                                            latency: start.elapsed(),
                                        };
                                        
                                        if let Ok(mut res) = results.lock() {
                                            res.push(result);
                                        }
                                    }
                                    break; // Success
                                }
                                Err(_) => {
                                    attempts += 1;
                                    report_fail(&resolver);
                                    // Retry with next resolver
                                }
                            }
                        } else {
                            break; // No resolvers left
                        }
                    }
                    progress_bar.tick(1);
                }
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.join();
        }

        let final_results = results.lock().unwrap().clone();
        final_results
    }
}