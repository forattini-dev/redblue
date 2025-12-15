//! DNS Response Cache
//!
//! Implements TTL-aware caching for DNS responses.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Cached DNS entry
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Record type
    pub rtype: u16,
    /// Cached addresses
    pub addresses: Vec<IpAddr>,
    /// Other data (CNAME, MX, etc.)
    pub data: Vec<String>,
    /// Time when entry was cached
    pub cached_at: Instant,
    /// Original TTL
    pub ttl: u32,
    /// Minimum TTL (for aggressive caching)
    pub min_ttl: u32,
}

impl CacheEntry {
    /// Create new cache entry
    pub fn new(rtype: u16, ttl: u32) -> Self {
        Self {
            rtype,
            addresses: Vec::new(),
            data: Vec::new(),
            cached_at: Instant::now(),
            ttl,
            min_ttl: 60, // Minimum 60 seconds
        }
    }

    /// Add an IP address
    pub fn add_address(&mut self, addr: IpAddr) {
        if !self.addresses.contains(&addr) {
            self.addresses.push(addr);
        }
    }

    /// Add string data (CNAME, MX, etc.)
    pub fn add_data(&mut self, data: String) {
        if !self.data.contains(&data) {
            self.data.push(data);
        }
    }

    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        let effective_ttl = self.ttl.max(self.min_ttl);
        self.cached_at.elapsed() > Duration::from_secs(effective_ttl as u64)
    }

    /// Get remaining TTL
    pub fn remaining_ttl(&self) -> u32 {
        let effective_ttl = self.ttl.max(self.min_ttl);
        let elapsed = self.cached_at.elapsed().as_secs() as u32;
        effective_ttl.saturating_sub(elapsed)
    }
}

/// Cache key
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub domain: String,
    pub rtype: u16,
}

impl CacheKey {
    pub fn new(domain: &str, rtype: u16) -> Self {
        Self {
            domain: domain.to_lowercase(),
            rtype,
        }
    }
}

/// DNS cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries
    pub max_entries: usize,
    /// Default TTL for entries without TTL
    pub default_ttl: u32,
    /// Minimum TTL (override low TTLs)
    pub min_ttl: u32,
    /// Maximum TTL (cap high TTLs)
    pub max_ttl: u32,
    /// Enable negative caching (NXDOMAIN)
    pub negative_cache: bool,
    /// Negative cache TTL
    pub negative_ttl: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10000,
            default_ttl: 300,
            min_ttl: 60,
            max_ttl: 86400,
            negative_cache: true,
            negative_ttl: 60,
        }
    }
}

/// DNS cache
pub struct DnsCache {
    entries: Arc<RwLock<HashMap<CacheKey, CacheEntry>>>,
    config: CacheConfig,
    stats: Arc<RwLock<CacheStats>>,
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub inserts: u64,
    pub evictions: u64,
    pub expirations: u64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

impl DnsCache {
    /// Create new cache with default config
    pub fn new() -> Self {
        Self::with_config(CacheConfig::default())
    }

    /// Create cache with custom config
    pub fn with_config(config: CacheConfig) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    /// Get entry from cache
    pub fn get(&self, domain: &str, rtype: u16) -> Option<CacheEntry> {
        let key = CacheKey::new(domain, rtype);
        let entries = self.entries.read().ok()?;

        if let Some(entry) = entries.get(&key) {
            if !entry.is_expired() {
                let mut stats = self.stats.write().ok()?;
                stats.hits += 1;
                return Some(entry.clone());
            }
        }

        let mut stats = self.stats.write().ok()?;
        stats.misses += 1;
        None
    }

    /// Insert entry into cache
    pub fn insert(&self, domain: &str, rtype: u16, mut entry: CacheEntry) {
        // Apply TTL limits
        entry.ttl = entry.ttl.clamp(self.config.min_ttl, self.config.max_ttl);
        entry.min_ttl = self.config.min_ttl;

        let key = CacheKey::new(domain, rtype);

        if let Ok(mut entries) = self.entries.write() {
            // Evict if at capacity
            if entries.len() >= self.config.max_entries {
                self.evict_expired(&mut entries);

                // If still at capacity, evict oldest
                if entries.len() >= self.config.max_entries {
                    self.evict_oldest(&mut entries);
                }
            }

            entries.insert(key, entry);

            if let Ok(mut stats) = self.stats.write() {
                stats.inserts += 1;
            }
        }
    }

    /// Insert A/AAAA record
    pub fn insert_address(&self, domain: &str, rtype: u16, addr: IpAddr, ttl: u32) {
        let key = CacheKey::new(domain, rtype);

        if let Ok(mut entries) = self.entries.write() {
            let entry = entries
                .entry(key)
                .or_insert_with(|| CacheEntry::new(rtype, ttl));
            entry.add_address(addr);
            // Update TTL if longer
            if ttl > entry.ttl {
                entry.ttl = ttl.clamp(self.config.min_ttl, self.config.max_ttl);
            }
        }
    }

    /// Insert negative cache entry (NXDOMAIN)
    pub fn insert_negative(&self, domain: &str, rtype: u16) {
        if !self.config.negative_cache {
            return;
        }

        let entry = CacheEntry::new(rtype, self.config.negative_ttl);
        self.insert(domain, rtype, entry);
    }

    /// Remove entry from cache
    pub fn remove(&self, domain: &str, rtype: u16) {
        let key = CacheKey::new(domain, rtype);
        if let Ok(mut entries) = self.entries.write() {
            entries.remove(&key);
        }
    }

    /// Clear all entries
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
    }

    /// Remove expired entries
    pub fn cleanup(&self) {
        if let Ok(mut entries) = self.entries.write() {
            self.evict_expired(&mut entries);
        }
    }

    /// Get cache size
    pub fn len(&self) -> usize {
        self.entries.read().map(|e| e.len()).unwrap_or(0)
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        self.stats.read().map(|s| s.clone()).unwrap_or_default()
    }

    /// Evict expired entries
    fn evict_expired(&self, entries: &mut HashMap<CacheKey, CacheEntry>) {
        let before = entries.len();
        entries.retain(|_, entry| !entry.is_expired());
        let evicted = before - entries.len();

        if evicted > 0 {
            if let Ok(mut stats) = self.stats.write() {
                stats.expirations += evicted as u64;
            }
        }
    }

    /// Evict oldest entries (10% of cache)
    fn evict_oldest(&self, entries: &mut HashMap<CacheKey, CacheEntry>) {
        let to_evict = entries.len() / 10 + 1;
        let mut oldest: Vec<_> = entries
            .iter()
            .map(|(k, v)| (k.clone(), v.cached_at))
            .collect();
        oldest.sort_by_key(|(_, t)| *t);

        for (key, _) in oldest.into_iter().take(to_evict) {
            entries.remove(&key);
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.evictions += to_evict as u64;
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for DnsCache {
    fn clone(&self) -> Self {
        Self {
            entries: Arc::clone(&self.entries),
            config: self.config.clone(),
            stats: Arc::clone(&self.stats),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_cache_insert_get() {
        let cache = DnsCache::new();

        let addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert_address("example.com", 1, addr, 300);

        let entry = cache.get("example.com", 1).expect("Should have entry");
        assert_eq!(entry.addresses.len(), 1);
        assert_eq!(entry.addresses[0], addr);
    }

    #[test]
    fn test_cache_expiry() {
        let mut config = CacheConfig::default();
        config.min_ttl = 0; // Allow immediate expiry for test
        let cache = DnsCache::with_config(config);

        let mut entry = CacheEntry::new(1, 0);
        entry.min_ttl = 0;
        entry.add_address(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

        cache.insert("example.com", 1, entry);

        // Entry should be expired immediately
        std::thread::sleep(Duration::from_millis(10));
        assert!(cache.get("example.com", 1).is_none());
    }

    #[test]
    fn test_cache_stats() {
        let cache = DnsCache::new();

        cache.insert_address("example.com", 1, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 300);

        // Hit
        let _ = cache.get("example.com", 1);
        // Miss
        let _ = cache.get("notfound.com", 1);

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.inserts, 1);
    }
}
