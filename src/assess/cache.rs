//! Cache Manager for Assessment Workflow
//!
//! Provides intelligent caching with TTL (default 24 hours) for:
//! - Technology fingerprint data
//! - Vulnerability correlation results
//!
//! Uses RedDb as the backing store.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::modules::web::fingerprinter::Technology;
use crate::storage::records::VulnerabilityRecord;
use crate::storage::RedDb;

/// Default cache TTL: 24 hours
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Cache status indicator
#[derive(Debug, Clone)]
pub enum CacheStatus {
    /// Data is fresh (within TTL)
    Fresh(Duration),
    /// Data exists but is stale (beyond TTL)
    Stale(Duration),
    /// No cached data found
    Miss,
}

impl CacheStatus {
    pub fn is_fresh(&self) -> bool {
        matches!(self, CacheStatus::Fresh(_))
    }

    pub fn is_stale(&self) -> bool {
        matches!(self, CacheStatus::Stale(_))
    }

    pub fn is_miss(&self) -> bool {
        matches!(self, CacheStatus::Miss)
    }

    pub fn age(&self) -> Option<Duration> {
        match self {
            CacheStatus::Fresh(d) | CacheStatus::Stale(d) => Some(*d),
            CacheStatus::Miss => None,
        }
    }
}

impl std::fmt::Display for CacheStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheStatus::Fresh(age) => {
                let hours = age.as_secs() / 3600;
                let mins = (age.as_secs() % 3600) / 60;
                if hours > 0 {
                    write!(f, "Cache ({}h {}m ago)", hours, mins)
                } else {
                    write!(f, "Cache ({}m ago)", mins)
                }
            }
            CacheStatus::Stale(age) => {
                let hours = age.as_secs() / 3600;
                write!(f, "Stale cache ({}h ago)", hours)
            }
            CacheStatus::Miss => write!(f, "No cache"),
        }
    }
}

/// Cached technology data
#[derive(Debug, Clone)]
pub struct CachedTechnologies {
    pub technologies: Vec<Technology>,
    pub status: CacheStatus,
    pub timestamp: u32,
}

/// Cached vulnerability data
#[derive(Debug, Clone)]
pub struct CachedVulnerabilities {
    pub vulnerabilities: Vec<VulnerabilityRecord>,
    pub status: CacheStatus,
    pub timestamp: u32,
}

/// Cache manager with configurable TTL
pub struct CacheManager {
    ttl: Duration,
}

impl Default for CacheManager {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_CACHE_TTL,
        }
    }
}

impl CacheManager {
    /// Create a new cache manager with default TTL (24 hours)
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a cache manager with custom TTL
    pub fn with_ttl(ttl: Duration) -> Self {
        Self { ttl }
    }

    /// Get current timestamp
    fn now_timestamp() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32
    }

    /// Calculate age from timestamp
    fn age_from_timestamp(timestamp: u32) -> Duration {
        let now = Self::now_timestamp();
        Duration::from_secs((now.saturating_sub(timestamp)) as u64)
    }

    /// Check cache status for a timestamp
    fn check_status(&self, timestamp: u32) -> CacheStatus {
        let age = Self::age_from_timestamp(timestamp);
        if age < self.ttl {
            CacheStatus::Fresh(age)
        } else {
            CacheStatus::Stale(age)
        }
    }

    /// Get cached technology fingerprints for a target
    ///
    /// Returns None if no data exists, otherwise returns data with cache status
    pub fn get_technologies(&self, target: &str, db: &mut RedDb) -> Option<CachedTechnologies> {
        // Try to get HTTP records for this host (contains fingerprint data)
        let records = db.get_http_by_host(target).ok()?;
        if records.is_empty() {
            return None;
        }

        // Find the most recent record
        let latest = records.iter().max_by_key(|r| r.timestamp)?;
        let status = self.check_status(latest.timestamp);

        // Extract technologies from the stored data
        // We store technologies in the 'server' field and headers
        let mut technologies = Vec::new();

        if let Some(server) = &latest.server {
            // Parse server header for tech info
            if let Some(tech) = parse_server_header(server) {
                technologies.push(tech);
            }
        }

        // Check for technologies in custom headers
        for (key, value) in &latest.headers {
            if let Some(tech) = parse_header_for_tech(key, value) {
                technologies.push(tech);
            }
        }

        Some(CachedTechnologies {
            technologies,
            status,
            timestamp: latest.timestamp,
        })
    }

    /// Get cached vulnerabilities for a target
    ///
    /// Returns all vulnerabilities in the database. For target-specific filtering,
    /// consider using technology-based matching.
    pub fn get_vulnerabilities(
        &self,
        _target: &str,
        db: &mut RedDb,
    ) -> Option<CachedVulnerabilities> {
        let vulns = db.vulns().all().ok()?;
        if vulns.is_empty() {
            return None;
        }

        // Find most recent timestamp
        let latest_ts = vulns.iter().map(|v| v.discovered_at).max().unwrap_or(0);

        let status = self.check_status(latest_ts);

        Some(CachedVulnerabilities {
            vulnerabilities: vulns,
            status,
            timestamp: latest_ts,
        })
    }

    /// Check if fingerprint cache is valid (fresh)
    pub fn has_fresh_fingerprints(&self, target: &str, db: &mut RedDb) -> bool {
        self.get_technologies(target, db)
            .map(|c| c.status.is_fresh())
            .unwrap_or(false)
    }

    /// Check if vulnerability cache is valid (fresh)
    pub fn has_fresh_vulnerabilities(&self, target: &str, db: &mut RedDb) -> bool {
        self.get_vulnerabilities(target, db)
            .map(|c| c.status.is_fresh())
            .unwrap_or(false)
    }

    /// Invalidate cache for a target (by updating timestamps)
    pub fn invalidate(&self, _target: &str, _db: &mut RedDb) {
        // Cache invalidation is handled by storing new data
        // Old data naturally becomes stale
    }
}

/// Parse server header for technology info
fn parse_server_header(server: &str) -> Option<Technology> {
    use crate::modules::web::fingerprinter::{Confidence, TechCategory};

    let server_lower = server.to_lowercase();

    // Common patterns: "nginx/1.24.0", "Apache/2.4.52", "Microsoft-IIS/10.0"
    let (name, version) = if let Some(idx) = server.find('/') {
        let name = &server[..idx];
        let version = server[idx + 1..].split_whitespace().next();
        (name.to_string(), version.map(String::from))
    } else {
        (server.split_whitespace().next()?.to_string(), None)
    };

    let category = if server_lower.contains("nginx")
        || server_lower.contains("apache")
        || server_lower.contains("iis")
        || server_lower.contains("lighttpd")
    {
        TechCategory::WebServer
    } else {
        TechCategory::Other
    };

    Some(Technology {
        name,
        category,
        version,
        confidence: Confidence::High,
    })
}

/// Parse header for technology info
fn parse_header_for_tech(key: &str, value: &str) -> Option<Technology> {
    use crate::modules::web::fingerprinter::{Confidence, TechCategory};

    let key_lower = key.to_lowercase();

    match key_lower.as_str() {
        "x-powered-by" => {
            // "PHP/8.1.0", "Express", "ASP.NET"
            let (name, version) = if let Some(idx) = value.find('/') {
                (&value[..idx], Some(value[idx + 1..].to_string()))
            } else {
                (value, None)
            };
            Some(Technology {
                name: name.to_string(),
                category: TechCategory::Language,
                version,
                confidence: Confidence::High,
            })
        }
        "x-aspnet-version" => Some(Technology {
            name: "ASP.NET".to_string(),
            category: TechCategory::Framework,
            version: Some(value.to_string()),
            confidence: Confidence::High,
        }),
        "x-drupal-cache" | "x-drupal-dynamic-cache" => Some(Technology {
            name: "Drupal".to_string(),
            category: TechCategory::CMS,
            version: None,
            confidence: Confidence::High,
        }),
        "x-generator" => Some(Technology {
            name: value.to_string(),
            category: TechCategory::CMS,
            version: None,
            confidence: Confidence::Medium,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_status_display() {
        let fresh = CacheStatus::Fresh(Duration::from_secs(3600 + 1800)); // 1h 30m
        assert!(fresh.to_string().contains("1h 30m"));

        let stale = CacheStatus::Stale(Duration::from_secs(48 * 3600)); // 48h
        assert!(stale.to_string().contains("48h"));

        let miss = CacheStatus::Miss;
        assert_eq!(miss.to_string(), "No cache");
    }

    #[test]
    fn test_parse_server_header() {
        let tech = parse_server_header("nginx/1.24.0").unwrap();
        assert_eq!(tech.name, "nginx");
        assert_eq!(tech.version, Some("1.24.0".to_string()));

        let tech = parse_server_header("Apache/2.4.52 (Ubuntu)").unwrap();
        assert_eq!(tech.name, "Apache");
        assert_eq!(tech.version, Some("2.4.52".to_string()));

        let tech = parse_server_header("Microsoft-IIS/10.0").unwrap();
        assert_eq!(tech.name, "Microsoft-IIS");
        assert_eq!(tech.version, Some("10.0".to_string()));
    }

    #[test]
    fn test_parse_header_for_tech() {
        let tech = parse_header_for_tech("X-Powered-By", "PHP/8.1.0").unwrap();
        assert_eq!(tech.name, "PHP");
        assert_eq!(tech.version, Some("8.1.0".to_string()));

        let tech = parse_header_for_tech("X-Drupal-Cache", "HIT").unwrap();
        assert_eq!(tech.name, "Drupal");

        let tech = parse_header_for_tech("X-AspNet-Version", "4.0.30319").unwrap();
        assert_eq!(tech.name, "ASP.NET");
        assert_eq!(tech.version, Some("4.0.30319".to_string()));
    }
}
