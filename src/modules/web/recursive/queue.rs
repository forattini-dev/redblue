//! Recursion Queue for URL Management
//!
//! Manages URLs to be scanned with priority ordering, depth tracking,
//! deduplication, and scope enforcement.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

/// A URL queued for scanning
#[derive(Debug, Clone)]
pub struct QueuedUrl {
    /// The URL to scan
    pub url: String,
    /// Current recursion depth (0 = seed URL)
    pub depth: usize,
    /// Priority (higher = scan sooner)
    pub priority: u32,
    /// Parent URL that linked to this one
    pub parent: Option<String>,
    /// Source of discovery
    pub source: DiscoverySource,
    /// Timestamp when queued
    pub queued_at: u64,
}

impl QueuedUrl {
    /// Create a seed URL (depth 0, high priority)
    pub fn seed(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            depth: 0,
            priority: 100,
            parent: None,
            source: DiscoverySource::Seed,
            queued_at: Self::now(),
        }
    }

    /// Create a discovered URL
    pub fn discovered(
        url: impl Into<String>,
        depth: usize,
        parent: impl Into<String>,
        source: DiscoverySource,
    ) -> Self {
        Self {
            url: url.into(),
            depth,
            priority: Self::calculate_priority(depth, &source),
            parent: Some(parent.into()),
            source,
            queued_at: Self::now(),
        }
    }

    /// Calculate priority based on depth and source
    fn calculate_priority(depth: usize, source: &DiscoverySource) -> u32 {
        // Base priority decreases with depth
        let base = 100u32.saturating_sub(depth as u32 * 10);

        // Bonus based on source
        let bonus = match source {
            DiscoverySource::Seed => 50,
            DiscoverySource::Href => 20,
            DiscoverySource::Form => 25,
            DiscoverySource::JavaScript => 15,
            DiscoverySource::Wordlist => 30,
            DiscoverySource::InferredDir => 10,
        };

        base + bonus
    }

    /// Get current timestamp
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

impl Eq for QueuedUrl {}

impl PartialEq for QueuedUrl {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Ord for QueuedUrl {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first, then lower depth, then earlier queued
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.depth.cmp(&self.depth))
            .then_with(|| other.queued_at.cmp(&self.queued_at))
    }
}

impl PartialOrd for QueuedUrl {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// How a URL was discovered
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Initial seed URL
    Seed,
    /// Found in href attribute
    Href,
    /// Found in form action
    Form,
    /// Found in JavaScript
    JavaScript,
    /// Generated from wordlist
    Wordlist,
    /// Inferred directory (parent of discovered path)
    InferredDir,
}

/// Configuration for the recursion queue
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Maximum recursion depth
    pub max_depth: usize,
    /// Whether to enforce same-origin policy
    pub same_origin: bool,
    /// Whether to stay within the seed path
    pub stay_in_scope: bool,
    /// Maximum URLs to queue
    pub max_queue_size: usize,
    /// Whether to infer parent directories
    pub infer_directories: bool,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            same_origin: true,
            stay_in_scope: false,
            max_queue_size: 100_000,
            infer_directories: true,
        }
    }
}

impl QueueConfig {
    /// Shallow recursion (depth 1)
    pub fn shallow() -> Self {
        Self {
            max_depth: 1,
            ..Default::default()
        }
    }

    /// Deep recursion (depth 5)
    pub fn deep() -> Self {
        Self {
            max_depth: 5,
            max_queue_size: 500_000,
            ..Default::default()
        }
    }

    /// Strict scope (same origin + stay in path)
    pub fn strict_scope() -> Self {
        Self {
            same_origin: true,
            stay_in_scope: true,
            ..Default::default()
        }
    }
}

/// Statistics for the recursion queue
#[derive(Debug, Clone, Default)]
pub struct QueueStats {
    /// Total URLs queued
    pub total_queued: usize,
    /// URLs currently pending
    pub pending: usize,
    /// URLs processed (dequeued)
    pub processed: usize,
    /// URLs rejected (out of scope, duplicate, etc.)
    pub rejected: usize,
    /// URLs by depth
    pub by_depth: HashMap<usize, usize>,
    /// URLs by discovery source
    pub by_source: HashMap<String, usize>,
}

/// Recursion queue for managing URLs to scan
pub struct RecursionQueue {
    config: QueueConfig,
    /// Priority queue for pending URLs
    queue: BinaryHeap<QueuedUrl>,
    /// Set of visited URLs (normalized)
    visited: HashSet<String>,
    /// Set of queued URLs (to avoid duplicates in queue)
    queued: HashSet<String>,
    /// Seed URL origin for scope checking
    origin: Option<String>,
    /// Seed URL path for scope checking
    scope_path: Option<String>,
    /// Statistics
    stats: QueueStats,
}

impl RecursionQueue {
    /// Create a new recursion queue with the given configuration
    pub fn new(config: QueueConfig) -> Self {
        Self {
            config,
            queue: BinaryHeap::new(),
            visited: HashSet::new(),
            queued: HashSet::new(),
            origin: None,
            scope_path: None,
            stats: QueueStats::default(),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(QueueConfig::default())
    }

    /// Add a seed URL (sets origin and scope)
    pub fn add_seed(&mut self, url: &str) {
        // Extract origin and scope from seed
        if let Some((origin, path)) = Self::parse_url(url) {
            self.origin = Some(origin);
            self.scope_path = Some(Self::get_directory_path(&path));
        }

        let seed = QueuedUrl::seed(url);
        self.enqueue(seed);
    }

    /// Add a discovered URL
    pub fn add_discovered(
        &mut self,
        url: &str,
        parent_url: &str,
        parent_depth: usize,
        source: DiscoverySource,
    ) -> bool {
        let new_depth = parent_depth + 1;

        // Check depth limit
        if new_depth > self.config.max_depth {
            self.stats.rejected += 1;
            return false;
        }

        // Resolve relative URL
        let absolute_url = self.resolve_url(url, parent_url);

        // Check scope
        if !self.is_in_scope(&absolute_url) {
            self.stats.rejected += 1;
            return false;
        }

        // Create queued URL
        let queued = QueuedUrl::discovered(absolute_url, new_depth, parent_url, source);
        self.enqueue(queued)
    }

    /// Add multiple discovered URLs
    pub fn add_all_discovered(
        &mut self,
        urls: &[String],
        parent_url: &str,
        parent_depth: usize,
        source: DiscoverySource,
    ) -> usize {
        let mut added = 0;
        for url in urls {
            if self.add_discovered(url, parent_url, parent_depth, source) {
                added += 1;
            }
        }
        added
    }

    /// Enqueue a URL (with deduplication)
    fn enqueue(&mut self, url: QueuedUrl) -> bool {
        let normalized = self.normalize_url(&url.url);

        // Check if already queued or visited
        if self.queued.contains(&normalized) || self.visited.contains(&normalized) {
            return false;
        }

        // Check queue size limit
        if self.queue.len() >= self.config.max_queue_size {
            self.stats.rejected += 1;
            return false;
        }

        // Infer parent directories if enabled
        if self.config.infer_directories && url.source != DiscoverySource::Seed {
            self.infer_directories(&url.url, url.depth);
        }

        // Update stats
        self.stats.total_queued += 1;
        self.stats.pending += 1;
        *self.stats.by_depth.entry(url.depth).or_insert(0) += 1;
        let source_name = format!("{:?}", url.source);
        *self.stats.by_source.entry(source_name).or_insert(0) += 1;

        self.queued.insert(normalized);
        self.queue.push(url);
        true
    }

    /// Get the next URL to scan
    pub fn next(&mut self) -> Option<QueuedUrl> {
        while let Some(url) = self.queue.pop() {
            let normalized = self.normalize_url(&url.url);

            // Skip if already visited (might have been visited while in queue)
            if self.visited.contains(&normalized) {
                self.queued.remove(&normalized);
                continue;
            }

            // Mark as visited
            self.visited.insert(normalized.clone());
            self.queued.remove(&normalized);
            self.stats.pending = self.stats.pending.saturating_sub(1);
            self.stats.processed += 1;

            return Some(url);
        }
        None
    }

    /// Check if there are pending URLs
    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Get number of pending URLs
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// Mark a URL as visited (without scanning)
    pub fn mark_visited(&mut self, url: &str) {
        let normalized = self.normalize_url(url);
        self.visited.insert(normalized);
    }

    /// Check if a URL has been visited
    pub fn is_visited(&self, url: &str) -> bool {
        let normalized = self.normalize_url(url);
        self.visited.contains(&normalized)
    }

    /// Get statistics
    pub fn stats(&self) -> &QueueStats {
        &self.stats
    }

    /// Clear the queue (but keep visited set)
    pub fn clear_pending(&mut self) {
        self.queue.clear();
        self.queued.clear();
        self.stats.pending = 0;
    }

    /// Reset everything
    pub fn reset(&mut self) {
        self.queue.clear();
        self.queued.clear();
        self.visited.clear();
        self.origin = None;
        self.scope_path = None;
        self.stats = QueueStats::default();
    }

    /// Get all pending URLs (for serialization)
    pub fn pending_urls(&self) -> Vec<QueuedUrl> {
        self.queue.iter().cloned().collect()
    }

    /// Get all visited URLs (for serialization)
    pub fn visited_urls(&self) -> Vec<String> {
        self.visited.iter().cloned().collect()
    }

    /// Restore queue state from serialized data
    pub fn restore(&mut self, pending: Vec<QueuedUrl>, visited: Vec<String>) {
        for url in pending {
            let normalized = self.normalize_url(&url.url);
            self.queued.insert(normalized);
            self.queue.push(url);
        }

        for url in visited {
            self.visited.insert(url);
        }
    }

    /// Infer parent directories from a discovered path
    fn infer_directories(&mut self, url: &str, depth: usize) {
        if let Some((origin, path)) = Self::parse_url(url) {
            let mut current_path = path.clone();

            // Walk up the path and add inferred directories
            while let Some(parent) = Self::parent_path(&current_path) {
                if parent.is_empty() || parent == "/" {
                    break;
                }

                let inferred_url = format!("{}{}/", origin, parent);
                let normalized = self.normalize_url(&inferred_url);

                // Only add if not already queued/visited
                if !self.queued.contains(&normalized) && !self.visited.contains(&normalized) {
                    let queued = QueuedUrl::discovered(
                        inferred_url,
                        depth,
                        url,
                        DiscoverySource::InferredDir,
                    );
                    // Don't recurse into enqueue to avoid infinite loop
                    self.queued.insert(normalized);
                    self.queue.push(queued);
                }

                current_path = parent.to_string();
            }
        }
    }

    /// Check if a URL is in scope
    fn is_in_scope(&self, url: &str) -> bool {
        let (origin, path) = match Self::parse_url(url) {
            Some(parts) => parts,
            None => return false,
        };

        // Check same-origin policy
        if self.config.same_origin {
            if let Some(ref seed_origin) = self.origin {
                if &origin != seed_origin {
                    return false;
                }
            }
        }

        // Check path scope
        if self.config.stay_in_scope {
            if let Some(ref scope_path) = self.scope_path {
                if !path.starts_with(scope_path) {
                    return false;
                }
            }
        }

        true
    }

    /// Resolve a relative URL against a base URL
    fn resolve_url(&self, url: &str, base: &str) -> String {
        // Already absolute
        if url.starts_with("http://") || url.starts_with("https://") {
            return url.to_string();
        }

        let (origin, base_path) = Self::parse_url(base).unwrap_or_default();

        if url.starts_with('/') {
            // Absolute path
            format!("{}{}", origin, url)
        } else if url.starts_with("./") {
            // Relative to current directory
            let dir = Self::get_directory_path(&base_path);
            format!("{}{}{}", origin, dir, &url[2..])
        } else if url.starts_with("../") {
            // Relative to parent directory
            let mut dir = Self::get_directory_path(&base_path);
            let mut rel = url;

            while rel.starts_with("../") {
                if let Some(parent) = Self::parent_path(&dir) {
                    dir = parent.to_string();
                }
                rel = &rel[3..];
            }

            format!("{}{}/{}", origin, dir, rel)
        } else {
            // Relative to current directory
            let dir = Self::get_directory_path(&base_path);
            format!("{}{}{}", origin, dir, url)
        }
    }

    /// Parse URL into origin and path
    fn parse_url(url: &str) -> Option<(String, String)> {
        if let Some(rest) = url.strip_prefix("https://") {
            let (host, path) = Self::split_host_path(rest);
            Some((format!("https://{}", host), path))
        } else if let Some(rest) = url.strip_prefix("http://") {
            let (host, path) = Self::split_host_path(rest);
            Some((format!("http://{}", host), path))
        } else {
            None
        }
    }

    /// Split host and path
    fn split_host_path(s: &str) -> (String, String) {
        if let Some(pos) = s.find('/') {
            (s[..pos].to_string(), s[pos..].to_string())
        } else {
            (s.to_string(), "/".to_string())
        }
    }

    /// Get directory path (remove filename)
    fn get_directory_path(path: &str) -> String {
        // If ends with /, it's already a directory
        if path.ends_with('/') {
            return path.to_string();
        }

        // Find last / and keep everything up to it
        if let Some(pos) = path.rfind('/') {
            format!("{}/", &path[..pos])
        } else {
            "/".to_string()
        }
    }

    /// Get parent path
    fn parent_path(path: &str) -> Option<&str> {
        let path = path.trim_end_matches('/');
        if path.is_empty() || path == "/" {
            return None;
        }

        path.rfind('/').map(|pos| &path[..pos])
    }

    /// Normalize URL for deduplication
    fn normalize_url(&self, url: &str) -> String {
        let mut normalized = url.to_lowercase();

        // Remove trailing slash (unless it's just the root)
        if normalized.len() > 1 && normalized.ends_with('/') {
            normalized.pop();
        }

        // Remove fragment
        if let Some(pos) = normalized.find('#') {
            normalized = normalized[..pos].to_string();
        }

        // Remove default ports
        normalized = normalized.replace(":80/", "/").replace(":443/", "/");

        // Sort query parameters for consistent deduplication
        if let Some(pos) = normalized.find('?') {
            let path = &normalized[..pos];
            let query = &normalized[pos + 1..];

            let mut params: Vec<&str> = query.split('&').collect();
            params.sort();

            normalized = format!("{}?{}", path, params.join("&"));
        }

        normalized
    }
}

/// Builder for RecursionQueue
pub struct RecursionQueueBuilder {
    config: QueueConfig,
    seeds: Vec<String>,
}

impl RecursionQueueBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: QueueConfig::default(),
            seeds: Vec::new(),
        }
    }

    /// Set maximum depth
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.config.max_depth = depth;
        self
    }

    /// Enable/disable same-origin policy
    pub fn same_origin(mut self, enable: bool) -> Self {
        self.config.same_origin = enable;
        self
    }

    /// Enable/disable stay-in-scope
    pub fn stay_in_scope(mut self, enable: bool) -> Self {
        self.config.stay_in_scope = enable;
        self
    }

    /// Set maximum queue size
    pub fn max_queue_size(mut self, size: usize) -> Self {
        self.config.max_queue_size = size;
        self
    }

    /// Enable/disable directory inference
    pub fn infer_directories(mut self, enable: bool) -> Self {
        self.config.infer_directories = enable;
        self
    }

    /// Add a seed URL
    pub fn add_seed(mut self, url: impl Into<String>) -> Self {
        self.seeds.push(url.into());
        self
    }

    /// Build the queue
    pub fn build(self) -> RecursionQueue {
        let mut queue = RecursionQueue::new(self.config);
        for seed in self.seeds {
            queue.add_seed(&seed);
        }
        queue
    }
}

impl Default for RecursionQueueBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_queue() {
        let mut queue = RecursionQueue::with_defaults();
        queue.add_seed("https://example.com/admin/");

        assert!(queue.has_pending());

        let url = queue.next().unwrap();
        assert_eq!(url.url, "https://example.com/admin/");
        assert_eq!(url.depth, 0);
    }

    #[test]
    fn test_discovered_urls() {
        let mut queue = RecursionQueue::with_defaults();
        queue.add_seed("https://example.com/");

        // Process seed
        let seed = queue.next().unwrap();

        // Add discovered URLs
        queue.add_discovered("/page1", &seed.url, seed.depth, DiscoverySource::Href);
        queue.add_discovered("/page2", &seed.url, seed.depth, DiscoverySource::Href);

        assert_eq!(queue.pending_count(), 2);

        // Should get page1 first (same priority, earlier queued)
        let next = queue.next().unwrap();
        assert!(next.url.contains("page"));
        assert_eq!(next.depth, 1);
    }

    #[test]
    fn test_depth_limit() {
        let config = QueueConfig {
            max_depth: 2,
            ..Default::default()
        };
        let mut queue = RecursionQueue::new(config);
        queue.add_seed("https://example.com/");

        let seed = queue.next().unwrap();
        assert!(queue.add_discovered("/level1", &seed.url, 0, DiscoverySource::Href));
        assert!(queue.add_discovered("/level2", "/level1", 1, DiscoverySource::Href));
        // This should fail (depth 3 > max 2)
        assert!(!queue.add_discovered("/level3", "/level2", 2, DiscoverySource::Href));
    }

    #[test]
    fn test_same_origin() {
        let mut queue = RecursionQueue::with_defaults();
        queue.add_seed("https://example.com/");

        let seed = queue.next().unwrap();

        // Same origin should work
        assert!(queue.add_discovered("/page", &seed.url, 0, DiscoverySource::Href));

        // Different origin should be rejected
        assert!(!queue.add_discovered(
            "https://other.com/page",
            &seed.url,
            0,
            DiscoverySource::Href
        ));
    }

    #[test]
    fn test_deduplication() {
        let mut queue = RecursionQueue::with_defaults();
        queue.add_seed("https://example.com/");

        let seed = queue.next().unwrap();

        // First add should work
        assert!(queue.add_discovered("/page", &seed.url, 0, DiscoverySource::Href));

        // Second add of same URL should be rejected (duplicate)
        assert!(!queue.add_discovered("/page", &seed.url, 0, DiscoverySource::Href));
    }

    #[test]
    fn test_url_normalization() {
        let mut queue = RecursionQueue::with_defaults();
        queue.add_seed("https://example.com/");

        let seed = queue.next().unwrap();

        // These should all be treated as the same URL
        assert!(queue.add_discovered("/page", &seed.url, 0, DiscoverySource::Href));
        assert!(!queue.add_discovered("/Page", &seed.url, 0, DiscoverySource::Href));
        assert!(!queue.add_discovered("/page/", &seed.url, 0, DiscoverySource::Href));
    }

    #[test]
    fn test_relative_url_resolution() {
        let mut queue = RecursionQueue::with_defaults();
        queue.add_seed("https://example.com/admin/dashboard/");

        let seed = queue.next().unwrap();

        // Absolute path
        queue.add_discovered("/api", &seed.url, 0, DiscoverySource::Href);

        // Relative path
        queue.add_discovered("./users", &seed.url, 0, DiscoverySource::Href);

        // Parent path
        queue.add_discovered("../settings", &seed.url, 0, DiscoverySource::Href);

        // Check resolved URLs
        let urls: Vec<_> = queue.pending_urls().into_iter().map(|u| u.url).collect();
        assert!(urls.iter().any(|u| u == "https://example.com/api"));
        assert!(urls
            .iter()
            .any(|u| u == "https://example.com/admin/dashboard/users"));
        assert!(urls
            .iter()
            .any(|u| u == "https://example.com/admin/settings"));
    }

    #[test]
    fn test_builder() {
        let queue = RecursionQueueBuilder::new()
            .max_depth(5)
            .same_origin(true)
            .add_seed("https://example.com/")
            .build();

        assert_eq!(queue.config.max_depth, 5);
        assert!(queue.has_pending());
    }
}
