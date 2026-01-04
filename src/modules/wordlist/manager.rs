//! Unified Wordlist Manager - Single entry point for all wordlist operations.
//!
//! Provides context-aware resolution, caching, mutations, and learning integration.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::loader::Loader;

// ==================== Context & Configuration ====================

/// Wordlist usage context for resolution
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum WordlistContext {
    /// Web directory fuzzing (/admin, /backup, etc.)
    Directories,
    /// File discovery (.bak, .old, etc.)
    Files,
    /// Subdomain enumeration (www, mail, etc.)
    Subdomains,
    /// GET/POST parameter fuzzing (id, page, etc.)
    Parameters,
    /// Password lists
    Passwords,
    /// Username enumeration
    Usernames,
    /// Virtual host enumeration (dev, staging, api, etc.)
    VHosts,
    /// Custom context with name
    Custom(String),
}

impl WordlistContext {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Directories => "directories",
            Self::Files => "files",
            Self::Subdomains => "subdomains",
            Self::Parameters => "parameters",
            Self::Passwords => "passwords",
            Self::Usernames => "usernames",
            Self::VHosts => "vhosts",
            Self::Custom(name) => name,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "directories" | "dirs" | "dir" => Self::Directories,
            "files" | "file" => Self::Files,
            "subdomains" | "subdomain" | "subs" | "sub" => Self::Subdomains,
            "parameters" | "params" | "param" => Self::Parameters,
            "passwords" | "password" | "pass" => Self::Passwords,
            "usernames" | "username" | "users" | "user" => Self::Usernames,
            "vhosts" | "vhost" | "virtualhosts" | "virtualhost" => Self::VHosts,
            other => Self::Custom(other.to_string()),
        }
    }
}

/// Wordlist size preference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WordlistSize {
    /// Small/quick scan (~100-1k words)
    Small,
    /// Medium/balanced (~10k words)
    Medium,
    /// Large/thorough (~100k words)
    Large,
    /// Huge/exhaustive (~1M+ words)
    Huge,
}

impl WordlistSize {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::Huge => "huge",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "small" | "quick" | "fast" => Self::Small,
            "medium" | "default" | "balanced" => Self::Medium,
            "large" | "thorough" | "big" => Self::Large,
            "huge" | "exhaustive" | "full" => Self::Huge,
            _ => Self::Medium,
        }
    }
}

/// Wordlist filter configuration
#[derive(Debug, Clone)]
pub enum WordlistFilter {
    /// Minimum word length
    MinLength(usize),
    /// Maximum word length
    MaxLength(usize),
    /// Only alphanumeric
    AlphanumericOnly,
    /// Only lowercase
    LowercaseOnly,
    /// Exclude words matching pattern
    ExcludePattern(String),
    /// Include only words matching pattern
    IncludePattern(String),
}

/// Mutation rules for wordlist transformation
#[derive(Debug, Clone)]
pub enum MutationRule {
    /// Convert to uppercase
    Uppercase,
    /// Convert to lowercase
    Lowercase,
    /// Capitalize first letter
    Capitalize,
    /// Toggle case
    ToggleCase,
    /// Reverse string
    Reverse,
    /// Duplicate word
    Duplicate,
    /// Append string
    Append(String),
    /// Prepend string
    Prepend(String),
    /// Replace character
    Replace(char, char),
    /// Leet speak substitution
    Leet,
    /// Append numbers (0-99)
    AppendNumbers,
    /// Append year (2020-2025)
    AppendYear,
    /// Custom rule string (hashcat-style)
    Custom(String),
}

/// Wordlist resolution request
#[derive(Debug, Clone)]
pub struct WordlistRequest {
    /// Usage context
    pub context: WordlistContext,
    /// Preferred size
    pub size: WordlistSize,
    /// Optional explicit path (overrides context resolution)
    pub explicit_path: Option<PathBuf>,
    /// Optional mutations to apply
    pub mutations: Option<Vec<MutationRule>>,
    /// Include TF-IDF learned words
    pub include_learned: bool,
    /// Filters to apply
    pub filters: Vec<WordlistFilter>,
    /// Target domain (for learned words association)
    pub target_domain: Option<String>,
}

impl Default for WordlistRequest {
    fn default() -> Self {
        Self {
            context: WordlistContext::Directories,
            size: WordlistSize::Medium,
            explicit_path: None,
            mutations: None,
            include_learned: false,
            filters: Vec::new(),
            target_domain: None,
        }
    }
}

impl WordlistRequest {
    pub fn new(context: WordlistContext) -> Self {
        Self {
            context,
            ..Default::default()
        }
    }

    pub fn with_size(mut self, size: WordlistSize) -> Self {
        self.size = size;
        self
    }

    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.explicit_path = Some(path.into());
        self
    }

    pub fn with_learned(mut self, target_domain: Option<String>) -> Self {
        self.include_learned = true;
        self.target_domain = target_domain;
        self
    }

    pub fn with_filter(mut self, filter: WordlistFilter) -> Self {
        self.filters.push(filter);
        self
    }
}

// ==================== Cache Key ====================

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct CacheKey {
    context: WordlistContext,
    size: WordlistSize,
    path: Option<PathBuf>,
}

// ==================== LRU Cache ====================

/// Simple LRU cache for wordlists
struct LruCache<K, V> {
    capacity: usize,
    entries: HashMap<K, (V, u64)>,
    access_counter: u64,
}

impl<K: std::hash::Hash + Eq + Clone, V> LruCache<K, V> {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::new(),
            access_counter: 0,
        }
    }

    fn get(&mut self, key: &K) -> Option<&V> {
        if let Some((value, access)) = self.entries.get_mut(key) {
            self.access_counter += 1;
            *access = self.access_counter;
            Some(value)
        } else {
            None
        }
    }

    fn insert(&mut self, key: K, value: V) {
        // Evict if at capacity
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&key) {
            if let Some(lru_key) = self.find_lru() {
                self.entries.remove(&lru_key);
            }
        }

        self.access_counter += 1;
        self.entries.insert(key, (value, self.access_counter));
    }

    fn find_lru(&self) -> Option<K> {
        self.entries
            .iter()
            .min_by_key(|(_, (_, access))| access)
            .map(|(k, _)| k.clone())
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

// ==================== Wordlist Manager ====================

/// Configuration for WordlistManager
#[derive(Debug, Clone)]
pub struct WordlistConfig {
    /// Maximum cached wordlists
    pub cache_capacity: usize,
    /// Search paths for wordlists (in priority order)
    pub search_paths: Vec<PathBuf>,
    /// Enable automatic downloading of missing wordlists
    pub auto_download: bool,
}

impl Default for WordlistConfig {
    fn default() -> Self {
        let mut search_paths = Vec::new();

        // 1. Project wordlists
        search_paths.push(PathBuf::from("./wordlists"));

        // 2. User cache
        if let Some(home) = std::env::var_os("HOME") {
            let mut cache_path = PathBuf::from(home);
            cache_path.push(".redblue/wordlists");
            search_paths.push(cache_path);
        }

        // 3. System paths
        search_paths.push(PathBuf::from("/usr/share/seclists"));
        search_paths.push(PathBuf::from("/usr/share/wordlists"));

        Self {
            cache_capacity: 10,
            search_paths,
            auto_download: false,
        }
    }
}

/// Unified wordlist management API
pub struct WordlistManager {
    cache: LruCache<CacheKey, Arc<Vec<String>>>,
    config: WordlistConfig,
    /// Learned words per context and domain
    learned_words: HashMap<(WordlistContext, Option<String>), Vec<LearnedWord>>,
}

/// A word learned from scanning with its TF-IDF score
#[derive(Debug, Clone)]
pub struct LearnedWord {
    pub word: String,
    pub score: f64,
    pub source_domain: Option<String>,
    pub last_seen: u64,
}

impl WordlistManager {
    /// Create a new WordlistManager with default configuration
    pub fn new() -> Self {
        Self::with_config(WordlistConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: WordlistConfig) -> Self {
        Self {
            cache: LruCache::new(config.cache_capacity),
            config,
            learned_words: HashMap::new(),
        }
    }

    /// Resolve wordlist for given request
    pub fn resolve(&mut self, request: &WordlistRequest) -> Result<WordlistIterator, String> {
        let words = self.load_words(request)?;

        // Apply filters
        let filtered = self.apply_filters(words, &request.filters);

        // Merge learned words if requested
        let final_words = if request.include_learned {
            self.merge_learned(filtered, &request.context, &request.target_domain)
        } else {
            filtered
        };

        Ok(WordlistIterator::new(final_words))
    }

    /// Stream wordlist without fully loading into memory
    pub fn stream(
        &self,
        request: &WordlistRequest,
    ) -> Result<Box<dyn Iterator<Item = String>>, String> {
        let path = self.resolve_path(request)?;
        let reader = Loader::open(&path).map_err(|e| format!("Failed to open wordlist: {}", e))?;
        let buf_reader = BufReader::new(reader);

        let filters = request.filters.clone();
        let iter = buf_reader
            .lines()
            .filter_map(|line| line.ok())
            .filter(move |word| Self::passes_filters_static(word, &filters));

        Ok(Box::new(iter))
    }

    /// Add learned words for a context
    pub fn add_learned(&mut self, context: &WordlistContext, words: Vec<LearnedWord>) {
        let key = (context.clone(), None);
        let entry = self.learned_words.entry(key).or_insert_with(Vec::new);
        entry.extend(words);

        // Sort by score descending
        entry.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Limit to top 10k words
        entry.truncate(10_000);
    }

    /// Add learned words for a specific domain
    pub fn add_learned_for_domain(
        &mut self,
        context: &WordlistContext,
        domain: &str,
        words: Vec<LearnedWord>,
    ) {
        let key = (context.clone(), Some(domain.to_string()));
        let entry = self.learned_words.entry(key).or_insert_with(Vec::new);
        entry.extend(words);
        entry.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        entry.truncate(10_000);
    }

    /// Get learned words for context
    pub fn get_learned(
        &self,
        context: &WordlistContext,
        domain: Option<&str>,
        limit: usize,
    ) -> Vec<&LearnedWord> {
        let key = (context.clone(), domain.map(String::from));
        self.learned_words
            .get(&key)
            .map(|words| words.iter().take(limit).collect())
            .unwrap_or_default()
    }

    /// Clear all learned words
    pub fn clear_learned(&mut self) {
        self.learned_words.clear();
    }

    // ==================== Internal Methods ====================

    fn load_words(&mut self, request: &WordlistRequest) -> Result<Vec<String>, String> {
        let cache_key = CacheKey {
            context: request.context.clone(),
            size: request.size,
            path: request.explicit_path.clone(),
        };

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok((**cached).clone());
        }

        // Load from file
        let path = self.resolve_path(request)?;
        let words = self.load_file(&path)?;

        // Cache result
        let arc_words = Arc::new(words.clone());
        self.cache.insert(cache_key, arc_words);

        Ok(words)
    }

    fn resolve_path(&self, request: &WordlistRequest) -> Result<PathBuf, String> {
        // 1. Explicit path takes priority
        if let Some(path) = &request.explicit_path {
            if path.exists() {
                return Ok(path.clone());
            }
            return Err(format!("Wordlist not found: {}", path.display()));
        }

        // 2. Resolve based on context
        let filename = self.context_to_filename(&request.context, request.size);

        // Search in priority order
        for search_path in &self.config.search_paths {
            let candidate = search_path.join(&filename);
            if candidate.exists() {
                return Ok(candidate);
            }

            // Try with .txt extension
            let txt_candidate = search_path.join(format!("{}.txt", filename));
            if txt_candidate.exists() {
                return Ok(txt_candidate);
            }

            // Try in context subdirectory
            let subdir_candidate = search_path.join(request.context.as_str()).join(&filename);
            if subdir_candidate.exists() {
                return Ok(subdir_candidate);
            }
        }

        // 3. Try embedded wordlist
        if let Some(embedded) = self.get_embedded_wordlist(&request.context, request.size) {
            return Ok(embedded);
        }

        Err(format!(
            "Wordlist not found for context '{}' size '{}'",
            request.context.as_str(),
            request.size.as_str()
        ))
    }

    fn context_to_filename(&self, context: &WordlistContext, size: WordlistSize) -> String {
        match (context, size) {
            (WordlistContext::Directories, WordlistSize::Small) => "common.txt".to_string(),
            (WordlistContext::Directories, WordlistSize::Medium) => {
                "raft-medium-directories.txt".to_string()
            }
            (WordlistContext::Directories, WordlistSize::Large) => {
                "raft-large-directories.txt".to_string()
            }
            (WordlistContext::Directories, WordlistSize::Huge) => {
                "directory-list-2.3-big.txt".to_string()
            }

            (WordlistContext::Files, WordlistSize::Small) => "raft-small-files.txt".to_string(),
            (WordlistContext::Files, WordlistSize::Medium) => "raft-medium-files.txt".to_string(),
            (WordlistContext::Files, WordlistSize::Large) => "raft-large-files.txt".to_string(),
            (WordlistContext::Files, _) => "raft-large-files.txt".to_string(),

            (WordlistContext::Subdomains, WordlistSize::Small) => {
                "subdomains-top1million-5000.txt".to_string()
            }
            (WordlistContext::Subdomains, WordlistSize::Medium) => {
                "subdomains-top1million-20000.txt".to_string()
            }
            (WordlistContext::Subdomains, WordlistSize::Large) => {
                "subdomains-top1million-110000.txt".to_string()
            }
            (WordlistContext::Subdomains, WordlistSize::Huge) => {
                "subdomains-top1million.txt".to_string()
            }

            (WordlistContext::Parameters, _) => "burp-parameter-names.txt".to_string(),

            (WordlistContext::Passwords, WordlistSize::Small) => {
                "10-million-password-list-top-100.txt".to_string()
            }
            (WordlistContext::Passwords, WordlistSize::Medium) => {
                "10-million-password-list-top-1000.txt".to_string()
            }
            (WordlistContext::Passwords, WordlistSize::Large) => {
                "10-million-password-list-top-10000.txt".to_string()
            }
            (WordlistContext::Passwords, WordlistSize::Huge) => "rockyou.txt".to_string(),

            (WordlistContext::Usernames, _) => "names.txt".to_string(),

            (WordlistContext::VHosts, WordlistSize::Small) => "vhosts-common.txt".to_string(),
            (WordlistContext::VHosts, WordlistSize::Medium) => "vhosts-pentest.txt".to_string(),
            (WordlistContext::VHosts, WordlistSize::Large) => "vhosts-cloud.txt".to_string(),
            (WordlistContext::VHosts, WordlistSize::Huge) => "vhosts-all.txt".to_string(),

            (WordlistContext::Custom(name), _) => format!("{}.txt", name),
        }
    }

    fn get_embedded_wordlist(
        &self,
        context: &WordlistContext,
        _size: WordlistSize,
    ) -> Option<PathBuf> {
        // For now, return None - embedded wordlists can be added later
        // This would typically compile wordlists into the binary
        let _ = context;
        None
    }

    fn load_file(&self, path: &Path) -> Result<Vec<String>, String> {
        let reader =
            Loader::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;

        let buf_reader = BufReader::new(reader);
        let words: Vec<String> = buf_reader
            .lines()
            .filter_map(|line| line.ok())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();

        Ok(words)
    }

    fn apply_filters(&self, words: Vec<String>, filters: &[WordlistFilter]) -> Vec<String> {
        if filters.is_empty() {
            return words;
        }

        words
            .into_iter()
            .filter(|word| Self::passes_filters_static(word, filters))
            .collect()
    }

    fn passes_filters_static(word: &str, filters: &[WordlistFilter]) -> bool {
        for filter in filters {
            match filter {
                WordlistFilter::MinLength(min) => {
                    if word.len() < *min {
                        return false;
                    }
                }
                WordlistFilter::MaxLength(max) => {
                    if word.len() > *max {
                        return false;
                    }
                }
                WordlistFilter::AlphanumericOnly => {
                    if !word.chars().all(|c| c.is_alphanumeric()) {
                        return false;
                    }
                }
                WordlistFilter::LowercaseOnly => {
                    if !word.chars().all(|c| !c.is_alphabetic() || c.is_lowercase()) {
                        return false;
                    }
                }
                WordlistFilter::ExcludePattern(pattern) => {
                    if word.contains(pattern.as_str()) {
                        return false;
                    }
                }
                WordlistFilter::IncludePattern(pattern) => {
                    if !word.contains(pattern.as_str()) {
                        return false;
                    }
                }
            }
        }
        true
    }

    fn merge_learned(
        &self,
        mut words: Vec<String>,
        context: &WordlistContext,
        domain: &Option<String>,
    ) -> Vec<String> {
        // Get learned words for this context
        let learned = self.get_learned(context, domain.as_deref(), 1000);

        if learned.is_empty() {
            return words;
        }

        // Prepend high-scoring learned words (they should be tried first)
        let learned_words: Vec<String> = learned.iter().map(|lw| lw.word.clone()).collect();

        // Create a set for deduplication
        let existing: std::collections::HashSet<_> = words.iter().cloned().collect();
        let unique_learned: Vec<String> = learned_words
            .into_iter()
            .filter(|w| !existing.contains(w))
            .collect();

        // Prepend learned words
        let mut merged = unique_learned;
        merged.append(&mut words);
        merged
    }
}

impl Default for WordlistManager {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== Wordlist Iterator ====================

/// Iterator over wordlist entries
pub struct WordlistIterator {
    words: Vec<String>,
    position: usize,
}

impl WordlistIterator {
    pub fn new(words: Vec<String>) -> Self {
        Self { words, position: 0 }
    }

    /// Get current position (for checkpointing)
    pub fn position(&self) -> usize {
        self.position
    }

    /// Skip to position (for resume)
    pub fn skip_to(&mut self, pos: usize) {
        self.position = pos.min(self.words.len());
    }

    /// Total word count
    pub fn total(&self) -> usize {
        self.words.len()
    }

    /// Remaining word count
    pub fn remaining(&self) -> usize {
        self.words.len().saturating_sub(self.position)
    }

    /// Clone the iterator (for recursive scanning)
    pub fn clone_iter(&self) -> Self {
        Self {
            words: self.words.clone(),
            position: 0,
        }
    }
}

impl Iterator for WordlistIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position < self.words.len() {
            let word = self.words[self.position].clone();
            self.position += 1;
            Some(word)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for WordlistIterator {}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_context_from_str() {
        assert!(matches!(
            WordlistContext::from_str("directories"),
            WordlistContext::Directories
        ));
        assert!(matches!(
            WordlistContext::from_str("dirs"),
            WordlistContext::Directories
        ));
        assert!(matches!(
            WordlistContext::from_str("subdomains"),
            WordlistContext::Subdomains
        ));
        assert!(matches!(
            WordlistContext::from_str("PASSWORDS"),
            WordlistContext::Passwords
        ));
        assert!(matches!(
            WordlistContext::from_str("custom-list"),
            WordlistContext::Custom(_)
        ));
    }

    #[test]
    fn test_wordlist_size_from_str() {
        assert_eq!(WordlistSize::from_str("small"), WordlistSize::Small);
        assert_eq!(WordlistSize::from_str("MEDIUM"), WordlistSize::Medium);
        assert_eq!(WordlistSize::from_str("huge"), WordlistSize::Huge);
        assert_eq!(WordlistSize::from_str("unknown"), WordlistSize::Medium);
    }

    #[test]
    fn test_wordlist_request_builder() {
        let request = WordlistRequest::new(WordlistContext::Directories)
            .with_size(WordlistSize::Large)
            .with_filter(WordlistFilter::MinLength(3))
            .with_learned(Some("example.com".to_string()));

        assert!(matches!(request.context, WordlistContext::Directories));
        assert_eq!(request.size, WordlistSize::Large);
        assert!(request.include_learned);
        assert_eq!(request.filters.len(), 1);
    }

    #[test]
    fn test_lru_cache() {
        let mut cache: LruCache<String, i32> = LruCache::new(2);

        cache.insert("a".to_string(), 1);
        cache.insert("b".to_string(), 2);

        assert_eq!(cache.get(&"a".to_string()), Some(&1));
        assert_eq!(cache.get(&"b".to_string()), Some(&2));

        // Insert third, should evict one
        cache.insert("c".to_string(), 3);
        assert_eq!(cache.len(), 2);

        // "b" was accessed after "a", so "a" might be evicted
        // (but we accessed "a" again, so "b" should be evicted)
        // Actually, after cache.get("a"), "a" has higher access counter
        // After cache.get("b"), "b" has even higher access counter
        // So "a" should be evicted when "c" is inserted
        assert_eq!(cache.get(&"c".to_string()), Some(&3));
    }

    #[test]
    fn test_filter_min_length() {
        let filters = vec![WordlistFilter::MinLength(5)];
        assert!(WordlistManager::passes_filters_static("hello", &filters));
        assert!(!WordlistManager::passes_filters_static("hi", &filters));
    }

    #[test]
    fn test_filter_max_length() {
        let filters = vec![WordlistFilter::MaxLength(5)];
        assert!(WordlistManager::passes_filters_static("hello", &filters));
        assert!(!WordlistManager::passes_filters_static(
            "hello_world",
            &filters
        ));
    }

    #[test]
    fn test_filter_alphanumeric() {
        let filters = vec![WordlistFilter::AlphanumericOnly];
        assert!(WordlistManager::passes_filters_static("hello123", &filters));
        assert!(!WordlistManager::passes_filters_static(
            "hello-world",
            &filters
        ));
    }

    #[test]
    fn test_filter_lowercase() {
        let filters = vec![WordlistFilter::LowercaseOnly];
        assert!(WordlistManager::passes_filters_static("hello", &filters));
        assert!(WordlistManager::passes_filters_static("hello123", &filters));
        assert!(!WordlistManager::passes_filters_static("Hello", &filters));
    }

    #[test]
    fn test_learned_words() {
        let mut manager = WordlistManager::new();

        let words = vec![
            LearnedWord {
                word: "admin".to_string(),
                score: 0.95,
                source_domain: None,
                last_seen: 0,
            },
            LearnedWord {
                word: "config".to_string(),
                score: 0.85,
                source_domain: None,
                last_seen: 0,
            },
        ];

        manager.add_learned(&WordlistContext::Directories, words);

        let learned = manager.get_learned(&WordlistContext::Directories, None, 10);
        assert_eq!(learned.len(), 2);
        assert_eq!(learned[0].word, "admin"); // Highest score first
    }

    #[test]
    fn test_wordlist_iterator() {
        let words = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let mut iter = WordlistIterator::new(words);

        assert_eq!(iter.total(), 3);
        assert_eq!(iter.remaining(), 3);
        assert_eq!(iter.position(), 0);

        assert_eq!(iter.next(), Some("a".to_string()));
        assert_eq!(iter.position(), 1);
        assert_eq!(iter.remaining(), 2);

        iter.skip_to(2);
        assert_eq!(iter.next(), Some("c".to_string()));
        assert_eq!(iter.next(), None);
    }
}
