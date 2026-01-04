//! Resume Manager for Scan Checkpointing
//!
//! Provides checkpoint coordination for pausing and resuming scans:
//! - Periodic state snapshots
//! - Resume-from-checkpoint logic
//! - State serialization/deserialization

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Unique identifier for a scan
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScanId(pub String);

impl ScanId {
    /// Generate a new unique scan ID
    pub fn generate() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        // Simple random component using timestamp
        let random = (timestamp % 0xFFFF) ^ ((timestamp >> 16) % 0xFFFF);

        Self(format!("{:016x}{:04x}", timestamp, random))
    }

    /// Create from an existing ID string
    pub fn from_string(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the ID string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ScanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Scan checkpoint state
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Scan identifier
    pub scan_id: ScanId,
    /// Target URL
    pub target_url: String,
    /// Current wordlist position
    pub wordlist_position: usize,
    /// Total wordlist size
    pub wordlist_total: usize,
    /// Discovered URLs
    pub discovered: Vec<String>,
    /// Visited URLs
    pub visited: HashSet<String>,
    /// Pending URLs in recursion queue
    pub pending_urls: Vec<(String, usize)>, // (url, depth)
    /// Simhash baselines
    pub simhash_baselines: Vec<(u64, u16)>, // (hash, status_code)
    /// Learned words (TF-IDF vocabulary)
    pub learned_words: Vec<(String, f64)>, // (word, score)
    /// Current rate limit state
    pub rate_limit_rate: f64,
    /// Timestamp of checkpoint
    pub timestamp: u64,
    /// Scan duration so far (seconds)
    pub elapsed_seconds: u64,
    /// Statistics snapshot
    pub stats: CheckpointStats,
}

impl Checkpoint {
    /// Create a new checkpoint
    pub fn new(scan_id: ScanId, target_url: impl Into<String>) -> Self {
        Self {
            scan_id,
            target_url: target_url.into(),
            wordlist_position: 0,
            wordlist_total: 0,
            discovered: Vec::new(),
            visited: HashSet::new(),
            pending_urls: Vec::new(),
            simhash_baselines: Vec::new(),
            learned_words: Vec::new(),
            rate_limit_rate: 50.0,
            timestamp: Self::now(),
            elapsed_seconds: 0,
            stats: CheckpointStats::default(),
        }
    }

    /// Get current timestamp
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Update timestamp
    pub fn touch(&mut self) {
        self.timestamp = Self::now();
    }

    /// Calculate progress percentage
    pub fn progress_percent(&self) -> f64 {
        if self.wordlist_total == 0 {
            0.0
        } else {
            (self.wordlist_position as f64 / self.wordlist_total as f64) * 100.0
        }
    }

    /// Serialize to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Version
        data.extend_from_slice(&1u32.to_le_bytes());

        // Scan ID
        self.write_string(&mut data, &self.scan_id.0);

        // Target URL
        self.write_string(&mut data, &self.target_url);

        // Wordlist state
        data.extend_from_slice(&self.wordlist_position.to_le_bytes());
        data.extend_from_slice(&self.wordlist_total.to_le_bytes());

        // Discovered URLs
        data.extend_from_slice(&(self.discovered.len() as u32).to_le_bytes());
        for url in &self.discovered {
            self.write_string(&mut data, url);
        }

        // Visited URLs
        data.extend_from_slice(&(self.visited.len() as u32).to_le_bytes());
        for url in &self.visited {
            self.write_string(&mut data, url);
        }

        // Pending URLs
        data.extend_from_slice(&(self.pending_urls.len() as u32).to_le_bytes());
        for (url, depth) in &self.pending_urls {
            self.write_string(&mut data, url);
            data.extend_from_slice(&(*depth as u32).to_le_bytes());
        }

        // Simhash baselines
        data.extend_from_slice(&(self.simhash_baselines.len() as u32).to_le_bytes());
        for (hash, status) in &self.simhash_baselines {
            data.extend_from_slice(&hash.to_le_bytes());
            data.extend_from_slice(&status.to_le_bytes());
        }

        // Learned words
        data.extend_from_slice(&(self.learned_words.len() as u32).to_le_bytes());
        for (word, score) in &self.learned_words {
            self.write_string(&mut data, word);
            data.extend_from_slice(&score.to_le_bytes());
        }

        // Rate limit state
        data.extend_from_slice(&self.rate_limit_rate.to_le_bytes());

        // Timestamps
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.elapsed_seconds.to_le_bytes());

        // Stats
        self.stats.write_to(&mut data);

        data
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        let mut pos = 0;

        // Version
        let version = Self::read_u32(data, &mut pos)?;
        if version != 1 {
            return None;
        }

        // Scan ID
        let scan_id = ScanId(Self::read_string(data, &mut pos)?);

        // Target URL
        let target_url = Self::read_string(data, &mut pos)?;

        // Wordlist state
        let wordlist_position = Self::read_usize(data, &mut pos)?;
        let wordlist_total = Self::read_usize(data, &mut pos)?;

        // Discovered URLs
        let discovered_count = Self::read_u32(data, &mut pos)? as usize;
        let mut discovered = Vec::with_capacity(discovered_count);
        for _ in 0..discovered_count {
            discovered.push(Self::read_string(data, &mut pos)?);
        }

        // Visited URLs
        let visited_count = Self::read_u32(data, &mut pos)? as usize;
        let mut visited = HashSet::with_capacity(visited_count);
        for _ in 0..visited_count {
            visited.insert(Self::read_string(data, &mut pos)?);
        }

        // Pending URLs
        let pending_count = Self::read_u32(data, &mut pos)? as usize;
        let mut pending_urls = Vec::with_capacity(pending_count);
        for _ in 0..pending_count {
            let url = Self::read_string(data, &mut pos)?;
            let depth = Self::read_u32(data, &mut pos)? as usize;
            pending_urls.push((url, depth));
        }

        // Simhash baselines
        let baseline_count = Self::read_u32(data, &mut pos)? as usize;
        let mut simhash_baselines = Vec::with_capacity(baseline_count);
        for _ in 0..baseline_count {
            let hash = Self::read_u64(data, &mut pos)?;
            let status = Self::read_u16(data, &mut pos)?;
            simhash_baselines.push((hash, status));
        }

        // Learned words
        let words_count = Self::read_u32(data, &mut pos)? as usize;
        let mut learned_words = Vec::with_capacity(words_count);
        for _ in 0..words_count {
            let word = Self::read_string(data, &mut pos)?;
            let score = Self::read_f64(data, &mut pos)?;
            learned_words.push((word, score));
        }

        // Rate limit state
        let rate_limit_rate = Self::read_f64(data, &mut pos)?;

        // Timestamps
        let timestamp = Self::read_u64(data, &mut pos)?;
        let elapsed_seconds = Self::read_u64(data, &mut pos)?;

        // Stats
        let stats = CheckpointStats::read_from(data, &mut pos)?;

        Some(Self {
            scan_id,
            target_url,
            wordlist_position,
            wordlist_total,
            discovered,
            visited,
            pending_urls,
            simhash_baselines,
            learned_words,
            rate_limit_rate,
            timestamp,
            elapsed_seconds,
            stats,
        })
    }

    // Helper methods for serialization
    fn write_string(&self, data: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        data.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(bytes);
    }

    fn read_string(data: &[u8], pos: &mut usize) -> Option<String> {
        let len = Self::read_u32(data, pos)? as usize;
        if *pos + len > data.len() {
            return None;
        }
        let s = std::str::from_utf8(&data[*pos..*pos + len])
            .ok()?
            .to_string();
        *pos += len;
        Some(s)
    }

    fn read_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
        if *pos + 2 > data.len() {
            return None;
        }
        let val = u16::from_le_bytes(data[*pos..*pos + 2].try_into().ok()?);
        *pos += 2;
        Some(val)
    }

    fn read_u32(data: &[u8], pos: &mut usize) -> Option<u32> {
        if *pos + 4 > data.len() {
            return None;
        }
        let val = u32::from_le_bytes(data[*pos..*pos + 4].try_into().ok()?);
        *pos += 4;
        Some(val)
    }

    fn read_u64(data: &[u8], pos: &mut usize) -> Option<u64> {
        if *pos + 8 > data.len() {
            return None;
        }
        let val = u64::from_le_bytes(data[*pos..*pos + 8].try_into().ok()?);
        *pos += 8;
        Some(val)
    }

    fn read_usize(data: &[u8], pos: &mut usize) -> Option<usize> {
        Self::read_u64(data, pos).map(|v| v as usize)
    }

    fn read_f64(data: &[u8], pos: &mut usize) -> Option<f64> {
        if *pos + 8 > data.len() {
            return None;
        }
        let val = f64::from_le_bytes(data[*pos..*pos + 8].try_into().ok()?);
        *pos += 8;
        Some(val)
    }
}

/// Statistics snapshot for checkpoint
#[derive(Debug, Clone, Default)]
pub struct CheckpointStats {
    pub requests_made: usize,
    pub successful: usize,
    pub filtered: usize,
    pub errors: usize,
    pub links_extracted: usize,
}

impl CheckpointStats {
    fn write_to(&self, data: &mut Vec<u8>) {
        data.extend_from_slice(&(self.requests_made as u64).to_le_bytes());
        data.extend_from_slice(&(self.successful as u64).to_le_bytes());
        data.extend_from_slice(&(self.filtered as u64).to_le_bytes());
        data.extend_from_slice(&(self.errors as u64).to_le_bytes());
        data.extend_from_slice(&(self.links_extracted as u64).to_le_bytes());
    }

    fn read_from(data: &[u8], pos: &mut usize) -> Option<Self> {
        Some(Self {
            requests_made: Checkpoint::read_u64(data, pos)? as usize,
            successful: Checkpoint::read_u64(data, pos)? as usize,
            filtered: Checkpoint::read_u64(data, pos)? as usize,
            errors: Checkpoint::read_u64(data, pos)? as usize,
            links_extracted: Checkpoint::read_u64(data, pos)? as usize,
        })
    }
}

/// Configuration for the resume manager
#[derive(Debug, Clone)]
pub struct ResumeConfig {
    /// Directory to store checkpoints
    pub checkpoint_dir: PathBuf,
    /// Checkpoint interval (save every N seconds)
    pub checkpoint_interval: Duration,
    /// Maximum checkpoints to keep per scan
    pub max_checkpoints: usize,
    /// Whether to auto-checkpoint on errors
    pub checkpoint_on_error: bool,
    /// Whether to checkpoint on Ctrl+C
    pub checkpoint_on_interrupt: bool,
}

impl Default for ResumeConfig {
    fn default() -> Self {
        Self {
            checkpoint_dir: PathBuf::from(".rb_checkpoints"),
            checkpoint_interval: Duration::from_secs(30),
            max_checkpoints: 5,
            checkpoint_on_error: true,
            checkpoint_on_interrupt: true,
        }
    }
}

/// Resume manager for checkpoint coordination
pub struct ResumeManager {
    config: ResumeConfig,
    /// Current checkpoint state
    current: Option<Checkpoint>,
    /// Start time of current scan
    start_time: Option<Instant>,
    /// Last checkpoint time
    last_checkpoint: Option<Instant>,
}

impl ResumeManager {
    /// Create a new resume manager
    pub fn new(config: ResumeConfig) -> Self {
        Self {
            config,
            current: None,
            start_time: None,
            last_checkpoint: None,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ResumeConfig::default())
    }

    /// Start a new scan
    pub fn start_scan(&mut self, target_url: &str) -> ScanId {
        let scan_id = ScanId::generate();
        self.current = Some(Checkpoint::new(scan_id.clone(), target_url));
        self.start_time = Some(Instant::now());
        self.last_checkpoint = None;
        scan_id
    }

    /// Resume from a checkpoint
    pub fn resume_scan(&mut self, scan_id: &ScanId) -> Option<Checkpoint> {
        let checkpoint = self.load_checkpoint(scan_id)?;
        self.current = Some(checkpoint.clone());
        self.start_time = Some(Instant::now());
        self.last_checkpoint = None;
        Some(checkpoint)
    }

    /// Update checkpoint state
    pub fn update_state<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Checkpoint),
    {
        if let Some(ref mut checkpoint) = self.current {
            f(checkpoint);
            checkpoint.touch();

            // Update elapsed time
            if let Some(start) = self.start_time {
                checkpoint.elapsed_seconds += start.elapsed().as_secs();
            }
        }
    }

    /// Check if a checkpoint is needed
    pub fn should_checkpoint(&self) -> bool {
        match self.last_checkpoint {
            Some(last) => last.elapsed() >= self.config.checkpoint_interval,
            None => true,
        }
    }

    /// Save a checkpoint if needed
    pub fn checkpoint_if_needed(&mut self) -> bool {
        if self.should_checkpoint() {
            self.checkpoint()
        } else {
            false
        }
    }

    /// Force save a checkpoint
    pub fn checkpoint(&mut self) -> bool {
        if let Some(ref checkpoint) = self.current {
            let success = self.save_checkpoint(checkpoint);
            if success {
                self.last_checkpoint = Some(Instant::now());
            }
            success
        } else {
            false
        }
    }

    /// Get the current checkpoint state (read-only)
    pub fn current_state(&self) -> Option<&Checkpoint> {
        self.current.as_ref()
    }

    /// Complete the current scan (remove checkpoint)
    pub fn complete_scan(&mut self) -> bool {
        if let Some(ref checkpoint) = self.current {
            let scan_id = checkpoint.scan_id.clone();
            self.current = None;
            self.start_time = None;
            self.last_checkpoint = None;
            self.delete_checkpoints(&scan_id)
        } else {
            false
        }
    }

    /// List all available checkpoints
    pub fn list_checkpoints(&self) -> Vec<CheckpointInfo> {
        let mut infos = Vec::new();

        let dir = &self.config.checkpoint_dir;
        if !dir.exists() {
            return infos;
        }

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "checkpoint").unwrap_or(false) {
                    if let Some(info) = self.read_checkpoint_info(&path) {
                        infos.push(info);
                    }
                }
            }
        }

        // Sort by timestamp (newest first)
        infos.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        infos
    }

    /// Get configuration
    pub fn config(&self) -> &ResumeConfig {
        &self.config
    }

    // Private methods

    fn save_checkpoint(&self, checkpoint: &Checkpoint) -> bool {
        // Ensure directory exists
        if let Err(_) = std::fs::create_dir_all(&self.config.checkpoint_dir) {
            return false;
        }

        let filename = format!("{}.checkpoint", checkpoint.scan_id);
        let path = self.config.checkpoint_dir.join(&filename);

        let data = checkpoint.serialize();

        match std::fs::write(&path, &data) {
            Ok(_) => {
                self.cleanup_old_checkpoints(&checkpoint.scan_id);
                true
            }
            Err(_) => false,
        }
    }

    fn load_checkpoint(&self, scan_id: &ScanId) -> Option<Checkpoint> {
        let filename = format!("{}.checkpoint", scan_id);
        let path = self.config.checkpoint_dir.join(&filename);

        let data = std::fs::read(&path).ok()?;
        Checkpoint::deserialize(&data)
    }

    fn delete_checkpoints(&self, scan_id: &ScanId) -> bool {
        let pattern = format!("{}", scan_id);
        let dir = &self.config.checkpoint_dir;

        if !dir.exists() {
            return true;
        }

        let mut success = true;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_stem().and_then(|n| n.to_str()) {
                    if name.starts_with(&pattern) {
                        if std::fs::remove_file(&path).is_err() {
                            success = false;
                        }
                    }
                }
            }
        }

        success
    }

    fn cleanup_old_checkpoints(&self, _scan_id: &ScanId) {
        // For now, just keep the latest checkpoint
        // A more sophisticated implementation would keep N versions
    }

    fn read_checkpoint_info(&self, path: &Path) -> Option<CheckpointInfo> {
        let data = std::fs::read(path).ok()?;
        let checkpoint = Checkpoint::deserialize(&data)?;

        let progress = checkpoint.progress_percent();
        Some(CheckpointInfo {
            scan_id: checkpoint.scan_id,
            target_url: checkpoint.target_url,
            progress_percent: progress,
            timestamp: checkpoint.timestamp,
            elapsed_seconds: checkpoint.elapsed_seconds,
            requests_made: checkpoint.stats.requests_made,
        })
    }
}

/// Information about a checkpoint (without full state)
#[derive(Debug, Clone)]
pub struct CheckpointInfo {
    pub scan_id: ScanId,
    pub target_url: String,
    pub progress_percent: f64,
    pub timestamp: u64,
    pub elapsed_seconds: u64,
    pub requests_made: usize,
}

impl CheckpointInfo {
    /// Format the timestamp as a human-readable string
    pub fn timestamp_string(&self) -> String {
        // Simple timestamp formatting
        let secs = self.timestamp;
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        let mins = (secs % 3600) / 60;

        format!("{}d {:02}:{:02}", days, hours, mins)
    }

    /// Format elapsed time as human-readable string
    pub fn elapsed_string(&self) -> String {
        let secs = self.elapsed_seconds;
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        let secs = secs % 60;

        if hours > 0 {
            format!("{}h {}m {}s", hours, mins, secs)
        } else if mins > 0 {
            format!("{}m {}s", mins, secs)
        } else {
            format!("{}s", secs)
        }
    }
}

/// Builder for ResumeManager
pub struct ResumeManagerBuilder {
    config: ResumeConfig,
}

impl ResumeManagerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: ResumeConfig::default(),
        }
    }

    /// Set checkpoint directory
    pub fn checkpoint_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config.checkpoint_dir = dir.into();
        self
    }

    /// Set checkpoint interval
    pub fn checkpoint_interval(mut self, interval: Duration) -> Self {
        self.config.checkpoint_interval = interval;
        self
    }

    /// Set maximum checkpoints to keep
    pub fn max_checkpoints(mut self, max: usize) -> Self {
        self.config.max_checkpoints = max.max(1);
        self
    }

    /// Enable/disable checkpoint on error
    pub fn checkpoint_on_error(mut self, enable: bool) -> Self {
        self.config.checkpoint_on_error = enable;
        self
    }

    /// Enable/disable checkpoint on interrupt
    pub fn checkpoint_on_interrupt(mut self, enable: bool) -> Self {
        self.config.checkpoint_on_interrupt = enable;
        self
    }

    /// Build the resume manager
    pub fn build(self) -> ResumeManager {
        ResumeManager::new(self.config)
    }
}

impl Default for ResumeManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_id_generation() {
        let id1 = ScanId::generate();
        let id2 = ScanId::generate();

        // IDs should be unique
        assert_ne!(id1, id2);

        // IDs should be reasonable length
        assert!(id1.as_str().len() > 10);
    }

    #[test]
    fn test_checkpoint_serialization() {
        let mut checkpoint = Checkpoint::new(ScanId::generate(), "https://example.com/");

        checkpoint.wordlist_position = 500;
        checkpoint.wordlist_total = 1000;
        checkpoint.discovered.push("/admin".to_string());
        checkpoint.discovered.push("/api".to_string());
        checkpoint.visited.insert("/index.html".to_string());
        checkpoint.pending_urls.push(("/users".to_string(), 2));
        checkpoint.simhash_baselines.push((0xDEADBEEF, 404));
        checkpoint.learned_words.push(("admin".to_string(), 0.75));
        checkpoint.stats.requests_made = 500;
        checkpoint.stats.successful = 450;

        // Serialize
        let data = checkpoint.serialize();

        // Deserialize
        let restored = Checkpoint::deserialize(&data).unwrap();

        assert_eq!(restored.scan_id, checkpoint.scan_id);
        assert_eq!(restored.target_url, checkpoint.target_url);
        assert_eq!(restored.wordlist_position, 500);
        assert_eq!(restored.wordlist_total, 1000);
        assert_eq!(restored.discovered.len(), 2);
        assert!(restored.visited.contains("/index.html"));
        assert_eq!(restored.pending_urls.len(), 1);
        assert_eq!(restored.simhash_baselines.len(), 1);
        assert_eq!(restored.learned_words.len(), 1);
        assert_eq!(restored.stats.requests_made, 500);
    }

    #[test]
    fn test_progress_calculation() {
        let mut checkpoint = Checkpoint::new(ScanId::generate(), "https://example.com/");

        assert_eq!(checkpoint.progress_percent(), 0.0);

        checkpoint.wordlist_position = 50;
        checkpoint.wordlist_total = 100;

        assert_eq!(checkpoint.progress_percent(), 50.0);
    }

    #[test]
    fn test_resume_manager_start_scan() {
        let mut manager = ResumeManager::with_defaults();

        let scan_id = manager.start_scan("https://example.com/");

        assert!(manager.current_state().is_some());
        assert_eq!(manager.current_state().unwrap().scan_id, scan_id);
    }

    #[test]
    fn test_resume_manager_update_state() {
        let mut manager = ResumeManager::with_defaults();
        manager.start_scan("https://example.com/");

        manager.update_state(|cp| {
            cp.wordlist_position = 100;
            cp.discovered.push("/found".to_string());
        });

        assert_eq!(manager.current_state().unwrap().wordlist_position, 100);
        assert_eq!(manager.current_state().unwrap().discovered.len(), 1);
    }

    #[test]
    fn test_builder() {
        let manager = ResumeManagerBuilder::new()
            .checkpoint_dir("/tmp/test_checkpoints")
            .checkpoint_interval(Duration::from_secs(60))
            .max_checkpoints(10)
            .build();

        assert_eq!(
            manager.config().checkpoint_interval,
            Duration::from_secs(60)
        );
        assert_eq!(manager.config().max_checkpoints, 10);
    }

    #[test]
    fn test_checkpoint_info_formatting() {
        let info = CheckpointInfo {
            scan_id: ScanId::from_string("test123"),
            target_url: "https://example.com/".to_string(),
            progress_percent: 50.0,
            timestamp: 1704067200, // Some timestamp
            elapsed_seconds: 3661, // 1h 1m 1s
            requests_made: 500,
        };

        assert_eq!(info.elapsed_string(), "1h 1m 1s");
    }
}
