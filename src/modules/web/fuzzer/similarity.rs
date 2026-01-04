//! Similarity Filter for Response Deduplication
//!
//! Uses simhash-based fingerprinting to detect and filter near-duplicate
//! HTTP responses, enabling effective soft-404 detection and noise reduction.

use super::simhash::{Simhash, SimhashCalculator, SimhashConfig, SimhashIndex};
use std::collections::HashMap;

/// Result of a similarity check
#[derive(Debug, Clone)]
pub enum SimilarityResult {
    /// Response is unique (not similar to any baseline)
    Unique,
    /// Response is similar to a baseline (soft-404 or duplicate)
    Similar {
        /// Index of the similar baseline
        baseline_index: usize,
        /// Hamming distance to the baseline
        distance: u32,
        /// Similarity percentage
        similarity: f64,
    },
    /// Response matches a baseline exactly
    Exact {
        /// Index of the matching baseline
        baseline_index: usize,
    },
}

impl SimilarityResult {
    /// Check if the response should be filtered out
    pub fn should_filter(&self) -> bool {
        matches!(
            self,
            SimilarityResult::Similar { .. } | SimilarityResult::Exact { .. }
        )
    }

    /// Check if the response is unique
    pub fn is_unique(&self) -> bool {
        matches!(self, SimilarityResult::Unique)
    }
}

/// Internal result type for statistics tracking
#[derive(Clone, Copy)]
enum CheckResultType {
    Unique,
    Exact,
    Similar,
}

/// Configuration for the similarity filter
#[derive(Debug, Clone)]
pub struct SimilarityConfig {
    /// Maximum hamming distance to consider similar (0-64)
    /// Lower values are more strict:
    /// - 0: exact match only
    /// - 3: very similar (recommended for soft-404)
    /// - 5: somewhat similar
    /// - 10: loosely similar
    pub threshold: u32,
    /// Number of baseline samples to capture per status code
    pub baseline_samples: usize,
    /// Whether to auto-calibrate threshold based on baseline variance
    pub auto_calibrate: bool,
    /// Minimum content length to apply similarity filtering
    pub min_content_length: usize,
    /// Whether to track per-status-code baselines
    pub per_status_baselines: bool,
    /// Simhash configuration
    pub simhash_config: SimhashConfig,
}

impl Default for SimilarityConfig {
    fn default() -> Self {
        Self {
            threshold: 3,
            baseline_samples: 3,
            auto_calibrate: true,
            min_content_length: 100,
            per_status_baselines: true,
            simhash_config: SimhashConfig::default(),
        }
    }
}

impl SimilarityConfig {
    /// Strict configuration (fewer false positives, may miss some duplicates)
    pub fn strict() -> Self {
        Self {
            threshold: 1,
            baseline_samples: 5,
            auto_calibrate: true,
            ..Default::default()
        }
    }

    /// Relaxed configuration (catches more duplicates, may have false positives)
    pub fn relaxed() -> Self {
        Self {
            threshold: 8,
            baseline_samples: 2,
            auto_calibrate: false,
            ..Default::default()
        }
    }

    /// Configuration optimized for soft-404 detection
    pub fn for_soft_404() -> Self {
        Self {
            threshold: 3,
            baseline_samples: 3,
            auto_calibrate: true,
            per_status_baselines: true,
            ..Default::default()
        }
    }
}

/// Baseline response information
#[derive(Debug, Clone)]
pub struct Baseline {
    /// Simhash of the response body
    pub hash: Simhash,
    /// HTTP status code
    pub status_code: u16,
    /// Content length
    pub content_length: usize,
    /// URL that generated this baseline (optional)
    pub source_url: Option<String>,
}

/// Statistics for the similarity filter
#[derive(Debug, Clone, Default)]
pub struct SimilarityStats {
    /// Total responses checked
    pub total_checked: usize,
    /// Responses marked as unique
    pub unique_count: usize,
    /// Responses filtered as similar
    pub similar_count: usize,
    /// Responses filtered as exact matches
    pub exact_count: usize,
    /// Number of baselines captured
    pub baseline_count: usize,
    /// Breakdown by status code
    pub by_status_code: HashMap<u16, StatusCodeStats>,
}

/// Per-status-code statistics
#[derive(Debug, Clone, Default)]
pub struct StatusCodeStats {
    pub total: usize,
    pub unique: usize,
    pub similar: usize,
    pub exact: usize,
}

/// Similarity filter for HTTP response deduplication
///
/// Captures baseline responses and filters similar ones based on simhash
/// comparison, enabling effective soft-404 detection.
pub struct SimilarityFilter {
    config: SimilarityConfig,
    calculator: SimhashCalculator,
    /// Global baseline index
    global_index: SimhashIndex,
    /// Per-status-code baseline indices
    status_indices: HashMap<u16, SimhashIndex>,
    /// All captured baselines
    baselines: Vec<Baseline>,
    /// Calibrated threshold (may differ from config if auto-calibrated)
    calibrated_threshold: Option<u32>,
    /// Statistics
    stats: SimilarityStats,
}

impl SimilarityFilter {
    /// Create a new similarity filter with the given configuration
    pub fn new(config: SimilarityConfig) -> Self {
        let calculator = SimhashCalculator::new(config.simhash_config.clone());

        Self {
            config,
            calculator,
            global_index: SimhashIndex::with_defaults(),
            status_indices: HashMap::new(),
            baselines: Vec::new(),
            calibrated_threshold: None,
            stats: SimilarityStats::default(),
        }
    }

    /// Create a filter with default configuration
    pub fn with_defaults() -> Self {
        Self::new(SimilarityConfig::default())
    }

    /// Create a filter optimized for soft-404 detection
    pub fn for_soft_404() -> Self {
        Self::new(SimilarityConfig::for_soft_404())
    }

    /// Get the effective threshold (calibrated or configured)
    pub fn effective_threshold(&self) -> u32 {
        self.calibrated_threshold.unwrap_or(self.config.threshold)
    }

    /// Add a baseline response
    ///
    /// Call this during the calibration phase to establish what
    /// "normal" error responses look like.
    pub fn add_baseline(&mut self, body: &str, status_code: u16, source_url: Option<String>) {
        // Skip very short content
        if body.len() < self.config.min_content_length {
            return;
        }

        let hash = self.calculator.hash(body);

        // Check if we already have too many baselines for this status
        let status_baseline_count = self
            .baselines
            .iter()
            .filter(|b| b.status_code == status_code)
            .count();

        if status_baseline_count >= self.config.baseline_samples {
            return;
        }

        let baseline = Baseline {
            hash,
            status_code,
            content_length: body.len(),
            source_url,
        };

        let idx = self.baselines.len();
        self.baselines.push(baseline);

        // Add to global index
        self.global_index.insert(hash);

        // Add to status-specific index
        if self.config.per_status_baselines {
            self.status_indices
                .entry(status_code)
                .or_insert_with(SimhashIndex::with_defaults)
                .insert(hash);
        }

        self.stats.baseline_count += 1;

        // Auto-calibrate if enabled and we have enough samples
        if self.config.auto_calibrate && self.baselines.len() >= 2 {
            self.calibrate_threshold();
        }
    }

    /// Add multiple baseline samples for calibration
    pub fn add_baselines(&mut self, samples: &[(&str, u16)]) {
        for (body, status) in samples {
            self.add_baseline(body, *status, None);
        }
    }

    /// Auto-calibrate the threshold based on baseline variance
    ///
    /// Calculates the maximum hamming distance between all baselines
    /// and sets the threshold to be slightly higher.
    fn calibrate_threshold(&mut self) {
        if self.baselines.len() < 2 {
            return;
        }

        let mut max_distance: u32 = 0;

        // Find maximum distance between baselines of the same status code
        for i in 0..self.baselines.len() {
            for j in (i + 1)..self.baselines.len() {
                // Only compare baselines of the same status code
                if self.baselines[i].status_code != self.baselines[j].status_code {
                    continue;
                }

                let distance = self.baselines[i]
                    .hash
                    .hamming_distance(&self.baselines[j].hash);
                max_distance = max_distance.max(distance);
            }
        }

        // Set threshold to be slightly above the maximum baseline variance
        // This ensures baselines are considered similar while unique responses
        // are allowed through
        self.calibrated_threshold = Some(max_distance.saturating_add(2).min(15));
    }

    /// Check if a response is similar to any baseline
    pub fn check(&mut self, body: &str, status_code: u16) -> SimilarityResult {
        self.stats.total_checked += 1;

        // Determine the result and stats update type
        let (result, update_type) = self.check_inner(body, status_code);

        // Update global stats
        match update_type {
            CheckResultType::Unique => self.stats.unique_count += 1,
            CheckResultType::Exact => self.stats.exact_count += 1,
            CheckResultType::Similar => self.stats.similar_count += 1,
        }

        // Update per-status stats
        let status_stats = self
            .stats
            .by_status_code
            .entry(status_code)
            .or_insert_with(StatusCodeStats::default);
        status_stats.total += 1;
        match update_type {
            CheckResultType::Unique => status_stats.unique += 1,
            CheckResultType::Exact => status_stats.exact += 1,
            CheckResultType::Similar => status_stats.similar += 1,
        }

        result
    }

    /// Inner check logic that determines result without updating stats
    fn check_inner(&self, body: &str, status_code: u16) -> (SimilarityResult, CheckResultType) {
        // Skip very short content
        if body.len() < self.config.min_content_length {
            return (SimilarityResult::Unique, CheckResultType::Unique);
        }

        // No baselines yet, everything is unique
        if self.baselines.is_empty() {
            return (SimilarityResult::Unique, CheckResultType::Unique);
        }

        let hash = self.calculator.hash(body);
        let threshold = self.effective_threshold();

        // Check status-specific index first (if available and configured)
        if self.config.per_status_baselines {
            if let Some(status_index) = self.status_indices.get(&status_code) {
                let similar = status_index.find_similar(hash, threshold);
                if let Some((_, baseline_hash, distance)) = similar.first() {
                    if *distance == 0 {
                        return (
                            SimilarityResult::Exact {
                                baseline_index: self.find_baseline_index(*baseline_hash),
                            },
                            CheckResultType::Exact,
                        );
                    }

                    return (
                        SimilarityResult::Similar {
                            baseline_index: self.find_baseline_index(*baseline_hash),
                            distance: *distance,
                            similarity: hash.similarity(baseline_hash),
                        },
                        CheckResultType::Similar,
                    );
                }
            }
        }

        // Check global index
        let similar = self.global_index.find_similar(hash, threshold);
        if let Some((_, baseline_hash, distance)) = similar.first() {
            if *distance == 0 {
                return (
                    SimilarityResult::Exact {
                        baseline_index: self.find_baseline_index(*baseline_hash),
                    },
                    CheckResultType::Exact,
                );
            }

            return (
                SimilarityResult::Similar {
                    baseline_index: self.find_baseline_index(*baseline_hash),
                    distance: *distance,
                    similarity: hash.similarity(baseline_hash),
                },
                CheckResultType::Similar,
            );
        }

        (SimilarityResult::Unique, CheckResultType::Unique)
    }

    /// Check and return a boolean (convenience method)
    pub fn is_similar(&mut self, body: &str, status_code: u16) -> bool {
        self.check(body, status_code).should_filter()
    }

    /// Check if body is unique (not similar to any baseline)
    pub fn is_unique(&mut self, body: &str, status_code: u16) -> bool {
        self.check(body, status_code).is_unique()
    }

    /// Find baseline index by hash
    fn find_baseline_index(&self, hash: Simhash) -> usize {
        self.baselines
            .iter()
            .position(|b| b.hash == hash)
            .unwrap_or(0)
    }

    /// Get filter statistics
    pub fn stats(&self) -> &SimilarityStats {
        &self.stats
    }

    /// Get all baselines
    pub fn baselines(&self) -> &[Baseline] {
        &self.baselines
    }

    /// Reset filter state (clear baselines and stats)
    pub fn reset(&mut self) {
        self.global_index.clear();
        self.status_indices.clear();
        self.baselines.clear();
        self.calibrated_threshold = None;
        self.stats = SimilarityStats::default();
    }

    /// Get the simhash of a body (for external use)
    pub fn hash(&self, body: &str) -> Simhash {
        self.calculator.hash(body)
    }
}

/// Builder for SimilarityFilter
pub struct SimilarityFilterBuilder {
    config: SimilarityConfig,
    initial_baselines: Vec<(String, u16)>,
}

impl SimilarityFilterBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: SimilarityConfig::default(),
            initial_baselines: Vec::new(),
        }
    }

    /// Set the similarity threshold
    pub fn threshold(mut self, threshold: u32) -> Self {
        self.config.threshold = threshold.min(64);
        self
    }

    /// Set the number of baseline samples to capture
    pub fn baseline_samples(mut self, count: usize) -> Self {
        self.config.baseline_samples = count.max(1);
        self
    }

    /// Enable/disable auto-calibration
    pub fn auto_calibrate(mut self, enable: bool) -> Self {
        self.config.auto_calibrate = enable;
        self
    }

    /// Set minimum content length for filtering
    pub fn min_content_length(mut self, length: usize) -> Self {
        self.config.min_content_length = length;
        self
    }

    /// Enable/disable per-status-code baselines
    pub fn per_status_baselines(mut self, enable: bool) -> Self {
        self.config.per_status_baselines = enable;
        self
    }

    /// Set simhash configuration
    pub fn simhash_config(mut self, config: SimhashConfig) -> Self {
        self.config.simhash_config = config;
        self
    }

    /// Add initial baselines
    pub fn with_baselines(mut self, baselines: Vec<(String, u16)>) -> Self {
        self.initial_baselines = baselines;
        self
    }

    /// Build the filter
    pub fn build(self) -> SimilarityFilter {
        let mut filter = SimilarityFilter::new(self.config);

        for (body, status) in self.initial_baselines {
            filter.add_baseline(&body, status, None);
        }

        filter
    }
}

impl Default for SimilarityFilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper struct for soft-404 detection workflow
pub struct Soft404Detector {
    filter: SimilarityFilter,
    calibrated: bool,
}

impl Soft404Detector {
    /// Create a new soft-404 detector
    pub fn new() -> Self {
        Self {
            filter: SimilarityFilter::for_soft_404(),
            calibrated: false,
        }
    }

    /// Calibrate with random path responses
    ///
    /// Provide responses from random/non-existent paths to establish
    /// what 404 pages look like for this target.
    pub fn calibrate(&mut self, responses: &[(&str, u16)]) {
        for (body, status) in responses {
            self.filter.add_baseline(body, *status, None);
        }
        self.calibrated = true;
    }

    /// Check if a response is a soft-404
    pub fn is_soft_404(&mut self, body: &str, status_code: u16) -> bool {
        // If not calibrated and status is 200, we can't detect soft-404
        if !self.calibrated && status_code == 200 {
            return false;
        }

        self.filter.is_similar(body, status_code)
    }

    /// Check and get detailed result
    pub fn check(&mut self, body: &str, status_code: u16) -> SimilarityResult {
        self.filter.check(body, status_code)
    }

    /// Get underlying filter stats
    pub fn stats(&self) -> &SimilarityStats {
        self.filter.stats()
    }
}

impl Default for Soft404Detector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_filtering() {
        let mut filter = SimilarityFilter::with_defaults();

        // Add baseline (404 error page)
        let baseline = "<!DOCTYPE html><html><body><h1>Page Not Found</h1><p>Sorry, the page you requested could not be found.</p></body></html>";
        filter.add_baseline(baseline, 404, None);

        // Similar 404 should be filtered
        let similar = "<!DOCTYPE html><html><body><h1>Page Not Found</h1><p>Sorry, the requested page could not be found.</p></body></html>";
        assert!(filter.is_similar(similar, 404));

        // Different content should be unique
        let different = "<!DOCTYPE html><html><body><h1>Admin Panel</h1><p>Welcome to the administration dashboard.</p></body></html>";
        assert!(filter.is_unique(different, 200));
    }

    #[test]
    fn test_auto_calibration() {
        let config = SimilarityConfig {
            auto_calibrate: true,
            baseline_samples: 3,
            ..Default::default()
        };
        let mut filter = SimilarityFilter::new(config);

        // Add multiple similar baselines
        let base1 = "Error: Page not found. The page you are looking for does not exist.";
        let base2 = "Error: Page not found. The page you requested does not exist.";
        let base3 = "Error: Page not found. This page does not exist on our server.";

        filter.add_baseline(base1, 404, None);
        filter.add_baseline(base2, 404, None);
        filter.add_baseline(base3, 404, None);

        // Threshold should be calibrated
        assert!(filter.calibrated_threshold.is_some());
    }

    #[test]
    fn test_per_status_baselines() {
        let mut filter = SimilarityFilter::with_defaults();

        // Add different baselines for different status codes
        let not_found = "<!DOCTYPE html><html><body><h1>404 - Not Found</h1></body></html>";
        let forbidden = "<!DOCTYPE html><html><body><h1>403 - Forbidden</h1></body></html>";

        filter.add_baseline(not_found, 404, None);
        filter.add_baseline(forbidden, 403, None);

        // Each should match its own status code's baseline
        assert!(filter.is_similar(not_found, 404));
        assert!(filter.is_similar(forbidden, 403));
    }

    #[test]
    fn test_soft_404_detector() {
        let mut detector = Soft404Detector::new();

        // Calibrate with random path responses
        let random_responses = vec![
            (
                "Page not found - this page doesn't exist on our server. Please check the URL.",
                200_u16,
            ),
            (
                "Page not found - the requested resource was not located. Try searching.",
                200_u16,
            ),
        ];
        detector.calibrate(&random_responses);

        // Should detect soft-404
        let soft_404 = "Page not found - this resource doesn't exist on our server. Check URL.";
        assert!(detector.is_soft_404(soft_404, 200));

        // Real content should pass
        let real_content =
            "Welcome to the Admin Dashboard. Here you can manage users and settings.";
        assert!(!detector.is_soft_404(real_content, 200));
    }

    #[test]
    fn test_stats_tracking() {
        let mut filter = SimilarityFilter::with_defaults();

        let baseline = "This is a baseline response for testing purposes with enough content.";
        filter.add_baseline(baseline, 200, None);

        // Check some responses
        filter.check(baseline, 200); // Exact match
        filter.check(
            "This is a baseline response for testing with enough content.",
            200,
        ); // Similar
        filter.check(
            "Completely different content that should be marked as unique here.",
            200,
        ); // Unique

        let stats = filter.stats();
        assert_eq!(stats.total_checked, 3);
        assert_eq!(stats.baseline_count, 1);
    }

    #[test]
    fn test_builder() {
        let filter = SimilarityFilterBuilder::new()
            .threshold(5)
            .baseline_samples(5)
            .auto_calibrate(false)
            .build();

        assert_eq!(filter.config.threshold, 5);
        assert_eq!(filter.config.baseline_samples, 5);
        assert!(!filter.config.auto_calibrate);
    }

    #[test]
    fn test_short_content_bypass() {
        let mut filter = SimilarityFilter::with_defaults();

        filter.add_baseline("Short", 200, None);

        // Short content should always be unique (bypass filtering)
        let result = filter.check("Short content", 200);
        assert!(result.is_unique());
    }
}
