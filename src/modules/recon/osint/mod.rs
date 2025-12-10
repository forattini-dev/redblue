/// OSINT Module - Username & Email Intelligence
///
/// Replaces: sherlock, maigret, holehe, socialscan
///
/// Implements:
/// - Username enumeration across 200+ platforms
/// - Email breach checking (HaveIBeenPwned-style)
/// - Social media profile discovery
/// - Identity correlation across platforms

pub mod username;
pub mod email;
pub mod platforms;
pub mod breach;

pub use username::UsernameEnumerator;
pub use email::EmailIntel;
pub use platforms::{Platform, PlatformCategory};
pub use breach::BreachChecker;

use std::time::Duration;

/// Result of a platform check
#[derive(Debug, Clone)]
pub struct ProfileResult {
    /// Platform name
    pub platform: String,
    /// Category (social, dev, gaming, etc.)
    pub category: PlatformCategory,
    /// Whether the username exists
    pub exists: bool,
    /// Profile URL if exists
    pub url: Option<String>,
    /// Additional data extracted
    pub metadata: ProfileMetadata,
    /// Check duration
    pub duration: Duration,
    /// Error if check failed
    pub error: Option<String>,
}

impl ProfileResult {
    pub fn found(platform: &str, category: PlatformCategory, url: &str) -> Self {
        Self {
            platform: platform.to_string(),
            category,
            exists: true,
            url: Some(url.to_string()),
            metadata: ProfileMetadata::default(),
            duration: Duration::ZERO,
            error: None,
        }
    }

    pub fn not_found(platform: &str, category: PlatformCategory) -> Self {
        Self {
            platform: platform.to_string(),
            category,
            exists: false,
            url: None,
            metadata: ProfileMetadata::default(),
            duration: Duration::ZERO,
            error: None,
        }
    }

    pub fn error(platform: &str, category: PlatformCategory, error: &str) -> Self {
        Self {
            platform: platform.to_string(),
            category,
            exists: false,
            url: None,
            metadata: ProfileMetadata::default(),
            duration: Duration::ZERO,
            error: Some(error.to_string()),
        }
    }

    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    pub fn with_metadata(mut self, metadata: ProfileMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Additional metadata extracted from profile
#[derive(Debug, Clone, Default)]
pub struct ProfileMetadata {
    /// Display name if available
    pub display_name: Option<String>,
    /// Bio/description
    pub bio: Option<String>,
    /// Profile image URL
    pub avatar_url: Option<String>,
    /// Follower count
    pub followers: Option<u64>,
    /// Following count
    pub following: Option<u64>,
    /// Number of posts/repos/etc
    pub post_count: Option<u64>,
    /// Account creation date
    pub created_at: Option<String>,
    /// Last activity date
    pub last_active: Option<String>,
    /// Location if available
    pub location: Option<String>,
    /// Website URL
    pub website: Option<String>,
    /// Email if public
    pub email: Option<String>,
    /// Verified account
    pub verified: bool,
    /// Raw extra data
    pub extra: Vec<(String, String)>,
}

/// Email intelligence result
#[derive(Debug, Clone)]
pub struct EmailResult {
    /// The email address checked
    pub email: String,
    /// Whether the email exists/is valid
    pub valid: bool,
    /// Email provider
    pub provider: Option<String>,
    /// Breaches found
    pub breaches: Vec<BreachInfo>,
    /// Pastes found
    pub pastes: Vec<PasteInfo>,
    /// Services registered
    pub services: Vec<String>,
    /// Social profiles linked
    pub social_profiles: Vec<ProfileResult>,
}

/// Information about a data breach
#[derive(Debug, Clone)]
pub struct BreachInfo {
    /// Breach name
    pub name: String,
    /// Date of breach
    pub date: Option<String>,
    /// Number of accounts affected
    pub accounts: Option<u64>,
    /// Types of data exposed
    pub data_types: Vec<String>,
    /// Description
    pub description: Option<String>,
    /// Is verified breach
    pub verified: bool,
    /// Is sensitive breach
    pub sensitive: bool,
}

/// Information about a paste
#[derive(Debug, Clone)]
pub struct PasteInfo {
    /// Paste source (Pastebin, etc.)
    pub source: String,
    /// Paste ID
    pub id: String,
    /// Title if available
    pub title: Option<String>,
    /// Date added
    pub date: Option<String>,
    /// Number of emails in paste
    pub email_count: Option<u64>,
}

/// Configuration for OSINT operations
#[derive(Debug, Clone)]
pub struct OsintConfig {
    /// Request timeout
    pub timeout: Duration,
    /// Number of concurrent requests
    pub threads: usize,
    /// Delay between requests (rate limiting)
    pub delay: Duration,
    /// User agent to use
    pub user_agent: String,
    /// Categories to check
    pub categories: Vec<PlatformCategory>,
    /// Platforms to skip
    pub skip_platforms: Vec<String>,
    /// Extract metadata (slower but more info)
    pub extract_metadata: bool,
    /// Follow redirects
    pub follow_redirects: bool,
}

impl Default for OsintConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            threads: 20,
            delay: Duration::from_millis(100),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            categories: vec![
                PlatformCategory::Social,
                PlatformCategory::Development,
                PlatformCategory::Gaming,
                PlatformCategory::Business,
                PlatformCategory::Creative,
            ],
            skip_platforms: Vec::new(),
            extract_metadata: false,
            follow_redirects: true,
        }
    }
}

/// Summary of username enumeration
#[derive(Debug, Clone, Default)]
pub struct EnumerationSummary {
    /// Total platforms checked
    pub total_checked: usize,
    /// Platforms where username exists
    pub found_count: usize,
    /// Platforms where username doesn't exist
    pub not_found_count: usize,
    /// Platforms that errored
    pub error_count: usize,
    /// Results by category
    pub by_category: std::collections::HashMap<PlatformCategory, Vec<ProfileResult>>,
    /// Total time taken
    pub duration: Duration,
}

impl EnumerationSummary {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_result(&mut self, result: ProfileResult) {
        self.total_checked += 1;

        if result.error.is_some() {
            self.error_count += 1;
        } else if result.exists {
            self.found_count += 1;
        } else {
            self.not_found_count += 1;
        }

        self.by_category
            .entry(result.category)
            .or_default()
            .push(result);
    }
}
