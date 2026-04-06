//! Platform type definitions for username enumeration
//!
//! Contains shared types used across all platform category modules.

/// Platform categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PlatformCategory {
  Social,
  Development,
  Gaming,
  Business,
  Creative,
  Music,
  Video,
  News,
  Education,
  Shopping,
  Dating,
  Finance,
  Photography,
  Forum,
  Crypto,
  Adult,
  #[default]
  Other,
}

impl std::fmt::Display for PlatformCategory {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Social => write!(f, "Social"),
      Self::Development => write!(f, "Development"),
      Self::Gaming => write!(f, "Gaming"),
      Self::Business => write!(f, "Business"),
      Self::Creative => write!(f, "Creative"),
      Self::Music => write!(f, "Music"),
      Self::Video => write!(f, "Video"),
      Self::News => write!(f, "News"),
      Self::Education => write!(f, "Education"),
      Self::Shopping => write!(f, "Shopping"),
      Self::Dating => write!(f, "Dating"),
      Self::Finance => write!(f, "Finance"),
      Self::Photography => write!(f, "Photography"),
      Self::Forum => write!(f, "Forum"),
      Self::Crypto => write!(f, "Crypto"),
      Self::Adult => write!(f, "Adult"),
      Self::Other => write!(f, "Other"),
    }
  }
}

/// Detection method for username existence
#[derive(Debug, Clone)]
pub enum DetectionMethod {
  /// Check HTTP status code (200 = exists, 404 = not found)
  StatusCode { found: u16, not_found: u16 },
  /// Search for specific text in response body
  ResponseContains {
    found: String,
    not_found: Option<String>,
  },
  /// Check if response body doesn't contain text
  ResponseNotContains { text: String },
  /// Check for redirect to specific URL pattern
  RedirectTo { pattern: String },
  /// Check JSON response field
  JsonField { path: String, expected: String },
  /// Custom regex match
  Regex { pattern: String },
}

/// Platform definition
#[derive(Debug, Clone)]
pub struct Platform {
  /// Platform name
  pub name: &'static str,
  /// Category
  pub category: PlatformCategory,
  /// URL pattern with {username} placeholder
  pub url_pattern: &'static str,
  /// Detection method
  pub detection: DetectionMethod,
  /// Whether username is case-sensitive
  pub case_sensitive: bool,
  /// Minimum username length
  pub min_length: usize,
  /// Maximum username length
  pub max_length: usize,
  /// Allowed characters regex pattern
  pub allowed_chars: Option<&'static str>,
  /// Required headers
  pub headers: Vec<(&'static str, &'static str)>,
  /// Request method (GET/HEAD/POST)
  pub method: &'static str,
  /// POST data if applicable
  pub post_data: Option<&'static str>,
}

impl Default for Platform {
  fn default() -> Self {
    Self {
      name: "",
      category: PlatformCategory::Other,
      url_pattern: "",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      case_sensitive: false,
      min_length: 1,
      max_length: 64,
      allowed_chars: None,
      headers: Vec::new(),
      method: "GET",
      post_data: None,
    }
  }
}

impl Platform {
  /// Check if a username is valid for this platform
  pub fn validate_username(&self, username: &str) -> bool {
    let len = username.len();
    if len < self.min_length || len > self.max_length {
      return false;
    }
    true
  }

  /// Get the URL for a specific username
  pub fn get_url(&self, username: &str) -> String {
    self.url_pattern.replace("{username}", username)
  }
}
