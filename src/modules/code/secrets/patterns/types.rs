//! Core Types for Secret Detection Patterns
//!
//! Contains the fundamental types used by all pattern modules.

use super::super::Severity;

/// Categories of secrets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternCategory {
  ApiKey,
  PrivateKey,
  Password,
  Token,
  CloudCredential,
  DatabaseCredential,
  CryptoKey,
  Certificate,
  Webhook,
  GenericSecret,
}

impl std::fmt::Display for PatternCategory {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::ApiKey => write!(f, "API Key"),
      Self::PrivateKey => write!(f, "Private Key"),
      Self::Password => write!(f, "Password"),
      Self::Token => write!(f, "Token"),
      Self::CloudCredential => write!(f, "Cloud Credential"),
      Self::DatabaseCredential => write!(f, "Database Credential"),
      Self::CryptoKey => write!(f, "Crypto Key"),
      Self::Certificate => write!(f, "Certificate"),
      Self::Webhook => write!(f, "Webhook"),
      Self::GenericSecret => write!(f, "Generic Secret"),
    }
  }
}

impl Default for PatternCategory {
  fn default() -> Self {
    Self::GenericSecret
  }
}

/// A secret detection pattern
#[derive(Debug, Clone)]
pub struct SecretPattern {
  /// Pattern name
  pub name: &'static str,
  /// Category
  pub category: PatternCategory,
  /// Pattern to match (simplified regex-like)
  pub pattern: PatternMatcher,
  /// Severity if matched
  pub severity: Severity,
  /// Keywords that must be present nearby
  pub keywords: Vec<&'static str>,
  /// Entropy check required
  pub requires_entropy: bool,
  /// Minimum length
  pub min_length: usize,
  /// Maximum length
  pub max_length: usize,
  /// Description
  pub description: &'static str,
}

/// Pattern matching methods (no external regex crate)
#[derive(Debug, Clone)]
pub enum PatternMatcher {
  /// Exact prefix match
  Prefix(&'static str),
  /// Exact suffix match
  Suffix(&'static str),
  /// Contains substring
  Contains(&'static str),
  /// Character set + length
  CharsetLength {
    charset: &'static str,
    length: usize,
  },
  /// Character set + length range
  CharsetRange {
    charset: &'static str,
    min_len: usize,
    max_len: usize,
  },
  /// PEM block format
  PemBlock(&'static str),
  /// Multiple conditions (AND)
  All(Vec<PatternMatcher>),
  /// Multiple conditions (OR)
  Any(Vec<PatternMatcher>),
  /// Base64-like pattern with length
  Base64Length(usize),
  /// Hex pattern with length
  HexLength(usize),
  /// JWT format
  Jwt,
  /// Connection string format
  ConnectionString(&'static str),
}

impl PatternMatcher {
  /// Check if a string matches this pattern
  pub fn matches(&self, s: &str) -> bool {
    match self {
      PatternMatcher::Prefix(p) => s.starts_with(p),
      PatternMatcher::Suffix(p) => s.ends_with(p),
      PatternMatcher::Contains(p) => s.contains(p),
      PatternMatcher::CharsetLength { charset, length } => {
        s.len() == *length && s.chars().all(|c| charset.contains(c))
      }
      PatternMatcher::CharsetRange {
        charset,
        min_len,
        max_len,
      } => s.len() >= *min_len && s.len() <= *max_len && s.chars().all(|c| charset.contains(c)),
      PatternMatcher::PemBlock(block_type) => {
        s.contains(&format!("-----BEGIN {}-----", block_type))
          && s.contains(&format!("-----END {}-----", block_type))
      }
      PatternMatcher::All(patterns) => patterns.iter().all(|p| p.matches(s)),
      PatternMatcher::Any(patterns) => patterns.iter().any(|p| p.matches(s)),
      PatternMatcher::Base64Length(len) => {
        s.len() >= *len
          && s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
      }
      PatternMatcher::HexLength(len) => s.len() == *len && s.chars().all(|c| c.is_ascii_hexdigit()),
      PatternMatcher::Jwt => {
        let parts: Vec<&str> = s.split('.').collect();
        parts.len() == 3
          && parts.iter().all(|p| {
            p.chars()
              .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
          })
      }
      PatternMatcher::ConnectionString(prefix) => {
        s.starts_with(prefix) && (s.contains("://") || s.contains("password="))
      }
    }
  }
}
