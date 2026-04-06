//! Monitoring & Analytics Secret Patterns
//!
//! Patterns for Datadog, Sentry, New Relic, Mixpanel, Amplitude, etc.

use super::super::Severity;
use super::types::{PatternCategory, PatternMatcher, SecretPattern};

/// Get all analytics patterns
pub fn patterns() -> Vec<SecretPattern> {
  vec![
    // ===============================
    // Datadog
    // ===============================
    SecretPattern {
      name: "Datadog API Key",
      category: PatternCategory::ApiKey,
      pattern: PatternMatcher::HexLength(32),
      severity: Severity::High,
      keywords: vec!["datadog", "dd", "api", "key"],
      requires_entropy: true,
      min_length: 32,
      max_length: 32,
      description: "Datadog API Key",
    },
    SecretPattern {
      name: "Datadog Application Key",
      category: PatternCategory::ApiKey,
      pattern: PatternMatcher::HexLength(40),
      severity: Severity::High,
      keywords: vec!["datadog", "dd", "application", "key"],
      requires_entropy: true,
      min_length: 40,
      max_length: 40,
      description: "Datadog Application Key",
    },
    // ===============================
    // New Relic
    // ===============================
    SecretPattern {
      name: "New Relic API Key",
      category: PatternCategory::ApiKey,
      pattern: PatternMatcher::Prefix("NRAK-"),
      severity: Severity::High,
      keywords: vec!["newrelic", "nr", "api", "key"],
      requires_entropy: false,
      min_length: 40,
      max_length: 50,
      description: "New Relic API Key",
    },
    // ===============================
    // Sentry
    // ===============================
    SecretPattern {
      name: "Sentry DSN",
      category: PatternCategory::ApiKey,
      pattern: PatternMatcher::Contains("@sentry.io/"),
      severity: Severity::Medium,
      keywords: vec!["sentry", "dsn"],
      requires_entropy: false,
      min_length: 50,
      max_length: 200,
      description: "Sentry DSN URL",
    },
    SecretPattern {
      name: "Sentry Auth Token",
      category: PatternCategory::Token,
      pattern: PatternMatcher::Prefix("sntrys_"),
      severity: Severity::High,
      keywords: vec!["sentry", "auth", "token"],
      requires_entropy: false,
      min_length: 60,
      max_length: 100,
      description: "Sentry Internal Integration Token",
    },
    // ===============================
    // PagerDuty
    // ===============================
    SecretPattern {
      name: "PagerDuty API Key",
      category: PatternCategory::ApiKey,
      pattern: PatternMatcher::CharsetRange {
        charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-+",
        min_len: 20,
        max_len: 30,
      },
      severity: Severity::High,
      keywords: vec!["pagerduty", "pd", "api", "key"],
      requires_entropy: true,
      min_length: 20,
      max_length: 30,
      description: "PagerDuty API Key",
    },
    // ===============================
    // LaunchDarkly
    // ===============================
    SecretPattern {
      name: "LaunchDarkly API Key",
      category: PatternCategory::ApiKey,
      pattern: PatternMatcher::Prefix("api-"),
      severity: Severity::High,
      keywords: vec!["launchdarkly", "ld", "api", "key"],
      requires_entropy: false,
      min_length: 36,
      max_length: 50,
      description: "LaunchDarkly API Key",
    },
    // ===============================
    // Grafana
    // ===============================
    SecretPattern {
      name: "Grafana API Key",
      category: PatternCategory::ApiKey,
      pattern: PatternMatcher::Prefix("eyJr"),
      severity: Severity::High,
      keywords: vec!["grafana", "api", "key"],
      requires_entropy: false,
      min_length: 40,
      max_length: 100,
      description: "Grafana API Key",
    },
    // ===============================
    // Splunk
    // ===============================
    SecretPattern {
      name: "Splunk HEC Token",
      category: PatternCategory::Token,
      pattern: PatternMatcher::HexLength(36),
      severity: Severity::High,
      keywords: vec!["splunk", "hec", "token"],
      requires_entropy: true,
      min_length: 36,
      max_length: 36,
      description: "Splunk HTTP Event Collector Token",
    },
    // ===============================
    // Loggly
    // ===============================
    SecretPattern {
      name: "Loggly Token",
      category: PatternCategory::Token,
      pattern: PatternMatcher::HexLength(36),
      severity: Severity::High,
      keywords: vec!["loggly", "token", "customer"],
      requires_entropy: true,
      min_length: 36,
      max_length: 36,
      description: "Loggly Customer Token",
    },
    // ===============================
    // Dynatrace
    // ===============================
    SecretPattern {
      name: "Dynatrace API Token",
      category: PatternCategory::Token,
      pattern: PatternMatcher::Prefix("dt0c01."),
      severity: Severity::High,
      keywords: vec!["dynatrace", "api", "token"],
      requires_entropy: false,
      min_length: 80,
      max_length: 120,
      description: "Dynatrace API Token",
    },
    // ===============================
    // Analytics Platforms
    // ===============================
    SecretPattern {
      name: "Mixpanel API Secret",
      category: PatternCategory::ApiKey,
      pattern: PatternMatcher::HexLength(32),
      severity: Severity::High,
      keywords: vec!["mixpanel", "api", "secret"],
      requires_entropy: true,
      min_length: 32,
      max_length: 32,
      description: "Mixpanel API Secret",
    },
    SecretPattern {
      name: "Amplitude API Key",
      category: PatternCategory::ApiKey,
      pattern: PatternMatcher::HexLength(32),
      severity: Severity::Medium,
      keywords: vec!["amplitude", "api", "key"],
      requires_entropy: true,
      min_length: 32,
      max_length: 32,
      description: "Amplitude API Key",
    },
    SecretPattern {
      name: "Segment Write Key",
      category: PatternCategory::ApiKey,
      pattern: PatternMatcher::CharsetRange {
        charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        min_len: 20,
        max_len: 30,
      },
      severity: Severity::Medium,
      keywords: vec!["segment", "write", "key"],
      requires_entropy: true,
      min_length: 20,
      max_length: 30,
      description: "Segment Write Key",
    },
    SecretPattern {
      name: "Heap Analytics App ID",
      category: PatternCategory::ApiKey,
      pattern: PatternMatcher::CharsetRange {
        charset: "0123456789",
        min_len: 9,
        max_len: 12,
      },
      severity: Severity::Low,
      keywords: vec!["heap", "analytics", "app", "id"],
      requires_entropy: false,
      min_length: 9,
      max_length: 12,
      description: "Heap Analytics App ID",
    },
  ]
}
