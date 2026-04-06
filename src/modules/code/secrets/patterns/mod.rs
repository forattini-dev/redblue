//! Secret Detection Patterns
//!
//! Contains 180+ patterns for detecting various types of secrets organized by category:
//!
//! - **Cloud Providers**: AWS, GCP, Azure, Alibaba, Oracle, IBM, DigitalOcean, Linode, Vultr, etc.
//! - **DevOps/CI/CD**: GitHub, GitLab, CircleCI, Travis, Jenkins, Docker, Kubernetes, Terraform
//! - **Databases**: PostgreSQL, MySQL, MongoDB, Redis, Supabase, PlanetScale, Neon, Upstash
//! - **Communication**: Slack, Discord, Telegram, Teams, Zoom, email services
//! - **Payment**: Stripe, PayPal, Square, Braintree, Coinbase, Plaid
//! - **Analytics**: Datadog, Sentry, New Relic, PagerDuty, Mixpanel, Amplitude
//! - **Social Media**: Facebook, Twitter, LinkedIn, Instagram, TikTok, YouTube
//! - **AI/ML**: OpenAI, Anthropic, Cohere, Hugging Face, Replicate, Stability AI, Mistral
//! - **SaaS/CMS**: Atlassian, Notion, Shopify, Salesforce, Contentful, Sanity, Strapi
//! - **Private Keys**: RSA, EC, SSH, PGP, PKCS8, DSA, Age
//! - **Generic**: API keys, passwords, JWTs, webhooks, package manager tokens

pub mod ai_ml;
pub mod analytics;
pub mod cloud;
pub mod communication;
pub mod database;
pub mod devops;
pub mod generic;
pub mod keys;
pub mod payment;
pub mod saas;
pub mod social;
pub mod types;

// Re-export common pattern types
pub use types::{PatternCategory, PatternMatcher, SecretPattern};

use super::Severity;

/// Get all built-in secret patterns
///
/// Returns 180+ patterns organized by provider/service type.
/// Patterns are aggregated from all category-specific modules.
pub fn get_all_patterns() -> Vec<SecretPattern> {
  let mut patterns = Vec::with_capacity(200);

  // Aggregate patterns from all modules
  patterns.extend(cloud::patterns());
  patterns.extend(devops::patterns());
  patterns.extend(database::patterns());
  patterns.extend(communication::patterns());
  patterns.extend(payment::patterns());
  patterns.extend(analytics::patterns());
  patterns.extend(social::patterns());
  patterns.extend(ai_ml::patterns());
  patterns.extend(saas::patterns());
  patterns.extend(keys::patterns());
  patterns.extend(generic::patterns());

  patterns
}

/// Get patterns by category
pub fn get_patterns_by_category(category: PatternCategory) -> Vec<SecretPattern> {
  get_all_patterns()
    .into_iter()
    .filter(|p| p.category == category)
    .collect()
}

/// Get high severity patterns only (High or Critical)
pub fn get_critical_patterns() -> Vec<SecretPattern> {
  get_all_patterns()
    .into_iter()
    .filter(|p| p.severity >= Severity::High)
    .collect()
}

/// Get patterns for a specific provider/service
pub fn get_patterns_for_provider(provider: &str) -> Vec<SecretPattern> {
  let provider_lower = provider.to_lowercase();
  get_all_patterns()
    .into_iter()
    .filter(|p| {
      p.name.to_lowercase().contains(&provider_lower)
        || p
          .keywords
          .iter()
          .any(|k| k.to_lowercase().contains(&provider_lower))
    })
    .collect()
}

/// Get pattern count statistics
pub fn get_pattern_stats() -> PatternStats {
  let all = get_all_patterns();

  let mut by_category = std::collections::HashMap::new();
  let mut by_severity = std::collections::HashMap::new();

  for pattern in &all {
    *by_category.entry(pattern.category).or_insert(0) += 1;
    *by_severity.entry(pattern.severity).or_insert(0) += 1;
  }

  PatternStats {
    total: all.len(),
    by_category,
    by_severity,
  }
}

/// Pattern statistics
#[derive(Debug)]
pub struct PatternStats {
  pub total: usize,
  pub by_category: std::collections::HashMap<PatternCategory, usize>,
  pub by_severity: std::collections::HashMap<Severity, usize>,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_all_patterns_load() {
    let patterns = get_all_patterns();
    assert!(!patterns.is_empty(), "Should have patterns");
    assert!(
      patterns.len() >= 150,
      "Should have at least 150 patterns, got {}",
      patterns.len()
    );
  }

  #[test]
  fn test_pattern_categories_covered() {
    let stats = get_pattern_stats();

    // Ensure all major categories have patterns
    assert!(
      stats
        .by_category
        .get(&PatternCategory::CloudCredential)
        .unwrap_or(&0)
        > &0
    );
    assert!(stats.by_category.get(&PatternCategory::Token).unwrap_or(&0) > &0);
    assert!(
      stats
        .by_category
        .get(&PatternCategory::ApiKey)
        .unwrap_or(&0)
        > &0
    );
    assert!(
      stats
        .by_category
        .get(&PatternCategory::PrivateKey)
        .unwrap_or(&0)
        > &0
    );
  }

  #[test]
  fn test_critical_patterns() {
    let critical = get_critical_patterns();
    assert!(!critical.is_empty(), "Should have critical patterns");

    // All returned patterns should be High or Critical
    for pattern in &critical {
      assert!(
        pattern.severity >= Severity::High,
        "Pattern {} should be High or Critical severity",
        pattern.name
      );
    }
  }

  #[test]
  fn test_patterns_by_category() {
    let cloud_patterns = get_patterns_by_category(PatternCategory::CloudCredential);
    assert!(!cloud_patterns.is_empty(), "Should have cloud patterns");

    for pattern in &cloud_patterns {
      assert_eq!(pattern.category, PatternCategory::CloudCredential);
    }
  }

  #[test]
  fn test_provider_search() {
    let aws_patterns = get_patterns_for_provider("aws");
    assert!(!aws_patterns.is_empty(), "Should find AWS patterns");

    let stripe_patterns = get_patterns_for_provider("stripe");
    assert!(!stripe_patterns.is_empty(), "Should find Stripe patterns");
  }

  #[test]
  fn test_pattern_matcher_prefix() {
    let matcher = PatternMatcher::Prefix("sk_live_");
    assert!(matcher.matches("sk_live_abc123"));
    assert!(!matcher.matches("pk_live_abc123"));
  }

  #[test]
  fn test_pattern_matcher_contains() {
    let matcher = PatternMatcher::Contains("@sentry.io/");
    assert!(matcher.matches("https://abc@sentry.io/12345"));
    assert!(!matcher.matches("https://example.com"));
  }

  #[test]
  fn test_pattern_matcher_jwt() {
    let matcher = PatternMatcher::Jwt;
    assert!(
      matcher.matches("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature")
    );
    assert!(!matcher.matches("not-a-jwt"));
  }

  #[test]
  fn test_pattern_matcher_hex() {
    let matcher = PatternMatcher::HexLength(32);
    assert!(matcher.matches("0123456789abcdef0123456789abcdef"));
    assert!(!matcher.matches("0123456789abcdef")); // Too short
  }

  #[test]
  fn test_pattern_matcher_charset_range() {
    let matcher = PatternMatcher::CharsetRange {
      charset: "0123456789",
      min_len: 5,
      max_len: 10,
    };
    assert!(matcher.matches("12345"));
    assert!(matcher.matches("1234567890"));
    assert!(!matcher.matches("1234")); // Too short
    assert!(!matcher.matches("12345678901")); // Too long
    assert!(!matcher.matches("12345abc")); // Invalid chars
  }

  #[test]
  fn test_cloud_submodule() {
    let patterns = cloud::patterns();
    assert!(!patterns.is_empty());
    // Should have AWS patterns
    assert!(patterns.iter().any(|p| p.name.contains("AWS")));
  }

  #[test]
  fn test_devops_submodule() {
    let patterns = devops::patterns();
    assert!(!patterns.is_empty());
    // Should have GitHub patterns
    assert!(patterns.iter().any(|p| p.name.contains("GitHub")));
  }

  #[test]
  fn test_payment_submodule() {
    let patterns = payment::patterns();
    assert!(!patterns.is_empty());
    // Should have Stripe patterns
    assert!(patterns.iter().any(|p| p.name.contains("Stripe")));
  }

  #[test]
  fn test_ai_ml_submodule() {
    let patterns = ai_ml::patterns();
    assert!(!patterns.is_empty());
    // Should have OpenAI and Anthropic patterns
    assert!(patterns.iter().any(|p| p.name.contains("OpenAI")));
    assert!(patterns.iter().any(|p| p.name.contains("Anthropic")));
  }

  #[test]
  fn test_keys_submodule() {
    let patterns = keys::patterns();
    assert!(!patterns.is_empty());
    // Should have RSA and SSH patterns
    assert!(patterns.iter().any(|p| p.name.contains("RSA")));
    assert!(patterns
      .iter()
      .any(|p| p.name.contains("SSH") || p.name.contains("OpenSSH")));
  }
}
