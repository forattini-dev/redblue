//! Payment Provider Secret Patterns
//!
//! Patterns for Stripe, PayPal, Square, Braintree, Coinbase, Plaid, etc.

use super::super::SecretSeverity;
use super::types::{PatternCategory, PatternMatcher, SecretPattern};

/// Get all payment provider patterns
pub fn patterns() -> Vec<SecretPattern> {
    vec![
        // ===============================
        // Stripe
        // ===============================
        SecretPattern {
            name: "Stripe Secret Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("sk_live_"),
            severity: SecretSeverity::Critical,
            keywords: vec!["stripe", "secret", "key", "payment"],
            requires_entropy: false,
            min_length: 30,
            max_length: 100,
            description: "Stripe Live Secret Key",
        },
        SecretPattern {
            name: "Stripe Test Secret Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("sk_test_"),
            severity: SecretSeverity::Low,
            keywords: vec!["stripe", "secret", "key", "test"],
            requires_entropy: false,
            min_length: 30,
            max_length: 100,
            description: "Stripe Test Secret Key",
        },
        SecretPattern {
            name: "Stripe Publishable Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("pk_live_"),
            severity: SecretSeverity::Medium,
            keywords: vec!["stripe", "publishable", "key"],
            requires_entropy: false,
            min_length: 30,
            max_length: 100,
            description: "Stripe Live Publishable Key",
        },
        SecretPattern {
            name: "Stripe Restricted Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("rk_live_"),
            severity: SecretSeverity::High,
            keywords: vec!["stripe", "restricted", "key"],
            requires_entropy: false,
            min_length: 30,
            max_length: 100,
            description: "Stripe Restricted API Key",
        },
        // ===============================
        // PayPal
        // ===============================
        SecretPattern {
            name: "PayPal Client Secret",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
                min_len: 50,
                max_len: 80,
            },
            severity: SecretSeverity::Critical,
            keywords: vec!["paypal", "client", "secret"],
            requires_entropy: true,
            min_length: 50,
            max_length: 80,
            description: "PayPal Client Secret",
        },
        // ===============================
        // Square
        // ===============================
        SecretPattern {
            name: "Square Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("sq0atp-"),
            severity: SecretSeverity::Critical,
            keywords: vec!["square", "access", "token"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "Square Access Token",
        },
        SecretPattern {
            name: "Square Application Secret",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("sq0csp-"),
            severity: SecretSeverity::Critical,
            keywords: vec!["square", "secret", "application"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "Square Application Secret",
        },
        // ===============================
        // Braintree
        // ===============================
        SecretPattern {
            name: "Braintree Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("access_token$"),
            severity: SecretSeverity::Critical,
            keywords: vec!["braintree", "access", "token"],
            requires_entropy: false,
            min_length: 50,
            max_length: 200,
            description: "Braintree Access Token",
        },
        // ===============================
        // Coinbase
        // ===============================
        SecretPattern {
            name: "Coinbase API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 16,
                max_len: 20,
            },
            severity: SecretSeverity::Critical,
            keywords: vec!["coinbase", "api", "key", "crypto"],
            requires_entropy: true,
            min_length: 16,
            max_length: 20,
            description: "Coinbase API Key",
        },
        // ===============================
        // Plaid
        // ===============================
        SecretPattern {
            name: "Plaid Client ID",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(24),
            severity: SecretSeverity::High,
            keywords: vec!["plaid", "client", "id"],
            requires_entropy: true,
            min_length: 24,
            max_length: 24,
            description: "Plaid Client ID",
        },
        SecretPattern {
            name: "Plaid Secret",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(30),
            severity: SecretSeverity::Critical,
            keywords: vec!["plaid", "secret"],
            requires_entropy: true,
            min_length: 30,
            max_length: 30,
            description: "Plaid Secret Key",
        },
    ]
}
