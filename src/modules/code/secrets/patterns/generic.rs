//! Generic Secret Patterns
//!
//! Patterns for generic API keys, passwords, JWTs, webhooks, and package managers.

use super::super::SecretSeverity;
use super::types::{PatternCategory, PatternMatcher, SecretPattern};

/// Get all generic patterns
pub fn patterns() -> Vec<SecretPattern> {
    vec![
        // ===============================
        // Generic Patterns
        // ===============================
        SecretPattern {
            name: "Generic API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
                min_len: 32,
                max_len: 64,
            },
            severity: SecretSeverity::Medium,
            keywords: vec!["api_key", "apikey", "api-key", "secret_key", "access_key"],
            requires_entropy: true,
            min_length: 32,
            max_length: 64,
            description: "Generic API Key pattern",
        },
        SecretPattern {
            name: "Generic Secret",
            category: PatternCategory::GenericSecret,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 16,
                max_len: 64,
            },
            severity: SecretSeverity::Low,
            keywords: vec!["secret", "password", "passwd", "pwd", "credential"],
            requires_entropy: true,
            min_length: 16,
            max_length: 64,
            description: "Generic secret pattern with high entropy",
        },
        SecretPattern {
            name: "Password Assignment",
            category: PatternCategory::Password,
            pattern: PatternMatcher::Any(vec![
                PatternMatcher::Contains("password="),
                PatternMatcher::Contains("password:"),
                PatternMatcher::Contains("PASSWORD="),
                PatternMatcher::Contains("passwd="),
            ]),
            severity: SecretSeverity::High,
            keywords: vec!["password", "passwd", "pwd"],
            requires_entropy: false,
            min_length: 10,
            max_length: 200,
            description: "Password assignment in configuration",
        },
        // ===============================
        // JWT
        // ===============================
        SecretPattern {
            name: "JSON Web Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Jwt,
            severity: SecretSeverity::Medium,
            keywords: vec!["jwt", "token", "bearer", "authorization"],
            requires_entropy: false,
            min_length: 50,
            max_length: 2000,
            description: "JSON Web Token (JWT)",
        },
        // ===============================
        // Webhooks
        // ===============================
        SecretPattern {
            name: "Zapier Webhook URL",
            category: PatternCategory::Webhook,
            pattern: PatternMatcher::Contains("hooks.zapier.com/hooks/catch/"),
            severity: SecretSeverity::Medium,
            keywords: vec!["zapier", "webhook", "hooks"],
            requires_entropy: false,
            min_length: 50,
            max_length: 150,
            description: "Zapier Webhook URL",
        },
        SecretPattern {
            name: "IFTTT Webhook Key",
            category: PatternCategory::Webhook,
            pattern: PatternMatcher::Contains("maker.ifttt.com/trigger/"),
            severity: SecretSeverity::Medium,
            keywords: vec!["ifttt", "webhook", "maker"],
            requires_entropy: false,
            min_length: 50,
            max_length: 150,
            description: "IFTTT Maker Webhook URL",
        },
        // ===============================
        // Package Managers
        // ===============================
        SecretPattern {
            name: "NPM Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("npm_"),
            severity: SecretSeverity::High,
            keywords: vec!["npm", "token", "registry"],
            requires_entropy: false,
            min_length: 36,
            max_length: 50,
            description: "NPM Access Token",
        },
        SecretPattern {
            name: "PyPI API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("pypi-"),
            severity: SecretSeverity::High,
            keywords: vec!["pypi", "python", "token"],
            requires_entropy: false,
            min_length: 50,
            max_length: 200,
            description: "PyPI API Token",
        },
        SecretPattern {
            name: "RubyGems API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("rubygems_"),
            severity: SecretSeverity::High,
            keywords: vec!["rubygems", "ruby", "api", "key"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "RubyGems API Key",
        },
        SecretPattern {
            name: "NuGet API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("oy2"),
            severity: SecretSeverity::High,
            keywords: vec!["nuget", "dotnet", "api", "key"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "NuGet API Key",
        },
        SecretPattern {
            name: "Cargo Registry Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("cio"),
            severity: SecretSeverity::High,
            keywords: vec!["cargo", "crates", "rust", "token"],
            requires_entropy: false,
            min_length: 32,
            max_length: 50,
            description: "Cargo (crates.io) Registry Token",
        },
        // ===============================
        // Firebase Extended
        // ===============================
        SecretPattern {
            name: "Firebase Cloud Messaging Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("AAAA"),
            severity: SecretSeverity::High,
            keywords: vec!["firebase", "fcm", "cloud", "messaging"],
            requires_entropy: false,
            min_length: 100,
            max_length: 200,
            description: "Firebase Cloud Messaging Server Key",
        },
    ]
}
