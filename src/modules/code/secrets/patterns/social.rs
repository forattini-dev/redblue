//! Social Media Secret Patterns
//!
//! Patterns for Facebook, Twitter, LinkedIn, Instagram, TikTok, YouTube, etc.

use super::super::Severity;
use super::types::{PatternCategory, PatternMatcher, SecretPattern};

/// Get all social media patterns
pub fn patterns() -> Vec<SecretPattern> {
    vec![
        // ===============================
        // Facebook
        // ===============================
        SecretPattern {
            name: "Facebook Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("EAA"),
            severity: Severity::High,
            keywords: vec!["facebook", "fb", "access", "token"],
            requires_entropy: false,
            min_length: 100,
            max_length: 300,
            description: "Facebook Access Token",
        },
        // ===============================
        // Twitter / X
        // ===============================
        SecretPattern {
            name: "Twitter API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 25,
                max_len: 25,
            },
            severity: Severity::High,
            keywords: vec!["twitter", "api", "key", "consumer"],
            requires_entropy: true,
            min_length: 25,
            max_length: 25,
            description: "Twitter API Key",
        },
        SecretPattern {
            name: "Twitter Bearer Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("AAAA"),
            severity: Severity::High,
            keywords: vec!["twitter", "bearer", "token"],
            requires_entropy: false,
            min_length: 100,
            max_length: 200,
            description: "Twitter Bearer Token",
        },
        // ===============================
        // LinkedIn
        // ===============================
        SecretPattern {
            name: "LinkedIn Client Secret",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 16,
                max_len: 16,
            },
            severity: Severity::High,
            keywords: vec!["linkedin", "client", "secret"],
            requires_entropy: true,
            min_length: 16,
            max_length: 16,
            description: "LinkedIn Client Secret",
        },
        // ===============================
        // Instagram
        // ===============================
        SecretPattern {
            name: "Instagram Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("IGQV"),
            severity: Severity::High,
            keywords: vec!["instagram", "access", "token"],
            requires_entropy: false,
            min_length: 100,
            max_length: 300,
            description: "Instagram Access Token",
        },
        // ===============================
        // TikTok
        // ===============================
        SecretPattern {
            name: "TikTok Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
                min_len: 100,
                max_len: 200,
            },
            severity: Severity::High,
            keywords: vec!["tiktok", "access", "token"],
            requires_entropy: true,
            min_length: 100,
            max_length: 200,
            description: "TikTok Access Token",
        },
        // ===============================
        // YouTube / Google Video
        // ===============================
        SecretPattern {
            name: "YouTube API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("AIza"),
            severity: Severity::Medium,
            keywords: vec!["youtube", "api", "key", "google"],
            requires_entropy: false,
            min_length: 39,
            max_length: 39,
            description: "YouTube API Key (Google API)",
        },
    ]
}
