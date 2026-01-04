//! Cloud Provider Secret Patterns
//!
//! Patterns for AWS, GCP, Azure, Alibaba, Oracle, IBM, DigitalOcean, Linode, Vultr, Hetzner, Scaleway

use super::super::SecretSeverity;
use super::types::{PatternCategory, PatternMatcher, SecretPattern};

/// Get all cloud provider patterns
pub fn patterns() -> Vec<SecretPattern> {
    vec![
        // ===============================
        // AWS
        // ===============================
        SecretPattern {
            name: "AWS Access Key ID",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::All(vec![
                PatternMatcher::Prefix("AKIA"),
                PatternMatcher::CharsetLength {
                    charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                    length: 20,
                },
            ]),
            severity: SecretSeverity::Critical,
            keywords: vec!["aws", "access", "key", "credential"],
            requires_entropy: false,
            min_length: 20,
            max_length: 20,
            description: "AWS Access Key ID starting with AKIA",
        },
        SecretPattern {
            name: "AWS Secret Access Key",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::CharsetLength {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                length: 40,
            },
            severity: SecretSeverity::Critical,
            keywords: vec!["aws", "secret", "key", "credential"],
            requires_entropy: true,
            min_length: 40,
            max_length: 40,
            description: "AWS Secret Access Key (40 chars, high entropy)",
        },
        SecretPattern {
            name: "AWS Session Token",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::Prefix("FwoGZXIvYXdz"),
            severity: SecretSeverity::Critical,
            keywords: vec!["aws", "session", "token"],
            requires_entropy: false,
            min_length: 100,
            max_length: 1000,
            description: "AWS Session Token",
        },
        // ===============================
        // Google Cloud
        // ===============================
        SecretPattern {
            name: "GCP API Key",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::Prefix("AIza"),
            severity: SecretSeverity::High,
            keywords: vec!["google", "gcp", "api", "key"],
            requires_entropy: false,
            min_length: 39,
            max_length: 39,
            description: "Google Cloud API Key starting with AIza",
        },
        SecretPattern {
            name: "GCP Service Account",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::Contains("\"type\": \"service_account\""),
            severity: SecretSeverity::Critical,
            keywords: vec!["google", "gcp", "service", "account", "private_key"],
            requires_entropy: false,
            min_length: 100,
            max_length: 10000,
            description: "Google Cloud Service Account JSON",
        },
        SecretPattern {
            name: "GCP OAuth Client Secret",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::Prefix("GOCSPX-"),
            severity: SecretSeverity::High,
            keywords: vec!["google", "oauth", "client", "secret"],
            requires_entropy: false,
            min_length: 28,
            max_length: 40,
            description: "Google OAuth Client Secret",
        },
        // ===============================
        // Azure
        // ===============================
        SecretPattern {
            name: "Azure Storage Account Key",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::Base64Length(88),
            severity: SecretSeverity::Critical,
            keywords: vec![
                "azure",
                "storage",
                "account",
                "key",
                "DefaultEndpointsProtocol",
            ],
            requires_entropy: true,
            min_length: 88,
            max_length: 88,
            description: "Azure Storage Account Key (base64)",
        },
        SecretPattern {
            name: "Azure Connection String",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::ConnectionString("DefaultEndpointsProtocol="),
            severity: SecretSeverity::Critical,
            keywords: vec!["azure", "connection", "endpoint", "AccountKey"],
            requires_entropy: false,
            min_length: 50,
            max_length: 500,
            description: "Azure Connection String",
        },
        SecretPattern {
            name: "Azure AD Client Secret",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~._-",
                min_len: 34,
                max_len: 40,
            },
            severity: SecretSeverity::Critical,
            keywords: vec!["azure", "client", "secret", "tenant", "app"],
            requires_entropy: true,
            min_length: 34,
            max_length: 40,
            description: "Azure AD Client Secret",
        },
        // ===============================
        // Alibaba Cloud
        // ===============================
        SecretPattern {
            name: "Alibaba Cloud Access Key ID",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::Prefix("LTAI"),
            severity: SecretSeverity::Critical,
            keywords: vec!["alibaba", "aliyun", "access", "key"],
            requires_entropy: false,
            min_length: 20,
            max_length: 30,
            description: "Alibaba Cloud Access Key ID",
        },
        SecretPattern {
            name: "Alibaba Cloud Access Key Secret",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 30,
                max_len: 30,
            },
            severity: SecretSeverity::Critical,
            keywords: vec!["alibaba", "aliyun", "secret", "key"],
            requires_entropy: true,
            min_length: 30,
            max_length: 30,
            description: "Alibaba Cloud Access Key Secret",
        },
        // ===============================
        // Oracle Cloud
        // ===============================
        SecretPattern {
            name: "Oracle Cloud OCID",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::Prefix("ocid1."),
            severity: SecretSeverity::Medium,
            keywords: vec!["oracle", "oci", "ocid"],
            requires_entropy: false,
            min_length: 50,
            max_length: 150,
            description: "Oracle Cloud Infrastructure OCID",
        },
        // ===============================
        // IBM Cloud
        // ===============================
        SecretPattern {
            name: "IBM Cloud API Key",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
                min_len: 44,
                max_len: 44,
            },
            severity: SecretSeverity::Critical,
            keywords: vec!["ibm", "cloud", "api", "key"],
            requires_entropy: true,
            min_length: 44,
            max_length: 44,
            description: "IBM Cloud API Key",
        },
        SecretPattern {
            name: "IBM COS HMAC Key",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::HexLength(64),
            severity: SecretSeverity::Critical,
            keywords: vec!["ibm", "cos", "hmac", "secret"],
            requires_entropy: true,
            min_length: 64,
            max_length: 64,
            description: "IBM Cloud Object Storage HMAC Secret",
        },
        // ===============================
        // DigitalOcean
        // ===============================
        SecretPattern {
            name: "DigitalOcean Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("dop_v1_"),
            severity: SecretSeverity::Critical,
            keywords: vec!["digitalocean", "do", "token"],
            requires_entropy: false,
            min_length: 64,
            max_length: 80,
            description: "DigitalOcean Personal Access Token",
        },
        SecretPattern {
            name: "DigitalOcean Spaces Key",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                min_len: 20,
                max_len: 20,
            },
            severity: SecretSeverity::High,
            keywords: vec!["digitalocean", "spaces", "access", "key"],
            requires_entropy: true,
            min_length: 20,
            max_length: 20,
            description: "DigitalOcean Spaces Access Key",
        },
        SecretPattern {
            name: "DigitalOcean OAuth Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::HexLength(64),
            severity: SecretSeverity::Critical,
            keywords: vec!["digitalocean", "oauth", "token"],
            requires_entropy: true,
            min_length: 64,
            max_length: 64,
            description: "DigitalOcean OAuth Application Token",
        },
        // ===============================
        // Linode
        // ===============================
        SecretPattern {
            name: "Linode API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::HexLength(64),
            severity: SecretSeverity::Critical,
            keywords: vec!["linode", "api", "token"],
            requires_entropy: true,
            min_length: 64,
            max_length: 64,
            description: "Linode Personal Access Token",
        },
        // ===============================
        // Vultr
        // ===============================
        SecretPattern {
            name: "Vultr API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                min_len: 36,
                max_len: 36,
            },
            severity: SecretSeverity::Critical,
            keywords: vec!["vultr", "api", "key"],
            requires_entropy: true,
            min_length: 36,
            max_length: 36,
            description: "Vultr API Key",
        },
        // ===============================
        // Hetzner
        // ===============================
        SecretPattern {
            name: "Hetzner API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 64,
                max_len: 64,
            },
            severity: SecretSeverity::Critical,
            keywords: vec!["hetzner", "api", "token"],
            requires_entropy: true,
            min_length: 64,
            max_length: 64,
            description: "Hetzner Cloud API Token",
        },
        // ===============================
        // Scaleway
        // ===============================
        SecretPattern {
            name: "Scaleway API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::HexLength(36),
            severity: SecretSeverity::Critical,
            keywords: vec!["scaleway", "api", "token"],
            requires_entropy: true,
            min_length: 36,
            max_length: 36,
            description: "Scaleway API Token",
        },
        // ===============================
        // Heroku
        // ===============================
        SecretPattern {
            name: "Heroku API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(36),
            severity: SecretSeverity::High,
            keywords: vec!["heroku", "api", "key"],
            requires_entropy: true,
            min_length: 36,
            max_length: 36,
            description: "Heroku API Key",
        },
    ]
}
