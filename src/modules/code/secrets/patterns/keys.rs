//! Private Key Secret Patterns
//!
//! Patterns for RSA, EC, SSH, PGP, PKCS8, DSA, Age encryption keys.

use super::super::SecretSeverity;
use super::types::{PatternCategory, PatternMatcher, SecretPattern};

/// Get all private key patterns
pub fn patterns() -> Vec<SecretPattern> {
    vec![
        // ===============================
        // RSA
        // ===============================
        SecretPattern {
            name: "RSA Private Key",
            category: PatternCategory::PrivateKey,
            pattern: PatternMatcher::PemBlock("RSA PRIVATE KEY"),
            severity: SecretSeverity::Critical,
            keywords: vec!["private", "key", "rsa"],
            requires_entropy: false,
            min_length: 100,
            max_length: 10000,
            description: "RSA Private Key in PEM format",
        },
        // ===============================
        // EC (Elliptic Curve)
        // ===============================
        SecretPattern {
            name: "EC Private Key",
            category: PatternCategory::PrivateKey,
            pattern: PatternMatcher::PemBlock("EC PRIVATE KEY"),
            severity: SecretSeverity::Critical,
            keywords: vec!["private", "key", "ec", "ecdsa"],
            requires_entropy: false,
            min_length: 100,
            max_length: 5000,
            description: "EC Private Key in PEM format",
        },
        // ===============================
        // OpenSSH
        // ===============================
        SecretPattern {
            name: "OpenSSH Private Key",
            category: PatternCategory::PrivateKey,
            pattern: PatternMatcher::PemBlock("OPENSSH PRIVATE KEY"),
            severity: SecretSeverity::Critical,
            keywords: vec!["ssh", "private", "key"],
            requires_entropy: false,
            min_length: 100,
            max_length: 10000,
            description: "OpenSSH Private Key",
        },
        // ===============================
        // PGP/GPG
        // ===============================
        SecretPattern {
            name: "PGP Private Key Block",
            category: PatternCategory::PrivateKey,
            pattern: PatternMatcher::PemBlock("PGP PRIVATE KEY BLOCK"),
            severity: SecretSeverity::Critical,
            keywords: vec!["pgp", "gpg", "private", "key"],
            requires_entropy: false,
            min_length: 100,
            max_length: 20000,
            description: "PGP Private Key Block",
        },
        // ===============================
        // PKCS8
        // ===============================
        SecretPattern {
            name: "PKCS8 Private Key",
            category: PatternCategory::PrivateKey,
            pattern: PatternMatcher::PemBlock("PRIVATE KEY"),
            severity: SecretSeverity::Critical,
            keywords: vec!["private", "key", "pkcs8"],
            requires_entropy: false,
            min_length: 100,
            max_length: 10000,
            description: "PKCS8 Private Key in PEM format",
        },
        // ===============================
        // DSA
        // ===============================
        SecretPattern {
            name: "DSA Private Key",
            category: PatternCategory::PrivateKey,
            pattern: PatternMatcher::PemBlock("DSA PRIVATE KEY"),
            severity: SecretSeverity::Critical,
            keywords: vec!["dsa", "private", "key"],
            requires_entropy: false,
            min_length: 100,
            max_length: 5000,
            description: "DSA Private Key in PEM format",
        },
        // ===============================
        // Encrypted Private Key
        // ===============================
        SecretPattern {
            name: "Encrypted Private Key",
            category: PatternCategory::PrivateKey,
            pattern: PatternMatcher::PemBlock("ENCRYPTED PRIVATE KEY"),
            severity: SecretSeverity::High,
            keywords: vec!["encrypted", "private", "key"],
            requires_entropy: false,
            min_length: 100,
            max_length: 10000,
            description: "Encrypted Private Key in PEM format",
        },
        // ===============================
        // Age Encryption
        // ===============================
        SecretPattern {
            name: "Age Secret Key",
            category: PatternCategory::CryptoKey,
            pattern: PatternMatcher::Prefix("AGE-SECRET-KEY-"),
            severity: SecretSeverity::Critical,
            keywords: vec!["age", "secret", "key", "encryption"],
            requires_entropy: false,
            min_length: 60,
            max_length: 80,
            description: "Age Encryption Secret Key",
        },
    ]
}
