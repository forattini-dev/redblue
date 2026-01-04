//! Database Secret Patterns
//!
//! Patterns for PostgreSQL, MySQL, MongoDB, Redis, and modern database platforms.

use super::super::SecretSeverity;
use super::types::{PatternCategory, PatternMatcher, SecretPattern};

/// Get all database patterns
pub fn patterns() -> Vec<SecretPattern> {
    vec![
        // ===============================
        // Connection Strings
        // ===============================
        SecretPattern {
            name: "PostgreSQL Connection String",
            category: PatternCategory::DatabaseCredential,
            pattern: PatternMatcher::ConnectionString("postgres://"),
            severity: SecretSeverity::Critical,
            keywords: vec!["postgres", "psql", "database", "connection"],
            requires_entropy: false,
            min_length: 20,
            max_length: 500,
            description: "PostgreSQL Connection String",
        },
        SecretPattern {
            name: "MySQL Connection String",
            category: PatternCategory::DatabaseCredential,
            pattern: PatternMatcher::ConnectionString("mysql://"),
            severity: SecretSeverity::Critical,
            keywords: vec!["mysql", "database", "connection"],
            requires_entropy: false,
            min_length: 20,
            max_length: 500,
            description: "MySQL Connection String",
        },
        SecretPattern {
            name: "MongoDB Connection String",
            category: PatternCategory::DatabaseCredential,
            pattern: PatternMatcher::ConnectionString("mongodb"),
            severity: SecretSeverity::Critical,
            keywords: vec!["mongo", "mongodb", "database", "connection"],
            requires_entropy: false,
            min_length: 20,
            max_length: 500,
            description: "MongoDB Connection String",
        },
        SecretPattern {
            name: "Redis Connection String",
            category: PatternCategory::DatabaseCredential,
            pattern: PatternMatcher::ConnectionString("redis://"),
            severity: SecretSeverity::High,
            keywords: vec!["redis", "cache", "connection"],
            requires_entropy: false,
            min_length: 20,
            max_length: 500,
            description: "Redis Connection String",
        },
        // ===============================
        // Supabase
        // ===============================
        SecretPattern {
            name: "Supabase Service Role Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
            severity: SecretSeverity::Critical,
            keywords: vec!["supabase", "service", "role", "key"],
            requires_entropy: false,
            min_length: 150,
            max_length: 300,
            description: "Supabase Service Role Key (JWT)",
        },
        SecretPattern {
            name: "Supabase Anon Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Jwt,
            severity: SecretSeverity::Low,
            keywords: vec!["supabase", "anon", "key"],
            requires_entropy: false,
            min_length: 150,
            max_length: 300,
            description: "Supabase Anonymous Key (public)",
        },
        // ===============================
        // PlanetScale
        // ===============================
        SecretPattern {
            name: "PlanetScale Database Password",
            category: PatternCategory::DatabaseCredential,
            pattern: PatternMatcher::Prefix("pscale_pw_"),
            severity: SecretSeverity::Critical,
            keywords: vec!["planetscale", "database", "password"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "PlanetScale Database Password",
        },
        SecretPattern {
            name: "PlanetScale OAuth Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("pscale_oauth_"),
            severity: SecretSeverity::High,
            keywords: vec!["planetscale", "oauth", "token"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "PlanetScale OAuth Token",
        },
        // ===============================
        // Neon
        // ===============================
        SecretPattern {
            name: "Neon API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
                min_len: 60,
                max_len: 80,
            },
            severity: SecretSeverity::High,
            keywords: vec!["neon", "postgres", "api", "key"],
            requires_entropy: true,
            min_length: 60,
            max_length: 80,
            description: "Neon Database API Key",
        },
        // ===============================
        // Upstash
        // ===============================
        SecretPattern {
            name: "Upstash Redis REST Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("AX"),
            severity: SecretSeverity::High,
            keywords: vec!["upstash", "redis", "token"],
            requires_entropy: false,
            min_length: 100,
            max_length: 200,
            description: "Upstash Redis REST API Token",
        },
        // ===============================
        // Elasticsearch
        // ===============================
        SecretPattern {
            name: "Elastic Cloud API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Base64Length(40),
            severity: SecretSeverity::Critical,
            keywords: vec!["elastic", "elasticsearch", "api", "key"],
            requires_entropy: true,
            min_length: 40,
            max_length: 100,
            description: "Elastic Cloud API Key",
        },
        // ===============================
        // Algolia
        // ===============================
        SecretPattern {
            name: "Algolia Admin API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(32),
            severity: SecretSeverity::Critical,
            keywords: vec!["algolia", "admin", "api", "key"],
            requires_entropy: true,
            min_length: 32,
            max_length: 32,
            description: "Algolia Admin API Key",
        },
        SecretPattern {
            name: "Algolia Search API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(32),
            severity: SecretSeverity::Low,
            keywords: vec!["algolia", "search", "api", "key"],
            requires_entropy: true,
            min_length: 32,
            max_length: 32,
            description: "Algolia Search-Only API Key",
        },
        // ===============================
        // Appwrite
        // ===============================
        SecretPattern {
            name: "Appwrite API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(64),
            severity: SecretSeverity::High,
            keywords: vec!["appwrite", "api", "key"],
            requires_entropy: true,
            min_length: 64,
            max_length: 64,
            description: "Appwrite API Key",
        },
        // ===============================
        // Convex
        // ===============================
        SecretPattern {
            name: "Convex Deploy Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("prod:"),
            severity: SecretSeverity::Critical,
            keywords: vec!["convex", "deploy", "key"],
            requires_entropy: false,
            min_length: 40,
            max_length: 80,
            description: "Convex Production Deploy Key",
        },
        // ===============================
        // Firebase
        // ===============================
        SecretPattern {
            name: "Firebase Database URL",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Contains(".firebaseio.com"),
            severity: SecretSeverity::Medium,
            keywords: vec!["firebase", "database", "url"],
            requires_entropy: false,
            min_length: 30,
            max_length: 100,
            description: "Firebase Realtime Database URL",
        },
    ]
}
