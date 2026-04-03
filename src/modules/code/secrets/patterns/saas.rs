//! SaaS & CMS Secret Patterns
//!
//! Patterns for Atlassian, Notion, Asana, Airtable, Linear, Monday,
//! Shopify, HubSpot, Salesforce, Marketo, CMS platforms (Contentful, Sanity, etc.),
//! Auth providers (Clerk, WorkOS, Stytch), and security tools.

use super::super::Severity;
use super::types::{PatternCategory, PatternMatcher, SecretPattern};

/// Get all SaaS and CMS patterns
pub fn patterns() -> Vec<SecretPattern> {
    vec![
        // ===============================
        // Atlassian (Jira, Confluence)
        // ===============================
        SecretPattern {
            name: "Atlassian API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 24,
                max_len: 28,
            },
            severity: Severity::High,
            keywords: vec!["atlassian", "jira", "confluence", "token", "api"],
            requires_entropy: true,
            min_length: 24,
            max_length: 28,
            description: "Atlassian API Token",
        },
        // ===============================
        // Notion
        // ===============================
        SecretPattern {
            name: "Notion Integration Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("secret_"),
            severity: Severity::High,
            keywords: vec!["notion", "integration", "token", "secret"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "Notion Internal Integration Token",
        },
        // ===============================
        // Asana
        // ===============================
        SecretPattern {
            name: "Asana Personal Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "0123456789/:",
                min_len: 50,
                max_len: 70,
            },
            severity: Severity::High,
            keywords: vec!["asana", "personal", "access", "token"],
            requires_entropy: false,
            min_length: 50,
            max_length: 70,
            description: "Asana Personal Access Token",
        },
        // ===============================
        // Airtable
        // ===============================
        SecretPattern {
            name: "Airtable API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("key"),
            severity: Severity::High,
            keywords: vec!["airtable", "api", "key"],
            requires_entropy: false,
            min_length: 14,
            max_length: 20,
            description: "Airtable API Key",
        },
        // ===============================
        // Linear
        // ===============================
        SecretPattern {
            name: "Linear API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("lin_api_"),
            severity: Severity::High,
            keywords: vec!["linear", "api", "key"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "Linear API Key",
        },
        // ===============================
        // Monday.com
        // ===============================
        SecretPattern {
            name: "Monday.com API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Jwt,
            severity: Severity::High,
            keywords: vec!["monday", "api", "token"],
            requires_entropy: false,
            min_length: 200,
            max_length: 500,
            description: "Monday.com API Token",
        },
        // ===============================
        // Shopify
        // ===============================
        SecretPattern {
            name: "Shopify Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("shpat_"),
            severity: Severity::High,
            keywords: vec!["shopify", "access", "token"],
            requires_entropy: false,
            min_length: 32,
            max_length: 50,
            description: "Shopify Admin API Access Token",
        },
        SecretPattern {
            name: "Shopify API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("shpss_"),
            severity: Severity::High,
            keywords: vec!["shopify", "api", "secret"],
            requires_entropy: false,
            min_length: 32,
            max_length: 50,
            description: "Shopify API Secret Key",
        },
        // ===============================
        // HubSpot
        // ===============================
        SecretPattern {
            name: "HubSpot API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(36),
            severity: Severity::High,
            keywords: vec!["hubspot", "api", "key"],
            requires_entropy: true,
            min_length: 36,
            max_length: 36,
            description: "HubSpot API Key",
        },
        SecretPattern {
            name: "HubSpot Private App Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("pat-na1-"),
            severity: Severity::High,
            keywords: vec!["hubspot", "private", "app", "token"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "HubSpot Private App Access Token",
        },
        // ===============================
        // Salesforce
        // ===============================
        SecretPattern {
            name: "Salesforce Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!.",
                min_len: 100,
                max_len: 300,
            },
            severity: Severity::Critical,
            keywords: vec!["salesforce", "sfdc", "access", "token"],
            requires_entropy: true,
            min_length: 100,
            max_length: 300,
            description: "Salesforce Access Token",
        },
        // ===============================
        // Marketo
        // ===============================
        SecretPattern {
            name: "Marketo Client Secret",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 36,
                max_len: 36,
            },
            severity: Severity::High,
            keywords: vec!["marketo", "client", "secret"],
            requires_entropy: true,
            min_length: 36,
            max_length: 36,
            description: "Marketo Client Secret",
        },
        // ===============================
        // Contentful
        // ===============================
        SecretPattern {
            name: "Contentful Delivery API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
                min_len: 43,
                max_len: 50,
            },
            severity: Severity::Medium,
            keywords: vec!["contentful", "delivery", "api", "token"],
            requires_entropy: true,
            min_length: 43,
            max_length: 50,
            description: "Contentful Content Delivery API Token",
        },
        SecretPattern {
            name: "Contentful Management API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("CFPAT-"),
            severity: Severity::Critical,
            keywords: vec!["contentful", "management", "api", "token"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "Contentful Content Management API Token",
        },
        // ===============================
        // Sanity
        // ===============================
        SecretPattern {
            name: "Sanity API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("sk"),
            severity: Severity::High,
            keywords: vec!["sanity", "api", "token"],
            requires_entropy: false,
            min_length: 100,
            max_length: 200,
            description: "Sanity API Token",
        },
        // ===============================
        // Strapi
        // ===============================
        SecretPattern {
            name: "Strapi API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 128,
                max_len: 256,
            },
            severity: Severity::High,
            keywords: vec!["strapi", "api", "token"],
            requires_entropy: true,
            min_length: 128,
            max_length: 256,
            description: "Strapi API Token",
        },
        // ===============================
        // Prismic
        // ===============================
        SecretPattern {
            name: "Prismic Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
                min_len: 80,
                max_len: 100,
            },
            severity: Severity::High,
            keywords: vec!["prismic", "access", "token"],
            requires_entropy: true,
            min_length: 80,
            max_length: 100,
            description: "Prismic Repository Access Token",
        },
        // ===============================
        // Contentstack
        // ===============================
        SecretPattern {
            name: "Contentstack Delivery Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("cs"),
            severity: Severity::Medium,
            keywords: vec!["contentstack", "delivery", "token"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "Contentstack Delivery Token",
        },
        // ===============================
        // Clerk
        // ===============================
        SecretPattern {
            name: "Clerk Secret Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("sk_live_"),
            severity: Severity::Critical,
            keywords: vec!["clerk", "secret", "key"],
            requires_entropy: false,
            min_length: 40,
            max_length: 80,
            description: "Clerk Secret Key",
        },
        SecretPattern {
            name: "Clerk Publishable Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("pk_live_"),
            severity: Severity::Low,
            keywords: vec!["clerk", "publishable", "key"],
            requires_entropy: false,
            min_length: 40,
            max_length: 80,
            description: "Clerk Publishable Key",
        },
        // ===============================
        // WorkOS
        // ===============================
        SecretPattern {
            name: "WorkOS API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("sk_live_"),
            severity: Severity::Critical,
            keywords: vec!["workos", "api", "key"],
            requires_entropy: false,
            min_length: 30,
            max_length: 60,
            description: "WorkOS API Key",
        },
        // ===============================
        // Stytch
        // ===============================
        SecretPattern {
            name: "Stytch Secret",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("secret-live-"),
            severity: Severity::Critical,
            keywords: vec!["stytch", "secret"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "Stytch Live Secret",
        },
        // ===============================
        // GitGuardian
        // ===============================
        SecretPattern {
            name: "GitGuardian API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 64,
                max_len: 64,
            },
            severity: Severity::High,
            keywords: vec!["gitguardian", "gg", "api", "key"],
            requires_entropy: true,
            min_length: 64,
            max_length: 64,
            description: "GitGuardian API Key",
        },
        // ===============================
        // Mapbox
        // ===============================
        SecretPattern {
            name: "Mapbox Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("pk."),
            severity: Severity::Medium,
            keywords: vec!["mapbox", "access", "token"],
            requires_entropy: false,
            min_length: 80,
            max_length: 120,
            description: "Mapbox Public Access Token",
        },
        SecretPattern {
            name: "Mapbox Secret Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("sk."),
            severity: Severity::High,
            keywords: vec!["mapbox", "secret", "token"],
            requires_entropy: false,
            min_length: 80,
            max_length: 120,
            description: "Mapbox Secret Access Token",
        },
        // ===============================
        // CDN & Storage
        // ===============================
        SecretPattern {
            name: "Cloudflare API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(37),
            severity: Severity::Critical,
            keywords: vec!["cloudflare", "cf", "api", "key"],
            requires_entropy: true,
            min_length: 37,
            max_length: 37,
            description: "Cloudflare Global API Key",
        },
        SecretPattern {
            name: "Cloudflare API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
                min_len: 40,
                max_len: 50,
            },
            severity: Severity::Critical,
            keywords: vec!["cloudflare", "cf", "api", "token"],
            requires_entropy: true,
            min_length: 40,
            max_length: 50,
            description: "Cloudflare Scoped API Token",
        },
        SecretPattern {
            name: "Fastly API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
                min_len: 32,
                max_len: 40,
            },
            severity: Severity::High,
            keywords: vec!["fastly", "api", "token"],
            requires_entropy: true,
            min_length: 32,
            max_length: 40,
            description: "Fastly API Token",
        },
        SecretPattern {
            name: "Bunny CDN API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(36),
            severity: Severity::High,
            keywords: vec!["bunny", "bunnycdn", "api", "key"],
            requires_entropy: true,
            min_length: 36,
            max_length: 36,
            description: "Bunny CDN API Key",
        },
        SecretPattern {
            name: "Backblaze Application Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 31,
                max_len: 31,
            },
            severity: Severity::High,
            keywords: vec!["backblaze", "b2", "application", "key"],
            requires_entropy: true,
            min_length: 31,
            max_length: 31,
            description: "Backblaze B2 Application Key",
        },
        // ===============================
        // Security & Identity
        // ===============================
        SecretPattern {
            name: "Auth0 Client Secret",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
                min_len: 32,
                max_len: 64,
            },
            severity: Severity::Critical,
            keywords: vec!["auth0", "client", "secret"],
            requires_entropy: true,
            min_length: 32,
            max_length: 64,
            description: "Auth0 Client Secret",
        },
        SecretPattern {
            name: "Okta API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
                min_len: 42,
                max_len: 50,
            },
            severity: Severity::Critical,
            keywords: vec!["okta", "api", "token"],
            requires_entropy: true,
            min_length: 42,
            max_length: 50,
            description: "Okta API Token",
        },
        SecretPattern {
            name: "OneLogin API Credential",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(64),
            severity: Severity::Critical,
            keywords: vec!["onelogin", "api", "credential"],
            requires_entropy: true,
            min_length: 64,
            max_length: 64,
            description: "OneLogin API Client Secret",
        },
        SecretPattern {
            name: "Snyk API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::HexLength(36),
            severity: Severity::High,
            keywords: vec!["snyk", "api", "token"],
            requires_entropy: true,
            min_length: 36,
            max_length: 36,
            description: "Snyk API Token",
        },
        SecretPattern {
            name: "SonarQube Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("squ_"),
            severity: Severity::High,
            keywords: vec!["sonarqube", "sonar", "token"],
            requires_entropy: false,
            min_length: 40,
            max_length: 50,
            description: "SonarQube User Token",
        },
    ]
}
