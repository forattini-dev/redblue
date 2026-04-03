//! Communication & Email Secret Patterns
//!
//! Patterns for Slack, Discord, Telegram, Teams, email services, etc.

use super::super::Severity;
use super::types::{PatternCategory, PatternMatcher, SecretPattern};

/// Get all communication patterns
pub fn patterns() -> Vec<SecretPattern> {
    vec![
        // ===============================
        // Slack
        // ===============================
        SecretPattern {
            name: "Slack Bot Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("xoxb-"),
            severity: Severity::High,
            keywords: vec!["slack", "bot", "token"],
            requires_entropy: false,
            min_length: 50,
            max_length: 100,
            description: "Slack Bot Token",
        },
        SecretPattern {
            name: "Slack User Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("xoxp-"),
            severity: Severity::High,
            keywords: vec!["slack", "user", "token"],
            requires_entropy: false,
            min_length: 50,
            max_length: 100,
            description: "Slack User Token",
        },
        SecretPattern {
            name: "Slack Webhook URL",
            category: PatternCategory::Webhook,
            pattern: PatternMatcher::Contains("hooks.slack.com/services/"),
            severity: Severity::Medium,
            keywords: vec!["slack", "webhook"],
            requires_entropy: false,
            min_length: 60,
            max_length: 200,
            description: "Slack Webhook URL",
        },
        // ===============================
        // Discord
        // ===============================
        SecretPattern {
            name: "Discord Bot Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-",
                min_len: 59,
                max_len: 72,
            },
            severity: Severity::High,
            keywords: vec!["discord", "bot", "token"],
            requires_entropy: true,
            min_length: 59,
            max_length: 72,
            description: "Discord Bot Token",
        },
        SecretPattern {
            name: "Discord Webhook URL",
            category: PatternCategory::Webhook,
            pattern: PatternMatcher::Contains("discord.com/api/webhooks/"),
            severity: Severity::Medium,
            keywords: vec!["discord", "webhook"],
            requires_entropy: false,
            min_length: 100,
            max_length: 200,
            description: "Discord Webhook URL",
        },
        // ===============================
        // Telegram
        // ===============================
        SecretPattern {
            name: "Telegram Bot Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Contains(":AA"),
            severity: Severity::High,
            keywords: vec!["telegram", "bot", "token"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "Telegram Bot Token",
        },
        // ===============================
        // Microsoft Teams
        // ===============================
        SecretPattern {
            name: "Microsoft Teams Webhook",
            category: PatternCategory::Webhook,
            pattern: PatternMatcher::Contains("webhook.office.com/webhookb2/"),
            severity: Severity::Medium,
            keywords: vec!["teams", "microsoft", "webhook"],
            requires_entropy: false,
            min_length: 100,
            max_length: 400,
            description: "Microsoft Teams Incoming Webhook",
        },
        // ===============================
        // Zoom
        // ===============================
        SecretPattern {
            name: "Zoom JWT Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Jwt,
            severity: Severity::High,
            keywords: vec!["zoom", "jwt", "token", "api"],
            requires_entropy: false,
            min_length: 100,
            max_length: 500,
            description: "Zoom JWT API Token",
        },
        // ===============================
        // Customer Support
        // ===============================
        SecretPattern {
            name: "Intercom Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("dG9rOg"),
            severity: Severity::High,
            keywords: vec!["intercom", "access", "token"],
            requires_entropy: false,
            min_length: 40,
            max_length: 80,
            description: "Intercom Access Token",
        },
        SecretPattern {
            name: "Zendesk API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 40,
                max_len: 50,
            },
            severity: Severity::High,
            keywords: vec!["zendesk", "api", "token"],
            requires_entropy: true,
            min_length: 40,
            max_length: 50,
            description: "Zendesk API Token",
        },
        SecretPattern {
            name: "Freshdesk API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 16,
                max_len: 24,
            },
            severity: Severity::High,
            keywords: vec!["freshdesk", "freshworks", "api", "key"],
            requires_entropy: true,
            min_length: 16,
            max_length: 24,
            description: "Freshdesk API Key",
        },
        SecretPattern {
            name: "Webex Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
                min_len: 64,
                max_len: 100,
            },
            severity: Severity::High,
            keywords: vec!["webex", "cisco", "access", "token"],
            requires_entropy: true,
            min_length: 64,
            max_length: 100,
            description: "Cisco Webex Access Token",
        },
        // ===============================
        // Email Services
        // ===============================
        SecretPattern {
            name: "SendGrid API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("SG."),
            severity: Severity::High,
            keywords: vec!["sendgrid", "api", "key", "mail"],
            requires_entropy: false,
            min_length: 50,
            max_length: 100,
            description: "SendGrid API Key",
        },
        SecretPattern {
            name: "Mailgun API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("key-"),
            severity: Severity::High,
            keywords: vec!["mailgun", "api", "key", "mail"],
            requires_entropy: false,
            min_length: 32,
            max_length: 40,
            description: "Mailgun API Key",
        },
        SecretPattern {
            name: "Postmark Server Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::HexLength(36),
            severity: Severity::High,
            keywords: vec!["postmark", "server", "token"],
            requires_entropy: true,
            min_length: 36,
            max_length: 36,
            description: "Postmark Server API Token",
        },
        SecretPattern {
            name: "SparkPost API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(40),
            severity: Severity::High,
            keywords: vec!["sparkpost", "api", "key"],
            requires_entropy: true,
            min_length: 40,
            max_length: 40,
            description: "SparkPost API Key",
        },
        SecretPattern {
            name: "Mailjet API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(32),
            severity: Severity::High,
            keywords: vec!["mailjet", "api", "key"],
            requires_entropy: true,
            min_length: 32,
            max_length: 32,
            description: "Mailjet API Key",
        },
        SecretPattern {
            name: "Mailchimp API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Suffix("-us"),
            severity: Severity::High,
            keywords: vec!["mailchimp", "api", "key"],
            requires_entropy: true,
            min_length: 32,
            max_length: 40,
            description: "Mailchimp API Key",
        },
        SecretPattern {
            name: "Twilio Account SID",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("AC"),
            severity: Severity::Medium,
            keywords: vec!["twilio", "account", "sid"],
            requires_entropy: false,
            min_length: 34,
            max_length: 34,
            description: "Twilio Account SID",
        },
        SecretPattern {
            name: "Twilio API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("SK"),
            severity: Severity::High,
            keywords: vec!["twilio", "api", "key"],
            requires_entropy: false,
            min_length: 34,
            max_length: 34,
            description: "Twilio API Key SID",
        },
    ]
}
