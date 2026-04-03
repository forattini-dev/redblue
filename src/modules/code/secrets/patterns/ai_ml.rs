//! AI/ML Service Secret Patterns
//!
//! Patterns for OpenAI, Anthropic, Cohere, Hugging Face, Replicate, Stability AI, Mistral, etc.

use super::super::Severity;
use super::types::{PatternCategory, PatternMatcher, SecretPattern};

/// Get all AI/ML service patterns
pub fn patterns() -> Vec<SecretPattern> {
    vec![
        // ===============================
        // OpenAI
        // ===============================
        SecretPattern {
            name: "OpenAI API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("sk-"),
            severity: Severity::Critical,
            keywords: vec!["openai", "gpt", "api", "key", "chatgpt"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "OpenAI API Key",
        },
        // ===============================
        // Anthropic
        // ===============================
        SecretPattern {
            name: "Anthropic API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("sk-ant-"),
            severity: Severity::Critical,
            keywords: vec!["anthropic", "claude", "api", "key"],
            requires_entropy: false,
            min_length: 60,
            max_length: 120,
            description: "Anthropic API Key",
        },
        // ===============================
        // Cohere
        // ===============================
        SecretPattern {
            name: "Cohere API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 40,
                max_len: 50,
            },
            severity: Severity::High,
            keywords: vec!["cohere", "api", "key"],
            requires_entropy: true,
            min_length: 40,
            max_length: 50,
            description: "Cohere API Key",
        },
        // ===============================
        // Hugging Face
        // ===============================
        SecretPattern {
            name: "Hugging Face API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("hf_"),
            severity: Severity::High,
            keywords: vec!["huggingface", "hf", "api", "token"],
            requires_entropy: false,
            min_length: 36,
            max_length: 50,
            description: "Hugging Face API Token",
        },
        // ===============================
        // Replicate
        // ===============================
        SecretPattern {
            name: "Replicate API Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("r8_"),
            severity: Severity::High,
            keywords: vec!["replicate", "api", "token"],
            requires_entropy: false,
            min_length: 36,
            max_length: 50,
            description: "Replicate API Token",
        },
        // ===============================
        // Stability AI
        // ===============================
        SecretPattern {
            name: "Stability AI API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("sk-"),
            severity: Severity::High,
            keywords: vec!["stability", "stable", "diffusion", "api", "key"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "Stability AI API Key",
        },
        // ===============================
        // Google AI Studio / Gemini
        // ===============================
        SecretPattern {
            name: "Google AI Studio API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("AIza"),
            severity: Severity::High,
            keywords: vec!["google", "ai", "studio", "gemini", "api", "key"],
            requires_entropy: false,
            min_length: 39,
            max_length: 39,
            description: "Google AI Studio API Key",
        },
        // ===============================
        // Mistral AI
        // ===============================
        SecretPattern {
            name: "Mistral API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 32,
                max_len: 40,
            },
            severity: Severity::High,
            keywords: vec!["mistral", "api", "key"],
            requires_entropy: true,
            min_length: 32,
            max_length: 40,
            description: "Mistral AI API Key",
        },
    ]
}
